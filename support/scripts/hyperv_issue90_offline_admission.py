"""Local-only #90 evidence admission; neither a cloud grant nor a custody receipt.

ReviewPins must be independently authenticated and cover an observed build
from the reviewed source and config; neither this module nor a self-reported
receipt can establish that review. No pins or private inputs are shipped here.
Source executable parents need not be trusted: only descriptor-copied,
reviewed bytes execute under owner-only, nonreplaceable directory ancestry.
The pinned QEMU's required option ROMs are copied and pinned the same way.
The private Git runtime also requires nonreplaceable ancestry. The legacy
#90 prepare/live gates remain closed.
"""

from dataclasses import dataclass, field, replace
import hashlib
import importlib
import os
from pathlib import Path
import signal
import stat
import subprocess

azure = importlib.import_module("hyperv-azure")
preflight = importlib.import_module("hyperv_private_preflight")
topology = importlib.import_module("hyperv_issue90_topology")

SCHEMA = "unikraft.hyperv.issue90-offline-admission"
FINAL = "HYPERV_TOPOLOGY FINAL UNAVAILABLE reason=no-devices"
RESULT = "HYPERV_TOPOLOGY RESULT UNAVAILABLE"
FORBIDDEN = (
    "HYPERV_TOPOLOGY FINAL PASS", "HYPERV_TOPOLOGY FINAL FAIL",
    "HYPERV_TOPOLOGY RESULT PASS", "HYPERV_TOPOLOGY RESULT FAIL",
    "UK_HYPERV_TOPOLOGY_READ_OK", "HYPERV_TOPOLOGY TARGET INFO",
    "HYPERV_TOPOLOGY OS_READ", "HYPERV_TOPOLOGY DATA_READ",
    "HYPERV_PERSISTENCE", "UK_HYPERV_IO_READY",
    "UK_HYPERV_ACCEPTANCE_FAIL:", "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:",
)
MODES = (
    ("raw", "x2apic", False), ("raw", "legacy-apic", True),
    ("vhd", "x2apic", False), ("vhd", "legacy-apic", True),
)
# The native runner's fixed q35/KVM argv loads exactly these option ROMs; the
# pinned QEMU release resolves them from the share/ directory beside its binary.
QEMU_SUPPORT_FILES = ("kvmvapic.bin", "vgabios-stdvga.bin")
QEMU_SUPPORT_MAX = 1024 * 1024
REPORT_FIELDS = {
    "schema_version", "scope", "acceptance", "passed", "consumed",
    "cleanup_complete", "input_unchanged", "serial_valid",
    "serial_limit_reached", "serial_bytes", "serial_sha256",
    "failures", "termination",
}


@dataclass(frozen=True)
class ReviewPins:
    head_commit: str
    tree_sha256: str
    physical_sha256: str
    config_sha256: str
    git_runtime_sha256: str
    build_receipt_sha256: str
    efi_sha256: str
    raw_sha256: str
    vhd_sha256: str
    miz_sha256: str
    runner_sha256: str
    qemu_sha256: str
    ovmf_code_sha256: str
    ovmf_vars_sha256: str
    qemu_support_sha256: str


@dataclass(frozen=True)
class OfflineInputs:
    state_dir: Path
    build_dir: Path
    image_dir: Path
    miz: Path
    runner: Path
    qemu: Path
    ovmf_code: Path
    ovmf_vars: Path
    reviewed: ReviewPins | None


@dataclass(frozen=True)
class BootEvidence:
    source: str
    mode: str
    image_sha256: str
    serial_sha256: str
    report_sha256: str


@dataclass(frozen=True)
class SeedEvidence:
    role: str
    lun: int
    sectors: int
    vhd_sha256: str
    manifest_sha256: str


@dataclass(frozen=True)
class OfflineAdmission:
    run_id: str
    operation_id: str
    reviewed_head: str
    source_sha256: str
    implementation_sha256: str
    config_sha256: str
    efi_sha256: str
    raw_sha256: str
    vhd_sha256: str
    miz_sha256: str
    seeds: tuple[SeedEvidence, SeedEvidence]
    boots: tuple[BootEvidence, BootEvidence, BootEvidence, BootEvidence]
    schema: str = field(default=SCHEMA, init=False)
    version: int = field(default=1, init=False)
    scope: str = field(default="offline_only", init=False)
    cloud_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class OfflineRefusal:
    stage: str
    reason: str
    schema: str = field(default=SCHEMA, init=False)
    version: int = field(default=1, init=False)
    scope: str = field(default="offline_only", init=False)


def _pins(value):
    if type(value) is not ReviewPins:
        raise ValueError("Independent reviewed source and tool pins are required")
    if (not isinstance(value.head_commit, str)
            or not preflight.GIT_COMMIT.fullmatch(value.head_commit)):
        raise ValueError("Reviewed source commit is invalid")
    for field in (
        "tree_sha256", "physical_sha256", "config_sha256", "git_runtime_sha256",
        "build_receipt_sha256", "efi_sha256", "raw_sha256", "vhd_sha256",
        "miz_sha256", "runner_sha256", "qemu_sha256",
        "ovmf_code_sha256", "ovmf_vars_sha256", "qemu_support_sha256",
    ):
        azure.require_sha256(getattr(value, field), field)


def _file(path, maximum, *, private=False, executable=False):
    if (not isinstance(path, Path) or not path.is_absolute()
            or path.resolve(strict=True) != path):
        raise ValueError("Offline input path must be absolute and symlink-free")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum
            or metadata.st_mode & 0o022
            or (private and metadata.st_uid != os.getuid())
            or (executable and not metadata.st_mode & 0o100)):
        raise ValueError("Offline input must be a bounded, protected regular file")
    return azure.image_sha256(path)


def _trusted_execution_parent(directory):
    preflight.private_directory(directory, "Executable custody directory")
    for path in (directory, *directory.parents):
        metadata = path.lstat()
        if (not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in (0, os.getuid())
                or (metadata.st_mode & 0o022
                    and not (metadata.st_uid == 0
                             and metadata.st_mode & stat.S_ISVTX))):
            raise ValueError("Executable custody has a replaceable parent")


def _stage_executable(source, destination, maximum, expected_sha256):
    if _file(source, maximum, executable=True) != expected_sha256:
        raise ValueError("Executable differs from independent review")
    size = source.stat().st_size
    if not 0 < size <= maximum:
        raise ValueError("Executable size changed before private copy")
    azure.copy_regular_file(source, destination, size, expected_sha256)
    destination.chmod(0o500)
    if (_file(destination, maximum, private=True, executable=True)
            != expected_sha256):
        raise ValueError("Private executable copy differs from independent review")
    with destination.open("rb") as program:
        if program.read(4) != b"\x7fELF":
            raise ValueError("Private executable is not a native ELF")
    return destination


def qemu_support_sha256(directory, *, private=False):
    """Digest the exact QEMU option ROMs that independent review must pin."""
    records = []
    for name in QEMU_SUPPORT_FILES:
        path = directory / name
        sha = _file(path, QEMU_SUPPORT_MAX, private=private)
        records.append({
            "name": name, "sha256": sha, "size": path.stat().st_size,
        })
    return hashlib.sha256(azure.canonical_json(records)).hexdigest()


def _stage_qemu_support(source, destination, expected_sha256):
    if qemu_support_sha256(source) != expected_sha256:
        raise ValueError("QEMU support files differ from independent review")
    destination.mkdir(mode=0o700, exist_ok=False)
    for name in QEMU_SUPPORT_FILES:
        path = source / name
        size = path.stat().st_size
        azure.copy_regular_file(
            path, destination / name, size,
            _file(path, QEMU_SUPPORT_MAX),
        )
        (destination / name).chmod(0o400)
    if (sorted(os.listdir(destination)) != sorted(QEMU_SUPPORT_FILES)
            or qemu_support_sha256(destination, private=True)
            != expected_sha256):
        raise ValueError(
            "Private QEMU support copy differs from independent review"
        )
    return destination


def _seed_proofs(directory, state):
    proofs = {}
    for role in topology.LUNS:
        path = directory / f"{role}.vhd"
        sha = _file(path, topology.DISK_BYTES + 512, private=True)
        if path.stat().st_size != topology.DISK_BYTES + 512:
            raise ValueError("Seeded VHD has the wrong sector count")
        manifest = directory / f"{role}-seed.json"
        proofs[role] = {
            "sha256": sha, "size": topology.DISK_BYTES + 512,
            "manifest_sha256": _file(manifest, 65536, private=True),
        }
    if proofs["data0"]["sha256"] == proofs["data7"]["sha256"]:
        raise ValueError("The policy-2 seeds must be distinct")
    candidate = {**state, "prepared": {"seeds": proofs}}
    for role in topology.LUNS:
        topology.verify_seed(directory, candidate, role)
    return tuple(
        SeedEvidence(role, topology.LUNS[role], topology.SECTORS,
                     proofs[role]["sha256"], proofs[role]["manifest_sha256"])
        for role in topology.LUNS
    )


def _boot(inputs, state_dir, state, source, mode, legacy, image, image_sha, tool_sha):
    if inputs.runner.parent != inputs.qemu.parent:
        raise ValueError("Native boot executables must share private custody")
    _trusted_execution_parent(inputs.runner.parent)
    work = state_dir / f"offline-{source}-{mode}"
    work.mkdir(mode=0o700, exist_ok=False)
    preflight.private_directory(work, "Fresh native boot workspace")
    required = [RESULT]
    forbidden = list(FORBIDDEN)
    if legacy:
        required.insert(0, azure.LEGACY_APIC_MARKER)
    else:
        forbidden.append(azure.LEGACY_APIC_MARKER)
    argv = [
        str(inputs.runner), "--raw-disk" if source == "raw" else "--fixed-vhd",
        str(image), "--qemu", str(inputs.qemu),
        "--ovmf-code", str(inputs.ovmf_code),
        "--ovmf-vars", str(inputs.ovmf_vars),
        "--work-dir", str(work), "--cpus", "1", "--timeout", "60",
        "--expect-main-return", "2", "--expect", FINAL,
    ]
    if legacy:
        argv.append("--disable-x2apic")
    for marker in required:
        argv.extend(("--require-marker", marker))
    for marker in forbidden:
        argv.extend(("--forbid-marker", marker))
    with subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=130)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
    if process.returncode or len(stdout) > 65536 or len(stderr) > 65536:
        raise ValueError("Native local boot did not complete successfully")
    report_bytes = azure.read_regular_file(work / "report.json", 65536, "Native boot report")
    if stdout != report_bytes:
        raise ValueError("Native boot report differs from the executed run")
    report = azure.parse_strict_json(report_bytes, "Native boot report")
    if (not isinstance(report, dict) or set(report) != REPORT_FIELDS
            or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1
            or report["scope"] != "public_local_qemu_only"
            or report["acceptance"] != "not_established"
            or any(report.get(key) is not True for key in (
                "passed", "consumed", "cleanup_complete", "input_unchanged",
                "serial_valid",
            ))
            or report.get("serial_limit_reached") is not False):
        raise ValueError("Native boot report is not a successful local execution")
    request = azure.parse_strict_json(
        azure.read_regular_file(work / "request.json", 65536, "Native boot request"),
        "Native boot request",
    )
    config = request.get("config") if isinstance(request, dict) else None
    expected = {
        "source": {"kind": "raw_disk" if source == "raw" else "fixed_vhd",
                   "path": str(image)},
        "ovmf_code": str(inputs.ovmf_code), "ovmf_vars": str(inputs.ovmf_vars),
        "qemu": str(inputs.qemu), "work_dir": str(work), "expect": FINAL,
        "expect_main_return": 2, "required": required, "forbidden": forbidden,
        "cpus": 1, "disable_x2apic": legacy, "timeout_ms": 60000,
    }
    pins = request.get("pins") if isinstance(request, dict) else None
    if (not isinstance(request, dict) or type(request.get("schema_version")) is not int
            or request["schema_version"] != 2 or config != expected
            or not isinstance(pins, list) or len(pins) != 4
            or not (work / "launched").is_file()):
        raise ValueError("Native boot request did not bind the exact disk and mode")
    sizes = (image.stat().st_size, inputs.ovmf_code.stat().st_size,
             inputs.ovmf_vars.stat().st_size, inputs.qemu.stat().st_size)
    for pin, sha, size in zip(pins, (image_sha, *tool_sha), sizes):
        if (not isinstance(pin, dict) or type(pin.get("size")) is not int
                or pin["size"] != size or not isinstance(pin.get("sha256"), list)
                or len(pin["sha256"]) != 32
                or any(type(byte) is not int or not 0 <= byte <= 255
                       for byte in pin["sha256"])
                or bytes(pin["sha256"]) != bytes.fromhex(sha)):
            raise ValueError("Native boot request lost its physical input pin")
    serial = azure.read_regular_file(
        work / "hyperv-efi-boot.log", topology.MAX_SERIAL, "Native guest serial"
    )
    serial_sha = hashlib.sha256(serial).hexdigest()
    if (type(report.get("serial_bytes")) is not int
            or report["serial_bytes"] != len(serial)
            or report.get("serial_sha256") != serial_sha):
        raise ValueError("Native guest serial differs from the executed run")
    text = serial.decode("utf-8")
    lines = [azure.ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
             for line in text.splitlines()]
    if (topology.PRIVATE_SERIAL.search(text)
            or any(identity in text.lower()
                   for identity in (state["run_id"], *state["disk_ids"].values()))
            or sum("HYPERV_TOPOLOGY FINAL " in line for line in lines) != 1
            or sum(line.endswith(FINAL) for line in lines) != 1
            or sum("HYPERV_TOPOLOGY RESULT " in line for line in lines) != 1
            or sum(line.endswith(RESULT) for line in lines) != 1
            or sum(line.endswith("UK_HYPERV_PLATFORM_READY") for line in lines) != 1
            or sum("main returned " in line for line in lines) != 1
            or not any(line.endswith("main returned 2") for line in lines)
            or any(marker in text for marker in FORBIDDEN)
            or (azure.LEGACY_APIC_MARKER in text) is not legacy):
        raise ValueError("Native guest did not report exactly one no-device boot")
    return BootEvidence(
        source, mode, image_sha, serial_sha,
        hashlib.sha256(report_bytes).hexdigest(),
    )


def _check_packaging(miz, state_dir, efi_sha, efi_size, vhd):
    _trusted_execution_parent(miz.parent)
    report = azure.miz_command(miz, [
        "check-efi-application", "--output=json", "--architecture", "x86_64",
        "--expected-efi-sha256", efi_sha, "--expected-virtual-size", "66M",
        str(vhd),
    ], state_dir / "miz-issue90-offline-check.log", json_output=True)
    preflight.validate_packaging_report(
        report, efi_sha, efi_size, azure.VIRTUAL_SIZE + 512,
    )


def admit(inputs: OfflineInputs) -> OfflineAdmission | OfflineRefusal:
    """Check private evidence and execute four fresh local boots; never call Azure."""
    stage = "review"
    reasons = {
        "review": "independent_review_missing_or_invalid",
        "state": "fresh_private_plan_missing_or_invalid",
        "config": "solved_topology_config_missing_or_unreviewed",
        "source": "reviewed_physical_source_missing_or_invalid",
        "build": "witnessed_build_receipt_or_efi_missing_or_invalid",
        "image": "raw_or_fixed_vhd_missing_or_invalid",
        "seeds": "policy2_seeds_missing_or_invalid",
        "tools": "reviewed_local_tools_missing_or_invalid",
        "packaging": "miz_physical_vhd_check_failed",
        "boots": "four_physical_no_device_boots_missing_or_invalid",
        "final": "offline_evidence_changed_during_verification",
    }
    try:
        if type(inputs) is not OfflineInputs:
            raise ValueError("Offline admission input type is invalid")
        _pins(inputs.reviewed)
        stage = "state"
        if not all(isinstance(path, Path) and path.is_absolute()
                   and path.resolve(strict=True) == path for path in (
            inputs.state_dir, inputs.build_dir, inputs.image_dir,
        )):
            raise ValueError("Offline admission directories must be canonical")
        state_dir = preflight.private_directory(inputs.state_dir, "Issue 90 state")
        state = topology.load(state_dir)
        if (state["phase"] != "planned" or state["boot_count"] != 0
                or state.get("prepared") is not None or state.get("pending_create") is not None
                or state.get("disks") or state.get("vm")):
            raise ValueError("Offline admission needs a fresh unallocated plan")
        build_dir = preflight.private_directory(inputs.build_dir, "Private build")
        image_dir = preflight.private_directory(inputs.image_dir, "Private image")
        _trusted_execution_parent(build_dir)
        _trusted_execution_parent(state_dir)
        stage = "config"
        config_path = build_dir / preflight.SOLVED_CONFIG
        config = azure.read_regular_file(config_path, 1024 * 1024, "Solved config")
        topology.solved_config(config, state)
        reviewed = inputs.reviewed
        if hashlib.sha256(config).hexdigest() != reviewed.config_sha256:
            raise ValueError("Solved config differs from independent review")
        stage = "source"
        git_runtime = build_dir / preflight.GIT_RUNTIME
        git_fingerprint = preflight.validate_git_runtime_record(
            preflight.git_runtime_record(git_runtime)
        )
        if git_fingerprint["sha256"] != reviewed.git_runtime_sha256:
            raise ValueError("Git executable closure differs from independent review")
        provenance = preflight.build_provenance(
            Path(topology.__file__).resolve().parents[2],
            config_path, git_runtime,
        )
        if (provenance["head_commit"] != reviewed.head_commit
                or provenance["tree_sha256"] != reviewed.tree_sha256
                or provenance["physical_sha256"] != reviewed.physical_sha256):
            raise ValueError("Physical source differs from independent review")
        stage = "build"
        efi_path = build_dir / "build" / preflight.NATIVE_EFI_NAME
        efi_sha = _file(efi_path, 64 * 1024 * 1024, private=True)
        if efi_sha != reviewed.efi_sha256:
            raise ValueError("Built EFI differs from independent review")
        efi = preflight.regular_record(
            efi_path, preflight.NATIVE_EFI_NAME, "Private topology EFI"
        )
        if _file(
            build_dir / preflight.PRIVATE_BUILD_RECEIPT,
            preflight.MAX_MANIFEST_BYTES, private=True,
        ) != reviewed.build_receipt_sha256:
            raise ValueError("Private build receipt differs from independent review")
        receipt = preflight.load_receipt(
            build_dir / preflight.PRIVATE_BUILD_RECEIPT,
            preflight.PRIVATE_BUILD_RECEIPT, "Private topology build receipt",
        )
        preflight.validate_private_build(receipt, provenance, efi)
        stage = "image"
        copied_efi = image_dir / "BOOTX64.EFI"
        if (_file(copied_efi, 64 * 1024 * 1024, private=True) != efi_sha
                or copied_efi.stat().st_size != efi["size"]):
            raise ValueError("Packaged EFI is not the reviewed build output")
        stage = "image"
        raw = image_dir / "unikraft.raw"
        vhd = image_dir / "unikraft.vhd"
        raw_sha = _file(raw, azure.VIRTUAL_SIZE, private=True)
        vhd_sha = _file(vhd, azure.VIRTUAL_SIZE + 512, private=True)
        if raw_sha != reviewed.raw_sha256 or vhd_sha != reviewed.vhd_sha256:
            raise ValueError("Packaged disks differ from independent review")
        topology.verify_raw_vhd_pair(raw, vhd, raw_sha, vhd_sha)
        stage = "seeds"
        seeds = _seed_proofs(state_dir, state)
        stage = "tools"
        tools = (
            (inputs.miz, 256 * 1024 * 1024, reviewed.miz_sha256),
            (inputs.runner, 256 * 1024 * 1024, reviewed.runner_sha256),
            (inputs.qemu, 256 * 1024 * 1024, reviewed.qemu_sha256),
            (inputs.ovmf_code, 16 * 1024 * 1024, reviewed.ovmf_code_sha256),
            (inputs.ovmf_vars, 4 * 1024 * 1024, reviewed.ovmf_vars_sha256),
        )
        for path, size, expected in tools:
            if _file(path, size, executable=path in (
                inputs.miz, inputs.runner, inputs.qemu
            )) != expected:
                raise ValueError("Tool differs from independent review")
        executable_dir = state_dir / "offline-executables"
        executable_dir.mkdir(mode=0o700, exist_ok=False)
        _trusted_execution_parent(executable_dir)
        staged = replace(
            inputs,
            miz=_stage_executable(
                inputs.miz, executable_dir / "miz",
                256 * 1024 * 1024, reviewed.miz_sha256,
            ),
            runner=_stage_executable(
                inputs.runner, executable_dir / "runner",
                256 * 1024 * 1024, reviewed.runner_sha256,
            ),
            qemu=_stage_executable(
                inputs.qemu, executable_dir / "qemu-system-x86_64",
                256 * 1024 * 1024, reviewed.qemu_sha256,
            ),
        )
        qemu_support = _stage_qemu_support(
            inputs.qemu.parent / "share", executable_dir / "share",
            reviewed.qemu_support_sha256,
        )
        stage = "packaging"
        _check_packaging(staged.miz, state_dir, efi_sha, efi["size"], vhd)
        stage = "boots"
        boots = tuple(
            _boot(staged, state_dir, state, source, mode, legacy,
                  raw if source == "raw" else vhd,
                  raw_sha if source == "raw" else vhd_sha,
                  (reviewed.ovmf_code_sha256, reviewed.ovmf_vars_sha256,
                   reviewed.qemu_sha256))
            for source, mode, legacy in MODES
        )
        stage = "final"
        _trusted_execution_parent(executable_dir)
        if (topology.digest(raw) != raw_sha or topology.digest(vhd) != vhd_sha
                or _file(copied_efi, 64 * 1024 * 1024, private=True) != efi_sha
                or _file(efi_path, 64 * 1024 * 1024, private=True) != efi_sha
                or _file(config_path, 1024 * 1024, private=True)
                != reviewed.config_sha256
                or _file(build_dir / preflight.PRIVATE_BUILD_RECEIPT,
                         preflight.MAX_MANIFEST_BYTES, private=True)
                != reviewed.build_receipt_sha256
                or _seed_proofs(state_dir, state) != seeds
                or preflight.build_provenance(
                    Path(topology.__file__).resolve().parents[2],
                    config_path, git_runtime,
                ) != provenance
                or preflight.validate_git_runtime_record(
                    preflight.git_runtime_record(git_runtime)
                ) != git_fingerprint
                or any(_file(path, size, executable=path in (
                    inputs.miz, inputs.runner, inputs.qemu
                )) != expected for path, size, expected in tools)
                or _file(staged.miz, 256 * 1024 * 1024, private=True,
                         executable=True) != reviewed.miz_sha256
                or _file(staged.runner, 256 * 1024 * 1024, private=True,
                         executable=True) != reviewed.runner_sha256
                or _file(staged.qemu, 256 * 1024 * 1024, private=True,
                         executable=True) != reviewed.qemu_sha256
                or qemu_support_sha256(inputs.qemu.parent / "share")
                != reviewed.qemu_support_sha256
                or sorted(os.listdir(qemu_support))
                != sorted(QEMU_SUPPORT_FILES)
                or qemu_support_sha256(qemu_support, private=True)
                != reviewed.qemu_support_sha256):
            raise ValueError("Booted image changed during local verification")
        return OfflineAdmission(
            state["run_id"], state["operation_id"], reviewed.head_commit,
            hashlib.sha256(azure.canonical_json(provenance)).hexdigest(),
            hashlib.sha256(azure.canonical_json(topology.implementation())).hexdigest(),
            provenance["config"]["sha256"], efi_sha, raw_sha, vhd_sha,
            reviewed.miz_sha256, seeds, boots,
        )
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired):
        return OfflineRefusal(stage, reasons[stage])
