#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit


SUPPORT = Path(__file__).resolve().parents[1]
MANAGED_BY = "unikraft-hyperv"


PLATFORM_READY = "UK_HYPERV_PLATFORM_READY"
BLOCK_READY = "UK_HYPERV_BLOCK_READ_OK"
NETWORK_READY = "UK_HYPERV_NET_DHCP_OFFER"
IO_READY = "UK_HYPERV_IO_READY"
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MIB = 1024 * 1024
ESP_SIZE = 64 * MIB
VIRTUAL_SIZE = 66 * MIB
LOCAL_BOOT_MODES = (
    ("x2apic", False),
    ("legacy-apic", True),
)
LEGACY_APIC_MARKER = "Using legacy xAPIC MMIO"
STATE_SCHEMA_VERSION = 1
PREPARED_IMAGE_SCHEMA = "unikraft.hyperv.prepared-image"
PREPARED_IMAGE_SCHEMA_VERSION = 1
PREPARED_IMAGE_CONTROLLER_REVISION = 1
PREPARED_IMAGE_MANIFEST = "prepared-image-manifest.json"
PREPARED_IMAGE_VHD = "unikraft.vhd"
PREPARED_IMAGE_FILES = frozenset((PREPARED_IMAGE_MANIFEST, PREPARED_IMAGE_VHD))
MIZ_REVISION = "2db68ca0c3ab12155012a823c3fb8d7aba1cb544"
MAX_MANIFEST_SIZE = 64 * 1024
MAX_LOCAL_LOG_SIZE = 4 * MIB
AZURE_OWNERSHIP_FIELDS = frozenset(("subscription", "disk_id", "vm_id"))
VM_SIZES = ("Standard_D2s_v5", "Standard_D2as_v5", "Standard_B2s")


class AzureCliError(RuntimeError):
    def __init__(self, arguments, result, private):
        match = re.search(
            r"(?:^ERROR: \(|^ErrorCode:)([A-Za-z][A-Za-z0-9_]{0,79})",
            result.stderr, re.MULTILINE,
        )
        self.code = match.group(1) if match else None
        detail = (
            f"{self.code or 'unclassified error'}; credential-bearing output withheld"
            if private else result.stderr.strip()
        )
        super().__init__(
            f"az {' '.join(arguments[:2])} failed ({result.returncode}): {detail}"
        )


def azure_cli(arguments, *, subscription=None, private=False, env=None,
              timeout=300):
    command = [
        "az", *arguments, "--only-show-errors", "--output", "json"
    ]
    if subscription is not None:
        command.extend(("--subscription", subscription))
    environment = os.environ.copy()
    environment["AZURE_CORE_COLLECT_TELEMETRY"] = "false"
    environment["AZURE_LOGGING_ENABLE_LOG_FILE"] = "false"
    environment["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
    if env:
        environment.update(env)
    result = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=environment,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise AzureCliError(arguments, result, private)
    return json.loads(result.stdout) if result.stdout.strip() else None


def save_json(path, value):
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, prefix=".azure-state-", delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            json.dump(value, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def image_sha256(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Image must be a regular, non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as image:
        for chunk in iter(lambda: image.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def read_regular_file(path, maximum, description):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{description} must be a readable non-symlink file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError(f"{description} has an invalid type or size")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > maximum:
            raise ValueError(f"{description} exceeds its size limit")
        return value
    finally:
        os.close(descriptor)


def copy_regular_file(source, destination, expected_size, expected_sha256):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source, flags)
    except OSError as error:
        raise ValueError("Prepared image must be a readable non-symlink file") from error
    destination_descriptor = None
    destination_created = False
    complete = False
    try:
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
            raise ValueError("Prepared image has an unexpected type or size")
        destination_descriptor = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        destination_created = True
        digest = hashlib.sha256()
        copied = 0
        while copied < expected_size:
            remaining = expected_size - copied
            chunk = os.read(source_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise ValueError("Prepared image grew beyond its expected size")
            digest.update(chunk)
            copied += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("Prepared image copy made no progress")
                view = view[written:]
        if copied == expected_size and os.read(source_descriptor, 1):
            raise ValueError("Prepared image grew beyond its expected size")
        os.fsync(destination_descriptor)
        if copied != expected_size or digest.hexdigest() != expected_sha256:
            raise ValueError("Prepared image content does not match its manifest")
        complete = True
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if destination_created and not complete:
            Path(destination).unlink(missing_ok=True)


def parse_strict_json(value, description):
    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"{description} contains duplicate field {key!r}")
            result[key] = item
        return result

    def reject_constant(constant):
        raise ValueError(f"{description} contains invalid number {constant}")

    try:
        return json.loads(
            value.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{description} is not valid UTF-8 JSON") from error


def load_strict_json(path, maximum, description, *, canonical=False):
    value = read_regular_file(path, maximum, description)
    result = parse_strict_json(value, description)
    if canonical and value != canonical_json(result):
        raise ValueError(f"{description} is not canonical JSON")
    return result, value


def require_exact_fields(value, fields, description):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(f"{description} has unknown or missing fields")
    return value


def require_sha256(value, description):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{description} must be a lowercase SHA-256 digest")
    return value


def controller_sha256():
    return image_sha256(Path(__file__).absolute())


def configure_tool_directories(directory):
    tools = directory / "tools"
    tools.mkdir(mode=0o700, exist_ok=True)
    if tools.is_symlink():
        raise ValueError("Tool artifact directory must not be a symlink")
    for name, child in (("TMPDIR", "tmp"), ("XDG_CACHE_HOME", "cache")):
        path = tools / child
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink():
            raise ValueError("Tool artifact directory must not be a symlink")
        os.environ[name] = str(path)


def load_state(directory):
    directory = directory.resolve(strict=True)
    metadata = directory.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("State directory must be private and owned by the current user")
    path = directory / "state.json"
    if path.is_symlink():
        raise ValueError("State file must not be a symlink")
    state = json.loads(path.read_text())
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise ValueError("Unsupported Azure run state schema")
    configure_tool_directories(directory)
    return state, path


def upload_endpoint(sas):
    parsed = urlsplit(sas)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith((
            ".blob.core.windows.net", ".blob.storage.azure.net",
        ))
        or parsed.port not in (None, 443, 8443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.query
        or not parsed.path.strip("/")
    ):
        raise ValueError("Expected an Azure public-cloud HTTPS Blob SAS endpoint")
    return urlunsplit(parsed._replace(query="")), parsed.query


def disk_access_sas(grant):
    if not isinstance(grant, dict):
        raise ValueError("Azure CLI returned an invalid disk-access response")
    values = [grant[key] for key in ("accessSAS", "accessSas") if key in grant]
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise ValueError("Azure CLI disk-access response has no valid SAS field")
    if any(value != values[0] for value in values[1:]):
        raise ValueError("Azure CLI disk-access response has conflicting SAS fields")
    return values[0]


def upload_helper(arguments, *, sas=None, timeout=1200):
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith("AZURE_STORAGE_")
    }
    if sas is not None:
        environment["AZURE_STORAGE_SAS_TOKEN"] = sas
    result = subprocess.run(
        [sys.executable, str(SUPPORT / "scripts/hyperv-azure-upload.py"), *arguments],
        stdin=subprocess.DEVNULL, capture_output=True,
        text=True, encoding="utf-8", errors="replace", env=environment,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Managed-disk upload helper failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def check_upload_dependencies():
    result = upload_helper(["--check-dependencies"], timeout=30)
    if not isinstance(result, dict) or result.get("available") is not True:
        raise RuntimeError("Managed-disk upload dependencies are unavailable")


def upload_managed_vhd(image, endpoint, sas):
    report = upload_helper(["--image", str(image), "--endpoint", endpoint], sas=sas)
    if (
        not isinstance(report, dict)
        or report.get("uploaded_bytes") != image.stat().st_size
        or report.get("footer_matches") is not True
    ):
        raise RuntimeError("Managed-disk page upload did not verify the expected image")


def packaging_contract(efi_sha256, file_size):
    return {
        "schema-version": 1,
        "contract": "miz.efi-application-image",
        "valid": True,
        "format": "vhd",
        "subformat": "fixed",
        "generation": 2,
        "virtual-size": VIRTUAL_SIZE,
        "file-size": file_size,
        "architecture": "x86_64",
        "boot-path": "EFI/BOOT/BOOTX64.EFI",
        "boot-file-sha256": efi_sha256,
        "esp-offset": MIB,
        "esp-length": ESP_SIZE,
    }


def check_packaging_report(report, efi_sha256, file_size):
    expected = packaging_contract(efi_sha256, file_size)
    if not isinstance(report, dict) or file_size != VIRTUAL_SIZE + 512:
        raise ValueError("Invalid fixed-VHD packaging report or file size")
    for key, value in expected.items():
        if type(report.get(key)) is not type(value) or report[key] != value:
            raise ValueError(f"Unexpected miz packaging field: {key}")


def miz_command(miz, arguments, log_path, *, json_output=False):
    with log_path.open("xb") as log:
        result = subprocess.run(
            [str(miz), *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if json_output else log, stderr=log,
            timeout=300, check=False,
        )
    if result.returncode:
        raise RuntimeError(f"miz {arguments[0]} failed; see {log_path}")
    if json_output:
        return json.loads(result.stdout)
    return None


def validate_local_boot_log(log_path, expected, disable_x2apic):
    text = read_regular_file(
        log_path, MAX_LOCAL_LOG_SIZE, "Local serial evidence"
    ).decode("utf-8", errors="replace")
    normalized = text.replace("\0", "")
    evidence = inspect_boot_log(normalized, expected)
    if not evidence["platform_ready"]:
        raise RuntimeError(
            f"Local application-ready marker is missing or guest crashed; see {log_path}"
        )
    if disable_x2apic and LEGACY_APIC_MARKER not in normalized:
        raise RuntimeError(
            f"Legacy-APIC local boot did not use the xAPIC fallback; see {log_path}"
        )
    if not disable_x2apic and LEGACY_APIC_MARKER in normalized:
        raise RuntimeError(
            f"Normal local boot unexpectedly used the xAPIC fallback; see {log_path}"
        )
    for marker in (
        "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:", "Powered by", "Calling main(",
    ):
        if marker not in normalized:
            raise RuntimeError(f"Local boot is missing {marker}; see {log_path}")
    return evidence


def local_disk_boot(image, image_format, directory, ovmf_code, ovmf_vars,
                    qemu, expected, timeout, mode, disable_x2apic):
    if image_format not in ("raw", "vpc"):
        raise ValueError("Local boot supports only raw GPT and fixed VHD images")
    log_path = directory / f"local-{image_format}-{mode}-serial.log"
    with tempfile.TemporaryDirectory(prefix="ovmf-", dir=directory) as temporary:
        work = Path(temporary)
        shutil.copyfile(ovmf_code, work / "OVMF_CODE.fd")
        shutil.copyfile(ovmf_vars, work / "OVMF_VARS.fd")
        os.link(image, work / "disk.img")
        cpu = (
            "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,"
            "hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies"
        )
        if disable_x2apic:
            cpu += ",x2apic=off"
        # Both formats expose the same raw data region. For fixed VHD, miz
        # validates the footer separately; it must not become a guest sector.
        disk = {
            "driver": "raw", "node-name": "hyperv-disk",
            "offset": 0, "size": VIRTUAL_SIZE, "read-only": True,
            "file": {
                "driver": "file", "filename": "disk.img", "read-only": True,
            },
        }
        command = [
            str(qemu), "-machine", "q35,accel=kvm",
            "-cpu", cpu,
            "-smp", "1", "-m", "512M",
            "-drive", "if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd",
            "-drive", "if=pflash,format=raw,file=OVMF_VARS.fd",
            "-blockdev", json.dumps(disk, separators=(",", ":")),
            "-device", "virtio-blk-pci,drive=hyperv-disk",
            "-device", "vmbus-bridge,irq=15",
            "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-no-reboot", "-nic", "none",
        ]
        with log_path.open("xb") as log:
            result = subprocess.run(
                command, cwd=work, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
        if result.returncode:
            raise RuntimeError(f"QEMU exited with {result.returncode}; see {log_path}")
    return validate_local_boot_log(log_path, expected, disable_x2apic)


def local_disk_boot_modes(image, image_format, directory, ovmf_code, ovmf_vars,
                          qemu, expected, timeout):
    return {
        mode: local_disk_boot(
            image, image_format, directory, ovmf_code, ovmf_vars,
            qemu, expected, timeout, mode, disable_x2apic,
        )
        for mode, disable_x2apic in LOCAL_BOOT_MODES
    }


def prepare_image(args):
    validate_platform_marker(args.expect)
    validate_deployment_config(args.location, args.vm_size)
    if not 1 <= args.timeout <= 300:
        raise ValueError("Expected a 1-300 second local timeout")
    efi = args.efi.resolve(strict=True)
    miz = args.miz.resolve(strict=True)
    ovmf_code = args.ovmf_code.resolve(strict=True)
    ovmf_vars = args.ovmf_vars.resolve(strict=True)
    qemu_name = shutil.which(args.qemu)
    if qemu_name is None:
        raise FileNotFoundError(f"QEMU executable not found: {args.qemu}")
    qemu = Path(qemu_name).resolve(strict=True)
    efi_digest = image_sha256(efi)
    miz_digest = image_sha256(miz)
    directory = args.state_dir.absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    directory = directory.resolve(strict=True)
    configure_tool_directories(directory)
    state_path = directory / "state.json"
    state = {
        "schema_version": STATE_SCHEMA_VERSION, "phase": "preparing",
        "name_prefix": "uk-hv-" + secrets.token_hex(10),
        "location": args.location, "vm_size": args.vm_size,
        "platform_marker": args.expect,
        "efi_sha256": efi_digest,
        "miz_executable": str(miz), "miz_executable_sha256": miz_digest,
        "local_platform_boot": False,
    }
    save_json(state_path, state)
    payload = directory / "BOOTX64.EFI"
    shutil.copyfile(efi, payload)
    if image_sha256(payload) != efi_digest:
        raise ValueError("EFI input changed while copying it into the private run directory")
    builder = [
        "build-efi-application", "--efi", str(payload),
        "--architecture", "x86_64", "--esp-size", "64M",
    ]
    raw = directory / "unikraft.raw"
    miz_command(miz, [*builder, "-O", "raw", "-o", str(raw)],
                directory / "miz-build-raw.log")
    if raw.stat().st_size != VIRTUAL_SIZE:
        raise ValueError("Unexpected raw GPT disk size from miz")
    raw_digest = image_sha256(raw)
    raw_boots = local_disk_boot_modes(
        raw, "raw", directory, ovmf_code, ovmf_vars,
        qemu, args.expect, args.timeout,
    )
    if image_sha256(raw) != raw_digest:
        raise ValueError("Raw disk changed during its read-only local boot")
    image = directory / "unikraft.vhd"
    miz_command(miz, [*builder, "-O", "vhd", "-o", str(image)],
                directory / "miz-build-vhd.log")
    image_digest = image_sha256(image)
    report = miz_command(miz, [
        "check-efi-application", "--output=json", "--architecture", "x86_64",
        "--expected-efi-sha256", efi_digest, "--expected-virtual-size", "66M",
        str(image),
    ], directory / "miz-check.log", json_output=True)
    check_packaging_report(report, efi_digest, image.stat().st_size)
    save_json(directory / "packaging.json", report)
    vhd_boots = local_disk_boot_modes(
        image, "vpc", directory, ovmf_code, ovmf_vars,
        qemu, args.expect, args.timeout,
    )
    if image_sha256(image) != image_digest:
        raise ValueError("VHD changed during read-only preflight or local boot")
    state.update(
        phase="prepared", image_sha256=image_digest,
        local_platform_boot=True, raw_sha256=raw_digest,
        local_platform_boot_modes={
            "raw": {
                mode: evidence["platform_ready"]
                for mode, evidence in raw_boots.items()
            },
            "vhd": {
                mode: evidence["platform_ready"]
                for mode, evidence in vhd_boots.items()
            },
        },
    )
    save_json(state_path, state)
    return directory


def validate_platform_marker(value):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character in value for character in "\r\n\0")
    ):
        raise ValueError("Expected a nonempty single-line platform marker")
    return value


def validate_deployment_config(location, vm_size):
    if (
        not isinstance(location, str)
        or not re.fullmatch(r"[a-z0-9]{3,30}", location)
        or vm_size not in VM_SIZES
    ):
        raise ValueError("Expected a valid Azure region and bounded VM size")


def prepared_image_source(repository, repository_id, workflow_ref, job,
                          run_id, run_attempt, head_sha):
    workflow_path = None
    workflow_revision = None
    if isinstance(workflow_ref, str) and "@" in workflow_ref:
        workflow_path, workflow_revision = workflow_ref.rsplit("@", 1)
    if (
        not isinstance(repository, str)
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
        )
        or type(repository_id) is not int or repository_id <= 0
        or not isinstance(workflow_ref, str)
        or len(workflow_ref) > 500
        or not isinstance(workflow_path, str)
        or not re.fullmatch(
            rf"{re.escape(repository)}/\.github/workflows/"
            r"[A-Za-z0-9_.-]+\.(?:yml|yaml)",
            workflow_path,
        )
        or not isinstance(workflow_revision, str)
        or not re.fullmatch(r"refs/[A-Za-z0-9_./-]{1,300}", workflow_revision)
        or ".." in workflow_revision
        or not isinstance(job, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", job)
        or type(run_id) is not int or run_id <= 0
        or type(run_attempt) is not int or run_attempt <= 0
        or not isinstance(head_sha, str)
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head_sha)
    ):
        raise ValueError("Invalid trusted GitHub workflow provenance")
    return {
        "provider": "github-actions",
        "repository": repository,
        "repository_id": repository_id,
        "workflow_ref": workflow_ref,
        "job": job,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "head_sha": head_sha,
    }


def validate_prepared_image_source(value):
    value = require_exact_fields(value, (
        "provider", "repository", "repository_id", "workflow_ref", "job",
        "run_id", "run_attempt", "head_sha",
    ), "Prepared-image source")
    if value["provider"] != "github-actions":
        raise ValueError("Prepared-image source provider is unsupported")
    return prepared_image_source(
        value["repository"], value["repository_id"], value["workflow_ref"],
        value["job"], value["run_id"], value["run_attempt"],
        value["head_sha"],
    )


def prepared_boot_outcomes():
    return {
        "raw": {
            "x2apic": {
                "platform_ready": True,
                "io_ready": False,
                "apic_path": "x2apic",
            },
            "legacy-apic": {
                "platform_ready": True,
                "io_ready": False,
                "apic_path": "legacy-xapic",
            },
        },
        "vhd": {
            "x2apic": {
                "platform_ready": True,
                "io_ready": False,
                "apic_path": "x2apic",
            },
            "legacy-apic": {
                "platform_ready": True,
                "io_ready": False,
                "apic_path": "legacy-xapic",
            },
        },
    }


def validate_prepared_image_manifest(manifest, expected_source=None):
    manifest = require_exact_fields(manifest, (
        "schema", "schema_version", "controller_revision",
        "controller_sha256", "source", "artifacts", "packaging",
        "preflight",
    ), "Prepared-image manifest")
    if (
        manifest["schema"] != PREPARED_IMAGE_SCHEMA
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != PREPARED_IMAGE_SCHEMA_VERSION
        or type(manifest["controller_revision"]) is not int
        or manifest["controller_revision"] != PREPARED_IMAGE_CONTROLLER_REVISION
        or require_sha256(
            manifest["controller_sha256"], "Controller fingerprint"
        ) != controller_sha256()
    ):
        raise ValueError("Prepared-image schema or controller revision is incompatible")

    source = validate_prepared_image_source(manifest["source"])
    if expected_source is not None and source != expected_source:
        raise ValueError("Prepared-image GitHub provenance does not match expectations")

    artifacts = require_exact_fields(
        manifest["artifacts"], ("efi", "raw", "vhd", "miz"),
        "Prepared-image fingerprints",
    )
    efi = require_exact_fields(
        artifacts["efi"], ("sha256",), "EFI fingerprint"
    )
    raw = require_exact_fields(
        artifacts["raw"], ("sha256", "size"), "Raw-image fingerprint"
    )
    vhd = require_exact_fields(
        artifacts["vhd"], ("sha256", "size"), "VHD fingerprint"
    )
    miz = require_exact_fields(
        artifacts["miz"], ("sha256", "revision"), "miz fingerprint"
    )
    efi_sha256 = require_sha256(efi["sha256"], "EFI fingerprint")
    require_sha256(raw["sha256"], "Raw-image fingerprint")
    vhd_sha256 = require_sha256(vhd["sha256"], "VHD fingerprint")
    require_sha256(miz["sha256"], "miz fingerprint")
    if (
        type(raw["size"]) is not int or raw["size"] != VIRTUAL_SIZE
        or type(vhd["size"]) is not int or vhd["size"] != VIRTUAL_SIZE + 512
        or miz["revision"] != MIZ_REVISION
    ):
        raise ValueError("Prepared-image size or miz revision is incompatible")

    packaging = require_exact_fields(
        manifest["packaging"],
        packaging_contract(efi_sha256, vhd["size"]).keys(),
        "Prepared-image packaging contract",
    )
    check_packaging_report(packaging, efi_sha256, vhd["size"])

    preflight = require_exact_fields(
        manifest["preflight"], ("scope", "platform_marker", "boots"),
        "Prepared-image preflight",
    )
    platform_marker = validate_platform_marker(preflight["platform_marker"])
    if (
        preflight["scope"] != "platform-only"
        or canonical_json(preflight["boots"])
        != canonical_json(prepared_boot_outcomes())
    ):
        raise ValueError("Prepared-image preflight does not contain all four exact boots")
    return {
        "source": source,
        "efi_sha256": efi_sha256,
        "raw_sha256": raw["sha256"],
        "vhd_sha256": vhd_sha256,
        "vhd_size": vhd["size"],
        "miz_sha256": miz["sha256"],
        "platform_marker": platform_marker,
        "boots": preflight["boots"],
    }


def export_prepared_image(directory, artifact_directory, source):
    state, state_path = load_state(directory)
    expected_modes = {
        "raw": {"x2apic": True, "legacy-apic": True},
        "vhd": {"x2apic": True, "legacy-apic": True},
    }
    if (
        state.get("phase") != "prepared"
        or state.get("local_platform_boot") is not True
        or state.get("local_platform_boot_modes") != expected_modes
    ):
        raise ValueError("Export requires a freshly prepared four-boot local image")
    if AZURE_OWNERSHIP_FIELDS.intersection(state):
        raise ValueError("Cloud-owned state cannot be exported")

    platform_marker = validate_platform_marker(state.get("platform_marker"))
    image = state_path.parent / PREPARED_IMAGE_VHD
    raw = state_path.parent / "unikraft.raw"
    efi = state_path.parent / "BOOTX64.EFI"
    miz_value = state.get("miz_executable")
    if not isinstance(miz_value, str):
        raise ValueError("Prepared state has no miz executable")
    miz = Path(miz_value).resolve(strict=True)
    if not os.access(miz, os.X_OK):
        raise ValueError("Prepared miz executable is not executable")

    fingerprints = {
        "efi": image_sha256(efi),
        "raw": image_sha256(raw),
        "vhd": image_sha256(image),
        "miz": image_sha256(miz),
    }
    for state_field, fingerprint in (
        ("efi_sha256", fingerprints["efi"]),
        ("raw_sha256", fingerprints["raw"]),
        ("image_sha256", fingerprints["vhd"]),
        ("miz_executable_sha256", fingerprints["miz"]),
    ):
        if state.get(state_field) != fingerprint:
            raise ValueError(f"Prepared {state_field} no longer matches its local gate")
    if raw.stat().st_size != VIRTUAL_SIZE or image.stat().st_size != VIRTUAL_SIZE + 512:
        raise ValueError("Prepared raw or fixed-VHD image has an unexpected size")

    packaging, _ = load_strict_json(
        state_path.parent / "packaging.json",
        MAX_MANIFEST_SIZE,
        "miz packaging report",
    )
    check_packaging_report(packaging, fingerprints["efi"], image.stat().st_size)
    check_log = (
        state_path.parent / "tools" / "tmp"
        / f"miz-export-{secrets.token_hex(8)}.log"
    )
    checked = miz_command(miz, [
        "check-efi-application", "--output=json", "--architecture", "x86_64",
        "--expected-efi-sha256", fingerprints["efi"],
        "--expected-virtual-size", "66M", str(image),
    ], check_log, json_output=True)
    check_packaging_report(checked, fingerprints["efi"], image.stat().st_size)
    check_log.unlink(missing_ok=True)

    boot_outcomes = {"raw": {}, "vhd": {}}
    for image_name, log_name in (("raw", "raw"), ("vhd", "vpc")):
        for mode, disable_x2apic in LOCAL_BOOT_MODES:
            evidence = validate_local_boot_log(
                state_path.parent / f"local-{log_name}-{mode}-serial.log",
                platform_marker,
                disable_x2apic,
            )
            if evidence["io_ready"]:
                raise ValueError(
                    f"Local {image_name}/{mode} evidence exceeded platform-only scope"
                )
            boot_outcomes[image_name][mode] = {
                "platform_ready": evidence["platform_ready"],
                "io_ready": evidence["io_ready"],
                "apic_path": "legacy-xapic" if disable_x2apic else "x2apic",
            }
    if canonical_json(boot_outcomes) != canonical_json(prepared_boot_outcomes()):
        raise ValueError("Prepared local evidence does not contain all four exact boots")

    manifest = {
        "schema": PREPARED_IMAGE_SCHEMA,
        "schema_version": PREPARED_IMAGE_SCHEMA_VERSION,
        "controller_revision": PREPARED_IMAGE_CONTROLLER_REVISION,
        "controller_sha256": controller_sha256(),
        "source": validate_prepared_image_source(source),
        "artifacts": {
            "efi": {"sha256": fingerprints["efi"]},
            "raw": {"sha256": fingerprints["raw"], "size": VIRTUAL_SIZE},
            "vhd": {
                "sha256": fingerprints["vhd"],
                "size": VIRTUAL_SIZE + 512,
            },
            "miz": {
                "sha256": fingerprints["miz"],
                "revision": MIZ_REVISION,
            },
        },
        "packaging": packaging_contract(
            fingerprints["efi"], VIRTUAL_SIZE + 512
        ),
        "preflight": {
            "scope": "platform-only",
            "platform_marker": platform_marker,
            "boots": boot_outcomes,
        },
    }
    validate_prepared_image_manifest(manifest, source)
    manifest_bytes = canonical_json(manifest)
    manifest_sha256 = sha256_bytes(manifest_bytes)

    artifact_directory = artifact_directory.absolute()
    artifact_directory.mkdir(mode=0o755, parents=True, exist_ok=False)
    artifact_directory = artifact_directory.resolve(strict=True)
    copy_regular_file(
        image,
        artifact_directory / PREPARED_IMAGE_VHD,
        VIRTUAL_SIZE + 512,
        fingerprints["vhd"],
    )
    manifest_path = artifact_directory / PREPARED_IMAGE_MANIFEST
    with manifest_path.open("xb") as output:
        output.write(manifest_bytes)
        output.flush()
        os.fsync(output.fileno())
    if {path.name for path in artifact_directory.iterdir()} != PREPARED_IMAGE_FILES:
        raise ValueError("Prepared-image export contains unexpected files")
    return manifest_sha256


def load_prepared_image_artifact(artifact_directory, expected_manifest_sha256,
                                 expected_source):
    require_sha256(expected_manifest_sha256, "Expected manifest fingerprint")
    artifact_argument = artifact_directory.absolute()
    if artifact_argument.is_symlink():
        raise ValueError("Prepared-image artifact directory must not be a symlink")
    artifact_directory = artifact_argument.resolve(strict=True)
    if not artifact_directory.is_dir():
        raise ValueError("Prepared-image artifact must be a directory")
    entries = {path.name: path for path in artifact_directory.iterdir()}
    if set(entries) != PREPARED_IMAGE_FILES:
        raise ValueError("Prepared-image artifact contains unexpected files")
    manifest, manifest_bytes = load_strict_json(
        entries[PREPARED_IMAGE_MANIFEST],
        MAX_MANIFEST_SIZE,
        "Prepared-image manifest",
        canonical=True,
    )
    if sha256_bytes(manifest_bytes) != expected_manifest_sha256:
        raise ValueError("Prepared-image manifest does not match the trusted digest")
    details = validate_prepared_image_manifest(manifest, expected_source)
    return artifact_directory, manifest, manifest_bytes, details


def import_prepared_image(artifact_directory, directory, miz,
                          expected_manifest_sha256, expected_source,
                          location, vm_size):
    validate_deployment_config(location, vm_size)
    artifact_directory, manifest, manifest_bytes, details = (
        load_prepared_image_artifact(
            artifact_directory, expected_manifest_sha256, expected_source
        )
    )
    miz = miz.resolve(strict=True)
    if not os.access(miz, os.X_OK):
        raise ValueError("Import miz executable is not executable")
    import_miz_sha256 = image_sha256(miz)

    directory = directory.absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    directory = directory.resolve(strict=True)
    configure_tool_directories(directory)
    state_path = directory / "state.json"
    state = {
        "schema_version": STATE_SCHEMA_VERSION,
        "phase": "preparing",
        "name_prefix": "uk-hv-" + secrets.token_hex(10),
        "location": location,
        "vm_size": vm_size,
        "platform_marker": details["platform_marker"],
        "efi_sha256": details["efi_sha256"],
        "raw_sha256": details["raw_sha256"],
        "image_sha256": details["vhd_sha256"],
        "source_miz_executable_sha256": details["miz_sha256"],
        "import_miz_executable_sha256": import_miz_sha256,
    }
    save_json(state_path, state)
    manifest_path = directory / PREPARED_IMAGE_MANIFEST
    with manifest_path.open("xb") as output:
        output.write(manifest_bytes)
        output.flush()
        os.fsync(output.fileno())
    image = directory / PREPARED_IMAGE_VHD
    copy_regular_file(
        artifact_directory / PREPARED_IMAGE_VHD,
        image,
        details["vhd_size"],
        details["vhd_sha256"],
    )
    report = miz_command(miz, [
        "check-efi-application", "--output=json", "--architecture", "x86_64",
        "--expected-efi-sha256", details["efi_sha256"],
        "--expected-virtual-size", "66M", str(image),
    ], directory / "miz-import-check.log", json_output=True)
    check_packaging_report(report, details["efi_sha256"], image.stat().st_size)
    checked_contract = {
        key: report[key] for key in manifest["packaging"]
    }
    if canonical_json(checked_contract) != canonical_json(manifest["packaging"]):
        raise ValueError("Imported VHD packaging differs from the trusted manifest")
    save_json(directory / "packaging.json", report)
    if image_sha256(image) != details["vhd_sha256"]:
        raise ValueError("Imported VHD changed during packaging validation")
    state.update(
        phase="prepared",
        prepared_image_import={
            "contract": PREPARED_IMAGE_SCHEMA,
            "manifest_sha256": expected_manifest_sha256,
            "source": details["source"],
        },
        trusted_platform_boot_modes=details["boots"],
    )
    save_json(state_path, state)
    return directory


def validate_prepared_run_provenance(state, directory):
    if state.get("local_platform_boot") is True:
        return
    receipt = require_exact_fields(
        state.get("prepared_image_import"),
        ("contract", "manifest_sha256", "source"),
        "Prepared-image import receipt",
    )
    if receipt["contract"] != PREPARED_IMAGE_SCHEMA:
        raise ValueError("Prepared-image import receipt has an invalid contract")
    manifest, manifest_bytes = load_strict_json(
        directory / PREPARED_IMAGE_MANIFEST,
        MAX_MANIFEST_SIZE,
        "Imported prepared-image manifest",
        canonical=True,
    )
    if sha256_bytes(manifest_bytes) != require_sha256(
        receipt["manifest_sha256"], "Imported manifest fingerprint"
    ):
        raise ValueError("Imported prepared-image manifest has changed")
    source = validate_prepared_image_source(receipt["source"])
    details = validate_prepared_image_manifest(manifest, source)
    if (
        state.get("image_sha256") != details["vhd_sha256"]
        or state.get("efi_sha256") != details["efi_sha256"]
        or state.get("raw_sha256") != details["raw_sha256"]
        or state.get("platform_marker") != details["platform_marker"]
        or state.get("trusted_platform_boot_modes") != details["boots"]
    ):
        raise ValueError("Private state does not match its trusted prepared image")


def quota_count(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    raise ValueError("Azure CLI returned an invalid nonnegative quota count")


def check_subscription(location, vm_size):
    account = azure_cli(["account", "show"])
    if account.get("state") != "Enabled" or account.get("environmentName") != "AzureCloud":
        raise RuntimeError("An enabled Azure public-cloud subscription is required")
    subscription = account["id"]
    for namespace in ("Microsoft.Compute", "Microsoft.Network"):
        registration = azure_cli([
            "provider", "show", "--namespace", namespace,
            "--query", "registrationState",
        ], subscription=subscription)
        if registration != "Registered":
            raise RuntimeError(f"{namespace} must already be registered")
    versions = azure_cli([
        "provider", "show", "--namespace", "Microsoft.Compute",
        "--query", "resourceTypes[?resourceType=='virtualMachines'].apiVersions | [0]",
    ], subscription=subscription)
    if "2025-11-01" not in versions:
        raise RuntimeError("Compute API 2025-11-01 is required for explicit Standard security")
    skus = azure_cli([
        "vm", "list-skus", "--all", "--location", location,
        "--resource-type", "virtualMachines", "--size", vm_size,
        "--query", f"[?name=='{vm_size}']",
    ], subscription=subscription)
    if len(skus) != 1 or skus[0].get("restrictions") != []:
        raise RuntimeError("Requested VM size is not unrestricted in this region/subscription")
    capabilities = {entry["name"]: entry["value"] for entry in skus[0]["capabilities"]}
    if (
        "V2" not in capabilities.get("HyperVGenerations", "").split(",")
        or capabilities.get("CpuArchitectureType") != "x64"
        or capabilities.get("vCPUs") != "2"
    ):
        raise RuntimeError("A two-vCPU x86-64 Generation 2 VM size is required")
    family = skus[0]["family"]
    usage = azure_cli([
        "vm", "list-usage", "--location", location,
        "--query", f"[?name.value=='cores' || name.value=='{family}']",
    ], subscription=subscription)
    limits = {entry["name"]["value"]: entry for entry in usage}
    for name in ("cores", family):
        if name not in limits:
            raise RuntimeError(f"Missing quota information for {name} in {location}")
        available = quota_count(limits[name]["limit"]) - quota_count(limits[name]["currentValue"])
        if available < 2:
            raise RuntimeError(f"Insufficient two-vCPU quota for {name} in {location}")
    return subscription


class AzureRun:
    def __init__(self, state, state_path):
        self.state = state
        self.state_path = state_path
        self.prefix = state["name_prefix"]
        if not re.fullmatch(r"[a-z][a-z0-9-]{5,31}", self.prefix):
            raise ValueError("Invalid run name prefix")
        if not re.fullmatch(r"[0-9a-f]{64}", state["image_sha256"]):
            raise ValueError("Invalid image SHA256")
        self.group = self.prefix + "-rg"
        self.vm = self.prefix + "-vm"
        self.disk = self.prefix + "-os"
        self.tags = {
            "managed-by": MANAGED_BY,
            "unikraft-run": self.prefix,
            "image-sha256": state["image_sha256"],
        }

    def az(self, arguments, **kwargs):
        return azure_cli(
            arguments, subscription=self.state["subscription"], **kwargs
        )

    def record(self, phase, **fields):
        self.state.update(fields)
        self.state["phase"] = phase
        save_json(self.state_path, self.state)

    def require_owned(self, resource):
        tags = resource.get("tags") or {}
        if any(tags.get(key) != value for key, value in self.tags.items()):
            raise RuntimeError(
                f"Refusing to use a resource without this run's ownership tags: "
                f"{resource.get('id', resource.get('name', '<unknown>'))}"
            )

    def resource_tags(self):
        return [f"{key}={value}" for key, value in self.tags.items()]

    def create_group(self):
        if self.az(["group", "exists", "--name", self.group]) is not False:
            raise RuntimeError(f"Refusing to adopt existing resource group {self.group}")
        self.record("creating-group")
        group = self.az([
            "group", "create", "--name", self.group,
            "--location", self.state["location"],
            "--tags", *self.resource_tags(),
        ])
        self.require_owned(group)
        self.record("group-created")

    def upload_disk(self, image):
        self.record("creating-disk")
        disk = self.az([
            "disk", "create", "--resource-group", self.group,
            "--name", self.disk, "--location", self.state["location"],
            "--upload-type", "Upload", "--upload-size-bytes", str(image.stat().st_size),
            "--hyper-v-generation", "V2", "--os-type", "Linux",
            "--sku", "Standard_LRS", "--tags", *self.resource_tags(),
        ], timeout=600)
        self.require_owned(disk)
        self.record("uploading-disk", disk_id=disk["id"])
        try:
            grant = self.az([
                "disk", "grant-access", "--resource-group", self.group,
                "--name", self.disk, "--access-level", "Write",
                "--duration-in-seconds", "1800",
            ], private=True)
            endpoint, sas = upload_endpoint(disk_access_sas(grant))
            upload_managed_vhd(image, endpoint, sas)
        except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
            print(f"Disk upload did not complete: {error}", file=sys.stderr)
            raise
        finally:
            self.az([
                "disk", "revoke-access", "--resource-group", self.group,
                "--name", self.disk,
            ])
        disk = self.az([
            "disk", "show", "--resource-group", self.group, "--name", self.disk,
        ])
        self.require_owned(disk)
        if (
            disk.get("diskState") != "Unattached"
            or disk.get("provisioningState") != "Succeeded"
            or disk.get("hyperVGeneration") != "V2"
            or disk.get("osType") != "Linux"
        ):
            raise RuntimeError("Uploaded disk is not a successfully imported Gen2 Linux disk")
        self.record("disk-ready")

    def deploy_vm(self):
        self.record("deploying-vm")
        self.az([
            "deployment", "group", "create", "--resource-group", self.group,
            "--name", self.prefix, "--mode", "Incremental",
            "--template-file", str(SUPPORT / "azure" / "hyperv-gen2.json"),
            "--parameters",
            f"namePrefix={self.prefix}", f"location={self.state['location']}",
            f"osDiskId={self.state['disk_id']}",
            f"imageSha256={self.state['image_sha256']}",
            f"vmSize={self.state['vm_size']}",
        ], timeout=900)
        vm = self.az([
            "vm", "show", "--resource-group", self.group, "--name", self.vm,
        ])
        self.require_owned(vm)
        if vm.get("provisioningState") != "Succeeded":
            raise RuntimeError("VM provisioning did not complete successfully")
        attached = vm.get("storageProfile", {}).get("osDisk", {}).get("managedDisk", {}).get("id")
        if not attached or attached.lower() != self.state["disk_id"].lower():
            raise RuntimeError("VM is not attached to this run's imported disk")
        # Azure represents Standard VMs with a null securityProfile.
        security = vm.get("securityProfile")
        if security is not None and (
            not isinstance(security, dict) or security.get("securityType") != "Standard"
        ):
            raise RuntimeError("VM is not using the requested Standard security type")
        self.record("vm-created", vm_id=vm["id"])

    def cleanup(self):
        if self.az(["group", "exists", "--name", self.group]) is False:
            self.record("cleaned")
            return
        group = self.az(["group", "show", "--name", self.group])
        self.require_owned(group)
        resources = self.az(["resource", "list", "--resource-group", self.group])
        for resource in resources:
            self.require_owned(resource)
        self.record("deleting-group")
        self.az(["group", "delete", "--name", self.group, "--yes"], timeout=900)
        if self.az(["group", "exists", "--name", self.group]) is not False:
            raise RuntimeError("Resource group deletion has not completed")
        self.record("cleaned")

    def wait_for_boot(self, stage, timeout):
        deadline = time.monotonic() + timeout
        self.record("waiting-for-boot")
        while time.monotonic() < deadline:
            try:
                text = self.az([
                    "vm", "boot-diagnostics", "get-boot-log",
                    "--resource-group", self.group, "--name", self.vm,
                ], private=True,
                    timeout=max(1, min(120, deadline - time.monotonic())))
            except AzureCliError as error:
                if error.code not in ("BlobNotFound", "BootDiagnosticsInformationNotAvailable"):
                    raise
                print(f"Serial console is not ready: {error.code}", file=sys.stderr)
                self.record("waiting-for-boot", serial_wait_code=error.code)
            else:
                if not isinstance(text, str):
                    raise RuntimeError("Azure CLI did not return a JSON serial-log string")
                if len(text.encode("utf-8")) > 4 * 1024 * 1024:
                    raise RuntimeError("Serial log exceeded the 4 MiB evidence limit")
                (self.state_path.parent / "serial.log").write_text(text)
                result = inspect_boot_log(text, self.state["platform_marker"])
                save_json(self.state_path.parent / "acceptance.json", result)
                if result["crashes"] or (stage == "io" and result["failures"]):
                    raise RuntimeError("Guest reported an acceptance failure; see serial.log")
                if result[f"{stage}_ready"]:
                    self.record("accepted", acceptance_stage=stage)
                    return result
            time.sleep(min(30, max(0, deadline - time.monotonic())))
        raise RuntimeError(
            f"Timed out waiting for {stage} acceptance; see saved serial.log and acceptance.json"
        )


def inspect_boot_log(text, platform_marker=PLATFORM_READY):
    lines = [
        ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
        for line in text.splitlines()
    ]
    positions = {
        marker: lines.index(marker)
        for marker in (platform_marker, BLOCK_READY, NETWORK_READY, IO_READY)
        if marker in lines
    }
    crashes = [
        line for line in lines
        if any(marker in line for marker in (
            "Unikraft Crash", "Assertion failure", "Exception Type"
        ))
    ]
    failures = [
        line for line in lines
        if line.startswith((
            "UK_HYPERV_ACCEPTANCE_FAIL:",
            "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:",
        ))
    ]
    failures.extend(
        line for line in lines
        if re.search(r"\bmain returned (?!0\b)-?\d+\b", line)
    )
    complete = all(
        marker in positions
        for marker in (platform_marker, BLOCK_READY, NETWORK_READY, IO_READY)
    )
    ordered = complete and (
        positions[platform_marker] < positions[BLOCK_READY] < positions[IO_READY]
        and positions[platform_marker] < positions[NETWORK_READY] < positions[IO_READY]
    )
    if IO_READY in positions and not ordered:
        failures.append("I/O-ready marker is missing its preceding stage markers")
    return {
        "platform_ready": platform_marker in positions and not crashes,
        "block_read": BLOCK_READY in positions and not crashes,
        "network_exchange": NETWORK_READY in positions and not crashes,
        "io_ready": bool(ordered and not crashes and not failures),
        "crashes": crashes,
        "failures": failures,
    }


def run_prepared(directory, stage, timeout, keep_resources):
    if stage not in ("platform", "io") or not 30 <= timeout <= 1800:
        raise ValueError("Expected platform/io stage and a timeout between 30 and 1800 seconds")
    state, state_path = load_state(directory)
    if state.get("phase") != "prepared":
        raise ValueError("Run requires a newly prepared image")
    validate_prepared_run_provenance(state, state_path.parent)
    image = state_path.parent / "unikraft.vhd"
    if image_sha256(image) != state["image_sha256"]:
        raise ValueError("Prepared VHD has changed since the local boot")
    check_upload_dependencies()
    state["subscription"] = check_subscription(state["location"], state["vm_size"])
    save_json(state_path, state)
    run = AzureRun(state, state_path)
    try:
        run.create_group()
        run.upload_disk(image)
        if image_sha256(image) != state["image_sha256"]:
            raise ValueError("VHD changed during upload")
        run.deploy_vm()
        return run.wait_for_boot(stage, timeout)
    finally:
        if state["phase"] != "prepared" and not keep_resources:
            run.cleanup()


def cleanup_state(directory):
    state, path = load_state(directory)
    if "subscription" not in state:
        if (
            state.get("phase") not in ("preparing", "prepared", "cleaned")
            or "disk_id" in state or "vm_id" in state
        ):
            raise ValueError("Incomplete Azure ownership state; subscription is missing")
        state["phase"] = "cleaned"
        save_json(path, state)
        return
    AzureRun(state, path).cleanup()


def add_provenance_arguments(parser, prefix):
    parser.add_argument(f"--{prefix}-repository", required=True)
    parser.add_argument(f"--{prefix}-repository-id", type=int, required=True)
    parser.add_argument(f"--{prefix}-workflow-ref", required=True)
    parser.add_argument(f"--{prefix}-job", required=True)
    parser.add_argument(f"--{prefix}-run-id", type=int, required=True)
    parser.add_argument(f"--{prefix}-run-attempt", type=int, required=True)
    parser.add_argument(f"--{prefix}-head-sha", required=True)


def provenance_from_args(args, prefix):
    attribute = prefix.replace("-", "_")
    return prepared_image_source(
        getattr(args, f"{attribute}_repository"),
        getattr(args, f"{attribute}_repository_id"),
        getattr(args, f"{attribute}_workflow_ref"),
        getattr(args, f"{attribute}_job"),
        getattr(args, f"{attribute}_run_id"),
        getattr(args, f"{attribute}_run_attempt"),
        getattr(args, f"{attribute}_head_sha"),
    )


def main():
    parser = argparse.ArgumentParser(
        description="Unikraft Hyper-V/Azure acceptance evidence"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    inspect = subparsers.add_parser("inspect-log")
    inspect.add_argument("log", type=Path)
    inspect.add_argument("--stage", choices=("platform", "io"), default="io")
    inspect.add_argument("--expect", default=PLATFORM_READY)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--efi", type=Path, required=True)
    prepare.add_argument("--miz", type=Path, required=True)
    prepare.add_argument("--state-dir", type=Path, required=True)
    prepare.add_argument("--ovmf-code", type=Path, required=True)
    prepare.add_argument("--ovmf-vars", type=Path, required=True)
    prepare.add_argument("--qemu", default="qemu-system-x86_64")
    prepare.add_argument("--expect", default=PLATFORM_READY)
    prepare.add_argument("--timeout", type=int, default=30)
    prepare.add_argument("--location", default="westus2")
    prepare.add_argument("--vm-size", default="Standard_D2s_v5", choices=VM_SIZES)
    export = subparsers.add_parser("export-prepared")
    export.add_argument("--state-dir", type=Path, required=True)
    export.add_argument("--artifact-dir", type=Path, required=True)
    add_provenance_arguments(export, "source")
    import_image = subparsers.add_parser("import-prepared")
    import_image.add_argument("--artifact-dir", type=Path, required=True)
    import_image.add_argument("--state-dir", type=Path, required=True)
    import_image.add_argument("--miz", type=Path, required=True)
    import_image.add_argument("--expected-manifest-sha256", required=True)
    add_provenance_arguments(import_image, "expected")
    import_image.add_argument("--location", default="westus2")
    import_image.add_argument(
        "--vm-size", default="Standard_D2s_v5", choices=VM_SIZES
    )
    run = subparsers.add_parser("run")
    run.add_argument("--state-dir", type=Path, required=True)
    run.add_argument("--stage", choices=("platform", "io"), default="io")
    run.add_argument("--timeout", type=int, default=300)
    run.add_argument("--keep-resources", action="store_true")
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "inspect-log":
            result = inspect_boot_log(args.log.read_text(errors="replace"), args.expect)
            print(json.dumps(result, indent=2))
            if not result[f"{args.stage}_ready"]:
                raise SystemExit(1)
        elif args.action == "prepare":
            directory = prepare_image(args)
            print(f"Image prepared and locally booted; private run state: {directory}")
        elif args.action == "export-prepared":
            digest = export_prepared_image(
                args.state_dir,
                args.artifact_dir,
                provenance_from_args(args, "source"),
            )
            print(digest)
        elif args.action == "import-prepared":
            directory = import_prepared_image(
                args.artifact_dir,
                args.state_dir,
                args.miz,
                args.expected_manifest_sha256,
                provenance_from_args(args, "expected"),
                args.location,
                args.vm_size,
            )
            print(f"Prepared image imported into private run state: {directory}")
        elif args.action == "run":
            if not 30 <= args.timeout <= 1800:
                parser.error("--timeout must be between 30 and 1800 seconds")
            result = run_prepared(
                args.state_dir, args.stage, args.timeout, args.keep_resources
            )
            print(json.dumps(result, indent=2))
        elif args.action == "cleanup":
            cleanup_state(args.state_dir)
            print("No Azure resources remain for this run")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
