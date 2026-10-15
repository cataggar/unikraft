# SPDX-License-Identifier: BSD-3-Clause
"""Real miz images plus synthetic local observations for v2 lineage tests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

SDK = "a53205d77be3b880eb8f8b96679512ba58e2331a"
SOURCE = "2830293aaf1df37877cddf4dae97f5cf255b9ae2"
TREE = "1234567890abcdef1234567890abcdef12345678"
MODES = (
    "raw-x2apic", "raw-legacy-apic",
    "qcow2-x2apic", "qcow2-legacy-apic",
    "vpc-x2apic", "vpc-legacy-apic",
)
ROLES = (
    "efi", "debug_elf", "bootinfo", "raw", "qcow2", "vhd",
    "runtime", "compiler", "wasm", "cwasm", "config",
    "runtime_identity", "image_identity", "local_result", "package",
    "build", "build_start", "boot_inputs",
    "qcow2_finalization_intent", "qcow2_finalization",
    "qcow2_acceptance", "fixed_vhd_derivation_intent",
    "fixed_vhd_derivation_gate", "fixed_vhd_derivation",
    "final_inspection", "cleanup",
)
STAGES = (
    "adapter", "config", "derive-fixed-vhd", "finalize-qcow2",
    "fixtures", "inspect", "local-boot-tool", "native-image",
    "package", "prepare", "qcow2-legacy-apic", "qcow2-x2apic",
    "raw-legacy-apic", "raw-x2apic", "vpc-legacy-apic",
    "vpc-x2apic",
)
RECORD_ROLES = {
    "build-start.json": "build_start",
    "build.json": "build",
    "boot-inputs.json": "boot_inputs",
    "package.json": "package",
    "qcow2-finalization-intent.json": "qcow2_finalization_intent",
    "qcow2-finalization.json": "qcow2_finalization",
    "qcow2-acceptance.json": "qcow2_acceptance",
    "fixed-vhd-derivation-intent.json":
        "fixed_vhd_derivation_intent",
    "fixed-vhd-derivation-gate.json": "fixed_vhd_derivation_gate",
    "fixed-vhd-derivation.json": "fixed_vhd_derivation",
}


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else encode(value))
    path.chmod(0o600)


def read(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path):
    return {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": digest(path),
    }


def metadata(path):
    value = path.stat()
    return [
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    ]


def observed(path, virtual_bytes):
    return {
        "path": str(path.resolve()),
        "sha256": digest(path),
        "file_bytes": path.stat().st_size,
        "allocated": {
            "state": "available",
            "bytes": path.stat().st_blocks * 512,
        },
        "virtual_bytes": virtual_bytes,
        "metadata": metadata(path),
    }


def limits():
    return {
        "max_input_bytes": 66 * 1024 * 1024,
        "max_output_bytes": 66 * 1024 * 1024 + 512,
        "max_virtual_bytes": 66 * 1024 * 1024,
        "max_partition_array_bytes": 1024 * 1024,
        "max_metadata_bytes": 128 * 1024,
        "max_metadata_work": 8194,
        "max_work_bytes": 4 * 66 * 1024 * 1024,
        "max_memory_bytes": 512 * 1024 * 1024,
        "max_workload_bytes": 64 * 1024 * 1024,
    }


def run(tool, *args):
    completed = subprocess.run(
        [tool, *args], env={}, capture_output=True, timeout=150)
    if completed.returncode:
        raise RuntimeError(completed.stderr)
    return json.loads(completed.stdout)


def make_efi(path):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    for offset, value in (
            (0x84, 0x8664), (0x86, 1), (0x94, 0xf0),
            (0x98, 0x20b), (0xdc, 10)):
        struct.pack_into("<H", data, offset, value)
    write(path, bytes(data))


def pin(path):
    value = path.stat()
    return {
        "device_major": os.major(value.st_dev),
        "device_minor": os.minor(value.st_dev),
        "inode": value.st_ino,
        "mode": value.st_mode,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_seconds": value.st_mtime_ns // 1_000_000_000,
        "mtime_nanoseconds": value.st_mtime_ns % 1_000_000_000,
        "ctime_seconds": value.st_ctime_ns // 1_000_000_000,
        "ctime_nanoseconds": value.st_ctime_ns % 1_000_000_000,
        "sha256": list(bytes.fromhex(digest(path))),
    }


def result(identity):
    return {
        "version": 1, "workload": "tiny", "wamr_revision": SDK,
        "wasm_sha256": identity["wasm_sha256"],
        "cwasm_sha256": identity["cwasm_sha256"],
        "runtime_sha256": identity["runtime_sha256"],
        "platform_status": 0, "checks": 2, "answer": 42,
        "terminal": 1, "detail": 2, "reserved_bytes": 0,
        "frame_bytes": 0, "accessible_bytes": 0,
        "allocation_bytes": 0, "system_page_table_bytes": 4096,
        "error_name": "",
    }


def serial(index, identity):
    lines = [
        f"synthetic boot {index}",
        "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:",
        "Powered by",
        "Calling main(0, 0)",
        "WAMR_NATIVE_COMPUTE=" + json.dumps(
            result(identity), separators=(",", ":")),
        "WAMR_NATIVE_AOT_OK answer=42 teardown=0",
        "[    1.000001] Info: [libukboot] main returned 0",
        "",
    ]
    if index % 2:
        lines.insert(1, "Using legacy xAPIC MMIO")
    return "\n".join(lines).encode()


def build(root, package_tool):
    root.mkdir(mode=0o700)
    artifacts = root / "artifacts"
    evidence = root / "evidence"
    boots = root / "boots"
    state = root / "state"
    for path in (artifacts, evidence, boots, state):
        path.mkdir(mode=0o700)
    make_efi(root / "workload.efi")
    package = run(
        package_tool, "package", root / "workload.efi", state)
    raw = package["image"]["raw"]
    efi = package["image"]["efi"]
    finalize_intent = {
        "schema": "uk.wamr.compute-qcow2-finalization-intent",
        "schema_version": 1,
        "source_path": str((state / "unikraft.raw").resolve()),
        "expected_source_sha256": raw["sha256"],
        "expected_source_bytes": raw["size"],
        "expected_virtual_bytes": raw["size"],
        "expected_workload_sha256": efi["sha256"],
        "expected_workload_bytes": efi["size"],
        "timeout_ms": 120_000,
        "limits": limits(),
    }
    write(root / "finalize-intent.json", finalize_intent)
    finalization = run(
        package_tool, "finalize-qcow2",
        root / "finalize-intent.json", state)
    derive_intent = {
        "schema": "uk.wamr.compute-fixed-vhd-derivation-intent",
        "schema_version": 1,
        "source_path": str((state / "unikraft.qcow2").resolve()),
        "accepted_qcow2_sha256": finalization["output"]["sha256"],
        "expected_source_bytes": finalization["output"]["file_bytes"],
        "expected_capacity_bytes": finalization["output"]["virtual_bytes"],
        "timeout_ms": 120_000,
        "limits": limits(),
    }
    write(root / "derive-intent.json", derive_intent)
    derivation = run(
        package_tool, "derive-fixed-vhd",
        root / "derive-intent.json", state)

    for name, source in {
            "efi": root / "workload.efi",
            "raw": state / "unikraft.raw",
            "qcow2": state / "unikraft.qcow2",
            "vhd": state / "unikraft-derived.vhd",
    }.items():
        shutil.copyfile(source, artifacts / name)
        (artifacts / name).chmod(0o600)
    for name in (
            "debug_elf", "bootinfo", "runtime", "compiler",
            "wasm", "cwasm", "config"):
        write(artifacts / name, f"fixture-{name}\n".encode())
    identity = {
        "wamr_revision": SDK,
        **{
            name + "_sha256": digest(artifacts / role)
            for name, role in (
                ("wasm", "wasm"), ("cwasm", "cwasm"),
                ("runtime", "runtime"), ("compiler", "compiler"),
                ("config", "config"),
            )
        },
    }
    write(artifacts / "runtime_identity", {"fixture": True})
    write(artifacts / "image_identity", {"fixture": True})
    build_record = {
        "source": {"revision": SOURCE, "tree": TREE},
        "runtime": {
            "wamr_revision": SDK,
            "minimal_wasi": False,
            "compiler_profile": "unikraft-x86_64",
            "zig_version": "0.16.0",
            "files": {
                "tiny.wasm": identity["wasm_sha256"],
                "tiny.cwasm": identity["cwasm_sha256"],
                "wamrc": identity["compiler_sha256"],
                "libwamr-aot.a": identity["runtime_sha256"],
            },
        },
        "image": {
            "unikraft_revision": SOURCE,
            "runtime_inputs_sha256": digest(
                artifacts / "runtime_identity"),
            "solved_config_sha256": identity["config_sha256"],
            "files": {
                "wamr_hyperv-x86_64-efi": digest(artifacts / "efi"),
                "wamr_hyperv-x86_64-efi.dbg":
                    digest(artifacts / "debug_elf"),
                "wamr_hyperv-x86_64-efi.bootinfo":
                    digest(artifacts / "bootinfo"),
            },
        },
    }
    write(evidence / "build.json", build_record)
    write(evidence / "build-start.json", {
        "source": build_record["source"]})
    write(evidence / "package.json", package)
    write(evidence / "boot-inputs.json", {
        "files": {
            "package_tool": {
                "path": str(package_tool),
                "sha256": digest(package_tool),
                "metadata": metadata(package_tool),
            },
        },
    })

    for index, mode in enumerate(MODES):
        directory = boots / mode
        directory.mkdir(mode=0o700)
        image = artifacts / (
            "raw" if index < 2 else "qcow2" if index < 4 else "vhd")
        kind = (
            "raw_disk" if index < 2 else
            "qcow2" if index < 4 else "fixed_vhd")
        pins = [
            pin(image), pin(artifacts / "efi"),
            pin(artifacts / "config"), pin(artifacts / "runtime"),
        ]
        request = {
            "schema_version": 2,
            "supervisor_pid": 12345,
            "config": {
                "source": {"kind": kind, "path": str(image)},
                "expect": "WAMR_NATIVE_AOT_OK answer=42 teardown=0",
                "expect_main_return": 0,
                "cpus": 1,
                "timeout_ms": 60000,
                "disable_x2apic": bool(index % 2),
            },
            "pins": pins,
        }
        write(directory / "request", request)
        raw_serial = serial(index, identity)
        write(directory / "serial", raw_serial)
        report = {
            "schema_version": 1,
            "scope": "public_local_qemu_only",
            "acceptance": "not_established",
            "passed": True,
            "consumed": True,
            "cleanup_complete": True,
            "input_unchanged": True,
            "serial_valid": True,
            "serial_limit_reached": False,
            "serial_bytes": len(raw_serial),
            "serial_sha256": hashlib.sha256(raw_serial).hexdigest(),
            "termination": {"exited": 0},
            "failures": {
                "primary": None, "cleanup": None, "recording": None},
        }
        write(directory / "report", report)
        write(directory / "compute", {
            "scope": "local_native_compute_only",
            "report": report,
            "input_pins": pins,
            "request_sha256": digest(directory / "request"),
            "report_sha256": digest(directory / "report"),
            "compute": result(identity),
        })

    write(evidence / "qcow2-finalization-intent.json", finalize_intent)
    write(evidence / "qcow2-finalization.json", finalization)
    write(evidence / "fixed-vhd-derivation-intent.json", derive_intent)
    write(evidence / "fixed-vhd-derivation.json", derivation)
    for stage in STAGES:
        write(evidence / f"command-{stage}.json", {"stage": stage})
    write(artifacts / "cleanup", b"primary=0 cleanup=0\n")
    seal(root)
    return root / "bundle.json"


def boot_hashes(root, mode):
    directory = root / "boots" / mode
    return {
        name + "_sha256": digest(directory / name)
        for name in ("request", "report", "serial", "compute")
    }


def seal(root):
    artifacts = root / "artifacts"
    evidence = root / "evidence"
    boots = root / "boots"
    identity = {
        "wamr_revision": SDK,
        **{
            name + "_sha256": digest(artifacts / role)
            for name, role in (
                ("wasm", "wasm"), ("cwasm", "cwasm"),
                ("runtime", "runtime"), ("compiler", "compiler"),
                ("config", "config"),
            )
        },
    }
    for mode in MODES:
        directory = boots / mode
        report = read(directory / "report")
        compute = read(directory / "compute")
        compute.update(
            report=report,
            input_pins=read(directory / "request")["pins"],
            request_sha256=digest(directory / "request"),
            report_sha256=digest(directory / "report"),
        )
        write(directory / "compute", compute)
        write(evidence / f"{mode}-compute.json", compute)

    raw_size = (artifacts / "raw").stat().st_size
    acceptance_path = evidence / "qcow2-acceptance.json"
    acceptance = read(acceptance_path) if acceptance_path.exists() else {
        "schema": "uk.wamr.compute-qcow2-acceptance",
        "schema_version": 1,
        "profile": "qcow2-derived-vhd",
        "status": "accepted",
        "source": {"revision": SOURCE, "tree": TREE},
        "accepted_qcow2": observed(artifacts / "qcow2", raw_size),
        "modes": list(MODES[:4]),
        "boots": {mode: {} for mode in MODES[:4]},
    }
    acceptance.update(
        finalization_sha256=digest(
            evidence / "qcow2-finalization.json"),
        build_sha256=digest(evidence / "build.json"),
        boot_inputs_sha256=digest(evidence / "boot-inputs.json"),
    )
    for mode in tuple(acceptance["boots"]):
        acceptance["boots"][mode] = boot_hashes(root, mode)
    write(acceptance_path, acceptance)

    gate_path = evidence / "fixed-vhd-derivation-gate.json"
    gate = read(gate_path) if gate_path.exists() else {
        "schema": "uk.wamr.compute-fixed-vhd-derivation-gate",
        "schema_version": 1,
        "profile": "qcow2-derived-vhd",
        "status": "accepted_qcow2_only",
        "accepted_qcow2_sha256": digest(artifacts / "qcow2"),
        "derived_output_absent": True,
    }
    gate.update(
        qcow2_acceptance_sha256=digest(acceptance_path),
        derivation_intent_sha256=digest(
            evidence / "fixed-vhd-derivation-intent.json"),
    )
    write(gate_path, gate)

    inspection_path = evidence / "final-inspection.json"
    inspection = read(inspection_path) if inspection_path.exists() else {
        "schema": "uk.wamr.compute-image-chain-inspection",
        "schema_version": 1,
        "profile": "qcow2-derived-vhd",
        "status": "complete",
        "source": {"revision": SOURCE, "tree": TREE},
        "artifacts": {
            "efi": observed(
                artifacts / "efi", (artifacts / "efi").stat().st_size),
            "raw": observed(artifacts / "raw", raw_size),
            "qcow2": observed(artifacts / "qcow2", raw_size),
            "vhd": observed(
                artifacts / "vhd",
                (artifacts / "vhd").stat().st_size - 512),
        },
        "modes": list(MODES),
        "boots": {mode: {} for mode in MODES},
        "records": {},
    }
    for mode in tuple(inspection["boots"]):
        inspection["boots"][mode] = boot_hashes(root, mode)
    for name in tuple(RECORD_ROLES):
        inspection["records"][name] = digest(evidence / name)
    write(inspection_path, inspection)

    for name, role in RECORD_ROLES.items():
        shutil.copyfile(evidence / name, artifacts / role)
        (artifacts / role).chmod(0o600)
    shutil.copyfile(inspection_path, artifacts / "final_inspection")
    (artifacts / "final_inspection").chmod(0o600)
    names = sorted(path.name for path in evidence.glob("*.json"))
    if len(names) != 33:
        raise AssertionError(names)
    local_result = {
        "schema_version": 2,
        "profile": "qcow2-derived-vhd",
        "scope": "local_native_compute_only",
        "passed": True,
        "hardware_acceptance": "not_established",
        "cloud_authority": "not_admitted",
        "benchmark": "not_measured",
        "workload": "tiny",
        "modes": list(MODES),
        "records": {name: digest(evidence / name) for name in names},
    }
    write(artifacts / "local_result", local_result)

    values = [artifact(artifacts / role) for role in ROLES]
    by_name = dict(zip(ROLES, values))
    bundle_path = root / "bundle.json"
    bundle = read(bundle_path) if bundle_path.exists() else {
        "schema": "uk.wamr.local-image-handoff",
        "version": 2,
        "profile": "qcow2-derived-vhd",
        "authority": "not_admitted",
        "source_revision": SOURCE,
        "source_tree": TREE,
        "run": {
            "repository": "cataggar/unikraft",
            "run_id": "1234567",
            "run_attempt": "1",
        },
    }
    bundle.update(
        identity=identity,
        lineage={
            "raw_sha256": by_name["raw"]["sha256"],
            "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
            "derived_vhd_sha256": by_name["vhd"]["sha256"],
            "qcow2_finalization_sha256":
                by_name["qcow2_finalization"]["sha256"],
            "qcow2_acceptance_sha256":
                by_name["qcow2_acceptance"]["sha256"],
            "fixed_vhd_derivation_gate_sha256":
                by_name["fixed_vhd_derivation_gate"]["sha256"],
            "fixed_vhd_derivation_sha256":
                by_name["fixed_vhd_derivation"]["sha256"],
            "final_inspection_sha256":
                by_name["final_inspection"]["sha256"],
        },
        artifacts=values,
        boots=[
            {
                "mode": mode,
                **{
                    name: artifact(boots / mode / name)
                    for name in ("serial", "request", "report", "compute")
                },
            }
            for mode in MODES
        ],
        evidence=[artifact(evidence / name) for name in names],
    )
    write(bundle_path, bundle)
