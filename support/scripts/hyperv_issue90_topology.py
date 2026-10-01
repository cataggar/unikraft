#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Default-off, single-boot, read-only #90 StorVSC Azure acceptance lane.

Plan a private directory with an explicit subscription. Build a fresh EFI
image with CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY=y, the printed run/disk
IDs, 8388608 sectors for each disk, nonzero LUN 7, at least three controller
slots and two LUNs per controller. The older hyperv-azure.py prepare opens a
raw prefix in VHD mode; only the separate offline admission's native raw/vpc
boots can prove both formats and both APIC modes. Preparation remains blocked
until a reviewed-source, solved-config-to-EFI build proof exists; finding
the IDs in the EFI is not that proof. Live allocation is separately disabled
until owner-checked cleanup can handle a lost Azure create response without
adopting an unproven replacement. Interrupted cloud state may ONLY be cleaned,
never redeployed. No #89 grant is consumed.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time
import uuid
import zlib

azure = importlib.import_module("hyperv-azure")
seed_producer = importlib.import_module("hyperv-storage-manifest")

TEMPLATE = Path(__file__).resolve().parents[1] / "azure/hyperv-issue90-topology.json"
TEMPLATE_SHA256 = "13374637446db9b010c4a212774f5d28b484d84ce490ff5ae6c4da10d0ea089b"
COMPUTE_API_VERSION = "2025-11-01"
SCHEMA = "unikraft.hyperv.issue90-one-boot-topology"
PURPOSE = "issue90-read-only-topology"
SECTORS = 4 * 1024**3 // 512
DISK_BYTES = SECTORS * 512
LUNS = {"data0": 0, "data7": 7}
ROLES = ("os", "data0", "data7")
RESOURCE_ROLES = ("os", "data0", "data7", "nsg", "vnet", "nic", "vm")
OUTPUT_ROLES = {
    "vmId": "vm", "osDiskId": "os", "dataDisk0Id": "data0",
    "dataDisk7Id": "data7", "nicId": "nic", "vnetId": "vnet",
    "nsgId": "nsg",
}
GIB = 1024**3
UPLOAD_STATES = ("ReadyToUpload", "ActiveUpload")
MAX_RUNTIME = 3600
CLEANUP_HEADROOM = 2400
MAX_SERIAL = 4 * 1024 * 1024
NAME = re.compile(r"uk90-[0-9a-f]{20}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
INFO = re.compile(
    r"HYPERV_TOPOLOGY TARGET INFO id=(\d+) controller=(\d+) "
    r"channel=(\d+) address=(\d+):(\d+):(\d+) sectors=(\d+) "
    r"sector_size=(\d+) instance_crc32=([0-9a-f]{8}) "
    r"vpd_length=(\d+) vpd_crc32=([0-9a-f]{8})"
)
OS_READ = re.compile(
    r"HYPERV_TOPOLOGY OS_READ PASS id=(\d+) controller=(\d+) "
    r"channel=(\d+) lun=0 bytes=1024 mbr=1 gpt=1"
)
DATA_READ = re.compile(
    r"HYPERV_TOPOLOGY DATA_READ PASS role=([01]) id=(\d+) "
    r"controller=(\d+) channel=(\d+) address=(\d+):(\d+):(\d+) "
    r"sectors=(\d+) bytes=1024 seed_crc32=([0-9a-f]{8})"
)
SKIP = re.compile(
    r"HYPERV_TOPOLOGY TARGET SKIP id=(\d+) reason=outside-seeded-geometry"
)
FINAL = re.compile(
    r"HYPERV_TOPOLOGY FINAL PASS devices=(\d+) os=1 data0=1 data_nonzero=1"
)
PRIVATE_SERIAL = re.compile(
    r"[0-9a-fA-F]{32,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"
    r"(?:/subscriptions/|(?:https?://)|(?:sig=)|(?:accessSAS))",
    re.IGNORECASE,
)


def require_uuid(value):
    try:
        parsed = uuid.UUID(value)
    except (TypeError, AttributeError, ValueError):
        raise ValueError("Azure immutable UUID is invalid or missing") from None
    if not parsed.int or str(parsed) != value:
        raise ValueError("Azure immutable UUID is invalid or missing")
    return value


def require_hex(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value) or not int(value, 16):
        raise ValueError(f"{label} must be a fresh nonzero lowercase ID")
    return value


def digest(path):
    return azure.image_sha256(path)


def implementation():
    paths = {
        "controller": Path(__file__),
        "template": TEMPLATE,
        "azure_controller": Path(azure.__file__),
        "upload_helper": Path(__file__).with_name("hyperv-azure-upload.py"),
        "seed_producer": Path(seed_producer.__file__),
    }
    if digest(TEMPLATE) != TEMPLATE_SHA256:
        raise ValueError("The reviewed #90 ARM template has changed")
    return {name: digest(path) for name, path in paths.items()}


def group_id(state):
    return (f"/subscriptions/{state['subscription']}/resourceGroups/"
            f"{state['prefix']}-rg")


def resource_id(state, role):
    provider, kind, suffix = {
        "os": ("Microsoft.Compute", "disks", "-os"),
        "data0": ("Microsoft.Compute", "disks", "-data0"),
        "data7": ("Microsoft.Compute", "disks", "-data7"),
        "vm": ("Microsoft.Compute", "virtualMachines", "-vm"),
        "nic": ("Microsoft.Network", "networkInterfaces", "-nic"),
        "vnet": ("Microsoft.Network", "virtualNetworks", "-vnet"),
        "nsg": ("Microsoft.Network", "networkSecurityGroups", "-nsg"),
        "deployment": ("Microsoft.Resources", "deployments", ""),
    }[role]
    return (f"{group_id(state)}/providers/{provider}/{kind}/"
            f"{state['prefix']}{suffix}")


def tags(state, role):
    prepared = state["prepared"]
    return {
        "managed-by": "unikraft-hyperv",
        "purpose": PURPOSE,
        "unikraft-run": state["prefix"],
        "issue90-run": state["run_id"],
        "issue90-operation": state["operation_id"],
        "image-sha256": prepared["image_sha256"],
        "seed0-sha256": prepared["seeds"]["data0"]["sha256"],
        "seed7-sha256": prepared["seeds"]["data7"]["sha256"],
        "issue90-role": role,
    }


def owned(state, resource, role):
    if not isinstance(resource, dict) or resource.get("tags") != tags(state, role):
        raise RuntimeError(f"Refusing an unowned or retagged {role}")
    expected = group_id(state) if role == "group" else resource_id(state, role)
    if str(resource.get("id", "")).lower() != expected.lower():
        raise RuntimeError(f"Refusing a foreign {role} ID")
    if role != "group" and (
        resource.get("name") != state["prefix"] + (
            {"os": "-os", "data0": "-data0", "data7": "-data7",
             "nsg": "-nsg", "vnet": "-vnet", "nic": "-nic", "vm": "-vm"}[role]
        )
        or str(resource.get("type", "")).lower()
        != resource_id(state, role).split("/providers/")[-1].rsplit("/", 1)[0].lower()
    ):
        raise RuntimeError(f"Refusing a foreign {role} type or name")
    if str(resource.get("location", "")).lower() != "northeurope":
        raise RuntimeError(f"Refusing a {role} outside northeurope")


@contextmanager
def locked(directory):
    directory = Path(directory).absolute()
    meta = directory.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid()
            or meta.st_mode & 0o077 or directory.resolve(strict=True) != directory):
        raise ValueError("State directory must be owner-only and symlink-free")
    path = directory / ".issue90.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1):
            raise ValueError("State lock must be a private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory
    finally:
        os.close(fd)


def save(directory, state):
    azure.save_durable_json(directory / "state.json", state)


def load(directory):
    raw = azure.read_regular_file(directory / "state.json", 256 * 1024, "Issue 90 state")
    state = azure.parse_strict_json(raw, "Issue 90 state")
    disk_ids = state.get("disk_ids") if isinstance(state, dict) else None
    if (not isinstance(state, dict) or state.get("schema") != SCHEMA
            or state.get("version") != 1 or state.get("phase") not in (
                "planned", "prepared", "authorized", "creating-group", "group-created",
                "creating-os", "creating-data0", "creating-data7",
                "uploading-os", "uploading-data0", "uploading-data7",
                "disk-ready", "deploying", "vm-created", "waiting-boot",
                "accepted", "deleting-group", "cleanup-failed", "cleaned",
            ) or not NAME.fullmatch(str(state.get("prefix", "")))
            or azure.validate_subscription_id(state.get("subscription"))
            != state.get("subscription")
            or state.get("location") != "northeurope"
            or require_hex(state.get("run_id"), HEX32, "run ID")
            != state.get("run_id")
            or require_uuid(state.get("operation_id")) != state.get("operation_id")
            or not isinstance(disk_ids, dict) or disk_ids.keys() != LUNS.keys()
            or type(state.get("boot_count")) is not int
            or state["boot_count"] not in (0, 1)):
        raise ValueError("Issue 90 state is invalid")
    ids = [state["run_id"], *(require_hex(state["disk_ids"][role], HEX32, role)
                              for role in LUNS)]
    if len(set(ids)) != 3:
        raise ValueError("Issue 90 run and disk IDs must be distinct")
    if state["phase"] not in ("planned",) and state.get("prepared") is None:
        raise ValueError("Prepared image provenance is unavailable")
    if state.get("prepared") is not None:
        prepared = state["prepared"]
        if (not isinstance(prepared, dict)
                or not isinstance(prepared.get("seeds"), dict)
                or set(prepared["seeds"]) != set(LUNS)
                or not isinstance(prepared.get("implementation"), dict)):
            raise ValueError("Issue 90 image or seed proofs are unavailable")
        azure.require_sha256(prepared.get("image_sha256"), "Guest fingerprint")
        azure.require_sha256(prepared.get("config_sha256"), "Config fingerprint")
        for role in LUNS:
            proof = prepared["seeds"][role]
            if not isinstance(proof, dict) or set(proof) != {
                "sha256", "manifest_sha256", "size"
            } or type(proof["size"]) is not int or proof["size"] != DISK_BYTES + 512:
                raise ValueError("Issue 90 seeded disk geometry is invalid")
            azure.require_sha256(proof["sha256"], "Seed fingerprint")
            azure.require_sha256(proof["manifest_sha256"], "Seed manifest fingerprint")
    disks = state.get("disks", {})
    if not isinstance(disks, dict) or not set(disks) <= set(ROLES):
        raise ValueError("Issue 90 disk receipts are invalid")
    for role, proof in disks.items():
        if (not isinstance(proof, dict) or set(proof) != {"id", "uuid"}
                or str(proof["id"]).lower() != resource_id(state, role).lower()):
            raise ValueError("Issue 90 disk receipt is not bound to this run")
        require_uuid(proof["uuid"])
    if len({proof["uuid"] for proof in disks.values()}) != len(disks):
        raise ValueError("Issue 90 disk UUID receipts are not distinct")
    pending = state.get("pending_create")
    if pending is not None:
        if not isinstance(pending, dict) or set(pending) != {"kind", "role"}:
            raise ValueError("Issue 90 unresolved create intent is invalid")
        kind, role = pending["kind"], pending["role"]
        valid = (
            kind == "disk" and role in ROLES and role not in disks
            or kind == "deployment" and role == "vm" and state.get("vm") is None
            or kind == "group" and role == "group"
            and state.get("resource_group_id") is None
        )
        if not valid:
            raise ValueError("Issue 90 unresolved create intent is invalid")
    return state


def plan(directory, subscription):
    subscription = azure.validate_subscription_id(subscription)
    directory = Path(directory).absolute()
    if directory.parent.resolve(strict=True) != directory.parent:
        raise ValueError("State parent must be symlink-free")
    directory.mkdir(mode=0o700, exist_ok=False)
    state = {
        "schema": SCHEMA, "version": 1, "phase": "planned",
        "subscription": subscription, "location": "northeurope",
        "run_id": uuid.uuid4().hex, "operation_id": str(uuid.uuid4()),
        "disk_ids": {role: uuid.uuid4().hex for role in LUNS},
        "prefix": "uk90-" + uuid.uuid4().hex[:20],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "boot_count": 0,
    }
    save(directory, state)
    return state


def solved_config(raw, state):
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise ValueError("Solved topology configuration is not UTF-8") from None
    settings = {}
    for line in lines:
        match = re.fullmatch(r"CONFIG_([A-Z0-9_]+)=(.*)", line)
        if match:
            if match[1] in settings:
                raise ValueError("Solved configuration contains duplicate settings")
            settings[match[1]] = match[2]
    exact = {
        "APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY": "y",
        "LIBSTORVSC_LUN_DISCOVERY": "y",
        "LIBSTORVSC_GUARDED_IO": "y",
        "APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID": f'"{state["run_id"]}"',
        "APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID": f'"{state["disk_ids"]["data0"]}"',
        "APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID": f'"{state["disk_ids"]["data7"]}"',
        "APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS": str(SECTORS),
        "APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS": str(SECTORS),
        "APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN": "7",
    }
    if any(settings.get(key) != value for key, value in exact.items()):
        raise ValueError("Guest configuration does not match fresh #90 run and both disks")
    if (settings.get("APPHYPERVACCEPTANCE_PERSISTENCE") == "y"
            or settings.get("APPHYPERVACCEPTANCE_NETWORK_APPLICATION") == "y"
            or not 3 <= int(settings.get("LIBSTORVSC_MAX_DEVICES", "0")) <= 16
            or not 2 <= int(settings.get("LIBSTORVSC_MAX_LUNS", "0")) <= 16):
        raise ValueError("Guest discovery bounds or read-only workload are invalid")


def seed_sector(state, role):
    return seed_producer.manifest(
        bytes.fromhex(state["run_id"]), bytes.fromhex(state["disk_ids"][role]),
        SECTORS, 2, 0, 0, LUNS[role],
    )


def create_seed(directory, state, role):
    path = directory / f"{role}.vhd"
    sector = seed_sector(state, role)
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.truncate(DISK_BYTES + 512)
        for lba in (8, 9):
            output.seek(lba * 512)
            output.write(sector)
        output.seek(DISK_BYTES)
        output.write(seed_producer.fixed_vhd_footer(
            SECTORS, bytes.fromhex(state["disk_ids"][role])
        ))
        output.flush()
        os.fsync(output.fileno())
    manifest = {
        "version": 2, "identity_policy": "seed-enrollment-v2",
        "identity_policy_version": 2,
        "run_id": state["run_id"], "disk_id": state["disk_ids"][role],
        "sectors": SECTORS, "sector_size": 512, "lun": LUNS[role],
        "path": None, "target": None, "seed_lbas": [8, 9],
        "intent_lba": 16, "receipt_lba": 17, "extent_lba": 32,
        "extent_sectors": 16, "manifest_crc32": struct.unpack_from("<I", sector, 508)[0],
    }
    azure.save_durable_json(directory / f"{role}-seed.json", manifest)
    return {"sha256": digest(path), "size": DISK_BYTES + 512,
            "manifest_sha256": digest(directory / f"{role}-seed.json")}


def verify_seed(directory, state, role):
    proof = state["prepared"]["seeds"][role]
    path = directory / f"{role}.vhd"
    if (path.is_symlink() or path.stat().st_size != DISK_BYTES + 512
            or proof["size"] != DISK_BYTES + 512
            or digest(path) != proof["sha256"]):
        raise ValueError(f"Seeded {role} VHD changed")
    manifest_path = directory / f"{role}-seed.json"
    manifest = azure.parse_strict_json(
        azure.read_regular_file(manifest_path, 65536, "Seed manifest"), "Seed manifest"
    )
    expected = {
        "version": 2, "identity_policy": "seed-enrollment-v2",
        "identity_policy_version": 2, "run_id": state["run_id"],
        "disk_id": state["disk_ids"][role], "sectors": SECTORS,
        "sector_size": 512, "lun": LUNS[role], "path": None,
        "target": None, "seed_lbas": [8, 9], "intent_lba": 16,
        "receipt_lba": 17, "extent_lba": 32, "extent_sectors": 16,
        "manifest_crc32": struct.unpack_from("<I", seed_sector(state, role), 508)[0],
    }
    if manifest != expected or digest(manifest_path) != proof["manifest_sha256"]:
        raise ValueError(f"Seeded {role} manifest changed")
    with path.open("rb") as source:
        source.seek(8 * 512)
        seeds = source.read(1024)
        source.seek(16 * 512)
        pristine = source.read(1024)
        source.seek(32 * 512)
        extent = source.read(16 * 512)
        source.seek(0)
        first = source.read(512)
        source.seek(DISK_BYTES - 512)
        last = source.read(512)
        footer = source.read(512)
    if (seeds != seed_sector(state, role) * 2 or any(pristine + extent + first + last)
            or footer != seed_producer.fixed_vhd_footer(
                SECTORS, bytes.fromhex(state["disk_ids"][role])
            )):
        raise ValueError(f"Seeded {role} sectors or official VHD footer changed")


def verify_inputs(directory, state):
    prepared = state["prepared"]
    require_reviewed_build_proof()
    if implementation() != prepared["implementation"]:
        raise ValueError("Prepared controller or reviewed template changed")
    if digest(directory / "guest.vhd") != prepared["image_sha256"]:
        raise ValueError("Locally booted guest image changed")
    raw = azure.read_regular_file(directory / "solved.config", 1024 * 1024, "Solved config")
    if hashlib.sha256(raw).hexdigest() != prepared["config_sha256"]:
        raise ValueError("Solved guest configuration changed")
    solved_config(raw, state)
    for role in LUNS:
        verify_seed(directory, state, role)
    if prepared["seeds"]["data0"]["sha256"] == prepared["seeds"]["data7"]["sha256"]:
        raise ValueError("Both data disks have identical bytes")


def verify_raw_vhd_pair(raw_image, image, raw_sha, image_sha):
    if (raw_image.is_symlink() or raw_image.stat().st_size != azure.VIRTUAL_SIZE
            or digest(raw_image) != raw_sha
            or image.is_symlink() or image.stat().st_size != azure.VIRTUAL_SIZE + 512
            or digest(image) != image_sha):
        raise ValueError("Locally booted raw/fixed-VHD pair changed")
    with raw_image.open("rb") as raw_disk, image.open("rb") as vhd_disk:
        for chunk in iter(lambda: raw_disk.read(1024 * 1024), b""):
            if vhd_disk.read(len(chunk)) != chunk:
                raise ValueError("Raw and fixed-VHD boot images have different guest bytes")
        if len(vhd_disk.read()) != 512:
            raise ValueError("Fixed-VHD footer is missing")


def require_reviewed_build_proof():
    raise ValueError(
        "Reviewed-source/solved-config-to-EFI build provenance is unavailable; "
        "an ID-byte scan, mutable build receipt or EFI hash is not a build proof"
    )


def prepare(directory, state, prepared_directory, config_path, config_sha,
            image_sha, miz_path):
    if state["phase"] != "planned":
        raise ValueError("Only a newly planned run can be prepared")
    azure.require_sha256(config_sha, "Expected solved config SHA-256")
    azure.require_sha256(image_sha, "Expected locally booted VHD SHA-256")
    raw = azure.read_regular_file(config_path, 1024 * 1024, "Solved config")
    if hashlib.sha256(raw).hexdigest() != config_sha:
        raise ValueError("Solved config differs from its independent fingerprint")
    solved_config(raw, state)
    source, source_path = azure.load_state(Path(prepared_directory))
    if (source["phase"] != "prepared" or source.get("local_platform_boot") is not True
            or source.get("image_sha256") != image_sha
            or not isinstance(source.get("raw_sha256"), str)
            or not HEX64.fullmatch(source["raw_sha256"])
            or source.get("location") != "northeurope"
            or source.get("vm_size") != "Standard_D2s_v5"
            or source.get("acceptance") != {"mode": "raw-dhcp"}
            or source.get("local_platform_boot_modes") != {
                "raw": {"x2apic": True, "legacy-apic": True},
                "vhd": {"x2apic": True, "legacy-apic": True},
            }
            or not isinstance(source.get("efi_sha256"), str)
            or not HEX64.fullmatch(source["efi_sha256"])):
        raise ValueError("A locally booted, read-only topology image is required")
    for kind, log_kind in (("raw", "raw"), ("vhd", "vpc")):
        for mode, legacy in azure.LOCAL_BOOT_MODES:
            log = source_path.parent / f"local-{log_kind}-{mode}-serial.log"
            evidence = azure.validate_local_boot_log(log, azure.PLATFORM_READY, legacy)
            text = azure.read_regular_file(log, MAX_SERIAL, "Local topology serial").decode(
                "utf-8", "replace").replace("\0", "")
            if (evidence["io_ready"] or evidence["crashes"]
                    or text.count("HYPERV_TOPOLOGY FINAL UNAVAILABLE reason=no-devices") != 1
                    or text.count("HYPERV_TOPOLOGY RESULT UNAVAILABLE") != 1
                    or "HYPERV_PERSISTENCE" in text or "HYPERV_TOPOLOGY DATA_READ" in text):
                raise ValueError("Local boot is not the read-only topology workload")
    efi = azure.read_regular_file(
        source_path.parent / "BOOTX64.EFI", 64 * 1024 * 1024,
        "Locally booted topology EFI",
    )
    if hashlib.sha256(efi).hexdigest() != source["efi_sha256"]:
        raise ValueError("Locally booted EFI no longer matches its prepared fingerprint")
    raw_image = source_path.parent / "unikraft.raw"
    image = source_path.parent / "unikraft.vhd"
    verify_raw_vhd_pair(raw_image, image, source["raw_sha256"], image_sha)
    miz = Path(miz_path).resolve(strict=True)
    if (not os.access(miz, os.X_OK)
            or source.get("miz_executable") != str(miz)
            or source.get("miz_executable_sha256") != digest(miz)):
        raise ValueError("Miz checker differs from the locally booted image producer")
    require_reviewed_build_proof()
    report = azure.miz_command(miz, [
        "check-efi-application", "--output=json", "--architecture", "x86_64",
        "--expected-efi-sha256", source["efi_sha256"],
        "--expected-virtual-size", "66M", str(image),
    ], directory / "miz-issue90-check.log", json_output=True)
    azure.check_packaging_report(report, source["efi_sha256"], image.stat().st_size)
    azure.copy_regular_file(image, directory / "guest.vhd",
                            azure.VIRTUAL_SIZE + 512, image_sha)
    with (directory / "solved.config").open("xb") as output:
        os.chmod(directory / "solved.config", 0o600)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    seeds = {role: create_seed(directory, state, role) for role in LUNS}
    state["prepared"] = {
        "implementation": implementation(),
        "image_sha256": image_sha, "config_sha256": config_sha,
        "source_efi_sha256": source["efi_sha256"], "seeds": seeds,
    }
    verify_inputs(directory, state)
    state["phase"] = "prepared"
    save(directory, state)
    return state


def envelope(state):
    if state["phase"] == "planned":
        raise ValueError("Prepare the guest and both seed disks first")
    return {
        "subscription": state["subscription"], "location": "northeurope",
        "resource_group": state["prefix"] + "-rg",
        "run_id": state["run_id"], "operation_id": state["operation_id"],
        "vm_size": "Standard_D2s_v5", "vm_count": 1, "max_boots": 1,
        "vm_runtime_seconds": MAX_RUNTIME, "public_ip_count": 0,
        "os_disk": {"id": resource_id(state, "os"), "sku": "StandardSSD_LRS",
                    "vhd_sha256": state["prepared"]["image_sha256"]},
        "data_disks": {
            role: {"id": resource_id(state, role), "sku": "StandardSSD_LRS",
                   "size_gib": 4, "lun": LUNS[role],
                   "seed_id": state["disk_ids"][role],
                   "vhd_sha256": state["prepared"]["seeds"][role]["sha256"]}
            for role in LUNS
        },
        "network": {"nics": 1, "vnets": 1, "nsgs": 1,
                    "public_ingress": False, "default_outbound": False},
    }


def envelope_sha(state):
    return hashlib.sha256(azure.canonical_json(envelope(state))).hexdigest()


def parse_serial(text, state):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_SERIAL:
        raise ValueError("Azure boot diagnostics are invalid or too large")
    lines = [azure.ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
             for line in text.splitlines()]
    normalized = "\n".join(lines)
    if PRIVATE_SERIAL.search(normalized) or any(
        identity in normalized.lower()
        for identity in (state["run_id"], *state["disk_ids"].values())
    ):
        raise ValueError("Azure boot diagnostics contain unredacted private identifiers")
    for line in lines:
        if (line.startswith(("HYPERV_TOPOLOGY FINAL FAIL",
                              "HYPERV_TOPOLOGY TARGET FAIL",
                              "UK_HYPERV_ACCEPTANCE_FAIL:",
                              "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:",
                              "HYPERV_PERSISTENCE"))
                or any(marker in line for marker in (
                    "HYPERV_TOPOLOGY RESULT FAIL",
                    "HYPERV_TOPOLOGY RESULT UNAVAILABLE",
                    "HYPERV_TOPOLOGY FINAL UNAVAILABLE",
                ))
                or any(crash in line for crash in (
                    "Unikraft Crash", "Assertion failure", "Exception Type"))
                or re.search(r"\bmain returned (?!0\b)-?\d+\b", line)):
            raise ValueError("The read-only guest reported a failure")
    info = [INFO.fullmatch(line) for line in lines if line.startswith(
        "HYPERV_TOPOLOGY TARGET INFO ")]
    os_records = [OS_READ.fullmatch(line) for line in lines if line.startswith(
        "HYPERV_TOPOLOGY OS_READ ")]
    data = [DATA_READ.fullmatch(line) for line in lines if line.startswith(
        "HYPERV_TOPOLOGY DATA_READ ")]
    skips = [SKIP.fullmatch(line) for line in lines if line.startswith(
        "HYPERV_TOPOLOGY TARGET SKIP ")]
    final = [FINAL.fullmatch(line) for line in lines if line.startswith(
        "HYPERV_TOPOLOGY FINAL ")]
    if (not all(info) or len(os_records) != 1
            or not all(os_records) or len(data) != 2 or not all(data)
            or not all(skips) or len(final) != 1 or not final[0]
            or lines.count("UK_HYPERV_PLATFORM_READY") != 1
            or lines.count("UK_HYPERV_TOPOLOGY_READ_OK") != 1
            or lines.count("HYPERV_TOPOLOGY RESULT PASS") != 1
            or lines.count("main returned 0") != 1):
        raise ValueError("Azure topology evidence is missing or ambiguous")
    count = int(final[0][1])
    if not 3 <= count <= 256 or len(info) != count or len(skips) != count - 3:
        raise ValueError("Guest device count disagrees with the complete inventory")
    ids = {}
    for match in info:
        disk_id, controller, channel, path, target, lun, sectors, ssize = (
            int(value) for value in match.groups()[:8])
        if disk_id in ids or ssize != 512 or not (0 <= lun <= 255):
            raise ValueError("Guest device inventory has duplicate or invalid geometry")
        ids[disk_id] = {
            "controller": controller, "channel": channel,
            "address": [path, target, lun], "sectors": sectors,
            "instance_crc32": match[9], "vpd_length": int(match[10]),
            "vpd_crc32": match[11],
        }
    os_match = os_records[0]
    os_id = int(os_match[1])
    if (os_id not in ids or ids[os_id]["address"][2] != 0
            or ids[os_id]["sectors"] != azure.VIRTUAL_SIZE // 512
            or (ids[os_id]["controller"], ids[os_id]["channel"])
            != (int(os_match[2]), int(os_match[3]))):
        raise ValueError("OS read does not match the coherent device inventory")
    accepted = {"os": {"id": os_id, **ids[os_id]}}
    for match in data:
        role = "data0" if match[1] == "0" else "data7"
        disk_id = int(match[2])
        mapping = ids.get(disk_id)
        if (role in accepted or not mapping or disk_id == os_id
                or mapping["controller"] != int(match[3])
                or mapping["channel"] != int(match[4])
                or mapping["address"] != [int(v) for v in match.groups()[4:7]]
                or mapping["address"][2] != LUNS[role]
                or mapping["sectors"] != SECTORS
                or int(match[8]) != SECTORS
                or match[9] != f"{zlib.crc32(seed_sector(state, role) * 2):08x}"):
            raise ValueError("Data read has a wrong LUN, size, seed or device identity")
        accepted[role] = {"id": disk_id, **mapping}
    skipped = [int(match[1]) for match in skips]
    if (len(set(skipped)) != len(skipped)
            or set(skipped) != set(ids) - {
                item["id"] for item in accepted.values()
            }):
        raise ValueError("Skipped devices do not match the coherent inventory")
    if (set(accepted) != {"os", "data0", "data7"}
            or lines.index("UK_HYPERV_PLATFORM_READY")
            >= lines.index(os_match.group(0))
            or any(lines.index(match.group(0)) >= lines.index(final[0].group(0))
                   for match in [os_match, *data, *skips])
            or lines.index("UK_HYPERV_TOPOLOGY_READ_OK")
            <= lines.index(final[0].group(0))
            or lines.index("HYPERV_TOPOLOGY RESULT PASS")
            <= lines.index("UK_HYPERV_TOPOLOGY_READ_OK")
            or lines.index("main returned 0")
            <= lines.index("HYPERV_TOPOLOGY RESULT PASS")):
        raise ValueError("The three read-only targets did not complete in order")
    return {
        "result": "PASS", "mode": "read-only", "guest_devices": accepted,
        "controller_count": len({item["controller"] for item in accepted.values()}),
        "observed_devices": count,
        "observed_controller_count": len({
            item["controller"] for item in ids.values()
        }),
        "skipped_device_ids": skipped,
        "serial_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def redacted_serial(text):
    markers = {
        "UK_HYPERV_PLATFORM_READY", "UK_HYPERV_TOPOLOGY_READ_OK",
        "HYPERV_TOPOLOGY RESULT PASS", "main returned 0",
    }
    lines = [azure.ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
             for line in text.splitlines()]
    return "\n".join(line for line in lines if (
        line in markers or any(pattern.fullmatch(line) for pattern in (
            INFO, OS_READ, DATA_READ, SKIP, FINAL
        ))
    )) + "\n"


class TopologyRun:
    def __init__(self, state, directory):
        self.state = state
        self.directory = directory
        self.deadline = None

    def record(self, phase, **updates):
        next_state = {**self.state, **updates, "phase": phase}
        save(self.directory, next_state)
        self.state.clear()
        self.state.update(next_state)

    def az(self, arguments, timeout=120):
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise RuntimeError("One-boot lifetime expired")
        return azure.azure_cli(
            arguments, subscription=self.state["subscription"],
            private=True, timeout=timeout,
        )

    def name(self, role):
        return self.state["prefix"] + {
            "os": "-os", "data0": "-data0", "data7": "-data7",
            "vm": "-vm", "nic": "-nic", "nsg": "-nsg", "vnet": "-vnet",
        }[role]

    def group(self):
        return self.state["prefix"] + "-rg"

    def tag_args(self, role):
        return [f"{key}={value}" for key, value in tags(self.state, role).items()]

    def disk_show(self, role, *, cleanup=False):
        return self.az(
            ["disk", "show", "--resource-group", self.group(),
             "--name", self.name(role)],
            timeout=120 if not cleanup else 180,
        )

    def verify_disk(self, role, disk, *, attached=None, ready=True):
        proof = self.state.get("disks", {}).get(role)
        if not isinstance(proof, dict) or set(proof) != {"id", "uuid"}:
            raise RuntimeError(f"Refusing an unproven {role} disk")
        self.validate_disk_response(role, disk)
        managed_by = disk.get("managedBy")
        if (proof["id"].lower() != resource_id(self.state, role).lower()
                or require_uuid(disk.get("uniqueId")) != proof["uuid"]
                or (str(managed_by or "").lower() != attached.lower()
                    if attached else managed_by not in (None, ""))
                or (ready and (disk.get("provisioningState") != "Succeeded"
                    or disk.get("diskState") != (
                        "Attached" if attached else "Unattached")))):
            raise RuntimeError(f"Refusing a replaced, attached elsewhere or wrong-size {role} disk")
        return proof

    def validate_disk_response(self, role, disk, *, created=False):
        owned(self.state, disk, role)
        size = (azure.VIRTUAL_SIZE if role == "os" else DISK_BYTES)
        creation = disk.get("creationData")
        state = disk.get("diskState")
        # Azure CLI 2.90 omits both size fields until an upload is revoked and
        # then reports diskSizeGB; older SDK-based commands used diskSizeGb.
        gib = [disk[key] for key in ("diskSizeGB", "diskSizeGb") if key in disk]
        sized = "diskSizeBytes" in disk or bool(gib) or state not in UPLOAD_STATES
        if (not isinstance(state, str)
                or (created and state != "ReadyToUpload")
                or (sized and (
                    type(disk.get("diskSizeBytes")) is not int
                    or disk["diskSizeBytes"] != size or not gib
                    or any(type(value) is not int
                           or value != (size + GIB - 1) // GIB for value in gib)))
                or not isinstance(creation, dict)
                or creation.get("createOption") != "Upload"
                or type(creation.get("uploadSizeBytes")) is not int
                or creation["uploadSizeBytes"] != size + 512
                or not isinstance(disk.get("sku"), dict)
                or disk["sku"].get("name") != "StandardSSD_LRS"
                or (disk.get("hyperVGeneration") != "V2" if role == "os"
                    else disk.get("hyperVGeneration") not in (None, "V2"))
                or (disk.get("osType") != "Linux" if role == "os"
                    else disk.get("osType") not in (None, ""))):
            raise RuntimeError(f"Refusing an unproven {role} upload size or disk geometry")
        return require_uuid(disk.get("uniqueId"))

    def preflight_cloud(self):
        subscription = azure.selected_account(self.state["subscription"])
        for namespace in ("Microsoft.Compute", "Microsoft.Network"):
            if self.az(["provider", "show", "--namespace", namespace,
                        "--query", "registrationState"]) != "Registered":
                raise RuntimeError("Required provider is not registered")
        versions = self.az([
            "provider", "show", "--namespace", "Microsoft.Compute",
            "--query", "resourceTypes[?resourceType=='virtualMachines'].apiVersions | [0]",
        ])
        if not isinstance(versions, list) or COMPUTE_API_VERSION not in versions:
            raise RuntimeError("Explicit Standard VM API version is unavailable")
        sku = azure.exact_vm_sku(
            "northeurope", "Standard_D2s_v5", subscription, 2, require_v2=True
        )
        details = self.az([
            "vm", "list-skus", "--all", "--location", "northeurope",
            "--resource-type", "virtualMachines", "--size", "Standard_D2s_v5",
            "--query", "[?name=='Standard_D2s_v5']",
        ])
        if (not isinstance(details, list) or len(details) != 1
                or not isinstance(details[0], dict)):
            raise RuntimeError("Two-data-disk SKU capabilities are ambiguous")
        capabilities = {entry.get("name"): entry.get("value")
                        for entry in details[0].get("capabilities", [])
                        if isinstance(entry, dict)}
        try:
            disks = int(capabilities["MaxDataDiskCount"])
        except (KeyError, TypeError, ValueError):
            raise RuntimeError("Data-disk capability is unavailable") from None
        if disks < 2:
            raise RuntimeError("VM cannot attach two data disks")
        usage = self.az([
            "vm", "list-usage", "--location", "northeurope",
            "--query", f"[?name.value=='cores' || name.value=='{sku['family']}']",
        ])
        if not isinstance(usage, list):
            raise RuntimeError("VM quota is unavailable")
        quota = {item.get("name", {}).get("value"): item for item in usage
                 if isinstance(item, dict)}
        for name in ("cores", sku["family"]):
            if name not in quota or (
                azure.quota_count(quota[name].get("limit"))
                - azure.quota_count(quota[name].get("currentValue")) < 2
            ):
                raise RuntimeError("Insufficient single-VM quota")
        if self.az(["group", "exists", "--name", self.group()]) is not False:
            raise RuntimeError("Refusing to adopt an existing resource group")

    def create_group(self):
        self.record(
            "creating-group", pending_create={"kind": "group", "role": "group"},
        )
        group = self.az([
            "group", "create", "--name", self.group(), "--location", "northeurope",
            "--tags", *self.tag_args("group"),
        ], timeout=300)
        owned(self.state, group, "group")
        self.record(
            "group-created", resource_group_id=group_id(self.state),
            pending_create=None,
        )

    def create_disk(self, role):
        self.record(
            f"creating-{role}", pending_create={"kind": "disk", "role": role},
        )
        path = self.directory / ("guest.vhd" if role == "os" else f"{role}.vhd")
        arguments = [
            "disk", "create", "--resource-group", self.group(),
            "--name", self.name(role), "--location", "northeurope",
            "--upload-type", "Upload", "--upload-size-bytes", str(path.stat().st_size),
            "--sku", "StandardSSD_LRS",
            "--tags", *self.tag_args(role),
        ]
        if role == "os":
            arguments += ["--os-type", "Linux", "--hyper-v-generation", "V2"]
        disk = self.az(arguments, timeout=600)
        proof = {"id": resource_id(self.state, role),
                 "uuid": self.validate_disk_response(role, disk, created=True)}
        if proof["uuid"] in {item["uuid"] for item in self.state.get("disks", {}).values()}:
            raise RuntimeError("Azure returned duplicate disk UUIDs")
        self.record(f"uploading-{role}",
                    disks={**self.state.get("disks", {}), role: proof},
                    pending_create=None)
        primary = None
        try:
            grant = self.az([
                "disk", "grant-access", "--resource-group", self.group(),
                "--name", self.name(role), "--access-level", "Write",
                "--duration-in-seconds", "1800",
            ])
            endpoint, sas = azure.upload_endpoint(azure.disk_access_sas(grant))
            azure.upload_managed_vhd(
                path, endpoint, sas, timeout=1200,
                expected_sha256=(self.state["prepared"]["image_sha256"] if role == "os"
                                 else self.state["prepared"]["seeds"][role]["sha256"]),
            )
        except BaseException as error:
            primary = error
        try:
            self.az([
                "disk", "revoke-access", "--resource-group", self.group(),
                "--name", self.name(role),
            ], timeout=120)
        except BaseException as revoke:
            if primary:
                raise RuntimeError(
                    "Upload and SAS revocation both failed: "
                    + azure.safe_failure_message(primary) + "; "
                    + azure.safe_failure_message(revoke)
                ) from None
            raise
        if primary:
            raise primary
        self.verify_disk(role, self.disk_show(role))
        self.record("disk-ready")

    def parameters(self):
        return {
            "namePrefix": self.state["prefix"], "location": "northeurope",
            "runId": self.state["run_id"], "operationId": self.state["operation_id"],
            "imageSha256": self.state["prepared"]["image_sha256"],
            "seed0Sha256": self.state["prepared"]["seeds"]["data0"]["sha256"],
            "seed7Sha256": self.state["prepared"]["seeds"]["data7"]["sha256"],
            "osDiskId": resource_id(self.state, "os"),
            "dataDisk0Id": resource_id(self.state, "data0"),
            "dataDisk7Id": resource_id(self.state, "data7"),
        }

    @contextmanager
    def parameters_file(self):
        path = self.directory / ".issue90-parameters.json"
        azure.save_durable_json(path, {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {key: {"value": value} for key, value in self.parameters().items()},
        })
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)

    def deployment_proof(self, deployment):
        if not isinstance(deployment, dict) or not isinstance(
            deployment.get("properties"), dict
        ):
            raise RuntimeError("Original ARM deployment is unavailable")
        props = deployment["properties"]
        expected = {resource_id(self.state, role).lower()
                    for role in ("nsg", "vnet", "nic", "vm")}
        output_resources = props.get("outputResources")
        parameters = props.get("parameters")
        outputs = props.get("outputs")
        if (deployment.get("name") != self.state["prefix"]
                or str(deployment.get("id", "")).lower()
                != resource_id(self.state, "deployment").lower()
                or props.get("provisioningState") != "Succeeded"
                or props.get("mode") != "Incremental"
                or deployment.get("type") != "Microsoft.Resources/deployments"
                or not isinstance(output_resources, list)
                or len(output_resources) != 4
                or not all(isinstance(item, dict)
                           and isinstance(item.get("id"), str)
                           for item in output_resources)
                or {item["id"].lower() for item in output_resources} != expected
                or not isinstance(parameters, dict)
                or set(parameters) != set(self.parameters())
                or any(not isinstance(parameters[key], dict)
                       or not isinstance(parameters[key].get("type"), str)
                       or parameters[key]["type"].lower() != "string"
                       or parameters[key].get("value") != value
                       for key, value in self.parameters().items())
                or not isinstance(outputs, dict)
                or set(outputs) != set(OUTPUT_ROLES) | {"vmUuid"}
                or not isinstance(outputs.get("vmUuid"), dict)
                or not isinstance(outputs["vmUuid"].get("type"), str)
                or outputs["vmUuid"]["type"].lower() != "string"
                or any(not isinstance(outputs[key], dict)
                       or not isinstance(outputs[key].get("type"), str)
                       or outputs[key]["type"].lower() != "string"
                       or str(outputs[key].get("value", "")).lower()
                       != resource_id(self.state, role).lower()
                       for key, role in OUTPUT_ROLES.items())):
            raise RuntimeError("Original ARM operation, outputs or inventory changed")
        vm_uuid = require_uuid(outputs["vmUuid"].get("value"))
        correlation = require_uuid(props.get("correlationId"))
        if vm_uuid in {item["uuid"] for item in self.state["disks"].values()}:
            raise RuntimeError("VM UUID collides with a seeded disk UUID")
        return {
            "id": resource_id(self.state, "vm"), "uuid": vm_uuid,
            "deployment_id": resource_id(self.state, "deployment"),
            "correlation_id": correlation,
            "resource_ids": sorted(expected),
            "disks": {role: self.state["disks"][role] for role in ROLES},
        }

    def deploy(self):
        if self.state["boot_count"] != 0 or set(self.state.get("disks", {})) != set(ROLES):
            raise RuntimeError("One boot and three original disks are required")
        for role in ROLES:
            self.verify_disk(role, self.disk_show(role))
        self.deadline = time.monotonic() + MAX_RUNTIME
        self.record(
            "deploying", boot_count=1,
            vm_start_requested_utc=datetime.now(timezone.utc).isoformat(),
            pending_create={"kind": "deployment", "role": "vm"},
        )
        with self.parameters_file() as path:
            deployment = self.az([
                "deployment", "group", "create", "--resource-group", self.group(),
                "--name", self.state["prefix"], "--mode", "Incremental",
                "--template-file", str(TEMPLATE), "--parameters", "@" + str(path),
            ], timeout=900)
        proof = self.deployment_proof(deployment)
        self.record("vm-created", vm=proof, pending_create=None)
        self.verify_topology()

    def verify_topology(self, *, cleanup=False):
        proof = self.state.get("vm")
        if not isinstance(proof, dict):
            raise RuntimeError("Original VM UUID and ARM operation are unproven")
        deployment = self.az([
            "deployment", "group", "show", "--resource-group", self.group(),
            "--name", self.state["prefix"],
        ], timeout=180 if cleanup else 120)
        if self.deployment_proof(deployment) != proof:
            raise RuntimeError("Original ARM deployment identity was replaced")
        vm = self.az([
            "vm", "show", "--resource-group", self.group(), "--name", self.name("vm"),
        ], timeout=180 if cleanup else 120)
        owned(self.state, vm, "vm")
        storage = vm.get("storageProfile") or {}
        data = storage.get("dataDisks")
        nics = (vm.get("networkProfile") or {}).get("networkInterfaces")
        if (require_uuid(vm.get("vmId")) != proof["uuid"]
                or (vm.get("hardwareProfile") or {}).get("vmSize") != "Standard_D2s_v5"
                or storage.get("diskControllerType") != "SCSI"
                or not self.valid_os_attachment(storage.get("osDisk"), proof)
                or not isinstance(data, list) or len(data) != 2
                or {entry.get("lun") for entry in data if isinstance(entry, dict)}
                != {0, 7}
                or any(not self.valid_data_attachment(entry, proof) for entry in data)
                or not isinstance(nics, list) or len(nics) != 1
                or not self.valid_nic_attachment(nics[0])
                or (vm.get("securityProfile") is not None
                    and (not isinstance(vm["securityProfile"], dict)
                         or vm["securityProfile"].get("securityType") != "Standard"))):
            raise RuntimeError("Original VM or LUN 0/7 attachments were replaced")
        self.verify_vm_security(proof, cleanup=cleanup)
        for role in ROLES:
            self.verify_disk(role, self.disk_show(role, cleanup=cleanup),
                             attached=proof["id"], ready=not cleanup)
        return proof

    def valid_os_attachment(self, disk, proof):
        return (
            isinstance(disk, dict)
            and isinstance(disk.get("managedDisk"), dict)
            and str(disk["managedDisk"].get("id", "")).lower()
            == proof["disks"]["os"]["id"].lower()
            and disk.get("name") == self.name("os")
            and disk.get("osType") == "Linux"
            and disk.get("createOption") == "Attach"
            and disk.get("caching") == "ReadOnly"
            and disk.get("deleteOption") == "Detach"
        )

    def valid_data_attachment(self, disk, proof):
        return (
            isinstance(disk, dict)
            and disk.get("lun") in (0, 7)
            and isinstance(disk.get("managedDisk"), dict)
            and str(disk["managedDisk"].get("id", "")).lower()
            == proof["disks"]["data0" if disk["lun"] == 0 else "data7"]["id"].lower()
            and disk.get("name") == self.name("data0" if disk["lun"] == 0 else "data7")
            and disk.get("createOption") == "Attach"
            and disk.get("caching") == "None"
            and disk.get("deleteOption") == "Detach"
        )

    def valid_nic_attachment(self, nic):
        return (
            isinstance(nic, dict)
            and str(nic.get("id", "")).lower()
            == resource_id(self.state, "nic").lower()
            and isinstance(nic.get("properties"), dict)
            and nic["properties"].get("primary") is True
            and nic["properties"].get("deleteOption") == "Delete"
        )

    def verify_vm_security(self, proof, *, cleanup=False):
        resource = self.az([
            "resource", "show", "--ids", proof["id"],
            "--api-version", COMPUTE_API_VERSION,
        ], timeout=180 if cleanup else 120)
        owned(self.state, resource, "vm")
        properties = resource.get("properties")
        if not isinstance(properties, dict):
            raise RuntimeError("Pinned Compute VM response has no properties")
        storage = properties.get("storageProfile")
        if not isinstance(storage, dict):
            raise RuntimeError("Pinned Compute VM response has no storage profile")
        hardware = properties.get("hardwareProfile")
        network = properties.get("networkProfile")
        interfaces = network.get("networkInterfaces") if isinstance(network, dict) else None
        os_disk = storage.get("osDisk")
        data = storage.get("dataDisks")
        security = properties.get("securityProfile")
        if (
            require_uuid(properties.get("vmId")) != proof["uuid"]
            or properties.get("provisioningState") != "Succeeded"
            or not isinstance(hardware, dict)
            or hardware.get("vmSize") != "Standard_D2s_v5"
            or storage.get("diskControllerType") != "SCSI"
            or not self.valid_os_attachment(os_disk, proof)
            or not isinstance(data, list)
            or len(data) != 2
            or {entry.get("lun") for entry in data if isinstance(entry, dict)}
            != {0, 7}
            or any(not self.valid_data_attachment(entry, proof) for entry in data)
            or not isinstance(interfaces, list)
            or len(interfaces) != 1
            or not self.valid_nic_attachment(interfaces[0])
            or not isinstance(security, dict)
            or not set(security).issubset({
                "securityType", "encryptionAtHost", "encryptionIdentity",
                "proxyAgentSettings", "uefiSettings",
            })
            or security.get("securityType") != "Standard"
            or (security.get("encryptionAtHost") is not None
                and security["encryptionAtHost"] is not False)
            or any(security.get(field) is not None for field in (
                "encryptionIdentity", "proxyAgentSettings", "uefiSettings",
            ))
        ):
            raise RuntimeError(
                "Pinned Compute VM identity, original disks or explicit "
                "Standard security profile is incompatible"
            )

    def wait_for_boot(self):
        self.record("waiting-boot")
        while time.monotonic() < self.deadline - CLEANUP_HEADROOM:
            self.verify_topology()
            self.verify_network()
            try:
                text = self.az([
                    "vm", "boot-diagnostics", "get-boot-log",
                    "--resource-group", self.group(), "--name", self.name("vm"),
                ])
            except azure.AzureCliError as error:
                if error.code not in (
                    "BlobNotFound", "BootDiagnosticsInformationNotAvailable",
                ):
                    raise
            else:
                if not isinstance(text, str):
                    raise RuntimeError("Azure returned invalid serial output")
                if "HYPERV_TOPOLOGY RESULT PASS" in text:
                    evidence = parse_serial(text, self.state)
                    azure.save_private_text(
                        self.directory / "guest-serial.log", redacted_serial(text)
                    )
                    azure.fsync_directory(self.directory)
                    self.record("accepted", evidence=evidence)
                    return evidence
                if any(value in text for value in (
                    "HYPERV_TOPOLOGY FINAL FAIL", "HYPERV_TOPOLOGY RESULT FAIL",
                    "Unikraft Crash", "Assertion failure", "Exception Type",
                    "main returned 1",
                )):
                    raise RuntimeError("Guest reported a failed read-only topology probe")
            time.sleep(min(5, max(0, self.deadline - time.monotonic())))
        raise RuntimeError(
            "The single VM boot reached its owner-checked cleanup headroom"
        )

    def verify_network(self):
        nic = self.az([
            "network", "nic", "show", "--resource-group", self.group(),
            "--name", self.name("nic"),
        ])
        vnet = self.az([
            "network", "vnet", "show", "--resource-group", self.group(),
            "--name", self.name("vnet"),
        ])
        nsg = self.az([
            "network", "nsg", "show", "--resource-group", self.group(),
            "--name", self.name("nsg"),
        ])
        for role, resource in (("nic", nic), ("vnet", vnet), ("nsg", nsg)):
            owned(self.state, resource, role)
        configs = nic.get("ipConfigurations")
        subnets = vnet.get("subnets")
        if (nic.get("enableIPForwarding") is not False
                or nic.get("enableAcceleratedNetworking") is not False
                or nic.get("networkSecurityGroup") is not None
                or not isinstance(configs, list) or len(configs) != 1
                or not isinstance(configs[0], dict)
                or configs[0].get("name") != "primary"
                or configs[0].get("privateIPAllocationMethod") != "Dynamic"
                or configs[0].get("publicIPAddress") is not None
                or str((configs[0].get("subnet") or {}).get("id", "")).lower()
                != (resource_id(self.state, "vnet") + "/subnets/default").lower()
                or (vnet.get("addressSpace") or {}).get("addressPrefixes")
                != ["10.90.0.0/29"]
                or not isinstance(subnets, list) or len(subnets) != 1
                or not isinstance(subnets[0], dict)
                or subnets[0].get("name") != "default"
                or subnets[0].get("addressPrefix") != "10.90.0.0/29"
                or subnets[0].get("defaultOutboundAccess") is not False
                or subnets[0].get("natGateway") is not None
                or subnets[0].get("routeTable") is not None
                or str((subnets[0].get("networkSecurityGroup") or {}).get("id", "")).lower()
                != resource_id(self.state, "nsg").lower()
                or nsg.get("securityRules") != []):
            raise RuntimeError("Private network gained public ingress or outbound access")

    def inventory_for_cleanup(self, resources):
        if not isinstance(resources, list):
            raise RuntimeError("Resource-group inventory is unavailable")
        expected_roles = set(self.state.get("disks", {}))
        if not expected_roles <= set(ROLES):
            raise RuntimeError("Unknown disk receipt in private state")
        if self.state.get("vm") is not None:
            expected_roles.update(("vm", "nic", "vnet", "nsg"))
            if expected_roles != set(RESOURCE_ROLES):
                raise RuntimeError("A VM is missing its original three disks")
        expected = {resource_id(self.state, role).lower(): role
                    for role in expected_roles}
        actual = {}
        for item in resources:
            if not isinstance(item, dict):
                raise RuntimeError("Invalid resource-group inventory entry")
            identifier = str(item.get("id", "")).lower()
            if identifier in actual or identifier not in expected:
                raise RuntimeError(
                    "Refusing duplicate, foreign or unproven resources; "
                    "original Azure UUID/operation cannot be inferred from "
                    "tags or names; manual owner verification required"
                )
            role = expected[identifier]
            owned(self.state, item, role)
            actual[identifier] = role
        if set(actual) != set(expected):
            raise RuntimeError(
                "Original resource inventory is missing an owned resource; "
                "manual owner verification required"
            )
        if "vm" in expected_roles and (
            self.state.get("boot_count") != 1 or not isinstance(self.state.get("vm"), dict)
        ):
            raise RuntimeError("Original VM is missing its one-boot proof")

    def cleanup(self):
        if self.state["phase"] in ("planned", "prepared"):
            return
        self.deadline = None
        try:
            if self.state.get("pending_create") is not None:
                raise RuntimeError(
                    "An Azure create response or durable receipt is unresolved; "
                    "an absent resource group cannot exclude an in-flight create, "
                    "and a matching name, ID or tags cannot prove the original "
                    "group, disk UUID or ARM deployment correlation"
                )
            if self.az(["group", "exists", "--name", self.group()]) is False:
                if self.state.get("resource_group_id") is not None:
                    raise RuntimeError(
                        "A previously created group is not currently visible; "
                        "absence cannot prove its deletion or exclude delayed visibility"
                    )
                self.record("cleaned")
                return
            group = self.az(["group", "show", "--name", self.group()])
            owned(self.state, group, "group")
            if self.state.get("resource_group_id") != group_id(self.state):
                raise RuntimeError(
                    "Original resource-group creation proof is missing; "
                    "manual owner verification required"
                )
            if not self.state.get("disks"):
                raise RuntimeError(
                    "A resource-group ID is a reusable name path and its tags "
                    "can be copied; no immutable group instance or original "
                    "disk receipt proves this group is the one created"
                )
            resources = self.az([
                "resource", "list", "--resource-group", self.group(),
            ])
            self.inventory_for_cleanup(resources)
            for role in self.state.get("disks", {}):
                self.verify_disk(role, self.disk_show(role, cleanup=True),
                                 attached=(self.state["vm"]["id"]
                                           if isinstance(self.state.get("vm"), dict)
                                           else None), ready=False)
            if self.state.get("vm") is not None:
                self.verify_topology(cleanup=True)
                self.verify_network()
                try:
                    self.az([
                        "vm", "deallocate", "--resource-group", self.group(),
                        "--name", self.name("vm"),
                    ], timeout=300)
                except BaseException as error:
                    # Group deletion remains mandatory if all identities are proven.
                    deallocation_error = error
                else:
                    deallocation_error = None
            else:
                deallocation_error = None
            self.record("deleting-group")
            self.az(["group", "delete", "--name", self.group(), "--yes"], timeout=900)
            if self.az(["group", "exists", "--name", self.group()]) is not False:
                raise RuntimeError("Owned resource-group deletion did not complete")
            self.record("cleaned", group_deletion_observed=True)
            if deallocation_error:
                self.state["deallocation_warning"] = azure.safe_failure_message(
                    deallocation_error
                )
                save(self.directory, self.state)
        except BaseException as error:
            detail = azure.safe_failure_message(
                error, (self.group(), self.state["subscription"],
                        self.state["prefix"], self.state["run_id"])
            )
            try:
                self.record(
                    "cleanup-failed",
                    cleanup_error=detail + "; manual owner verification required before deletion",
                )
            except BaseException as recording:
                raise RuntimeError(
                    "Owner-checked cleanup and durable failure recording both failed: "
                    + detail + "; "
                    + azure.safe_failure_message(recording)
                ) from None
            raise RuntimeError(
                "Owner-checked cleanup refused: " + detail
                + "; manual owner verification required before deletion"
            ) from None


def require_live_cleanup_proof():
    raise RuntimeError(
        "Live #90 allocation is disabled: a lost Azure create response "
        "cannot establish the original resource identity needed for "
        "mandatory owner-checked deletion"
    )


def run(directory, subscription, approved_envelope):
    with locked(directory) as directory:
        state = load(directory)
        if state["phase"] != "prepared" or state.get("boot_count") != 0:
            raise ValueError("Only fresh, unused #90 state can be deployed; use cleanup")
        if azure.validate_subscription_id(subscription) != state["subscription"]:
            raise ValueError("Selected subscription differs from the run envelope")
        if not isinstance(approved_envelope, str) or approved_envelope != envelope_sha(state):
            raise ValueError("Explicit exact #90 resource-envelope approval is required")
        require_live_cleanup_proof()
        verify_inputs(directory, state)
        azure.check_upload_dependencies()
        controller = TopologyRun(state, directory)
        controller.preflight_cloud()
        controller.deadline = time.monotonic() + MAX_RUNTIME
        controller.record("authorized", cleanup_required=True)
        primary = None
        try:
            with azure.interrupt_as_exception():
                controller.create_group()
                for role in ROLES:
                    controller.create_disk(role)
                verify_inputs(directory, state)
                controller.deploy()
                controller.wait_for_boot()
        except BaseException as error:
            primary = error
        cleanup_error = None
        try:
            controller.cleanup()
        except BaseException as error:
            cleanup_error = error
        if primary is not None:
            if cleanup_error is not None:
                raise RuntimeError(
                    "One-boot acceptance failed: "
                    + azure.safe_failure_message(primary)
                    + "; mandatory owner-checked cleanup refused/failed: "
                    + azure.safe_failure_message(cleanup_error)
                ) from None
            raise RuntimeError("One-boot acceptance failed; cleanup completed: "
                               + azure.safe_failure_message(primary)) from None
        if cleanup_error is not None:
            raise RuntimeError("Acceptance is NOT valid until owner-checked cleanup: "
                               + azure.safe_failure_message(cleanup_error)) from None
        receipt = {
            "schema": SCHEMA, "version": 1, "result": "PASS",
            "run_id": state["run_id"], "operation_id": state["operation_id"],
            "image_sha256": state["prepared"]["image_sha256"],
            "disks": state["disks"], "vm": state["vm"],
            "evidence": state["evidence"], "boot_count": 1,
            "cleanup": "complete",
        }
        azure.save_durable_json(directory / "acceptance.json", receipt)
        return receipt


def cleanup_state(directory):
    with locked(directory) as directory:
        state = load(directory)
        if state["phase"] in ("planned", "prepared") or (
            state["phase"] == "cleaned" and state.get("pending_create") is None
            and (state.get("resource_group_id") is None
                 or state.get("group_deletion_observed") is True)
        ):
            return
        TopologyRun(state, directory).cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    planner = commands.add_parser("plan", help="generate fresh build IDs; no cloud calls")
    planner.add_argument("--state-dir", required=True, type=Path)
    planner.add_argument("--subscription", required=True)
    prepared = commands.add_parser(
        "prepare", help="validate local boots and package two fresh read-only seed VHDs"
    )
    prepared.add_argument("--state-dir", required=True, type=Path)
    prepared.add_argument("--prepared-state", required=True, type=Path,
                          help="locally four-booted hyperv-azure.py prepare state")
    prepared.add_argument("--solved-config", required=True, type=Path)
    prepared.add_argument("--expected-config-sha256", required=True)
    prepared.add_argument("--expected-image-sha256", required=True)
    prepared.add_argument("--miz", required=True, type=Path)
    launch = commands.add_parser("run", help="one boot, mandatory owner-checked cleanup")
    launch.add_argument("--state-dir", required=True, type=Path)
    launch.add_argument("--subscription", required=True)
    launch.add_argument("--approved-envelope-sha256", required=True)
    inspect = commands.add_parser("envelope", help="print exact approval envelope; no cloud")
    inspect.add_argument("--state-dir", required=True, type=Path)
    cleanup = commands.add_parser("cleanup", help="resume owner-checked deletion only")
    cleanup.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            state = plan(args.state_dir, args.subscription)
            print(json.dumps({
                "run_id": state["run_id"], "disk_ids": state["disk_ids"],
                "sector_count": SECTORS, "luns": LUNS,
                "solved_config_required": {
                    "CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY": "y",
                    "CONFIG_LIBSTORVSC_LUN_DISCOVERY": "y",
                    "CONFIG_LIBSTORVSC_MAX_DEVICES": "3 or more",
                    "CONFIG_LIBSTORVSC_MAX_LUNS": "2 or more",
                    "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID": state["run_id"],
                    "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID":
                        state["disk_ids"]["data0"],
                    "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID":
                        state["disk_ids"]["data7"],
                    "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS": SECTORS,
                    "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS":
                        SECTORS,
                    "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN": 7,
                },
            }, indent=2))
        elif args.command == "prepare":
            with locked(args.state_dir) as directory:
                state = prepare(directory, load(directory), args.prepared_state,
                                args.solved_config, args.expected_config_sha256,
                                args.expected_image_sha256, args.miz)
            print(json.dumps({"approved_envelope_sha256": envelope_sha(state)}, indent=2))
        elif args.command == "envelope":
            with locked(args.state_dir) as directory:
                state = load(directory)
                verify_inputs(directory, state)
                print(json.dumps({
                    "envelope": envelope(state),
                    "approved_envelope_sha256": envelope_sha(state),
                }, indent=2))
        elif args.command == "run":
            print(json.dumps(run(args.state_dir, args.subscription,
                                 args.approved_envelope_sha256), indent=2))
        elif args.command == "cleanup":
            cleanup_state(args.state_dir)
            print("Owner-checked cleanup completed or no #90 cloud run was started")
    except (RuntimeError, ValueError, OSError) as error:
        raise SystemExit(azure.safe_failure_message(error)) from None


if __name__ == "__main__":
    main()
