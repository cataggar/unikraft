#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Exact, default-off two-boot Azure StorVSC persistence controller."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import errno
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
private_preflight = importlib.import_module("hyperv_private_preflight")

SUPPORT = Path(__file__).resolve().parents[1]
TEMPLATE = SUPPORT / "azure" / "hyperv-persistence.json"
UPLOAD_HELPER = Path(__file__).with_name("hyperv-azure-upload.py")
SHARED_CONTROLLER = Path(__file__).with_name("hyperv-azure.py")
REQUIREMENTS = SUPPORT / "azure" / "requirements.txt"

CONTRACT_SCHEMA = "unikraft.hyperv.persistence-two-boot-contract"
CONTRACT_VERSION = 1
PREFLIGHT_SCHEMA = "unikraft.hyperv.private-preflight-receipt"
PREFLIGHT_VERSION = 3
STATE_SCHEMA = "unikraft.hyperv.persistence-two-boot-state"
STATE_VERSION = 1
RECEIPT_SCHEMA = "unikraft.hyperv.persistence-two-boot-receipt"
RECEIPT_VERSION = 1
WORKLOAD = "guarded-v2-two-boot-persistence"
BOOT_POLICY = "guarded-v2-pristine-unavailable"
PURPOSE = "guarded-v2-two-boot-persistence"
MANAGED_BY = "unikraft-hyperv"

SECTOR_SIZE = 512
SEED0_LBA = 8
SEED1_LBA = 9
INTENT_LBA = 16
RECEIPT_LBA = 17
EXTENT_LBA = 32
EXTENT_SECTORS = 16
MIN_SECTORS = EXTENT_LBA + EXTENT_SECTORS + 1
MAX_SECTORS = (2 * 1024 ** 4) // SECTOR_SIZE
MAX_JSON_BYTES = 256 * 1024
MAX_SERIAL_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_SECONDS = 60 * 60
MIN_RUNTIME_SECONDS = 60
MAX_CLEANUP_SECONDS = 30 * 60
MIN_CLEANUP_SECONDS = 60
PERSISTENCE_VM_SIZES = frozenset((
    "Standard_B1s", "Standard_B2s",
    "Standard_D2s_v5", "Standard_D2as_v5",
))
FILE_NAMES = {
    "guest_vhd": "guest.vhd",
    "data_raw": "data.raw",
    "data_vhd": "data.vhd",
    "seed_manifest": "seed.json",
    "preflight_receipt": "private-receipt.json",
}
PERSISTENCE_INPUT_ROLES = (
    "guest_vhd", "data_raw", "data_vhd", "seed_manifest",
)
PREFLIGHT_INPUT_ROLES = (
    "qemu", "ovmf_code", "ovmf_vars", "capability_raw",
    "raw", "vhd", "efi",
)
RESOURCE_COUNTS = {
    "resource_groups": 1,
    "virtual_machines": 1,
    "managed_os_disks": 1,
    "managed_data_disks": 1,
    "network_interfaces": 1,
    "virtual_networks": 1,
    "network_security_groups": 1,
    "public_ip_addresses": 0,
}
PHASES = frozenset((
    "prepared", "cloud-authorized", "creating-group", "group-created",
    "creating-os-disk", "os-disk-created", "uploading-os-disk",
    "os-disk-ready", "creating-data-disk", "data-disk-created",
    "uploading-data-disk", "data-disk-ready", "deploying-vm",
    "vm-created", "waiting-boot1", "boot1-accepted",
    "deallocating-boot1", "boot1-deallocated",
    "boot2-start-requested", "waiting-boot2", "boot2-accepted",
    "deallocating-boot2", "boot2-deallocated", "acceptance-recorded",
    "cleanup-failed", "deleting-group", "cleaned", "failed",
))
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
AZURE_NAME = re.compile(r"[a-z][a-z0-9-]{5,31}")
RESOURCE_GROUP = re.compile(r"[A-Za-z0-9_.()-]{1,90}")
LOCATION = re.compile(r"[a-z0-9]{3,30}")
START = re.compile(
    r"HYPERV_PERSISTENCE START PASS run=([0-9a-f]{32}) "
    r"address=([0-9]+):([0-9]+):([0-9]+) "
    r"sectors=([0-9]+) sector_size=([0-9]+)"
)
SELECT = re.compile(
    r"HYPERV_PERSISTENCE SELECT PASS id=([0-9]+) "
    r"controller=([0-9]+) state=(-?[0-9]+)"
)
IDENTITY = re.compile(
    r"UK_HYPERV_PERSISTENCE_IDENTITY:1:([0-9]+):"
    r"([0-9a-f]{32}):([0-9a-f]{32}):([0-9a-f]{32}):"
    r"([0-9]+):([0-9]+):([0-9]+):([0-9]+):([0-9]+):"
    r"([0-9]+):([0-9]+):([0-9]+):([0-9]+):([0-9a-f]+)"
)
IO_EVIDENCE = re.compile(
    r"UK_HYPERV_PERSISTENCE_IO:1:([12]):([0-9a-f]{32}):"
    r"([0-9]+):([0-9]+):receipt-verified"
)
MAIN_RETURN = re.compile(r"main returned (-?[0-9]+)")


class EvidenceIncomplete(RuntimeError):
    pass


class PersistenceCleanupError(RuntimeError):
    def __init__(self, failures, recording_error=None):
        self.recording_error = recording_error
        super().__init__(
            "Persistence cleanup failed: " + "; ".join(
                f"{name}: {azure.safe_failure_message(error)}"
                for name, error in failures
            )
        )


def exact_fields(value, fields, description):
    return azure.require_exact_fields(value, fields, description)


def require_integer(value, minimum, maximum, description):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{description} is outside its permitted integer range")
    return value


def require_hex(value, pattern, description):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{description} is invalid")
    return value


def require_uuid(value, description):
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ValueError(f"{description} is invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError(f"{description} is invalid")
    return value


def require_file_record(value, role):
    value = exact_fields(
        value, ("name", "sha256", "size"), f"{role} file record"
    )
    if value["name"] != FILE_NAMES[role]:
        raise ValueError(f"{role} file name is incompatible")
    require_hex(value["sha256"], HEX64, f"{role} SHA-256")
    require_integer(value["size"], 1, MAX_SECTORS * SECTOR_SIZE + 512,
                    f"{role} size")
    return dict(value)


def implementation_contract():
    files = {}
    for name, path in (
        ("controller", Path(__file__)),
        ("template", TEMPLATE),
        ("shared_controller", SHARED_CONTROLLER),
        ("upload_helper", UPLOAD_HELPER),
        (
            "private_preflight",
            Path(private_preflight.__file__).resolve(),
        ),
        ("requirements", REQUIREMENTS),
    ):
        value = azure.read_regular_file(
            path, 4 * 1024 * 1024, f"{name} implementation"
        )
        files[name] = {
            "sha256": hashlib.sha256(value).hexdigest(),
            "size": len(value),
        }
    return {
        "schema": "unikraft.hyperv.persistence-controller-implementation",
        "schema_version": 1,
        "files": files,
    }


def validate_preflight_receipt(
    value, guest_vhd, run_id, disk_id, geometry,
):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "result", "identity",
            "input_manifest_sha256", "implementation", "provenance",
            "capability_reference", "private_build", "inputs",
            "qemu_support", "miz", "packaging", "budget", "host_image",
            "host", "capability_receipt_sha256",
            "private_receipt_sha256", "boot_policy",
            "acceptance_scope", "storage_result", "guarded",
            "capability_boots", "private_boots", "cleanup",
        ),
        "Completed private-preflight receipt",
    )
    inputs = exact_fields(
        value["inputs"], PREFLIGHT_INPUT_ROLES,
        "Completed private-preflight inputs",
    )
    normalized_inputs = {}
    for role in PREFLIGHT_INPUT_ROLES:
        record = exact_fields(
            inputs[role], ("sha256", "size"),
            f"Completed private-preflight {role} input",
        )
        normalized_inputs[role] = {
            "sha256": require_hex(
                record["sha256"], HEX64,
                f"Completed private-preflight {role} SHA-256",
            ),
            "size": require_integer(
                record["size"], 1, MAX_SECTORS * SECTOR_SIZE + 512,
                f"Completed private-preflight {role} size",
            ),
        }
    guarded = exact_fields(
        value["guarded"],
        (
            "schema", "schema_version", "scope", "result", "protocol",
            "identity_policy", "reason", "main_return", "run_id",
            "disk_id", "path", "target", "lun", "sectors",
            "sector_size", "solved_config_sha256", "producer",
        ),
        "Completed guarded V2 contract",
    )
    producer = exact_fields(
        guarded["producer"], ("schema", "schema_version", "files"),
        "Completed guarded producer pin",
    )
    if not isinstance(producer["files"], dict) or not producer["files"]:
        raise ValueError("Completed guarded producer pin is empty")
    for name, digest in producer["files"].items():
        if (
            not isinstance(name, str)
            or not name
            or require_hex(
                digest, HEX64, "Completed guarded producer file"
            ) != digest
        ):
            raise ValueError("Completed guarded producer pin is invalid")
    host = exact_fields(
        value["host"],
        (
            "operation_id", "deployment_correlation_id", "vm_uuid",
            "disk_uuid", "boot_id",
        ),
        "Completed private-preflight host",
    )
    for field in host:
        require_uuid(
            host[field], f"Completed private-preflight host {field}"
        )
    private_build = exact_fields(
        value["private_build"], ("name", "sha256", "size", "receipt"),
        "Completed private build",
    )
    require_hex(
        private_build["sha256"], HEX64,
        "Completed private build receipt SHA-256",
    )
    require_integer(
        private_build["size"], 1, MAX_JSON_BYTES,
        "Completed private build receipt size",
    )
    build_receipt = exact_fields(
        private_build["receipt"],
        (
            "schema", "schema_version", "result", "source_before",
            "source_after", "invocation", "tools", "output",
            "builder_sha256", "guarded",
        ),
        "Completed private build receipt",
    )
    for field in (
        "input_manifest_sha256", "capability_receipt_sha256",
        "private_receipt_sha256",
    ):
        require_hex(value[field], HEX64, f"Completed {field}")
    require_hex(
        guarded["solved_config_sha256"], HEX64,
        "Completed guarded solved configuration",
    )
    private_boots = exact_fields(
        value["private_boots"], ("raw", "vhd"),
        "Completed private boots",
    )
    for image_format in ("raw", "vhd"):
        modes = exact_fields(
            private_boots[image_format],
            ("x2apic", "legacy-apic"),
            "Completed private boot formats",
        )
        for mode in modes.values():
            outcome = exact_fields(
                mode, ("result", "log_sha256", "return_code"),
                "Completed private boot outcome",
            )
            require_hex(
                outcome["log_sha256"], HEX64,
                "Completed private boot log SHA-256",
            )
            if outcome["result"] != "PASS" or outcome["return_code"] != 0:
                raise ValueError("Completed private boot did not pass")
    if (
        value["schema"] != PREFLIGHT_SCHEMA
        or value["schema_version"] != PREFLIGHT_VERSION
        or value["result"] != "PASS"
        or value["boot_policy"] != BOOT_POLICY
        or value["acceptance_scope"] != "platform-only"
        or value["storage_result"] != "UNAVAILABLE"
    ):
        raise ValueError("Completed private x86 preflight is incompatible")
    if (
        value["cleanup"] != "complete"
        or normalized_inputs["vhd"] != {
            "sha256": guest_vhd["sha256"],
            "size": guest_vhd["size"],
        }
        or host["vm_uuid"] == host["disk_uuid"]
        or guarded["schema"]
        != "unikraft.hyperv.guarded-v2-pristine-unavailable"
        or guarded["schema_version"] != 1
        or guarded["scope"] != "platform-only"
        or guarded["result"] != "UNAVAILABLE"
        or guarded["protocol"] != 1
        or guarded["identity_policy"] != 2
        or guarded["reason"] != "no-devices"
        or guarded["main_return"] != 2
        or guarded["run_id"] != run_id
        or guarded["disk_id"] != disk_id
        or guarded["path"] != 0
        or guarded["target"] != 0
        or guarded["lun"] != geometry["lun"]
        or guarded["sectors"] != geometry["sectors"]
        or guarded["sector_size"] != SECTOR_SIZE
        or producer["schema"] != "unikraft.hyperv.guarded-producer-pin"
        or producer["schema_version"] != 2
        or build_receipt["result"] != "PASS"
        or build_receipt["guarded"] != value["guarded"]
        or build_receipt["source_before"] != value["provenance"]
        or build_receipt["source_after"] != value["provenance"]
    ):
        raise ValueError("Completed private x86 preflight is mismatched")
    return {
        **value,
        "inputs": normalized_inputs,
        "host": dict(host),
        "guarded": {
            **guarded,
            "producer": {
                **producer,
                "files": dict(producer["files"]),
            },
        },
        "private_build": {
            **private_build,
            "receipt": dict(build_receipt),
        },
    }


def load_completed_preflight(state_directory, guest_vhd, run_id, disk_id,
                             geometry):
    loader = getattr(private_preflight, "load_completed_receipt", None)
    if not callable(loader):
        raise RuntimeError(
            "Private-preflight completed-handoff validator is unavailable"
        )
    receipt, receipt_path = loader(state_directory)
    validated = validate_preflight_receipt(
        receipt, guest_vhd, run_id, disk_id, geometry
    )
    expected_path = (
        Path(state_directory).resolve(strict=True)
        / FILE_NAMES["preflight_receipt"]
    )
    if Path(receipt_path).resolve(strict=True) != expected_path:
        raise ValueError(
            "Completed private-preflight receipt path is unexpected"
        )
    return validated, expected_path


def validate_seed_manifest(value, contract):
    value = exact_fields(
        value,
        (
            "version", "run_id", "disk_id", "sectors", "sector_size",
            "identity_policy", "identity_policy_version", "path", "target",
            "lun", "seed_lbas", "intent_lba", "receipt_lba", "extent_lba",
            "extent_sectors", "manifest_crc32",
        ),
        "Storage seed manifest",
    )
    geometry = contract["geometry"]
    require_integer(value["manifest_crc32"], 0, (1 << 32) - 1,
                    "Seed manifest CRC")
    if value != {
        "version": 2,
        "run_id": contract["run_id"],
        "disk_id": contract["disk_id"],
        "sectors": geometry["sectors"],
        "sector_size": SECTOR_SIZE,
        "identity_policy": "seed-enrollment-v2",
        "identity_policy_version": 2,
        "path": None,
        "target": None,
        "lun": geometry["lun"],
        "seed_lbas": [SEED0_LBA, SEED1_LBA],
        "intent_lba": INTENT_LBA,
        "receipt_lba": RECEIPT_LBA,
        "extent_lba": EXTENT_LBA,
        "extent_sectors": EXTENT_SECTORS,
        "manifest_crc32": value["manifest_crc32"],
    }:
        raise ValueError("Storage seed manifest does not match the V2 contract")
    return dict(value)


def validate_contract(value):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "workload", "implementation",
            "run_id", "disk_id", "geometry", "azure", "files",
            "preflight",
        ),
        "Two-boot persistence contract",
    )
    if (
        value["schema"] != CONTRACT_SCHEMA
        or value["schema_version"] != CONTRACT_VERSION
        or value["workload"] != WORKLOAD
        or value["implementation"] != implementation_contract()
    ):
        raise ValueError("Two-boot persistence contract is incompatible")
    require_hex(value["run_id"], HEX32, "Persistence run ID")
    require_hex(value["disk_id"], HEX32, "Persistence disk ID")
    if (
        value["run_id"] == "0" * 32
        or value["disk_id"] == "0" * 32
        or value["run_id"] == value["disk_id"]
    ):
        raise ValueError(
            "Persistence run and disk IDs must be distinct nonzero IDs"
        )
    geometry = exact_fields(
        value["geometry"], ("sectors", "sector_size", "lun"),
        "Persistence geometry",
    )
    require_integer(
        geometry["sectors"], MIN_SECTORS, MAX_SECTORS,
        "Persistence sector count",
    )
    if (
        geometry["sector_size"] != SECTOR_SIZE
        or geometry["sectors"] % (1024 * 1024 // SECTOR_SIZE)
    ):
        raise ValueError(
            "Persistence geometry must use 512-byte sectors and whole MiB"
        )
    require_integer(geometry["lun"], 0, 63, "Azure data-disk LUN")

    cloud = exact_fields(
        value["azure"],
        (
            "subscription", "location", "vm_size", "vm_vcpus",
            "name_prefix", "resource_group", "vm_name", "os_disk_name",
            "data_disk_name", "nic_name", "vnet_name", "nsg_name",
            "os_disk_sku", "data_disk_sku", "resource_counts",
            "max_boots", "runtime_seconds", "cleanup_seconds",
        ),
        "Azure resource envelope",
    )
    azure.validate_subscription_id(cloud["subscription"])
    if (
        not isinstance(cloud["location"], str)
        or not LOCATION.fullmatch(cloud["location"])
        or cloud["vm_size"] not in PERSISTENCE_VM_SIZES
        or not isinstance(cloud["name_prefix"], str)
        or not AZURE_NAME.fullmatch(cloud["name_prefix"])
        or not isinstance(cloud["resource_group"], str)
        or not RESOURCE_GROUP.fullmatch(cloud["resource_group"])
        or cloud["resource_group"] != cloud["name_prefix"] + "-rg"
        or cloud["vm_name"] != cloud["name_prefix"] + "-vm"
        or cloud["os_disk_name"] != cloud["name_prefix"] + "-os"
        or cloud["data_disk_name"] != cloud["name_prefix"] + "-data"
        or cloud["nic_name"] != cloud["name_prefix"] + "-nic"
        or cloud["vnet_name"] != cloud["name_prefix"] + "-vnet"
        or cloud["nsg_name"] != cloud["name_prefix"] + "-nsg"
        or cloud["os_disk_sku"] not in ("Standard_LRS", "StandardSSD_LRS")
        or cloud["data_disk_sku"] not in (
            "Standard_LRS", "StandardSSD_LRS",
        )
        or cloud["resource_counts"] != RESOURCE_COUNTS
        or cloud["max_boots"] != 2
    ):
        raise ValueError("Azure resource envelope is invalid or unbounded")
    require_integer(cloud["vm_vcpus"], 1, 2, "Azure VM vCPU count")
    require_integer(
        cloud["runtime_seconds"], MIN_RUNTIME_SECONDS, MAX_RUNTIME_SECONDS,
        "Azure persistence runtime",
    )
    require_integer(
        cloud["cleanup_seconds"], MIN_CLEANUP_SECONDS, MAX_CLEANUP_SECONDS,
        "Azure cleanup runtime",
    )

    files = exact_fields(value["files"], FILE_NAMES, "Persistence inputs")
    files = {
        role: require_file_record(files[role], role)
        for role in FILE_NAMES
    }
    logical_size = geometry["sectors"] * SECTOR_SIZE
    if (
        files["data_raw"]["size"] != logical_size
        or files["data_vhd"]["size"] != logical_size + 512
        or files["guest_vhd"]["size"] < 1024
        or files["seed_manifest"]["size"] > MAX_JSON_BYTES
        or files["preflight_receipt"]["size"] > MAX_JSON_BYTES
    ):
        raise ValueError("Persistence input geometry is incompatible")
    preflight = validate_preflight_receipt(
        value["preflight"], files["guest_vhd"],
        value["run_id"], value["disk_id"], geometry,
    )
    return {
        **value,
        "geometry": dict(geometry),
        "azure": {**cloud, "resource_counts": dict(RESOURCE_COUNTS)},
        "files": files,
        "preflight": preflight,
    }


def private_directory(path, description, *, must_exist=True):
    path = Path(path).absolute()
    if must_exist:
        resolved = path.resolve(strict=True)
        metadata = path.stat()
        if (
            resolved != path
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError(f"{description} must be owner-only and symlink-free")
    else:
        parent = path.parent.resolve(strict=True)
        if parent != path.parent:
            raise ValueError(f"{description} parent must be symlink-free")
    return path


class PersistenceStateLock:
    def __init__(self, state_directory):
        self.directory = Path(state_directory).absolute()
        self.path = self.directory / ".persistence-controller.lock"
        self.descriptor = None

    def __enter__(self):
        private_directory(
            self.directory, "Persistence state directory"
        )
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            self.descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise ValueError(
                "Persistence state lock must be a private regular file"
            ) from error
        try:
            metadata = os.fstat(self.descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
            ):
                raise ValueError(
                    "Persistence state lock must be owner-only"
                )
            try:
                fcntl.flock(
                    self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                )
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise RuntimeError(
                        "Persistence state is already controlled by "
                        "another process"
                    ) from None
                raise
            return self
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = None
            raise

    def __exit__(self, _error_type, _error, _traceback):
        if self.descriptor is not None:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = None


def read_json(path, description, *, canonical=True):
    raw = azure.read_regular_file(path, MAX_JSON_BYTES, description)
    value = azure.parse_strict_json(raw, description)
    if canonical and raw != azure.canonical_json(value):
        raise ValueError(f"{description} must be canonical JSON")
    return value, raw


def file_record(path, name, description, maximum):
    path = Path(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not 0 < metadata.st_size <= maximum
    ):
        raise ValueError(f"{description} has an invalid type or size")
    return {
        "name": name,
        "sha256": azure.image_sha256(path),
        "size": metadata.st_size,
    }


def sha256_prefix(path, length):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        remaining = length
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("Fixed VHD data region is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def validate_vhd_footer(
    vhd_path, logical_size, description, expected_uuid=None,
):
    with Path(vhd_path).open("rb") as source:
        source.seek(-512, os.SEEK_END)
        footer = bytearray(source.read(512))
    checksum = struct.unpack_from(">I", footer, 64)[0]
    footer[64:68] = b"\0" * 4
    expected_checksum = (~sum(footer)) & 0xFFFFFFFF
    if (
        footer[0:8] != b"conectix"
        or struct.unpack_from(">I", footer, 12)[0] != 0x00010000
        or struct.unpack_from(">Q", footer, 16)[0] != 0xFFFFFFFFFFFFFFFF
        or struct.unpack_from(">Q", footer, 40)[0] != logical_size
        or struct.unpack_from(">Q", footer, 48)[0] != logical_size
        or struct.unpack_from(">I", footer, 60)[0] != 2
        or checksum != expected_checksum
        or not any(footer[68:84])
        or (
            expected_uuid is not None
            and footer[68:84].hex() != expected_uuid
        )
    ):
        raise ValueError(f"{description} is not an exact valid fixed VHD")


def validate_fixed_vhd(
    raw_path, vhd_path, raw_record, vhd_record, disk_id,
):
    if (
        Path(raw_path).stat().st_size != raw_record["size"]
        or azure.image_sha256(raw_path) != raw_record["sha256"]
        or Path(vhd_path).stat().st_size != vhd_record["size"]
        or azure.image_sha256(vhd_path) != vhd_record["sha256"]
        or sha256_prefix(vhd_path, raw_record["size"])
        != raw_record["sha256"]
    ):
        raise ValueError("Seeded raw and fixed-VHD bytes do not match")
    validate_vhd_footer(
        vhd_path, raw_record["size"], "Data disk", disk_id
    )


def validate_seed_bytes(raw_path, manifest):
    with Path(raw_path).open("rb") as source:
        source.seek(SEED0_LBA * SECTOR_SIZE)
        seed0 = source.read(SECTOR_SIZE)
        seed1 = source.read(SECTOR_SIZE)
        source.seek(INTENT_LBA * SECTOR_SIZE)
        intent = source.read(SECTOR_SIZE)
        receipt = source.read(SECTOR_SIZE)
        source.seek(EXTENT_LBA * SECTOR_SIZE)
        extent = source.read(EXTENT_SECTORS * SECTOR_SIZE)
        source.seek(0)
        first = source.read(SECTOR_SIZE)
        source.seek((manifest["sectors"] - 1) * SECTOR_SIZE)
        last = source.read(SECTOR_SIZE)
    if (
        len(seed0) != SECTOR_SIZE
        or seed0 != seed1
        or seed0[:8] != b"UKPSEED2"
        or struct.unpack_from("<H", seed0, 8)[0] != 2
        or struct.unpack_from("<H", seed0, 10)[0] != 128
        or struct.unpack_from("<I", seed0, 12)[0] != SECTOR_SIZE
        or seed0[16:32].hex() != manifest["run_id"]
        or seed0[32:48].hex() != manifest["disk_id"]
        or struct.unpack_from("<Q", seed0, 48)[0] != manifest["sectors"]
        or struct.unpack_from("<I", seed0, 56)[0] != SECTOR_SIZE
        or struct.unpack_from("<I", seed0, 60)[0] != 2
        or struct.unpack_from("<Q", seed0, 64)[0] != SEED0_LBA
        or struct.unpack_from("<Q", seed0, 72)[0] != SEED1_LBA
        or struct.unpack_from("<Q", seed0, 80)[0] != INTENT_LBA
        or struct.unpack_from("<Q", seed0, 88)[0] != RECEIPT_LBA
        or struct.unpack_from("<Q", seed0, 96)[0] != EXTENT_LBA
        or struct.unpack_from("<I", seed0, 104)[0] != EXTENT_SECTORS
        or seed0[108:112] != bytes((2, 0, manifest["lun"], 0))
    ):
        raise ValueError("Seeded data bytes do not match the V2 manifest")
    stored_crc = struct.unpack_from("<I", seed0, 508)[0]
    seed_for_crc = bytearray(seed0)
    seed_for_crc[508:512] = b"\0" * 4
    if (
        stored_crc != manifest["manifest_crc32"]
        or zlib.crc32(seed_for_crc) != stored_crc
        or any(intent)
        or any(receipt)
        or any(extent)
        or any(first)
        or any(last)
    ):
        raise ValueError("Seeded data disk is not pristine")


def create_contract(output_path, *, run_id, disk_id, sectors, lun,
                    subscription, location, vm_size, vm_vcpus, name_prefix,
                    os_disk_sku, data_disk_sku, runtime_seconds,
                    cleanup_seconds, inputs, preflight_state_directory):
    require_hex(run_id, HEX32, "Persistence run ID")
    require_hex(disk_id, HEX32, "Persistence disk ID")
    require_integer(sectors, MIN_SECTORS, MAX_SECTORS, "Sector count")
    require_integer(lun, 0, 63, "Data-disk LUN")
    if set(inputs) != set(PERSISTENCE_INPUT_ROLES):
        raise ValueError("Persistence contract inputs are incomplete")
    geometry = {
        "sectors": sectors,
        "sector_size": SECTOR_SIZE,
        "lun": lun,
    }
    guest_record = file_record(
        inputs["guest_vhd"], FILE_NAMES["guest_vhd"],
        "guest_vhd input", MAX_SECTORS * SECTOR_SIZE + 512,
    )
    preflight, preflight_path = load_completed_preflight(
        preflight_state_directory, guest_record,
        run_id, disk_id, geometry,
    )
    all_inputs = {
        **inputs,
        "preflight_receipt": preflight_path,
    }
    files = {
        role: file_record(
            path, FILE_NAMES[role], f"{role} input",
            (
                MAX_JSON_BYTES if role in (
                    "seed_manifest", "preflight_receipt"
                ) else MAX_SECTORS * SECTOR_SIZE + 512
            ),
        )
        for role, path in all_inputs.items()
    }
    current_preflight, _ = read_json(
        preflight_path, "Completed private-preflight receipt",
        canonical=False,
    )
    if current_preflight != preflight:
        raise ValueError(
            "Completed private-preflight receipt changed during validation"
        )
    if files["guest_vhd"] != guest_record:
        raise ValueError("Guarded guest input changed during preflight validation")
    prefix = name_prefix
    contract = {
        "schema": CONTRACT_SCHEMA,
        "schema_version": CONTRACT_VERSION,
        "workload": WORKLOAD,
        "implementation": implementation_contract(),
        "run_id": run_id,
        "disk_id": disk_id,
        "geometry": geometry,
        "azure": {
            "subscription": subscription,
            "location": location,
            "vm_size": vm_size,
            "vm_vcpus": vm_vcpus,
            "name_prefix": prefix,
            "resource_group": prefix + "-rg",
            "vm_name": prefix + "-vm",
            "os_disk_name": prefix + "-os",
            "data_disk_name": prefix + "-data",
            "nic_name": prefix + "-nic",
            "vnet_name": prefix + "-vnet",
            "nsg_name": prefix + "-nsg",
            "os_disk_sku": os_disk_sku,
            "data_disk_sku": data_disk_sku,
            "resource_counts": dict(RESOURCE_COUNTS),
            "max_boots": 2,
            "runtime_seconds": runtime_seconds,
            "cleanup_seconds": cleanup_seconds,
        },
        "files": files,
        "preflight": preflight,
    }
    contract = validate_contract(contract)
    seed, _ = read_json(
        inputs["seed_manifest"], "Storage seed manifest", canonical=False
    )
    seed = validate_seed_manifest(seed, contract)
    validate_seed_bytes(inputs["data_raw"], seed)
    validate_fixed_vhd(
        inputs["data_raw"], inputs["data_vhd"],
        files["data_raw"], files["data_vhd"],
        contract["disk_id"],
    )
    validate_vhd_footer(
        inputs["guest_vhd"], files["guest_vhd"]["size"] - 512,
        "Guarded guest image",
    )
    output_path = Path(output_path).absolute()
    if output_path.parent.resolve(strict=True) != output_path.parent:
        raise ValueError("Contract output parent must be symlink-free")
    descriptor = os.open(
        output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        value = azure.canonical_json(contract)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        azure.fsync_directory(output_path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return hashlib.sha256(value).hexdigest()


def prepare_state(contract_path, expected_contract_sha256, state_directory,
                  inputs, preflight_state_directory):
    contract_value, contract_bytes = read_json(
        contract_path, "Two-boot persistence contract"
    )
    if (
        hashlib.sha256(contract_bytes).hexdigest()
        != require_hex(
            expected_contract_sha256, HEX64,
            "Expected persistence contract SHA-256",
        )
    ):
        raise ValueError("Two-boot persistence contract digest does not match")
    contract = validate_contract(contract_value)
    if set(inputs) != set(PERSISTENCE_INPUT_ROLES):
        raise ValueError("Persistence prepare inputs are incomplete")
    preflight, preflight_path = load_completed_preflight(
        preflight_state_directory, contract["files"]["guest_vhd"],
        contract["run_id"], contract["disk_id"], contract["geometry"],
    )
    all_inputs = {
        **inputs,
        "preflight_receipt": preflight_path,
    }
    for role, path in all_inputs.items():
        record = contract["files"][role]
        if (
            Path(path).is_symlink()
            or not Path(path).is_file()
            or Path(path).stat().st_size != record["size"]
            or azure.image_sha256(path) != record["sha256"]
        ):
            raise ValueError(f"{role} input differs from the contract")
    seed, seed_bytes = read_json(
        inputs["seed_manifest"], "Storage seed manifest", canonical=False
    )
    if hashlib.sha256(seed_bytes).hexdigest() != (
        contract["files"]["seed_manifest"]["sha256"]
    ):
        raise ValueError("Storage seed manifest fingerprint changed")
    seed = validate_seed_manifest(seed, contract)
    if (
        azure.image_sha256(preflight_path)
        != contract["files"]["preflight_receipt"]["sha256"]
        or preflight != contract["preflight"]
    ):
        raise ValueError("Private preflight receipt differs from the contract")
    validate_fixed_vhd(
        inputs["data_raw"], inputs["data_vhd"],
        contract["files"]["data_raw"], contract["files"]["data_vhd"],
        contract["disk_id"],
    )
    validate_seed_bytes(inputs["data_raw"], seed)
    validate_vhd_footer(
        inputs["guest_vhd"],
        contract["files"]["guest_vhd"]["size"] - 512,
        "Guarded guest image",
    )
    state_directory = private_directory(
        state_directory, "Persistence state directory", must_exist=False
    )
    state_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    copied = state_directory / "inputs"
    copied.mkdir(mode=0o700)
    try:
        contract_target = copied / "contract.json"
        with contract_target.open("xb") as output:
            os.chmod(contract_target, 0o600)
            output.write(contract_bytes)
            output.flush()
            os.fsync(output.fileno())
        for role, source in all_inputs.items():
            record = contract["files"][role]
            azure.copy_regular_file(
                Path(source), copied / record["name"],
                record["size"], record["sha256"],
            )
        state = {
            "schema": STATE_SCHEMA,
            "schema_version": STATE_VERSION,
            "phase": "prepared",
            "contract_sha256": expected_contract_sha256,
            "contract": contract,
            "cleanup_required": False,
            "boot_count": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        azure.save_durable_json(state_directory / "state.json", state)
        azure.fsync_directory(copied)
        return state_directory
    except BaseException:
        import shutil
        shutil.rmtree(state_directory, ignore_errors=True)
        raise


def validate_state(state):
    if (
        not isinstance(state, dict)
        or state.get("schema") != STATE_SCHEMA
        or state.get("schema_version") != STATE_VERSION
        or state.get("phase") not in PHASES
        or type(state.get("cleanup_required")) is not bool
        or type(state.get("boot_count")) is not int
        or not 0 <= state["boot_count"] <= 2
        or not isinstance(state.get("created_at"), str)
    ):
        raise ValueError("Persistence state is incompatible")
    contract = validate_contract(state.get("contract"))
    if (
        state.get("contract_sha256")
        != hashlib.sha256(azure.canonical_json(contract)).hexdigest()
    ):
        raise ValueError("Persistence state contract binding is invalid")
    if "resource_group_id" in state and (
        not isinstance(state["resource_group_id"], str)
        or not state["resource_group_id"]
    ):
        raise ValueError("Resource-group proof is invalid")
    for field in ("os_disk", "data_disk"):
        if field in state:
            proof = exact_fields(
                state[field], ("id", "uuid"), f"{field} proof"
            )
            require_uuid(proof["uuid"], f"{field} UUID")
            if not isinstance(proof["id"], str) or not proof["id"]:
                raise ValueError(f"{field} resource ID is invalid")
    if "vm" in state:
        proof = exact_fields(
            state["vm"],
            (
                "id", "uuid", "deployment_id", "correlation_id",
                "nic_id", "os_disk_id", "data_disk_id",
            ),
            "VM deployment proof",
        )
        require_uuid(proof["uuid"], "VM UUID")
        require_uuid(proof["correlation_id"], "Deployment correlation UUID")
        if any(not isinstance(proof[field], str) or not proof[field]
               for field in proof if field not in ("uuid", "correlation_id")):
            raise ValueError("VM deployment proof is invalid")
    if "vm_operation" in state:
        operation = exact_fields(
            state["vm_operation"],
            ("phase", "operation_id", "deployment_id"),
            "VM deployment operation",
        )
        require_uuid(
            operation["operation_id"], "VM deployment operation UUID"
        )
        if (
            operation["phase"] not in ("pending", "created")
            or not isinstance(operation["deployment_id"], str)
            or not operation["deployment_id"]
            or (
                operation["phase"] == "created"
                and not isinstance(state.get("vm"), dict)
            )
        ):
            raise ValueError("VM deployment operation is invalid")
    if isinstance(state.get("vm"), dict) and (
        not isinstance(state.get("vm_operation"), dict)
        or state["vm_operation"]["phase"] != "created"
        or state["vm_operation"]["deployment_id"]
        != state["vm"]["deployment_id"]
    ):
        raise ValueError("VM proof lacks its original deployment operation")
    resource_uuids = [
        state[field]["uuid"]
        for field in ("os_disk", "data_disk", "vm")
        if isinstance(state.get(field), dict)
    ]
    if len(resource_uuids) != len(set(resource_uuids)):
        raise ValueError("Persistence resource UUID proofs are not distinct")
    if "enrolled_identity" in state:
        validate_identity(state["enrolled_identity"], contract)
    if "boot1" in state:
        boot1 = validate_boot_evidence(
            state["boot1"], 1, contract,
            state.get("enrolled_identity"),
        )
        require_integer(
            state.get("boot1_serial_bytes"), 1, MAX_SERIAL_BYTES,
            "Boot 1 serial byte count",
        )
        require_hex(
            state.get("boot1_serial_sha256"), HEX64,
            "Boot 1 serial SHA-256",
        )
        if (
            state["boot1_serial_bytes"] != boot1["segment_bytes"]
            or state["boot1_serial_sha256"] != boot1["segment_sha256"]
        ):
            raise ValueError("Boot 1 durable serial binding is invalid")
    if "boot2" in state:
        validate_boot_evidence(
            state["boot2"], 2, contract,
            state.get("enrolled_identity"),
        )
        if "boot1" not in state:
            raise ValueError("Boot 2 state lacks Boot 1 evidence")
    if "acceptance_receipt_sha256" in state:
        require_hex(
            state["acceptance_receipt_sha256"], HEX64,
            "Acceptance receipt SHA-256",
        )
    return state


def load_state(directory):
    directory = private_directory(directory, "Persistence state directory")
    value, _ = read_json(
        directory / "state.json", "Persistence state", canonical=False
    )
    return validate_state(value), directory / "state.json"


def verify_immutable_inputs(state, directory):
    contract = state["contract"]
    contract_path = directory / "inputs" / "contract.json"
    raw = azure.read_regular_file(
        contract_path, MAX_JSON_BYTES, "Prepared persistence contract"
    )
    if (
        hashlib.sha256(raw).hexdigest() != state["contract_sha256"]
        or azure.parse_strict_json(raw, "Prepared persistence contract")
        != contract
        or implementation_contract() != contract["implementation"]
    ):
        raise ValueError(
            "Persistence contract or controller implementation changed"
        )
    for role, record in contract["files"].items():
        path = directory / "inputs" / record["name"]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != record["size"]
            or azure.image_sha256(path) != record["sha256"]
        ):
            raise ValueError(f"Prepared {role} input changed")
    seed, _ = read_json(
        directory / "inputs" / FILE_NAMES["seed_manifest"],
        "Prepared storage seed manifest", canonical=False,
    )
    seed = validate_seed_manifest(seed, contract)
    preflight, _ = read_json(
        directory / "inputs" / FILE_NAMES["preflight_receipt"],
        "Prepared exact-image private preflight receipt", canonical=False,
    )
    if validate_preflight_receipt(
        preflight, contract["files"]["guest_vhd"],
        contract["run_id"], contract["disk_id"], contract["geometry"],
    ) != contract["preflight"]:
        raise ValueError("Prepared private x86 preflight evidence changed")
    validate_fixed_vhd(
        directory / "inputs" / FILE_NAMES["data_raw"],
        directory / "inputs" / FILE_NAMES["data_vhd"],
        contract["files"]["data_raw"], contract["files"]["data_vhd"],
        contract["disk_id"],
    )
    validate_seed_bytes(
        directory / "inputs" / FILE_NAMES["data_raw"], seed
    )
    validate_vhd_footer(
        directory / "inputs" / FILE_NAMES["guest_vhd"],
        contract["files"]["guest_vhd"]["size"] - 512,
        "Prepared guarded guest image",
    )


def clean_lines(text):
    if not isinstance(text, str):
        raise ValueError("Serial evidence must be text")
    if len(text.encode("utf-8")) > MAX_SERIAL_BYTES:
        raise ValueError("Serial evidence exceeds its 4 MiB limit")
    return [
        azure.ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
        for line in text.splitlines()
    ]


def single_match(lines, pattern, description):
    found = []
    for index, line in enumerate(lines):
        match = pattern.fullmatch(line)
        if match:
            found.append((index, match))
    if not found:
        raise EvidenceIncomplete(f"{description} is not available yet")
    if len(found) != 1:
        raise ValueError(f"Serial evidence has repeated {description}")
    return found[0]


def validate_identity(value, contract):
    value = exact_fields(
        value,
        (
            "protocol", "policy", "run_id", "disk_id", "controller_guid",
            "path", "target", "lun", "sectors", "sector_size",
            "vpd_length", "vpd_code_set", "vpd_type",
            "vpd_association", "vpd_id",
        ),
        "Enrolled storage identity",
    )
    geometry = contract["geometry"]
    for field, minimum, maximum in (
        ("protocol", 1, 1),
        ("policy", 2, 2),
        ("path", 0, 255),
        ("target", 0, 255),
        ("lun", 0, 255),
        ("sectors", MIN_SECTORS, MAX_SECTORS),
        ("sector_size", SECTOR_SIZE, SECTOR_SIZE),
        ("vpd_length", 1, 128),
        ("vpd_code_set", 0, 255),
        ("vpd_type", 0, 255),
        ("vpd_association", 0, 255),
    ):
        require_integer(
            value[field], minimum, maximum,
            f"Enrolled storage identity {field}",
        )
    if (
        value["run_id"] != contract["run_id"]
        or value["disk_id"] != contract["disk_id"]
        or value["lun"] != geometry["lun"]
        or value["sectors"] != geometry["sectors"]
        or not isinstance(value["controller_guid"], str)
        or not HEX32.fullmatch(value["controller_guid"])
        or value["controller_guid"] == "0" * 32
        or not isinstance(value["vpd_id"], str)
        or len(value["vpd_id"]) != value["vpd_length"] * 2
        or not re.fullmatch(r"[0-9a-f]+", value["vpd_id"])
        or set(value["vpd_id"]) == {"0"}
    ):
        raise ValueError("Enrolled storage identity does not match the contract")
    return dict(value)


def validate_boot_evidence(value, boot, contract, enrolled_identity=None):
    value = exact_fields(
        value,
        (
            "boot", "identity", "writes", "flushes", "receipt",
            "main_return", "segment_sha256", "segment_bytes",
        ),
        f"Boot {boot} evidence",
    )
    expected_writes, expected_flushes = ((5, 3) if boot == 1 else (0, 0))
    require_integer(value["boot"], boot, boot, f"Boot {boot} number")
    require_integer(
        value["writes"], expected_writes, expected_writes,
        f"Boot {boot} write count",
    )
    require_integer(
        value["flushes"], expected_flushes, expected_flushes,
        f"Boot {boot} flush count",
    )
    require_integer(value["main_return"], 0, 0, f"Boot {boot} return")
    require_integer(
        value["segment_bytes"], 1, MAX_SERIAL_BYTES,
        f"Boot {boot} serial byte count",
    )
    require_hex(
        value["segment_sha256"], HEX64, f"Boot {boot} serial SHA-256"
    )
    identity = validate_identity(value["identity"], contract)
    if (
        value["receipt"] != "verified"
        or (
            enrolled_identity is not None
            and identity != enrolled_identity
        )
    ):
        raise ValueError(f"Boot {boot} durable evidence is incompatible")
    return {**value, "identity": identity}


def identity_from_match(match, contract):
    values = match.groups()
    identity = {
        "protocol": 1,
        "policy": int(values[0]),
        "run_id": values[1],
        "disk_id": values[2],
        "controller_guid": values[3],
        "path": int(values[4]),
        "target": int(values[5]),
        "lun": int(values[6]),
        "sectors": int(values[7]),
        "sector_size": int(values[8]),
        "vpd_length": int(values[9]),
        "vpd_code_set": int(values[10]),
        "vpd_type": int(values[11]),
        "vpd_association": int(values[12]),
        "vpd_id": values[13],
    }
    return validate_identity(identity, contract)


def parse_boot_segment(text, boot, contract, enrolled_identity=None):
    require_integer(boot, 1, 2, "Persistence boot number")
    lines = clean_lines(text)
    terminal = any(MAIN_RETURN.fullmatch(line) for line in lines)

    def required(pattern, description):
        try:
            return single_match(lines, pattern, description)
        except EvidenceIncomplete:
            if terminal:
                raise ValueError(
                    "Completed guest serial lacks " + description
                ) from None
            raise

    forbidden = [
        line for line in lines
        if line.startswith((
            "UK_HYPERV_ACCEPTANCE_FAIL:",
            "UK_HYPERV_PERSISTENCE_UNAVAILABLE:",
            "HYPERV_PERSISTENCE SELECT FAIL",
            "HYPERV_PERSISTENCE SELECT UNAVAILABLE",
            "HYPERV_PERSISTENCE FINAL FAIL",
        ))
        or any(marker in line for marker in (
            "Unikraft Crash", "Assertion failure", "Exception Type",
        ))
    ]
    nonzero_returns = [
        line for line in lines
        if (match := MAIN_RETURN.fullmatch(line)) and int(match.group(1)) != 0
    ]
    if forbidden or nonzero_returns:
        raise ValueError("Guest reported failure or unavailable evidence")
    if boot == 2 and any(
        line.startswith((
            "HYPERV_PERSISTENCE BOOT1_",
            "UK_HYPERV_PERSISTENCE_BOOT1_",
            "UK_HYPERV_PERSISTENCE_IO:1:1:",
        ))
        or any(
            marker in line.upper()
            for marker in (
                "BOOT1", "RESEED", "FRESH_WRITE", "FRESH-WRITE",
                "FRESH WRITE", "INTENT_WRITE", "INTENT WRITE",
            )
        )
        for line in lines
    ):
        raise ValueError("Boot 2 serial segment contains Boot 1 or write evidence")
    if boot == 1 and any(
        line.startswith((
            "HYPERV_PERSISTENCE BOOT2_",
            "UK_HYPERV_PERSISTENCE_BOOT2_",
            "UK_HYPERV_PERSISTENCE_IO:1:2:",
        ))
        for line in lines
    ):
        raise ValueError("Boot 1 serial segment contains Boot 2 evidence")

    start_index, start = required(START, "persistence START marker")
    select_index, select = required(SELECT, "persistence SELECT marker")
    identity_index, identity_match = required(
        IDENTITY, "persistence identity marker"
    )
    expected_action = re.compile(
        rf"HYPERV_PERSISTENCE BOOT{boot}_"
        rf"{'WRITE' if boot == 1 else 'READ'} PASS "
        rf"run={contract['run_id']}"
    )
    action_index, _ = required(
        expected_action, f"Boot {boot} action marker"
    )
    io_index, io_match = required(
        IO_EVIDENCE, f"Boot {boot} I/O marker"
    )
    complete = re.compile(
        rf"UK_HYPERV_PERSISTENCE_BOOT{boot}_COMPLETE:"
        rf"{contract['run_id']}"
    )
    complete_index, _ = required(
        complete, f"Boot {boot} completion receipt"
    )
    final_index, _ = required(
        re.compile(r"HYPERV_PERSISTENCE FINAL PASS rc=0"),
        "persistence final marker",
    )
    return_index, returned = required(MAIN_RETURN, "normal main return")
    if int(returned.group(1)) != 0:
        raise ValueError("Persistence guest returned a nonzero result")

    geometry = contract["geometry"]
    if (
        start.group(1) != contract["run_id"]
        or int(start.group(2)) != 0
        or int(start.group(3)) != 0
        or int(start.group(4)) != geometry["lun"]
        or int(start.group(5)) != geometry["sectors"]
        or int(start.group(6)) != SECTOR_SIZE
        or int(select.group(3)) != (0 if boot == 1 else 2)
    ):
        raise ValueError("Persistence selection does not match this boot contract")
    identity = identity_from_match(identity_match, contract)
    if enrolled_identity is not None and identity != enrolled_identity:
        raise ValueError("Boot 2 storage identity drifted from Boot 1")
    expected_writes, expected_flushes = ((5, 3) if boot == 1 else (0, 0))
    if (
        int(io_match.group(1)) != boot
        or io_match.group(2) != contract["run_id"]
        or int(io_match.group(3)) != expected_writes
        or int(io_match.group(4)) != expected_flushes
    ):
        raise ValueError("Persistence I/O evidence is incomplete or excessive")
    order = (
        start_index, select_index, identity_index, action_index, io_index,
        complete_index, final_index, return_index,
    )
    if tuple(sorted(order)) != order:
        raise ValueError("Persistence serial evidence is out of causal order")
    expected_indices = {
        start_index, select_index, identity_index, action_index, io_index,
        complete_index, final_index,
    }
    candidate = re.compile(
        r"HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
        r"reason=boot-signature id=[0-9]+"
    )
    candidate_indices = [
        index for index, line in enumerate(lines) if candidate.fullmatch(line)
    ]
    if (
        len(candidate_indices) > 16
        or any(
            index <= start_index or index >= select_index
            for index in candidate_indices
        )
    ):
        raise ValueError(
            "Persistence candidate-rejection evidence is unbounded or unordered"
        )
    for index, line in enumerate(lines):
        if line.startswith((
            "HYPERV_PERSISTENCE ",
            "UK_HYPERV_PERSISTENCE_",
        )) and index not in expected_indices and not candidate.fullmatch(line):
            raise ValueError(
                "Persistence segment has an unknown or extra protocol marker"
            )
    return {
        "boot": boot,
        "identity": identity,
        "writes": expected_writes,
        "flushes": expected_flushes,
        "receipt": "verified",
        "main_return": 0,
        "segment_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "segment_bytes": len(text.encode("utf-8")),
    }


def boot2_suffix(full_text, boot1_bytes, boot1_sha256):
    if not isinstance(full_text, str):
        raise ValueError("Accumulated serial evidence must be text")
    full = full_text.encode("utf-8")
    if (
        type(boot1_bytes) is not int
        or not 1 <= boot1_bytes <= MAX_SERIAL_BYTES
        or len(full) < boot1_bytes
        or hashlib.sha256(full[:boot1_bytes]).hexdigest() != boot1_sha256
    ):
        raise ValueError("Boot 1 serial prefix changed before Boot 2")
    suffix = full[boot1_bytes:]
    if not suffix:
        raise EvidenceIncomplete("Boot 2 serial segment is not available yet")
    try:
        return suffix.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Boot 2 serial segment is not valid UTF-8") from None


class PersistenceRun:
    def __init__(self, state, state_path):
        self.state = state
        self.state_path = state_path
        self.contract = state["contract"]
        self.cloud = self.contract["azure"]
        self.directory = state_path.parent
        self.deadline = None
        self.cleanup_deadline = None
        self.tags = {
            "managed-by": MANAGED_BY,
            "purpose": PURPOSE,
            "unikraft-run": self.cloud["name_prefix"],
            "image-sha256": self.contract["files"]["guest_vhd"]["sha256"],
            "seed-sha256": self.contract["files"]["data_raw"]["sha256"],
        }

    def az(self, arguments, *, timeout=300):
        return azure.azure_cli(
            arguments, subscription=self.cloud["subscription"],
            private=True, timeout=timeout,
        )

    def record(self, phase, **fields):
        if phase not in PHASES:
            raise ValueError("Invalid persistence controller phase")
        self.state.update(fields)
        self.state["phase"] = phase
        azure.save_durable_json(self.state_path, self.state)

    def private_failure_values(self):
        values = {
            self.cloud["subscription"], self.cloud["resource_group"],
            self.cloud["name_prefix"], self.contract["run_id"],
            self.contract["disk_id"], str(self.directory),
        }
        for proof_name in ("os_disk", "data_disk", "vm"):
            proof = self.state.get(proof_name)
            if isinstance(proof, dict):
                values.update(
                    value for value in proof.values()
                    if isinstance(value, str)
                )
        return values

    def remaining(self, maximum, *, cleanup=False):
        deadline = self.cleanup_deadline if cleanup else self.deadline
        if deadline is None:
            return maximum
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                "Persistence cleanup deadline expired"
                if cleanup else "Persistence acceptance deadline expired"
            )
        return min(maximum, remaining)

    def ensure_deadline(self, *, cleanup=False):
        deadline = self.cleanup_deadline if cleanup else self.deadline
        if deadline is not None and time.monotonic() >= deadline:
            raise RuntimeError(
                "Persistence cleanup deadline expired"
                if cleanup else "Persistence acceptance deadline expired"
            )

    def whole_seconds_remaining(self, maximum):
        remaining = self.remaining(maximum)
        if remaining < 1:
            raise RuntimeError("Persistence acceptance deadline expired")
        return int(remaining)

    def expected_id(self, provider, resource_type, name):
        group_id = self.state.get("resource_group_id")
        if not isinstance(group_id, str) or not group_id:
            raise RuntimeError("Resource-group identity is unavailable")
        return (
            group_id.rstrip("/") + f"/providers/{provider}/"
            f"{resource_type}/{name}"
        )

    def require_tags(self, resource, description):
        tags = resource.get("tags") if isinstance(resource, dict) else None
        if (
            not isinstance(tags, dict)
            or any(tags.get(key) != value for key, value in self.tags.items())
        ):
            raise RuntimeError(
                f"{description} lacks this run's exact ownership tags"
            )

    def require_operation_tags(self, resource, description):
        operation = self.state.get("vm_operation")
        if not isinstance(operation, dict):
            raise RuntimeError("VM deployment operation is unavailable")
        self.require_tags(resource, description)
        tags = resource.get("tags")
        if tags.get("persistence-operation") != operation["operation_id"]:
            raise RuntimeError(
                f"{description} lacks the original deployment operation"
            )

    def resource_tags(self):
        return [f"{key}={value}" for key, value in self.tags.items()]

    def check_cloud(self):
        subscription = azure.selected_account(self.cloud["subscription"])
        for namespace in ("Microsoft.Compute", "Microsoft.Network"):
            state = self.az([
                "provider", "show", "--namespace", namespace,
                "--query", "registrationState",
            ], timeout=self.remaining(120))
            if state != "Registered":
                raise RuntimeError(
                    "Required Azure providers must already be registered"
                )
        sku = azure.exact_vm_sku(
            self.cloud["location"], self.cloud["vm_size"], subscription,
            self.cloud["vm_vcpus"], require_v2=True,
        )
        details = self.az([
            "vm", "list-skus", "--all",
            "--location", self.cloud["location"],
            "--resource-type", "virtualMachines",
            "--size", self.cloud["vm_size"],
            "--query", f"[?name=='{self.cloud['vm_size']}]",
        ], timeout=self.remaining(120))
        if (
            not isinstance(details, list)
            or len(details) != 1
            or not isinstance(details[0], dict)
        ):
            raise RuntimeError(
                "Requested VM size has ambiguous capability metadata"
            )
        capabilities = {
            entry.get("name"): entry.get("value")
            for entry in details[0].get("capabilities", [])
            if isinstance(entry, dict)
        }
        try:
            max_data_disks = int(capabilities["MaxDataDiskCount"])
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(
                "Requested VM size lacks a bounded data-disk capability"
            ) from None
        if max_data_disks < 1:
            raise RuntimeError("Requested VM size cannot attach one data disk")
        self.ensure_deadline()
        return {"subscription": subscription, "sku": sku}

    def create_group(self):
        if self.az([
            "group", "exists", "--name", self.cloud["resource_group"],
        ], timeout=self.remaining(120)) is not False:
            raise RuntimeError("Refusing to adopt an existing resource group")
        self.record("creating-group")
        group = self.az([
            "group", "create",
            "--name", self.cloud["resource_group"],
            "--location", self.cloud["location"],
            "--tags", *self.resource_tags(),
        ], timeout=self.remaining(300))
        self.ensure_deadline()
        self.require_tags(group, "Created resource group")
        if str(group.get("location", "")).lower() != self.cloud["location"]:
            raise RuntimeError(
                "Azure created the resource group in an unexpected location"
            )
        group_id = group.get("id")
        if not isinstance(group_id, str) or not group_id:
            raise RuntimeError(
                "Azure did not return the created resource-group identity"
            )
        self.record("group-created", resource_group_id=group_id)

    def disk_name(self, role):
        return self.cloud[f"{role}_disk_name"]

    def disk_file(self, role):
        file_role = "guest_vhd" if role == "os" else "data_vhd"
        return self.directory / "inputs" / FILE_NAMES[file_role]

    def disk_logical_bytes(self, role):
        if role == "os":
            return self.contract["files"]["guest_vhd"]["size"] - 512
        return self.contract["geometry"]["sectors"] * SECTOR_SIZE

    def disk_proof(self, role, disk):
        name = self.disk_name(role)
        expected_id = self.expected_id("Microsoft.Compute", "disks", name)
        self.require_tags(disk, f"Created {role} disk")
        if str(disk.get("id", "")).lower() != expected_id.lower():
            raise RuntimeError(f"Created {role} disk ID is unexpected")
        proof = {
            "id": expected_id,
            "uuid": require_uuid(
                disk.get("uniqueId"), f"Created {role} disk UUID"
            ),
        }
        other = self.state.get(
            "data_disk" if role == "os" else "os_disk"
        )
        if isinstance(other, dict) and proof["uuid"] == other.get("uuid"):
            raise RuntimeError("Created disk UUIDs are not distinct")
        return proof

    def verify_disk(self, role, disk, attached_vm_id=None,
                    ready_states=("Unattached",)):
        proof = self.state.get(f"{role}_disk")
        if not isinstance(proof, dict):
            raise RuntimeError(f"{role} disk creation proof is unavailable")
        self.require_tags(disk, f"{role} disk")
        managed_by = disk.get("managedBy")
        common_invalid = (
            str(disk.get("id", "")).lower() != proof["id"].lower()
            or require_uuid(
                disk.get("uniqueId"), f"{role} disk UUID"
            ) != proof["uuid"]
            or (
                attached_vm_id is None
                and managed_by not in (None, "")
            )
            or (
                attached_vm_id is not None
                and str(managed_by or "").lower()
                != attached_vm_id.lower()
            )
            or disk.get("diskSizeBytes") != self.disk_logical_bytes(role)
            or (
                ready_states is not None
                and (
                    disk.get("provisioningState") != "Succeeded"
                    or disk.get("diskState") not in ready_states
                )
            )
        )
        role_invalid = (
            disk.get("osType") != "Linux"
            or disk.get("hyperVGeneration") != "V2"
            if role == "os"
            else disk.get("osType") not in (None, "")
        )
        if common_invalid or role_invalid:
            raise RuntimeError(
                f"{role} disk is detached, replaced, or has wrong geometry"
            )
        return proof

    def verify_uploaded_disks(self):
        for role in ("os", "data"):
            disk = self.az([
                "disk", "show",
                "--resource-group", self.cloud["resource_group"],
                "--name", self.disk_name(role),
            ], timeout=self.remaining(120))
            self.verify_disk(
                role, disk, attached_vm_id=None,
                ready_states=("Unattached",),
            )
        self.ensure_deadline()

    def upload_disk(self, role):
        if role not in ("os", "data"):
            raise ValueError("Unknown persistence disk role")
        name = self.disk_name(role)
        image = self.disk_file(role)
        self.record(f"creating-{role}-disk")
        arguments = [
            "disk", "create",
            "--resource-group", self.cloud["resource_group"],
            "--name", name,
            "--location", self.cloud["location"],
            "--upload-type", "Upload",
            "--upload-size-bytes", str(image.stat().st_size),
            "--sku", self.cloud[f"{role}_disk_sku"],
            "--tags", *self.resource_tags(),
        ]
        if role == "os":
            arguments.extend((
                "--hyper-v-generation", "V2", "--os-type", "Linux",
            ))
        disk = self.az(arguments, timeout=self.remaining(600))
        proof = self.disk_proof(role, disk)
        self.record(f"{role}-disk-created", **{f"{role}_disk": proof})
        self.record(f"uploading-{role}-disk")
        primary = None
        revoke = None
        try:
            grant = self.az([
                "disk", "grant-access",
                "--resource-group", self.cloud["resource_group"],
                "--name", name, "--access-level", "Write",
                "--duration-in-seconds",
                str(self.whole_seconds_remaining(1800)),
            ], timeout=self.remaining(120))
            endpoint, sas = azure.upload_endpoint(
                azure.disk_access_sas(grant)
            )
            azure.upload_managed_vhd(
                image, endpoint, sas,
                timeout=self.remaining(1200),
                expected_sha256=self.contract["files"][
                    "guest_vhd" if role == "os" else "data_vhd"
                ]["sha256"],
            )
        except BaseException as error:
            primary = error
        finally:
            try:
                self.az([
                    "disk", "revoke-access",
                    "--resource-group", self.cloud["resource_group"],
                    "--name", name,
                ], timeout=120)
            except BaseException as error:
                revoke = error
        if primary is not None and revoke is not None:
            raise RuntimeError(
                "Managed-disk upload and SAS revocation both failed: "
                f"{azure.safe_failure_message(primary)}; "
                f"{azure.safe_failure_message(revoke)}"
            )
        if primary is not None:
            raise primary
        if revoke is not None:
            raise revoke
        self.ensure_deadline()
        disk = self.az([
            "disk", "show",
            "--resource-group", self.cloud["resource_group"],
            "--name", name,
        ], timeout=self.remaining(120))
        self.verify_disk(role, disk)
        self.ensure_deadline()
        self.record(f"{role}-disk-ready")

    @contextmanager
    def deployment_parameters(self):
        path = self.directory / ".persistence-deployment.json"
        values = {
            "namePrefix": self.cloud["name_prefix"],
            "location": self.cloud["location"],
            "vmSize": self.cloud["vm_size"],
            "osDiskId": self.state["os_disk"]["id"],
            "dataDiskId": self.state["data_disk"]["id"],
            "dataLun": self.contract["geometry"]["lun"],
            "imageSha256": self.contract["files"]["guest_vhd"]["sha256"],
            "seedSha256": self.contract["files"]["data_raw"]["sha256"],
            "operationId": self.state["vm_operation"]["operation_id"],
        }
        azure.save_json(path, {
            "$schema": (
                "https://schema.management.azure.com/schemas/"
                "2019-04-01/deploymentParameters.json#"
            ),
            "contentVersion": "1.0.0.0",
            "parameters": {
                name: {"value": value} for name, value in values.items()
            },
        })
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)

    @staticmethod
    def deployment_output(properties, name):
        outputs = properties.get("outputs")
        output = outputs.get(name) if isinstance(outputs, dict) else None
        if (
            not isinstance(output, dict)
            or str(output.get("type", "")).lower() != "string"
            or not isinstance(output.get("value"), str)
        ):
            raise RuntimeError("VM deployment output is unavailable")
        return output["value"]

    def vm_proof(self, deployment):
        if not isinstance(deployment, dict):
            raise RuntimeError("VM deployment result is invalid")
        properties = deployment.get("properties")
        if not isinstance(properties, dict):
            raise RuntimeError("VM deployment properties are unavailable")
        expected_deployment = self.expected_id(
            "Microsoft.Resources", "deployments",
            self.cloud["name_prefix"],
        )
        expected_vm = self.expected_id(
            "Microsoft.Compute", "virtualMachines",
            self.cloud["vm_name"],
        )
        expected_nic = self.expected_id(
            "Microsoft.Network", "networkInterfaces",
            self.cloud["nic_name"],
        )
        expected_resources = {
            expected_vm.lower(),
            expected_nic.lower(),
            self.expected_id(
                "Microsoft.Network", "virtualNetworks",
                self.cloud["vnet_name"],
            ).lower(),
            self.expected_id(
                "Microsoft.Network", "networkSecurityGroups",
                self.cloud["nsg_name"],
            ).lower(),
        }
        resources = properties.get("outputResources", [])
        actual_resources = {
            str(resource.get("id", "")).lower()
            for resource in resources if isinstance(resource, dict)
        }
        parameters = properties.get("parameters")
        expected_parameters = {
            "namePrefix": self.cloud["name_prefix"],
            "location": self.cloud["location"],
            "vmSize": self.cloud["vm_size"],
            "osDiskId": self.state["os_disk"]["id"],
            "dataDiskId": self.state["data_disk"]["id"],
            "dataLun": self.contract["geometry"]["lun"],
            "imageSha256": self.contract["files"]["guest_vhd"]["sha256"],
            "seedSha256": self.contract["files"]["data_raw"]["sha256"],
            "operationId": self.state["vm_operation"]["operation_id"],
        }
        if (
            deployment.get("name") != self.cloud["name_prefix"]
            or str(deployment.get("id", "")).lower()
            != expected_deployment.lower()
            or properties.get("provisioningState") != "Succeeded"
            or not isinstance(parameters, dict)
            or any(
                not isinstance(parameters.get(name), dict)
                or parameters[name].get("value") != value
                for name, value in expected_parameters.items()
            )
            or len(resources) != len(expected_resources)
            or actual_resources != expected_resources
            or self.deployment_output(properties, "vmId").lower()
            != expected_vm.lower()
            or self.deployment_output(properties, "nicId").lower()
            != expected_nic.lower()
            or self.deployment_output(properties, "osDiskId").lower()
            != self.state["os_disk"]["id"].lower()
            or self.deployment_output(properties, "dataDiskId").lower()
            != self.state["data_disk"]["id"].lower()
        ):
            raise RuntimeError("VM deployment provenance is invalid")
        proof = {
            "id": expected_vm,
            "uuid": require_uuid(
                self.deployment_output(properties, "vmUuid"), "VM UUID"
            ),
            "deployment_id": expected_deployment,
            "correlation_id": require_uuid(
                properties.get("correlationId"),
                "VM deployment correlation UUID",
            ),
            "nic_id": expected_nic,
            "os_disk_id": self.state["os_disk"]["id"],
            "data_disk_id": self.state["data_disk"]["id"],
        }
        if proof["uuid"] in {
            self.state["os_disk"]["uuid"],
            self.state["data_disk"]["uuid"],
        }:
            raise RuntimeError("VM and disk UUID proofs are not distinct")
        return proof

    def deploy_vm(self):
        if self.state["boot_count"] != 0:
            raise RuntimeError("VM deployment would exceed the boot contract")
        deployment_id = self.expected_id(
            "Microsoft.Resources", "deployments",
            self.cloud["name_prefix"],
        )
        operation = {
            "phase": "pending",
            "operation_id": str(uuid.uuid4()),
            "deployment_id": deployment_id,
        }
        self.record(
            "deploying-vm", boot_count=1, vm_operation=operation
        )
        self.verify_uploaded_disks()
        with self.deployment_parameters() as parameters:
            deployment = self.az([
                "deployment", "group", "create",
                "--resource-group", self.cloud["resource_group"],
                "--name", self.cloud["name_prefix"],
                "--mode", "Incremental",
                "--template-file", str(TEMPLATE),
                "--parameters", "@" + str(parameters),
            ], timeout=self.remaining(600))
        proof = self.vm_proof(deployment)
        self.record(
            "deploying-vm", vm=proof,
            vm_operation={**operation, "phase": "created"},
        )
        self.ensure_deadline()
        self.record("vm-created")
        self.verify_topology()

    def verify_deployment(self, *, cleanup=False):
        proof = self.state.get("vm")
        if not isinstance(proof, dict):
            raise RuntimeError("VM deployment proof is unavailable")
        deployment = self.az([
            "deployment", "group", "show",
            "--resource-group", self.cloud["resource_group"],
            "--name", self.cloud["name_prefix"],
        ], timeout=self.remaining(120, cleanup=cleanup))
        if self.vm_proof(deployment) != proof:
            raise RuntimeError("Original VM deployment proof changed")
        return proof

    def verify_vm_identity(self, *, cleanup=False):
        proof = self.state.get("vm")
        if not isinstance(proof, dict):
            raise RuntimeError("VM creation proof is unavailable")
        timeout = self.remaining(120, cleanup=cleanup)
        vm = self.az([
            "vm", "show", "--resource-group", self.cloud["resource_group"],
            "--name", self.cloud["vm_name"],
        ], timeout=timeout)
        self.require_operation_tags(vm, "Persistence VM")
        if (
            str(vm.get("id", "")).lower() != proof["id"].lower()
            or require_uuid(vm.get("vmId"), "VM UUID") != proof["uuid"]
            or vm.get("hardwareProfile", {}).get("vmSize")
            != self.cloud["vm_size"]
        ):
            raise RuntimeError("Persistence VM identity was replaced")
        return vm

    def verify_vm(self, *, cleanup=False):
        vm = self.verify_vm_identity(cleanup=cleanup)
        self.verify_vm_attachments(vm)
        return self.state["vm"]

    def verify_vm_attachments(self, vm):
        proof = self.state["vm"]
        os_id = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        data = vm.get("storageProfile", {}).get("dataDisks")
        interfaces = vm.get("networkProfile", {}).get("networkInterfaces")
        if (
            str(os_id or "").lower() != proof["os_disk_id"].lower()
            or not isinstance(data, list)
            or len(data) != 1
            or data[0].get("lun") != self.contract["geometry"]["lun"]
            or str(
                data[0].get("managedDisk", {}).get("id", "")
            ).lower() != proof["data_disk_id"].lower()
            or not isinstance(interfaces, list)
            or len(interfaces) != 1
            or str(interfaces[0].get("id", "")).lower()
            != proof["nic_id"].lower()
        ):
            raise RuntimeError("VM or reciprocal disk attachment was replaced")
        return proof

    def verify_topology(self, *, cleanup=False,
                        disk_states=("Attached",)):
        self.verify_deployment(cleanup=cleanup)
        proof = self.verify_vm(cleanup=cleanup)
        for role in ("os", "data"):
            disk = self.az([
                "disk", "show",
                "--resource-group", self.cloud["resource_group"],
                "--name", self.disk_name(role),
            ], timeout=self.remaining(120, cleanup=cleanup))
            self.verify_disk(
                role, disk, attached_vm_id=proof["id"],
                ready_states=disk_states,
            )
        return proof

    def serial_log(self):
        text = self.az([
            "vm", "boot-diagnostics", "get-boot-log",
            "--resource-group", self.cloud["resource_group"],
            "--name", self.cloud["vm_name"],
        ], timeout=self.remaining(120))
        if not isinstance(text, str):
            raise RuntimeError("Azure did not return serial text")
        if len(text.encode("utf-8")) > MAX_SERIAL_BYTES:
            raise RuntimeError("Azure serial evidence exceeded 4 MiB")
        return text

    def wait_for_boot(self, boot):
        self.record(f"waiting-boot{boot}")
        while True:
            if time.monotonic() >= self.deadline:
                raise RuntimeError(f"Timed out waiting for Boot {boot}")
            try:
                text = self.serial_log()
            except azure.AzureCliError as error:
                if error.code not in (
                    "BlobNotFound", "BootDiagnosticsInformationNotAvailable",
                ):
                    raise
            else:
                try:
                    if boot == 1:
                        segment = text
                        evidence = parse_boot_segment(
                            segment, 1, self.contract
                        )
                    else:
                        segment = boot2_suffix(
                            text, self.state["boot1_serial_bytes"],
                            self.state["boot1_serial_sha256"],
                        )
                        evidence = parse_boot_segment(
                            segment, 2, self.contract,
                            self.state["enrolled_identity"],
                        )
                except EvidenceIncomplete:
                    pass
                else:
                    self.ensure_deadline()
                    if not text.endswith("\n"):
                        raise EvidenceIncomplete(
                            "Accepted serial boundary lacks a final newline"
                        )
                    log_path = self.directory / f"boot{boot}-serial.log"
                    azure.save_private_text(log_path, segment)
                    azure.fsync_directory(self.directory)
                    return text, evidence
            time.sleep(min(5, max(0, self.deadline - time.monotonic())))

    def deallocate(self, boot, *, cleanup=False):
        phase = f"deallocating-boot{boot}"
        if not cleanup:
            self.record(phase)
            self.verify_topology()
        self.az([
            "vm", "deallocate",
            "--resource-group", self.cloud["resource_group"],
            "--name", self.cloud["vm_name"],
        ], timeout=self.remaining(300, cleanup=cleanup))
        self.ensure_deadline(cleanup=cleanup)
        if not cleanup:
            self.record(f"boot{boot}-deallocated")

    def start_boot2(self):
        if self.state["boot_count"] != 1:
            raise RuntimeError("Boot 2 start would violate the exact boot count")
        self.verify_topology(disk_states=("Reserved", "Attached"))
        self.record("boot2-start-requested", boot_count=2)
        self.az([
            "vm", "start",
            "--resource-group", self.cloud["resource_group"],
            "--name", self.cloud["vm_name"],
        ], timeout=self.remaining(300))
        self.ensure_deadline()

    def expected_resource_ids(self):
        return {
            self.expected_id(
                "Microsoft.Compute", "virtualMachines",
                self.cloud["vm_name"],
            ).lower(),
            self.expected_id(
                "Microsoft.Compute", "disks",
                self.cloud["os_disk_name"],
            ).lower(),
            self.expected_id(
                "Microsoft.Compute", "disks",
                self.cloud["data_disk_name"],
            ).lower(),
            self.expected_id(
                "Microsoft.Network", "networkInterfaces",
                self.cloud["nic_name"],
            ).lower(),
            self.expected_id(
                "Microsoft.Network", "virtualNetworks",
                self.cloud["vnet_name"],
            ).lower(),
            self.expected_id(
                "Microsoft.Network", "networkSecurityGroups",
                self.cloud["nsg_name"],
            ).lower(),
        }

    def cleanup(self):
        self.cleanup_deadline = (
            time.monotonic() + self.cloud["cleanup_seconds"]
        )
        failures = []
        try:
            exists = self.az([
                "group", "exists",
                "--name", self.cloud["resource_group"],
            ], timeout=self.remaining(120, cleanup=True))
        except BaseException as error:
            raise PersistenceCleanupError([
                ("resource-group lookup", error)
            ]) from None
        if exists is False:
            self.ensure_deadline(cleanup=True)
            self.record("cleaned", cleanup_required=False)
            return
        group_verified = False
        group_has_creation_proof = isinstance(
            self.state.get("resource_group_id"), str
        )
        try:
            group = self.az([
                "group", "show",
                "--name", self.cloud["resource_group"],
            ], timeout=self.remaining(120, cleanup=True))
            self.require_tags(group, "Persistence resource group")
            if (
                str(group.get("location", "")).lower()
                != self.cloud["location"]
                or (
                    group_has_creation_proof
                    and str(group.get("id", "")).lower()
                    != self.state["resource_group_id"].lower()
                )
                or (
                    not group_has_creation_proof
                    and (
                        self.state["phase"] != "creating-group"
                        or self.state["boot_count"] != 0
                        or any(
                            key in self.state
                            for key in ("os_disk", "data_disk", "vm")
                        )
                    )
                )
            ):
                raise RuntimeError("Resource-group identity changed")
            group_verified = True
        except BaseException as error:
            failures.append(("resource-group identity", error))

        resources = None
        try:
            resources = self.az([
                "resource", "list",
                "--resource-group", self.cloud["resource_group"],
            ], timeout=self.remaining(120, cleanup=True))
            if not isinstance(resources, list):
                raise RuntimeError("Azure resource inventory is invalid")
        except BaseException as error:
            failures.append(("resource inventory", error))

        vm_identity_verified = False
        if isinstance(self.state.get("vm"), dict):
            try:
                self.verify_deployment(cleanup=True)
            except BaseException as error:
                failures.append(("VM deployment provenance", error))
            try:
                vm = self.verify_vm_identity(cleanup=True)
                vm_identity_verified = True
            except BaseException as error:
                failures.append(("VM identity", error))
            if vm_identity_verified:
                try:
                    self.verify_vm_attachments(vm)
                except BaseException as error:
                    failures.append(("VM attachments", error))
            for role in ("os", "data"):
                try:
                    disk = self.az([
                        "disk", "show",
                        "--resource-group", self.cloud["resource_group"],
                        "--name", self.disk_name(role),
                    ], timeout=self.remaining(120, cleanup=True))
                    self.verify_disk(
                        role, disk,
                        attached_vm_id=self.state["vm"]["id"],
                        ready_states=None,
                    )
                except BaseException as error:
                    failures.append((f"{role} disk identity", error))
            if vm_identity_verified:
                try:
                    self.deallocate(
                        min(max(self.state["boot_count"], 1), 2),
                        cleanup=True,
                    )
                except BaseException as error:
                    failures.append(("VM deallocation", error))
        else:
            for role in ("os", "data"):
                if not isinstance(self.state.get(f"{role}_disk"), dict):
                    continue
                try:
                    disk = self.az([
                        "disk", "show",
                        "--resource-group", self.cloud["resource_group"],
                        "--name", self.disk_name(role),
                    ], timeout=self.remaining(120, cleanup=True))
                    self.verify_disk(
                        role, disk, ready_states=None
                    )
                except BaseException as error:
                    failures.append((f"{role} disk identity", error))

        if resources is not None:
            actual_ids = set()
            operation_resource_ids = set()
            if group_has_creation_proof:
                operation_resource_ids = self.expected_resource_ids() - {
                    self.expected_id(
                        "Microsoft.Compute", "disks",
                        self.cloud["os_disk_name"],
                    ).lower(),
                    self.expected_id(
                        "Microsoft.Compute", "disks",
                        self.cloud["data_disk_name"],
                    ).lower(),
                }
            for resource in resources:
                try:
                    if not isinstance(resource, dict):
                        raise RuntimeError("Resource inventory entry is invalid")
                    self.require_tags(resource, "Persistence resource")
                    identifier = str(resource.get("id", "")).lower()
                    if not identifier:
                        raise RuntimeError("Resource identity is unavailable")
                    if identifier in operation_resource_ids:
                        self.require_operation_tags(
                            resource, "Persistence deployment resource"
                        )
                    actual_ids.add(identifier)
                except BaseException as error:
                    failures.append(("resource ownership", error))
            try:
                if not group_verified:
                    raise RuntimeError(
                        "Resource group is not proven for cleanup"
                    )
                expected = (
                    self.expected_resource_ids()
                    if group_has_creation_proof else set()
                )
                if not actual_ids <= expected:
                    raise RuntimeError(
                        "Resource inventory has extra or foreign entries"
                    )
                vm_id = (
                    self.expected_id(
                        "Microsoft.Compute", "virtualMachines",
                        self.cloud["vm_name"],
                    ).lower()
                    if group_has_creation_proof else None
                )
                if vm_id in actual_ids and not isinstance(
                    self.state.get("vm"), dict
                ):
                    raise RuntimeError(
                        "Resource inventory has an unproven VM"
                    )
                for role in ("os", "data"):
                    disk_id = (
                        self.expected_id(
                            "Microsoft.Compute", "disks",
                            self.disk_name(role),
                        ).lower()
                        if group_has_creation_proof else None
                    )
                    if disk_id in actual_ids and not isinstance(
                        self.state.get(f"{role}_disk"), dict
                    ):
                        raise RuntimeError(
                            f"Resource inventory has an unproven {role} disk"
                        )
            except BaseException as error:
                failures.append(("resource envelope", error))

        if failures:
            cleanup_error = PersistenceCleanupError(failures)
            try:
                self.record(
                    "cleanup-failed", cleanup_required=True,
                    cleanup_failures=[name for name, _ in failures],
                )
            except BaseException as recording:
                raise PersistenceCleanupError(
                    failures, recording
                ) from None
            raise cleanup_error
        try:
            self.record("deleting-group")
            self.az([
                "group", "delete",
                "--name", self.cloud["resource_group"], "--yes",
            ], timeout=self.remaining(
                self.cloud["cleanup_seconds"], cleanup=True
            ))
            if self.az([
                "group", "exists",
                "--name", self.cloud["resource_group"],
            ], timeout=self.remaining(120, cleanup=True)) is not False:
                raise RuntimeError("Resource-group deletion did not complete")
            self.ensure_deadline(cleanup=True)
        except BaseException as error:
            failures = [("resource-group deletion", error)]
            try:
                self.record(
                    "cleanup-failed", cleanup_required=True,
                    cleanup_failures=["resource-group deletion"],
                )
            except BaseException as recording:
                raise PersistenceCleanupError(
                    failures, recording
                ) from None
            raise PersistenceCleanupError(failures) from None
        self.record("cleaned", cleanup_required=False)


def resource_envelope_sha256(contract):
    return hashlib.sha256(
        azure.canonical_json(contract["azure"])
    ).hexdigest()


def save_acceptance_receipt(run, boot1, boot2, cleanup):
    state = run.state
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "schema_version": RECEIPT_VERSION,
        "result": "PASS",
        "workload": WORKLOAD,
        "contract_sha256": state["contract_sha256"],
        "implementation": state["contract"]["implementation"],
        "preflight": state["contract"]["preflight"],
        "run_id": state["contract"]["run_id"],
        "disk_id": state["contract"]["disk_id"],
        "geometry": state["contract"]["geometry"],
        "resources": {
            "subscription": state["contract"]["azure"]["subscription"],
            "location": state["contract"]["azure"]["location"],
            "vm_size": state["contract"]["azure"]["vm_size"],
            "vm": state["vm"],
            "os_disk": state["os_disk"],
            "data_disk": state["data_disk"],
        },
        "identity": state["enrolled_identity"],
        "boots": {
            "boot1": boot1,
            "boot2": boot2,
            "count": 2,
            "same_vm_uuid": state["vm"]["uuid"],
            "same_os_disk_uuid": state["os_disk"]["uuid"],
            "same_data_disk_uuid": state["data_disk"]["uuid"],
        },
        "cleanup": cleanup,
    }
    path = run.directory / "persistence-receipt.json"
    azure.save_durable_json(path, receipt)
    return receipt, path


def finalize_cleaned_acceptance(run):
    state = run.state
    receipt_sha256 = state.get("acceptance_receipt_sha256")
    if receipt_sha256 is None:
        return None
    require_hex(
        receipt_sha256, HEX64, "Pending acceptance receipt SHA-256"
    )
    pending_path = run.directory / "persistence-receipt.json"
    if (
        not pending_path.is_file()
        or pending_path.is_symlink()
        or azure.image_sha256(pending_path) != receipt_sha256
    ):
        raise ValueError("Pending acceptance receipt changed before cleanup")
    pending, _ = read_json(
        pending_path, "Pending persistence acceptance receipt",
        canonical=False,
    )
    if (
        not isinstance(pending, dict)
        or pending.get("schema") != RECEIPT_SCHEMA
        or pending.get("schema_version") != RECEIPT_VERSION
        or pending.get("result") != "PASS"
        or pending.get("contract_sha256") != state["contract_sha256"]
    ):
        raise ValueError("Pending acceptance receipt is incompatible")
    if pending.get("cleanup") == "complete":
        return pending
    if pending.get("cleanup") != "pending":
        raise ValueError("Pending acceptance receipt is incompatible")
    receipt, path = save_acceptance_receipt(
        run,
        validate_boot_evidence(
            state.get("boot1"), 1, state["contract"],
            state.get("enrolled_identity"),
        ),
        validate_boot_evidence(
            state.get("boot2"), 2, state["contract"],
            state.get("enrolled_identity"),
        ),
        "complete",
    )
    run.record(
        "cleaned", cleanup_required=False,
        acceptance_receipt_sha256=azure.image_sha256(path),
    )
    return receipt


def combined_recording_error(errors, private_values):
    present = [error for error in errors if error is not None]
    if not present:
        return None
    return RuntimeError(
        "; ".join(
            azure.safe_failure_message(error, private_values)
            for error in present
        )
    )


def cleanup_recording_failure(error, private_values):
    recording = getattr(error, "recording_error", None)
    if recording is None:
        return error
    return RuntimeError(
        azure.safe_failure_message(error, private_values)
        + "; durable cleanup-failure recording also failed: "
        + azure.safe_failure_message(recording, private_values)
    )


def run_acceptance(state_directory, subscription, approve_cloud_run,
                   approved_envelope_sha256):
    with PersistenceStateLock(state_directory):
        return _run_acceptance_locked(
            state_directory, subscription, approve_cloud_run,
            approved_envelope_sha256,
        )


def _run_acceptance_locked(state_directory, subscription, approve_cloud_run,
                           approved_envelope_sha256):
    state, state_path = load_state(state_directory)
    if state["phase"] != "prepared" or state["cleanup_required"]:
        raise ValueError(
            "Persistence run requires fresh prepared state; "
            "interrupted cloud state may only be cleaned"
        )
    verify_immutable_inputs(state, state_path.parent)
    if approve_cloud_run is not True:
        raise ValueError("Explicit two-boot Azure approval is required")
    if (
        azure.validate_subscription_id(subscription)
        != state["contract"]["azure"]["subscription"]
    ):
        raise ValueError("Explicit subscription differs from the contract")
    expected_envelope = resource_envelope_sha256(state["contract"])
    if (
        require_hex(
            approved_envelope_sha256, HEX64,
            "Approved resource-envelope SHA-256",
        )
        != expected_envelope
    ):
        raise ValueError("Explicit resource-envelope approval does not match")
    azure.check_upload_dependencies()
    run = PersistenceRun(state, state_path)
    run.deadline = (
        time.monotonic() + state["contract"]["azure"]["runtime_seconds"]
    )
    deadline_utc = (
        datetime.now(timezone.utc)
        + timedelta(seconds=state["contract"]["azure"]["runtime_seconds"])
    ).isoformat()
    run.record(
        "cloud-authorized", cleanup_required=True,
        approved_resource_envelope_sha256=expected_envelope,
        deadline_utc=deadline_utc,
    )
    receipt = None
    receipt_path = None
    primary = None
    cleanup_error = None
    try:
        with azure.interrupt_as_exception():
            cloud_proof = run.check_cloud()
            run.record("cloud-authorized", cloud_preflight=cloud_proof)
            run.create_group()
            run.upload_disk("os")
            run.upload_disk("data")
            verify_immutable_inputs(state, state_path.parent)
            run.deploy_vm()
            accumulated_boot1, boot1 = run.wait_for_boot(1)
            boot1_bytes = accumulated_boot1.encode("utf-8")
            run.record(
                "boot1-accepted",
                enrolled_identity=boot1["identity"],
                boot1=boot1,
                boot1_serial_bytes=len(boot1_bytes),
                boot1_serial_sha256=hashlib.sha256(
                    boot1_bytes
                ).hexdigest(),
            )
            run.deallocate(1)
            run.start_boot2()
            _accumulated_boot2, boot2 = run.wait_for_boot(2)
            run.record("boot2-accepted", boot2=boot2)
            run.deallocate(2)
            run.ensure_deadline()
            receipt, receipt_path = save_acceptance_receipt(
                run, boot1, boot2, "pending"
            )
            run.ensure_deadline()
            run.record(
                "acceptance-recorded",
                acceptance_receipt_sha256=azure.image_sha256(receipt_path),
            )
            run.ensure_deadline()
    except BaseException as error:
        primary = error
    if run.state.get("cleanup_required"):
        try:
            run.cleanup()
        except BaseException as error:
            cleanup_error = error
    if primary is not None:
        failure = {
            "category": type(primary).__name__,
            "message": azure.safe_failure_message(
                primary, run.private_failure_values()
            ),
            "cleanup": (
                "complete" if cleanup_error is None else
                azure.safe_failure_message(
                    cleanup_error, run.private_failure_values()
                )
            ),
        }
        recording_error = None
        try:
            run.record(
                "failed", cleanup_required=cleanup_error is not None,
                failure=failure,
            )
        except BaseException as error:
            recording_error = error
        if cleanup_error is not None:
            recording_error = combined_recording_error(
                (
                    getattr(
                        cleanup_error, "recording_error", None
                    ),
                    recording_error,
                ),
                run.private_failure_values(),
            )
            raise azure.RunCleanupError(
                primary, cleanup_error, recording_error,
                private_values=run.private_failure_values(),
            ) from None
        if recording_error is not None:
            private_values = run.private_failure_values()
            raise RuntimeError(
                "Primary run failure: "
                + azure.safe_failure_message(primary, private_values)
                + "; durable failure recording also failed: "
                + azure.safe_failure_message(
                    recording_error, private_values
                )
            ) from None
        raise primary
    if cleanup_error is not None:
        raise cleanup_recording_failure(
            cleanup_error, run.private_failure_values()
        )
    finalize_cleaned_acceptance(run)
    return receipt_path


def cleanup_state(state_directory, subscription):
    with PersistenceStateLock(state_directory):
        return _cleanup_state_locked(state_directory, subscription)


def _cleanup_state_locked(state_directory, subscription):
    state, state_path = load_state(state_directory)
    if (
        azure.validate_subscription_id(subscription)
        != state["contract"]["azure"]["subscription"]
    ):
        raise ValueError("Cleanup subscription differs from the contract")
    if not state.get("cleanup_required"):
        if state["phase"] == "prepared":
            state["phase"] = "cleaned"
            azure.save_durable_json(state_path, state)
        elif (
            state["phase"] == "cleaned"
            and "acceptance_receipt_sha256" in state
        ):
            finalize_cleaned_acceptance(
                PersistenceRun(state, state_path)
            )
        return
    run = PersistenceRun(state, state_path)
    try:
        run.cleanup()
    except PersistenceCleanupError as error:
        raise cleanup_recording_failure(
            error, run.private_failure_values()
        ) from None
    finalize_cleaned_acceptance(run)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Default-off exact two-boot Azure StorVSC persistence controller"
        )
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("create-contract")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--disk-id", required=True)
    create.add_argument("--sectors", type=int, required=True)
    create.add_argument("--lun", type=int, required=True)
    create.add_argument("--subscription", required=True)
    create.add_argument("--location", required=True)
    create.add_argument(
        "--vm-size", choices=sorted(PERSISTENCE_VM_SIZES), required=True
    )
    create.add_argument("--vm-vcpus", type=int, required=True)
    create.add_argument("--name-prefix", required=True)
    create.add_argument(
        "--os-disk-sku",
        choices=("Standard_LRS", "StandardSSD_LRS"), required=True,
    )
    create.add_argument(
        "--data-disk-sku",
        choices=("Standard_LRS", "StandardSSD_LRS"), required=True,
    )
    create.add_argument("--runtime-seconds", type=int, required=True)
    create.add_argument("--cleanup-seconds", type=int, required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--contract", type=Path, required=True)
    prepare.add_argument("--expected-contract-sha256", required=True)
    prepare.add_argument("--state-dir", type=Path, required=True)
    input_options = (
        ("guest_vhd", "--guest-vhd"),
        ("data_raw", "--data-raw"),
        ("data_vhd", "--data-vhd"),
        ("seed_manifest", "--seed-manifest"),
    )
    for role, option in input_options:
        create.add_argument(option, dest=role, type=Path, required=True)
        prepare.add_argument(option, dest=role, type=Path, required=True)
    create.add_argument(
        "--preflight-state-dir", type=Path, required=True
    )
    prepare.add_argument(
        "--preflight-state-dir", type=Path, required=True
    )
    run = subparsers.add_parser("run")
    run.add_argument("--state-dir", type=Path, required=True)
    run.add_argument("--subscription", required=True)
    run.add_argument("--approve-cloud-run", action="store_true")
    run.add_argument(
        "--approved-resource-envelope-sha256", required=True
    )
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--state-dir", type=Path, required=True)
    cleanup.add_argument("--subscription", required=True)
    args = parser.parse_args()
    try:
        if args.action == "create-contract":
            digest = create_contract(
                args.output,
                run_id=args.run_id,
                disk_id=args.disk_id,
                sectors=args.sectors,
                lun=args.lun,
                subscription=args.subscription,
                location=args.location,
                vm_size=args.vm_size,
                vm_vcpus=args.vm_vcpus,
                name_prefix=args.name_prefix,
                os_disk_sku=args.os_disk_sku,
                data_disk_sku=args.data_disk_sku,
                runtime_seconds=args.runtime_seconds,
                cleanup_seconds=args.cleanup_seconds,
                inputs={
                    role: getattr(args, role) for role, _ in input_options
                },
                preflight_state_directory=args.preflight_state_dir,
            )
            print("Two-boot persistence contract SHA-256: " + digest)
            contract, _ = read_json(
                args.output, "Generated two-boot persistence contract"
            )
            print(
                "Azure resource envelope SHA-256: "
                + resource_envelope_sha256(contract)
            )
        elif args.action == "prepare":
            prepared = prepare_state(
                args.contract, args.expected_contract_sha256,
                args.state_dir,
                {
                    role: getattr(args, role)
                    for role in PERSISTENCE_INPUT_ROLES
                },
                args.preflight_state_dir,
            )
            print(f"Prepared exact two-boot state: {prepared}")
        elif args.action == "run":
            receipt = run_acceptance(
                args.state_dir, args.subscription,
                args.approve_cloud_run,
                args.approved_resource_envelope_sha256,
            )
            print(f"Exact two-boot persistence receipt: {receipt}")
        else:
            cleanup_state(args.state_dir, args.subscription)
            print("Persistence cleanup complete")
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(azure.safe_failure_message(error)) from None


if __name__ == "__main__":
    main()
