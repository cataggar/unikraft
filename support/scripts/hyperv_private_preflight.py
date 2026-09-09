#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded private nested-KVM Hyper-V platform preflight controller."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from importlib.metadata import distribution as package_distribution
from importlib.metadata import PackageNotFoundError
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

import hyperv_private_preflight_runner as host_runner


azure = importlib.import_module("hyperv-azure")

SUPPORT = Path(__file__).resolve().parents[1]
RUNNER_PATH = Path(__file__).with_name("hyperv_private_preflight_runner.py")
BLOB_WORKER_PATH = Path(__file__).with_name(
    "hyperv_private_preflight_blob.py"
)
TEMPLATE_PATH = SUPPORT / "azure" / "hyperv-private-preflight.json"
REQUIREMENTS_PATH = SUPPORT / "azure" / "requirements.txt"
SHARED_CONTROLLER_PATH = Path(__file__).with_name("hyperv-azure.py")
NETWORK_CONTROLLER_PATH = Path(__file__).with_name(
    "hyperv_network_controller.py"
)
INPUT_SCHEMA = "unikraft.hyperv.private-preflight-input"
STATE_SCHEMA = "unikraft.hyperv.private-preflight-state"
RECEIPT_SCHEMA = "unikraft.hyperv.private-preflight-receipt"
INPUT_SCHEMA_VERSION = 5
STATE_SCHEMA_VERSION = 2
RECEIPT_SCHEMA_VERSION = 2
HOST_PHASE_SCHEMA = host_runner.SCHEMA
HOST_EVIDENCE_SCHEMA = host_runner.EVIDENCE_SCHEMA
INPUT_MANIFEST = "private-preflight-input.json"
SOLVED_CONFIG = "solved.config"
CAPABILITY_REFERENCE = "capability.source.json"
PRIVATE_BUILD_RECEIPT = "private-build-receipt.json"
NATIVE_EFI_NAME = "helloworld_hyperv-x86_64-efi-netvsc"
CAPABILITY_REFERENCE_SCHEMA = "unikraft.hyperv.capability-reference"
PRIVATE_BUILD_SCHEMA = "unikraft.hyperv.private-local-build"
STATE_FILE = "state.json"
LOCATION = "northeurope"
VM_SIZE = "Standard_D2s_v5"
CONTAINER = "preflight"
WORKLOAD = "platform-only-v1"
SDK_VERSION = "12.28.0"
SDK_DISTRIBUTIONS = (
    ("azure-core", "1.41.0"),
    ("azure-storage-blob", SDK_VERSION),
    ("certifi", "2026.7.22"),
    ("cffi", "2.1.1"),
    ("charset-normalizer", "3.5.1"),
    ("cryptography", "50.0.1"),
    ("idna", "3.19"),
    ("isodate", "0.7.2"),
    ("pycparser", "3.0"),
    ("requests", "2.34.2"),
    ("typing-extensions", "4.16.0"),
    ("urllib3", "2.7.0"),
)
MAX_ATTEMPT_SECONDS = 60 * 60
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_CONTROL_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_STATE_BYTES = 192 * 1024
MAX_BLOB_SAS_BYTES = 4096
TRANSFER_TIMEOUT_SECONDS = 300
RECONCILE_TIMEOUT_SECONDS = 120
CLEANUP_TIMEOUT_SECONDS = 20 * 60
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[0-9a-f]{32}")
STORAGE_NAME = re.compile(r"[a-z0-9]{3,24}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40,64}")
SAFE_RELATIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")
INPUT_NAMES = {
    "qemu": "qemu/bin/qemu-system-x86_64",
    "ovmf_code": "OVMF_CODE.fd",
    "ovmf_vars": "OVMF_VARS.fd",
    "capability_raw": "capability.raw",
    "efi": "private.efi",
    "raw": "private.raw",
    "vhd": "private.vhd",
}
PUBLIC_ROLES = ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
PRIVATE_ROLES = ("raw", "vhd")
REMOTE_ROLES = PUBLIC_ROLES + PRIVATE_ROLES
LOCAL_ROLES = ("efi",)
ALL_ROLES = REMOTE_ROLES + LOCAL_ROLES
BOOT_POLICIES = ("platform-unavailable-v1", "platform-main-zero-v1")
BUILD_TOOL_NAMES = (
    "zig", "make", "python", "bison", "flex", "m4",
    "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf",
    "llvm-strip", "bison-data",
)
PURPOSE = "private-hyperv-platform-preflight"
IMPLEMENTATION_PATHS = {
    "controller": Path(__file__),
    "runner": RUNNER_PATH,
    "blob_worker": BLOB_WORKER_PATH,
    "shared_controller": SHARED_CONTROLLER_PATH,
    "network_controller": NETWORK_CONTROLLER_PATH,
    "template": TEMPLATE_PATH,
    "requirements": REQUIREMENTS_PATH,
}


def require_sha256(value, description):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{description} must be a lowercase SHA-256 digest")
    return value


def require_uuid(value, description):
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ValueError(f"{description} is invalid") from None
    if str(parsed) != value:
        raise ValueError(f"{description} is invalid")
    return value


def exact_fields(value, fields, description):
    return azure.require_exact_fields(value, fields, description)


def require_relative(value, description):
    if (
        not isinstance(value, str)
        or not SAFE_RELATIVE.fullmatch(value)
        or value.startswith("/")
        or ".." in Path(value).parts
    ):
        raise ValueError(f"{description} is invalid")
    return value


def file_record(value, role):
    value = exact_fields(
        value, ("name", "sha256", "size"), f"{role} input fingerprint"
    )
    if (
        value["name"] != INPUT_NAMES[role]
        or type(value["size"]) is not int
        or value["size"] <= 0
        or value["size"] > host_runner.MAX_FILE_BYTES
    ):
        raise ValueError(f"{role} input name or size is invalid")
    require_sha256(value["sha256"], f"{role} input fingerprint")
    return dict(value)


def support_record(value):
    value = exact_fields(
        value, ("path", "sha256", "size"), "QEMU support file"
    )
    path = require_relative(value["path"], "QEMU support path")
    if (
        not path.startswith("qemu/")
        or path == INPUT_NAMES["qemu"]
        or len(Path(path).parts) < 3
        or Path(path).parts[1] not in ("lib", "share")
        or type(value["size"]) is not int
        or not 0 < value["size"] <= host_runner.MAX_FILE_BYTES
    ):
        raise ValueError("QEMU support file is invalid")
    require_sha256(value["sha256"], "QEMU support fingerprint")
    return dict(value)


def implementation_contract():
    return {
        "sdk": sdk_dependency_contract(),
        "files": {
            name: {
                "path": str(path.relative_to(SUPPORT.parent)),
                "sha256": azure.image_sha256(path),
                "size": path.stat().st_size,
            }
            for name, path in IMPLEMENTATION_PATHS.items()
        },
    }


def sdk_dependency_contract():
    expected_requirements = "".join(
        f"{name}=={version}\n" for name, version in SDK_DISTRIBUTIONS
    ).encode()
    requirements = azure.read_regular_file(
        REQUIREMENTS_PATH, 16 * 1024,
        "Private-preflight dependency lock",
    )
    if requirements != expected_requirements:
        raise RuntimeError(
            "Private-preflight dependency lock is incompatible"
        )
    records = []
    for name, expected_version in SDK_DISTRIBUTIONS:
        try:
            package = package_distribution(name)
        except PackageNotFoundError:
            raise RuntimeError(
                "Pinned private-preflight dependency is unavailable"
            ) from None
        if package.version != expected_version or package.files is None:
            raise RuntimeError(
                "Pinned private-preflight dependency is incompatible"
            )
        digest = hashlib.sha256()
        count = 0
        total = 0
        for relative in sorted(package.files, key=str):
            path = Path(package.locate_file(relative))
            try:
                metadata = path.lstat()
            except OSError:
                raise RuntimeError(
                    "Pinned private-preflight dependency is incomplete"
                ) from None
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise RuntimeError(
                    "Pinned private-preflight dependency is unsafe"
                )
            fingerprint = azure.image_sha256(path)
            encoded = str(relative).encode()
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            digest.update(metadata.st_size.to_bytes(8, "big"))
            digest.update(bytes.fromhex(fingerprint))
            count += 1
            total += metadata.st_size
        if count == 0:
            raise RuntimeError(
                "Pinned private-preflight dependency is empty"
            )
        records.append({
            "name": name,
            "version": expected_version,
            "files": count,
            "bytes": total,
            "sha256": digest.hexdigest(),
        })
    return {
        "requirements_sha256": hashlib.sha256(requirements).hexdigest(),
        "distributions": records,
    }


def validate_implementation(value):
    value = exact_fields(
        value, ("sdk", "files"), "Private-preflight implementation"
    )
    sdk = exact_fields(
        value["sdk"], ("requirements_sha256", "distributions"),
        "Blob SDK contract",
    )
    require_sha256(
        sdk["requirements_sha256"], "Dependency lock fingerprint"
    )
    if (
        sdk["requirements_sha256"] != azure.image_sha256(REQUIREMENTS_PATH)
        or not isinstance(sdk["distributions"], list)
        or len(sdk["distributions"]) != len(SDK_DISTRIBUTIONS)
    ):
        raise ValueError("Blob SDK contract is incompatible")
    distributions = []
    for record, (name, version) in zip(
        sdk["distributions"], SDK_DISTRIBUTIONS
    ):
        record = exact_fields(
            record, ("name", "version", "files", "bytes", "sha256"),
            "Blob SDK distribution",
        )
        if (
            record["name"] != name
            or record["version"] != version
            or type(record["files"]) is not int
            or record["files"] <= 0
            or type(record["bytes"]) is not int
            or record["bytes"] <= 0
        ):
            raise ValueError("Blob SDK distribution is incompatible")
        require_sha256(
            record["sha256"], "Blob SDK distribution fingerprint"
        )
        distributions.append(dict(record))
    files = exact_fields(
        value["files"], tuple(IMPLEMENTATION_PATHS),
        "Private-preflight implementation files",
    )
    normalized = {}
    for name, path in IMPLEMENTATION_PATHS.items():
        record = exact_fields(
            files[name], ("path", "sha256", "size"),
            f"{name} implementation file",
        )
        if (
            record["path"] != str(path.relative_to(SUPPORT.parent))
            or type(record["size"]) is not int
            or record["size"] <= 0
        ):
            raise ValueError("Private-preflight implementation is invalid")
        require_sha256(
            record["sha256"], f"{name} implementation fingerprint"
        )
        normalized[name] = dict(record)
    return {
        "sdk": {
            "requirements_sha256": sdk["requirements_sha256"],
            "distributions": distributions,
        },
        "files": normalized,
    }


def validate_provenance(value):
    value = exact_fields(
        value,
        (
            "scheme", "head_commit", "tree_sha256", "tracked_entries",
            "config",
        ),
        "Private-preflight build provenance",
    )
    config = exact_fields(
        value["config"], ("name", "sha256", "size"),
        "Solved configuration provenance",
    )
    if (
        value["scheme"] != "unikraft.git-ls-tree-v1"
        or not isinstance(value["head_commit"], str)
        or not GIT_COMMIT.fullmatch(value["head_commit"])
        or type(value["tracked_entries"]) is not int
        or value["tracked_entries"] <= 0
        or config["name"] != SOLVED_CONFIG
        or type(config["size"]) is not int
        or not 0 < config["size"] <= 1024 * 1024
    ):
        raise ValueError("Private-preflight build provenance is invalid")
    require_sha256(value["tree_sha256"], "Tracked source-tree fingerprint")
    require_sha256(config["sha256"], "Solved configuration fingerprint")
    return {**value, "config": dict(config)}


def expected_budget(files, qemu_support):
    remote = sum(files[role]["size"] for role in REMOTE_ROLES)
    remote += sum(record["size"] for record in qemu_support)
    firmware_working = (
        files["ovmf_vars"]["size"] * host_runner.TOTAL_BOOT_COUNT
    )
    total = (
        remote + firmware_working
        + MAX_CONTROL_BYTES + MAX_EVIDENCE_BYTES
    )
    return {
        "remote_input_bytes": remote,
        "firmware_variable_copy_count": host_runner.TOTAL_BOOT_COUNT,
        "firmware_working_copy_bytes": firmware_working,
        "control_payload_max_bytes": MAX_CONTROL_BYTES,
        "evidence_max_bytes": MAX_EVIDENCE_BYTES,
        "total_max_bytes": total,
        "remaining_bytes": MAX_TOTAL_BYTES - total,
    }


def validate_packaging_report(report, efi_sha256, efi_size, file_size):
    expected = azure.packaging_contract(efi_sha256, file_size)
    report = exact_fields(
        report,
        tuple(expected) + (
            "boot-file-size", "disk-guid", "esp-partition-guid",
            "esp-volume-id",
        ),
        "Fixed-VHD packaging contract",
    )
    azure.check_packaging_report(report, efi_sha256, file_size)
    if type(report["boot-file-size"]) is not int or (
        report["boot-file-size"] != efi_size
    ):
        raise ValueError("Fixed-VHD boot file size is invalid")
    if (
        type(report["esp-volume-id"]) is not int
        or not 0 < report["esp-volume-id"] <= 0xffffffff
    ):
        raise ValueError("Fixed-VHD ESP volume ID is invalid")
    for field in ("disk-guid", "esp-partition-guid"):
        value = report[field]
        try:
            parsed = uuid.UUID(value) if isinstance(value, str) else None
        except ValueError:
            parsed = None
        if parsed is None or parsed.int == 0 or str(parsed) != value:
            raise ValueError(f"Fixed-VHD {field} is invalid")
    return dict(report)


def validate_input_manifest(value):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "workload", "boot_policy",
            "raw_size", "provenance", "files", "qemu_support", "miz",
            "packaging", "implementation", "budget",
            "capability_reference", "private_build",
        ),
        "Private-preflight input manifest",
    )
    if (
        value["schema"] != INPUT_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != INPUT_SCHEMA_VERSION
        or value["workload"] != WORKLOAD
        or value["boot_policy"] not in BOOT_POLICIES
        or type(value["raw_size"]) is not int
        or value["raw_size"] != azure.VIRTUAL_SIZE
    ):
        raise ValueError("Private-preflight input manifest is incompatible")
    files = exact_fields(
        value["files"], ALL_ROLES, "Private-preflight input files"
    )
    files = {role: file_record(files[role], role) for role in ALL_ROLES}
    if (
        not isinstance(value["qemu_support"], list)
        or len(value["qemu_support"]) > 124
    ):
        raise ValueError("QEMU support closure must be a list")
    qemu_support = [support_record(record) for record in value["qemu_support"]]
    support_paths = [record["path"] for record in qemu_support]
    if support_paths != sorted(set(support_paths)):
        raise ValueError("QEMU support closure must be sorted and unique")
    if (
        files["raw"]["size"] != value["raw_size"]
        or files["capability_raw"]["size"] != value["raw_size"]
        or files["vhd"]["size"] != value["raw_size"] + 512
    ):
        raise ValueError("Private-preflight raw/fixed-VHD sizes are invalid")
    miz = exact_fields(
        value["miz"], ("name", "revision", "sha256", "size"),
        "Private-preflight miz fingerprint",
    )
    if (
        miz["name"] != "miz"
        or miz["revision"] != azure.MIZ_REVISION
        or type(miz["size"]) is not int
        or miz["size"] <= 0
    ):
        raise ValueError("Private-preflight miz contract is invalid")
    require_sha256(miz["sha256"], "Private-preflight miz fingerprint")
    provenance = validate_provenance(value["provenance"])
    capability_reference = validate_capability_reference(
        value["capability_reference"], files["capability_raw"]
    )
    private_build = validate_private_build(
        value["private_build"], provenance, files["efi"]
    )
    implementation = validate_implementation(value["implementation"])
    budget = exact_fields(
        value["budget"],
        (
            "remote_input_bytes", "firmware_variable_copy_count",
            "firmware_working_copy_bytes",
            "control_payload_max_bytes",
            "evidence_max_bytes", "total_max_bytes", "remaining_bytes",
        ),
        "Private-preflight byte budget",
    )
    expected = expected_budget(files, qemu_support)
    if (
        any(type(budget[field]) is not int for field in budget)
        or dict(budget) != expected
        or expected["remaining_bytes"] < 0
    ):
        raise ValueError("Private-preflight staged files exceed 256 MiB")
    packaging = validate_packaging_report(
        value["packaging"], files["efi"]["sha256"], files["efi"]["size"],
        files["vhd"]["size"],
    )
    return {
        **value,
        "provenance": provenance,
        "capability_reference": capability_reference,
        "private_build": private_build,
        "files": files,
        "qemu_support": qemu_support,
        "miz": dict(miz),
        "packaging": dict(packaging),
        "implementation": implementation,
        "budget": dict(budget),
    }


def private_directory(path, description, *, must_exist=True):
    path = path.absolute()
    if must_exist:
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ValueError(f"{description} must not contain symlinks")
        metadata = path.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError(f"{description} must be owner-only")
    else:
        parent = path.parent.resolve(strict=True)
        if parent != path.parent:
            raise ValueError(f"{description} parent must not contain symlinks")
    return path


def sha256_prefix(path, length):
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as source:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("Fixed VHD data region is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def regular_record(path, name, description):
    original = Path(path)
    metadata = original.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise ValueError(f"{description} must be a regular non-symlink file")
    path = original.resolve(strict=True)
    size = path.stat().st_size
    if not 0 < size <= host_runner.MAX_FILE_BYTES:
        raise ValueError(f"{description} has an invalid size")
    return {
        "name": name,
        "sha256": azure.image_sha256(path),
        "size": size,
    }


def directory_record(path, name, description):
    original = Path(path)
    metadata = original.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{description} must be a non-symlink directory")
    root = original.resolve(strict=True)
    digest = hashlib.sha256()
    count = 0
    total = 0
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{description} contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{description} contains a nonregular file")
        encoded = relative.encode()
        fingerprint = azure.image_sha256(entry)
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(metadata.st_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(fingerprint))
        count += 1
        total += metadata.st_size
    if count == 0:
        raise ValueError(f"{description} is empty")
    return {
        "name": name,
        "sha256": digest.hexdigest(),
        "size": total,
        "files": count,
    }


def validate_tool_record(value, expected_name):
    value = exact_fields(
        value, ("name", "sha256", "size", "files"),
        "Private build tool fingerprint",
    )
    if (
        value["name"] != expected_name
        or type(value["size"]) is not int
        or value["size"] <= 0
        or type(value["files"]) is not int
        or value["files"] <= 0
    ):
        raise ValueError("Private build tool fingerprint is invalid")
    require_sha256(value["sha256"], "Private build tool fingerprint")
    return dict(value)


def validate_capability_reference(value, capability_raw):
    value = exact_fields(
        value, ("name", "sha256", "size", "receipt"),
        "Public capability reference",
    )
    if (
        value["name"] != CAPABILITY_REFERENCE
        or type(value["size"]) is not int
        or not 0 < value["size"] <= MAX_MANIFEST_BYTES
    ):
        raise ValueError("Public capability reference is invalid")
    require_sha256(value["sha256"], "Public capability reference")
    receipt = exact_fields(
        value["receipt"],
        (
            "schema", "schema_version", "scope", "source",
            "manifest_sha256", "efi_sha256", "raw", "source_vhd",
            "source_boot_evidence",
        ),
        "Public capability receipt",
    )
    if (
        receipt["schema"] != CAPABILITY_REFERENCE_SCHEMA
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["scope"] != (
            "historical nonsecret capability only; "
            "not current private deployment provenance"
        )
    ):
        raise ValueError("Public capability receipt is incompatible")
    source = exact_fields(
        receipt["source"],
        (
            "provider", "repository", "repository_id", "workflow_ref",
            "head_sha", "run_id", "run_attempt", "job",
        ),
        "Public capability source",
    )
    if (
        source["provider"] != "github-actions"
        or not isinstance(source["repository"], str)
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}",
            source["repository"],
        )
        or type(source["repository_id"]) is not int
        or source["repository_id"] <= 0
        or not isinstance(source["workflow_ref"], str)
        or not source["workflow_ref"].startswith(
            source["repository"] + "/.github/workflows/"
        )
        or not GIT_COMMIT.fullmatch(source["head_sha"])
        or type(source["run_id"]) is not int
        or source["run_id"] <= 0
        or type(source["run_attempt"]) is not int
        or source["run_attempt"] <= 0
        or not isinstance(source["job"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", source["job"])
    ):
        raise ValueError("Public capability source is invalid")
    require_sha256(
        receipt["manifest_sha256"], "Public capability manifest"
    )
    require_sha256(receipt["efi_sha256"], "Public capability EFI")
    raw = exact_fields(
        receipt["raw"], ("sha256", "size"), "Public capability raw image"
    )
    source_vhd = exact_fields(
        receipt["source_vhd"], ("sha256", "size"),
        "Public capability fixed VHD",
    )
    if (
        raw != {
            "sha256": capability_raw["sha256"],
            "size": capability_raw["size"],
        }
        or type(source_vhd["size"]) is not int
        or source_vhd["size"] != capability_raw["size"] + 512
    ):
        raise ValueError("Public capability image binding is invalid")
    require_sha256(source_vhd["sha256"], "Public capability fixed VHD")
    evidence = exact_fields(
        receipt["source_boot_evidence"],
        ("boots", "platform_marker", "scope"),
        "Public capability boot evidence",
    )
    if (
        evidence["platform_marker"] != host_runner.PLATFORM_MARKER
        or evidence["scope"] != "platform-only"
    ):
        raise ValueError("Public capability boot evidence is invalid")
    boots = exact_fields(
        evidence["boots"], ("raw", "vhd"), "Public capability boot formats"
    )
    for image, modes in boots.items():
        modes = exact_fields(
            modes, ("legacy-apic", "x2apic"),
            "Public capability boot modes",
        )
        for mode, outcome in modes.items():
            outcome = exact_fields(
                outcome, ("apic_path", "io_ready", "platform_ready"),
                "Public capability boot outcome",
            )
            expected_apic = (
                "legacy-xapic" if mode == "legacy-apic" else "x2apic"
            )
            if outcome != {
                "apic_path": expected_apic,
                "io_ready": False,
                "platform_ready": True,
            }:
                raise ValueError(
                    "Public capability boot outcome is invalid"
                )
    return {
        **value,
        "receipt": {
            **receipt,
            "source": dict(source),
            "raw": dict(raw),
            "source_vhd": dict(source_vhd),
            "source_boot_evidence": {
                **evidence,
                "boots": {
                    image: {
                        mode: dict(outcome)
                        for mode, outcome in image_modes.items()
                    }
                    for image, image_modes in boots.items()
                },
            },
        },
    }


def validate_private_build(value, provenance, efi):
    value = exact_fields(
        value, ("name", "sha256", "size", "receipt"),
        "Private local build receipt",
    )
    if (
        value["name"] != PRIVATE_BUILD_RECEIPT
        or type(value["size"]) is not int
        or not 0 < value["size"] <= MAX_MANIFEST_BYTES
    ):
        raise ValueError("Private local build receipt is invalid")
    require_sha256(value["sha256"], "Private local build receipt")
    receipt = exact_fields(
        value["receipt"],
        (
            "schema", "schema_version", "result", "source_before",
            "source_after", "invocation", "tools", "output",
            "builder_sha256",
        ),
        "Private local build receipt",
    )
    before = validate_provenance(receipt["source_before"])
    after = validate_provenance(receipt["source_after"])
    if (
        receipt["schema"] != PRIVATE_BUILD_SCHEMA
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["result"] != "PASS"
        or before != provenance
        or after != provenance
        or require_sha256(
            receipt["builder_sha256"], "Private build implementation"
        ) != azure.image_sha256(Path(__file__))
    ):
        raise ValueError("Private local build provenance is incompatible")
    invocation = exact_fields(
        receipt["invocation"],
        (
            "engine", "jobs", "app", "profile", "compiler_target",
            "output",
        ),
        "Private local build invocation",
    )
    if invocation != {
        "engine": "zig-native-images-v1",
        "jobs": 2,
        "app": "support/apps/hyperv-acceptance",
        "profile": "hyperv-x86_64-efi-netvsc",
        "compiler_target": "x86_64-freestanding-none",
        "output": NATIVE_EFI_NAME,
    }:
        raise ValueError("Private local build invocation is incompatible")
    tools = exact_fields(
        receipt["tools"], BUILD_TOOL_NAMES, "Private local build tools"
    )
    tools = {
        name: validate_tool_record(tools[name], name)
        for name in BUILD_TOOL_NAMES
    }
    output = exact_fields(
        receipt["output"], ("name", "sha256", "size"),
        "Private local build output",
    )
    if output != {
        "name": NATIVE_EFI_NAME,
        "sha256": efi["sha256"],
        "size": efi["size"],
    }:
        raise ValueError("Private local build output is unrelated to the EFI")
    return {
        **value,
        "receipt": {
            **receipt,
            "source_before": before,
            "source_after": after,
            "invocation": dict(invocation),
            "tools": tools,
            "output": dict(output),
        },
    }


def load_receipt(path, name, description):
    record = regular_record(path, name, description)
    if record["size"] > MAX_MANIFEST_BYTES:
        raise ValueError(f"{description} is too large")
    raw = azure.read_regular_file(path, MAX_MANIFEST_BYTES, description)
    return {
        **record,
        "receipt": azure.parse_strict_json(raw, description),
    }


def git_output(repository, arguments):
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Unable to derive local Git source provenance")
    return result.stdout


def build_provenance(repository, config_path):
    repository = repository.resolve(strict=True)
    if repository != SUPPORT.parent.resolve(strict=True):
        raise ValueError("Source provenance must use this repository worktree")
    if git_output(
        repository,
        ["status", "--porcelain=v1", "--untracked-files=no", "-z"],
    ):
        raise ValueError("Source provenance requires a clean tracked worktree")
    head = git_output(repository, ["rev-parse", "HEAD"]).decode().strip()
    tree = git_output(
        repository, ["ls-tree", "-r", "--full-tree", "-z", "HEAD"]
    )
    if not GIT_COMMIT.fullmatch(head) or not tree:
        raise ValueError("Git source provenance is invalid")
    config = regular_record(config_path, SOLVED_CONFIG, "Solved configuration")
    return {
        "scheme": "unikraft.git-ls-tree-v1",
        "head_commit": head,
        "tree_sha256": hashlib.sha256(tree).hexdigest(),
        "tracked_entries": tree.count(b"\0"),
        "config": config,
    }


def local_tool_record(path, name):
    path = Path(path).resolve(strict=True)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Private build tool {name} is not a regular file")
    return {
        "name": name,
        "sha256": azure.image_sha256(path),
        "size": metadata.st_size,
        "files": 1,
    }


def write_tool_wrapper(path, executable, environment=None):
    lines = ["#!/bin/sh", "set -eu"]
    for name, value in (environment or {}).items():
        lines.append(f"export {name}={shlex.quote(str(value))}")
    lines.append(f"exec {shlex.quote(str(executable))} \"$@\"")
    save_private_bytes(path, ("\n".join(lines) + "\n").encode())
    path.chmod(0o700)


def build_private_image(
    output_directory, repository, config_path, zig_path, make_path,
    python_path, bison_path, flex_path, m4_path, bison_data,
    llvm_directory, timeout,
):
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("Private local build timeout must be 1-3600 seconds")
    repository = Path(repository).resolve(strict=True)
    source_before = build_provenance(repository, config_path)
    output_directory = private_directory(
        output_directory, "Private local build directory", must_exist=False
    )
    tools = {
        "zig": local_tool_record(zig_path, "zig"),
        "make": local_tool_record(make_path, "make"),
        "python": local_tool_record(python_path, "python"),
        "bison": local_tool_record(bison_path, "bison"),
        "flex": local_tool_record(flex_path, "flex"),
        "m4": local_tool_record(m4_path, "m4"),
    }
    resolved = {
        "zig": Path(zig_path).resolve(strict=True),
        "make": Path(make_path).resolve(strict=True),
        "python": Path(python_path).resolve(strict=True),
        "bison": Path(bison_path).resolve(strict=True),
        "flex": Path(flex_path).resolve(strict=True),
        "m4": Path(m4_path).resolve(strict=True),
    }
    llvm_directory = Path(llvm_directory).resolve(strict=True)
    for name in (
        "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf",
        "llvm-strip",
    ):
        path = llvm_directory / name
        path.resolve(strict=True)
        tools[name] = local_tool_record(path, name)
        resolved[name] = path
    tools["bison-data"] = directory_record(
        bison_data, "bison-data", "Private build Bison data"
    )
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = output_directory / SOLVED_CONFIG
    build_output = output_directory / "build"
    wrappers = output_directory / ".tool-bin"
    temporary = output_directory / "tmp"
    cache = output_directory / "cache"
    wrappers.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    copy_record(
        Path(config_path).resolve(strict=True), config,
        source_before["config"],
    )
    wrapper_tools = {
        "make": ("make", None),
        "python3": ("python", None),
        "bison": (
            "bison",
            {
                "BISON_PKGDATADIR": Path(bison_data).resolve(strict=True),
                "M4": resolved["m4"],
            },
        ),
        "yacc": (
            "bison",
            {
                "BISON_PKGDATADIR": Path(bison_data).resolve(strict=True),
                "M4": resolved["m4"],
            },
        ),
        "flex": ("flex", {"M4": resolved["m4"]}),
        "lex": ("flex", {"M4": resolved["m4"]}),
        "llvm-nm": ("llvm-nm", None),
        "llvm-objcopy": ("llvm-objcopy", None),
        "llvm-objdump": ("llvm-objdump", None),
        "llvm-readelf": ("llvm-readelf", None),
        "llvm-strip": ("llvm-strip", None),
    }
    for wrapper, (tool, environment) in wrapper_tools.items():
        write_tool_wrapper(
            wrappers / wrapper, resolved[tool], environment
        )
    zig = str(resolved["zig"])
    command = [
        zig, "build", "native-images", "-j2",
        "-Dapp=" + str(SUPPORT / "apps" / "hyperv-acceptance"),
        "-Dconfig=" + str(config),
        "-Doutput=" + str(build_output),
        "-Dnative-profile=hyperv-x86_64-efi-netvsc",
        f"-Dcompiler={zig} cc -target x86_64-freestanding-none",
        "-Dcompiler-targeted=true",
        f"-Dhost-cc={zig} cc",
        f"-Dhost-cxx={zig} c++",
        "-Dhost-cflags=-fno-sanitize=null",
        f"-Dmake-arg=AR={zig} ar",
        "-Dmake-arg=NM=llvm-nm",
        "-Dmake-arg=OBJCOPY=llvm-objcopy",
        "-Dmake-arg=OBJDUMP=llvm-objdump",
        "-Dmake-arg=READELF=llvm-readelf",
        "-Dmake-arg=STRIP=llvm-strip",
        "-Dmake-arg=UK_CFLAGS=-std=gnu17",
        "-Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt",
    ]
    environment = os.environ.copy()
    environment.update({
        "PATH": str(wrappers) + os.pathsep + environment.get("PATH", ""),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache / "xdg"),
        "ZIG_GLOBAL_CACHE_DIR": str(cache / "zig-global"),
        "ZIG_LOCAL_CACHE_DIR": str(cache / "zig-local"),
        "PYTHONPYCACHEPREFIX": str(cache / "pycache"),
        "BISON_PKGDATADIR": str(Path(bison_data).resolve(strict=True)),
        "M4": str(resolved["m4"]),
        "LC_ALL": "C",
    })

    log_path = output_directory / "build.log"
    with log_path.open("xb") as log:
        os.chmod(log_path, 0o600)
        process = subprocess.Popen(
            command, cwd=repository, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=environment, start_new_session=True,
        )
        overflow = threading.Event()

        def drain_output():
            written = 0
            for chunk in iter(lambda: process.stdout.read(64 * 1024), b""):
                remaining = 8 * 1024 * 1024 - written
                if remaining > 0:
                    log.write(chunk[:remaining])
                    written += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    overflow.set()
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        reader = threading.Thread(target=drain_output, daemon=True)
        reader.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            reader.join()
            process.stdout.close()
            raise RuntimeError("Private local native build timed out") from None
        reader.join()
        process.stdout.close()
        log.flush()
        os.fsync(log.fileno())
    if overflow.is_set():
        raise RuntimeError("Private local native build log exceeded 8 MiB")
    if returncode:
        raise RuntimeError(
            "Private local native build failed; inspect its owner-only log"
        )
    source_after = build_provenance(repository, config)
    if source_after != source_before:
        raise RuntimeError("Private source or configuration changed during build")
    efi_path = build_output / NATIVE_EFI_NAME
    output = regular_record(
        efi_path, NATIVE_EFI_NAME, "Private local EFI build output"
    )
    receipt = {
        "schema": PRIVATE_BUILD_SCHEMA,
        "schema_version": 1,
        "result": "PASS",
        "source_before": source_before,
        "source_after": source_after,
        "invocation": {
            "engine": "zig-native-images-v1",
            "jobs": 2,
            "app": "support/apps/hyperv-acceptance",
            "profile": "hyperv-x86_64-efi-netvsc",
            "compiler_target": "x86_64-freestanding-none",
            "output": NATIVE_EFI_NAME,
        },
        "tools": tools,
        "output": output,
        "builder_sha256": azure.image_sha256(Path(__file__)),
    }
    receipt_path = output_directory / PRIVATE_BUILD_RECEIPT
    save_private_bytes(receipt_path, azure.canonical_json(receipt))
    validate_private_build(
        load_receipt(
            receipt_path, PRIVATE_BUILD_RECEIPT,
            "Private local build receipt",
        ),
        source_before,
        {
            "name": INPUT_NAMES["efi"],
            "sha256": output["sha256"],
            "size": output["size"],
        },
    )
    azure.fsync_directory(output_directory)
    return receipt_path, efi_path


def qemu_closure_records(qemu_root):
    original = Path(qemu_root)
    metadata = original.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("QEMU closure root must be a non-symlink directory")
    qemu_root = original.resolve(strict=True)
    records = []
    executable = None
    for entry in sorted(qemu_root.rglob("*")):
        relative = entry.relative_to(qemu_root)
        if (
            relative.parts
            and relative.parts[0] not in ("bin", "lib", "share")
        ):
            raise ValueError("QEMU closure has an unsupported top-level path")
        destination = Path("qemu") / relative
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("QEMU closure must not contain symlinks")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("QEMU closure contains a nonregular file")
        record = regular_record(
            entry, destination.as_posix(), "QEMU closure member"
        )
        if record["name"] == INPUT_NAMES["qemu"]:
            executable = record
        elif relative.parts[0] == "bin":
            raise ValueError("QEMU closure contains an unexpected executable")
        else:
            records.append({
                "path": record["name"],
                "sha256": record["sha256"],
                "size": record["size"],
            })
    if executable is None:
        raise ValueError(
            "QEMU closure requires bin/qemu-system-x86_64"
        )
    return executable, records


def copy_record(source, destination, record):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    azure.copy_regular_file(
        source, destination, record["size"], record["sha256"]
    )


def generate_input(
    output_directory, repository, config_path, qemu_root, ovmf_code,
    ovmf_vars, capability_raw, capability_receipt, efi, build_receipt,
    raw, vhd, miz_path, boot_policy,
):
    check_blob_dependency()
    if boot_policy not in BOOT_POLICIES:
        raise ValueError("Unsupported platform-only boot policy")
    provenance = build_provenance(repository, config_path)
    qemu, qemu_support = qemu_closure_records(qemu_root)
    files = {
        "qemu": qemu,
        "ovmf_code": regular_record(
            ovmf_code, INPUT_NAMES["ovmf_code"], "OVMF code"
        ),
        "ovmf_vars": regular_record(
            ovmf_vars, INPUT_NAMES["ovmf_vars"], "OVMF variables"
        ),
        "capability_raw": regular_record(
            capability_raw, INPUT_NAMES["capability_raw"],
            "Public capability raw image",
        ),
        "efi": regular_record(efi, INPUT_NAMES["efi"], "Private EFI"),
        "raw": regular_record(raw, INPUT_NAMES["raw"], "Private raw image"),
        "vhd": regular_record(
            vhd, INPUT_NAMES["vhd"], "Private fixed VHD"
        ),
    }
    if (
        files["capability_raw"]["size"] != azure.VIRTUAL_SIZE
        or files["raw"]["size"] != azure.VIRTUAL_SIZE
        or files["vhd"]["size"] != azure.VIRTUAL_SIZE + 512
    ):
        raise ValueError("Generated raw/fixed-VHD geometry is invalid")
    capability_reference = validate_capability_reference(
        load_receipt(
            capability_receipt, CAPABILITY_REFERENCE,
            "Public capability reference",
        ),
        files["capability_raw"],
    )
    private_build = validate_private_build(
        load_receipt(
            build_receipt, PRIVATE_BUILD_RECEIPT,
            "Private local build receipt",
        ),
        provenance, files["efi"],
    )
    miz = regular_record(miz_path, "miz", "Pinned miz executable")
    miz["revision"] = azure.MIZ_REVISION
    miz = {
        "name": miz["name"],
        "revision": miz["revision"],
        "sha256": miz["sha256"],
        "size": miz["size"],
    }
    output_directory = private_directory(
        output_directory, "Generated private-preflight input directory",
        must_exist=False,
    )
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for role, record in files.items():
            sources = {
                "ovmf_code": ovmf_code,
                "ovmf_vars": ovmf_vars,
                "capability_raw": capability_raw,
                "efi": efi,
                "raw": raw,
                "vhd": vhd,
            }
            source = (
                qemu_root.resolve(strict=True)
                / Path(record["name"]).relative_to("qemu")
                if role == "qemu" else sources[role]
            )
            copy_record(
                Path(source).resolve(strict=True),
                output_directory / record["name"],
                record,
            )
        for record in qemu_support:
            source = (
                qemu_root.resolve(strict=True)
                / Path(record["path"]).relative_to("qemu")
            )
            copy_record(source, output_directory / record["path"], record)
        copy_record(
            config_path.resolve(strict=True),
            output_directory / SOLVED_CONFIG,
            provenance["config"],
        )
        copy_record(
            Path(capability_receipt).resolve(strict=True),
            output_directory / CAPABILITY_REFERENCE,
            capability_reference,
        )
        copy_record(
            Path(build_receipt).resolve(strict=True),
            output_directory / PRIVATE_BUILD_RECEIPT,
            private_build,
        )
        packaging = azure.miz_command(
            miz_path.resolve(strict=True),
            [
                "check-efi-application", "--output=json",
                "--architecture", "x86_64",
                "--expected-efi-sha256", files["efi"]["sha256"],
                "--expected-virtual-size", "66M",
                str(output_directory / INPUT_NAMES["vhd"]),
            ],
            output_directory / "miz-generate-check.log",
            json_output=True,
        )
        (output_directory / "miz-generate-check.log").unlink(missing_ok=True)
        packaging = validate_packaging_report(
            packaging, files["efi"]["sha256"], files["efi"]["size"],
            files["vhd"]["size"],
        )
        if sha256_prefix(
            output_directory / INPUT_NAMES["vhd"], azure.VIRTUAL_SIZE
        ) != files["raw"]["sha256"]:
            raise ValueError("Fixed VHD data region differs from raw image")
        budget = expected_budget(files, qemu_support)
        if budget["remaining_bytes"] < 0:
            raise ValueError("Generated staged closure exceeds 256 MiB")
        manifest = validate_input_manifest({
            "schema": INPUT_SCHEMA,
            "schema_version": INPUT_SCHEMA_VERSION,
            "workload": WORKLOAD,
            "boot_policy": boot_policy,
            "raw_size": azure.VIRTUAL_SIZE,
            "provenance": provenance,
            "capability_reference": capability_reference,
            "private_build": private_build,
            "files": files,
            "qemu_support": qemu_support,
            "miz": miz,
            "packaging": dict(packaging),
            "implementation": implementation_contract(),
            "budget": budget,
        })
        manifest_bytes = azure.canonical_json(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ValueError("Generated private-preflight manifest is too large")
        save_private_bytes(
            output_directory / INPUT_MANIFEST, manifest_bytes
        )
        azure.fsync_directory(output_directory)
        return hashlib.sha256(manifest_bytes).hexdigest()
    except BaseException:
        shutil.rmtree(output_directory, ignore_errors=True)
        raise


def load_input_manifest(input_directory, expected_sha256):
    input_directory = private_directory(
        input_directory, "Private-preflight input directory"
    )
    path = input_directory / INPUT_MANIFEST
    raw = azure.read_regular_file(
        path, MAX_MANIFEST_BYTES, "Private-preflight input manifest"
    )
    if hashlib.sha256(raw).hexdigest() != require_sha256(
        expected_sha256, "Expected private-preflight manifest"
    ):
        raise ValueError("Private-preflight manifest digest does not match")
    expected_names = {
        INPUT_MANIFEST, SOLVED_CONFIG, CAPABILITY_REFERENCE,
        PRIVATE_BUILD_RECEIPT, "qemu",
        *(Path(name).parts[0] for role, name in INPUT_NAMES.items()
          if role != "qemu"),
    }
    actual_names = {entry.name for entry in input_directory.iterdir()}
    if actual_names != expected_names:
        raise ValueError("Private-preflight input directory has extra or missing files")
    manifest = validate_input_manifest(
        azure.parse_strict_json(raw, "Private-preflight input manifest")
    )
    expected_qemu = {
        manifest["files"]["qemu"]["name"],
        *(record["path"] for record in manifest["qemu_support"]),
    }
    actual_qemu = {
        str(path.relative_to(input_directory)).replace(os.sep, "/")
        for path in (input_directory / "qemu").rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_qemu != expected_qemu:
        raise ValueError("Private-preflight QEMU closure differs from manifest")
    return input_directory, manifest, raw


def prepare(input_directory, state_directory, miz_path, expected_sha256):
    source, manifest, manifest_bytes = load_input_manifest(
        input_directory, expected_sha256
    )
    check_blob_dependency()
    if (
        manifest["implementation"] != implementation_contract()
        or build_provenance(
            SUPPORT.parent, source / SOLVED_CONFIG
        ) != manifest["provenance"]
    ):
        raise ValueError(
            "Private-preflight source, configuration, or dependencies changed"
        )
    miz_source = Path(miz_path)
    if stat.S_ISLNK(miz_source.lstat().st_mode):
        raise ValueError("Pinned miz executable must not be a symlink")
    miz_path = miz_source.resolve(strict=True)
    if (
        not miz_path.is_file()
        or not os.access(miz_path, os.X_OK)
        or miz_path.stat().st_size != manifest["miz"]["size"]
        or azure.image_sha256(miz_path) != manifest["miz"]["sha256"]
    ):
        raise ValueError("Pinned miz executable does not match the manifest")
    state_directory = private_directory(
        state_directory, "Private-preflight state directory", must_exist=False
    )
    state_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs = state_directory / "inputs"
    inputs.mkdir(mode=0o700)
    local_tools = state_directory / "local-tools"
    local_tools.mkdir(mode=0o700)
    try:
        manifest_path = inputs / INPUT_MANIFEST
        with manifest_path.open("xb") as output:
            os.chmod(manifest_path, 0o600)
            output.write(manifest_bytes)
            output.flush()
            os.fsync(output.fileno())
        for role, record in manifest["files"].items():
            copy_record(
                source / record["name"], inputs / record["name"], record
            )
        for record in manifest["qemu_support"]:
            copy_record(
                source / record["path"], inputs / record["path"], record
            )
        copy_record(
            source / SOLVED_CONFIG,
            inputs / SOLVED_CONFIG,
            manifest["provenance"]["config"],
        )
        copy_record(
            source / CAPABILITY_REFERENCE,
            inputs / CAPABILITY_REFERENCE,
            manifest["capability_reference"],
        )
        copy_record(
            source / PRIVATE_BUILD_RECEIPT,
            inputs / PRIVATE_BUILD_RECEIPT,
            manifest["private_build"],
        )
        azure.copy_regular_file(
            miz_path, local_tools / "miz",
            manifest["miz"]["size"], manifest["miz"]["sha256"],
        )
        copied_miz = local_tools / "miz"
        copied_miz.chmod(0o700)
        checked = azure.miz_command(copied_miz, [
            "check-efi-application", "--output=json",
            "--architecture", "x86_64",
            "--expected-efi-sha256", manifest["files"]["efi"]["sha256"],
            "--expected-virtual-size", "66M",
            str(inputs / INPUT_NAMES["vhd"]),
        ], state_directory / "miz-check.log", json_output=True)
        checked = validate_packaging_report(
            checked, manifest["files"]["efi"]["sha256"],
            manifest["files"]["efi"]["size"],
            manifest["files"]["vhd"]["size"],
        )
        if (
            azure.canonical_json(checked)
            != azure.canonical_json(manifest["packaging"])
        ):
            raise ValueError("Pinned miz result differs from the input manifest")
        if sha256_prefix(
            inputs / INPUT_NAMES["vhd"], manifest["raw_size"]
        ) != manifest["files"]["raw"]["sha256"]:
            raise ValueError("Fixed VHD data region does not match the raw image")
        identity = secrets.token_hex(16)
        prefix = "uk-hvp-" + secrets.token_hex(6)
        state = {
            "schema": STATE_SCHEMA,
            "schema_version": STATE_SCHEMA_VERSION,
            "phase": "prepared",
            "identity": identity,
            "name_prefix": prefix,
            "location": LOCATION,
            "vm_size": VM_SIZE,
            "image_sha256": manifest["files"]["vhd"]["sha256"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "implementation": manifest["implementation"],
            "input_manifest": manifest,
            "staged_input_bytes": 0,
            "control_payload_bytes": 0,
            "evidence_bytes": 0,
            "pending_secret_files": [],
            "cleanup_required": False,
        }
        azure.save_durable_json(state_directory / STATE_FILE, state)
        return state_directory
    except BaseException:
        if not (state_directory / STATE_FILE).exists():
            import shutil
            shutil.rmtree(state_directory, ignore_errors=True)
        raise


def load_state(directory):
    directory = private_directory(
        directory, "Private-preflight state directory"
    )
    path = directory / STATE_FILE
    raw = azure.read_regular_file(
        path, MAX_STATE_BYTES, "Private-preflight private state"
    )
    state = azure.parse_strict_json(raw, "Private-preflight private state")
    if any(
        field in state
        for field in (
            "acceptance", "group_precreated", "prepared_image_import",
            "reservation_claim", "resource_group",
        )
    ):
        raise ValueError(
            "Private-preflight state cannot adopt another controller's resources"
        )
    if (
        not isinstance(state, dict)
        or state.get("schema") != STATE_SCHEMA
        or type(state.get("schema_version")) is not int
        or state["schema_version"] != STATE_SCHEMA_VERSION
        or not isinstance(state.get("name_prefix"), str)
        or not re.fullmatch(r"uk-hvp-[0-9a-f]{12}", state["name_prefix"])
        or not isinstance(state.get("identity"), str)
        or not IDENTITY.fullmatch(state["identity"])
        or state.get("location") != LOCATION
        or state.get("vm_size") != VM_SIZE
        or not isinstance(state.get("input_manifest"), dict)
        or not isinstance(state.get("implementation"), dict)
        or type(state.get("staged_input_bytes")) is not int
        or state["staged_input_bytes"] < 0
        or type(state.get("control_payload_bytes")) is not int
        or state["control_payload_bytes"] < 0
        or type(state.get("evidence_bytes")) is not int
        or state["evidence_bytes"] < 0
        or not isinstance(state.get("pending_secret_files"), list)
        or type(state.get("cleanup_required")) is not bool
    ):
        raise ValueError("Private-preflight state is incompatible")
    if any(
        not isinstance(name, str)
        or not re.fullmatch(
            r"\.(?:blob-request|deployment-parameters|run-command)-"
            r"[0-9a-f]{16}\.json",
            name,
        )
        for name in state["pending_secret_files"]
    ) or len(set(state["pending_secret_files"])) != len(
        state["pending_secret_files"]
    ):
        raise ValueError("Private-preflight secret-file obligation is invalid")
    state["input_manifest"] = validate_input_manifest(state["input_manifest"])
    state["implementation"] = validate_implementation(
        state["implementation"]
    )
    require_sha256(state.get("manifest_sha256"), "State manifest fingerprint")
    require_sha256(state.get("image_sha256"), "State image fingerprint")
    if (
        state["image_sha256"]
        != state["input_manifest"]["files"]["vhd"]["sha256"]
        or state["control_payload_bytes"] > MAX_CONTROL_BYTES
        or state["evidence_bytes"] > MAX_EVIDENCE_BYTES
        or state["staged_input_bytes"]
        > state["input_manifest"]["budget"]["remote_input_bytes"]
        or (
            state["staged_input_bytes"]
            + state["input_manifest"]["budget"][
                "firmware_working_copy_bytes"
            ]
            + state["control_payload_bytes"]
            + state["evidence_bytes"]
            > MAX_TOTAL_BYTES
        )
    ):
        raise ValueError("Private-preflight image binding is incompatible")
    obligation = state.get("firewall_obligation")
    if obligation is not None:
        obligation = exact_fields(
            obligation, ("cidr", "phase"), "Private Blob firewall obligation"
        )
        try:
            network = ipaddress.ip_network(obligation["cidr"], strict=True)
        except ValueError:
            raise ValueError("Private Blob firewall obligation is invalid") from None
        if (
            network.version != 4
            or network.prefixlen != 32
            or obligation["phase"] not in (
                "pending-add", "active", "pending-remove"
            )
        ):
            raise ValueError("Private Blob firewall obligation is invalid")
    host_deployment = state.get("host_deployment")
    if host_deployment is not None:
        host_deployment = exact_fields(
            host_deployment,
            (
                "phase", "operation_id", "deployment_id",
                "correlation_id", "vm_id", "vm_uuid", "disk_id",
                "disk_uuid", "shutdown_time",
            ),
            "Private host deployment obligation",
        )
        if (
            host_deployment["phase"] not in (
                "pending", "deployment-succeeded", "resources-verified",
                "deployment-terminal", "vm-verified", "failed-no-compute",
                "not-created-empty",
            )
            or not isinstance(host_deployment["operation_id"], str)
            or str(uuid.UUID(host_deployment["operation_id"]))
            != host_deployment["operation_id"]
            or not isinstance(host_deployment["shutdown_time"], str)
            or not re.fullmatch(r"(?:[01][0-9]|2[0-3])[0-5][0-9]",
                                host_deployment["shutdown_time"])
        ):
            raise ValueError("Private host deployment obligation is invalid")
        for field in ("deployment_id", "vm_id", "disk_id"):
            if not isinstance(host_deployment[field], str):
                raise ValueError("Private host deployment obligation is invalid")
        for field in ("correlation_id", "vm_uuid", "disk_uuid"):
            if host_deployment[field] is not None:
                require_uuid(
                    host_deployment[field],
                    "Private host deployment identity",
                )
        phase = host_deployment["phase"]
        correlation = host_deployment["correlation_id"]
        vm_uuid = host_deployment["vm_uuid"]
        disk_uuid = host_deployment["disk_uuid"]
        if (
            ((vm_uuid is None) != (disk_uuid is None))
            or (phase == "pending" and any(
                value is not None
                for value in (correlation, vm_uuid, disk_uuid)
            ))
            or (
                phase in (
                    "deployment-succeeded", "vm-verified",
                    "resources-verified",
                )
                and any(
                    value is None
                    for value in (correlation, vm_uuid, disk_uuid)
                )
            )
            or (
                phase in (
                    "failed-no-compute", "not-created-empty",
                )
                and (vm_uuid is not None or disk_uuid is not None)
            )
        ):
            raise ValueError(
                "Private host deployment identity anchors are invalid"
            )
    subscription = state.get("subscription")
    if subscription is not None:
        azure.validate_subscription_id(subscription)
        if (
            type(state.get("deadline_monotonic")) not in (int, float)
            or state["deadline_monotonic"] <= 0
            or not isinstance(state.get("deadline_utc"), str)
        ):
            raise ValueError("Private-preflight deadline binding is invalid")
        storage = state.get("storage_account")
        if not isinstance(storage, str) or not STORAGE_NAME.fullmatch(storage):
            raise ValueError("Private-preflight storage binding is invalid")
        group_id = state.get("resource_group_id")
        if group_id is not None:
            expected_group_id = (
                f"/subscriptions/{subscription}/resourceGroups/"
                f"{state['name_prefix']}-rg"
            )
            if (
                not isinstance(group_id, str)
                or group_id.lower() != expected_group_id.lower()
            ):
                raise ValueError("Private-preflight group binding is invalid")
    return state, path


def verify_immutable_inputs(state, state_directory):
    manifest = state["input_manifest"]
    manifest_path = state_directory / "inputs" / INPUT_MANIFEST
    manifest_bytes = azure.read_regular_file(
        manifest_path, MAX_MANIFEST_BYTES,
        "Prepared private-preflight input manifest",
    )
    if (
        hashlib.sha256(manifest_bytes).hexdigest()
        != state["manifest_sha256"]
        or validate_input_manifest(
            azure.parse_strict_json(
                manifest_bytes, "Prepared private-preflight input manifest"
            )
        ) != manifest
        or state["implementation"] != state["input_manifest"]["implementation"]
        or state["implementation"] != implementation_contract()
    ):
        raise ValueError(
            "Private-preflight controller, runner, template, or manifest changed"
        )
    for role, record in manifest["files"].items():
        path = state_directory / "inputs" / record["name"]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != record["size"]
            or azure.image_sha256(path) != record["sha256"]
        ):
            raise ValueError(f"Prepared {role} input changed")
    for record in manifest["qemu_support"]:
        path = state_directory / "inputs" / record["path"]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != record["size"]
            or azure.image_sha256(path) != record["sha256"]
        ):
            raise ValueError("Prepared QEMU support closure changed")
    config = manifest["provenance"]["config"]
    config_path = state_directory / "inputs" / config["name"]
    if (
        config_path.is_symlink()
        or not config_path.is_file()
        or config_path.stat().st_size != config["size"]
        or azure.image_sha256(config_path) != config["sha256"]
        or build_provenance(SUPPORT.parent, config_path)
        != manifest["provenance"]
    ):
        raise ValueError("Prepared source or solved configuration changed")
    for name, key, description in (
        (
            CAPABILITY_REFERENCE, "capability_reference",
            "Prepared public capability reference",
        ),
        (
            PRIVATE_BUILD_RECEIPT, "private_build",
            "Prepared private local build receipt",
        ),
    ):
        record = manifest[key]
        path = state_directory / "inputs" / name
        raw = azure.read_regular_file(path, MAX_MANIFEST_BYTES, description)
        if (
            path.is_symlink()
            or path.stat().st_size != record["size"]
            or hashlib.sha256(raw).hexdigest() != record["sha256"]
            or azure.parse_strict_json(raw, description)
            != record["receipt"]
        ):
            raise ValueError(f"{description} changed")
    miz = state_directory / "local-tools" / "miz"
    if (
        miz.is_symlink()
        or not miz.is_file()
        or not os.access(miz, os.X_OK)
        or miz.stat().st_size != manifest["miz"]["size"]
        or azure.image_sha256(miz) != manifest["miz"]["sha256"]
    ):
        raise ValueError("Prepared miz executable changed")


def check_blob_dependency():
    sdk_dependency_contract()
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        raise RuntimeError(
            "Pinned azure-storage-blob dependency is unavailable"
        ) from None
    return BlobServiceClient


def transfer_source(value):
    if not isinstance(value, str):
        raise ValueError("An explicit transfer source IPv4 address is required")
    try:
        address = ipaddress.IPv4Address(value.removesuffix("/32"))
    except ipaddress.AddressValueError:
        raise ValueError("Transfer source must be one explicit IPv4 /32") from None
    if (
        value not in (str(address), f"{address}/32")
        or not address.is_global
    ):
        raise ValueError("Transfer source must be one explicit public IPv4 /32")
    return f"{address}/32"


def check_subscription(subscription):
    subscription = azure.selected_account(subscription)
    for namespace in (
        "Microsoft.Compute", "Microsoft.Network", "Microsoft.Storage",
        "Microsoft.DevTestLab",
    ):
        if azure.azure_cli([
            "provider", "show", "--namespace", namespace,
            "--query", "registrationState",
        ], subscription=subscription, private=True) != "Registered":
            raise RuntimeError("Required Azure providers must already be registered")
    versions = azure.azure_cli([
        "provider", "show", "--namespace", "Microsoft.Compute",
        "--query",
        "resourceTypes[?resourceType=='virtualMachines'].apiVersions | [0]",
    ], subscription=subscription, private=True)
    if not isinstance(versions, list) or "2025-11-01" not in versions:
        raise RuntimeError("Compute API 2025-11-01 is required")
    sku = azure.exact_vm_sku(
        LOCATION, VM_SIZE, subscription, vcpus=2, require_v2=True
    )
    nested = azure.azure_cli([
        "vm", "list-skus", "--all", "--location", LOCATION,
        "--resource-type", "virtualMachines", "--size", VM_SIZE,
        "--query",
        (
            f"[?name=='{VM_SIZE}'].capabilities[] | "
            "[?name=='NestedVirtualization'].value"
        ),
    ], subscription=subscription, private=True)
    if nested != ["True"]:
        raise RuntimeError(
            "The exact preflight SKU does not advertise nested virtualization"
        )
    image = azure.resolve_peer_image(LOCATION, subscription, ("V2",))
    if image["hyperv_generation"] != "V2":
        raise RuntimeError("The selected immutable Ubuntu image is not Gen2")
    usage = azure.azure_cli([
        "vm", "list-usage", "--location", LOCATION,
        "--query",
        f"[?name.value=='cores' || name.value=='{sku['family']}']",
    ], subscription=subscription, private=True)
    if not isinstance(usage, list):
        raise RuntimeError("Azure returned invalid quota information")
    limits = {
        item.get("name", {}).get("value"): item
        for item in usage if isinstance(item, dict)
    }
    for name in ("cores", sku["family"]):
        if name not in limits or (
            azure.quota_count(limits[name].get("limit"))
            - azure.quota_count(limits[name].get("currentValue"))
        ) < 2:
            raise RuntimeError("Two-vCPU preflight quota is unavailable")
    return {"subscription": subscription, "sku": sku, "image": image}


def utc_text(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def bounded_timeout(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("The private preflight deadline has expired")
    return max(1, min(maximum, int(remaining)))


def run_blob_worker(run, request, sas, deadline):
    check_blob_dependency()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError(
            "Authenticated private Blob transfer exceeded its deadline"
        )
    environment = os.environ.copy()
    environment["HYPERV_PREFLIGHT_SAS"] = sas
    with run.tracked_private_json(
        "blob-request", request
    ) as request_path:
        process = subprocess.Popen(
            [
                sys.executable, str(BLOB_WORKER_PATH),
                "--request", str(request_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
        try:
            stdout, _ = process.communicate(
                timeout=remaining
            )
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError(
                "Authenticated private Blob transfer exceeded its deadline"
            ) from None
        except BaseException:
            process.kill()
            process.wait()
            raise
    if time.monotonic() >= deadline:
        raise RuntimeError(
            "Authenticated private Blob transfer exceeded its deadline"
        )
    if process.returncode or len(stdout) > MAX_MANIFEST_BYTES:
        raise RuntimeError("Authenticated private Blob transfer failed")
    result = azure.parse_strict_json(stdout, "Private Blob worker result")
    result = exact_fields(
        result, ("schema", "result", "bytes"), "Private Blob worker result"
    )
    if (
        type(result["schema"]) is not int
        or result["schema"] != 1
        or result["result"] != "PASS"
        or type(result["bytes"]) is not int
        or result["bytes"] < 0
    ):
        raise RuntimeError("Authenticated private Blob transfer failed")
    return result["bytes"]


def upload_blob_set(
    run, account_url, sas, container, files, *, create_container, deadline
):
    records = []
    expected = 0
    for blob_name, source, expected_size, expected_sha256 in files:
        records.append({
            "blob": blob_name,
            "path": str(source),
            "size": expected_size,
            "sha256": expected_sha256,
        })
        expected += expected_size
    transferred = run_blob_worker(
        run,
        {
            "schema": "unikraft.hyperv.private-preflight-blob-worker",
            "schema_version": 1,
            "action": "upload",
            "account_url": account_url,
            "container": container,
            "files": records,
            "create_container": create_container,
        },
        sas,
        deadline,
    )
    if transferred != expected:
        raise RuntimeError("Private Blob upload byte count is inconsistent")
    return transferred


def download_blob_set(
    run, account_url, sas, container, files, deadline
):
    directory = run.state_path.parent / (
        ".blob-download-" + secrets.token_hex(8)
    )
    directory.mkdir(mode=0o700)
    records = []
    try:
        for index, (blob_name, maximum) in enumerate(files):
            records.append({
                "blob": blob_name,
                "path": str(directory / f"{index:03d}.bin"),
                "maximum": maximum,
            })
        transferred = run_blob_worker(
            run,
            {
                "schema": "unikraft.hyperv.private-preflight-blob-worker",
                "schema_version": 1,
                "action": "download",
                "account_url": account_url,
                "container": container,
                "files": records,
                "create_container": False,
            },
            sas,
            deadline,
        )
        values = [
            azure.read_regular_file(
                directory / f"{index:03d}.bin",
                maximum,
                "Private Blob evidence",
            )
            for index, (_, maximum) in enumerate(files)
        ]
        if sum(map(len, values)) != transferred:
            raise RuntimeError(
                "Private Blob download byte count is inconsistent"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Authenticated private Blob transfer exceeded its deadline"
            )
        return values
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def save_private_bytes(path, value):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


class PrivatePreflightRun(azure.AzureRun):
    def __init__(self, state, state_path):
        super().__init__(state, state_path)
        self.host_vm = self.prefix + "-host"
        self.host_disk = self.prefix + "-host-os"
        self.host_nic = self.prefix + "-host-nic"
        self.storage = state["storage_account"]
        self.container = CONTAINER
        self.deadline = state.get("deadline_monotonic")
        self.cleanup_deadline = None
        self.group_tags.update({
            "purpose": PURPOSE,
            "disposable": "true",
            "private-manifest-sha256": state["manifest_sha256"],
        })

    def account_bytes(self, category, amount):
        if type(amount) is not int or amount < 0:
            raise ValueError("Private-preflight byte accounting is invalid")
        field = {
            "input": "staged_input_bytes",
            "control": "control_payload_bytes",
            "evidence": "evidence_bytes",
        }.get(category)
        if field is None:
            raise ValueError("Private-preflight byte category is invalid")
        updated = self.state[field] + amount
        if category == "control" and updated > MAX_CONTROL_BYTES:
            raise RuntimeError(
                "Private-preflight control payload exceeds its allowance"
            )
        if category == "evidence" and updated > MAX_EVIDENCE_BYTES:
            raise RuntimeError(
                "Private-preflight evidence exceeds its allowance"
            )
        if (
            category == "input"
            and updated
            > self.state["input_manifest"]["budget"]["remote_input_bytes"]
        ):
            raise RuntimeError(
                "Private-preflight staged inputs exceed their manifest"
            )
        total = (
            (
                updated if category == "input"
                else self.state["staged_input_bytes"]
            )
            + self.state["input_manifest"]["budget"][
                "firmware_working_copy_bytes"
            ]
            + (
                updated if category == "control"
                else self.state["control_payload_bytes"]
            )
            + (
                updated if category == "evidence"
                else self.state["evidence_bytes"]
            )
        )
        if total > MAX_TOTAL_BYTES:
            raise RuntimeError(
                "Private-preflight cumulative byte budget exceeds 256 MiB"
            )
        self.record("accounted-" + category, **{field: updated})

    @contextmanager
    def tracked_private_json(self, kind, value):
        if kind not in (
            "blob-request", "deployment-parameters", "run-command"
        ):
            raise ValueError("Private parameter-file kind is invalid")
        name = "." + kind + "-" + secrets.token_hex(8) + ".json"
        pending = list(self.state["pending_secret_files"])
        pending.append(name)
        self.record(
            "private-parameter-file-pending",
            pending_secret_files=pending,
        )
        path = self.state_path.parent / name
        save_private_bytes(path, azure.canonical_json(value))
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)
            azure.fsync_directory(path.parent)
            pending = [
                item for item in self.state["pending_secret_files"]
                if item != name
            ]
            self.record(
                "private-parameter-file-cleared",
                pending_secret_files=pending,
            )

    @contextmanager
    def private_parameters(self, values):
        document = {
            "$schema": (
                "https://schema.management.azure.com/schemas/"
                "2019-04-01/deploymentParameters.json#"
            ),
            "contentVersion": "1.0.0.0",
            "parameters": {
                key: {"value": value} for key, value in values.items()
            },
        }
        with self.tracked_private_json(
            "deployment-parameters", document
        ) as path:
            yield path

    def clear_private_files(self):
        pending = list(self.state.get("pending_secret_files", []))
        for name in pending:
            if not re.fullmatch(
                r"\.(?:blob-request|deployment-parameters|run-command)-"
                r"[0-9a-f]{16}\.json",
                name,
            ):
                raise RuntimeError(
                    "Private parameter-file obligation is invalid"
                )
            path = self.state_path.parent / name
            try:
                path.unlink(missing_ok=True)
            except OSError:
                raise RuntimeError(
                    "Private parameter-file cleanup failed"
                ) from None
        for path in self.state_path.parent.glob(".azure-state-*"):
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise RuntimeError(
                    "Private state temporary-file cleanup failed"
                )
            path.unlink()
        azure.fsync_directory(self.state_path.parent)
        self.record(
            "private-parameter-files-cleared", pending_secret_files=[]
        )

    def phase_timeout(self, maximum):
        return bounded_timeout(self.state["deadline_monotonic"], maximum)

    def operation_timeout(self, maximum, deadline=None):
        if deadline is None:
            deadline = (
                self.cleanup_deadline
                if self.cleanup_deadline is not None
                else self.state["deadline_monotonic"]
            )
        return bounded_timeout(deadline, maximum)

    def az(self, arguments, **kwargs):
        kwargs.setdefault("private", True)
        if self.cleanup_deadline is not None:
            kwargs["timeout"] = self.operation_timeout(
                kwargs.get("timeout", TRANSFER_TIMEOUT_SECONDS)
            )
        return azure.azure_cli(
            arguments, subscription=self.state["subscription"], **kwargs
        )

    def expected_resource_id(self, provider, resource_type, name):
        group_id = self.state.get("resource_group_id")
        if not isinstance(group_id, str):
            raise RuntimeError("Private resource-group identity is unavailable")
        return (
            group_id.rstrip("/") + f"/providers/{provider}/"
            f"{resource_type}/{name}"
        )

    def operation_tags(self):
        receipt = self.state.get("host_deployment")
        operation_id = (
            receipt.get("operation_id")
            if isinstance(receipt, dict) else None
        )
        if not isinstance(operation_id, str):
            raise RuntimeError("Private host operation identity is unavailable")
        return {**self.tags, "preflight-operation": operation_id}

    def require_operation_owned(self, resource):
        tags = resource.get("tags") or {}
        if any(
            tags.get(key) != value
            for key, value in self.operation_tags().items()
        ):
            raise RuntimeError(
                "Private host resource lacks operation ownership"
            )

    def expected_host_ids(self):
        return {
            "deployment_id": self.expected_resource_id(
                "Microsoft.Resources", "deployments", self.prefix + "-host"
            ),
            "vm_id": self.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", self.host_vm
            ),
            "disk_id": self.expected_resource_id(
                "Microsoft.Compute", "disks", self.host_disk
            ),
            "nic_id": self.expected_resource_id(
                "Microsoft.Network", "networkInterfaces", self.host_nic
            ),
            "nsg_id": self.expected_resource_id(
                "Microsoft.Network", "networkSecurityGroups",
                self.prefix + "-nsg",
            ),
            "vnet_id": self.expected_resource_id(
                "Microsoft.Network", "virtualNetworks",
                self.prefix + "-vnet",
            ),
            "storage_id": self.expected_resource_id(
                "Microsoft.Storage", "storageAccounts", self.storage
            ),
            "schedule_id": self.expected_resource_id(
                "Microsoft.DevTestLab", "schedules",
                "shutdown-computevm-" + self.host_vm,
            ),
        }

    def begin_host_deployment(self, shutdown_time):
        ids = self.expected_host_ids()
        receipt = {
            "phase": "pending",
            "operation_id": str(uuid.uuid4()),
            "deployment_id": ids["deployment_id"],
            "correlation_id": None,
            "vm_id": ids["vm_id"],
            "vm_uuid": None,
            "disk_id": ids["disk_id"],
            "disk_uuid": None,
            "shutdown_time": shutdown_time,
        }
        self.record(
            "host-deployment-pending",
            host_deployment=receipt,
            host_deallocated=False,
        )
        return receipt

    def validate_deployment_identity(self, deployment):
        receipt = self.state["host_deployment"]
        properties = (
            deployment.get("properties")
            if isinstance(deployment, dict) else None
        )
        parameters = (
            properties.get("parameters")
            if isinstance(properties, dict) else None
        )
        expected_parameters = {
            "namePrefix": self.prefix,
            "location": LOCATION,
            "imageSha256": self.state["image_sha256"],
            "storageAccountName": self.storage,
            "hostImageVersion": self.state["cloud_preflight"]["image"][
                "version"
            ],
            "operationId": receipt["operation_id"],
            "shutdownTime": receipt["shutdown_time"],
        }
        if (
            deployment.get("name") != self.prefix + "-host"
            or str(deployment.get("id", "")).lower()
            != receipt["deployment_id"].lower()
            or not isinstance(properties, dict)
            or not isinstance(parameters, dict)
            or any(
                not isinstance(parameters.get(name), dict)
                or parameters[name].get("value") != value
                for name, value in expected_parameters.items()
            )
        ):
            raise RuntimeError("Private host deployment provenance is invalid")
        return properties

    def validate_deployment_result(self, deployment):
        receipt = self.state["host_deployment"]
        properties = self.validate_deployment_identity(deployment)
        if properties.get("provisioningState") != "Succeeded":
            raise RuntimeError("Private host deployment did not succeed")
        correlation = self.require_resource_uuid(
            properties.get("correlationId"),
            "Private host deployment correlation",
        )
        if receipt.get("correlation_id") not in (None, correlation):
            raise RuntimeError(
                "Private host deployment correlation changed"
            )
        outputs = properties.get("outputs")
        if not isinstance(outputs, dict) or set(outputs) != {
            "hostVmUuid", "hostDiskUuid",
        }:
            raise RuntimeError(
                "Private host deployment identity outputs are invalid"
            )
        identities = {}
        for output, field, label in (
            ("hostVmUuid", "vm_uuid", "Private host VM identity"),
            ("hostDiskUuid", "disk_uuid", "Private host disk identity"),
        ):
            value = outputs.get(output)
            if (
                not isinstance(value, dict)
                or set(value) != {"type", "value"}
                or value.get("type") != "String"
            ):
                raise RuntimeError(
                    "Private host deployment identity outputs are invalid"
                )
            identities[field] = self.require_resource_uuid(
                value.get("value"), label
            )
            if receipt.get(field) not in (None, identities[field]):
                raise RuntimeError(
                    "Private host deployment identity anchor changed"
                )
        receipt = {
            **receipt,
            "phase": "deployment-succeeded",
            "correlation_id": correlation,
            **identities,
        }
        self.record(
            "host-deployment-succeeded", host_deployment=receipt
        )
        return receipt

    def capture_host_identity(self, deadline=None):
        receipt = self.state["host_deployment"]
        if (
            receipt.get("phase") not in (
                "deployment-succeeded", "deployment-terminal",
                "vm-verified",
                "resources-verified",
            )
            or receipt.get("correlation_id") is None
            or receipt.get("vm_uuid") is None
            or receipt.get("disk_uuid") is None
        ):
            raise RuntimeError(
                "Private host deployment identities are not anchored"
            )
        vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.host_vm,
        ], timeout=self.operation_timeout(
            TRANSFER_TIMEOUT_SECONDS, deadline
        ))
        self.require_operation_owned(vm)
        expected_vm = receipt["vm_id"]
        expected_disk = receipt["disk_id"]
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            str(vm.get("id", "")).lower() != expected_vm.lower()
            or str(attached or "").lower() != expected_disk.lower()
        ):
            raise RuntimeError("Private host VM provenance is invalid")
        vm_uuid = self.require_resource_uuid(
            vm.get("vmId"), "Private host VM identity"
        )
        if receipt["vm_uuid"] != vm_uuid:
            raise RuntimeError("Private host VM identity changed")
        receipt = {
            **receipt,
            "phase": "vm-verified",
        }
        self.record("host-vm-verified", host_deployment=receipt)
        self.verify_vm_identity()
        disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", self.host_disk,
        ], timeout=self.operation_timeout(
            TRANSFER_TIMEOUT_SECONDS, deadline
        ))
        if (
            str(disk.get("id", "")).lower() != expected_disk.lower()
            or str(disk.get("managedBy") or "").lower()
            != expected_vm.lower()
        ):
            raise RuntimeError("Private host disk provenance is invalid")
        disk_uuid = self.require_resource_uuid(
            disk.get("uniqueId"), "Private host disk identity"
        )
        if receipt["disk_uuid"] != disk_uuid:
            raise RuntimeError("Private host disk identity changed")
        receipt = {**receipt, "phase": "resources-verified"}
        self.record("host-resources-verified", host_deployment=receipt)
        settling_deadline = min(
            (
                deadline if deadline is not None
                else self.state["deadline_monotonic"]
            ),
            time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
        )
        self.settle_host_identity(settling_deadline)
        return receipt

    def verify_vm_identity(self, vm=None, require_attachment=True):
        receipt = self.state.get("host_deployment")
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") not in (
                "deployment-succeeded", "deployment-terminal",
                "vm-verified", "resources-verified",
            )
            or receipt.get("vm_uuid") is None
            or receipt.get("disk_uuid") is None
        ):
            raise RuntimeError("Private host VM identity is unproven")
        if vm is None:
            vm = self.az([
                "vm", "show", "--resource-group", self.group,
                "--name", self.host_vm,
            ])
        self.require_operation_owned(vm)
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            str(vm.get("id", "")).lower() != receipt["vm_id"].lower()
            or vm.get("vmId") != receipt["vm_uuid"]
            or (
                require_attachment
                and str(attached or "").lower()
                != receipt["disk_id"].lower()
            )
        ):
            raise RuntimeError("Private host VM identity changed")
        return vm

    def verify_host_identity(self, vm=None, disk=None):
        receipt = self.state.get("host_deployment")
        required = {
            "phase", "operation_id", "deployment_id", "correlation_id",
            "vm_id", "vm_uuid", "disk_id", "disk_uuid", "shutdown_time",
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != required
            or receipt["phase"] != "resources-verified"
            or receipt["vm_uuid"] is None
            or receipt["disk_uuid"] is None
        ):
            raise RuntimeError("Private host VM/disk identity is unproven")
        if vm is None:
            vm = self.verify_vm_identity()
        else:
            self.verify_vm_identity(vm)
        if disk is None:
            disk = self.az([
                "disk", "show", "--resource-group", self.group,
                "--name", self.host_disk,
            ])
        self.require_operation_owned(disk)
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            str(vm.get("id", "")).lower() != receipt["vm_id"].lower()
            or vm.get("vmId") != receipt["vm_uuid"]
            or str(attached or "").lower() != receipt["disk_id"].lower()
            or str(disk.get("id", "")).lower()
            != receipt["disk_id"].lower()
            or disk.get("uniqueId") != receipt["disk_uuid"]
            or str(disk.get("managedBy") or "").lower()
            != receipt["vm_id"].lower()
        ):
            raise RuntimeError(
                "Private host VM/disk identity or attachment changed"
            )
        return vm, disk

    def settle_host_identity(self, deadline):
        while time.monotonic() < deadline:
            try:
                vm, disk = self.verify_host_identity()
                vm_state = vm.get("provisioningState")
                disk_state = disk.get("provisioningState")
                if (
                    vm_state in (None, "Succeeded")
                    and disk_state in (None, "Succeeded")
                ):
                    return vm, disk
                if vm_state in ("Failed", "Canceled") or disk_state in (
                    "Failed", "Canceled",
                ):
                    raise RuntimeError(
                        "Private host provisioning reached a terminal state"
                    )
            except RuntimeError:
                pass
            if deadline - time.monotonic() > 1:
                time.sleep(min(2, deadline - time.monotonic()))
        raise RuntimeError(
            "Private host identity or metadata did not settle"
        ) from None

    def reconcile_host_deployment(self, deadline):
        receipt = self.state.get("host_deployment")
        if not isinstance(receipt, dict) or receipt.get("phase") not in (
            "pending", "deployment-succeeded", "resources-verified",
            "deployment-terminal", "vm-verified", "failed-no-compute",
            "not-created-empty",
        ):
            raise RuntimeError("Private host deployment obligation is invalid")
        if receipt["phase"] == "resources-verified":
            self.settle_host_identity(deadline)
            return True
        if receipt["phase"] == "vm-verified":
            self.capture_host_identity(deadline)
            return True
        if receipt["phase"] == "failed-no-compute":
            return False
        if receipt["phase"] == "not-created-empty":
            return False
        absent_empty = 0
        last_error = None
        while time.monotonic() < deadline:
            try:
                deployment = self.az([
                    "deployment", "group", "show",
                    "--resource-group", self.group,
                    "--name", self.prefix + "-host",
                ], timeout=max(
                    1, min(30, int(deadline - time.monotonic()))
                ))
                properties = (
                    deployment.get("properties")
                    if isinstance(deployment, dict) else None
                )
                self.validate_deployment_identity(deployment)
                provisioned = (
                    properties.get("provisioningState")
                    if isinstance(properties, dict) else None
                )
                if provisioned == "Succeeded":
                    self.validate_deployment_result(deployment)
                    self.capture_host_identity(deadline)
                    return True
                if provisioned in ("Failed", "Canceled"):
                    resources = self.az([
                        "resource", "list", "--resource-group", self.group,
                    ])
                    has_compute = any(
                        str(resource.get("type", "")).lower()
                        in (
                            "microsoft.compute/virtualmachines",
                            "microsoft.compute/disks",
                        )
                        for resource in resources
                    )
                    if has_compute:
                        correlation = self.require_resource_uuid(
                            properties.get("correlationId"),
                            "Private host deployment correlation",
                        )
                        terminal = {
                            **receipt,
                            "phase": "deployment-terminal",
                            "correlation_id": correlation,
                        }
                        self.record(
                            "host-deployment-terminal",
                            host_deployment=terminal,
                        )
                        raise RuntimeError(
                            "Terminal private host deployment left "
                            "unanchored compute resources"
                        )
                    failed = {**receipt, "phase": "failed-no-compute"}
                    self.record(
                        "host-deployment-failed-no-compute",
                        host_deployment=failed,
                    )
                    return False
            except (azure.AzureCliError, azure.AzureCliTimeout) as error:
                last_error = error
                if (
                    isinstance(error, azure.AzureCliError)
                    and error.code in (
                        "ResourceNotFound", "DeploymentNotFound"
                    )
                ):
                    resources = self.az([
                        "resource", "list", "--resource-group", self.group,
                    ])
                    if resources == []:
                        absent_empty += 1
                        if absent_empty >= 3:
                            absent = {
                                **receipt, "phase": "not-created-empty"
                            }
                            self.record(
                                "host-deployment-not-created",
                                host_deployment=absent,
                            )
                            return False
                    else:
                        raise RuntimeError(
                            "Missing deployment has unexpected resources"
                        )
            if deadline - time.monotonic() > 1:
                time.sleep(min(2, deadline - time.monotonic()))
        raise RuntimeError(
            "Private host deployment provenance could not be reconciled"
        ) from None

    def verify_deployed_envelope(self):
        receipt = self.state["host_deployment"]
        vm, disk = self.settle_host_identity(min(
            self.state["deadline_monotonic"],
            time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
        ))
        image = self.state["cloud_preflight"]["image"]
        storage_profile = vm.get("storageProfile", {})
        os_disk = storage_profile.get("osDisk", {})
        image_reference = storage_profile.get("imageReference", {})
        interfaces = vm.get("networkProfile", {}).get("networkInterfaces")
        security = vm.get("securityProfile")
        ids = self.expected_host_ids()
        if (
            vm.get("provisioningState") != "Succeeded"
            or vm.get("location") != LOCATION
            or vm.get("hardwareProfile", {}).get("vmSize") != VM_SIZE
            or security != {"securityType": "Standard"}
            or storage_profile.get("dataDisks") != []
            or os_disk.get("diskSizeGb") != 32
            or os_disk.get("createOption") != "FromImage"
            or os_disk.get("caching") != "ReadWrite"
            or os_disk.get("deleteOption") != "Delete"
            or any(
                image_reference.get(key) != image[key]
                for key in ("publisher", "offer", "sku", "version")
            )
            or not isinstance(interfaces, list)
            or len(interfaces) != 1
            or str(interfaces[0].get("id", "")).lower()
            != ids["nic_id"].lower()
            or interfaces[0].get("primary") is not True
            or interfaces[0].get("deleteOption") != "Delete"
            or disk.get("diskSizeGb") != 32
            or disk.get("location") != LOCATION
            or disk.get("sku", {}).get("name") != "StandardSSD_LRS"
            or disk.get("osType") != "Linux"
            or disk.get("hyperVGeneration") != "V2"
        ):
            raise RuntimeError("Private preflight host envelope is incompatible")
        nic = self.az([
            "network", "nic", "show", "--resource-group", self.group,
            "--name", self.host_nic,
        ])
        self.require_operation_owned(nic)
        configurations = nic.get("ipConfigurations")
        subnet_id = (
            ids["vnet_id"] + "/subnets/preflight"
        )
        if (
            str(nic.get("id", "")).lower() != ids["nic_id"].lower()
            or nic.get("location") != LOCATION
            or nic.get("enableAcceleratedNetworking") is not False
            or nic.get("enableIPForwarding") is not False
            or nic.get("networkSecurityGroup") is not None
            or not isinstance(configurations, list)
            or len(configurations) != 1
            or configurations[0].get("name") != "private"
            or configurations[0].get("primary") is not True
            or configurations[0].get("privateIPAddressVersion") != "IPv4"
            or configurations[0].get("publicIPAddress") is not None
            or configurations[0].get("privateIPAllocationMethod") != "Static"
            or configurations[0].get("privateIPAddress") != "10.88.0.4"
            or str(
                configurations[0].get("subnet", {}).get("id", "")
            ).lower() != subnet_id.lower()
        ):
            raise RuntimeError("Private preflight NIC envelope is incompatible")
        nsg = self.az([
            "network", "nsg", "show", "--resource-group", self.group,
            "--name", self.prefix + "-nsg",
        ])
        self.require_operation_owned(nsg)
        expected_rules = {
            "AllowAzurePlatformDns": (
                100, "Allow", "Outbound", "Udp", "53",
                "VirtualNetwork", "AzurePlatformDNS",
            ),
            "AllowAzurePlatformImds": (
                110, "Allow", "Outbound", "Tcp", "80",
                "VirtualNetwork", "AzurePlatformIMDS",
            ),
            "AllowAzurePlatformAgent": (
                120, "Allow", "Outbound", "Tcp", ("80", "32526"),
                "VirtualNetwork", "168.63.129.16",
            ),
            "AllowRegionalStorage": (
                130, "Allow", "Outbound", "Tcp", "443",
                "VirtualNetwork", "Storage.NorthEurope",
            ),
            "DenyAllInbound": (
                4095, "Deny", "Inbound", "*", "*", "*", "*",
            ),
            "DenyAllOutbound": (
                4096, "Deny", "Outbound", "*", "*", "*", "*",
            ),
        }
        rules = nsg.get("securityRules")
        if (
            str(nsg.get("id", "")).lower() != ids["nsg_id"].lower()
            or nsg.get("location") != LOCATION
            or not isinstance(rules, list)
            or {rule.get("name") for rule in rules} != set(expected_rules)
        ):
            raise RuntimeError("Private preflight NSG envelope is incompatible")
        for rule in rules:
            expected = expected_rules[rule["name"]]
            destination_ports = (
                tuple(rule.get("destinationPortRanges", ()))
                if expected[4] == ("80", "32526")
                else rule.get("destinationPortRange")
            )
            if (
                (
                    rule.get("priority"), rule.get("access"),
                    rule.get("direction"), rule.get("protocol"),
                    destination_ports, rule.get("sourceAddressPrefix"),
                    rule.get("destinationAddressPrefix"),
                ) != expected
                or rule.get("sourcePortRange") != "*"
                or rule.get("sourcePortRanges") not in (None, [])
                or (
                    expected[4] != ("80", "32526")
                    and rule.get("destinationPortRanges") not in (None, [])
                )
                or rule.get("sourceAddressPrefixes") not in (None, [])
                or rule.get("destinationAddressPrefixes") not in (None, [])
            ):
                raise RuntimeError(
                    "Private preflight NSG rule set is incompatible"
                )
        vnet = self.az([
            "network", "vnet", "show", "--resource-group", self.group,
            "--name", self.prefix + "-vnet",
        ])
        self.require_operation_owned(vnet)
        if (
            str(vnet.get("id", "")).lower() != ids["vnet_id"].lower()
            or vnet.get("location") != LOCATION
            or vnet.get("addressSpace", {}).get("addressPrefixes")
            != ["10.88.0.0/29"]
            or vnet.get("virtualNetworkPeerings") not in (None, [])
            or vnet.get("enableDdosProtection") not in (None, False)
            or not isinstance(vnet.get("subnets"), list)
            or len(vnet["subnets"]) != 1
        ):
            raise RuntimeError("Private preflight VNet envelope is incompatible")
        subnet = self.az([
            "network", "vnet", "subnet", "show",
            "--resource-group", self.group,
            "--vnet-name", self.prefix + "-vnet",
            "--name", "preflight",
        ])
        endpoints = subnet.get("serviceEndpoints")
        if (
            str(subnet.get("id", "")).lower() != subnet_id.lower()
            or subnet.get("addressPrefix") != "10.88.0.0/29"
            or subnet.get("defaultOutboundAccess") is not False
            or subnet.get("natGateway") is not None
            or subnet.get("publicIpAddressPool") is not None
            or subnet.get("ipAllocations") not in (None, [])
            or subnet.get("delegations") not in (None, [])
            or subnet.get("routeTable") is not None
            or subnet.get("applicationGatewayIPConfigurations")
            not in (None, [])
            or subnet.get("serviceEndpointPolicies") not in (None, [])
            or str(
                subnet.get("networkSecurityGroup", {}).get("id", "")
            ).lower() != ids["nsg_id"].lower()
            or not isinstance(endpoints, list)
            or len(endpoints) != 1
            or endpoints[0].get("service") != "Microsoft.Storage"
            or endpoints[0].get("locations") != ["northeurope"]
            or endpoints[0].get("provisioningState")
            not in (None, "Succeeded")
        ):
            raise RuntimeError("Private preflight subnet envelope is incompatible")
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ])
        self.require_operation_owned(storage)
        rules = storage.get("networkRuleSet", {})
        if (
            str(storage.get("id", "")).lower() != ids["storage_id"].lower()
            or storage.get("location") != LOCATION
            or storage.get("kind") != "StorageV2"
            or storage.get("sku", {}).get("name") != "Standard_LRS"
            or storage.get("allowBlobPublicAccess") is not False
            or storage.get("allowSharedKeyAccess") is not True
            or storage.get("defaultToOAuthAuthentication") is not False
            or storage.get("minimumTlsVersion") != "TLS1_2"
            or storage.get("publicNetworkAccess") != "Enabled"
            or storage.get("supportsHttpsTrafficOnly") is not True
            or storage.get("privateEndpointConnections") not in (None, [])
            or rules.get("resourceAccessRules") not in (None, [])
        ):
            raise RuntimeError("Private preflight storage envelope is incompatible")
        self.verify_storage_rules()
        schedule = self.az([
            "resource", "show", "--resource-group", self.group,
            "--resource-type", "Microsoft.DevTestLab/schedules",
            "--name", "shutdown-computevm-" + self.host_vm,
            "--api-version", "2018-09-15",
        ])
        self.require_operation_owned(schedule)
        properties = schedule.get("properties", {})
        if (
            properties.get("status") != "Enabled"
            or str(schedule.get("id", "")).lower()
            != ids["schedule_id"].lower()
            or schedule.get("location") != LOCATION
            or properties.get("taskType") != "ComputeVmShutdownTask"
            or str(properties.get("targetResourceId", "")).lower()
            != receipt["vm_id"].lower()
            or properties.get("dailyRecurrence", {}).get("time")
            != receipt["shutdown_time"]
            or properties.get("timeZoneId") != "UTC"
        ):
            raise RuntimeError("Private host auto-shutdown backstop is invalid")
        self.verify_resource_inventory()
        self.record(
            "host-created",
            host_vm_id=receipt["vm_id"],
            host_disk_id=receipt["disk_id"],
            host_nic_id=ids["nic_id"],
            storage_account_id=ids["storage_id"],
            shutdown_schedule_id=schedule["id"],
        )

    def verify_resource_inventory(self):
        resources = self.az([
            "resource", "list", "--resource-group", self.group,
        ])
        if not isinstance(resources, list):
            raise RuntimeError("Azure returned an invalid resource inventory")
        expected = {
            ("microsoft.network/networksecuritygroups", self.prefix + "-nsg"),
            ("microsoft.network/virtualnetworks", self.prefix + "-vnet"),
            ("microsoft.storage/storageaccounts", self.storage),
            ("microsoft.network/networkinterfaces", self.host_nic),
            ("microsoft.compute/virtualmachines", self.host_vm),
            ("microsoft.compute/disks", self.host_disk),
            (
                "microsoft.devtestlab/schedules",
                "shutdown-computevm-" + self.host_vm,
            ),
        }
        actual = {
            (str(resource.get("type", "")).lower(), resource.get("name"))
            for resource in resources
        }
        if actual != expected:
            raise RuntimeError(
                "Private preflight resource inventory is not exact"
            )
        for resource in resources:
            key = (str(resource.get("type", "")).lower(), resource.get("name"))
            if key == (
                "microsoft.compute/disks", self.host_disk
            ):
                self.verify_host_identity()
            else:
                self.require_operation_owned(resource)

    def deploy_host(self, shutdown_time):
        receipt = self.begin_host_deployment(shutdown_time)
        password = "Uk!" + secrets.token_urlsafe(32) + "a7"
        image = self.state["cloud_preflight"]["image"]
        parameters = {
            "namePrefix": self.prefix,
            "location": LOCATION,
            "imageSha256": self.state["image_sha256"],
            "storageAccountName": self.storage,
            "hostImageVersion": image["version"],
            "operationId": receipt["operation_id"],
            "adminPassword": password,
            "shutdownTime": shutdown_time,
        }
        try:
            with self.private_parameters(parameters) as parameter_file:
                deployment = self.az([
                    "deployment", "group", "create",
                    "--resource-group", self.group,
                    "--name", self.prefix + "-host", "--mode", "Incremental",
                    "--template-file", str(TEMPLATE_PATH),
                    "--parameters", "@" + str(parameter_file),
                ], timeout=self.phase_timeout(900))
            self.validate_deployment_result(deployment)
            self.capture_host_identity(self.state["deadline_monotonic"])
        except (RuntimeError, ValueError, OSError):
            reconcile_deadline = min(
                self.deadline,
                time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
            )
            if not self.reconcile_host_deployment(reconcile_deadline):
                raise RuntimeError(
                    "Private host deployment did not create compute resources"
                ) from None
        finally:
            password = None
        self.verify_deployed_envelope()

    def verify_storage_rules(self, transfer_cidr=None, *, enforce_deadline=True):
        timeout = (
            self.phase_timeout(TRANSFER_TIMEOUT_SECONDS)
            if enforce_deadline else TRANSFER_TIMEOUT_SECONDS
        )
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ], timeout=timeout)
        self.require_owned(storage)
        rules = storage.get("networkRuleSet")
        if (
            not isinstance(rules, dict)
            or rules.get("defaultAction") != "Deny"
            or rules.get("bypass") != "None"
            or rules.get("resourceAccessRules") not in (None, [])
        ):
            raise RuntimeError("Private Blob firewall is invalid")
        ip_rules = rules.get("ipRules")
        if not isinstance(ip_rules, list):
            raise RuntimeError("Private Blob firewall IP rules are invalid")
        values = {
            item.get("ipAddressOrRange")
            for item in ip_rules if isinstance(item, dict)
        }
        expected = set() if transfer_cidr is None else {transfer_cidr}
        if (
            values != expected
            or len(ip_rules) != len(expected)
            or any(
                set(item) - {"ipAddressOrRange", "action"}
                or item.get("action") not in (None, "Allow")
                for item in ip_rules
                if isinstance(item, dict)
            )
        ):
            raise RuntimeError("Private Blob transfer firewall is not exact")
        expected_subnet = (
            self.state["resource_group_id"].rstrip("/")
            + "/providers/Microsoft.Network/virtualNetworks/"
            + self.prefix + "-vnet/subnets/preflight"
        )
        subnet_rules = rules.get("virtualNetworkRules")
        if (
            not isinstance(subnet_rules, list)
            or len(subnet_rules) != 1
            or not isinstance(subnet_rules[0], dict)
            or str(
                subnet_rules[0].get("virtualNetworkResourceId", "")
            ).lower() != expected_subnet.lower()
            or subnet_rules[0].get("action") != "Allow"
            or subnet_rules[0].get("state") not in (None, "Succeeded")
        ):
            raise RuntimeError("Private Blob subnet rule is not exact")

    @contextmanager
    def transfer_access(self, transfer_cidr):
        if self.state.get("firewall_obligation") is not None:
            raise RuntimeError(
                "An unresolved private Blob firewall obligation exists"
            )
        obligation = {"cidr": transfer_cidr, "phase": "pending-add"}
        self.record(
            "blob-firewall-add-pending",
            firewall_obligation=obligation,
        )
        try:
            self.az([
                "storage", "account", "network-rule", "add",
                "--resource-group", self.group,
                "--account-name", self.storage,
                "--ip-address", transfer_cidr,
            ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
            self.verify_storage_rules(transfer_cidr)
            obligation = {"cidr": transfer_cidr, "phase": "active"}
            self.record(
                "blob-firewall-active",
                firewall_obligation=obligation,
            )
            yield
        finally:
            self.record(
                "blob-firewall-remove-pending",
                firewall_obligation={
                    "cidr": transfer_cidr, "phase": "pending-remove"
                },
            )
            self.clear_firewall_obligation()

    def clear_firewall_obligation(self):
        obligation = self.state.get("firewall_obligation")
        if obligation is None:
            return
        if (
            not isinstance(obligation, dict)
            or set(obligation) != {"cidr", "phase"}
            or obligation["phase"] not in (
                "pending-add", "active", "pending-remove"
            )
        ):
            raise RuntimeError("Private Blob firewall obligation is invalid")
        try:
            network = ipaddress.ip_network(obligation["cidr"], strict=True)
        except ValueError:
            raise RuntimeError("Private Blob firewall CIDR is invalid") from None
        if network.version != 4 or network.prefixlen != 32:
            raise RuntimeError("Private Blob firewall CIDR is invalid")
        cidr = str(network)
        self.record(
            "blob-firewall-remove-pending",
            firewall_obligation={"cidr": cidr, "phase": "pending-remove"},
        )
        if self.az(["group", "exists", "--name", self.group]) is False:
            self.record(
                "blob-firewall-absent", firewall_obligation=None
            )
            return
        group = self.az(["group", "show", "--name", self.group])
        self.require_owned_group(group)
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ])
        self.require_operation_owned(storage)
        self.az([
            "storage", "account", "network-rule", "remove",
            "--resource-group", self.group,
            "--account-name", self.storage,
            "--ip-address", cidr,
        ])
        self.verify_storage_rules(enforce_deadline=False)
        self.record("blob-firewall-cleared", firewall_obligation=None)

    def generate_sas(self):
        keys = self.az([
            "storage", "account", "keys", "list",
            "--resource-group", self.group, "--account-name", self.storage,
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        primary = next((
            item.get("value") for item in keys
            if isinstance(item, dict)
            and item.get("keyName") == "key1"
            and isinstance(item.get("value"), str)
        ), None) if isinstance(keys, list) else None
        if not primary:
            raise RuntimeError("Private Blob signing key is unavailable")
        signing_key_sha256 = hashlib.sha256(primary.encode()).hexdigest()
        self.record(
            "issuing-sas", active_sas=True,
            active_sas_signing_key_sha256=signing_key_sha256,
        )
        expiry = datetime.now(timezone.utc) + timedelta(
            seconds=self.phase_timeout(MAX_ATTEMPT_SECONDS)
        )
        sas = self.az([
            "storage", "account", "generate-sas",
            "--account-name", self.storage,
            "--services", "b", "--resource-types", "sco",
            "--permissions", "rcw",
            "--expiry", utc_text(expiry), "--https-only",
        ], env={"AZURE_STORAGE_KEY": primary},
           timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        if (
            not isinstance(sas, str)
            or not sas
            or len(sas.encode()) > MAX_BLOB_SAS_BYTES
            or any(character.isspace() for character in sas)
        ):
            raise RuntimeError("Azure did not return a bounded private Blob SAS")
        token = {
            "value": sas.lstrip("?"),
            "signing_key_sha256": signing_key_sha256,
        }
        primary = None
        self.record(
            "sas-issued", active_sas=True,
            active_sas_signing_key_sha256=token["signing_key_sha256"],
        )
        return token

    def revoke_sas(self, token):
        self.az([
            "storage", "account", "keys", "renew",
            "--resource-group", self.group, "--account-name", self.storage,
            "--key", "primary",
        ])
        keys = self.az([
            "storage", "account", "keys", "list",
            "--resource-group", self.group, "--account-name", self.storage,
        ])
        primary = next((
            item.get("value") for item in keys
            if isinstance(item, dict)
            and item.get("keyName") == "key1"
            and isinstance(item.get("value"), str)
        ), None) if isinstance(keys, list) else None
        if (
            not primary
            or hashlib.sha256(primary.encode()).hexdigest()
            == token["signing_key_sha256"]
        ):
            raise RuntimeError("Private Blob SAS revocation did not complete")
        self.record(
            "sas-revoked", active_sas=False,
            active_sas_signing_key_sha256=None,
        )

    @contextmanager
    def private_request(self, value):
        with self.tracked_private_json("run-command", value) as path:
            yield path

    def run_host_phase(self, phase, manifest, sas):
        runner_source = azure.read_regular_file(
            RUNNER_PATH, 1024 * 1024, "Private-preflight host runner"
        )
        manifest_bytes = azure.canonical_json(manifest)
        script = "\n".join((
            "set -eu",
            "umask 077",
            "command -v python3 >/dev/null",
            "command -v base64 >/dev/null",
            "command -v timeout >/dev/null",
            "root=/var/lib/unikraft-private-preflight",
            "mkdir -p \"$root\"",
            (
                "printf '%s' "
                + shlex.quote(base64.b64encode(runner_source).decode())
                + " | base64 -d > \"$root/runner.py\""
            ),
            (
                "test \"$#\" -eq 1; "
                "HYPERV_PREFLIGHT_SAS=\"$1\""
                + " timeout --signal=KILL "
                + str(self.phase_timeout(900)) + "s"
                + " python3 \"$root/runner.py\""
                + " --phase " + shlex.quote(phase)
                + " --manifest-b64 "
                + shlex.quote(base64.b64encode(manifest_bytes).decode())
                + " --blob-base-url "
                + shlex.quote(f"https://{self.storage}.blob.core.windows.net")
                + " --container " + shlex.quote(self.container)
            ),
        ))
        request = {
            "commandId": "RunShellScript",
            "script": [script],
            "protectedParameters": [{"name": "sas", "value": sas}],
        }
        request_bytes = azure.canonical_json(request)
        self.account_bytes("control", len(request_bytes))
        url = (
            self.state["host_vm_id"]
            + "/runCommand?api-version=2024-11-01"
        )
        with self.private_request(request) as request_path:
            response = self.az([
                "rest", "--method", "post", "--url", url,
                "--body", "@" + str(request_path),
            ], timeout=self.phase_timeout(900))
        values = response.get("value") if isinstance(response, dict) else None
        if not isinstance(values, list):
            raise RuntimeError("Private RunCommand returned no bounded result")
        stdout = []
        output_bytes = 0
        for item in values:
            if not isinstance(item, dict):
                raise RuntimeError("Private RunCommand result is malformed")
            code = item.get("code")
            message = item.get("message")
            if not isinstance(code, str) or not isinstance(message, str):
                raise RuntimeError("Private RunCommand result is malformed")
            output_bytes += len(message.encode("utf-8"))
            if output_bytes > MAX_MANIFEST_BYTES:
                raise RuntimeError("Private RunCommand result exceeds its size limit")
            if "/StdOut/" in code:
                stdout.append(message)
            elif "/StdErr/" in code and message.strip():
                raise RuntimeError("Private RunCommand reported a private-host failure")
        lines = [
            line.strip() for message in stdout for line in message.splitlines()
            if line.strip().startswith("HYPERV_PRIVATE_PREFLIGHT ")
        ]
        if len(lines) != 1:
            raise RuntimeError("Private RunCommand result is missing or duplicated")
        record = azure.parse_strict_json(
            lines[0].removeprefix("HYPERV_PRIVATE_PREFLIGHT ").encode("utf-8"),
            "Private RunCommand result",
        )
        record = exact_fields(
            record,
            (
                "schema", "phase", "result", "identity",
                "receipt_sha256", "boot_count",
            ),
            "Private RunCommand result",
        )
        expected_boots = 2 if phase == "capability" else 4
        if (
            type(record["schema"]) is not int
            or record["schema"] != 1
            or record["phase"] != phase
            or record["result"] != "PASS"
            or record["identity"] != self.state["identity"]
            or require_sha256(
                record["receipt_sha256"], "Host receipt fingerprint"
            ) != record["receipt_sha256"]
            or type(record["boot_count"]) is not int
            or record["boot_count"] != expected_boots
        ):
            raise RuntimeError("Private RunCommand did not prove its exact phase")
        self.record(
            phase + "-passed",
            **{phase + "_receipt_sha256": record["receipt_sha256"]},
        )
        return record

    def verified_host_disk_for_cleanup(self, resource):
        receipt = self.state.get("host_deployment")
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") != "resources-verified"
        ):
            raise RuntimeError("Refusing to clean an unproven host OS disk")
        if (
            str(resource.get("id", "")).lower()
            != receipt["disk_id"].lower()
            or resource.get("name") != self.host_disk
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/disks"
        ):
            raise RuntimeError("Refusing to clean an unproven host OS disk")
        self.require_operation_owned(resource)
        self.verify_host_identity()

    def require_owned_vm_child(self, resource):
        receipt = self.state.get("host_deployment")
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") != "resources-verified"
        ):
            raise RuntimeError(
                "Refusing to clean an unproven host extension child"
            )
        resource_id = str(resource.get("id", ""))
        expected_prefix = receipt["vm_id"].rstrip("/") + "/extensions/"
        child = resource_id[len(expected_prefix):]
        name = resource.get("name")
        if (
            not resource_id.lower().startswith(expected_prefix.lower())
            or not child
            or "/" in child
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/virtualmachines/extensions"
            or name not in (child, self.host_vm + "/" + child)
            or resource.get("location") not in (None, LOCATION)
        ):
            raise RuntimeError(
                "Refusing to clean an unproven host extension child"
            )

    def deallocate_host(self):
        if self.state.get("host_deallocated") is True:
            return
        receipt = self.state.get("host_deployment")
        if not isinstance(receipt, dict):
            return
        if receipt.get("phase") in ("pending", "deployment-terminal"):
            try:
                if not self.reconcile_host_deployment(
                    min(
                        self.cleanup_deadline
                        or self.state["deadline_monotonic"],
                        time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
                    )
                ):
                    return
            except (RuntimeError, ValueError, OSError):
                receipt = self.state.get("host_deployment")
                if (
                    not isinstance(receipt, dict)
                    or receipt.get("phase") not in (
                        "deployment-succeeded", "deployment-terminal",
                        "vm-verified", "resources-verified",
                    )
                    or receipt.get("correlation_id") is None
                    or receipt.get("vm_uuid") is None
                    or receipt.get("disk_uuid") is None
                ):
                    raise
            receipt = self.state["host_deployment"]
        if receipt.get("phase") in (
            "failed-no-compute", "not-created-empty"
        ):
            return
        self.verify_vm_identity(require_attachment=False)
        self.az([
            "vm", "deallocate", "--resource-group", self.group,
            "--name", self.host_vm,
        ], timeout=300)
        self.verify_vm_identity(require_attachment=False)
        view = self.az([
            "vm", "get-instance-view", "--resource-group", self.group,
            "--name", self.host_vm,
        ])
        statuses = view.get("instanceView", {}).get("statuses", [])
        if not any(
            isinstance(item, dict)
            and item.get("code") == "PowerState/deallocated"
            for item in statuses
        ):
            raise RuntimeError("Private host deallocation did not complete")
        self.record("host-deallocated", host_deallocated=True)

    def delete_owned_group(self):
        if self.az(["group", "exists", "--name", self.group]) is False:
            self.record("cleaned", cleanup_required=False)
            return
        group = self.az(["group", "show", "--name", self.group])
        self.require_owned_group(group)
        resources = self.az([
            "resource", "list", "--resource-group", self.group,
        ])
        if not isinstance(resources, list):
            raise RuntimeError("Azure returned an invalid resource inventory")
        receipt = self.state.get("host_deployment")
        if receipt is None:
            if resources:
                raise RuntimeError(
                    "Refusing to delete an unproven nonempty private group"
                )
        elif receipt.get("phase") == "resources-verified":
            self.verify_host_identity()
        elif receipt.get("phase") == "failed-no-compute":
            deployment = self.az([
                "deployment", "group", "show",
                "--resource-group", self.group,
                "--name", self.prefix + "-host",
            ])
            properties = self.validate_deployment_identity(deployment)
            if properties.get("provisioningState") not in (
                "Failed", "Canceled"
            ) or any(
                str(resource.get("type", "")).lower() in (
                    "microsoft.compute/virtualmachines",
                    "microsoft.compute/disks",
                )
                for resource in resources
            ):
                raise RuntimeError(
                    "Refusing to delete an ambiguously provisioned group"
                )
        elif receipt.get("phase") == "not-created-empty":
            if resources:
                raise RuntimeError(
                    "Refusing to delete a nonempty undeployed group"
                )
        else:
            raise RuntimeError(
                "Refusing to delete an unreconciled private host group"
            )
        for resource in resources:
            resource_type = str(resource.get("type", "")).lower()
            if resource_type == "microsoft.compute/disks":
                self.verified_host_disk_for_cleanup(resource)
            elif (
                resource_type
                == "microsoft.compute/virtualmachines/extensions"
            ):
                self.require_owned_vm_child(resource)
            else:
                self.require_operation_owned(resource)
        self.record("deleting-group")
        self.az([
            "group", "delete", "--name", self.group, "--yes",
        ], timeout=900)
        if self.az(["group", "exists", "--name", self.group]) is not False:
            raise RuntimeError("Private resource-group deletion did not complete")
        self.record("cleaned", cleanup_required=False)

    def cleanup(self):
        if self.cleanup_deadline is None:
            self.cleanup_deadline = (
                time.monotonic() + CLEANUP_TIMEOUT_SECONDS
            )
        errors = []
        try:
            self.clear_private_files()
        except (RuntimeError, ValueError, OSError) as error:
            errors.append(error)
        if self.state.get("firewall_obligation") is not None:
            try:
                self.clear_firewall_obligation()
            except (RuntimeError, ValueError, OSError) as error:
                errors.append(error)
        if self.state.get("active_sas") is True:
            fingerprint = self.state.get("active_sas_signing_key_sha256")
            try:
                self.revoke_sas({"signing_key_sha256": require_sha256(
                    fingerprint, "Active private Blob signing key"
                )})
            except (RuntimeError, ValueError, OSError) as error:
                errors.append(error)
        try:
            self.deallocate_host()
        except (RuntimeError, ValueError, OSError) as error:
            errors.append(error)
        try:
            self.delete_owned_group()
        except (RuntimeError, ValueError, OSError) as error:
            errors.append(error)
        if errors:
            raise RuntimeError(
                "Private preflight cleanup or deallocation did not complete"
            ) from None


def host_phase_manifest(state, phase, capability_sha256=None):
    input_manifest = state["input_manifest"]
    roles = PUBLIC_ROLES if phase == "capability" else (
        "qemu", "ovmf_code", "ovmf_vars", *PRIVATE_ROLES
    )
    files = {}
    for role in roles:
        record = input_manifest["files"][role]
        source_phase = "public" if role in PUBLIC_ROLES else "private"
        files[role] = {
            **record,
            "blob": (
                f"inputs/{state['identity']}/{source_phase}/{record['name']}"
            ),
        }
    result = {
        "schema": HOST_PHASE_SCHEMA,
        "schema_version": 2,
        "phase": phase,
        "identity": state["identity"],
        "runner_sha256": state["implementation"]["files"]["runner"][
            "sha256"
        ],
        "input_manifest_sha256": state["manifest_sha256"],
        "workload": WORKLOAD,
        "boot_policy": (
            "platform-unavailable-v1"
            if phase == "capability"
            else input_manifest["boot_policy"]
        ),
        "raw_size": input_manifest["raw_size"],
        "files": files,
        "qemu_support": [
            {
                "name": record["path"],
                "size": record["size"],
                "sha256": record["sha256"],
                "blob": (
                    f"inputs/{state['identity']}/public/{record['path']}"
                ),
            }
            for record in input_manifest["qemu_support"]
        ],
        "evidence_prefix": f"evidence/{state['identity']}/{phase}",
    }
    if phase == "private":
        result["capability_manifest_sha256"] = require_sha256(
            capability_sha256, "Capability manifest fingerprint"
        )
    host_runner.parse_manifest(
        base64.b64encode(azure.canonical_json(result)).decode(), phase
    )
    return result


def blob_files(state, state_directory, roles):
    result = []
    for role in roles:
        record = state["input_manifest"]["files"][role]
        phase = "public" if role in PUBLIC_ROLES else "private"
        result.append((
            f"inputs/{state['identity']}/{phase}/{record['name']}",
            state_directory / "inputs" / record["name"],
            record["size"], record["sha256"],
        ))
    if "qemu" in roles:
        known = {item[0] for item in result}
        for record in state["input_manifest"]["qemu_support"]:
            blob = f"inputs/{state['identity']}/public/{record['path']}"
            if blob not in known:
                result.append((
                    blob,
                    state_directory / "inputs" / record["path"],
                    record["size"], record["sha256"],
                ))
    return result


def validate_host_receipt(value, state, phase, manifest, logs):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "phase", "identity", "result",
            "manifest_sha256", "runner_sha256", "host_boot_id",
            "boot_policy", "boots",
        ),
        "Private host evidence receipt",
    )
    formats = ("capability",) if phase == "capability" else ("raw", "vhd")
    boots = exact_fields(
        value["boots"], formats, "Private host boot formats"
    )
    for image_format in formats:
        modes = exact_fields(
            boots[image_format], ("x2apic", "legacy-apic"),
            "Private host APIC modes",
        )
        for mode in ("x2apic", "legacy-apic"):
            outcome = exact_fields(
                modes[mode], ("result", "log_sha256", "return_code"),
                "Private host boot outcome",
            )
            log_name = f"{image_format}-{mode}.log"
            if (
                outcome["result"] != "PASS"
                or require_sha256(
                    outcome["log_sha256"], "Private boot log fingerprint"
                ) != hashlib.sha256(logs[log_name]).hexdigest()
                or type(outcome["return_code"]) is not int
                or outcome["return_code"] != 0
            ):
                raise ValueError("Private host boot evidence is inconsistent")
    if (
        value["schema"] != HOST_EVIDENCE_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["phase"] != phase
        or value["identity"] != state["identity"]
        or value["result"] != "PASS"
        or value["manifest_sha256"]
        != hashlib.sha256(azure.canonical_json(manifest)).hexdigest()
        or value["runner_sha256"]
        != state["implementation"]["files"]["runner"]["sha256"]
        or require_uuid(
            value["host_boot_id"], "Private host boot identity"
        ) != value["host_boot_id"]
        or value["boot_policy"] != manifest["boot_policy"]
    ):
        raise ValueError("Private host receipt is stale or mismatched")
    return value


def retrieve_phase_evidence(run, transfer_cidr, sas, phase, manifest):
    formats = ("capability",) if phase == "capability" else ("raw", "vhd")
    names = [
        f"{image_format}-{mode}.log"
        for image_format in formats
        for mode in ("x2apic", "legacy-apic")
    ]
    prefix = f"evidence/{run.state['identity']}/{phase}"
    with run.transfer_access(transfer_cidr):
        values = download_blob_set(
            run,
            f"https://{run.storage}.blob.core.windows.net",
            sas,
            run.container,
            [(prefix + "/receipt.json", MAX_MANIFEST_BYTES)] + [
                (prefix + "/" + name, host_runner.MAX_LOG_BYTES)
                for name in names
            ],
            run.deadline,
        )
    receipt_bytes = values[0]
    logs = dict(zip(names, values[1:]))
    run.account_bytes("evidence", sum(map(len, values)))
    receipt = validate_host_receipt(
        azure.parse_strict_json(
            receipt_bytes, "Private host evidence receipt"
        ),
        run.state, phase, manifest, logs,
    )
    if (
        hashlib.sha256(receipt_bytes).hexdigest()
        != run.state.get(phase + "_receipt_sha256")
    ):
        raise ValueError("Private host receipt differs from RunCommand proof")
    evidence_directory = run.state_path.parent / "evidence" / phase
    evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, content in logs.items():
        path = evidence_directory / name
        save_private_bytes(path, content)
    receipt_path = evidence_directory / "receipt.json"
    save_private_bytes(receipt_path, receipt_bytes)
    azure.fsync_directory(evidence_directory)
    return receipt


def record_private_failure(run, error, phase):
    code = getattr(error, "code", None)
    if not isinstance(code, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_-]{0,79}", code
    ):
        code = None
    run.record("failed", failure={
        "category": type(error).__name__,
        "code": code,
        "phase": phase,
    })


def run_preflight(
    state_directory, subscription, transfer_ip, approve_transfer_source_ip
):
    state, state_path = load_state(state_directory)
    if state["phase"] != "prepared" or state.get("cleanup_required") is not False:
        raise ValueError("Private preflight requires a fresh prepared state")
    verify_immutable_inputs(state, state_path.parent)
    check_blob_dependency()
    if approve_transfer_source_ip is not True:
        raise ValueError(
            "Explicit uploader /32 transfer authorization is required"
        )
    transfer_cidr = transfer_source(transfer_ip)
    cloud = check_subscription(subscription)
    started = datetime.now(timezone.utc)
    deadline = time.monotonic() + MAX_ATTEMPT_SECONDS
    deadline_utc = started + timedelta(seconds=MAX_ATTEMPT_SECONDS)
    state.update({
        "phase": "cloud-preflight-complete",
        "subscription": cloud["subscription"],
        "cloud_preflight": cloud,
        "deadline_utc": utc_text(deadline_utc),
        "deadline_monotonic": deadline,
        "cleanup_required": True,
        "storage_account": "ukhvp" + secrets.token_hex(8),
        "firewall_obligation": None,
    })
    azure.save_durable_json(state_path, state)
    run = PrivatePreflightRun(state, state_path)
    shutdown_time = deadline_utc.strftime("%H%M")
    try:
        with azure.interrupt_as_exception():
            run.create_group()
            run.deploy_host(shutdown_time)
            run.verify_storage_rules()
            account_url = f"https://{run.storage}.blob.core.windows.net"
            public_manifest = host_phase_manifest(state, "capability")
            public_manifest_sha256 = hashlib.sha256(
                azure.canonical_json(public_manifest)
            ).hexdigest()
            public_token = run.generate_sas()
            try:
                with run.transfer_access(transfer_cidr):
                    transferred = upload_blob_set(
                        run,
                        account_url, public_token["value"], run.container,
                        blob_files(state, state_path.parent, PUBLIC_ROLES),
                        create_container=True,
                        deadline=run.deadline,
                    )
                    run.account_bytes("input", transferred)
                run.record(
                    "public-tools-staged",
                    capability_manifest_sha256=public_manifest_sha256,
                )
                run.run_host_phase(
                    "capability", public_manifest, public_token["value"]
                )
                capability_receipt = retrieve_phase_evidence(
                    run, transfer_cidr, public_token["value"],
                    "capability", public_manifest,
                )
            finally:
                run.revoke_sas(public_token)

            private_manifest = host_phase_manifest(
                state, "private", public_manifest_sha256
            )
            private_token = run.generate_sas()
            try:
                with run.transfer_access(transfer_cidr):
                    transferred = upload_blob_set(
                        run,
                        account_url, private_token["value"], run.container,
                        blob_files(state, state_path.parent, PRIVATE_ROLES),
                        create_container=False,
                        deadline=run.deadline,
                    )
                    run.account_bytes("input", transferred)
                run.record(
                    "private-inputs-staged",
                    private_manifest_sha256=hashlib.sha256(
                        azure.canonical_json(private_manifest)
                    ).hexdigest(),
                )
                run.run_host_phase(
                    "private", private_manifest, private_token["value"]
                )
                private_receipt = retrieve_phase_evidence(
                    run, transfer_cidr, private_token["value"],
                    "private", private_manifest,
                )
            finally:
                run.revoke_sas(private_token)
            if (
                private_receipt["host_boot_id"]
                != capability_receipt["host_boot_id"]
            ):
                raise RuntimeError(
                    "Private host restarted after its public capability proof"
                )
            if time.monotonic() >= run.deadline:
                raise RuntimeError(
                    "Private preflight exceeded its absolute deadline"
                )
            if (
                state["staged_input_bytes"]
                != state["input_manifest"]["budget"]["remote_input_bytes"]
            ):
                raise RuntimeError(
                    "Private-preflight staged input accounting is incomplete"
                )
            run.deallocate_host()
            final = {
                "schema": RECEIPT_SCHEMA,
                "schema_version": RECEIPT_SCHEMA_VERSION,
                "result": "PASS",
                "identity": state["identity"],
                "input_manifest_sha256": state["manifest_sha256"],
                "implementation": state["implementation"],
                "provenance": state["input_manifest"]["provenance"],
                "capability_reference": state["input_manifest"][
                    "capability_reference"
                ],
                "private_build": state["input_manifest"]["private_build"],
                "inputs": {
                    role: {
                        "sha256": record["sha256"],
                        "size": record["size"],
                    }
                    for role, record in state["input_manifest"]["files"].items()
                },
                "qemu_support": state["input_manifest"]["qemu_support"],
                "miz": state["input_manifest"]["miz"],
                "packaging": state["input_manifest"]["packaging"],
                "budget": {
                    **state["input_manifest"]["budget"],
                    "staged_input_bytes": state["staged_input_bytes"],
                    "control_payload_bytes": state[
                        "control_payload_bytes"
                    ],
                    "evidence_bytes": state["evidence_bytes"],
                },
                "host_image": state["cloud_preflight"]["image"],
                "host": {
                    "operation_id": state["host_deployment"][
                        "operation_id"
                    ],
                    "deployment_correlation_id": state["host_deployment"][
                        "correlation_id"
                    ],
                    "vm_uuid": state["host_deployment"]["vm_uuid"],
                    "disk_uuid": state["host_deployment"]["disk_uuid"],
                    "boot_id": private_receipt["host_boot_id"],
                },
                "capability_receipt_sha256": state[
                    "capability_receipt_sha256"
                ],
                "private_receipt_sha256": state["private_receipt_sha256"],
                "boot_policy": state["input_manifest"]["boot_policy"],
                "capability_boots": capability_receipt["boots"],
                "private_boots": private_receipt["boots"],
                "cleanup": "pending",
            }
            final_path = state_path.parent / "private-receipt.json"
            azure.save_durable_json(final_path, final)
            run.record(
                "accepted", final_receipt_sha256=azure.image_sha256(final_path)
            )
    except BaseException as error:
        record_private_failure(run, error, state.get("phase", "unknown"))
        raise
    finally:
        if state.get("cleanup_required"):
            try:
                run.cleanup()
            except BaseException as error:
                record_private_failure(run, error, "cleanup")
                raise
    final["cleanup"] = "complete"
    azure.save_durable_json(state_path.parent / "private-receipt.json", final)
    run.record(
        "complete", cleanup_required=False,
        final_receipt_sha256=azure.image_sha256(
            state_path.parent / "private-receipt.json"
        ),
    )
    return state_path.parent / "private-receipt.json"


def cleanup(state_directory, subscription):
    state, state_path = load_state(state_directory)
    subscription = azure.validate_subscription_id(subscription)
    if not state.get("subscription"):
        if state["phase"] != "prepared":
            raise ValueError("Private state lacks explicit cleanup ownership")
        state["phase"] = "cleaned"
        azure.save_durable_json(state_path, state)
        return
    if state["subscription"] != subscription:
        raise ValueError("Explicit cleanup subscription does not match private state")
    PrivatePreflightRun(state, state_path).cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Bounded private nested-KVM Hyper-V platform preflight"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    build_parser = subparsers.add_parser("build-private")
    build_parser.add_argument("--output-dir", type=Path, required=True)
    build_parser.add_argument(
        "--repository", type=Path, default=SUPPORT.parent
    )
    build_parser.add_argument("--solved-config", type=Path, required=True)
    build_parser.add_argument("--zig", type=Path, required=True)
    build_parser.add_argument("--make", type=Path, required=True)
    build_parser.add_argument("--python", type=Path, required=True)
    build_parser.add_argument("--bison", type=Path, required=True)
    build_parser.add_argument("--flex", type=Path, required=True)
    build_parser.add_argument("--m4", type=Path, required=True)
    build_parser.add_argument("--bison-data", type=Path, required=True)
    build_parser.add_argument("--llvm-bin", type=Path, required=True)
    build_parser.add_argument("--timeout", type=int, default=1800)
    generate_parser = subparsers.add_parser("generate-input")
    generate_parser.add_argument("--output-dir", type=Path, required=True)
    generate_parser.add_argument(
        "--repository", type=Path, default=SUPPORT.parent
    )
    generate_parser.add_argument("--solved-config", type=Path, required=True)
    generate_parser.add_argument("--qemu-root", type=Path, required=True)
    generate_parser.add_argument("--ovmf-code", type=Path, required=True)
    generate_parser.add_argument("--ovmf-vars", type=Path, required=True)
    generate_parser.add_argument(
        "--capability-raw", type=Path, required=True
    )
    generate_parser.add_argument(
        "--capability-receipt", type=Path, required=True
    )
    generate_parser.add_argument("--private-efi", type=Path, required=True)
    generate_parser.add_argument(
        "--private-build-receipt", type=Path, required=True
    )
    generate_parser.add_argument("--private-raw", type=Path, required=True)
    generate_parser.add_argument("--private-vhd", type=Path, required=True)
    generate_parser.add_argument("--miz", type=Path, required=True)
    generate_parser.add_argument(
        "--boot-policy", choices=BOOT_POLICIES, required=True
    )
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--input-dir", type=Path, required=True)
    prepare_parser.add_argument("--state-dir", type=Path, required=True)
    prepare_parser.add_argument("--miz", type=Path, required=True)
    prepare_parser.add_argument(
        "--expected-manifest-sha256", required=True
    )
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--state-dir", type=Path, required=True)
    run_parser.add_argument("--subscription", required=True)
    run_parser.add_argument("--transfer-source-ip", required=True)
    run_parser.add_argument(
        "--approve-transfer-source-ip", action="store_true",
        help="explicitly authorize the exact temporary uploader /32",
    )
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--state-dir", type=Path, required=True)
    cleanup_parser.add_argument("--subscription", required=True)
    args = parser.parse_args()
    try:
        if args.action == "build-private":
            build_private_image(
                args.output_dir, args.repository, args.solved_config,
                args.zig, args.make, args.python, args.bison, args.flex,
                args.m4, args.bison_data, args.llvm_bin, args.timeout,
            )
            print("Private local build completed in owner-only directory")
        elif args.action == "generate-input":
            digest = generate_input(
                args.output_dir,
                args.repository,
                args.solved_config,
                args.qemu_root,
                args.ovmf_code,
                args.ovmf_vars,
                args.capability_raw,
                args.capability_receipt,
                args.private_efi,
                args.private_build_receipt,
                args.private_raw,
                args.private_vhd,
                args.miz,
                args.boot_policy,
            )
            print(
                "Private preflight input manifest SHA-256: " + digest
            )
        elif args.action == "prepare":
            prepare(
                args.input_dir, args.state_dir, args.miz,
                args.expected_manifest_sha256,
            )
            print("Private preflight inputs prepared in owner-only state")
        elif args.action == "run":
            run_preflight(
                args.state_dir, args.subscription, args.transfer_source_ip,
                args.approve_transfer_source_ip,
            )
            print("Private preflight completed; private receipt retained locally")
        else:
            cleanup(args.state_dir, args.subscription)
            print("Private preflight cleanup completed")
    except subprocess.TimeoutExpired:
        raise SystemExit(
            "A bounded private-preflight subprocess timed out; details withheld"
        ) from None
    except (OSError, RuntimeError, ValueError, KeyboardInterrupt):
        raise SystemExit(
            "Private preflight failed; inspect the owner-only state directory"
        ) from None


if __name__ == "__main__":
    main()
