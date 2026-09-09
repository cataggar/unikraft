#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private Hyper-V nested-KVM preflight runner for an owned Azure host."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request


SCHEMA = "unikraft.hyperv.private-preflight-host-phase"
EVIDENCE_SCHEMA = "unikraft.hyperv.private-preflight-host-evidence"
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[0-9a-f]{32}")
BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,159}")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAIN_RETURN = re.compile(
    r"^(?:\[\s*[0-9]+(?:\.[0-9]+)?\]\s+)?"
    r"(?:Info:\s+)?(?:\[[A-Za-z0-9_.-]{1,64}\]\s+)?"
    r"(?:<[^<>\r\n]{1,160}>:?\s+)?main returned (-?[0-9]+)$"
)
LOCAL_BOOT_MODES = (("x2apic", False), ("legacy-apic", True))
TOTAL_BOOT_COUNT = 6
CPU_FEATURES = (
    "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,"
    "hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies"
)
LEGACY_APIC_MARKER = "Using legacy xAPIC MMIO"
PLATFORM_MARKER = "UK_HYPERV_PLATFORM_READY"
UNAVAILABLE_MARKER = "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network"
UNAVAILABLE_RECORDS = (
    "HYPERV_ACCEPTANCE PLATFORM_READY PASS cpu_count=1 vmbus_offers=0",
    (
        "HYPERV_ACCEPTANCE STORAGE_INVENTORY UNAVAILABLE "
        "devices=0 offers=0 reason=no-storvsc-offer"
    ),
    "HYPERV_ACCEPTANCE STORAGE_READ UNAVAILABLE reason=no-device",
    (
        "HYPERV_ACCEPTANCE NETWORK_INVENTORY UNAVAILABLE "
        "devices=0 offers=0 reason=no-netvsc-offer"
    ),
    "HYPERV_ACCEPTANCE NETWORK_DHCP_TX UNAVAILABLE reason=no-device",
    "HYPERV_ACCEPTANCE NETWORK_DHCP_RX UNAVAILABLE reason=no-device",
    (
        "HYPERV_ACCEPTANCE FINAL_RESULT UNAVAILABLE "
        "storage=UNAVAILABLE network=UNAVAILABLE"
    ),
)
GUARDED_BOOT_POLICY = "guarded-v2-pristine-unavailable"
GUARDED_CONTRACT_SCHEMA = (
    "unikraft.hyperv.guarded-v2-pristine-unavailable"
)
GUARDED_PRODUCER_SCHEMA = "unikraft.hyperv.guarded-producer-pin"
GUARDED_PRODUCER_FILES = {
    "drivers/hyperv/storvsc/include/uk/storvsc.h": (
        "e0e666ff4faefc2ba1186403a4320170fb3163375cc31a04312bbce011aa9f10"
    ),
    "drivers/hyperv/storvsc/storvsc.c": (
        "cb9e5afefb8f18612c36b5975b94ed64c0702c4a4e6988ea4edfa9c6bc6da213"
    ),
    "drivers/hyperv/vmbus/include/uk/vmbus.h": (
        "e11c351dcb6bf4596285193bf728f1f30a2152da25e075539e4143edafc6d763"
    ),
    "drivers/hyperv/vmbus/vmbus_bus.c": (
        "70f4157ce22475e88b037b9f599e4910719a3cfdde0e70cbf32f0f9004b0b185"
    ),
    "support/apps/hyperv-acceptance/Config.uk": (
        "548e97aadb9b55101e2ec1dbb7a4b22f82b210a22d5f14eb441b17fdd2009aa7"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.h": (
        "0298f62c5db8cfec137d39d6a33f9726ca291c7f55150780588a17795cd2b0da"
    ),
    "support/apps/hyperv-acceptance/main.c": (
        "35cdcb441b8acc2520d56aefab0f4538eda74164e26c005d12d7ffd4f5e2691c"
    ),
    "support/apps/hyperv-acceptance/persistence.c": (
        "fff49e4a09ecb6a5e788b817a5f2677d39cadd1f5a7693a2cb2be6721399d9ee"
    ),
}
LIVE_IO_MARKERS = (
    "UK_HYPERV_BLOCK_READ_OK",
    "UK_HYPERV_NET_DHCP_OFFER",
    "UK_HYPERV_NET_APP_LEASE",
    "UK_HYPERV_NET_APP_ARP",
    "UK_HYPERV_NET_APP_TCP",
    "UK_HYPERV_NET_APP_UDP",
    "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_IO_READY",
)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
BOOT_TIMEOUT_SECONDS = 120
INPUT_NAMES = {
    "qemu": "qemu/bin/qemu-system-x86_64",
    "ovmf_code": "OVMF_CODE.fd",
    "ovmf_vars": "OVMF_VARS.fd",
    "capability_raw": "capability.raw",
    "raw": "private.raw",
    "vhd": "private.vhd",
}


class RunnerError(RuntimeError):
    def __init__(self, code):
        if not re.fullmatch(r"[a-z0-9-]{3,64}", code):
            code = "internal"
        self.code = code
        super().__init__(code)


def strict_json(value, description):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise RunnerError("duplicate-json-field")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise RunnerError("malformed-json") from None
    if not isinstance(parsed, dict):
        raise RunnerError(f"invalid-{description}")
    return parsed


def exact_fields(value, fields, code):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise RunnerError(code)
    return value


def require_sha256(value):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise RunnerError("invalid-sha256")
    return value


def require_identity(value):
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise RunnerError("invalid-identity")
    return value


def validate_guarded_contract(value, boot_policy):
    if boot_policy != GUARDED_BOOT_POLICY:
        if value is not None:
            raise RunnerError("unexpected-guarded-contract")
        return None
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "scope", "result", "protocol",
            "identity_policy", "reason", "main_return", "run_id",
            "disk_id", "path", "target", "lun", "sectors",
            "sector_size", "solved_config_sha256", "producer",
        ),
        "invalid-guarded-contract",
    )
    producer = exact_fields(
        value["producer"], ("schema", "schema_version", "files"),
        "invalid-guarded-producer",
    )
    files = exact_fields(
        producer["files"], GUARDED_PRODUCER_FILES,
        "invalid-guarded-producer-files",
    )
    if (
        value["schema"] != GUARDED_CONTRACT_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != "platform-only"
        or value["result"] != "UNAVAILABLE"
        or type(value["protocol"]) is not int
        or value["protocol"] != 1
        or type(value["identity_policy"]) is not int
        or value["identity_policy"] != 2
        or value["reason"] != "no-devices"
        or type(value["main_return"]) is not int
        or value["main_return"] != 2
        or require_identity(value["run_id"]) != value["run_id"]
        or require_identity(value["disk_id"]) != value["disk_id"]
        or type(value["path"]) is not int
        or value["path"] != 0
        or type(value["target"]) is not int
        or value["target"] != 0
        or type(value["lun"]) is not int
        or not 0 <= value["lun"] <= 255
        or type(value["sectors"]) is not int
        or value["sectors"] <= 48
        or value["sectors"] > ((1 << 63) - 1) // 512
        or type(value["sector_size"]) is not int
        or value["sector_size"] != 512
        or require_sha256(value["solved_config_sha256"])
        != value["solved_config_sha256"]
        or producer["schema"] != GUARDED_PRODUCER_SCHEMA
        or type(producer["schema_version"]) is not int
        or producer["schema_version"] != 1
        or dict(files) != GUARDED_PRODUCER_FILES
    ):
        raise RunnerError("invalid-guarded-contract")
    return {
        **value,
        "producer": {
            **producer,
            "files": dict(files),
        },
    }


def host_boot_id():
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        raise RunnerError("host-boot-id-unavailable") from None
    if not BOOT_ID.fullmatch(value):
        raise RunnerError("host-boot-id-invalid")
    return value


def require_file_record(value):
    value = exact_fields(
        value, ("blob", "name", "sha256", "size"), "invalid-file-record"
    )
    for field in ("blob", "name"):
        text = value[field]
        if (
            not isinstance(text, str)
            or not SAFE_NAME.fullmatch(text)
            or text.startswith("/")
            or ".." in Path(text).parts
        ):
            raise RunnerError("invalid-file-name")
    if type(value["size"]) is not int or not 0 < value["size"] <= MAX_FILE_BYTES:
        raise RunnerError("invalid-file-size")
    require_sha256(value["sha256"])
    return dict(value)


def parse_manifest(encoded, expected_phase):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise RunnerError("invalid-manifest-encoding") from None
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RunnerError("manifest-too-large")
    fields = (
            "schema", "schema_version", "phase", "identity",
            "boot_policy", "raw_size", "files", "evidence_prefix",
            "runner_sha256", "qemu_support", "input_manifest_sha256",
            "workload", "guarded",
        ) + (
            ("capability_manifest_sha256",)
            if expected_phase == "private" else ()
        )
    manifest = exact_fields(
        strict_json(raw, "manifest"),
        fields,
        "invalid-manifest-fields",
    )
    if (
        manifest["schema"] != SCHEMA
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 3
        or manifest["phase"] != expected_phase
        or manifest["workload"] != "platform-only-v1"
        or manifest["boot_policy"] not in (
            "platform-unavailable-v1", "platform-main-zero-v1",
            GUARDED_BOOT_POLICY,
        )
        or type(manifest["raw_size"]) is not int
        or not 1024 * 1024 <= manifest["raw_size"] <= MAX_FILE_BYTES
        or require_sha256(manifest["runner_sha256"])
        != manifest["runner_sha256"]
        or require_sha256(manifest["input_manifest_sha256"])
        != manifest["input_manifest_sha256"]
    ):
        raise RunnerError("invalid-manifest-contract")
    manifest["guarded"] = validate_guarded_contract(
        manifest["guarded"], manifest["boot_policy"]
    )
    identity = require_identity(manifest["identity"])
    prefix = manifest["evidence_prefix"]
    if (
        not isinstance(prefix, str)
        or prefix != f"evidence/{identity}/{expected_phase}"
    ):
        raise RunnerError("invalid-evidence-prefix")
    expected_files = (
        ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
        if expected_phase == "capability"
        else ("qemu", "ovmf_code", "ovmf_vars", "raw", "vhd")
    )
    files = exact_fields(
        manifest["files"], expected_files, "invalid-manifest-files"
    )
    manifest["files"] = {
        name: require_file_record(files[name]) for name in expected_files
    }
    for role, record in manifest["files"].items():
        source_phase = (
            "public"
            if role in ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
            else "private"
        )
        if (
            record["name"] != INPUT_NAMES[role]
            or record["blob"] != (
                f"inputs/{identity}/{source_phase}/{INPUT_NAMES[role]}"
            )
        ):
            raise RunnerError("invalid-file-binding")
    support = manifest["qemu_support"]
    if not isinstance(support, list) or len(support) > 124:
        raise RunnerError("invalid-qemu-support")
    parsed_support = []
    names = set()
    for record in support:
        record = require_file_record(record)
        if (
            not record["name"].startswith("qemu/")
            or len(Path(record["name"]).parts) < 3
            or Path(record["name"]).parts[1] not in ("lib", "share")
            or record["blob"] != (
                f"inputs/{identity}/public/{record['name']}"
            )
            or record["name"] in names
        ):
            raise RunnerError("invalid-qemu-support")
        names.add(record["name"])
        parsed_support.append(record)
    manifest["qemu_support"] = parsed_support
    if expected_phase == "capability":
        if manifest["files"]["capability_raw"]["size"] != manifest["raw_size"]:
            raise RunnerError("invalid-capability-size")
        if manifest["boot_policy"] != "platform-unavailable-v1":
            raise RunnerError("invalid-capability-policy")
        if manifest["guarded"] is not None:
            raise RunnerError("invalid-capability-policy")
    else:
        if (
            manifest["files"]["raw"]["size"] != manifest["raw_size"]
            or manifest["files"]["vhd"]["size"] != manifest["raw_size"] + 512
            or require_sha256(manifest["capability_manifest_sha256"])
            != manifest["capability_manifest_sha256"]
        ):
            raise RunnerError("invalid-private-image-size")
    return manifest, raw


def blob_url(base_url, container, name, sas):
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or not re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", parsed.hostname or "")
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", container)
        or not isinstance(sas, str)
        or len(sas) > 4096
        or any(character.isspace() for character in sas)
    ):
        raise RunnerError("invalid-blob-endpoint")
    return (
        f"https://{parsed.hostname}/{container}/"
        f"{urllib.parse.quote(name, safe='/')}?{sas.lstrip('?')}"
    )


def download_file(base_url, container, record, sas, destination):
    request = urllib.request.Request(
        blob_url(base_url, container, record["blob"], sas),
        headers={"x-ms-version": "2023-11-03"},
    )
    digest = hashlib.sha256()
    written = 0
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=60) as response, \
                destination.open("xb") as output:
            os.chmod(destination, 0o600)
            while written <= record["size"]:
                chunk = response.read(
                    min(1024 * 1024, record["size"] + 1 - written)
                )
                if not chunk:
                    break
                written += len(chunk)
                if written > record["size"]:
                    raise RunnerError("download-size-mismatch")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
    except RunnerError:
        destination.unlink(missing_ok=True)
        raise
    except Exception:
        destination.unlink(missing_ok=True)
        raise RunnerError("blob-download-failed") from None
    if written != record["size"] or digest.hexdigest() != record["sha256"]:
        destination.unlink(missing_ok=True)
        raise RunnerError("download-fingerprint-mismatch")


def upload_file(base_url, container, name, sas, source):
    data = source.read_bytes()
    maximum = MAX_MANIFEST_BYTES if name.endswith("receipt.json") else MAX_LOG_BYTES
    if len(data) > maximum:
        raise RunnerError("evidence-too-large")
    request = urllib.request.Request(
        blob_url(base_url, container, name, sas),
        data=data,
        method="PUT",
        headers={
            "Content-Length": str(len(data)),
            "If-None-Match": "*",
            "x-ms-blob-type": "BlockBlob",
            "x-ms-version": "2023-11-03",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status not in (200, 201):
                raise RunnerError("blob-upload-failed")
    except RunnerError:
        raise
    except Exception:
        raise RunnerError("blob-upload-failed") from None


def hash_prefix(path, length):
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as source:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RunnerError("image-size-mismatch")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def immutable_identity(path, record, code):
    try:
        metadata = path.lstat()
    except OSError:
        raise RunnerError(code) from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != record["size"]
        or hash_file(path) != record["sha256"]
    ):
        raise RunnerError(code)
    return metadata.st_dev, metadata.st_ino


def revalidate_boot_image(image, backing, record, identity):
    source_identity = immutable_identity(
        image, record, "boot-image-mutated"
    )
    backing_identity = immutable_identity(
        backing, record, "boot-backing-mutated"
    )
    if source_identity != identity or backing_identity != identity:
        raise RunnerError("boot-image-replaced")


def write_durable(path, value):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def normalized_lines(text):
    return [
        ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
        for line in text.splitlines()
        if ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
    ]


def validate_boot_log(text, policy, legacy_apic, guarded=None):
    lines = normalized_lines(text)
    guarded = validate_guarded_contract(guarded, policy)
    for marker in (
        "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:", "Powered by", "Calling main(",
    ):
        if sum(marker in line for line in lines) != 1:
            raise RunnerError("missing-hyperv-capability")
    if lines.count(PLATFORM_MARKER) != 1:
        raise RunnerError("invalid-platform-marker")
    if any(
        "Unikraft Crash" in line
        or "Assertion failure" in line
        or "Exception Type" in line
        for line in lines
    ):
        raise RunnerError("guest-crash")
    main = [
        MAIN_RETURN.fullmatch(line) for line in lines if "main returned" in line
    ]
    if len(main) != 1 or main[0] is None:
        raise RunnerError("invalid-main-return")
    expected_return = (
        2 if policy in ("platform-unavailable-v1", GUARDED_BOOT_POLICY)
        else 0
    )
    if int(main[0].group(1)) != expected_return:
        raise RunnerError("unexpected-main-return")
    if policy == GUARDED_BOOT_POLICY:
        start = (
            "HYPERV_PERSISTENCE START PASS "
            f"run={guarded['run_id']} "
            f"address={guarded['path']}:{guarded['target']}:{guarded['lun']} "
            f"sectors={guarded['sectors']} "
            f"sector_size={guarded['sector_size']}"
        )
        select = (
            "HYPERV_PERSISTENCE SELECT UNAVAILABLE "
            f"reason={guarded['reason']} writes=0 flushes=0"
        )
        unavailable = (
            "UK_HYPERV_PERSISTENCE_UNAVAILABLE:"
            f"{guarded['protocol']}:{guarded['identity_policy']}:"
            f"{guarded['reason']}"
        )
        persistence = [
            line for line in lines
            if (
                "HYPERV_PERSISTENCE" in line
                or "UK_HYPERV_PERSISTENCE" in line
            )
        ]
        if persistence != [start, select, unavailable]:
            raise RunnerError("invalid-guarded-unavailable-policy")
        positions = []
        for marker in (
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:", "Powered by", "Calling main(",
        ):
            positions.append(next(
                index for index, line in enumerate(lines) if marker in line
            ))
        positions.extend((
            lines.index(start),
            lines.index(select),
            lines.index(PLATFORM_MARKER),
            lines.index(unavailable),
            next(
                index for index, line in enumerate(lines)
                if "main returned" in line
            ),
        ))
        if positions != sorted(positions) or len(set(positions)) != len(positions):
            raise RunnerError("reordered-guarded-unavailable-policy")
        if (
            any("FAIL" in line for line in lines)
            or any(
                line.startswith((
                    "HYPERV_ACCEPTANCE ", "UK_HYPERV_ACCEPTANCE_",
                    "HYPERV_STORAGE ", "HYPERV_NETWORK_APP ",
                ))
                for line in lines
            )
        ):
            raise RunnerError("unexpected-guarded-activity")
    elif policy == "platform-unavailable-v1":
        acceptance = [
            line for line in lines
            if line.startswith("HYPERV_ACCEPTANCE ")
        ]
        unavailable = [
            line for line in lines
            if line.startswith("UK_HYPERV_ACCEPTANCE_")
        ]
        if (
            acceptance != list(UNAVAILABLE_RECORDS)
            or unavailable != [UNAVAILABLE_MARKER]
        ):
            raise RunnerError("invalid-unavailable-policy")
        if any("FAIL" in line for line in lines):
            raise RunnerError("unexpected-guest-failure")
    elif (
        any("FAIL" in line or "UNAVAILABLE" in line for line in lines)
        or "UK_HYPERV_IO_READY" in lines
    ):
        raise RunnerError("unexpected-platform-only-evidence")
    if legacy_apic:
        if sum(LEGACY_APIC_MARKER in line for line in lines) != 1:
            raise RunnerError("missing-legacy-apic")
    elif any(LEGACY_APIC_MARKER in line for line in lines):
        raise RunnerError("unexpected-legacy-apic")
    if (
        any(marker in lines for marker in LIVE_IO_MARKERS)
        or any(
            line.startswith("UK_HYPERV_")
            and (
                (line.endswith("_READY") and line != PLATFORM_MARKER)
                or line.endswith("_READ_OK")
            )
            for line in lines
        )
        or (
            policy != GUARDED_BOOT_POLICY
            and any(
                " PASS" in line
                and line.startswith((
                    "HYPERV_ACCEPTANCE", "HYPERV_NETWORK_APP",
                    "HYPERV_STORAGE",
                ))
                and line != UNAVAILABLE_RECORDS[0]
                for line in lines
            )
        )
    ):
        raise RunnerError("unexpected-live-io")


def run_boot(qemu, ovmf_code, ovmf_code_record, ovmf_vars, ovmf_vars_record,
             image, image_record, raw_size, policy, mode, legacy_apic,
             output_directory, guarded=None):
    work = Path(tempfile.mkdtemp(prefix="boot-", dir=output_directory))
    image_identity = immutable_identity(
        image, image_record, "boot-image-invalid"
    )
    code_identity = immutable_identity(
        ovmf_code, ovmf_code_record, "ovmf-code-invalid"
    )
    variables_identity = immutable_identity(
        ovmf_vars, ovmf_vars_record, "ovmf-vars-invalid"
    )
    backing = work / "disk.img"
    linked = False
    failure = None
    try:
        shutil.copyfile(ovmf_vars, work / "OVMF_VARS.fd")
        immutable_identity(
            work / "OVMF_VARS.fd", ovmf_vars_record,
            "ovmf-vars-copy-invalid",
        )
        (work / "OVMF_VARS.fd").chmod(0o600)
        os.link(image, backing)
        linked = True
        if immutable_identity(
            backing, image_record, "boot-backing-invalid"
        ) != image_identity:
            raise RunnerError("boot-backing-identity-mismatch")
        cpu = CPU_FEATURES + (",x2apic=off" if legacy_apic else "")
        disk = {
            "driver": "raw", "node-name": "hyperv-disk",
            "offset": 0, "size": raw_size, "read-only": True,
            "file": {
                "driver": "file", "filename": "disk.img",
                "read-only": True,
            },
        }
        command = [
            str(qemu), "-machine", "q35,accel=kvm", "-cpu", cpu,
            "-L", str(qemu.parent.parent / "share"),
            "-smp", "1", "-m", "512M",
            "-drive",
            "if=pflash,format=raw,readonly=on,file=" + str(ovmf_code),
            "-drive", "if=pflash,format=raw,file=OVMF_VARS.fd",
            "-blockdev", json.dumps(disk, separators=(",", ":")),
            "-device", "virtio-blk-pci,drive=hyperv-disk",
            "-device", "vmbus-bridge,irq=15",
            "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-no-reboot", "-nic", "none",
        ]
        log_path = output_directory / f"{mode}.log"

        def bound_output():
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES)
            )

        with log_path.open("xb") as log:
            os.chmod(log_path, 0o600)
            try:
                environment = os.environ.copy()
                qemu_root = qemu.parent.parent
                library = qemu_root / "lib"
                if library.is_dir():
                    environment["LD_LIBRARY_PATH"] = str(library)
                result = subprocess.run(
                    command, cwd=work, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT,
                    timeout=BOOT_TIMEOUT_SECONDS, check=False,
                    preexec_fn=bound_output,
                    env=environment,
                )
            except subprocess.TimeoutExpired:
                raise RunnerError("qemu-timeout") from None
        if result.returncode:
            raise RunnerError("qemu-failed")
        text = log_path.read_text(errors="replace")
        validate_boot_log(text, policy, legacy_apic, guarded)
        return {
            "result": "PASS",
            "log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
            "return_code": result.returncode,
        }, log_path
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if immutable_identity(
                ovmf_code, ovmf_code_record, "ovmf-code-mutated"
            ) != code_identity:
                raise RunnerError("ovmf-code-replaced")
            if immutable_identity(
                ovmf_vars, ovmf_vars_record, "ovmf-vars-mutated"
            ) != variables_identity:
                raise RunnerError("ovmf-vars-replaced")
            if linked and (backing.exists() or backing.is_symlink()):
                revalidate_boot_image(
                    image, backing, image_record, image_identity
                )
            elif linked:
                immutable_identity(
                    image, image_record, "boot-image-mutated"
                )
                raise RunnerError("boot-backing-replaced")
            else:
                immutable_identity(
                    image, image_record, "boot-image-mutated"
                )
        except RunnerError:
            if failure is None:
                raise
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)


def execute_phase(phase, manifest, manifest_bytes, base_url, container, sas,
                  root):
    identity = manifest["identity"]
    if (
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        != manifest["runner_sha256"]
    ):
        raise RunnerError("runner-fingerprint-mismatch")
    boot_id = host_boot_id()
    run_root = root / identity
    public_root = run_root / "public"
    phase_root = run_root / phase
    evidence_root = phase_root / "evidence"
    evidence_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    capability_complete = run_root / "capability.complete"
    if phase == "private":
        if capability_complete.is_symlink() or not capability_complete.is_file():
            raise RunnerError("capability-not-complete")
        capability = strict_json(
            capability_complete.read_bytes(), "capability-state"
        )
        capability = exact_fields(
            capability,
            ("identity", "manifest_sha256", "result", "host_boot_id"),
            "invalid-capability-state",
        )
        if capability != {
            "identity": identity,
            "manifest_sha256": manifest["capability_manifest_sha256"],
            "result": "PASS",
            "host_boot_id": boot_id,
        }:
            raise RunnerError("capability-state-mismatch")
    records = manifest["files"]
    paths = {}
    download_records = list(records.items()) + [
        ("support:" + record["name"], record)
        for record in manifest["qemu_support"]
    ]
    for name, record in download_records:
        public_file = name in (
            "qemu", "ovmf_code", "ovmf_vars", "capability_raw"
        ) or name.startswith("support:")
        destination_root = public_root if public_file else phase_root
        destination = destination_root / record["name"]
        if destination.exists():
            if (
                destination.is_symlink()
                or destination.stat().st_size != record["size"]
                or hashlib.sha256(destination.read_bytes()).hexdigest()
                != record["sha256"]
            ):
                raise RunnerError("stale-host-input")
        elif phase == "private" and public_file:
            raise RunnerError("capability-input-missing")
        else:
            download_file(base_url, container, record, sas, destination)
        paths[name] = destination
    qemu = paths["qemu"]
    qemu.chmod(0o700)
    paths["ovmf_code"].chmod(0o400)
    paths["ovmf_vars"].chmod(0o400)
    raw_size = manifest["raw_size"]
    if phase == "private":
        if hash_prefix(paths["vhd"], raw_size) != records["raw"]["sha256"]:
            raise RunnerError("vhd-data-region-mismatch")
        with paths["vhd"].open("rb") as vhd:
            vhd.seek(-512, os.SEEK_END)
            if vhd.read(8) != b"conectix":
                raise RunnerError("invalid-fixed-vhd-footer")
    images = (
        (("capability", paths["capability_raw"]),)
        if phase == "capability"
        else (("raw", paths["raw"]), ("vhd", paths["vhd"]))
    )
    boots = {}
    logs = []
    for image_name, image in images:
        boots[image_name] = {}
        for mode, legacy_apic in LOCAL_BOOT_MODES:
            outcome, log_path = run_boot(
                qemu,
                paths["ovmf_code"], records["ovmf_code"],
                paths["ovmf_vars"], records["ovmf_vars"],
                image,
                records[image_name if image_name != "capability"
                        else "capability_raw"],
                raw_size, manifest["boot_policy"],
                f"{image_name}-{mode}", legacy_apic, evidence_root,
                manifest["guarded"],
            )
            boots[image_name][mode] = outcome
            logs.append(log_path)
    receipt = {
        "schema": EVIDENCE_SCHEMA,
        "schema_version": 2,
        "phase": phase,
        "identity": identity,
        "result": "PASS",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "runner_sha256": manifest["runner_sha256"],
        "host_boot_id": boot_id,
        "boot_policy": manifest["boot_policy"],
        "acceptance_scope": "platform-only",
        "storage_result": (
            "UNAVAILABLE"
            if manifest["boot_policy"] == GUARDED_BOOT_POLICY
            else "NOT_EVALUATED"
        ),
        "boots": boots,
    }
    receipt_path = evidence_root / "receipt.json"
    write_durable(
        receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode()
    )
    total = receipt_path.stat().st_size + sum(path.stat().st_size for path in logs)
    if total > MAX_EVIDENCE_BYTES:
        raise RunnerError("evidence-total-too-large")
    prefix = manifest["evidence_prefix"]
    for path in logs:
        upload_file(
            base_url, container, f"{prefix}/{path.name}", sas, path
        )
    upload_file(
        base_url, container, f"{prefix}/receipt.json", sas, receipt_path
    )
    if phase == "capability":
        write_durable(
            capability_complete,
            (json.dumps({
            "identity": identity,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "result": "PASS",
            "host_boot_id": boot_id,
            }, sort_keys=True) + "\n").encode(),
        )
    return hashlib.sha256(receipt_path.read_bytes()).hexdigest(), len(boots) * 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("capability", "private"), required=True)
    parser.add_argument("--manifest-b64", required=True)
    parser.add_argument("--blob-base-url", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument(
        "--root", type=Path,
        default=Path("/var/lib/unikraft-private-preflight"),
    )
    args = parser.parse_args()
    try:
        sas = os.environ.pop("HYPERV_PREFLIGHT_SAS")
        manifest, manifest_bytes = parse_manifest(
            args.manifest_b64, args.phase
        )
        args.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        receipt_sha256, boot_count = execute_phase(
            args.phase, manifest, manifest_bytes,
            args.blob_base_url, args.container, sas, args.root,
        )
        print("HYPERV_PRIVATE_PREFLIGHT " + json.dumps({
            "schema": 1, "phase": args.phase, "result": "PASS",
            "identity": manifest["identity"],
            "receipt_sha256": receipt_sha256,
            "boot_count": boot_count,
        }, sort_keys=True))
    except (KeyError, OSError, RunnerError, ValueError) as error:
        code = getattr(error, "code", None)
        print("HYPERV_PRIVATE_PREFLIGHT " + json.dumps({
            "schema": 1, "phase": args.phase, "result": "FAIL",
            "reason": code or "internal",
        }, sort_keys=True))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
