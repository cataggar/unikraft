#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import base64
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

import hyperv_network_controller as network


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
PREPARED_IMAGE_SCHEMA_VERSION = 2
PREPARED_IMAGE_CONTROLLER_REVISION = 3
PREPARED_IMAGE_MANIFEST = "prepared-image-manifest.json"
PREPARED_IMAGE_VHD = "unikraft.vhd"
PREPARED_IMAGE_FILES = frozenset((PREPARED_IMAGE_MANIFEST, PREPARED_IMAGE_VHD))
MIZ_REVISION = "2db68ca0c3ab12155012a823c3fb8d7aba1cb544"
MAX_MANIFEST_SIZE = 64 * 1024
MAX_LOCAL_LOG_SIZE = 4 * MIB
MAX_RESERVATION_SIZE = 16 * 1024
AZURE_OWNERSHIP_FIELDS = frozenset((
    "subscription", "resource_group", "resource_group_id", "disk_id", "vm_id",
    "peer_vm_id", "peer_disk_id", "peer_nic_id", "guest_nic_id",
))
VM_SIZES = ("Standard_D2s_v5", "Standard_D2as_v5", "Standard_B2s")
RESERVATION_SCHEMA = "unikraft.hyperv.resource-group-reservation"
RESERVATION_TAGS = {
    "managed-by": MANAGED_BY,
    "purpose": "disposable-unikraft-acceptance",
    "disposable": "true",
}
RESERVATION_FIELDS = (
    "schema", "schema_version", "phase", "subscription", "location",
    "name_prefix", "resource_group", "tags", "resource_group_id",
    "resource_count",
)
RESERVATION_CLAIM_FIELDS = (
    "claim_id", "run_name_prefix", "image_sha256",
    "prepared_manifest_sha256",
)
PEER_DEPLOYMENT_PROOF_FIELDS = frozenset((
    "deployment_id", "correlation_id", "declared_resource_ids",
))
PEER_DEPLOYMENT_IDENTITY_FIELDS = frozenset((
    "peer_vm_id", "peer_vm_uuid", "peer_disk_id", "peer_disk_uuid",
))
GUEST_DEPLOYMENT_FIELDS = frozenset((
    "deployment_id", "correlation_id", "declared_resource_ids",
    "vm_id", "vm_uuid", "disk_id", "disk_uuid", "nic_id",
))
UPLOADED_DISK_FIELDS = frozenset(("disk_id", "disk_uuid"))
PEER_TRANSIENT_PROVISIONING_STATES = frozenset(("Creating", "Updating"))


def safe_failure_message(error, private_values=()):
    message = str(error)
    message = re.sub(r"https://\S+", "<private-endpoint>", message)
    message = re.sub(
        r"/subscriptions/[^\s;]+", "<private-resource>", message,
        flags=re.IGNORECASE,
    )
    message = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        "<private-identifier>", message, flags=re.IGNORECASE,
    )
    for value in sorted(
        (
            str(value) for value in private_values
            if value and len(str(value)) >= 6
        ),
        key=len, reverse=True,
    ):
        message = re.sub(
            re.escape(value), "<private-identifier>", message,
            flags=re.IGNORECASE,
        )
    return message


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


class AzureCliTimeout(RuntimeError):
    def __init__(self, arguments):
        super().__init__(
            f"az {' '.join(arguments[:2])} timed out; private command details withheld"
        )


class ManagedDiskUploadTimeout(RuntimeError):
    def __init__(self):
        super().__init__(
            "Managed-disk upload helper timed out; "
            "private upload details withheld"
        )


class RunCleanupError(RuntimeError):
    def __init__(
        self, primary, cleanup, recording=None, private_values=(),
    ):
        message = (
            "Primary run failure: "
            f"{safe_failure_message(primary, private_values)}; "
            "cleanup also failed: "
            f"{safe_failure_message(cleanup, private_values)}"
        )
        if recording is not None:
            message += (
                "; durable cleanup-failure recording also failed: "
                + safe_failure_message(recording, private_values)
            )
        super().__init__(message)


class CleanupOperationError(RuntimeError):
    def __init__(self, deallocation, group_cleanup, private_values=()):
        super().__init__(
            "Peer VM deallocation failed: "
            f"{safe_failure_message(deallocation, private_values)}; "
            "resource-group cleanup also failed: "
            f"{safe_failure_message(group_cleanup, private_values)}"
        )


class CleanupValidationError(RuntimeError):
    def __init__(self, failures, private_values=()):
        super().__init__(
            "Cleanup ownership checks failed: " + "; ".join(
                f"{description}: "
                f"{safe_failure_message(error, private_values)}"
                for description, error in failures
            )
        )


def cleanup_after_primary_failure(run, primary):
    private_values = ()
    private_values_fn = getattr(run, "private_failure_values", None)
    if callable(private_values_fn):
        values = private_values_fn()
        if isinstance(values, (list, tuple, set, frozenset)):
            private_values = values
    try:
        run.cleanup()
    except BaseException as cleanup:
        fields = {
            "primary_failure": safe_failure_message(primary, private_values),
            "cleanup_failure": safe_failure_message(cleanup, private_values),
        }
        try:
            run.record("cleanup-failed", **fields)
        except BaseException as recording:
            raise RunCleanupError(
                primary, cleanup, recording, private_values
            ) from None
        raise RunCleanupError(
            primary, cleanup, private_values=private_values
        ) from None


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
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=environment, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise AzureCliTimeout(arguments) from None
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


def fsync_directory(path):
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_durable_json(path, value):
    save_json(path, value)
    fsync_directory(path.parent)


def save_private_text(path, value):
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, prefix=".azure-evidence-", delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            output.write(value)
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
    digest = hashlib.sha256()
    for path in (
        Path(__file__).absolute(),
        Path(network.__file__).absolute(),
        SUPPORT / "azure" / "hyperv-gen2.json",
        SUPPORT / "azure" / "hyperv-network-peer.json",
    ):
        digest.update(path.name.encode("ascii"))
        digest.update(b"\0")
        digest.update(read_regular_file(
            path, 4 * 1024 * 1024, "Controller source"
        ))
        digest.update(b"\0")
    return digest.hexdigest()


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
    timed_out = False
    try:
        result = subprocess.run(
            [sys.executable, str(SUPPORT / "scripts/hyperv-azure-upload.py"),
             *arguments],
            stdin=subprocess.DEVNULL, capture_output=True,
            text=True, encoding="utf-8", errors="replace", env=environment,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    if timed_out:
        raise ManagedDiskUploadTimeout() from None
    if result.returncode:
        raise RuntimeError(f"Managed-disk upload helper failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def check_upload_dependencies():
    result = upload_helper(["--check-dependencies"], timeout=30)
    if not isinstance(result, dict) or result.get("available") is not True:
        raise RuntimeError("Managed-disk upload dependencies are unavailable")


def upload_managed_vhd(
    image, endpoint, sas, *, timeout=1200, expected_sha256=None,
):
    report = upload_helper(
        ["--image", str(image), "--endpoint", endpoint],
        sas=sas, timeout=timeout,
    )
    if (
        not isinstance(report, dict)
        or report.get("uploaded_bytes") != image.stat().st_size
        or report.get("footer_matches") is not True
        or (
            expected_sha256 is not None
            and report.get("image_sha256") != expected_sha256
        )
    ):
        raise RuntimeError(
            "Managed-disk page upload did not verify the expected image"
        )


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
    if args.solved_config is None:
        acceptance = {"mode": network.RAW_ACCEPTANCE_MODE}
    else:
        config = read_regular_file(
            args.solved_config, MIB, "Solved application-network configuration"
        )
        peer_script = read_regular_file(
            network.PEER_SCRIPT, 4 * 1024 * 1024,
            "Pinned Hyper-V network peer"
        )
        acceptance = network.acceptance_from_solved_config(config, peer_script)
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
        "local_platform_boot": False, "acceptance": acceptance,
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
    if acceptance["mode"] == network.NETWORK_ACCEPTANCE_MODE:
        for log_name in ("raw", "vpc"):
            for mode, _ in LOCAL_BOOT_MODES:
                text = read_regular_file(
                    directory / f"local-{log_name}-{mode}-serial.log",
                    MAX_LOCAL_LOG_SIZE,
                    f"Local {log_name}/{mode} serial evidence",
                ).decode("utf-8", errors="replace")
                network.validate_preflight_log(text, acceptance)
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


def prepared_boot_outcomes(acceptance=None):
    outcomes = {
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
    if (
        acceptance is not None
        and network.validate_acceptance(acceptance)["mode"]
        == network.NETWORK_ACCEPTANCE_MODE
    ):
        for image in outcomes.values():
            for result in image.values():
                result["network_config"] = "matched"
    return outcomes


def validate_prepared_image_manifest(manifest, expected_source=None):
    manifest = require_exact_fields(manifest, (
        "schema", "schema_version", "controller_revision",
        "controller_sha256", "source", "acceptance", "artifacts", "packaging",
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
    acceptance = network.validate_acceptance(manifest["acceptance"])
    if (
        acceptance["mode"] == network.NETWORK_ACCEPTANCE_MODE
        and sha256_bytes(read_regular_file(
            network.PEER_SCRIPT, 4 * 1024 * 1024,
            "Pinned Hyper-V network peer"
        )) != acceptance["peer_script_sha256"]
    ):
        raise ValueError("Prepared image requires a different pinned network peer")

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
        != canonical_json(prepared_boot_outcomes(acceptance))
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
        "acceptance": acceptance,
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
    acceptance = network.validate_acceptance(
        state.get("acceptance", {"mode": network.RAW_ACCEPTANCE_MODE})
    )
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
            if acceptance["mode"] == network.NETWORK_ACCEPTANCE_MODE:
                text = read_regular_file(
                    state_path.parent / f"local-{log_name}-{mode}-serial.log",
                    MAX_LOCAL_LOG_SIZE,
                    f"Local {image_name}/{mode} serial evidence",
                ).decode("utf-8", errors="replace")
                network.validate_preflight_log(text, acceptance)
            boot_outcome = {
                "platform_ready": evidence["platform_ready"],
                "io_ready": evidence["io_ready"],
                "apic_path": "legacy-xapic" if disable_x2apic else "x2apic",
            }
            if acceptance["mode"] == network.NETWORK_ACCEPTANCE_MODE:
                boot_outcome["network_config"] = "matched"
            boot_outcomes[image_name][mode] = boot_outcome
    if canonical_json(boot_outcomes) != canonical_json(
        prepared_boot_outcomes(acceptance)
    ):
        raise ValueError("Prepared local evidence does not contain all four exact boots")

    manifest = {
        "schema": PREPARED_IMAGE_SCHEMA,
        "schema_version": PREPARED_IMAGE_SCHEMA_VERSION,
        "controller_revision": PREPARED_IMAGE_CONTROLLER_REVISION,
        "controller_sha256": controller_sha256(),
        "source": validate_prepared_image_source(source),
        "acceptance": acceptance,
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
        "acceptance": details["acceptance"],
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
        or state.get("acceptance") != details["acceptance"]
        or state.get("trusted_platform_boot_modes") != details["boots"]
    ):
        raise ValueError("Private state does not match its trusted prepared image")


def validate_subscription_id(value):
    if not isinstance(value, str):
        raise ValueError("An explicit Azure subscription UUID is required")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("An explicit Azure subscription UUID is required") from error
    if parsed.int == 0:
        raise ValueError("An explicit nonzero Azure subscription UUID is required")
    return str(parsed)


def read_resource_group_reservation(path):
    path = path.absolute()
    try:
        if path.resolve(strict=True) != path:
            raise ValueError(
                "Resource-group reservation path must not contain symlinks"
            )
    except OSError as error:
        raise ValueError("Resource-group reservation does not exist") from error
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(
            "Resource-group reservation must be a private non-symlink file"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or metadata.st_size > MAX_RESERVATION_SIZE
        ):
            raise ValueError(
                "Resource-group reservation must be a private owner-only regular file"
            )
        chunks = []
        remaining = MAX_RESERVATION_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > MAX_RESERVATION_SIZE:
            raise ValueError("Resource-group reservation exceeds its size limit")
    finally:
        os.close(descriptor)
    return path, parse_strict_json(value, "Resource-group reservation")


def validate_resource_group_reservation(reservation, phases):
    if not isinstance(reservation, dict):
        raise ValueError("Resource-group reservation is not a JSON object")
    phase = reservation.get("phase")
    fields = RESERVATION_FIELDS + (
        ("claim",) if phase in ("claiming", "consumed") else ()
    )
    reservation = require_exact_fields(
        reservation, fields, "Resource-group reservation"
    )
    subscription = validate_subscription_id(reservation["subscription"])
    prefix = reservation["name_prefix"]
    group = reservation["resource_group"]
    location = reservation["location"]
    if (
        reservation["schema"] != RESERVATION_SCHEMA
        or reservation["schema_version"] != 1
        or type(reservation["schema_version"]) is not int
        or phase not in phases
        or not isinstance(prefix, str)
        or not re.fullmatch(r"[a-z][a-z0-9-]{5,31}", prefix)
        or not isinstance(group, str)
        or group != prefix + "-rg"
        or not isinstance(location, str)
        or not re.fullmatch(r"[a-z0-9]{3,30}", location)
        or type(reservation["resource_count"]) is not int
        or reservation["resource_count"] != 0
    ):
        raise ValueError("Resource-group reservation is incompatible or not empty")
    expected_tags = {
        **RESERVATION_TAGS,
        "unikraft-run": prefix,
    }
    if reservation["tags"] != expected_tags:
        raise ValueError("Resource-group reservation has invalid ownership tags")
    expected_id = f"/subscriptions/{subscription}/resourceGroups/{group}"
    resource_group_id = reservation["resource_group_id"]
    if (
        not isinstance(resource_group_id, str)
        or resource_group_id.lower() != expected_id.lower()
    ):
        raise ValueError("Resource-group reservation identity is invalid")
    result = {
        **reservation,
        "subscription": subscription,
        "resource_group_id": resource_group_id,
        "tags": expected_tags,
    }
    if phase in ("claiming", "consumed"):
        claim = require_exact_fields(
            reservation["claim"], RESERVATION_CLAIM_FIELDS,
            "Resource-group reservation claim",
        )
        if (
            not isinstance(claim["claim_id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", claim["claim_id"])
            or not isinstance(claim["run_name_prefix"], str)
            or not re.fullmatch(
                r"[a-z][a-z0-9-]{5,31}", claim["run_name_prefix"]
            )
            or require_sha256(
                claim["image_sha256"], "Reservation image fingerprint"
            ) != claim["image_sha256"]
            or require_sha256(
                claim["prepared_manifest_sha256"],
                "Reservation manifest fingerprint",
            ) != claim["prepared_manifest_sha256"]
        ):
            raise ValueError("Resource-group reservation claim is invalid")
        result["claim"] = dict(claim)
    return result


def load_resource_group_reservation(path):
    _, reservation = read_resource_group_reservation(path)
    return validate_resource_group_reservation(reservation, ("group-created",))


class ResourceGroupReservationClaim:
    def __init__(self, path):
        self.path = path.absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.descriptor = None
        self.reservation = None
        self.claim = None
        self.claiming_document = None

    def __enter__(self):
        try:
            if self.path.parent.resolve(strict=True) != self.path.parent:
                raise ValueError(
                    "Resource-group reservation directory must not contain symlinks"
                )
        except OSError as error:
            raise ValueError(
                "Resource-group reservation directory does not exist"
            ) from error
        flags = (
            os.O_RDWR | os.O_CREAT | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            self.descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as error:
            raise ValueError(
                "Resource-group reservation lock must be a private regular file"
            ) from error
        try:
            metadata = os.fstat(self.descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise ValueError(
                    "Resource-group reservation lock must be owner-only"
                )
            try:
                fcntl.flock(
                    self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                )
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise RuntimeError(
                        "Resource-group reservation is already being claimed"
                    ) from None
                raise
            path, reservation = read_resource_group_reservation(self.path)
            if path != self.path:
                raise ValueError("Resource-group reservation path changed")
            self.reservation = validate_resource_group_reservation(
                reservation, ("group-created",)
            )
            return self
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = None
            raise

    def bind(self, run_name_prefix, image_sha256, prepared_manifest_sha256):
        if self.descriptor is None or self.reservation is None or self.claim:
            raise RuntimeError("Resource-group reservation claim is not active")
        claim = {
            "claim_id": secrets.token_hex(16),
            "run_name_prefix": run_name_prefix,
            "image_sha256": require_sha256(
                image_sha256, "Reservation image fingerprint"
            ),
            "prepared_manifest_sha256": require_sha256(
                prepared_manifest_sha256,
                "Reservation manifest fingerprint",
            ),
        }
        validate_resource_group_reservation(
            {
                **self.reservation,
                "phase": "claiming",
                "claim": claim,
            },
            ("claiming",),
        )
        self.claim = claim
        self.claiming_document = {
            **self.reservation,
            "phase": "claiming",
            "claim": claim,
        }
        save_durable_json(self.path, self.claiming_document)
        return {
            "resource_group_id": self.reservation["resource_group_id"],
            "original_tags": self.reservation["tags"],
            "claim": dict(claim),
        }

    def mark_consumed(self):
        if self.claiming_document is None:
            raise RuntimeError("Resource-group reservation has not been bound")
        _, current = read_resource_group_reservation(self.path)
        current = validate_resource_group_reservation(current, ("claiming",))
        if current != self.claiming_document:
            raise RuntimeError(
                "Resource-group reservation changed during its claim"
            )
        save_durable_json(
            self.path, {**self.claiming_document, "phase": "consumed"}
        )

    def __exit__(self, _error_type, _error, _traceback):
        if self.descriptor is not None:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = None


def quota_count(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    raise ValueError("Azure CLI returned an invalid nonnegative quota count")


def selected_account(subscription):
    subscription = validate_subscription_id(subscription)
    account = azure_cli(
        ["account", "show"], subscription=subscription, private=True
    )
    try:
        account_subscription = validate_subscription_id(account["id"])
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(
            "Azure CLI did not return the explicitly selected subscription"
        ) from error
    if (
        account_subscription != subscription
        or account.get("state") != "Enabled"
        or account.get("environmentName") != "AzureCloud"
    ):
        raise RuntimeError(
            "The explicitly selected Azure public-cloud subscription is unavailable"
        )
    return subscription


def exact_vm_sku(location, vm_size, subscription, vcpus, require_v2):
    skus = azure_cli([
        "vm", "list-skus", "--all", "--location", location,
        "--resource-type", "virtualMachines", "--size", vm_size,
        "--query", f"[?name=='{vm_size}']",
    ], subscription=subscription, private=True)
    if (
        not isinstance(skus, list)
        or len(skus) != 1
        or skus[0].get("restrictions") != []
        or not isinstance(skus[0].get("capabilities"), list)
        or not isinstance(skus[0].get("family"), str)
        or not re.fullmatch(r"[A-Za-z0-9_]{1,100}", skus[0]["family"])
    ):
        raise RuntimeError(
            f"Requested VM size {vm_size} is not unrestricted in {location}"
        )
    capabilities = {
        entry.get("name"): entry.get("value")
        for entry in skus[0]["capabilities"]
        if isinstance(entry, dict)
    }
    generations = capabilities.get("HyperVGenerations", "").split(",")
    if (
        capabilities.get("CpuArchitectureType") != "x64"
        or capabilities.get("vCPUs") != str(vcpus)
        or require_v2 and "V2" not in generations
    ):
        raise RuntimeError(
            f"Requested VM size {vm_size} lacks its required x64/generation capabilities"
        )
    return {
        "name": vm_size,
        "family": skus[0]["family"],
        "vcpus": vcpus,
        "generations": generations,
    }


def image_version_key(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){1,4}", value
    ):
        raise ValueError("Azure returned a malformed immutable image version")
    return tuple(int(part) for part in value.split("."))


def resolve_peer_image(location, subscription, supported_generations):
    publisher = network.PEER_IMAGE["publisher"]
    offer = network.PEER_IMAGE["offer"]
    sku = network.PEER_IMAGE["sku"]
    images = azure_cli([
        "vm", "image", "list", "--location", location,
        "--publisher", publisher, "--offer", offer, "--sku", sku, "--all",
    ], subscription=subscription, private=True)
    candidates = []
    if not isinstance(images, list):
        raise RuntimeError("Azure returned an invalid Ubuntu image list")
    for image in images:
        if not isinstance(image, dict):
            continue
        urn = image.get("urn")
        version = image.get("version")
        if (
            isinstance(urn, str)
            and urn.split(":") == [publisher, offer, sku, version]
            and version != "latest"
        ):
            candidates.append((image_version_key(version), urn, version))
    if not candidates:
        raise RuntimeError("No immutable pinned Ubuntu peer image is available")
    _, urn, version = max(candidates)
    details = azure_cli([
        "vm", "image", "show", "--location", location, "--urn", urn,
    ], subscription=subscription, private=True)
    if (
        not isinstance(details, dict)
        or details.get("architecture") != "x64"
        or details.get("hyperVGeneration") not in supported_generations
    ):
        raise RuntimeError(
            "Pinned Ubuntu peer image is incompatible with Standard_B1s"
        )
    return {
        "publisher": publisher,
        "offer": offer,
        "sku": sku,
        "version": version,
        "urn": urn,
        "architecture": "x64",
        "hyperv_generation": details["hyperVGeneration"],
    }


def check_network_subscription(location, guest_vm_size, subscription):
    subscription = selected_account(subscription)
    for namespace in ("Microsoft.Compute", "Microsoft.Network"):
        registration = azure_cli([
            "provider", "show", "--namespace", namespace,
            "--query", "registrationState",
        ], subscription=subscription, private=True)
        if registration != "Registered":
            raise RuntimeError(f"{namespace} must already be registered")
    versions = azure_cli([
        "provider", "show", "--namespace", "Microsoft.Compute",
        "--query", "resourceTypes[?resourceType=='virtualMachines'].apiVersions | [0]",
    ], subscription=subscription, private=True)
    if not isinstance(versions, list) or "2025-11-01" not in versions:
        raise RuntimeError(
            "Compute API 2025-11-01 is required for explicit Standard security"
        )
    guest = exact_vm_sku(
        location, guest_vm_size, subscription, vcpus=2, require_v2=True
    )
    peer = exact_vm_sku(
        location, network.PEER_VM_SIZE, subscription, vcpus=1, require_v2=False
    )
    peer_image = resolve_peer_image(
        location, subscription, peer["generations"]
    )
    required = {"cores": guest["vcpus"] + peer["vcpus"]}
    for sku in (guest, peer):
        required[sku["family"]] = required.get(sku["family"], 0) + sku["vcpus"]
    names = " || ".join(f"name.value=='{name}'" for name in required)
    usage = azure_cli([
        "vm", "list-usage", "--location", location,
        "--query", f"[?{names}]",
    ], subscription=subscription, private=True)
    if not isinstance(usage, list):
        raise RuntimeError("Azure returned invalid quota information")
    limits = {
        entry.get("name", {}).get("value"): entry
        for entry in usage if isinstance(entry, dict)
    }
    for name, count in required.items():
        if name not in limits:
            raise RuntimeError(f"Missing quota information for {name} in {location}")
        available = (
            quota_count(limits[name].get("limit"))
            - quota_count(limits[name].get("currentValue"))
        )
        if available < count:
            raise RuntimeError(
                f"Insufficient quota for one guest and one private peer in {location}"
            )
    return {
        "subscription": subscription,
        "guest_sku": guest,
        "peer_sku": peer,
        "peer_image": peer_image,
    }


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
        self.group = state.get("resource_group", self.prefix + "-rg")
        if (
            not isinstance(self.group, str)
            or not re.fullmatch(r"[a-zA-Z0-9_.()/-]{1,90}", self.group)
            or "/" in self.group
        ):
            raise ValueError("Invalid resource group name")
        if not state.get("group_precreated") and self.group != self.prefix + "-rg":
            raise ValueError("Only an explicit reservation may select an existing group")
        self.vm = self.prefix + "-vm"
        self.peer_vm = self.prefix + "-peer-vm"
        self.disk = self.prefix + "-os"
        self.tags = {
            "managed-by": MANAGED_BY,
            "unikraft-run": self.prefix,
            "image-sha256": state["image_sha256"],
        }
        self.group_tags = dict(self.tags)
        acceptance = network.validate_acceptance(
            state.get("acceptance", {"mode": network.RAW_ACCEPTANCE_MODE})
        )
        self.network_mode = (
            acceptance["mode"] == network.NETWORK_ACCEPTANCE_MODE
        )
        if self.network_mode:
            receipt = state.get("prepared_image_import")
            if not isinstance(receipt, dict):
                raise ValueError(
                    "Application-network runs require a trusted imported image"
                )
            self.group_tags.update({
                "purpose": RESERVATION_TAGS["purpose"],
                "disposable": RESERVATION_TAGS["disposable"],
                "prepared-manifest-sha256": require_sha256(
                    receipt.get("manifest_sha256"), "Prepared manifest fingerprint"
                ),
            })

    def az(self, arguments, **kwargs):
        kwargs.setdefault("private", self.network_mode)
        return azure_cli(
            arguments, subscription=self.state["subscription"], **kwargs
        )

    def record(self, phase, **fields):
        self.state.update(fields)
        self.state["phase"] = phase
        save_durable_json(self.state_path, self.state)

    def private_failure_values(self):
        values = {
            self.prefix, self.group, str(self.state_path),
            str(self.state_path.parent),
        }
        values.update(
            self.state.get(key)
            for key in AZURE_OWNERSHIP_FIELDS
            if isinstance(self.state.get(key), str)
        )
        return values

    def require_owned(self, resource):
        tags = resource.get("tags")
        if not isinstance(tags, dict):
            raise RuntimeError(
                "Refusing to use a resource without this run's ownership tags"
            )
        if any(tags.get(key) != value for key, value in self.tags.items()):
            raise RuntimeError(
                "Refusing to use a resource without this run's ownership tags"
            )

    def require_owned_if_tagged(self, resource):
        tags = resource.get("tags")
        if tags in (None, {}):
            return
        self.require_owned(resource)

    def require_owned_group(self, resource):
        tags = resource.get("tags") or {}
        if any(tags.get(key) != value for key, value in self.group_tags.items()):
            raise RuntimeError(
                "Refusing to use a resource group without this run's "
                "ownership tags and exact binding"
            )

    def resource_tags(self, *, group=False):
        tags = self.group_tags if group else self.tags
        return [f"{key}={value}" for key, value in tags.items()]

    def create_group(self):
        if self.az(["group", "exists", "--name", self.group]) is not False:
            raise RuntimeError(f"Refusing to adopt existing resource group {self.group}")
        self.record("creating-group")
        group = self.az([
            "group", "create", "--name", self.group,
            "--location", self.state["location"],
            "--tags", *self.resource_tags(group=True),
        ])
        self.require_owned_group(group)
        if not isinstance(group.get("id"), str):
            raise RuntimeError("Azure did not return the created resource group ID")
        self.record("group-created", resource_group_id=group["id"])

    def claim_group_reservation(self, reservation):
        if not self.state.get("group_precreated"):
            raise ValueError("Reservation claim requires explicit private state")
        if (
            reservation["resource_group"] != self.group
            or reservation["resource_group_id"].lower()
            != self.state["resource_group_id"].lower()
            or reservation["location"] != self.state["location"]
            or reservation["subscription"] != self.state["subscription"]
        ):
            raise ValueError("Reservation no longer matches the private run state")
        reservation_claim = self.state.get("reservation_claim")
        if (
            not isinstance(reservation_claim, dict)
            or reservation_claim.get("resource_group_id")
            != reservation["resource_group_id"]
            or reservation_claim.get("original_tags") != reservation["tags"]
            or not isinstance(reservation_claim.get("claim"), dict)
            or reservation_claim["claim"].get("run_name_prefix") != self.prefix
            or reservation_claim["claim"].get("image_sha256")
            != self.state["image_sha256"]
            or reservation_claim["claim"].get("prepared_manifest_sha256")
            != self.state["prepared_image_import"]["manifest_sha256"]
        ):
            raise ValueError(
                "Reservation claim is not durably bound to this private run"
            )
        group = self.az(["group", "show", "--name", self.group], private=True)
        if (
            not isinstance(group, dict)
            or str(group.get("id", "")).lower()
            != reservation["resource_group_id"].lower()
            or group.get("location") != reservation["location"]
            or group.get("tags") != reservation["tags"]
        ):
            raise RuntimeError(
                "Live resource group does not match the private reservation"
            )
        resources = self.az(
            ["resource", "list", "--resource-group", self.group], private=True
        )
        if resources != []:
            raise RuntimeError("Reserved resource group is no longer empty")
        group = self.az([
            "group", "update", "--name", self.group,
            "--tags", *self.resource_tags(group=True),
        ], private=True)
        if group.get("tags") != self.group_tags:
            raise RuntimeError("Resource-group reservation tag binding did not complete")
        self.require_owned_group(group)
        group = self.az(
            ["group", "show", "--name", self.group], private=True
        )
        self.require_owned_group(group)
        if self.az([
            "resource", "list", "--resource-group", self.group,
        ], private=True) != []:
            raise RuntimeError("Reserved resource group changed during its claim")
        self.record("group-claimed")

    def expected_uploaded_disk_id(self):
        return self.expected_resource_id(
            "Microsoft.Compute", "disks", self.disk
        )

    def uploaded_disk_receipt(self, disk):
        self.require_owned(disk)
        expected_id = self.expected_uploaded_disk_id()
        if str(disk.get("id", "")).lower() != expected_id.lower():
            raise RuntimeError(
                "Created disk does not have this run's expected identity"
            )
        return {
            "disk_id": expected_id,
            "disk_uuid": self.require_resource_uuid(
                disk.get("uniqueId"), "Uploaded disk identity"
            ),
        }

    def require_uploaded_disk_proof(self, receipt=None):
        if receipt is None:
            receipt = self.state.get("uploaded_disk")
        expected_id = self.expected_uploaded_disk_id()
        if (
            not isinstance(receipt, dict)
            or set(receipt) != UPLOADED_DISK_FIELDS
            or str(receipt["disk_id"]).lower() != expected_id.lower()
            or self.state.get("disk_id") != receipt["disk_id"]
            or self.require_resource_uuid(
                receipt["disk_uuid"], "Uploaded disk identity"
            ) != receipt["disk_uuid"]
        ):
            raise RuntimeError("Uploaded disk provenance is incomplete")
        return receipt

    def verify_uploaded_disk_identity(
        self, disk, *, attached_vm_id=None, require_ready=True,
    ):
        receipt = self.require_uploaded_disk_proof()
        self.require_owned(disk)
        managed_by = disk.get("managedBy")
        if (
            str(disk.get("id", "")).lower()
            != receipt["disk_id"].lower()
            or self.require_resource_uuid(
                disk.get("uniqueId"), "Uploaded disk identity"
            ) != receipt["disk_uuid"]
            or (
                attached_vm_id is None
                and managed_by not in (None, "")
            )
            or (
                attached_vm_id is not None
                and str(managed_by or "").lower()
                != attached_vm_id.lower()
            )
            or (
                require_ready
                and (
                    disk.get("provisioningState") != "Succeeded"
                    or disk.get("hyperVGeneration") != "V2"
                    or disk.get("osType") != "Linux"
                    or disk.get("diskState")
                    != (
                        "Unattached"
                        if attached_vm_id is None
                        else "Attached"
                    )
                )
            )
        ):
            raise RuntimeError(
                "Uploaded disk is missing, detached, replaced or unproven"
            )
        return receipt

    def upload_disk(self, image):
        self.record("creating-disk")
        disk = self.az([
            "disk", "create", "--resource-group", self.group,
            "--name", self.disk, "--location", self.state["location"],
            "--upload-type", "Upload", "--upload-size-bytes", str(image.stat().st_size),
            "--hyper-v-generation", "V2", "--os-type", "Linux",
            "--sku", "Standard_LRS", "--tags", *self.resource_tags(),
        ], timeout=600)
        disk_receipt = self.uploaded_disk_receipt(disk)
        self.record(
            "uploading-disk",
            disk_id=disk_receipt["disk_id"],
            uploaded_disk=disk_receipt,
        )
        try:
            grant = self.az([
                "disk", "grant-access", "--resource-group", self.group,
                "--name", self.disk, "--access-level", "Write",
                "--duration-in-seconds", "1800",
            ], private=True)
            endpoint, sas = upload_endpoint(disk_access_sas(grant))
            upload_managed_vhd(image, endpoint, sas)
        except (RuntimeError, OSError, ValueError) as error:
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
        try:
            self.verify_uploaded_disk_identity(disk)
        except RuntimeError:
            raise RuntimeError("Uploaded disk is not a successfully imported Gen2 Linux disk")
        self.record("disk-ready")

    @contextmanager
    def private_parameters(self, values):
        path = self.state_path.parent / (
            ".deployment-parameters-" + secrets.token_hex(8) + ".json"
        )
        save_json(path, {
            "$schema": (
                "https://schema.management.azure.com/schemas/"
                "2019-04-01/deploymentParameters.json#"
            ),
            "contentVersion": "1.0.0.0",
            "parameters": {
                key: {"value": value} for key, value in values.items()
            },
        })
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)

    @staticmethod
    def deadline_timeout(deadline, maximum):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("The private peer lifetime has expired")
        return min(maximum, remaining)

    @staticmethod
    def require_before_deadline(deadline, operation):
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"The private peer lifetime expired during {operation}"
            )

    def expected_resource_id(self, provider, resource_type, name):
        group_id = self.state.get("resource_group_id")
        if not isinstance(group_id, str):
            raise RuntimeError("Private resource-group identity is unavailable")
        return (
            group_id.rstrip("/") + f"/providers/{provider}/"
            f"{resource_type}/{name}"
        )

    def expected_peer_deployment_resource_ids(self):
        resources = (
            ("Microsoft.Network", "networkSecurityGroups",
             self.prefix + "-nsg"),
            ("Microsoft.Network", "virtualNetworks",
             self.prefix + "-vnet"),
            ("Microsoft.Network", "networkInterfaces",
             self.prefix + "-peer-nic"),
            ("Microsoft.Network", "networkInterfaces",
             self.prefix + "-guest-nic"),
            ("Microsoft.Compute", "virtualMachines", self.peer_vm),
        )
        return [
            self.expected_resource_id(provider, resource_type, name)
            for provider, resource_type, name in resources
        ]

    def require_peer_deployment_proof(self, receipt, *, complete):
        fields = PEER_DEPLOYMENT_PROOF_FIELDS
        if complete:
            fields |= PEER_DEPLOYMENT_IDENTITY_FIELDS
        if not isinstance(receipt, dict) or set(receipt) != fields:
            raise RuntimeError(
                "Private peer deployment provenance is incomplete"
            )
        expected_deployment_id = self.expected_resource_id(
            "Microsoft.Resources", "deployments", self.prefix + "-peer"
        )
        expected_resources = self.expected_peer_deployment_resource_ids()
        if (
            str(receipt["deployment_id"]).lower()
            != expected_deployment_id.lower()
            or self.require_resource_uuid(
                receipt["correlation_id"],
                "Private peer deployment correlation",
            ) != receipt["correlation_id"]
            or not isinstance(receipt["declared_resource_ids"], list)
            or [str(value).lower()
                for value in receipt["declared_resource_ids"]]
            != [value.lower() for value in expected_resources]
        ):
            raise RuntimeError("Private peer deployment provenance is invalid")
        if complete:
            expected_vm_id = self.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", self.peer_vm
            )
            expected_disk_id = self.expected_resource_id(
                "Microsoft.Compute", "disks", self.prefix + "-peer-os"
            )
            if (
                str(receipt["peer_vm_id"]).lower()
                != expected_vm_id.lower()
                or str(receipt["peer_disk_id"]).lower()
                != expected_disk_id.lower()
                or self.require_resource_uuid(
                    receipt["peer_vm_uuid"], "Private peer VM identity"
                ) != receipt["peer_vm_uuid"]
                or self.require_resource_uuid(
                    receipt["peer_disk_uuid"], "Private peer disk identity"
                ) != receipt["peer_disk_uuid"]
            ):
                raise RuntimeError(
                    "Private peer deployment identity is invalid"
                )
        return receipt

    @staticmethod
    def require_resource_uuid(value, description):
        if not isinstance(value, str):
            raise RuntimeError(f"{description} is unavailable")
        try:
            parsed = uuid.UUID(value)
        except ValueError:
            raise RuntimeError(f"{description} is invalid") from None
        if parsed.int == 0:
            raise RuntimeError(f"{description} is invalid")
        return str(parsed)

    @staticmethod
    def deployment_output(properties, name, description):
        outputs = properties.get("outputs")
        output = outputs.get(name) if isinstance(outputs, dict) else None
        if (
            not isinstance(output, dict)
            or str(output.get("type", "")).lower() != "string"
            or not isinstance(output.get("value"), str)
        ):
            raise RuntimeError(f"{description} is unavailable")
        return output["value"]

    def peer_deployment_receipt(self, deployment):
        if not isinstance(deployment, dict):
            raise RuntimeError("Private peer deployment provenance is unavailable")
        properties = deployment.get("properties")
        expected_name = self.prefix + "-peer"
        expected_id = self.expected_resource_id(
            "Microsoft.Resources", "deployments", expected_name
        )
        if (
            deployment.get("name") != expected_name
            or str(deployment.get("id", "")).lower() != expected_id.lower()
            or not isinstance(properties, dict)
            or properties.get("provisioningState") != "Succeeded"
        ):
            raise RuntimeError("Private peer deployment provenance is invalid")
        output_resources = properties.get("outputResources")
        if not isinstance(output_resources, list):
            raise RuntimeError(
                "Private peer deployment resource provenance is unavailable"
            )
        actual_resources = []
        for resource in output_resources:
            if not isinstance(resource, dict) or not isinstance(
                resource.get("id"), str
            ):
                raise RuntimeError(
                    "Private peer deployment resource provenance is invalid"
                )
            actual_resources.append(resource["id"])
        expected_resources = self.expected_peer_deployment_resource_ids()
        if (
            len({value.lower() for value in actual_resources})
            != len(actual_resources)
            or {value.lower() for value in actual_resources}
            != {value.lower() for value in expected_resources}
        ):
            raise RuntimeError(
                "Private peer deployment resource provenance is invalid"
            )
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.peer_vm
        )
        expected_disk_id = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.prefix + "-peer-os"
        )
        output_vm_id = self.deployment_output(
            properties, "peerVmId", "Private peer deployment VM identity"
        )
        output_disk_id = self.deployment_output(
            properties, "peerDiskId", "Private peer deployment disk identity"
        )
        if (
            output_vm_id.lower() != expected_vm_id.lower()
            or output_disk_id.lower() != expected_disk_id.lower()
        ):
            raise RuntimeError(
                "Private peer deployment immutable resource identity is invalid"
            )
        return {
            "deployment_id": expected_id,
            "correlation_id": self.require_resource_uuid(
                properties.get("correlationId"),
                "Private peer deployment correlation",
            ),
            "declared_resource_ids": expected_resources,
            "peer_vm_id": expected_vm_id,
            "peer_vm_uuid": self.require_resource_uuid(
                self.deployment_output(
                    properties, "peerVmUuid",
                    "Private peer deployment VM UUID",
                ),
                "Private peer deployment VM UUID",
            ),
            "peer_disk_id": expected_disk_id,
            "peer_disk_uuid": self.require_resource_uuid(
                self.deployment_output(
                    properties, "peerDiskUuid",
                    "Private peer deployment disk UUID",
                ),
                "Private peer deployment disk UUID",
            ),
        }

    def verify_peer_deployment_for_cleanup(self, receipt):
        self.require_peer_deployment_proof(receipt, complete=True)
        deployment = self.az([
            "deployment", "group", "show",
            "--resource-group", self.group,
            "--name", self.prefix + "-peer",
        ], private=True, timeout=120)
        if self.peer_deployment_receipt(deployment) != receipt:
            raise RuntimeError(
                "Refusing to clean a peer whose original deployment changed"
            )

    def guest_deployment_receipt(self, deployment, guest_nic_id):
        if not isinstance(deployment, dict):
            raise RuntimeError(
                "Private guest deployment provenance is unavailable"
            )
        properties = deployment.get("properties")
        expected_id = self.expected_resource_id(
            "Microsoft.Resources", "deployments", self.prefix
        )
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.vm
        )
        if (
            deployment.get("name") != self.prefix
            or str(deployment.get("id", "")).lower()
            != expected_id.lower()
            or not isinstance(properties, dict)
            or properties.get("provisioningState") != "Succeeded"
            or not isinstance(guest_nic_id, str)
            or not isinstance(self.state.get("disk_id"), str)
        ):
            raise RuntimeError("Private guest deployment provenance is invalid")
        output_resources = properties.get("outputResources")
        if (
            not isinstance(output_resources, list)
            or len(output_resources) != 1
            or not isinstance(output_resources[0], dict)
            or str(output_resources[0].get("id", "")).lower()
            != expected_vm_id.lower()
        ):
            raise RuntimeError(
                "Private guest deployment resource provenance is invalid"
            )
        output_vm_id = self.deployment_output(
            properties, "vmId", "Private guest deployment VM identity"
        )
        output_disk_id = self.deployment_output(
            properties, "osDiskId", "Private guest deployment disk identity"
        )
        output_nic_id = self.deployment_output(
            properties, "nicId", "Private guest deployment NIC identity"
        )
        if (
            output_vm_id.lower() != expected_vm_id.lower()
            or output_disk_id.lower() != self.state["disk_id"].lower()
            or output_nic_id.lower() != guest_nic_id.lower()
        ):
            raise RuntimeError(
                "Private guest deployment immutable resource identity is invalid"
            )
        return {
            "deployment_id": expected_id,
            "correlation_id": self.require_resource_uuid(
                properties.get("correlationId"),
                "Private guest deployment correlation",
            ),
            "declared_resource_ids": [expected_vm_id],
            "vm_id": expected_vm_id,
            "vm_uuid": self.require_resource_uuid(
                self.deployment_output(
                    properties, "vmUuid",
                    "Private guest deployment VM UUID",
                ),
                "Private guest deployment VM UUID",
            ),
            "disk_id": self.state["disk_id"],
            "disk_uuid": self.require_uploaded_disk_proof()["disk_uuid"],
            "nic_id": guest_nic_id,
        }

    def require_guest_deployment_proof(self, receipt):
        if not isinstance(receipt, dict) or set(receipt) != GUEST_DEPLOYMENT_FIELDS:
            raise RuntimeError(
                "Private guest deployment provenance is incomplete"
            )
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.vm
        )
        expected_deployment_id = self.expected_resource_id(
            "Microsoft.Resources", "deployments", self.prefix
        )
        if (
            str(receipt["deployment_id"]).lower()
            != expected_deployment_id.lower()
            or receipt["declared_resource_ids"] != [expected_vm_id]
            or str(receipt["vm_id"]).lower() != expected_vm_id.lower()
            or self.require_resource_uuid(
                receipt["correlation_id"],
                "Private guest deployment correlation",
            ) != receipt["correlation_id"]
            or self.require_resource_uuid(
                receipt["vm_uuid"], "Private guest VM identity"
            ) != receipt["vm_uuid"]
            or receipt["disk_id"] != self.state.get("disk_id")
            or receipt["disk_uuid"]
            != self.require_uploaded_disk_proof()["disk_uuid"]
            or receipt["nic_id"] != self.state.get("guest_nic_id")
        ):
            raise RuntimeError("Private guest deployment provenance is invalid")
        return receipt

    def verify_guest_deployment_for_cleanup(self, receipt):
        self.require_guest_deployment_proof(receipt)
        deployment = self.az([
            "deployment", "group", "show",
            "--resource-group", self.group, "--name", self.prefix,
        ], private=True, timeout=120)
        if self.guest_deployment_receipt(
            deployment, receipt["nic_id"]
        ) != receipt:
            raise RuntimeError(
                "Refusing to clean a guest whose original deployment changed"
            )

    def verify_guest_vm_identity(self, vm, receipt):
        self.require_guest_deployment_proof(receipt)
        self.require_owned(vm)
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        interfaces = vm.get(
            "networkProfile", {}
        ).get("networkInterfaces")
        security = vm.get("securityProfile")
        if (
            str(vm.get("id", "")).lower() != receipt["vm_id"].lower()
            or self.require_resource_uuid(
                vm.get("vmId"), "Private guest VM identity"
            ) != receipt["vm_uuid"]
            or str(attached or "").lower() != receipt["disk_id"].lower()
            or vm.get("hardwareProfile", {}).get("vmSize")
            != self.state["vm_size"]
            or (
                security is not None
                and (
                    not isinstance(security, dict)
                    or security.get("securityType") != "Standard"
                )
            )
            or not isinstance(interfaces, list)
            or len(interfaces) != 1
            or str(interfaces[0].get("id", "")).lower()
            != receipt["nic_id"].lower()
        ):
            raise RuntimeError(
                "Private guest VM identity or attachment is invalid"
            )

    def wait_for_guest_provisioning(self, receipt, deadline):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            vm = self.az([
                "vm", "show", "--resource-group", self.group,
                "--name", self.vm,
            ], private=True, timeout=min(120, remaining))
            if time.monotonic() >= deadline:
                break
            self.verify_guest_vm_identity(vm, receipt)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            disk = self.az([
                "disk", "show", "--resource-group", self.group,
                "--name", self.disk,
            ], private=True, timeout=min(120, remaining))
            if time.monotonic() >= deadline:
                break
            self.verify_uploaded_disk_identity(
                disk, attached_vm_id=receipt["vm_id"]
            )
            if self.provisioning_ready(vm, "Private guest VM"):
                return
            time.sleep(min(10, max(0, deadline - time.monotonic())))
        raise RuntimeError(
            "Timed out waiting for private guest provisioning readiness"
        )

    def verify_peer_vm_identity(self, peer_vm, peer_image, receipt=None):
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.peer_vm
        )
        expected_disk_id = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.prefix + "-peer-os"
        )
        self.require_owned(peer_vm)
        image_reference = (
            peer_vm.get("storageProfile", {}).get("imageReference", {})
        )
        attached_disk_id = (
            peer_vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        peer_vm_uuid = self.require_resource_uuid(
            peer_vm.get("vmId"), "Private peer VM identity"
        )
        if (
            str(peer_vm.get("id", "")).lower() != expected_vm_id.lower()
            or str(attached_disk_id or "").lower()
            != expected_disk_id.lower()
            or peer_vm.get("hardwareProfile", {}).get("vmSize")
            != network.PEER_VM_SIZE
            or any(
                image_reference.get(key) != peer_image[key]
                for key in ("publisher", "offer", "sku", "version")
            )
            or (
                receipt is not None
                and peer_vm_uuid != receipt["peer_vm_uuid"]
            )
        ):
            raise RuntimeError(
                "Private peer VM did not use its proven identity, "
                "pinned image and size"
            )
        return peer_vm_uuid

    def verify_peer_disk_identity(self, peer_disk, receipt=None):
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.peer_vm
        )
        expected_disk_id = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.prefix + "-peer-os"
        )
        self.require_owned_if_tagged(peer_disk)
        peer_disk_uuid = self.require_resource_uuid(
            peer_disk.get("uniqueId"), "Private peer disk identity"
        )
        if (
            str(peer_disk.get("id", "")).lower()
            != expected_disk_id.lower()
            or str(peer_disk.get("managedBy", "")).lower()
            != expected_vm_id.lower()
            or (
                receipt is not None
                and peer_disk_uuid != receipt["peer_disk_uuid"]
            )
        ):
            raise RuntimeError(
                "Private peer OS disk is detached or replaced or unproven"
            )
        return peer_disk_uuid

    @staticmethod
    def provisioning_ready(vm, description):
        state = vm.get("provisioningState")
        if state == "Succeeded":
            return True
        if state in PEER_TRANSIENT_PROVISIONING_STATES:
            return False
        raise RuntimeError(
            f"{description} entered a terminal or invalid provisioning state"
        )

    def wait_for_peer_provisioning(self, peer_image, receipt, deadline):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            peer_vm = self.az([
                "vm", "show", "--resource-group", self.group,
                "--name", self.peer_vm,
            ], private=True, timeout=min(120, remaining))
            self.verify_peer_vm_identity(peer_vm, peer_image, receipt)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            peer_disk = self.az([
                "disk", "show", "--resource-group", self.group,
                "--name", self.prefix + "-peer-os",
            ], private=True, timeout=min(120, remaining))
            self.verify_peer_disk_identity(peer_disk, receipt)
            if time.monotonic() >= deadline:
                break
            if self.provisioning_ready(peer_vm, "Private peer VM"):
                return
            time.sleep(min(10, max(0, deadline - time.monotonic())))
        raise RuntimeError(
            "Timed out waiting for private peer provisioning readiness"
        )

    def verified_peer_disk_for_cleanup(self, resource):
        receipt = self.state.get("peer_deployment")
        self.require_peer_deployment_proof(receipt, complete=True)
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.peer_vm
        )
        expected_disk_id = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.prefix + "-peer-os"
        )
        if (
            str(resource.get("id", "")).lower() != expected_disk_id.lower()
            or resource.get("name") != self.prefix + "-peer-os"
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/disks"
        ):
            raise RuntimeError(
                "Refusing to clean an unproven private peer OS disk"
            )
        self.require_owned_if_tagged(resource)
        peer_vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.peer_vm,
        ], private=True, timeout=120)
        peer_image = self.state.get("network_preflight", {}).get("peer_image")
        if isinstance(peer_image, dict):
            self.verify_peer_vm_identity(peer_vm, peer_image, receipt)
        else:
            self.require_owned(peer_vm)
            attached_disk_id = (
                peer_vm.get("storageProfile", {}).get("osDisk", {})
                .get("managedDisk", {}).get("id")
            )
            if (
                str(peer_vm.get("id", "")).lower() != expected_vm_id.lower()
                or peer_vm.get("vmId") != receipt["peer_vm_uuid"]
                or str(attached_disk_id or "").lower()
                != expected_disk_id.lower()
            ):
                raise RuntimeError(
                    "Refusing to clean a detached or replaced "
                    "private peer OS disk"
                )
        disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", self.prefix + "-peer-os",
        ], private=True, timeout=120)
        self.verify_peer_disk_identity(disk, receipt)
        return peer_vm

    def deploy_network_peer(self, network_config, peer_image, deadline):
        peer_script = read_regular_file(
            network.PEER_SCRIPT, 4 * 1024 * 1024,
            "Pinned Hyper-V network peer"
        )
        bootstrap = network.peer_bootstrap(
            peer_script, self.state["acceptance"], network_config
        )
        password = (
            "Uk!" + secrets.token_urlsafe(32) + "a7"
        )
        parameters = {
            "namePrefix": self.prefix,
            "location": self.state["location"],
            "imageSha256": self.state["image_sha256"],
            "peerIPAddress": network_config["peer_ipv4"],
            "guestIPAddress": network_config["guest_ipv4"],
            "subnetPrefix": network_config["subnet"],
            "tcpPort": network_config["tcp_port"],
            "udpPort": network_config["udp_port"],
            "peerImageVersion": peer_image["version"],
            "peerCustomData": base64.b64encode(bootstrap.encode()).decode("ascii"),
            "adminPassword": password,
        }
        self.record("deploying-peer")
        with self.private_parameters(parameters) as parameter_file:
            deployment = self.az([
                "deployment", "group", "create", "--resource-group", self.group,
                "--name", self.prefix + "-peer", "--mode", "Incremental",
                "--template-file",
                str(SUPPORT / "azure" / "hyperv-network-peer.json"),
                "--parameters", "@" + str(parameter_file),
            ], private=True, timeout=self.deadline_timeout(deadline, 300))
        deployment_receipt = self.peer_deployment_receipt(deployment)
        self.record(
            "peer-deployment-succeeded",
            peer_deployment=deployment_receipt,
        )
        password = None

        peer_vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.peer_vm,
        ], private=True, timeout=self.deadline_timeout(deadline, 120))
        self.require_before_deadline(deadline, "private peer VM inspection")
        self.verify_peer_vm_identity(
            peer_vm, peer_image, deployment_receipt
        )
        peer_disk_name = self.prefix + "-peer-os"
        peer_disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", peer_disk_name,
        ], private=True, timeout=self.deadline_timeout(deadline, 120))
        self.require_before_deadline(deadline, "private peer disk inspection")
        self.verify_peer_disk_identity(peer_disk, deployment_receipt)
        self.record(
            "peer-resources-verified",
            peer_deployment=deployment_receipt,
        )
        self.wait_for_peer_provisioning(
            peer_image, deployment_receipt, deadline
        )

        peer_nic_name = self.prefix + "-peer-nic"
        guest_nic_name = self.prefix + "-guest-nic"
        nics = {}
        for name, address in (
            (peer_nic_name, network_config["peer_ipv4"]),
            (guest_nic_name, network_config["guest_ipv4"]),
        ):
            nic = self.az([
                "network", "nic", "show", "--resource-group", self.group,
                "--name", name,
            ], private=True, timeout=self.deadline_timeout(deadline, 120))
            self.require_before_deadline(
                deadline, "private network interface inspection"
            )
            self.require_owned(nic)
            configurations = nic.get("ipConfigurations")
            if (
                not isinstance(configurations, list)
                or len(configurations) != 1
                or configurations[0].get("privateIPAddress") != address
                or configurations[0].get("privateIPAllocationMethod") != "Static"
                or configurations[0].get("publicIPAddress") is not None
            ):
                raise RuntimeError("Private network NIC does not match its static address")
            nics[name] = nic
        self.record(
            "peer-created",
            peer_deployment=deployment_receipt,
            peer_vm_id=deployment_receipt["peer_vm_id"],
            peer_disk_id=deployment_receipt["peer_disk_id"],
            peer_nic_id=nics[peer_nic_name]["id"],
            guest_nic_id=nics[guest_nic_name]["id"],
        )

    def deploy_vm(self, guest_nic_id=None, deadline=None):
        self.record("deploying-vm")
        disk_arguments = [
            "disk", "show", "--resource-group", self.group,
            "--name", self.disk,
        ]
        if deadline is None:
            disk = self.az(disk_arguments)
        else:
            disk = self.az(
                disk_arguments,
                timeout=self.deadline_timeout(deadline, 120),
            )
            self.require_before_deadline(
                deadline, "uploaded guest disk inspection"
            )
        self.verify_uploaded_disk_identity(disk)
        parameters = [
            f"namePrefix={self.prefix}", f"location={self.state['location']}",
            f"osDiskId={self.state['disk_id']}",
            f"imageSha256={self.state['image_sha256']}",
            f"vmSize={self.state['vm_size']}",
        ]
        if guest_nic_id is not None:
            parameters.append(f"existingNicId={guest_nic_id}")
        deployment = self.az([
            "deployment", "group", "create", "--resource-group", self.group,
            "--name", self.prefix, "--mode", "Incremental",
            "--template-file", str(SUPPORT / "azure" / "hyperv-gen2.json"),
            "--parameters", *parameters,
        ], timeout=(
            900 if deadline is None else self.deadline_timeout(deadline, 300)
        ))
        if deadline is not None:
            receipt = self.guest_deployment_receipt(
                deployment, guest_nic_id
            )
            self.record(
                "guest-deployment-succeeded",
                guest_deployment=receipt,
            )
            self.wait_for_guest_provisioning(receipt, deadline)
            self.record("vm-created", vm_id=receipt["vm_id"])
            return
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
        if guest_nic_id is not None:
            interfaces = vm.get("networkProfile", {}).get("networkInterfaces")
            if (
                not isinstance(interfaces, list)
                or len(interfaces) != 1
                or str(interfaces[0].get("id", "")).lower()
                != guest_nic_id.lower()
            ):
                raise RuntimeError("Guest VM is not attached to the reserved private NIC")
        self.record("vm-created", vm_id=vm["id"])

    def verified_guest_for_cleanup(self, resources):
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.vm
        )
        candidates = [
            resource for resource in resources
            if (
                str(resource.get("id", "")).lower()
                == expected_vm_id.lower()
                or resource.get("name") == self.vm
            )
        ]
        if len(candidates) > 1:
            raise RuntimeError("Refusing to clean an unproven guest VM")
        receipt = self.state.get("guest_deployment")
        vm_id = self.state.get("vm_id")
        if not candidates and receipt is None and vm_id is None:
            return None
        if len(candidates) != 1:
            raise RuntimeError("Refusing to clean an unproven guest VM")
        self.require_guest_deployment_proof(receipt)
        if (
            vm_id is not None
            and (
                not isinstance(vm_id, str)
                or vm_id.lower() != receipt["vm_id"].lower()
            )
        ):
            raise RuntimeError("Refusing to clean an unproven guest VM")
        resource = candidates[0]
        if (
            str(resource.get("id", "")).lower()
            != receipt["vm_id"].lower()
            or resource.get("name") != self.vm
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/virtualmachines"
        ):
            raise RuntimeError("Refusing to clean an unproven guest VM")
        self.require_owned(resource)
        self.verify_guest_deployment_for_cleanup(receipt)
        vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.vm,
        ], private=True, timeout=120)
        self.verify_guest_vm_identity(vm, receipt)
        if vm_id is None:
            self.record(
                "guest-cleanup-identity-verified",
                vm_id=receipt["vm_id"],
            )
        return receipt["vm_id"]

    def verified_uploaded_disk_for_cleanup(
        self, resources, attached_vm_id,
    ):
        expected_id = self.expected_uploaded_disk_id()
        candidates = [
            resource for resource in resources
            if (
                str(resource.get("id", "")).lower() == expected_id.lower()
                or resource.get("name") == self.disk
            )
        ]
        receipt = self.state.get("uploaded_disk")
        disk_id = self.state.get("disk_id")
        if not candidates and receipt is None and disk_id is None:
            return None
        if len(candidates) != 1:
            raise RuntimeError(
                "Refusing to clean a missing or unproven uploaded disk"
            )
        receipt = self.require_uploaded_disk_proof(receipt)
        resource = candidates[0]
        if (
            str(resource.get("id", "")).lower()
            != receipt["disk_id"].lower()
            or resource.get("name") != self.disk
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/disks"
        ):
            raise RuntimeError(
                "Refusing to clean a missing or unproven uploaded disk"
            )
        self.require_owned(resource)
        disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", self.disk,
        ], private=True, timeout=120)
        self.verify_uploaded_disk_identity(
            disk, attached_vm_id=attached_vm_id, require_ready=False
        )
        return resource

    def verified_peer_for_cleanup(self, resources):
        expected_vm_id = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.peer_vm
        )
        expected_disk_id = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.prefix + "-peer-os"
        )
        vm_candidates = [
            resource for resource in resources
            if (
                str(resource.get("id", "")).lower()
                == expected_vm_id.lower()
                or resource.get("name") == self.peer_vm
            )
        ]
        disk_name = self.prefix + "-peer-os"
        disk_candidates = [
            resource for resource in resources
            if (
                str(resource.get("id", "")).lower()
                == expected_disk_id.lower()
                or resource.get("name") == disk_name
            )
        ]
        if len(vm_candidates) > 1 or len(disk_candidates) > 1:
            raise RuntimeError(
                "Refusing to clean unproven private peer resources"
            )
        receipt = self.state.get("peer_deployment")
        receipt_fields = set(receipt) if isinstance(receipt, dict) else set()
        complete_fields = (
            PEER_DEPLOYMENT_PROOF_FIELDS
            | PEER_DEPLOYMENT_IDENTITY_FIELDS
        )
        if receipt is not None and receipt_fields != complete_fields:
            raise RuntimeError(
                "Refusing to clean unproven, detached or replaced "
                "private peer resources"
            )
        if not vm_candidates and not disk_candidates and not receipt_fields:
            return None, None, set(), None
        if (
            len(vm_candidates) != 1
            or len(disk_candidates) != 1
            or receipt_fields != complete_fields
        ):
            raise RuntimeError(
                "Refusing to clean unproven, detached or replaced "
                "private peer resources"
            )
        vm_resource = vm_candidates[0]
        disk_resource = disk_candidates[0]
        if (
            str(vm_resource.get("id", "")).lower()
            != expected_vm_id.lower()
            or vm_resource.get("name") != self.peer_vm
            or str(vm_resource.get("type", "")).lower()
            != "microsoft.compute/virtualmachines"
            or str(disk_resource.get("id", "")).lower()
            != expected_disk_id.lower()
            or disk_resource.get("name") != disk_name
            or str(disk_resource.get("type", "")).lower()
            != "microsoft.compute/disks"
        ):
            raise RuntimeError(
                "Refusing to clean unproven private peer resources"
            )
        self.require_owned(vm_resource)
        self.require_owned_if_tagged(disk_resource)
        self.verify_peer_deployment_for_cleanup(receipt)
        self.verified_peer_disk_for_cleanup(disk_resource)
        deallocation_error = None
        try:
            self.az([
                "vm", "deallocate", "--resource-group", self.group,
                "--name", self.peer_vm, "--no-wait",
            ], private=True, timeout=120)
        except BaseException as error:
            deallocation_error = error
        allowed = {
            value.lower() for value in receipt["declared_resource_ids"]
        }
        allowed.add(receipt["peer_disk_id"].lower())
        return disk_resource, receipt["peer_vm_id"], allowed, deallocation_error

    def verified_peer_vm_extension(self, resource, peer_vm_id):
        if (
            str(resource.get("type", "")).lower()
            != "microsoft.compute/virtualmachines/extensions"
        ):
            return False
        resource_id = str(resource.get("id", ""))
        prefix = peer_vm_id.rstrip("/") + "/extensions/"
        if not resource_id.lower().startswith(prefix.lower()):
            return False
        child = resource_id[len(prefix):]
        if not child or "/" in child:
            return False
        if resource.get("tags") in (None, {}):
            return True
        try:
            self.require_owned(resource)
        except RuntimeError:
            return False
        return True

    def cleanup(self):
        if self.az(["group", "exists", "--name", self.group]) is False:
            self.record("cleaned")
            return
        group = self.az(["group", "show", "--name", self.group])
        reservation_claim = self.state.get("reservation_claim")
        original_reservation = (
            isinstance(reservation_claim, dict)
            and str(group.get("id", "")).lower()
            == str(reservation_claim.get("resource_group_id", "")).lower()
            and group.get("tags") == reservation_claim.get("original_tags")
        )
        if not original_reservation:
            self.require_owned_group(group)
        resources = self.az(["resource", "list", "--resource-group", self.group])
        if original_reservation and resources:
            raise RuntimeError(
                "Refusing to clean a reservation that changed before its claim"
            )
        network_mode = (
            network.validate_acceptance(
                self.state.get(
                    "acceptance",
                    {"mode": network.RAW_ACCEPTANCE_MODE},
                )
            )["mode"] == network.NETWORK_ACCEPTANCE_MODE
        )
        verified_peer_disk = None
        verified_peer_vm_id = None
        deallocation_error = None
        allowed_network_resource_ids = set()
        if network_mode:
            validation_failures = []
            try:
                (
                    verified_peer_disk,
                    verified_peer_vm_id,
                    peer_ids,
                    deallocation_error,
                ) = self.verified_peer_for_cleanup(resources)
                allowed_network_resource_ids.update(peer_ids)
            except BaseException as error:
                validation_failures.append(("private peer", error))

            verified_guest_vm_id = None
            try:
                verified_guest_vm_id = self.verified_guest_for_cleanup(
                    resources
                )
                if verified_guest_vm_id is not None:
                    allowed_network_resource_ids.add(
                        verified_guest_vm_id.lower()
                    )
            except BaseException as error:
                validation_failures.append(("private guest", error))

            attached_vm_id = verified_guest_vm_id
            if attached_vm_id is None:
                try:
                    attached_vm_id = self.require_guest_deployment_proof(
                        self.state.get("guest_deployment")
                    )["vm_id"]
                except BaseException:
                    attached_vm_id = None
            try:
                uploaded_disk = self.verified_uploaded_disk_for_cleanup(
                    resources, attached_vm_id
                )
                if uploaded_disk is not None:
                    allowed_network_resource_ids.add(
                        str(uploaded_disk["id"]).lower()
                    )
            except BaseException as error:
                validation_failures.append(("uploaded guest disk", error))

            if validation_failures:
                validation_error = CleanupValidationError(
                    validation_failures, self.private_failure_values()
                )
                if deallocation_error is not None:
                    raise CleanupOperationError(
                        deallocation_error, validation_error,
                        self.private_failure_values(),
                    ) from None
                raise validation_error from None
        try:
            for resource in resources:
                if resource is verified_peer_disk:
                    continue
                if (
                    network_mode and verified_peer_vm_id is not None
                    and self.verified_peer_vm_extension(
                        resource, verified_peer_vm_id
                    )
                ):
                    continue
                if (
                    network_mode
                    and str(resource.get("id", "")).lower()
                    not in allowed_network_resource_ids
                ):
                    raise RuntimeError(
                        "Refusing to clean an unproven resource"
                    )
                try:
                    self.require_owned(resource)
                except RuntimeError:
                    if not network_mode:
                        raise
                    raise RuntimeError(
                        "Refusing to clean an unproven resource"
                    ) from None
            self.record("deleting-group")
            self.az(
                ["group", "delete", "--name", self.group, "--yes"],
                timeout=900,
            )
            if self.az(["group", "exists", "--name", self.group]) is not False:
                raise RuntimeError("Resource group deletion has not completed")
        except BaseException as cleanup_error:
            if deallocation_error is not None:
                raise CleanupOperationError(
                    deallocation_error, cleanup_error,
                    self.private_failure_values(),
                ) from None
            raise
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

    def network_boot_log(self, vm, deadline):
        try:
            text = self.az([
                "vm", "boot-diagnostics", "get-boot-log",
                "--resource-group", self.group, "--name", vm,
            ], private=True, timeout=self.deadline_timeout(deadline, 120))
            self.require_before_deadline(
                deadline, "private boot diagnostics query"
            )
        except AzureCliError as error:
            if error.code not in (
                "BlobNotFound", "BootDiagnosticsInformationNotAvailable",
            ):
                raise
            return None
        if not isinstance(text, str):
            raise RuntimeError("Azure CLI did not return a JSON serial-log string")
        if len(text.encode("utf-8")) > MAX_LOCAL_LOG_SIZE:
            raise RuntimeError("Serial log exceeded the 4 MiB evidence limit")
        return text

    def wait_for_peer_ready(self, deadline):
        ready_deadline = min(deadline, time.monotonic() + 240)
        self.record("waiting-for-peer-ready")
        while time.monotonic() < ready_deadline:
            text = self.network_boot_log(self.peer_vm, ready_deadline)
            if text is not None:
                save_private_text(self.state_path.parent / "peer-serial.log", text)
                try:
                    result = network.inspect_peer_ready(
                        text, self.state["acceptance"],
                        self.state["network_run"],
                    )
                except network.EvidenceIncomplete:
                    pass
                else:
                    self.record("peer-ready")
                    return result
            time.sleep(min(10, max(0, ready_deadline - time.monotonic())))
        raise RuntimeError(
            "Timed out waiting for the exact private peer READY record"
        )

    def wait_for_network_acceptance(self, deadline):
        self.record("waiting-for-network-acceptance")
        guest_text = None
        peer_text = None
        while time.monotonic() < deadline:
            current_peer = self.network_boot_log(self.peer_vm, deadline)
            if current_peer is not None:
                peer_text = current_peer
                save_private_text(
                    self.state_path.parent / "peer-serial.log", peer_text
                )
            current_guest = self.network_boot_log(self.vm, deadline)
            if current_guest is not None:
                guest_text = current_guest
                save_private_text(
                    self.state_path.parent / "guest-serial.log", guest_text
                )
            if peer_text is not None and guest_text is not None:
                try:
                    evidence = network.correlate_evidence(
                        guest_text, peer_text, self.state["acceptance"],
                        self.state["network_run"],
                    )
                except network.EvidenceIncomplete:
                    pass
                else:
                    safe = {
                        **evidence,
                        "image": {
                            "vhd_sha256": self.state["image_sha256"],
                            "prepared_manifest_sha256": (
                                self.state["prepared_image_import"]["manifest_sha256"]
                            ),
                        },
                        "peer_image": self.state["network_preflight"]["peer_image"],
                        "source": self.state["prepared_image_import"]["source"],
                    }
                    private = {
                        **safe,
                        "run": {
                            "name_prefix": self.prefix,
                            "resource_group": self.group,
                            "guest_vm_id": self.state["vm_id"],
                            "peer_vm_id": self.state["peer_vm_id"],
                        },
                    }
                    save_json(
                        self.state_path.parent / "network-acceptance.json",
                        private,
                    )
                    self.record("accepted", acceptance_stage="io")
                    return safe
            time.sleep(min(10, max(0, deadline - time.monotonic())))
        raise RuntimeError(
            "Timed out waiting for correlated peer and guest network acceptance"
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


@contextmanager
def interrupt_as_exception():
    previous = {}
    received = False

    def interrupted(signum, _frame):
        nonlocal received
        if received:
            return
        received = True
        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, signal.SIG_IGN)
        raise InterruptedError(f"Interrupted by signal {signum}")

    for number in (signal.SIGINT, signal.SIGTERM):
        previous[number] = signal.getsignal(number)
        signal.signal(number, interrupted)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def run_prepared(directory, stage, timeout, keep_resources, *,
                 subscription=None, resource_group_reservation=None,
                 guest_ipv4=None, subnet=None):
    if stage not in ("platform", "io"):
        raise ValueError("Expected platform or io acceptance stage")
    state, state_path = load_state(directory)
    if state.get("phase") != "prepared":
        raise ValueError("Run requires a newly prepared image")
    validate_prepared_run_provenance(state, state_path.parent)
    acceptance = network.validate_acceptance(
        state.get("acceptance", {"mode": network.RAW_ACCEPTANCE_MODE})
    )
    network_mode = acceptance["mode"] == network.NETWORK_ACCEPTANCE_MODE
    if timeout is None:
        timeout = network.PEER_TIMEOUT_SECONDS if network_mode else 300
    maximum_timeout = network.PEER_TIMEOUT_SECONDS if network_mode else 1800
    if not 30 <= timeout <= maximum_timeout:
        raise ValueError(
            f"Expected a timeout between 30 and {maximum_timeout} seconds"
        )
    if network_mode and (
        stage != "io" or keep_resources
        or not isinstance(state.get("prepared_image_import"), dict)
    ):
        raise ValueError(
            "Application-network acceptance requires an imported image, "
            "the io stage, and mandatory cleanup"
        )
    image = state_path.parent / "unikraft.vhd"
    if image_sha256(image) != state["image_sha256"]:
        raise ValueError("Prepared VHD has changed since the local boot")
    check_upload_dependencies()
    if not network_mode:
        if any(value is not None for value in (
            subscription, resource_group_reservation, guest_ipv4, subnet,
        )):
            raise ValueError(
                "Private network options require an application-network image"
            )
        state["subscription"] = check_subscription(
            state["location"], state["vm_size"]
        )
        save_json(state_path, state)
        run = AzureRun(state, state_path)
        try:
            run.create_group()
            run.upload_disk(image)
            if image_sha256(image) != state["image_sha256"]:
                raise ValueError("VHD changed during upload")
            run.deploy_vm()
            result = run.wait_for_boot(stage, timeout)
        except BaseException as primary:
            if state["phase"] != "prepared" and not keep_resources:
                cleanup_after_primary_failure(run, primary)
            raise
        if state["phase"] != "prepared" and not keep_resources:
            run.cleanup()
        return result

    if guest_ipv4 is None or subnet is None:
        raise ValueError(
            "Application-network runs require explicit guest IPv4 and subnet"
        )
    network_run = network.private_network(
        acceptance, guest_ipv4, subnet
    )

    def execute_network_run(reservation=None, reservation_claim=None):
        if reservation is not None:
            if subscription is not None and (
                validate_subscription_id(subscription)
                != reservation["subscription"]
            ):
                raise ValueError(
                    "Explicit subscription does not match the private reservation"
                )
            if reservation["location"] != state["location"]:
                raise ValueError(
                    "Private reservation location does not match imported image state"
                )
            selected_subscription = reservation["subscription"]
            receipt = reservation_claim.bind(
                state["name_prefix"], state["image_sha256"],
                state["prepared_image_import"]["manifest_sha256"],
            )
            state.update(
                phase="claiming-reservation",
                subscription=selected_subscription,
                network_run=network_run,
                resource_group=reservation["resource_group"],
                resource_group_id=reservation["resource_group_id"],
                group_precreated=True,
                reservation_claim=receipt,
            )
            save_durable_json(state_path, state)
            run = AzureRun(state, state_path)
        else:
            if subscription is None:
                raise ValueError(
                    "Application-network runs require --subscription or "
                    "--resource-group-reservation"
                )
            selected_subscription = validate_subscription_id(subscription)
            run = None

        with interrupt_as_exception():
            try:
                preflight = check_network_subscription(
                    state["location"], state["vm_size"],
                    selected_subscription,
                )
                state.update(
                    subscription=selected_subscription,
                    network_run=network_run,
                    network_preflight=preflight,
                )
                save_json(state_path, state)
                if run is None:
                    run = AzureRun(state, state_path)
                    run.create_group()
                else:
                    run.claim_group_reservation(reservation)
                    reservation_claim.mark_consumed()
                run.upload_disk(image)
                if image_sha256(image) != state["image_sha256"]:
                    raise ValueError("VHD changed during upload")
                peer_deadline = time.monotonic() + timeout
                run.deploy_network_peer(
                    network_run, preflight["peer_image"], peer_deadline
                )
                run.wait_for_peer_ready(peer_deadline)
                run.deploy_vm(state["guest_nic_id"], peer_deadline)
                result = run.wait_for_network_acceptance(peer_deadline)
            except BaseException as primary:
                if run is not None and state["phase"] != "prepared":
                    cleanup_after_primary_failure(run, primary)
                raise
            if run is not None and state["phase"] != "prepared":
                run.cleanup()
            return result

    if resource_group_reservation is None:
        return execute_network_run()
    with ResourceGroupReservationClaim(
        resource_group_reservation
    ) as reservation_claim:
        return execute_network_run(
            reservation_claim.reservation, reservation_claim
        )


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
    prepare.add_argument(
        "--solved-config", type=Path,
        help="Bind a solved application-network configuration to the image",
    )
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
    run.add_argument("--timeout", type=int)
    run.add_argument("--keep-resources", action="store_true")
    run.add_argument("--subscription")
    run.add_argument("--resource-group-reservation", type=Path)
    run.add_argument("--guest-ipv4")
    run.add_argument("--subnet")
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
            result = run_prepared(
                args.state_dir, args.stage, args.timeout, args.keep_resources,
                subscription=args.subscription,
                resource_group_reservation=args.resource_group_reservation,
                guest_ipv4=args.guest_ipv4,
                subnet=args.subnet,
            )
            print(json.dumps(result, indent=2))
        elif args.action == "cleanup":
            cleanup_state(args.state_dir)
            print("No Azure resources remain for this run")
    except subprocess.TimeoutExpired:
        raise SystemExit(
            "A bounded subprocess timed out; private command details withheld"
        ) from None
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
