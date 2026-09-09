#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded private nested-KVM Hyper-V platform preflight controller."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import uuid

import hyperv_private_preflight_runner as host_runner


azure = importlib.import_module("hyperv-azure")

SUPPORT = Path(__file__).resolve().parents[1]
RUNNER_PATH = Path(__file__).with_name("hyperv_private_preflight_runner.py")
TEMPLATE_PATH = SUPPORT / "azure" / "hyperv-private-preflight.json"
INPUT_SCHEMA = "unikraft.hyperv.private-preflight-input"
STATE_SCHEMA = "unikraft.hyperv.private-preflight-state"
RECEIPT_SCHEMA = "unikraft.hyperv.private-preflight-receipt"
HOST_PHASE_SCHEMA = host_runner.SCHEMA
HOST_EVIDENCE_SCHEMA = host_runner.EVIDENCE_SCHEMA
INPUT_MANIFEST = "private-preflight-input.json"
STATE_FILE = "state.json"
LOCATION = "northeurope"
VM_SIZE = "Standard_D2s_v5"
CONTAINER = "preflight"
MAX_ATTEMPT_SECONDS = 60 * 60
MAX_INPUT_BYTES = 248 * 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_BLOB_SAS_BYTES = 4096
TRANSFER_TIMEOUT_SECONDS = 300
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[0-9a-f]{32}")
STORAGE_NAME = re.compile(r"[a-z0-9]{3,24}")
INPUT_NAMES = {
    "qemu": "qemu-system-x86_64",
    "ovmf_code": "OVMF_CODE.fd",
    "ovmf_vars": "OVMF_VARS.fd",
    "capability_raw": "capability.raw",
    "efi": "private.efi",
    "raw": "private.raw",
    "vhd": "private.vhd",
}
PUBLIC_ROLES = ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
PRIVATE_ROLES = ("efi", "raw", "vhd")
ALL_ROLES = PUBLIC_ROLES + PRIVATE_ROLES
BOOT_POLICIES = ("platform-unavailable-v1", "platform-main-zero-v1")
PURPOSE = "private-hyperv-platform-preflight"


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


def validate_input_manifest(value):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "boot_policy", "raw_size",
            "source", "files", "miz", "packaging",
        ),
        "Private-preflight input manifest",
    )
    if (
        value["schema"] != INPUT_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["boot_policy"] not in BOOT_POLICIES
        or type(value["raw_size"]) is not int
        or value["raw_size"] != azure.VIRTUAL_SIZE
    ):
        raise ValueError("Private-preflight input manifest is incompatible")
    files = exact_fields(
        value["files"], ALL_ROLES, "Private-preflight input files"
    )
    source = exact_fields(
        value["source"], ("config_sha256", "source_sha256"),
        "Private-preflight local build source",
    )
    require_sha256(source["config_sha256"], "Solved configuration fingerprint")
    require_sha256(source["source_sha256"], "Local source fingerprint")
    files = {role: file_record(files[role], role) for role in ALL_ROLES}
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
    total = sum(record["size"] for record in files.values())
    if total + MAX_EVIDENCE_BYTES > 256 * 1024 * 1024:
        raise ValueError("Private-preflight staged files exceed 256 MiB")
    if total > MAX_INPUT_BYTES:
        raise ValueError("Private-preflight input allowance is exceeded")
    azure.check_packaging_report(
        value["packaging"], files["efi"]["sha256"], files["vhd"]["size"]
    )
    return {
        **value,
        "source": dict(source),
        "files": files,
        "miz": dict(miz),
        "packaging": dict(value["packaging"]),
        "staged_bytes": total,
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
    expected_names = {INPUT_MANIFEST, *INPUT_NAMES.values()}
    actual_names = {entry.name for entry in input_directory.iterdir()}
    if actual_names != expected_names:
        raise ValueError("Private-preflight input directory has extra or missing files")
    return input_directory, validate_input_manifest(
        azure.parse_strict_json(raw, "Private-preflight input manifest")
    ), raw


def prepare(input_directory, state_directory, miz_path, expected_sha256):
    source, manifest, manifest_bytes = load_input_manifest(
        input_directory, expected_sha256
    )
    miz_path = miz_path.resolve(strict=True)
    if (
        miz_path.is_symlink()
        or not miz_path.is_file()
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
            azure.copy_regular_file(
                source / record["name"], inputs / record["name"],
                record["size"], record["sha256"],
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
        azure.check_packaging_report(
            checked, manifest["files"]["efi"]["sha256"],
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
            "schema_version": 1,
            "phase": "prepared",
            "identity": identity,
            "name_prefix": prefix,
            "location": LOCATION,
            "vm_size": VM_SIZE,
            "image_sha256": manifest["files"]["vhd"]["sha256"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "controller_sha256": azure.image_sha256(Path(__file__)),
            "runner_sha256": azure.image_sha256(RUNNER_PATH),
            "template_sha256": azure.image_sha256(TEMPLATE_PATH),
            "input_manifest": manifest,
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
        path, MAX_MANIFEST_BYTES, "Private-preflight private state"
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
        or state["schema_version"] != 1
        or not isinstance(state.get("name_prefix"), str)
        or not re.fullmatch(r"uk-hvp-[0-9a-f]{12}", state["name_prefix"])
        or not isinstance(state.get("identity"), str)
        or not IDENTITY.fullmatch(state["identity"])
        or state.get("location") != LOCATION
        or state.get("vm_size") != VM_SIZE
        or not isinstance(state.get("input_manifest"), dict)
        or type(state.get("cleanup_required")) is not bool
    ):
        raise ValueError("Private-preflight state is incompatible")
    state["input_manifest"] = validate_input_manifest(state["input_manifest"])
    require_sha256(state.get("manifest_sha256"), "State manifest fingerprint")
    require_sha256(
        state.get("controller_sha256"), "State controller fingerprint"
    )
    require_sha256(state.get("runner_sha256"), "State runner fingerprint")
    require_sha256(state.get("template_sha256"), "State template fingerprint")
    require_sha256(state.get("image_sha256"), "State image fingerprint")
    if (
        state["image_sha256"]
        != state["input_manifest"]["files"]["vhd"]["sha256"]
    ):
        raise ValueError("Private-preflight image binding is incompatible")
    subscription = state.get("subscription")
    if subscription is not None:
        azure.validate_subscription_id(subscription)
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
        or azure.image_sha256(RUNNER_PATH) != state["runner_sha256"]
        or azure.image_sha256(Path(__file__)) != state["controller_sha256"]
        or azure.image_sha256(TEMPLATE_PATH) != state["template_sha256"]
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
    try:
        from azure.core.exceptions import AzureError
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        raise RuntimeError(
            "Pinned azure-storage-blob dependency is unavailable"
        ) from None
    return BlobServiceClient, AzureError


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


def upload_blob_set(
    account_url, sas, container, files, *, create_container, deadline
):
    BlobServiceClient, AzureError = check_blob_dependency()
    try:
        timeout = bounded_timeout(deadline, TRANSFER_TIMEOUT_SECONDS)
        service = BlobServiceClient(
            account_url=account_url, credential=sas,
            retry_total=0, connection_timeout=min(30, timeout),
            read_timeout=min(60, timeout),
        )
        client = service.get_container_client(container)
        if create_container:
            client.create_container(timeout=bounded_timeout(deadline, 60))
        for blob_name, source, expected_size, expected_sha256 in files:
            if (
                source.stat().st_size != expected_size
                or azure.image_sha256(source) != expected_sha256
            ):
                raise ValueError("Blob input changed before upload")
            with source.open("rb") as data:
                client.upload_blob(
                    name=blob_name, data=data, length=expected_size,
                    overwrite=False, validate_content=True,
                    max_concurrency=1,
                    timeout=bounded_timeout(
                        deadline, TRANSFER_TIMEOUT_SECONDS
                    ),
                )
    except ValueError:
        raise
    except AzureError:
        raise RuntimeError("Authenticated private Blob upload failed") from None


def download_blob_bytes(account_url, sas, container, name, maximum, deadline):
    BlobServiceClient, AzureError = check_blob_dependency()
    try:
        timeout = bounded_timeout(deadline, TRANSFER_TIMEOUT_SECONDS)
        service = BlobServiceClient(
            account_url=account_url, credential=sas,
            retry_total=0, connection_timeout=min(30, timeout),
            read_timeout=min(60, timeout),
        )
        downloader = service.get_container_client(container).download_blob(
            name, max_concurrency=1, timeout=timeout
        )
        chunks = []
        total = 0
        for chunk in downloader.chunks():
            total += len(chunk)
            if total > maximum:
                raise ValueError("Private evidence exceeds its size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    except ValueError:
        raise
    except AzureError:
        raise RuntimeError("Authenticated private Blob download failed") from None


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
        self.group_tags.update({
            "purpose": PURPOSE,
            "disposable": "true",
            "private-manifest-sha256": state["manifest_sha256"],
        })

    def phase_timeout(self, maximum):
        return bounded_timeout(self.state["deadline_monotonic"], maximum)

    def az(self, arguments, **kwargs):
        kwargs.setdefault("private", True)
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

    def deploy_host(self, shutdown_time):
        password = "Uk!" + secrets.token_urlsafe(32) + "a7"
        image = self.state["cloud_preflight"]["image"]
        parameters = {
            "namePrefix": self.prefix,
            "location": LOCATION,
            "imageSha256": self.state["image_sha256"],
            "storageAccountName": self.storage,
            "hostImageVersion": image["version"],
            "adminPassword": password,
            "shutdownTime": shutdown_time,
        }
        self.record("deploying-host")
        with self.private_parameters(parameters) as parameter_file:
            deployment = self.az([
                "deployment", "group", "create",
                "--resource-group", self.group,
                "--name", self.prefix + "-host", "--mode", "Incremental",
                "--template-file", str(TEMPLATE_PATH),
                "--parameters", "@" + str(parameter_file),
            ], timeout=self.phase_timeout(900))
        password = None
        expected_deployment = self.expected_resource_id(
            "Microsoft.Resources", "deployments", self.prefix + "-host"
        )
        properties = deployment.get("properties") if isinstance(deployment, dict) else None
        if (
            not isinstance(properties, dict)
            or deployment.get("name") != self.prefix + "-host"
            or str(deployment.get("id", "")).lower()
            != expected_deployment.lower()
            or properties.get("provisioningState") != "Succeeded"
        ):
            raise RuntimeError("Private host deployment provenance is invalid")
        receipt = {
            "deployment_id": expected_deployment,
            "correlation_id": self.require_resource_uuid(
                properties.get("correlationId"),
                "Private host deployment correlation",
            ),
        }
        self.record("host-deployment-succeeded", host_deployment=receipt)
        vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.host_vm,
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        self.require_owned(vm)
        expected_vm = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.host_vm
        )
        expected_disk = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.host_disk
        )
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        image_reference = vm.get("storageProfile", {}).get("imageReference", {})
        security = vm.get("securityProfile")
        if (
            str(vm.get("id", "")).lower() != expected_vm.lower()
            or str(attached or "").lower() != expected_disk.lower()
            or vm.get("provisioningState") != "Succeeded"
            or vm.get("hardwareProfile", {}).get("vmSize") != VM_SIZE
            or vm.get("storageProfile", {}).get("osDisk", {}).get("diskSizeGb") != 32
            or any(
                image_reference.get(key) != image[key]
                for key in ("publisher", "offer", "sku", "version")
            )
            or security is not None and (
                not isinstance(security, dict)
                or security.get("securityType") != "Standard"
            )
        ):
            raise RuntimeError("Private preflight host is incompatible")
        disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", self.host_disk,
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        if (
            str(disk.get("id", "")).lower() != expected_disk.lower()
            or str(disk.get("managedBy") or "").lower() != expected_vm.lower()
            or disk.get("diskSizeGb") != 32
            or disk.get("sku", {}).get("name") != "StandardSSD_LRS"
            or disk.get("tags") not in (None, {}, self.tags)
        ):
            raise RuntimeError("Private host OS disk provenance is invalid")
        receipt.update({
            "vm_id": expected_vm,
            "vm_uuid": self.require_resource_uuid(
                vm.get("vmId"), "Private host VM identity"
            ),
            "disk_id": expected_disk,
            "disk_uuid": self.require_resource_uuid(
                disk.get("uniqueId"), "Private host disk identity"
            ),
        })
        self.record("host-resources-verified", host_deployment=receipt)
        if disk.get("tags") != self.tags:
            disk = self.az([
                "disk", "update", "--resource-group", self.group,
                "--name", self.host_disk, "--tags", *self.resource_tags(),
            ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        self.require_owned(disk)
        if (
            disk.get("uniqueId") != receipt["disk_uuid"]
            or str(disk.get("managedBy") or "").lower() != expected_vm.lower()
        ):
            raise RuntimeError("Private host OS disk changed while tagging")
        nic = self.az([
            "network", "nic", "show", "--resource-group", self.group,
            "--name", self.host_nic,
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        self.require_owned(nic)
        configurations = nic.get("ipConfigurations")
        expected_subnet = (
            self.state["resource_group_id"].rstrip("/")
            + "/providers/Microsoft.Network/virtualNetworks/"
            + self.prefix + "-vnet/subnets/preflight"
        )
        if (
            not isinstance(configurations, list)
            or len(configurations) != 1
            or configurations[0].get("publicIPAddress") is not None
            or configurations[0].get("privateIPAllocationMethod") != "Static"
            or configurations[0].get("privateIPAddress") != "10.88.0.4"
            or str(
                configurations[0].get("subnet", {}).get("id", "")
            ).lower() != expected_subnet.lower()
        ):
            raise RuntimeError("Private preflight NIC exposes public ingress")
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        self.require_owned(storage)
        expected_storage = self.expected_resource_id(
            "Microsoft.Storage", "storageAccounts", self.storage
        )
        if (
            str(storage.get("id", "")).lower() != expected_storage.lower()
            or storage.get("allowBlobPublicAccess") is not False
            or storage.get("allowSharedKeyAccess") is not True
            or storage.get("minimumTlsVersion") != "TLS1_2"
            or storage.get("publicNetworkAccess") != "Enabled"
            or storage.get("supportsHttpsTrafficOnly") is not True
            or storage.get("networkRuleSet", {}).get("defaultAction") != "Deny"
        ):
            raise RuntimeError("Private preflight Blob account is not locked down")
        schedule = self.az([
            "resource", "show", "--resource-group", self.group,
            "--resource-type", "Microsoft.DevTestLab/schedules",
            "--name", "shutdown-computevm-" + self.host_vm,
            "--api-version", "2018-09-15",
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        self.require_owned(schedule)
        schedule_properties = schedule.get("properties", {})
        if (
            schedule_properties.get("status") != "Enabled"
            or str(schedule_properties.get("targetResourceId", "")).lower()
            != expected_vm.lower()
            or schedule_properties.get("dailyRecurrence", {}).get("time")
            != shutdown_time
        ):
            raise RuntimeError("Private host auto-shutdown backstop is invalid")
        self.record(
            "host-created", host_deployment=receipt,
            host_vm_id=expected_vm, host_disk_id=expected_disk,
            host_nic_id=nic["id"], storage_account_id=storage["id"],
            shutdown_schedule_id=schedule["id"],
        )

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
        if values != expected:
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
        attempted = False
        try:
            attempted = True
            self.az([
                "storage", "account", "network-rule", "add",
                "--resource-group", self.group,
                "--account-name", self.storage,
                "--ip-address", transfer_cidr,
            ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
            self.verify_storage_rules(transfer_cidr)
            yield
        finally:
            if attempted:
                self.az([
                    "storage", "account", "network-rule", "remove",
                    "--resource-group", self.group,
                    "--account-name", self.storage,
                    "--ip-address", transfer_cidr,
                ])
                self.verify_storage_rules(enforce_deadline=False)

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
        path = self.state_path.parent / (
            ".run-command-" + secrets.token_hex(8) + ".json"
        )
        azure.save_json(path, value)
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)

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
            "root=/var/lib/unikraft-private-preflight",
            "mkdir -p \"$root\"",
            (
                "printf '%s' "
                + shlex.quote(base64.b64encode(runner_source).decode())
                + " | base64 -d > \"$root/runner.py\""
            ),
            (
                "HYPERV_PREFLIGHT_SAS=" + shlex.quote(sas)
                + " python3 \"$root/runner.py\""
                + " --phase " + shlex.quote(phase)
                + " --manifest-b64 "
                + shlex.quote(base64.b64encode(manifest_bytes).decode())
                + " --blob-base-url "
                + shlex.quote(f"https://{self.storage}.blob.core.windows.net")
                + " --container " + shlex.quote(self.container)
            ),
        ))
        request = {"commandId": "RunShellScript", "script": [script]}
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
        fields = {
            "deployment_id", "correlation_id", "vm_id", "vm_uuid",
            "disk_id", "disk_uuid",
        }
        if not isinstance(receipt, dict) or set(receipt) != fields:
            raise RuntimeError("Refusing to clean an unproven host OS disk")
        expected_disk = self.expected_resource_id(
            "Microsoft.Compute", "disks", self.host_disk
        )
        expected_vm = self.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", self.host_vm
        )
        if (
            str(resource.get("id", "")).lower() != expected_disk.lower()
            or resource.get("name") != self.host_disk
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/disks"
            or resource.get("tags") not in (None, {})
            or str(receipt.get("disk_id", "")).lower()
            != expected_disk.lower()
            or str(receipt.get("vm_id", "")).lower() != expected_vm.lower()
        ):
            raise RuntimeError("Refusing to clean an unproven host OS disk")
        vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.host_vm,
        ])
        self.require_owned(vm)
        disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", self.host_disk,
        ])
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            vm.get("vmId") != receipt["vm_uuid"]
            or str(attached or "").lower() != expected_disk.lower()
            or disk.get("uniqueId") != receipt["disk_uuid"]
            or str(disk.get("managedBy") or "").lower()
            != expected_vm.lower()
            or disk.get("tags") not in (None, {})
        ):
            raise RuntimeError("Refusing to clean a detached or replaced host disk")

    def deallocate_host(self):
        if self.state.get("host_deallocated") is True:
            return
        receipt = self.state.get("host_deployment")
        if not isinstance(receipt, dict) or "vm_uuid" not in receipt:
            return
        vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.host_vm,
        ])
        self.require_owned(vm)
        if vm.get("vmId") != receipt["vm_uuid"]:
            raise RuntimeError("Refusing to deallocate a replaced private host")
        self.az([
            "vm", "deallocate", "--resource-group", self.group,
            "--name", self.host_vm,
        ], timeout=300)
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
        for resource in resources:
            try:
                self.require_owned(resource)
            except RuntimeError:
                self.verified_host_disk_for_cleanup(resource)
        self.record("deleting-group")
        self.az([
            "group", "delete", "--name", self.group, "--yes",
        ], timeout=900)
        if self.az(["group", "exists", "--name", self.group]) is not False:
            raise RuntimeError("Private resource-group deletion did not complete")
        self.record("cleaned", cleanup_required=False)

    def cleanup(self):
        errors = []
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
        "schema_version": 1,
        "phase": phase,
        "identity": state["identity"],
        "runner_sha256": state["runner_sha256"],
        "boot_policy": (
            "platform-unavailable-v1"
            if phase == "capability"
            else input_manifest["boot_policy"]
        ),
        "raw_size": input_manifest["raw_size"],
        "files": files,
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
        or value["runner_sha256"] != state["runner_sha256"]
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
        receipt_bytes = download_blob_bytes(
            f"https://{run.storage}.blob.core.windows.net",
            sas, run.container, prefix + "/receipt.json", MAX_MANIFEST_BYTES,
            run.state["deadline_monotonic"],
        )
        logs = {
            name: download_blob_bytes(
                f"https://{run.storage}.blob.core.windows.net",
                sas, run.container, prefix + "/" + name,
                host_runner.MAX_LOG_BYTES,
                run.state["deadline_monotonic"],
            )
            for name in names
        }
    if len(receipt_bytes) + sum(map(len, logs.values())) > MAX_EVIDENCE_BYTES:
        raise ValueError("Private host evidence exceeds 8 MiB")
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


def run_preflight(state_directory, subscription, transfer_ip):
    state, state_path = load_state(state_directory)
    if state["phase"] != "prepared" or state.get("cleanup_required") is not False:
        raise ValueError("Private preflight requires a fresh prepared state")
    verify_immutable_inputs(state, state_path.parent)
    check_blob_dependency()
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
                    upload_blob_set(
                        account_url, public_token["value"], run.container,
                        blob_files(state, state_path.parent, PUBLIC_ROLES),
                        create_container=True,
                        deadline=state["deadline_monotonic"],
                    )
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
                    upload_blob_set(
                        account_url, private_token["value"], run.container,
                        blob_files(state, state_path.parent, PRIVATE_ROLES),
                        create_container=False,
                        deadline=state["deadline_monotonic"],
                    )
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
            run.deallocate_host()
            final = {
                "schema": RECEIPT_SCHEMA,
                "schema_version": 1,
                "result": "PASS",
                "identity": state["identity"],
                "input_manifest_sha256": state["manifest_sha256"],
                "runner_sha256": state["runner_sha256"],
                "controller_sha256": state["controller_sha256"],
                "template_sha256": state["template_sha256"],
                "source": state["input_manifest"]["source"],
                "inputs": {
                    role: {
                        "sha256": record["sha256"],
                        "size": record["size"],
                    }
                    for role, record in state["input_manifest"]["files"].items()
                },
                "miz": state["input_manifest"]["miz"],
                "host_image": state["cloud_preflight"]["image"],
                "host_vm_uuid": state["host_deployment"]["vm_uuid"],
                "host_disk_uuid": state["host_deployment"]["disk_uuid"],
                "host_boot_id": private_receipt["host_boot_id"],
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
    except (OSError, RuntimeError, ValueError) as error:
        record_private_failure(run, error, state.get("phase", "unknown"))
        raise
    finally:
        if state.get("cleanup_required"):
            try:
                run.cleanup()
            except (OSError, RuntimeError, ValueError) as error:
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
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--state-dir", type=Path, required=True)
    cleanup_parser.add_argument("--subscription", required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(
                args.input_dir, args.state_dir, args.miz,
                args.expected_manifest_sha256,
            )
            print("Private preflight inputs prepared in owner-only state")
        elif args.action == "run":
            run_preflight(
                args.state_dir, args.subscription, args.transfer_source_ip
            )
            print("Private preflight completed; private receipt retained locally")
        else:
            cleanup(args.state_dir, args.subscription)
            print("Private preflight cleanup completed")
    except subprocess.TimeoutExpired:
        raise SystemExit(
            "A bounded private-preflight subprocess timed out; details withheld"
        ) from None
    except (OSError, RuntimeError, ValueError):
        raise SystemExit(
            "Private preflight failed; inspect the owner-only state directory"
        ) from None


if __name__ == "__main__":
    main()
