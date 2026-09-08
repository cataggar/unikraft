#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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


class AzureCliError(RuntimeError):
    def __init__(self, arguments, result, private):
        match = re.search(
            r"(?:^ERROR: \(|^ErrorCode:)([A-Za-z][A-Za-z0-9_]{0,79})",
            result.stderr, re.MULTILINE,
        )
        self.code = match.group(1) if match else None
        detail = "credential-bearing output withheld" if private else result.stderr.strip()
        super().__init__(
            f"az {' '.join(arguments[:2])} failed ({result.returncode}): {detail}"
        )


def azure_cli(arguments, *, subscription=None, private=False, env=None,
              timeout=300, raw=False):
    command = [
        "az", *arguments, "--only-show-errors", "--output", "tsv" if raw else "json"
    ]
    if subscription is not None:
        command.extend(("--subscription", subscription))
    environment = os.environ.copy()
    environment["AZURE_CORE_COLLECT_TELEMETRY"] = "false"
    environment["AZURE_LOGGING_ENABLE_LOG_FILE"] = "false"
    environment["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
    if arguments[:3] == ["storage", "blob", "upload"]:
        for name in tuple(environment):
            if name.startswith("AZURE_STORAGE_"):
                del environment[name]
    if env:
        environment.update(env)
    result = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=environment,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise AzureCliError(arguments, result, private)
    if raw:
        return result.stdout
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
    if state.get("schema_version") != 1:
        raise ValueError("Unsupported Azure run state schema")
    configure_tool_directories(directory)
    return state, path


def upload_endpoint(sas):
    parsed = urlsplit(sas)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".blob.core.windows.net")
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.query
        or not parsed.path.strip("/")
    ):
        raise ValueError("Expected an Azure public-cloud HTTPS Blob SAS endpoint")
    return urlunsplit(parsed._replace(query="")), parsed.query


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
        if name not in limits or limits[name]["limit"] - limits[name]["currentValue"] < 2:
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
            endpoint, sas = upload_endpoint(grant["accessSas"])
            self.az([
                "storage", "blob", "upload", "--blob-url", endpoint,
                "--file", str(image), "--type", "page", "--overwrite", "true",
                "--validate-content", "--max-connections", "2", "--no-progress",
            ], private=True, env={"AZURE_STORAGE_SAS_TOKEN": sas}, timeout=1200)
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
        if vm.get("securityProfile", {}).get("securityType") != "Standard":
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
                ], private=True, raw=True,
                    timeout=max(1, min(120, deadline - time.monotonic())))
            except AzureCliError as error:
                if error.code not in ("BlobNotFound", "BootDiagnosticsInformationNotAvailable"):
                    raise
                print(f"Serial console is not ready: {error.code}", file=sys.stderr)
                self.record("waiting-for-boot", serial_wait_code=error.code)
            else:
                if len(text.encode("utf-8")) > 4 * 1024 * 1024:
                    raise RuntimeError("Serial log exceeded the 4 MiB evidence limit")
                (self.state_path.parent / "serial.log").write_text(text)
                result = inspect_boot_log(text)
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


def inspect_boot_log(text):
    lines = [
        ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
        for line in text.splitlines()
    ]
    positions = {
        marker: lines.index(marker)
        for marker in (PLATFORM_READY, BLOCK_READY, NETWORK_READY, IO_READY)
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
        for marker in (PLATFORM_READY, BLOCK_READY, NETWORK_READY, IO_READY)
    )
    ordered = complete and (
        positions[PLATFORM_READY] < positions[BLOCK_READY] < positions[IO_READY]
        and positions[PLATFORM_READY] < positions[NETWORK_READY] < positions[IO_READY]
    )
    if IO_READY in positions and not ordered:
        failures.append("I/O-ready marker is missing its preceding stage markers")
    return {
        "platform_ready": PLATFORM_READY in positions and not crashes,
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
    if state.get("phase") != "prepared" or state.get("local_platform_boot") is not True:
        raise ValueError("Run requires a newly prepared, locally booted image")
    image = state_path.parent / "unikraft.vhd"
    if image_sha256(image) != state["image_sha256"]:
        raise ValueError("Prepared VHD has changed since the local boot")
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


def main():
    parser = argparse.ArgumentParser(
        description="Unikraft Hyper-V/Azure acceptance evidence"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    inspect = subparsers.add_parser("inspect-log")
    inspect.add_argument("log", type=Path)
    inspect.add_argument("--stage", choices=("platform", "io"), default="io")
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
            result = inspect_boot_log(args.log.read_text(errors="replace"))
            print(json.dumps(result, indent=2))
            if not result[f"{args.stage}_ready"]:
                raise SystemExit(1)
        elif args.action == "run":
            if not 30 <= args.timeout <= 1800:
                parser.error("--timeout must be between 30 and 1800 seconds")
            result = run_prepared(
                args.state_dir, args.stage, args.timeout, args.keep_resources
            )
            print(json.dumps(result, indent=2))
        elif args.action == "cleanup":
            state, path = load_state(args.state_dir)
            AzureRun(state, path).cleanup()
            print("Owned Azure resources have been deleted")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
