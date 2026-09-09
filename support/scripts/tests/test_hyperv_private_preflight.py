# SPDX-License-Identifier: BSD-3-Clause

from contextlib import contextmanager
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock


SUPPORT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SUPPORT / "scripts"))
preflight = importlib.import_module("hyperv_private_preflight")
runner = importlib.import_module("hyperv_private_preflight_runner")
blob_worker = importlib.import_module("hyperv_private_preflight_blob")
TEST_TEMP = SUPPORT.parent / ".d" / "private-preflight-test-tmp"
TEST_TEMP.mkdir(mode=0o700, parents=True, exist_ok=True)
tempfile.tempdir = str(TEST_TEMP)
GUARDED_PRODUCER_RECORDS = (
    Path(__file__).with_name("fixtures")
    / "hyperv-guarded-v2-pristine-unavailable.records"
)


def selected_git_executable():
    selected = shutil.which("git")
    if selected is None:
        raise RuntimeError("A Git executable is required by this test")
    ambient = Path(selected).resolve()
    configuration = (
        ambient.parent / "trampoline_configuration" / "git.json"
    )
    if configuration.is_file():
        return Path(json.loads(configuration.read_text())["exe"]).resolve()
    return ambient


def create_git_runtime(root):
    root = Path(root)
    runtime = root / "git-runtime"
    (runtime / "bin").mkdir(parents=True)
    git = selected_git_executable()
    shutil.copy2(git, runtime / preflight.GIT_EXECUTABLE)
    (runtime / "lib").mkdir()
    result = subprocess.run(
        ["ldd", str(git)], capture_output=True, check=True, text=True,
        env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
    )
    loader = None
    libraries = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("linux-vdso.so.1 "):
            continue
        match = re.fullmatch(r"(\S+) => (/.+) \(0x[0-9a-fA-F]+\)", line)
        if match is not None:
            libraries[match.group(1)] = Path(match.group(2)).resolve()
            continue
        match = re.fullmatch(r"(/.+) \(0x[0-9a-fA-F]+\)", line)
        if match is not None:
            loader = Path(match.group(1)).resolve()
            continue
        raise RuntimeError("Unable to stage the test Git runtime")
    if loader is None or not libraries:
        raise RuntimeError("The test Git runtime closure is incomplete")
    shutil.copy2(loader, runtime / preflight.GIT_LOADER)
    for name, source in libraries.items():
        shutil.copy2(source, runtime / "lib" / name)
    (runtime / preflight.GIT_EXECUTABLE).chmod(0o700)
    (runtime / preflight.GIT_LOADER).chmod(0o700)
    for library in libraries:
        (runtime / "lib" / library).chmod(0o600)
    preflight.preflight_git_runtime(runtime)
    return runtime


def fake_git_runtime_record():
    executable = {
        "name": preflight.GIT_EXECUTABLE.as_posix(),
        "sha256": "d" * 64,
        "size": 1,
    }
    loader = {
        "name": preflight.GIT_LOADER.as_posix(),
        "sha256": "e" * 64,
        "size": 1,
    }
    libraries = [{
        "name": "lib/libc.so.6",
        "sha256": "f" * 64,
        "size": 1,
    }]
    members = sorted(
        (executable, loader, *libraries), key=lambda item: item["name"]
    )
    digest = hashlib.sha256()
    for member in members:
        encoded = member["name"].encode()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(member["size"].to_bytes(8, "big"))
        digest.update(bytes.fromhex(member["sha256"]))
    return {
        "schema": preflight.GIT_RUNTIME_SCHEMA,
        "name": preflight.GIT_RUNTIME,
        "sha256": digest.hexdigest(),
        "size": sum(member["size"] for member in members),
        "files": len(members),
        "executable": executable,
        "loader": loader,
        "libraries": libraries,
    }


def modeled_host_disk_output_order(template):
    output = template["outputs"]["hostDiskUuid"]["value"]
    if "reference(resourceId('Microsoft.Compute/disks'" in output:
        raise RuntimeError(
            "ResourceNotFound: implicit disk read can precede VM creation"
        )
    identity = next(
        resource for resource in template["resources"]
        if resource["type"] == "Microsoft.Resources/deployments"
        and resource["name"]
        == "[variables('hostIdentityDeploymentName')]"
    )
    dependency = (
        "[resourceId('Microsoft.Compute/virtualMachines', "
        "variables('hostName'))]"
    )
    if identity.get("dependsOn") != [dependency]:
        raise RuntimeError(
            "ResourceNotFound: implicit disk read lacks a VM dependency"
        )
    properties = identity["properties"]
    if (
        properties.get("expressionEvaluationOptions") != {"scope": "inner"}
        or properties.get("mode") != "Incremental"
        or properties["template"].get("resources") != []
    ):
        raise RuntimeError("Identity deployment is not an output-only inner scope")
    if properties["parameters"] != {
        "hostDiskId": {
            "value": (
                "[reference(variables('hostName'), '2025-11-01')"
                ".storageProfile.osDisk.managedDisk.id]"
            )
        }
    }:
        raise RuntimeError(
            "Identity deployment does not use the VM's returned disk ID"
        )
    if output != (
        "[reference(variables('hostIdentityDeploymentName'), "
        "'2022-09-01').outputs.hostDiskUuid.value]"
    ):
        raise RuntimeError("Outer output does not await identity deployment")
    inner = properties["template"]["outputs"][
        "hostDiskUuid"
    ]["value"]
    if "reference(parameters(" not in inner or ".uniqueId]" not in inner:
        raise RuntimeError("Identity deployment does not read the disk UUID")
    return ("vm-created", "implicit-disk-read", "outer-output")


def base64_encode(value):
    import base64
    return base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).decode()


def packaging_contract(efi_sha256, efi_size, file_size):
    value = preflight.azure.packaging_contract(efi_sha256, file_size)
    value.update({
        "boot-file-size": efi_size,
        "disk-guid": "7e7ff0d3-0472-5a76-a74c-8679a83fafbe",
        "esp-partition-guid": "70a887c3-dd2d-5f06-a5da-bdcfc00a0b5c",
        "esp-volume-id": 159129288,
    })
    return value


def capability_reference(capability, approved=True):
    if approved:
        value = json.loads(json.dumps(
            preflight.APPROVED_CAPABILITY_REFERENCE
        ))
        if value["receipt"]["raw"] != {
            "sha256": capability["sha256"],
            "size": capability["size"],
        }:
            raise ValueError("Fixture capability differs from approved source")
        return value
    receipt = {
        "schema": preflight.CAPABILITY_REFERENCE_SCHEMA,
        "schema_version": 1,
        "scope": (
            "historical nonsecret capability only; "
            "not current private deployment provenance"
        ),
        "source": {
            "provider": "github-actions",
            "repository": "example/unikraft",
            "repository_id": 123,
            "workflow_ref": (
                "example/unikraft/.github/workflows/integration.yaml@"
                "refs/heads/example"
            ),
            "head_sha": "8" * 40,
            "run_id": 456,
            "run_attempt": 1,
            "job": "generic-capability",
        },
        "manifest_sha256": "7" * 64,
        "efi_sha256": "6" * 64,
        "raw": {
            "sha256": capability["sha256"],
            "size": capability["size"],
        },
        "source_vhd": {
            "sha256": "5" * 64,
            "size": capability["size"] + 512,
        },
        "source_boot_evidence": {
            "boots": {
                image: {
                    "legacy-apic": {
                        "apic_path": "legacy-xapic",
                        "io_ready": False,
                        "platform_ready": True,
                    },
                    "x2apic": {
                        "apic_path": "x2apic",
                        "io_ready": False,
                        "platform_ready": True,
                    },
                }
                for image in ("raw", "vhd")
            },
            "platform_marker": preflight.host_runner.PLATFORM_MARKER,
            "scope": "platform-only",
        },
    }
    return {
        "name": preflight.CAPABILITY_REFERENCE,
        "sha256": "4" * 64,
        "size": 1024,
        "receipt": receipt,
    }


def private_build_receipt(provenance, efi, guarded=None):
    receipt = {
        "schema": preflight.PRIVATE_BUILD_SCHEMA,
        "schema_version": preflight.PRIVATE_BUILD_SCHEMA_VERSION,
        "result": "PASS",
        "source_before": provenance,
        "source_after": provenance,
        "invocation": {
            "engine": "zig-native-images-two-pass-v1",
            "passes": 2,
            "jobs": 2,
            "materialization_returncode": 0,
            "recovery": "none",
            "recovery_returncode": None,
            "verification_returncode": 0,
            "app": "support/apps/hyperv-acceptance",
            "profile": "hyperv-x86_64-efi-netvsc",
            "compiler_target": "x86_64-freestanding-none",
            "output": preflight.NATIVE_EFI_NAME,
        },
        "tools": {
            name: {
                "name": name,
                "sha256": f"{index + 1:x}" * 64,
                "size": 1,
                "files": 1,
            }
            for index, name in enumerate(preflight.BUILD_TOOL_NAMES)
        },
        "output": {
            "name": preflight.NATIVE_EFI_NAME,
            "sha256": efi["sha256"],
            "size": efi["size"],
        },
        "builder_sha256": preflight.azure.image_sha256(
            Path(preflight.__file__)
        ),
        "guarded": (
            json.loads(json.dumps(guarded)) if guarded is not None else None
        ),
    }
    receipt["tools"]["git"] = json.loads(json.dumps(provenance["git"]))
    return {
        "name": preflight.PRIVATE_BUILD_RECEIPT,
        "sha256": "3" * 64,
        "size": 2048,
        "receipt": receipt,
    }


class PrivatePreflightFixture(unittest.TestCase):
    @staticmethod
    def guarded_config():
        return (
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE=y\n"
            "CONFIG_LIBSTORVSC=y\n"
            "CONFIG_LIBSTORVSC_LUN_DISCOVERY=y\n"
            "CONFIG_LIBSTORVSC_GUARDED_IO=y\n"
            "CONFIG_LIBSTORVSC_MAX_DEVICES=2\n"
            "CONFIG_LIBSTORVSC_MAX_LUNS=8\n"
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID="
            '"00112233445566778899aabbccddeeff"\n'
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID="
            '"102132435465768798a9bacbdcedfe0f"\n'
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS=1000\n"
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE=512\n"
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=2\n"
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN=0\n"
        ).encode()

    @staticmethod
    def guarded_contract(config_sha256):
        return {
            "schema": preflight.GUARDED_CONTRACT_SCHEMA,
            "schema_version": 1,
            "scope": "platform-only",
            "result": "UNAVAILABLE",
            "protocol": 1,
            "identity_policy": 2,
            "reason": "no-devices",
            "main_return": 2,
            "run_id": "00112233445566778899aabbccddeeff",
            "disk_id": "102132435465768798a9bacbdcedfe0f",
            "path": 0,
            "target": 0,
            "lun": 0,
            "sectors": 1000,
            "sector_size": 512,
            "solved_config_sha256": config_sha256,
            "producer": preflight.guarded_producer_contract(),
        }

    def implementation(self):
        return {
            "sdk": {
                "requirements_sha256": preflight.azure.image_sha256(
                    preflight.REQUIREMENTS_PATH
                ),
                "distributions": [
                    {
                        "name": name,
                        "version": version,
                        "files": 1,
                        "bytes": 1,
                        "sha256": f"{index + 1:x}" * 64,
                    }
                    for index, (name, version) in enumerate(
                        preflight.SDK_DISTRIBUTIONS
                    )
                ],
            },
            "files": {
                name: {
                    "path": str(path.relative_to(SUPPORT.parent)),
                    "sha256": preflight.azure.image_sha256(path),
                    "size": path.stat().st_size,
                }
                for name, path in preflight.IMPLEMENTATION_PATHS.items()
            },
        }

    def manifest(self, **changes):
        boot_policy = changes.pop("boot_policy", "platform-unavailable-v1")
        raw_size = preflight.azure.VIRTUAL_SIZE
        sizes = {
            "qemu": 26_911_032,
            "ovmf_code": 3_653_632,
            "ovmf_vars": 540_672,
            "capability_raw": raw_size,
            "efi": 49_981_328,
            "raw": raw_size,
            "vhd": raw_size + 512,
        }
        files = {
            role: {
                "name": preflight.INPUT_NAMES[role],
                "sha256": f"{index + 1:x}" * 64,
                "size": sizes[role],
            }
            for index, role in enumerate(preflight.ALL_ROLES)
        }
        files["capability_raw"]["sha256"] = (
            preflight.APPROVED_CAPABILITY_REFERENCE["receipt"]["raw"][
                "sha256"
            ]
        )
        qemu_support = [{
            "path": "qemu/share/qemu/firmware.json",
            "sha256": "9" * 64,
            "size": 1024 * 1024,
        }]
        provenance = {
            "scheme": "unikraft.git-physical-tree-v2",
            "head_commit": "a" * 40,
            "tree_sha256": "b" * 64,
            "physical_sha256": "9" * 64,
            "tracked_entries": 200,
            "tracked_bytes": 1024 * 1024,
            "config": {
                "name": preflight.SOLVED_CONFIG,
                "sha256": "c" * 64,
                "size": 4096,
            },
            "git": fake_git_runtime_record(),
        }
        guarded = (
            self.guarded_contract(provenance["config"]["sha256"])
            if boot_policy == preflight.GUARDED_BOOT_POLICY else None
        )
        value = {
            "schema": preflight.INPUT_SCHEMA,
            "schema_version": preflight.INPUT_SCHEMA_VERSION,
            "workload": preflight.WORKLOAD,
            "boot_policy": boot_policy,
            "guarded": guarded,
            "raw_size": raw_size,
            "provenance": provenance,
            "files": files,
            "qemu_support": qemu_support,
            "miz": {
                "name": "miz",
                "revision": preflight.azure.MIZ_REVISION,
                "sha256": "d" * 64,
                "size": 8 * 1024 * 1024,
            },
            "packaging": packaging_contract(
                files["efi"]["sha256"], files["efi"]["size"],
                files["vhd"]["size"],
            ),
            "capability_reference": capability_reference(
                files["capability_raw"]
            ),
            "private_build": private_build_receipt(
                provenance, files["efi"], guarded
            ),
            "implementation": self.implementation(),
            "budget": preflight.expected_budget(files, qemu_support),
        }
        value.update(changes)
        return value

    def state(self, **manifest_changes):
        manifest = preflight.validate_input_manifest(
            self.manifest(**manifest_changes)
        )
        manifest_sha = hashlib.sha256(
            preflight.azure.canonical_json(manifest)
        ).hexdigest()
        return {
            "schema": preflight.STATE_SCHEMA,
            "schema_version": preflight.STATE_SCHEMA_VERSION,
            "phase": "prepared",
            "identity": "1" * 32,
            "name_prefix": "uk-hvp-123456789abc",
            "location": preflight.LOCATION,
            "vm_size": preflight.VM_SIZE,
            "image_sha256": manifest["files"]["vhd"]["sha256"],
            "manifest_sha256": manifest_sha,
            "implementation": manifest["implementation"],
            "input_manifest": manifest,
            "staged_input_bytes": 0,
            "control_payload_bytes": 0,
            "evidence_bytes": 0,
            "pending_secret_files": [],
            "cleanup_required": False,
        }

    def cloud_state(self):
        state = self.state()
        state.update({
            "phase": "cloud-preflight-complete",
            "subscription": "11111111-2222-3333-4444-555555555555",
            "cloud_preflight": {
                "image": {
                    "publisher": "Canonical",
                    "offer": "ubuntu-24_04-lts",
                    "sku": "server",
                    "version": "24.04.202609010",
                    "hyperv_generation": "V2",
                },
            },
            "deadline_monotonic": time.monotonic() + 3600,
            "deadline_utc": "2026-09-09T05:26:00Z",
            "cleanup_required": True,
            "storage_account": "ukhvp1234567890abcd",
            "firewall_obligation": None,
            "resource_group_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg"
            ),
            "host_vm_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Compute/virtualMachines/"
                "uk-hvp-123456789abc-host"
            ),
            "host_disk_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Compute/disks/"
                "uk-hvp-123456789abc-host-os"
            ),
            "host_nic_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Network/networkInterfaces/"
                "uk-hvp-123456789abc-host-nic"
            ),
            "storage_account_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Storage/storageAccounts/ukhvp1234567890abcd"
            ),
            "shutdown_schedule_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.DevTestLab/schedules/"
                "shutdown-computevm-uk-hvp-123456789abc-host"
            ),
        })
        return state

    def run_fixture(self, root):
        state = self.cloud_state()
        path = root / "state.json"
        preflight.azure.save_json(path, state)
        run = preflight.PrivatePreflightRun(state, path)
        run.az = mock.Mock()

        def record(phase, **fields):
            state.update(phase=phase, **fields)

        run.record = mock.Mock(side_effect=record)
        return run, state

    def begin_operation(self, run, state, phase="resources-verified"):
        operation = "22222222-2222-4222-8222-222222222222"
        ids = run.expected_host_ids()
        state["host_deployment"] = {
            "phase": phase,
            "operation_id": operation,
            "deployment_id": ids["deployment_id"],
            "correlation_id": (
                None if phase == "pending"
                else "33333333-3333-4333-8333-333333333333"
            ),
            "vm_id": ids["vm_id"],
            "vm_uuid": (
                None if phase in ("pending", "deployment-succeeded")
                else "44444444-4444-4444-8444-444444444444"
            ),
            "disk_id": ids["disk_id"],
            "disk_uuid": (
                "55555555-5555-4555-8555-555555555555"
                if phase == "resources-verified" else None
            ),
            "shutdown_time": "0526",
        }
        return state["host_deployment"]

    def vm_disk(self, run, state):
        receipt = state["host_deployment"]
        image = state["cloud_preflight"]["image"]
        vm = {
            "id": receipt["vm_id"],
            "name": run.host_vm,
            "type": "Microsoft.Compute/virtualMachines",
            "vmId": receipt["vm_uuid"]
            or "44444444-4444-4444-8444-444444444444",
            "tags": run.operation_tags(),
            "location": preflight.LOCATION,
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": preflight.VM_SIZE},
            "securityProfile": {"securityType": "Standard"},
            "networkProfile": {
                "networkInterfaces": [{
                    "id": run.expected_host_ids()["nic_id"],
                    "primary": True,
                    "deleteOption": "Delete",
                }],
            },
            "storageProfile": {
                "imageReference": image,
                "osDisk": {
                    "diskSizeGb": 32,
                    "createOption": "FromImage",
                    "caching": "ReadWrite",
                    "deleteOption": "Delete",
                    "managedDisk": {"id": receipt["disk_id"]},
                },
                "dataDisks": [],
            },
        }
        disk = {
            "id": receipt["disk_id"],
            "name": run.host_disk,
            "type": "Microsoft.Compute/disks",
            "uniqueId": receipt["disk_uuid"]
            or "55555555-5555-4555-8555-555555555555",
            "managedBy": receipt["vm_id"],
            "diskSizeGb": 32,
            "sku": {"name": "StandardSSD_LRS"},
            "osType": "Linux",
            "hyperVGeneration": "V2",
            "tags": {
                **run.operation_tags(),
                "azure-generated": "metadata",
            },
            "location": preflight.LOCATION,
        }
        return vm, disk

    def deployment(self, run, state, provisioning="Succeeded"):
        receipt = state["host_deployment"]
        image = state["cloud_preflight"]["image"]
        parameters = {
            "namePrefix": run.prefix,
            "location": preflight.LOCATION,
            "imageSha256": state["image_sha256"],
            "storageAccountName": run.storage,
            "hostImageVersion": image["version"],
            "operationId": receipt["operation_id"],
            "shutdownTime": receipt["shutdown_time"],
        }
        return {
            "id": receipt["deployment_id"],
            "name": run.prefix + "-host",
            "properties": {
                "provisioningState": provisioning,
                "correlationId": "33333333-3333-4333-8333-333333333333",
                "outputs": {
                    "hostVmUuid": {
                        "type": "String",
                        "value": "44444444-4444-4444-8444-444444444444",
                    },
                    "hostDiskUuid": {
                        "type": "String",
                        "value": "55555555-5555-4555-8555-555555555555",
                    },
                },
                "parameters": {
                    name: {"value": value}
                    for name, value in parameters.items()
                },
            },
        }


class PrivatePreflightManifestTest(PrivatePreflightFixture):
    def test_guarded_source_pin_covers_pristine_proof_dependency_closure(self):
        self.assertEqual(
            preflight.GUARDED_PRODUCER_FILES,
            runner.GUARDED_PRODUCER_FILES,
        )
        self.assertEqual(
            preflight.GUARDED_PRODUCER_SCHEMA_VERSION,
            runner.GUARDED_PRODUCER_SCHEMA_VERSION,
        )
        self.assertEqual(
            preflight.GUARDED_PRODUCER_CLOSURES,
            runner.GUARDED_PRODUCER_CLOSURES,
        )
        self.assertEqual(
            preflight.directory_record(
                SUPPORT / "build", "support/build",
                "Guarded producer execution closure",
            ),
            preflight.GUARDED_PRODUCER_CLOSURES["support/build"],
        )
        proof_roles = {
            "plat/hyperv/Makefile.uk",
            "plat/hyperv/hyperv_runtime.zig",
            "plat/hyperv/include/hyperv/hyperv.h",
            "plat/hyperv/time.c",
            "drivers/hyperv/vmbus/Makefile.uk",
            "drivers/hyperv/vmbus/include/uk/vmbus.h",
            "drivers/hyperv/vmbus/vmbus_bus.c",
            "drivers/hyperv/vmbus/vmbus_channel.c",
            "drivers/hyperv/vmbus/vmbus_protocol.h",
            "drivers/hyperv/vmbus/vmbus_protocol.zig",
            "drivers/hyperv/storvsc/Makefile.uk",
            "drivers/hyperv/storvsc/include/uk/storvsc.h",
            "drivers/hyperv/storvsc/storvsc.c",
            "drivers/hyperv/storvsc/storvsc_core.h",
            "drivers/hyperv/storvsc/storvsc_core.zig",
            "support/build/native-image-graph.zig",
            "support/build/native-postprocess.zig",
            "support/build/native-postprocess-runner.py",
            "support/apps/hyperv-acceptance/Makefile.uk",
            "support/apps/hyperv-acceptance/acceptance_protocol.c",
            "support/apps/hyperv-acceptance/acceptance_protocol.h",
            "support/apps/hyperv-acceptance/application_network.c",
            "support/apps/hyperv-acceptance/application_network.h",
            "support/apps/hyperv-acceptance/main.c",
            "support/apps/hyperv-acceptance/persistence.c",
            "support/apps/hyperv-acceptance/storage_target.c",
            "support/apps/hyperv-acceptance/storage_target.h",
            *preflight.GUARDED_BUILD_CONTROL_FILES,
            *preflight.GUARDED_EXECUTED_HELPER_FILES,
        }
        self.assertLessEqual(
            proof_roles, set(preflight.GUARDED_PRODUCER_FILES)
        )
        for relative, expected in preflight.GUARDED_PRODUCER_FILES.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    preflight.azure.image_sha256(SUPPORT.parent / relative),
                    expected,
                )
                self.assertEqual(
                    preflight.IMPLEMENTATION_PATHS[
                        f"guarded_producer:{relative}"
                    ],
                    SUPPORT.parent / relative,
                )

    def test_guarded_matcher_mutations_fail_before_packaging(self):
        mutation_targets = (
            "drivers/hyperv/vmbus/vmbus_protocol.zig",
            "drivers/hyperv/vmbus/vmbus_protocol.h",
            "drivers/hyperv/vmbus/vmbus_channel.c",
            "support/apps/hyperv-acceptance/application_network.c",
            "support/apps/hyperv-acceptance/application_network.h",
            "support/apps/hyperv-acceptance/storage_target.c",
            "support/apps/hyperv-acceptance/storage_target.h",
            "support/build/native-target-object.zig",
            "support/build/tests/hyperv-smp-link-test.py",
            "support/build/tests/hyperv-irq-register-test.py",
            "support/build/tests/hyperv-driver-registration-test.py",
            "support/build/tests/storvsc-production-test.c",
            "support/scripts/mkcompiledb.py",
            "support/scripts/gitsha1",
            "support/build/unreviewed-native-helper.py",
        )
        for relative in mutation_targets:
            with self.subTest(relative=relative), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for source_relative in preflight.GUARDED_PRODUCER_FILES:
                    source = SUPPORT.parent / source_relative
                    destination = root / source_relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
                shutil.copytree(
                    SUPPORT.parent / "support" / "build",
                    root / "support" / "build",
                    dirs_exist_ok=True,
                )
                fake_support = root / "support"
                with mock.patch.object(preflight, "SUPPORT", fake_support):
                    preflight.verify_guarded_producer_sources(root)
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(
                        (target.read_bytes() if target.exists() else b"")
                        + b"\n"
                    )
                    with self.assertRaisesRegex(
                        ValueError, "reviewed V2 contract"
                    ):
                        preflight.verify_guarded_producer_sources(root)

                    config = root / "solved.config"
                    config.write_bytes(self.guarded_config())
                    arguments = [
                        root / "output", root, config, root / "qemu",
                        root / "code", root / "vars", root / "capability",
                        root / "capability-receipt", root / "efi",
                        root / "build-receipt", root / "raw", root / "vhd",
                        root / "miz", root / "git",
                    ]
                    provenance = self.manifest(
                        boot_policy=preflight.GUARDED_BOOT_POLICY
                    )["provenance"]
                    provenance["config"] = {
                        "name": preflight.SOLVED_CONFIG,
                        "sha256": hashlib.sha256(
                            self.guarded_config()
                        ).hexdigest(),
                        "size": len(self.guarded_config()),
                    }
                    with mock.patch.object(
                        preflight, "check_blob_dependency"
                    ), mock.patch.object(
                        preflight, "build_provenance",
                        return_value=provenance,
                    ), mock.patch.object(
                        preflight, "qemu_closure_records"
                    ) as packaging:
                        with self.assertRaisesRegex(
                            ValueError, "reviewed V2 contract"
                        ):
                            preflight.generate_input(
                                *arguments, preflight.GUARDED_BOOT_POLICY
                            )
                        packaging.assert_not_called()

    def test_guarded_olddefconfig_recipe_uses_pinned_make_and_python(self):
        readme = (SUPPORT / "azure" / "README.md").read_text()
        start = readme.index(
            'PERSISTENCE="$PWD/.d/private-preflight-persistence"'
        )
        end = readme.index(
            'SOLVED_CONFIG="$PWD/support/apps/hyperv-acceptance/.config"',
            start,
        )
        recipe = readme[start:end]
        self.assertIn(
            (
                'PATH="$CONFIG_TOOLS:$RUNTIME/venv/bin:$LLVM_BIN:'
                '/usr/bin:/bin"'
            ),
            recipe,
        )
        self.assertIn('-Dmake-command="$MAKE"', recipe)
        self.assertNotIn("$LLVM_BIN:$PATH", recipe)
        self.assertIn('exec "$GIT_RUNTIME/lib/loader"', recipe)
        self.assertIn("--no-replace-objects", recipe)
        self.assertIn('--git-runtime "$GIT_RUNTIME"', readme)
        self.assertIn("canonical schema-9 manifest", readme)

    def test_guarded_contract_is_derived_from_exact_solved_v2_config(self):
        preflight.verify_guarded_producer_sources(SUPPORT.parent)
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "solved.config"
            config.write_bytes(self.guarded_config())
            contract = preflight.guarded_contract_from_solved_config(config)
        self.assertEqual(
            contract,
            self.guarded_contract(
                hashlib.sha256(self.guarded_config()).hexdigest()
            ),
        )
        manifest = preflight.validate_input_manifest(
            self.manifest(boot_policy=preflight.GUARDED_BOOT_POLICY)
        )
        self.assertEqual(manifest["guarded"]["result"], "UNAVAILABLE")
        self.assertEqual(manifest["guarded"]["scope"], "platform-only")
        self.assertEqual(
            manifest["private_build"]["receipt"]["guarded"],
            manifest["guarded"],
        )

    def test_guarded_contract_rejects_v1_or_mismatched_configuration(self):
        variants = []
        for old, new in (
            (
                b"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=2",
                b"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=1",
            ),
            (
                b"CONFIG_LIBSTORVSC_GUARDED_IO=y",
                b"CONFIG_LIBSTORVSC_GUARDED_IO=n",
            ),
            (
                b"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN=0",
                b"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN=256",
            ),
        ):
            variants.append(self.guarded_config().replace(old, new))
        variants.append(
            self.guarded_config()
            + b"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH=0\n"
        )
        for index, raw in enumerate(variants):
            with self.subTest(index=index), \
                    tempfile.TemporaryDirectory() as temporary:
                config = Path(temporary) / "solved.config"
                config.write_bytes(raw)
                with self.assertRaises(ValueError):
                    preflight.guarded_contract_from_solved_config(config)
        value = self.manifest(boot_policy=preflight.GUARDED_BOOT_POLICY)
        value["guarded"]["lun"] = 1
        with self.assertRaises(ValueError):
            preflight.validate_input_manifest(value)
        value = self.manifest(boot_policy=preflight.GUARDED_BOOT_POLICY)
        value["private_build"]["receipt"]["guarded"]["sectors"] = 2000
        with self.assertRaises(ValueError):
            preflight.validate_input_manifest(value)
        value = self.manifest()
        value["guarded"] = self.guarded_contract(
            value["provenance"]["config"]["sha256"]
        )
        with self.assertRaises(ValueError):
            preflight.validate_input_manifest(value)

    def test_manifest_binds_real_budget_and_keeps_efi_local(self):
        manifest = preflight.validate_input_manifest(self.manifest())
        budget = manifest["budget"]
        measured_without_support = (
            207_618_560 + 26_911_032 + 4_194_304
            + 540_672 * runner.TOTAL_BOOT_COUNT
            + preflight.MAX_CONTROL_BYTES + preflight.MAX_EVIDENCE_BYTES
        )
        self.assertEqual(
            budget["total_max_bytes"],
            measured_without_support + 1024 * 1024,
        )
        self.assertEqual(
            budget["remaining_bytes"],
            preflight.MAX_TOTAL_BYTES - budget["total_max_bytes"],
        )
        self.assertNotIn(
            manifest["files"]["efi"]["size"],
            (budget["remote_input_bytes"], budget["total_max_bytes"]),
        )
        self.assertEqual(
            manifest["packaging"]["boot-file-sha256"],
            manifest["files"]["efi"]["sha256"],
        )

    def test_capability_reference_is_exact_reviewed_historical_source(self):
        approved = preflight.validate_input_manifest(self.manifest())
        self.assertEqual(
            approved["capability_reference"],
            preflight.APPROVED_CAPABILITY_REFERENCE,
        )
        mutations = {
            "fork": lambda value: (
                value["capability_reference"]["receipt"]["source"].__setitem__(
                    "repository", "attacker/unikraft"
                ),
                value["capability_reference"]["receipt"]["source"].__setitem__(
                    "workflow_ref",
                    "attacker/unikraft/.github/workflows/"
                    "integration.yaml@refs/heads/zig16",
                ),
            ),
            "commit": lambda value: value["capability_reference"]["receipt"][
                "source"
            ].__setitem__("head_sha", "9" * 40),
            "run": lambda value: value["capability_reference"]["receipt"][
                "source"
            ].__setitem__("run_id", 999999),
            "manifest": lambda value: value["capability_reference"][
                "receipt"
            ].__setitem__("manifest_sha256", "9" * 64),
            "efi": lambda value: value["capability_reference"][
                "receipt"
            ].__setitem__("efi_sha256", "9" * 64),
            "vhd": lambda value: value["capability_reference"]["receipt"][
                "source_vhd"
            ].__setitem__("sha256", "9" * 64),
            "receipt-file": lambda value: value[
                "capability_reference"
            ].__setitem__("sha256", "9" * 64),
        }
        for description, mutate in mutations.items():
            value = self.manifest()
            mutate(value)
            with self.subTest(description=description):
                with self.assertRaisesRegex(
                    ValueError, "reviewed known-good source"
                ):
                    preflight.validate_input_manifest(value)
        changed_raw = self.manifest()
        changed_raw["files"]["capability_raw"]["sha256"] = "9" * 64
        changed_raw["capability_reference"]["receipt"]["raw"][
            "sha256"
        ] = "9" * 64
        with self.assertRaisesRegex(
            ValueError, "reviewed known-good source"
        ):
            preflight.validate_input_manifest(changed_raw)

    def test_manifest_rejects_bool_unknown_oversize_and_nonplatform_workload(self):
        variants = []
        unknown = self.manifest()
        unknown["private_path"] = "/secret"
        variants.append(unknown)
        boolean = self.manifest()
        boolean["files"]["raw"]["size"] = True
        variants.append(boolean)
        oversized = self.manifest()
        oversized["qemu_support"][0]["size"] = 30 * 1024 * 1024
        oversized["budget"] = preflight.expected_budget(
            oversized["files"], oversized["qemu_support"]
        )
        variants.append(oversized)
        variants.append(self.manifest(workload="persistence-v2"))
        variants.append(self.manifest(boot_policy="accept-any-failure"))
        invalid_packaging = self.manifest()
        invalid_packaging["packaging"]["boot-file-size"] = True
        variants.append(invalid_packaging)
        invalid_packaging = self.manifest()
        invalid_packaging["packaging"]["disk-guid"] = str(uuid.UUID(int=0))
        variants.append(invalid_packaging)
        unrelated_build = self.manifest()
        unrelated_build["private_build"]["receipt"]["output"][
            "sha256"
        ] = "e" * 64
        variants.append(unrelated_build)
        unrelated_capability = self.manifest()
        unrelated_capability["capability_reference"]["receipt"]["raw"][
            "sha256"
        ] = "e" * 64
        variants.append(unrelated_capability)
        for value in variants:
            with self.subTest(value=value.get("workload")):
                with self.assertRaises(ValueError):
                    preflight.validate_input_manifest(value)

    def test_host_manifests_bind_qemu_closure_and_never_stage_efi(self):
        state = self.state()
        capability = preflight.host_phase_manifest(state, "capability")
        digest = hashlib.sha256(
            preflight.azure.canonical_json(capability)
        ).hexdigest()
        private = preflight.host_phase_manifest(state, "private", digest)
        self.assertEqual(capability["schema_version"], 3)
        self.assertIsNone(capability["guarded"])
        self.assertIsNone(private["guarded"])
        self.assertEqual(private["capability_manifest_sha256"], digest)
        self.assertNotIn("efi", private["files"])
        self.assertEqual(
            private["qemu_support"][0]["name"],
            "qemu/share/qemu/firmware.json",
        )
        staged = preflight.blob_files(
            state, Path("/owner/state"), preflight.PUBLIC_ROLES
        )
        self.assertTrue(any(
            item[0].endswith("/qemu/share/qemu/firmware.json")
            for item in staged
        ))

    def test_private_host_manifest_binds_guarded_contract_after_capability(self):
        state = self.state(boot_policy=preflight.GUARDED_BOOT_POLICY)
        capability = preflight.host_phase_manifest(state, "capability")
        digest = hashlib.sha256(
            preflight.azure.canonical_json(capability)
        ).hexdigest()
        private = preflight.host_phase_manifest(state, "private", digest)
        self.assertEqual(
            capability["boot_policy"], "platform-unavailable-v1"
        )
        self.assertIsNone(capability["guarded"])
        self.assertEqual(
            private["boot_policy"], preflight.GUARDED_BOOT_POLICY
        )
        self.assertEqual(private["guarded"], state["input_manifest"]["guarded"])
        parsed, _ = runner.parse_manifest(
            base64_encode(private), "private"
        )
        self.assertEqual(parsed["guarded"], private["guarded"])

    def test_transfer_source_and_deadline_are_explicit(self):
        self.assertEqual(preflight.transfer_source("8.8.8.8"), "8.8.8.8/32")
        self.assertEqual(
            preflight.transfer_source("8.8.4.4/32"), "8.8.4.4/32"
        )
        for value in (
            "10.0.0.1", "127.0.0.1", "192.0.2.1",
            "8.8.8.0/24", "latest", None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    preflight.transfer_source(value)
        with mock.patch.object(preflight.time, "monotonic", return_value=101):
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                preflight.bounded_timeout(100, 300)

    def test_run_requires_explicit_uploader_authorization_before_cloud(self):
        state = self.state()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(
                    preflight, "load_state",
                    return_value=(state, Path(temporary) / "state.json"),
                ), mock.patch.object(
                    preflight, "verify_immutable_inputs"
                ), mock.patch.object(
                    preflight, "check_blob_dependency"
                ), mock.patch.object(
                    preflight, "check_subscription"
                ) as cloud:
            with self.assertRaisesRegex(ValueError, "authorization"):
                preflight.run_preflight(
                    Path(temporary), "1" * 36, "8.8.8.8", False
                )
            cloud.assert_not_called()

    def test_source_or_dependency_change_fails_before_cloud_preflight(self):
        state = self.state()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(
                    preflight, "load_state",
                    return_value=(state, Path(temporary) / "state.json"),
                ), mock.patch.object(
                    preflight, "verify_immutable_inputs",
                    side_effect=ValueError("implementation changed"),
                ), mock.patch.object(
                    preflight, "check_subscription"
                ) as cloud:
            with self.assertRaisesRegex(ValueError, "implementation changed"):
                preflight.run_preflight(
                    Path(temporary), "1" * 36, "8.8.8.8", True
                )
            cloud.assert_not_called()

    def test_provenance_binds_physical_tree_and_rejects_concealment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "support").mkdir(parents=True)
            config = root / "solved.config"
            config.write_text("CONFIG_HYPERV=y\n")
            git_command = str(selected_git_executable())
            subprocess.run(
                [git_command, "init", "-q"], cwd=repository, check=True
            )
            (repository / "tracked").write_text("source\n")
            production = repository / "lib" / "ukboot" / "boot.c"
            production.parent.mkdir(parents=True)
            production.write_bytes(
                (SUPPORT.parent / "lib" / "ukboot" / "boot.c").read_bytes()
            )
            unusual = repository / "tracked\nname\twith-bytes"
            unusual.write_bytes(b"binary-safe\n")
            executable = repository / "tracked-executable"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            link = repository / "tracked-link"
            link.symlink_to("tracked")
            subprocess.run(
                [
                    git_command, "add", "--", "tracked",
                    "lib/ukboot/boot.c", unusual.name,
                    executable.name, link.name,
                ],
                cwd=repository, check=True,
            )
            subprocess.run(
                [
                    git_command, "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                cwd=repository, check=True,
            )
            git_runtime = create_git_runtime(root / "tools")
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\nprintf '%s' 'forged ambient git'\n"
            )
            fake_git.chmod(0o700)
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ), mock.patch.dict(
                preflight.os.environ,
                {
                    "PATH": str(fake_bin),
                    "GIT_DIR": str(repository / "forged-git-dir"),
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "core.fsmonitor",
                    "GIT_CONFIG_VALUE_0": "forged",
                    "LD_LIBRARY_PATH": str(repository / "forged-libs"),
                    "LD_PRELOAD": str(repository / "forged-preload.so"),
                    "LD_DEBUG": "all",
                    "GLIBC_TUNABLES": "glibc.rtld.dynamic_sort=1",
                },
            ):
                first = preflight.build_provenance(
                    repository, config, git_runtime
                )
                second = preflight.build_provenance(
                    repository, config, git_runtime
                )
            self.assertEqual(first, second)
            self.assertEqual(
                first["scheme"], "unikraft.git-physical-tree-v2"
            )
            self.assertEqual(first["tracked_entries"], 5)
            self.assertEqual(
                first["tracked_bytes"],
                len(b"source\n") + production.stat().st_size
                + len(b"binary-safe\n") + len(b"#!/bin/sh\nexit 0\n")
                + len(b"tracked"),
            )
            self.assertEqual(
                first["git"], preflight.git_runtime_record(git_runtime)
            )
            config.write_text("CONFIG_HYPERV=n\n")
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ):
                changed = preflight.build_provenance(
                    repository, config, git_runtime
                )
            self.assertNotEqual(
                first["config"]["sha256"], changed["config"]["sha256"]
            )

            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ):
                tree = preflight.parse_git_tree(preflight.git_output(
                    git_runtime, repository,
                    ["ls-tree", "-r", "--full-tree", "-z", "HEAD"],
                ))
                executable.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "mode changed"):
                    preflight.verify_physical_git_tree(repository, tree)
                executable.chmod(0o755)
                link.unlink()
                link.write_bytes(b"tracked")
                with self.assertRaisesRegex(ValueError, "symlink type"):
                    preflight.verify_physical_git_tree(repository, tree)
                link.unlink()
                link.symlink_to("tracked")

            original_production = production.read_bytes()
            subprocess.run(
                [
                    git_command, "update-index", "--assume-unchanged",
                    "--", "lib/ukboot/boot.c",
                ],
                cwd=repository, check=True,
            )
            production.write_bytes(original_production + b"\nconcealed\n")
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ):
                tree = preflight.parse_git_tree(preflight.git_output(
                    git_runtime, repository,
                    ["ls-tree", "-r", "--full-tree", "-z", "HEAD"],
                ))
                with self.assertRaisesRegex(
                    ValueError, "Physical tracked source"
                ):
                    preflight.verify_physical_git_tree(repository, tree)
                with self.assertRaisesRegex(
                    ValueError, "concealment flags"
                ):
                    preflight.build_provenance(
                        repository, config, git_runtime
                    )
            production.write_bytes(original_production)
            subprocess.run(
                [
                    git_command, "update-index", "--no-assume-unchanged",
                    "--", "lib/ukboot/boot.c",
                ],
                cwd=repository, check=True,
            )

            subprocess.run(
                [
                    git_command, "update-index", "--skip-worktree",
                    "--", "lib/ukboot/boot.c",
                ],
                cwd=repository, check=True,
            )
            production.write_bytes(original_production + b"\nskipped\n")
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ), self.assertRaisesRegex(ValueError, "concealment flags"):
                preflight.build_provenance(
                    repository, config, git_runtime
                )
            production.write_bytes(original_production)
            subprocess.run(
                [
                    git_command, "update-index", "--no-skip-worktree",
                    "--", "lib/ukboot/boot.c",
                ],
                cwd=repository, check=True,
            )

            original_head = subprocess.run(
                [git_command, "rev-parse", "HEAD"],
                cwd=repository, check=True, capture_output=True, text=True,
            ).stdout.strip()
            production.write_bytes(original_production + b"\nreplacement\n")
            subprocess.run(
                [git_command, "add", "--", "lib/ukboot/boot.c"],
                cwd=repository, check=True,
            )
            subprocess.run(
                [
                    git_command, "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "replacement",
                ],
                cwd=repository, check=True,
            )
            replacement = subprocess.run(
                [git_command, "rev-parse", "HEAD"],
                cwd=repository, check=True, capture_output=True, text=True,
            ).stdout.strip()
            subprocess.run(
                [git_command, "reset", "--hard", "-q", original_head],
                cwd=repository, check=True,
            )
            subprocess.run(
                [git_command, "replace", original_head, replacement],
                cwd=repository, check=True,
            )
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ), self.assertRaisesRegex(ValueError, "replacement refs"):
                preflight.build_provenance(
                    repository, config, git_runtime
                )

    def test_private_build_rejects_unbound_git_launcher_before_native_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = create_git_runtime(root / "launcher-tools")
            shutil.copy2(
                Path(shutil.which("true")).resolve(),
                runtime / preflight.GIT_EXECUTABLE,
            )
            with mock.patch.object(
                preflight, "build_provenance"
            ) as provenance:
                with self.assertRaisesRegex(
                    ValueError, "dependency closure"
                ):
                    preflight.build_private_image(
                        root / "output", root, root / "config",
                        root / "zig", root / "make", root / "python",
                        root / "bison", root / "flex", root / "m4",
                        root / "bison-data", root / "llvm", runtime, 30,
                    )
                provenance.assert_not_called()
            ambient_name = shutil.which("git")
            if ambient_name is not None:
                ambient = Path(ambient_name).resolve()
                configuration = (
                    ambient.parent / "trampoline_configuration" / "git.json"
                )
            else:
                configuration = None
            if configuration is not None and configuration.is_file():
                pixi_runtime = root / "pixi-runtime"
                (pixi_runtime / "bin").mkdir(parents=True)
                shutil.copy2(
                    ambient, pixi_runtime / preflight.GIT_EXECUTABLE
                )
                with self.assertRaisesRegex(
                    ValueError, "requires bin/git"
                ):
                    preflight.copy_git_runtime(
                        pixi_runtime, root / "copied-pixi-runtime"
                    )

    def test_git_runtime_requires_complete_exact_relocated_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = create_git_runtime(root / "valid")
            expected = preflight.preflight_git_runtime(runtime)
            preferred = (
                runtime / "lib" / "libz.so.1"
                if (runtime / "lib" / "libz.so.1").is_file()
                else runtime / expected["libraries"][0]["name"]
            )
            missing_targets = [
                runtime / "lib" / name
                for name in ("libz.so.1", "libcrypto.so.3")
                if (runtime / "lib" / name).is_file()
            ] or [preferred]
            for index, missing_target in enumerate(missing_targets):
                with self.subTest(missing=missing_target.name):
                    missing = root / f"missing-{index}"
                    shutil.copytree(runtime, missing)
                    (
                        missing / missing_target.relative_to(runtime)
                    ).unlink()
                    with self.assertRaisesRegex(
                        ValueError,
                        "ambient dependency|closure is incomplete",
                    ):
                        preflight.preflight_git_runtime(missing)

            changed = root / "changed"
            shutil.copytree(runtime, changed)
            target = changed / preferred.relative_to(runtime)
            target.write_bytes(target.read_bytes() + b"\0")
            with self.assertRaisesRegex(ValueError, "differs"):
                preflight.copy_git_runtime(
                    changed, root / "changed-copy", expected
                )

            extra = root / "extra"
            shutil.copytree(runtime, extra)
            shutil.copy2(
                extra / expected["libraries"][0]["name"],
                extra / "lib" / "unresolved-extra.so",
            )
            with self.assertRaisesRegex(ValueError, "closure is incomplete"):
                preflight.preflight_git_runtime(extra)

            linked = root / "linked"
            shutil.copytree(runtime, linked)
            target = linked / preferred.relative_to(runtime)
            target.unlink()
            target.symlink_to(
                runtime / preferred.relative_to(runtime)
            )
            with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
                preflight.preflight_git_runtime(linked)

    def test_generate_input_creates_complete_canonical_operator_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "support").mkdir(parents=True)
            config = repository / "solved.config"
            config.write_text("CONFIG_HYPERV=y\n")
            (repository / "tracked").write_text("source\n")
            git_command = str(selected_git_executable())
            subprocess.run(
                [git_command, "init", "-q"], cwd=repository, check=True
            )
            subprocess.run(
                [git_command, "add", "tracked"], cwd=repository, check=True
            )
            subprocess.run(
                [
                    git_command, "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                cwd=repository, check=True,
            )
            qemu = root / "qemu"
            (qemu / "bin").mkdir(parents=True)
            (qemu / "share").mkdir()
            (qemu / "bin" / "qemu-system-x86_64").write_bytes(b"qemu")
            (qemu / "share" / "firmware.json").write_bytes(b"support")
            assets = {}
            for name, content in (
                ("code", b"code"), ("vars", b"vars"),
                ("capability", b"c" * 1024), ("efi", b"efi"),
                ("raw", b"r" * 1024), ("vhd", b"r" * 1024 + b"v" * 512),
                ("miz", b"miz"),
            ):
                assets[name] = root / name
                assets[name].write_bytes(content)
            assets["miz"].chmod(0o700)
            git_runtime = create_git_runtime(root / "git-tools")
            output = root / "input"

            def packaging(_miz, _arguments, _log, **_kwargs):
                return packaging_contract(
                    hashlib.sha256(b"efi").hexdigest(), 3, 1536
                )

            provenance = {
                **self.manifest()["provenance"],
                "config": {
                    "name": preflight.SOLVED_CONFIG,
                    "sha256": hashlib.sha256(
                        config.read_bytes()
                    ).hexdigest(),
                    "size": config.stat().st_size,
                },
                "git": preflight.git_runtime_record(git_runtime),
            }
            capability = capability_reference({
                "sha256": hashlib.sha256(b"c" * 1024).hexdigest(),
                "size": 1024,
            }, approved=False)
            capability_path = root / preflight.CAPABILITY_REFERENCE
            capability_path.write_bytes(
                preflight.azure.canonical_json(capability["receipt"])
            )
            capability["sha256"] = preflight.azure.image_sha256(
                capability_path
            )
            capability["size"] = capability_path.stat().st_size
            build = private_build_receipt(
                provenance,
                {
                    "sha256": hashlib.sha256(b"efi").hexdigest(),
                    "size": 3,
                },
            )
            build_path = root / preflight.PRIVATE_BUILD_RECEIPT
            build_path.write_bytes(
                preflight.azure.canonical_json(build["receipt"])
            )
            with mock.patch.object(
                preflight, "check_blob_dependency"
            ), mock.patch.object(
                preflight, "build_provenance",
                return_value=provenance,
            ), mock.patch.object(
                preflight, "implementation_contract",
                return_value=self.implementation(),
            ), mock.patch.object(
                preflight.azure, "VIRTUAL_SIZE", 1024
            ), mock.patch.object(
                preflight.azure, "miz_command", side_effect=packaging
            ), mock.patch.object(
                preflight, "APPROVED_CAPABILITY_REFERENCE", capability
            ):
                digest = preflight.generate_input(
                    output, repository, config, qemu,
                    assets["code"], assets["vars"], assets["capability"],
                    capability_path, assets["efi"], build_path,
                    assets["raw"], assets["vhd"],
                    assets["miz"], git_runtime,
                    "platform-unavailable-v1",
                )
                state_directory = root / "state"
                preflight.prepare(
                    output, state_directory, assets["miz"], digest
                )
                state, _ = preflight.load_state(state_directory)
                preflight.verify_immutable_inputs(state, state_directory)
                prepared_runtime = (
                    state_directory / "local-tools"
                    / preflight.GIT_RUNTIME
                )
                self.assertEqual(
                    preflight.git_runtime_record(prepared_runtime),
                    provenance["git"],
                )
                (
                    prepared_runtime
                    / provenance["git"]["libraries"][0]["name"]
                ).unlink()
                with self.assertRaisesRegex(
                    ValueError, "ambient dependency|Prepared source"
                ):
                    preflight.verify_immutable_inputs(
                        state, state_directory
                    )
            manifest_bytes = (
                output / preflight.INPUT_MANIFEST
            ).read_bytes()
            self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), digest)
            self.assertEqual(
                {
                    str(path.relative_to(output))
                    for path in output.rglob("*") if path.is_file()
                },
                {
                    preflight.INPUT_MANIFEST,
                    preflight.SOLVED_CONFIG,
                    preflight.CAPABILITY_REFERENCE,
                    preflight.PRIVATE_BUILD_RECEIPT,
                    *{
                        str(path.relative_to(git_runtime.parent))
                        for path in git_runtime.rglob("*") if path.is_file()
                    },
                    "qemu/bin/qemu-system-x86_64",
                    "qemu/share/firmware.json",
                    "OVMF_CODE.fd", "OVMF_VARS.fd", "capability.raw",
                    "private.efi", "private.raw", "private.vhd",
                },
            )

    def test_generate_input_rejects_config_policy_mismatch_before_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ordinary = root / "ordinary.config"
            ordinary.write_text("CONFIG_PLAT_HYPERV=y\n")
            guarded = root / "guarded.config"
            guarded.write_bytes(self.guarded_config())
            provenance = self.manifest()["provenance"]
            arguments = [
                root / "output", root, ordinary, root / "qemu",
                root / "code", root / "vars", root / "capability",
                root / "capability-receipt", root / "efi",
                root / "build-receipt", root / "raw", root / "vhd",
                root / "miz", root / "git",
            ]
            with mock.patch.object(
                preflight, "check_blob_dependency"
            ), mock.patch.object(
                preflight, "build_provenance",
                return_value=provenance,
            ), mock.patch.object(
                preflight, "qemu_closure_records"
            ) as packaging:
                with self.assertRaises(ValueError):
                    preflight.generate_input(
                        *arguments, preflight.GUARDED_BOOT_POLICY
                    )
                packaging.assert_not_called()
            arguments[2] = guarded
            with mock.patch.object(
                preflight, "check_blob_dependency"
            ), mock.patch.object(
                preflight, "build_provenance",
                return_value=provenance,
            ), mock.patch.object(
                preflight, "verify_guarded_producer_sources"
            ), mock.patch.object(
                preflight, "qemu_closure_records"
            ) as packaging:
                with self.assertRaises(ValueError):
                    preflight.generate_input(
                        *arguments, "platform-unavailable-v1"
                    )
                packaging.assert_not_called()

    def test_local_build_action_emits_causal_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            support = repository / "support"
            (support / "apps" / "hyperv-acceptance").mkdir(parents=True)
            native_runner = support / "build" / "native-postprocess-runner.py"
            native_runner.parent.mkdir(parents=True)
            native_runner.write_text("raise SystemExit(0)\n")
            uk_reloc = support / "scripts" / "mkukreloc.py"
            uk_reloc.parent.mkdir(parents=True)
            uk_reloc.write_text("raise SystemExit(0)\n")
            (repository / "tracked").write_text("source\n")
            git_command = str(selected_git_executable())
            subprocess.run(
                [git_command, "init", "-q"], cwd=repository, check=True
            )
            subprocess.run(
                [git_command, "add", "tracked", "support"],
                cwd=repository, check=True,
            )
            subprocess.run(
                [
                    git_command, "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                cwd=repository, check=True,
            )
            config = root / "solved.config"
            config.write_text("CONFIG_PLAT_HYPERV=y\n")
            tools = root / "tools"
            tools.mkdir()
            zig_target = tools / "zig-real"
            invoked = tools / "zig-invoked"
            invoked_args = tools / "zig-invoked-args"
            zig_target.write_text(
                "#!/bin/sh\nset -eu\nout=''\n"
                f"printf '%s' \"$0\" > {invoked}\n"
                f"printf '%s\\n' \"$@\" > {invoked_args}\n"
                "for arg in \"$@\"; do\n"
                " case \"$arg\" in -Doutput=*) out=${arg#-Doutput=};; esac\n"
                "done\n"
                "marker=\"$ZIG_LOCAL_CACHE_DIR/materialized\"\n"
                "if test ! -e \"$marker\"; then\n"
                " input=\"$ZIG_LOCAL_CACHE_DIR/o/111/"
                "hyperv-validated-final.dbg\"\n"
                " output=\"$ZIG_LOCAL_CACHE_DIR/o/222/"
                f"{preflight.NATIVE_EFI_NAME}.dbg\"\n"
                " reloc=\"$output.uk_reloc.bin\"\n"
                " mkdir -p \"${input%/*}\" \"${output%/*}\"\n"
                " printf input > \"$input\"\n"
                " printf output > \"$output\"\n"
                " printf reloc > \"$reloc\"\n"
                " : > \"$marker\"\n"
                " printf '%s\\n' 'failed command: PYTHON=python3 python3 "
                f"{native_runner} uk-reloc --script {uk_reloc} "
                "--nm llvm-nm --readelf llvm-readelf "
                "--objcopy llvm-objcopy '"
                "\"$input\"' '\"$reloc\"' '\"$output\"\n"
                " exit 0\n"
                "fi\n"
                "test -n \"$out\"\nmkdir -p \"$out\"\n"
                f"printf efi > \"$out/{preflight.NATIVE_EFI_NAME}\"\n"
            )
            zig_target.chmod(0o700)
            zig = tools / "zig"
            zig.symlink_to(zig_target)
            paths = {"zig": zig}
            for name in ("make", "python", "bison", "flex", "m4"):
                path = tools / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o700)
                paths[name] = path
            llvm = tools / "llvm"
            llvm.mkdir()
            for name in (
                "llvm-nm", "llvm-objcopy", "llvm-objdump",
                "llvm-readelf", "llvm-strip",
            ):
                path = llvm / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o700)
            bison_data = tools / "bison-data"
            bison_data.mkdir()
            (bison_data / "skeleton").write_text("data\n")
            output = root / "build-result"
            git_runtime = create_git_runtime(root / "git-tools")
            with mock.patch.object(
                preflight, "SUPPORT", support
            ), mock.patch.object(
                preflight, "NATIVE_POSTPROCESS_RUNNER_PATH", native_runner
            ), mock.patch.object(
                preflight, "UK_RELOC_SCRIPT_PATH", uk_reloc
            ):
                receipt_path, efi_path = preflight.build_private_image(
                    output, repository, config, paths["zig"],
                    paths["make"], paths["python"], paths["bison"],
                    paths["flex"], paths["m4"], bison_data, llvm,
                    git_runtime,
                    30,
                )
                provenance = preflight.build_provenance(
                    repository, output / preflight.SOLVED_CONFIG,
                    output / preflight.GIT_RUNTIME,
                )
            receipt = preflight.load_receipt(
                receipt_path, preflight.PRIVATE_BUILD_RECEIPT,
                "Private local build receipt",
            )
            validated = preflight.validate_private_build(
                receipt, provenance, {
                    "name": preflight.INPUT_NAMES["efi"],
                    "sha256": hashlib.sha256(b"efi").hexdigest(),
                    "size": 3,
                },
            )
            self.assertEqual(validated["receipt"]["result"], "PASS")
            self.assertEqual(efi_path.read_bytes(), b"efi")
            self.assertEqual(
                validated["receipt"]["source_before"],
                validated["receipt"]["source_after"],
            )
            self.assertEqual(invoked.read_text(), str(zig.absolute()))
            self.assertIn("-j2", invoked_args.read_text().splitlines())
            self.assertEqual(
                validated["receipt"]["invocation"][
                    "materialization_returncode"
                ],
                0,
            )
            self.assertEqual(
                validated["receipt"]["invocation"]["recovery"],
                "uk-reloc-v1",
            )
            self.assertEqual(
                validated["receipt"]["invocation"][
                    "recovery_returncode"
                ],
                0,
            )
            self.assertEqual(
                validated["receipt"]["invocation"][
                    "verification_returncode"
                ],
                0,
            )
            self.assertEqual(
                validated["receipt"]["tools"]["git"],
                preflight.git_runtime_record(git_runtime),
            )
            unrelated_git = copy.deepcopy(receipt)
            unrelated_git["receipt"]["tools"]["git"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "Git runtime"):
                preflight.validate_private_build(
                    unrelated_git, provenance, {
                        "name": preflight.INPUT_NAMES["efi"],
                        "sha256": hashlib.sha256(b"efi").hexdigest(),
                        "size": 3,
                    },
                )
            self.assertIn(
                f"exec {zig.absolute()} \"$@\"",
                (output / ".tool-bin" / "zig").read_text(),
            )
            self.assertIn(
                str(output / preflight.GIT_RUNTIME / preflight.GIT_EXECUTABLE),
                (output / ".tool-bin" / "git").read_text(),
            )
            self.assertIn(
                str(output / preflight.GIT_RUNTIME / preflight.GIT_LOADER),
                (output / ".tool-bin" / "git").read_text(),
            )
            self.assertIn(
                "--no-replace-objects",
                (output / ".tool-bin" / "git").read_text(),
            )

            script = zig_target.read_text()
            variants = {
                "verification-failure": script.replace(
                    'test -n "$out"\n',
                    "printf '%s\\n' 'failed command: unrelated "
                    "verification failure'\n"
                    'test -n "$out"\n',
                ),
                "hidden-materialization-failure": script.replace(
                    ' : > "$marker"\n',
                    ' : > "$marker"\n'
                    " printf '%s\\n' 'failed command: unrelated "
                    "materialization failure'\n"
                    " i=0\n"
                    " while test \"$i\" -lt 5000; do\n"
                    "  printf '%064d\\n' \"$i\"\n"
                    "  i=$((i + 1))\n"
                    " done\n",
                ),
                "nonzero-materialization": script.replace(
                    " exit 0\nfi\n", " exit 1\nfi\n", 1
                ),
                "ambiguous-materialization": script.replace(
                    ' : > "$marker"\n',
                    ' : > "$marker"\n'
                    " printf '%s\\n' 'prefix failed command: unrelated'\n",
                ),
                "oversized-materialization": script.replace(
                    ' : > "$marker"\n',
                    ' : > "$marker"\n'
                    " i=0\n"
                    " while test \"$i\" -lt 140000; do\n"
                    "  printf '%064d\\n' \"$i\"\n"
                    "  i=$((i + 1))\n"
                    " done\n",
                ),
            }
            for name, changed_script in variants.items():
                with self.subTest(name=name):
                    zig_target.write_text(changed_script)
                    rejected_output = root / ("rejected-" + name)
                    with mock.patch.object(
                        preflight, "SUPPORT", support
                    ), mock.patch.object(
                        preflight,
                        "NATIVE_POSTPROCESS_RUNNER_PATH",
                        native_runner,
                    ), mock.patch.object(
                        preflight, "UK_RELOC_SCRIPT_PATH", uk_reloc
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError, "failed|failure|exceeded"
                        ):
                            preflight.build_private_image(
                                rejected_output, repository, config,
                                paths["zig"], paths["make"],
                                paths["python"], paths["bison"],
                                paths["flex"], paths["m4"], bison_data,
                                llvm, git_runtime, 30,
                            )
            zig_target.write_text(script)


class PrivatePreflightRunnerTest(PrivatePreflightFixture):
    @staticmethod
    def boot_log(main_return=2, legacy=False, extra=""):
        lines = [
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:",
            "Powered by",
            "Calling main(",
            runner.UNAVAILABLE_RECORDS[0],
            runner.PLATFORM_MARKER,
            *runner.UNAVAILABLE_RECORDS[1:-1],
            runner.UNAVAILABLE_MARKER,
            runner.UNAVAILABLE_RECORDS[-1],
        ]
        if legacy:
            lines.append(runner.LEGACY_APIC_MARKER)
        if extra:
            lines.append(extra)
        lines.append(
            "[    0.100000] Info: [libukboot] "
            f"<boot.c @  523> main returned {main_return}"
        )
        return "\n".join(lines)

    @staticmethod
    def guarded_boot_log(records=None, main_return=2, legacy=False, extra=()):
        records = (
            GUARDED_PRODUCER_RECORDS.read_text().splitlines()
            if records is None else list(records)
        )
        lines = [
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:",
            "Powered by",
            "Calling main(",
            *records,
        ]
        if legacy:
            lines.append(runner.LEGACY_APIC_MARKER)
        lines.extend(extra)
        lines.append(
            "[    0.100000] Info: [libukboot] "
            f"<boot.c @  523> main returned {main_return}"
        )
        return "\n".join(lines)

    def fake_qemu(self, root, action="pass"):
        qemu = root / "qemu" / "bin" / "qemu-system-x86_64"
        qemu.parent.mkdir(parents=True)
        script = [
            "#!/usr/bin/python3",
            "import os, pathlib, sys",
        ]
        if action == "mutate":
            script.append(
                "p=pathlib.Path('disk.img'); "
                "d=p.read_bytes(); p.write_bytes(b'Z'+d[1:])"
            )
        elif action == "replace":
            script.append(
                "p=pathlib.Path('disk.img'); d=p.read_bytes(); "
                "p.unlink(); p.write_bytes(d)"
            )
        script.extend([
            "print('Hyper-V Hv#1 hypercall page enabled')",
            "print('Hyper-V SynIC:')",
            "print('Powered by')",
            "print('Calling main(')",
            *[
                "print(" + repr(record) + ")"
                for record in runner.UNAVAILABLE_RECORDS[:1]
            ],
            f"print('{runner.PLATFORM_MARKER}')",
            *[
                "print(" + repr(record) + ")"
                for record in runner.UNAVAILABLE_RECORDS[1:-1]
            ],
            f"print('{runner.UNAVAILABLE_MARKER}')",
            *[
                "print(" + repr(record) + ")"
                for record in runner.UNAVAILABLE_RECORDS[-1:]
            ],
            (
                f"print('{runner.LEGACY_APIC_MARKER}') "
                "if 'x2apic=off' in ' '.join(sys.argv) else None"
            ),
            "print('[ 0.1] Info: [libukboot] <boot.c @ 523> main returned 2')",
        ])
        qemu.write_text("\n".join(script) + "\n")
        qemu.chmod(0o700)
        return qemu

    def run_fake_boot(self, action):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qemu = self.fake_qemu(root, action)
            code = root / "code"
            variables = root / "vars"
            image = root / "image"
            code.write_bytes(b"code")
            variables.write_bytes(b"vars")
            image.write_bytes(b"image")
            record = {
                "blob": "unused",
                "name": "image",
                "size": image.stat().st_size,
                "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            }
            return runner.run_boot(
                qemu, code, {
                    **record, "name": "OVMF_CODE.fd",
                    "size": code.stat().st_size,
                    "sha256": hashlib.sha256(code.read_bytes()).hexdigest(),
                }, variables, {
                    **record, "name": "OVMF_VARS.fd",
                    "size": variables.stat().st_size,
                    "sha256": hashlib.sha256(
                        variables.read_bytes()
                    ).hexdigest(),
                }, image, record, image.stat().st_size,
                "platform-unavailable-v1", "raw-x2apic", False, root,
            )

    def run_fake_guarded_boot(self, extra=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qemu = root / "qemu" / "bin" / "qemu-system-x86_64"
            qemu.parent.mkdir(parents=True)
            lines = [
                "Hyper-V Hv#1 hypercall page enabled",
                "Hyper-V SynIC:",
                "Powered by",
                "Calling main(",
                *GUARDED_PRODUCER_RECORDS.read_text().splitlines(),
            ]
            if extra is not None:
                lines.append(extra)
            lines.append(
                "[ 0.1] Info: [libukboot] <boot.c @ 523> main returned 2"
            )
            qemu.write_text(
                "#!/bin/sh\n"
                + "\n".join("printf '%s\\n' " + repr(line) for line in lines)
                + "\n"
            )
            qemu.chmod(0o700)
            code = root / "code"
            variables = root / "vars"
            image = root / "image"
            code.write_bytes(b"code")
            variables.write_bytes(b"vars")
            image.write_bytes(b"image")

            def record(path, name):
                return {
                    "blob": "unused",
                    "name": name,
                    "size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }

            return runner.run_boot(
                qemu, code, record(code, "OVMF_CODE.fd"),
                variables, record(variables, "OVMF_VARS.fd"),
                image, record(image, "image"), image.stat().st_size,
                preflight.GUARDED_BOOT_POLICY, "raw-x2apic", False, root,
                self.guarded_contract(
                    hashlib.sha256(self.guarded_config()).hexdigest()
                ),
            )

    def test_boot_reuses_readonly_code_and_copies_only_variables(self):
        original = runner.shutil.copyfile
        copies = []

        def tracked(source, destination, *args, **kwargs):
            copies.append((Path(source).name, Path(destination).name))
            return original(source, destination, *args, **kwargs)

        with mock.patch.object(
            runner.shutil, "copyfile", side_effect=tracked
        ):
            self.run_fake_boot("pass")
        self.assertEqual(copies, [("vars", "OVMF_VARS.fd")])

    def test_strict_no_device_policy_rejects_guarded_storage_failures(self):
        runner.validate_boot_log(
            self.boot_log(), "platform-unavailable-v1", False
        )
        for text in (
            self.boot_log(
                main_return=1,
                extra="HYPERV_STORAGE SELECT FAIL rc=-2 writes=0",
            ),
            self.boot_log(extra="UK_HYPERV_IO_READY"),
            self.boot_log(extra="HYPERV_STORAGE WRITE PASS bytes=512"),
            self.boot_log(main_return=0),
            self.boot_log(
                extra="diagnostic: expected main returned 2 but continued"
            ),
        ):
            with self.subTest(text=text[-80:]):
                with self.assertRaises(runner.RunnerError):
                    runner.validate_boot_log(
                        text, "platform-unavailable-v1", False
                    )

    def test_guarded_v2_accepts_only_authentic_pristine_unavailable_records(self):
        contract = self.guarded_contract(
            hashlib.sha256(self.guarded_config()).hexdigest()
        )
        runner.validate_boot_log(
            self.guarded_boot_log(), preflight.GUARDED_BOOT_POLICY,
            False, contract,
        )
        runner.validate_boot_log(
            self.guarded_boot_log(legacy=True),
            preflight.GUARDED_BOOT_POLICY, True, contract,
        )
        self.assertEqual(
            GUARDED_PRODUCER_RECORDS.read_text().splitlines(),
            [
                (
                    "HYPERV_PERSISTENCE START PASS "
                    "run=00112233445566778899aabbccddeeff "
                    "address=0:0:0 sectors=1000 sector_size=512"
                ),
                (
                    "HYPERV_PERSISTENCE SELECT UNAVAILABLE "
                    "reason=no-devices writes=0 flushes=0"
                ),
                runner.PLATFORM_MARKER,
                "UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices",
            ],
        )

    def test_guarded_v2_rejects_wrong_or_additional_persistence_activity(self):
        contract = self.guarded_contract(
            hashlib.sha256(self.guarded_config()).hexdigest()
        )
        authentic = GUARDED_PRODUCER_RECORDS.read_text().splitlines()
        variants = {
            "missing": authentic[:-1],
            "duplicate": authentic + [authentic[-1]],
            "reordered": [authentic[0], authentic[2], authentic[1], authentic[3]],
            "wrong-run": [
                authentic[0].replace(contract["run_id"], "f" * 32),
                *authentic[1:],
            ],
            "wrong-lun": [
                authentic[0].replace("address=0:0:0", "address=0:0:1"),
                *authentic[1:],
            ],
            "wrong-geometry": [
                authentic[0].replace("sectors=1000", "sectors=999"),
                *authentic[1:],
            ],
            "wrong-protocol": [
                *authentic[:-1],
                "UK_HYPERV_PERSISTENCE_UNAVAILABLE:2:2:no-devices",
            ],
            "wrong-policy": [
                *authentic[:-1],
                "UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:1:no-devices",
            ],
            "wrong-reason": [
                authentic[0],
                authentic[1].replace("no-devices", "discovery-failed"),
                authentic[2],
                authentic[3].replace("no-devices", "discovery-failed"),
            ],
            "old-fail": [
                authentic[0],
                "HYPERV_PERSISTENCE SELECT FAIL rc=-2 writes=0",
            ],
            "final-pass": authentic + [
                "HYPERV_PERSISTENCE FINAL PASS rc=0"
            ],
            "final-fail": authentic + [
                "HYPERV_PERSISTENCE FINAL FAIL rc=-2"
            ],
            "identity": authentic + [
                "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:synthetic"
            ],
            "boot1": authentic + [
                "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:synthetic"
            ],
            "boot2": authentic + [
                "UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:synthetic"
            ],
            "write": authentic + [
                "HYPERV_PERSISTENCE BOOT1_WRITE PASS run="
                + contract["run_id"]
            ],
            "read": authentic + [
                "HYPERV_PERSISTENCE BOOT2_READ PASS run="
                + contract["run_id"]
            ],
            "flush": authentic + [
                "HYPERV_PERSISTENCE FLUSH PASS writes=0 flushes=1"
            ],
            "wrong-seed": authentic + [
                "HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
                "reason=boot-signature id=0"
            ],
            "receipt": authentic + [
                "UK_HYPERV_PERSISTENCE_RECEIPT:synthetic"
            ],
            "ordinary-acceptance": authentic + [
                runner.UNAVAILABLE_RECORDS[0]
            ],
            "live-io": authentic + ["UK_HYPERV_IO_READY"],
            "prefixed-diagnostic": authentic + [
                "diagnostic HYPERV_PERSISTENCE FINAL PASS rc=0"
            ],
        }
        for description, records in variants.items():
            with self.subTest(description=description):
                with self.assertRaises(runner.RunnerError):
                    runner.validate_boot_log(
                        self.guarded_boot_log(records),
                        preflight.GUARDED_BOOT_POLICY, False, contract,
                    )
        with self.assertRaises(runner.RunnerError):
            runner.validate_boot_log(
                self.guarded_boot_log(main_return=1),
                preflight.GUARDED_BOOT_POLICY, False, contract,
            )
        with self.assertRaises(runner.RunnerError):
            runner.validate_boot_log(
                self.guarded_boot_log(),
                preflight.GUARDED_BOOT_POLICY, False, None,
            )

    def test_actual_qemu_process_uses_readonly_footer_mask_and_passes(self):
        result, _ = self.run_fake_boot("pass")
        self.assertEqual(result["result"], "PASS")

    def test_actual_runner_path_enforces_guarded_platform_only_outcome(self):
        result, _ = self.run_fake_guarded_boot()
        self.assertEqual(result["result"], "PASS")
        with self.assertRaises(runner.RunnerError):
            self.run_fake_guarded_boot(
                "HYPERV_PERSISTENCE FINAL PASS rc=0"
            )

    def test_actual_qemu_mutation_cannot_forge_pass(self):
        with self.assertRaisesRegex(runner.RunnerError, "mutated"):
            self.run_fake_boot("mutate")

    def test_actual_qemu_replacement_cannot_forge_pass(self):
        with self.assertRaisesRegex(runner.RunnerError, "replaced"):
            self.run_fake_boot("replace")

    def test_qemu_command_shape_masks_fixed_vhd_footer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qemu = root / "qemu" / "bin" / "qemu-system-x86_64"
            qemu.parent.mkdir(parents=True)
            for path, value in (
                (qemu, b"q"), (root / "code", b"c"),
                (root / "vars", b"v"), (root / "image", b"i"),
            ):
                path.write_bytes(value)
            captured = {}

            def execute(command, **kwargs):
                captured["command"] = command
                kwargs["stdout"].write(self.boot_log().encode())
                return mock.Mock(returncode=0)

            image = root / "image"
            record = {
                "name": "image", "blob": "unused", "size": 1,
                "sha256": hashlib.sha256(b"i").hexdigest(),
            }
            with mock.patch.object(
                runner.subprocess, "run", side_effect=execute
            ):
                runner.run_boot(
                    qemu, root / "code", {
                        **record, "name": "OVMF_CODE.fd",
                        "sha256": hashlib.sha256(b"c").hexdigest(),
                    }, root / "vars", {
                        **record, "name": "OVMF_VARS.fd",
                        "sha256": hashlib.sha256(b"v").hexdigest(),
                    }, image, record,
                    preflight.azure.VIRTUAL_SIZE,
                    "platform-unavailable-v1", "raw-x2apic", False, root,
                )
            command = captured["command"]
            disk = json.loads(command[command.index("-blockdev") + 1])
            self.assertEqual(disk["size"], preflight.azure.VIRTUAL_SIZE)
            self.assertTrue(disk["read-only"])
            self.assertEqual(command[-2:], ["-nic", "none"])
            self.assertIn("vmbus-bridge,irq=15", command)

    def test_runner_manifest_requires_exact_integer_and_closure_fields(self):
        state = self.state()
        manifest = preflight.host_phase_manifest(state, "capability")
        for field, value in (
            ("schema_version", True),
            ("raw_size", float(manifest["raw_size"])),
        ):
            changed = json.loads(json.dumps(manifest))
            changed[field] = value
            with self.assertRaises(runner.RunnerError):
                runner.parse_manifest(base64_encode(changed), "capability")
        changed = json.loads(json.dumps(manifest))
        changed["qemu_support"][0]["blob"] += "/foreign"
        with self.assertRaisesRegex(runner.RunnerError, "qemu-support"):
            runner.parse_manifest(base64_encode(changed), "capability")
        state = self.state(boot_policy=preflight.GUARDED_BOOT_POLICY)
        capability = preflight.host_phase_manifest(state, "capability")
        private = preflight.host_phase_manifest(
            state, "private",
            hashlib.sha256(
                preflight.azure.canonical_json(capability)
            ).hexdigest(),
        )
        for mutate in (
            lambda value: value["guarded"].__setitem__("protocol", 2),
            lambda value: value["guarded"].__setitem__("scope", "storage"),
            lambda value: value["guarded"]["producer"]["files"].__setitem__(
                "support/apps/hyperv-acceptance/persistence.c", "f" * 64
            ),
            lambda value: value.__setitem__(
                "boot_policy", "platform-unavailable-v1"
            ),
        ):
            changed = json.loads(json.dumps(private))
            mutate(changed)
            with self.assertRaises(runner.RunnerError):
                runner.parse_manifest(base64_encode(changed), "private")


class PrivatePreflightCompletedReceiptTest(PrivatePreflightFixture):
    @staticmethod
    def host_receipt(state, phase, manifest, logs):
        formats = ("capability",) if phase == "capability" else ("raw", "vhd")
        return {
            "schema": runner.EVIDENCE_SCHEMA,
            "schema_version": 2,
            "phase": phase,
            "identity": state["identity"],
            "result": "PASS",
            "manifest_sha256": hashlib.sha256(
                preflight.azure.canonical_json(manifest)
            ).hexdigest(),
            "runner_sha256": state["implementation"]["files"]["runner"][
                "sha256"
            ],
            "host_boot_id": "66666666-6666-4666-8666-666666666666",
            "boot_policy": (
                "platform-unavailable-v1"
                if phase == "capability"
                else preflight.GUARDED_BOOT_POLICY
            ),
            "acceptance_scope": "platform-only",
            "storage_result": (
                "NOT_EVALUATED" if phase == "capability" else "UNAVAILABLE"
            ),
            "boots": {
                image_format: {
                    mode: {
                        "result": "PASS",
                        "log_sha256": hashlib.sha256(
                            logs[f"{image_format}-{mode}.log"]
                        ).hexdigest(),
                        "return_code": 0,
                    }
                    for mode in ("x2apic", "legacy-apic")
                }
                for image_format in formats
            },
        }

    def completed_handoff(self, root):
        root.mkdir(mode=0o700)
        state = self.state(boot_policy=preflight.GUARDED_BOOT_POLICY)
        state.update({
            "phase": "complete",
            "subscription": "11111111-2222-3333-4444-555555555555",
            "cloud_preflight": {
                "subscription": "11111111-2222-3333-4444-555555555555",
                "sku": {},
                "image": {
                    "publisher": "Canonical",
                    "offer": "ubuntu-24_04-lts",
                    "sku": "server",
                    "version": "24.04.202609010",
                    "urn": (
                        "Canonical:ubuntu-24_04-lts:"
                        "server:24.04.202609010"
                    ),
                    "architecture": "x64",
                    "hyperv_generation": "V2",
                },
            },
            "deadline_monotonic": time.monotonic() + 3600,
            "deadline_utc": "2026-09-09T16:00:00Z",
            "storage_account": "ukhvp1234567890abcd",
            "firewall_obligation": None,
            "resource_group_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg"
            ),
            "host_vm_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Compute/virtualMachines/"
                "uk-hvp-123456789abc-host"
            ),
            "host_disk_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Compute/disks/"
                "uk-hvp-123456789abc-host-os"
            ),
            "host_nic_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Network/networkInterfaces/"
                "uk-hvp-123456789abc-host-nic"
            ),
            "storage_account_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.Storage/storageAccounts/ukhvp1234567890abcd"
            ),
            "shutdown_schedule_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                "Microsoft.DevTestLab/schedules/"
                "shutdown-computevm-uk-hvp-123456789abc-host"
            ),
            "host_deployment": {
                "phase": "resources-verified",
                "operation_id": "22222222-2222-4222-8222-222222222222",
                "deployment_id": (
                    "/subscriptions/11111111-2222-3333-4444-555555555555/"
                    "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                    "Microsoft.Resources/deployments/uk-hvp-123456789abc-host"
                ),
                "correlation_id": (
                    "33333333-3333-4333-8333-333333333333"
                ),
                "vm_id": (
                    "/subscriptions/11111111-2222-3333-4444-555555555555/"
                    "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                    "Microsoft.Compute/virtualMachines/"
                    "uk-hvp-123456789abc-host"
                ),
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_id": (
                    "/subscriptions/11111111-2222-3333-4444-555555555555/"
                    "resourceGroups/uk-hvp-123456789abc-rg/providers/"
                    "Microsoft.Compute/disks/"
                    "uk-hvp-123456789abc-host-os"
                ),
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
                "shutdown_time": "1600",
            },
            "staged_input_bytes": state["input_manifest"]["budget"][
                "remote_input_bytes"
            ],
            "control_payload_bytes": 4096,
            "pending_secret_files": [],
            "cleanup_required": False,
            "active_sas": False,
            "active_sas_signing_key_sha256": None,
            "host_deallocated": True,
        })
        capability_manifest = preflight.host_phase_manifest(
            state, "capability"
        )
        capability_manifest_sha256 = hashlib.sha256(
            preflight.azure.canonical_json(capability_manifest)
        ).hexdigest()
        private_manifest = preflight.host_phase_manifest(
            state, "private", capability_manifest_sha256
        )
        state["capability_manifest_sha256"] = capability_manifest_sha256
        state["private_manifest_sha256"] = hashlib.sha256(
            preflight.azure.canonical_json(private_manifest)
        ).hexdigest()

        capability_logs = {
            f"capability-{mode}.log": (
                PrivatePreflightRunnerTest.boot_log(
                    legacy=mode == "legacy-apic"
                ).encode()
            )
            for mode in ("x2apic", "legacy-apic")
        }
        private_logs = {
            f"{image_format}-{mode}.log": (
                PrivatePreflightRunnerTest.guarded_boot_log(
                    legacy=mode == "legacy-apic"
                ).encode()
            )
            for image_format in ("raw", "vhd")
            for mode in ("x2apic", "legacy-apic")
        }
        receipts = {}
        evidence_bytes = 0
        for phase, manifest, logs in (
            ("capability", capability_manifest, capability_logs),
            ("private", private_manifest, private_logs),
        ):
            directory = root / "evidence" / phase
            directory.mkdir(mode=0o700, parents=True)
            for name, raw in logs.items():
                preflight.save_private_bytes(directory / name, raw)
                evidence_bytes += len(raw)
            receipt = self.host_receipt(state, phase, manifest, logs)
            receipt_bytes = preflight.azure.canonical_json(receipt)
            preflight.save_private_bytes(
                directory / "receipt.json", receipt_bytes
            )
            evidence_bytes += len(receipt_bytes)
            digest = hashlib.sha256(receipt_bytes).hexdigest()
            state[phase + "_receipt_sha256"] = digest
            receipts[phase] = receipt
        state["evidence_bytes"] = evidence_bytes

        manifest = state["input_manifest"]
        final = {
            "schema": preflight.RECEIPT_SCHEMA,
            "schema_version": preflight.RECEIPT_SCHEMA_VERSION,
            "result": "PASS",
            "identity": state["identity"],
            "input_manifest_sha256": state["manifest_sha256"],
            "implementation": json.loads(json.dumps(state["implementation"])),
            "provenance": json.loads(json.dumps(manifest["provenance"])),
            "capability_reference": json.loads(json.dumps(
                manifest["capability_reference"]
            )),
            "private_build": json.loads(json.dumps(
                manifest["private_build"]
            )),
            "inputs": {
                role: {
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
                for role, record in manifest["files"].items()
            },
            "qemu_support": json.loads(json.dumps(manifest["qemu_support"])),
            "miz": json.loads(json.dumps(manifest["miz"])),
            "packaging": json.loads(json.dumps(manifest["packaging"])),
            "budget": {
                **manifest["budget"],
                "staged_input_bytes": state["staged_input_bytes"],
                "control_payload_bytes": state["control_payload_bytes"],
                "evidence_bytes": state["evidence_bytes"],
            },
            "host_image": json.loads(json.dumps(
                state["cloud_preflight"]["image"]
            )),
            "host": {
                "operation_id": state["host_deployment"]["operation_id"],
                "deployment_correlation_id": state["host_deployment"][
                    "correlation_id"
                ],
                "vm_uuid": state["host_deployment"]["vm_uuid"],
                "disk_uuid": state["host_deployment"]["disk_uuid"],
                "boot_id": receipts["private"]["host_boot_id"],
            },
            "capability_receipt_sha256": state[
                "capability_receipt_sha256"
            ],
            "private_receipt_sha256": state["private_receipt_sha256"],
            "boot_policy": manifest["boot_policy"],
            "acceptance_scope": "platform-only",
            "storage_result": receipts["private"]["storage_result"],
            "guarded": json.loads(json.dumps(manifest["guarded"])),
            "capability_boots": json.loads(json.dumps(
                receipts["capability"]["boots"]
            )),
            "private_boots": json.loads(json.dumps(
                receipts["private"]["boots"]
            )),
            "cleanup": "complete",
        }
        receipt_path = root / "private-receipt.json"
        preflight.save_private_bytes(
            receipt_path, preflight.azure.canonical_json(final)
        )
        state["final_receipt_sha256"] = preflight.azure.image_sha256(
            receipt_path
        )
        preflight.azure.save_durable_json(root / preflight.STATE_FILE, state)
        return state, final, receipt_path

    def test_completed_handoff_loads_only_full_exact_image_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            state, final, receipt_path = self.completed_handoff(root)
            with mock.patch.object(
                preflight, "verify_immutable_inputs"
            ) as verify:
                validated, loaded_path = preflight.load_completed_receipt(
                    root
                )
            verify.assert_called_once()
            self.assertEqual(loaded_path, receipt_path)
            self.assertEqual(validated, final)
            self.assertEqual(
                validated["inputs"]["vhd"]["sha256"],
                state["input_manifest"]["files"]["vhd"]["sha256"],
            )
            self.assertEqual(
                validated["private_build"],
                state["input_manifest"]["private_build"],
            )

    def test_completed_handoff_rejects_prepared_or_stale_bindings(self):
        for mutation in (
            "prepared", "vhd", "build", "cleanup", "sas",
            "deallocated", "deployment", "control", "resource",
            "evidence",
        ):
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "state"
                state, final, receipt_path = self.completed_handoff(root)
                if mutation == "prepared":
                    state["phase"] = "prepared"
                elif mutation == "vhd":
                    final["inputs"]["vhd"]["sha256"] = "f" * 64
                elif mutation == "build":
                    final["private_build"]["receipt"]["output"][
                        "sha256"
                    ] = "e" * 64
                elif mutation == "cleanup":
                    final["cleanup"] = "pending"
                elif mutation == "sas":
                    state["active_sas"] = True
                elif mutation == "deallocated":
                    state["host_deallocated"] = False
                elif mutation == "deployment":
                    state["host_deployment"][
                        "phase"
                    ] = "deployment-succeeded"
                elif mutation == "control":
                    state["control_payload_bytes"] = 0
                    final["budget"]["control_payload_bytes"] = 0
                elif mutation == "resource":
                    state["host_nic_id"] += "-replacement"
                else:
                    state["evidence_bytes"] += 1
                    final["budget"]["evidence_bytes"] = state[
                        "evidence_bytes"
                    ]
                if mutation != "prepared":
                    receipt_path.unlink()
                    preflight.save_private_bytes(
                        receipt_path,
                        preflight.azure.canonical_json(final),
                    )
                    state["final_receipt_sha256"] = (
                        preflight.azure.image_sha256(receipt_path)
                    )
                preflight.azure.save_durable_json(
                    root / preflight.STATE_FILE, state
                )
                with mock.patch.object(
                    preflight, "verify_immutable_inputs"
                ):
                    with self.assertRaises(ValueError):
                        preflight.load_completed_receipt(root)

    def test_completed_handoff_reparses_private_boot_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            state, final, receipt_path = self.completed_handoff(root)
            log_path = root / "evidence" / "private" / "raw-x2apic.log"
            log_path.write_bytes(
                log_path.read_bytes()
                + b"\nHYPERV_PERSISTENCE WRITE PASS writes=1"
            )
            evidence_path = root / "evidence" / "private" / "receipt.json"
            evidence = json.loads(evidence_path.read_text())
            evidence["boots"]["raw"]["x2apic"]["log_sha256"] = (
                preflight.azure.image_sha256(log_path)
            )
            evidence_path.unlink()
            preflight.save_private_bytes(
                evidence_path, preflight.azure.canonical_json(evidence)
            )
            state["private_receipt_sha256"] = (
                preflight.azure.image_sha256(evidence_path)
            )
            final["private_receipt_sha256"] = state[
                "private_receipt_sha256"
            ]
            final["private_boots"] = evidence["boots"]
            receipt_path.unlink()
            preflight.save_private_bytes(
                receipt_path, preflight.azure.canonical_json(final)
            )
            state["final_receipt_sha256"] = (
                preflight.azure.image_sha256(receipt_path)
            )
            preflight.azure.save_durable_json(
                root / preflight.STATE_FILE, state
            )
            with mock.patch.object(
                preflight, "verify_immutable_inputs"
            ):
                with self.assertRaises(runner.RunnerError):
                    preflight.load_completed_receipt(root)


class PrivatePreflightBlobTest(PrivatePreflightFixture):
    def test_declared_blob_sdk_is_exact_when_available(self):
        try:
            from importlib.metadata import PackageNotFoundError, version
            installed = version("azure-storage-blob")
        except PackageNotFoundError:
            self.skipTest("azure-storage-blob is not installed in this runner")
        self.assertEqual(installed, preflight.SDK_VERSION)
        self.assertIsNotNone(preflight.check_blob_dependency())
        contract = preflight.sdk_dependency_contract()
        self.assertEqual(
            [
                (item["name"], item["version"])
                for item in contract["distributions"]
            ],
            list(preflight.SDK_DISTRIBUTIONS),
        )

    def test_blob_worker_rejects_bool_sizes_and_public_request_files(self):
        request = {
            "schema": blob_worker.SCHEMA,
            "schema_version": 1,
            "action": "upload",
            "account_url": "https://ukhvp123.blob.core.windows.net",
            "container": "preflight",
            "files": [{
                "blob": "input", "path": "/owner/input",
                "size": True, "sha256": "a" * 64,
            }],
            "create_container": False,
        }
        with self.assertRaises(blob_worker.WorkerError):
            blob_worker.require_nonnegative(True)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "request.json"
            path.write_text(json.dumps(request))
            path.chmod(0o644)
            with self.assertRaisesRegex(
                blob_worker.WorkerError, "request-file"
            ):
                blob_worker.load_request(path)

    def test_absolute_deadline_kills_blocked_blob_worker(self):
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired(
            ["worker"], 1
        )
        with mock.patch.object(
            preflight, "check_blob_dependency"
        ), mock.patch.object(
            preflight.subprocess, "Popen", return_value=process
        ), tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            state_path.write_text("{}")

            @contextmanager
            def request_file(_kind, value):
                path = Path(temporary) / ".blob-request.json"
                path.write_text(json.dumps(value))
                try:
                    yield path
                finally:
                    path.unlink(missing_ok=True)

            run = mock.Mock()
            run.tracked_private_json.side_effect = request_file
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                preflight.run_blob_worker(
                    run,
                    {
                        "schema": blob_worker.SCHEMA,
                        "schema_version": 1,
                        "action": "download",
                        "account_url": (
                            "https://ukhvp123.blob.core.windows.net"
                        ),
                        "container": "preflight",
                        "files": [{
                            "blob": "receipt", "path": "/owner/output",
                            "maximum": 1,
                        }],
                        "create_container": False,
                    },
                    "sv=secret", time.monotonic() + 0.1,
                )
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()

    def test_multifile_transfer_is_one_deadline_bounded_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state()
            path = root / "state.json"
            run = mock.Mock(state=state, state_path=path)
            files = []
            for index, content in enumerate((b"a", b"bb")):
                source = root / f"in-{index}"
                source.write_bytes(content)
                files.append((
                    f"blob-{index}", source, len(content),
                    hashlib.sha256(content).hexdigest(),
                ))
            with mock.patch.object(
                preflight, "run_blob_worker", return_value=3
            ) as worker:
                self.assertEqual(
                    preflight.upload_blob_set(
                        run,
                        "https://ukhvp123.blob.core.windows.net",
                        "sv=secret", "preflight", files,
                        create_container=True,
                        deadline=time.monotonic() + 10,
                    ),
                    3,
                )
            self.assertEqual(len(worker.call_args.args[1]["files"]), 2)

    def test_success_returned_after_deadline_is_rejected(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (
            b'{"schema":1,"result":"PASS","bytes":1}', b""
        )
        monotonic = iter((10.0, 11.0))
        with mock.patch.object(
            preflight, "check_blob_dependency"
        ), mock.patch.object(
            preflight.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            preflight.time, "monotonic", side_effect=lambda: next(monotonic)
        ), tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            state_path.write_text("{}")

            @contextmanager
            def request_file(_kind, value):
                path = Path(temporary) / ".blob-request.json"
                path.write_text(json.dumps(value))
                try:
                    yield path
                finally:
                    path.unlink(missing_ok=True)

            run = mock.Mock()
            run.tracked_private_json.side_effect = request_file
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                preflight.run_blob_worker(
                    run, {}, "sv=secret", 10.5
                )


class PrivatePreflightTemplateTest(PrivatePreflightFixture):
    def test_arm_template_is_exact_private_standard_host(self):
        template = json.loads(preflight.TEMPLATE_PATH.read_text())
        self.assertIn("operationId", template["parameters"])
        self.assertEqual(
            template["variables"]["tags"]["preflight-operation"],
            "[parameters('operationId')]",
        )
        self.assertEqual(
            set(template["outputs"]), {"hostVmUuid", "hostDiskUuid"}
        )
        self.assertEqual(
            template["outputs"]["hostVmUuid"]["value"],
            "[reference(variables('hostName'), '2025-11-01').vmId]",
        )
        self.assertEqual(
            modeled_host_disk_output_order(template),
            ("vm-created", "implicit-disk-read", "outer-output"),
        )
        direct = copy.deepcopy(template)
        direct["outputs"]["hostDiskUuid"]["value"] = (
            "[reference(resourceId('Microsoft.Compute/disks', "
            "variables('hostDiskName')), '2025-01-02').uniqueId]"
        )
        with self.assertRaisesRegex(RuntimeError, "ResourceNotFound"):
            modeled_host_disk_output_order(direct)
        unordered = copy.deepcopy(template)
        identity = next(
            resource for resource in unordered["resources"]
            if resource["type"] == "Microsoft.Resources/deployments"
        )
        identity["dependsOn"] = []
        with self.assertRaisesRegex(RuntimeError, "ResourceNotFound"):
            modeled_host_disk_output_order(unordered)
        resources = template["resources"]
        kinds = [resource["type"] for resource in resources]
        self.assertEqual(
            kinds.count("Microsoft.Compute/virtualMachines"), 1
        )
        self.assertNotIn("Microsoft.Network/publicIPAddresses", kinds)
        self.assertNotIn("Microsoft.Network/natGateways", kinds)
        vm = next(
            item for item in resources
            if item["type"] == "Microsoft.Compute/virtualMachines"
        )
        profile = vm["properties"]["storageProfile"]
        self.assertEqual(profile["dataDisks"], [])
        self.assertEqual(profile["osDisk"]["diskSizeGB"], 32)
        self.assertEqual(
            vm["properties"]["securityProfile"],
            {"securityType": "Standard"},
        )
        nic = next(
            item for item in resources
            if item["type"] == "Microsoft.Network/networkInterfaces"
        )
        self.assertIs(nic["properties"]["enableIPForwarding"], False)
        subnet = next(
            item for item in resources
            if item["type"] == "Microsoft.Network/virtualNetworks"
        )["properties"]["subnets"][0]["properties"]
        self.assertIs(subnet["defaultOutboundAccess"], False)
        self.assertNotIn("natGateway", subnet)
        storage = next(
            item for item in resources
            if item["type"] == "Microsoft.Storage/storageAccounts"
        )
        self.assertEqual(
            storage["properties"]["networkAcls"],
            {
                "bypass": "None",
                "defaultAction": "Deny",
                "ipRules": [],
                "virtualNetworkRules": [{
                    "id": "[variables('subnetId')]",
                    "action": "Allow",
                }],
            },
        )


class PrivatePreflightCloudTest(PrivatePreflightFixture):
    @mock.patch.object(preflight.azure, "resolve_peer_image")
    @mock.patch.object(preflight.azure, "exact_vm_sku")
    @mock.patch.object(preflight.azure, "azure_cli")
    @mock.patch.object(preflight.azure, "selected_account")
    def test_subscription_preflight_is_exact_and_private(
        self, account, command, sku, image
    ):
        subscription = "11111111-2222-3333-4444-555555555555"
        account.return_value = subscription
        command.side_effect = [
            "Registered", "Registered", "Registered", "Registered",
            ["2025-11-01"], ["True"],
            [
                {"name": {"value": "cores"}, "limit": 8, "currentValue": 0},
                {
                    "name": {"value": "standardDSv5Family"},
                    "limit": 2, "currentValue": 0,
                },
            ],
        ]
        sku.return_value = {
            "name": preflight.VM_SIZE,
            "family": "standardDSv5Family",
            "vcpus": 2,
            "generations": ["V2"],
        }
        image.return_value = {
            "publisher": "Canonical", "offer": "ubuntu-24_04-lts",
            "sku": "server", "version": "24.04.202609010",
            "hyperv_generation": "V2",
        }
        result = preflight.check_subscription(subscription)
        self.assertEqual(result["image"]["version"], "24.04.202609010")
        self.assertTrue(all(
            call.kwargs.get("private") is True
            for call in command.call_args_list
        ))

    def test_deployment_obligation_is_durable_before_create(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            with mock.patch.object(
                preflight.uuid, "uuid4",
                return_value=uuid.UUID(
                    "22222222-2222-4222-8222-222222222222"
                ),
            ):
                receipt = run.begin_host_deployment("0526")
            self.assertEqual(receipt["phase"], "pending")
            self.assertEqual(
                receipt["vm_id"], run.expected_host_ids()["vm_id"]
            )
            self.assertIs(state["host_deployment"], receipt)
            run.record.assert_called_once()

    def test_partial_persisted_identity_anchors_are_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, state = self.run_fixture(root)
            self.begin_operation(run, state, "vm-verified")
            preflight.azure.save_json(run.state_path, state)
            with self.assertRaisesRegex(ValueError, "anchors are invalid"):
                preflight.load_state(root)

    def test_ambiguous_create_reconciles_only_original_deployment(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "pending")
            deployment = self.deployment(run, state)
            run.az.return_value = deployment
            run.capture_host_identity = mock.Mock()
            self.assertTrue(
                run.reconcile_host_deployment(time.monotonic() + 10)
            )
            run.capture_host_identity.assert_called_once_with(
                mock.ANY
            )
            command = run.az.call_args.args[0]
            self.assertEqual(command[:3], ["deployment", "group", "show"])
            self.assertEqual(
                state["host_deployment"]["correlation_id"],
                "33333333-3333-4333-8333-333333333333",
            )
            self.assertEqual(
                state["host_deployment"]["vm_uuid"],
                "44444444-4444-4444-8444-444444444444",
            )
            self.assertEqual(
                state["host_deployment"]["disk_uuid"],
                "55555555-5555-4555-8555-555555555555",
            )

    def test_missing_original_deployment_needs_repeated_empty_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "pending")
            missing = preflight.azure.AzureCliError(
                ["deployment", "group"],
                mock.Mock(
                    returncode=1,
                    stderr="ERROR: (DeploymentNotFound) absent",
                ),
                True,
            )
            run.az.side_effect = [
                missing, [], missing, [], missing, [],
            ]
            with mock.patch.object(preflight.time, "sleep"):
                self.assertFalse(
                    run.reconcile_host_deployment(time.monotonic() + 10)
                )
            self.assertEqual(
                state["host_deployment"]["phase"], "not-created-empty"
            )

    def test_vm_and_disk_proof_never_tags_or_adopts_implicit_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "deployment-succeeded")
            state["host_deployment"].update({
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            })
            vm, disk = self.vm_disk(run, state)
            run.az.side_effect = [vm, vm, disk, vm, disk]
            run.capture_host_identity()
            commands = [" ".join(call.args[0]) for call in run.az.call_args_list]
            self.assertFalse(any("disk update" in command for command in commands))
            self.assertEqual(
                state["host_deployment"]["disk_uuid"], disk["uniqueId"]
            )

    def test_disk_identity_is_durable_before_metadata_settles(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "deployment-succeeded")
            state["host_deployment"].update({
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            })
            vm, disk = self.vm_disk(run, state)
            disk["tags"] = {}
            run.az.side_effect = [vm, vm, disk]
            run.settle_host_identity = mock.Mock(
                side_effect=RuntimeError("metadata did not settle")
            )
            with self.assertRaisesRegex(RuntimeError, "did not settle"):
                run.capture_host_identity()
            self.assertEqual(
                state["host_deployment"]["phase"], "resources-verified"
            )
            self.assertEqual(
                state["host_deployment"]["disk_uuid"], disk["uniqueId"]
            )

    def test_updating_vm_is_bounded_until_identity_settles(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            vm, disk = self.vm_disk(run, state)
            updating = {**vm, "provisioningState": "Updating"}
            run.verify_host_identity = mock.Mock(
                side_effect=[(updating, disk), (vm, disk)]
            )
            with mock.patch.object(preflight.time, "sleep"):
                settled = run.settle_host_identity(time.monotonic() + 10)
            self.assertEqual(settled, (vm, disk))
            self.assertEqual(run.verify_host_identity.call_count, 2)

    def test_partial_live_read_preserves_deployment_identity_anchors(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "deployment-succeeded")
            state["host_deployment"].update({
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            })
            vm, _ = self.vm_disk(run, state)
            run.az.side_effect = [
                vm, vm, RuntimeError("disk unavailable"),
            ]
            with self.assertRaisesRegex(RuntimeError, "disk unavailable"):
                run.capture_host_identity()
            self.assertEqual(state["host_deployment"]["phase"], "vm-verified")
            self.assertEqual(
                state["host_deployment"]["disk_uuid"],
                "55555555-5555-4555-8555-555555555555",
            )
            view = {
                "instanceView": {
                    "statuses": [{"code": "PowerState/deallocated"}]
                },
            }
            run.az.reset_mock()
            _, disk = self.vm_disk(run, state)
            state["deadline_monotonic"] = time.monotonic() - 1
            run.cleanup_deadline = time.monotonic() + 60
            run.az.side_effect = [
                vm, None, vm, view,
            ]
            run.deallocate_host()
            self.assertTrue(state["host_deallocated"])
            self.assertFalse(any(
                call.args[0][:2] == ["disk", "show"]
                for call in run.az.call_args_list
            ))

    def test_reconcile_disk_failure_still_deallocates_anchored_vm(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "pending")
            deployment = self.deployment(run, state)
            vm, _ = self.vm_disk(run, state)
            view = {
                "instanceView": {
                    "statuses": [{"code": "PowerState/deallocated"}]
                },
            }
            run.cleanup_deadline = time.monotonic() + 60
            run.az.side_effect = [
                deployment,
                vm, vm, RuntimeError("disk unavailable"),
                vm, None, vm, view,
            ]
            run.deallocate_host()
            self.assertTrue(state["host_deallocated"])
            self.assertEqual(
                state["host_deployment"]["vm_uuid"],
                "44444444-4444-4444-8444-444444444444",
            )
            self.assertEqual(
                state["host_deployment"]["disk_uuid"],
                "55555555-5555-4555-8555-555555555555",
            )
            commands = [
                call.args[0] for call in run.az.call_args_list
            ]
            self.assertEqual(
                sum(command[:2] == ["vm", "deallocate"]
                    for command in commands),
                1,
            )

    def test_deallocation_uses_vm_anchor_not_live_disk_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "resources-verified")
            vm, _ = self.vm_disk(run, state)
            view = {
                "instanceView": {
                    "statuses": [{"code": "PowerState/deallocated"}]
                },
            }
            run.az.side_effect = [vm, None, vm, view]
            run.deallocate_host()
            self.assertTrue(state["host_deallocated"])
            self.assertFalse(any(
                call.args[0][:2] == ["disk", "show"]
                for call in run.az.call_args_list
            ))

    def test_deallocation_refuses_replacement_vm(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "resources-verified")
            vm, _ = self.vm_disk(run, state)
            vm["vmId"] = "66666666-6666-4666-8666-666666666666"
            run.az.return_value = vm
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                run.deallocate_host()
            self.assertFalse(state.get("host_deallocated", False))
            self.assertFalse(any(
                call.args[0][:2] == ["vm", "deallocate"]
                for call in run.az.call_args_list
            ))

    def test_reconcile_refuses_replacement_before_first_live_vm_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "pending")
            deployment = self.deployment(run, state)
            replacement, _ = self.vm_disk(run, state)
            replacement["vmId"] = (
                "66666666-6666-4666-8666-666666666666"
            )
            run.az.side_effect = [deployment, replacement]
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                run.reconcile_host_deployment(time.monotonic() + 10)
            self.assertEqual(
                state["host_deployment"]["vm_uuid"],
                "44444444-4444-4444-8444-444444444444",
            )
            self.assertFalse(any(
                call.args[0][:2] == ["vm", "deallocate"]
                for call in run.az.call_args_list
            ))

    def test_observed_vm_anchor_cannot_be_reenrolled_after_disk_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "deployment-succeeded")
            state["host_deployment"].update({
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            })
            original, _ = self.vm_disk(run, state)
            run.az.side_effect = [
                original, original, RuntimeError("disk unavailable"),
            ]
            with self.assertRaisesRegex(RuntimeError, "disk unavailable"):
                run.capture_host_identity()
            replacement = {
                **original,
                "vmId": "66666666-6666-4666-8666-666666666666",
            }
            run.az.reset_mock()
            run.az.side_effect = None
            run.az.return_value = replacement
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                run.reconcile_host_deployment(time.monotonic() + 10)
            self.assertEqual(
                state["host_deployment"]["vm_uuid"],
                "44444444-4444-4444-8444-444444444444",
            )
            self.assertEqual(
                state["host_deployment"]["disk_uuid"],
                "55555555-5555-4555-8555-555555555555",
            )
            self.assertFalse(any(
                call.args[0][:2] == ["vm", "deallocate"]
                for call in run.az.call_args_list
            ))

    def test_success_without_server_identity_outputs_cannot_adopt_live_vm(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "pending")
            deployment = self.deployment(run, state)
            del deployment["properties"]["outputs"]
            run.az.return_value = deployment
            with self.assertRaisesRegex(RuntimeError, "outputs are invalid"):
                run.reconcile_host_deployment(time.monotonic() + 10)
            self.assertIsNone(state["host_deployment"]["vm_uuid"])
            self.assertIsNone(state["host_deployment"]["disk_uuid"])
            self.assertFalse(any(
                call.args[0][:2] == ["vm", "show"]
                for call in run.az.call_args_list
            ))

    def test_deployment_correlation_anchor_is_monotonic(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "deployment-succeeded")
            state["host_deployment"].update({
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            })
            deployment = self.deployment(run, state)
            deployment["properties"]["correlationId"] = (
                "77777777-7777-4777-8777-777777777777"
            )
            with self.assertRaisesRegex(RuntimeError, "correlation changed"):
                run.validate_deployment_result(deployment)
            self.assertEqual(
                state["host_deployment"]["correlation_id"],
                "33333333-3333-4333-8333-333333333333",
            )

    def test_failed_deployment_compute_without_outputs_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "pending")
            deployment = self.deployment(run, state, "Failed")
            vm, _ = self.vm_disk(run, state)
            run.az.side_effect = [deployment, [vm]]
            with self.assertRaisesRegex(RuntimeError, "unanchored compute"):
                run.reconcile_host_deployment(time.monotonic() + 10)
            self.assertEqual(
                state["host_deployment"]["phase"], "deployment-terminal"
            )
            self.assertIsNone(state["host_deployment"]["vm_uuid"])
            self.assertIsNone(state["host_deployment"]["disk_uuid"])
            self.assertFalse(any(
                call.args[0][:2] in (
                    ["vm", "show"], ["vm", "deallocate"],
                )
                for call in run.az.call_args_list
            ))

    def test_cleanup_refuses_matching_name_disk_with_changed_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            group = {"id": state["resource_group_id"], "tags": run.group_tags}
            vm, disk = self.vm_disk(run, state)
            foreign = {**disk, "uniqueId": "6" * 32}
            run.az.side_effect = [True, group, [disk], vm, foreign]
            with self.assertRaises(RuntimeError):
                run.delete_owned_group()
            self.assertFalse(any(
                call.args[0][:2] == ["group", "delete"]
                for call in run.az.call_args_list
            ))

    def test_cleanup_allows_only_structural_children_of_proven_vm(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            group = {
                "id": state["resource_group_id"],
                "tags": {**run.group_tags, "azure-generated": "metadata"},
            }
            vm, disk = self.vm_disk(run, state)
            vm["tags"]["azure-generated"] = "metadata"
            extension = {
                "id": (
                    state["host_deployment"]["vm_id"]
                    + "/extensions/generic-agent"
                ),
                "name": run.host_vm + "/generic-agent",
                "type": "Microsoft.Compute/virtualMachines/extensions",
                "location": preflight.LOCATION,
                "tags": None,
                "publisher": "Generic.Publisher",
            }
            run.az.side_effect = [
                vm, None, vm, {
                    "instanceView": {
                        "statuses": [{"code": "PowerState/deallocated"}]
                    },
                },
                True, group, [vm, disk, extension],
                vm, disk, vm, disk, None, False,
            ]
            state["deadline_monotonic"] = time.monotonic() - 1
            run.cleanup()
            self.assertTrue(state["host_deallocated"])
            self.assertFalse(state["cleanup_required"])

            foreign = {
                **extension,
                "id": (
                    state["resource_group_id"]
                    + "/providers/Microsoft.Compute/virtualMachines/"
                    "unrelated/extensions/generic-agent"
                ),
                "name": "unrelated/generic-agent",
            }
            with self.assertRaisesRegex(RuntimeError, "unproven"):
                run.require_owned_vm_child(foreign)

    def test_group_cleanup_cannot_succeed_when_proven_disk_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            group = {"id": state["resource_group_id"], "tags": run.group_tags}
            vm, _ = self.vm_disk(run, state)
            run.az.side_effect = [
                True, group, [], vm, RuntimeError("disk missing"),
            ]
            with self.assertRaises(RuntimeError):
                run.delete_owned_group()

    def test_group_cleanup_succeeds_only_with_rechecked_vm_disk_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            group = {"id": state["resource_group_id"], "tags": run.group_tags}
            vm, disk = self.vm_disk(run, state)
            run.az.side_effect = [
                True, group, [vm, disk],
                vm, disk,
                vm, disk,
                None, False,
            ]
            run.delete_owned_group()
            self.assertFalse(state["cleanup_required"])
            self.assertTrue(any(
                call.args[0][:2] == ["group", "delete"]
                for call in run.az.call_args_list
            ))

    def test_firewall_intent_precedes_add_and_survives_ambiguous_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            phases = []

            def record(phase, **fields):
                phases.append(phase)
                state.update(phase=phase, **fields)

            run.record.side_effect = record
            run.az.side_effect = RuntimeError("ambiguous add")
            run.clear_firewall_obligation = mock.Mock(
                side_effect=RuntimeError("remove unconfirmed")
            )
            with self.assertRaisesRegex(RuntimeError, "remove unconfirmed"):
                with run.transfer_access("8.8.8.8/32"):
                    self.fail("ambiguous add must not expose a transfer")
            self.assertEqual(phases[0], "blob-firewall-add-pending")
            self.assertEqual(
                state["firewall_obligation"]["phase"], "pending-remove"
            )

    def test_cleanup_attempts_firewall_sas_deallocate_and_group_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            secret_name = ".run-command-0123456789abcdef.json"
            secret_path = Path(temporary) / secret_name
            secret_path.write_text("private")
            secret_path.chmod(0o600)
            state.update({
                "pending_secret_files": [secret_name],
                "firewall_obligation": {
                    "cidr": "8.8.8.8/32", "phase": "active"
                },
                "active_sas": True,
                "active_sas_signing_key_sha256": "a" * 64,
            })
            run.clear_firewall_obligation = mock.Mock(
                side_effect=RuntimeError("firewall")
            )
            run.revoke_sas = mock.Mock(side_effect=RuntimeError("sas"))
            run.deallocate_host = mock.Mock(side_effect=RuntimeError("vm"))
            run.delete_owned_group = mock.Mock(side_effect=RuntimeError("group"))
            with self.assertRaisesRegex(RuntimeError, "did not complete"):
                run.cleanup()
            self.assertFalse(secret_path.exists())
            self.assertEqual(state["pending_secret_files"], [])
            run.clear_firewall_obligation.assert_called_once_with()
            run.revoke_sas.assert_called_once()
            run.deallocate_host.assert_called_once_with()
            run.delete_owned_group.assert_called_once_with()

    def test_unresolved_firewall_blocks_new_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            state["firewall_obligation"] = {
                "cidr": "8.8.8.8/32", "phase": "pending-remove"
            }
            with self.assertRaisesRegex(RuntimeError, "unresolved"):
                with run.transfer_access("8.8.4.4/32"):
                    pass

    def test_storage_firewall_rejects_resource_access_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            subnet = (
                run.expected_host_ids()["vnet_id"] + "/subnets/preflight"
            )
            storage = {
                "tags": run.operation_tags(),
                "networkRuleSet": {
                    "defaultAction": "Deny",
                    "bypass": "None",
                    "ipRules": [],
                    "virtualNetworkRules": [{
                        "virtualNetworkResourceId": subnet,
                        "action": "Allow",
                        "state": "Succeeded",
                    }],
                    "resourceAccessRules": [{"tenantId": "foreign"}],
                },
            }
            run.az.return_value = storage
            with self.assertRaisesRegex(RuntimeError, "firewall"):
                run.verify_storage_rules()

    def test_run_command_uses_protected_parameter_and_bounded_control(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            state["host_vm_id"] = state["host_deployment"]["vm_id"]
            manifest = preflight.host_phase_manifest(state, "capability")
            receipt = "6" * 64
            captured = {}

            def command(arguments, **_kwargs):
                captured["arguments"] = arguments
                request_path = Path(
                    arguments[arguments.index("--body") + 1][1:]
                )
                captured["request"] = json.loads(request_path.read_text())
                return {"value": [{
                    "code": "ComponentStatus/StdOut/succeeded",
                    "message": "HYPERV_PRIVATE_PREFLIGHT " + json.dumps({
                        "schema": 1, "phase": "capability",
                        "result": "PASS", "identity": state["identity"],
                        "receipt_sha256": receipt, "boot_count": 2,
                    }),
                }]}

            run.az.side_effect = command
            run.run_host_phase(
                "capability", manifest, "sv=private-secret"
            )
            self.assertNotIn(
                "private-secret", " ".join(captured["arguments"])
            )
            self.assertNotIn(
                "private-secret", captured["request"]["script"][0]
            )
            self.assertEqual(
                captured["request"]["protectedParameters"],
                [{"name": "sas", "value": "sv=private-secret"}],
            )
            self.assertGreater(state["control_payload_bytes"], 0)
            self.assertEqual(state["pending_secret_files"], [])
            self.assertFalse(any(
                path.name.startswith(".run-command-")
                for path in Path(temporary).iterdir()
            ))

    def test_deployed_envelope_rejects_any_data_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            vm, disk = self.vm_disk(run, state)
            vm["storageProfile"]["dataDisks"] = [{"lun": 0}]
            run.verify_host_identity = mock.Mock(return_value=(vm, disk))
            with self.assertRaisesRegex(RuntimeError, "envelope"):
                run.verify_deployed_envelope()
            run.az.assert_not_called()

    def test_deployed_envelope_rejects_nat_on_private_subnet(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            vm, disk = self.vm_disk(run, state)
            ids = run.expected_host_ids()
            run.verify_host_identity = mock.Mock(return_value=(vm, disk))
            nic = {
                "id": ids["nic_id"], "tags": run.operation_tags(),
                "location": preflight.LOCATION,
                "enableAcceleratedNetworking": False,
                "enableIPForwarding": False,
                "networkSecurityGroup": None,
                "ipConfigurations": [{
                    "name": "private",
                    "primary": True,
                    "privateIPAddressVersion": "IPv4",
                    "publicIPAddress": None,
                    "privateIPAllocationMethod": "Static",
                    "privateIPAddress": "10.88.0.4",
                    "subnet": {"id": ids["vnet_id"] + "/subnets/preflight"},
                }],
            }
            nsg = {
                "id": ids["nsg_id"], "tags": run.operation_tags(),
                "location": preflight.LOCATION,
                "securityRules": [],
            }
            expected = {
                "AllowAzurePlatformDns": (
                    100, "Allow", "Outbound", "Udp", "53",
                    "VirtualNetwork", "AzurePlatformDNS",
                ),
                "AllowAzurePlatformImds": (
                    110, "Allow", "Outbound", "Tcp", "80",
                    "VirtualNetwork", "AzurePlatformIMDS",
                ),
                "AllowAzurePlatformAgent": (
                    120, "Allow", "Outbound", "Tcp", ["80", "32526"],
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
            for name, values in expected.items():
                rule = {
                    "name": name, "priority": values[0],
                    "access": values[1], "direction": values[2],
                    "protocol": values[3], "sourcePortRange": "*",
                    "sourceAddressPrefix": values[5],
                    "destinationAddressPrefix": values[6],
                }
                if isinstance(values[4], list):
                    rule["destinationPortRanges"] = values[4]
                else:
                    rule["destinationPortRange"] = values[4]
                nsg["securityRules"].append(rule)
            vnet = {
                "id": ids["vnet_id"], "tags": run.operation_tags(),
                "location": preflight.LOCATION,
                "addressSpace": {"addressPrefixes": ["10.88.0.0/29"]},
                "subnets": [{"name": "preflight"}],
            }
            subnet = {
                "id": ids["vnet_id"] + "/subnets/preflight",
                "addressPrefix": "10.88.0.0/29",
                "defaultOutboundAccess": False,
                "natGateway": {"id": "/foreign/nat"},
                "networkSecurityGroup": {"id": ids["nsg_id"]},
                "serviceEndpoints": [{
                    "service": "Microsoft.Storage",
                    "locations": ["northeurope"],
                }],
            }
            run.az.side_effect = [nic, nsg, vnet, subnet]
            with self.assertRaisesRegex(RuntimeError, "subnet"):
                run.verify_deployed_envelope()
            subnet["natGateway"] = None
            storage = {
                "id": ids["storage_id"], "tags": run.operation_tags(),
                "location": preflight.LOCATION,
                "kind": "StorageV2",
                "sku": {"name": "Standard_LRS"},
                "allowBlobPublicAccess": False,
                "allowSharedKeyAccess": True,
                "defaultToOAuthAuthentication": False,
                "minimumTlsVersion": "TLS1_2",
                "publicNetworkAccess": "Enabled",
                "supportsHttpsTrafficOnly": True,
                "privateEndpointConnections": [],
                "networkRuleSet": {"resourceAccessRules": []},
            }
            schedule = {
                "id": ids["schedule_id"], "tags": run.operation_tags(),
                "location": preflight.LOCATION,
                "properties": {
                    "status": "Enabled",
                    "taskType": "ComputeVmShutdownTask",
                    "targetResourceId": state["host_deployment"]["vm_id"],
                    "dailyRecurrence": {"time": "0526"},
                    "timeZoneId": "UTC",
                },
            }
            run.az.reset_mock()
            run.az.side_effect = [
                nic, nsg, vnet, subnet, storage, schedule,
            ]
            run.verify_storage_rules = mock.Mock()
            run.verify_resource_inventory = mock.Mock()
            run.verify_deployed_envelope()
            run.verify_storage_rules.assert_called_once_with()
            run.verify_resource_inventory.assert_called_once_with()

    def test_resource_inventory_rejects_extra_public_ip(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            run.az.return_value = [{
                "type": "Microsoft.Network/publicIPAddresses",
                "name": "forbidden",
                "id": "/foreign/public-ip",
                "tags": run.operation_tags(),
            }]
            with self.assertRaisesRegex(RuntimeError, "inventory"):
                run.verify_resource_inventory()

    @mock.patch.object(preflight.azure, "azure_cli")
    def test_all_lifecycle_cli_failures_are_private(self, command):
        state = self.cloud_state()
        with tempfile.TemporaryDirectory() as temporary:
            run = preflight.PrivatePreflightRun(
                state, Path(temporary) / "state.json"
            )
            command.side_effect = preflight.azure.AzureCliError(
                ["vm", "show"],
                mock.Mock(
                    returncode=1,
                    stderr=(
                        "failed /subscriptions/private/resourceGroups/private "
                        "?sig=private-secret"
                    ),
                ),
                True,
            )
            with self.assertRaises(preflight.azure.AzureCliError) as error:
                run.az(["vm", "show", "--ids", "/private/id"])
            self.assertNotIn("private-secret", str(error.exception))
            self.assertNotIn("/subscriptions/", str(error.exception))
            self.assertTrue(command.call_args.kwargs["private"])

    def test_private_run_failure_values_redact_state_and_resource_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state)
            state["firewall_obligation"] = {
                "cidr": "8.8.8.8/32", "phase": "active",
            }
            state["pending_secret_files"] = [
                ".run-command-0123456789abcdef.json"
            ]
            message = preflight.azure.safe_failure_message(
                RuntimeError(
                    f"{run.storage} {run.state_path} "
                    f"{state['subscription']} "
                    f"{state['host_deployment']['vm_uuid']} 8.8.8.8/32"
                ),
                run.private_failure_values(),
            )
            for private in (
                run.storage, str(run.state_path), state["subscription"],
                state["host_deployment"]["vm_uuid"], "8.8.8.8/32",
            ):
                self.assertNotIn(private, message)


class PrivatePreflightOrderingTest(PrivatePreflightFixture):
    def execute(
        self, capability_error=None, cleanup_error=None,
        recording_error=None,
    ):
        state = self.state()
        events = []
        raised_error = None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "state.json"
            fake = mock.Mock()
            fake.storage = "ukhvp1234567890abcd"
            fake.container = preflight.CONTAINER
            fake.state = state
            fake.state_path = state_path
            fake.deadline = time.monotonic() + 3600

            def record(phase, **fields):
                if (
                    phase in ("cleanup-failed", "failed")
                    and recording_error is not None
                ):
                    raise recording_error
                state.update(phase=phase, **fields)

            def account(category, amount):
                field = {
                    "input": "staged_input_bytes",
                    "control": "control_payload_bytes",
                    "evidence": "evidence_bytes",
                }[category]
                state[field] += amount

            fake.record.side_effect = record
            fake.account_bytes.side_effect = account
            fake.create_group.side_effect = lambda: events.append("group")
            fake.deploy_host.side_effect = lambda _: (
                events.append("host"),
                state.update(
                    host_vm_id="/private/vm",
                    host_deployment={
                        "operation_id": (
                            "22222222-2222-4222-8222-222222222222"
                        ),
                        "correlation_id": (
                            "33333333-3333-4333-8333-333333333333"
                        ),
                        "vm_uuid": "44444444-4444-4444-8444-444444444444",
                        "disk_uuid": "55555555-5555-4555-8555-555555555555",
                    },
                ),
            )
            fake.verify_storage_rules.side_effect = lambda: events.append(
                "firewall-closed"
            )
            fake.generate_sas.side_effect = [
                {"value": "public-sas", "signing_key_sha256": "a" * 64},
                {"value": "private-sas", "signing_key_sha256": "b" * 64},
            ]
            fake.revoke_sas.side_effect = lambda token: events.append(
                "revoke-" + token["value"]
            )

            @contextmanager
            def access(_cidr):
                events.append("firewall-open")
                try:
                    yield
                finally:
                    events.append("firewall-remove")

            fake.transfer_access.side_effect = access

            def host_phase(phase, _manifest, _sas):
                events.append("run-" + phase)
                if phase == "capability" and capability_error is not None:
                    raise capability_error
                state[phase + "_receipt_sha256"] = (
                    "c" * 64 if phase == "capability" else "d" * 64
                )

            fake.run_host_phase.side_effect = host_phase
            fake.deallocate_host.side_effect = lambda: events.append(
                "deallocate"
            )

            def cleanup():
                events.append("cleanup")
                if cleanup_error is not None:
                    raise cleanup_error
                state["cleanup_required"] = False

            fake.cleanup.side_effect = cleanup
            fake.private_failure_values.return_value = (
                fake.storage, str(root),
                "/owner/private/state",
                "11111111-2222-3333-4444-555555555555",
            )

            def upload(_run, _url, sas, _container, files, **_kwargs):
                events.append(
                    "upload-public" if sas == "public-sas"
                    else "upload-private"
                )
                return sum(record[2] for record in files)

            def retrieve(_run, _cidr, _sas, phase, _manifest):
                events.append("retrieve-" + phase)
                state[phase + "_receipt_sha256"] = (
                    "c" * 64 if phase == "capability" else "d" * 64
                )
                return {
                    "host_boot_id": (
                        "66666666-6666-4666-8666-666666666666"
                    ),
                    "storage_result": "NOT_EVALUATED",
                    "boots": {
                        "capability" if phase == "capability" else "raw": {},
                    },
                }

            cloud = {
                "subscription": "11111111-2222-3333-4444-555555555555",
                "sku": {},
                "image": {
                    "publisher": "Canonical",
                    "offer": "ubuntu-24_04-lts",
                    "sku": "server", "version": "24.04.202609010",
                    "hyperv_generation": "V2",
                },
            }
            with mock.patch.object(
                preflight, "load_state", return_value=(state, state_path)
            ), mock.patch.object(
                preflight, "verify_immutable_inputs"
            ), mock.patch.object(
                preflight, "check_blob_dependency"
            ), mock.patch.object(
                preflight, "transfer_source", return_value="8.8.8.8/32"
            ), mock.patch.object(
                preflight, "check_subscription", return_value=cloud
            ), mock.patch.object(
                preflight, "PrivatePreflightRun", return_value=fake
            ), mock.patch.object(
                preflight, "upload_blob_set", side_effect=upload
            ), mock.patch.object(
                preflight, "retrieve_phase_evidence", side_effect=retrieve
            ), mock.patch.object(
                preflight.azure, "save_durable_json"
            ), mock.patch.object(
                preflight.azure, "image_sha256", return_value="e" * 64
            ):
                if capability_error is not None:
                    expected = (
                        preflight.azure.RunCleanupError
                        if cleanup_error is not None
                        else type(capability_error)
                    )
                    with self.assertRaises(expected) as raised:
                        preflight.run_preflight(
                            root, cloud["subscription"], "8.8.8.8", True
                        )
                    raised_error = raised.exception
                else:
                    preflight.run_preflight(
                        root, cloud["subscription"], "8.8.8.8", True
                    )
        return events, state, raised_error

    def test_capability_pass_precedes_any_private_upload(self):
        events, state, _ = self.execute()
        self.assertLess(
            events.index("retrieve-capability"),
            events.index("upload-private"),
        )
        self.assertIn("deallocate", events)
        self.assertEqual(events[-1], "cleanup")
        self.assertIs(state["cleanup_required"], False)

    def test_capability_failure_and_cancellation_cleanup_without_private_upload(self):
        for error in (
            RuntimeError("capability failed"),
            InterruptedError("cancelled"),
        ):
            with self.subTest(error=type(error).__name__):
                events, _, raised = self.execute(error)
                self.assertNotIn("upload-private", events)
                self.assertEqual(events[-1], "cleanup")
                self.assertIs(raised, error)

    def test_primary_and_cleanup_failures_are_both_sanitized_and_durable(self):
        private = "11111111-2222-3333-4444-555555555555"
        primary = RuntimeError(
            "deployment failed at "
            "https://ukhvp1234567890abcd.blob.core.windows.net/private "
            f"/subscriptions/{private}/resourceGroups/private"
        )
        cleanup = RuntimeError(
            "cleanup failed for ukhvp1234567890abcd in /owner/private/state"
        )
        events, state, raised = self.execute(primary, cleanup)
        self.assertEqual(events[-1], "cleanup")
        self.assertIsInstance(raised, preflight.azure.RunCleanupError)
        self.assertIn("Primary run failure", str(raised))
        self.assertIn("cleanup also failed", str(raised))
        self.assertNotIn("ukhvp1234567890abcd", str(raised))
        self.assertNotIn("/subscriptions/", str(raised))
        self.assertNotIn("/owner/private/state", str(raised))
        self.assertEqual(state["phase"], "cleanup-failed")
        self.assertIn("primary_failure", state)
        self.assertIn("cleanup_failure", state)
        self.assertNotIn(
            "ukhvp1234567890abcd", state["cleanup_failure"]
        )

    def test_cleanup_recording_failure_reports_all_three_failures(self):
        primary = RuntimeError("deployment failed /owner/private/state")
        cleanup = RuntimeError("cleanup failed ukhvp1234567890abcd")
        recording = RuntimeError(
            "record failed /owner/private/state ukhvp1234567890abcd"
        )
        events, _, raised = self.execute(
            primary, cleanup, recording
        )
        self.assertEqual(events[-1], "cleanup")
        self.assertIsInstance(raised, preflight.azure.RunCleanupError)
        message = str(raised)
        self.assertIn("Primary run failure", message)
        self.assertIn("cleanup also failed", message)
        self.assertIn(
            "durable cleanup-failure recording also failed", message
        )
        self.assertNotIn("ukhvp1234567890abcd", message)
        self.assertNotIn("/owner/private/state", message)

    def test_primary_recording_failure_survives_successful_cleanup(self):
        primary = RuntimeError("deployment failed /owner/private/state")
        recording = RuntimeError(
            "record failed /owner/private/state ukhvp1234567890abcd"
        )
        events, _, raised = self.execute(
            primary, recording_error=recording
        )
        self.assertEqual(events[-1], "cleanup")
        message = str(raised)
        self.assertIn("Primary run failure", message)
        self.assertIn("durable failure recording also failed", message)
        self.assertNotIn("ukhvp1234567890abcd", message)
        self.assertNotIn("/owner/private/state", message)

    def test_cli_error_redacts_ids_secrets_and_paths(self):
        secret = (
            "/subscriptions/private/resourceGroups/private "
            "?sig=private-secret /owner/private/state"
        )
        output = io.StringIO()
        with mock.patch.object(
            preflight.sys, "argv",
            [
                "hyperv_private_preflight.py", "cleanup",
                "--state-dir", "/owner/private/state",
                "--subscription", "11111111-2222-3333-4444-555555555555",
            ],
        ), mock.patch.object(
            preflight, "cleanup", side_effect=RuntimeError(secret)
        ), mock.patch.object(preflight.sys, "stderr", output):
            with self.assertRaises(SystemExit) as stopped:
                preflight.main()
            print(stopped.exception, file=preflight.sys.stderr)
        message = output.getvalue()
        self.assertNotIn("private-secret", message)
        self.assertNotIn("/subscriptions/", message)
        self.assertNotIn("/owner/private", message)
        self.assertNotIn("Traceback", message)


if __name__ == "__main__":
    unittest.main()
