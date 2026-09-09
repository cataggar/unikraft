# SPDX-License-Identifier: BSD-3-Clause

from contextlib import contextmanager
import hashlib
import importlib
import io
import json
from pathlib import Path
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


class PrivatePreflightFixture(unittest.TestCase):
    def implementation(self):
        return {
            "sdk": {
                "name": "azure-storage-blob",
                "version": preflight.SDK_VERSION,
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
        raw_size = preflight.azure.VIRTUAL_SIZE
        sizes = {
            "qemu": 26_911_032,
            "ovmf_code": 4 * 1024 * 1024,
            "ovmf_vars": 4 * 1024 * 1024,
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
        qemu_support = [{
            "path": "qemu/share/qemu/firmware.json",
            "sha256": "9" * 64,
            "size": 1024 * 1024,
        }]
        value = {
            "schema": preflight.INPUT_SCHEMA,
            "schema_version": preflight.INPUT_SCHEMA_VERSION,
            "workload": preflight.WORKLOAD,
            "boot_policy": "platform-unavailable-v1",
            "raw_size": raw_size,
            "provenance": {
                "scheme": "unikraft.git-ls-tree-v1",
                "head_commit": "a" * 40,
                "tree_sha256": "b" * 64,
                "tracked_entries": 200,
                "config": {
                    "name": preflight.SOLVED_CONFIG,
                    "sha256": "c" * 64,
                    "size": 4096,
                },
            },
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
            "implementation": self.implementation(),
            "budget": preflight.expected_budget(files, qemu_support),
        }
        value.update(changes)
        return value

    def state(self):
        manifest = preflight.validate_input_manifest(self.manifest())
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
            "tags": None,
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
                "parameters": {
                    name: {"value": value}
                    for name, value in parameters.items()
                },
            },
        }


class PrivatePreflightManifestTest(PrivatePreflightFixture):
    def test_manifest_binds_real_budget_and_keeps_efi_local(self):
        manifest = preflight.validate_input_manifest(self.manifest())
        budget = manifest["budget"]
        measured_without_support = (
            207_618_560 + 26_911_032 + 8_388_608
            + 8_388_608
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
        self.assertEqual(capability["schema_version"], 2)
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

    def test_provenance_generator_hashes_clean_git_tree_and_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "support").mkdir()
            config = repository / "solved.config"
            config.write_text("CONFIG_HYPERV=y\n")
            subprocess.run(
                ["git", "init", "-q"], cwd=repository, check=True
            )
            (repository / "tracked").write_text("source\n")
            subprocess.run(
                ["git", "add", "tracked"], cwd=repository, check=True
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                cwd=repository, check=True,
            )
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ):
                first = preflight.build_provenance(repository, config)
                second = preflight.build_provenance(repository, config)
            self.assertEqual(first, second)
            self.assertEqual(first["scheme"], "unikraft.git-ls-tree-v1")
            self.assertEqual(first["tracked_entries"], 1)
            config.write_text("CONFIG_HYPERV=n\n")
            with mock.patch.object(
                preflight, "SUPPORT", repository / "support"
            ):
                changed = preflight.build_provenance(repository, config)
            self.assertNotEqual(
                first["config"]["sha256"], changed["config"]["sha256"]
            )

    def test_generate_input_creates_complete_canonical_operator_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "support").mkdir(parents=True)
            config = repository / "solved.config"
            config.write_text("CONFIG_HYPERV=y\n")
            (repository / "tracked").write_text("source\n")
            subprocess.run(
                ["git", "init", "-q"], cwd=repository, check=True
            )
            subprocess.run(
                ["git", "add", "tracked"], cwd=repository, check=True
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Fixture",
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
            }
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
            ):
                digest = preflight.generate_input(
                    output, repository, config, qemu,
                    assets["code"], assets["vars"], assets["capability"],
                    assets["efi"], assets["raw"], assets["vhd"],
                    assets["miz"], "platform-unavailable-v1",
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
                    "qemu/bin/qemu-system-x86_64",
                    "qemu/share/firmware.json",
                    "OVMF_CODE.fd", "OVMF_VARS.fd", "capability.raw",
                    "private.efi", "private.raw", "private.vhd",
                },
            )


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
                qemu, code, variables, image, record, image.stat().st_size,
                "platform-unavailable-v1", "raw-x2apic", False, root,
            )

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

    def test_actual_qemu_process_uses_readonly_footer_mask_and_passes(self):
        result, _ = self.run_fake_boot("pass")
        self.assertEqual(result["result"], "PASS")

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
                    qemu, root / "code", root / "vars", image, record,
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


class PrivatePreflightBlobTest(PrivatePreflightFixture):
    def test_declared_blob_sdk_is_exact_when_available(self):
        try:
            from importlib.metadata import PackageNotFoundError, version
            installed = version("azure-storage-blob")
        except PackageNotFoundError:
            self.skipTest("azure-storage-blob is not installed in this runner")
        self.assertEqual(installed, preflight.SDK_VERSION)
        self.assertIsNotNone(preflight.check_blob_dependency())

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
            run.capture_host_identity.assert_called_once_with()
            command = run.az.call_args.args[0]
            self.assertEqual(command[:3], ["deployment", "group", "show"])
            self.assertEqual(
                state["host_deployment"]["correlation_id"],
                "33333333-3333-4333-8333-333333333333",
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
            vm, disk = self.vm_disk(run, state)
            run.az.side_effect = [vm, vm, disk, vm, disk]
            run.capture_host_identity()
            commands = [" ".join(call.args[0]) for call in run.az.call_args_list]
            self.assertFalse(any("disk update" in command for command in commands))
            self.assertEqual(
                state["host_deployment"]["disk_uuid"], disk["uniqueId"]
            )

    def test_partial_deployment_persists_vm_proof_for_deallocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            self.begin_operation(run, state, "deployment-terminal")
            vm, _ = self.vm_disk(run, state)
            run.az.side_effect = [
                vm, vm, RuntimeError("disk unavailable"),
            ]
            with self.assertRaisesRegex(RuntimeError, "disk unavailable"):
                run.capture_host_identity()
            self.assertEqual(state["host_deployment"]["phase"], "vm-verified")
            view = {
                "instanceView": {
                    "statuses": [{"code": "PowerState/deallocated"}]
                },
            }
            run.az.reset_mock()
            run.az.side_effect = [vm, None, view]
            run.deallocate_host()
            self.assertTrue(state["host_deallocated"])

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


class PrivatePreflightOrderingTest(PrivatePreflightFixture):
    def execute(self, capability_error=None):
        state = self.state()
        events = []
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
            fake.cleanup.side_effect = lambda: events.append("cleanup")

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
                    with self.assertRaises(type(capability_error)):
                        preflight.run_preflight(
                            root, cloud["subscription"], "8.8.8.8", True
                        )
                else:
                    preflight.run_preflight(
                        root, cloud["subscription"], "8.8.8.8", True
                    )
        return events, state

    def test_capability_pass_precedes_any_private_upload(self):
        events, state = self.execute()
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
                events, _ = self.execute(error)
                self.assertNotIn("upload-private", events)
                self.assertEqual(events[-1], "cleanup")

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
