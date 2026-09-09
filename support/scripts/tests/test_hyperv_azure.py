# SPDX-License-Identifier: BSD-3-Clause

import copy
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
import zlib
from unittest import mock

SUPPORT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SUPPORT / "scripts"))
azure = importlib.import_module("hyperv-azure")
uploader = importlib.import_module("hyperv-azure-upload")
persistence = importlib.import_module("hyperv_persistence_controller")


def modeled_implicit_disk_output_order(
    template, vm_variable, identity_variable, output_name, inner_output_name,
):
    output = template["outputs"][output_name]["value"]
    if "reference(resourceId('Microsoft.Compute/disks'" in output:
        raise RuntimeError(
            "ResourceNotFound: implicit disk read can precede VM creation"
        )
    identity = next(
        resource for resource in template["resources"]
        if resource["type"] == "Microsoft.Resources/deployments"
        and resource["name"] == f"[variables('{identity_variable}')]"
    )
    vm_dependency = (
        "[resourceId('Microsoft.Compute/virtualMachines', "
        f"variables('{vm_variable}'))]"
    )
    if identity.get("dependsOn") != [vm_dependency]:
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
        "peerDiskId": {
            "value": (
                f"[reference(variables('{vm_variable}'), '2025-11-01')"
                ".storageProfile.osDisk.managedDisk.id]"
            )
        }
    }:
        raise RuntimeError(
            "Identity deployment does not use the VM's returned disk ID"
        )
    expected_output = (
        f"[reference(variables('{identity_variable}'), '2022-09-01')"
        f".outputs.{inner_output_name}.value]"
    )
    if output != expected_output:
        raise RuntimeError("Outer output does not await identity deployment")
    inner = properties["template"]["outputs"][
        inner_output_name
    ]["value"]
    if "reference(parameters(" not in inner or ".uniqueId]" not in inner:
        raise RuntimeError("Identity deployment does not read the disk UUID")
    return ("vm-created", "implicit-disk-read", "outer-output")


class UploadFailure(Exception):
    error_code = "UploadFailed"


class HypervAzurePageUploadTest(unittest.TestCase):
    def test_precreated_disk_uses_page_updates_and_exact_footer_readback(self):
        footer = b"conectix" + b"\0" * 504
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.vhd"
            image.write_bytes(b"\0" * uploader.PAGE_CHUNK + footer)
            factory = mock.Mock()
            client = mock.MagicMock()
            factory.from_blob_url.return_value = client
            client.__enter__.return_value = client
            client.download_blob.return_value.readall.return_value = footer
            with mock.patch.object(uploader, "storage_sdk", return_value=(factory, UploadFailure)):
                report = uploader.upload_pages(
                    image, "https://md.blob.storage.azure.net:8443/disk/image", "sig=secret"
                )
            self.assertEqual(report["uploaded_bytes"], uploader.PAGE_CHUNK + 512)
            self.assertEqual(
                report["image_sha256"], hashlib.sha256(
                    b"\0" * uploader.PAGE_CHUNK + footer
                ).hexdigest(),
            )
            self.assertTrue(report["footer_matches"])
            self.assertEqual(client.upload_page.call_count, 2)
            self.assertEqual(client.upload_page.call_args_list[0].args[1:], (0, uploader.PAGE_CHUNK))
            self.assertEqual(client.upload_page.call_args_list[1].args[1:], (uploader.PAGE_CHUNK, 512))
            for call in client.upload_page.call_args_list:
                self.assertTrue(call.kwargs["validate_content"])
            client.create_page_blob.assert_not_called()
            client.upload_blob.assert_not_called()
            client.download_blob.assert_called_once_with(
                offset=uploader.PAGE_CHUNK, length=512,
                validate_content=True, max_concurrency=1,
            )

    def test_readback_mismatch_and_sdk_error_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.vhd"
            image.write_bytes(b"conectix" + b"\0" * 504)
            factory = mock.Mock()
            client = mock.MagicMock()
            factory.from_blob_url.return_value = client
            client.__enter__.return_value = client
            client.download_blob.return_value.readall.return_value = b"\0" * 512
            with mock.patch.object(uploader, "storage_sdk", return_value=(factory, UploadFailure)):
                with self.assertRaisesRegex(ValueError, "footer does not match"):
                    uploader.upload_pages(
                        image, "https://md.blob.storage.azure.net/disk/image", "sig=secret"
                    )
                client.upload_page.side_effect = UploadFailure("failed at ?sig=secret")
                with self.assertRaises(RuntimeError) as error:
                    uploader.upload_pages(
                        image, "https://md.blob.storage.azure.net/disk/image", "sig=secret"
                    )
                self.assertIn("UploadFailed", str(error.exception))
                self.assertNotIn("secret", str(error.exception))

    @mock.patch.object(azure, "upload_helper")
    def test_expected_image_digest_is_enforced(self, helper):
        image = mock.Mock()
        image.stat.return_value.st_size = 1024
        helper.return_value = {
            "uploaded_bytes": 1024,
            "image_sha256": "b" * 64,
            "footer_matches": True,
        }
        with self.assertRaisesRegex(RuntimeError, "expected image"):
            azure.upload_managed_vhd(
                image, "https://example.invalid/disk", "secret",
                expected_sha256="a" * 64,
            )


class HypervAzurePackagingTest(unittest.TestCase):
    def report(self):
        return {
            "schema-version": 1, "contract": "miz.efi-application-image",
            "valid": True, "format": "vhd", "subformat": "fixed",
            "generation": 2, "virtual-size": azure.VIRTUAL_SIZE,
            "file-size": azure.VIRTUAL_SIZE + 512, "architecture": "x86_64",
            "boot-path": "EFI/BOOT/BOOTX64.EFI", "boot-file-sha256": "a" * 64,
            "esp-offset": azure.MIB, "esp-length": azure.ESP_SIZE,
        }

    def test_expected_miz_contract_is_accepted(self):
        azure.check_packaging_report(
            self.report(), "a" * 64, azure.VIRTUAL_SIZE + 512
        )

    def test_invalid_or_mismatched_packaging_is_rejected(self):
        for field, value in (
            ("valid", False), ("subformat", "dynamic"), ("generation", 1),
            ("architecture", "aarch64"), ("virtual-size", azure.VIRTUAL_SIZE + 1),
            ("boot-path", "EFI/BOOT/BOOTAA64.EFI"),
            ("boot-file-sha256", "b" * 64), ("schema-version", True),
        ):
            with self.subTest(field=field):
                report = self.report()
                report[field] = value
                with self.assertRaises(ValueError):
                    azure.check_packaging_report(
                        report, "a" * 64, azure.VIRTUAL_SIZE + 512
                    )

    def test_missing_field_or_incorrect_file_length_is_rejected(self):
        report = self.report()
        del report["esp-length"]
        with self.assertRaises(ValueError):
            azure.check_packaging_report(report, "a" * 64, azure.VIRTUAL_SIZE + 512)
        with self.assertRaises(ValueError):
            azure.check_packaging_report(self.report(), "a" * 64, azure.VIRTUAL_SIZE)


class HypervAzureLocalBootTest(unittest.TestCase):
    def test_raw_and_vhd_boot_in_normal_and_masked_x2apic_modes(self):
        milestones = "\n".join((
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:",
            "Powered by",
            "Calling main(",
            azure.PLATFORM_READY,
            "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network",
            "main returned 2",
        ))
        booted_inodes = []

        def execute(command, **kwargs):
            booted_inodes.append((Path(kwargs["cwd"]) / "disk.img").stat().st_ino)
            text = milestones
            cpu = command[command.index("-cpu") + 1]
            if "x2apic=off" in cpu:
                text += f"\n{azure.LEGACY_APIC_MARKER}"
            kwargs["stdout"].write(text.encode())
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ovmf_code = directory / "code.fd"
            ovmf_vars = directory / "vars.fd"
            raw = directory / "unikraft.raw"
            vhd = directory / "unikraft.vhd"
            for path in (raw, vhd, ovmf_code, ovmf_vars):
                path.write_bytes(b"fixture")
            with mock.patch.object(azure.subprocess, "run", side_effect=execute) as run:
                evidence = {
                    image_format: azure.local_disk_boot_modes(
                        image, image_format, directory, ovmf_code, ovmf_vars,
                        Path("/qemu-system-x86_64"), azure.PLATFORM_READY, 30,
                    )
                    for image_format, image in (("raw", raw), ("vpc", vhd))
                }

            for image_evidence in evidence.values():
                self.assertEqual(set(image_evidence), {"x2apic", "legacy-apic"})
                self.assertTrue(
                    all(item["platform_ready"] for item in image_evidence.values())
                )
                self.assertTrue(
                    all(not item["io_ready"] for item in image_evidence.values())
                )
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(
                booted_inodes,
                [raw.stat().st_ino] * 2 + [vhd.stat().st_ino] * 2,
            )
            cpus = [command[command.index("-cpu") + 1] for command in commands]
            self.assertNotIn("x2apic=off", cpus[0])
            self.assertIn("x2apic=off", cpus[1])
            self.assertNotIn("x2apic=off", cpus[2])
            self.assertIn("x2apic=off", cpus[3])
            for command in commands:
                self.assertIn("vmbus-bridge,irq=15", command)
                self.assertNotIn("hv-balloon", command)
                disk = json.loads(command[command.index("-blockdev") + 1])
                self.assertEqual(disk, {
                    "driver": "raw", "node-name": "hyperv-disk",
                    "offset": 0, "size": azure.VIRTUAL_SIZE, "read-only": True,
                    "file": {
                        "driver": "file", "filename": "disk.img",
                        "read-only": True,
                    },
                })
                self.assertIn("virtio-blk-pci,drive=hyperv-disk", command)
            for image_format in ("raw", "vpc"):
                for mode in ("x2apic", "legacy-apic"):
                    self.assertTrue(
                        (directory / f"local-{image_format}-{mode}-serial.log").is_file()
                    )

    def test_other_disk_formats_are_rejected_before_boot(self):
        with mock.patch.object(azure.subprocess, "run") as execute:
            with self.assertRaisesRegex(ValueError, "raw GPT and fixed VHD"):
                azure.local_disk_boot(
                    Path("/image"), "qcow2", Path("/state"),
                    Path("/code"), Path("/vars"), Path("/qemu"),
                    azure.PLATFORM_READY, 30, "x2apic", False,
                )
            execute.assert_not_called()

    @mock.patch.object(azure.subprocess, "run")
    def test_masked_x2apic_boot_must_reach_legacy_apic_fallback(self, execute):
        def complete_without_legacy_marker(command, **kwargs):
            del command
            kwargs["stdout"].write("\n".join((
                "Hyper-V Hv#1 hypercall page enabled",
                "Hyper-V SynIC:",
                "Powered by",
                "Calling main(",
                azure.PLATFORM_READY,
            )).encode())
            return mock.Mock(returncode=0)

        execute.side_effect = complete_without_legacy_marker
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            image = directory / "unikraft.vhd"
            ovmf_code = directory / "code.fd"
            ovmf_vars = directory / "vars.fd"
            for path in (image, ovmf_code, ovmf_vars):
                path.write_bytes(b"fixture")
            with self.assertRaisesRegex(RuntimeError, "did not use the xAPIC fallback"):
                azure.local_disk_boot(
                    image, "vpc", directory, ovmf_code, ovmf_vars,
                    Path("/qemu-system-x86_64"), azure.PLATFORM_READY, 30,
                    "legacy-apic", True,
                )


class HypervAzureFileHandlingTest(unittest.TestCase):
    def test_fifo_inputs_are_opened_nonblocking_before_type_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "input"
            os.mkfifo(fifo)
            real_open = os.open

            def guarded_open(path, flags, *args):
                self.assertTrue(
                    flags & os.O_NONBLOCK,
                    "FIFO-safe input opens must use O_NONBLOCK",
                )
                return real_open(path, flags, *args)

            operations = (
                lambda: azure.read_regular_file(fifo, 64, "Manifest"),
                lambda: azure.copy_regular_file(
                    fifo, root / "copy", 0, azure.sha256_bytes(b"")
                ),
            )
            for operation in operations:
                with self.subTest(operation=operation):
                    with mock.patch.object(azure.os, "open", side_effect=guarded_open):
                        with self.assertRaisesRegex(
                            ValueError, "invalid type|non-symlink|unexpected type"
                        ):
                            operation()

    def test_copy_detects_growth_without_unbounded_reads_or_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.write_bytes(b"1234")
            reads = []

            def growing_read(descriptor, size):
                del descriptor
                reads.append(size)
                if len(reads) > 2:
                    raise AssertionError("copy read past its bounded detection byte")
                return b"x" * min(size, 4)

            with mock.patch.object(azure.os, "read", side_effect=growing_read):
                with self.assertRaisesRegex(ValueError, "grew|expected size"):
                    azure.copy_regular_file(
                        source, destination, 4,
                        azure.sha256_bytes(b"x" * 4),
                    )
            self.assertEqual(reads, [4, 1])
            self.assertFalse(destination.exists())

    def test_exact_copy_fsyncs_and_rejects_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.write_bytes(b"exact-content")
            with mock.patch.object(
                azure.os, "fsync", wraps=os.fsync
            ) as fsync:
                azure.copy_regular_file(
                    source, destination, source.stat().st_size,
                    azure.sha256_bytes(b"exact-content"),
                )
            self.assertEqual(destination.read_bytes(), b"exact-content")
            fsync.assert_called_once()

            mismatch = root / "mismatch"
            with self.assertRaisesRegex(ValueError, "does not match"):
                azure.copy_regular_file(
                    source, mismatch, source.stat().st_size, "f" * 64
                )
            self.assertFalse(mismatch.exists())

    def test_failed_exclusive_create_preserves_existing_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"new")
            digest = azure.sha256_bytes(b"new")

            existing = root / "existing"
            existing.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                azure.copy_regular_file(source, existing, 3, digest)
            self.assertEqual(existing.read_bytes(), b"keep")

            target = root / "target"
            target.write_bytes(b"target")
            linked = root / "linked"
            linked.symlink_to(target)
            with self.assertRaises(FileExistsError):
                azure.copy_regular_file(source, linked, 3, digest)
            self.assertTrue(linked.is_symlink())
            self.assertEqual(linked.readlink(), target)
            self.assertEqual(target.read_bytes(), b"target")


class HypervAzurePreparedImageTransferTest(unittest.TestCase):
    def setUp(self):
        self.constants = (
            mock.patch.object(azure, "MIB", 512),
            mock.patch.object(azure, "ESP_SIZE", 2048),
            mock.patch.object(azure, "VIRTUAL_SIZE", 4096),
        )
        for patcher in self.constants:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.constants):
            patcher.stop()

    @staticmethod
    def source(**changes):
        value = {
            "provider": "github-actions",
            "repository": "unikraft/unikraft",
            "repository_id": 12345,
            "workflow_ref": (
                "unikraft/unikraft/.github/workflows/integration.yaml@"
                "refs/heads/zig16"
            ),
            "job": "zig-hyperv",
            "run_id": 67890,
            "run_attempt": 1,
            "head_sha": "a" * 40,
        }
        value.update(changes)
        return value

    @staticmethod
    def boot_text(legacy=False):
        lines = [
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:",
            "Powered by",
            "Calling main(",
            azure.PLATFORM_READY,
            "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network",
            "main returned 2",
        ]
        if legacy:
            lines.append(azure.LEGACY_APIC_MARKER)
        return "\n".join(lines)

    def make_prepared(self, root):
        state_dir = root / "prepared"
        state_dir.mkdir(mode=0o700)
        efi = state_dir / "BOOTX64.EFI"
        raw = state_dir / "unikraft.raw"
        vhd = state_dir / azure.PREPARED_IMAGE_VHD
        miz = state_dir / "miz"
        efi.write_bytes(b"efi-application")
        raw.write_bytes(b"r" * azure.VIRTUAL_SIZE)
        vhd.write_bytes(b"v" * (azure.VIRTUAL_SIZE + 512))
        miz.write_bytes(b"pinned-miz")
        miz.chmod(0o700)
        report = azure.packaging_contract(
            azure.image_sha256(efi), vhd.stat().st_size
        )
        azure.save_json(state_dir / "packaging.json", report)
        for _, log_name in (("raw", "raw"), ("vhd", "vpc")):
            for mode, legacy in azure.LOCAL_BOOT_MODES:
                (state_dir / f"local-{log_name}-{mode}-serial.log").write_text(
                    self.boot_text(legacy)
                )
        state = {
            "schema_version": azure.STATE_SCHEMA_VERSION,
            "phase": "prepared",
            "name_prefix": "uk-hv-private-source",
            "location": "westus2",
            "vm_size": "Standard_D2s_v5",
            "platform_marker": azure.PLATFORM_READY,
            "efi_sha256": azure.image_sha256(efi),
            "raw_sha256": azure.image_sha256(raw),
            "image_sha256": azure.image_sha256(vhd),
            "miz_executable": str(miz),
            "miz_executable_sha256": azure.image_sha256(miz),
            "local_platform_boot": True,
            "local_platform_boot_modes": {
                "raw": {"x2apic": True, "legacy-apic": True},
                "vhd": {"x2apic": True, "legacy-apic": True},
            },
        }
        azure.save_json(state_dir / "state.json", state)
        return state_dir, report

    def make_network_prepared(self, root):
        state_dir, report = self.make_prepared(root)
        config = (
            b"CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y\n"
            b'CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4="10.87.0.4"\n'
            b"CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=18887\n"
            b"CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT=18888\n"
            b'CONFIG_APPHYPERVACCEPTANCE_NONCE="87c0ffee5aa8dfd6"\n'
        )
        acceptance = azure.network.acceptance_from_solved_config(
            config, azure.network.PEER_SCRIPT.read_bytes()
        )
        state = json.loads((state_dir / "state.json").read_text())
        state["acceptance"] = acceptance
        azure.save_json(state_dir / "state.json", state)
        marker = azure.network.configuration_marker(acceptance)
        for log in state_dir.glob("local-*-serial.log"):
            log.write_text(log.read_text() + "\n" + marker + "\n")
        return state_dir, report, acceptance

    def export(self, root):
        state_dir, report = self.make_prepared(root)
        artifact = root / "artifact"
        with mock.patch.object(azure, "miz_command", return_value=report):
            digest = azure.export_prepared_image(
                state_dir, artifact, self.source()
            )
        return state_dir, artifact, digest, report

    @staticmethod
    def rewrite_manifest(artifact, update):
        path = artifact / azure.PREPARED_IMAGE_MANIFEST
        manifest = json.loads(path.read_text())
        update(manifest)
        value = azure.canonical_json(manifest)
        path.write_bytes(value)
        return azure.sha256_bytes(value)

    def test_exact_export_import_creates_new_private_run_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir, artifact, digest, report = self.export(root)
            self.assertEqual(
                {path.name for path in artifact.iterdir()},
                azure.PREPARED_IMAGE_FILES,
            )
            manifest_path = artifact / azure.PREPARED_IMAGE_MANIFEST
            manifest_text = manifest_path.read_text()
            self.assertNotIn(str(state_dir), manifest_text)
            self.assertNotIn("uk-hv-private-source", manifest_text)
            self.assertNotIn("subscription", manifest_text)
            self.assertNotIn("serial.log", manifest_text)
            self.assertEqual(
                azure.sha256_bytes(manifest_path.read_bytes()), digest
            )

            local_miz = root / "local-miz"
            local_miz.write_bytes(b"same-revision-local-tool")
            local_miz.chmod(0o700)
            imported = root / "imported"
            with mock.patch.object(azure, "miz_command", return_value=report):
                azure.import_prepared_image(
                    artifact, imported, local_miz, digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )
            state, state_path = azure.load_state(imported)
            self.assertEqual(state["phase"], "prepared")
            self.assertNotEqual(state["name_prefix"], "uk-hv-private-source")
            self.assertNotIn("local_platform_boot", state)
            self.assertFalse(azure.AZURE_OWNERSHIP_FIELDS.intersection(state))
            self.assertEqual(
                state["prepared_image_import"]["manifest_sha256"], digest
            )
            self.assertEqual(
                azure.image_sha256(imported / azure.PREPARED_IMAGE_VHD),
                state["image_sha256"],
            )
            self.assertFalse(state_path.parent.stat().st_mode & 0o077)
            azure.validate_prepared_run_provenance(state, state_path.parent)
            with mock.patch.object(
                azure, "check_upload_dependencies",
                side_effect=RuntimeError("dependency gate reached"),
            ):
                with self.assertRaisesRegex(RuntimeError, "dependency gate reached"):
                    azure.run_prepared(imported, "platform", 30, False)

    def test_network_export_binds_config_peer_transcript_and_four_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir, report, acceptance = self.make_network_prepared(root)
            artifact = root / "artifact"
            with mock.patch.object(azure, "miz_command", return_value=report):
                digest = azure.export_prepared_image(
                    state_dir, artifact, self.source()
                )
            manifest = json.loads(
                (artifact / azure.PREPARED_IMAGE_MANIFEST).read_text()
            )
            self.assertEqual(manifest["acceptance"], acceptance)
            self.assertEqual(manifest["schema_version"], 2)
            self.assertNotIn("10.87.0.5", json.dumps(manifest))
            self.assertTrue(all(
                outcome["network_config"] == "matched"
                for image in manifest["preflight"]["boots"].values()
                for outcome in image.values()
            ))

            local_miz = root / "local-miz"
            local_miz.write_bytes(b"local-miz")
            local_miz.chmod(0o700)
            imported = root / "imported"
            with mock.patch.object(azure, "miz_command", return_value=report):
                azure.import_prepared_image(
                    artifact, imported, local_miz, digest, self.source(),
                    "northeurope", "Standard_D2s_v5",
                )
            state, path = azure.load_state(imported)
            self.assertEqual(state["acceptance"], acceptance)
            azure.validate_prepared_run_provenance(state, path.parent)

            missing = state_dir / "local-vpc-legacy-apic-serial.log"
            missing.write_text(
                missing.read_text().replace(
                    azure.network.configuration_marker(acceptance), ""
                )
            )
            with mock.patch.object(azure, "miz_command", return_value=report):
                with self.assertRaisesRegex(ValueError, "CONFIG"):
                    azure.export_prepared_image(
                        state_dir, root / "missing-config", self.source()
                    )

    def test_export_rechecks_serial_evidence_and_rejects_cloud_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir, report = self.make_prepared(root)
            legacy = state_dir / "local-vpc-legacy-apic-serial.log"
            legacy.write_text(self.boot_text(False))
            with mock.patch.object(azure, "miz_command", return_value=report):
                with self.assertRaisesRegex(RuntimeError, "xAPIC fallback"):
                    azure.export_prepared_image(
                        state_dir, root / "bad-evidence", self.source()
                    )
            legacy.write_text(self.boot_text(True))
            state = json.loads((state_dir / "state.json").read_text())
            state["subscription"] = "must-not-export"
            azure.save_json(state_dir / "state.json", state)
            with self.assertRaisesRegex(ValueError, "Cloud-owned"):
                azure.export_prepared_image(
                    state_dir, root / "cloud-state", self.source()
                )

    def test_import_requires_external_digest_and_exact_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifact, digest, report = self.export(root)
            miz = root / "miz"
            miz.write_bytes(b"local-miz")
            miz.chmod(0o700)
            with mock.patch.object(
                azure, "miz_command", return_value=report
            ) as check:
                with self.assertRaisesRegex(ValueError, "trusted digest"):
                    azure.import_prepared_image(
                        artifact, root / "wrong-digest", miz, "f" * 64,
                        self.source(), "westus2", "Standard_D2s_v5",
                    )
                with self.assertRaisesRegex(ValueError, "provenance"):
                    azure.import_prepared_image(
                        artifact, root / "wrong-source", miz, digest,
                        self.source(run_id=67891),
                        "westus2", "Standard_D2s_v5",
                    )
            check.assert_not_called()
            self.assertFalse((root / "wrong-digest").exists())
            self.assertFalse((root / "wrong-source").exists())

    def test_import_rejects_unknown_duplicate_and_malformed_contracts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifact, _, report = self.export(root)
            miz = root / "miz"
            miz.write_bytes(b"local-miz")
            miz.chmod(0o700)

            unknown = root / "unknown"
            shutil.copytree(artifact, unknown)
            unknown_digest = self.rewrite_manifest(
                unknown, lambda value: value.update(secret_path="/private")
            )
            with self.assertRaisesRegex(ValueError, "unknown or missing"):
                azure.import_prepared_image(
                    unknown, root / "unknown-state", miz, unknown_digest,
                    self.source(), "westus2", "Standard_D2s_v5",
                )

            duplicate = root / "duplicate"
            shutil.copytree(artifact, duplicate)
            duplicate_value = (
                b'{"schema":"first","schema":"second"}\n'
            )
            (duplicate / azure.PREPARED_IMAGE_MANIFEST).write_bytes(
                duplicate_value
            )
            with self.assertRaisesRegex(ValueError, "duplicate field"):
                azure.import_prepared_image(
                    duplicate, root / "duplicate-state", miz,
                    azure.sha256_bytes(duplicate_value), self.source(),
                    "westus2", "Standard_D2s_v5",
                )

            packaging = root / "packaging"
            shutil.copytree(artifact, packaging)
            packaging_digest = self.rewrite_manifest(
                packaging,
                lambda value: value["packaging"].update(generation=1),
            )
            with self.assertRaisesRegex(ValueError, "packaging field"):
                azure.import_prepared_image(
                    packaging, root / "packaging-state", miz,
                    packaging_digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )

            preflight = root / "preflight"
            shutil.copytree(artifact, preflight)
            preflight_digest = self.rewrite_manifest(
                preflight,
                lambda value: value["preflight"]["boots"]["raw"]["x2apic"].update(
                    apic_path="legacy-xapic"
                ),
            )
            with self.assertRaisesRegex(ValueError, "all four exact boots"):
                azure.import_prepared_image(
                    preflight, root / "preflight-state", miz,
                    preflight_digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )

            controller = root / "controller"
            shutil.copytree(artifact, controller)
            controller_digest = self.rewrite_manifest(
                controller,
                lambda value: value.update(controller_sha256="f" * 64),
            )
            with self.assertRaisesRegex(ValueError, "controller revision"):
                azure.import_prepared_image(
                    controller, root / "controller-state", miz,
                    controller_digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )

    def test_import_rejects_extra_files_symlinks_and_changed_vhd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifact, digest, report = self.export(root)
            miz = root / "miz"
            miz.write_bytes(b"local-miz")
            miz.chmod(0o700)

            extra = root / "extra"
            shutil.copytree(artifact, extra)
            (extra / "state.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "unexpected files"):
                azure.import_prepared_image(
                    extra, root / "extra-state", miz, digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )

            linked = root / "linked"
            shutil.copytree(artifact, linked)
            target = root / "outside.vhd"
            shutil.move(linked / azure.PREPARED_IMAGE_VHD, target)
            (linked / azure.PREPARED_IMAGE_VHD).symlink_to(target)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                azure.import_prepared_image(
                    linked, root / "linked-state", miz, digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )

            changed = root / "changed"
            shutil.copytree(artifact, changed)
            image = changed / azure.PREPARED_IMAGE_VHD
            image.write_bytes(b"x" + image.read_bytes()[1:])
            with mock.patch.object(
                azure, "miz_command", return_value=report
            ) as check:
                with self.assertRaisesRegex(ValueError, "does not match"):
                    azure.import_prepared_image(
                        changed, root / "changed-state", miz, digest,
                        self.source(), "westus2", "Standard_D2s_v5",
                    )
            check.assert_not_called()

    def test_import_rechecks_miz_contract_and_private_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifact, digest, report = self.export(root)
            miz = root / "miz"
            miz.write_bytes(b"local-miz")
            miz.chmod(0o700)
            wrong = dict(report)
            wrong["boot-file-sha256"] = "f" * 64
            with mock.patch.object(azure, "miz_command", return_value=wrong):
                with self.assertRaisesRegex(ValueError, "packaging field"):
                    azure.import_prepared_image(
                        artifact, root / "wrong-miz", miz, digest,
                        self.source(), "westus2", "Standard_D2s_v5",
                    )

            imported = root / "imported"
            with mock.patch.object(azure, "miz_command", return_value=report):
                azure.import_prepared_image(
                    artifact, imported, miz, digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )
            manifest = imported / azure.PREPARED_IMAGE_MANIFEST
            manifest.write_bytes(manifest.read_bytes() + b" ")
            state, state_path = azure.load_state(imported)
            with self.assertRaisesRegex(ValueError, "canonical JSON"):
                azure.validate_prepared_run_provenance(
                    state, state_path.parent
                )

    def test_cleanup_of_imported_prepared_state_needs_no_cloud_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, artifact, digest, report = self.export(root)
            miz = root / "miz"
            miz.write_bytes(b"local-miz")
            miz.chmod(0o700)
            imported = root / "imported"
            with mock.patch.object(azure, "miz_command", return_value=report):
                azure.import_prepared_image(
                    artifact, imported, miz, digest, self.source(),
                    "westus2", "Standard_D2s_v5",
                )
            with mock.patch.object(azure, "AzureRun") as cloud:
                azure.cleanup_state(imported)
            cloud.assert_not_called()
            state, _ = azure.load_state(imported)
            self.assertEqual(state["phase"], "cleaned")


class HypervAzureControllerTest(unittest.TestCase):
    def run_fixture(self):
        disk_id = (
            "/test/providers/Microsoft.Compute/disks/uk-hv-fixture-os"
        )
        run = azure.AzureRun({
            "name_prefix": "uk-hv-fixture",
            "image_sha256": "a" * 64,
            "subscription": "test-subscription",
            "location": "westus2",
            "vm_size": "Standard_D2s_v5",
            "platform_marker": azure.PLATFORM_READY,
            "resource_group_id": "/test",
            "disk_id": disk_id,
            "uploaded_disk": {
                "disk_id": disk_id,
                "disk_uuid": "88888888-8888-4888-8888-888888888888",
            },
        }, Path("/unused/state.json"))
        run.record = mock.Mock()
        run.az = mock.Mock()
        return run

    def disk_fixture(self, run):
        return {
            "id": run.state["disk_id"],
            "name": run.disk,
            "type": "Microsoft.Compute/disks",
            "uniqueId": run.state["uploaded_disk"]["disk_uuid"],
            "managedBy": None,
            "tags": run.tags,
            "diskState": "Unattached",
            "provisioningState": "Succeeded",
            "hyperVGeneration": "V2",
            "osType": "Linux",
        }

    def network_run_fixture(self):
        state = {
            "name_prefix": "uk-hv-network-fixture",
            "image_sha256": "a" * 64,
            "subscription": "11111111-2222-3333-4444-555555555555",
            "location": "northeurope",
            "vm_size": "Standard_D2s_v5",
            "platform_marker": azure.PLATFORM_READY,
            "acceptance": self.network_acceptance(),
            "prepared_image_import": {
                "contract": azure.PREPARED_IMAGE_SCHEMA,
                "manifest_sha256": "b" * 64,
                "source": HypervAzurePreparedImageTransferTest.source(),
            },
            "resource_group": "uk-reservation-fixture-rg",
            "resource_group_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-reservation-fixture-rg"
            ),
            "group_precreated": True,
        }
        run = azure.AzureRun(state, Path("/unused/state.json"))
        run.record = mock.Mock()
        run.az = mock.Mock()
        return run, state

    @staticmethod
    def peer_declared_ids(run):
        return [
            run.expected_resource_id(
                "Microsoft.Network", "networkSecurityGroups",
                run.prefix + "-nsg",
            ),
            run.expected_resource_id(
                "Microsoft.Network", "virtualNetworks",
                run.prefix + "-vnet",
            ),
            run.expected_resource_id(
                "Microsoft.Network", "networkInterfaces",
                run.prefix + "-peer-nic",
            ),
            run.expected_resource_id(
                "Microsoft.Network", "networkInterfaces",
                run.prefix + "-guest-nic",
            ),
            run.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", run.peer_vm,
            ),
        ]

    @classmethod
    def peer_deployment(cls, run):
        receipt = cls.peer_receipt(run)
        return {
            "id": run.expected_resource_id(
                "Microsoft.Resources", "deployments", run.prefix + "-peer"
            ),
            "name": run.prefix + "-peer",
            "properties": {
                "provisioningState": "Succeeded",
                "correlationId": "11111111-1111-4111-8111-111111111111",
                "outputResources": [
                    {"id": identifier}
                    for identifier in cls.peer_declared_ids(run)
                ],
                "outputs": {
                    "peerVmId": {
                        "type": "String",
                        "value": receipt["peer_vm_id"],
                    },
                    "peerVmUuid": {
                        "type": "String",
                        "value": receipt["peer_vm_uuid"],
                    },
                    "peerDiskId": {
                        "type": "String",
                        "value": receipt["peer_disk_id"],
                    },
                    "peerDiskUuid": {
                        "type": "String",
                        "value": receipt["peer_disk_uuid"],
                    },
                },
            },
        }

    @classmethod
    def peer_receipt(cls, run, *, complete=True):
        receipt = {
            "deployment_id": run.expected_resource_id(
                "Microsoft.Resources", "deployments", run.prefix + "-peer"
            ),
            "correlation_id": "11111111-1111-4111-8111-111111111111",
            "declared_resource_ids": cls.peer_declared_ids(run),
        }
        if complete:
            receipt.update({
                "peer_vm_id": run.expected_resource_id(
                    "Microsoft.Compute", "virtualMachines", run.peer_vm
                ),
                "peer_vm_uuid": "22222222-2222-4222-8222-222222222222",
                "peer_disk_id": run.expected_resource_id(
                    "Microsoft.Compute", "disks", run.prefix + "-peer-os"
                ),
                "peer_disk_uuid": "33333333-3333-4333-8333-333333333333",
            })
        return receipt

    @classmethod
    def guest_receipt(cls, run):
        vm_id = run.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", run.vm
        )
        return {
            "deployment_id": run.expected_resource_id(
                "Microsoft.Resources", "deployments", run.prefix
            ),
            "correlation_id": "55555555-5555-4555-8555-555555555555",
            "declared_resource_ids": [vm_id],
            "vm_id": vm_id,
            "vm_uuid": "66666666-6666-4666-8666-666666666666",
            "disk_id": run.state["disk_id"],
            "disk_uuid": run.state["uploaded_disk"]["disk_uuid"],
            "nic_id": run.state["guest_nic_id"],
        }

    @classmethod
    def bind_uploaded_disk(cls, run):
        disk_id = run.expected_resource_id(
            "Microsoft.Compute", "disks", run.disk
        )
        run.state.update(
            disk_id=disk_id,
            uploaded_disk={
                "disk_id": disk_id,
                "disk_uuid": "88888888-8888-4888-8888-888888888888",
            },
        )
        return disk_id

    @classmethod
    def uploaded_disk(cls, run, *, attached_vm_id=None):
        return {
            "id": run.state["disk_id"],
            "name": run.disk,
            "type": "Microsoft.Compute/disks",
            "uniqueId": run.state["uploaded_disk"]["disk_uuid"],
            "managedBy": attached_vm_id,
            "tags": run.tags,
            "diskState": (
                "Attached" if attached_vm_id is not None else "Unattached"
            ),
            "provisioningState": "Succeeded",
            "hyperVGeneration": "V2",
            "osType": "Linux",
        }

    def complete_disk_upload(self, run, state):
        disk_id = run.expected_resource_id(
            "Microsoft.Compute", "disks", run.disk
        )
        disk_uuid = "88888888-8888-4888-8888-888888888888"
        disk = {
            "id": disk_id,
            "name": run.disk,
            "type": "Microsoft.Compute/disks",
            "uniqueId": disk_uuid,
            "managedBy": None,
            "tags": run.tags,
            "diskState": "Unattached",
            "provisioningState": "Succeeded",
            "hyperVGeneration": "V2",
            "osType": "Linux",
        }
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )
        run.az.side_effect = [
            disk,
            {"accessSas": (
                "https://fixture.blob.core.windows.net/"
                "upload?sig=fixture"
            )},
            None,
            disk,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with mock.patch.object(azure, "upload_managed_vhd"):
            run.upload_disk(image)
        self.assertEqual(state["disk_id"], disk_id)
        self.assertEqual(state["uploaded_disk"], {
            "disk_id": disk_id,
            "disk_uuid": disk_uuid,
        })
        return disk

    @classmethod
    def guest_deployment(cls, run):
        receipt = cls.guest_receipt(run)
        return {
            "id": receipt["deployment_id"],
            "name": run.prefix,
            "properties": {
                "provisioningState": "Succeeded",
                "correlationId": receipt["correlation_id"],
                "outputResources": [{"id": receipt["vm_id"]}],
                "outputs": {
                    "vmId": {
                        "type": "String", "value": receipt["vm_id"],
                    },
                    "vmUuid": {
                        "type": "String", "value": receipt["vm_uuid"],
                    },
                    "osDiskId": {
                        "type": "String", "value": receipt["disk_id"],
                    },
                    "nicId": {
                        "type": "String", "value": receipt["nic_id"],
                    },
                },
            },
        }

    @classmethod
    def guest_vm(cls, run, *, provisioning="Succeeded", vm_uuid=None):
        receipt = cls.guest_receipt(run)
        return {
            "id": receipt["vm_id"], "name": run.vm,
            "type": "Microsoft.Compute/virtualMachines",
            "vmId": vm_uuid or receipt["vm_uuid"],
            "tags": run.tags,
            "provisioningState": provisioning,
            "hardwareProfile": {"vmSize": run.state["vm_size"]},
            "storageProfile": {
                "osDisk": {"managedDisk": {"id": receipt["disk_id"]}},
            },
            "securityProfile": {"securityType": "Standard"},
            "networkProfile": {
                "networkInterfaces": [{"id": receipt["nic_id"]}],
            },
        }

    @staticmethod
    def network_acceptance():
        config = (
            b"CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y\n"
            b'CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4="10.87.0.4"\n'
            b"CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=18887\n"
            b"CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT=18888\n"
            b'CONFIG_APPHYPERVACCEPTANCE_NONCE="87c0ffee5aa8dfd6"\n'
        )
        return azure.network.acceptance_from_solved_config(
            config, azure.network.PEER_SCRIPT.read_bytes()
        )

    @staticmethod
    def reservation():
        subscription = "11111111-2222-3333-4444-555555555555"
        prefix = "uk-reservation-fixture"
        return {
            "schema": azure.RESERVATION_SCHEMA,
            "schema_version": 1,
            "phase": "group-created",
            "subscription": subscription,
            "location": "northeurope",
            "name_prefix": prefix,
            "resource_group": prefix + "-rg",
            "tags": {
                **azure.RESERVATION_TAGS,
                "unikraft-run": prefix,
            },
            "resource_group_id": (
                f"/subscriptions/{subscription}/resourceGroups/{prefix}-rg"
            ),
            "resource_count": 0,
        }

    def test_existing_group_is_never_adopted(self):
        run = self.run_fixture()
        run.az.return_value = True
        with self.assertRaisesRegex(RuntimeError, "Refusing to adopt"):
            run.create_group()
        self.assertEqual(run.az.call_count, 1)

    def test_standard_vm_accepts_null_profile_but_rejects_other_security_types(self):
        for profile in (None, {"securityType": "Standard"},
                        {"securityType": "TrustedLaunch"}, {}, "Standard"):
            with self.subTest(profile=profile):
                run = self.run_fixture()
                run.az.side_effect = [self.disk_fixture(run), None, {
                    "id": "/test/vm", "tags": run.tags,
                    "provisioningState": "Succeeded",
                    "storageProfile": {
                        "osDisk": {
                            "managedDisk": {"id": run.state["disk_id"]}
                        }
                    },
                    "securityProfile": profile,
                }]
                if profile is None or profile == {"securityType": "Standard"}:
                    run.deploy_vm()
                    run.record.assert_called_with("vm-created", vm_id="/test/vm")
                else:
                    with self.assertRaisesRegex(RuntimeError, "Standard security"):
                        run.deploy_vm()

    def test_private_guest_updating_becomes_ready_with_deployment_anchor(self):
        run, state = self.network_run_fixture()
        self.bind_uploaded_disk(run)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        receipt = self.guest_receipt(run)
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )
        run.az.side_effect = [
            self.uploaded_disk(run),
            self.guest_deployment(run),
            self.guest_vm(run, provisioning="Updating"),
            self.uploaded_disk(run, attached_vm_id=receipt["vm_id"]),
            self.guest_vm(run),
            self.uploaded_disk(run, attached_vm_id=receipt["vm_id"]),
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100), \
                mock.patch.object(azure.time, "sleep"):
            run.deploy_vm(state["guest_nic_id"], deadline=700)
        self.assertEqual(state["guest_deployment"], receipt)
        self.assertEqual(state["vm_id"], receipt["vm_id"])
        self.assertEqual(state["phase"], "vm-created")
        self.assertTrue(all(
            call.kwargs["timeout"] <= 300
            for call in run.az.call_args_list
        ))

    def test_private_guest_query_cannot_complete_after_deadline(self):
        run, state = self.network_run_fixture()
        self.bind_uploaded_disk(run)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        deployment = self.guest_deployment(run)
        vm = self.guest_vm(run)
        clock = [100.0]
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )

        def command(arguments, **_):
            if arguments[:2] == ["disk", "show"]:
                return self.uploaded_disk(run)
            if arguments[:3] == ["deployment", "group", "create"]:
                return deployment
            if arguments[:2] == ["vm", "show"]:
                clock[0] = 102.0
                return vm
            self.fail(f"Unexpected mocked command: {arguments[:3]}")

        run.az.side_effect = command
        with mock.patch.object(
            azure.time, "monotonic", side_effect=lambda: clock[0]
        ):
            with self.assertRaisesRegex(
                RuntimeError, "guest provisioning readiness"
            ):
                run.deploy_vm(state["guest_nic_id"], deadline=101.0)
        self.assertEqual(
            state["guest_deployment"], self.guest_receipt(run)
        )
        self.assertNotIn("vm_id", state)

    def test_deadline_timeout_preserves_subsecond_budget(self):
        with mock.patch.object(azure.time, "monotonic", return_value=100.75):
            self.assertEqual(
                azure.AzureRun.deadline_timeout(101.0, 120), 0.25
            )

    def test_guest_cleanup_recovers_only_original_deployment_instance(self):
        run, state = self.network_run_fixture()
        self.bind_uploaded_disk(run)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        deployment = self.guest_deployment(run)
        vm = self.guest_vm(run)
        receipt = self.guest_receipt(run)
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )
        run.az.side_effect = [
            self.uploaded_disk(run), deployment,
            RuntimeError("fixture guest read unavailable"),
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "read unavailable"):
                run.deploy_vm(state["guest_nic_id"], deadline=700)
        self.assertNotIn("vm_id", state)
        self.assertEqual(state["guest_deployment"], receipt)

        disk_resource = {
            "id": state["disk_id"], "name": run.disk,
            "type": "Microsoft.Compute/disks", "tags": run.tags,
        }
        vm_resource = {
            "id": receipt["vm_id"], "name": run.vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        run.az.reset_mock()
        run.az.side_effect = [
            True, group, [disk_resource, vm_resource],
            deployment, vm,
            self.uploaded_disk(run, attached_vm_id=receipt["vm_id"]),
            None, False,
        ]
        run.cleanup()
        self.assertEqual(state["phase"], "cleaned")
        self.assertEqual(state["vm_id"], receipt["vm_id"])

    def test_guest_cleanup_refuses_replacement_after_deployment_success(self):
        run, state = self.network_run_fixture()
        self.bind_uploaded_disk(run)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        deployment = self.guest_deployment(run)
        receipt = self.guest_receipt(run)
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )
        run.az.side_effect = [
            self.uploaded_disk(run), deployment,
            RuntimeError("fixture guest read unavailable"),
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "read unavailable"):
                run.deploy_vm(state["guest_nic_id"], deadline=700)

        disk_resource = {
            "id": state["disk_id"], "name": run.disk,
            "type": "Microsoft.Compute/disks", "tags": run.tags,
        }
        replacement = self.guest_vm(
            run, vm_uuid="77777777-7777-4777-8777-777777777777"
        )
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        run.az.reset_mock()
        run.az.side_effect = [
            True, group, [disk_resource, replacement],
            deployment, replacement,
            self.uploaded_disk(run, attached_vm_id=receipt["vm_id"]),
        ]
        with self.assertRaisesRegex(RuntimeError, "identity"):
            run.cleanup()
        self.assertEqual(state["guest_deployment"], receipt)
        self.assertNotIn("vm_id", state)
        self.assertFalse(any(
            call.args[0][:2] == ["group", "delete"]
            for call in run.az.call_args_list
        ))

    def test_upload_deploy_and_cleanup_reject_replaced_guest_disk(self):
        run, state = self.network_run_fixture()
        original = self.complete_disk_upload(run, state)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        deployment = self.guest_deployment(run)
        receipt = self.guest_receipt(run)
        vm = self.guest_vm(run)
        run.az.reset_mock()
        run.az.side_effect = [
            original, deployment,
            RuntimeError("fixture guest read unavailable"),
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "read unavailable"):
                run.deploy_vm(state["guest_nic_id"], deadline=700)
        self.assertEqual(state["guest_deployment"], receipt)

        replacement = {
            **original,
            "uniqueId": "99999999-9999-4999-8999-999999999999",
            "managedBy": receipt["vm_id"],
            "diskState": "Attached",
        }
        vm_resource = {
            "id": receipt["vm_id"], "name": run.vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        run.az.reset_mock()
        run.az.side_effect = [
            True, group, [replacement, vm_resource],
            deployment, vm, replacement,
        ]
        with self.assertRaisesRegex(
            RuntimeError, "replaced or unproven"
        ):
            run.cleanup()
        self.assertEqual(
            state["uploaded_disk"]["disk_uuid"], original["uniqueId"]
        )
        self.assertFalse(any(
            call.args[0][:2] == ["group", "delete"]
            for call in run.az.call_args_list
        ))

    def test_guest_deployment_rejects_replaced_attached_disk(self):
        run, state = self.network_run_fixture()
        original = self.complete_disk_upload(run, state)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        receipt = self.guest_receipt(run)
        replacement = {
            **original,
            "uniqueId": "99999999-9999-4999-8999-999999999999",
            "managedBy": receipt["vm_id"],
            "diskState": "Attached",
        }
        run.az.reset_mock()
        run.az.side_effect = [
            original, self.guest_deployment(run),
            self.guest_vm(run), replacement,
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(
                RuntimeError, "replaced or unproven"
            ):
                run.deploy_vm(state["guest_nic_id"], deadline=700)
        self.assertEqual(state["guest_deployment"], receipt)
        self.assertNotIn("vm_id", state)

    def test_unknown_guest_still_deallocates_proven_peer(self):
        run, state = self.network_run_fixture()
        original = self.complete_disk_upload(run, state)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        peer_receipt = self.peer_receipt(run)
        peer_deployment = self.peer_deployment(run)
        state.update(
            peer_deployment=peer_receipt,
            network_preflight={"peer_image": image},
        )
        primary = azure.AzureCliTimeout(
            ["deployment", "group", "create"]
        )
        run.az.reset_mock()
        run.az.side_effect = [original, primary]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaises(azure.AzureCliTimeout):
                run.deploy_vm(state["guest_nic_id"], deadline=700)

        peer_vm_resource = {
            "id": peer_receipt["peer_vm_id"], "name": run.peer_vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        peer_disk_resource = {
            "id": peer_receipt["peer_disk_id"],
            "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": run.tags,
        }
        unknown_guest = {
            "id": run.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", run.vm
            ),
            "name": run.vm,
            "type": "Microsoft.Compute/virtualMachines",
            "tags": run.tags,
        }
        attached_disk = {
            **original,
            "managedBy": unknown_guest["id"],
            "diskState": "Attached",
        }
        peer_vm = {
            **peer_vm_resource,
            "vmId": peer_receipt["peer_vm_uuid"],
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": image,
                "osDisk": {
                    "managedDisk": {"id": peer_receipt["peer_disk_id"]}
                },
            },
        }
        peer_disk = {
            **peer_disk_resource,
            "uniqueId": peer_receipt["peer_disk_uuid"],
            "managedBy": peer_receipt["peer_vm_id"],
        }
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        deallocated = []

        def command(arguments, **_kwargs):
            if arguments[:2] == ["group", "exists"]:
                return True
            if arguments[:2] == ["group", "show"]:
                return group
            if arguments[:2] == ["resource", "list"]:
                return [
                    peer_vm_resource, peer_disk_resource,
                    unknown_guest, attached_disk,
                ]
            if arguments[:3] == ["deployment", "group", "show"]:
                return peer_deployment
            if arguments[:2] == ["vm", "show"]:
                return peer_vm
            if arguments[:2] == ["disk", "show"]:
                if arguments[-1] == run.disk:
                    return attached_disk
                return peer_disk
            if arguments[:2] == ["vm", "deallocate"]:
                deallocated.append(arguments)
                return None
            if arguments[:2] == ["group", "delete"]:
                self.fail("Unknown guest ownership reached group deletion")
            self.fail(f"Unexpected mocked command: {arguments[:3]}")

        run.az.reset_mock()
        run.az.side_effect = command
        with self.assertRaises(azure.RunCleanupError) as raised:
            azure.cleanup_after_primary_failure(run, primary)
        message = str(raised.exception)
        self.assertIn("Primary run failure", message)
        self.assertIn("cleanup also failed", message)
        self.assertIn("guest deployment provenance is incomplete", message)
        self.assertIn("Uploaded disk is missing", message)
        self.assertEqual(len(deallocated), 1)
        deallocate_call = next(
            call for call in run.az.call_args_list
            if call.args[0][:2] == ["vm", "deallocate"]
        )
        self.assertEqual(deallocate_call.kwargs["timeout"], 120)
        bounded = [
            call for call in run.az.call_args_list
            if (
                call.args[0][:3] == ["deployment", "group", "show"]
                or call.args[0][:2] in (
                    ["vm", "show"], ["disk", "show"],
                    ["vm", "deallocate"],
                )
            )
        ]
        self.assertEqual(len(bounded), 5)
        self.assertTrue(all(
            call.kwargs.get("timeout") == 120 for call in bounded
        ))
        self.assertEqual(state["phase"], "cleanup-failed")

    def test_guest_cleanup_revalidates_original_deployment_outputs(self):
        run, state = self.network_run_fixture()
        self.bind_uploaded_disk(run)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        receipt = self.guest_receipt(run)
        state["guest_deployment"] = receipt
        disk_resource = {
            "id": state["disk_id"], "name": run.disk,
            "type": "Microsoft.Compute/disks", "tags": run.tags,
        }
        vm_resource = {
            "id": receipt["vm_id"], "name": run.vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        changed = self.guest_deployment(run)
        changed["properties"]["outputs"]["vmUuid"]["value"] = (
            "77777777-7777-4777-8777-777777777777"
        )
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        run.az.side_effect = [
            True, group, [disk_resource, vm_resource], changed,
            self.uploaded_disk(run, attached_vm_id=receipt["vm_id"]),
        ]
        with self.assertRaisesRegex(RuntimeError, "deployment changed"):
            run.cleanup()
        self.assertFalse(any(
            call.args[0][:2] == ["group", "delete"]
            for call in run.az.call_args_list
        ))

        missing = self.guest_deployment(run)
        del missing["properties"]["outputs"]["vmUuid"]
        with self.assertRaisesRegex(RuntimeError, "VM UUID.*unavailable"):
            run.guest_deployment_receipt(
                missing, state["guest_nic_id"]
            )

    def test_unowned_group_cannot_be_deleted(self):
        run = self.run_fixture()
        run.az.side_effect = [True, {"id": "/other/group", "tags": {}}]
        with self.assertRaisesRegex(RuntimeError, "ownership tags"):
            run.cleanup()
        self.assertEqual(run.az.call_count, 2)

    def test_unowned_resource_prevents_group_deletion(self):
        run = self.run_fixture()
        run.az.side_effect = [
            True, {"tags": run.tags}, [{"id": "/other/disk", "tags": {}}],
        ]
        with self.assertRaisesRegex(RuntimeError, "ownership tags"):
            run.cleanup()
        self.assertEqual(run.az.call_count, 3)

    def test_repeated_cleanup_of_absent_group_is_safe(self):
        run = self.run_fixture()
        run.az.return_value = False
        run.cleanup()
        run.record.assert_called_once_with("cleaned")

    @mock.patch.object(azure, "upload_managed_vhd", side_effect=RuntimeError("upload failed"))
    def test_upload_failure_always_revokes_disk_access(self, upload):
        run = self.run_fixture()
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.core.windows.net/path?sig=secret"},
            None,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with mock.patch.object(azure.sys, "stderr", io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "upload failed"):
                run.upload_disk(image)
        self.assertEqual(run.az.call_args.args[0][:2], ["disk", "revoke-access"])
        upload.assert_called_once_with(
            image, "https://disk.blob.core.windows.net/path", "sig=secret"
        )

    @mock.patch.object(azure.subprocess, "run")
    def test_upload_timeout_is_sanitized_before_intermediate_logging(self, execute):
        run = self.run_fixture()
        endpoint = (
            "https://privateaccount.blob.core.windows.net/"
            "private-container/private-disk"
        )
        image_path = "/private/build/private-image.vhd"
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": endpoint + "?sig=private-sas"},
            None,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        image.__str__ = mock.Mock(return_value=image_path)

        def time_out(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        execute.side_effect = time_out
        errors = io.StringIO()
        with mock.patch.object(azure.sys, "stderr", errors):
            with self.assertRaisesRegex(
                RuntimeError,
                "Managed-disk upload helper timed out; "
                "private upload details withheld",
            ) as stopped:
                run.upload_disk(image)
        rendered = "".join(traceback.format_exception(stopped.exception))
        visible = errors.getvalue() + str(stopped.exception) + rendered
        for private in (
            "privateaccount", "private-container", "private-disk",
            "private-image.vhd", image_path, endpoint, "private-sas",
        ):
            self.assertNotIn(private, visible)
        self.assertIsNone(stopped.exception.__cause__)
        self.assertIsNone(stopped.exception.__context__)
        self.assertEqual(
            run.az.call_args.args[0][:2], ["disk", "revoke-access"]
        )

    @mock.patch.object(azure, "upload_managed_vhd")
    def test_unimported_disk_cannot_advance_to_deployment(self, upload):
        run = self.run_fixture()
        incomplete = self.disk_fixture(run)
        incomplete["diskState"] = "ReadyToUpload"
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.core.windows.net/path?sig=secret"},
            None, incomplete,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with self.assertRaisesRegex(RuntimeError, "successfully imported"):
            run.upload_disk(image)
        self.assertNotIn(mock.call("disk-ready"), run.record.call_args_list)

    def test_uploaded_disk_replacement_blocks_cleanup(self):
        run, state = self.network_run_fixture()
        original = self.complete_disk_upload(run, state)
        replacement = {
            **original,
            "uniqueId": "99999999-9999-4999-8999-999999999999",
        }
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        run.az.reset_mock()
        run.az.side_effect = [
            True, group, [replacement], replacement,
        ]
        with self.assertRaisesRegex(
            RuntimeError, "replaced or unproven"
        ):
            run.cleanup()
        self.assertEqual(
            state["uploaded_disk"]["disk_uuid"], original["uniqueId"]
        )
        self.assertFalse(any(
            call.args[0][:2] == ["group", "delete"]
            for call in run.az.call_args_list
        ))

    def test_uploaded_disk_identity_is_durable_before_access_grant(self):
        run, state = self.network_run_fixture()
        disk_id = run.expected_resource_id(
            "Microsoft.Compute", "disks", run.disk
        )
        disk_uuid = "88888888-8888-4888-8888-888888888888"
        created = {
            "id": disk_id, "name": run.disk,
            "type": "Microsoft.Compute/disks",
            "uniqueId": disk_uuid, "managedBy": None,
            "tags": run.tags,
        }
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )
        run.az.side_effect = [
            created, RuntimeError("fixture grant unavailable"), None,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with mock.patch.object(azure.sys, "stderr", io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "grant unavailable"):
                run.upload_disk(image)
        self.assertEqual(state["phase"], "uploading-disk")
        self.assertEqual(state["uploaded_disk"], {
            "disk_id": disk_id, "disk_uuid": disk_uuid,
        })

        run, state = self.network_run_fixture()
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )
        run.az.return_value = {key: value for key, value in created.items()
                               if key != "uniqueId"}
        with self.assertRaisesRegex(RuntimeError, "identity is unavailable"):
            run.upload_disk(image)
        self.assertNotIn("uploaded_disk", state)
        self.assertEqual(run.az.call_count, 1)

    def test_interrupted_upload_cleanup_uses_durable_identity_not_readiness(self):
        variants = (
            ({}, True),
            ({"uniqueId": "99999999-9999-4999-8999-999999999999"}, False),
            ({"managedBy": "/fixture/other-vm"}, False),
        )
        for changes, cleanup_allowed in variants:
            with self.subTest(changes=changes), \
                    mock.patch.dict(os.environ), \
                    tempfile.TemporaryDirectory() as temporary:
                run, state = self.network_run_fixture()
                state["schema_version"] = azure.STATE_SCHEMA_VERSION
                directory = Path(temporary)
                run.state_path = directory / "state.json"
                disk_id = run.expected_uploaded_disk_id()
                disk_uuid = "88888888-8888-4888-8888-888888888888"
                created = {
                    "id": disk_id, "name": run.disk,
                    "type": "Microsoft.Compute/disks",
                    "uniqueId": disk_uuid, "managedBy": None,
                    "tags": {**run.tags, "fixture-extra": "retained"},
                    "diskState": "ReadyToUpload",
                    "provisioningState": "Succeeded",
                    "hyperVGeneration": "V2", "osType": "Linux",
                }

                def interrupt_after_record(phase, **fields):
                    azure.AzureRun.record(run, phase, **fields)
                    if phase == "uploading-disk":
                        raise InterruptedError("fixture interruption")

                run.record = interrupt_after_record
                run.az.return_value = created
                image = mock.Mock()
                image.stat.return_value.st_size = 69206528
                with self.assertRaisesRegex(
                    InterruptedError, "fixture interruption"
                ):
                    run.upload_disk(image)
                self.assertEqual(run.az.call_count, 1)
                self.assertEqual(
                    run.az.call_args.args[0][:2], ["disk", "create"]
                )

                saved, path = azure.load_state(directory)
                self.assertEqual(saved["uploaded_disk"], {
                    "disk_id": disk_id, "disk_uuid": disk_uuid,
                })
                recovered = azure.AzureRun(saved, path)
                with self.assertRaisesRegex(RuntimeError, "unproven"):
                    recovered.verify_uploaded_disk_identity(created)
                current = {**created, **changes}
                group = {
                    "id": saved["resource_group_id"],
                    "tags": recovered.group_tags,
                }
                responses = [True, group, [current], current]
                if cleanup_allowed:
                    responses.extend((None, False))
                recovered.az = mock.Mock(side_effect=responses)
                if cleanup_allowed:
                    recovered.cleanup()
                    self.assertEqual(
                        azure.load_state(directory)[0]["phase"], "cleaned"
                    )
                else:
                    with self.assertRaises(azure.CleanupValidationError):
                        recovered.cleanup()
                self.assertEqual(
                    any(
                        call.args[0][:2] == ["group", "delete"]
                        for call in recovered.az.call_args_list
                    ),
                    cleanup_allowed,
                )
                self.assertEqual(
                    saved["uploaded_disk"]["disk_uuid"], disk_uuid
                )

    def test_uploaded_disk_replacement_blocks_vm_deployment(self):
        run, state = self.network_run_fixture()
        original = self.complete_disk_upload(run, state)
        state["guest_nic_id"] = run.expected_resource_id(
            "Microsoft.Network", "networkInterfaces",
            run.prefix + "-guest-nic",
        )
        replacement = {
            **original,
            "uniqueId": "99999999-9999-4999-8999-999999999999",
        }
        run.az.reset_mock()
        run.az.side_effect = [replacement]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(
                RuntimeError, "replaced or unproven"
            ):
                run.deploy_vm(state["guest_nic_id"], deadline=700)
        self.assertFalse(any(
            call.args[0][:3] == ["deployment", "group", "create"]
            for call in run.az.call_args_list
        ))

    def test_initial_upload_error_remains_visible_if_revocation_also_fails(self):
        run = self.run_fixture()
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.storage.azure.net:8080/path?sig=secret"},
            RuntimeError("revoke failed"),
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with mock.patch.object(azure.sys, "stderr") as errors:
            with self.assertRaisesRegex(RuntimeError, "revoke failed"):
                run.upload_disk(image)
        output = "".join(call.args[0] for call in errors.write.call_args_list)
        self.assertIn("Disk upload did not complete:", output)
        self.assertIn("Expected an Azure public-cloud HTTPS Blob SAS endpoint", output)
        self.assertNotIn("secret", output)

    def test_upload_rejects_non_azure_or_plaintext_endpoints(self):
        for endpoint in (
            "http://disk.blob.core.windows.net/path?sig=secret",
            "https://blob.core.windows.net.attacker.invalid/path?sig=secret",
            "https://user@disk.blob.core.windows.net/path?sig=secret",
            "https://disk.blob.core.windows.net/path",
            "https://disk.blob.storage.azure.net:8080/path?sig=secret",
            "https://md-partition.blob.storage.azure.net.attacker.invalid/path?sig=secret",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    azure.upload_endpoint(endpoint)

    def test_both_documented_managed_disk_hostname_families_are_supported(self):
        for host in (
            "md-impexp-disk.blob.core.windows.net",
            "md-diskpartition.blob.storage.azure.net",
            "md-impexp-disk.z43.blob.storage.azure.net",
            "md-impexp-disk.z20.blob.storage.azure.net:8443",
        ):
            with self.subTest(host=host):
                endpoint, sas = azure.upload_endpoint(f"https://{host}/path?sig=secret")
                self.assertEqual(endpoint, f"https://{host}/path")
                self.assertEqual(sas, "sig=secret")

    def test_disk_access_response_supports_cli_and_rest_sas_spellings(self):
        for key in ("accessSAS", "accessSas"):
            with self.subTest(key=key):
                self.assertEqual(azure.disk_access_sas({key: "expected"}), "expected")
        self.assertEqual(azure.disk_access_sas({
            "accessSAS": "expected", "accessSas": "expected",
        }), "expected")
        for grant in (
            None, {}, {"accessSAS": None}, {"accessSAS": 1},
            {"accessSAS": ""}, {"accessSAS": "first", "accessSas": "second"},
        ):
            with self.subTest(grant=grant):
                with self.assertRaises(ValueError):
                    azure.disk_access_sas(grant)

    @mock.patch.object(azure.subprocess, "run")
    def test_managed_serial_json_preserves_lines(self, execute):
        serial = "\n".join((
            azure.PLATFORM_READY, azure.BLOCK_READY,
            azure.NETWORK_READY, azure.IO_READY,
        )) + "\n"
        execute.return_value = mock.Mock(returncode=0, stdout=json.dumps(serial))
        text = azure.azure_cli(
            ["vm", "boot-diagnostics", "get-boot-log"], private=True
        )
        self.assertTrue(azure.inspect_boot_log(text)["io_ready"])
        command = execute.call_args.args[0]
        self.assertEqual(command[command.index("--output") + 1], "json")
        self.assertFalse(azure.inspect_boot_log(repr(serial.encode()))["io_ready"])

    @mock.patch.object(azure.subprocess, "run")
    def test_private_cli_error_does_not_print_credentials(self, execute):
        execute.return_value = mock.Mock(
            returncode=1, stderr="failed at ?sig=secret", stdout=""
        )
        with self.assertRaises(RuntimeError) as error:
            azure.azure_cli(["disk", "grant-access"], private=True)
        self.assertNotIn("secret", str(error.exception))

    @mock.patch.object(azure.subprocess, "run")
    def test_selected_account_timeout_withholds_command_and_subscription(
        self, execute
    ):
        subscription = "11111111-2222-3333-4444-555555555555"
        execute.side_effect = subprocess.TimeoutExpired(
            ["az", "account", "show", "--subscription", subscription], 5
        )
        with self.assertRaises(azure.AzureCliTimeout) as error:
            azure.selected_account(subscription)
        self.assertNotIn(subscription, str(error.exception))
        self.assertNotIn("--subscription", str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    @mock.patch.object(azure.subprocess, "run")
    def test_network_lifecycle_cli_errors_are_private_by_default(self, execute):
        run, state = self.network_run_fixture()
        private_run = azure.AzureRun(state, Path("/unused/state.json"))
        resource_id = (
            state["resource_group_id"]
            + "/providers/Microsoft.Compute/virtualMachines/private-peer"
        )
        execute.return_value = mock.Mock(
            returncode=1,
            stderr=(
                "Authorization failed for " + resource_id
                + " using ?sig=private-secret"
            ),
            stdout="",
        )
        with self.assertRaises(azure.AzureCliError) as error:
            private_run.az([
                "vm", "show", "--ids", resource_id,
            ])
        message = str(error.exception)
        self.assertNotIn(resource_id, message)
        self.assertNotIn(state["subscription"], message)
        self.assertNotIn("private-secret", message)
        self.assertIn("credential-bearing output withheld", message)

    def test_ownership_and_top_level_timeout_errors_withhold_private_ids(self):
        run, state = self.network_run_fixture()
        resource_id = (
            state["resource_group_id"]
            + "/providers/Microsoft.Compute/disks/private"
        )
        with self.assertRaises(RuntimeError) as ownership:
            run.require_owned({"id": resource_id, "tags": {}})
        self.assertNotIn(resource_id, str(ownership.exception))

        timeout = subprocess.TimeoutExpired(
            ["az", "group", "show", "--subscription", state["subscription"]],
            5,
        )
        output = io.StringIO()
        with mock.patch.object(
            azure.sys, "argv",
            ["hyperv-azure.py", "cleanup", "--state-dir", "/private/state"],
        ), mock.patch.object(
            azure, "cleanup_state", side_effect=timeout
        ), mock.patch.object(azure.sys, "stderr", output):
            with self.assertRaises(SystemExit) as stopped:
                azure.main()
            print(stopped.exception, file=azure.sys.stderr)
        message = output.getvalue()
        self.assertNotIn(state["subscription"], message)
        self.assertNotIn("/private/state", message)
        self.assertNotIn("Traceback", message)
        self.assertIn("private command details withheld", message)
        self.assertIsNone(stopped.exception.__cause__)

    @mock.patch.object(azure.subprocess, "run")
    def test_upload_helper_ignores_ambient_credentials_and_bounds_runtime(self, execute):
        execute.return_value = mock.Mock(returncode=0, stdout='{"available": true}')
        with mock.patch.dict(azure.os.environ, {
            "AZURE_STORAGE_CONNECTION_STRING": "unrelated-account",
            "AZURE_STORAGE_KEY": "unrelated-key",
        }):
            azure.upload_helper(["--check-dependencies"], sas="expected-sas")
        environment = execute.call_args.kwargs["env"]
        self.assertNotIn("AZURE_STORAGE_CONNECTION_STRING", environment)
        self.assertNotIn("AZURE_STORAGE_KEY", environment)
        self.assertEqual(environment["AZURE_STORAGE_SAS_TOKEN"], "expected-sas")
        self.assertNotIn("expected-sas", " ".join(execute.call_args.args[0]))
        self.assertEqual(execute.call_args.kwargs["timeout"], 1200)

    @mock.patch.object(azure, "azure_cli")
    def test_subscription_preflight_never_registers_providers(self, command):
        command.side_effect = [
            {"id": "subscription", "state": "Enabled", "environmentName": "AzureCloud"},
            "NotRegistered",
        ]
        with self.assertRaisesRegex(RuntimeError, "must already be registered"):
            azure.check_subscription("westus2", "Standard_D2s_v5")
        self.assertEqual(command.call_count, 2)

    @mock.patch.object(azure, "azure_cli")
    def test_subscription_preflight_rejects_restricted_sku(self, command):
        command.side_effect = [
            {"id": "subscription", "state": "Enabled", "environmentName": "AzureCloud"},
            "Registered", "Registered", ["2025-11-01"],
            [{"restrictions": [{"type": "Location"}]}],
        ]
        with self.assertRaisesRegex(RuntimeError, "not unrestricted"):
            azure.check_subscription("eastus", "Standard_D2s_v5")
        self.assertEqual(command.call_count, 5)

    @mock.patch.object(azure, "azure_cli")
    def test_subscription_preflight_requires_both_core_quotas(self, command):
        command.side_effect = [
            {"id": "subscription", "state": "Enabled", "environmentName": "AzureCloud"},
            "Registered", "Registered", ["2025-11-01"],
            [{
                "restrictions": [], "family": "testFamily",
                "capabilities": [
                    {"name": "HyperVGenerations", "value": "V1,V2"},
                    {"name": "CpuArchitectureType", "value": "x64"},
                    {"name": "vCPUs", "value": "2"},
                ],
            }],
            [
                {"name": {"value": "cores"}, "limit": 100, "currentValue": 0},
                {"name": {"value": "testFamily"}, "limit": 1, "currentValue": 0},
            ],
        ]
        with self.assertRaisesRegex(RuntimeError, "Insufficient two-vCPU quota"):
            azure.check_subscription("westus2", "Standard_D2s_v5")

    def test_quota_counts_accept_cli_decimal_strings_without_silent_defaults(self):
        for value in (0, "0", 100, "100"):
            with self.subTest(value=value):
                self.assertEqual(azure.quota_count(value), int(value))
        for value in (None, True, -1, "-1", "unlimited", "1.5", 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    azure.quota_count(value)

    def test_unknown_serial_error_is_not_hidden_as_not_ready(self):
        run = self.run_fixture()
        result = mock.Mock(returncode=1, stderr="ERROR: (AuthorizationFailed) denied")
        run.az.side_effect = azure.AzureCliError(["vm", "boot-diagnostics"], result, True)
        with self.assertRaises(azure.AzureCliError):
            run.wait_for_boot("io", 10)
        self.assertEqual(run.az.call_count, 1)

    @mock.patch.object(azure, "check_subscription")
    @mock.patch.object(azure, "image_sha256", return_value="b" * 64)
    @mock.patch.object(azure, "load_state")
    def test_modified_image_is_rejected_before_any_cloud_call(self, load, digest, check):
        load.return_value = ({
            "phase": "prepared", "local_platform_boot": True,
            "image_sha256": "a" * 64,
        }, Path("/unused/state.json"))
        with self.assertRaisesRegex(ValueError, "changed since the local boot"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        check.assert_not_called()

    @mock.patch.object(azure, "check_subscription")
    @mock.patch.object(azure, "load_state")
    def test_partial_run_cannot_be_silently_resumed(self, load, check):
        load.return_value = ({
            "phase": "uploading-disk", "local_platform_boot": True,
        }, Path("/unused/state.json"))
        with self.assertRaisesRegex(ValueError, "newly prepared"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        check.assert_not_called()

    @mock.patch.object(azure, "check_subscription")
    @mock.patch.object(azure, "check_upload_dependencies", side_effect=RuntimeError("missing SDK"))
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_missing_upload_sdk_fails_before_cloud_calls(self, load, digest, dependencies, check):
        load.return_value = ({
            "phase": "prepared", "local_platform_boot": True,
            "image_sha256": "a" * 64,
        }, Path("/unused/state.json"))
        with self.assertRaisesRegex(RuntimeError, "missing SDK"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        check.assert_not_called()

    @mock.patch.object(azure, "save_json")
    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "check_subscription", return_value="subscription")
    @mock.patch.object(azure, "check_upload_dependencies")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_failed_run_cleans_owned_resources_by_default(
        self, load, digest, dependencies, check, constructor, save
    ):
        state = {
            "phase": "prepared", "local_platform_boot": True,
            "image_sha256": "a" * 64, "location": "westus2",
            "vm_size": "Standard_D2s_v5",
        }
        load.return_value = (state, Path("/unused/state.json"))
        run = constructor.return_value
        run.create_group.side_effect = lambda: state.update(phase="group-created")
        run.upload_disk.side_effect = RuntimeError("upload failed")
        with self.assertRaisesRegex(RuntimeError, "upload failed"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        run.cleanup.assert_called_once_with()
        run.deploy_vm.assert_not_called()

    @mock.patch.object(azure, "save_json")
    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "load_state")
    def test_local_only_preparation_cleanup_needs_no_subscription(self, load, constructor, save):
        state = {"phase": "preparing"}
        load.return_value = (state, Path("/unused/state.json"))
        azure.cleanup_state(Path("/unused"))
        self.assertEqual(state["phase"], "cleaned")
        azure.cleanup_state(Path("/unused"))
        constructor.assert_not_called()

    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "load_state")
    def test_cloud_cleanup_requires_complete_subscription_ownership(self, load, constructor):
        load.return_value = (
            {"phase": "creating-group"}, Path("/unused/state.json")
        )
        with self.assertRaisesRegex(ValueError, "subscription is missing"):
            azure.cleanup_state(Path("/unused"))
        constructor.assert_not_called()


class HypervWorkflowTest(unittest.TestCase):
    def test_bootstrap_uses_only_ubuntu_package_sources(self):
        workflow = (
            SUPPORT.parent / ".github/workflows/integration.yaml"
        ).read_text()
        job = workflow.split("  zig-hyperv:\n", 1)[1]
        header, body = job.split(
            "    - name: Install checkout, build, and OVMF dependencies\n"
            "      run: |\n",
            1,
        )
        self.assertIn("    runs-on: ubuntu-24.04\n", header)
        body = body.split("\n    - ", 1)[0]
        lines = body.splitlines()
        self.assertTrue(all(not line or line.startswith(" " * 8)
                            for line in lines))
        script = "\n".join(line[8:] for line in lines)
        self.assertIn(
            "test -s /etc/apt/sources.list.d/ubuntu.sources", script
        )
        self.assertIn(
            "-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources",
            script,
        )
        self.assertIn("-o Dir::Etc::sourceparts=-", script)
        self.assertIn('sudo apt-get "${ubuntu_apt[@]}" update', script)
        self.assertIn(
            'sudo apt-get "${ubuntu_apt[@]}" install -y '
            "--no-install-recommends", script,
        )
        for bypass in ("--allow-unauthenticated", "AllowInsecureRepositories",
                       "Check-Valid-Until=false", "trusted=yes"):
            self.assertNotIn(bypass, script)
        subprocess.run(
            ["bash", "-n"], input=script, text=True, check=True, timeout=10
        )


class HypervAzureNetworkReservationTest(unittest.TestCase):
    def reservation(self):
        return HypervAzureControllerTest.reservation()

    def write_reservation(self, root, value=None, mode=0o600):
        path = root / "reservation.json"
        path.write_text(json.dumps(value or self.reservation()))
        path.chmod(mode)
        return path

    @staticmethod
    def claim_receipt(run, reservation):
        return {
            "resource_group_id": reservation["resource_group_id"],
            "original_tags": reservation["tags"],
            "claim": {
                "claim_id": "c" * 32,
                "run_name_prefix": run.prefix,
                "image_sha256": run.state["image_sha256"],
                "prepared_manifest_sha256": (
                    run.state["prepared_image_import"]["manifest_sha256"]
                ),
            },
        }

    def test_private_reservation_requires_owner_only_strict_empty_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.write_reservation(root)
            self.assertEqual(
                azure.load_resource_group_reservation(path),
                self.reservation(),
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                azure.load_resource_group_reservation(path)
            path.chmod(0o600)
            value = self.reservation()
            value["unknown"] = "private"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "unknown or missing"):
                azure.load_resource_group_reservation(path)
            value.pop("unknown")
            value["resource_count"] = 1
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "not empty"):
                azure.load_resource_group_reservation(path)

    def test_private_reservation_rejects_symlink_and_opens_fifo_nonblocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.write_reservation(root)
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlink"):
                azure.load_resource_group_reservation(linked)

            fifo = root / "reservation.fifo"
            os.mkfifo(fifo, 0o600)
            real_open = azure.os.open

            def bounded_open(path, flags, *arguments):
                self.assertTrue(flags & os.O_NONBLOCK)
                return real_open(path, flags, *arguments)

            with mock.patch.object(azure.os, "open", side_effect=bounded_open):
                with self.assertRaisesRegex(ValueError, "owner-only"):
                    azure.load_resource_group_reservation(fifo)

    def test_live_reservation_claim_retags_only_exact_empty_group(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        reservation = self.reservation()
        state["reservation_claim"] = self.claim_receipt(run, reservation)
        original = {
            "id": reservation["resource_group_id"],
            "location": reservation["location"],
            "tags": reservation["tags"],
        }
        claimed = {**original, "tags": run.group_tags}
        run.az.side_effect = [original, [], claimed, claimed, []]
        run.claim_group_reservation(reservation)
        self.assertEqual(run.az.call_count, 5)
        run.record.assert_called_once_with("group-claimed")
        update = run.az.call_args_list[2].args[0]
        self.assertEqual(update[:4], [
            "group", "update", "--name", reservation["resource_group"],
        ])
        self.assertIn(
            "prepared-manifest-sha256=" + "b" * 64, update
        )

        run, state = fixture.network_run_fixture()
        state["reservation_claim"] = self.claim_receipt(run, reservation)
        changed = {**original, "tags": {**reservation["tags"], "other": "owner"}}
        run.az.return_value = changed
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            run.claim_group_reservation(reservation)
        self.assertEqual(run.az.call_count, 1)
        run.record.assert_not_called()

    def test_reservation_claim_is_exclusive_and_durably_consumed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_reservation(Path(temporary))
            entered = threading.Event()
            release = threading.Event()
            results = []

            def winner():
                with azure.ResourceGroupReservationClaim(path) as claim:
                    claim.bind("uk-hv-winner", "a" * 64, "b" * 64)
                    entered.set()
                    release.wait(5)
                    claim.mark_consumed()
                    results.append("winner")

            thread = threading.Thread(target=winner)
            thread.start()
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(RuntimeError, "already being claimed"):
                with azure.ResourceGroupReservationClaim(path):
                    pass
            release.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results, ["winner"])
            value = json.loads(path.read_text())
            self.assertEqual(value["phase"], "consumed")
            self.assertEqual(value["claim"]["run_name_prefix"], "uk-hv-winner")
            with self.assertRaises(ValueError):
                with azure.ResourceGroupReservationClaim(path):
                    pass

    def test_reservation_claim_rejects_symlink_and_fifo_lock_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.write_reservation(root)
            lock_path = path.with_name(path.name + ".lock")
            lock_path.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "private regular file"):
                with azure.ResourceGroupReservationClaim(path):
                    pass
            lock_path.unlink()
            os.mkfifo(lock_path, 0o600)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                with azure.ResourceGroupReservationClaim(path):
                    pass

    def test_crashed_claim_stays_bound_and_cannot_be_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_reservation(Path(temporary))
            pid = os.fork()
            if pid == 0:
                try:
                    with azure.ResourceGroupReservationClaim(path) as claim:
                        claim.bind("uk-hv-crashed", "a" * 64, "b" * 64)
                        os._exit(23)
                except BaseException:
                    os._exit(24)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 23)
            value = json.loads(path.read_text())
            self.assertEqual(value["phase"], "claiming")
            self.assertEqual(value["claim"]["run_name_prefix"], "uk-hv-crashed")
            with self.assertRaises(ValueError):
                with azure.ResourceGroupReservationClaim(path):
                    pass

    def test_cleanup_can_delete_exact_unclaimed_reservation_but_not_children(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        reservation = self.reservation()
        state["reservation_claim"] = {
            "resource_group_id": reservation["resource_group_id"],
            "original_tags": reservation["tags"],
        }
        state["phase"] = "claiming-reservation"
        group = {
            "id": reservation["resource_group_id"],
            "tags": reservation["tags"],
        }
        run.az.side_effect = [True, group, [], None, False]
        run.cleanup()
        self.assertEqual(run.record.call_args_list[-1].args[0], "cleaned")

        run, state = fixture.network_run_fixture()
        state["reservation_claim"] = {
            "resource_group_id": reservation["resource_group_id"],
            "original_tags": reservation["tags"],
        }
        state["phase"] = "claiming-reservation"
        run.az.side_effect = [
            True, group, [{"id": "/unexpected", "tags": reservation["tags"]}],
        ]
        with self.assertRaisesRegex(RuntimeError, "changed before its claim"):
            run.cleanup()

    def test_cleanup_requires_durable_peer_disk_creation_provenance(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["phase"] = "deploying-peer"
        group = {
            "id": state["resource_group_id"], "tags": run.group_tags,
        }
        disk_id = (
            state["resource_group_id"]
            + "/providers/Microsoft.Compute/disks/"
            + state["name_prefix"] + "-peer-os"
        )
        peer_vm_id = (
            state["resource_group_id"]
            + "/providers/Microsoft.Compute/virtualMachines/"
            + state["name_prefix"] + "-peer-vm"
        )
        resource = {
            "id": disk_id, "name": state["name_prefix"] + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": None,
        }
        peer_vm_uuid = "22222222-2222-4222-8222-222222222222"
        peer_disk_uuid = "33333333-3333-4333-8333-333333333333"
        peer_vm = {
            "id": peer_vm_id, "vmId": peer_vm_uuid, "tags": run.tags,
            "storageProfile": {
                "osDisk": {"managedDisk": {"id": disk_id}},
            },
        }
        disk = {
            **resource, "managedBy": peer_vm_id, "uniqueId": peer_disk_uuid,
        }

        run.az.side_effect = [True, group, [resource]]
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            run.cleanup()
        self.assertNotIn(
            ["group", "delete", "--name", run.group, "--yes"],
            [call.args[0] for call in run.az.call_args_list],
        )

        run, state = fixture.network_run_fixture()
        state["phase"] = "deploying-peer"
        state["peer_deployment"] = {
            "deployment_id": run.expected_resource_id(
                "Microsoft.Resources", "deployments", run.prefix + "-peer"
            ),
            "correlation_id": "11111111-1111-4111-8111-111111111111",
        }
        run.az.side_effect = [True, group, [resource]]
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            run.cleanup()

        for phase in (
            "peer-resources-verified", "peer-created",
            "waiting-for-peer-ready",
        ):
            with self.subTest(phase=phase):
                run, state = fixture.network_run_fixture()
                state["phase"] = phase
                state["peer_deployment"] = fixture.peer_receipt(run)
                vm_resource = {
                    "id": peer_vm_id, "name": run.peer_vm,
                    "type": "Microsoft.Compute/virtualMachines",
                    "tags": run.tags,
                }
                run.az.side_effect = [
                    True, group, [vm_resource, resource],
                    fixture.peer_deployment(run),
                    peer_vm, disk, None, None, False,
                ]
                run.cleanup()
                self.assertEqual(
                    run.az.call_args_list[-2].args[0][:2],
                    ["group", "delete"],
                )

    def test_cleanup_refuses_peer_vm_without_proven_os_disk(self):
        for partial_receipt in (False, True):
            with self.subTest(partial_receipt=partial_receipt):
                fixture = HypervAzureControllerTest()
                run, state = fixture.network_run_fixture()
                state["phase"] = (
                    "peer-deployment-succeeded" if partial_receipt
                    else "deploying-peer"
                )
                if partial_receipt:
                    state["peer_deployment"] = {
                        "deployment_id": run.expected_resource_id(
                            "Microsoft.Resources", "deployments",
                            run.prefix + "-peer",
                        ),
                        "correlation_id": "11111111-1111-4111-8111-111111111111",
                    }
                group = {
                    "id": state["resource_group_id"], "tags": run.group_tags,
                }
                peer_vm = {
                    "id": run.expected_resource_id(
                        "Microsoft.Compute", "virtualMachines", run.peer_vm,
                    ),
                    "name": run.peer_vm,
                    "type": "Microsoft.Compute/virtualMachines",
                    "tags": run.tags,
                }
                run.az.side_effect = [
                    True, group, [peer_vm], None, False,
                ]
                with self.assertRaisesRegex(RuntimeError, "detached or replaced"):
                    run.cleanup()
                self.assertFalse(any(
                    call.args[0][:2] == ["group", "delete"]
                    for call in run.az.call_args_list
                ))

    def test_cleanup_refuses_detached_or_replaced_peer_disk(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["phase"] = "peer-resources-verified"
        disk_id = run.expected_resource_id(
            "Microsoft.Compute", "disks", run.prefix + "-peer-os"
        )
        peer_vm_id = run.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", run.peer_vm
        )
        peer_vm_uuid = "22222222-2222-4222-8222-222222222222"
        peer_disk_uuid = "33333333-3333-4333-8333-333333333333"
        state["peer_deployment"] = fixture.peer_receipt(run)
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        resource = {
            "id": disk_id, "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": None,
        }
        peer_vm = {
            "id": peer_vm_id, "vmId": peer_vm_uuid, "tags": run.tags,
            "storageProfile": {
                "osDisk": {"managedDisk": {"id": disk_id}},
            },
        }
        disk = {
            **resource, "managedBy": peer_vm_id,
            "uniqueId": peer_disk_uuid,
        }
        vm_resource = {
            "id": peer_vm_id, "name": run.peer_vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        variants = (
            ({**peer_vm, "vmId": "44444444-4444-4444-8444-444444444444"},
             disk),
            (peer_vm, {**disk, "managedBy": None}),
            (peer_vm, {
                **disk,
                "uniqueId": "44444444-4444-4444-8444-444444444444",
            }),
        )
        for changed_vm, changed_disk in variants:
            with self.subTest(changed_vm=changed_vm, changed_disk=changed_disk):
                run.az.reset_mock()
                run.az.side_effect = [
                    True, group, [vm_resource, resource],
                    fixture.peer_deployment(run),
                    changed_vm, changed_disk,
                ]
                with self.assertRaisesRegex(RuntimeError, "detached or replaced"):
                    run.cleanup()

    @mock.patch.object(azure, "azure_cli")
    def test_network_preflight_pins_image_and_checks_combined_quota(self, command):
        subscription = "11111111-2222-3333-4444-555555555555"
        command.side_effect = [
            {
                "id": subscription, "state": "Enabled",
                "environmentName": "AzureCloud",
            },
            "Registered", "Registered", ["2025-11-01"],
            [{
                "restrictions": [], "family": "standardDSv5Family",
                "capabilities": [
                    {"name": "HyperVGenerations", "value": "V1,V2"},
                    {"name": "CpuArchitectureType", "value": "x64"},
                    {"name": "vCPUs", "value": "2"},
                ],
            }],
            [{
                "restrictions": [], "family": "standardBSFamily",
                "capabilities": [
                    {"name": "HyperVGenerations", "value": "V1,V2"},
                    {"name": "CpuArchitectureType", "value": "x64"},
                    {"name": "vCPUs", "value": "1"},
                ],
            }],
            [
                {
                    "urn": "Canonical:ubuntu-24_04-lts:server:24.04.202501010",
                    "version": "24.04.202501010",
                },
                {
                    "urn": "Canonical:ubuntu-24_04-lts:server:24.04.202601010",
                    "version": "24.04.202601010",
                },
            ],
            {"architecture": "x64", "hyperVGeneration": "V1"},
            [
                {"name": {"value": "cores"}, "limit": 10, "currentValue": 0},
                {
                    "name": {"value": "standardDSv5Family"},
                    "limit": 2, "currentValue": 0,
                },
                {
                    "name": {"value": "standardBSFamily"},
                    "limit": 1, "currentValue": 0,
                },
            ],
        ]
        result = azure.check_network_subscription(
            "northeurope", "Standard_D2s_v5", subscription
        )
        self.assertEqual(
            result["peer_image"]["version"], "24.04.202601010"
        )
        self.assertEqual(result["peer_image"]["hyperv_generation"], "V1")
        self.assertTrue(all(
            call.kwargs["subscription"] == subscription
            for call in command.call_args_list
        ))

    def test_templates_have_no_public_ip_and_reuse_the_static_guest_nic(self):
        peer = json.loads(
            (SUPPORT / "azure" / "hyperv-network-peer.json").read_text()
        )
        guest = json.loads(
            (SUPPORT / "azure" / "hyperv-gen2.json").read_text()
        )
        peer_text = json.dumps(peer)
        self.assertNotIn("publicIPAddresses", peer_text)
        self.assertIn('"defaultOutboundAccess": false', peer_text)
        self.assertEqual(
            peer["parameters"]["adminPassword"]["type"], "secureString"
        )
        self.assertIn("peerImageVersion", peer["parameters"])
        self.assertEqual(
            peer["outputs"]["peerVmUuid"]["value"],
            "[reference(variables('peerVmName'), '2025-11-01').vmId]",
        )
        self.assertEqual(
            modeled_implicit_disk_output_order(
                peer, "peerVmName", "peerIdentityDeploymentName",
                "peerDiskUuid", "peerDiskUuid",
            ),
            ("vm-created", "implicit-disk-read", "outer-output"),
        )
        self.assertEqual(
            peer["outputs"]["peerDiskId"]["value"],
            "[reference(variables('peerIdentityDeploymentName'), "
            "'2022-09-01').outputs.peerDiskId.value]",
        )
        direct = copy.deepcopy(peer)
        direct["outputs"]["peerDiskUuid"]["value"] = (
            "[reference(resourceId('Microsoft.Compute/disks', "
            "concat(parameters('namePrefix'), '-peer-os')), "
            "'2025-01-02').uniqueId]"
        )
        with self.assertRaisesRegex(RuntimeError, "ResourceNotFound"):
            modeled_implicit_disk_output_order(
                direct, "peerVmName", "peerIdentityDeploymentName",
                "peerDiskUuid", "peerDiskUuid",
            )
        unordered = copy.deepcopy(peer)
        identity = next(
            resource for resource in unordered["resources"]
            if resource["type"] == "Microsoft.Resources/deployments"
        )
        identity["dependsOn"] = []
        with self.assertRaisesRegex(RuntimeError, "ResourceNotFound"):
            modeled_implicit_disk_output_order(
                unordered, "peerVmName", "peerIdentityDeploymentName",
                "peerDiskUuid", "peerDiskUuid",
            )
        self.assertIn("existingNicId", guest["parameters"])
        self.assertEqual(
            guest["outputs"]["vmUuid"]["value"],
            "[reference(variables('vmName'), '2025-11-01').vmId]",
        )
        self.assertEqual(
            guest["outputs"]["osDiskId"]["value"],
            "[parameters('osDiskId')]",
        )
        guest_vm = next(
            resource for resource in guest["resources"]
            if resource["type"] == "Microsoft.Compute/virtualMachines"
        )
        self.assertIn(
            "parameters('existingNicId')",
            json.dumps(guest_vm["properties"]["networkProfile"]),
        )

    def test_peer_deployment_keeps_password_and_cloud_init_out_of_cli(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        peer_image = {
            "publisher": "Canonical", "offer": "ubuntu-24_04-lts",
            "sku": "server", "version": "24.04.202601010",
        }
        peer_vm_id = run.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", run.peer_vm
        )
        peer_disk_id = run.expected_resource_id(
            "Microsoft.Compute", "disks", run.prefix + "-peer-os"
        )
        deployment = HypervAzureControllerTest.peer_deployment(run)
        peer_vm = {
            "id": peer_vm_id,
            "vmId": "22222222-2222-4222-8222-222222222222",
            "tags": run.tags,
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": peer_image,
                "osDisk": {"managedDisk": {"id": peer_disk_id}},
            },
        }
        peer_disk = {
            "id": peer_disk_id,
            "uniqueId": "33333333-3333-4333-8333-333333333333",
            "tags": None,
            "managedBy": peer_vm_id,
        }

        def nic(identifier, address):
            return {
                "id": identifier, "tags": run.tags,
                "ipConfigurations": [{
                    "privateIPAddress": address,
                    "privateIPAllocationMethod": "Static",
                    "publicIPAddress": None,
                }],
            }

        run.az.side_effect = [
            deployment, peer_vm, peer_disk, peer_vm, peer_disk,
            nic("/peer-nic", "10.87.0.4"),
            nic("/guest-nic", "10.87.0.5"),
        ]
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **fields
        )
        captured = {}

        @azure.contextmanager
        def parameters(values):
            captured.update(values)
            yield Path("/private/parameters.json")

        run.private_parameters = parameters
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            run.deploy_network_peer(
                state["network_run"], peer_image, 400
            )
        command = run.az.call_args_list[0].args[0]
        self.assertIn("@/private/parameters.json", command)
        self.assertNotIn(captured["adminPassword"], " ".join(command))
        self.assertNotIn(captured["peerCustomData"], " ".join(command))
        self.assertRegex(captured["adminPassword"], r"[A-Z].*[a-z].*[!].*[0-9]")
        self.assertEqual(state["guest_nic_id"], "/guest-nic")
        self.assertEqual(
            state["peer_deployment"]["peer_disk_uuid"],
            "33333333-3333-4333-8333-333333333333",
        )
        self.assertFalse(any(
            call.args[0][:2] == ["disk", "update"]
            for call in run.az.call_args_list
        ))

    def test_peer_deployment_persists_identity_before_updating_becomes_ready(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        peer_image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        receipt = fixture.peer_receipt(run)
        extra_tags = {**run.tags, "fixture-extra": "retained"}
        peer_vm = {
            "id": receipt["peer_vm_id"], "vmId": receipt["peer_vm_uuid"],
            "tags": extra_tags,
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": peer_image,
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        peer_disk = {
            "id": receipt["peer_disk_id"],
            "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"],
            "tags": extra_tags,
        }

        def nic(identifier, address):
            return {
                "id": identifier, "tags": extra_tags,
                "ipConfigurations": [{
                    "privateIPAddress": address,
                    "privateIPAllocationMethod": "Static",
                    "publicIPAddress": None,
                }],
            }

        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **fields
        )

        @azure.contextmanager
        def parameters(_):
            yield Path("/private/parameters.json")

        run.private_parameters = parameters
        run.az.side_effect = [
            fixture.peer_deployment(run),
            {**peer_vm, "provisioningState": "Updating"},
            peer_disk,
            {**peer_vm, "provisioningState": "Succeeded"},
            peer_disk,
            nic("/peer-nic", "10.87.0.4"),
            nic("/guest-nic", "10.87.0.5"),
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100), \
                mock.patch.object(azure.time, "sleep"):
            run.deploy_network_peer(state["network_run"], peer_image, 700)
        self.assertEqual(state["phase"], "peer-created")
        self.assertEqual(state["peer_deployment"], receipt)
        phases = [call.args[0] for call in run.record.call_args_list]
        self.assertLess(
            phases.index("peer-resources-verified"),
            phases.index("peer-created"),
        )

    def test_peer_deployment_anchor_blocks_replacement_after_disk_read_failure(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        receipt = fixture.peer_receipt(run)
        deployment = fixture.peer_deployment(run)
        vm = {
            "id": receipt["peer_vm_id"], "name": run.peer_vm,
            "type": "Microsoft.Compute/virtualMachines",
            "vmId": receipt["peer_vm_uuid"], "tags": run.tags,
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": image,
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        disk = {
            "id": receipt["peer_disk_id"],
            "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": run.tags,
            "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"],
        }
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )

        @azure.contextmanager
        def parameters(_):
            yield Path("/private/parameters.json")

        run.private_parameters = parameters
        run.az.side_effect = [
            deployment, vm, RuntimeError("fixture disk read unavailable"),
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "disk read unavailable"):
                run.deploy_network_peer(state["network_run"], image, 700)
        self.assertEqual(state["peer_deployment"], receipt)

        replacement = {
            **vm, "vmId": "44444444-4444-4444-8444-444444444444",
        }
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        run.az.reset_mock()
        run.az.side_effect = [
            True, group, [replacement, disk], deployment, replacement,
        ]
        with self.assertRaisesRegex(
            RuntimeError, "detached or replaced|proven identity"
        ):
            run.cleanup()
        self.assertEqual(
            state["peer_deployment"]["peer_vm_uuid"],
            receipt["peer_vm_uuid"],
        )
        self.assertFalse(any(
            call.args[0][:2] in (
                ["vm", "deallocate"], ["group", "delete"],
            )
            for call in run.az.call_args_list
        ))

    def test_peer_readiness_rejects_success_after_disk_query_deadline(self):
        fixture = HypervAzureControllerTest()
        run, _ = fixture.network_run_fixture()
        receipt = fixture.peer_receipt(run)
        image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        vm = {
            "id": receipt["peer_vm_id"], "vmId": receipt["peer_vm_uuid"],
            "tags": run.tags, "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": image,
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        disk = {
            "id": receipt["peer_disk_id"],
            "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"], "tags": run.tags,
        }
        clock = [100.0]

        def command(arguments, **_):
            if arguments[:2] == ["vm", "show"]:
                return vm
            if arguments[:2] == ["disk", "show"]:
                clock[0] = 102.0
                return disk
            self.fail(f"Unexpected mocked command: {arguments[:3]}")

        run.az.side_effect = command
        with mock.patch.object(
            azure.time, "monotonic", side_effect=lambda: clock[0]
        ):
            with self.assertRaisesRegex(RuntimeError, "provisioning readiness"):
                run.wait_for_peer_provisioning(image, receipt, 101.0)

    def test_peer_nic_queries_remain_within_original_deadline(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        receipt = fixture.peer_receipt(run)
        deployment = fixture.peer_deployment(run)
        image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        vm = {
            "id": receipt["peer_vm_id"], "vmId": receipt["peer_vm_uuid"],
            "tags": run.tags, "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": image,
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        disk = {
            "id": receipt["peer_disk_id"],
            "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"], "tags": run.tags,
        }
        nic = {
            "id": "/fixture/peer-nic", "tags": run.tags,
            "ipConfigurations": [{
                "privateIPAddress": "10.87.0.4",
                "privateIPAllocationMethod": "Static",
                "publicIPAddress": None,
            }],
        }
        clock = [100.0]
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **copy.deepcopy(fields)
        )

        @azure.contextmanager
        def parameters(_):
            yield Path("/private/parameters.json")

        run.private_parameters = parameters

        def command(arguments, **_):
            if arguments[:3] == ["deployment", "group", "create"]:
                return deployment
            if arguments[:2] == ["vm", "show"]:
                return vm
            if arguments[:2] == ["disk", "show"]:
                return disk
            if arguments[:3] == ["network", "nic", "show"]:
                clock[0] = 102.0
                return nic
            self.fail(f"Unexpected mocked command: {arguments[:3]}")

        run.az.side_effect = command
        with mock.patch.object(
            azure.time, "monotonic", side_effect=lambda: clock[0]
        ):
            with self.assertRaisesRegex(
                RuntimeError, "network interface inspection"
            ):
                run.deploy_network_peer(state["network_run"], image, 101.0)
        self.assertEqual(state["phase"], "peer-resources-verified")
        self.assertNotIn("peer_vm_id", state)

    def test_network_boot_log_query_cannot_cross_original_deadline(self):
        fixture = HypervAzureControllerTest()
        run, _ = fixture.network_run_fixture()
        clock = [100.0]

        def command(_arguments, **_kwargs):
            clock[0] = 102.0
            return "fixture serial"

        run.az.side_effect = command
        with mock.patch.object(
            azure.time, "monotonic", side_effect=lambda: clock[0]
        ):
            with self.assertRaisesRegex(
                RuntimeError, "boot diagnostics query"
            ):
                run.network_boot_log(run.peer_vm, 101.0)

    def test_peer_readiness_deadline_retains_recoverable_identity(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        peer_image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        receipt = fixture.peer_receipt(run)
        peer_vm = {
            "id": receipt["peer_vm_id"], "vmId": receipt["peer_vm_uuid"],
            "tags": run.tags, "provisioningState": "Updating",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": peer_image,
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        peer_disk = {
            "id": receipt["peer_disk_id"],
            "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"], "tags": run.tags,
        }
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **fields
        )

        @azure.contextmanager
        def parameters(_):
            yield Path("/private/parameters.json")

        run.private_parameters = parameters
        run.az.side_effect = [
            fixture.peer_deployment(run), peer_vm, peer_disk,
            peer_vm, peer_disk,
        ]
        clock = iter((100, 100, 100, 100, 102, 102))
        with mock.patch.object(
            azure.time, "monotonic", side_effect=lambda: next(clock)
        ), mock.patch.object(azure.time, "sleep"):
            with self.assertRaisesRegex(
                RuntimeError, "expired|provisioning readiness"
            ):
                run.deploy_network_peer(state["network_run"], peer_image, 101)
        self.assertEqual(state["phase"], "peer-deployment-succeeded")
        self.assertEqual(state["peer_deployment"], receipt)

    def test_peer_receipt_accepts_five_leaf_resources_and_nested_outputs(self):
        fixture = HypervAzureControllerTest()
        run, _ = fixture.network_run_fixture()
        receipt = fixture.peer_receipt(run)
        deployment = fixture.peer_deployment(run)
        output_resources = deployment["properties"]["outputResources"]
        self.assertEqual(
            output_resources,
            [
                {"id": identifier}
                for identifier in fixture.peer_declared_ids(run)
            ],
        )
        self.assertEqual(len(output_resources), 5)
        self.assertNotIn(
            run.prefix + "-peer-identity", json.dumps(output_resources)
        )
        self.assertEqual(
            deployment["properties"]["outputs"]["peerVmUuid"]["value"],
            receipt["peer_vm_uuid"],
        )
        self.assertEqual(
            deployment["properties"]["outputs"]["peerDiskUuid"]["value"],
            receipt["peer_disk_uuid"],
        )
        self.assertEqual(run.peer_deployment_receipt(deployment), receipt)

    def test_peer_terminal_state_and_foreign_deployment_output_are_rejected(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        peer_image = {
            "publisher": "ExamplePublisher", "offer": "test-offer",
            "sku": "test-sku", "version": "1.2.3",
        }
        receipt = fixture.peer_receipt(run)
        peer_vm = {
            "id": receipt["peer_vm_id"], "vmId": receipt["peer_vm_uuid"],
            "tags": run.tags, "provisioningState": "Failed",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": peer_image,
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        peer_disk = {
            "id": receipt["peer_disk_id"],
            "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"], "tags": run.tags,
        }
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **fields
        )

        @azure.contextmanager
        def parameters(_):
            yield Path("/private/parameters.json")

        run.private_parameters = parameters
        run.az.side_effect = [
            fixture.peer_deployment(run), peer_vm, peer_disk,
            peer_vm, peer_disk,
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "terminal"):
                run.deploy_network_peer(
                    state["network_run"], peer_image, 700
                )
        self.assertEqual(state["phase"], "peer-resources-verified")
        self.assertEqual(state["peer_deployment"], receipt)

        deployment = fixture.peer_deployment(run)
        deployment["properties"]["outputResources"].append({
            "id": state["resource_group_id"]
            + "/providers/Example.Provider/widgets/foreign",
        })
        with self.assertRaisesRegex(RuntimeError, "resource provenance"):
            run.peer_deployment_receipt(deployment)

        deployment = fixture.peer_deployment(run)
        del deployment["properties"]["outputs"]["peerDiskUuid"]
        with self.assertRaisesRegex(RuntimeError, "disk UUID.*unavailable"):
            run.peer_deployment_receipt(deployment)

        deployment = fixture.peer_deployment(run)
        deployment["properties"]["provisioningState"] = "Failed"
        del deployment["properties"]["outputs"]
        with self.assertRaisesRegex(RuntimeError, "provenance is invalid"):
            run.peer_deployment_receipt(deployment)

    def test_cleanup_revalidates_original_peer_deployment_outputs(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        receipt = fixture.peer_receipt(run)
        state["peer_deployment"] = receipt
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        vm_resource = {
            "id": receipt["peer_vm_id"], "name": run.peer_vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        disk_resource = {
            "id": receipt["peer_disk_id"],
            "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": run.tags,
        }
        changed = fixture.peer_deployment(run)
        changed["properties"]["outputs"]["peerVmUuid"]["value"] = (
            "44444444-4444-4444-8444-444444444444"
        )
        run.az.side_effect = [
            True, group, [vm_resource, disk_resource], changed,
        ]
        with self.assertRaisesRegex(RuntimeError, "deployment changed"):
            run.cleanup()
        self.assertFalse(any(
            call.args[0][:2] in (
                ["vm", "deallocate"], ["group", "delete"],
            )
            for call in run.az.call_args_list
        ))

    def test_cleanup_accepts_only_exact_owned_peer_vm_extensions(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        receipt = fixture.peer_receipt(run)
        state.update(
            phase="peer-resources-verified",
            peer_deployment=receipt,
            network_preflight={"peer_image": {
                "publisher": "ExamplePublisher", "offer": "test-offer",
                "sku": "test-sku", "version": "1.2.3",
            }},
        )
        extra_tags = {**run.tags, "fixture-extra": "retained"}
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        vm_resource = {
            "id": receipt["peer_vm_id"], "name": run.peer_vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": extra_tags,
        }
        disk_resource = {
            "id": receipt["peer_disk_id"],
            "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": extra_tags,
        }
        extension = {
            "id": receipt["peer_vm_id"] + "/extensions/fixture-agent",
            "name": run.peer_vm + "/fixture-agent",
            "type": "Microsoft.Compute/virtualMachines/extensions",
            "tags": None,
        }
        tagged_extension = {
            **extension,
            "id": receipt["peer_vm_id"] + "/extensions/fixture-monitor",
            "name": run.peer_vm + "/fixture-monitor",
            "tags": extra_tags,
        }
        peer_vm = {
            **vm_resource, "vmId": receipt["peer_vm_uuid"],
            "provisioningState": "Updating",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": state["network_preflight"]["peer_image"],
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        peer_disk = {
            **disk_resource, "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"],
        }
        run.az.side_effect = [
            True, group, [
                vm_resource, disk_resource, extension, tagged_extension,
            ],
            fixture.peer_deployment(run),
            peer_vm, peer_disk, None, None, False,
        ]
        run.cleanup()
        self.assertIn(
            ["vm", "deallocate", "--resource-group", run.group,
             "--name", run.peer_vm, "--no-wait"],
            [call.args[0] for call in run.az.call_args_list],
        )

        invalid = (
            {
                **extension,
                "id": receipt["peer_vm_id"] + "/diagnostics/unknown",
                "type": "Microsoft.Compute/virtualMachines/diagnostics",
            },
            {
                **extension,
                "id": state["resource_group_id"]
                + "/providers/Microsoft.Compute/virtualMachines/"
                "other-vm/extensions/fixture-agent",
            },
            {
                "id": state["resource_group_id"]
                + "/providers/Example.Provider/widgets/unknown",
                "name": "unknown", "type": "Example.Provider/widgets",
                "tags": run.tags,
            },
            {
                **tagged_extension,
                "tags": {"fixture-extra": "not-owned"},
            },
        )
        for resource in invalid:
            with self.subTest(resource=resource):
                run.az.reset_mock()
                run.az.side_effect = [
                    True, group, [vm_resource, disk_resource, resource],
                    fixture.peer_deployment(run),
                    peer_vm, peer_disk, None,
                ]
                with self.assertRaisesRegex(RuntimeError, "unproven resource"):
                    run.cleanup()

    def test_cleanup_never_enrolls_partial_peer_identity(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        receipt = fixture.peer_receipt(run)
        state.update(
            phase="peer-deployment-succeeded",
            peer_deployment=fixture.peer_receipt(run, complete=False),
            network_preflight={"peer_image": {
                "publisher": "ExamplePublisher", "offer": "test-offer",
                "sku": "test-sku", "version": "1.2.3",
            }},
        )
        group = {"id": state["resource_group_id"], "tags": run.group_tags}
        vm_resource = {
            "id": receipt["peer_vm_id"], "name": run.peer_vm,
            "type": "Microsoft.Compute/virtualMachines", "tags": run.tags,
        }
        disk_resource = {
            "id": receipt["peer_disk_id"],
            "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": run.tags,
        }
        peer_vm = {
            **vm_resource, "vmId": receipt["peer_vm_uuid"],
            "provisioningState": "Updating",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": state["network_preflight"]["peer_image"],
                "osDisk": {"managedDisk": {"id": receipt["peer_disk_id"]}},
            },
        }
        peer_disk = {
            **disk_resource, "uniqueId": receipt["peer_disk_uuid"],
            "managedBy": receipt["peer_vm_id"],
        }
        run.az.side_effect = [
            True, group, [vm_resource, disk_resource],
        ]
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            run.cleanup()
        self.assertNotIn("peer_vm_uuid", state["peer_deployment"])
        self.assertFalse(any(
            call.args[0][:2] in (
                ["vm", "deallocate"], ["group", "delete"],
            )
            for call in run.az.call_args_list
        ))

        run, state = fixture.network_run_fixture()
        state.update(
            phase="peer-deployment-succeeded",
            peer_deployment={
                "deployment_id": receipt["deployment_id"],
                "declared_resource_ids": receipt["declared_resource_ids"],
            },
        )
        run.az.side_effect = [True, group, [vm_resource, disk_resource]]
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            run.cleanup()

    def test_replaced_peer_disk_with_run_tags_still_blocks_cleanup(self):
        fixture = HypervAzureControllerTest()
        run, state = fixture.network_run_fixture()
        state["network_run"] = azure.network.private_network(
            state["acceptance"], "10.87.0.5", "10.87.0.0/29"
        )
        peer_image = {
            "publisher": "Canonical", "offer": "ubuntu-24_04-lts",
            "sku": "server", "version": "24.04.202601010",
        }
        peer_vm_id = run.expected_resource_id(
            "Microsoft.Compute", "virtualMachines", run.peer_vm
        )
        peer_disk_id = run.expected_resource_id(
            "Microsoft.Compute", "disks", run.prefix + "-peer-os"
        )
        original_uuid = "33333333-3333-4333-8333-333333333333"
        replacement_uuid = "44444444-4444-4444-8444-444444444444"
        deployment = HypervAzureControllerTest.peer_deployment(run)
        peer_vm = {
            "id": peer_vm_id,
            "vmId": "22222222-2222-4222-8222-222222222222",
            "tags": run.tags,
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {
                "imageReference": peer_image,
                "osDisk": {"managedDisk": {"id": peer_disk_id}},
            },
        }
        original_disk = {
            "id": peer_disk_id, "name": run.prefix + "-peer-os",
            "type": "Microsoft.Compute/disks", "tags": None,
            "managedBy": peer_vm_id, "uniqueId": original_uuid,
        }
        replacement_disk = {
            **original_disk, "tags": run.tags,
            "uniqueId": replacement_uuid,
        }
        run.record.side_effect = lambda phase, **fields: state.update(
            phase=phase, **fields
        )

        @azure.contextmanager
        def parameters(_):
            yield Path("/private/parameters.json")

        run.private_parameters = parameters
        run.az.side_effect = [
            deployment, peer_vm, original_disk, peer_vm, replacement_disk,
        ]
        with mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "detached or replaced"):
                run.deploy_network_peer(
                    state["network_run"], peer_image, 400
                )
        self.assertEqual(
            state["peer_deployment"]["peer_disk_uuid"], original_uuid
        )
        self.assertFalse(any(
            call.args[0][:2] == ["disk", "update"]
            for call in run.az.call_args_list
        ))

        group = {
            "id": state["resource_group_id"], "tags": run.group_tags,
        }
        resources = [
            {
                "id": peer_vm_id, "name": run.peer_vm,
                "type": "Microsoft.Compute/virtualMachines",
                "tags": run.tags,
            },
            replacement_disk,
        ]
        run.az.reset_mock()
        run.az.side_effect = [
            True, group, resources, fixture.peer_deployment(run),
            peer_vm, replacement_disk,
        ]
        with self.assertRaisesRegex(RuntimeError, "detached or replaced"):
            run.cleanup()
        self.assertFalse(any(
            call.args[0][:2] == ["group", "delete"]
            for call in run.az.call_args_list
        ))

    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "check_network_subscription")
    @mock.patch.object(azure, "check_upload_dependencies")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_network_run_orders_peer_ready_before_guest_and_always_cleans(
        self, load, digest, dependencies, preflight, constructor
    ):
        state = {
            "phase": "prepared", "image_sha256": "a" * 64,
            "location": "northeurope", "vm_size": "Standard_D2s_v5",
            "acceptance": HypervAzureControllerTest.network_acceptance(),
            "prepared_image_import": {
                "contract": azure.PREPARED_IMAGE_SCHEMA,
                "manifest_sha256": "b" * 64,
                "source": HypervAzurePreparedImageTransferTest.source(),
            },
        }
        load.return_value = (state, Path("/unused/state.json"))
        preflight.return_value = {
            "subscription": "11111111-2222-3333-4444-555555555555",
            "peer_image": {"version": "24.04.202601010"},
        }
        run = constructor.return_value
        order = []
        run.create_group.side_effect = lambda: (
            order.append("group"), state.update(phase="group-created")
        )
        run.upload_disk.side_effect = lambda _: order.append("upload")

        def deploy_peer(*_):
            order.append("peer")
            state["guest_nic_id"] = "/guest-nic"

        run.deploy_network_peer.side_effect = deploy_peer
        run.wait_for_peer_ready.side_effect = lambda _: order.append("ready")
        run.deploy_vm.side_effect = lambda *_: order.append("guest")
        run.wait_for_network_acceptance.side_effect = (
            lambda _: order.append("evidence") or {"result": "PASS"}
        )
        run.cleanup.side_effect = lambda: order.append("cleanup")
        with mock.patch.object(azure, "validate_prepared_run_provenance"), \
                mock.patch.object(azure, "save_json"), \
                mock.patch.object(azure.time, "monotonic", return_value=100):
            result = azure.run_prepared(
                Path("/unused"), "io", 600, False,
                subscription="11111111-2222-3333-4444-555555555555",
                guest_ipv4="10.87.0.5", subnet="10.87.0.0/29",
            )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(
            order,
            ["group", "upload", "peer", "ready", "guest", "evidence", "cleanup"],
        )

        order.clear()
        state["phase"] = "prepared"
        run.wait_for_peer_ready.side_effect = RuntimeError("bad READY")
        with mock.patch.object(azure, "validate_prepared_run_provenance"), \
                mock.patch.object(azure, "save_json"), \
                mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "bad READY"):
                azure.run_prepared(
                    Path("/unused"), "io", 600, False,
                    subscription="11111111-2222-3333-4444-555555555555",
                    guest_ipv4="10.87.0.5", subnet="10.87.0.0/29",
                )
        run.cleanup.assert_called()

        state["phase"] = "prepared"
        private_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        private_endpoint = "https://fixture.invalid/private?credential=secret"
        private_group = "fixture-private-group"
        run.private_failure_values.return_value = {private_group}
        run.wait_for_peer_ready.side_effect = RuntimeError(
            f"primary failure {private_uuid} {private_endpoint} {private_group}"
        )
        run.cleanup.side_effect = RuntimeError(
            f"cleanup failure /subscriptions/{private_uuid}/resourceGroups/private"
        )
        with mock.patch.object(azure, "validate_prepared_run_provenance"), \
                mock.patch.object(azure, "save_json"), \
                mock.patch.object(azure.time, "monotonic", return_value=100):
            with self.assertRaises(azure.RunCleanupError) as raised:
                azure.run_prepared(
                    Path("/unused"), "io", 600, False,
                    subscription="11111111-2222-3333-4444-555555555555",
                    guest_ipv4="10.87.0.5", subnet="10.87.0.0/29",
                )
        message = str(raised.exception)
        self.assertIn("primary failure", message)
        self.assertIn("cleanup also failed", message)
        self.assertNotIn(private_uuid, message)
        self.assertNotIn(private_endpoint, message)
        self.assertNotIn(private_group, message)
        rendered = "".join(traceback.format_exception(raised.exception))
        self.assertNotIn(private_uuid, rendered)
        self.assertNotIn(private_endpoint, rendered)
        failure_record = run.record.call_args
        self.assertEqual(failure_record.args[0], "cleanup-failed")
        self.assertNotIn(
            private_uuid,
            json.dumps(failure_record.kwargs, sort_keys=True),
        )

    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "check_upload_dependencies")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "validate_prepared_run_provenance")
    def test_reservation_is_durably_bound_before_cloud_preflight(
        self, provenance, digest, dependencies, constructor
    ):
        del provenance, digest, dependencies
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reservation_path = self.write_reservation(root)
            state_path = root / "state.json"
            state = {
                "phase": "prepared", "name_prefix": "uk-hv-bound-run",
                "image_sha256": "a" * 64, "location": "northeurope",
                "vm_size": "Standard_D2s_v5",
                "acceptance": HypervAzureControllerTest.network_acceptance(),
                "prepared_image_import": {
                    "contract": azure.PREPARED_IMAGE_SCHEMA,
                    "manifest_sha256": "b" * 64,
                    "source": HypervAzurePreparedImageTransferTest.source(),
                },
            }
            run = constructor.return_value
            run.claim_group_reservation.side_effect = lambda _: state.update(
                phase="group-claimed"
            )
            run.deploy_network_peer.side_effect = lambda *_: state.update(
                guest_nic_id="/guest-nic"
            )
            run.wait_for_network_acceptance.return_value = {"result": "PASS"}

            def preflight(*_arguments):
                private_reservation = json.loads(reservation_path.read_text())
                private_state = json.loads(state_path.read_text())
                self.assertEqual(private_reservation["phase"], "claiming")
                self.assertEqual(
                    private_reservation["claim"]["run_name_prefix"],
                    state["name_prefix"],
                )
                self.assertEqual(private_state["phase"], "claiming-reservation")
                self.assertEqual(
                    private_state["reservation_claim"]["claim"],
                    private_reservation["claim"],
                )
                return {
                    "subscription": self.reservation()["subscription"],
                    "peer_image": {"version": "24.04.202601010"},
                }

            with mock.patch.object(
                azure, "load_state", return_value=(state, state_path)
            ), mock.patch.object(
                azure, "check_network_subscription", side_effect=preflight
            ), mock.patch.object(azure.time, "monotonic", return_value=100):
                result = azure.run_prepared(
                    root, "io", 600, False,
                    resource_group_reservation=reservation_path,
                    guest_ipv4="10.87.0.5", subnet="10.87.0.0/29",
                )
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(
                json.loads(reservation_path.read_text())["phase"], "consumed"
            )
            run.cleanup.assert_called_once_with()

    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(
        azure, "check_network_subscription",
        side_effect=RuntimeError("preflight failed"),
    )
    @mock.patch.object(azure, "check_upload_dependencies")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "validate_prepared_run_provenance")
    def test_bound_reservation_preflight_failure_invokes_cleanup(
        self, provenance, digest, dependencies, preflight, constructor
    ):
        del provenance, digest, dependencies, preflight
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reservation_path = self.write_reservation(root)
            state = {
                "phase": "prepared", "name_prefix": "uk-hv-failed-run",
                "image_sha256": "a" * 64, "location": "northeurope",
                "vm_size": "Standard_D2s_v5",
                "acceptance": HypervAzureControllerTest.network_acceptance(),
                "prepared_image_import": {
                    "contract": azure.PREPARED_IMAGE_SCHEMA,
                    "manifest_sha256": "b" * 64,
                    "source": HypervAzurePreparedImageTransferTest.source(),
                },
            }
            with mock.patch.object(
                azure, "load_state",
                return_value=(state, root / "state.json"),
            ):
                with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                    azure.run_prepared(
                        root, "io", 600, False,
                        resource_group_reservation=reservation_path,
                        guest_ipv4="10.87.0.5", subnet="10.87.0.0/29",
                    )
            self.assertEqual(
                json.loads(reservation_path.read_text())["phase"], "claiming"
            )
            constructor.return_value.cleanup.assert_called_once_with()

    @mock.patch.object(azure, "check_upload_dependencies")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_network_run_rejects_keep_resources_before_cloud(
        self, load, digest, dependencies
    ):
        load.return_value = ({
            "phase": "prepared", "image_sha256": "a" * 64,
            "location": "northeurope", "vm_size": "Standard_D2s_v5",
            "acceptance": HypervAzureControllerTest.network_acceptance(),
            "prepared_image_import": {
                "contract": azure.PREPARED_IMAGE_SCHEMA,
                "manifest_sha256": "b" * 64,
                "source": HypervAzurePreparedImageTransferTest.source(),
            },
        }, Path("/unused/state.json"))
        with mock.patch.object(azure, "validate_prepared_run_provenance"):
            with self.assertRaisesRegex(ValueError, "mandatory cleanup"):
                azure.run_prepared(
                    Path("/unused"), "io", 600, True,
                    subscription="11111111-2222-3333-4444-555555555555",
                    guest_ipv4="10.87.0.5", subnet="10.87.0.0/29",
                )
        dependencies.assert_not_called()


class HypervAzureEvidenceTest(unittest.TestCase):
    def complete_log(self):
        return "\n".join((
            azure.PLATFORM_READY, azure.BLOCK_READY,
            azure.NETWORK_READY, azure.IO_READY,
        ))

    def test_all_stages_are_required_for_io(self):
        self.assertTrue(azure.inspect_boot_log(self.complete_log())["io_ready"])
        for marker in (
            azure.PLATFORM_READY, azure.BLOCK_READY,
            azure.NETWORK_READY, azure.IO_READY,
        ):
            with self.subTest(marker=marker):
                text = self.complete_log().replace(marker, "")
                self.assertFalse(azure.inspect_boot_log(text)["io_ready"])

    def test_embedded_marker_does_not_establish_acceptance(self):
        result = azure.inspect_boot_log(f"Looking for {azure.PLATFORM_READY}")
        self.assertFalse(result["platform_ready"])

    def test_custom_application_marker_only_establishes_platform_boot(self):
        result = azure.inspect_boot_log("Hello world!\n", "Hello world!")
        self.assertTrue(result["platform_ready"])
        self.assertFalse(result["io_ready"])

    def test_firmware_escape_sequences_and_nuls_are_supported(self):
        text = "\x1b[2J" + self.complete_log().replace("\n", "\0\r\n")
        self.assertTrue(azure.inspect_boot_log(text)["io_ready"])

    def test_final_marker_must_follow_device_results(self):
        text = "\n".join((
            azure.PLATFORM_READY, azure.IO_READY,
            azure.BLOCK_READY, azure.NETWORK_READY,
        ))
        result = azure.inspect_boot_log(text)
        self.assertFalse(result["io_ready"])
        self.assertTrue(result["failures"])

    def test_missing_devices_are_not_io_success(self):
        text = self.complete_log() + "\nUK_HYPERV_ACCEPTANCE_UNAVAILABLE:netvsc"
        result = azure.inspect_boot_log(text)
        self.assertTrue(result["platform_ready"])
        self.assertFalse(result["io_ready"])

    def test_later_crash_invalidates_success(self):
        text = self.complete_log() + "\nUnikraft Crash"
        result = azure.inspect_boot_log(text)
        self.assertFalse(result["platform_ready"])
        self.assertFalse(result["io_ready"])

    def test_nonzero_application_result_invalidates_io_success(self):
        text = self.complete_log() + "\nmain returned -1"
        result = azure.inspect_boot_log(text)
        self.assertFalse(result["io_ready"])
        self.assertTrue(result["failures"])


class HypervAzureTemplateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = json.loads(
            (SUPPORT / "azure/hyperv-gen2.json").read_text()
        )
        cls.resources = {
            resource["type"]: resource
            for resource in cls.template["resources"]
        }

    def test_specialized_disk_does_not_require_guest_provisioning(self):
        vm = self.resources["Microsoft.Compute/virtualMachines"]["properties"]
        self.assertNotIn("osProfile", vm)
        self.assertNotIn("imageReference", vm["storageProfile"])
        disk = vm["storageProfile"]["osDisk"]
        self.assertEqual(disk["createOption"], "Attach")
        self.assertEqual(disk["osType"], "Linux")
        self.assertEqual(disk["deleteOption"], "Detach")
        self.assertEqual(
            disk["managedDisk"]["id"], "[parameters('osDiskId')]"
        )

    def test_unsigned_efi_and_serial_capture_are_configured_before_boot(self):
        resource = self.resources["Microsoft.Compute/virtualMachines"]
        self.assertEqual(resource["apiVersion"], "2025-11-01")
        vm = resource["properties"]
        self.assertEqual(vm["securityProfile"]["securityType"], "Standard")
        self.assertEqual(
            vm["diagnosticsProfile"]["bootDiagnostics"], {"enabled": True}
        )

    def test_synthetic_nic_has_no_public_address(self):
        nic = self.resources["Microsoft.Network/networkInterfaces"]["properties"]
        self.assertFalse(nic["enableAcceleratedNetworking"])
        self.assertFalse(nic["enableIPForwarding"])
        self.assertEqual(len(nic["ipConfigurations"]), 1)
        self.assertNotIn(
            "publicIPAddress", nic["ipConfigurations"][0]["properties"]
        )
        self.assertNotIn("Microsoft.Network/publicIPAddresses", self.resources)
        self.assertEqual(
            self.resources["Microsoft.Network/networkSecurityGroups"]
            ["properties"]["securityRules"],
            [],
        )
        vnet = self.resources["Microsoft.Network/virtualNetworks"]["properties"]
        self.assertFalse(vnet["subnets"][0]["properties"]["defaultOutboundAccess"])

    def test_resources_carry_run_and_image_ownership(self):
        for resource in self.resources.values():
            self.assertEqual(resource["tags"], "[variables('tags')]")
        tags = self.template["variables"]["tags"]
        self.assertEqual(tags["managed-by"], "unikraft-hyperv")
        self.assertEqual(tags["unikraft-run"], "[parameters('namePrefix')]")
        self.assertEqual(tags["image-sha256"], "[parameters('imageSha256')]")

    def test_vm_choices_remain_small(self):
        size = self.template["parameters"]["vmSize"]
        self.assertEqual(size["defaultValue"], "Standard_D2s_v5")
        self.assertEqual(
            size["allowedValues"],
            ["Standard_D2s_v5", "Standard_D2as_v5", "Standard_B2s"],
        )


class HypervPersistenceControllerTest(unittest.TestCase):
    RUN_ID = "00112233445566778899aabbccddeeff"
    DISK_ID = "102132435465768798a9bacbdcedfe0f"
    SUBSCRIPTION = "12345678-1234-4234-9234-123456789abc"
    VM_UUID = "11111111-1111-4111-8111-111111111111"
    OS_UUID = "22222222-2222-4222-8222-222222222222"
    DATA_UUID = "33333333-3333-4333-8333-333333333333"
    CORRELATION_UUID = "44444444-4444-4444-8444-444444444444"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "source"
        self.inputs.mkdir(mode=0o700)
        self.state_dir = self.root / "state"
        self.contract, self.paths = self.make_inputs()
        self.contract_path = self.root / "contract.json"
        self.contract_path.write_bytes(azure.canonical_json(self.contract))
        os.chmod(self.contract_path, 0o600)
        self.contract_sha256 = azure.image_sha256(self.contract_path)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def fixed_footer(logical_size, identifier):
        footer = bytearray(512)
        footer[0:8] = b"conectix"
        struct.pack_into(">I", footer, 8, 2)
        struct.pack_into(">I", footer, 12, 0x00010000)
        struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
        footer[28:32] = b"ukrt"
        struct.pack_into(">I", footer, 32, 0x00010000)
        footer[36:40] = b"Wi2k"
        struct.pack_into(">Q", footer, 40, logical_size)
        struct.pack_into(">Q", footer, 48, logical_size)
        struct.pack_into(">I", footer, 60, 2)
        footer[68:84] = bytes.fromhex(identifier)
        struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
        return bytes(footer)

    def write_fixed_vhd(self, path, data, identifier):
        path.write_bytes(data + self.fixed_footer(len(data), identifier))
        os.chmod(path, 0o600)

    def make_seed(self, sectors, lun):
        raw = bytearray(sectors * persistence.SECTOR_SIZE)
        seed = bytearray(persistence.SECTOR_SIZE)
        seed[0:8] = b"UKPSEED2"
        struct.pack_into("<HHI", seed, 8, 2, 128, 512)
        seed[16:32] = bytes.fromhex(self.RUN_ID)
        seed[32:48] = bytes.fromhex(self.DISK_ID)
        struct.pack_into(
            "<QIIQQQQQI", seed, 48, sectors, 512, 2,
            persistence.SEED0_LBA, persistence.SEED1_LBA,
            persistence.INTENT_LBA, persistence.RECEIPT_LBA,
            persistence.EXTENT_LBA, persistence.EXTENT_SECTORS,
        )
        seed[108:112] = bytes((2, 0, lun, 0))
        crc = zlib.crc32(seed)
        struct.pack_into("<I", seed, 508, crc)
        for lba in (persistence.SEED0_LBA, persistence.SEED1_LBA):
            offset = lba * persistence.SECTOR_SIZE
            raw[offset:offset + persistence.SECTOR_SIZE] = seed
        manifest = {
            "version": 2,
            "run_id": self.RUN_ID,
            "disk_id": self.DISK_ID,
            "sectors": sectors,
            "sector_size": 512,
            "identity_policy": "seed-enrollment-v2",
            "identity_policy_version": 2,
            "path": None,
            "target": None,
            "lun": lun,
            "seed_lbas": [8, 9],
            "intent_lba": 16,
            "receipt_lba": 17,
            "extent_lba": 32,
            "extent_sectors": 16,
            "manifest_crc32": crc,
        }
        return bytes(raw), manifest

    def make_inputs(self):
        sectors = 4096
        lun = 7
        guest_data = b"G" * 4096
        guest_vhd = self.inputs / persistence.FILE_NAMES["guest_vhd"]
        self.write_fixed_vhd(
            guest_vhd, guest_data,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        data, seed = self.make_seed(sectors, lun)
        data_raw = self.inputs / persistence.FILE_NAMES["data_raw"]
        data_raw.write_bytes(data)
        os.chmod(data_raw, 0o600)
        data_vhd = self.inputs / persistence.FILE_NAMES["data_vhd"]
        self.write_fixed_vhd(
            data_vhd, data,
            self.DISK_ID,
        )
        seed_path = self.inputs / persistence.FILE_NAMES["seed_manifest"]
        seed_path.write_text(json.dumps(seed, sort_keys=True) + "\n")
        os.chmod(seed_path, 0o600)
        guest_record = {
            "name": guest_vhd.name,
            "sha256": azure.image_sha256(guest_vhd),
            "size": guest_vhd.stat().st_size,
        }
        preflight = {
            "schema": persistence.PREFLIGHT_SCHEMA,
            "schema_version": persistence.PREFLIGHT_VERSION,
            "result": "PASS",
            "scope": "exact-image-private-x86",
            "workload": persistence.WORKLOAD,
            "boot_policy": persistence.BOOT_POLICY,
            "identity_policy_version": 2,
            "image": {
                "sha256": guest_record["sha256"],
                "size": guest_record["size"],
            },
            "provenance": {
                "source_tree_sha256": "1" * 64,
                "solved_config_sha256": "2" * 64,
                "private_build_receipt_sha256": "3" * 64,
                "toolchain_sha256": "4" * 64,
                "input_manifest_sha256": "5" * 64,
                "preflight_receipt_sha256": "6" * 64,
            },
            "private_host": {
                "vm_uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "disk_uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "boot_count": 4,
                "boot_evidence_sha256": "7" * 64,
                "cleanup": "complete",
            },
        }
        preflight_path = (
            self.inputs / persistence.FILE_NAMES["preflight_receipt"]
        )
        preflight_path.write_text(json.dumps(preflight, indent=2) + "\n")
        os.chmod(preflight_path, 0o600)
        paths = {
            "guest_vhd": guest_vhd,
            "data_raw": data_raw,
            "data_vhd": data_vhd,
            "seed_manifest": seed_path,
            "preflight_receipt": preflight_path,
        }
        records = {
            role: {
                "name": path.name,
                "sha256": azure.image_sha256(path),
                "size": path.stat().st_size,
            }
            for role, path in paths.items()
        }
        prefix = "uk-hvpersist01"
        contract = {
            "schema": persistence.CONTRACT_SCHEMA,
            "schema_version": persistence.CONTRACT_VERSION,
            "workload": persistence.WORKLOAD,
            "implementation": persistence.implementation_contract(),
            "run_id": self.RUN_ID,
            "disk_id": self.DISK_ID,
            "geometry": {
                "sectors": sectors, "sector_size": 512, "lun": lun,
            },
            "azure": {
                "subscription": self.SUBSCRIPTION,
                "location": "northeurope",
                "vm_size": "Standard_B1s",
                "vm_vcpus": 1,
                "name_prefix": prefix,
                "resource_group": prefix + "-rg",
                "vm_name": prefix + "-vm",
                "os_disk_name": prefix + "-os",
                "data_disk_name": prefix + "-data",
                "nic_name": prefix + "-nic",
                "vnet_name": prefix + "-vnet",
                "nsg_name": prefix + "-nsg",
                "os_disk_sku": "Standard_LRS",
                "data_disk_sku": "Standard_LRS",
                "resource_counts": dict(persistence.RESOURCE_COUNTS),
                "max_boots": 2,
                "runtime_seconds": 600,
                "cleanup_seconds": 600,
            },
            "files": records,
            "preflight": preflight,
        }
        return contract, paths

    def prepare(self):
        persistence.prepare_state(
            self.contract_path, self.contract_sha256,
            self.state_dir, self.paths,
        )
        return persistence.load_state(self.state_dir)

    def identity_line(self, *, controller=None, lun=7, sectors=4096,
                      vpd="5000010102030400"):
        controller = controller or "aabbccddeeff00112233445566778899"
        return (
            "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:"
            f"{self.RUN_ID}:{self.DISK_ID}:{controller}:1:2:{lun}:"
            f"{sectors}:512:{len(vpd) // 2}:1:3:0:{vpd}"
        )

    def boot_log(self, boot, *, identity=None, writes=None, flushes=None):
        writes = (5 if boot == 1 else 0) if writes is None else writes
        flushes = (3 if boot == 1 else 0) if flushes is None else flushes
        action = "WRITE" if boot == 1 else "READ"
        state = 0 if boot == 1 else 2
        return "\n".join((
            "Powered by",
            "Calling main(",
            (
                f"HYPERV_PERSISTENCE START PASS run={self.RUN_ID} "
                "address=0:0:7 sectors=4096 sector_size=512"
            ),
            f"HYPERV_PERSISTENCE SELECT PASS id=3 controller=1 state={state}",
            identity or self.identity_line(),
            (
                f"HYPERV_PERSISTENCE BOOT{boot}_{action} PASS "
                f"run={self.RUN_ID}"
            ),
            (
                f"UK_HYPERV_PERSISTENCE_IO:1:{boot}:{self.RUN_ID}:"
                f"{writes}:{flushes}:receipt-verified"
            ),
            f"UK_HYPERV_PERSISTENCE_BOOT{boot}_COMPLETE:{self.RUN_ID}",
            "HYPERV_PERSISTENCE FINAL PASS rc=0",
            "main returned 0",
            "",
        ))

    def attach_proofs(self, state):
        group_id = (
            f"/subscriptions/{self.SUBSCRIPTION}/resourceGroups/"
            f"{self.contract['azure']['resource_group']}"
        )
        state.update({
            "resource_group_id": group_id,
            "cleanup_required": True,
            "boot_count": 2,
            "os_disk": {
                "id": group_id + (
                    "/providers/Microsoft.Compute/disks/"
                    + self.contract["azure"]["os_disk_name"]
                ),
                "uuid": self.OS_UUID,
            },
            "data_disk": {
                "id": group_id + (
                    "/providers/Microsoft.Compute/disks/"
                    + self.contract["azure"]["data_disk_name"]
                ),
                "uuid": self.DATA_UUID,
            },
        })
        state["vm"] = {
            "id": group_id + (
                "/providers/Microsoft.Compute/virtualMachines/"
                + self.contract["azure"]["vm_name"]
            ),
            "uuid": self.VM_UUID,
            "deployment_id": group_id + (
                "/providers/Microsoft.Resources/deployments/"
                + self.contract["azure"]["name_prefix"]
            ),
            "correlation_id": self.CORRELATION_UUID,
            "nic_id": group_id + (
                "/providers/Microsoft.Network/networkInterfaces/"
                + self.contract["azure"]["nic_name"]
            ),
            "os_disk_id": state["os_disk"]["id"],
            "data_disk_id": state["data_disk"]["id"],
        }
        return state

    def live_vm(self, state, *, data_disk_id=None, vm_uuid=None):
        return {
            "id": state["vm"]["id"],
            "vmId": vm_uuid or state["vm"]["uuid"],
            "tags": {
                "managed-by": persistence.MANAGED_BY,
                "purpose": persistence.PURPOSE,
                "unikraft-run": self.contract["azure"]["name_prefix"],
                "image-sha256": self.contract["files"]["guest_vhd"]["sha256"],
                "seed-sha256": self.contract["files"]["data_raw"]["sha256"],
            },
            "hardwareProfile": {"vmSize": self.contract["azure"]["vm_size"]},
            "storageProfile": {
                "osDisk": {
                    "managedDisk": {"id": state["os_disk"]["id"]},
                },
                "dataDisks": [{
                    "lun": 7,
                    "managedDisk": {
                        "id": data_disk_id or state["data_disk"]["id"],
                    },
                }],
            },
            "networkProfile": {
                "networkInterfaces": [{"id": state["vm"]["nic_id"]}],
            },
        }

    def live_disk(self, state, role, *, disk_uuid=None):
        proof = state[f"{role}_disk"]
        return {
            "id": proof["id"],
            "uniqueId": disk_uuid or proof["uuid"],
            "tags": self.live_vm(state)["tags"],
            "managedBy": state["vm"]["id"],
            "diskSizeBytes": (
                self.contract["files"]["guest_vhd"]["size"] - 512
                if role == "os"
                else self.contract["geometry"]["sectors"] * 512
            ),
            "provisioningState": "Succeeded",
            "diskState": "Attached",
            "osType": "Linux" if role == "os" else None,
            "hyperVGeneration": "V2" if role == "os" else None,
        }

    def live_deployment(self, state):
        group_id = state["resource_group_id"]

        def output(value):
            return {"type": "String", "value": value}

        resources = [
            state["vm"]["id"],
            state["vm"]["nic_id"],
            group_id + (
                "/providers/Microsoft.Network/virtualNetworks/"
                + self.contract["azure"]["vnet_name"]
            ),
            group_id + (
                "/providers/Microsoft.Network/networkSecurityGroups/"
                + self.contract["azure"]["nsg_name"]
            ),
        ]
        return {
            "name": self.contract["azure"]["name_prefix"],
            "id": state["vm"]["deployment_id"],
            "properties": {
                "provisioningState": "Succeeded",
                "correlationId": state["vm"]["correlation_id"],
                "outputResources": [{"id": value} for value in resources],
                "outputs": {
                    "vmId": output(state["vm"]["id"]),
                    "vmUuid": output(state["vm"]["uuid"]),
                    "osDiskId": output(state["os_disk"]["id"]),
                    "dataDiskId": output(state["data_disk"]["id"]),
                    "nicId": output(state["vm"]["nic_id"]),
                },
            },
        }

    def test_exact_two_boot_parser_and_causal_serial_boundary(self):
        boot1_text = self.boot_log(1)
        boot1 = persistence.parse_boot_segment(
            boot1_text, 1, self.contract
        )
        full = boot1_text + self.boot_log(2)
        boot2_text = persistence.boot2_suffix(
            full, len(boot1_text.encode()),
            hashlib.sha256(boot1_text.encode()).hexdigest(),
        )
        boot2 = persistence.parse_boot_segment(
            boot2_text, 2, self.contract, boot1["identity"]
        )
        self.assertEqual((boot1["writes"], boot1["flushes"]), (5, 3))
        self.assertEqual((boot2["writes"], boot2["flushes"]), (0, 0))
        self.assertEqual(boot2["identity"], boot1["identity"])

    def test_stale_or_replayed_boot1_never_authorizes_boot2(self):
        boot1 = self.boot_log(1)
        with self.assertRaisesRegex(ValueError, "Boot 1 or write"):
            persistence.parse_boot_segment(
                boot1 + self.boot_log(2), 2, self.contract
            )
        replay = (
            "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:" + self.RUN_ID + "\n"
            + self.boot_log(2)
        )
        with self.assertRaisesRegex(ValueError, "Boot 1 or write"):
            persistence.parse_boot_segment(
                replay, 2, self.contract
            )
        with self.assertRaisesRegex(ValueError, "Boot 1 or write"):
            persistence.parse_boot_segment(
                "storage reseed detected\n" + self.boot_log(2),
                2, self.contract,
            )
        with self.assertRaisesRegex(ValueError, "prefix changed"):
            persistence.boot2_suffix(
                "changed" + self.boot_log(2), len(boot1.encode()),
                hashlib.sha256(boot1.encode()).hexdigest(),
            )

    def test_candidate_rejections_are_bounded_before_selection(self):
        valid = self.boot_log(1).replace(
            "HYPERV_PERSISTENCE SELECT PASS",
            (
                "HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
                "reason=boot-signature id=2\n"
                "HYPERV_PERSISTENCE SELECT PASS"
            ),
        )
        persistence.parse_boot_segment(valid, 1, self.contract)
        late = self.boot_log(1).replace(
            "main returned 0",
            (
                "HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
                "reason=boot-signature id=2\nmain returned 0"
            ),
        )
        with self.assertRaisesRegex(ValueError, "unbounded or unordered"):
            persistence.parse_boot_segment(late, 1, self.contract)
        excessive = self.boot_log(1).replace(
            "HYPERV_PERSISTENCE SELECT PASS",
            "\n".join(
                (
                    "HYPERV_PERSISTENCE CANDIDATE_REJECT PASS "
                    f"reason=boot-signature id={index}"
                )
                for index in range(17)
            ) + "\nHYPERV_PERSISTENCE SELECT PASS",
        )
        with self.assertRaisesRegex(ValueError, "unbounded or unordered"):
            persistence.parse_boot_segment(
                excessive, 1, self.contract
            )

    def test_identity_geometry_lun_and_vpd_drift_fail_closed(self):
        boot1 = persistence.parse_boot_segment(
            self.boot_log(1), 1, self.contract
        )
        variants = (
            self.identity_line(
                controller="ffeeddccbbaa99887766554433221100"
            ),
            self.identity_line(lun=6),
            self.identity_line(sectors=6144),
            self.identity_line(vpd="5000010102030401"),
        )
        for identity in variants:
            with self.subTest(identity=identity):
                with self.assertRaises(ValueError):
                    persistence.parse_boot_segment(
                        self.boot_log(2, identity=identity), 2,
                        self.contract, boot1["identity"],
                    )

    def test_failure_unavailable_exit_and_io_receipt_variants_are_rejected(self):
        variants = (
            self.boot_log(1).replace(
                "HYPERV_PERSISTENCE SELECT PASS id=3 controller=1 state=0",
                "HYPERV_PERSISTENCE SELECT UNAVAILABLE reason=no-devices "
                "writes=0 flushes=0",
            ),
            self.boot_log(1).replace(
                "HYPERV_PERSISTENCE FINAL PASS rc=0",
                "HYPERV_PERSISTENCE FINAL FAIL rc=-5",
            ),
            self.boot_log(1).replace("main returned 0", "main returned 1"),
            self.boot_log(1, writes=4),
            self.boot_log(1, flushes=2),
            self.boot_log(1).replace(
                (
                    f"UK_HYPERV_PERSISTENCE_IO:1:1:{self.RUN_ID}:"
                    "5:3:receipt-verified\n"
                ),
                "",
            ),
            self.boot_log(1).replace(
                "5:3:receipt-verified", "5:3:receipt-missing"
            ),
            self.boot_log(1).replace(
                f"UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:{self.RUN_ID}\n",
                "",
            ),
            self.boot_log(1).replace(
                "UK_HYPERV_PERSISTENCE_IO:1:1:",
                "UK_HYPERV_PERSISTENCE_IO:1:1:"
            ) + (
                f"UK_HYPERV_PERSISTENCE_IO:1:1:{self.RUN_ID}:5:3:"
                "receipt-verified\n"
            ),
        )
        for text in variants:
            with self.subTest(text=text[-100:]):
                with self.assertRaises(ValueError):
                    persistence.parse_boot_segment(
                        text, 1, self.contract
                    )

    def test_prepare_pins_seed_vhd_preflight_and_mutation(self):
        state, path = self.prepare()
        self.assertEqual(state["phase"], "prepared")
        self.assertEqual(state["boot_count"], 0)
        persistence.verify_immutable_inputs(state, path.parent)
        data = path.parent / "inputs" / persistence.FILE_NAMES["data_raw"]
        with data.open("r+b") as output:
            output.seek(0)
            output.write(b"x")
        with self.assertRaisesRegex(ValueError, "input changed"):
            persistence.verify_immutable_inputs(state, path.parent)

    def test_contract_generator_requires_all_explicit_identity_and_envelope(self):
        output = self.root / "generated-contract.json"
        digest = persistence.create_contract(
            output,
            run_id=self.RUN_ID,
            disk_id=self.DISK_ID,
            sectors=4096,
            lun=7,
            subscription=self.SUBSCRIPTION,
            location="northeurope",
            vm_size="Standard_B1s",
            vm_vcpus=1,
            name_prefix="uk-hvpersist01",
            os_disk_sku="Standard_LRS",
            data_disk_sku="Standard_LRS",
            runtime_seconds=600,
            cleanup_seconds=600,
            inputs=self.paths,
        )
        self.assertEqual(digest, azure.image_sha256(output))
        self.assertEqual(json.loads(output.read_text()), self.contract)
        with self.assertRaises(FileExistsError):
            persistence.create_contract(
                output,
                run_id=self.RUN_ID,
                disk_id=self.DISK_ID,
                sectors=4096,
                lun=7,
                subscription=self.SUBSCRIPTION,
                location="northeurope",
                vm_size="Standard_B1s",
                vm_vcpus=1,
                name_prefix="uk-hvpersist01",
                os_disk_sku="Standard_LRS",
                data_disk_sku="Standard_LRS",
                runtime_seconds=600,
                cleanup_seconds=600,
                inputs=self.paths,
            )

    def test_contract_limits_and_build_only_preflight_fail_closed(self):
        variants = []
        for field, value in (
            ("sectors", True),
            ("sectors", persistence.MAX_SECTORS + 1),
            ("sector_size", 4096),
            ("lun", 64),
        ):
            contract = copy.deepcopy(self.contract)
            contract["geometry"][field] = value
            variants.append(contract)
        contract = copy.deepcopy(self.contract)
        contract["azure"]["max_boots"] = 3
        variants.append(contract)
        contract = copy.deepcopy(self.contract)
        contract["azure"]["resource_counts"]["virtual_machines"] = 2
        variants.append(contract)
        contract = copy.deepcopy(self.contract)
        contract["run_id"] = "0" * 32
        variants.append(contract)
        contract = copy.deepcopy(self.contract)
        contract["disk_id"] = contract["run_id"]
        variants.append(contract)
        for contract in variants:
            contract["implementation"] = persistence.implementation_contract()
            with self.subTest(contract=contract["geometry"]):
                with self.assertRaises(ValueError):
                    persistence.validate_contract(contract)
        for field, value in (
            ("result", "PREPARED"),
            ("scope", "build-package-only"),
            ("boot_policy", "platform-unavailable-v1"),
        ):
            preflight = copy.deepcopy(self.contract["preflight"])
            preflight[field] = value
            with self.subTest(preflight_field=field):
                with self.assertRaisesRegex(
                    ValueError, "incomplete or mismatched"
                ):
                    persistence.validate_preflight_receipt(
                        preflight, self.contract["files"]["guest_vhd"]
                    )
        preflight = copy.deepcopy(self.contract["preflight"])
        preflight["private_host"]["cleanup"] = "pending"
        with self.assertRaisesRegex(ValueError, "incomplete or mismatched"):
            persistence.validate_preflight_receipt(
                preflight, self.contract["files"]["guest_vhd"]
            )
        preflight = copy.deepcopy(self.contract["preflight"])
        preflight["private_host"]["disk_uuid"] = (
            preflight["private_host"]["vm_uuid"]
        )
        with self.assertRaisesRegex(ValueError, "incomplete or mismatched"):
            persistence.validate_preflight_receipt(
                preflight, self.contract["files"]["guest_vhd"]
            )

    def test_cloud_is_default_off_and_interrupted_state_cannot_restart(self):
        state, path = self.prepare()
        with mock.patch.object(persistence.azure, "azure_cli") as cloud:
            with self.assertRaisesRegex(ValueError, "approval"):
                persistence.run_acceptance(
                    self.state_dir, self.SUBSCRIPTION, False,
                    persistence.resource_envelope_sha256(self.contract),
                )
            cloud.assert_not_called()
        with mock.patch.object(persistence.azure, "azure_cli") as cloud:
            with self.assertRaisesRegex(ValueError, "approval does not match"):
                persistence.run_acceptance(
                    self.state_dir, self.SUBSCRIPTION, True, "f" * 64,
                )
            cloud.assert_not_called()
        state["phase"] = "boot2-start-requested"
        state["cleanup_required"] = True
        state["boot_count"] = 2
        azure.save_durable_json(path, state)
        with mock.patch.object(persistence.azure, "azure_cli") as cloud:
            with self.assertRaisesRegex(ValueError, "may only be cleaned"):
                persistence.run_acceptance(
                    self.state_dir, self.SUBSCRIPTION, True,
                    persistence.resource_envelope_sha256(self.contract),
                )
            cloud.assert_not_called()

    def test_all_irreversible_phases_refuse_reenrollment_or_another_boot(self):
        _state, path = self.prepare()
        for phase, boot_count in (
            ("creating-os-disk", 0),
            ("uploading-data-disk", 0),
            ("deploying-vm", 1),
            ("waiting-boot1", 1),
            ("boot1-deallocated", 1),
            ("boot2-start-requested", 2),
            ("waiting-boot2", 2),
        ):
            with self.subTest(phase=phase):
                state, _ = persistence.load_state(self.state_dir)
                state.update(
                    phase=phase, boot_count=boot_count,
                    cleanup_required=True,
                )
                azure.save_durable_json(path, state)
                with mock.patch.object(
                    persistence.azure, "azure_cli"
                ) as cloud:
                    with self.assertRaisesRegex(
                        ValueError, "may only be cleaned"
                    ):
                        persistence.run_acceptance(
                            self.state_dir, self.SUBSCRIPTION, True,
                            persistence.resource_envelope_sha256(
                                self.contract
                            ),
                        )
                    cloud.assert_not_called()
                state.update(
                    phase="prepared", boot_count=0,
                    cleanup_required=False,
                )
                azure.save_durable_json(path, state)

    def test_exact_state_machine_uses_one_deployment_and_one_restart(self):
        _state, _path = self.prepare()
        calls = []
        outer = self

        class FakeRun:
            def __init__(self, state, state_path):
                self.state = state
                self.state_path = state_path
                self.directory = state_path.parent
                self.deadline = None

            def record(self, phase, **fields):
                self.state.update(fields, phase=phase)
                azure.save_durable_json(self.state_path, self.state)

            def check_cloud(self):
                calls.append("preflight")
                return {"subscription": outer.SUBSCRIPTION, "sku": {}}

            def create_group(self):
                calls.append("group")
                self.record("group-created", resource_group_id="/group")

            def upload_disk(self, role):
                calls.append("upload-" + role)
                self.state[role + "_disk"] = {
                    "id": "/" + role, "uuid": (
                        outer.OS_UUID if role == "os" else outer.DATA_UUID
                    ),
                }
                self.record(role + "-disk-ready")

            def deploy_vm(self):
                calls.append("deploy")
                self.state["boot_count"] = 1
                self.state["vm"] = {
                    "id": "/vm", "uuid": outer.VM_UUID,
                    "deployment_id": "/deployment",
                    "correlation_id": outer.CORRELATION_UUID,
                    "nic_id": "/nic", "os_disk_id": "/os",
                    "data_disk_id": "/data",
                }
                self.record("vm-created")

            def wait_for_boot(self, boot):
                calls.append("boot" + str(boot))
                text = outer.boot_log(boot)
                enrolled = self.state.get("enrolled_identity")
                evidence = persistence.parse_boot_segment(
                    text, boot, outer.contract, enrolled
                )
                return (
                    text if boot == 1
                    else outer.boot_log(1) + text,
                    evidence,
                )

            def deallocate(self, boot):
                calls.append("deallocate" + str(boot))
                self.record(f"boot{boot}-deallocated")

            def start_boot2(self):
                calls.append("start")
                self.record("boot2-start-requested", boot_count=2)

            def cleanup(self):
                calls.append("cleanup")
                self.record("cleaned", cleanup_required=False)

            def private_failure_values(self):
                return ()

        with (
            mock.patch.object(
                persistence, "PersistenceRun", FakeRun
            ),
            mock.patch.object(
                persistence.azure, "check_upload_dependencies"
            ),
            mock.patch.object(
                persistence.azure, "interrupt_as_exception",
                return_value=contextlib.nullcontext(),
            ),
        ):
            receipt_path = persistence.run_acceptance(
                self.state_dir, self.SUBSCRIPTION, True,
                persistence.resource_envelope_sha256(self.contract),
            )
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["boots"]["count"], 2)
        self.assertEqual(receipt["cleanup"], "complete")
        self.assertEqual(calls.count("deploy"), 1)
        self.assertEqual(calls.count("start"), 1)
        self.assertEqual(
            calls,
            [
                "preflight", "group", "upload-os", "upload-data",
                "deploy", "boot1", "deallocate1", "start", "boot2",
                "deallocate2", "cleanup",
            ],
        )

    def test_primary_and_cleanup_failures_are_both_durable(self):
        _state, _path = self.prepare()

        class FailingRun:
            def __init__(self, state, state_path):
                self.state = state
                self.state_path = state_path
                self.deadline = None

            def record(self, phase, **fields):
                self.state.update(fields, phase=phase)
                azure.save_durable_json(self.state_path, self.state)

            def check_cloud(self):
                raise RuntimeError(
                    "/subscriptions/primary-private-id failed"
                )

            def cleanup(self):
                raise RuntimeError(
                    "/subscriptions/cleanup-private-id failed"
                )

            def private_failure_values(self):
                return ("primary-private-id", "cleanup-private-id")

        with (
            mock.patch.object(persistence, "PersistenceRun", FailingRun),
            mock.patch.object(
                persistence.azure, "check_upload_dependencies"
            ),
            mock.patch.object(
                persistence.azure, "interrupt_as_exception",
                return_value=contextlib.nullcontext(),
            ),
        ):
            with self.assertRaises(azure.RunCleanupError) as raised:
                persistence.run_acceptance(
                    self.state_dir, self.SUBSCRIPTION, True,
                    persistence.resource_envelope_sha256(self.contract),
                )
        self.assertNotIn("primary-private-id", str(raised.exception))
        self.assertNotIn("cleanup-private-id", str(raised.exception))
        state, _ = persistence.load_state(self.state_dir)
        self.assertEqual(state["phase"], "failed")
        self.assertTrue(state["cleanup_required"])
        self.assertIn("cleanup", state["failure"])

    def test_replaced_uuid_and_foreign_attachment_are_rejected(self):
        state, path = self.prepare()
        state = self.attach_proofs(state)
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            run.verify_disk(
                "data",
                self.live_disk(
                    state, "data",
                    disk_uuid="55555555-5555-4555-8555-555555555555",
                ),
                attached_vm_id=state["vm"]["id"],
            )
        run.az = mock.Mock(return_value=self.live_vm(
            state, data_disk_id="/foreign/data"
        ))
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            run.verify_vm()
        run.az = mock.Mock(return_value=self.live_vm(
            state,
            vm_uuid="66666666-6666-4666-8666-666666666666",
        ))
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            run.verify_vm()

    def test_vm_and_disk_uuid_proofs_must_come_from_create_outputs(self):
        state, path = self.prepare()
        state["resource_group_id"] = (
            f"/subscriptions/{self.SUBSCRIPTION}/resourceGroups/"
            f"{self.contract['azure']['resource_group']}"
        )
        run = persistence.PersistenceRun(state, path)
        disk = {
            "id": run.expected_id(
                "Microsoft.Compute", "disks",
                self.contract["azure"]["data_disk_name"],
            ),
            "tags": run.tags,
        }
        with self.assertRaisesRegex(ValueError, "UUID"):
            run.disk_proof("data", disk)

    def test_cleanup_deallocates_proven_vm_when_one_disk_is_unproven(self):
        state, path = self.prepare()
        state = self.attach_proofs(state)
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        run.deadline = time.monotonic() - 1
        commands = []
        group = {
            "id": state["resource_group_id"],
            "location": self.contract["azure"]["location"],
            "tags": run.tags,
        }
        resources = [
            {"id": identifier, "tags": run.tags}
            for identifier in run.expected_resource_ids()
        ]

        def execute(arguments, **_kwargs):
            commands.append(tuple(arguments[:2]))
            if arguments[:2] == ["group", "exists"]:
                return True
            if arguments[:2] == ["group", "show"]:
                return group
            if arguments[:2] == ["resource", "list"]:
                return resources
            if arguments[:3] == ["deployment", "group", "show"]:
                return self.live_deployment(state)
            if arguments[:2] == ["vm", "show"]:
                return self.live_vm(state)
            if arguments[:2] == ["disk", "show"]:
                role = (
                    "os" if arguments[arguments.index("--name") + 1]
                    == self.contract["azure"]["os_disk_name"] else "data"
                )
                return self.live_disk(
                    state, role,
                    disk_uuid=(
                        "55555555-5555-4555-8555-555555555555"
                        if role == "data" else None
                    ),
                )
            if arguments[:2] == ["vm", "deallocate"]:
                return None
            self.fail(f"unexpected cloud operation: {arguments}")

        run.az = execute
        with self.assertRaises(persistence.PersistenceCleanupError):
            run.cleanup()
        self.assertIn(("vm", "deallocate"), commands)
        self.assertNotIn(("group", "delete"), commands)

    def test_cleanup_accepts_proven_partial_resource_envelope(self):
        state, path = self.prepare()
        group_id = (
            f"/subscriptions/{self.SUBSCRIPTION}/resourceGroups/"
            f"{self.contract['azure']['resource_group']}"
        )
        state.update({
            "phase": "os-disk-created",
            "cleanup_required": True,
            "resource_group_id": group_id,
            "os_disk": {
                "id": group_id + (
                    "/providers/Microsoft.Compute/disks/"
                    + self.contract["azure"]["os_disk_name"]
                ),
                "uuid": self.OS_UUID,
            },
        })
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        group = {
            "id": group_id,
            "location": self.contract["azure"]["location"],
            "tags": run.tags,
        }
        disk = {
            "id": state["os_disk"]["id"],
            "uniqueId": self.OS_UUID,
            "tags": run.tags,
            "managedBy": None,
            "diskSizeBytes": (
                self.contract["files"]["guest_vhd"]["size"] - 512
            ),
            "provisioningState": "Succeeded",
            "diskState": "Unattached",
            "osType": "Linux",
            "hyperVGeneration": "V2",
        }
        commands = []

        def execute(arguments, **_kwargs):
            commands.append(tuple(arguments[:2]))
            if arguments[:2] == ["group", "exists"]:
                return len([
                    command for command in commands
                    if command == ("group", "exists")
                ]) == 1
            if arguments[:2] == ["group", "show"]:
                return group
            if arguments[:2] == ["resource", "list"]:
                return [{"id": state["os_disk"]["id"], "tags": run.tags}]
            if arguments[:2] == ["disk", "show"]:
                return disk
            if arguments[:2] == ["group", "delete"]:
                return None
            self.fail(f"unexpected cloud operation: {arguments}")

        run.az = execute
        run.cleanup()
        self.assertEqual(run.state["phase"], "cleaned")
        self.assertIn(("group", "delete"), commands)

    def test_unproven_partial_disk_blocks_group_deletion(self):
        state, path = self.prepare()
        group_id = (
            f"/subscriptions/{self.SUBSCRIPTION}/resourceGroups/"
            f"{self.contract['azure']['resource_group']}"
        )
        state.update({
            "phase": "creating-os-disk",
            "cleanup_required": True,
            "resource_group_id": group_id,
        })
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        disk_id = run.expected_id(
            "Microsoft.Compute", "disks",
            self.contract["azure"]["os_disk_name"],
        )

        def execute(arguments, **_kwargs):
            if arguments[:2] == ["group", "exists"]:
                return True
            if arguments[:2] == ["group", "show"]:
                return {
                    "id": group_id,
                    "location": self.contract["azure"]["location"],
                    "tags": run.tags,
                }
            if arguments[:2] == ["resource", "list"]:
                return [{"id": disk_id, "tags": run.tags}]
            self.fail(f"unexpected cloud operation: {arguments}")

        run.az = execute
        with self.assertRaises(persistence.PersistenceCleanupError):
            run.cleanup()
        self.assertEqual(run.state["phase"], "cleanup-failed")

    def test_interrupted_group_creation_cleans_only_an_empty_group(self):
        state, path = self.prepare()
        state.update({
            "phase": "creating-group",
            "cleanup_required": True,
        })
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        calls = 0

        def execute(arguments, **_kwargs):
            nonlocal calls
            if arguments[:2] == ["group", "exists"]:
                calls += 1
                return calls == 1
            if arguments[:2] == ["group", "show"]:
                return {
                    "id": "/created-response-was-lost",
                    "location": self.contract["azure"]["location"],
                    "tags": run.tags,
                }
            if arguments[:2] == ["resource", "list"]:
                return []
            if arguments[:2] == ["group", "delete"]:
                return None
            self.fail(f"unexpected cloud operation: {arguments}")

        run.az = execute
        run.cleanup()
        self.assertEqual(run.state["phase"], "cleaned")

    def test_cleanup_recovers_vm_uuid_from_original_deployment_output(self):
        state, path = self.prepare()
        state = self.attach_proofs(state)
        deployment = self.live_deployment(state)
        state.pop("vm")
        state.update({
            "phase": "deploying-vm",
            "cleanup_required": True,
            "boot_count": 1,
        })
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        group = {
            "id": state["resource_group_id"],
            "location": self.contract["azure"]["location"],
            "tags": run.tags,
        }
        expected_resources = [
            {"id": identifier, "tags": run.tags}
            for identifier in run.expected_resource_ids()
        ]
        exists_calls = 0
        commands = []

        def execute(arguments, **_kwargs):
            nonlocal exists_calls
            commands.append(tuple(arguments[:3]))
            if arguments[:2] == ["group", "exists"]:
                exists_calls += 1
                return exists_calls == 1
            if arguments[:2] == ["group", "show"]:
                return group
            if arguments[:2] == ["resource", "list"]:
                return expected_resources
            if arguments[:3] == ["deployment", "group", "show"]:
                return deployment
            if arguments[:2] == ["vm", "show"]:
                return self.live_vm(run.state)
            if arguments[:2] == ["disk", "show"]:
                role = (
                    "os" if arguments[arguments.index("--name") + 1]
                    == self.contract["azure"]["os_disk_name"] else "data"
                )
                return self.live_disk(run.state, role)
            if arguments[:2] in (
                ["vm", "deallocate"], ["group", "delete"]
            ):
                return None
            self.fail(f"unexpected cloud operation: {arguments}")

        run.az = execute
        run.cleanup()
        self.assertEqual(run.state["vm"]["uuid"], self.VM_UUID)
        self.assertIn(("vm", "deallocate"), [
            command[:2] for command in commands
        ])
        self.assertEqual(run.state["phase"], "cleaned")

    def test_cleanup_finalizes_durable_acceptance_after_reload(self):
        state, path = self.prepare()
        state = self.attach_proofs(state)
        boot1_text = self.boot_log(1)
        identity = persistence.parse_boot_segment(
            boot1_text, 1, self.contract
        )["identity"]
        state.update({
            "phase": "boot2-deallocated",
            "enrolled_identity": identity,
            "boot1": persistence.parse_boot_segment(
                boot1_text, 1, self.contract
            ),
            "boot1_serial_bytes": len(boot1_text.encode()),
            "boot1_serial_sha256": hashlib.sha256(
                boot1_text.encode()
            ).hexdigest(),
            "boot2": persistence.parse_boot_segment(
                self.boot_log(2), 2, self.contract, identity
            ),
        })
        azure.save_durable_json(path, state)
        run = persistence.PersistenceRun(state, path)
        _receipt, receipt_path = persistence.save_acceptance_receipt(
            run, state["boot1"], state["boot2"], "pending"
        )
        run.record(
            "acceptance-recorded",
            acceptance_receipt_sha256=azure.image_sha256(receipt_path),
        )

        def complete_cleanup(reloaded):
            reloaded.record("cleaned", cleanup_required=False)

        with mock.patch.object(
            persistence.PersistenceRun, "cleanup", complete_cleanup
        ):
            persistence.cleanup_state(self.state_dir, self.SUBSCRIPTION)
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["cleanup"], "complete")
        final, _ = persistence.load_state(self.state_dir)
        self.assertEqual(
            final["acceptance_receipt_sha256"],
            azure.image_sha256(receipt_path),
        )


class HypervPersistenceTemplateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = json.loads(
            (SUPPORT / "azure/hyperv-persistence.json").read_text()
        )
        cls.resources = {
            resource["type"]: resource
            for resource in cls.template["resources"]
        }

    def test_exact_data_disk_and_no_public_ingress(self):
        vm = self.resources["Microsoft.Compute/virtualMachines"][
            "properties"
        ]
        self.assertEqual(len(vm["storageProfile"]["dataDisks"]), 1)
        data = vm["storageProfile"]["dataDisks"][0]
        self.assertEqual(data["lun"], "[parameters('dataLun')]")
        self.assertEqual(data["createOption"], "Attach")
        self.assertEqual(data["caching"], "None")
        self.assertEqual(data["deleteOption"], "Detach")
        self.assertFalse(data["writeAcceleratorEnabled"])
        self.assertNotIn(
            "Microsoft.Network/publicIPAddresses", self.resources
        )
        vnet = self.resources["Microsoft.Network/virtualNetworks"][
            "properties"
        ]
        self.assertFalse(
            vnet["subnets"][0]["properties"]["defaultOutboundAccess"]
        )

    def test_all_resources_have_exact_persistence_ownership(self):
        for resource in self.resources.values():
            self.assertEqual(resource["tags"], "[variables('tags')]")
        tags = self.template["variables"]["tags"]
        self.assertEqual(tags["purpose"], persistence.PURPOSE)
        self.assertEqual(tags["seed-sha256"], "[parameters('seedSha256')]")


if __name__ == "__main__":
    unittest.main()
