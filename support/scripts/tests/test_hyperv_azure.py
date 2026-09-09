# SPDX-License-Identifier: BSD-3-Clause

import importlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

SUPPORT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SUPPORT / "scripts"))
azure = importlib.import_module("hyperv-azure")
uploader = importlib.import_module("hyperv-azure-upload")


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
        run = azure.AzureRun({
            "name_prefix": "uk-hv-fixture",
            "image_sha256": "a" * 64,
            "subscription": "test-subscription",
            "location": "westus2",
            "vm_size": "Standard_D2s_v5",
            "platform_marker": azure.PLATFORM_READY,
            "disk_id": "/test/disk",
        }, Path("/unused/state.json"))
        run.record = mock.Mock()
        run.az = mock.Mock()
        return run

    def disk_fixture(self, run):
        return {
            "id": "/test/disk",
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
                run.az.side_effect = [None, {
                    "id": "/test/vm", "tags": run.tags,
                    "provisioningState": "Succeeded",
                    "storageProfile": {"osDisk": {"managedDisk": {"id": "/test/disk"}}},
                    "securityProfile": profile,
                }]
                if profile is None or profile == {"securityType": "Standard"}:
                    run.deploy_vm()
                    run.record.assert_called_with("vm-created", vm_id="/test/vm")
                else:
                    with self.assertRaisesRegex(RuntimeError, "Standard security"):
                        run.deploy_vm()

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


class HypervAzureNetworkReservationTest(unittest.TestCase):
    def reservation(self):
        return HypervAzureControllerTest.reservation()

    def write_reservation(self, root, value=None, mode=0o600):
        path = root / "reservation.json"
        path.write_text(json.dumps(value or self.reservation()))
        path.chmod(mode)
        return path

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
        run, _ = fixture.network_run_fixture()
        reservation = self.reservation()
        original = {
            "id": reservation["resource_group_id"],
            "location": reservation["location"],
            "tags": reservation["tags"],
        }
        claimed = {**original, "tags": run.group_tags}
        run.az.side_effect = [original, [], claimed, []]
        run.claim_group_reservation(reservation)
        self.assertEqual(run.az.call_count, 4)
        self.assertEqual(
            run.record.call_args_list[0].args[0], "claiming-reservation"
        )
        self.assertEqual(run.record.call_args_list[1].args[0], "group-claimed")
        update = run.az.call_args_list[2].args[0]
        self.assertEqual(update[:4], [
            "group", "update", "--name", reservation["resource_group"],
        ])
        self.assertIn(
            "prepared-manifest-sha256=" + "b" * 64, update
        )

        run, _ = fixture.network_run_fixture()
        changed = {**original, "tags": {**reservation["tags"], "other": "owner"}}
        run.az.return_value = changed
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            run.claim_group_reservation(reservation)
        self.assertEqual(run.az.call_count, 1)
        run.record.assert_not_called()

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

    def test_cleanup_owner_checks_implicit_peer_disk_after_failed_deployment(self):
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
        disk = {**resource, "managedBy": peer_vm_id}
        run.az.side_effect = [True, group, [resource], disk, None, False]
        run.cleanup()

        run, state = fixture.network_run_fixture()
        state["phase"] = "deploying-peer"
        run.az.side_effect = [
            True, group, [{**resource, "id": disk_id + "-other"}],
        ]
        with self.assertRaisesRegex(RuntimeError, "ownership tags"):
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
        self.assertIn("existingNicId", guest["parameters"])
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
        peer_vm = {
            "id": "/peer-vm", "tags": run.tags,
            "provisioningState": "Succeeded",
            "hardwareProfile": {"vmSize": azure.network.PEER_VM_SIZE},
            "storageProfile": {"imageReference": peer_image},
        }
        peer_disk = {
            "id": "/peer-os", "tags": run.tags, "managedBy": "/peer-vm",
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
            None, peer_vm, peer_disk,
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


if __name__ == "__main__":
    unittest.main()
