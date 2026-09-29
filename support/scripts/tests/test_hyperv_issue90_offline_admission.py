# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic refusals only; no QEMU, private image build, or Azure access."""

from dataclasses import fields, replace
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "support/scripts"))
admission = importlib.import_module("hyperv_issue90_offline_admission")
topology = importlib.import_module("hyperv_issue90_topology")


class OfflineAdmissionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        self.state_dir = parent / "state"
        self.state = topology.plan(
            self.state_dir, "12345678-1234-4234-8234-123456789abc"
        )
        self.build_dir = parent / "build"
        self.image_dir = parent / "image"
        self.build_dir.mkdir(mode=0o700)
        self.image_dir.mkdir(mode=0o700)
        self.pins = admission.ReviewPins(
            "a" * 40, *("b" * 64 for _ in range(13))
        )

    def inputs(self, reviewed=None):
        return admission.OfflineInputs(
            self.state_dir, self.build_dir, self.image_dir,
            self.build_dir / "miz", self.build_dir / "native-runner",
            self.build_dir / "qemu", self.build_dir / "ovmf-code",
            self.build_dir / "ovmf-vars", reviewed,
        )

    def config(self, **changes):
        values = {
            "APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY": "y",
            "LIBSTORVSC_LUN_DISCOVERY": "y",
            "LIBSTORVSC_GUARDED_IO": "y",
            "LIBSTORVSC_MAX_DEVICES": "3",
            "LIBSTORVSC_MAX_LUNS": "4",
            "APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID":
                f'"{self.state["run_id"]}"',
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID":
                f'"{self.state["disk_ids"]["data0"]}"',
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID":
                f'"{self.state["disk_ids"]["data7"]}"',
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS": str(topology.SECTORS),
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS": str(topology.SECTORS),
            "APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN": "7",
        }
        values.update(changes)
        (self.build_dir / "solved.config").write_text(
            "\n".join(f"CONFIG_{key}={value}" for key, value in values.items()) + "\n"
        )

    def test_review_and_output_are_typed_and_do_not_authorize_cloud(self):
        with mock.patch.object(admission.subprocess, "Popen") as process:
            refused = admission.admit(self.inputs())
        process.assert_not_called()
        self.assertEqual(refused, admission.OfflineRefusal(
            "review", "independent_review_missing_or_invalid"
        ))
        self.assertNotIsInstance(refused, admission.OfflineAdmission)
        self.assertEqual(refused.schema, admission.SCHEMA)
        self.assertEqual(refused.scope, "offline_only")
        self.assertEqual(
            {field.name for field in fields(admission.OfflineAdmission)},
            {
                "schema", "version", "scope", "cloud_authorized",
                "run_id", "operation_id", "reviewed_head", "source_sha256",
                "implementation_sha256", "config_sha256", "efi_sha256",
                "raw_sha256", "vhd_sha256", "miz_sha256", "seeds", "boots",
            },
        )
        self.assertFalse(admission.OfflineAdmission.__dataclass_fields__[
            "cloud_authorized"
        ].init)

    def test_unreviewed_config_or_wrong_ids_refuse_before_build_or_boot(self):
        for change in (
            {"LIBSTORVSC_GUARDED_IO": "n"},
            {"APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY": "n"},
            {"APPHYPERVACCEPTANCE_PERSISTENCE": "y"},
            {"APPHYPERVACCEPTANCE_NETWORK_APPLICATION": "y"},
            {"APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID": '"wrong"'},
            {"APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS": "16"},
        ):
            with self.subTest(field=next(iter(change))):
                self.config(**change)
                with mock.patch.object(admission.preflight, "build_provenance") as build:
                    refused = admission.admit(self.inputs(self.pins))
                build.assert_not_called()
                self.assertEqual(refused.stage, "config")
                self.assertEqual(
                    refused.reason,
                    "solved_topology_config_missing_or_unreviewed",
                )

    def test_missing_guards_and_private_build_receipt_cannot_pass(self):
        self.config()
        (self.build_dir / "solved.config").write_text(
            (self.build_dir / "solved.config").read_text().replace(
                "CONFIG_LIBSTORVSC_GUARDED_IO=y\n", ""
            )
        )
        self.assertEqual(admission.admit(self.inputs(self.pins)).stage, "config")
        self.config()
        with mock.patch.object(admission.preflight, "build_provenance") as build:
            self.assertEqual(admission.admit(self.inputs(self.pins)).stage, "config")
        build.assert_not_called()
        self.assertNotEqual(
            hashlib.sha256((self.build_dir / "solved.config").read_bytes()).hexdigest(),
            self.pins.config_sha256,
        )
        with (
            mock.patch.object(admission.subprocess, "Popen") as process,
            mock.patch.object(admission.azure, "azure_cli") as cli,
        ):
            reviewed = replace(
                self.pins, config_sha256=hashlib.sha256(
                    (self.build_dir / "solved.config").read_bytes()
                ).hexdigest(),
            )
            refused = admission.admit(self.inputs(reviewed))
        process.assert_not_called()
        cli.assert_not_called()
        self.assertEqual(refused.stage, "source")
        self.assertFalse((self.state_dir / "offline-raw-x2apic").exists())

    def test_missing_witnessed_build_receipt_refuses_after_synthetic_source(self):
        self.config()
        efi_path = self.build_dir / "build" / admission.preflight.NATIVE_EFI_NAME
        efi_path.parent.mkdir()
        efi_path.write_bytes(b"synthetic not a guest")
        pins = replace(
            self.pins,
            config_sha256=hashlib.sha256(
                (self.build_dir / "solved.config").read_bytes()
            ).hexdigest(),
            efi_sha256=hashlib.sha256(efi_path.read_bytes()).hexdigest(),
        )
        source = {
            "head_commit": pins.head_commit,
            "tree_sha256": pins.tree_sha256,
            "physical_sha256": pins.physical_sha256,
        }
        with (
            mock.patch.object(admission.preflight, "git_runtime_record",
                              return_value={"sha256": pins.git_runtime_sha256}),
            mock.patch.object(admission.preflight, "validate_git_runtime_record",
                              side_effect=lambda value: value),
            mock.patch.object(admission.preflight, "build_provenance",
                              return_value=source),
            mock.patch.object(admission.subprocess, "Popen") as process,
        ):
            refused = admission.admit(self.inputs(pins))
        process.assert_not_called()
        self.assertEqual(refused.stage, "build")
        self.assertFalse((self.state_dir / "offline-raw-x2apic").exists())

    def test_unreviewed_git_runtime_refuses_before_execution(self):
        self.config()
        pins = replace(
            self.pins, config_sha256=hashlib.sha256(
                (self.build_dir / "solved.config").read_bytes()
            ).hexdigest(),
        )
        with (
            mock.patch.object(admission.preflight, "git_runtime_record",
                              return_value={"sha256": "c" * 64}),
            mock.patch.object(admission.preflight, "validate_git_runtime_record",
                              side_effect=lambda value: value),
            mock.patch.object(admission.preflight, "build_provenance") as build,
        ):
            refused = admission.admit(self.inputs(pins))
        build.assert_not_called()
        self.assertEqual(refused.stage, "source")
        self.assertEqual(refused.reason, "reviewed_physical_source_missing_or_invalid")

    def test_prepared_or_allocated_state_refuses_without_external_activity(self):
        self.state["phase"] = "prepared"
        topology.save(self.state_dir, self.state)
        with mock.patch.object(admission.subprocess, "Popen") as process:
            refused = admission.admit(self.inputs(self.pins))
        process.assert_not_called()
        self.assertEqual(refused.stage, "state")

    def test_missing_policy2_seed_refuses(self):
        with self.assertRaises(FileNotFoundError):
            admission._seed_proofs(self.state_dir, self.state)
        (self.state_dir / "data0.vhd").write_bytes(b"not 8388608 sectors")
        with self.assertRaisesRegex(ValueError, "wrong sector count"):
            admission._seed_proofs(self.state_dir, self.state)

    def test_missing_native_report_refuses_even_after_zero_exit(self):
        class SyntheticProcess:
            returncode = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def communicate(self, timeout):
                return b'{"passed":true}', b""

        with mock.patch.object(admission.subprocess, "Popen",
                               return_value=SyntheticProcess()):
            with self.assertRaisesRegex(ValueError, "Native boot report"):
                admission._boot(
                    self.inputs(self.pins), self.state_dir, self.state,
                    "raw", "x2apic", False, self.image_dir / "unikraft.raw",
                    "a" * 64, ("b" * 64,) * 3,
                )

    def test_preexisting_report_or_raw_prefix_vhd_cannot_replace_a_boot(self):
        work = self.state_dir / "offline-vhd-x2apic"
        work.mkdir(mode=0o700)
        (work / "report.json").write_text(json.dumps({"passed": True}))
        (work / "request.json").write_text(json.dumps({
            "config": {"source": {"kind": "raw_disk"}}
        }))
        with mock.patch.object(admission.subprocess, "Popen") as process:
            with self.assertRaises(FileExistsError):
                admission._boot(
                    self.inputs(self.pins), self.state_dir, self.state,
                    "vhd", "x2apic", False, self.image_dir / "unikraft.vhd", "a" * 64,
                    ("b" * 64,) * 3,
                )
        process.assert_not_called()

    def test_forged_success_report_with_raw_prefix_vhd_request_refuses(self):
        report = admission.azure.canonical_json({
            "schema_version": 1, "scope": "public_local_qemu_only",
            "acceptance": "not_established", "passed": True, "consumed": True,
            "cleanup_complete": True, "input_unchanged": True,
            "serial_valid": True, "serial_limit_reached": False,
            "serial_bytes": 1, "serial_sha256": "a" * 64,
            "failures": {}, "termination": {"exited": 0},
        })

        class SyntheticProcess:
            returncode = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def communicate(self, timeout):
                return report, b""

        def fake_native(argv, **kwargs):
            self.assertIn("--fixed-vhd", argv)
            self.assertNotIn("--raw-disk", argv)
            work = Path(argv[argv.index("--work-dir") + 1])
            (work / "report.json").write_bytes(report)
            (work / "request.json").write_bytes(
                admission.azure.canonical_json({
                    "schema_version": 2,
                    "config": {"source": {"kind": "raw_disk"}},
                    "pins": [{}] * 4,
                })
            )
            (work / "launched").touch()
            return SyntheticProcess()

        with mock.patch.object(admission.subprocess, "Popen", side_effect=fake_native):
            with self.assertRaisesRegex(ValueError, "exact disk and mode"):
                admission._boot(
                    self.inputs(self.pins), self.state_dir, self.state,
                    "vhd", "x2apic", False, self.image_dir / "unikraft.vhd",
                    "a" * 64, ("b" * 64,) * 3,
                )


if __name__ == "__main__":
    unittest.main()
