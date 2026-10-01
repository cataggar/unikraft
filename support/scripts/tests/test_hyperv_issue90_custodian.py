# SPDX-License-Identifier: BSD-3-Clause
"""Offline custodian tooling tests; fakes only, never Azure."""

from datetime import datetime, timedelta, timezone
import importlib
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_hyperv_issue90_custody_records import Fixture

custodian = importlib.import_module("hyperv_issue90_custodian")
custody = importlib.import_module("hyperv_issue90_custody_records")
azure = importlib.import_module("hyperv-azure")

NOW = datetime(2026, 9, 29, 4, 6, tzinfo=timezone.utc)
SAS = "https://upload.blob.core.windows.net/disk?sig=synthetic-secret"


class FakeAzure:
    def __init__(self, fixture):
        self.fixture = fixture
        self.created = set()
        self.revoked = set()
        self.deployed = False
        self.deallocated = False
        self.swapped = False
        self.inventory_tamper = None
        self.calls = []
        self.names = {
            role: fixture.ids[role].rsplit("/", 1)[-1]
            for role in (*custodian.DISKS, *custody.CHILDREN, "deployment")
        }

    def __call__(self, args, *, timeout):
        self.calls.append(tuple(args))
        action = tuple(args[:3])
        if args[:2] == ["group", "create"]:
            return self.response(self.fixture.resource("group"))
        if args[:2] == ["group", "show"]:
            return self.response(self.fixture.resource("group"))
        if args[:2] == ["disk", "create"]:
            role = self.disk_role(args)
            self.created.add(role)
            return self.response(self.disk(role, original=True))
        if args[:2] == ["disk", "grant-access"]:
            return self.response({"accessSAS": SAS})
        if args[:2] == ["disk", "revoke-access"]:
            self.revoked.add(self.disk_role(args))
            return self.response(None)
        if args[:2] == ["disk", "show"]:
            return self.response(self.disk(self.disk_role(args)))
        if action == ("deployment", "group", "create"):
            self.deployed = True
            return self.response(self.fixture.resource("deployment"))
        if action == ("deployment", "group", "show"):
            return self.response(self.fixture.resource("deployment"))
        if args[:2] == ["resource", "list"]:
            return self.response(self.inventory())
        if args[:2] == ["vm", "deallocate"]:
            self.deallocated = True
            return self.response(None)
        if action == ("vm", "get-instance-view", "--resource-group"):
            return self.response(self.fixture.instance_view())
        if args[:2] == ["vm", "update"]:
            self.swapped = True
            return self.response(self.fixture.vm("os", deallocated=False))
        if args[:2] == ["vm", "show"]:
            details = "-d" in args
            os_role = "os" if self.swapped else "dummy"
            return self.response(self.fixture.vm(os_role, deallocated=details))
        if action == ("network", "nic", "show"):
            return self.response(self.fixture.resource("nic"))
        if action == ("network", "vnet", "show"):
            return self.response(self.fixture.resource("vnet"))
        if action == ("network", "nsg", "show"):
            return self.response(self.fixture.resource("nsg"))
        raise AssertionError(f"unexpected fake az call: {args}")

    @staticmethod
    def response(value, raw=None):
        return custodian.RunnerResult(
            stdout=raw if raw is not None else (
                b"" if value is None else azure.canonical_json(value)
            ),
            value=value,
        )

    def disk_role(self, args):
        name = args[args.index("--name") + 1]
        for role, expected in self.names.items():
            if role in custodian.DISKS and name == expected:
                return role
        raise AssertionError(f"unexpected disk name {name}")

    def disk(self, role, *, original=False):
        result = self.fixture.resource(role)
        size = azure.VIRTUAL_SIZE if role in ("dummy", "os") else 4 * 1024**3
        result["diskSizeGB"] = 1 if role in ("dummy", "os") else 4
        if original:
            result["diskState"] = "ReadyToUpload"
            result.pop("diskSizeBytes", None)
            result.pop("diskSizeGB", None)
            return result
        attached = (
            role in ("dummy", "data0", "data7") if not self.swapped
            else role in ("os", "data0", "data7")
        )
        result["diskState"] = "Reserved" if attached and self.deallocated else "Unattached"
        result["managedBy"] = self.fixture.ids["vm"] if attached and self.deployed else None
        result["diskSizeBytes"] = size
        return result

    def inventory(self):
        result = [{
            "id": self.fixture.ids[role],
            "type": {
                "dummy": "Microsoft.Compute/disks",
                "os": "Microsoft.Compute/disks",
                "data0": "Microsoft.Compute/disks",
                "data7": "Microsoft.Compute/disks",
                "vm": "Microsoft.Compute/virtualMachines",
                "nic": "Microsoft.Network/networkInterfaces",
                "vnet": "Microsoft.Network/virtualNetworks",
                "nsg": "Microsoft.Network/networkSecurityGroups",
            }[role],
        } for role in custody.INVENTORY]
        if self.inventory_tamper == "extra":
            result.append({
                "id": self.fixture.ids["vm"] + "/extensions/policy",
                "type": "Microsoft.Compute/virtualMachines/extensions",
            })
        if self.inventory_tamper == "missing":
            result = [item for item in result
                      if item["id"] != self.fixture.ids["data7"]]
        return result


class CustodianToolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = Fixture()
        self.clock = datetime(2026, 9, 29, 4, 0, tzinfo=timezone.utc)

    def tick(self):
        value = self.clock
        self.clock += timedelta(seconds=5)
        return value

    def image_paths(self):
        return {role: self.root / f"{role}.vhd" for role in custodian.DISKS}

    def plan(self, **changes):
        values = {
            "expected": self.fixture.expected,
            "reviewed_head": "a" * 40,
            "config_sha256": "b" * 64,
            "efi_sha256": "c" * 64,
            "raw_sha256": "d" * 64,
            "miz_sha256": "e" * 64,
            "name_prefix": "uk90",
            "image_paths": self.image_paths(),
        }
        values.update(changes)
        return custodian.CustodianPlan(**values)

    def build(self, *, handoff=True, inventory_tamper=None, upload=None, plan=None):
        keys = custodian.generate_test_keys(self.root / "keys")
        fake = FakeAzure(self.fixture)
        fake.inventory_tamper = inventory_tamper
        recorder = custodian.CustodianRecorder(
            self.root / "custodian", runner=fake, clock=self.tick,
        )
        plan = plan or self.plan()
        uploads = []
        upload = upload or (
            lambda role, path, sas, digest, size: (
                uploads.append((role, path, sas, digest, size))
                or {"sha256": digest, "size": size}
            )
        )
        phase = custodian.record_preprovision(
            recorder, plan, upload=upload,
        )
        if handoff:
            custodian.record_handoff(recorder, plan, phase)
        assembler = custodian.CustodyAssembler(
            self.root / "custodian", self.fixture.expected,
        )
        return keys, fake, uploads, assembler

    def write_records(self, assembler, private_key):
        return assembler.write_signed(
            self.root / "records", private_key,
            prepared_at="2026-09-29T04:00:00Z",
            handoff_at="2026-09-29T04:01:00Z",
            handoff_expires_at="2026-09-29T04:31:00Z",
            prepared_nonce="b" * 32,
            handoff_nonce="c" * 32,
        )

    def registry(self, name):
        path = self.root / name
        path.mkdir(mode=0o700)
        return path

    def test_fake_run_assembles_signs_and_verifies_handoff(self):
        keys, _fake, uploads, assembler = self.build()
        prepared, handoff = self.write_records(
            assembler, keys["custodian"]["private_key"],
        )
        result = custodian.verify_handoff(
            prepared, handoff, expected=self.fixture.expected,
            public_key=keys["custodian"]["public_key"],
            archive_dir=self.root / "custodian/archive",
            registry_dir=self.registry("registry"),
            now=NOW,
        )
        self.assertTrue(result.passed, result.reason)
        self.assertEqual([item[0] for item in uploads], list(custodian.DISKS))
        self.assertTrue(all(item[2] == SAS for item in uploads))

    def test_original_stdout_bytes_are_archived_verbatim(self):
        raw = b'{ "z" : 2,\n  "a" : 1 }\n'
        recorder = custodian.CustodianRecorder(
            self.root / "bytes",
            runner=lambda args, *, timeout: custodian.RunnerResult(stdout=raw),
            clock=self.tick,
        )
        observation = recorder.az("odd.bytes", ["group", "show"])
        archived = self.root / "bytes/archive" / observation.ref["sha256"]
        self.assertEqual(archived.read_bytes(), raw)

    def test_upload_callable_and_image_paths_are_required(self):
        fake = FakeAzure(self.fixture)
        recorder = custodian.CustodianRecorder(
            self.root / "missing-upload", runner=fake, clock=self.tick,
        )
        with self.assertRaisesRegex(ValueError, "upload callable"):
            custodian.record_preprovision(recorder, self.plan())
        self.assertEqual(fake.calls, [])
        recorder = custodian.CustodianRecorder(
            self.root / "missing-image", runner=fake, clock=self.tick,
        )
        with self.assertRaisesRegex(ValueError, "image path"):
            custodian.record_preprovision(
                recorder, self.plan(image_paths={}), upload=lambda *args: None,
            )
        self.assertEqual(fake.calls, [])

    def test_upload_digest_and_size_are_verified(self):
        with self.assertRaisesRegex(ValueError, "uploaded bytes differ"):
            self.build(
                upload=lambda role, path, sas, digest, size: {
                    "sha256": "f" * 64,
                    "size": size,
                },
            )

    def test_inventory_refuses_extra_or_missing_resources(self):
        for tamper, reason in (("extra", "unexpected"), ("missing", "missing")):
            with self.subTest(tamper=tamper):
                self.root = self.root / tamper
                self.root.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, reason):
                    self.build(inventory_tamper=tamper)

    def test_handoff_runtime_is_derived_from_journal_timestamps(self):
        keys, _fake, _uploads, assembler = self.build()
        prepared = assembler.sign(
            assembler.assemble_prepared(
                issued_at_utc="2026-09-29T04:00:00Z",
                nonce="b" * 32,
            ),
            keys["custodian"]["private_key"],
        )
        derived = assembler._running_seconds(None)
        handoff = assembler.assemble_handoff(
            prepared,
            issued_at_utc="2026-09-29T04:01:00Z",
            expires_at_utc="2026-09-29T04:31:00Z",
            nonce="c" * 32,
        )
        self.assertEqual(handoff["evidence"]["running_seconds"], derived)
        self.assertGreater(derived, 0)
        with self.assertRaisesRegex(ValueError, "below observed"):
            assembler.assemble_handoff(
                prepared,
                issued_at_utc="2026-09-29T04:01:00Z",
                expires_at_utc="2026-09-29T04:31:00Z",
                nonce="d" * 32,
                running_seconds=derived - 1,
            )

    def test_plan_provenance_fields_are_required_nonzero_lowercase_hex(self):
        with self.assertRaises(TypeError):
            custodian.CustodianPlan(self.fixture.expected)
        for field, value in (
            ("reviewed_head", "A" * 40),
            ("config_sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "nonzero lowercase hex"):
                    self.plan(**{field: value})

    def test_tampered_archive_byte_is_rejected(self):
        keys, _fake, _uploads, assembler = self.build()
        prepared, handoff = self.write_records(
            assembler, keys["custodian"]["private_key"],
        )
        ref = assembler.journal.ref("group.create")
        blob = self.root / "custodian/archive" / ref["sha256"]
        data = blob.read_bytes()
        blob.write_bytes((b" " if data[:1] != b" " else b"{") + data[1:])
        result = custodian.verify_handoff(
            prepared, handoff, expected=self.fixture.expected,
            public_key=keys["custodian"]["public_key"],
            archive_dir=self.root / "custodian/archive",
            registry_dir=self.registry("tampered-registry"),
            now=NOW,
        )
        self.assertFalse(result.passed)
        self.assertIn("digest", result.reason)

    def test_missing_observation_fails_closed(self):
        keys, _fake, _uploads, assembler = self.build(handoff=False)
        prepared = assembler.sign(
            assembler.assemble_prepared(
                issued_at_utc="2026-09-29T04:00:00Z",
                nonce="b" * 32,
            ),
            keys["custodian"]["private_key"],
        )
        with self.assertRaisesRegex(ValueError, "Missing custodian observation vm.swap"):
            assembler.assemble_handoff(
                prepared,
                issued_at_utc="2026-09-29T04:01:00Z",
                expires_at_utc="2026-09-29T04:31:00Z",
                nonce="c" * 32,
            )

    def test_wrong_key_is_rejected(self):
        keys, _fake, _uploads, assembler = self.build()
        prepared, handoff = self.write_records(
            assembler, keys["custodian"]["private_key"],
        )
        result = custodian.verify_handoff(
            prepared, handoff, expected=self.fixture.expected,
            public_key=keys["witness"]["public_key"],
            archive_dir=self.root / "custodian/archive",
            registry_dir=self.registry("wrong-key-registry"),
            now=NOW,
        )
        self.assertFalse(result.passed)
        self.assertIn("signature", result.reason)

    def test_sas_value_is_never_persisted(self):
        self.build()
        leaked = []
        for path in (self.root / "custodian").rglob("*"):
            if path.is_file() and SAS.encode() in path.read_bytes():
                leaked.append(path)
        self.assertEqual(leaked, [])

    def test_private_modes_and_refusing_existing_key_directory(self):
        keys, _fake, _uploads, assembler = self.build()
        self.write_records(assembler, keys["custodian"]["private_key"])
        self.assert_private_tree(self.root / "keys")
        self.assert_private_tree(self.root / "custodian")
        self.assert_private_tree(self.root / "records")
        for role in custodian.KEY_ROLES:
            self.assertEqual(len(custodian.load_public_key(keys[role]["public_key"])), 32)
        with self.assertRaises(FileExistsError):
            custodian.generate_test_keys(self.root / "keys")

    def test_live_entry_point_is_closed_before_runner_use(self):
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            custodian.run_live()

    def assert_private_tree(self, root):
        for path in [root, *root.rglob("*")]:
            mode = stat.S_IMODE(path.stat().st_mode)
            if path.is_dir():
                self.assertEqual(mode, 0o700, path)
            else:
                self.assertEqual(mode, 0o600, path)


if __name__ == "__main__":
    unittest.main()
