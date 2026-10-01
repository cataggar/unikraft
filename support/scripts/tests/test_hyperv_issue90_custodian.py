# SPDX-License-Identifier: BSD-3-Clause
"""Offline custodian tooling tests; fakes only, never Azure."""

from datetime import datetime, timezone
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
        self.calls = []
        self.names = {
            role: fixture.ids[role].rsplit("/", 1)[-1]
            for role in (*custodian.DISKS, *custody.CHILDREN, "deployment")
        }

    def __call__(self, args, *, timeout):
        self.calls.append(tuple(args))
        action = tuple(args[:3])
        if args[:2] == ["group", "create"]:
            return self.fixture.resource("group")
        if args[:2] == ["group", "show"]:
            return self.fixture.resource("group")
        if args[:2] == ["disk", "create"]:
            role = self.disk_role(args)
            self.created.add(role)
            return self.disk(role, original=True)
        if args[:2] == ["disk", "grant-access"]:
            return {"accessSAS": SAS}
        if args[:2] == ["disk", "revoke-access"]:
            self.revoked.add(self.disk_role(args))
            return None
        if args[:2] == ["disk", "show"]:
            return self.disk(self.disk_role(args))
        if action == ("deployment", "group", "create"):
            self.deployed = True
            return self.fixture.resource("deployment")
        if action == ("deployment", "group", "show"):
            return self.fixture.resource("deployment")
        if args[:2] == ["vm", "deallocate"]:
            self.deallocated = True
            return None
        if action == ("vm", "get-instance-view", "--resource-group"):
            return self.fixture.instance_view()
        if args[:2] == ["vm", "update"]:
            self.swapped = True
            return self.fixture.vm("os", deallocated=False)
        if args[:2] == ["vm", "show"]:
            details = "-d" in args
            os_role = "os" if self.swapped else "dummy"
            return self.fixture.vm(os_role, deallocated=details)
        if action == ("network", "nic", "show"):
            return self.fixture.resource("nic")
        if action == ("network", "vnet", "show"):
            return self.fixture.resource("vnet")
        if action == ("network", "nsg", "show"):
            return self.fixture.resource("nsg")
        raise AssertionError(f"unexpected fake az call: {args}")

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


class CustodianToolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = Fixture()

    def build(self, *, handoff=True):
        keys = custodian.generate_test_keys(self.root / "keys")
        fake = FakeAzure(self.fixture)
        recorder = custodian.CustodianRecorder(self.root / "custodian", runner=fake)
        plan = custodian.CustodianPlan(self.fixture.expected, name_prefix="uk90")
        uploads = []
        phase = custodian.record_preprovision(
            recorder, plan,
            upload=lambda role, path, sas, digest, size: uploads.append(
                (role, path, sas, digest, size)
            ),
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
            running_seconds=10,
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
