# SPDX-License-Identifier: BSD-3-Clause
"""Offline custodian tooling tests; fakes only, never Azure."""

import contextlib
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
import os
import signal
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_hyperv_issue90_custody_records as custody_tests
from test_hyperv_issue90_custody_records import Fixture

custodian = importlib.import_module("hyperv_issue90_custodian")
custody = importlib.import_module("hyperv_issue90_custody_records")
azure = importlib.import_module("hyperv-azure")

NOW = datetime(2026, 9, 29, 4, 6, tzinfo=timezone.utc)
SAS = "https://upload.blob.core.windows.net/disk?sig=synthetic-secret"
SUBSCRIPTION = "11111111-1111-4111-8111-111111111111"


class FakeAzure:
    def __init__(self, fixture):
        self.fixture = fixture
        self.created = set()
        self.revoked = set()
        self.active_sas = set()
        self.deployed = False
        self.deallocated = False
        self.swapped = False
        self.inventory_tamper = None
        self.cleanup_tamper = None
        self.preexisting = False
        self.group_present = False
        self.group_tags = None
        self.group_id = None
        self.subscription = None
        self.fail_once = {}
        self.after = None
        self.resource_lists = 0
        self.calls = []
        self.raw_calls = []
        self.names = {
            role: fixture.ids[role].rsplit("/", 1)[-1]
            for role in (*custodian.DISKS, *custody.CHILDREN, "deployment")
        }

    def __call__(self, args, *, timeout):
        self.raw_calls.append(tuple(args))
        if self.subscription is not None:
            if (args[-2:] != ["--subscription", self.subscription]
                    or args.count("--subscription") != 1):
                raise AssertionError(f"az call is not subscription-pinned: {args}")
            args = args[:-2]
        self.calls.append(tuple(args))
        for prefix, error in list(self.fail_once.items()):
            if tuple(args[:len(prefix)]) == prefix:
                del self.fail_once[prefix]
                raise error
        try:
            return self.dispatch(args)
        finally:
            if self.after is not None:
                self.after(args)

    def dispatch(self, args):
        action = tuple(args[:3])
        if args[:2] == ["group", "exists"]:
            return self.response(self.preexisting or self.group_present)
        if args[:2] == ["group", "create"]:
            self.group_present = True
            return self.response(self.group())
        if args[:2] == ["group", "show"]:
            return self.response(self.group())
        if args[:2] == ["group", "delete"]:
            if self.active_sas:
                raise RuntimeError("Call EndGetAccess before deleting the disk")
            self.group_present = False
            return self.response(None)
        if args[:2] == ["disk", "create"]:
            role = self.disk_role(args)
            self.created.add(role)
            return self.response(self.disk(role, original=True))
        if args[:2] == ["disk", "grant-access"]:
            self.active_sas.add(self.disk_role(args))
            return self.response({"accessSAS": SAS})
        if args[:2] == ["disk", "revoke-access"]:
            self.revoked.add(self.disk_role(args))
            self.active_sas.discard(self.disk_role(args))
            return self.response(None)
        if args[:2] == ["disk", "show"]:
            return self.response(self.disk(self.disk_role(args)))
        if action == ("deployment", "group", "create"):
            self.deployed = True
            return self.response(self.fixture.resource("deployment"))
        if action == ("deployment", "group", "show"):
            return self.response(self.fixture.resource("deployment"))
        if args[:2] == ["resource", "list"]:
            self.resource_lists += 1
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

    def group(self):
        result = self.fixture.resource("group")
        if self.group_tags is not None:
            result["tags"] = dict(self.group_tags)
        if self.group_id is not None and self.resource_lists >= 2:
            result["id"] = self.group_id
        return result

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
        tags = {
            "issue90-run": self.fixture.expected.run_id,
            "issue90-operation": self.fixture.expected.operation_id,
        }
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
            "tags": dict(tags, **({"azsecpack": "nonprod"} if role == "vm" else {})),
        } for role in custody.INVENTORY
            if role in self.created or (role in custody.CHILDREN and self.deployed)]
        if self.inventory_tamper == "extra":
            result.append({
                "id": self.fixture.ids["vm"] + "/extensions/policy",
                "type": "Microsoft.Compute/virtualMachines/extensions",
            })
        if self.inventory_tamper == "missing":
            result = [item for item in result
                      if item["id"] != self.fixture.ids["data7"]]
        if self.cleanup_tamper is not None and self.resource_lists >= 3:
            group = self.fixture.ids["group"]
            result.append({
                "foreign": {
                    "id": group + "/providers/Microsoft.Storage/storageAccounts/other",
                    "type": "Microsoft.Storage/storageAccounts",
                    "tags": {"issue90-run": "e" * 32,
                             "issue90-operation": tags["issue90-operation"]},
                },
                "untagged": {
                    "id": group + "/providers/Microsoft.Network/publicIPAddresses/ip",
                    "type": "Microsoft.Network/publicIPAddresses",
                },
                "outside": {
                    "id": group + "-other/providers/Microsoft.Compute/disks/x",
                    "type": "Microsoft.Compute/disks",
                    "tags": dict(tags),
                },
            }[self.cleanup_tamper])
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

    def test_pinned_policy_footprint_verifies_and_round_trips(self):
        policy_case = custody_tests.CustodyRecordsTests()
        policy = policy_case._policy()
        self.fixture = Fixture(expected_changes={"azure_policy": policy},
                               vm_identity=policy_case._policy_identity())
        mapping = {
            field.name: getattr(self.fixture.expected, field.name)
            for field in fields(custody.Expected)
        }
        self.assertEqual(custodian.expected_from_mapping(mapping),
                         self.fixture.expected)
        keys, _fake, _uploads, assembler = self.build()
        prepared, handoff = self.write_records(
            assembler, keys["custodian"]["private_key"],
        )
        verify = lambda expected, name: custodian.verify_handoff(
            prepared, handoff, expected=expected,
            public_key=keys["custodian"]["public_key"],
            archive_dir=self.root / "custodian/archive",
            registry_dir=self.registry(name), now=NOW,
        )
        result = verify(self.fixture.expected, "registry")
        self.assertTrue(result.passed, result.reason)
        unpinned = replace(self.fixture.expected, azure_policy=None)
        result = verify(unpinned, "unpinned")
        self.assertFalse(result.passed)
        self.assertIn("unpinned managed identity", result.reason)

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
        with self.assertRaisesRegex(custodian.LiveApprovalRefused, "disabled"):
            custodian.run_live()
        with self.assertRaisesRegex(custodian.LiveApprovalRefused, "disabled"):
            custodian.require_live_custodian_approval()
        fake = FakeAzure(self.fixture)
        with self.assertRaisesRegex(custodian.LiveApprovalRefused, "disabled"):
            custodian.run_live(
                None, expected=self.fixture.expected, plan=self.plan(),
                subscription=SUBSCRIPTION, directory=self.root / "live",
                records_dir=self.root / "records",
                registry_dir=self.registry("closed-registry"),
                runner=fake, cleanup_runner=fake,
                upload=lambda *args: None,
            )
        self.assertEqual(fake.calls, [])
        self.assertFalse((self.root / "live").exists())

    def test_existing_group_is_never_adopted(self):
        fake = FakeAzure(self.fixture)
        fake.preexisting = True
        recorder = custodian.CustodianRecorder(
            self.root / "custodian", runner=fake, clock=self.tick,
        )
        with self.assertRaisesRegex(ValueError, "already exists"):
            custodian.record_preprovision(
                recorder, self.plan(), upload=lambda *args: None,
            )
        self.assertEqual(fake.calls, [("group", "exists", "--name", "uk90-rg")])
        self.assertEqual(
            custodian.cleanup_disposable(recorder, self.plan()).status,
            "not-created",
        )
        self.assertEqual(len(fake.calls), 1)

    def test_upload_failure_still_revokes_write_access(self):
        def upload(role, path, sas, digest, size):
            if role == "os":
                raise RuntimeError("synthetic upload failure")
            return {"sha256": digest, "size": size}

        with self.assertRaisesRegex(RuntimeError, "synthetic upload failure"):
            self.build(upload=upload)
        journal = custodian.Journal(self.root / "custodian/journal.jsonl")
        self.assertIn("disk.os.revoke", journal.by_step)
        self.assertNotIn("disk.os.upload", journal.by_step)
        self.assertNotIn("disk.os.revocation", journal.by_step)
        self.assertEqual(journal.entries[-1]["step"], "disk.os.revoke")

    def test_cleanup_deletes_only_a_proven_owned_group(self):
        keys, fake, _uploads, _assembler = self.build()
        del keys
        plan = self.plan()
        fake.group_tags = plan.tags("group")
        recorder = custodian.CustodianRecorder(
            self.root / "custodian", runner=fake, clock=self.tick,
        )
        result = custodian.cleanup_disposable(recorder, plan)
        self.assertEqual(result, custodian.CleanupResult("deleted", False))
        self.assertFalse(fake.group_present)
        steps = [entry["step"] for entry in
                 custodian.Journal(recorder.journal_path).entries[-4:]]
        self.assertEqual(steps, ["cleanup.group", "cleanup.inventory",
                                 "cleanup.delete", "cleanup.exists"])

    def test_cleanup_refuses_foreign_inventory_or_group_tags(self):
        for case in ("foreign", "untagged", "outside", "group-tags", "group-id"):
            with self.subTest(case=case):
                self.root = self.root / case
                self.root.mkdir(mode=0o700)
                _keys, fake, _uploads, _assembler = self.build()
                plan = self.plan()
                fake.group_tags = plan.tags("group")
                if case == "group-tags":
                    fake.group_tags = dict(fake.group_tags, **{"unikraft-run": "x"})
                elif case == "group-id":
                    fake.group_id = self.fixture.ids["group"] + "-other"
                else:
                    fake.cleanup_tamper = case
                recorder = custodian.CustodianRecorder(
                    self.root / "custodian", runner=fake, clock=self.tick,
                )
                with self.assertRaises(custodian.CleanupRefused):
                    custodian.cleanup_disposable(recorder, plan)
                self.assertNotIn("delete", [call[1] for call in fake.calls])
                self.assertTrue(fake.group_present)

    def test_cleanup_deallocates_an_undeallocated_vm_best_effort(self):
        for second_failure in (False, True):
            with self.subTest(second_failure=second_failure):
                self.root = self.root / str(second_failure)
                self.root.mkdir(mode=0o700)
                fake = FakeAzure(self.fixture)
                fake.fail_once[("vm", "deallocate")] = RuntimeError("first")
                plan = self.plan()
                fake.group_tags = plan.tags("group")
                recorder = custodian.CustodianRecorder(
                    self.root / "custodian", runner=fake, clock=self.tick,
                )
                with self.assertRaisesRegex(RuntimeError, "first"):
                    custodian.record_preprovision(
                        recorder, plan,
                        upload=lambda role, path, sas, digest, size: {
                            "sha256": digest, "size": size,
                        },
                    )
                if second_failure:
                    fake.fail_once[("vm", "deallocate")] = RuntimeError("again")
                result = custodian.cleanup_disposable(recorder, plan)
                self.assertEqual(result.status, "deleted")
                self.assertEqual(result.deallocated, not second_failure)
                deallocations = [call for call in fake.calls
                                 if call[:2] == ("vm", "deallocate")]
                self.assertEqual(len(deallocations), 2)
                self.assertFalse(fake.group_present)

    def test_subscription_runner_pins_and_enforces_deadline(self):
        fake = FakeAzure(self.fixture)
        fake.subscription = SUBSCRIPTION
        deadline = datetime(2026, 9, 29, 5, 0, tzinfo=timezone.utc)
        now = [deadline]
        runner = custodian.SubscriptionRunner(
            SUBSCRIPTION, deadline=deadline, clock=lambda: now[0], runner=fake,
        )
        self.assertIs(runner(["group", "exists", "--name", "g"]).value, False)
        self.assertEqual(fake.raw_calls[-1][-2:], ("--subscription", SUBSCRIPTION))
        with self.assertRaisesRegex(ValueError, "own subscription"):
            runner(["group", "show", "--subscription", "x"])
        now[0] = deadline + timedelta(microseconds=1)
        with self.assertRaisesRegex(RuntimeError, "window has closed"):
            runner(["group", "exists", "--name", "g"])
        self.assertEqual(len(fake.raw_calls), 1)
        unbounded = custodian.SubscriptionRunner(
            SUBSCRIPTION, clock=lambda: now[0], runner=fake,
        )
        unbounded(["group", "exists", "--name", "g"])
        self.assertEqual(len(fake.raw_calls), 2)
        with self.assertRaisesRegex(ValueError, "canonical"):
            custodian.SubscriptionRunner("not-a-uuid")

    def test_azure_vhd_upload_checks_bytes_before_upload(self):
        image = self.root / "image.vhd"
        image.write_bytes(b"\0" * 1024)
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        link = self.root / "link.vhd"
        link.symlink_to(image)
        with mock.patch.object(custodian.azure, "upload_managed_vhd") as upload:
            for path, sha, size, reason in (
                (link, digest, 1024, "non-symlink"),
                (self.root / "missing.vhd", digest, 1024, "non-symlink"),
                (image, digest, 512, "size"),
                (image, "f" * 64, 1024, "digest"),
            ):
                with self.subTest(reason=reason, path=path.name):
                    with self.assertRaisesRegex(ValueError, reason):
                        custodian.azure_vhd_upload("os", path, SAS, sha, size)
            upload.assert_not_called()
            result = custodian.azure_vhd_upload("os", image, SAS, digest, 1024)
        self.assertEqual(result, {"sha256": digest, "size": 1024})
        upload.assert_called_once_with(
            image, "https://upload.blob.core.windows.net/disk",
            "sig=synthetic-secret", timeout=1200, expected_sha256=digest,
        )

    def test_plan_mapping_is_exact(self):
        mapping = {
            "reviewed_head": "a" * 40, "config_sha256": "b" * 64,
            "efi_sha256": "c" * 64, "raw_sha256": "d" * 64,
            "miz_sha256": "e" * 64,
            "image_paths": {role: f"/images/{role}.vhd" for role in custodian.DISKS},
        }
        plan = custodian.plan_from_mapping(mapping, self.fixture.expected)
        self.assertEqual(plan.image_path("os"), Path("/images/os.vhd"))
        for change in (
            {"extra": 1},
            {"image_paths": {"os": "/x"}},
            {"upload_sizes": {"os": 0}},
            {"upload_sizes": {"other": 1}},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    custodian.plan_from_mapping(
                        {**mapping, **change}, self.fixture.expected,
                    )
        with self.assertRaises(ValueError):
            custodian.plan_from_mapping(
                {k: v for k, v in mapping.items() if k != "miz_sha256"},
                self.fixture.expected,
            )

    def assert_private_tree(self, root):
        for path in [root, *root.rglob("*")]:
            mode = stat.S_IMODE(path.stat().st_mode)
            if path.is_dir():
                self.assertEqual(mode, 0o700, path)
            else:
                self.assertEqual(mode, 0o600, path)


RUN = custody_tests.RUN
OPERATION = custody_tests.OPERATION
GROUP = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/uk90-rg"
OTHER_SUBSCRIPTION = "33333333-3333-4333-8333-333333333333"
WINDOW = ("2026-09-29T04:00:00Z", "2026-09-29T08:00:00Z")
TEMPLATE_SHA = hashlib.sha256(custodian.DEFAULT_TEMPLATE.read_bytes()).hexdigest()
PRIVATE = (SUBSCRIPTION, RUN, "uk90-rg", "synthetic-secret")


def sign_approval(body, private_key):
    signature = custodian.load_private_key(private_key).sign(
        (custodian.LIVE_APPROVAL_SCHEMA + "\n").encode("ascii")
        + azure.canonical_json(body)
    )
    return azure.canonical_json({"body": body, "signature": signature.hex()})


def write_private(path, raw):
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    return path


class LiveGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.keys = custodian.generate_test_keys(self.root / "keys")
        self.count = 0

    def tick(self):
        value = self.clock
        self.clock += timedelta(seconds=5)
        return value

    def body(self, **changes):
        body = custodian.approval_body(
            subscription=SUBSCRIPTION, run_id=RUN, operation_id=OPERATION,
            group_id=GROUP, not_before_utc=WINDOW[0], not_after_utc=WINDOW[1],
            max_vm_running_seconds=600, nonce="f" * 32,
        )
        body.update(changes)
        return body

    def prepare(self, body=None, *, signer="approver", raw=None,
                expected_changes=None, digest=None):
        self.count += 1
        self.clock = datetime(2026, 9, 29, 4, 1, tzinfo=timezone.utc)
        if raw is None:
            raw = sign_approval(body or self.body(),
                                self.keys[signer]["private_key"])
        self.approval = write_private(
            self.root / f"approval-{self.count}.json", raw,
        )
        changes = {
            "preprovision_authorization_sha256":
                digest or hashlib.sha256(raw).hexdigest(),
            "template_sha256": TEMPLATE_SHA,
        }
        changes.update(expected_changes or {})
        self.fixture = Fixture(expected_changes=changes)
        self.plan = custodian.CustodianPlan(
            expected=self.fixture.expected,
            reviewed_head="a" * 40, config_sha256="b" * 64,
            efi_sha256="c" * 64, raw_sha256="d" * 64, miz_sha256="e" * 64,
            name_prefix="uk90",
            image_paths={role: self.root / f"{role}.vhd"
                         for role in custodian.DISKS},
        )
        self.fake = FakeAzure(self.fixture)
        self.fake.subscription = SUBSCRIPTION
        self.fake.group_tags = self.plan.tags("group")
        self.registry = self.root / f"registry-{self.count}"
        self.registry.mkdir(mode=0o700)
        self.uploads = []
        return raw

    def upload(self, role, path, sas, digest, size):
        self.uploads.append((role, sas))
        return {"sha256": digest, "size": size}

    def run_live(self, **changes):
        kwargs = {
            "approver_public_key": self.keys["approver"]["public_key"],
            "custodian_private_key": self.keys["custodian"]["private_key"],
            "custodian_public_key": self.keys["custodian"]["public_key"],
            "expected": self.fixture.expected,
            "plan": self.plan,
            "subscription": SUBSCRIPTION,
            "directory": self.root / f"live-{self.count}",
            "records_dir": self.root / f"records-{self.count}",
            "registry_dir": self.registry,
            "runner": self.fake,
            "upload": self.upload,
            "clock": self.tick,
        }
        kwargs.update(changes)
        return custodian.run_live(self.approval, **kwargs)

    def journal(self):
        return custodian.Journal(self.root / f"live-{self.count}/journal.jsonl")

    def assert_sanitized(self, text):
        for value in PRIVATE:
            self.assertNotIn(value.lower(), text.lower())

    def assert_deleted(self, result):
        self.assertEqual(result.cleanup, "deleted", result.cleanup_reason)
        self.assertIn(("group", "delete", "--name", "uk90-rg", "--yes"),
                      self.fake.calls)
        self.assertFalse(self.fake.group_present)

    def test_signed_dry_run_verifies_and_deletes_the_owned_group(self):
        raw = self.prepare()
        result = self.run_live()
        self.assertTrue(result.passed, result.reason)
        self.assertIsNone(result.reason)
        custody._sha(result.verification_digest, "Verification digest")
        self.assert_deleted(result)
        self.assertEqual([role for role, _sas in self.uploads],
                         list(custodian.DISKS))
        self.assertTrue(all(call[-2:] == ("--subscription", SUBSCRIPTION)
                            for call in self.fake.raw_calls))
        self.assertEqual(self.fake.calls[0],
                         ("group", "exists", "--name", "uk90-rg"))
        self.assertEqual(self.fake.calls[1][:2], ("group", "create"))
        journal = self.journal()
        for entry in journal.entries:
            self.assertNotIn("--subscription", entry["argv"])
            self.assertNotIn(SUBSCRIPTION, entry["argv"])
        self.assertEqual(journal.entries[0]["step"], "group.precheck")
        self.assertEqual(
            [entry["step"] for entry in journal.entries[-4:]],
            ["cleanup.group", "cleanup.inventory", "cleanup.delete",
             "cleanup.exists"],
        )
        self.assertNotIn("cleanup.deallocate", journal.by_step)
        claims = {path.name for path in self.registry.iterdir()}
        self.assertIn(
            f"live-approval-{hashlib.sha256(raw).hexdigest()}.json", claims,
        )
        self.assertIn(f"run-{RUN}.json", claims)
        for path in (self.root / f"live-{self.count}",
                     self.root / f"records-{self.count}"):
            CustodianToolTests.assert_private_tree(self, path)
        calls = len(self.fake.raw_calls)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.run_live(directory=self.root / "second",
                          records_dir=self.root / "second-records")
        self.assertEqual(len(self.fake.raw_calls), calls)
        self.assertFalse((self.root / "second").exists())

    def test_live_approval_is_single_use(self):
        self.prepare()
        self.fake.preexisting = True
        self.assertEqual(self.run_live().cleanup, "not-created")
        self.fake.preexisting = False
        calls = len(self.fake.raw_calls)
        with self.assertRaisesRegex(custodian.LiveApprovalRefused,
                                    "Live approval was already consumed"):
            self.run_live(directory=self.root / "second",
                          records_dir=self.root / "second-records")
        self.assertEqual(len(self.fake.raw_calls), calls)
        self.assertFalse((self.root / "second").exists())

    def test_live_approval_refusals_happen_before_any_azure_call(self):
        other = dict(Fixture().ids)
        other["nic"] = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/other-rg"
                        "/providers/Microsoft.Network/networkInterfaces/nic")
        dotted = dict(Fixture().ids)
        dotted["nic"] = (GROUP + "/providers/../../other-rg/providers/"
                         "Microsoft.Network/networkInterfaces/nic")
        noncanonical = json.dumps({
            "body": self.body(),
            "signature": "0" * 128,
        }, indent=1).encode()
        cases = (
            ("garbled", {"raw": b"not json\n"}, {}, "not valid"),
            ("noncanonical", {"raw": noncanonical}, {}, "canonical"),
            ("signature", {"signer": "witness"}, {}, "signature"),
            ("same-key", {}, {
                "approver_public_key": self.keys["custodian"]["public_key"],
            }, "differ from the custodian"),
            ("acceptance", {"body": self.body(mode="acceptance")}, {},
             "Only the disposable dry-run live mode is available"),
            ("cleanup", {"body": self.body(cleanup="keep-group")}, {},
             "deleting the owned group"),
            ("location", {"body": self.body(location="westeurope")}, {},
             "region"),
            ("extra-field", {"body": {**self.body(), "extra": 1}}, {},
             "unknown or missing"),
            ("subscription", {}, {"subscription": OTHER_SUBSCRIPTION},
             "different subscription"),
            ("subscription-hash",
             {"body": self.body(subscription_sha256="0" * 64)}, {},
             "different subscription"),
            ("run", {"body": self.body(run_id="e" * 32)}, {},
             "run or operation"),
            ("operation", {"body": self.body(
                operation_id="22222222-2222-4222-8222-222222222222")}, {},
             "run or operation"),
            ("group", {"body": self.body(group_id=GROUP + "x")}, {},
             "group differs"),
            ("foreign-resource",
             {"expected_changes": {"resource_ids": other}}, {},
             "inside the approved group"),
            ("dotted-resource",
             {"expected_changes": {"resource_ids": dotted}}, {},
             "inside the approved group"),
            ("span", {"body": self.body(not_after_utc="2026-09-29T09:01:00Z")},
             {}, "at most 300 minutes"),
            ("empty-span",
             {"body": self.body(not_after_utc=WINDOW[0])}, {},
             "at most 300 minutes"),
            ("runtime-zero", {"body": self.body(max_vm_running_seconds=0)},
             {}, "1..3600"),
            ("runtime-large", {"body": self.body(max_vm_running_seconds=3601)},
             {}, "1..3600"),
            ("runtime-bool", {"body": self.body(max_vm_running_seconds=True)},
             {}, "1..3600"),
            ("nonce", {"body": self.body(nonce="F" * 32)}, {}, "nonce"),
            ("digest", {"digest": "1" * 64}, {}, "digest differs"),
            ("before-window", {}, {"clock": lambda: datetime(
                2026, 9, 29, 3, 59, 59, tzinfo=timezone.utc)},
             "outside the approved live window"),
            ("after-window", {}, {"clock": lambda: datetime(
                2026, 9, 29, 8, 0, 1, tzinfo=timezone.utc)},
             "outside the approved live window"),
        )
        for name, prepare, run, reason in cases:
            with self.subTest(case=name):
                self.prepare(**prepare)
                with self.assertRaisesRegex(custodian.LiveApprovalRefused, reason):
                    self.run_live(**run)
                self.assertEqual(self.fake.raw_calls, [])
                self.assertFalse((self.root / f"live-{self.count}").exists())
                self.assertEqual(list(self.registry.iterdir()), [])

    def test_live_approval_file_and_preflight_refusals(self):
        self.prepare()
        os.chmod(self.approval, 0o644)
        with self.assertRaisesRegex(custodian.LiveApprovalRefused, "private"):
            self.run_live()
        self.approval.unlink()
        with self.assertRaisesRegex(custodian.LiveApprovalRefused, "private"):
            self.run_live()
        for name, prepare, run, reason in (
            ("template", {"expected_changes": {"template_sha256": "6" * 64}},
             {}, "ARM template"),
            ("custodian-key", {}, {
                "custodian_public_key": self.keys["witness"]["public_key"],
            }, "do not match"),
            ("records", {}, {"records_dir": "stale-records"}, "already holds"),
            ("run-claim", {}, {"registry_dir": "run"}, "already consumed"),
            ("challenge-claim", {}, {"registry_dir": "challenge"},
             "already consumed"),
        ):
            with self.subTest(case=name):
                self.prepare(**prepare)
                if run.get("records_dir") == "stale-records":
                    run = {"records_dir": self.root / f"stale-{self.count}"}
                    run["records_dir"].mkdir(mode=0o700)
                    write_private(run["records_dir"] / "prepared.json", b"{}\n")
                elif "registry_dir" in run:
                    value = (RUN if run["registry_dir"] == "run"
                             else self.fixture.expected.handoff_challenge)
                    write_private(
                        self.registry / f"{run['registry_dir']}-{value}.json",
                        b"{}\n",
                    )
                    run = {}
                with self.assertRaisesRegex(ValueError, reason):
                    self.run_live(**run)
                self.assertEqual(self.fake.raw_calls, [])
                self.assertFalse(any(path.name.startswith("live-approval-")
                                     for path in self.registry.iterdir()))
                self.assertFalse((self.root / f"live-{self.count}").exists())

    def test_existing_group_refuses_without_cleanup(self):
        self.prepare()
        self.fake.preexisting = True
        result = self.run_live()
        self.assertFalse(result.passed)
        self.assertIn("already exists", result.reason)
        self.assertEqual(result.cleanup, "not-created")
        self.assertEqual(self.fake.calls,
                         [("group", "exists", "--name", "uk90-rg")])

    def test_failed_group_create_is_probed_before_cleanup(self):
        self.prepare()
        self.fake.fail_once[("group", "create")] = RuntimeError("create timed out")
        result = self.run_live()
        self.assertFalse(result.passed)
        self.assertEqual(result.cleanup, "not-created")
        self.assertEqual([call[:2] for call in self.fake.calls],
                         [("group", "exists"), ("group", "create"),
                          ("group", "exists")])

    def test_group_created_despite_create_error_is_deleted_when_owned(self):
        self.prepare()

        def fail_after_create(args):
            if args[:2] == ["group", "create"]:
                self.fake.after = None
                raise RuntimeError("create response lost")

        self.fake.after = fail_after_create
        result = self.run_live()
        self.assertFalse(result.passed)
        self.assertEqual(result.cleanup, "deleted")
        self.assertFalse(self.fake.group_present)
        self.assertIn(("group", "delete"),
                      [call[:2] for call in self.fake.calls])

    def test_unprovable_group_probe_is_unconfirmed_and_not_deleted(self):
        self.prepare()
        self.fake.fail_once[("group", "create")] = RuntimeError("create timed out")
        original = self.fake.dispatch
        probes = []

        def dispatch(args):
            if args[:2] == ["group", "exists"] and probes:
                return self.fake.response("maybe")
            if args[:2] == ["group", "exists"]:
                probes.append(args)
            return original(args)

        self.fake.dispatch = dispatch
        result = self.run_live()
        self.assertEqual(result.cleanup, "unconfirmed")
        self.assertIn("manually", result.cleanup_reason)
        self.assertNotIn(("group", "delete"),
                         [call[:2] for call in self.fake.calls])

    def test_upload_failure_revokes_and_cleans_up(self):
        self.prepare()

        def upload(role, path, sas, digest, size):
            if role == "data0":
                raise RuntimeError(f"upload to {sas} failed")
            return {"sha256": digest, "size": size}

        result = self.run_live(upload=upload)
        self.assertFalse(result.passed)
        self.assertIn("upload to <private-endpoint> failed", result.reason)
        self.assert_sanitized(result.reason)
        journal = self.journal()
        self.assertIn("disk.data0.revoke", journal.by_step)
        self.assertNotIn("disk.data0.upload", journal.by_step)
        self.assertIn("data0", self.fake.revoked)
        self.assertNotIn("cleanup.deallocate", journal.by_step)
        self.assert_deleted(result)

    def test_window_closing_during_upload_still_revokes(self):
        self.prepare()

        def upload(role, path, sas, digest, size):
            if role == "os":
                self.clock += timedelta(hours=5)
            return {"sha256": digest, "size": size}

        result = self.run_live(upload=upload)
        self.assertFalse(result.passed)
        self.assertIn("window has closed", result.reason)
        self.assertIn("disk.os.revoke", self.journal().by_step)
        self.assertEqual(self.fake.active_sas, set())
        self.assert_deleted(result)

    def test_lost_grant_response_is_revoked_before_delete(self):
        self.prepare()

        def lose_grant(args):
            if args[:2] == ["disk", "grant-access"]:
                self.fake.after = None
                raise RuntimeError("grant-access timed out")

        self.fake.after = lose_grant
        result = self.run_live()
        self.assertFalse(result.passed)
        journal = self.journal()
        self.assertNotIn("disk.dummy.grant", journal.by_step)
        self.assertIn("disk.dummy.revoke", journal.by_step)
        self.assertEqual(self.fake.active_sas, set())
        self.assert_deleted(result)

    def test_cleanup_revokes_disks_lacking_a_journaled_revoke(self):
        self.prepare()
        self.fake.fail_once[("disk", "revoke-access")] = RuntimeError("revoke failed")

        def upload(role, path, sas, digest, size):
            raise RuntimeError("upload failed")

        result = self.run_live(upload=upload)
        self.assertFalse(result.passed)
        journal = self.journal()
        self.assertNotIn("disk.dummy.revoke", journal.by_step)
        self.assertIn("cleanup.revoke.dummy", journal.by_step)
        self.assertNotIn("cleanup.revoke.os", journal.by_step)
        self.assertEqual(self.fake.active_sas, set())
        self.assert_deleted(result)

    def test_interrupt_is_reported_after_owned_cleanup(self):
        self.prepare()

        def upload(role, path, sas, digest, size):
            if role == "data0":
                raise KeyboardInterrupt
            return {"sha256": digest, "size": size}

        result = self.run_live(upload=upload)
        self.assertFalse(result.passed)
        self.assertIn("Interrupted (KeyboardInterrupt)", result.reason)
        self.assertIn("disk.data0.revoke", self.journal().by_step)
        self.assert_deleted(result)

    def test_termination_signals_raise_keyboard_interrupt(self):
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(KeyboardInterrupt):
            with custodian._interrupt_on_termination():
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(1)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_runtime_over_budget_refuses_swap_and_cleans_up(self):
        self.prepare(self.body(max_vm_running_seconds=30))
        result = self.run_live()
        self.assertFalse(result.passed)
        self.assertIn("exceeds the approved maximum", result.reason)
        self.assertNotIn(("vm", "update"), [call[:2] for call in self.fake.calls])
        self.assertNotIn("vm.swap", self.journal().by_step)
        self.assert_deleted(result)

    def test_foreign_cleanup_inventory_refuses_deletion(self):
        for tamper in ("foreign", "untagged", "outside"):
            with self.subTest(tamper=tamper):
                self.prepare()
                self.fake.cleanup_tamper = tamper
                result = self.run_live()
                self.assertFalse(result.passed)
                self.assertIsNotNone(result.verification_digest)
                self.assertEqual(result.cleanup, "refused")
                self.assertIn("foreign or untagged", result.cleanup_reason)
                self.assertIn("cleanup was not proven", result.reason)
                self.assertNotIn(("group", "delete"),
                                 [call[:2] for call in self.fake.calls])
                self.assertTrue(self.fake.group_present)

    def test_deadline_stops_azure_calls_but_cleanup_still_runs(self):
        self.prepare()

        def jump(args):
            if args[:3] == ["deployment", "group", "create"]:
                self.clock += timedelta(hours=5)

        self.fake.after = jump
        result = self.run_live()
        self.assertFalse(result.passed)
        self.assertIn("window has closed", result.reason)
        self.assertEqual(
            [call[:3] for call in self.fake.calls].count(
                ("deployment", "group", "show")), 0,
        )
        self.assertIn("cleanup.deallocate", self.journal().by_step)
        self.assert_deleted(result)

    def test_failure_reasons_are_sanitized(self):
        self.prepare()
        message = f"boom {SUBSCRIPTION} {RUN} {GROUP} uk90-rg {SAS}"
        self.fake.fail_once[("vm", "deallocate")] = RuntimeError(message)
        self.fake.fail_once[("group", "delete")] = RuntimeError(message)
        result = self.run_live()
        self.assertFalse(result.passed)
        self.assertEqual(result.cleanup, "failed")
        self.assertIn("boom", result.reason)
        self.assertIn("boom", result.cleanup_reason)
        self.assert_sanitized(result.reason)
        self.assert_sanitized(result.cleanup_reason)
        self.assertIn("cleanup.deallocate", self.journal().by_step)

    def cli_files(self, *, digest="0" * 64, not_after_minutes=240):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        fixture = Fixture(expected_changes={
            "preprovision_authorization_sha256": digest,
            "template_sha256": TEMPLATE_SHA,
        })
        mapping = {field.name: getattr(fixture.expected, field.name)
                   for field in fields(custody.Expected)}
        files = {
            "subscription": write_private(
                self.root / "subscription", (SUBSCRIPTION + "\n").encode(),
            ),
            "expected": write_private(
                self.root / f"expected-{digest[:8]}.json",
                json.dumps(mapping).encode(),
            ),
            "plan": write_private(self.root / "plan.json", json.dumps({
                "reviewed_head": "a" * 40, "config_sha256": "b" * 64,
                "efi_sha256": "c" * 64, "raw_sha256": "d" * 64,
                "miz_sha256": "e" * 64,
                "image_paths": {role: str(self.root / f"{role}.vhd")
                                for role in custodian.DISKS},
            }).encode()),
            "not_before": (now - timedelta(minutes=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "not_after": (now + timedelta(minutes=not_after_minutes)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
        }
        return fixture, files

    def cli(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = custodian.main([str(item) for item in argv])
        return code, output.getvalue()

    def approve(self, files, output):
        return self.cli(
            "approve-dry-run", "--expected-json", files["expected"],
            "--subscription-file", files["subscription"],
            "--approver-private-key", self.keys["approver"]["private_key"],
            "--not-before", files["not_before"],
            "--not-after", files["not_after"],
            "--max-vm-running-seconds", 600, "--output", output,
        )

    def live_cli(self, *, fail=None):
        _fixture, files = self.cli_files()
        approval = self.root / "approval.json"
        code, output = self.approve(files, approval)
        self.assertEqual(code, 0, output)
        self.assertEqual(stat.S_IMODE(approval.stat().st_mode), 0o600)
        digest = hashlib.sha256(approval.read_bytes()).hexdigest()
        self.assertIn(digest, output)
        fixture, files = self.cli_files(digest=digest)
        plan = custodian.plan_from_mapping(
            json.loads(files["plan"].read_bytes()), fixture.expected,
        )
        fake = FakeAzure(fixture)
        fake.subscription = SUBSCRIPTION
        fake.group_tags = plan.tags("group")
        if fail is not None:
            fake.fail_once.update(fail)
        registry = self.root / "registry"
        registry.mkdir(mode=0o700)
        with mock.patch.object(custodian, "default_az_runner", fake), \
                mock.patch.object(custodian, "_preflight_uploads",
                                  lambda plan: None), \
                mock.patch.object(custodian, "azure_vhd_upload",
                                  lambda role, path, sas, digest, size: {
                                      "sha256": digest, "size": size}):
            code, output = self.cli(
                "live", "--approval", approval,
                "--approver-public-key", self.keys["approver"]["public_key"],
                "--custodian-private-key",
                self.keys["custodian"]["private_key"],
                "--custodian-public-key", self.keys["custodian"]["public_key"],
                "--expected-json", files["expected"],
                "--subscription-file", files["subscription"],
                "--plan-json", files["plan"],
                "--directory", self.root / "live",
                "--records-dir", self.root / "records",
                "--registry-dir", registry,
            )
        return code, output, fake

    def test_cli_approves_and_runs_a_fake_dry_run(self):
        code, output, fake = self.live_cli()
        self.assertEqual((code, output), (0, "PASS cleanup=deleted\n"))
        self.assertIn(("group", "delete", "--name", "uk90-rg", "--yes"), fake.calls)
        self.assertFalse(fake.group_present)

    def test_cli_failure_output_is_sanitized(self):
        message = f"boom {SUBSCRIPTION} {RUN} {GROUP} uk90-rg"
        code, output, fake = self.live_cli(
            fail={("vm", "deallocate"): RuntimeError(message)},
        )
        self.assertEqual(code, 1)
        self.assertTrue(output.startswith("FAIL "), output)
        self.assertIn("boom", output)
        self.assertIn("cleanup=deleted", output)
        self.assert_sanitized(output)
        self.assertFalse(fake.group_present)

    def test_cli_refuses_bad_approval_and_window(self):
        _fixture, files = self.cli_files(not_after_minutes=301)
        output_path = self.root / "too-long.json"
        code, output = self.approve(files, output_path)
        self.assertEqual(code, 1)
        self.assertIn("at most 300 minutes", output)
        self.assertFalse(output_path.exists())
        _fixture, files = self.cli_files()
        approval = write_private(self.root / "garbled.json", b"{}\n")
        registry = self.root / "registry"
        registry.mkdir(mode=0o700)
        with mock.patch.object(custodian, "default_az_runner") as runner:
            code, output = self.cli(
                "live", "--approval", approval,
                "--approver-public-key", self.keys["approver"]["public_key"],
                "--custodian-private-key",
                self.keys["custodian"]["private_key"],
                "--custodian-public-key", self.keys["custodian"]["public_key"],
                "--expected-json", files["expected"],
                "--subscription-file", files["subscription"],
                "--plan-json", files["plan"],
                "--directory", self.root / "live",
                "--records-dir", self.root / "records",
                "--registry-dir", registry,
            )
        runner.assert_not_called()
        self.assertEqual(code, 1)
        self.assertTrue(output.startswith("FAIL Live approval refused"), output)
        self.assertTrue(output.endswith(" cleanup=not-started\n"), output)
        self.assert_sanitized(output)


if __name__ == "__main__":
    unittest.main()
