# SPDX-License-Identifier: BSD-3-Clause
"""Only synthetic signed evidence: never substitute for actual boots or Azure CLI."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_hyperv_issue90_custody_records import Fixture, signature_key
from test_hyperv_issue90_topology import serial as synthetic_serial

azure = importlib.import_module("hyperv-azure")
admission = importlib.import_module("hyperv_issue90_offline_admission")
custody = importlib.import_module("hyperv_issue90_custody_records")
topology = importlib.import_module("hyperv_issue90_topology")
verifier = importlib.import_module("hyperv_issue90_custody_verifier")

RESERVATION = datetime(2026, 9, 29, 4, 6, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 29, 4, 13, tzinfo=timezone.utc)
DUMMY_RUNTIME = {
    "complete": True, "running_seconds": 10,
    "intervals": [{
        "kind": "dummy", "start_utc": "2026-09-29T04:00:40Z",
        "end_utc": "2026-09-29T04:00:50Z",
    }],
}
TOTAL_RUNTIME = {
    "complete": True, "running_seconds": 20,
    "intervals": [*DUMMY_RUNTIME["intervals"], {
        "kind": "acceptance", "start_utc": "2026-09-29T04:07:05Z",
        "end_utc": "2026-09-29T04:07:15Z",
    }],
}


class CustodyVerifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state_dir = root / "state"
        self.state = topology.plan(
            self.state_dir, "12345678-1234-4234-8234-123456789abc",
        )
        self.offline = admission.OfflineAdmission(
            self.state["run_id"], self.state["operation_id"], "a" * 40,
            "3" * 64, "c" * 64, "b" * 64, "d" * 64,
            "e" * 64, "2" * 64, "f" * 64,
            (
                admission.SeedEvidence("data0", 0, topology.SECTORS,
                                       "4" * 64, "a" * 64),
                admission.SeedEvidence("data7", 7, topology.SECTORS,
                                       "5" * 64, "b" * 64),
            ),
            tuple(admission.BootEvidence(
                source, mode, "e" * 64 if source == "raw" else "2" * 64,
                "a" * 64, "b" * 64,
            ) for source, mode, _ in admission.MODES),
        )
        self.approver = Ed25519PrivateKey.generate()
        approval = {
            "schema": verifier.SCHEMA, "stage": "preprovision",
            "run_id": self.state["run_id"],
            "operation_id": self.state["operation_id"],
            "issued_at_utc": "2026-09-29T03:59:00Z",
            "reviewed_image_sha256": "2" * 64,
            "dummy_image_sha256": "9" * 64,
            "provenance_sha256": "3" * 64,
            "reviewed_head": self.offline.reviewed_head,
            "config_sha256": self.offline.config_sha256,
            "efi_sha256": self.offline.efi_sha256,
            "raw_sha256": self.offline.raw_sha256,
            "miz_sha256": self.offline.miz_sha256,
            "offline_sha256": self.sha(azure.canonical_json(asdict(self.offline))),
            "seed_sha256": {"data0": "4" * 64, "data7": "5" * 64},
            "resource_ids": {
                role: topology.resource_id(self.state, role)
                for role in (*topology.ROLES, *custody.CHILDREN, "deployment")
            } | {
                "group": topology.group_id(self.state),
                "dummy": topology.group_id(self.state)
                + "/providers/Microsoft.Compute/disks/"
                + self.state["prefix"] + "-dummy",
            },
            "template_sha256": "6" * 64,
            "final_envelope_sha256": topology.envelope_sha({
                **self.state, "phase": "prepared", "prepared": {
                    "image_sha256": "2" * 64,
                    "seeds": {
                        "data0": {"sha256": "4" * 64},
                        "data7": {"sha256": "5" * 64},
                    },
                },
            }),
        }
        self.preprovision = self.sign(approval, self.approver)
        self.fixture = Fixture(self.state, {
            "preprovision_authorization_sha256":
                self.sha(self.preprovision),
            "final_envelope_sha256": approval["final_envelope_sha256"],
        })
        self.baseline = b""
        self.reservation_clock = RESERVATION
        self.registry = custody.FileReplayRegistry(root)
        self.addCleanup(self.registry.close)
        self.inputs = admission.OfflineInputs(
            self.state_dir, root / "build", root / "images",
            root / "miz", root / "runner", root / "qemu",
            root / "ovmf-code", root / "ovmf-vars",
            admission.ReviewPins("a" * 40, *("b" * 64 for _ in range(14))),
        )
        self.v = verifier.Verifier(
            self.inputs, self.fixture.expected,
            self.fixture.archive, self.registry,
            custodian_key=signature_key(self.fixture.signer),
            approver_key=signature_key(self.approver),
            witness_key=signature_key(self.fixture.witness),
            clock=lambda: self.reservation_clock,
        )
        self.approval = approval

    @staticmethod
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def sign(body, signer):
        signature = signer.sign(
            (verifier.SCHEMA + "-" + body["stage"] + "\n").encode()
            + azure.canonical_json(body)
        )
        return azure.canonical_json({
            "body": body, "signature": signature.hex(),
        })

    def prepare(self, *, now=RESERVATION, **changes):
        if self.v._offline is None:
            with mock.patch.object(admission, "admit", return_value=self.offline):
                result = self.v.verify_offline()
            self.assertIsInstance(result, admission.OfflineAdmission)
        else:
            result = self.v._offline
        f = self.fixture
        self.assurance = {
            "schema": verifier.SCHEMA, "stage": "assurance",
            "run_id": self.state["run_id"],
            "operation_id": self.state["operation_id"],
            "issued_at_utc": "2026-09-29T04:01:01Z",
            "expires_at_utc": "2026-09-29T04:30:00Z",
            "handoff_sha256": self.sha(f.handoff_raw),
            "preprovision_sha256": self.sha(self.preprovision),
            "challenge": f.expected.handoff_challenge,
            "vm_uuid": f.uuids["vm"],
            "disks": {
                role: {"id": f.ids[role], "uuid": f.uuids[role]}
                for role in verifier.DISKS
            },
            "no_writers": True, "no_prior_acceptance_boot": True,
            "rbac_sha256": f.put({
                "vm_id": f.ids["vm"], "no_other_writers": True, "complete": True,
            })["sha256"],
            "boot_history_sha256": f.put({
                "vm_id": f.ids["vm"], "acceptance_starts": 0,
                "dummy_starts": 1, "complete": True,
            })["sha256"],
            "baseline_generation": "1" * 32,
            "baseline_serial_sha256": self.sha(self.baseline),
            "runtime": DUMMY_RUNTIME,
        }
        self.assurance.update(changes)
        return self.v.verify_handoff(
            result, f.prepared_raw, f.handoff_raw, self.preprovision,
            self.sign(self.assurance, f.witness), self.baseline, now=now,
        )

    def dispatch(self, preboot=None, *, now=RESERVATION, **changes):
        preboot = preboot or self.prepare()
        self.assertIsInstance(preboot, verifier.PreBootCandidate)
        self.authorization = {
            "schema": verifier.SCHEMA, "stage": "acceptance",
            "run_id": self.state["run_id"],
            "operation_id": self.state["operation_id"],
            "issued_at_utc": "2026-09-29T04:02:00Z",
            "expires_at_utc": "2026-09-29T04:29:00Z",
            "challenge": "f" * 32,
            "handoff_sha256": preboot.handoff_sha256,
            "prepared_sha256": preboot.prepared_sha256,
            "preprovision_sha256": preboot.preprovision_sha256,
            "assurance_sha256": preboot.assurance_sha256,
            "vm_id": self.fixture.ids["vm"], "vm_uuid": preboot.vm_uuid,
            "disks": {
                role: {"id": identifier, "uuid": uid}
                for role, identifier, uid in preboot.disks
            },
            "reviewed_image_sha256": preboot.offline.vhd_sha256,
            "offline_sha256": self.sha(azure.canonical_json(asdict(preboot.offline))),
            "seed_sha256": self.fixture.expected.seed_sha256,
            "remaining_seconds": 3590, "one_start": True,
        }
        self.authorization.update(changes)
        return self.v.reserve_dispatch(
            preboot, self.sign(self.authorization, self.approver),
            "f" * 32, now=now,
        )

    def observe(self, permit=None, *, guest=None, baseline=b"", **changes):
        permit = permit or self.dispatch()
        self.assertIsInstance(permit, verifier.DispatchPermit)
        if guest is None:
            guest = synthetic_serial(self.state).replace(
                "TARGET INFO id=12 controller=0",
                "TARGET INFO id=12 controller=1",
            ).replace(
                "DATA_READ PASS role=1 id=12 controller=0",
                "DATA_READ PASS role=1 id=12 controller=1",
            ).encode()
        try:
            devices = topology.parse_serial(guest.decode(), self.state)["guest_devices"]
        except (UnicodeError, ValueError):
            devices = {}
        self.observation = {
            "schema": verifier.SCHEMA, "stage": "observation",
            "run_id": self.state["run_id"],
            "operation_id": self.state["operation_id"],
            "issued_at_utc": "2026-09-29T04:08:00Z",
            "challenge": permit.challenge,
            "dispatch_sha256": permit.claim_sha256,
            "acceptance_sha256": permit.acceptance_sha256,
            "vm_uuid": permit.preboot.vm_uuid,
            "disks": {role: uid for role, _, uid in permit.preboot.disks},
            "start_status": "succeeded",
            "start_receipt_sha256": self.fixture.put({
                "vm_id": self.fixture.ids["vm"], "vm_uuid": permit.preboot.vm_uuid,
                "dispatch_sha256": permit.claim_sha256,
                "status": "Succeeded", "start_count": 1,
            })["sha256"],
            "start_dispatch_count": 1, "observed_boot_count": 1,
            "baseline_generation": "1" * 32,
            "boot_generation": "2" * 32,
            "baseline_serial_sha256": self.sha(baseline),
            "serial_sha256": self.sha(guest),
            "device_binding": {
                role: {
                    "id": self.fixture.ids[role],
                    "uuid": self.fixture.uuids[role],
                    "controller": disk["controller"],
                    "channel": disk["channel"],
                    "address": disk["address"],
                    "instance_crc32": disk["instance_crc32"],
                    "vpd_crc32": disk["vpd_crc32"],
                }
                for role, disk in devices.items()
            },
            "runtime": TOTAL_RUNTIME,
        }
        self.observation.update(changes)
        return self.v.verify_observation(
            permit, self.sign(self.observation, self.fixture.witness),
            guest, baseline, now=NOW,
        )

    def dispose(self, candidate, *, disposition="disposed", **changes):
        f = self.fixture
        permit = (candidate.permit if isinstance(candidate, verifier.CandidateAcceptance)
                  else candidate)
        f.closed["evidence"]["acceptance_authorization_sha256"] = (
            permit.acceptance_sha256
        )
        f.closed["issued_at_utc"] = "2026-09-29T04:10:00Z"
        f.closed["evidence"]["disposition"] = disposition
        f.closed["evidence"]["disposal_receipt"] = f.put({
            "run_id": f.expected.run_id, "disposition": disposition,
        })
        f.closed_raw = f.sign(f.closed)
        f.ack["issued_at_utc"] = "2026-09-29T04:11:00Z"
        f.ack["closed_sha256"] = self.sha(f.closed_raw)
        f.ack_raw = f.sign(f.ack, key=f.witness)
        disposition = {
            "schema": verifier.SCHEMA, "stage": "disposal",
            "run_id": self.state["run_id"],
            "operation_id": self.state["operation_id"],
            "issued_at_utc": "2026-09-29T04:12:30Z",
            "handoff_sha256": permit.preboot.handoff_sha256,
            "dispatch_sha256": permit.claim_sha256,
            "acceptance_sha256": permit.acceptance_sha256,
            "closed_sha256": self.sha(f.closed_raw),
            "ack_sha256": self.sha(f.ack_raw),
            "disposition": disposition,
            "resources": [
                {"role": role, "id": f.ids[role],
                 "uuid": f.uuids["vm"] if role == "vm"
                 else f.uuids.get(role),
                 "status": disposition, "terminal": f.put({
                     "id": f.ids[role],
                     "uuid": f.uuids["vm"] if role == "vm"
                     else f.uuids.get(role), "status": "Succeeded",
                 })}
                for role in verifier.ROLES
            ],
            "all_operations_settled": True, "no_writers": True,
            "vm_deallocated": True,
            "quiescence_sha256": f.put({
                "vm_id": f.ids["vm"], "vm_uuid": permit.preboot.vm_uuid,
                "complete": True, "no_writers": True,
                "vm_deallocated": True,
            })["sha256"],
            "runtime": TOTAL_RUNTIME,
        }
        disposition.update(changes)
        return self.v.verify_disposal(
            candidate, f.closed_raw, f.ack_raw,
            self.sign(disposition, f.witness), now=NOW,
        )

    def test_complete_synthetic_stages_stay_offline(self):
        preboot = self.prepare()
        self.assertIsInstance(preboot, verifier.PreBootCandidate)
        permit = self.dispatch(preboot)
        self.assertIsInstance(permit, verifier.DispatchPermit)
        self.assertFalse(permit.cloud_authorized)
        candidate = self.observe(permit)
        self.assertIsInstance(candidate, verifier.CandidateAcceptance)
        self.assertEqual(candidate.evidence["controller_count"], 2)
        self.assertNotIn("result", candidate.evidence)
        with self.assertRaises(TypeError):
            candidate.evidence["guest_devices"]["os"]["address"] = (0, 0, 0)
        self.assertEqual(candidate.evidence["guest_devices"]["data7"]["address"][2], 7)
        result = self.dispose(candidate)
        self.assertIsInstance(result, verifier.FinalAcceptance)
        self.assertEqual(result.result, "PASS")
        self.assertFalse(result.cloud_authorized)
        self.assertEqual(result.scope, "offline_only")

    def test_reservation_is_durable_and_stale_boot_cannot_become_candidate(self):
        permit = self.dispatch()
        self.assertEqual(permit.reserved_at_utc, "2026-09-29T04:06:00.000000Z")
        start = self.state_dir.parent / (
            "start-" + self.state["run_id"] + ".json"
        )
        claim = azure.parse_strict_json(start.read_bytes(), "Durable start claim")
        self.assertEqual(claim["reserved_at_utc"], permit.reserved_at_utc)
        self.assertEqual(
            permit.claim_sha256, self.sha(azure.canonical_json(claim)),
        )
        stale_runtime = {
            "complete": True, "running_seconds": 20,
            "intervals": [*DUMMY_RUNTIME["intervals"], {
                "kind": "acceptance", "start_utc": "2026-09-29T04:02:05Z",
                "end_utc": "2026-09-29T04:02:15Z",
            }],
        }
        self.assertIsInstance(self.observe(
            permit, issued_at_utc="2026-09-29T04:03:00Z",
            runtime=stale_runtime,
        ), verifier.Refusal)
        self.assertIsInstance(self.observe(
            permit, runtime=stale_runtime,
        ), verifier.Refusal)
        candidate = self.observe(permit)
        self.assertIsInstance(candidate, verifier.CandidateAcceptance)
        self.assertIsInstance(self.dispose(candidate), verifier.FinalAcceptance)

    def test_reservation_preserves_microseconds_and_requires_trusted_clock(self):
        self.reservation_clock = RESERVATION.replace(microsecond=654321)
        permit = self.dispatch()
        self.assertEqual(permit.reserved_at_utc, "2026-09-29T04:06:00.654321Z")
        self.assertIsInstance(self.observe(
            permit, issued_at_utc="2026-09-29T04:06:00Z",
        ), verifier.Refusal)
        almost_current = {
            "complete": True, "running_seconds": 20,
            "intervals": [*DUMMY_RUNTIME["intervals"], {
                "kind": "acceptance", "start_utc": "2026-09-29T04:06:00Z",
                "end_utc": "2026-09-29T04:06:10Z",
            }],
        }
        self.assertIsInstance(
            self.observe(permit, runtime=almost_current), verifier.Refusal,
        )
        self.assertIsInstance(self.observe(permit), verifier.CandidateAcceptance)

    def test_reservation_cannot_precede_independent_handoff_assurance(self):
        preboot = self.prepare(
            now=NOW, issued_at_utc="2026-09-29T04:07:00Z",
        )
        self.assertIsInstance(preboot, verifier.PreBootCandidate)
        self.assertIsInstance(self.dispatch(preboot), verifier.Refusal)
        self.assertFalse((self.state_dir.parent / (
            "start-" + self.state["run_id"] + ".json"
        )).exists())

    def test_trusted_call_and_handoff_at_0410_refuse_0406_reservation(self):
        call_at = datetime(2026, 9, 29, 4, 10, tzinfo=timezone.utc)
        preboot = self.prepare(now=call_at)
        self.assertIsInstance(preboot, verifier.PreBootCandidate)
        self.reservation_clock = RESERVATION
        self.assertIsInstance(
            self.dispatch(preboot, now=call_at), verifier.Refusal,
        )
        self.assertIsInstance(
            self.dispatch(preboot, now=RESERVATION), verifier.Refusal,
        )
        self.assertFalse((self.state_dir.parent / (
            "start-" + self.state["run_id"] + ".json"
        )).exists())
        self.reservation_clock = call_at
        permit = self.dispatch(preboot, now=call_at)
        self.assertIsInstance(permit, verifier.DispatchPermit)
        self.assertIsInstance(self.observe(permit), verifier.Refusal)

    def test_trusted_call_time_alone_rejects_backwards_clock(self):
        call_at = datetime(2026, 9, 29, 4, 10, tzinfo=timezone.utc)
        preboot = self.prepare()
        self.reservation_clock = RESERVATION
        self.assertIsInstance(
            self.dispatch(preboot, now=call_at), verifier.Refusal,
        )
        self.assertFalse((self.state_dir.parent / (
            "start-" + self.state["run_id"] + ".json"
        )).exists())
        self.reservation_clock = call_at.replace(
            minute=9, second=59, microsecond=999999,
        )
        self.assertIsInstance(
            self.dispatch(preboot, now=call_at), verifier.Refusal,
        )
        self.reservation_clock = call_at.replace(microsecond=1)
        self.assertIsInstance(
            self.dispatch(preboot, now=call_at), verifier.DispatchPermit,
        )

    def test_persisted_clock_high_water_survives_registry_reopen(self):
        permit = self.dispatch()
        self.assertIsInstance(permit, verifier.DispatchPermit)
        second = custody.FileReplayRegistry(self.state_dir.parent)
        self.addCleanup(second.close)
        earlier = {
            "run_id": "b" * 32,
            "reserved_at_utc": "2026-09-29T04:05:59.999999Z",
        }
        with self.assertRaisesRegex(ValueError, "clock moved backwards"):
            second.claim_start(earlier["run_id"], earlier)
        self.assertFalse((self.state_dir.parent / (
            "start-" + earlier["run_id"] + ".json"
        )).exists())
        equal = {
            "run_id": "c" * 32,
            "reserved_at_utc": permit.reserved_at_utc,
        }
        with self.assertRaisesRegex(ValueError, "clock moved backwards"):
            second.claim_start(equal["run_id"], equal)
        later = {
            "run_id": "e" * 32,
            "reserved_at_utc": "2026-09-29T04:06:00.000001Z",
        }
        second.claim_start(later["run_id"], later)
        self.assertEqual(
            second._read("start", later["run_id"]), later,
        )

    def test_incomplete_prior_reservation_blocks_new_run(self):
        previous = {
            "run_id": "b" * 32, "reserved_at_utc": "not-a-time",
        }
        self.registry._create("start", previous["run_id"], previous)
        reopened = custody.FileReplayRegistry(self.state_dir.parent)
        self.addCleanup(reopened.close)
        next_run = {
            "run_id": "c" * 32,
            "reserved_at_utc": "2026-09-29T04:06:00.000000Z",
        }
        with self.assertRaisesRegex(ValueError, "timestamp is invalid"):
            reopened.claim_start(next_run["run_id"], next_run)
        self.assertFalse((self.state_dir.parent / (
            "start-" + next_run["run_id"] + ".json"
        )).exists())

    def test_concurrent_reservations_share_one_clock_high_water(self):
        other = custody.FileReplayRegistry(self.state_dir.parent)
        self.addCleanup(other.close)
        when = "2026-09-29T04:07:00.000000Z"
        claims = (
            (self.registry, "b" * 32, {"run_id": "b" * 32, "reserved_at_utc": when}),
            (other, "c" * 32, {"run_id": "c" * 32, "reserved_at_utc": when}),
        )

        def reserve(arguments):
            registry, run_id, claim = arguments
            try:
                registry.claim_start(run_id, claim)
            except ValueError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(
                sorted(executor.map(reserve, claims)), [False, True],
            )

    def test_closed_registry_cannot_create_reservation_lock(self):
        self.registry.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            self.registry.claim_start(
                "b" * 32,
                {"run_id": "b" * 32,
                 "reserved_at_utc": "2026-09-29T04:06:00.000000Z"},
            )
        self.assertFalse(
            (self.state_dir.parent / ".reservation-clock.lock").exists()
        )

    def test_stale_trusted_reservation_clock_refuses_before_claim(self):
        preboot = self.prepare()
        self.reservation_clock = datetime(
            2026, 9, 29, 4, 0, tzinfo=timezone.utc,
        )
        self.assertIsInstance(self.dispatch(preboot), verifier.Refusal)
        self.assertFalse((self.state_dir.parent / (
            "start-" + self.state["run_id"] + ".json"
        )).exists())
        self.reservation_clock = RESERVATION
        self.assertIsInstance(self.dispatch(preboot), verifier.DispatchPermit)

    def test_missing_private_offline_evidence_refuses(self):
        result = self.v.verify_offline()
        self.assertIsInstance(result, verifier.Refusal)
        self.assertEqual(result.stage, "offline")
        self.assertIsNone(self.v._offline)

    def test_offline_policy_allowance_must_match_the_admitted_plan(self):
        policy = {"vm_tags": {"policy-pack": "nonprod"}, "user_assigned_identity": None}

        def offline(expected):
            candidate = verifier.Verifier(
                self.inputs, expected, self.fixture.archive, self.registry,
                custodian_key=signature_key(self.fixture.signer),
                approver_key=signature_key(self.approver),
                witness_key=signature_key(self.fixture.witness),
                clock=lambda: self.reservation_clock,
            )
            with mock.patch.object(admission, "admit", return_value=self.offline):
                return candidate.verify_offline()

        pinned = replace(self.fixture.expected, azure_policy=policy)
        self.assertIsInstance(offline(pinned), verifier.Refusal)
        self.state["azure_policy"] = policy
        topology.save(self.state_dir, self.state)
        envelope = topology.envelope_sha({
            **self.state, "phase": "prepared", "prepared": {
                "image_sha256": "2" * 64,
                "seeds": {"data0": {"sha256": "4" * 64},
                          "data7": {"sha256": "5" * 64}},
            },
        })
        self.assertNotEqual(envelope, self.fixture.expected.final_envelope_sha256)
        self.assertIsInstance(offline(replace(
            self.fixture.expected, final_envelope_sha256=envelope,
        )), verifier.Refusal)
        self.assertIsInstance(offline(replace(
            pinned, final_envelope_sha256=envelope,
        )), admission.OfflineAdmission)

    def test_unreviewed_or_tampered_offline_shape_refuses(self):
        for alteration in (
            replace(self.offline, source_sha256="9" * 64),
            replace(self.offline, vhd_sha256="9" * 64),
            replace(self.offline, boots=self.offline.boots[:3]),
            replace(self.offline, seeds=self.offline.seeds[:1]),
            replace(self.offline, seeds=(
                replace(self.offline.seeds[0], sectors=topology.SECTORS - 1),
                self.offline.seeds[1],
            )),
        ):
            with self.subTest(alteration=alteration):
                with mock.patch.object(admission, "admit", return_value=alteration):
                    refused = self.v.verify_offline()
                self.assertEqual(refused.stage, "offline")

    def test_preprovision_requires_independent_key_exact_source_and_ids(self):
        with mock.patch.object(admission, "admit", return_value=self.offline):
            self.assertIsInstance(self.v.verify_offline(), admission.OfflineAdmission)
        for edit in (
            {"config_sha256": "9" * 64},
            {"efi_sha256": "9" * 64},
            {"raw_sha256": "9" * 64},
            {"miz_sha256": "9" * 64},
            {"offline_sha256": "9" * 64},
            {"dummy_image_sha256": "8" * 64},
            {"resource_ids": {**self.approval["resource_ids"],
                              "vm": self.fixture.ids["nic"]}},
        ):
            with self.subTest(edit=edit):
                approval = self.sign({**self.approval, **edit}, self.approver)
                assurance = self.prepare(
                    preprovision_sha256=self.sha(approval),
                )
                self.assertIsInstance(assurance, verifier.Refusal)
        self.assertIsInstance(self.v.verify_handoff(
            self.offline, self.fixture.prepared_raw, self.fixture.handoff_raw,
            self.sign(self.approval, self.fixture.witness),
            self.sign(self.assurance, self.fixture.witness), self.baseline,
            now=NOW,
        ), verifier.Refusal)

    def test_wrong_key_run_digest_challenge_and_assertions_refuse(self):
        for alteration in (
            {"run_id": "9" * 32},
            {"handoff_sha256": "9" * 64},
            {"challenge": "9" * 32},
            {"no_writers": False},
            {"boot_history_sha256": "9" * 64},
            {"runtime": {"complete": False, "intervals": [], "running_seconds": 0}},
        ):
            with self.subTest(alteration=alteration):
                refused = self.prepare(**alteration)
                self.assertIsInstance(refused, verifier.Refusal)
        preboot = self.prepare()
        self.assertIsInstance(preboot, verifier.PreBootCandidate)
        self.assertIsInstance(self.v.verify_handoff(
            self.offline, self.fixture.prepared_raw, self.fixture.handoff_raw,
            self.preprovision, self.sign(self.assurance, self.approver),
            self.baseline, now=NOW,
        ), verifier.Refusal)

    def test_approval_and_dispatch_identity_tamper_refuses(self):
        preboot = self.prepare()
        for alteration in (
            {"vm_uuid": "22222222-2222-4222-8222-222222222222"},
            {"challenge": "9" * 32},
            {"seed_sha256": {"data0": "5" * 64, "data7": "4" * 64}},
            {"remaining_seconds": 3600},
            {"one_start": False},
        ):
            with self.subTest(alteration=alteration):
                self.assertIsInstance(
                    self.dispatch(preboot, **alteration), verifier.Refusal,
                )
        permit = self.dispatch(preboot)
        self.assertIsInstance(permit, verifier.DispatchPermit)

    def test_start_is_durably_consumed_even_on_lost_response(self):
        permit = self.dispatch()
        self.assertIsInstance(permit, verifier.DispatchPermit)
        self.assertIsInstance(self.v.reserve_dispatch(
            permit.preboot, self.sign(self.authorization, self.approver),
            "f" * 32, now=RESERVATION,
        ), verifier.Refusal)
        lost = self.observe(permit, start_status="lost", observed_boot_count=0)
        self.assertEqual(lost.reason, "lost_start_consumed_disposal_required")
        self.assertIsInstance(self.observe(
            permit, start_status="succeeded",
        ), verifier.Refusal)
        another = verifier.Verifier(
            self.inputs, self.fixture.expected,
            self.fixture.archive, self.registry,
            custodian_key=signature_key(self.fixture.signer),
            approver_key=signature_key(self.approver),
            witness_key=signature_key(self.fixture.witness),
            clock=lambda: self.reservation_clock,
        )
        with mock.patch.object(admission, "admit", return_value=self.offline):
            self.assertIsInstance(another.verify_offline(), admission.OfflineAdmission)
        self.assertIsInstance(another.verify_handoff(
            self.offline, self.fixture.prepared_raw, self.fixture.handoff_raw,
            self.preprovision, self.sign(self.assurance, self.fixture.witness),
            self.baseline, now=NOW,
        ), verifier.Refusal)

    def test_start_claim_fsync_failure_does_not_reopen_budget(self):
        preboot = self.prepare()
        claim = self.registry.claim_start

        def after_create(run, value):
            claim(run, value)
            raise OSError("simulated lost fsync acknowledgment")

        with mock.patch.object(
            self.registry, "claim_start", side_effect=after_create,
        ):
            self.assertIsInstance(self.dispatch(preboot), verifier.Refusal)
        self.assertIsInstance(self.dispatch(preboot), verifier.Refusal)
        self.assertTrue(
            (self.state_dir.parent / ("start-" + self.state["run_id"] + ".json")).exists()
        )

    def test_dispatch_challenge_collision_burns_start(self):
        preboot = self.prepare()
        self.registry.claim_dispatch_challenge("f" * 32, {"taken": True})
        self.assertIsInstance(self.dispatch(preboot), verifier.Refusal)
        self.assertIsInstance(self.dispatch(preboot), verifier.Refusal)
        self.assertTrue(
            (self.state_dir.parent / ("start-" + self.state["run_id"] + ".json")).exists()
        )

    def test_dummy_runtime_exhaustion_and_unknown_interval_refuse(self):
        self.fixture.handoff["evidence"]["running_seconds"] = 3600
        self.fixture.handoff_raw = self.fixture.sign(self.fixture.handoff)
        exhausted = {"complete": True, "running_seconds": 3600, "intervals": [{
            "kind": "dummy", "start_utc": "2026-09-29T03:00:50Z",
            "end_utc": "2026-09-29T04:00:50Z",
        }]}
        self.assertIsInstance(
            self.prepare(runtime=exhausted), verifier.Refusal,
        )

    def test_runtime_boundary_and_unknown_interval(self):
        exact = {"complete": True, "running_seconds": 3600, "intervals": [{
            "kind": "acceptance", "start_utc": "2026-09-29T04:00:00Z",
            "end_utc": "2026-09-29T05:00:00Z",
        }]}
        self.assertEqual(verifier._runtime(exact)[1], 3600)
        over = {**exact, "running_seconds": 3601, "intervals": [{
            **exact["intervals"][0], "end_utc": "2026-09-29T05:00:01Z",
        }]}
        with self.assertRaisesRegex(ValueError, "60 minutes"):
            verifier._runtime(over)
        unknown = {"complete": True, "running_seconds": 10, "intervals": [{
            "kind": "unknown", "start_utc": "2026-09-29T04:00:40Z",
            "end_utc": "2026-09-29T04:00:50Z",
        }]}
        self.assertIsInstance(self.prepare(runtime=unknown), verifier.Refusal)

    def test_stale_serial_and_wrong_lun_refuse(self):
        permit = self.dispatch()
        for alteration in (
            {"boot_generation": "1" * 32},
            {"serial_sha256": "f" * 64},
            {"observed_boot_count": 0},
            {"runtime": DUMMY_RUNTIME},
            {"start_receipt_sha256": "f" * 64},
            {"device_binding": {"data0": {"uuid": self.fixture.uuids["data7"]}}},
        ):
            with self.subTest(alteration=alteration):
                self.assertIsInstance(
                    self.observe(permit, **alteration), verifier.Refusal,
                )
        stale = synthetic_serial(self.state).encode()
        self.assertIsInstance(
            self.observe(permit, guest=stale, baseline=stale), verifier.Refusal,
        )
        invalid = synthetic_serial(self.state).replace("address=0:0:7", "address=0:0:6")
        self.assertIsInstance(
            self.observe(permit, guest=invalid.encode()), verifier.Refusal,
        )
        self.assertIsInstance(self.observe(permit), verifier.CandidateAcceptance)

    def test_tampered_ledger_and_swapped_offline_state_refuse(self):
        permit = self.dispatch()
        self.state_dir.joinpath("state.json").write_bytes(b"{}")
        self.assertIsInstance(self.observe(permit), verifier.Refusal)
        self.assertIsInstance(self.v.verify_disposal(
            permit, self.fixture.closed_raw, self.fixture.ack_raw,
            b"", now=NOW,
        ), verifier.Refusal)

    def test_tampered_durable_start_or_observation_refuses(self):
        permit = self.dispatch()
        root = self.state_dir.parent
        start = root / ("start-" + self.state["run_id"] + ".json")
        original = start.read_bytes()
        start.write_bytes(b"{}")
        self.assertIsInstance(self.observe(permit), verifier.Refusal)
        start.write_bytes(original)
        candidate = self.observe(permit)
        self.assertIsInstance(candidate, verifier.CandidateAcceptance)
        observation = root / ("observation-" + self.state["run_id"] + ".json")
        observation.write_bytes(b"{}")
        self.assertIsInstance(self.dispose(candidate), verifier.Refusal)

    def test_state_swapped_during_offline_load_refuses(self):
        load = topology.load

        def swap_after_load(directory):
            state = load(directory)
            self.state_dir.joinpath("state.json").write_bytes(b"{}")
            return state

        with mock.patch.object(admission, "admit", return_value=self.offline):
            with mock.patch.object(topology, "load", side_effect=swap_after_load):
                result = self.v.verify_offline()
        self.assertEqual(result.stage, "offline")
        self.assertIsNone(self.v._offline)

    def test_failed_attempt_can_close_but_never_pass(self):
        permit = self.dispatch()
        lost = self.observe(permit, start_status="lost", observed_boot_count=0)
        self.assertIsInstance(lost, verifier.Refusal)
        result = self.dispose(permit)
        self.assertEqual(result, verifier.Refusal(
            "disposal", "failed_attempt_disposal_recorded", True,
        ))
        self.assertIsInstance(self.dispose(permit), verifier.Refusal)

    def test_quarantined_candidate_cannot_be_final(self):
        candidate = self.observe()
        result = self.dispose(candidate, disposition="quarantined")
        self.assertEqual(result, verifier.Refusal(
            "disposal", "quarantine_recorded_not_final", True,
        ))

    def test_baseline_swap_before_observation_and_expired_capture_refuse(self):
        permit = self.dispatch()
        self.assertIsInstance(self.observe(
            permit, baseline=b"other",
        ), verifier.Refusal)
        self.assertIsInstance(self.observe(
            permit, baseline_generation="3" * 32,
        ), verifier.Refusal)
        self.assertIsInstance(self.observe(
            permit, issued_at_utc="2026-09-29T04:30:00Z",
        ), verifier.Refusal)
        self.assertIsInstance(self.observe(permit), verifier.CandidateAcceptance)

    def test_missing_disposal_ack_inventory_and_runtime_refuse(self):
        candidate = self.observe()
        self.assertIsInstance(candidate, verifier.CandidateAcceptance)
        self.assertIsInstance(self.v.verify_disposal(
            candidate, self.fixture.closed_raw, b"", b"", now=NOW,
        ), verifier.Refusal)
        for alteration in (
            {"resources": []},
            {"all_operations_settled": False},
            {"runtime": DUMMY_RUNTIME},
            {"no_writers": False},
            {"quiescence_sha256": "f" * 64},
        ):
            with self.subTest(alteration=alteration):
                self.assertIsInstance(
                    self.dispose(candidate, **alteration), verifier.Refusal,
                )
        self.assertIsInstance(self.dispose(candidate), verifier.FinalAcceptance)

    def test_disposal_signed_before_closed_ack_or_observation_refuses(self):
        candidate = self.observe()
        self.assertIsInstance(candidate, verifier.CandidateAcceptance)
        for timestamp in (
            "2026-09-29T04:02:20Z",
            "2026-09-29T04:10:30Z",
            "2026-09-29T04:11:00Z",
        ):
            with self.subTest(timestamp=timestamp):
                result = self.dispose(candidate, issued_at_utc=timestamp)
                self.assertIsInstance(result, verifier.Refusal)
                self.assertFalse(result.disposal_recorded)
        self.assertIsInstance(self.dispose(candidate), verifier.FinalAcceptance)

    def test_closed_before_candidate_observation_refuses(self):
        permit = self.dispatch()
        candidate = self.observe(
            permit, issued_at_utc="2026-09-29T04:11:30Z",
        )
        self.assertIsInstance(candidate, verifier.CandidateAcceptance)
        self.assertIsInstance(self.dispose(candidate), verifier.Refusal)

    def test_replaced_terminal_or_missing_archive_refuses_disposal(self):
        candidate = self.observe()
        f = self.fixture
        wrong = f.put({
            "id": f.ids["os"], "uuid": f.uuids["data0"],
            "status": "Succeeded",
        })
        resources = [
            {"role": role, "id": f.ids[role],
             "uuid": f.uuids["vm"] if role == "vm" else f.uuids.get(role),
             "status": "disposed", "terminal": wrong}
            for role in verifier.ROLES
        ]
        self.assertIsInstance(
            self.dispose(candidate, resources=resources), verifier.Refusal,
        )
        self.assertIsInstance(
            self.dispose(candidate, quiescence_sha256="9" * 64), verifier.Refusal,
        )
        self.assertIsInstance(self.dispose(candidate), verifier.FinalAcceptance)

if __name__ == "__main__":
    unittest.main()
