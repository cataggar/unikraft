# SPDX-License-Identifier: BSD-3-Clause
"""Owner-attested #90 acceptance lane: fake Azure and mocked admission only."""

import contextlib
from dataclasses import asdict, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import test_hyperv_issue90_custodian as custodian_tests
from test_hyperv_issue90_custody_records import Fixture
from test_hyperv_issue90_topology import serial as synthetic_serial

acceptance = importlib.import_module("hyperv_issue90_acceptance")
admission = importlib.import_module("hyperv_issue90_offline_admission")
azure = importlib.import_module("hyperv-azure")
custodian = importlib.import_module("hyperv_issue90_custodian")
custody = importlib.import_module("hyperv_issue90_custody_records")
topology = importlib.import_module("hyperv_issue90_topology")
verifier = importlib.import_module("hyperv_issue90_custody_verifier")

SUBSCRIPTION = "12345678-1234-4234-8234-123456789abc"
WINDOW = ("2026-09-29T04:00:00Z", "2026-09-29T08:00:00Z")
START = datetime(2026, 9, 29, 4, 1, 0, 250000, tzinfo=timezone.utc)
P_ISSUED = "2026-09-29T04:00:30Z"
BASELINE = "dummy firmware boot\n"
SAS_ERROR = ("BootDiagnostics failed for "
             "https://diag.blob.core.windows.net/serial.log?sv=1&sig=secret")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_private(path, raw):
    return custodian_tests.write_private(Path(path), raw)


def guest_serial(state):
    return synthetic_serial(state).replace(
        "TARGET INFO id=12 controller=0", "TARGET INFO id=12 controller=1",
    ).replace(
        "DATA_READ PASS role=1 id=12 controller=0",
        "DATA_READ PASS role=1 id=12 controller=1",
    )


def partial_serial(state):
    text = guest_serial(state)
    return text[:text.index("HYPERV_TOPOLOGY FINAL ")]


def child_argv(*bodies):
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(SCRIPTS)!r})
        sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
        import importlib
        acceptance = importlib.import_module("hyperv_issue90_acceptance")
        from test_hyperv_issue90_acceptance import FakeLocal
    """) + "".join(textwrap.dedent(body) for body in bodies)
    return [sys.executable, "-c", code]


RAW_READY = """
    import json, time
    ready = {{"protocol": acceptance.PROTOCOL, "stage": "ready",
              "passed": True, "reason": None}}
    ready.update({change})
    sys.stdout.buffer.write(json.dumps(
        ready, sort_keys=True, separators=(",", ":")).encode() + b"\\n")
    sys.stdout.buffer.flush()
"""
READY = """
    import time
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc) - timedelta(seconds={shift})
    sys.stdout.buffer.write(acceptance.encode_response({{
        "stage": "ready", "passed": True, "reason": None,
        "now_utc": now.strftime(acceptance.PRECISE_UTC)}}))
    sys.stdout.buffer.flush()
"""


class Clock:
    def __init__(self, start=START):
        self.now = start
        self.sleeps = []

    def __call__(self):
        self.now += timedelta(milliseconds=500)
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += timedelta(seconds=seconds)


class AcceptanceAzure(custodian_tests.FakeAzure):
    def __init__(self, fixture, serials):
        super().__init__(fixture)
        self.serials = list(serials)
        self.baseline = BASELINE
        self.starts = 0
        self.start_error = None
        self.poll_hook = None

    def dispatch(self, args):
        if args[:2] == ["vm", "start"]:
            self.starts += 1
            if self.start_error is not None:
                raise self.start_error
            return self.response(None)
        if args[:3] == ["vm", "boot-diagnostics", "get-boot-log"]:
            if not self.starts or self.start_error is not None:
                if self.baseline is None:
                    raise RuntimeError(SAS_ERROR)
                text = self.baseline
            else:
                if self.poll_hook is not None:
                    self.poll_hook()
                text = (self.serials.pop(0) if len(self.serials) > 1
                        else self.serials[0])
            return custodian.RunnerResult(stdout=json.dumps(text).encode() + b"\n")
        return super().dispatch(args)


class Recording:
    def __init__(self, inner):
        self.inner = inner
        self.calls = []

    def __getattr__(self, name):
        method = getattr(self.inner, name)

        def call(*args):
            result = method(*args)
            self.calls.append((name, result))
            return result
        return call


class AcceptanceLaneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_dir = self.root / "state"
        self.state = topology.plan(self.state_dir, SUBSCRIPTION)
        self.keys = custodian.generate_test_keys(self.root / "keys")
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
        self.fresh = replace(self.offline, boots=tuple(
            replace(boot, serial_sha256="7" * 64, report_sha256="8" * 64)
            for boot in self.offline.boots
        ))
        envelope = topology.envelope_sha({
            **self.state, "phase": "prepared", "prepared": {
                "image_sha256": "2" * 64,
                "seeds": {"data0": {"sha256": "4" * 64},
                          "data7": {"sha256": "5" * 64}},
            },
        })
        self.fixture = Fixture(self.state, {
            "template_sha256": custodian_tests.TEMPLATE_SHA,
            "final_envelope_sha256": envelope,
        })
        self.bind(self.sign_preprovision())
        self.count = 0
        self.fake = None

    def make_plan(self, expected):
        return custodian.CustodianPlan(
            expected=expected, reviewed_head="a" * 40,
            config_sha256="b" * 64, efi_sha256="d" * 64,
            raw_sha256="e" * 64, miz_sha256="f" * 64,
            image_paths={role: self.root / f"{role}.vhd"
                         for role in custodian.DISKS},
        )

    def sign_preprovision(self, *, offline=None, signer="approver", **changes):
        body = acceptance.preprovision_body(
            expected=self.fixture.expected,
            plan=self.make_plan(self.fixture.expected),
            offline_sha256=verifier.reproducible_offline_sha256(
                offline or self.offline),
            issued_at_utc=P_ISSUED,
        )
        body.update(changes)
        return acceptance.sign_statement(body, self.keys[signer]["private_key"])

    def bind(self, preprovision_raw):
        self.preprovision_raw = preprovision_raw
        self.fixture.expected = replace(
            self.fixture.expected,
            preprovision_authorization_sha256=sha(preprovision_raw),
        )
        self.plan = self.make_plan(self.fixture.expected)

    def approval_raw(self, *, sign=None, **changes):
        body = custodian.approval_body(
            subscription=SUBSCRIPTION, run_id=self.fixture.expected.run_id,
            operation_id=self.fixture.expected.operation_id,
            group_id=self.fixture.expected.resource_ids["group"],
            not_before_utc=WINDOW[0], not_after_utc=WINDOW[1],
            max_vm_running_seconds=3600, nonce="f" * 32,
            mode=custodian.LIVE_ACCEPTANCE_MODE,
            preprovision_sha256=sha(self.preprovision_raw),
        )
        body.update(changes)
        return custodian_tests.sign_approval(
            body, self.keys[sign or "approver"]["private_key"],
        )

    def public(self, role):
        return custodian.load_public_key(self.keys[role]["public_key"])

    def upload(self, role, path, sas, digest, size):
        return {"sha256": digest, "size": size}

    def run_acceptance(self, serials=None, *, admit=None, approval=None,
                       preprovision=None, configure=None, registry=None,
                       verifier_claims=(), max_poll_seconds=600,
                       lane_skew=None, correct=True):
        self.count += 1
        number = self.count
        self.clock = Clock()
        self.fake = AcceptanceAzure(self.fixture, serials or [
            partial_serial(self.state), guest_serial(self.state),
        ])
        self.fake.subscription = SUBSCRIPTION
        self.fake.group_tags = self.plan.tags("group")
        if configure is not None:
            configure(self.fake)
        approval_path = write_private(
            self.root / f"approval-{number}.json",
            approval or self.approval_raw(),
        )
        preprovision_path = write_private(
            self.root / f"preprovision-{number}.json",
            preprovision or self.preprovision_raw,
        )
        if registry is None:
            registry = self.root / f"registry-{number}"
            registry.mkdir(mode=0o700)
        self.registry = registry
        verifier_dir = self.root / f"verifier-{number}"
        verifier_dir.mkdir(mode=0o700)
        for name in verifier_claims:
            write_private(verifier_dir / name, b"{}\n")
        ledger = custody.FileReplayRegistry(verifier_dir)
        self.addCleanup(ledger.close)
        inputs = admission.OfflineInputs(
            self.state_dir, self.root / "build", self.root / "images",
            self.root / "miz", self.root / "runner", self.root / "qemu",
            self.root / "ovmf-code", self.root / "ovmf-vars",
            admission.ReviewPins("a" * 40, *("b" * 64 for _ in range(14))),
        )
        self.local = acceptance.LocalVerifier(
            inputs, self.fixture.expected, ledger,
            custodian_key=self.public("custodian"),
            approver_key=self.public("approver"),
            witness_key=self.public("witness"),
            clock=self.clock, sleep=self.clock.sleep,
        )
        self.verifier = Recording(self.local)
        lane_clock, offset = self.clock, None
        if lane_skew is not None:
            def raw():
                return self.clock() + timedelta(seconds=lane_skew)
            lane_clock = raw
            if correct:
                lane_clock, offset = self.ready_clock(raw)
        self.directory = self.root / f"live-{number}"
        self.records = self.root / f"records-{number}"
        with mock.patch.object(admission, "admit",
                               return_value=admit or self.fresh) as admitted:
            self.admitted = admitted
            return acceptance.run_acceptance(
                approval_path, preprovision=preprovision_path, keys=self.keys,
                expected=self.fixture.expected, plan=self.plan,
                subscription=SUBSCRIPTION, state=self.state,
                directory=self.directory, records_dir=self.records,
                registry_dir=registry, verifier=self.verifier,
                runner=self.fake, upload=self.upload, clock=lane_clock,
                sleep=self.clock.sleep, max_poll_seconds=max_poll_seconds,
                clock_offset_seconds=offset,
            )

    def ready_clock(self, raw):
        """Derive the lane clock from the verifier's real `ready` line."""
        stdout = io.BytesIO()
        acceptance.serve(self.local, io.BytesIO(), stdout)
        ready = acceptance.decode_response(
            stdout.getvalue().splitlines(True)[0], "ready")

        def monotonic():
            return (self.clock() - START).total_seconds()
        clock = acceptance.VerifierClock(
            ready["now_utc"], received_utc=raw(), anchor=monotonic(),
            monotonic=monotonic,
        )
        return clock, clock.offset_seconds

    def journal(self):
        return custodian.Journal(self.directory / "journal.jsonl")

    def steps(self):
        return [entry["step"] for entry in self.journal().entries]

    def stage_results(self):
        return {name: result for name, result in self.verifier.calls}

    def starts(self):
        return [call for call in self.fake.calls if call[:2] == ("vm", "start")]

    def assert_no_azure(self):
        self.assertIsNotNone(self.fake)
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(os.path.lexists(self.directory))

    def assert_cleaned(self, result):
        self.assertEqual(result.cleanup, "deleted", result.cleanup_reason)
        self.assertFalse(self.fake.group_present)
        self.assertEqual(self.steps().count("cleanup.exists"), 1)

    def assert_failed_attempt_recorded(self, result):
        self.assertFalse(result.passed)
        self.assertEqual(result.verifier_result, "FAIL")
        disposal = self.stage_results()["disposal"]
        self.assertFalse(disposal["passed"])
        self.assertTrue(disposal["disposal_recorded"])
        self.assertEqual(disposal["reason"], "failed_attempt_disposal_recorded")
        self.assertTrue((self.records / "disposal.json").exists())

    def assert_private_summary(self):
        text = (self.records / "summary.json").read_text()
        for value in (SUBSCRIPTION, self.fixture.expected.run_id,
                      self.state["prefix"], self.plan.group_name(),
                      *self.state["disk_ids"].values(), "synthetic-secret",
                      "sig=secret", self.fixture.uuids["vm"]):
            self.assertNotIn(str(value).lower(), text.lower())
        return json.loads(text)

    def test_signed_acceptance_passes_with_fresh_admission_serials(self):
        self.assertNotEqual(asdict(self.fresh), asdict(self.offline))
        result = self.run_acceptance()
        self.assertTrue(result.passed, result.reasons)
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.verifier_result, "PASS")
        self.assertEqual(result.stage, "disposal")
        self.assertTrue(result.owner_attested_test_keys)
        self.assert_cleaned(result)
        self.assertEqual(self.admitted.call_count, 1)
        self.assertEqual(
            [name for name, _ in self.verifier.calls],
            ["offline", "handoff", "dispatch", "observation", "disposal"],
        )
        self.assertTrue(all(item["passed"] for _, item in self.verifier.calls))
        self.assertEqual(
            self.stage_results()["offline"]["offline_sha256"],
            verifier.reproducible_offline_sha256(self.offline),
        )
        self.assertEqual(self.fake.starts, 1)
        self.assertEqual(len(self.starts()), 1)
        steps = self.steps()
        order = [steps.index(step) for step in (
            "vm.deallocate", "vm.swap", "serial.baseline", "witness.rbac",
            "witness.boot-history", "witness.start-receipt", "serial.poll-1",
            "serial.poll-2", "acceptance.deallocate", "acceptance.deallocation",
            "cleanup.delete", "cleanup.exists", "custody.return-receipt",
            "witness.quiescence",
        )]
        self.assertEqual(order, sorted(order))
        self.assertLess(steps.index("acceptance.start"),
                        steps.index("witness.start-receipt"))
        self.assertNotIn("serial.poll-3", steps)
        self.assertTrue(all(call[-2:] == ("--subscription", SUBSCRIPTION)
                            for call in self.fake.raw_calls))
        for name in acceptance.RECORD_NAMES:
            path = self.records / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, name)
        summary = self.assert_private_summary()
        self.assertEqual(summary["result"], "PASS")
        self.assertIs(summary["owner_attested_test_keys"], True)
        self.assertIs(summary["independent_custody"], False)
        self.assertLessEqual(len(self.local.archive), 128)
        self.assertFalse(any(b"HYPERV_TOPOLOGY" in raw
                             for raw in self.local.archive.values()))
        handoff = json.loads((self.records / "handoff.json").read_bytes())
        acceptance_record = json.loads(
            (self.records / "acceptance.json").read_bytes())["body"]
        self.assertEqual(
            acceptance_record["remaining_seconds"],
            3600 - handoff["body"]["evidence"]["running_seconds"],
        )
        self.assertNotEqual(acceptance_record["challenge"],
                            self.fixture.expected.handoff_challenge)

    def assert_verifier_clock_domain(self, skew):
        result = self.run_acceptance(lane_skew=skew)
        self.assertTrue(result.passed, result.reasons)
        self.assertEqual(result.verifier_result, "PASS")
        self.assert_cleaned(result)
        self.assertEqual(len(self.starts()), 1)
        self.assertLessEqual(abs(result.clock_offset_seconds - skew), 2)
        summary = self.assert_private_summary()
        self.assertEqual(summary["clock_offset_seconds"],
                         result.clock_offset_seconds)
        note = self.journal().by_step["verifier.clock-offset"]
        self.assertEqual(self.steps()[0], "verifier.clock-offset")
        raw = (self.directory / "archive" / note["ref"]["sha256"]).read_bytes()
        self.assertEqual(json.loads(raw), {
            "clock_offset_seconds": result.clock_offset_seconds,
        })
        verifier_now = self.clock.now
        for name in ("prepared.json", "assurance.json", "acceptance.json",
                     "observation.json", "disposal.json"):
            issued = custody._utc(json.loads(
                (self.records / name).read_bytes())["body"]["issued_at_utc"])
            self.assertLessEqual(issued, verifier_now, name)

    def test_lane_clock_ahead_of_verifier_uses_ready_time(self):
        self.assert_verifier_clock_domain(125)

    def test_lane_clock_behind_verifier_uses_ready_time(self):
        self.assert_verifier_clock_domain(-125)

    def test_uncorrected_lane_clock_ahead_loses_the_attempt(self):
        result = self.run_acceptance(lane_skew=125, correct=False)
        self.assertFalse(result.passed)
        self.assertTrue(any("statement_issued_in_future" in reason
                            for reason in result.reasons), result.reasons)
        self.assertEqual(self.starts(), [])
        self.assert_cleaned(result)
        self.assertIsNone(result.clock_offset_seconds)

    def test_unavailable_baseline_is_recorded_without_storage_tokens(self):
        result = self.run_acceptance(
            configure=lambda fake: setattr(fake, "baseline", None),
        )
        self.assertTrue(result.passed, result.reasons)
        note = self.journal().by_step["serial.baseline-unavailable"]
        raw = (self.directory / "archive" / note["ref"]["sha256"]).read_bytes()
        self.assertEqual(json.loads(raw), {"status": "unavailable",
                                           "error": "RuntimeError"})
        for path in self.directory.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"sig=secret", path.read_bytes(), path)

    def test_offline_refusal_makes_no_azure_call(self):
        result = self.run_acceptance(
            admit=admission.OfflineRefusal("boot", "serial_mismatch"),
        )
        self.assertFalse(result.passed)
        self.assertEqual((result.stage, result.cleanup), ("offline", "not-started"))
        self.assertIn("verifier offline: boot_serial_mismatch", result.reasons)
        self.assert_no_azure()
        self.assertEqual(list(self.registry.iterdir()), [])

    def test_offline_admission_differing_from_preprovision_makes_no_azure_call(self):
        result = self.run_acceptance(
            admit=replace(self.fresh, implementation_sha256="0" * 64),
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.stage, "offline")
        self.assertIn("differs from the pre-provision", result.reasons[0])
        self.assert_no_azure()

    def test_dispatch_refusal_never_starts_and_cleans_up(self):
        run_id = self.fixture.expected.run_id
        result = self.run_acceptance(verifier_claims=(f"start-{run_id}.json",))
        self.assertFalse(result.passed)
        self.assertEqual(result.stage, "dispatch")
        self.assertEqual(self.starts(), [])
        self.assertEqual(self.fake.starts, 0)
        self.assertEqual([name for name, _ in self.verifier.calls],
                         ["offline", "handoff", "dispatch"])
        self.assertTrue(any(reason.startswith("verifier dispatch:")
                            for reason in result.reasons))
        self.assert_cleaned(result)
        self.assertFalse((self.records / "disposal.json").exists())
        self.assertFalse(any(step.startswith("serial.poll") for step in self.steps()))

    def test_failed_start_is_never_retried_and_disposal_is_recorded(self):
        result = self.run_acceptance(configure=lambda fake: setattr(
            fake, "start_error", RuntimeError("start response lost"),
        ))
        self.assertEqual(self.fake.starts, 1)
        self.assertEqual(len(self.starts()), 1)
        steps = self.steps()
        self.assertIn("acceptance.start-lost", steps)
        self.assertNotIn("witness.start-receipt", steps)
        self.assertFalse(any(step.startswith("serial.poll") for step in steps))
        self.assertIn("acceptance.deallocate", steps)
        self.assertEqual(self.stage_results()["observation"]["reason"],
                         "lost_start_consumed_disposal_required")
        self.assertTrue(any("single VM start" in reason
                            for reason in result.reasons))
        self.assert_failed_attempt_recorded(result)
        self.assert_cleaned(result)

    def test_serial_without_final_is_bounded_then_deallocated_and_fails(self):
        result = self.run_acceptance(
            [partial_serial(self.state)], max_poll_seconds=60,
        )
        polls = [step for step in self.steps() if step.startswith("serial.poll-")]
        self.assertTrue(1 <= len(polls) <= 5, polls)
        self.assertLessEqual(max(self.clock.sleeps), 120)
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(
            sum(call[:2] == ("vm", "deallocate") for call in self.fake.calls), 2,
        )
        self.assertTrue(any("final result" in reason for reason in result.reasons))
        self.assertNotIn("observation", self.stage_results())
        self.assert_failed_attempt_recorded(result)
        self.assert_cleaned(result)

    def test_guest_failure_serial_fails_after_one_poll(self):
        failed = guest_serial(self.state).replace(
            "HYPERV_TOPOLOGY FINAL PASS", "HYPERV_TOPOLOGY FINAL FAIL",
        )
        result = self.run_acceptance([failed])
        self.assertEqual([step for step in self.steps()
                          if step.startswith("serial.poll-")], ["serial.poll-1"])
        self.assertTrue(any("did not prove" in reason for reason in result.reasons))
        self.assert_failed_attempt_recorded(result)
        self.assert_cleaned(result)

    def test_single_controller_serial_is_refused_by_the_verifier(self):
        result = self.run_acceptance([synthetic_serial(self.state)])
        self.assertEqual(self.stage_results()["observation"]["reason"],
                         "stale_partial_or_unproven_boot")
        self.assert_failed_attempt_recorded(result)
        self.assert_cleaned(result)

    def test_interrupt_while_polling_still_cleans_up_and_records(self):
        def interrupt():
            raise KeyboardInterrupt
        result = self.run_acceptance(
            configure=lambda fake: setattr(fake, "poll_hook", interrupt),
        )
        self.assertTrue(any(reason.startswith("Interrupted (KeyboardInterrupt)")
                            for reason in result.reasons))
        self.assertEqual(len(self.starts()), 1)
        self.assert_failed_attempt_recorded(result)
        self.assert_cleaned(result)

    def test_consumed_approval_is_refused_before_azure(self):
        self.assertTrue(self.run_acceptance().passed)
        approval = self.approval_raw()
        with self.assertRaises(ValueError):
            self.run_acceptance(approval=approval, registry=self.registry)
        self.assert_no_azure()

    def assert_gate_refused(self, **kwargs):
        with self.assertRaises(custodian.LiveApprovalRefused):
            self.run_acceptance(**kwargs)
        self.assert_no_azure()
        self.assertEqual(self.admitted.call_count, 0)

    def test_approval_for_another_preprovision_is_refused(self):
        self.assert_gate_refused(approval=self.approval_raw(
            preprovision_sha256="0" * 64,
        ))

    def test_preprovision_not_bound_by_expected_is_refused(self):
        self.assert_gate_refused(
            preprovision=self.sign_preprovision(issued_at_utc="2026-09-29T04:00:31Z"),
        )

    def test_preprovision_signed_by_another_role_is_refused(self):
        self.bind(self.sign_preprovision(signer="witness"))
        self.assert_gate_refused()

    def test_preprovision_differing_from_plan_is_refused(self):
        self.bind(self.sign_preprovision(config_sha256="0" * 64))
        self.assert_gate_refused()

    def test_preprovision_issued_in_future_is_refused(self):
        self.bind(self.sign_preprovision(issued_at_utc="2026-09-29T05:00:00Z"))
        self.assert_gate_refused()

    def test_dry_run_approval_cannot_authorize_acceptance(self):
        body = custodian.approval_body(
            subscription=SUBSCRIPTION, run_id=self.fixture.expected.run_id,
            operation_id=self.fixture.expected.operation_id,
            group_id=self.fixture.expected.resource_ids["group"],
            not_before_utc=WINDOW[0], not_after_utc=WINDOW[1],
            max_vm_running_seconds=600, nonce="f" * 32,
        )
        self.assert_gate_refused(approval=custodian_tests.sign_approval(
            body, self.keys["approver"]["private_key"],
        ))

    def test_acceptance_approval_limits_are_enforced(self):
        self.assert_gate_refused(approval=self.approval_raw(
            max_vm_running_seconds=3601,
        ))
        self.assert_gate_refused(approval=self.approval_raw(
            not_after_utc="2026-09-29T09:01:00Z",
        ))
        self.assert_gate_refused(approval=self.approval_raw(sign="witness"))
        body = json.loads(self.approval_raw())["body"]
        del body["preprovision_sha256"]
        self.assert_gate_refused(approval=custodian_tests.sign_approval(
            body, self.keys["approver"]["private_key"],
        ))

    def test_acceptance_approval_cannot_run_the_dry_run(self):
        fake = AcceptanceAzure(self.fixture, [""])
        registry = self.root / "dry-registry"
        registry.mkdir(mode=0o700)
        approval = write_private(self.root / "dry-approval.json",
                                 self.approval_raw())
        with self.assertRaises(custodian.LiveApprovalRefused):
            custodian.run_live(
                approval, approver_public_key=self.keys["approver"]["public_key"],
                custodian_private_key=self.keys["custodian"]["private_key"],
                custodian_public_key=self.keys["custodian"]["public_key"],
                expected=self.fixture.expected, plan=self.plan,
                subscription=SUBSCRIPTION, directory=self.root / "dry-live",
                records_dir=self.root / "dry-records", registry_dir=registry,
                runner=fake, upload=self.upload, clock=Clock(),
            )
        self.assertEqual(fake.calls, [])

    def test_require_preprovision_checks_signature_plan_and_time(self):
        now = datetime(2026, 9, 29, 4, 1, tzinfo=timezone.utc)
        body = acceptance.require_preprovision(
            self.preprovision_raw, approver_public_key=self.public("approver"),
            expected=self.fixture.expected, plan=self.plan, now=now,
        )
        self.assertEqual(body["offline_sha256"],
                         verifier.reproducible_offline_sha256(self.offline))
        with self.assertRaises(ValueError):
            acceptance.require_preprovision(
                self.preprovision_raw, approver_public_key=self.public("approver"),
                expected=self.fixture.expected, plan=self.plan,
                now=datetime(2026, 9, 29, 4, 0, 30, tzinfo=timezone.utc),
            )
        with self.assertRaises(ValueError):
            acceptance.require_preprovision(
                self.preprovision_raw, approver_public_key=self.public("custodian"),
                expected=self.fixture.expected, plan=self.plan, now=now,
            )


class SerialStatusTests(unittest.TestCase):
    def test_status_follows_guest_markers(self):
        self.assertIsNone(acceptance.serial_status("booting\n"))
        self.assertEqual(acceptance.serial_status(
            "HYPERV_TOPOLOGY FINAL PASS devices=3\n"), "final")
        self.assertEqual(acceptance.serial_status(
            "\x1b[0mHYPERV_TOPOLOGY FINAL PASS devices=3\nmain returned 0\n"),
            "complete")
        for text in ("HYPERV_TOPOLOGY FINAL FAIL x\n", "main returned 3\n",
                     "[ 1.0] Unikraft Crash\n",
                     "UK_HYPERV_ACCEPTANCE_UNAVAILABLE: x\n"):
            self.assertEqual(acceptance.serial_status(text), "failed", text)


class FakeLocal:
    def __init__(self, fail=None, error=None):
        self.fail = fail
        self.error = error
        self.calls = []
        self.clock = lambda: datetime.now(timezone.utc)

    def _result(self, stage, **extra):
        self.calls.append(stage)
        if stage == self.error:
            raise RuntimeError("private detail")
        if stage == self.fail:
            failed = ({"result": "FAIL", "disposal_recorded": False}
                      if stage == "disposal" else {})
            return {"stage": stage, "passed": False, "reason": "refused_here",
                    **failed}
        return {"stage": stage, "passed": True, "reason": None, **extra}

    def offline(self):
        return self._result("offline", offline_sha256="a" * 64)

    def handoff(self, prepared, handoff, preprovision, assurance, baseline, blobs):
        ok = (prepared, handoff, preprovision, assurance, baseline, blobs) == (
            b"P", b"H", b"A", b"W", b"x" * 300000, [b"1", b"2" * 65536],
        )
        return self._result("handoff", consumed_seconds=7 if ok else 0)

    def dispatch(self, acceptance, challenge):
        return self._result(
            "dispatch", claim_sha256="b" * 64,
            reserved_at_utc="2026-09-29T04:06:00.123456Z",
            expires_at_utc="2026-09-29T04:30:00Z", max_remaining_seconds=3593,
        )

    def observation(self, witness_record, serial, baseline, blobs):
        return self._result("observation", running_seconds=20)

    def disposal(self, closed, ack, disposal, blobs):
        return self._result("disposal", result="PASS", disposal_recorded=True)


REQUESTS = (
    ("offline", {}),
    ("handoff", {"prepared": b"P", "handoff": b"H", "preprovision": b"A",
                 "assurance": b"W", "baseline": b"x" * 300000,
                 "blobs": [b"1", b"2" * 65536]}),
    ("dispatch", {"acceptance": b"C", "challenge": "c" * 32}),
    ("observation", {"witness_record": b"O", "serial": b"S", "baseline": b"",
                     "blobs": [b"R"]}),
    ("disposal", {"closed": b"X", "ack": b"K", "disposal": b"D",
                  "blobs": [b"T"]}),
)


class ProtocolTests(unittest.TestCase):
    def serve(self, local, lines):
        stdin = io.BytesIO(b"".join(lines))
        stdout = io.BytesIO()
        code = acceptance.serve(local, stdin, stdout)
        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        return code, responses

    def test_request_codec_round_trips_and_is_strict(self):
        for stage, values in REQUESTS:
            line = acceptance.encode_request(stage, **values)
            self.assertTrue(line.endswith(b"\n"))
            self.assertEqual(acceptance.decode_request(line), (stage, values))
        line = acceptance.encode_request("dispatch", acceptance=b"C",
                                         challenge="c" * 32)
        message = json.loads(line)
        for change in ({"protocol": "other"}, {"extra": 1},
                       {"acceptance": "Qw"}, {"acceptance": "Qx=="},
                       {"challenge": "C" * 32}, {"stage": "start"}):
            with self.assertRaises(ValueError, msg=change):
                acceptance.decode_request(azure.canonical_json({**message, **change}))
        with self.assertRaises(ValueError):
            acceptance.decode_request(json.dumps(message).encode() + b"\n")
        with self.assertRaises(ValueError):
            acceptance.encode_request("handoff", prepared=b"P")
        with self.assertRaises(ValueError):
            acceptance.encode_request(
                "observation", witness_record=b"O", serial=b"S", baseline=b"",
                blobs=[b"x" * (custody.MAX_ARCHIVE + 1)],
            )

    def test_response_checks_are_exact(self):
        good = {"stage": "dispatch", "passed": True, "reason": None,
                "claim_sha256": "b" * 64,
                "reserved_at_utc": "2026-09-29T04:06:00.123456Z",
                "expires_at_utc": "2026-09-29T04:30:00Z",
                "max_remaining_seconds": 3593}
        line = acceptance.encode_response(good)
        self.assertEqual(acceptance.decode_response(line, "dispatch"), good)
        with self.assertRaises(ValueError):
            acceptance.decode_response(line, "handoff")
        for change in ({"reason": "x"}, {"passed": 1},
                       {"max_remaining_seconds": 3601},
                       {"reserved_at_utc": "2026-09-29T04:06:00Z"}):
            with self.assertRaises(ValueError, msg=change):
                acceptance.check_response("dispatch", {**good, **change})
        refused = {"stage": "dispatch", "passed": False, "reason": "No Spaces"}
        with self.assertRaises(ValueError):
            acceptance.check_response("dispatch", refused)
        with self.assertRaises(ValueError):
            acceptance.check_response("disposal", {
                "stage": "disposal", "passed": True, "reason": None,
                "result": "FAIL", "disposal_recorded": True,
            })

    def test_serve_runs_stages_in_order(self):
        local = FakeLocal()
        code, responses = self.serve(local, [
            acceptance.encode_request(stage, **values)
            for stage, values in REQUESTS
        ])
        self.assertEqual(code, 0)
        self.assertEqual([item["stage"] for item in responses],
                         ["ready", *(stage for stage, _ in REQUESTS)])
        self.assertTrue(all(item["passed"] for item in responses))
        self.assertEqual(responses[2]["consumed_seconds"], 7)
        self.assertEqual(local.calls, [stage for stage, _ in REQUESTS])

    def test_serve_refuses_out_of_order_and_malformed_requests(self):
        code, responses = self.serve(FakeLocal(), [
            acceptance.encode_request(*REQUESTS[2][:1], **REQUESTS[2][1]),
            acceptance.encode_request("offline"),
        ])
        self.assertEqual(code, 1)
        self.assertEqual(responses[1], {
            "protocol": acceptance.PROTOCOL, "stage": "dispatch",
            "passed": False, "reason": "stage_out_of_order",
        })
        self.assertEqual(len(responses), 2)
        code, responses = self.serve(FakeLocal(), [b"{not json}\n"])
        self.assertEqual(code, 1)
        self.assertEqual(responses[1]["stage"], "error")
        code, responses = self.serve(None, [acceptance.encode_request("offline")])
        self.assertEqual(code, 1)
        self.assertEqual(responses, [{
            "protocol": acceptance.PROTOCOL, "stage": "ready", "passed": False,
            "reason": "verifier_setup_failed",
        }])

    def test_serve_ends_after_refused_dispatch_and_hides_errors(self):
        local = FakeLocal(fail="dispatch")
        code, responses = self.serve(local, [
            acceptance.encode_request(stage, **values)
            for stage, values in REQUESTS
        ])
        self.assertEqual(code, 1)
        self.assertEqual(responses[-1]["reason"], "refused_here")
        self.assertEqual(local.calls, ["offline", "handoff", "dispatch"])
        code, responses = self.serve(FakeLocal(error="offline"), [
            acceptance.encode_request("offline"),
        ])
        self.assertEqual(responses[-1]["reason"], "verifier_internal_error")
        self.assertNotIn(b"private detail", json.dumps(responses).encode())

    def test_failed_observation_still_allows_disposal(self):
        local = FakeLocal(fail="observation")
        code, responses = self.serve(local, [
            acceptance.encode_request(stage, **values)
            for stage, values in REQUESTS
        ])
        self.assertEqual(code, 0)
        self.assertEqual(responses[-1]["stage"], "disposal")

    def child(self, body):
        return child_argv(body)

    def test_remote_verifier_round_trip_over_a_subprocess(self):
        remote = acceptance.RemoteVerifier(self.child("""
            raise SystemExit(acceptance.serve(
                FakeLocal(), sys.stdin.buffer, sys.stdout.buffer))
        """), timeouts={stage: 60 for stage in acceptance.TIMEOUTS})
        self.addCleanup(remote.close)
        self.assertEqual(remote.offline()["offline_sha256"], "a" * 64)
        values = REQUESTS[1][1]
        self.assertEqual(remote.handoff(
            values["prepared"], values["handoff"], values["preprovision"],
            values["assurance"], values["baseline"], values["blobs"],
        )["consumed_seconds"], 7)
        permit = remote.dispatch(b"C", "c" * 32)
        self.assertEqual(permit["max_remaining_seconds"], 3593)
        self.assertTrue(remote.observation(b"O", b"S", b"", [b"R"])["passed"])
        final = remote.disposal(b"X", b"K", b"D", [b"T"])
        self.assertEqual(final["result"], "PASS")
        self.assertIsNone(remote.process)

    def test_remote_verifier_fails_closed_on_timeout_and_eof(self):
        slow = acceptance.RemoteVerifier(
            self.child("import time; time.sleep(30)"), timeouts={"ready": 0.5},
        )
        self.addCleanup(slow.close)
        result = acceptance._call_verifier(slow, "offline")
        self.assertEqual(result["reason"], "verifier_transport_failed")
        self.assertIsNone(slow.process)
        self.assertEqual(acceptance._call_verifier(slow, "offline")["reason"],
                         "verifier_transport_failed")
        closed = acceptance.RemoteVerifier([sys.executable, "-c", "pass"])
        self.assertEqual(acceptance._call_verifier(closed, "offline")["reason"],
                         "verifier_transport_failed")
        garbage = acceptance.RemoteVerifier(
            [sys.executable, "-c", "print('hello')"],
        )
        self.assertEqual(acceptance._call_verifier(garbage, "offline")["reason"],
                         "verifier_transport_failed")
        disposal = acceptance._call_verifier(closed, "disposal", b"", b"", b"", [])
        self.assertEqual((disposal["result"], disposal["disposal_recorded"]),
                         ("FAIL", False))
        with self.assertRaises(ValueError):
            acceptance.RemoteVerifier([])

    def test_invalid_local_response_is_refused(self):
        class Bad:
            def offline(self):
                return {"stage": "offline", "passed": True, "reason": None}
        self.assertEqual(acceptance._call_verifier(Bad(), "offline")["reason"],
                         "verifier_response_invalid")

    def test_ready_reports_the_verifier_time(self):
        local = FakeLocal()
        local.clock = lambda: datetime(2026, 9, 29, 4, 0, 1, 25,
                                       tzinfo=timezone.utc)
        code, responses = self.serve(local, [])
        self.assertEqual(code, 1)
        self.assertEqual(responses, [{
            "protocol": acceptance.PROTOCOL, "stage": "ready", "passed": True,
            "reason": None, "now_utc": "2026-09-29T04:00:01.000025Z",
        }])

        def broken():
            raise RuntimeError("private detail")
        local.clock = broken
        code, responses = self.serve(local, [acceptance.encode_request("offline")])
        self.assertEqual(responses, [{
            "protocol": acceptance.PROTOCOL, "stage": "ready", "passed": False,
            "reason": "verifier_clock_unavailable",
        }])
        self.assertEqual(local.calls, [])
        ready = {"stage": "ready", "passed": True, "reason": None,
                 "now_utc": "2026-09-29T04:00:01.000025Z"}
        self.assertEqual(acceptance.check_response("ready", ready), ready)
        for change in ({"now_utc": "2026-09-29T04:00:01Z"}, {"now_utc": None},
                       {"now_utc": "2026-02-30T04:00:01.000000Z"}):
            with self.assertRaises(ValueError, msg=change):
                acceptance.check_response("ready", {**ready, **change})
        missing = dict(ready)
        del missing["now_utc"]
        with self.assertRaises(ValueError):
            acceptance.check_response("ready", missing)

    def test_verifier_clock_lags_the_ready_time(self):
        ticks = [100.0]
        clock = acceptance.VerifierClock(
            "2026-09-29T04:00:00.500000Z",
            received_utc=datetime(2026, 9, 29, 4, 2, 5, 750000,
                                  tzinfo=timezone.utc),
            anchor=100.0, monotonic=lambda: ticks[0],
        )
        self.assertEqual(clock.offset_seconds, 125.25)
        self.assertEqual(clock(), datetime(2026, 9, 29, 4, 0, 0, 500000,
                                           tzinfo=timezone.utc))
        ticks[0] = 160.25
        self.assertEqual(clock(), datetime(2026, 9, 29, 4, 1, 0, 750000,
                                           tzinfo=timezone.utc))
        ticks[0] = 99.0
        self.assertEqual(clock(), datetime(2026, 9, 29, 4, 0, 0, 500000,
                                           tzinfo=timezone.utc))
        for value in ("2026-09-29T04:00:00Z", None, 5):
            with self.assertRaises(ValueError):
                acceptance.VerifierClock(
                    value, received_utc=datetime.now(timezone.utc), anchor=0.0)
        self.assertEqual(acceptance.clock_offset(-125.4), -125)
        for value in (float("nan"), float("inf"), True, "1", 3600.5):
            with self.assertRaises(ValueError, msg=value):
                acceptance.clock_offset(value)
        shifted = acceptance.offset_clock(
            125, clock=lambda: datetime(2026, 9, 29, 4, 2, 5, tzinfo=timezone.utc))
        self.assertEqual(shifted(), datetime(2026, 9, 29, 4, 0, 0,
                                             tzinfo=timezone.utc))

    def test_remote_verifier_derives_the_verifier_clock_from_ready(self):
        remote = acceptance.RemoteVerifier(
            child_argv(READY.format(shift=125), "time.sleep(30)\n"),
            timeouts={"ready": 60},
        )
        self.addCleanup(remote.close)
        before = datetime.now(timezone.utc)
        clock = remote.connect()
        self.assertIsInstance(clock, acceptance.VerifierClock)
        self.assertGreaterEqual(remote.clock_offset_seconds, 125)
        self.assertLess(remote.clock_offset_seconds, 125 + 30)
        lane = clock()
        self.assertLessEqual(lane, datetime.now(timezone.utc)
                             - timedelta(seconds=125))
        self.assertGreater(lane, before - timedelta(seconds=126))
        self.assertIs(remote.connect(), clock)
        remote.close(kill=True)
        with self.assertRaises(acceptance.VerifierTransportError):
            remote.offline()

    def test_remote_verifier_refuses_missing_invalid_or_distant_ready_time(self):
        for body in (
            RAW_READY.format(change="{}"),
            RAW_READY.format(change='{"now_utc": "2026-09-29T04:00:00Z"}'),
            RAW_READY.format(change='{"now_utc": 5}'),
            RAW_READY.format(change='{"now_utc": "garbage"}'),
            READY.format(shift=7200),
            READY.format(shift=-7200),
        ):
            remote = acceptance.RemoteVerifier(
                child_argv(body, "time.sleep(30)\n"), timeouts={"ready": 60},
            )
            self.addCleanup(remote.close)
            started = time.monotonic()
            with self.assertRaises(acceptance.VerifierTransportError):
                remote.connect()
            self.assertLess(time.monotonic() - started, 20)
            self.assertIsNone(remote.process)
            self.assertIsNone(remote.clock)

    def test_stalled_reader_times_out_within_the_stage_deadline(self):
        remote = acceptance.RemoteVerifier(child_argv(READY.format(shift=0), """
            for _ in range(4):
                sys.stdin.buffer.raw.read(4096)
                time.sleep(0.05)
            time.sleep(60)
        """), timeouts={"ready": 60, "handoff": 1})
        self.addCleanup(remote.close)
        remote.connect()
        started = time.monotonic()
        result = acceptance._call_verifier(
            remote, "handoff", b"P", b"H", b"A", b"W",
            b"x" * (2 * 1024 * 1024), [],
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result["reason"], "verifier_transport_failed")
        self.assertLess(elapsed, 4)
        self.assertIsNone(remote.process)

    def test_partial_response_times_out_within_the_stage_deadline(self):
        remote = acceptance.RemoteVerifier(child_argv(READY.format(shift=0), """
            sys.stdin.buffer.readline()
            sys.stdout.buffer.write(b'{"protocol":"' + b"x" * 300000)
            sys.stdout.buffer.flush()
            time.sleep(60)
        """), timeouts={"ready": 60, "offline": 1})
        self.addCleanup(remote.close)
        remote.connect()
        started = time.monotonic()
        result = acceptance._call_verifier(remote, "offline")
        self.assertEqual(result["reason"], "verifier_transport_failed")
        self.assertLess(time.monotonic() - started, 4)
        self.assertIsNone(remote.process)


class LocalVerifierTests(unittest.TestCase):
    def local(self, clock, sleep):
        local = acceptance.LocalVerifier.__new__(acceptance.LocalVerifier)
        local.clock = clock
        local.sleep = sleep
        local.max_skew = acceptance.MAX_SKEW_SECONDS
        return local

    @staticmethod
    def statement(issued):
        return azure.canonical_json({"body": {"issued_at_utc": issued},
                                     "signature": "0" * 128})

    def test_skew_guard_waits_bounded_then_refuses(self):
        now = [datetime(2026, 9, 29, 4, 0, 0, 500000, tzinfo=timezone.utc)]
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += timedelta(seconds=seconds)
        local = self.local(lambda: now[0], sleep)
        settled = local._settle(self.statement("2026-09-29T04:00:03Z"))
        self.assertGreaterEqual(settled, datetime(2026, 9, 29, 4, 0, 3,
                                                  tzinfo=timezone.utc))
        self.assertLessEqual(sum(sleeps), 3)
        sleeps.clear()
        frozen = self.local(lambda: now[0], sleeps.append)
        self.assertIsNone(frozen._settle(self.statement("2026-09-29T05:00:00Z")))
        self.assertLessEqual(sum(sleeps), acceptance.MAX_SKEW_SECONDS)
        self.assertEqual(frozen._settle(b"not json"), now[0])

    def test_stages_are_ordered_and_single_use(self):
        local = self.local(lambda: datetime.now(timezone.utc), lambda _: None)
        local.archive = {}
        local.used = set()
        local._offline = local._preboot = local._permit = local._candidate = None
        self.assertEqual(local.dispatch(b"", "c" * 32)["reason"],
                         "stage_out_of_order")
        self.assertEqual(local.disposal(b"", b"", b"", [])["result"], "FAIL")
        local.verifier = mock.Mock()
        local.verifier.verify_offline.return_value = verifier.Refusal(
            "offline", "Offline Admission Failed!")
        self.assertEqual(local.offline()["reason"], "offline_admission_failed")
        self.assertEqual(local.offline()["reason"], "stage_out_of_order")
        local.verifier.verify_offline.assert_called_once()


class AzTextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def recorder(self, stdout=None, error=None):
        def runner(arguments, *, timeout):
            if error is not None:
                raise error
            return custodian.RunnerResult(stdout=stdout)
        return custodian.CustodianRecorder(
            self.root / "custodian", runner=runner,
            clock=lambda: datetime(2026, 9, 29, 4, tzinfo=timezone.utc),
        )

    def test_json_string_plain_text_and_large_output(self):
        observed = self.recorder(b'"line one\\nline two"\n').az_text(
            "serial.one", ["vm", "boot-diagnostics", "get-boot-log"],
        )
        self.assertEqual(observed.value, "line one\nline two")
        self.assertEqual(
            (self.root / "custodian/archive" / observed.ref["sha256"]).read_bytes(),
            b'"line one\\nline two"\n',
        )
        self.assertEqual(self.recorder(b"plain\n").az_text("serial.two", ["x"]).value,
                         "plain\n")
        self.assertEqual(self.recorder(b"").az_text("serial.three", ["x"]).value, "")
        large = b"A" * (custody.MAX_ARCHIVE + 1)
        observed = self.recorder(large).az_text("serial.four", ["x"])
        self.assertEqual(observed.value, large.decode())
        manifest = json.loads(
            (self.root / "custodian/archive" / observed.ref["sha256"]).read_bytes())
        self.assertEqual(manifest, {"schema": custodian.TEXT_MANIFEST_SCHEMA,
                                    "sha256": sha(large), "size": len(large)})
        self.assertEqual(
            (self.root / "custodian/text" / sha(large)).read_bytes(), large,
        )
        entry = custodian.Journal(self.root / "custodian/journal.jsonl").by_step[
            "serial.four"]
        self.assertIsNotNone(entry["started_at_utc"])

    def test_refuses_tokens_json_objects_and_binary(self):
        for stdout in (b'{"a": 1}', b"\xff\xfe", b'"https://x.blob.core.windows.net/?sig=1"',
                       b"x" * (custodian.TEXT_LIMIT + 1)):
            with self.assertRaises(ValueError, msg=stdout[:20]):
                self.recorder(stdout).az_text("serial.bad", ["x"])
        self.assertFalse(any(
            b"sig=1" in path.read_bytes()
            for path in (self.root / "custodian").rglob("*") if path.is_file()
        ))
        with self.assertRaises(RuntimeError):
            self.recorder(error=RuntimeError("boom")).az_text("serial.err", ["x"])


class CliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.keys = custodian.generate_test_keys(self.root / "keys")
        self.state = topology.plan(self.root / "state", SUBSCRIPTION)
        self.fixture = Fixture(self.state, {
            "template_sha256": custodian_tests.TEMPLATE_SHA,
        })

    def cli(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = acceptance.main([str(item) for item in argv])
        return code, output.getvalue()

    def expected_file(self, expected, name):
        mapping = {item.name: getattr(expected, item.name)
                   for item in fields(custody.Expected)}
        return write_private(self.root / name, json.dumps(mapping).encode())

    def assert_private_output(self, output):
        for value in (SUBSCRIPTION, self.fixture.expected.run_id,
                      self.state["prefix"]):
            self.assertNotIn(value, output)

    def test_sign_preprovision_then_approve_acceptance(self):
        plan = write_private(self.root / "plan.json", json.dumps({
            "reviewed_head": "a" * 40, "config_sha256": "b" * 64,
            "efi_sha256": "d" * 64, "raw_sha256": "e" * 64,
            "miz_sha256": "f" * 64,
            "image_paths": {role: str(self.root / f"{role}.vhd")
                            for role in custodian.DISKS},
        }).encode())
        expected = self.expected_file(self.fixture.expected, "expected0.json")
        statement = self.root / "preprovision.json"
        code, output = self.cli(
            "sign-preprovision", "--expected-json", expected,
            "--plan-json", plan,
            "--approver-private-key", self.keys["approver"]["private_key"],
            "--offline-sha256", "9" * 64, "--output", statement,
        )
        self.assertEqual(code, 0, output)
        digest = sha(statement.read_bytes())
        self.assertIn(digest, output)
        self.assert_private_output(output)
        self.assertEqual(stat.S_IMODE(statement.stat().st_mode), 0o600)
        body = json.loads(statement.read_bytes())["body"]
        self.assertEqual(body["offline_sha256"], "9" * 64)
        subscription = write_private(self.root / "subscription",
                                     (SUBSCRIPTION + "\n").encode())
        now = datetime.now(timezone.utc).replace(microsecond=0)
        window = [(now + timedelta(minutes=minutes)).strftime(
            "%Y-%m-%dT%H:%M:%SZ") for minutes in (-1, 120)]

        def approve(expected_path, output_path):
            return self.cli(
                "approve-acceptance", "--expected-json", expected_path,
                "--preprovision", statement, "--subscription-file", subscription,
                "--approver-private-key", self.keys["approver"]["private_key"],
                "--not-before", window[0], "--not-after", window[1],
                "--max-vm-running-seconds", 3600, "--output", output_path,
            )
        code, output = approve(expected, self.root / "refused.json")
        self.assertEqual(code, 1)
        self.assertIn("pre-provision", output)
        self.assertFalse((self.root / "refused.json").exists())
        bound = replace(self.fixture.expected,
                        preprovision_authorization_sha256=digest)
        approval = self.root / "approval.json"
        code, output = approve(self.expected_file(bound, "expected.json"), approval)
        self.assertEqual(code, 0, output)
        self.assertIn(sha(approval.read_bytes()), output)
        self.assert_private_output(output)
        approved = json.loads(approval.read_bytes())["body"]
        self.assertEqual(approved["mode"], custodian.LIVE_ACCEPTANCE_MODE)
        self.assertEqual(approved["preprovision_sha256"], digest)

    def test_offline_digest_ignores_boot_serials(self):
        offline = admission.OfflineAdmission(
            "a" * 32, "11111111-1111-4111-8111-111111111111", "a" * 40,
            "3" * 64, "c" * 64, "b" * 64, "d" * 64, "e" * 64, "2" * 64, "f" * 64,
            (admission.SeedEvidence("data0", 0, topology.SECTORS, "4" * 64, "a" * 64),
             admission.SeedEvidence("data7", 7, topology.SECTORS, "5" * 64, "b" * 64)),
            tuple(admission.BootEvidence(source, mode, "2" * 64, "a" * 64, "b" * 64)
                  for source, mode, _ in admission.MODES),
        )
        path = write_private(self.root / "admission.json",
                             json.dumps(asdict(offline)).encode())
        code, output = self.cli("offline-digest", "--admission-json", path)
        self.assertEqual(code, 0)
        self.assertEqual(output.strip(), "offline_sha256="
                         + verifier.reproducible_offline_sha256(offline))
        bad = write_private(self.root / "bad.json", b"{}")
        self.assertEqual(self.cli("offline-digest", "--admission-json", bad)[0], 1)

    def test_offline_inputs_mapping_is_exact(self):
        mapping = {name: str(self.root / name) for name in acceptance.INPUT_PATHS}
        mapping["reviewed"] = {
            item.name: ("a" * 40 if item.name == "head_commit" else "b" * 64)
            for item in fields(admission.ReviewPins)
        }
        inputs = acceptance.offline_inputs_from_mapping(mapping)
        self.assertEqual(inputs.state_dir, self.root / "state_dir")
        self.assertEqual(inputs.qemu_support, admission.PINNED_QEMU_SUPPORT)
        with self.assertRaises(ValueError):
            acceptance.offline_inputs_from_mapping({**mapping, "extra": "x"})
        with self.assertRaises(ValueError):
            acceptance.offline_inputs_from_mapping(
                {**mapping, "reviewed": {"head_commit": "a" * 40}})

    def plan_file(self):
        return write_private(self.root / "plan.json", json.dumps({
            "reviewed_head": "a" * 40, "config_sha256": "b" * 64,
            "efi_sha256": "d" * 64, "raw_sha256": "e" * 64,
            "miz_sha256": "f" * 64,
            "image_paths": {role: str(self.root / f"{role}.vhd")
                            for role in custodian.DISKS},
        }).encode())

    def acceptance_cli(self, *bodies):
        argv = write_private(self.root / "verifier-argv.json", json.dumps(
            child_argv(*bodies)).encode())
        subscription = write_private(self.root / "subscription",
                                     (SUBSCRIPTION + "\n").encode())
        calls = []

        def run(*args, **kwargs):
            calls.append(kwargs)
            return acceptance.AcceptanceResult(
                False, "offline", "not-started", ("stub",),
                clock_offset_seconds=acceptance.clock_offset(
                    kwargs["clock_offset_seconds"]),
            )
        with mock.patch.object(acceptance, "run_acceptance", side_effect=run):
            code, output = self.cli(
                "acceptance", "--approval", self.root / "approval.json",
                "--preprovision", self.root / "preprovision.json",
                "--keys-dir", self.root / "keys",
                "--expected-json", self.expected_file(self.fixture.expected,
                                                      "expected.json"),
                "--plan-json", self.plan_file(),
                "--subscription-file", subscription,
                "--state-dir", self.root / "state",
                "--directory", self.root / "live",
                "--records-dir", self.root / "records",
                "--registry-dir", self.root / "registry",
                "--verifier-argv-json", argv,
            )
        self.assert_private_output(output)
        return code, json.loads(output), calls

    def test_acceptance_runs_in_the_verifier_clock_domain(self):
        code, summary, calls = self.acceptance_cli(
            READY.format(shift=125), "time.sleep(30)\n")
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        clock = calls[0]["clock"]
        self.assertIsInstance(clock, acceptance.VerifierClock)
        self.assertGreaterEqual(calls[0]["clock_offset_seconds"], 125)
        self.assertLess(calls[0]["clock_offset_seconds"], 155)
        self.assertLessEqual(clock(), datetime.now(timezone.utc)
                             - timedelta(seconds=125))
        self.assertEqual(summary["clock_offset_seconds"],
                         round(calls[0]["clock_offset_seconds"]))
        self.assertIs(summary["independent_custody"], False)

    def test_missing_or_invalid_verifier_time_refuses_before_azure(self):
        for change in ("{}", '{"now_utc": "2026-09-29T04:00:00Z"}',
                       '{"now_utc": null}'):
            code, summary, calls = self.acceptance_cli(
                RAW_READY.format(change=change), "time.sleep(30)\n")
            self.assertEqual(code, 1)
            self.assertEqual(calls, [])
            self.assertEqual((summary["stage"], summary["cleanup"]),
                             ("gate", "not-started"))
            self.assertIsNone(summary["clock_offset_seconds"])
            self.assertFalse(os.path.lexists(self.root / "live"))

    def test_serve_verifier_writes_only_protocol_lines(self):
        script = SCRIPTS / "hyperv_issue90_acceptance.py"
        missing = self.root / "missing.json"
        done = subprocess.run(
            [sys.executable, str(script), "serve-verifier",
             "--offline-inputs-json", str(missing),
             "--expected-json", str(missing),
             "--registry-dir", str(self.root / "registry"),
             *(item for role in custodian.KEY_ROLES for item in (
                 f"--{role}-public-key", str(missing)))],
            input=acceptance.encode_request("offline"), capture_output=True,
            timeout=120, check=False,
        )
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stdout, azure.canonical_json({
            "protocol": acceptance.PROTOCOL, "stage": "ready", "passed": False,
            "reason": "verifier_setup_failed",
        }))
        self.assertEqual(done.stderr, b"")
        done = subprocess.run(
            [sys.executable, str(script), "serve-verifier"],
            input=b"", capture_output=True, timeout=120, check=False,
        )
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, b"")

    def test_clock_offset_stamps_and_checks_in_the_verifier_domain(self):
        bound_offset = -300
        statement = self.root / "preprovision.json"
        code, output = self.cli(
            "sign-preprovision", "--expected-json",
            self.expected_file(self.fixture.expected, "expected0.json"),
            "--plan-json", self.plan_file(),
            "--approver-private-key", self.keys["approver"]["private_key"],
            "--offline-sha256", "9" * 64, "--output", statement,
            "--clock-offset-seconds", bound_offset,
        )
        self.assertEqual(code, 0, output)
        issued = custody._utc(json.loads(statement.read_bytes())["body"][
            "issued_at_utc"])
        shifted = datetime.now(timezone.utc) + timedelta(seconds=300)
        self.assertLessEqual(abs((shifted - issued).total_seconds()), 5)
        bound = replace(self.fixture.expected,
                        preprovision_authorization_sha256=sha(
                            statement.read_bytes()))
        expected = self.expected_file(bound, "expected.json")
        subscription = write_private(self.root / "subscription",
                                     (SUBSCRIPTION + "\n").encode())
        now = datetime.now(timezone.utc).replace(microsecond=0)

        def approve(offset, minutes=(-1, 120), name="approval.json"):
            window = [(now + timedelta(minutes=value)).strftime(
                "%Y-%m-%dT%H:%M:%SZ") for value in minutes]
            return self.cli(
                "approve-acceptance", "--expected-json", expected,
                "--preprovision", statement, "--subscription-file", subscription,
                "--approver-private-key", self.keys["approver"]["private_key"],
                "--not-before", window[0], "--not-after", window[1],
                "--max-vm-running-seconds", 3600,
                "--output", self.root / name, "--clock-offset-seconds", offset,
            )
        code, output = approve(0, name="local.json")
        self.assertEqual(code, 1)
        self.assertIn("future", output)
        self.assertFalse((self.root / "local.json").exists())
        code, output = approve(bound_offset, minutes=(-10, 3), name="late.json")
        self.assertEqual(code, 1)
        self.assertIn("ended", output)
        code, output = approve("nan", name="nan.json")
        self.assertEqual(code, 1)
        code, output = approve(bound_offset)
        self.assertEqual(code, 0, output)
        self.assertTrue((self.root / "approval.json").exists())


if __name__ == "__main__":
    unittest.main()
