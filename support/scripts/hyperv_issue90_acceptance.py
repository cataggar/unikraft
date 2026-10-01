#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Owner-attested #90 acceptance lane: one signed live start, then cleanup.

All three custodian/approver/witness keys are self-held TEST-ONLY keys, so a
result is owner-attested and is not independent custody. The verifier runs on
a separate KVM host (it re-runs the offline admission) behind `serve-verifier`;
`require_live_cleanup_proof()` and the topology live gate stay closed.
"""

import argparse
import base64
from dataclasses import dataclass, fields
from datetime import timedelta
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import subprocess
import sys
import time

azure = importlib.import_module("hyperv-azure")
admission = importlib.import_module("hyperv_issue90_offline_admission")
custody = importlib.import_module("hyperv_issue90_custody_records")
custodian = importlib.import_module("hyperv_issue90_custodian")
custody_verifier = importlib.import_module("hyperv_issue90_custody_verifier")
topology = importlib.import_module("hyperv_issue90_topology")

SCHEMA = custody_verifier.SCHEMA
PROTOCOL = "uk-hyperv-issue90-acceptance-verifier-v1"
STATEMENT_STAGES = ("preprovision", "assurance", "acceptance", "observation",
                    "disposal")
PREPROVISION_FIELDS = (
    "schema", "stage", "run_id", "operation_id", "issued_at_utc",
    "reviewed_image_sha256", "dummy_image_sha256", "provenance_sha256",
    "reviewed_head", "config_sha256", "efi_sha256", "raw_sha256", "miz_sha256",
    "offline_sha256", "seed_sha256", "resource_ids", "template_sha256",
    "final_envelope_sha256",
)
RECORD_NAMES = ("prepared.json", "handoff.json", "assurance.json",
                "acceptance.json", "observation.json", "closed.json",
                "ack.json", "disposal.json", "summary.json")
NO_ACCEPTANCE = (
    "Live #90 acceptance is disabled without a valid signed acceptance "
    "approval, its pre-provision statement and a passing remote verifier"
)
RUNTIME_LIMIT = 3600
HANDOFF_LIFETIME = timedelta(minutes=55)
MIN_HANDOFF_WINDOW = timedelta(minutes=15)
MIN_DISPATCH_WINDOW = timedelta(minutes=10)
STOP_MARGIN = timedelta(seconds=300)
MIN_BOOT_SECONDS = 60
POLL_INTERVAL_SECONDS = 15
MAX_POLL_SECONDS = 900
MAX_POLLS = 240
FINAL_GRACE_POLLS = 2
START_TIMEOUT_SECONDS = 900
WAIT_LIMIT_SECONDS = 120
START_WAIT_LIMIT_SECONDS = 60
MAX_SKEW_SECONDS = 10
MAX_BLOBS = 128
MAX_LINE = 32 * 1024 * 1024
TIMEOUTS = {
    "ready": 120, "offline": 1800, "handoff": 300, "dispatch": 120,
    "observation": 300, "disposal": 300,
}
REQUESTS = {
    "offline": (),
    "handoff": (("prepared", "record"), ("handoff", "record"),
                ("preprovision", "record"), ("assurance", "record"),
                ("baseline", "serial"), ("blobs", "blobs")),
    "dispatch": (("acceptance", "record"), ("challenge", "nonce")),
    "observation": (("witness_record", "record"), ("serial", "serial"),
                    ("baseline", "serial"), ("blobs", "blobs")),
    "disposal": (("closed", "record"), ("ack", "record"),
                 ("disposal", "record"), ("blobs", "blobs")),
}
RESPONSES = {
    "ready": (),
    "offline": ("offline_sha256",),
    "handoff": ("consumed_seconds",),
    "dispatch": ("claim_sha256", "reserved_at_utc", "expires_at_utc",
                 "max_remaining_seconds"),
    "observation": ("running_seconds",),
    "disposal": ("result", "disposal_recorded"),
}
NEXT_STAGES = {
    None: ("offline",), "offline": ("handoff",), "handoff": ("dispatch",),
    "dispatch": ("observation", "disposal"), "observation": ("disposal",),
}
REASON = re.compile(r"[a-z0-9_]{1,160}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
INPUT_PATHS = ("state_dir", "build_dir", "image_dir", "miz", "runner", "qemu",
               "ovmf_code", "ovmf_vars")
SERIAL_FAILURE_PREFIXES = (
    "HYPERV_TOPOLOGY FINAL FAIL", "HYPERV_TOPOLOGY TARGET FAIL",
    "UK_HYPERV_ACCEPTANCE_FAIL:", "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:",
    "HYPERV_PERSISTENCE",
)
SERIAL_FAILURES = (
    "HYPERV_TOPOLOGY RESULT FAIL", "HYPERV_TOPOLOGY RESULT UNAVAILABLE",
    "HYPERV_TOPOLOGY FINAL UNAVAILABLE", "Unikraft Crash",
    "Assertion failure", "Exception Type",
)


class VerifierTransportError(RuntimeError):
    pass


@dataclass(frozen=True)
class AcceptanceResult:
    passed: bool
    stage: str
    cleanup: str
    reasons: tuple = ()
    cleanup_reason: str | None = None
    verifier_result: str | None = None
    owner_attested_test_keys: bool = True

    def summary(self, private_values=()):
        def clean(text):
            return custodian.sanitize_reason(text, private_values)
        return {
            "result": "PASS" if self.passed else "FAIL",
            "stage": self.stage,
            "cleanup": self.cleanup,
            "cleanup_reason": (None if self.cleanup_reason is None
                               else clean(self.cleanup_reason)),
            "reasons": [clean(item) for item in self.reasons],
            "verifier_result": self.verifier_result,
            "owner_attested_test_keys": True,
            "independent_custody": False,
        }


def _floor(value):
    return custodian._aware(value, "Acceptance clock").replace(microsecond=0)


def _ceil(value):
    value = custodian._aware(value, "Acceptance clock")
    if value.microsecond:
        return value.replace(microsecond=0) + timedelta(seconds=1)
    return value


def _stamp(value):
    return _floor(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh_nonce(*avoid):
    while True:
        value = secrets.token_hex(16)
        if int(value, 16) and value not in avoid:
            return value


def sign_statement(body, private_key):
    """Sign one verifier-v1 statement (preprovision ... disposal)."""
    if (not isinstance(body, dict) or body.get("schema") != SCHEMA
            or body.get("stage") not in STATEMENT_STAGES):
        raise ValueError("Verifier statement schema or stage is invalid")
    signature = custodian.load_private_key(private_key).sign(
        (SCHEMA + "-" + body["stage"] + "\n").encode("ascii")
        + azure.canonical_json(body)
    )
    return azure.canonical_json({"body": body, "signature": signature.hex()})


def sign_custody(body, private_key):
    """Sign one custody record (CLOSED with the custodian, ACK with the witness)."""
    if (not isinstance(body, dict) or body.get("schema") != custody.SCHEMA
            or body.get("stage") not in ("closed", "ack")):
        raise ValueError("Custody record schema or stage is invalid")
    signature = custodian.load_private_key(private_key).sign(
        (custody.DOMAINS[body["stage"]] + "\n").encode("ascii")
        + azure.canonical_json(body)
    )
    return azure.canonical_json({"body": body, "signature": signature.hex()})


def runtime_ledger(intervals):
    items = []
    total = 0
    for kind, start, end in intervals:
        total += int((custody._utc(end) - custody._utc(start)).total_seconds())
        items.append({"kind": kind, "start_utc": start, "end_utc": end})
    return {"complete": True, "intervals": items, "running_seconds": total}


def _statement(stage, expected, issued_at_utc, **values):
    custody._utc(issued_at_utc)
    return {
        "schema": SCHEMA, "stage": stage, "run_id": expected.run_id,
        "operation_id": expected.operation_id, "issued_at_utc": issued_at_utc,
        **values,
    }


def preprovision_body(*, expected, plan, offline_sha256, issued_at_utc):
    return _statement(
        "preprovision", expected, issued_at_utc,
        reviewed_image_sha256=expected.reviewed_image_sha256,
        dummy_image_sha256=expected.dummy_image_sha256,
        provenance_sha256=expected.provenance_sha256,
        reviewed_head=plan.reviewed_head,
        config_sha256=plan.config_sha256,
        efi_sha256=plan.efi_sha256,
        raw_sha256=plan.raw_sha256,
        miz_sha256=plan.miz_sha256,
        offline_sha256=custody._sha(offline_sha256, "Offline admission digest"),
        seed_sha256=dict(expected.seed_sha256),
        resource_ids=dict(expected.resource_ids),
        template_sha256=expected.template_sha256,
        final_envelope_sha256=expected.final_envelope_sha256,
    )


def assurance_body(*, expected, issued_at_utc, expires_at_utc, handoff_sha256,
                   preprovision_sha256, vm_uuid, disks, rbac_sha256,
                   boot_history_sha256, baseline_generation,
                   baseline_serial_sha256, runtime):
    return _statement(
        "assurance", expected, issued_at_utc,
        expires_at_utc=expires_at_utc,
        handoff_sha256=handoff_sha256,
        preprovision_sha256=preprovision_sha256,
        challenge=expected.handoff_challenge,
        vm_uuid=vm_uuid,
        disks=disks,
        no_writers=True,
        no_prior_acceptance_boot=True,
        rbac_sha256=rbac_sha256,
        boot_history_sha256=boot_history_sha256,
        baseline_generation=baseline_generation,
        baseline_serial_sha256=baseline_serial_sha256,
        runtime=runtime,
    )


def acceptance_body(*, expected, issued_at_utc, expires_at_utc, challenge,
                    handoff_sha256, prepared_sha256, preprovision_sha256,
                    assurance_sha256, vm_uuid, disks, offline_sha256,
                    remaining_seconds):
    return _statement(
        "acceptance", expected, issued_at_utc,
        expires_at_utc=expires_at_utc,
        challenge=challenge,
        handoff_sha256=handoff_sha256,
        prepared_sha256=prepared_sha256,
        preprovision_sha256=preprovision_sha256,
        assurance_sha256=assurance_sha256,
        vm_id=expected.resource_ids["vm"],
        vm_uuid=vm_uuid,
        disks=disks,
        reviewed_image_sha256=expected.reviewed_image_sha256,
        offline_sha256=offline_sha256,
        seed_sha256=dict(expected.seed_sha256),
        remaining_seconds=remaining_seconds,
        one_start=True,
    )


def observation_body(*, expected, issued_at_utc, challenge, dispatch_sha256,
                     acceptance_sha256, vm_uuid, disk_uuids, start_status,
                     start_receipt_sha256, observed_boot_count,
                     baseline_generation, boot_generation,
                     baseline_serial_sha256, serial_sha256, device_binding,
                     runtime):
    return _statement(
        "observation", expected, issued_at_utc,
        challenge=challenge,
        dispatch_sha256=dispatch_sha256,
        acceptance_sha256=acceptance_sha256,
        vm_uuid=vm_uuid,
        disks=disk_uuids,
        start_status=start_status,
        start_receipt_sha256=start_receipt_sha256,
        start_dispatch_count=1,
        observed_boot_count=observed_boot_count,
        baseline_generation=baseline_generation,
        boot_generation=boot_generation,
        baseline_serial_sha256=baseline_serial_sha256,
        serial_sha256=serial_sha256,
        device_binding=device_binding,
        runtime=runtime,
    )


def disposal_body(*, expected, issued_at_utc, handoff_sha256, dispatch_sha256,
                  acceptance_sha256, closed_sha256, ack_sha256, disposition,
                  resources, quiescence_sha256, runtime):
    return _statement(
        "disposal", expected, issued_at_utc,
        handoff_sha256=handoff_sha256,
        dispatch_sha256=dispatch_sha256,
        acceptance_sha256=acceptance_sha256,
        closed_sha256=closed_sha256,
        ack_sha256=ack_sha256,
        disposition=disposition,
        resources=resources,
        all_operations_settled=True,
        no_writers=True,
        vm_deallocated=True,
        quiescence_sha256=quiescence_sha256,
        runtime=runtime,
    )


def closed_body(*, expected, issued_at_utc, nonce, handoff_sha256,
                acceptance_sha256, return_receipt, disposal_receipt,
                disposition):
    custody._utc(issued_at_utc)
    return {
        "schema": custody.SCHEMA, "version": 1, "stage": "closed",
        "sequence": 3, "previous_sha256": handoff_sha256,
        "run_id": expected.run_id, "operation_id": expected.operation_id,
        "issued_at_utc": issued_at_utc, "nonce": nonce,
        "preprovision_authorization_sha256":
            expected.preprovision_authorization_sha256,
        "evidence": {
            "handoff_sha256": handoff_sha256,
            "acceptance_authorization_sha256": acceptance_sha256,
            "return_receipt": return_receipt,
            "disposal_receipt": disposal_receipt,
            "disposition": disposition,
        },
    }


def ack_body(*, expected, issued_at_utc, closed_sha256):
    custody._utc(issued_at_utc)
    return {
        "schema": custody.SCHEMA, "version": 1, "stage": "ack",
        "run_id": expected.run_id, "challenge": expected.handoff_challenge,
        "closed_sha256": closed_sha256, "issued_at_utc": issued_at_utc,
    }


def require_preprovision(raw, *, approver_public_key, expected, plan, now):
    """Check the approver's signed pre-provision statement against the plan."""
    if not isinstance(raw, bytes) or len(raw) > custody.MAX_RECORD:
        raise ValueError("Pre-provision statement exceeds its byte limit")
    body, digest = custody_verifier._signed(
        raw, "preprovision", custodian.load_public_key(approver_public_key),
    )
    azure.require_exact_fields(body, PREPROVISION_FIELDS, "Pre-provision statement")
    if not isinstance(expected, custody.Expected):
        raise ValueError("Pre-provision check requires an Expected custody context")
    expected.validate()
    if not isinstance(plan, custodian.CustodianPlan) or plan.expected != expected:
        raise ValueError("Custodian plan differs from the expected custody context")
    issued = custody._utc(body["issued_at_utc"])
    wanted = preprovision_body(
        expected=expected, plan=plan, offline_sha256=body["offline_sha256"],
        issued_at_utc=body["issued_at_utc"],
    )
    if body != wanted:
        raise ValueError("Pre-provision statement differs from the expected plan")
    if issued >= _floor(custody._now(now)):
        raise ValueError("Pre-provision statement is not issued before now")
    if digest != expected.preprovision_authorization_sha256:
        raise ValueError("Expected does not bind this pre-provision statement")
    return body


def serial_status(text):
    """Classify a boot-log snapshot: failed, complete, final or None."""
    lines = [azure.ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
             for line in text.splitlines()]
    for line in lines:
        if (line.startswith(SERIAL_FAILURE_PREFIXES)
                or any(marker in line for marker in SERIAL_FAILURES)
                or re.search(r"\bmain returned (?!0\b)-?\d+\b", line)):
            return "failed"
    if "main returned 0" in lines:
        return "complete"
    if any(line.startswith("HYPERV_TOPOLOGY FINAL ") for line in lines):
        return "final"
    return None


def _issued_at(raw):
    try:
        return custody._utc(json.loads(raw)["body"]["issued_at_utc"])
    except (TypeError, ValueError, KeyError, UnicodeError):
        return None


def _refused(stage, reason, **extra):
    code = re.sub(r"[^a-z0-9_]+", "_", str(reason).lower()).strip("_")[:160]
    return {"stage": stage, "passed": False,
            "reason": code or "verifier_refused", **extra}


class LocalVerifier:
    """Run the offline custody Verifier stages and return plain dicts."""

    def __init__(self, inputs, expected, registry, *, custodian_key,
                 approver_key, witness_key, clock=None, sleep=None,
                 archive=None, max_skew_seconds=MAX_SKEW_SECONDS):
        self.archive = {} if archive is None else archive
        self.clock = clock or custodian._utc_now
        self.sleep = sleep or time.sleep
        self.max_skew = max_skew_seconds
        self.verifier = custody_verifier.Verifier(
            inputs, expected, self.archive, registry,
            custodian_key=custodian_key, approver_key=approver_key,
            witness_key=witness_key, clock=self.clock,
        )
        self.used = set()
        self._offline = self._preboot = self._permit = self._candidate = None

    def _enter(self, stage, ready):
        if stage in self.used or not ready:
            return False
        self.used.add(stage)
        return True

    def _settle(self, *raws):
        # Wait (bounded) when a statement was issued ahead of this clock.
        latest = max((item for item in map(_issued_at, raws) if item is not None),
                     default=None)
        waited = 0.0
        while True:
            now = custodian._aware(self.clock(), "Verifier clock")
            if latest is None or now >= latest:
                return now
            if waited >= self.max_skew:
                return None
            step = min(1.0, self.max_skew - waited,
                       max((latest - now).total_seconds(), 0.01))
            self.sleep(step)
            waited += step

    def _add(self, blobs):
        if (not isinstance(blobs, (list, tuple))
                or len(self.archive) + len(blobs) > MAX_BLOBS
                or any(not isinstance(raw, bytes)
                       or not 0 < len(raw) <= custody.MAX_ARCHIVE
                       for raw in blobs)):
            return False
        for raw in blobs:
            self.archive[_sha(raw)] = raw
        return True

    def offline(self):
        if not self._enter("offline", True):
            return _refused("offline", "stage_out_of_order")
        result = self.verifier.verify_offline()
        if type(result) is not admission.OfflineAdmission:
            return _refused("offline", getattr(
                result, "reason", "offline_admission_unavailable",
            ))
        self._offline = result
        return {
            "stage": "offline", "passed": True, "reason": None,
            "offline_sha256": custody_verifier.reproducible_offline_sha256(result),
        }

    def handoff(self, prepared, handoff, preprovision, assurance, baseline, blobs):
        if not self._enter("handoff", self._offline is not None):
            return _refused("handoff", "stage_out_of_order")
        now = self._settle(prepared, handoff, preprovision, assurance)
        if now is None:
            return _refused("handoff", "statement_issued_in_future")
        if not self._add(blobs):
            return _refused("handoff", "evidence_blobs_invalid")
        result = self.verifier.verify_handoff(
            self._offline, prepared, handoff, preprovision, assurance,
            baseline, now=now,
        )
        if type(result) is not custody_verifier.PreBootCandidate:
            return _refused("handoff", result.reason)
        self._preboot = result
        return {"stage": "handoff", "passed": True, "reason": None,
                "consumed_seconds": result.consumed_seconds}

    def dispatch(self, acceptance, challenge):
        if not self._enter("dispatch", self._preboot is not None):
            return _refused("dispatch", "stage_out_of_order")
        now = self._settle(acceptance)
        if now is None:
            return _refused("dispatch", "statement_issued_in_future")
        result = self.verifier.reserve_dispatch(
            self._preboot, acceptance, challenge, now=now,
        )
        if type(result) is not custody_verifier.DispatchPermit:
            return _refused("dispatch", result.reason)
        self._permit = result
        return {
            "stage": "dispatch", "passed": True, "reason": None,
            "claim_sha256": result.claim_sha256,
            "reserved_at_utc": result.reserved_at_utc,
            "expires_at_utc": result.expires_at_utc,
            "max_remaining_seconds": result.max_remaining_seconds,
        }

    def observation(self, witness_record, serial, baseline, blobs):
        if not self._enter("observation", self._permit is not None):
            return _refused("observation", "stage_out_of_order")
        now = self._settle(witness_record)
        if now is None:
            return _refused("observation", "statement_issued_in_future")
        if not self._add(blobs):
            return _refused("observation", "evidence_blobs_invalid")
        result = self.verifier.verify_observation(
            self._permit, witness_record, serial, baseline, now=now,
        )
        if type(result) is not custody_verifier.CandidateAcceptance:
            return _refused("observation", result.reason)
        self._candidate = result
        return {"stage": "observation", "passed": True, "reason": None,
                "running_seconds": result.running_seconds}

    def disposal(self, closed, ack, disposal, blobs):
        failed = {"result": "FAIL", "disposal_recorded": False}
        if not self._enter("disposal", self._permit is not None):
            return _refused("disposal", "stage_out_of_order", **failed)
        now = self._settle(closed, ack, disposal)
        if now is None:
            return _refused("disposal", "statement_issued_in_future", **failed)
        if not self._add(blobs):
            return _refused("disposal", "evidence_blobs_invalid", **failed)
        result = self.verifier.verify_disposal(
            self._candidate or self._permit, closed, ack, disposal, now=now,
        )
        if type(result) is custody_verifier.FinalAcceptance:
            return {"stage": "disposal", "passed": True, "reason": None,
                    "result": "PASS", "disposal_recorded": True}
        return _refused("disposal", result.reason, result="FAIL",
                        disposal_recorded=result.disposal_recorded is True)


def _encode_bytes(raw, limit, label):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError(f"{label} must be bounded bytes")
    return base64.b64encode(raw).decode("ascii")


def _decode_bytes(value, limit, label):
    if not isinstance(value, str) or len(value) > 4 * (limit // 3 + 1):
        raise ValueError(f"{label} must be bounded base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise ValueError(f"{label} is not valid base64") from None
    if len(raw) > limit or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"{label} is not bounded canonical base64")
    return raw


def _limit(kind):
    return {"record": custody.MAX_RECORD, "serial": topology.MAX_SERIAL}[kind]


def _encode_value(kind, value, label):
    if kind == "nonce":
        if not isinstance(value, str) or not NONCE.fullmatch(value):
            raise ValueError(f"{label} must be a 128-bit lowercase nonce")
        return value
    if kind == "blobs":
        if (not isinstance(value, (list, tuple)) or len(value) > MAX_BLOBS
                or any(not isinstance(raw, bytes) or not raw for raw in value)):
            raise ValueError(f"{label} must be at most {MAX_BLOBS} blobs")
        return [_encode_bytes(raw, custody.MAX_ARCHIVE, label) for raw in value]
    return _encode_bytes(value, _limit(kind), label)


def _decode_value(kind, value, label):
    if kind == "nonce":
        return _encode_value(kind, value, label)
    if kind == "blobs":
        if not isinstance(value, list) or len(value) > MAX_BLOBS:
            raise ValueError(f"{label} must be at most {MAX_BLOBS} blobs")
        result = [_decode_bytes(item, custody.MAX_ARCHIVE, label) for item in value]
        if any(not raw for raw in result):
            raise ValueError(f"{label} contains an empty blob")
        return result
    return _decode_bytes(value, _limit(kind), label)


def encode_request(stage, **values):
    if stage not in REQUESTS:
        raise ValueError("Unknown verifier stage")
    names = tuple(name for name, _ in REQUESTS[stage])
    if set(values) != set(names):
        raise ValueError("Verifier request fields differ from the stage")
    message = {"protocol": PROTOCOL, "stage": stage}
    for name, kind in REQUESTS[stage]:
        message[name] = _encode_value(kind, values[name], name)
    return azure.canonical_json(message)


def decode_request(line):
    if not isinstance(line, bytes) or len(line) > MAX_LINE:
        raise ValueError("Verifier request exceeds its byte limit")
    message = azure.parse_strict_json(line, "Verifier request")
    if (not isinstance(message, dict) or message.get("protocol") != PROTOCOL
            or message.get("stage") not in REQUESTS
            or line != azure.canonical_json(message)):
        raise ValueError("Verifier request protocol or stage is invalid")
    stage = message["stage"]
    azure.require_exact_fields(
        message, ("protocol", "stage", *(name for name, _ in REQUESTS[stage])),
        "Verifier request",
    )
    return stage, {
        name: _decode_value(kind, message[name], name)
        for name, kind in REQUESTS[stage]
    }


def check_response(stage, value):
    if not isinstance(value, dict) or stage not in RESPONSES:
        raise ValueError("Verifier response must be an object for a known stage")
    passed = value.get("passed")
    extra = RESPONSES[stage] if passed is True or stage == "disposal" else ()
    azure.require_exact_fields(
        value, ("stage", "passed", "reason", *extra), "Verifier response",
    )
    if (value["stage"] != stage or type(passed) is not bool
            or (value["reason"] is not None if passed
                else not isinstance(value["reason"], str)
                or not REASON.fullmatch(value["reason"]))):
        raise ValueError("Verifier response stage, result or reason is invalid")
    if stage == "offline" and passed:
        custody._sha(value["offline_sha256"], "Offline admission digest")
    elif stage == "handoff" and passed:
        seconds = value["consumed_seconds"]
        if type(seconds) is not int or not 0 <= seconds < RUNTIME_LIMIT:
            raise ValueError("Verifier consumed runtime is invalid")
    elif stage == "dispatch" and passed:
        custody._sha(value["claim_sha256"], "Dispatch claim digest")
        custody._precise_utc(value["reserved_at_utc"])
        custody._utc(value["expires_at_utc"])
        seconds = value["max_remaining_seconds"]
        if type(seconds) is not int or not 0 < seconds <= RUNTIME_LIMIT:
            raise ValueError("Verifier remaining runtime is invalid")
    elif stage == "observation" and passed:
        seconds = value["running_seconds"]
        if type(seconds) is not int or not 0 < seconds <= RUNTIME_LIMIT:
            raise ValueError("Verifier observed runtime is invalid")
    elif stage == "disposal":
        if (value["result"] != ("PASS" if passed else "FAIL")
                or type(value["disposal_recorded"]) is not bool
                or (passed and value["disposal_recorded"] is not True)):
            raise ValueError("Verifier disposal result is inconsistent")
    return value


def encode_response(value):
    check_response(value.get("stage") if isinstance(value, dict) else None, value)
    return azure.canonical_json({"protocol": PROTOCOL, **value})


def decode_response(line, stage):
    if not isinstance(line, bytes) or len(line) > MAX_LINE:
        raise ValueError("Verifier response exceeds its byte limit")
    message = azure.parse_strict_json(line, "Verifier response")
    if (not isinstance(message, dict) or message.get("protocol") != PROTOCOL
            or line != azure.canonical_json(message)):
        raise ValueError("Verifier response protocol is invalid")
    del message["protocol"]
    return check_response(stage, message)


def _read_line(stream):
    line = stream.readline(MAX_LINE + 1)
    if not line:
        return None
    if len(line) > MAX_LINE or not line.endswith(b"\n"):
        raise ValueError("Verifier request line is unterminated or too long")
    return line


def _emit(stdout, value):
    stdout.write(encode_response(value))
    stdout.flush()


def serve(local, stdin, stdout):
    """Serve one verifier session over newline-delimited canonical JSON.

    The first line reports readiness; then one request per stage, strictly
    in order. A refused offline/handoff/dispatch stage, a disposal or any
    protocol error ends the session.
    """
    if local is None:
        _emit(stdout, _refused("ready", "verifier_setup_failed"))
        return 1
    _emit(stdout, {"stage": "ready", "passed": True, "reason": None})
    previous = None
    while True:
        try:
            line = _read_line(stdin)
            if line is None:
                return 0 if previous == "disposal" else 1
            stage, values = decode_request(line)
        except ValueError:
            stdout.write(azure.canonical_json({
                "protocol": PROTOCOL, "stage": "error", "passed": False,
                "reason": "malformed_request",
            }))
            stdout.flush()
            return 1
        if previous == "disposal" or stage not in NEXT_STAGES[previous]:
            _emit(stdout, _refused(
                stage, "stage_out_of_order",
                **({"result": "FAIL", "disposal_recorded": False}
                   if stage == "disposal" else {}),
            ))
            return 1
        try:
            result = getattr(local, stage)(**values)
            payload = encode_response(result)
        except Exception:
            result = _refused(
                stage, "verifier_internal_error",
                **({"result": "FAIL", "disposal_recorded": False}
                   if stage == "disposal" else {}),
            )
            payload = encode_response(result)
        stdout.write(payload)
        stdout.flush()
        previous = stage
        if stage == "disposal" or (
                not result["passed"] and stage in ("offline", "handoff", "dispatch")):
            return 0 if result["passed"] else 1


class RemoteVerifier:
    """Speak the verifier protocol to a `serve-verifier` command (e.g. ssh)."""

    def __init__(self, argv, *, timeouts=None):
        if (not isinstance(argv, (list, tuple)) or not argv or len(argv) > 64
                or any(not isinstance(item, str) or not item or "\0" in item
                       for item in argv)):
            raise ValueError("Verifier command must be a non-empty argv list")
        self.argv = list(argv)
        self.timeouts = {**TIMEOUTS, **(timeouts or {})}
        self.process = None
        self.buffer = b""
        self.broken = False

    def _start(self):
        if self.process is not None:
            return
        try:
            self.process = subprocess.Popen(
                self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True,
            )
        except OSError:
            self.broken = True
            raise VerifierTransportError("Verifier command could not start") from None
        ready = self._receive("ready")
        if not ready["passed"]:
            self._fail("Remote verifier setup refused: " + ready["reason"])

    def _fail(self, message):
        self.broken = True
        self.close(kill=True)
        raise VerifierTransportError(message)

    def _send(self, raw, deadline):
        descriptor = self.process.stdin.fileno()
        view = memoryview(raw)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail("Verifier request timed out")
            _, writable, _ = select.select([], [descriptor], [], remaining)
            if not writable:
                continue
            try:
                written = os.write(descriptor, view[:65536])
            except OSError:
                self._fail("Verifier connection closed")
            view = view[written:]

    def _receive(self, stage, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + self.timeouts[stage]
        descriptor = self.process.stdout.fileno()
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_LINE:
                self._fail("Verifier response exceeds its byte limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail(f"Verifier {stage} response timed out")
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if not readable:
                continue
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                self._fail("Verifier connection closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        try:
            return decode_response(line + b"\n", stage)
        except ValueError:
            self._fail(f"Verifier {stage} response is invalid")

    def _call(self, stage, **values):
        if self.broken:
            raise VerifierTransportError("Verifier session is no longer usable")
        self._start()
        deadline = time.monotonic() + self.timeouts[stage]
        self._send(encode_request(stage, **values), deadline)
        result = self._receive(stage, deadline)
        if stage == "disposal" or (
                not result["passed"] and stage in ("offline", "handoff", "dispatch")):
            self.close()
        return result

    def offline(self):
        return self._call("offline")

    def handoff(self, prepared, handoff, preprovision, assurance, baseline, blobs):
        return self._call(
            "handoff", prepared=prepared, handoff=handoff,
            preprovision=preprovision, assurance=assurance, baseline=baseline,
            blobs=blobs,
        )

    def dispatch(self, acceptance, challenge):
        return self._call("dispatch", acceptance=acceptance, challenge=challenge)

    def observation(self, witness_record, serial, baseline, blobs):
        return self._call(
            "observation", witness_record=witness_record, serial=serial,
            baseline=baseline, blobs=blobs,
        )

    def disposal(self, closed, ack, disposal, blobs):
        return self._call(
            "disposal", closed=closed, ack=ack, disposal=disposal, blobs=blobs,
        )

    def close(self, *, kill=False):
        process, self.process = self.process, None
        if process is None:
            return
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            if kill:
                process.kill()
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        finally:
            process.stdout.close()


def _call_verifier(verifier, stage, *args):
    failed = {"result": "FAIL", "disposal_recorded": False} if stage == "disposal" else {}
    try:
        result = getattr(verifier, stage)(*args)
    except VerifierTransportError:
        return _refused(stage, "verifier_transport_failed", **failed)
    except Exception:
        return _refused(stage, "verifier_call_failed", **failed)
    try:
        return check_response(stage, result)
    except ValueError:
        return _refused(stage, "verifier_response_invalid", **failed)


def _record_refs(value):
    if isinstance(value, dict):
        if set(value) == {"sha256", "size"} and isinstance(value["sha256"], str):
            yield value["sha256"]
            return
        for item in value.values():
            yield from _record_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from _record_refs(item)


def _key_material(keys):
    if not isinstance(keys, dict) or set(keys) != set(custodian.KEY_ROLES):
        raise ValueError("Custodian, approver and witness keys are required")
    material = {}
    for role in custodian.KEY_ROLES:
        entry = keys[role]
        private = custodian.load_private_key(entry["private_key"])
        public = custodian.load_public_key(entry["public_key"])
        if custodian._public_bytes(private) != public:
            raise ValueError(f"{role} private and public keys do not match")
        material[role] = (private, public)
    if len({public for _, public in material.values()}) != len(material):
        raise ValueError("Custodian, approver and witness keys must differ")
    return material


def _require_state(state, expected):
    if (not isinstance(state, dict)
            or state.get("run_id") != expected.run_id
            or state.get("operation_id") != expected.operation_id
            or topology.group_id(state) != expected.resource_ids["group"]
            or any(topology.resource_id(state, role) != expected.resource_ids[role]
                   for role in ("os", "data0", "data7", "deployment", "vm",
                                "nic", "vnet", "nsg"))
            or not isinstance(state.get("disk_ids"), dict)):
        raise ValueError("Offline topology state differs from the expected run")


def run_acceptance(approval=None, *, preprovision=None, keys=None,
                   expected=None, plan=None, subscription=None, state=None,
                   directory=None, records_dir=None, registry_dir=None,
                   verifier=None, runner=None, cleanup_runner=None,
                   upload=None, clock=None, sleep=None,
                   poll_interval=POLL_INTERVAL_SECONDS,
                   max_poll_seconds=MAX_POLL_SECONDS):
    """Run one owner-attested acceptance: at most one VM start, always cleanup.

    Every refusal before the offline verifier passes happens before any
    Azure call. PASS needs the verifier's FinalAcceptance and a deleted group.
    """
    clock = clock or custodian._utc_now
    sleep = sleep or time.sleep
    if approval is None or preprovision is None or verifier is None:
        raise custodian.LiveApprovalRefused(NO_ACCEPTANCE)
    try:
        approval_raw = custodian._read_private_file(
            approval, custodian.LIVE_APPROVAL_LIMIT, "Acceptance approval",
        )
        preprovision_raw = custodian._read_private_file(
            preprovision, custody.MAX_RECORD, "Pre-provision statement",
        )
    except (OSError, ValueError):
        raise custodian.LiveApprovalRefused(
            NO_ACCEPTANCE + " (approval and pre-provision statement must be "
            "private bounded files)"
        ) from None
    material = _key_material(keys)
    body = custodian.require_live_acceptance_approval(
        approval_raw, preprovision_raw=preprovision_raw,
        approver_public_key=material["approver"][1],
        custodian_public_key=material["custodian"][1],
        expected=expected, plan=plan, subscription=subscription, now=clock(),
    )
    try:
        statement = require_preprovision(
            preprovision_raw, approver_public_key=material["approver"][1],
            expected=expected, plan=plan, now=clock(),
        )
    except ValueError as error:
        raise custodian.LiveApprovalRefused(
            f"Pre-provision statement refused: {error}"
        ) from None
    _require_state(state, expected)
    custodian._check_template(plan, expected)
    if upload is None:
        custodian._preflight_uploads(plan)
        upload = custodian.azure_vhd_upload
    records_dir = custodian._ensure_private_dir(records_dir)
    if any(os.path.lexists(records_dir / name) for name in RECORD_NAMES):
        raise ValueError("Records directory already holds custody records")
    registry_dir = custodian._require_private_dir(registry_dir, "Replay registry")
    if any(os.path.lexists(registry_dir / name) for name in (
        f"run-{expected.run_id}.json",
        f"challenge-{expected.handoff_challenge}.json",
        f"live-approval-{_sha(approval_raw)}.json",
    )):
        raise ValueError("Run, handoff challenge or approval was already consumed")
    directory = Path(directory).absolute()
    if os.path.lexists(directory):
        raise FileExistsError("Live custodian directory already exists")
    offline = _call_verifier(verifier, "offline")
    if not offline["passed"]:
        return AcceptanceResult(False, "offline", "not-started",
                                ("verifier offline: " + offline["reason"],))
    if offline["offline_sha256"] != statement["offline_sha256"]:
        return AcceptanceResult(False, "offline", "not-started", (
            "verifier offline admission differs from the pre-provision statement",
        ))
    directory = custodian._create_private_dir(directory, "Live custodian directory")
    try:
        custodian._claim_live_approval(registry_dir, approval_raw, body)
    except BaseException:
        directory.rmdir()
        raise
    return _AcceptanceRun(
        body, material, statement, preprovision_raw,
        expected=expected, plan=plan, subscription=subscription, state=state,
        directory=directory, records_dir=records_dir, registry_dir=registry_dir,
        verifier=verifier, runner=runner, cleanup_runner=cleanup_runner,
        upload=upload, clock=clock, sleep=sleep, poll_interval=poll_interval,
        max_poll_seconds=max_poll_seconds,
    ).run()


def _no_azure(arguments, *, timeout=120):
    raise RuntimeError("No Azure call is allowed after owned cleanup")


class _AcceptanceRun:
    def __init__(self, body, material, statement, preprovision_raw, *, expected,
                 plan, subscription, state, directory, records_dir,
                 registry_dir, verifier, runner, cleanup_runner, upload,
                 clock, sleep, poll_interval, max_poll_seconds):
        self.body = body
        self.keys = material
        self.statement = statement
        self.preprovision_raw = preprovision_raw
        self.expected = expected
        self.plan = plan
        self.subscription = subscription
        self.state = state
        self.directory = directory
        self.records_dir = records_dir
        self.registry_dir = registry_dir
        self.verifier = verifier
        self.runner = runner
        self.cleanup_runner = cleanup_runner
        self.clock = clock
        self.sleep = sleep
        self.poll_interval = poll_interval
        self.max_poll_seconds = max_poll_seconds
        self.not_after = custody._utc(body["not_after_utc"])
        self.recorder = custodian.CustodianRecorder(
            directory,
            runner=custodian.SubscriptionRunner(
                subscription, deadline=self.not_after, clock=clock, runner=runner,
            ),
            clock=clock,
            revoke_runner=custodian.SubscriptionRunner(
                subscription, clock=clock, runner=cleanup_runner or runner,
            ),
            sleep=sleep,
        )
        self.private = [
            *custodian._live_private_values(subscription, expected, plan),
            *state["disk_ids"].values(), state["prefix"],
        ]

        def tracked_upload(role, path, sas, digest, size):
            if isinstance(sas, str):
                self.private.extend((sas, *sas.split("?", 1)[1:]))
            return upload(role, path, sas, digest, size)

        self.upload = tracked_upload
        self.group = plan.group_name()
        self.vm_name = plan.resource_name("vm")
        self.boot_log = [
            "vm", "boot-diagnostics", "get-boot-log",
            "--resource-group", self.group, "--name", self.vm_name,
        ]
        self.stage = "provision"
        self.reasons = []
        self.permit = None
        self.final = None
        self.start_before = None
        self.start_status = None
        self.start_receipt = None
        self.lost_note = None
        self.serial_text = None
        self.acceptance_end = None
        self.observation_at = None
        self.observation_intervals = None
        self.observed = False

    def _private(self, *values):
        self.private.extend(item for item in values if item)

    def _clean(self, error):
        text = custodian.sanitize_reason(error, self.private)
        if not text or custodian.SAS_TOKEN.search(text):
            return type(error).__name__
        return text

    def _reason(self, prefix, error=None):
        text = prefix if error is None else prefix + ": " + self._clean(error)
        self.reasons.append(self._clean(text))

    def _wait_until(self, target, limit=WAIT_LIMIT_SECONDS):
        waited = 0.0
        while True:
            now = custodian._aware(self.clock(), "Acceptance clock")
            if now >= target:
                return now
            if waited >= limit:
                raise ValueError("Clock did not reach the required statement time")
            step = min(max((target - now).total_seconds(), 0.05),
                       limit - waited, 5.0)
            self.sleep(step)
            waited += step

    def _write(self, name, raw):
        custodian._write_private_file(self.records_dir / name, raw)

    def run(self):
        try:
            self._provision()
            if self._assure() and self._authorize():
                self._start_and_observe()
        except BaseException as error:
            # Interrupts are reported, not re-raised, so owned cleanup runs.
            reason = self._clean(error)
            if not isinstance(error, Exception):
                reason = f"Interrupted ({type(error).__name__}): {reason}"
            self.reasons.append(reason)
        finally:
            cleanup, cleanup_reason = custodian._live_cleanup(
                self.directory, self.plan,
                custodian.SubscriptionRunner(
                    self.subscription, clock=self.clock,
                    runner=self.cleanup_runner or self.runner,
                ),
                self.clock, self.private,
            )
        if cleanup == "deleted" and self.permit is not None:
            try:
                self._dispose()
            except BaseException as error:
                reason = self._clean(error)
                if not isinstance(error, Exception):
                    reason = f"Interrupted ({type(error).__name__}): {reason}"
                self.reasons.append("Disposal was not recorded: " + reason)
        elif self.permit is not None:
            self.reasons.append(
                "Owned group deletion was not proven, so no disposal was recorded"
            )
        verdict = self.final["result"] if self.final is not None else None
        passed = verdict == "PASS" and cleanup == "deleted" and not self.reasons
        if not passed and not self.reasons:
            self.reasons.append("Owned acceptance resource group cleanup was not proven")
        result = AcceptanceResult(
            passed, self.stage, cleanup, tuple(self.reasons),
            cleanup_reason, verdict,
        )
        try:
            self._write("summary.json", azure.canonical_json(
                result.summary(self.private),
            ))
        except (OSError, ValueError):
            pass
        return result

    def _provision(self):
        phase = custodian.record_preprovision(self.recorder, self.plan,
                                              upload=self.upload)
        journal = custodian.Journal(self.recorder.journal_path)
        start = _floor(custody._precise_utc(
            journal.by_step["deployment.create"]["started_at_utc"]))
        end = _ceil(custody._precise_utc(
            journal.by_step["vm.deallocate"]["completed_at_utc"]))
        seconds = int((end - start).total_seconds())
        if (not 1 <= seconds <= self.body["max_vm_running_seconds"]
                or seconds >= RUNTIME_LIMIT):
            raise ValueError(
                "Observed dummy VM runtime exceeds the approved maximum; "
                "refusing the OS swap"
            )
        self.dummy = ("dummy", _stamp(start), _stamp(end))
        self.consumed = seconds
        self.stage = "handoff"
        custodian.record_handoff(self.recorder, self.plan, phase)
        issued = _floor(self._wait_until(end))
        expires = min(issued + HANDOFF_LIFETIME, self.not_after)
        if expires - issued < MIN_HANDOFF_WINDOW:
            raise ValueError("Approved live window leaves too little acceptance time")
        assembler = custodian.CustodyAssembler(self.directory, self.expected)
        prepared, handoff = assembler.write_signed(
            self.records_dir, self.keys["custodian"][0], prepared_at=issued,
            handoff_at=issued, handoff_expires_at=expires, running_seconds=seconds,
        )
        verification = custodian.verify_handoff(
            prepared, handoff, expected=self.expected,
            public_key=self.keys["custodian"][1],
            archive_dir=self.directory / "archive",
            registry_dir=self.registry_dir, now=self.clock(),
            private_values=self.private,
        )
        if not verification.passed:
            raise ValueError("Local handoff verification failed: "
                             + verification.reason)
        self.prepared_raw = custodian._read_private_file(
            prepared, custody.MAX_RECORD, "PREPARED")
        self.handoff_raw = custodian._read_private_file(
            handoff, custody.MAX_RECORD, "HANDOFF")
        self.handoff_sha = verification.digest
        self.handoff_at = issued
        self.handoff_expires = expires

    def _assure(self):
        try:
            observed = self.recorder.az_text("serial.baseline", self.boot_log,
                                             timeout=300)
            self.baseline = observed.value.encode("utf-8")
        except Exception as error:
            self.baseline = b""
            self.recorder.synthetic("serial.baseline-unavailable", {
                "status": "unavailable", "error": type(error).__name__,
            })
        vm_id = self.expected.resource_ids["vm"]
        rbac = self.recorder.synthetic("witness.rbac", {
            "vm_id": vm_id, "no_other_writers": True, "complete": True,
        }).ref
        history = self.recorder.synthetic("witness.boot-history", {
            "vm_id": vm_id, "acceptance_starts": 0, "complete": True,
            "dummy_starts": 1,
        }).ref
        archive = custodian.load_archive(self.directory / "archive")
        self.vm_uuid, self.correlation, disks = custody_verifier._identity(
            self.prepared_raw, archive, self.keys["custodian"][1],
        )
        self.disks = {role: {"id": identifier, "uuid": uid}
                      for role, identifier, uid in disks}
        self._private(self.vm_uuid, self.correlation,
                      *(uid for _, _, uid in disks))
        self.baseline_generation = fresh_nonce(
            self.expected.handoff_challenge, self.expected.run_id,
        )
        self._private(self.baseline_generation)
        issued = _floor(self._wait_until(self.handoff_at))
        self.assurance_at = issued
        self.assurance_expires = self.handoff_expires
        assurance = assurance_body(
            expected=self.expected, issued_at_utc=_stamp(issued),
            expires_at_utc=_stamp(self.assurance_expires),
            handoff_sha256=self.handoff_sha,
            preprovision_sha256=_sha(self.preprovision_raw),
            vm_uuid=self.vm_uuid, disks=self.disks,
            rbac_sha256=rbac["sha256"], boot_history_sha256=history["sha256"],
            baseline_generation=self.baseline_generation,
            baseline_serial_sha256=_sha(self.baseline),
            runtime=runtime_ledger([self.dummy]),
        )
        self.assurance_raw = sign_statement(assurance, self.keys["witness"][0])
        self._write("assurance.json", self.assurance_raw)
        digests = dict.fromkeys((
            *_record_refs(json.loads(self.prepared_raw)["body"]),
            *_record_refs(json.loads(self.handoff_raw)["body"]),
            rbac["sha256"], history["sha256"],
        ))
        blobs = [archive[digest] for digest in digests]
        result = _call_verifier(
            self.verifier, "handoff", self.prepared_raw, self.handoff_raw,
            self.preprovision_raw, self.assurance_raw, self.baseline, blobs,
        )
        if not result["passed"]:
            self._reason("verifier handoff: " + result["reason"])
            return False
        if result["consumed_seconds"] != self.consumed:
            self._reason("verifier consumed runtime differs from the dummy ledger")
            return False
        return True

    def _authorize(self):
        self.stage = "dispatch"
        self.budget = (min(RUNTIME_LIMIT, self.body["max_vm_running_seconds"])
                       - self.consumed - int(STOP_MARGIN.total_seconds()))
        if self.budget < MIN_BOOT_SECONDS:
            self._reason("Approved VM runtime budget leaves no acceptance boot time")
            return False
        self.challenge = fresh_nonce(
            self.expected.handoff_challenge, self.expected.run_id,
            self.baseline_generation,
        )
        self._private(self.challenge)
        issued = _floor(self._wait_until(
            max(self.handoff_at, self.assurance_at) + timedelta(seconds=1),
        ))
        expires = self.assurance_expires
        if expires - issued < MIN_DISPATCH_WINDOW:
            self._reason("Handoff assurance leaves too little acceptance time")
            return False
        self.remaining = RUNTIME_LIMIT - self.consumed
        acceptance = acceptance_body(
            expected=self.expected, issued_at_utc=_stamp(issued),
            expires_at_utc=_stamp(expires), challenge=self.challenge,
            handoff_sha256=self.handoff_sha,
            prepared_sha256=_sha(self.prepared_raw),
            preprovision_sha256=_sha(self.preprovision_raw),
            assurance_sha256=_sha(self.assurance_raw),
            vm_uuid=self.vm_uuid, disks=self.disks,
            offline_sha256=self.statement["offline_sha256"],
            remaining_seconds=self.remaining,
        )
        self.acceptance_raw = sign_statement(acceptance, self.keys["approver"][0])
        self._write("acceptance.json", self.acceptance_raw)
        result = _call_verifier(self.verifier, "dispatch",
                                self.acceptance_raw, self.challenge)
        if not result["passed"]:
            self._reason("verifier dispatch: " + result["reason"])
            return False
        self.permit = result
        self.reserved = custody._precise_utc(result["reserved_at_utc"])
        self.permit_expires = custody._utc(result["expires_at_utc"])
        if (result["max_remaining_seconds"] != self.remaining
                or self.permit_expires != expires):
            self._reason("Verifier permit differs from the acceptance authorization")
            return False
        return True

    def _start_and_observe(self):
        self.stage = "start"
        try:
            before = self._wait_until(
                _ceil(self.reserved) + timedelta(seconds=1),
                limit=START_WAIT_LIMIT_SECONDS,
            )
        except ValueError as error:
            self._reason("Local clock did not pass the verifier reservation", error)
            return
        if (_floor(before) <= self.reserved
                or before >= self.permit_expires - STOP_MARGIN):
            self._reason("Local clock is outside the reserved start window")
            return
        self.start_before = before
        self.start_status = "lost"
        try:
            self.recorder.az("acceptance.start", [
                "vm", "start", "--resource-group", self.group,
                "--name", self.vm_name,
            ], timeout=START_TIMEOUT_SECONDS)
        except Exception as error:
            # One start only: a failed or lost response is never retried.
            self.lost_note = self.recorder.synthetic("acceptance.start-lost", {
                "status": "lost", "error": type(error).__name__,
            }).ref
            self._reason("The single VM start response failed or was lost", error)
        else:
            self.start_status = "succeeded"
            self.start_receipt = self.recorder.synthetic("witness.start-receipt", {
                "vm_id": self.expected.resource_ids["vm"],
                "vm_uuid": self.vm_uuid,
                "dispatch_sha256": self.permit["claim_sha256"],
                "status": "Succeeded", "start_count": 1,
            }).ref
        self.stage = "observation"
        if self.start_status == "succeeded":
            try:
                self._poll()
            except Exception as error:
                self._reason("Serial polling failed", error)
        self._deallocate()
        self._observe()

    def _poll(self):
        deadline = min(
            self.start_before + timedelta(seconds=self.max_poll_seconds),
            self.start_before + timedelta(seconds=self.budget),
            self.permit_expires - STOP_MARGIN,
            self.not_after - STOP_MARGIN,
        )
        final_polls = 0
        for number in range(1, MAX_POLLS + 1):
            now = custodian._aware(self.clock(), "Acceptance clock")
            if now >= deadline:
                break
            self.sleep(min(self.poll_interval, (deadline - now).total_seconds()))
            try:
                text = self.recorder.az_text(
                    f"serial.poll-{number}", self.boot_log, timeout=120,
                ).value
            except Exception as error:
                self.recorder.synthetic(f"serial.poll-{number}.unavailable", {
                    "status": "unavailable", "error": type(error).__name__,
                })
                continue
            self.serial_text = text
            status = serial_status(text)
            if status in ("failed", "complete"):
                return
            if status == "final":
                final_polls += 1
                if final_polls > FINAL_GRACE_POLLS:
                    return
        if not final_polls:
            self._reason("Guest serial did not report a final result before "
                         "the deadline")

    def _deallocate(self):
        argv = ["--resource-group", self.group, "--name", self.vm_name]
        try:
            self.recorder.az("acceptance.deallocate", ["vm", "deallocate", *argv],
                             timeout=900)
            completed = custodian.Journal(self.recorder.journal_path).by_step[
                "acceptance.deallocate"]["completed_at_utc"]
            view = self.recorder.az_settled(
                "acceptance.deallocation", ["vm", "get-instance-view", *argv],
            ).value
            if not custody._deallocation_view(view, self.expected, self.vm_uuid):
                raise ValueError("Acceptance VM instance view is not deallocated")
        except Exception as error:
            self._reason("Acceptance VM deallocation was not proven", error)
            return
        self.acceptance_end = _ceil(custody._precise_utc(completed))

    def _observe(self):
        intervals = [self.dummy]
        if self.acceptance_end is not None:
            intervals.append(("acceptance", _stamp(self.start_before),
                              _stamp(self.acceptance_end)))
        if self.start_status == "succeeded":
            if self.acceptance_end is None:
                return
            if self.serial_text is None:
                self._reason("No guest serial was captured")
                return
            try:
                parsed = topology.parse_serial(self.serial_text, self.state)
            except ValueError as error:
                self._reason("Guest serial did not prove the read-only topology",
                             error)
                return
            binding = {
                role: {
                    "id": self.expected.resource_ids[role],
                    "uuid": self.disks[role]["uuid"],
                    "controller": device["controller"],
                    "channel": device["channel"],
                    "address": device["address"],
                    "instance_crc32": device["instance_crc32"],
                    "vpd_crc32": device["vpd_crc32"],
                }
                for role, device in parsed["guest_devices"].items()
            }
            lines = [azure.ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
                     for line in self.serial_text.splitlines()]
            boots = 1 if lines.count("UK_HYPERV_PLATFORM_READY") == 1 else 0
            serial = self.serial_text.encode("utf-8")
            receipt = self.start_receipt["sha256"]
            blobs = [custodian._read_private_file(
                self.directory / "archive" / receipt, custody.MAX_ARCHIVE,
                "Start receipt",
            )]
        else:
            binding, boots, serial, blobs = {}, 0, b"", []
            receipt = self.lost_note["sha256"]
        boot_generation = fresh_nonce(
            self.baseline_generation, self.challenge,
            self.expected.handoff_challenge, self.expected.run_id,
        )
        self._private(boot_generation)
        issued = _floor(self._wait_until(max(
            self.acceptance_end or self.start_before, _ceil(self.reserved),
        )))
        observation = observation_body(
            expected=self.expected, issued_at_utc=_stamp(issued),
            challenge=self.challenge,
            dispatch_sha256=self.permit["claim_sha256"],
            acceptance_sha256=_sha(self.acceptance_raw),
            vm_uuid=self.vm_uuid,
            disk_uuids={role: item["uuid"] for role, item in self.disks.items()},
            start_status=self.start_status, start_receipt_sha256=receipt,
            observed_boot_count=boots,
            baseline_generation=self.baseline_generation,
            boot_generation=boot_generation,
            baseline_serial_sha256=_sha(self.baseline),
            serial_sha256=_sha(serial), device_binding=binding,
            runtime=runtime_ledger(intervals),
        )
        raw = sign_statement(observation, self.keys["witness"][0])
        self._write("observation.json", raw)
        self.observation_at = issued
        result = _call_verifier(self.verifier, "observation", raw, serial,
                                self.baseline, blobs)
        if result["passed"]:
            self.observed = True
            self.observation_intervals = intervals
        elif result["reason"] != "lost_start_consumed_disposal_required":
            self._reason("verifier observation: " + result["reason"])

    def _dispose(self):
        self.stage = "disposal"
        recorder = custodian.CustodianRecorder(
            self.directory, runner=_no_azure, clock=self.clock,
        )
        if self.observed:
            intervals = self.observation_intervals
        else:
            intervals = [self.dummy]
            if self.start_before is not None:
                end = self.acceptance_end or _ceil(custody._precise_utc(
                    custodian.Journal(recorder.journal_path).by_step[
                        "cleanup.exists"]["completed_at_utc"]))
                intervals.append(("acceptance", _stamp(self.start_before),
                                  _stamp(end)))
        after = self.observation_at or self.handoff_at
        self._wait_until(after + timedelta(seconds=1))
        run_id = self.expected.run_id
        returned = recorder.synthetic("custody.return-receipt", {
            "run_id": run_id, "status": "returned",
        }).ref
        disposed = recorder.synthetic("custody.disposal-receipt", {
            "run_id": run_id, "disposition": "disposed",
        }).ref
        closed_at = _stamp(self.clock())
        closed = sign_custody(closed_body(
            expected=self.expected, issued_at_utc=closed_at,
            nonce=fresh_nonce(self.expected.handoff_challenge, run_id),
            handoff_sha256=self.handoff_sha,
            acceptance_sha256=_sha(self.acceptance_raw),
            return_receipt=returned, disposal_receipt=disposed,
            disposition="disposed",
        ), self.keys["custodian"][0])
        self._write("closed.json", closed)
        ack_at = custody._utc(_stamp(self.clock()))
        ack = sign_custody(ack_body(
            expected=self.expected, issued_at_utc=_stamp(ack_at),
            closed_sha256=_sha(closed),
        ), self.keys["witness"][0])
        self._write("ack.json", ack)
        uuids = {role: item["uuid"] for role, item in self.disks.items()}
        uuids.update({"vm": self.vm_uuid, "deployment": self.correlation})
        resources = []
        refs = [returned, disposed]
        for role in custody_verifier.ROLES:
            identifier = self.expected.resource_ids[role]
            terminal = recorder.synthetic(f"witness.terminal.{role}", {
                "id": identifier, "uuid": uuids.get(role), "status": "Succeeded",
            }).ref
            refs.append(terminal)
            resources.append({
                "role": role, "id": identifier, "uuid": uuids.get(role),
                "status": "disposed", "terminal": terminal,
            })
        quiescence = recorder.synthetic("witness.quiescence", {
            "vm_id": self.expected.resource_ids["vm"], "vm_uuid": self.vm_uuid,
            "complete": True, "no_writers": True, "vm_deallocated": True,
        }).ref
        refs.append(quiescence)
        issued = self._wait_until(ack_at + timedelta(seconds=1))
        disposal = sign_statement(disposal_body(
            expected=self.expected, issued_at_utc=_stamp(issued),
            handoff_sha256=self.handoff_sha,
            dispatch_sha256=self.permit["claim_sha256"],
            acceptance_sha256=_sha(self.acceptance_raw),
            closed_sha256=_sha(closed), ack_sha256=_sha(ack),
            disposition="disposed", resources=resources,
            quiescence_sha256=quiescence["sha256"],
            runtime=runtime_ledger(intervals),
        ), self.keys["witness"][0])
        self._write("disposal.json", disposal)
        blobs = [custodian._read_private_file(
            self.directory / "archive" / ref["sha256"], custody.MAX_ARCHIVE,
            "Disposal evidence",
        ) for ref in refs]
        self.final = _call_verifier(self.verifier, "disposal", closed, ack,
                                    disposal, blobs)
        if not self.final["passed"]:
            self._reason("verifier disposal: " + self.final["reason"])


def offline_inputs_from_mapping(value):
    names = {item.name for item in fields(admission.ReviewPins)}
    if (not isinstance(value, dict)
            or not {*INPUT_PATHS, "reviewed"} <= set(value)
            or set(value) - {*INPUT_PATHS, "reviewed", "qemu_support"}):
        raise ValueError("Offline inputs have unknown or missing fields")
    if any(not isinstance(value[name], str) or not value[name]
           for name in INPUT_PATHS):
        raise ValueError("Offline input paths must be non-empty strings")
    reviewed = azure.require_exact_fields(value["reviewed"], names,
                                          "Offline review pins")
    support = value.get("qemu_support", admission.PINNED_QEMU_SUPPORT)
    if (not isinstance(support, (list, tuple))
            or any(not isinstance(item, str) or not item for item in support)):
        raise ValueError("Offline QEMU support paths must be strings")
    return admission.OfflineInputs(
        **{name: Path(value[name]) for name in INPUT_PATHS},
        reviewed=admission.ReviewPins(**reviewed),
        qemu_support=tuple(support),
    )


def key_paths(directory):
    directory = custodian._require_private_dir(directory, "Key directory")
    return {
        role: {
            "private_key": directory / f"{role}.ed25519.private",
            "public_key": directory / f"{role}.ed25519.public.hex",
        }
        for role in custodian.KEY_ROLES
    }


def _load_expected(path):
    expected = custodian.expected_from_mapping(
        custodian._load_private_json(path, "Expected custody context"),
    )
    expected.validate()
    return expected


def _expected_private(expected):
    return (expected.run_id, expected.operation_id, expected.handoff_challenge,
            *expected.resource_ids.values())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    serve_cmd = sub.add_parser(
        "serve-verifier", help="serve the offline verifier on stdin/stdout",
    )
    serve_cmd.add_argument("--offline-inputs-json", required=True, type=Path)
    serve_cmd.add_argument("--expected-json", required=True, type=Path)
    serve_cmd.add_argument("--registry-dir", required=True, type=Path)
    for role in custodian.KEY_ROLES:
        serve_cmd.add_argument(f"--{role}-public-key", required=True, type=Path)
    digest = sub.add_parser(
        "offline-digest",
        help="print the reproducible digest of a recorded offline admission",
    )
    digest.add_argument("--admission-json", required=True, type=Path)
    sign = sub.add_parser(
        "sign-preprovision",
        help="sign the TEST-ONLY approver pre-provision statement",
    )
    sign.add_argument("--expected-json", required=True, type=Path)
    sign.add_argument("--plan-json", required=True, type=Path)
    sign.add_argument("--approver-private-key", required=True, type=Path)
    sign.add_argument("--offline-sha256", required=True)
    sign.add_argument("--output", required=True, type=Path)
    approve = sub.add_parser(
        "approve-acceptance", help="sign a live acceptance approval",
    )
    approve.add_argument("--expected-json", required=True, type=Path)
    approve.add_argument("--preprovision", required=True, type=Path)
    approve.add_argument("--subscription-file", required=True, type=Path)
    approve.add_argument("--approver-private-key", required=True, type=Path)
    approve.add_argument("--not-before", required=True)
    approve.add_argument("--not-after", required=True)
    approve.add_argument("--max-vm-running-seconds", required=True, type=int)
    approve.add_argument("--output", required=True, type=Path)
    live = sub.add_parser(
        "acceptance", help="run the single owner-attested acceptance attempt",
    )
    live.add_argument("--approval", required=True, type=Path)
    live.add_argument("--preprovision", required=True, type=Path)
    live.add_argument("--keys-dir", required=True, type=Path)
    live.add_argument("--expected-json", required=True, type=Path)
    live.add_argument("--plan-json", required=True, type=Path)
    live.add_argument("--subscription-file", required=True, type=Path)
    live.add_argument("--state-dir", required=True, type=Path)
    live.add_argument("--directory", required=True, type=Path)
    live.add_argument("--records-dir", required=True, type=Path)
    live.add_argument("--registry-dir", required=True, type=Path)
    live.add_argument("--verifier-argv-json", required=True, type=Path)
    args = parser.parse_args(argv)
    return {
        "serve-verifier": _main_serve,
        "offline-digest": _main_digest,
        "sign-preprovision": _main_sign,
        "approve-acceptance": _main_approve,
        "acceptance": _main_acceptance,
    }[args.command](args)


def _main_serve(args):
    # Keep the protocol on private descriptors; admission subprocesses and any
    # diagnostics go to /dev/null so nothing private reaches the transport.
    protocol_in = os.fdopen(os.dup(0), "rb")
    protocol_out = os.fdopen(os.dup(1), "wb")
    null = os.open(os.devnull, os.O_RDWR)
    for descriptor in (0, 1, 2):
        os.dup2(null, descriptor)
    os.close(null)
    local = None
    try:
        inputs = offline_inputs_from_mapping(custodian._load_private_json(
            args.offline_inputs_json, "Offline verifier inputs",
        ))
        expected = _load_expected(args.expected_json)
        registry = custody.FileReplayRegistry(args.registry_dir)
        local = LocalVerifier(
            inputs, expected, registry,
            custodian_key=custodian.load_public_key(args.custodian_public_key),
            approver_key=custodian.load_public_key(args.approver_public_key),
            witness_key=custodian.load_public_key(args.witness_public_key),
        )
    except Exception:
        local = None
    try:
        return serve(local, protocol_in, protocol_out)
    finally:
        protocol_out.close()
        protocol_in.close()


def _main_digest(args):
    try:
        value = custodian._load_private_json(args.admission_json,
                                             "Offline admission result")
        digest = custody_verifier.reproducible_offline_sha256(value)
    except Exception:
        print("FAIL offline admission result is unreadable or malformed")
        return 1
    print("offline_sha256=" + digest)
    return 0


def _main_sign(args):
    private = []
    try:
        expected = _load_expected(args.expected_json)
        private.extend(_expected_private(expected))
        plan = custodian.plan_from_mapping(custodian._load_private_json(
            args.plan_json, "Custodian plan"), expected)
        body = preprovision_body(
            expected=expected, plan=plan, offline_sha256=args.offline_sha256,
            issued_at_utc=_stamp(custodian._utc_now()),
        )
        raw = sign_statement(body, args.approver_private_key)
        custodian._write_private_file(args.output, raw)
    except Exception as error:
        print("FAIL " + custodian.sanitize_reason(error, private))
        return 1
    print(
        "Wrote TEST-ONLY pre-provision statement; set "
        "Expected.preprovision_authorization_sha256 to " + _sha(raw)
    )
    return 0


def _main_approve(args):
    private = []
    try:
        subscription = custodian.read_subscription(args.subscription_file)
        private.append(subscription)
        expected = _load_expected(args.expected_json)
        private.extend(_expected_private(expected))
        statement = custodian._read_private_file(
            args.preprovision, custody.MAX_RECORD, "Pre-provision statement",
        )
        approver = custodian.load_private_key(args.approver_private_key)
        custody_verifier._signed(statement, "preprovision",
                                 custodian._public_bytes(approver))
        if _sha(statement) != expected.preprovision_authorization_sha256:
            raise ValueError(
                "Expected.preprovision_authorization_sha256 differs from the "
                "pre-provision statement"
            )
        group_id = expected.resource_ids["group"]
        body = custodian.approval_body(
            subscription=subscription, run_id=expected.run_id,
            operation_id=expected.operation_id, group_id=group_id,
            not_before_utc=args.not_before, not_after_utc=args.not_after,
            max_vm_running_seconds=args.max_vm_running_seconds,
            mode=custodian.LIVE_ACCEPTANCE_MODE,
            preprovision_sha256=_sha(statement),
        )
        custodian._require_owned_scope(expected, group_id)
        raw = custodian.sign_live_approval(body, approver)
        custodian._write_private_file(args.output, raw)
    except Exception as error:
        print("FAIL " + custodian.sanitize_reason(error, private))
        return 1
    print("Wrote signed TEST-ONLY acceptance approval " + _sha(raw))
    return 0


def _main_acceptance(args):
    private = []
    verifier = None
    try:
        subscription = custodian.read_subscription(args.subscription_file)
        private.append(subscription)
        expected = custodian.expected_from_mapping(custodian._load_private_json(
            args.expected_json, "Expected custody context"))
        private.extend((expected.run_id, expected.operation_id))
        if isinstance(expected.resource_ids, dict):
            private.extend(str(item) for item in expected.resource_ids.values())
        plan = custodian.plan_from_mapping(custodian._load_private_json(
            args.plan_json, "Custodian plan"), expected)
        state = topology.load(Path(args.state_dir).absolute())
        private.extend((state["prefix"], *state["disk_ids"].values()))
        argv = custodian._load_private_json(args.verifier_argv_json,
                                            "Verifier command")
        verifier = RemoteVerifier(argv)
        with custodian._interrupt_on_termination():
            result = run_acceptance(
                args.approval, preprovision=args.preprovision,
                keys=key_paths(args.keys_dir), expected=expected, plan=plan,
                subscription=subscription, state=state,
                directory=args.directory, records_dir=args.records_dir,
                registry_dir=args.registry_dir, verifier=verifier,
            )
    except Exception as error:
        print(azure.canonical_json({
            "result": "FAIL", "stage": "gate", "cleanup": "not-started",
            "reasons": [custodian.sanitize_reason(error, private)],
            "owner_attested_test_keys": True, "independent_custody": False,
        }).decode("ascii"), end="")
        return 1
    finally:
        if verifier is not None:
            verifier.close()
    print(azure.canonical_json(result.summary(private)).decode("ascii"), end="")
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
