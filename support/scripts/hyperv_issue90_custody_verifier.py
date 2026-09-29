# SPDX-License-Identifier: BSD-3-Clause
"""Opt-in offline #90 verifier. Signed assertions are not Azure observations."""

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import importlib
import re
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

azure = importlib.import_module("hyperv-azure")
admission = importlib.import_module("hyperv_issue90_offline_admission")
custody = importlib.import_module("hyperv_issue90_custody_records")
topology = importlib.import_module("hyperv_issue90_topology")

SCHEMA = "uk-hyperv-issue90-verifier-v1"
ROLES = (*custody.DIRECT, *custody.CHILDREN)
DISKS = ("dummy", "os", "data0", "data7")
MAX_SERIAL = topology.MAX_SERIAL


def _exact(value, fields, label):
    return azure.require_exact_fields(value, fields, label)


def _sha(value, label):
    return custody._sha(value, label)


def _time(value):
    return custody._utc(value)


def _signed(raw, stage, public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("A separately trusted verifier public key is required")
    envelope = _exact(custody._parse(raw, stage), ("body", "signature"), stage)
    body = envelope["body"]
    signature = envelope["signature"]
    if (not isinstance(body, dict) or body.get("schema") != SCHEMA
            or body.get("stage") != stage
            or not isinstance(signature, str)
            or not re.fullmatch(r"[0-9a-f]{128}", signature)):
        raise ValueError("Invalid signed verifier statement")
    message = (SCHEMA + "-" + stage + "\n").encode() + azure.canonical_json(body)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), message,
        )
    except (InvalidSignature, ValueError) as error:
        raise ValueError("Invalid verifier signature") from error
    return body, hashlib.sha256(raw).hexdigest()


def _when(body, run_id, operation_id, stage, now):
    if (body.get("run_id") != run_id or body.get("operation_id") != operation_id
            or _time(body.get("issued_at_utc")) > custody._now(now)):
        raise ValueError(f"{stage} is foreign or issued in the future")
    return _time(body["issued_at_utc"])


def _archive(archive, digest, label):
    digest = _sha(digest, label)
    try:
        raw = archive[digest]
    except (KeyError, TypeError):
        raise ValueError(f"{label} archive is missing") from None
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= custody.MAX_ARCHIVE
            or hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError(f"{label} archive fingerprint is invalid")
    return custody._parse(raw, label, custody.MAX_ARCHIVE, canonical=False)


def _bounded_archive(archive):
    if (type(archive) is not dict or len(archive) > 128
            or any(not isinstance(raw, bytes) or len(raw) > custody.MAX_ARCHIVE
                   or not isinstance(digest, str)
                   or not custody.SHA.fullmatch(digest)
                   for digest, raw in archive.items())
            or sum(len(raw) for raw in archive.values()) > 2 * 1024 * 1024):
        raise ValueError("A bounded in-memory evidence archive is required")


def _runtime(value, *, before=None):
    _exact(value, ("complete", "intervals", "running_seconds"), "Runtime ledger")
    intervals = value["intervals"]
    if (value["complete"] is not True or not isinstance(intervals, list)
            or len(intervals) > 16 or type(value["running_seconds"]) is not int):
        raise ValueError("Complete bounded VM runtime ledger is required")
    parsed = []
    total = 0
    previous_end = None
    for item in intervals:
        _exact(item, ("kind", "start_utc", "end_utc"), "Runtime interval")
        if item["kind"] not in ("dummy", "acceptance"):
            raise ValueError("Unknown VM runtime interval")
        start, end = _time(item["start_utc"]), _time(item["end_utc"])
        if (not start < end or (previous_end is not None and start < previous_end)
                or (before is not None and end > before)):
            raise ValueError("VM runtime intervals overlap or are out of order")
        total += int((end - start).total_seconds())
        parsed.append((item["kind"], item["start_utc"], item["end_utc"]))
        previous_end = end
    if total != value["running_seconds"] or not 0 <= total <= 3600:
        raise ValueError("VM runtime total is unknown or exceeds 60 minutes")
    return tuple(parsed), total


def _identity(prepared, archive, custodian_key):
    body, _ = custody._envelope(prepared, "prepared", custodian_key)
    receipts = body["evidence"]["direct_receipts"]
    deployment = custody._Archive(archive).read(
        receipts["deployment"]["terminal"], "Original deployment identity",
    )
    properties = custody._props(deployment)
    vm_uuid = properties["outputs"]["vmUuid"]["value"]
    return vm_uuid, properties["correlationId"], tuple(
        (role, receipts[role]["id"], receipts[role]["uuid"])
        for role in DISKS
    )


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class Refusal:
    stage: str
    reason: str
    disposal_recorded: bool = False
    scope: str = field(default="offline_only", init=False)


@dataclass(frozen=True)
class PreBootCandidate:
    offline: admission.OfflineAdmission
    handoff_sha256: str
    prepared_sha256: str
    preprovision_sha256: str
    assurance_sha256: str
    verified_at_utc: str
    assurance_issued_at_utc: str
    handoff_challenge: str
    handoff_issued_at_utc: str
    expires_at_utc: str
    baseline_generation: str
    baseline_serial_sha256: str
    vm_uuid: str
    deployment_correlation: str
    disks: tuple[tuple[str, str, str], ...]
    dummy_intervals: tuple[tuple[str, str, str], ...]
    consumed_seconds: int
    scope: str = field(default="offline_only", init=False)


@dataclass(frozen=True)
class DispatchPermit:
    preboot: PreBootCandidate
    acceptance_sha256: str
    challenge: str
    issued_at_utc: str
    reserved_at_utc: str
    expires_at_utc: str
    claim_sha256: str
    max_remaining_seconds: int
    cloud_authorized: bool = field(default=False, init=False)
    scope: str = field(default="offline_only", init=False)


@dataclass(frozen=True)
class CandidateAcceptance:
    permit: DispatchPermit
    observation_sha256: str
    serial_sha256: str
    evidence: Mapping[str, object]
    intervals: tuple[tuple[str, str, str], ...]
    running_seconds: int
    result: str = field(default="CANDIDATE", init=False)
    scope: str = field(default="offline_only", init=False)


@dataclass(frozen=True)
class FinalAcceptance:
    candidate: CandidateAcceptance
    closed_sha256: str
    witness_ack_sha256: str
    disposal_sha256: str
    result: str = field(default="PASS", init=False)
    cloud_authorized: bool = field(default=False, init=False)
    scope: str = field(default="offline_only", init=False)


class Verifier:
    def __init__(self, inputs, expected, archive, registry, *,
                 custodian_key, approver_key, witness_key, clock):
        if (type(inputs) is not admission.OfflineInputs
                or type(expected) is not custody.Expected
                or type(registry) is not custody.FileReplayRegistry
                or any(not isinstance(key, bytes) or len(key) != 32
                       for key in (custodian_key, approver_key, witness_key))
                or len({custodian_key, approver_key, witness_key}) != 3
                or type(archive) is not dict or not callable(clock)):
            raise ValueError(
                "Independent keys, trusted clock, evidence, and a durable registry are required"
            )
        expected.validate()
        _bounded_archive(archive)
        self.inputs = inputs
        self.expected = deepcopy(expected)
        self.archive = archive
        self.registry = registry
        self.custodian_key = custodian_key
        self.approver_key = approver_key
        self.witness_key = witness_key
        self.clock = clock
        self._offline = None
        self._state = None
        self._state_sha = None
        self._preboot = None
        self._permit = None
        self._candidate = None
        self._start_claim = None
        self._observation_claim = None

    def _durable_reservation(self, permit):
        self.registry.require_start(
            permit.preboot.offline.run_id, self._start_claim,
        )
        self.registry.require_dispatch_challenge(
            permit.challenge, self._start_claim,
        )
        if (permit.reserved_at_utc != self._start_claim["reserved_at_utc"]
                or permit.claim_sha256 != hashlib.sha256(
                    azure.canonical_json(self._start_claim)
                ).hexdigest()):
            raise ValueError("Permit differs from its durable one-use reservation")
        return custody._precise_utc(self._start_claim["reserved_at_utc"])

    def _unchanged_state(self):
        raw = azure.read_regular_file(
            self.inputs.state_dir / "state.json", 256 * 1024, "Offline state",
        )
        if hashlib.sha256(raw).hexdigest() != self._state_sha:
            raise ValueError("Offline image/seed identity state changed")

    def verify_offline(self):
        if self._offline is not None:
            return Refusal("offline", "offline_admission_already_consumed")
        result = admission.admit(self.inputs)
        if type(result) is admission.OfflineRefusal:
            return Refusal("offline", result.stage + "_" + result.reason)
        if type(result) is not admission.OfflineAdmission:
            return Refusal("offline", "offline_admission_unavailable")
        try:
            self.expected.validate()
            raw_before = azure.read_regular_file(
                self.inputs.state_dir / "state.json", 256 * 1024, "Offline state",
            )
            state = topology.load(self.inputs.state_dir)
            seeds = {item.role: item.vhd_sha256 for item in result.seeds}
            if (result.scope != "offline_only" or result.cloud_authorized is not False
                    or (result.run_id, result.operation_id)
                    != (state["run_id"], state["operation_id"])
                    or tuple((item.role, item.lun, item.sectors) for item
                             in result.seeds) != (
                        ("data0", 0, topology.SECTORS),
                        ("data7", 7, topology.SECTORS),
                    )
                    or seeds != self.expected.seed_sha256
                    or result.source_sha256 != self.expected.provenance_sha256
                    or result.vhd_sha256 != self.expected.reviewed_image_sha256
                    or result.reviewed_head != self.inputs.reviewed.head_commit
                    or tuple((boot.source, boot.mode, boot.image_sha256)
                             for boot in result.boots) != tuple(
                        (source, mode, result.raw_sha256 if source == "raw"
                         else result.vhd_sha256)
                        for source, mode, _ in admission.MODES
                    )):
                raise ValueError("Offline reviewed source, image, seeds or boots differ")
            if (self.expected.template_sha256 == topology.TEMPLATE_SHA256
                    or self.expected.resource_ids["group"] != topology.group_id(state)
                    or any(self.expected.resource_ids[role]
                           != topology.resource_id(state, role)
                           for role in (*topology.ROLES, *custody.CHILDREN, "deployment"))
                    or not self.expected.resource_ids["dummy"].startswith(
                        topology.group_id(state) + "/providers/Microsoft.Compute/disks/"
                    )):
                raise ValueError("Reviewed dummy template or resource envelope differs")
            prepared = {
                "image_sha256": result.vhd_sha256,
                "seeds": {item.role: {"sha256": item.vhd_sha256}
                          for item in result.seeds},
            }
            shadow = {**state, "phase": "prepared", "prepared": prepared}
            if topology.envelope_sha(shadow) != self.expected.final_envelope_sha256:
                raise ValueError("Final resource envelope differs from offline admission")
            raw_after = azure.read_regular_file(
                self.inputs.state_dir / "state.json", 256 * 1024, "Offline state",
            )
            if raw_after != raw_before:
                raise ValueError("Offline state changed during admission")
            self._state = state
            self._state_sha = hashlib.sha256(raw_before).hexdigest()
            self._offline = result
            return result
        except (ValueError, OSError, TypeError, KeyError):
            return Refusal("offline", "offline_context_missing_or_mismatched")

    def verify_handoff(self, offline, prepared, handoff, preprovision, assurance,
                       baseline, *, now):
        if offline is not self._offline or self._preboot is not None:
            return Refusal("handoff", "offline_admission_or_fresh_handoff_missing")
        try:
            self._unchanged_state()
            _bounded_archive(self.archive)
            first, first_sha = custody._envelope(
                prepared, "prepared", self.custodian_key,
            )
            second, handoff_sha = custody._envelope(
                handoff, "handoff", self.custodian_key,
            )
            approval, approval_sha = _signed(
                preprovision, "preprovision", self.approver_key,
            )
            _exact(approval, ("schema", "stage", "run_id", "operation_id",
                              "issued_at_utc", "reviewed_image_sha256",
                              "dummy_image_sha256", "provenance_sha256",
                              "reviewed_head", "config_sha256", "efi_sha256",
                              "raw_sha256", "miz_sha256", "offline_sha256",
                              "seed_sha256", "resource_ids",
                              "template_sha256", "final_envelope_sha256"),
                   "Pre-provision authorization")
            approved_at = _when(
                approval, offline.run_id, offline.operation_id, "Pre-provision", now,
            )
            if (approval_sha != self.expected.preprovision_authorization_sha256
                    or approved_at >= _time(first["issued_at_utc"])
                    or approval["reviewed_image_sha256"] != offline.vhd_sha256
                    or approval["dummy_image_sha256"]
                    != self.expected.dummy_image_sha256
                    or approval["provenance_sha256"] != offline.source_sha256
                    or approval["reviewed_head"] != offline.reviewed_head
                    or approval["config_sha256"] != offline.config_sha256
                    or approval["efi_sha256"] != offline.efi_sha256
                    or approval["raw_sha256"] != offline.raw_sha256
                    or approval["miz_sha256"] != offline.miz_sha256
                    or approval["offline_sha256"] != hashlib.sha256(
                        azure.canonical_json(asdict(offline))
                    ).hexdigest()
                    or approval["seed_sha256"] != self.expected.seed_sha256
                    or approval["resource_ids"] != self.expected.resource_ids
                    or approval["template_sha256"] != self.expected.template_sha256
                    or approval["final_envelope_sha256"]
                    != self.expected.final_envelope_sha256):
                raise ValueError("Independent pre-provision authorization differs")
            witness, witness_sha = _signed(
                assurance, "assurance", self.witness_key,
            )
            _exact(witness, ("schema", "stage", "run_id", "operation_id",
                             "issued_at_utc", "expires_at_utc", "handoff_sha256",
                             "preprovision_sha256", "challenge", "vm_uuid",
                             "disks", "no_writers", "no_prior_acceptance_boot",
                             "rbac_sha256", "boot_history_sha256",
                             "baseline_generation", "baseline_serial_sha256",
                             "runtime"),
                   "Independent handoff assurance")
            witness_at = _when(
                witness, offline.run_id, offline.operation_id, "Handoff assurance", now,
            )
            handoff_at = _time(second["issued_at_utc"])
            expires = _time(second["evidence"]["expires_at_utc"])
            custody._nonce(witness["baseline_generation"], "Baseline boot generation")
            if (not isinstance(baseline, bytes) or len(baseline) > MAX_SERIAL
                    or hashlib.sha256(baseline).hexdigest()
                    != witness["baseline_serial_sha256"]
                    or any(marker in baseline for marker in (
                        b"HYPERV_TOPOLOGY RESULT PASS",
                        b"HYPERV_TOPOLOGY FINAL PASS",
                        b"UK_HYPERV_TOPOLOGY_READ_OK",
                    ))):
                raise ValueError("Pre-dispatch serial baseline is missing or stale")
            if (witness["handoff_sha256"] != handoff_sha
                    or witness["preprovision_sha256"] != approval_sha
                    or witness["challenge"] != self.expected.handoff_challenge
                    or witness["no_writers"] is not True
                    or witness["no_prior_acceptance_boot"] is not True
                    or not handoff_at <= witness_at <= custody._now(now) < expires
                    or _time(witness["expires_at_utc"]) > expires
                    or custody._now(now) >= _time(witness["expires_at_utc"])):
                raise ValueError("Independent no-writer/boot assurance is stale")
            rbac = _archive(self.archive, witness["rbac_sha256"], "RBAC review")
            history = _archive(
                self.archive, witness["boot_history_sha256"], "Boot history",
            )
            if (rbac != {"vm_id": self.expected.resource_ids["vm"],
                         "no_other_writers": True, "complete": True}
                    or history != {"vm_id": self.expected.resource_ids["vm"],
                                   "acceptance_starts": 0, "complete": True,
                                   "dummy_starts": len(witness["runtime"]["intervals"])}):
                raise ValueError("Independent RBAC or boot-history review is incomplete")
            intervals, consumed = _runtime(witness["runtime"], before=handoff_at)
            if (any(kind != "dummy" for kind, _, _ in intervals)
                    or consumed != second["evidence"]["running_seconds"]
                    or consumed >= 3600):
                raise ValueError("Dummy boots exhausted the total VM runtime")
            digest = custody.inspect_handoff(
                prepared, handoff, expected=self.expected,
                public_key=self.custodian_key, archive=self.archive,
                registry=self.registry, now=now,
            )
            if digest != handoff_sha:
                raise ValueError("Durable handoff differs from authenticated record")
            vm_uuid, correlation, disks = _identity(
                prepared, self.archive, self.custodian_key,
            )
            if witness["vm_uuid"] != vm_uuid or witness["disks"] != {
                    role: {"id": identifier, "uuid": uid}
                    for role, identifier, uid in disks
            }:
                raise ValueError("Independent witness has foreign resource identities")
            result = PreBootCandidate(
                offline, handoff_sha, first_sha, approval_sha, witness_sha,
                custody._now(now).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                witness["issued_at_utc"],
                self.expected.handoff_challenge, second["issued_at_utc"],
                witness["expires_at_utc"], witness["baseline_generation"],
                witness["baseline_serial_sha256"], vm_uuid, correlation,
                disks, intervals, consumed,
            )
            self._unchanged_state()
            self._prepared_raw = prepared
            self._handoff_raw = handoff
            self._preboot = result
            return result
        except (ValueError, OSError, TypeError, KeyError, AttributeError):
            return Refusal("handoff", "signed_or_independent_handoff_incomplete")

    def reserve_dispatch(self, preboot, acceptance, challenge, *, now):
        if preboot is not self._preboot or self._permit is not None:
            return Refusal("dispatch", "fresh_preboot_candidate_missing")
        try:
            self._unchanged_state()
            _bounded_archive(self.archive)
            custody._nonce(challenge, "Independent acceptance challenge")
            if challenge in (preboot.handoff_challenge, preboot.offline.run_id):
                raise ValueError("Acceptance challenge was reused")
            self.registry.require_handoff(
                preboot.offline.run_id, preboot.handoff_challenge,
                preboot.handoff_sha256,
            )
            approval, approval_sha = _signed(
                acceptance, "acceptance", self.approver_key,
            )
            _exact(approval, ("schema", "stage", "run_id", "operation_id",
                              "issued_at_utc", "expires_at_utc", "challenge",
                              "handoff_sha256", "prepared_sha256",
                              "preprovision_sha256", "assurance_sha256", "vm_id",
                              "vm_uuid", "disks", "reviewed_image_sha256",
                              "offline_sha256", "seed_sha256",
                              "remaining_seconds", "one_start"),
                   "Post-handoff acceptance authorization")
            issued = _when(
                approval, preboot.offline.run_id, preboot.offline.operation_id,
                "Acceptance authorization", now,
            )
            expires = _time(approval["expires_at_utc"])
            if (not _time(preboot.handoff_issued_at_utc) < issued
                    or not issued < expires
                    or expires > _time(preboot.expires_at_utc)
                    or custody._now(now) >= expires
                    or approval["challenge"] != challenge
                    or approval["handoff_sha256"] != preboot.handoff_sha256
                    or approval["prepared_sha256"] != preboot.prepared_sha256
                    or approval["preprovision_sha256"] != preboot.preprovision_sha256
                    or approval["assurance_sha256"] != preboot.assurance_sha256
                    or approval["vm_id"] != self.expected.resource_ids["vm"]
                    or approval["vm_uuid"] != preboot.vm_uuid
                    or approval["disks"] != {
                        role: {"id": identifier, "uuid": uid}
                        for role, identifier, uid in preboot.disks
                    }
                    or approval["reviewed_image_sha256"]
                    != preboot.offline.vhd_sha256
                    or approval["offline_sha256"] != hashlib.sha256(
                        azure.canonical_json(asdict(preboot.offline))
                    ).hexdigest()
                    or approval["seed_sha256"] != self.expected.seed_sha256
                    or type(approval["remaining_seconds"]) is not int
                    or approval["remaining_seconds"] != 3600 - preboot.consumed_seconds
                    or approval["one_start"] is not True):
                raise ValueError("Acceptance authorization differs from exact handoff")
            reserved = custody._now(self.clock())
            if (not _time(preboot.handoff_issued_at_utc) < reserved
                    or not _time(preboot.assurance_issued_at_utc) < reserved
                    or custody._precise_utc(preboot.verified_at_utc) > reserved
                    or custody._now(now) > reserved
                    or issued > reserved or reserved >= expires):
                raise ValueError("Trusted reservation clock is outside the authorized window")
            reserved_at = reserved.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            claim = {
                "run_id": preboot.offline.run_id,
                "handoff_sha256": preboot.handoff_sha256,
                "acceptance_sha256": approval_sha, "challenge": challenge,
                "reserved_at_utc": reserved_at,
                "vm_uuid": preboot.vm_uuid,
                "disks": {role: uid for role, _, uid in preboot.disks},
                "remaining_seconds": 3600 - preboot.consumed_seconds,
            }
            self._unchanged_state()
            self.registry.claim_start(preboot.offline.run_id, claim)
            self.registry.claim_dispatch_challenge(challenge, claim)
            self._unchanged_state()
            self._start_claim = claim
            permit = DispatchPermit(
                preboot, approval_sha, challenge, approval["issued_at_utc"],
                reserved_at, approval["expires_at_utc"],
                hashlib.sha256(azure.canonical_json(claim)).hexdigest(),
                claim["remaining_seconds"],
            )
            self._permit = permit
            return permit
        except (ValueError, OSError, TypeError, KeyError, AttributeError):
            return Refusal("dispatch", "invalid_authorization_or_start_consumed")

    def verify_observation(self, permit, witness_record, serial, baseline, *, now):
        if permit is not self._permit or self._observation_claim is not None:
            return Refusal("observation", "one_start_or_observation_already_consumed")
        try:
            self._unchanged_state()
            _bounded_archive(self.archive)
            reserved = self._durable_reservation(permit)
            body, digest = _signed(
                witness_record, "observation", self.witness_key,
            )
            _exact(body, ("schema", "stage", "run_id", "operation_id",
                          "issued_at_utc", "challenge", "dispatch_sha256",
                          "acceptance_sha256", "vm_uuid", "disks",
                          "start_status", "start_receipt_sha256",
                          "start_dispatch_count", "observed_boot_count",
                          "baseline_generation", "boot_generation",
                          "baseline_serial_sha256", "serial_sha256",
                          "device_binding", "runtime"),
                   "Independent start and serial observation")
            captured = _when(
                body, permit.preboot.offline.run_id,
                permit.preboot.offline.operation_id, "Observation", now,
            )
            if (not reserved <= captured
                    or captured >= _time(permit.expires_at_utc)
                    or body["challenge"] != permit.challenge
                    or body["dispatch_sha256"] != permit.claim_sha256
                    or body["acceptance_sha256"] != permit.acceptance_sha256
                    or body["vm_uuid"] != permit.preboot.vm_uuid
                    or body["disks"] != {
                        role: uid for role, _, uid in permit.preboot.disks
                    }
                    or body["start_status"] not in ("succeeded", "lost")
                    or type(body["start_dispatch_count"]) is not int
                    or body["start_dispatch_count"] != 1
                    or type(body["observed_boot_count"]) is not int
                    or body["observed_boot_count"] not in (0, 1)):
                raise ValueError("Start and serial do not bind the reserved dispatch")
            _sha(body["start_receipt_sha256"], "Witnessed start receipt")
            if body["start_status"] == "succeeded":
                start = _archive(
                    self.archive, body["start_receipt_sha256"],
                    "Independent start witness receipt",
                )
                if start != {
                    "vm_id": self.expected.resource_ids["vm"],
                    "vm_uuid": permit.preboot.vm_uuid,
                    "dispatch_sha256": permit.claim_sha256,
                    "status": "Succeeded", "start_count": 1,
                }:
                    raise ValueError("Start witness receipt is foreign or incomplete")
            claim = {
                "run_id": permit.preboot.offline.run_id,
                "dispatch_sha256": permit.claim_sha256,
                "observation_sha256": digest, "status": body["start_status"],
                "observed_at_utc": body["issued_at_utc"],
            }
            if body["start_status"] == "lost":
                self.registry.claim_observation(permit.preboot.offline.run_id, claim)
                self._observation_claim = claim
                return Refusal("observation", "lost_start_consumed_disposal_required")
            custody._nonce(body["baseline_generation"], "Baseline boot generation")
            custody._nonce(body["boot_generation"], "Fresh boot generation")
            if (body["baseline_generation"]
                    != permit.preboot.baseline_generation
                    or body["baseline_serial_sha256"]
                    != permit.preboot.baseline_serial_sha256
                    or body["baseline_generation"] == body["boot_generation"]
                    or body["boot_generation"] in (
                        permit.challenge, permit.preboot.handoff_challenge,
                    ) or body["observed_boot_count"] != 1
                    or not isinstance(serial, bytes) or not 0 < len(serial) <= MAX_SERIAL
                    or not isinstance(baseline, bytes) or len(baseline) > MAX_SERIAL
                    or hashlib.sha256(serial).hexdigest() != body["serial_sha256"]
                    or hashlib.sha256(baseline).hexdigest()
                    != body["baseline_serial_sha256"]
                    or serial == baseline
                    or any(marker in baseline for marker in (
                        b"HYPERV_TOPOLOGY RESULT PASS",
                        b"HYPERV_TOPOLOGY FINAL PASS",
                        b"UK_HYPERV_TOPOLOGY_READ_OK",
                    ))):
                raise ValueError("Fresh post-start serial is unproven")
            intervals, total = _runtime(body["runtime"], before=captured)
            if (intervals[:-1] != permit.preboot.dummy_intervals
                    or len(intervals) != len(permit.preboot.dummy_intervals) + 1
                    or intervals[-1][0] != "acceptance"
                    or _time(intervals[-1][1]) <= reserved
                    or total > 3600):
                raise ValueError("Observed VM runtime is incomplete or over budget")
            parsed = topology.parse_serial(serial.decode("utf-8"), self._state)
            if (parsed["result"] != "PASS"
                    or set(parsed["guest_devices"]) != {"os", "data0", "data7"}
                    or parsed["observed_controller_count"] < 2):
                raise ValueError("Read-only multi-controller topology did not pass")
            _exact(body["device_binding"], topology.ROLES, "Guest disk binding")
            for role, _, uid in permit.preboot.disks:
                if role == "dummy":
                    continue
                guest = parsed["guest_devices"][role]
                claimed = body["device_binding"][role]
                _exact(claimed, ("id", "uuid", "controller", "channel",
                                 "address", "instance_crc32", "vpd_crc32"),
                       "Witnessed controller/LUN binding")
                if claimed != {
                    "id": self.expected.resource_ids[role], "uuid": uid,
                    "controller": guest["controller"],
                    "channel": guest["channel"], "address": guest["address"],
                    "instance_crc32": guest["instance_crc32"],
                    "vpd_crc32": guest["vpd_crc32"],
                }:
                    raise ValueError("Guest target is not bound to the original disk UUID")
            self._unchanged_state()
            self.registry.claim_observation(permit.preboot.offline.run_id, claim)
            self._observation_claim = claim
            candidate = CandidateAcceptance(
                permit, digest, parsed["serial_sha256"],
                _freeze({key: value for key, value in parsed.items()
                         if key != "result"}), intervals, total,
            )
            self._candidate = candidate
            return candidate
        except (ValueError, OSError, TypeError, KeyError, AttributeError, UnicodeError):
            return Refusal("observation", "stale_partial_or_unproven_boot")

    def verify_disposal(self, candidate_or_permit, closed, acknowledgment,
                        disposal, *, now):
        if (candidate_or_permit is not self._candidate
                and candidate_or_permit is not self._permit):
            return Refusal("disposal", "reserved_attempt_missing")
        permit = (candidate_or_permit.permit if type(candidate_or_permit)
                  is CandidateAcceptance else candidate_or_permit)
        try:
            self._unchanged_state()
            _bounded_archive(self.archive)
            self._durable_reservation(permit)
            if type(candidate_or_permit) is CandidateAcceptance:
                self.registry.require_observation(
                    permit.preboot.offline.run_id, self._observation_claim,
                )
            elif self._observation_claim is not None:
                self.registry.require_observation(
                    permit.preboot.offline.run_id, self._observation_claim,
                )
            body, disposal_sha = _signed(disposal, "disposal", self.witness_key)
            _exact(body, ("schema", "stage", "run_id", "operation_id",
                          "issued_at_utc", "handoff_sha256", "dispatch_sha256",
                          "acceptance_sha256", "closed_sha256", "ack_sha256",
                          "disposition", "resources", "all_operations_settled",
                          "no_writers", "vm_deallocated", "quiescence_sha256",
                          "runtime"),
                   "Independent complete disposal inventory")
            observed_at = _when(
                body, permit.preboot.offline.run_id,
                permit.preboot.offline.operation_id, "Disposal", now,
            )
            closed_body, _ = custody._envelope(
                closed, "closed", self.custodian_key,
            )
            ack_body, _ = custody._envelope(
                acknowledgment, "ack", self.witness_key,
            )
            closed_at = _time(closed_body["issued_at_utc"])
            ack_at = _time(ack_body["issued_at_utc"])
            observation_at = (
                _time(self._observation_claim["observed_at_utc"])
                if self._observation_claim is not None else None
            )
            if (not closed_at <= ack_at < observed_at
                    or (observation_at is not None
                        and not observation_at < closed_at)
                    or observed_at <= custody._precise_utc(permit.reserved_at_utc)
                    or body["handoff_sha256"] != permit.preboot.handoff_sha256
                    or body["dispatch_sha256"] != permit.claim_sha256
                    or body["acceptance_sha256"] != permit.acceptance_sha256
                    or body["closed_sha256"] != hashlib.sha256(closed).hexdigest()
                    or body["ack_sha256"] != hashlib.sha256(acknowledgment).hexdigest()
                    or body["disposition"] not in ("disposed", "quarantined")
                    or body["all_operations_settled"] is not True
                    or body["no_writers"] is not True
                    or body["vm_deallocated"] is not True):
                raise ValueError("Disposal assertion is foreign, incomplete or unsettled")
            intervals, total = _runtime(body["runtime"], before=observed_at)
            quiescence = _archive(
                self.archive, body["quiescence_sha256"],
                "Independent post-run quiescence",
            )
            if quiescence != {
                "vm_id": self.expected.resource_ids["vm"],
                "vm_uuid": permit.preboot.vm_uuid,
                "complete": True, "no_writers": True,
                "vm_deallocated": True,
            }:
                raise ValueError("Post-run VM quiescence is incomplete")
            if (intervals[:len(permit.preboot.dummy_intervals)]
                    != permit.preboot.dummy_intervals
                    or (type(candidate_or_permit) is CandidateAcceptance
                        and (intervals != candidate_or_permit.intervals
                             or total != candidate_or_permit.running_seconds))):
                raise ValueError("Disposal VM runtime does not reconcile")
            resources = body["resources"]
            if (not isinstance(resources, list) or len(resources) != len(ROLES)
                    or {item.get("role") for item in resources
                        if isinstance(item, dict)} != set(ROLES)):
                raise ValueError("Disposal inventory omitted an original resource")
            disk_uuids = {role: uid for role, _, uid in permit.preboot.disks}
            for item in resources:
                _exact(item, ("role", "id", "uuid", "status", "terminal"),
                       "Disposal resource")
                role = item["role"]
                expected_uuid = (
                    permit.preboot.vm_uuid if role == "vm"
                    else permit.preboot.deployment_correlation if role == "deployment"
                    else disk_uuids.get(role)
                )
                if (item["id"] != self.expected.resource_ids[role]
                        or item["uuid"] != expected_uuid
                        or item["status"] != body["disposition"]):
                    raise ValueError("Disposal resource is replaced or not settled")
                terminal = custody._Archive(self.archive).read(
                    item["terminal"], f"{role} disposal terminal",
                )
                if (not isinstance(terminal, dict)
                        or terminal.get("id") != item["id"]
                        or terminal.get("uuid") != expected_uuid
                        or terminal.get("status") != "Succeeded"):
                    raise ValueError("Disposal terminal lacks original identity")
            claim = custody.inspect_closed(
                self._prepared_raw, self._handoff_raw, closed, acknowledgment,
                expected=self.expected, public_key=self.custodian_key,
                witness_public_key=self.witness_key, archive=self.archive,
                registry=self.registry,
                acceptance_authorization_sha256=permit.acceptance_sha256,
                acceptance_issued_at_utc=permit.issued_at_utc, now=now,
            )
            if (claim.claimed_disposition != body["disposition"]
                    or claim.closed_sha256 != body["closed_sha256"]
                    or claim.witness_ack_sha256 != body["ack_sha256"]):
                raise ValueError("Acknowledged CLOSED differs from disposal inventory")
            self._unchanged_state()
            if type(candidate_or_permit) is not CandidateAcceptance:
                return Refusal("disposal", "failed_attempt_disposal_recorded", True)
            if claim.claimed_disposition != "disposed":
                return Refusal("disposal", "quarantine_recorded_not_final", True)
            return FinalAcceptance(
                candidate_or_permit, claim.closed_sha256,
                claim.witness_ack_sha256, disposal_sha,
            )
        except (ValueError, OSError, TypeError, KeyError, AttributeError):
            return Refusal("disposal", "closed_or_independent_disposal_incomplete")
