#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""#90 custodian recorder and signed handoff assembler.

Live Azure use is limited to one signed, disposable dry run; acceptance is
not available.
"""

from dataclasses import MISSING, dataclass, fields
from datetime import datetime, timedelta, timezone
import argparse
import hashlib
import importlib
import math
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

azure = importlib.import_module("hyperv-azure")
custody = importlib.import_module("hyperv_issue90_custody_records")

KEY_ROLES = ("custodian", "approver", "witness")
DISKS = ("dummy", "os", "data0", "data7")
LOCATION = "northeurope"
DEFAULT_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "azure/hyperv-issue90-dummy-topology.json"
)
JOURNAL_LIMIT = 512 * 1024
STEP = re.compile(r"[a-z0-9][a-z0-9_.-]{0,79}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PRIVATE_TOKEN = re.compile(
    r"(?:https?://|sig=|accessSAS|access[Ss][Aa][Ss])", re.IGNORECASE,
)
NO_LIVE_APPROVAL = (
    "Live #90 custodian Azure access is disabled without a valid signed "
    "disposable dry-run approval; acceptance mode is not available"
)
LIVE_APPROVAL_SCHEMA = "uk-hyperv-issue90-custodian-live-approval-v1"
LIVE_MODE = "disposable-dry-run"
LIVE_CLEANUP = "delete-owned-group"
LIVE_APPROVAL_FIELDS = (
    "schema", "version", "mode", "subscription_sha256", "location", "run_id",
    "operation_id", "group_id", "not_before_utc", "not_after_utc",
    "max_vm_running_seconds", "cleanup", "nonce",
)
LIVE_APPROVAL_LIMIT = 4096
LIVE_WINDOW = timedelta(minutes=300)
HANDOFF_LIFETIME = timedelta(minutes=30)
PLAN_FIELDS = (
    "reviewed_head", "config_sha256", "efi_sha256", "raw_sha256", "miz_sha256",
    "image_paths",
)
_MISSING = object()


class LiveApprovalRefused(RuntimeError):
    pass


class CleanupRefused(ValueError):
    pass


@dataclass(frozen=True)
class RunnerResult:
    stdout: bytes
    value: object = _MISSING


@dataclass(frozen=True)
class Observation:
    step: str
    ref: dict
    value: object


@dataclass(frozen=True)
class PhaseState:
    disk_uuids: dict
    vm_uuid: str


@dataclass(frozen=True)
class VerificationResult:
    passed: bool
    digest: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class CleanupResult:
    status: str
    deallocated: bool = False


@dataclass(frozen=True)
class LiveResult:
    passed: bool
    verification_digest: str | None
    cleanup: str
    reason: str | None = None
    cleanup_reason: str | None = None


@dataclass(frozen=True)
class CustodianPlan:
    expected: object
    reviewed_head: str
    config_sha256: str
    efi_sha256: str
    raw_sha256: str
    miz_sha256: str
    location: str = LOCATION
    template_file: Path = DEFAULT_TEMPLATE
    name_prefix: str | None = None
    image_paths: dict | None = None
    upload_sizes: dict | None = None

    def __post_init__(self):
        _hex(self.reviewed_head, HEX40, "Reviewed source head")
        for name in ("config_sha256", "efi_sha256", "raw_sha256", "miz_sha256"):
            _hex(getattr(self, name), HEX64, name)

    def group_name(self):
        return _resource_group_name(self.expected.resource_ids["group"])

    def resource_name(self, role):
        return self.expected.resource_ids[role].rsplit("/", 1)[-1]

    def prefix(self):
        if self.name_prefix is not None:
            return self.name_prefix
        name = self.resource_name("vm")
        return name[:-3] if name.endswith("-vm") else self.resource_name("deployment")

    def tags(self, role):
        return {
            "managed-by": "unikraft-hyperv",
            "purpose": "issue90-read-only-topology",
            "unikraft-run": self.prefix(),
            "issue90-run": self.expected.run_id,
            "issue90-operation": self.expected.operation_id,
            "issue90-role": role,
        }

    def tag_args(self, role):
        return [f"{key}={value}" for key, value in self.tags(role).items()]

    def image_sha256(self, role):
        if role == "dummy":
            return self.expected.dummy_image_sha256
        if role == "os":
            return self.expected.reviewed_image_sha256
        return self.expected.seed_sha256[role]

    def upload_size(self, role):
        if self.upload_sizes is not None and role in self.upload_sizes:
            return self.upload_sizes[role]
        return (azure.VIRTUAL_SIZE if role in ("dummy", "os")
                else 4 * 1024**3) + 512

    def image_path(self, role):
        if self.image_paths is None:
            return None
        return self.image_paths.get(role)

    def deployment_parameters(self, disk_uuids):
        return {
            "namePrefix": self.prefix(),
            "location": self.location,
            "runId": self.expected.run_id,
            "operationId": self.expected.operation_id,
            "reviewedHead": self.reviewed_head,
            "provenanceSha256": self.expected.provenance_sha256,
            "configSha256": self.config_sha256,
            "efiSha256": self.efi_sha256,
            "rawSha256": self.raw_sha256,
            "mizSha256": self.miz_sha256,
            "imageSha256": self.expected.reviewed_image_sha256,
            "dummyImageSha256": self.expected.dummy_image_sha256,
            "seed0Sha256": self.expected.seed_sha256["data0"],
            "seed7Sha256": self.expected.seed_sha256["data7"],
            "dummyDiskId": self.expected.resource_ids["dummy"],
            "dummyOsDiskUuid": disk_uuids["dummy"],
            "osDiskId": self.expected.resource_ids["os"],
            "acceptanceOsDiskUuid": disk_uuids["os"],
            "dataDisk0Id": self.expected.resource_ids["data0"],
            "dataDisk0Uuid": disk_uuids["data0"],
            "dataDisk7Id": self.expected.resource_ids["data7"],
            "dataDisk7Uuid": disk_uuids["data7"],
        }


class ArchiveStore:
    def __init__(self, directory):
        self.directory = _ensure_private_dir(directory)

    def put(self, raw):
        if not isinstance(raw, bytes) or len(raw) > custody.MAX_ARCHIVE:
            raise ValueError("Custodian archive observation exceeds its byte limit")
        digest = hashlib.sha256(raw).hexdigest()
        path = self.directory / digest
        try:
            _write_private_file(path, raw)
        except FileExistsError:
            if _read_private_file(path, custody.MAX_ARCHIVE, "Custodian archive blob") != raw:
                raise ValueError("Custodian archive digest collision or tampering")
        return {"sha256": digest, "size": len(raw)}


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        self.entries = _read_journal(path)
        self.by_step = {}
        for entry in self.entries:
            step = entry["step"]
            if step in self.by_step:
                raise ValueError(f"Duplicate custodian observation {step}")
            self.by_step[step] = entry

    def ref(self, step):
        try:
            return self.by_step[step]["ref"]
        except KeyError:
            raise ValueError(f"Missing custodian observation {step}") from None


class CustodianRecorder:
    def __init__(self, directory, runner=None, clock=None, revoke_runner=None):
        self.directory = _ensure_private_dir(directory)
        self.archive = ArchiveStore(self.directory / "archive")
        self.journal_path = self.directory / "journal.jsonl"
        self.runner = runner or default_az_runner
        self.revoke_runner = revoke_runner or self.runner
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sequence = len(_read_journal(self.journal_path))

    def az(self, step, argv, *, timeout=120):
        _check_step(step)
        # Write-access revocation must still reach Azure after the window.
        runner = (self.revoke_runner if list(argv[:2]) == ["disk", "revoke-access"]
                  else self.runner)
        started = _precise_timestamp(self.clock())
        result = runner(list(argv), timeout=timeout)
        completed = _precise_timestamp(self.clock())
        raw, value = _stdout_and_value(result, step)
        redacted = argv[:2] == ["disk", "grant-access"]
        stored = azure.canonical_json({
            "redacted": "grant-access stdout omitted",
        }) if redacted else raw
        return self._store(step, stored, value, argv, redacted=redacted,
                           synthetic=False, started_at_utc=started,
                           completed_at_utc=completed)

    def synthetic(self, step, value, argv=()):
        _check_step(step)
        return self._store(step, azure.canonical_json(value), value, argv,
                           redacted=False, synthetic=True,
                           started_at_utc=None, completed_at_utc=None)

    def _store(self, step, raw, value, argv, *, redacted, synthetic,
               started_at_utc, completed_at_utc):
        ref = self.archive.put(raw)
        self.sequence += 1
        entry = {
            "sequence": self.sequence,
            "step": step,
            "argv": _sanitize_argv(argv),
            "ref": ref,
            "redacted": redacted,
            "synthetic": synthetic,
            "started_at_utc": started_at_utc,
            "completed_at_utc": completed_at_utc,
        }
        _append_journal(self.journal_path, entry)
        return Observation(step, ref, value)


class CustodyAssembler:
    def __init__(self, directory, expected):
        self.directory = _require_private_dir(directory, "Custodian directory")
        self.archive_dir = _require_private_dir(
            self.directory / "archive", "Custodian archive directory",
        )
        self.journal = Journal(self.directory / "journal.jsonl")
        self.archive = load_archive(self.archive_dir)
        self.expected = expected
        self.expected.validate()

    def assemble_prepared(self, *, issued_at_utc=None, nonce=None):
        evidence = {
            "reviewed_image_sha256": self.expected.reviewed_image_sha256,
            "dummy_image_sha256": self.expected.dummy_image_sha256,
            "provenance_sha256": self.expected.provenance_sha256,
            "seed_sha256": self.expected.seed_sha256,
            "template_sha256": self.expected.template_sha256,
            "direct_receipts": self._direct_receipts(),
            "children": {
                "vm": self.journal.ref("child.vm"),
                "nic": self.journal.ref("child.nic"),
                "vnet": self.journal.ref("child.vnet"),
                "nsg": self.journal.ref("child.nsg"),
            },
            "inventory": self.journal.ref("inventory.prepared"),
            "dummy_vm": self.journal.ref("vm.dummy"),
            "dummy_disk": self.journal.ref("disk.dummy.prepared"),
            "os_disk": self.journal.ref("disk.os.prepared"),
            "data_disks": {
                "data0": self.journal.ref("disk.data0.prepared"),
                "data7": self.journal.ref("disk.data7.prepared"),
            },
        }
        return self._body(
            "prepared", 1, None, evidence,
            issued_at_utc=issued_at_utc, nonce=nonce,
        )

    def assemble_handoff(self, prepared_raw, *, issued_at_utc=None,
                         expires_at_utc=None, nonce=None, running_seconds=None,
                         no_prior_acceptance_boot=True,
                         exclusive_no_writer=True):
        prepared_sha = hashlib.sha256(prepared_raw).hexdigest()
        issued = _timestamp(issued_at_utc)
        expires = (
            _timestamp(expires_at_utc) if expires_at_utc is not None
            else _timestamp(_parse_timestamp(issued) + timedelta(minutes=30))
        )
        runtime = self._running_seconds(running_seconds)
        evidence = {
            "prepared_sha256": prepared_sha,
            "challenge": self.expected.handoff_challenge,
            "expires_at_utc": expires,
            "final_envelope_sha256": self.expected.final_envelope_sha256,
            "deallocation": self.journal.ref("vm.deallocation"),
            "swap": self.journal.ref("vm.swap"),
            "swap_tracking": None,
            "swap_settlement": self.journal.ref("vm.swap-settlement"),
            "vm": self.journal.ref("vm.final"),
            "dummy": self.journal.ref("disk.dummy.handoff"),
            "os": self.journal.ref("disk.os.handoff"),
            "data_disks": {
                "data0": self.journal.ref("disk.data0.handoff"),
                "data7": self.journal.ref("disk.data7.handoff"),
            },
            "inventory": self.journal.ref("inventory.handoff"),
            "children": {
                "vm": self.journal.ref("handoff.child.vm"),
                "nic": self.journal.ref("handoff.child.nic"),
                "vnet": self.journal.ref("handoff.child.vnet"),
                "nsg": self.journal.ref("handoff.child.nsg"),
            },
            "no_prior_acceptance_boot": no_prior_acceptance_boot,
            "exclusive_no_writer": exclusive_no_writer,
            "running_seconds": runtime,
        }
        return self._body(
            "handoff", 2, prepared_sha, evidence,
            issued_at_utc=issued, nonce=nonce,
        )

    def sign(self, body, private_key):
        key = _private_key(private_key)
        signature = key.sign(
            (custody.DOMAINS[body["stage"]] + "\n").encode("ascii")
            + azure.canonical_json(body)
        )
        return azure.canonical_json({"body": body, "signature": signature.hex()})

    def write_signed(self, output_dir, private_key, *, prepared_at=None,
                     handoff_at=None, handoff_expires_at=None,
                     prepared_nonce=None, handoff_nonce=None,
                     running_seconds=None):
        output_dir = _ensure_private_dir(output_dir)
        prepared = self.sign(
            self.assemble_prepared(
                issued_at_utc=prepared_at, nonce=prepared_nonce,
            ),
            private_key,
        )
        handoff = self.sign(
            self.assemble_handoff(
                prepared,
                issued_at_utc=handoff_at,
                expires_at_utc=handoff_expires_at,
                nonce=handoff_nonce,
                running_seconds=running_seconds,
            ),
            private_key,
        )
        prepared_path = output_dir / "prepared.json"
        handoff_path = output_dir / "handoff.json"
        _write_private_file(prepared_path, prepared)
        _write_private_file(handoff_path, handoff)
        _fsync_directory(output_dir)
        return prepared_path, handoff_path

    def _body(self, stage, sequence, previous, evidence, *,
              issued_at_utc=None, nonce=None):
        return {
            "schema": custody.SCHEMA,
            "version": 1,
            "stage": stage,
            "sequence": sequence,
            "previous_sha256": previous,
            "run_id": self.expected.run_id,
            "operation_id": self.expected.operation_id,
            "issued_at_utc": _timestamp(issued_at_utc),
            "nonce": nonce or secrets.token_hex(16),
            "preprovision_authorization_sha256":
                self.expected.preprovision_authorization_sha256,
            "evidence": evidence,
        }

    def _running_seconds(self, override):
        derived = _observed_running_seconds(self.journal)
        if override is None:
            return derived
        if type(override) is not int or override < derived:
            raise ValueError("Explicit running_seconds is below observed dummy runtime")
        return override

    def _direct_receipts(self):
        receipts = {}
        for role in custody.DIRECT:
            original = self._json(self.journal.ref(_direct_create_step(role)),
                                  f"{role} original create")
            terminal = self._json(self.journal.ref(_direct_terminal_step(role)),
                                  f"{role} terminal observation")
            receipt = {
                "id": self.expected.resource_ids[role],
                "uuid": None if role == "group"
                else custody._identity(terminal, role),
                "create": self.journal.ref(_direct_create_step(role)),
                "terminal": self.journal.ref(_direct_terminal_step(role)),
                "tracking": None,
            }
            if role in DISKS:
                receipt.update({
                    "vhd_sha256": self._image_sha(role),
                    "upload": self.journal.ref(f"disk.{role}.upload"),
                    "revocation": self.journal.ref(f"disk.{role}.revocation"),
                })
            receipts[role] = receipt
            if terminal.get("id") != self.expected.resource_ids[role]:
                raise ValueError(f"{role} terminal observation has wrong resource ID")
            if role != "group" and receipt["uuid"] is None:
                raise ValueError(f"{role} terminal observation lacks immutable identity")
            if role == "group" and original.get("id") != self.expected.resource_ids[role]:
                raise ValueError("Group original create has wrong resource ID")
        return receipts

    def _image_sha(self, role):
        if role == "dummy":
            return self.expected.dummy_image_sha256
        if role == "os":
            return self.expected.reviewed_image_sha256
        return self.expected.seed_sha256[role]

    def _json(self, ref, label):
        try:
            raw = self.archive[ref["sha256"]]
        except KeyError:
            raise ValueError(f"{label} archived bytes are missing") from None
        if len(raw) != ref["size"]:
            raise ValueError(f"{label} archived bytes differ from journal size")
        return custody._parse(raw, label, custody.MAX_ARCHIVE, canonical=False)


def default_az_runner(arguments, *, timeout=120):
    command = [
        "az", *arguments, "--only-show-errors", "--output", "json",
    ]
    environment = os.environ.copy()
    environment["AZURE_CORE_COLLECT_TELEMETRY"] = "false"
    environment["AZURE_LOGGING_ENABLE_LOG_FILE"] = "false"
    environment["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
    try:
        result = subprocess.run(
            command, capture_output=True, env=environment,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise azure.AzureCliTimeout(arguments) from None
    if result.returncode:
        if isinstance(result.stderr, bytes):
            result.stderr = result.stderr.decode("utf-8", "replace")
        raise azure.AzureCliError(arguments, result, True)
    return RunnerResult(stdout=result.stdout)


class SubscriptionRunner:
    """Pin every az call to one subscription, optionally until a deadline."""

    def __init__(self, subscription, deadline=None, clock=None, runner=None):
        self.subscription = custody._uuid(subscription, "Subscription")
        if deadline is not None:
            deadline = _aware(deadline, "Live runner deadline")
        self.deadline = deadline
        self.clock = clock or _utc_now
        self.runner = runner

    def __call__(self, arguments, *, timeout=120):
        arguments = list(arguments)
        if any(not isinstance(item, str) or item == "--subscription"
               or item.startswith("--subscription=") for item in arguments):
            raise ValueError("Custodian argv must not select its own subscription")
        if (self.deadline is not None
                and _aware(self.clock(), "Custodian clock") > self.deadline):
            raise RuntimeError(
                "Approved live window has closed; refusing further Azure calls"
            )
        runner = self.runner or default_az_runner
        return runner(
            [*arguments, "--subscription", self.subscription], timeout=timeout,
        )


def read_subscription(path):
    raw = _read_private_file(path, 128, "Subscription file")
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise ValueError("Subscription file must contain one UUID") from None
    return custody._uuid(text, "Subscription")


def approval_body(*, subscription, run_id, operation_id, group_id,
                  not_before_utc, not_after_utc, max_vm_running_seconds,
                  location=LOCATION, nonce=None):
    subscription = custody._uuid(subscription, "Subscription")
    if not_before_utc is None or not_after_utc is None:
        raise ValueError("Live approval window bounds are required")
    body = {
        "schema": LIVE_APPROVAL_SCHEMA,
        "version": 1,
        "mode": LIVE_MODE,
        "subscription_sha256": _subscription_sha256(subscription),
        "location": location,
        "run_id": run_id,
        "operation_id": operation_id,
        "group_id": group_id,
        "not_before_utc": _timestamp(not_before_utc),
        "not_after_utc": _timestamp(not_after_utc),
        "max_vm_running_seconds": max_vm_running_seconds,
        "cleanup": LIVE_CLEANUP,
        "nonce": nonce or secrets.token_hex(16),
    }
    _approval_shape(body)
    _approval_group_prefix(group_id, subscription)
    return body


def sign_live_approval(body, approver_private_key):
    _approval_shape(body)
    signature = _private_key(approver_private_key).sign(_approval_message(body))
    return azure.canonical_json({"body": body, "signature": signature.hex()})


def require_live_custodian_approval(approval_raw=None, *, approver_public_key=None,
                                    custodian_public_key=None, expected=None,
                                    plan=None, subscription=None, now=None):
    if not approval_raw:
        raise LiveApprovalRefused(NO_LIVE_APPROVAL)
    if any(value is None for value in (
        approver_public_key, custodian_public_key, expected, plan,
        subscription, now,
    )):
        raise LiveApprovalRefused(NO_LIVE_APPROVAL)
    try:
        return _require_live_approval(
            approval_raw, approver_public_key, custodian_public_key,
            expected, plan, subscription, now,
        )
    except LiveApprovalRefused:
        raise
    except Exception as error:
        raise LiveApprovalRefused(f"Live approval refused: {error}") from None


def _require_live_approval(approval_raw, approver_public_key,
                           custodian_public_key, expected, plan,
                           subscription, now):
    if not isinstance(approval_raw, bytes) or len(approval_raw) > LIVE_APPROVAL_LIMIT:
        raise ValueError("Live approval exceeds its byte limit")
    record = azure.require_exact_fields(
        custody._parse(approval_raw, "Live approval", LIVE_APPROVAL_LIMIT),
        ("body", "signature"), "Live approval",
    )
    signature = record["signature"]
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{128}", signature):
        raise ValueError("Invalid live approval signature encoding")
    approver = load_public_key(approver_public_key)
    if approver == load_public_key(custodian_public_key):
        raise ValueError("Live approver key must differ from the custodian key")
    body = record["body"]
    if not isinstance(body, dict):
        raise ValueError("Live approval body must be an object")
    try:
        Ed25519PublicKey.from_public_bytes(approver).verify(
            bytes.fromhex(signature), _approval_message(body),
        )
    except (InvalidSignature, ValueError):
        raise ValueError("Invalid live approval signature") from None
    not_before, not_after = _approval_shape(body)
    subscription = custody._uuid(subscription, "Subscription")
    if body["subscription_sha256"] != _subscription_sha256(subscription):
        raise ValueError("Live approval is bound to a different subscription")
    if not isinstance(expected, custody.Expected):
        raise ValueError("Live approval requires an Expected custody context")
    expected.validate()
    if not isinstance(plan, CustodianPlan) or plan.expected != expected:
        raise ValueError("Custodian plan differs from the expected custody context")
    if plan.location != LOCATION or body["location"] != plan.location:
        raise ValueError("Live approval location differs from the custodian plan")
    if (body["run_id"] != expected.run_id
            or body["operation_id"] != expected.operation_id):
        raise ValueError("Live approval run or operation differs from expected")
    group_id = body["group_id"]
    if group_id != expected.resource_ids["group"]:
        raise ValueError("Live approval group differs from the expected group")
    _approval_group_prefix(group_id, subscription)
    _require_owned_scope(expected, group_id)
    now = custody._now(now)
    if not not_before <= now <= not_after:
        raise ValueError("Current time is outside the approved live window")
    if (expected.preprovision_authorization_sha256
            != hashlib.sha256(approval_raw).hexdigest()):
        raise ValueError(
            "Expected preprovision authorization digest differs from the live approval"
        )
    return body


def _approval_message(body):
    return (LIVE_APPROVAL_SCHEMA + "\n").encode("ascii") + azure.canonical_json(body)


def _approval_shape(body):
    azure.require_exact_fields(body, LIVE_APPROVAL_FIELDS, "Live approval body")
    if (body["schema"] != LIVE_APPROVAL_SCHEMA
            or type(body["version"]) is not int or body["version"] != 1):
        raise ValueError("Live approval schema or version is not supported")
    if body["mode"] != LIVE_MODE:
        raise ValueError(
            "Only the disposable dry-run live mode is available; acceptance "
            "and every other live mode are not authorized"
        )
    if body["cleanup"] != LIVE_CLEANUP:
        raise ValueError("Live approval must require deleting the owned group")
    if body["location"] != LOCATION:
        raise ValueError("Live approval location is not the reviewed region")
    custody._sha(body["subscription_sha256"], "Live approval subscription digest")
    custody._nonce(body["run_id"], "Live approval run ID")
    custody._uuid(body["operation_id"], "Live approval operation ID")
    group = body["group_id"]
    parts = group.split("/") if isinstance(group, str) else []
    if (not isinstance(group, str) or len(group) > 512 or len(parts) != 5
            or parts[0] or parts[1] != "subscriptions"
            or parts[3] != "resourceGroups" or not parts[4]):
        raise ValueError("Live approval group is not a resource-group ARM path")
    not_before = custody._utc(body["not_before_utc"])
    not_after = custody._utc(body["not_after_utc"])
    if not not_before < not_after or not_after - not_before > LIVE_WINDOW:
        raise ValueError(
            "Live approval window must be positive and at most 300 minutes"
        )
    seconds = body["max_vm_running_seconds"]
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise ValueError("Live approval VM runtime budget must be 1..3600 seconds")
    custody._nonce(body["nonce"], "Live approval nonce")
    return not_before, not_after


def _approval_group_prefix(group_id, subscription):
    if not group_id.startswith(f"/subscriptions/{subscription}/resourceGroups/"):
        raise ValueError("Live approval group is outside the pinned subscription")


def _require_owned_scope(expected, group_id):
    prefix = (group_id + "/providers/").lower()
    for role, resource_id in expected.resource_ids.items():
        if role == "group":
            continue
        segments = resource_id.split("/")[1:]
        if (not resource_id.lower().startswith(prefix)
                or any(item in ("", ".", "..") for item in segments)):
            raise ValueError(
                "Every expected resource ID must be inside the approved group"
            )


def _subscription_sha256(subscription):
    return hashlib.sha256(subscription.encode("ascii")).hexdigest()


def azure_vhd_upload(role, path, sas, digest, size):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{role} image must be a regular non-symlink file")
    actual_size = path.stat().st_size
    if actual_size != size:
        raise ValueError(f"{role} image size differs from the planned upload")
    actual = azure.image_sha256(path)
    if actual != digest:
        raise ValueError(f"{role} image digest differs from the reviewed input")
    endpoint, token = azure.upload_endpoint(sas)
    azure.upload_managed_vhd(
        path, endpoint, token, timeout=1200, expected_sha256=digest,
    )
    return {"sha256": actual, "size": actual_size}


def cleanup_disposable(recorder, plan):
    """Delete only a group this journal proved new that still carries this
    run's exact owner tags and only owned resources."""
    journal = Journal(recorder.journal_path)
    proven_new = (
        "group.precheck" in journal.by_step
        and _journal_value(recorder, journal, "group.precheck") is False
    )
    if not proven_new:
        if "group.create" in journal.by_step:
            raise CleanupRefused(
                "Group pre-existence check did not prove a new group"
            )
        return CleanupResult("not-created")
    group_id = plan.expected.resource_ids["group"]
    group = plan.group_name()
    if "group.create" not in journal.by_step:
        # The absence precheck passed but create failed or timed out. A group
        # now present must still carry this run's exact owner tags below.
        probe = recorder.az("cleanup.probe", [
            "group", "exists", "--name", group,
        ]).value
        if probe is False:
            return CleanupResult("not-created")
        if probe is not True:
            return CleanupResult("unconfirmed")
    shown = recorder.az("cleanup.group", ["group", "show", "--name", group]).value
    tags = shown.get("tags") if isinstance(shown, dict) else None
    if (not isinstance(shown, dict) or not isinstance(shown.get("id"), str)
            or shown["id"].lower() != group_id.lower()):
        raise CleanupRefused("Cleanup group identity differs from the expected group")
    if (not isinstance(tags, dict)
            or any(tags.get(key) != value
                   for key, value in plan.tags("group").items())):
        raise CleanupRefused("Cleanup group lacks this run's exact owner tags")
    listed = recorder.az("cleanup.inventory", [
        "resource", "list", "--resource-group", group,
    ]).value
    owned, vm_present = _cleanup_inventory(listed, plan)
    deallocated = False
    if vm_present and "vm.deallocate" not in journal.by_step:
        try:
            recorder.az("cleanup.deallocate", [
                "vm", "deallocate", "--resource-group", group,
                "--name", plan.resource_name("vm"),
            ], timeout=900)
            deallocated = True
        except Exception:
            pass
    if not owned:
        raise CleanupRefused(
            "Cleanup group contains foreign or untagged resources; deletion refused"
        )
    listed_ids = {item["id"].lower() for item in listed}
    for role in DISKS:
        if (f"disk.{role}.revoke" in journal.by_step
                or plan.expected.resource_ids[role].lower() not in listed_ids):
            continue
        try:
            recorder.az(f"cleanup.revoke.{role}", [
                "disk", "revoke-access", "--resource-group", group,
                "--name", plan.resource_name(role),
            ], timeout=180)
        except Exception:
            pass  # An active SAS makes the group delete below fail closed.
    recorder.az("cleanup.delete", [
        "group", "delete", "--name", group, "--yes",
    ], timeout=1800)
    exists = recorder.az("cleanup.exists", [
        "group", "exists", "--name", group,
    ]).value
    if exists is not False:
        raise ValueError("Cleanup did not prove the owned group is gone")
    return CleanupResult("deleted", deallocated)


def _cleanup_inventory(listed, plan):
    if not isinstance(listed, list):
        return False, False
    prefix = (plan.expected.resource_ids["group"] + "/providers/").lower()
    vm_id = plan.expected.resource_ids["vm"].lower()
    owned = True
    vm_present = False
    for item in listed:
        resource_id = item.get("id") if isinstance(item, dict) else None
        tags = item.get("tags") if isinstance(item, dict) else None
        if (not isinstance(resource_id, str)
                or not resource_id.lower().startswith(prefix)
                or not isinstance(tags, dict)
                or tags.get("issue90-run") != plan.expected.run_id
                or tags.get("issue90-operation") != plan.expected.operation_id):
            owned = False
            continue
        if resource_id.lower() == vm_id:
            vm_present = True
    return owned, vm_present


def run_live(approval=None, *, approver_public_key=None,
             custodian_private_key=None, custodian_public_key=None,
             expected=None, plan=None, subscription=None, directory=None,
             records_dir=None, registry_dir=None, runner=None,
             cleanup_runner=None, upload=None, clock=None):
    """Run one signed disposable dry run; acceptance is never available."""
    clock = clock or _utc_now
    if approval is None:
        raise LiveApprovalRefused(NO_LIVE_APPROVAL)
    try:
        approval_raw = _read_private_file(
            approval, LIVE_APPROVAL_LIMIT, "Live approval",
        )
    except (OSError, ValueError):
        raise LiveApprovalRefused(
            NO_LIVE_APPROVAL + " (approval must be a private bounded file)"
        ) from None
    body = require_live_custodian_approval(
        approval_raw,
        approver_public_key=approver_public_key,
        custodian_public_key=custodian_public_key,
        expected=expected, plan=plan, subscription=subscription, now=clock(),
    )
    if any(value is None for value in (
        custodian_private_key, directory, records_dir, registry_dir,
    )):
        raise LiveApprovalRefused(NO_LIVE_APPROVAL)
    custodian_key = _private_key(custodian_private_key)
    custodian_public = load_public_key(custodian_public_key)
    if _public_bytes(custodian_key) != custodian_public:
        raise ValueError("Custodian private and public keys do not match")
    _check_template(plan, expected)
    if upload is None:
        _preflight_uploads(plan)
        upload = azure_vhd_upload
    records_dir = _ensure_private_dir(records_dir)
    if any(os.path.lexists(records_dir / name)
           for name in ("prepared.json", "handoff.json")):
        raise ValueError("Records directory already holds custody records")
    registry_dir = _require_private_dir(registry_dir, "Replay registry")
    if any(os.path.lexists(registry_dir / name) for name in (
        f"run-{expected.run_id}.json",
        f"challenge-{expected.handoff_challenge}.json",
    )):
        raise ValueError("Run or handoff challenge was already consumed")
    directory = _create_private_dir(directory, "Live custodian directory")
    try:
        _claim_live_approval(registry_dir, approval_raw, body)
    except BaseException:
        directory.rmdir()
        raise
    return _run_live_session(
        body, expected=expected, plan=plan, subscription=subscription,
        directory=directory, records_dir=records_dir,
        registry_dir=registry_dir, custodian_key=custodian_key,
        custodian_public=custodian_public, runner=runner,
        cleanup_runner=cleanup_runner, upload=upload, clock=clock,
    )


def _run_live_session(body, *, expected, plan, subscription, directory,
                      records_dir, registry_dir, custodian_key,
                      custodian_public, runner, cleanup_runner, upload, clock):
    not_after = custody._utc(body["not_after_utc"])
    recorder = CustodianRecorder(
        directory,
        runner=SubscriptionRunner(
            subscription, deadline=not_after, clock=clock, runner=runner,
        ),
        clock=clock,
        revoke_runner=SubscriptionRunner(
            subscription, clock=clock, runner=cleanup_runner or runner,
        ),
    )
    private = list(_live_private_values(subscription, expected, plan))

    def tracked_upload(role, path, sas, digest, size):
        if isinstance(sas, str):
            private.extend((sas, *sas.split("?", 1)[1:]))
        return upload(role, path, sas, digest, size)

    digest = reason = None
    try:
        phase = record_preprovision(recorder, plan, upload=tracked_upload)
        runtime = _observed_running_seconds(Journal(recorder.journal_path))
        if runtime > body["max_vm_running_seconds"]:
            raise ValueError(
                "Observed dummy VM runtime exceeds the approved maximum; "
                "refusing the OS swap"
            )
        record_handoff(recorder, plan, phase)
        issued = _aware(clock(), "Custodian clock").replace(microsecond=0)
        expires = min(issued + HANDOFF_LIFETIME, not_after)
        if expires <= issued:
            raise ValueError("Approved live window closed before handoff signing")
        prepared, handoff = CustodyAssembler(directory, expected).write_signed(
            records_dir, custodian_key, prepared_at=issued, handoff_at=issued,
            handoff_expires_at=expires,
        )
        verification = verify_handoff(
            prepared, handoff, expected=expected, public_key=custodian_public,
            archive_dir=directory / "archive", registry_dir=registry_dir,
            now=clock(), private_values=private,
        )
        if verification.passed:
            digest = verification.digest
        else:
            reason = verification.reason
    except BaseException as error:
        # Interrupts are reported, not re-raised, so the cleanup status is kept.
        reason = (sanitize_reason(error, private) or type(error).__name__)
        if not isinstance(error, Exception):
            reason = f"Interrupted ({type(error).__name__}): {reason}"
    finally:
        cleanup, cleanup_reason = _live_cleanup(
            directory, plan,
            SubscriptionRunner(
                subscription, clock=clock, runner=cleanup_runner or runner,
            ),
            clock, private,
        )
    passed = digest is not None and cleanup == "deleted"
    if not passed and reason is None:
        reason = "Owned dry-run resource group cleanup was not proven"
    return LiveResult(passed, digest, cleanup, reason, cleanup_reason)


def _live_cleanup(directory, plan, runner, clock, private):
    try:
        result = cleanup_disposable(
            CustodianRecorder(directory, runner=runner, clock=clock), plan,
        )
    except CleanupRefused as error:
        return "refused", sanitize_reason(error, private)
    except Exception as error:
        return "failed", sanitize_reason(error, private)
    if result.status == "unconfirmed":
        return result.status, (
            "Group creation could be neither confirmed nor ruled out; no "
            "deletion was attempted, so check the subscription manually"
        )
    return result.status, None


def _live_private_values(subscription, expected, plan):
    values = {
        subscription, expected.run_id, expected.operation_id,
        expected.handoff_challenge, plan.group_name(), plan.prefix(),
    }
    for resource_id in expected.resource_ids.values():
        values.add(resource_id)
        values.add(resource_id.rsplit("/", 1)[-1])
    return tuple(sorted(values))


def _claim_live_approval(registry_dir, approval_raw, body):
    digest = hashlib.sha256(approval_raw).hexdigest()
    claim = azure.canonical_json({
        "approval_sha256": digest,
        "run_id": body["run_id"],
        "nonce": body["nonce"],
    })
    try:
        _write_private_file(registry_dir / f"live-approval-{digest}.json", claim)
    except FileExistsError:
        raise LiveApprovalRefused("Live approval was already consumed") from None


def _check_template(plan, expected):
    raw = azure.read_regular_file(
        plan.template_file, 1024 * 1024, "Custodian ARM template",
    )
    if hashlib.sha256(raw).hexdigest() != expected.template_sha256:
        raise ValueError("ARM template bytes differ from Expected.template_sha256")


def _preflight_uploads(plan):
    for role in DISKS:
        path = plan.image_path(role)
        if path is None:
            raise ValueError(f"{role} image path is required")
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{role} image must be a regular non-symlink file")
        if path.stat().st_size != plan.upload_size(role):
            raise ValueError(f"{role} image size differs from the planned upload")
    azure.check_upload_dependencies()


def _observed_running_seconds(journal):
    try:
        started = journal.by_step["deployment.create"]["started_at_utc"]
        completed = journal.by_step["vm.deallocate"]["completed_at_utc"]
    except KeyError:
        raise ValueError(
            "Missing custodian timestamps for dummy VM runtime"
        ) from None
    if started is None or completed is None:
        raise ValueError("Missing custodian timestamps for dummy VM runtime")
    start = custody._precise_utc(started)
    end = custody._precise_utc(completed)
    if end < start:
        raise ValueError("Custodian dummy VM runtime timestamps are reversed")
    return max(1, math.ceil((end - start).total_seconds()))


def _journal_value(recorder, journal, step):
    ref = journal.ref(step)
    raw = _read_private_file(
        recorder.archive.directory / ref["sha256"], custody.MAX_ARCHIVE,
        "Custodian archive blob",
    )
    if len(raw) != ref["size"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        raise ValueError("Custodian archive blob differs from its journal reference")
    return _parse_stdout(raw, step)


def record_preprovision(recorder, plan, *, upload=None):
    plan.expected.validate()
    if upload is None:
        raise ValueError("A VHD upload callable is required")
    for role in DISKS:
        if plan.image_path(role) is None:
            raise ValueError(f"{role} image path is required")
    group = plan.group_name()
    exists = recorder.az("group.precheck", [
        "group", "exists", "--name", group,
    ]).value
    if exists is not False:
        raise ValueError(
            "Resource group already exists or its absence is unproven; "
            "refusing to adopt it"
        )
    recorder.az("group.create", [
        "group", "create", "--name", group, "--location", plan.location,
        "--tags", *plan.tag_args("group"),
    ], timeout=300)
    recorder.az("group.terminal", [
        "group", "show", "--name", group,
    ])
    disk_uuids = {}
    for role in DISKS:
        size = plan.upload_size(role)
        argv = [
            "disk", "create", "--resource-group", group,
            "--name", plan.resource_name(role), "--location", plan.location,
            "--upload-type", "Upload", "--upload-size-bytes", str(size),
            "--sku", "StandardSSD_LRS", "--tags", *plan.tag_args(role),
        ]
        if role in ("dummy", "os"):
            argv += ["--os-type", "Linux", "--hyper-v-generation", "V2"]
        created = recorder.az(f"disk.{role}.create", argv, timeout=600).value
        disk_uuids[role] = custody._identity(created, role)
        if disk_uuids[role] is None:
            raise ValueError(f"{role} create response lacks an immutable disk UUID")
        revoke = [
            "disk", "revoke-access", "--resource-group", group,
            "--name", plan.resource_name(role),
        ]
        try:
            grant = recorder.az(f"disk.{role}.grant", [
                "disk", "grant-access", "--resource-group", group,
                "--name", plan.resource_name(role), "--access-level", "Write",
                "--duration-in-seconds", "1800",
            ]).value
            sas = _grant_sas(grant)
            uploaded_sha, uploaded_size = _upload_result(
                upload(role, plan.image_path(role), sas,
                       plan.image_sha256(role), size)
            )
            if uploaded_sha != plan.image_sha256(role) or uploaded_size != size:
                raise ValueError(f"{role} uploaded bytes differ from reviewed input")
        except BaseException:
            try:
                recorder.az(f"disk.{role}.revoke", revoke, timeout=180)
            except Exception:
                pass  # Cleanup revokes every owned disk again before deletion.
            raise
        recorder.synthetic(f"disk.{role}.upload", {
            "id": plan.expected.resource_ids[role],
            "sha256": uploaded_sha,
            "size": uploaded_size,
            "status": "Succeeded",
        })
        recorder.az(f"disk.{role}.revoke", revoke, timeout=180)
        recorder.synthetic(f"disk.{role}.revocation", {
            "id": plan.expected.resource_ids[role],
            "status": "Succeeded",
            "active_sas": False,
        })
        recorder.az(f"disk.{role}.terminal", [
            "disk", "show", "--resource-group", group,
            "--name", plan.resource_name(role),
        ])
    parameters = plan.deployment_parameters(disk_uuids)
    parameter_args = [f"{key}={value}" for key, value in parameters.items()]
    recorder.az("deployment.create", [
        "deployment", "group", "create", "--resource-group", group,
        "--name", plan.resource_name("deployment"),
        "--template-file", str(plan.template_file),
        "--parameters", *parameter_args,
    ], timeout=1800)
    deployment = recorder.az("deployment.terminal", [
        "deployment", "group", "show", "--resource-group", group,
        "--name", plan.resource_name("deployment"),
    ]).value
    vm_uuid = _deployment_vm_uuid(deployment)
    _record_children(recorder, plan, prefix="child")
    recorder.az("vm.deallocate", [
        "vm", "deallocate", "--resource-group", group,
        "--name", plan.resource_name("vm"),
    ], timeout=900)
    recorder.az("vm.dummy", [
        "vm", "show", "-d", "--resource-group", group,
        "--name", plan.resource_name("vm"),
    ])
    recorder.az("vm.deallocation", [
        "vm", "get-instance-view", "--resource-group", group,
        "--name", plan.resource_name("vm"),
    ])
    for role in DISKS:
        recorder.az(f"disk.{role}.prepared", [
            "disk", "show", "--resource-group", group,
            "--name", plan.resource_name(role),
        ])
    _record_inventory(recorder, plan, "inventory.prepared", disk_uuids, vm_uuid)
    return PhaseState(disk_uuids, vm_uuid)


def record_handoff(recorder, plan, phase):
    group = plan.group_name()
    recorder.az("vm.swap", [
        "vm", "update", "--resource-group", group,
        "--name", plan.resource_name("vm"), "--os-disk",
        plan.expected.resource_ids["os"],
    ], timeout=900)
    recorder.az("vm.swap-settlement", [
        "vm", "show", "-d", "--resource-group", group,
        "--name", plan.resource_name("vm"),
    ])
    recorder.az("vm.final", [
        "vm", "show", "-d", "--resource-group", group,
        "--name", plan.resource_name("vm"),
    ])
    _record_children(recorder, plan, prefix="handoff.child")
    for role in DISKS:
        recorder.az(f"disk.{role}.handoff", [
            "disk", "show", "--resource-group", group,
            "--name", plan.resource_name(role),
        ])
    _record_inventory(
        recorder, plan, "inventory.handoff", phase.disk_uuids, phase.vm_uuid,
    )


def verify_handoff(prepared_path, handoff_path, *, expected, public_key,
                   archive_dir, registry_dir, now=None, output=None,
                   private_values=()):
    try:
        archive = load_archive(archive_dir)
        registry = custody.FileReplayRegistry(registry_dir)
        try:
            digest = custody.inspect_handoff(
                _read_private_file(prepared_path, custody.MAX_RECORD, "PREPARED"),
                _read_private_file(handoff_path, custody.MAX_RECORD, "HANDOFF"),
                expected=expected,
                public_key=load_public_key(public_key),
                archive=archive,
                registry=registry,
                now=now or datetime.now(timezone.utc),
            )
        finally:
            registry.close()
    except ValueError as error:
        reason = sanitize_reason(error, private_values)
        if output is not None:
            print("FAIL " + reason, file=output)
        return VerificationResult(False, reason=reason)
    except OSError as error:
        reason = sanitize_reason(error, private_values)
        if output is not None:
            print("FAIL " + reason, file=output)
        return VerificationResult(False, reason=reason)
    if output is not None:
        print("PASS", file=output)
    return VerificationResult(True, digest=digest)


def load_archive(directory):
    directory = _require_private_dir(directory, "Custodian archive directory")
    result = {}
    for path in sorted(directory.iterdir()):
        if not custody.SHA.fullmatch(path.name):
            raise ValueError("Custodian archive contains an unexpected file")
        raw = _read_private_file(path, custody.MAX_ARCHIVE, "Custodian archive blob")
        result[path.name] = raw
    return result


def generate_test_keys(directory):
    directory = _create_private_dir(directory)
    result = {}
    public_values = set()
    for role in KEY_ROLES:
        private = Ed25519PrivateKey.generate()
        private_raw = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if public_raw in public_values:
            raise ValueError("Generated duplicate Ed25519 public key")
        public_values.add(public_raw)
        private_path = directory / f"{role}.ed25519.private"
        public_path = directory / f"{role}.ed25519.public.hex"
        _write_private_file(private_path, private_raw)
        _write_private_file(public_path, public_raw.hex().encode("ascii") + b"\n")
        result[role] = {
            "private_key": private_path,
            "public_key": public_path,
            "public_key_hex": public_raw.hex(),
        }
    _write_private_file(directory / "WARNING.txt", (
        "TEST-ONLY #90 custodian keys generated by one operator.\n"
        "They do not provide independent custodian/approver/witness custody.\n"
    ).encode("ascii"))
    _fsync_directory(directory)
    return result


def load_public_key(value):
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes")
        return value
    path = Path(value)
    raw = _read_private_file(path, 256, "Ed25519 public key")
    text = raw.strip()
    if len(text) == 64 and re.fullmatch(rb"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text.decode("ascii"))
    if len(raw) == 32:
        return raw
    raise ValueError("Ed25519 public key must be raw bytes or hex")


def load_private_key(value):
    return _private_key(value)


def expected_from_mapping(value):
    if not isinstance(value, dict):
        raise ValueError("Expected custody context must be a JSON object")
    names = {field.name: field for field in fields(custody.Expected)}
    extras = set(value) - set(names)
    if extras:
        raise ValueError("Expected custody context contains unknown fields")
    kwargs = {}
    for name, field in names.items():
        if name in value:
            kwargs[name] = value[name]
        elif field.default is MISSING and field.default_factory is MISSING:
            raise ValueError(f"Expected custody context is missing {name}")
    return custody.Expected(**kwargs)


def plan_from_mapping(value, expected):
    if not isinstance(value, dict):
        raise ValueError("Custodian plan must be a JSON object")
    if set(value) - {*PLAN_FIELDS, "upload_sizes"} or not set(PLAN_FIELDS) <= set(value):
        raise ValueError("Custodian plan has unknown or missing fields")
    paths = azure.require_exact_fields(
        value["image_paths"], DISKS, "Custodian plan image paths",
    )
    if any(not isinstance(item, str) or not item for item in paths.values()):
        raise ValueError("Custodian plan image paths must be non-empty strings")
    sizes = value.get("upload_sizes")
    if sizes is not None and (
        not isinstance(sizes, dict) or set(sizes) - set(DISKS)
        or any(type(item) is not int or item <= 0 for item in sizes.values())
    ):
        raise ValueError("Custodian plan upload sizes are invalid")
    return CustodianPlan(
        expected=expected,
        reviewed_head=value["reviewed_head"],
        config_sha256=value["config_sha256"],
        efi_sha256=value["efi_sha256"],
        raw_sha256=value["raw_sha256"],
        miz_sha256=value["miz_sha256"],
        image_paths={role: Path(item) for role, item in paths.items()},
        upload_sizes=sizes,
    )


def sanitize_reason(error, private_values=()):
    return azure.safe_failure_message(error, private_values)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keys", help="generate self-held TEST-ONLY Ed25519 keys")
    keys.add_argument("directory", type=Path)
    verify = sub.add_parser("verify", help="run offline handoff validation")
    verify.add_argument("--prepared", required=True, type=Path)
    verify.add_argument("--handoff", required=True, type=Path)
    verify.add_argument("--archive-dir", required=True, type=Path)
    verify.add_argument("--registry-dir", required=True, type=Path)
    verify.add_argument("--expected-json", required=True, type=Path)
    verify.add_argument("--custodian-public-key", required=True, type=Path)
    verify.add_argument("--now")
    approve = sub.add_parser(
        "approve-dry-run",
        help="sign a disposable dry-run live approval (acceptance unavailable)",
    )
    approve.add_argument("--expected-json", required=True, type=Path)
    approve.add_argument("--subscription-file", required=True, type=Path)
    approve.add_argument("--approver-private-key", required=True, type=Path)
    approve.add_argument("--not-before", required=True)
    approve.add_argument("--not-after", required=True)
    approve.add_argument("--max-vm-running-seconds", required=True, type=int)
    approve.add_argument("--output", required=True, type=Path)
    live = sub.add_parser(
        "live", help="run one signed disposable dry run (acceptance unavailable)",
    )
    live.add_argument("--approval", required=True, type=Path)
    live.add_argument("--approver-public-key", required=True, type=Path)
    live.add_argument("--custodian-private-key", required=True, type=Path)
    live.add_argument("--custodian-public-key", required=True, type=Path)
    live.add_argument("--expected-json", required=True, type=Path)
    live.add_argument("--subscription-file", required=True, type=Path)
    live.add_argument("--plan-json", required=True, type=Path)
    live.add_argument("--directory", required=True, type=Path)
    live.add_argument("--records-dir", required=True, type=Path)
    live.add_argument("--registry-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "keys":
        generate_test_keys(args.directory)
        print(
            "Wrote TEST-ONLY Ed25519 key set. A single operator holding all "
            "three roles is not independent custody."
        )
        return 0
    if args.command == "approve-dry-run":
        return _main_approve(args)
    if args.command == "live":
        return _main_live(args)
    expected = expected_from_mapping(azure.load_strict_json(
        args.expected_json, custody.MAX_RECORD, "Expected custody context",
    )[0])
    result = verify_handoff(
        args.prepared, args.handoff,
        expected=expected,
        public_key=args.custodian_public_key,
        archive_dir=args.archive_dir,
        registry_dir=args.registry_dir,
        now=_parse_timestamp(args.now) if args.now else None,
        output=sys.stdout,
    )
    return 0 if result.passed else 1


def _main_approve(args):
    private = []
    try:
        subscription = read_subscription(args.subscription_file)
        private.append(subscription)
        expected = expected_from_mapping(
            _load_private_json(args.expected_json, "Expected custody context"),
        )
        expected.validate()
        private.extend((expected.run_id, expected.operation_id,
                        *expected.resource_ids.values()))
        group_id = expected.resource_ids["group"]
        body = approval_body(
            subscription=subscription,
            run_id=expected.run_id,
            operation_id=expected.operation_id,
            group_id=group_id,
            not_before_utc=args.not_before,
            not_after_utc=args.not_after,
            max_vm_running_seconds=args.max_vm_running_seconds,
        )
        _require_owned_scope(expected, group_id)
        raw = sign_live_approval(body, args.approver_private_key)
        _write_private_file(args.output, raw)
    except Exception as error:
        print("FAIL " + sanitize_reason(error, private))
        return 1
    print(
        "Wrote signed disposable dry-run approval; set "
        "Expected.preprovision_authorization_sha256 to "
        + hashlib.sha256(raw).hexdigest()
    )
    return 0


def _main_live(args):
    private = []
    try:
        subscription = read_subscription(args.subscription_file)
        private.append(subscription)
        expected = expected_from_mapping(
            _load_private_json(args.expected_json, "Expected custody context"),
        )
        private.extend((expected.run_id, expected.operation_id))
        if isinstance(expected.resource_ids, dict):
            private.extend(str(item) for item in expected.resource_ids.values())
        plan = plan_from_mapping(azure.load_strict_json(
            args.plan_json, custody.MAX_RECORD, "Custodian plan",
        )[0], expected)
        with _interrupt_on_termination():
            result = run_live(
                args.approval,
                approver_public_key=args.approver_public_key,
                custodian_private_key=args.custodian_private_key,
                custodian_public_key=args.custodian_public_key,
                expected=expected, plan=plan, subscription=subscription,
                directory=args.directory, records_dir=args.records_dir,
                registry_dir=args.registry_dir,
            )
    except Exception as error:
        print("FAIL " + sanitize_reason(error, private) + " cleanup=not-started")
        return 1
    if result.passed:
        print("PASS cleanup=deleted")
        return 0
    message = "FAIL " + sanitize_reason(result.reason, private)
    message += " cleanup=" + result.cleanup
    if result.cleanup_reason:
        message += " (" + sanitize_reason(result.cleanup_reason, private) + ")"
    print(message)
    return 1


class _interrupt_on_termination:
    """Turn SIGTERM/SIGHUP into KeyboardInterrupt so owned cleanup runs."""

    SIGNALS = tuple(getattr(signal, name) for name in ("SIGTERM", "SIGHUP")
                    if hasattr(signal, name))

    def __enter__(self):
        self.previous = {}
        for number in self.SIGNALS:
            if signal.getsignal(number) is signal.SIG_IGN:
                continue  # Respect nohup and other inherited ignores.
            self.previous[number] = signal.signal(number, self._raise)
        return self

    def __exit__(self, *_exc):
        for number, handler in self.previous.items():
            signal.signal(number, handler)
        return False

    def _raise(self, number, _frame):
        # Fire once: later signals must not abort the owned cleanup, and the
        # cleanup az children inherit the ignore disposition.
        for item in self.previous:
            signal.signal(item, signal.SIG_IGN)
        raise KeyboardInterrupt(f"signal {number}")


def _load_private_json(path, label):
    return azure.parse_strict_json(
        _read_private_file(path, custody.MAX_RECORD, label), label,
    )
    result = verify_handoff(
        args.prepared, args.handoff,
        expected=expected,
        public_key=args.custodian_public_key,
        archive_dir=args.archive_dir,
        registry_dir=args.registry_dir,
        now=_parse_timestamp(args.now) if args.now else None,
        output=sys.stdout,
    )
    return 0 if result.passed else 1


def _private_key(value):
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes):
        raw = value
    else:
        raw = _read_private_file(value, 256, "Ed25519 private key")
    if len(raw) != 32:
        raise ValueError("Ed25519 private key must be 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _utc_now():
    return datetime.now(timezone.utc)


def _aware(value, label):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{label} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _record_children(recorder, plan, *, prefix):
    group = plan.group_name()
    recorder.az(f"{prefix}.vm", [
        "vm", "show", "--resource-group", group,
        "--name", plan.resource_name("vm"),
    ])
    recorder.az(f"{prefix}.nic", [
        "network", "nic", "show", "--resource-group", group,
        "--name", plan.resource_name("nic"),
    ])
    recorder.az(f"{prefix}.vnet", [
        "network", "vnet", "show", "--resource-group", group,
        "--name", plan.resource_name("vnet"),
    ])
    recorder.az(f"{prefix}.nsg", [
        "network", "nsg", "show", "--resource-group", group,
        "--name", plan.resource_name("nsg"),
    ])


def _record_inventory(recorder, plan, step, disk_uuids, vm_uuid):
    listed = recorder.az(step + ".list", [
        "resource", "list", "--resource-group", plan.group_name(),
    ]).value
    _validate_inventory_list(listed, plan)
    recorder.synthetic(step, {
        "resources": [
            {
                "role": role,
                "id": plan.expected.resource_ids[role],
                "uuid": vm_uuid if role == "vm" else disk_uuids.get(role),
            }
            for role in custody.INVENTORY
        ],
    })


def _validate_inventory_list(resources, plan):
    expected = {
        plan.expected.resource_ids[role].lower(): (role, _resource_type(role))
        for role in custody.INVENTORY
    }
    if not isinstance(resources, list):
        raise ValueError("Custodian inventory observation must be a list")
    seen = {}
    for resource in resources:
        if not isinstance(resource, dict):
            raise ValueError("Custodian inventory contains a non-object resource")
        resource_id = resource.get("id")
        resource_type = resource.get("type")
        if not isinstance(resource_id, str) or not isinstance(resource_type, str):
            raise ValueError("Custodian inventory resource lacks ID or type")
        folded = resource_id.lower()
        if folded in seen:
            raise ValueError("Custodian inventory contains duplicate resources")
        seen[folded] = resource
        if folded not in expected:
            raise ValueError("Custodian inventory contains an unexpected resource")
        _role, expected_type = expected[folded]
        if resource_type.lower() != expected_type.lower():
            raise ValueError("Custodian inventory resource has an unexpected type")
    if set(seen) != set(expected):
        raise ValueError("Custodian inventory is missing expected resources")


def _resource_type(role):
    return {
        "dummy": "Microsoft.Compute/disks",
        "os": "Microsoft.Compute/disks",
        "data0": "Microsoft.Compute/disks",
        "data7": "Microsoft.Compute/disks",
        "vm": "Microsoft.Compute/virtualMachines",
        "nic": "Microsoft.Network/networkInterfaces",
        "vnet": "Microsoft.Network/virtualNetworks",
        "nsg": "Microsoft.Network/networkSecurityGroups",
    }[role]


def _direct_create_step(role):
    if role == "group":
        return "group.create"
    if role == "deployment":
        return "deployment.create"
    return f"disk.{role}.create"


def _direct_terminal_step(role):
    if role == "group":
        return "group.terminal"
    if role == "deployment":
        return "deployment.terminal"
    return f"disk.{role}.terminal"


def _resource_group_name(resource_id):
    parts = resource_id.split("/")
    if len(parts) < 5 or parts[3].lower() != "resourcegroups":
        raise ValueError("Expected group ID is not an ARM resource group path")
    return parts[4]


def _deployment_vm_uuid(deployment):
    props = custody._props(deployment)
    outputs = props.get("outputs") if isinstance(props, dict) else None
    value = outputs.get("vmUuid") if isinstance(outputs, dict) else None
    if not isinstance(value, dict) or not isinstance(value.get("value"), str):
        raise ValueError("Deployment observation lacks VM UUID output")
    return value["value"]


def _grant_sas(value):
    if not isinstance(value, dict) or not isinstance(value.get("accessSAS"), str):
        raise ValueError("grant-access did not return an accessSAS value")
    return value["accessSAS"]


def _upload_result(value):
    if isinstance(value, dict):
        sha = value.get("sha256")
        size = value.get("size")
    elif isinstance(value, tuple) and len(value) == 2:
        sha, size = value
    else:
        raise ValueError("Upload callable must return sha256 and size")
    custody._sha(sha, "Upload digest")
    if type(size) is not int or size <= 0:
        raise ValueError("Upload size is invalid")
    return sha, size


def _stdout_and_value(result, label):
    if isinstance(result, RunnerResult):
        raw = result.stdout
        if not isinstance(raw, bytes):
            raise ValueError(f"{label} runner stdout must be bytes")
        value = result.value
        if value is _MISSING:
            value = _parse_stdout(raw, label)
        return raw, value
    if isinstance(result, bytes):
        return result, _parse_stdout(result, label)
    raise ValueError("Custodian runner must return original stdout bytes")


def _parse_stdout(raw, label):
    if not isinstance(raw, bytes):
        raise ValueError(f"{label} runner stdout must be bytes")
    if not raw.strip():
        return None
    return azure.parse_strict_json(raw, label)


def _timestamp(value=None):
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, datetime):
        value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        custody._utc(value)
        return value
    raise ValueError("Custody timestamp must be a UTC datetime or string")


def _precise_timestamp(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Custodian clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    return custody._utc(value)


def _check_step(step):
    if not isinstance(step, str) or not STEP.fullmatch(step):
        raise ValueError("Custodian observation step name is invalid")


def _sanitize_argv(argv):
    result = []
    for item in argv:
        if not isinstance(item, str) or len(item) > 2048:
            raise ValueError("Custodian argv contains an invalid item")
        result.append("<redacted-secret>" if PRIVATE_TOKEN.search(item) else item)
    return result


def _hex(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value) or not int(value, 16):
        raise ValueError(f"{label} must be nonzero lowercase hex")
    return value


def _read_journal(path):
    path = Path(path)
    if not path.exists():
        return []
    raw = _read_private_file(path, JOURNAL_LIMIT, "Custodian journal")
    entries = []
    for number, line in enumerate(raw.splitlines(), 1):
        entry = azure.require_exact_fields(
            azure.parse_strict_json(line, "Custodian journal entry"),
            ("sequence", "step", "argv", "ref", "redacted", "synthetic",
             "started_at_utc", "completed_at_utc"),
            "Custodian journal entry",
        )
        if entry["sequence"] != number:
            raise ValueError("Custodian journal sequence is not append-only")
        _check_step(entry["step"])
        if (not isinstance(entry["argv"], list)
                or any(not isinstance(item, str) for item in entry["argv"])
                or not isinstance(entry["redacted"], bool)
                or not isinstance(entry["synthetic"], bool)):
            raise ValueError("Custodian journal entry is malformed")
        if entry["synthetic"]:
            if (entry["started_at_utc"] is not None
                    or entry["completed_at_utc"] is not None):
                raise ValueError("Synthetic journal entries cannot claim runner time")
        else:
            started = custody._precise_utc(entry["started_at_utc"])
            completed = custody._precise_utc(entry["completed_at_utc"])
            if completed < started:
                raise ValueError("Custodian journal timestamps are reversed")
        _archive_ref(entry["ref"], allow_empty=True)
        entries.append(entry)
    return entries


def _append_journal(path, entry):
    raw = azure.canonical_json(entry)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError("Custodian journal must be a private regular file")
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(Path(path).parent)


def _archive_ref(value, *, allow_empty):
    azure.require_exact_fields(value, ("sha256", "size"), "Archive reference")
    custody._sha(value["sha256"], "Archive reference")
    size = value["size"]
    if type(size) is not int or size < 0 or size > custody.MAX_ARCHIVE:
        raise ValueError("Archive reference has invalid size")
    if not allow_empty and size == 0:
        raise ValueError("Archive reference is empty")
    return value


def _ensure_private_dir(path):
    path = Path(path).absolute()
    if path.exists():
        return _require_private_dir(path, "Custodian directory")
    os.mkdir(path, 0o700)
    try:
        os.chmod(path, 0o700)
        _fsync_directory(path.parent)
        return _require_private_dir(path, "Custodian directory")
    except BaseException:
        try:
            path.rmdir()
        finally:
            raise


def _create_private_dir(path, label="Custodian key directory"):
    path = Path(path).absolute()
    if path.exists():
        raise FileExistsError(f"{label} already exists")
    os.mkdir(path, 0o700)
    try:
        os.chmod(path, 0o700)
        _fsync_directory(path.parent)
        return _require_private_dir(path, label)
    except BaseException:
        try:
            path.rmdir()
        finally:
            raise


def _require_private_dir(path, label):
    path = Path(path).absolute()
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or path.resolve(strict=True) != path):
        raise ValueError(f"{label} must be an owner-only symlink-free directory")
    return path


def _write_private_file(path, raw):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    _fsync_directory(Path(path).parent)


def _read_private_file(path, maximum, label):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or info.st_size > maximum):
            raise ValueError(f"{label} must be a private bounded regular file")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise ValueError(f"{label} exceeds its size limit")
        return raw
    finally:
        os.close(descriptor)


def _fsync_directory(path):
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
