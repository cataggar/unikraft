#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Offline #90 custodian recorder and signed handoff assembler; no live gate."""

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
import stat
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    "Live #90 custodian Azure access is disabled: this offline tool requires "
    "a separate reviewed live approval gate that is intentionally not present"
)
_MISSING = object()


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
    def __init__(self, directory, runner=None, clock=None):
        self.directory = _ensure_private_dir(directory)
        self.archive = ArchiveStore(self.directory / "archive")
        self.journal_path = self.directory / "journal.jsonl"
        self.runner = runner or default_az_runner
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sequence = len(_read_journal(self.journal_path))

    def az(self, step, argv, *, timeout=120):
        _check_step(step)
        started = _precise_timestamp(self.clock())
        result = self.runner(list(argv), timeout=timeout)
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
        try:
            started = self.journal.by_step["deployment.create"]["started_at_utc"]
            completed = self.journal.by_step["vm.deallocate"]["completed_at_utc"]
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
        derived = max(1, math.ceil((end - start).total_seconds()))
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


def require_live_custodian_approval():
    raise RuntimeError(NO_LIVE_APPROVAL)


def run_live(*_args, **_kwargs):
    require_live_custodian_approval()


def record_preprovision(recorder, plan, *, upload=None):
    plan.expected.validate()
    if upload is None:
        raise ValueError("A VHD upload callable is required")
    for role in DISKS:
        if plan.image_path(role) is None:
            raise ValueError(f"{role} image path is required")
    group = plan.group_name()
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
        grant = recorder.az(f"disk.{role}.grant", [
            "disk", "grant-access", "--resource-group", group,
            "--name", plan.resource_name(role), "--access-level", "Write",
            "--duration-in-seconds", "1800",
        ]).value
        sas = _grant_sas(grant)
        uploaded_sha, uploaded_size = _upload_result(
            upload(role, plan.image_path(role), sas, plan.image_sha256(role), size)
        )
        if uploaded_sha != plan.image_sha256(role) or uploaded_size != size:
            raise ValueError(f"{role} uploaded bytes differ from reviewed input")
        recorder.synthetic(f"disk.{role}.upload", {
            "id": plan.expected.resource_ids[role],
            "sha256": uploaded_sha,
            "size": uploaded_size,
            "status": "Succeeded",
        })
        recorder.az(f"disk.{role}.revoke", [
            "disk", "revoke-access", "--resource-group", group,
            "--name", plan.resource_name(role),
        ], timeout=180)
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
    sub.add_parser("live", help="disabled live custodian entry point")
    args = parser.parse_args(argv)
    if args.command == "keys":
        generate_test_keys(args.directory)
        print(
            "Wrote TEST-ONLY Ed25519 key set. A single operator holding all "
            "three roles is not independent custody."
        )
        return 0
    if args.command == "live":
        run_live()
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


def _create_private_dir(path):
    path = Path(path).absolute()
    if path.exists():
        raise FileExistsError("Custodian key directory already exists")
    os.mkdir(path, 0o700)
    try:
        os.chmod(path, 0o700)
        _fsync_directory(path.parent)
        return _require_private_dir(path, "Custodian key directory")
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
