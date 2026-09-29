# SPDX-License-Identifier: BSD-3-Clause
"""Offline validation of accountable #90 custody claims; no Azure admission."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib
import os
from pathlib import Path
import re
import stat
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

azure = importlib.import_module("hyperv-azure")

SCHEMA = "uk-hyperv-issue90-custody-v1"
DOMAINS = {
    "prepared": SCHEMA + "-prepared",
    "handoff": SCHEMA + "-handoff",
    "closed": SCHEMA + "-closed",
    "ack": SCHEMA + "-ack",
}
DIRECT = ("group", "dummy", "os", "data0", "data7", "deployment")
CHILDREN = ("vm", "nic", "vnet", "nsg")
INVENTORY = ("dummy", "os", "data0", "data7", *CHILDREN)
MAX_RECORD = 64 * 1024
MAX_ARCHIVE = 64 * 1024
MAX_TOTAL_ARCHIVE = 512 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")


def _exact(value, fields, label):
    return azure.require_exact_fields(value, fields, label)


def _sha(value, label):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _nonce(value, label):
    if not isinstance(value, str) or not NONCE.fullmatch(value) or not int(value, 16):
        raise ValueError(f"{label} must be a nonzero lowercase 128-bit nonce")
    return value


def _uuid(value, label):
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError(f"{label} must be a canonical UUID") from None
    if not parsed.int or str(parsed) != value:
        raise ValueError(f"{label} must be a canonical nonzero UUID")
    return value


def _utc(value):
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise ValueError("Custody timestamp must be UTC to the second")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("Invalid custody timestamp") from None
    return parsed.replace(tzinfo=timezone.utc)


def _tree(value, depth=0):
    if depth > 12:
        raise ValueError("Custody JSON nesting exceeds limit")
    if isinstance(value, dict):
        if len(value) > 32:
            raise ValueError("Custody JSON object exceeds limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 80:
                raise ValueError("Custody JSON key exceeds limit")
            _tree(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 16:
            raise ValueError("Custody JSON array exceeds limit")
        for item in value:
            _tree(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 2048:
            raise ValueError("Custody JSON string exceeds limit")
    elif value is not None and type(value) not in (bool, int):
        raise ValueError("Custody JSON value has unsupported type")


def _parse(raw, label, limit=MAX_RECORD, *, canonical=True):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError(f"{label} exceeds its byte limit")
    value = azure.parse_strict_json(raw, label)
    _tree(value)
    if canonical and raw != azure.canonical_json(value):
        raise ValueError(f"{label} must use the repository canonical JSON")
    return value


def _envelope(raw, stage, public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("An external Ed25519 public key is required")
    record = _exact(_parse(raw, stage), ("body", "signature"), stage)
    signature = record["signature"]
    if (not isinstance(signature, str) or len(signature) != 128
            or not re.fullmatch(r"[0-9a-f]{128}", signature)):
        raise ValueError("Invalid custody signature encoding")
    body = record["body"]
    if not isinstance(body, dict) or body.get("stage") != stage:
        raise ValueError("Wrong custody stage")
    message = (DOMAINS[stage] + "\n").encode("ascii") + azure.canonical_json(body)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), message
        )
    except (InvalidSignature, ValueError) as error:
        raise ValueError("Invalid custody signature") from error
    return body, hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Expected:
    run_id: str
    operation_id: str
    handoff_challenge: str
    preprovision_authorization_sha256: str
    reviewed_image_sha256: str
    dummy_image_sha256: str
    provenance_sha256: str
    seed_sha256: dict
    template_sha256: str
    final_envelope_sha256: str
    resource_ids: dict

    def validate(self):
        _nonce(self.run_id, "Run ID")
        _uuid(self.operation_id, "Operation ID")
        _nonce(self.handoff_challenge, "Independently selected handoff challenge")
        for name in ("preprovision_authorization_sha256", "reviewed_image_sha256",
                     "dummy_image_sha256", "provenance_sha256", "template_sha256",
                     "final_envelope_sha256"):
            _sha(getattr(self, name), name)
        _exact(self.seed_sha256, ("data0", "data7"), "Seed digests")
        for value in self.seed_sha256.values():
            _sha(value, "Seed digest")
        if (self.seed_sha256["data0"] == self.seed_sha256["data7"]
                or self.dummy_image_sha256 == self.reviewed_image_sha256):
            raise ValueError("Dummy/final images and seeded data disks must be distinct")
        _exact(self.resource_ids, (*DIRECT, *CHILDREN), "Resource IDs")
        if (any(not isinstance(value, str) or not value.startswith("/subscriptions/")
                or len(value) > 512 for value in self.resource_ids.values())
                or len({value.lower() for value in self.resource_ids.values()}) != 10):
            raise ValueError("Expected resource IDs must be distinct absolute ARM paths")


@dataclass(frozen=True)
class DispositionClaim:
    claimed_disposition: str
    closed_sha256: str
    witness_ack_sha256: str


def _body(body, stage, number, expected, predecessor):
    required = ("schema", "version", "stage", "sequence", "previous_sha256",
                "run_id", "operation_id", "issued_at_utc", "nonce",
                "preprovision_authorization_sha256", "evidence")
    _exact(body, required, stage)
    if (body["schema"] != SCHEMA or type(body["version"]) is not int
            or body["version"] != 1 or body["stage"] != stage
            or type(body["sequence"]) is not int or body["sequence"] != number
            or body["previous_sha256"] != predecessor
            or body["run_id"] != expected.run_id
            or body["operation_id"] != expected.operation_id
            or body["preprovision_authorization_sha256"]
            != expected.preprovision_authorization_sha256):
        raise ValueError("Custody chain differs from independent expected context")
    _nonce(body["nonce"], "Record nonce")
    return _utc(body["issued_at_utc"])


class _Archive:
    def __init__(self, blobs):
        if blobs is None or not hasattr(blobs, "__getitem__"):
            raise ValueError("Original response archive must be supplied")
        self.blobs = blobs
        self.total = 0

    def read(self, ref, label):
        _exact(ref, ("sha256", "size"), label)
        digest = _sha(ref["sha256"], label)
        size = ref["size"]
        if type(size) is not int or not 0 < size <= MAX_ARCHIVE:
            raise ValueError(f"{label} byte length is invalid")
        self.total += size
        if self.total > MAX_TOTAL_ARCHIVE:
            raise ValueError("Custody archive exceeds its total byte limit")
        try:
            raw = self.blobs[digest]
        except KeyError:
            raise ValueError(f"{label} original archive bytes are missing") from None
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError(f"{label} archived bytes do not match their digest and length")
        return _parse(raw, label, MAX_ARCHIVE, canonical=False)


def _props(value):
    properties = value.get("properties")
    return properties if isinstance(properties, dict) else value


def _state(value):
    return _props(value).get("provisioningState")


def _identity(value, role):
    props = _props(value)
    if role in ("dummy", "os", "data0", "data7"):
        return value.get("uniqueId", props.get("uniqueId"))
    if role == "deployment":
        return props.get("correlationId")
    return None


def _uuid_receipt(value, label):
    return _uuid(value, label)


def _run_tags(value, expected, label):
    tags = value.get("tags")
    if (not isinstance(tags, dict)
            or tags.get("issue90-run") != expected.run_id
            or tags.get("issue90-operation") != expected.operation_id):
        raise ValueError(f"{label} has foreign or missing run tags")


def _deployment_parameters(value, expected, label):
    parameters = _props(value).get("parameters")
    if (not isinstance(parameters, dict)
            or any(not isinstance(parameters.get(name), dict)
                   or not isinstance(parameters[name].get("type"), str)
                   or parameters[name]["type"].lower() != "string"
                   or parameters[name].get("value") != expected_value
                   for name, expected_value in (
                       ("runId", expected.run_id),
                       ("operationId", expected.operation_id),
                   ))):
        raise ValueError(f"{label} has foreign or missing deployment parameters")


def _settled_lro(original, tracking, archive, label):
    _exact(tracking, ("initial", "terminal"), f"{label} LRO")
    operation = _exact(original.get("operation"), ("url", "operation_id"),
                       f"{label} original operation")
    initial = archive.read(tracking["initial"], f"{label} original LRO")
    settled = archive.read(tracking["terminal"], f"{label} terminal LRO")
    if (not isinstance(initial, dict) or not isinstance(settled, dict)
            or not isinstance(operation["url"], str)
            or not operation["url"].startswith("https://management.azure.com/")
            or not isinstance(operation["operation_id"], str)
            or initial.get("url") != operation["url"]
            or settled.get("url") != operation["url"]
            or initial.get("operation_id") != operation["operation_id"]
            or settled.get("operation_id") != operation["operation_id"]
            or initial.get("status") not in ("Accepted", "InProgress", "Running")
            or settled.get("status") != "Succeeded"):
        raise ValueError(f"{label} original LRO was not settled")
    _uuid(operation["operation_id"], f"{label} LRO operation ID")


def _direct(receipts, expected, archive):
    _exact(receipts, DIRECT, "Direct create receipts")
    identities = {}
    for role in DIRECT:
        disk_role = role in ("dummy", "os", "data0", "data7")
        receipt = _exact(
            receipts[role],
            ("id", "uuid", "create", "terminal", "tracking",
             "vhd_sha256", "upload", "revocation") if disk_role
            else ("id", "uuid", "create", "terminal", "tracking"),
            f"{role} receipt",
        )
        resource_id = expected.resource_ids[role]
        if receipt["id"] != resource_id:
            raise ValueError(f"{role} original resource ID differs")
        original = archive.read(receipt["create"], f"{role} original create")
        terminal = archive.read(receipt["terminal"], f"{role} terminal observation")
        if (not isinstance(original, dict) or not isinstance(terminal, dict)
                or original.get("id") != resource_id
                or terminal.get("id") != resource_id
                or _state(terminal) != "Succeeded"):
            raise ValueError(f"{role} lacks its original create and terminal identity")
        if role == "deployment":
            _deployment_parameters(original, expected, "Original deployment")
            _deployment_parameters(terminal, expected, "Terminal deployment")
        else:
            _run_tags(original, expected, f"{role} original create")
            _run_tags(terminal, expected, f"{role} terminal observation")
        state = _state(original)
        tracking = receipt["tracking"]
        if state == "Succeeded":
            if tracking is not None:
                raise ValueError(f"{role} successful create has unrelated LRO tracking")
        elif state in ("Accepted", "InProgress", "Running"):
            if tracking is None:
                raise ValueError(f"{role} unsettled create lacks original LRO")
            _settled_lro(original, tracking, archive, role)
        else:
            raise ValueError(f"{role} original create did not succeed or remain pending")
        if role == "group":
            if receipt["uuid"] is not None:
                raise ValueError("Group ARM path is not an incarnation UUID")
        else:
            identity = _uuid_receipt(receipt["uuid"], f"{role} original UUID")
            if (_identity(original, role) != identity
                    or _identity(terminal, role) != identity):
                raise ValueError(f"{role} immutable field differs from original create")
            identities[role] = identity
        if disk_role:
            image_sha = {
                "dummy": expected.dummy_image_sha256,
                "os": expected.reviewed_image_sha256,
                **expected.seed_sha256,
            }[role]
            size = (azure.VIRTUAL_SIZE if role in ("dummy", "os")
                    else 4 * 1024**3) + 512
            upload = archive.read(receipt["upload"], f"{role} upload outcome")
            revocation = archive.read(receipt["revocation"], f"{role} SAS revocation")
            creation = _props(terminal).get("creationData")
            sku = terminal.get("sku")
            if (receipt["vhd_sha256"] != image_sha
                    or type(terminal.get("diskSizeBytes")) is not int
                    or terminal["diskSizeBytes"] != size - 512
                    or not isinstance(creation, dict)
                    or creation.get("createOption") != "Upload"
                    or type(creation.get("uploadSizeBytes")) is not int
                    or creation["uploadSizeBytes"] != size
                    or not isinstance(sku, dict)
                    or sku.get("name") != "StandardSSD_LRS"
                    or (role in ("dummy", "os")
                        and (terminal.get("osType") != "Linux"
                             or terminal.get("hyperVGeneration") != "V2"))
                    or not isinstance(upload, dict)
                    or upload.get("id") != resource_id
                    or upload.get("sha256") != image_sha
                    or type(upload.get("size")) is not int or upload["size"] != size
                    or upload.get("status") != "Succeeded"
                    or not isinstance(revocation, dict)
                    or revocation.get("id") != resource_id
                    or revocation.get("status") != "Succeeded"
                    or revocation.get("active_sas") is not False):
                raise ValueError(f"{role} VHD upload or access revocation is unproven")
    if len(set(identities.values())) != 5:
        raise ValueError("Disk/deployment immutable values must be distinct")
    return identities


def _children(observations, expected, archive, vm_uuid, os_role):
    _exact(observations, CHILDREN, "Deployment child observations")
    resources = {}
    for role in CHILDREN:
        child = archive.read(observations[role], f"{role} deployment child")
        if (not isinstance(child, dict) or child.get("id") != expected.resource_ids[role]
                or _state(child) != "Succeeded"):
            raise ValueError(f"{role} is not a settled observed deployment child")
        if role == "vm":
            _vm_attachment(child, expected, vm_uuid, os_role)
        else:
            _run_tags(child, expected, f"{role} deployment child")
        resources[role] = child
    nic = resources["nic"]
    vnet = resources["vnet"]
    nsg = resources["nsg"]
    configs = nic.get("ipConfigurations")
    subnets = vnet.get("subnets")
    if (nic.get("enableIPForwarding") is not False
            or nic.get("enableAcceleratedNetworking") is not False
            or nic.get("networkSecurityGroup") is not None
            or not isinstance(configs, list) or len(configs) != 1
            or not isinstance(configs[0], dict)
            or configs[0].get("publicIPAddress") is not None
            or configs[0].get("privateIPAllocationMethod") != "Dynamic"
            or not isinstance(configs[0].get("subnet"), dict)
            or configs[0]["subnet"].get("id")
            != expected.resource_ids["vnet"] + "/subnets/default"
            or not isinstance(vnet.get("addressSpace"), dict)
            or vnet["addressSpace"].get("addressPrefixes") != ["10.90.0.0/29"]
            or not isinstance(subnets, list) or len(subnets) != 1
            or not isinstance(subnets[0], dict)
            or subnets[0].get("name") != "default"
            or subnets[0].get("addressPrefix") != "10.90.0.0/29"
            or subnets[0].get("defaultOutboundAccess") is not False
            or subnets[0].get("natGateway") is not None
            or subnets[0].get("routeTable") is not None
            or not isinstance(subnets[0].get("networkSecurityGroup"), dict)
            or subnets[0]["networkSecurityGroup"].get("id") != expected.resource_ids["nsg"]
            or nsg.get("securityRules") != []):
        raise ValueError("Deployment children do not have the approved private network")


def _inventory(ref, expected, archive, identities, vm_uuid):
    value = _exact(archive.read(ref, "Complete inventory"), ("resources",), "Inventory")
    items = value["resources"]
    if not isinstance(items, list) or len(items) != len(INVENTORY):
        raise ValueError("Incomplete or excess resource inventory")
    seen = set()
    for item in items:
        _exact(item, ("role", "id", "uuid"), "Inventory entry")
        role = item["role"]
        if (role not in INVENTORY or role in seen
                or item["id"] != expected.resource_ids[role]
                or item["uuid"] != (vm_uuid if role == "vm" else identities.get(role))):
            raise ValueError("Missing, foreign, replaced or duplicate inventory resource")
        seen.add(role)


def _vm_attachment(value, expected, vm_uuid, os_role):
    if not isinstance(value, dict) or value.get("id") != expected.resource_ids["vm"]:
        raise ValueError("VM observation has wrong identity")
    _run_tags(value, expected, "VM observation")
    props = _props(value)
    storage = props.get("storageProfile")
    network = props.get("networkProfile")
    interfaces = network.get("networkInterfaces") if isinstance(network, dict) else None
    if (props.get("vmId") != vm_uuid or not isinstance(storage, dict)
            or storage.get("diskControllerType") != "SCSI"
            or not isinstance(props.get("securityProfile"), dict)
            or props["securityProfile"].get("securityType") != "Standard"
            or not isinstance(props.get("hardwareProfile"), dict)
            or props["hardwareProfile"].get("vmSize") != "Standard_D2s_v5"
            or not isinstance(interfaces, list) or len(interfaces) != 1
            or not isinstance(interfaces[0], dict)
            or interfaces[0].get("id") != expected.resource_ids["nic"]
            or not isinstance(interfaces[0].get("properties"), dict)
            or interfaces[0]["properties"].get("primary") is not True
            or interfaces[0]["properties"].get("deleteOption") != "Delete"):
        raise ValueError("VM UUID, storage profile or private NIC attachment differs")
    disk = storage.get("osDisk")
    data = storage.get("dataDisks")
    if (not isinstance(disk, dict) or not isinstance(disk.get("managedDisk"), dict)
            or disk["managedDisk"].get("id") != expected.resource_ids[os_role]
            or not isinstance(data, list) or len(data) != 2
            or any(not isinstance(item, dict) for item in data)
            or any(not isinstance(item.get("managedDisk"), dict) for item in data)
            or {item.get("lun"): (item.get("managedDisk") or {}).get("id")
                for item in data} != {0: expected.resource_ids["data0"],
                                     7: expected.resource_ids["data7"]}):
        raise ValueError("VM original data disks or OS attachment differs")


def _current_disk(role, ref, expected, archive, identities, attached):
    value = archive.read(ref, f"{role} current disk observation")
    if (not isinstance(value, dict) or value.get("id") != expected.resource_ids[role]
            or _identity(value, role) != identities[role]
            or _state(value) != "Succeeded"
            or (value.get("managedBy") != expected.resource_ids["vm"]
                if attached else bool(value.get("managedBy")))):
        raise ValueError(f"{role} current disk identity or attachment differs")
    _run_tags(value, expected, f"{role} current disk")


def _current_data_disks(refs, expected, archive, identities):
    _exact(refs, ("data0", "data7"), "Current data disk observations")
    for role in ("data0", "data7"):
        _current_disk(role, refs[role], expected, archive, identities, True)


def _prepared(body, expected, archive):
    evidence = _exact(
        body["evidence"],
        ("reviewed_image_sha256", "dummy_image_sha256", "provenance_sha256",
         "seed_sha256",
         "template_sha256", "direct_receipts", "children", "inventory",
         "dummy_vm", "dummy_disk", "os_disk", "data_disks"),
        "PREPARED evidence",
    )
    if (evidence["reviewed_image_sha256"] != expected.reviewed_image_sha256
            or evidence["dummy_image_sha256"] != expected.dummy_image_sha256
            or evidence["provenance_sha256"] != expected.provenance_sha256
            or evidence["seed_sha256"] != expected.seed_sha256
            or evidence["template_sha256"] != expected.template_sha256):
        raise ValueError("PREPARED differs from reviewed inputs or deallocated dummy")
    identities = _direct(evidence["direct_receipts"], expected, archive)
    deployment = archive.read(
        evidence["direct_receipts"]["deployment"]["terminal"], "Deployment outputs"
    )
    original_deployment = archive.read(
        evidence["direct_receipts"]["deployment"]["create"], "Original deployment outputs"
    )
    deployment_props = _props(deployment)
    outputs = deployment_props.get("outputs")
    output_resources = deployment_props.get("outputResources")
    roles = {
        "vmId": "vm", "osDiskId": "dummy", "dataDisk0Id": "data0",
        "dataDisk7Id": "data7", "nicId": "nic", "vnetId": "vnet", "nsgId": "nsg",
    }
    if (not isinstance(outputs, dict) or set(outputs) != set(roles) | {"vmUuid"}
            or not isinstance(output_resources, list)
            or len(output_resources) != len(CHILDREN)
            or any(not isinstance(item, dict) or set(item) != {"id"}
                   for item in output_resources)
            or {item["id"] for item in output_resources}
            != {expected.resource_ids[role] for role in CHILDREN}
            or any(not isinstance(outputs[name], dict)
                   or outputs[name].get("value") != expected.resource_ids[role]
                   for name, role in roles.items())):
        raise ValueError("Original deployment output inventory differs")
    vm_output = outputs["vmUuid"]
    vm_uuid = vm_output.get("value") if isinstance(vm_output, dict) else None
    _uuid(vm_uuid, "Original VM UUID output")
    original_props = _props(original_deployment)
    original_outputs = original_props.get("outputs")
    if (_state(original_deployment) == "Succeeded"
            and (original_outputs != outputs
                 or original_props.get("outputResources") != output_resources)):
        raise ValueError("Original deployment outputs differ from terminal observation")
    if original_outputs is not None:
        original_vm = (original_outputs.get("vmUuid")
                       if isinstance(original_outputs, dict) else None)
        if (not isinstance(original_vm, dict)
                or original_vm.get("value") != vm_uuid):
            raise ValueError("Original deployment VM UUID differs from terminal output")
    if vm_uuid in identities.values():
        raise ValueError("VM UUID collides with a disk or deployment correlation")
    _children(evidence["children"], expected, archive, vm_uuid, "dummy")
    _inventory(evidence["inventory"], expected, archive, identities, vm_uuid)
    dummy_vm = archive.read(evidence["dummy_vm"], "Original dummy VM attachment")
    _vm_attachment(dummy_vm, expected, vm_uuid, "dummy")
    if _props(dummy_vm).get("powerState") != "deallocated":
        raise ValueError("PREPARED VM must be observed deallocated")
    _current_disk("dummy", evidence["dummy_disk"], expected, archive, identities, True)
    _current_disk("os", evidence["os_disk"], expected, archive, identities, False)
    _current_data_disks(evidence["data_disks"], expected, archive, identities)
    return identities, vm_uuid


def _handoff(body, expected, archive, identities, vm_uuid, prepared_sha, now, fresh):
    evidence = _exact(
        body["evidence"],
        ("prepared_sha256", "challenge", "expires_at_utc", "final_envelope_sha256",
         "deallocation", "swap", "swap_tracking", "swap_settlement", "vm", "dummy", "os",
         "data_disks", "inventory", "children", "no_prior_acceptance_boot",
         "exclusive_no_writer", "running_seconds"),
        "HANDOFF evidence",
    )
    issued = _utc(body["issued_at_utc"])
    expires = _utc(evidence["expires_at_utc"])
    if (evidence["prepared_sha256"] != prepared_sha
            or evidence["final_envelope_sha256"] != expected.final_envelope_sha256
            or evidence["no_prior_acceptance_boot"] is not True
            or evidence["exclusive_no_writer"] is not True
            or type(evidence["running_seconds"]) is not int
            or not 0 <= evidence["running_seconds"] < 3600
            or not issued < expires
            or (expires - issued).total_seconds() > 3600
            or (fresh and now >= expires)):
        raise ValueError("HANDOFF claims are incomplete, expired or out of budget")
    if (evidence["challenge"] != expected.handoff_challenge
            or evidence["challenge"] in (expected.run_id, body["nonce"])):
        raise ValueError("Handoff challenge differs from independent expected context")
    deallocation = archive.read(evidence["deallocation"], "Terminal deallocation")
    swap = archive.read(evidence["swap"], "Original OS swap response")
    settled = archive.read(evidence["swap_settlement"], "Settled OS swap")
    vm = archive.read(evidence["vm"], "Final VM observation")
    if (not isinstance(deallocation, dict)
            or deallocation.get("id") != expected.resource_ids["vm"]
            or deallocation.get("vmId") != vm_uuid
            or deallocation.get("status") != "Succeeded"
            or not isinstance(swap, dict) or not isinstance(settled, dict)
            or _state(settled) != "Succeeded" or _state(vm) != "Succeeded"):
        raise ValueError("Deallocation and original OS swap are not settled")
    if "tags" in deallocation:
        _run_tags(deallocation, expected, "Deallocation outcome")
    swap_state = _state(swap)
    tracking = evidence["swap_tracking"]
    if swap_state == "Succeeded":
        if tracking is not None:
            raise ValueError("Successful original OS swap has unrelated LRO tracking")
    elif swap_state in ("Accepted", "InProgress", "Running"):
        if tracking is None:
            raise ValueError("Pending original OS swap lacks operation tracking")
        _settled_lro(swap, tracking, archive, "OS swap")
    else:
        raise ValueError("Original OS swap did not succeed or remain pending")
    for item in (swap, settled, vm):
        _vm_attachment(item, expected, vm_uuid, "os")
    _current_disk("dummy", evidence["dummy"], expected, archive, identities, False)
    _current_disk("os", evidence["os"], expected, archive, identities, True)
    _current_data_disks(evidence["data_disks"], expected, archive, identities)
    _children(evidence["children"], expected, archive, vm_uuid, "os")
    _inventory(evidence["inventory"], expected, archive, identities, vm_uuid)
    if not isinstance(vm, dict) or _props(vm).get("powerState") != "deallocated":
        raise ValueError("Handoff VM must be observed deallocated")
    return evidence["challenge"], expires


class FileReplayRegistry:
    """Injected operator-owned, create-only replay ledger; never infer from tags."""

    def __init__(self, directory):
        path = Path(directory).absolute()
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or path.resolve(strict=True) != path):
            raise ValueError("Replay registry must be an owner-only, symlink-free directory")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(descriptor)
            raise ValueError("Replay registry changed during opening")
        self._directory_fd = descriptor

    def close(self):
        if self._directory_fd is not None:
            os.close(self._directory_fd)
            self._directory_fd = None

    def _name(self, kind, identifier):
        if self._directory_fd is None:
            raise ValueError("Replay registry is closed")
        return kind + "-" + identifier + ".json"

    def _read(self, kind, identifier):
        name = self._name(kind, identifier)
        descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=self._directory_fd,
        )
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1
                    or info.st_size > 4096):
                raise ValueError("Replay claim is not a private regular file")
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        return _parse(raw, "Replay claim", 4096)

    def _create(self, kind, identifier, claim):
        name = self._name(kind, identifier)
        raw = azure.canonical_json(claim)
        try:
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0), 0o600,
                dir_fd=self._directory_fd,
            )
        except FileExistsError:
            raise ValueError("Custody run or challenge was already consumed") from None
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(self._directory_fd)
        except BaseException:
            # A failed publication is never made retryable by deleting the claim.
            raise

    def claim_handoff(self, run_id, challenge, digest):
        claim = {"run_id": run_id, "challenge": challenge, "handoff_sha256": digest}
        self._create("run", run_id, claim)
        self._create("challenge", challenge, claim)

    def require_handoff(self, run_id, challenge, digest):
        claim = {"run_id": run_id, "challenge": challenge, "handoff_sha256": digest}
        if (self._read("run", run_id) != claim
                or self._read("challenge", challenge) != claim):
            raise ValueError("Durable handoff claim differs")

    def claim_closed(self, run_id, digest):
        self._create("closed", run_id, {"run_id": run_id, "closed_sha256": digest})

    def claim_start(self, run_id, claim):
        self._create("start", run_id, claim)

    def require_start(self, run_id, claim):
        if self._read("start", run_id) != claim:
            raise ValueError("Durable acceptance-image start claim differs")

    def claim_dispatch_challenge(self, challenge, claim):
        self._create("dispatch-challenge", challenge, claim)

    def require_dispatch_challenge(self, challenge, claim):
        if self._read("dispatch-challenge", challenge) != claim:
            raise ValueError("Durable dispatch challenge claim differs")

    def claim_observation(self, run_id, claim):
        self._create("observation", run_id, claim)

    def require_observation(self, run_id, claim):
        if self._read("observation", run_id) != claim:
            raise ValueError("Durable acceptance-image observation differs")


def _registry(value):
    if type(value) is not FileReplayRegistry:
        raise ValueError("An injected durable operator-owned FileReplayRegistry is required")
    return value


def _now(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("A timezone-aware independent clock is required")
    return value.astimezone(timezone.utc)


def _check_handoff(prepared, handoff, *, expected, public_key, archive, now,
                   fresh=True):
    expected.validate()
    now = _now(now)
    blobs = _Archive(archive)
    first, first_sha = _envelope(prepared, "prepared", public_key)
    second, second_sha = _envelope(handoff, "handoff", public_key)
    first_at = _body(first, "prepared", 1, expected, None)
    second_at = _body(second, "handoff", 2, expected, first_sha)
    if (first_at > second_at or second_at > now
            or first["nonce"] == second["nonce"]):
        raise ValueError("Custody records have stale or reordered timestamps/nonces")
    identities, vm_uuid = _prepared(first, expected, blobs)
    challenge, expires = _handoff(
        second, expected, blobs, identities, vm_uuid, first_sha, now, fresh
    )
    return second_sha, challenge, second_at, expires


def inspect_handoff(prepared, handoff, *, expected, public_key, archive, registry, now):
    """Consume one handoff; return its digest, not Azure admission or a PASS."""
    ledger = _registry(registry)
    digest, challenge, _, _ = _check_handoff(
        prepared, handoff, expected=expected, public_key=public_key,
        archive=archive, now=now,
    )
    ledger.claim_handoff(expected.run_id, challenge, digest)
    return digest


def inspect_closed(prepared, handoff, closed, acknowledgment, *,
                   expected, public_key, witness_public_key, archive, registry,
                   acceptance_authorization_sha256, acceptance_issued_at_utc, now):
    """Consume an independently acknowledged disposition, not proof of Azure deletion."""
    ledger = _registry(registry)
    now = _now(now)
    approval_at = _utc(acceptance_issued_at_utc)
    if approval_at > now:
        raise ValueError("Acceptance authorization time is in the future")
    digest, challenge, handoff_at, handoff_expires = _check_handoff(
        prepared, handoff, expected=expected, public_key=public_key,
        archive=archive, now=now, fresh=False,
    )
    ledger.require_handoff(expected.run_id, challenge, digest)
    if not handoff_at < approval_at < handoff_expires:
        raise ValueError("Acceptance authorization was not issued after handoff")
    accepted = _sha(acceptance_authorization_sha256, "Acceptance authorization")
    body, closed_sha = _envelope(closed, "closed", public_key)
    closed_at = _body(body, "closed", 3, expected, digest)
    if (body["nonce"] in (challenge, expected.run_id)
            or not approval_at <= closed_at <= now):
        raise ValueError("Custody return has invalid chronology or nonce")
    evidence = _exact(
        body["evidence"],
        ("handoff_sha256", "acceptance_authorization_sha256",
         "return_receipt", "disposal_receipt", "disposition"),
        "CLOSED evidence",
    )
    if (evidence["handoff_sha256"] != digest
            or evidence["acceptance_authorization_sha256"] != accepted
            or evidence["disposition"] not in ("disposed", "quarantined")):
        raise ValueError("Custody disposition has wrong approval or handoff")
    blobs = _Archive(archive)
    returned = blobs.read(evidence["return_receipt"], "Custody return receipt")
    disposition = blobs.read(evidence["disposal_receipt"], "Custody disposition receipt")
    if (not isinstance(returned, dict) or returned.get("run_id") != expected.run_id
            or returned.get("status") != "returned"
            or not isinstance(disposition, dict)
            or disposition.get("run_id") != expected.run_id
            or disposition.get("disposition") != evidence["disposition"]):
        raise ValueError("Custody return or disposal archive contradicts the signed record")
    if public_key == witness_public_key:
        raise ValueError("Independent acknowledgment requires another pinned key")
    ack, ack_sha = _envelope(acknowledgment, "ack", witness_public_key)
    _exact(ack, ("schema", "version", "stage", "run_id", "challenge",
                 "closed_sha256", "issued_at_utc"), "Independent acknowledgment")
    if (ack["schema"] != SCHEMA or type(ack["version"]) is not int
            or ack["version"] != 1 or ack["stage"] != "ack"
            or ack["run_id"] != expected.run_id or ack["challenge"] != challenge
            or ack["closed_sha256"] != closed_sha
            or not closed_at <= _utc(ack["issued_at_utc"]) <= now):
        raise ValueError("Independent acknowledgment does not bind the disposition")
    ledger.claim_closed(expected.run_id, closed_sha)
    return DispositionClaim(evidence["disposition"], closed_sha, ack_sha)
