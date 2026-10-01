# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic signed #90 custody records; no Azure calls or operator keys."""

from datetime import datetime, timezone
from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
custody = importlib.import_module("hyperv_issue90_custody_records")
azure = importlib.import_module("hyperv-azure")
topology = importlib.import_module("hyperv_issue90_topology")

TIME = datetime(2026, 9, 29, 4, 6, tzinfo=timezone.utc)
RUN = "a" * 32
OPERATION = "11111111-1111-4111-8111-111111111111"


def signature_key(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class Fixture:
    def __init__(self, state=None, expected_changes=None):
        self.signer = Ed25519PrivateKey.generate()
        self.witness = Ed25519PrivateKey.generate()
        self.archive = {}
        base = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/uk90-rg"
        ids = {
            "group": base,
            "dummy": base + "/providers/Microsoft.Compute/disks/dummy",
            "os": base + "/providers/Microsoft.Compute/disks/os",
            "data0": base + "/providers/Microsoft.Compute/disks/data0",
            "data7": base + "/providers/Microsoft.Compute/disks/data7",
            "deployment": base + "/providers/Microsoft.Resources/deployments/uk90",
            "vm": base + "/providers/Microsoft.Compute/virtualMachines/vm",
            "nic": base + "/providers/Microsoft.Network/networkInterfaces/nic",
            "vnet": base + "/providers/Microsoft.Network/virtualNetworks/vnet",
            "nsg": base + "/providers/Microsoft.Network/networkSecurityGroups/nsg",
        }
        if state is not None:
            ids = {
                role: topology.resource_id(state, role)
                for role in ("os", "data0", "data7", "deployment",
                             "vm", "nic", "vnet", "nsg")
            }
            ids["group"] = topology.group_id(state)
            ids["dummy"] = (
                ids["group"] + "/providers/Microsoft.Compute/disks/"
                + state["prefix"] + "-dummy"
            )
        run_id = state["run_id"] if state is not None else RUN
        operation_id = state["operation_id"] if state is not None else OPERATION
        self.ids = ids
        self.uuids = {
            role: f"22222222-2222-4222-8222-{number:012x}"
            for number, role in enumerate(("dummy", "os", "data0", "data7",
                                           "deployment", "vm"), 1)
        }
        self.expected = custody.Expected(
            run_id=run_id, operation_id=operation_id, handoff_challenge="d" * 32,
            preprovision_authorization_sha256="1" * 64,
            reviewed_image_sha256="2" * 64, dummy_image_sha256="9" * 64,
            provenance_sha256="3" * 64,
            seed_sha256={"data0": "4" * 64, "data7": "5" * 64},
            template_sha256="6" * 64, final_envelope_sha256="7" * 64,
            resource_ids=ids,
        )
        if expected_changes:
            self.expected = replace(self.expected, **expected_changes)
        self.direct = {}
        for role in custody.DIRECT:
            resource = self.resource(role)
            self.direct[role] = {
                "id": ids[role],
                "uuid": self.uuids.get(role),
                "create": self.put(resource),
                "terminal": self.put(resource),
                "tracking": None,
            }
            if role in ("dummy", "os", "data0", "data7"):
                image_sha = {
                    "dummy": self.expected.dummy_image_sha256,
                    "os": self.expected.reviewed_image_sha256,
                    **self.expected.seed_sha256,
                }[role]
                self.direct[role].update({
                    "vhd_sha256": image_sha,
                    "upload": self.put({
                        "id": ids[role], "sha256": image_sha,
                        "size": (azure.VIRTUAL_SIZE if role in ("dummy", "os")
                                 else 4 * 1024**3) + 512,
                        "status": "Succeeded",
                    }),
                    "revocation": self.put({
                        "id": ids[role], "status": "Succeeded", "active_sas": False,
                    }),
                })
        self.network = {role: self.put(self.resource(role)) for role in ("nic", "vnet", "nsg")}
        self.dummy_child = self.put(self.vm("dummy", deallocated=False))
        self.dummy_vm = self.put(self.vm("dummy"))
        self.final_child = self.put(self.vm("os", deallocated=False))
        self.final_vm = self.put(self.vm("os"))
        self.prepared_dummy = self.put({
            **self.resource("dummy"), "managedBy": ids["vm"],
        })
        self.prepared_os = self.put({
            **self.resource("os"), "managedBy": None,
        })
        self.dummy = self.put({**self.resource("dummy"), "managedBy": None})
        self.os = self.put({**self.resource("os"), "managedBy": ids["vm"]})
        self.data_disks = {
            role: self.put({**self.resource(role), "managedBy": ids["vm"]})
            for role in ("data0", "data7")
        }
        self.inventory = self.put({
            "resources": [
                {"role": role, "id": ids[role],
                 "uuid": self.uuids.get(role)}
                for role in custody.INVENTORY
            ]
        })
        self.prepared = self.body("prepared", 1, None, "b" * 32, "2026-09-29T04:00:00Z", {
            "reviewed_image_sha256": self.expected.reviewed_image_sha256,
            "dummy_image_sha256": self.expected.dummy_image_sha256,
            "provenance_sha256": self.expected.provenance_sha256,
            "seed_sha256": self.expected.seed_sha256,
            "template_sha256": self.expected.template_sha256,
            "direct_receipts": self.direct,
            "children": {"vm": self.dummy_child, **self.network},
            "inventory": self.inventory,
            "dummy_vm": self.dummy_vm,
            "dummy_disk": self.prepared_dummy,
            "os_disk": self.prepared_os,
            "data_disks": self.data_disks,
        })
        self.prepared_raw = self.sign(self.prepared)
        self.handoff = self.body(
            "handoff", 2, self.sha(self.prepared_raw), "c" * 32,
            "2026-09-29T04:01:00Z", {
                "prepared_sha256": self.sha(self.prepared_raw),
                "challenge": "d" * 32,
                "expires_at_utc": "2026-09-29T04:31:00Z",
                "final_envelope_sha256": self.expected.final_envelope_sha256,
                "deallocation": self.put(self.instance_view()),
                "swap": self.final_child,
                "swap_tracking": None,
                "swap_settlement": self.final_child,
                "vm": self.final_vm, "dummy": self.dummy, "os": self.os,
                "data_disks": self.data_disks,
                "inventory": self.inventory,
                "children": {"vm": self.final_child, **self.network},
                "no_prior_acceptance_boot": True, "exclusive_no_writer": True,
                "running_seconds": 10,
            },
        )
        self.handoff_raw = self.sign(self.handoff)
        self.closed = self.body(
            "closed", 3, self.sha(self.handoff_raw), "e" * 32,
            "2026-09-29T04:04:00Z", {
                "handoff_sha256": self.sha(self.handoff_raw),
                "acceptance_authorization_sha256": "8" * 64,
                "return_receipt": self.put({
                    "run_id": self.expected.run_id, "status": "returned",
                }),
                "disposal_receipt": self.put({
                    "run_id": self.expected.run_id, "disposition": "quarantined"
                }),
                "disposition": "quarantined",
            },
        )
        self.closed_raw = self.sign(self.closed)
        self.ack = {
            "schema": custody.SCHEMA, "version": 1, "stage": "ack",
            "run_id": self.expected.run_id, "challenge": "d" * 32,
            "closed_sha256": self.sha(self.closed_raw),
            "issued_at_utc": "2026-09-29T04:05:00Z",
        }
        self.ack_raw = self.sign(self.ack, key=self.witness)

    @staticmethod
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    def put(self, value):
        raw = azure.canonical_json(value)
        digest = self.sha(raw)
        self.archive[digest] = raw
        return {"sha256": digest, "size": len(raw)}

    def resource(self, role):
        result = {"id": self.ids[role], "provisioningState": "Succeeded"}
        if role != "deployment":
            result["tags"] = {
                "issue90-run": self.expected.run_id,
                "issue90-operation": self.expected.operation_id,
            }
        if role in ("dummy", "os", "data0", "data7"):
            result["uniqueId"] = self.uuids[role]
            size = (azure.VIRTUAL_SIZE if role in ("dummy", "os")
                    else 4 * 1024**3)
            result["diskSizeBytes"] = size
            result["creationData"] = {
                "createOption": "Upload", "uploadSizeBytes": size + 512,
            }
            result["sku"] = {"name": "StandardSSD_LRS"}
            if role in ("dummy", "os"):
                result["osType"] = "Linux"
                result["hyperVGeneration"] = "V2"
        elif role == "deployment":
            result["properties"] = {
                "correlationId": self.uuids[role], "provisioningState": "Succeeded",
                "parameters": {
                    "runId": {"type": "String", "value": self.expected.run_id},
                    "operationId": {"type": "String", "value": self.expected.operation_id},
                },
                "outputResources": [
                    {"apiVersion": None, "extension": None,
                     "id": self.ids[child], "identifiers": None,
                     "resourceGroup": self.ids["group"].split("/")[4],
                     "resourceType": "/".join(
                         self.ids[child].split("/providers/")[1].split("/")[:2])}
                    for child in custody.CHILDREN
                ],
                "outputs": {
                    **{name: {"value": self.ids[target]} for name, target in {
                        "vmId": "vm", "osDiskId": "dummy", "dataDisk0Id": "data0",
                        "dataDisk7Id": "data7", "nicId": "nic", "vnetId": "vnet",
                        "nsgId": "nsg",
                    }.items()},
                    "vmUuid": {"value": self.uuids["vm"]},
                },
            }
        elif role == "nic":
            result.update({
                "enableIPForwarding": False,
                "enableAcceleratedNetworking": False,
                "networkSecurityGroup": None,
                "ipConfigurations": [{
                    "publicIPAddress": None,
                    "privateIPAllocationMethod": "Dynamic",
                    "subnet": {"id": self.ids["vnet"] + "/subnets/default"},
                }],
            })
        elif role == "vnet":
            result.update({
                "addressSpace": {"addressPrefixes": ["10.90.0.0/29"]},
                "subnets": [{
                    "name": "default", "addressPrefix": "10.90.0.0/29",
                    "defaultOutboundAccess": False,
                    "natGateway": None, "routeTable": None,
                    "networkSecurityGroup": {"id": self.ids["nsg"]},
                }],
            })
        elif role == "nsg":
            result["securityRules"] = [
                {
                    "name": f"DenyAll{direction}",
                    "priority": priority,
                    "access": "Deny",
                    "direction": direction,
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "id": self.ids["nsg"] + f"/securityRules/DenyAll{direction}",
                    "etag": 'W/"synthetic"',
                    "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                    "provisioningState": "Succeeded",
                    "resourceGroup": self.ids["group"].split("/")[4],
                    "sourcePortRanges": [], "destinationPortRanges": [],
                    "sourceAddressPrefixes": [], "destinationAddressPrefixes": [],
                }
                for direction, priority in (("Inbound", 4095), ("Outbound", 4096))
            ]
        elif role == "vm":
            result["vmId"] = self.uuids["vm"]
        return result

    def vm(self, os_role, *, deallocated=True):
        # Azure CLI 2.90 `vm show` flattens NIC options; `vm show -d` adds powerState.
        result = self.resource("vm")
        if deallocated:
            result["powerState"] = "VM deallocated"
        result.update({
            "hardwareProfile": {"vmSize": "Standard_D2s_v5"},
            "securityProfile": {"securityType": "Standard"},
            "networkProfile": {"networkInterfaces": [{
                "id": self.ids["nic"], "primary": True, "deleteOption": "Delete",
                "resourceGroup": self.ids["group"].split("/")[4],
            }]},
            "storageProfile": {
                "diskControllerType": "SCSI",
                "osDisk": {"managedDisk": {"id": self.ids[os_role]}},
                "dataDisks": [
                    {"lun": lun, "managedDisk": {"id": self.ids[role]}}
                    for lun, role in ((0, "data0"), (7, "data7"))
                ],
            },
        })
        return result

    def instance_view(self, codes=("ProvisioningState/succeeded",
                                   "PowerState/deallocated")):
        return {
            **self.vm("dummy", deallocated=False),
            "instanceView": {"statuses": [
                {"code": code, "level": "Info"} for code in codes
            ]},
        }

    @staticmethod
    def rest_vm(vm):
        nic = vm["networkProfile"]["networkInterfaces"][0]
        properties = {key: value for key, value in vm.items()
                      if key not in ("id", "tags", "powerState")}
        properties["networkProfile"] = {"networkInterfaces": [{
            "id": nic["id"], "resourceGroup": nic["resourceGroup"],
            "properties": {"primary": nic["primary"],
                           "deleteOption": nic["deleteOption"]},
        }]}
        return {"id": vm["id"], "tags": vm["tags"], "properties": properties}

    def tracking(self, original):
        operation = {
            "url": "https://management.azure.com/operation/status",
            "operation_id": "55555555-5555-4555-8555-555555555555",
        }
        original["operation"] = operation
        return {
            "initial": self.put({**operation, "status": "Accepted"}),
            "terminal": self.put({**operation, "status": "Succeeded"}),
        }

    def body(self, stage, sequence, previous, nonce, timestamp, evidence):
        return {
            "schema": custody.SCHEMA, "version": 1, "stage": stage,
            "sequence": sequence, "previous_sha256": previous,
            "run_id": self.expected.run_id,
            "operation_id": self.expected.operation_id,
            "issued_at_utc": timestamp, "nonce": nonce,
            "preprovision_authorization_sha256":
            self.expected.preprovision_authorization_sha256,
            "evidence": evidence,
        }

    def sign(self, body, *, key=None, domain=None):
        signer = key or self.signer
        namespace = domain or custody.DOMAINS[body["stage"]]
        signature = signer.sign(
            (namespace + "\n").encode("ascii") + azure.canonical_json(body)
        )
        return azure.canonical_json({"body": body, "signature": signature.hex()})

    def resign_prepared(self):
        self.prepared_raw = self.sign(self.prepared)
        digest = self.sha(self.prepared_raw)
        self.handoff["previous_sha256"] = digest
        self.handoff["evidence"]["prepared_sha256"] = digest
        self.handoff_raw = self.sign(self.handoff)

    def kwargs(self, registry, now=TIME):
        return {
            "expected": self.expected,
            "public_key": signature_key(self.signer),
            "archive": self.archive, "registry": registry, "now": now,
        }

    def close_kwargs(self, registry, now=TIME):
        return {
            **self.kwargs(registry, now),
            "witness_public_key": signature_key(self.witness),
            "acceptance_authorization_sha256": "8" * 64,
            "acceptance_issued_at_utc": "2026-09-29T04:02:00Z",
        }


class CustodyRecordsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = custody.FileReplayRegistry(self.temp.name)
        self.addCleanup(self.registry.close)

    def handoff(self, *, prepared=None, handoff=None, **options):
        fixture = self.fixture
        return custody.inspect_handoff(
            prepared if prepared is not None else fixture.prepared_raw,
            handoff if handoff is not None else fixture.handoff_raw,
            **{**fixture.kwargs(self.registry), **options},
        )

    def closed(self, *, closed=None, ack=None, **options):
        fixture = self.fixture
        return custody.inspect_closed(
            fixture.prepared_raw, fixture.handoff_raw,
            closed if closed is not None else fixture.closed_raw,
            ack if ack is not None else fixture.ack_raw,
            **{**fixture.close_kwargs(self.registry), **options},
        )

    def test_real_ed25519_and_disk_backed_one_use_handoff_and_closure(self):
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))
        claim = self.closed()
        self.assertEqual(claim.claimed_disposition, "quarantined")
        self.assertEqual(claim.closed_sha256, self.fixture.sha(self.fixture.closed_raw))
        self.assertEqual(claim.witness_ack_sha256, self.fixture.sha(self.fixture.ack_raw))
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.handoff()
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.closed()

    def test_wrong_key_and_wrong_domain_rejected(self):
        with self.assertRaisesRegex(ValueError, "signature"):
            self.handoff(public_key=signature_key(self.fixture.witness))
        wrong = self.fixture.sign(
            self.fixture.handoff, domain=custody.DOMAINS["prepared"]
        )
        with self.assertRaisesRegex(ValueError, "signature"):
            self.handoff(handoff=wrong)

    def test_tampered_record_and_unknown_field_rejected(self):
        altered = json.loads(self.fixture.prepared_raw)
        altered["body"]["evidence"]["reviewed_image_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "signature"):
            self.handoff(prepared=azure.canonical_json(altered))
        altered = dict(self.fixture.handoff)
        altered["operator_public_key"] = signature_key(self.fixture.signer).hex()
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            self.handoff(handoff=self.fixture.sign(altered))

    def test_wrong_version_bad_utc_and_oversized_envelope_refused(self):
        for field, value, reason in (
            ("version", True, "chain differs"),
            ("issued_at_utc", "2026-09-29T04:01:00+00:00", "UTC"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, reason):
                    self.handoff(handoff=self.fixture.sign(
                        {**self.fixture.handoff, field: value}
                    ))
        with self.assertRaisesRegex(ValueError, "byte limit"):
            self.handoff(prepared=b" " * (custody.MAX_RECORD + 1))

    def test_duplicate_json_and_noncanonical_input_rejected(self):
        duplicate = self.fixture.prepared_raw.replace(b'"body":', b'"body":{},\"body\":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate field"):
            self.handoff(prepared=duplicate)
        with self.assertRaisesRegex(ValueError, "canonical JSON"):
            self.handoff(prepared=self.fixture.prepared_raw + b"\n")

    def test_wrong_stage_sequence_predecessor_and_nonce_rejected(self):
        for field, value, reason in (
            ("stage", "prepared", "Wrong custody stage"),
            ("sequence", 1, "chain differs"),
            ("previous_sha256", "9" * 64, "chain differs"),
            ("nonce", self.fixture.prepared["nonce"], "reordered timestamps/nonces"),
        ):
            with self.subTest(field=field):
                body = {**self.fixture.handoff, field: value}
                with self.assertRaisesRegex(ValueError, reason):
                    self.handoff(handoff=self.fixture.sign(body))

    def test_challenge_must_be_independently_selected_and_approval_not_in_handoff(self):
        expected = replace(self.fixture.expected, handoff_challenge="f" * 32)
        with self.assertRaisesRegex(ValueError, "challenge differs"):
            self.handoff(expected=expected)
        self.fixture.handoff["evidence"]["acceptance_authorization_sha256"] = "8" * 64
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_original_response_missing_or_wrong_uuid_cannot_be_reconstructed(self):
        self.fixture.archive.pop(self.fixture.direct["group"]["create"]["sha256"])
        with self.assertRaisesRegex(ValueError, "archive bytes are missing"):
            self.handoff()
        self.fixture = Fixture()
        forged = self.fixture.resource("os")
        forged["uniqueId"] = "33333333-3333-4333-8333-333333333333"
        self.fixture.direct["os"]["create"] = self.fixture.put(forged)
        self.fixture.resign_prepared()
        with self.assertRaisesRegex(ValueError, "original create"):
            self.handoff(prepared=self.fixture.prepared_raw)

    def test_unsettled_create_and_unavailable_tracking_refused(self):
        pending = self.fixture.resource("dummy")
        pending["provisioningState"] = "Accepted"
        self.fixture.direct["dummy"]["create"] = self.fixture.put(pending)
        self.fixture.resign_prepared()
        raw = self.fixture.prepared_raw
        with self.assertRaisesRegex(ValueError, "unsettled create"):
            self.handoff(prepared=raw)
        self.fixture.direct["dummy"]["tracking"] = {
            "initial": {"sha256": "f" * 64, "size": 40},
            "terminal": {"sha256": "e" * 64, "size": 40},
        }
        self.fixture.tracking(pending)
        self.fixture.direct["dummy"]["create"] = self.fixture.put(pending)
        self.fixture.resign_prepared()
        with self.assertRaisesRegex(ValueError, "archive bytes are missing"):
            self.handoff(prepared=self.fixture.sign(self.fixture.prepared))

    def test_original_async_operation_requires_matching_terminal_result(self):
        original = self.fixture.resource("group")
        original["provisioningState"] = "Accepted"
        group = self.fixture.direct["group"]
        group["tracking"] = self.fixture.tracking(original)
        group["create"] = self.fixture.put(original)
        self.fixture.resign_prepared()
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))

    def test_failed_or_unbound_original_group_create_cannot_borrow_successful_lro(self):
        for state, operation, reason in (
            ("Failed", True, "did not succeed"),
            ("Succeeded", True, "unrelated LRO"),
            ("Accepted", False, "original operation"),
            ("Accepted", "foreign", "original LRO"),
        ):
            with self.subTest(state=state, operation=operation):
                self.fixture = Fixture()
                original = self.fixture.resource("group")
                original["provisioningState"] = state
                tracking = self.fixture.tracking(original)
                if operation is False:
                    del original["operation"]
                elif operation == "foreign":
                    original["operation"]["operation_id"] = (
                        "66666666-6666-4666-8666-666666666666"
                    )
                self.fixture.direct["group"].update({
                    "create": self.fixture.put(original), "tracking": tracking,
                })
                self.fixture.resign_prepared()
                with self.assertRaisesRegex(ValueError, reason):
                    self.handoff()

    def test_deployment_run_parameters_bind_both_original_and_terminal(self):
        for receipt in ("create", "terminal"):
            for field in ("runId", "operationId"):
                with self.subTest(receipt=receipt, field=field):
                    self.fixture = Fixture()
                    response = self.fixture.resource("deployment")
                    response["properties"]["parameters"][field]["value"] = "foreign"
                    self.fixture.direct["deployment"][receipt] = self.fixture.put(response)
                    self.fixture.resign_prepared()
                    with self.assertRaisesRegex(ValueError, "deployment parameters"):
                        self.handoff()

    def test_run_tags_bind_original_direct_and_observed_children(self):
        for role, receipt in (
            ("group", "create"), ("os", "terminal"),
            ("nic", "prepared"), ("vm", "handoff"),
        ):
            for field in ("issue90-run", "issue90-operation"):
                with self.subTest(role=role, receipt=receipt, field=field):
                    self.fixture = Fixture()
                    response = (self.fixture.vm("dummy" if receipt == "prepared" else "os")
                                if role == "vm" else self.fixture.resource(role))
                    response["tags"][field] = "foreign"
                    ref = self.fixture.put(response)
                    if receipt in ("create", "terminal"):
                        self.fixture.direct[role][receipt] = ref
                    elif receipt == "prepared":
                        self.fixture.prepared["evidence"]["children"][role] = ref
                    else:
                        self.fixture.handoff["evidence"]["children"][role] = ref
                    self.fixture.resign_prepared()
                    with self.assertRaisesRegex(ValueError, "run tags"):
                        self.handoff()

    def test_original_deployment_vm_uuid_and_outputs_cannot_contradict_terminal(self):
        for state in ("Succeeded", "Accepted"):
            with self.subTest(state=state):
                self.fixture = Fixture()
                original = self.fixture.resource("deployment")
                original["properties"]["provisioningState"] = state
                original["properties"]["outputs"]["vmUuid"]["value"] = (
                    "33333333-3333-4333-8333-333333333333"
                )
                if state == "Accepted":
                    self.fixture.direct["deployment"]["tracking"] = (
                        self.fixture.tracking(original)
                    )
                self.fixture.direct["deployment"]["create"] = self.fixture.put(original)
                self.fixture.resign_prepared()
                with self.assertRaisesRegex(ValueError, "Original deployment"):
                    self.handoff()

    def test_pending_deployment_requires_its_original_tracking(self):
        original = self.fixture.resource("deployment")
        original["properties"]["provisioningState"] = "Accepted"
        original["properties"].pop("outputs")
        original["properties"].pop("outputResources")
        self.fixture.direct["deployment"]["tracking"] = self.fixture.tracking(original)
        self.fixture.direct["deployment"]["create"] = self.fixture.put(original)
        self.fixture.resign_prepared()
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))
        del original["operation"]
        self.fixture.direct["deployment"]["create"] = self.fixture.put(original)
        self.fixture.resign_prepared()
        with self.assertRaisesRegex(ValueError, "original operation"):
            self.handoff()

    def test_pending_create_terminal_lro_cannot_be_swapped(self):
        for role in ("group", "dummy", "deployment"):
            with self.subTest(role=role):
                self.fixture = Fixture()
                original = self.fixture.resource(role)
                if role == "deployment":
                    original["properties"]["provisioningState"] = "Accepted"
                else:
                    original["provisioningState"] = "Accepted"
                tracking = self.fixture.tracking(original)
                foreign = {
                    **original["operation"],
                    "operation_id": "66666666-6666-4666-8666-666666666666",
                    "status": "Succeeded",
                }
                tracking["terminal"] = self.fixture.put(foreign)
                self.fixture.direct[role].update({
                    "create": self.fixture.put(original), "tracking": tracking,
                })
                self.fixture.resign_prepared()
                with self.assertRaisesRegex(ValueError, "original LRO"):
                    self.handoff()

    def test_missing_upload_revocation_or_dummy_original_refuses_handoff(self):
        for field in ("upload", "revocation", "create"):
            with self.subTest(field=field):
                self.fixture = Fixture()
                blob = self.fixture.direct["dummy"][field]
                self.fixture.archive.pop(blob["sha256"])
                with self.assertRaisesRegex(ValueError, "archive bytes are missing"):
                    self.handoff()

    def test_archive_digest_length_and_dummy_image_are_pinned(self):
        self.fixture.direct["os"]["create"] = {
            **self.fixture.direct["os"]["create"],
            "size": self.fixture.direct["os"]["create"]["size"] + 1,
        }
        self.fixture.resign_prepared()
        with self.assertRaisesRegex(ValueError, "digest and length"):
            self.handoff()
        self.fixture = Fixture()
        identical_dummy = replace(
            self.fixture.expected,
            dummy_image_sha256=self.fixture.expected.reviewed_image_sha256,
        )
        with self.assertRaisesRegex(ValueError, "must be distinct"):
            self.handoff(expected=identical_dummy)

    def test_original_cli_json_need_not_be_canonical_but_signed_record_must(self):
        original = self.fixture.resource("group")
        pretty = (json.dumps(original, indent=2) + "\n").encode()
        digest = self.fixture.sha(pretty)
        self.fixture.archive[digest] = pretty
        self.fixture.direct["group"]["create"] = {
            "sha256": digest, "size": len(pretty),
        }
        self.fixture.resign_prepared()
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))

    def test_swap_to_foreign_os_or_replaced_vm_fails(self):
        vm = self.fixture.vm("dummy")
        self.fixture.handoff["evidence"]["swap"] = self.fixture.put(vm)
        with self.assertRaisesRegex(ValueError, "attachment differs"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))
        self.fixture = Fixture()
        replaced = self.fixture.vm("os")
        replaced["vmId"] = "33333333-3333-4333-8333-333333333333"
        self.fixture.handoff["evidence"]["vm"] = self.fixture.put(replaced)
        with self.assertRaisesRegex(ValueError, "VM UUID"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_failed_or_unbound_original_swap_cannot_borrow_successful_settlement(self):
        for state, operation, reason in (
            ("Failed", True, "did not succeed"),
            ("Succeeded", True, "unrelated LRO"),
            ("Accepted", False, "original operation"),
            ("Accepted", "foreign", "original LRO"),
        ):
            with self.subTest(state=state, operation=operation):
                self.fixture = Fixture()
                original = self.fixture.vm("os")
                original["provisioningState"] = state
                tracking = self.fixture.tracking(original)
                if operation is False:
                    del original["operation"]
                elif operation == "foreign":
                    original["operation"]["url"] = (
                        "https://management.azure.com/operation/foreign"
                    )
                self.fixture.handoff["evidence"].update({
                    "swap": self.fixture.put(original),
                    "swap_tracking": tracking,
                })
                with self.assertRaisesRegex(ValueError, reason):
                    self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_pending_swap_requires_matching_original_operation_and_terminal(self):
        original = self.fixture.vm("os")
        original["provisioningState"] = "Accepted"
        self.fixture.handoff["evidence"]["swap_tracking"] = self.fixture.tracking(original)
        self.fixture.handoff["evidence"]["swap"] = self.fixture.put(original)
        self.assertIsInstance(self.handoff(handoff=self.fixture.sign(self.fixture.handoff)),
                              str)
        self.fixture = Fixture()
        original = self.fixture.vm("os")
        original["provisioningState"] = "Accepted"
        self.fixture.handoff["evidence"]["swap"] = self.fixture.put(original)
        with self.assertRaisesRegex(ValueError, "lacks operation tracking"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))
        tracking = self.fixture.tracking(original)
        tracking["terminal"] = self.fixture.put({
            **original["operation"],
            "operation_id": "66666666-6666-4666-8666-666666666666",
            "status": "Succeeded",
        })
        self.fixture.handoff["evidence"].update({
            "swap": self.fixture.put(original),
            "swap_tracking": tracking,
        })
        with self.assertRaisesRegex(ValueError, "original LRO"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_post_swap_vm_observations_reject_foreign_or_missing_run_tags(self):
        for role in ("swap", "swap_settlement", "vm"):
            for field in ("issue90-run", "issue90-operation"):
                for missing in (False, True):
                    with self.subTest(role=role, field=field, missing=missing):
                        self.fixture = Fixture()
                        foreign = self.fixture.vm("os")
                        if missing:
                            del foreign["tags"][field]
                        else:
                            foreign["tags"][field] = "foreign"
                        self.fixture.handoff["evidence"][role] = self.fixture.put(foreign)
                        with self.assertRaisesRegex(ValueError, "VM observation.*run tags"):
                            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_prepared_vm_and_current_disk_observations_bind_run_tags(self):
        for stage, field, role, attached in (
            ("prepared", "dummy_vm", "vm", False),
            ("prepared", "os_disk", "os", False),
            ("handoff", "dummy", "dummy", False),
            ("handoff", "os", "os", True),
            ("handoff", "data_disks", "data7", True),
        ):
            with self.subTest(stage=stage, field=field):
                self.fixture = Fixture()
                resource = (self.fixture.vm("dummy") if role == "vm"
                            else self.fixture.resource(role))
                if role != "vm":
                    resource["managedBy"] = (
                        self.fixture.ids["vm"] if attached else None
                    )
                resource["tags"]["issue90-operation"] = "foreign"
                evidence = getattr(self.fixture, stage)["evidence"]
                if field == "data_disks":
                    evidence[field][role] = self.fixture.put(resource)
                else:
                    evidence[field] = self.fixture.put(resource)
                self.fixture.resign_prepared()
                with self.assertRaisesRegex(ValueError, "run tags"):
                    self.handoff()

    def test_deallocation_instance_view_requires_vm_run_tags(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.fixture = Fixture()
                outcome = self.fixture.instance_view()
                if missing:
                    del outcome["tags"]
                else:
                    outcome["tags"]["issue90-run"] = "foreign"
                self.fixture.handoff["evidence"]["deallocation"] = self.fixture.put(outcome)
                with self.assertRaisesRegex(ValueError,
                                            "Deallocation instance view.*run tags"):
                    self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_deallocation_requires_captured_instance_view_power_state(self):
        for codes in (
            (),
            ("ProvisioningState/succeeded",),
            ("PowerState/deallocated",),
            ("ProvisioningState/succeeded", "PowerState/running"),
            ("ProvisioningState/succeeded", "PowerState/deallocating"),
            ("ProvisioningState/succeeded", "PowerState/deallocated",
             "PowerState/running"),
            ("ProvisioningState/failed", "PowerState/deallocated"),
            ("ProvisioningState/succeeded", "PowerState/deallocated",
             "OSState/generalized"),
        ):
            with self.subTest(codes=codes):
                self.fixture = Fixture()
                self.fixture.handoff["evidence"]["deallocation"] = self.fixture.put(
                    self.fixture.instance_view(codes)
                )
                with self.assertRaisesRegex(ValueError, "Deallocation and original OS swap"):
                    self.handoff(handoff=self.fixture.sign(self.fixture.handoff))
        for outcome in (
            {"id": self.fixture.ids["vm"], "vmId": self.fixture.uuids["vm"],
             "status": "Succeeded"},
            {**self.fixture.instance_view(), "instanceView": {"statuses": [
                "PowerState/deallocated", "ProvisioningState/succeeded"]}},
            {**self.fixture.instance_view(), "vmId": self.fixture.uuids["os"]},
        ):
            with self.subTest(outcome=sorted(outcome)):
                self.fixture = Fixture()
                self.fixture.handoff["evidence"]["deallocation"] = self.fixture.put(outcome)
                with self.assertRaisesRegex(ValueError, "Deallocation and original OS swap"):
                    self.handoff(handoff=self.fixture.sign(self.fixture.handoff))
        self.fixture = Fixture()
        self.fixture.handoff["evidence"]["deallocation"] = self.fixture.put(
            self.fixture.instance_view(("PowerState/deallocated",
                                        "ProvisioningState/succeeded"))
        )
        raw = self.fixture.sign(self.fixture.handoff)
        self.assertEqual(self.handoff(handoff=raw), self.fixture.sha(raw))

    def test_observed_power_state_uses_cli_show_details_text(self):
        for stage, field in (("prepared", "dummy_vm"), ("handoff", "vm")):
            for power in ("deallocated", "VM running", "VM stopped", None):
                with self.subTest(stage=stage, power=power):
                    self.fixture = Fixture()
                    vm = self.fixture.vm("dummy" if stage == "prepared" else "os")
                    if power is None:
                        del vm["powerState"]
                    else:
                        vm["powerState"] = power
                    getattr(self.fixture, stage)["evidence"][field] = self.fixture.put(vm)
                    self.fixture.resign_prepared()
                    with self.assertRaisesRegex(ValueError, "observed deallocated"):
                        self.handoff()

    def test_lost_original_swap_or_deallocation_response_refuses_handoff(self):
        for field in ("swap", "deallocation"):
            with self.subTest(field=field):
                self.fixture = Fixture()
                self.fixture.archive.pop(
                    self.fixture.handoff["evidence"][field]["sha256"]
                )
                with self.assertRaisesRegex(ValueError, "archive bytes are missing"):
                    self.handoff()

    def test_same_name_replaced_disk_uuid_and_dummy_attached_after_swap_fail(self):
        replaced = self.fixture.resource("os")
        replaced["uniqueId"] = "33333333-3333-4333-8333-333333333333"
        replaced["managedBy"] = self.fixture.ids["vm"]
        self.fixture.handoff["evidence"]["os"] = self.fixture.put(replaced)
        with self.assertRaisesRegex(ValueError, "disk identity"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))
        self.fixture = Fixture()
        still_attached = self.fixture.resource("dummy")
        still_attached["managedBy"] = self.fixture.ids["vm"]
        self.fixture.handoff["evidence"]["dummy"] = self.fixture.put(still_attached)
        with self.assertRaisesRegex(ValueError, "disk identity"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_same_name_replaced_data_disk_at_handoff_fails(self):
        replaced = self.fixture.resource("data7")
        replaced["uniqueId"] = "33333333-3333-4333-8333-333333333333"
        replaced["managedBy"] = self.fixture.ids["vm"]
        self.fixture.handoff["evidence"]["data_disks"]["data7"] = self.fixture.put(replaced)
        with self.assertRaisesRegex(ValueError, "data7 current disk identity"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_tampered_original_deployment_child_outputs_refused(self):
        result = self.fixture.resource("deployment")
        result["properties"]["outputs"]["nicId"]["value"] = self.fixture.ids["vm"]
        self.fixture.direct["deployment"]["terminal"] = self.fixture.put(result)
        self.fixture.resign_prepared()
        with self.assertRaisesRegex(ValueError, "output inventory"):
            self.handoff()

    def test_public_network_and_extra_inventory_fail_closed(self):
        nic = self.fixture.resource("nic")
        nic["ipConfigurations"][0]["publicIPAddress"] = {"id": "public"}
        self.fixture.handoff["evidence"]["children"]["nic"] = self.fixture.put(nic)
        with self.assertRaisesRegex(ValueError, "private network"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))
        self.fixture = Fixture()
        foreign = self.fixture.archive[self.fixture.inventory["sha256"]]
        inventory = json.loads(foreign)
        inventory["resources"].append({"role": "foreign", "id": "unknown", "uuid": None})
        self.fixture.prepared["evidence"]["inventory"] = self.fixture.put(inventory)
        self.fixture.resign_prepared()
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.handoff(prepared=self.fixture.sign(self.fixture.prepared))

    def test_prepared_and_handoff_inventory_require_the_same_exact_nsg(self):
        self.assertEqual(
            self.fixture.prepared["evidence"]["children"]["nsg"],
            self.fixture.handoff["evidence"]["children"]["nsg"],
        )
        inventory = json.loads(self.fixture.archive[self.fixture.inventory["sha256"]])
        self.assertEqual({item["role"] for item in inventory["resources"]},
                         set(custody.INVENTORY))
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))

    def test_fresh_handoff_nsg_observation_can_reorder_only_the_two_deny_rules(self):
        nsg = self.fixture.resource("nsg")
        nsg["securityRules"].reverse()
        self.fixture.handoff["evidence"]["children"]["nsg"] = self.fixture.put(nsg)
        self.assertNotEqual(self.fixture.prepared["evidence"]["children"]["nsg"],
                            self.fixture.handoff["evidence"]["children"]["nsg"])
        raw = self.fixture.sign(self.fixture.handoff)
        self.assertEqual(self.handoff(handoff=raw), self.fixture.sha(raw))

    def test_prepared_or_handoff_nsg_refuses_missing_and_extra_rules(self):
        for stage in ("prepared", "handoff"):
            for mutation in ("empty", "no-inbound", "no-outbound",
                             "duplicate", "extra-allow-platform"):
                with self.subTest(stage=stage, mutation=mutation):
                    self.fixture = Fixture()
                    nsg = self.fixture.resource("nsg")
                    rules = nsg["securityRules"]
                    if mutation == "empty":
                        rules.clear()
                    elif mutation == "no-inbound":
                        rules.pop(0)
                    elif mutation == "no-outbound":
                        rules.pop()
                    elif mutation == "duplicate":
                        rules[1] = dict(rules[0])
                    else:
                        rules.append({
                            **rules[1], "name": "AllowPlatformDNS",
                            "priority": 100, "access": "Allow",
                            "destinationAddressPrefix": "AzurePlatformDNS",
                        })
                    getattr(self.fixture, stage)["evidence"]["children"]["nsg"] = (
                        self.fixture.put(nsg)
                    )
                    if stage == "prepared":
                        self.fixture.resign_prepared()
                    with self.assertRaisesRegex(ValueError, "exact inbound/outbound"):
                        self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_prepared_or_handoff_nsg_refuses_weaker_rules(self):
        for stage in ("prepared", "handoff"):
            for index in (0, 1):
                for field, value in (
                    ("access", "Allow"),
                    ("direction", "Outbound" if index == 0 else "Inbound"),
                    ("priority", 65000),
                    ("priority", 100),
                    ("sourceAddressPrefix", "VirtualNetwork"),
                    ("destinationAddressPrefix", "10.90.0.0/29"),
                    ("sourcePortRange", "1024"),
                    ("destinationPortRange", "443"),
                    ("protocol", "Tcp"),
                ):
                    with self.subTest(stage=stage, rule=index, field=field, value=value):
                        self.fixture = Fixture()
                        nsg = self.fixture.resource("nsg")
                        nsg["securityRules"][index][field] = value
                        getattr(self.fixture, stage)["evidence"]["children"]["nsg"] = (
                            self.fixture.put(nsg)
                        )
                        if stage == "prepared":
                            self.fixture.resign_prepared()
                        with self.assertRaisesRegex(ValueError, "exact inbound/outbound"):
                            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_each_vm_observation_must_attach_only_approved_private_nic(self):
        for stage, field, os_role in (
            ("prepared", "children", "dummy"),
            ("prepared", "dummy_vm", "dummy"),
            ("handoff", "children", "os"),
            ("handoff", "swap", "os"),
            ("handoff", "vm", "os"),
        ):
            for attachment in ("foreign", "missing", "extra", "wrong-primary",
                               "wrong-delete", "nested-in-cli", "unknown-field"):
                with self.subTest(stage=stage, field=field, attachment=attachment):
                    self.fixture = Fixture()
                    vm = self.fixture.vm(os_role)
                    nics = vm["networkProfile"]["networkInterfaces"]
                    if attachment == "foreign":
                        nics[0]["id"] = self.fixture.ids["nic"] + "-public"
                    elif attachment == "missing":
                        nics.clear()
                    elif attachment == "extra":
                        nics.append({"id": self.fixture.ids["nic"] + "-public"})
                    elif attachment == "wrong-primary":
                        nics[0]["primary"] = False
                    elif attachment == "wrong-delete":
                        nics[0]["deleteOption"] = "Detach"
                    elif attachment == "nested-in-cli":
                        nics[0]["properties"] = {
                            "primary": nics[0].pop("primary"),
                            "deleteOption": nics[0].pop("deleteOption"),
                        }
                    else:
                        nics[0]["networkSecurityGroup"] = {"id": "foreign"}
                    ref = self.fixture.put(vm)
                    if field == "children":
                        getattr(self.fixture, stage)["evidence"]["children"]["vm"] = ref
                    else:
                        getattr(self.fixture, stage)["evidence"][field] = ref
                    self.fixture.resign_prepared()
                    with self.assertRaisesRegex(ValueError, "private NIC attachment"):
                        self.handoff()

    def test_vm_observations_reject_managed_identities(self):
        # Observed tenant policy can add identities that guest IMDS requests could use.
        identities = (
            {"type": "SystemAssigned", "principalId": str(uuid.uuid4()),
             "tenantId": str(uuid.uuid4())},
            {"type": "SystemAssigned, UserAssigned", "principalId": str(uuid.uuid4()),
             "tenantId": str(uuid.uuid4()), "userAssignedIdentities": {
                 "/subscriptions/x/resourceGroups/y/providers/"
                 "Microsoft.ManagedIdentity/userAssignedIdentities/z": {}}},
        )
        for stage, field, os_role in (
            ("prepared", "children", "dummy"),
            ("prepared", "dummy_vm", "dummy"),
            ("handoff", "children", "os"),
            ("handoff", "swap", "os"),
            ("handoff", "vm", "os"),
        ):
            with self.subTest(stage=stage, field=field):
                self.fixture = Fixture()
                vm = self.fixture.vm(os_role)
                vm["identity"] = identities[0]
                ref = self.fixture.put(vm)
                if field == "children":
                    getattr(self.fixture, stage)["evidence"]["children"]["vm"] = ref
                else:
                    getattr(self.fixture, stage)["evidence"][field] = ref
                self.fixture.resign_prepared()
                with self.assertRaisesRegex(ValueError, "managed identity"):
                    self.handoff()
        # Real user-assigned identity keys are resource IDs beyond the parser key limit.
        for identity, reason in zip(identities, ("Deallocation and original OS swap",
                                                 "Custody JSON key exceeds limit")):
            with self.subTest(deallocation=identity["type"]):
                self.fixture = Fixture()
                view = self.fixture.instance_view()
                view["identity"] = identity
                self.fixture.handoff["evidence"]["deallocation"] = self.fixture.put(view)
                with self.assertRaisesRegex(ValueError, reason):
                    self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_rest_vm_observation_requires_nested_nic_options(self):
        rest = Fixture.rest_vm(self.fixture.vm("os", deallocated=False))
        self.fixture.handoff["evidence"]["children"]["vm"] = self.fixture.put(rest)
        raw = self.fixture.sign(self.fixture.handoff)
        self.assertEqual(self.handoff(handoff=raw), self.fixture.sha(raw))
        self.fixture = Fixture()
        rest = Fixture.rest_vm(self.fixture.vm("os", deallocated=False))
        nic = rest["properties"]["networkProfile"]["networkInterfaces"][0]
        nic.update(nic.pop("properties"))
        self.fixture.handoff["evidence"]["children"]["vm"] = self.fixture.put(rest)
        with self.assertRaisesRegex(ValueError, "private NIC attachment"):
            self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_cli_output_resources_allow_only_exact_read_only_fields(self):
        bare = self.fixture.resource("deployment")
        for item in bare["properties"]["outputResources"]:
            for key in ("apiVersion", "extension", "identifiers",
                        "resourceGroup", "resourceType"):
                del item[key]
        self.fixture.direct["deployment"]["create"] = self.fixture.put(bare)
        self.fixture.direct["deployment"]["terminal"] = self.fixture.put(bare)
        self.fixture.resign_prepared()
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))
        for field, value in (
            ("apiVersion", "2025-11-01"), ("extension", {"name": "x"}),
            ("identifiers", [{"name": "vm"}]), ("resourceGroup", "other-rg"),
            ("resourceType", "Microsoft.Compute/disks"), ("symbolicName", "vm"),
        ):
            with self.subTest(field=field):
                self.fixture = Fixture()
                deployment = self.fixture.resource("deployment")
                deployment["properties"]["outputResources"][0][field] = value
                self.fixture.direct["deployment"]["create"] = self.fixture.put(deployment)
                self.fixture.direct["deployment"]["terminal"] = self.fixture.put(deployment)
                self.fixture.resign_prepared()
                with self.assertRaisesRegex(ValueError, "output inventory"):
                    self.handoff()

    def test_cli_nsg_rule_read_only_fields_cannot_widen_rules(self):
        for field, value in (
            ("sourceAddressPrefixes", ["Internet"]),
            ("destinationAddressPrefixes", ["AzurePlatformDNS"]),
            ("sourcePortRanges", ["1-65535"]),
            ("destinationPortRanges", ["443"]),
            ("provisioningState", "Updating"),
            ("type", "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"),
            ("id", "/foreign/securityRules/DenyAllInbound"),
            ("etag", 1),
            ("sourceApplicationSecurityGroups", [{"id": "asg"}]),
            ("description", "allow"),
        ):
            with self.subTest(field=field):
                self.fixture = Fixture()
                nsg = self.fixture.resource("nsg")
                nsg["securityRules"][0][field] = value
                self.fixture.handoff["evidence"]["children"]["nsg"] = self.fixture.put(nsg)
                with self.assertRaisesRegex(ValueError, "exact inbound/outbound"):
                    self.handoff(handoff=self.fixture.sign(self.fixture.handoff))

    def test_no_in_memory_or_absent_registry_can_claim_success(self):
        for registry in (None, {}, object()):
            with self.subTest(registry=registry):
                with self.assertRaisesRegex(ValueError, "injected durable"):
                    self.handoff(registry=registry)

    def test_private_registry_and_prior_handoff_claim_required(self):
        self.registry.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            self.handoff()
        self.registry = custody.FileReplayRegistry(self.temp.name)
        self.addCleanup(self.registry.close)
        with self.assertRaises(FileNotFoundError):
            self.closed()
        link = Path(self.temp.name).parent / (Path(self.temp.name).name + "-link")
        link.symlink_to(self.temp.name, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(ValueError, "symlink-free"):
            custody.FileReplayRegistry(link)
    def test_failed_registry_fsync_burns_run_and_refuses_retry(self):
        with mock.patch.object(custody.os, "fsync", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                self.handoff()
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.handoff()

    def test_stale_handoff_fails_before_replay_claim(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            self.handoff(now=datetime(2026, 9, 29, 4, 32, tzinfo=timezone.utc))
        self.assertEqual(self.handoff(), self.fixture.sha(self.fixture.handoff_raw))

    def test_closed_requires_post_handoff_authorization_and_independent_ack(self):
        self.handoff()
        with self.assertRaisesRegex(ValueError, "after handoff"):
            self.closed(acceptance_issued_at_utc="2026-09-29T03:59:00Z")
        with self.assertRaisesRegex(ValueError, "another pinned key"):
            self.closed(witness_public_key=signature_key(self.fixture.signer))
        with self.assertRaisesRegex(ValueError, "signature"):
            self.closed(witness_public_key=signature_key(Ed25519PrivateKey.generate()))
        self.assertEqual(self.closed().claimed_disposition, "quarantined")

    def test_closed_wrong_disposal_or_ack_and_late_audit(self):
        self.handoff()
        altered = dict(self.fixture.closed)
        altered["evidence"] = {**self.fixture.closed["evidence"],
                               "acceptance_authorization_sha256": "9" * 64}
        with self.assertRaisesRegex(ValueError, "wrong approval"):
            self.closed(closed=self.fixture.sign(altered))
        with self.assertRaisesRegex(ValueError, "acknowledgment"):
            self.closed(ack=self.fixture.sign({**self.fixture.ack,
                                               "closed_sha256": "0" * 64},
                                              key=self.fixture.witness))
        self.assertEqual(
            self.closed(now=datetime(2026, 9, 29, 5, 0, tzinfo=timezone.utc))
            .claimed_disposition,
            "quarantined",
        )


if __name__ == "__main__":
    unittest.main()
