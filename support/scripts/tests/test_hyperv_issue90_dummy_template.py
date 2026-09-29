# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic structural checks only; no ARM deployment or Azure CLI calls."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "support/scripts"))
import hyperv_issue90_topology as topology

TEMPLATE = ROOT / "support/azure/hyperv-issue90-custodian-dummy.json"
PIN_NAMES = (
    "provenanceSha256", "configSha256", "efiSha256", "rawSha256",
    "mizSha256", "imageSha256", "dummyImageSha256",
    "seed0Sha256", "seed7Sha256",
)
DISK_IDS = ("dummyOsDiskId", "acceptanceOsDiskId", "dataDisk0Id", "dataDisk7Id")
DISK_UUIDS = (
    "dummyOsDiskUuid", "acceptanceOsDiskUuid",
    "dataDisk0Uuid", "dataDisk7Uuid",
)
ROLES = ("nsg", "vnet", "nic", "vm")


def load():
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate ARM template key")
            result[key] = value
        return result

    return json.loads(TEMPLATE.read_text(encoding="utf-8"), object_pairs_hook=unique)


def check_contract(template):
    assert set(template) == {
        "$schema", "contentVersion", "parameters", "variables", "resources",
        "outputs",
    }
    assert template["$schema"] == (
        "https://schema.management.azure.com/schemas/"
        "2019-04-01/deploymentTemplate.json#"
    )
    assert template["contentVersion"] == "1.0.0.0"
    definitions = template["parameters"]
    assert set(definitions) == {
        "namePrefix", "location", "runId", "operationId", "reviewedHead",
        *PIN_NAMES, *DISK_IDS, *DISK_UUIDS,
    }
    for name, bounds in {
        "namePrefix": (6, 32), "runId": (32, 32),
        "operationId": (36, 36), "reviewedHead": (40, 40),
        **{name: (64, 64) for name in PIN_NAMES},
        **{name: (1, 512) for name in DISK_IDS},
        **{name: (36, 36) for name in DISK_UUIDS},
    }.items():
        assert definitions[name] == {
            "type": "string", "minLength": bounds[0], "maxLength": bounds[1],
        }
    assert definitions["location"] == {
        "type": "string", "allowedValues": ["northeurope"],
    }
    tags = template["variables"]["tags"]
    assert set(template["variables"]) == {"tags"}
    assert tags == {
        "managed-by": "unikraft-hyperv",
        "purpose": "issue90-read-only-topology",
        "unikraft-run": "[parameters('namePrefix')]",
        "issue90-run": "[parameters('runId')]",
        "issue90-operation": "[parameters('operationId')]",
        "reviewed-head": "[parameters('reviewedHead')]",
        "provenance-sha256": "[parameters('provenanceSha256')]",
        "config-sha256": "[parameters('configSha256')]",
        "efi-sha256": "[parameters('efiSha256')]",
        "raw-sha256": "[parameters('rawSha256')]",
        "miz-sha256": "[parameters('mizSha256')]",
        "image-sha256": "[parameters('imageSha256')]",
        "dummy-image-sha256": "[parameters('dummyImageSha256')]",
        "seed0-sha256": "[parameters('seed0Sha256')]",
        "seed7-sha256": "[parameters('seed7Sha256')]",
        "dummy-os-uuid": "[parameters('dummyOsDiskUuid')]",
        "acceptance-os-uuid": "[parameters('acceptanceOsDiskUuid')]",
        "data0-uuid": "[parameters('dataDisk0Uuid')]",
        "data7-uuid": "[parameters('dataDisk7Uuid')]",
    }
    resources = template["resources"]
    assert isinstance(resources, list) and len(resources) == 4
    assert [resource["type"] for resource in resources] == [
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Network/virtualNetworks",
        "Microsoft.Network/networkInterfaces",
        "Microsoft.Compute/virtualMachines",
    ]
    for role, resource in zip(ROLES, resources):
        assert resource["apiVersion"] == (
            "2025-11-01" if role == "vm" else "2024-05-01"
        )
        assert resource["name"] == (
            f"[concat(parameters('namePrefix'), '-{role}')]"
        )
        assert resource["location"] == "[parameters('location')]"
        assert resource["tags"] == (
            "[union(variables('tags'), createObject('issue90-role', "
            f"'{role}'))]"
        )
        assert set(resource) == {
            "type", "apiVersion", "name", "location", "tags", "properties",
            *(() if role == "nsg" else ("dependsOn",)),
        }
    assert resources[0]["properties"] == {"securityRules": []}
    assert resources[1]["dependsOn"] == [
        "[resourceId('Microsoft.Network/networkSecurityGroups', "
        "concat(parameters('namePrefix'), '-nsg'))]"
    ]
    assert resources[1]["properties"] == {
        "addressSpace": {"addressPrefixes": ["10.90.0.0/29"]},
        "subnets": [{
            "name": "default",
            "properties": {
                "addressPrefix": "10.90.0.0/29",
                "defaultOutboundAccess": False,
                "networkSecurityGroup": {"id": (
                    "[resourceId('Microsoft.Network/networkSecurityGroups', "
                    "concat(parameters('namePrefix'), '-nsg'))]"
                )},
            },
        }],
    }
    assert resources[2]["dependsOn"] == [
        "[resourceId('Microsoft.Network/virtualNetworks', "
        "concat(parameters('namePrefix'), '-vnet'))]"
    ]
    assert resources[2]["properties"] == {
        "enableAcceleratedNetworking": False,
        "enableIPForwarding": False,
        "ipConfigurations": [{
            "name": "primary",
            "properties": {
                "privateIPAllocationMethod": "Dynamic",
                "subnet": {"id": (
                    "[resourceId('Microsoft.Network/virtualNetworks/subnets', "
                    "concat(parameters('namePrefix'), '-vnet'), 'default')]"
                )},
            },
        }],
    }
    assert resources[3]["dependsOn"] == [
        "[resourceId('Microsoft.Network/networkInterfaces', "
        "concat(parameters('namePrefix'), '-nic'))]"
    ]
    vm = resources[3]["properties"]
    assert set(vm) == {
        "hardwareProfile", "storageProfile", "securityProfile",
        "networkProfile", "diagnosticsProfile",
    }
    assert vm["hardwareProfile"] == {"vmSize": "Standard_D2s_v5"}
    assert vm["securityProfile"] == {"securityType": "Standard"}
    assert vm["diagnosticsProfile"] == {"bootDiagnostics": {"enabled": True}}
    assert vm["networkProfile"] == {"networkInterfaces": [{
        "id": resources[3]["dependsOn"][0],
        "properties": {"primary": True, "deleteOption": "Delete"},
    }]}
    storage = vm["storageProfile"]
    assert set(storage) == {"diskControllerType", "osDisk", "dataDisks"}
    assert storage["diskControllerType"] == "SCSI"
    assert storage["osDisk"] == {
        "name": "[last(split(parameters('dummyOsDiskId'), '/'))]",
        "osType": "Linux", "createOption": "Attach", "caching": "ReadOnly",
        "deleteOption": "Detach",
        "managedDisk": {"id": "[parameters('dummyOsDiskId')]"},
    }
    assert storage["dataDisks"] == [{
        "lun": lun, "name": f"[last(split(parameters('{name}'), '/'))]",
        "createOption": "Attach", "caching": "None",
        "deleteOption": "Detach", "managedDisk": {"id": f"[parameters('{name}')]"},
    } for lun, name in ((0, "dataDisk0Id"), (7, "dataDisk7Id"))]
    assert template["outputs"] == {
        "vmId": {"type": "string", "value": (
            "[resourceId('Microsoft.Compute/virtualMachines', "
            "concat(parameters('namePrefix'), '-vm'))]"
        )},
        "vmUuid": {"type": "string", "value": (
            "[reference(resourceId('Microsoft.Compute/virtualMachines', "
            "concat(parameters('namePrefix'), '-vm')), '2025-11-01', "
            "'Full').properties.vmId]"
        )},
        "osDiskId": {"type": "string", "value": "[parameters('dummyOsDiskId')]"},
        "dataDisk0Id": {"type": "string", "value": "[parameters('dataDisk0Id')]"},
        "dataDisk7Id": {"type": "string", "value": "[parameters('dataDisk7Id')]"},
        "nicId": {"type": "string", "value": (
            "[resourceId('Microsoft.Network/networkInterfaces', "
            "concat(parameters('namePrefix'), '-nic'))]"
        )},
        "vnetId": {"type": "string", "value": (
            "[resourceId('Microsoft.Network/virtualNetworks', "
            "concat(parameters('namePrefix'), '-vnet'))]"
        )},
        "nsgId": {"type": "string", "value": resources[1]["dependsOn"][0]},
    }
    assert "parameters('acceptanceOsDiskId')" not in json.dumps(
        {"resources": resources, "outputs": template["outputs"]},
    )


def check_synthetic_inputs(template, state, values, receipts):
    assert set(values) == set(template["parameters"])
    for name, definition in template["parameters"].items():
        value = values[name]
        assert type(value) is str
        if "allowedValues" in definition:
            assert value in definition["allowedValues"]
        else:
            assert definition["minLength"] <= len(value) <= definition["maxLength"]
    assert topology.NAME.fullmatch(values["namePrefix"])
    assert values["namePrefix"] == state["prefix"]
    assert topology.HEX32.fullmatch(values["runId"]) and int(values["runId"], 16)
    assert values["runId"] == state["run_id"]
    assert values["operationId"] == state["operation_id"]
    assert re.fullmatch(r"[0-9a-f]{40}", values["reviewedHead"])
    for name in PIN_NAMES:
        assert re.fullmatch(r"[0-9a-f]{64}", values[name])
        assert int(values[name], 16)
    assert values["imageSha256"] != values["dummyImageSha256"]
    assert values["seed0Sha256"] != values["seed7Sha256"]
    assert len({values[name] for name in DISK_IDS}) == 4
    assert len({values[name] for name in DISK_UUIDS}) == 4
    for name in ("operationId", *DISK_UUIDS):
        assert str(uuid.UUID(values[name])) == values[name]
    assert values["dummyOsDiskId"] == (
        topology.group_id(state) + "/providers/Microsoft.Compute/disks/"
        + state["prefix"] + "-dummy"
    )
    for name, role in (
        ("acceptanceOsDiskId", "os"),
        ("dataDisk0Id", "data0"),
        ("dataDisk7Id", "data7"),
    ):
        assert values[name] == topology.resource_id(state, role)
    assert set(receipts) == {"dummy", "os", "data0", "data7"}
    for role, disk_id, disk_uuid, image, size in (
        ("dummy", "dummyOsDiskId", "dummyOsDiskUuid",
         "dummyImageSha256", topology.azure.VIRTUAL_SIZE),
        ("os", "acceptanceOsDiskId", "acceptanceOsDiskUuid",
         "imageSha256", topology.azure.VIRTUAL_SIZE),
        ("data0", "dataDisk0Id", "dataDisk0Uuid",
         "seed0Sha256", topology.DISK_BYTES),
        ("data7", "dataDisk7Id", "dataDisk7Uuid",
         "seed7Sha256", topology.DISK_BYTES),
    ):
        disk = receipts[role]
        assert disk == {
            "id": values[disk_id], "uuid": values[disk_uuid],
            "sku": "StandardSSD_LRS", "vhd_sha256": values[image],
            "diskSizeBytes": size, "uploadSizeBytes": size + 512,
            "hyperVGeneration": "V2" if role in ("dummy", "os") else None,
            "osType": "Linux" if role in ("dummy", "os") else None,
            "seedPolicy": 2 if role.startswith("data") else None,
        }
    assert receipts["data0"]["diskSizeBytes"] // 512 == topology.SECTORS
    assert receipts["data7"]["diskSizeBytes"] // 512 == topology.SECTORS


def check_synthetic_deployment(template, state, snapshot, disk_uuids):
    assert snapshot["id"] == topology.resource_id(state, "deployment")
    props = snapshot["properties"]
    assert str(uuid.UUID(props["correlationId"])) == props["correlationId"]
    assert props["correlationId"] not in disk_uuids
    assert all(set(item) == {"id"} for item in props["outputResources"])
    assert {item["id"] for item in props["outputResources"]} == {
        topology.resource_id(state, role) for role in ROLES
    }
    assert len(props["outputResources"]) == len(ROLES)
    outputs = props["outputs"]
    assert set(outputs) == set(template["outputs"])
    assert str(uuid.UUID(outputs["vmUuid"]["value"])) == outputs["vmUuid"]["value"]
    assert outputs["vmUuid"]["value"] not in disk_uuids
    assert outputs["vmUuid"]["value"] != props["correlationId"]
    assert outputs["vmId"]["value"] == topology.resource_id(state, "vm")
    assert outputs["osDiskId"]["value"] == (
        topology.group_id(state) + "/providers/Microsoft.Compute/disks/"
        + state["prefix"] + "-dummy"
    )
    for name, role in (
        ("dataDisk0Id", "data0"), ("dataDisk7Id", "data7"),
        ("nicId", "nic"), ("vnetId", "vnet"), ("nsgId", "nsg"),
    ):
        assert outputs[name]["value"] == topology.resource_id(state, role)
    assert all(item["type"] == "String" for item in outputs.values())


class DummyTemplateTest(unittest.TestCase):
    def test_candidate_is_syntactically_valid_and_separate_from_disabled_lane(self):
        candidate = load()
        check_contract(candidate)
        self.assertNotEqual(
            hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
            topology.TEMPLATE_SHA256,
        )
        self.assertEqual(
            topology.digest(topology.TEMPLATE), topology.TEMPLATE_SHA256,
        )
        self.assertNotEqual(TEMPLATE.resolve(), topology.TEMPLATE.resolve())

    def test_synthetic_role_identity_and_external_disk_receipts(self):
        template = load()
        check_contract(template)
        state = {
            "subscription": "12345678-1234-4234-8234-123456789abc",
            "prefix": "uk90-" + "a" * 20,
            "run_id": "b" * 32,
            "operation_id": "11111111-1111-4111-8111-111111111111",
        }
        group = topology.group_id(state)
        disks = {
            "dummy": group + "/providers/Microsoft.Compute/disks/"
                     + state["prefix"] + "-dummy",
            **{role: topology.resource_id(state, role)
               for role in ("os", "data0", "data7")},
        }
        synthetic = {
            "namePrefix": state["prefix"],
            "location": "northeurope",
            "runId": state["run_id"],
            "operationId": state["operation_id"],
            "reviewedHead": "e" * 40,
            "provenanceSha256": "f" * 64,
            "configSha256": "1" * 64,
            "efiSha256": "2" * 64,
            "rawSha256": "3" * 64,
            "mizSha256": "4" * 64,
            "dummyOsDiskId": disks["dummy"],
            "acceptanceOsDiskId": disks["os"],
            "dataDisk0Id": disks["data0"],
            "dataDisk7Id": disks["data7"],
            "dummyOsDiskUuid": "22222222-2222-4222-8222-222222222221",
            "acceptanceOsDiskUuid": "22222222-2222-4222-8222-222222222222",
            "dataDisk0Uuid": "22222222-2222-4222-8222-222222222223",
            "dataDisk7Uuid": "22222222-2222-4222-8222-222222222224",
            "imageSha256": "a" * 64, "dummyImageSha256": "b" * 64,
            "seed0Sha256": "c" * 64, "seed7Sha256": "d" * 64,
        }
        self.assertEqual(len(set(synthetic[key] for key in DISK_IDS)), 4)
        self.assertEqual(len(set(synthetic[key] for key in DISK_UUIDS)), 4)
        self.assertNotEqual(synthetic["imageSha256"], synthetic["dummyImageSha256"])
        self.assertNotEqual(synthetic["seed0Sha256"], synthetic["seed7Sha256"])
        receipt = {
            role: {
                "id": disks[role],
                "uuid": synthetic[key],
                "sku": "StandardSSD_LRS",
                "vhd_sha256": synthetic[digest_key],
                "diskSizeBytes": size,
                "uploadSizeBytes": size + 512,
                "hyperVGeneration": "V2" if role in ("dummy", "os") else None,
                "osType": "Linux" if role in ("dummy", "os") else None,
                "seedPolicy": 2 if role.startswith("data") else None,
            }
            for role, key, digest_key, size in (
                ("dummy", "dummyOsDiskUuid", "dummyImageSha256",
                 topology.azure.VIRTUAL_SIZE),
                ("os", "acceptanceOsDiskUuid", "imageSha256",
                 topology.azure.VIRTUAL_SIZE),
                ("data0", "dataDisk0Uuid", "seed0Sha256", topology.DISK_BYTES),
                ("data7", "dataDisk7Uuid", "seed7Sha256", topology.DISK_BYTES),
            )
        }
        check_synthetic_inputs(template, state, synthetic, receipt)
        self.assertEqual(set(receipt), {"dummy", "os", "data0", "data7"})
        self.assertTrue(all(value["sku"] == "StandardSSD_LRS"
                            for value in receipt.values()))
        self.assertEqual(
            [receipt[role]["diskSizeBytes"] // 512
             for role in ("data0", "data7")],
            [topology.SECTORS, topology.SECTORS],
        )
        self.assertEqual(
            template["outputs"]["osDiskId"]["value"],
            "[parameters('dummyOsDiskId')]",
        )
        self.assertNotIn(
            "parameters('acceptanceOsDiskId')",
            json.dumps(template["resources"]),
        )
        changes = {
            "foreign final OS ID": ("acceptanceOsDiskId", disks["dummy"]),
            "wrong data LUN owner": ("dataDisk7Id", disks["data0"]),
            "wrong region": ("location", "westus2"),
            "missing reviewed head": ("reviewedHead", "e" * 39),
            "zero run": ("runId", "0" * 32),
            "identical seed images": ("seed7Sha256", synthetic["seed0Sha256"]),
            "identical OS images": ("dummyImageSha256", synthetic["imageSha256"]),
            "malformed source hash": ("provenanceSha256", "F" * 64),
            "foreign disk uuid": ("dataDisk7Uuid", synthetic["dataDisk0Uuid"]),
        }
        for label, (key, value) in changes.items():
            with self.subTest(label=label):
                altered = {**synthetic, key: value}
                with self.assertRaises(AssertionError):
                    check_synthetic_inputs(template, state, altered, receipt)
        for label, role, field, wrong in (
            ("dummy not Gen2", "dummy", "hyperVGeneration", "V1"),
            ("final not Gen2", "os", "hyperVGeneration", "V1"),
            ("wrong sku", "data0", "sku", "Premium_LRS"),
            ("wrong sectors", "data7", "diskSizeBytes", topology.DISK_BYTES - 512),
            ("wrong upload size", "dummy", "uploadSizeBytes",
             topology.azure.VIRTUAL_SIZE),
            ("missing seed policy", "data0", "seedPolicy", None),
            ("swapped uuid", "data7", "uuid", synthetic["dataDisk0Uuid"]),
        ):
            with self.subTest(label=label):
                altered = deepcopy(receipt)
                altered[role][field] = wrong
                with self.assertRaises(AssertionError):
                    check_synthetic_inputs(template, state, synthetic, altered)
        for role in ("dummy", "os", "data0", "data7"):
            with self.subTest(missing_original_receipt=role):
                altered = deepcopy(receipt)
                altered.pop(role)
                with self.assertRaises(AssertionError):
                    check_synthetic_inputs(template, state, synthetic, altered)

    def test_tampered_security_network_disks_pins_and_outputs_fail_closed(self):
        base = load()
        changes = {
            "unbounded source pin": lambda t: t["parameters"]["provenanceSha256"]
                .pop("maxLength"),
            "wrong final image pin": lambda t: t["variables"]["tags"]
                .update({"image-sha256": "[parameters('dummyImageSha256')]"}),
            "missing dummy uuid": lambda t: t["parameters"]
                .pop("dummyOsDiskUuid"),
            "public ip": lambda t: t["resources"][2]["properties"]
                ["ipConfigurations"][0]["properties"]
                .update({"publicIPAddress": {"id": "synthetic-public"}}),
            "public ingress": lambda t: t["resources"][0]["properties"]
                ["securityRules"].append({"name": "allow-all"}),
            "outbound enabled": lambda t: t["resources"][1]["properties"]
                ["subnets"][0]["properties"]
                .update({"defaultOutboundAccess": True}),
            "extra disk PUT": lambda t: t["resources"].append({
                "type": "Microsoft.Compute/disks",
            }),
            "trusted launch": lambda t: t["resources"][3]["properties"]
                ["securityProfile"].update({"securityType": "TrustedLaunch"}),
            "wrong VM size": lambda t: t["resources"][3]["properties"]
                ["hardwareProfile"].update({"vmSize": "Standard_D4s_v5"}),
            "final OS attached": lambda t: t["resources"][3]["properties"]
                ["storageProfile"]["osDisk"]["managedDisk"]
                .update({"id": "[parameters('acceptanceOsDiskId')]"}),
            "final OS output": lambda t: t["outputs"]["osDiskId"]
                .update({"value": "[parameters('acceptanceOsDiskId')]"}),
            "wrong LUN": lambda t: t["resources"][3]["properties"]
                ["storageProfile"]["dataDisks"][1].update({"lun": 6}),
            "seed swapped": lambda t: t["resources"][3]["properties"]
                ["storageProfile"]["dataDisks"][1]["managedDisk"]
                .update({"id": "[parameters('dataDisk0Id')]"}),
            "extra output": lambda t: t["outputs"].update({
                "acceptanceOsDiskId": {
                    "type": "string", "value": "[parameters('acceptanceOsDiskId')]",
                },
            }),
        }
        for label, mutate in changes.items():
            with self.subTest(label=label):
                tampered = deepcopy(base)
                mutate(tampered)
                with self.assertRaises(AssertionError):
                    check_contract(tampered)

    def test_synthetic_deployment_correlation_and_children_are_not_disk_puts(self):
        template = load()
        state = {
            "subscription": "12345678-1234-4234-8234-123456789abc",
            "prefix": "uk90-" + "a" * 20,
        }
        vm_uuid = "22222222-2222-4222-8222-222222222225"
        snapshot = {
            "id": topology.resource_id(state, "deployment"),
            "properties": {
                "correlationId": "22222222-2222-4222-8222-222222222226",
                "outputResources": [
                    {"id": topology.resource_id(state, role)} for role in ROLES
                ],
                "outputs": {
                    "vmUuid": {"type": "String", "value": vm_uuid},
                    "vmId": {
                        "type": "String",
                        "value": topology.resource_id(state, "vm"),
                    },
                    "osDiskId": {
                        "type": "String",
                        "value": topology.group_id(state)
                                 + "/providers/Microsoft.Compute/disks/"
                                 + state["prefix"] + "-dummy",
                    },
                    **{
                        key: {
                            "type": "String",
                            "value": topology.resource_id(state, role),
                        }
                        for key, role in (
                            ("dataDisk0Id", "data0"), ("dataDisk7Id", "data7"),
                            ("nicId", "nic"), ("vnetId", "vnet"), ("nsgId", "nsg"),
                        )
                    },
                },
            },
        }
        disk_uuids = {
            f"22222222-2222-4222-8222-{number:012x}"
            for number in range(1, 5)
        }
        check_synthetic_deployment(template, state, snapshot, disk_uuids)
        for label, alter in {
            "missing NIC child": lambda item: item["properties"]["outputResources"]
                .pop(2),
            "foreign correlation": lambda item: item["properties"]
                .update({"correlationId": "not-a-uuid"}),
            "dummy output replaced by final": lambda item: item["properties"]
                ["outputs"]["osDiskId"].update({
                    "value": topology.resource_id(state, "os"),
                }),
            "missing original VM UUID": lambda item: item["properties"]
                ["outputs"].pop("vmUuid"),
            "VM UUID borrows dummy disk": lambda item: item["properties"]
                ["outputs"]["vmUuid"].update({
                    "value": min(disk_uuids),
                }),
            "disk misrepresented as ARM child": lambda item: item["properties"]
                ["outputResources"].append({
                    "id": topology.resource_id(state, "data0"),
                }),
        }.items():
            with self.subTest(label=label):
                tampered = deepcopy(snapshot)
                alter(tampered)
                with self.assertRaises((AssertionError, ValueError, KeyError)):
                    check_synthetic_deployment(
                        template, state, tampered, disk_uuids,
                    )

    def test_duplicate_json_property_refuses(self):
        original = TEMPLATE.read_text(encoding="utf-8")
        duplicate = original.replace(
            '"contentVersion": "1.0.0.0",',
            '"contentVersion": "1.0.0.0", "contentVersion": "1.0.0.0",',
            1,
        )
        self.assertNotEqual(original, duplicate)

        def reject_duplicates(pairs):
            values = {}
            for key, value in pairs:
                if key in values:
                    raise ValueError("Duplicate ARM template key")
                values[key] = value
            return values

        with self.assertRaisesRegex(ValueError, "Duplicate ARM template key"):
            json.loads(duplicate, object_pairs_hook=reject_duplicates)


if __name__ == "__main__":
    unittest.main()
