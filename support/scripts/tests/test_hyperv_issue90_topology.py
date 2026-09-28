# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic #90 acceptance and owner-checked cleanup; never invokes Azure."""

import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "support/scripts"))
lane = importlib.import_module("hyperv_issue90_topology")
seed_producer = importlib.import_module("hyperv-storage-manifest")
live_cleanup_proof = lane.require_live_cleanup_proof


def serial(state):
    result = [
        "UK_HYPERV_PLATFORM_READY",
        "HYPERV_TOPOLOGY TARGET INFO id=10 controller=0 channel=3 "
        "address=0:0:0 sectors=135168 sector_size=512 "
        "instance_crc32=01234567 vpd_length=0 vpd_crc32=00000000",
        "HYPERV_TOPOLOGY OS_READ PASS id=10 controller=0 channel=3 "
        "lun=0 bytes=1024 mbr=1 gpt=1",
    ]
    for role, disk_id, channel in (
        ("data0", 11, 4), ("data7", 12, 5),
    ):
        result += [
            f"HYPERV_TOPOLOGY TARGET INFO id={disk_id} controller=0 "
            f"channel={channel} address=0:0:{lane.LUNS[role]} "
            f"sectors={lane.SECTORS} sector_size=512 "
            "instance_crc32=98765432 vpd_length=0 vpd_crc32=00000000",
            f"HYPERV_TOPOLOGY DATA_READ PASS role={0 if role == 'data0' else 1} "
            f"id={disk_id} controller=0 channel={channel} "
            f"address=0:0:{lane.LUNS[role]} sectors={lane.SECTORS} bytes=1024 "
            f"seed_crc32={zlib.crc32(lane.seed_sector(state, role) * 2):08x}",
        ]
    result += [
        "HYPERV_TOPOLOGY FINAL PASS devices=3 os=1 data0=1 data_nonzero=1",
        "UK_HYPERV_TOPOLOGY_READ_OK",
        "HYPERV_TOPOLOGY RESULT PASS",
        "main returned 0",
    ]
    return "\n".join(result) + "\n"


class FakeAzure:
    def __init__(self, state):
        self.state = state
        self.group_exists = False
        self.created = []
        self.deployed = False
        self.deleted = False
        self.tamper = None
        self.missing_response = None
        self.group_hidden_after_lost_response = False
        self.replace_after_lost_response = False
        self.group_incarnation = str(uuid.uuid5(uuid.NAMESPACE_DNS, "issue90-group"))
        self.fail_vm_show_once = False
        self.deployment_shown = False
        self.pinned_reads = 0
        self.serial_noise = ""
        self.calls = []
        self.disk_uuids = {
            role: str(uuid.uuid5(uuid.NAMESPACE_DNS, role)) for role in lane.ROLES
        }
        self.vm_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "issue90-vm"))
        self.correlation = str(uuid.uuid5(uuid.NAMESPACE_DNS, "issue90-operation"))

    def resource(self, role):
        if role == "group":
            return {"id": lane.group_id(self.state),
                    "name": self.state["prefix"] + "-rg",
                    "location": "northeurope",
                    "tags": lane.tags(self.state, role)}
        name = self.state["prefix"] + {
            "os": "-os", "data0": "-data0", "data7": "-data7",
            "vm": "-vm", "nic": "-nic", "vnet": "-vnet", "nsg": "-nsg",
        }[role]
        kind = lane.resource_id(self.state, role).split("/providers/")[-1].rsplit("/", 1)[0]
        resource = {
            "id": lane.resource_id(self.state, role), "name": name,
            "type": kind, "location": "northeurope",
            "tags": lane.tags(self.state, role),
        }
        if self.tamper == ("disk-owner", role) and role in self.created:
            resource["tags"]["issue90-run"] = "foreign"
        return resource

    def disk(self, role):
        result = {
            **self.resource(role),
            "uniqueId": self.disk_uuids[role],
            "sku": {"name": "StandardSSD_LRS"},
            "diskSizeBytes": lane.azure.VIRTUAL_SIZE if role == "os" else lane.DISK_BYTES,
            "diskSizeGb": 1 if role == "os" else 4,
            "creationData": {
                "createOption": "Upload",
                "uploadSizeBytes": (lane.azure.VIRTUAL_SIZE if role == "os"
                                    else lane.DISK_BYTES) + 512,
            },
            "hyperVGeneration": "V2" if role == "os" else None,
            "osType": "Linux" if role == "os" else None,
            "provisioningState": "Succeeded",
            "diskState": "Attached" if self.deployed else "Unattached",
            "managedBy": lane.resource_id(self.state, "vm") if self.deployed else None,
        }
        if self.tamper == ("disk-uuid", role) and self.deployed:
            result["uniqueId"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, "replaced"))
        if self.tamper == ("disk-size", role):
            result["diskSizeBytes"] += 512
        if self.tamper == ("disk-size-missing", role):
            del result["diskSizeBytes"]
        if self.tamper == ("disk-uuid-missing", role):
            del result["uniqueId"]
        if self.tamper == ("disk-upload-size", role):
            result["creationData"]["uploadSizeBytes"] += 512
        if self.tamper == ("disk-upload-option", role):
            result["creationData"]["createOption"] = "Empty"
        if self.tamper == ("disk-gib", role):
            result["diskSizeGb"] += 1
        if self.tamper == ("disk-generation", role):
            result["hyperVGeneration"] = "V1"
        if self.tamper == ("disk-owner", role):
            result["tags"]["issue90-run"] = "foreign"
        return result

    def deployment(self):
        parameters = lane.TopologyRun(self.state, Path(".")).parameters()
        outputs = {
            key: {"type": "String", "value": lane.resource_id(self.state, role)}
            for key, role in lane.OUTPUT_ROLES.items()
        }
        outputs["vmUuid"] = {"type": "String", "value": self.vm_uuid}
        if self.tamper == ("output-missing", "data7"):
            del outputs["dataDisk7Id"]
        if self.tamper == ("output-foreign", "data7"):
            outputs["dataDisk7Id"]["value"] = lane.resource_id(self.state, "data0")
        if self.tamper == ("output-uuid-missing", "vm"):
            del outputs["vmUuid"]
        if self.tamper == ("output-uuid-type", "vm"):
            outputs["vmUuid"]["type"] = "Integer"
        result = {
            "id": lane.resource_id(self.state, "deployment"),
            "name": self.state["prefix"],
            "type": "Microsoft.Resources/deployments",
            "properties": {
                "provisioningState": "Succeeded", "mode": "Incremental",
                "correlationId": (
                    str(uuid.uuid5(uuid.NAMESPACE_DNS, "replaced-operation"))
                    if self.tamper == ("correlation-replaced", "deployment")
                    and self.deployment_shown else self.correlation
                ),
                "parameters": {key: {"type": "String", "value": value}
                               for key, value in parameters.items()},
                "outputResources": [{"id": lane.resource_id(self.state, role)}
                                    for role in ("nsg", "vnet", "nic", "vm")],
                "outputs": outputs,
            },
        }
        if self.tamper == ("deployment-mode-missing", "deployment"):
            del result["properties"]["mode"]
        if self.tamper == ("deployment-parameter-missing", "deployment"):
            del result["properties"]["parameters"]["runId"]["type"]
        return result

    def vm(self):
        vm = {
            **self.resource("vm"), "vmId": self.vm_uuid,
            "hardwareProfile": {"vmSize": "Standard_D2s_v5"},
            "storageProfile": {
                "diskControllerType": "SCSI",
                "osDisk": {
                    "name": self.state["prefix"] + "-os", "osType": "Linux",
                    "createOption": "Attach", "caching": "ReadOnly",
                    "deleteOption": "Detach",
                    "managedDisk": {"id": lane.resource_id(self.state, "os")},
                },
                "dataDisks": [
                    {"lun": lane.LUNS[role], "name": self.state["prefix"] + "-" + role,
                     "createOption": "Attach", "caching": "None",
                     "deleteOption": "Detach", "managedDisk": {
                        "id": lane.resource_id(self.state, role)}}
                    for role in lane.LUNS
                ],
            },
            "securityProfile": {"securityType": "Standard"},
            "networkProfile": {"networkInterfaces": [
                {"id": lane.resource_id(self.state, "nic"),
                 "properties": {"primary": True, "deleteOption": "Delete"}}
            ]},
        }
        if self.tamper == ("vm-lun", "data7"):
            vm["storageProfile"]["dataDisks"][1]["lun"] = 6
        if self.tamper == ("vm-uuid", "vm"):
            vm["vmId"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, "other-vm"))
        if self.tamper == ("vm-os-create", "vm"):
            vm["storageProfile"]["osDisk"]["createOption"] = "FromImage"
        if self.tamper == ("vm-os-delete", "vm"):
            vm["storageProfile"]["osDisk"]["deleteOption"] = "Delete"
        if self.tamper == ("vm-data-cache", "vm"):
            vm["storageProfile"]["dataDisks"][1]["caching"] = "ReadWrite"
        if self.tamper == ("vm-nic-delete", "vm"):
            vm["networkProfile"]["networkInterfaces"][0]["properties"]["deleteOption"] = "Detach"
        if self.tamper == ("security-missing", "vm-show"):
            del vm["securityProfile"]
        return vm

    def pinned_vm(self):
        vm = self.vm()
        resource = self.resource("vm")
        properties = {
            "vmId": self.vm_uuid, "provisioningState": "Succeeded",
            "hardwareProfile": vm["hardwareProfile"],
            "storageProfile": copy.deepcopy(vm["storageProfile"]),
            "networkProfile": copy.deepcopy(vm["networkProfile"]),
            "securityProfile": {"securityType": "Standard"},
        }
        if self.tamper == ("security-missing", "pinned"):
            del properties["securityProfile"]
        if self.tamper == ("security-forged", "pinned"):
            properties["securityProfile"]["securityType"] = "TrustedLaunch"
        if (self.tamper == ("security-on-cleanup", "pinned")
                and self.pinned_reads >= 3):
            properties["securityProfile"]["securityType"] = "TrustedLaunch"
        if self.tamper == ("security-extra", "pinned"):
            properties["securityProfile"]["uefiSettings"] = {
                "secureBootEnabled": True
            }
        if self.tamper == ("security-uuid", "pinned"):
            properties["vmId"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, "other-vm"))
        if self.tamper == ("security-os-disk", "pinned"):
            properties["storageProfile"]["osDisk"]["managedDisk"]["id"] = (
                lane.resource_id(self.state, "data0")
            )
        if self.tamper == ("security-nic", "pinned"):
            properties["networkProfile"]["networkInterfaces"][0]["id"] = (
                lane.resource_id(self.state, "vnet")
            )
        if self.tamper == ("security-operation", "pinned"):
            resource["tags"]["issue90-operation"] = str(uuid.uuid4())
        if self.tamper == ("security-type", "pinned"):
            resource["type"] = "Microsoft.Compute/disks"
        if self.tamper == ("security-os-delete", "pinned"):
            properties["storageProfile"]["osDisk"]["deleteOption"] = "Delete"
        return {**resource, "properties": properties}

    def az(self, args, *, subscription, private, timeout):
        assert subscription == self.state["subscription"] and private and timeout > 0
        action = tuple(args[:3])
        self.calls.append(action)
        if action[:2] == ("group", "exists"):
            return self.group_exists
        if action[:2] == ("group", "create"):
            self.group_exists = True
            if self.missing_response == ("group", "group"):
                if self.group_hidden_after_lost_response:
                    self.group_exists = False
                if self.replace_after_lost_response:
                    self.group_incarnation = str(uuid.uuid5(
                        uuid.NAMESPACE_DNS, "issue90-replaced-group"
                    ))
                raise lane.azure.AzureCliTimeout(["group", "create"])
            return self.resource("group")
        if action[:2] == ("group", "show"):
            return self.resource("group")
        if action[:2] == ("group", "delete"):
            self.deleted = True
            self.group_exists = False
            return None
        if action[:2] == ("resource", "list"):
            resources = [self.resource(role) for role in self.created]
            if self.deployed:
                resources += [self.resource(role) for role in ("nsg", "vnet", "nic", "vm")]
            if self.tamper == ("inventory", "foreign"):
                resources += [{
                    **self.resource("nic"),
                    "id": lane.resource_id(self.state, "nic") + "/foreign",
                    "name": "foreign", "tags": {"managed-by": "other"},
                }]
            if self.tamper == ("inventory", "missing"):
                resources = [r for r in resources
                             if r["id"] != lane.resource_id(self.state, "data7")]
            if self.tamper == ("inventory", "not-yet-visible"):
                resources = [r for r in resources
                             if r["id"] not in {
                                 lane.resource_id(self.state, role)
                                 for role in ("os", "data0", "data7", "nsg",
                                              "vnet", "nic", "vm")
                                 }]
            return resources
        if action == ("resource", "show", "--ids"):
            assert args == [
                "resource", "show", "--ids", lane.resource_id(self.state, "vm"),
                "--api-version", lane.COMPUTE_API_VERSION,
            ]
            self.pinned_reads += 1
            return self.pinned_vm()
        if action[:2] == ("disk", "create"):
            role = {self.state["prefix"] + {
                "os": "-os", "data0": "-data0", "data7": "-data7"}[role]: role
                for role in lane.ROLES}[args[args.index("--name") + 1]]
            self.created.append(role)
            if self.missing_response == ("disk", role):
                if self.group_hidden_after_lost_response:
                    self.group_exists = False
                if self.replace_after_lost_response:
                    self.disk_uuids[role] = str(uuid.uuid5(
                        uuid.NAMESPACE_DNS, "issue90-replaced-" + role
                    ))
                raise lane.azure.AzureCliTimeout(["disk", "create"])
            return self.disk(role)
        if action[:2] == ("disk", "show"):
            return self.disk({
                self.state["prefix"] + {"os": "-os", "data0": "-data0",
                                        "data7": "-data7"}[role]: role
                for role in lane.ROLES
            }[args[args.index("--name") + 1]])
        if action[:2] == ("disk", "grant-access"):
            return {"accessSAS": "https://upload.blob.core.windows.net/disk?sig=synthetic"}
        if action[:2] == ("disk", "revoke-access"):
            return {}
        if action == ("deployment", "group", "create"):
            assert self.created == list(lane.ROLES)
            self.deployed = True
            if self.missing_response == ("deployment", "vm"):
                if self.group_hidden_after_lost_response:
                    self.group_exists = False
                if self.replace_after_lost_response:
                    self.correlation = str(uuid.uuid5(
                        uuid.NAMESPACE_DNS, "issue90-replaced-deployment"
                    ))
                    self.vm_uuid = str(uuid.uuid5(
                        uuid.NAMESPACE_DNS, "issue90-replaced-vm"
                    ))
                raise lane.azure.AzureCliTimeout(["deployment", "group", "create"])
            return self.deployment()
        if action == ("deployment", "group", "show"):
            self.deployment_shown = True
            return self.deployment()
        if action[:2] == ("vm", "show"):
            if self.fail_vm_show_once:
                self.fail_vm_show_once = False
                raise lane.azure.AzureCliTimeout(["vm", "show"])
            return self.vm()
        if action[:2] == ("vm", "deallocate"):
            return {}
        if action == ("vm", "boot-diagnostics", "get-boot-log"):
            return serial(self.state) + self.serial_noise
        if action == ("network", "nic", "show"):
            resource = {**self.resource("nic"), "enableIPForwarding": False,
                    "enableAcceleratedNetworking": False,
                    "ipConfigurations": [{
                        "name": "primary", "privateIPAllocationMethod": "Dynamic",
                        "publicIPAddress": None, "subnet": {"id":
                            lane.resource_id(self.state, "vnet") + "/subnets/default"}
                    }]}
            if self.tamper == ("network-public", "nic"):
                resource["ipConfigurations"][0]["publicIPAddress"] = {
                    "id": lane.resource_id(self.state, "nic") + "-public"
                }
            return resource
        if action == ("network", "vnet", "show"):
            resource = {**self.resource("vnet"),
                        "addressSpace": {"addressPrefixes": ["10.90.0.0/29"]},
                        "subnets": [{
                "name": "default", "addressPrefix": "10.90.0.0/29",
                "defaultOutboundAccess": False,
                "networkSecurityGroup": {"id": lane.resource_id(self.state, "nsg")},
            }]}
            if self.tamper == ("network-outbound", "vnet"):
                resource["subnets"][0]["defaultOutboundAccess"] = True
            if self.tamper == ("network-nat", "vnet"):
                resource["subnets"][0]["natGateway"] = {"id": "external-nat"}
            return resource
        if action == ("network", "nsg", "show"):
            return {**self.resource("nsg"), "securityRules": []}
        raise AssertionError(f"Unexpected synthetic Azure command: {action}")


class Issue90TopologyTest(unittest.TestCase):
    def setUp(self):
        parent = ROOT / ".d/issue90-test-fixtures"
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = parent / uuid.uuid4().hex
        self.state = lane.plan(
            self.directory, "12345678-1234-4234-8234-123456789abc"
        )
        self.state["prepared"] = {
            "image_sha256": "a" * 64,
            "config_sha256": "b" * 64,
            "seeds": {role: {"sha256": char * 64,
                              "manifest_sha256": char * 64,
                              "size": lane.DISK_BYTES + 512}
                      for role, char in (("data0", "c"), ("data7", "d"))},
            "implementation": {"synthetic": "e" * 64},
        }
        self.state["phase"] = "prepared"
        lane.save(self.directory, self.state)
        for role in lane.ROLES:
            name = "guest.vhd" if role == "os" else f"{role}.vhd"
            (self.directory / name).write_bytes(b"synthetic image")
        self.fake = FakeAzure(self.state)
        self.synthetic_live_gate = mock.patch.object(
            lane, "require_live_cleanup_proof", return_value=None
        )
        self.synthetic_live_gate.start()
        self.addCleanup(self.synthetic_live_gate.stop)

    def tearDown(self):
        shutil.rmtree(self.directory)

    def test_live_run_is_disabled_before_cloud_access(self):
        with mock.patch.object(
            lane, "require_live_cleanup_proof", side_effect=live_cleanup_proof
        ), mock.patch.object(lane.azure, "azure_cli") as cli, mock.patch.object(
            lane.azure, "check_upload_dependencies"
        ) as dependencies:
            with self.assertRaisesRegex(RuntimeError, "allocation is disabled"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        cli.assert_not_called()
        dependencies.assert_not_called()
        self.assertEqual(lane.load(self.directory)["phase"], "prepared")
        self.assertFalse(self.fake.group_exists)

    def test_prepared_state_cannot_claim_unverified_build_provenance(self):
        with self.assertRaisesRegex(ValueError, "build provenance is unavailable"):
            lane.verify_inputs(self.directory, self.state)

    def test_exact_arm_envelope_is_private_and_pinned(self):
        template = json.loads(lane.TEMPLATE.read_text())
        self.assertEqual(lane.digest(lane.TEMPLATE), lane.TEMPLATE_SHA256)
        self.assertEqual(
            set(template["parameters"]),
            set(lane.TopologyRun(self.state, self.directory).parameters()),
        )
        self.assertEqual(template["variables"]["tags"]["issue90-operation"],
                         "[parameters('operationId')]")
        for role, key in (("os", "image-sha256"), ("data0", "seed0-sha256"),
                          ("data7", "seed7-sha256")):
            self.assertEqual(lane.tags(self.state, role)[key],
                             self.fake.resource(role)["tags"][key])
        for resource in template["resources"]:
            self.assertIn("variables('tags')", resource["tags"])
            self.assertIn("'issue90-role'", resource["tags"])
        vm = next(resource for resource in template["resources"]
                  if resource["type"] == "Microsoft.Compute/virtualMachines")
        self.assertEqual(vm["apiVersion"], lane.COMPUTE_API_VERSION)
        self.assertEqual(vm["properties"]["securityProfile"]["securityType"],
                         "Standard")
        self.assertEqual(vm["properties"]["hardwareProfile"]["vmSize"],
                         "Standard_D2s_v5")
        os_disk = vm["properties"]["storageProfile"]["osDisk"]
        self.assertEqual(os_disk["createOption"], "Attach")
        self.assertEqual(os_disk["osType"], "Linux")
        self.assertEqual(os_disk["caching"], "ReadOnly")
        self.assertEqual(os_disk["deleteOption"], "Detach")
        self.assertEqual(os_disk["managedDisk"]["id"], "[parameters('osDiskId')]")
        data = vm["properties"]["storageProfile"]["dataDisks"]
        self.assertEqual([disk["lun"] for disk in data], [0, 7])
        self.assertEqual([disk["managedDisk"]["id"] for disk in data],
                         ["[parameters('dataDisk0Id')]",
                          "[parameters('dataDisk7Id')]"])
        self.assertTrue(all(disk["createOption"] == "Attach"
                            and disk["caching"] == "None"
                            and disk["deleteOption"] == "Detach" for disk in data))
        self.assertEqual(
            vm["properties"]["networkProfile"]["networkInterfaces"][0]["properties"],
            {"primary": True, "deleteOption": "Delete"},
        )
        self.assertEqual(len(template["resources"]), 4)
        self.assertEqual(set(template["outputs"]), set(lane.OUTPUT_ROLES) | {"vmUuid"})
        self.assertIn(f"'{lane.COMPUTE_API_VERSION}'",
                      template["outputs"]["vmUuid"]["value"])
        self.assertEqual(template["resources"][0]["properties"]["securityRules"], [])
        self.assertFalse(template["resources"][1]["properties"]["subnets"][0]
                         ["properties"]["defaultOutboundAccess"])
        self.assertNotIn("publicIPAddress", template["resources"][2]
                         ["properties"]["ipConfigurations"][0]["properties"])
        self.assertFalse(any(resource["type"].endswith("/publicIPAddresses")
                             for resource in template["resources"]))
        with mock.patch.object(lane, "TEMPLATE_SHA256", "f" * 64):
            with self.assertRaisesRegex(ValueError, "reviewed #90 ARM template"):
                lane.implementation()

    def test_solved_guest_config_binds_both_fresh_seeds_and_read_only_mode(self):
        settings = {
            "APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY": "y",
            "LIBSTORVSC_LUN_DISCOVERY": "y",
            "LIBSTORVSC_MAX_DEVICES": "3",
            "LIBSTORVSC_MAX_LUNS": "2",
            "APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID": f'"{self.state["run_id"]}"',
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID":
                f'"{self.state["disk_ids"]["data0"]}"',
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID":
                f'"{self.state["disk_ids"]["data7"]}"',
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS": str(lane.SECTORS),
            "APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS": str(lane.SECTORS),
            "APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN": "7",
        }

        def encode(values):
            return "\n".join(
                f"CONFIG_{key}={value}" for key, value in values.items()
            ).encode()

        lane.solved_config(encode(settings), self.state)
        for key, value in (
            ("APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID", '"wrong"'),
            ("APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN", "6"),
            ("APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS", "1048576"),
            ("LIBSTORVSC_MAX_DEVICES", "1"),
            ("APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY", "n"),
            ("APPHYPERVACCEPTANCE_PERSISTENCE", "y"),
            ("APPHYPERVACCEPTANCE_NETWORK_APPLICATION", "y"),
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    lane.solved_config(encode({**settings, key: value}), self.state)

    def test_local_preparation_rejects_missing_topology_unavailable_marker(self):
        config_path = self.directory / "producer.config"
        config_path.write_text("\n".join((
            "CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY=y",
            "CONFIG_LIBSTORVSC_LUN_DISCOVERY=y",
            "CONFIG_LIBSTORVSC_MAX_DEVICES=3",
            "CONFIG_LIBSTORVSC_MAX_LUNS=2",
            f'CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID="{self.state["run_id"]}"',
            f'CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID="{self.state["disk_ids"]["data0"]}"',
            f'CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID="{self.state["disk_ids"]["data7"]}"',
            f"CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS={lane.SECTORS}",
            f"CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS={lane.SECTORS}",
            "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN=7",
        )))
        producer = self.directory / "producer"
        producer.mkdir(mode=0o700)
        source = {
            "phase": "prepared", "local_platform_boot": True,
            "location": "northeurope", "vm_size": "Standard_D2s_v5",
            "image_sha256": "a" * 64, "efi_sha256": "b" * 64,
            "raw_sha256": "c" * 64,
            "acceptance": {"mode": "raw-dhcp"},
            "local_platform_boot_modes": {
                "raw": {"x2apic": True, "legacy-apic": True},
                "vhd": {"x2apic": True, "legacy-apic": True},
            },
        }
        for kind in ("raw", "vpc"):
            for mode in ("x2apic", "legacy-apic"):
                (producer / f"local-{kind}-{mode}-serial.log").write_text(
                    "UK_HYPERV_PLATFORM_READY\nHYPERV_TOPOLOGY RESULT UNAVAILABLE\n"
                )
        with mock.patch.object(lane.azure, "load_state", return_value=(
            source, producer / "state.json"
        )), mock.patch.object(lane.azure, "validate_local_boot_log",
                             return_value={"io_ready": False, "crashes": []}):
            self.state["phase"] = "planned"
            with self.assertRaisesRegex(ValueError, "read-only topology"):
                lane.prepare(
                    self.directory, self.state, producer, config_path,
                    hashlib.sha256(config_path.read_bytes()).hexdigest(),
                    "a" * 64, Path("/usr/bin/true"),
                )
        self.assertEqual(self.state["phase"], "planned")
        self.assertFalse(self.fake.group_exists)

    def test_local_prepare_rejects_id_bytes_without_reviewed_build_proof(self):
        source = {
            "phase": "prepared", "local_platform_boot": True,
            "location": "northeurope", "vm_size": "Standard_D2s_v5",
            "image_sha256": "a" * 64, "efi_sha256": None,
            "miz_executable": str(Path(sys.executable).resolve()),
            "miz_executable_sha256": lane.digest(Path(sys.executable).resolve()),
            "acceptance": {"mode": "raw-dhcp"},
            "local_platform_boot_modes": {
                "raw": {"x2apic": True, "legacy-apic": True},
                "vhd": {"x2apic": True, "legacy-apic": True},
            },
        }
        producer = self.directory / "producer"
        producer.mkdir(mode=0o700)
        efi = producer / "BOOTX64.EFI"
        efi.write_bytes(
            b"synthetic guest topology IDs: "
            + b" ".join(identity.encode("ascii") for identity in (
                self.state["run_id"], *self.state["disk_ids"].values()
            ))
        )
        source["efi_sha256"] = hashlib.sha256(efi.read_bytes()).hexdigest()
        image = producer / "unikraft.vhd"
        with image.open("xb") as output:
            output.truncate(lane.azure.VIRTUAL_SIZE + 512)
        raw = producer / "unikraft.raw"
        with raw.open("xb") as output:
            output.truncate(lane.azure.VIRTUAL_SIZE)
        source["raw_sha256"] = lane.digest(raw)
        for kind in ("raw", "vpc"):
            for mode in ("x2apic", "legacy-apic"):
                (producer / f"local-{kind}-{mode}-serial.log").write_text(
                    "UK_HYPERV_PLATFORM_READY\n"
                    "HYPERV_TOPOLOGY FINAL UNAVAILABLE reason=no-devices\n"
                    "HYPERV_TOPOLOGY RESULT UNAVAILABLE\n"
                )
        config = self.directory / "topology.config"
        config.write_text("\n".join((
            "CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY=y",
            "CONFIG_LIBSTORVSC_LUN_DISCOVERY=y",
            "CONFIG_LIBSTORVSC_MAX_DEVICES=3",
            "CONFIG_LIBSTORVSC_MAX_LUNS=2",
            f'CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID="{self.state["run_id"]}"',
            f'CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID="{self.state["disk_ids"]["data0"]}"',
            f'CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID="{self.state["disk_ids"]["data7"]}"',
            f"CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS={lane.SECTORS}",
            f"CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS={lane.SECTORS}",
            "CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN=7",
        )))
        report = lane.azure.packaging_contract(
            source["efi_sha256"], lane.azure.VIRTUAL_SIZE + 512
        )
        real_digest = lane.digest

        def image_digest(path):
            return "a" * 64 if Path(path) == image else real_digest(path)

        self.state["phase"] = "planned"
        with mock.patch.object(lane.azure, "load_state", return_value=(
            source, producer / "state.json"
        )), mock.patch.object(lane.azure, "validate_local_boot_log",
                             return_value={"io_ready": False, "crashes": []}), mock.patch.object(
            lane.azure, "miz_command", return_value=report
        ), mock.patch.object(lane, "digest", side_effect=image_digest):
            legacy_log = producer / "local-vpc-legacy-apic-serial.log"
            original_log = legacy_log.read_bytes()
            legacy_log.unlink()
            with self.assertRaisesRegex(ValueError, "Local topology serial"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
            legacy_log.write_bytes(original_log)
            source["local_platform_boot_modes"]["raw"]["legacy-apic"] = False
            with self.assertRaisesRegex(ValueError, "locally booted"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
            source["local_platform_boot_modes"]["raw"]["legacy-apic"] = True
            original_efi = efi.read_bytes()
            efi.write_bytes(b"public fixture run and disk IDs, not this run")
            source["efi_sha256"] = hashlib.sha256(efi.read_bytes()).hexdigest()
            report["boot-file-sha256"] = source["efi_sha256"]
            with self.assertRaisesRegex(ValueError, "build provenance is unavailable"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
            efi.write_bytes(original_efi)
            source["efi_sha256"] = hashlib.sha256(original_efi).hexdigest()
            report["boot-file-sha256"] = source["efi_sha256"]
            source["miz_executable_sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "Miz checker differs"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
            source["miz_executable_sha256"] = lane.digest(Path(sys.executable).resolve())
            with self.assertRaisesRegex(ValueError, "build provenance is unavailable"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
            with raw.open("r+b") as output:
                output.write(b"tampered")
            source["raw_sha256"] = lane.digest(raw)
            with self.assertRaisesRegex(ValueError, "different guest bytes"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
            source["raw_sha256"] = "1" * 64
            with self.assertRaisesRegex(ValueError, "raw/fixed-VHD pair changed"):
                lane.prepare(
                    self.directory, self.state, producer, config,
                    hashlib.sha256(config.read_bytes()).hexdigest(), "a" * 64,
                    Path(sys.executable),
                )
        self.assertEqual(self.state["phase"], "planned")
        self.assertFalse((self.directory / "solved.config").exists())
        self.assertEqual(lane.load(self.directory)["prepared"]["implementation"],
                         {"synthetic": "e" * 64})
        self.assertFalse(self.fake.group_exists)

    def test_seed_copies_have_distinct_fresh_ids_and_identical_mirrors(self):
        for role in lane.LUNS:
            (self.directory / f"{role}.vhd").unlink()

        def sparse_fingerprint(path):
            path = Path(path)
            if path.suffix != ".vhd":
                return hashlib.sha256(path.read_bytes()).hexdigest()
            with path.open("rb") as source:
                source.seek(8 * 512)
                seed = source.read(1024)
                source.seek(lane.DISK_BYTES)
                footer = source.read(512)
            return hashlib.sha256(seed + footer).hexdigest()

        with mock.patch.object(lane, "digest", side_effect=sparse_fingerprint):
            proofs = {role: lane.create_seed(self.directory, self.state, role)
                      for role in lane.LUNS}
            self.state["prepared"]["seeds"] = proofs
            for role in lane.LUNS:
                lane.verify_seed(self.directory, self.state, role)
            self.assertNotEqual(proofs["data0"]["sha256"], proofs["data7"]["sha256"])
            for role in lane.LUNS:
                manifest = json.loads((self.directory / f"{role}-seed.json").read_text())
                self.assertEqual(manifest["version"], 2)
                self.assertEqual(manifest["identity_policy"], "seed-enrollment-v2")
                self.assertEqual(manifest["run_id"], self.state["run_id"])
                self.assertEqual(manifest["disk_id"], self.state["disk_ids"][role])
                self.assertEqual(manifest["lun"], lane.LUNS[role])
                sector = seed_producer.manifest(
                    bytes.fromhex(self.state["run_id"]),
                    bytes.fromhex(self.state["disk_ids"][role]),
                    lane.SECTORS, 2, 0, 0, lane.LUNS[role],
                )
                with (self.directory / f"{role}.vhd").open("rb") as disk:
                    disk.seek(8 * 512)
                    self.assertEqual(disk.read(1024), sector * 2)
                    disk.seek(lane.DISK_BYTES)
                    self.assertEqual(
                        disk.read(512),
                        seed_producer.fixed_vhd_footer(
                            lane.SECTORS, bytes.fromhex(self.state["disk_ids"][role])
                        ),
                    )
            with (self.directory / "data0.vhd").open("r+b") as disk:
                disk.seek(lane.DISK_BYTES)
                footer = bytearray(disk.read(512))
                footer[28:32] = b"UK90"
                footer[64:68] = b"\0" * 4
                footer[64:68] = ((~sum(footer)) & 0xffffffff).to_bytes(4, "big")
                disk.seek(lane.DISK_BYTES)
                disk.write(footer)
            self.state["prepared"]["seeds"]["data0"]["sha256"] = sparse_fingerprint(
                self.directory / "data0.vhd"
            )
            with self.assertRaisesRegex(ValueError, "official VHD footer"):
                lane.verify_seed(self.directory, self.state, "data0")
            manifest_path = self.directory / "data0-seed.json"
            manifest = json.loads(manifest_path.read_text())
            del manifest["identity_policy_version"]
            manifest_path.write_text(json.dumps(manifest))
            self.state["prepared"]["seeds"]["data0"]["manifest_sha256"] = (
                sparse_fingerprint(manifest_path)
            )
            with self.assertRaisesRegex(ValueError, "manifest changed"):
                lane.verify_seed(self.directory, self.state, "data0")
            with (self.directory / "data7.vhd").open("r+b") as disk:
                disk.seek(9 * 512)
                disk.write(b"tampered")
            with self.assertRaisesRegex(ValueError, "changed"):
                lane.verify_seed(self.directory, self.state, "data7")
        for role in lane.LUNS:
            (self.directory / f"{role}.vhd").unlink()
            (self.directory / f"{role}-seed.json").unlink()

    def test_serial_requires_three_unique_read_only_devices_and_exact_seed(self):
        proof = lane.parse_serial(serial(self.state), self.state)
        self.assertEqual(proof["controller_count"], 1)
        self.assertEqual(proof["observed_devices"], 3)
        self.assertEqual(proof["skipped_device_ids"], [])
        self.assertEqual(set(proof["guest_devices"]), {"os", "data0", "data7"})
        for changed in (
            serial(self.state).replace("address=0:0:7", "address=0:0:6"),
            serial(self.state).replace(f"sectors={lane.SECTORS}",
                                       f"sectors={lane.SECTORS - 1}"),
            serial(self.state).replace("DATA_READ PASS role=1", "DATA_READ PASS role=0"),
            serial(self.state).replace("main returned 0", "main returned 1"),
            serial(self.state).replace("UK_HYPERV_PLATFORM_READY", "other"),
            serial(self.state) + f"run={self.state['run_id']}\n",
            serial(self.state) + (
                f"run={self.state['run_id'][:16]}\x1b[31m"
                f"{self.state['run_id'][16:]}\n"
            ),
            serial(self.state) + "secret=https://example.invalid/disk?sig=abc\n",
            serial(self.state) + "HYPERV_TOPOLOGY RESULT FAIL\n",
        ):
            with self.subTest(changed=changed[-200:]):
                with self.assertRaises(ValueError):
                    lane.parse_serial(changed, self.state)
        noisy = serial(self.state) + "UEFI non-topology line\n"
        lane.parse_serial(noisy, self.state)
        self.assertNotIn("UEFI non-topology line", lane.redacted_serial(noisy))
        self.assertEqual(lane.redacted_serial(noisy), serial(self.state))

    def test_extra_host_disk_is_skipped_but_counted_not_accepted_as_data(self):
        extra = (
            "HYPERV_TOPOLOGY TARGET INFO id=13 controller=1 channel=9 "
            "address=0:0:0 sectors=33554432 sector_size=512 "
            "instance_crc32=12345678 vpd_length=0 vpd_crc32=00000000\n"
            "HYPERV_TOPOLOGY TARGET SKIP id=13 reason=outside-seeded-geometry\n"
        )
        text = serial(self.state).replace(
            "HYPERV_TOPOLOGY FINAL PASS",
            extra + "HYPERV_TOPOLOGY FINAL PASS",
        ).replace("FINAL PASS devices=3", "FINAL PASS devices=4")
        proof = lane.parse_serial(text, self.state)
        self.assertEqual(proof["observed_devices"], 4)
        self.assertEqual(proof["observed_controller_count"], 2)
        self.assertEqual(proof["controller_count"], 1)
        self.assertEqual(proof["skipped_device_ids"], [13])
        for invalid in (
            text.replace("FINAL PASS devices=4", "FINAL PASS devices=3"),
            text.replace("TARGET SKIP id=13", "TARGET SKIP id=11"),
            text.replace(
                "HYPERV_TOPOLOGY TARGET SKIP id=13 reason=outside-seeded-geometry\n",
                "",
            ),
        ):
            with self.subTest(invalid=invalid[-200:]):
                with self.assertRaises(ValueError):
                    lane.parse_serial(invalid, self.state)

    def test_missing_output_fails_before_any_acceptance_or_deletion(self):
        self.fake.tamper = ("output-missing", "data7")
        self._run_refused()

    def test_foreign_output_fails_before_any_acceptance_or_deletion(self):
        self.fake.tamper = ("output-foreign", "data7")
        self._run_refused()

    def test_missing_vm_uuid_output_fails_before_any_acceptance_or_deletion(self):
        self.fake.tamper = ("output-uuid-missing", "vm")
        self._run_refused()

    def test_wrong_vm_uuid_output_type_fails_before_any_acceptance_or_deletion(self):
        self.fake.tamper = ("output-uuid-type", "vm")
        self._run_refused()

    def test_missing_arm_mode_fails_before_any_acceptance_or_deletion(self):
        self.fake.tamper = ("deployment-mode-missing", "deployment")
        self._run_refused()

    def test_missing_arm_parameter_type_fails_before_any_acceptance_or_deletion(self):
        self.fake.tamper = ("deployment-parameter-missing", "deployment")
        self._run_refused()

    def test_wrong_lun_refuses_cleanup(self):
        self.fake.tamper = ("vm-lun", "data7")
        self._run_refused()

    def test_replaced_vm_uuid_refuses_cleanup(self):
        self.fake.tamper = ("vm-uuid", "vm")
        self._run_refused()

    def test_missing_pinned_security_profile_refuses_acceptance_and_deletion(self):
        self.fake.tamper = ("security-missing", "pinned")
        self._run_refused()
        self.assertIn(("resource", "show", "--ids"), self.fake.calls)

    def test_forged_pinned_security_profile_refuses_acceptance_and_deletion(self):
        self.fake.tamper = ("security-forged", "pinned")
        self._run_refused()

    def test_unexpected_pinned_security_settings_refuse_deletion(self):
        self.fake.tamper = ("security-extra", "pinned")
        self._run_refused()

    def test_security_change_after_acceptance_refuses_deletion_and_receipt(self):
        self.fake.tamper = ("security-on-cleanup", "pinned")
        self._run_refused()
        self.assertGreaterEqual(self.fake.pinned_reads, 3)
        self.assertEqual(lane.load(self.directory)["evidence"]["result"], "PASS")

    def test_pinned_security_resource_must_bind_original_vm_and_os_disk(self):
        disk_proofs = {
            role: {"id": lane.resource_id(self.state, role),
                   "uuid": self.fake.disk_uuids[role]}
            for role in lane.ROLES
        }
        proof = {
            "id": lane.resource_id(self.state, "vm"),
            "uuid": self.fake.vm_uuid, "disks": disk_proofs,
        }
        for tamper in ("security-uuid", "security-os-disk", "security-nic",
                       "security-operation", "security-type"):
            with self.subTest(tamper=tamper):
                self.fake.tamper = (tamper, "pinned")
                with mock.patch.object(
                    lane.azure, "azure_cli", side_effect=self.fake.az
                ):
                    with self.assertRaises((RuntimeError, ValueError)):
                        lane.TopologyRun(self.state, self.directory).verify_vm_security(
                            proof, cleanup=True
                        )
        self.assertFalse(self.fake.deleted)

    def test_missing_vm_show_profile_needs_explicit_pinned_standard(self):
        self.fake.tamper = ("security-missing", "vm-show")
        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4]:
            receipt = lane.run(self.directory, self.state["subscription"],
                               lane.envelope_sha(self.state))
        self.assertEqual(receipt["result"], "PASS")
        self.assertIn(("resource", "show", "--ids"), self.fake.calls)
        self.assertTrue(self.fake.deleted)

    def test_replaced_arm_correlation_refuses_cleanup(self):
        self.fake.tamper = ("correlation-replaced", "deployment")
        self._run_refused()

    def test_replaced_disk_uuid_refuses_cleanup(self):
        self.fake.tamper = ("disk-uuid", "data7")
        self._run_refused()

    def test_wrong_disk_size_refuses_cleanup(self):
        self.fake.tamper = ("disk-size", "data0")
        self._run_refused()

    def test_missing_disk_size_refuses_cleanup(self):
        self.fake.tamper = ("disk-size-missing", "data0")
        self._run_refused()

    def test_missing_disk_uuid_refuses_cleanup(self):
        self.fake.tamper = ("disk-uuid-missing", "data0")
        self._run_refused()

    def test_upload_proof_requires_exact_size_option_and_generation(self):
        for tamper in ("disk-upload-size", "disk-upload-option", "disk-gib",
                       "disk-generation"):
            with self.subTest(tamper=tamper):
                role = "os" if tamper == "disk-generation" else "data7"
                self.fake.tamper = (tamper, role)
                with self.assertRaises(RuntimeError):
                    lane.TopologyRun(self.state, self.directory).validate_disk_response(
                        role, self.fake.disk(role)
                    )
        self.fake.tamper = None
        for role in lane.ROLES:
            self.assertEqual(lane.TopologyRun(self.state, self.directory)
                             .validate_disk_response(role, self.fake.disk(role)),
                             self.fake.disk_uuids[role])

    def test_os_disk_must_attach_original_not_create_from_image(self):
        self.fake.tamper = ("vm-os-create", "vm")
        self._run_refused()

    def test_os_disk_must_detach_on_vm_deletion(self):
        self.fake.tamper = ("vm-os-delete", "vm")
        self._run_refused()

    def test_data_disk_must_not_enable_write_cache(self):
        self.fake.tamper = ("vm-data-cache", "vm")
        self._run_refused()

    def test_nic_must_delete_with_vm(self):
        self.fake.tamper = ("vm-nic-delete", "vm")
        self._run_refused()

    def test_pinned_os_disk_delete_option_must_remain_detach(self):
        self.fake.tamper = ("security-os-delete", "pinned")
        self._run_refused()

    def test_public_ip_refuses_acceptance_and_cleanup(self):
        self.fake.tamper = ("network-public", "nic")
        self._run_refused()

    def test_default_outbound_refuses_acceptance_and_cleanup(self):
        self.fake.tamper = ("network-outbound", "vnet")
        self._run_refused()

    def test_cross_group_nat_gateway_refuses_acceptance_and_cleanup(self):
        self.fake.tamper = ("network-nat", "vnet")
        self._run_refused()

    def test_unredacted_serial_refuses_receipt_and_discards_raw_log(self):
        self.fake.serial_noise = f"run={self.state['run_id']}\n"
        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4]:
            with self.assertRaisesRegex(RuntimeError, "cleanup completed"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        self.assertTrue(self.fake.deleted)
        self.assertFalse((self.directory / "acceptance.json").exists())
        self.assertFalse((self.directory / "guest-serial.log").exists())

    def test_foreign_disk_tags_refuse_cleanup(self):
        self.fake.tamper = ("disk-owner", "data0")
        self._run_refused()

    def test_foreign_resource_inventory_refuses_cleanup(self):
        self.fake.tamper = ("inventory", "foreign")
        self._run_refused()

    def test_missing_original_disk_refuses_cleanup(self):
        self.fake.tamper = ("inventory", "missing")
        self._run_refused()

    def _patch_cloud(self):
        return (
            mock.patch.object(lane, "verify_inputs"),
            mock.patch.object(lane.azure, "check_upload_dependencies"),
            mock.patch.object(lane.TopologyRun, "preflight_cloud"),
            mock.patch.object(lane.azure, "azure_cli", side_effect=self.fake.az),
            mock.patch.object(lane.azure, "upload_managed_vhd"),
        )

    def _run_refused(self):
        with (self._patch_cloud()[0], self._patch_cloud()[1],
              self._patch_cloud()[2], self._patch_cloud()[3],
              self._patch_cloud()[4]):
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        self.assertFalse(self.fake.deleted)
        self.assertFalse((self.directory / "acceptance.json").exists())
        self.assertEqual(lane.load(self.directory)["phase"], "cleanup-failed")

    def _missing_create_response(self, stage, role, *, hidden_group=False):
        self.fake.missing_response = (stage, role)
        self.fake.group_hidden_after_lost_response = hidden_group
        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4]:
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.cleanup_state(self.directory)
        recorded = lane.load(self.directory)
        self.assertEqual(recorded["phase"], "cleanup-failed")
        self.assertIn("manual owner verification required", recorded["cleanup_error"])
        self.assertEqual(recorded["pending_create"], {"kind": stage, "role": role})
        self.assertEqual(self.fake.group_exists, not hidden_group)
        self.assertFalse(self.fake.deleted)
        self.assertFalse((self.directory / "acceptance.json").exists())
        self.assertNotIn(("group", "delete", "--name"), self.fake.calls)
        return recorded

    def test_os_create_timeout_does_not_adopt_current_uuid_even_with_owned_tags(self):
        recorded = self._missing_create_response("disk", "os")
        self.assertEqual(recorded.get("disks", {}), {})
        self.assertEqual(self.fake.created, ["os"])

    def test_group_create_timeout_cannot_adopt_matching_recreated_group(self):
        self.fake.replace_after_lost_response = True
        original_incarnation = self.fake.group_incarnation
        original_response = self.fake.resource("group")
        recorded = self._missing_create_response("group", "group")
        self.assertNotIn("resource_group_id", recorded)
        self.assertEqual(self.fake.created, [])
        self.assertNotEqual(self.fake.group_incarnation, original_incarnation)
        self.assertEqual(self.fake.resource("group"), original_response)

    def _hidden_group_remains_unresolved(self, stage, role):
        self._missing_create_response(stage, role, hidden_group=True)
        self.fake.group_exists = True
        with mock.patch.object(lane.azure, "azure_cli", side_effect=self.fake.az):
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.cleanup_state(self.directory)
        self.assertFalse(self.fake.deleted)
        self.assertEqual(lane.load(self.directory)["phase"], "cleanup-failed")
        self.assertNotIn(("group", "delete", "--name"), self.fake.calls)

    def test_lost_group_response_with_invisible_in_flight_group_stays_pending(self):
        self._hidden_group_remains_unresolved("group", "group")

    def test_lost_disk_response_with_invisible_group_stays_pending(self):
        self._hidden_group_remains_unresolved("disk", "os")

    def test_lost_deployment_response_with_invisible_group_stays_pending(self):
        self._hidden_group_remains_unresolved("deployment", "vm")

    def test_previously_cleaned_state_with_unresolved_create_is_not_skipped(self):
        self.state["phase"] = "cleaned"
        self.state["pending_create"] = {"kind": "group", "role": "group"}
        lane.save(self.directory, self.state)
        with mock.patch.object(lane.azure, "azure_cli") as cli:
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.cleanup_state(self.directory)
        cli.assert_not_called()
        self.assertEqual(lane.load(self.directory)["phase"], "cleanup-failed")

    def test_same_name_and_tags_cannot_prove_recreated_group_without_disk_receipts(self):
        self.state["phase"] = "group-created"
        self.state["resource_group_id"] = lane.group_id(self.state)
        lane.save(self.directory, self.state)
        self.fake.group_exists = True
        with mock.patch.object(lane.azure, "azure_cli", side_effect=self.fake.az):
            with self.assertRaisesRegex(RuntimeError, "immutable group instance"):
                lane.cleanup_state(self.directory)
        self.assertFalse(self.fake.deleted)
        self.assertEqual(lane.load(self.directory)["phase"], "cleanup-failed")

    def test_temporarily_invisible_created_group_cannot_be_marked_cleaned(self):
        self.state["phase"] = "group-created"
        self.state["resource_group_id"] = lane.group_id(self.state)
        lane.save(self.directory, self.state)
        with mock.patch.object(lane.azure, "azure_cli", side_effect=self.fake.az):
            with self.assertRaisesRegex(RuntimeError, "delayed visibility"):
                lane.cleanup_state(self.directory)
        self.assertFalse(self.fake.deleted)
        self.assertEqual(lane.load(self.directory)["phase"], "cleanup-failed")

    def test_legacy_cleaned_group_without_deletion_observation_is_not_skipped(self):
        self.state["phase"] = "cleaned"
        self.state["resource_group_id"] = lane.group_id(self.state)
        lane.save(self.directory, self.state)
        with mock.patch.object(lane.azure, "azure_cli", side_effect=self.fake.az):
            with self.assertRaisesRegex(RuntimeError, "delayed visibility"):
                lane.cleanup_state(self.directory)
        self.assertFalse(self.fake.deleted)
        self.assertEqual(lane.load(self.directory)["phase"], "cleanup-failed")

    def test_data0_create_timeout_preserves_original_os_proof_but_refuses_adoption(self):
        recorded = self._missing_create_response("disk", "data0")
        self.assertEqual(set(recorded["disks"]), {"os"})
        self.assertEqual(self.fake.created, ["os", "data0"])

    def test_data7_create_timeout_preserves_prior_proofs_but_refuses_adoption(self):
        recorded = self._missing_create_response("disk", "data7")
        self.assertEqual(set(recorded["disks"]), {"os", "data0"})
        self.assertEqual(self.fake.created, ["os", "data0", "data7"])

    def test_deployment_create_timeout_cannot_infer_original_vm_or_correlation(self):
        self.fake.replace_after_lost_response = True
        original_correlation, original_vm = self.fake.correlation, self.fake.vm_uuid
        recorded = self._missing_create_response("deployment", "vm")
        self.assertEqual(set(recorded["disks"]), set(lane.ROLES))
        self.assertNotIn("vm", recorded)
        self.assertTrue(self.fake.deployed)
        self.assertNotEqual(self.fake.correlation, original_correlation)
        self.assertNotEqual(self.fake.vm_uuid, original_vm)
        self.assertEqual(self.fake.deployment()["name"], self.state["prefix"])

    def test_disk_create_timeout_with_replaced_current_resource_remains_refused(self):
        self.fake.replace_after_lost_response = True
        original_uuid = self.fake.disk_uuids["os"]
        self._missing_create_response("disk", "os")
        self.assertNotEqual(self.fake.disk_uuids["os"], original_uuid)
        self.assertEqual(self.fake.disk("os")["tags"], lane.tags(self.state, "os"))

    def test_invisible_in_flight_create_does_not_make_empty_inventory_safe(self):
        self.fake.tamper = ("inventory", "not-yet-visible")
        self._missing_create_response("disk", "os")

    def test_invisible_in_flight_deployment_cannot_be_safely_adopted(self):
        self.fake.tamper = ("inventory", "not-yet-visible")
        self._missing_create_response("deployment", "vm")

    def _failed_create_receipt(self, phase, stage, role):
        original_save = lane.save

        def fail_receipt(directory, state):
            if state["phase"] == phase:
                raise OSError("synthetic durable receipt write failed")
            original_save(directory, state)

        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4], mock.patch.object(
            lane, "save", side_effect=fail_receipt
        ):
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        recorded = lane.load(self.directory)
        self.assertEqual(recorded["pending_create"], {"kind": stage, "role": role})
        self.assertTrue(self.fake.group_exists)
        self.assertFalse(self.fake.deleted)
        self.assertFalse((self.directory / "acceptance.json").exists())
        with mock.patch.object(lane.azure, "azure_cli", side_effect=self.fake.az):
            with self.assertRaisesRegex(RuntimeError, "manual owner verification required"):
                lane.cleanup_state(self.directory)
        self.assertNotIn(("group", "delete", "--name"), self.fake.calls)
        return recorded

    def test_failed_group_receipt_write_keeps_create_intent_for_cleanup(self):
        recorded = self._failed_create_receipt("group-created", "group", "group")
        self.assertNotIn("resource_group_id", recorded)
        self.assertEqual(recorded.get("disks", {}), {})

    def test_failed_immutable_disk_receipt_write_keeps_create_intent_for_cleanup(self):
        recorded = self._failed_create_receipt("uploading-os", "disk", "os")
        self.assertEqual(recorded.get("disks", {}), {})

    def test_failed_deployment_receipt_write_keeps_create_intent_for_cleanup(self):
        recorded = self._failed_create_receipt("vm-created", "deployment", "vm")
        self.assertTrue(self.fake.deployed)
        self.assertNotIn("vm", recorded)
        self.assertEqual(set(recorded["disks"]), set(lane.ROLES))

    def test_failed_group_intent_write_makes_no_group_create_call(self):
        original_save = lane.save

        def fail_intent(directory, state):
            if state["phase"] == "creating-group":
                raise OSError("synthetic durable intent write failed")
            original_save(directory, state)

        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4], mock.patch.object(
            lane, "save", side_effect=fail_intent
        ):
            with self.assertRaisesRegex(RuntimeError, "cleanup completed"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        self.assertNotIn(("group", "create"), self.fake.calls)
        self.assertFalse(self.fake.group_exists)
        self.assertEqual(lane.load(self.directory)["phase"], "cleaned")

    def test_proven_os_disk_upload_failure_can_still_delete_exact_owned_inventory(self):
        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], mock.patch.object(
            lane.azure, "upload_managed_vhd", side_effect=RuntimeError("upload failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "cleanup completed"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        self.assertEqual(set(lane.load(self.directory)["disks"]), {"os"})
        self.assertTrue(self.fake.deleted)
        self.assertFalse((self.directory / "acceptance.json").exists())

    def test_proven_deployment_vm_read_timeout_recovers_from_saved_correlation(self):
        self.fake.fail_vm_show_once = True
        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4]:
            with self.assertRaisesRegex(RuntimeError, "cleanup completed"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        self.assertEqual(lane.load(self.directory)["phase"], "cleaned")
        self.assertTrue(self.fake.deleted)
        self.assertFalse((self.directory / "acceptance.json").exists())

    def test_success_has_one_boot_and_complete_owner_checked_deletion(self):
        self.fake.serial_noise = "UEFI non-topology diagnostic\n"
        checks = self._patch_cloud()
        with checks[0], checks[1], checks[2], checks[3], checks[4]:
            receipt = lane.run(self.directory, self.state["subscription"],
                               lane.envelope_sha(self.state))
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(receipt["cleanup"], "complete")
        self.assertEqual(receipt["boot_count"], 1)
        self.assertTrue(self.fake.deleted)
        self.assertEqual(lane.load(self.directory)["phase"], "cleaned")
        self.assertIs(lane.load(self.directory)["group_deletion_observed"], True)
        with mock.patch.object(lane.azure, "azure_cli") as cli:
            lane.cleanup_state(self.directory)
        cli.assert_not_called()
        self.assertTrue((self.directory / "acceptance.json").exists())
        self.assertEqual((self.directory / "guest-serial.log").read_text(),
                         serial(self.state))
        self.assertEqual(receipt["evidence"]["serial_sha256"],
                         hashlib.sha256(
                             (serial(self.state) + self.fake.serial_noise).encode()
                         ).hexdigest())

    def test_wrong_approval_or_preflight_cannot_create_group(self):
        with self.assertRaisesRegex(ValueError, "approval"):
            lane.run(self.directory, self.state["subscription"], "0" * 64)
        with mock.patch.object(lane, "verify_inputs"), mock.patch.object(
            lane.azure, "check_upload_dependencies"
        ), mock.patch.object(lane.TopologyRun, "preflight_cloud",
                             side_effect=RuntimeError("quota")):
            with self.assertRaisesRegex(RuntimeError, "quota"):
                lane.run(self.directory, self.state["subscription"],
                         lane.envelope_sha(self.state))
        self.assertFalse(self.fake.group_exists)
        self.assertEqual(lane.load(self.directory)["phase"], "prepared")


if __name__ == "__main__":
    unittest.main()
