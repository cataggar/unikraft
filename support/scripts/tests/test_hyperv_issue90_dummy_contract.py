# SPDX-License-Identifier: BSD-3-Clause
"""Offline dummy-OS ARM shape, not proof of disk generation or a settled swap."""

from copy import deepcopy
import json
from pathlib import Path
import unittest


AZURE = Path(__file__).resolve().parents[2] / "azure"
ORIGINAL = AZURE / "hyperv-issue90-topology.json"
CANDIDATE = AZURE / "hyperv-issue90-dummy-topology.json"
CHILD_TYPES = {
    "nsg": "Microsoft.Network/networkSecurityGroups",
    "vnet": "Microsoft.Network/virtualNetworks",
    "nic": "Microsoft.Network/networkInterfaces",
    "vm": "Microsoft.Compute/virtualMachines",
}
DUMMY_ID = "[parameters('dummyDiskId')]"
DUMMY_NAME = "[last(split(parameters('dummyDiskId'), '/'))]"
MISSING = object()
PIN_NAMES = (
    "provenanceSha256", "configSha256", "efiSha256", "rawSha256",
    "mizSha256", "imageSha256", "dummyImageSha256",
    "seed0Sha256", "seed7Sha256",
)
DISK_IDS = ("dummyDiskId", "osDiskId", "dataDisk0Id", "dataDisk7Id")
DISK_UUIDS = (
    "dummyOsDiskUuid", "acceptanceOsDiskUuid",
    "dataDisk0Uuid", "dataDisk7Uuid",
)
PARAMETER_BOUNDS = {
    "namePrefix": (6, 32),
    "runId": (32, 32),
    "operationId": (36, 36),
    "reviewedHead": (40, 40),
    **{name: (64, 64) for name in PIN_NAMES},
    **{name: (1, 512) for name in DISK_IDS},
    **{name: (36, 36) for name in DISK_UUIDS},
}
EXTRA_TAGS = {
    "reviewed-head": "reviewedHead",
    "provenance-sha256": "provenanceSha256",
    "config-sha256": "configSha256",
    "efi-sha256": "efiSha256",
    "raw-sha256": "rawSha256",
    "miz-sha256": "mizSha256",
    "dummy-image-sha256": "dummyImageSha256",
    "dummy-os-uuid": "dummyOsDiskUuid",
    "acceptance-os-uuid": "acceptanceOsDiskUuid",
    "data0-uuid": "dataDisk0Uuid",
    "data7-uuid": "dataDisk7Uuid",
}


def _deny_rule(direction):
    return {
        "name": f"DenyAll{direction}",
        "properties": {
            "priority": 4095 if direction == "Inbound" else 4096,
            "access": "Deny",
            "direction": direction,
            "protocol": "*",
            "sourceAddressPrefix": "*",
            "sourcePortRange": "*",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*",
        },
    }


DENY_RULES = [_deny_rule("Inbound"), _deny_rule("Outbound")]


def _read(path):
    if path.stat().st_size > 64 * 1024:
        raise ValueError(f"{path.name} exceeds the offline template limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path.name} has duplicate JSON key {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def _require(condition, label):
    if not condition:
        raise ValueError(f"Dummy ARM contract: {label}")


def _field(value, *path):
    for name in path:
        if not isinstance(value, dict) or name not in value:
            raise ValueError(f"Dummy ARM contract: missing {'.'.join(path)}")
        value = value[name]
    return value


def _roles(resources):
    _require(isinstance(resources, list) and len(resources) == len(CHILD_TYPES),
             "exactly four ARM-created VM/network children, no disks or public IP")
    _require(all(isinstance(item, dict) for item in resources),
             "malformed ARM-created child")
    types = [item.get("type") for item in resources]
    _require(all(isinstance(kind, str) for kind in types)
             and set(types) == set(CHILD_TYPES.values())
             and len(set(types)) == len(types),
             "ARM-created children inventory differs")
    return {role: next(item for item in resources if item["type"] == kind)
            for role, kind in CHILD_TYPES.items()}


def _dummy_spec(legacy):
    spec = deepcopy(legacy)
    spec["parameters"].update({
        name: {"type": "string", "minLength": lower, "maxLength": upper}
        for name, (lower, upper) in PARAMETER_BOUNDS.items()
    })
    spec["variables"]["tags"].update({
        tag: f"[parameters('{name}')]"
        for tag, name in EXTRA_TAGS.items()
    })
    resources = _roles(spec["resources"])
    resources["nsg"]["properties"]["securityRules"] = deepcopy(DENY_RULES)
    vm = resources["vm"]
    disk = vm["properties"]["storageProfile"]["osDisk"]
    disk["name"] = DUMMY_NAME
    disk["managedDisk"]["id"] = DUMMY_ID
    spec["outputs"]["osDiskId"]["value"] = DUMMY_ID
    return spec


def check_dummy_contract(template, legacy):
    spec = _dummy_spec(legacy)
    _require(isinstance(template, dict)
             and template.get("$schema") == legacy["$schema"]
             and template.get("contentVersion") == legacy["contentVersion"],
             "pinned ARM schema and content version")
    parameters = _field(template, "parameters")
    _require(isinstance(parameters, dict)
             and set(parameters) == set(spec["parameters"]),
             "all 22 dummyDiskId/dummyImageSha256, reviewed source/build, disk "
             "UUID, final OS and run/operation parameters")
    _require(parameters == spec["parameters"],
             "exact bounded source/build, run, disk ID/UUID and digest parameter "
             "declarations")
    _require(_field(template, "variables", "tags") == spec["variables"]["tags"]
             and template["variables"] == spec["variables"],
             "exact run/operation, source/build, image and disk UUID tag expressions")

    actual = _roles(_field(template, "resources"))
    baseline = _roles(legacy["resources"])
    _require(actual["nsg"] == _roles(spec["resources"])["nsg"],
             "nsg needs exact priority-4095/4096 inbound/outbound wildcard Deny, "
             "no custom Allow or extra rules")
    for role in ("vnet", "nic"):
        _require(actual[role] == baseline[role],
                 f"approved private {role} (no public IP/default outbound)")

    vm = actual["vm"]
    expected_vm = _roles(spec["resources"])["vm"]
    _require({key: value for key, value in vm.items() if key != "properties"}
             == {key: value for key, value in expected_vm.items()
                 if key != "properties"},
             "VM name/API version/tags/NIC dependency or extra ARM children")
    props = _field(vm, "properties")
    _require(_field(props, "hardwareProfile") == {"vmSize": "Standard_D2s_v5"},
             "approved VM size")
    _require(_field(props, "securityProfile") == {"securityType": "Standard"},
             "explicit Standard VM security profile")
    _require(_field(props, "networkProfile")
             == expected_vm["properties"]["networkProfile"],
             "single attached approved private NIC")
    _require(_field(props, "diagnosticsProfile")
             == expected_vm["properties"]["diagnosticsProfile"],
             "approved boot diagnostics")
    storage = _field(props, "storageProfile")
    _require(isinstance(storage, dict)
             and set(storage) == {"diskControllerType", "osDisk", "dataDisks"}
             and storage["diskControllerType"] == "SCSI",
             "SCSI storage without an unreviewed image or disk")
    _require(storage["osDisk"]
             == expected_vm["properties"]["storageProfile"]["osDisk"],
             "dummy OS Attach/Linux/ReadOnly/Detach, never original final OS")
    _require(storage["dataDisks"]
             == expected_vm["properties"]["storageProfile"]["dataDisks"],
             "two original attached data disks at exactly LUN 0 and LUN 7")
    _require(props == expected_vm["properties"],
             "unreviewed VM properties or nested resources")

    outputs = _field(template, "outputs")
    _require(isinstance(outputs, dict)
             and set(outputs) == set(spec["outputs"]),
             "VM UUID and exactly four child IDs plus dummy OS/data disk outputs")
    _require(outputs == spec["outputs"],
             "original deployment outputs must name dummy OS, not final OS")
    _require(set(template) == set(spec), "unexpected top-level ARM behavior")


def _change(template, path, value):
    target = template
    for name in path[:-1]:
        target = target[name]
    if value is MISSING:
        del target[path[-1]]
    else:
        target[path[-1]] = value


class DummyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = _read(ORIGINAL)

    def setUp(self):
        self.template = _dummy_spec(self.original)

    def refuse(self, path, value, reason):
        _change(self.template, path, value)
        with self.assertRaisesRegex(ValueError, reason):
            check_dummy_contract(self.template, self.original)

    def test_existing_final_os_template_is_not_a_dummy_candidate(self):
        with self.assertRaisesRegex(ValueError, "dummyDiskId/dummyImageSha256"):
            check_dummy_contract(self.original, self.original)
        self.refuse(
            ("resources", 3, "properties", "storageProfile", "osDisk",
             "managedDisk", "id"),
            "[parameters('osDiskId')]", "dummy OS",
        )

    def test_synthetic_reviewed_dummy_candidate_satisfies_offline_contract(self):
        check_dummy_contract(self.template, self.original)

    def test_separately_owned_candidate_when_integrated(self):
        if not CANDIDATE.exists():
            self.skipTest(
                f"Candidate required at {CANDIDATE.relative_to(AZURE.parent.parent)}; "
                "add the reviewed 22 bounded parameters and tag bindings; "
                "attach only dummyDiskId, keep osDiskId for the separate final OS"
            )
        check_dummy_contract(_read(CANDIDATE), self.original)

    def test_missing_or_wrong_dummy_and_authorization_parameters_refuse(self):
        for path, value, reason in (
            (("parameters", "dummyDiskId"), MISSING, "dummyDiskId"),
            (("parameters", "dummyImageSha256"), MISSING, "dummyDiskId"),
            (("parameters", "runId"), MISSING, "run/operation"),
            (("parameters", "operationId"), MISSING, "run/operation"),
            (("parameters", "osDiskId"), MISSING, "dummyDiskId"),
            (("variables", "tags", "dummy-image-sha256"),
             "[parameters('imageSha256')]", "tag expressions"),
            (("variables", "tags", "issue90-run"), "foreign", "tag expressions"),
            (("variables", "tags", "issue90-operation"),
             "[parameters('runId')]", "tag expressions"),
            (("resources", 3, "tags"), "[variables('tags')]", "VM name"),
            (("resources", 3, "properties", "storageProfile", "osDisk",
              "name"), "[last(split(parameters('osDiskId'), '/'))]", "dummy OS"),
            (("outputs", "osDiskId", "value"),
             "[parameters('osDiskId')]", "deployment outputs"),
        ):
            with self.subTest(path=path):
                self.template = _dummy_spec(self.original)
                self.refuse(path, value, reason)

    def test_each_reviewed_extension_is_bounded_and_its_tag_is_pinned(self):
        for name in (*PARAMETER_BOUNDS, "location"):
            with self.subTest(missing_parameter=name):
                self.template = _dummy_spec(self.original)
                self.refuse(("parameters", name), MISSING, "parameters")
        for name, (lower, upper) in PARAMETER_BOUNDS.items():
            for field, value in (
                ("type", "int"),
                ("minLength", lower - 1),
                ("maxLength", upper + 1),
            ):
                with self.subTest(parameter=name, field=field):
                    self.template = _dummy_spec(self.original)
                    self.refuse(("parameters", name, field), value,
                                "parameter declarations")
        for tag, name in EXTRA_TAGS.items():
            for value in (MISSING, "[parameters('runId')]"):
                with self.subTest(tag=tag, replacement=value):
                    self.template = _dummy_spec(self.original)
                    self.refuse(("variables", "tags", tag), value, "tag expressions")
        self.template = _dummy_spec(self.original)
        self.refuse(("parameters", "unreviewedExtra"), {"type": "string"},
                    "parameters")

    def test_outputs_and_children_exclude_unowned_or_extra_arm_resources(self):
        for name in ("vmUuid", "vmId", "osDiskId", "dataDisk7Id", "nicId", "vnetId",
                     "nsgId"):
            with self.subTest(output=name):
                self.template = _dummy_spec(self.original)
                self.refuse(("outputs", name), MISSING, "outputs|VM UUID")
        for kind in CHILD_TYPES.values():
            with self.subTest(child=kind):
                self.template = _dummy_spec(self.original)
                self.template["resources"] = [
                    r for r in self.template["resources"] if r["type"] != kind
                ]
                with self.assertRaisesRegex(ValueError, "four ARM-created"):
                    check_dummy_contract(self.template, self.original)
        for kind in ("Microsoft.Compute/disks", "Microsoft.Network/publicIPAddresses"):
            with self.subTest(extra=kind):
                self.template = _dummy_spec(self.original)
                self.template["resources"].append({"type": kind, "name": "unowned"})
                with self.assertRaisesRegex(ValueError, "no disks or public IP"):
                    check_dummy_contract(self.template, self.original)
        self.template = _dummy_spec(self.original)
        self.refuse(("outputs", "finalOsDiskId"),
                    {"type": "string", "value": "[parameters('osDiskId')]"},
                    "outputs")

    def test_private_network_never_accepts_public_or_default_egress(self):
        for path, value, reason in (
            (("resources", 0, "properties", "securityRules"),
             [{"name": "AllowInternet", "properties": {"direction": "Inbound",
                                                         "access": "Allow"}}], "nsg"),
            (("resources", 1, "properties", "subnets", 0,
              "properties", "defaultOutboundAccess"), True, "vnet"),
            (("resources", 1, "properties", "subnets", 0,
              "properties", "defaultOutboundAccess"), MISSING, "vnet"),
            (("resources", 1, "properties", "subnets", 0,
              "properties", "natGateway"), {"id": "public"}, "vnet"),
            (("resources", 1, "properties", "subnets", 0,
              "properties", "networkSecurityGroup"), MISSING, "vnet"),
            (("resources", 2, "properties", "ipConfigurations", 0,
              "properties", "publicIPAddress"), {"id": "public"}, "nic"),
            (("resources", 2, "properties", "enableIPForwarding"), True, "nic"),
            (("resources", 3, "properties", "networkProfile", "networkInterfaces"),
             [], "private NIC"),
        ):
            with self.subTest(path=path):
                self.template = _dummy_spec(self.original)
                self.refuse(path, value, reason)

    def test_nsg_overrides_default_vnet_and_internet_allows_without_exceptions(self):
        for direction in ("Inbound", "Outbound"):
            with self.subTest(missing=direction):
                self.template = _dummy_spec(self.original)
                rules = self.template["resources"][0]["properties"]["securityRules"]
                rules[:] = [rule for rule in rules
                            if rule["properties"]["direction"] != direction]
                with self.assertRaisesRegex(ValueError, "nsg needs exact"):
                    check_dummy_contract(self.template, self.original)
            for field, value in (
                ("access", "Allow"),
                ("direction", "Outbound" if direction == "Inbound" else "Inbound"),
                ("priority", 65000),
                ("priority", 100),
                ("sourceAddressPrefix", "VirtualNetwork"),
                ("destinationAddressPrefix", "10.90.0.0/29"),
                ("sourcePortRange", "1024"),
                ("destinationPortRange", "443"),
                ("protocol", "Tcp"),
            ):
                with self.subTest(direction=direction, field=field, value=value):
                    self.template = _dummy_spec(self.original)
                    index = 0 if direction == "Inbound" else 1
                    self.refuse(
                        ("resources", 0, "properties", "securityRules", index,
                         "properties", field),
                        value, "nsg needs exact",
                    )
        for additional in (
            _deny_rule("Inbound"),
            {
                "name": "allow-platform-dns",
                "properties": {
                    **_deny_rule("Outbound")["properties"],
                    "priority": 99,
                    "access": "Allow",
                    "destinationAddressPrefix": "AzurePlatformDNS",
                },
            },
        ):
            with self.subTest(extra_rule=additional["name"]):
                self.template = _dummy_spec(self.original)
                self.template["resources"][0]["properties"]["securityRules"].append(
                    additional
                )
                with self.assertRaisesRegex(ValueError, "no custom Allow or extra"):
                    check_dummy_contract(self.template, self.original)
        self.template = _dummy_spec(self.original)
        self.refuse(("resources", 0, "properties", "securityRules"), [], "nsg needs exact")

    def test_gen2_compatible_standard_scsi_and_exact_luns(self):
        for path, value, reason in (
            (("resources", 3, "apiVersion"), "2024-07-01", "VM name/API"),
            (("resources", 3, "properties", "hardwareProfile", "vmSize"),
             "Standard_A1", "VM size"),
            (("resources", 3, "properties", "securityProfile", "securityType"),
             "TrustedLaunch", "Standard"),
            (("resources", 3, "properties", "storageProfile", "diskControllerType"),
             "NVMe", "SCSI"),
            (("resources", 3, "properties", "storageProfile", "osDisk", "osType"),
             "Windows", "dummy OS"),
            (("resources", 3, "properties", "storageProfile", "osDisk",
              "createOption"), "FromImage", "dummy OS"),
            (("resources", 3, "properties", "storageProfile", "osDisk",
              "deleteOption"), "Delete", "dummy OS"),
            (("resources", 3, "properties", "storageProfile", "dataDisks", 1,
              "lun"), 1, "LUN 0 and LUN 7"),
            (("resources", 3, "properties", "storageProfile", "dataDisks", 0,
              "managedDisk", "id"), DUMMY_ID, "LUN 0 and LUN 7"),
            (("resources", 3, "properties", "storageProfile", "dataDisks"),
             [], "LUN 0 and LUN 7"),
        ):
            with self.subTest(path=path):
                self.template = _dummy_spec(self.original)
                self.refuse(path, value, reason)


if __name__ == "__main__":
    unittest.main()
