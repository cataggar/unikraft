# SPDX-License-Identifier: BSD-3-Clause

from contextlib import contextmanager
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SUPPORT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SUPPORT / "scripts"))
preflight = importlib.import_module("hyperv_private_preflight")
runner = importlib.import_module("hyperv_private_preflight_runner")
TEST_TEMP = SUPPORT.parent / ".d" / "private-preflight-test-tmp"
TEST_TEMP.mkdir(mode=0o700, parents=True, exist_ok=True)
tempfile.tempdir = str(TEST_TEMP)


class PrivatePreflightFixture(unittest.TestCase):
    def manifest(self, **changes):
        raw_size = preflight.azure.VIRTUAL_SIZE
        sizes = {
            "qemu": 1024 * 1024,
            "ovmf_code": 2 * 1024 * 1024,
            "ovmf_vars": 2 * 1024 * 1024,
            "capability_raw": raw_size,
            "efi": 1024 * 1024,
            "raw": raw_size,
            "vhd": raw_size + 512,
        }
        files = {
            role: {
                "name": preflight.INPUT_NAMES[role],
                "sha256": "0123456"[index] * 64,
                "size": sizes[role],
            }
            for index, role in enumerate(preflight.ALL_ROLES)
        }
        value = {
            "schema": preflight.INPUT_SCHEMA,
            "schema_version": 1,
            "boot_policy": "platform-unavailable-v1",
            "raw_size": raw_size,
            "source": {
                "config_sha256": "8" * 64,
                "source_sha256": "9" * 64,
            },
            "files": files,
            "miz": {
                "name": "miz",
                "revision": preflight.azure.MIZ_REVISION,
                "sha256": "f" * 64,
                "size": 1024 * 1024,
            },
            "packaging": preflight.azure.packaging_contract(
                files["efi"]["sha256"], files["vhd"]["size"]
            ),
        }
        value.update(changes)
        return value

    def state(self):
        manifest = preflight.validate_input_manifest(self.manifest())
        return {
            "schema": preflight.STATE_SCHEMA,
            "schema_version": 1,
            "phase": "prepared",
            "identity": "1" * 32,
            "name_prefix": "uk-hvp-123456789abc",
            "location": preflight.LOCATION,
            "vm_size": preflight.VM_SIZE,
            "image_sha256": manifest["files"]["vhd"]["sha256"],
            "manifest_sha256": "2" * 64,
            "controller_sha256": preflight.azure.image_sha256(
                Path(preflight.__file__)
            ),
            "runner_sha256": preflight.azure.image_sha256(
                preflight.RUNNER_PATH
            ),
            "template_sha256": preflight.azure.image_sha256(
                preflight.TEMPLATE_PATH
            ),
            "input_manifest": manifest,
            "cleanup_required": False,
        }

    def cloud_state(self):
        state = self.state()
        state.update({
            "phase": "cloud-preflight-complete",
            "subscription": "11111111-2222-3333-4444-555555555555",
            "cloud_preflight": {
                "image": {
                    "publisher": "Canonical",
                    "offer": "ubuntu-24_04-lts",
                    "sku": "server",
                    "version": "24.04.202609010",
                    "hyperv_generation": "V2",
                },
            },
            "deadline_monotonic": 10**18,
            "deadline_utc": "2026-09-09T05:26:00Z",
            "cleanup_required": True,
            "storage_account": "ukhvp1234567890abcd",
            "resource_group_id": (
                "/subscriptions/11111111-2222-3333-4444-555555555555/"
                "resourceGroups/uk-hvp-123456789abc-rg"
            ),
        })
        return state


class PrivatePreflightManifestTest(PrivatePreflightFixture):
    def test_strict_manifest_binds_build_tools_images_and_size_cap(self):
        manifest = preflight.validate_input_manifest(self.manifest())
        self.assertEqual(manifest["raw_size"], preflight.azure.VIRTUAL_SIZE)
        self.assertLessEqual(
            manifest["staged_bytes"] + preflight.MAX_EVIDENCE_BYTES,
            256 * 1024 * 1024,
        )
        self.assertEqual(
            manifest["packaging"]["boot-file-sha256"],
            manifest["files"]["efi"]["sha256"],
        )

    def test_manifest_rejects_unknown_fields_bool_sizes_and_oversize(self):
        variants = []
        unknown = self.manifest()
        unknown["private_path"] = "/secret"
        variants.append(unknown)
        boolean = self.manifest()
        boolean["files"]["raw"]["size"] = True
        variants.append(boolean)
        oversized = self.manifest()
        oversized["files"]["qemu"]["size"] = 60 * 1024 * 1024
        variants.append(oversized)
        bad_policy = self.manifest(boot_policy="accept-any-failure")
        variants.append(bad_policy)
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    preflight.validate_input_manifest(value)

    def test_input_directory_rejects_extra_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            manifest = self.manifest()
            manifest_bytes = json.dumps(manifest).encode()
            (root / preflight.INPUT_MANIFEST).write_bytes(manifest_bytes)
            for name in preflight.INPUT_NAMES.values():
                (root / name).write_bytes(b"x")
            (root / "private.log").write_text("not allowed")
            with self.assertRaisesRegex(ValueError, "extra or missing"):
                preflight.load_input_manifest(
                    root, hashlib.sha256(manifest_bytes).hexdigest()
                )
            (root / "private.log").unlink()
            linked = root.parent / (root.name + "-linked")
            linked.symlink_to(root, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    preflight.load_input_manifest(
                        linked, hashlib.sha256(manifest_bytes).hexdigest()
                    )
            finally:
                linked.unlink()

    def test_transfer_source_is_explicit_single_public_ipv4(self):
        self.assertEqual(preflight.transfer_source("8.8.8.8"), "8.8.8.8/32")
        self.assertEqual(
            preflight.transfer_source("8.8.4.4/32"), "8.8.4.4/32"
        )
        for value in (
            "10.0.0.1", "127.0.0.1", "192.0.2.1",
            "8.8.8.0/24", "latest", None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    preflight.transfer_source(value)

    def test_deadline_timeout_never_extends_an_expired_attempt(self):
        with mock.patch.object(preflight.time, "monotonic", return_value=101):
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                preflight.bounded_timeout(100, 300)

    def test_private_state_cannot_enable_existing_group_adoption(self):
        state = self.state()
        state.update({
            "group_precreated": True,
            "resource_group": "foreign-group",
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight.azure.save_json(root / preflight.STATE_FILE, state)
            with self.assertRaisesRegex(ValueError, "cannot adopt"):
                preflight.load_state(root)

    def test_host_manifests_bind_capability_before_private_phase(self):
        state = self.state()
        capability = preflight.host_phase_manifest(state, "capability")
        capability_digest = hashlib.sha256(
            preflight.azure.canonical_json(capability)
        ).hexdigest()
        private = preflight.host_phase_manifest(
            state, "private", capability_digest
        )
        self.assertEqual(
            private["capability_manifest_sha256"], capability_digest
        )
        self.assertEqual(
            set(capability["files"]), set(preflight.PUBLIC_ROLES)
        )
        self.assertNotIn("capability_raw", private["files"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                runner.RunnerError, "capability-not-complete"
            ):
                runner.execute_phase(
                    "private", private,
                    preflight.azure.canonical_json(private),
                    "https://abc.blob.core.windows.net",
                    preflight.CONTAINER, "sv=fixture", root,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / state["identity"]
            run_root.mkdir(mode=0o700)
            runner.write_durable(
                run_root / "capability.complete",
                (json.dumps({
                    "identity": state["identity"],
                    "manifest_sha256": capability_digest,
                    "result": "PASS",
                    "host_boot_id": (
                        "11111111-1111-4111-8111-111111111111"
                    ),
                }, sort_keys=True) + "\n").encode(),
            )
            with mock.patch.object(
                runner, "host_boot_id",
                return_value="22222222-2222-4222-8222-222222222222",
            ), self.assertRaisesRegex(
                runner.RunnerError, "capability-state-mismatch"
            ):
                runner.execute_phase(
                    "private", private,
                    preflight.azure.canonical_json(private),
                    "https://abc.blob.core.windows.net",
                    preflight.CONTAINER, "sv=fixture", root,
                )


class PrivatePreflightRunnerTest(PrivatePreflightFixture):
    @staticmethod
    def boot_log(main_return=2, legacy=False, extra=""):
        lines = [
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:",
            "Powered by",
            "Calling main(",
            runner.PLATFORM_MARKER,
            runner.UNAVAILABLE_MARKER,
        ]
        if legacy:
            lines.append(runner.LEGACY_APIC_MARKER)
        if extra:
            lines.append(extra)
        lines.append(
            "[    0.100000] Info: [libukboot] "
            f"<boot.c @  523> main returned {main_return}"
        )
        return "\n".join(lines)

    def test_strict_no_device_policy_is_not_arbitrary_failure_success(self):
        runner.validate_boot_log(
            self.boot_log(), "platform-unavailable-v1", False
        )
        runner.validate_boot_log(
            self.boot_log(legacy=True), "platform-unavailable-v1", True
        )
        for text in (
            self.boot_log(extra="HYPERV_ACCEPTANCE STORAGE_READ FAIL reason=io"),
            self.boot_log(extra="UK_HYPERV_IO_READY"),
            self.boot_log(extra="UK_HYPERV_BLOCK_READ_OK"),
            self.boot_log(extra="HYPERV_STORAGE WRITE PASS bytes=512"),
            self.boot_log(main_return=0),
            self.boot_log(extra=runner.UNAVAILABLE_MARKER),
            self.boot_log(
                extra="diagnostic: expected main returned 2 but continued"
            ),
        ):
            with self.subTest(text=text[-100:]):
                with self.assertRaises(runner.RunnerError):
                    runner.validate_boot_log(
                        text, "platform-unavailable-v1", False
                    )

    def test_qemu_command_uses_kvm_hyperv_footer_mask_and_no_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qemu = root / "qemu"
            code = root / "code"
            variables = root / "vars"
            image = root / "image"
            for path in (qemu, code, variables, image):
                path.write_bytes(b"x")
            captured = {}

            def execute(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                kwargs["stdout"].write(self.boot_log().encode())
                return mock.Mock(returncode=0)

            with mock.patch.object(
                runner.subprocess, "run", side_effect=execute
            ):
                result, _ = runner.run_boot(
                    qemu, code, variables, image,
                    preflight.azure.VIRTUAL_SIZE,
                    "platform-unavailable-v1", "raw-x2apic", False, root,
                )
            self.assertEqual(result["result"], "PASS")
            command = captured["command"]
            self.assertEqual(
                command[command.index("-machine") + 1], "q35,accel=kvm"
            )
            cpu = command[command.index("-cpu") + 1]
            for feature in ("hv-synic", "hv-stimer", "hv-vpindex", "hv-runtime"):
                self.assertIn(feature, cpu)
            self.assertNotIn("x2apic=off", cpu)
            self.assertIn("vmbus-bridge,irq=15", command)
            self.assertEqual(command[-2:], ["-nic", "none"])
            disk = json.loads(command[command.index("-blockdev") + 1])
            self.assertEqual(disk["size"], preflight.azure.VIRTUAL_SIZE)
            self.assertTrue(disk["read-only"])
            self.assertEqual(captured["kwargs"]["timeout"], 120)

    def test_runner_manifest_requires_exact_integer_fields(self):
        state = self.state()
        manifest = preflight.host_phase_manifest(state, "capability")
        for field, value in (
            ("schema_version", True), ("raw_size", float(manifest["raw_size"])),
        ):
            changed = json.loads(json.dumps(manifest))
            changed[field] = value
            encoded = base64_encode(changed)
            with self.assertRaises(runner.RunnerError):
                runner.parse_manifest(encoded, "capability")
        changed = json.loads(json.dumps(manifest))
        changed["files"]["qemu"]["blob"] = (
            "inputs/" + state["identity"] + "/public/foreign-qemu"
        )
        with self.assertRaisesRegex(runner.RunnerError, "invalid-file-binding"):
            runner.parse_manifest(base64_encode(changed), "capability")

    def test_runner_download_detects_one_byte_overrun_without_writing_it(self):
        class Response:
            status = 200

            def __init__(self):
                self.returned = False

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, _size):
                if self.returned:
                    return b""
                self.returned = True
                return b"abcd"

        record = {
            "blob": "inputs/" + "1" * 32 + "/public/qemu-system-x86_64",
            "name": "qemu-system-x86_64",
            "sha256": hashlib.sha256(b"abc").hexdigest(),
            "size": 3,
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            runner.urllib.request, "urlopen", return_value=Response()
        ):
            destination = Path(temporary) / "qemu"
            with self.assertRaisesRegex(
                runner.RunnerError, "download-size-mismatch"
            ):
                runner.download_file(
                    "https://ukhvp123.blob.core.windows.net",
                    "preflight", record, "sv=private", destination,
                )
            self.assertFalse(destination.exists())


def base64_encode(value):
    import base64
    return base64.b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).decode()


class PrivatePreflightTemplateTest(PrivatePreflightFixture):
    def test_arm_template_is_one_private_bounded_standard_host(self):
        template = json.loads(preflight.TEMPLATE_PATH.read_text())
        resources = template["resources"]
        kinds = [resource["type"] for resource in resources]
        self.assertEqual(
            kinds.count("Microsoft.Compute/virtualMachines"), 1
        )
        self.assertNotIn("Microsoft.Network/publicIPAddresses", kinds)
        self.assertNotIn("Microsoft.Network/natGateways", kinds)
        vm = next(
            resource for resource in resources
            if resource["type"] == "Microsoft.Compute/virtualMachines"
        )
        properties = vm["properties"]
        self.assertEqual(
            properties["hardwareProfile"]["vmSize"], "Standard_D2s_v5"
        )
        self.assertEqual(
            properties["securityProfile"], {"securityType": "Standard"}
        )
        os_disk = properties["storageProfile"]["osDisk"]
        self.assertEqual(os_disk["diskSizeGB"], 32)
        self.assertEqual(
            os_disk["managedDisk"]["storageAccountType"], "StandardSSD_LRS"
        )
        self.assertEqual(properties["storageProfile"]["dataDisks"], [])
        self.assertTrue(
            properties["diagnosticsProfile"]["bootDiagnostics"]["enabled"]
        )
        vnet = next(
            resource for resource in resources
            if resource["type"] == "Microsoft.Network/virtualNetworks"
        )
        subnet = vnet["properties"]["subnets"][0]["properties"]
        self.assertIs(subnet["defaultOutboundAccess"], False)
        self.assertEqual(
            subnet["serviceEndpoints"],
            [{"service": "Microsoft.Storage", "locations": ["northeurope"]}],
        )
        storage = next(
            resource for resource in resources
            if resource["type"] == "Microsoft.Storage/storageAccounts"
        )
        self.assertEqual(storage["apiVersion"], "2023-05-01")
        self.assertIs(storage["properties"]["allowBlobPublicAccess"], False)
        self.assertEqual(
            storage["properties"]["networkAcls"]["defaultAction"], "Deny"
        )
        self.assertEqual(
            storage["properties"]["networkAcls"]["bypass"], "None"
        )
        self.assertEqual(storage["properties"]["networkAcls"]["ipRules"], [])
        self.assertEqual(
            storage["properties"]["networkAcls"]["virtualNetworkRules"],
            [{"id": "[variables('subnetId')]", "action": "Allow"}],
        )
        nsg = next(
            resource for resource in resources
            if resource["type"] == "Microsoft.Network/networkSecurityGroups"
        )
        rules = nsg["properties"]["securityRules"]
        self.assertFalse(any(
            rule["properties"]["direction"] == "Inbound"
            and rule["properties"]["access"] == "Allow"
            for rule in rules
        ))
        self.assertEqual(
            {
                rule["properties"].get("destinationAddressPrefix")
                for rule in rules
                if rule["properties"]["access"] == "Allow"
            },
            {
                "AzurePlatformDNS", "AzurePlatformIMDS",
                "168.63.129.16", "Storage.NorthEurope",
            },
        )
        schedules = [
            resource for resource in resources
            if resource["type"] == "Microsoft.DevTestLab/schedules"
        ]
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0]["properties"]["status"], "Enabled")


class PrivatePreflightCloudTest(PrivatePreflightFixture):
    def run_fixture(self, root):
        state = self.cloud_state()
        path = root / "state.json"
        preflight.azure.save_json(path, state)
        run = preflight.PrivatePreflightRun(state, path)
        run.az = mock.Mock()
        run.record = mock.Mock(side_effect=lambda phase, **fields: state.update(
            phase=phase, **fields
        ))
        return run, state

    @mock.patch.object(preflight.azure, "resolve_peer_image")
    @mock.patch.object(preflight.azure, "exact_vm_sku")
    @mock.patch.object(preflight.azure, "azure_cli")
    @mock.patch.object(preflight.azure, "selected_account")
    def test_subscription_preflight_is_exact_and_has_no_retry(
        self, account, command, sku, image
    ):
        subscription = "11111111-2222-3333-4444-555555555555"
        account.return_value = subscription
        command.side_effect = [
            "Registered", "Registered", "Registered", "Registered",
            ["2025-11-01"],
            ["True"],
            [
                {"name": {"value": "cores"}, "limit": 8, "currentValue": 0},
                {
                    "name": {"value": "standardDSv5Family"},
                    "limit": 2, "currentValue": 0,
                },
            ],
        ]
        sku.return_value = {
            "name": preflight.VM_SIZE,
            "family": "standardDSv5Family",
            "vcpus": 2,
            "generations": ["V2"],
        }
        image.return_value = {
            "publisher": "Canonical", "offer": "ubuntu-24_04-lts",
            "sku": "server", "version": "24.04.202609010",
            "hyperv_generation": "V2",
        }
        result = preflight.check_subscription(subscription)
        self.assertEqual(result["image"]["version"], "24.04.202609010")
        account.assert_called_once_with(subscription)
        sku.assert_called_once_with(
            "northeurope", "Standard_D2s_v5", subscription,
            vcpus=2, require_v2=True,
        )
        image.assert_called_once_with("northeurope", subscription, ("V2",))
        self.assertEqual(command.call_count, 7)
        self.assertTrue(all(
            call.kwargs.get("private") is True
            and call.kwargs.get("subscription") == subscription
            for call in command.call_args_list
        ))

    @mock.patch.object(preflight.azure, "exact_vm_sku")
    @mock.patch.object(preflight.azure, "azure_cli")
    @mock.patch.object(preflight.azure, "selected_account")
    def test_subscription_preflight_rejects_missing_nested_capability(
        self, account, command, sku
    ):
        subscription = "11111111-2222-3333-4444-555555555555"
        account.return_value = subscription
        command.side_effect = [
            "Registered", "Registered", "Registered", "Registered",
            ["2025-11-01"], [],
        ]
        sku.return_value = {
            "name": preflight.VM_SIZE,
            "family": "standardDSv5Family",
            "vcpus": 2,
            "generations": ["V2"],
        }
        with self.assertRaisesRegex(RuntimeError, "nested virtualization"):
            preflight.check_subscription(subscription)

    def test_host_deployment_records_immutable_vm_and_disk_before_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            group = state["resource_group_id"]
            deployment_id = (
                group + "/providers/Microsoft.Resources/deployments/"
                + run.prefix + "-host"
            )
            vm_id = (
                group + "/providers/Microsoft.Compute/virtualMachines/"
                + run.host_vm
            )
            disk_id = (
                group + "/providers/Microsoft.Compute/disks/"
                + run.host_disk
            )
            image = state["cloud_preflight"]["image"]
            deployment = {
                "id": deployment_id, "name": run.prefix + "-host",
                "properties": {
                    "provisioningState": "Succeeded",
                    "correlationId": "33333333-3333-4333-8333-333333333333",
                },
            }
            vm = {
                "id": vm_id, "vmId": "44444444-4444-4444-8444-444444444444",
                "tags": run.tags, "provisioningState": "Succeeded",
                "hardwareProfile": {"vmSize": preflight.VM_SIZE},
                "securityProfile": {"securityType": "Standard"},
                "storageProfile": {
                    "imageReference": image,
                    "osDisk": {
                        "diskSizeGb": 32,
                        "managedDisk": {"id": disk_id},
                    },
                },
            }
            disk = {
                "id": disk_id,
                "uniqueId": "55555555-5555-4555-8555-555555555555",
                "managedBy": vm_id, "diskSizeGb": 32,
                "sku": {"name": "StandardSSD_LRS"}, "tags": run.tags,
            }
            nic = {
                "id": "/private/nic", "tags": run.tags,
                "ipConfigurations": [{
                    "publicIPAddress": None,
                    "privateIPAllocationMethod": "Static",
                    "privateIPAddress": "10.88.0.4",
                    "subnet": {"id": (
                        group
                        + "/providers/Microsoft.Network/virtualNetworks/"
                        + run.prefix + "-vnet/subnets/preflight"
                    )},
                }],
            }
            storage = {
                "id": (
                    group + "/providers/Microsoft.Storage/storageAccounts/"
                    + run.storage
                ),
                "tags": run.tags,
                "allowBlobPublicAccess": False,
                "allowSharedKeyAccess": True,
                "minimumTlsVersion": "TLS1_2",
                "publicNetworkAccess": "Enabled",
                "supportsHttpsTrafficOnly": True,
                "networkRuleSet": {"defaultAction": "Deny"},
            }
            schedule = {
                "id": "/private/schedule", "tags": run.tags,
                "properties": {
                    "status": "Enabled", "targetResourceId": vm_id,
                    "dailyRecurrence": {"time": "0526"},
                },
            }
            run.az.side_effect = [
                deployment, vm, disk, nic, storage, schedule,
            ]

            @contextmanager
            def parameters(values):
                self.assertNotIn(values["adminPassword"], str(values.keys()))
                yield Path("/owner-only/parameters.json")

            run.private_parameters = parameters
            with mock.patch.object(
                run, "deadline_timeout", return_value=900
            ):
                run.deploy_host("0526")
            self.assertEqual(
                state["host_deployment"]["disk_uuid"],
                "55555555-5555-4555-8555-555555555555",
            )
            command = run.az.call_args_list[0].args[0]
            self.assertEqual(command[:3], ["deployment", "group", "create"])
            self.assertNotIn("adminPassword", " ".join(command))

    def test_transfer_firewall_is_removed_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, _ = self.run_fixture(Path(temporary))
            events = []
            run.az.side_effect = lambda arguments, **_: events.append(
                arguments
            )
            run.verify_storage_rules = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "inside"):
                with run.transfer_access("8.8.8.8/32"):
                    raise RuntimeError("inside")
            self.assertEqual(
                [command[3] for command in events], ["add", "remove"]
            )
            self.assertEqual(
                run.verify_storage_rules.call_args_list,
                [
                    mock.call("8.8.8.8/32"),
                    mock.call(enforce_deadline=False),
                ],
            )

    def test_transfer_firewall_cleanup_runs_after_ambiguous_add(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, _ = self.run_fixture(Path(temporary))
            events = []

            def command(arguments, **_):
                events.append(arguments)
                if arguments[3] == "add":
                    raise RuntimeError("ambiguous add")

            run.az.side_effect = command
            run.verify_storage_rules = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "ambiguous add"):
                with run.transfer_access("8.8.8.8/32"):
                    self.fail("ambiguous add must not enter the transfer")
            self.assertEqual(
                [arguments[3] for arguments in events], ["add", "remove"]
            )
            run.verify_storage_rules.assert_called_once_with(
                enforce_deadline=False
            )

    def test_storage_firewall_requires_exact_private_subnet(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            subnet = (
                state["resource_group_id"]
                + "/providers/Microsoft.Network/virtualNetworks/"
                + run.prefix + "-vnet/subnets/preflight"
            )
            storage = {
                "tags": run.tags,
                "networkRuleSet": {
                    "defaultAction": "Deny",
                    "bypass": "None",
                    "ipRules": [],
                    "virtualNetworkRules": [{
                        "virtualNetworkResourceId": subnet,
                        "action": "Allow",
                        "state": "Succeeded",
                    }],
                },
            }
            run.az.return_value = storage
            run.verify_storage_rules()
            storage["networkRuleSet"]["virtualNetworkRules"][0][
                "virtualNetworkResourceId"
            ] = subnet + "-foreign"
            with self.assertRaisesRegex(RuntimeError, "subnet rule"):
                run.verify_storage_rules()

    def test_sas_intent_is_durable_and_revocation_rotates_the_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            first_key = "first-private-key"
            second_key = "second-private-key"
            run.az.side_effect = [
                [{"keyName": "key1", "value": first_key}],
                "sv=private",
                None,
                [{"keyName": "key1", "value": second_key}],
            ]
            token = run.generate_sas()
            self.assertIs(state["active_sas"], True)
            command = run.az.call_args_list[1].args[0]
            self.assertEqual(
                command[command.index("--permissions") + 1], "rcw"
            )
            self.assertNotIn(first_key, " ".join(command))
            self.assertEqual(
                run.az.call_args_list[1].kwargs["env"],
                {"AZURE_STORAGE_KEY": first_key},
            )
            run.revoke_sas(token)
            self.assertIs(state["active_sas"], False)
            self.assertEqual(
                run.az.call_args_list[2].args[0][-2:], ["--key", "primary"]
            )

    def test_failed_sas_issue_retains_revocation_obligation(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            run.az.side_effect = [
                [{"keyName": "key1", "value": "private-key"}],
                RuntimeError("generation failed"),
            ]
            with self.assertRaisesRegex(RuntimeError, "generation failed"):
                run.generate_sas()
            self.assertIs(state["active_sas"], True)
            self.assertRegex(
                state["active_sas_signing_key_sha256"], r"^[0-9a-f]{64}$"
            )

    def test_run_command_keeps_sas_out_of_arguments_and_requires_exact_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, state = self.run_fixture(root)
            state["host_vm_id"] = (
                state["resource_group_id"]
                + "/providers/Microsoft.Compute/virtualMachines/"
                + run.host_vm
            )
            manifest = preflight.host_phase_manifest(state, "capability")
            receipt = "6" * 64
            captured = {}

            def command(arguments, **_kwargs):
                captured["arguments"] = arguments
                request_path = Path(
                    arguments[arguments.index("--body") + 1][1:]
                )
                captured["request"] = request_path.read_text()
                return {"value": [{
                    "code": "ComponentStatus/StdOut/succeeded",
                    "message": "HYPERV_PRIVATE_PREFLIGHT " + json.dumps({
                        "schema": 1, "phase": "capability",
                        "result": "PASS", "identity": state["identity"],
                        "receipt_sha256": receipt, "boot_count": 2,
                    }),
                }]}

            run.az.side_effect = command
            run.run_host_phase("capability", manifest, "sv=private-secret")
            self.assertNotIn(
                "private-secret", " ".join(captured["arguments"])
            )
            self.assertIn("private-secret", captured["request"])
            self.assertFalse(any(
                path.name.startswith(".run-command-")
                for path in root.iterdir()
            ))
            self.assertEqual(state["capability_receipt_sha256"], receipt)
            run.az.side_effect = None
            run.az.return_value = {
                "value": [{
                    "code": "ComponentStatus/StdOut/succeeded",
                    "message": (
                        "HYPERV_PRIVATE_PREFLIGHT "
                        + json.dumps({
                            "schema": 1, "phase": "capability",
                            "result": "PASS", "identity": state["identity"],
                            "receipt_sha256": receipt, "boot_count": 2,
                        })
                        + "\nHYPERV_PRIVATE_PREFLIGHT "
                        + json.dumps({
                            "schema": 1, "phase": "capability",
                            "result": "PASS", "identity": state["identity"],
                            "receipt_sha256": receipt, "boot_count": 2,
                        })
                    ),
                }]
            }
            with self.assertRaisesRegex(RuntimeError, "duplicated"):
                run.run_host_phase(
                    "capability", manifest, "sv=private-secret"
                )

    def test_downloaded_receipt_must_match_run_command_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            manifest = preflight.host_phase_manifest(state, "capability")
            logs = {
                "capability-x2apic.log": b"x2apic\n",
                "capability-legacy-apic.log": b"legacy\n",
            }
            receipt = {
                "schema": preflight.HOST_EVIDENCE_SCHEMA,
                "schema_version": 1,
                "phase": "capability",
                "identity": state["identity"],
                "result": "PASS",
                "manifest_sha256": hashlib.sha256(
                    preflight.azure.canonical_json(manifest)
                ).hexdigest(),
                "runner_sha256": state["runner_sha256"],
                "host_boot_id": "66666666-6666-4666-8666-666666666666",
                "boot_policy": manifest["boot_policy"],
                "boots": {"capability": {
                    "x2apic": {
                        "result": "PASS",
                        "log_sha256": hashlib.sha256(
                            logs["capability-x2apic.log"]
                        ).hexdigest(),
                        "return_code": 0,
                    },
                    "legacy-apic": {
                        "result": "PASS",
                        "log_sha256": hashlib.sha256(
                            logs["capability-legacy-apic.log"]
                        ).hexdigest(),
                        "return_code": 0,
                    },
                }},
            }
            receipt_bytes = preflight.azure.canonical_json(receipt)
            state["capability_receipt_sha256"] = "0" * 64

            @contextmanager
            def access(_cidr):
                yield

            run.transfer_access = access
            with mock.patch.object(
                preflight, "download_blob_bytes",
                side_effect=[
                    receipt_bytes,
                    logs["capability-x2apic.log"],
                    logs["capability-legacy-apic.log"],
                ],
            ), self.assertRaisesRegex(ValueError, "RunCommand proof"):
                preflight.retrieve_phase_evidence(
                    run, "8.8.8.8/32", "sv=private",
                    "capability", manifest,
                )

    def test_cleanup_refuses_foreign_or_detached_implicit_host_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            group = {"id": state["resource_group_id"], "tags": run.group_tags}
            disk_id = run.expected_resource_id(
                "Microsoft.Compute", "disks", run.host_disk
            )
            foreign = {
                "id": disk_id, "name": run.host_disk,
                "type": "Microsoft.Compute/disks", "tags": None,
            }
            run.az.side_effect = [True, group, [foreign]]
            with self.assertRaisesRegex(RuntimeError, "unproven"):
                run.delete_owned_group()
            self.assertFalse(any(
                call.args[0][:2] == ["group", "delete"]
                for call in run.az.call_args_list
            ))

            vm_id = run.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", run.host_vm
            )
            state["host_deployment"] = {
                "deployment_id": run.expected_resource_id(
                    "Microsoft.Resources", "deployments",
                    run.prefix + "-host",
                ),
                "correlation_id": "33333333-3333-4333-8333-333333333333",
                "vm_id": vm_id,
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_id": disk_id,
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            }
            vm = {
                "id": vm_id, "vmId": state["host_deployment"]["vm_uuid"],
                "tags": run.tags,
                "storageProfile": {
                    "osDisk": {"managedDisk": {"id": disk_id}},
                },
            }
            detached = {
                **foreign,
                "uniqueId": state["host_deployment"]["disk_uuid"],
                "managedBy": None,
            }
            run.az.reset_mock()
            run.az.side_effect = [True, group, [foreign], vm, detached]
            with self.assertRaisesRegex(RuntimeError, "detached or replaced"):
                run.delete_owned_group()

    def test_cleanup_requires_the_explicit_bound_subscription(self):
        state = self.cloud_state()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            preflight, "load_state",
            return_value=(state, Path(temporary) / "state.json"),
        ):
            with self.assertRaisesRegex(ValueError, "does not match"):
                preflight.cleanup(
                    Path(temporary),
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                )

    def test_cleanup_accepts_only_proven_attached_untagged_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, state = self.run_fixture(Path(temporary))
            group = {"id": state["resource_group_id"], "tags": run.group_tags}
            vm_id = run.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", run.host_vm
            )
            disk_id = run.expected_resource_id(
                "Microsoft.Compute", "disks", run.host_disk
            )
            state["host_deployment"] = {
                "deployment_id": run.expected_resource_id(
                    "Microsoft.Resources", "deployments",
                    run.prefix + "-host",
                ),
                "correlation_id": "33333333-3333-4333-8333-333333333333",
                "vm_id": vm_id,
                "vm_uuid": "44444444-4444-4444-8444-444444444444",
                "disk_id": disk_id,
                "disk_uuid": "55555555-5555-4555-8555-555555555555",
            }
            resource = {
                "id": disk_id, "name": run.host_disk,
                "type": "Microsoft.Compute/disks", "tags": None,
            }
            vm = {
                "id": vm_id, "tags": run.tags,
                "vmId": state["host_deployment"]["vm_uuid"],
                "storageProfile": {"osDisk": {
                    "managedDisk": {"id": disk_id},
                }},
            }
            disk = {
                **resource,
                "uniqueId": state["host_deployment"]["disk_uuid"],
                "managedBy": vm_id,
            }
            run.az.side_effect = [
                True, group, [resource], vm, disk, None, False,
            ]
            run.delete_owned_group()
            self.assertTrue(any(
                call.args[0][:2] == ["group", "delete"]
                for call in run.az.call_args_list
            ))
            self.assertIs(state["cleanup_required"], False)

    def test_cleanup_attempts_group_delete_after_deallocation_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, _ = self.run_fixture(Path(temporary))
            run.deallocate_host = mock.Mock(
                side_effect=RuntimeError("deallocation failed")
            )
            run.delete_owned_group = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "did not complete"):
                run.cleanup()
            run.delete_owned_group.assert_called_once_with()

    @mock.patch.object(preflight.azure, "azure_cli")
    def test_all_lifecycle_cli_failures_are_private(self, command):
        state = self.cloud_state()
        with tempfile.TemporaryDirectory() as temporary:
            run = preflight.PrivatePreflightRun(
                state, Path(temporary) / "state.json"
            )
            command.side_effect = preflight.azure.AzureCliError(
                ["vm", "show"],
                mock.Mock(
                    returncode=1,
                    stderr=(
                        "failed /subscriptions/private/resourceGroups/private "
                        "?sig=private-secret"
                    ),
                ),
                True,
            )
            with self.assertRaises(preflight.azure.AzureCliError) as error:
                run.az(["vm", "show", "--ids", "/private/id"])
            self.assertNotIn("private-secret", str(error.exception))
            self.assertNotIn("/subscriptions/", str(error.exception))
            self.assertTrue(command.call_args.kwargs["private"])


class PrivatePreflightOrderingTest(PrivatePreflightFixture):
    def execute(self, capability_error=None):
        state = self.state()
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "state.json"
            fake = mock.Mock()
            fake.storage = "ukhvp1234567890abcd"
            fake.container = preflight.CONTAINER
            fake.state = state
            fake.state_path = state_path

            def record(phase, **fields):
                state.update(phase=phase, **fields)

            fake.record.side_effect = record
            fake.create_group.side_effect = lambda: events.append("group")
            fake.deploy_host.side_effect = lambda _: (
                events.append("host"),
                state.update(
                    host_vm_id="/private/vm",
                    host_deployment={
                        "vm_uuid": "4" * 32,
                        "disk_uuid": "5" * 32,
                    },
                ),
            )
            fake.verify_storage_rules.side_effect = lambda: events.append(
                "firewall-closed"
            )
            fake.generate_sas.side_effect = [
                {"value": "public-sas", "signing_key_sha256": "a" * 64},
                {"value": "private-sas", "signing_key_sha256": "b" * 64},
            ]
            fake.revoke_sas.side_effect = lambda token: events.append(
                "revoke-" + token["value"]
            )

            @contextmanager
            def access(_cidr):
                events.append("firewall-open")
                try:
                    yield
                finally:
                    events.append("firewall-remove")

            fake.transfer_access.side_effect = access

            def host_phase(phase, _manifest, _sas):
                events.append("run-" + phase)
                if phase == "capability" and capability_error is not None:
                    raise capability_error
                state[phase + "_receipt_sha256"] = (
                    "c" * 64 if phase == "capability" else "d" * 64
                )

            fake.run_host_phase.side_effect = host_phase
            fake.deallocate_host.side_effect = lambda: events.append(
                "deallocate"
            )
            fake.cleanup.side_effect = lambda: events.append("cleanup")

            def upload(_url, sas, _container, _files, **_kwargs):
                events.append(
                    "upload-public" if sas == "public-sas"
                    else "upload-private"
                )

            def retrieve(_run, _cidr, sas, phase, _manifest):
                events.append("retrieve-" + phase)
                return {
                    "host_boot_id": (
                        "66666666-6666-4666-8666-666666666666"
                    ),
                    "boots": {
                        "capability" if phase == "capability" else "raw": {},
                    },
                }

            cloud = {
                "subscription": "11111111-2222-3333-4444-555555555555",
                "sku": {},
                "image": {
                    "publisher": "Canonical",
                    "offer": "ubuntu-24_04-lts",
                    "sku": "server", "version": "24.04.202609010",
                    "hyperv_generation": "V2",
                },
            }
            with mock.patch.object(
                preflight, "load_state", return_value=(state, state_path)
            ), mock.patch.object(
                preflight, "verify_immutable_inputs"
            ), mock.patch.object(
                preflight, "check_blob_dependency"
            ), mock.patch.object(
                preflight, "transfer_source", return_value="8.8.8.8/32"
            ), mock.patch.object(
                preflight, "check_subscription", return_value=cloud
            ), mock.patch.object(
                preflight, "PrivatePreflightRun", return_value=fake
            ), mock.patch.object(
                preflight, "upload_blob_set", side_effect=upload
            ), mock.patch.object(
                preflight, "retrieve_phase_evidence", side_effect=retrieve
            ), mock.patch.object(
                preflight.azure, "save_durable_json"
            ), mock.patch.object(
                preflight.azure, "image_sha256", return_value="e" * 64
            ):
                if capability_error is not None:
                    with self.assertRaises(type(capability_error)):
                        preflight.run_preflight(
                            root, cloud["subscription"], "8.8.8.8"
                        )
                else:
                    preflight.run_preflight(
                        root, cloud["subscription"], "8.8.8.8"
                    )
        return events, state

    def test_capability_pass_precedes_any_private_upload(self):
        events, state = self.execute()
        self.assertLess(events.index("run-capability"), events.index("upload-private"))
        self.assertLess(
            events.index("retrieve-capability"), events.index("upload-private")
        )
        self.assertEqual(events[-1], "cleanup")
        self.assertIn("deallocate", events)
        self.assertIs(state["cleanup_required"], False)

    def test_capability_failure_or_cancellation_cleans_without_private_upload(self):
        for error in (
            RuntimeError("capability failed"),
            InterruptedError("cancelled"),
        ):
            with self.subTest(error=type(error).__name__):
                events, _ = self.execute(capability_error=error)
                self.assertNotIn("upload-private", events)
                self.assertEqual(events[-1], "cleanup")

    def test_cli_error_redacts_ids_secrets_and_paths(self):
        secret = (
            "/subscriptions/private/resourceGroups/private "
            "?sig=private-secret /owner/private/state"
        )
        output = io.StringIO()
        with mock.patch.object(
            preflight.sys, "argv",
            [
                "hyperv_private_preflight.py", "cleanup",
                "--state-dir", "/owner/private/state",
                "--subscription", "11111111-2222-3333-4444-555555555555",
            ],
        ), mock.patch.object(
            preflight, "cleanup", side_effect=RuntimeError(secret)
        ), mock.patch.object(preflight.sys, "stderr", output):
            with self.assertRaises(SystemExit) as stopped:
                preflight.main()
            print(stopped.exception, file=preflight.sys.stderr)
        message = output.getvalue()
        self.assertNotIn("private-secret", message)
        self.assertNotIn("/subscriptions/", message)
        self.assertNotIn("/owner/private", message)
        self.assertNotIn("Traceback", message)


if __name__ == "__main__":
    unittest.main()
