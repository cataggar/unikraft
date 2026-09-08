# SPDX-License-Identifier: BSD-3-Clause

import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

SUPPORT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SUPPORT / "scripts"))
azure = importlib.import_module("hyperv-azure")


class HypervAzurePackagingTest(unittest.TestCase):
    def report(self):
        return {
            "schema-version": 1, "contract": "miz.efi-application-image",
            "valid": True, "format": "vhd", "subformat": "fixed",
            "generation": 2, "virtual-size": azure.VIRTUAL_SIZE,
            "file-size": azure.VIRTUAL_SIZE + 512, "architecture": "x86_64",
            "boot-path": "EFI/BOOT/BOOTX64.EFI", "boot-file-sha256": "a" * 64,
            "esp-offset": azure.MIB, "esp-length": azure.ESP_SIZE,
        }

    def test_expected_miz_contract_is_accepted(self):
        azure.check_packaging_report(
            self.report(), "a" * 64, azure.VIRTUAL_SIZE + 512
        )

    def test_invalid_or_mismatched_packaging_is_rejected(self):
        for field, value in (
            ("valid", False), ("subformat", "dynamic"), ("generation", 1),
            ("architecture", "aarch64"), ("virtual-size", azure.VIRTUAL_SIZE + 1),
            ("boot-path", "EFI/BOOT/BOOTAA64.EFI"),
            ("boot-file-sha256", "b" * 64), ("schema-version", True),
        ):
            with self.subTest(field=field):
                report = self.report()
                report[field] = value
                with self.assertRaises(ValueError):
                    azure.check_packaging_report(
                        report, "a" * 64, azure.VIRTUAL_SIZE + 512
                    )

    def test_missing_field_or_incorrect_file_length_is_rejected(self):
        report = self.report()
        del report["esp-length"]
        with self.assertRaises(ValueError):
            azure.check_packaging_report(report, "a" * 64, azure.VIRTUAL_SIZE + 512)
        with self.assertRaises(ValueError):
            azure.check_packaging_report(self.report(), "a" * 64, azure.VIRTUAL_SIZE)


class HypervAzureControllerTest(unittest.TestCase):
    def run_fixture(self):
        run = azure.AzureRun({
            "name_prefix": "uk-hv-fixture",
            "image_sha256": "a" * 64,
            "subscription": "test-subscription",
            "location": "westus2",
            "vm_size": "Standard_D2s_v5",
            "platform_marker": azure.PLATFORM_READY,
        }, Path("/unused/state.json"))
        run.record = mock.Mock()
        run.az = mock.Mock()
        return run

    def disk_fixture(self, run):
        return {
            "id": "/test/disk",
            "tags": run.tags,
            "diskState": "Unattached",
            "provisioningState": "Succeeded",
            "hyperVGeneration": "V2",
            "osType": "Linux",
        }

    def test_existing_group_is_never_adopted(self):
        run = self.run_fixture()
        run.az.return_value = True
        with self.assertRaisesRegex(RuntimeError, "Refusing to adopt"):
            run.create_group()
        self.assertEqual(run.az.call_count, 1)

    def test_unowned_group_cannot_be_deleted(self):
        run = self.run_fixture()
        run.az.side_effect = [True, {"id": "/other/group", "tags": {}}]
        with self.assertRaisesRegex(RuntimeError, "ownership tags"):
            run.cleanup()
        self.assertEqual(run.az.call_count, 2)

    def test_unowned_resource_prevents_group_deletion(self):
        run = self.run_fixture()
        run.az.side_effect = [
            True, {"tags": run.tags}, [{"id": "/other/disk", "tags": {}}],
        ]
        with self.assertRaisesRegex(RuntimeError, "ownership tags"):
            run.cleanup()
        self.assertEqual(run.az.call_count, 3)

    def test_repeated_cleanup_of_absent_group_is_safe(self):
        run = self.run_fixture()
        run.az.return_value = False
        run.cleanup()
        run.record.assert_called_once_with("cleaned")

    def test_upload_failure_always_revokes_disk_access(self):
        run = self.run_fixture()
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.core.windows.net/path?sig=secret"},
            RuntimeError("upload failed"), None,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with self.assertRaisesRegex(RuntimeError, "upload failed"):
            run.upload_disk(image)
        self.assertEqual(run.az.call_args.args[0][:2], ["disk", "revoke-access"])
        upload = run.az.call_args_list[2]
        self.assertNotIn("secret", " ".join(upload.args[0]))
        self.assertEqual(upload.kwargs["env"]["AZURE_STORAGE_SAS_TOKEN"], "sig=secret")
        self.assertTrue(upload.kwargs["private"])

    def test_unimported_disk_cannot_advance_to_deployment(self):
        run = self.run_fixture()
        incomplete = self.disk_fixture(run)
        incomplete["diskState"] = "ReadyToUpload"
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.core.windows.net/path?sig=secret"},
            None, None, incomplete,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with self.assertRaisesRegex(RuntimeError, "successfully imported"):
            run.upload_disk(image)
        self.assertNotIn(mock.call("disk-ready"), run.record.call_args_list)

    def test_upload_rejects_non_azure_or_plaintext_endpoints(self):
        for endpoint in (
            "http://disk.blob.core.windows.net/path?sig=secret",
            "https://blob.core.windows.net.attacker.invalid/path?sig=secret",
            "https://user@disk.blob.core.windows.net/path?sig=secret",
            "https://disk.blob.core.windows.net/path",
            "https://md-partition.blob.storage.azure.net.attacker.invalid/path?sig=secret",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    azure.upload_endpoint(endpoint)

    def test_both_documented_managed_disk_hostname_families_are_supported(self):
        for host in (
            "md-impexp-disk.blob.core.windows.net",
            "md-diskpartition.blob.storage.azure.net",
            "md-impexp-disk.z43.blob.storage.azure.net",
        ):
            with self.subTest(host=host):
                endpoint, sas = azure.upload_endpoint(f"https://{host}/path?sig=secret")
                self.assertEqual(endpoint, f"https://{host}/path")
                self.assertEqual(sas, "sig=secret")

    @mock.patch.object(azure.subprocess, "run")
    def test_managed_serial_json_preserves_lines(self, execute):
        serial = "\n".join((
            azure.PLATFORM_READY, azure.BLOCK_READY,
            azure.NETWORK_READY, azure.IO_READY,
        )) + "\n"
        execute.return_value = mock.Mock(returncode=0, stdout=json.dumps(serial))
        text = azure.azure_cli(
            ["vm", "boot-diagnostics", "get-boot-log"], private=True
        )
        self.assertTrue(azure.inspect_boot_log(text)["io_ready"])
        command = execute.call_args.args[0]
        self.assertEqual(command[command.index("--output") + 1], "json")
        self.assertFalse(azure.inspect_boot_log(repr(serial.encode()))["io_ready"])

    @mock.patch.object(azure.subprocess, "run")
    def test_private_cli_error_does_not_print_credentials(self, execute):
        execute.return_value = mock.Mock(
            returncode=1, stderr="failed at ?sig=secret", stdout=""
        )
        with self.assertRaises(RuntimeError) as error:
            azure.azure_cli(["disk", "grant-access"], private=True)
        self.assertNotIn("secret", str(error.exception))

    @mock.patch.object(azure.subprocess, "run")
    def test_storage_upload_ignores_ambient_account_credentials(self, execute):
        execute.return_value = mock.Mock(returncode=0, stdout="null")
        with mock.patch.dict(azure.os.environ, {
            "AZURE_STORAGE_CONNECTION_STRING": "unrelated-account",
            "AZURE_STORAGE_KEY": "unrelated-key",
        }):
            azure.azure_cli(
                ["storage", "blob", "upload"],
                env={"AZURE_STORAGE_SAS_TOKEN": "expected-sas"},
            )
        environment = execute.call_args.kwargs["env"]
        self.assertNotIn("AZURE_STORAGE_CONNECTION_STRING", environment)
        self.assertNotIn("AZURE_STORAGE_KEY", environment)
        self.assertEqual(environment["AZURE_STORAGE_SAS_TOKEN"], "expected-sas")

    @mock.patch.object(azure, "azure_cli")
    def test_subscription_preflight_never_registers_providers(self, command):
        command.side_effect = [
            {"id": "subscription", "state": "Enabled", "environmentName": "AzureCloud"},
            "NotRegistered",
        ]
        with self.assertRaisesRegex(RuntimeError, "must already be registered"):
            azure.check_subscription("westus2", "Standard_D2s_v5")
        self.assertEqual(command.call_count, 2)

    @mock.patch.object(azure, "azure_cli")
    def test_subscription_preflight_rejects_restricted_sku(self, command):
        command.side_effect = [
            {"id": "subscription", "state": "Enabled", "environmentName": "AzureCloud"},
            "Registered", "Registered", ["2025-11-01"],
            [{"restrictions": [{"type": "Location"}]}],
        ]
        with self.assertRaisesRegex(RuntimeError, "not unrestricted"):
            azure.check_subscription("eastus", "Standard_D2s_v5")
        self.assertEqual(command.call_count, 5)

    @mock.patch.object(azure, "azure_cli")
    def test_subscription_preflight_requires_both_core_quotas(self, command):
        command.side_effect = [
            {"id": "subscription", "state": "Enabled", "environmentName": "AzureCloud"},
            "Registered", "Registered", ["2025-11-01"],
            [{
                "restrictions": [], "family": "testFamily",
                "capabilities": [
                    {"name": "HyperVGenerations", "value": "V1,V2"},
                    {"name": "CpuArchitectureType", "value": "x64"},
                    {"name": "vCPUs", "value": "2"},
                ],
            }],
            [
                {"name": {"value": "cores"}, "limit": 100, "currentValue": 0},
                {"name": {"value": "testFamily"}, "limit": 1, "currentValue": 0},
            ],
        ]
        with self.assertRaisesRegex(RuntimeError, "Insufficient two-vCPU quota"):
            azure.check_subscription("westus2", "Standard_D2s_v5")

    def test_unknown_serial_error_is_not_hidden_as_not_ready(self):
        run = self.run_fixture()
        result = mock.Mock(returncode=1, stderr="ERROR: (AuthorizationFailed) denied")
        run.az.side_effect = azure.AzureCliError(["vm", "boot-diagnostics"], result, True)
        with self.assertRaises(azure.AzureCliError):
            run.wait_for_boot("io", 10)
        self.assertEqual(run.az.call_count, 1)

    @mock.patch.object(azure, "check_subscription")
    @mock.patch.object(azure, "image_sha256", return_value="b" * 64)
    @mock.patch.object(azure, "load_state")
    def test_modified_image_is_rejected_before_any_cloud_call(self, load, digest, check):
        load.return_value = ({
            "phase": "prepared", "local_platform_boot": True,
            "image_sha256": "a" * 64,
        }, Path("/unused/state.json"))
        with self.assertRaisesRegex(ValueError, "changed since the local boot"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        check.assert_not_called()

    @mock.patch.object(azure, "check_subscription")
    @mock.patch.object(azure, "load_state")
    def test_partial_run_cannot_be_silently_resumed(self, load, check):
        load.return_value = ({
            "phase": "uploading-disk", "local_platform_boot": True,
        }, Path("/unused/state.json"))
        with self.assertRaisesRegex(ValueError, "newly prepared"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        check.assert_not_called()

    @mock.patch.object(azure, "save_json")
    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "check_subscription", return_value="subscription")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_failed_run_cleans_owned_resources_by_default(
        self, load, digest, check, constructor, save
    ):
        state = {
            "phase": "prepared", "local_platform_boot": True,
            "image_sha256": "a" * 64, "location": "westus2",
            "vm_size": "Standard_D2s_v5",
        }
        load.return_value = (state, Path("/unused/state.json"))
        run = constructor.return_value
        run.create_group.side_effect = lambda: state.update(phase="group-created")
        run.upload_disk.side_effect = RuntimeError("upload failed")
        with self.assertRaisesRegex(RuntimeError, "upload failed"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        run.cleanup.assert_called_once_with()
        run.deploy_vm.assert_not_called()

    @mock.patch.object(azure, "save_json")
    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "load_state")
    def test_local_only_preparation_cleanup_needs_no_subscription(self, load, constructor, save):
        state = {"phase": "preparing"}
        load.return_value = (state, Path("/unused/state.json"))
        azure.cleanup_state(Path("/unused"))
        self.assertEqual(state["phase"], "cleaned")
        azure.cleanup_state(Path("/unused"))
        constructor.assert_not_called()

    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "load_state")
    def test_cloud_cleanup_requires_complete_subscription_ownership(self, load, constructor):
        load.return_value = (
            {"phase": "creating-group"}, Path("/unused/state.json")
        )
        with self.assertRaisesRegex(ValueError, "subscription is missing"):
            azure.cleanup_state(Path("/unused"))
        constructor.assert_not_called()


class HypervAzureEvidenceTest(unittest.TestCase):
    def complete_log(self):
        return "\n".join((
            azure.PLATFORM_READY, azure.BLOCK_READY,
            azure.NETWORK_READY, azure.IO_READY,
        ))

    def test_all_stages_are_required_for_io(self):
        self.assertTrue(azure.inspect_boot_log(self.complete_log())["io_ready"])
        for marker in (
            azure.PLATFORM_READY, azure.BLOCK_READY,
            azure.NETWORK_READY, azure.IO_READY,
        ):
            with self.subTest(marker=marker):
                text = self.complete_log().replace(marker, "")
                self.assertFalse(azure.inspect_boot_log(text)["io_ready"])

    def test_embedded_marker_does_not_establish_acceptance(self):
        result = azure.inspect_boot_log(f"Looking for {azure.PLATFORM_READY}")
        self.assertFalse(result["platform_ready"])

    def test_custom_application_marker_only_establishes_platform_boot(self):
        result = azure.inspect_boot_log("Hello world!\n", "Hello world!")
        self.assertTrue(result["platform_ready"])
        self.assertFalse(result["io_ready"])

    def test_firmware_escape_sequences_and_nuls_are_supported(self):
        text = "\x1b[2J" + self.complete_log().replace("\n", "\0\r\n")
        self.assertTrue(azure.inspect_boot_log(text)["io_ready"])

    def test_final_marker_must_follow_device_results(self):
        text = "\n".join((
            azure.PLATFORM_READY, azure.IO_READY,
            azure.BLOCK_READY, azure.NETWORK_READY,
        ))
        result = azure.inspect_boot_log(text)
        self.assertFalse(result["io_ready"])
        self.assertTrue(result["failures"])

    def test_missing_devices_are_not_io_success(self):
        text = self.complete_log() + "\nUK_HYPERV_ACCEPTANCE_UNAVAILABLE:netvsc"
        result = azure.inspect_boot_log(text)
        self.assertTrue(result["platform_ready"])
        self.assertFalse(result["io_ready"])

    def test_later_crash_invalidates_success(self):
        text = self.complete_log() + "\nUnikraft Crash"
        result = azure.inspect_boot_log(text)
        self.assertFalse(result["platform_ready"])
        self.assertFalse(result["io_ready"])

    def test_nonzero_application_result_invalidates_io_success(self):
        text = self.complete_log() + "\nmain returned -1"
        result = azure.inspect_boot_log(text)
        self.assertFalse(result["io_ready"])
        self.assertTrue(result["failures"])


class HypervAzureTemplateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = json.loads(
            (SUPPORT / "azure/hyperv-gen2.json").read_text()
        )
        cls.resources = {
            resource["type"]: resource
            for resource in cls.template["resources"]
        }

    def test_specialized_disk_does_not_require_guest_provisioning(self):
        vm = self.resources["Microsoft.Compute/virtualMachines"]["properties"]
        self.assertNotIn("osProfile", vm)
        self.assertNotIn("imageReference", vm["storageProfile"])
        disk = vm["storageProfile"]["osDisk"]
        self.assertEqual(disk["createOption"], "Attach")
        self.assertEqual(disk["osType"], "Linux")
        self.assertEqual(disk["deleteOption"], "Detach")
        self.assertEqual(
            disk["managedDisk"]["id"], "[parameters('osDiskId')]"
        )

    def test_unsigned_efi_and_serial_capture_are_configured_before_boot(self):
        resource = self.resources["Microsoft.Compute/virtualMachines"]
        self.assertEqual(resource["apiVersion"], "2025-11-01")
        vm = resource["properties"]
        self.assertEqual(vm["securityProfile"]["securityType"], "Standard")
        self.assertEqual(
            vm["diagnosticsProfile"]["bootDiagnostics"], {"enabled": True}
        )

    def test_synthetic_nic_has_no_public_address(self):
        nic = self.resources["Microsoft.Network/networkInterfaces"]["properties"]
        self.assertFalse(nic["enableAcceleratedNetworking"])
        self.assertFalse(nic["enableIPForwarding"])
        self.assertEqual(len(nic["ipConfigurations"]), 1)
        self.assertNotIn(
            "publicIPAddress", nic["ipConfigurations"][0]["properties"]
        )
        self.assertNotIn("Microsoft.Network/publicIPAddresses", self.resources)
        self.assertEqual(
            self.resources["Microsoft.Network/networkSecurityGroups"]
            ["properties"]["securityRules"],
            [],
        )
        vnet = self.resources["Microsoft.Network/virtualNetworks"]["properties"]
        self.assertFalse(vnet["subnets"][0]["properties"]["defaultOutboundAccess"])

    def test_resources_carry_run_and_image_ownership(self):
        for resource in self.resources.values():
            self.assertEqual(resource["tags"], "[variables('tags')]")
        tags = self.template["variables"]["tags"]
        self.assertEqual(tags["managed-by"], "unikraft-hyperv")
        self.assertEqual(tags["unikraft-run"], "[parameters('namePrefix')]")
        self.assertEqual(tags["image-sha256"], "[parameters('imageSha256')]")

    def test_vm_choices_remain_small(self):
        size = self.template["parameters"]["vmSize"]
        self.assertEqual(size["defaultValue"], "Standard_D2s_v5")
        self.assertEqual(
            size["allowedValues"],
            ["Standard_D2s_v5", "Standard_D2as_v5", "Standard_B2s"],
        )


if __name__ == "__main__":
    unittest.main()
