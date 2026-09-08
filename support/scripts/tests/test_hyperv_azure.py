# SPDX-License-Identifier: BSD-3-Clause

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
azure = importlib.import_module("hyperv-azure")
uploader = importlib.import_module("hyperv-azure-upload")


class UploadFailure(Exception):
    error_code = "UploadFailed"


class HypervAzurePageUploadTest(unittest.TestCase):
    def test_precreated_disk_uses_page_updates_and_exact_footer_readback(self):
        footer = b"conectix" + b"\0" * 504
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.vhd"
            image.write_bytes(b"\0" * uploader.PAGE_CHUNK + footer)
            factory = mock.Mock()
            client = mock.MagicMock()
            factory.from_blob_url.return_value = client
            client.__enter__.return_value = client
            client.download_blob.return_value.readall.return_value = footer
            with mock.patch.object(uploader, "storage_sdk", return_value=(factory, UploadFailure)):
                report = uploader.upload_pages(
                    image, "https://md.blob.storage.azure.net:8443/disk/image", "sig=secret"
                )
            self.assertEqual(report["uploaded_bytes"], uploader.PAGE_CHUNK + 512)
            self.assertTrue(report["footer_matches"])
            self.assertEqual(client.upload_page.call_count, 2)
            self.assertEqual(client.upload_page.call_args_list[0].args[1:], (0, uploader.PAGE_CHUNK))
            self.assertEqual(client.upload_page.call_args_list[1].args[1:], (uploader.PAGE_CHUNK, 512))
            for call in client.upload_page.call_args_list:
                self.assertTrue(call.kwargs["validate_content"])
            client.create_page_blob.assert_not_called()
            client.upload_blob.assert_not_called()
            client.download_blob.assert_called_once_with(
                offset=uploader.PAGE_CHUNK, length=512,
                validate_content=True, max_concurrency=1,
            )

    def test_readback_mismatch_and_sdk_error_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.vhd"
            image.write_bytes(b"conectix" + b"\0" * 504)
            factory = mock.Mock()
            client = mock.MagicMock()
            factory.from_blob_url.return_value = client
            client.__enter__.return_value = client
            client.download_blob.return_value.readall.return_value = b"\0" * 512
            with mock.patch.object(uploader, "storage_sdk", return_value=(factory, UploadFailure)):
                with self.assertRaisesRegex(ValueError, "footer does not match"):
                    uploader.upload_pages(
                        image, "https://md.blob.storage.azure.net/disk/image", "sig=secret"
                    )
                client.upload_page.side_effect = UploadFailure("failed at ?sig=secret")
                with self.assertRaises(RuntimeError) as error:
                    uploader.upload_pages(
                        image, "https://md.blob.storage.azure.net/disk/image", "sig=secret"
                    )
                self.assertIn("UploadFailed", str(error.exception))
                self.assertNotIn("secret", str(error.exception))


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

    @mock.patch.object(azure, "upload_managed_vhd", side_effect=RuntimeError("upload failed"))
    def test_upload_failure_always_revokes_disk_access(self, upload):
        run = self.run_fixture()
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.core.windows.net/path?sig=secret"},
            None,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with mock.patch.object(azure.sys, "stderr", io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "upload failed"):
                run.upload_disk(image)
        self.assertEqual(run.az.call_args.args[0][:2], ["disk", "revoke-access"])
        upload.assert_called_once_with(
            image, "https://disk.blob.core.windows.net/path", "sig=secret"
        )

    @mock.patch.object(azure, "upload_managed_vhd")
    def test_unimported_disk_cannot_advance_to_deployment(self, upload):
        run = self.run_fixture()
        incomplete = self.disk_fixture(run)
        incomplete["diskState"] = "ReadyToUpload"
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.core.windows.net/path?sig=secret"},
            None, incomplete,
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with self.assertRaisesRegex(RuntimeError, "successfully imported"):
            run.upload_disk(image)
        self.assertNotIn(mock.call("disk-ready"), run.record.call_args_list)

    def test_initial_upload_error_remains_visible_if_revocation_also_fails(self):
        run = self.run_fixture()
        run.az.side_effect = [
            self.disk_fixture(run),
            {"accessSas": "https://disk.blob.storage.azure.net:8080/path?sig=secret"},
            RuntimeError("revoke failed"),
        ]
        image = mock.Mock()
        image.stat.return_value.st_size = 67109376
        with mock.patch.object(azure.sys, "stderr") as errors:
            with self.assertRaisesRegex(RuntimeError, "revoke failed"):
                run.upload_disk(image)
        output = "".join(call.args[0] for call in errors.write.call_args_list)
        self.assertIn("Disk upload did not complete:", output)
        self.assertIn("Expected an Azure public-cloud HTTPS Blob SAS endpoint", output)
        self.assertNotIn("secret", output)

    def test_upload_rejects_non_azure_or_plaintext_endpoints(self):
        for endpoint in (
            "http://disk.blob.core.windows.net/path?sig=secret",
            "https://blob.core.windows.net.attacker.invalid/path?sig=secret",
            "https://user@disk.blob.core.windows.net/path?sig=secret",
            "https://disk.blob.core.windows.net/path",
            "https://disk.blob.storage.azure.net:8080/path?sig=secret",
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
            "md-impexp-disk.z20.blob.storage.azure.net:8443",
        ):
            with self.subTest(host=host):
                endpoint, sas = azure.upload_endpoint(f"https://{host}/path?sig=secret")
                self.assertEqual(endpoint, f"https://{host}/path")
                self.assertEqual(sas, "sig=secret")

    def test_disk_access_response_supports_cli_and_rest_sas_spellings(self):
        for key in ("accessSAS", "accessSas"):
            with self.subTest(key=key):
                self.assertEqual(azure.disk_access_sas({key: "expected"}), "expected")
        self.assertEqual(azure.disk_access_sas({
            "accessSAS": "expected", "accessSas": "expected",
        }), "expected")
        for grant in (
            None, {}, {"accessSAS": None}, {"accessSAS": 1},
            {"accessSAS": ""}, {"accessSAS": "first", "accessSas": "second"},
        ):
            with self.subTest(grant=grant):
                with self.assertRaises(ValueError):
                    azure.disk_access_sas(grant)

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
    def test_upload_helper_ignores_ambient_credentials_and_bounds_runtime(self, execute):
        execute.return_value = mock.Mock(returncode=0, stdout='{"available": true}')
        with mock.patch.dict(azure.os.environ, {
            "AZURE_STORAGE_CONNECTION_STRING": "unrelated-account",
            "AZURE_STORAGE_KEY": "unrelated-key",
        }):
            azure.upload_helper(["--check-dependencies"], sas="expected-sas")
        environment = execute.call_args.kwargs["env"]
        self.assertNotIn("AZURE_STORAGE_CONNECTION_STRING", environment)
        self.assertNotIn("AZURE_STORAGE_KEY", environment)
        self.assertEqual(environment["AZURE_STORAGE_SAS_TOKEN"], "expected-sas")
        self.assertNotIn("expected-sas", " ".join(execute.call_args.args[0]))
        self.assertEqual(execute.call_args.kwargs["timeout"], 1200)

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

    def test_quota_counts_accept_cli_decimal_strings_without_silent_defaults(self):
        for value in (0, "0", 100, "100"):
            with self.subTest(value=value):
                self.assertEqual(azure.quota_count(value), int(value))
        for value in (None, True, -1, "-1", "unlimited", "1.5", 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    azure.quota_count(value)

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

    @mock.patch.object(azure, "check_subscription")
    @mock.patch.object(azure, "check_upload_dependencies", side_effect=RuntimeError("missing SDK"))
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_missing_upload_sdk_fails_before_cloud_calls(self, load, digest, dependencies, check):
        load.return_value = ({
            "phase": "prepared", "local_platform_boot": True,
            "image_sha256": "a" * 64,
        }, Path("/unused/state.json"))
        with self.assertRaisesRegex(RuntimeError, "missing SDK"):
            azure.run_prepared(Path("/unused"), "io", 300, False)
        check.assert_not_called()

    @mock.patch.object(azure, "save_json")
    @mock.patch.object(azure, "AzureRun")
    @mock.patch.object(azure, "check_subscription", return_value="subscription")
    @mock.patch.object(azure, "check_upload_dependencies")
    @mock.patch.object(azure, "image_sha256", return_value="a" * 64)
    @mock.patch.object(azure, "load_state")
    def test_failed_run_cleans_owned_resources_by_default(
        self, load, digest, dependencies, check, constructor, save
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
