// SPDX-License-Identifier: BSD-3-Clause
//! Synthetic observations, written independently of the observation validators.
//! No real Azure response, seed, disk, credential or private run is used.
const direct = @import("main.zig");

pub const scope: direct.Scope = .{
    .schema = "uk.hyperv.direct-two-boot",
    .version = 1,
    .approval = .{
        .destructive_data_disk = true,
        .direct_specialized_gen2 = true,
        .two_boots_only = true,
        .cleanup_owned_group = true,
        .original_seed_reviewed = true,
        .guarded_native_image_reviewed = true,
        .expires_unix = 2000000000,
    },
    .attempt_id = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    .subscription = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
    .location = "fixture",
    .prefix = "fixture-direct",
    .vm_size = "Standard_D2s_v5",
    .run_id = "11111111111111111111111111111111",
    .disk_id = "22222222222222222222222222222222",
    .controller = .SCSI,
    .lun = 7,
    .sectors = 8388608,
    .sector_size = 512,
    .serial_mode = .per_boot,
    .runtime_seconds = 60,
    .cleanup_seconds = 60,
    .operation_seconds = 10,
    .poll_seconds = 1,
    .os_vhd = .{ .path = "/synthetic-only/os.vhd", .size = 1049088, .sha256 = "a" ** 64 },
    .seed_raw = .{ .path = "/synthetic-only/seed.raw", .size = 4294967296, .sha256 = "a" ** 64 },
    .seed_vhd = .{ .path = "/synthetic-only/seed.vhd", .size = 4294967808, .sha256 = "a" ** 64 },
    .manifest = .{ .path = "/synthetic-only/seed.json", .size = 1, .sha256 = "a" ** 64 },
    .config = .{ .path = "/synthetic-only/config", .size = 1, .sha256 = "a" ** 64 },
};

pub const group_id = "/subscriptions/bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb/resourceGroups/fixture-direct-rg";
pub const vm_id = group_id ++ "/providers/Microsoft.Compute/virtualMachines/fixture-direct-vm";
pub const os_id = group_id ++ "/providers/Microsoft.Compute/disks/fixture-direct-os";
pub const data_id = group_id ++ "/providers/Microsoft.Compute/disks/fixture-direct-data";
pub const nic_id = group_id ++ "/providers/Microsoft.Network/networkInterfaces/fixture-direct-nic";
pub const tags =
    \\"tags":{"uk-direct-run":"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    \\"unikraft-run":"fixture-direct",
    \\"image-sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    \\"managed-by":"unikraft-hyperv"}
;
pub const group = "{\"id\":\"" ++ group_id ++ "\"," ++ tags ++ "}";
pub const os_fields =
    "\"id\":\"" ++ os_id ++ "\"," ++ tags ++
    \\,"name":"fixture-direct-os","type":"Microsoft.Compute/disks",
    \\"uniqueId":"original-os","osType":"Linux","hyperVGeneration":"V2",
    \\"sku":{"name":"StandardSSD_LRS"},"logicalSectorSize":"512",
    \\"creationData":{"createOption":"Upload","uploadSizeBytes":"1049088"}
    ;
pub const data_fields =
    "\"id\":\"" ++ data_id ++ "\"," ++ tags ++
    \\,"name":"fixture-direct-data","type":"Microsoft.Compute/disks",
    \\"uniqueId":"original-data","osType":null,"hyperVGeneration":null,
    \\"sku":{"name":"StandardSSD_LRS"},"logicalSectorSize":512,
    \\"creationData":{"createOption":"Upload","uploadSizeBytes":4294967808}
    ;
pub const os_ready = "{" ++ os_fields ++ ",\"diskState\":\"ReadyToUpload\"}";
pub const data_ready = "{" ++ data_fields ++ ",\"diskState\":\"ReadyToUpload\"}";
pub const os_after = "{" ++ os_fields ++ ",\"diskState\":\"Unattached\",\"managedBy\":null,\"diskSizeBytes\":\"1048576\"}";
pub const data_after = "{" ++ data_fields ++ ",\"diskState\":\"Unattached\",\"diskSizeBytes\":4294967296}";
pub const os_attached = "{" ++ os_fields ++ ",\"diskState\":\"Attached\",\"managedBy\":\"" ++ vm_id ++ "\",\"diskSizeBytes\":1048576}";
pub const data_attached = "{" ++ data_fields ++ ",\"diskState\":\"Attached\",\"managedBy\":\"" ++ vm_id ++ "\",\"diskSizeBytes\":\"4294967296\"}";
pub const os_reserved = "{" ++ os_fields ++ ",\"diskState\":\"Reserved\",\"managedBy\":\"" ++ vm_id ++ "\",\"diskSizeBytes\":1048576}";
pub const data_reserved = "{" ++ data_fields ++ ",\"diskState\":\"Reserved\",\"managedBy\":\"" ++ vm_id ++ "\",\"diskSizeBytes\":\"4294967296\"}";
pub const vm =
    "{\"id\":\"" ++ vm_id ++ "\"," ++ tags ++
    \\,"name":"fixture-direct-vm","type":"Microsoft.Compute/virtualMachines","vmId":"original-vm",
    \\"securityProfile":{"securityType":"Standard"},"hardwareProfile":{"vmSize":"Standard_D2s_v5"},
    \\"diagnosticsProfile":{"bootDiagnostics":{"enabled":true}},
    \\"storageProfile":{"diskControllerType":"SCSI",
    \\"osDisk":{"createOption":"Attach","caching":"ReadOnly","deleteOption":"Detach",
    \\"managedDisk":{"id":"
    ++ os_id ++
    \\"}},
    \\"dataDisks":[{"lun":"7","createOption":"Attach","caching":"None","deleteOption":"Detach",
    \\"managedDisk":{"id":"
    ++ data_id ++
    \\"}}]},
    \\"networkProfile":{"networkInterfaces":[{"id":"
    ++ nic_id ++
    \\"}]}}
    ;
pub const running = "{\"instanceView\":{\"statuses\":[{\"code\":\"ProvisioningState/succeeded\"},{\"code\":\"PowerState/running\"}]}}";
pub const stopped = "{\"statuses\":[{\"code\":\"PowerState/stopped\"}]}";
pub const deallocated = "{\"instanceView\":{\"statuses\":[{\"code\":\"PowerState/deallocated\"}]}}";
pub const grant = "{\"accessSAS\":\"https://fixture.blob.core.windows.net/upload?sv=fixture&sig=SYNTHETIC_ONLY\"}";
pub const lower_grant = "{\"accessSas\":\"https://fixture.blob.core.windows.net:443/upload?sv=fixture&sig=SYNTHETIC_ONLY\"}";
pub const storage_grant = "{\"accessSAS\":\"https://md-fixture.z99.blob.storage.azure.net:8443/upload/vhd?sv=fixture&sig=SYNTHETIC_ONLY\"}";

pub const first_serial =
    "UK_HYPERV_PLATFORM_READY\n" ++
    "HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512\n" ++
    "HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=0\n" ++
    "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444\n" ++
    "HYPERV_PERSISTENCE BOOT1_WRITE PASS run=11111111111111111111111111111111\n" ++
    "UK_HYPERV_PERSISTENCE_IO:1:1:11111111111111111111111111111111:5:3:receipt-verified\n" ++
    "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:11111111111111111111111111111111\n" ++
    "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
pub const second_serial =
    "UK_HYPERV_PLATFORM_READY\n" ++
    "HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512\n" ++
    "HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=2\n" ++
    "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444\n" ++
    "HYPERV_PERSISTENCE BOOT2_READ PASS run=11111111111111111111111111111111\n" ++
    "UK_HYPERV_PERSISTENCE_IO:1:2:11111111111111111111111111111111:0:0:receipt-verified\n" ++
    "UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:11111111111111111111111111111111\n" ++
    "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
