const std = @import("std");
const sdk = @import("azure_sdk_core");
const contracts = @import("hyperv_core").contracts;
const s = @import("scope.zig");

pub const Provider = enum {
    compute,
    network,
    storage,
    resources,
    devtestlab,
    pub fn wire(self: Provider) []const u8 {
        return switch (self) {
            .compute => "Microsoft.Compute",
            .network => "Microsoft.Network",
            .storage => "Microsoft.Storage",
            .resources => "Microsoft.Resources",
            .devtestlab => "Microsoft.DevTestLab",
        };
    }
};
pub const Key = enum { key1, key2 };
pub const Power = enum { running, deallocated };
pub const VmAction = struct { vm: s.Ref, original_uuid: s.Uuid };
pub const DiskIdentity = struct { disk: s.Ref, original_uuid: s.Uuid, geometry: contracts.Geometry };
pub const Grant = struct { identity: DiskIdentity, seconds: u32 };
pub const Disk = struct { name: []const u8, size_gib: u32, upload_bytes: ?u64 = null };
pub const Vm = struct { name: []const u8, os_disk: DiskIdentity, nic: s.Ref, size: []const u8, data_disk: ?DiskIdentity = null };
pub const Storage = struct { name: []const u8 };
pub const Resource = union(enum) { disk: Disk, vm: Vm, storage: Storage };
pub const Deployment = struct { name: []const u8, resources: []const Resource };
pub const Firewall = struct {
    account: s.Ref,
    before_address: ?[4]u8,
    address: ?[4]u8,
    subnets: []const s.Ref,
};
pub const KeySnapshot = struct { key1: [32]u8, key2: [32]u8 };
pub const KeyOperation = struct { account: s.Ref, key: Key, previous: KeySnapshot };
pub const Schedule = struct { name: []const u8, vm: s.Ref, time: [4]u8 };
pub const Image = struct { ref: s.Ref, group: []const u8 };

pub const Operation = union(enum) {
    subscription,
    providers,
    provider: Provider,
    skus,
    usage,
    quota: []const u8,
    inventory,
    list: s.Kind,
    get: s.Ref,
    image: Image,
    instance_view: s.Ref,
    group_create,
    group_delete,
    deploy: Deployment,
    disk_create: Disk,
    grant: Grant,
    revoke: DiskIdentity,
    deallocate: VmAction,
    start: VmAction,
    boot_diagnostics: VmAction,
    firewall: Firewall,
    list_keys: s.Ref,
    regenerate_key: KeyOperation,
    schedule_put: Schedule,
    schedule_delete: s.Ref,

    pub fn isMutation(self: Operation) bool {
        return switch (self) {
            .group_create, .group_delete, .deploy, .disk_create, .grant, .revoke, .deallocate, .start, .firewall, .regenerate_key, .schedule_put, .schedule_delete => true,
            else => false,
        };
    }
    pub fn isList(self: Operation) bool {
        return switch (self) {
            .providers, .skus, .usage, .inventory, .list => true,
            else => false,
        };
    }
};

pub const Plan = struct {
    operation: Operation,
    method: sdk.http.Method = .GET,
    path: []const u8,
    version: []const u8,
    url: []const u8,
    body: ?[]const u8 = null,
    target: ?s.Ref = null,
    provider: []const u8,
    mutation: bool,
    filter: ?[]const u8 = null,

    /// All allocations belong to the caller's secret arena.
    pub fn create(a: std.mem.Allocator, authority: s.Authority, operation: Operation) !Plan {
        try authority.validate();
        var plan: Plan = .{
            .operation = operation,
            .path = "",
            .version = "2021-04-01",
            .url = "",
            .provider = "Microsoft.Resources",
            .mutation = operation.isMutation(),
        };
        const group = try authority.groupPath(a);
        switch (operation) {
            .subscription => {
                plan.path = try std.fmt.allocPrint(a, "/subscriptions/{s}", .{authority.subscription});
                plan.version = "2022-12-01";
            },
            .providers => plan.path = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers", .{authority.subscription}),
            .provider => |provider| plan.path = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers/{s}", .{ authority.subscription, provider.wire() }),
            .skus => {
                plan.path = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers/Microsoft.Compute/skus", .{authority.subscription});
                plan.version = "2021-07-01";
                plan.provider = "Microsoft.Compute";
                plan.filter = try std.fmt.allocPrint(a, "location eq '{s}'", .{authority.location});
            },
            .usage => {
                plan.path = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers/Microsoft.Compute/locations/{s}/usages", .{ authority.subscription, authority.location });
                plan.version = "2025-11-01";
                plan.provider = "Microsoft.Compute";
            },
            .quota => |quota| {
                try s.name(quota);
                plan.path = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers/Microsoft.Compute/locations/{s}/providers/Microsoft.Quota/quotas/{s}", .{ authority.subscription, authority.location, quota });
                plan.version = "2023-02-01";
                plan.provider = "Microsoft.Quota";
            },
            .inventory => plan.path = try std.fmt.allocPrint(a, "{s}/resources", .{group}),
            .list => |kind| {
                if (kind == .group or kind == .subnet or kind == .gallery_image or kind == .gallery_version) return error.InvalidOperation;
                plan.path = try std.fmt.allocPrint(a, "{s}/providers/{s}/{s}", .{ group, kind.provider(), kind.resourceType() });
                plan.version = kind.version();
                plan.provider = kind.provider();
            },
            .get => |target| try plan.resource(a, authority, target, ""),
            .image => |image| {
                if (image.ref.kind != .image and image.ref.kind != .gallery_image and image.ref.kind != .gallery_version)
                    return error.InvalidImage;
                var image_scope = authority;
                image_scope.group = image.group;
                try image_scope.validate();
                try plan.resource(a, image_scope, image.ref, "");
            },
            .instance_view => |target| {
                try requireKind(target, .vm);
                try plan.resource(a, authority, target, "/instanceView");
            },
            .group_create => {
                try plan.resource(a, authority, .{ .kind = .group, .name = authority.group }, "");
                plan.method = .PUT;
                plan.body = try encode(a, .{ .location = authority.location, .tags = ownerTags(authority) });
            },
            .group_delete => {
                try plan.resource(a, authority, .{ .kind = .group, .name = authority.group }, "");
                plan.method = .DELETE;
            },
            .deploy => |deployment| {
                try plan.resource(a, authority, .{ .kind = .deployment, .name = deployment.name }, "");
                if (deployment.resources.len == 0 or deployment.resources.len > 16) return error.InvalidDeployment;
                var writer = std.Io.Writer.Allocating.init(a);
                try writer.writer.writeAll("{\"properties\":{\"mode\":\"Incremental\",\"template\":{\"$schema\":\"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#\",\"contentVersion\":\"1.0.0.0\",\"resources\":[");
                for (deployment.resources, 0..) |definition, i| {
                    if (i != 0) try writer.writer.writeByte(',');
                    const payload = try resourceBody(a, authority, definition);
                    try writer.writer.writeAll(payload);
                    for (deployment.resources[0..i]) |previous| if (std.ascii.eqlIgnoreCase(resourceName(previous), resourceName(definition)))
                        return error.DuplicateResource;
                }
                try writer.writer.writeAll("]}}}");
                plan.body = try writer.toOwnedSlice();
                plan.method = .PUT;
            },
            .disk_create => |disk| {
                try plan.resource(a, authority, .{ .kind = .disk, .name = disk.name }, "");
                plan.body = try diskBody(a, authority, disk, false);
                plan.method = .PUT;
            },
            .grant => |grant| {
                try diskIdentity(a, authority, grant.identity);
                if (grant.seconds < 60 or grant.seconds > 3600) return error.InvalidGrantLifetime;
                try plan.resource(a, authority, grant.identity.disk, "/beginGetAccess");
                plan.body = try encode(a, .{ .access = "Write", .durationInSeconds = grant.seconds, .fileFormat = "VHD" });
                plan.method = .POST;
            },
            .revoke => |identity| {
                try diskIdentity(a, authority, identity);
                try plan.resource(a, authority, identity.disk, "/endGetAccess");
                plan.method = .POST;
                plan.body = "{}";
            },
            .deallocate, .start, .boot_diagnostics => |action| {
                try requireKind(action.vm, .vm);
                _ = try s.uuid(&action.original_uuid);
                const suffix: []const u8 = switch (operation) {
                    .deallocate => "/deallocate",
                    .start => "/start",
                    .boot_diagnostics => "/retrieveBootDiagnosticsData",
                    else => unreachable,
                };
                try plan.resource(a, authority, action.vm, suffix);
                plan.method = .POST;
                plan.body = if (operation == .boot_diagnostics) null else "{}";
            },
            .firewall => |firewall| {
                try requireKind(firewall.account, .storage);
                try plan.resource(a, authority, firewall.account, "");
                plan.method = .PATCH;
                if (firewall.subnets.len > 4) return error.InvalidFirewall;
                if (firewall.before_address) |address| try publicIp(address);
                var writer = std.Io.Writer.Allocating.init(a);
                try writer.writer.writeAll("{\"properties\":{\"networkAcls\":{\"bypass\":\"None\",\"defaultAction\":\"Deny\",\"ipRules\":[");
                if (firewall.address) |address| {
                    try publicIp(address);
                    // Storage rejects /32 on the wire; intent may retain canonical CIDR.
                    try writer.writer.print("{{\"action\":\"Allow\",\"value\":\"{d}.{d}.{d}.{d}\"}}", .{ address[0], address[1], address[2], address[3] });
                }
                try writer.writer.writeAll("],\"virtualNetworkRules\":[");
                for (firewall.subnets, 0..) |subnet, i| {
                    try requireKind(subnet, .subnet);
                    const id = try subnet.path(a, authority);
                    for (firewall.subnets[0..i]) |previous| {
                        if (std.ascii.eqlIgnoreCase(id, try previous.path(a, authority))) return error.InvalidFirewall;
                    }
                    if (i != 0) try writer.writer.writeByte(',');
                    try std.json.Stringify.value(.{ .id = id, .action = "Allow" }, .{}, &writer.writer);
                }
                try writer.writer.writeAll("],\"resourceAccessRules\":[]}}}");
                plan.body = try writer.toOwnedSlice();
            },
            .list_keys => |account| {
                try requireKind(account, .storage);
                try plan.resource(a, authority, account, "/listKeys");
                plan.method = .POST;
                plan.body = "{}";
            },
            .regenerate_key => |key| {
                try requireKind(key.account, .storage);
                try plan.resource(a, authority, key.account, "/regenerateKey");
                plan.method = .POST;
                plan.body = try encode(a, .{ .keyName = @tagName(key.key) });
            },
            .schedule_put => |schedule| {
                try requireKind(schedule.vm, .vm);
                for (schedule.time) |c| if (!std.ascii.isDigit(c)) return error.InvalidSchedule;
                if (try std.fmt.parseInt(u16, schedule.time[0..2], 10) > 23 or try std.fmt.parseInt(u16, schedule.time[2..4], 10) > 59) return error.InvalidSchedule;
                try plan.resource(a, authority, .{ .kind = .schedule, .name = schedule.name }, "");
                plan.method = .PUT;
                plan.body = try encode(a, .{ .location = authority.location, .tags = ownerTags(authority), .properties = .{
                    .status = "Enabled",
                    .taskType = "ComputeVmShutdownTask",
                    .targetResourceId = try schedule.vm.path(a, authority),
                    .dailyRecurrence = .{ .time = &schedule.time },
                    .timeZoneId = "UTC",
                    .notificationSettings = .{ .status = "Disabled" },
                } });
            },
            .schedule_delete => |schedule| {
                try requireKind(schedule, .schedule);
                try plan.resource(a, authority, schedule, "");
                plan.method = .DELETE;
            },
        }
        plan.url = try std.fmt.allocPrint(a, "{s}{s}?api-version={s}", .{ s.arm_host, plan.path, plan.version });
        if (operation == .skus) plan.url = try std.fmt.allocPrint(a, "{s}&$filter=location%20eq%20%27{s}%27", .{ plan.url, authority.location });
        if (operation == .boot_diagnostics) plan.url = try std.fmt.allocPrint(a, "{s}&sasUriExpirationTimeInMinutes=10", .{plan.url});
        if (plan.body) |body| if (body.len > 256 * 1024) return error.InvalidBody;
        try plan.validateInitialUrl(a);
        return plan;
    }

    pub fn validateInitialUrl(self: Plan, a: std.mem.Allocator) !void {
        const relative = try s.relativeUrl(self.url);
        const end = std.mem.indexOfScalar(u8, relative, '?').?;
        if (!std.mem.eql(u8, relative[0..end], self.path)) return error.ScopeMismatch;
        try s.initialQuery(a, relative, self.version, self.filter, self.operation == .boot_diagnostics);
    }

    fn resource(self: *Plan, a: std.mem.Allocator, authority: s.Authority, target: s.Ref, suffix: []const u8) !void {
        self.path = try std.fmt.allocPrint(a, "{s}{s}", .{ try target.path(a, authority), suffix });
        self.version = target.kind.version();
        self.provider = target.kind.provider();
        self.target = target;
    }
};

fn requireKind(ref: s.Ref, kind: s.Kind) !void {
    if (ref.kind != kind) return error.WrongResourceKind;
}
fn diskIdentity(a: std.mem.Allocator, authority: s.Authority, identity: DiskIdentity) !void {
    try requireKind(identity.disk, .disk);
    _ = try identity.disk.path(a, authority);
    _ = try s.uuid(&identity.original_uuid);
    _ = try identity.geometry.byteSize();
}
fn ownerTags(authority: s.Authority) struct { @"uk-hyperv-run": s.Uuid } {
    return .{ .@"uk-hyperv-run" = authority.owner_run };
}
fn encode(a: std.mem.Allocator, value: anytype) ![]u8 {
    return std.json.Stringify.valueAlloc(a, value, .{});
}
fn resourceName(resource: Resource) []const u8 {
    return switch (resource) {
        inline else => |value| value.name,
    };
}
fn resourceBody(a: std.mem.Allocator, authority: s.Authority, resource: Resource) ![]const u8 {
    return switch (resource) {
        .disk => |disk| diskBody(a, authority, disk, true),
        .vm => |vm| vmBody(a, authority, vm),
        .storage => |storage| storageBody(a, authority, storage),
    };
}
fn diskBody(a: std.mem.Allocator, authority: s.Authority, disk: Disk, deployment: bool) ![]u8 {
    try s.name(disk.name);
    if (disk.size_gib == 0 or disk.size_gib > 32) return error.InvalidGeometry;
    if (disk.upload_bytes) |bytes| if (bytes != @as(u64, disk.size_gib) * 1024 * 1024 * 1024 + 512) return error.InvalidGeometry;
    const value = .{
        .type = if (deployment) @as(?[]const u8, "Microsoft.Compute/disks") else null,
        .apiVersion = if (deployment) @as(?[]const u8, s.Kind.disk.version()) else null,
        .name = disk.name,
        .location = authority.location,
        .tags = ownerTags(authority),
        .sku = .{ .name = "StandardSSD_LRS" },
        .properties = .{ .diskSizeGB = disk.size_gib, .logicalSectorSize = @as(u16, 512), .creationData = .{
            .createOption = if (disk.upload_bytes != null) "Upload" else "Empty",
            .uploadSizeBytes = disk.upload_bytes,
        } },
    };
    return std.json.Stringify.valueAlloc(a, value, .{ .emit_null_optional_fields = false });
}
fn vmBody(a: std.mem.Allocator, authority: s.Authority, vm: Vm) ![]u8 {
    try s.name(vm.name);
    try s.name(vm.size);
    try diskIdentity(a, authority, vm.os_disk);
    try requireKind(vm.nic, .nic);
    const DataDisk = struct { lun: u8, createOption: []const u8, caching: []const u8, managedDisk: struct { id: []const u8 } };
    var disks: [1]DataDisk = undefined;
    if (vm.data_disk) |disk| {
        try diskIdentity(a, authority, disk);
        if (std.ascii.eqlIgnoreCase(disk.disk.name, vm.os_disk.disk.name) or try disk.geometry.byteSize() != 4 * 1024 * 1024 * 1024)
            return error.InvalidGeometry;
        disks[0] = .{ .lun = 7, .createOption = "Attach", .caching = "None", .managedDisk = .{ .id = try disk.disk.path(a, authority) } };
    }
    return encode(a, .{
        .type = "Microsoft.Compute/virtualMachines",
        .apiVersion = s.Kind.vm.version(),
        .name = vm.name,
        .location = authority.location,
        .tags = ownerTags(authority),
        .properties = .{
            .hardwareProfile = .{ .vmSize = vm.size },
            .securityProfile = .{ .securityType = "Standard" },
            .storageProfile = .{
                .osDisk = .{ .createOption = "Attach", .osType = "Linux", .caching = "None", .managedDisk = .{ .id = try vm.os_disk.disk.path(a, authority) } },
                .dataDisks = disks[0..@as(usize, if (vm.data_disk != null) 1 else 0)],
            },
            .networkProfile = .{ .networkInterfaces = &.{.{ .id = try vm.nic.path(a, authority) }} },
            .diagnosticsProfile = .{ .bootDiagnostics = .{ .enabled = true } },
        },
    });
}
fn storageBody(a: std.mem.Allocator, authority: s.Authority, storage: Storage) ![]u8 {
    _ = try (s.Ref{ .kind = .storage, .name = storage.name }).path(a, authority);
    return encode(a, .{
        .type = "Microsoft.Storage/storageAccounts",
        .apiVersion = s.Kind.storage.version(),
        .name = storage.name,
        .location = authority.location,
        .tags = ownerTags(authority),
        .kind = "StorageV2",
        .sku = .{ .name = "Standard_LRS" },
        .properties = .{
            .supportsHttpsTrafficOnly = true,
            .allowBlobPublicAccess = false,
            .minimumTlsVersion = "TLS1_2",
            .publicNetworkAccess = "Enabled",
            .networkAcls = .{
                .bypass = "None",
                .defaultAction = "Deny",
                .ipRules = &[_]struct {}{},
                .virtualNetworkRules = &[_]struct {}{},
                .resourceAccessRules = &[_]struct {}{},
            },
        },
    });
}
pub fn publicIp(address: [4]u8) !void {
    if (address[0] == 0 or address[0] == 10 or address[0] == 127 or address[0] >= 224 or
        (address[0] == 169 and address[1] == 254) or
        (address[0] == 172 and address[1] >= 16 and address[1] <= 31) or
        (address[0] == 192 and address[1] == 168) or
        (address[0] == 100 and address[1] >= 64 and address[1] <= 127)) return error.InvalidPublicAddress;
}
