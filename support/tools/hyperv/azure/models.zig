const std = @import("std");
const c = @import("hyperv_core").contracts;
const s = @import("scope.zig");
const ops = @import("operations.zig");
const wire = @import("transport.zig");

pub const State = enum { succeeded, creating, updating, deleting, running, accepted, failed, canceled, in_progress };
pub const Availability = enum { unavailable, no, yes };
pub const Subscription = struct { id: s.Uuid, enabled: bool };
pub const Provider = struct { namespace: []const u8, registered: bool, compute_version: bool };
pub const Sku = struct { name: []const u8, family: []const u8, vcpus: ?u32, memory_mib: ?u32, generation2: Availability, nested: Availability, restricted: bool, in_location: bool };
pub const Usage = struct { name: []const u8, current: u64, limit: u64 };
pub const Vm = struct { id: s.Ref, uuid: s.Uuid, size: []const u8, os_disk: s.Ref, nic: s.Ref, data_disk: ?s.Ref, state: State };
pub const DiskAccess = enum { unattached, attached, reserved, frozen, active_sas, ready_to_upload, active_upload };
pub const Disk = struct {
    id: s.Ref,
    uuid: s.Uuid,
    bytes: u64,
    sector_size: u16,
    state: State,
    access: DiskAccess,
    upload_bytes: ?u64,
    linux_gen2: bool = false,
};
pub const Storage = struct { id: s.Ref, public_network: bool, ip: ?[4]u8, subnet_rules: usize, subnets: []const s.Ref, state: State };
pub const Network = struct { id: s.Ref, entries: usize, state: ?State = null };
pub const Image = struct { id: s.Ref, generation2: bool, specialized_linux: bool, state: State };
pub const ImageVersion = struct { id: s.Ref, state: State, in_location: bool, published: []const u8 };
pub const Keys = struct {
    key1: []const u8,
    key2: []const u8,

    pub fn digest(self: Keys, selected: ops.Key) [32]u8 {
        var result: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(if (selected == .key1) self.key1 else self.key2, &result, .{});
        return result;
    }
    pub fn snapshot(self: Keys) ops.KeySnapshot {
        return .{ .key1 = self.digest(.key1), .key2 = self.digest(.key2) };
    }
};
pub const Boot = struct { serial: []const u8, screenshot: ?[]const u8 };
pub const Schedule = struct { id: s.Ref, vm: s.Ref, enabled: bool, time: [4]u8 };
pub const Summary = struct { id: s.Ref };
pub const Model = union(enum) {
    subscription: Subscription,
    provider: Provider,
    sku: Sku,
    usage: Usage,
    quota: u64,
    group: State,
    deployment: State,
    vm: Vm,
    disk: Disk,
    storage: Storage,
    network: Network,
    image: Image,
    image_version: ImageVersion,
    schedule: Schedule,
    summary: Summary,
    power: enum { running, deallocated, starting, stopping, stopped, deallocating, unknown },
    keys: Keys,
    grant: []const u8,
    boot: Boot,
    empty,
};

pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.ExpectedObject;
    return value.object.get(name) orelse error.MissingField;
}
pub fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    return c.string(try field(value, name));
}
pub fn array(value: std.json.Value) ![]const std.json.Value {
    return if (value == .array) value.array.items else error.ExpectedArray;
}
pub fn boolean(value: std.json.Value) !bool {
    return if (value == .bool) value.bool else error.ExpectedBoolean;
}
pub fn state(value: std.json.Value) !State {
    const raw = try c.string(value);
    const names = .{ "Succeeded", "Creating", "Updating", "Deleting", "Running", "Accepted", "Failed", "Canceled", "InProgress" };
    inline for (names, 0..) |name, i| if (std.mem.eql(u8, raw, name)) return @enumFromInt(i);
    return error.InvalidProvisioningState;
}

pub fn parse(a: std.mem.Allocator, authority: s.Authority, operation: ops.Operation, value: std.json.Value) !Model {
    return switch (operation) {
        .subscription => subscription(authority, value),
        .providers, .provider => provider(value),
        .skus => sku(a, authority, value),
        .usage => usage(value),
        .quota => |name| quota(a, authority, name, value),
        .inventory => .{ .summary = .{ .id = try ownedId(a, authority, try string(value, "id")) } },
        .list => |kind| resource(a, authority, kind, null, value),
        .get => |ref| resource(a, authority, ref.kind, ref, value),
        .image => |image| image: {
            var image_scope = authority;
            image_scope.group = image.group;
            break :image resource(a, image_scope, image.ref.kind, image.ref, value);
        },
        .instance_view => power(value),
        .group_create => resource(a, authority, .group, .{ .kind = .group, .name = authority.group }, value),
        .deploy => |deployment| resource(a, authority, .deployment, .{ .kind = .deployment, .name = deployment.name }, value),
        .disk_create => |disk| resource(a, authority, .disk, .{ .kind = .disk, .name = disk.name }, value),
        .persistence_network => |definition| network: {
            const ref = try definition.ref(a);
            break :network resource(a, authority, ref.kind, ref, value);
        },
        .grant => grant(value),
        .list_keys, .regenerate_key => keys(value),
        .boot_diagnostics => boot(value),
        .firewall => |firewall| resource(a, authority, .storage, firewall.account, value),
        .schedule_put => |schedule| resource(a, authority, .schedule, .{ .kind = .schedule, .name = schedule.name }, value),
        .group_delete, .schedule_delete, .deallocate, .start, .revoke => emptyAction(value),
    };
}

pub fn requireOriginalVm(model: Model, expected: s.Uuid) !void {
    if (model != .vm or !std.mem.eql(u8, &model.vm.uuid, &expected)) return error.OriginalIdentityMismatch;
}
pub fn requireOriginalDisk(model: Model, expected: ops.DiskIdentity) !void {
    if (model != .disk or !std.mem.eql(u8, &model.disk.uuid, &expected.original_uuid) or
        model.disk.bytes != try expected.geometry.byteSize() or model.disk.sector_size != expected.geometry.sector_size)
        return error.OriginalIdentityMismatch;
}

fn subscription(authority: s.Authority, value: std.json.Value) !Model {
    const id = try s.uuid(try string(value, "subscriptionId"));
    if (!std.mem.eql(u8, &id, &authority.subscription)) return error.ScopeMismatch;
    const status = try string(value, "state");
    const enabled = std.mem.eql(u8, status, "Enabled");
    if (!enabled and !std.mem.eql(u8, status, "Disabled") and !std.mem.eql(u8, status, "Warned") and
        !std.mem.eql(u8, status, "PastDue") and !std.mem.eql(u8, status, "Deleted")) return error.InvalidSubscriptionState;
    return .{ .subscription = .{ .id = id, .enabled = enabled } };
}
fn provider(value: std.json.Value) !Model {
    const namespace = try string(value, "namespace");
    try s.name(namespace);
    const registration = try string(value, "registrationState");
    if (!std.mem.eql(u8, registration, "Registered") and !std.mem.eql(u8, registration, "NotRegistered") and
        !std.mem.eql(u8, registration, "Registering") and !std.mem.eql(u8, registration, "Unregistering")) return error.InvalidProvider;
    var compute_version = false;
    var vm_seen = false;
    for (try array(try field(value, "resourceTypes"))) |resource_type| {
        const kind = try string(resource_type, "resourceType");
        const versions = try array(try field(resource_type, "apiVersions"));
        if (std.mem.eql(u8, kind, "virtualMachines")) {
            if (vm_seen) return error.DuplicateResourceType;
            vm_seen = true;
            for (versions) |version| if (std.mem.eql(u8, try c.string(version), "2025-11-01")) {
                compute_version = true;
            };
        }
    }
    return .{ .provider = .{ .namespace = namespace, .registered = std.mem.eql(u8, registration, "Registered"), .compute_version = compute_version } };
}
fn sku(a: std.mem.Allocator, authority: s.Authority, value: std.json.Value) !Model {
    if (!std.mem.eql(u8, try string(value, "resourceType"), "virtualMachines")) return error.UnexpectedSkuType;
    var result: Sku = .{
        .name = try string(value, "name"),
        .family = try string(value, "family"),
        .vcpus = null,
        .memory_mib = null,
        .generation2 = .unavailable,
        .nested = .unavailable,
        .restricted = (try array(try field(value, "restrictions"))).len != 0,
        .in_location = false,
    };
    for (try array(try field(value, "locations"))) |location| {
        if (std.mem.eql(u8, try c.string(location), authority.location)) result.in_location = true;
    }
    var seen: std.StringHashMap(void) = .init(a);
    defer seen.deinit();
    for (try array(try field(value, "capabilities"))) |capability| {
        const name = try string(capability, "name");
        const cap = try string(capability, "value");
        if ((try seen.getOrPut(name)).found_existing) return error.DuplicateCapability;
        if (std.mem.eql(u8, name, "vCPUs")) result.vcpus = std.math.cast(u32, try wire.unsigned(cap)) orelse return error.InvalidCapability;
        if (std.mem.eql(u8, name, "MemoryGB")) result.memory_mib = try memoryMiB(cap);
        if (std.mem.eql(u8, name, "HyperVGenerations")) {
            result.generation2 = .no;
            var generations = std.mem.splitScalar(u8, cap, ',');
            while (generations.next()) |generation| {
                const trimmed = std.mem.trim(u8, generation, " ");
                if (std.mem.eql(u8, trimmed, "V2")) result.generation2 = .yes else if (!std.mem.eql(u8, trimmed, "V1")) return error.InvalidCapability;
            }
        }
        if (std.mem.eql(u8, name, "NestedVirtualizationEnabled")) {
            result.nested = if (std.ascii.eqlIgnoreCase(cap, "true")) .yes else if (std.ascii.eqlIgnoreCase(cap, "false")) .no else return error.InvalidCapability;
        }
    }
    return .{ .sku = result };
}
fn usage(value: std.json.Value) !Model {
    const current = try c.integer(u64, try field(value, "currentValue"));
    const limit = try c.integer(u64, try field(value, "limit"));
    if (!std.mem.eql(u8, try string(value, "unit"), "Count")) return error.InvalidQuotaUnit;
    return .{ .usage = .{ .name = try string(try field(value, "name"), "value"), .current = current, .limit = limit } };
}
fn quota(a: std.mem.Allocator, authority: s.Authority, name: []const u8, value: std.json.Value) !Model {
    const plan = try ops.Plan.create(a, authority, .{ .quota = name });
    const properties = try field(value, "properties");
    const limit = try field(properties, "limit");
    if (!std.ascii.eqlIgnoreCase(try string(value, "id"), plan.path) or
        !std.ascii.eqlIgnoreCase(try string(value, "type"), "Microsoft.Quota/Quotas") or
        !std.mem.eql(u8, try string(value, "name"), name) or
        !std.mem.eql(u8, try string(try field(properties, "name"), "value"), name) or
        !std.mem.eql(u8, try string(properties, "unit"), "Count") or
        !try boolean(try field(properties, "isQuotaApplicable")) or
        !std.mem.eql(u8, try string(limit, "limitObjectType"), "LimitValue")) return error.InvalidQuota;
    return .{ .quota = try c.integer(u64, try field(limit, "value")) };
}

fn resource(a: std.mem.Allocator, authority: s.Authority, kind: s.Kind, expected: ?s.Ref, value: std.json.Value) !Model {
    const id = try ownedId(a, authority, try string(value, "id"));
    if (id.kind != kind) return error.WrongResourceKind;
    if (expected) |ref| try ref.requireId(a, authority, try string(value, "id"));
    if (!std.mem.eql(u8, try string(value, "name"), id.name)) return error.ResourceNameMismatch;
    if (kind != .subnet and kind != .deployment and !std.mem.eql(u8, try string(value, "location"), authority.location)) return error.LocationMismatch;
    const properties = try field(value, "properties");
    return switch (kind) {
        .group => parseGroup(authority, value, properties),
        .deployment => .{ .deployment = try state(try field(properties, "provisioningState")) },
        .vm => vm(a, authority, id, properties),
        .disk => parseDisk(id, value, properties),
        .storage => storage(a, authority, id, value, properties),
        .nic, .nsg, .vnet, .subnet => network(a, authority, id, properties),
        .image, .gallery_image => .{ .image = .{
            .id = id,
            .generation2 = try generation2(try string(properties, "hyperVGeneration")),
            .specialized_linux = try specializedLinux(if (kind == .image)
                try field(try field(properties, "storageProfile"), "osDisk")
            else
                properties),
            .state = try state(try field(properties, "provisioningState")),
        } },
        .gallery_version => imageVersion(authority, id, properties),
        .schedule => parseSchedule(a, authority, id, properties),
    };
}
fn specializedLinux(properties: std.json.Value) !bool {
    const os = try string(properties, "osType");
    const mode = try string(properties, "osState");
    if ((!std.mem.eql(u8, os, "Linux") and !std.mem.eql(u8, os, "Windows")) or
        (!std.mem.eql(u8, mode, "Specialized") and !std.mem.eql(u8, mode, "Generalized"))) return error.InvalidImage;
    return std.mem.eql(u8, os, "Linux") and std.mem.eql(u8, mode, "Specialized");
}
fn parseGroup(authority: s.Authority, value: std.json.Value, properties: std.json.Value) !Model {
    if (!std.mem.eql(u8, try string(try field(value, "tags"), "uk-hyperv-run"), &authority.owner_run)) return error.OwnershipMismatch;
    return .{ .group = try state(try field(properties, "provisioningState")) };
}
fn vm(a: std.mem.Allocator, authority: s.Authority, id: s.Ref, properties: std.json.Value) !Model {
    if (!std.mem.eql(u8, try string(try field(properties, "securityProfile"), "securityType"), "Standard")) return error.SecurityMismatch;
    const storage_profile = try field(properties, "storageProfile");
    const os_disk = try ownedId(a, authority, try string(try field(try field(storage_profile, "osDisk"), "managedDisk"), "id"));
    if (os_disk.kind != .disk) return error.WrongResourceKind;
    const data_disks = try array(try field(storage_profile, "dataDisks"));
    if (data_disks.len > 1) return error.InvalidGeometry;
    var data_disk: ?s.Ref = null;
    if (data_disks.len == 1) {
        const item = data_disks[0];
        if (try c.integer(u8, try field(item, "lun")) != 7 or
            !std.mem.eql(u8, try string(item, "caching"), "None")) return error.InvalidGeometry;
        if (item.object.get("diskSizeGB")) |size| if (try c.integer(u32, size) != 4) return error.InvalidGeometry;
        data_disk = try ownedId(a, authority, try string(try field(item, "managedDisk"), "id"));
        if (data_disk.?.kind != .disk or std.ascii.eqlIgnoreCase(data_disk.?.name, os_disk.name)) return error.InvalidGeometry;
    }
    const nics = try array(try field(try field(properties, "networkProfile"), "networkInterfaces"));
    if (nics.len != 1) return error.InvalidNetwork;
    const nic = try ownedId(a, authority, try string(nics[0], "id"));
    if (nic.kind != .nic) return error.InvalidNetwork;
    return .{ .vm = .{
        .id = id,
        .uuid = try s.uuid(try string(properties, "vmId")),
        .size = try string(try field(properties, "hardwareProfile"), "vmSize"),
        .os_disk = os_disk,
        .nic = nic,
        .data_disk = data_disk,
        .state = try state(try field(properties, "provisioningState")),
    } };
}
fn parseDisk(id: s.Ref, root: std.json.Value, properties: std.json.Value) !Model {
    const size = try c.integer(u32, try field(properties, "diskSizeGB"));
    if (size == 0 or size > 32 or try c.integer(u16, try field(properties, "logicalSectorSize")) != 512 or
        !std.mem.eql(u8, try string(try field(root, "sku"), "name"), "StandardSSD_LRS")) return error.InvalidGeometry;
    const raw_access = try string(properties, "diskState");
    const access: DiskAccess = access: {
        inline for (.{ "Unattached", "Attached", "Reserved", "Frozen", "ActiveSAS", "ReadyToUpload", "ActiveUpload" }, 0..) |name, i|
            if (std.mem.eql(u8, raw_access, name)) break :access @enumFromInt(i);
        return error.InvalidDiskState;
    };
    const creation = try field(properties, "creationData");
    const option = try string(creation, "createOption");
    var known = false;
    inline for (.{ "Empty", "Upload", "FromImage", "Copy", "Import", "Restore" }) |name|
        if (std.mem.eql(u8, option, name)) {
            known = true;
        };
    if (!known) return error.InvalidCreationOption;
    const upload_bytes: ?u64 = if (std.mem.eql(u8, option, "Upload"))
        try c.integer(u64, try field(creation, "uploadSizeBytes"))
    else
        null;
    if (upload_bytes) |bytes| try ops.uploadGeometry(size, bytes);
    var logical_bytes = if (upload_bytes) |bytes| bytes - 512 else @as(u64, size) * 1024 * 1024 * 1024;
    if (properties.object.get("diskSizeBytes")) |raw| {
        const actual = try c.integer(u64, raw);
        if (actual > 32 * @as(u64, 1024 * 1024 * 1024) or (upload_bytes != null and actual != logical_bytes))
            return error.InvalidGeometry;
        try ops.uploadGeometry(size, actual + 512);
        logical_bytes = actual;
    }
    return .{ .disk = .{
        .id = id,
        .uuid = try s.uuid(try string(properties, "uniqueId")),
        .bytes = logical_bytes,
        .linux_gen2 = linuxGen2(properties),
        .sector_size = 512,
        .state = try state(try field(properties, "provisioningState")),
        .access = access,
        .upload_bytes = upload_bytes,
    } };
}
fn linuxGen2(properties: std.json.Value) bool {
    const os = properties.object.get("osType") orelse return false;
    const generation = properties.object.get("hyperVGeneration") orelse return false;
    return os == .string and generation == .string and std.mem.eql(u8, os.string, "Linux") and std.mem.eql(u8, generation.string, "V2");
}
fn storage(a: std.mem.Allocator, authority: s.Authority, id: s.Ref, root: std.json.Value, properties: std.json.Value) !Model {
    if (!try boolean(try field(properties, "supportsHttpsTrafficOnly")) or try boolean(try field(properties, "allowBlobPublicAccess")) or
        !std.mem.eql(u8, try string(properties, "minimumTlsVersion"), "TLS1_2") or
        !std.mem.eql(u8, try string(root, "kind"), "StorageV2") or
        !std.mem.eql(u8, try string(try field(root, "sku"), "name"), "Standard_LRS")) return error.InvalidStorageSecurity;
    const access = try string(properties, "publicNetworkAccess");
    if (!std.mem.eql(u8, access, "Enabled") and !std.mem.eql(u8, access, "Disabled")) return error.InvalidStorageSecurity;
    const rules = try field(properties, "networkAcls");
    if (!std.mem.eql(u8, try string(rules, "defaultAction"), "Deny") or !std.mem.eql(u8, try string(rules, "bypass"), "None")) return error.InvalidFirewall;
    const ips = try array(try field(rules, "ipRules"));
    if (ips.len > 1) return error.InvalidFirewall;
    var ip: ?[4]u8 = null;
    if (ips.len == 1) {
        if (!std.mem.eql(u8, try string(ips[0], "action"), "Allow")) return error.InvalidFirewall;
        ip = try ipv4(try string(ips[0], "value"));
        try ops.publicIp(ip.?);
    }
    const subnets = try array(try field(rules, "virtualNetworkRules"));
    if (subnets.len > 4) return error.InvalidFirewall;
    const subnet_refs = try a.alloc(s.Ref, subnets.len);
    for (subnets, 0..) |rule, i| {
        const subnet = try ownedId(a, authority, try string(rule, "id"));
        if (subnet.kind != .subnet or !std.mem.eql(u8, try string(rule, "action"), "Allow")) return error.InvalidFirewall;
        for (subnet_refs[0..i]) |previous| if (std.ascii.eqlIgnoreCase(try subnet.path(a, authority), try previous.path(a, authority))) return error.InvalidFirewall;
        subnet_refs[i] = subnet;
    }
    if (rules.object.get("resourceAccessRules")) |extra| if ((try array(extra)).len != 0) return error.InvalidFirewall;
    return .{ .storage = .{
        .id = id,
        .public_network = std.mem.eql(u8, access, "Enabled"),
        .ip = ip,
        .subnet_rules = subnets.len,
        .subnets = subnet_refs,
        .state = try state(try field(properties, "provisioningState")),
    } };
}
fn network(a: std.mem.Allocator, authority: s.Authority, id: s.Ref, properties: std.json.Value) !Model {
    var entries: usize = 0;
    switch (id.kind) {
        .nic => {
            if (try boolean(try field(properties, "enableIPForwarding"))) return error.InvalidNetwork;
            const configs = try array(try field(properties, "ipConfigurations"));
            if (configs.len != 1) return error.InvalidNetwork;
            const config = try field(configs[0], "properties");
            if (config != .object) return error.ExpectedObject;
            if (config.object.get("publicIPAddress")) |public| if (public != .null) return error.PublicAddressForbidden;
            _ = try ipv4(try string(config, "privateIPAddress"));
            const subnet = try ownedId(a, authority, try string(try field(config, "subnet"), "id"));
            if (subnet.kind != .subnet) return error.InvalidNetwork;
            entries = 1;
        },
        .vnet => {
            const prefixes = try array(try field(try field(properties, "addressSpace"), "addressPrefixes"));
            if (prefixes.len == 0 or prefixes.len > 4) return error.InvalidNetwork;
            for (prefixes) |prefix| try cidr(try c.string(prefix));
            const subnets = try array(try field(properties, "subnets"));
            for (subnets) |subnet| {
                const ref = try ownedId(a, authority, try string(subnet, "id"));
                if (ref.kind != .subnet or !std.mem.eql(u8, ref.parent.?, id.name)) return error.InvalidNetwork;
                try cidr(try string(try field(subnet, "properties"), "addressPrefix"));
            }
            entries = subnets.len;
        },
        .subnet => {
            try cidr(try string(properties, "addressPrefix"));
            entries = (try array(try field(properties, "serviceEndpoints"))).len;
        },
        .nsg => {
            const rules = try array(try field(properties, "securityRules"));
            if (rules.len > 32) return error.InvalidNetwork;
            var priorities: [32]u16 = undefined;
            for (rules, 0..) |rule, i| {
                const p = try field(rule, "properties");
                const priority = try c.integer(u16, try field(p, "priority"));
                if (priority < 100 or priority > 4096) return error.InvalidNetwork;
                for (priorities[0..i]) |previous| if (previous == priority) return error.InvalidNetwork;
                priorities[i] = priority;
                const direction = try string(p, "direction");
                const access = try string(p, "access");
                if ((!std.mem.eql(u8, direction, "Inbound") and !std.mem.eql(u8, direction, "Outbound")) or
                    (!std.mem.eql(u8, access, "Allow") and !std.mem.eql(u8, access, "Deny"))) return error.InvalidNetwork;
                inline for (.{ "protocol", "sourceAddressPrefix", "destinationAddressPrefix", "sourcePortRange", "destinationPortRange" }) |name|
                    _ = try string(p, name);
            }
            entries = rules.len;
        },
        else => return error.InvalidNetwork,
    }
    return .{ .network = .{ .id = id, .entries = entries, .state = if (properties.object.get("provisioningState")) |value| try state(value) else null } };
}

pub fn requirePersistenceNetwork(a: std.mem.Allocator, authority: s.Authority, definition: ops.PersistenceNetwork, value: std.json.Value) !void {
    try persistenceNetwork(a, authority, definition, value, true);
}
/// Cleanup ownership is independent of provisioning success; a failed but
/// scope-bound, correctly tagged/configured resource must remain deletable.
pub fn requireOwnedPersistenceNetwork(a: std.mem.Allocator, authority: s.Authority, definition: ops.PersistenceNetwork, value: std.json.Value) !void {
    try persistenceNetwork(a, authority, definition, value, false);
}
fn persistenceNetwork(a: std.mem.Allocator, authority: s.Authority, definition: ops.PersistenceNetwork, value: std.json.Value, ready: bool) !void {
    const ref = try definition.ref(a);
    _ = try resource(a, authority, ref.kind, ref, value);
    if (!std.mem.eql(u8, try string(try field(value, "tags"), "uk-hyperv-run"), &authority.owner_run))
        return error.ScopeMismatch;
    const p = try field(value, "properties");
    const provisioning = try state(try field(p, "provisioningState"));
    if (ready and provisioning != .succeeded) return error.InvalidNetwork;
    switch (definition.kind) {
        .nsg => if ((try array(try field(p, "securityRules"))).len != 0) return error.InvalidNetwork,
        .vnet => {
            const prefixes = try array(try field(try field(p, "addressSpace"), "addressPrefixes"));
            const subnets = try array(try field(p, "subnets"));
            if (prefixes.len != 1 or subnets.len != 1 or !std.mem.eql(u8, try c.string(prefixes[0]), "10.79.0.0/29") or
                !std.mem.eql(u8, try string(subnets[0], "name"), "default")) return error.InvalidNetwork;
            const subnet = try field(subnets[0], "properties");
            if (!std.mem.eql(u8, try string(subnet, "addressPrefix"), "10.79.0.0/29") or
                try boolean(try field(subnet, "defaultOutboundAccess"))) return error.InvalidNetwork;
            const nsg: s.Ref = .{ .kind = .nsg, .name = try std.fmt.allocPrint(a, "{s}-nsg", .{definition.prefix}) };
            try nsg.requireId(a, authority, try string(try field(subnet, "networkSecurityGroup"), "id"));
            if (subnet.object.get("natGateway")) |nat| if (nat != .null) return error.InvalidNetwork;
            if (subnet.object.get("routeTable")) |route| if (route != .null) return error.InvalidNetwork;
            if (subnet.object.get("serviceEndpoints")) |endpoints| if ((try array(endpoints)).len != 0) return error.InvalidNetwork;
        },
        .nic => {
            if (try boolean(try field(p, "enableAcceleratedNetworking"))) return error.InvalidNetwork;
            const configurations = try array(try field(p, "ipConfigurations"));
            const configuration = try field(configurations[0], "properties");
            if (!std.mem.eql(u8, try string(configurations[0], "name"), "primary") or
                !std.mem.eql(u8, try string(configuration, "privateIPAllocationMethod"), "Dynamic")) return error.InvalidNetwork;
            inline for (.{ "loadBalancerBackendAddressPools", "loadBalancerInboundNatRules", "applicationGatewayBackendAddressPools" }) |relationship| {
                if (configuration.object.get(relationship)) |associations|
                    if ((try array(associations)).len != 0) return error.InvalidNetwork;
            }
            const subnet: s.Ref = .{ .kind = .subnet, .name = "default", .parent = try std.fmt.allocPrint(a, "{s}-vnet", .{definition.prefix}) };
            try subnet.requireId(a, authority, try string(try field(configuration, "subnet"), "id"));
        },
    }
}
fn parseSchedule(a: std.mem.Allocator, authority: s.Authority, id: s.Ref, properties: std.json.Value) !Model {
    if (!std.mem.eql(u8, try string(properties, "taskType"), "ComputeVmShutdownTask")) return error.InvalidSchedule;
    const status = try string(properties, "status");
    if (!std.mem.eql(u8, status, "Enabled") and !std.mem.eql(u8, status, "Disabled")) return error.InvalidSchedule;
    const target = try ownedId(a, authority, try string(properties, "targetResourceId"));
    if (target.kind != .vm or !std.mem.eql(u8, try string(properties, "timeZoneId"), "UTC")) return error.InvalidSchedule;
    const time = try string(try field(properties, "dailyRecurrence"), "time");
    if (time.len != 4) return error.InvalidSchedule;
    for (time) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidSchedule;
    if (try std.fmt.parseInt(u8, time[0..2], 10) > 23 or try std.fmt.parseInt(u8, time[2..], 10) > 59) return error.InvalidSchedule;
    if (!std.mem.eql(u8, try string(try field(properties, "notificationSettings"), "status"), "Disabled"))
        return error.InvalidSchedule;
    return .{ .schedule = .{ .id = id, .vm = target, .enabled = std.mem.eql(u8, status, "Enabled"), .time = time[0..4].* } };
}
fn emptyAction(value: std.json.Value) !Model {
    if (value != .object) return error.InvalidActionResponse;
    if (value.object.count() == 0) return .empty;
    if (value.object.get("error")) |err| if (err != .null) return error.RemoteFailed;
    if (value.object.get("status")) |status| {
        if (try state(status) == .succeeded) return .empty;
    }
    return error.InvalidActionResponse;
}
fn power(value: std.json.Value) !Model {
    var found: ?Model = null;
    for (try array(try field(value, "statuses"))) |status| {
        const code = try string(status, "code");
        if (std.mem.eql(u8, code, "ProvisioningState/failed")) return error.RemoteFailed;
        if (!std.mem.startsWith(u8, code, "PowerState/")) continue;
        if (found != null) return error.DuplicatePowerState;
        const T = @FieldType(Model, "power");
        found = .{ .power = std.meta.stringToEnum(T, code["PowerState/".len..]) orelse return error.InvalidPowerState };
    }
    return found orelse error.MissingPowerState;
}
fn keys(value: std.json.Value) !Model {
    const items = try array(try field(value, "keys"));
    if (items.len != 2) return error.InvalidKeys;
    var result: Keys = .{ .key1 = "", .key2 = "" };
    for (items) |key| {
        const name = try string(key, "keyName");
        if (!std.mem.eql(u8, try string(key, "permissions"), "FULL")) return error.InvalidKeys;
        const bytes = try string(key, "value");
        if (try std.base64.standard.Decoder.calcSizeForSlice(bytes) != 64) return error.InvalidKeys;
        var decoded: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &decoded);
        try std.base64.standard.Decoder.decode(&decoded, bytes);
        var canonical: [88]u8 = undefined;
        defer std.crypto.secureZero(u8, &canonical);
        if (!std.mem.eql(u8, bytes, std.base64.standard.Encoder.encode(&canonical, &decoded))) return error.InvalidKeys;
        if (std.mem.eql(u8, name, "key1")) {
            if (result.key1.len != 0) return error.InvalidKeys;
            result.key1 = bytes;
        } else if (std.mem.eql(u8, name, "key2")) {
            if (result.key2.len != 0) return error.InvalidKeys;
            result.key2 = bytes;
        } else return error.InvalidKeys;
    }
    if (result.key1.len == 0 or result.key2.len == 0 or std.mem.eql(u8, result.key1, result.key2)) return error.InvalidKeys;
    return .{ .keys = result };
}
fn grant(value: std.json.Value) !Model {
    const fields = try c.exactFields(value, &.{"accessSAS"});
    const sas = try c.string(fields.get("accessSAS").?);
    try sasUri(sas, true);
    return .{ .grant = sas };
}
fn boot(value: std.json.Value) !Model {
    const serial = try string(value, "serialConsoleLogBlobUri");
    try sasUri(serial, false);
    var screenshot: ?[]const u8 = null;
    if (value.object.get("consoleScreenshotBlobUri")) |uri| {
        if (uri != .null) {
            screenshot = try c.string(uri);
            try sasUri(screenshot.?, false);
        }
    }
    return .{ .boot = .{ .serial = serial, .screenshot = screenshot } };
}

pub fn sasUri(raw: []const u8, disk: bool) !void {
    if (raw.len > 8192 or !std.mem.startsWith(u8, raw, "https://") or std.mem.indexOfAny(u8, raw, "#\\\r\n\t ") != null) return error.InvalidSas;
    const slash = std.mem.indexOfScalarPos(u8, raw, 8, '/') orelse return error.InvalidSas;
    const authority = raw[8..slash];
    if (std.mem.indexOfAny(u8, authority, "@%") != null) return error.InvalidSas;
    const colon = std.mem.indexOfScalar(u8, authority, ':');
    const host = authority[0 .. colon orelse authority.len];
    if (host.len > 253 or !(std.mem.endsWith(u8, host, ".blob.core.windows.net") or (disk and std.mem.endsWith(u8, host, ".blob.storage.azure.net"))))
        return error.InvalidSas;
    for (host) |ch| if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '.' and ch != '-') return error.InvalidSas;
    if (colon) |port| if (!std.mem.eql(u8, authority[port + 1 ..], "443") and !(disk and std.mem.eql(u8, authority[port + 1 ..], "8443"))) return error.InvalidSas;
    const question = std.mem.indexOfScalarPos(u8, raw, slash + 1, '?') orelse return error.InvalidSas;
    if (question == slash + 1 or std.mem.indexOf(u8, raw[slash..question], "..") != null) return error.InvalidSas;
    var pairs = std.mem.splitScalar(u8, raw[question + 1 ..], '&');
    var signature = false;
    while (pairs.next()) |pair| {
        if (std.mem.startsWith(u8, pair, "sig=")) {
            if (signature or pair.len <= 4) return error.InvalidSas;
            signature = true;
        }
    }
    if (!signature) return error.InvalidSas;
}

pub fn ownedId(a: std.mem.Allocator, authority: s.Authority, raw: []const u8) !s.Ref {
    const group = try authority.groupPath(a);
    if (std.ascii.eqlIgnoreCase(raw, group)) return .{ .kind = .group, .name = authority.group };
    if (raw.len <= group.len or !std.ascii.eqlIgnoreCase(raw[0..group.len], group) or raw[group.len] != '/') return error.ScopeMismatch;
    var parts = std.mem.splitScalar(u8, raw[group.len + 1 ..], '/');
    var segments: [8][]const u8 = undefined;
    var count: usize = 0;
    while (parts.next()) |part| {
        if (count == segments.len) return error.ScopeMismatch;
        try s.name(part);
        segments[count] = part;
        count += 1;
    }
    if (count < 4 or !std.ascii.eqlIgnoreCase(segments[0], "providers")) return error.ScopeMismatch;
    inline for (std.meta.tags(s.Kind)) |kind| {
        if (kind != .group and kind != .subnet and kind != .gallery_image and kind != .gallery_version and count == 4 and
            std.ascii.eqlIgnoreCase(kind.provider(), segments[1]) and std.ascii.eqlIgnoreCase(kind.resourceType(), segments[2]))
            return .{ .kind = kind, .name = segments[3] };
    }
    if (count == 6 and std.ascii.eqlIgnoreCase(segments[1], "Microsoft.Network") and
        std.ascii.eqlIgnoreCase(segments[2], "virtualNetworks") and std.ascii.eqlIgnoreCase(segments[4], "subnets"))
        return .{ .kind = .subnet, .parent = segments[3], .name = segments[5] };
    if (count == 8 and std.ascii.eqlIgnoreCase(segments[1], "Microsoft.Compute") and
        std.ascii.eqlIgnoreCase(segments[2], "galleries") and std.ascii.eqlIgnoreCase(segments[4], "images") and
        std.ascii.eqlIgnoreCase(segments[6], "versions"))
        return .{ .kind = .gallery_version, .parent = segments[3], .gallery_image = segments[5], .name = segments[7] };
    if (count == 6 and std.ascii.eqlIgnoreCase(segments[1], "Microsoft.Compute") and
        std.ascii.eqlIgnoreCase(segments[2], "galleries") and std.ascii.eqlIgnoreCase(segments[4], "images"))
        return .{ .kind = .gallery_image, .parent = segments[3], .name = segments[5] };
    return error.UnexpectedResource;
}
pub fn ipv4(raw: []const u8) ![4]u8 {
    var parts = std.mem.splitScalar(u8, raw, '.');
    var result: [4]u8 = undefined;
    for (&result) |*octet| octet.* = std.math.cast(u8, try wire.unsigned(parts.next() orelse return error.InvalidAddress)) orelse return error.InvalidAddress;
    if (parts.next() != null) return error.InvalidAddress;
    return result;
}
fn cidr(raw: []const u8) !void {
    const slash = std.mem.indexOfScalar(u8, raw, '/') orelse return error.InvalidAddress;
    _ = try ipv4(raw[0..slash]);
    if (try wire.unsigned(raw[slash + 1 ..]) > 32) return error.InvalidAddress;
}

fn memoryMiB(raw: []const u8) !u32 {
    const dot = std.mem.indexOfScalar(u8, raw, '.');
    const whole = try wire.unsigned(raw[0 .. dot orelse raw.len]);
    if (whole > 1_048_576) return error.InvalidCapability;
    var total = whole * 1024;
    if (dot) |position| {
        const fraction = raw[position + 1 ..];
        if (fraction.len == 0 or fraction.len > 4) return error.InvalidCapability;
        var numerator: u64 = 0;
        var denominator: u64 = 1;
        for (fraction) |digit| {
            if (!std.ascii.isDigit(digit)) return error.InvalidCapability;
            numerator = numerator * 10 + digit - '0';
            denominator *= 10;
        }
        if ((numerator * 1024) % denominator != 0) return error.InvalidCapability;
        total += numerator * 1024 / denominator;
    }
    return std.math.cast(u32, total) orelse error.InvalidCapability;
}
fn generation2(raw: []const u8) !bool {
    if (std.mem.eql(u8, raw, "V2")) return true;
    if (std.mem.eql(u8, raw, "V1")) return false;
    return error.InvalidGeneration;
}
fn imageVersion(authority: s.Authority, id: s.Ref, properties: std.json.Value) !Model {
    const publishing = try field(properties, "publishingProfile");
    const published = try string(publishing, "publishedDate");
    if (published.len == 0) return error.UnpublishedImage;
    var in_location = false;
    for (try array(try field(publishing, "targetRegions"))) |region| {
        if (std.mem.eql(u8, try string(region, "name"), authority.location)) in_location = true;
    }
    _ = try field(properties, "storageProfile");
    return .{ .image_version = .{
        .id = id,
        .state = try state(try field(properties, "provisioningState")),
        .in_location = in_location,
        .published = published,
    } };
}
