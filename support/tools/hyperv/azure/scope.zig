const std = @import("std");
const contracts = @import("hyperv_core").contracts;

pub const arm_host = "https://management.azure.com";
pub const login_host = "https://login.microsoftonline.com";
pub const arm_scope = arm_host ++ "/.default";
pub const arm_resource = arm_host;
pub const Uuid = [36]u8;

pub fn uuid(source: []const u8) !Uuid {
    _ = try contracts.parseUuid(source);
    if (std.mem.eql(u8, source, "00000000-0000-0000-0000-000000000000")) return error.InvalidIdentity;
    return source[0..36].*;
}

pub fn name(source: []const u8) !void {
    if (source.len == 0 or source.len > 80 or !std.ascii.isAlphanumeric(source[0]) or
        !std.ascii.isAlphanumeric(source[source.len - 1])) return error.InvalidName;
    for (source) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return error.InvalidName;
    if (std.mem.indexOf(u8, source, "..") != null) return error.InvalidName;
}

pub fn location(source: []const u8) !void {
    if (source.len == 0 or source.len > 32) return error.InvalidLocation;
    for (source) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return error.InvalidLocation;
}

pub const Authority = struct {
    tenant: Uuid,
    subscription: Uuid,
    principal: Uuid,
    client: Uuid,
    group: []const u8,
    location: []const u8,
    owner_run: Uuid,

    pub fn validate(self: Authority) !void {
        inline for (.{ "tenant", "subscription", "principal", "client", "owner_run" }) |field|
            _ = try uuid(&@field(self, field));
        try name(self.group);
        try location(self.location);
    }

    pub fn groupPath(self: Authority, allocator: std.mem.Allocator) ![]u8 {
        try self.validate();
        return std.fmt.allocPrint(allocator, "/subscriptions/{s}/resourceGroups/{s}", .{ self.subscription, self.group });
    }
};

pub const Kind = enum {
    group,
    deployment,
    vm,
    disk,
    nic,
    nsg,
    vnet,
    subnet,
    storage,
    schedule,
    image,
    gallery_image,
    gallery_version,

    pub fn provider(self: Kind) []const u8 {
        return switch (self) {
            .group, .deployment => "Microsoft.Resources",
            .vm, .disk, .image, .gallery_image, .gallery_version => "Microsoft.Compute",
            .nic, .nsg, .vnet, .subnet => "Microsoft.Network",
            .storage => "Microsoft.Storage",
            .schedule => "Microsoft.DevTestLab",
        };
    }

    pub fn resourceType(self: Kind) []const u8 {
        return switch (self) {
            .group => "resourceGroups",
            .deployment => "deployments",
            .vm => "virtualMachines",
            .disk => "disks",
            .nic => "networkInterfaces",
            .nsg => "networkSecurityGroups",
            .vnet, .subnet => "virtualNetworks",
            .storage => "storageAccounts",
            .schedule => "schedules",
            .image => "images",
            .gallery_image, .gallery_version => "galleries",
        };
    }

    pub fn version(self: Kind) []const u8 {
        return switch (self) {
            .group, .deployment => "2021-04-01",
            .vm, .image => "2025-11-01",
            .disk => "2025-01-02",
            .gallery_image, .gallery_version => "2025-03-03",
            .nic, .nsg, .vnet, .subnet => "2024-05-01",
            .storage => "2023-05-01",
            .schedule => "2018-09-15",
        };
    }
};

pub const Ref = struct {
    kind: Kind,
    name: []const u8,
    parent: ?[]const u8 = null,
    gallery_image: ?[]const u8 = null,

    pub fn path(self: Ref, allocator: std.mem.Allocator, authority: Authority) ![]u8 {
        try authority.validate();
        try name(self.name);
        if (self.kind == .storage) {
            if (self.name.len < 3 or self.name.len > 24) return error.InvalidName;
            for (self.name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return error.InvalidName;
        }
        if (self.kind == .group) {
            if (!std.mem.eql(u8, self.name, authority.group) or self.parent != null or self.gallery_image != null)
                return error.ScopeMismatch;
            return authority.groupPath(allocator);
        }
        const group = try authority.groupPath(allocator);
        defer allocator.free(group);
        if (self.kind == .subnet) {
            const vnet = self.parent orelse return error.InvalidName;
            try name(vnet);
            if (self.gallery_image != null) return error.InvalidName;
            return std.fmt.allocPrint(allocator, "{s}/providers/Microsoft.Network/virtualNetworks/{s}/subnets/{s}", .{ group, vnet, self.name });
        }
        if (self.kind == .gallery_image) {
            const gallery = self.parent orelse return error.InvalidName;
            try name(gallery);
            if (self.gallery_image != null) return error.InvalidName;
            return std.fmt.allocPrint(allocator, "{s}/providers/Microsoft.Compute/galleries/{s}/images/{s}", .{ group, gallery, self.name });
        }
        if (self.kind == .gallery_version) {
            const gallery = self.parent orelse return error.InvalidName;
            const image = self.gallery_image orelse return error.InvalidName;
            try name(gallery);
            try name(image);
            if (std.ascii.eqlIgnoreCase(self.name, "latest")) return error.UnpinnedImage;
            return std.fmt.allocPrint(allocator, "{s}/providers/Microsoft.Compute/galleries/{s}/images/{s}/versions/{s}", .{ group, gallery, image, self.name });
        }
        if (self.parent != null or self.gallery_image != null) return error.InvalidName;
        return std.fmt.allocPrint(allocator, "{s}/providers/{s}/{s}/{s}", .{ group, self.kind.provider(), self.kind.resourceType(), self.name });
    }

    pub fn requireId(self: Ref, allocator: std.mem.Allocator, authority: Authority, raw: []const u8) !void {
        const expected = try self.path(allocator, authority);
        defer allocator.free(expected);
        if (!std.ascii.eqlIgnoreCase(expected, raw)) return error.ScopeMismatch;
    }
};

pub fn relativeUrl(raw: []const u8) ![]const u8 {
    if (raw.len == 0 or raw.len > 4096 or std.mem.indexOfAny(u8, raw, "#\\\r\n\t ") != null) return error.UnsafeUrl;
    for (raw) |byte| if (byte < 0x21 or byte > 0x7e) return error.UnsafeUrl;
    const path = if (std.mem.startsWith(u8, raw, arm_host ++ "/")) raw[arm_host.len..] else if (raw[0] == '/' and
        (raw.len == 1 or raw[1] != '/')) raw else return error.UnsafeUrl;
    const query = std.mem.indexOfScalar(u8, path, '?') orelse return error.MissingApiVersion;
    if (std.mem.indexOfAny(u8, path[0..query], "%@") != null or
        std.mem.indexOf(u8, path[0..query], "..") != null or
        std.mem.indexOf(u8, path[0..query], "//") != null) return error.UnsafeUrl;
    return path;
}

pub fn queryVersion(path: []const u8, expected: []const u8, pagination: bool) !void {
    return queryPolicy(path, expected, pagination, null);
}

const Filter = struct { allocator: std.mem.Allocator, expected: []const u8 };
fn queryPolicy(path: []const u8, expected: []const u8, pagination: bool, filter: ?Filter) !void {
    const start = std.mem.indexOfScalar(u8, path, '?') orelse return error.MissingApiVersion;
    var parts = std.mem.splitScalar(u8, path[start + 1 ..], '&');
    var version_seen = false;
    var continuation_seen = false;
    var filter_seen = false;
    var count: usize = 0;
    while (parts.next()) |part| {
        count += 1;
        if (count > 3) return error.UnsafeUrl;
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse return error.UnsafeUrl;
        const key = part[0..eq];
        const value = part[eq + 1 ..];
        if (value.len == 0 or std.mem.indexOfAny(u8, value, "?#") != null) return error.UnsafeUrl;
        if (std.mem.eql(u8, key, "api-version")) {
            if (version_seen or !std.mem.eql(u8, value, expected)) return error.UnsafeUrl;
            version_seen = true;
        } else if (pagination and (std.mem.eql(u8, key, "$skiptoken") or std.mem.eql(u8, key, "skiptoken"))) {
            if (continuation_seen) return error.UnsafeUrl;
            continuation_seen = true;
        } else if (filter != null and (std.mem.eql(u8, key, "$filter") or std.mem.eql(u8, key, "%24filter"))) {
            if (filter_seen) return error.UnsafeUrl;
            filter_seen = true;
            const copy = try filter.?.allocator.dupe(u8, value);
            defer filter.?.allocator.free(copy);
            for (copy) |*ch| if (ch.* == '+') {
                ch.* = ' ';
            };
            const decoded = try (std.Uri.Component{ .percent_encoded = copy }).toRawMaybeAlloc(filter.?.allocator);
            defer if (decoded.ptr != copy.ptr) filter.?.allocator.free(decoded);
            if (!std.mem.eql(u8, decoded, filter.?.expected)) return error.UnsafeUrl;
        } else return error.UnsafeUrl;
    }
    if (!version_seen) return error.MissingApiVersion;
    if (filter != null and !filter_seen) return error.UnsafeUrl;
}

pub fn continuation(allocator: std.mem.Allocator, original_path: []const u8, raw: []const u8, version: []const u8) ![]u8 {
    return continuationFiltered(allocator, original_path, raw, version, null);
}

pub fn continuationFiltered(allocator: std.mem.Allocator, original_path: []const u8, raw: []const u8, version: []const u8, filter: ?[]const u8) ![]u8 {
    const path = try relativeUrl(raw);
    try queryPolicy(path, version, true, if (filter) |expected| .{ .allocator = allocator, .expected = expected } else null);
    const end = std.mem.indexOfScalar(u8, path, '?').?;
    if (!std.ascii.eqlIgnoreCase(path[0..end], original_path)) return error.ScopeMismatch;
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ arm_host, path });
}
