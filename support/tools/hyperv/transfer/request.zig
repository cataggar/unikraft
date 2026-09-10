const std = @import("std");
const file_io = @import("files.zig");
const shared = @import("hyperv_core");
const contracts = shared.contracts;
const common = @import("azure_sdk_storage_common");

pub const schema = "unikraft.hyperv.private-preflight-blob-worker";
pub const maximum_request = 256 * 1024;
pub const maximum_file = 256 * 1024 * 1024;
pub const maximum_sas = 4096;
pub const maximum_disk_bytes = 4 * 1024 * 1024 * 1024 + 512;
pub const disk_schema = "unikraft.hyperv.managed-disk-page-worker";
pub const Action = enum { upload, download };
pub const Record = union(Action) {
    upload: struct { blob: []const u8, input: file_io.Input },
    download: struct { blob: []const u8, path: []const u8, maximum: u64 },
};
pub const Request = struct {
    allocator: std.mem.Allocator,
    document: contracts.SensitiveDocument,
    action: Action,
    account_url: []const u8,
    container: []const u8,
    create_container: bool,
    records: []Record,

    pub fn deinit(self: *Request) void {
        self.allocator.free(self.records);
        self.document.deinit();
        self.* = undefined;
    }

    pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Request {
        var raw = try file_io.readSensitive(io, allocator, path, maximum_request, null);
        defer raw.deinit();
        return parse(allocator, raw.bytes());
    }

    pub fn parse(allocator: std.mem.Allocator, raw: []const u8) !Request {
        const document = contracts.SensitiveDocument.parse(allocator, raw, .{ .bytes = maximum_request }) catch |err| {
            if (err == error.OutOfMemory) return err;
            return error.InvalidContract;
        };
        errdefer document.deinit();
        const value = document.value();
        try exact(value, &.{ "schema", "schema_version", "action", "account_url", "container", "files", "create_container" });
        if (!std.mem.eql(u8, try string(value, "schema"), schema) or try integer(value.object.get("schema_version").?, 1) != 1)
            return error.InvalidContract;
        const action = contracts.enumeration(Action, value.object.get("action").?) catch return error.InvalidContract;
        const account = try string(value, "account_url");
        const container = try string(value, "container");
        if (!validAccount(account) or !validContainer(container)) return error.InvalidContract;
        const create = value.object.get("create_container").?;
        if (create != .bool or (action == .download and create.bool)) return error.InvalidContract;
        const array = value.object.get("files").?;
        if (array != .array or array.array.items.len == 0 or array.array.items.len > 128) return error.InvalidContract;
        const records = try allocator.alloc(Record, array.array.items.len);
        errdefer allocator.free(records);
        for (array.array.items, 0..) |item, i| {
            const fields: []const []const u8 = switch (action) {
                .upload => &.{ "blob", "path", "size", "sha256" },
                .download => &.{ "blob", "path", "maximum" },
            };
            try exact(item, fields);
            const blob = try string(item, "blob");
            const path = try string(item, "path");
            if (!validBlob(blob) or !file_io.validPath(path)) return error.InvalidContract;
            records[i] = switch (action) {
                .upload => .{ .upload = .{ .blob = blob, .input = .{
                    .path = path,
                    .size = try integer(item.object.get("size").?, maximum_file),
                    .sha256 = try digest(try string(item, "sha256")),
                } } },
                .download => .{ .download = .{ .blob = blob, .path = path, .maximum = try integer(item.object.get("maximum").?, maximum_file) } },
            };
            for (records[0..i]) |previous| {
                const previous_blob = switch (previous) {
                    .upload => |p| p.blob,
                    .download => |p| p.blob,
                };
                const previous_path = switch (previous) {
                    .upload => |p| p.input.path,
                    .download => |p| p.path,
                };
                if (std.mem.eql(u8, previous_blob, blob) or std.mem.eql(u8, previous_path, path)) return error.InvalidContract;
            }
        }
        return .{
            .allocator = allocator,
            .document = document,
            .action = action,
            .account_url = account,
            .container = container,
            .create_container = create.bool,
            .records = records,
        };
    }
};

pub const DiskRequest = struct {
    document: contracts.SensitiveDocument,
    endpoint: []const u8,
    input: file_io.Input,

    pub fn deinit(self: *DiskRequest) void {
        self.document.deinit();
        self.* = undefined;
    }

    pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !DiskRequest {
        var raw = try file_io.readSensitive(io, allocator, path, maximum_request, null);
        defer raw.deinit();
        return parse(allocator, raw.bytes());
    }

    pub fn parse(allocator: std.mem.Allocator, raw: []const u8) !DiskRequest {
        const document = contracts.SensitiveDocument.parse(allocator, raw, .{ .bytes = maximum_request }) catch |err| {
            if (err == error.OutOfMemory) return err;
            return error.InvalidContract;
        };
        errdefer document.deinit();
        const value = document.value();
        try exact(value, &.{ "schema", "schema_version", "endpoint", "path", "size", "sha256" });
        if (!std.mem.eql(u8, try string(value, "schema"), disk_schema) or try integer(value.object.get("schema_version").?, 1) != 1)
            return error.InvalidContract;
        const endpoint = try string(value, "endpoint");
        const path = try string(value, "path");
        const size = try integer(value.object.get("size").?, maximum_disk_bytes);
        if (!validDiskEndpoint(endpoint) or !file_io.validPath(path) or size < 512 or size % 512 != 0)
            return error.InvalidContract;
        return .{
            .document = document,
            .endpoint = endpoint,
            .input = .{ .path = path, .size = size, .sha256 = try digest(try string(value, "sha256")) },
        };
    }
};

fn exact(value: std.json.Value, fields: []const []const u8) !void {
    _ = contracts.exactFields(value, fields) catch return error.InvalidContract;
}

fn string(value: std.json.Value, field: []const u8) ![]const u8 {
    const item = value.object.get(field) orelse return error.InvalidContract;
    return contracts.string(item) catch error.InvalidContract;
}

fn integer(value: std.json.Value, maximum: u64) !u64 {
    const result = contracts.integer(u64, value) catch return error.InvalidContract;
    return if (result <= maximum) result else error.InvalidContract;
}

pub fn digest(value: []const u8) ![32]u8 {
    return contracts.parseSha256(value) catch error.InvalidContract;
}

pub fn validAccount(value: []const u8) bool {
    const prefix = "https://";
    const suffix = ".blob.core.windows.net";
    if (!std.mem.startsWith(u8, value, prefix) or !std.mem.endsWith(u8, value, suffix) or value.len < prefix.len + suffix.len + 3)
        return false;
    const account = value[prefix.len .. value.len - suffix.len];
    if (account.len > 24) return false;
    for (account) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'z')) return false;
    return true;
}

pub fn validContainer(value: []const u8) bool {
    if (value.len < 3 or value.len > 63 or value[0] == '-' or value[value.len - 1] == '-' or std.mem.indexOf(u8, value, "--") != null) return false;
    for (value) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'z') and c != '-') return false;
    return true;
}

pub fn validBlob(value: []const u8) bool {
    if (value.len == 0 or value.len > 512 or !std.ascii.isAlphanumeric(value[0])) return false;
    for (value) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "._/-", c) == null) return false;
    var parts = std.mem.splitScalar(u8, value, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

pub fn validSas(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_sas) return false;
    for (value) |c| if (c <= 0x20 or c >= 0x7f or c == '?' or c == '#') return false;
    const allowed = [_][]const u8{
        "sv",    "ss",    "srt",  "sp",   "se",  "st",  "spr",   "sip",   "si",   "sr",  "sig",
        "skoid", "sktid", "skt",  "ske",  "sks", "skv", "saoid", "suoid", "scid", "ses", "rscc",
        "rscd",  "rsce",  "rscl", "rsct",
    };
    var seen: u32 = 0;
    var signature = false;
    var parameters = std.mem.splitScalar(u8, value, '&');
    while (parameters.next()) |parameter| {
        const equals = std.mem.indexOfScalar(u8, parameter, '=') orelse return false;
        const name = parameter[0..equals];
        const body = parameter[equals + 1 ..];
        var found = false;
        for (allowed, 0..) |key, index| {
            if (std.mem.eql(u8, name, key)) {
                const bit = @as(u32, 1) << @intCast(index);
                if (seen & bit != 0) return false;
                seen |= bit;
                found = true;
            }
        }
        if (!found) return false;
        if (std.mem.eql(u8, name, "sig")) signature = body.len > 0;
        var index: usize = 0;
        while (index < body.len) : (index += 1) {
            if (body[index] == '%') {
                if (index + 2 >= body.len or !std.ascii.isHex(body[index + 1]) or !std.ascii.isHex(body[index + 2])) return false;
                index += 2;
            }
        }
    }
    return signature;
}

/// SAS bytes arrive only in private memory or through this owner-only loader.
/// There is intentionally no argv/environment fallback or credential discovery.
pub fn loadSas(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !shared.sensitive.Buffer {
    var buffer = try file_io.readSensitive(io, allocator, path, maximum_sas, null);
    errdefer buffer.deinit();
    if (!validSas(buffer.bytes())) return error.InvalidContract;
    return buffer;
}

pub fn blobUri(allocator: std.mem.Allocator, account: []const u8, container: []const u8, blob: ?[]const u8, sas: []const u8) !common.sas.CompleteSasUri {
    if (!validAccount(account) or !validContainer(container) or !validSas(sas)) return error.InvalidContract;
    if (blob) |name| if (!validBlob(name)) return error.InvalidContract;
    const raw = if (blob) |name|
        try std.fmt.allocPrint(allocator, "{s}/{s}/{s}?{s}", .{ account, container, name, sas })
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}?{s}", .{ account, container, sas });
    defer {
        std.crypto.secureZero(u8, raw);
        allocator.free(raw);
    }
    return common.sas.CompleteSasUri.init(allocator, raw);
}

pub fn validDiskEndpoint(endpoint: []const u8) bool {
    if (!std.mem.startsWith(u8, endpoint, "https://") or endpoint.len > 2048) return false;
    if (std.mem.indexOfAny(u8, endpoint, "?#@\\") != null) return false;
    const slash = std.mem.indexOfScalarPos(u8, endpoint, 8, '/') orelse return false;
    const authority = endpoint[8..slash];
    const colon = std.mem.indexOfScalar(u8, authority, ':');
    const host = if (colon) |position| authority[0..position] else authority;
    if (colon) |position| {
        const port = authority[position + 1 ..];
        if (!std.mem.eql(u8, port, "443") and !std.mem.eql(u8, port, "8443")) return false;
    }
    var matched = false;
    for ([_][]const u8{ ".blob.core.windows.net", ".blob.storage.azure.net" }) |suffix| {
        if (host.len > suffix.len and std.mem.endsWith(u8, host, suffix)) matched = true;
    }
    if (!matched) return false;
    for (host) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'z') and c != '-' and c != '.') return false;
    if (host[0] == '.' or host[0] == '-' or std.mem.indexOf(u8, host, "..") != null) return false;
    return validBlob(endpoint[slash + 1 ..]);
}

pub fn diskUri(allocator: std.mem.Allocator, endpoint: []const u8, sas: []const u8) !common.sas.CompleteSasUri {
    if (!validDiskEndpoint(endpoint) or !validSas(sas)) return error.InvalidContract;
    const raw = try std.fmt.allocPrint(allocator, "{s}?{s}", .{ endpoint, sas });
    defer {
        std.crypto.secureZero(u8, raw);
        allocator.free(raw);
    }
    return common.sas.CompleteSasUri.init(allocator, raw);
}
