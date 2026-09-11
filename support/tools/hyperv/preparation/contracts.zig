const std = @import("std");
pub const core = @import("hyperv_core");
pub const c = core.contracts;
pub const Sha = [64]u8;
pub const Identity = [32]u8;
pub const miz_revision = "2db68ca0c3ab12155012a823c3fb8d7aba1cb544";
pub const compiler_version = "0.16.0";
pub const guest_target = "x86_64-freestanding-none";
pub const total_cap: u64 = 268435456;
pub const control_cap: u64 = 2097152;
pub const image_bytes: u64 = 66 * 1024 * 1024;

pub const File = struct { path: []const u8, sha256: Sha, size: u64, mode: u16 };
pub const Tree = struct { sha256: Sha, files: u32, bytes: u64 };
pub const Source = struct {
    scheme: enum { git_physical_native_v1 },
    head: []const u8,
    tree: []const u8,
    tree_sha256: Sha,
    physical: Tree,
};
pub const Phase = enum { prepared, configured, built, packaged };
pub const Purpose = enum { platform_preflight, persistence, synthetic };
pub const Failure = core.diagnostics.Failures;

pub fn digest(bytes: []const u8) Sha {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return std.fmt.bytesToHex(value, .lower);
}
pub fn sha(bytes: []const u8) !Sha {
    _ = try c.parseSha256(bytes);
    return bytes[0..64].*;
}
pub fn identity(bytes: []const u8) !Identity {
    if (bytes.len != 32) return error.InvalidIdentity;
    var nonzero = false;
    for (bytes) |ch| {
        if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return error.InvalidIdentity;
        nonzero = nonzero or ch != '0';
    }
    if (!nonzero) return error.InvalidIdentity;
    return bytes[0..32].*;
}
pub fn objectId(bytes: []const u8) !void {
    if (bytes.len != 40 and bytes.len != 64) return error.InvalidObjectId;
    for (bytes) |ch| if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return error.InvalidObjectId;
}
pub fn relative(path: []const u8) !void {
    if (path.len == 0 or path.len > 1024 or path[0] == '/') return error.UnsafePath;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        try core.private_files.basename(part);
        for (part) |ch| if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, "._+-@", ch) == null)
            return error.UnsafePath;
    }
}
pub fn same(a: anytype, b: @TypeOf(a)) bool {
    return std.meta.eql(a, b);
}
pub fn canonical(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    const doc = try c.Document.parse(allocator, raw, .{ .bytes = 4 * 1024 * 1024, .depth = 32, .items = 4096, .tokens = 65536, .string_bytes = 8192 });
    defer doc.deinit();
    return doc.canonicalAlloc(allocator);
}
pub fn parse(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    const doc = try c.Document.parse(allocator, bytes, .{ .bytes = 4 * 1024 * 1024, .depth = 32, .items = 4096, .tokens = 65536, .string_bytes = 8192 });
    defer doc.deinit();
    try doc.requireCanonical(allocator, bytes);
    try shape(T, doc.value());
    return std.json.parseFromValue(T, allocator, doc.value(), .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
}
fn shape(comptime T: type, value: std.json.Value) anyerror!void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            const fields = comptime fields: {
                var result: [info.fields.len][]const u8 = undefined;
                for (info.fields, 0..) |field, i| result[i] = field.name;
                break :fields result;
            };
            const object = try c.exactFields(value, &fields);
            inline for (info.fields) |field| try shape(field.type, object.get(field.name).?);
        },
        .optional => |info| if (value != .null) {
            try shape(info.child, value);
        },
        .pointer => |info| {
            if (info.size != .slice) @compileError("Only slice pointers belong in preparation contracts");
            if (info.child == u8) {
                _ = try c.string(value);
            } else {
                if (value != .array) return error.ExpectedArray;
                for (value.array.items) |item| try shape(info.child, item);
            }
        },
        .array => |info| {
            if (info.child == u8) {
                if ((try c.string(value)).len != info.len) return error.InvalidLength;
            } else {
                if (value != .array or value.array.items.len != info.len) return error.InvalidLength;
                for (value.array.items) |item| try shape(info.child, item);
            }
        },
        .int => _ = try c.integer(T, value),
        .bool => if (value != .bool) {
            return error.ExpectedBoolean;
        },
        .@"enum" => _ = try c.enumeration(T, value),
        else => @compileError("Unsupported preparation contract type"),
    }
}
pub fn failure(err: anyerror) Failure {
    return .{ .primary = .{ .stage = .admission, .category = switch (err) {
        error.WouldBlock => .contention,
        error.HashMismatch, error.SourceChanged, error.UnreviewedInput => .integrity,
        error.DependencyUnavailable => .unavailable,
        error.DeadlineExceeded => .timeout,
        error.UnsafePath, error.UnsafeFile => .unsafe_file,
        error.LimitExceeded, error.FileTooLarge => .output_limit,
        else => .invalid_input,
    } } };
}
