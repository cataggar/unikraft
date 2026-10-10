// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const contracts = @import("contracts.zig");

pub fn goldenRecord(a: std.mem.Allocator, name: []const u8) ![]const u8 {
    if (!@import("builtin").is_test) @compileError("Authority fixtures are test-only");
    var golden = try contracts.parseCanonical(a, @embedFile("goldens/contracts.json"));
    defer golden.deinit();
    const bytes = golden.value().object.get("canonical_records").?.object.get(name).?.string;
    var record = try contracts.parseCanonical(a, bytes);
    defer record.deinit();
    const allocator = record.parsed.arena.allocator();
    const root = &record.parsed.value.object;
    // Frozen wire fixtures use UID 1000; constructor policy requires the live
    // owner. Rebind only that identity and the resulting exact record bindings.
    if (root.getPtr("ledger")) |ledger| {
        ledger.object.getPtr("directory").?.object.getPtr("uid").?.* = .{
            .integer = core.private_files.hostUid(std.os.linux.geteuid()),
        };
    }
    if (root.getPtr("plan_sha256")) |digest| {
        const plan = try goldenRecord(a, "plan");
        defer a.free(plan);
        digest.* = .{ .string = try sha256(allocator, plan) };
    }
    if (root.getPtr("plan")) |artifact| {
        const plan = try goldenRecord(a, "plan");
        defer a.free(plan);
        try bind(allocator, artifact, plan);
    }
    if (root.getPtr("authorization")) |artifact| {
        const authorization = try goldenRecord(a, "authorization_approved");
        defer a.free(authorization);
        try bind(allocator, artifact, authorization);
    }
    return record.canonicalAlloc(a);
}

fn sha256(a: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    core.Sha256.hash(bytes, &digest, .{});
    return a.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn bind(a: std.mem.Allocator, artifact: *std.json.Value, bytes: []const u8) !void {
    artifact.object.getPtr("sha256").?.* = .{ .string = try sha256(a, bytes) };
    artifact.object.getPtr("size").?.* = .{ .integer = @intCast(bytes.len) };
}

pub fn namedAtomic(_: ?*anyopaque, dir: std.Io.Dir, destination: []const u8, options: std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
    if (!@import("builtin").is_test) @compileError("Authority fixtures are test-only");
    std.debug.assert(!options.make_path and std.mem.indexOfScalar(u8, destination, '/') == null);
    const name: u64 = 0xa170c;
    const file = dir.createFile(std.testing.io, &std.fmt.hex(name), .{
        .exclusive = true,
        .permissions = options.permissions,
    }) catch |err| std.debug.panic("named atomic fixture creation failed: {s}", .{@errorName(err)});
    return .{
        .file = file,
        .file_basename_hex = name,
        .dest_sub_path = destination,
        .file_open = true,
        .file_exists = true,
        .close_dir_on_deinit = false,
        .dir = dir,
    };
}
