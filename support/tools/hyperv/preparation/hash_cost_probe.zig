//! Actual namespace-fixture bytes through the unchanged pre-entry hash APIs.
//! Observation only: never executes the fixture or enters a namespace.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const measurement = @import("synthetic_measurement");
const options = @import("hash_cost_options");
const maximum = 64 * 1024 * 1024;
const Phase = enum { inventory_begin, inventory_end, executable_record_begin, executable_record_end, executable_read_begin, executable_read_end, executable_hash_end };

fn mark(io: std.Io, artifact: usize, pass: usize, phase: Phase, bytes: usize) !void {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(.{
        .schema_version = @as(u8, 1),
        .scope = "synthetic_observation_only",
        .authority = "none",
        .namespace_operations = "none",
        .artifact_index = artifact,
        .pass_index = pass,
        .dirty_upper_control = pass == 1,
        .phase = phase,
        .fixture_bytes = bytes,
        .self_bytes = try measurement.selfExecutableBytes(io),
        .cpu_model = builtin.cpu.model.name,
        .sample = try measurement.capture(),
    }, .{}, &writer);
    std.debug.print("preparation synthetic hash cost: {s}\n", .{writer.buffered()});
}

inline fn dirtyUpper(pass: usize) void {
    if (comptime builtin.cpu.arch == .x86_64 and builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 })) {
        if (pass == 1)
            asm volatile ("vpcmpeqd %%ymm0, %%ymm0, %%ymm0" ::: .{ .ymm0 = true });
    }
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 2 or args.len > 3) return error.InvalidArguments;
    const workspace = try fs.openPrivate(io, options.workspace);
    defer workspace.close(io);
    for (args[1..], 0..) |input, artifact| {
        const path = try std.Io.Dir.cwd().realPathFileAlloc(io, input, a);
        const source = try fs.Directory.open(a, io, std.fs.path.dirname(path).?);
        defer source.close(a, io);
        const bytes = try source.read(a, io, std.fs.path.basename(path), maximum, .executable);
        defer a.free(bytes);
        if (bytes.len == 0) return error.EmptyFixture;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const expected: c.File = .{
            .path = "namespace-fixture",
            .size = bytes.len,
            .sha256 = std.fmt.bytesToHex(digest, .lower),
            .mode = 0o500,
        };
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try workspace.dir.createDir(io, &name, .fromMode(0o700));
        defer workspace.dir.deleteTree(io, &name) catch @panic("private hash observation cleanup failed");
        const directory_path = try std.fs.path.join(a, &.{ options.workspace, &name });
        const directory = try fs.Directory.open(a, io, directory_path);
        defer directory.close(a, io);
        try directory.dir.writeFile(io, .{
            .sub_path = expected.path,
            .data = bytes,
            .flags = .{ .exclusive = true, .permissions = .fromMode(0o500) },
        });
        // These are the three independent full hashes used by Bound.validate,
        // including every inventory/record/read snapshot and named-file check.
        var first_tree: ?c.Tree = null;
        for (0..2) |pass| {
            try mark(io, artifact, pass, .inventory_begin, bytes.len);
            dirtyUpper(pass);
            const inventory = try fs.inventory(a, io, directory, 1, maximum);
            try mark(io, artifact, pass, .inventory_end, bytes.len);
            if (inventory.entries.len != 1 or inventory.tree.bytes != bytes.len) return error.InventoryMismatch;
            try fs.requireFile(inventory.entries[0], expected);
            if (first_tree) |tree| try fs.requireTree(inventory.tree, tree) else first_tree = inventory.tree;
            try mark(io, artifact, pass, .executable_record_begin, bytes.len);
            dirtyUpper(pass);
            const record = try directory.record(a, io, expected.path, maximum, .executable);
            try mark(io, artifact, pass, .executable_record_end, bytes.len);
            try fs.requireFile(record, expected);
            try mark(io, artifact, pass, .executable_read_begin, bytes.len);
            const actual = try directory.read(a, io, expected.path, maximum, .executable);
            defer a.free(actual);
            try mark(io, artifact, pass, .executable_read_end, bytes.len);
            dirtyUpper(pass);
            const actual_digest = c.digest(actual);
            try mark(io, artifact, pass, .executable_hash_end, bytes.len);
            if (actual.len != bytes.len or !std.crypto.timing_safe.eql(c.Sha, actual_digest, expected.sha256))
                return error.DigestMismatch;
        }
        std.debug.print("preparation synthetic hash digest: artifact={d} bytes={d} sha256={s} tree={s}\n", .{ artifact, bytes.len, expected.sha256, first_tree.?.sha256 });
    }
}
