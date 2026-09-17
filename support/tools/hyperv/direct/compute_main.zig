// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const compute = @import("compute.zig");
pub const wamr_direct_compute = true;

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    run(init) catch |err| {
        if (err == error.EvidenceIncomplete) std.process.exit(2);
        var writer = std.Io.File.stderr().writerStreaming(init.io, &.{});
        writer.interface.print("WAMR direct validation refused: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 3) return error.InvalidCommand;
    if (args.len == 3 and std.mem.eql(u8, args[1], "handoff")) {
        var bytes = try core.private_files.readSensitiveAbsolute(init.io, a, args[2], 65536, null);
        defer bytes.deinit();
        const bundle = try compute.parse(compute.Bundle, a, bytes.bytes());
        defer bundle.deinit();
        try compute.verifyBundle(a, init.io, bundle.value);
        var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
        try writer.interface.writeAll("Compute handoff revalidated; authority=not_admitted.\n");
        return;
    }
    const scope = try compute.loadScope(a, init.io, args[2]);
    defer scope.deinit();
    if (args.len == 3 and std.mem.eql(u8, args[1], "scope")) {
        const now = std.Io.Clock.real.now(init.io).toSeconds();
        if (now < 0) return error.InvalidClock;
        return scope.value.current(@intCast(now));
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "ledger")) {
        const dir = try core.private_files.Directory.open(init.io, args[3]);
        dir.close(init.io);
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "json")) {
        var bytes = try core.private_files.readSensitiveAbsolute(init.io, a, args[3], 65536, null);
        defer bytes.deinit();
        const doc = try core.contracts.SensitiveDocument.parse(a, bytes.bytes(), .{ .bytes = 65536 });
        defer doc.deinit();
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "inputs")) return compute.inspect(a, init.io, scope.value);
    if ((args.len == 4 or args.len == 5) and std.mem.eql(u8, args[1], "serial")) {
        var first = try core.private_files.readSensitiveAbsolute(init.io, a, args[3], 4 * 1024 * 1024, null);
        defer first.deinit();
        var result = try compute.checkSerial(a, first.bytes(), scope.value.identity);
        if (args.len == 5) {
            var second = try core.private_files.readSensitiveAbsolute(init.io, a, args[4], 4 * 1024 * 1024, null);
            defer second.deinit();
            result = try compute.checkSerial(a, try compute.secondBytes(second.bytes(), first.bytes(), scope.value.serial_mode), scope.value.identity);
        }
        var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
        try std.json.Stringify.value(result, .{}, &writer.interface);
        try writer.interface.writeByte('\n');
        return;
    }
    return error.InvalidCommand;
}
