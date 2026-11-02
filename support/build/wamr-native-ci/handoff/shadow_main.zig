// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
        stderr.interface.print("TEST-ONLY shadow comparison refused: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--request")) return error.InvalidUsage;
    var bytes = try core.private_files.readSensitiveAbsolute(init.io, a, args[2], 1024 * 1024, null);
    defer bytes.deinit();
    try @import("shadow_compare.zig").compareRequest(a, bytes.bytes());
    try std.Io.File.stdout().writeStreamingAll(init.io, "TEST-ONLY records equal; not authority, not genuine producer acceptance.\n");
}
