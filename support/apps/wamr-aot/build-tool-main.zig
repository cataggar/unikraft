// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const build_tool = @import("wamr_aot_build");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        stderr.interface.print("wamr_aot_build_failed category={s}\n", .{category(err)}) catch {};
        std.process.exit(2);
    };
}

fn run(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len == 2 and std.mem.eql(u8, arguments[1], "--version")) {
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.writeAll("uk-wamr-aot-build foundation/1\n");
        return;
    }
    _ = try build_tool.parseArguments(arguments[1..]);
    return error.FoundationCommandUnavailable;
}

fn category(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidArguments,
        error.DuplicateOption,
        error.MissingOption,
        error.UnsupportedCombination,
        error.InvalidRevision,
        error.UnsafePath,
        => "invalid_invocation",
        error.FoundationCommandUnavailable => "foundation_only",
        else => "local_failure",
    };
}
