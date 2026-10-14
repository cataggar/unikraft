// SPDX-License-Identifier: BSD-3-Clause
//! Parse-only integration witness; never opens a runtime or executes a product.
const std = @import("std");
const cli = @import("publication_cli");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
        stderr.interface.print("TEST-ONLY publication parser refused: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.InvalidUsage;
    const command = try cli.parse(args[1..]);
    if (command.action != .@"import-public-source-download") return error.InvalidUsage;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
    try std.json.Stringify.value(.{
        .source_revision = command.source_revision.?,
        .source_tree = command.source_tree.?,
        .run_id = command.run_id.?,
        .run_attempt = command.run_attempt.?,
        .selected_source_revision = command.selected_source_revision.?,
        .selected_source_tree = command.selected_source_tree.?,
        .selected_run_id = command.selected_run_id.?,
        .selected_run_attempt = command.selected_run_attempt.?,
        .supervisor = command.supervisor.?,
        .validator = command.validator.?,
    }, .{}, &stdout.interface);
    try stdout.interface.writeByte('\n');
}
