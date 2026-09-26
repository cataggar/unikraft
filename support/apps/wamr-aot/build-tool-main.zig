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
        try stdout.interface.writeAll("uk-wamr-aot-build prepare-verify/1\n");
        return;
    }
    const parsed = try build_tool.parseArguments(arguments[1..]);
    try build_tool.process.initialize();
    switch (parsed.command) {
        .prepare, .verify => try build_tool.prepare.execute(
            init.gpa,
            init.io,
            init.environ_map,
            parsed,
        ),
        .olddefconfig, .native_images => {
            const executable: [:0]u8 = if (init.environ_map.get("WAMR_CI_EXECUTABLE_PATH")) |path|
                try init.gpa.dupeZ(u8, path)
            else
                try std.Io.Dir.cwd().realPathFileAlloc(
                    init.io,
                    "/proc/self/exe",
                    init.gpa,
                );
            defer init.gpa.free(executable);
            try build_tool.image.execute(
                init.gpa,
                init.io,
                init.environ_map,
                executable,
                parsed,
            );
        },
    }
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
        error.UnsupportedProducerIdentity,
        error.UnsupportedZigVersion,
        error.SourceRevisionUnavailable,
        => "unsupported_input",
        error.ZigVersionCommandFailed,
        error.GitRevisionCommandFailed,
        error.GitArchiveCommandFailed,
        error.RuntimeBuildCommandFailed,
        error.CompilerBuildCommandFailed,
        error.RuntimeStripCommandFailed,
        error.RuntimeArchiveMembersCommandFailed,
        error.RuntimeArchiveExtractCommandFailed,
        error.RuntimeArchiveRepackCommandFailed,
        error.SnapshotComputeCommandFailed,
        error.SnapshotMemoryCommandFailed,
        error.MatchedWasmCommandFailed,
        error.MatchedAotCommandFailed,
        error.WorkloadBuildCommandFailed,
        error.TinyWasmCommandFailed,
        error.TinyAotCommandFailed,
        error.CoremarkCommandFailed,
        error.CoremarkNofpCommandFailed,
        error.BisonDataCommandFailed,
        error.RootBuildCommandFailed,
        error.GitCleanCommandFailed,
        => "command_failed",
        error.DirtyImageSource,
        error.ImageInputChanged,
        => "unsupported_input",
        else => "local_failure",
    };
}
