// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("wamr_controller");

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch refused(init.io);
    const command = controller.cli.parse(args) catch usage(init.io);
    if (command.action == .describe) {
        const closure = std.fmt.bytesToHex(controller.source_custody.contentClosure(), .lower);
        const raw = std.json.Stringify.valueAlloc(allocator, .{
            .schema = "uk.wamr.native-ci-describe",
            .schema_version = 1,
            .recorded_executable_target = controller.profile.executable_target,
            .source_closure_sha256 = closure[0..],
        }, .{}) catch refused(init.io);
        const encoded = controller.records.canonicalAlloc(allocator, raw) catch refused(init.io);
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
        stdout.interface.writeAll(encoded) catch refused(init.io);
        return;
    }
    const runtime = controller.layout.runtime(init.io, command.runtime.?) catch refused(init.io);
    defer runtime.close(init.io);
    const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
    const compute = std.fs.path.join(allocator, &.{ command.runtime.?, "compute" }) catch refused(init.io);
    var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
    defer signal.deinit();
    var context: controller.build_pipeline.Context = .{
        .allocator = allocator,
        .io = init.io,
        .environ = init.minimal.environ,
        .runtime = command.runtime.?,
        .repository = repository,
        .wamr = command.wamr_source orelse "",
        .compute = compute,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    switch (command.action) {
        .build => _ = controller.build_pipeline.run(&context) catch |err| failed(init.io, context.failed_stage, context.failed_operation, err),
        .boot => {
            var boot_context: controller.boot_pipeline.Context = .{
                .build_context = &context,
                .pinned = std.StringHashMap(controller.custody_files.File).init(allocator),
            };
            _ = controller.boot_pipeline.run(&boot_context) catch |err| {
                if (err == error.KvmUnavailable) refusedWithMessage(init.io, "x86 KVM unavailable");
                failed(init.io, context.failed_stage, context.failed_operation, err);
            };
        },
        .diagnostics => {
            var boot_context: controller.boot_pipeline.Context = .{
                .build_context = &context,
                .pinned = std.StringHashMap(controller.custody_files.File).init(allocator),
            };
            controller.boot_pipeline.diagnostics(&boot_context) catch |err| failed(init.io, "diagnostics", "", err);
        },
        .describe => unreachable,
    }
}

fn usage(io: std.Io) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.writeAll(
        "usage: uk-wamr-native-ci build --runtime ABS --wamr-source ABS\n" ++
            "       uk-wamr-native-ci boot|diagnostics --runtime ABS\n" ++
            "       uk-wamr-native-ci describe --output json-v1\n",
    ) catch {};
    std.process.exit(2);
}

fn refused(io: std.Io) noreturn {
    refusedWithMessage(io, "controller stage unavailable");
}

fn refusedWithMessage(io: std.Io, message: []const u8) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.print("WAMR_CI_REFUSED: {s}\n", .{message}) catch {};
    std.process.exit(1);
}

fn failed(io: std.Io, stage: []const u8, operation: []const u8, reason: anyerror) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    if (std.mem.eql(u8, stage, "dependency-restore")) {
        stderr.interface.print(
            "WAMR_CI_FAILED_STAGE: {s}; operation: {s}; cause: {s}; bounded private logs retained.\n",
            .{ stage, operation, @errorName(reason) },
        ) catch {};
    } else {
        stderr.interface.print(
            "WAMR_CI_FAILED_STAGE: {s}; cause: {s}; bounded private logs retained.\n",
            .{ stage, @errorName(reason) },
        ) catch {};
    }
    std.process.exit(1);
}
