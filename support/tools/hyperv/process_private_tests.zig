const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

test "private capture accepts exact eight MiB per stream while legacy stays at four" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var options: process.Options = .{
        .argv = &.{ executable, "bytes", "8388608", "8388608", "0" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(5000),
        .cleanup_ms = 3000,
        .stdout_limit = process.private_output_limit,
        .stderr_limit = process.private_output_limit,
    };
    try testing.expectError(error.InvalidOptions, process.run(allocator, io, options));
    const captured = try process.runPrivate(allocator, io, &lock, "out", "err", .{ .process = options });
    try captured.requireSuccess();
    try testing.expectEqual(process.private_output_limit, captured.stdout_bytes);
    try testing.expectEqual(process.private_output_limit, captured.stderr_bytes);
    var out = try fixture.read("out");
    defer out.deinit();
    var err = try fixture.read("err");
    defer err.deinit();
    try testing.expect(std.mem.allEqual(u8, out.bytes(), 'o'));
    try testing.expect(std.mem.allEqual(u8, err.bytes(), 'e'));
    options.stdout_limit = 4 * 1024 * 1024;
    options.stderr_limit = 4 * 1024 * 1024;
    options.argv = &.{ executable, "bytes", "4194304", "4194304", "0" };
    options.deadline = try process.Deadline.afterMilliseconds(5000);
    var legacy = try process.run(allocator, io, options);
    defer legacy.deinit(allocator);
    try testing.expectEqual(@as(usize, 4 * 1024 * 1024), legacy.stdout.len);
    try testing.expect(legacy.failures.primary == null);
    options.argv = &.{ executable, "bytes", "4194305", "0", "0" };
    var overflow = try process.run(allocator, io, options);
    defer overflow.deinit(allocator);
    try testing.expectEqual(.output_limit, overflow.failures.primary.?.category);
    try testing.expect(std.mem.allEqual(u8, overflow.storage, 0));
    try support.noChildren();
}

test "private streams fail at eight MiB plus one without unbounded files" {
    for ([_][]const []const u8{
        &.{ "8388609", "0" }, &.{ "0", "8388609" },
    }) |counts| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const executable = try support.executable();
        defer allocator.free(executable);
        var environment = std.process.Environ.Map.init(allocator);
        defer environment.deinit();
        const result = try process.runPrivate(allocator, io, &lock, "out", "err", .{ .process = .{
            .argv = &.{ executable, "bytes", counts[0], counts[1], "0" },
            .environment = &environment,
            .cwd = fixture.directory.dir,
            .deadline = try process.Deadline.afterMilliseconds(5000),
            .cleanup_ms = 3000,
            .stdout_limit = process.private_output_limit,
            .stderr_limit = process.private_output_limit,
        } });
        try testing.expectEqual(.output_limit, result.execution.failures.primary.?.category);
        try testing.expectEqual(.overflow, result.capture);
        try testing.expectEqual(process.private_output_limit, @max(result.stdout_bytes, result.stderr_bytes));
        try testing.expectError(error.UnsuccessfulCapture, result.requireSuccess());
        try support.noChildren();
    }
}

test "private pre-cancelled expired and over-limit options cannot execute" {
    const incomplete: process.PrivateResult = .{
        .execution = .{},
        .capture = .complete,
        .stdout_bytes = 0,
        .stderr_bytes = 0,
    };
    try testing.expectError(error.UnsuccessfulCapture, incomplete.requireSuccess());
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var cancel = std.atomic.Value(bool).init(true);
    var options: process.PrivateOptions = .{ .process = .{
        .argv = &.{ executable, "bytes", "17", "23", "0" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_ms = 3000,
        .cancel = &cancel,
    } };
    const cancelled = try process.runPrivate(allocator, io, &lock, "cancelled", "cancelled-err", options);
    try testing.expectEqual(.cancelled, cancelled.execution.failures.primary.?.category);
    try testing.expectEqual(.process_spawn, cancelled.execution.failures.primary.?.stage);
    try testing.expectEqual(@as(usize, 0), cancelled.stdout_bytes);
    options.process.cancel = null;
    options.process.deadline.expires_ns = 0;
    const expired = try process.runPrivate(allocator, io, &lock, "expired", "expired-err", options);
    try testing.expectEqual(.timeout, expired.execution.failures.primary.?.category);
    try testing.expectEqual(@as(usize, 0), expired.stderr_bytes);
    options.process.stdout_limit = process.private_output_limit + 1;
    try testing.expectError(error.InvalidOptions, process.runPrivate(allocator, io, &lock, "large", "large-err", options));
    try support.noChildren();
}

test "failed exit preserves both private streams but legacy stdout is securely wiped" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var options: process.Options = .{
        .argv = &.{ executable, "bytes", "17", "23", "7" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(5000),
        .cleanup_ms = 3000,
    };
    const result = try process.runPrivate(allocator, io, &lock, "out", "err", .{ .process = options });
    try testing.expectEqual(@as(u8, 7), result.execution.termination.?.exited);
    try testing.expectEqual(.child_failed, result.execution.failures.primary.?.category);
    try testing.expectEqual(.partial, result.capture);
    var out = try fixture.read("out");
    defer out.deinit();
    var err = try fixture.read("err");
    defer err.deinit();
    try testing.expectEqual(@as(usize, 17), out.bytes().len);
    try testing.expectEqual(@as(usize, 23), err.bytes().len);
    options.deadline = try process.Deadline.afterMilliseconds(5000);
    var old = try process.run(allocator, io, options);
    defer old.deinit(allocator);
    try testing.expect(std.mem.allEqual(u8, old.storage, 0));
    try testing.expectEqual(@as(usize, 0), old.stdout.len);
}

test "timeout and cancellation retain private partial output and reap trees" {
    for ([_][]const u8{ "partial", "ignore-term", "tree", "term-output" }, 0..) |mode, i| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const executable = try support.executable();
        defer allocator.free(executable);
        var environment = std.process.Environ.Map.init(allocator);
        defer environment.deinit();
        var cancel = std.atomic.Value(bool).init(false);
        const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancel, @as(u32, 150) });
        defer thread.join();
        const started = try process.monotonicNanoseconds();
        const result = try process.runPrivate(allocator, io, &lock, "out", "err", .{ .process = .{
            .argv = &.{ executable, mode },
            .environment = &environment,
            .cwd = fixture.directory.dir,
            .deadline = try process.Deadline.afterMilliseconds(if (i == 1) 5000 else 150),
            .cleanup_ms = 3000,
            .cancel = if (i == 1) &cancel else null,
        } });
        const elapsed = (try process.monotonicNanoseconds()) - started;
        try testing.expect(elapsed >= 2000 * std.time.ns_per_ms and elapsed < 3200 * std.time.ns_per_ms);
        try testing.expectEqual(@as(support.core.diagnostics.Category, if (i == 1) .cancelled else .timeout), result.execution.failures.primary.?.category);
        try testing.expectEqual(.partial, result.capture);
        try testing.expect(result.stdout_bytes > 0);
        if (i != 2) try testing.expect(result.stderr_bytes > 0);
        if (i == 3) {
            var late = try fixture.read("err");
            defer late.deinit();
            try testing.expectEqualStrings("private-after-term\n", late.bytes());
        }
        if (i == 1) try testing.expectEqual(.KILL, result.execution.termination.?.signal);
        try testing.expect(result.execution.cleanup_complete);
        var rendered = std.Io.Writer.Allocating.init(allocator);
        defer rendered.deinit();
        try result.execution.failures.write(&rendered.writer);
        try testing.expect(std.mem.indexOf(u8, rendered.written(), "synthetic-secret") == null);
        try support.noChildren();
    }
}

test "private capture handles pre-exec stall spawn failure partial write and sync failure" {
    for ([_]?process.PrivateTestFault{ .pre_exec_stall, .capture_write, .sync, null }) |fault| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const executable = try support.executable();
        defer allocator.free(executable);
        var environment = std.process.Environ.Map.init(allocator);
        defer environment.deinit();
        const options: process.PrivateOptions = .{ .process = .{
            .argv = &.{ if (fault == null) "/nonexistent-direct-runtime-fixture" else executable, "bytes", "17", "23", "0" },
            .environment = &environment,
            .cwd = fixture.directory.dir,
            .deadline = try process.Deadline.afterMilliseconds(if (fault == .pre_exec_stall) 100 else 3000),
            .cleanup_ms = 3000,
        } };
        const result = if (fault) |injection|
            try process.runPrivateTest(allocator, io, &lock, "out", "err", options, injection)
        else
            try process.runPrivate(allocator, io, &lock, "out", "err", options);
        try testing.expect(!result.succeeded());
        switch (fault orelse .pre_exec_stall) {
            .pre_exec_stall => try testing.expectEqual(@as(support.core.diagnostics.Category, if (fault == null) .spawn_failed else .timeout), result.execution.failures.primary.?.category),
            .capture_write => {
                try testing.expectEqual(.io_failed, result.capture);
                try testing.expectEqual(@as(usize, 4), result.stdout_bytes);
            },
            .sync => {
                try testing.expect(result.execution.failures.primary == null);
                try testing.expectEqual(.durability_failed, result.capture);
            },
        }
        try testing.expect(result.execution.cleanup_complete);
        try support.noChildren();
    }
}

test "private supervision refuses unrelated child ownership and shares the legacy busy guard" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const options: process.Options = .{
        .argv = &.{ executable, "partial" },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_ms = 3000,
    };
    {
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.ForkFailed;
        if (child == 0) {
            while (true) {
                var fds: [0]linux.pollfd = .{};
                _ = linux.poll(&fds, 0, 1000);
            }
        }
        defer {
            _ = linux.kill(@intCast(child), .KILL);
            var status: u32 = 0;
            _ = linux.waitpid(@intCast(child), &status, 0);
        }
        try testing.expectError(error.UnownedChildren, process.runPrivate(allocator, io, &lock, "out", "err", .{ .process = options }));
        try testing.expectEqual(.SUCCESS, linux.errno(linux.kill(@intCast(child), @enumFromInt(0))));
        try testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "out"));
    }
    var saw_busy = std.atomic.Value(bool).init(false);
    var cancel = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, struct {
        fn attempt(input: process.Options, observed: *std.atomic.Value(bool), cancellation: *std.atomic.Value(bool)) void {
            const duration: linux.timespec = .{ .sec = 0, .nsec = 150 * std.time.ns_per_ms };
            _ = linux.nanosleep(&duration, null);
            var result = process.run(allocator, io, input) catch |err| {
                observed.store(err == error.SupervisorBusy, .release);
                cancellation.store(true, .release);
                return;
            };
            result.deinit(allocator);
        }
    }.attempt, .{ options, &saw_busy, &cancel });
    defer thread.join();
    var active = options;
    active.cancel = &cancel;
    const captured = try process.runPrivate(allocator, io, &lock, "out", "err", .{ .process = active });
    try testing.expect(saw_busy.load(.acquire));
    try testing.expectEqual(.cancelled, captured.execution.failures.primary.?.category);
    try support.noChildren();
}

test "capture names are exclusive private no-symlink and do not leak writer descriptors" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var fd: [32]u8 = undefined;
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const options: process.PrivateOptions = .{ .process = .{
        .argv = &.{ executable, "fd-closed", try std.fmt.bufPrint(&fd, "{d}", .{lock.file.?.handle}) },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(5000),
        .cleanup_ms = 3000,
    } };
    const result = try process.runPrivate(allocator, io, &lock, "out", "err", options);
    try result.requireSuccess();
    try testing.expectError(error.WouldBlock, fixture.directory.lock(io));
    try testing.expectError(error.PathAlreadyExists, process.runPrivate(allocator, io, &lock, "out", "again", options));
    try testing.expectError(error.UnsafePath, process.runPrivate(allocator, io, &lock, "../out", "other", options));
    try fixture.directory.dir.symLink(io, "out", "symlink", .{});
    try testing.expectError(error.PathAlreadyExists, process.runPrivate(allocator, io, &lock, "symlink", "other", options));
    const out = try fixture.directory.openFile(io, "out");
    defer out.close(io);
    const stat = try support.core.private_files.snapshot(out);
    try testing.expectEqual(@as(u16, 0o600), stat.mode & 0o7777);
    try testing.expectEqual(@as(u32, 1), stat.nlink);
}

test "nested native supervisor gets cleanup grace and all adopted groups are reaped" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var cancel = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancel, @as(u32, 200) });
    defer thread.join();
    const started = try process.monotonicNanoseconds();
    const result = try process.runPrivate(allocator, io, &lock, "out", "err", .{
        .process = .{
            .argv = &.{ executable, "nested", "5200" },
            .environment = &environment,
            .cwd = fixture.directory.dir,
            .deadline = try process.Deadline.afterMilliseconds(10000),
            .cleanup_ms = 8000,
            .cancel = &cancel,
        },
        .term_grace_ms = 7000,
        .nested_supervisor = true,
    });
    try testing.expect((try process.monotonicNanoseconds()) - started >= 5200 * std.time.ns_per_ms);
    try testing.expectEqual(.cancelled, result.execution.failures.primary.?.category);
    try testing.expectEqual(@as(u8, 7), result.execution.termination.?.exited);
    try testing.expect(result.execution.cleanup_complete);
    var out = try fixture.read("out");
    defer out.deinit();
    try testing.expect(std.mem.indexOf(u8, out.bytes(), "nested-reaped\n") != null);
    try support.noChildren();
}
