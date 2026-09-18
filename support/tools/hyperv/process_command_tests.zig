const std = @import("std");
const support = @import("process_private_test_support.zig");
const process = support.process;
const testing = std.testing;
const allocator = support.allocator;
const io = support.io;
const linux = std.os.linux;

fn openExecutable() !process.Executable {
    const path = try support.executable();
    defer allocator.free(path);
    return process.Executable.open(io, path);
}

fn writeAll(descriptor: linux.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const amount = linux.write(descriptor, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(amount)) {
            .SUCCESS => {
                if (amount == 0) return error.FixtureWrite;
                offset += amount;
            },
            .INTR => continue,
            else => return error.FixtureWrite,
        }
    }
}

fn createExecutableFile(fixture: *support.Fixture, name: [:0]const u8, bytes: []const u8) ![:0]u8 {
    const opened = linux.openat(fixture.directory.dir.handle, name, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
    }, 0o700);
    if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
    const descriptor: linux.fd_t = @intCast(opened);
    errdefer _ = linux.close(descriptor);
    try writeAll(descriptor, bytes);
    _ = linux.close(descriptor);
    return fixture.directory.dir.realPathFileAlloc(io, name, allocator);
}

fn copyExecutableFile(fixture: *support.Fixture, name: [:0]const u8, source: [:0]const u8) ![:0]u8 {
    const opened = linux.openat(linux.AT.FDCWD, source, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
    const source_descriptor: linux.fd_t = @intCast(opened);
    defer _ = linux.close(source_descriptor);
    const destination = linux.openat(fixture.directory.dir.handle, name, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
    }, 0o700);
    if (linux.errno(destination) != .SUCCESS) return error.FixtureOpen;
    const destination_descriptor: linux.fd_t = @intCast(destination);
    errdefer _ = linux.close(destination_descriptor);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const amount = linux.read(source_descriptor, &buffer, buffer.len);
        switch (linux.errno(amount)) {
            .SUCCESS => {
                if (amount == 0) break;
                try writeAll(destination_descriptor, buffer[0..amount]);
            },
            .INTR => continue,
            else => return error.FixtureRead,
        }
    }
    _ = linux.close(destination_descriptor);
    return fixture.directory.dir.realPathFileAlloc(io, name, allocator);
}

fn expectPidsGone(bytes: []const u8, expected: usize) !void {
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        const pid = try std.fmt.parseInt(linux.pid_t, line, 10);
        try testing.expectEqual(.SRCH, linux.errno(linux.kill(pid, @enumFromInt(0))));
        count += 1;
    }
    try testing.expectEqual(expected, count);
}

fn request(
    executable: process.Executable,
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
) !process.CommandRequest {
    return .{
        .executable = executable,
        .argv = argv,
        .environment = environment,
        .cwd = cwd,
        .primary_deadline = try process.Deadline.afterMilliseconds(3000),
        .cleanup_deadline = try process.Deadline.afterMilliseconds(5000),
    };
}

test "command contract captures successful bounded stdout and stderr" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    var result = try process.runCommand(allocator, io, try request(
        executable,
        &.{ path, "bytes", "17", "23", "0" },
        &environment,
        fixture.directory.dir,
    ));
    defer result.deinit(allocator);
    try testing.expect(result.succeeded());
    try testing.expectEqual(.complete, result.stdout_status);
    try testing.expectEqual(.complete, result.stderr_status);
    try testing.expectEqual(@as(usize, 17), result.stdout.len);
    try testing.expectEqual(@as(usize, 23), result.stderr.len);
    try testing.expect(std.mem.allEqual(u8, result.stdout, 'o'));
    try testing.expect(std.mem.allEqual(u8, result.stderr, 'e'));
    try testing.expect(result.executable_stable);
    try testing.expectEqual(@as(u16, 0), result.descendants.observed);
    try support.noChildren();
}

test "executable contract accepts native and dynamically linked ELF binaries" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    var native = try openExecutable();
    const native_descriptor = native.file.handle;
    try testing.expectEqual(.SUCCESS, linux.errno(linux.fcntl(native_descriptor, linux.F.GETFD, 0)));
    native.close(io);
    try testing.expectEqual(.BADF, linux.errno(linux.fcntl(native_descriptor, linux.F.GETFD, 0)));

    const dynamic_path = try std.Io.Dir.cwd().realPathFileAlloc(io, "/usr/bin/true", allocator);
    defer allocator.free(dynamic_path);
    var dynamic = try process.Executable.open(io, dynamic_path);
    defer dynamic.close(io);
    try testing.expect(try process.ExecutableFormatTest.usesInterpreter(dynamic));
    var result = try process.runCommand(allocator, io, try request(
        dynamic,
        &.{dynamic_path},
        &environment,
        fixture.directory.dir,
    ));
    defer result.deinit(allocator);
    try testing.expect(result.succeeded());
    try support.noChildren();
}

test "executable contract rejects scripts text and malformed ELF before spawn" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const cases = [_]struct { name: [:0]const u8, bytes: []const u8 }{
        .{ .name = "shebang", .bytes = "#!/bin/sh\nexit 0\n" },
        .{ .name = "text", .bytes = "echo executable text\n" },
        .{ .name = "truncated", .bytes = "\x7fELF" },
        .{ .name = "magic-only", .bytes = "\x7fELF\x02\x01\x01" ++ "\x00" ** 57 },
    };
    for (cases) |case| {
        const path = try createExecutableFile(&fixture, case.name, case.bytes);
        defer allocator.free(path);
        try testing.expectError(error.UnsupportedExecutableFormat, process.Executable.open(io, path));
    }

    const probe = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(probe) != .SUCCESS) return error.FixtureOpen;
    const expected_descriptor: linux.fd_t = @intCast(probe);
    _ = linux.close(expected_descriptor);
    const text_path = try fixture.directory.dir.realPathFileAlloc(io, "text", allocator);
    defer allocator.free(text_path);
    try testing.expectError(error.UnsupportedExecutableFormat, process.Executable.open(io, text_path));
    const reused = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(reused) != .SUCCESS) return error.FixtureOpen;
    defer _ = linux.close(@intCast(reused));
    try testing.expectEqual(expected_descriptor, @as(linux.fd_t, @intCast(reused)));
    try support.noChildren();
}

test "executable descriptor mutation is rejected and ownership remains with caller" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const source = try support.executable();
    defer allocator.free(source);
    const path = try copyExecutableFile(&fixture, "mutable-elf", source);
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    const descriptor = executable.file.handle;
    var executable_open = true;
    defer if (executable_open) executable.close(io);

    const mutation = linux.openat(linux.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(mutation) != .SUCCESS) return error.FixtureOpen;
    const mutation_descriptor: linux.fd_t = @intCast(mutation);
    errdefer _ = linux.close(mutation_descriptor);
    try writeAll(mutation_descriptor, "x");
    _ = linux.close(mutation_descriptor);

    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try testing.expectError(error.ExecutableIdentityChanged, process.runCommand(
        allocator,
        io,
        try request(executable, &.{path}, &environment, fixture.directory.dir),
    ));
    try testing.expectEqual(.SUCCESS, linux.errno(linux.fcntl(descriptor, linux.F.GETFD, 0)));
    try support.noChildren();
    executable.close(io);
    executable_open = false;
    try testing.expectEqual(.BADF, linux.errno(linux.fcntl(descriptor, linux.F.GETFD, 0)));
}

test "tracked parent identity rejects reaped PID reuse before candidate open" {
    const expected_pid: linux.pid_t = 1234;
    const expected_start: u64 = 5678;
    try testing.expectEqual(
        process.CommandIdentityTest.Action.rescan_without_open,
        process.CommandIdentityTest.parentAction(
            expected_pid,
            expected_start,
            true,
            expected_pid,
            expected_start + 1,
            true,
        ),
    );
    try testing.expectEqual(
        process.CommandIdentityTest.Action.poison,
        process.CommandIdentityTest.parentAction(
            expected_pid,
            expected_start,
            false,
            expected_pid,
            expected_start + 1,
            false,
        ),
    );
    try testing.expectEqual(
        process.CommandIdentityTest.Action.poison,
        process.CommandIdentityTest.parentAction(
            expected_pid,
            expected_start,
            false,
            null,
            0,
            false,
        ),
    );
    try testing.expectEqual(
        process.CommandIdentityTest.Action.open_candidate,
        process.CommandIdentityTest.parentAction(
            expected_pid,
            expected_start,
            false,
            expected_pid,
            expected_start,
            false,
        ),
    );
}

test "pidfd liveness and proc start identity agree across exit and reap" {
    try process.initialize();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.FixtureFork;
    if (forked == 0) {
        while (true) {
            var pollfds: [0]linux.pollfd = .{};
            _ = linux.poll(&pollfds, 0, 1000);
        }
    }
    const pid: linux.pid_t = @intCast(forked);
    const opened = linux.pidfd_open(pid, 0);
    if (linux.errno(opened) != .SUCCESS) return error.FixturePidfd;
    const descriptor: linux.fd_t = @intCast(opened);
    defer _ = linux.close(descriptor);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.pidfd_send_signal(descriptor, .KILL, null, 0);
        var status: u32 = 0;
        while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    };

    const start_ticks = try process.CommandIdentityTest.startTicks(pid);
    try testing.expect(try process.CommandIdentityTest.identityLive(pid, start_ticks, descriptor));
    try testing.expectEqual(.SUCCESS, linux.errno(linux.pidfd_send_signal(descriptor, .KILL, null, 0)));
    var status: u32 = 0;
    while (true) switch (linux.errno(linux.waitpid(pid, &status, 0))) {
        .SUCCESS => {
            reaped = true;
            break;
        },
        .INTR => continue,
        else => return error.FixtureReap,
    };
    try testing.expect(!(try process.CommandIdentityTest.identityLive(pid, start_ticks, descriptor)));
    try support.noChildren();
}

test "command cleanup owns ordinary setsid double-fork and closed-fd descendants" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_][]const u8{ "ordinary-child", "setsid-child", "double-fork", "closed-child" }) |mode| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var command = try request(executable, &.{ path, mode }, &environment, fixture.directory.dir);
        command.limits.term_grace_ms = 50;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expect(result.succeeded());
        try testing.expectEqual(@as(u16, 1), result.descendants.observed);
        try testing.expectEqual(result.descendants.observed, result.descendants.identity_validated);
        try testing.expect(result.descendants.adopted >= 1);
        try expectPidsGone(result.stdout, 1);
        try support.noChildren();
    }
}

test "TERM-resistant descendants receive one grace then KILL" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var command = try request(executable, &.{ path, "resistant-child" }, &environment, fixture.directory.dir);
    command.limits.term_grace_ms = 120;
    const started = try process.monotonicNanoseconds();
    var result = try process.runCommand(allocator, io, command);
    defer result.deinit(allocator);
    const elapsed = (try process.monotonicNanoseconds()) - started;
    try testing.expect(elapsed >= 100 * std.time.ns_per_ms);
    try testing.expect(elapsed < 1000 * std.time.ns_per_ms);
    try testing.expect(result.succeeded());
    try expectPidsGone(result.stdout, 1);
    try support.noChildren();
}

test "primary deadline and cancellation do not reset on activity" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]bool{ false, true }) |use_cancel| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var cancellation = std.atomic.Value(bool).init(false);
        const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancellation, @as(u32, 150) });
        defer thread.join();
        var command = try request(
            executable,
            &.{ path, if (use_cancel) "partial" else "drip" },
            &environment,
            fixture.directory.dir,
        );
        command.primary_deadline = try process.Deadline.afterMilliseconds(if (use_cancel) 3000 else 150);
        command.cleanup_deadline = try process.Deadline.afterMilliseconds(1200);
        command.cancel = if (use_cancel) &cancellation else null;
        command.limits.term_grace_ms = 50;
        const started = try process.monotonicNanoseconds();
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        const elapsed = (try process.monotonicNanoseconds()) - started;
        try testing.expect(elapsed < 800 * std.time.ns_per_ms);
        if (use_cancel) {
            try testing.expectEqual(.cancelled, result.primary);
            try testing.expect(result.cancellation_observed);
        } else {
            try testing.expectEqual(.timeout, result.primary);
            try testing.expect(result.primary_deadline_reached);
        }
        try testing.expect(result.cleanup_complete);
        try testing.expect(result.stdout.len > 0);
        try support.noChildren();
    }
}

test "timeout and cancellation reap live descendant trees" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]bool{ false, true }) |use_cancel| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var cancellation = std.atomic.Value(bool).init(false);
        const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancellation, @as(u32, 120) });
        defer thread.join();
        var command = try request(executable, &.{ path, "tree" }, &environment, fixture.directory.dir);
        command.primary_deadline = try process.Deadline.afterMilliseconds(if (use_cancel) 3000 else 120);
        command.cleanup_deadline = try process.Deadline.afterMilliseconds(1200);
        command.cancel = if (use_cancel) &cancellation else null;
        command.limits.term_grace_ms = 50;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        if (use_cancel) {
            try testing.expectEqual(.cancelled, result.primary);
        } else {
            try testing.expectEqual(.timeout, result.primary);
        }
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(@as(u16, 1), result.descendants.observed);
        try expectPidsGone(result.stdout, 1);
        try support.noChildren();
    }
}

test "stdout and stderr overflow are explicit and bounded" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]bool{ false, true }) |stderr| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var command = try request(
            executable,
            &.{ path, "bytes", if (stderr) "0" else "33", if (stderr) "33" else "0", "0" },
            &environment,
            fixture.directory.dir,
        );
        command.limits.stdout_bytes = 32;
        command.limits.stderr_bytes = 32;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expectEqual(.output_overflow, result.primary);
        if (stderr) {
            try testing.expectEqual(.overflow, result.stderr_status);
            try testing.expectEqual(@as(usize, 32), result.stderr.len);
        } else {
            try testing.expectEqual(.overflow, result.stdout_status);
            try testing.expectEqual(@as(usize, 32), result.stdout.len);
        }
        try testing.expect(result.cleanup_complete);
        try support.noChildren();
    }
}

test "nonzero exits remain primary and non-ELF is refused before spawn" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const path = try support.executable();
    defer allocator.free(path);
    {
        var executable = try process.Executable.open(io, path);
        defer executable.close(io);
        var result = try process.runCommand(allocator, io, try request(
            executable,
            &.{ path, "bytes", "0", "0", "7" },
            &environment,
            fixture.directory.dir,
        ));
        defer result.deinit(allocator);
        try testing.expectEqual(@as(u8, 7), result.primary.exited);
        try testing.expect(result.cleanup_complete);
    }
    {
        const opened = linux.openat(fixture.directory.dir.handle, "invalid-executable", .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .CLOEXEC = true,
        }, 0o700);
        if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
        const descriptor: linux.fd_t = @intCast(opened);
        const bytes = "not an executable\n";
        if (linux.write(descriptor, bytes.ptr, bytes.len) != bytes.len) return error.FixtureWrite;
        _ = linux.close(descriptor);
        const invalid_path = try fixture.directory.dir.realPathFileAlloc(io, "invalid-executable", allocator);
        defer allocator.free(invalid_path);
        try testing.expectError(error.UnsupportedExecutableFormat, process.Executable.open(io, invalid_path));
    }
    try support.noChildren();
}

test "descendant limit accepts the limit and reports the first excess without poison" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]u16{ 3, 4 }) |limit| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var command = try request(executable, &.{ path, "many-children", "4" }, &environment, fixture.directory.dir);
        command.limits.descendants = limit;
        command.limits.reap_events = 16;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expectEqual(@as(u16, 4), result.descendants.observed);
        try testing.expectEqual(limit == 3, result.descendants.limit_exceeded);
        try testing.expect(!result.descendants.untracked);
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(limit == 4, result.succeeded());
        try expectPidsGone(result.stdout, 4);
        try support.noChildren();
    }
}

test "reap event minimum covers sentinel and terminal ECHILD proof" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();

    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var below = try request(executable, &.{ path, "many-children", "4" }, &environment, fixture.directory.dir);
    below.limits.descendants = 4;
    below.limits.reap_events = 6;
    try testing.expectError(error.InvalidOptions, process.runCommand(allocator, io, below));

    var sentinel = try request(executable, &.{ path, "many-children", "5" }, &environment, fixture.directory.dir);
    sentinel.limits.descendants = 4;
    sentinel.limits.reap_events = 7;
    var excess = try process.runCommand(allocator, io, sentinel);
    defer excess.deinit(allocator);
    try testing.expect(excess.cleanup_complete);
    try testing.expect(excess.descendants.limit_exceeded);
    try testing.expectEqual(@as(u16, 7), excess.reap_events);
    try expectPidsGone(excess.stdout, 5);
    try support.noChildren();

    var within = try request(executable, &.{ path, "many-children", "4" }, &environment, fixture.directory.dir);
    within.limits.descendants = 4;
    within.limits.reap_events = 7;
    var complete = try process.runCommand(allocator, io, within);
    defer complete.deinit(allocator);
    try testing.expect(complete.succeeded());
    try testing.expectEqual(@as(u16, 6), complete.reap_events);
    try expectPidsGone(complete.stdout, 4);
    try support.noChildren();
}

test "cleanup grace and deadline are absolute across many descendants" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var command = try request(executable, &.{ path, "many-resistant", "6" }, &environment, fixture.directory.dir);
    command.limits.descendants = 6;
    command.limits.term_grace_ms = 150;
    command.cleanup_deadline = try process.Deadline.afterMilliseconds(700);
    const started = try process.monotonicNanoseconds();
    var result = try process.runCommand(allocator, io, command);
    defer result.deinit(allocator);
    const elapsed = (try process.monotonicNanoseconds()) - started;
    try testing.expect(elapsed >= 120 * std.time.ns_per_ms);
    try testing.expect(elapsed < 650 * std.time.ns_per_ms);
    try testing.expect(result.succeeded());
    try expectPidsGone(result.stdout, 6);
    try support.noChildren();
}

test "command bounds and executable identity refuse before spawn" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var bounded = try request(executable, &.{ path, "bytes", "0", "0", "0" }, &environment, fixture.directory.dir);
    bounded.limits.descendants = 0;
    try testing.expectError(error.InvalidOptions, process.runCommand(allocator, io, bounded));
    var changed = executable;
    changed.identity.inode +%= 1;
    bounded = try request(changed, &.{ path, "bytes", "0", "0", "0" }, &environment, fixture.directory.dir);
    try testing.expectError(error.ExecutableIdentityChanged, process.runCommand(allocator, io, bounded));
    try support.noChildren();
}
