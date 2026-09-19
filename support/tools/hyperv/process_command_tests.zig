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

fn preadAll(descriptor: linux.fd_t, bytes: []u8, offset: u64) !void {
    var read: usize = 0;
    while (read < bytes.len) {
        const amount = linux.pread(
            descriptor,
            bytes[read..].ptr,
            bytes.len - read,
            @intCast(offset + read),
        );
        switch (linux.errno(amount)) {
            .SUCCESS => {
                if (amount == 0) return error.FixtureRead;
                read += amount;
            },
            .INTR => continue,
            else => return error.FixtureRead,
        }
    }
}

fn pwriteAll(descriptor: linux.fd_t, bytes: []const u8, offset: u64) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const amount = linux.pwrite(
            descriptor,
            bytes[written..].ptr,
            bytes.len - written,
            @intCast(offset + written),
        );
        switch (linux.errno(amount)) {
            .SUCCESS => {
                if (amount == 0) return error.FixtureWrite;
                written += amount;
            },
            .INTR => continue,
            else => return error.FixtureWrite,
        }
    }
}

fn readLittle16(bytes: *const [2]u8) u16 {
    return @as(u16, bytes[0]) | @as(u16, bytes[1]) << 8;
}

fn readLittle32(bytes: *const [4]u8) u32 {
    return @as(u32, bytes[0]) |
        @as(u32, bytes[1]) << 8 |
        @as(u32, bytes[2]) << 16 |
        @as(u32, bytes[3]) << 24;
}

fn readLittle64(bytes: *const [8]u8) u64 {
    return @as(u64, readLittle32(bytes[0..4])) |
        @as(u64, readLittle32(bytes[4..8])) << 32;
}

fn writeLittle64(bytes: *[8]u8, value: u64) void {
    for (bytes, 0..) |*byte, index| byte.* = @truncate(value >> @intCast(index * 8));
}

const ProgramHeader = struct {
    offset: u64,
    file_offset: u64,
    virtual_address: u64,
};

fn firstLoadProgram(descriptor: linux.fd_t) !ProgramHeader {
    var header: [64]u8 = undefined;
    try preadAll(descriptor, &header, 0);
    const program_offset = readLittle64(header[32..40]);
    const program_size = readLittle16(header[54..56]);
    const program_count = readLittle16(header[56..58]);
    if (program_size != 56) return error.InvalidFixture;
    for (0..program_count) |index| {
        const offset = program_offset + index * program_size;
        var program: [56]u8 = undefined;
        try preadAll(descriptor, &program, offset);
        if (readLittle32(program[0..4]) == 1) return .{
            .offset = offset,
            .file_offset = readLittle64(program[8..16]),
            .virtual_address = readLittle64(program[16..24]),
        };
    }
    return error.InvalidFixture;
}

fn openReadWrite(path: [:0]const u8) !linux.fd_t {
    const opened = linux.openat(linux.AT.FDCWD, path, .{
        .ACCMODE = .RDWR,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
    return @intCast(opened);
}

fn nextDescriptor() !linux.fd_t {
    const opened = linux.openat(linux.AT.FDCWD, "/dev/null", .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.FixtureOpen;
    const descriptor: linux.fd_t = @intCast(opened);
    _ = linux.close(descriptor);
    return descriptor;
}

const MutationContext = struct {
    gate: *process.CommandSnapshotGate,
    path: [:0]const u8,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn mutateDuringSnapshot(context: *MutationContext) void {
    while (!context.gate.started.load(.acquire)) {
        var fds: [0]linux.pollfd = .{};
        _ = linux.poll(&fds, 0, 1);
    }
    const opened = linux.openat(linux.AT.FDCWD, context.path, .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) {
        context.failed.store(true, .release);
    } else {
        const descriptor: linux.fd_t = @intCast(opened);
        const changed = [_]u8{0xa5};
        if (linux.write(descriptor, &changed, changed.len) != changed.len)
            context.failed.store(true, .release);
        _ = linux.close(descriptor);
    }
    context.gate.continue_copy.store(true, .release);
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

fn expectExactPreSpawn(
    result: process.CommandResult,
    primary: std.meta.Tag(process.CommandPrimary),
) !void {
    try testing.expectEqual(primary, std.meta.activeTag(result.primary));
    try testing.expectEqual(.not_required, result.cleanup);
    try testing.expect(result.cleanup_complete);
    try testing.expect(result.executable_stable);
    try testing.expectEqual(@as(usize, 0), result.stdout.len);
    try testing.expectEqual(@as(usize, 0), result.stderr.len);
    try testing.expectEqual(.complete, result.stdout_status);
    try testing.expectEqual(.complete, result.stderr_status);
    try testing.expectEqual(@as(?std.process.Child.Term, null), result.termination);
    try testing.expectEqual(@as(u32, 0), result.primary_events);
    try testing.expectEqual(@as(u32, 0), result.cleanup_events);
    try testing.expectEqual(@as(u16, 0), result.reap_events);
    try testing.expectEqual(process.CommandDescendants{}, result.descendants);
    try testing.expectEqual(result.primary_completed_ns, result.completed_ns);
    try testing.expect(result.started_ns <= result.primary_completed_ns);
    try testing.expectEqual(primary == .timeout, result.primary_deadline_reached);
    try testing.expectEqual(primary == .cancelled, result.cancellation_observed);
}

test "command pre-spawn results have one exact not-required shape" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const cases = [_]struct {
        primary: std.meta.Tag(process.CommandPrimary),
        expired: bool = false,
        cancelled: bool = false,
        fault: ?process.CommandPreSpawnTestFault = null,
    }{
        .{ .primary = .timeout, .expired = true },
        .{ .primary = .cancelled, .cancelled = true },
        .{ .primary = .snapshot_unsupported, .fault = .snapshot_unsupported },
        .{ .primary = .local_io, .fault = .snapshot_local_io },
        .{ .primary = .local_io, .fault = .spawn_local_io },
    };
    for (cases) |case| {
        var cancellation = std.atomic.Value(bool).init(case.cancelled);
        var command = try request(
            executable,
            &.{ path, "bytes", "0", "0", "0" },
            &environment,
            fixture.directory.dir,
        );
        if (case.expired) command.primary_deadline = .{ .expires_ns = 1 };
        command.cancel = if (case.cancelled) &cancellation else null;
        var result = try process.runCommandTest(
            allocator,
            io,
            command,
            .{ .pre_spawn = case.fault },
        );
        defer result.deinit(allocator);
        try expectExactPreSpawn(result, case.primary);
        try support.noChildren();
    }
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

    const dynamic_path = try std.Io.Dir.cwd().realPathFileAlloc(io, "/bin/bash", allocator);
    defer allocator.free(dynamic_path);
    var dynamic = try process.Executable.open(io, dynamic_path);
    defer dynamic.close(io);
    try testing.expect(try process.ExecutableFormatTest.usesInterpreter(dynamic));
    var result = try process.runCommand(allocator, io, try request(
        dynamic,
        &.{ dynamic_path, "--version" },
        &environment,
        fixture.directory.dir,
    ));
    defer result.deinit(allocator);
    try testing.expect(result.succeeded());
    try support.noChildren();
}

test "executable snapshot has distinct sealed identity and releases its descriptor" {
    var executable = try openExecutable();
    defer executable.close(io);
    const source_stat = blk: {
        var stat: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            executable.file.handle,
            "",
            linux.AT.EMPTY_PATH,
            .BASIC_STATS,
            &stat,
        )) != .SUCCESS) return error.FixtureStat;
        break :blk stat;
    };
    const expected_descriptor = try nextDescriptor();
    const snapshot = try process.ExecutableSnapshotTest.create(executable);
    var snapshot_open = true;
    defer if (snapshot_open) {
        _ = linux.close(snapshot);
    };
    var snapshot_stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(snapshot, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &snapshot_stat)) != .SUCCESS)
        return error.FixtureStat;
    try testing.expect(snapshot_stat.dev_major != source_stat.dev_major or
        snapshot_stat.dev_minor != source_stat.dev_minor or snapshot_stat.ino != source_stat.ino);
    try testing.expectEqual(source_stat.size, snapshot_stat.size);
    try testing.expectEqual(@as(u32, 0), snapshot_stat.nlink);
    try testing.expectEqual(
        executable.identity.content_sha256,
        try process.ExecutableSnapshotTest.contentSha256(snapshot, snapshot_stat.size),
    );
    try testing.expectEqual(@as(usize, 15), linux.fcntl(snapshot, linux.F.GET_SEALS, 0));
    const changed = [_]u8{0};
    try testing.expectEqual(
        .PERM,
        linux.errno(linux.pwrite(snapshot, &changed, changed.len, 0)),
    );
    _ = linux.close(snapshot);
    snapshot_open = false;
    try testing.expectEqual(expected_descriptor, try nextDescriptor());
}

test "sealed snapshot executes after source pathname replacement and removal" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const source = try support.executable();
    defer allocator.free(source);
    const path = try copyExecutableFile(&fixture, "selected-executable", source);
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    if (linux.errno(linux.unlinkat(fixture.directory.dir.handle, "selected-executable", 0)) != .SUCCESS)
        return error.FixtureDelete;
    const replacement = try createExecutableFile(
        &fixture,
        "selected-executable",
        "not the selected executable\n",
    );
    defer allocator.free(replacement);

    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const expected_descriptor = try nextDescriptor();
    var result = try process.runCommand(allocator, io, try request(
        executable,
        &.{ path, "bytes", "3", "4", "0" },
        &environment,
        fixture.directory.dir,
    ));
    defer result.deinit(allocator);
    try testing.expect(result.succeeded());
    try testing.expectEqualStrings("ooo", result.stdout);
    try testing.expectEqualStrings("eeee", result.stderr);
    try testing.expectEqual(expected_descriptor, try nextDescriptor());
    try support.noChildren();
}

test "source mutation during snapshot is refused before spawn" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const source = try support.executable();
    defer allocator.free(source);
    const path = try copyExecutableFile(&fixture, "snapshot-race", source);
    defer allocator.free(path);
    var executable = try process.Executable.open(io, path);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var gate: process.CommandSnapshotGate = .{};
    var context: MutationContext = .{ .gate = &gate, .path = path };
    const thread = try std.Thread.spawn(.{}, mutateDuringSnapshot, .{&context});
    defer thread.join();
    try testing.expectError(error.ExecutableIdentityChanged, process.runCommandTest(
        allocator,
        io,
        try request(
            executable,
            &.{ path, "bytes", "0", "0", "0" },
            &environment,
            fixture.directory.dir,
        ),
        .{ .snapshot_gate = &gate },
    ));
    try testing.expect(!context.failed.load(.acquire));
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

test "ELF program alignment rejects malformed values and accepts valid forms" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    const source = try support.executable();
    defer allocator.free(source);

    for ([_]u64{ 0, 1, 2 }) |alignment| {
        var name_buffer: [32:0]u8 = undefined;
        const name = try std.fmt.bufPrintZ(&name_buffer, "valid-align-{d}", .{alignment});
        const path = try copyExecutableFile(&fixture, name, source);
        defer allocator.free(path);
        const descriptor = try openReadWrite(path);
        const program = try firstLoadProgram(descriptor);
        var encoded: [8]u8 = undefined;
        writeLittle64(&encoded, alignment);
        try pwriteAll(descriptor, &encoded, program.offset + 48);
        _ = linux.close(descriptor);
        var executable = try process.Executable.open(io, path);
        executable.close(io);
    }

    {
        const path = try copyExecutableFile(&fixture, "invalid-align-three", source);
        defer allocator.free(path);
        const descriptor = try openReadWrite(path);
        const program = try firstLoadProgram(descriptor);
        var encoded: [8]u8 = undefined;
        writeLittle64(&encoded, 3);
        try pwriteAll(descriptor, &encoded, program.offset + 48);
        _ = linux.close(descriptor);
        try testing.expectError(error.UnsupportedExecutableFormat, process.Executable.open(io, path));
    }
    {
        const path = try copyExecutableFile(&fixture, "invalid-align-congruence", source);
        defer allocator.free(path);
        const descriptor = try openReadWrite(path);
        const program = try firstLoadProgram(descriptor);
        var encoded: [8]u8 = undefined;
        writeLittle64(&encoded, program.virtual_address ^ 1);
        try pwriteAll(descriptor, &encoded, program.offset + 16);
        writeLittle64(&encoded, 2);
        try pwriteAll(descriptor, &encoded, program.offset + 48);
        _ = linux.close(descriptor);
        try testing.expectError(error.UnsupportedExecutableFormat, process.Executable.open(io, path));
    }
    {
        const path = try copyExecutableFile(&fixture, "truncated-program-header", source);
        defer allocator.free(path);
        const descriptor = try openReadWrite(path);
        var header: [64]u8 = undefined;
        try preadAll(descriptor, &header, 0);
        const end = readLittle64(header[32..40]) + readLittle16(header[54..56]) - 1;
        if (linux.errno(linux.ftruncate(descriptor, @intCast(end))) != .SUCCESS)
            return error.FixtureWrite;
        _ = linux.close(descriptor);
        try testing.expectError(error.UnsupportedExecutableFormat, process.Executable.open(io, path));
    }
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
    try testing.expectEqual(
        process.CommandIdentityTest.OwnedAction.retain,
        process.CommandIdentityTest.ownedAction(
            expected_pid,
            expected_start,
            true,
            expected_pid,
            expected_start,
            true,
        ),
    );
    try testing.expectEqual(
        process.CommandIdentityTest.OwnedAction.poison,
        process.CommandIdentityTest.ownedAction(
            expected_pid,
            expected_start,
            true,
            expected_pid,
            expected_start + 1,
            true,
        ),
    );
    try testing.expectEqual(
        process.CommandIdentityTest.OwnedAction.gone,
        process.CommandIdentityTest.ownedAction(
            expected_pid,
            expected_start,
            true,
            null,
            0,
            true,
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
    while (try process.CommandIdentityTest.identityLive(pid, start_ticks, descriptor)) {
        var fds: [0]linux.pollfd = .{};
        _ = linux.poll(&fds, 0, 1);
    }
    try testing.expect(try process.CommandIdentityTest.identityOwned(pid, start_ticks, descriptor));
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
    try testing.expect(!(try process.CommandIdentityTest.identityOwned(pid, start_ticks, descriptor)));
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

test "forced fast leader exit retains zombie identity and does not poison" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var result = try process.runCommandTest(
        allocator,
        io,
        try request(
            executable,
            &.{ path, "bytes", "0", "0", "0" },
            &environment,
            fixture.directory.dir,
        ),
        .{ .leader_track_delay_ms = 100 },
    );
    defer result.deinit(allocator);
    try testing.expect(result.succeeded());
    try testing.expectEqual(@as(u16, 2), result.reap_events);
    try support.noChildren();
}

test "leader exit observation uses the inclusive absolute deadline boundary" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]i2{ -1, 0, 1 }) |offset| {
        var command = try request(
            executable,
            &.{ path, "bytes", "0", "0", "0" },
            &environment,
            fixture.directory.dir,
        );
        const current = try process.monotonicNanoseconds();
        command.primary_deadline = .{ .expires_ns = current + 10 * std.time.ns_per_s };
        command.cleanup_deadline = .{ .expires_ns = current + 20 * std.time.ns_per_s };
        const observed = if (offset < 0)
            command.primary_deadline.expires_ns - 1
        else
            command.primary_deadline.expires_ns + @as(u64, @intCast(offset));
        var clock: process.CommandClockTest = .{
            .monitor_check_ns = command.primary_deadline.expires_ns - 1,
            .leader_exit_ns = observed,
        };
        var signals: process.CommandSignalTestState = .{};
        var result = try process.runCommandTest(
            allocator,
            io,
            command,
            .{ .clock = &clock, .signal = &signals },
        );
        defer result.deinit(allocator);
        try testing.expect(clock.monitor_checks >= 1);
        try testing.expectEqual(@as(u32, 1), clock.leader_exit_observations);
        try testing.expectEqual(observed, result.primary_completed_ns);
        try testing.expectEqual(.complete, result.cleanup);
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(@as(u32, 0), signals.attempts);
        try testing.expectEqual(
            std.process.Child.Term{ .exited = 0 },
            result.termination.?,
        );
        if (offset < 0) {
            try testing.expectEqual(
                process.CommandPrimary{ .exited = 0 },
                result.primary,
            );
            try testing.expect(!result.primary_deadline_reached);
            try testing.expect(result.succeeded());
        } else {
            try testing.expectEqual(.timeout, result.primary);
            try testing.expect(result.primary_deadline_reached);
            try testing.expect(!result.succeeded());
        }
        try testing.expect(result.completed_ns >= result.primary_completed_ns);
        try testing.expectEqual(
            result.descendants.observed + 2,
            result.reap_events,
        );
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

test "immediate-exit descendants count exactly through first excess and minimum reap budget" {
    var executable = try openExecutable();
    defer executable.close(io);
    const path = try support.executable();
    defer allocator.free(path);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for ([_]struct {
        count: u16,
        expected_reaps: u16,
        excess: bool,
    }{
        .{ .count = 4, .expected_reaps = 6, .excess = false },
        .{ .count = 5, .expected_reaps = 7, .excess = true },
    }) |case| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var count_buffer: [8]u8 = undefined;
        const count = try std.fmt.bufPrint(&count_buffer, "{d}", .{case.count});
        var command = try request(
            executable,
            &.{ path, "many-immediate", count },
            &environment,
            fixture.directory.dir,
        );
        command.limits.descendants = 4;
        command.limits.reap_events = 7;
        var result = try process.runCommand(allocator, io, command);
        defer result.deinit(allocator);
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(case.count, result.descendants.observed);
        try testing.expectEqual(case.count, result.descendants.identity_validated);
        try testing.expectEqual(case.excess, result.descendants.limit_exceeded);
        try testing.expect(!result.descendants.untracked);
        try testing.expectEqual(case.expected_reaps, result.reap_events);
        try testing.expectEqual(!case.excess, result.succeeded());
        try expectPidsGone(result.stdout, case.count);
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
