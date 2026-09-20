const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const diagnostics = @import("diagnostics.zig");
const files = @import("private_files.zig");
const Sha256 = @import("sha256.zig").Sha256;

const max_executable_bytes = 256 * 1024 * 1024;
const executable_snapshot_seals = 1 | 2 | 4 | 8;
const mfd_exec = 0x10;

comptime {
    if (builtin.os.tag != .linux) @compileError("Hyper-V process supervision currently requires Linux");
}

pub const Deadline = struct {
    expires_ns: u64,

    pub fn afterMilliseconds(milliseconds: u64) !Deadline {
        if (milliseconds == 0 or milliseconds > 24 * 60 * 60 * 1000) return error.InvalidDeadline;
        return .{ .expires_ns = try std.math.add(u64, try now(), milliseconds * std.time.ns_per_ms) };
    }

    pub fn expired(self: Deadline) !bool {
        return try now() >= self.expires_ns;
    }

    fn waitMilliseconds(self: Deadline, maximum: u32) !i32 {
        const current = try now();
        if (current >= self.expires_ns) return 0;
        return @intCast(@min(maximum, (self.expires_ns - current) / std.time.ns_per_ms + 1));
    }
};

pub const Options = struct {
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
    deadline: Deadline,
    cleanup_ms: u32 = 2000,
    stdout_limit: usize = 64 * 1024,
    stderr_limit: usize = 64 * 1024,
    cancel: ?*const std.atomic.Value(bool) = null,
    /// One already retained read-only descriptor deliberately survives exec.
    inherited_descriptor: ?linux.fd_t = null,
};

pub const Result = struct {
    storage: []u8,
    stdout: []const u8 = &.{},
    termination: ?std.process.Child.Term = null,
    failures: diagnostics.Failures = .{},
    cleanup_complete: bool = true,
    /// Private recovery metadata, never serialize this into diagnostics.
    unreaped_group: ?linux.pid_t = null,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.storage);
        allocator.free(self.storage);
        self.* = undefined;
    }
};

pub const Execution = struct {
    termination: ?std.process.Child.Term = null,
    failures: diagnostics.Failures = .{},
    cleanup_complete: bool = true,
    /// Private recovery metadata, not a reusable PID or public diagnostic.
    unreaped_group: ?linux.pid_t = null,
};

pub const ExecutableIdentity = struct {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    size: u64,
    mode: u16,
    uid: u32,
    mtime_seconds: i64,
    mtime_nanoseconds: u32,
    ctime_seconds: i64,
    ctime_nanoseconds: u32,
    content_sha256: [Sha256.digest_length]u8,

    fn fromStat(stat: files.Snapshot, content_sha256: [Sha256.digest_length]u8) ExecutableIdentity {
        return .{
            .device_major = stat.dev_major,
            .device_minor = stat.dev_minor,
            .inode = stat.ino,
            .size = stat.size,
            .mode = stat.mode,
            .uid = stat.uid,
            .mtime_seconds = stat.mtime.sec,
            .mtime_nanoseconds = stat.mtime.nsec,
            .ctime_seconds = stat.ctime.sec,
            .ctime_nanoseconds = stat.ctime.nsec,
            .content_sha256 = content_sha256,
        };
    }
};

/// Borrowed by CommandRequest. open accepts only a native 64-bit little-endian
/// ELF executable with bounded load headers; scripts and executable text return
/// UnsupportedExecutableFormat. The caller owns the retained descriptor until
/// close, and runCommand validates its recorded identity before exec.
pub const Executable = struct {
    file: std.Io.File,
    identity: ExecutableIdentity,

    pub fn open(io: std.Io, path: []const u8) !Executable {
        try files.absoluteFilePath(path);
        var path_buffer: [4096:0]u8 = undefined;
        @memcpy(path_buffer[0..path.len], path);
        path_buffer[path.len] = 0;
        const opened = linux.openat(linux.AT.FDCWD, path_buffer[0..path.len :0], .{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, 0);
        if (linux.errno(opened) != .SUCCESS) return error.ExecutableUnavailable;
        const handle = aboveStdio(@intCast(opened)) catch return error.ExecutableUnavailable;
        const file: std.Io.File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
        return fromOwnedFile(io, file);
    }

    pub fn fromFile(io: std.Io, source: std.Io.File) !Executable {
        const duplicated = linux.fcntl(source.handle, linux.F.DUPFD_CLOEXEC, 3);
        if (linux.errno(duplicated) != .SUCCESS)
            return error.ExecutableUnavailable;
        const file: std.Io.File = .{
            .handle = @intCast(duplicated),
            .flags = .{ .nonblocking = false },
        };
        const source_snapshot = files.snapshot(source) catch |err| {
            file.close(io);
            return err;
        };
        const duplicate_snapshot = files.snapshot(file) catch |err| {
            file.close(io);
            return err;
        };
        if (!files.sameSnapshot(source_snapshot, duplicate_snapshot)) {
            file.close(io);
            return error.ExecutableIdentityChanged;
        }
        return fromOwnedFile(io, file);
    }

    fn fromOwnedFile(io: std.Io, file: std.Io.File) !Executable {
        errdefer file.close(io);
        const stat = try files.snapshot(file);
        if (stat.mode & linux.S.IFMT != linux.S.IFREG or
            stat.mode & 0o111 == 0 or stat.mode & 0o6000 != 0)
            return error.InvalidExecutable;
        if (stat.size > max_executable_bytes) return error.UnsupportedExecutableFormat;
        _ = try validateElfExecutable(file.handle, stat.size);
        const content_sha256 = try hashExecutable(file.handle, stat.size);
        const verified = try files.snapshot(file);
        if (!files.sameSnapshot(stat, verified)) return error.ExecutableIdentityChanged;
        return .{ .file = file, .identity = .fromStat(verified, content_sha256) };
    }

    pub fn close(self: Executable, io: std.Io) void {
        self.file.close(io);
    }
};

fn validateElfExecutable(descriptor: linux.fd_t, size: u64) !bool {
    const header_size = 64;
    if (size < header_size or size > std.math.maxInt(i64)) return error.UnsupportedExecutableFormat;
    var header: [header_size]u8 = undefined;
    try preadExecutable(descriptor, &header, 0);
    if (!std.mem.eql(u8, header[0..4], "\x7fELF") or
        header[4] != 2 or header[5] != 1 or header[6] != 1)
        return error.UnsupportedExecutableFormat;

    const executable_type = readLittle16(header[16..18]);
    if (executable_type != 2 and executable_type != 3) return error.UnsupportedExecutableFormat;
    const expected_machine: u16 = switch (builtin.cpu.arch) {
        .x86_64 => 62,
        .aarch64 => 183,
        else => return error.UnsupportedExecutableFormat,
    };
    if (readLittle16(header[18..20]) != expected_machine or
        readLittle32(header[20..24]) != 1 or readLittle16(header[52..54]) != header_size)
        return error.UnsupportedExecutableFormat;

    const entry = readLittle64(header[24..32]);
    const program_offset = readLittle64(header[32..40]);
    const program_entry_size = readLittle16(header[54..56]);
    const program_count = readLittle16(header[56..58]);
    if (entry == 0 or program_entry_size != 56 or program_count == 0 or program_count > 1024)
        return error.UnsupportedExecutableFormat;
    const program_bytes = std.math.mul(u64, program_entry_size, program_count) catch
        return error.UnsupportedExecutableFormat;
    if (!fileRange(size, program_offset, program_bytes)) return error.UnsupportedExecutableFormat;

    var executable_entry = false;
    var interpreter_seen = false;
    var index: u16 = 0;
    while (index < program_count) : (index += 1) {
        var program: [56]u8 = undefined;
        const offset = std.math.add(u64, program_offset, @as(u64, index) * program_entry_size) catch
            return error.UnsupportedExecutableFormat;
        try preadExecutable(descriptor, &program, offset);
        const program_type = readLittle32(program[0..4]);
        const flags = readLittle32(program[4..8]);
        const file_offset = readLittle64(program[8..16]);
        const virtual_address = readLittle64(program[16..24]);
        const file_size = readLittle64(program[32..40]);
        const memory_size = readLittle64(program[40..48]);
        const alignment = readLittle64(program[48..56]);
        if (alignment > 1 and
            (alignment & (alignment - 1) != 0 or virtual_address % alignment != file_offset % alignment))
            return error.UnsupportedExecutableFormat;
        if (!fileRange(size, file_offset, file_size)) return error.UnsupportedExecutableFormat;
        if (program_type == 1) {
            if (file_size > memory_size) return error.UnsupportedExecutableFormat;
            const virtual_end = std.math.add(u64, virtual_address, memory_size) catch
                return error.UnsupportedExecutableFormat;
            if (flags & 1 != 0 and entry >= virtual_address and entry < virtual_end)
                executable_entry = true;
        } else if (program_type == 3) {
            if (interpreter_seen or file_size < 2 or file_size > 4096)
                return error.UnsupportedExecutableFormat;
            var interpreter: [4096]u8 = undefined;
            try preadExecutable(descriptor, interpreter[0..@intCast(file_size)], file_offset);
            const path = interpreter[0..@intCast(file_size)];
            if (path[0] != '/' or path[path.len - 1] != 0 or
                std.mem.indexOfScalar(u8, path[0 .. path.len - 1], 0) != null)
                return error.UnsupportedExecutableFormat;
            interpreter_seen = true;
        }
    }
    if (!executable_entry) return error.UnsupportedExecutableFormat;
    return interpreter_seen;
}

fn hashExecutable(descriptor: linux.fd_t, size: u64) ![Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: u64 = 0;
    while (offset < size) {
        const amount: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
        try preadExecutable(descriptor, buffer[0..amount], offset);
        hash.update(buffer[0..amount]);
        offset = try std.math.add(u64, offset, @as(u64, @intCast(amount)));
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn sameExecutablePhysical(identity: ExecutableIdentity, stat: files.Snapshot) bool {
    return identity.device_major == stat.dev_major and identity.device_minor == stat.dev_minor and
        identity.inode == stat.ino and identity.size == stat.size and identity.mode == stat.mode and
        identity.uid == stat.uid and identity.mtime_seconds == stat.mtime.sec and
        identity.mtime_nanoseconds == stat.mtime.nsec;
}

fn verifyExecutableSource(executable: Executable) !void {
    const before = files.snapshot(executable.file) catch return error.ExecutableUnavailable;
    if (!sameExecutablePhysical(executable.identity, before)) return error.ExecutableIdentityChanged;
    const content_sha256 = hashExecutable(executable.file.handle, before.size) catch
        return error.ExecutableIdentityChanged;
    const after = files.snapshot(executable.file) catch return error.ExecutableUnavailable;
    if (!files.sameSnapshot(before, after) or !sameExecutablePhysical(executable.identity, after) or
        !std.crypto.timing_safe.eql(
            [Sha256.digest_length]u8,
            executable.identity.content_sha256,
            content_sha256,
        ))
        return error.ExecutableIdentityChanged;
}

fn createExecutableMemfd() !linux.fd_t {
    var opened = linux.memfd_create(
        "hyperv-command-executable",
        linux.MFD.CLOEXEC | linux.MFD.ALLOW_SEALING | mfd_exec,
    );
    if (linux.errno(opened) == .INVAL)
        opened = linux.memfd_create(
            "hyperv-command-executable",
            linux.MFD.CLOEXEC | linux.MFD.ALLOW_SEALING,
        );
    if (linux.errno(opened) != .SUCCESS) return error.ExecutableSnapshotUnsupported;
    var descriptor: linux.fd_t = @intCast(opened);
    if (descriptor <= 2) {
        const duplicate = linux.fcntl(descriptor, linux.F.DUPFD_CLOEXEC, 3);
        _ = linux.close(descriptor);
        if (linux.errno(duplicate) != .SUCCESS) return error.ExecutableSnapshotUnavailable;
        descriptor = @intCast(duplicate);
    }
    return descriptor;
}

fn writeExecutableSnapshot(
    source: linux.fd_t,
    destination: linux.fd_t,
    size: u64,
    gate: ?*CommandSnapshotGate,
) ![Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: u64 = 0;
    var gate_released = false;
    while (offset < size) {
        const amount: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
        try preadExecutable(source, buffer[0..amount], offset);
        hash.update(buffer[0..amount]);
        var written: usize = 0;
        while (written < amount) {
            const position = std.math.add(u64, offset, written) catch
                return error.ExecutableSnapshotUnavailable;
            const result = linux.pwrite(
                destination,
                buffer[written..amount].ptr,
                amount - written,
                @intCast(position),
            );
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 0) return error.ExecutableSnapshotUnavailable;
                    written += result;
                },
                .INTR => continue,
                else => return error.ExecutableSnapshotUnavailable,
            }
        }
        offset = std.math.add(u64, offset, @as(u64, @intCast(amount))) catch
            return error.ExecutableSnapshotUnavailable;
        if (!gate_released and gate != null and offset < size) {
            const active = gate.?;
            active.started.store(true, .release);
            while (!active.continue_copy.load(.acquire)) try pause(1);
            gate_released = true;
        }
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn createExecutableSnapshot(executable: Executable, gate: ?*CommandSnapshotGate) !linux.fd_t {
    try verifyExecutableSource(executable);
    const descriptor = try createExecutableMemfd();
    errdefer _ = linux.close(descriptor);
    if (linux.errno(linux.fchmod(descriptor, 0o500)) != .SUCCESS)
        return error.ExecutableSnapshotUnavailable;
    const content_sha256 = writeExecutableSnapshot(
        executable.file.handle,
        descriptor,
        executable.identity.size,
        gate,
    ) catch |err| switch (err) {
        error.UnsupportedExecutableFormat, error.ExecutableUnavailable => return error.ExecutableIdentityChanged,
        else => return err,
    };
    if (!std.crypto.timing_safe.eql(
        [Sha256.digest_length]u8,
        executable.identity.content_sha256,
        content_sha256,
    ))
        return error.ExecutableIdentityChanged;
    try verifyExecutableSource(executable);
    _ = validateElfExecutable(descriptor, executable.identity.size) catch
        return error.ExecutableSnapshotInvalid;
    const stat = files.snapshot(.{ .handle = descriptor, .flags = .{ .nonblocking = false } }) catch
        return error.ExecutableSnapshotUnavailable;
    if (stat.mode & linux.S.IFMT != linux.S.IFREG or stat.mode & 0o7777 != 0o500 or
        stat.size != executable.identity.size or stat.nlink != 0)
        return error.ExecutableSnapshotInvalid;
    const sealed = linux.fcntl(descriptor, linux.F.ADD_SEALS, executable_snapshot_seals);
    if (linux.errno(sealed) != .SUCCESS or
        linux.fcntl(descriptor, linux.F.GET_SEALS, 0) != executable_snapshot_seals)
        return error.ExecutableSnapshotUnsupported;
    switch (linux.errno(linux.faccessat(descriptor, "", linux.X_OK, linux.AT.EMPTY_PATH))) {
        .SUCCESS => {},
        .ACCES, .PERM, .NOSYS => return error.ExecutableSnapshotUnsupported,
        else => return error.ExecutableSnapshotUnavailable,
    }
    return descriptor;
}

fn createCommandExecutableSnapshot(
    executable: Executable,
    gate: ?*CommandSnapshotGate,
    fault: ?CommandPreSpawnTestFault,
) !linux.fd_t {
    if (fault) |active| switch (active) {
        .snapshot_unsupported => return error.ExecutableSnapshotUnsupported,
        .snapshot_local_io => return error.ExecutableSnapshotUnavailable,
        .spawn_local_io => {},
    };
    return createExecutableSnapshot(executable, gate);
}

pub const ExecutableSnapshotTest = struct {
    pub fn create(executable: Executable) !linux.fd_t {
        if (!builtin.is_test) @compileError("executable snapshot evidence is test-only");
        return createExecutableSnapshot(executable, null);
    }

    pub fn contentSha256(descriptor: linux.fd_t, size: u64) ![Sha256.digest_length]u8 {
        if (!builtin.is_test) @compileError("executable snapshot evidence is test-only");
        return hashExecutable(descriptor, size);
    }
};

fn preadExecutable(descriptor: linux.fd_t, bytes: []u8, offset: u64) !void {
    var read: usize = 0;
    while (read < bytes.len) {
        const position = std.math.add(u64, offset, read) catch return error.UnsupportedExecutableFormat;
        const amount = linux.pread(descriptor, bytes[read..].ptr, bytes.len - read, @intCast(position));
        switch (linux.errno(amount)) {
            .SUCCESS => {
                if (amount == 0) return error.UnsupportedExecutableFormat;
                read += amount;
            },
            .INTR => continue,
            else => return error.ExecutableUnavailable,
        }
    }
}

fn fileRange(size: u64, offset: u64, length: u64) bool {
    const end = std.math.add(u64, offset, length) catch return false;
    return end <= size;
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

pub const ExecutableFormatTest = struct {
    pub fn usesInterpreter(executable: Executable) !bool {
        if (!builtin.is_test) @compileError("executable format evidence is test-only");
        const stat = try files.snapshot(executable.file);
        return validateElfExecutable(executable.file.handle, stat.size);
    }
};

pub const CommandSnapshotGate = struct {
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    continue_copy: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

pub const CommandPidfdTestFault = enum {
    second_parent_verification,
    temporary_signal,
};

pub const CommandPidfdTestState = struct {
    fault: CommandPidfdTestFault,
    candidate_opens: u32 = 0,
    candidate_closes: u32 = 0,
    candidate_transfers: u32 = 0,
    fault_injections: u32 = 0,
    fault_candidate: ?u32 = null,
    fault_candidate_closes: u32 = 0,
    fault_candidate_transfers: u32 = 0,

    fn openCandidate(self: *CommandPidfdTestState) u32 {
        const candidate = self.candidate_opens;
        self.candidate_opens += 1;
        return candidate;
    }

    fn inject(self: *CommandPidfdTestState, fault: CommandPidfdTestFault, candidate: u32) bool {
        if (self.fault != fault or self.fault_injections != 0) return false;
        self.fault_injections = 1;
        self.fault_candidate = candidate;
        return true;
    }

    fn closeCandidate(self: *CommandPidfdTestState, candidate: u32) void {
        self.candidate_closes += 1;
        if (self.fault_candidate == candidate) self.fault_candidate_closes += 1;
    }

    fn transferCandidate(self: *CommandPidfdTestState, candidate: u32) void {
        self.candidate_transfers += 1;
        if (self.fault_candidate == candidate) self.fault_candidate_transfers += 1;
    }
};

pub const CommandClockTest = struct {
    monitor_check_ns: u64,
    leader_exit_ns: u64,
    monitor_checks: u32 = 0,
    leader_exit_observations: u32 = 0,
};

pub const CommandPostReleaseTestFault = enum {
    monitor_clock,
    monitor_cancelled,
    monitor_event,
    monitor_output,
    monitor_io,
    monitor_poll,
    fallback_clock,
    result_build,
    cleanup_proof,
    unwind,
    unwind_cleanup_proof,
};

pub const CommandPostReleaseTestState = struct {
    fault: CommandPostReleaseTestFault,
    boundaries: u32 = 0,
    fault_injections: u32 = 0,

    fn inject(self: *CommandPostReleaseTestState, fault: CommandPostReleaseTestFault) bool {
        if (self.fault != fault or self.fault_injections != 0) return false;
        self.fault_injections = 1;
        return true;
    }
};

pub const CommandSignalTestState = struct {
    attempts: u32 = 0,
};

pub const CommandLeaderTrackTest = struct {
    observed_ns: u64,
    fault_injections: u32 = 0,
    timestamp_observations: u32 = 0,
};

pub const CommandGateTestFault = enum {
    pidfd,
    procfs,
    identity,
    tracker,
    clock,
    ready_eof,
    ready_bad,
    release_write,
    parent_close,
    parent_crash,
    release_bad,
    recovery_proof,
};

pub const CommandGateTestState = struct {
    fault: CommandGateTestFault,
    fault_injections: u32 = 0,

    fn inject(self: *CommandGateTestState, fault: CommandGateTestFault) bool {
        if (self.fault != fault or self.fault_injections != 0) return false;
        self.fault_injections = 1;
        return true;
    }
};

pub const CommandPreSpawnTestFault = enum {
    snapshot_unsupported,
    snapshot_local_io,
    spawn_local_io,
};

pub const CommandTestOptions = struct {
    snapshot_gate: ?*CommandSnapshotGate = null,
    leader_track_delay_ms: u32 = 0,
    pidfd: ?*CommandPidfdTestState = null,
    clock: ?*CommandClockTest = null,
    signal: ?*CommandSignalTestState = null,
    leader_track: ?*CommandLeaderTrackTest = null,
    gate: ?*CommandGateTestState = null,
    post_release: ?*CommandPostReleaseTestState = null,
    pre_spawn: ?CommandPreSpawnTestFault = null,
};

const command_contract_source =
    @embedFile("process-command-v1.json");
const command_contract_expected =
    "{\"complete_cleanup_events_min\":5,\"complete_primary_events_min\":1," ++
    "\"pre_release_cleanup_events_min\":4}\n";
comptime {
    if (!std.mem.eql(u8, command_contract_source, command_contract_expected))
        @compileError("process-command-v1.json does not match the native producer contract");
}
pub const command_complete_primary_events_min: u32 = 1;
pub const command_complete_cleanup_events_min: u32 = 5;
pub const command_pre_release_cleanup_events_min: u32 = 4;

pub const CommandLimits = struct {
    stdout_bytes: usize = 64 * 1024,
    stderr_bytes: usize = 64 * 1024,
    descendants: u16 = 64,
    primary_events: u32 = 1_000_000,
    cleanup_events: u32 = 1_000_000,
    proc_entries_per_scan: u32 = 262_144,
    /// Must cover leader, requested descendants, first-excess sentinel and ECHILD.
    reap_events: u16 = 512,
    term_grace_ms: u32 = 100,
};

/// Internal trusted-command contract. This is deliberately not a general CLI:
/// argv, environment, cwd, executable descriptor and both absolute deadlines
/// are supplied by the owning controller. After fork, the child remains behind
/// a close-on-exec sequenced-socket gate until its pidfd/start identity belongs
/// to the tracker; the original primary deadline continues across that gate.
pub const CommandRequest = struct {
    executable: Executable,
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
    primary_deadline: Deadline,
    cleanup_deadline: Deadline,
    cancel: ?*const std.atomic.Value(bool) = null,
    limits: CommandLimits = .{},
};

pub const CommandPrimary = union(enum) {
    exited: u8,
    signal: linux.SIG,
    unknown: u32,
    timeout,
    cancelled,
    output_overflow,
    exec_failed,
    snapshot_unsupported,
    event_limit,
    local_io,
    executable_changed,
};

pub const CommandStreamStatus = enum { complete, overflow, io_failed, incomplete };

pub const CommandCleanup = enum {
    complete,
    not_required,
    deadline,
    event_limit,
    descendant_untracked,
    identity_changed,
    signal_failed,
    reap_failed,
    proc_unavailable,
    local_io,
};

pub const CommandDescendants = struct {
    observed: u16 = 0,
    adopted: u16 = 0,
    identity_validated: u16 = 0,
    limit_exceeded: bool = false,
    untracked: bool = false,
};

pub const CommandResult = struct {
    storage: []u8,
    stdout: []const u8 = &.{},
    stderr: []const u8 = &.{},
    started_ns: u64,
    primary_completed_ns: u64,
    completed_ns: u64,
    executable: ExecutableIdentity,
    executable_stable: bool = true,
    primary: CommandPrimary,
    termination: ?std.process.Child.Term = null,
    primary_deadline_reached: bool = false,
    cancellation_observed: bool = false,
    stdout_status: CommandStreamStatus = .incomplete,
    stderr_status: CommandStreamStatus = .incomplete,
    descendants: CommandDescendants = .{},
    cleanup: CommandCleanup = .not_required,
    cleanup_complete: bool = true,
    primary_events: u32 = 0,
    cleanup_events: u32 = 0,
    reap_events: u16 = 0,

    pub fn succeeded(self: CommandResult) bool {
        return switch (self.primary) {
            .exited => |code| code == 0 and self.cleanup_complete and
                self.cleanup == .complete and !self.descendants.limit_exceeded and
                self.stdout_status == .complete and self.stderr_status == .complete and
                self.executable_stable,
            else => false,
        };
    }

    pub fn deinit(self: *CommandResult, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.storage);
        allocator.free(self.storage);
        self.* = undefined;
    }
};

const CommandCleanupGuard = struct {
    io: std.Io,
    proc: linux.fd_t,
    request: CommandRequest,
    tracker: *OwnedTracker,
    child: *Spawned,
    capture: *Capture,
    result: *CommandResult,
    gate_test: ?*CommandGateTestState,
    post_release_test: ?*CommandPostReleaseTestState,
    gate_released: bool = false,
    normal_cleanup_completed: bool = false,
    handled: bool = false,

    fn finishGated(
        self: *CommandCleanupGuard,
        candidate: ?*PidfdOwnership,
        primary: CommandPrimary,
        primary_observed_ns: u64,
        unavailable_cleanup: CommandCleanup,
    ) CommandResult {
        const finished = finishGatedCommandFailure(
            self.io,
            self.proc,
            self.request,
            self.tracker,
            self.child,
            self.capture,
            candidate,
            primary,
            primary_observed_ns,
            unavailable_cleanup,
            self.gate_test,
            self.result,
        );
        self.handled = true;
        return finished;
    }

    fn completeNormal(self: *CommandCleanupGuard) void {
        self.normal_cleanup_completed = true;
        self.handled = true;
    }

    fn completeFailed(self: *CommandCleanupGuard) void {
        self.handled = true;
    }

    fn deinit(self: *CommandCleanupGuard) void {
        if (self.handled or self.normal_cleanup_completed) return;
        if (!self.gate_released) {
            self.child.closeGate();
            const descriptor = if (self.tracker.len == 1)
                self.tracker.items[0].pidfd
            else
                commandPidfd(self.child.pid) catch {
                    poisonUnpinnedGatedChild(
                        self.child.pid,
                        self.request,
                        self.result,
                    );
                    self.result.cleanup_complete = false;
                    poisoned.store(true, .release);
                    return;
                };
            var recovered_descriptor: ?linux.fd_t = null;
            if (self.tracker.len == 0) recovered_descriptor = descriptor;
            defer if (recovered_descriptor) |owned| {
                _ = linux.close(owned);
            };
            recoverGatedChild(
                self.proc,
                self.child.pid,
                descriptor,
                if (self.tracker.len == 1)
                    self.tracker.items[0].start_ticks
                else
                    null,
                self.request,
                self.gate_test,
                self.result,
            ) catch {
                poisonGatedChild(
                    self.child.pid,
                    descriptor,
                    self.request,
                    self.result,
                );
                self.result.cleanup_complete = false;
                poisoned.store(true, .release);
                return;
            };
            if (self.tracker.len == 1)
                self.tracker.items[0].reaped = self.result.termination != null;
            self.result.cleanup = .complete;
            self.result.cleanup_complete = true;
            return;
        }
        cleanupCommand(
            self.io,
            self.proc,
            self.request,
            self.tracker,
            self.result,
            self.post_release_test,
        ) catch |err| {
            self.result.cleanup_complete = false;
            self.result.cleanup = commandCleanupFromError(err);
            poisonCommand(
                self.io,
                self.proc,
                self.request,
                self.tracker,
                self.result,
            );
            return;
        };
        self.normal_cleanup_completed = true;
    }
};

pub const private_output_limit = 8 * 1024 * 1024;
pub const CaptureState = enum { complete, partial, overflow, io_failed, durability_failed };
pub const PrivateOptions = struct {
    /// cleanup_ms must cover the TERM grace and a separate reaping reserve.
    process: Options,
    /// When supplied, execute only the retained ELF snapshot through execveat.
    executable: ?Executable = null,
    term_grace_ms: u32 = 2000,
    /// An optional outer cleanup bound; never extends process.cleanup_ms.
    cleanup_deadline: ?Deadline = null,
    /// TERM only the supervisor first, allowing it to clean its own groups.
    nested_supervisor: bool = false,
};

pub const PrivateResult = struct {
    execution: Execution,
    capture: CaptureState,
    stdout_bytes: usize,
    stderr_bytes: usize,

    pub fn succeeded(self: PrivateResult) bool {
        if (self.execution.failures.primary != null or self.execution.failures.cleanup != null or self.execution.failures.recording != null or
            !self.execution.cleanup_complete or self.capture != .complete) return false;
        return if (self.execution.termination) |termination| switch (termination) {
            .exited => |code| code == 0,
            else => false,
        } else false;
    }

    /// Failure output remains private diagnostic evidence, never accepted input.
    pub fn requireSuccess(self: PrivateResult) !void {
        if (!self.succeeded()) return error.UnsuccessfulCapture;
    }
};

var busy = std.atomic.Value(bool).init(false);
var poisoned = std.atomic.Value(bool).init(false);
// An unresolved writer keeps its lock until process exit, even if the caller
// closes its original guard. Poison is deliberately irreversible.
var retained_writer: ?linux.fd_t = null;

/// Explicit process-wide ownership policy. Use in a dedicated supervisor, not an
/// application with unrelated waitpid users. Legacy run/runPrivate require group
/// containment; runCommand opts into bounded pidfd/procfs descendant discovery.
pub fn initialize() !void {
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)) != .SUCCESS)
        return error.SubreaperUnavailable;
}

/// No inherited environment, PATH lookup, shell, raw stderr, or automatic replay.
/// A failed cleanup poisons this supervisor; writer ownership must not transfer.
pub fn run(allocator: std.mem.Allocator, io: std.Io, options: Options) !Result {
    _ = io;
    try validateOptions(options, 4 * 1024 * 1024);
    try enter();
    defer busy.store(false, .release);
    var result: Result = .{ .storage = try allocator.alloc(u8, options.stdout_limit) };
    @memset(result.storage, 0);
    errdefer result.deinit(allocator);
    var capture: Capture = .{ .output = result.storage, .stderr_limit = options.stderr_limit };
    const execution = try supervise(allocator, options, &capture, .{}, null);
    result.termination = execution.termination;
    result.failures = execution.failures;
    result.cleanup_complete = execution.cleanup_complete;
    result.unreaped_group = execution.unreaped_group;
    if (result.failures.primary == null and result.cleanup_complete) {
        result.stdout = result.storage[0..capture.stdout_count];
    } else {
        std.crypto.secureZero(u8, result.storage);
    }
    return result;
}

/// Supervise one trusted Linux command and all ordinary descendants in a
/// dedicated subreaper process. Descendants are identified by procfs
/// parentage/start time, pinned with pidfds, signalled exactly, and fully
/// reaped. A pre-release failure can remain unpoisoned only after the gated
/// leader is pidfd-reaped and final ECHILD proves that user code never created
/// an owned tree. Cleanup failure irreversibly poisons this process.
pub fn runCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: CommandRequest,
) !CommandResult {
    return runCommandImpl(allocator, io, request, null);
}

pub fn runCommandTest(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: CommandRequest,
    test_options: CommandTestOptions,
) !CommandResult {
    if (!builtin.is_test) @compileError("command supervision faults are test-only");
    return runCommandImpl(allocator, io, request, test_options);
}

fn runCommandImpl(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: CommandRequest,
    test_options: ?CommandTestOptions,
) !CommandResult {
    const options = commandOptions(request);
    try validateOptions(options, 4 * 1024 * 1024);
    try validateCommandLimits(request.limits);
    try enter();
    defer busy.store(false, .release);
    try requireNoChildren();
    const proc = try openCommandProc();
    defer _ = linux.close(proc);
    try requirePidfds();

    const started_ns = try now();
    const total = try std.math.add(usize, request.limits.stdout_bytes, request.limits.stderr_bytes);
    var result: CommandResult = .{
        .storage = try allocator.alloc(u8, total),
        .started_ns = started_ns,
        .primary_completed_ns = started_ns,
        .completed_ns = started_ns,
        .executable = request.executable.identity,
        .primary = .local_io,
    };
    @memset(result.storage, 0);
    errdefer result.deinit(allocator);
    var capture: Capture = .{
        .output = result.storage[0..request.limits.stdout_bytes],
        .stderr_output = result.storage[request.limits.stdout_bytes..],
        .stderr_limit = request.limits.stderr_bytes,
    };
    var observed_ns = try now();
    if (observed_ns >= request.primary_deadline.expires_ns)
        return completePreSpawnCommand(&result, .timeout, observed_ns);
    if (cancelled(options))
        return completePreSpawnCommand(&result, .cancelled, observed_ns);

    const snapshot = createCommandExecutableSnapshot(
        request.executable,
        if (test_options) |options_value| options_value.snapshot_gate else null,
        if (test_options) |options_value| options_value.pre_spawn else null,
    ) catch |err| switch (err) {
        error.ExecutableSnapshotUnsupported => {
            observed_ns = try now();
            return completePreSpawnCommand(
                &result,
                if (observed_ns >= request.primary_deadline.expires_ns)
                    .timeout
                else
                    .snapshot_unsupported,
                observed_ns,
            );
        },
        error.ExecutableSnapshotUnavailable, error.ExecutableSnapshotInvalid => {
            observed_ns = try now();
            return completePreSpawnCommand(
                &result,
                if (observed_ns >= request.primary_deadline.expires_ns) .timeout else .local_io,
                observed_ns,
            );
        },
        else => return err,
    };
    defer _ = linux.close(snapshot);
    observed_ns = try now();
    if (observed_ns >= request.primary_deadline.expires_ns)
        return completePreSpawnCommand(&result, .timeout, observed_ns);
    if (cancelled(options))
        return completePreSpawnCommand(&result, .cancelled, observed_ns);

    var tracker = try OwnedTracker.init(
        allocator,
        request.limits.descendants,
        if (test_options) |options_value| options_value.pidfd else null,
        if (test_options) |options_value| options_value.signal else null,
    );
    defer tracker.deinit(allocator);
    var child = spawnCommandOwned(
        allocator,
        options,
        snapshot,
        if (test_options) |options_value| options_value.pre_spawn else null,
        if (test_options) |options_value| options_value.gate else null,
    ) catch |err| {
        if (err != error.SpawnFailed) return err;
        observed_ns = try now();
        return completePreSpawnCommand(
            &result,
            if (observed_ns >= request.primary_deadline.expires_ns) .timeout else .local_io,
            observed_ns,
        );
    };
    defer _ = linux.close(child.stdout);
    defer _ = linux.close(child.stderr);
    defer _ = linux.close(child.control);
    defer child.closeGate();
    var cleanup_guard: CommandCleanupGuard = .{
        .io = io,
        .proc = proc,
        .request = request,
        .tracker = &tracker,
        .child = &child,
        .capture = &capture,
        .result = &result,
        .gate_test = if (test_options) |options_value| options_value.gate else null,
        .post_release_test = if (test_options) |options_value|
            options_value.post_release
        else
            null,
    };
    defer cleanup_guard.deinit();

    if (test_options) |options_value| {
        if (options_value.leader_track_delay_ms != 0) {
            pause(@intCast(options_value.leader_track_delay_ms)) catch {
                const failure_ns = now() catch observed_ns;
                return cleanup_guard.finishGated(
                    null,
                    .local_io,
                    failure_ns,
                    .local_io,
                );
            };
        }
    }
    const leader_pidfd = commandPidfd(child.pid) catch {
        const failure_ns = now() catch observed_ns;
        return cleanup_guard.finishGated(
            null,
            .local_io,
            failure_ns,
            .proc_unavailable,
        );
    };
    var leader_ownership = PidfdOwnership.init(leader_pidfd);
    defer leader_ownership.deinit();
    if (commandGateInject(
        if (test_options) |options_value| options_value.gate else null,
        .pidfd,
    )) {
        const failure_ns = now() catch observed_ns;
        return cleanup_guard.finishGated(
            &leader_ownership,
            .local_io,
            failure_ns,
            .proc_unavailable,
        );
    }
    var leader_start_ticks: ?u64 = null;
    tracker.addLeader(
        proc,
        child.pid,
        &leader_ownership,
        &leader_start_ticks,
        if (test_options) |options_value| options_value.leader_track else null,
        if (test_options) |options_value| options_value.gate else null,
    ) catch |err| {
        const primary_observed_ns = commandLeaderTrackFailureObserved(
            if (test_options) |options_value| options_value.leader_track else null,
        ) catch observed_ns;
        return cleanup_guard.finishGated(
            &leader_ownership,
            classifyPreReleasePrimary(.local_io, options, primary_observed_ns),
            primary_observed_ns,
            switch (err) {
                error.IdentityChanged => .identity_changed,
                error.ProcessGone, error.ProcUnavailable => .proc_unavailable,
                error.PollFailed, error.TrackerUnavailable => .local_io,
            },
        );
    };

    var pre_release_ns = primaryPreReleaseObservation(
        if (test_options) |options_value| options_value.gate else null,
    ) catch {
        return cleanup_guard.finishGated(
            null,
            .local_io,
            observed_ns,
            .local_io,
        );
    };
    if (pre_release_ns >= request.primary_deadline.expires_ns or cancelled(options)) {
        return cleanup_guard.finishGated(
            null,
            classifyPreReleasePrimary(.local_io, options, pre_release_ns),
            pre_release_ns,
            .local_io,
        );
    }
    awaitCommandGateReady(
        child.gate.?,
        options,
        if (test_options) |options_value| options_value.gate else null,
        &pre_release_ns,
    ) catch |err| {
        if (err == error.GateEof)
            _ = commandGateInject(
                if (test_options) |options_value| options_value.gate else null,
                .ready_eof,
            );
        if (err == error.GateProtocol)
            _ = commandGateInject(
                if (test_options) |options_value| options_value.gate else null,
                .ready_bad,
            );
        const failure_ns = if (err == error.DeadlineExceeded or err == error.Cancelled)
            pre_release_ns
        else
            primaryPreReleaseObservation(
                if (test_options) |options_value| options_value.gate else null,
            ) catch pre_release_ns;
        return cleanup_guard.finishGated(
            null,
            classifyPreReleasePrimary(
                if (err == error.Cancelled) .cancelled else .local_io,
                options,
                failure_ns,
            ),
            failure_ns,
            .local_io,
        );
    };
    pre_release_ns = primaryPreReleaseObservation(
        if (test_options) |options_value| options_value.gate else null,
    ) catch {
        return cleanup_guard.finishGated(
            null,
            .local_io,
            pre_release_ns,
            .local_io,
        );
    };
    if (pre_release_ns >= request.primary_deadline.expires_ns or cancelled(options)) {
        return cleanup_guard.finishGated(
            null,
            classifyPreReleasePrimary(.local_io, options, pre_release_ns),
            pre_release_ns,
            .local_io,
        );
    }
    if (commandGateInject(
        if (test_options) |options_value| options_value.gate else null,
        .parent_close,
    ) or commandGateFaultIs(
        if (test_options) |options_value| options_value.gate else null,
        .recovery_proof,
    )) {
        child.closeGate();
        return cleanup_guard.finishGated(
            null,
            .local_io,
            pre_release_ns,
            .local_io,
        );
    }
    if (commandGateInject(
        if (test_options) |options_value| options_value.gate else null,
        .parent_crash,
    )) linux.exit_group(123);
    releaseCommandGate(
        child.gate.?,
        if (test_options) |options_value| options_value.gate else null,
    ) catch {
        _ = commandGateInject(
            if (test_options) |options_value| options_value.gate else null,
            .release_write,
        );
        const failure_ns = primaryPreReleaseObservation(
            if (test_options) |options_value| options_value.gate else null,
        ) catch pre_release_ns;
        return cleanup_guard.finishGated(
            null,
            classifyPreReleasePrimary(.local_io, options, failure_ns),
            failure_ns,
            .local_io,
        );
    };
    cleanup_guard.gate_released = true;
    child.closeGate();

    var monitor_completed = true;
    var terminal_observed_ns: ?u64 = null;
    monitorCommand(
        &child,
        options,
        &capture,
        request.limits.primary_events,
        &result.primary_events,
        if (test_options) |options_value| options_value.clock else null,
        cleanup_guard.post_release_test,
        &terminal_observed_ns,
    ) catch |err| {
        monitor_completed = false;
        switch (err) {
            error.DeadlineExceeded => {
                result.primary = .timeout;
                result.primary_deadline_reached = true;
            },
            error.Cancelled => {
                result.primary = .cancelled;
                result.cancellation_observed = true;
            },
            error.StdoutLimit => {
                result.primary = .output_overflow;
                result.stdout_status = .overflow;
            },
            error.StderrLimit => {
                result.primary = .output_overflow;
                result.stderr_status = .overflow;
            },
            error.SpawnFailed => result.primary = .exec_failed,
            error.ExecutableSnapshotUnsupported => result.primary = .snapshot_unsupported,
            error.EventLimit => result.primary = .event_limit,
            error.StdoutIo => result.stdout_status = .io_failed,
            error.StderrIo => result.stderr_status = .io_failed,
            else => {},
        }
        if (err == error.StdoutIo or err == error.StderrIo or err == error.PollFailed or err == error.WaitFailed)
            result.primary = .local_io;
    };
    const primary_observed_ns = terminal_observed_ns orelse
        commandPostReleaseFallbackTimestamp(cleanup_guard.post_release_test) catch blk: {
        if (monitor_completed) {
            monitor_completed = false;
            result.primary = .local_io;
        }
        break :blk pre_release_ns;
    };
    completePrimaryCommandTimingAt(&result, primary_observed_ns);
    if (result.primary_completed_ns >= request.primary_deadline.expires_ns) {
        monitor_completed = false;
        result.primary = .timeout;
        result.primary_deadline_reached = true;
        result.cancellation_observed = false;
    }
    commandPostReleaseResultBuild(cleanup_guard.post_release_test) catch {
        monitor_completed = false;
        result.primary = .local_io;
        result.primary_deadline_reached = false;
        result.cancellation_observed = false;
    };
    if (commandPostReleaseBoundaryIs(
        cleanup_guard.post_release_test,
        .unwind,
    ) or commandPostReleaseBoundaryIs(
        cleanup_guard.post_release_test,
        .unwind_cleanup_proof,
    )) return error.PostReleaseTestFailure;

    cleanupCommand(
        io,
        proc,
        request,
        &tracker,
        &result,
        cleanup_guard.post_release_test,
    ) catch |err| {
        result.cleanup_complete = false;
        result.cleanup = commandCleanupFromError(err);
        poisonCommand(io, proc, request, &tracker, &result);
    };
    if (result.cleanup_complete) {
        cleanup_guard.completeNormal();
    } else {
        cleanup_guard.completeFailed();
    }
    result.descendants = tracker.report;

    finishCommandCapture(&capture, child.stdout, child.stderr, &result);
    result.stdout = capture.output[0..capture.stdout_count];
    result.stderr = capture.stderr_output[0..capture.stderr_count];
    if (monitor_completed) result.primary = primaryFromTermination(result.termination);
    if (primaryExitedZero(result.primary) and
        (result.stdout_status == .overflow or result.stderr_status == .overflow))
        result.primary = .output_overflow;

    verifyExecutableSource(request.executable) catch {
        result.executable_stable = false;
    };
    if (!result.executable_stable and primaryExitedZero(result.primary))
        result.primary = .executable_changed;
    const completed_ns = now() catch {
        if (monitor_completed) {
            monitor_completed = false;
            result.primary = .local_io;
            result.primary_deadline_reached = false;
            result.cancellation_observed = false;
        }
        result.completed_ns = result.primary_completed_ns;
        return result;
    };
    result.completed_ns = @max(result.primary_completed_ns, completed_ns);
    return result;
}

fn completePreSpawnCommand(
    result: *CommandResult,
    primary: CommandPrimary,
    observed_ns: u64,
) CommandResult {
    result.primary = primary;
    result.primary_deadline_reached = primary == .timeout;
    result.cancellation_observed = primary == .cancelled;
    result.stdout_status = .complete;
    result.stderr_status = .complete;
    completePrimaryCommandTimingAt(result, observed_ns);
    result.completed_ns = result.primary_completed_ns;
    return result.*;
}

fn completePrimaryCommandTimingAt(result: *CommandResult, timestamp: u64) void {
    result.primary_completed_ns = @max(result.started_ns, timestamp);
}

fn completePrimaryCommandTiming(result: *CommandResult) !void {
    completePrimaryCommandTimingAt(result, try now());
}

fn completeCleanupCommandTiming(result: *CommandResult) !void {
    const timestamp = try now();
    result.completed_ns = @max(result.primary_completed_ns, timestamp);
}

fn completeAllCommandTiming(result: *CommandResult) !void {
    try completePrimaryCommandTiming(result);
    try completeCleanupCommandTiming(result);
}

/// Opt-in private raw capture. Borrows a live writer guard and never hands file
/// descriptors to the child. Both names are consume-once, including failures.
/// This dedicated supervisor must have no unrelated children or child reapers.
/// For non-nested commands, observed leader exit plus both pipe EOFs ends the
/// command: any remaining group members are abandoned and killed without grace.
/// EOF is not proof of descendant exit; the final group signal and full reaping
/// are still required. Running work and inherited open pipes retain TERM grace.
pub fn runPrivate(
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *files.Locked,
    stdout_name: []const u8,
    stderr_name: []const u8,
    options: PrivateOptions,
) !PrivateResult {
    return runPrivateImpl(allocator, io, lock, stdout_name, stderr_name, options, null);
}

pub const PrivateTestFault = enum { pre_exec_stall, capture_write, sync };

pub fn runPrivateTest(
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *files.Locked,
    stdout_name: []const u8,
    stderr_name: []const u8,
    options: PrivateOptions,
    fault: PrivateTestFault,
) !PrivateResult {
    if (!builtin.is_test) @compileError("Private supervision faults are test-only");
    return runPrivateImpl(allocator, io, lock, stdout_name, stderr_name, options, fault);
}

fn runPrivateImpl(
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: *files.Locked,
    stdout_name: []const u8,
    stderr_name: []const u8,
    options: PrivateOptions,
    fault: ?PrivateTestFault,
) !PrivateResult {
    try validateOptions(options.process, private_output_limit);
    if (options.term_grace_ms == 0 or options.term_grace_ms >= options.process.cleanup_ms or
        std.mem.eql(u8, stdout_name, stderr_name)) return error.InvalidOptions;
    try files.basename(stdout_name);
    try files.basename(stderr_name);
    if (stdout_name[0] == '.' or stderr_name[0] == '.') return error.InvalidOptions;
    try enter();
    defer busy.store(false, .release);
    try requireNoChildren();
    const guard = lock.file orelse return error.LockNotHeld;
    const lease = linux.fcntl(guard.handle, linux.F.DUPFD_CLOEXEC, 3);
    if (linux.errno(lease) != .SUCCESS) return error.LockNotHeld;
    defer {
        if (poisoned.load(.acquire)) {
            retained_writer = @intCast(lease);
        } else {
            _ = linux.close(@intCast(lease));
        }
    }
    try validatePrivateDirectory(lock.directory.dir);
    const stdout = try createCapture(lock.directory.dir, stdout_name);
    defer stdout.close(io);
    const stderr = try createCapture(lock.directory.dir, stderr_name);
    defer stderr.close(io);
    var capture: Capture = .{
        .output = &.{},
        .stderr_limit = options.process.stderr_limit,
        .private = .{ .stdout = stdout, .stderr = stderr, .limit = options.process.stdout_limit },
        .fault = fault,
    };
    const executable = if (options.executable) |value|
        try createExecutableSnapshot(value, null)
    else
        null;
    defer if (executable) |descriptor| {
        _ = linux.close(descriptor);
    };
    const execution = try supervise(allocator, options.process, &capture, .{
        .term_grace_ms = options.term_grace_ms,
        .deadline = options.cleanup_deadline,
        .all_children = true,
        .nested_supervisor = options.nested_supervisor,
        .reap_reserve_ms = @min(1000, options.process.cleanup_ms - options.term_grace_ms),
        .fault = fault,
    }, executable);
    // Preserve partial output, including failed execution, but never label it
    // complete merely because the bytes and their directory entry are durable.
    stdout.sync(io) catch {
        capture.state = .durability_failed;
    };
    stderr.sync(io) catch {
        capture.state = .durability_failed;
    };
    if (linux.errno(linux.fsync(lock.directory.dir.handle)) != .SUCCESS) capture.state = .durability_failed;
    if (fault == .sync) capture.state = .durability_failed;
    validateCapture(io, lock.directory, stdout_name, stdout, capture.stdout_count) catch {
        capture.state = .io_failed;
    };
    validateCapture(io, lock.directory, stderr_name, stderr, capture.stderr_count) catch {
        capture.state = .io_failed;
    };
    validatePrivateDirectory(lock.directory.dir) catch {
        capture.state = .io_failed;
    };
    if (capture.state == .complete and (!capture.stdout_eof or !capture.stderr_eof or
        execution.failures.primary != null or !execution.cleanup_complete)) capture.state = .partial;
    return .{
        .execution = execution,
        .capture = capture.state,
        .stdout_bytes = capture.stdout_count,
        .stderr_bytes = capture.stderr_count,
    };
}

fn validateOptions(options: Options, maximum: usize) !void {
    if (options.argv.len == 0 or options.argv.len > 128 or !std.fs.path.isAbsolute(options.argv[0]) or
        options.stdout_limit > maximum or options.stderr_limit > maximum or
        options.cleanup_ms < 100 or options.cleanup_ms > 30 * 60 * 1000)
        return error.InvalidOptions;
    if (options.inherited_descriptor) |descriptor|
        if (descriptor <= 2) return error.InvalidOptions;
    var argument_bytes: usize = 0;
    for (options.argv) |arg| {
        if (arg.len > 64 * 1024 or std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidOptions;
        argument_bytes += arg.len;
    }
    if (argument_bytes > 256 * 1024 or options.environment.count() > 256) return error.InvalidOptions;
    var environment_bytes: usize = 0;
    var entries = options.environment.iterator();
    while (entries.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        if (key.len == 0 or key.len > 256 or value.len > 64 * 1024 or
            std.mem.indexOfAny(u8, key, "=\x00") != null or std.mem.indexOfScalar(u8, value, 0) != null)
            return error.InvalidOptions;
        environment_bytes += key.len + value.len;
    }
    if (environment_bytes > 256 * 1024) return error.InvalidOptions;
}

fn commandOptions(request: CommandRequest) Options {
    return .{
        .argv = request.argv,
        .environment = request.environment,
        .cwd = request.cwd,
        .deadline = request.primary_deadline,
        .cleanup_ms = 100,
        .stdout_limit = request.limits.stdout_bytes,
        .stderr_limit = request.limits.stderr_bytes,
        .cancel = request.cancel,
    };
}

fn validateCommandLimits(limits: CommandLimits) !void {
    if (limits.stdout_bytes == 0 or limits.stderr_bytes == 0 or
        limits.stdout_bytes > 4 * 1024 * 1024 or limits.stderr_bytes > 4 * 1024 * 1024 or
        limits.descendants == 0 or limits.descendants > 256 or
        limits.primary_events < 16 or limits.primary_events > 10_000_000 or
        limits.cleanup_events < 32 or limits.cleanup_events > 10_000_000 or
        limits.proc_entries_per_scan < 16 or limits.proc_entries_per_scan > 1_000_000 or
        limits.reap_events < limits.descendants + 3 or limits.reap_events > 1024 or
        limits.term_grace_ms == 0 or limits.term_grace_ms > 60_000)
        return error.InvalidOptions;
}

fn enter() !void {
    if (busy.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.SupervisorBusy;
    errdefer busy.store(false, .release);
    if (poisoned.load(.acquire)) return error.UnresolvedCleanup;
    var subreaper: c_int = 0;
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.GET_CHILD_SUBREAPER), @intFromPtr(&subreaper), 0, 0, 0)) != .SUCCESS or subreaper != 1)
        return error.SubreaperRequired;
}

const CleanupPolicy = struct {
    term_grace_ms: ?u32 = null,
    deadline: ?Deadline = null,
    all_children: bool = false,
    nested_supervisor: bool = false,
    reap_reserve_ms: u32 = 0,
    fault: ?PrivateTestFault = null,
};

const Completion = enum { unfinished, closed_command };

fn supervise(
    allocator: std.mem.Allocator,
    options: Options,
    capture: *Capture,
    policy: CleanupPolicy,
    executable: ?linux.fd_t,
) !Execution {
    var result: Execution = .{};
    if (try options.deadline.expired()) {
        result.failures.primary = .{ .stage = .process_spawn, .category = .timeout };
        return result;
    }
    if (cancelled(options)) {
        result.failures.primary = .{ .stage = .process_spawn, .category = .cancelled };
        return result;
    }
    var child = spawnOwned(allocator, options, policy.fault, executable, false, null) catch {
        result.failures.primary = .{ .stage = .process_spawn, .category = .spawn_failed };
        return result;
    };
    const pid = child.pid;
    defer _ = linux.close(child.stdout);
    defer _ = linux.close(child.stderr);
    defer _ = linux.close(child.control);
    const leader_exited = if (monitor(&child, options, capture)) true else |err| failure: {
        result.failures.primary = .{
            .stage = if (err == error.SpawnFailed) .process_spawn else .process_run,
            .category = switch (err) {
                error.DeadlineExceeded => .timeout,
                error.OutputLimit => .output_limit,
                error.Cancelled => .cancelled,
                error.SpawnFailed => .spawn_failed,
                else => .local_io,
            },
        };
        break :failure false;
    };
    const completion: Completion = if (capture.private != null and !policy.nested_supervisor and
        leader_exited and capture.stdout_eof and capture.stderr_eof) .closed_command else .unfinished;
    // This is an independent budget, also used after normal leader exit so a
    // successful parent cannot strand background descendants holding pipes.
    cleanup(pid, options.cleanup_ms, &result, policy, completion) catch {
        result.cleanup_complete = false;
        result.unreaped_group = pid;
        result.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
        poisoned.store(true, .release);
    };
    if (capture.private != null and result.cleanup_complete) {
        // No writers survive successful cleanup. Drain already-buffered bytes
        // even after timeout/cancellation, without restarting their execution.
        capture.drainFinal(child.stdout, false) catch {};
        capture.drainFinal(child.stderr, true) catch {};
    }
    if (result.failures.primary == null) {
        if (result.termination) |termination| {
            switch (termination) {
                .exited => |code| if (code != 0) {
                    result.failures.primary = .{ .stage = .process_run, .category = .child_failed };
                },
                else => result.failures.primary = .{ .stage = .process_run, .category = .child_failed },
            }
        } else {
            result.failures.primary = .{ .stage = .process_run, .category = .child_failed };
        }
    }
    return result;
}

const Capture = struct {
    output: []u8,
    stderr_output: []u8 = &.{},
    stderr_limit: usize,
    stdout_count: usize = 0,
    stderr_count: usize = 0,
    stdout_eof: bool = false,
    stderr_eof: bool = false,
    private: ?struct { stdout: std.Io.File, stderr: std.Io.File, limit: usize } = null,
    state: CaptureState = .complete,
    fault: ?PrivateTestFault = null,

    fn drain(self: *Capture, fd: linux.fd_t, stderr: bool, options: Options) !void {
        try self.drainImpl(fd, stderr, options);
    }

    fn drainFinal(self: *Capture, fd: linux.fd_t, stderr: bool) !void {
        try self.drainImpl(fd, stderr, null);
    }

    fn drainImpl(self: *Capture, fd: linux.fd_t, stderr: bool, options: ?Options) !void {
        var buffer: [4096]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        const count = if (stderr) &self.stderr_count else &self.stdout_count;
        const limit = if (stderr) self.stderr_limit else if (self.private) |sink| sink.limit else self.output.len;
        while (true) {
            if (options) |active| {
                if (cancelled(active)) return error.Cancelled;
                if (try active.deadline.expired()) return error.DeadlineExceeded;
            }
            const n = linux.read(fd, &buffer, @min(buffer.len, limit - count.* + 1));
            switch (linux.errno(n)) {
                .SUCCESS => {
                    if (n == 0) {
                        if (stderr) self.stderr_eof = true else self.stdout_eof = true;
                        return;
                    }
                    const fitting = @min(n, limit - count.*);
                    if (self.private) |sink| {
                        const out = if (stderr) sink.stderr.handle else sink.stdout.handle;
                        var written: usize = 0;
                        while (written < fitting) {
                            if (self.fault == .capture_write and count.* >= 4) {
                                self.state = .io_failed;
                                return error.CaptureFailed;
                            }
                            const amount = linux.write(out, buffer[written..].ptr, if (self.fault == .capture_write) @min(4, fitting - written) else fitting - written);
                            switch (linux.errno(amount)) {
                                .SUCCESS => {
                                    if (amount == 0) {
                                        self.state = .io_failed;
                                        return error.CaptureFailed;
                                    }
                                    written += amount;
                                    count.* += amount;
                                },
                                .INTR => continue,
                                else => {
                                    self.state = .io_failed;
                                    return error.CaptureFailed;
                                },
                            }
                        }
                    } else {
                        if (fitting != 0) {
                            if (stderr) {
                                if (self.stderr_output.len != 0)
                                    @memcpy(self.stderr_output[count.*..][0..fitting], buffer[0..fitting]);
                            } else {
                                @memcpy(self.output[count.*..][0..fitting], buffer[0..fitting]);
                            }
                            count.* += fitting;
                        }
                        if (n > fitting) {
                            self.state = .overflow;
                            return error.OutputLimit;
                        }
                    }
                    if (n > fitting) {
                        self.state = .overflow;
                        return error.OutputLimit;
                    }
                },
                .AGAIN => return,
                .INTR => continue,
                else => {
                    self.state = .io_failed;
                    return error.CaptureFailed;
                },
            }
        }
    }
};

fn monitor(child: *Spawned, options: Options, capture: *Capture) !void {
    const stdout = child.stdout;
    const stderr = child.stderr;
    try nonblocking(stdout);
    try nonblocking(stderr);
    try nonblocking(child.control);
    var exec_confirmed = false;
    while (true) {
        if (cancelled(options)) return error.Cancelled;
        if (try options.deadline.expired()) return error.DeadlineExceeded;
        if (!capture.stdout_eof) try capture.drain(stdout, false, options);
        if (!capture.stderr_eof) try capture.drain(stderr, true, options);
        if (!exec_confirmed) exec_confirmed = try execStatus(child.control);
        if (try exited(child.pid)) {
            if (!exec_confirmed and !try execStatus(child.control)) return error.SpawnFailed;
            // Drain once more after observing exit to include the final writes.
            if (!capture.stdout_eof) try capture.drain(stdout, false, options);
            if (!capture.stderr_eof) try capture.drain(stderr, true, options);
            return;
        }
        var pollfds = [_]linux.pollfd{
            .{ .fd = if (capture.stdout_eof) -1 else stdout, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (capture.stderr_eof) -1 else stderr, .events = linux.POLL.IN, .revents = 0 },
        };
        switch (linux.errno(linux.poll(&pollfds, pollfds.len, try options.deadline.waitMilliseconds(10)))) {
            .SUCCESS, .INTR => {},
            else => return error.PollFailed,
        }
    }
}

fn monitorCommand(
    child: *Spawned,
    options: Options,
    capture: *Capture,
    event_limit: u32,
    events: *u32,
    clock: ?*CommandClockTest,
    post_release_test: ?*CommandPostReleaseTestState,
    terminal_observed_ns: *?u64,
) !void {
    try nonblocking(child.stdout);
    try nonblocking(child.stderr);
    try nonblocking(child.control);
    var exec_confirmed = false;
    while (true) {
        try takeCommandEvent(event_limit, events);
        if (cancelled(options)) return error.Cancelled;
        const deadline_observed_ns = try commandMonitorTimestamp(clock);
        if (deadline_observed_ns >= options.deadline.expires_ns) {
            terminal_observed_ns.* = deadline_observed_ns;
            return error.DeadlineExceeded;
        }
        if (!capture.stdout_eof) capture.drain(child.stdout, false, options) catch |err| switch (err) {
            error.OutputLimit => return error.StdoutLimit,
            error.CaptureFailed => return error.StdoutIo,
            error.Cancelled => return error.Cancelled,
            error.DeadlineExceeded => return error.DeadlineExceeded,
            else => return error.StdoutIo,
        };
        if (!capture.stderr_eof) capture.drain(child.stderr, true, options) catch |err| switch (err) {
            error.OutputLimit => return error.StderrLimit,
            error.CaptureFailed => return error.StderrIo,
            error.Cancelled => return error.Cancelled,
            error.DeadlineExceeded => return error.DeadlineExceeded,
            else => return error.StderrIo,
        };
        try commandPostReleaseMonitorFault(
            post_release_test,
            capture,
            event_limit,
            events,
        );
        if (!exec_confirmed) exec_confirmed = try execStatus(child.control);
        if (try exited(child.pid)) {
            const observed_ns = try commandLeaderExitObserved(clock);
            terminal_observed_ns.* = observed_ns;
            // Deadline.expired uses the same inclusive boundary: a terminal
            // observation exactly at the absolute deadline is a timeout.
            if (observed_ns >= options.deadline.expires_ns)
                return error.DeadlineExceeded;
            if (!exec_confirmed and !try execStatus(child.control)) return error.SpawnFailed;
            if (!capture.stdout_eof) capture.drainFinal(child.stdout, false) catch |err| switch (err) {
                error.OutputLimit => return error.StdoutLimit,
                error.CaptureFailed => return error.StdoutIo,
                else => return error.StdoutIo,
            };
            if (!capture.stderr_eof) capture.drainFinal(child.stderr, true) catch |err| switch (err) {
                error.OutputLimit => return error.StderrLimit,
                error.CaptureFailed => return error.StderrIo,
                else => return error.StderrIo,
            };
            return;
        }
        var pollfds = [_]linux.pollfd{
            .{ .fd = if (capture.stdout_eof) -1 else child.stdout, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (capture.stderr_eof) -1 else child.stderr, .events = linux.POLL.IN, .revents = 0 },
        };
        switch (linux.errno(linux.poll(&pollfds, pollfds.len, try options.deadline.waitMilliseconds(10)))) {
            .SUCCESS, .INTR => {},
            else => return error.PollFailed,
        }
    }
}

fn commandMonitorTimestamp(clock: ?*CommandClockTest) !u64 {
    return if (clock) |active| timestamp: {
        active.monitor_checks += 1;
        break :timestamp active.monitor_check_ns;
    } else try now();
}

fn commandLeaderExitObserved(clock: ?*CommandClockTest) !u64 {
    if (clock) |active| {
        active.leader_exit_observations += 1;
        return active.leader_exit_ns;
    }
    return now();
}

fn commandLeaderTrackFailureObserved(fault: ?*CommandLeaderTrackTest) !u64 {
    if (fault) |active| {
        active.timestamp_observations += 1;
        return active.observed_ns;
    }
    return now();
}

fn commandPostReleaseMonitorFault(
    test_state: ?*CommandPostReleaseTestState,
    capture: *Capture,
    event_limit: u32,
    events: *u32,
) !void {
    const active = test_state orelse return;
    if (capture.stdout_count == 0) return;
    switch (active.fault) {
        .monitor_clock => if (active.inject(.monitor_clock))
            return error.ClockUnavailable,
        .monitor_cancelled => if (active.inject(.monitor_cancelled))
            return error.Cancelled,
        .monitor_event => if (active.inject(.monitor_event)) {
            events.* = event_limit;
            return error.EventLimit;
        },
        .monitor_output => if (active.inject(.monitor_output)) {
            capture.stdout_count = capture.output.len;
            capture.state = .overflow;
            return error.StdoutLimit;
        },
        .monitor_io => if (active.inject(.monitor_io)) {
            capture.state = .io_failed;
            return error.StdoutIo;
        },
        .monitor_poll => if (active.inject(.monitor_poll))
            return error.PollFailed,
        .fallback_clock, .result_build, .unwind, .unwind_cleanup_proof => {
            if (active.boundaries == 0) {
                active.boundaries = 1;
                return error.PostReleaseBoundary;
            }
        },
        .cleanup_proof => {},
    }
}

fn commandPostReleaseFallbackTimestamp(
    test_state: ?*CommandPostReleaseTestState,
) !u64 {
    if (test_state) |active| {
        if (active.boundaries != 0 and active.inject(.fallback_clock))
            return error.ClockUnavailable;
    }
    return now();
}

fn commandPostReleaseResultBuild(
    test_state: ?*CommandPostReleaseTestState,
) !void {
    if (test_state) |active| {
        if (active.boundaries != 0 and active.inject(.result_build))
            return error.ResultBuildFailed;
    }
}

fn commandPostReleaseBoundaryIs(
    test_state: ?*CommandPostReleaseTestState,
    fault: CommandPostReleaseTestFault,
) bool {
    const active = test_state orelse return false;
    return active.fault == fault and active.boundaries != 0;
}

fn commandPostReleaseCleanupProof(
    test_state: ?*CommandPostReleaseTestState,
) bool {
    const active = test_state orelse return false;
    return active.inject(.cleanup_proof) or
        active.inject(.unwind_cleanup_proof);
}

fn commandGateInject(test_state: ?*CommandGateTestState, fault: CommandGateTestFault) bool {
    const active = test_state orelse return false;
    return active.inject(fault);
}

fn commandGateFaultIs(test_state: ?*CommandGateTestState, fault: CommandGateTestFault) bool {
    const active = test_state orelse return false;
    return active.fault == fault and active.fault_injections == 0;
}

fn primaryPreReleaseObservation(test_state: ?*CommandGateTestState) !u64 {
    if (commandGateInject(test_state, .clock)) return error.ClockUnavailable;
    return now();
}

fn classifyPreReleasePrimary(
    fallback: CommandPrimary,
    options: Options,
    observed_ns: u64,
) CommandPrimary {
    if (observed_ns >= options.deadline.expires_ns) return .timeout;
    if (cancelled(options)) return .cancelled;
    return fallback;
}

fn takeCommandEvent(limit: u32, events: *u32) !void {
    if (events.* >= limit) return error.EventLimit;
    events.* += 1;
}

fn cancelled(options: Options) bool {
    return if (options.cancel) |flag| flag.load(.acquire) else false;
}

fn nonblocking(fd: linux.fd_t) !void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return error.PipeFlags;
    const nonblock: linux.O = .{ .NONBLOCK = true };
    if (linux.errno(linux.fcntl(fd, linux.F.SETFL, flags | @as(u32, @bitCast(nonblock)))) != .SUCCESS)
        return error.PipeFlags;
}

fn exited(pid: linux.pid_t) !bool {
    var info = std.mem.zeroes(linux.siginfo_t);
    switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null))) {
        .SUCCESS => return info.fields.common.first.piduid.pid != 0,
        .INTR => return false,
        else => return error.WaitFailed,
    }
}

fn cleanup(pid: linux.pid_t, milliseconds: u32, result: *Execution, policy: CleanupPolicy, completion: Completion) !void {
    var final_signal_sent = false;
    errdefer if (!final_signal_sent) signalGroup(pid, .KILL) catch {};
    var deadline = try Deadline.afterMilliseconds(milliseconds);
    if (policy.deadline) |outer| deadline.expires_ns = @min(deadline.expires_ns, outer.expires_ns);
    if (completion == .unfinished) {
        if (policy.nested_supervisor) {
            try signalLeader(pid, .TERM);
        } else try signalGroup(pid, .TERM);
        var grace = try Deadline.afterMilliseconds(policy.term_grace_ms orelse @min(50, milliseconds / 4));
        grace.expires_ns = @min(grace.expires_ns, deadline.expires_ns -| (@as(u64, policy.reap_reserve_ms) * std.time.ns_per_ms));
        while (!try grace.expired()) {
            if (policy.nested_supervisor and try exited(pid)) break;
            try pause(try grace.waitMilliseconds(10));
        }
    }
    // Even a closed command can leave live descendants with closed output.
    // Its unreaped leader pins PID/PGID ownership through the final signal.
    // Only the subsequent reaping proof permits a successful cleanup.
    try signalGroup(pid, .KILL);
    final_signal_sent = true;
    while (true) {
        var status: u32 = 0;
        const child = linux.waitpid(if (result.termination == null) pid else if (policy.all_children) -1 else -pid, &status, linux.W.NOHANG);
        switch (linux.errno(child)) {
            .SUCCESS => {
                if (child != 0) {
                    if (child == @as(usize, @intCast(pid))) {
                        result.termination = if (linux.W.IFEXITED(status))
                            .{ .exited = linux.W.EXITSTATUS(status) }
                        else if (linux.W.IFSIGNALED(status))
                            .{ .signal = linux.W.TERMSIG(status) }
                        else
                            .{ .unknown = status };
                    }
                    if (try deadline.expired()) return error.CleanupDeadline;
                    continue;
                }
            },
            .CHILD => {
                if (result.termination == null) return error.ReapFailed;
                return;
            },
            .INTR => {},
            else => return error.ReapFailed,
        }
        if (try deadline.expired()) return error.CleanupDeadline;
        try pause(try deadline.waitMilliseconds(5));
    }
}

const ProcStat = struct {
    pid: linux.pid_t,
    parent: linux.pid_t,
    start_ticks: u64,
};

const OwnedProcess = struct {
    pid: linux.pid_t,
    start_ticks: u64,
    pidfd: linux.fd_t,
    term_sent: bool = false,
    kill_sent: bool = false,
    reaped: bool = false,
};

const PidfdOwnership = struct {
    descriptor: linux.fd_t,
    start_ticks: ?u64 = null,
    test_state: ?*CommandPidfdTestState = null,
    candidate: ?u32 = null,
    owned: bool = true,

    fn init(descriptor: linux.fd_t) PidfdOwnership {
        return .{ .descriptor = descriptor };
    }

    fn initCandidate(descriptor: linux.fd_t, test_state: ?*CommandPidfdTestState) PidfdOwnership {
        return .{
            .descriptor = descriptor,
            .test_state = test_state,
            .candidate = if (test_state) |state| state.openCandidate() else null,
        };
    }

    fn deinit(self: *PidfdOwnership) void {
        if (!self.owned) return;
        self.owned = false;
        _ = linux.close(self.descriptor);
        if (self.test_state) |state| state.closeCandidate(self.candidate.?);
    }

    fn transfer(self: *PidfdOwnership) void {
        std.debug.assert(self.owned);
        self.owned = false;
        if (self.test_state) |state| state.transferCandidate(self.candidate.?);
    }

    fn inject(self: *const PidfdOwnership, fault: CommandPidfdTestFault) bool {
        const state = self.test_state orelse return false;
        return state.inject(fault, self.candidate.?);
    }
};

const OwnedTracker = struct {
    items: []OwnedProcess,
    len: usize = 0,
    descendant_limit: u16,
    report: CommandDescendants = .{},
    pidfd_test: ?*CommandPidfdTestState,
    signal_test: ?*CommandSignalTestState,

    fn init(
        allocator: std.mem.Allocator,
        descendant_limit: u16,
        pidfd_test: ?*CommandPidfdTestState,
        signal_test: ?*CommandSignalTestState,
    ) !OwnedTracker {
        return .{
            .items = try allocator.alloc(OwnedProcess, @as(usize, descendant_limit) + 2),
            .descendant_limit = descendant_limit,
            .pidfd_test = pidfd_test,
            .signal_test = signal_test,
        };
    }

    fn deinit(self: *OwnedTracker, allocator: std.mem.Allocator) void {
        for (self.items[0..self.len]) |item| _ = linux.close(item.pidfd);
        allocator.free(self.items);
        self.* = undefined;
    }

    fn addLeader(
        self: *OwnedTracker,
        proc: linux.fd_t,
        pid: linux.pid_t,
        ownership: *PidfdOwnership,
        start_ticks: *?u64,
        fault: ?*CommandLeaderTrackTest,
        gate_test: ?*CommandGateTestState,
    ) !void {
        if (commandGateInject(gate_test, .procfs)) return error.ProcUnavailable;
        const observed = try readProcStat(proc, pid);
        start_ticks.* = observed.start_ticks;
        ownership.start_ticks = observed.start_ticks;
        if (observed.pid != pid or observed.parent != linux.getpid() or observed.start_ticks == 0)
            return error.IdentityChanged;
        if (commandGateInject(gate_test, .identity)) return error.IdentityChanged;
        const identity = (try verifiedOwnedIdentity(
            proc,
            observed.pid,
            observed.start_ticks,
            ownership.descriptor,
        )) orelse
            return error.IdentityChanged;
        if (identity.parent != linux.getpid()) return error.IdentityChanged;
        if (fault) |active| {
            active.fault_injections += 1;
            return error.IdentityChanged;
        }
        if (commandGateInject(gate_test, .tracker)) return error.TrackerUnavailable;
        self.items[0] = .{
            .pid = pid,
            .start_ticks = identity.start_ticks,
            .pidfd = ownership.descriptor,
        };
        self.len = 1;
        ownership.transfer();
    }

    fn findPid(self: *const OwnedTracker, pid: linux.pid_t) ?usize {
        for (self.items[0..self.len], 0..) |item, index| if (item.pid == pid) return index;
        return null;
    }

    fn ownsLiveParent(
        self: *const OwnedTracker,
        proc: linux.fd_t,
        parent: linux.pid_t,
        candidate: ?*const PidfdOwnership,
    ) !bool {
        if (candidate) |ownership| {
            if (ownership.inject(.second_parent_verification)) return error.IdentityChanged;
        }
        if (parent == linux.getpid()) return true;
        const index = self.findPid(parent) orelse return false;
        return (try verifiedLiveIdentity(
            proc,
            self.items[index].pid,
            self.items[index].start_ticks,
            self.items[index].pidfd,
        )) != null;
    }

    fn addDescendant(self: *OwnedTracker, identity: ProcStat, descriptor: linux.fd_t) bool {
        if (self.len == self.items.len) {
            self.report.untracked = true;
            return false;
        }
        self.items[self.len] = .{
            .pid = identity.pid,
            .start_ticks = identity.start_ticks,
            .pidfd = descriptor,
        };
        self.len += 1;
        self.report.observed += 1;
        self.report.identity_validated += 1;
        if (identity.parent == linux.getpid()) self.report.adopted += 1;
        if (self.report.observed > self.descendant_limit) self.report.limit_exceeded = true;
        return true;
    }
};

const CleanupSignal = enum { term, kill };

fn commandCleanupFromError(err: anyerror) CommandCleanup {
    return switch (err) {
        error.CleanupDeadline => .deadline,
        error.EventLimit, error.ProcEntryLimit, error.ReapLimit => .event_limit,
        error.DescendantUntracked => .descendant_untracked,
        error.IdentityChanged => .identity_changed,
        error.SignalFailed => .signal_failed,
        error.ReapFailed => .reap_failed,
        error.ProcUnavailable => .proc_unavailable,
        error.ClockUnavailable, error.PollFailed => .local_io,
        else => .local_io,
    };
}

fn cleanupCommand(
    io: std.Io,
    proc: linux.fd_t,
    request: CommandRequest,
    tracker: *OwnedTracker,
    result: *CommandResult,
    post_release_test: ?*CommandPostReleaseTestState,
) !void {
    const started = try now();
    const grace_ns = try std.math.mul(u64, request.limits.term_grace_ms, std.time.ns_per_ms);
    const grace: Deadline = .{
        .expires_ns = @min(request.cleanup_deadline.expires_ns, try std.math.add(u64, started, grace_ns)),
    };

    _ = try scanOwned(io, proc, request, tracker, result, .term);
    try signalTracked(request, tracker, result, .term);
    while (!try allTrackedExited(request, tracker, result)) {
        if (try grace.expired()) break;
        _ = try scanOwned(io, proc, request, tracker, result, .term);
        if (tracker.report.untracked) break;
        try signalTracked(request, tracker, result, .term);
        try pause(try grace.waitMilliseconds(5));
    }

    _ = try scanOwned(io, proc, request, tracker, result, .kill);
    try signalTracked(request, tracker, result, .kill);
    if (tracker.report.untracked) return error.DescendantUntracked;
    while (true) {
        const added = try scanOwned(io, proc, request, tracker, result, .kill);
        try signalTracked(request, tracker, result, .kill);
        if (tracker.report.untracked) return error.DescendantUntracked;
        if (try allTrackedExited(request, tracker, result)) {
            const final_added = try scanOwned(io, proc, request, tracker, result, .kill);
            try signalTracked(request, tracker, result, .kill);
            if (!added and !final_added and try allTrackedExited(request, tracker, result)) break;
        }
        if (try request.cleanup_deadline.expired()) return error.CleanupDeadline;
        try pause(try request.cleanup_deadline.waitMilliseconds(5));
    }
    try reapCommand(request, tracker, result);
    if (commandPostReleaseCleanupProof(post_release_test))
        return error.ReapFailed;
    result.cleanup = .complete;
    result.cleanup_complete = true;
}

fn scanOwned(
    io: std.Io,
    proc: linux.fd_t,
    request: CommandRequest,
    tracker: *OwnedTracker,
    result: *CommandResult,
    phase: CleanupSignal,
) !bool {
    var discovered_any = false;
    while (true) {
        const opened = linux.openat(proc, ".", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, 0);
        if (linux.errno(opened) != .SUCCESS) return error.ProcUnavailable;
        const directory: std.Io.Dir = .{ .handle = @intCast(opened) };
        defer directory.close(io);
        var iterator = directory.iterate();
        var entries: u32 = 0;
        var discovered_pass = false;
        while (iterator.next(io) catch return error.ProcUnavailable) |entry| {
            if (entries >= request.limits.proc_entries_per_scan) return error.ProcEntryLimit;
            entries += 1;
            try takeCleanupEvent(request, result);
            const pid = std.fmt.parseInt(linux.pid_t, entry.name, 10) catch continue;
            if (pid <= 1 or pid == linux.getpid()) continue;
            if (tracker.findPid(pid)) |index| {
                _ = try verifiedOwnedIdentity(
                    proc,
                    tracker.items[index].pid,
                    tracker.items[index].start_ticks,
                    tracker.items[index].pidfd,
                );
                continue;
            }
            const observed = readProcStat(proc, pid) catch |err| switch (err) {
                error.ProcessGone => continue,
                else => return error.ProcUnavailable,
            };
            if (!try tracker.ownsLiveParent(proc, observed.parent, null)) continue;
            const descriptor = commandPidfd(pid) catch |err| switch (err) {
                error.ProcessGone => continue,
                else => return error.PidfdUnavailable,
            };
            var ownership = PidfdOwnership.initCandidate(descriptor, tracker.pidfd_test);
            defer ownership.deinit();
            const identity = (try verifiedOwnedIdentity(
                proc,
                observed.pid,
                observed.start_ticks,
                descriptor,
            )) orelse continue;
            if (!try tracker.ownsLiveParent(proc, identity.parent, &ownership)) continue;
            if (!tracker.addDescendant(identity, descriptor)) {
                try signalTemporary(descriptor, phase, &ownership);
            } else {
                ownership.transfer();
                try signalOwned(
                    request,
                    &tracker.items[tracker.len - 1],
                    result,
                    phase,
                    tracker.signal_test,
                );
            }
            discovered_pass = true;
            discovered_any = true;
        }
        if (!discovered_pass or tracker.report.untracked) return discovered_any;
    }
}

fn signalTracked(
    request: CommandRequest,
    tracker: *OwnedTracker,
    result: *CommandResult,
    phase: CleanupSignal,
) !void {
    for (tracker.items[0..tracker.len]) |*item|
        try signalOwned(request, item, result, phase, tracker.signal_test);
}

fn signalOwned(
    request: CommandRequest,
    item: *OwnedProcess,
    result: *CommandResult,
    phase: CleanupSignal,
    signal_test: ?*CommandSignalTestState,
) !void {
    const already = if (phase == .term) item.term_sent else item.kill_sent;
    if (already) return;
    try takeCleanupEvent(request, result);
    if (try pidfdExited(item.pidfd)) {
        if (phase == .term) item.term_sent = true else item.kill_sent = true;
        return;
    }
    if (signal_test) |state| state.attempts += 1;
    const signal: linux.SIG = if (phase == .term) .TERM else .KILL;
    switch (linux.errno(linux.pidfd_send_signal(item.pidfd, signal, null, 0))) {
        .SUCCESS, .SRCH => {},
        else => return error.SignalFailed,
    }
    if (phase == .term) item.term_sent = true else item.kill_sent = true;
}

fn signalTemporary(
    descriptor: linux.fd_t,
    phase: CleanupSignal,
    ownership: *const PidfdOwnership,
) !void {
    if (ownership.inject(.temporary_signal)) return error.SignalFailed;
    if (try pidfdExited(descriptor)) return;
    const signal: linux.SIG = if (phase == .term) .TERM else .KILL;
    switch (linux.errno(linux.pidfd_send_signal(descriptor, signal, null, 0))) {
        .SUCCESS, .SRCH => {},
        else => return error.SignalFailed,
    }
}

fn allTrackedExited(
    request: CommandRequest,
    tracker: *const OwnedTracker,
    result: *CommandResult,
) !bool {
    for (tracker.items[0..tracker.len]) |item| {
        try takeCleanupEvent(request, result);
        if (!try pidfdExited(item.pidfd)) return false;
    }
    return true;
}

fn pidfdExited(descriptor: linux.fd_t) !bool {
    var pollfds = [_]linux.pollfd{.{ .fd = descriptor, .events = linux.POLL.IN, .revents = 0 }};
    switch (linux.errno(linux.poll(&pollfds, pollfds.len, 0))) {
        .SUCCESS => {},
        .INTR => return false,
        else => return error.PollFailed,
    }
    if (pollfds[0].revents & linux.POLL.NVAL != 0) return error.PollFailed;
    return pollfds[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0;
}

const IdentityAction = enum { live, gone, poison };

fn identityAction(
    expected_pid: linux.pid_t,
    expected_start_ticks: u64,
    exited_before: bool,
    current: ?ProcStat,
    exited_after: bool,
) IdentityAction {
    if (exited_before or exited_after) return .gone;
    const observed = current orelse return .poison;
    if (observed.pid != expected_pid or expected_start_ticks == 0 or
        observed.start_ticks != expected_start_ticks) return .poison;
    return .live;
}

fn verifiedLiveIdentity(
    proc: linux.fd_t,
    expected_pid: linux.pid_t,
    expected_start_ticks: u64,
    descriptor: linux.fd_t,
) !?ProcStat {
    const exited_before = try pidfdExited(descriptor);
    if (exited_before) return null;
    const current: ?ProcStat = readProcStat(proc, expected_pid) catch |err| switch (err) {
        error.ProcessGone => null,
        else => return error.ProcUnavailable,
    };
    const exited_after = try pidfdExited(descriptor);
    return switch (identityAction(expected_pid, expected_start_ticks, exited_before, current, exited_after)) {
        .live => current.?,
        .gone => null,
        .poison => error.IdentityChanged,
    };
}

const OwnedIdentityAction = enum { retain, gone, poison };

fn ownedIdentityAction(
    expected_pid: linux.pid_t,
    expected_start_ticks: u64,
    exited_before: bool,
    current: ?ProcStat,
    exited_after: bool,
) OwnedIdentityAction {
    if (current) |observed| {
        if (observed.pid != expected_pid or expected_start_ticks == 0 or
            observed.start_ticks != expected_start_ticks) return .poison;
        return .retain;
    }
    if (exited_before or exited_after) return .gone;
    return .poison;
}

fn verifiedOwnedIdentity(
    proc: linux.fd_t,
    expected_pid: linux.pid_t,
    expected_start_ticks: u64,
    descriptor: linux.fd_t,
) !?ProcStat {
    const exited_before = try pidfdExited(descriptor);
    const current: ?ProcStat = readProcStat(proc, expected_pid) catch |err| switch (err) {
        error.ProcessGone => null,
        else => return error.ProcUnavailable,
    };
    const exited_after = try pidfdExited(descriptor);
    return switch (ownedIdentityAction(
        expected_pid,
        expected_start_ticks,
        exited_before,
        current,
        exited_after,
    )) {
        .retain => current.?,
        .gone => null,
        .poison => error.IdentityChanged,
    };
}

pub const CommandIdentityTest = struct {
    pub const Action = enum { open_candidate, rescan_without_open, poison };
    pub const OwnedAction = enum { retain, gone, poison };

    pub fn parentAction(
        expected_pid: linux.pid_t,
        expected_start_ticks: u64,
        exited_before: bool,
        observed_pid: ?linux.pid_t,
        observed_start_ticks: u64,
        exited_after: bool,
    ) Action {
        if (!builtin.is_test) @compileError("command identity evidence is test-only");
        const current: ?ProcStat = if (observed_pid) |pid| .{
            .pid = pid,
            .parent = 0,
            .start_ticks = observed_start_ticks,
        } else null;
        return switch (identityAction(
            expected_pid,
            expected_start_ticks,
            exited_before,
            current,
            exited_after,
        )) {
            .live => .open_candidate,
            .gone => .rescan_without_open,
            .poison => .poison,
        };
    }

    pub fn ownedAction(
        expected_pid: linux.pid_t,
        expected_start_ticks: u64,
        exited_before: bool,
        observed_pid: ?linux.pid_t,
        observed_start_ticks: u64,
        exited_after: bool,
    ) OwnedAction {
        if (!builtin.is_test) @compileError("command identity evidence is test-only");
        const current: ?ProcStat = if (observed_pid) |pid| .{
            .pid = pid,
            .parent = 0,
            .start_ticks = observed_start_ticks,
        } else null;
        return switch (ownedIdentityAction(
            expected_pid,
            expected_start_ticks,
            exited_before,
            current,
            exited_after,
        )) {
            .retain => .retain,
            .gone => .gone,
            .poison => .poison,
        };
    }

    pub fn startTicks(pid: linux.pid_t) !u64 {
        if (!builtin.is_test) @compileError("command identity evidence is test-only");
        const proc = try openCommandProc();
        defer _ = linux.close(proc);
        return (try readProcStat(proc, pid)).start_ticks;
    }

    pub fn identityLive(pid: linux.pid_t, start_ticks: u64, descriptor: linux.fd_t) !bool {
        if (!builtin.is_test) @compileError("command identity evidence is test-only");
        const proc = try openCommandProc();
        defer _ = linux.close(proc);
        return (try verifiedLiveIdentity(proc, pid, start_ticks, descriptor)) != null;
    }

    pub fn identityOwned(pid: linux.pid_t, start_ticks: u64, descriptor: linux.fd_t) !bool {
        if (!builtin.is_test) @compileError("command identity evidence is test-only");
        const proc = try openCommandProc();
        defer _ = linux.close(proc);
        return (try verifiedOwnedIdentity(proc, pid, start_ticks, descriptor)) != null;
    }
};

fn reapCommand(request: CommandRequest, tracker: *OwnedTracker, result: *CommandResult) !void {
    var remaining = tracker.len;
    while (true) {
        var status: u32 = 0;
        const child = linux.waitpid(-1, &status, linux.W.NOHANG);
        switch (linux.errno(child)) {
            .SUCCESS => {
                if (child == 0) {
                    if (try request.cleanup_deadline.expired()) return error.CleanupDeadline;
                    try pause(try request.cleanup_deadline.waitMilliseconds(2));
                    continue;
                }
                if (result.reap_events >= request.limits.reap_events) return error.ReapLimit;
                result.reap_events += 1;
                const pid: linux.pid_t = @intCast(child);
                const index = tracker.findPid(pid) orelse return error.ReapFailed;
                if (tracker.items[index].reaped) return error.ReapFailed;
                tracker.items[index].reaped = true;
                remaining -= 1;
                if (index == 0) result.termination = terminationFromStatus(status);
                continue;
            },
            .CHILD => {
                if (result.reap_events >= request.limits.reap_events) return error.ReapLimit;
                result.reap_events += 1;
                if (remaining != 0 or result.termination == null) return error.ReapFailed;
                return;
            },
            .INTR => {
                if (try request.cleanup_deadline.expired()) return error.CleanupDeadline;
                continue;
            },
            else => return error.ReapFailed,
        }
    }
}

fn terminationFromStatus(status: u32) std.process.Child.Term {
    if (linux.W.IFEXITED(status)) return .{ .exited = linux.W.EXITSTATUS(status) };
    if (linux.W.IFSIGNALED(status)) return .{ .signal = linux.W.TERMSIG(status) };
    return .{ .unknown = status };
}

fn primaryFromTermination(termination: ?std.process.Child.Term) CommandPrimary {
    if (termination) |value| return switch (value) {
        .exited => |code| .{ .exited = code },
        .signal => |signal| .{ .signal = signal },
        .unknown => |status| .{ .unknown = status },
        else => .{ .unknown = 0 },
    };
    return .local_io;
}

fn primaryExitedZero(primary: CommandPrimary) bool {
    return switch (primary) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn finishCommandCapture(
    capture: *Capture,
    stdout: linux.fd_t,
    stderr: linux.fd_t,
    result: *CommandResult,
) void {
    if (result.stdout_status != .overflow) capture.drainFinal(stdout, false) catch |err| {
        result.stdout_status = if (err == error.OutputLimit) .overflow else .io_failed;
    };
    if (result.stderr_status != .overflow) capture.drainFinal(stderr, true) catch |err| {
        result.stderr_status = if (err == error.OutputLimit) .overflow else .io_failed;
    };
    if (result.stdout_status != .overflow and result.stdout_status != .io_failed)
        result.stdout_status = if (capture.stdout_eof) .complete else .incomplete;
    if (result.stderr_status != .overflow and result.stderr_status != .io_failed)
        result.stderr_status = if (capture.stderr_eof) .complete else .incomplete;
}

fn takeCleanupEvent(request: CommandRequest, result: *CommandResult) !void {
    if (try request.cleanup_deadline.expired()) return error.CleanupDeadline;
    if (result.cleanup_events >= request.limits.cleanup_events) return error.EventLimit;
    result.cleanup_events += 1;
}

fn commandPidfd(pid: linux.pid_t) !linux.fd_t {
    const opened = linux.pidfd_open(pid, 0);
    return switch (linux.errno(opened)) {
        .SUCCESS => @intCast(opened),
        .SRCH => error.ProcessGone,
        else => error.PidfdUnavailable,
    };
}

fn readProcStat(proc: linux.fd_t, pid: linux.pid_t) !ProcStat {
    var path: [64:0]u8 = undefined;
    const name = std.fmt.bufPrintZ(&path, "{d}/stat", .{pid}) catch return error.ProcUnavailable;
    const opened = linux.openat(proc, name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    switch (linux.errno(opened)) {
        .SUCCESS => {},
        .NOENT, .SRCH => return error.ProcessGone,
        else => return error.ProcUnavailable,
    }
    const descriptor: linux.fd_t = @intCast(opened);
    defer _ = linux.close(descriptor);
    var buffer: [4096]u8 = undefined;
    var length: usize = 0;
    while (true) {
        const amount = linux.read(descriptor, buffer[length..].ptr, buffer.len - length);
        switch (linux.errno(amount)) {
            .SUCCESS => {
                if (amount == 0) break;
                length += amount;
                if (length == buffer.len) return error.ProcUnavailable;
            },
            .INTR => continue,
            else => return error.ProcUnavailable,
        }
    }
    const record = buffer[0..length];
    const end = std.mem.lastIndexOfScalar(u8, record, ')') orelse return error.ProcUnavailable;
    var fields = std.mem.tokenizeScalar(u8, record[end + 2 ..], ' ');
    var index: usize = 3;
    var parent: ?linux.pid_t = null;
    var start_ticks: ?u64 = null;
    while (fields.next()) |field| : (index += 1) {
        if (index == 4) parent = std.fmt.parseInt(linux.pid_t, field, 10) catch return error.ProcUnavailable;
        if (index == 22) {
            start_ticks = std.fmt.parseInt(u64, field, 10) catch return error.ProcUnavailable;
            break;
        }
    }
    return .{
        .pid = pid,
        .parent = parent orelse return error.ProcUnavailable,
        .start_ticks = start_ticks orelse return error.ProcUnavailable,
    };
}

fn openCommandProc() !linux.fd_t {
    const opened = linux.openat(linux.AT.FDCWD, "/proc", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.ProcUnavailable;
    const descriptor: linux.fd_t = @intCast(opened);
    errdefer _ = linux.close(descriptor);
    const Statfs = extern struct {
        f_type: usize,
        bsize: usize,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files_count: u64,
        ffree: u64,
        fsid: [2]i32,
        namelen: usize,
        frsize: usize,
        flags: usize,
        spare: [4]usize,
    };
    var metadata: Statfs = undefined;
    if (linux.errno(linux.syscall2(.fstatfs, @intCast(descriptor), @intFromPtr(&metadata))) != .SUCCESS or
        metadata.f_type != 0x9fa0) return error.ProcUnavailable;
    return descriptor;
}

fn requirePidfds() !void {
    const descriptor = try commandPidfd(linux.getpid());
    defer _ = linux.close(descriptor);
    const signal: linux.SIG = @enumFromInt(0);
    if (linux.errno(linux.pidfd_send_signal(descriptor, signal, null, 0)) != .SUCCESS)
        return error.PidfdUnavailable;
}

fn poisonCommand(
    io: std.Io,
    proc: linux.fd_t,
    request: CommandRequest,
    tracker: *OwnedTracker,
    result: *CommandResult,
) void {
    for (tracker.items[0..tracker.len]) |*item| {
        _ = linux.pidfd_send_signal(item.pidfd, .KILL, null, 0);
        item.kill_sent = true;
    }
    _ = scanOwned(io, proc, request, tracker, result, .kill) catch false;
    var attempts: u16 = 0;
    while (attempts < request.limits.reap_events) : (attempts += 1) {
        var status: u32 = 0;
        const child = linux.waitpid(-1, &status, linux.W.NOHANG);
        if (linux.errno(child) == .CHILD or child == 0) break;
        if (linux.errno(child) != .SUCCESS and linux.errno(child) != .INTR) break;
        if (linux.errno(child) == .SUCCESS and @as(linux.pid_t, @intCast(child)) == tracker.items[0].pid)
            result.termination = terminationFromStatus(status);
    }
    poisoned.store(true, .release);
}

fn finishGatedCommandFailure(
    io: std.Io,
    proc: linux.fd_t,
    request: CommandRequest,
    tracker: *OwnedTracker,
    child: *Spawned,
    capture: *Capture,
    candidate: ?*PidfdOwnership,
    primary: CommandPrimary,
    primary_observed_ns: u64,
    unavailable_cleanup: CommandCleanup,
    gate_test: ?*CommandGateTestState,
    result: *CommandResult,
) CommandResult {
    _ = io;
    child.closeGate();
    result.primary = primary;
    result.primary_deadline_reached = primary == .timeout;
    result.cancellation_observed = primary == .cancelled;
    completePrimaryCommandTimingAt(result, primary_observed_ns);

    const descriptor = if (tracker.len == 1)
        tracker.items[0].pidfd
    else if (candidate) |ownership|
        ownership.descriptor
    else
        commandPidfd(child.pid) catch {
            poisonUnpinnedGatedChild(child.pid, request, result);
            result.cleanup_complete = false;
            result.cleanup = unavailable_cleanup;
            finishCommandCapture(capture, child.stdout, child.stderr, result);
            result.stdout = capture.output[0..capture.stdout_count];
            result.stderr = capture.stderr_output[0..capture.stderr_count];
            result.completed_ns = result.primary_completed_ns;
            poisoned.store(true, .release);
            return result.*;
        };
    var recovered_descriptor: ?linux.fd_t = null;
    if (tracker.len == 0 and candidate == null) recovered_descriptor = descriptor;
    defer if (recovered_descriptor) |owned| {
        _ = linux.close(owned);
    };

    recoverGatedChild(
        proc,
        child.pid,
        descriptor,
        if (tracker.len == 1)
            tracker.items[0].start_ticks
        else if (candidate) |ownership|
            ownership.start_ticks
        else
            null,
        request,
        gate_test,
        result,
    ) catch |err| {
        poisonGatedChild(child.pid, descriptor, request, result);
        result.cleanup_complete = false;
        result.cleanup = commandCleanupFromError(err);
        poisoned.store(true, .release);
    };
    if (result.cleanup_complete) result.cleanup = .complete;
    if (tracker.len == 1) tracker.items[0].reaped = result.termination != null;
    result.descendants = tracker.report;
    finishCommandCapture(capture, child.stdout, child.stderr, result);
    result.stdout = capture.output[0..capture.stdout_count];
    result.stderr = capture.stderr_output[0..capture.stderr_count];
    const completed = now() catch result.primary_completed_ns;
    result.completed_ns = @max(result.primary_completed_ns, completed);
    if (result.cleanup_complete and result.completed_ns > request.cleanup_deadline.expires_ns) {
        result.cleanup_complete = false;
        result.cleanup = .deadline;
        poisoned.store(true, .release);
    }
    return result.*;
}

fn recoverGatedChild(
    proc: linux.fd_t,
    pid: linux.pid_t,
    descriptor: linux.fd_t,
    start_ticks: ?u64,
    request: CommandRequest,
    gate_test: ?*CommandGateTestState,
    result: *CommandResult,
) !void {
    try takeCleanupEvent(request, result);
    if (start_ticks) |expected| {
        if (try verifiedOwnedIdentity(proc, pid, expected, descriptor)) |identity| {
            if (identity.parent != linux.getpid()) return error.IdentityChanged;
        }
    }
    var exited_child_gate = false;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        try takeCleanupEvent(request, result);
        if (try pidfdExited(descriptor)) {
            exited_child_gate = true;
            break;
        }
        try pause(1);
    }
    if (!exited_child_gate) {
        try takeCleanupEvent(request, result);
        switch (linux.errno(linux.pidfd_send_signal(descriptor, .KILL, null, 0))) {
            .SUCCESS, .SRCH => {},
            else => return error.SignalFailed,
        }
    }
    while (true) {
        try takeCleanupEvent(request, result);
        var status: u32 = 0;
        const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(waited)) {
            .SUCCESS => {
                if (waited == 0) {
                    try pause(1);
                    continue;
                }
                if (result.reap_events >= request.limits.reap_events) return error.ReapLimit;
                result.reap_events += 1;
                result.termination = terminationFromStatus(status);
                break;
            },
            .INTR => continue,
            else => return error.ReapFailed,
        }
    }
    try takeCleanupEvent(request, result);
    if (!try pidfdExited(descriptor)) return error.ReapFailed;
    if (commandGateInject(gate_test, .recovery_proof)) return error.ReapFailed;
    var info = std.mem.zeroes(linux.siginfo_t);
    while (true) switch (linux.errno(linux.waitid(
        .ALL,
        0,
        &info,
        linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT,
        null,
    ))) {
        .CHILD => {
            if (result.reap_events >= request.limits.reap_events) return error.ReapLimit;
            result.reap_events += 1;
            result.cleanup_complete = true;
            return;
        },
        .INTR => continue,
        else => return error.ReapFailed,
    };
}

fn poisonGatedChild(
    pid: linux.pid_t,
    descriptor: linux.fd_t,
    request: CommandRequest,
    result: *CommandResult,
) void {
    _ = linux.pidfd_send_signal(descriptor, .KILL, null, 0);
    var attempts: u16 = 0;
    while (attempts < request.limits.reap_events) : (attempts += 1) {
        var status: u32 = 0;
        const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(waited)) {
            .SUCCESS => {
                if (waited == 0) {
                    pause(1) catch {};
                    continue;
                }
                if (result.termination == null) {
                    result.termination = terminationFromStatus(status);
                    if (result.reap_events < request.limits.reap_events)
                        result.reap_events += 1;
                }
                break;
            },
            .INTR => continue,
            .CHILD => break,
            else => break,
        }
    }
}

fn poisonUnpinnedGatedChild(
    pid: linux.pid_t,
    request: CommandRequest,
    result: *CommandResult,
) void {
    _ = linux.kill(pid, .KILL);
    var attempts: u16 = 0;
    while (attempts < request.limits.reap_events) : (attempts += 1) {
        var status: u32 = 0;
        const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(waited)) {
            .SUCCESS => {
                if (waited == 0) {
                    pause(1) catch {};
                    continue;
                }
                result.termination = terminationFromStatus(status);
                if (result.reap_events < request.limits.reap_events)
                    result.reap_events += 1;
                return;
            },
            .INTR => continue,
            else => return,
        }
    }
}

fn signalGroup(pid: linux.pid_t, signal: linux.SIG) !void {
    switch (linux.errno(linux.kill(-pid, signal))) {
        .SUCCESS, .SRCH => {},
        else => return error.SignalFailed,
    }
    // The leader may not yet have run setpgid; it cannot create descendants until
    // after that succeeds. Its unreaped PID is independently owned throughout.
    try signalLeader(pid, signal);
}

fn signalLeader(pid: linux.pid_t, signal: linux.SIG) !void {
    switch (linux.errno(linux.kill(pid, signal))) {
        .SUCCESS, .SRCH => {},
        else => return error.SignalFailed,
    }
}

fn pause(milliseconds: i32) !void {
    var fds: [0]linux.pollfd = .{};
    switch (linux.errno(linux.poll(&fds, 0, milliseconds))) {
        .SUCCESS, .INTR => {},
        else => return error.PollFailed,
    }
}

fn now() !u64 {
    var timestamp: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &timestamp)) != .SUCCESS or timestamp.sec < 0)
        return error.ClockUnavailable;
    return @as(u64, @intCast(timestamp.sec)) * std.time.ns_per_s + @as(u64, @intCast(timestamp.nsec));
}

pub fn monotonicNanoseconds() !u64 {
    return now();
}

const Spawned = struct {
    pid: linux.pid_t,
    stdout: linux.fd_t,
    stderr: linux.fd_t,
    control: linux.fd_t,
    gate: ?linux.fd_t = null,

    fn closeGate(self: *Spawned) void {
        if (self.gate) |descriptor| {
            _ = linux.close(descriptor);
            self.gate = null;
        }
    }
};

fn spawnCommandOwned(
    allocator: std.mem.Allocator,
    options: Options,
    executable: linux.fd_t,
    fault: ?CommandPreSpawnTestFault,
    gate_test: ?*CommandGateTestState,
) !Spawned {
    if (fault == .spawn_local_io) return error.SpawnFailed;
    return spawnOwned(
        allocator,
        options,
        null,
        executable,
        true,
        if (gate_test) |active| active.fault else null,
    );
}

// Zig 0.16 Threaded.spawn loses PID and pipe ownership on exec failure. Keep the
// fork/exec handshake here so both spawn errors and pre-exec stalls are supervised.
fn spawnOwned(
    allocator: std.mem.Allocator,
    options: Options,
    fault: ?PrivateTestFault,
    executable: ?linux.fd_t,
    command_gate: bool,
    gate_fault: ?CommandGateTestFault,
) !Spawned {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const argv = try scratch.allocSentinel(?[*:0]const u8, options.argv.len, null);
    for (options.argv, 0..) |arg, i| argv[i] = (try scratch.dupeZ(u8, arg)).ptr;
    const environment = try options.environment.createPosixBlock(scratch, .{ .zig_progress_fd = -1 });
    defer for (environment.slice) |entry| std.crypto.secureZero(u8, @constCast(std.mem.span(entry.?)));

    const stdout = try makePipe();
    errdefer closePipe(stdout);
    const stderr = try makePipe();
    errdefer closePipe(stderr);
    const control = try makePipe();
    errdefer closePipe(control);
    const gate = if (command_gate) try makeGatePair() else null;
    errdefer if (gate) |pair| closePipe(pair);
    const opened = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.SpawnFailed;
    const null_fd = try aboveStdio(@intCast(opened));
    defer _ = linux.close(null_fd);

    const parent_pid = linux.getpid();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.SpawnFailed;
    if (forked == 0) {
        // No allocation, std.Io, libc, or locks are permitted between fork and exec.
        _ = linux.close(stdout[0]);
        _ = linux.close(stderr[0]);
        _ = linux.close(control[0]);
        if (gate) |pair| _ = linux.close(pair[0]);
        if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS or
            linux.getppid() != parent_pid) childFailure(control[1], 1);
        if (fault == .pre_exec_stall) {
            while (true) {
                var fds: [0]linux.pollfd = .{};
                _ = linux.poll(&fds, 0, 1000);
            }
        }
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) childFailure(control[1], 1);
        if (options.cwd.handle != linux.AT.FDCWD and linux.errno(linux.fchdir(options.cwd.handle)) != .SUCCESS)
            childFailure(control[1], 1);
        if (linux.errno(linux.dup3(null_fd, 0, 0)) != .SUCCESS or
            linux.errno(linux.dup3(stdout[1], 1, 0)) != .SUCCESS or
            linux.errno(linux.dup3(stderr[1], 2, 0)) != .SUCCESS) childFailure(control[1], 1);
        // Linux UAPI CLOSE_RANGE_CLOEXEC is bit 2; Zig 0.16's packed flag labels
        // are shifted by one. Preserve only stdio at exec, including private locks.
        if (linux.errno(linux.close_range(3, std.math.maxInt(linux.fd_t), @bitCast(@as(u32, 1 << 2)))) != .SUCCESS)
            childFailure(control[1], 1);
        if (options.inherited_descriptor) |descriptor|
            if (linux.errno(linux.fcntl(descriptor, linux.F.SETFD, 0)) != .SUCCESS)
                childFailure(control[1], 1);
        if (gate) |pair| childCommandGate(pair[1], control[1], gate_fault);
        if (executable) |descriptor| {
            const executed = linux.execveat(descriptor, "", argv.ptr, environment.slice.ptr, .{
                .EMPTY_PATH = true,
                .SYMLINK_NOFOLLOW = true,
            });
            switch (linux.errno(executed)) {
                .ACCES, .PERM => childFailure(control[1], 2),
                else => childFailure(control[1], 1),
            }
        } else {
            _ = linux.execve(argv[0].?, argv.ptr, environment.slice.ptr);
        }
        childFailure(control[1], 1);
    }
    // Establish the group from both sides of fork, before a deadline can race
    // the child into creating descendants between the group and leader signals.
    _ = linux.setpgid(@intCast(forked), @intCast(forked));
    _ = linux.close(stdout[1]);
    _ = linux.close(stderr[1]);
    _ = linux.close(control[1]);
    if (gate) |pair| _ = linux.close(pair[1]);
    return .{
        .pid = @intCast(forked),
        .stdout = stdout[0],
        .stderr = stderr[0],
        .control = control[0],
        .gate = if (gate) |pair| pair[0] else null,
    };
}

fn childFailure(fd: linux.fd_t, code: u8) noreturn {
    const marker = [_]u8{code};
    _ = linux.write(fd, &marker, marker.len);
    linux.exit_group(126);
}

const command_gate_ready: u8 = 0xa5;
const command_gate_release: u8 = 0x5a;

fn childCommandGate(
    descriptor: linux.fd_t,
    control: linux.fd_t,
    fault: ?CommandGateTestFault,
) void {
    if (fault == .ready_eof) {
        _ = linux.close(descriptor);
        childFailure(control, 3);
    }
    if (fault == .ready_bad) {
        const invalid = [_]u8{ command_gate_ready, command_gate_ready };
        _ = linux.sendto(descriptor, &invalid, invalid.len, linux.MSG.NOSIGNAL, null, 0);
        _ = linux.close(descriptor);
        childFailure(control, 3);
    }
    const ready = [_]u8{command_gate_ready};
    while (true) {
        const sent = linux.sendto(descriptor, &ready, ready.len, linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(sent)) {
            .SUCCESS => {
                if (sent != ready.len) childFailure(control, 3);
                break;
            },
            .INTR => continue,
            else => childFailure(control, 3),
        }
    }
    if (fault == .release_write) {
        _ = linux.close(descriptor);
        childFailure(control, 3);
    }
    var release: [1]u8 = undefined;
    while (true) {
        const received = linux.recvfrom(descriptor, &release, release.len, 0, null, null);
        switch (linux.errno(received)) {
            .SUCCESS => {
                if (received != release.len or release[0] != command_gate_release) {
                    _ = linux.close(descriptor);
                    childFailure(control, 3);
                }
                break;
            },
            .INTR => continue,
            else => {
                _ = linux.close(descriptor);
                childFailure(control, 3);
            },
        }
    }
    _ = linux.close(descriptor);
}

fn awaitCommandGateReady(
    descriptor: linux.fd_t,
    options: Options,
    gate_test: ?*CommandGateTestState,
    observed_ns: *u64,
) !void {
    while (true) {
        observed_ns.* = try primaryPreReleaseObservation(gate_test);
        if (observed_ns.* >= options.deadline.expires_ns) return error.DeadlineExceeded;
        if (cancelled(options)) return error.Cancelled;
        const remaining_ns = options.deadline.expires_ns - observed_ns.*;
        const wait_ms: i32 = @intCast(@min(
            @as(u64, 10),
            @max(@as(u64, 1), (remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms),
        ));
        var pollfds = [_]linux.pollfd{.{
            .fd = descriptor,
            .events = linux.POLL.IN,
            .revents = 0,
        }};
        switch (linux.errno(linux.poll(&pollfds, pollfds.len, wait_ms))) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.PollFailed,
        }
        if (pollfds[0].revents & linux.POLL.NVAL != 0) return error.GateReadFailed;
        if (pollfds[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) == 0)
            continue;
        var ready: [2]u8 = undefined;
        const received = linux.recvfrom(descriptor, &ready, ready.len, 0, null, null);
        switch (linux.errno(received)) {
            .SUCCESS => {
                if (received == 0) return error.GateEof;
                if (received != 1 or ready[0] != command_gate_ready)
                    return error.GateProtocol;
                return;
            },
            .INTR => continue,
            else => return error.GateReadFailed,
        }
    }
}

fn releaseCommandGate(
    descriptor: linux.fd_t,
    gate_test: ?*CommandGateTestState,
) !void {
    const marker = [_]u8{if (commandGateInject(gate_test, .release_bad))
        command_gate_release ^ 0xff
    else
        command_gate_release};
    while (true) {
        const sent = linux.sendto(descriptor, &marker, marker.len, linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(sent)) {
            .SUCCESS => {
                if (sent != marker.len) return error.GateWriteFailed;
                return;
            },
            .INTR => continue,
            else => return error.GateWriteFailed,
        }
    }
}

fn execStatus(fd: linux.fd_t) !bool {
    var byte: [1]u8 = undefined;
    const count = linux.read(fd, &byte, byte.len);
    return switch (linux.errno(count)) {
        .SUCCESS => if (count == 0)
            true
        else if (byte[0] == 2)
            error.ExecutableSnapshotUnsupported
        else
            error.SpawnFailed,
        .AGAIN, .INTR => false,
        else => error.SpawnFailed,
    };
}

fn makePipe() ![2]linux.fd_t {
    var pipe: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.SpawnFailed;
    pipe[0] = aboveStdio(pipe[0]) catch {
        _ = linux.close(pipe[1]);
        return error.SpawnFailed;
    };
    pipe[1] = aboveStdio(pipe[1]) catch {
        _ = linux.close(pipe[0]);
        return error.SpawnFailed;
    };
    return pipe;
}

fn makeGatePair() ![2]linux.fd_t {
    var pair: [2]linux.fd_t = undefined;
    if (linux.errno(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
        0,
        &pair,
    )) != .SUCCESS) return error.SpawnFailed;
    pair[0] = aboveStdio(pair[0]) catch {
        _ = linux.close(pair[1]);
        return error.SpawnFailed;
    };
    pair[1] = aboveStdio(pair[1]) catch {
        _ = linux.close(pair[0]);
        return error.SpawnFailed;
    };
    return pair;
}

fn aboveStdio(fd: linux.fd_t) !linux.fd_t {
    if (fd > 2) return fd;
    const duplicate = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 3);
    _ = linux.close(fd);
    if (linux.errno(duplicate) != .SUCCESS) return error.SpawnFailed;
    return @intCast(duplicate);
}

fn closePipe(pipe: [2]linux.fd_t) void {
    for (pipe) |fd| _ = linux.close(fd);
}

fn requireNoChildren() !void {
    var info = std.mem.zeroes(linux.siginfo_t);
    while (true) switch (linux.errno(linux.waitid(.ALL, 0, &info, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null))) {
        .CHILD => return,
        .INTR => continue,
        else => return error.UnownedChildren,
    };
}

fn validatePrivateDirectory(directory: std.Io.Dir) !void {
    const stat = try files.snapshot(.{ .handle = directory.handle, .flags = .{ .nonblocking = false } });
    if (stat.mode & linux.S.IFMT != linux.S.IFDIR or stat.mode & 0o7777 != 0o700 or
        stat.uid != linux.geteuid()) return error.UnsafeFile;
}

fn createCapture(directory: std.Io.Dir, name: []const u8) !std.Io.File {
    var buffer: [256:0]u8 = undefined;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    const fd = linux.openat(directory.handle, buffer[0..name.len :0], .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0o600);
    switch (linux.errno(fd)) {
        .SUCCESS => {},
        .EXIST => return error.PathAlreadyExists,
        else => return error.CaptureOpenFailed,
    }
    errdefer _ = linux.close(@intCast(fd));
    const result: std.Io.File = .{ .handle = @intCast(fd), .flags = .{ .nonblocking = true } };
    const stat = try files.snapshot(result);
    if (stat.mode & linux.S.IFMT != linux.S.IFREG or stat.mode & 0o7777 != 0o600 or
        stat.uid != linux.geteuid() or stat.nlink != 1 or stat.size != 0) return error.UnsafeFile;
    return result;
}

fn validateCapture(io: std.Io, directory: files.Directory, name: []const u8, file: std.Io.File, size: usize) !void {
    const observed = try directory.openFile(io, name);
    defer observed.close(io);
    const stat = try files.snapshot(file);
    if (stat.size != size or !files.sameSnapshot(stat, try files.snapshot(observed))) return error.CaptureChanged;
}

var signals_busy = std.atomic.Value(bool).init(false);
var signal_cancelled = std.atomic.Value(bool).init(false);
var received_signal = std.atomic.Value(u8).init(0);

/// Install before starting work, retain through separately budgeted cleanup.
/// The handler only writes lock-free atomics; cleanup must not reset the latch.
pub const SignalCancellation = struct {
    previous: [3]linux.Sigaction,
    const handled = [_]linux.SIG{ .HUP, .INT, .TERM };

    pub fn install() !SignalCancellation {
        if (signals_busy.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.SignalHandlerBusy;
        errdefer signals_busy.store(false, .release);
        signal_cancelled.store(false, .release);
        received_signal.store(0, .release);
        var result: SignalCancellation = undefined;
        var installed: usize = 0;
        errdefer for (handled[0..installed], 0..) |item, i| {
            _ = linux.sigaction(item, &result.previous[i], null);
        };
        var action: linux.Sigaction = .{
            .handler = .{ .handler = handle },
            .mask = linux.sigemptyset(),
            .flags = 0,
        };
        for (handled, 0..) |item, i| {
            if (linux.errno(linux.sigaction(item, &action, &result.previous[i])) != .SUCCESS)
                return error.SignalSetupFailed;
            installed += 1;
        }
        return result;
    }

    pub fn flag(_: *const SignalCancellation) *const std.atomic.Value(bool) {
        return &signal_cancelled;
    }

    pub fn signal(_: *const SignalCancellation) ?u8 {
        const value = received_signal.load(.acquire);
        return if (value == 0) null else value;
    }

    pub fn deinit(self: *SignalCancellation) void {
        for (handled, 0..) |item, i| _ = linux.sigaction(item, &self.previous[i], null);
        signals_busy.store(false, .release);
        self.* = undefined;
    }

    fn handle(number: linux.SIG) callconv(.c) void {
        _ = received_signal.cmpxchgStrong(0, @intCast(@intFromEnum(number)), .acq_rel, .acquire);
        signal_cancelled.store(true, .release);
    }
};
