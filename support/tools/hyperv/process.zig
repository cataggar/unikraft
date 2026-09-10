const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const diagnostics = @import("diagnostics.zig");

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

var busy = std.atomic.Value(bool).init(false);
var poisoned = std.atomic.Value(bool).init(false);

/// Explicit process-wide ownership policy. Use in a dedicated supervisor, not an
/// application with unrelated waitpid users. Children may not escape their group.
pub fn initialize() !void {
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_CHILD_SUBREAPER), 1, 0, 0, 0)) != .SUCCESS)
        return error.SubreaperUnavailable;
}

/// No inherited environment, PATH lookup, shell, raw stderr, or automatic replay.
/// A failed cleanup poisons this supervisor; writer ownership must not transfer.
pub fn run(allocator: std.mem.Allocator, io: std.Io, options: Options) !Result {
    _ = io;
    if (options.argv.len == 0 or options.argv.len > 128 or !std.fs.path.isAbsolute(options.argv[0]) or
        options.stdout_limit > 4 * 1024 * 1024 or options.stderr_limit > 4 * 1024 * 1024 or
        options.cleanup_ms < 100 or options.cleanup_ms > 30 * 60 * 1000)
        return error.InvalidOptions;
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
    if (busy.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.SupervisorBusy;
    defer busy.store(false, .release);
    if (poisoned.load(.acquire)) return error.UnresolvedCleanup;
    var subreaper: c_int = 0;
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.GET_CHILD_SUBREAPER), @intFromPtr(&subreaper), 0, 0, 0)) != .SUCCESS or subreaper != 1)
        return error.SubreaperRequired;

    var result: Result = .{ .storage = try allocator.alloc(u8, options.stdout_limit) };
    @memset(result.storage, 0);
    errdefer result.deinit(allocator);
    if (try options.deadline.expired()) {
        result.failures.primary = .{ .stage = .process_spawn, .category = .timeout };
        return result;
    }
    if (cancelled(options)) {
        result.failures.primary = .{ .stage = .process_spawn, .category = .cancelled };
        return result;
    }
    var child = spawnOwned(allocator, options) catch {
        result.failures.primary = .{ .stage = .process_spawn, .category = .spawn_failed };
        return result;
    };
    const pid = child.pid;
    defer _ = linux.close(child.stdout);
    defer _ = linux.close(child.stderr);
    defer _ = linux.close(child.control);
    var capture: Capture = .{ .output = result.storage, .stderr_limit = options.stderr_limit };
    monitor(&child, options, &capture) catch |err| {
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
    };
    // This is an independent budget, also used after normal leader exit so a
    // successful parent cannot strand background descendants holding pipes.
    cleanup(pid, options.cleanup_ms, &result) catch {
        result.cleanup_complete = false;
        result.unreaped_group = pid;
        result.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
        poisoned.store(true, .release);
    };
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
    if (result.failures.primary == null and result.cleanup_complete) {
        result.stdout = result.storage[0..capture.stdout_count];
    } else {
        std.crypto.secureZero(u8, result.storage);
    }
    return result;
}

const Capture = struct {
    output: []u8,
    stderr_limit: usize,
    stdout_count: usize = 0,
    stderr_count: usize = 0,
    stdout_eof: bool = false,
    stderr_eof: bool = false,

    fn drain(self: *Capture, fd: linux.fd_t, stderr: bool, options: Options) !void {
        var buffer: [4096]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        const count = if (stderr) &self.stderr_count else &self.stdout_count;
        const limit = if (stderr) self.stderr_limit else self.output.len;
        while (true) {
            if (cancelled(options)) return error.Cancelled;
            if (try options.deadline.expired()) return error.DeadlineExceeded;
            const n = linux.read(fd, &buffer, @min(buffer.len, limit - count.* + 1));
            switch (linux.errno(n)) {
                .SUCCESS => {
                    if (n == 0) {
                        if (stderr) self.stderr_eof = true else self.stdout_eof = true;
                        return;
                    }
                    if (n > limit - count.*) return error.OutputLimit;
                    if (!stderr) @memcpy(self.output[count.*..][0..n], buffer[0..n]);
                    count.* += n;
                },
                .AGAIN => return,
                .INTR => continue,
                else => return error.CaptureFailed,
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

fn cleanup(pid: linux.pid_t, milliseconds: u32, result: *Result) !void {
    var final_signal_sent = false;
    errdefer if (!final_signal_sent) signalGroup(pid, .KILL) catch {};
    const deadline = try Deadline.afterMilliseconds(milliseconds);
    try signalGroup(pid, .TERM);
    // Retain the unreaped group leader until the final group signal to prevent
    // PID/PGID reuse from ever directing a signal at an unrelated process.
    const grace = try Deadline.afterMilliseconds(@min(50, milliseconds / 4));
    while (!try grace.expired()) try pause(try grace.waitMilliseconds(10));
    try signalGroup(pid, .KILL);
    final_signal_sent = true;
    while (true) {
        var status: u32 = 0;
        const child = linux.waitpid(if (result.termination == null) pid else -pid, &status, linux.W.NOHANG);
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

fn signalGroup(pid: linux.pid_t, signal: linux.SIG) !void {
    switch (linux.errno(linux.kill(-pid, signal))) {
        .SUCCESS, .SRCH => {},
        else => return error.SignalFailed,
    }
    // The leader may not yet have run setpgid; it cannot create descendants until
    // after that succeeds. Its unreaped PID is independently owned throughout.
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

const Spawned = struct {
    pid: linux.pid_t,
    stdout: linux.fd_t,
    stderr: linux.fd_t,
    control: linux.fd_t,
};

// Zig 0.16 Threaded.spawn loses PID and pipe ownership on exec failure. Keep the
// fork/exec handshake here so both spawn errors and pre-exec stalls are supervised.
fn spawnOwned(allocator: std.mem.Allocator, options: Options) !Spawned {
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
    const opened = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.SpawnFailed;
    const null_fd = try aboveStdio(@intCast(opened));
    defer _ = linux.close(null_fd);

    const parent_pid = linux.getpid();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.SpawnFailed;
    if (forked == 0) {
        // No allocation, std.Io, libc, or locks are permitted between fork and exec.
        if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS or
            linux.getppid() != parent_pid) childFailure(control[1]);
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) childFailure(control[1]);
        if (options.cwd.handle != linux.AT.FDCWD and linux.errno(linux.fchdir(options.cwd.handle)) != .SUCCESS)
            childFailure(control[1]);
        if (linux.errno(linux.dup3(null_fd, 0, 0)) != .SUCCESS or
            linux.errno(linux.dup3(stdout[1], 1, 0)) != .SUCCESS or
            linux.errno(linux.dup3(stderr[1], 2, 0)) != .SUCCESS) childFailure(control[1]);
        // Linux UAPI CLOSE_RANGE_CLOEXEC is bit 2; Zig 0.16's packed flag labels
        // are shifted by one. Preserve only stdio at exec, including private locks.
        if (linux.errno(linux.close_range(3, std.math.maxInt(linux.fd_t), @bitCast(@as(u32, 1 << 2)))) != .SUCCESS)
            childFailure(control[1]);
        _ = linux.execve(argv[0].?, argv.ptr, environment.slice.ptr);
        childFailure(control[1]);
    }
    // Establish the group from both sides of fork, before a deadline can race
    // the child into creating descendants between the group and leader signals.
    _ = linux.setpgid(@intCast(forked), @intCast(forked));
    _ = linux.close(stdout[1]);
    _ = linux.close(stderr[1]);
    _ = linux.close(control[1]);
    return .{ .pid = @intCast(forked), .stdout = stdout[0], .stderr = stderr[0], .control = control[0] };
}

fn childFailure(fd: linux.fd_t) noreturn {
    const marker = [_]u8{1};
    _ = linux.write(fd, &marker, marker.len);
    linux.exit_group(126);
}

fn execStatus(fd: linux.fd_t) !bool {
    var byte: [1]u8 = undefined;
    const count = linux.read(fd, &byte, byte.len);
    return switch (linux.errno(count)) {
        .SUCCESS => if (count == 0) true else error.SpawnFailed,
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
