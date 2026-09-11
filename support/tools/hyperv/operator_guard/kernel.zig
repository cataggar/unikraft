const std = @import("std");
const builtin = @import("builtin");
pub const linux = std.os.linux;
const r = @import("records.zig");
comptime {
    if (builtin.os.tag != .linux or (builtin.cpu.arch != .aarch64 and builtin.cpu.arch != .x86_64))
        @compileError("Operator custody requires Linux AArch64 or x86_64");
}
pub fn checked(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        else => error.KernelCustodyUnavailable,
    };
}
pub fn now() !u64 {
    return r.core.process.monotonicNanoseconds();
}
pub fn fd(result: usize) !linux.fd_t {
    return @intCast(try checked(result));
}
pub fn close(descriptor: linux.fd_t) void {
    _ = linux.close(descriptor);
}
pub fn pipe() ![2]linux.fd_t {
    var descriptors: [2]linux.fd_t = undefined;
    _ = try checked(linux.pipe2(&descriptors, .{ .CLOEXEC = true, .NONBLOCK = true }));
    return descriptors;
}
pub fn pidfd(pid: i32) !linux.fd_t {
    return fd(linux.pidfd_open(pid, 0));
}
pub fn eventfd() !linux.fd_t {
    const flags: linux.O = .{ .NONBLOCK = true, .CLOEXEC = true };
    return fd(linux.syscall2(.eventfd2, 0, @as(u32, @bitCast(flags))));
}
pub fn readable(descriptor: linux.fd_t) !bool {
    var fds = [_]linux.pollfd{.{ .fd = descriptor, .events = linux.POLL.IN, .revents = 0 }};
    _ = try checked(linux.poll(&fds, 1, 0));
    if ((fds[0].revents & linux.POLL.NVAL) != 0) return error.InvalidDescriptor;
    return (fds[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR)) != 0;
}
pub fn pause() void {
    var fds: [0]linux.pollfd = .{};
    _ = linux.poll(&fds, 0, 5);
}
pub fn kill(descriptor: linux.fd_t) !void {
    const result = linux.pidfd_send_signal(descriptor, .KILL, null, 0);
    if (linux.errno(result) != .SUCCESS and linux.errno(result) != .SRCH) return error.TerminationFailed;
}
pub fn write(descriptor: linux.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = linux.write(descriptor, bytes.ptr + offset, bytes.len - offset);
        if (linux.errno(n) == .INTR) continue;
        offset += try checked(n);
        if (n == 0) return error.ShortWrite;
    }
}
pub fn read(descriptor: linux.fd_t, buffer: []u8) !usize {
    while (true) {
        const n = linux.read(descriptor, buffer.ptr, buffer.len);
        switch (linux.errno(n)) {
            .SUCCESS => return n,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.ReadFailed,
        }
    }
}
pub fn memfd(bytes: []const u8) !linux.fd_t {
    const descriptor = try fd(linux.memfd_create("operator-guard", linux.MFD.CLOEXEC | linux.MFD.ALLOW_SEALING));
    errdefer close(descriptor);
    try write(descriptor, bytes);
    // Linux F_ADD_SEALS / F_GET_SEALS; write, shrink, grow and seal itself.
    _ = try checked(linux.fcntl(descriptor, 1033, 15));
    return descriptor;
}
pub fn readSealed(a: std.mem.Allocator, io: std.Io, descriptor: linux.fd_t) ![]u8 {
    if (try checked(linux.fcntl(descriptor, 1034, 0)) != 15) return error.UnsealedDispatch;
    const file: std.Io.File = .{ .handle = descriptor, .flags = .{ .nonblocking = false } };
    const size = (try file.stat(io)).size;
    if (size == 0 or size > r.max_record) return error.InvalidDispatch;
    const bytes = try a.alloc(u8, @intCast(size));
    errdefer a.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != size) return error.InvalidDispatch;
    return bytes;
}
pub fn directory(descriptor: linux.fd_t) !r.Directory {
    const value = try r.core.private_files.snapshot(.{ .handle = descriptor, .flags = .{ .nonblocking = false } });
    return .{ .device_major = value.dev_major, .device_minor = value.dev_minor, .inode = value.ino };
}
pub fn procRead(proc: linux.fd_t, name: [:0]const u8, buffer: []u8) ![]const u8 {
    const descriptor = try fd(linux.openat(proc, name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer close(descriptor);
    const length = try read(descriptor, buffer);
    if (length == buffer.len) return error.ProcRecordTooLarge;
    return buffer[0..length];
}
pub fn openProc() !linux.fd_t {
    const descriptor = try fd(linux.openat(linux.AT.FDCWD, "/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    errdefer close(descriptor);
    try requireProc(descriptor);
    return descriptor;
}
pub fn requireProc(descriptor: linux.fd_t) !void {
    // statfs uses the same 64-bit-long UAPI on supported AArch64 and x86_64.
    const Statfs = extern struct {
        f_type: usize,
        bsize: usize,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        fsid: [2]i32,
        namelen: usize,
        frsize: usize,
        flags: usize,
        spare: [4]usize,
    };
    var metadata: Statfs = undefined;
    _ = try checked(linux.syscall2(.fstatfs, @intCast(descriptor), @intFromPtr(&metadata)));
    if (metadata.f_type != 0x9fa0) return error.ProcfsRequired;
    var buffer: [4096]u8 = undefined;
    const status = try procRead(descriptor, "self/status", &buffer);
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "NSpid:")) {
            var ids = std.mem.tokenizeAny(u8, line[6..], " \t");
            const first = ids.next() orelse return error.InvalidProcIdentity;
            if (try std.fmt.parseInt(i32, first, 10) != linux.getpid() or ids.next() != null)
                return error.ProcNamespaceMismatch;
            return;
        }
    }
    return error.MissingNamespaceIdentity;
}
pub fn boot(proc: linux.fd_t) !r.Uuid {
    var buffer: [128]u8 = undefined;
    const bytes = std.mem.trim(u8, try procRead(proc, "sys/kernel/random/boot_id", &buffer), "\n");
    _ = try r.core.contracts.parseUuid(bytes);
    return bytes[0..36].*;
}
pub fn requireUnprivileged(proc: linux.fd_t) !void {
    var buffer: [4096]u8 = undefined;
    const status = try procRead(proc, "self/status", &buffer);
    for ([_][]const u8{ "CapEff:\t0000000000000000\n", "CapPrm:\t0000000000000000\n", "CapInh:\t0000000000000000\n", "CapAmb:\t0000000000000000\n" }) |field| {
        if (std.mem.indexOf(u8, status, field) == null) return error.HostCapabilitiesNotAllowed;
    }
}
pub fn identity(proc: linux.fd_t, pid: i32) !r.Identity {
    const ticks = try startTicks(proc, pid);
    var path: [80]u8 = undefined;
    var value: linux.Statx = undefined;
    _ = try checked(linux.statx(proc, try std.fmt.bufPrintZ(&path, "{d}/ns/pid", .{pid}), 0, .BASIC_STATS, &value));
    return .{ .pid = pid, .start_ticks = ticks, .namespace = .{ .device_major = value.dev_major, .device_minor = value.dev_minor, .inode = value.ino } };
}
pub fn startTicks(proc: linux.fd_t, pid: i32) !u64 {
    var path: [80]u8 = undefined;
    var buffer: [4096]u8 = undefined;
    const stat = try procRead(proc, try std.fmt.bufPrintZ(&path, "{d}/stat", .{pid}), &buffer);
    const end = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.InvalidProcIdentity;
    var fields = std.mem.tokenizeScalar(u8, stat[end + 2 ..], ' ');
    var ticks: ?u64 = null;
    var index: usize = 3;
    while (fields.next()) |field| : (index += 1) {
        if (index == 22) {
            ticks = try std.fmt.parseInt(u64, field, 10);
            break;
        }
    }
    return ticks orelse error.InvalidProcIdentity;
}
pub fn requirePid1(proc: linux.fd_t, pid: i32) !void {
    var path: [80]u8 = undefined;
    var buffer: [4096]u8 = undefined;
    const status = try procRead(proc, try std.fmt.bufPrintZ(&path, "{d}/status", .{pid}), &buffer);
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "NSpid:")) {
            var ids = std.mem.tokenizeAny(u8, line[6..], " \t");
            var count: usize = 0;
            var last: u64 = 0;
            while (ids.next()) |id| {
                last = try std.fmt.parseInt(u64, id, 10);
                count += 1;
            }
            if (count != 2 or last != 1) return error.NotNamespaceInit;
            return;
        }
    }
    return error.MissingNamespaceIdentity;
}
pub fn mapChild(proc: linux.fd_t, pid: i32) !void {
    const uid = linux.getuid();
    const gid = linux.getgid();
    var path: [80]u8 = undefined;
    procWrite(proc, try std.fmt.bufPrintZ(&path, "{d}/setgroups", .{pid}), "deny") catch return error.SetgroupsMapUnavailable;
    var buffer: [80]u8 = undefined;
    procWrite(proc, try std.fmt.bufPrintZ(&path, "{d}/uid_map", .{pid}), try std.fmt.bufPrint(&buffer, "0 {d} 1\n", .{uid})) catch return error.UidMapUnavailable;
    procWrite(proc, try std.fmt.bufPrintZ(&path, "{d}/gid_map", .{pid}), try std.fmt.bufPrint(&buffer, "0 {d} 1\n", .{gid})) catch return error.GidMapUnavailable;
}
fn procWrite(proc: linux.fd_t, name: [:0]const u8, bytes: []const u8) !void {
    const descriptor = try fd(linux.openat(proc, name, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer close(descriptor);
    try write(descriptor, bytes);
}
pub fn mountProc() !void {
    if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) return error.MountNamespaceUnavailable;
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return error.PrivateMountUnavailable;
    if (linux.errno(linux.mount("proc", "/proc", "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, 0)) != .SUCCESS) return error.NamespaceProcUnavailable;
}
pub fn protect() !void {
    _ = try checked(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0));
}
pub fn dropCapabilities() !void {
    _ = try checked(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    _ = try checked(linux.prctl(@intFromEnum(linux.PR.SET_SECUREBITS), linux.SECBIT_NOROOT | linux.SECBIT_NOROOT_LOCKED, 0, 0, 0));
    // UAPI pid is u32, unlike Zig 0.16's usize declaration.
    const Header = extern struct { version: u32, pid: i32 };
    var header: Header = .{ .version = 0x20080522, .pid = 0 };
    const data = [_]linux.cap_user_data_t{std.mem.zeroes(linux.cap_user_data_t)} ** 2;
    _ = try checked(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
    try protect();
}
pub fn reap(pid: i32) !?u32 {
    var status: u32 = 0;
    const result = linux.waitpid(pid, &status, linux.W.NOHANG);
    if (linux.errno(result) == .INTR) return null;
    if (try checked(result) == 0) return null;
    if (result != @as(usize, @intCast(pid))) return error.WrongReapedProcess;
    return status;
}
/// Fixed same-executable dispatch, no caller argv/env or shell. Duplicate before
/// remapping to avoid aliasing inherited descriptor numbers.
pub const Child = struct { pid: i32, pidfd: i32 };
pub fn spawn(executable: linux.fd_t, mode: [:0]const u8, descriptors: []const linux.fd_t, stdio: ?[2]linux.fd_t) !Child {
    return spawnImpl(false, executable, mode, descriptors, stdio, 0);
}
pub fn spawnNamespace(executable: linux.fd_t, descriptors: []const linux.fd_t, deadline_ns: u64) !Child {
    return spawnImpl(true, executable, "--operator-guard-init", descriptors, .{ 1, 2 }, deadline_ns);
}
fn spawnImpl(namespace: bool, executable: linux.fd_t, mode: [:0]const u8, descriptors: []const linux.fd_t, stdio: ?[2]linux.fd_t, deadline_ns: u64) !Child {
    if (descriptors.len > 12) return error.InvalidDispatch;
    var copies: [12]linux.fd_t = undefined;
    var count: usize = 0;
    defer for (copies[0..count]) |copy| close(copy);
    for (descriptors, 0..) |source, i| {
        copies[i] = try fd(linux.fcntl(source, linux.F.DUPFD_CLOEXEC, 32));
        count += 1;
    }
    const executable_copy = try fd(linux.fcntl(executable, linux.F.DUPFD_CLOEXEC, 48));
    defer close(executable_copy);
    const null_fd = try fd(linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer close(null_fd);
    const out = try fd(linux.fcntl(if (stdio) |fds| fds[0] else null_fd, linux.F.DUPFD_CLOEXEC, 32));
    defer close(out);
    const err = try fd(linux.fcntl(if (stdio) |fds| fds[1] else null_fd, linux.F.DUPFD_CLOEXEC, 32));
    defer close(err);
    var retained: i32 = -1;
    const flags = linux.CLONE.PIDFD | @intFromEnum(linux.SIG.CHLD) |
        (if (namespace) linux.CLONE.NEWUSER | linux.CLONE.NEWPID else @as(usize, 0));
    const child = checked(linux.syscall5(.clone, flags, 0, @intFromPtr(&retained), 0, 0)) catch
        return if (namespace) error.UserPidNamespaceUnavailable else error.AtomicPidfdUnavailable;
    if (child == 0) {
        // Raw syscalls only in the post-fork child.
        if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS) linux.exit_group(126);
        if (linux.errno(linux.dup3(null_fd, 0, 0)) != .SUCCESS) linux.exit_group(126);
        if (linux.errno(linux.dup3(out, 1, 0)) != .SUCCESS) linux.exit_group(126);
        if (linux.errno(linux.dup3(err, 2, 0)) != .SUCCESS) linux.exit_group(126);
        if (linux.errno(linux.close_range(3, std.math.maxInt(linux.fd_t), @bitCast(@as(u32, 1 << 2)))) != .SUCCESS) linux.exit_group(126);
        for (copies[0..count], 0..) |copy, i| {
            if (linux.errno(linux.dup3(copy, @intCast(i + 3), 0)) != .SUCCESS) linux.exit_group(126);
        }
        if (namespace) {
            // No key is in this address space or descriptor set. The private
            // signing key is loaded by the custodian only after this child's exec.
            if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 1, 0, 0, 0)) != .SUCCESS) linux.exit_group(126);
            if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS)
                linux.exit_group(126);
            write(8, &.{0x4d}) catch linux.exit_group(126);
            // Mapping must precede exec, which otherwise drops capabilities
            // for the as-yet-unmapped UID. This child performs raw syscalls only.
            while (true) {
                if ((readable(5) catch true) or (readable(7) catch true) or (now() catch deadline_ns) >= deadline_ns)
                    linux.exit_group(126);
                var marker: [1]u8 = undefined;
                const n = linux.read(9, &marker, 1);
                if (linux.errno(n) == .SUCCESS) {
                    if (n != 1 or marker[0] != 0x55) linux.exit_group(126);
                    break;
                }
                if (linux.errno(n) != .AGAIN and linux.errno(n) != .INTR) linux.exit_group(126);
                pause();
            }
        }
        const argv = [_:null]?[*:0]const u8{ "operator-guard", mode };
        const env = [_:null]?[*:0]const u8{};
        _ = linux.execveat(executable_copy, "", &argv, &env, .{ .EMPTY_PATH = true, .SYMLINK_NOFOLLOW = false });
        linux.exit_group(126);
    }
    return .{ .pid = @intCast(child), .pidfd = retained };
}
