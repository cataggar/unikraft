// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const runtime = @import("types.zig").runtime;
const Fixture = @import("composition_tests.zig").Fixture;
const linux = std.os.linux;

const Report = extern struct {
    err: u16,
    unchanged: u16,
    uid: u32,
    gid: u32,
    parent: linux.pid_t,
};

fn attempt(path: []const u8, wrong_parent: bool) !Report {
    var descriptors: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&descriptors, .{ .CLOEXEC = true })) != .SUCCESS)
        return error.NamespaceTestPipe;
    defer _ = linux.close(descriptors[0]);
    const parent = linux.getpid();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) {
        _ = linux.close(descriptors[1]);
        return error.NamespaceTestFork;
    }
    if (forked == 0) {
        _ = linux.close(descriptors[0]);
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        const uid = linux.geteuid();
        const gid = linux.getegid();
        const before = namespaceIdentity() catch linux.exit_group(123);
        var failure: ?anyerror = null;
        child(io, path, if (wrong_parent) 1 else parent) catch |err| {
            failure = err;
        };
        const after = namespaceIdentity() catch linux.exit_group(123);
        var report: Report = .{
            .err = if (failure) |err| @intFromError(err) else 0,
            .unchanged = @intFromBool(uid == linux.geteuid() and gid == linux.getegid() and std.mem.eql(u64, &before, &after)),
            .uid = linux.geteuid(),
            .gid = linux.getegid(),
            .parent = linux.getppid(),
        };
        const bytes = std.mem.asBytes(&report);
        const count = linux.write(descriptors[1], bytes.ptr, bytes.len);
        linux.exit_group(if (linux.errno(count) == .SUCCESS and count == bytes.len) 0 else 125);
    }
    _ = linux.close(descriptors[1]);
    const pid: linux.pid_t = @intCast(forked);
    const opened = linux.pidfd_open(pid, 0);
    if (linux.errno(opened) != .SUCCESS) {
        _ = linux.kill(pid, .KILL);
        var status: u32 = 0;
        _ = linux.waitpid(pid, &status, 0);
        return error.NamespaceTestPidfd;
    }
    const pidfd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(pidfd);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.pidfd_send_signal(pidfd, .KILL, null, 0);
        var status: u32 = 0;
        while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    };
    var poll = [_]linux.pollfd{.{ .fd = descriptors[0], .events = linux.POLL.IN, .revents = 0 }};
    const ready = linux.poll(&poll, poll.len, 5_000);
    if (linux.errno(ready) != .SUCCESS or ready != 1 or poll[0].revents & linux.POLL.IN == 0)
        return error.NamespaceTestReportTimeout;
    var report: Report = undefined;
    const bytes = std.mem.asBytes(&report);
    const count = linux.read(descriptors[0], bytes.ptr, bytes.len);
    if (linux.errno(count) != .SUCCESS or count != bytes.len) return error.NamespaceTestReport;
    poll[0] = .{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 };
    const exited = linux.poll(&poll, poll.len, 5_000);
    if (linux.errno(exited) != .SUCCESS or exited != 1) return error.NamespaceTestExitTimeout;
    var status: u32 = 0;
    if (linux.errno(linux.waitpid(pid, &status, 0)) != .SUCCESS) return error.NamespaceTestWait;
    reaped = true;
    if (!linux.W.IFEXITED(status) or linux.W.EXITSTATUS(status) != 0) return error.NamespaceTestExit;
    return report;
}

fn child(io: std.Io, path: []const u8, parent: linux.pid_t) !void {
    try runtime.enterPreparationNamespace(io, parent);
    var retained = try core.private_files.RetainedFile.open(io, path, .private);
    defer retained.close(io);
    try retained.verify(io);
}

fn namespaceIdentity() ![3]u64 {
    const opened = linux.openat(linux.AT.FDCWD, "/proc/self/ns/user", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.NamespaceTestIdentity;
    const file: std.Io.File = .{ .handle = @intCast(opened), .flags = .{ .nonblocking = false } };
    defer _ = linux.close(file.handle);
    const snapshot = try core.private_files.snapshot(file);
    return .{ snapshot.ino, snapshot.dev_major, snapshot.dev_minor };
}

test "joined namespace rejects a nonparent before changing identity or mappings" {
    const report = try attempt("/not-opened", true);
    try std.testing.expectEqual(@as(u16, @intFromError(error.InvalidNamespaceParent)), report.err);
    try std.testing.expectEqual(@as(u16, 1), report.unchanged);
    try std.testing.expectEqual(linux.geteuid(), report.uid);
    try std.testing.expectEqual(linux.getegid(), report.gid);
    try std.testing.expectEqual(linux.getpid(), report.parent);
}

test "joined namespace authenticates actual mapped owner and retained file or remains explicitly unqualified" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const path = try std.fs.path.join(fixture.arena.allocator(), &.{ fixture.request.stdlib, "os.py" });
    const report = try attempt(path, false);
    if (report.err != 0) {
        const err: anyerror = @errorFromInt(report.err);
        switch (err) {
            error.AzureRuntimeNamespaceUserDenied,
            error.AzureRuntimeNamespaceSetgroupsDenied,
            error.AzureRuntimeNamespaceUidMapDenied,
            error.AzureRuntimeNamespaceGidMapDenied,
            error.AzureRuntimeNamespaceIdentityDenied,
            error.AzureRuntimeNamespaceMountDenied,
            => {
                std.log.warn("real preparation namespace unavailable: {s}; positive unqualified", .{@errorName(err)});
                return error.SkipZigTest;
            },
            else => return err,
        }
    }
    try std.testing.expectEqual(@as(u16, 0), report.unchanged);
    try std.testing.expectEqual(@as(u32, 0), report.uid);
    try std.testing.expectEqual(@as(u32, 0), report.gid);
    try std.testing.expectEqual(linux.getpid(), report.parent);
}
