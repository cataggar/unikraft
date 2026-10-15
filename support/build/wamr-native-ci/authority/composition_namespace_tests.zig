// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const runtime = @import("types.zig").runtime;
const Fixture = @import("composition_tests.zig").Fixture;
const linux = std.os.linux;

const Report = extern struct {
    err: u16,
    identity_err: u16,
    identity_errno: u16,
    unchanged: u16,
    uid: u32,
    gid: u32,
    parent: linux.pid_t,
};

const Options = struct {
    after_identity_path: [*:0]const u8 = "/proc/self/ns/user",
};

fn attempt(path: []const u8, wrong_parent: bool, options: Options) !Report {
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
        var failure: ?anyerror = null;
        var identity_errno: linux.E = .SUCCESS;
        const before = namespaceIdentity("/proc/self/ns/user", &identity_errno) catch |err| blk: {
            failure = err;
            break :blk null;
        };
        if (failure == null) child(io, path, if (wrong_parent) 1 else parent) catch |err| {
            failure = err;
        };
        var identity_failure: ?anyerror = null;
        const after = namespaceIdentity(options.after_identity_path, &identity_errno) catch |err| blk: {
            identity_failure = err;
            break :blk null;
        };
        if (failure == null) failure = identity_failure;
        var report: Report = .{
            .err = if (failure) |err| @intFromError(err) else 0,
            .identity_err = if (identity_failure) |err| @intFromError(err) else 0,
            .identity_errno = @intFromEnum(identity_errno),
            .unchanged = if (before != null and after != null)
                @intFromBool(uid == linux.geteuid() and gid == linux.getegid() and
                    std.mem.eql(u64, &before.?, &after.?))
            else
                2,
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
        _ = linux.waitpid(pid, @ptrCast(&status), 0);
        return error.NamespaceTestPidfd;
    }
    const pidfd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(pidfd);
    var reaped = false;
    defer if (!reaped) {
        _ = linux.pidfd_send_signal(pidfd, .KILL, null, 0);
        var status: u32 = 0;
        while (linux.errno(linux.waitpid(pid, @ptrCast(&status), 0)) == .INTR) {}
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
    if (linux.errno(linux.waitpid(pid, @ptrCast(&status), 0)) != .SUCCESS) return error.NamespaceTestWait;
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

fn namespaceIdentity(path: [*:0]const u8, errno: *linux.E) ![3]u64 {
    const opened = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    errno.* = linux.errno(opened);
    switch (errno.*) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.NamespaceTestIdentityAccessDenied,
        .NOENT => return error.NamespaceTestIdentityNotFound,
        else => return error.NamespaceTestIdentityUnavailable,
    }
    const file: std.Io.File = .{ .handle = @intCast(opened), .flags = .{ .nonblocking = false } };
    defer _ = linux.close(file.handle);
    const snapshot = try core.private_files.snapshot(file);
    return .{ snapshot.ino, snapshot.dev_major, snapshot.dev_minor };
}

test "joined namespace rejects a nonparent before changing identity or mappings" {
    const report = try attempt("/not-opened", true, .{});
    try std.testing.expectEqual(@as(u16, @intFromError(error.InvalidNamespaceParent)), report.err);
    try std.testing.expectEqual(@as(u16, 1), report.unchanged);
    try std.testing.expectEqual(linux.geteuid(), report.uid);
    try std.testing.expectEqual(linux.getegid(), report.gid);
    try std.testing.expectEqual(linux.getpid(), report.parent);
}

test "joined namespace reports original refusal and actual identity syscall error without false timeout" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const inaccessible = try fixture.dir.createFile(std.testing.io, "identity-denied", .{
        .exclusive = true,
        .permissions = .fromMode(0),
    });
    inaccessible.close(std.testing.io);
    const path = try std.fs.path.join(fixture.arena.allocator(), &.{ fixture.path, "identity-denied" });
    const report = try attempt("/not-opened", true, .{
        .after_identity_path = try fixture.arena.allocator().dupeSentinel(u8, path, 0),
    });
    try std.testing.expectEqual(@as(u16, @intFromError(error.InvalidNamespaceParent)), report.err);
    try std.testing.expectEqual(@as(u16, @intFromError(error.NamespaceTestIdentityAccessDenied)), report.identity_err);
    try std.testing.expectEqual(@as(u16, @intFromEnum(linux.E.ACCES)), report.identity_errno);
    try std.testing.expectEqual(@as(u16, 2), report.unchanged);
    try std.testing.expectEqual(linux.geteuid(), report.uid);
    try std.testing.expectEqual(linux.getegid(), report.gid);
    try std.testing.expectEqual(linux.getpid(), report.parent);
}

test "joined namespace authenticates actual mapped owner and retained file or remains explicitly unqualified" {
    var fixture = Fixture.init() catch |err| {
        std.debug.print(
            "preparation namespace fixture acquisition failed: {s}; " ++
                "uid={d} gid={d}\n",
            .{ @errorName(err), linux.geteuid(), linux.getegid() },
        );
        return err;
    };
    defer fixture.deinit();
    const path = try std.fs.path.join(fixture.arena.allocator(), &.{ fixture.request.stdlib, "os.py" });
    const report = attempt(path, false, .{}) catch |err| {
        std.debug.print(
            "preparation namespace fixture failed: {s}; " ++
                "uid={d} gid={d} parent={d}\n",
            .{ @errorName(err), linux.geteuid(), linux.getegid(), linux.getpid() },
        );
        return err;
    };
    std.debug.print(
        "preparation namespace result: {s}; mapped_uid={d} mapped_gid={d} " ++
            "parent={d} unchanged={d} identity={s} identity_errno={d}\n",
        .{
            if (report.err == 0)
                "authenticated"
            else
                @errorName(@errorFromInt(report.err)),
            report.uid,
            report.gid,
            report.parent,
            report.unchanged,
            if (report.identity_err == 0)
                "retained"
            else
                @errorName(@errorFromInt(report.identity_err)),
            report.identity_errno,
        },
    );
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
