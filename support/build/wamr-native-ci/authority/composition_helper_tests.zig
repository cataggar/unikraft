// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const helper = @import("prepare_helper.zig");
const tx = @import("transaction.zig");
const Fixture = @import("composition_tests.zig").Fixture;
const linux = std.os.linux;
const a = std.testing.allocator;
const io = std.testing.io;
var active: ?*Witness = null;

const Witness = struct {
    leader: linux.pid_t = 0,
    worker: linux.pid_t = 0,
    cancel: bool = false,
    canceled_calls: usize = 0,
    foreign: ?*Foreign = null,
    fn check(_: *anyopaque) !void {}
    fn barrier(self: *Witness) tx.Barrier {
        return .{ .context = self, .check = check };
    }
    fn observed(raw: *anyopaque, leader: linux.pid_t, worker: linux.pid_t) !void {
        const self: *Witness = @ptrCast(@alignCast(raw));
        self.leader = leader;
        self.worker = worker;
        if (self.foreign) |foreign| try foreign.spawn();
    }
};

fn checkCancel(userdata: ?*anyopaque) std.Io.Cancelable!void {
    if (active) |witness| if (witness.cancel and witness.worker != 0) {
        witness.canceled_calls += 1;
        return error.Canceled;
    };
    try io.vtable.checkCancel(userdata);
}

fn assertReaped(pid: linux.pid_t) !void {
    try std.testing.expect(pid > 1);
    var status: u32 = 0;
    try std.testing.expectEqual(linux.E.CHILD, linux.errno(linux.waitpid(pid, &status, linux.W.NOHANG)));
}

fn namespaceUnavailable(err: anyerror) !void {
    switch (err) {
        error.AzureRuntimeNamespaceUserDenied,
        error.AzureRuntimeNamespaceSetgroupsDenied,
        error.AzureRuntimeNamespaceUidMapDenied,
        error.AzureRuntimeNamespaceGidMapDenied,
        error.AzureRuntimeNamespaceIdentityDenied,
        error.AzureRuntimeNamespaceMountDenied,
        error.HelperPidNamespaceUnavailable,
        error.HelperProcNamespaceUnavailable,
        => {
            std.log.warn("real second-fork helper namespace unavailable: {s}; unqualified", .{@errorName(err)});
            return error.SkipZigTest;
        },
        else => return err,
    }
}

test "joined helper second fork initializes actual PID worker before real native supervision" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").process_fixture, a);
    defer a.free(executable);
    var witness: Witness = .{};
    const hooks: helper.Test.Hooks = .{ .context = &witness, .after_worker = Witness.observed };
    const outcome = helper.Test.run(.{ .allocator = a, .io = io }, .{
        .cwd = fixture.dir,
        .executable = executable,
        .barrier = witness.barrier(),
    }, try core.process.Deadline.afterMilliseconds(5_000), &hooks);
    if (outcome.result.refused.cause != error.SourceOnlyWorkerFinished)
        try namespaceUnavailable(outcome.result.refused.cause);
    try std.testing.expect(outcome.cleanup_complete);
    try assertReaped(witness.leader);
    try assertReaped(witness.worker);
}

const Foreign = struct {
    slots: *[3]linux.pid_t,
    live_fd: ?linux.fd_t = null,

    fn init() !Foreign {
        const mapped = linux.mmap(null, std.heap.pageSize(), .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .ANONYMOUS = true }, -1, 0);
        if (linux.errno(mapped) != .SUCCESS) return error.ForeignTestMap;
        const slots: *[3]linux.pid_t = @ptrFromInt(mapped);
        slots.* = .{ 0, 0, 0 };
        return .{ .slots = slots };
    }
    fn forkInto(slot: *linux.pid_t) usize {
        return linux.syscall5(.clone, linux.CLONE.PARENT_SETTID | @intFromEnum(linux.SIG.CHLD), 0, @intFromPtr(slot), 0, 0);
    }
    fn spawn(self: *Foreign) !void {
        const root = forkInto(&self.slots[0]);
        if (linux.errno(root) != .SUCCESS) return error.ForeignTestFork;
        if (root == 0) {
            const dead = forkInto(&self.slots[1]);
            if (linux.errno(dead) != .SUCCESS) linux.exit_group(125);
            if (dead == 0) linux.exit_group(23);
            const live = forkInto(&self.slots[2]);
            if (linux.errno(live) != .SUCCESS) linux.exit_group(125);
            if (live == 0) {
                while (true) {
                    var pause: [0]linux.pollfd = .{};
                    _ = linux.poll(&pause, 0, 20);
                }
            }
            linux.exit_group(0);
        }
        const status = try waitOwned(@intCast(root), 5_000);
        self.slots[0] = 0;
        if (!linux.W.IFEXITED(status) or linux.W.EXITSTATUS(status) != 0)
            return error.ForeignTestChild;
        const opened = linux.pidfd_open(@atomicLoad(linux.pid_t, &self.slots[2], .acquire), 0);
        if (linux.errno(opened) != .SUCCESS) return error.ForeignTestPidfd;
        self.live_fd = @intCast(opened);
    }
    fn assertUntouched(self: *Foreign) !void {
        var poll = [_]linux.pollfd{.{ .fd = self.live_fd.?, .events = linux.POLL.IN, .revents = 0 }};
        try std.testing.expectEqual(@as(usize, 0), linux.poll(&poll, 1, 0));
        const dead = @atomicLoad(linux.pid_t, &self.slots[1], .acquire);
        const status = try waitOwned(dead, 1_000);
        self.slots[1] = 0;
        try std.testing.expect(linux.W.IFEXITED(status));
        try std.testing.expectEqual(@as(u8, 23), linux.W.EXITSTATUS(status));
    }
    fn close(self: *Foreign) void {
        if (self.live_fd) |fd| {
            _ = linux.pidfd_send_signal(fd, .KILL, null, 0);
            _ = linux.close(fd);
        }
        for (self.slots, 0..) |pid, index| {
            if (pid == 0) continue;
            if (index != 1 and (index != 2 or self.live_fd == null)) _ = linux.kill(pid, .KILL);
            _ = waitOwned(pid, 5_000) catch @panic("owned foreign fixture cleanup failed");
        }
        _ = linux.munmap(@ptrCast(self.slots), std.heap.pageSize());
    }
};

fn waitOwned(pid: linux.pid_t, milliseconds: u64) !u32 {
    if (pid <= 1) return error.ForeignTestIdentity;
    const deadline = try core.process.Deadline.afterMilliseconds(milliseconds);
    var status: u32 = 0;
    while (!try deadline.expired()) {
        const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
        if (linux.errno(waited) == .SUCCESS and waited == @as(usize, @intCast(pid))) return status;
        if (linux.errno(waited) != .SUCCESS and linux.errno(waited) != .INTR) return error.ForeignTestReap;
        var pause: [0]linux.pollfd = .{};
        _ = linux.poll(&pause, 0, 10);
    }
    return error.ForeignTestDeadline;
}

test "joined helper IO cancellation after worker fork reaps only owned family and leaves dynamically orphaned foreign children" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var foreign = try Foreign.init();
    defer foreign.close();
    var witness: Witness = .{ .cancel = true, .foreign = &foreign };
    active = &witness;
    defer active = null;
    var table = io.vtable.*;
    table.checkCancel = checkCancel;
    const injected: std.Io = .{ .userdata = io.userdata, .vtable = &table };
    const hooks: helper.Test.Hooks = .{
        .context = &witness,
        .after_worker = Witness.observed,
        .cleanup_ms = 600,
    };
    const outcome = helper.Test.run(.{ .allocator = a, .io = injected }, .{
        .cwd = fixture.dir,
        .executable = "",
        .barrier = witness.barrier(),
        .hold = true,
    }, try core.process.Deadline.afterMilliseconds(5_000), &hooks);
    if (witness.worker == 0) try namespaceUnavailable(outcome.result.refused.cause);
    try std.testing.expectEqual(error.Canceled, outcome.result.refused.cause);
    try std.testing.expect(witness.canceled_calls > 0);
    // Forced termination remains explicit uncertainty despite proven reaping.
    try std.testing.expect(!outcome.cleanup_complete);
    try assertReaped(witness.leader);
    try assertReaped(witness.worker);
    try foreign.assertUntouched();
}
