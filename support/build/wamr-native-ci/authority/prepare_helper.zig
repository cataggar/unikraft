// SPDX-License-Identifier: BSD-3-Clause
//! Closed fork helper, not a discoverable command or path-to-owner adapter.
//! Parent-live custody checks stay in the original UID/mount namespace.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const types = @import("types.zig");
const probes = @import("runtime_probes.zig");
const tx = @import("transaction.zig");
const runtime = types.runtime;
const linux = std.os.linux;
const count = runtime.commands.len + 3;
const magic = 0x554b505245503031;

pub const Result = struct { result: probes.Result, cleanup_complete: bool };
const Job = union(enum) {
    probes: probes.CopiedInput,
    process_test: Test.Command,

    fn root(self: Job) std.Io.Dir {
        return switch (self) {
            .probes => |input| input.root,
            .process_test => |input| input.cwd,
        };
    }
    fn barrier(self: Job) tx.Barrier {
        return switch (self) {
            .probes => |input| input.barrier,
            .process_test => |input| input.barrier,
        };
    }
    fn decode(self: Job, frame: Frame) !probes.Result {
        return switch (self) {
            .probes => |input| frame.decode(input.contract),
            .process_test => if (builtin.is_test and frame.kind == .refused and
                frame.error_code != 0 and frame.completed_steps == 0)
                .{ .refused = .{ .cause = @errorFromInt(frame.error_code), .step = null, .completed_steps = 0 } }
            else
                error.InvalidHelperReport,
        };
    }
};

const Family = struct {
    slot: *linux.pid_t,
    leader: linux.pid_t = 0,
    leader_fd: ?linux.fd_t = null,
    worker: linux.pid_t = 0,
    worker_fd: ?linux.fd_t = null,
    leader_reaped: bool = false,
    worker_reaped: bool = false,
    leader_status: u32 = 0,
    worker_status: u32 = 0,

    fn init() !Family {
        const mapped = linux.mmap(null, std.heap.pageSize(), .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .ANONYMOUS = true }, -1, 0);
        if (linux.errno(mapped) != .SUCCESS) return error.HelperOwnershipUnavailable;
        const slot: *linux.pid_t = @ptrFromInt(mapped);
        @atomicStore(linux.pid_t, slot, 0, .release);
        return .{ .slot = slot };
    }
    fn close(self: *Family) void {
        if (self.leader_fd) |fd| _ = linux.close(fd);
        if (self.worker_fd) |fd| _ = linux.close(fd);
        _ = linux.munmap(@ptrCast(self.slot), std.heap.pageSize());
    }
    fn discover(self: *Family) !void {
        const worker = @atomicLoad(linux.pid_t, self.slot, .acquire);
        if (worker == 0) return;
        if (worker <= 1 or worker == self.leader or worker == linux.getpid() or
            (self.worker != 0 and self.worker != worker))
            return error.InvalidHelperOwnership;
        self.worker = worker;
        if (self.worker_fd == null and !self.worker_reaped) {
            // The leader never reaps this child: its kernel-written PID remains
            // reserved until this controller specifically reaps the adopted PID.
            const opened = linux.pidfd_open(worker, 0);
            if (linux.errno(opened) != .SUCCESS) return error.HelperPidfdUnavailable;
            self.worker_fd = @intCast(opened);
        }
    }
    fn signalOwned(self: *Family, signal: linux.SIG) !void {
        var failure = false;
        if (!self.leader_reaped) {
            const result = if (self.leader_fd) |fd| linux.pidfd_send_signal(fd, signal, null, 0) else linux.kill(self.leader, signal);
            if (linux.errno(result) != .SUCCESS and linux.errno(result) != .SRCH) failure = true;
        }
        if (self.worker != 0 and !self.worker_reaped) {
            const result = if (self.worker_fd) |fd| linux.pidfd_send_signal(fd, signal, null, 0) else linux.kill(self.worker, signal);
            if (linux.errno(result) != .SUCCESS and linux.errno(result) != .SRCH) failure = true;
        }
        if (failure) return error.HelperSignalFailed;
    }
    fn reap(self: *Family) !bool {
        try self.discover();
        if (!self.leader_reaped) self.leader_reaped = try reapOne(self.leader, &self.leader_status);
        if (!self.leader_reaped) return false;
        // Re-read after leader exit, including a fork racing the preceding load.
        try self.discover();
        if (self.worker == 0) return true;
        if (!self.worker_reaped) self.worker_reaped = try reapOne(self.worker, &self.worker_status);
        return self.worker_reaped;
    }
    fn reapOne(pid: linux.pid_t, status: *u32) !bool {
        const waited = linux.waitpid(pid, status, linux.W.NOHANG);
        if (linux.errno(waited) == .INTR) return false;
        if (linux.errno(waited) != .SUCCESS) return error.HelperReapFailed;
        if (waited == 0) return false;
        if (waited != @as(usize, @intCast(pid))) return error.HelperReapFailed;
        return true;
    }
};
const WireCommand = struct {
    primary: core.process.CommandPrimary,
    termination: ?std.process.Child.Term,
    cleanup: core.process.CommandCleanup,
    cleanup_complete: bool,
    stdout_status: core.process.CommandStreamStatus,
    stderr_status: core.process.CommandStreamStatus,
    descendants: core.process.CommandDescendants,
    executable: core.process.ExecutableIdentity,
    executable_stable: bool,
    cancellation_observed: bool,
    primary_deadline_reached: bool,
    started_ns: u64,
    primary_completed_ns: u64,
    completed_ns: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_sha256: [32]u8,
    stderr_sha256: [32]u8,
    freshness_code: u16,
    supervision_passed: bool,

    fn encode(value: probes.CommandEvidence) WireCommand {
        var result: WireCommand = undefined;
        @memset(std.mem.asBytes(&result), 0);
        inline for (std.meta.fields(WireCommand)) |field| {
            if (comptime std.mem.eql(u8, field.name, "freshness_code"))
                result.freshness_code = if (value.freshness) |err| @intFromError(err) else 0
            else
                @field(result, field.name) = @field(value, field.name);
        }
        return result;
    }
    fn decode(self: WireCommand) probes.CommandEvidence {
        var result: probes.CommandEvidence = undefined;
        inline for (std.meta.fields(WireCommand)) |field| {
            if (comptime std.mem.eql(u8, field.name, "freshness_code"))
                result.freshness = if (self.freshness_code != 0) @errorFromInt(self.freshness_code) else null
            else
                @field(result, field.name) = @field(self, field.name);
        }
        result.stdout_redacted = if (self.stdout_bytes == 0) "" else "[redacted]";
        result.stderr_redacted = if (self.stderr_bytes == 0) "" else "[redacted]";
        return result;
    }
};
const Frame = struct {
    marker: u64,
    kind: enum(u8) { barrier, acknowledgment, complete, refused },
    error_code: u16,
    completed_steps: u8,
    step: ?probes.Step,
    command_present: bool,
    command: WireCommand,
    elf: probes.ElfEvidence,
    commands: [count]WireCommand,
    loader_entries: u16,
    content: [32]u8,
    metadata: [32]u8,
    parents: [32]u8,
    manifest: [32]u8,
    fn init(kind: @FieldType(Frame, "kind")) Frame {
        var result: Frame = undefined;
        @memset(std.mem.asBytes(&result), 0);
        result.marker = magic;
        result.kind = kind;
        return result;
    }
    fn encode(value: probes.Result) Frame {
        var result = Frame.init(.refused);
        switch (value) {
            .complete => |evidence| {
                result.kind = .complete;
                result.completed_steps = count;
                result.elf = evidence.elf;
                for (evidence.probes, &result.commands) |command, *encoded| encoded.* = WireCommand.encode(command);
                result.loader_entries = evidence.loader_entries;
                result.content = evidence.content_sha256;
                result.metadata = evidence.metadata_sha256;
                result.parents = evidence.parents_sha256;
                result.manifest = evidence.manifest_sha256;
            },
            .refused => |failure| {
                result.error_code = @intFromError(failure.cause);
                result.completed_steps = failure.completed_steps;
                result.step = failure.step;
                if (failure.command) |command| {
                    result.command_present = true;
                    result.command = WireCommand.encode(command);
                }
            },
        }
        return result;
    }
    fn decode(self: Frame, contract: runtime.Contract) !probes.Result {
        if (self.completed_steps > count) return error.InvalidHelperReport;
        if (self.kind == .refused) {
            if (self.error_code == 0) return error.InvalidHelperReport;
            return .{ .refused = .{
                .cause = @errorFromInt(self.error_code),
                .step = self.step,
                .completed_steps = self.completed_steps,
                .command = if (self.command_present) self.command.decode() else null,
            } };
        }
        if (self.kind != .complete or self.completed_steps != count or self.error_code != 0 or
            !std.mem.eql(u8, &self.content, &try core.contracts.parseSha256(contract.content_sha256)) or
            !std.mem.eql(u8, &self.metadata, &try core.contracts.parseSha256(contract.metadata_sha256)) or
            !std.mem.eql(u8, &self.parents, &try core.contracts.parseSha256(contract.parents_sha256)) or
            !std.mem.eql(u8, &self.manifest, &try core.contracts.parseSha256(contract.manifest.sha256)))
            return error.InvalidHelperReport;
        var evidence: probes.Evidence = .{
            .elf = self.elf,
            .probes = undefined,
            .loader_entries = self.loader_entries,
            .content_sha256 = self.content,
            .metadata_sha256 = self.metadata,
            .parents_sha256 = self.parents,
            .manifest_sha256 = self.manifest,
        };
        for (self.commands, &evidence.probes) |command, *decoded| {
            decoded.* = command.decode();
            if (!decoded.supervision_passed or !decoded.cleanup_complete or decoded.freshness != null)
                return error.InvalidHelperReport;
        }
        return .{ .complete = evidence };
    }
};

fn send(fd: linux.fd_t, frame: *const Frame) !void {
    const bytes = std.mem.asBytes(frame);
    while (true) {
        const written = linux.sendto(fd, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(written)) {
            .SUCCESS => if (written == bytes.len) return else return error.HelperChannelFailed,
            .INTR => continue,
            else => return error.HelperChannelFailed,
        }
    }
}
fn receive(fd: linux.fd_t, frame: *Frame) !void {
    const bytes = std.mem.asBytes(frame);
    while (true) {
        const received = linux.recvfrom(fd, bytes.ptr, bytes.len, linux.MSG.TRUNC, null, null);
        switch (linux.errno(received)) {
            .SUCCESS => if (received == bytes.len and frame.marker == magic) return else return error.InvalidHelperReport,
            .INTR => continue,
            else => return error.HelperChannelFailed,
        }
    }
}
const Peer = struct {
    fd: linux.fd_t,
    fn check(raw: *anyopaque) !void {
        const self: *Peer = @ptrCast(@alignCast(raw));
        const request = Frame.init(.barrier);
        try send(self.fd, &request);
        var response: Frame = undefined;
        try receive(self.fd, &response);
        if (response.kind != .acknowledgment) return error.InvalidHelperReport;
        if (response.error_code != 0) return @errorFromInt(response.error_code);
    }
    fn barrier(self: *Peer) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};
fn closeOtherDescriptors(fd: linux.fd_t, root: linux.fd_t, cwd: linux.fd_t) !void {
    var retained = [_]linux.fd_t{ fd, root, cwd };
    std.mem.sort(linux.fd_t, &retained, {}, std.sort.asc(linux.fd_t));
    var first: u32 = 0;
    for (retained) |descriptor| {
        const next: u32 = @intCast(descriptor);
        if (next < first) continue;
        if (next > first and linux.errno(linux.syscall3(.close_range, first, next - 1, 0)) != .SUCCESS)
            return error.HelperDescriptorIsolationFailed;
        first = next + 1;
    }
    if (linux.errno(linux.syscall3(.close_range, first, std.math.maxInt(u32), 0)) != .SUCCESS)
        return error.HelperDescriptorIsolationFailed;
}
fn child(fd: linux.fd_t, parent: linux.pid_t, job: Job, cwd: std.Io.Dir, slot: *linux.pid_t, inherited_signal: ?*core.process.SignalCancellation) noreturn {
    var threaded: std.Io.Threaded = .init_single_threaded;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const ctx: types.Context = .{ .allocator = arena.allocator(), .io = threaded.io(), .signal = inherited_signal };
    var peer: Peer = .{ .fd = fd };
    const outcome = childRun(ctx, parent, job, cwd, slot, &peer) catch |err| probes.Result{
        .refused = .{ .step = null, .cause = err, .completed_steps = 0 },
    };
    var frame = Frame.encode(outcome);
    // No process address, borrowed slice or path crosses the inherited channel.
    send(fd, &frame) catch linux.exit_group(125);
    linux.exit_group(0);
}
fn childRun(ctx_: types.Context, parent: linux.pid_t, job: Job, cwd: std.Io.Dir, slot: *linux.pid_t, peer: *Peer) !probes.Result {
    var ctx = ctx_;
    try closeOtherDescriptors(peer.fd, job.root().handle, cwd.handle);
    if (linux.errno(linux.setsid()) != .SUCCESS) return error.HelperSessionFailed;
    // The leader cannot begin destructive work before parent PID pinning and
    // the first fresh custody acknowledgment.
    try peer.barrier().revalidate();
    var cancellation: core.process.SignalCancellation = undefined;
    if (ctx.signal == null) {
        cancellation = try core.process.SignalCancellation.install();
        ctx.signal = &cancellation;
    }
    try core.process.initialize();
    try runtime.enterPreparationNamespace(ctx.io, parent);
    return runPidWorker(ctx, job, cwd, slot, peer);
}
fn runPidWorker(ctx: types.Context, job: Job, cwd: std.Io.Dir, slot: *linux.pid_t, peer: *Peer) !probes.Result {
    // The namespace init's death kills every probe descendant, including an
    // escaped session, even if the outer helper must be killed during cleanup.
    if (linux.errno(linux.unshare(linux.CLONE.NEWPID)) != .SUCCESS)
        return error.HelperPidNamespaceUnavailable;
    const own_pidfd = linux.pidfd_open(linux.getpid(), 0);
    if (linux.errno(own_pidfd) != .SUCCESS) return error.HelperPidfdUnavailable;
    defer _ = linux.close(@intCast(own_pidfd));
    // Kernel publication precedes either clone return, including leader death
    // before userspace can report the owned worker to the original controller.
    const worker = linux.syscall5(.clone, linux.CLONE.PARENT_SETTID | @intFromEnum(linux.SIG.CHLD), 0, @intFromPtr(slot), 0, 0);
    if (linux.errno(worker) != .SUCCESS) return error.HelperForkFailed;
    if (worker != 0) {
        const worker_fd = linux.pidfd_open(@intCast(worker), 0);
        if (linux.errno(worker_fd) != .SUCCESS) linux.exit_group(124);
        while (true) {
            var fds = [_]linux.pollfd{.{ .fd = @intCast(worker_fd), .events = linux.POLL.IN, .revents = 0 }};
            const polled = linux.poll(&fds, 1, 20);
            if (linux.errno(polled) != .SUCCESS and linux.errno(polled) != .INTR) linux.exit_group(124);
            if (fds[0].revents & linux.POLL.IN != 0) linux.exit_group(0);
        }
    }
    if (linux.getpid() != 1 or linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS)
        return error.HelperParentGuardFailed;
    var parent_poll = [_]linux.pollfd{.{ .fd = @intCast(own_pidfd), .events = linux.POLL.IN, .revents = 0 }};
    if (linux.errno(linux.poll(&parent_poll, 1, 0)) != .SUCCESS or parent_poll[0].revents != 0)
        return error.HelperParentGuardFailed;
    if (linux.errno(linux.mount("proc", "/proc", "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, 0)) != .SUCCESS)
        return error.HelperProcNamespaceUnavailable;
    // PR_SET_CHILD_SUBREAPER is not inherited across the second fork.
    try core.process.initialize();
    if (builtin.is_test and job == .process_test)
        return Test.worker(ctx, job.process_test, peer);
    const input = job.probes;
    var copied = input;
    copied.barrier = peer.barrier();
    const sealed = try probes.sealCopied(ctx, copied);
    defer sealed.close(ctx.io);
    return probes.runSealed(ctx, .{
        .sealed = &sealed,
        .layout = input.layout,
        .contract = input.contract,
        .cwd = cwd,
        .barrier = peer.barrier(),
    });
}
fn refusal(err: anyerror, cleanup: bool) Result {
    return .{
        .result = .{ .refused = .{ .step = null, .cause = err, .completed_steps = 0 } },
        .cleanup_complete = cleanup,
    };
}

pub fn run(ctx: types.Context, input: probes.CopiedInput, deadline: core.process.Deadline) Result {
    input.barrier.revalidate() catch |err| return refusal(err, true);
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux)
        return refusal(error.CompatibleRuntimeUnavailable, true);
    const cwd = filesOpenOutput(ctx, input.layout.output) catch |err| return refusal(err, true);
    defer cwd.close(ctx.io);
    return runImpl(ctx, .{ .probes = input }, cwd, deadline, null) catch |err| refusal(err, true);
}

// Every fallible return is before fork. Once a child exists, supervise owns all
// outcomes and reports cleanup explicitly, including thrown I/O cancellation.
fn runImpl(ctx: types.Context, job: Job, cwd: std.Io.Dir, deadline: core.process.Deadline, hooks: ?*const Test.Hooks) !Result {
    try job.barrier().revalidate();
    try ctx.io.checkCancel();
    var family = try Family.init();
    defer family.close();
    var sockets: [2]linux.fd_t = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &sockets)) != .SUCCESS)
        return error.HelperChannelFailed;
    defer _ = linux.close(sockets[0]);
    const flags = linux.fcntl(sockets[0], linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS or linux.errno(linux.fcntl(sockets[0], linux.F.SETFL, flags | @as(u32, @bitCast(linux.O{ .NONBLOCK = true })))) != .SUCCESS) {
        _ = linux.close(sockets[1]);
        return error.HelperChannelFailed;
    }
    const parent = linux.getpid();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) {
        _ = linux.close(sockets[1]);
        return error.HelperForkFailed;
    }
    if (forked == 0) child(sockets[1], parent, job, cwd, family.slot, ctx.signal);
    _ = linux.close(sockets[1]);
    family.leader = @intCast(forked);
    const opened = linux.pidfd_open(family.leader, 0);
    var failure: ?anyerror = null;
    if (linux.errno(opened) != .SUCCESS) {
        failure = error.HelperPidfdUnavailable;
    } else family.leader_fd = @intCast(opened);
    return supervise(ctx, job, sockets[0], &family, deadline, hooks, failure);
}

fn supervise(ctx: types.Context, job: Job, socket: linux.fd_t, family: *Family, deadline: core.process.Deadline, hooks: ?*const Test.Hooks, initial_failure: ?anyerror) Result {
    var received: ?Frame = null;
    var failure = initial_failure;
    var cleanup_failed = false;
    var cleanup_deadline: ?core.process.Deadline = null;
    var kill_deadline: ?core.process.Deadline = null;
    var cleanup_ticks: u32 = 0;
    var worker_announced = false;
    var killed = false;
    const cleanup_ms: u64 = if (builtin.is_test and hooks != null) hooks.?.cleanup_ms else 15_000;
    while (true) {
        family.discover() catch |err| {
            failure = failure orelse err;
            cleanup_failed = true;
        };
        if (builtin.is_test and hooks != null and family.worker != 0 and !worker_announced) {
            worker_announced = true;
            if (hooks.?.after_worker) |action| action(hooks.?.context, family.leader, family.worker) catch |err| {
                failure = failure orelse err;
            };
        }
        ctx.io.checkCancel() catch |err| {
            failure = failure orelse err;
        };
        if (failure == null) {
            if (ctx.signal) |signal| if (signal.flag().load(.acquire)) {
                failure = error.Cancelled;
            };
            const expired = deadline.expired() catch |err| blk: {
                failure = err;
                break :blk false;
            };
            if (expired) failure = error.BudgetExhausted;
        }
        if ((failure != null or received != null) and cleanup_deadline == null) {
            cleanup_deadline = core.process.Deadline.afterMilliseconds(cleanup_ms) catch |err| {
                family.signalOwned(.KILL) catch {};
                return refusal(failure orelse err, false);
            };
            kill_deadline = .{ .expires_ns = cleanup_deadline.?.expires_ns - cleanup_ms / 3 * std.time.ns_per_ms };
            if (failure != null) family.signalOwned(.TERM) catch {
                cleanup_failed = true;
            };
        }
        if (kill_deadline) |kill| if (!killed and (kill.expired() catch true)) {
            family.signalOwned(.KILL) catch {
                cleanup_failed = true;
            };
            killed = true;
        };
        if (family.reap()) |complete| {
            if (complete) break;
        } else |err| {
            failure = failure orelse err;
            cleanup_failed = true;
        }
        if (cleanup_deadline) |cleanup| {
            cleanup_ticks += 1;
            if ((cleanup.expired() catch true) or cleanup_ticks >= (cleanup_ms + 19) / 20) {
                family.signalOwned(.KILL) catch {};
                return refusal(failure orelse error.PreparationHelperCleanupFailed, false);
            }
        }
        var pollfds = [_]linux.pollfd{
            .{ .fd = socket, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = family.leader_fd orelse -1, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = family.worker_fd orelse -1, .events = linux.POLL.IN, .revents = 0 },
        };
        const polled = linux.poll(&pollfds, pollfds.len, 20);
        if (linux.errno(polled) != .SUCCESS and linux.errno(polled) != .INTR)
            failure = failure orelse error.HelperChannelFailed;
        if (pollfds[0].revents & linux.POLL.IN != 0) {
            var frame: Frame = undefined;
            if (receive(socket, &frame)) |_| {
                if (frame.kind == .barrier and received == null) {
                    var acknowledgment = Frame.init(.acknowledgment);
                    job.barrier().revalidate() catch |err| {
                        failure = failure orelse err;
                    };
                    acknowledgment.error_code = if (failure) |err| @intFromError(err) else 0;
                    send(socket, &acknowledgment) catch {
                        failure = failure orelse error.HelperChannelFailed;
                    };
                } else if ((frame.kind == .complete or frame.kind == .refused) and received == null) {
                    received = frame;
                } else failure = failure orelse error.InvalidHelperReport;
            } else |err| failure = failure orelse err;
        }
        if (cleanup_deadline != null) {
            var pause: [0]linux.pollfd = .{};
            _ = linux.poll(&pause, 0, 20);
        }
    }
    if (killed or cleanup_failed) return refusal(failure orelse error.PreparationHelperCleanupFailed, false);
    if (failure) |err| return refusal(err, true);
    if (received == null) {
        var final_poll = [_]linux.pollfd{.{ .fd = socket, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.errno(linux.poll(&final_poll, 1, 0)) == .SUCCESS and final_poll[0].revents & linux.POLL.IN != 0) {
            var frame: Frame = undefined;
            receive(socket, &frame) catch |err| return refusal(err, true);
            if (frame.kind == .complete or frame.kind == .refused) received = frame;
        }
    }
    if (!linux.W.IFEXITED(family.leader_status) or linux.W.EXITSTATUS(family.leader_status) != 0 or
        (family.worker != 0 and (!linux.W.IFEXITED(family.worker_status) or linux.W.EXITSTATUS(family.worker_status) != 0)) or received == null)
        return refusal(error.HelperExitedWithoutEvidence, true);
    const result = job.decode(received.?) catch |err| return refusal(err, true);
    job.barrier().revalidate() catch |err| return refusal(err, true);
    return .{ .result = result, .cleanup_complete = true };
}
fn filesOpenOutput(ctx: types.Context, path: []const u8) !std.Io.Dir {
    return core.private_files.openDirectory(ctx.io, path, .private);
}

pub const Test = struct {
    pub const Command = struct {
        cwd: std.Io.Dir,
        executable: []const u8,
        barrier: tx.Barrier,
        hold: bool = false,
    };
    pub const Hooks = struct {
        context: *anyopaque,
        after_worker: ?*const fn (*anyopaque, linux.pid_t, linux.pid_t) anyerror!void = null,
        cleanup_ms: u64 = 15_000,
    };
    pub fn run(ctx: types.Context, command: Command, deadline: core.process.Deadline, hooks: ?*const Hooks) Result {
        if (!builtin.is_test) @compileError("Helper process fixtures are test-only");
        if (hooks) |selected| if (selected.cleanup_ms < 60 or selected.cleanup_ms > 15_000)
            return refusal(error.InvalidDeadline, true);
        core.process.initialize() catch |err| return refusal(err, true);
        return runImpl(ctx, .{ .process_test = command }, command.cwd, deadline, hooks) catch |err| refusal(err, true);
    }
    fn worker(ctx: types.Context, command: Command, peer: *Peer) !probes.Result {
        if (!builtin.is_test) @compileError("Helper process fixtures are test-only");
        if (command.hold) {
            var action: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
            if (linux.errno(linux.sigaction(.TERM, &action, null)) != .SUCCESS) return error.HelperTestSignalFailed;
            while (true) {
                var fds: [0]linux.pollfd = .{};
                _ = linux.poll(&fds, 0, 20);
            }
        }
        const executable = try core.process.Executable.open(ctx.io, command.executable);
        defer executable.close(ctx.io);
        var environment = std.process.Environ.Map.init(ctx.allocator);
        defer environment.deinit();
        var result = try tx.supervise(ctx, .{
            .executable = executable,
            .argv = &.{ command.executable, "success" },
            .environment = &environment,
            .cwd = command.cwd,
            .primary_deadline = try core.process.Deadline.afterMilliseconds(2000),
            .cleanup_deadline = try core.process.Deadline.afterMilliseconds(4000),
        }, peer.barrier());
        defer result.deinit(ctx.allocator);
        if (!result.succeeded() or !std.mem.eql(u8, result.result.stdout, "native-fixture\n"))
            return error.HelperTestCommandFailed;
        // A real benign supervised command is not genuine runtime evidence.
        return .{ .refused = .{ .cause = error.SourceOnlyWorkerFinished, .step = null, .completed_steps = 0 } };
    }
};
