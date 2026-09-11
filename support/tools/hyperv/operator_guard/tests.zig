const std = @import("std");
const guard = @import("operator_guard");
const r = guard.records;
const k = guard.kernel;
const f = @import("fixture.zig");
const t = std.testing;
const a = t.allocator;
const io = t.io;

const Fixture = struct {
    root: guard.core.private_files.Directory,
    directory: guard.core.private_files.Directory,
    work: guard.core.private_files.Directory,
    executable: i32,
    owner: i32,
    owner_fd: i32,
    expected: r.Expected,
    reaped: bool = false,
    custody_pid: ?i32 = null,
    custody_fd: ?i32 = null,

    fn init(mode: f.Mode) !Fixture {
        try guard.core.process.initialize();
        const root_path = @import("test_options").test_root orelse return error.TestRootRequired;
        const root = try guard.core.private_files.Directory.open(io, root_path);
        errdefer root.close(io);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(a, "guard-{x}", .{nonce});
        defer a.free(name);
        try root.dir.createDir(io, name, .fromMode(0o700));
        const container = try root.dir.openDir(io, name, .{ .follow_symlinks = false, .iterate = true });
        defer container.close(io);
        try container.createDir(io, "guard", .fromMode(0o700));
        try container.createDir(io, "work", .fromMode(0o700));
        const directory: guard.core.private_files.Directory = .{ .dir = try container.openDir(io, "guard", .{ .follow_symlinks = false, .iterate = true }) };
        errdefer directory.close(io);
        const work: guard.core.private_files.Directory = .{ .dir = try container.openDir(io, "work", .{ .follow_symlinks = false, .iterate = true }) };
        errdefer work.close(io);
        try work.dir.writeFile(io, .{ .sub_path = "mode", .data = @tagName(mode), .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        const path = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").fixture, a);
        defer a.free(path);
        const binary = try guard.core.private_files.openAbsolute(io, path, .artifact);
        errdefer binary.close(io);
        const identity = try guard.selfIdentity(io, binary.handle);
        const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(f.seed);
        const expected: r.Expected = .{
            .kind = .synthetic,
            .operation = .preflight,
            .attempt = "01234567-89ab-4cde-8fab-0123456789ab".*,
            .run = "10234567-89ab-4cde-8fab-0123456789ab".*,
            .context = r.hash(name),
            .implementation = identity.digest,
            .public_key = pair.public_key.toBytes(),
            .budget = f.budget,
        };
        if (mode == .recording) try directory.dir.writeFile(io, .{ .sub_path = "custody-seal.json", .data = "occupied\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        if (mode == .registration) try directory.dir.writeFile(io, .{ .sub_path = "custody-registration.json", .data = "occupied\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        try directory.dir.writeFile(io, .{ .sub_path = "fixture-mode", .data = @tagName(mode), .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        const bytes = try r.canonical(a, f.Request{ .mode = mode, .expected = expected });
        defer a.free(bytes);
        const request = try k.memfd(bytes);
        defer k.close(request);
        const log = try work.dir.createFile(io, "owner-error", .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer log.close(io);
        const owner = try k.spawn(binary.handle, "--fixture-owner", &.{ request, directory.dir.handle, work.dir.handle }, .{ log.handle, log.handle });
        return .{ .root = root, .directory = directory, .work = work, .executable = binary.handle, .owner = owner.pid, .owner_fd = owner.pidfd, .expected = expected };
    }
    fn deinit(self: *Fixture) void {
        if (!self.reaped) {
            k.kill(self.owner_fd) catch @panic("fixture owner kill");
            var status: u32 = 0;
            _ = k.linux.waitpid(self.owner, &status, 0);
        }
        k.close(self.owner_fd);
        if (self.custody_fd) |descriptor| {
            const end = k.now() catch @panic("fixture clock");
            while (true) {
                const result = k.reap(self.custody_pid.?) catch |err| switch (err) {
                    error.KernelCustodyUnavailable => break,
                    else => @panic("fixture custodian reap"),
                };
                if (result != null) break;
                if ((k.now() catch @panic("fixture clock")) - end > 3000 * std.time.ns_per_ms)
                    k.kill(descriptor) catch @panic("fixture custodian kill");
                if ((k.now() catch @panic("fixture clock")) - end > 5000 * std.time.ns_per_ms)
                    @panic("fixture custodian unreaped");
                k.pause();
            }
            k.close(descriptor);
        }
        k.close(self.executable);
        self.work.close(io);
        self.directory.close(io);
        self.root.close(io);
    }
    fn wait(self: *Fixture) !u32 {
        const limit = try guard.core.process.Deadline.afterMilliseconds(10000);
        while (!try limit.expired()) {
            if (try k.reap(self.owner)) |status| {
                self.reaped = true;
                return status;
            }
            k.pause();
        }
        return error.FixtureOwnerDeadline;
    }
    fn waitFile(self: *Fixture, directory: guard.core.private_files.Directory, name: []const u8) !void {
        errdefer self.reportOwnerFailure(name);
        const deadline = try guard.core.process.Deadline.afterMilliseconds(10000);
        while (!try deadline.expired()) {
            const file = directory.openFile(io, name) catch |err| switch (err) {
                error.FileNotFound => {
                    if (try k.readable(self.owner_fd)) return error.FixtureOwnerFailed;
                    k.pause();
                    continue;
                },
                else => return err,
            };
            file.close(io);
            return;
        }
        return error.FixtureHandshakeDeadline;
    }
    fn reportOwnerFailure(self: *Fixture, awaited: []const u8) void {
        const bytes = self.work.read(io, a, "owner-error", 4096, null) catch |err| {
            std.debug.print("Synthetic custody diagnostic unavailable while awaiting {s}: {s}\n", .{ awaited, @errorName(err) });
            return;
        };
        defer a.free(bytes);
        std.debug.print("Synthetic custody stderr while awaiting {s} ({d} bytes):\n{s}\n", .{ awaited, bytes.len, bytes });
    }
    fn registration(self: *Fixture) !r.Registration {
        try self.waitFile(self.directory, "custody-registration.json");
        const bytes = try self.directory.read(io, a, "custody-registration.json", r.max_record, null);
        defer a.free(bytes);
        const parsed = try r.verify(r.Registration, a, bytes, self.expected.public_key, "uk-operator-custody-registration-v1");
        defer parsed.deinit();
        var result = parsed.value;
        result.schema = "uk-operator-custody-registration-v1";
        self.custody_pid = result.custodian.pid;
        self.custody_fd = try k.pidfd(result.custodian.pid);
        return result;
    }
    fn release(self: *Fixture) !void {
        try self.work.dir.writeFile(io, .{ .sub_path = "release", .data = "release\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    }
};

test "kernel guard completes after namespace-wide reaping and refuses unbound production" {
    var fixture = try Fixture.init(.normal);
    defer fixture.deinit();
    const registration = try fixture.registration();
    try fixture.waitFile(fixture.work, "ready");
    const descendants = try Descendants.retain(registration.namespace_init.pid);
    defer descendants.close();
    try fixture.release();
    const status = try fixture.wait();
    try t.expect(k.linux.W.IFEXITED(status) and k.linux.W.EXITSTATUS(status) == 0);
    const proof = try guard.recovery.load(a, io, fixture.directory, fixture.expected);
    try t.expectEqual(r.Cause.completed, proof.cause);
    try requireCleanupOnly(proof);
    for ([_][]const u8{ "custody-claim.json", "custody-registration.json", "custody-seal.json" }) |name| {
        const bytes = try fixture.directory.read(io, a, name, r.max_record, null);
        defer a.free(bytes);
        try t.expect(bytes.len <= r.max_record);
    }
    const result = try ownerResult(&fixture);
    try t.expectEqual(guard.core.diagnostics.Failures{}, result.failures);
    try descendants.requireReaped();
    var wrong = fixture.expected;
    wrong.kind = .production;
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, wrong));
}

const Descendants = struct {
    fds: [2]i32,
    fn retain(init_pid: i32) !Descendants {
        const proc = try k.openProc();
        defer k.close(proc);
        var path: [96]u8 = undefined;
        var bytes: [4096]u8 = undefined;
        const data = try k.procRead(proc, try std.fmt.bufPrintZ(&path, "{d}/task/{d}/children", .{ init_pid, init_pid }), &bytes);
        var parts = std.mem.tokenizeAny(u8, data, " \n");
        var fds: [2]i32 = undefined;
        var count: usize = 0;
        errdefer for (fds[0..count]) |descriptor| k.close(descriptor);
        while (parts.next()) |part| {
            if (count >= 2) return error.UnexpectedFixtureDescendant;
            const pid = try std.fmt.parseInt(i32, part, 10);
            fds[count] = try k.pidfd(pid);
            count += 1;
        }
        if (count != 2) return error.MissingFixtureDescendant;
        return .{ .fds = fds };
    }
    fn close(self: Descendants) void {
        for (self.fds) |descriptor| k.close(descriptor);
    }
    fn requireReaped(self: Descendants) !void {
        const limit = try guard.core.process.Deadline.afterMilliseconds(3000);
        for (self.fds) |descriptor| {
            while (true) {
                var pollfds = [_]k.linux.pollfd{.{ .fd = descriptor, .events = k.linux.POLL.IN, .revents = 0 }};
                _ = try k.checked(k.linux.poll(&pollfds, 1, 0));
                if (pollfds[0].revents & k.linux.POLL.HUP != 0) break;
                if (try limit.expired()) return error.DescendantNotReaped;
                k.pause();
            }
        }
    }
};

fn requireCleanupOnly(proof: r.Proof) !void {
    try t.expectEqual(.cleanup_only, proof.scope);
    try t.expectEqual(r.Publication.unconfirmed, proof.publication);
    try t.expectEqual(guard.core.diagnostics.Category.ambiguous, proof.failures.recording.?.category);
    try t.expectEqual(guard.core.diagnostics.Category.ambiguous, proof.failures.cleanup.?.category);
}

fn ownerResult(fixture: *Fixture) !guard.WaitResult {
    const bytes = try fixture.work.read(io, a, "owner-result.json", r.max_record, null);
    defer a.free(bytes);
    const parsed = try r.parse(guard.WaitResult, a, bytes);
    defer parsed.deinit();
    return parsed.value;
}

test "owner SIGKILL recovers only through a sealed namespace witness and kills escaped sessions" {
    for ([_]bool{ false, true }) |stop_init| {
        var fixture = try Fixture.init(.normal);
        defer fixture.deinit();
        const registration = try fixture.registration();
        try fixture.waitFile(fixture.work, "ready");
        const descendants = try Descendants.retain(registration.namespace_init.pid);
        defer descendants.close();
        if (stop_init) {
            const init_fd = try k.pidfd(registration.namespace_init.pid);
            defer k.close(init_fd);
            _ = try k.checked(k.linux.pidfd_send_signal(init_fd, .STOP, null, 0));
        }
        try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
        try k.kill(fixture.owner_fd);
        const status = try fixture.wait();
        try t.expect(k.linux.W.IFSIGNALED(status));
        const proof = try guard.recovery.awaitStopped(a, io, fixture.directory, fixture.expected, try guard.core.process.Deadline.afterMilliseconds(5000));
        try t.expectEqual(r.Cause.owner_died, proof.cause);
        try t.expect(proof.failures.primary != null);
        try requireCleanupOnly(proof);
        try descendants.requireReaped();
    }
}

test "a paused custodian cannot keep namespace workers alive after original owner death" {
    var fixture = try Fixture.init(.normal);
    defer fixture.deinit();
    const registration = try fixture.registration();
    try fixture.waitFile(fixture.work, "ready");
    const descendants = try Descendants.retain(registration.namespace_init.pid);
    defer descendants.close();
    _ = try k.checked(k.linux.pidfd_send_signal(fixture.custody_fd.?, .STOP, null, 0));
    try k.kill(fixture.owner_fd);
    _ = try fixture.wait();
    try descendants.requireReaped();
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    _ = try k.checked(k.linux.pidfd_send_signal(fixture.custody_fd.?, .CONT, null, 0));
    const proof = try guard.recovery.awaitStopped(a, io, fixture.directory, fixture.expected, try guard.core.process.Deadline.afterMilliseconds(5000));
    try t.expectEqual(r.Cause.owner_died, proof.cause);
}

test "killing nested worker descendant or PID1 never leaves another writer" {
    for (0..3) |victim| {
        var fixture = try Fixture.init(.normal);
        defer fixture.deinit();
        const registration = try fixture.registration();
        try fixture.waitFile(fixture.work, "ready");
        const descendants = try Descendants.retain(registration.namespace_init.pid);
        defer descendants.close();
        if (victim < 2) {
            try k.kill(descendants.fds[victim]);
            if (victim == 1) try fixture.release();
        } else {
            const init_fd = try k.pidfd(registration.namespace_init.pid);
            defer k.close(init_fd);
            try k.kill(init_fd);
        }
        _ = try fixture.wait();
        const proof = try guard.recovery.load(a, io, fixture.directory, fixture.expected);
        try t.expectEqual(switch (victim) {
            0 => r.Cause.worker_failed,
            1 => .completed,
            else => .initializer_failed,
        }, proof.cause);
        try descendants.requireReaped();
    }
}

test "custodian loss still kills namespace but missing sealed witness remains ProcessRecoveryRequired" {
    var fixture = try Fixture.init(.normal);
    defer fixture.deinit();
    const registration = try fixture.registration();
    try fixture.waitFile(fixture.work, "ready");
    const descendants = try Descendants.retain(registration.namespace_init.pid);
    defer descendants.close();
    try k.kill(fixture.custody_fd.?);
    _ = try fixture.wait();
    try descendants.requireReaped();
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    const bytes = try fixture.work.read(io, a, "owner-result.json", r.max_record, null);
    defer a.free(bytes);
    const result = try r.parse(guard.WaitResult, a, bytes);
    defer result.deinit();
    try t.expect(result.value.failures.primary != null and result.value.failures.cleanup != null);
}

test "native custody deadlines and output bounds terminate actual workloads" {
    for ([_]f.Mode{ .deadline, .flood, .cancel }) |mode| {
        var fixture = try Fixture.init(mode);
        defer fixture.deinit();
        _ = try fixture.wait();
        const proof = try guard.recovery.load(a, io, fixture.directory, fixture.expected);
        try t.expectEqual(switch (mode) {
            .deadline => r.Cause.deadline,
            .cancel => .cancelled,
            else => .output_limit,
        }, proof.cause);
        try t.expect(proof.failures.primary != null);
        const bytes = try fixture.work.read(io, a, "owner-result.json", r.max_record, null);
        defer a.free(bytes);
        const result = try r.parse(guard.WaitResult, a, bytes);
        defer result.deinit();
        try t.expectEqual(proof.failures.primary, result.value.failures.primary);
        try t.expect(result.value.failures.cleanup == null and result.value.failures.recording == null);
        try requireCleanupOnly(proof);
    }
}

test "queued cancellation stops PID1 before the durable registration worker gate opens" {
    var fixture = try Fixture.init(.pre_dispatch_cancel);
    defer fixture.deinit();
    _ = try fixture.wait();
    const observed = try fixture.work.openFile(io, "pre-dispatch-observed");
    observed.close(io);
    const proof = try guard.recovery.load(a, io, fixture.directory, fixture.expected);
    try t.expectEqual(r.Cause.cancelled, proof.cause);
    try requireCleanupOnly(proof);
    try t.expectError(error.FileNotFound, fixture.work.openFile(io, "entered"));
    try t.expectError(error.FileNotFound, fixture.work.openFile(io, "ready"));
    const result = try ownerResult(&fixture);
    try t.expectEqual(guard.core.diagnostics.Category.cancelled, result.failures.primary.?.category);
    try t.expect(result.failures.cleanup == null and result.failures.recording == null);
}

test "latched cancellation survives paused PID1 and bounds shutdown with both observers paused" {
    for ([_]bool{ true, false }) |resume_custodian| {
        var fixture = try Fixture.init(.cancel_observed);
        defer fixture.deinit();
        const registration = try fixture.registration();
        try fixture.waitFile(fixture.work, "ready");
        const descendants = try Descendants.retain(registration.namespace_init.pid);
        defer descendants.close();
        const init_fd = try k.pidfd(registration.namespace_init.pid);
        defer k.close(init_fd);
        _ = try k.checked(k.linux.pidfd_send_signal(fixture.custody_fd.?, .STOP, null, 0));
        const started = try k.now();
        try fixture.work.dir.writeFile(io, .{ .sub_path = "request-cancel", .data = "cancel\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        // The synthetic I/O adapter blocks precisely after PID1 observed the
        // cancellation, before it reports/exits. The custodian cannot observe
        // that event until the test explicitly resumes it.
        try fixture.waitFile(fixture.work, "cancel-observed");
        _ = try k.checked(k.linux.pidfd_send_signal(init_fd, .STOP, null, 0));
        if (resume_custodian)
            _ = try k.checked(k.linux.pidfd_send_signal(fixture.custody_fd.?, .CONT, null, 0));
        _ = try fixture.wait();
        try t.expect(try k.now() - started < 5000 * std.time.ns_per_ms);
        try descendants.requireReaped();
        const result = try ownerResult(&fixture);
        try t.expectEqual(guard.core.diagnostics.Category.cancelled, result.failures.primary.?.category);
        if (resume_custodian) {
            const proof = try guard.recovery.load(a, io, fixture.directory, fixture.expected);
            try t.expectEqual(r.Cause.cancelled, proof.cause);
            try requireCleanupOnly(proof);
            try t.expect(result.failures.cleanup == null and result.failures.recording == null);
        } else {
            try t.expect(result.failures.cleanup != null and result.failures.recording != null);
            try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
            // With both original observers lost, the test subreaper owns PID1.
            // This fixture cleanup does not create a production custody witness.
            const deadline = try guard.core.process.Deadline.afterMilliseconds(3000);
            while (try k.reap(registration.namespace_init.pid) == null) {
                if (try deadline.expired()) return error.FixtureInitNotReaped;
                k.pause();
            }
        }
    }
}

test "visible seal fsync failure retains publication uncertainty with and without owner feedback" {
    for ([_]bool{ false, true }) |lose_owner| {
        var fixture = try Fixture.init(if (lose_owner) .seal_sync_owner_loss else .seal_sync_failure);
        defer fixture.deinit();
        const registration = try fixture.registration();
        try fixture.waitFile(fixture.work, "ready");
        const descendants = try Descendants.retain(registration.namespace_init.pid);
        defer descendants.close();
        try k.kill(descendants.fds[0]);
        _ = try fixture.wait();
        const proof = try guard.recovery.awaitStopped(a, io, fixture.directory, fixture.expected, try guard.core.process.Deadline.afterMilliseconds(5000));
        try descendants.requireReaped();
        try t.expectEqual(r.Cause.worker_failed, proof.cause);
        try t.expectEqual(guard.core.diagnostics.Category.child_failed, proof.failures.primary.?.category);
        try requireCleanupOnly(proof);
        if (lose_owner) {
            try t.expectError(error.FileNotFound, fixture.work.openFile(io, "owner-result.json"));
        } else {
            const result = try ownerResult(&fixture);
            try t.expectEqual(guard.core.diagnostics.Category.child_failed, result.failures.primary.?.category);
            try t.expectEqual(guard.core.diagnostics.Category.local_io, result.failures.recording.?.category);
            try t.expect(result.failures.cleanup != null);
        }
    }
}

test "interruption after seal visibility cannot certify final fsync even after owner loss" {
    for ([_]bool{ false, true }) |lose_owner| {
        var fixture = try Fixture.init(.seal_interrupted);
        defer fixture.deinit();
        const registration = try fixture.registration();
        try fixture.waitFile(fixture.work, "ready");
        const descendants = try Descendants.retain(registration.namespace_init.pid);
        defer descendants.close();
        try fixture.release();
        try fixture.waitFile(fixture.work, "seal-visible");
        try descendants.requireReaped();
        try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
        if (lose_owner) try k.kill(fixture.owner_fd);
        try k.kill(fixture.custody_fd.?);
        _ = try fixture.wait();
        const proof = try guard.recovery.awaitStopped(a, io, fixture.directory, fixture.expected, try guard.core.process.Deadline.afterMilliseconds(5000));
        try t.expectEqual(r.Cause.completed, proof.cause);
        try requireCleanupOnly(proof);
        if (lose_owner) {
            try t.expectError(error.FileNotFound, fixture.work.openFile(io, "owner-result.json"));
        } else {
            const result = try ownerResult(&fixture);
            try t.expect(result.failures.primary != null and result.failures.cleanup != null and result.failures.recording != null);
        }
    }
}

test "publication uncertainty never overwrites any prior failure lane" {
    const prior: guard.core.diagnostics.Failures = .{
        .primary = .{ .stage = .process_run, .category = .child_failed },
        .cleanup = .{ .stage = .state_record, .category = .cleanup_failed },
        .recording = .{ .stage = .state_record, .category = .local_io },
    };
    try t.expectEqual(prior, try r.publicationFailures(prior));
}

test "crash before handoff has no witness and cannot authorize recovery by PID absence" {
    var fixture = try Fixture.init(.before);
    defer fixture.deinit();
    try fixture.waitFile(fixture.work, "before");
    try k.kill(fixture.owner_fd);
    _ = try fixture.wait();
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    try t.expectEqual(guard.recovery.Inspection{ .reason = .pending, .failures = .{ .cleanup = .{ .stage = .process_cleanup, .category = .ambiguous } } }, guard.recovery.inspect(a, io, fixture.directory, fixture.expected));
}

test "recording failure retains prior worker failure and independent cleanup obligations" {
    var fixture = try Fixture.init(.recording);
    defer fixture.deinit();
    const registration = try fixture.registration();
    try fixture.waitFile(fixture.work, "ready");
    const descendants = try Descendants.retain(registration.namespace_init.pid);
    defer descendants.close();
    try k.kill(descendants.fds[0]);
    _ = try fixture.wait();
    try descendants.requireReaped();
    const bytes = try fixture.work.read(io, a, "owner-result.json", r.max_record, null);
    defer a.free(bytes);
    const result = try r.parse(guard.WaitResult, a, bytes);
    defer result.deinit();
    try t.expectEqual(guard.core.diagnostics.Category.child_failed, result.value.failures.primary.?.category);
    try t.expectEqual(guard.core.diagnostics.Category.local_io, result.value.failures.recording.?.category);
    try t.expect(result.value.failures.cleanup != null);
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
}

test "guard control reservation includes executable records and output at exact policy boundary" {
    try t.expectEqual(@as(u64, 8388608), try guard.requiredControl(8388608 - r.overhead));
    try f.budget.admit(8388608 - r.overhead, 8388608);
    try t.expectError(error.ControlReservationExceeded, f.budget.admit(8388608 - r.overhead + 1, 8388608));
    try t.expectError(error.ControlReservationExceeded, f.budget.admit(8388608 - r.overhead + 1, 8388609));
    try f.budget.admit(4 * 1024 * 1024, try guard.requiredControl(4 * 1024 * 1024));
    try t.expectError(error.ControlReservationExceeded, guard.requiredControl(std.math.maxInt(u64)));
    try t.expectEqual(@as(u64, 268435456), f.budget.staging);
    try t.expectEqual(@as(usize, 233504), r.overhead);
    try t.expectEqual(@as(usize, 16 * 1024), r.max_record);
    try t.expectEqual(@as(usize, 64 * 1024), r.output_limit);
    try t.expectEqual(@as(usize, 4096), r.feedback_limit);
}

test "explicit component budget enforces both remaining ledger allowances and all copies" {
    const available: r.Budget = .{ .control = 500001, .staging = 500000 };
    try available.admit(500000 - r.overhead, 500000);
    try t.expectError(error.ControlReservationExceeded, available.admit(500001 - r.overhead, 500001));
    const control_limited: r.Budget = .{ .control = 499999, .staging = 500000 };
    try t.expectError(error.ControlReservationExceeded, control_limited.admit(500000 - r.overhead, 500000));
    try t.expectError(error.ControlReservationExceeded, available.admit(0, r.overhead - 1));
    try t.expectError(error.InvalidBudget, (r.Budget{ .control = 0, .staging = 500000 }).reserve(r.overhead));
    try t.expectError(error.InvalidBudget, (r.Budget{ .control = 500000, .staging = 0 }).reserve(r.overhead));
}

test "signed custody binds the explicit budget without a missing-field default" {
    var fixture = try Fixture.init(.normal);
    defer fixture.deinit();
    _ = try fixture.registration();
    try fixture.waitFile(fixture.work, "ready");
    try fixture.release();
    _ = try fixture.wait();
    const proof = try guard.recovery.load(a, io, fixture.directory, fixture.expected);
    try t.expectEqual(f.budget, proof.expected.budget);
    var changed = fixture.expected;
    changed.budget.control -= 1;
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, changed));
    changed = fixture.expected;
    changed.budget.staging -= 1;
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, changed));
    const bytes = try r.canonical(a, fixture.expected);
    defer a.free(bytes);
    var document = try guard.core.contracts.Document.parse(a, bytes, .{});
    defer document.deinit();
    try t.expect(document.parsed.value.object.swapRemove("budget"));
    const missing = try document.canonicalAlloc(a);
    defer a.free(missing);
    try t.expectError(error.MissingField, r.parse(r.Expected, a, missing));
}

test "registration publication failure cannot release the worker gate" {
    var fixture = try Fixture.init(.registration);
    defer fixture.deinit();
    _ = try fixture.wait();
    try t.expectError(error.FileNotFound, fixture.work.openFile(io, "ready"));
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    const bytes = try fixture.work.read(io, a, "owner-result.json", r.max_record, null);
    defer a.free(bytes);
    const result = try r.parse(guard.WaitResult, a, bytes);
    defer result.deinit();
    try t.expect(result.value.failures.recording != null and result.value.failures.cleanup != null);
}

test "owner death after durable registration seals stopped custody without dispatching a worker" {
    var fixture = try Fixture.init(.after_registration);
    defer fixture.deinit();
    _ = try fixture.registration();
    _ = try fixture.wait();
    const proof = try guard.recovery.awaitStopped(a, io, fixture.directory, fixture.expected, try guard.core.process.Deadline.afterMilliseconds(5000));
    try t.expectEqual(r.Cause.owner_died, proof.cause);
    try t.expect(proof.failures.primary != null);
    try requireCleanupOnly(proof);
    try t.expectError(error.FileNotFound, fixture.work.openFile(io, "ready"));
}

test "recovery rejects cross boot stale reused live writer missing claim and tampered signed records" {
    var fixture = try Fixture.init(.normal);
    defer fixture.deinit();
    const original_registration = try fixture.registration();
    try fixture.waitFile(fixture.work, "ready");
    try fixture.release();
    _ = try fixture.wait();
    const registration_bytes = try fixture.directory.read(io, a, "custody-registration.json", r.max_record, null);
    defer a.free(registration_bytes);
    const seal_bytes = try fixture.directory.read(io, a, "custody-seal.json", r.max_record, null);
    defer a.free(seal_bytes);
    const original_seal = try r.verify(r.Seal, a, seal_bytes, fixture.expected.public_key, r.seal_schema);
    defer original_seal.deinit();
    var signer = try guard.Signer.fromSeed(f.seed, fixture.expected.public_key);
    defer signer.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    try r.durable(try lock.createImmutable(io, "fixture-original-registration.json", registration_bytes));
    try r.durable(try lock.createImmutable(io, "fixture-original-seal.json", seal_bytes));
    const proc = try k.openProc();
    defer k.close(proc);
    const current = try k.identity(proc, k.linux.getpid());
    for (0..4) |case| {
        var changed = original_registration;
        switch (case) {
            0 => changed.boot = "20234567-89ab-4cde-8fab-0123456789ab".*,
            1 => {
                changed.custodian = current;
                changed.custodian.start_ticks += 1;
            },
            2 => changed.custodian = current,
            else => changed.namespace_init.namespace = changed.custodian.namespace,
        }
        const signed = try signer.sign(a, changed, "uk-operator-custody-registration-v1");
        defer a.free(signed);
        var seal = original_seal.value;
        seal.registration = r.hash(signed);
        const sealed = try signer.sign(a, seal, r.seal_schema);
        defer a.free(sealed);
        try r.durable(try lock.commit(io, "custody-registration.json", signed));
        try r.durable(try lock.commit(io, "custody-seal.json", sealed));
        try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    }
    try r.durable(try lock.commit(io, "custody-registration.json", registration_bytes));
    try r.durable(try lock.commit(io, "custody-seal.json", seal_bytes));
    var document = try guard.core.contracts.Document.parse(a, seal_bytes, .{ .bytes = r.max_record, .items = 1024 });
    defer document.deinit();
    const body = document.parsed.value.object.getPtr("body").?;
    try t.expect(body.object.swapRemove("witness"));
    const missing = try document.canonicalAlloc(a);
    defer a.free(missing);
    try r.durable(try lock.commit(io, "custody-seal.json", missing));
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    try r.durable(try lock.commit(io, "custody-seal.json", seal_bytes));
    var publication_document = try guard.core.contracts.Document.parse(a, seal_bytes, .{ .bytes = r.max_record, .items = 1024 });
    defer publication_document.deinit();
    const publication_body = publication_document.parsed.value.object.getPtr("body").?;
    publication_body.object.getPtr("publication").?.* = .{ .string = "confirmed" };
    const invented_publication = try signer.sign(a, publication_body.*, r.seal_schema);
    defer a.free(invented_publication);
    try r.durable(try lock.commit(io, "custody-seal.json", invented_publication));
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    try t.expect(publication_body.object.swapRemove("publication"));
    const missing_publication = try signer.sign(a, publication_body.*, r.seal_schema);
    defer a.free(missing_publication);
    try r.durable(try lock.commit(io, "custody-seal.json", missing_publication));
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    var legacy_seal = original_seal.value;
    legacy_seal.schema = "uk-operator-custody-seal-v1";
    const legacy = try signer.sign(a, legacy_seal, "uk-operator-custody-seal-v1");
    defer a.free(legacy);
    try r.durable(try lock.commit(io, "custody-seal.json", legacy));
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    try r.durable(try lock.commit(io, "custody-seal.json", seal_bytes));
    try fixture.directory.dir.rename("custody-claim.json", fixture.directory.dir, "fixture-saved-claim.json", io);
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
    try fixture.directory.dir.rename("custody-registration.json", fixture.directory.dir, "fixture-saved-registration.json", io);
    try t.expectError(error.ProcessRecoveryRequired, guard.recovery.load(a, io, fixture.directory, fixture.expected));
}
