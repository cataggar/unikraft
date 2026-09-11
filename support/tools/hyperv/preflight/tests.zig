const std = @import("std");
const pf = @import("preflight");
const f = @import("fixture_support.zig");
const c = pf.contract;
const p = c.p;
const t = std.testing;
const a = t.allocator;
const io = t.io;

pub const Directory = struct {
    path: []u8,
    value: pf.core.private_files.Directory,
    pub fn create(name: []const u8) !Directory {
        const root_path = @import("test_options").test_root orelse return error.TestRootRequired;
        const root = try pf.core.private_files.Directory.open(io, root_path);
        defer root.close(io);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const basename = try std.fmt.allocPrint(a, "{s}-{s}", .{ name, p.hex(nonce) });
        defer a.free(basename);
        try root.dir.createDir(io, basename, .fromMode(0o700));
        const path = try std.fs.path.join(a, &.{ root_path, basename });
        errdefer a.free(path);
        return .{ .path = path, .value = try pf.core.private_files.Directory.open(io, path) };
    }
    pub fn deinit(self: Directory) void {
        self.value.close(io);
        a.free(self.path);
    }
};
pub fn prepare(fixture: *f.Context) !void {
    const result = try pf.worker.execute(.synthetic, a, io, .prepare, fixture.directory, try fixture.resolved(), null);
    try t.expectEqual(c.Phase.prepared, result.phase);
}
fn run(fixture: *f.Context) !pf.worker.Report {
    for (0..c.action_count + 3) |_| {
        const result = try pf.worker.execute(.synthetic, a, io, .step, fixture.directory, try fixture.resolved(), null);
        if (!result.more) return result;
    }
    return error.FixtureDidNotFinish;
}

pub fn until(fixture: *f.Context, action: c.Action) !void {
    for (0..@intFromEnum(action) + 1) |_| {
        const result = try pf.worker.execute(.synthetic, a, io, .step, fixture.directory, try fixture.resolved(), null);
        try t.expect(result.failures.primary == null and result.failures.cleanup == null and result.failures.recording == null);
    }
}
pub fn state(fixture: *f.Context) !pf.journal.State {
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    return (try pf.journal.Store.open(a, io, &lock, &fixture.input)).state;
}
test "strict preparation boundary budget partitions and all proof bindings" {
    const directory = try Directory.create("boundary");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    var admission = try fixture.input.validate(a, f.now);
    defer admission.deinit();
    const total = try (try fixture.input.approved.budget.floor()).add(fixture.input.approved.budget.host_runtime);
    try t.expect(total.control < p.max_control and total.staged < p.max_staging);
    const before = fixture.input.approved.proofs.native_provider;
    fixture.input.approved.proofs.native_provider = [_]u8{0} ** 32;
    try t.expectError(error.MissingBinding, fixture.input.validate(a, f.now));
    fixture.input.approved.proofs.native_provider = before;
    fixture.input.approved.budget.controller.staged += 1;
    try t.expectError(error.InvalidBudgetPartition, fixture.input.validate(a, f.now));
    try t.expectError(error.BudgetExceeded, (c.Debit{ .staged = p.max_staging, .control = p.max_control }).add(.{ .staged = 1, .control = 1 }));
    try t.expectError(error.InvalidBudget, (c.Debit{ .staged = 1, .control = 2 }).validate());
}

test "synthetic lifecycle signs exact public acceptance then private phases and cleans" {
    const directory = try Directory.create("lifecycle");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try fixture.refreshAdmission(f.now - 50);
    try prepare(&fixture);
    const result = try run(&fixture);
    try t.expectEqual(c.Phase.synthetic_completed, result.phase);
    try t.expectEqual(@as(usize, 1), fixture.private_transfers);
    for (fixture.calls, 0..) |count, index| {
        if (index != @intFromEnum(c.Action.accept_public)) try t.expectEqual(@as(u8, 1), count);
    }
    try t.expectError(error.SyntheticEvidence, pf.completed.load(a, io, directory.value, &fixture.input));
    fixture.input.kind = .production;
    try t.expectError(error.NativeBindingMismatch, pf.completed.load(a, io, directory.value, &fixture.input));
    fixture.input.kind = .synthetic;
    const completion = try directory.value.read(io, a, "completion.json", p.max_command, null);
    defer a.free(completion);
    var signed = try p.verify(a, completion, fixture.input.approved.public_key, "uk-hyperv-preflight-completion-v1");
    defer signed.deinit();
    var document = try pf.core.contracts.Document.parse(a, signed.canonical, .{});
    defer document.deinit();
    try t.expectEqual(f.now, try pf.core.contracts.integer(u64, document.value().object.get("admitted_at").?));
    try t.expectError(error.AttemptConsumed, prepare(&fixture));
}

test "public evidence failure and publication ambiguity prevent every private transfer" {
    for ([_]bool{ false, true }) |publication| {
        const directory = try Directory.create("public-failure");
        defer directory.deinit();
        var fixture = try f.Context.init(a, io, directory.value, directory.path);
        defer fixture.deinit();
        if (publication) fixture.fail_action = .publish_public else fixture.malformed_public = true;
        try prepare(&fixture);
        const result = try run(&fixture);
        try t.expectEqual(c.Phase.cleaned, result.phase);
        try t.expect(result.failures.primary != null);
        try t.expectEqual(@as(usize, 0), fixture.private_transfers);
        try t.expectEqual(@as(u8, 0), fixture.calls[@intFromEnum(c.Action.publish_private)]);
        try t.expectEqual(@as(u8, 1), fixture.calls[@intFromEnum(c.Action.prove_group_absent)]);
    }
}

test "consumed mutation intent survives restart without replay or rearming" {
    const directory = try Directory.create("interruption");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    _ = try pf.worker.execute(.synthetic, a, io, .step, directory.value, try fixture.resolved(), null);
    {
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
        try store.begin(.create_group, 4096, true);
    }
    {
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
        try t.expectEqual(c.Phase.cleaning, store.state.phase);
        try t.expectEqual(pf.journal.Status.unknown, store.state.actions[@intFromEnum(c.Action.create_group)].status);
        try t.expectError(error.AttemptConsumed, store.begin(.create_group, 4096, true));
        try t.expectError(error.PrematurePrivateTransfer, pf.engine.requirePublic(store.state));
    }
    try t.expectEqual(@as(u8, 0), fixture.calls[@intFromEnum(c.Action.create_group)]);
}

test "primary cleanup and recording outcomes remain separate" {
    const directory = try Directory.create("failures");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    fixture.fail_action = .create_group;
    try prepare(&fixture);
    _ = try run(&fixture);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    store.fail(.primary, .{ .stage = .arm, .category = .authorization });
    store.fail(.cleanup, .{ .stage = .cleanup, .category = .authentication });
    store.fail(.recording, .{ .stage = .state_record, .category = .local_io });
    try store.save();
    const loaded = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try t.expectEqual(pf.core.diagnostics.Category.transport, loaded.state.failures.primary.?.category);
    try t.expect(loaded.state.failures.cleanup != null and loaded.state.failures.recording != null);
}

test "completed loader rejects prepared standalone and substituted native bindings" {
    const directory = try Directory.create("loader");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    fixture.input.kind = .production;
    {
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        _ = try pf.journal.Store.prepare(a, io, &lock, &fixture.input, f.now);
    }
    try t.expectError(error.NotCompleted, pf.completed.load(a, io, directory.value, &fixture.input));
    fixture.input.preparation.binding.implementation[0] ^= 1;
    try t.expectError(error.NativeBindingMismatch, pf.completed.load(a, io, directory.value, &fixture.input));
    const standalone = try Directory.create("standalone");
    defer standalone.deinit();
    const file = try standalone.value.dir.createFile(io, "completion.json", .{ .permissions = .fromMode(0o600) });
    try file.writeStreamingAll(io, "{}\n");
    file.close(io);
    try t.expectError(error.FileNotFound, pf.completed.load(a, io, standalone.value, &fixture.input));
}

test "native supervised operation workers execute complete synthetic lifecycle" {
    const directory = try Directory.create("supervised");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    const child = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").child, a);
    defer a.free(child);
    const result = try pf.supervisor.run(a, io, .{
        .executable = child,
        .directory = directory.value,
        .attempt_deadline = try pf.core.process.Deadline.afterMilliseconds(60000),
        .cleanup_deadline = try pf.core.process.Deadline.afterMilliseconds(90000),
        .kind = .synthetic,
        .operation_ms = 5000,
        .child_cleanup_ms = 1000,
    }, false);
    try t.expect(result.process_cleanup_complete);
    try t.expect(result.last != null);
    try t.expectEqual(c.Phase.synthetic_completed, result.last.?.phase);
    try t.expect(result.failures.primary == null and result.failures.cleanup == null and result.failures.recording == null);
}

test "hard deadline terminates operation before cleanup writer takes ownership" {
    const directory = try Directory.create("deadline");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    const fault = try directory.value.dir.createFile(io, "fixture-fault", .{ .permissions = .fromMode(0o600) });
    try fault.writeStreamingAll(io, "deadline");
    fault.close(io);
    const child = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").child, a);
    defer a.free(child);
    const result = try pf.supervisor.run(a, io, .{
        .executable = child,
        .directory = directory.value,
        .attempt_deadline = try pf.core.process.Deadline.afterMilliseconds(5000),
        .cleanup_deadline = try pf.core.process.Deadline.afterMilliseconds(10000),
        .kind = .synthetic,
        .operation_ms = 1000,
        .child_cleanup_ms = 1000,
    }, false);
    try t.expect(result.process_cleanup_complete);
    try t.expectEqual(pf.core.diagnostics.Category.timeout, result.failures.primary.?.category);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    const store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try t.expectEqual(pf.journal.Status.unknown, store.state.actions[@intFromEnum(c.Action.create_group)].status);
    try t.expect(store.state.private == null);
}

test "production CLI refuses unbound execution instead of accepting fixture argv" {
    const directory = try Directory.create("closed-cli");
    defer directory.deinit();
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").cli, a);
    defer a.free(cli);
    try pf.core.process.initialize();
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    var result = try pf.core.process.run(a, io, .{
        .argv = &.{ cli, "--worker-step", "synthetic" },
        .environment = &environment,
        .cwd = directory.value.dir,
        .deadline = try pf.core.process.Deadline.afterMilliseconds(5000),
        .stdout_limit = 0,
        .stderr_limit = 1024,
        .cleanup_ms = 1000,
    });
    defer result.deinit(a);
    try t.expect(result.cleanup_complete);
    try t.expectEqual(@as(u8, 2), result.termination.?.exited);
    try t.expectError(error.FileNotFound, directory.value.openFile(io, "attempt-consumed.json"));
}

test "local canonical schemas reject Boolean integers duplicates and unknown fields" {
    const Record = struct { counter: u64 };
    try t.expectError(error.UnexpectedToken, c.parse(Record, a, "{\"counter\":true}\n"));
    try t.expectError(error.DuplicateField, c.parse(Record, a, "{\"counter\":1,\"counter\":2}\n"));
    try t.expectError(error.UnknownField, c.parse(Record, a, "{\"counter\":1,\"extra\":2}\n"));
    try t.expectError(error.MissingField, c.parse(struct { schema: []const u8 = "native", counter: u64 = 0 }, a, "{\"counter\":0}\n"));
}

test "complete disjoint control and staging totals accept exact limits but reject one byte" {
    const exact = try (c.Debit{ .staged = p.max_staging - 1, .control = p.max_control - 1 }).add(.{ .staged = 1, .control = 1 });
    try t.expectEqual(@as(u64, 268435456), exact.staged);
    try t.expectEqual(@as(u64, 8388608), exact.control);
    try t.expectError(error.BudgetExceeded, exact.add(.{ .staged = 1, .control = 0 }));
    try t.expectError(error.BudgetExceeded, (c.Debit{ .staged = p.max_control, .control = p.max_control }).add(.{ .staged = 1, .control = 1 }));
    const expanded = try (c.Debit{ .staged = 2097152, .control = 2097152 }).add(.{ .staged = 1, .control = 1 });
    try t.expectEqual(@as(u64, 2097153), expanded.control);
    try t.expectEqual(@as(usize, 245760), c.worker_output_reservation);
}

test "claim consumed before mutable publication permits only cleanup recovery" {
    const directory = try Directory.create("claim-interrupt");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    store.state.phase = .running;
    store.state.owner_pid = std.os.linux.getppid();
    store.state.operator_boot_id = f.boot;
    store.state.started_at = f.now;
    store.state.deadline_ns = (try pf.core.process.Deadline.afterMilliseconds(5000)).expires_ns;
    try store.consume();
    const recovered = try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input);
    try t.expectEqual(c.Phase.cleaning, recovered.state.phase);
    try t.expect(recovered.state.failures.primary != null);
    try t.expect(recovered.state.spent.control >= store.state.spent.control);
    try t.expectEqual(c.Action.deallocate, pf.engine.next(recovered.state).?);
    try t.expectError(error.AttemptConsumed, store.consume());
}

test "cleanup planning preserves expired and restart wall ceilings before effects" {
    const directory = try Directory.create("cleanup-clock");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    try until(&fixture, .metadata);
    var resolved = try fixture.resolved();
    {
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
        store.state.phase = .cleaning;
        store.state.cleanup_until = f.now + 5;
        store.state.cleanup_deadline_ns = resolved.monotonic_ns + 5 * @as(u64, std.time.ns_per_s);
        try store.save();
    }
    resolved.now = f.now + 4;
    resolved.operator_boot_id[0] = 'a';
    const planned = try pf.worker.execute(.synthetic, a, io, .plan_cleanup, directory.value, resolved, null);
    try t.expect(planned.deadline_ns.? <= resolved.monotonic_ns + std.time.ns_per_s);
    resolved.now = f.now + 6;
    const expired = try pf.worker.execute(.synthetic, a, io, .plan_cleanup, directory.value, resolved, null);
    try t.expectEqual(resolved.monotonic_ns, expired.deadline_ns.?);
    try t.expectEqual(@as(u8, 0), fixture.calls[@intFromEnum(c.Action.deallocate)]);
}

test "independent native supervisor handles recording poison descendants and output overflow" {
    for ([_][]const u8{ "recording", "orphan", "flood" }) |fault_name| {
        const directory = try Directory.create(fault_name);
        defer directory.deinit();
        var fixture = try f.Context.init(a, io, directory.value, directory.path);
        defer fixture.deinit();
        try prepare(&fixture);
        try directory.value.dir.writeFile(io, .{ .sub_path = "fixture-fault", .data = fault_name, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        const child = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").child, a);
        defer a.free(child);
        const result = try pf.supervisor.run(a, io, .{
            .executable = child,
            .directory = directory.value,
            .attempt_deadline = try pf.core.process.Deadline.afterMilliseconds(30000),
            .cleanup_deadline = try pf.core.process.Deadline.afterMilliseconds(60000),
            .kind = .synthetic,
            .operation_ms = 3000,
            .child_cleanup_ms = 1000,
        }, false);
        try t.expect(result.process_cleanup_complete);
        if (std.mem.eql(u8, fault_name, "recording")) {
            try t.expect(result.failures.recording != null);
            try t.expectError(error.FileNotFound, directory.value.openFile(io, "synthetic-group"));
        } else {
            try t.expectEqual(if (std.mem.eql(u8, fault_name, "orphan")) pf.core.diagnostics.Category.timeout else .output_limit, result.failures.primary.?.category);
        }
        if (std.mem.eql(u8, fault_name, "orphan")) {
            const raw = try directory.value.read(io, a, "synthetic-descendant.pid", 32, null);
            defer a.free(raw);
            const pid = try std.fmt.parseInt(u32, raw, 10);
            try t.expectEqual(std.os.linux.E.SRCH, std.os.linux.errno(std.os.linux.syscall2(.kill, pid, 0)));
        }
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        const recovered = try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input);
        try t.expect(recovered.state.private == null and recovered.state.phase != .completed);
        try t.expect(recovered.state.actions[@intFromEnum(c.Action.prove_group_absent)].status == .complete);
    }
}

test "host receipt rejects wrong bindings counts duplicate launches serial and architecture labels" {
    const directory = try Directory.create("evidence-negatives");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    try until(&fixture, .publish_public);
    const saved = try state(&fixture);
    var admission = try fixture.input.validate(a, f.now);
    defer admission.deinit();
    const bytes = try directory.value.read(io, a, pf.engine.commandName(.public), p.max_command, null);
    defer a.free(bytes);
    var command = try p.Command.parse(a, bytes, fixture.input.approved.public_key, &admission, try fixture.input.scope(&admission), try pf.core.contracts.parseUuid(&f.vm), f.now);
    defer command.deinit();
    try t.expectError(error.NotAdmitted, p.Command.parse(a, bytes, fixture.input.approved.public_key, &admission, try fixture.input.scope(&admission), try pf.core.contracts.parseUuid(&f.vm), fixture.input.approved.expires_at));
    try t.expectError(error.ScopeMismatch, p.Command.parse(a, bytes, fixture.input.approved.public_key, &admission, try fixture.input.scope(&admission), try pf.core.contracts.parseUuid(&f.disk), f.now));
    const bundle = try fixture.bundle(.public, &saved);
    _ = try pf.evidence.verify(a, &fixture.input, &admission, &command, bundle, null);
    const Mutation = enum { vm, nonce, manifest, count, duplicate, skipped, serial, image, failure };
    inline for (std.meta.tags(Mutation)) |mutation| {
        var parsed = try std.json.parseFromSlice(std.json.Value, a, bundle.receipt, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const object = &parsed.value.object;
        const boots = &object.getPtr("boots").?.array;
        switch (mutation) {
            .vm => object.getPtr("vm_id").?.* = .{ .string = &f.disk },
            .nonce => object.getPtr("phase_nonce").?.* = .{ .string = &f.disk },
            .manifest => object.getPtr("manifest_sha256").?.* = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" },
            .count => boots.items.len = 1,
            .duplicate => boots.items[1].object.getPtr("launch_id").?.* = boots.items[0].object.get("launch_id").?,
            .skipped => object.getPtr("evidence_kind").?.* = .{ .string = "architecture_skip" },
            .serial => boots.items[0].object.getPtr("serial_bytes").?.* = .{ .integer = 0 },
            .image => boots.items[0].object.getPtr("image_sha256").?.* = boots.items[1].object.get("serial_sha256").?,
            .failure => boots.items[0].object.getPtr("passed").?.* = .{ .bool = false },
        }
        const malformed = try c.canonical(a, parsed.value);
        defer a.free(malformed);
        const expected: anyerror = switch (mutation) {
            .vm, .nonce, .manifest, .skipped => error.EvidenceMismatch,
            .count => error.WrongBootCount,
            .duplicate => error.DuplicateBoot,
            .image => error.ImageMismatch,
            .serial, .failure => error.InvalidBootEvidence,
        };
        try t.expectError(expected, pf.evidence.verify(a, &fixture.input, &admission, &command, .{ .receipt = malformed, .logs = bundle.logs }, null));
    }
}

test "production worker rejects synthetic kind and unadmitted self binary before effects" {
    const directory = try Directory.create("production-binding");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try t.expectError(error.EvidenceKindMismatch, pf.worker.execute(.production, a, io, .prepare, directory.value, try fixture.resolved(), null));
    fixture.input.kind = .production;
    if (pf.worker.execute(.production, a, io, .prepare, directory.value, try fixture.resolved(), null)) |_| {
        return error.SyntheticBinaryAdmitted;
    } else |err| try t.expect(err == error.NativeControlNotAdmitted or err == error.NativeBindingMismatch);
    try t.expectError(error.FileNotFound, directory.value.openFile(io, "attempt-consumed.json"));
    try t.expectError(error.SigningAuthorityMismatch, pf.commands.Signer.fromSeed([_]u8{0x11} ** 32, fixture.input.approved.public_key));
}

test "prepared context freezes complete artifacts not just caller supplied manifest hash" {
    const directory = try Directory.create("preparation-binding");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    const changed = try fixture.arena.allocator().dupe(c.File, fixture.input.preparation.files);
    changed[0].artifact.sha256[0] ^= 1;
    fixture.input.preparation.files = changed;
    try t.expectError(error.NativeBindingMismatch, state(&fixture));
    try t.expectError(error.FileNotFound, directory.value.openFile(io, "attempt-consumed.json"));
}

test "interrupted original VM reconciliation remains bound before mutable publication" {
    const directory = try Directory.create("vm-reconciliation");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try prepare(&fixture);
    try until(&fixture, .metadata);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    const bytes = try c.canonical(a, pf.journal.VmRecord{ .attempt = store.state.attempt, .vm_id = f.vm });
    defer a.free(bytes);
    try store.immutable("reconciled-vm.json", bytes, true);
    const recovered = try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input);
    try t.expectEqual(f.vm, recovered.state.vm_id.?);
    store.state.vm_id = f.disk;
    try store.save();
    try t.expectError(error.OriginalIdentityMismatch, pf.journal.Store.openRecovery(a, io, &lock, &fixture.input));
}

test {
    _ = @import("wire_fixtures.zig");
    _ = @import("adapter_fixtures.zig");
    _ = @import("review_fixtures.zig");
}
