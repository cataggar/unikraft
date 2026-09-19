//! Packaging only: use the existing miz/worker/proof machinery, not the
//! hardware application's return-2 preparation or its export contract.
const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const f = image.files;
const compute = image.compute_artifacts;

const Command = enum { package, inspect, finalize_qcow2, derive_fixed_vhd };
const Args = struct { command: Command, input: []const u8, state: []const u8 };

fn parse(args: []const []const u8) !Args {
    if (args.len != 4) return error.InvalidArguments;
    const command: Command = if (std.mem.eql(u8, args[1], "package"))
        .package
    else if (std.mem.eql(u8, args[1], "inspect"))
        .inspect
    else if (std.mem.eql(u8, args[1], "finalize-qcow2"))
        .finalize_qcow2
    else if (std.mem.eql(u8, args[1], "derive-fixed-vhd"))
        .derive_fixed_vhd
    else
        return error.InvalidArguments;
    try image.core.private_files.absoluteFilePath(args[2]);
    try image.core.private_files.absoluteFilePath(args[3]);
    return .{ .command = command, .input = args[2], .state = args[3] };
}

fn openEmptyState(io: std.Io, path: []const u8) !image.core.private_files.Directory {
    const root = try image.core.private_files.Directory.open(io, path);
    errdefer root.close(io);
    var entries = root.dir.iterate();
    if (try entries.next(io) != null) return error.StateAlreadyUsed;
    return root;
}

pub fn main(init: std.process.Init) void {
    execute(init) catch {
        // No paths, guest bytes, environment, or raw operating-system errors.
        std.Io.File.stderr().writeStreamingAll(init.io, "WAMR_CI_PACKAGE_FAILED\n") catch {};
        std.process.exit(1);
    };
}

fn execute(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--package-worker"))
        return image.worker.execute(init);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--qcow2-worker"))
        return image.worker.executeQcow2(init);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--vhd-worker"))
        return image.worker.executeVhd(init);
    const input = try parse(args);
    if (input.command == .finalize_qcow2 or input.command == .derive_fixed_vhd)
        return executeCompute(init, input, args[0]);
    const inherited_path = init.environ_map.get("WAMR_CI_EXECUTABLE_PATH");
    const inherited_executable = init.environ_map.get("WAMR_CI_RETAINED_EXECUTABLE");
    const retained_self = inherited_path != null and inherited_executable != null and
        std.mem.eql(u8, args[0], inherited_path.?);
    const self_path = if (retained_self)
        inherited_path.?
    else
        try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
    const self_executable = if (retained_self) inherited_executable.? else self_path;
    const efi = try f.record(a, io, input.input, c.max_efi, false);
    const producer = try f.record(a, io, self_path, c.max_tool, true);
    const root = if (input.command == .package)
        try openEmptyState(io, input.state)
    else
        try image.core.private_files.Directory.open(io, input.state);
    defer root.close(io);
    var lock = try root.lock(io);
    var release = true;
    defer if (release) lock.close(io);

    if (input.command == .package) {
        const job: image.worker.Job = .{
            .supervisor_pid = @intCast(std.os.linux.getpid()),
            .state_dir = input.state,
            .efi = efi,
            .producer = producer,
        };
        try f.immutable(a, io, &lock, "package-job.json", job);
        try image.core.process.initialize();
        var environment: std.process.Environ.Map = .init(a);
        defer environment.deinit();
        try environment.put("TMPDIR", input.state);
        try environment.put("WAMR_CI_EXECUTABLE_PATH", self_path);
        try environment.put(
            "WAMR_CI_RETAINED_EXECUTABLE",
            self_executable,
        );
        var result = try image.core.process.run(a, io, .{
            .argv = &.{ self_executable, "--package-worker" },
            .environment = &environment,
            .cwd = root.dir,
            .deadline = try image.core.process.Deadline.afterMilliseconds(c.package_timeout_ms),
            .cleanup_ms = image.boot.config.cleanup_ms,
            .stdout_limit = 0,
            .stderr_limit = 0,
        });
        defer result.deinit(a);
        release = result.cleanup_complete;
        try f.immutable(a, io, &lock, "supervision.json", .{
            .failures = result.failures,
            .cleanup_complete = result.cleanup_complete,
            .termination = result.termination,
        });
        if (!release or !image.engine.clean(result.failures) or result.termination == null or
            result.termination.? != .exited or result.termination.?.exited != 0)
            return error.PackageFailed;
    } else {
        const supervision = try root.read(io, a, "supervision.json", c.max_record, null);
        const Supervision = struct {
            failures: image.core.diagnostics.Failures,
            cleanup_complete: bool,
            termination: ?std.process.Child.Term,
        };
        try f.same(a, Supervision{
            .failures = image.core.diagnostics.Failures{},
            .cleanup_complete = true,
            .termination = @as(?std.process.Child.Term, .{ .exited = 0 }),
        }, try c.read(Supervision, a, supervision));
    }

    const job = try c.read(image.worker.Job, a, try root.read(io, a, "package-job.json", c.max_record, null));
    if (job.schema_version != 1 or job.supervisor_pid == 0 or !std.mem.eql(u8, input.state, job.state_dir))
        return error.InvalidJob;
    try f.same(a, efi, job.efi);
    try f.same(a, producer, job.producer);
    if ((try root.read(io, a, "package-launched", 1, null)).len != 0) return error.InvalidLaunch;
    const observed = try image.package.observe(a, io, root, efi);
    try f.same(a, observed, try c.read(image.package.Report, a, try root.read(io, a, "package-report.json", c.max_record, null)));
    const copied = try f.record(a, io, try f.path(a, input.state, "BOOTX64.EFI"), c.max_efi, false);
    if (copied.size != efi.size or !std.mem.eql(u8, copied.sha256, efi.sha256)) return error.WrongEfi;
    if (input.command == .package) try f.cleanupStage(io, root, "package-stage");
    const vhd = try root.openFile(io, "unikraft.vhd");
    defer vhd.close(io);
    const inspection = try image.package.inspectVhd(a, io, vhd, .{
        .efi = try c.sha(efi.sha256),
        .raw = try c.sha(observed.raw.sha256),
        .vhd = try c.sha(observed.vhd.sha256),
    });
    try f.verify(a, io, producer, c.max_tool, true);
    const bytes = try c.encode(a, .{
        .schema_version = @as(u8, 1),
        .scope = "public_local_compute_packaging_only",
        .acceptance = "not_established",
        .producer_sha256 = producer.sha256,
        .image = inspection,
    });
    try std.Io.File.stdout().writeStreamingAll(io, bytes);
}

test "only packaging and compute artifact operations with explicit paths" {
    const a = try parse(&.{ "tool", "package", "/efi", "/new-state" });
    try std.testing.expectEqual(Command.package, a.command);
    try std.testing.expectEqualStrings("/efi", a.input);
    try std.testing.expectEqual(Command.finalize_qcow2, (try parse(&.{ "tool", "finalize-qcow2", "/request", "/state" })).command);
    try std.testing.expectEqual(Command.derive_fixed_vhd, (try parse(&.{ "tool", "derive-fixed-vhd", "/request", "/state" })).command);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "tool", "prepare", "/efi", "/state" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "tool", "package", "/efi", "/state", "--skip" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "tool", "--package-worker" }));
    try std.testing.expectError(error.UnsafePath, parse(&.{ "tool", "inspect", "relative", "/state" }));
}

const ComputeSupervision = struct {
    failures: image.core.diagnostics.Failures,
    cleanup_complete: bool,
    termination: ?std.process.Child.Term,
    stage_cleanup_complete: bool,
    rollback_complete: bool,
    outcome: compute.Outcome,
};

fn executeCompute(init: std.process.Init, input: Args, argv0: []const u8) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const inherited_path = init.environ_map.get("WAMR_CI_EXECUTABLE_PATH");
    const inherited_executable = init.environ_map.get("WAMR_CI_RETAINED_EXECUTABLE");
    const retained_self = inherited_path != null and inherited_executable != null and
        std.mem.eql(u8, argv0, inherited_path.?);
    const self_path = if (retained_self)
        inherited_path.?
    else
        try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
    const self_executable = if (retained_self) inherited_executable.? else self_path;
    const producer = try f.record(a, io, self_path, c.max_tool, true);
    const request_file = try f.record(a, io, input.input, c.max_record, false);
    const request_bytes = try f.readArtifact(a, io, request_file, c.max_record);
    const config_sha256 = compute.configHash(request_bytes);
    const root = try image.core.private_files.Directory.open(io, input.state);
    defer root.close(io);
    var lock = try root.lock(io);
    var release = true;
    defer if (release) lock.close(io);

    if (input.command == .finalize_qcow2) {
        const intent = try compute.readFinalizeIntent(a, request_bytes);
        const source = try compute.bindExpected(
            a,
            io,
            intent.source_path,
            intent.expected_source_bytes,
            intent.expected_source_sha256,
            intent.limits.max_input_bytes,
        );
        const config_hex = try c.hex(a, config_sha256);
        var attempt = try compute.reserveAttempt(io, root, .qcow2);
        defer attempt.close(io);
        const job: image.worker.Qcow2Job = .{
            .supervisor_pid = @intCast(std.os.linux.getpid()),
            .state_dir = input.state,
            .attempt = attempt.evidence,
            .source = source,
            .producer = producer,
            .expected_virtual_bytes = intent.expected_virtual_bytes,
            .expected_workload_sha256 = intent.expected_workload_sha256,
            .expected_workload_bytes = intent.expected_workload_bytes,
            .limits = intent.limits,
            .config_sha256 = config_hex,
        };
        f.immutable(a, io, &lock, "qcow2-job.json", job) catch |err| {
            try rollbackPendingAttempt(io, root, &attempt);
            return err;
        };
        var run = runComputeWorker(
            a,
            io,
            root,
            self_path,
            self_executable,
            "--qcow2-worker",
            intent.timeout_ms,
        ) catch |err| {
            try rollbackPendingAttempt(io, root, &attempt);
            return err;
        };
        defer run.result.deinit(a);
        release = run.result.cleanup_complete;
        if (!run.process_succeeded) {
            _ = try finishCompute(
                a,
                io,
                root,
                &lock,
                &attempt,
                run,
                false,
                "qcow2-supervision.json",
            );
            return error.ComputeFailed;
        }
        const verified = verifyQcow2Admission(
            a,
            io,
            root,
            request_file,
            intent,
            job,
            producer,
            &attempt,
        ) catch {
            _ = try finishCompute(
                a,
                io,
                root,
                &lock,
                &attempt,
                run,
                false,
                "qcow2-supervision.json",
            );
            return error.ComputeFailed;
        };
        const ok = try finishCompute(
            a,
            io,
            root,
            &lock,
            &attempt,
            run,
            true,
            "qcow2-supervision.json",
        );
        if (!ok.succeeded) return error.ComputeFailed;
        try std.Io.File.stdout().writeStreamingAll(io, verified.bytes);
        return;
    }

    const intent = try compute.readDeriveIntent(a, request_bytes);
    const source = try compute.bindExpected(
        a,
        io,
        intent.source_path,
        intent.expected_source_bytes,
        intent.accepted_qcow2_sha256,
        intent.limits.max_input_bytes,
    );
    const config_hex = try c.hex(a, config_sha256);
    var attempt = try compute.reserveAttempt(io, root, .vhd);
    defer attempt.close(io);
    const job: image.worker.VhdJob = .{
        .supervisor_pid = @intCast(std.os.linux.getpid()),
        .state_dir = input.state,
        .attempt = attempt.evidence,
        .source = source,
        .producer = producer,
        .expected_capacity_bytes = intent.expected_capacity_bytes,
        .limits = intent.limits,
        .config_sha256 = config_hex,
    };
    f.immutable(a, io, &lock, "vhd-job.json", job) catch |err| {
        try rollbackPendingAttempt(io, root, &attempt);
        return err;
    };
    var run = runComputeWorker(
        a,
        io,
        root,
        self_path,
        self_executable,
        "--vhd-worker",
        intent.timeout_ms,
    ) catch |err| {
        try rollbackPendingAttempt(io, root, &attempt);
        return err;
    };
    defer run.result.deinit(a);
    release = run.result.cleanup_complete;
    if (!run.process_succeeded) {
        _ = try finishCompute(
            a,
            io,
            root,
            &lock,
            &attempt,
            run,
            false,
            "vhd-supervision.json",
        );
        return error.ComputeFailed;
    }
    const verified = verifyVhdAdmission(
        a,
        io,
        root,
        request_file,
        intent,
        job,
        producer,
        &attempt,
    ) catch {
        _ = try finishCompute(
            a,
            io,
            root,
            &lock,
            &attempt,
            run,
            false,
            "vhd-supervision.json",
        );
        return error.ComputeFailed;
    };
    const ok = try finishCompute(
        a,
        io,
        root,
        &lock,
        &attempt,
        run,
        true,
        "vhd-supervision.json",
    );
    if (!ok.succeeded) return error.ComputeFailed;
    try std.Io.File.stdout().writeStreamingAll(io, verified.bytes);
}

const WorkerRun = struct {
    result: image.core.process.Result,
    process_succeeded: bool,
};

const WorkerOutcome = struct { succeeded: bool };

fn runComputeWorker(
    a: std.mem.Allocator,
    io: std.Io,
    root: image.core.private_files.Directory,
    self_path: []const u8,
    self_executable: []const u8,
    worker_argument: []const u8,
    timeout_ms: u32,
) !WorkerRun {
    try image.core.process.initialize();
    var environment: std.process.Environ.Map = .init(a);
    defer environment.deinit();
    var path_buffer: [4096]u8 = undefined;
    const state_path = path_buffer[0..try root.dir.realPath(io, &path_buffer)];
    try environment.put("TMPDIR", state_path);
    try environment.put("WAMR_CI_EXECUTABLE_PATH", self_path);
    try environment.put("WAMR_CI_RETAINED_EXECUTABLE", self_executable);
    const result = try image.core.process.run(a, io, .{
        .argv = &.{ self_executable, worker_argument },
        .environment = &environment,
        .cwd = root.dir,
        .deadline = try image.core.process.Deadline.afterMilliseconds(timeout_ms),
        .cleanup_ms = image.boot.config.cleanup_ms,
        .stdout_limit = 0,
        .stderr_limit = 0,
    });
    const process_succeeded = result.cleanup_complete and
        image.engine.clean(result.failures) and result.termination != null and
        result.termination.? == .exited and result.termination.?.exited == 0;
    return .{ .result = result, .process_succeeded = process_succeeded };
}

fn finishCompute(
    a: std.mem.Allocator,
    io: std.Io,
    root: image.core.private_files.Directory,
    lock: *image.core.private_files.Locked,
    attempt: *compute.ReservedAttempt,
    run: WorkerRun,
    parent_verified: bool,
    supervision_name: []const u8,
) !WorkerOutcome {
    const stage_cleanup_complete = attempt.cleanupStage(io, root);
    var accepted = run.process_succeeded and parent_verified and stage_cleanup_complete;
    if (accepted) attempt.published(io, root) catch {
        accepted = false;
    };
    var rollback_complete = true;
    if (!accepted) {
        const cleanup = attempt.rollback(io, root);
        rollback_complete = cleanup.rollbackComplete();
    }
    const names = switch (attempt.evidence.kind) {
        .qcow2 => .{ compute.qcow2_name, compute.qcow2_record_name },
        .vhd => .{ compute.vhd_name, compute.vhd_record_name },
    };
    const output_visible = if (accepted) true else exists(io, root, names[0]) catch true;
    const record_visible = if (accepted) true else exists(io, root, names[1]) catch true;
    const outcome: compute.Outcome = if (accepted and output_visible and record_visible)
        .succeeded
    else if (!output_visible and !record_visible and rollback_complete)
        .refused
    else
        .partial;
    f.immutable(a, io, lock, supervision_name, ComputeSupervision{
        .failures = run.result.failures,
        .cleanup_complete = run.result.cleanup_complete,
        .termination = run.result.termination,
        .stage_cleanup_complete = stage_cleanup_complete,
        .rollback_complete = rollback_complete,
        .outcome = outcome,
    }) catch |err| {
        if (accepted) _ = attempt.rollback(io, root);
        return err;
    };
    return .{ .succeeded = outcome == .succeeded };
}

fn rollbackPendingAttempt(
    io: std.Io,
    root: image.core.private_files.Directory,
    attempt: *compute.ReservedAttempt,
) !void {
    if (!attempt.rollback(io, root).rollbackComplete())
        return error.AttemptCleanupFailed;
}

fn verifyQcow2Admission(
    a: std.mem.Allocator,
    io: std.Io,
    root: image.core.private_files.Directory,
    request_file: c.File,
    intent: compute.FinalizeIntent,
    job: image.worker.Qcow2Job,
    producer: c.File,
    attempt: *compute.ReservedAttempt,
) !compute.VerifiedFinalization {
    try f.same(a, intent, try compute.readFinalizeIntent(
        a,
        try f.readArtifact(a, io, request_file, c.max_record),
    ));
    const stored = try c.read(
        image.worker.Qcow2Job,
        a,
        try root.read(io, a, "qcow2-job.json", c.max_record, null),
    );
    try f.same(a, job, stored);
    try compute.verifyPinned(io, stored.source, stored.limits.max_input_bytes);
    try f.verify(a, io, producer, c.max_tool, true);
    const verified = try compute.verifyFinalizedQcow2(a, io, root, attempt, .{
        .source = stored.source,
        .expected_virtual_bytes = stored.expected_virtual_bytes,
        .expected_workload_sha256 = try c.sha(stored.expected_workload_sha256),
        .expected_workload_bytes = stored.expected_workload_bytes,
        .limits = stored.limits,
        .producer = stored.producer,
        .config_sha256 = try c.sha(stored.config_sha256),
    });
    try f.same(a, intent, try compute.readFinalizeIntent(
        a,
        try f.readArtifact(a, io, request_file, c.max_record),
    ));
    try compute.verifyPinned(io, stored.source, stored.limits.max_input_bytes);
    try f.verify(a, io, producer, c.max_tool, true);
    return verified;
}

fn verifyVhdAdmission(
    a: std.mem.Allocator,
    io: std.Io,
    root: image.core.private_files.Directory,
    request_file: c.File,
    intent: compute.DeriveIntent,
    job: image.worker.VhdJob,
    producer: c.File,
    attempt: *compute.ReservedAttempt,
) !compute.VerifiedDerivation {
    try f.same(a, intent, try compute.readDeriveIntent(
        a,
        try f.readArtifact(a, io, request_file, c.max_record),
    ));
    const stored = try c.read(
        image.worker.VhdJob,
        a,
        try root.read(io, a, "vhd-job.json", c.max_record, null),
    );
    try f.same(a, job, stored);
    try compute.verifyPinned(io, stored.source, stored.limits.max_input_bytes);
    try f.verify(a, io, producer, c.max_tool, true);
    const verified = try compute.verifyDerivedFixedVhd(a, io, root, attempt, .{
        .source = stored.source,
        .expected_capacity_bytes = stored.expected_capacity_bytes,
        .limits = stored.limits,
        .producer = stored.producer,
        .config_sha256 = try c.sha(stored.config_sha256),
    });
    try f.same(a, intent, try compute.readDeriveIntent(
        a,
        try f.readArtifact(a, io, request_file, c.max_record),
    ));
    try compute.verifyPinned(io, stored.source, stored.limits.max_input_bytes);
    try f.verify(a, io, producer, c.max_tool, true);
    return verified;
}

fn exists(io: std.Io, root: image.core.private_files.Directory, name: []const u8) !bool {
    _ = root.dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}
