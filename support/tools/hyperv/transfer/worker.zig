const std = @import("std");
const core = @import("hyperv_core");
const sdk = @import("azure_sdk_core");
const client = @import("client.zig");
const request = @import("request.zig");
const d = @import("diagnostic.zig");
const job = @import("job.zig");
pub const protocol = @import("protocol.zig");
pub const Report = protocol.Report;

const Clock = struct {
    fn now(_: *anyopaque) !u64 {
        return try core.process.monotonicNanoseconds() / std.time.ns_per_ms;
    }
};

/// Restricted child entry. The native caller never supplies credentials or an
/// endpoint in argv; cwd and the durable parent intent bind its private inputs.
pub fn executeNative(allocator: std.mem.Allocator, io: std.Io, name: []const u8) Report {
    var wiping: core.sensitive.Allocator = .{ .backing = allocator };
    var native = client.NativeRuntime.init(.{ .allocator = wiping.allocator(), .io = io });
    defer native.deinit();
    return execute(wiping.allocator(), io, name, native.runtime());
}

/// Runtime injection is used by a separately built native fixture executable,
/// never selected by the production CLI, job JSON or environment.
pub fn execute(allocator: std.mem.Allocator, io: std.Io, name: []const u8, runtime: sdk.http.HttpRuntime) Report {
    var report: Report = .{};
    return executeChecked(allocator, io, name, runtime, &report) catch |err| {
        if (err == error.AttemptConsumed or err == error.WouldBlock) {
            report.side_effect = .unknown;
            report.progress = null;
        }
        var outcome = d.Outcome.fail(.request_file, transferCategory(err));
        if (err == error.RecordingFailed) {
            outcome.diagnostic.category = .none;
            outcome.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        }
        outcome.side_effect = report.side_effect;
        report.outcome = outcome;
        report.phase = .finished;
        report.delivery_complete = true;
        report.merge(outcome.failureSummary() catch unreachable);
        return report;
    };
}

fn executeChecked(allocator: std.mem.Allocator, io: std.Io, name: []const u8, runtime: sdk.http.HttpRuntime, report: *Report) !Report {
    try job.filename(name);
    const directory = try core.private_files.Directory.openWorkerCwd(io);
    defer directory.close(io);
    var lock = try directory.lock(io);
    defer lock.close(io);
    const intent = try protocol.Intent.load(allocator, io, directory);
    if (intent.parent_pid != std.os.linux.getppid()) return error.InvalidParent;
    report.* = Report.initial(intent);
    const definition = try job.Job.load(allocator, io, directory, name);
    defer definition.deinit();
    var spec = try job.Spec.load(allocator, io, directory, definition);
    defer spec.deinit();
    if (!std.mem.eql(u8, &definition.binding, &intent.job_sha256) or
        !std.mem.eql(u8, &spec.binding, &intent.request_sha256) or
        definition.kind != intent.kind or !std.meta.eql(spec.plan(), intent.plan)) return error.HashMismatch;
    var sas = try directory.readSensitive(io, allocator, definition.sas_name, request.maximum_sas, intent.sas_sha256);
    defer sas.deinit();
    if (!request.validSas(sas.bytes())) return error.InvalidContract;
    const now = try core.process.monotonicNanoseconds();
    if (now >= intent.deadline_ns) return error.Deadline;
    if (intent.deadline_ns - now > @as(u64, definition.timeout_ms) * std.time.ns_per_ms) return error.InvalidDeadline;
    var marker: [256]u8 = undefined;
    var marker_writer = std.Io.Writer.fixed(&marker);
    try marker_writer.print("{{\"job_sha256\":\"{s}\",\"schema_version\":1}}\n", .{std.fmt.bytesToHex(intent.job_sha256, .lower)});
    const consumed = lock.createImmutable(io, job.started_name, marker_writer.buffered()) catch |err| {
        if (err == error.PathAlreadyExists) {
            report.side_effect = .unknown;
            return error.AttemptConsumed;
        }
        return err;
    };
    report.merge(consumed.failures);
    if (consumed.status != .durable or consumed.failures.cleanup != null or consumed.failures.recording != null)
        return error.RecordingFailed;
    var journal: protocol.Journal = .{ .io = io, .lock = &lock, .plan = intent.plan, .report = report.* };
    var clock: Clock = .{};
    var cancellation: sdk.http.CancellationToken = .{};
    var engine: client.Client = .{
        .allocator = allocator,
        .io = io,
        .runtime = runtime,
        .budget = .{ .context = &clock, .nowMsFn = Clock.now, .deadline_ms = intent.deadline_ns / std.time.ns_per_ms, .cancellation = &cancellation },
        .observer = journal.observer(),
    };
    const outcome = switch (spec.value) {
        .blob => |*value| engine.execute(value, sas.bytes()),
        .pages => |value| engine.uploadPages(.{ .endpoint = value.endpoint, .sas = sas.bytes() }, value.input),
    };
    return journal.finish(outcome);
}

pub const SuperviseOptions = struct {
    /// The production CLI passes its kernel-resolved executable path. Embedders
    /// must bind this native executable to their reviewed source/binary receipt.
    executable: []const u8,
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// This process must be a dedicated supervisor (no unrelated child reapers).
/// The job directory is single-use, including failed or interrupted attempts.
pub fn supervise(allocator: std.mem.Allocator, io: std.Io, root: []const u8, name: []const u8, options: SuperviseOptions) Report {
    var report: Report = .{};
    return superviseChecked(allocator, io, root, name, options, &report) catch |err| {
        if (err == error.AttemptConsumed or err == error.WouldBlock) {
            report.side_effect = .unknown;
            report.progress = null;
        }
        if (err == error.RecordingFailed) {
            report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        } else report.primary(coreCategory(err));
        if (report.process_cleanup_complete == null) report.process_cleanup_complete = true;
        return report;
    };
}

fn superviseChecked(allocator: std.mem.Allocator, io: std.Io, root: []const u8, name: []const u8, options: SuperviseOptions, report: *Report) !Report {
    try job.filename(name);
    if (!std.fs.path.isAbsolute(options.executable) or std.mem.indexOfAny(u8, options.executable, "?#\x00") != null)
        return error.InvalidContract;
    const directory = try core.private_files.Directory.open(io, root);
    defer directory.close(io);
    const definition = try job.Job.load(allocator, io, directory, name);
    defer definition.deinit();
    var spec = try job.Spec.load(allocator, io, directory, definition);
    defer spec.deinit();
    const plan = spec.plan();
    const deadline = try core.process.Deadline.afterMilliseconds(definition.timeout_ms);
    const sas_hash = blk: {
        var sas = try directory.readSensitive(io, allocator, definition.sas_name, request.maximum_sas, null);
        defer sas.deinit();
        if (!request.validSas(sas.bytes())) return error.InvalidContract;
        break :blk job.hash(sas.bytes());
    };
    var attempt: [32]u8 = undefined;
    io.random(&attempt);
    const intent: protocol.Intent = .{
        .attempt_id = attempt,
        .deadline_ns = deadline.expires_ns,
        .job_sha256 = definition.binding,
        .request_sha256 = spec.binding,
        .sas_sha256 = sas_hash,
        .kind = definition.kind,
        .plan = plan,
        .parent_pid = @intCast(std.os.linux.getpid()),
    };
    report.* = Report.initial(intent);
    try core.process.initialize();
    {
        var lock = try directory.lock(io);
        defer lock.close(io);
        var bytes: [2048]u8 = undefined;
        defer std.crypto.secureZero(u8, &bytes);
        var writer = std.Io.Writer.fixed(&bytes);
        try intent.write(&writer);
        const recorded = lock.createImmutable(io, job.intent_name, writer.buffered()) catch |err| {
            if (err == error.PathAlreadyExists) return error.AttemptConsumed;
            return err;
        };
        report.merge(recorded.failures);
        if (recorded.status != .durable or recorded.failures.cleanup != null or recorded.failures.recording != null)
            return error.RecordingFailed;
        var journal: protocol.Journal = .{ .io = io, .lock = &lock, .plan = plan, .report = report.* };
        journal.persist() catch |err| {
            report.* = journal.report;
            return err;
        };
    }
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var child = try core.process.run(allocator, io, .{
        .argv = &.{ options.executable, "__transfer-worker", name },
        .environment = &environment,
        .cwd = directory.dir,
        .deadline = deadline,
        .cleanup_ms = definition.cleanup_ms,
        .stdout_limit = protocol.maximum_result,
        .stderr_limit = 4096,
        .cancel = options.cancel,
    });
    defer child.deinit(allocator);
    report.merge(child.failures);
    if (!child.cleanup_complete) {
        report.progress = null;
        report.side_effect = if (plan.mutations == 0) .not_applicable else .unknown;
        report.process_cleanup_complete = false;
        report.merge(child.failures);
        return report.*;
    }
    report.progress = null;
    report.side_effect = if (plan.mutations == 0) .not_applicable else .unknown;
    report.process_cleanup_complete = true;
    var valid_output = false;
    var output_error: ?anyerror = null;
    if (child.failures.primary == null) {
        if (Report.parse(allocator, child.stdout, intent)) |decoded| {
            report.merge(decoded.failures);
            if (decoded.delivery_complete and decoded.phase == .finished and decoded.kind == intent.kind and
                decoded.process_cleanup_complete == null)
            {
                report.retain(decoded);
                valid_output = true;
            } else output_error = error.InvalidReport;
        } else |err| output_error = err;
    }
    const delivery_failure: ?core.diagnostics.Diagnostic = child.failures.primary orelse
        if (output_error) |err| .{
            .stage = .transfer_worker,
            .category = if (err == error.BindingMismatch) .integrity else .invalid_response,
        } else null;
    report.process_cleanup_complete = true;
    if (delivery_failure) |failure| report.failures.record(.primary, failure) catch unreachable;
    report.merge(child.failures);
    var lock = directory.lock(io) catch {
        report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        return report.*;
    };
    defer lock.close(io);
    if (!valid_output) {
        report.retain(recover(allocator, io, directory, intent));
        report.delivery_complete = false;
    }
    report.process_cleanup_complete = true;
    if (delivery_failure) |failure| report.failures.record(.primary, failure) catch unreachable;
    report.merge(child.failures);
    var bytes: [protocol.maximum_result]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    var writer = std.Io.Writer.fixed(&bytes);
    report.write(&writer) catch {
        report.failures.record(.recording, .{ .stage = .state_record, .category = .invalid_response }) catch unreachable;
        return report.*;
    };
    const recorded = lock.createImmutable(io, job.supervised_name, writer.buffered()) catch {
        report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        return report.*;
    };
    report.merge(recorded.failures);
    if (recorded.status != .durable)
        report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
    return report.*;
}

fn recover(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, intent: protocol.Intent) Report {
    var result = Report.initial(intent);
    result.progress = null;
    result.side_effect = if (intent.plan.mutations == 0) .not_applicable else .unknown;
    var bytes = directory.readSensitive(io, allocator, job.state_name, protocol.maximum_result, null) catch {
        result.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
        return result;
    };
    defer bytes.deinit();
    const recorded = Report.recover(allocator, bytes.bytes(), intent) catch {
        result.failures.record(.recording, .{ .stage = .state_record, .category = .invalid_response }) catch unreachable;
        return result;
    };
    if (recorded.kind != intent.kind or recorded.process_cleanup_complete != null) {
        result.failures.record(.recording, .{ .stage = .state_record, .category = .invalid_response }) catch unreachable;
        return result;
    }
    return recorded;
}

fn transferCategory(err: anyerror) d.Category {
    return switch (err) {
        error.UnsafeFile, error.UnsafePath => .unsafe_file,
        error.HashMismatch, error.FileChanged => .input_changed,
        error.Deadline => .deadline,
        error.RecordingFailed => .local_io,
        error.OutOfMemory => .allocation,
        else => .invalid_contract,
    };
}

fn coreCategory(err: anyerror) core.diagnostics.Category {
    return switch (err) {
        error.UnsafeFile, error.UnsafePath => .unsafe_file,
        error.HashMismatch, error.FileChanged => .integrity,
        error.AttemptConsumed => .conflict,
        error.WouldBlock => .contention,
        error.RecordingFailed, error.FileNotFound, error.FileOpenFailed => .local_io,
        error.OutOfMemory => .internal,
        else => .invalid_input,
    };
}
