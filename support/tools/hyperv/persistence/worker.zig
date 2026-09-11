const std = @import("std");
const core = @import("hyperv_core");
const transfer = @import("hyperv_transfer");
const local = @import("local.zig");
const m = @import("model.zig");
const engine = @import("engine.zig");
const native = @import("native.zig");

pub const Backend = struct {
    context: *anyopaque,
    executeFn: *const fn (*anyopaque, m.Job, core.private_files.Directory, *core.private_files.Locked) anyerror!m.Result,
};
pub const Ack = struct {
    contract: []const u8 = "uk.hyperv.persistence-worker-ack",
    schema_version: u8 = 1,
    job_sha256: local.Hash,
    nonce: local.Hash,
    result_sha256: local.Hash,
};
const Stopped = struct {
    contract: []const u8 = "uk.hyperv.persistence-worker-stopped",
    schema_version: u8 = 1,
    nonce: local.Hash,
    job_sha256: local.Hash,
    process_cleanup_complete: bool,
    failures: core.diagnostics.Failures,
};

/// The production facade must provide its committed admission/credential
/// bootstrap. This entry never forks or installs another process reaper.
pub fn child(allocator: std.mem.Allocator, io: std.Io, backend: Backend) !void {
    const directory = try core.private_files.Directory.openWorkerCwd(io);
    defer directory.close(io);
    var lock = try directory.lock(io);
    defer lock.close(io);
    var raw = try directory.readSensitive(io, allocator, "job.json", local.maximum, null);
    defer raw.deinit();
    const document = try core.contracts.SensitiveDocument.parse(allocator, raw.bytes(), .{ .bytes = local.maximum, .tokens = 32768 });
    defer document.deinit();
    try document.requireCanonical(raw.bytes());
    const job = try local.parse(m.Job, document.value());
    try job.validate();
    if (job.parent_pid != std.os.linux.getppid() or try core.process.monotonicNanoseconds() >= job.deadline_ns)
        return error.InvalidParentOrDeadline;
    const input = try local.encode(allocator, job.input);
    defer allocator.free(input);
    if (!std.mem.eql(u8, &local.hash(input), &job.input_sha256)) return error.ContractSubstitution;
    const started = try lock.createImmutable(io, "started.json", "{\"schema_version\":1}\n");
    if (started.status != .durable or started.failures.recording != null or started.failures.cleanup != null)
        return error.RecordingFailed;
    var result = try backend.executeFn(backend.context, job, directory, &lock);
    try result.validate();
    if (!std.mem.eql(u8, &result.job_sha256, &local.hash(raw.bytes())) or
        !std.mem.eql(u8, &result.nonce, &job.nonce) or result.step != job.step) return error.StaleWorker;
    const bytes = try local.encode(allocator, result);
    defer allocator.free(bytes);
    const written = try lock.createImmutable(io, "result.json", bytes);
    if (written.status != .durable or written.failures.recording != null or written.failures.cleanup != null)
        return error.RecordingFailed;
    const ack = try local.encode(allocator, Ack{
        .job_sha256 = result.job_sha256,
        .nonce = job.nonce,
        .result_sha256 = local.hash(bytes),
    });
    defer allocator.free(ack);
    var output = std.Io.File.stdout().writer(io, &.{});
    try output.interface.writeAll(ack);
}

pub const Supervisor = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: core.private_files.Directory,
    root_path: []const u8,
    executable: transfer.files.Input,
    cancellation: ?*const std.atomic.Value(bool) = null,
    provision: struct {
        context: *anyopaque,
        call: *const fn (*anyopaque, m.Job, core.private_files.Directory) anyerror!void,
    },
    directories: [m.step_count]?[]u8 = [_]?[]u8{null} ** m.step_count,

    pub fn driver(self: *Supervisor) engine.Driver {
        return .{ .context = self, .executeFn = execute, .serialFn = readSerial, .recoverFn = recover };
    }
    pub fn deinit(self: *Supervisor) void {
        for (self.directories) |path| if (path) |value| self.allocator.free(value);
    }

    fn recover(context: *anyopaque, state: *m.State) !void {
        const self: *Supervisor = @ptrCast(@alignCast(context));
        state.process_cleanup_complete = false;
        for (&state.records, 0..) |*record, index| {
            if (record.progress != .intent) continue;
            for (0..8) |generation| {
                var buffer: [48]u8 = undefined;
                const name = try std.fmt.bufPrint(&buffer, "worker-{d:0>2}-{d}", .{ index, generation });
                const path = try std.fs.path.join(self.allocator, &.{ self.root_path, name });
                defer self.allocator.free(path);
                const directory = core.private_files.Directory.open(self.io, path) catch |err| switch (err) {
                    error.FileNotFound => break,
                    else => return err,
                };
                defer directory.close(self.io);
                var lock = try directory.lock(self.io);
                defer lock.close(self.io);
                const raw_job = try directory.read(self.io, self.allocator, "job.json", local.maximum, null);
                defer self.allocator.free(raw_job);
                const job = try local.Document(m.Job).load(self.allocator, raw_job);
                defer job.deinit();
                try job.value.validate();
                if (@intFromEnum(job.value.step) != index or !std.mem.eql(u8, &job.value.nonce, &state.nonce) or
                    !std.mem.eql(u8, &job.value.input_sha256, &state.input_sha256)) return error.StaleWorker;
                // A lock alone is not a terminate/reap proof. Missing parent
                // supervision evidence requires the outer owner's recovery.
                const stopped = try self.requireStopped(directory, job.value, local.hash(raw_job));
                m.mergeStep(&state.failures, stopped.failures, job.value.step);
                var fallback = try native.initial(self.allocator, job.value);
                fallback.effect = if (job.value.step.mutation()) .unknown else .not_applicable;
                if (recoverResult(self, directory, job.value)) |saved| {
                    fallback = saved;
                } else |err| switch (err) {
                    error.FileNotFound => {},
                    else => fallback.failures.recording = .{ .stage = .state_record, .category = .invalid_response },
                }
                if (fallback.page_report == null) try recoverPages(self, directory, job.value, &fallback);
                record.effect = fallback.effect;
                record.transfer = fallback.transfer;
                record.page_report = fallback.page_report;
                record.http_status = fallback.http_status;
                record.service_code = fallback.service_code;
                record.access_metadata = fallback.access_metadata;
                m.mergeStep(&state.failures, fallback.failures, job.value.step);
                try state.retainOriginals(job.value.step, fallback.observation.originals);
            }
            record.progress = .failed;
            state.reconcileUnstartedGrant(@enumFromInt(index));
        }
        state.process_cleanup_complete = true;
        state.phase = .failed;
        state.failures.primary = state.failures.primary orelse .{ .stage = .process_run, .category = .ambiguous };
    }

    fn requireStopped(self: *Supervisor, directory: core.private_files.Directory, job: m.Job, binding: local.Hash) !Stopped {
        const raw = directory.read(self.io, self.allocator, "supervised.json", 8192, null) catch |err| switch (err) {
            error.FileNotFound => return error.ProcessRecoveryRequired,
            else => return err,
        };
        defer self.allocator.free(raw);
        const document = try local.Document(Stopped).load(self.allocator, raw);
        defer document.deinit();
        var stopped = document.value;
        if (stopped.schema_version != 1 or !std.mem.eql(u8, stopped.contract, "uk.hyperv.persistence-worker-stopped") or
            !stopped.process_cleanup_complete or !std.mem.eql(u8, &stopped.nonce, &job.nonce) or
            !std.mem.eql(u8, &stopped.job_sha256, &binding)) return error.ProcessRecoveryRequired;
        stopped.contract = "uk.hyperv.persistence-worker-stopped";
        return stopped;
    }
    fn previousStopped(self: *Supervisor, name: []const u8, job: m.Job) !void {
        const path = try std.fs.path.join(self.allocator, &.{ self.root_path, name });
        defer self.allocator.free(path);
        const directory = try core.private_files.Directory.open(self.io, path);
        defer directory.close(self.io);
        var lock = try directory.lock(self.io);
        defer lock.close(self.io);
        const raw = try directory.read(self.io, self.allocator, "job.json", local.maximum, null);
        defer self.allocator.free(raw);
        const previous = try local.Document(m.Job).load(self.allocator, raw);
        defer previous.deinit();
        try previous.value.validate();
        if (previous.value.step != job.step or !std.mem.eql(u8, &previous.value.nonce, &job.nonce) or
            !std.mem.eql(u8, &previous.value.input_sha256, &job.input_sha256)) return error.StaleWorker;
        _ = try self.requireStopped(directory, previous.value, local.hash(raw));
    }

    fn execute(context: *anyopaque, job: m.Job) !engine.Reply {
        const self: *Supervisor = @ptrCast(@alignCast(context));
        try job.validate();
        try core.process.initialize();
        var guard = Guard{ .deadline = job.deadline_ns };
        var binary = try transfer.files.SealedInput.open(self.io, self.executable, .{ .context = &guard, .checkFn = Guard.check });
        defer binary.close();
        const index = @intFromEnum(job.step);
        var name_buffer: [48]u8 = undefined;
        var selected: ?[]const u8 = null;
        for (0..8) |generation| {
            const name = try std.fmt.bufPrint(&name_buffer, "worker-{d:0>2}-{d}", .{ index, generation });
            self.directory.dir.createDir(self.io, name, .fromMode(0o700)) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    if (job.step.mutation()) return error.MutationReplay;
                    try self.previousStopped(name, job);
                    continue;
                },
                else => return err,
            };
            selected = name;
            break;
        }
        const name = selected orelse return error.ReadReconciliationLimit;
        const path = try std.fs.path.join(self.allocator, &.{ self.root_path, name });
        if (self.directories[index]) |old| self.allocator.free(old);
        self.directories[index] = path;
        const directory = try core.private_files.Directory.open(self.io, path);
        defer directory.close(self.io);
        const job_bytes = try local.encode(self.allocator, job);
        defer self.allocator.free(job_bytes);
        {
            var lock = try directory.lock(self.io);
            defer lock.close(self.io);
            const prepared = try lock.createImmutable(self.io, "job.json", job_bytes);
            if (prepared.status != .durable or prepared.failures.recording != null or prepared.failures.cleanup != null)
                return error.RecordingFailed;
        }
        try self.provision.call(self.provision.context, job, directory);
        try binary.verify(.{ .context = &guard, .checkFn = Guard.check });
        var environment = std.process.Environ.Map.init(self.allocator);
        defer environment.deinit();
        // This supervisor is the outer process owner. The restricted worker is
        // a leaf; calling transfer.worker.supervise here would escape its group.
        var process = try core.process.run(self.allocator, self.io, .{
            .argv = &.{ self.executable.path, "__persistence-worker" },
            .environment = &environment,
            .cwd = directory.dir,
            .deadline = .{ .expires_ns = job.deadline_ns },
            .cleanup_ms = 2000,
            .stdout_limit = 2048,
            .stderr_limit = 8192,
            .cancel = if (job.step.cleanup()) null else self.cancellation,
        });
        defer process.deinit(self.allocator);
        var fallback = try native.initial(self.allocator, job);
        fallback.effect = if (job.step.mutation()) .unknown else .not_applicable;
        fallback.process_cleanup_complete = process.cleanup_complete;
        m.merge(&fallback.failures, process.failures);
        if (!process.cleanup_complete) return .{ .value = fallback };
        var lock = try directory.lock(self.io);
        defer lock.close(self.io);
        const readback = directory.read(self.io, self.allocator, "result.json", local.maximum, null) catch |err| switch (err) {
            error.FileNotFound => {
                try recoverPages(self, directory, job, &fallback);
                if (fallback.failures.primary == null) fallback.failures.primary = .{ .stage = .process_run, .category = .invalid_response };
                try recordSupervision(self, &lock, job, &fallback);
                return .{ .value = fallback };
            },
            else => return err,
        };
        defer self.allocator.free(readback);
        const parsed = local.Document(m.Result).load(self.allocator, readback) catch {
            fallback.failures.primary = fallback.failures.primary orelse .{ .stage = .process_run, .category = .invalid_response };
            try recoverPages(self, directory, job, &fallback);
            try recordSupervision(self, &lock, job, &fallback);
            return .{ .value = fallback };
        };
        var keep = false;
        defer if (!keep) parsed.deinit();
        var result = parsed.value;
        const valid = blk: {
            result.validate() catch break :blk false;
            break :blk result.step == job.step and std.mem.eql(u8, &result.job_sha256, &local.hash(job_bytes)) and
                std.mem.eql(u8, &result.nonce, &job.nonce);
        };
        if (!valid) {
            fallback.failures.primary = fallback.failures.primary orelse .{ .stage = .process_run, .category = .invalid_response };
            try recoverPages(self, directory, job, &fallback);
            try recordSupervision(self, &lock, job, &fallback);
            return .{ .value = fallback };
        }
        m.merge(&result.failures, process.failures);
        const delivered = blk: {
            if (process.failures.primary != null) break :blk false;
            const ack = local.Document(Ack).load(self.allocator, process.stdout) catch break :blk false;
            defer ack.deinit();
            break :blk std.mem.eql(u8, ack.value.contract, "uk.hyperv.persistence-worker-ack") and ack.value.schema_version == 1 and
                std.mem.eql(u8, &ack.value.nonce, &job.nonce) and std.mem.eql(u8, &ack.value.job_sha256, &result.job_sha256) and
                std.mem.eql(u8, &ack.value.result_sha256, &local.hash(readback));
        };
        if (!delivered) {
            result.complete = false;
            result.failures.primary = result.failures.primary orelse .{ .stage = .process_run, .category = .invalid_response };
        }
        try recordSupervision(self, &lock, job, &result);
        keep = true;
        return .{ .value = result, .document = parsed };
    }

    fn readSerial(context: *anyopaque, allocator: std.mem.Allocator, step: m.Step, serial: m.Serial) ![]u8 {
        const self: *Supervisor = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, serial.name, "serial.bin")) return error.InvalidSerialResult;
        const directory = try core.private_files.Directory.open(self.io, self.directories[@intFromEnum(step)] orelse return error.MissingWorker);
        defer directory.close(self.io);
        return directory.read(self.io, allocator, "serial.bin", @import("contract.zig").serial_limit, try core.contracts.parseSha256(&serial.sha256));
    }
};

const Guard = struct {
    deadline: u64,
    fn check(context: *anyopaque) !void {
        const self: *Guard = @ptrCast(@alignCast(context));
        if (try core.process.monotonicNanoseconds() >= self.deadline) return error.Deadline;
    }
};
fn recordSupervision(self: *Supervisor, lock: *core.private_files.Locked, job: m.Job, result: *m.Result) !void {
    writeSupervision(self, lock, job, result) catch {
        result.complete = false;
        result.failures.recording = result.failures.recording orelse .{ .stage = .state_record, .category = .local_io };
    };
}
fn writeSupervision(self: *Supervisor, lock: *core.private_files.Locked, job: m.Job, result: *m.Result) !void {
    const proof = try local.encode(self.allocator, Stopped{
        .nonce = job.nonce,
        .job_sha256 = result.job_sha256,
        .process_cleanup_complete = result.process_cleanup_complete,
        .failures = result.failures,
    });
    defer self.allocator.free(proof);
    const saved = try lock.createImmutable(self.io, "supervised.json", proof);
    m.merge(&result.failures, saved.failures);
    if (saved.status != .durable or saved.failures.recording != null or saved.failures.cleanup != null) {
        result.complete = false;
        result.failures.recording = result.failures.recording orelse .{ .stage = .state_record, .category = .local_io };
    }
}
fn recoverResult(self: *Supervisor, directory: core.private_files.Directory, job: m.Job) !m.Result {
    const raw = try directory.read(self.io, self.allocator, "result.json", local.maximum, null);
    defer self.allocator.free(raw);
    const parsed = try local.Document(m.Result).load(self.allocator, raw);
    defer parsed.deinit();
    var result = parsed.value;
    try result.validate();
    const expected = try native.initial(self.allocator, job);
    if (result.step != job.step or !std.mem.eql(u8, &result.job_sha256, &expected.job_sha256) or
        !std.mem.eql(u8, &result.nonce, &job.nonce)) return error.StaleWorker;
    result.contract = "uk.hyperv.persistence-result";
    if (result.serial) |*serial| serial.name = "serial.bin";
    return result;
}
fn recoverPages(self: *Supervisor, directory: core.private_files.Directory, job: m.Job, result: *m.Result) !void {
    if (!job.step.upload()) return;
    const intent = transfer.worker.protocol.Intent.load(self.allocator, self.io, directory) catch |err| switch (err) {
        error.FileNotFound => return,
        else => {
            result.failures.recording = result.failures.recording orelse .{ .stage = .state_record, .category = .invalid_response };
            return;
        },
    };
    const source = if (job.step == .os_upload) job.input.guest else job.input.data;
    if (intent.kind != .pages or intent.plan.bytes != source.size or
        !std.mem.eql(u8, &std.fmt.bytesToHex(intent.job_sha256, .lower), &result.job_sha256) or
        !std.mem.eql(u8, &std.fmt.bytesToHex(intent.attempt_id, .lower), &job.nonce))
    {
        result.failures.recording = result.failures.recording orelse .{ .stage = .state_record, .category = .invalid_response };
        return;
    }
    const raw = directory.read(self.io, self.allocator, transfer.job.state_name, 8192, null) catch |err| switch (err) {
        error.FileNotFound => return,
        else => {
            result.failures.recording = result.failures.recording orelse .{ .stage = .state_record, .category = .local_io };
            return;
        },
    };
    defer self.allocator.free(raw);
    const report = transfer.worker.protocol.Report.recover(self.allocator, raw, intent) catch {
        result.failures.recording = result.failures.recording orelse .{ .stage = .state_record, .category = .invalid_response };
        return;
    };
    result.page_report = try m.PageReport.capture(report);
    result.transfer = report.outcome;
    result.effect = report.side_effect;
    m.merge(&result.failures, report.failures);
}
