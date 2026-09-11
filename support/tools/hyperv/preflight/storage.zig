const std = @import("std");
const core = @import("hyperv_core");
const az = @import("hyperv_azure");
const transfer = @import("hyperv_transfer");
const sdk = @import("azure_sdk_core");
const c = @import("contract.zig");
const p = c.p;
const j = @import("journal.zig");
const ev = @import("evidence.zig");

pub const Adapter = struct {
    store: *j.Store,
    runtime: sdk.http.HttpRuntime,
    budget: transfer.Budget,
    root: []const u8,
    last: az.transport.Failure = .{ .effect = .not_started, .diagnostic = .{ .stage = .blob_upload, .category = .internal } },

    pub fn stage(self: *Adapter, phase: p.Phase) !p.Hash {
        self.last = .{ .effect = .not_started, .diagnostic = .{ .stage = .blob_upload, .category = .internal } };
        if (phase == .private) try @import("engine.zig").requirePublic(self.store.state);
        const a = self.store.allocator;
        const InputFile = struct { blob: []const u8, path: []const u8, size: u64, sha256: []const u8 };
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        var records: std.ArrayList(InputFile) = .empty;
        for (self.store.input.preparation.files) |file| if (file.phase == phase) {
            const blob = try p.artifactBlob(scratch, try core.contracts.parseUuid(&self.store.state.run_id), phase, file.artifact.name);
            try records.append(scratch, .{ .blob = blob, .path = file.path, .size = file.artifact.size, .sha256 = try scratch.dupe(u8, &p.hex(file.artifact.sha256)) });
        };
        var admission = try self.store.admission();
        defer admission.deinit();
        const request = try c.canonical(scratch, .{
            .schema = transfer.request.schema,
            .schema_version = 1,
            .action = "upload",
            .account_url = try std.fmt.allocPrint(scratch, "https://{s}.blob.core.windows.net", .{admission.account}),
            .container = admission.container,
            .files = records.items,
            .create_container = false,
        });
        return self.transferWorker(phase, request);
    }

    /// Execute the merged transfer worker directly inside this already supervised
    /// operation process. It never creates a nested process group/supervisor.
    fn transferWorker(self: *Adapter, phase: p.Phase, request: []const u8) !p.Hash {
        const store = self.store;
        const a = store.allocator;
        const name = if (phase == .public) "transfer-public" else "transfer-private";
        try store.lock.directory.dir.createDir(store.io, name, .fromMode(0o700));
        const directory = core.private_files.Directory{ .dir = try store.lock.directory.dir.openDir(store.io, name, .{ .follow_symlinks = false, .iterate = true }) };
        defer directory.close(store.io);
        var lock = try directory.lock(store.io);
        defer lock.close(store.io);
        var sas = try store.lock.directory.readSensitive(store.io, a, "storage-capability", transfer.request.maximum_sas, null);
        defer sas.deinit();
        const job = try c.canonical(a, .{ .contract = "uk.hyperv.transfer-job", .schema_version = 1, .kind = "blob", .request = "request.json", .sas = "capability", .timeout_ms = 300_000, .cleanup_ms = c.child_cleanup_ms });
        defer a.free(job);
        var definition = try transfer.request.Request.parse(a, request);
        defer definition.deinit();
        var bytes: u64 = 0;
        for (definition.records) |record| bytes += record.upload.input.size;
        const plan: transfer.job.Plan = .{ .bytes = bytes, .download_bytes = 0, .mutations = definition.records.len, .requests = definition.records.len };
        const clock_ns = try core.process.monotonicNanoseconds();
        const operation_end = try std.math.add(u64, clock_ns, @as(u64, 300_000) * std.time.ns_per_ms);
        const intent: transfer.worker.protocol.Intent = .{
            .attempt_id = p.hash(&store.state.attempt),
            .deadline_ns = @min(operation_end, try std.math.mul(u64, self.budget.deadline_ms, std.time.ns_per_ms)),
            .job_sha256 = p.hash(job),
            .request_sha256 = p.hash(request),
            .sas_sha256 = p.hash(sas.bytes()),
            .kind = .blob,
            .parent_pid = @intCast(std.os.linux.getppid()),
            .plan = plan,
        };
        var buffer: [2048]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try intent.write(&writer);
        // Blob uploads have begin/end per request, one final journal and one
        // consumed marker. Keep an extra final/error checkpoint reservation.
        try store.charge(job.len + request.len + sas.bytes().len + writer.buffered().len +
            (definition.records.len * 2 + 3) * transfer.worker.protocol.maximum_result, true);
        try store.save();
        try j.durable(try lock.createImmutable(store.io, "job.json", job));
        try j.durable(try lock.createImmutable(store.io, "request.json", request));
        try j.durable(try lock.createImmutable(store.io, "capability", sas.bytes()));
        try j.durable(try lock.createImmutable(store.io, transfer.job.intent_name, writer.buffered()));
        lock.close(store.io);
        // Cwd changes are isolated to the single-operation child. Restore its
        // descriptor before any parent journal access or credential disposal.
        if (std.os.linux.errno(std.os.linux.fchdir(directory.dir.handle)) != .SUCCESS) return error.UnsafeDirectory;
        const report = transfer.worker.execute(a, store.io, "job.json", self.runtime);
        // Preserve the worker's effects and independent lanes before cwd,
        // credential cleanup, validation or serialization can fail.
        self.observeWorker(report);
        var local_error: ?anyerror = null;
        if (std.os.linux.errno(std.os.linux.fchdir(store.lock.directory.dir.handle)) != .SUCCESS) {
            self.postFailure(.cleanup, .{ .stage = .private_file, .category = .local_io });
            local_error = error.UnsafeDirectory;
        }
        directory.dir.deleteFile(store.io, "capability") catch |err| {
            self.postFailure(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
            if (local_error == null) local_error = err;
        };
        @import("hyperv_host").files.syncDirectory(store.io, directory.dir) catch |err| {
            self.postFailure(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
            self.postFailure(.recording, .{ .stage = .state_record, .category = .local_io });
            if (local_error == null) local_error = err;
        };
        report.validate() catch |err| {
            if (self.last.effect != .accepted) self.last.effect = .unknown;
            self.postFailure(.recording, .{ .stage = .transfer_worker, .category = .invalid_response });
            return local_error orelse err;
        };
        if (local_error) |err| return err;
        if (!report.delivery_complete or report.process_cleanup_complete != null or report.failures.primary != null or
            report.failures.cleanup != null or report.failures.recording != null or report.outcome == null or report.outcome.?.completion != .complete)
        {
            if (self.last.diagnostic.category == .internal)
                self.last.diagnostic = .{ .stage = .transfer_worker, .category = .ambiguous };
            return error.TransferFailed;
        }
        var output: [transfer.worker.protocol.maximum_result]u8 = undefined;
        var result = std.Io.Writer.fixed(&output);
        report.write(&result) catch |err| {
            self.postFailure(.recording, .{ .stage = .transfer_worker, .category = .invalid_response });
            return err;
        };
        return p.hash(result.buffered());
    }

    fn observeWorker(self: *Adapter, report: transfer.worker.Report) void {
        self.last = .{
            .effect = transferEffect(report.side_effect),
            .diagnostic = report.failures.primary orelse report.failures.recording orelse report.failures.cleanup orelse
                .{ .stage = .transfer_worker, .category = .internal },
        };
        if (report.failures.primary) |value| self.store.fail(.primary, value);
        if (report.failures.cleanup) |value| self.store.fail(.cleanup, value);
        if (report.failures.recording) |value| self.store.fail(.recording, value);
        if (report.outcome) |outcome| {
            if (self.last.effect != transferEffect(outcome.side_effect) and self.last.effect != .accepted)
                self.last.effect = .unknown;
            if (outcome.failures.primary) |value| self.store.fail(.primary, value);
            if (outcome.failures.cleanup) |value| self.store.fail(.cleanup, value);
            if (outcome.failures.recording) |value| self.store.fail(.recording, value);
            if (outcome.cleanup_failed) self.postFailure(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
        }
    }
    fn postFailure(self: *Adapter, lane: c.Lane, value: core.diagnostics.Diagnostic) void {
        self.store.fail(lane, value);
        if (self.last.diagnostic.category == .internal) self.last.diagnostic = value;
    }

    pub fn requireRevocation(self: *Adapter, result: transfer.Outcome) !void {
        const failures = try result.failureSummary();
        if (failures.cleanup) |value| self.store.fail(.cleanup, value);
        if (failures.recording) |value| self.store.fail(.recording, value);
        // Discharge only the expected service rejection, never local failures.
        if (result.failures.primary) |value| self.store.fail(.cleanup, value);
        try result.validate();
        const diagnostic = result.aggregateDiagnostic();
        if (result.completion == .complete or diagnostic.http_status != 403 or diagnostic.service_code != .AuthenticationFailed or
            (diagnostic.category != .authentication and diagnostic.category != .authorization) or
            failures.cleanup != null or failures.recording != null or result.failures.primary != null)
            return error.DataPlaneRevocationUnproved;
    }

    pub fn publish(self: *Adapter, phase: p.Phase, bytes: []const u8) !p.Hash {
        const store = self.store;
        const a = store.allocator;
        var sas = try store.lock.directory.readSensitive(store.io, a, "storage-capability", transfer.request.maximum_sas, null);
        defer sas.deinit();
        const name = @import("engine.zig").commandName(phase);
        const path = try std.fs.path.join(a, &.{ self.root, name });
        defer a.free(path);
        const account = try std.fmt.allocPrint(a, "https://{s}.blob.core.windows.net", .{store.input.approved.resources.storage.name});
        defer a.free(account);
        var admission = try store.admission();
        defer admission.deinit();
        const blob = try std.fmt.allocPrint(a, "runs/{s}/commands/{s}.json", .{ store.state.run_id, @tagName(phase) });
        defer a.free(blob);
        var client: transfer.Client = .{ .allocator = a, .io = store.io, .runtime = self.runtime, .budget = self.budget };
        const outcome = client.uploadBlock(.{ .account_url = account, .container = admission.container, .name = blob, .sas = sas.bytes() }, .{ .path = path, .size = bytes.len, .sha256 = p.hash(bytes) });
        try self.requireOutcome(outcome);
        return p.hash(bytes);
    }
    pub fn fetch(self: *Adapter, phase: p.Phase, nonce: c.Uuid) !ev.Bundle {
        const store = self.store;
        const a = store.allocator;
        const prefix = try std.fmt.allocPrint(a, "runs/{s}/evidence/{s}/{s}/", .{ store.state.run_id, @tagName(phase), nonce });
        defer a.free(prefix);
        const name = if (phase == .public) "download-public-receipt" else "download-private-receipt";
        const receipt = try self.download(prefix, "receipt.json", name, p.max_command, true);
        errdefer {
            std.crypto.secureZero(u8, receipt);
            a.free(receipt);
        }
        const count: usize = if (phase == .public) 2 else 4;
        const logs = try a.alloc([]const u8, count);
        var loaded: usize = 0;
        errdefer {
            for (logs[0..loaded]) |log| {
                std.crypto.secureZero(u8, @constCast(log));
                a.free(log);
            }
            a.free(logs);
        }
        for (logs, 0..) |*log, i| {
            const file = try std.fmt.allocPrint(a, "boot-{d}.log", .{i + @as(usize, if (phase == .public) 0 else 2)});
            defer a.free(file);
            const local = try std.fmt.allocPrint(a, "download-{s}", .{file});
            defer a.free(local);
            log.* = try self.download(prefix, file, local, p.max_serial, false);
            loaded += 1;
        }
        return .{ .receipt = receipt, .logs = logs };
    }
    fn download(self: *Adapter, prefix: []const u8, name: []const u8, local: []const u8, maximum: usize, poll: bool) ![]u8 {
        const store = self.store;
        const a = store.allocator;
        const blob = try std.mem.concat(a, u8, &.{ prefix, name });
        defer a.free(blob);
        const account = try std.fmt.allocPrint(a, "https://{s}.blob.core.windows.net", .{store.input.approved.resources.storage.name});
        defer a.free(account);
        const path = try std.fs.path.join(a, &.{ self.root, local });
        defer a.free(path);
        var sas = try store.lock.directory.readSensitive(store.io, a, "storage-capability", transfer.request.maximum_sas, null);
        defer sas.deinit();
        var admission = try store.admission();
        defer admission.deinit();
        var client: transfer.Client = .{ .allocator = a, .io = store.io, .runtime = self.runtime, .budget = self.budget };
        for (0..600) |_| {
            const result = client.downloadBlob(.{ .account_url = account, .container = admission.container, .name = blob, .sas = sas.bytes() }, .{ .path = path, .maximum = maximum });
            if (result.completion == .complete) {
                return store.lock.directory.read(store.io, a, local, maximum, null);
            }
            if (!poll or result.cleanup_failed or result.failures.cleanup != null or result.failures.recording != null or
                result.diagnostic.status != 404 or result.diagnostic.service.code != .BlobNotFound)
            {
                try self.requireOutcome(result);
                return error.InvalidEvidence;
            }
            try self.budget.check();
            try store.io.sleep(.fromSeconds(1), .awake);
        }
        return error.Deadline;
    }
    pub fn release(self: *Adapter, bundle: ev.Bundle) void {
        const a = self.store.allocator;
        std.crypto.secureZero(u8, @constCast(bundle.receipt));
        a.free(bundle.receipt);
        for (bundle.logs) |log| {
            std.crypto.secureZero(u8, @constCast(log));
            a.free(log);
        }
        a.free(bundle.logs);
    }
    fn requireOutcome(self: *Adapter, value: transfer.Outcome) !void {
        const failures = try value.failureSummary();
        if (failures.cleanup) |failure| self.store.fail(.cleanup, failure);
        if (failures.recording) |failure| self.store.fail(.recording, failure);
        if (value.completion == .complete and failures.primary == null and failures.cleanup == null and failures.recording == null) return;
        self.last = .{ .diagnostic = value.aggregateDiagnostic(), .effect = transferEffect(value.side_effect) };
        return error.TransferFailed;
    }
};

fn transferEffect(certainty: transfer.diagnostic.Certainty) az.transport.Effect {
    return switch (certainty) {
        .not_started => .not_started,
        .accepted => .accepted,
        .rejected => .rejected,
        .unknown, .incomplete => .unknown,
        .not_applicable => .not_applicable,
    };
}

/// The historical owned-account scope is deliberately rcw / b / sco / HTTPS.
/// This signs native bytes, not an Azure CLI account-SAS operation.
pub fn signSas(allocator: std.mem.Allocator, account: []const u8, base64_key: []const u8, expires_at: u64) !az.secret.Bytes {
    if (expires_at < 946684800 or expires_at > 4102444800) return error.InvalidExpiry;
    const account_url = try std.fmt.allocPrint(allocator, "https://{s}.blob.core.windows.net", .{account});
    defer allocator.free(account_url);
    if (!transfer.request.validAccount(account_url)) return error.InvalidAccount;
    var decoded: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    if (try std.base64.standard.Decoder.calcSizeForSlice(base64_key) != decoded.len) return error.InvalidSigningKey;
    try std.base64.standard.Decoder.decode(&decoded, base64_key);
    const epoch = std.time.epoch.EpochSeconds{ .secs = expires_at };
    const year = epoch.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = epoch.getDaySeconds();
    var expiry_buffer: [20]u8 = undefined;
    const expiry = try std.fmt.bufPrint(&expiry_buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ year.year, @intFromEnum(month.month), @as(u8, month.day_index) + 1, day.getHoursIntoDay(), day.getMinutesIntoHour(), day.getSecondsIntoMinute() });
    const message = try std.fmt.allocPrint(allocator, "{s}\nrcw\nb\nsco\n\n{s}\n\nhttps\n2024-11-04\n\n", .{ account, expiry });
    defer allocator.free(message);
    var signature: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &signature);
    std.crypto.auth.hmac.sha2.HmacSha256.create(&signature, message, &decoded);
    var encoded: [44]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    _ = std.base64.standard.Encoder.encode(&encoded, &signature);
    var output = std.Io.Writer.Allocating.init(allocator);
    defer {
        std.crypto.secureZero(u8, output.written());
        output.deinit();
    }
    try output.writer.writeAll("sv=2024-11-04&ss=b&srt=sco&sp=rcw&spr=https&se=");
    try percent(&output.writer, expiry);
    try output.writer.writeAll("&sig=");
    try percent(&output.writer, &encoded);
    if (!transfer.request.validSas(output.written())) return error.InvalidCapability;
    return az.secret.Bytes.copy(allocator, output.written());
}
fn percent(writer: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |byte| {
        if (std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "-._~", byte) != null) try writer.writeByte(byte) else try writer.print("%{X:0>2}", .{byte});
    }
}
