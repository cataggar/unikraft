const std = @import("std");
const core = @import("hyperv_core");
const sdk = @import("azure_sdk_core");
const azure = @import("hyperv_azure");
const transfer = @import("hyperv_transfer");
const local = @import("local.zig");
const c = @import("contract.zig");
const m = @import("model.zig");
const aops = azure.operations;
const evidence = @import("evidence.zig");

/// Stable-address native session, created inside a directly supervised leaf.
/// Config supplies exactly one approved SDK provider and caller-selected trust.
/// Deinit is required even after init reports an authentication failure.
pub const Session = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    clock: azure.transport.NativeClock = undefined,
    cancellation: sdk.http.CancellationToken = .{},
    budget: azure.transport.Budget = undefined,
    runtime: ?azure.transport.NativeRuntime = null,
    token: ?azure.auth.Token = null,
    arm: azure.client.Client = undefined,
    blobs: transfer.Client = undefined,
    failure: ?azure.transport.Failure = null,

    pub fn init(self: *Session, config: azure.auth.Config, certs: []const []const u8, trust: [32]u8, deadline_ns: u64) !void {
        if (self.runtime != null or self.token != null) return error.SessionAlreadyInitialized;
        try config.validate();
        self.clock = .{ .io = self.io };
        self.budget = .{ .clock = self.clock.clock(), .deadline_ms = deadline_ns / std.time.ns_per_ms, .cancellation = &self.cancellation };
        try self.budget.check();
        self.runtime = try azure.transport.NativeRuntime.init(self.allocator, self.io, certs, trust, self.clock.clock());
        const channel: azure.transport.Channel = .{ .allocator = self.allocator, .runtime = self.runtime.?.runtime(), .budget = &self.budget };
        self.token = switch (azure.auth.acquire(self.allocator, channel, config)) {
            .ok => |token| token,
            .failed => |failure| {
                self.failure = failure;
                return error.CredentialAcquisitionFailed;
            },
        };
        self.arm = .{ .allocator = self.allocator, .authority = config.authority, .token = &self.token.?, .channel = channel };
        self.blobs = .{
            .allocator = self.allocator,
            .io = self.io,
            .runtime = self.runtime.?.runtime(),
            .budget = .{ .context = self, .nowMsFn = now, .deadline_ms = self.budget.deadline_ms, .cancellation = &self.cancellation },
        };
    }
    pub fn deinit(self: *Session) !void {
        if (self.token) |*token| {
            token.deinit();
            self.token = null;
        }
        if (self.runtime) |*runtime| {
            try runtime.deinit();
            self.runtime = null;
        }
    }
    fn now(context: *anyopaque) !u64 {
        const self: *Session = @ptrCast(@alignCast(context));
        return self.budget.clock.monotonicMsFn(self.budget.clock.context);
    }
};

/// Leaf-worker context. The enclosing native bootstrap owns the explicitly
/// acquired token and pinned-CA runtime; this adapter never discovers either.
pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    arm: *azure.client.Client,
    blobs: *transfer.Client,
    secrets: core.private_files.Directory,
    output: core.private_files.Directory,
    output_lock: *core.private_files.Locked,
    output_path: []const u8,

    pub fn execute(self: *Context, job: m.Job) !m.Result {
        var result = try initial(self.allocator, job);
        const arena = azure.secret.Arena.create(self.allocator) catch {
            result.failures.primary = .{ .stage = .private_file, .category = .local_io };
            return result;
        };
        defer arena.destroy();
        var scoped = self.*;
        scoped.allocator = arena.allocator();
        scoped.checked(job, &result) catch |err| {
            var failure = azure.transport.Failure.local(.arm, err, .not_started, result.http_status);
            failure.diagnostic.service_code = result.service_code;
            if (job.step.cleanup()) {
                if (result.failures.cleanup == null) result.failures.cleanup = failure.diagnostic;
            } else if (result.failures.primary == null) result.failures.primary = failure.diagnostic;
            result.complete = false;
        };
        return result;
    }

    fn checked(self: *Context, job: m.Job, out: *m.Result) !void {
        try job.validate();
        if (!std.mem.eql(u8, self.arm.authority.group, job.input.authority.group) or
            !std.mem.eql(u8, &self.arm.authority.owner_run, &job.input.authority.owner_run)) return error.AuthorityMismatch;
        const clock = self.arm.channel.budget.clock;
        const now = clock.monotonicMsFn(clock.context);
        const deadline = job.deadline_ns / std.time.ns_per_ms;
        if (now >= deadline) return error.Deadline;
        try self.arm.token.require(if (job.authority_lane == .cleanup) job.input.cleanup_authority else job.input.authority, clock.unixSecondsFn(clock.context), @intCast((deadline - now + 999) / 1000));
        self.arm.channel.budget.deadline_ms = @min(self.arm.channel.budget.deadline_ms, deadline);
        self.blobs.budget.deadline_ms = @min(self.blobs.budget.deadline_ms, deadline);
        switch (job.step) {
            .os_upload, .data_upload => try self.upload(job, out),
            .os_access_closed, .data_access_closed, .cleanup_os_access, .cleanup_data_access => try self.probe(job, out),
            .serial_boot1, .serial_boot2 => try self.serial(job, out),
            .observe_boot1, .observe_boot2, .observe_deallocated, .observe_final_deallocated, .cleanup_observe => try self.observe(job, out),
            .cleanup_absence => try self.absence(job, out),
            .cleanup_dispose => {
                var lock = try self.secrets.lock(self.io);
                defer lock.close(self.io);
                for ([_][]const u8{ "os-grant", "data-grant" }) |name| {
                    const file = self.secrets.openFile(self.io, name) catch |err| switch (err) {
                        error.FileNotFound => continue,
                        else => return err,
                    };
                    file.close(self.io);
                    try self.secrets.dir.deleteFile(self.io, name);
                }
                const recorded = try lock.commit(self.io, "disposed.json", "{\"schema_version\":1}\n");
                m.merge(&out.failures, recorded.failures);
                if (recorded.status != .durable or recorded.failures.recording != null or recorded.failures.cleanup != null)
                    return error.RecordingFailed;
                out.secrets_disposed = true;
                out.complete = true;
            },
            else => {
                if (job.step == .deploy_boot1) try self.uploadedDisks(job, out);
                if (job.step == .cleanup_delete) {
                    var check_job = job;
                    check_job.step = .cleanup_observe;
                    var checked_result = out.*;
                    try self.observe(check_job, &checked_result);
                    if (checked_result.observation.group != .absent and !checked_result.observation.owned_inventory)
                        return error.UnownedResources;
                }
                const operation = try operationFor(self.allocator, job);
                var result = try self.armCall(operation, out);
                defer result.deinit();
                switch (job.step) {
                    .os_create => {
                        if (result.model != .disk) return error.InvalidDiskResponse;
                        out.observation.originals.os = result.model.disk.uuid;
                    },
                    .data_create => {
                        if (result.model != .disk) return error.InvalidDiskResponse;
                        out.observation.originals.data = result.model.disk.uuid;
                    },
                    .deploy_boot1 => {
                        if (result.created.len != 1 or result.created[0].kind != .vm or result.created[0].uuid == null)
                            return error.MissingOriginalIdentity;
                        out.observation.originals.vm = result.created[0].uuid;
                    },
                    .os_grant, .data_grant => {
                        if (result.model != .grant) return error.InvalidGrantResponse;
                        var lock = try self.secrets.lock(self.io);
                        defer lock.close(self.io);
                        const stored = try lock.createImmutable(self.io, if (job.step == .os_grant) "os-grant" else "data-grant", result.model.grant);
                        m.merge(&out.failures, stored.failures);
                        if (stored.status != .durable or stored.failures.recording != null or stored.failures.cleanup != null)
                            return error.RecordingFailed;
                    },
                    else => {},
                }
                out.complete = true;
            },
        }
    }

    fn armCall(self: *Context, operation: aops.Operation, out: *m.Result) !azure.client.Result {
        return switch (self.arm.execute(operation)) {
            .ok => |result| result: {
                out.effect = if (out.step.mutation()) certainty(result.effect) else .not_applicable;
                out.http_status = result.reply.status;
                break :result result;
            },
            .failed => |failure| {
                out.effect = if (out.step.mutation()) certainty(failure.effect) else .not_applicable;
                out.http_status = failure.diagnostic.http_status;
                out.service_code = failure.diagnostic.service_code;
                if (out.step.cleanup()) out.failures.cleanup = failure.diagnostic else out.failures.primary = failure.diagnostic;
                return error.ArmFailed;
            },
        };
    }

    fn upload(self: *Context, job: m.Job, out: *m.Result) !void {
        var raw = try self.secrets.readSensitive(self.io, self.allocator, if (job.step == .os_upload) "os-grant" else "data-grant", 8192, null);
        defer raw.deinit();
        const target = try splitSas(raw.bytes(), true);
        const source = if (job.step == .os_upload) job.input.guest else job.input.data;
        const description = try local.encode(self.allocator, .{
            .schema = "unikraft.hyperv.managed-disk-page-worker",
            .schema_version = @as(u8, 1),
            .endpoint = target.endpoint,
            .path = source.path,
            .size = source.size,
            .sha256 = source.sha256,
        });
        defer self.allocator.free(description);
        var spec: transfer.job.Spec = .{
            .binding = try core.contracts.parseSha256(&local.hash(description)),
            .value = .{ .pages = try transfer.request.DiskRequest.parse(self.allocator, description) },
        };
        defer spec.deinit();
        const intent: transfer.worker.protocol.Intent = .{
            .attempt_id = try core.contracts.parseSha256(&job.nonce),
            .job_sha256 = try core.contracts.parseSha256(&out.job_sha256),
            .request_sha256 = spec.binding,
            .sas_sha256 = try core.contracts.parseSha256(&local.hash(target.sas)),
            .kind = .pages,
            .plan = spec.plan(),
            .deadline_ns = job.deadline_ns,
            .parent_pid = job.parent_pid,
        };
        var buffer: [2048]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try intent.write(&writer);
        const saved = try self.output_lock.createImmutable(self.io, transfer.job.intent_name, writer.buffered());
        m.merge(&out.failures, saved.failures);
        if (saved.status != .durable or saved.failures.recording != null or saved.failures.cleanup != null) return error.RecordingFailed;
        var journal: transfer.worker.protocol.Journal = .{
            .io = self.io,
            .lock = self.output_lock,
            .plan = spec.plan(),
            .report = transfer.worker.protocol.Report.initial(intent),
        };
        try journal.persist();
        const prior_observer = self.blobs.observer;
        self.blobs.observer = journal.observer();
        defer self.blobs.observer = prior_observer;
        const outcome = self.blobs.uploadPages(.{ .endpoint = target.endpoint, .sas = target.sas }, .{
            .path = source.path,
            .size = source.size,
            .sha256 = try core.contracts.parseSha256(&source.sha256),
        });
        const report = journal.finish(outcome);
        out.transfer = outcome;
        out.effect = outcome.side_effect;
        out.http_status = outcome.diagnostic.status;
        out.service_code = outcome.aggregateDiagnostic().service_code;
        m.merge(&out.failures, try outcome.failureSummary());
        m.merge(&out.failures, report.failures);
        out.page_report = try m.PageReport.capture(report);
        out.transfer = report.outcome;
        out.effect = report.side_effect;
        out.complete = report.outcome != null and report.outcome.?.completion == .complete and
            out.failures.primary == null and out.failures.cleanup == null and out.failures.recording == null;
    }

    fn probe(self: *Context, job: m.Job, out: *m.Result) !void {
        const os = job.step == .os_access_closed or job.step == .cleanup_os_access;
        var raw = try self.secrets.readSensitive(self.io, self.allocator, if (os) "os-grant" else "data-grant", 8192, null);
        defer raw.deinit();
        const target = try splitSas(raw.bytes(), true);
        var uri = try transfer.request.diskUri(self.allocator, target.endpoint, target.sas);
        defer {
            std.crypto.secureZero(u8, uri.bytes);
            uri.deinit();
        }
        var request = sdk.http.Request.init(self.allocator, .GET, uri.bytes);
        defer request.deinit();
        try request.setHeader("Range", "bytes=0-511");
        try request.setHeader("x-ms-version", transfer.client.page_api_version);
        try request.setHeader("Accept-Encoding", "identity");
        request.retryable = false;
        request.redirect_policy = .not_allowed;
        try self.blobs.budget.check();
        request.operation_timeout_ms = self.blobs.budget.deadline_ms - try self.blobs.budget.nowMsFn(self.blobs.budget.context);
        var pipeline = sdk.http.HttpPipeline.init(self.blobs.runtime, &.{});
        const operation = try pipeline.open(&request, .{ .cancellation = self.blobs.budget.cancellation });
        defer operation.deinit();
        defer operation.abort();
        out.http_status = operation.status_code;
        var body: [8193]u8 = undefined;
        defer std.crypto.secureZero(u8, &body);
        var length: usize = 0;
        errdefer {
            if (out.access_metadata == null)
                setAccessMetadata(out, transfer.diagnostic.extract(operation, body[0..@min(length, 8192)], true));
        }
        while (length < body.len) {
            self.blobs.budget.check() catch |err| {
                operation.cancel();
                return err;
            };
            var vectors = [_][]u8{body[length..]};
            const count = operation.body_reader.readVec(&vectors) catch |err| switch (err) {
                error.EndOfStream => {
                    try self.blobs.budget.check();
                    break;
                },
                else => return err,
            };
            self.blobs.budget.check() catch |err| {
                operation.cancel();
                return err;
            };
            length += count;
        }
        const metadata = transfer.diagnostic.extract(operation, body[0..@min(length, 8192)], length > 8192);
        setAccessMetadata(out, metadata);
        if (operation.status_code != 403 or metadata.state != .known or metadata.code != .AuthenticationFailed)
            return error.AccessUnresolved;
        out.access_closed = true;
        out.complete = true;
    }

    fn serial(self: *Context, job: m.Job, out: *m.Result) !void {
        const action: aops.VmAction = .{ .vm = try ref(self.allocator, job.input, .vm, "vm"), .original_uuid = job.originals.vm orelse return error.MissingOriginalIdentity };
        const path = try std.fs.path.join(self.allocator, &.{ self.output_path, "serial.bin" });
        defer self.allocator.free(path);
        for (0..32) |_| {
            var result = try self.armCall(.{ .boot_diagnostics = action }, out);
            defer result.deinit();
            if (result.model != .boot) return error.InvalidSerialResponse;
            const target = try splitSas(result.model.boot.serial, false);
            const slash = std.mem.indexOfScalarPos(u8, target.endpoint, 8, '/') orelse return error.InvalidSas;
            const blob_slash = std.mem.indexOfScalarPos(u8, target.endpoint, slash + 1, '/') orelse return error.InvalidSas;
            const outcome = self.blobs.downloadBlob(.{
                .account_url = target.endpoint[0..slash],
                .container = target.endpoint[slash + 1 .. blob_slash],
                .name = target.endpoint[blob_slash + 1 ..],
                .sas = target.sas,
            }, .{ .path = path, .maximum = c.serial_limit });
            m.merge(&out.failures, try outcome.failureSummary());
            if (outcome.completion != .complete or outcome.sha256 == null) return error.SerialDownloadFailed;
            const budget = self.arm.channel.budget;
            if (outcome.bytes_downloaded > budget.max_total_bytes - budget.bytes) return error.BodyTooLarge;
            budget.bytes += @intCast(outcome.bytes_downloaded);
            const bytes = try self.output.read(self.io, self.allocator, "serial.bin", c.serial_limit, outcome.sha256);
            defer self.allocator.free(bytes);
            const accepted = blk: {
                if (bytes.len == 0) break :blk false;
                const second = job.step == .serial_boot2;
                const segment = if (second) evidence.boot2Suffix(bytes, job.boot1 orelse return error.MissingBoot1) catch |err| switch (err) {
                    error.EvidenceIncomplete => break :blk false,
                    else => return err,
                } else bytes;
                _ = evidence.parse(segment, if (second) 2 else 1, job.input, if (second) job.boot1 else null) catch |err| switch (err) {
                    error.EvidenceIncomplete => break :blk false,
                    else => return err,
                };
                break :blk true;
            };
            if (accepted) {
                out.serial = .{ .name = "serial.bin", .bytes = @intCast(bytes.len), .sha256 = std.fmt.bytesToHex(outcome.sha256.?, .lower) };
                out.complete = true;
                return;
            }
            try self.output.dir.deleteFile(self.io, "serial.bin");
            try budget.sleep(1000);
        }
        return error.EvidenceIncomplete;
    }

    fn absence(self: *Context, job: m.Job, out: *m.Result) !void {
        switch (self.arm.execute(.{ .get = .{ .kind = .group, .name = job.input.authority.group } })) {
            .ok => |value| {
                var present = value;
                defer present.deinit();
                return error.GroupStillPresent;
            },
            .failed => |failure| {
                out.http_status = failure.diagnostic.http_status;
                out.service_code = failure.diagnostic.service_code;
                if (failure.diagnostic.http_status != 404 or failure.diagnostic.service_code != .ResourceGroupNotFound)
                    return error.AbsenceUnproved;
            },
        }
        out.observation.group = .absent;
        out.complete = true;
    }

    fn observe(self: *Context, job: m.Job, out: *m.Result) !void {
        var group = switch (self.arm.execute(.{ .get = .{ .kind = .group, .name = job.input.authority.group } })) {
            .ok => |result| result,
            .failed => |failure| {
                if (job.step == .cleanup_observe and failure.diagnostic.http_status == 404 and failure.diagnostic.service_code == .ResourceGroupNotFound) {
                    out.observation.group = .absent;
                    out.http_status = 404;
                    out.service_code = .ResourceGroupNotFound;
                    out.complete = true;
                    return;
                }
                if (job.step.cleanup()) out.failures.cleanup = failure.diagnostic else out.failures.primary = failure.diagnostic;
                return error.GroupUnproved;
            },
        };
        defer group.deinit();
        if (group.model != .group or (job.step != .cleanup_observe and group.model.group != .succeeded)) return error.GroupUnproved;
        if (!job.group_intent) return error.UnownedResources;
        const group_json = try azureJson(self.allocator, group.reply.body);
        if (!std.mem.eql(u8, try azure.models.string(try azure.models.field(group_json, "tags"), "uk-hyperv-run"), &job.input.authority.owner_run)) return error.UnownedResources;
        out.observation.group = .present;
        var inventory = switch (self.arm.list(.inventory)) {
            .ok => |list| list,
            .failed => |failure| {
                if (job.step.cleanup()) out.failures.cleanup = failure.diagnostic else out.failures.primary = failure.diagnostic;
                return error.InventoryUnproved;
            },
        };
        defer inventory.deinit();
        if (inventory.items.len > 7) return error.UnownedResources;
        var seen: [7]bool = [_]bool{false} ** 7;
        for (inventory.items) |item| {
            if (item != .summary) return error.InvalidInventory;
            const candidate = item.summary.id;
            const expected = [_]azure.scope.Ref{
                try ref(self.allocator, job.input, .disk, "os"),               try ref(self.allocator, job.input, .disk, "data"),
                try ref(self.allocator, job.input, .vm, "vm"),                 try ref(self.allocator, job.input, .nic, "nic"),
                try ref(self.allocator, job.input, .vnet, "vnet"),             try ref(self.allocator, job.input, .nsg, "nsg"),
                try ref(self.allocator, job.input, .deployment, "deployment"),
            };
            var matched: ?usize = null;
            for (expected, 0..) |wanted, index| if (wanted.kind == candidate.kind and std.mem.eql(u8, wanted.name, candidate.name)) {
                matched = index;
            };
            const index = matched orelse return error.UnownedResources;
            if (seen[index]) return error.DuplicateResource;
            const admitted = switch (index) {
                0, 1, 2 => job.creation_intent[index],
                3 => job.network_intent[2],
                4 => job.network_intent[1],
                5 => job.network_intent[0],
                6 => job.creation_intent[2],
                else => unreachable,
            };
            if (!admitted) return error.UnownedResources;
            seen[index] = true;
            var observed = try self.armCall(.{ .get = candidate }, out);
            defer observed.deinit();
            const json = try azureJson(observed.reply.arena.allocator(), observed.reply.body);
            if (candidate.kind != .deployment) {
                if (!std.mem.eql(u8, try azure.models.string(try azure.models.field(json, "tags"), "uk-hyperv-run"), &job.input.authority.owner_run))
                    return error.UnownedResources;
            }
            if (candidate.kind == .disk) {
                if (if (index == 0) job.originals.os != null else job.originals.data != null) {
                    const identity = try diskIdentity(self.allocator, job, index == 0);
                    try azure.models.requireOriginalDisk(observed.model, identity);
                } else if (!job.creation_intent[index]) return error.UnownedResources;
                if (observed.model != .disk or observed.model.disk.bytes != diskBytes(job.input, index == 0)) return error.WrongGeometry;
                try requireDiskReadback(self.allocator, job, index == 0, json, if (job.step == .cleanup_observe) .cleanup else .attached);
                if (index == 0) out.observation.originals.os = observed.model.disk.uuid else out.observation.originals.data = observed.model.disk.uuid;
            } else if (candidate.kind == .vm) {
                if (job.originals.vm) |uuid| try azure.models.requireOriginalVm(observed.model, uuid) else if (!job.creation_intent[2]) return error.UnownedResources;
                if (observed.model != .vm) return error.InvalidVm;
                out.observation.originals.vm = observed.model.vm.uuid;
                try requireVm(self.allocator, job, observed.model.vm, json);
            } else if (candidate.kind == .nsg or candidate.kind == .vnet or candidate.kind == .nic) {
                const definition: aops.PersistenceNetwork = .{
                    .prefix = job.input.prefix,
                    .kind = if (candidate.kind == .nsg) .nsg else if (candidate.kind == .vnet) .vnet else .nic,
                };
                if (job.step == .cleanup_observe)
                    try azure.models.requireOwnedPersistenceNetwork(self.allocator, job.input.authority, definition, json)
                else
                    try azure.models.requirePersistenceNetwork(self.allocator, job.input.authority, definition, json);
            }
        }
        out.observation.owned_inventory = true;
        if (job.step != .cleanup_observe) {
            for (seen[0..6]) |present| if (!present) return error.MissingResource;
            var power = try self.armCall(.{ .instance_view = try ref(self.allocator, job.input, .vm, "vm") }, out);
            defer power.deinit();
            if (power.model != .power) return error.InvalidPower;
            out.observation.power = switch (power.model.power) {
                .running => .running,
                .deallocated => .deallocated,
                else => .unknown,
            };
            out.observation.envelope = true;
        }
        out.complete = true;
    }
    fn uploadedDisks(self: *Context, job: m.Job, out: *m.Result) !void {
        for ([_]bool{ true, false }) |os| {
            const identity = try diskIdentity(self.allocator, job, os);
            var observed = switch (self.arm.execute(.{ .get = identity.disk })) {
                .ok => |result| result,
                .failed => |failure| {
                    out.http_status = failure.diagnostic.http_status;
                    out.service_code = failure.diagnostic.service_code;
                    out.failures.primary = failure.diagnostic;
                    return error.DiskReadbackFailed;
                },
            };
            defer observed.deinit();
            out.http_status = observed.reply.status;
            try azure.models.requireOriginalDisk(observed.model, identity);
            if (observed.model.disk.state != .succeeded or observed.model.disk.access != .unattached)
                return error.InvalidDiskState;
            try requireDiskReadback(self.allocator, job, os, try azureJson(self.allocator, observed.reply.body), .detached);
        }
    }
};

pub fn initial(allocator: std.mem.Allocator, job: m.Job) !m.Result {
    const bytes = try local.encode(allocator, job);
    defer allocator.free(bytes);
    return .{ .job_sha256 = local.hash(bytes), .nonce = job.nonce, .step = job.step, .effect = if (job.step.mutation()) .not_started else .not_applicable };
}
fn setAccessMetadata(out: *m.Result, metadata: transfer.diagnostic.Metadata) void {
    out.access_metadata = metadata;
    out.service_code = switch (metadata.state) {
        .known => metadata.code.?,
        .absent => .unavailable,
        .unknown => .unknown,
        .malformed => .malformed,
        .conflicting => .conflicting,
    };
}

pub fn operationFor(a: std.mem.Allocator, job: m.Job) !aops.Operation {
    const os = job.step == .os_create or job.step == .os_grant or job.step == .os_revoke or job.step == .cleanup_os_revoke;
    return switch (job.step) {
        .group_create => .group_create,
        .os_create, .data_create => .{ .disk_create = .{
            .name = (try ref(a, job.input, .disk, if (os) "os" else "data")).name,
            .size_gib = if (os) @intCast((job.input.guest.size - 513) / (1024 * 1024 * 1024) + 1) else 4,
            .upload_bytes = if (os) job.input.guest.size else job.input.data.size,
            .linux_gen2 = os,
        } },
        .os_grant, .data_grant => .{ .grant = .{ .identity = try diskIdentity(a, job, os), .seconds = job.input.grant_seconds } },
        .os_revoke, .data_revoke, .cleanup_os_revoke, .cleanup_data_revoke => .{ .revoke = try diskIdentity(a, job, os) },
        .network_nsg, .network_vnet, .network_nic => .{ .persistence_network = .{ .prefix = job.input.prefix, .kind = if (job.step == .network_nsg) .nsg else if (job.step == .network_vnet) .vnet else .nic } },
        .deploy_boot1 => deploy: {
            const resources = try a.alloc(aops.Resource, 1);
            resources[0] = .{ .vm = .{
                .name = (try ref(a, job.input, .vm, "vm")).name,
                .os_disk = try diskIdentity(a, job, true),
                .data_disk = try diskIdentity(a, job, false),
                .nic = try ref(a, job.input, .nic, "nic"),
                .size = "Standard_D2s_v5",
                .persistence_envelope = true,
            } };
            break :deploy .{ .deploy = .{ .name = (try ref(a, job.input, .deployment, "deployment")).name, .resources = resources } };
        },
        .deallocate_boot1, .deallocate_boot2, .cleanup_deallocate => .{ .deallocate = .{
            .vm = try ref(a, job.input, .vm, "vm"),
            .original_uuid = job.originals.vm orelse return error.MissingOriginalIdentity,
        } },
        .start_boot2 => .{ .start = .{
            .vm = try ref(a, job.input, .vm, "vm"),
            .original_uuid = job.originals.vm orelse return error.MissingOriginalIdentity,
        } },
        .cleanup_delete => .group_delete,
        else => error.NotArmOperation,
    };
}
fn ref(a: std.mem.Allocator, input: c.Contract, kind: azure.scope.Kind, suffix: []const u8) !azure.scope.Ref {
    return .{ .kind = kind, .name = try std.fmt.allocPrint(a, "{s}-{s}", .{ input.prefix, suffix }) };
}
fn diskIdentity(a: std.mem.Allocator, job: m.Job, os: bool) !aops.DiskIdentity {
    return .{
        .disk = try ref(a, job.input, .disk, if (os) "os" else "data"),
        .original_uuid = (if (os) job.originals.os else job.originals.data) orelse return error.MissingOriginalIdentity,
        .geometry = .{ .sectors = diskBytes(job.input, os) / 512, .sector_size = 512 },
    };
}
fn diskBytes(input: c.Contract, os: bool) u64 {
    return if (os) input.guest.size - 512 else c.data_bytes;
}
pub fn requireDiskReadback(a: std.mem.Allocator, job: m.Job, os: bool, value: std.json.Value, attachment: enum { detached, attached, cleanup }) !void {
    const properties = try azure.models.field(value, "properties");
    if (try core.contracts.integer(u64, try azure.models.field(properties, "diskSizeBytes")) != diskBytes(job.input, os))
        return error.WrongGeometry;
    if (os) {
        if (!std.mem.eql(u8, try azure.models.string(properties, "osType"), "Linux") or
            !std.mem.eql(u8, try azure.models.string(properties, "hyperVGeneration"), "V2")) return error.InvalidDiskRole;
    } else if (properties.object.get("osType")) |role| {
        if (role != .null and !(role == .string and role.string.len == 0)) return error.InvalidDiskRole;
    }
    const managed = value.object.get("managedBy") orelse .null;
    const detached = managed == .null or (managed == .string and managed.string.len == 0);
    if ((attachment == .attached and detached) or (attachment == .detached and !detached)) return error.InvalidAttachment;
    if (!detached) {
        if (!job.creation_intent[2]) return error.InvalidAttachment;
        try (try ref(a, job.input, .vm, "vm")).requireId(a, job.input.authority, try core.contracts.string(managed));
    }
}
fn splitSas(raw: []const u8, disk: bool) !struct { endpoint: []const u8, sas: []const u8 } {
    try azure.models.sasUri(raw, disk);
    const question = std.mem.indexOfScalar(u8, raw, '?') orelse return error.InvalidSas;
    const sas = raw[question + 1 ..];
    if (!transfer.request.validSas(sas)) return error.InvalidSas;
    return .{ .endpoint = raw[0..question], .sas = sas };
}
fn certainty(effect: azure.transport.Effect) transfer.diagnostic.Certainty {
    return switch (effect) {
        .accepted => .accepted,
        .rejected => .rejected,
        .unknown => .unknown,
        .not_started => .not_started,
        .not_applicable => .not_applicable,
    };
}
fn azureJson(a: std.mem.Allocator, bytes: []const u8) !std.json.Value {
    // ARM already validated its bounded remote JSON profile; retain its original
    // value for the additional controller-specific ownership/envelope predicates.
    return std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{ .allocate = .alloc_always, .parse_numbers = false });
}
fn requireVm(a: std.mem.Allocator, job: m.Job, vm: azure.models.Vm, value: std.json.Value) !void {
    if (!std.mem.eql(u8, vm.size, "Standard_D2s_v5") or vm.data_disk == null) return error.InvalidEnvelope;
    try (try ref(a, job.input, .disk, "os")).requireId(a, job.input.authority, try vm.os_disk.path(a, job.input.authority));
    try (try ref(a, job.input, .disk, "data")).requireId(a, job.input.authority, try vm.data_disk.?.path(a, job.input.authority));
    try (try ref(a, job.input, .nic, "nic")).requireId(a, job.input.authority, try vm.nic.path(a, job.input.authority));
    const p = try azure.models.field(value, "properties");
    const storage = try azure.models.field(p, "storageProfile");
    const os = try azure.models.field(storage, "osDisk");
    const data = (try azure.models.array(try azure.models.field(storage, "dataDisks")))[0];
    if (!std.mem.eql(u8, try azure.models.string(os, "caching"), "ReadOnly") or
        !std.mem.eql(u8, try azure.models.string(os, "deleteOption"), "Detach") or
        !std.mem.eql(u8, try azure.models.string(data, "deleteOption"), "Detach") or
        !std.mem.eql(u8, try azure.models.string(data, "caching"), "None") or
        try azure.models.boolean(try azure.models.field(data, "writeAcceleratorEnabled")))
        return error.InvalidEnvelope;
    const nic = (try azure.models.array(try azure.models.field(try azure.models.field(p, "networkProfile"), "networkInterfaces")))[0];
    const nic_properties = try azure.models.field(nic, "properties");
    if (!try azure.models.boolean(try azure.models.field(nic_properties, "primary")) or
        !std.mem.eql(u8, try azure.models.string(nic_properties, "deleteOption"), "Delete")) return error.InvalidEnvelope;
    const diagnostics = try azure.models.field(try azure.models.field(p, "diagnosticsProfile"), "bootDiagnostics");
    if (!try azure.models.boolean(try azure.models.field(diagnostics, "enabled"))) return error.InvalidEnvelope;
}
