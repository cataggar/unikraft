const std = @import("std");
const core = @import("hyperv_core");
const p = @import("protocol.zig");
const state = @import("state.zig");
const files = @import("files.zig");
const boot = @import("boot.zig");
const wire = @import("wire.zig");

/// Native CLI uses separate supervised wire children; fixtures inject a streaming
/// transport into these same operations, never a production credential fallback.
pub const Remote = struct {
    context: *anyopaque,
    fetchFn: *const fn (*anyopaque, p.Phase) anyerror![]u8,
    downloadFn: *const fn (*anyopaque, *const p.Command, p.Artifact, []const u8) anyerror!void,
    publishFn: *const fn (*anyopaque, *const p.Command, []const u8, []const u8) wire.PublishResult,
    failuresFn: *const fn (*anyopaque) core.diagnostics.Failures,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    key: [32]u8,
    admission: *const p.Admission,
    scope: p.Scope,
    vm_id: p.Uuid,
    clock_context: *anyopaque,
    nowFn: *const fn (*anyopaque) anyerror!u64,
    remote: Remote,
    runner: boot.Runner,
    store: *state.Store,

    pub fn execute(self: *Engine, bytes: []const u8) !void {
        var command = try p.Command.parse(self.allocator, bytes, self.key, self.admission, self.scope, self.vm_id, try self.nowFn(self.clock_context));
        defer command.deinit();
        try self.store.begin(&command, bytes);
        var outcomes: [4]boot.Outcome = undefined;
        var count: usize = 0;
        self.stage(&command) catch {
            var failures = self.remote.failuresFn(self.remote.context);
            if (failures.primary == null) failures.primary = .{ .stage = .blob_download, .category = .integrity };
            self.store.fail(failures);
            try self.publish(&command, outcomes[0..count], false);
            return error.PhaseFailed;
        };
        const image_roles: []const p.Role = if (command.phase == .public) &.{.capability_raw} else &.{ .raw, .vhd };
        outer: for (image_roles) |role| {
            for ([_]bool{ false, true }) |legacy| {
                const now = try self.nowFn(self.clock_context);
                if (now >= command.expires_at) {
                    self.store.fail(.{ .primary = .{ .stage = .host_phase, .category = .timeout } });
                    break :outer;
                }
                var runner = self.runner;
                const authorization_deadline = try core.process.Deadline.afterMilliseconds(@min(p.boot_ms, (command.expires_at - now) * 1000));
                runner.attempt_deadline.expires_ns = @min(runner.attempt_deadline.expires_ns, authorization_deadline.expires_ns);
                const outcome = runner.run(self.store, &command, command.artifact(role), legacy) catch {
                    self.store.fail(.{ .primary = .{ .stage = .host_phase, .category = .local_io } });
                    break :outer;
                };
                outcomes[count] = outcome;
                count += 1;
                if (!outcome.passed) break :outer;
            }
        }
        const expected: usize = if (command.phase == .public) 2 else 4;
        const passed = count == expected and self.store.record.stage != .failed;
        try self.publish(&command, outcomes[0..count], passed);
        if (!passed) return error.PhaseFailed;
    }

    fn stage(self: *Engine, command: *const p.Command) !void {
        // begin() has already verified the exact published public receipt and
        // signed parent acceptance before this function can see private bytes.
        for (command.artifacts) |artifact| {
            if (try self.nowFn(self.clock_context) >= command.expires_at) return error.StaleCommand;
            const is_private = artifact.role == .raw or artifact.role == .vhd;
            if (command.phase == .private and !is_private) {
                const existing = try files.verify(self.allocator, self.io, self.runner.artifact_root, artifact, 1);
                existing.close(self.io);
                continue;
            }
            if (is_private and self.store.record.stage != .private_intent) return error.PrematurePrivateTransfer;
            try self.store.reserve(artifact.size, false, false);
            const container = try files.parent(self.allocator, self.io, self.runner.artifact_root, artifact.name, true);
            defer container.close(self.io);
            const file = try container.directory.dir.createFile(self.io, container.name, .{ .read = true, .exclusive = true, .permissions = .fromMode(0o600) });
            defer file.close(self.io);
            const path = try std.fs.path.join(self.allocator, &.{ self.runner.artifact_root, artifact.name });
            defer self.allocator.free(path);
            try self.remote.downloadFn(self.remote.context, command, artifact, path);
            if (!std.mem.eql(u8, &try files.digest(self.io, file, artifact.size), &artifact.sha256)) return error.ArtifactIntegrity;
            if (artifact.role == .vhd) try files.verifyVhd(self.io, file, command.raw_size, command.image_sha256);
            if (artifact.role == .qemu) {
                try file.setPermissions(self.io, .fromMode(0o700));
                try file.sync(self.io);
            }
            try files.syncDirectory(self.io, container.directory.dir);
        }
    }

    fn publish(self: *Engine, command: *const p.Command, outcomes: []const boot.Outcome, passed: bool) !void {
        var publication: state.Publication = .not_started;
        for (outcomes) |outcome| {
            if (outcome.serial_bytes == 0) continue;
            var name_buffer: [16]u8 = undefined;
            const local = try std.fmt.bufPrint(&name_buffer, "boot-{d}", .{outcome.index});
            const path = try std.fs.path.join(self.allocator, &.{ self.runner.work_root, local });
            defer self.allocator.free(path);
            const directory = try core.private_files.Directory.open(self.io, path);
            defer directory.close(self.io);
            const bytes = try directory.read(self.io, self.allocator, "serial.log", p.max_serial, try core.contracts.parseSha256(&outcome.serial_sha256));
            defer {
                std.crypto.secureZero(u8, bytes);
                self.allocator.free(bytes);
            }
            try self.store.reserve(bytes.len, false, true);
            var blob_buffer: [16]u8 = undefined;
            const name = try std.fmt.bufPrint(&blob_buffer, "boot-{d}.log", .{outcome.index});
            const result = self.remote.publishFn(self.remote.context, command, name, bytes);
            publication = result.publication;
            if (publication != .complete) {
                self.store.record.publication = publication;
                self.store.fail(.{ .recording = result.failure orelse .{ .stage = .blob_upload, .category = .ambiguous } });
                return error.EvidencePublicationFailed;
            }
        }
        const receipt = .{
            .schema = "uk-hyperv-host-evidence-v1",
            .evidence_kind = self.runner.evidence_kind,
            .phase = command.phase,
            .run_id = &p.uuidText(self.scope.run_id),
            .vm_id = &p.uuidText(self.vm_id),
            .phase_nonce = &p.uuidText(command.phase_nonce),
            .host_boot_id = &p.uuidText(self.store.record.host_boot_id),
            .command_sha256 = &p.hex(command.verified.digest),
            .manifest_sha256 = &p.hex(command.manifest_sha256),
            .runner_sha256 = &p.hex(self.admission.runner_sha256),
            .image_sha256 = &p.hex(command.image_sha256),
            .host_image_sha256 = &p.hex(self.admission.host_image_sha256),
            .scope = "platform-only",
            .status = if (passed) "PASS" else "FAIL",
            .boots = outcomes,
            .failures = self.store.record.failures,
            .staging_bytes_reserved_before_receipt = self.store.record.staging_bytes,
            .control_bytes_reserved_before_receipt = self.store.record.control_bytes,
            .evidence_bytes_reserved_before_receipt = self.store.record.evidence_bytes,
        };
        const bytes = try self.store.encode(receipt);
        defer self.allocator.free(bytes);
        try self.store.reserve(bytes.len * 2, true, true);
        try self.store.immutable(if (command.phase == .public) "public-receipt.json" else "private-receipt.json", bytes);
        const result = self.remote.publishFn(self.remote.context, command, "receipt.json", bytes);
        self.store.record.publication = result.publication;
        if (result.publication != .complete) {
            self.store.fail(.{ .recording = result.failure orelse .{ .stage = .blob_upload, .category = .ambiguous } });
            return error.EvidencePublicationFailed;
        }
        if (passed) try self.store.complete(command.phase, p.hash(bytes)) else try self.store.save();
    }
};
