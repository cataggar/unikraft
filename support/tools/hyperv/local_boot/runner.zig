const std = @import("std");
const core = @import("hyperv_core");
const c = @import("config.zig");
const files = @import("files.zig");
const serial = @import("serial.zig");

pub const Request = struct {
    schema_version: u8 = 1,
    supervisor_pid: u32,
    config: c.Config,
    pins: [4]files.Pin,

    pub fn validate(self: Request) !void {
        if (self.schema_version != 1 or self.supervisor_pid < 1) return error.InvalidRequest;
        try self.config.validate();
        for (self.pins, 0..) |pin, i| {
            const maximum: u64 = if (i == 1) c.max_firmware else if (i == 2) c.max_vars else c.max_input;
            if (pin.size == 0 or pin.size > maximum) return error.InvalidRequest;
        }
    }
};

pub const Report = struct {
    failures: core.diagnostics.Failures = .{},
    consumed: bool = false,
    cleanup_complete: bool = true,
    input_unchanged: bool = false,
    serial_valid: bool = false,
    serial_limit_reached: bool = false,
    serial_bytes: u64 = 0,
    serial_sha256: ?[32]u8 = null,
    termination: ?std.process.Child.Term = null,

    pub fn succeeded(self: Report) bool {
        return self.consumed and self.cleanup_complete and self.input_unchanged and self.serial_valid and !self.serial_limit_reached and
            self.serial_sha256 != null and self.serial_bytes > 0 and self.serial_bytes < c.max_serial and
            self.termination != null and self.termination.? == .exited and self.termination.?.exited == 0 and
            self.failures.primary == null and self.failures.cleanup == null and self.failures.recording == null;
    }

    pub fn encode(self: Report, a: std.mem.Allocator) ![]u8 {
        const hex = if (self.serial_sha256) |hash| std.fmt.bytesToHex(hash, .lower) else null;
        return c.encode(a, .{
            .schema_version = @as(u8, 1),
            .scope = "public_local_qemu_only",
            .acceptance = "not_established",
            .passed = self.succeeded(),
            .consumed = self.consumed,
            .cleanup_complete = self.cleanup_complete,
            .input_unchanged = self.input_unchanged,
            .serial_valid = self.serial_valid,
            .serial_limit_reached = self.serial_limit_reached,
            .serial_bytes = self.serial_bytes,
            .serial_sha256 = if (hex) |*value| @as(?[]const u8, value) else null,
            .failures = self.failures,
            .termination = self.termination,
        });
    }
};

pub const Options = struct {
    self_executable: []const u8,
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// Dedicated supervisor only: caller must initialize core.process first.
/// Each existing 0700 work directory is consumed once, even on failure.
pub fn run(a: std.mem.Allocator, io: std.Io, config: c.Config, options: Options) !Report {
    try config.validate();
    try core.private_files.absoluteFilePath(options.self_executable);
    for (config.paths()) |path| {
        if (std.mem.startsWith(u8, path, config.work_dir) and
            (path.len == config.work_dir.len or path[config.work_dir.len] == '/')) return error.InputInsideWorkspace;
    }
    const work = try core.private_files.Directory.open(io, config.work_dir);
    defer work.close(io);
    var lock = try work.lock(io);
    var release = true;
    defer if (release) lock.close(io);
    var entries = work.dir.iterate();
    while (try entries.next(io)) |entry| if (!std.mem.eql(u8, entry.name, ".writer.lock")) return error.WorkspaceConsumed;
    const originals = try files.Set.open(io, config);
    defer originals.close(io);
    const request: Request = .{ .supervisor_pid = @intCast(std.os.linux.getpid()), .config = config, .pins = originals.pins() };
    const encoded = try c.encode(a, request);
    defer a.free(encoded);
    try files.durable(try lock.createImmutable(io, "request.json", encoded));
    var report: Report = .{ .consumed = true };
    var environment: std.process.Environ.Map = .init(a);
    defer environment.deinit();
    const deadline = try core.process.Deadline.afterMilliseconds(config.timeout_ms);
    if (core.process.run(a, io, .{
        .argv = &.{ options.self_executable, "--exec" },
        .environment = &environment,
        .cwd = work.dir,
        .deadline = deadline,
        .cleanup_ms = c.cleanup_ms,
        .stdout_limit = 0,
        .stderr_limit = 0,
        .cancel = options.cancel,
    })) |value| {
        var result = value;
        defer result.deinit(a);
        report.failures = result.failures;
        report.termination = result.termination;
        report.cleanup_complete = result.cleanup_complete;
    } else |_| {
        try report.failures.record(.primary, .{ .stage = .process_spawn, .category = .spawn_failed });
    }
    if (!report.cleanup_complete) {
        // Preserve writer custody in this poisoned supervisor. Never clean files
        // while descendants may still be using them, and never offer replay.
        release = false;
        return report;
    }
    if (work.openFile(io, c.log_name)) |log| {
        defer log.close(io);
        log.sync(io) catch {
            try report.failures.record(.recording, .{ .stage = .serial_evidence, .category = .local_io });
        };
        if (work.read(io, a, c.log_name, c.max_serial, null)) |bytes| {
            defer a.free(bytes);
            report.serial_bytes = bytes.len;
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
            report.serial_sha256 = hash;
            // A full file might end at the cap while the last write failed.
            if (bytes.len == c.max_serial) {
                report.serial_limit_reached = true;
                try report.failures.record(.primary, .{ .stage = .serial_evidence, .category = .output_limit });
            } else if (serial.validate(a, bytes, config)) |_| {
                report.serial_valid = true;
            } else |_| {
                try report.failures.record(.primary, .{ .stage = .serial_evidence, .category = .invalid_response });
            }
        } else |_| {
            try report.failures.record(.recording, .{ .stage = .serial_evidence, .category = .local_io });
        }
    } else |_| {
        try report.failures.record(.recording, .{ .stage = .serial_evidence, .category = .local_io });
    }
    if (originals.verify(io, config)) |_| {
        report.input_unchanged = true;
    } else |_| {
        try report.failures.record(.primary, .{ .stage = .private_file, .category = .integrity });
    }
    files.cleanup(io, work, config.image != null) catch {
        try report.failures.record(.cleanup, .{ .stage = .cleanup, .category = .cleanup_failed });
    };
    const output = report.encode(a) catch {
        try report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
        return report;
    };
    defer a.free(output);
    if (lock.createImmutable(io, "report.json", output)) |committed| {
        files.durable(committed) catch {
            try report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
        };
    } else |_| {
        try report.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
    }
    return report;
}
