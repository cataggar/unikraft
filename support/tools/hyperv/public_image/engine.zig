const std = @import("std");
const c = @import("contracts.zig");
const f = @import("files.zig");
const p = c.core.private_files;
const network = @import("network.zig");
const package = @import("package.zig");
pub const Options = struct { self_executable: []const u8, cancel: ?*const std.atomic.Value(bool) = null };

pub fn clean(failures: c.core.diagnostics.Failures) bool {
    return failures.primary == null and failures.cleanup == null and failures.recording == null;
}
fn save(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, state: c.State) !void {
    const bytes = try c.encode(a, state);
    defer a.free(bytes);
    try f.durable(try lock.commit(io, "state.json", bytes));
}
pub fn prepare(a: std.mem.Allocator, io: std.Io, input: c.Input, options: Options) !c.State {
    try input.validate();
    const inputs: c.Inputs = .{
        .efi = try f.record(a, io, input.efi, c.max_efi, false),
        .qemu = try f.record(a, io, input.qemu, c.max_tool, true),
        .code = try f.record(a, io, input.ovmf_code, c.boot.config.max_firmware, false),
        .vars = try f.record(a, io, input.ovmf_vars, c.boot.config.max_vars, false),
        .producer = try f.record(a, io, options.self_executable, c.max_tool, true),
        .solved_config = if (input.solved_config) |path| try f.record(a, io, path, c.max_config, false) else null,
    };
    var state: c.State = .{ .input = input, .inputs = inputs, .acceptance = if (inputs.solved_config) |config|
        try network.fromConfig(a, try f.readArtifact(a, io, config, c.max_config))
    else
        try network.raw(a) };
    try state.validate();
    const root = try f.create(io, input.state_dir);
    defer root.close(io);
    var lock = try root.lock(io);
    var release = true;
    defer if (release) lock.close(io);
    try f.immutable(a, io, &lock, "prepare.json", state);
    try save(a, io, &lock, state);
    perform(a, io, &lock, &state, options, &release) catch {
        if (clean(state.failures)) try state.failures.record(.primary, .{ .stage = .inspection, .category = .invalid_response });
    };
    if (release) f.cleanupStage(io, root, "package-stage") catch {
        try state.failures.record(.cleanup, .{ .stage = .cleanup, .category = .cleanup_failed });
    };
    state.phase = if (clean(state.failures)) .prepared else .failed;
    save(a, io, &lock, state) catch {
        state.phase = .failed;
        try state.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
    };
    return state;
}
fn perform(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, state: *c.State, options: Options, release: *bool) !void {
    const job: @import("worker.zig").Job = .{ .supervisor_pid = @intCast(std.os.linux.getpid()), .state_dir = state.input.state_dir, .efi = state.inputs.efi, .producer = state.inputs.producer };
    try f.immutable(a, io, lock, "package-job.json", job);
    var environment: std.process.Environ.Map = .init(a);
    defer environment.deinit();
    try environment.put("TMPDIR", state.input.state_dir);
    var packaged = try c.core.process.run(a, io, .{ .argv = &.{ options.self_executable, "--package-worker" }, .environment = &environment, .cwd = lock.directory.dir, .deadline = try c.core.process.Deadline.afterMilliseconds(c.package_timeout_ms), .cleanup_ms = c.boot.config.cleanup_ms, .stdout_limit = 0, .stderr_limit = 0, .cancel = options.cancel });
    defer packaged.deinit(a);
    state.failures = packaged.failures;
    if (!packaged.cleanup_complete) {
        release.* = false;
        return error.UnresolvedCleanup;
    }
    if (!clean(state.failures) or packaged.termination == null or packaged.termination.? != .exited or packaged.termination.?.exited != 0)
        return error.PackageFailed;
    const report_bytes = try lock.directory.read(io, a, "package-report.json", c.max_record, null);
    state.package = try c.read(package.Report, a, report_bytes);
    try f.same(a, try package.observe(a, io, lock.directory, state.inputs.efi), state.package.?);
    try f.immutable(a, io, lock, "packaging.json", state.package.?.packaging);
    try f.cleanupStage(io, lock.directory, "package-stage");
    try progress(a, io, lock, state);
    for (0..4) |index| {
        const config = try bootConfig(a, state.*, index);
        const work = try f.create(io, config.work_dir);
        work.close(io);
        const booted = try c.boot.runner.run(a, io, config, .{ .self_executable = options.self_executable, .cancel = options.cancel });
        state.failures = booted.failures;
        if (!booted.cleanup_complete) release.* = false;
        if (booted.cleanup_complete) {
            retainSerial(a, io, lock.directory, config, index) catch {
                try state.failures.record(.recording, .{ .stage = .serial_evidence, .category = .local_io });
            };
        }
        if (!booted.succeeded() or !clean(state.failures)) return error.BootFailed;
        state.boots[index] = evidence(a, io, state.*, index, null) catch {
            try state.failures.record(.primary, .{ .stage = .serial_evidence, .category = .invalid_response });
            return error.InvalidSerial;
        };
        try progress(a, io, lock, state);
    }
    try verifyInputs(a, io, state.inputs);
}
fn progress(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, state: *c.State) !void {
    save(a, io, lock, state.*) catch {
        try state.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
        return error.RecordingFailed;
    };
}
fn retainSerial(a: std.mem.Allocator, io: std.Io, root: p.Directory, config: c.boot.config.Config, index: usize) !void {
    const serial_file = try f.record(a, io, try f.path(a, config.work_dir, c.boot.config.log_name), c.boot.config.max_serial, false);
    const name = try std.fmt.allocPrint(a, "local-{s}-serial.log", .{c.modes[index]});
    try f.copy(io, serial_file, root, name);
}
pub fn bootConfig(a: std.mem.Allocator, state: c.State, index: usize) !c.boot.config.Config {
    if (index >= 4 or state.package == null) return error.InvalidMatrix;
    return .{
        .raw_disk = if (index < 2) state.package.?.raw.path else null,
        .fixed_vhd = if (index >= 2) state.package.?.vhd.path else null,
        .qemu = state.inputs.qemu.path,
        .ovmf_code = state.inputs.code.path,
        .ovmf_vars = state.inputs.vars.path,
        .work_dir = try f.path(a, state.input.state_dir, try std.fmt.allocPrint(a, "boot-{s}", .{c.modes[index]})),
        .expect = state.input.expect,
        .expect_main_return = 2,
        .timeout_ms = state.input.timeout_ms,
        .disable_x2apic = index % 2 == 1,
    };
}
fn evidence(a: std.mem.Allocator, io: std.Io, state: c.State, index: usize, expected: ?c.Boot) !c.Boot {
    const config = try bootConfig(a, state, index);
    const work = try p.Directory.open(io, config.work_dir);
    defer work.close(io);
    const requested = try work.read(io, a, "request.json", c.max_record, if (expected) |e| try c.sha(e.request_sha256) else null);
    const request = try c.read(c.boot.runner.Request, a, requested);
    try request.validate();
    try f.same(a, config, request.config);
    const inputs = [_]c.File{ if (index < 2) state.package.?.raw else state.package.?.vhd, state.inputs.code, state.inputs.vars, state.inputs.qemu };
    for (inputs, request.pins) |file, pin|
        if (file.size != pin.size or !std.mem.eql(u8, &try c.sha(file.sha256), &pin.sha256)) return error.WrongBootInput;
    const launched = try work.read(io, a, "launched", 1, null);
    if (launched.len != 0) return error.InvalidLaunch;
    const recorded = try work.read(io, a, "report.json", c.max_record, if (expected) |e| try c.sha(e.report_sha256) else null);
    const report = try c.boot.runner.Report.decode(a, recorded);
    if (!report.succeeded()) return error.IncompleteBoot;
    const serial = try work.read(io, a, c.boot.config.log_name, c.boot.config.max_serial, report.serial_sha256);
    defer a.free(serial);
    if (serial.len != report.serial_bytes) return error.SerialChanged;
    try network.serial(a, serial, config, state.acceptance);
    const result: c.Boot = .{ .index = @intCast(index), .request_sha256 = try c.hex(a, c.hash(requested)), .report_sha256 = try c.hex(a, c.hash(recorded)), .serial_sha256 = try c.hex(a, c.hash(serial)), .serial_bytes = serial.len };
    if (expected) |e| try f.same(a, result, e);
    return result;
}
fn verifyInputs(a: std.mem.Allocator, io: std.Io, inputs: c.Inputs) !void {
    try f.verify(a, io, inputs.efi, c.max_efi, false);
    try f.verify(a, io, inputs.qemu, c.max_tool, true);
    try f.verify(a, io, inputs.code, c.boot.config.max_firmware, false);
    try f.verify(a, io, inputs.vars, c.boot.config.max_vars, false);
    try f.verify(a, io, inputs.producer, c.max_tool, true);
    if (inputs.solved_config) |file| try f.verify(a, io, file, c.max_config, false);
}
/// Caller holds the original stable writer lock throughout load and export.
/// Physical public build evidence is not an unforgeable host-admission capability.
pub fn load(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, self_executable: []const u8) !c.State {
    const root = lock.directory;
    const bytes = try root.read(io, a, "state.json", c.max_record, null);
    const state = try c.read(c.State, a, bytes);
    try state.validate();
    if (state.phase != .prepared or !clean(state.failures) or state.package == null) return error.NotPrepared;
    for (state.boots, 0..) |maybe, index| {
        const boot = maybe orelse return error.IncompleteMatrix;
        if (boot.index != index or boot.serial_bytes == 0 or boot.serial_bytes >= c.boot.config.max_serial) return error.IncompleteMatrix;
        _ = try c.sha(boot.request_sha256);
        _ = try c.sha(boot.report_sha256);
        _ = try c.sha(boot.serial_sha256);
    }
    var path_buffer: [4096]u8 = undefined;
    if (!std.mem.eql(u8, state.input.state_dir, path_buffer[0..try root.dir.realPath(io, &path_buffer)]) or
        !std.mem.eql(u8, self_executable, state.inputs.producer.path)) return error.SourceChanged;
    try verifyInputs(a, io, state.inputs);
    var initial = state;
    initial.phase = .preparing;
    initial.package = null;
    initial.boots = .{ null, null, null, null };
    try f.same(a, initial, try c.read(c.State, a, try root.read(io, a, "prepare.json", c.max_record, null)));
    const job = try c.read(@import("worker.zig").Job, a, try root.read(io, a, "package-job.json", c.max_record, null));
    if (job.schema_version != 1 or job.supervisor_pid == 0 or !std.mem.eql(u8, job.state_dir, state.input.state_dir)) return error.InvalidPackage;
    try f.same(a, state.inputs.efi, job.efi);
    try f.same(a, state.inputs.producer, job.producer);
    if ((try root.read(io, a, "package-launched", 1, null)).len != 0) return error.InvalidPackage;
    const physical = try package.observe(a, io, root, state.inputs.efi);
    try f.same(a, physical, state.package.?);
    try f.same(a, physical, try c.read(package.Report, a, try root.read(io, a, "package-report.json", c.max_record, null)));
    try f.same(a, physical.packaging, try c.read(package.Packaging, a, try root.read(io, a, "packaging.json", c.max_record, null)));
    const private_efi = try root.openFile(io, "BOOTX64.EFI");
    defer private_efi.close(io);
    const copied = try f.record(a, io, try f.path(a, state.input.state_dir, "BOOTX64.EFI"), c.max_efi, false);
    if (copied.size != state.inputs.efi.size or !std.mem.eql(u8, copied.sha256, state.inputs.efi.sha256)) return error.SourceChanged;
    try f.same(a, state.acceptance, if (state.inputs.solved_config) |config|
        try network.fromConfig(a, try f.readArtifact(a, io, config, c.max_config))
    else
        try network.raw(a));
    for (0..4) |index| {
        const expected = state.boots[index] orelse return error.IncompleteMatrix;
        _ = try evidence(a, io, state, index, expected);
        const alias = try root.read(io, a, try std.fmt.allocPrint(a, "local-{s}-serial.log", .{c.modes[index]}), c.boot.config.max_serial, try c.sha(expected.serial_sha256));
        defer a.free(alias);
        if (alias.len != expected.serial_bytes) return error.SerialChanged;
    }
    return state;
}
