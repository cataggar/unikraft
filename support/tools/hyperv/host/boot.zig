const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");
const p = @import("protocol.zig");
const files = @import("files.zig");
const serial = @import("serial.zig");
const state = @import("state.zig");

pub const cpu_features = "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies";
pub const EvidenceKind = enum { qemu_kvm, synthetic_child };
pub const Outcome = struct {
    evidence_kind: EvidenceKind,
    index: u8,
    host_boot_id: [36]u8,
    launch_id: [36]u8,
    image_sha256: [64]u8,
    serial_sha256: [64]u8,
    serial_bytes: u64,
    legacy_apic: bool,
    passed: bool,
    failures: core.diagnostics.Failures,
};

pub const Execution = struct {
    argv: []const []const u8,
    library_path: []const u8,
    qemu_sha256: p.Hash,
    qemu_size: u64,
};

pub fn arguments(allocator: std.mem.Allocator, artifact_root: []const u8, raw_size: u64, legacy_apic: bool) ![]const []const u8 {
    const qemu = try std.fs.path.join(allocator, &.{ artifact_root, "qemu/bin/qemu-system-x86_64" });
    const share = try std.fs.path.join(allocator, &.{ artifact_root, "qemu/share" });
    const code = try std.fmt.allocPrint(allocator, "if=pflash,format=raw,readonly=on,file={s}/OVMF_CODE.fd", .{artifact_root});
    const block = try std.fmt.allocPrint(allocator, "{{\"driver\":\"raw\",\"node-name\":\"hyperv-disk\",\"offset\":0,\"size\":{d},\"read-only\":true,\"file\":{{\"driver\":\"file\",\"filename\":\"disk.img\",\"read-only\":true}}}}", .{raw_size});
    return allocator.dupe([]const u8, &.{
        qemu,                  "-machine", "q35,accel=kvm", "-cpu",                             if (legacy_apic) cpu_features ++ ",x2apic=off" else cpu_features,
        "-L",                  share,      "-smp",          "1",                                "-m",
        "512M",                "-drive",   code,            "-drive",                           "if=pflash,format=raw,file=OVMF_VARS.fd",
        "-blockdev",           block,      "-device",       "virtio-blk-pci,drive=hyperv-disk", "-device",
        "vmbus-bridge,irq=15", "-display", "none",          "-serial",                          "stdio",
        "-monitor",            "none",     "-no-reboot",    "-nic",                             "none",
    });
}

pub const Runner = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    self_executable: []const u8,
    artifact_root: []const u8,
    work_root: []const u8,
    attempt_deadline: core.process.Deadline,
    boot_timeout_ms: u32 = p.boot_ms,
    cleanup_timeout_ms: u32 = p.cleanup_ms,
    evidence_kind: EvidenceKind = .qemu_kvm,

    pub fn run(self: *Runner, store: *state.Store, command: *const p.Command, image: p.Artifact, legacy_apic: bool) !Outcome {
        if (self.boot_timeout_ms == 0 or self.boot_timeout_ms > p.boot_ms or self.cleanup_timeout_ms < 100 or self.cleanup_timeout_ms > p.cleanup_ms) return error.InvalidDeadline;
        if (try self.attempt_deadline.expired()) return error.AttemptExpired;
        const boot_id = try files.hostBootId(self.io);
        if (!std.mem.eql(u8, &boot_id, &store.record.host_boot_id)) return error.HostBootChanged;
        const index = try store.bootIntent(command.phase);
        var random: p.Uuid = undefined;
        self.io.random(&random);
        random[6] = (random[6] & 15) | 0x40;
        random[8] = (random[8] & 63) | 0x80;
        var outcome: Outcome = .{ .evidence_kind = self.evidence_kind, .index = index, .host_boot_id = p.uuidText(boot_id), .launch_id = p.uuidText(random), .image_sha256 = p.hex(image.sha256), .serial_sha256 = p.hex(p.hash("")), .serial_bytes = 0, .legacy_apic = legacy_apic, .passed = false, .failures = .{} };
        const root = try files.durableDirectory(self.io, self.work_root);
        defer root.close(self.io);
        var name_buffer: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "boot-{d}", .{index});
        try root.dir.createDir(self.io, name, .fromMode(0o700));
        try files.syncDirectory(self.io, root.dir);
        const path = try std.fs.path.join(self.allocator, &.{ self.work_root, name });
        defer self.allocator.free(path);
        const work = try files.durableDirectory(self.io, path);
        defer work.close(self.io);
        var work_lock = try work.lock(self.io);
        defer work_lock.close(self.io);
        const original = try files.verify(self.allocator, self.io, self.artifact_root, image, 1);
        defer original.close(self.io);
        const source_parent = try files.parent(self.allocator, self.io, self.artifact_root, image.name, false);
        defer source_parent.close(self.io);
        const source_name = try self.allocator.dupeZ(u8, source_parent.name);
        defer self.allocator.free(source_name);
        if (linux.errno(linux.linkat(source_parent.directory.dir.handle, source_name, work.dir.handle, "disk.img", 0)) != .SUCCESS) return error.LinkFailed;
        var linked = true;
        defer if (linked) {
            work.dir.deleteFile(self.io, "disk.img") catch {
                store.fail(.{ .cleanup = .{ .stage = .cleanup, .category = .cleanup_failed } });
            };
        };
        const linked_image = try files.open(self.io, work, "disk.img", false, 2);
        defer linked_image.close(self.io);
        const image_before = try original.stat(self.io);
        if (image_before.inode != (try linked_image.stat(self.io)).inode) return error.ImageIdentityMismatch;
        const code_record = command.artifact(.ovmf_code);
        const vars_record = command.artifact(.ovmf_vars);
        const code = try files.verify(self.allocator, self.io, self.artifact_root, code_record, 1);
        defer code.close(self.io);
        const template = try files.verify(self.allocator, self.io, self.artifact_root, vars_record, 1);
        defer template.close(self.io);
        const code_before = try code.stat(self.io);
        const vars_before = try template.stat(self.io);
        try store.reserve(vars_record.size, false, false);
        const vars = try work.dir.createFile(self.io, "OVMF_VARS.fd", .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer vars.close(self.io);
        try files.copy(self.io, template, vars, vars_record.size);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        const argv = try arguments(scratch, self.artifact_root, command.raw_size, legacy_apic);
        const execution: Execution = .{
            .argv = argv,
            .library_path = try std.fs.path.join(scratch, &.{ self.artifact_root, "qemu/lib" }),
            .qemu_sha256 = command.artifact(.qemu).sha256,
            .qemu_size = command.artifact(.qemu).size,
        };
        const execution_bytes = try store.encode(execution);
        defer self.allocator.free(execution_bytes);
        try store.reserve(execution_bytes.len, true, false);
        try store.reserve(p.max_serial, false, false);
        const committed = try work_lock.createImmutable(self.io, "execution.json", execution_bytes);
        if (!files.isDurable(committed)) return error.StateNotDurable;
        var environment: std.process.Environ.Map = .init(self.allocator);
        defer environment.deinit();
        const local_deadline = try core.process.Deadline.afterMilliseconds(self.boot_timeout_ms);
        var result = try core.process.run(self.allocator, self.io, .{
            .argv = &.{ self.self_executable, "--boot-child" },
            .environment = &environment,
            .cwd = work.dir,
            .deadline = .{ .expires_ns = @min(local_deadline.expires_ns, self.attempt_deadline.expires_ns) },
            .cleanup_ms = self.cleanup_timeout_ms,
            .stdout_limit = 0,
            .stderr_limit = 0,
        });
        defer result.deinit(self.allocator);
        outcome.failures = result.failures;
        const serial_file = work.openFile(self.io, "serial.log") catch null;
        if (serial_file) |file| {
            defer file.close(self.io);
            file.sync(self.io) catch {
                outcome.failures.recording = .{ .stage = .serial_evidence, .category = .local_io };
            };
        }
        const contents = work.read(self.io, self.allocator, "serial.log", p.max_serial, null) catch |err| blk: {
            if (outcome.failures.recording == null) outcome.failures.recording = .{ .stage = .serial_evidence, .category = .local_io };
            if (err != error.FileNotFound and outcome.failures.primary == null) outcome.failures.primary = .{ .stage = .serial_evidence, .category = .integrity };
            break :blk null;
        };
        defer if (contents) |bytes| {
            std.crypto.secureZero(u8, bytes);
            self.allocator.free(bytes);
        };
        if (contents) |bytes| {
            outcome.serial_bytes = bytes.len;
            outcome.serial_sha256 = p.hex(p.hash(bytes));
            serial.validate(self.allocator, bytes, command.policy, legacy_apic, command.guarded) catch {
                if (outcome.failures.primary == null) outcome.failures.primary = .{ .stage = .serial_evidence, .category = .invalid_response };
            };
        }
        files.unchanged(self.io, original, image_before) catch {
            if (outcome.failures.primary == null) outcome.failures.primary = .{ .stage = .private_file, .category = .integrity };
        };
        files.unchanged(self.io, code, code_before) catch {
            if (outcome.failures.primary == null) outcome.failures.primary = .{ .stage = .private_file, .category = .integrity };
        };
        files.unchanged(self.io, template, vars_before) catch {
            if (outcome.failures.primary == null) outcome.failures.primary = .{ .stage = .private_file, .category = .integrity };
        };
        work.dir.deleteFile(self.io, "disk.img") catch {
            outcome.failures.cleanup = .{ .stage = .cleanup, .category = .cleanup_failed };
        };
        linked = false;
        work.dir.deleteFile(self.io, "OVMF_VARS.fd") catch {
            outcome.failures.cleanup = .{ .stage = .cleanup, .category = .cleanup_failed };
        };
        outcome.passed = outcome.failures.primary == null and outcome.failures.cleanup == null and outcome.failures.recording == null and result.cleanup_complete and contents != null;
        const outcome_bytes = try store.encode(outcome);
        defer self.allocator.free(outcome_bytes);
        try store.reserve(outcome_bytes.len, true, false);
        const recording = work_lock.createImmutable(self.io, "outcome.json", outcome_bytes) catch null;
        if (recording == null or !files.isDurable(recording.?)) {
            outcome.failures.recording = .{ .stage = .state_record, .category = .local_io };
            outcome.passed = false;
        }
        if (outcome.passed) try store.bootPassed() else store.fail(outcome.failures);
        return outcome;
    }
};

/// Same executable, exec-only helper. It never supervises another process group.
/// The parent has already durably consumed the phase and owns the only deadline.
pub fn execChild(init: std.process.Init) !void {
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const length = try files.cwdPath(init.io, &path);
    const work = files.durableDirectory(init.io, path[0..length]) catch return error.BootDirectoryUnavailable;
    defer work.close(init.io);
    const bytes = work.read(init.io, init.gpa, "execution.json", p.max_command, null) catch return error.ExecutionRecordUnavailable;
    defer init.gpa.free(bytes);
    var doc = try core.contracts.Document.parse(init.gpa, bytes, .{});
    defer doc.deinit();
    try doc.requireCanonical(init.gpa, bytes);
    const parsed = try std.json.parseFromSlice(Execution, init.gpa, bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const execution = parsed.value;
    if (execution.argv.len != 30 or !std.fs.path.isAbsolute(execution.argv[0]) or !std.fs.path.isAbsolute(execution.library_path)) return error.InvalidExecution;
    const parent_dir = std.fs.path.dirname(execution.argv[0]) orelse return error.InvalidExecution;
    const directory = core.private_files.Directory.open(init.io, parent_dir) catch return error.QemuDirectoryUnavailable;
    defer directory.close(init.io);
    const qemu = try files.open(init.io, directory, std.fs.path.basename(execution.argv[0]), true, 1);
    defer qemu.close(init.io);
    if (!std.mem.eql(u8, &try files.digest(init.io, qemu, execution.qemu_size), &execution.qemu_sha256)) return error.ArtifactIntegrity;
    const claim = try work.dir.createFile(init.io, "launched", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer claim.close(init.io);
    try claim.sync(init.io);
    const directory_file: std.Io.File = .{ .handle = work.dir.handle, .flags = .{ .nonblocking = false } };
    try directory_file.sync(init.io);
    const serial_file = try work.dir.createFile(init.io, "serial.log", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer serial_file.close(init.io);
    const limit: linux.rlimit = .{ .cur = p.max_serial, .max = p.max_serial };
    if (linux.errno(linux.setrlimit(.FSIZE, &limit)) != .SUCCESS or
        linux.errno(linux.dup3(serial_file.handle, 1, 0)) != .SUCCESS or
        linux.errno(linux.dup3(serial_file.handle, 2, 0)) != .SUCCESS) return error.RedirectFailed;
    var environment: std.process.Environ.Map = .init(init.gpa);
    defer environment.deinit();
    try environment.put("LD_LIBRARY_PATH", execution.library_path);
    const argv = try init.gpa.allocSentinel(?[*:0]const u8, execution.argv.len, null);
    for (execution.argv, 0..) |arg, i| argv[i] = (try init.gpa.dupeZ(u8, arg)).ptr;
    const env = try environment.createPosixBlock(init.gpa, .{ .zig_progress_fd = -1 });
    _ = linux.execveat(qemu.handle, "", argv.ptr, env.slice.ptr, .{ .EMPTY_PATH = true, .SYMLINK_NOFOLLOW = true });
    return error.ExecFailed;
}
