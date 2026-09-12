const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");
const c = @import("config.zig");
const files = @import("files.zig");
const runner = @import("runner.zig");
const synthetic_diagnostics = @hasDecl(@import("root"), "local_boot_synthetic_diagnostics") and
    @import("root").local_boot_synthetic_diagnostics;
const diagnostics = if (synthetic_diagnostics) @import("synthetic_diagnostics") else void;

pub fn arguments(a: std.mem.Allocator, config: c.Config, raw_size: u64, raw_fd: linux.fd_t) ![]const []const u8 {
    try config.validate();
    var args: std.ArrayList([]const u8) = .empty;
    errdefer args.deinit(a);
    try args.appendSlice(a, &.{
        config.qemu, "-no-user-config",
        "-machine",  "q35,accel=kvm",
        "-cpu",      if (config.disable_x2apic) c.cpu_features ++ ",x2apic=off" else c.cpu_features,
        "-smp",      try std.fmt.allocPrint(a, "{d}", .{config.cpus}),
        "-m",        "512M",
        "-drive",    "if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd",
        "-drive",    "if=pflash,format=raw,file=OVMF_VARS.fd",
    });
    if (config.image == null) {
        if (raw_fd < 3 or raw_size == 0 or raw_size > c.max_input + @as(u64, if (config.fixed_vhd != null) 512 else 0)) return error.InvalidRawDisk;
        const filename = try std.fmt.allocPrint(a, "/proc/self/fd/{d}", .{raw_fd});
        const block = if (config.fixed_vhd != null) try std.json.Stringify.valueAlloc(a, .{
            .driver = "vpc",
            .@"node-name" = "local-boot-disk",
            .@"read-only" = true,
            .file = .{ .driver = "file", .filename = filename, .@"read-only" = true },
        }, .{}) else try std.json.Stringify.valueAlloc(a, .{
            .driver = "raw",
            .@"node-name" = "local-boot-disk",
            .offset = @as(u64, 0),
            .size = raw_size,
            .@"read-only" = true,
            .file = .{ .driver = "file", .filename = filename, .@"read-only" = true },
        }, .{});
        try args.appendSlice(a, &.{ "-blockdev", block, "-device", "virtio-blk-pci,drive=local-boot-disk" });
    } else try args.appendSlice(a, &.{ "-drive", "format=raw,file=fat:rw:esp" });
    try args.appendSlice(a, &.{
        "-device",    "vmbus-bridge,irq=15",
        "-display",   "none",
        "-serial",    "stdio",
        "-monitor",   "none",
        "-no-reboot", "-nic",
        "none",
    });
    return args.toOwnedSlice(a);
}

/// Exec-only leaf: no fork, no nested supervisor, no arbitrary argv record.
pub fn execute(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const work = try core.private_files.Directory.openWorkerCwd(io);
    defer work.close(io);
    const raw = try work.read(io, a, "request.json", c.max_record, null);
    var document = try core.contracts.Document.parse(a, raw, .{ .bytes = c.max_record });
    defer document.deinit();
    try document.requireCanonical(a, raw);
    const parsed = try std.json.parseFromSlice(runner.Request, a, raw, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const request = parsed.value;
    try request.validate();
    const canonical = try c.encode(a, request);
    if (!std.mem.eql(u8, raw, canonical)) return error.IncompleteRequest;
    var death_signal: c_int = 0;
    if (request.supervisor_pid != linux.getppid() or linux.getpgid(0) != linux.getpid() or
        linux.errno(linux.prctl(@intFromEnum(linux.PR.GET_PDEATHSIG), @intFromPtr(&death_signal), 0, 0, 0)) != .SUCCESS or
        death_signal != @intFromEnum(linux.SIG.KILL)) return error.InvalidSupervisor;
    if (work.lock(io)) |value| {
        var unexpected = value;
        unexpected.close(io);
        return error.MissingSupervisorLock;
    } else |err| if (err != error.WouldBlock) return err;
    var path_buffer: [4096]u8 = undefined;
    const path_length = try work.dir.realPath(io, &path_buffer);
    if (!std.mem.eql(u8, path_buffer[0..path_length], request.config.work_dir)) return error.WrongWorkspace;
    const claim = try work.dir.createFile(io, "launched", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer claim.close(io);
    try claim.sync(io);
    try files.sync(io, work.dir);
    const log = try work.dir.createFile(io, c.log_name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer log.close(io);
    const limit: linux.rlimit = .{ .cur = c.max_serial, .max = c.max_serial };
    const append: linux.O = .{ .APPEND = true };
    if (linux.errno(linux.fcntl(log.handle, linux.F.SETFL, @as(u32, @bitCast(append)))) != .SUCCESS or
        linux.errno(linux.dup3(log.handle, 1, 0)) != .SUCCESS or
        linux.errno(linux.dup3(log.handle, 2, 0)) != .SUCCESS) return error.RedirectFailed;
    var trace: if (synthetic_diagnostics) diagnostics.Trace else void =
        if (synthetic_diagnostics) try diagnostics.Trace.create(io, work, request.pins[3].size) else {};
    defer if (synthetic_diagnostics) trace.close(io);
    if (synthetic_diagnostics) try trace.mark(io, .artifact_hash_begin);
    const artifacts = try files.Set.open(io, request.config);
    defer artifacts.close(io);
    if (!std.meta.eql(artifacts.pins(), request.pins)) return error.ArtifactChanged;
    if (synthetic_diagnostics) try trace.mark(io, .artifact_hash_end);
    if (synthetic_diagnostics) try trace.mark(io, .firmware_copy_begin);
    try files.copy(io, artifacts.items[1], work.dir, "OVMF_CODE.fd");
    try files.copy(io, artifacts.items[2], work.dir, "OVMF_VARS.fd");
    if (synthetic_diagnostics) try trace.mark(io, .firmware_copy_end);
    var raw_fd: linux.fd_t = -1;
    defer if (raw_fd >= 0) {
        _ = linux.close(raw_fd);
    };
    if (request.config.image != null) {
        try work.dir.createDir(io, "esp", .fromMode(0o700));
        const esp = try work.dir.openDir(io, "esp", .{ .follow_symlinks = false, .iterate = true });
        defer esp.close(io);
        try esp.createDir(io, "EFI", .fromMode(0o700));
        const efi = try esp.openDir(io, "EFI", .{ .follow_symlinks = false, .iterate = true });
        defer efi.close(io);
        try efi.createDir(io, "BOOT", .fromMode(0o700));
        const boot = try efi.openDir(io, "BOOT", .{ .follow_symlinks = false, .iterate = true });
        defer boot.close(io);
        try files.copy(io, artifacts.items[0], boot, "BOOTX64.EFI");
    } else raw_fd = try files.inheritedReadOnly(artifacts.items[0].file);
    const args = try arguments(a, request.config, request.pins[0].size, raw_fd);
    const argv = try a.allocSentinel(?[*:0]const u8, args.len, null);
    for (args, 0..) |arg, i| argv[i] = (try a.dupeZ(u8, arg)).ptr;
    var environment: std.process.Environ.Map = .init(a);
    defer environment.deinit();
    try environment.put("TMPDIR", request.config.work_dir);
    const env = try environment.createPosixBlock(a, .{ .zig_progress_fd = -1 });
    if (synthetic_diagnostics) try trace.mark(io, .final_verify_begin);
    try artifacts.verify(io, request.config);
    if (synthetic_diagnostics) try trace.mark(io, .final_verify_end);
    const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(.FSIZE, &limit)) != .SUCCESS or
        linux.errno(linux.setrlimit(.CORE, &no_core)) != .SUCCESS) return error.LimitFailed;
    if (synthetic_diagnostics) try trace.mark(io, .exec_handoff);
    _ = linux.execveat(artifacts.items[3].file.handle, "", argv.ptr, env.slice.ptr, .{ .EMPTY_PATH = true, .SYMLINK_NOFOLLOW = true });
    return error.ExecFailed;
}
