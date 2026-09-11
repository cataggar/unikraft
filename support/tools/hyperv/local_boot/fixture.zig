//! Public synthetic QEMU substitute, built for tests only and never installed.
const std = @import("std");
const boot = @import("local_boot");
const linux = std.os.linux;
pub const log = "synthetic local-boot fixture, not a guest or acceptance proof\n" ++
    "Hyper-V Hv#1 hypercall page enabled at GPA 0x1000\n" ++
    "Hyper-V SynIC: synthetic IRQs\nPowered by Unikraft\n" ++
    "Calling main(1, ['synthetic'])\nHello world!\n" ++
    "[    0.123456] Info: [libukboot] <boot.c @  544> main returned 0\n";

pub fn main(init: std.process.Init) void {
    execute(init) catch {
        var out = std.Io.File.stderr().writer(init.io, &.{});
        out.interface.writeAll("synthetic_qemu_fixture_failed\n") catch {};
        std.process.exit(127);
    };
}

fn execute(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    const work = try boot.core.private_files.Directory.openWorkerCwd(io);
    defer work.close(io);
    const raw = try work.read(io, a, "request.json", boot.config.max_record, null);
    const parsed = try std.json.parseFromSlice(boot.runner.Request, a, raw, .{});
    defer parsed.deinit();
    const request = parsed.value;
    const is_raw = request.config.raw_disk != null;
    if (args.len != @as(usize, if (is_raw) 29 else 27)) return error.Arguments;
    const leading = [_][]const u8{
        "-no-user-config",                                    "-machine", "q35,accel=kvm",                          "-cpu", "",
        "-smp",                                               "",         "-m",                                     "512M", "-drive",
        "if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd", "-drive",   "if=pflash,format=raw,file=OVMF_VARS.fd",
    };
    for (leading, args[1..14]) |want, got| if (want.len != 0 and !std.mem.eql(u8, want, got)) return error.Arguments;
    const cpu = "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies";
    if (!std.mem.eql(u8, args[5], if (request.config.disable_x2apic) cpu ++ ",x2apic=off" else cpu)) return error.Cpu;
    if (try boot.config.integer(u8, args[7]) != request.config.cpus) return error.CpuCount;
    const ending = [_][]const u8{ "-device", "vmbus-bridge,irq=15", "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none" };
    for (ending, args[args.len - ending.len ..]) |want, got| if (!std.mem.eql(u8, want, got)) return error.Arguments;
    if (init.environ_map.count() != 1 or !std.mem.eql(u8, init.environ_map.get("TMPDIR") orelse return error.Environment, request.config.work_dir)) return error.Environment;
    if (linux.getpid() != linux.getpgid(0) or linux.getppid() != request.supervisor_pid) return error.ProcessOwnership;
    var limit: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.FSIZE, &limit)) != .SUCCESS or limit.cur != boot.config.max_serial or limit.max != limit.cur) return error.OutputLimit;
    if (linux.errno(linux.getrlimit(.CORE, &limit)) != .SUCCESS or limit.cur != 0 or limit.max != 0) return error.OutputLimit;
    const original = try boot.core.private_files.openAbsolute(io, request.config.source(), .artifact);
    defer original.close(io);
    const source: std.Io.File = source: {
        if (is_raw) {
            if (!std.mem.eql(u8, args[14], "-blockdev") or !std.mem.eql(u8, args[16], "-device") or
                !std.mem.eql(u8, args[17], "virtio-blk-pci,drive=local-boot-disk")) return error.RawArguments;
            const Block = struct {
                driver: []const u8,
                @"node-name": []const u8,
                offset: u64,
                size: u64,
                @"read-only": bool,
                file: struct { driver: []const u8, filename: []const u8, @"read-only": bool },
            };
            const block = try std.json.parseFromSlice(Block, a, args[15], .{ .ignore_unknown_fields = false });
            defer block.deinit();
            const b = block.value;
            if (!std.mem.eql(u8, b.driver, "raw") or !std.mem.eql(u8, b.@"node-name", "local-boot-disk") or
                b.offset != 0 or b.size != request.pins[0].size or !b.@"read-only" or !b.file.@"read-only" or
                !std.mem.eql(u8, b.file.driver, "file") or !std.mem.startsWith(u8, b.file.filename, "/proc/self/fd/")) return error.RawArguments;
            const fd = try std.fmt.parseInt(linux.fd_t, b.file.filename["/proc/self/fd/".len..], 10);
            const flags = linux.fcntl(fd, linux.F.GETFL, 0);
            if (linux.errno(flags) != .SUCCESS or flags & 3 != 0) return error.WritableRaw;
            const file = try std.Io.Dir.openFileAbsolute(io, b.file.filename, .{ .mode = .read_only });
            if (!boot.core.private_files.sameSnapshot(try boot.core.private_files.snapshot(original), try boot.core.private_files.snapshot(file))) return error.WrongBacking;
            if (work.dir.openDir(io, "esp", .{})) |esp| {
                esp.close(io);
                return error.UnexpectedEsp;
            } else |err| if (err != error.FileNotFound) return err;
            break :source file;
        }
        if (!std.mem.eql(u8, args[14], "-drive") or !std.mem.eql(u8, args[15], "format=raw,file=fat:rw:esp")) return error.EfiArguments;
        const file = try work.dir.openFile(io, "esp/EFI/BOOT/BOOTX64.EFI", .{ .mode = .read_only });
        if ((try file.stat(io)).inode == (try original.stat(io)).inode) return error.SharedEfi;
        break :source file;
    };
    defer source.close(io);
    const source_stat = try boot.core.private_files.snapshot(source);
    if (!std.mem.eql(u8, &try boot.files.digest(io, source, source_stat), &request.pins[0].sha256)) return error.SourceChanged;
    var mode: [1]u8 = undefined;
    if (try source.readPositionalAll(io, &mode, 0) != 1) return error.EmptySource;
    const vars = try work.dir.openFile(io, "OVMF_VARS.fd", .{ .mode = .read_write });
    defer vars.close(io);
    var byte: [1]u8 = undefined;
    if (try vars.readPositionalAll(io, &byte, 0) != 1 or byte[0] != 0xa5) return error.FirmwareReused;
    try vars.writePositionalAll(io, &.{0x5a}, 0);
    var out = std.Io.File.stdout().writer(io, &.{});
    var errout = std.Io.File.stderr().writer(io, &.{});
    try errout.interface.writeAll("synthetic stderr retained\n");
    const invoked = try work.dir.createFile(io, "fixture-invoked", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer invoked.close(io);
    try invoked.writePositionalAll(io, "native fixture invoked once\n", 0);
    try invoked.sync(io);
    switch (mode[0]) {
        3 => {
            try ignoreTerm();
            try out.interface.writeAll("synthetic blocking child\n");
            while (true) try std.Io.sleep(io, .fromSeconds(1), .awake);
        },
        4 => while (true) {
            try out.interface.writeAll("synthetic serial flood\n" ** 256);
        },
        5 => {
            try ignoreTerm();
            const forked = linux.fork();
            if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
            if (forked == 0) while (true) {
                const duration: linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = linux.nanosleep(&duration, null);
            };
            const pid = try std.fmt.allocPrint(a, "{d}", .{forked});
            try work.dir.writeFile(io, .{ .sub_path = "descendant.pid", .data = pid, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        },
        7, 14 => {
            try work.dir.deleteFile(io, "OVMF_VARS.fd");
            try work.dir.createDir(io, "OVMF_VARS.fd", .fromMode(0o700));
        },
        9 => {
            const changed = try std.Io.Dir.openFileAbsolute(io, request.config.source(), .{ .mode = .read_write });
            defer changed.close(io);
            try changed.writePositionalAll(io, "changed", source_stat.size - 7);
        },
        12 => {
            try out.interface.writeAll("synthetic killed child\n");
            _ = linux.kill(linux.getpid(), .KILL);
        },
        else => {},
    }
    if (mode[0] == 8 or mode[0] == 14)
        try work.dir.writeFile(io, .{ .sub_path = "report.json", .data = "synthetic recording collision", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    const actual_log = switch (mode[0]) {
        2 => try std.mem.replaceOwned(u8, a, log, "[    0.123456] Info: [libukboot] <boot.c @  544> main returned 0\n", ""),
        10 => try std.mem.replaceOwned(u8, a, log, "Calling main(1, ['synthetic'])\nHello world!", "Hello world!\nCalling main(1, ['synthetic'])"),
        11 => try std.mem.replaceOwned(u8, a, log, "main returned 0", "main returned 10"),
        else => log,
    };
    try out.interface.writeAll(actual_log);
    if (mode[0] == 6) try out.interface.writeAll("Unikraft Crash\n");
    if (mode[0] == 1 or mode[0] == 14) std.process.exit(19);
}

fn ignoreTerm() !void {
    var action: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
    if (linux.errno(linux.sigaction(.TERM, &action, null)) != .SUCCESS) return error.SignalSetup;
}
