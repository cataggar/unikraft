//! Native synthetic QEMU fixture. Not installed and never a real guest proof.
const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const linux = std.os.linux;
pub const prefix = "PUBLIC SYNTHETIC FIXTURE: not real QEMU or acceptance\n" ++
    "Hyper-V Hv#1 hypercall page enabled at GPA 0x1000\nHyper-V SynIC: synthetic IRQs\nPowered by Unikraft\n";
pub const application = "Calling main(1, ['synthetic'])\nUK_HYPERV_PLATFORM_READY\nUK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network\n";
pub const terminal = "[    0.123456] Info: [libukboot] <boot.c @  544> main returned 2\n";
pub fn main(init: std.process.Init) void {
    execute(init) catch std.process.exit(127);
}
fn execute(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    const work = try image.core.private_files.Directory.openWorkerCwd(io);
    defer work.close(io);
    const request = try c.read(image.boot.runner.Request, a, try work.read(io, a, "request.json", c.max_record, null));
    try request.validate();
    if (args.len != 29 or request.config.image != null or request.config.cpus != 1) return error.Arguments;
    const leading = [_][]const u8{
        "-no-user-config",                                    "-machine", "q35,accel=kvm",                          "-cpu",      "", "-smp", "1", "-m", "512M", "-drive",
        "if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd", "-drive",   "if=pflash,format=raw,file=OVMF_VARS.fd", "-blockdev",
    };
    for (leading, args[1..15]) |want, got| if (want.len != 0 and !std.mem.eql(u8, want, got)) return error.Arguments;
    const cpu = "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies";
    if (!std.mem.eql(u8, args[5], if (request.config.disable_x2apic) cpu ++ ",x2apic=off" else cpu)) return error.Cpu;
    const ending = [_][]const u8{ "-device", "virtio-blk-pci,drive=local-boot-disk", "-device", "vmbus-bridge,irq=15", "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none" };
    for (ending, args[16..]) |want, got| if (!std.mem.eql(u8, want, got)) return error.Arguments;
    var document = try image.core.contracts.Document.parse(a, args[15], .{});
    defer document.deinit();
    const fixed = request.config.fixed_vhd != null;
    const object = try image.core.contracts.exactFields(document.value(), if (fixed)
        &.{ "driver", "node-name", "read-only", "force-size", "file" }
    else
        &.{ "driver", "node-name", "read-only", "offset", "size", "file" });
    const string = image.core.contracts.string;
    if (!std.mem.eql(u8, try string(object.get("driver").?), if (fixed) "vpc" else "raw") or
        !std.mem.eql(u8, try string(object.get("node-name").?), "local-boot-disk") or !object.get("read-only").?.bool) return error.Format;
    if (fixed) {
        if (!object.get("force-size").?.bool or request.pins[0].size != c.vhd_bytes) return error.Vpc;
    } else if (try image.core.contracts.integer(u64, object.get("offset").?) != 0 or
        try image.core.contracts.integer(u64, object.get("size").?) != c.raw_bytes) return error.Raw;
    const backing = try image.core.contracts.exactFields(object.get("file").?, &.{ "driver", "filename", "read-only" });
    const filename = try string(backing.get("filename").?);
    if (!std.mem.eql(u8, try string(backing.get("driver").?), "file") or !backing.get("read-only").?.bool or
        !std.mem.startsWith(u8, filename, "/proc/self/fd/")) return error.Backing;
    const fd = try std.fmt.parseInt(linux.fd_t, filename["/proc/self/fd/".len..], 10);
    if (linux.fcntl(fd, linux.F.GETFL, 0) & 3 != 0) return error.Writable;
    const descriptor: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const original = try image.core.private_files.openAbsolute(io, request.config.source(), .artifact);
    defer original.close(io);
    if (!image.core.private_files.sameSnapshot(try image.core.private_files.snapshot(descriptor), try image.core.private_files.snapshot(original))) return error.WrongInput;
    if (fixed) _ = try image.boot.vhd.validate(io, descriptor);
    if ((try image.core.private_files.snapshot(descriptor)).size != request.pins[0].size) return error.SlicedInput;
    if (init.environ_map.count() != 1 or !std.mem.eql(u8, init.environ_map.get("TMPDIR") orelse return error.Environment, request.config.work_dir) or
        linux.getpgid(0) != linux.getpid() or linux.getppid() != request.supervisor_pid) return error.Ownership;
    var limit: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.FSIZE, &limit)) != .SUCCESS or limit.cur != image.boot.config.max_serial) return error.Limit;
    const vars = try work.dir.openFile(io, "OVMF_VARS.fd", .{ .mode = .read_write });
    defer vars.close(io);
    var modes: [2]u8 = undefined;
    if (try vars.readPositionalAll(io, &modes, 0) != 2 or modes[0] != 0xa5) return error.VarsReused;
    try vars.writePositionalAll(io, &.{0x5a}, 0);
    const mode = modes[1];
    var out = std.Io.File.stdout().writer(io, &.{});
    var errout = std.Io.File.stderr().writer(io, &.{});
    try errout.interface.writeAll("synthetic stderr retained\n");
    try out.interface.writeAll(prefix);
    if (mode == 4) while (true) try std.Io.sleep(io, .fromSeconds(1), .awake);
    if (mode == 5) while (true) try out.interface.writeAll("synthetic flood\n" ** 1024);
    if (mode == 6) {
        try work.dir.deleteFile(io, "OVMF_VARS.fd");
        try work.dir.createDir(io, "OVMF_VARS.fd", .fromMode(0o700));
    }
    if (mode == 7) try work.dir.writeFile(io, .{ .sub_path = "report.json", .data = "synthetic collision", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    if (mode == 8) {
        const pid = linux.fork();
        if (linux.errno(pid) != .SUCCESS) return error.Fork;
        if (pid == 0) while (true) {
            const duration: linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = linux.nanosleep(&duration, null);
        };
        try work.dir.writeFile(io, .{ .sub_path = "descendant.pid", .data = try std.fmt.allocPrint(a, "{d}", .{pid}), .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    }
    if (mode == 9) {
        const writable = try std.Io.Dir.openFileAbsolute(io, request.config.source(), .{ .mode = .read_write });
        defer writable.close(io);
        try writable.writePositionalAll(io, "changed", 1024);
    }
    if (request.config.disable_x2apic != (mode == 1 and fixed)) try out.interface.writeAll(c.legacy_marker ++ "\n");
    if (mode == 10) try out.interface.writeAll(terminal);
    if (mode != 11) try out.interface.writeAll(application);
    const parent = try image.core.private_files.Directory.open(io, std.fs.path.dirname(request.config.work_dir).?);
    defer parent.close(io);
    const state = try c.read(c.State, a, try parent.read(io, a, "prepare.json", c.max_record, null));
    if (try image.network.parse(state.acceptance)) |net| {
        try out.interface.print("{s}{s}\n", .{ try image.network.marker(a, net), if (mode == 12) "wrong" else "" });
    }
    if (mode == 2) try out.interface.writeAll("main returned 20\n") else try out.interface.writeAll(terminal);
    if (mode == 3) std.process.exit(19);
}
