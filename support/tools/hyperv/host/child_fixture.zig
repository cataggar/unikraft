const std = @import("std");
const host = @import("host");
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    execute(init) catch |err| {
        std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "fixture-error.txt", .data = @errorName(err), .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } }) catch {};
        std.process.exit(127);
    };
}

fn execute(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "--boot-child")) return host.boot.execChild(init);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--wire-child")) {
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "fixture-wire-started", .data = "native child started\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
        while (true) try std.Io.sleep(init.io, .fromSeconds(1), .awake);
    }
    if (args.len != 30) return error.InvalidFixtureArguments;
    const expected = [_][]const u8{
        "-machine", "q35,accel=kvm", "-cpu",    "",                                       "-L",        "",                                                                                                                                                                                "-smp",       "1",                                "-m",      "512M",
        "-drive",   "",              "-drive",  "if=pflash,format=raw,file=OVMF_VARS.fd", "-blockdev", "{\"driver\":\"raw\",\"node-name\":\"hyperv-disk\",\"offset\":0,\"size\":1048576,\"read-only\":true,\"file\":{\"driver\":\"file\",\"filename\":\"disk.img\",\"read-only\":true}}", "-device",    "virtio-blk-pci,drive=hyperv-disk", "-device", "vmbus-bridge,irq=15",
        "-display", "none",          "-serial", "stdio",                                  "-monitor",  "none",                                                                                                                                                                            "-no-reboot", "-nic",                             "none",
    };
    for (expected, args[1..]) |want, actual| if (want.len != 0 and !std.mem.eql(u8, want, actual)) return error.InvalidFixtureArguments;
    const cpu = "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies";
    const legacy = std.mem.eql(u8, args[4], cpu ++ ",x2apic=off");
    if (!legacy and !std.mem.eql(u8, args[4], cpu)) return error.MissingFixtureFeatures;
    if (init.environ_map.count() != 1 or init.environ_map.get("LD_LIBRARY_PATH") == null) return error.AmbientFixtureEnvironment;
    const vars = try std.Io.Dir.cwd().openFile(init.io, "OVMF_VARS.fd", .{ .mode = .read_write });
    defer vars.close(init.io);
    var byte: [1]u8 = undefined;
    if (try vars.readPositionalAll(init.io, &byte, 0) != 1 or byte[0] != 0xa5) return error.ReusedFirmwareVariables;
    try vars.writePositionalAll(init.io, &.{0x5a}, 0);
    const disk = try std.Io.Dir.cwd().openFile(init.io, "disk.img", .{ .mode = .read_only });
    defer disk.close(init.io);
    if (try disk.readPositionalAll(init.io, &byte, 0) != 1) return error.InvalidFixtureImage;
    const mode = byte[0];
    var out = std.Io.File.stdout().writer(init.io, &.{});
    if (mode == 3) {
        try out.interface.writeAll("synthetic child waiting\n");
        while (true) try std.Io.sleep(init.io, .fromSeconds(1), .awake);
    }
    if (mode == 4) while (true) {
        try out.interface.writeAll("synthetic bounded serial flood\n");
    };
    if (mode == 5) {
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.FixtureFork;
        if (child == 0) {
            while (true) {
                const duration: linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = linux.nanosleep(&duration, null);
            }
        }
        const pid = try std.fmt.allocPrint(init.gpa, "{d}", .{child});
        defer init.gpa.free(pid);
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "descendant.pid", .data = pid, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    }
    if (legacy) try out.interface.writeAll("Using legacy xAPIC MMIO\n");
    try out.interface.writeAll("Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by\nCalling main(\nUK_HYPERV_PLATFORM_READY\n");
    for (host.serial.unavailable_records) |record| {
        try out.interface.writeAll(record);
        try out.interface.writeByte('\n');
    }
    try out.interface.writeAll(host.serial.unavailable_marker ++ "\n");
    if (mode != 2) try out.interface.writeAll("main returned 2\n");
    if (mode == 6 or mode == 8) try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "outcome.json", .data = "fixture recording collision", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    if (mode == 7 or mode == 8) {
        try std.Io.Dir.cwd().deleteFile(init.io, "OVMF_VARS.fd");
        try std.Io.Dir.cwd().createDir(init.io, "OVMF_VARS.fd", .fromMode(0o700));
        std.process.exit(19);
    }
    if (mode == 1) std.process.exit(19);
}
