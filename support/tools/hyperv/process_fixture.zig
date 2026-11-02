const std = @import("std");
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.InvalidFixture;
    const mode = args[1];
    if (std.mem.eql(u8, mode, "fd-closed")) {
        if (args.len != 3) return error.InvalidFixture;
        const fd = try std.fmt.parseInt(linux.fd_t, args[2], 10);
        if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) != .BADF) std.process.exit(1);
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.writeAll("closed\n");
    } else if (std.mem.eql(u8, mode, "empty-environment")) {
        if (init.environ_map.count() != 0) std.process.exit(1);
    } else if (std.mem.eql(u8, mode, "success")) {
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.writeAll("native-fixture\n");
    } else if (std.mem.eql(u8, mode, "failure")) {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        try stderr.interface.writeAll("synthetic-private-marker?sig=never-publish\n");
        std.process.exit(7);
    } else if (std.mem.eql(u8, mode, "stdout-flood") or std.mem.eql(u8, mode, "stderr-flood")) {
        const file = if (mode[3] == 'o') std.Io.File.stdout() else std.Io.File.stderr();
        var writer = file.writer(init.io, &.{});
        while (true) try writer.interface.writeAll("synthetic-output-limit\n");
    } else if (std.mem.eql(u8, mode, "tree") or std.mem.eql(u8, mode, "orphan")) {
        // fork's child executes only raw Linux syscalls; no allocator or runtime locks.
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.ForkFailed;
        if (child == 0) {
            while (true) {
                const duration: linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = linux.nanosleep(&duration, null);
            }
        }
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.print("{d}\n", .{child});
        if (std.mem.eql(u8, mode, "orphan")) return;
        while (true) try std.Io.sleep(init.io, .fromSeconds(1), .awake);
    } else if (std.mem.eql(u8, mode, "sleep") or std.mem.eql(u8, mode, "ignore-term")) {
        if (std.mem.eql(u8, mode, "ignore-term")) {
            var action: linux.Sigaction = .{
                .handler = .{ .handler = linux.SIG.IGN },
                .mask = linux.sigemptyset(),
                .flags = 0,
            };
            if (linux.errno(linux.sigaction(.TERM, &action, null)) != .SUCCESS) return error.SignalSetup;
        }
        while (true) try std.Io.sleep(init.io, .fromSeconds(1), .awake);
    } else return error.InvalidFixture;
}
