const std = @import("std");
pub const core = @import("hyperv_core");
pub const options = @import("test_options");
pub const io = std.testing.io;
pub const allocator = std.testing.allocator;
pub const process = core.process;

pub const Fixture = struct {
    root: core.private_files.Directory,
    directory: core.private_files.Directory,
    name: [32]u8,

    pub fn init() !Fixture {
        try process.initialize();
        var root = try core.private_files.Directory.open(io, options.test_root.?);
        errdefer root.close(io);
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try root.dir.createDir(io, &name, .fromMode(0o700));
        errdefer root.dir.deleteDir(io, &name) catch {};
        const directory = try root.dir.openDir(io, &name, .{ .follow_symlinks = false, .iterate = true });
        return .{ .root = root, .directory = .{ .dir = directory }, .name = name };
    }

    pub fn deinit(self: *Fixture) void {
        self.directory.close(io);
        self.root.dir.deleteTree(io, &self.name) catch @panic("private fixture cleanup failed");
        self.root.close(io);
    }

    pub fn read(self: Fixture, name: []const u8) !core.sensitive.Buffer {
        return self.directory.readSensitive(io, allocator, name, process.private_output_limit, null);
    }
};

pub fn executable() ![:0]u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(io, options.runtime_fixture, allocator);
}

pub fn noChildren() !void {
    var status: u32 = 0;
    try std.testing.expectEqual(.CHILD, std.os.linux.errno(std.os.linux.waitpid(-1, &status, std.os.linux.W.NOHANG)));
}

pub fn cancelAfter(flag: *std.atomic.Value(bool), milliseconds: u32) void {
    const duration: std.os.linux.timespec = .{
        .sec = milliseconds / 1000,
        .nsec = @as(isize, @intCast(milliseconds % 1000)) * std.time.ns_per_ms,
    };
    _ = std.os.linux.nanosleep(&duration, null);
    flag.store(true, .release);
}
