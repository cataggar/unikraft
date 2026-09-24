// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const layout = @import("wamr_controller").layout;

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch refused(init.io);
    if (args.len != 4) refused(init.io);
    const binary = std.fs.path.resolve(init.arena.allocator(), &.{ args[2], args[3] }) catch refused(init.io);
    install(init.arena.allocator(), init.io, args[1], binary) catch refused(init.io);
}

fn install(allocator: std.mem.Allocator, io: std.Io, root: []const u8, binary: []const u8) !void {
    const runtime = try layout.runtime(io, root);
    defer runtime.close(io);
    var source = try files.RetainedFile.open(io, binary, .tool);
    defer source.close(io);
    var contents = try files.readSensitiveFile(io, allocator, source.file, 64 * 1024 * 1024, .tool);
    defer contents.deinit();
    if (contents.bytes().len < 64 or
        !std.mem.eql(u8, contents.bytes()[0..4], "\x7fELF") or
        contents.bytes()[4] != 2 or contents.bytes()[5] != 1 or
        contents.bytes()[18] != 62 or contents.bytes()[19] != 0)
        return error.NotPortableElf;
    try source.verify(io);
    try runtime.dir.createDir(io, "controller", .fromMode(0o700));
    const controller = try runtime.dir.openDir(io, "controller", .{
        .follow_symlinks = false,
        .iterate = true,
    });
    defer controller.close(io);
    try controller.createDir(io, "bin", .fromMode(0o700));
    const bin = try controller.openDir(io, "bin", .{
        .follow_symlinks = false,
        .iterate = true,
    });
    defer bin.close(io);
    const output = try bin.createFile(io, "uk-wamr-native-ci", .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    try output.writeStreamingAll(io, contents.bytes());
    try output.sync(io);
    try source.verify(io);
    var hash = core.Sha256.init(.{});
    var chunk: [64 * 1024]u8 = undefined;
    var offset: usize = 0;
    while (offset < contents.bytes().len) {
        const count = @min(chunk.len, contents.bytes().len - offset);
        if (try output.readPositionalAll(io, chunk[0..count], offset) != count)
            return error.InstallChanged;
        hash.update(chunk[0..count]);
        offset += count;
    }
    var expected: [core.Sha256.digest_length]u8 = undefined;
    core.Sha256.hash(contents.bytes(), &expected, .{});
    const actual = hash.finalResult();
    if (!std.crypto.timing_safe.eql(@TypeOf(actual), actual, expected))
        return error.InstallChanged;
    if (std.os.linux.errno(std.os.linux.fchmod(output.handle, 0o700)) != .SUCCESS)
        return error.InstallChanged;
    try output.sync(io);
    const named = try bin.openFile(io, "uk-wamr-native-ci", .{ .follow_symlinks = false });
    defer named.close(io);
    if (!files.sameSnapshot(try files.snapshot(output), try files.snapshot(named)))
        return error.InstallChanged;
    try syncDir(io, bin);
    try syncDir(io, controller);
    try syncDir(io, runtime.dir);
}

fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn refused(io: std.Io) noreturn {
    std.Io.File.stderr().writeStreamingAll(io, "WAMR_CI_REFUSED: controller install unavailable\n") catch {};
    std.process.exit(1);
}
