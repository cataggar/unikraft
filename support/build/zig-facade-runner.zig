const std = @import("std");
const facade_paths = @import("zig-facade-paths.zig");
const builtin = @import("builtin");

const lock_name = "unikraft-zig-facade.lock";

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) {
        std.debug.print("error: internal Zig facade invocation is missing the output or Make command\n", .{});
        std.process.exit(2);
    }

    const lock_root = init.environ_map.get("TMPDIR") orelse
        init.environ_map.get("TEMP") orelse
        init.environ_map.get("TMP") orelse
        if (builtin.os.tag == .windows) "." else "/tmp";
    try std.Io.Dir.cwd().createDirPath(init.io, lock_root);
    const absolute_lock_root = try std.fs.path.resolve(allocator, &.{lock_root});
    var lock_root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const lock_root_length = try std.Io.Dir.realPathFileAbsolute(
        init.io,
        absolute_lock_root,
        &lock_root_buffer,
    );
    const canonical_lock_root = lock_root_buffer[0..lock_root_length];
    if (facade_paths.isSameOrAncestor(args[1], canonical_lock_root)) {
        std.debug.print(
            "error: the Zig facade runtime directory '{s}' is inside output '{s}'; set TMPDIR to a stable directory outside every Make output tree\n",
            .{ canonical_lock_root, args[1] },
        );
        std.process.exit(2);
    }
    const lock_path = try std.fs.path.join(allocator, &.{ canonical_lock_root, lock_name });
    const lock = acquireLock(std.Io.Dir.cwd(), init.io, lock_path) catch |err| switch (err) {
        error.WouldBlock => {
            std.debug.print(
                "error: another Make-backed Zig facade process is running on this host; wait for it to finish and retry\n",
                .{},
            );
            std.process.exit(2);
        },
        error.FileLocksUnsupported => {
            std.debug.print(
                "error: this filesystem does not support the portable file lock required to protect concurrent Make-backed Zig steps\n",
                .{},
            );
            std.process.exit(2);
        },
        else => return err,
    };
    defer lock.close(init.io);

    try std.Io.Dir.cwd().createDirPath(init.io, args[1]);
    const marker = try facade_paths.markerPath(allocator, args[1]);
    try std.Io.Dir.cwd().writeFile(init.io, .{
        .sub_path = marker,
        .data = facade_paths.marker_contents,
    });

    if (comptime !std.process.can_replace) {
        std.debug.print(
            "error: this host cannot safely replace the Zig facade runner with the Make backend while retaining the build lock\n",
            .{},
        );
        std.process.exit(2);
    }

    // Exec keeps the locked descriptor in Make and every normally spawned descendant.
    try setCloseOnExec(lock, false);
    const replace_error = std.process.replace(init.io, .{ .argv = args[2..] });
    setCloseOnExec(lock, true) catch {};
    return replace_error;
}

fn acquireLock(
    directory: std.Io.Dir,
    io: std.Io,
    path: []const u8,
) std.Io.File.OpenError!std.Io.File {
    return directory.createFile(io, path, .{
        .truncate = false,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });
}

fn setCloseOnExec(file: std.Io.File, enabled: bool) !void {
    const flags: usize = if (enabled) std.posix.FD_CLOEXEC else 0;
    while (true) {
        switch (std.posix.errno(std.posix.system.fcntl(
            file.handle,
            std.posix.F.SETFD,
            flags,
        ))) {
            .SUCCESS => return,
            .INTR => continue,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn expectConcurrentInvocationRejected() !void {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();

    const first = try acquireLock(temporary.dir, std.testing.io, "make.lock");
    defer first.close(std.testing.io);

    try std.testing.expectError(
        error.WouldBlock,
        acquireLock(temporary.dir, std.testing.io, "make.lock"),
    );
}

test "clean all cannot execute concurrently" {
    try expectConcurrentInvocationRejected();
}

test "all images cannot execute concurrently" {
    try expectConcurrentInvocationRejected();
}

test "parent and nested outputs share the host-wide lock" {
    try expectConcurrentInvocationRejected();
}
