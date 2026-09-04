const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) {
        std.debug.print("error: internal Zig facade invocation is missing the lock path or Make command\n", .{});
        std.process.exit(2);
    }

    const lock = acquireLock(std.Io.Dir.cwd(), init.io, args[1]) catch |err| switch (err) {
        error.WouldBlock => {
            std.debug.print(
                "error: another Make-backed Zig step is already using this build tree; invoke only one of clean/all/images/libs/objs/preprocess/prepare/fetch/configuration/cleanup per 'zig build' command\n",
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

    var child = try std.process.spawn(init.io, .{ .argv = args[2..] });
    const term = try child.wait(init.io);
    switch (term) {
        .exited => |code| std.process.exit(code),
        .signal => |signal| {
            std.debug.print("error: Make terminated by signal {d}\n", .{@intFromEnum(signal)});
            std.process.exit(1);
        },
        .stopped => |signal| {
            std.debug.print("error: Make stopped by signal {d}\n", .{@intFromEnum(signal)});
            std.process.exit(1);
        },
        .unknown => |status| {
            std.debug.print("error: Make terminated with unknown status {d}\n", .{status});
            std.process.exit(1);
        },
    }
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
