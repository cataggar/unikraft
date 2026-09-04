const std = @import("std");
const facade_paths = @import("zig-facade-paths.zig");
const builtin = @import("builtin");

const lock_name = "build.lock";
const runtime_prefix = "unikraft-zig-facade-";

const RuntimeDirectory = struct {
    dir: std.Io.Dir,
    path: []const u8,
};

const MetadataRole = enum {
    temp_root,
    runtime_directory,
    lock_file,
};

const Metadata = struct {
    mode: u32,
    uid: u64,
    nlink: u64,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) {
        std.debug.print("error: internal Zig facade invocation is missing the output or Make command\n", .{});
        std.process.exit(2);
    }

    if (comptime !std.process.can_replace) {
        std.debug.print(
            "error: this host cannot safely replace the Zig facade runner with the Make backend while retaining the build lock\n",
            .{},
        );
        std.process.exit(2);
    }

    const temp_root = init.environ_map.get("TMPDIR") orelse
        init.environ_map.get("TEMP") orelse
        init.environ_map.get("TMP") orelse
        defaultTempRoot();
    const uid = std.posix.system.geteuid();
    var runtime = prepareRuntimeDirectory(
        allocator,
        init.io,
        temp_root,
        uid,
    ) catch |err| switch (err) {
        error.UnsafeTempRoot => {
            std.debug.print(
                "error: refusing insecure temporary root '{s}': it must be a real directory owned by this user without group/other write access, or a root-owned sticky shared directory\n",
                .{temp_root},
            );
            std.process.exit(2);
        },
        error.UnsafeRuntimeDirectory => {
            std.debug.print(
                "error: refusing insecure UID-scoped Zig facade runtime directory below '{s}': expected a real, current-user-owned 0700 directory\n",
                .{temp_root},
            );
            std.process.exit(2);
        },
        else => return err,
    };
    defer runtime.dir.close(init.io);
    if (facade_paths.isSameOrAncestor(args[1], runtime.path)) {
        std.debug.print(
            "error: the Zig facade runtime directory '{s}' is inside output '{s}'; set TMPDIR to a stable directory outside every Make output tree\n",
            .{ runtime.path, args[1] },
        );
        std.process.exit(2);
    }
    const lock = acquireLock(runtime.dir, init.io, uid) catch |err| switch (err) {
        error.WouldBlock => {
            std.debug.print(
                "error: another Make-backed Zig facade process for this user is running; wait for it to finish and retry\n",
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
        error.UnsafeLockFile => {
            std.debug.print(
                "error: refusing insecure Zig facade lock file in '{s}': expected a real, current-user-owned 0600 regular file with one link\n",
                .{runtime.path},
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

    // Exec keeps the locked descriptor in Make and every normally spawned descendant.
    try setCloseOnExec(lock, false);
    const replace_error = std.process.replace(init.io, .{ .argv = args[2..] });
    setCloseOnExec(lock, true) catch {};
    return replace_error;
}

fn acquireLock(
    directory: std.Io.Dir,
    io: std.Io,
    uid: std.posix.uid_t,
) !std.Io.File {
    const file = directory.createFile(io, lock_name, .{
        .read = true,
        .truncate = false,
        .exclusive = true,
        .lock = .exclusive,
        .lock_nonblocking = true,
        .permissions = .fromMode(0o600),
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => directory.openFile(io, lock_name, .{
            .mode = .read_write,
            .allow_directory = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch |open_err| switch (open_err) {
            error.WouldBlock => return error.WouldBlock,
            else => return error.UnsafeLockFile,
        },
        else => return err,
    };
    errdefer file.close(io);
    const metadata = try metadataForHandle(file.handle);
    try validateMetadata(metadata, uid, .lock_file);
    return file;
}

fn defaultTempRoot() []const u8 {
    return if (builtin.os.tag == .windows) "." else "/tmp";
}

fn runtimeDirectoryName(
    allocator: std.mem.Allocator,
    uid: std.posix.uid_t,
) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}{d}", .{ runtime_prefix, uid });
}

fn prepareRuntimeDirectory(
    allocator: std.mem.Allocator,
    io: std.Io,
    temp_root: []const u8,
    uid: std.posix.uid_t,
) !RuntimeDirectory {
    const absolute_root = try std.fs.path.resolve(allocator, &.{temp_root});
    var root = std.Io.Dir.cwd().openDir(io, absolute_root, .{
        .follow_symlinks = false,
    }) catch return error.UnsafeTempRoot;
    defer root.close(io);
    try validateMetadata(try metadataForHandle(root.handle), uid, .temp_root);

    const runtime_name = try runtimeDirectoryName(allocator, uid);
    root.createDir(io, runtime_name, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const runtime = root.openDir(io, runtime_name, .{
        .follow_symlinks = false,
    }) catch return error.UnsafeRuntimeDirectory;
    errdefer runtime.close(io);
    try validateMetadata(
        try metadataForHandle(runtime.handle),
        uid,
        .runtime_directory,
    );

    const lexical_path = try std.fs.path.join(allocator, &.{ absolute_root, runtime_name });
    var canonical_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const canonical_length = try std.Io.Dir.realPathFileAbsolute(
        io,
        lexical_path,
        &canonical_buffer,
    );
    return .{
        .dir = runtime,
        .path = try allocator.dupe(u8, canonical_buffer[0..canonical_length]),
    };
}

fn metadataForHandle(handle: std.posix.fd_t) !Metadata {
    if (comptime builtin.os.tag == .linux) {
        var metadata: std.os.linux.Statx = undefined;
        while (true) {
            switch (std.os.linux.errno(std.os.linux.statx(
                handle,
                "",
                std.os.linux.AT.EMPTY_PATH,
                .BASIC_STATS,
                &metadata,
            ))) {
                .SUCCESS => {
                    if (!metadata.mask.TYPE or
                        !metadata.mask.MODE or
                        !metadata.mask.UID or
                        !metadata.mask.NLINK)
                    {
                        return error.IncompleteMetadata;
                    }
                    return .{
                        .mode = metadata.mode,
                        .uid = metadata.uid,
                        .nlink = metadata.nlink,
                    };
                },
                .INTR => continue,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    } else {
        var metadata = std.mem.zeroes(std.posix.Stat);
        while (true) {
            switch (std.posix.errno(std.posix.system.fstat(handle, &metadata))) {
                .SUCCESS => return .{
                    .mode = @intCast(metadata.mode),
                    .uid = @intCast(metadata.uid),
                    .nlink = @intCast(metadata.nlink),
                },
                .INTR => continue,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    }
}

fn validateMetadata(
    metadata: Metadata,
    uid: std.posix.uid_t,
    role: MetadataRole,
) !void {
    const permissions = metadata.mode & 0o7777;
    switch (role) {
        .temp_root => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR)
                return error.UnsafeTempRoot;
            const root_owned_sticky =
                metadata.uid == 0 and
                permissions & 0o1000 != 0 and
                permissions & 0o003 == 0o003;
            const user_owned_private =
                metadata.uid == @as(u64, uid) and
                permissions & 0o700 == 0o700 and
                permissions & 0o022 == 0;
            if (!root_owned_sticky and !user_owned_private)
                return error.UnsafeTempRoot;
        },
        .runtime_directory => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
                metadata.uid != @as(u64, uid) or
                permissions != 0o700)
            {
                return error.UnsafeRuntimeDirectory;
            }
        },
        .lock_file => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFREG or
                metadata.uid != @as(u64, uid) or
                permissions != 0o600 or
                metadata.nlink != 1)
            {
                return error.UnsafeLockFile;
            }
        },
    }
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

    const uid = std.posix.system.geteuid();
    const first = try acquireLock(temporary.dir, std.testing.io, uid);
    defer first.close(std.testing.io);

    try std.testing.expectError(
        error.WouldBlock,
        acquireLock(temporary.dir, std.testing.io, uid),
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

test "runtime directory names are UID scoped" {
    const first = try runtimeDirectoryName(std.testing.allocator, 1000);
    defer std.testing.allocator.free(first);
    const second = try runtimeDirectoryName(std.testing.allocator, 1001);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings("unikraft-zig-facade-1000", first);
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "default POSIX temporary root is system scoped" {
    if (builtin.os.tag != .windows) {
        try std.testing.expectEqualStrings("/tmp", defaultTempRoot());
    }
}

test "temporary roots require trusted ownership and permissions" {
    const uid = std.posix.system.geteuid();
    var metadata = Metadata{
        .mode = std.posix.S.IFDIR | 0o755,
        .uid = @as(u64, uid),
        .nlink = 2,
    };
    try validateMetadata(metadata, uid, .temp_root);
    metadata.mode = std.posix.S.IFDIR | 0o775;
    try std.testing.expectError(
        error.UnsafeTempRoot,
        validateMetadata(metadata, uid, .temp_root),
    );

    metadata.mode = std.posix.S.IFDIR | 0o1777;
    metadata.uid = 0;
    try validateMetadata(metadata, uid, .temp_root);
    metadata.uid = @as(u64, uid) + 1;
    try std.testing.expectError(
        error.UnsafeTempRoot,
        validateMetadata(metadata, uid, .temp_root),
    );
}

test "private runtime metadata rejects unsafe ownership permissions and links" {
    const uid = std.posix.system.geteuid();
    var metadata = std.mem.zeroes(Metadata);

    metadata.mode = std.posix.S.IFDIR | 0o700;
    metadata.uid = @as(u64, uid);
    try validateMetadata(metadata, uid, .runtime_directory);
    metadata.mode = std.posix.S.IFDIR | 0o755;
    try std.testing.expectError(
        error.UnsafeRuntimeDirectory,
        validateMetadata(metadata, uid, .runtime_directory),
    );
    metadata.mode = std.posix.S.IFDIR | 0o700;
    metadata.uid = @as(u64, uid) + 1;
    try std.testing.expectError(
        error.UnsafeRuntimeDirectory,
        validateMetadata(metadata, uid, .runtime_directory),
    );

    metadata.mode = std.posix.S.IFREG | 0o600;
    metadata.uid = @as(u64, uid);
    metadata.nlink = 1;
    try validateMetadata(metadata, uid, .lock_file);
    metadata.nlink = 2;
    try std.testing.expectError(
        error.UnsafeLockFile,
        validateMetadata(metadata, uid, .lock_file),
    );
}
