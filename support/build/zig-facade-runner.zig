const std = @import("std");
const facade_paths = @import("zig-facade-paths.zig");
const builtin = @import("builtin");

const lock_name = "build.lock";
const runtime_prefix = "unikraft-zig-facade-";
const stable_temp_root = if (builtin.os.tag == .macos) "/private/tmp" else "/tmp";

const RuntimeDirectory = struct {
    dir: std.Io.Dir,
    path: []const u8,
};

const MetadataRole = enum {
    temp_root,
    isolated_temp_root,
    runtime_directory,
    lock_file,
    output_directory,
    marker_file,
};

const stable_temp_root_role: MetadataRole = .temp_root;

const Metadata = struct {
    mode: u32,
    uid: u64,
    nlink: u64,
    size: u64,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 5) {
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

    if (isDestructiveGoal(args[4])) {
        std.debug.print(
            "error: destructive Make goal '{s}' is refused by the Zig facade because mutable pathnames cannot provide descriptor-relative deletion safety\n",
            .{args[4]},
        );
        std.process.exit(2);
    }

    validateCanonicalMakeArguments(allocator, init.io, args[2..]) catch {
        std.debug.print(
            "error: a Make-facing A/O/C/L/P/E path no longer resolves to the canonical identity validated by build.zig; retry from a stable filesystem state\n",
            .{},
        );
        std.process.exit(2);
    };

    const uid = std.posix.system.geteuid();
    var runtime = prepareRuntimeDirectory(
        allocator,
        init.io,
        stable_temp_root,
        uid,
        stable_temp_root_role,
    ) catch |err| switch (err) {
        error.UnsafeTempRoot => {
            std.debug.print(
                "error: refusing insecure stable temporary root '{s}': it must be a real, root-owned sticky shared directory\n",
                .{stable_temp_root},
            );
            std.process.exit(2);
        },
        error.UnsafeRuntimeDirectory => {
            std.debug.print(
                "error: refusing insecure UID-scoped Zig facade runtime directory below '{s}': expected a real, current-user-owned 0700 directory\n",
                .{stable_temp_root},
            );
            std.process.exit(2);
        },
        else => return err,
    };
    defer runtime.dir.close(init.io);
    if (facade_paths.isSameOrAncestor(args[1], runtime.path)) {
        std.debug.print(
            "error: the Zig facade runtime directory '{s}' is inside output '{s}'\n",
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

    _ = try std.Io.Dir.cwd().createDirPathStatus(
        init.io,
        args[1],
        .fromMode(0o700),
    );
    var output = std.Io.Dir.cwd().openDir(init.io, args[1], .{
        .follow_symlinks = false,
    }) catch {
        std.debug.print(
            "error: refusing unsafe output directory '{s}': expected a real, current-user-owned directory without group/other write access\n",
            .{args[1]},
        );
        std.process.exit(2);
    };
    defer output.close(init.io);
    validateMetadata(
        try metadataForHandle(output.handle),
        uid,
        .output_directory,
    ) catch {
        std.debug.print(
            "error: refusing unsafe output directory '{s}': expected a real, current-user-owned directory without group/other write access\n",
            .{args[1]},
        );
        std.process.exit(2);
    };
    ensureBuildMarker(output, init.io, uid) catch {
        std.debug.print(
            "error: refusing unsafe build marker '{s}' in output '{s}': expected a real, current-user-owned, single-link regular file with safe permissions and exact facade marker content\n",
            .{ facade_paths.marker_name, args[1] },
        );
        std.process.exit(2);
    };

    validateCanonicalMakeArguments(allocator, init.io, args[2..]) catch {
        std.debug.print(
            "error: a Make-facing A/O/C/L/P/E path changed identity immediately before backend execution; refusing delegation\n",
            .{},
        );
        std.process.exit(2);
    };

    // Exec keeps the locked descriptor in Make and every normally spawned descendant.
    try setCloseOnExec(lock, false);
    const replace_error = std.process.replace(init.io, .{ .argv = args[2..] });
    setCloseOnExec(lock, true) catch {};
    return replace_error;
}

fn isDestructiveGoal(goal: []const u8) bool {
    return std.mem.eql(u8, goal, "clean") or
        std.mem.eql(u8, goal, "clean-libs") or
        std.mem.eql(u8, goal, "properclean") or
        std.mem.eql(u8, goal, "distclean");
}

fn validateCanonicalMakeArguments(
    allocator: std.mem.Allocator,
    io: std.Io,
    arguments: []const []const u8,
) !void {
    for (arguments) |argument| {
        const separator = std.mem.indexOfScalar(u8, argument, '=') orelse continue;
        const name = argument[0..separator];
        const value = argument[separator + 1 ..];
        const is_list = std.mem.eql(u8, name, "L") or
            std.mem.eql(u8, name, "P") or
            std.mem.eql(u8, name, "E");
        const is_path = is_list or
            std.mem.eql(u8, name, "A") or
            std.mem.eql(u8, name, "O") or
            std.mem.eql(u8, name, "C");
        if (!is_path) continue;

        if (is_list) {
            var iterator = std.mem.splitScalar(u8, value, ':');
            while (iterator.next()) |path| {
                try validateCanonicalPath(allocator, io, path);
            }
        } else {
            try validateCanonicalPath(allocator, io, value);
        }
    }
}

fn validateCanonicalPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !void {
    const canonical = try facade_paths.canonicalizeNearestExisting(
        allocator,
        io,
        path,
    );
    defer allocator.free(canonical.path);
    if (!std.mem.eql(u8, canonical.path, path)) return error.PathIdentityChanged;
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
    temp_root_role: MetadataRole,
) !RuntimeDirectory {
    const absolute_root = try std.fs.path.resolve(allocator, &.{temp_root});
    var root = std.Io.Dir.cwd().openDir(io, absolute_root, .{
        .follow_symlinks = false,
    }) catch return error.UnsafeTempRoot;
    defer root.close(io);
    try validateMetadata(try metadataForHandle(root.handle), uid, temp_root_role);

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
                        .size = metadata.size,
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
                    .size = @intCast(metadata.size),
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
            if (!root_owned_sticky) return error.UnsafeTempRoot;
        },
        .isolated_temp_root => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR)
                return error.UnsafeTempRoot;
            const user_owned_private =
                metadata.uid == @as(u64, uid) and
                permissions & 0o700 == 0o700 and
                permissions & 0o022 == 0;
            if (!user_owned_private) return error.UnsafeTempRoot;
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
        .output_directory => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
                metadata.uid != @as(u64, uid) or
                permissions & 0o700 != 0o700 or
                permissions & 0o022 != 0)
            {
                return error.UnsafeOutputDirectory;
            }
        },
        .marker_file => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFREG or
                metadata.uid != @as(u64, uid) or
                permissions & 0o600 != 0o600 or
                permissions & 0o022 != 0 or
                metadata.nlink != 1)
            {
                return error.UnsafeMarkerFile;
            }
        },
    }
}

fn ensureBuildMarker(
    output: std.Io.Dir,
    io: std.Io,
    uid: std.posix.uid_t,
) !void {
    const marker = output.createFile(io, facade_paths.marker_name, .{
        .read = true,
        .truncate = false,
        .exclusive = true,
        .permissions = .fromMode(0o600),
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const path_metadata = output.statFile(
                io,
                facade_paths.marker_name,
                .{ .follow_symlinks = false },
            ) catch return error.UnsafeMarkerFile;
            if (path_metadata.kind != .file) return error.UnsafeMarkerFile;
            const existing = try openExistingMarker(output);
            defer existing.close(io);
            const metadata = try metadataForHandle(existing.handle);
            try validateMetadata(metadata, uid, .marker_file);
            if (metadata.size != facade_paths.marker_contents.len)
                return error.UnsafeMarkerFile;
            var contents: [facade_paths.marker_contents.len]u8 = undefined;
            const count = try existing.readPositionalAll(io, &contents, 0);
            if (count != contents.len or
                !std.mem.eql(u8, &contents, facade_paths.marker_contents))
            {
                return error.UnsafeMarkerFile;
            }
            return;
        },
        else => return err,
    };
    defer marker.close(io);
    try validateMetadata(try metadataForHandle(marker.handle), uid, .marker_file);
    try marker.writePositionalAll(io, facade_paths.marker_contents, 0);
}

fn openExistingMarker(output: std.Io.Dir) !std.Io.File {
    const flags: std.posix.O = .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
    };
    while (true) {
        const result = std.posix.system.openat(
            output.handle,
            facade_paths.marker_name,
            flags,
            @as(std.posix.mode_t, 0),
        );
        switch (std.posix.errno(result)) {
            .SUCCESS => return .{
                .handle = @intCast(result),
                .flags = .{ .nonblocking = true },
            },
            .INTR => continue,
            else => return error.UnsafeMarkerFile,
        }
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

test "stable POSIX temporary root ignores process environment" {
    const expected = if (builtin.os.tag == .macos) "/private/tmp" else "/tmp";
    try std.testing.expectEqualStrings(expected, stable_temp_root);
}

test "temporary roots require trusted ownership and permissions" {
    const uid = std.posix.system.geteuid();
    var metadata = Metadata{
        .mode = std.posix.S.IFDIR | 0o755,
        .uid = @as(u64, uid),
        .nlink = 2,
        .size = 0,
    };
    try validateMetadata(metadata, uid, .isolated_temp_root);
    metadata.mode = std.posix.S.IFDIR | 0o775;
    try std.testing.expectError(
        error.UnsafeTempRoot,
        validateMetadata(metadata, uid, .isolated_temp_root),
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

    metadata.mode = std.posix.S.IFCHR | 0o600;
    metadata.nlink = 1;
    try std.testing.expectError(
        error.UnsafeMarkerFile,
        validateMetadata(metadata, uid, .marker_file),
    );

    metadata.mode = std.posix.S.IFREG | 0o600;
    metadata.uid = @as(u64, uid) + 1;
    try std.testing.expectError(
        error.UnsafeMarkerFile,
        validateMetadata(metadata, uid, .marker_file),
    );

    metadata.mode = std.posix.S.IFDIR | 0o700;
    metadata.uid = @as(u64, uid);
    try validateMetadata(metadata, uid, .output_directory);
    metadata.mode = std.posix.S.IFDIR | 0o722;
    try std.testing.expectError(
        error.UnsafeOutputDirectory,
        validateMetadata(metadata, uid, .output_directory),
    );
}

test "build marker creation is repeatable and rejects symlinks without writes" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const uid = std.posix.system.geteuid();

    try ensureBuildMarker(temporary.dir, std.testing.io, uid);
    try ensureBuildMarker(temporary.dir, std.testing.io, uid);
    const contents = try temporary.dir.readFileAlloc(
        std.testing.io,
        facade_paths.marker_name,
        std.testing.allocator,
        .limited(facade_paths.marker_contents.len + 1),
    );
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings(facade_paths.marker_contents, contents);

    try temporary.dir.deleteFile(std.testing.io, facade_paths.marker_name);
    try temporary.dir.writeFile(std.testing.io, .{
        .sub_path = "victim",
        .data = "unchanged",
    });
    try temporary.dir.symLink(
        std.testing.io,
        "victim",
        facade_paths.marker_name,
        .{},
    );
    try std.testing.expectError(
        error.UnsafeMarkerFile,
        ensureBuildMarker(temporary.dir, std.testing.io, uid),
    );
    const victim = try temporary.dir.readFileAlloc(
        std.testing.io,
        "victim",
        std.testing.allocator,
        .limited(32),
    );
    defer std.testing.allocator.free(victim);
    try std.testing.expectEqualStrings("unchanged", victim);
}

test "destructive Make goals are refused defensively" {
    try std.testing.expect(isDestructiveGoal("clean"));
    try std.testing.expect(isDestructiveGoal("clean-libs"));
    try std.testing.expect(isDestructiveGoal("properclean"));
    try std.testing.expect(isDestructiveGoal("distclean"));
    try std.testing.expect(!isDestructiveGoal("all"));
}

test "canonical Make path validation detects intermediate replacement" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "base/app");
    try temporary.dir.createDirPath(std.testing.io, "external/app");

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const app = try std.fs.path.join(
        std.testing.allocator,
        &.{ root_buffer[0..root_length], "base/app" },
    );
    defer std.testing.allocator.free(app);
    const assignment = try std.fmt.allocPrint(
        std.testing.allocator,
        "A={s}",
        .{app},
    );
    defer std.testing.allocator.free(assignment);
    try validateCanonicalMakeArguments(
        std.testing.allocator,
        std.testing.io,
        &.{assignment},
    );

    try temporary.dir.rename("base", temporary.dir, "moved", std.testing.io);
    try temporary.dir.symLink(
        std.testing.io,
        "external",
        "base",
        .{ .is_directory = true },
    );
    try std.testing.expectError(
        error.PathIdentityChanged,
        validateCanonicalMakeArguments(
            std.testing.allocator,
            std.testing.io,
            &.{assignment},
        ),
    );
}
