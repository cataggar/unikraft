const std = @import("std");
const facade_paths = @import("zig-facade-paths.zig");
const builtin = @import("builtin");

const lock_name = "build.lock";
const runtime_prefix = "unikraft-zig-facade-";
const injected_runtime_root: ?[]const u8 = null;
const injected_pre_exec_gate: ?[]const u8 = null;
const descriptor_exec_supported = switch (builtin.os.tag) {
    .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos => true,
    else => false,
};

const RuntimeDirectory = struct {
    dir: std.Io.Dir,
    path: []const u8,
};

const BackendExecutable = struct {
    file: std.Io.File,
    path: []const u8,
};

const MetadataRole = enum {
    isolated_temp_root,
    trusted_ancestor,
    user_runtime_root,
    runtime_directory,
    lock_file,
    output_directory,
    marker_file,
    backend_executable,
};

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

    validateOutputIdentity(allocator, init.io, args[1], args[2..]) catch {
        std.debug.print(
            "error: internal Zig facade output mismatch: the canonical O= assignment must exactly match the runner output argument\n",
            .{},
        );
        std.process.exit(2);
    };

    validateCanonicalMakeArguments(allocator, init.io, args[2..]) catch {
        std.debug.print(
            "error: a Make-facing A/O/C/L/P/E path no longer resolves to the canonical identity validated by build.zig; retry from a stable filesystem state\n",
            .{},
        );
        std.process.exit(2);
    };

    const uid = std.posix.system.geteuid();
    const home = canonicalPasswdHome(allocator, init.io, uid) catch |err| {
        std.debug.print(
            "error: unable to obtain and validate the current user's canonical passwd home directory: {s}\n",
            .{@errorName(err)},
        );
        std.process.exit(2);
    };
    var environment = try controlledMakeEnvironment(
        allocator,
        init.environ_map,
        home,
    );
    var executable = resolveBackendExecutable(
        allocator,
        init.io,
        args[2],
        environment.get("PATH").?,
        uid,
    ) catch |err| {
        std.debug.print(
            "error: unable to resolve Make backend executable '{s}' under the sanitized execution policy: {s}; use an existing regular executable with safe ownership and permissions\n",
            .{ args[2], @errorName(err) },
        );
        std.process.exit(2);
    };
    defer executable.file.close(init.io);
    const backend_argv = try allocator.alloc([]const u8, args.len - 2);
    @memcpy(backend_argv, args[2..]);
    backend_argv[0] = executable.path;

    var runtime = prepareSelectedRuntimeDirectory(
        allocator,
        init.io,
        uid,
        home,
    ) catch |err| switch (err) {
        error.UnsafeRuntimeRoot => {
            std.debug.print(
                "error: refusing insecure stable per-user runtime root: expected a canonical directory chain owned only by root or the current user without group/other write access\n",
                .{},
            );
            std.process.exit(2);
        },
        error.UnsafeRuntimeDirectory => {
            std.debug.print(
                "error: refusing insecure UID-scoped Zig facade runtime directory: expected a real, current-user-owned 0700 directory\n",
                .{},
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
    validateOutputIdentity(allocator, init.io, args[1], args[2..]) catch {
        std.debug.print(
            "error: the canonical output identity changed immediately before backend execution; refusing delegation\n",
            .{},
        );
        std.process.exit(2);
    };
    try waitForInjectedPreExecGate(allocator, init.io);

    // Exec keeps the locked descriptor in Make and every normally spawned descendant.
    try setCloseOnExec(lock, false);
    const replace_error = replaceBackend(
        allocator,
        init.io,
        &executable,
        backend_argv,
        &environment,
        uid,
    );
    setCloseOnExec(lock, true) catch {};
    return replace_error;
}

fn isDestructiveGoal(goal: []const u8) bool {
    return std.mem.eql(u8, goal, "clean") or
        std.mem.eql(u8, goal, "clean-libs") or
        std.mem.eql(u8, goal, "properclean") or
        std.mem.eql(u8, goal, "distclean");
}

fn validateOutputIdentity(
    allocator: std.mem.Allocator,
    io: std.Io,
    output: []const u8,
    arguments: []const []const u8,
) !void {
    var make_output: ?[]const u8 = null;
    for (arguments) |argument| {
        if (!std.mem.startsWith(u8, argument, "O=")) continue;
        if (make_output != null) return error.DuplicateOutputAssignment;
        make_output = argument[2..];
    }
    const value = make_output orelse return error.MissingOutputAssignment;
    if (!std.mem.eql(u8, output, value)) return error.OutputMismatch;

    const canonical = try facade_paths.canonicalizeNearestExisting(
        allocator,
        io,
        value,
    );
    defer allocator.free(canonical.path);
    if (!std.mem.eql(u8, canonical.path, output))
        return error.PathIdentityChanged;
}

fn controlledMakeEnvironment(
    allocator: std.mem.Allocator,
    inherited: *const std.process.Environ.Map,
    canonical_home: []const u8,
) !std.process.Environ.Map {
    var environment = std.process.Environ.Map.init(allocator);
    errdefer environment.deinit();

    if (!isSafeEnvironmentPath(canonical_home, false))
        return error.UnsafeEnvironmentValue;
    try environment.put("HOME", canonical_home);
    const inherited_path = inherited.get("PATH") orelse "";
    const search_path = if (isSafeEnvironmentPath(inherited_path, true))
        inherited_path
    else
        "/usr/bin:/bin";
    try environment.put("PATH", search_path);
    for ([_][]const u8{ "LANG", "LC_ALL" }) |name| {
        const value = inherited.get(name) orelse continue;
        if (isSafeLocale(value)) try environment.put(name, value);
    }
    return environment;
}

fn isSafeLocale(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.', '+', '@' => {},
        else => return false,
    };
    return true;
}

fn isSafeEnvironmentPath(value: []const u8, allow_colon: bool) bool {
    if (value.len == 0) return false;
    for (value) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '/', '-', '_', '.', '+', '@' => {},
        ':' => if (!allow_colon) return false,
        else => return false,
    };
    if (allow_colon) {
        var entries = std.mem.splitScalar(u8, value, ':');
        while (entries.next()) |entry| {
            if (entry.len == 0 or !std.fs.path.isAbsolute(entry)) return false;
        }
    } else if (!std.fs.path.isAbsolute(value)) {
        return false;
    }
    return true;
}

fn resolveBackendExecutable(
    allocator: std.mem.Allocator,
    io: std.Io,
    command: []const u8,
    search_path: []const u8,
    uid: std.posix.uid_t,
) !BackendExecutable {
    if (command.len == 0) return error.InvalidBackendExecutable;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);

    if (std.mem.indexOfScalar(u8, command, std.fs.path.sep) != null) {
        const lexical = try std.fs.path.resolve(allocator, &.{ cwd, command });
        defer allocator.free(lexical);
        return validateBackendExecutable(allocator, io, lexical, uid);
    }

    var entries = std.mem.splitScalar(u8, search_path, ':');
    while (entries.next()) |entry| {
        const candidate = try std.fs.path.join(allocator, &.{ entry, command });
        defer allocator.free(candidate);
        return validateBackendExecutable(
            allocator,
            io,
            candidate,
            uid,
        ) catch |err| switch (err) {
            error.BackendExecutableNotFound => continue,
            else => return err,
        };
    }
    return error.BackendExecutableNotFound;
}

fn validateBackendExecutable(
    allocator: std.mem.Allocator,
    io: std.Io,
    lexical: []const u8,
    uid: std.posix.uid_t,
) !BackendExecutable {
    const canonical = try facade_paths.canonicalizeNearestExisting(
        allocator,
        io,
        lexical,
    );
    errdefer allocator.free(canonical.path);
    if (!canonical.exists) return error.BackendExecutableNotFound;
    if (!std.mem.eql(u8, lexical, canonical.path)) {
        const lexical_parent = std.fs.path.dirname(lexical) orelse
            return error.UnsafeBackendExecutable;
        const canonical_parent = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            lexical_parent,
        );
        defer allocator.free(canonical_parent.path);
        if (!canonical_parent.exists or
            !std.mem.eql(u8, lexical_parent, canonical_parent.path))
        {
            return error.UnsafeBackendExecutable;
        }
        try validateBackendDirectoryOnly(
            allocator,
            io,
            canonical_parent.path,
            uid,
        );
    }

    const executable = try openBackendExecutableDescriptorRelative(
        allocator,
        io,
        canonical.path,
        uid,
    );
    return .{ .file = executable, .path = canonical.path };
}

fn validateBackendDirectoryOnly(
    allocator: std.mem.Allocator,
    io: std.Io,
    canonical_path: []const u8,
    uid: std.posix.uid_t,
) !void {
    var ancestors = std.array_list.Managed(Metadata).init(allocator);
    defer ancestors.deinit();
    var directory = std.Io.Dir.cwd().openDir(io, "/", .{
        .follow_symlinks = false,
    }) catch return error.UnsafeBackendExecutable;
    defer directory.close(io);
    try ancestors.append(try metadataForHandle(directory.handle));

    var components = std.mem.tokenizeScalar(u8, canonical_path, '/');
    while (components.next()) |component| {
        const child = directory.openDir(io, component, .{
            .follow_symlinks = false,
        }) catch return error.UnsafeBackendExecutable;
        directory.close(io);
        directory = child;
        try ancestors.append(try metadataForHandle(directory.handle));
    }

    const leaf = ancestors.items[ancestors.items.len - 1];
    const leaf_permissions = leaf.mode & 0o7777;
    if (leaf.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
        (leaf.uid != 0 and leaf.uid != @as(u64, uid)) or
        leaf_permissions & 0o022 != 0)
    {
        return error.UnsafeBackendExecutable;
    }
    var index = ancestors.items.len - 1;
    while (index > 0) {
        const child = ancestors.items[index];
        index -= 1;
        try validateBackendAncestor(ancestors.items[index], child, uid);
    }
}

fn openBackendExecutableDescriptorRelative(
    allocator: std.mem.Allocator,
    io: std.Io,
    canonical_path: []const u8,
    uid: std.posix.uid_t,
) !std.Io.File {
    const parent_path = std.fs.path.dirname(canonical_path) orelse
        return error.UnsafeBackendExecutable;
    const basename = std.fs.path.basename(canonical_path);
    if (basename.len == 0) return error.UnsafeBackendExecutable;

    var ancestors = std.array_list.Managed(Metadata).init(allocator);
    defer ancestors.deinit();
    var directory = std.Io.Dir.cwd().openDir(io, "/", .{
        .follow_symlinks = false,
    }) catch return error.UnsafeBackendExecutable;
    defer directory.close(io);
    try ancestors.append(try metadataForHandle(directory.handle));

    var components = std.mem.tokenizeScalar(u8, parent_path, '/');
    while (components.next()) |component| {
        const child = directory.openDir(io, component, .{
            .follow_symlinks = false,
        }) catch return error.UnsafeBackendExecutable;
        directory.close(io);
        directory = child;
        try ancestors.append(try metadataForHandle(directory.handle));
    }

    const executable = directory.openFile(io, basename, .{
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.BackendExecutableNotFound,
        else => return error.UnsafeBackendExecutable,
    };
    errdefer executable.close(io);
    const executable_metadata = try metadataForHandle(executable.handle);
    try validateMetadata(executable_metadata, uid, .backend_executable);

    var child_metadata = executable_metadata;
    var index = ancestors.items.len;
    while (index > 0) {
        index -= 1;
        const ancestor = ancestors.items[index];
        try validateBackendAncestor(ancestor, child_metadata, uid);
        child_metadata = ancestor;
    }
    return executable;
}

fn validateBackendAncestor(
    ancestor: Metadata,
    child: Metadata,
    uid: std.posix.uid_t,
) !void {
    const permissions = ancestor.mode & 0o7777;
    if (ancestor.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
        (ancestor.uid != 0 and ancestor.uid != @as(u64, uid)))
    {
        return error.UnsafeBackendExecutable;
    }
    if (permissions & 0o022 == 0) return;

    const sticky_root =
        ancestor.uid == 0 and
        permissions & 0o7000 == 0o1000 and
        permissions & 0o777 == 0o777;
    const child_permissions = child.mode & 0o7777;
    const trusted_sticky_entry =
        (child.uid == 0 or child.uid == @as(u64, uid)) and
        child_permissions & 0o022 == 0;
    if (!sticky_root or !trusted_sticky_entry)
        return error.UnsafeBackendExecutable;
}

fn replaceBackend(
    allocator: std.mem.Allocator,
    io: std.Io,
    executable: *BackendExecutable,
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    uid: std.posix.uid_t,
) !void {
    if (comptime descriptor_exec_supported) {
        const argv_buffer = try allocator.allocSentinel(
            ?[*:0]const u8,
            argv.len,
            null,
        );
        for (argv, 0..) |argument, index| {
            argv_buffer[index] = (try allocator.dupeZ(u8, argument)).ptr;
        }
        const environment_block = try environment.createPosixBlock(
            allocator,
            .{},
        );

        try setCloseOnExec(executable.file, false);
        const result = fexecve(
            executable.file.handle,
            argv_buffer.ptr,
            environment_block.slice.ptr,
        );
        setCloseOnExec(executable.file, true) catch {};
        return switch (std.posix.errno(result)) {
            .ACCES => error.AccessDenied,
            .NOENT => error.FileNotFound,
            .NOEXEC => error.InvalidExe,
            .TXTBSY => error.FileBusy,
            else => |err| std.posix.unexpectedErrno(err),
        };
    }

    var revalidated = try validateBackendExecutable(
        allocator,
        io,
        executable.path,
        uid,
    );
    defer revalidated.file.close(io);
    defer allocator.free(revalidated.path);
    if (!std.mem.eql(u8, executable.path, revalidated.path))
        return error.UnsafeBackendExecutable;
    return std.process.replace(io, .{
        .argv = argv,
        .environ_map = environment,
    });
}

extern "c" fn fexecve(
    fd: c_int,
    argv: [*:null]const ?[*:0]const u8,
    environment: [*:null]const ?[*:0]const u8,
) c_int;

fn waitForInjectedPreExecGate(
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    const gate = injected_pre_exec_gate orelse return;
    const arm_path = try std.fs.path.join(allocator, &.{ gate, "arm" });
    const arm = std.Io.Dir.openFileAbsolute(io, arm_path, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    arm.close(io);

    const ready_path = try std.fs.path.join(allocator, &.{ gate, "ready" });
    const ready = try std.Io.Dir.createFileAbsolute(io, ready_path, .{
        .truncate = true,
    });
    ready.close(io);
    const release_path = try std.fs.path.join(allocator, &.{ gate, "release" });
    var attempts: usize = 0;
    while (attempts < 3000) : (attempts += 1) {
        const release = std.Io.Dir.openFileAbsolute(io, release_path, .{
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.FileNotFound => {
                try std.Io.sleep(io, .fromMilliseconds(10), .awake);
                continue;
            },
            else => return err,
        };
        release.close(io);
        return;
    }
    return error.TestGateTimeout;
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

fn canonicalPasswdHome(
    allocator: std.mem.Allocator,
    io: std.Io,
    uid: std.posix.uid_t,
) ![]const u8 {
    if (comptime builtin.os.tag == .windows)
        return error.UnsupportedHost;

    var entry: std.c.passwd = undefined;
    var result: ?*std.c.passwd = null;
    var buffer: [16 * 1024]u8 = undefined;
    if (std.c.getpwuid_r(uid, &entry, &buffer, buffer.len, &result) != 0 or
        result == null or entry.dir == null)
    {
        return error.PasswdLookupFailed;
    }
    const lexical = std.mem.span(entry.dir.?);
    if (!std.fs.path.isAbsolute(lexical)) return error.UnsafeRuntimeRoot;

    var canonical_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try std.Io.Dir.realPathFileAbsolute(
        io,
        lexical,
        &canonical_buffer,
    );
    const canonical = canonical_buffer[0..length];
    if (!isSafeEnvironmentPath(canonical, false))
        return error.UnsafeRuntimeRoot;
    try validateTrustedDirectoryChain(io, canonical, uid, true);
    return allocator.dupe(u8, canonical);
}

fn prepareSelectedRuntimeDirectory(
    allocator: std.mem.Allocator,
    io: std.Io,
    uid: std.posix.uid_t,
    canonical_home: []const u8,
) !RuntimeDirectory {
    if (injected_runtime_root) |root| {
        return prepareRuntimeDirectory(
            allocator,
            io,
            root,
            uid,
            .isolated_temp_root,
        );
    }

    if (comptime builtin.os.tag == .linux) {
        const run_user = try std.fmt.allocPrint(allocator, "/run/user/{d}", .{uid});
        validateTrustedDirectoryChain(io, run_user, uid, true) catch |err| switch (err) {
            error.FileNotFound => return prepareRuntimeDirectory(
                allocator,
                io,
                canonical_home,
                uid,
                .user_runtime_root,
            ),
            else => return err,
        };
        return prepareRuntimeDirectory(
            allocator,
            io,
            run_user,
            uid,
            .user_runtime_root,
        );
    }

    if (comptime builtin.os.tag == .macos) {
        const user_temp = try darwinUserTempDirectory(allocator);
        const canonical = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            user_temp,
        );
        if (!canonical.exists) return error.UnsafeRuntimeRoot;
        try validateTrustedDirectoryChain(io, canonical.path, uid, true);
        return prepareRuntimeDirectory(
            allocator,
            io,
            canonical.path,
            uid,
            .user_runtime_root,
        );
    }

    return prepareRuntimeDirectory(
        allocator,
        io,
        canonical_home,
        uid,
        .user_runtime_root,
    );
}

fn darwinUserTempDirectory(allocator: std.mem.Allocator) ![]const u8 {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedHost;
    const darwin_user_temp_dir = 65537;
    const needed = confstr(darwin_user_temp_dir, null, 0);
    if (needed <= 1 or needed > std.fs.max_path_bytes)
        return error.UnsafeRuntimeRoot;
    const buffer = try allocator.alloc(u8, needed);
    const actual = confstr(darwin_user_temp_dir, buffer.ptr, buffer.len);
    if (actual != needed or buffer[needed - 1] != 0)
        return error.UnsafeRuntimeRoot;
    return buffer[0 .. needed - 1];
}

extern "c" fn confstr(name: c_int, buffer: ?[*]u8, length: usize) usize;

fn validateTrustedDirectoryChain(
    io: std.Io,
    path: []const u8,
    uid: std.posix.uid_t,
    require_user_final: bool,
) !void {
    if (!std.fs.path.isAbsolute(path)) return error.UnsafeRuntimeRoot;
    var current = path;
    var final = true;
    while (true) {
        var directory = std.Io.Dir.cwd().openDir(io, current, .{
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            else => return error.UnsafeRuntimeRoot,
        };
        defer directory.close(io);
        const role: MetadataRole = if (final and require_user_final)
            .user_runtime_root
        else
            .trusted_ancestor;
        try validateMetadata(try metadataForHandle(directory.handle), uid, role);

        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;
        current = parent;
        final = false;
    }
}

fn prepareRuntimeDirectory(
    allocator: std.mem.Allocator,
    io: std.Io,
    runtime_root: []const u8,
    uid: std.posix.uid_t,
    runtime_root_role: MetadataRole,
) !RuntimeDirectory {
    const absolute_root = try std.fs.path.resolve(allocator, &.{runtime_root});
    var root = std.Io.Dir.cwd().openDir(io, absolute_root, .{
        .follow_symlinks = false,
    }) catch return error.UnsafeRuntimeRoot;
    defer root.close(io);
    try validateMetadata(try metadataForHandle(root.handle), uid, runtime_root_role);

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
        .isolated_temp_root => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR)
                return error.UnsafeRuntimeRoot;
            const user_owned_private =
                metadata.uid == @as(u64, uid) and
                permissions & 0o700 == 0o700 and
                permissions & 0o022 == 0;
            if (!user_owned_private) return error.UnsafeRuntimeRoot;
        },
        .trusted_ancestor => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
                (metadata.uid != 0 and metadata.uid != @as(u64, uid)) or
                permissions & 0o022 != 0)
            {
                return error.UnsafeRuntimeRoot;
            }
        },
        .user_runtime_root => {
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
                metadata.uid != @as(u64, uid) or
                permissions & 0o700 != 0o700 or
                permissions & 0o022 != 0)
            {
                return error.UnsafeRuntimeRoot;
            }
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
        .backend_executable => {
            const trusted_owner =
                metadata.uid == 0 or metadata.uid == @as(u64, uid);
            const executable_by_user = if (uid == 0)
                permissions & 0o111 != 0
            else if (metadata.uid == @as(u64, uid))
                permissions & 0o100 != 0
            else
                permissions & 0o001 != 0;
            if (metadata.mode & std.posix.S.IFMT != std.posix.S.IFREG or
                !trusted_owner or
                permissions & 0o7000 != 0 or
                permissions & 0o022 != 0 or
                !executable_by_user)
            {
                return error.UnsafeBackendExecutable;
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

test "production runtime selection has no environment override" {
    try std.testing.expect(injected_runtime_root == null);
}

test "runtime roots require trusted ownership and permissions" {
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
        error.UnsafeRuntimeRoot,
        validateMetadata(metadata, uid, .isolated_temp_root),
    );

    metadata.mode = std.posix.S.IFDIR | 0o755;
    metadata.uid = 0;
    try validateMetadata(metadata, uid, .trusted_ancestor);
    metadata.mode = std.posix.S.IFDIR | 0o775;
    try std.testing.expectError(
        error.UnsafeRuntimeRoot,
        validateMetadata(metadata, uid, .trusted_ancestor),
    );

    metadata.mode = std.posix.S.IFDIR | 0o700;
    metadata.uid = @as(u64, uid);
    try validateMetadata(metadata, uid, .user_runtime_root);
    metadata.uid = @as(u64, uid) + 1;
    try std.testing.expectError(
        error.UnsafeRuntimeRoot,
        validateMetadata(metadata, uid, .user_runtime_root),
    );
}

test "controlled Make environment excludes control and build variables" {
    var inherited = std.process.Environ.Map.init(std.testing.allocator);
    defer inherited.deinit();
    try inherited.put("PATH", "/safe/bin");
    try inherited.put("LANG", "en_US.UTF-8");
    try inherited.put("LC_ALL", "bad;locale");
    for ([_][]const u8{
        "MAKEFLAGS",
        "GNUMAKEFLAGS",
        "MAKEFILES",
        "MFLAGS",
        "MAKEOVERRIDES",
        "MAKELEVEL",
        "CC",
        "BUILD_DIR",
        "UK_CONFIG",
        "CONFIG_DIR",
        "O",
        "A",
    }) |name| try inherited.put(name, "hostile");

    var controlled = try controlledMakeEnvironment(
        std.testing.allocator,
        &inherited,
        "/canonical/home",
    );
    defer controlled.deinit();
    try std.testing.expectEqualStrings("/safe/bin", controlled.get("PATH").?);
    try std.testing.expectEqualStrings("/canonical/home", controlled.get("HOME").?);
    try std.testing.expectEqualStrings("en_US.UTF-8", controlled.get("LANG").?);
    try std.testing.expect(controlled.get("LC_ALL") == null);
    try std.testing.expectEqual(@as(usize, 3), controlled.keys().len);

    try inherited.put("PATH", "/safe/bin;hostile");
    var fallback = try controlledMakeEnvironment(
        std.testing.allocator,
        &inherited,
        "/canonical/home",
    );
    defer fallback.deinit();
    try std.testing.expectEqualStrings("/usr/bin:/bin", fallback.get("PATH").?);
    try std.testing.expect(!isSafeEnvironmentPath("/bin::/usr/bin", true));
    try std.testing.expect(!isSafeEnvironmentPath("/home/user;hostile", false));
}

test "backend executable resolution uses only validated paths" {
    const uid = std.posix.system.geteuid();
    var bare = try resolveBackendExecutable(
        std.testing.allocator,
        std.testing.io,
        "make",
        "/usr/bin",
        uid,
    );
    defer bare.file.close(std.testing.io);
    defer std.testing.allocator.free(bare.path);
    try std.testing.expectEqualStrings("/usr/bin/make", bare.path);

    var absolute = try resolveBackendExecutable(
        std.testing.allocator,
        std.testing.io,
        "/usr/bin/make",
        "/does/not/matter",
        uid,
    );
    defer absolute.file.close(std.testing.io);
    defer std.testing.allocator.free(absolute.path);
    try std.testing.expectEqualStrings("/usr/bin/make", absolute.path);

    try std.testing.expectError(
        error.BackendExecutableNotFound,
        resolveBackendExecutable(
            std.testing.allocator,
            std.testing.io,
            "missing",
            "/usr/bin",
            uid,
        ),
    );
    try std.testing.expectError(
        error.UnsafeBackendExecutable,
        resolveBackendExecutable(
            std.testing.allocator,
            std.testing.io,
            "/etc/passwd",
            "/does/not/matter",
            uid,
        ),
    );
}

test "backend ancestor policy rejects writable directories and handles sticky roots" {
    const uid = std.posix.system.geteuid();
    const executable = Metadata{
        .mode = std.posix.S.IFREG | 0o700,
        .uid = @as(u64, uid),
        .nlink = 1,
        .size = 0,
    };
    try validateBackendAncestor(.{
        .mode = std.posix.S.IFDIR | 0o755,
        .uid = 0,
        .nlink = 1,
        .size = 0,
    }, executable, uid);
    try validateBackendAncestor(.{
        .mode = std.posix.S.IFDIR | 0o700,
        .uid = @as(u64, uid),
        .nlink = 1,
        .size = 0,
    }, executable, uid);
    try std.testing.expectError(
        error.UnsafeBackendExecutable,
        validateBackendAncestor(.{
            .mode = std.posix.S.IFDIR | 0o777,
            .uid = @as(u64, uid),
            .nlink = 1,
            .size = 0,
        }, executable, uid),
    );
    try validateBackendAncestor(.{
        .mode = std.posix.S.IFDIR | 0o1777,
        .uid = 0,
        .nlink = 1,
        .size = 0,
    }, executable, uid);
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

test "runner output argument and Make O assignment have one identity" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDirPath(std.testing.io, "output");
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const output = try std.fs.path.join(
        std.testing.allocator,
        &.{ root_buffer[0..root_length], "output" },
    );
    defer std.testing.allocator.free(output);
    const assignment = try std.fmt.allocPrint(
        std.testing.allocator,
        "O={s}",
        .{output},
    );
    defer std.testing.allocator.free(assignment);

    try validateOutputIdentity(
        std.testing.allocator,
        std.testing.io,
        output,
        &.{ "make", "all", assignment },
    );
    try std.testing.expectError(
        error.OutputMismatch,
        validateOutputIdentity(
            std.testing.allocator,
            std.testing.io,
            "/different/output",
            &.{ "make", "all", assignment },
        ),
    );
    try std.testing.expectError(
        error.DuplicateOutputAssignment,
        validateOutputIdentity(
            std.testing.allocator,
            std.testing.io,
            output,
            &.{ assignment, assignment },
        ),
    );
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
