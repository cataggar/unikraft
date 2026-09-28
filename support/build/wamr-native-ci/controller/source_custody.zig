// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const Sha256 = core.Sha256;
const files = core.private_files;
const process = core.process;
const linux = std.os.linux;
const limits = @import("custody_limits.zig");
const physical = @import("custody_files.zig");
const inputs = @import("controller_source_closure");
pub const Entry = inputs.Entry;

// The embedded bytes make this executable's own compile-time source inputs
// independently checkable. Git revision/clean-tree admission is owned by PR 02.
pub const closure = inputs.entries;

pub fn contentClosure() [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update("uk.wamr.controller-source-v1\x00");
    for (closure) |entry| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, entry.name.len, .big);
        hash.update(&length);
        hash.update(entry.name);
        std.mem.writeInt(u64, &length, entry.content.len, .big);
        hash.update(&length);
        hash.update(entry.content);
    }
    return hash.finalResult();
}

pub fn verifyContent(expected: Entry, observed: []const u8) !void {
    if (observed.len != expected.content.len or !std.mem.eql(u8, observed, expected.content))
        return error.SourceChanged;
}

pub fn verifyPhysical(io: std.Io, allocator: std.mem.Allocator, repository: []const u8) !void {
    const dir = try files.openDirectory(io, repository, .artifact);
    defer dir.close(io);
    if (std.os.linux.geteuid() == 0) return error.RootUser;
    for (closure) |entry| {
        const path = try std.fs.path.join(allocator, &.{ repository, entry.name });
        defer allocator.free(path);
        var retained = try files.RetainedFile.open(io, path, .artifact);
        defer retained.close(io);
        const before = retained.file_snapshot;
        if (before.nlink != 1 or before.uid != std.os.linux.geteuid() or
            before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or
            before.mode & 0o022 != 0 or before.size != entry.content.len)
            return error.UnsafeSource;
        var contents = try files.readSensitiveFile(io, allocator, retained.file, 64 * 1024 * 1024, .artifact);
        defer contents.deinit();
        try verifyContent(entry, contents.bytes());
        try retained.verify(io);
    }
}

pub const Source = struct {
    revision: []const u8,
    tree: []const u8,
    custody: struct {
        schema: []const u8 = "uk.wamr.git-physical-source",
        version: u8 = 1,
        object_format: []const u8,
        files: usize,
        directories: usize,
        bytes: usize,
        content_sha256: [64]u8,
        physical_sha256: [64]u8,
        role_excluded_outputs: [limits.roles.len][]const u8 = limits.roles,
    },

    pub fn same(a: Source, b: Source) bool {
        const first = a.custody;
        const second = b.custody;
        if (!std.mem.eql(u8, a.revision, b.revision) or
            !std.mem.eql(u8, a.tree, b.tree) or
            !std.mem.eql(u8, first.schema, second.schema) or
            first.version != second.version or
            !std.mem.eql(u8, first.object_format, second.object_format) or
            first.files != second.files or first.directories != second.directories or
            first.bytes != second.bytes or
            !std.meta.eql(first.content_sha256, second.content_sha256) or
            !std.meta.eql(first.physical_sha256, second.physical_sha256))
            return false;
        for (first.role_excluded_outputs, second.role_excluded_outputs) |left, right|
            if (!std.mem.eql(u8, left, right)) return false;
        return true;
    }
};

const git_prefix = [_][]const u8{
    "--no-pager",     "-c",                         "core.hooksPath=/dev/null", "-c",                 "core.fsmonitor=false",
    "-c",             "core.fsmonitorHookVersion=", "-c",                       "credential.helper=", "-c",
    "core.pager=cat",
};

pub const git_probe_deadline_ms = 120_000;

pub fn gitOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    git_executable: []const u8,
    args: []const []const u8,
    limit: usize,
    output: ?std.Io.File,
) ![]u8 {
    if (output != null and (limit == 0 or limit > limits.tracked_file))
        return error.InvalidGitBound;
    try process.initialize();
    const cwd = try files.openDirectory(io, repository, .artifact);
    defer cwd.close(io);
    const before = try files.snapshot(.{ .handle = cwd.handle, .flags = .{ .nonblocking = false } });
    var executable = try process.Executable.open(io, git_executable);
    defer executable.close(io);
    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("GIT_CONFIG_GLOBAL", "/dev/null");
    try env.put("GIT_CONFIG_NOSYSTEM", "1");
    try env.put("GIT_NO_REPLACE_OBJECTS", "1");
    try env.put("GIT_OPTIONAL_LOCKS", "0");
    try env.put("GIT_PAGER", "cat");
    try env.put("GIT_TERMINAL_PROMPT", "0");
    try env.put("HOME", "/");
    try env.put("LANG", "C");
    try env.put("LC_ALL", "C");
    try env.put("PAGER", "cat");
    try env.put("PATH", "/usr/bin:/bin");
    const argv = try allocator.alloc([]const u8, 1 + git_prefix.len + args.len);
    defer allocator.free(argv);
    argv[0] = git_executable;
    @memcpy(argv[1..][0..git_prefix.len], &git_prefix);
    @memcpy(argv[1 + git_prefix.len ..], args);
    const bounded_fd: ?linux.fd_t = if (output != null) block: {
        const created = linux.memfd_create("wamr-source-archive", linux.MFD.CLOEXEC | linux.MFD.ALLOW_SEALING);
        if (linux.errno(created) != .SUCCESS) return error.ArchiveBoundUnavailable;
        const fd: linux.fd_t = @intCast(created);
        if (fd <= 2 or linux.errno(linux.ftruncate(fd, @intCast(limit))) != .SUCCESS or
            linux.errno(linux.fcntl(fd, linux.F.ADD_SEALS, 4)) != .SUCCESS)
        {
            _ = linux.close(fd);
            return error.ArchiveBoundUnavailable;
        }
        break :block fd;
    } else null;
    defer {
        if (bounded_fd) |fd| _ = linux.close(fd);
    }
    const primary = try process.Deadline.afterMilliseconds(git_probe_deadline_ms);
    const cleanup: process.Deadline = .{ .expires_ns = try std.math.add(u64, primary.expires_ns, 10 * std.time.ns_per_s) };
    var result = try process.runCommand(allocator, io, .{
        .executable = executable,
        .argv = argv,
        .environment = &env,
        .cwd = cwd,
        .primary_deadline = primary,
        .cleanup_deadline = cleanup,
        .stdout_file = if (bounded_fd) |fd| std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } } else null,
        .snapshot_executable = false,
        .limits = .{ .stdout_bytes = if (output != null) 1024 else @max(1, @min(limit, 8 * limits.mib)), .stderr_bytes = 4096 },
    });
    defer result.deinit(allocator);
    try requireGitOutcome(result, limit);
    if (bounded_fd) |fd| {
        const length = linux.lseek(fd, 0, 1);
        if (linux.errno(length) != .SUCCESS or length == 0 or length > limit)
            return error.GitRefused;
        const bounded: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
        var buffer: [64 * 1024]u8 = undefined;
        var offset: usize = 0;
        while (offset < length) {
            const size = @min(buffer.len, length - offset);
            if (try bounded.readPositionalAll(io, buffer[0..size], offset) != size)
                return error.GitRefused;
            try output.?.writePositionalAll(io, buffer[0..size], offset);
            offset += size;
        }
    }
    const after = try files.openDirectory(io, repository, .artifact);
    defer after.close(io);
    if (!files.sameSnapshot(before, try files.snapshot(.{ .handle = after.handle, .flags = .{ .nonblocking = false } })))
        return error.SourceChanged;
    return allocator.dupe(u8, result.stdout);
}

pub fn requireGitOutcome(result: process.CommandResult, limit: usize) !void {
    if (result.primary_deadline_reached) return error.GitTimedOut;
    if (!result.succeeded()) {
        switch (result.primary) {
            .exited => |code| if (code != 0) return error.GitExited,
            .signal => return error.GitSignaled,
            .timeout => return error.GitTimedOut,
            .cancelled => return error.GitCancelled,
            .output_overflow => return error.GitOutputOverflow,
            .exec_failed => return error.GitExecFailed,
            .snapshot_unsupported => return error.GitSnapshotUnsupported,
            .event_limit => return error.GitEventLimit,
            .local_io => {
                if (result.stdout_status == .io_failed) return error.GitStdoutIo;
                if (result.stderr_status == .io_failed) return error.GitStderrIo;
                if (result.primary_events == 0) return error.GitStartupIo;
                return error.GitMonitorIo;
            },
            .executable_changed => return error.GitExecutableChanged,
            .unknown => return error.GitUnknownTermination,
        }
        if (!result.cleanup_complete or result.cleanup != .complete) return switch (result.cleanup) {
            .deadline => error.GitCleanupTimedOut,
            .event_limit => error.GitCleanupEventLimit,
            .descendant_untracked => error.GitCleanupDescendantUntracked,
            .identity_changed => error.GitCleanupIdentityChanged,
            .signal_failed => error.GitCleanupSignalFailed,
            .reap_failed => error.GitCleanupReapFailed,
            .proc_unavailable => error.GitCleanupProcUnavailable,
            .local_io => error.GitCleanupLocalIo,
            .complete, .not_required => error.GitCleanupIncomplete,
        };
        if (result.descendants.limit_exceeded) return error.GitDescendantLimit;
        if (result.stdout_status != .complete or result.stderr_status != .complete)
            return error.GitStreamIncomplete;
        if (!result.executable_stable) return error.GitExecutableChanged;
        return error.GitRefused;
    }
    if (result.stderr.len != 0) return error.GitDiagnostic;
    if (result.stdout.len > limit) return error.GitOutputOverflow;
}

fn gitLine(allocator: std.mem.Allocator, io: std.Io, repo: []const u8, git: []const u8, args: []const []const u8) ![]u8 {
    const output = try gitOutput(allocator, io, repo, git, args, 128, null);
    defer allocator.free(output);
    if (output.len < 2 or output[output.len - 1] != '\n' or
        std.mem.indexOfScalar(u8, output[0 .. output.len - 1], '\n') != null)
        return error.InvalidGitOutput;
    return allocator.dupe(u8, output[0 .. output.len - 1]);
}

fn clean(allocator: std.mem.Allocator, io: std.Io, repo: []const u8, git: []const u8) !void {
    const output = try gitOutput(allocator, io, repo, git, &.{
        "status", "--porcelain=v2", "--untracked-files=all", "-z",
    }, limits.mib, null);
    defer allocator.free(output);
    if (output.len != 0) return error.DirtySource;
}

const Ignored = struct { entries: usize, bytes: usize, physical_sha256: [64]u8, inventory_sha256: [64]u8 };

fn inspectOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    repo: []const u8,
    git: []const u8,
    role: []const u8,
    relative: []const u8,
    state: *Ignored,
    hash: *Sha256,
) !void {
    try limits.relative(relative, limits.ignored_path, limits.ignored_depth);
    _ = try limits.outputRole(relative);
    const path = try std.fs.path.join(allocator, &.{ repo, relative });
    defer allocator.free(path);
    const parent_path = std.fs.path.dirname(path).?;
    const parent = try files.openDirectory(io, parent_path, .artifact);
    defer parent.close(io);
    const named = try parent.openFile(io, std.fs.path.basename(path), .{ .path_only = true, .follow_symlinks = false });
    defer named.close(io);
    const before = try files.snapshot(named);
    if (before.uid != std.os.linux.geteuid()) return error.UnsafeIgnoredEntry;
    const kind = before.mode & std.os.linux.S.IFMT;
    if (std.mem.eql(u8, relative, role)) {
        const file_role = std.mem.eql(u8, role, "support/apps/wamr-aot/.config");
        if (kind != (if (file_role) @as(u32, std.os.linux.S.IFREG) else std.os.linux.S.IFDIR) or
            before.mode & 0o022 != 0 or (file_role and before.nlink != 1))
            return error.UnsafeIgnoredEntry;
    }
    try limits.addBounded(&state.entries, 1, limits.ignored_entries);
    if (kind == std.os.linux.S.IFDIR) {
        if (before.mode & 0o022 != 0) return error.UnsafeIgnoredEntry;
        try physical.bind(allocator, hash, .{ "directory", relative, physical.metadata(before), @as(?[]const u8, null) });
        const dir = try files.openDirectory(io, path, .artifact);
        defer dir.close(io);
        var names: std.ArrayList([]const u8) = .empty;
        defer {
            for (names.items) |name| allocator.free(name);
            names.deinit(allocator);
        }
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (names.items.len >= limits.ignored_entries - state.entries) return error.LimitExceeded;
            try names.append(allocator, try allocator.dupe(u8, entry.name));
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        for (names.items) |name| {
            const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ relative, name });
            defer allocator.free(child);
            try inspectOutput(allocator, io, repo, git, role, child, state, hash);
        }
    } else if (kind == std.os.linux.S.IFREG) {
        if (before.nlink != 1 or before.size > limits.ignored_file)
            return error.UnsafeIgnoredEntry;
        try limits.addBounded(&state.bytes, @intCast(before.size), limits.ignored_bytes);
        try physical.bind(allocator, hash, .{ "file", relative, physical.metadata(before), @as(?[]const u8, null) });
    } else if (kind == std.os.linux.S.IFLNK) {
        if (before.nlink != 1 or before.size == 0 or before.size >= 4096)
            return error.UnsafeIgnoredEntry;
        var buffer: [4096]u8 = undefined;
        const link: std.Io.Dir = .{ .handle = named.handle };
        const length = try link.readLink(io, "", &buffer);
        if (length != before.size) return error.IgnoredChanged;
        try limits.addBounded(&state.bytes, length, limits.ignored_bytes);
        const target = if (std.Io.Dir.realPathFileAbsoluteAlloc(io, path, allocator)) |actual| block: {
            defer allocator.free(actual);
            break :block try allocator.dupe(u8, actual);
        } else |err| switch (err) {
            error.FileNotFound => try std.fs.path.resolve(allocator, &.{ parent_path, buffer[0..length] }),
            else => return error.IgnoredLinkEscapesRole,
        };
        defer allocator.free(target);
        const role_root = try std.fs.path.join(allocator, &.{ repo, role });
        defer allocator.free(role_root);
        if (!(std.mem.eql(u8, target, role_root) or
            (target.len > role_root.len and std.mem.startsWith(u8, target, role_root) and target[role_root.len] == '/')))
        {
            if (target.len <= repo.len or !std.mem.startsWith(u8, target, repo) or target[repo.len] != '/')
                return error.IgnoredLinkEscapesRole;
            const tracked = target[repo.len + 1 ..];
            try limits.relative(tracked, limits.ignored_path, limits.ignored_depth);
            _ = physical.readFile(io, target, limits.tracked_file, false) catch return error.IgnoredLinkEscapesRole;
            const listed = gitOutput(allocator, io, repo, git, &.{
                "ls-files", "--error-unmatch", "-z", "--", tracked,
            }, limits.ignored_path + 1, null) catch return error.IgnoredLinkEscapesRole;
            defer allocator.free(listed);
            if (listed.len != tracked.len + 1 or
                !std.mem.eql(u8, listed[0..tracked.len], tracked) or listed[tracked.len] != 0)
                return error.IgnoredLinkEscapesRole;
        }
        try physical.bind(allocator, hash, .{ "symlink", relative, physical.metadata(before), buffer[0..length] });
    } else return error.UnsafeIgnoredEntry;
    const reopened = try parent.openFile(io, std.fs.path.basename(path), .{ .path_only = true, .follow_symlinks = false });
    defer reopened.close(io);
    if (!files.sameSnapshot(before, try files.snapshot(named)) or
        !files.sameSnapshot(before, try files.snapshot(reopened)))
        return error.IgnoredChanged;
}

fn ignoredState(allocator: std.mem.Allocator, io: std.Io, repo: []const u8, git: []const u8) !Ignored {
    const inventory = try gitOutput(allocator, io, repo, git, &.{
        "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z",
    }, limits.ignored_git_output, null);
    defer allocator.free(inventory);
    if (inventory.len != 0 and inventory[inventory.len - 1] != 0)
        return error.InvalidIgnoredInventory;
    var paths = std.StringHashMap(void).init(allocator);
    defer paths.deinit();
    if (inventory.len != 0) {
        var entries = std.mem.splitScalar(u8, inventory[0 .. inventory.len - 1], 0);
        while (entries.next()) |name| {
            const path = if (std.mem.endsWith(u8, name, "/")) name[0 .. name.len - 1] else name;
            _ = try limits.outputRole(path);
            if (paths.contains(path) or paths.count() >= limits.ignored_entries)
                return error.InvalidIgnoredInventory;
            try paths.put(path, {});
        }
    }
    var inventory_hash: [32]u8 = undefined;
    Sha256.hash(inventory, &inventory_hash, .{});
    var hash = Sha256.init(.{});
    hash.update("uk.wamr.ignored-source-policy-v1\x00");
    var state: Ignored = .{ .entries = 0, .bytes = 0, .physical_sha256 = undefined, .inventory_sha256 = std.fmt.bytesToHex(inventory_hash, .lower) };
    for (limits.roles) |role| {
        try inspectOutput(allocator, io, repo, git, role, role, &state, &hash);
    }
    state.physical_sha256 = physical.hex(&hash);
    return state;
}

const Tracked = struct { path: []const u8, mode: []const u8, oid: []const u8 };

fn trackedMap(allocator: std.mem.Allocator, listing: []const u8, oid_length: usize) ![]Tracked {
    if (listing.len < 2 or listing.len > 4 * limits.mib or listing[listing.len - 1] != 0)
        return error.InvalidGitOutput;
    var entries: std.ArrayList(Tracked) = .empty;
    errdefer entries.deinit(allocator);
    var names: std.StringHashMap(void) = .init(allocator);
    defer names.deinit();
    var parts = std.mem.splitScalar(u8, listing[0 .. listing.len - 1], 0);
    while (parts.next()) |entry| {
        const tab = std.mem.indexOfScalar(u8, entry, '\t') orelse return error.InvalidGitOutput;
        var header = std.mem.splitScalar(u8, entry[0..tab], ' ');
        const mode = header.next() orelse return error.InvalidGitOutput;
        const kind = header.next() orelse return error.InvalidGitOutput;
        const oid = header.next() orelse return error.InvalidGitOutput;
        if (header.next() != null or !std.mem.eql(u8, kind, "blob") or
            !(std.mem.eql(u8, mode, "100644") or std.mem.eql(u8, mode, "100755") or std.mem.eql(u8, mode, "120000")) or
            oid.len != oid_length)
            return error.InvalidGitOutput;
        for (oid) |digit| if (!std.ascii.isHex(digit)) return error.InvalidGitOutput;
        const path = entry[tab + 1 ..];
        try limits.relative(path, 1024, 64);
        if (names.contains(path)) return error.InvalidGitOutput;
        try names.put(path, {});
        if (entries.items.len >= limits.tracked_entries) return error.LimitExceeded;
        try entries.append(allocator, .{ .path = path, .mode = mode, .oid = oid });
    }
    return entries.toOwnedSlice(allocator);
}

fn directoryBefore(io: std.Io, path: []const u8) !files.Snapshot {
    return physical.directory(io, path, false);
}

fn trackedFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    repo: []const u8,
    entry: Tracked,
    format: []const u8,
) !struct { bytes: usize, sha256: [64]u8, metadata: [9]i128 } {
    const path = try std.fs.path.join(allocator, &.{ repo, entry.path });
    defer allocator.free(path);
    var raw: []u8 = undefined;
    var before: files.Snapshot = undefined;
    var retained_file: ?files.RetainedFile = null;
    defer if (retained_file) |*retained| retained.close(io);
    if (std.mem.eql(u8, entry.mode, "120000")) {
        const parent_path = std.fs.path.dirname(path).?;
        const parent = try files.openDirectory(io, parent_path, .artifact);
        defer parent.close(io);
        const link = try parent.openFile(io, std.fs.path.basename(path), .{ .path_only = true, .follow_symlinks = false });
        defer link.close(io);
        before = try files.snapshot(link);
        if (before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFLNK or
            before.size == 0 or before.size >= 4096 or
            (before.uid != 0 and before.uid != std.os.linux.geteuid())) return error.UnsafeSource;
        var buffer: [4096]u8 = undefined;
        const handle: std.Io.Dir = .{ .handle = link.handle };
        const count = try handle.readLink(io, "", &buffer);
        if (count != before.size) return error.SourceChanged;
        const target = buffer[0..count];
        const resolved = try std.fs.path.resolve(allocator, &.{ parent_path, target });
        defer allocator.free(resolved);
        if (!(std.mem.eql(u8, resolved, repo) or
            (std.mem.startsWith(u8, resolved, repo) and resolved.len > repo.len and resolved[repo.len] == '/')))
            return error.UnsafeSource;
        if (files.openDirectory(io, resolved, .artifact)) |dir| {
            dir.close(io);
        } else |_| {
            var destination = try files.RetainedFile.open(io, resolved, .artifact);
            defer destination.close(io);
            try destination.verify(io);
        }
        raw = try allocator.dupe(u8, target);
        const named = try parent.openFile(io, std.fs.path.basename(path), .{ .path_only = true, .follow_symlinks = false });
        defer named.close(io);
        if (!files.sameSnapshot(before, try files.snapshot(named)) or
            !files.sameSnapshot(before, try files.snapshot(link))) return error.SourceChanged;
    } else {
        const retained = try files.RetainedFile.open(io, path, .artifact);
        before = retained.file_snapshot;
        retained_file = retained;
        if (before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or
            before.size > limits.tracked_file or before.nlink != 1 or
            (before.uid != 0 and before.uid != std.os.linux.geteuid()) or before.mode & 0o022 != 0 or
            (before.mode & 0o111 != 0) != std.mem.eql(u8, entry.mode, "100755"))
            return error.UnsafeSource;
        raw = try allocator.alloc(u8, @intCast(before.size));
        if (try retained.file.readPositionalAll(io, raw, 0) != raw.len)
            return error.SourceChanged;
        try retained.verify(io);
    }
    defer allocator.free(raw);
    const header = try std.fmt.allocPrint(allocator, "blob {d}\x00", .{raw.len});
    defer allocator.free(header);
    if (std.mem.eql(u8, format, "sha1")) {
        var hash = std.crypto.hash.Sha1.init(.{});
        hash.update(header);
        hash.update(raw);
        const oid = std.fmt.bytesToHex(hash.finalResult(), .lower);
        if (!std.mem.eql(u8, &oid, entry.oid))
            return error.SourceChanged;
    } else {
        var hash = Sha256.init(.{});
        hash.update(header);
        hash.update(raw);
        const oid = std.fmt.bytesToHex(hash.finalResult(), .lower);
        if (!std.mem.eql(u8, &oid, entry.oid))
            return error.SourceChanged;
    }
    var digest: [32]u8 = undefined;
    Sha256.hash(raw, &digest, .{});
    return .{ .bytes = raw.len, .sha256 = std.fmt.bytesToHex(digest, .lower), .metadata = physical.metadata(before) };
}

pub fn source(allocator: std.mem.Allocator, io: std.Io, repo: []const u8, git: []const u8) !Source {
    _ = try directoryBefore(io, repo);
    const ignored_before = try ignoredState(allocator, io, repo, git);
    try clean(allocator, io, repo, git);
    const revision = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "HEAD" });
    const tree = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "HEAD^{tree}" });
    const format = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "--show-object-format" });
    if (!std.mem.eql(u8, format, "sha1") and !std.mem.eql(u8, format, "sha256"))
        return error.InvalidGitOutput;
    const listing = try gitOutput(allocator, io, repo, git, &.{ "ls-tree", "-r", "-z", "--full-tree", "HEAD" }, 4 * limits.mib, null);
    defer allocator.free(listing);
    const entries = try trackedMap(allocator, listing, if (std.mem.eql(u8, format, "sha1")) 40 else 64);
    defer allocator.free(entries);
    var dirs: std.StringHashMap(files.Snapshot) = .init(allocator);
    defer dirs.deinit();
    try dirs.put("", try directoryBefore(io, repo));
    for (entries) |entry| {
        var parent = std.fs.path.dirname(entry.path);
        while (parent) |relative| {
            if (dirs.contains(relative)) break;
            const path = try std.fs.path.join(allocator, &.{ repo, relative });
            defer allocator.free(path);
            try dirs.put(relative, try directoryBefore(io, path));
            parent = std.fs.path.dirname(relative);
        }
    }
    const names = try allocator.alloc([]const u8, dirs.count());
    defer allocator.free(names);
    var keys = dirs.keyIterator();
    for (names) |*name| name.* = keys.next().?.*;
    std.mem.sort([]const u8, names, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    var content = Sha256.init(.{});
    content.update("uk.wamr.git-source-content-v1\x00");
    var physical_hash = Sha256.init(.{});
    physical_hash.update("uk.wamr.git-source-physical-v1\x00");
    for (names) |relative| try physical.bind(allocator, &physical_hash, .{ "directory", relative, physical.metadata(dirs.get(relative).?) });
    var bytes: usize = 0;
    for (entries) |entry| {
        const data = try trackedFile(allocator, io, repo, entry, format);
        try limits.addBounded(&bytes, data.bytes, limits.tracked_bytes);
        try physical.bind(allocator, &content, .{ "file", entry.path, entry.mode, entry.oid, data.bytes, data.sha256 });
        try physical.bind(allocator, &physical_hash, .{ "file", entry.path, entry.mode, entry.oid, data.bytes, data.sha256, data.metadata });
    }
    for (names) |relative| {
        const path = if (relative.len == 0) repo else try std.fs.path.join(allocator, &.{ repo, relative });
        defer if (relative.len != 0) allocator.free(path);
        if (!files.sameSnapshot(dirs.get(relative).?, try directoryBefore(io, path)))
            return error.SourceChanged;
    }
    try clean(allocator, io, repo, git);
    const final_revision = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "HEAD" });
    defer allocator.free(final_revision);
    const final_tree = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "HEAD^{tree}" });
    defer allocator.free(final_tree);
    if (!std.mem.eql(u8, revision, final_revision) or !std.mem.eql(u8, tree, final_tree))
        return error.SourceChanged;
    const ignored_after = try ignoredState(allocator, io, repo, git);
    if (!std.meta.eql(ignored_before, ignored_after)) return error.IgnoredChanged;
    return .{
        .revision = revision,
        .tree = tree,
        .custody = .{
            .object_format = format,
            .files = entries.len,
            .directories = dirs.count(),
            .bytes = bytes,
            .content_sha256 = physical.hex(&content),
            .physical_sha256 = physical.hex(&physical_hash),
        },
    };
}

pub fn sealWamr(allocator: std.mem.Allocator, io: std.Io, checkout: []const u8, runtime: []const u8, git: []const u8) !physical.File {
    return sealRevision(allocator, io, checkout, runtime, git, limits.wamr_revision);
}

pub const Fixture = if (@import("builtin").is_test) struct {
    pub fn seal(allocator: std.mem.Allocator, io: std.Io, checkout: []const u8, runtime: []const u8, git: []const u8, revision: []const u8) !physical.File {
        return sealRevision(allocator, io, checkout, runtime, git, revision);
    }
    pub fn sealLimited(allocator: std.mem.Allocator, io: std.Io, checkout: []const u8, runtime: []const u8, git: []const u8, revision: []const u8, maximum: usize) !physical.File {
        return sealRevisionWithLimit(allocator, io, checkout, runtime, git, revision, maximum);
    }
} else struct {};

fn sealRevision(allocator: std.mem.Allocator, io: std.Io, checkout: []const u8, runtime: []const u8, git: []const u8, pinned: []const u8) !physical.File {
    return sealRevisionWithLimit(allocator, io, checkout, runtime, git, pinned, limits.tracked_file);
}

fn sealRevisionWithLimit(allocator: std.mem.Allocator, io: std.Io, checkout: []const u8, runtime: []const u8, git: []const u8, pinned: []const u8, maximum: usize) !physical.File {
    _ = try directoryBefore(io, checkout);
    const head = try gitLine(allocator, io, checkout, git, &.{ "rev-parse", "HEAD" });
    defer allocator.free(head);
    if (!std.mem.eql(u8, head, pinned)) return error.UnpinnedSource;
    const reference = try std.fmt.allocPrint(allocator, "{s}^{{commit}}", .{pinned});
    defer allocator.free(reference);
    const revision = try gitLine(allocator, io, checkout, git, &.{ "rev-parse", "--verify", reference });
    defer allocator.free(revision);
    if (!std.mem.eql(u8, revision, pinned)) return error.UnpinnedSource;
    try clean(allocator, io, checkout, git);
    const custody_path = try std.fs.path.join(allocator, &.{ runtime, "custody" });
    defer allocator.free(custody_path);
    const directory = try files.openDirectory(io, custody_path, .private);
    defer directory.close(io);
    const output = try directory.createFile(io, "wamr-source.tar", .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    const unused = try gitOutput(allocator, io, checkout, git, &.{
        "archive", "--format=tar", pinned,
    }, maximum, output);
    defer allocator.free(unused);
    try output.sync(io);
    const directory_file: std.Io.File = .{ .handle = directory.handle, .flags = .{ .nonblocking = false } };
    try directory_file.sync(io);
    try clean(allocator, io, checkout, git);
    const archive = try std.fs.path.join(allocator, &.{ custody_path, "wamr-source.tar" });
    defer allocator.free(archive);
    const record = try physical.readFile(io, archive, maximum, true);
    if (record.bytes == 0) return error.InvalidArchive;
    return record;
}

pub const TrackedManifest = struct {
    path: []const u8,
    mode: []const u8,
    bytes: usize,
    sha256: [64]u8,
    git_oid: []const u8,
    metadata: [9]i128,
    metadata_sha256: [64]u8,
    content: []u8,

    pub fn deinit(self: TrackedManifest, allocator: std.mem.Allocator) void {
        allocator.free(self.mode);
        allocator.free(self.git_oid);
        allocator.free(self.content);
    }
};

pub fn trackedManifest(
    allocator: std.mem.Allocator,
    io: std.Io,
    repo: []const u8,
    git: []const u8,
    relative: []const u8,
) !TrackedManifest {
    try limits.relative(relative, 1024, 64);
    const format = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "--show-object-format" });
    defer allocator.free(format);
    if (!std.mem.eql(u8, format, "sha1") and !std.mem.eql(u8, format, "sha256"))
        return error.InvalidGitOutput;
    const listing = try gitOutput(allocator, io, repo, git, &.{ "ls-tree", "-z", "HEAD", "--", relative }, 2048, null);
    defer allocator.free(listing);
    const matches = try trackedMap(allocator, listing, if (std.mem.eql(u8, format, "sha1")) 40 else 64);
    defer allocator.free(matches);
    if (matches.len != 1 or !std.mem.eql(u8, matches[0].path, relative) or std.mem.eql(u8, matches[0].mode, "120000"))
        return error.UntrackedManifest;
    const entry = try trackedFile(allocator, io, repo, matches[0], format);
    if (entry.bytes > limits.mib) return error.ManifestTooLarge;
    const path = try std.fs.path.join(allocator, &.{ repo, relative });
    defer allocator.free(path);
    var retained = try files.RetainedFile.open(io, path, .artifact);
    defer retained.close(io);
    if (!std.meta.eql(entry.metadata, physical.metadata(retained.file_snapshot))) return error.SourceChanged;
    const content = try allocator.alloc(u8, entry.bytes);
    errdefer allocator.free(content);
    if (try retained.file.readPositionalAll(io, content, 0) != entry.bytes)
        return error.SourceChanged;
    try retained.verify(io);
    const raw_metadata = try std.json.Stringify.valueAlloc(allocator, entry.metadata, .{});
    defer allocator.free(raw_metadata);
    const metadata_sha256 = try @import("records.zig").identity(allocator, raw_metadata);
    return .{
        .path = relative,
        .mode = try allocator.dupe(u8, matches[0].mode),
        .bytes = entry.bytes,
        .sha256 = entry.sha256,
        .git_oid = try allocator.dupe(u8, matches[0].oid),
        .metadata = entry.metadata,
        .metadata_sha256 = std.fmt.bytesToHex(metadata_sha256, .lower),
        .content = content,
    };
}

pub const MetadataEntry = struct {
    kind: []const u8,
    path: []const u8,
    metadata: [9]i128,
};
pub const MetadataBaseline = struct {
    schema: []const u8 = "uk.wamr.git-physical-source-baseline",
    version: u8 = 1,
    records: []MetadataEntry,

    pub fn deinit(self: *MetadataBaseline, allocator: std.mem.Allocator) void {
        for (self.records) |record| allocator.free(record.path);
        allocator.free(self.records);
    }
};
pub const MetadataChange = struct {
    kind: []const u8,
    path: []const u8,
    before: ?[9]i128,
    after: ?[9]i128,
};
pub const MetadataDiagnostic = struct {
    schema: []const u8 = "uk.wamr.git-physical-source-diagnostic",
    version: u8 = 1,
    changed: []MetadataChange,
    changed_records: usize,
    truncated: bool,

    pub fn deinit(self: *MetadataDiagnostic, allocator: std.mem.Allocator) void {
        allocator.free(self.changed);
    }
};

pub fn sourceMetadata(allocator: std.mem.Allocator, io: std.Io, repo: []const u8, git: []const u8) !MetadataBaseline {
    const head = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "HEAD" });
    defer allocator.free(head);
    const listing = try gitOutput(allocator, io, repo, git, &.{ "ls-tree", "-r", "-z", "--full-tree", head }, 4 * limits.mib, null);
    defer allocator.free(listing);
    const format = try gitLine(allocator, io, repo, git, &.{ "rev-parse", "--show-object-format" });
    defer allocator.free(format);
    if (!std.mem.eql(u8, format, "sha1") and !std.mem.eql(u8, format, "sha256"))
        return error.InvalidGitOutput;
    const tracked = try trackedMap(allocator, listing, if (std.mem.eql(u8, format, "sha1")) 40 else 64);
    defer allocator.free(tracked);
    var directories = std.StringHashMap(void).init(allocator);
    defer directories.deinit();
    try directories.put("", {});
    for (tracked) |entry| {
        var parent = std.fs.path.dirname(entry.path);
        while (parent) |relative| {
            if (directories.contains(relative)) break;
            try directories.put(relative, {});
            parent = std.fs.path.dirname(relative);
        }
    }
    const names = try allocator.alloc([]const u8, directories.count());
    defer allocator.free(names);
    var it = directories.keyIterator();
    for (names) |*name| name.* = it.next().?.*;
    std.mem.sort([]const u8, names, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    const recorded = try allocator.alloc(MetadataEntry, names.len + tracked.len);
    var complete: usize = 0;
    errdefer {
        for (recorded[0..complete]) |entry| allocator.free(entry.path);
        allocator.free(recorded);
    }
    for (names, 0..) |relative, index| {
        const path = if (relative.len == 0) repo else try std.fs.path.join(allocator, &.{ repo, relative });
        defer if (relative.len != 0) allocator.free(path);
        recorded[index] = .{ .kind = "directory", .path = try allocator.dupe(u8, relative), .metadata = physical.metadata(try directoryBefore(io, path)) };
        complete += 1;
    }
    for (tracked, 0..) |entry, index| {
        const path = try std.fs.path.join(allocator, &.{ repo, entry.path });
        defer allocator.free(path);
        const parent = try files.openDirectory(io, std.fs.path.dirname(path).?, .artifact);
        defer parent.close(io);
        const member = try parent.openFile(io, std.fs.path.basename(path), .{ .path_only = true, .follow_symlinks = false });
        defer member.close(io);
        recorded[names.len + index] = .{ .kind = "file", .path = try allocator.dupe(u8, entry.path), .metadata = physical.metadata(try files.snapshot(member)) };
        complete += 1;
    }
    return .{ .records = recorded };
}

pub fn metadataChanges(allocator: std.mem.Allocator, before: []const MetadataEntry, after: []const MetadataEntry) !MetadataDiagnostic {
    if (before.len > 2 * limits.tracked_entries or after.len > 2 * limits.tracked_entries)
        return error.LimitExceeded;
    var originals = std.StringHashMap([9]i128).init(allocator);
    defer {
        var keys = originals.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        originals.deinit();
    }
    var current = std.StringHashMap([9]i128).init(allocator);
    defer {
        var keys = current.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        current.deinit();
    }
    for (before) |item| {
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ item.kind, item.path });
        errdefer allocator.free(key);
        if (originals.contains(key)) return error.InvalidMetadataBaseline;
        try originals.put(key, item.metadata);
    }
    for (after) |item| {
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ item.kind, item.path });
        errdefer allocator.free(key);
        if (current.contains(key)) return error.InvalidMetadataBaseline;
        try current.put(key, item.metadata);
    }
    var changes: std.ArrayList(MetadataChange) = .empty;
    defer changes.deinit(allocator);
    for (before) |original| {
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ original.kind, original.path });
        defer allocator.free(key);
        const replacement = current.get(key);
        if (replacement) |snapshot| if (std.meta.eql(original.metadata, snapshot)) continue;
        try changes.append(allocator, .{
            .kind = original.kind,
            .path = original.path,
            .before = original.metadata,
            .after = replacement,
        });
    }
    for (after) |item| {
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ item.kind, item.path });
        defer allocator.free(key);
        if (!originals.contains(key)) {
            try changes.append(allocator, .{
                .kind = item.kind,
                .path = item.path,
                .before = null,
                .after = item.metadata,
            });
        }
    }
    std.mem.sort(MetadataChange, changes.items, {}, struct {
        fn less(_: void, a: MetadataChange, b: MetadataChange) bool {
            if (!std.mem.eql(u8, a.kind, b.kind)) return std.mem.lessThan(u8, a.kind, b.kind);
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.less);
    const total = changes.items.len;
    const bounded = try allocator.dupe(MetadataChange, changes.items[0..@min(total, limits.diagnostic_changes)]);
    return .{ .changed = bounded, .changed_records = total, .truncated = total > bounded.len };
}

pub const IgnoredDiagnostic = struct {
    paths: [][]const u8,
    truncated: bool,

    pub fn deinit(self: *IgnoredDiagnostic, allocator: std.mem.Allocator) void {
        for (self.paths) |path| allocator.free(path);
        allocator.free(self.paths);
    }
};

pub fn ignoredDiagnostic(allocator: std.mem.Allocator, io: std.Io, repo: []const u8, git: []const u8) !IgnoredDiagnostic {
    const listing = try gitOutput(allocator, io, repo, git, &.{
        "status", "--short", "--ignored", "--untracked-files=all", "-z",
    }, limits.mib, null);
    defer allocator.free(listing);
    if (listing.len != 0 and listing[listing.len - 1] != 0) return error.InvalidGitOutput;
    var result: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }
    var total: usize = 0;
    if (listing.len > 0) {
        var items = std.mem.splitScalar(u8, listing[0 .. listing.len - 1], 0);
        while (items.next()) |entry| {
            if (!std.mem.startsWith(u8, entry, "!! ")) continue;
            try limits.relative(entry[3..], limits.ignored_path, limits.ignored_depth);
            total += 1;
            if (result.items.len < limits.diagnostic_ignored)
                try result.append(allocator, try allocator.dupe(u8, entry));
        }
    }
    return .{ .paths = try result.toOwnedSlice(allocator), .truncated = total > limits.diagnostic_ignored };
}

pub const RootEntry = struct { name: []const u8, kind: []const u8 };
pub fn rootInventory(allocator: std.mem.Allocator, io: std.Io, repo: []const u8) ![]RootEntry {
    const before = try directoryBefore(io, repo);
    const dir = try files.openDirectory(io, repo, .artifact);
    defer dir.close(io);
    var result: std.ArrayList(RootEntry) = .empty;
    errdefer {
        for (result.items) |entry| allocator.free(entry.name);
        result.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (result.items.len >= limits.diagnostic_root) return error.LimitExceeded;
        try files.basename(entry.name);
        const named = try dir.openFile(io, entry.name, .{ .path_only = true, .follow_symlinks = false });
        defer named.close(io);
        const info = try files.snapshot(named);
        const kind: []const u8 = if (info.mode & std.os.linux.S.IFMT == std.os.linux.S.IFDIR)
            "directory"
        else if (info.mode & std.os.linux.S.IFMT == std.os.linux.S.IFLNK)
            "symlink"
        else
            "file";
        try result.append(allocator, .{ .name = try allocator.dupe(u8, entry.name), .kind = kind });
    }
    std.mem.sort(RootEntry, result.items, {}, struct {
        fn less(_: void, a: RootEntry, b: RootEntry) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    if (!files.sameSnapshot(before, try directoryBefore(io, repo))) return error.SourceChanged;
    return result.toOwnedSlice(allocator);
}
