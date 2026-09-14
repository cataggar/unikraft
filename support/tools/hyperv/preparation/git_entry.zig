// SPDX-License-Identifier: BSD-3-Clause
//! The namespace helper's /bin/git personality. No inherited policy, command
//! proxy, subprocess supervisor, or independently installed executable.
const std = @import("std");
const linux = std.os.linux;
const c = @import("contracts.zig");
const fs = @import("files.zig");
const runtime = @import("runtime.zig");
const environment = @import("environment.zig");

pub const policy_path = "/etc/unikraft-preparation-git.json";
pub const maximum_bytes = 256 * 1024;

pub const Record = struct {
    schema: enum { hyperv_native_git_entry_v1 },
    repository: []const u8,
    runtime_directory: []const u8,
    runtime: runtime.Tool,
    environment: environment.Record,
    account: environment.Account,

    pub fn validate(self: Record) !void {
        try environment.absolute(self.repository);
        try environment.absolute(self.runtime_directory);
        try environment.absolute(self.account.home);
        try self.environment.validate();
        try c.core.private_files.basename(self.account.name);
        for (self.account.name) |ch|
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return error.InvalidAccount;
        if (self.runtime.role != .git or self.runtime.executable == null or
            self.runtime.loader == null or self.runtime.libraries.len == 0 or
            self.runtime.libraries.len > 256) return error.InvalidRuntime;
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Record) {
    if (bytes.len > maximum_bytes) return error.FileTooLarge;
    const result = try c.parse(Record, allocator, bytes);
    errdefer result.deinit();
    try result.value.validate();
    return result;
}

pub fn load(allocator: std.mem.Allocator, io: std.Io) !std.json.Parsed(Record) {
    const directory = try fs.Directory.open(allocator, io, "/etc");
    defer directory.close(allocator, io);
    const bytes = try directory.read(allocator, io, std.fs.path.basename(policy_path), maximum_bytes, .private);
    defer allocator.free(bytes);
    return parse(allocator, bytes);
}

const Operation = enum {
    head,
    modified,

    fn arguments(self: Operation) []const []const u8 {
        return switch (self) {
            .head => &.{ "rev-parse", "--short", "HEAD" },
            .modified => &.{ "ls-files", "-m" },
        };
    }
};

fn operation(args: []const []const u8) !Operation {
    inline for (std.meta.tags(Operation)) |candidate| {
        const expected = candidate.arguments();
        if (args.len == expected.len) {
            var equal = true;
            for (args, expected) |actual, fixed| equal = equal and std.mem.eql(u8, actual, fixed);
            if (equal) return candidate;
        }
    }
    return error.InvalidGitOperation;
}

fn requireDroppedPrivileges() !void {
    if (linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 1)
        return error.PrivilegeDropUnavailable;
    const header: extern struct { version: u32, pid: i32 } = .{ .version = 0x20080522, .pid = 0 };
    var data = [_]linux.cap_user_data_t{std.mem.zeroes(linux.cap_user_data_t)} ** 2;
    if (linux.errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&data))) != .SUCCESS or
        !std.mem.allEqual(u8, std.mem.asBytes(&data), 0)) return error.PrivilegeDropUnavailable;
    for (0..64) |cap| {
        const bounding = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(bounding) == .INVAL) break;
        if (bounding != 0 or linux.prctl(47, 1, cap, 0, 0) != 0) return error.PrivilegeDropUnavailable;
    }
}

fn closeDescriptors() !void {
    if (linux.errno(linux.close_range(3, std.math.maxInt(linux.fd_t), @bitCast(@as(u32, 0)))) != .SUCCESS)
        return error.DescriptorIsolationUnavailable;
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !noreturn {
    try closeDescriptors();
    const selected = try operation(args);
    try requireDroppedPrivileges();
    const parsed = try load(allocator, io);
    const record = parsed.value;
    const account = try environment.Account.current(allocator, io);
    if (account.uid != record.account.uid or account.gid != record.account.gid or
        !std.mem.eql(u8, account.name, record.account.name) or
        !std.mem.eql(u8, account.home, record.account.home)) return error.InvalidAccount;
    const repository = try fs.Directory.open(allocator, io, record.repository);
    // Do not let Git discover an unrelated ancestor when the bound repository
    // loses its own metadata. Both ordinary and linked worktrees are supported.
    const dotgit = try repository.dir.openFile(io, ".git", .{ .path_only = true, .follow_symlinks = false });
    const kind = (try fs.metadata(dotgit)).mode & linux.S.IFMT;
    if (kind != linux.S.IFDIR and kind != linux.S.IFREG) return error.UnsafeFile;
    const bound: runtime.Bound = .{
        .directory = try fs.Directory.open(allocator, io, record.runtime_directory),
        .contract = record.runtime,
    };
    try bound.validate(allocator, io);
    var argv = try bound.prefix(allocator);
    try argv.appendSlice(allocator, &.{
        "--no-replace-objects", "--no-pager",                    "-c", "core.fsmonitor=false",      "-c", "core.hooksPath=/dev/null",
        "-c",                   "core.attributesFile=/dev/null", "-c", "core.untrackedCache=false", "-c", "core.sparseCheckout=false",
        "-c",                   "core.useReplaceRefs=false",     "-c", "maintenance.auto=false",    "-c", "protocol.allow=never",
        "-c",                   "fetch.writeCommitGraph=false",
    });
    try argv.appendSlice(allocator, selected.arguments());
    var map = try record.environment.create(allocator, account.home);
    const block = try map.createPosixBlock(allocator, .{ .zig_progress_fd = -1 });
    const pointers = try allocator.allocSentinel(?[*:0]const u8, argv.items.len, null);
    for (argv.items, 0..) |arg, i| pointers[i] = (try allocator.dupeZ(u8, arg)).ptr;
    if (linux.errno(linux.fchdir(repository.dir.handle)) != .SUCCESS) return error.UnsafePath;
    try closeDescriptors();
    // Keep only a CLOEXEC copy for a bounded wrapper diagnostic if exec fails.
    // Native Git (and its loader) never receive the raw stderr descriptor.
    const saved = linux.fcntl(2, linux.F.DUPFD_CLOEXEC, 3);
    if (linux.errno(saved) != .SUCCESS) return error.DescriptorIsolationUnavailable;
    const diagnostic_fd: linux.fd_t = @intCast(saved);
    defer _ = linux.close(diagnostic_fd);
    const opened = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.DescriptorIsolationUnavailable;
    const null_fd: linux.fd_t = @intCast(opened);
    var metadata: linux.Statx = undefined;
    if (linux.errno(linux.statx(null_fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &metadata)) != .SUCCESS or
        metadata.mode & linux.S.IFMT != linux.S.IFCHR or metadata.rdev_major != 1 or metadata.rdev_minor != 3)
        return error.UnsafeFile;
    if (linux.errno(linux.dup3(null_fd, 2, 0)) != .SUCCESS) return error.DescriptorIsolationUnavailable;
    _ = linux.close(null_fd);
    _ = linux.execve(pointers[0].?, pointers.ptr, block.slice.ptr);
    _ = linux.dup3(diagnostic_fd, 2, 0);
    return error.GitExecUnavailable;
}

pub fn fail(err: anyerror) noreturn {
    var failures = c.failure(err);
    if (err == error.GitExecUnavailable)
        failures.primary = .{ .stage = .process_spawn, .category = .spawn_failed };
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    failures.write(&writer) catch linux.exit_group(125);
    const bytes = writer.buffered();
    _ = linux.write(2, bytes.ptr, bytes.len);
    linux.exit_group(125);
}
