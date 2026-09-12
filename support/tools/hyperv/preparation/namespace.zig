// SPDX-License-Identifier: BSD-3-Clause
//! Linux namespace mechanism. The only production entry consumes a producer
//! binding and constructs producer.plan; no command/argv passthrough exists.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const c = @import("contracts.zig");
const fs = @import("files.zig");
const rt = @import("runtime.zig");
const env = @import("environment.zig");
const git_entry = @import("git_entry.zig");
const paths = @import("facade_paths");
const elf = @import("producer_elf");
const producer = @import("producer.zig");

pub const Identity = struct {
    path: []const u8,
    device: u64,
    inode: u64,
    mode: u16,
    uid: u32,

    pub fn of(path: []const u8, file: std.Io.File) !Identity {
        try env.absolute(path);
        const m = try fs.metadata(file);
        return .{ .path = path, .device = m.device, .inode = m.inode, .mode = m.mode, .uid = m.uid };
    }
    pub fn directory(value: fs.Directory) !Identity {
        return of(value.path, .{ .handle = value.dir.handle, .flags = .{ .nonblocking = false } });
    }
    pub fn require(self: Identity, other: Identity) !void {
        if (!std.mem.eql(u8, self.path, other.path) or self.device != other.device or
            self.inode != other.inode or self.mode != other.mode or self.uid != other.uid)
            return error.SourceChanged;
    }
};

pub const GitTree = struct { directory: fs.Directory, tree: c.Tree };
pub const Inputs = struct {
    /// A separately reviewed static native namespace helper, run by core.process.
    helper: rt.Bound,
    git_metadata: []const GitTree,
    account: env.Account,
    facade_runtime: fs.Directory,
    facade_lock: Identity,
    /// Relative to producer workspace; immutable for all three actions.
    environment: c.File,
    make_environment: ?c.File = null,
    git_policy: ?c.File = null,
};
pub const Tool = struct { path: []const u8, contract: rt.Tool };
pub const GitBinding = struct { directory: Identity, tree: c.Tree };
pub const Binding = struct {
    helper: Tool,
    git_metadata: []const GitBinding,
    account: env.Account,
    facade_runtime: Identity,
    facade_lock: Identity,
    environment: c.File,
    make_environment: ?c.File = null,
    git_policy: ?c.File = null,
};

pub fn describe(allocator: std.mem.Allocator, input: Inputs) !Binding {
    const git = try allocator.alloc(GitBinding, input.git_metadata.len);
    for (input.git_metadata, git) |item, *bound|
        bound.* = .{ .directory = try Identity.directory(item.directory), .tree = item.tree };
    return .{
        .helper = .{ .path = input.helper.directory.path, .contract = input.helper.contract },
        .git_metadata = git,
        .account = input.account,
        .facade_runtime = try Identity.directory(input.facade_runtime),
        .facade_lock = input.facade_lock,
        .environment = input.environment,
        .make_environment = input.make_environment,
        .git_policy = input.git_policy,
    };
}

pub fn reopen(allocator: std.mem.Allocator, io: std.Io, value: Binding) !Inputs {
    const git = try allocator.alloc(GitTree, value.git_metadata.len);
    for (value.git_metadata, git) |item, *bound| {
        const directory = try fs.Directory.open(allocator, io, item.directory.path);
        try item.directory.require(try Identity.directory(directory));
        bound.* = .{ .directory = directory, .tree = item.tree };
    }
    const facade = try fs.Directory.open(allocator, io, value.facade_runtime.path);
    try value.facade_runtime.require(try Identity.directory(facade));
    return .{
        .helper = .{ .directory = try fs.Directory.open(allocator, io, value.helper.path), .contract = value.helper.contract },
        .git_metadata = git,
        .account = value.account,
        .facade_runtime = facade,
        .facade_lock = value.facade_lock,
        .environment = value.environment,
        .make_environment = value.make_environment,
        .git_policy = value.git_policy,
    };
}

/// Does not acquire or create a lock. The root facade alone acquires build.lock.
pub fn validate(allocator: std.mem.Allocator, io: std.Io, input: Inputs, repository: fs.Directory, workspace: fs.Directory) !void {
    const account = try env.Account.current(allocator, io);
    if (account.uid != input.account.uid or account.gid != input.account.gid or
        !std.mem.eql(u8, account.home, input.account.home) or !std.mem.eql(u8, account.name, input.account.name))
        return error.InvalidAccount;
    const selected = try std.fs.path.join(allocator, &.{ repository.path, ".d/zig-migration-preparation" });
    if (!paths.isDescendant(selected, workspace.path)) return error.UnsafePath;
    const run_user = try std.fmt.allocPrint(allocator, "/run/user/{d}", .{account.uid});
    // Match the facade: a missing final /run/user/UID selects passwd HOME.
    // If it exists, validate the entire chain rather than trusting this probe.
    const probe = std.Io.Dir.openDirAbsolute(io, run_user, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (probe) |directory| directory.close(io);
    const runtime_root = if (probe != null) try fs.Directory.open(allocator, io, run_user) else null;
    defer if (runtime_root) |directory| directory.close(allocator, io);
    const expected_runtime = try std.fmt.allocPrint(allocator, "{s}/unikraft-zig-facade-{d}", .{
        if (runtime_root != null) run_user else account.home, account.uid,
    });
    if (!std.mem.eql(u8, expected_runtime, input.facade_runtime.path)) return error.AlternateFacadeLock;
    const identity = try Identity.directory(input.facade_runtime);
    if (identity.mode & 0o7777 != 0o700 or identity.uid != account.uid) return error.UnsafeFile;
    const named = try fs.Directory.open(allocator, io, expected_runtime);
    defer named.close(allocator, io);
    try identity.require(try Identity.directory(named));
    const lock = try input.facade_runtime.openFile(io, "build.lock", .private);
    defer lock.close(io);
    try input.facade_lock.require(try Identity.of(try std.fs.path.join(allocator, &.{ expected_runtime, "build.lock" }), lock));
    if (input.helper.contract.role != .preparation or input.helper.contract.executable == null or
        input.helper.contract.loader != null or input.helper.contract.libraries.len != 0) return error.InvalidRuntime;
    try input.helper.validate(allocator, io);
    if (input.git_metadata.len == 0 or input.git_metadata.len > 2) return error.IncompleteGitMounts;
    for (input.git_metadata, 0..) |git, i| {
        if (!std.mem.endsWith(u8, git.directory.path, "/.git") and
            std.mem.indexOf(u8, git.directory.path, "/.git/worktrees/") == null) return error.IncompleteGitMounts;
        if (paths.isSameOrAncestor(git.directory.path, repository.path) or
            paths.isSameOrAncestor(git.directory.path, workspace.path)) return error.UnsafePath;
        for (input.git_metadata[0..i]) |previous|
            if (std.mem.eql(u8, git.directory.path, previous.directory.path)) return error.UnsafePath;
        try fs.requireTree((try fs.inventory(allocator, io, git.directory, 100000, 4 * 1024 * 1024 * 1024)).tree, git.tree);
    }
    try fs.requireFile(try workspace.record(allocator, io, input.environment.path, 16 * 1024, .private), input.environment);
    if (input.make_environment) |file|
        try fs.requireFile(try workspace.record(allocator, io, file.path, 64 * 1024, .private), file);
    if (input.git_policy) |file| {
        try fs.requireFile(try workspace.record(allocator, io, file.path, git_entry.maximum_bytes, .private), file);
        const policy = try readGitPolicy(allocator, io, workspace, file);
        defer policy.deinit();
        if (!std.mem.eql(u8, policy.value.repository, repository.path) or
            !try sameRecord(allocator, policy.value.account, input.account)) return error.InvalidGitPolicy;
        const original = try env.load(allocator, io, try std.fs.path.join(allocator, &.{ workspace.path, input.environment.path }), input.environment.sha256);
        defer original.deinit();
        if (!try sameRecord(allocator, policy.value.environment, original.value)) return error.InvalidGitPolicy;
    }
}

fn readGitPolicy(allocator: std.mem.Allocator, io: std.Io, workspace: fs.Directory, file: c.File) !std.json.Parsed(git_entry.Record) {
    const bytes = try workspace.read(allocator, io, file.path, git_entry.maximum_bytes, .private);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), file.sha256) or bytes.len != file.size) return error.HashMismatch;
    return git_entry.parse(allocator, bytes);
}

fn sameRecord(allocator: std.mem.Allocator, a: anytype, b: @TypeOf(a)) !bool {
    const left = try c.canonical(allocator, a);
    defer allocator.free(left);
    const right = try c.canonical(allocator, b);
    defer allocator.free(right);
    return std.mem.eql(u8, left, right);
}

pub const Request = struct {
    schema: enum { @"uk.native-preparation-namespace.v2" } = .@"uk.native-preparation-namespace.v2",
    step: producer.Step,
    binding: producer.Binding,
    root: Identity,
};

/// Eight bytes, no strings or externally supplied diagnostics. Only the outer
/// helper holds the supervisor's descriptor; PID 1 uses a separate private pipe.
pub const Status = struct {
    primary: enum(u8) { unknown, exited, signaled, spawn_failed, setup_failed } = .unknown,
    code: u8 = 0,
    cleanup: enum(u8) { complete = 1, failed } = .complete,
    recording: enum(u8) { complete = 1, missing, malformed } = .complete,

    pub fn encode(self: Status) [8]u8 {
        return .{ 0x4e, 1, @intFromEnum(self.primary), self.code, @intFromEnum(self.cleanup), @intFromEnum(self.recording), 0x53, 0xff };
    }

    pub fn decode(bytes: []const u8) !Status {
        if (bytes.len == 0 or std.mem.allEqual(u8, bytes, 0)) return error.MissingNamespaceStatus;
        if (bytes.len != 8 or bytes[0] != 0x4e or bytes[1] != 1 or bytes[6] != 0x53 or bytes[7] != 0xff)
            return error.InvalidNamespaceStatus;
        const result: Status = .{
            .primary = std.enums.fromInt(@FieldType(Status, "primary"), bytes[2]) orelse return error.InvalidNamespaceStatus,
            .code = bytes[3],
            .cleanup = std.enums.fromInt(@FieldType(Status, "cleanup"), bytes[4]) orelse return error.InvalidNamespaceStatus,
            .recording = std.enums.fromInt(@FieldType(Status, "recording"), bytes[5]) orelse return error.InvalidNamespaceStatus,
        };
        switch (result.primary) {
            .unknown => if (result.recording == .complete or result.code != 0) return error.InvalidNamespaceStatus,
            .exited => {},
            .signaled => if (result.code == 0 or result.code > 64) return error.InvalidNamespaceStatus,
            .spawn_failed, .setup_failed => if (result.code != 0) return error.InvalidNamespaceStatus,
        }
        return result;
    }

    pub fn termination(self: Status) ?std.process.Child.Term {
        return switch (self.primary) {
            .exited => .{ .exited = self.code },
            .signaled => .{ .signal = @enumFromInt(self.code) },
            else => null,
        };
    }
};

pub const StatusFile = struct {
    fd: linux.fd_t,

    pub fn create() !StatusFile {
        const opened = linux.syscall2(.memfd_create, @intFromPtr("namespace-status"), 3); // CLOEXEC | ALLOW_SEALING
        if (linux.errno(opened) != .SUCCESS) return error.StatusUnavailable;
        const fd: linux.fd_t = @intCast(opened);
        errdefer _ = linux.close(fd);
        if (linux.errno(linux.ftruncate(fd, 8)) != .SUCCESS or
            linux.errno(linux.fchmod(fd, 0o600)) != .SUCCESS or
            linux.errno(linux.fcntl(fd, linux.F.ADD_SEALS, 2 | 4)) != .SUCCESS)
            return error.StatusUnavailable;
        return .{ .fd = fd };
    }

    pub fn close(self: StatusFile) void {
        _ = linux.close(self.fd);
    }

    pub fn openParent(allocator: std.mem.Allocator, descriptor: []const u8) !StatusFile {
        const fd = try std.fmt.parseInt(u31, descriptor, 10);
        if (fd < 3) return error.InvalidNamespaceStatus;
        const path = try std.fmt.allocPrintSentinel(allocator, "/proc/{d}/fd/{d}", .{ linux.getppid(), fd }, 0);
        const opened = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) return error.StatusUnavailable;
        const result: StatusFile = .{ .fd = @intCast(opened) };
        errdefer result.close();
        const metadata = try fs.metadata(.{ .handle = result.fd, .flags = .{ .nonblocking = false } });
        if (metadata.mode != linux.S.IFREG | 0o600 or metadata.uid != linux.geteuid() or metadata.links != 0 or metadata.size != 8 or
            linux.fcntl(result.fd, linux.F.GET_SEALS, 0) != 6) return error.InvalidNamespaceStatus;
        var bytes: [8]u8 = undefined;
        if (linux.pread(result.fd, &bytes, bytes.len, 0) != bytes.len or !std.mem.allEqual(u8, &bytes, 0))
            return error.InvalidNamespaceStatus;
        return result;
    }

    pub fn write(self: StatusFile, status: Status) !void {
        const bytes = status.encode();
        if (linux.pwrite(self.fd, &bytes, bytes.len, 0) != bytes.len) return error.StatusUnavailable;
    }

    pub fn read(self: StatusFile) !Status {
        // Called only after process cleanup. Prevent later descriptor holders
        // from changing an observation after it has been validated.
        if (linux.errno(linux.fcntl(self.fd, linux.F.ADD_SEALS, 1 | 8)) != .SUCCESS) return error.InvalidNamespaceStatus;
        var bytes: [8]u8 = undefined;
        if (linux.pread(self.fd, &bytes, bytes.len, 0) != bytes.len) return error.InvalidNamespaceStatus;
        return Status.decode(&bytes);
    }
};

pub const ParentGuard = struct {
    fd: linux.fd_t,

    pub fn acquire() !ParentGuard {
        const opened = linux.syscall2(.pidfd_open, @intCast(linux.getpid()), 0);
        if (linux.errno(opened) != .SUCCESS) return error.ParentDeathUnavailable;
        return .{ .fd = @intCast(opened) };
    }

    pub fn close(self: ParentGuard) void {
        _ = linux.close(self.fd);
    }

    pub fn arm(self: ParentGuard) !void {
        if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS)
            return error.ParentDeathUnavailable;
        var poll = [_]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
        var zero: linux.timespec = .{ .sec = 0, .nsec = 0 };
        while (true) {
            const result = linux.ppoll(&poll, poll.len, &zero, null);
            switch (linux.errno(result)) {
                .INTR => continue,
                .SUCCESS => if (result == 0) return else return error.ParentDied,
                else => return error.ParentDeathUnavailable,
            }
        }
    }
};

pub fn runRequest(allocator: std.mem.Allocator, io: std.Io, path: []const u8, digest: c.Sha, status_file: StatusFile) !Status {
    try env.absolute(path);
    const directory = try fs.Directory.open(allocator, io, std.fs.path.dirname(path).?);
    const bytes = try directory.read(allocator, io, std.fs.path.basename(path), 4 * 1024 * 1024, .private);
    if (!std.crypto.timing_safe.eql(c.Sha, c.digest(bytes), digest)) return error.HashMismatch;
    const parsed = try c.parse(Request, allocator, bytes);
    const request = parsed.value;
    const input = try producer.reopenBinding(allocator, io, request.binding);
    try producer.preflight(allocator, io, request.step, input, .{
        .source = request.binding.source,
        .binding_sha256 = try producer.bindingDigest(allocator, request.binding),
    });
    const record = try producer.environmentRecord(allocator, io, input);
    var environment = try record.create(allocator, input.isolation.?.account.home);
    const command = try producer.plan(allocator, request.step, try producer.commandPaths(allocator, input));
    var runtimes: std.ArrayList(rt.Bound) = .empty;
    for (input.tools.native) |native| try runtimes.append(allocator, native.bound);
    try runtimes.appendSlice(allocator, &.{ input.tools.git, input.tools.packages, input.tools.bison_data, input.tools.trust, input.isolation.?.helper });
    var aliases: std.ArrayList(Alias) = .empty;
    for (input.tools.native) |native| {
        if (std.mem.eql(u8, @tagName(native.name), "git")) continue;
        try aliases.append(allocator, .{ .name = @tagName(native.name), .bound = native.bound });
    }
    try aliases.append(allocator, .{ .name = "git", .bound = input.isolation.?.helper });
    return enter(allocator, io, .{
        .repository = input.repository,
        .workspace = input.workspace.directory,
        .scratch = input.workspace.scratch,
        .runtimes = runtimes.items,
        .aliases = aliases.items,
        .isolation = input.isolation.?,
        .root = request.root,
        .status_file = status_file,
    }, command.argv, &environment);
}

pub const Alias = struct { name: []const u8, bound: rt.Bound };
pub const Sandbox = struct {
    repository: fs.Directory,
    workspace: fs.Directory,
    scratch: fs.Directory,
    runtimes: []const rt.Bound,
    aliases: []const Alias,
    isolation: Inputs,
    root: Identity,
    /// Closed in PID 1 before any namespace setup or payload.
    status_file: ?StatusFile = null,
};
fn hasAlias(aliases: []const Alias, name: []const u8) bool {
    for (aliases) |alias| if (std.mem.eql(u8, alias.name, name)) return true;
    return false;
}

const Mount = struct {
    file: std.Io.File,
    target: []const u8,
    directory: bool,
    readonly: bool = true,
    device: bool = false,
    record: ?c.File = null,
};

/// Mechanism shared with the small synthetic fixture, not an executable API.
/// Invoke only in the dedicated single-threaded helper; never fork a live
/// threaded producer. The production caller above supplies only typed plans.
pub fn enter(allocator: std.mem.Allocator, io: std.Io, sandbox: Sandbox, argv: []const []const u8, environment: *const std.process.Environ.Map) !Status {
    return enterWithCleanupFault(allocator, io, sandbox, argv, environment, false);
}

/// Only the native fixture calls this fault-injection mechanism. Request has no
/// corresponding field, and the production entry always supplies false.
pub fn enterWithCleanupFault(allocator: std.mem.Allocator, io: std.Io, sandbox: Sandbox, argv: []const []const u8, environment: *const std.process.Environ.Map, cleanup_fault: bool) !Status {
    if (!builtin.single_threaded) @compileError("namespace helper must be built single_threaded");
    try validate(allocator, io, sandbox.isolation, sandbox.repository, sandbox.workspace);
    if (hasAlias(sandbox.aliases, "git")) {
        const file = sandbox.isolation.git_policy orelse return error.MissingGitPolicy;
        const policy = try readGitPolicy(allocator, io, sandbox.workspace, file);
        defer policy.deinit();
        var helper_mounted = false;
        var git_mounted = false;
        for (sandbox.runtimes) |bound| {
            if (std.mem.eql(u8, bound.directory.path, sandbox.isolation.helper.directory.path) and
                try sameRecord(allocator, bound.contract, sandbox.isolation.helper.contract)) helper_mounted = true;
            if (std.mem.eql(u8, bound.directory.path, policy.value.runtime_directory) and
                try sameRecord(allocator, bound.contract, policy.value.runtime)) git_mounted = true;
        }
        if (!helper_mounted or !git_mounted) return error.IncompleteRuntime;
        for (sandbox.aliases) |alias| {
            if (!std.mem.eql(u8, alias.name, "git")) continue;
            if (!std.mem.eql(u8, alias.bound.directory.path, sandbox.isolation.helper.directory.path) or
                !try sameRecord(allocator, alias.bound.contract, sandbox.isolation.helper.contract)) return error.InvalidGitAlias;
            try (try Identity.directory(sandbox.isolation.helper.directory)).require(try Identity.directory(alias.bound.directory));
        }
    }
    if (!paths.isDescendant(sandbox.workspace.path, sandbox.scratch.path)) return error.UnsafePath;
    var mounts: std.ArrayList(Mount) = .empty;
    var evidence_directories: std.ArrayList(fs.Directory) = .empty;
    defer {
        for (evidence_directories.items) |directory| directory.close(allocator, io);
        evidence_directories.deinit(allocator);
    }
    const facade = sandbox.isolation.facade_runtime;
    try addDirectory(allocator, &mounts, sandbox.workspace, false);
    try addDirectory(allocator, &mounts, facade, false);
    const lock = try facade.openFile(io, "build.lock", .private);
    try mounts.append(allocator, .{ .file = lock, .target = sandbox.isolation.facade_lock.path, .directory = false, .readonly = false });
    for (sandbox.isolation.git_metadata) |git| try addDirectory(allocator, &mounts, git.directory, true);
    for (sandbox.runtimes) |bound| {
        try bound.validate(allocator, io);
        for ([_][]const u8{ "/bin", "/lib", "/lib64", "/usr", "/etc", "/dev", "/proc", sandbox.repository.path, sandbox.workspace.path, facade.path, sandbox.isolation.account.home }) |reserved|
            if (paths.isSameOrAncestor(bound.directory.path, reserved)) return error.UnsafePath;
        if (paths.isSameOrAncestor(sandbox.scratch.path, bound.directory.path)) return error.UnsafePath;
        try addDirectory(allocator, &mounts, bound.directory, true);
        for (bound.contract.evidence) |evidence| {
            for ([_][]const u8{ "/bin", "/lib", "/lib64", "/usr", "/etc", "/dev", "/proc", sandbox.repository.path, sandbox.workspace.path, facade.path, sandbox.isolation.account.home }) |reserved|
                if (paths.isSameOrAncestor(evidence.directory.path, reserved)) return error.UnsafePath;
            if (paths.isSameOrAncestor(sandbox.scratch.path, evidence.directory.path)) return error.UnsafePath;
            const directory = try fs.Directory.open(allocator, io, evidence.directory.path);
            try evidence_directories.append(allocator, directory);
            try evidence.directory.require(try rt.origin.Identity.directory(directory));
            try addDirectory(allocator, &mounts, directory, true);
        }
        if (bound.contract.executable) |executable| {
            try interpreterMount(allocator, io, &mounts, bound, executable);
            if (bound.contract.loader) |loader| {
                for (bound.contract.libraries) |library| {
                    try addFile(allocator, io, &mounts, bound.directory, library, try std.fmt.allocPrint(allocator, "/lib/{s}", .{std.fs.path.basename(library.path)}), .artifact);
                    try interpreterMount(allocator, io, &mounts, bound, library);
                }
                // libc can itself require the loader by SONAME.
                const bytes = try bound.directory.read(allocator, io, loader.path, 64 * 1024 * 1024, .artifact);
                var image = try elf.Image.parse(allocator, bytes);
                defer image.deinit();
                const soname = try loaderSoname(image, bytes);
                if (soname) |name| try addFile(allocator, io, &mounts, bound.directory, loader, try std.fmt.allocPrint(allocator, "/lib/{s}", .{name}), .artifact);
            }
        }
    }
    for ([_][]const u8{ "null", "zero", "random", "urandom" }, [_]u32{ 3, 5, 8, 9 }) |name, minor| {
        const path = try std.fmt.allocPrint(allocator, "/dev/{s}", .{name});
        const file = try std.Io.Dir.openFileAbsolute(io, path, .{ .path_only = true, .follow_symlinks = false });
        var metadata: linux.Statx = undefined;
        if (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &metadata)) != .SUCCESS or
            metadata.mode & linux.S.IFMT != linux.S.IFCHR or metadata.rdev_major != 1 or metadata.rdev_minor != minor)
            return error.UnsafeFile;
        try mounts.append(allocator, .{ .file = file, .target = path, .directory = false, .device = true });
    }
    const environment_path = try std.fs.path.join(allocator, &.{ sandbox.workspace.path, sandbox.isolation.environment.path });
    try addFile(allocator, io, &mounts, sandbox.workspace, sandbox.isolation.environment, environment_path, .private);
    if (sandbox.isolation.make_environment) |file|
        try addFile(allocator, io, &mounts, sandbox.workspace, file, try std.fs.path.join(allocator, &.{ sandbox.workspace.path, file.path }), .private);
    if (sandbox.isolation.git_policy) |file| {
        // Protect the original inode's workspace spelling as well: a readonly
        // /etc bind alone would still permit writes through the source path.
        try addFile(allocator, io, &mounts, sandbox.workspace, file, try std.fs.path.join(allocator, &.{ sandbox.workspace.path, file.path }), .private);
        try addFile(allocator, io, &mounts, sandbox.workspace, file, git_entry.policy_path, .private);
    }
    std.mem.sort(Mount, mounts.items, {}, struct {
        fn less(_: void, a: Mount, b: Mount) bool {
            return if (a.target.len == b.target.len) std.mem.lessThan(u8, a.target, b.target) else a.target.len < b.target.len;
        }
    }.less);
    const root_path = try std.fs.path.join(allocator, &.{ sandbox.scratch.path, "namespace-root" });
    const root_z = try allocator.dupeZ(u8, root_path);
    const root_before = try fs.Directory.open(allocator, io, root_path);
    defer root_before.close(allocator, io);
    try sandbox.root.require(try Identity.directory(root_before));
    // A fresh directory is mandatory. Do not reuse a historical root.
    var it = root_before.dir.iterate();
    if (try it.next(io) != null) return error.UnsafeFile;
    try userNamespace(sandbox.isolation.account);
    if (linux.errno(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.NEWPID | linux.CLONE.NEWNET | linux.CLONE.NEWIPC | linux.CLONE.NEWUTS)) != .SUCCESS)
        return error.NamespaceUnavailable;
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS)
        return error.MountNamespaceUnavailable;
    const scratch_dir = try std.Io.Dir.openDirAbsolute(io, sandbox.scratch.path, .{ .follow_symlinks = false, .iterate = true });
    defer scratch_dir.close(io);
    try sameObject(.{ .handle = sandbox.scratch.dir.handle, .flags = .{ .nonblocking = false } }, .{ .handle = scratch_dir.handle, .flags = .{ .nonblocking = false } });
    const parent = try ParentGuard.acquire();
    defer parent.close();
    const channel = try makePipe();
    defer _ = linux.close(channel[0]);
    const child = linux.fork();
    if (linux.errno(child) != .SUCCESS) {
        _ = linux.close(channel[1]);
        return error.NamespaceForkUnavailable;
    }
    if (child != 0) {
        _ = linux.close(channel[1]);
        _ = wait(@intCast(child)) catch {
            // Exiting the helper kills PID 1 through the armed pidfd guard.
            return .{ .primary = .setup_failed, .cleanup = .failed };
        };
        var status = readPipeStatus(channel[0]);
        const unmounted = linux.errno(linux.umount2(root_z, if (cleanup_fault) 0xffff else linux.MNT.DETACH));
        if (cleanup_fault and unmounted == .SUCCESS) return error.CleanupFaultNotTriggered;
        if (cleanup_fault or (unmounted != .SUCCESS and unmounted != .INVAL)) status.cleanup = .failed;
        if (cleanup_fault) _ = linux.umount2(root_z, linux.MNT.DETACH);
        return status;
    }
    _ = linux.close(channel[0]);
    if (sandbox.status_file) |status_file| status_file.close();
    const status = childNamespace(allocator, io, sandbox, argv, environment, mounts.items, root_before, scratch_dir, parent, channel[1]) catch
        Status{ .primary = .setup_failed };
    const bytes = status.encode();
    _ = linux.write(channel[1], &bytes, bytes.len);
    linux.exit_group(0);
}

fn childNamespace(allocator: std.mem.Allocator, io: std.Io, sandbox: Sandbox, argv: []const []const u8, environment: *const std.process.Environ.Map, mounts: []const Mount, root_before: fs.Directory, scratch_dir: std.Io.Dir, parent: ParentGuard, status_fd: linux.fd_t) !Status {
    if (linux.getpid() != 1 or linux.getppid() != 0) return error.PidNamespaceUnavailable;
    // getppid()==0 cannot identify the original parent across PID namespaces.
    // The held pidfd covers death before registration as well as PID reuse.
    try parent.arm();
    parent.close();
    const root_target = try scratch_dir.openDir(io, "namespace-root", .{ .follow_symlinks = false });
    try sameObject(
        .{ .handle = root_before.dir.handle, .flags = .{ .nonblocking = false } },
        .{ .handle = root_target.handle, .flags = .{ .nonblocking = false } },
    );
    try tmpfs(allocator, root_target.handle);
    root_target.close(io);
    // The unmapped host root UID is intentionally unavailable in this user
    // namespace. Continue from held descriptors, not a new host-root traversal.
    const root: fs.Directory = .{
        .dir = try scratch_dir.openDir(io, "namespace-root", .{ .follow_symlinks = false, .iterate = true }),
        .path = root_before.path,
    };
    // Recursive clones must preserve validated submount content, but must not
    // recursively copy this root back through the source's writable subtree.
    const root_fd_path = try std.fmt.allocPrintSentinel(allocator, "/proc/self/fd/{d}", .{root.dir.handle}, 0);
    if (linux.errno(linux.mount(null, root_fd_path, null, linux.MS.UNBINDABLE, 0)) != .SUCCESS)
        return error.MountNamespaceUnavailable;
    try bindAt(allocator, io, root, .{
        .file = .{ .handle = sandbox.repository.dir.handle, .flags = .{ .nonblocking = false } },
        .target = sandbox.repository.path,
        .directory = true,
    });
    const hidden = try std.fmt.allocPrint(allocator, "{s}/.d", .{sandbox.repository.path});
    const hidden_directory = try ensureDirectory(allocator, io, root, hidden);
    try tmpfs(allocator, hidden_directory.handle);
    hidden_directory.close(io);
    for (mounts) |mount| try bindAt(allocator, io, root, mount);
    for ([_][]const u8{ "/bin", "/lib", "/lib64", "/usr", "/etc", "/proc", sandbox.isolation.account.home }) |path| {
        const directory = try ensureDirectory(allocator, io, root, path);
        directory.close(io);
    }
    try symlink(allocator, root, "/bin", "usr/bin");
    try symlink(allocator, root, "/lib", "usr/lib");
    try symlink(allocator, root, "/lib64", "usr/lib64");
    try symlink(allocator, root, ".", if (builtin.cpu.arch == .aarch64) "lib/aarch64-linux-gnu" else "lib/x86_64-linux-gnu");
    for (sandbox.aliases) |alias| {
        try c.core.private_files.basename(alias.name);
        const executable = alias.bound.contract.executable orelse return error.InvalidRuntime;
        try symlink(allocator, root, try std.fs.path.join(allocator, &.{ alias.bound.directory.path, executable.path }), try std.fmt.allocPrint(allocator, "bin/{s}", .{alias.name}));
    }
    try symlink(allocator, root, "/proc/self/fd", "dev/fd");
    inline for (.{ "stdin", "stdout", "stderr" }, 0..) |name, fd|
        try symlink(allocator, root, try std.fmt.allocPrint(allocator, "/proc/self/fd/{d}", .{fd}), "dev/" ++ name);
    try writeRoot(io, root, "etc/passwd", try sandbox.isolation.account.passwd(allocator));
    try writeRoot(io, root, "etc/group", try std.fmt.allocPrint(allocator, "{s}:x:{d}:\n", .{ sandbox.isolation.account.name, sandbox.isolation.account.gid }));
    try writeRoot(io, root, "etc/nsswitch.conf", "passwd: files\ngroup: files\n");
    const proc_path = try allocator.dupeZ(u8, try std.fs.path.join(allocator, &.{ root.path, "proc" }));
    if (linux.errno(linux.mount("proc", proc_path, "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, 0)) != .SUCCESS)
        return error.ProcNamespaceUnavailable;
    try readonlyAt(io, root, "proc");
    try readonlyAt(io, root, hidden[1..]);
    try attributes(root.dir.handle, true, false, false);
    if (linux.errno(linux.fchdir(root.dir.handle)) != .SUCCESS or linux.errno(linux.chroot(".")) != .SUCCESS or
        linux.errno(linux.chdir("/")) != .SUCCESS) return error.ChrootUnavailable;
    try sandbox.isolation.facade_lock.require(try Identity.of(sandbox.isolation.facade_lock.path, try facadeInside(allocator, io, sandbox.isolation.facade_runtime.path)));
    const args = try allocator.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |arg, i| args[i] = (try allocator.dupeZ(u8, arg)).ptr;
    const block = try environment.createPosixBlock(allocator, .{ .zig_progress_fd = -1 });
    const cwd = try allocator.dupeZ(u8, sandbox.repository.path);
    if (linux.errno(linux.chdir(cwd)) != .SUCCESS) return error.ChrootUnavailable;
    try dropPrivileges();
    // Same-UID payloads must not reopen PID 1's private status/exec pipe through
    // procfs. This does not change passwd HOME, lock identity, or payload FDs.
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_DUMPABLE), 0, 0, 0, 0)) != .SUCCESS)
        return error.DescriptorIsolationUnavailable;
    try closeExcept(status_fd);
    _ = linux.syscall1(.umask, 0o077);
    const exec_pipe = try makePipe();
    const command = linux.fork();
    if (linux.errno(command) != .SUCCESS) return .{ .primary = .spawn_failed };
    if (command == 0) {
        _ = linux.close(status_fd);
        _ = linux.close(exec_pipe[0]);
        _ = linux.execve(args[0].?, args.ptr, block.slice.ptr);
        _ = linux.write(exec_pipe[1], "E", 1);
        linux.exit_group(126);
    }
    _ = linux.close(exec_pipe[1]);
    const status = try wait(@intCast(command));
    var marker: [2]u8 = undefined;
    const count = linux.read(exec_pipe[0], &marker, marker.len);
    _ = linux.close(exec_pipe[0]);
    if (count == 1 and marker[0] == 'E') return .{ .primary = .spawn_failed };
    if (count != 0) return error.InvalidNamespaceStatus;
    // PID 1 is chrooted too. Reap the command; exiting
    // destroys the namespace, including detached/setsid grandchildren.
    return status;
}

pub fn closeExcept(fd: linux.fd_t) !void {
    if (fd < 3) return error.DescriptorIsolationUnavailable;
    if (fd > 3 and linux.errno(linux.close_range(3, @intCast(fd - 1), @bitCast(@as(u32, 0)))) != .SUCCESS)
        return error.DescriptorIsolationUnavailable;
    if (linux.errno(linux.close_range(@intCast(fd + 1), std.math.maxInt(linux.fd_t), @bitCast(@as(u32, 0)))) != .SUCCESS)
        return error.DescriptorIsolationUnavailable;
}

fn makePipe() ![2]linux.fd_t {
    var pipe: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.StatusUnavailable;
    return pipe;
}

fn readPipeStatus(fd: linux.fd_t) Status {
    // The writer has been reaped; do not block even if a bug retained a copy.
    if (linux.errno(linux.fcntl(fd, linux.F.SETFL, @as(u32, @bitCast(linux.O{ .NONBLOCK = true })))) != .SUCCESS)
        return .{ .recording = .malformed };
    var bytes: [9]u8 = undefined;
    const count = linux.read(fd, &bytes, bytes.len);
    if (linux.errno(count) != .SUCCESS) return .{ .recording = .malformed };
    return Status.decode(bytes[0..count]) catch |err| .{ .recording = if (err == error.MissingNamespaceStatus) .missing else .malformed };
}

fn loaderSoname(image: elf.Image, bytes: []const u8) !?[]const u8 {
    // Bound.validate already checks the table; only extract its mount spelling.
    for (image.sections) |section| {
        if (section.header.sh_type != std.elf.SHT_DYNAMIC) continue;
        const strings = try image.sectionData(image.sections[section.header.sh_link]);
        var offset: u64 = 0;
        while (offset < section.header.sh_size) : (offset += @sizeOf(std.elf.Elf64_Dyn)) {
            const entry = try elf.structure(std.elf.Elf64_Dyn, bytes, section.header.sh_offset + offset, image.header.endian);
            if (entry.d_tag == std.elf.DT_NULL) break;
            if (entry.d_tag == std.elf.DT_SONAME) return try elf.string(strings, entry.d_val);
        }
    }
    return null;
}
fn facadeInside(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.Io.File {
    const directory = try fs.Directory.open(allocator, io, path);
    defer directory.close(allocator, io);
    return directory.openFile(io, "build.lock", .private);
}
fn addDirectory(allocator: std.mem.Allocator, mounts: *std.ArrayList(Mount), directory: fs.Directory, readonly: bool) !void {
    for (mounts.items) |previous| if (std.mem.eql(u8, previous.target, directory.path)) {
        try (try Identity.directory(directory)).require(try Identity.of(previous.target, previous.file));
        if (previous.readonly != readonly or !previous.directory) return error.ConflictingMount;
        return;
    };
    try mounts.append(allocator, .{
        .file = .{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } },
        .target = directory.path,
        .directory = true,
        .readonly = readonly,
    });
}
fn addFile(allocator: std.mem.Allocator, io: std.Io, mounts: *std.ArrayList(Mount), directory: fs.Directory, record: c.File, target: []const u8, policy: fs.Policy) !void {
    try env.absolute(target);
    const file = try directory.openFile(io, record.path, policy);
    const m = try fs.metadata(file);
    if (m.size != record.size or m.mode & 0o7777 != record.mode or
        !std.crypto.timing_safe.eql(c.Sha, try fs.hashFile(io, file, m.size), record.sha256) or
        !std.meta.eql(m, try fs.metadata(file)))
        return error.SourceChanged;
    for (mounts.items) |previous| if (std.mem.eql(u8, previous.target, target)) {
        file.close(io);
        const prior = previous.record orelse return error.ConflictingMount;
        if (prior.size != record.size or !std.meta.eql(prior.sha256, record.sha256)) return error.ConflictingRuntime;
        return;
    };
    try mounts.append(allocator, .{ .file = file, .target = target, .directory = false, .record = record });
}
fn interpreterMount(allocator: std.mem.Allocator, io: std.Io, mounts: *std.ArrayList(Mount), bound: rt.Bound, record: c.File) !void {
    const bytes = try bound.directory.read(allocator, io, record.path, 1024 * 1024 * 1024, .artifact);
    defer allocator.free(bytes);
    var image = try elf.Image.parse(allocator, bytes);
    defer image.deinit();
    for (image.programs) |program| if (program.p_type == std.elf.PT_INTERP) {
        const interpreter = try elf.range(bytes, program.p_offset, program.p_filesz);
        const path = interpreter[0 .. interpreter.len - 1];
        if (!std.mem.startsWith(u8, path, "/lib/") and !std.mem.startsWith(u8, path, "/lib64/")) return error.InvalidRuntime;
        try addFile(allocator, io, mounts, bound.directory, bound.contract.loader orelse return error.IncompleteRuntime, try allocator.dupe(u8, path), .artifact);
    };
}
fn ensureDirectory(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory, absolute: []const u8) !std.Io.Dir {
    _ = allocator;
    try env.absolute(absolute);
    var current = try root.dir.openDir(io, ".", .{ .follow_symlinks = false, .iterate = true });
    errdefer current.close(io);
    var parts = std.mem.splitScalar(u8, absolute[1..], '/');
    while (parts.next()) |part| {
        current.createDir(io, part, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const next = try current.openDir(io, part, .{ .follow_symlinks = false, .iterate = true });
        current.close(io);
        current = next;
    }
    return current;
}
fn tmpfs(allocator: std.mem.Allocator, target: linux.fd_t) !void {
    const path = try std.fmt.allocPrintSentinel(allocator, "/proc/self/fd/{d}", .{target}, 0);
    if (linux.errno(linux.mount("tmpfs", path, "tmpfs", linux.MS.NOSUID | linux.MS.NODEV, @intFromPtr("mode=0700,size=16m"))) != .SUCCESS)
        return error.MountNamespaceUnavailable;
}
const MountAttributes = extern struct { set: u64, clear: u64 = 0, propagation: u64 = 0, userns: u64 = 0 };
fn attributes(fd: linux.fd_t, readonly: bool, device: bool, recursive: bool) !void {
    const attr: MountAttributes = .{ .set = (if (readonly) @as(u64, 1) else 0) | 2 | (if (device) @as(u64, 0) else 4) };
    // Linux UAPI, not Zig 0.16's incomplete three-argument mount_setattr wrapper.
    const flags = @as(u32, linux.AT.EMPTY_PATH) | (if (recursive) @as(u32, 0x8000) else 0);
    if (linux.errno(linux.syscall5(.mount_setattr, @intCast(fd), @intFromPtr(""), flags, @intFromPtr(&attr), @sizeOf(MountAttributes))) != .SUCCESS)
        return error.MountAttributesUnavailable;
}
fn bindAt(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory, mount: Mount) !void {
    const target = if (mount.directory)
        (try ensureDirectory(allocator, io, root, mount.target)).handle
    else blk: {
        const parent = try ensureDirectory(allocator, io, root, std.fs.path.dirname(mount.target).?);
        defer parent.close(io);
        const file = parent.createFile(io, std.fs.path.basename(mount.target), .{
            .read = true,
            .exclusive = true,
            .permissions = .fromMode(0o600),
        }) catch |err| switch (err) {
            error.PathAlreadyExists => try parent.openFile(io, std.fs.path.basename(mount.target), .{ .path_only = true, .follow_symlinks = false }),
            else => return err,
        };
        errdefer file.close(io);
        if ((try fs.metadata(file)).mode & linux.S.IFMT != linux.S.IFREG) return error.UnsafeFile;
        break :blk file.handle;
    };
    defer _ = linux.close(target);
    // Pre-unshare descriptors refer to mounts in the *old* namespace. Resolve
    // their kernel-provided names in the new mount tree, requiring the same
    // held object, before open_tree/move_mount (which reject foreign mounts).
    var path_buffer: [4096]u8 = undefined;
    const source_path = path_buffer[0..try std.Io.Dir.readLinkAbsolute(io, try std.fmt.allocPrint(allocator, "/proc/self/fd/{d}", .{mount.file.handle}), &path_buffer)];
    const current = try std.Io.Dir.openFileAbsolute(io, source_path, .{ .path_only = true, .follow_symlinks = false });
    defer current.close(io);
    try sameObject(mount.file, current);
    const flags = @as(u32, linux.AT.EMPTY_PATH | 1 | 0x80000) | (if (mount.directory) @as(u32, 0x8000) else 0);
    const opened = linux.syscall3(.open_tree, @intCast(current.handle), @intFromPtr(""), flags);
    if (linux.errno(opened) != .SUCCESS) return switch (linux.errno(opened)) {
        .PERM, .ACCES => error.OpenTreeDenied,
        .INVAL => error.OpenTreeInvalid,
        .NOSYS => error.OpenTreeUnavailable,
        else => error.DetachedMountUnavailable,
    };
    const detached: linux.fd_t = @intCast(opened);
    defer _ = linux.close(detached);
    try attributes(detached, mount.readonly, mount.device, mount.directory);
    const moved = linux.syscall5(.move_mount, @intCast(detached), @intFromPtr(""), @intCast(target), @intFromPtr(""), 0x4 | 0x40);
    if (linux.errno(moved) != .SUCCESS) return switch (linux.errno(moved)) {
        .PERM, .ACCES => error.MoveMountDenied,
        .INVAL => error.MoveMountInvalid,
        .NOSYS => error.MoveMountUnavailable,
        else => error.DetachedMountUnavailable,
    };
}
fn sameObject(held: std.Io.File, named: std.Io.File) !void {
    if (!std.meta.eql(try fs.metadata(held), try fs.metadata(named))) return error.SourceChanged;
}
fn readonlyAt(io: std.Io, root: fs.Directory, path: []const u8) !void {
    const directory = try root.dir.openDir(io, path, .{ .follow_symlinks = false });
    defer directory.close(io);
    try attributes(directory.handle, true, false, false);
}
fn symlink(allocator: std.mem.Allocator, root: fs.Directory, target: []const u8, path: []const u8) !void {
    if (linux.errno(linux.symlinkat(try allocator.dupeZ(u8, target), root.dir.handle, try allocator.dupeZ(u8, path))) != .SUCCESS)
        return error.InvalidAlias;
}
fn writeRoot(io: std.Io, root: fs.Directory, path: []const u8, bytes: []const u8) !void {
    const file = try root.dir.createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}
fn writeMap(path: [*:0]const u8, bytes: []const u8) !void {
    const opened = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.UserMappingUnavailable;
    defer _ = linux.close(@intCast(opened));
    if (linux.write(@intCast(opened), bytes.ptr, bytes.len) != bytes.len) return error.UserMappingUnavailable;
}
pub fn userNamespace(account: env.Account) !void {
    var groups: [64]linux.gid_t = undefined;
    const count = linux.getgroups(groups.len, &groups);
    if (linux.errno(count) != .SUCCESS) return error.SupplementaryGroupsUnavailable;
    // Unprivileged gid_map requires setgroups=deny. Do not retain any ambient
    // group authority beyond the single passwd GID that we actually map.
    for (groups[0..count]) |group| if (group != account.gid) return error.SupplementaryGroupsUnavailable;
    if (linux.errno(linux.unshare(linux.CLONE.NEWUSER)) != .SUCCESS) return error.UserNamespaceUnavailable;
    try writeMap("/proc/self/setgroups", "deny\n");
    var buffer: [96]u8 = undefined;
    try writeMap("/proc/self/uid_map", try std.fmt.bufPrint(&buffer, "{d} {d} 1\n", .{ account.uid, account.uid }));
    try writeMap("/proc/self/gid_map", try std.fmt.bufPrint(&buffer, "{d} {d} 1\n", .{ account.gid, account.gid }));
    if (linux.geteuid() != account.uid or linux.getegid() != account.gid) return error.UserMappingUnavailable;
}
fn dropPrivileges() !void {
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) != .SUCCESS)
        return error.PrivilegeDropUnavailable;
    var cap: usize = 0;
    while (cap < 64) : (cap += 1) {
        const result = linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
        if (linux.errno(result) == .INVAL) break;
        if (linux.errno(result) != .SUCCESS) return error.PrivilegeDropUnavailable;
    }
    // PR_CAP_AMBIENT_CLEAR_ALL.
    if (linux.errno(linux.prctl(47, 4, 0, 0, 0)) != .SUCCESS) return error.PrivilegeDropUnavailable;
    // Linux UAPI pid is 32-bit; Zig 0.16's cap_user_header_t uses usize.
    const header: extern struct { version: u32, pid: i32 } = .{ .version = 0x20080522, .pid = 0 };
    const data = [_]linux.cap_user_data_t{std.mem.zeroes(linux.cap_user_data_t)} ** 2;
    if (linux.errno(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data))) != .SUCCESS)
        return error.PrivilegeDropUnavailable;
}
fn wait(pid: linux.pid_t) !Status {
    while (true) {
        var status: u32 = 0;
        const result = linux.waitpid(-1, &status, 0);
        switch (linux.errno(result)) {
            .SUCCESS => if (result == @as(usize, @intCast(pid))) {
                if (linux.W.IFEXITED(status)) return .{ .primary = .exited, .code = linux.W.EXITSTATUS(status) };
                if (linux.W.IFSIGNALED(status)) return .{ .primary = .signaled, .code = @intCast(@intFromEnum(linux.W.TERMSIG(status))) };
                return error.NamespaceWaitFailed;
            },
            .INTR => {},
            else => return error.NamespaceWaitFailed,
        }
    }
}
