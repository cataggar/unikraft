// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const c = @import("contracts.zig");
const fs = @import("files.zig");
const rt = @import("runtime.zig");
const ns = @import("namespace.zig");
const env = @import("environment.zig");
const git_entry = @import("git_entry.zig");
const producer = @import("producer.zig");
const options = @import("fixture_options");

comptime {
    _ = producer;
}

pub fn main(init: std.process.Init.Minimal) void {
    // Only this synthetic executable receives the hosted CI audit name.
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NAME), @intFromPtr("uk-prep-ns-test"), 0, 0, 0)) != .SUCCESS)
        fail(error.FixtureAuditNameUnavailable);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const args = init.args.toSlice(allocator) catch |err| fail(err);
    if (args.len < 2) fail(error.InvalidFixtureMode);
    if (std.mem.startsWith(u8, args[1], "inside-")) {
        if (args.len != 2) fail(error.InvalidFixtureMode);
        inside(allocator, io, args[1], init.environ) catch |err| fail(err);
        return;
    }
    requireOrdinaryCredentials(allocator, io) catch |err| fail(err);
    if (std.mem.eql(u8, args[1], "ci-isolation")) {
        if (args.len != 4) fail(error.InvalidFixtureMode);
        const status_file = ns.StatusFile.openParent(allocator, args[2]) catch |err| fail(err);
        const diagnostic = ns.StatusFile.openParent(allocator, args[3]) catch |err| fail(err);
        const status = fixture(allocator, io, "isolation", status_file) catch |err| {
            diagnostic.write(.{ .primary = .exited, .code = @intFromEnum(namespaceError(err)) }) catch |write_error| fail(write_error);
            fail(err);
        };
        diagnostic.write(.{ .primary = .exited, .code = @intFromEnum(NamespaceError.none) }) catch |err| fail(err);
        status_file.write(status) catch |err| fail(err);
        return;
    }
    if (args.len != 3) fail(error.InvalidFixtureMode);
    const status_file = ns.StatusFile.openParent(allocator, args[2]) catch |err| fail(err);
    if (std.mem.eql(u8, args[1], "status-missing")) return;
    if (std.mem.eql(u8, args[1], "status-exit143")) linux.exit_group(143);
    if (std.mem.eql(u8, args[1], "status-partial")) {
        const bytes = (ns.Status{ .primary = .exited }).encode();
        _ = linux.pwrite(status_file.fd, &bytes, 3, 0);
        return;
    }
    if (std.mem.eql(u8, args[1], "status-malformed")) {
        _ = linux.pwrite(status_file.fd, "garbage!", 8, 0);
        return;
    }
    if (std.mem.eql(u8, args[1], "parent-death-race")) {
        parentDeathRace(allocator, io) catch |err| fail(err);
        status_file.write(.{ .primary = .exited }) catch |err| fail(err);
        return;
    }
    const status = fixture(allocator, io, args[1], status_file) catch |err| fail(err);
    status_file.write(status) catch |err| fail(err);
}
fn fail(err: anyerror) noreturn {
    const name = @errorName(err);
    _ = linux.write(2, name.ptr, name.len);
    _ = linux.write(2, "\n", 1);
    linux.exit_group(125);
}
fn put(io: std.Io, directory: std.Io.Dir, path: []const u8, bytes: []const u8, mode: u16) !void {
    const file = try directory.createFile(io, path, .{ .exclusive = true, .permissions = .fromMode(mode) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}
fn makeDir(allocator: std.mem.Allocator, io: std.Io, parent: fs.Directory, relative: []const u8) !fs.Directory {
    try parent.dir.createDirPath(io, relative);
    const dir = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ parent.path, relative }));
    try dir.dir.setPermissions(io, .fromMode(0o700));
    return dir;
}
fn copy(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, input: []const u8, destination: []const u8, mode: u16) !void {
    // Only fixed public native fixture inputs (and this fixture's own binary).
    const file = try std.Io.Dir.openFileAbsolute(io, input, .{});
    defer file.close(io);
    const metadata = try fs.metadata(file);
    if (metadata.size > 64 * 1024 * 1024) return error.FileTooLarge;
    const bytes = try allocator.alloc(u8, @intCast(metadata.size));
    defer allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len or
        !std.meta.eql(metadata, try fs.metadata(file))) return error.SourceChanged;
    try put(io, directory.dir, destination, bytes, mode);
}

fn requireOrdinaryCredentials(allocator: std.mem.Allocator, io: std.Io) !void {
    const account = try env.Account.current(allocator, io);
    if (account.uid == 0 or linux.getuid() != account.uid or linux.geteuid() != account.uid or
        linux.getgid() != account.gid or linux.getegid() != account.gid) return error.InvalidFixtureCredentials;
    var groups: [64]linux.gid_t = undefined;
    const count = linux.getgroups(groups.len, &groups);
    if (linux.errno(count) != .SUCCESS) return error.SupplementaryGroupsUnavailable;
    try requireFixtureGroups(groups[0..count], account.gid);
    const header: extern struct { version: u32, pid: i32 } = .{ .version = 0x20080522, .pid = 0 };
    var data = [_]linux.cap_user_data_t{std.mem.zeroes(linux.cap_user_data_t)} ** 2;
    if (linux.errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&data))) != .SUCCESS or
        !std.mem.allEqual(u8, std.mem.asBytes(&data), 0)) return error.InvalidFixtureCredentials;
    for (0..64) |cap| {
        const result = linux.prctl(47, 1, cap, 0, 0); // PR_CAP_AMBIENT_IS_SET
        if (linux.errno(result) == .INVAL) break;
        if (linux.errno(result) != .SUCCESS or result != 0) return error.InvalidFixtureCredentials;
    }
}

fn requireFixtureGroups(groups: []const linux.gid_t, primary: linux.gid_t) !void {
    for (groups) |group| if (group != primary) return error.SupplementaryGroupsUnavailable;
}

fn facadeDirectory(allocator: std.mem.Allocator, io: std.Io, account: env.Account) !fs.Directory {
    const run_user = try std.fmt.allocPrint(allocator, "/run/user/{d}", .{account.uid});
    const probe = std.Io.Dir.openDirAbsolute(io, run_user, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (probe) |value| value.close(io);
    const directory = if (probe != null) try fs.Directory.open(allocator, io, run_user) else null;
    defer if (directory) |value| value.close(allocator, io);
    return fs.Directory.open(allocator, io, try std.fmt.allocPrint(allocator, "{s}/unikraft-zig-facade-{d}", .{
        if (directory != null) run_user else account.home, account.uid,
    }));
}
const NamespaceIds = struct { user: u64, mnt: u64, pid: u64, net: u64 };
fn namespaceIds(io: std.Io) !NamespaceIds {
    var ids: NamespaceIds = undefined;
    inline for (std.meta.fields(NamespaceIds)) |field| {
        const file = try std.Io.Dir.openFileAbsolute(io, "/proc/self/ns/" ++ field.name, .{});
        defer file.close(io);
        @field(ids, field.name) = (try fs.metadata(file)).inode;
    }
    return ids;
}
fn tool(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, executable: []const u8, dynamic: bool) !rt.Bound {
    const libraries = try allocator.alloc(c.File, if (dynamic) 1 else 0);
    if (dynamic) libraries[0] = try directory.record(allocator, io, "lib/libc.so.6", 16 * 1024 * 1024, .artifact);
    return .{ .directory = directory, .contract = .{
        .role = .preparation,
        .origin = .{ .scheme = .authenticated_distribution, .revision = "synthetic-public-fixture", .source_sha256 = c.digest("fixture"), .producer_sha256 = c.digest("fixture") },
        .target = if (builtin.cpu.arch == .aarch64) .aarch64_linux else .x86_64_linux,
        .tree = (try fs.inventory(allocator, io, directory, 32, 128 * 1024 * 1024)).tree,
        .executable = try directory.record(allocator, io, executable, 64 * 1024 * 1024, .executable),
        .loader = if (dynamic) try directory.record(allocator, io, "lib/loader", 16 * 1024 * 1024, .executable) else null,
        .libraries = libraries,
    } };
}
fn fixture(allocator: std.mem.Allocator, io: std.Io, mode: []const u8, status_file: ns.StatusFile) !ns.Status {
    if (std.mem.startsWith(u8, mode, "git-")) return gitFixture(allocator, io, mode, status_file);
    if (!std.mem.eql(u8, mode, "isolation") and !std.mem.eql(u8, mode, "failure") and
        !std.mem.eql(u8, mode, "timeout") and !std.mem.eql(u8, mode, "descendant") and
        !std.mem.eql(u8, mode, "exit143") and !std.mem.eql(u8, mode, "signal") and
        !std.mem.eql(u8, mode, "exec-missing") and !std.mem.eql(u8, mode, "setup-failure") and
        !std.mem.eql(u8, mode, "cleanup-failure")) return error.InvalidFixtureMode;
    const base = try fs.Directory.open(allocator, io, options.workspace);
    const repository = try makeDir(allocator, io, base, try std.fmt.allocPrint(allocator, "fixture-{s}", .{mode}));
    try put(io, repository.dir, "source.txt", "readonly synthetic source\n", 0o600);
    const historical = try makeDir(allocator, io, repository, ".d");
    try put(io, historical.dir, "hidden-marker", "synthetic historical marker\n", 0o600);
    const workspace = try makeDir(allocator, io, repository, ".d/zig-migration-preparation/resume-producer/work");
    const scratch = try makeDir(allocator, io, workspace, "scratch");
    const root = try makeDir(allocator, io, scratch, "namespace-root");
    for ([_][]const u8{ "tmp", "cache", "config", "zig-local", "zig-global", "disabled-git-exec", "disabled-openssl" }) |name|
        _ = try makeDir(allocator, io, scratch, name);
    const native = try makeDir(allocator, io, workspace, "native");
    try copy(allocator, io, native, "/proc/self/exe", "fixture", 0o700);
    const static = try tool(allocator, io, native, "fixture", false);
    const dynamic_directory = try makeDir(allocator, io, workspace, "dynamic");
    _ = try makeDir(allocator, io, dynamic_directory, "lib");
    try copy(allocator, io, dynamic_directory, "/usr/bin/true", "true", 0o700);
    const system_lib = if (builtin.cpu.arch == .aarch64) "/usr/lib/aarch64-linux-gnu/" else "/usr/lib/x86_64-linux-gnu/";
    try copy(allocator, io, dynamic_directory, system_lib ++ "libc.so.6", "lib/libc.so.6", 0o600);
    try copy(allocator, io, dynamic_directory, system_lib ++ (if (builtin.cpu.arch == .aarch64) "ld-linux-aarch64.so.1" else "ld-linux-x86-64.so.2"), "lib/loader", 0o700);
    const dynamic = try tool(allocator, io, dynamic_directory, "true", true);
    var incomplete = dynamic;
    incomplete.contract.libraries = &.{};
    if (incomplete.validate(allocator, io)) |_| {
        return error.AcceptedIncompleteRuntime;
    } else |err| if (err != error.IncompleteRuntime) return err;
    const metadata = try makeDir(allocator, io, repository, ".git");
    try put(io, metadata.dir, "fixture", "readonly synthetic Git metadata\n", 0o600);
    const account = try env.Account.current(allocator, io);
    const facade = try facadeDirectory(allocator, io, account);
    const lock = try facade.openFile(io, "build.lock", .private);
    const lock_identity = try ns.Identity.of(try std.fs.path.join(allocator, &.{ facade.path, "build.lock" }), lock);
    const environment_record: env.Record = .{
        .workspace = scratch.path,
        .bison_pkgdatadir = native.path,
        .m4 = try std.fs.path.join(allocator, &.{ dynamic_directory.path, "true" }),
        .git_exec_path = try std.fs.path.join(allocator, &.{ scratch.path, "disabled-git-exec" }),
        .trust_bundle = try std.fs.path.join(allocator, &.{ repository.path, "source.txt" }),
    };
    try put(io, workspace.dir, "environment.json", try c.canonical(allocator, environment_record), 0o600);
    // Store expected lock identity under selected scratch, never change host lock.
    try put(io, workspace.dir, "lock.json", try c.canonical(allocator, lock_identity), 0o600);
    try put(io, workspace.dir, "host-namespaces.json", try c.canonical(allocator, try namespaceIds(io)), 0o600);
    var environment = try environment_record.create(allocator, account.home);
    const sandbox: ns.Sandbox = .{
        .repository = repository,
        .workspace = workspace,
        .scratch = scratch,
        .runtimes = &.{ static, dynamic },
        .aliases = &.{ .{ .name = "true", .bound = dynamic }, .{ .name = if (std.mem.eql(u8, mode, "setup-failure")) "invalid/alias" else "fixture", .bound = static } },
        .isolation = .{
            .helper = static,
            .account = account,
            .facade_runtime = facade,
            .facade_lock = lock_identity,
            .git_metadata = &.{.{ .directory = metadata, .tree = (try fs.inventory(allocator, io, metadata, 32, 1024)).tree }},
            .environment = try workspace.record(allocator, io, "environment.json", 16 * 1024, .private),
        },
        .root = try ns.Identity.directory(root),
        .status_file = status_file,
    };
    // Deliberately inherited non-CLOEXEC host descriptor. The payload must not
    // find it (or any namespace setup/source/lock descriptor).
    const leaked = try repository.openFile(io, "source.txt", .artifact);
    if (linux.errno(linux.fcntl(leaked.handle, linux.F.SETFD, 0)) != .SUCCESS) return error.FixtureFailed;
    const status = try ns.enterWithCleanupFault(allocator, io, sandbox, &.{
        if (std.mem.eql(u8, mode, "exec-missing")) "/bin/missing-fixture" else "/bin/fixture",
        try std.fmt.allocPrint(allocator, "inside-{s}", .{mode}),
    }, &environment, std.mem.eql(u8, mode, "cleanup-failure"));
    try scratch.dir.deleteDir(io, "namespace-root");
    return status;
}
fn inside(allocator: std.mem.Allocator, io: std.Io, mode: []const u8, inherited: std.process.Environ) !void {
    if (linux.getpid() != 2 or linux.getppid() != 1) return error.OutsidePidNamespace;
    if (std.mem.startsWith(u8, mode, "inside-git-")) return insideGit(allocator, io, mode);
    if (std.mem.eql(u8, mode, "inside-failure")) linux.exit_group(19);
    if (std.mem.eql(u8, mode, "inside-exit143")) linux.exit_group(143);
    if (std.mem.eql(u8, mode, "inside-signal")) {
        _ = linux.kill(linux.getpid(), .TERM);
        return error.FixtureFailed;
    }
    if (std.mem.eql(u8, mode, "inside-cleanup-failure")) linux.exit_group(19);
    if (std.mem.eql(u8, mode, "inside-timeout")) {
        try detached(io);
        try put(io, std.Io.Dir.cwd(), ".d/zig-migration-preparation/resume-producer/work/scratch/timeout-ready", "inside namespace\n", 0o600);
        while (true) _ = linux.syscall0(.sched_yield);
    }
    var link_buffer: [4096]u8 = undefined;
    if (std.Io.Dir.readLinkAbsolute(io, "/proc/1/root", &link_buffer)) |_| {
        return error.AccessibleSupervisor;
    } else |err| if (err != error.AccessDenied) return err;
    if (std.Io.Dir.openDirAbsolute(io, "/proc/1/fd", .{ .iterate = true })) |dir| {
        dir.close(io);
        return error.AccessibleSupervisor;
    } else |err| if (err != error.AccessDenied) return err;
    for ([_][]const u8{"/proc/self/fd"}) |path| {
        const fd_dir = try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true });
        defer fd_dir.close(io);
        var fds = fd_dir.iterate();
        while (try fds.next(io)) |entry| {
            const fd = try std.fmt.parseInt(linux.fd_t, entry.name, 10);
            if (fd > 2 and fd != fd_dir.handle) return error.InheritedDescriptor;
        }
    }
    const account = try env.Account.current(allocator, io);
    var map = try inherited.createMap(allocator);
    defer map.deinit();
    if (!std.mem.eql(u8, map.get("HOME") orelse "", account.home)) return error.AmbientHome;
    if (map.get("LD_LIBRARY_PATH") != null or !std.mem.eql(u8, map.get("GIT_CONFIG_GLOBAL") orelse "", "/dev/null") or
        !std.mem.eql(u8, map.get("GIT_CONFIG_NOSYSTEM") orelse "", "1")) return error.AmbientEnvironment;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    const repository = try fs.Directory.open(allocator, io, cwd);
    const workspace = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ cwd, ".d/zig-migration-preparation/resume-producer/work" }));
    const expected = try c.parse(ns.Identity, allocator, try workspace.read(allocator, io, "lock.json", 4096, .private));
    const facade = try fs.Directory.open(allocator, io, std.fs.path.dirname(expected.value.path).?);
    const lock = try facade.openFile(io, "build.lock", .private);
    try expected.value.require(try ns.Identity.of(expected.value.path, lock));
    lock.close(io);
    facade.close(allocator, io);
    for ([_][]const u8{ ".d/hidden-marker", "/etc/ld.so.cache", "/root", "/run/user" }) |path| {
        const file = repository.dir.openFile(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        file.close(io);
        return error.AmbientFilesystem;
    }
    for ([_][]const u8{ "source.txt", ".git/fixture", ".d/zig-migration-preparation/resume-producer/work/dynamic/true", ".d/zig-migration-preparation/resume-producer/work/environment.json" }) |path| {
        const file = repository.dir.openFile(io, path, .{ .mode = .write_only }) catch |err| switch (err) {
            error.ReadOnlyFileSystem => continue,
            else => return err,
        };
        file.close(io);
        return error.WritableInput;
    }
    try put(io, workspace.dir, "scratch/created", "private scratch output\n", 0o666);
    const created = try workspace.openFile(io, "scratch/created", .artifact);
    if ((try fs.metadata(created)).mode & 0o7777 != 0o600) return error.UnsafeUmask;
    created.close(io);
    if (linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 1) return error.PrivilegeDropUnavailable;
    var header: extern struct { version: u32, pid: i32 } = .{ .version = 0x20080522, .pid = 0 };
    var data = [_]linux.cap_user_data_t{std.mem.zeroes(linux.cap_user_data_t)} ** 2;
    if (linux.errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&data))) != .SUCCESS or !std.mem.allEqual(u8, std.mem.asBytes(&data), 0))
        return error.PrivilegeDropUnavailable;
    for (0..64) |cap| {
        const bounding = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
        if (linux.errno(bounding) == .INVAL) break;
        if (bounding != 0 or linux.prctl(47, 1, cap, 0, 0) != 0) return error.PrivilegeDropUnavailable;
    }
    const host = try c.parse(NamespaceIds, allocator, try workspace.read(allocator, io, "host-namespaces.json", 4096, .private));
    const isolated = try namespaceIds(io);
    inline for (std.meta.fields(NamespaceIds)) |field|
        if (@field(host.value, field.name) == @field(isolated, field.name)) return error.AmbientNamespace;
    try c.core.process.initialize();
    var result = try c.core.process.run(allocator, io, .{
        .argv = &.{"/bin/true"},
        .environment = &map,
        .cwd = repository.dir,
        .deadline = try c.core.process.Deadline.afterMilliseconds(5000),
    });
    if (result.failures.primary != null or !result.cleanup_complete) return error.DynamicClosureFailed;
    result.deinit(allocator);
    if (std.mem.eql(u8, mode, "inside-descendant")) {
        try detached(io);
    }
    _ = linux.write(1, "namespace-isolation-ok\n", "namespace-isolation-ok\n".len);
}

fn detached(io: std.Io) !void {
    const file = try std.Io.Dir.cwd().createFile(io, ".d/zig-migration-preparation/resume-producer/work/scratch/descendant-lock", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    if (linux.errno(linux.flock(file.handle, 2)) != .SUCCESS) return error.FixtureFailed;
    var pipe: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.FixtureFailed;
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.FixtureFailed;
    if (pid == 0) {
        if (linux.errno(linux.setsid()) != .SUCCESS) linux.exit_group(120);
        _ = linux.write(pipe[1], "1", 1);
        while (true) _ = linux.syscall0(.sched_yield);
    }
    _ = linux.close(pipe[1]);
    var ready: [1]u8 = undefined;
    if (linux.read(pipe[0], &ready, 1) != 1 or ready[0] != '1') return error.FixtureFailed;
    _ = linux.close(pipe[0]);
}

fn parentDeathRace(allocator: std.mem.Allocator, io: std.Io) !void {
    try c.core.process.initialize();
    const account = try env.Account.current(allocator, io);
    var ready: [2]linux.fd_t = undefined;
    var release: [2]linux.fd_t = undefined;
    var report: [2]linux.fd_t = undefined;
    for ([_]*[2]linux.fd_t{ &ready, &release, &report }) |pipe|
        if (linux.errno(linux.pipe2(pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.FixtureFailed;
    const parent = linux.fork();
    if (linux.errno(parent) != .SUCCESS) return error.FixtureFailed;
    if (parent == 0) {
        try ns.userNamespace(account);
        if (linux.errno(linux.unshare(linux.CLONE.NEWPID)) != .SUCCESS) return error.FixtureFailed;
        const guard = try ns.ParentGuard.acquire();
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) return error.FixtureFailed;
        if (child == 0) {
            _ = linux.write(ready[1], "R", 1);
            var marker: [1]u8 = undefined;
            if (linux.read(release[0], &marker, 1) != 1 or marker[0] != 'G') linux.exit_group(121);
            if (linux.getpid() != 1 or linux.getppid() != 0) linux.exit_group(122);
            guard.arm() catch |err| {
                if (err != error.ParentDied) linux.exit_group(123);
                guard.close();
                _ = linux.write(report[1], "D", 1);
                linux.exit_group(0);
            };
            // A vulnerable implementation reaches this payload marker.
            _ = linux.write(report[1], "P", 1);
            linux.exit_group(124);
        }
        while (true) _ = linux.syscall0(.sched_yield);
    }
    _ = linux.close(ready[1]);
    _ = linux.close(release[0]);
    _ = linux.close(report[1]);
    var marker: [1]u8 = undefined;
    if (linux.read(ready[0], &marker, 1) != 1 or marker[0] != 'R') return error.FixtureFailed;
    if (linux.errno(linux.kill(@intCast(parent), .KILL)) != .SUCCESS) return error.FixtureFailed;
    var status: u32 = 0;
    if (linux.waitpid(@intCast(parent), &status, 0) != parent or !linux.W.IFSIGNALED(status)) return error.FixtureFailed;
    // The original parent is dead and reaped before PID 1 registers PDEATHSIG.
    if (linux.write(release[1], "G", 1) != 1) return error.FixtureFailed;
    if (linux.errno(linux.waitpid(-1, &status, 0)) != .SUCCESS or !linux.W.IFEXITED(status) or linux.W.EXITSTATUS(status) != 0)
        return error.FixtureFailed;
    if (linux.read(report[0], &marker, 1) != 1 or marker[0] != 'D') return error.FixtureFailed;
    for ([_]linux.fd_t{ ready[0], release[1], report[0] }) |fd| _ = linux.close(fd);
    _ = linux.write(1, "parent-death-race-ok\n", "parent-death-race-ok\n".len);
}

const NamespaceError = enum(u8) {
    none,
    namespace_unavailable,
    mount_namespace_unavailable,
    other,
    unavailable,
    credentials,
    unsafe_file,
    unsafe_path,
    missing_file,
    source_changed,
    invalid_runtime,
    user_namespace_unavailable,
};

fn namespaceError(err: anyerror) NamespaceError {
    return switch (err) {
        error.NamespaceUnavailable => .namespace_unavailable,
        error.MountNamespaceUnavailable => .mount_namespace_unavailable,
        error.InvalidFixtureCredentials, error.SupplementaryGroupsUnavailable => .credentials,
        error.UnsafeFile => .unsafe_file,
        error.UnsafePath => .unsafe_path,
        error.FileNotFound => .missing_file,
        error.SourceChanged => .source_changed,
        error.InvalidRuntime, error.IncompleteRuntime => .invalid_runtime,
        error.UserNamespaceUnavailable => .user_namespace_unavailable,
        else => .other,
    };
}

fn readNamespaceError(value: anyerror!ns.Status) !NamespaceError {
    const status = value catch |err| switch (err) {
        error.MissingNamespaceStatus => return .unavailable,
        else => return err,
    };
    if (status.primary != .exited or status.cleanup != .complete or status.recording != .complete)
        return error.InvalidFixtureDiagnostic;
    return std.enums.fromInt(NamespaceError, status.code) orelse error.InvalidFixtureDiagnostic;
}

test "namespace CI diagnostics use a bounded side channel not discarded stderr" {
    try std.testing.expectEqual(NamespaceError.namespace_unavailable, namespaceError(error.NamespaceUnavailable));
    try std.testing.expectEqual(NamespaceError.mount_namespace_unavailable, namespaceError(error.MountNamespaceUnavailable));
    try std.testing.expectEqual(NamespaceError.credentials, namespaceError(error.SupplementaryGroupsUnavailable));
    try std.testing.expectEqual(NamespaceError.user_namespace_unavailable, namespaceError(error.UserNamespaceUnavailable));
    try std.testing.expectEqual(NamespaceError.unavailable, try readNamespaceError(error.MissingNamespaceStatus));
    try std.testing.expectEqual(NamespaceError.none, try readNamespaceError(.{ .primary = .exited }));
    try std.testing.expectError(error.InvalidFixtureDiagnostic, readNamespaceError(.{ .primary = .exited, .code = 255 }));
    try std.testing.expectError(error.InvalidFixtureDiagnostic, readNamespaceError(.{ .primary = .setup_failed }));
}

test "namespace CI group prerequisites retain production supplementary group restriction" {
    try requireFixtureGroups(&.{}, 1000);
    try requireFixtureGroups(&.{1000}, 1000);
    try std.testing.expectError(error.SupplementaryGroupsUnavailable, requireFixtureGroups(&.{ 1000, 4 }, 1000));
    try std.testing.expectError(error.SupplementaryGroupsUnavailable, requireFixtureGroups(&.{999}, 1000));
}

test "namespace CI baseline crosses native user and mount boundaries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try requireOrdinaryCredentials(a, io);
    try c.core.process.initialize();
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    const base = try fs.Directory.open(allocator, io, options.workspace);
    defer base.close(allocator, io);
    defer base.dir.deleteTree(io, "fixture-isolation") catch @panic("native baseline cleanup failed");
    const status_file = try ns.StatusFile.create();
    defer status_file.close();
    const diagnostic = try ns.StatusFile.create();
    defer diagnostic.close();
    const arg = try std.fmt.allocPrint(allocator, "{d}", .{status_file.fd});
    defer allocator.free(arg);
    const diagnostic_arg = try std.fmt.allocPrint(allocator, "{d}", .{diagnostic.fd});
    defer allocator.free(diagnostic_arg);
    var outcome: producer.Outcome = .{ .step = .inspect, .child = try c.core.process.run(allocator, io, .{
        .argv = &.{ @import("test_options").namespace_fixture, "ci-isolation", arg, diagnostic_arg },
        .environment = &map,
        .cwd = base.dir,
        .deadline = try c.core.process.Deadline.afterMilliseconds(15000),
        .stdout_limit = 4096,
        .stderr_limit = 4096,
    }) };
    defer outcome.deinit(allocator);
    const process_cleanup = outcome.child.cleanup_complete;
    const helper_exit: ?u8 = if (outcome.child.termination) |term|
        if (term == .exited) term.exited else null
    else
        null;
    const setup_error = try readNamespaceError(diagnostic.read());
    const status = status_file.read();
    outcome.namespaceStatus(status);
    const CopyProof = struct { size: u64, sha256: c.Sha, distinct_physical_copy: bool };
    var copy_proof: ?CopyProof = null;
    if (outcome.succeeded()) {
        const source_path = @import("test_options").namespace_fixture;
        const source_dir = try fs.Directory.open(a, io, std.fs.path.dirname(source_path).?);
        defer source_dir.close(a, io);
        const source_file = try source_dir.openFile(io, std.fs.path.basename(source_path), .executable);
        defer source_file.close(io);
        const copied_path = "fixture-isolation/.d/zig-migration-preparation/resume-producer/work/native/fixture";
        const copied = try base.openFile(io, copied_path, .executable);
        defer copied.close(io);
        const original_metadata = try fs.metadata(source_file);
        const copied_metadata = try fs.metadata(copied);
        const original_hash = try fs.hashFile(io, source_file, original_metadata.size);
        const copied_hash = try fs.hashFile(io, copied, copied_metadata.size);
        try std.testing.expectEqualDeep(original_metadata, try fs.metadata(source_file));
        try std.testing.expectEqualDeep(copied_metadata, try fs.metadata(copied));
        try std.testing.expectEqual(original_metadata.size, copied_metadata.size);
        try std.testing.expectEqualStrings(&original_hash, &copied_hash);
        const distinct = original_metadata.device != copied_metadata.device or original_metadata.inode != copied_metadata.inode;
        try std.testing.expect(distinct);
        copy_proof = .{ .size = copied_metadata.size, .sha256 = copied_hash, .distinct_physical_copy = distinct };
    }
    if (@import("test_options").ci_report) |path| {
        const directory = try fs.openPrivate(io, std.fs.path.dirname(path).?);
        defer directory.close(io);
        const bytes = try c.canonical(a, .{
            .schema = "hyperv_preparation_namespace_ci_baseline_v1",
            .authority = "synthetic_only",
            .namespace_error = setup_error,
            .helper_exit = helper_exit,
            .process_cleanup_complete = process_cleanup,
            .namespace_succeeded = outcome.succeeded(),
            .failures = outcome.child.failures,
            .runtime_copy = copy_proof,
        });
        const report = try directory.dir.createFile(io, std.fs.path.basename(path), .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer report.close(io);
        try report.writeStreamingAll(io, bytes);
        try report.sync(io);
    }
    try std.testing.expect(outcome.succeeded());
    try std.testing.expectEqualStrings("namespace-isolation-ok\n", outcome.child.stdout);
}

test "namespace native dynamic isolation, nonzero status, deadline and detached cleanup" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try c.core.process.initialize();
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    const base = try fs.Directory.open(allocator, io, options.workspace);
    defer base.close(allocator, io);
    for ([_][]const u8{ "isolation", "failure", "timeout", "descendant", "exit143", "signal", "exec-missing", "setup-failure", "cleanup-failure" }) |mode| {
        const path = try std.fmt.allocPrint(allocator, "fixture-{s}", .{mode});
        defer allocator.free(path);
        defer base.dir.deleteTree(io, path) catch @panic("native fixture cleanup failed");
        const status_file = try ns.StatusFile.create();
        defer status_file.close();
        const fd_arg = try std.fmt.allocPrint(allocator, "{d}", .{status_file.fd});
        defer allocator.free(fd_arg);
        var outcome: producer.Outcome = .{ .step = .inspect, .child = try c.core.process.run(allocator, io, .{
            .argv = &.{ @import("test_options").namespace_fixture, mode, fd_arg },
            .environment = &map,
            .cwd = base.dir,
            .deadline = try c.core.process.Deadline.afterMilliseconds(if (std.mem.eql(u8, mode, "timeout")) 5000 else 15000),
        }) };
        defer outcome.deinit(allocator);
        outcome.namespaceStatus(status_file.read());
        const result = &outcome.child;
        // A kernel denial or absent status on a normal run is NOT a skip.
        if (!std.mem.eql(u8, mode, "timeout")) try std.testing.expect(result.failures.recording == null);
        try std.testing.expectEqual(!std.mem.eql(u8, mode, "cleanup-failure"), result.cleanup_complete);
        if (std.mem.eql(u8, mode, "failure") or std.mem.eql(u8, mode, "cleanup-failure")) {
            try std.testing.expectEqual(@as(u8, 19), result.termination.?.exited);
            try std.testing.expectEqual(.child_failed, result.failures.primary.?.category);
            if (std.mem.eql(u8, mode, "cleanup-failure"))
                try std.testing.expectEqual(.cleanup_failed, result.failures.cleanup.?.category);
        } else if (std.mem.eql(u8, mode, "exit143")) {
            try std.testing.expectEqual(@as(u8, 143), result.termination.?.exited);
        } else if (std.mem.eql(u8, mode, "signal")) {
            try std.testing.expectEqual(linux.SIG.TERM, result.termination.?.signal);
        } else if (std.mem.eql(u8, mode, "exec-missing")) {
            try std.testing.expect(result.termination == null);
            try std.testing.expectEqual(.spawn_failed, result.failures.primary.?.category);
        } else if (std.mem.eql(u8, mode, "setup-failure")) {
            try std.testing.expect(result.termination == null);
            try std.testing.expectEqual(.unavailable, result.failures.primary.?.category);
        } else if (std.mem.eql(u8, mode, "timeout")) {
            try std.testing.expectEqual(.timeout, result.failures.primary.?.category);
            const ready_path = try std.fmt.allocPrint(allocator, "{s}/.d/zig-migration-preparation/resume-producer/work/scratch/timeout-ready", .{path});
            defer allocator.free(ready_path);
            const ready = try base.dir.openFile(io, ready_path, .{});
            ready.close(io);
        } else {
            try std.testing.expect(result.failures.primary == null);
            try std.testing.expectEqualStrings("namespace-isolation-ok\n", result.stdout);
        }
        if (std.mem.eql(u8, mode, "timeout") or std.mem.eql(u8, mode, "descendant")) {
            const lock_path = try std.fmt.allocPrint(allocator, "{s}/.d/zig-migration-preparation/resume-producer/work/scratch/descendant-lock", .{path});
            defer allocator.free(lock_path);
            const lock = try base.dir.openFile(io, lock_path, .{});
            defer lock.close(io);
            // A detached survivor retains this native flock even after losing
            // its process group and stdout. No PIDs or arbitrary logs needed.
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.flock(lock.handle, 2 | 4)));
        }
    }
}

test "namespace forced parent death before PID 1 registration and bounded status failures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try c.core.process.initialize();
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    for ([_][]const u8{ "parent-death-race", "status-missing", "status-exit143", "status-partial", "status-malformed" }) |mode| {
        const status_file = try ns.StatusFile.create();
        defer status_file.close();
        const arg = try std.fmt.allocPrint(allocator, "{d}", .{status_file.fd});
        defer allocator.free(arg);
        var outcome: producer.Outcome = .{ .step = .inspect, .child = try c.core.process.run(allocator, io, .{
            .argv = &.{ @import("test_options").namespace_fixture, mode, arg },
            .environment = &map,
            .cwd = std.Io.Dir.cwd(),
            .deadline = try c.core.process.Deadline.afterMilliseconds(5000),
        }) };
        defer outcome.deinit(allocator);
        try std.testing.expect(outcome.child.cleanup_complete);
        if (std.mem.eql(u8, mode, "status-exit143"))
            try std.testing.expectEqual(@as(u8, 143), outcome.child.termination.?.exited)
        else
            try std.testing.expect(outcome.child.failures.primary == null);
        outcome.namespaceStatus(status_file.read());
        if (std.mem.eql(u8, mode, "parent-death-race")) {
            try std.testing.expect(outcome.succeeded());
            try std.testing.expectEqualStrings("parent-death-race-ok\n", outcome.child.stdout);
        } else {
            try std.testing.expect(!outcome.succeeded() and outcome.child.termination == null);
            try std.testing.expectEqual(.invalid_response, outcome.child.failures.recording.?.category);
            try std.testing.expectEqual(@as(usize, 0), outcome.child.stdout.len);
        }
    }
}

test "namespace status rejects invalid enums signal ranges inconsistent and oversized records" {
    try std.testing.expectError(error.MissingNamespaceStatus, ns.Status.decode(&.{}));
    const valid = (ns.Status{ .primary = .exited, .code = 143 }).encode();
    try std.testing.expectEqual(@as(u8, 143), (try ns.Status.decode(&valid)).termination().?.exited);
    for (0..valid.len) |length|
        if (length != 0) try std.testing.expectError(error.InvalidNamespaceStatus, ns.Status.decode(valid[0..length]));
    for ([_]usize{ 0, 1, 2, 4, 5, 6, 7 }) |index| {
        var bad = valid;
        bad[index] = 0x80;
        try std.testing.expectError(error.InvalidNamespaceStatus, ns.Status.decode(&bad));
    }
    for ([_]ns.Status{
        .{},
        .{ .primary = .signaled },
        .{ .primary = .signaled, .code = 65 },
        .{ .primary = .setup_failed, .code = 126 },
        .{ .primary = .spawn_failed, .code = 126 },
    }) |bad| try std.testing.expectError(error.InvalidNamespaceStatus, ns.Status.decode(&bad.encode()));
    try std.testing.expectError(error.InvalidNamespaceStatus, ns.Status.decode(&(valid ++ .{0})));
}

test "namespace early publication errors clean only owned names and preserve independent failure lanes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base = try fs.Directory.open(allocator, io, options.workspace);
    defer base.close(allocator, io);
    try base.dir.createDir(io, "resource-cleanup", .fromMode(0o700));
    const dir = try base.dir.openDir(io, "resource-cleanup", .{});
    defer dir.close(io);
    defer base.dir.deleteDir(io, "resource-cleanup") catch @panic("resource fixture cleanup failed");
    try put(io, dir, "unrelated", "must remain\n", 0o600);
    defer dir.deleteFile(io, "unrelated") catch @panic("resource fixture cleanup failed");
    for ([_]enum { early_error, write_failure, request_replaced, request_moved, request_linked, root_moved, root_nonempty, preexisting }{
        .early_error, .write_failure, .request_replaced, .request_moved, .request_linked, .root_moved, .root_nonempty, .preexisting,
    }) |mode| {
        var resources: producer.NamespaceResources = .{ .directory = dir };
        var outcome: producer.Outcome = .{
            .step = .inspect,
            .child = .{
                .storage = try allocator.alloc(u8, 0),
                .failures = .{
                    .primary = .{ .stage = .process_spawn, .category = .spawn_failed },
                    .recording = .{ .stage = .state_record, .category = .local_io },
                },
            },
        };
        defer outcome.deinit(allocator);
        if (mode == .preexisting) {
            try dir.createDir(io, "namespace-root", .fromMode(0o700));
            try put(io, dir, "namespace-request.json", "unowned", 0o600);
            try std.testing.expectError(error.PathAlreadyExists, resources.createRoot(io));
            try std.testing.expectError(error.PathAlreadyExists, resources.publishRequest(io, "not published"));
        } else {
            try resources.createRoot(io);
            if (mode == .write_failure) {
                var old_limit: linux.rlimit = undefined;
                try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getrlimit(.FSIZE, &old_limit)));
                var old_action: linux.Sigaction = undefined;
                var action: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
                try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.sigaction(.XFSZ, &action, &old_action)));
                defer if (linux.errno(linux.sigaction(.XFSZ, &old_action, null)) != .SUCCESS) @panic("restore signal failed");
                const limited: linux.rlimit = .{ .cur = 0, .max = old_limit.max };
                try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.setrlimit(.FSIZE, &limited)));
                defer if (linux.errno(linux.setrlimit(.FSIZE, &old_limit)) != .SUCCESS) @panic("restore file limit failed");
                if (resources.publishRequest(io, "cannot write")) |_| return error.AcceptedFailedWrite else |_| {}
                try std.testing.expect(resources.request != null);
                try std.testing.expectEqual(@as(u64, 0), (try fs.metadata(resources.request.?)).size);
            } else try resources.publishRequest(io, "synthetic request");
            if (mode == .request_replaced) {
                try dir.deleteFile(io, "namespace-request.json");
                try put(io, dir, "namespace-request.json", "replacement", 0o600);
            }
            if (mode == .request_moved or mode == .root_moved) {
                try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.renameat(
                    dir.handle,
                    if (mode == .request_moved) "namespace-request.json" else "namespace-root",
                    dir.handle,
                    "moved",
                )));
            }
            if (mode == .request_linked)
                try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.linkat(dir.handle, "namespace-request.json", dir.handle, "linked", 0)));
            if (mode == .root_nonempty) try put(io, resources.root.?, "retained", "not ours to remove", 0o600);
        }
        resources.cleanup(io, &outcome);
        try std.testing.expectEqual(.spawn_failed, outcome.child.failures.primary.?.category);
        try std.testing.expectEqual(.local_io, outcome.child.failures.recording.?.category);
        if (mode == .request_replaced or mode == .request_moved or mode == .request_linked or mode == .root_moved or mode == .root_nonempty)
            try std.testing.expectEqual(.cleanup_failed, outcome.child.failures.cleanup.?.category)
        else
            try std.testing.expect(outcome.child.failures.cleanup == null);
        if (mode == .request_replaced or mode == .preexisting) {
            const remaining = try dir.openFile(io, "namespace-request.json", .{});
            remaining.close(io);
            try dir.deleteFile(io, "namespace-request.json");
        } else try std.testing.expectError(error.FileNotFound, dir.openFile(io, "namespace-request.json", .{}));
        if (mode == .root_nonempty) try dir.deleteFile(io, "namespace-root/retained");
        if (mode == .root_nonempty or mode == .preexisting)
            try dir.deleteDir(io, "namespace-root")
        else
            try std.testing.expectError(error.FileNotFound, dir.openDir(io, "namespace-root", .{}));
        if (mode == .request_moved) try dir.deleteFile(io, "moved");
        if (mode == .request_linked) try dir.deleteFile(io, "linked");
        if (mode == .root_moved) try dir.deleteDir(io, "moved");
        const unrelated = try dir.openFile(io, "unrelated", .{});
        unrelated.close(io);
    }
}

test "namespace production helper setup status and producer entry compile without root execution" {
    std.testing.refAllDecls(producer);
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try c.core.process.initialize();
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    const status_file = try ns.StatusFile.create();
    defer status_file.close();
    const arg = try std.fmt.allocPrint(allocator, "{d}", .{status_file.fd});
    defer allocator.free(arg);
    const missing = try std.fs.path.join(allocator, &.{ options.workspace, "missing-request.json" });
    defer allocator.free(missing);
    var outcome: producer.Outcome = .{ .step = .inspect, .child = try c.core.process.run(allocator, io, .{
        .argv = &.{ @import("test_options").namespace_helper, missing, &c.digest("missing"), arg },
        .environment = &map,
        .cwd = std.Io.Dir.cwd(),
        .deadline = try c.core.process.Deadline.afterMilliseconds(5000),
    }) };
    defer outcome.deinit(allocator);
    outcome.namespaceStatus(status_file.read());
    try std.testing.expectEqual(@as(u8, 0), outcome.helper_termination.?.exited);
    try std.testing.expect(outcome.child.termination == null);
    try std.testing.expectEqual(.unavailable, outcome.child.failures.primary.?.category);
    try std.testing.expect(outcome.child.failures.recording == null and outcome.child.failures.cleanup == null);
}

test "namespace canonical environment handoff has fixed Git/cache values and no inherited HOME" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const record: env.Record = .{
        .workspace = "/selected/scratch",
        .bison_pkgdatadir = "/reviewed/bison",
        .m4 = "/reviewed/m4",
        .git_exec_path = "/selected/scratch/disabled-git-exec",
        .trust_bundle = "/reviewed/ca.pem",
    };
    const bytes = try c.canonical(allocator, record);
    const parsed = try c.parse(env.Record, allocator, bytes);
    try std.testing.expectEqualStrings("uk.native-preparation-environment.v1", @tagName(parsed.value.schema));
    var map = try record.create(allocator, "/home/canonical");
    defer map.deinit();
    try std.testing.expectEqualStrings("/home/canonical", map.get("HOME").?);
    try std.testing.expectEqualStrings("/selected/scratch/tmp", map.get("TMPDIR").?);
    try std.testing.expectEqualStrings("/selected/scratch/zig-local", map.get("ZIG_LOCAL_CACHE_DIR").?);
    try std.testing.expectEqualStrings("/dev/null", map.get("GIT_CONFIG_GLOBAL").?);
    try std.testing.expectEqualStrings("1", map.get("GIT_NO_REPLACE_OBJECTS").?);
    try std.testing.expect(map.get("LD_LIBRARY_PATH") == null and map.get("SSH_AUTH_SOCK") == null);
    var bad = record;
    bad.workspace = "/selected/../ambient";
    try std.testing.expectError(error.UnsafePath, bad.validate());
}

test "namespace environment loader rejects substitution symlinks public mode and unknown fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const base = try fs.Directory.open(allocator, io, options.workspace);
    defer base.close(allocator, io);
    try base.dir.createDir(io, "environment-loader", .fromMode(0o700));
    defer base.dir.deleteTree(io, "environment-loader") catch {};
    const directory = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ base.path, "environment-loader" }));
    defer directory.close(allocator, io);
    const record: env.Record = .{
        .workspace = "/selected/scratch",
        .bison_pkgdatadir = "/reviewed/bison",
        .m4 = "/reviewed/m4",
        .git_exec_path = "/selected/scratch/disabled-git-exec",
        .trust_bundle = "/reviewed/ca.pem",
    };
    const bytes = try c.canonical(allocator, record);
    try put(io, directory.dir, "record.json", bytes, 0o600);
    const path = try std.fs.path.join(allocator, &.{ directory.path, "record.json" });
    const loaded = try env.load(allocator, io, path, c.digest(bytes));
    try std.testing.expectEqualStrings(record.workspace, loaded.value.workspace);
    try std.testing.expectError(error.HashMismatch, env.load(allocator, io, path, c.digest("substitution")));
    try put(io, directory.dir, "public.json", bytes, 0o644);
    const public_file = try directory.dir.openFile(io, "public.json", .{});
    defer public_file.close(io);
    try public_file.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.UnsafeFile, env.load(allocator, io, try std.fs.path.join(allocator, &.{ directory.path, "public.json" }), c.digest(bytes)));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlinkat("record.json", directory.dir.handle, "link.json")));
    try std.testing.expectError(error.UnsafeFile, env.load(allocator, io, try std.fs.path.join(allocator, &.{ directory.path, "link.json" }), c.digest(bytes)));
    const unknown = try c.canonical(allocator, .{
        .schema = record.schema,
        .workspace = record.workspace,
        .bison_pkgdatadir = record.bison_pkgdatadir,
        .m4 = record.m4,
        .git_exec_path = record.git_exec_path,
        .trust_bundle = record.trust_bundle,
        .arbitrary_environment = "not accepted",
    });
    try put(io, directory.dir, "unknown.json", unknown, 0o600);
    try std.testing.expectError(error.UnexpectedFields, env.load(allocator, io, try std.fs.path.join(allocator, &.{ directory.path, "unknown.json" }), c.digest(unknown)));
}

fn publicGit(allocator: std.mem.Allocator, io: std.Io, workspace: fs.Directory) !rt.Bound {
    const directory = try makeDir(allocator, io, workspace, "git-runtime");
    _ = try makeDir(allocator, io, directory, "bin");
    _ = try makeDir(allocator, io, directory, "lib");
    return rt.TestFixture.copyRuntime(allocator, io, directory, .{
        .executable = options.git_executable,
        .loader = options.git_loader,
        .libraries = options.git_libraries,
    });
}

const FixtureChild = struct {
    pid: linux.pid_t,
    output: linux.fd_t,
    diagnostic: linux.fd_t,

    fn collect(self: FixtureChild, allocator: std.mem.Allocator) !struct { status: ns.Status, stdout: []const u8, stderr: []const u8 } {
        defer _ = linux.close(self.output);
        defer _ = linux.close(self.diagnostic);
        var status: u32 = 0;
        while (true) {
            const result = linux.waitpid(self.pid, &status, 0);
            if (linux.errno(result) == .INTR) continue;
            if (linux.errno(result) != .SUCCESS) return error.FixtureFailed;
            break;
        }
        // Fixed fixture operations emit at most one short line/diagnostic.
        // Reap before draining so the signal test cannot unblock a pending write.
        const stdout = try readPipe(allocator, self.output, 64 * 1024);
        const stderr = try readPipe(allocator, self.diagnostic, 4096);
        return .{
            .status = if (linux.W.IFEXITED(status))
                .{ .primary = .exited, .code = linux.W.EXITSTATUS(status) }
            else if (linux.W.IFSIGNALED(status))
                .{ .primary = .signaled, .code = @intCast(@intFromEnum(linux.W.TERMSIG(status))) }
            else
                return error.FixtureFailed,
            .stdout = stdout,
            .stderr = stderr,
        };
    }
};

fn readPipe(allocator: std.mem.Allocator, fd: linux.fd_t, maximum: usize) ![]const u8 {
    var bytes: std.ArrayList(u8) = .empty;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = linux.read(fd, &buffer, buffer.len);
        if (linux.errno(count) == .INTR) continue;
        if (linux.errno(count) != .SUCCESS) return error.FixtureFailed;
        if (count == 0) return bytes.toOwnedSlice(allocator);
        if (bytes.items.len + count > maximum) return error.FixtureOutputLimit;
        try bytes.appendSlice(allocator, buffer[0..count]);
    }
}

fn spawnFixture(allocator: std.mem.Allocator, argv: []const []const u8, map: *const std.process.Environ.Map, cwd: fs.Directory, stalled: bool) !FixtureChild {
    const pointers = try allocator.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |arg, i| pointers[i] = (try allocator.dupeZ(u8, arg)).ptr;
    const block = try map.createPosixBlock(allocator, .{ .zig_progress_fd = -1 });
    var output: [2]linux.fd_t = undefined;
    var diagnostic: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&output, .{ .CLOEXEC = true })) != .SUCCESS or
        linux.errno(linux.pipe2(&diagnostic, .{ .CLOEXEC = true })) != .SUCCESS) return error.FixtureFailed;
    if (stalled) {
        if (linux.fcntl(output[1], linux.F.SETPIPE_SZ, 4096) != 4096) return error.FixtureFailed;
        const fill = [_]u8{'P'} ** 4096;
        if (linux.write(output[1], &fill, fill.len) != fill.len) return error.FixtureFailed;
    }
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.FixtureFailed;
    if (pid == 0) {
        if (linux.errno(linux.fchdir(cwd.dir.handle)) != .SUCCESS or
            linux.errno(linux.dup3(output[1], 1, 0)) != .SUCCESS or
            linux.errno(linux.dup3(diagnostic[1], 2, 0)) != .SUCCESS or
            linux.errno(linux.close_range(3, std.math.maxInt(linux.fd_t), @bitCast(@as(u32, 0)))) != .SUCCESS) linux.exit_group(124);
        if (stalled) {
            const fd = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd) != .SUCCESS or linux.errno(linux.dup3(@intCast(fd), 100, 0)) != .SUCCESS) linux.exit_group(124);
            _ = linux.close(@intCast(fd));
        }
        _ = linux.execve(pointers[0].?, pointers.ptr, block.slice.ptr);
        linux.exit_group(126);
    }
    _ = linux.close(output[1]);
    _ = linux.close(diagnostic[1]);
    return .{ .pid = @intCast(pid), .output = output[0], .diagnostic = diagnostic[0] };
}

fn setupGit(allocator: std.mem.Allocator, bound: rt.Bound, repository: fs.Directory, map: *const std.process.Environ.Map, args: []const []const u8) ![]const u8 {
    var argv = try bound.prefix(allocator);
    try argv.appendSlice(allocator, &.{ "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-c", "protocol.allow=never" });
    try argv.appendSlice(allocator, args);
    const result = try (try spawnFixture(allocator, argv.items, map, repository, false)).collect(allocator);
    if (result.status.primary != .exited or result.status.code != 0) return error.SyntheticGitSetupFailed;
    return result.stdout;
}

fn gitFixture(allocator: std.mem.Allocator, io: std.Io, mode: []const u8, status_file: ns.StatusFile) !ns.Status {
    if (!std.mem.eql(u8, mode, "git-policy") and !std.mem.eql(u8, mode, "git-unborn") and
        !std.mem.eql(u8, mode, "git-modified") and !std.mem.eql(u8, mode, "git-timeout")) return error.InvalidFixtureMode;
    const base = try fs.Directory.open(allocator, io, options.workspace);
    const repository = try makeDir(allocator, io, base, try std.fmt.allocPrint(allocator, "fixture-{s}", .{mode}));
    try put(io, repository.dir, "tracked.txt", "public synthetic Git fixture\n", 0o600);
    const workspace = try makeDir(allocator, io, repository, ".d/zig-migration-preparation/bridge-git/work");
    const scratch = try makeDir(allocator, io, workspace, "scratch");
    const root = try makeDir(allocator, io, scratch, "namespace-root");
    for ([_][]const u8{ "tmp", "cache", "config", "zig-local", "zig-global", "disabled-git-exec", "disabled-openssl", "empty-template", "poison-home" }) |name|
        _ = try makeDir(allocator, io, scratch, name);
    const helper_dir = try makeDir(allocator, io, workspace, "helper");
    try copy(allocator, io, helper_dir, options.namespace_helper, "preparation-namespace", 0o700);
    const helper = try tool(allocator, io, helper_dir, "preparation-namespace", false);
    const payload_dir = try makeDir(allocator, io, workspace, "payload");
    try copy(allocator, io, payload_dir, "/proc/self/exe", "fixture", 0o700);
    const payload = try tool(allocator, io, payload_dir, "fixture", false);
    const git = try publicGit(allocator, io, workspace);
    const account = try env.Account.current(allocator, io);
    const facade = try facadeDirectory(allocator, io, account);
    const lock = try facade.openFile(io, "build.lock", .private);
    const lock_identity = try ns.Identity.of(try std.fs.path.join(allocator, &.{ facade.path, "build.lock" }), lock);
    const record: env.Record = .{
        .workspace = scratch.path,
        .bison_pkgdatadir = helper_dir.path,
        .m4 = try std.fs.path.join(allocator, &.{ payload_dir.path, "fixture" }),
        .git_exec_path = try std.fs.path.join(allocator, &.{ scratch.path, "disabled-git-exec" }),
        .trust_bundle = try std.fs.path.join(allocator, &.{ repository.path, "tracked.txt" }),
    };
    var clean = try record.create(allocator, account.home);
    var setup = try record.create(allocator, account.home);
    inline for (.{ "AUTHOR", "COMMITTER" }) |kind| {
        try setup.put("GIT_" ++ kind ++ "_NAME", "Synthetic Fixture");
        try setup.put("GIT_" ++ kind ++ "_EMAIL", "synthetic@example.invalid");
        try setup.put("GIT_" ++ kind ++ "_DATE", "2001-01-01T00:00:00Z");
    }
    _ = try setupGit(allocator, git, repository, &setup, &.{
        "init",                                                                              "--quiet", "--initial-branch=main",
        try std.fmt.allocPrint(allocator, "--template={s}/empty-template", .{scratch.path}),
    });
    if (!std.mem.eql(u8, mode, "git-unborn")) {
        _ = try setupGit(allocator, git, repository, &setup, &.{ "add", "--", "tracked.txt" });
        _ = try setupGit(allocator, git, repository, &setup, &.{ "commit", "--quiet", "-m", "public synthetic fixture" });
        try put(io, workspace.dir, "short-head", try setupGit(allocator, git, repository, &clean, &.{ "rev-parse", "--short", "HEAD" }), 0o600);
    }
    if (std.mem.eql(u8, mode, "git-modified")) {
        const file = try repository.dir.openFile(io, "tracked.txt", .{ .mode = .write_only });
        defer file.close(io);
        try file.writePositionalAll(io, "modified synthetic source\n", 0);
    }
    try put(io, workspace.dir, "environment.json", try c.canonical(allocator, record), 0o600);
    const make: env.MakeRecord = .{
        .schema = .unikraft_native_make_environment_v1,
        .bison_data = record.bison_pkgdatadir,
        .m4 = record.m4,
        .shell = record.m4,
        .tmp = clean.get("TMPDIR").?,
        .xdg_cache = clean.get("XDG_CACHE_HOME").?,
        .xdg_config = clean.get("XDG_CONFIG_HOME").?,
        .zig_global_cache = clean.get("ZIG_GLOBAL_CACHE_DIR").?,
        .zig_local_cache = clean.get("ZIG_LOCAL_CACHE_DIR").?,
    };
    try put(io, workspace.dir, "make-environment.json", try c.canonical(allocator, make), 0o600);
    const policy: git_entry.Record = .{
        .schema = .hyperv_native_git_entry_v1,
        .repository = repository.path,
        .runtime_directory = git.directory.path,
        .runtime = git.contract,
        .environment = record,
        .account = account,
    };
    try put(io, workspace.dir, "git-policy.json", try c.canonical(allocator, policy), 0o600);
    try put(io, workspace.dir, "lock.json", try c.canonical(allocator, lock_identity), 0o600);
    try put(io, scratch.dir, "poison-home/.gitconfig", "[core]\nabbrev = 40\n", 0o600);
    try put(io, scratch.dir, "poison-index", "not a Git index\n", 0o600);
    const metadata = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ repository.path, ".git" }));
    const sandbox: ns.Sandbox = .{
        .repository = repository,
        .workspace = workspace,
        .scratch = scratch,
        .runtimes = &.{ helper, payload, git },
        .aliases = &.{ .{ .name = "git", .bound = helper }, .{ .name = "fixture", .bound = payload } },
        .isolation = .{
            .helper = helper,
            .account = account,
            .facade_runtime = facade,
            .facade_lock = lock_identity,
            .git_metadata = &.{.{ .directory = metadata, .tree = (try fs.inventory(allocator, io, metadata, 128, 1024 * 1024)).tree }},
            .environment = try workspace.record(allocator, io, "environment.json", 16 * 1024, .private),
            .make_environment = try workspace.record(allocator, io, "make-environment.json", 64 * 1024, .private),
            .git_policy = try workspace.record(allocator, io, "git-policy.json", git_entry.maximum_bytes, .private),
        },
        .root = try ns.Identity.directory(root),
        .status_file = status_file,
    };
    const serialized = try c.parse(ns.Binding, allocator, try c.canonical(allocator, try ns.describe(allocator, sandbox.isolation)));
    const reopened = try ns.reopen(allocator, io, serialized.value);
    try ns.validate(allocator, io, reopened, repository, workspace);
    if (reopened.make_environment == null or reopened.git_policy == null) return error.FixtureFailed;
    for ([_]c.File{ sandbox.isolation.make_environment.?, sandbox.isolation.git_policy.? }) |file| {
        const opened = try workspace.dir.openFile(io, file.path, .{});
        defer opened.close(io);
        try opened.setPermissions(io, .fromMode(0o644));
        if (ns.validate(allocator, io, sandbox.isolation, repository, workspace)) |_| return error.AcceptedPublicPolicy else |err| if (err != error.UnsafeFile) return err;
        try opened.setPermissions(io, .fromMode(0o600));
    }
    var bad = sandbox;
    bad.isolation.git_policy = null;
    if (ns.enter(allocator, io, bad, &.{"/bin/git"}, &clean)) |_| return error.AcceptedMissingPolicy else |err| if (err != error.MissingGitPolicy) return err;
    bad = sandbox;
    bad.aliases = &.{.{ .name = "git", .bound = git }};
    if (ns.enter(allocator, io, bad, &.{"/bin/git"}, &clean)) |_| return error.AcceptedRealGitAlias else |err| if (err != error.InvalidGitAlias) return err;
    bad = sandbox;
    bad.runtimes = &.{ payload, git };
    if (ns.enter(allocator, io, bad, &.{"/bin/git"}, &clean)) |_| return error.AcceptedMissingHelper else |err| if (err != error.IncompleteRuntime) return err;
    bad.runtimes = &.{ payload, helper };
    if (ns.enter(allocator, io, bad, &.{"/bin/git"}, &clean)) |_| return error.AcceptedMissingGit else |err| if (err != error.IncompleteRuntime) return err;
    const status = try ns.enter(allocator, io, sandbox, &.{ "/bin/fixture", try std.fmt.allocPrint(allocator, "inside-{s}", .{mode}) }, &clean);
    try scratch.dir.deleteDir(io, "namespace-root");
    return status;
}

fn poisonedGitEnvironment(allocator: std.mem.Allocator, record: git_entry.Record) !std.process.Environ.Map {
    var map = std.process.Environ.Map.init(allocator);
    // Model the root facade's clear environment followed by hostile ambient
    // additions. Neither source is a Git policy transport.
    try map.put("PATH", "/bin");
    const poison = try std.fs.path.join(allocator, &.{ record.environment.workspace, "poison-home" });
    try map.put("HOME", poison);
    try map.put("GIT_DIR", poison);
    try map.put("GIT_WORK_TREE", poison);
    try map.put("GIT_INDEX_FILE", try std.fs.path.join(allocator, &.{ record.environment.workspace, "poison-index" }));
    try map.put("GIT_OBJECT_DIRECTORY", poison);
    try map.put("GIT_CONFIG_COUNT", "1");
    try map.put("GIT_CONFIG_KEY_0", "core.abbrev");
    try map.put("GIT_CONFIG_VALUE_0", "40");
    try map.put("GIT_CONFIG_GLOBAL", try std.fs.path.join(allocator, &.{ poison, ".gitconfig" }));
    try map.put("GIT_CONFIG_SYSTEM", map.get("GIT_CONFIG_GLOBAL").?);
    try map.put("LD_LIBRARY_PATH", poison);
    try map.put("LD_PRELOAD", "/missing-public-fixture.so");
    try map.put("LD_DEBUG", "all");
    try map.put("OPENSSL_CONF", "/missing-public-fixture.conf");
    return map;
}

fn insideGit(allocator: std.mem.Allocator, io: std.Io, mode: []const u8) !void {
    const parsed = try git_entry.load(allocator, io);
    const record = parsed.value;
    const workspace = try fs.Directory.open(allocator, io, std.fs.path.dirname(record.environment.workspace).?);
    const scratch = try fs.Directory.open(allocator, io, record.environment.workspace);
    const account = try env.Account.current(allocator, io);
    if (!std.mem.eql(u8, account.home, record.account.home)) return error.AmbientHome;
    const expected_lock = try c.parse(ns.Identity, allocator, try workspace.read(allocator, io, "lock.json", 4096, .private));
    const facade = try fs.Directory.open(allocator, io, std.fs.path.dirname(expected_lock.value.path).?);
    const lock = try facade.openFile(io, "build.lock", .private);
    try expected_lock.value.require(try ns.Identity.of(expected_lock.value.path, lock));
    const make_file = try workspace.record(allocator, io, "make-environment.json", 64 * 1024, .private);
    const make = try env.loadMake(allocator, io, try std.fs.path.join(allocator, &.{ workspace.path, make_file.path }), make_file.sha256);
    if (!std.mem.eql(u8, make.value.tmp, try std.fs.path.join(allocator, &.{ scratch.path, "tmp" }))) return error.FixtureFailed;
    var link: [4096]u8 = undefined;
    const git_link = link[0..try std.Io.Dir.readLinkAbsolute(io, "/bin/git", &link)];
    if (!std.mem.eql(u8, git_link, try std.fs.path.join(allocator, &.{ record.environment.bison_pkgdatadir, "preparation-namespace" })))
        return error.RealGitAlias;
    for ([_][]const u8{
        git_entry.policy_path,
        try std.fs.path.join(allocator, &.{ workspace.path, "git-policy.json" }),
        try std.fs.path.join(allocator, &.{ workspace.path, "make-environment.json" }),
        try std.fs.path.join(allocator, &.{ workspace.path, "environment.json" }),
        try std.fs.path.join(allocator, &.{ record.runtime_directory, "bin/git" }),
        git_link,
    }) |path| {
        const file = std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .write_only }) catch |err| switch (err) {
            error.ReadOnlyFileSystem => continue,
            else => return err,
        };
        file.close(io);
        return error.WritableInput;
    }
    for ([_][]const u8{ record.runtime_directory, record.environment.bison_pkgdatadir }) |path| {
        const directory = try std.Io.Dir.openDirAbsolute(io, path, .{});
        defer directory.close(io);
        directory.createDir(io, "not-created", .fromMode(0o700)) catch |err| switch (err) {
            error.ReadOnlyFileSystem => continue,
            else => return err,
        };
        return error.WritableRuntime;
    }
    var poison = try poisonedGitEnvironment(allocator, record);
    var stripped = std.process.Environ.Map.init(allocator);
    const unborn = std.mem.eql(u8, mode, "inside-git-unborn");
    for ([_]*const std.process.Environ.Map{ &stripped, &poison }) |map| {
        const head = try (try spawnFixture(allocator, &.{ "/bin/git", "rev-parse", "--short", "HEAD" }, map, scratch, false)).collect(allocator);
        if (head.status.primary != .exited or head.status.code != (if (unborn) @as(u8, 128) else 0) or head.stderr.len != 0)
            return error.GitStatusMismatch;
        const expected = if (unborn) "" else try workspace.read(allocator, io, "short-head", 128, .private);
        if (!std.mem.eql(u8, head.stdout, expected)) return error.GitHeadMismatch;
        const modified = try (try spawnFixture(allocator, &.{ "/bin/git", "ls-files", "-m" }, map, scratch, false)).collect(allocator);
        if (modified.status.primary != .exited or modified.status.code != 0 or modified.stderr.len != 0 or
            !std.mem.eql(u8, modified.stdout, if (std.mem.eql(u8, mode, "inside-git-modified")) "tracked.txt\n" else ""))
            return error.GitIndexMismatch;
    }
    if (!unborn) try inspectBlockedGit(allocator, io, record, scratch, &poison, std.mem.eql(u8, mode, "inside-git-timeout"));
    const invalid: []const []const []const u8 = &.{
        &.{},                                                         &.{"--version"},                             &.{ "rev-parse", "HEAD" },                             &.{ "rev-parse", "--short=12", "HEAD" },
        &.{ "rev-parse", "--short", "HEAD", "--git-dir" },            &.{ "ls-files", "-m", "--", "tracked.txt" }, &.{ "ls-files", "--modified" },                        &.{ "-C", "/", "ls-files", "-m" },
        &.{ "-c", "core.abbrev=40", "rev-parse", "--short", "HEAD" }, &.{ "remote", "-v" },                        &.{ "fetch", "https://public.invalid/not-contacted" }, &.{ "help", "rev-parse" },
    };
    for (invalid) |args| {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(allocator, "/bin/git");
        try argv.appendSlice(allocator, args);
        const result = try (try spawnFixture(allocator, argv.items, &poison, scratch, false)).collect(allocator);
        if (result.status.primary != .exited or result.status.code != 125 or result.stdout.len != 0 or result.stderr.len > 1024)
            return error.AcceptedGitOperation;
        const document = try c.c.Document.parse(allocator, std.mem.trimEnd(u8, result.stderr, "\n"), .{});
        const diagnostic = try c.core.diagnostics.Failures.parse(document.value());
        if (diagnostic.primary == null or diagnostic.primary.?.category != .invalid_input or
            diagnostic.cleanup != null or diagnostic.recording != null) return error.UnboundedGitDiagnostic;
    }
    try expected_lock.value.require(try ns.Identity.of(expected_lock.value.path, lock));
    _ = linux.write(1, "namespace-git-policy-ok\n", "namespace-git-policy-ok\n".len);
}

fn inspectBlockedGit(allocator: std.mem.Allocator, io: std.Io, record: git_entry.Record, scratch: fs.Directory, poison: *const std.process.Environ.Map, timeout: bool) !void {
    const child = try spawnFixture(allocator, &.{ "/bin/git", "rev-parse", "--short", "HEAD" }, poison, scratch, true);
    const proc = try std.fmt.allocPrint(allocator, "/proc/{d}", .{child.pid});
    const executable = try std.fs.path.join(allocator, &.{ record.runtime_directory, "lib/loader" });
    var link: [4096]u8 = undefined;
    var observed = false;
    for (0..5000) |_| {
        const actual = link[0..try std.Io.Dir.readLinkAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "exe" }), &link)];
        if (std.mem.eql(u8, actual, executable)) {
            const syscall = try std.Io.Dir.openFileAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "syscall" }), .{});
            defer syscall.close(io);
            var state: [512]u8 = undefined;
            const length = linux.read(syscall.handle, &state, state.len);
            switch (linux.errno(length)) {
                .SUCCESS => {
                    var fields = std.mem.tokenizeScalar(u8, state[0..length], ' ');
                    const number = std.fmt.parseInt(usize, fields.next() orelse "", 10) catch 0;
                    const descriptor = std.fmt.parseInt(usize, fields.next() orelse "", 0) catch 0;
                    if (number == @intFromEnum(linux.SYS.write) and descriptor == 1) {
                        observed = true;
                        break;
                    }
                },
                .AGAIN, .INTR => {},
                else => return error.FixtureFailed,
            }
        }
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    if (!observed) return error.GitExecNotObserved;
    // A full stdout pipe holds the actual native Git at its write, not a fake
    // runtime or a wrapper supervisor. Inspect only our public synthetic child.
    const file = try std.Io.Dir.openFileAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "environ" }), .{});
    defer file.close(io);
    var bytes: [32768]u8 = undefined;
    const length = try file.readPositionalAll(io, &bytes, 0);
    var actual = std.process.Environ.Map.init(allocator);
    var entries = std.mem.splitScalar(u8, bytes[0..length], 0);
    while (entries.next()) |entry| {
        if (entry.len == 0) continue;
        const split = std.mem.indexOfScalar(u8, entry, '=') orelse return error.FixtureFailed;
        if (actual.get(entry[0..split]) != null) return error.AmbientEnvironment;
        try actual.put(entry[0..split], entry[split + 1 ..]);
    }
    var expected = try record.environment.create(allocator, record.account.home);
    if (actual.count() != expected.count()) return error.AmbientEnvironment;
    var it = expected.iterator();
    while (it.next()) |entry|
        if (!std.mem.eql(u8, actual.get(entry.key_ptr.*) orelse return error.AmbientEnvironment, entry.value_ptr.*))
            return error.AmbientEnvironment;
    const cwd = link[0..try std.Io.Dir.readLinkAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "cwd" }), &link)];
    if (!std.mem.eql(u8, cwd, record.repository)) return error.AmbientRepository;
    if (std.Io.Dir.openFileAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "fd/100" }), .{})) |leaked| {
        leaked.close(io);
        return error.InheritedDescriptor;
    } else |err| if (err != error.FileNotFound) return err;
    const descriptors = try std.Io.Dir.openDirAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "fd" }), .{ .iterate = true });
    defer descriptors.close(io);
    var fds = descriptors.iterate();
    while (try fds.next(io)) |entry|
        if (try std.fmt.parseInt(usize, entry.name, 10) > 2) return error.InheritedDescriptor;
    const stderr = link[0..try std.Io.Dir.readLinkAbsolute(io, try std.fs.path.join(allocator, &.{ proc, "fd/2" }), &link)];
    if (!std.mem.eql(u8, stderr, "/dev/null")) return error.RawGitDiagnostic;
    if (timeout) {
        try put(io, scratch.dir, "timeout-ready", "native Git blocked on stdout\n", 0o600);
        _ = try child.collect(allocator);
        return error.GitUnexpectedCompletion;
    }
    if (linux.errno(linux.kill(child.pid, .TERM)) != .SUCCESS) return error.FixtureFailed;
    const result = try child.collect(allocator);
    if (result.status.primary != .signaled or result.status.code != @intFromEnum(linux.SIG.TERM) or
        result.stderr.len != 0 or result.stdout.len != 4096) return error.GitSignalMismatch;
}

test "namespace Git actual static dispatch restores stripped and poisoned policy with native status" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try c.core.process.initialize();
    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();
    const base = try fs.Directory.open(allocator, io, options.workspace);
    defer base.close(allocator, io);
    for ([_][]const u8{ "git-policy", "git-unborn", "git-modified", "git-timeout" }) |mode| {
        const path = try std.fmt.allocPrint(allocator, "fixture-{s}", .{mode});
        defer allocator.free(path);
        defer base.dir.deleteTree(io, path) catch @panic("Git namespace fixture cleanup failed");
        const status_file = try ns.StatusFile.create();
        defer status_file.close();
        const arg = try std.fmt.allocPrint(allocator, "{d}", .{status_file.fd});
        defer allocator.free(arg);
        var outcome: producer.Outcome = .{ .step = .inspect, .child = try c.core.process.run(allocator, io, .{
            .argv = &.{ @import("test_options").namespace_fixture, mode, arg },
            .environment = &map,
            .cwd = base.dir,
            .deadline = try c.core.process.Deadline.afterMilliseconds(if (std.mem.eql(u8, mode, "git-timeout")) 5000 else 30000),
            .stdout_limit = 4096,
            .stderr_limit = 4096,
        }) };
        defer outcome.deinit(allocator);
        outcome.namespaceStatus(status_file.read());
        if (std.mem.eql(u8, mode, "git-timeout")) {
            try std.testing.expectEqual(.timeout, outcome.child.failures.primary.?.category);
            try std.testing.expect(outcome.child.cleanup_complete and outcome.child.failures.cleanup == null);
            const scratch_path = try std.fmt.allocPrint(allocator, "{s}/.d/zig-migration-preparation/bridge-git/work/scratch", .{path});
            defer allocator.free(scratch_path);
            const scratch = try base.dir.openDir(io, scratch_path, .{});
            defer scratch.close(io);
            const ready = try scratch.openFile(io, "timeout-ready", .{});
            ready.close(io);
            const root = try scratch.openDir(io, "namespace-root", .{ .iterate = true });
            defer root.close(io);
            var entries = root.iterate();
            try std.testing.expect(try entries.next(io) == null);
            continue;
        }
        if (!outcome.succeeded()) std.debug.print("Git fixture {s}: {any}, {any}\n", .{ mode, outcome.child.termination, outcome.child.failures });
        try std.testing.expect(outcome.succeeded());
        try std.testing.expectEqualStrings("namespace-git-policy-ok\n", outcome.child.stdout);
    }
}

test "namespace Git policy exact canonical schema has no command or environment fallback" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const executable: c.File = .{ .path = "bin/git", .sha256 = c.digest("public fixture"), .size = 1, .mode = 0o700 };
    const record: git_entry.Record = .{
        .schema = .hyperv_native_git_entry_v1,
        .repository = "/selected/repository",
        .runtime_directory = "/selected/runtime",
        .runtime = .{
            .role = .git,
            .origin = .{
                .scheme = .authenticated_distribution,
                .revision = "synthetic",
                .source_sha256 = c.digest("public fixture"),
                .producer_sha256 = c.digest("public fixture"),
            },
            .target = .aarch64_linux,
            .tree = .{ .sha256 = c.digest("public fixture"), .files = 3, .bytes = 3 },
            .executable = executable,
            .loader = .{ .path = "lib/loader", .sha256 = executable.sha256, .size = 1, .mode = 0o700 },
            .libraries = &.{.{ .path = "lib/libc.so.6", .sha256 = executable.sha256, .size = 1, .mode = 0o600 }},
        },
        .environment = .{
            .workspace = "/selected/scratch",
            .bison_pkgdatadir = "/selected/bison",
            .m4 = "/selected/m4",
            .git_exec_path = "/selected/scratch/disabled-git-exec",
            .trust_bundle = "/selected/ca.pem",
        },
        .account = .{ .name = "synthetic", .uid = 1000, .gid = 1000, .home = "/home/synthetic" },
    };
    const bytes = try c.canonical(allocator, record);
    const parsed = try git_entry.parse(allocator, bytes);
    try std.testing.expectEqualStrings("hyperv_native_git_entry_v1", @tagName(parsed.value.schema));
    try std.testing.expectEqualStrings(record.account.home, parsed.value.account.home);
    try std.testing.expectEqualStrings("/etc/unikraft-preparation-git.json", git_entry.policy_path);
    for ([_][]const u8{ "repository", "runtime_directory" }) |field| {
        var document = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
        try document.value.object.put(allocator, field, .{ .string = "/selected/../unbound" });
        try std.testing.expectError(error.UnsafePath, git_entry.parse(allocator, try c.canonical(allocator, document.value)));
    }
    for ([_][]const u8{ "command", "argv", "policy_path", "inherited_environment" }) |field| {
        var document = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
        try document.value.object.put(allocator, field, .{ .string = "not accepted" });
        if (git_entry.parse(allocator, try c.canonical(allocator, document.value))) |_| return error.AcceptedUnknownField else |_| {}
    }
    for ([_][]const u8{ "repository", "runtime_directory", "runtime", "environment", "account", "schema" }) |field| {
        var document = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always });
        _ = document.value.object.orderedRemove(field);
        if (git_entry.parse(allocator, try c.canonical(allocator, document.value))) |_| return error.AcceptedMissingField else |_| {}
    }
    const duplicate = try std.mem.concat(allocator, u8, &.{ bytes[0 .. bytes.len - 1], ",\"repository\":\"/other\"}" });
    if (git_entry.parse(allocator, duplicate)) |_| return error.AcceptedDuplicateField else |_| {}
    if (git_entry.parse(allocator, try std.mem.concat(allocator, u8, &.{ bytes, "\n" }))) |_| return error.AcceptedNoncanonicalPolicy else |_| {}
    var wrong = record;
    wrong.runtime.role = .preparation;
    try std.testing.expectError(error.InvalidRuntime, git_entry.parse(allocator, try c.canonical(allocator, wrong)));
    wrong = record;
    wrong.account.home = "/home/../unbound";
    try std.testing.expectError(error.UnsafePath, git_entry.parse(allocator, try c.canonical(allocator, wrong)));
}
