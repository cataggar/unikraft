// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
const files = @import("hyperv_core").private_files;
const process = @import("hyperv_core").process;
const options = @import("test_options");
const limits = @import("custody_limits.zig");
const source = @import("source_custody.zig");
const a = std.testing.allocator;
const io = std.testing.io;

const inventory_args = &[_][]const u8{
    "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z",
};
const output_ignore =
    "/.d/\n/.zig-cache/\n/support/apps/wamr-aot/.config\n/support/apps/wamr-aot/build/\n";

test "Git custody remains bounded and reports static supervised failure classes" {
    try std.testing.expectEqual(@as(u64, 120_000), source.git_probe_deadline_ms);
    var empty: [0]u8 = .{};
    var result: process.CommandResult = .{
        .storage = &empty,
        .started_ns = 0,
        .primary_completed_ns = 0,
        .completed_ns = 0,
        .executable = undefined,
        .primary = .timeout,
        .primary_deadline_reached = true,
    };
    try std.testing.expectError(error.GitTimedOut, source.requireGitOutcome(result, 2));
    result.primary_deadline_reached = false;
    result.primary = .output_overflow;
    try std.testing.expectError(error.GitOutputOverflow, source.requireGitOutcome(result, 2));
    result.primary = .{ .signal = .KILL };
    try std.testing.expectError(error.GitSignaled, source.requireGitOutcome(result, 2));
    result.primary = .{ .exited = 1 };
    try std.testing.expectError(error.GitExited, source.requireGitOutcome(result, 2));
    result.primary = .local_io;
    try std.testing.expectError(error.GitStartupIo, source.requireGitOutcome(result, 2));
    result.primary_events = 1;
    try std.testing.expectError(error.GitMonitorIo, source.requireGitOutcome(result, 2));
    result.stdout_status = .io_failed;
    try std.testing.expectError(error.GitStdoutIo, source.requireGitOutcome(result, 2));
    result.stdout_status = .incomplete;
    result.stderr_status = .io_failed;
    try std.testing.expectError(error.GitStderrIo, source.requireGitOutcome(result, 2));
    result.stderr_status = .incomplete;
    result.primary = .event_limit;
    try std.testing.expectError(error.GitEventLimit, source.requireGitOutcome(result, 2));
    result.primary = .{ .exited = 0 };
    try std.testing.expectError(error.GitCleanupIncomplete, source.requireGitOutcome(result, 2));
    result.cleanup = .deadline;
    try std.testing.expectError(error.GitCleanupTimedOut, source.requireGitOutcome(result, 2));
    result.cleanup = .event_limit;
    try std.testing.expectError(error.GitCleanupEventLimit, source.requireGitOutcome(result, 2));
    result.cleanup = .complete;
    result.descendants.limit_exceeded = true;
    try std.testing.expectError(error.GitDescendantLimit, source.requireGitOutcome(result, 2));
    result.descendants.limit_exceeded = false;
    try std.testing.expectError(error.GitStreamIncomplete, source.requireGitOutcome(result, 2));
    result.stdout_status = .complete;
    result.stderr_status = .complete;
    result.stderr = "diagnostic content remains private";
    try std.testing.expectError(error.GitDiagnostic, source.requireGitOutcome(result, 2));
    result.stderr = "";
    result.stdout = "abc";
    try std.testing.expectError(error.GitOutputOverflow, source.requireGitOutcome(result, 2));
    try source.requireGitOutcome(result, 3);
}

fn write(dir: std.Io.Dir, name: []const u8, contents: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
}

fn sparse(dir: std.Io.Dir, name: []const u8, bytes: usize) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    if (linux.errno(linux.ftruncate(file.handle, @intCast(bytes))) != .SUCCESS)
        return error.SparseFixtureFailed;
    try std.testing.expectEqual(bytes, (try file.stat(io)).size);
}

fn resize(dir: std.Io.Dir, name: []const u8, bytes: usize) !void {
    const file = try dir.openFile(io, name, .{ .mode = .write_only });
    defer file.close(io);
    if (linux.errno(linux.ftruncate(file.handle, @intCast(bytes))) != .SUCCESS)
        return error.SparseFixtureFailed;
}

fn openFixtureRoot(parent: []const u8) !std.Io.Dir {
    if (parent.len <= 1 or !std.fs.path.isAbsolute(parent) or
        parent[parent.len - 1] == '/')
        return error.UnsafeFixtureRoot;
    const canonical = std.Io.Dir.realPathFileAbsoluteAlloc(io, parent, a) catch |err| switch (err) {
        error.FileNotFound => return error.FixtureRootUnavailable,
        else => return err,
    };
    defer a.free(canonical);
    if (!std.mem.eql(u8, canonical, parent)) return error.UnsafeFixtureRoot;
    const repository = try std.Io.Dir.realPathFileAbsoluteAlloc(io, options.repository_root, a);
    defer a.free(repository);
    if (std.mem.eql(u8, parent, repository) or
        (std.mem.startsWith(u8, parent, repository) and
            parent.len > repository.len and parent[repository.len] == '/'))
        return error.UnsafeFixtureRoot;
    return files.openDirectory(io, parent, .private) catch |err| switch (err) {
        error.FileNotFound => return error.FixtureRootUnavailable,
        error.UnsafeFile, error.UnsafePath, error.SymLinkLoop => return error.UnsafeFixtureRoot,
        else => return err,
    };
}

const Fixture = struct {
    cache: std.Io.Dir,
    root: std.Io.Dir,
    name: []u8,
    path: []u8,
    git: []u8,

    fn init(label: []const u8) !Fixture {
        const parent = options.fixture_root;
        const cache = try openFixtureRoot(parent);
        errdefer cache.close(io);
        const name = try std.fmt.allocPrint(a, "source-custody-limits-{s}-{d}", .{ label, linux.getpid() });
        errdefer a.free(name);
        try cache.createDir(io, name, .fromMode(0o700));
        errdefer cache.deleteTree(io, name) catch {};
        const root = try cache.openDir(io, name, .{ .iterate = true });
        errdefer root.close(io);
        const path = try std.fs.path.join(a, &.{ parent, name });
        errdefer a.free(path);
        const which = try std.process.run(a, io, .{
            .argv = &.{ "which", "git" },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(which.stdout);
        defer a.free(which.stderr);
        if (which.term != .exited or which.term.exited != 0) return error.GitUnavailable;
        const git = try a.dupe(u8, std.mem.trimEnd(u8, which.stdout, "\r\n"));
        errdefer a.free(git);
        if (!std.fs.path.isAbsolute(git)) return error.GitUnavailable;
        return .{ .cache = cache, .root = root, .name = name, .path = path, .git = git };
    }

    fn deinit(self: *Fixture) void {
        self.root.close(io);
        self.cache.deleteTree(io, self.name) catch @panic("source custody fixture cleanup failed");
        self.cache.close(io);
        a.free(self.git);
        a.free(self.path);
        a.free(self.name);
    }
};

const Repo = struct {
    fixture: *Fixture,
    dir: std.Io.Dir,
    path: []u8,

    fn init(fixture: *Fixture, name: []const u8, ignore: []const u8) !Repo {
        try fixture.root.createDir(io, name, .fromMode(0o700));
        const dir = try fixture.root.openDir(io, name, .{ .iterate = true });
        errdefer dir.close(io);
        const path = try std.fs.path.join(a, &.{ fixture.path, name });
        errdefer a.free(path);
        const repo: Repo = .{ .fixture = fixture, .dir = dir, .path = path };
        try write(dir, ".gitignore", ignore);
        try repo.git(&.{ "init", "-q" });
        try repo.git(&.{ "add", ".gitignore" });
        try repo.commit();
        return repo;
    }

    fn deinit(self: *Repo) void {
        self.dir.close(io);
        a.free(self.path);
    }

    fn gitOutput(self: Repo, args: []const []const u8, maximum: usize) ![]u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(a);
        try argv.appendSlice(a, &.{ self.fixture.git, "-c", "gc.auto=0", "-c", "maintenance.auto=false" });
        try argv.appendSlice(a, args);
        const result = try std.process.run(a, io, .{
            .argv = argv.items,
            .cwd = .{ .path = self.path },
            .stdout_limit = .limited(maximum),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0) {
            a.free(result.stdout);
            return error.FixtureGitFailed;
        }
        return result.stdout;
    }

    fn git(self: Repo, args: []const []const u8) !void {
        const output = try self.gitOutput(args, 4096);
        defer a.free(output);
    }

    fn commit(self: Repo) !void {
        try self.git(&.{
            "-c",     "user.name=Fixture", "-c",      "user.email=fixture@example.invalid",
            "commit", "-qm",               "fixture",
        });
    }

    fn withOutputs(fixture: *Fixture, name: []const u8, ignore: []const u8) !Repo {
        var repo = try Repo.init(fixture, name, ignore);
        errdefer repo.deinit();
        try repo.dir.createDir(io, "support", .fromMode(0o700));
        const support = try repo.dir.openDir(io, "support", .{ .iterate = true });
        defer support.close(io);
        try support.createDir(io, "apps", .fromMode(0o700));
        const apps = try support.openDir(io, "apps", .{ .iterate = true });
        defer apps.close(io);
        try apps.createDir(io, "wamr-aot", .fromMode(0o700));
        const app = try apps.openDir(io, "wamr-aot", .{ .iterate = true });
        defer app.close(io);
        try write(app, "defconfig", "CONFIG_FIXTURE=y\n");
        try repo.git(&.{ "add", "support/apps/wamr-aot/defconfig" });
        try repo.commit();
        try repo.dir.createDir(io, ".d", .fromMode(0o700));
        try repo.dir.createDir(io, ".zig-cache", .fromMode(0o700));
        try app.createDir(io, "build", .fromMode(0o700));
        try write(app, ".config", "");
        return repo;
    }
};

fn checkSource(repo: Repo, expected_files: usize, expected_bytes: usize) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const result = try source.source(arena.allocator(), io, repo.path, repo.fixture.git);
    try std.testing.expectEqual(expected_files, result.custody.files);
    try std.testing.expectEqual(expected_bytes, result.custody.bytes);
}

fn refuseSource(repo: Repo, expected: anyerror) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectError(expected, source.source(arena.allocator(), io, repo.path, repo.fixture.git));
}

test "two real Git source captures agree until tracked physical metadata changes" {
    var fixture = try Fixture.init("source-recapture");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "stable", output_ignore);
    defer repo.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const before = try source.source(arena.allocator(), io, repo.path, repo.fixture.git);
    const unchanged = try source.source(arena.allocator(), io, repo.path, repo.fixture.git);
    try std.testing.expect(before.same(unchanged));

    const file = try repo.dir.openFile(io, "support/apps/wamr-aot/defconfig", .{});
    defer file.close(io);
    if (linux.errno(linux.fchmod(file.handle, 0o640)) != .SUCCESS)
        return error.ChmodFixtureFailed;
    const changed = try source.source(arena.allocator(), io, repo.path, repo.fixture.git);
    try std.testing.expect(!before.same(changed));
}

fn addIgnored(repo: Repo, path: []const u8) !void {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/').?;
    try repo.dir.createDirPath(io, path[0..slash]);
    try write(repo.dir, path, "");
}

fn boundaryPath(parts: usize, size: usize) ![]u8 {
    var components = try a.alloc([]u8, parts);
    defer a.free(components);
    components[0] = try a.dupe(u8, ".d");
    defer a.free(components[0]);
    for (components[1 .. parts - 1]) |*component| component.* = try a.dupe(u8, "d");
    defer for (components[1 .. parts - 1]) |component| a.free(component);
    components[parts - 1] = try a.dupe(u8, "x.ignored");
    defer a.free(components[parts - 1]);
    var length: usize = parts - 1;
    for (components) |component| length += component.len;
    if (length > size) return error.InvalidFixture;
    var remainder = size - length;
    for (components[1 .. parts - 1]) |*component| {
        const count = @min(remainder, 255 - component.*.len);
        const grown = try a.alloc(u8, component.*.len + count);
        @memcpy(grown[0..component.*.len], component.*);
        @memset(grown[component.*.len..], 'x');
        a.free(component.*);
        component.* = grown;
        remainder -= count;
    }
    if (remainder != 0) return error.InvalidFixture;
    const path = try std.mem.join(a, "/", components);
    try std.testing.expectEqual(size, path.len);
    return path;
}

test "fixture parent rejects missing, noncanonical, source-tree and nonprivate roots" {
    const safe = try openFixtureRoot(options.fixture_root);
    defer safe.close(io);
    try std.testing.expectError(error.UnsafeFixtureRoot, openFixtureRoot(options.repository_root));
    const noncanonical = try std.fmt.allocPrint(a, "{s}/.", .{options.fixture_root});
    defer a.free(noncanonical);
    try std.testing.expectError(error.UnsafeFixtureRoot, openFixtureRoot(noncanonical));
    const name = try std.fmt.allocPrint(a, "source-custody-unsafe-{d}", .{linux.getpid()});
    defer a.free(name);
    const missing = try std.fs.path.join(a, &.{ options.fixture_root, name });
    defer a.free(missing);
    try std.testing.expectError(error.FixtureRootUnavailable, openFixtureRoot(missing));
    try safe.createDir(io, name, .fromMode(0o755));
    defer safe.deleteTree(io, name) catch @panic("unsafe fixture cleanup failed");
    // The managed CI umask would otherwise turn the requested 0755 into 0700.
    const terminated = try a.dupeZ(u8, name);
    defer a.free(terminated);
    if (linux.errno(linux.fchmodat(safe.handle, terminated, 0o755)) != .SUCCESS)
        return error.ChmodFixtureFailed;
    try std.testing.expectError(error.UnsafeFixtureRoot, openFixtureRoot(missing));
}

test "production source limits are frozen and tracked counters accept only the exact maximum" {
    try std.testing.expectEqual(@as(usize, 40_000), limits.tracked_entries);
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024 * 1024), limits.tracked_bytes);
    try std.testing.expectEqual(@as(usize, 256 * 1024 * 1024), limits.tracked_file);
    try std.testing.expectEqual(@as(usize, 131_072), limits.ignored_entries);
    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024 * 1024), limits.ignored_bytes);
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), limits.ignored_file);
    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024), limits.ignored_git_output);
    try std.testing.expectEqual(@as(usize, 1024), limits.ignored_path);
    try std.testing.expectEqual(@as(usize, 64), limits.ignored_depth);
    try std.testing.expectEqual(@as(usize, 128), limits.diagnostic_root);
    try std.testing.expectEqual(@as(usize, 4), limits.roles.len);
    for ([_]struct { maximum: usize, amount: usize }{
        .{ .maximum = limits.tracked_entries, .amount = 1 },
        .{ .maximum = limits.tracked_bytes, .amount = limits.tracked_file },
        .{ .maximum = limits.ignored_entries, .amount = 1 },
        .{ .maximum = limits.ignored_bytes, .amount = limits.ignored_file },
    }) |bound| {
        var count = bound.maximum - bound.amount;
        try limits.addBounded(&count, bound.amount, bound.maximum);
        try std.testing.expectEqual(bound.maximum, count);
        try std.testing.expectError(error.LimitExceeded, limits.addBounded(&count, 1, bound.maximum));
    }
    try std.testing.expectEqual(@as(usize, 0), try limits.outputRole(".d/accepted"));
    try std.testing.expectError(error.IgnoredOutsideOutput, limits.outputRole(".d-sibling/ignored"));
    try std.testing.expectError(error.IgnoredOutsideOutput, limits.outputRole("support/apps/wamr-aot/build-sibling/ignored"));
}

test "real ignored source enumeration accepts 131072 entries and 8 GiB, refuses first excess" {
    var fixture = try Fixture.init("ignored-count-bytes");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "ignored", output_ignore);
    defer repo.deinit();
    const build = try repo.dir.openDir(io, "support/apps/wamr-aot/build", .{ .iterate = true });
    defer build.close(io);
    const sparse_count = limits.ignored_bytes / limits.ignored_file;
    try std.testing.expectEqual(@as(usize, 0), limits.ignored_bytes % limits.ignored_file);
    for (0..limits.ignored_entries - limits.roles.len) |i| {
        const name = try std.fmt.allocPrint(a, "entry-{x:0>6}", .{i});
        defer a.free(name);
        try sparse(build, name, if (i < sparse_count) limits.ignored_file else 0);
    }
    try checkSource(repo, 2, output_ignore.len + "CONFIG_FIXTURE=y\n".len);
    try resize(build, "entry-000010", 1);
    try refuseSource(repo, error.LimitExceeded);
    try resize(build, "entry-000010", 0);
    const extra = try std.fmt.allocPrint(a, "entry-{x:0>6}", .{limits.ignored_entries - limits.roles.len});
    defer a.free(extra);
    try sparse(build, extra, 0);
    try refuseSource(repo, error.LimitExceeded);
}

test "real ignored file accepts 512 MiB and refuses its first excess byte" {
    var fixture = try Fixture.init("ignored-file");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "ignored", output_ignore);
    defer repo.deinit();
    const build = try repo.dir.openDir(io, "support/apps/wamr-aot/build", .{ .iterate = true });
    defer build.close(io);
    try sparse(build, "large", limits.ignored_file);
    try checkSource(repo, 2, output_ignore.len + "CONFIG_FIXTURE=y\n".len);
    try resize(build, "large", limits.ignored_file + 1);
    try refuseSource(repo, error.UnsafeIgnoredEntry);
}

test "real ignored Git inventory accepts eight MiB and refuses the next byte" {
    var fixture = try Fixture.init("git-inventory");
    defer fixture.deinit();
    var repo = try Repo.init(&fixture, "inventory", "*.ignored\n");
    defer repo.deinit();
    var relative: std.ArrayList(u8) = .empty;
    defer relative.deinit(a);
    try relative.appendSlice(a, ".d");
    var directory_bytes: usize = relative.items.len + 2;
    for ([_]struct { byte: u8, count: usize }{
        .{ .byte = 'a', .count = 191 },
        .{ .byte = 'b', .count = 190 },
        .{ .byte = 'c', .count = 190 },
        .{ .byte = 'd', .count = 182 },
    }) |component| {
        try relative.append(a, '/');
        try relative.appendNTimes(a, component.byte, component.count);
        directory_bytes += relative.items.len + 2;
    }
    try repo.dir.createDirPath(io, relative.items);
    const directory = try repo.dir.openDir(io, relative.items, .{ .iterate = true });
    defer directory.close(io);
    const prefix_bytes = relative.items.len + 1;
    const record_bytes = prefix_bytes + 255 + 1;
    const available = limits.ignored_git_output - directory_bytes;
    const full_count = available / record_bytes - 1;
    const tail = available % record_bytes + record_bytes;
    try std.testing.expectEqual(@as(usize, 0), tail % 2);
    const short_length = tail / 2 - prefix_bytes - 1;
    try std.testing.expect(short_length >= "short-0-.ignored".len and short_length < 255);
    for (0..full_count) |i| {
        const name = try a.alloc(u8, 255);
        defer a.free(name);
        const number = try std.fmt.allocPrint(a, "{x:0>4}", .{i});
        defer a.free(number);
        @memcpy(name[0..number.len], number);
        @memset(name[number.len .. 255 - ".ignored".len], 'x');
        @memcpy(name[255 - ".ignored".len ..], ".ignored");
        try write(directory, name, "");
    }
    var short_names: [2][]u8 = undefined;
    for (&short_names, 0..) |*name, index| {
        name.* = try a.alloc(u8, short_length);
        const prefix = try std.fmt.allocPrint(a, "short-{d}-", .{index});
        defer a.free(prefix);
        @memcpy(name.*[0..prefix.len], prefix);
        @memset(name.*[prefix.len .. short_length - ".ignored".len], 'y');
        @memcpy(name.*[short_length - ".ignored".len ..], ".ignored");
        try write(directory, name.*, "");
    }
    defer for (short_names) |name| a.free(name);
    const inventory = try repo.gitOutput(inventory_args, limits.ignored_git_output + 1);
    defer a.free(inventory);
    try std.testing.expectEqual(limits.ignored_git_output, inventory.len);
    const exact = try source.gitOutput(a, io, repo.path, fixture.git, inventory_args, limits.ignored_git_output, null);
    defer a.free(exact);
    try std.testing.expectEqualSlices(u8, inventory, exact);
    const longer = try std.fmt.allocPrint(a, "{s}z.ignored", .{short_names[0][0 .. short_names[0].len - ".ignored".len]});
    defer a.free(longer);
    try std.Io.Dir.rename(directory, short_names[0], directory, longer, io);
    const excess = try repo.gitOutput(inventory_args, limits.ignored_git_output + 2);
    defer a.free(excess);
    try std.testing.expectEqual(limits.ignored_git_output + 1, excess.len);
    try std.testing.expectError(error.GitOutputOverflow, source.gitOutput(
        a,
        io,
        repo.path,
        fixture.git,
        inventory_args,
        limits.ignored_git_output,
        null,
    ));
}

test "real ignored inventory path 1024 and depth 64 succeed, first excess refuses" {
    var fixture = try Fixture.init("ignored-path");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "paths", "*.ignored\n/.zig-cache/\n/support/apps/wamr-aot/.config\n/support/apps/wamr-aot/build/\n");
    defer repo.deinit();
    const exact = try boundaryPath(limits.ignored_depth, limits.ignored_path);
    defer a.free(exact);
    try addIgnored(repo, exact);
    try limits.relative(exact, limits.ignored_path, limits.ignored_depth);
    try checkSource(repo, 2, "*.ignored\n/.zig-cache/\n/support/apps/wamr-aot/.config\n/support/apps/wamr-aot/build/\n".len + "CONFIG_FIXTURE=y\n".len);
    const longer = try boundaryPath(limits.ignored_depth, limits.ignored_path + 1);
    defer a.free(longer);
    try addIgnored(repo, longer);
    try refuseSource(repo, error.UnsafePath);
    try repo.dir.deleteFile(io, longer);
    var deeper: std.ArrayList(u8) = .empty;
    defer deeper.deinit(a);
    try deeper.appendSlice(a, ".d");
    for (0..limits.ignored_depth - 1) |_| try deeper.appendSlice(a, "/d");
    try deeper.appendSlice(a, "/x.ignored");
    try std.testing.expect(deeper.items.len <= limits.ignored_path);
    try addIgnored(repo, deeper.items);
    try refuseSource(repo, error.LimitExceeded);
}

test "real root inventory accepts 128 entries and refuses 129" {
    var fixture = try Fixture.init("root-inventory");
    defer fixture.deinit();
    for (0..limits.diagnostic_root) |i| {
        const name = try std.fmt.allocPrint(a, "entry-{d:0>3}", .{i});
        defer a.free(name);
        try write(fixture.root, name, "");
    }
    const exact = try source.rootInventory(a, io, fixture.path);
    defer {
        for (exact) |item| a.free(item.name);
        a.free(exact);
    }
    try std.testing.expectEqual(limits.diagnostic_root, exact.len);
    for (exact) |item| try std.testing.expectEqualStrings("file", item.kind);
    try write(fixture.root, "entry-128", "");
    try std.testing.expectError(error.LimitExceeded, source.rootInventory(a, io, fixture.path));
}

test "real ignored outputs refuse escaping links, FIFOs, and sibling roots" {
    var fixture = try Fixture.init("ignored-types");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "outputs", output_ignore ++ "/.d-sibling/\n");
    defer repo.deinit();
    const output = try repo.dir.openDir(io, ".d", .{ .iterate = true });
    defer output.close(io);
    try write(output, "target", "");
    try output.symLink(io, "target", "contained", .{});
    try checkSource(repo, 2, (output_ignore ++ "/.d-sibling/\n").len + "CONFIG_FIXTURE=y\n".len);
    try output.symLink(io, "../../../outside", "escaped", .{});
    try refuseSource(repo, error.IgnoredLinkEscapesRole);
    try output.deleteFile(io, "escaped");
    if (linux.errno(linux.mknodat(output.handle, "fifo", linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
        return error.FifoFixtureFailed;
    try refuseSource(repo, error.UnsafeIgnoredEntry);
    try output.deleteFile(io, "fifo");
    try repo.dir.createDir(io, ".d-sibling", .fromMode(0o700));
    try refuseSource(repo, error.IgnoredOutsideOutput);
}

test "real tracked 40000 entries succeed and 40001 refuse" {
    var fixture = try Fixture.init("tracked-entries");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "tracked", output_ignore);
    defer repo.deinit();
    for (0..limits.tracked_entries - 2) |i| {
        const name = try std.fmt.allocPrint(a, "tracked-{d:0>5}", .{i});
        defer a.free(name);
        try write(repo.dir, name, "");
    }
    try repo.git(&.{ "add", "-A" });
    try repo.commit();
    try checkSource(repo, limits.tracked_entries, output_ignore.len + "CONFIG_FIXTURE=y\n".len);
    try write(repo.dir, "tracked-overflow", "");
    try repo.git(&.{ "add", "tracked-overflow" });
    try repo.commit();
    try refuseSource(repo, error.LimitExceeded);
}

test "real tracked 2 GiB in bounded sparse blobs succeeds, first byte refuses" {
    var fixture = try Fixture.init("tracked-bytes");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "tracked", output_ignore);
    defer repo.deinit();
    var remaining = limits.tracked_bytes - output_ignore.len - "CONFIG_FIXTURE=y\n".len;
    for (0..limits.tracked_bytes / limits.tracked_file) |i| {
        const name = try std.fmt.allocPrint(a, "blob-{d:0>2}", .{i});
        defer a.free(name);
        const size = @min(remaining, limits.tracked_file);
        try sparse(repo.dir, name, size);
        remaining -= size;
    }
    try std.testing.expectEqual(@as(usize, 0), remaining);
    try repo.git(&.{ "add", "-A" });
    try repo.commit();
    try checkSource(repo, 2 + limits.tracked_bytes / limits.tracked_file, limits.tracked_bytes);
    try write(repo.dir, "z-first-excess", "x");
    try repo.git(&.{ "add", "z-first-excess" });
    try repo.commit();
    try refuseSource(repo, error.LimitExceeded);
    try repo.dir.deleteFile(io, "z-first-excess");
    try repo.git(&.{ "add", "-u" });
    try repo.commit();
    try resize(repo.dir, "blob-00", limits.tracked_file + 1);
    try repo.git(&.{ "add", "blob-00" });
    try repo.commit();
    try refuseSource(repo, error.UnsafeSource);
}

test "real Git source refuses unsafe tracked blob/mode/link and tree directory" {
    var fixture = try Fixture.init("tracked-types");
    defer fixture.deinit();
    var repo = try Repo.withOutputs(&fixture, "types", output_ignore);
    defer repo.deinit();
    try write(repo.dir, "tracked", "original\n");
    try repo.dir.symLink(io, "tracked", "link", .{});
    try repo.git(&.{ "add", "tracked", "link" });
    try repo.commit();
    try checkSource(repo, 4, output_ignore.len + "CONFIG_FIXTURE=y\n".len + "original\n".len + "tracked".len);

    const tracked = try repo.dir.openFile(io, "tracked", .{});
    defer tracked.close(io);
    if (linux.errno(linux.fchmod(tracked.handle, 0o622)) != .SUCCESS) return error.ChmodFixtureFailed;
    try refuseSource(repo, error.UnsafeSource);
    if (linux.errno(linux.fchmod(tracked.handle, 0o600)) != .SUCCESS) return error.ChmodFixtureFailed;

    try std.Io.Dir.hardLink(repo.dir, "tracked", repo.dir, ".git/alias", io, .{});
    try refuseSource(repo, error.UnsafeSource);
    try repo.dir.deleteFile(io, ".git/alias");

    try repo.git(&.{ "update-index", "--assume-unchanged", "tracked" });
    if (linux.errno(linux.fchmod(tracked.handle, 0o700)) != .SUCCESS) return error.ChmodFixtureFailed;
    try refuseSource(repo, error.UnsafeSource);
    if (linux.errno(linux.fchmod(tracked.handle, 0o600)) != .SUCCESS) return error.ChmodFixtureFailed;
    const changed = try repo.dir.openFile(io, "tracked", .{ .mode = .write_only });
    try changed.writePositionalAll(io, "replaced\n", 0);
    changed.close(io);
    try refuseSource(repo, error.SourceChanged);
    try repo.git(&.{ "update-index", "--no-assume-unchanged", "tracked" });
    const restored = try repo.dir.openFile(io, "tracked", .{ .mode = .write_only });
    try restored.writePositionalAll(io, "original\n", 0);
    restored.close(io);

    const support = try repo.dir.openDir(io, "support", .{ .iterate = true });
    defer support.close(io);
    if (linux.errno(linux.fchmod(support.handle, 0o733)) != .SUCCESS) return error.ChmodFixtureFailed;
    defer {
        if (linux.errno(linux.fchmod(support.handle, 0o700)) != .SUCCESS)
            @panic("source directory permission cleanup failed");
    }
    try refuseSource(repo, error.UnsafeFile);
}
