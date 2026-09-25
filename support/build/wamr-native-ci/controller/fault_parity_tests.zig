// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const options = @import("test_options");
const a = std.testing.allocator;
const io = std.testing.io;

const Fixture = struct {
    parent: std.Io.Dir,
    root: std.Io.Dir,
    name: []u8,
    path: []u8,

    fn init(label: []const u8) !Fixture {
        const base = options.fixture_root;
        if (!std.fs.path.isAbsolute(base) or base.len <= 1 or base[base.len - 1] == '/')
            return error.UnsafeFixtureRoot;
        const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(io, base, a);
        defer a.free(canonical);
        if (!std.mem.eql(u8, canonical, base)) return error.UnsafeFixtureRoot;
        const source_root = try std.Io.Dir.realPathFileAbsoluteAlloc(io, options.repository_root, a);
        defer a.free(source_root);
        if (std.mem.eql(u8, base, source_root) or
            (std.mem.startsWith(u8, base, source_root) and base.len > source_root.len and base[source_root.len] == '/'))
            return error.UnsafeFixtureRoot;
        const parent = try core.private_files.openDirectory(io, base, .private);
        errdefer parent.close(io);
        const name = try std.fmt.allocPrint(a, "controller-fault-parity-{s}-{d}", .{ label, linux.getpid() });
        errdefer a.free(name);
        try parent.createDir(io, name, .fromMode(0o700));
        errdefer parent.deleteTree(io, name) catch {};
        const root = try parent.openDir(io, name, .{ .iterate = true });
        errdefer root.close(io);
        const path = try std.fs.path.join(a, &.{ base, name });
        return .{ .parent = parent, .root = root, .name = name, .path = path };
    }

    fn deinit(self: *Fixture) void {
        self.root.close(io);
        self.parent.deleteTree(io, self.name) catch @panic("fault fixture cleanup failed");
        self.parent.close(io);
        a.free(self.path);
        a.free(self.name);
    }

    fn child(self: Fixture, relative: []const u8) ![]u8 {
        return std.fs.path.join(a, &.{ self.path, relative });
    }
};

fn write(dir: std.Io.Dir, name: []const u8, contents: []const u8, mode: u16) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(mode) });
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
}

fn chmod(file: std.Io.File, mode: u32) !void {
    if (linux.errno(linux.fchmod(file.handle, mode)) != .SUCCESS) return error.FixtureChmodFailed;
}

fn expectPackageError(packages: []const u8, expected: anyerror) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectError(expected, controller.dependency_custody.packageSet(arena.allocator(), io, packages));
}

fn package(files: std.Io.Dir) !void {
    try write(files, "build.zig.zon", ".{ .name = .miz_fixture, }\n", 0o600);
    try write(files, "source.zig", "pub const answer = 42;\n", 0o600);
}

fn trackedBytes(relative: []const u8) ![]u8 {
    const path = try std.fs.path.join(a, &.{ options.repository_root, relative });
    defer a.free(path);
    var retained = try core.private_files.RetainedFile.open(io, path, .artifact);
    defer retained.close(io);
    if (retained.file_snapshot.size == 0 or retained.file_snapshot.size > 1024 * 1024)
        return error.InvalidFixtureManifest;
    const bytes = try a.alloc(u8, @intCast(retained.file_snapshot.size));
    errdefer a.free(bytes);
    if (try retained.file.readPositionalAll(io, bytes, 0) != bytes.len)
        return error.FixtureManifestChanged;
    try retained.verify(io);
    return bytes;
}

fn git(repo: []const u8, args: []const []const u8) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(a);
    try argv.appendSlice(a, &.{ options.git_executable, "-c", "gc.auto=0", "-c", "maintenance.auto=false" });
    try argv.appendSlice(a, args);
    const result = try std.process.run(a, io, .{
        .argv = argv.items,
        .cwd = .{ .path = repo },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.FixtureGitFailed;
}

const ManifestRepo = struct {
    dir: std.Io.Dir,
    path: []u8,
    data: [2][]u8,

    fn init(fixture: *Fixture) !ManifestRepo {
        const paths = controller.dependency_custody.manifest_paths;
        const build = try trackedBytes(paths[0]);
        errdefer a.free(build);
        const zon = try trackedBytes(paths[1]);
        errdefer a.free(zon);
        try fixture.root.createDir(io, "repository", .fromMode(0o700));
        const dir = try fixture.root.openDir(io, "repository", .{ .iterate = true });
        errdefer dir.close(io);
        const path = try fixture.child("repository");
        errdefer a.free(path);
        try dir.createDirPath(io, "support/tools/hyperv/local_boot");
        try write(dir, paths[0], build, 0o600);
        try write(dir, paths[1], zon, 0o600);
        try git(path, &.{ "init", "-q" });
        try git(path, &.{ "add", paths[0], paths[1] });
        try git(path, &.{
            "-c",     "user.name=Fixture", "-c",               "user.email=fixture@example.invalid",
            "commit", "-qm",               "pinned manifests",
        });
        return .{ .dir = dir, .path = path, .data = .{ build, zon } };
    }

    fn deinit(self: *ManifestRepo) void {
        self.dir.close(io);
        a.free(self.path);
        for (self.data) |bytes| a.free(bytes);
    }
};

fn expectManifestRefusal(repository: []const u8, relative: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    if (controller.source_custody.trackedManifest(arena.allocator(), io, repository, options.git_executable, relative)) |record| {
        record.deinit(arena.allocator());
        return error.UnsafeManifestAdmitted;
    } else |err| switch (err) {
        error.NotDir, error.SymLinkLoop, error.UnsafeFile, error.UnsafeSource => {},
        else => return err,
    }
}

test "private Bison rejects writable file and nonprivate root after same-size mutation" {
    var fixture = try Fixture.init("bison-modes");
    defer fixture.deinit();
    try fixture.root.createDir(io, "bison", .fromMode(0o700));
    const dir = try fixture.root.openDir(io, "bison", .{ .iterate = true });
    defer dir.close(io);
    const path = try fixture.child("bison");
    defer a.free(path);
    try write(dir, "skeleton", "first", 0o600);
    try write(dir, "empty", "", 0o600);
    const before = try controller.input_custody.bison(a, io, path);
    try std.testing.expectEqual(@as(usize, 2), before.files);
    try std.testing.expectEqual(@as(usize, 5), before.bytes);
    const skeleton = try dir.openFile(io, "skeleton", .{ .mode = .read_write });
    defer skeleton.close(io);
    try skeleton.writePositionalAll(io, "other", 0);
    const changed = try controller.input_custody.bison(a, io, path);
    try std.testing.expect(!std.meta.eql(before.sha256, changed.sha256));
    try chmod(skeleton, 0o666);
    try std.testing.expectError(error.UnsafeBisonInput, controller.input_custody.bison(a, io, path));
    try chmod(skeleton, 0o600);
    try chmod(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } }, 0o755);
    defer chmod(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } }, 0o700) catch
        @panic("Bison directory mode cleanup failed");
    try std.testing.expectError(error.UnsafeFile, controller.input_custody.bison(a, io, path));
}

test "consumer retains the original executable but rejects same-byte inode replacement" {
    var fixture = try Fixture.init("retained-tool");
    defer fixture.deinit();
    try fixture.root.createDir(io, "tools", .fromMode(0o700));
    try fixture.root.createDir(io, "data", .fromMode(0o700));
    const tools = try fixture.root.openDir(io, "tools", .{ .iterate = true });
    defer tools.close(io);
    const data = try fixture.root.openDir(io, "data", .{ .iterate = true });
    defer data.close(io);
    try write(data, "input", "same bytes", 0o600);
    const source_path = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/true", a);
    defer a.free(source_path);
    const original = try std.Io.Dir.openFileAbsolute(io, source_path, .{ .follow_symlinks = false });
    defer original.close(io);
    const size: usize = @intCast((try original.stat(io)).size);
    try std.testing.expect(size >= 64 and size < 1024 * 1024);
    const bytes = try a.alloc(u8, size);
    defer a.free(bytes);
    try std.testing.expectEqual(size, try original.readPositionalAll(io, bytes, 0));
    try write(tools, "tool", bytes, 0o700);
    const tool_path = try fixture.child("tools/tool");
    defer a.free(tool_path);
    const data_path = try fixture.child("data");
    defer a.free(data_path);
    const files = [_]controller.input_custody.Binding{.{ .role = "tool:fixture", .path = tool_path }};
    const trees = [_]controller.input_custody.Binding{.{ .role = "fixture", .path = data_path }};
    var expected = try controller.input_custody.capture(a, io, &files, &trees);
    defer expected.deinit(a);
    try controller.input_custody.requireSame(a, io, expected, &files, &trees);
    var pinned = try core.private_files.RetainedFile.open(io, tool_path, .artifact);
    defer pinned.close(io);
    const executable = try core.process.Executable.open(io, tool_path);
    defer executable.close(io);
    try std.Io.Dir.rename(tools, "tool", tools, "retained", io);
    try write(tools, "tool", bytes, 0o700);
    const pinned_contents = try a.alloc(u8, size);
    defer a.free(pinned_contents);
    try std.testing.expectEqual(size, try pinned.file.readPositionalAll(io, pinned_contents, 0));
    try std.testing.expectEqualSlices(u8, bytes, pinned_contents);
    try std.testing.expectError(error.FileChanged, pinned.verify(io));
    try std.testing.expectEqual(size, try executable.file.readPositionalAll(io, pinned_contents, 0));
    try std.testing.expectEqualSlices(u8, bytes, pinned_contents);
    var replacement = try controller.input_custody.capture(a, io, &files, &trees);
    defer replacement.deinit(a);
    try std.testing.expectEqualDeep(expected.files[0].sha256, replacement.files[0].sha256);
    try std.testing.expect(expected.files[0].metadata[1] != replacement.files[0].metadata[1]);
    try std.testing.expectError(error.InputChanged, controller.input_custody.requireSame(a, io, expected, &files, &trees));
}

test "only pinned Zig and LLVM roles admit large executables under retained custody" {
    var fixture = try Fixture.init("zig-tool-bound");
    defer fixture.deinit();
    const file = try fixture.root.createFile(io, "zig", .{
        .exclusive = true, .permissions = .fromMode(0o700),
    });
    defer file.close(io);
    const path = try fixture.child("zig");
    defer a.free(path);
    if (linux.errno(linux.ftruncate(file.handle, 65 * 1024 * 1024)) != .SUCCESS)
        return error.FixtureTruncateFailed;
    try std.testing.expectError(error.UnsafeFile,
        controller.command_adapter.openPinnedTool(io, path, "tool:git"));
    try std.testing.expectError(error.UnsafeFile,
        controller.command_adapter.openPinnedTool(io, path, "tool:llvm-other"));
    var retained = try controller.command_adapter.openPinnedTool(io, path, "tool:zig");
    defer retained.close(io);
    try retained.verify(io);
    var llvm = try controller.command_adapter.openPinnedTool(io, path, "tool:llvm-nm");
    defer llvm.close(io);
    try llvm.verify(io);

    try chmod(file, 0o722);
    try std.testing.expectError(error.UnsafeFile,
        controller.command_adapter.openPinnedTool(io, path, "tool:zig"));
    try chmod(file, 0o700);
    if (linux.errno(linux.ftruncate(file.handle, 256 * 1024 * 1024 + 1)) != .SUCCESS)
        return error.FixtureTruncateFailed;
    try std.testing.expectError(error.UnsafeFile,
        controller.command_adapter.openPinnedTool(io, path, "tool:zig"));
    try std.testing.expectError(error.UnsafeFile,
        controller.command_adapter.openPinnedTool(io, path, "tool:llvm-objdump"));
}

test "consumer tree permits a directory alias inside its root but refuses external directory" {
    var fixture = try Fixture.init("directory-link");
    defer fixture.deinit();
    try fixture.root.createDir(io, "tree", .fromMode(0o700));
    const tree = try fixture.root.openDir(io, "tree", .{ .iterate = true });
    defer tree.close(io);
    try tree.createDir(io, "data", .fromMode(0o700));
    const data = try tree.openDir(io, "data", .{ .iterate = true });
    defer data.close(io);
    try write(data, "input", "bounded", 0o600);
    try tree.symLink(io, "data", "alias", .{ .is_directory = true });
    const path = try fixture.child("tree");
    defer a.free(path);
    const binding: controller.input_custody.Binding = .{ .role = "zig", .path = path };
    const admitted = try controller.input_custody.tree(a, io, binding);
    try std.testing.expectEqual(@as(usize, 1), admitted.files);
    try std.testing.expectEqual(@as(usize, 2), admitted.directories);
    try std.testing.expectEqual(@as(usize, 1), admitted.symlinks);
    try fixture.root.createDir(io, "outside", .fromMode(0o700));
    try tree.symLink(io, "../outside", "escape", .{ .is_directory = true });
    try std.testing.expectError(error.UnsafeInputLink, controller.input_custody.tree(a, io, binding));
}

test "package custody rejects symlink and FIFO entries, unexpected roots and missing transitive hash" {
    var fixture = try Fixture.init("dependency-roots");
    defer fixture.deinit();
    try fixture.root.createDir(io, "zig-pkg", .fromMode(0o700));
    const packages = try fixture.root.openDir(io, "zig-pkg", .{ .iterate = true });
    defer packages.close(io);
    const path = try fixture.child("zig-pkg");
    defer a.free(path);
    const miz_name = controller.custody_limits.miz_package_hash;
    try packages.createDir(io, miz_name, .fromMode(0o700));
    const miz = try packages.openDir(io, miz_name, .{ .iterate = true });
    defer miz.close(io);
    try write(miz, "build.zig.zon", ".{ .name = .miz_fixture, .dependencies = .{}, }\n", 0o600);
    try write(miz, "source.zig", "pub const answer = 42;\n", 0o600);
    var admitted = try controller.dependency_custody.packageSet(a, io, path);
    defer admitted.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), admitted.roots);
    try miz.symLink(io, "source.zig", "alias", .{});
    try expectPackageError(path, error.UnsafePackageEntry);
    try miz.deleteFile(io, "alias");
    if (linux.errno(linux.mknodat(miz.handle, "fifo", linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
        return error.FifoFixtureFailed;
    try expectPackageError(path, error.UnsafePackageEntry);
    try miz.deleteFile(io, "fifo");
    const extra = "extra-0.1.0-aaaaaaaa";
    try packages.createDir(io, extra, .fromMode(0o700));
    const other = try packages.openDir(io, extra, .{ .iterate = true });
    try write(other, "source.zig", "extra\n", 0o600);
    other.close(io);
    try expectPackageError(path, error.UnexpectedPackage);
    try packages.deleteTree(io, extra);
    const manifest = try miz.openFile(io, "build.zig.zon", .{ .mode = .read_write });
    defer manifest.close(io);
    const missing = ".{ .dependencies = .{ .missing = .{ .hash = \"missing-0.1.0-aaaaaaaa\", }, }, }\n";
    if (linux.errno(linux.ftruncate(manifest.handle, @intCast(missing.len))) != .SUCCESS)
        return error.ManifestFixtureFailed;
    try manifest.writePositionalAll(io, missing, 0);
    try expectPackageError(path, error.MissingDependency);
}

test "pinned package custody accepts writable archive members only beneath its private root" {
    var fixture = try Fixture.init("package-modes");
    defer fixture.deinit();
    try fixture.root.createDir(io, "zig-pkg", .fromMode(0o700));
    const packages = try fixture.root.openDir(io, "zig-pkg", .{ .iterate = true });
    defer packages.close(io);
    const path = try fixture.child("zig-pkg");
    defer a.free(path);
    try packages.createDir(io, controller.custody_limits.miz_package_hash, .fromMode(0o700));
    const miz = try packages.openDir(io, controller.custody_limits.miz_package_hash, .{ .iterate = true });
    defer miz.close(io);
    try package(miz);
    const source = try miz.openFile(io, "source.zig", .{});
    defer source.close(io);
    try chmod(source, 0o777);
    try miz.createDir(io, "scripts", .fromMode(0o700));
    const scripts = try miz.openDir(io, "scripts", .{ .iterate = true });
    defer scripts.close(io);
    try write(scripts, "build.sh", "#!/bin/sh\n", 0o600);
    try chmod(.{ .handle = scripts.handle, .flags = .{ .nonblocking = false } }, 0o777);
    var admitted = try controller.dependency_custody.packageSet(a, io, path);
    defer admitted.deinit(a);
    try controller.dependency_custody.requireSame(a, io, path, admitted);
    try chmod(source, 0o600);
    try std.testing.expectError(error.DependencyChanged,
        controller.dependency_custody.requireSame(a, io, path, admitted));
    try chmod(.{ .handle = packages.handle, .flags = .{ .nonblocking = false } }, 0o755);
    try expectPackageError(path, error.UnsafeFile);
}

test "empty package dependencies do not unpin the root manifest" {
    const manifest = ".{ .dependencies = .{}, }\n";
    const hashes = try controller.dependency_custody.packageDependencies(a, manifest);
    defer a.free(hashes);
    try std.testing.expectEqual(@as(usize, 0), hashes.len);
    try std.testing.expectError(error.UnpinnedDependency,
        controller.dependency_custody.pinnedManifest(a, manifest));
}

test "identical-content package root replacement breaks retained physical dependency custody" {
    var fixture = try Fixture.init("dependency-replace");
    defer fixture.deinit();
    try fixture.root.createDir(io, "zig-pkg", .fromMode(0o700));
    const packages = try fixture.root.openDir(io, "zig-pkg", .{ .iterate = true });
    defer packages.close(io);
    const path = try fixture.child("zig-pkg");
    defer a.free(path);
    const miz_name = controller.custody_limits.miz_package_hash;
    try packages.createDir(io, miz_name, .fromMode(0o700));
    const original = try packages.openDir(io, miz_name, .{ .iterate = true });
    try package(original);
    original.close(io);
    var expected = try controller.dependency_custody.packageSet(a, io, path);
    defer expected.deinit(a);
    try controller.dependency_custody.requireSame(a, io, path, expected);
    try std.Io.Dir.rename(packages, miz_name, fixture.root, "retained-package", io);
    try packages.createDir(io, miz_name, .fromMode(0o700));
    const replaced = try packages.openDir(io, miz_name, .{ .iterate = true });
    try package(replaced);
    replaced.close(io);
    var current = try controller.dependency_custody.packageSet(a, io, path);
    defer current.deinit(a);
    try std.testing.expectEqualDeep(expected.packages[0].tree_sha256, current.packages[0].tree_sha256);
    try std.testing.expect(!std.meta.eql(expected.packages[0].physical_sha256, current.packages[0].physical_sha256));
    try std.testing.expectError(error.DependencyChanged, controller.dependency_custody.requireSame(a, io, path, expected));
}

test "tracked restore manifests reject symlinked parent and final component" {
    var fixture = try Fixture.init("manifest-components");
    defer fixture.deinit();
    var repository = try ManifestRepo.init(&fixture);
    defer repository.deinit();
    const relative = controller.dependency_custody.manifest_paths[0];
    const original = try controller.source_custody.trackedManifest(a, io, repository.path, options.git_executable, relative);
    defer original.deinit(a);
    try std.testing.expectEqualSlices(u8, repository.data[0], original.content);
    try fixture.root.createDir(io, "external", .fromMode(0o700));
    const external = try fixture.root.openDir(io, "external", .{ .iterate = true });
    defer external.close(io);
    try write(external, "build.zig", repository.data[0], 0o600);
    const external_dir = try fixture.child("external");
    defer a.free(external_dir);
    try std.Io.Dir.rename(repository.dir, "support/tools/hyperv/local_boot", fixture.root, "retained-local-boot", io);
    try repository.dir.symLink(io, external_dir, "support/tools/hyperv/local_boot", .{ .is_directory = true });
    try expectManifestRefusal(repository.path, relative);
    try repository.dir.deleteFile(io, "support/tools/hyperv/local_boot");
    try std.Io.Dir.rename(fixture.root, "retained-local-boot", repository.dir, "support/tools/hyperv/local_boot", io);
    const restored = try controller.source_custody.trackedManifest(a, io, repository.path, options.git_executable, relative);
    defer restored.deinit(a);
    try std.testing.expectEqualSlices(u8, original.content, restored.content);
    const external_file = try fixture.child("external/build.zig");
    defer a.free(external_file);
    try std.Io.Dir.rename(repository.dir, relative, fixture.root, "retained-build", io);
    try repository.dir.symLink(io, external_file, relative, .{});
    try expectManifestRefusal(repository.path, relative);
}

test "dependency record refuses same-byte restore manifest copy replacement" {
    var fixture = try Fixture.init("manifest-copy");
    defer fixture.deinit();
    var repository = try ManifestRepo.init(&fixture);
    defer repository.deinit();
    try fixture.root.createDir(io, "compute", .fromMode(0o700));
    const compute = try fixture.root.openDir(io, "compute", .{ .iterate = true });
    defer compute.close(io);
    try compute.createDir(io, "dependencies", .fromMode(0o700));
    try compute.createDir(io, "private", .fromMode(0o700));
    const restore = try compute.openDir(io, "dependencies", .{ .iterate = true });
    defer restore.close(io);
    const private = try compute.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    for (controller.dependency_custody.manifest_paths, repository.data) |relative, bytes|
        try write(restore, std.fs.path.basename(relative), bytes, 0o600);
    try restore.createDir(io, "zig-pkg", .fromMode(0o700));
    const packages = try restore.openDir(io, "zig-pkg", .{ .iterate = true });
    defer packages.close(io);
    const miz = controller.custody_limits.miz_package_hash;
    try packages.createDir(io, miz, .fromMode(0o700));
    const entry = try packages.openDir(io, miz, .{ .iterate = true });
    defer entry.close(io);
    try package(entry);
    try write(private, "dependency-restore.log", "restored\n", 0o600);
    const hash = try std.fmt.allocPrint(a, "{s}\n", .{miz});
    defer a.free(hash);
    try write(private, "dependency-hash-000.log", hash, 0o600);
    const compute_path = try fixture.child("compute");
    defer a.free(compute_path);
    var recorded = try controller.dependency_custody.capture(a, io, repository.path, options.git_executable, compute_path);
    defer recorded.deinit(a);
    try controller.dependency_custody.requireDocument(a, io, repository.path, options.git_executable, compute_path, recorded);
    try std.Io.Dir.rename(restore, "build.zig", fixture.root, "retained-build-copy", io);
    try write(restore, "build.zig", repository.data[0], 0o600);
    var replaced = try controller.dependency_custody.capture(a, io, repository.path, options.git_executable, compute_path);
    defer replaced.deinit(a);
    try std.testing.expectEqualDeep(recorded.source_manifests.@"build.zig".copy.sha256, replaced.source_manifests.@"build.zig".copy.sha256);
    try std.testing.expect(recorded.source_manifests.@"build.zig".copy.metadata[1] != replaced.source_manifests.@"build.zig".copy.metadata[1]);
    try std.testing.expectError(error.DependencyChanged, controller.dependency_custody.requireDocument(
        a,
        io,
        repository.path,
        options.git_executable,
        compute_path,
        recorded,
    ));
}

test "transient in later package directory changes physical custody without changing content" {
    var fixture = try Fixture.init("later-directory");
    defer fixture.deinit();
    try fixture.root.createDir(io, "zig-pkg", .fromMode(0o700));
    const packages = try fixture.root.openDir(io, "zig-pkg", .{ .iterate = true });
    defer packages.close(io);
    const path = try fixture.child("zig-pkg");
    defer a.free(path);
    try packages.createDir(io, controller.custody_limits.miz_package_hash, .fromMode(0o700));
    const miz = try packages.openDir(io, controller.custody_limits.miz_package_hash, .{ .iterate = true });
    defer miz.close(io);
    try package(miz);
    try write(miz, "a-first", "read first\n", 0o600);
    try miz.createDir(io, "z-later", .fromMode(0o700));
    const later = try miz.openDir(io, "z-later", .{ .iterate = true });
    defer later.close(io);
    try write(later, "retained", "stable\n", 0o600);
    var expected = try controller.dependency_custody.packageSet(a, io, path);
    defer expected.deinit(a);
    try controller.dependency_custody.requireSame(a, io, path, expected);
    var empty: [0]linux.pollfd = .{};
    _ = linux.poll(&empty, 0, 10);
    try write(later, "transient", "created and removed\n", 0o600);
    try later.deleteFile(io, "transient");
    var actual = try controller.dependency_custody.packageSet(a, io, path);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected.packages[0].tree_sha256, actual.packages[0].tree_sha256);
    try std.testing.expect(!std.meta.eql(expected.packages[0].physical_sha256, actual.packages[0].physical_sha256));
    try std.testing.expectError(error.DependencyChanged, controller.dependency_custody.requireSame(a, io, path, expected));
}

test "pre-spawn timeout and cancellation leave no command or cleanup events" {
    var fixture = try Fixture.init("pre-spawn");
    defer fixture.deinit();
    const executable_path = try std.Io.Dir.realPathFileAbsoluteAlloc(io, "/usr/bin/true", a);
    defer a.free(executable_path);
    const executable = try core.process.Executable.open(io, executable_path);
    defer executable.close(io);
    const cwd = try core.private_files.openDirectory(io, fixture.path, .private);
    defer cwd.close(io);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    const cancelled = std.atomic.Value(bool).init(true);
    try core.process.initialize();
    for ([_]struct { kind: std.meta.Tag(core.process.CommandPrimary), cancel: bool }{
        .{ .kind = .timeout, .cancel = false },
        .{ .kind = .cancelled, .cancel = true },
    }) |scenario| {
        const future = try core.process.Deadline.afterMilliseconds(60_000);
        var result = try core.process.runCommand(a, io, .{
            .executable = executable,
            .argv = &.{executable_path},
            .environment = &environment,
            .cwd = cwd,
            .primary_deadline = if (scenario.cancel) future else .{ .expires_ns = 1 },
            .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, future.expires_ns, 10 * std.time.ns_per_s) },
            .cancel = if (scenario.cancel) &cancelled else null,
            .snapshot_executable = false,
            .limits = .{ .stdout_bytes = 64, .stderr_bytes = 64 },
        });
        defer result.deinit(a);
        try std.testing.expectEqual(scenario.kind, std.meta.activeTag(result.primary));
        try std.testing.expectEqual(scenario.kind == .timeout, result.primary_deadline_reached);
        try std.testing.expectEqual(scenario.cancel, result.cancellation_observed);
        try std.testing.expectEqual(core.process.CommandCleanup.not_required, result.cleanup);
        try std.testing.expect(result.cleanup_complete and result.executable_stable);
        try std.testing.expectEqual(core.process.CommandStreamStatus.complete, result.stdout_status);
        try std.testing.expectEqual(core.process.CommandStreamStatus.complete, result.stderr_status);
        try std.testing.expectEqual(@as(usize, 0), result.stdout.len + result.stderr.len);
        try std.testing.expectEqual(@as(u32, 0), result.primary_events + result.cleanup_events);
        try std.testing.expectEqual(@as(u16, 0), result.reap_events + result.descendants.observed);
        try std.testing.expectEqual(result.primary_completed_ns, result.completed_ns);
    }
}

fn descendantFixture(fixture: Fixture) ![]u8 {
    const source = try std.fs.path.join(a, &.{ options.repository_root, "support/tools/hyperv/direct/runtime_fixture.zig" });
    defer a.free(source);
    const core_source = try std.fs.path.join(a, &.{ options.repository_root, "support/tools/hyperv/core.zig" });
    defer a.free(core_source);
    const assembly = try std.fs.path.join(a, &.{ options.repository_root, "support/tools/hyperv/sha256_clear_upper.S" });
    defer a.free(assembly);
    const binary = try fixture.child("runtime-fixture");
    errdefer a.free(binary);
    const local_cache = try fixture.child("local-cache");
    defer a.free(local_cache);
    const global_cache = try fixture.child("global-cache");
    defer a.free(global_cache);
    const emit = try std.fmt.allocPrint(a, "-femit-bin={s}", .{binary});
    defer a.free(emit);
    const module = try std.fmt.allocPrint(a, "-Mroot={s}", .{source});
    defer a.free(module);
    const core_module = try std.fmt.allocPrint(a, "-Mhyperv_core={s}", .{core_source});
    defer a.free(core_module);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(a);
    try argv.appendSlice(a, &.{
        options.zig_executable, "build-exe", "-O",                 "ReleaseSafe",
        "--cache-dir",          local_cache, "--global-cache-dir", global_cache,
        emit,
    });
    if (@import("builtin").cpu.arch == .x86_64) try argv.append(a, assembly);
    try argv.appendSlice(a, &.{ "--dep", "hyperv_core", module, core_module });
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try environment.put("HOME", fixture.path);
    try environment.put("PATH", "/usr/bin:/bin");
    try environment.put("LANG", "C");
    try environment.put("ZIG_LOCAL_CACHE_DIR", local_cache);
    try environment.put("ZIG_GLOBAL_CACHE_DIR", global_cache);
    const result = try std.process.run(a, io, .{
        .argv = argv.items,
        .cwd = .{ .path = options.repository_root },
        .environ_map = &environment,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(16 * 1024),
    });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("native descendant fixture build: {s}\n", .{result.stderr});
        return error.DescendantFixtureBuildFailed;
    }
    const executable = try core.process.Executable.open(io, binary);
    executable.close(io);
    return binary;
}

fn commandRequest(
    executable: core.process.Executable,
    argv: []const []const u8,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
    milliseconds: u64,
) !core.process.CommandRequest {
    const deadline = try core.process.Deadline.afterMilliseconds(milliseconds);
    return .{
        .executable = executable,
        .argv = argv,
        .environment = environment,
        .cwd = cwd,
        .primary_deadline = deadline,
        .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, deadline.expires_ns, 3000 * std.time.ns_per_ms) },
        .snapshot_executable = false,
        .limits = .{ .stdout_bytes = 256, .stderr_bytes = 64, .term_grace_ms = 50 },
    };
}

fn expectGone(bytes: []const u8, allow_partial: bool, minimum: usize) !void {
    const final = std.mem.lastIndexOfScalar(u8, bytes, '\n') orelse return error.MissingDescendantPid;
    if (!allow_partial and final != bytes.len - 1) return error.IncompleteDescendantPid;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes[0 .. final + 1], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const pid = try std.fmt.parseInt(linux.pid_t, line, 10);
        if (pid <= 1) return error.InvalidDescendantPid;
        try std.testing.expectEqual(linux.E.SRCH, linux.errno(linux.kill(pid, @enumFromInt(0))));
        count += 1;
    }
    try std.testing.expect(count >= minimum);
    var status: u32 = 0;
    try std.testing.expectEqual(linux.E.CHILD, linux.errno(linux.waitpid(-1, &status, linux.W.NOHANG)));
}

const CancellationOnOutput = struct {
    descriptor: linux.fd_t,
    flag: *std.atomic.Value(bool),
    saw_pid: std.atomic.Value(bool) = .init(false),

    fn wait(context: *CancellationOnOutput) void {
        const deadline = core.process.Deadline.afterMilliseconds(2000) catch unreachable;
        while (!(deadline.expired() catch unreachable)) {
            var pid: [32]u8 = undefined;
            const count = linux.pread(context.descriptor, &pid, pid.len, 0);
            if (linux.errno(count) == .SUCCESS and std.mem.indexOfScalar(u8, pid[0..count], '\n') != null) {
                context.saw_pid.store(true, .release);
                break;
            }
            var fds: [0]linux.pollfd = .{};
            _ = linux.poll(&fds, 0, 2);
        }
        context.flag.store(true, .release);
    }
};

test "ordinary setsid double-fork and closed-fd descendants are reaped after leader success" {
    var fixture = try Fixture.init("descendant-shapes");
    defer fixture.deinit();
    const binary = try descendantFixture(fixture);
    defer a.free(binary);
    const executable = try core.process.Executable.open(io, binary);
    defer executable.close(io);
    const cwd = try core.private_files.openDirectory(io, fixture.path, .private);
    defer cwd.close(io);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try core.process.initialize();
    for ([_][]const u8{ "ordinary-child", "setsid-child", "double-fork", "closed-child" }) |mode| {
        var result = try core.process.runCommand(a, io, try commandRequest(executable, &.{ binary, mode }, &environment, cwd, 5000));
        defer result.deinit(a);
        try std.testing.expect(result.succeeded());
        try std.testing.expectEqual(core.process.CommandCleanup.complete, result.cleanup);
        try std.testing.expect(result.cleanup_complete and result.executable_stable);
        try std.testing.expectEqual(@as(u16, 1), result.descendants.observed);
        try std.testing.expectEqual(result.descendants.observed, result.descendants.identity_validated);
        try std.testing.expect(result.descendants.adopted >= 1);
        try expectGone(result.stdout, false, 1);
    }
}

test "timeout and post-spawn cancellation reap a live child and retain its bounded PID evidence" {
    var fixture = try Fixture.init("descendant-refusals");
    defer fixture.deinit();
    const binary = try descendantFixture(fixture);
    defer a.free(binary);
    const executable = try core.process.Executable.open(io, binary);
    defer executable.close(io);
    const cwd = try core.private_files.openDirectory(io, fixture.path, .private);
    defer cwd.close(io);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try core.process.initialize();
    var timed = try core.process.runCommand(a, io, try commandRequest(executable, &.{ binary, "tree" }, &environment, cwd, 1500));
    defer timed.deinit(a);
    try std.testing.expectEqual(core.process.CommandPrimary.timeout, timed.primary);
    try std.testing.expect(timed.primary_deadline_reached and !timed.succeeded());
    try std.testing.expect(timed.cleanup_complete and timed.cleanup == .complete);
    try std.testing.expectEqual(@as(u16, 1), timed.descendants.observed);
    try std.testing.expectEqual(timed.descendants.observed, timed.descendants.identity_validated);
    try std.testing.expect(timed.stdout.len > 0 and timed.stdout.len <= 32);
    try expectGone(timed.stdout, false, 1);

    const output = try fixture.root.createFile(io, "cancel-pid", .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    var cancel = std.atomic.Value(bool).init(false);
    var watcher: CancellationOnOutput = .{ .descriptor = output.handle, .flag = &cancel };
    const thread = try std.Thread.spawn(.{}, CancellationOnOutput.wait, .{&watcher});
    var joined = false;
    defer if (!joined) thread.join();
    var request = try commandRequest(executable, &.{ binary, "tree" }, &environment, cwd, 5000);
    request.cancel = &cancel;
    request.stdout_file = output;
    var cancelled = try core.process.runCommand(a, io, request);
    defer cancelled.deinit(a);
    thread.join();
    joined = true;
    try std.testing.expect(watcher.saw_pid.load(.acquire));
    try std.testing.expectEqual(core.process.CommandPrimary.cancelled, cancelled.primary);
    try std.testing.expect(cancelled.cancellation_observed and !cancelled.succeeded());
    try std.testing.expect(cancelled.cleanup_complete and cancelled.cleanup == .complete);
    try std.testing.expectEqual(@as(u16, 1), cancelled.descendants.observed);
    try std.testing.expectEqual(cancelled.descendants.observed, cancelled.descendants.identity_validated);
    const count: usize = @intCast((try output.stat(io)).size);
    try std.testing.expect(count > 0 and count <= 32);
    var retained: [32]u8 = undefined;
    try std.testing.expectEqual(count, try output.readPositionalAll(io, retained[0..count], 0));
    try expectGone(retained[0..count], false, 1);
}

test "output overflow refuses a spawning leader and still reaps its owned children" {
    var fixture = try Fixture.init("descendant-overflow");
    defer fixture.deinit();
    const binary = try descendantFixture(fixture);
    defer a.free(binary);
    const executable = try core.process.Executable.open(io, binary);
    defer executable.close(io);
    const cwd = try core.private_files.openDirectory(io, fixture.path, .private);
    defer cwd.close(io);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try core.process.initialize();
    var request = try commandRequest(executable, &.{ binary, "many-children", "12" }, &environment, cwd, 5000);
    request.limits.stdout_bytes = 32;
    var result = try core.process.runCommand(a, io, request);
    defer result.deinit(a);
    try std.testing.expectEqual(core.process.CommandPrimary.output_overflow, result.primary);
    try std.testing.expectEqual(core.process.CommandStreamStatus.overflow, result.stdout_status);
    try std.testing.expect(!result.succeeded() and result.cleanup_complete);
    try std.testing.expectEqual(core.process.CommandCleanup.complete, result.cleanup);
    try std.testing.expect(result.descendants.observed >= 1);
    try std.testing.expectEqual(result.descendants.observed, result.descendants.identity_validated);
    try std.testing.expectEqual(@as(usize, 32), result.stdout.len);
    try expectGone(result.stdout, true, 1);
}
