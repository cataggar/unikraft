// SPDX-License-Identifier: BSD-3-Clause
//! Synthetic source qualification. No genuine interpreter or Azure runtime.
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const runtime_copy = @import("runtime_copy.zig");
const types = @import("types.zig");
const records = @import("records.zig");
const runtime = types.runtime;
const linux = std.os.linux;
const a = std.testing.allocator;
const io = std.testing.io;
const launch_size = 64 * 1024 + 1;
var next_fixture: usize = 0;

const Fixture = struct {
    parent: std.Io.Dir,
    directory: std.Io.Dir,
    path: []const u8,
    name: []const u8,
    arena: *std.heap.ArenaAllocator,
    request: types.PrepareRuntime,
    loader: files.RetainedFile,
    dependencies: [1]types.LoaderSource,

    fn init() !Fixture {
        next_fixture += 1;
        const arena = try a.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(a);
        errdefer {
            arena.deinit();
            a.destroy(arena);
        }
        const alloc = arena.allocator();
        const parent = try files.openDirectory(io, @import("test_options").fixture_root, .private);
        errdefer parent.close(io);
        const name = try std.fmt.allocPrint(alloc, "copy-{d}-{d}", .{ linux.getpid(), next_fixture });
        try parent.createDir(io, name, .fromMode(0o700));
        const directory = try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
        errdefer directory.close(io);
        const path = try std.fs.path.join(alloc, &.{ @import("test_options").fixture_root, name });
        for ([_][]const u8{ "python3.11", "packages", "data" }) |component| try directory.createDir(io, component, .fromMode(0o700));
        var launch: [launch_size]u8 = undefined;
        for (&launch, 0..) |*byte, index| byte.* = @truncate(index);
        try write(directory, "launcher", &launch, 0o500);
        try write(directory, "python", "synthetic-interpreter\n", 0o500);
        try write(directory, "ld-synthetic.so", "synthetic-loader\n", 0o500);
        const stdlib = try directory.openDir(io, "python3.11", .{ .iterate = true });
        defer stdlib.close(io);
        try stdlib.createDir(io, "encodings", .fromMode(0o700));
        try write(stdlib, "os.py", "synthetic-os\n", 0o600);
        const encodings = try stdlib.openDir(io, "encodings", .{});
        defer encodings.close(io);
        try write(encodings, "__init__.py", "synthetic-encodings\n", 0o600);
        const packages = try directory.openDir(io, "packages", .{ .iterate = true });
        defer packages.close(io);
        try packages.createDir(io, "azure", .fromMode(0o700));
        const azure = try packages.openDir(io, "azure", .{});
        defer azure.close(io);
        try write(azure, "__init__.py", "synthetic-azure\n", 0o600);
        try write(packages, "_native.so", "synthetic-native\n", 0o600);
        const data = try directory.openDir(io, "data", .{});
        defer data.close(io);
        try write(data, "fixed.txt", "synthetic-data\n", 0o600);
        const package_roots = try alloc.alloc([]const u8, 1);
        package_roots[0] = try std.fs.path.join(alloc, &.{ path, "packages" });
        const data_roots = try alloc.alloc([]const u8, 1);
        data_roots[0] = try std.fs.path.join(alloc, &.{ path, "data" });
        const loader_path = try std.fs.path.join(alloc, &.{ path, "ld-synthetic.so" });
        const loader = try files.RetainedFile.open(io, loader_path, .artifact);
        return .{
            .parent = parent,
            .directory = directory,
            .path = path,
            .name = name,
            .arena = arena,
            .request = .{
                .output = try std.fs.path.join(alloc, &.{ path, "output" }),
                .azure = try std.fs.path.join(alloc, &.{ path, "launcher" }),
                .az_python = try std.fs.path.join(alloc, &.{ path, "python" }),
                .stdlib = try std.fs.path.join(alloc, &.{ path, "python3.11" }),
                .package_root = package_roots,
                .data_root = data_roots,
            },
            .loader = loader,
            .dependencies = undefined,
        };
    }
    fn stage(self: *Fixture, signal: ?*core.process.SignalCancellation) !runtime_copy.Stage {
        return self.stageIo(io, signal);
    }
    fn stageIo(self: *Fixture, selected_io: std.Io, signal: ?*core.process.SignalCancellation) !runtime_copy.Stage {
        self.dependencies[0] = .{ .file = &self.loader, .executable = true };
        return runtime_copy.Stage.init(.{ .allocator = a, .io = selected_io, .signal = signal }, self.request, .{ .dynamic_loader = &self.loader, .dependencies = &self.dependencies });
    }
    fn child(self: *Fixture, path: []const u8) ![]const u8 {
        return std.fs.path.join(self.arena.allocator(), &.{ self.path, path });
    }
    fn deinit(self: *Fixture) void {
        self.loader.close(io);
        const keep = if (@hasDecl(@import("test_options"), "oracle_keep_first"))
            @import("test_options").oracle_keep_first and std.mem.endsWith(u8, self.name, "-1")
        else
            false;
        if (!keep) makeRemovable(self.directory) catch @panic("synthetic COPY permissions cleanup failed");
        self.directory.close(io);
        if (!keep) self.parent.deleteTree(io, self.name) catch @panic("synthetic COPY cleanup failed");
        self.parent.close(io);
        self.arena.deinit();
        a.destroy(self.arena);
    }
};
fn write(directory: std.Io.Dir, name: []const u8, bytes: []const u8, mode: u32) !void {
    const file = try directory.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try modeFd(file.handle, mode);
    try file.sync(io);
}
fn modeFd(fd: linux.fd_t, mode: u32) !void {
    if (linux.errno(linux.fchmod(fd, mode)) != .SUCCESS) return error.FixtureMode;
}
fn makeRemovable(directory: std.Io.Dir) !void {
    try modeFd(directory.handle, 0o700);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const child = try directory.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
        defer child.close(io);
        try makeRemovable(child);
    }
}
fn expectAbsent(directory: std.Io.Dir, name: []const u8) !void {
    try std.testing.expectError(error.FileNotFound, directory.openFile(io, name, .{ .path_only = true, .follow_symlinks = false }));
}
fn noFinal(fixture: *Fixture) !void {
    const output = fixture.directory.openDir(io, "output", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer output.close(io);
    try expectAbsent(output, "azure-runtime.manifest");
    try expectAbsent(output, "azure-runtime.json");
}
fn expectFailure(outcome: runtime_copy.Outcome) !types.Diagnostic {
    return switch (outcome) {
        .staged => error.ExpectedRefusal,
        .refused, .poisoned => |diagnostic| diagnostic,
    };
}

test "synthetic COPY retains exact bytes frozen layout and canonical runtime commitments without admission" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var stage = try fixture.stage(null);
    defer stage.deinit();
    try std.testing.expect(stage.copyStage() == .staged);
    const root = try stage.root();
    const draft = try stage.manifestInputs();
    try std.testing.expectEqualStrings("3.11", (try stage.layout()).python_version);
    try std.testing.expectEqual(@as(u32, 8), draft.observed.files);
    try std.testing.expectEqual(@as(u32, 11), draft.observed.directories);
    try std.testing.expectEqual(@as(u8, 3), draft.observed.depth);
    const launcher = try root.openFile(io, "bootstrap/azure-cli", .{ .follow_symlinks = false });
    defer launcher.close(io);
    var bytes: [launch_size + 1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, launch_size), try launcher.readPositionalAll(io, &bytes, 0));
    for (bytes[0..launch_size], 0..) |byte, index| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    try std.testing.expectEqual(@as(u16, 0o500), (try files.snapshot(launcher)).mode & 0o7777);
    const module = try root.openFile(io, "lib/python3.11/os.py", .{});
    defer module.close(io);
    try std.testing.expectEqual(@as(u16, 0o400), (try files.snapshot(module)).mode & 0o7777);
    try std.testing.expectEqual(@as(u16, 0o500), (try files.snapshot(.{ .handle = root.handle, .flags = .{ .nonblocking = false } })).mode & 0o7777);
    try expectAbsent(root, "lib64");
    try std.testing.expect(std.mem.startsWith(u8, draft.bytes, "UK-WAMR-AZURE-RUNTIME-CLOSURE\t1\nD\truntime\t.\t"));
    try std.testing.expect(std.mem.indexOf(u8, draft.bytes, "F\tpython-module\tlib/python3.11/os.py\t") != null);
    try std.testing.expect(std.mem.indexOf(u8, draft.bytes, "F\tfixed-data\tshare/000-data/fixed.txt\t") != null);
    try stage.barrier().revalidate();
    try noFinal(&fixture);
    try std.testing.expectEqual(error.StageSpent, (try expectFailure(stage.copyStage())).err);

    // Test-only publication joins the physical A record to independently
    // verified direct schema commitments. It does not execute synthetic code.
    const output = try fixture.directory.openDir(io, "output", .{});
    defer output.close(io);
    try write(output, "azure-runtime.manifest", draft.bytes, 0o600);
    var manifest = try files.RetainedFile.open(io, draft.manifest.path, .private);
    defer manifest.close(io);
    const commitments = try draft.bindManifest(.{ .allocator = a, .io = io }, &manifest);
    const contract: runtime.Contract = .{
        .schema = "uk.wamr.azure-cli-runtime-closure",
        .version = 1,
        .canonicalization = "utf8-byte-sorted-keys-compact-lf-v1",
        .root = (try stage.layout()).root,
        .python_version = "3.11",
        .extensions = (try stage.layout()).extensions,
        .launcher = draft.launcher,
        .interpreter = draft.interpreter,
        .dynamic_loader = draft.dynamic_loader,
        .manifest = draft.manifest,
        .limits = runtime_copy.canonicalLimits(),
        .observed = draft.observed,
        .content_sha256 = &commitments.content_sha256,
        .metadata_sha256 = &commitments.metadata_sha256,
        .parents_sha256 = &commitments.parents_sha256,
        .loader_dependencies = draft.loader_dependencies,
        .commands = &runtime.commands,
        .isolation = .{
            .python_home = .closure_root,
            .module_layout = .flat_python_home_v1,
            .extensions = .closure_empty,
            .dynamic_extension_install = .disabled,
            .user_site = .disabled,
            .site_import = .disabled,
            .bytecode_writes = .disabled,
            .path_environment = .forbidden,
            .startup_hooks = .forbidden,
            .loader_environment = .retained_readonly_root,
            .host_loader_fallback = .forbidden,
            .package_restore = .forbidden_after_custody,
        },
    };
    const encoded = try records.runtimeBytes(a, contract);
    defer a.free(encoded);
    var parsed = try records.parse(runtime.Contract, a, encoded);
    defer parsed.deinit();
    try runtime.verify(a, io, parsed.value);
    try write(output, "test-only-runtime.json", encoded, 0o600);
    try stage.revalidate();
    const original_bytes = draft.bytes;
    const exact_size = draft.bytes.len;
    try stage.testManifestBound(exact_size);
    try std.testing.expectEqualStrings(original_bytes, (try stage.manifestInputs()).bytes);
    try std.testing.expectError(error.ManifestLimit, stage.testManifestBound(exact_size - 1));
    try std.testing.expectError(error.PathAlreadyExists, fixture.stage(null));
}

test "synthetic COPY rejects startup hooks links special files and unsafe names without final records" {
    const cases = [_][]const u8{ "sitecustomize.py", "usercustomize.py", "activate.pth", "symlink", "hardlink", "fifo", "bad\tname", "\xff.py", "writable.py" };
    for (cases) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const source = try fixture.directory.openDir(io, "python3.11", .{ .iterate = true });
        defer source.close(io);
        if (std.mem.eql(u8, case, "symlink")) {
            try source.symLink(io, "os.py", case, .{});
        } else if (std.mem.eql(u8, case, "hardlink")) {
            if (linux.errno(linux.linkat(source.handle, "os.py", source.handle, "linked.py", 0)) != .SUCCESS) return error.FixtureLink;
        } else if (std.mem.eql(u8, case, "fifo")) {
            if (linux.errno(linux.mknodat(source.handle, "fifo", linux.S.IFIFO | 0o600, 0)) != .SUCCESS) return error.FixtureFifo;
        } else {
            try write(source, case, "synthetic-refusal\n", if (std.mem.eql(u8, case, "writable.py")) 0o666 else 0o600);
        }
        var stage = try fixture.stage(null);
        defer stage.deinit();
        _ = try expectFailure(stage.copyStage());
        try noFinal(&fixture);
        try std.testing.expectEqual(error.StageNotReady, stage.root());
    }
}

test "synthetic COPY refuses root duplicates overlaps collisions unsafe ancestors and unbound native inventory" {
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        fixture.request.package_root = &.{fixture.request.stdlib};
        try std.testing.expectError(error.DuplicateSource, fixture.stage(null));
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        fixture.request.data_root = &.{try fixture.child("python3.11/encodings")};
        try std.testing.expectError(error.DuplicateSource, fixture.stage(null));
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        fixture.request.native_dependency = &.{try fixture.child("unknown.so")};
        try std.testing.expectError(error.UnboundNativeDependency, fixture.stage(null));
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const packages = try fixture.directory.openDir(io, "packages", .{});
        defer packages.close(io);
        try write(packages, "os.py", "same name\n", 0o600);
        var stage = try fixture.stage(null);
        defer stage.deinit();
        try std.testing.expectEqual(error.PathAlreadyExists, (try expectFailure(stage.copyStage())).err);
        try noFinal(&fixture);
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const source = try fixture.directory.openDir(io, "python3.11", .{ .iterate = true });
        defer source.close(io);
        try modeFd(source.handle, 0o777);
        try std.testing.expectError(error.UnsafeSource, fixture.stage(null));
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        fixture.request.stdlib = try fixture.child("python3.11/../python3.11");
        try std.testing.expectError(error.UnsafePath, fixture.stage(null));
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        fixture.dependencies[0] = .{ .file = &fixture.loader, .executable = true };
        const duplicate = [_]types.LoaderSource{ fixture.dependencies[0], fixture.dependencies[0] };
        try std.testing.expectError(error.LoaderCollision, runtime_copy.Stage.init(.{ .allocator = a, .io = io }, fixture.request, .{ .dynamic_loader = &fixture.loader, .dependencies = &duplicate }));
    }
}

test "synthetic COPY rechecks same-byte file directory and ancestor replacements" {
    const cases = [_][]const u8{ "source-file", "destination-file", "source-directory", "destination-root", "startup-config", "ancestor" };
    for (cases) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var stage = try fixture.stage(null);
        defer stage.deinit();
        try std.testing.expect(stage.copyStage() == .staged);
        if (std.mem.eql(u8, case, "source-file")) {
            const source = try fixture.directory.openDir(io, "python3.11", .{});
            defer source.close(io);
            try source.rename("os.py", source, "old.py", io);
            try write(source, "os.py", "synthetic-os\n", 0o600);
        } else if (std.mem.eql(u8, case, "destination-file")) {
            const root = try stage.root();
            const bootstrap = try root.openDir(io, "bootstrap", .{ .iterate = true });
            defer bootstrap.close(io);
            try modeFd(bootstrap.handle, 0o700);
            const file = try bootstrap.openFile(io, "azure-cli", .{});
            defer file.close(io);
            var bytes: [launch_size]u8 = undefined;
            _ = try file.readPositionalAll(io, &bytes, 0);
            try bootstrap.rename("azure-cli", bootstrap, "old", io);
            try write(bootstrap, "azure-cli", &bytes, 0o500);
            try modeFd(bootstrap.handle, 0o500);
        } else if (std.mem.eql(u8, case, "source-directory")) {
            try fixture.directory.rename("python3.11", fixture.directory, "old-stdlib", io);
            try fixture.directory.createDir(io, "python3.11", .fromMode(0o700));
        } else if (std.mem.eql(u8, case, "destination-root")) {
            const output = try fixture.directory.openDir(io, "output", .{});
            defer output.close(io);
            try output.rename("runtime", output, "old-runtime", io);
            try output.createDir(io, "runtime", .fromMode(0o500));
        } else if (std.mem.eql(u8, case, "startup-config")) {
            const output = try fixture.directory.openDir(io, "output", .{});
            defer output.close(io);
            try output.rename("startup-config", output, "old-config", io);
            try output.createDir(io, "startup-config", .fromMode(0o700));
        } else {
            try fixture.parent.rename(fixture.name, fixture.parent, "replaced-ancestor", io);
            try fixture.parent.createDir(io, fixture.name, .fromMode(0o700));
        }

        try std.testing.expectError(if (std.mem.eql(u8, case, "ancestor")) error.AncestorChanged else if (std.mem.eql(u8, case, "source-file")) error.SourceChanged else if (std.mem.eql(u8, case, "source-directory")) error.AncestorChanged else error.CopyChanged, stage.revalidate());
        if (std.mem.eql(u8, case, "ancestor")) {
            try fixture.parent.deleteDir(io, fixture.name);
            try fixture.parent.rename("replaced-ancestor", fixture.parent, fixture.name, io);
        }
        try noFinal(&fixture);
    }
}

test "synthetic COPY bounds accept exact streamed bytes files directories depth and refuse excess" {
    var baseline = try Fixture.init();
    defer baseline.deinit();
    var base_stage = try baseline.stage(null);
    defer base_stage.deinit();
    try std.testing.expect(base_stage.copyStage() == .staged);
    const observed = (try base_stage.manifestInputs()).observed;
    for (0..6) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var stage = try fixture.stage(null);
        defer stage.deinit();
        var bounds = runtime_copy.canonicalLimits();
        bounds.file_bytes = launch_size;
        bounds.files = observed.files;
        bounds.directories = observed.directories;
        bounds.bytes = observed.bytes;
        bounds.depth = observed.depth;
        if (case == 1) bounds.file_bytes -= 1;
        if (case == 2) bounds.files -= 1;
        if (case == 3) bounds.directories -= 1;
        if (case == 4) bounds.bytes -= 1;
        if (case == 5) bounds.depth -= 1;
        try stage.testBounds(bounds, runtime.max_manifest_bytes);
        if (case == 0) {
            try std.testing.expect(stage.copyStage() == .staged);
        } else {
            _ = try expectFailure(stage.copyStage());
        }
        try noFinal(&fixture);
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var stage = try fixture.stage(null);
        defer stage.deinit();
        try stage.testBounds(runtime_copy.canonicalLimits(), 32);
        try std.testing.expectEqual(error.ManifestLimit, (try expectFailure(stage.copyStage())).err);
        try noFinal(&fixture);
    }
}

test "synthetic COPY faults preserve partial data durability uncertainty cancellation and collisions" {
    inline for (.{ .short_write, .before_file_sync, .before_parent_sync, .cancel_after_first_chunk, .replace_destination_same_bytes, .replace_destination_fifo }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var stage = try fixture.stage(&signal);
        defer stage.deinit();
        const diagnostic = try expectFailure(stage.copyFault(fault));
        try std.testing.expectEqual(core.private_files.CommitStatus.visible_not_durable, diagnostic.publication);
        try std.testing.expect(diagnostic.failures.primary != null);
        if (fault == .cancel_after_first_chunk) try std.testing.expectEqual(error.Cancelled, diagnostic.err);
        if (fault == .short_write) try std.testing.expectEqual(error.ShortWrite, diagnostic.err);
        if (fault == .before_file_sync or fault == .before_parent_sync) try std.testing.expectEqual(error.AmbiguousWrite, diagnostic.err);
        const output = try fixture.directory.openDir(io, "output", .{});
        defer output.close(io);
        const partial = try output.openFile(io, "runtime/bootstrap/azure-cli", .{ .path_only = true, .follow_symlinks = false });
        defer partial.close(io);
        try std.testing.expect((try files.snapshot(partial)).size > 0 or fault == .replace_destination_fifo);
        try noFinal(&fixture);
        try std.testing.expectEqual(error.StageSpent, (try expectFailure(stage.copyStage())).err);
    }
}

test "synthetic COPY streams a member beyond small immutable-record limits and leaves source modes untouched" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.directory.openDir(io, "python3.11", .{});
    defer source.close(io);
    const file = try source.createFile(io, "large.dat", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    var bytes: [64 * 1024]u8 = @splat(0xa5);
    for (0..80) |_| try file.writeStreamingAll(io, &bytes);
    try file.sync(io);
    const before = try files.snapshot(file);
    var stage = try fixture.stage(null);
    defer stage.deinit();
    try std.testing.expect(stage.copyStage() == .staged);
    const root = try stage.root();
    const copied = try root.openFile(io, "lib/python3.11/large.dat", .{});
    defer copied.close(io);
    try std.testing.expectEqual(@as(u64, 5 * 1024 * 1024), (try files.snapshot(copied)).size);
    try std.testing.expectEqual(@as(usize, bytes.len), try copied.readPositionalAll(io, &bytes, 4 * 1024 * 1024));
    for (bytes) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    try std.testing.expect(files.sameSnapshot(before, try files.snapshot(file)));
    try noFinal(&fixture);
}

test "synthetic COPY source replacement and cancellation before construction leave no staged output" {
    for (0..2) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var stage = try fixture.stage(&signal);
        defer stage.deinit();
        if (case == 0) {
            try fixture.directory.rename("python", fixture.directory, "old-python", io);
            try write(fixture.directory, "python", "synthetic-interpreter\n", 0o500);
        } else {
            @constCast(signal.flag()).store(true, .release);
        }
        const failure = try expectFailure(stage.copyStage());
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, failure.publication);
        if (case == 1) try std.testing.expectEqual(error.Cancelled, failure.err);
        try expectAbsent(fixture.directory, "output");
        try noFinal(&fixture);
    }
}

test "synthetic COPY preserves explicit SONAME placements and exact loader entry bounds without source hardlinks" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try write(fixture.directory, "libsynthetic.so.1.2", "synthetic-dso\n", 0o600);
    var library = try files.RetainedFile.open(io, try fixture.child("libsynthetic.so.1.2"), .artifact);
    defer library.close(io);
    const alloc = fixture.arena.allocator();
    const dependencies = try alloc.alloc(types.LoaderSource, runtime.max_loader_files + 1);
    const names = try alloc.alloc([]const u8, dependencies.len);
    dependencies[0] = .{ .file = &fixture.loader, .executable = true };
    names[0] = "ld-synthetic.so";
    for (dependencies[1..], names[1..], 0..) |*dependency, *name, index| {
        dependency.* = .{ .file = &library, .executable = false };
        name.* = try std.fmt.allocPrint(alloc, "libsynthetic-{d:0>3}.so.1", .{index});
    }
    const inventory: types.LoaderInventory = .{ .dynamic_loader = &fixture.loader, .dependencies = dependencies[0..runtime.max_loader_files] };
    var stage = try runtime_copy.Stage.initNamed(.{ .allocator = a, .io = io }, fixture.request, inventory, names[0..runtime.max_loader_files]);
    defer stage.deinit();
    try std.testing.expect(stage.copyStage() == .staged);
    const draft = try stage.manifestInputs();
    try std.testing.expectEqual(@as(u16, runtime.max_loader_files), draft.observed.loader_files);
    const root = try stage.root();
    try expectAbsent(root, "loader/libsynthetic.so.1.2");
    const alias = try root.openFile(io, "loader/libsynthetic-000.so.1", .{});
    defer alias.close(io);
    const snapshot = try files.snapshot(alias);
    try std.testing.expectEqual(@as(u32, 1), snapshot.nlink);
    try std.testing.expectEqual(@as(u16, 0o400), snapshot.mode & 0o7777);
    try std.testing.expectEqual(@as(u32, 1), (try files.snapshot(library.file)).nlink);
    try stage.revalidate();
    try noFinal(&fixture);
    try std.testing.expectError(error.LoaderLimit, runtime_copy.Stage.initNamed(.{ .allocator = a, .io = io }, fixture.request, .{ .dynamic_loader = &fixture.loader, .dependencies = dependencies }, names));
    try std.testing.expectError(error.LoaderCollision, runtime_copy.Stage.initNamed(.{ .allocator = a, .io = io }, fixture.request, inventory, &@as([runtime.max_loader_files][]const u8, @splat("duplicate.so"))));
    try std.testing.expectError(error.UnsafePath, runtime_copy.Stage.initNamed(.{ .allocator = a, .io = io }, fixture.request, .{ .dynamic_loader = &fixture.loader, .dependencies = dependencies[0..2] }, &.{ "ld-synthetic.so", "../escape.so" }));
}

test "synthetic COPY deinit retains poisoned partial files and refuses fresh reuse of their output" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    {
        var stage = try fixture.stage(null);
        defer stage.deinit();
        const failure = try expectFailure(stage.copyFault(.short_write));
        try std.testing.expectEqual(error.ShortWrite, failure.err);
        try std.testing.expect(failure.failures.cleanup == null and failure.failures.recording == null);
    }
    const file = try fixture.directory.openFile(io, "output/runtime/bootstrap/azure-cli", .{});
    defer file.close(io);
    const snapshot = try files.snapshot(file);
    try std.testing.expect(snapshot.size > 0 and snapshot.size < launch_size);
    try noFinal(&fixture);
    try std.testing.expectError(error.PathAlreadyExists, fixture.stage(null));
}

test "synthetic COPY streams the exact canonical 256MiB member limit and refuses one excess byte" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.directory.openDir(io, "python3.11", .{});
    defer source.close(io);
    const file = try source.createFile(io, "bound.dat", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    if (linux.errno(linux.ftruncate(file.handle, runtime.max_file_bytes)) != .SUCCESS) return error.FixtureTruncate;
    try file.sync(io);
    var stage = try fixture.stage(null);
    defer stage.deinit();
    try std.testing.expect(stage.copyStage() == .staged);
    const copied = try (try stage.root()).openFile(io, "lib/python3.11/bound.dat", .{});
    defer copied.close(io);
    try std.testing.expectEqual(runtime.max_file_bytes, (try files.snapshot(copied)).size);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try copied.readPositionalAll(io, &byte, runtime.max_file_bytes - 1));
    try std.testing.expectEqual(@as(u8, 0), byte[0]);
    try noFinal(&fixture);
    if (linux.errno(linux.ftruncate(file.handle, runtime.max_file_bytes + 1)) != .SUCCESS) return error.FixtureTruncate;
    try file.sync(io);
    try std.testing.expectError(error.SourceChanged, stage.revalidate());
    fixture.request.output = try fixture.child("excess-output");
    var excess = try fixture.stage(null);
    defer excess.deinit();
    try std.testing.expectEqual(error.UnsafeSource, (try expectFailure(excess.copyStage())).err);
    const output = try fixture.directory.openDir(io, "excess-output", .{});
    defer output.close(io);
    try expectAbsent(output, "azure-runtime.manifest");
    try expectAbsent(output, "azure-runtime.json");
}

test "synthetic COPY refuses an untracked immutable entry inserted before final snapshots" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var stage = try fixture.stage(null);
    defer stage.deinit();
    const failure = try expectFailure(stage.copyFault(.untracked_destination));
    try std.testing.expectEqual(error.CopyChanged, failure.err);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, failure.publication);
    try noFinal(&fixture);
    const file = try fixture.directory.openFile(io, "output/runtime/untracked.py", .{ .path_only = true });
    defer file.close(io);
    try std.testing.expectEqual(@as(u16, 0o400), (try files.snapshot(file)).mode & 0o7777);
}

test "synthetic COPY private loader modes preserve the frozen non-executable source policy" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try write(fixture.directory, "nonexec-loader", "synthetic-nonexec\n", 0o600);
    var loader = try files.RetainedFile.open(io, try fixture.child("nonexec-loader"), .artifact);
    defer loader.close(io);
    const dependencies = [_]types.LoaderSource{
        .{ .file = &loader, .executable = false },
        .{ .file = &loader, .executable = true },
    };
    var stage = try runtime_copy.Stage.initNamed(.{ .allocator = a, .io = io }, fixture.request, .{ .dynamic_loader = &loader, .dependencies = &dependencies }, &.{ "loader-alias.so", "nonexec-loader" });
    defer stage.deinit();
    try std.testing.expect(stage.copyStage() == .staged);
    const root = try stage.root();
    const copied = try root.openFile(io, "loader/nonexec-loader", .{});
    defer copied.close(io);
    const alias = try root.openFile(io, "loader/loader-alias.so", .{});
    defer alias.close(io);
    try std.testing.expectEqual(@as(u16, 0o600), (try files.snapshot(loader.file)).mode & 0o7777);
    try std.testing.expectEqual(@as(u16, 0o500), (try files.snapshot(copied)).mode & 0o7777);
    try std.testing.expectEqual(@as(u16, 0o400), (try files.snapshot(alias)).mode & 0o7777);
    try stage.revalidate();
    try noFinal(&fixture);
}

const WriteProbe = struct {
    const Mode = enum { zero, signal_cancel, io_cancel, overrun, source_replacement, destination_replacement, ancestor_replacement, short_complete };
    table: std.Io.VTable = io.vtable.*,
    mode: Mode,
    fixture: *Fixture,
    signal: ?*core.process.SignalCancellation = null,
    calls: usize = 0,
    ancestor_replaced: bool = false,
    threadlocal var active: ?*WriteProbe = null;

    fn install(self: *WriteProbe) std.Io {
        std.debug.assert(active == null);
        active = self;
        self.table.fileWritePositional = writeSome;
        self.table.checkCancel = checkCancel;
        return .{ .userdata = io.userdata, .vtable = &self.table };
    }
    fn deinit(self: *WriteProbe) void {
        if (self.ancestor_replaced) {
            self.fixture.parent.deleteDir(io, self.fixture.name) catch @panic("synthetic write ancestor cleanup failed");
            self.fixture.parent.rename("write-replaced-ancestor", self.fixture.parent, self.fixture.name, io) catch @panic("synthetic write ancestor restore failed");
        }
        active = null;
    }
    fn checkCancel(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = active.?;
        if (self.mode == .io_cancel and self.calls >= 3) return error.Canceled;
        try io.vtable.checkCancel(userdata);
    }
    fn writeSome(userdata: ?*anyopaque, file: std.Io.File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) std.Io.File.WritePositionalError!usize {
        const self = active.?;
        self.calls += 1;
        // Even the unfixed std write-all loop must terminate this regression.
        if (self.calls > (if (self.mode == .short_complete) @as(usize, 128) else 8)) return error.InputOutput;
        if (header.len != 0 or data.len != 1 or data[0].len == 0 or splat != 1) return error.InputOutput;
        if (self.mode == .zero) return 0;
        if (self.mode == .overrun) return data[0].len + 1;
        const amount = @min(data[0].len, if (self.mode == .short_complete) @as(usize, 4096) else 7);
        const written = try io.vtable.fileWritePositional(userdata, file, header, &.{data[0][0..amount]}, splat, offset);
        if (self.mode == .signal_cancel and self.calls == 3)
            @constCast(self.signal.?.flag()).store(true, .release);
        if (self.calls == 1) switch (self.mode) {
            .source_replacement => self.replaceSource() catch return error.InputOutput,
            .destination_replacement => self.replaceDestination(file, written) catch return error.InputOutput,
            .ancestor_replacement => self.replaceAncestor() catch return error.InputOutput,
            else => {},
        };
        return written;
    }
    fn replaceSource(self: *WriteProbe) !void {
        const source = try self.fixture.directory.openFile(io, "launcher", .{});
        defer source.close(io);
        var bytes: [launch_size]u8 = undefined;
        if (try source.readPositionalAll(io, &bytes, 0) != bytes.len) return error.FixtureRead;
        try self.fixture.directory.rename("launcher", self.fixture.directory, "write-held-launcher", io);
        try write(self.fixture.directory, "launcher", &bytes, 0o500);
    }
    fn replaceDestination(self: *WriteProbe, file: std.Io.File, size: usize) !void {
        const parent = try self.fixture.directory.openDir(io, "output/runtime/bootstrap", .{ .iterate = true });
        defer parent.close(io);
        var bytes: [7]u8 = undefined;
        if (size > bytes.len or try file.readPositionalAll(io, bytes[0..size], 0) != size) return error.FixtureRead;
        try parent.rename("azure-cli", parent, "write-held-copy", io);
        try write(parent, "azure-cli", bytes[0..size], 0o600);
    }
    fn replaceAncestor(self: *WriteProbe) !void {
        try self.fixture.parent.rename(self.fixture.name, self.fixture.parent, "write-replaced-ancestor", io);
        self.ancestor_replaced = true;
        try self.fixture.parent.createDir(io, self.fixture.name, .fromMode(0o700));
    }
};

test "synthetic COPY write progress refuses bounded zero overrun and rechecks cancellation and custody between short writes" {
    for ([_]WriteProbe.Mode{ .zero, .signal_cancel, .io_cancel, .overrun, .source_replacement, .destination_replacement, .ancestor_replacement }) |mode| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var signal = try core.process.SignalCancellation.install();
        defer signal.deinit();
        var probe: WriteProbe = .{ .mode = mode, .fixture = &fixture, .signal = &signal };
        defer probe.deinit();
        var stage = try fixture.stageIo(probe.install(), &signal);
        defer stage.deinit();
        const failure = try expectFailure(stage.copyStage());
        const expected_error: anyerror = switch (mode) {
            .zero => error.ZeroWriteProgress,
            .signal_cancel => error.Cancelled,
            .io_cancel => error.Canceled,
            .overrun => error.InvalidWriteProgress,
            .source_replacement => error.SourceChanged,
            .destination_replacement => error.CopyChanged,
            .ancestor_replacement => error.AncestorChanged,
            .short_complete => unreachable,
        };
        try std.testing.expectEqual(expected_error, failure.err);
        try std.testing.expectEqual(@as(usize, if (mode == .signal_cancel or mode == .io_cancel) 3 else 1), probe.calls);
        try std.testing.expectEqual(files.CommitStatus.visible_not_durable, failure.publication);
        try std.testing.expect(failure.failures.cleanup == null and failure.failures.recording == null);
        if (mode == .signal_cancel or mode == .io_cancel)
            try std.testing.expectEqual(core.diagnostics.Category.cancelled, failure.failures.primary.?.category);
        if (mode == .zero)
            try std.testing.expectEqual(core.diagnostics.Category.local_io, failure.failures.primary.?.category);
        try noFinal(&fixture);
        const partial = try fixture.directory.openFile(io, "output/runtime/bootstrap/azure-cli", .{ .path_only = true, .follow_symlinks = false });
        defer partial.close(io);
        const expected_size: u64 = if (mode == .zero or mode == .overrun) 0 else if (mode == .signal_cancel or mode == .io_cancel) 21 else 7;
        try std.testing.expectEqual(expected_size, (try files.snapshot(partial)).size);
        try std.testing.expectEqual(error.StageSpent, (try expectFailure(stage.copyStage())).err);
    }
}

test "synthetic COPY short writes advance exact offsets and produce unchanged copied bytes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var probe: WriteProbe = .{ .mode = .short_complete, .fixture = &fixture };
    defer probe.deinit();
    var stage = try fixture.stageIo(probe.install(), null);
    defer stage.deinit();
    try std.testing.expect(stage.copyStage() == .staged);
    try std.testing.expect(probe.calls > 16 and probe.calls < 128);
    const file = try (try stage.root()).openFile(io, "bootstrap/azure-cli", .{});
    defer file.close(io);
    var bytes: [launch_size + 1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, launch_size), try file.readPositionalAll(io, &bytes, 0));
    for (bytes[0..launch_size], 0..) |byte, index| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    try stage.barrier().revalidate();
    try noFinal(&fixture);
}
