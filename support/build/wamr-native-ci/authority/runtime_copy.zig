// SPDX-License-Identifier: BSD-3-Clause
//! Retained COPY stage only. No probe, manifest publication, or admission.
//! Stage.initNamed consumes independently retained loader discovery placements.
//! On .staged, root/layout/manifestInputs are borrowed through Stage.deinit.
//! Keep the Stage address stable while any borrowed barrier/view is in use.
//! Runtime directories are 0500, files 0400/0500; output/config remain 0700.
//! The integrated owner must run isolated probes and join their typed evidence
//! before publishing the final runtime document. The physical manifest is
//! retained first so its A metadata cannot be invented or relocated. Mounting a
//! clone over the caller's named root deliberately fails this stage's barrier;
//! isolated helper sealing must not replace the parent's retained root.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const copy = @import("wamr_handoff").retained_copy;
const types = @import("types.zig");
const tx = @import("transaction.zig");
const contracts = @import("contracts.zig");
const runtime = types.runtime;
const linux = std.os.linux;
const chunk_bytes = 64 * 1024;

pub const Outcome = union(enum) {
    staged: void,
    refused: types.Diagnostic,
    poisoned: types.Diagnostic,
};
pub const State = enum { ready, copying, staged, refused, poisoned };
pub const TestFault = enum {
    none,
    short_write,
    before_file_sync,
    before_parent_sync,
    cancel_after_first_chunk,
    replace_destination_same_bytes,
    replace_destination_fifo,
    untracked_destination,
};
pub const Commitments = struct {
    content_sha256: [64]u8,
    metadata_sha256: [64]u8,
    parents_sha256: [64]u8,
};

/// Borrowed until Stage.deinit. These are construction inputs, not an
/// authoritative runtime contract or evidence of successful probes.
pub const ManifestInputs = struct {
    bytes: []const u8,
    manifest: runtime.Artifact,
    observed: runtime.Observed,
    launcher: runtime.Artifact,
    interpreter: runtime.Artifact,
    dynamic_loader: runtime.Artifact,
    loader_dependencies: []runtime.Artifact,
    native_files: []const runtime.Artifact,
    tree_content: core.Sha256,
    tree_metadata: core.Sha256,
    parents_sha256: [64]u8,

    /// The integrated owner must join probe evidence before publishing the
    /// final runtime document. Its physical A record cannot be invented in advance.
    pub fn bindManifest(self: *const ManifestInputs, ctx: types.Context, manifest: *files.RetainedFile) !Commitments {
        if (!std.mem.eql(u8, manifest.path, self.manifest.path) or
            manifest.policy != .private or manifest.file_snapshot.size != self.bytes.len)
            return error.ManifestChanged;
        const digest = try copy.hashRetained(ctx.io, manifest, runtime.max_manifest_bytes, cancellation(ctx));
        if (!std.mem.eql(u8, &digest, self.manifest.sha256)) return error.ManifestChanged;
        var content = self.tree_content;
        var metadata = self.tree_metadata;
        var buffer: [8192]u8 = undefined;
        content.update(try std.fmt.bufPrint(&buffer, "C\tA\t{s}\t{d}\t{s}\n", .{ manifest.path, manifest.file_snapshot.size, &digest }));
        metadata.update(try metadataLine(&buffer, "A", manifest.path, manifest.file_snapshot));
        return .{
            .content_sha256 = std.fmt.bytesToHex(content.finalResult(), .lower),
            .metadata_sha256 = std.fmt.bytesToHex(metadata.finalResult(), .lower),
            .parents_sha256 = self.parents_sha256,
        };
    }
};

const Anchor = struct {
    path: []const u8,
    directories: std.ArrayList(std.Io.Dir) = .empty,
    snapshots: std.ArrayList(files.Snapshot) = .empty,

    fn open(ctx: types.Context, path: []const u8, private: bool) !Anchor {
        if (!std.mem.eql(u8, path, "/")) try files.absoluteFilePath(path);
        var result: Anchor = .{ .path = try ctx.allocator.dupe(u8, path) };
        errdefer result.close(ctx.io);
        var current = try std.Io.Dir.openDirAbsolute(ctx.io, "/", .{ .iterate = true, .follow_symlinks = false });
        result.directories.append(ctx.allocator, current) catch |err| {
            current.close(ctx.io);
            return err;
        };
        try result.snapshots.append(ctx.allocator, try copy.directorySnapshot(current));
        try sourceDirectory(result.snapshots.items[0]);
        if (path.len > 1) {
            var parts = std.mem.splitScalar(u8, path[1..], '/');
            while (parts.next()) |part| {
                if (result.directories.items.len >= files.retained_path_components) return error.UnsafePath;
                current = try current.openDir(ctx.io, part, .{ .iterate = true, .follow_symlinks = false });
                result.directories.append(ctx.allocator, current) catch |err| {
                    current.close(ctx.io);
                    return err;
                };
                const snapshot = try copy.directorySnapshot(current);
                try sourceDirectory(snapshot);
                try result.snapshots.append(ctx.allocator, snapshot);
            }
        }
        if (private) try privateDirectory(try copy.directorySnapshot(current));
        try result.verify(ctx);
        return result;
    }
    fn directory(self: *const Anchor) std.Io.Dir {
        return self.directories.items[self.directories.items.len - 1];
    }
    fn verify(self: *const Anchor, ctx: types.Context) !void {
        try copy.checkCancellation(cancellation(ctx));
        var named = try std.Io.Dir.openDirAbsolute(ctx.io, "/", .{ .iterate = true, .follow_symlinks = false });
        defer named.close(ctx.io);
        var index: usize = 0;
        var parts = std.mem.splitScalar(u8, if (self.path.len > 1) self.path[1..] else "", '/');
        while (true) {
            const retained = try copy.directorySnapshot(self.directories.items[index]);
            const observed = try copy.directorySnapshot(named);
            try sourceDirectory(retained);
            try sourceDirectory(observed);
            if (!copy.sameDirectory(self.snapshots.items[index], retained) or
                !copy.sameDirectory(self.snapshots.items[index], observed))
                return error.AncestorChanged;
            if (index + 1 == self.directories.items.len) break;
            const next = try named.openDir(ctx.io, parts.next().?, .{ .iterate = true, .follow_symlinks = false });
            named.close(ctx.io);
            named = next;
            index += 1;
        }
    }
    fn close(self: *Anchor, io: std.Io) void {
        for (self.directories.items) |dir| dir.close(io);
    }
};

const SourceDirectory = struct {
    directory: std.Io.Dir,
    snapshot: files.Snapshot,
    parent: ?usize,
    name: []const u8,
};
const SourceTree = struct {
    anchor: Anchor,
    directory: usize,
};
const SourceFile = struct {
    path: []const u8,
    parent: ?usize,
    retained: ?files.RetainedFile,
    snapshot: files.Snapshot,
    sha256: [64]u8,
};
const DestinationDirectory = struct {
    directory: std.Io.Dir,
    relative: []const u8,
    parent: ?usize,
    snapshot: files.Snapshot,
    entries: std.StringHashMapUnmanaged(Child) = .empty,
};
const Child = union(enum) { directory: usize, file: usize };
const DestinationFile = struct {
    relative: []const u8,
    snapshot: files.Snapshot,
    sha256: [64]u8,
    parent: usize,
};
const Parent = struct {
    path: []const u8,
    directory: std.Io.Dir,
    snapshot: files.Snapshot,
};
const Entry = struct {
    relative: []const u8,
    snapshot: files.Snapshot,
    sha256: ?[64]u8,
    fn less(_: void, a: Entry, b: Entry) bool {
        return std.mem.order(u8, a.relative, b.relative) == .lt;
    }
};

/// A create-only, single-use stage. Failures retain partial filesystem data;
/// deinit closes custody descriptors only. The owner must retain this object
/// and all borrowed views through probes and final publication.
pub const Stage = struct {
    owner_allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    ctx: types.Context,
    request: types.PrepareRuntime,
    parent: Anchor,
    output: ?Anchor = null,
    startup_config: ?std.Io.Dir = null,
    startup_snapshot: ?files.Snapshot = null,
    source_trees: std.ArrayList(SourceTree) = .empty,
    source_directories: std.ArrayList(SourceDirectory) = .empty,
    source_files: std.ArrayList(SourceFile) = .empty,
    directories: std.ArrayList(DestinationDirectory) = .empty,
    members: std.ArrayList(DestinationFile) = .empty,
    parents: std.ArrayList(Parent) = .empty,
    loader_sources: std.ArrayList(usize) = .empty,
    loader_executable: std.ArrayList(bool) = .empty,
    loader_names: std.ArrayList([]const u8) = .empty,
    dynamic_loader_source: ?usize = null,
    layout_value: types.RuntimeLayout,
    inputs: ?ManifestInputs = null,
    bounds: runtime.Limits = canonicalLimits(),
    manifest_limit: u64 = runtime.max_manifest_bytes,
    observed: runtime.Observed = .{ .files = 0, .directories = 0, .bytes = 0, .depth = 0, .loader_files = 0 },
    state: State = .ready,
    phase: types.Phase = .inputs,
    publication: files.CommitStatus = .not_committed,
    failures: core.diagnostics.Failures = .{},

    pub fn init(ctx: types.Context, request: types.PrepareRuntime, inventory: types.LoaderInventory) !Stage {
        if (inventory.dependencies.len == 0 or inventory.dependencies.len > runtime.max_loader_files)
            return error.LoaderLimit;
        const names = try ctx.allocator.alloc([]const u8, inventory.dependencies.len);
        defer ctx.allocator.free(names);
        for (inventory.dependencies, names) |dependency, *name|
            name.* = std.fs.path.basename(dependency.file.path);
        return initNamed(ctx, request, inventory, names);
    }

    /// DT_NEEDED names need not equal the canonical source basename. Discovery
    /// supplies explicit placements; two aliases are independent byte copies
    /// of a retained single-link source, never hardlink normalization.
    pub fn initNamed(ctx: types.Context, request: types.PrepareRuntime, inventory: types.LoaderInventory, names: []const []const u8) !Stage {
        try copy.checkCancellation(cancellation(ctx));
        try files.absoluteFilePath(request.output);
        try files.absoluteFilePath(request.azure);
        try files.absoluteFilePath(request.az_python);
        try files.absoluteFilePath(request.stdlib);
        if (!std.unicode.utf8ValidateSlice(request.output)) return error.UnsafePath;
        if (request.package_root.len >= runtime.max_directories or
            request.data_root.len >= runtime.max_directories - request.package_root.len or
            request.native_dependency.len > runtime.max_loader_files)
            return error.RuntimeLimit;
        if (inventory.dependencies.len == 0 or inventory.dependencies.len > runtime.max_loader_files)
            return error.LoaderLimit;
        if (names.len != inventory.dependencies.len) return error.LoaderNames;
        for (names, 0..) |name, index| {
            try files.basename(name);
            if (!std.unicode.utf8ValidateSlice(name)) return error.UnsafePath;
            for (names[0..index]) |prior|
                if (std.mem.eql(u8, name, prior)) return error.LoaderCollision;
        }
        const version = try pythonVersion(std.fs.path.basename(request.stdlib));
        const arena = try ctx.allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(ctx.allocator);
        errdefer {
            arena.deinit();
            ctx.allocator.destroy(arena);
        }
        var owned_ctx = ctx;
        owned_ctx.allocator = arena.allocator();
        const output_path = try owned_ctx.allocator.dupe(u8, request.output);
        const runtime_path = try join(owned_ctx, output_path, "runtime");
        if (depth(runtime_path) > runtime.max_depth) return error.RuntimeLimit;
        const layout_value: types.RuntimeLayout = .{
            .output = output_path,
            .root = runtime_path,
            .launcher = try join(owned_ctx, runtime_path, "bootstrap/azure-cli"),
            .interpreter = try join(owned_ctx, runtime_path, "bin/python"),
            .extensions = try join(owned_ctx, runtime_path, "extensions"),
            .loader_directory = try join(owned_ctx, runtime_path, "loader"),
            .startup_config = try join(owned_ctx, output_path, "startup-config"),
            .python_version = try owned_ctx.allocator.dupe(u8, version),
        };
        const output_parent = try Anchor.open(owned_ctx, std.fs.path.dirname(output_path).?, true);
        var self: Stage = .{
            .owner_allocator = ctx.allocator,
            .arena = arena,
            .ctx = owned_ctx,
            .request = request,
            .parent = output_parent,
            .layout_value = layout_value,
        };
        errdefer self.closeHandles();
        try absent(owned_ctx.io, self.parent.directory(), std.fs.path.basename(output_path));
        try self.addTree(request.stdlib);
        for (request.package_root) |path| try self.addTree(path);
        for (request.data_root) |path| try self.addTree(path);
        _ = try self.addExternal(request.azure, true);
        _ = try self.addExternal(request.az_python, true);
        var found_loader = false;
        for (inventory.dependencies, names) |dependency, name| {
            try copy.verifyRetained(ctx.io, dependency.file);
            const is_loader = std.mem.eql(u8, dependency.file.path, inventory.dynamic_loader.path) and
                std.mem.eql(u8, name, std.fs.path.basename(inventory.dynamic_loader.path));
            if (dependency.executable != is_loader) return error.LoaderMode;
            if (is_loader) {
                if (found_loader or !dependency.executable or
                    !copy.sameCustodySnapshot(dependency.file.file_snapshot, inventory.dynamic_loader.file_snapshot))
                    return error.LoaderCollision;
                try copy.verifyRetained(ctx.io, inventory.dynamic_loader);
                found_loader = true;
            }
            var previous_source: ?usize = null;
            for (self.loader_sources.items) |previous|
                if (std.mem.eql(u8, self.source_files.items[previous].path, dependency.file.path)) {
                    previous_source = previous;
                    break;
                };
            // The frozen loader flag controls the private copy's mode, not
            // the source's execute bits; caller-owned inputs remain unchanged.
            const index = previous_source orelse try self.addExternal(dependency.file.path, false);
            if (is_loader) self.dynamic_loader_source = index;
            if (!copy.sameCustodySnapshot(self.source_files.items[index].snapshot, dependency.file.file_snapshot))
                return error.SourceChanged;
            try self.loader_sources.append(owned_ctx.allocator, index);
            try self.loader_executable.append(owned_ctx.allocator, dependency.executable);
            try self.loader_names.append(owned_ctx.allocator, try owned_ctx.allocator.dupe(u8, name));
        }
        if (!found_loader) return error.MissingLoader;
        for (request.native_dependency, 0..) |path, index| {
            try files.absoluteFilePath(path);
            for (request.native_dependency[0..index]) |prior|
                if (std.mem.eql(u8, path, prior)) return error.DuplicateSource;
            var found = false;
            for (self.loader_sources.items) |source|
                if (std.mem.eql(u8, path, self.source_files.items[source].path)) {
                    found = true;
                    break;
                };
            if (!found) return error.UnboundNativeDependency;
        }
        self.request.output = output_path;
        self.request.azure = self.source_files.items[0].path;
        self.request.az_python = self.source_files.items[1].path;
        self.request.validator = try owned_ctx.allocator.dupe(u8, request.validator);
        self.request.stdlib = self.source_trees.items[0].anchor.path;
        self.request.package_root = try duplicateStrings(owned_ctx.allocator, request.package_root);
        self.request.data_root = try duplicateStrings(owned_ctx.allocator, request.data_root);
        self.request.native_dependency = try duplicateStrings(owned_ctx.allocator, request.native_dependency);
        return self;
    }

    pub fn bindInterpreter(self: *Stage, original: *const files.RetainedFile, sha256: [64]u8) !void {
        if (self.state != .ready) return error.StageNotReady;
        if (!std.mem.eql(u8, original.path, self.request.az_python)) return error.SourceChanged;
        try copy.verifyRetained(self.ctx.io, original);
        for (self.source_files.items) |*source| {
            if (!std.mem.eql(u8, source.path, self.request.az_python)) continue;
            if (!copy.sameCustodySnapshot(source.snapshot, original.file_snapshot) or
                !std.mem.eql(u8, &source.sha256, &sha256))
                return error.SourceChanged;
            try copy.verifyRetained(self.ctx.io, &source.retained.?);
            const digest = try copy.hashRetained(self.ctx.io, original, self.bounds.file_bytes, cancellation(self.ctx));
            if (!std.mem.eql(u8, &digest, &sha256)) return error.SourceChanged;
            try copy.verifyRetained(self.ctx.io, original);
            return;
        }
        return error.SourceChanged;
    }

    pub fn copyStage(self: *Stage) Outcome {
        return self.copyImpl(.none);
    }
    pub fn copyFault(self: *Stage, fault: TestFault) Outcome {
        if (!builtin.is_test) @compileError("Runtime copy faults are test-only");
        return self.copyImpl(fault);
    }
    pub fn testBounds(self: *Stage, bounds: runtime.Limits, manifest_bytes: u64) !void {
        if (!builtin.is_test) @compileError("Runtime copy bounds are test-only");
        const maximum = canonicalLimits();
        if (self.state != .ready or bounds.files == 0 or bounds.files > maximum.files or
            bounds.directories == 0 or bounds.directories > maximum.directories or
            bounds.bytes == 0 or bounds.bytes > maximum.bytes or bounds.depth == 0 or bounds.depth > maximum.depth or
            bounds.file_bytes == 0 or bounds.file_bytes > maximum.file_bytes or
            bounds.loader_files == 0 or bounds.loader_files > maximum.loader_files or
            manifest_bytes == 0 or manifest_bytes > runtime.max_manifest_bytes)
            return error.InvalidLimit;
        self.bounds = bounds;
        self.manifest_limit = manifest_bytes;
    }
    pub fn testManifestBound(self: *Stage, manifest_bytes: u64) !void {
        if (!builtin.is_test) @compileError("Runtime manifest bounds are test-only");
        if (self.state != .staged or manifest_bytes == 0 or manifest_bytes > runtime.max_manifest_bytes)
            return error.InvalidLimit;
        const previous = self.manifest_limit;
        defer self.manifest_limit = previous;
        self.manifest_limit = manifest_bytes;
        try self.buildManifest();
    }
    fn copyImpl(self: *Stage, fault: TestFault) Outcome {
        if (self.state != .ready) return .{ .poisoned = self.diagnostic(error.StageSpent) };
        self.state = .copying;
        self.perform(fault) catch |err| {
            self.failures.primary = .{
                .stage = .private_file,
                .category = if (err == error.Cancelled or err == error.Canceled) .cancelled else if (err == error.ZeroWriteProgress) .local_io else if (err == error.AmbiguousWrite or err == error.ShortWrite) .ambiguous else .integrity,
            };
            self.state = if (self.publication == .not_committed) .refused else .poisoned;
            const failure = self.diagnostic(err);
            return if (self.state == .refused) .{ .refused = failure } else .{ .poisoned = failure };
        };
        self.state = .staged;
        return .{ .staged = {} };
    }
    fn perform(self: *Stage, fault: TestFault) !void {
        self.phase = .custody;
        try self.verifySources();
        try self.parent.verify(self.ctx);
        if (self.loader_sources.items.len > self.bounds.loader_files) return error.LoaderLimit;
        try absent(self.ctx.io, self.parent.directory(), std.fs.path.basename(self.request.output));
        self.phase = .construction;
        try self.parent.directory().createDir(self.ctx.io, std.fs.path.basename(self.request.output), .fromMode(0o700));
        self.publication = .visible_not_durable;
        self.output = try Anchor.open(self.ctx, self.request.output, true);
        var empty = self.output.?.directory().iterate();
        if (try empty.next(self.ctx.io) != null) return error.CopyChanged;
        try syncDirectory(self.ctx.io, self.output.?.directory());
        try syncDirectory(self.ctx.io, self.parent.directory());
        self.publication = .durable;
        try self.output.?.directory().createDir(self.ctx.io, "startup-config", .fromMode(0o700));
        self.publication = .visible_not_durable;
        const config = try self.output.?.directory().openDir(self.ctx.io, "startup-config", .{ .iterate = true, .follow_symlinks = false });
        self.startup_config = config;
        try privateDirectory(try copy.directorySnapshot(config));
        self.startup_snapshot = try copy.directorySnapshot(config);
        try syncDirectory(self.ctx.io, config);
        try syncDirectory(self.ctx.io, self.output.?.directory());
        self.publication = .durable;
        const root_index = try self.createDirectory(null, "runtime");
        _ = try self.createDirectory(root_index, "extensions");
        const bootstrap = try self.createDirectory(root_index, "bootstrap");
        const bin = try self.createDirectory(root_index, "bin");
        const lib = try self.createDirectory(root_index, "lib");
        const library = try self.createDirectory(lib, std.fs.path.basename(self.request.stdlib));
        try self.copyMember(0, bootstrap, "azure-cli", true, fault);
        try self.copyMember(1, bin, "python", true, .none);
        for (self.source_trees.items[0 .. 1 + self.request.package_root.len]) |tree|
            try self.copyTree(tree.directory, library);
        if (self.request.data_root.len != 0) {
            const share = try self.createDirectory(root_index, "share");
            for (self.request.data_root, 0..) |_, index| {
                const tree = self.source_trees.items[1 + self.request.package_root.len + index];
                const name = try std.fmt.allocPrint(self.ctx.allocator, "{d:0>3}-{s}", .{ index, std.fs.path.basename(tree.anchor.path) });
                const target = try self.createDirectory(share, name);
                try self.copyTree(tree.directory, target);
            }
        }
        const loader = try self.createDirectory(root_index, "loader");
        for (self.loader_sources.items, self.loader_executable.items, self.loader_names.items) |source, executable, name|
            try self.copyMember(source, loader, name, executable, .none);
        self.observed.loader_files = @intCast(self.loader_sources.items.len);
        if (fault == .untracked_destination) {
            if (!builtin.is_test) return error.InvalidFault;
            const unexpected = try self.directories.items[0].directory.createFile(self.ctx.io, "untracked.py", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer unexpected.close(self.ctx.io);
            try unexpected.writeStreamingAll(self.ctx.io, "not supplied\n");
            try setMode(unexpected.handle, 0o400);
            try unexpected.sync(self.ctx.io);
        }
        try self.freezeDirectories();
        self.phase = .freshness;
        try self.verifySources();
        try self.verifyDestination();
        try self.buildManifest();
        try self.verifyDestination();
        try self.verifySources();
        try copy.checkCancellation(cancellation(self.ctx));
    }

    pub fn root(self: *const Stage) !std.Io.Dir {
        if (self.state != .staged) return error.StageNotReady;
        return self.directories.items[0].directory;
    }
    pub fn outputDirectory(self: *const Stage) !std.Io.Dir {
        if (self.state != .staged) return error.StageNotReady;
        return self.output.?.directory();
    }
    pub fn layout(self: *const Stage) !types.RuntimeLayout {
        if (self.state != .staged) return error.StageNotReady;
        return self.layout_value;
    }
    pub fn manifestInputs(self: *const Stage) !*const ManifestInputs {
        if (self.state != .staged) return error.StageNotReady;
        return &self.inputs.?;
    }
    pub fn barrier(self: *Stage) tx.Barrier {
        return .{ .context = self, .check = checkBarrier };
    }
    fn checkBarrier(raw: *anyopaque) !void {
        const self: *Stage = @ptrCast(@alignCast(raw));
        try self.revalidate();
    }
    pub fn revalidate(self: *Stage) !void {
        if (self.state != .staged) return error.StageNotReady;
        try self.verifySources();
        try self.verifyDestination();
        for (self.parents.items) |parent| {
            if (!copy.sameDirectory(parent.snapshot, try copy.directorySnapshot(parent.directory)))
                return error.AncestorChanged;
            const named = try files.openDirectory(self.ctx.io, parent.path, .artifact);
            defer named.close(self.ctx.io);
            if (!copy.sameDirectory(parent.snapshot, try copy.directorySnapshot(named)))
                return error.AncestorChanged;
        }
    }

    fn addTree(self: *Stage, path: []const u8) !void {
        try files.absoluteFilePath(path);
        if (!std.unicode.utf8ValidateSlice(path)) return error.UnsafePath;
        try disjoint(path, self.request.output);
        for (self.source_trees.items) |tree| try disjoint(path, tree.anchor.path);
        var anchor = try Anchor.open(self.ctx, path, false);
        errdefer anchor.close(self.ctx.io);
        for (self.source_trees.items) |tree|
            if (sameInode(try copy.directorySnapshot(anchor.directory()), self.source_directories.items[tree.directory].snapshot))
                return error.DuplicateSource;
        const index = self.source_directories.items.len;
        try self.source_directories.append(self.ctx.allocator, .{
            .directory = anchor.directory(),
            .snapshot = try copy.directorySnapshot(anchor.directory()),
            .parent = null,
            .name = anchor.path,
        });
        self.source_trees.append(self.ctx.allocator, .{ .anchor = anchor, .directory = index }) catch |err| {
            _ = self.source_directories.pop();
            return err;
        };
    }
    fn addExternal(self: *Stage, path: []const u8, executable: bool) !usize {
        try files.absoluteFilePath(path);
        if (!std.unicode.utf8ValidateSlice(path)) return error.UnsafePath;
        try disjoint(path, self.request.output);
        for (self.source_trees.items) |tree| try disjoint(path, tree.anchor.path);
        for (self.source_files.items) |source|
            if (std.mem.eql(u8, source.path, path)) return error.DuplicateSource;
        const owned = try self.ctx.allocator.dupe(u8, path);
        var retained = try files.RetainedFile.open(self.ctx.io, owned, .artifact);
        errdefer retained.close(self.ctx.io);
        try sourceFile(retained.file_snapshot, self.bounds.file_bytes);
        if (executable) try executableSource(retained.file_snapshot);
        for (self.source_files.items) |source|
            if (sameInode(retained.file_snapshot, source.snapshot)) return error.DuplicateSource;
        const digest = try copy.hashRetained(self.ctx.io, &retained, self.bounds.file_bytes, cancellation(self.ctx));
        const index = self.source_files.items.len;
        try self.source_files.append(self.ctx.allocator, .{
            .path = owned,
            .parent = null,
            .retained = retained,
            .snapshot = retained.file_snapshot,
            .sha256 = digest,
        });
        return index;
    }
    fn createDirectory(self: *Stage, parent: ?usize, name: []const u8) !usize {
        try files.basename(name);
        if (!std.unicode.utf8ValidateSlice(name)) return error.UnsafePath;
        try copy.checkCancellation(cancellation(self.ctx));
        const target = if (parent) |index| self.directories.items[index].directory else self.output.?.directory();
        if (parent) |index| if (self.directories.items[index].entries.contains(name)) return error.PathAlreadyExists;
        const relative = if (parent) |index| if (index == 0) try self.ctx.allocator.dupe(u8, name) else try join(self.ctx, self.directories.items[index].relative, name) else try self.ctx.allocator.dupe(u8, ".");
        const relative_depth: u8 = if (parent == null) 0 else @intCast(depth(relative));
        if (self.observed.directories >= self.bounds.directories or relative_depth > self.bounds.depth or
            (parent != null and self.layout_value.root.len + 1 + relative.len > 4095))
            return error.RuntimeLimit;
        try absent(self.ctx.io, target, name);
        try target.createDir(self.ctx.io, name, .fromMode(0o700));
        self.publication = .visible_not_durable;
        const directory = try target.openDir(self.ctx.io, name, .{ .iterate = true, .follow_symlinks = false });
        var registered = false;
        errdefer if (!registered) directory.close(self.ctx.io);
        try privateDirectory(try copy.directorySnapshot(directory));
        try syncDirectory(self.ctx.io, directory);
        try syncDirectory(self.ctx.io, target);
        const index = self.directories.items.len;
        try self.directories.append(self.ctx.allocator, .{
            .directory = directory,
            .relative = relative,
            .parent = parent,
            .snapshot = try copy.directorySnapshot(directory),
        });
        registered = true;
        if (parent) |parent_index| {
            const key = try self.ctx.allocator.dupe(u8, name);
            try self.directories.items[parent_index].entries.putNoClobber(self.ctx.allocator, key, .{ .directory = index });
        }
        self.observed.directories += 1;
        self.observed.depth = @max(self.observed.depth, relative_depth);
        self.publication = .durable;
        return index;
    }
    fn copyTree(self: *Stage, source_index: usize, target_index: usize) !void {
        const source = self.source_directories.items[source_index];
        if (!copy.sameCustodySnapshot(source.snapshot, try copy.directorySnapshot(source.directory)))
            return error.SourceChanged;
        var iterator = source.directory.iterate();
        while (try iterator.next(self.ctx.io)) |item| {
            try copy.checkCancellation(cancellation(self.ctx));
            try files.basename(item.name);
            if (!std.unicode.utf8ValidateSlice(item.name)) return error.UnsafePath;
            const name = try self.ctx.allocator.dupe(u8, item.name);
            const path_file = try source.directory.openFile(self.ctx.io, name, .{ .path_only = true, .follow_symlinks = false });
            defer path_file.close(self.ctx.io);
            const before = try files.snapshot(path_file);
            switch (before.mode & linux.S.IFMT) {
                linux.S.IFDIR => {
                    try sourceDirectory(before);
                    const destination = try self.createDirectory(target_index, name);
                    const directory = try source.directory.openDir(self.ctx.io, name, .{ .iterate = true, .follow_symlinks = false });
                    const snapshot = copy.directorySnapshot(directory) catch |err| {
                        directory.close(self.ctx.io);
                        return err;
                    };
                    if (!copy.sameCustodySnapshot(before, snapshot)) {
                        directory.close(self.ctx.io);
                        return error.SourceChanged;
                    }
                    const child_index = self.source_directories.items.len;
                    self.source_directories.append(self.ctx.allocator, .{ .directory = directory, .snapshot = before, .parent = source_index, .name = name }) catch |err| {
                        directory.close(self.ctx.io);
                        return err;
                    };
                    try self.copyTree(child_index, destination);
                },
                linux.S.IFREG => {
                    try sourceFile(before, self.bounds.file_bytes);
                    if (std.mem.endsWith(u8, name, ".pth") or
                        std.mem.eql(u8, name, "sitecustomize.py") or std.mem.eql(u8, name, "usercustomize.py"))
                        return error.StartupHook;
                    const index = self.source_files.items.len;
                    try self.source_files.append(self.ctx.allocator, .{
                        .path = name,
                        .parent = source_index,
                        .retained = null,
                        .snapshot = before,
                        .sha256 = undefined,
                    });
                    try self.copyMember(index, target_index, name, before.mode & 0o111 != 0, .none);
                },
                else => return error.UnsafeSource,
            }
            if (!copy.sameCustodySnapshot(before, try files.snapshot(path_file))) return error.SourceChanged;
        }
        if (!copy.sameCustodySnapshot(source.snapshot, try copy.directorySnapshot(source.directory))) return error.SourceChanged;
    }
    fn openSource(self: *Stage, index: usize) !std.Io.File {
        const source = &self.source_files.items[index];
        if (source.parent) |parent| {
            return (files.FileParent{
                .directory = self.source_directories.items[parent].directory,
                .name = source.path,
                .policy = .artifact,
            }).openFile(self.ctx.io);
        }
        try copy.verifyRetained(self.ctx.io, &source.retained.?);
        return (files.FileParent{
            .directory = source.retained.?.directories[source.retained.?.directory_count - 1],
            .name = std.fs.path.basename(source.path),
            .policy = .artifact,
        }).openFile(self.ctx.io);
    }
    fn copyMember(self: *Stage, source_index: usize, parent: usize, name: []const u8, executable: bool, fault: TestFault) !void {
        try files.basename(name);
        try copy.checkCancellation(cancellation(self.ctx));
        const source = self.source_files.items[source_index];
        try sourceFile(source.snapshot, self.bounds.file_bytes);
        const destination_parent = self.directories.items[parent].directory;
        if (self.directories.items[parent].entries.contains(name)) return error.PathAlreadyExists;
        const relative = try join(self.ctx, self.directories.items[parent].relative, name);
        if (self.observed.files >= self.bounds.files or source.snapshot.size > self.bounds.bytes -| self.observed.bytes or
            self.layout_value.root.len + 1 + relative.len > 4095)
            return error.RuntimeLimit;
        try absent(self.ctx.io, destination_parent, name);
        const incoming = try self.openSource(source_index);
        defer incoming.close(self.ctx.io);
        if (!copy.sameCustodySnapshot(source.snapshot, try files.snapshot(incoming))) return error.SourceChanged;
        const outgoing = try destination_parent.createFile(self.ctx.io, name, .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
        defer outgoing.close(self.ctx.io);
        self.publication = .visible_not_durable;
        var writing_snapshot = try files.snapshot(outgoing);
        var hash = core.Sha256.init(.{});
        var buffer: [chunk_bytes]u8 = undefined;
        var offset: u64 = 0;
        while (offset < source.snapshot.size) {
            try copy.checkCancellation(cancellation(self.ctx));
            const amount: usize = @intCast(@min(buffer.len, source.snapshot.size - offset));
            if (try incoming.readPositionalAll(self.ctx.io, buffer[0..amount], offset) != amount)
                return error.SourceChanged;
            if (fault == .short_write) {
                if (amount > 1) try self.writeMemberBytes(source_index, incoming, outgoing, parent, name, &writing_snapshot, buffer[0 .. amount - 1], offset);
                return error.ShortWrite;
            }
            try self.writeMemberBytes(source_index, incoming, outgoing, parent, name, &writing_snapshot, buffer[0..amount], offset);
            hash.update(buffer[0..amount]);
            offset += amount;
            if (fault == .cancel_after_first_chunk) {
                const flag = cancellation(self.ctx) orelse return error.InvalidFault;
                @constCast(flag).store(true, .release);
            }
        }
        try copy.checkCancellation(cancellation(self.ctx));
        if (try incoming.readPositionalAll(self.ctx.io, buffer[0..1], offset) != 0 or
            !copy.sameCustodySnapshot(source.snapshot, try files.snapshot(incoming)))
            return error.SourceChanged;
        const reopened = try self.openSource(source_index);
        defer reopened.close(self.ctx.io);
        if (!copy.sameCustodySnapshot(source.snapshot, try files.snapshot(reopened))) return error.SourceChanged;
        const digest = std.fmt.bytesToHex(hash.finalResult(), .lower);
        if (source.retained != null and !std.mem.eql(u8, &digest, &source.sha256)) return error.SourceChanged;
        self.source_files.items[source_index].sha256 = digest;
        try setMode(outgoing.handle, if (executable) 0o500 else 0o400);
        if (fault == .before_file_sync) return error.AmbiguousWrite;
        try outgoing.sync(self.ctx.io);
        if (fault == .before_parent_sync) return error.AmbiguousWrite;
        try syncDirectory(self.ctx.io, destination_parent);
        const snapshot = try files.snapshot(outgoing);
        try destinationFile(snapshot, source.snapshot.size);
        if (fault == .replace_destination_same_bytes or fault == .replace_destination_fifo) {
            if (!builtin.is_test) return error.InvalidFault;
            try destination_parent.rename(name, destination_parent, "replaced-copy", self.ctx.io);
            if (fault == .replace_destination_fifo) {
                const zname = try self.ctx.allocator.dupeZ(u8, name);
                if (linux.errno(linux.mknodat(destination_parent.handle, zname, linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
                    return error.FixtureFifo;
            } else {
                const replacement = try destination_parent.createFile(self.ctx.io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
                defer replacement.close(self.ctx.io);
                var replacement_snapshot = try files.snapshot(replacement);
                var at: u64 = 0;
                while (at < snapshot.size) {
                    const amount: usize = @intCast(@min(buffer.len, snapshot.size - at));
                    if (try outgoing.readPositionalAll(self.ctx.io, buffer[0..amount], at) != amount) return error.CopyChanged;
                    try self.writeMemberBytes(source_index, incoming, replacement, parent, name, &replacement_snapshot, buffer[0..amount], at);
                    at += amount;
                }
                try setMode(replacement.handle, if (executable) 0o500 else 0o400);
                try replacement.sync(self.ctx.io);
            }
        }
        const named = try (files.FileParent{ .directory = destination_parent, .name = name, .policy = .artifact }).openFile(self.ctx.io);
        defer named.close(self.ctx.io);
        if (!copy.sameCustodySnapshot(snapshot, try files.snapshot(named)) or
            !std.mem.eql(u8, &digest, &try hashFile(self.ctx, named, snapshot, self.bounds.file_bytes)))
            return error.CopyChanged;
        const member_index = self.members.items.len;
        try self.members.append(self.ctx.allocator, .{ .relative = relative, .snapshot = snapshot, .sha256 = digest, .parent = parent });
        try self.directories.items[parent].entries.putNoClobber(self.ctx.allocator, try self.ctx.allocator.dupe(u8, name), .{ .file = member_index });
        self.observed.files += 1;
        self.observed.bytes += snapshot.size;
        self.publication = .durable;
    }
    fn writeMemberBytes(self: *Stage, source_index: usize, incoming: std.Io.File, outgoing: std.Io.File, parent: usize, name: []const u8, expected: *files.Snapshot, bytes: []const u8, offset: u64) !void {
        const size = self.source_files.items[source_index].snapshot.size;
        if (bytes.len == 0 or bytes.len > chunk_bytes or offset > size or bytes.len > size - offset or
            expected.size != offset or expected.mode & linux.S.IFMT != linux.S.IFREG or
            expected.mode & 0o7777 != 0o600 or expected.uid != linux.geteuid() or expected.nlink != 1)
            return error.CopyBounds;
        var at: usize = 0;
        while (at < bytes.len) {
            try self.checkWriteFreshness(source_index, incoming, outgoing, parent, name, expected.*);
            const remaining = bytes[at..];
            const written = try outgoing.writePositional(self.ctx.io, &.{remaining}, offset + at);
            if (written == 0) return error.ZeroWriteProgress;
            if (written > remaining.len) return error.InvalidWriteProgress;
            at += written;
            const observed = try files.snapshot(outgoing);
            // A write may advance size/timestamps, never the retained identity.
            if (!copy.sameDirectory(expected.*, observed) or expected.nlink != observed.nlink or observed.size != offset + at)
                return error.CopyChanged;
            expected.* = observed;
        }
        try self.checkWriteFreshness(source_index, incoming, outgoing, parent, name, expected.*);
    }
    fn checkWriteFreshness(self: *Stage, source_index: usize, incoming: std.Io.File, outgoing: std.Io.File, parent: usize, name: []const u8, expected: files.Snapshot) !void {
        try copy.checkCancellation(cancellation(self.ctx));
        try self.ctx.io.checkCancel();
        try self.parent.verify(self.ctx);
        try self.output.?.verify(self.ctx);
        try privateDirectory(try copy.directorySnapshot(self.output.?.directory()));
        var destination_index: ?usize = parent;
        while (destination_index) |index| {
            const directory = self.directories.items[index];
            if (!copy.sameDirectory(directory.snapshot, try copy.directorySnapshot(directory.directory)))
                return error.CopyChanged;
            const ancestor = if (directory.parent) |ancestor_index| self.directories.items[ancestor_index].directory else self.output.?.directory();
            const named = try ancestor.openDir(self.ctx.io, if (directory.parent == null) "runtime" else std.fs.path.basename(directory.relative), .{ .iterate = true, .follow_symlinks = false });
            defer named.close(self.ctx.io);
            if (!copy.sameDirectory(directory.snapshot, try copy.directorySnapshot(named))) return error.CopyChanged;
            destination_index = directory.parent;
        }
        const source = self.source_files.items[source_index];
        var source_index_directory = source.parent;
        while (source_index_directory) |index| {
            const directory = self.source_directories.items[index];
            if (!copy.sameCustodySnapshot(directory.snapshot, try copy.directorySnapshot(directory.directory)))
                return error.SourceChanged;
            if (directory.parent) |ancestor_index| {
                const named = try self.source_directories.items[ancestor_index].directory.openDir(self.ctx.io, directory.name, .{ .iterate = true, .follow_symlinks = false });
                defer named.close(self.ctx.io);
                if (!copy.sameCustodySnapshot(directory.snapshot, try copy.directorySnapshot(named))) return error.SourceChanged;
            } else {
                for (self.source_trees.items) |*tree| if (tree.directory == index) try tree.anchor.verify(self.ctx);
            }
            source_index_directory = directory.parent;
        }
        if (!copy.sameCustodySnapshot(source.snapshot, try files.snapshot(incoming))) return error.SourceChanged;
        const reopened = try self.openSource(source_index);
        defer reopened.close(self.ctx.io);
        if (!copy.sameCustodySnapshot(source.snapshot, try files.snapshot(reopened))) return error.SourceChanged;
        if (!copy.sameCustodySnapshot(expected, try files.snapshot(outgoing))) return error.CopyChanged;
        const named = try (files.FileParent{ .directory = self.directories.items[parent].directory, .name = name, .policy = .artifact }).openFile(self.ctx.io);
        defer named.close(self.ctx.io);
        if (!copy.sameCustodySnapshot(expected, try files.snapshot(named))) return error.CopyChanged;
        try copy.checkCancellation(cancellation(self.ctx));
        try self.ctx.io.checkCancel();
    }
    fn freezeDirectories(self: *Stage) !void {
        var index = self.directories.items.len;
        while (index != 0) {
            index -= 1;
            try copy.checkCancellation(cancellation(self.ctx));
            const directory = self.directories.items[index].directory;
            self.publication = .visible_not_durable;
            try setMode(directory.handle, 0o500);
            try syncDirectory(self.ctx.io, directory);
        }
        try syncDirectory(self.ctx.io, self.output.?.directory());
        for (self.directories.items) |*directory| directory.snapshot = try copy.directorySnapshot(directory.directory);
        self.publication = .durable;
    }
    fn verifySources(self: *Stage) !void {
        try copy.checkCancellation(cancellation(self.ctx));
        for (self.source_trees.items) |*tree| try tree.anchor.verify(self.ctx);
        for (self.source_directories.items) |directory| {
            try sourceDirectory(try copy.directorySnapshot(directory.directory));
            if (!copy.sameCustodySnapshot(directory.snapshot, try copy.directorySnapshot(directory.directory)))
                return error.SourceChanged;
            if (directory.parent) |parent| {
                const named = try self.source_directories.items[parent].directory.openDir(self.ctx.io, directory.name, .{ .iterate = true, .follow_symlinks = false });
                defer named.close(self.ctx.io);
                if (!copy.sameCustodySnapshot(directory.snapshot, try copy.directorySnapshot(named))) return error.SourceChanged;
            }
        }
        for (self.source_files.items, 0..) |source, index| {
            const file = try self.openSource(index);
            defer file.close(self.ctx.io);
            if (!copy.sameCustodySnapshot(source.snapshot, try files.snapshot(file))) return error.SourceChanged;
            const digest = try hashFile(self.ctx, file, source.snapshot, self.bounds.file_bytes);
            if (!std.mem.eql(u8, &digest, &source.sha256)) return error.SourceChanged;
        }
    }
    fn verifyDestination(self: *Stage) !void {
        try copy.checkCancellation(cancellation(self.ctx));
        try self.parent.verify(self.ctx);
        try self.output.?.verify(self.ctx);
        try privateDirectory(try copy.directorySnapshot(self.output.?.directory()));
        try privateDirectory(try copy.directorySnapshot(self.startup_config.?));
        if (!copy.sameDirectory(self.startup_snapshot.?, try copy.directorySnapshot(self.startup_config.?)))
            return error.CopyChanged;
        const config = try self.output.?.directory().openDir(self.ctx.io, "startup-config", .{ .iterate = true, .follow_symlinks = false });
        defer config.close(self.ctx.io);
        if (!copy.sameDirectory(self.startup_snapshot.?, try copy.directorySnapshot(config))) return error.CopyChanged;
        if (self.state == .copying) {
            try absent(self.ctx.io, self.output.?.directory(), "azure-runtime.manifest");
            try absent(self.ctx.io, self.output.?.directory(), "azure-runtime.json");
        }
        for (self.directories.items) |directory| {
            const snapshot = try copy.directorySnapshot(directory.directory);
            if (snapshot.mode & 0o7777 != 0o500 or snapshot.uid != linux.geteuid() or
                !copy.sameCustodySnapshot(directory.snapshot, snapshot))
                return error.CopyChanged;
            const parent = if (directory.parent) |index| self.directories.items[index].directory else self.output.?.directory();
            const named = try parent.openDir(self.ctx.io, if (directory.parent == null) "runtime" else std.fs.path.basename(directory.relative), .{ .iterate = true, .follow_symlinks = false });
            defer named.close(self.ctx.io);
            if (!copy.sameCustodySnapshot(snapshot, try copy.directorySnapshot(named))) return error.CopyChanged;
            var iterator = directory.directory.iterate();
            var count: usize = 0;
            while (try iterator.next(self.ctx.io)) |entry| {
                try copy.checkCancellation(cancellation(self.ctx));
                try files.basename(entry.name);
                const expected = directory.entries.get(entry.name) orelse return error.CopyChanged;
                const child = try directory.directory.openFile(self.ctx.io, entry.name, .{ .path_only = true, .follow_symlinks = false });
                defer child.close(self.ctx.io);
                const expected_snapshot = switch (expected) {
                    .directory => |index| self.directories.items[index].snapshot,
                    .file => |index| self.members.items[index].snapshot,
                };
                if (!copy.sameCustodySnapshot(expected_snapshot, try files.snapshot(child))) return error.CopyChanged;
                count += 1;
            }
            if (count != directory.entries.count() or
                !copy.sameCustodySnapshot(snapshot, try copy.directorySnapshot(directory.directory)))
                return error.CopyChanged;
        }
        for (self.members.items) |member| {
            const named = try (files.FileParent{
                .directory = self.directories.items[member.parent].directory,
                .name = std.fs.path.basename(member.relative),
                .policy = .artifact,
            }).openFile(self.ctx.io);
            defer named.close(self.ctx.io);
            try destinationFile(try files.snapshot(named), member.snapshot.size);
            if (!copy.sameCustodySnapshot(member.snapshot, try files.snapshot(named)) or
                !std.mem.eql(u8, &member.sha256, &try hashFile(self.ctx, named, member.snapshot, self.bounds.file_bytes)))
                return error.CopyChanged;
        }
    }
    fn buildManifest(self: *Stage) !void {
        const a = self.ctx.allocator;
        var entries: std.ArrayList(Entry) = .empty;
        for (self.directories.items) |directory|
            try entries.append(a, .{ .relative = directory.relative, .snapshot = directory.snapshot, .sha256 = null });
        for (self.members.items) |member|
            try entries.append(a, .{ .relative = member.relative, .snapshot = member.snapshot, .sha256 = member.sha256 });
        std.mem.sort(Entry, entries.items, {}, Entry.less);
        var manifest: std.ArrayList(u8) = .empty;
        try appendBounded(a, &manifest, contracts.manifest.header, self.manifest_limit);
        var content = core.Sha256.init(.{});
        var metadata = core.Sha256.init(.{});
        var buffer: [8192]u8 = undefined;
        var physical: [512]u8 = undefined;
        var native: std.ArrayList(runtime.Artifact) = .empty;
        var loaders: std.ArrayList(runtime.Artifact) = .empty;
        var launcher: ?runtime.Artifact = null;
        var interpreter: ?runtime.Artifact = null;
        var dynamic_loader: ?runtime.Artifact = null;
        for (entries.items) |entry| {
            try copy.checkCancellation(cancellation(self.ctx));
            const kind: u8 = if (entry.sha256 == null) 'D' else 'F';
            const digest: []const u8 = if (entry.sha256) |value| &value else "-";
            const role_value = role(entry.relative);
            content.update(try std.fmt.bufPrint(&buffer, "C\t{c}\t{s}\t{d}\t{s}\n", .{ kind, entry.relative, if (entry.sha256 == null) @as(u64, 0) else entry.snapshot.size, digest }));
            metadata.update(try metadataLine(&buffer, "M", entry.relative, entry.snapshot));
            try appendBounded(a, &manifest, try std.fmt.bufPrint(&buffer, "{c}\t{s}\t{s}\t{s}\t{s}\n", .{ kind, role_value, entry.relative, try physicalLine(&physical, entry.snapshot), digest }), self.manifest_limit);
            if (entry.sha256) |value| {
                const item = try self.memberArtifact(entry.relative, entry.snapshot.size, value);
                if (std.mem.eql(u8, role_value, "launcher")) launcher = item;
                if (std.mem.eql(u8, role_value, "interpreter")) interpreter = item;
                if (std.mem.eql(u8, role_value, "native-extension") or std.mem.eql(u8, role_value, "interpreter"))
                    try native.append(a, item);
                if (std.mem.startsWith(u8, entry.relative, "loader/")) {
                    try loaders.append(a, item);
                    if (std.mem.eql(u8, std.fs.path.basename(item.path), std.fs.path.basename(self.source_files.items[self.dynamic_loader_source.?].path)))
                        dynamic_loader = item;
                }
            }
        }
        if (dynamic_loader == null or launcher == null or interpreter == null) return error.MissingLoader;
        for (loaders.items) |item| {
            const member = self.findMember(item.path[self.layout_value.root.len + 1 ..]).?;
            content.update(try std.fmt.bufPrint(&buffer, "C\tL\t{s}\t{d}\t{s}\n", .{ item.path, item.size, item.sha256 }));
            metadata.update(try metadataLine(&buffer, "L", item.path, member.snapshot));
            try appendBounded(a, &manifest, try std.fmt.bufPrint(&buffer, "L\tloader-dependency\t{s}\t{s}\t{s}\n", .{ item.path, try physicalLine(&physical, member.snapshot), item.sha256 }), self.manifest_limit);
        }
        var parent_paths: std.ArrayList([]const u8) = .empty;
        try addParents(a, &parent_paths, self.layout_value.root);
        for (loaders.items) |item| try addParents(a, &parent_paths, item.path);
        std.mem.sort([]const u8, parent_paths.items, {}, struct {
            fn less(_: void, left: []const u8, right: []const u8) bool {
                return std.mem.order(u8, left, right) == .lt;
            }
        }.less);
        var parents_hash = core.Sha256.init(.{});
        var previous: ?[]const u8 = null;
        for (parent_paths.items) |path| {
            if (previous != null and std.mem.eql(u8, previous.?, path)) continue;
            const directory = try files.openDirectory(self.ctx.io, path, .artifact);
            errdefer directory.close(self.ctx.io);
            const snapshot = try copy.directorySnapshot(directory);
            try sourceDirectory(snapshot);
            const line = try std.fmt.bufPrint(&buffer, "P\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n", .{ path, snapshot.dev_major, snapshot.dev_minor, snapshot.ino, snapshot.mode, files.hostUid(snapshot.uid), files.hostGid(snapshot.gid) });
            parents_hash.update(line);
            try appendBounded(a, &manifest, line, self.manifest_limit);
            try self.parents.append(a, .{ .path = path, .directory = directory, .snapshot = snapshot });
            previous = path;
        }
        const manifest_digest = try a.dupe(u8, &std.fmt.bytesToHex(tx.hash(manifest.items), .lower));
        self.inputs = .{
            .bytes = manifest.items,
            .manifest = .{ .path = try join(self.ctx, self.request.output, "azure-runtime.manifest"), .size = manifest.items.len, .sha256 = manifest_digest },
            .observed = self.observed,
            .launcher = launcher.?,
            .interpreter = interpreter.?,
            .dynamic_loader = dynamic_loader.?,
            .loader_dependencies = loaders.items,
            .native_files = native.items,
            .tree_content = content,
            .tree_metadata = metadata,
            .parents_sha256 = std.fmt.bytesToHex(parents_hash.finalResult(), .lower),
        };
    }
    fn findMember(self: *const Stage, relative: []const u8) ?DestinationFile {
        for (self.members.items) |member| if (std.mem.eql(u8, member.relative, relative)) return member;
        return null;
    }
    fn memberArtifact(self: *Stage, relative: []const u8, size: u64, digest: [64]u8) !runtime.Artifact {
        return .{ .path = try join(self.ctx, self.layout_value.root, relative), .size = size, .sha256 = try self.ctx.allocator.dupe(u8, &digest) };
    }
    fn diagnostic(self: *const Stage, err: anyerror) types.Diagnostic {
        return .{ .phase = self.phase, .err = err, .publication = self.publication, .failures = self.failures };
    }
    fn closeHandles(self: *Stage) void {
        for (self.parents.items) |parent| parent.directory.close(self.ctx.io);
        for (self.directories.items) |directory| directory.directory.close(self.ctx.io);
        for (self.source_files.items) |*source| if (source.retained) |*retained| retained.close(self.ctx.io);
        for (self.source_directories.items) |directory| if (directory.parent != null) directory.directory.close(self.ctx.io);
        for (self.source_trees.items) |*tree| tree.anchor.close(self.ctx.io);
        if (self.startup_config) |config| config.close(self.ctx.io);
        if (self.output) |*output| output.close(self.ctx.io);
        self.parent.close(self.ctx.io);
    }
    pub fn deinit(self: *Stage) void {
        self.closeHandles();
        self.arena.deinit();
        self.owner_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn canonicalLimits() runtime.Limits {
    return .{ .files = runtime.max_files, .directories = runtime.max_directories, .bytes = runtime.max_bytes, .depth = runtime.max_depth, .file_bytes = runtime.max_file_bytes, .loader_files = runtime.max_loader_files };
}
fn cancellation(ctx: types.Context) ?*const std.atomic.Value(bool) {
    return if (ctx.signal) |signal| signal.flag() else null;
}
fn sourceDirectory(value: files.Snapshot) !void {
    if (!value.mask.GID or value.mode & linux.S.IFMT != linux.S.IFDIR or
        (value.uid != linux.geteuid() and value.uid != 0) or value.mode & 0o022 != 0)
        return error.UnsafeSource;
}
fn privateDirectory(value: files.Snapshot) !void {
    if (!value.mask.GID or value.mode & linux.S.IFMT != linux.S.IFDIR or
        value.uid != linux.geteuid() or value.mode & 0o7777 != 0o700)
        return error.UnsafeDestination;
}
fn sourceFile(value: files.Snapshot, limit: u64) !void {
    if (!value.mask.GID or value.mode & linux.S.IFMT != linux.S.IFREG or
        (value.uid != linux.geteuid() and value.uid != 0) or value.mode & 0o7022 != 0 or
        value.nlink != 1 or value.size == 0 or value.size > limit)
        return error.UnsafeSource;
}
fn executableSource(value: files.Snapshot) !void {
    if (value.mode & 0o111 == 0 or value.size > 64 * 1024 * 1024) return error.UnsafeSource;
}
fn destinationFile(value: files.Snapshot, size: u64) !void {
    if (!value.mask.GID or value.mode & linux.S.IFMT != linux.S.IFREG or value.uid != linux.geteuid() or
        (value.mode & 0o7777 != 0o400 and value.mode & 0o7777 != 0o500) or
        value.nlink != 1 or value.size != size)
        return error.UnsafeDestination;
}
fn absent(io: std.Io, parent: std.Io.Dir, name: []const u8) !void {
    const existing = parent.openFile(io, name, .{ .path_only = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    existing.close(io);
    return error.PathAlreadyExists;
}
fn hashFile(ctx: types.Context, file: std.Io.File, expected: files.Snapshot, limit: u64) ![64]u8 {
    try sourceFile(expected, limit);
    if (!copy.sameCustodySnapshot(expected, try files.snapshot(file))) return error.SourceChanged;
    var hash = core.Sha256.init(.{});
    var buffer: [chunk_bytes]u8 = undefined;
    var offset: u64 = 0;
    while (offset < expected.size) {
        try copy.checkCancellation(cancellation(ctx));
        const amount: usize = @intCast(@min(buffer.len, expected.size - offset));
        if (try file.readPositionalAll(ctx.io, buffer[0..amount], offset) != amount) return error.SourceChanged;
        hash.update(buffer[0..amount]);
        offset += amount;
    }
    if (try file.readPositionalAll(ctx.io, buffer[0..1], offset) != 0 or
        !copy.sameCustodySnapshot(expected, try files.snapshot(file)))
        return error.SourceChanged;
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}
fn physicalLine(buffer: []u8, value: files.Snapshot) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}", .{
        value.dev_major, value.dev_minor, value.ino, value.mode, files.hostUid(value.uid), files.hostGid(value.gid), value.nlink, value.size, value.mtime.sec, value.mtime.nsec, value.ctime.sec, value.ctime.nsec,
    });
}
fn metadataLine(buffer: []u8, tag: []const u8, path: []const u8, value: files.Snapshot) ![]const u8 {
    var physical: [512]u8 = undefined;
    return std.fmt.bufPrint(buffer, "{s}\t{s}\t{s}\n", .{ tag, path, try physicalLine(&physical, value) });
}
fn appendBounded(a: std.mem.Allocator, list: *std.ArrayList(u8), bytes: []const u8, limit: u64) !void {
    if (bytes.len > limit -| list.items.len) return error.ManifestLimit;
    try list.appendSlice(a, bytes);
}
fn addParents(a: std.mem.Allocator, paths: *std.ArrayList([]const u8), path: []const u8) !void {
    var parent = std.fs.path.dirname(path).?;
    while (true) {
        try paths.append(a, parent);
        if (std.mem.eql(u8, parent, "/")) break;
        parent = std.fs.path.dirname(parent).?;
    }
}
fn role(relative: []const u8) []const u8 {
    if (std.mem.eql(u8, relative, "bootstrap/azure-cli")) return "launcher";
    if (std.mem.eql(u8, relative, "bin/python")) return "interpreter";
    if (std.mem.indexOf(u8, std.fs.path.basename(relative), ".so") != null) return "native-extension";
    if (std.mem.startsWith(u8, relative, "lib/")) return "python-module";
    if (std.mem.startsWith(u8, relative, "share/")) return "fixed-data";
    return "runtime";
}
fn pythonVersion(name: []const u8) ![]const u8 {
    if (!std.mem.startsWith(u8, name, "python") or name.len > 16) return error.PythonVersion;
    const value = name["python".len..];
    var parts = std.mem.splitScalar(u8, value, '.');
    const major = parts.next() orelse return error.PythonVersion;
    const minor = parts.next() orelse return error.PythonVersion;
    if (parts.next() != null) return error.PythonVersion;
    for ([_][]const u8{ major, minor }) |part| {
        if (part.len == 0 or part.len > 3) return error.PythonVersion;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return error.PythonVersion;
    }
    return value;
}
fn contains(parent: []const u8, path: []const u8) bool {
    return std.mem.eql(u8, parent, path) or (path.len > parent.len and std.mem.startsWith(u8, path, parent) and path[parent.len] == '/');
}
fn sameInode(left: files.Snapshot, right: files.Snapshot) bool {
    return left.dev_major == right.dev_major and left.dev_minor == right.dev_minor and left.ino == right.ino;
}
fn disjoint(left: []const u8, right: []const u8) !void {
    if (contains(left, right) or contains(right, left)) return error.DuplicateSource;
}
fn duplicateStrings(a: std.mem.Allocator, strings: []const []const u8) ![]const []const u8 {
    const result = try a.alloc([]const u8, strings.len);
    for (strings, result) |source, *target| target.* = try a.dupe(u8, source);
    return result;
}
fn join(ctx: types.Context, parent: []const u8, name: []const u8) ![]const u8 {
    return std.fs.path.join(ctx.allocator, &.{ parent, name });
}
fn depth(path: []const u8) usize {
    var parts = std.mem.splitScalar(u8, path, '/');
    var count: usize = 0;
    while (parts.next()) |part| if (part.len != 0) {
        count += 1;
    };
    return count;
}
fn setMode(fd: linux.fd_t, mode: u32) !void {
    while (true) switch (linux.errno(linux.fchmod(fd, mode))) {
        .SUCCESS => return,
        .INTR => continue,
        else => return error.ModeChanged,
    };
}
fn syncDirectory(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
