// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const physical = @import("custody_files.zig");
const limits = @import("custody_limits.zig");
const source = @import("source_custody.zig");
const Sha256 = core.Sha256;
const linux = std.os.linux;
const process = core.process;

pub const manifest_paths = [_][]const u8{
    "support/tools/hyperv/local_boot/build.zig",
    "support/tools/hyperv/local_boot/build.zig.zon",
};

const Pin = struct { url: []const u8, hash: []const u8 };
pub const Package = struct {
    name: []const u8,
    files: usize,
    directories: usize,
    bytes: usize,
    tree_sha256: [64]u8,
    physical_sha256: [64]u8,
    manifest_sha256: ?[64]u8,
    manifest_bytes: usize,
    dependencies: [][]const u8,
};
pub const PackageSet = struct {
    roots: usize,
    files: usize,
    directories: usize,
    bytes: usize,
    closure_sha256: [64]u8,
    physical_sha256: [64]u8,
    packages: []Package,

    pub fn deinit(self: *PackageSet, allocator: std.mem.Allocator) void {
        for (self.packages) |package| {
            allocator.free(package.name);
            for (package.dependencies) |dependency| allocator.free(dependency);
            allocator.free(package.dependencies);
        }
        allocator.free(self.packages);
        self.* = undefined;
    }
};

fn dependencyNode(allocator: std.mem.Allocator, bytes: []const u8) !struct {
    source_bytes: [:0]u8,
    ast: std.zig.Ast,
    zoir: std.zig.Zoir,
    node: ?std.zig.Zoir.Node,
} {
    if (bytes.len > 4 * limits.mib or bytes.len == 0) return error.InvalidManifest;
    const zero = try allocator.dupeZ(u8, bytes);
    errdefer allocator.free(zero);
    var ast = try std.zig.Ast.parse(allocator, zero, .zon);
    errdefer ast.deinit(allocator);
    if (ast.errors.len != 0) return error.InvalidManifest;
    const zoir = try std.zig.ZonGen.generate(allocator, ast, .{});
    errdefer zoir.deinit(allocator);
    if (zoir.hasCompileErrors() or zoir.nodes.len > 4096) return error.InvalidManifest;
    const root = std.zig.Zoir.Node.Index.root.get(zoir);
    if (root != .struct_literal) return error.InvalidManifest;
    var found: ?std.zig.Zoir.Node = null;
    for (root.struct_literal.names, 0..) |name, i| {
        if (!std.mem.eql(u8, name.get(zoir), "dependencies")) continue;
        if (found != null) return error.InvalidManifest;
        found = root.struct_literal.vals.at(@intCast(i)).get(zoir);
    }
    if (found) |node| switch (node) {
        .struct_literal, .empty_literal => {},
        else => return error.InvalidManifest,
    };
    return .{ .source_bytes = zero, .ast = ast, .zoir = zoir, .node = found };
}

pub fn pinnedManifest(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var parsed = try dependencyNode(allocator, bytes);
    defer allocator.free(parsed.source_bytes);
    defer parsed.ast.deinit(allocator);
    defer parsed.zoir.deinit(allocator);
    const dependencies = parsed.node orelse return error.UnpinnedDependency;
    if (dependencies != .struct_literal or dependencies.struct_literal.names.len != 1 or
        !std.mem.eql(u8, dependencies.struct_literal.names[0].get(parsed.zoir), "miz_source"))
        return error.UnpinnedDependency;
    const index = dependencies.struct_literal.vals.at(0);
    const pin = try std.zon.parse.fromZoirNodeAlloc(Pin, allocator, parsed.ast, parsed.zoir, index, null, .{});
    defer {
        allocator.free(pin.url);
        allocator.free(pin.hash);
    }
    if (!std.mem.eql(u8, pin.url, limits.miz_url) or
        !std.mem.eql(u8, pin.hash, limits.miz_package_hash))
        return error.UnpinnedDependency;
}

pub fn packageDependencies(allocator: std.mem.Allocator, bytes: []const u8) ![][]const u8 {
    var parsed = try dependencyNode(allocator, bytes);
    defer allocator.free(parsed.source_bytes);
    defer parsed.ast.deinit(allocator);
    defer parsed.zoir.deinit(allocator);
    const dependencies = parsed.node orelse return allocator.alloc([]const u8, 0);
    if (dependencies == .empty_literal) return allocator.alloc([]const u8, 0);
    const result = try allocator.alloc([]const u8, dependencies.struct_literal.names.len);
    errdefer allocator.free(result);
    for (dependencies.struct_literal.names, 0..) |_, i| {
        const node = dependencies.struct_literal.vals.at(@intCast(i)).get(parsed.zoir);
        if (node != .struct_literal) return error.InvalidManifest;
        var found: ?[]const u8 = null;
        for (node.struct_literal.names, 0..) |name, j| {
            if (std.mem.eql(u8, name.get(parsed.zoir), "hash")) {
                if (found != null) return error.InvalidManifest;
                const pin = try std.zon.parse.fromZoirNodeAlloc([]const u8, allocator, parsed.ast, parsed.zoir, node.struct_literal.vals.at(@intCast(j)), null, .{});
                found = pin;
            }
        }
        result[i] = found orelse return error.InvalidManifest;
        try limits.packageName(result[i]);
        for (result[0..i]) |prior|
            if (std.mem.eql(u8, prior, result[i])) return error.InvalidManifest;
    }
    std.mem.sort([]const u8, result, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    return result;
}

const Stats = struct {
    files: usize = 0,
    directories: usize = 0,
    bytes: usize = 0,
    content: Sha256,
    physical_hash: Sha256,
};

fn packageDirectory(io: std.Io, parent: std.Io.Dir, name: []const u8) !std.Io.Dir {
    const dir = try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
    errdefer dir.close(io);
    const info = try files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
    if (info.mode & linux.S.IFMT != linux.S.IFDIR or info.uid != linux.geteuid())
        return error.UnsafePackageDirectory;
    return dir;
}

fn packageFile(io: std.Io, dir: std.Io.Dir, name: []const u8, before: files.Snapshot) !physical.File {
    const file = try dir.openFile(io, name, .{ .follow_symlinks = false });
    defer file.close(io);
    if (before.mode & linux.S.IFMT != linux.S.IFREG or before.uid != linux.geteuid() or
        before.nlink != 1 or before.size > limits.dependency_file or
        !files.sameSnapshot(before, try files.snapshot(file)))
        return error.UnsafePackageFile;
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        const count = try file.readPositionalAll(io, buffer[0..@intCast(@min(buffer.len, before.size - offset))], offset);
        if (count == 0) return error.PackageChanged;
        hash.update(buffer[0..count]);
        offset += count;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0 or
        !files.sameSnapshot(before, try files.snapshot(file)))
        return error.PackageChanged;
    return .{
        .bytes = before.size,
        .sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
        .metadata = physical.metadata(before),
    };
}

fn scan(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, prefix: []const u8, state: *Stats) !void {
    const before = try files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
    if (before.uid != linux.geteuid()) return error.UnsafePackageDirectory;
    try limits.addBounded(&state.directories, 1, limits.dependency_entries - state.files);
    try physical.bind(allocator, &state.content, .{ "directory", prefix, before.mode & 0o7777 });
    try physical.bind(allocator, &state.physical_hash, .{ "directory", prefix, physical.metadata(before) });
    var entries: std.ArrayList([]const u8) = .empty;
    defer {
        for (entries.items) |name| allocator.free(name);
        entries.deinit(allocator);
    }
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entries.items.len >= limits.dependency_entries - state.files - state.directories)
            return error.LimitExceeded;
        try files.basename(entry.name);
        try entries.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, entries.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    for (entries.items) |name| {
        const relative = if (prefix.len == 0) try allocator.dupe(u8, name) else try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name });
        defer allocator.free(relative);
        try limits.relative(relative, 1024, 64);
        const member = try dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
        defer member.close(io);
        const info = try files.snapshot(member);
        if (info.mode & linux.S.IFMT == linux.S.IFDIR) {
            const child = try packageDirectory(io, dir, name);
            defer child.close(io);
            if (!files.sameSnapshot(info, try files.snapshot(.{ .handle = child.handle, .flags = .{ .nonblocking = false } })))
                return error.PackageChanged;
            try scan(allocator, io, child, relative, state);
        } else if (info.mode & linux.S.IFMT == linux.S.IFREG) {
            if (info.uid != linux.geteuid() or info.nlink != 1 or info.size > limits.dependency_file)
                return error.UnsafePackageFile;
            try limits.addBounded(&state.files, 1, limits.dependency_entries - state.directories);
            try limits.addBounded(&state.bytes, @intCast(info.size), limits.dependency_bytes);
            const member_record = try packageFile(io, dir, name, info);
            if (!std.meta.eql(member_record.metadata, physical.metadata(info)))
                return error.PackageChanged;
            try physical.bind(allocator, &state.content, .{ "file", relative, info.size, info.mode & 0o7777, member_record.sha256 });
            try physical.bind(allocator, &state.physical_hash, .{ "file", relative, info.size, member_record.sha256, physical.metadata(info) });
        } else return error.UnsafePackageEntry;
        const reopened = try dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
        defer reopened.close(io);
        if (!files.sameSnapshot(info, try files.snapshot(reopened))) return error.PackageChanged;
    }
    if (!files.sameSnapshot(before, try files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } })))
        return error.PackageChanged;
}

fn inventory(allocator: std.mem.Allocator, io: std.Io, packages: std.Io.Dir, name: []const u8) !Package {
    try limits.packageName(name);
    const dir = try packageDirectory(io, packages, name);
    defer dir.close(io);
    var state: Stats = .{ .content = Sha256.init(.{}), .physical_hash = Sha256.init(.{}) };
    state.content.update("hyperv-native-tree-v1\x00");
    state.physical_hash.update("hyperv-native-physical-v1\x00");
    try scan(allocator, io, dir, "", &state);
    if (state.files == 0) return error.EmptyPackage;
    var manifest_sha256: ?[64]u8 = null;
    var manifest_bytes: usize = 0;
    var dependencies = try allocator.alloc([]const u8, 0);
    if (dir.openFile(io, "build.zig.zon", .{ .follow_symlinks = false })) |file| {
        defer file.close(io);
        const before = try files.snapshot(file);
        if (before.size > 4 * limits.mib or before.mode & linux.S.IFMT != linux.S.IFREG or
            before.uid != linux.geteuid() or before.nlink != 1)
            return error.InvalidManifest;
        const raw = try allocator.alloc(u8, @intCast(before.size));
        defer allocator.free(raw);
        if (try file.readPositionalAll(io, raw, 0) != raw.len or
            !files.sameSnapshot(before, try files.snapshot(file)))
            return error.PackageChanged;
        var hash: [32]u8 = undefined;
        Sha256.hash(raw, &hash, .{});
        manifest_sha256 = std.fmt.bytesToHex(hash, .lower);
        manifest_bytes = raw.len;
        allocator.free(dependencies);
        dependencies = try packageDependencies(allocator, raw);
    } else |err| if (err != error.FileNotFound) return err;
    return .{
        .name = try allocator.dupe(u8, name),
        .files = state.files,
        .directories = state.directories,
        .bytes = state.bytes,
        .tree_sha256 = physical.hex(&state.content),
        .physical_sha256 = physical.hex(&state.physical_hash),
        .manifest_sha256 = manifest_sha256,
        .manifest_bytes = manifest_bytes,
        .dependencies = dependencies,
    };
}

pub fn packageSet(allocator: std.mem.Allocator, io: std.Io, packages: []const u8) !PackageSet {
    const before = try physical.directory(io, packages, true);
    const dir = try files.openDirectory(io, packages, .private);
    defer dir.close(io);
    var roots: std.ArrayList([]const u8) = .empty;
    defer {
        for (roots.items) |name| allocator.free(name);
        roots.deinit(allocator);
    }
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (roots.items.len >= limits.dependency_roots) return error.LimitExceeded;
        try limits.packageName(entry.name);
        try roots.append(allocator, try allocator.dupe(u8, entry.name));
    }
    if (roots.items.len == 0) return error.EmptyPackages;
    std.mem.sort([]const u8, roots.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    const collected = try allocator.alloc(Package, roots.items.len);
    var populated: usize = 0;
    errdefer {
        for (collected[0..populated]) |package| {
            allocator.free(package.name);
            for (package.dependencies) |dependency| allocator.free(dependency);
            allocator.free(package.dependencies);
        }
        allocator.free(collected);
    }
    var closure = Sha256.init(.{});
    closure.update("uk.wamr.package-closure-v1\x00");
    var physical_hash = Sha256.init(.{});
    physical_hash.update("uk.wamr.package-physical-closure-v1\x00");
    var files_count: usize = 0;
    var directories: usize = 0;
    var bytes: usize = 0;
    for (roots.items, 0..) |name, i| {
        collected[i] = try inventory(allocator, io, dir, name);
        populated += 1;
        try limits.addBounded(&files_count, collected[i].files, limits.dependency_entries);
        try limits.addBounded(&directories, collected[i].directories, limits.dependency_entries - files_count);
        try limits.addBounded(&bytes, collected[i].bytes, limits.dependency_bytes);
        try physical.bind(allocator, &closure, .{
            .package_hash = name,
            .content = .{
                .files = collected[i].files,
                .directories = collected[i].directories,
                .bytes = collected[i].bytes,
                .tree_sha256 = collected[i].tree_sha256,
                .physical_sha256 = collected[i].physical_sha256,
            },
            .manifest = if (collected[i].manifest_sha256) |digest|
                @as(?struct { bytes: usize, sha256: [64]u8, dependencies: [][]const u8 }, .{
                    .bytes = collected[i].manifest_bytes,
                    .sha256 = digest,
                    .dependencies = collected[i].dependencies,
                })
            else
                null,
        });
        try physical.bind(allocator, &physical_hash, .{ name, collected[i].physical_sha256 });
    }
    for (collected) |package| {
        for (package.dependencies) |child| {
            var found = false;
            for (collected) |candidate| if (std.mem.eql(u8, child, candidate.name)) {
                found = true;
                break;
            };
            if (!found) return error.MissingDependency;
        }
    }
    var found_miz = false;
    for (collected) |package| if (std.mem.eql(u8, package.name, limits.miz_package_hash)) {
        found_miz = true;
        break;
    };
    if (found_miz) {
        var seen = try allocator.alloc(bool, collected.len);
        defer allocator.free(seen);
        @memset(seen, false);
        var changed = true;
        for (collected, 0..) |package, index| {
            if (std.mem.eql(u8, package.name, limits.miz_package_hash)) seen[index] = true;
        }
        while (changed) {
            changed = false;
            for (collected, 0..) |package, index| {
                if (!seen[index]) continue;
                for (package.dependencies) |child| {
                    for (collected, 0..) |candidate, child_index| {
                        if (std.mem.eql(u8, candidate.name, child) and !seen[child_index]) {
                            seen[child_index] = true;
                            changed = true;
                        }
                    }
                }
            }
        }
        for (seen) |reachable| if (!reachable) return error.UnexpectedPackage;
    }
    if (!found_miz or !files.sameSnapshot(before, try physical.directory(io, packages, true)))
        return error.PackageChanged;
    return .{
        .roots = collected.len,
        .files = files_count,
        .directories = directories,
        .bytes = bytes,
        .closure_sha256 = physical.hex(&closure),
        .physical_sha256 = physical.hex(&physical_hash),
        .packages = collected,
    };
}

pub fn requireSame(allocator: std.mem.Allocator, io: std.Io, packages: []const u8, expected: PackageSet) !void {
    var actual = try packageSet(allocator, io, packages);
    defer actual.deinit(allocator);
    if (expected.roots != actual.roots or expected.files != actual.files or
        expected.directories != actual.directories or expected.bytes != actual.bytes or
        !std.meta.eql(expected.closure_sha256, actual.closure_sha256) or
        !std.meta.eql(expected.physical_sha256, actual.physical_sha256))
        return error.DependencyChanged;
}

pub fn sourceManifests(allocator: std.mem.Allocator, io: std.Io, repository: []const u8, git: []const u8) ![2]source.TrackedManifest {
    const build = try source.trackedManifest(allocator, io, repository, git, manifest_paths[0]);
    errdefer build.deinit(allocator);
    const zon = try source.trackedManifest(allocator, io, repository, git, manifest_paths[1]);
    errdefer zon.deinit(allocator);
    try pinnedManifest(allocator, zon.content);
    return .{ build, zon };
}

const ManifestSource = struct {
    path: []const u8,
    mode: []const u8,
    bytes: usize,
    sha256: [64]u8,
    git_oid: []const u8,
    metadata: [9]i128,
    metadata_sha256: [64]u8,
};
const ManifestCopy = struct { bytes: usize, sha256: [64]u8, metadata: [9]i128 };
const ManifestPair = struct { source: ManifestSource, copy: ManifestCopy };
const Manifest = struct { bytes: usize, sha256: [64]u8, dependencies: [][]const u8 };
const Content = struct {
    files: usize,
    directories: usize,
    bytes: usize,
    tree_sha256: [64]u8,
    physical_sha256: [64]u8,
};
const PackageRecord = struct {
    package_hash: []const u8,
    content: Content,
    manifest: ?Manifest,
};
const HashRecord = struct { package_hash: []const u8, sha256: [64]u8 };
const CommandRecord = struct {
    scope: []const u8 = "command_diagnostic_not_acceptance",
    stage: []const u8 = "dependency-restore",
    exit_code: u8 = 0,
    bytes: usize,
    sha256: [64]u8,
    over_limit: bool = false,
    known_error_markers: []const []const u8 = &.{},
};

pub const Document = struct {
    schema: []const u8 = "uk.wamr.zig-dependency-custody",
    version: u8 = 1,
    request: struct { url: []const u8 = limits.miz_url, revision: []const u8 = limits.miz_revision, package_hash: []const u8 = limits.miz_package_hash } = .{},
    source_manifests: struct { @"build.zig": ManifestPair, @"build.zig.zon": ManifestPair },
    restore_directory: struct { metadata: [9]i128 },
    restore: CommandRecord,
    packages: struct {
        roots: usize,
        files: usize,
        directories: usize,
        bytes: usize,
        closure_sha256: [64]u8,
        physical_sha256: [64]u8,
        root_metadata: [9]i128,
        root_metadata_sha256: [64]u8,
        manifests: struct { count: usize, bytes: usize, sha256: [64]u8 },
        hash_verification: struct { algorithm: []const u8 = "zig-0.16.0-fetch-path", count: usize, sha256: [64]u8 },
        records: []PackageRecord,
    },
    hash_records: []HashRecord,
    owned_packages: PackageSet,
    owned_manifests: [2]source.TrackedManifest,

    pub fn deinit(self: *Document, allocator: std.mem.Allocator) void {
        for (self.owned_manifests) |item| item.deinit(allocator);
        self.owned_packages.deinit(allocator);
        allocator.free(self.packages.records);
        allocator.free(self.hash_records);
        self.* = undefined;
    }

    pub fn canonical(self: Document, allocator: std.mem.Allocator) ![]u8 {
        const value = .{
            .schema = self.schema,
            .version = self.version,
            .request = self.request,
            .source_manifests = self.source_manifests,
            .restore_directory = self.restore_directory,
            .restore = self.restore,
            .packages = self.packages,
        };
        const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer allocator.free(raw);
        return @import("records.zig").canonicalAlloc(allocator, raw);
    }
};

fn copy(allocator: std.mem.Allocator, io: std.Io, restore: []const u8, name: []const u8, original: source.TrackedManifest) !ManifestCopy {
    const path = try std.fs.path.join(allocator, &.{ restore, name });
    defer allocator.free(path);
    const record = try physical.readFile(io, path, limits.mib, true);
    if (record.bytes != original.bytes or !std.meta.eql(record.sha256, original.sha256) or
        record.metadata[2] & 0o7777 != 0o600 or record.metadata[3] != linux.geteuid())
        return error.ManifestCopyChanged;
    var retained = try files.RetainedFile.open(io, path, .private);
    defer retained.close(io);
    const data = try allocator.alloc(u8, original.bytes);
    defer allocator.free(data);
    if (try retained.file.readPositionalAll(io, data, 0) != data.len or
        !std.mem.eql(u8, data, original.content)) return error.ManifestCopyChanged;
    try retained.verify(io);
    return .{ .bytes = original.bytes, .sha256 = record.sha256, .metadata = record.metadata };
}

fn sourceRecord(value: source.TrackedManifest) ManifestSource {
    return .{
        .path = value.path,
        .mode = value.mode,
        .bytes = value.bytes,
        .sha256 = value.sha256,
        .git_oid = value.git_oid,
        .metadata = value.metadata,
        .metadata_sha256 = value.metadata_sha256,
    };
}

pub fn capture(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    git: []const u8,
    compute: []const u8,
) !Document {
    const source_manifests = try sourceManifests(allocator, io, repository, git);
    errdefer for (source_manifests) |item| item.deinit(allocator);
    const restore = try std.fs.path.join(allocator, &.{ compute, "dependencies" });
    defer allocator.free(restore);
    const restore_info = try physical.directory(io, restore, true);
    const restore_dir = try files.openDirectory(io, restore, .private);
    defer restore_dir.close(io);
    var count: usize = 0;
    var iterator = restore_dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (count >= 3 or (!std.mem.eql(u8, entry.name, "build.zig") and
            !std.mem.eql(u8, entry.name, "build.zig.zon") and
            !std.mem.eql(u8, entry.name, "zig-pkg"))) return error.UnexpectedRestoreEntry;
        count += 1;
    }
    if (count != 3) return error.MissingRestoreEntry;
    const copied_build = try copy(allocator, io, restore, "build.zig", source_manifests[0]);
    const copied_zon = try copy(allocator, io, restore, "build.zig.zon", source_manifests[1]);
    try pinnedManifest(allocator, source_manifests[1].content);
    const packages_path = try std.fs.path.join(allocator, &.{ restore, "zig-pkg" });
    defer allocator.free(packages_path);
    const root_info = try physical.directory(io, packages_path, true);
    var packages = try packageSet(allocator, io, packages_path);
    errdefer packages.deinit(allocator);
    var package_records = try allocator.alloc(PackageRecord, packages.packages.len);
    errdefer allocator.free(package_records);
    var hashes = try allocator.alloc(HashRecord, packages.packages.len);
    errdefer allocator.free(hashes);
    var manifests_hash = Sha256.init(.{});
    manifests_hash.update("uk.wamr.package-manifests-v1\x00");
    var manifest_count: usize = 0;
    var manifest_bytes: usize = 0;
    var closure = Sha256.init(.{});
    closure.update("uk.wamr.package-closure-v1\x00");
    var physical_hash = Sha256.init(.{});
    physical_hash.update("uk.wamr.package-physical-closure-v1\x00");
    for (packages.packages, 0..) |item, i| {
        const manifest: ?Manifest = if (item.manifest_sha256) |digest| .{
            .bytes = item.manifest_bytes,
            .sha256 = digest,
            .dependencies = item.dependencies,
        } else null;
        if (manifest) |value| {
            manifest_count += 1;
            manifest_bytes += value.bytes;
            try physical.bind(allocator, &manifests_hash, .{ item.name, value });
        }
        package_records[i] = .{
            .package_hash = item.name,
            .content = .{
                .files = item.files,
                .directories = item.directories,
                .bytes = item.bytes,
                .tree_sha256 = item.tree_sha256,
                .physical_sha256 = item.physical_sha256,
            },
            .manifest = manifest,
        };
        try physical.bind(allocator, &closure, package_records[i]);
        try physical.bind(allocator, &physical_hash, .{ item.name, item.physical_sha256 });
        const log_name = try std.fmt.allocPrint(allocator, "dependency-hash-{d:0>3}.log", .{i});
        defer allocator.free(log_name);
        const log_path = try std.fs.path.join(allocator, &.{ compute, "private", log_name });
        defer allocator.free(log_path);
        var retained = try files.RetainedFile.open(io, log_path, .private);
        defer retained.close(io);
        if (retained.file_snapshot.size > 512 or retained.file_snapshot.size != item.name.len + 1)
            return error.PackageHashMismatch;
        const raw = try allocator.alloc(u8, @intCast(retained.file_snapshot.size));
        defer allocator.free(raw);
        if (try retained.file.readPositionalAll(io, raw, 0) != raw.len or
            !std.mem.eql(u8, raw[0 .. raw.len - 1], item.name) or raw[raw.len - 1] != '\n')
            return error.PackageHashMismatch;
        try retained.verify(io);
        var digest: [32]u8 = undefined;
        Sha256.hash(raw, &digest, .{});
        hashes[i] = .{ .package_hash = item.name, .sha256 = std.fmt.bytesToHex(digest, .lower) };
    }
    const hash_raw = try std.json.Stringify.valueAlloc(allocator, hashes, .{});
    defer allocator.free(hash_raw);
    const verified = try @import("records.zig").identity(allocator, hash_raw);
    const root_metadata = physical.metadata(root_info);
    const metadata_raw = try std.json.Stringify.valueAlloc(allocator, root_metadata, .{});
    defer allocator.free(metadata_raw);
    const root_metadata_hash = try @import("records.zig").identity(allocator, metadata_raw);
    const restore_log = try std.fs.path.join(allocator, &.{ compute, "private", "dependency-restore.log" });
    defer allocator.free(restore_log);
    const log = try physical.readFile(io, restore_log, 8 * limits.mib, true);
    const after = try physical.directory(io, restore, true);
    if (!files.sameSnapshot(restore_info, after) or
        !files.sameSnapshot(root_info, try physical.directory(io, packages_path, true)))
        return error.DependencyChanged;
    return .{
        .source_manifests = .{
            .@"build.zig" = .{ .source = sourceRecord(source_manifests[0]), .copy = copied_build },
            .@"build.zig.zon" = .{ .source = sourceRecord(source_manifests[1]), .copy = copied_zon },
        },
        .restore_directory = .{ .metadata = physical.metadata(restore_info) },
        .restore = .{ .bytes = @intCast(log.bytes), .sha256 = log.sha256 },
        .packages = .{
            .roots = packages.roots,
            .files = packages.files,
            .directories = packages.directories,
            .bytes = packages.bytes,
            .closure_sha256 = physical.hex(&closure),
            .physical_sha256 = physical.hex(&physical_hash),
            .root_metadata = root_metadata,
            .root_metadata_sha256 = std.fmt.bytesToHex(root_metadata_hash, .lower),
            .manifests = .{ .count = manifest_count, .bytes = manifest_bytes, .sha256 = physical.hex(&manifests_hash) },
            .hash_verification = .{ .count = hashes.len, .sha256 = std.fmt.bytesToHex(verified, .lower) },
            .records = package_records,
        },
        .hash_records = hashes,
        .owned_packages = packages,
        .owned_manifests = source_manifests,
    };
}

pub fn requireDocument(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    git: []const u8,
    compute: []const u8,
    expected: Document,
) !void {
    var actual = try capture(allocator, io, repository, git, compute);
    defer actual.deinit(allocator);
    const expected_bytes = try expected.canonical(allocator);
    defer allocator.free(expected_bytes);
    const actual_bytes = try actual.canonical(allocator);
    defer allocator.free(actual_bytes);
    if (!std.mem.eql(u8, expected_bytes, actual_bytes)) return error.DependencyChanged;
}

fn copyImmutable(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
}

pub fn verifyZigPackageHashes(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    git: []const u8,
    compute: []const u8,
    zig: []const u8,
    expected: Document,
) !void {
    try requireDocument(allocator, io, repository, git, compute, expected);
    const root = try files.openDirectory(io, compute, .private);
    defer root.close(io);
    try root.createDir(io, "dependency-hash-work", .fromMode(0o700));
    try root.createDir(io, "dependency-hash-cache", .fromMode(0o700));
    const work_path = try std.fs.path.join(allocator, &.{ compute, "dependency-hash-work" });
    defer allocator.free(work_path);
    const cache_path = try std.fs.path.join(allocator, &.{ compute, "dependency-hash-cache" });
    defer allocator.free(cache_path);
    const work = try files.openDirectory(io, work_path, .private);
    defer work.close(io);
    try copyImmutable(io, work, "build.zig", expected.owned_manifests[0].content);
    try copyImmutable(io, work, "build.zig.zon", expected.owned_manifests[1].content);
    try work.createDir(io, "zig-pkg", .fromMode(0o700));
    const baseline = try physical.directory(io, work_path, true);
    const packages_path = try std.fs.path.join(allocator, &.{ compute, "dependencies", "zig-pkg" });
    defer allocator.free(packages_path);
    const packages = try files.openDirectory(io, packages_path, .private);
    defer packages.close(io);
    var executable = try process.Executable.open(io, zig);
    defer executable.close(io);
    try process.initialize();
    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("HOME", compute);
    try env.put("PATH", "/usr/bin:/bin");
    try env.put("LANG", "C");
    try env.put("LC_ALL", "C");
    for (expected.owned_packages.packages) |package| {
        try requireDocument(allocator, io, repository, git, compute, expected);
        const package_path = try std.fs.path.join(allocator, &.{ packages_path, package.name });
        defer allocator.free(package_path);
        const package_dir = try packageDirectory(io, packages, package.name);
        defer package_dir.close(io);
        const package_before = try files.snapshot(.{ .handle = package_dir.handle, .flags = .{ .nonblocking = false } });
        const deadline = try process.Deadline.afterMilliseconds(300_000);
        var result = try process.runCommand(allocator, io, .{
            .executable = executable,
            .argv = &.{ zig, "fetch", "--global-cache-dir", cache_path, package_path },
            .environment = &env,
            .cwd = work,
            .primary_deadline = deadline,
            .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, deadline.expires_ns, 10 * std.time.ns_per_s) },
            .snapshot_executable = false,
            .limits = .{ .stdout_bytes = 511, .stderr_bytes = 4096 },
        });
        defer result.deinit(allocator);
        if (!result.succeeded() or result.stderr.len != 0 or
            result.stdout.len != package.name.len + 1 or
            !std.mem.eql(u8, result.stdout[0..package.name.len], package.name) or
            result.stdout[package.name.len] != '\n')
            return error.PackageHashMismatch;
        const reopened = try packageDirectory(io, packages, package.name);
        defer reopened.close(io);
        if (!files.sameSnapshot(package_before, try files.snapshot(.{ .handle = reopened.handle, .flags = .{ .nonblocking = false } })))
            return error.PackageChanged;
        const first = try std.fs.path.join(allocator, &.{ work_path, "build.zig" });
        defer allocator.free(first);
        const second = try std.fs.path.join(allocator, &.{ work_path, "build.zig.zon" });
        defer allocator.free(second);
        const build_copy = try physical.readFile(io, first, limits.mib, true);
        const zon_copy = try physical.readFile(io, second, limits.mib, true);
        if (!std.meta.eql(build_copy.sha256, expected.source_manifests.@"build.zig".source.sha256) or
            !std.meta.eql(zon_copy.sha256, expected.source_manifests.@"build.zig.zon".source.sha256))
            return error.ManifestCopyChanged;
        try requireDocument(allocator, io, repository, git, compute, expected);
    }
    if (!files.sameSnapshot(baseline, try physical.directory(io, work_path, true)))
        return error.DependencyChanged;
    try requireDocument(allocator, io, repository, git, compute, expected);
}
