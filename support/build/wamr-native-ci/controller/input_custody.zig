// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const physical = @import("custody_files.zig");
const limits = @import("custody_limits.zig");
const records = @import("records.zig");
const files = core.private_files;
const Sha256 = core.Sha256;
const process = core.process;
const linux = std.os.linux;

pub const host_tools = [_][]const u8{
    "git",   "python3", "bash", "dash",    "cp",           "env",          "mkdir",        "readlink",
    "uname", "zig",     "make", "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf", "llvm-strip",
    "bison", "flex",    "m4",
};
pub const native_roles = [_][]const u8{ "native:wamr-aot-build", "native:wamr-log-validate" };

fn interpreter(allocator: std.mem.Allocator, io: std.Io, executable: []const u8) !?[]u8 {
    var retained = try files.RetainedFile.open(io, executable, .artifact);
    defer retained.close(io);
    var header: [64]u8 = undefined;
    if (try retained.file.readPositionalAll(io, &header, 0) != header.len or
        !std.mem.eql(u8, header[0..4], "\x7fELF"))
        return null;
    if (header[5] != 1 or (header[4] != 2 and header[4] != 1))
        return error.UnsupportedElfFormat;
    const is_64 = header[4] == 2;
    const offset = if (is_64) std.mem.readInt(u64, header[32..40], .little) else std.mem.readInt(u32, header[28..32], .little);
    const size: u16 = if (is_64) std.mem.readInt(u16, header[54..56], .little) else std.mem.readInt(u16, header[42..44], .little);
    const count: u16 = if (is_64) std.mem.readInt(u16, header[56..58], .little) else std.mem.readInt(u16, header[44..46], .little);
    if (size == 0 or size > 256 or count > 256 or size < (if (is_64) @as(u16, 56) else 32))
        return error.UnsupportedElfFormat;
    var table: [256]u8 = undefined;
    for (0..count) |index| {
        const at = try std.math.add(u64, offset, try std.math.mul(u64, index, size));
        if (try retained.file.readPositionalAll(io, table[0..size], at) != size)
            return error.UnsupportedElfFormat;
        if (std.mem.readInt(u32, table[0..4], .little) != 3) continue;
        const start: u64 = if (is_64) std.mem.readInt(u64, table[8..16], .little) else std.mem.readInt(u32, table[4..8], .little);
        const length: u64 = if (is_64) std.mem.readInt(u64, table[32..40], .little) else std.mem.readInt(u32, table[16..20], .little);
        if (length < 2 or length > 4096) return error.UnsupportedElfFormat;
        const buffer = try allocator.alloc(u8, @intCast(length));
        defer allocator.free(buffer);
        if (try retained.file.readPositionalAll(io, buffer, start) != length or
            buffer[buffer.len - 1] != 0 or buffer[0] != '/')
            return error.UnsupportedElfFormat;
        const resolved = try std.Io.Dir.realPathFileAbsoluteAlloc(io, buffer[0 .. buffer.len - 1], allocator);
        defer allocator.free(resolved);
        var pinned = try files.RetainedFile.open(io, resolved, .artifact);
        defer pinned.close(io);
        try pinned.verify(io);
        try retained.verify(io);
        return try allocator.dupe(u8, resolved);
    }
    try retained.verify(io);
    return null;
}

pub fn executableRuntimePaths(allocator: std.mem.Allocator, io: std.Io, executable: []const u8) ![][]const u8 {
    const loader = try interpreter(allocator, io, executable) orelse return allocator.alloc([]const u8, 0);
    errdefer allocator.free(loader);
    var pinned_executable = try files.RetainedFile.open(io, executable, .artifact);
    defer pinned_executable.close(io);
    var pinned_loader = try files.RetainedFile.open(io, loader, .artifact);
    defer pinned_loader.close(io);
    try process.initialize();
    var native_loader = try process.Executable.open(io, loader);
    defer native_loader.close(io);
    const cwd = try files.openDirectory(io, "/", .artifact);
    defer cwd.close(io);
    var env = std.process.Environ.Map.init(allocator);
    defer env.deinit();
    try env.put("LC_ALL", "C");
    const deadline = try process.Deadline.afterMilliseconds(30_000);
    var result = try process.runCommand(allocator, io, .{
        .executable = native_loader,
        .argv = &.{ loader, "--list", executable },
        .environment = &env,
        .cwd = cwd,
        .primary_deadline = deadline,
        .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, deadline.expires_ns, 10 * std.time.ns_per_s) },
        .snapshot_executable = false,
        .limits = .{ .stdout_bytes = limits.mib, .stderr_bytes = 4096 },
    });
    defer result.deinit(allocator);
    if (!result.succeeded() or result.stderr.len != 0) return error.RuntimeInventoryRefused;
    var paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    try paths.append(allocator, loader);
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        var token = std.mem.trim(u8, line, " \t");
        if (std.mem.indexOf(u8, token, "=> ")) |at| token = token[at + 3 ..];
        if (token.len == 0 or token[0] != '/') continue;
        const end = std.mem.indexOfScalar(u8, token, ' ') orelse token.len;
        const resolved = try std.Io.Dir.realPathFileAbsoluteAlloc(io, token[0..end], allocator);
        defer allocator.free(resolved);
        if (std.mem.eql(u8, resolved, executable)) continue;
        var seen = false;
        for (paths.items) |prior| if (std.mem.eql(u8, prior, resolved)) {
            seen = true;
            break;
        };
        if (seen) continue;
        var retained = try files.RetainedFile.open(io, resolved, .artifact);
        defer retained.close(io);
        try retained.verify(io);
        if (paths.items.len >= 256) return error.RuntimeInventoryRefused;
        try paths.append(allocator, try allocator.dupe(u8, resolved));
    }
    try pinned_executable.verify(io);
    try pinned_loader.verify(io);
    std.mem.sort([]const u8, paths.items, {}, entryLess);
    return paths.toOwnedSlice(allocator);
}

pub const ProductionPaths = struct {
    runtime: []const u8,
    tools: [host_tools.len][]const u8,
    python_stdlib: []const u8,
};

pub const Production = struct {
    custody: Custody,
    file_bindings: []Binding,
    tree_bindings: []Binding,

    pub fn deinit(self: *Production, allocator: std.mem.Allocator) void {
        self.custody.deinit(allocator);
        for (self.file_bindings) |entry| {
            allocator.free(entry.role);
            allocator.free(entry.path);
        }
        allocator.free(self.file_bindings);
        for (self.tree_bindings) |entry| {
            allocator.free(entry.role);
            allocator.free(entry.path);
        }
        allocator.free(self.tree_bindings);
        self.* = undefined;
    }
};

fn appendBinding(allocator: std.mem.Allocator, bindings: *std.ArrayList(Binding), role: []const u8, path: []const u8) !void {
    for (bindings.items) |known| {
        if (std.mem.eql(u8, known.role, role)) return error.DuplicateInputRole;
    }
    try files.absoluteFilePath(path);
    const owned_role = try allocator.dupe(u8, role);
    errdefer allocator.free(owned_role);
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    try bindings.append(allocator, .{ .role = owned_role, .path = owned_path });
}

fn collectRuntime(allocator: std.mem.Allocator, io: std.Io, executable: []const u8, bindings: *std.ArrayList(Binding)) !void {
    const paths = try executableRuntimePaths(allocator, io, executable);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    for (paths) |path| {
        const role = try std.fmt.allocPrint(allocator, "runtime:{s}", .{path});
        defer allocator.free(role);
        var present = false;
        for (bindings.items) |item| if (std.mem.eql(u8, item.role, role)) {
            present = true;
            break;
        };
        if (!present) try appendBinding(allocator, bindings, role, path);
    }
}

pub fn captureProduction(allocator: std.mem.Allocator, io: std.Io, paths: ProductionPaths) !Production {
    var file_bindings: std.ArrayList(Binding) = .empty;
    errdefer {
        for (file_bindings.items) |item| {
            allocator.free(item.role);
            allocator.free(item.path);
        }
        file_bindings.deinit(allocator);
    }
    var tree_bindings: std.ArrayList(Binding) = .empty;
    errdefer {
        for (tree_bindings.items) |item| {
            allocator.free(item.role);
            allocator.free(item.path);
        }
        tree_bindings.deinit(allocator);
    }
    for (host_tools, paths.tools) |name, path| {
        const role = try std.fmt.allocPrint(allocator, "tool:{s}", .{name});
        defer allocator.free(role);
        try appendBinding(allocator, &file_bindings, role, path);
        try collectRuntime(allocator, io, path, &file_bindings);
    }
    const static_roles = [_]struct { role: []const u8, relative: []const u8 }{
        .{ .role = "command-supervisor", .relative = "controller/bin/uk-wamr-native-ci" },
        .{ .role = "wamr-source-archive", .relative = "custody/wamr-source.tar" },
        .{ .role = "native:wamr-aot-build", .relative = "compute/tools/bin/uk-wamr-aot-build" },
        .{ .role = "native:wamr-log-validate", .relative = "compute/tools/bin/uk-wamr-log-validate" },
        .{ .role = "native:wamr-native-ci-fixtures", .relative = "compute/tools/bin/wamr-native-ci-fixtures" },
        .{ .role = "native:wamr-ci-package", .relative = "compute/tools/bin/wamr-ci-package" },
        .{ .role = "native:wamr-ci-supervisor-fixture", .relative = "compute/tools/bin/wamr-ci-supervisor-fixture" },
    };
    for (static_roles) |item| {
        const path = try std.fs.path.join(allocator, &.{ paths.runtime, item.relative });
        defer allocator.free(path);
        try appendBinding(allocator, &file_bindings, item.role, path);
        if (!std.mem.eql(u8, item.role, "wamr-source-archive"))
            try collectRuntime(allocator, io, path, &file_bindings);
    }
    const tree_roles = [_]struct { role: []const u8, path: []const u8 }{
        .{ .role = "bison", .path = try std.fs.path.join(allocator, &.{ paths.runtime, "bison" }) },
        .{ .role = "zig", .path = std.fs.path.dirname(paths.tools[9]) orelse return error.UnsafePath },
        .{ .role = "python-stdlib", .path = paths.python_stdlib },
    };
    defer allocator.free(tree_roles[0].path);
    for (tree_roles) |item| try appendBinding(allocator, &tree_bindings, item.role, item.path);
    const llvm_path = try std.fs.path.join(allocator, &.{ paths.runtime, "llvm" });
    defer allocator.free(llvm_path);
    if (files.openDirectory(io, llvm_path, .artifact)) |opened| {
        opened.close(io);
        try appendBinding(allocator, &tree_bindings, "llvm", llvm_path);
    } else |err| if (err != error.FileNotFound) return err;
    var production: Production = .{
        .custody = undefined,
        .file_bindings = try file_bindings.toOwnedSlice(allocator),
        .tree_bindings = try tree_bindings.toOwnedSlice(allocator),
    };
    errdefer {
        for (production.file_bindings) |item| {
            allocator.free(item.role);
            allocator.free(item.path);
        }
        allocator.free(production.file_bindings);
        for (production.tree_bindings) |item| {
            allocator.free(item.role);
            allocator.free(item.path);
        }
        allocator.free(production.tree_bindings);
    }
    production.custody = try capture(allocator, io, production.file_bindings, production.tree_bindings);
    return production;
}

pub fn requireProduction(allocator: std.mem.Allocator, io: std.Io, paths: ProductionPaths, expected: Custody) !void {
    var current = try captureProduction(allocator, io, paths);
    defer current.deinit(allocator);
    try compareCaptured(expected, current.custody);
}
pub const Bison = struct { files: usize, bytes: usize, sha256: [64]u8 };
pub const Binding = struct { role: []const u8, path: []const u8 };
pub const FileRecord = struct { role: []const u8, path: []const u8, metadata: [9]i128, sha256: [64]u8 };
pub const TreeRecord = struct {
    role: []const u8,
    path: []const u8,
    files: usize,
    directories: usize,
    symlinks: usize,
    bytes: usize,
    content_sha256: [64]u8,
    physical_sha256: [64]u8,
};
pub const Custody = struct {
    schema: []const u8 = "uk.wamr.consumer-input-custody",
    version: u8 = 2,
    files: []FileRecord,
    trees: []TreeRecord,
    directories: []DirectoryRecord,
    aggregate_sha256: [64]u8,

    pub fn deinit(self: *Custody, allocator: std.mem.Allocator) void {
        allocator.free(self.files);
        allocator.free(self.trees);
        allocator.free(self.directories);
        self.* = undefined;
    }

    pub fn canonical(self: Custody, allocator: std.mem.Allocator) ![]u8 {
        const raw = try consumerDocument(allocator, self, true);
        defer allocator.free(raw);
        return records.canonicalAlloc(allocator, raw);
    }
};
pub const DirectoryRecord = struct { path: []const u8, metadata: [9]i128 };

fn less(_: void, a: Binding, b: Binding) bool {
    return std.mem.lessThan(u8, a.role, b.role);
}
fn entryLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn entries(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, limit: usize) ![][]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (names.items.len >= limit) return error.LimitExceeded;
        try files.basename(entry.name);
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, entryLess);
    return names.toOwnedSlice(allocator);
}

const BisonEntry = struct { path: []const u8, bytes: usize, sha256: [64]u8 };
fn bisonWalk(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    prefix: []const u8,
    count: *usize,
    total: *usize,
    found: *std.ArrayList(BisonEntry),
) !void {
    const dir_path = if (prefix.len == 0) root else try std.fs.path.join(allocator, &.{ root, prefix });
    defer if (prefix.len != 0) allocator.free(dir_path);
    const before = try physical.directory(io, dir_path, prefix.len == 0);
    if (before.uid != linux.geteuid() or before.mode & 0o7022 != 0)
        return error.UnsafeBisonInput;
    const dir = try files.openDirectory(io, dir_path, .artifact);
    defer dir.close(io);
    const names = try entries(allocator, io, dir, limits.bison_entries - count.*);
    defer {
        for (names) |name| allocator.free(name);
        allocator.free(names);
    }
    for (names) |name| {
        try limits.addBounded(count, 1, limits.bison_entries);
        const relative = if (prefix.len == 0) try allocator.dupe(u8, name) else try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name });
        var owned = true;
        defer if (owned) allocator.free(relative);
        const path = try std.fs.path.join(allocator, &.{ root, relative });
        defer allocator.free(path);
        const child = try dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
        defer child.close(io);
        const info = try files.snapshot(child);
        if (info.uid != linux.geteuid() or info.mode & 0o7022 != 0)
            return error.UnsafeBisonInput;
        if (info.mode & linux.S.IFMT == linux.S.IFDIR) {
            try bisonWalk(allocator, io, root, relative, count, total, found);
        } else if (info.mode & linux.S.IFMT == linux.S.IFREG) {
            if (info.nlink != 1 or info.size > limits.bison_bytes - total.*)
                return error.UnsafeBisonInput;
            const identity = try physical.readFile(io, path, limits.bison_bytes - total.*, false);
            if (!std.meta.eql(identity.metadata, physical.metadata(info))) return error.BisonChanged;
            try limits.addBounded(total, @intCast(identity.bytes), limits.bison_bytes);
            try found.append(allocator, .{ .path = relative, .bytes = @intCast(identity.bytes), .sha256 = identity.sha256 });
            owned = false;
        } else {
            return error.UnsafeBisonInput;
        }
    }
    if (!files.sameSnapshot(before, try physical.directory(io, dir_path, prefix.len == 0)))
        return error.BisonChanged;
}

pub fn bison(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !Bison {
    var found: std.ArrayList(BisonEntry) = .empty;
    defer {
        for (found.items) |entry| allocator.free(entry.path);
        found.deinit(allocator);
    }
    var count: usize = 0;
    var total: usize = 0;
    try bisonWalk(allocator, io, root, "", &count, &total, &found);
    if (found.items.len == 0) return error.EmptyBisonData;
    std.mem.sort(BisonEntry, found.items, {}, struct {
        fn byPath(_: void, a: BisonEntry, b: BisonEntry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.byPath);
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    const w = &writer.writer;
    try w.writeByte('{');
    for (found.items, 0..) |entry, index| {
        if (index != 0) try w.writeByte(',');
        const name = try std.json.Stringify.valueAlloc(allocator, entry.path, .{});
        defer allocator.free(name);
        try w.print("{s}:{{\"bytes\":{d},\"sha256\":\"{s}\"}}", .{ name, entry.bytes, &entry.sha256 });
    }
    try w.writeByte('}');
    const document = try writer.toOwnedSlice();
    defer allocator.free(document);
    return .{ .files = found.items.len, .bytes = total, .sha256 = std.fmt.bytesToHex(try records.identity(allocator, document), .lower) };
}

const TreeCounter = struct {
    files: usize = 0,
    directories: usize = 0,
    symlinks: usize = 0,
    bytes: usize = 0,
    hash_work: usize = 0,
    hash_limit: usize = limits.input_bytes,
    identities: std.AutoHashMap([9]i128, [64]u8),
    content: Sha256,
    physical_hash: Sha256,
};

fn treeFile(io: std.Io, path: []const u8, state: *TreeCounter) !physical.File {
    var retained = try files.RetainedFile.open(io, path, .artifact);
    defer retained.close(io);
    const before = retained.file_snapshot;
    if (before.mode & linux.S.IFMT != linux.S.IFREG or
        (before.uid == 0 and before.nlink == 0) or
        (before.uid != 0 and before.nlink != 1) or
        (before.uid != linux.geteuid() and before.uid != 0) or
        before.mode & 0o022 != 0 or before.size > limits.input_file)
        return error.UnsafeFile;
    const metadata = physical.metadata(before);
    if (state.identities.get(metadata)) |sha256| {
        try retained.verify(io);
        return .{ .bytes = before.size, .sha256 = sha256, .metadata = metadata };
    }
    try limits.addBounded(&state.hash_work, @intCast(before.size), state.hash_limit);
    const identity = try physical.readFile(io, path, limits.input_file, false);
    if (!std.meta.eql(identity.metadata, metadata)) return error.InputChanged;
    try retained.verify(io);
    try state.identities.put(metadata, identity.sha256);
    return identity;
}

fn componentMap(allocator: std.mem.Allocator, io: std.Io, target: []const u8, is_directory: bool) !std.json.ObjectMap {
    var ancestors: std.ArrayList(DirectoryRecord) = .empty;
    defer ancestors.deinit(allocator);
    try addAncestors(allocator, io, if (is_directory) target else std.fs.path.dirname(target).?, &ancestors);
    var map: std.json.ObjectMap = .empty;
    errdefer {
        for (map.values()) |value| value.array.deinit();
        map.deinit(allocator);
    }
    for (ancestors.items) |item| {
        var array = std.json.Array.init(allocator);
        errdefer array.deinit();
        for (item.metadata) |number| {
            if (number < std.math.minInt(i64) or number > std.math.maxInt(i64))
                return error.InvalidMetadata;
            try array.append(.{ .integer = @intCast(number) });
        }
        try map.put(allocator, item.path, .{ .array = array });
    }
    return map;
}

fn closeComponentMap(allocator: std.mem.Allocator, map: *std.json.ObjectMap) void {
    for (map.values()) |value| value.array.deinit();
    map.deinit(allocator);
}

fn bindMissingTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: []const u8,
    relative: []const u8,
    raw_target: []const u8,
    metadata: [9]i128,
    state: *TreeCounter,
) !void {
    const target = try std.fs.path.resolve(allocator, &.{ directory, raw_target });
    defer allocator.free(target);
    if (target.len > limits.ignored_path or target.len < 2 or target[0] != '/')
        return error.UnsafeInputLink;
    limits.relative(target[1..], limits.ignored_path, limits.ignored_depth) catch return error.UnsafeInputLink;
    var missing: std.ArrayList([]const u8) = .empty;
    defer missing.deinit(allocator);
    var probe: []const u8 = target;
    while (!std.mem.eql(u8, probe, "/")) {
        if (physical.directory(io, probe, false)) |snapshot| {
            if (missing.items.len == 0 or linux.geteuid() == 0 or snapshot.uid != 0 or snapshot.mode & 0o022 != 0)
                return error.UnsafeInputLink;
            std.mem.reverse([]const u8, missing.items);
            const parent = try files.openDirectory(io, probe, .artifact);
            defer parent.close(io);
            const first = parent.openFile(io, missing.items[0], .{ .path_only = true, .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return error.UnsafeInputLink,
            };
            if (first) |existing| {
                existing.close(io);
                return error.UnsafeInputLink;
            }
            var components = try componentMap(allocator, io, probe, true);
            defer closeComponentMap(allocator, &components);
            try physical.bind(allocator, &state.content, .{
                "symlink-missing", relative, raw_target, probe, missing.items,
            });
            try physical.bind(allocator, &state.physical_hash, .{
                "symlink-missing", relative, raw_target, metadata,
                .{
                    .ancestor = probe,
                    .missing = missing.items,
                    .metadata = physical.metadata(snapshot),
                    .directories = std.json.Value{ .object = components },
                },
            });
            if (!files.sameSnapshot(snapshot, try physical.directory(io, probe, false)))
                return error.InputChanged;
            return;
        } else |err| if (err != error.FileNotFound) return error.UnsafeInputLink;
        try missing.append(allocator, std.fs.path.basename(probe));
        probe = std.fs.path.dirname(probe) orelse return error.UnsafeInputLink;
    }
    return error.UnsafeInputLink;
}

fn treeWalk(allocator: std.mem.Allocator, io: std.Io, root: []const u8, prefix: []const u8, state: *TreeCounter) !void {
    try limits.relative(if (prefix.len == 0) "root" else prefix, limits.ignored_path, limits.ignored_depth);
    const path = if (prefix.len == 0) root else try std.fs.path.join(allocator, &.{ root, prefix });
    defer if (prefix.len != 0) allocator.free(path);
    const before = try physical.directory(io, path, false);
    try limits.addBounded(&state.directories, 1, limits.input_entries - state.files - state.symlinks);
    try physical.bind(allocator, &state.physical_hash, .{ "directory", prefix, physical.metadata(before) });
    const dir = try files.openDirectory(io, path, .artifact);
    defer dir.close(io);
    const names = try entries(allocator, io, dir, limits.input_entries - state.files - state.directories - state.symlinks);
    defer {
        for (names) |name| allocator.free(name);
        allocator.free(names);
    }
    for (names) |name| {
        const relative = if (prefix.len == 0) try allocator.dupe(u8, name) else try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name });
        defer allocator.free(relative);
        try limits.relative(relative, limits.ignored_path, limits.ignored_depth);
        const member = try dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
        defer member.close(io);
        const info = try files.snapshot(member);
        if (info.mode & linux.S.IFMT == linux.S.IFDIR) {
            try treeWalk(allocator, io, root, relative, state);
        } else if (info.mode & linux.S.IFMT == linux.S.IFREG) {
            try limits.addBounded(&state.files, 1, limits.input_entries - state.directories - state.symlinks);
            if (info.size > limits.input_file) return error.LimitExceeded;
            const absolute = try std.fs.path.join(allocator, &.{ root, relative });
            defer allocator.free(absolute);
            const identity = try treeFile(io, absolute, state);
            if (!std.meta.eql(identity.metadata, physical.metadata(info))) return error.InputChanged;
            try limits.addBounded(&state.bytes, @intCast(info.size), limits.input_bytes);
            try physical.bind(allocator, &state.content, .{ "file", relative, info.size, identity.sha256 });
            try physical.bind(allocator, &state.physical_hash, .{ "file", relative, physical.metadata(info) });
        } else if (info.mode & linux.S.IFMT == linux.S.IFLNK) {
            if (info.size == 0 or info.size >= 4096 or
                (info.uid != linux.geteuid() and info.uid != 0)) return error.UnsafeInputLink;
            var target_buffer: [4096]u8 = undefined;
            const link: std.Io.Dir = .{ .handle = member.handle };
            const length = try link.readLink(io, "", &target_buffer);
            if (length != info.size) return error.InputChanged;
            const link_path = try std.fs.path.join(allocator, &.{ path, name });
            defer allocator.free(link_path);
            const resolved: ?[:0]u8 = std.Io.Dir.realPathFileAbsoluteAlloc(io, link_path, allocator) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return error.UnsafeInputLink,
            };
            if (resolved) |actual| {
                defer allocator.free(actual);
                if (actual.len > limits.ignored_path) return error.UnsafeInputLink;
                const directory_target = if (files.openDirectory(io, actual, .artifact)) |opened| block: {
                    opened.close(io);
                    break :block true;
                } else |_| false;
                if (directory_target and
                    !(std.mem.eql(u8, actual, root) or
                        (actual.len > root.len and std.mem.startsWith(u8, actual, root) and actual[root.len] == '/')))
                    return error.UnsafeInputLink;
                var target_file: ?physical.File = null;
                if (!directory_target) target_file = try treeFile(io, actual, state);
                const target_metadata = if (directory_target)
                    physical.metadata(try physical.directory(io, actual, false))
                else
                    target_file.?.metadata;
                var components = try componentMap(allocator, io, actual, directory_target);
                defer closeComponentMap(allocator, &components);
                const target_sha: []const u8 = if (directory_target)
                    "directory"
                else
                    &target_file.?.sha256;
                try physical.bind(allocator, &state.content, .{
                    if (directory_target) "symlink-directory" else "symlink",
                    relative,
                    target_buffer[0..length],
                    target_sha,
                });
                try physical.bind(allocator, &state.physical_hash, .{
                    "symlink",       relative,                               target_buffer[0..length], physical.metadata(info),
                    target_metadata, std.json.Value{ .object = components },
                });
            } else try bindMissingTarget(allocator, io, path, relative, target_buffer[0..length], physical.metadata(info), state);
            try limits.addBounded(&state.symlinks, 1, limits.input_entries - state.files - state.directories);
            try limits.addBounded(&state.bytes, length, limits.input_bytes);
        } else return error.UnsafeInputEntry;
        const again = try dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
        defer again.close(io);
        if (!files.sameSnapshot(info, try files.snapshot(again))) return error.InputChanged;
    }
    if (!files.sameSnapshot(before, try physical.directory(io, path, false))) return error.InputChanged;
}

fn treeBounded(allocator: std.mem.Allocator, io: std.Io, binding: Binding, hash_limit: usize) !TreeRecord {
    if (hash_limit > limits.input_bytes) return error.LimitExceeded;
    var state: TreeCounter = .{
        .hash_limit = hash_limit,
        .identities = std.AutoHashMap([9]i128, [64]u8).init(allocator),
        .content = Sha256.init(.{}),
        .physical_hash = Sha256.init(.{}),
    };
    defer state.identities.deinit();
    state.content.update("uk.wamr.consumer-input-tree-content-v2\x00");
    state.physical_hash.update("uk.wamr.consumer-input-tree-physical-v2\x00");
    try treeWalk(allocator, io, binding.path, "", &state);
    return .{
        .role = binding.role,
        .path = binding.path,
        .files = state.files,
        .directories = state.directories,
        .symlinks = state.symlinks,
        .bytes = state.bytes,
        .content_sha256 = physical.hex(&state.content),
        .physical_sha256 = physical.hex(&state.physical_hash),
    };
}

pub fn tree(allocator: std.mem.Allocator, io: std.Io, binding: Binding) !TreeRecord {
    return treeBounded(allocator, io, binding, limits.input_bytes);
}

pub const Fixture = struct {
    pub fn treeWithHashLimit(allocator: std.mem.Allocator, io: std.Io, binding: Binding, hash_limit: usize) !TreeRecord {
        return treeBounded(allocator, io, binding, hash_limit);
    }
};

fn addAncestors(allocator: std.mem.Allocator, io: std.Io, path: []const u8, result: *std.ArrayList(DirectoryRecord)) !void {
    var current: ?[]const u8 = path;
    while (current) |component| : (current = std.fs.path.dirname(component)) {
        var present = false;
        for (result.items) |record| if (std.mem.eql(u8, component, record.path)) {
            present = true;
            break;
        };
        if (!present) try result.append(allocator, .{
            .path = component,
            .metadata = physical.metadata(try physical.directory(io, component, false)),
        });
        if (std.mem.eql(u8, component, "/")) break;
    }
}

fn quoted(allocator: std.mem.Allocator, writer: *std.Io.Writer, value: []const u8) !void {
    const encoded = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(encoded);
    try writer.writeAll(encoded);
}

fn consumerDocument(allocator: std.mem.Allocator, custody: Custody, aggregate: bool) ![]u8 {
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.writeAll("{\"schema\":\"uk.wamr.consumer-input-custody\",\"version\":2,\"files\":{");
    for (custody.files, 0..) |item, index| {
        if (index != 0) try writer.writeByte(',');
        try quoted(allocator, writer, item.role);
        try writer.writeByte(':');
        const encoded = try std.json.Stringify.valueAlloc(allocator, .{
            .path = item.path,
            .metadata = item.metadata,
            .sha256 = item.sha256,
        }, .{});
        defer allocator.free(encoded);
        try writer.writeAll(encoded);
    }
    try writer.writeAll("},\"trees\":{");
    for (custody.trees, 0..) |item, index| {
        if (index != 0) try writer.writeByte(',');
        try quoted(allocator, writer, item.role);
        try writer.writeByte(':');
        const encoded = try std.json.Stringify.valueAlloc(allocator, .{
            .path = item.path,
            .files = item.files,
            .directories = item.directories,
            .symlinks = item.symlinks,
            .bytes = item.bytes,
            .content_sha256 = item.content_sha256,
            .physical_sha256 = item.physical_sha256,
        }, .{});
        defer allocator.free(encoded);
        try writer.writeAll(encoded);
    }
    try writer.writeAll("},\"directories\":{");
    const sorted = try allocator.dupe(DirectoryRecord, custody.directories);
    defer allocator.free(sorted);
    std.mem.sort(DirectoryRecord, sorted, {}, struct {
        fn byPath(_: void, a: DirectoryRecord, b: DirectoryRecord) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.byPath);
    for (sorted, 0..) |item, index| {
        if (index != 0) try writer.writeByte(',');
        try quoted(allocator, writer, item.path);
        try writer.writeByte(':');
        const encoded = try std.json.Stringify.valueAlloc(allocator, item.metadata, .{});
        defer allocator.free(encoded);
        try writer.writeAll(encoded);
    }
    try writer.writeByte('}');
    if (aggregate) try writer.print(",\"aggregate_sha256\":\"{s}\"", .{&custody.aggregate_sha256});
    try writer.writeByte('}');
    return output.toOwnedSlice();
}

pub fn capture(allocator: std.mem.Allocator, io: std.Io, file_paths: []const Binding, tree_paths: []const Binding) !Custody {
    const sorted_files = try allocator.dupe(Binding, file_paths);
    defer allocator.free(sorted_files);
    const sorted_trees = try allocator.dupe(Binding, tree_paths);
    defer allocator.free(sorted_trees);
    std.mem.sort(Binding, sorted_files, {}, less);
    std.mem.sort(Binding, sorted_trees, {}, less);
    var result: Custody = .{
        .files = try allocator.alloc(FileRecord, sorted_files.len),
        .trees = try allocator.alloc(TreeRecord, sorted_trees.len),
        .directories = undefined,
        .aggregate_sha256 = undefined,
    };
    errdefer allocator.free(result.files);
    errdefer allocator.free(result.trees);
    var ancestors: std.ArrayList(DirectoryRecord) = .empty;
    defer ancestors.deinit(allocator);
    for (sorted_files, 0..) |binding, index| {
        if (index != 0 and std.mem.eql(u8, binding.role, sorted_files[index - 1].role))
            return error.DuplicateInputRole;
        const identity = try physical.readFile(io, binding.path, limits.input_file, false);
        if (identity.bytes == 0) return error.EmptyInputFile;
        for (result.files[0..index]) |prior| {
            if (prior.metadata[0] == identity.metadata[0] and prior.metadata[1] == identity.metadata[1])
                return error.DuplicateInputAlias;
        }
        result.files[index] = .{ .role = binding.role, .path = binding.path, .metadata = identity.metadata, .sha256 = identity.sha256 };
        try addAncestors(allocator, io, std.fs.path.dirname(binding.path) orelse return error.UnsafePath, &ancestors);
    }
    for (sorted_trees, 0..) |binding, index| {
        if (index != 0 and std.mem.eql(u8, binding.role, sorted_trees[index - 1].role))
            return error.DuplicateInputRole;
        result.trees[index] = try tree(allocator, io, binding);
        try addAncestors(allocator, io, binding.path, &ancestors);
    }
    for (ancestors.items) |record| {
        if (!std.meta.eql(physical.metadata(try physical.directory(io, record.path, false)), record.metadata))
            return error.InputChanged;
    }
    result.directories = try ancestors.toOwnedSlice(allocator);
    errdefer allocator.free(result.directories);
    const json = try consumerDocument(allocator, result, false);
    defer allocator.free(json);
    result.aggregate_sha256 = std.fmt.bytesToHex(try records.identity(allocator, json), .lower);
    return result;
}

pub fn requireSame(allocator: std.mem.Allocator, io: std.Io, expected: Custody, file_paths: []const Binding, tree_paths: []const Binding) !void {
    if (!std.mem.eql(u8, expected.schema, "uk.wamr.consumer-input-custody") or expected.version != 2 or
        file_paths.len != expected.files.len or tree_paths.len != expected.trees.len)
        return error.InvalidInputCustody;
    var current = try capture(allocator, io, file_paths, tree_paths);
    defer current.deinit(allocator);
    try compareCaptured(expected, current);
}

fn compareCaptured(expected: Custody, current: Custody) !void {
    if (!std.mem.eql(u8, expected.schema, "uk.wamr.consumer-input-custody") or expected.version != 2 or
        expected.files.len != current.files.len or expected.trees.len != current.trees.len)
        return error.InvalidInputCustody;
    if (!std.meta.eql(expected.aggregate_sha256, current.aggregate_sha256) or
        expected.directories.len != current.directories.len) return error.InputChanged;
    for (expected.files, current.files) |a, b| {
        if (!std.mem.eql(u8, a.role, b.role) or !std.mem.eql(u8, a.path, b.path) or
            !std.meta.eql(a.metadata, b.metadata) or !std.meta.eql(a.sha256, b.sha256))
            return error.InputChanged;
    }
    for (expected.trees, current.trees) |a, b| {
        if (!std.mem.eql(u8, a.role, b.role) or !std.mem.eql(u8, a.path, b.path) or
            a.files != b.files or a.directories != b.directories or
            a.symlinks != b.symlinks or a.bytes != b.bytes or
            !std.meta.eql(a.content_sha256, b.content_sha256) or
            !std.meta.eql(a.physical_sha256, b.physical_sha256))
            return error.InputChanged;
    }
    for (expected.directories, current.directories) |a, b| {
        if (!std.mem.eql(u8, a.path, b.path) or !std.meta.eql(a.metadata, b.metadata))
            return error.InputChanged;
    }
}

test "captured production inputs compare every pinned field without recapture" {
    var files_before = [_]FileRecord{.{
        .role = "tool:zig", .path = "/runtime/zig",
        .metadata = [_]i128{0} ** 9, .sha256 = [_]u8{'a'} ** 64,
    }};
    var trees_before = [_]TreeRecord{.{
        .role = "zig", .path = "/runtime", .files = 1, .directories = 1,
        .symlinks = 0, .bytes = 1, .content_sha256 = [_]u8{'b'} ** 64,
        .physical_sha256 = [_]u8{'c'} ** 64,
    }};
    var directories_before = [_]DirectoryRecord{.{
        .path = "/runtime", .metadata = [_]i128{0} ** 9,
    }};
    const expected: Custody = .{
        .files = &files_before, .trees = &trees_before,
        .directories = &directories_before, .aggregate_sha256 = [_]u8{'d'} ** 64,
    };
    var files_after = files_before;
    var trees_after = trees_before;
    var directories_after = directories_before;
    var current = expected;
    current.files = &files_after;
    current.trees = &trees_after;
    current.directories = &directories_after;
    try compareCaptured(expected, current);

    current.aggregate_sha256[0] = 'e';
    try std.testing.expectError(error.InputChanged, compareCaptured(expected, current));
    current.aggregate_sha256[0] = 'd';
    files_after[0].sha256[0] = 'e';
    try std.testing.expectError(error.InputChanged, compareCaptured(expected, current));
    files_after[0].sha256[0] = 'a';
    trees_after[0].physical_sha256[0] = 'e';
    try std.testing.expectError(error.InputChanged, compareCaptured(expected, current));
    trees_after[0].physical_sha256[0] = 'c';
    directories_after[0].metadata[0] = 1;
    try std.testing.expectError(error.InputChanged, compareCaptured(expected, current));
    directories_after[0].metadata[0] = 0;
    current.version = 1;
    try std.testing.expectError(error.InvalidInputCustody, compareCaptured(expected, current));
}
