//! Fixture-only, post-run diagnostic capture. Never an admission or execution path.
const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");
const pf = core.private_files;
const files = @import("preparation_files");
const elf = @import("producer_elf");
const qualification = @import("qualification");
const gate = qualification.gate;
pub const schema = @import("fixture_build_schema.zig");
const Sha = [64]u8;
const Hash = std.crypto.hash.sha2.Sha256;
const marker = "hyperv-persistence-private-build-baseline-v1";

const Identity = struct {
    device: u64,
    inode: u64,
    mode: u16,
    uid: u32,

    fn from(value: files.Metadata) Identity {
        return .{ .device = value.device, .inode = value.inode, .mode = value.mode, .uid = value.uid };
    }
};

fn dirMetadata(dir: std.Io.Dir) !files.Metadata {
    return checkedMetadata(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
}

fn checkedMetadata(file: std.Io.File) !files.Metadata {
    _ = try pf.snapshot(file);
    return files.metadata(file);
}

fn requireMetadata(expected: files.Metadata, actual: files.Metadata) !void {
    if (!std.meta.eql(expected, actual)) return error.SourceChanged;
}

fn requireSha(expected: Sha, actual: Sha) !void {
    if (!std.crypto.timing_safe.eql(Sha, expected, actual)) return error.HashMismatch;
}

fn checkRegular(value: files.Metadata, maximum: u64) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFREG or value.links != 1 or
        value.mode & 0o7022 != 0 or (value.uid != 0 and value.uid != linux.geteuid()))
        return error.UnsafeFile;
    if (value.size > maximum) return error.FileTooLarge;
}

fn checkDirectory(value: files.Metadata) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFDIR or value.mode & 0o7022 != 0 or
        (value.uid != 0 and value.uid != linux.geteuid())) return error.UnsafeFile;
}

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

const FilePin = struct {
    parent: files.Directory,
    file: std.Io.File,
    path: []const u8,
    before: files.Metadata,

    pub fn open(a: std.mem.Allocator, io: std.Io, path: []const u8, maximum: u64) !FilePin {
        try pf.absoluteFilePath(path);
        const parent = try files.Directory.open(a, io, std.fs.path.dirname(path).?);
        errdefer parent.close(a, io);
        const file = try parent.openFile(io, std.fs.path.basename(path), .artifact);
        errdefer file.close(io);
        const before = try checkedMetadata(file);
        try checkRegular(before, maximum);
        const result: FilePin = .{ .parent = parent, .file = file, .path = path, .before = before };
        try result.recheck(a, io);
        return result;
    }

    pub fn close(self: FilePin, a: std.mem.Allocator, io: std.Io) void {
        self.file.close(io);
        self.parent.close(a, io);
    }

    pub fn recheck(self: FilePin, a: std.mem.Allocator, io: std.Io) !void {
        try requireMetadata(self.before, try checkedMetadata(self.file));
        const parent = try files.Directory.open(a, io, std.fs.path.dirname(self.path).?);
        defer parent.close(a, io);
        try files.requireDirectoryIdentity(self.parent, parent);
        const named = try parent.openFile(io, std.fs.path.basename(self.path), .artifact);
        defer named.close(io);
        try requireMetadata(self.before, try checkedMetadata(named));
    }

    pub fn hash(self: FilePin, a: std.mem.Allocator, io: std.Io) !Sha {
        try self.recheck(a, io);
        const sha = try files.hashFile(io, self.file, self.before.size);
        try self.recheck(a, io);
        return sha;
    }

    fn read(self: FilePin, a: std.mem.Allocator, io: std.Io, maximum: u64) ![]u8 {
        if (self.before.size > maximum) return error.FileTooLarge;
        try self.recheck(a, io);
        const data = try a.alloc(u8, @intCast(self.before.size));
        errdefer a.free(data);
        if (try self.file.readPositionalAll(io, data, 0) != data.len) return error.SourceChanged;
        var extra: [1]u8 = undefined;
        if (try self.file.readPositionalAll(io, &extra, data.len) != 0) return error.SourceChanged;
        try self.recheck(a, io);
        return data;
    }

    fn proof(self: FilePin, sha: Sha) gate.FileProof {
        return .{
            .path = self.path,
            .size = self.before.size,
            .sha256 = sha,
            .device_major = @intCast(self.before.device >> 32),
            .device_minor = @truncate(self.before.device),
            .inode = self.before.inode,
            .uid = self.before.uid,
            .mode = self.before.mode,
            .links = @intCast(self.before.links),
        };
    }
};

const TreeEntry = struct {
    path: []const u8,
    metadata: files.Metadata,
    sha256: ?Sha = null,
};

pub const TreeRecord = struct {
    metadata_sha256: Sha,
    content_sha256: ?Sha,
    files: u32,
    directories: u32,
    bytes: u64,
};

pub const TreeLimits = struct {
    files: usize = schema.max_tree_files,
    bytes: u64 = schema.max_lib_bytes,
    per_file: u64 = schema.max_lib_file_bytes,
};

fn number(hash: *Hash, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .big);
    hash.update(&encoded);
}

fn pathHash(hash: *Hash, path: []const u8) void {
    number(hash, u32, @intCast(path.len));
    hash.update(path);
}

fn metadataHash(hash: *Hash, value: files.Metadata) void {
    inline for (std.meta.fields(files.Metadata)) |field|
        number(hash, field.type, @field(value, field.name));
}

fn walk(
    a: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    prefix: []const u8,
    entries: *std.ArrayList(TreeEntry),
    count: *u32,
    directories: *u32,
    bytes: *u64,
    limits: TreeLimits,
    content: bool,
    depth: usize,
) anyerror!void {
    if (depth > 64) return error.LimitExceeded;
    const before = try dirMetadata(directory);
    try checkDirectory(before);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        try pf.basename(entry.name);
        const relative = if (prefix.len == 0)
            try a.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(a, "{s}/{s}", .{ prefix, entry.name });
        if (relative.len > 4095) return error.UnsafePath;
        const held = try directory.openFile(io, entry.name, .{ .path_only = true, .follow_symlinks = false });
        defer held.close(io);
        const identity = try checkedMetadata(held);
        var digest: ?Sha = null;
        switch (identity.mode & linux.S.IFMT) {
            linux.S.IFDIR => {
                if (directories.* >= limits.files) return error.LimitExceeded;
                directories.* += 1;
                try checkDirectory(identity);
                const child = try directory.openDir(io, entry.name, .{ .follow_symlinks = false, .iterate = true });
                defer child.close(io);
                try requireMetadata(identity, try dirMetadata(child));
                try walk(a, io, child, relative, entries, count, directories, bytes, limits, content, depth + 1);
            },
            linux.S.IFREG => {
                try checkRegular(identity, limits.per_file);
                if (count.* >= limits.files or identity.size > limits.bytes -| bytes.*) return error.LimitExceeded;
                count.* += 1;
                bytes.* += identity.size;
                if (content) {
                    const source: files.Directory = .{ .dir = directory, .path = "" };
                    const input = try source.openFile(io, entry.name, .artifact);
                    defer input.close(io);
                    try requireMetadata(identity, try checkedMetadata(input));
                    digest = try files.hashFile(io, input, identity.size);
                    try requireMetadata(identity, try checkedMetadata(input));
                }
            },
            else => return error.UnsafeFile,
        }
        const named = try directory.openFile(io, entry.name, .{ .path_only = true, .follow_symlinks = false });
        defer named.close(io);
        try requireMetadata(identity, try checkedMetadata(named));
        try requireMetadata(identity, try checkedMetadata(held));
        try entries.append(a, .{ .path = relative, .metadata = identity, .sha256 = digest });
    }
    try requireMetadata(before, try dirMetadata(directory));
}

/// Metadata-only by default. Every entry type is inspected; links are not skipped.
pub fn observeTree(a: std.mem.Allocator, io: std.Io, path: []const u8, limits: TreeLimits, content: bool) !TreeRecord {
    const root = try files.Directory.open(a, io, path);
    defer root.close(a, io);
    return observeHeldTree(a, io, root, limits, content);
}

fn observeHeldTree(a: std.mem.Allocator, io: std.Io, root: files.Directory, limits: TreeLimits, content: bool) !TreeRecord {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var entries: std.ArrayList(TreeEntry) = .empty;
    var count: u32 = 0;
    var directories: u32 = 0;
    var bytes: u64 = 0;
    const before = try dirMetadata(root.dir);
    // Each scan uses a new file description: directory iteration consumes its offset.
    const scan = try root.dir.openDir(io, ".", .{ .follow_symlinks = false, .iterate = true });
    defer scan.close(io);
    try requireMetadata(before, try dirMetadata(scan));
    try walk(scratch, io, scan, "", &entries, &count, &directories, &bytes, limits, content, 0);
    std.mem.sort(TreeEntry, entries.items, {}, struct {
        fn less(_: void, left: TreeEntry, right: TreeEntry) bool {
            return std.mem.lessThan(u8, left.path, right.path);
        }
    }.less);
    var physical = Hash.init(.{});
    physical.update("hyperv-persistence-metadata-tree-v1\x00");
    metadataHash(&physical, before);
    var contents = Hash.init(.{});
    contents.update("hyperv-persistence-content-tree-v1\x00");
    number(&contents, u16, before.mode & 0o7777);
    for (entries.items) |entry| {
        pathHash(&physical, entry.path);
        metadataHash(&physical, entry.metadata);
        pathHash(&contents, entry.path);
        number(&contents, u16, entry.metadata.mode);
        if (entry.metadata.mode & linux.S.IFMT == linux.S.IFREG) {
            number(&contents, u64, entry.metadata.size);
            if (entry.sha256) |sha| contents.update(&sha);
        }
    }
    try requireMetadata(before, try dirMetadata(root.dir));
    const named = try files.Directory.open(a, io, root.path);
    defer named.close(a, io);
    try requireMetadata(before, try dirMetadata(named.dir));
    return .{
        .metadata_sha256 = std.fmt.bytesToHex(physical.finalResult(), .lower),
        .content_sha256 = if (content) std.fmt.bytesToHex(contents.finalResult(), .lower) else null,
        .files = count,
        .directories = directories,
        .bytes = bytes,
    };
}

const FileRecord = struct { role: []const u8, metadata: files.Metadata };
const NamedTree = struct { role: []const u8, tree: TreeRecord };
const InputsRecord = struct { files: []const FileRecord, trees: []const NamedTree };
const NamedFilePin = struct { role: []const u8, pin: FilePin };
const TreePin = struct { role: []const u8, directory: files.Directory, before: TreeRecord };

const Inputs = struct {
    files: std.ArrayList(NamedFilePin) = .empty,
    trees: std.ArrayList(TreePin) = .empty,

    fn close(self: *Inputs, a: std.mem.Allocator, io: std.Io) void {
        for (self.files.items) |item| item.pin.close(a, io);
        for (self.trees.items) |item| item.directory.close(a, io);
        self.files.deinit(a);
        self.trees.deinit(a);
    }

    fn addFile(self: *Inputs, a: std.mem.Allocator, io: std.Io, role: []const u8, path: []const u8, limit: u64) !void {
        const pin = try FilePin.open(a, io, path, limit);
        errdefer pin.close(a, io);
        try self.files.append(a, .{ .role = role, .pin = pin });
    }

    fn addTree(self: *Inputs, a: std.mem.Allocator, io: std.Io, role: []const u8, path: []const u8) !void {
        const directory = try files.Directory.open(a, io, path);
        errdefer directory.close(a, io);
        const before = try observeHeldTree(a, io, directory, .{}, false);
        try self.trees.append(a, .{ .role = role, .directory = directory, .before = before });
    }

    fn open(a: std.mem.Allocator, io: std.Io, request: schema.Request) !Inputs {
        var result: Inputs = .{};
        errdefer result.close(a, io);
        try result.addFile(a, io, "compiler", request.compiler, schema.max_compiler_bytes);
        try result.addFile(a, io, "main_options", request.main_options, schema.max_metadata_bytes);
        try result.addFile(a, io, "main_source", request.main_source, schema.max_lib_file_bytes);
        try result.addTree(a, io, "compiler_lib", request.compiler_lib);
        try result.addTree(a, io, "repository_hyperv", request.repository_hyperv);
        try result.addTree(a, io, "repository_build", request.repository_build);
        for (request.modules) |module| {
            try result.addFile(a, io, try std.fmt.allocPrint(a, "module_{s}_root", .{module.name}), module.root, schema.max_lib_file_bytes);
            try result.addTree(a, io, try std.fmt.allocPrint(a, "module_{s}_envelope", .{module.name}), module.scope);
        }
        try result.recheck(a, io);
        return result;
    }

    fn record(self: Inputs, a: std.mem.Allocator) !InputsRecord {
        const file_records = try a.alloc(FileRecord, self.files.items.len);
        for (self.files.items, file_records) |item, *entry| entry.* = .{ .role = item.role, .metadata = item.pin.before };
        const trees = try a.alloc(NamedTree, self.trees.items.len);
        for (self.trees.items, trees) |item, *entry| entry.* = .{ .role = item.role, .tree = item.before };
        return .{ .files = file_records, .trees = trees };
    }

    fn require(self: Inputs, expected: InputsRecord) !void {
        if (self.files.items.len != expected.files.len or self.trees.items.len != expected.trees.len)
            return error.BaselineMismatch;
        for (self.files.items, expected.files) |actual, before| {
            if (!std.mem.eql(u8, actual.role, before.role)) return error.BaselineMismatch;
            try requireMetadata(before.metadata, actual.pin.before);
        }
        for (self.trees.items, expected.trees) |actual, before| {
            if (!std.mem.eql(u8, actual.role, before.role) or !std.meta.eql(actual.before, before.tree))
                return error.SourceChanged;
        }
    }

    fn recheck(self: Inputs, a: std.mem.Allocator, io: std.Io) !void {
        for (self.files.items) |item| try item.pin.recheck(a, io);
        for (self.trees.items) |item| {
            const now = try observeHeldTree(a, io, item.directory, .{}, false);
            if (!std.meta.eql(item.before, now)) return error.SourceChanged;
        }
    }
};

const Custody = struct {
    parent: pf.Directory,
    parent_lock: pf.Locked,
    root: pf.Directory,
    lock: pf.Locked,
    path: []const u8,
    parent_identity: Identity,
    root_identity: Identity,

    fn open(io: std.Io, path: []const u8, fresh: bool) !Custody {
        try pf.absoluteFilePath(path);
        const parent = try files.openPrivate(io, std.fs.path.dirname(path).?);
        errdefer parent.close(io);
        var parent_lock = try parent.lock(io);
        errdefer parent_lock.close(io);
        if (fresh) {
            try parent.dir.createDir(io, std.fs.path.basename(path), .fromMode(0o700));
            try syncDirectory(io, parent.dir);
        }
        const root = try files.openPrivate(io, path);
        errdefer root.close(io);
        var lock = try root.lock(io);
        errdefer lock.close(io);
        const result: Custody = .{
            .parent = parent,
            .parent_lock = parent_lock,
            .root = root,
            .lock = lock,
            .path = path,
            .parent_identity = Identity.from(try dirMetadata(parent.dir)),
            .root_identity = Identity.from(try dirMetadata(root.dir)),
        };
        var mutable = result;
        try mutable.recheck(io);
        return mutable;
    }

    fn close(self: *Custody, io: std.Io) void {
        self.lock.close(io);
        self.root.close(io);
        self.parent_lock.close(io);
        self.parent.close(io);
    }

    fn recheck(self: *Custody, io: std.Io) !void {
        try files.requireLock(io, &self.parent_lock);
        try files.requireLock(io, &self.lock);
        const named_parent = try files.openPrivate(io, std.fs.path.dirname(self.path).?);
        defer named_parent.close(io);
        const named = try files.openPrivate(io, self.path);
        defer named.close(io);
        if (!std.meta.eql(self.parent_identity, Identity.from(try dirMetadata(named_parent.dir))) or
            !std.meta.eql(self.root_identity, Identity.from(try dirMetadata(named.dir))))
            return error.SourceChanged;
    }
};

const Baseline = struct {
    marker: []const u8,
    root_path: []const u8,
    request: schema.Request,
    parent_identity: Identity,
    root_identity: Identity,
    collector: FileRecord,
    collector_sha256: Sha,
    inputs: InputsRecord,
};

const Plan = struct {
    marker: []const u8,
    baseline_sha256: Sha,
    request: schema.Request,
    parent: files.Metadata,
    raw_worker: files.Metadata,
    selected_worker: files.Metadata,
};

fn hashBytes(bytes: []const u8) Sha {
    var result: [32]u8 = undefined;
    Hash.hash(bytes, &result, .{});
    return std.fmt.bytesToHex(result, .lower);
}

fn canonical(a: std.mem.Allocator, value: anytype, maximum: usize) ![]const u8 {
    const json = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(json);
    if (json.len >= maximum) return error.FileTooLarge;
    return std.fmt.allocPrint(a, "{s}\n", .{json});
}

fn publish(a: std.mem.Allocator, io: std.Io, lock: *pf.Locked, name: []const u8, value: anytype, maximum: usize) !void {
    try files.requireLock(io, lock);
    const bytes = try canonical(a, value, maximum);
    const result = try files.publish(lock, io, name, bytes);
    if (result.status != .durable or result.failures.primary != null or
        result.failures.recording != null or result.failures.cleanup != null) return error.PublicationFailed;
    const actual = try lock.directory.read(io, a, name, maximum, null);
    if (!std.mem.eql(u8, actual, bytes)) return error.ReportChanged;
    try files.requireLock(io, lock);
}

fn parse(comptime T: type, a: std.mem.Allocator, bytes: []const u8) !T {
    return std.json.parseFromSliceLeaky(T, a, bytes, .{ .allocate = .alloc_always });
}

pub fn validateRequest(request: schema.Request, parent_present: bool) !void {
    try schema.validateIdentity(request.source_commit);
    try schema.validateIdentity(request.source_tree);
    if (request.configured_json.len == 0 or request.configured_json.len > schema.max_metadata_bytes)
        return error.InvalidConfiguration;
    if (parent_present) try pf.absoluteFilePath(request.parent) else if (request.parent.len != 0)
        return error.InvalidParentPhase;
    inline for (.{
        "raw_worker",        "selected_worker",  "compiler",     "compiler_lib", "main_options",    "main_source",
        "repository_hyperv", "repository_build", "worker_proof", "fixture_log",  "invocation_exit",
    }) |field| try pf.absoluteFilePath(@field(request, field));
    if (request.modules.len == 0 or request.modules.len > schema.max_modules) return error.InvalidModules;
    for (request.modules, 0..) |module, index| {
        try schema.validateModuleName(module.name);
        try pf.absoluteFilePath(module.root);
        try pf.absoluteFilePath(module.scope);
        if (!std.mem.startsWith(u8, module.root, module.scope) or module.root.len <= module.scope.len or
            module.root[module.scope.len] != '/') return error.InvalidModuleScope;
        for (request.modules[0..index]) |previous| if (std.mem.eql(u8, previous.name, module.name))
            return error.DuplicateModule;
    }
}

pub fn requireSameRequest(a: std.mem.Allocator, before: schema.Request, after: schema.Request) !void {
    if (before.parent.len != 0) return error.BaselineMismatch;
    var normalized = after;
    normalized.parent = "";
    const left = try canonical(a, before, schema.max_plan_bytes);
    defer a.free(left);
    const right = try canonical(a, normalized, schema.max_plan_bytes);
    defer a.free(right);
    if (!std.mem.eql(u8, left, right)) return error.BaselineMismatch;
}

pub const Artifact = struct { role: []const u8, path: []const u8, size: u64, sha256: Sha };
pub const Observation = struct { size: u64, sha256: Sha };

/// The fresh private child and exclusive names deliberately retain partial history.
fn copyPinned(a: std.mem.Allocator, io: std.Io, source: FilePin, target: std.Io.Dir, name: []const u8, mode: u16) !Observation {
    return copyPinnedImpl(a, io, source, target, name, mode, false);
}

fn copyPinnedImpl(a: std.mem.Allocator, io: std.Io, source: FilePin, target: std.Io.Dir, name: []const u8, mode: u16, inject_partial: bool) !Observation {
    if (!@import("builtin").is_test and inject_partial) unreachable;
    try pf.basename(name);
    try source.recheck(a, io);
    const file = try target.createFile(io, name, .{ .read = true, .exclusive = true, .permissions = .fromMode(mode) });
    defer file.close(io);
    const created = try checkedMetadata(file);
    if (created.mode & 0o7777 != mode or created.uid != linux.geteuid() or created.links != 1) return error.UnsafeFile;
    // Persist even the exclusive empty name before starting the streamed copy.
    try syncDirectory(io, target);
    var hash = Hash.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: u64 = 0;
    while (offset < source.before.size) {
        const length: usize = @intCast(@min(buffer.len, source.before.size - offset));
        if (try source.file.readPositionalAll(io, buffer[0..length], offset) != length) return error.SourceChanged;
        hash.update(buffer[0..length]);
        try file.writePositionalAll(io, buffer[0..length], offset);
        offset += length;
        if (@import("builtin").is_test and inject_partial) {
            try file.sync(io);
            return error.InjectedPrimaryFailure;
        }
    }
    if (try source.file.readPositionalAll(io, buffer[0..1], offset) != 0) return error.SourceChanged;
    try source.recheck(a, io);
    const sha = std.fmt.bytesToHex(hash.finalResult(), .lower);
    try file.sync(io);
    const completed = try checkedMetadata(file);
    try checkRegular(completed, source.before.size);
    if (completed.size != source.before.size or !std.meta.eql(Identity.from(created), Identity.from(completed)))
        return error.SourceChanged;
    try requireSha(sha, try files.hashFile(io, file, completed.size));
    try requireMetadata(completed, try checkedMetadata(file));
    const named = try target.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
    defer named.close(io);
    try requireMetadata(completed, try checkedMetadata(named));
    try requireSha(sha, try source.hash(a, io));
    try syncDirectory(io, target);
    return .{ .size = completed.size, .sha256 = sha };
}

pub fn baseline(allocator: std.mem.Allocator, io: std.Io, root: []const u8, request: schema.Request, self_path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try validateRequest(request, false);
    try configuredModules(try configuredMetadata(a, request.configured_json), request.modules);
    var custody = try Custody.open(io, root, true);
    defer custody.close(io);
    var inputs = try Inputs.open(a, io, request);
    defer inputs.close(a, io);
    const collector = try FilePin.open(a, io, self_path, schema.max_parent_bytes);
    defer collector.close(a, io);
    const copied = try copyPinned(a, io, collector, custody.root.dir, "collector", 0o700);
    const private_collector = try FilePin.open(a, io, try std.fs.path.join(a, &.{ root, "collector" }), schema.max_parent_bytes);
    defer private_collector.close(a, io);
    try inputs.recheck(a, io);
    try custody.recheck(io);
    try publish(a, io, &custody.lock, "baseline.json", Baseline{
        .marker = marker,
        .root_path = root,
        .request = request,
        .parent_identity = custody.parent_identity,
        .root_identity = custody.root_identity,
        .collector = .{ .role = "collector", .metadata = private_collector.before },
        .collector_sha256 = copied.sha256,
        .inputs = try inputs.record(a),
    }, schema.max_plan_bytes);
    try inputs.recheck(a, io);
    try private_collector.recheck(a, io);
    try custody.recheck(io);
}

fn readBaseline(a: std.mem.Allocator, io: std.Io, custody: *Custody) !struct { value: Baseline, bytes: []const u8, pin: FilePin } {
    const pin = try FilePin.open(a, io, try std.fs.path.join(a, &.{ custody.path, "baseline.json" }), schema.max_plan_bytes);
    errdefer pin.close(a, io);
    if (pin.before.mode & 0o7777 != 0o600) return error.UnsafeFile;
    const bytes = try pin.read(a, io, schema.max_plan_bytes);
    const value = try parse(Baseline, a, bytes);
    if (!std.mem.eql(u8, marker, value.marker) or !std.mem.eql(u8, custody.path, value.root_path) or
        !std.meta.eql(custody.parent_identity, value.parent_identity) or
        !std.meta.eql(custody.root_identity, value.root_identity)) return error.BaselineMismatch;
    try validateRequest(value.request, false);
    return .{ .value = value, .bytes = bytes, .pin = pin };
}

pub fn prepare(allocator: std.mem.Allocator, io: std.Io, root: []const u8, request: schema.Request) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try validateRequest(request, true);
    var custody = try Custody.open(io, root, false);
    defer custody.close(io);
    const before = try readBaseline(a, io, &custody);
    defer before.pin.close(a, io);
    try requireSameRequest(a, before.value.request, request);
    var inputs = try Inputs.open(a, io, request);
    defer inputs.close(a, io);
    try inputs.require(before.value.inputs);
    const parent = try FilePin.open(a, io, request.parent, schema.max_parent_bytes);
    defer parent.close(a, io);
    const raw = try FilePin.open(a, io, request.raw_worker, schema.max_raw_worker_bytes);
    defer raw.close(a, io);
    const selected = try FilePin.open(a, io, request.selected_worker, schema.max_selected_worker_bytes);
    defer selected.close(a, io);
    try inputs.recheck(a, io);
    try custody.recheck(io);
    try publish(a, io, &custody.lock, "plan.json", Plan{
        .marker = marker,
        .baseline_sha256 = hashBytes(before.bytes),
        .request = request,
        .parent = parent.before,
        .raw_worker = raw.before,
        .selected_worker = selected.before,
    }, schema.max_plan_bytes);
    try parent.recheck(a, io);
    try raw.recheck(a, io);
    try selected.recheck(a, io);
    try before.pin.recheck(a, io);
    try inputs.recheck(a, io);
    try custody.recheck(io);
}

pub fn parseExit(bytes: []const u8) !u8 {
    const value = if (std.mem.endsWith(u8, bytes, "\n")) bytes[0 .. bytes.len - 1] else bytes;
    if (value.len == 0 or value.len > 3 or (value.len > 1 and value[0] == '0')) return error.InvalidExitMarker;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidExitMarker;
    return std.fmt.parseInt(u8, value, 10) catch error.InvalidExitMarker;
}

fn jsonEqual(left: std.json.Value, right: std.json.Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .null => true,
        .bool => left.bool == right.bool,
        .integer => left.integer == right.integer,
        .float => left.float == right.float,
        .number_string => std.mem.eql(u8, left.number_string, right.number_string),
        .string => std.mem.eql(u8, left.string, right.string),
        .array => blk: {
            if (left.array.items.len != right.array.items.len) break :blk false;
            for (left.array.items, right.array.items) |l, r| if (!jsonEqual(l, r)) break :blk false;
            break :blk true;
        },
        .object => blk: {
            if (left.object.count() != right.object.count()) break :blk false;
            var iterator = left.object.iterator();
            while (iterator.next()) |entry| {
                if (!jsonEqual(entry.value_ptr.*, right.object.get(entry.key_ptr.*) orelse break :blk false))
                    break :blk false;
            }
            break :blk true;
        },
    };
}

fn verifyProof(a: std.mem.Allocator, bytes: []const u8, raw: FilePin, raw_bytes: []const u8, selected: FilePin, selected_bytes: []const u8) !gate.ContentProof {
    if (bytes.len > schema.max_metadata_bytes) return error.FileTooLarge;
    const actual = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    if (actual.value != .object) return error.InvalidWorkerProof;
    const policy_value = actual.value.object.get("layout_policy") orelse return error.InvalidWorkerProof;
    if (policy_value != .string) return error.InvalidWorkerProof;
    const policy = std.meta.stringToEnum(gate.LayoutPolicy, policy_value.string) orelse return error.InvalidWorkerProof;
    if (raw.before.device == selected.before.device and raw.before.inode == selected.before.inode)
        return error.NotDistinctFiles;
    if (raw.before.mode & 0o111 == 0 or selected.before.mode & 0o111 == 0) return error.UnsafeExecutable;
    const content = try gate.compareWithPolicy(a, raw_bytes, selected_bytes, policy);
    const expected = try std.json.Stringify.valueAlloc(a, qualification.Proof{
        .layout_policy = policy,
        .worker = .{
            .raw = raw.proof(hashBytes(raw_bytes)),
            .candidate = selected.proof(hashBytes(selected_bytes)),
            .content = content,
        },
    }, .{});
    const document = try std.json.parseFromSlice(std.json.Value, a, expected, .{});
    if (!jsonEqual(actual.value, document.value)) return error.WorkerProofMismatch;
    return content;
}

const FileEvidence = struct { role: []const u8, size: u64, sha256: Sha, metadata_sha256: Sha };
const TreeEvidence = struct { role: []const u8, tree: TreeRecord };

fn fileMetadataDigest(value: files.Metadata) Sha {
    var hash = Hash.init(.{});
    hash.update("hyperv-persistence-file-metadata-v1\x00");
    metadataHash(&hash, value);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn artifact(role: []const u8, path: []const u8, observed: Observation) Artifact {
    return .{ .role = role, .path = path, .size = observed.size, .sha256 = observed.sha256 };
}

fn objectFields(value: std.json.Value, names: []const []const u8) !void {
    if (value != .object or value.object.count() != names.len) return error.InvalidBuildMetadata;
    for (names) |name| if (!value.object.contains(name)) return error.InvalidBuildMetadata;
}

fn literal(value: std.json.Value, expected: []const u8) !void {
    if (value != .string or !std.mem.eql(u8, value.string, expected)) return error.InvalidBuildMetadata;
}

fn safeAtom(value: []const u8) !void {
    if (value.len == 0 or value.len > 256) return error.InvalidBuildMetadata;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.' and byte != '+')
        return error.InvalidBuildMetadata;
}

fn safeValue(value: std.json.Value, depth: usize) !void {
    if (depth > 16) return error.InvalidBuildMetadata;
    switch (value) {
        .string => try safeAtom(value.string),
        .integer, .bool, .null => {},
        .number_string => {
            _ = std.fmt.parseInt(u64, value.number_string, 10) catch return error.InvalidBuildMetadata;
        },
        .array => {
            if (value.array.items.len > 4096) return error.InvalidBuildMetadata;
            for (value.array.items) |item| try safeValue(item, depth + 1);
        },
        .object => {
            if (value.object.count() > 64) return error.InvalidBuildMetadata;
            var iterator = value.object.iterator();
            while (iterator.next()) |entry| {
                try safeAtom(entry.key_ptr.*);
                try safeValue(entry.value_ptr.*, depth + 1);
            }
        },
        else => return error.InvalidBuildMetadata,
    }
}

const observed_names = [_][]const u8{
    "zig_version",               "zig_version_string",              "zig_backend",      "mode",        "is_test",            "output_mode",
    "link_mode",                 "object_format",                   "single_threaded",  "link_libc",   "link_libcpp",        "error_return_tracing",
    "position_independent_code", "position_independent_executable", "strip_debug_info", "code_model",  "omit_frame_pointer", "valgrind_support",
    "sanitize_thread",           "sanitize_c",                      "fuzz",             "stack_check", "stack_protector",    "red_zone",
    "unwind_tables",             "dwarf_format",
};

fn knownName(name: []const u8, names: []const []const u8) bool {
    for (names) |expected| if (std.mem.eql(u8, name, expected)) return true;
    return false;
}

fn validateFeatures(value: std.json.Value) !void {
    try objectFields(value, &.{ "available_feature_count", "word_bit_width", "bitset_words", "names" });
    if (value.object.get("available_feature_count").? != .integer or
        value.object.get("word_bit_width").? != .integer or
        value.object.get("bitset_words").? != .array or value.object.get("names").? != .array)
        return error.InvalidBuildMetadata;
    for (value.object.get("bitset_words").?.array.items) |item| {
        // The std serializer may emit the high bit of a u64 as number_string.
        if (item != .integer and item != .number_string) return error.InvalidBuildMetadata;
    }
    for (value.object.get("names").?.array.items) |item| {
        if (item != .string) return error.InvalidBuildMetadata;
        try safeAtom(item.string);
    }
}

fn validateTarget(value: std.json.Value) !void {
    try objectFields(value, &.{ "cpu", "os", "abi", "ofmt", "dynamic_linker_present", "dynamic_linker_path", "dynamic_linker_sha256" });
    try literal(value.object.get("dynamic_linker_path").?, "omitted_path");
    if (value.object.get("dynamic_linker_present").? != .bool) return error.InvalidBuildMetadata;
    const linker_sha = value.object.get("dynamic_linker_sha256").?;
    if (value.object.get("dynamic_linker_present").?.bool) {
        if (linker_sha != .string) return error.InvalidBuildMetadata;
        _ = core.contracts.parseSha256(linker_sha.string) catch return error.InvalidBuildMetadata;
    } else if (linker_sha != .null) return error.InvalidBuildMetadata;
    const cpu = value.object.get("cpu").?;
    try objectFields(cpu, &.{ "arch", "model", "features" });
    const model = cpu.object.get("model").?;
    try objectFields(model, &.{ "name", "llvm_name", "baseline_features" });
    try validateFeatures(model.object.get("baseline_features").?);
    try validateFeatures(cpu.object.get("features").?);
    const os = value.object.get("os").?;
    try objectFields(os, &.{ "tag", "version_range_kind", "version_range" });
    try literal(os.object.get("tag").?, "linux");
    try literal(os.object.get("version_range_kind").?, "linux");
    const range = os.object.get("version_range").?;
    try objectFields(range, &.{ "range", "glibc", "android" });
    try objectFields(range.object.get("range").?, &.{ "min", "max" });
    for ([_]std.json.Value{
        range.object.get("range").?.object.get("min").?,
        range.object.get("range").?.object.get("max").?,
        range.object.get("glibc").?,
    }) |version| try objectFields(version, &.{ "major", "minor", "patch", "pre", "build" });
}

fn configuredModules(configured: std.json.Value, modules: []const schema.Module) !void {
    const graph = configured.object.get("modules").?.array.items;
    if (graph.len != modules.len) return error.InvalidModules;
    for (graph, modules) |entry, module| {
        try literal(entry.object.get("name").?, module.name);
        for (entry.object.get("imports").?.array.items) |edge| {
            const import_name = edge.object.get("name").?;
            const target_name = edge.object.get("module").?;
            if (import_name != .string or target_name != .string) return error.InvalidModules;
            try schema.validateModuleName(import_name.string);
            const found = for (modules) |target| {
                if (std.mem.eql(u8, target.name, target_name.string)) break true;
            } else false;
            if (!found) return error.InvalidModules;
        }
    }
}

pub fn configuredMetadata(a: std.mem.Allocator, bytes: []const u8) !std.json.Value {
    if (bytes.len > schema.max_metadata_bytes) return error.FileTooLarge;
    const value = try parse(std.json.Value, a, bytes);
    try objectFields(value, &.{
        "schema",          "origin",                     "null_semantics",          "source_identity", "test_selection", "test_filters",
        "test_run_seed",   "parent_compilation_bookend", "worker_compiler_bookend", "module_scope",    "modules",        "target_query",
        "resolved_target", "compile",                    "root_module",
    });
    try literal(value.object.get("schema").?, "hyperv_persistence_fixture_configured_build_v1");
    try literal(value.object.get("origin").?, "actual_parent_Compile_and_rootModule");
    try literal(value.object.get("null_semantics").?, "unspecified_compiler_default_not_observed_false");
    try literal(value.object.get("source_identity").?, "user_supplied_not_authenticated");
    try literal(value.object.get("test_selection").?, "all_unfiltered_35_main_cases");
    try literal(value.object.get("parent_compilation_bookend").?, "metadata_only_baseline_and_prepare");
    try literal(value.object.get("worker_compiler_bookend").?, "not_claimed_workers_precede_baseline");
    try literal(value.object.get("module_scope").?, "configured_reachable_package_envelopes_not_compiler_resolved_import_embed_closure");
    const filters = value.object.get("test_filters").?;
    if (filters != .array or filters.array.items.len != 0) return error.InvalidBuildMetadata;
    const modules = value.object.get("modules").?;
    if (modules != .array or modules.array.items.len == 0 or modules.array.items.len > schema.max_modules)
        return error.InvalidBuildMetadata;
    for (modules.array.items) |module| {
        try objectFields(module, &.{ "name", "imports" });
        if (module.object.get("name").? != .string or module.object.get("imports").? != .array)
            return error.InvalidBuildMetadata;
        try schema.validateModuleName(module.object.get("name").?.string);
        for (module.object.get("imports").?.array.items) |item| try objectFields(item, &.{ "name", "module" });
    }
    try objectFields(value.object.get("target_query").?, &.{
        "cpu_arch", "cpu_model",      "explicit_cpu_model",       "cpu_features_add",    "cpu_features_sub",
        "os_tag",   "os_version_min", "os_version_max",           "glibc_version",       "android_api_level",
        "abi",      "ofmt",           "dynamic_linker_specified", "dynamic_linker_path",
    });
    try literal(value.object.get("target_query").?.object.get("dynamic_linker_path").?, "omitted_path");
    try validateTarget(value.object.get("resolved_target").?);
    try objectFields(value.object.get("compile").?, &.{
        "debug_compiler_runtime_libs", "incremental",        "debug_incremental", "build_id_kind",        "build_id_hex",           "build_id_override",
        "kind",                        "use_llvm",           "use_lld",           "use_new_linker",       "linkage",                "pie",
        "lto",                         "stack_size",         "rdynamic",          "link_gc_sections",     "link_function_sections", "link_data_sections",
        "compress_debug_sections",     "bundle_compiler_rt", "bundle_ubsan_rt",   "zig_lib_dir_override", "custom_test_runner",
    });
    try literal(value.object.get("compile").?.object.get("kind").?, "test");
    try objectFields(value.object.get("root_module").?, &.{
        "optimize",    "strip",      "dwarf_format",       "unwind_tables", "single_threaded", "stack_protector",
        "stack_check", "sanitize_c", "sanitize_thread",    "fuzz",          "code_model",      "valgrind",
        "pic",         "red_zone",   "omit_frame_pointer", "error_tracing", "link_libc",       "link_libcpp",
        "no_builtin",
    });
    try safeValue(value, 0);
    return value;
}

pub fn parentMetadata(a: std.mem.Allocator, bytes: []const u8, request: schema.Request) !std.json.Value {
    if (bytes.len > schema.max_parent_bytes) return error.FileTooLarge;
    var image = try elf.Image.parse(a, bytes);
    defer image.deinit();
    const section = try image.section(schema.section_name);
    const sh = section.header;
    if ((sh.sh_type != std.elf.SHT_NOTE and sh.sh_type != std.elf.SHT_PROGBITS) or
        sh.sh_size < schema.note_prefix_bytes or sh.sh_size > schema.max_note_bytes or
        sh.sh_addralign != schema.note_alignment or sh.sh_addr % schema.note_alignment != 0 or
        sh.sh_offset % schema.note_alignment != 0 or
        sh.sh_flags & ~@as(u64, std.elf.SHF_ALLOC | std.elf.SHF_WRITE) != 0 or
        (sh.sh_type == std.elf.SHT_NOTE and sh.sh_flags & std.elf.SHF_WRITE != 0))
        return error.InvalidBuildMetadata;
    try image.requireLoadedSection(section);
    for (image.programs) |program| {
        if (program.p_type == std.elf.PT_LOAD and program.p_flags & std.elf.PF_X != 0 and
            sh.sh_addr < program.p_vaddr + program.p_memsz and program.p_vaddr < sh.sh_addr + sh.sh_size)
            return error.InvalidBuildMetadata;
    }
    if (try image.symbol(schema.symbol_name) != sh.sh_addr) return error.InvalidBuildMetadata;
    for (image.symbols) |symbol| {
        if (!std.mem.eql(u8, symbol.name, schema.symbol_name)) continue;
        const sym = symbol.header;
        const binding = sym.st_info >> 4;
        // The self-hosted linker localizes this export in its final executable.
        if (sym.st_info & 15 != std.elf.STT_OBJECT or
            (binding != std.elf.STB_GLOBAL and !(sh.sh_type == std.elf.SHT_PROGBITS and binding == std.elf.STB_LOCAL)) or sym.st_other != 0 or
            sym.st_size != sh.sh_size or sym.st_shndx >= image.sections.len or
            !std.mem.eql(u8, image.sections[sym.st_shndx].name, schema.section_name))
            return error.InvalidBuildMetadata;
    }
    const data = try image.sectionData(section);
    const note = try elf.structure(std.elf.Elf64_Nhdr, data, 0, image.header.endian);
    if (note.n_namesz != schema.note_name.len or note.n_type != schema.note_type or
        note.n_descsz == 0 or note.n_descsz > schema.max_metadata_bytes or
        data.len != schema.note_prefix_bytes + std.mem.alignForward(usize, note.n_descsz, schema.note_alignment) or
        !std.mem.eql(u8, data[@sizeOf(std.elf.Elf64_Nhdr)..schema.note_prefix_bytes], schema.note_name))
        return error.InvalidBuildMetadata;
    const end = schema.note_prefix_bytes + note.n_descsz;
    for (data[end..]) |byte| if (byte != 0) return error.InvalidBuildMetadata;
    const value = try parse(std.json.Value, a, data[schema.note_prefix_bytes..end]);
    try objectFields(value, &.{ "schema", "role", "origin", "observed" });
    try literal(value.object.get("schema").?, "hyperv_persistence_fixture_parent_build_v1");
    try literal(value.object.get("role").?, "persistence_main_test_parent");
    try literal(value.object.get("origin").?, "actual_tests_zig_compile_builtin");
    const observed = value.object.get("observed").?;
    if (observed != .object) return error.InvalidBuildMetadata;
    if (sh.sh_type == std.elf.SHT_PROGBITS) {
        if (image.header.machine != .X86_64) return error.InvalidBuildMetadata;
        try literal(observed.object.get("zig_backend") orelse return error.InvalidBuildMetadata, "stage2_x86_64");
        try literal(observed.object.get("mode") orelse return error.InvalidBuildMetadata, "Debug");
    }
    var iterator = observed.object.iterator();
    while (iterator.next()) |entry| {
        if (!knownName(entry.key_ptr.*, &observed_names) and
            !std.mem.eql(u8, entry.key_ptr.*, "target") and !std.mem.eql(u8, entry.key_ptr.*, "not_exposed_by_builtin"))
            return error.InvalidBuildMetadata;
    }
    const unavailable = observed.object.get("not_exposed_by_builtin") orelse return error.InvalidBuildMetadata;
    if (unavailable != .array or unavailable.array.items.len > observed_names.len) return error.InvalidBuildMetadata;
    for (unavailable.array.items, 0..) |name, index| {
        if (name != .string or !knownName(name.string, &observed_names) or observed.object.contains(name.string))
            return error.InvalidBuildMetadata;
        for (unavailable.array.items[0..index]) |previous| if (std.mem.eql(u8, name.string, previous.string))
            return error.InvalidBuildMetadata;
    }
    if (observed.object.count() + unavailable.array.items.len != observed_names.len + 2)
        return error.InvalidBuildMetadata;
    const is_test = observed.object.get("is_test") orelse return error.InvalidBuildMetadata;
    if (is_test != .bool or !is_test.bool) return error.InvalidBuildMetadata;
    const target = observed.object.get("target") orelse return error.InvalidBuildMetadata;
    try validateTarget(target);
    const configured = try configuredMetadata(a, request.configured_json);
    try configuredModules(configured, request.modules);
    if (!jsonEqual(target, configured.object.get("resolved_target").?)) return error.ParentConfigurationMismatch;
    if (!jsonEqual(observed.object.get("mode") orelse return error.InvalidBuildMetadata, configured.object.get("root_module").?.object.get("optimize").?)) return error.ParentConfigurationMismatch;
    const architecture = target.object.get("cpu").?.object.get("arch").?;
    try literal(architecture, switch (image.header.machine) {
        .AARCH64 => "aarch64",
        .X86_64 => "x86_64",
        else => return error.InvalidBuildMetadata,
    });
    try literal(observed.object.get("object_format") orelse return error.InvalidBuildMetadata, "elf");
    try safeValue(value, 0);
    return value;
}

pub fn collect(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var custody = try Custody.open(io, root, false);
    defer custody.close(io);
    const before = try readBaseline(a, io, &custody);
    defer before.pin.close(a, io);
    const plan_pin = try FilePin.open(a, io, try std.fs.path.join(a, &.{ root, "plan.json" }), schema.max_plan_bytes);
    defer plan_pin.close(a, io);
    if (plan_pin.before.mode & 0o7777 != 0o600) return error.UnsafeFile;
    const plan = try parse(Plan, a, try plan_pin.read(a, io, schema.max_plan_bytes));
    if (!std.mem.eql(u8, plan.marker, marker)) return error.BaselineMismatch;
    try requireSha(plan.baseline_sha256, hashBytes(before.bytes));
    const request = plan.request;
    try validateRequest(request, true);
    try requireSameRequest(a, before.value.request, request);
    const collector = try FilePin.open(a, io, try std.fs.path.join(a, &.{ root, "collector" }), schema.max_parent_bytes);
    defer collector.close(a, io);
    try requireMetadata(before.value.collector.metadata, collector.before);
    try requireSha(before.value.collector_sha256, try collector.hash(a, io));
    var inputs = try Inputs.open(a, io, request);
    defer inputs.close(a, io);
    try inputs.require(before.value.inputs);
    const parent = try FilePin.open(a, io, request.parent, schema.max_parent_bytes);
    defer parent.close(a, io);
    const raw = try FilePin.open(a, io, request.raw_worker, schema.max_raw_worker_bytes);
    defer raw.close(a, io);
    const selected = try FilePin.open(a, io, request.selected_worker, schema.max_selected_worker_bytes);
    defer selected.close(a, io);
    try requireMetadata(plan.parent, parent.before);
    try requireMetadata(plan.raw_worker, raw.before);
    try requireMetadata(plan.selected_worker, selected.before);
    const total = try std.math.add(u64, parent.before.size, try std.math.add(u64, raw.before.size, selected.before.size));
    if (total > schema.max_collection_bytes - schema.max_metadata_bytes) return error.LimitExceeded;
    const proof = try FilePin.open(a, io, request.worker_proof, schema.max_metadata_bytes);
    defer proof.close(a, io);
    const log = try FilePin.open(a, io, request.fixture_log, schema.max_log_bytes);
    defer log.close(a, io);
    const exit = try FilePin.open(a, io, request.invocation_exit, 4);
    defer exit.close(a, io);
    const exit_bytes = try exit.read(a, io, 4);
    const exit_code = try parseExit(exit_bytes);
    const log_observation: Observation = .{ .size = log.before.size, .sha256 = try log.hash(a, io) };
    const proof_bytes = try proof.read(a, io, schema.max_metadata_bytes);
    if (custody.root.dir.statFile(io, "evidence", .{ .follow_symlinks = false })) |_| {
        return error.PathAlreadyExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    // Failed or unvalidated copies stay outside the fixed CI upload paths.
    try custody.root.dir.createDir(io, "pending", .fromMode(0o700));
    try syncDirectory(io, custody.root.dir);
    const evidence_path = try std.fs.path.join(a, &.{ root, "pending" });
    const evidence = try files.openPrivate(io, evidence_path);
    defer evidence.close(io);
    const evidence_identity = Identity.from(try dirMetadata(evidence.dir));
    var evidence_lock = try evidence.lock(io);
    defer evidence_lock.close(io);
    const parent_copy = try copyPinned(a, io, parent, evidence.dir, "parent-test", 0o600);
    const raw_copy = try copyPinned(a, io, raw, evidence.dir, "worker-raw", 0o600);
    const selected_copy = try copyPinned(a, io, selected, evidence.dir, "worker-selected", 0o600);
    const parent_bytes = try parent.read(a, io, schema.max_parent_bytes);
    try requireSha(parent_copy.sha256, hashBytes(parent_bytes));
    const metadata = try parentMetadata(a, parent_bytes, request);
    const raw_bytes = try raw.read(a, io, schema.max_raw_worker_bytes);
    try requireSha(raw_copy.sha256, hashBytes(raw_bytes));
    const selected_bytes = try selected.read(a, io, schema.max_selected_worker_bytes);
    try requireSha(selected_copy.sha256, hashBytes(selected_bytes));
    const worker_content = try verifyProof(a, proof_bytes, raw, raw_bytes, selected, selected_bytes);
    const input_files = try a.alloc(FileEvidence, inputs.files.items.len);
    for (inputs.files.items, input_files) |item, *record| record.* = .{
        .role = item.role,
        .size = item.pin.before.size,
        .sha256 = try item.pin.hash(a, io),
        .metadata_sha256 = fileMetadataDigest(item.pin.before),
    };
    const input_trees = try a.alloc(TreeEvidence, inputs.trees.items.len);
    for (inputs.trees.items, input_trees) |item, *record| {
        const tree = try observeHeldTree(a, io, item.directory, .{}, true);
        try requireSha(item.before.metadata_sha256, tree.metadata_sha256);
        record.* = .{ .role = item.role, .tree = tree };
    }
    try inputs.recheck(a, io);
    try before.pin.recheck(a, io);
    try plan_pin.recheck(a, io);
    try proof.recheck(a, io);
    try requireSha(log_observation.sha256, try log.hash(a, io));
    try exit.recheck(a, io);
    try collector.recheck(a, io);
    try custody.recheck(io);
    const report = .{
        .schema = "hyperv_persistence_fixture_build_evidence_v1",
        .authority = "diagnostic_not_admitted_non_authenticating",
        .diagnostic = true,
        .admitted = false,
        .authenticating = false,
        .source_commit = request.source_commit,
        .source_tree = request.source_tree,
        .configured = try configuredMetadata(a, request.configured_json),
        .parent = artifact("exact_main_parent", "parent-test", parent_copy),
        .parent_metadata = metadata,
        .raw_worker = artifact("raw_worker", "worker-raw", raw_copy),
        .selected_worker = artifact("selected_worker", "worker-selected", selected_copy),
        .worker_equivalence = worker_content,
        .worker_proof = Observation{ .size = proof_bytes.len, .sha256 = hashBytes(proof_bytes) },
        .fixture_log = log_observation,
        .invocation_exit = .{ .code = exit_code, .observation = Observation{ .size = exit_bytes.len, .sha256 = hashBytes(exit_bytes) } },
        .input_files = input_files,
        .input_trees = input_trees,
        .input_scope = "configured_module_and_source_envelopes_not_compiler_resolved_import_or_embed_closure",
        .binary_path_policy = "exact_approved_bytes_may_retain_ordinary_embedded_CI_paths_no_secret_free_scan_claim",
    };
    // Re-read all completed destinations before publishing the sole completeness marker.
    var destinations: std.ArrayList(FilePin) = .empty;
    defer {
        for (destinations.items) |pin| pin.close(a, io);
        destinations.deinit(a);
    }
    for ([_][]const u8{ "parent-test", "worker-raw", "worker-selected" }, [_]Observation{ parent_copy, raw_copy, selected_copy }) |name, observation| {
        const pin = try FilePin.open(a, io, try std.fs.path.join(a, &.{ evidence_path, name }), observation.size);
        errdefer pin.close(a, io);
        if (pin.before.mode & 0o7777 != 0o600 or pin.before.size != observation.size) return error.SourceChanged;
        try requireSha(observation.sha256, try pin.hash(a, io));
        try destinations.append(a, pin);
    }
    try requireSha(parent_copy.sha256, try parent.hash(a, io));
    try requireSha(raw_copy.sha256, try raw.hash(a, io));
    try requireSha(selected_copy.sha256, try selected.hash(a, io));
    const named_evidence = try files.openPrivate(io, evidence_path);
    defer named_evidence.close(io);
    if (!std.meta.eql(evidence_identity, Identity.from(try dirMetadata(named_evidence.dir)))) return error.SourceChanged;
    try inputs.recheck(a, io);
    try publish(a, io, &evidence_lock, "report.json", report, schema.max_metadata_bytes);
    for (destinations.items, [_]Observation{ parent_copy, raw_copy, selected_copy }) |pin, observation|
        try requireSha(observation.sha256, try pin.hash(a, io));
    try inputs.recheck(a, io);
    try parent.recheck(a, io);
    try raw.recheck(a, io);
    try selected.recheck(a, io);
    try before.pin.recheck(a, io);
    try plan_pin.recheck(a, io);
    try proof.recheck(a, io);
    try log.recheck(a, io);
    try exit.recheck(a, io);
    try collector.recheck(a, io);
    try custody.recheck(io);
    try custody.root.dir.renamePreserve("pending", custody.root.dir, "evidence", io);
    try syncDirectory(io, custody.root.dir);
    const published = try files.openPrivate(io, try std.fs.path.join(a, &.{ root, "evidence" }));
    defer published.close(io);
    if (!std.meta.eql(evidence_identity, Identity.from(try dirMetadata(published.dir)))) return error.SourceChanged;
    try custody.recheck(io);
}

pub const testing = if (@import("builtin").is_test) struct {
    pub const Pin = FilePin;
    pub const HeldInputs = struct {
        inner: Inputs,
        pub fn open(allocator: std.mem.Allocator, input_io: std.Io, request: schema.Request) !@This() {
            return .{ .inner = try Inputs.open(allocator, input_io, request) };
        }
        pub fn recheck(self: @This(), allocator: std.mem.Allocator, input_io: std.Io) !void {
            return self.inner.recheck(allocator, input_io);
        }
        pub fn close(self: *@This(), allocator: std.mem.Allocator, input_io: std.Io) void {
            self.inner.close(allocator, input_io);
        }
    };

    pub fn copy(a: std.mem.Allocator, io: std.Io, source: []const u8, target: std.Io.Dir, name: []const u8, limit: u64) !Observation {
        const pin = try FilePin.open(a, io, source, limit);
        defer pin.close(a, io);
        return copyPinned(a, io, pin, target, name, 0o600);
    }

    pub fn partialCopy(a: std.mem.Allocator, io: std.Io, source: []const u8, target: std.Io.Dir, name: []const u8) !void {
        const pin = try FilePin.open(a, io, source, schema.max_parent_bytes);
        defer pin.close(a, io);
        _ = try copyPinnedImpl(a, io, pin, target, name, 0o600, true);
    }

    pub fn proof(a: std.mem.Allocator, io: std.Io, bytes: []const u8, raw_path: []const u8, selected_path: []const u8) !void {
        const raw = try FilePin.open(a, io, raw_path, schema.max_raw_worker_bytes);
        defer raw.close(a, io);
        const selected = try FilePin.open(a, io, selected_path, schema.max_selected_worker_bytes);
        defer selected.close(a, io);
        const raw_bytes = try raw.read(a, io, schema.max_raw_worker_bytes);
        defer a.free(raw_bytes);
        const selected_bytes = try selected.read(a, io, schema.max_selected_worker_bytes);
        defer a.free(selected_bytes);
        _ = try verifyProof(a, bytes, raw, raw_bytes, selected, selected_bytes);
    }
} else struct {};
