// SPDX-License-Identifier: BSD-3-Clause
//! Canonical, bounded Azure CLI Python/module closure verification.
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const linux = std.os.linux;

pub const max_files: u32 = 16_384;
pub const max_directories: u32 = 4_096;
pub const max_bytes: u64 = 2 * 1024 * 1024 * 1024;
pub const max_depth: u8 = 32;
pub const max_file_bytes: u64 = 256 * 1024 * 1024;
pub const max_loader_files: u16 = 256;
pub const max_manifest_bytes: u64 = 32 * 1024 * 1024;

pub const Artifact = struct {
    path: []const u8,
    size: u64,
    sha256: []const u8,
};

pub const Limits = struct {
    files: u32,
    directories: u32,
    bytes: u64,
    depth: u8,
    file_bytes: u64,
    loader_files: u16,
};

pub const Observed = struct {
    files: u32,
    directories: u32,
    bytes: u64,
    depth: u8,
    loader_files: u16,
};

pub const Isolation = struct {
    python_home: enum { closure_root },
    module_layout: enum { flat_python_home_v1 },
    extensions: enum { closure_empty },
    dynamic_extension_install: enum { disabled },
    user_site: enum { disabled },
    site_import: enum { disabled },
    bytecode_writes: enum { disabled },
    path_environment: enum { forbidden },
    startup_hooks: enum { forbidden },
    loader_environment: enum { forbidden },
    package_restore: enum { forbidden_after_custody },
};

pub const Contract = struct {
    schema: []const u8,
    version: u8,
    canonicalization: []const u8,
    root: []const u8,
    python_version: []const u8,
    extensions: []const u8,
    launcher: Artifact,
    interpreter: Artifact,
    manifest: Artifact,
    limits: Limits,
    observed: Observed,
    content_sha256: []const u8,
    metadata_sha256: []const u8,
    parents_sha256: []const u8,
    loader_dependencies: []Artifact,
    isolation: Isolation,

    pub fn validate(self: Contract) !void {
        if (!std.mem.eql(u8, self.schema, "uk.wamr.azure-cli-runtime-closure") or
            self.version != 1 or
            !std.mem.eql(u8, self.canonicalization, "utf8-byte-sorted-keys-compact-lf-v1") or
            !pythonVersion(self.python_version))
            return error.InvalidAzureRuntime;
        try files.absoluteFilePath(self.root);
        try files.absoluteFilePath(self.extensions);
        try artifact(self.launcher);
        try artifact(self.interpreter);
        try artifact(self.manifest);
        if (!exactChild(self.root, self.launcher.path, "/bootstrap/azure-cli") or
            !exactChild(self.root, self.interpreter.path, "/bin/python") or
            !exactChild(self.root, self.extensions, "/extensions") or
            !exactManifest(self.root, self.manifest.path) or
            self.launcher.size > max_file_bytes or
            self.interpreter.size > max_file_bytes or
            self.manifest.size > max_manifest_bytes)
            return error.InvalidAzureRuntime;
        if (!std.meta.eql(self.limits, Limits{
            .files = max_files,
            .directories = max_directories,
            .bytes = max_bytes,
            .depth = max_depth,
            .file_bytes = max_file_bytes,
            .loader_files = max_loader_files,
        })) return error.InvalidAzureRuntime;
        if (self.observed.files == 0 or self.observed.files > self.limits.files or
            self.observed.directories == 0 or self.observed.directories > self.limits.directories or
            self.observed.bytes == 0 or self.observed.bytes > self.limits.bytes or
            self.observed.depth > self.limits.depth or
            self.observed.loader_files != self.loader_dependencies.len or
            self.observed.loader_files > self.limits.loader_files)
            return error.InvalidAzureRuntime;
        _ = try core.contracts.parseSha256(self.content_sha256);
        _ = try core.contracts.parseSha256(self.metadata_sha256);
        _ = try core.contracts.parseSha256(self.parents_sha256);
        var previous: ?[]const u8 = null;
        for (self.loader_dependencies) |dependency| {
            try artifact(dependency);
            if (dependency.size > self.limits.file_bytes or
                (previous != null and std.mem.order(u8, previous.?, dependency.path) != .lt))
                return error.InvalidAzureRuntime;
            previous = dependency.path;
        }
        if (self.isolation.python_home != .closure_root or
            self.isolation.module_layout != .flat_python_home_v1 or
            self.isolation.extensions != .closure_empty or
            self.isolation.dynamic_extension_install != .disabled or
            self.isolation.user_site != .disabled or
            self.isolation.site_import != .disabled or
            self.isolation.bytecode_writes != .disabled or
            self.isolation.path_environment != .forbidden or
            self.isolation.startup_hooks != .forbidden or
            self.isolation.loader_environment != .forbidden or
            self.isolation.package_restore != .forbidden_after_custody)
            return error.InvalidAzureRuntime;
    }
};

pub const Parsed = struct {
    bytes: core.sensitive.Buffer,
    value: std.json.Parsed(Contract),

    pub fn deinit(self: *Parsed) void {
        self.value.deinit();
        self.bytes.deinit();
        self.* = undefined;
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !Parsed {
    var bytes = try files.readSensitiveAbsolute(io, allocator, path, 64 * 1024, null);
    errdefer bytes.deinit();
    const document = try core.contracts.Document.parse(allocator, bytes.bytes(), .{
        .bytes = 64 * 1024,
        .items = 4096,
    });
    defer document.deinit();
    try document.requireCanonical(allocator, bytes.bytes());
    const parsed = try std.json.parseFromValue(
        Contract,
        allocator,
        document.value(),
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    );
    errdefer parsed.deinit();
    try parsed.value.validate();
    return .{ .bytes = bytes, .value = parsed };
}

pub fn equal(a: Contract, b: Contract) bool {
    if (!std.mem.eql(u8, a.schema, b.schema) or
        a.version != b.version or
        !std.mem.eql(u8, a.canonicalization, b.canonicalization) or
        !std.mem.eql(u8, a.root, b.root) or
        !std.mem.eql(u8, a.python_version, b.python_version) or
        !std.mem.eql(u8, a.extensions, b.extensions) or
        !sameArtifact(a.launcher, b.launcher) or
        !sameArtifact(a.interpreter, b.interpreter) or
        !sameArtifact(a.manifest, b.manifest) or
        !std.meta.eql(a.limits, b.limits) or
        !std.meta.eql(a.observed, b.observed) or
        !std.mem.eql(u8, a.content_sha256, b.content_sha256) or
        !std.mem.eql(u8, a.metadata_sha256, b.metadata_sha256) or
        !std.mem.eql(u8, a.parents_sha256, b.parents_sha256) or
        !std.meta.eql(a.isolation, b.isolation) or
        a.loader_dependencies.len != b.loader_dependencies.len)
        return false;
    for (a.loader_dependencies, b.loader_dependencies) |left, right|
        if (!sameArtifact(left, right)) return false;
    return true;
}

pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    contract: Contract,
) !void {
    try contract.validate();
    try inspectArtifact(io, contract.launcher, contract.limits.file_bytes);
    try inspectArtifact(io, contract.interpreter, contract.limits.file_bytes);

    var entries: std.ArrayList(Entry) = .empty;
    defer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit(allocator);
    }
    const root = try files.openDirectory(io, contract.root, .artifact);
    defer root.close(io);
    const root_snapshot = try files.snapshot(.{
        .handle = root.handle,
        .flags = .{ .nonblocking = false },
    });
    try validateDirectory(root_snapshot);
    try entries.append(allocator, .{
        .path = try allocator.dupe(u8, "."),
        .snapshot = root_snapshot,
        .sha256 = null,
    });
    var counts: Counts = .{ .directories = 1 };
    try walk(
        allocator,
        io,
        root,
        "",
        0,
        contract.limits,
        &entries,
        &counts,
    );
    std.mem.sort(Entry, entries.items, {}, Entry.lessThan);

    var content = core.Sha256.init(.{});
    var metadata = core.Sha256.init(.{});
    for (entries.items) |entry| {
        hashContent(&content, entry);
        hashMetadata(&metadata, "M", entry.path, entry.snapshot);
    }
    for (contract.loader_dependencies) |dependency| {
        const observed = try inspectArtifactIdentity(io, dependency, contract.limits.file_bytes);
        const digest = try core.contracts.parseSha256(dependency.sha256);
        hashExternalContent(&content, "L", dependency.path, observed.size, digest);
        hashMetadata(&metadata, "L", dependency.path, observed);
    }
    const manifest_observed = try inspectArtifactIdentity(
        io,
        contract.manifest,
        max_manifest_bytes,
    );
    hashExternalContent(
        &content,
        "A",
        contract.manifest.path,
        manifest_observed.size,
        try core.contracts.parseSha256(contract.manifest.sha256),
    );
    hashMetadata(&metadata, "A", contract.manifest.path, manifest_observed);
    const content_result = std.fmt.bytesToHex(content.finalResult(), .lower);
    const metadata_result = std.fmt.bytesToHex(metadata.finalResult(), .lower);
    if (!std.mem.eql(u8, &content_result, contract.content_sha256) or
        !std.mem.eql(u8, &metadata_result, contract.metadata_sha256) or
        counts.files != contract.observed.files or
        counts.directories != contract.observed.directories or
        counts.bytes != contract.observed.bytes or
        counts.depth != contract.observed.depth)
        return error.AzureRuntimeChanged;
    const parent_result = try parentDigest(allocator, io, contract);
    const parent_hex = std.fmt.bytesToHex(parent_result, .lower);
    if (!std.mem.eql(u8, &parent_hex, contract.parents_sha256))
        return error.AzureRuntimeChanged;
}

const Counts = struct {
    files: u32 = 0,
    directories: u32 = 0,
    bytes: u64 = 0,
    depth: u8 = 0,
};

const Entry = struct {
    path: []u8,
    snapshot: files.Snapshot,
    sha256: ?core.contracts.Sha256,

    fn lessThan(_: void, a: Entry, b: Entry) bool {
        return std.mem.order(u8, a.path, b.path) == .lt;
    }
};

fn walk(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    prefix: []const u8,
    depth: u8,
    limits: Limits,
    entries: *std.ArrayList(Entry),
    counts: *Counts,
) !void {
    const before = try files.snapshot(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    });
    try validateDirectory(before);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |item| {
        try files.basename(item.name);
        const relative = if (prefix.len == 0)
            try allocator.dupe(u8, item.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, item.name });
        errdefer allocator.free(relative);
        if (relative.len > 4095) return error.AzureRuntimeLimit;
        const path_file = try directory.openFile(io, item.name, .{
            .path_only = true,
            .follow_symlinks = false,
        });
        defer path_file.close(io);
        const snapshot = try files.snapshot(path_file);
        var digest: ?core.contracts.Sha256 = null;
        switch (snapshot.mode & linux.S.IFMT) {
            linux.S.IFDIR => {
                try validateDirectory(snapshot);
                if (counts.directories >= limits.directories or depth >= limits.depth)
                    return error.AzureRuntimeLimit;
                counts.directories += 1;
                counts.depth = @max(counts.depth, depth + 1);
                const child = try directory.openDir(io, item.name, .{
                    .follow_symlinks = false,
                    .iterate = true,
                });
                defer child.close(io);
                if (!files.sameSnapshot(snapshot, try files.snapshot(.{
                    .handle = child.handle,
                    .flags = .{ .nonblocking = false },
                }))) return error.AzureRuntimeChanged;
                try walk(
                    allocator,
                    io,
                    child,
                    relative,
                    depth + 1,
                    limits,
                    entries,
                    counts,
                );
            },
            linux.S.IFREG => {
                try validateFile(snapshot, limits.file_bytes);
                if (counts.files >= limits.files or
                    snapshot.size > limits.bytes -| counts.bytes)
                    return error.AzureRuntimeLimit;
                counts.files += 1;
                counts.bytes += snapshot.size;
                const file = try directory.openFile(io, item.name, .{
                    .follow_symlinks = false,
                });
                defer file.close(io);
                if (!files.sameSnapshot(snapshot, try files.snapshot(file)))
                    return error.AzureRuntimeChanged;
                digest = try hashFile(io, file, snapshot);
            },
            else => return error.UnsafeAzureRuntime,
        }
        if (!files.sameSnapshot(snapshot, try files.snapshot(path_file)))
            return error.AzureRuntimeChanged;
        try entries.append(allocator, .{
            .path = relative,
            .snapshot = snapshot,
            .sha256 = digest,
        });
    }
    if (!files.sameSnapshot(before, try files.snapshot(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    }))) return error.AzureRuntimeChanged;
}

fn hashFile(
    io: std.Io,
    file: std.Io.File,
    expected: files.Snapshot,
) !core.contracts.Sha256 {
    var hash = core.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < expected.size) {
        const amount: usize = @intCast(@min(@as(u64, buffer.len), expected.size - offset));
        if (try file.readPositionalAll(io, buffer[0..amount], offset) != amount)
            return error.AzureRuntimeChanged;
        hash.update(buffer[0..amount]);
        offset += amount;
    }
    if (try file.readPositionalAll(io, buffer[0..1], expected.size) != 0 or
        !files.sameSnapshot(expected, try files.snapshot(file)))
        return error.AzureRuntimeChanged;
    return hash.finalResult();
}

fn hashContent(hash: *core.Sha256, entry: Entry) void {
    var buffer: [8192]u8 = undefined;
    const kind: u8 = if (entry.sha256 == null) 'D' else 'F';
    const line = if (entry.sha256) |value| line: {
        const digest = std.fmt.bytesToHex(value, .lower);
        break :line std.fmt.bufPrint(
            &buffer,
            "C\t{c}\t{s}\t{d}\t{s}\n",
            .{ kind, entry.path, entry.snapshot.size, &digest },
        ) catch unreachable;
    } else std.fmt.bufPrint(
        &buffer,
        "C\t{c}\t{s}\t{d}\t-\n",
        .{ kind, entry.path, entry.snapshot.size },
    ) catch unreachable;
    hash.update(line);
}

fn hashExternalContent(
    hash: *core.Sha256,
    comptime kind: []const u8,
    path: []const u8,
    size: u64,
    digest: core.contracts.Sha256,
) void {
    var buffer: [8192]u8 = undefined;
    const encoded = std.fmt.bytesToHex(digest, .lower);
    const line = std.fmt.bufPrint(
        &buffer,
        "C\t" ++ kind ++ "\t{s}\t{d}\t{s}\n",
        .{ path, size, &encoded },
    ) catch unreachable;
    hash.update(line);
}

fn hashMetadata(
    hash: *core.Sha256,
    comptime tag: []const u8,
    path: []const u8,
    value: files.Snapshot,
) void {
    var buffer: [8192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        tag ++ "\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n",
        .{
            path,
            value.dev_major,
            value.dev_minor,
            value.ino,
            value.mode,
            value.uid,
            value.gid,
            value.nlink,
            value.size,
            value.mtime.sec,
            value.mtime.nsec,
            value.ctime.sec,
            value.ctime.nsec,
        },
    ) catch unreachable;
    hash.update(line);
}

fn parentDigest(
    allocator: std.mem.Allocator,
    io: std.Io,
    contract: Contract,
) !core.contracts.Sha256 {
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    try addParents(allocator, &paths, contract.root);
    for (contract.loader_dependencies) |dependency|
        try addParents(allocator, &paths, dependency.path);
    std.mem.sort([]u8, paths.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    var hash = core.Sha256.init(.{});
    var previous: ?[]const u8 = null;
    for (paths.items) |path| {
        if (previous != null and std.mem.eql(u8, previous.?, path)) continue;
        const directory = try files.openDirectory(io, path, .artifact);
        defer directory.close(io);
        const observed = try files.snapshot(.{
            .handle = directory.handle,
            .flags = .{ .nonblocking = false },
        });
        try validateDirectory(observed);
        hashParent(&hash, path, observed);
        previous = path;
    }
    return hash.finalResult();
}

fn hashParent(
    hash: *core.Sha256,
    path: []const u8,
    value: files.Snapshot,
) void {
    var buffer: [8192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "P\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n",
        .{
            path,
            value.dev_major,
            value.dev_minor,
            value.ino,
            value.mode,
            value.uid,
            value.gid,
        },
    ) catch unreachable;
    hash.update(line);
}

fn addParents(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]u8),
    input: []const u8,
) !void {
    const parent = std.fs.path.dirname(input) orelse return error.UnsafePath;
    try paths.append(allocator, try allocator.dupe(u8, "/"));
    if (parent.len == 1) return;
    var offset: usize = 1;
    var parts = std.mem.splitScalar(u8, parent[1..], '/');
    while (parts.next()) |part| {
        offset += part.len;
        try paths.append(allocator, try allocator.dupe(u8, parent[0..offset]));
        offset += 1;
    }
}

fn inspectArtifact(
    io: std.Io,
    item: Artifact,
    maximum: u64,
) !void {
    _ = try inspectArtifactIdentity(io, item, maximum);
}

fn inspectArtifactIdentity(
    io: std.Io,
    item: Artifact,
    maximum: u64,
) !files.Snapshot {
    try artifact(item);
    if (item.size > maximum) return error.AzureRuntimeLimit;
    var retained = try files.RetainedFile.open(io, item.path, .artifact);
    defer retained.close(io);
    const before = retained.file_snapshot;
    try validateFile(before, maximum);
    if (before.size != item.size) return error.AzureRuntimeChanged;
    const digest = try hashFile(io, retained.file, before);
    if (!std.crypto.timing_safe.eql(
        core.contracts.Sha256,
        digest,
        try core.contracts.parseSha256(item.sha256),
    )) return error.AzureRuntimeChanged;
    try retained.verify(io);
    return before;
}

fn validateDirectory(value: files.Snapshot) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFDIR or
        (value.uid != 0 and value.uid != linux.geteuid()) or
        value.mode & 0o022 != 0)
        return error.UnsafeAzureRuntime;
}

fn validateFile(value: files.Snapshot, maximum: u64) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFREG or
        (value.uid != 0 and value.uid != linux.geteuid()) or
        value.mode & 0o7022 != 0 or value.nlink != 1 or
        value.size == 0 or value.size > maximum)
        return error.UnsafeAzureRuntime;
}

fn artifact(item: Artifact) !void {
    try files.absoluteFilePath(item.path);
    if (item.size == 0) return error.InvalidAzureRuntime;
    _ = try core.contracts.parseSha256(item.sha256);
}

fn sameArtifact(a: Artifact, b: Artifact) bool {
    return std.mem.eql(u8, a.path, b.path) and
        a.size == b.size and
        std.mem.eql(u8, a.sha256, b.sha256);
}

fn exactChild(root: []const u8, path: []const u8, suffix: []const u8) bool {
    return path.len == root.len + suffix.len and
        std.mem.startsWith(u8, path, root) and
        std.mem.eql(u8, path[root.len..], suffix);
}

fn exactManifest(root: []const u8, path: []const u8) bool {
    const parent = std.fs.path.dirname(root) orelse return false;
    const name = "/azure-runtime.manifest";
    return path.len == parent.len + name.len and
        std.mem.startsWith(u8, path, parent) and
        std.mem.eql(u8, path[parent.len..], name);
}

fn pythonVersion(value: []const u8) bool {
    if (value.len < 3 or value.len > 16) return false;
    var parts = std.mem.splitScalar(u8, value, '.');
    var count: usize = 0;
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 3) return false;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return false;
        count += 1;
    }
    return count == 2;
}
