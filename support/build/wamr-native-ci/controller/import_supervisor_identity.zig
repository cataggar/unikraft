// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;
const accepted_run = @import("accepted_run.zig");
const adapter = @import("command_adapter.zig");
const physical = @import("custody_files.zig");
const inputs = @import("input_custody.zig");
const plan = @import("command_plan.zig");
const records = @import("records.zig");
const source = @import("source_custody.zig");

pub const historical_supervisor_sources = [_][]const u8{
    "support/build/wamr-native-ci/build.zig.zon",
    "support/build/wamr-native-ci/run.py",
    "support/build/wamr-native-ci/supervisor.build.zig",
    "support/build/wamr-native-ci/supervisor.zig",
    "support/tools/hyperv/contracts.zig",
    "support/tools/hyperv/core.zig",
    "support/tools/hyperv/diagnostics.zig",
    "support/tools/hyperv/private_files.zig",
    "support/tools/hyperv/process-command-v1.json",
    "support/tools/hyperv/process.zig",
    "support/tools/hyperv/sensitive.zig",
    "support/tools/hyperv/sha256.zig",
    "support/tools/hyperv/sha256_clear_upper.S",
};

pub fn supervisorSourceContentClosure(allocator: std.mem.Allocator, io: std.Io, repository: []const u8, git: []const u8) ![64]u8 {
    var hash = core.Sha256.init(.{});
    hash.update("uk.wamr.command-supervisor-source-v1-content\x00");
    for (historical_supervisor_sources) |name| {
        const manifest = try source.trackedManifest(allocator, io, repository, git, name);
        defer manifest.deinit(allocator);
        try physical.bind(allocator, &hash, .{ name, manifest.bytes, manifest.sha256 });
    }
    return physical.hex(&hash);
}

pub fn nativeSourceContentClosure(allocator: std.mem.Allocator) ![64]u8 {
    var hash = core.Sha256.init(.{});
    hash.update("uk.wamr.command-supervisor-source-v1-content\x00");
    for (source.closure) |entry| {
        const digest = std.fmt.bytesToHex(records.fileIdentity(entry.content), .lower);
        try physical.bind(allocator, &hash, .{ entry.name, entry.content.len, digest });
    }
    return physical.hex(&hash);
}

pub fn currentReaderSourceContentClosure(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    git: []const u8,
) ![64]u8 {
    var retained = try adapter.openPinnedTool(io, git, "tool:git");
    defer retained.close(io);
    try source.verifyPhysical(io, allocator, repository);
    const before = try source.portableSource(allocator, io, repository, git);
    const result = try nativeSourceContentClosure(allocator);
    try source.verifyPhysical(io, allocator, repository);
    const after = try source.portableSource(allocator, io, repository, git);
    if (!before.same(after)) return error.SourceChanged;
    try retained.verify(io);
    return result;
}

pub fn identityBytes(allocator: std.mem.Allocator, source_sha256: []const u8) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(allocator, .{
        .protocol = "uk.wamr.command-supervisor/1 process-command/1",
        .schema = "uk.wamr.command-supervisor-identity",
        .source_content_closure_sha256 = source_sha256,
        .version = 1,
    }, .{});
    defer allocator.free(raw);
    return records.canonicalAlloc(allocator, raw);
}

fn get(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidImportIdentity;
    return value.object.get(key) orelse error.InvalidImportIdentity;
}

fn text(value: std.json.Value) ![]const u8 {
    return contracts.string(value);
}

fn same(a: []const u8, b: []const u8) !void {
    if (!std.mem.eql(u8, a, b)) return error.ImportIdentityChanged;
}

fn number(value: std.json.Value) !u64 {
    return contracts.integer(u64, value);
}

fn notCancelled(signal: ?*core.process.SignalCancellation) !void {
    if (signal) |active|
        if (active.flag().load(.acquire)) return error.Cancelled;
}

fn contained(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or
        (path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/');
}

pub fn validateSourceNames(records_map: std.json.Value) !void {
    if (records_map != .object) return error.InvalidImportIdentity;
    if (records_map.object.count() == historical_supervisor_sources.len) {
        for (historical_supervisor_sources) |name|
            _ = try get(records_map, name);
    } else if (records_map.object.count() == source.closure.len) {
        for (source.closure) |entry|
            _ = try get(records_map, entry.name);
    } else if (records_map.object.count() == source.previous_export_closure.len) {
        for (source.previous_export_closure) |entry|
            if (!records_map.object.contains(entry.name)) return error.UnsupportedSupervisorSource;
    } else if (records_map.object.count() == source.previous_private_closure.len) {
        for (source.previous_private_closure) |entry|
            _ = try get(records_map, entry.name);
    } else if (records_map.object.count() == source.previous_native_closure.len) {
        for (source.previous_native_closure) |entry|
            _ = try get(records_map, entry.name);
    } else if (records_map.object.count() == source.previous_closure.len) {
        for (source.previous_closure) |entry|
            _ = try get(records_map, entry.name);
    } else return error.UnsupportedSupervisorSource;
}

pub fn verifyGitIdentity(
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: accepted_run.SourceIdentity,
    repository: []const u8,
    git: []const u8,
    signal: ?*core.process.SignalCancellation,
) !void {
    const a = allocator;
    for ([_][]const u8{ identity.revision, identity.tree }) |digest| {
        if (digest.len != 40) return error.InvalidImportIdentity;
        for (digest) |byte|
            if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
                return error.InvalidImportIdentity;
    }
    const revision_ref = try std.mem.concat(a, u8, &.{ identity.revision, "^{commit}" });
    defer a.free(revision_ref);
    const tree_ref = try std.mem.concat(a, u8, &.{ identity.revision, "^{tree}" });
    defer a.free(tree_ref);
    try notCancelled(signal);
    const commit = try source.gitOutput(a, io, repository, git, &.{ "rev-parse", "--verify", revision_ref }, 65, null);
    defer a.free(commit);
    const expected_commit = try std.fmt.allocPrint(a, "{s}\n", .{identity.revision});
    defer a.free(expected_commit);
    try same(commit, expected_commit);
    try notCancelled(signal);
    const tree = try source.gitOutput(a, io, repository, git, &.{ "rev-parse", tree_ref }, 65, null);
    defer a.free(tree);
    const expected_tree = try std.fmt.allocPrint(a, "{s}\n", .{identity.tree});
    defer a.free(expected_tree);
    try same(tree, expected_tree);
}

pub fn verifyGitSource(
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: accepted_run.SourceIdentity,
    repository: []const u8,
    git: []const u8,
    source_map: std.json.Value,
    signal: ?*core.process.SignalCancellation,
) ![]const u8 {
    const a = allocator;
    const records_map = try get(source_map, "records");
    try validateSourceNames(records_map);
    try verifyGitIdentity(a, io, identity, repository, git, signal);
    for (records_map.object.keys(), records_map.object.values()) |name, value| {
        try notCancelled(signal);
        try @import("custody_limits.zig").relative(name, 256, 8);
        const size = try number(try get(value, "bytes"));
        if (size == 0 or size > 8 * 1024 * 1024) return error.InvalidImportIdentity;
        const digest = try text(try get(value, "sha256"));
        const listing = try source.gitOutput(a, io, repository, git, &.{
            "ls-tree", "-z", identity.tree, "--", name,
        }, 512, null);
        defer a.free(listing);
        if (listing.len == 0 or listing[listing.len - 1] != 0 or
            std.mem.indexOfScalar(u8, listing[0 .. listing.len - 1], 0) != null)
            return error.ImportSourceChanged;
        const separator = std.mem.indexOfScalar(u8, listing, '\t') orelse return error.ImportSourceChanged;
        try same(listing[separator + 1 .. listing.len - 1], name);
        const header = listing[0..separator];
        if (!std.mem.startsWith(u8, header, "100644 blob ") or header.len != "100644 blob ".len + 40)
            return error.ImportSourceChanged;
        const oid = header["100644 blob ".len..];
        for (oid) |char|
            if (!std.ascii.isDigit(char) and !(char >= 'a' and char <= 'f'))
                return error.ImportSourceChanged;
        try notCancelled(signal);
        const size_raw = try source.gitOutput(a, io, repository, git, &.{ "cat-file", "-s", oid }, 32, null);
        defer a.free(size_raw);
        if (size_raw.len < 2 or size_raw[size_raw.len - 1] != '\n' or
            try std.fmt.parseInt(u64, size_raw[0 .. size_raw.len - 1], 10) != size)
            return error.ImportSourceChanged;
        try notCancelled(signal);
        const blob = try source.gitOutput(a, io, repository, git, &.{ "cat-file", "blob", oid }, @intCast(size), null);
        defer a.free(blob);
        const hash = std.fmt.bytesToHex(records.fileIdentity(blob), .lower);
        if (blob.len != size) return error.ImportSourceChanged;
        try same(&hash, digest);
    }
    return text(try get(source_map, "content_closure_sha256"));
}

const Library = struct { bytes: u64, sha256: [64]u8 };
pub const PinnedRuntime = struct {
    supervisor: files.RetainedFile,
    loaders: []files.RetainedFile,

    pub fn verify(self: *PinnedRuntime, io: std.Io) !void {
        try self.supervisor.verify(io);
        for (self.loaders) |*loader| try loader.verify(io);
    }

    pub fn deinit(self: *PinnedRuntime, allocator: std.mem.Allocator, io: std.Io) void {
        self.supervisor.close(io);
        for (self.loaders) |*loader| loader.close(io);
        allocator.free(self.loaders);
    }
};

fn libraryLess(_: void, first: Library, second: Library) bool {
    if (first.bytes != second.bytes) return first.bytes < second.bytes;
    return std.mem.lessThan(u8, &first.sha256, &second.sha256);
}

pub fn verifyRuntime(
    allocator: std.mem.Allocator,
    io: std.Io,
    supervisor_path: []const u8,
    start: std.json.Value,
    signal: ?*core.process.SignalCancellation,
) !PinnedRuntime {
    const expected = try get(try get(try get(start, "command_supervisor"), "runtime_map"), "records");
    const executable_record = try get(expected, "executable");
    const imported = try get(try get(try get(start, "consumer_inputs"), "files"), "command-supervisor");
    const observed = try physical.readFile(io, supervisor_path, 16 * 1024 * 1024, false);
    const size = try number(try get(executable_record, "bytes"));
    const imported_metadata = try get(imported, "metadata");
    if (imported_metadata != .array or imported_metadata.array.items.len != 9 or
        observed.bytes != size or try number(imported_metadata.array.items[6]) != size)
        return error.ImportSupervisorChanged;
    try same(&observed.sha256, try text(try get(executable_record, "sha256")));
    try same(&observed.sha256, try text(try get(imported, "sha256")));
    var retained = try files.RetainedFile.open(io, supervisor_path, .tool);
    errdefer retained.close(io);
    if (!std.meta.eql(observed.metadata, physical.metadata(retained.file_snapshot)))
        return error.ImportSupervisorChanged;
    var header: [20]u8 = undefined;
    if (try retained.file.readPositionalAll(io, &header, 0) != header.len or
        !std.mem.eql(u8, header[0..4], "\x7fELF") or header[4] != 2 or header[5] != 1 or
        (header[16] != 2 and header[16] != 3) or header[17] != 0 or
        (header[18] != 62 and header[18] != 183) or header[19] != 0)
        return error.InvalidSupervisor;

    try notCancelled(signal);
    const paths = try inputs.executableRuntimePaths(allocator, io, supervisor_path);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    if (paths.len + 1 != expected.object.count()) return error.ImportSupervisorChanged;
    var trusted: std.ArrayList(Library) = .empty;
    defer trusted.deinit(allocator);
    for (expected.object.keys(), expected.object.values()) |name, record| {
        if (std.mem.eql(u8, name, "executable")) continue;
        const digest = try contracts.parseSha256(try text(try get(record, "sha256")));
        try trusted.append(allocator, .{
            .bytes = try number(try get(record, "bytes")),
            .sha256 = std.fmt.bytesToHex(digest, .lower),
        });
    }
    var actual: std.ArrayList(Library) = .empty;
    defer actual.deinit(allocator);
    var pinned_loaders: std.ArrayList(files.RetainedFile) = .empty;
    errdefer {
        for (pinned_loaders.items) |*loader| loader.close(io);
        pinned_loaders.deinit(allocator);
    }
    for (paths) |path| {
        var pinned = try files.RetainedFile.open(io, path, .artifact);
        errdefer pinned.close(io);
        const item = try physical.readFile(io, path, 16 * 1024 * 1024, false);
        if (!std.meta.eql(item.metadata, physical.metadata(pinned.file_snapshot)))
            return error.ImportSupervisorChanged;
        try pinned_loaders.append(allocator, pinned);
        try actual.append(allocator, .{ .bytes = item.bytes, .sha256 = item.sha256 });
    }
    std.mem.sort(Library, trusted.items, {}, libraryLess);
    std.mem.sort(Library, actual.items, {}, libraryLess);
    for (trusted.items, actual.items) |first, second|
        if (first.bytes != second.bytes or !std.meta.eql(first.sha256, second.sha256))
            return error.ImportSupervisorChanged;
    try retained.verify(io);
    return .{ .supervisor = retained, .loaders = try pinned_loaders.toOwnedSlice(allocator) };
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
    repository: []const u8,
    git: []const u8,
    supervisor_path: []const u8,
    output: []const u8,
    signal: ?*core.process.SignalCancellation,
) !void {
    if (accepted.context != .trusted_inner_zip or
        accepted.compatibility != .tiny_v2_qcow2_derived_vhd)
        return error.InvalidContext;
    try files.absoluteFilePath(output);
    try files.absoluteFilePath(supervisor_path);
    try files.absoluteFilePath(git);
    if (contained(output, accepted.root) or contained(output, repository) or
        contained(accepted.root, output) or contained(repository, output))
        return error.AliasedOutput;
    try notCancelled(signal);
    var git_file = try adapter.openPinnedTool(io, git, "tool:git");
    defer git_file.close(io);
    try accepted.revalidateWithSignal(signal);
    var pinned_start = try accepted.pinArtifact(.build_start);
    defer pinned_start.close(io);
    var raw = try files.readSensitiveFile(io, allocator, pinned_start.file, records.max_record_bytes, .private);
    defer raw.deinit();
    var document = try contracts.Document.parse(allocator, raw.bytes(), .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(allocator, raw.bytes());
    const start = document.value();
    const source_map = try get(try get(start, "command_supervisor"), "source_map");
    const source_sha256 = try verifyGitSource(allocator, io, accepted.source, repository, git, source_map, signal);
    var supervisor = try verifyRuntime(allocator, io, supervisor_path, start, signal);
    defer supervisor.deinit(allocator, io);
    try git_file.verify(io);
    try accepted.revalidateWithSignal(signal);
    try notCancelled(signal);

    const parent_path = std.fs.path.dirname(output) orelse return error.UnsafePath;
    const name = std.fs.path.basename(output);
    try files.basename(name);
    const parent = try files.openDirectory(io, parent_path, .private);
    defer parent.close(io);
    try parent.createDir(io, name, .fromMode(0o700));
    const work = try files.openDirectory(io, output, .private);
    defer work.close(io);
    try work.createDir(io, "private", .fromMode(0o700));
    try work.createDir(io, "evidence", .fromMode(0o700));
    const private = try work.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);

    const roots = plan.Roots{
        .source_root = repository,
        .work = output,
        .runtime = accepted.root,
        .zig = "",
        .producer = "",
        .supervisor = supervisor_path,
        .package_tool = "",
        .validator = "",
        .tools = @splat(""),
    };
    const outcome = try adapter.execute(allocator, io, .{
        .roots = roots,
        .stage = .@"supervisor-import-identity",
        .private_dir = private,
        .evidence_dir = evidence,
        .cancel = if (signal) |active| active.flag() else null,
        .capture_stdout = true,
    });
    defer allocator.free(outcome.stdout);
    if (outcome.poisoned) return error.CleanupPoisoned;
    if (!outcome.accepted or outcome.stderr_bytes != 0) return error.StageRefused;
    const expected = try identityBytes(allocator, source_sha256);
    if (!std.mem.eql(u8, expected, outcome.stdout)) return error.ImportIdentityChanged;

    const record_path = try std.fs.path.join(allocator, &.{ output, "evidence/command-supervisor-import-identity.json" });
    const record = try physical.readFile(io, record_path, records.max_record_bytes, true);
    var pinned_record = try files.RetainedFile.open(io, record_path, .private);
    defer pinned_record.close(io);
    var record_raw = try files.readSensitiveFile(io, allocator, pinned_record.file, records.max_record_bytes, .private);
    defer record_raw.deinit();
    const observed_sha = std.fmt.bytesToHex(records.fileIdentity(record_raw.bytes()), .lower);
    if (record.bytes != record_raw.bytes().len or
        !std.meta.eql(record.metadata, physical.metadata(pinned_record.file_snapshot)) or
        !std.mem.eql(u8, &record.sha256, &observed_sha))
        return error.CommandOutputChanged;
    const checked = try accepted_run.validateCommandBinding(
        allocator,
        record_raw.bytes(),
        .@"supervisor-import-identity",
        .trusted_inner_zip,
    );
    const log_path = try std.fs.path.join(allocator, &.{ output, "private/supervisor-import-identity.log" });
    const log = try physical.readFile(io, log_path, 1025, true);
    if (checked.output_bytes != outcome.stdout.len or checked.output_bytes != log.bytes or
        !std.mem.eql(u8, &checked.output_sha256, &log.sha256))
        return error.CommandOutputChanged;
    try accepted.revalidateWithSignal(signal);
    try pinned_start.verify(io);
    try pinned_record.verify(io);
    try supervisor.verify(io);
    try git_file.verify(io);
}
