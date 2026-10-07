// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const controller = @import("wamr_controller");
const accepted_run = controller.accepted_run;
const contracts = controller.handoff_contracts;
const c = core.contracts;
const layout = contracts.layout;
const profile = contracts.profile;
const copy = @import("retained_copy.zig");
const zip = @import("zip.zig");

pub const Context = struct {
    repository: []const u8 = profile.repository,
    run_id: []const u8,
    run_attempt: []const u8,
    source_revision: []const u8,
    source_tree: []const u8,
    wamr_revision: []const u8 = profile.wamr_revision,

    pub fn validate(self: Context) !void {
        if (!std.mem.eql(u8, self.repository, profile.repository) or
            !std.mem.eql(u8, self.wamr_revision, profile.wamr_revision))
            return error.InvalidContext;
        inline for (.{ self.run_id, self.run_attempt }) |identifier| {
            if (identifier.len == 0 or identifier.len > 20 or identifier[0] < '1' or identifier[0] > '9')
                return error.InvalidRunIdentity;
            for (identifier) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidRunIdentity;
        }
        inline for (.{ self.source_revision, self.source_tree }) |identity| {
            if (identity.len != 40) return error.InvalidSourceIdentity;
            for (identity) |digit| if (!std.ascii.isDigit(digit) and (digit < 'a' or digit > 'f'))
                return error.InvalidSourceIdentity;
        }
    }

    pub fn fromCI(environ: std.process.Environ, repository_path: []const u8, source: accepted_run.SourceIdentity) !Context {
        try files.absoluteFilePath(repository_path);
        const fixed = .{
            .{ "GITHUB_ACTIONS", "true" },
            .{ "GITHUB_REPOSITORY", profile.repository },
            .{ "GITHUB_JOB", "wamr-native-compute" },
            .{ "GITHUB_EVENT_NAME", "pull_request" },
            .{ "GITHUB_REPOSITORY_VISIBILITY", "public" },
            .{ "GITHUB_WORKSPACE", repository_path },
            .{ "GITHUB_SHA", source.revision },
        };
        inline for (fixed) |pair|
            try equal(std.process.Environ.getPosix(environ, pair[0]) orelse return error.MissingCiContext, pair[1]);
        const workflow = std.process.Environ.getPosix(environ, "GITHUB_WORKFLOW_REF") orelse return error.MissingCiContext;
        if (!std.mem.startsWith(u8, workflow, "cataggar/unikraft/.github/workflows/wamr-native-compute.yaml@") or
            workflow.len == "cataggar/unikraft/.github/workflows/wamr-native-compute.yaml@".len)
            return error.InvalidCiContext;
        const result: Context = .{
            .run_id = std.process.Environ.getPosix(environ, "GITHUB_RUN_ID") orelse return error.MissingCiContext,
            .run_attempt = std.process.Environ.getPosix(environ, "GITHUB_RUN_ATTEMPT") orelse return error.MissingCiContext,
            .source_revision = source.revision,
            .source_tree = source.tree,
        };
        try result.validate();
        return result;
    }
};

pub const Member = struct {
    name: []const u8,
    size: u64,
    sha256: [32]u8,
    limit: u64,
};

pub const Metadata = struct {
    arena: std.heap.ArenaAllocator,
    compatibility: profile.Compatibility,
    selected: []const Member,
    bundle: []const u8,
    manifest: []const u8,

    pub fn deinit(self: *Metadata) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn fromRootBound(allocator: std.mem.Allocator, raw: []const u8, root: []const u8, context: Context) !Metadata {
        try files.absoluteFilePath(root);
        return prepare(allocator, raw, root, context);
    }

    pub fn fromPortable(allocator: std.mem.Allocator, raw: []const u8, context: Context) !Metadata {
        return prepare(allocator, raw, null, context);
    }

    pub fn rootBoundBundle(self: *const Metadata, allocator: std.mem.Allocator, root: []const u8) ![]const u8 {
        try files.absoluteFilePath(root);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var document = try contracts.parseCanonical(a, self.bundle);
        defer document.deinit();
        const value = document.value();
        for ([_][]const u8{ "artifacts", "evidence" }) |key|
            for ((try field(value, key)).array.items) |item|
                try rebaseMember(a, item, root);
        for ((try field(value, "boots")).array.items) |boot|
            for (layout.boot_keys) |part|
                try rebaseMember(a, try field(boot, @tagName(part)), root);
        if (try contracts.validateLocalImageHandoffWithRoot(value, root) != self.compatibility)
            return error.ProfileMismatch;
        return canonical(allocator, value);
    }

    fn prepare(allocator: std.mem.Allocator, raw: []const u8, root: ?[]const u8, context: Context) !Metadata {
        try context.validate();
        try scan(raw);
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var document = try contracts.parseCanonical(a, raw);
        defer document.deinit();
        const value = document.value();
        const compatibility = try contracts.validateLocalImageHandoffWithRoot(value, root);
        try bindBundle(value, compatibility, context);
        const selected = try a.alloc(Member, layout.selectedMemberCount(compatibility));
        var cursor: usize = 0;
        for ((try field(value, "artifacts")).array.items, layout.artifactNames(compatibility)) |item, name| {
            try addMember(a, selected, &cursor, item, try std.fmt.allocPrint(a, "artifacts/{s}", .{name}));
        }
        for ((try field(value, "boots")).array.items, profile.modes(compatibility)) |boot, mode| {
            for (layout.boot_keys) |part|
                try addMember(a, selected, &cursor, try field(boot, @tagName(part)), try std.fmt.allocPrint(a, "boots/{s}/{s}", .{ @tagName(mode), @tagName(part) }));
        }
        for ((try field(value, "evidence")).array.items, layout.evidenceNames(compatibility)) |item, name|
            try addMember(a, selected, &cursor, item, try std.fmt.allocPrint(a, "evidence/{s}", .{name}));
        std.mem.sort(Member, selected, {}, struct {
            fn less(_: void, left: Member, right: Member) bool {
                return std.mem.order(u8, left.name, right.name) == .lt;
            }
        }.less);
        var members: std.json.ObjectMap = .empty;
        for (selected) |member| {
            var item: std.json.ObjectMap = .empty;
            try item.put(a, "size", .{ .integer = @intCast(member.size) });
            try item.put(a, "sha256", .{ .string = try a.dupe(u8, &std.fmt.bytesToHex(member.sha256, .lower)) });
            try members.put(a, member.name, .{ .object = item });
        }
        const manifest = if (compatibility == .frozen_tiny_v1)
            try canonical(a, .{
                .schema = "uk.wamr.public-source-bundle",
                .version = @as(u8, 1),
                .authority = profile.authority,
                .source = context,
                .members = std.json.Value{ .object = members },
            })
        else
            try canonical(a, .{
                .schema = "uk.wamr.public-source-bundle",
                .version = @as(u8, 2),
                .profile = profile.current_profile,
                .authority = profile.authority,
                .source = context,
                .members = std.json.Value{ .object = members },
            });
        const bundle = try canonical(a, value);
        if (bundle.len > layout.max_json_bytes or manifest.len > layout.max_json_bytes) return error.TooLarge;
        return .{ .arena = arena, .compatibility = compatibility, .selected = selected, .bundle = bundle, .manifest = manifest };
    }
};

fn rebaseMember(a: std.mem.Allocator, item: std.json.Value, root: []const u8) !void {
    const path = try c.string(try field(item, "path"));
    item.object.getPtr("path").?.* = .{ .string = try std.fs.path.join(a, &.{ root, path }) };
}

fn addMember(a: std.mem.Allocator, members: []Member, cursor: *usize, item: std.json.Value, name: []const u8) !void {
    members[cursor.*] = .{
        .name = name,
        .size = try c.integer(u64, try field(item, "size")),
        .sha256 = try c.parseSha256(try c.string(try field(item, "sha256"))),
        .limit = try layout.memberLimit(name),
    };
    cursor.* += 1;
    // The closed positional schema above authenticated the original root-bound
    // path; only now replace it with its fixed portable publication name.
    item.object.getPtr("path").?.* = .{ .string = try a.dupe(u8, name) };
}

pub fn verifyBytes(allocator: std.mem.Allocator, bytes: []const u8, context: Context, expected_digest: ?[32]u8) !Metadata {
    try context.validate();
    if (bytes.len > layout.max_total_bytes) return error.TooLarge;
    if (expected_digest) |digest| {
        if (!std.mem.eql(u8, &zip.sha256(bytes), &digest)) return error.DigestMismatch;
    } else if (!profile.omitsExternalArchiveDigest(.{ .revision = context.source_revision, .tree = context.source_tree })) {
        return error.MissingArchiveDigest;
    }
    var views_storage: [layout.max_members]zip.MemberView = undefined;
    const views = try zip.indexArchive(bytes, &views_storage);
    if (views.len < 3) return error.UnexpectedMemberCount;
    const bundle = views[views.len - 2];
    const manifest = views[views.len - 1];
    try equal(bundle.name, "bundle.json");
    try equal(manifest.name, "public-source.json");
    if (bundle.bytes.len > layout.max_json_bytes or manifest.bytes.len > layout.max_json_bytes) return error.TooLarge;
    var metadata = try Metadata.fromPortable(allocator, bundle.bytes, context);
    errdefer metadata.deinit();
    if (views.len != layout.expectedZipMemberCount(metadata.compatibility)) return error.UnexpectedMemberCount;
    try scan(manifest.bytes);
    var manifest_document = try contracts.parseCanonical(allocator, manifest.bytes);
    defer manifest_document.deinit();
    if (try contracts.validatePublicSourceManifest(manifest_document.value()) != metadata.compatibility)
        return error.ProfileMismatch;
    try equal(manifest.bytes, metadata.manifest);
    var expected_storage: [layout.max_members]zip.ExpectedMember = undefined;
    for (metadata.selected, 0..) |member, i| {
        expected_storage[i] = .{ .name = member.name, .size = member.size, .sha256 = member.sha256, .limit = member.limit };
        try scan(views[i].bytes);
    }
    expected_storage[metadata.selected.len] = expectedSlice("bundle.json", metadata.bundle);
    expected_storage[metadata.selected.len + 1] = expectedSlice("public-source.json", metadata.manifest);
    try zip.verifyArchive(bytes, .{
        .members = expected_storage[0..views.len],
        .archive_sha256 = expected_digest orelse zip.sha256(bytes),
    });
    if (expected_digest == null) {
        if (metadata.compatibility != .frozen_tiny_v1) return error.MissingArchiveDigest;
        for (views) |view| {
            if (!std.mem.eql(u8, view.name, "evidence/build-start.json")) continue;
            var start = try contracts.parseCanonical(allocator, view.bytes);
            defer start.deinit();
            if (start.value() != .object or start.value().object.contains("dependencies")) return error.MissingArchiveDigest;
        }
    }
    return metadata;
}

pub const Archive = struct {
    allocator: std.mem.Allocator,
    retained: files.RetainedFile,
    image: core.sensitive.Buffer,
    metadata: Metadata,
    digest: [32]u8,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8, context: Context, expected_digest: ?[32]u8, cancel: ?*const std.atomic.Value(bool)) !Archive {
        try context.validate();
        try copy.checkCancellation(cancel);
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        var retained = try files.RetainedFile.open(io, owned_path, .artifact);
        errdefer retained.close(io);
        try copy.verifyRetained(io, &retained);
        var image = try readImage(allocator, io, &retained, cancel);
        errdefer image.deinit();
        try copy.checkCancellation(cancel);
        var metadata = try verifyBytes(allocator, image.bytes(), context, expected_digest);
        errdefer metadata.deinit();
        const digest = zip.sha256(image.bytes());
        try copy.verifyRetained(io, &retained);
        const actual = try copy.hashRetained(io, &retained, layout.max_total_bytes, cancel);
        try equal(&actual, &std.fmt.bytesToHex(digest, .lower));
        return .{ .allocator = allocator, .retained = retained, .image = image, .metadata = metadata, .digest = digest };
    }

    pub fn deinit(self: *Archive, io: std.Io) void {
        const path = self.retained.path;
        self.metadata.deinit();
        self.image.deinit();
        self.retained.close(io);
        self.allocator.free(path);
        self.* = undefined;
    }

    pub fn revalidate(self: *const Archive, io: std.Io, cancel: ?*const std.atomic.Value(bool)) !void {
        const actual = try copy.hashRetained(io, &self.retained, layout.max_total_bytes, cancel);
        try equal(&actual, &std.fmt.bytesToHex(self.digest, .lower));
    }

    // This creates a portable imported-stage owner, not a root-bound private
    // handoff. The existing controller performs the acceptance/lineage checks.
    pub fn materialize(self: *Archive, io: std.Io, output_path: []const u8, cancel: ?*const std.atomic.Value(bool)) !Imported {
        try self.revalidate(io, cancel);
        if (!std.mem.eql(u8, &zip.sha256(self.image.bytes()), &self.digest)) return error.DigestMismatch;
        const directory = try reserve(io, output_path, null);
        errdefer directory.close(io);
        var views_storage: [layout.max_members]zip.MemberView = undefined;
        const views = try zip.indexArchive(self.image.bytes(), &views_storage);
        for (views) |view| {
            try copy.checkCancellation(cancel);
            const name = if (std.mem.eql(u8, view.name, "bundle.json")) "portable-bundle.json" else view.name;
            try writeMember(io, directory.dir, name, view.bytes);
        }
        try syncDir(io, directory.dir);
        try self.revalidate(io, cancel);
        var accepted = try accepted_run.openImportedStage(self.allocator, io, &directory, output_path);
        errdefer accepted.deinit();
        const path = try self.allocator.dupe(u8, output_path);
        return .{ .archive = self, .directory = directory, .accepted = accepted, .path = path };
    }
};

pub const Imported = struct {
    archive: *Archive,
    directory: files.Directory,
    accepted: accepted_run.AcceptedRun,
    path: []const u8,

    pub fn revalidate(self: *Imported, io: std.Io, signal: ?*core.process.SignalCancellation) !void {
        try self.archive.revalidate(io, if (signal) |active| active.flag() else null);
        try self.accepted.revalidateWithSignal(signal);
        try self.archive.revalidate(io, if (signal) |active| active.flag() else null);
    }
    pub fn deinit(self: *Imported, io: std.Io) void {
        self.accepted.deinit();
        self.directory.close(io);
        self.archive.allocator.free(self.path);
        self.* = undefined;
    }
};

pub const Source = union(enum) {
    private_bundle: *accepted_run.PrivateBundle,
    local_handoff: struct {
        accepted: *accepted_run.AcceptedRun,
        manifest: *files.RetainedFile,
        root: []const u8,
    },

    fn accepted(self: Source) *accepted_run.AcceptedRun {
        return switch (self) {
            .private_bundle => |owner| &owner.evidence,
            .local_handoff => |owner| owner.accepted,
        };
    }
    fn root(self: Source) []const u8 {
        return switch (self) {
            .private_bundle => |owner| owner.evidence.root,
            .local_handoff => |owner| owner.root,
        };
    }
    fn manifest(self: Source) *files.RetainedFile {
        return switch (self) {
            .private_bundle => |owner| &owner.manifest,
            .local_handoff => |owner| owner.manifest,
        };
    }
    fn revalidate(self: Source, signal: ?*core.process.SignalCancellation) !void {
        switch (self) {
            .private_bundle => |owner| try owner.revalidate(signal),
            .local_handoff => |owner| {
                if (owner.accepted.context != .local_runtime) return error.InvalidContext;
                try owner.accepted.revalidateWithSignal(signal);
                try copy.verifyRetained(owner.accepted.io, owner.manifest);
            },
        }
    }
};

pub const Phase = enum { inputs, reserved, writing, file_sync, reopen, revalidated, publication, parent_sync };
pub const Diagnostic = struct {
    phase: Phase,
    err: anyerror,
    publication: files.CommitStatus,
};
pub const Published = struct { sha256: [32]u8, bytes: u64, members: usize };
pub const Outcome = union(enum) { success: Published, refused: Diagnostic, poisoned: Diagnostic };
pub const Fault = enum {
    none,
    write,
    before_file_sync,
    before_parent_sync,
    after_publication,
    mutate_member,
    replace_staged,
    cancel_after_write,
    publication_collision,
    transient_source_entry,
};
pub const Invocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    source: Source,
    context: Context,
    environ: std.process.Environ = .empty,
    output_path: []const u8,
    signal: ?*core.process.SignalCancellation = null,
    fault: Fault = .none,
};

pub fn pack(invocation: Invocation) Outcome {
    var attempt: Pack = .{ .invocation = invocation };
    const result = attempt.run(false, true) catch |err| {
        const diagnostic: Diagnostic = .{ .phase = attempt.phase, .err = err, .publication = attempt.publication };
        return if (attempt.reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = result };
}

const Held = struct { member: Member, retained: files.RetainedFile, crc32: u32 };
const Inspection = struct {
    record: files.RetainedFile,
    log: files.RetainedFile,
    record_sha256: [64]u8,
    log_sha256: [64]u8,

    fn pin(invocation: Invocation) !?Inspection {
        if (invocation.source != .local_handoff) return null;
        const source = invocation.source.local_handoff;
        const stage: accepted_run.Stage = if (source.accepted.compatibility == .tiny_v1_legacy) .@"handoff-inspect-legacy" else .@"handoff-inspect";
        const record_path = try std.fmt.allocPrint(invocation.allocator, "{s}/evidence/command-{s}.json", .{ source.root, @tagName(stage) });
        errdefer invocation.allocator.free(record_path);
        var record = try files.RetainedFile.open(invocation.io, record_path, .private);
        errdefer record.close(invocation.io);
        const log_path = try std.fmt.allocPrint(invocation.allocator, "{s}/private/{s}.log", .{ source.root, @tagName(stage) });
        errdefer invocation.allocator.free(log_path);
        var log = try files.RetainedFile.open(invocation.io, log_path, .private);
        errdefer log.close(invocation.io);
        var raw = try files.readSensitiveFile(invocation.io, invocation.allocator, record.file, layout.max_json_bytes, .private);
        defer raw.deinit();
        const checked = try accepted_run.validateLocalPostRunCommand(source.accepted, raw.bytes(), stage);
        const cancel = if (invocation.signal) |signal| signal.flag() else null;
        const log_sha256 = try copy.hashRetained(invocation.io, &log, layout.max_json_bytes, cancel);
        if (log.file_snapshot.size != checked.output_bytes) return error.CommandOutputChanged;
        try equal(&log_sha256, &checked.output_sha256);
        var observed = try files.readSensitiveFile(invocation.io, invocation.allocator, log.file, layout.max_json_bytes, .private);
        defer observed.deinit();
        var package = try source.accepted.pinArtifact(.package);
        defer package.close(invocation.io);
        var expected = try files.readSensitiveFile(invocation.io, invocation.allocator, package.file, layout.max_json_bytes, .private);
        defer expected.deinit();
        try controller.handoff_inspect.matchPackage(invocation.allocator, observed.bytes(), expected.bytes());
        return .{
            .record = record,
            .log = log,
            .record_sha256 = try copy.hashRetained(invocation.io, &record, layout.max_json_bytes, cancel),
            .log_sha256 = log_sha256,
        };
    }
    fn verify(self: *const Inspection, io: std.Io, cancel: ?*const std.atomic.Value(bool)) !void {
        try equal(&try copy.hashRetained(io, &self.record, layout.max_json_bytes, cancel), &self.record_sha256);
        try equal(&try copy.hashRetained(io, &self.log, layout.max_json_bytes, cancel), &self.log_sha256);
    }
    fn deinit(self: *Inspection, allocator: std.mem.Allocator, io: std.Io) void {
        const record_path = self.record.path;
        const log_path = self.log.path;
        self.record.close(io);
        self.log.close(io);
        allocator.free(record_path);
        allocator.free(log_path);
    }
};
const Pack = struct {
    invocation: Invocation,
    phase: Phase = .inputs,
    reserved: bool = false,
    publication: files.CommitStatus = .not_committed,

    fn cancel(self: *Pack) ?*const std.atomic.Value(bool) {
        return if (self.invocation.signal) |signal| signal.flag() else null;
    }
    fn revalidate(self: *Pack, fixture: bool) !void {
        try copy.checkCancellation(self.cancel());
        if (!fixture) try self.invocation.source.revalidate(self.invocation.signal);
    }
    fn run(self: *Pack, fixture: bool, bind_evidence: bool) !Published {
        var owned_signal: ?core.process.SignalCancellation = null;
        defer if (owned_signal) |*signal| signal.deinit();
        if (self.invocation.signal == null) {
            owned_signal = try core.process.SignalCancellation.install();
            self.invocation.signal = &owned_signal.?;
        }
        const invocation = self.invocation;
        if (!builtin.is_test and invocation.fault != .none) return error.InvalidFault;
        try invocation.context.validate();
        try files.absoluteFilePath(invocation.output_path);
        const source_root = invocation.source.root();
        try files.absoluteFilePath(source_root);
        if (inside(invocation.output_path, source_root)) return error.OutputInsideSource;
        if (!fixture) try verifyPublicScope(invocation.allocator, invocation.source);
        try self.revalidate(fixture);
        if (!fixture) {
            const accepted = invocation.source.accepted();
            const ci = try Context.fromCI(invocation.environ, accepted.repository orelse return error.InvalidContext, accepted.source);
            inline for (.{ "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision" }) |name|
                try equal(@field(ci, name), @field(invocation.context, name));
        }
        var inspection = if (fixture) null else try Inspection.pin(invocation);
        defer if (inspection) |*held| held.deinit(invocation.allocator, invocation.io);
        const manifest = invocation.source.manifest();
        const expected_path = try std.fs.path.join(invocation.allocator, &.{ source_root, "bundle.json" });
        defer invocation.allocator.free(expected_path);
        try equal(manifest.path, expected_path);
        var raw = try files.readSensitiveFile(invocation.io, invocation.allocator, manifest.file, layout.max_json_bytes, .private);
        defer raw.deinit();
        const manifest_digest = zip.sha256(raw.bytes());
        var metadata = try Metadata.fromRootBound(invocation.allocator, raw.bytes(), source_root, invocation.context);
        defer metadata.deinit();
        if (bind_evidence) try bindAccepted(invocation.source.accepted(), &metadata, invocation.context);
        const source_directory = try files.Directory.open(invocation.io, source_root);
        defer source_directory.close(invocation.io);
        const source_snapshot = try copy.directorySnapshot(source_directory.dir);
        try inspectTree(invocation.allocator, invocation.io, source_directory.dir, "", metadata.selected);
        var held: std.ArrayList(Held) = .empty;
        defer {
            for (held.items) |*item| {
                const path = item.retained.path;
                item.retained.close(invocation.io);
                invocation.allocator.free(path);
            }
            held.deinit(invocation.allocator);
        }
        for (metadata.selected) |member| {
            const path = try std.fs.path.join(invocation.allocator, &.{ source_root, member.name });
            errdefer invocation.allocator.free(path);
            var retained = try files.RetainedFile.open(invocation.io, path, .private);
            errdefer retained.close(invocation.io);
            const observed = try measure(invocation.io, &retained, member, self.cancel());
            try held.append(invocation.allocator, .{ .member = member, .retained = retained, .crc32 = observed });
        }
        try verifyManifest(invocation.io, manifest, manifest_digest, self.cancel());
        if (inspection) |*held_inspection| try held_inspection.verify(invocation.io, self.cancel());
        try self.revalidate(fixture);
        try verifySourceDirectories(source_root, source_directory.dir, source_snapshot, held.items);
        self.phase = .reserved;
        const directory = try reserve(invocation.io, invocation.output_path, &self.reserved);
        defer directory.close(invocation.io);
        const output_snapshot = try copy.directorySnapshot(directory.dir);
        var lock = try directory.lock(invocation.io);
        defer lock.close(invocation.io);
        const partial_path = try std.fs.path.join(invocation.allocator, &.{ invocation.output_path, "archive.partial" });
        defer invocation.allocator.free(partial_path);
        const file = try directory.dir.createFile(invocation.io, "archive.partial", .{
            .exclusive = true,
            .read = true,
            .permissions = .fromMode(0o600),
        });
        defer file.close(invocation.io);
        self.phase = .writing;
        const readers = try invocation.allocator.alloc(std.Io.File.Reader, held.items.len);
        defer invocation.allocator.free(readers);
        var entries_storage: [layout.max_members]zip.Entry = undefined;
        for (held.items, 0..) |*item, i| {
            readers[i] = item.retained.file.reader(invocation.io, &.{});
            entries_storage[i] = .{
                .name = item.member.name,
                .reader = &readers[i].interface,
                .size = item.member.size,
                .crc32 = item.crc32,
                .sha256 = item.member.sha256,
                .limit = item.member.limit,
                .cancel = self.cancel(),
            };
        }
        var bundle_reader = std.Io.Reader.fixed(metadata.bundle);
        var manifest_reader = std.Io.Reader.fixed(metadata.manifest);
        entries_storage[held.items.len] = sliceEntry("bundle.json", metadata.bundle, &bundle_reader);
        entries_storage[held.items.len + 1] = sliceEntry("public-source.json", metadata.manifest, &manifest_reader);
        var buffer: [64 * 1024]u8 = undefined;
        var writer = file.writer(invocation.io, &buffer);
        if (invocation.fault == .write) {
            try file.writePositionalAll(invocation.io, "PK", 0);
            return error.AmbiguousWrite;
        }
        var digest: [32]u8 = undefined;
        try zip.writeArchive(&writer.interface, entries_storage[0 .. held.items.len + 2], &digest);
        try writer.flush();
        self.phase = .file_sync;
        if (invocation.fault == .before_file_sync) return error.AmbiguousWrite;
        try file.sync(invocation.io);
        try syncDir(invocation.io, directory.dir);
        if (builtin.is_test) try self.injectAfterWrite(directory.dir, file, held.items);
        try copy.checkCancellation(self.cancel());
        self.phase = .reopen;
        var reopened = try Archive.open(invocation.allocator, invocation.io, partial_path, invocation.context, digest, self.cancel());
        defer reopened.deinit(invocation.io);
        if (!copy.sameCustodySnapshot(try files.snapshot(file), reopened.retained.file_snapshot)) return error.FileChanged;
        self.phase = .revalidated;
        try self.revalidate(fixture);
        if (inspection) |*held_inspection| try held_inspection.verify(invocation.io, self.cancel());
        try verifyManifest(invocation.io, manifest, manifest_digest, self.cancel());
        for (held.items) |*item| _ = try measure(invocation.io, &item.retained, item.member, self.cancel());
        try inspectTree(invocation.allocator, invocation.io, source_directory.dir, "", metadata.selected);
        try copy.verifyRoot(invocation.io, source_root, source_snapshot);
        try verifySourceDirectories(source_root, source_directory.dir, source_snapshot, held.items);
        try copy.verifyRoot(invocation.io, invocation.output_path, output_snapshot);
        try reopened.revalidate(invocation.io, self.cancel());
        try copy.checkCancellation(self.cancel());
        if (invocation.fault == .before_parent_sync) return error.AmbiguousWrite;
        try syncDir(invocation.io, directory.dir);
        self.phase = .publication;
        self.publication = .publication_unknown;
        directory.dir.renamePreserve("archive.partial", directory.dir, "public-inner.zip", invocation.io) catch |err| {
            if (err == error.PathAlreadyExists) self.publication = .not_committed;
            return err;
        };
        self.publication = .visible_not_durable;
        self.phase = .parent_sync;
        if (invocation.fault == .after_publication) return error.AmbiguousWrite;
        try syncDir(invocation.io, directory.dir);
        self.publication = .durable;
        const final_path = try std.fs.path.join(invocation.allocator, &.{ invocation.output_path, "public-inner.zip" });
        defer invocation.allocator.free(final_path);
        var final = try files.RetainedFile.open(invocation.io, final_path, .private);
        defer final.close(invocation.io);
        const actual = try copy.hashRetained(invocation.io, &final, layout.max_total_bytes, self.cancel());
        try equal(&actual, &std.fmt.bytesToHex(digest, .lower));
        try self.revalidate(fixture);
        if (inspection) |*held_inspection| try held_inspection.verify(invocation.io, self.cancel());
        try verifyManifest(invocation.io, manifest, manifest_digest, self.cancel());
        for (held.items) |*item| _ = try measure(invocation.io, &item.retained, item.member, self.cancel());
        try verifySourceDirectories(source_root, source_directory.dir, source_snapshot, held.items);
        return .{ .sha256 = digest, .bytes = final.file_snapshot.size, .members = held.items.len + 2 };
    }

    fn injectAfterWrite(self: *Pack, directory: std.Io.Dir, file: std.Io.File, held: []Held) !void {
        const io = self.invocation.io;
        switch (self.invocation.fault) {
            .mutate_member => {
                const target = try std.Io.Dir.openFileAbsolute(io, held[0].retained.path, .{ .mode = .read_write, .follow_symlinks = false });
                defer target.close(io);
                try target.writePositionalAll(io, "!", 0);
                try target.sync(io);
            },
            .replace_staged => {
                try directory.renamePreserve("archive.partial", directory, "replaced.partial", io);
                const replacement = try directory.createFile(io, "archive.partial", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
                defer replacement.close(io);
                var buffer: [64 * 1024]u8 = undefined;
                var offset: u64 = 0;
                const size = (try files.snapshot(file)).size;
                while (offset < size) {
                    const want: usize = @intCast(@min(buffer.len, size - offset));
                    if (try file.readPositionalAll(io, buffer[0..want], offset) != want) return error.FileChanged;
                    try replacement.writePositionalAll(io, buffer[0..want], offset);
                    offset += want;
                }
                try replacement.sync(io);
            },
            .cancel_after_write => @constCast(self.cancel() orelse return error.InvalidFault).store(true, .release),
            .publication_collision => {
                const collision = try directory.createFile(io, "public-inner.zip", .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
                defer collision.close(io);
                try collision.writePositionalAll(io, "foreign", 0);
                try collision.sync(io);
            },
            .transient_source_entry => {
                const parent = try files.FileParent.open(io, held[0].retained.path, .private);
                defer parent.close(io);
                const extra = try parent.directory.createFile(io, "transient", .{ .exclusive = true, .permissions = .fromMode(0o600) });
                extra.close(io);
                try parent.directory.deleteFile(io, "transient");
                try parent.sync(io);
            },
            else => {},
        }
    }
};

fn verifySourceDirectories(root: []const u8, directory: std.Io.Dir, snapshot: files.Snapshot, held: []const Held) !void {
    if (!copy.sameCustodySnapshot(snapshot, try copy.directorySnapshot(directory))) return error.SourceChanged;
    const root_index = std.mem.count(u8, root, "/");
    for (held) |item| {
        if (root_index >= item.retained.directory_count) return error.InvalidPath;
        for (root_index..item.retained.directory_count) |index|
            if (!copy.sameCustodySnapshot(item.retained.directory_snapshots[index], try copy.directorySnapshot(item.retained.directories[index])))
                return error.SourceChanged;
    }
}

fn bindAccepted(accepted: *accepted_run.AcceptedRun, metadata: *const Metadata, context: Context) !void {
    try equal(accepted.source.revision, context.source_revision);
    try equal(accepted.source.tree, context.source_tree);
    const compatibility: profile.Compatibility = if (accepted.compatibility == .tiny_v1_legacy) .frozen_tiny_v1 else .tiny_qcow2_derived_vhd_v2;
    if (compatibility != metadata.compatibility or accepted.records.len != layout.evidenceNames(compatibility).len)
        return error.ProfileMismatch;
    var document = try contracts.parseCanonical(accepted.arena.allocator(), metadata.bundle);
    defer document.deinit();
    const identity = try field(document.value(), "identity");
    for (metadata.selected) |member| {
        inline for (.{ "wasm", "cwasm", "runtime", "compiler", "config" }) |name| {
            if (std.mem.eql(u8, member.name, "artifacts/" ++ name))
                try equal(try c.string(try field(identity, name ++ "_sha256")), &std.fmt.bytesToHex(member.sha256, .lower));
        }
    }
    for (metadata.selected) |member| {
        if (std.mem.eql(u8, member.name, "artifacts/local_result")) {
            if (member.size != accepted.result.bytes) return error.ResultChanged;
            try equal(&std.fmt.bytesToHex(member.sha256, .lower), &accepted.result.sha256);
        }
        if (std.mem.startsWith(u8, member.name, "evidence/")) {
            var found = false;
            for (accepted.records) |record| {
                if (!std.mem.eql(u8, record.name, member.name["evidence/".len..])) continue;
                if (record.bytes != member.size) return error.RecordChanged;
                try equal(&std.fmt.bytesToHex(member.sha256, .lower), &record.sha256);
                found = true;
            }
            if (!found) return error.MissingRecord;
        } else {
            const role = if (std.mem.startsWith(u8, member.name, "artifacts/"))
                member.name["artifacts/".len..]
            else
                null;
            var found = false;
            for (accepted.artifacts) |artifact| {
                var buffer: [128]u8 = undefined;
                const name = if (role) |name| name else blk: {
                    const relative = member.name["boots/".len..];
                    const split = std.mem.lastIndexOfScalar(u8, relative, '/') orelse return error.UnknownBootRole;
                    break :blk try std.fmt.bufPrint(&buffer, "boot:{s}:{s}", .{ relative[0..split], relative[split + 1 ..] });
                };
                if (!std.mem.eql(u8, artifact.role, name)) continue;
                if (artifact.bytes != member.size) return error.ArtifactChanged;
                try equal(&std.fmt.bytesToHex(member.sha256, .lower), &artifact.sha256);
                found = true;
            }
            // Cleanup is pinned separately by the merged local export owner.
            if (!found and role != null and std.mem.eql(u8, role.?, "cleanup") and accepted.context == .local_runtime) {
                var cleanup = try accepted.pinExportCleanup();
                defer cleanup.close(accepted.io);
                _ = try measure(accepted.io, &cleanup, member, null);
                found = true;
            }
            if (!found) return error.MissingArtifact;
        }
    }
}

fn bindBundle(value: std.json.Value, compatibility: profile.Compatibility, context: Context) !void {
    try equal(try c.string(try field(value, "source_revision")), context.source_revision);
    try equal(try c.string(try field(value, "source_tree")), context.source_tree);
    try equal(try c.string(try field(try field(value, "identity"), "wamr_revision")), context.wamr_revision);
    if (compatibility == .tiny_qcow2_derived_vhd_v2) {
        const run = try field(value, "run");
        try equal(try c.string(try field(run, "repository")), context.repository);
        try equal(try c.string(try field(run, "run_id")), context.run_id);
        try equal(try c.string(try field(run, "run_attempt")), context.run_attempt);
    }
}
fn verifyPublicScope(allocator: std.mem.Allocator, source: Source) !void {
    const accepted = source.accepted();
    const repository = accepted.repository orelse return error.InvalidContext;
    const default_runtime = try std.fs.path.join(allocator, &.{ repository, ".d/wamr-native-runtime" });
    defer allocator.free(default_runtime);
    for ([_][]const u8{ default_runtime, "/d/wamr-ci/wamr-native-runtime" }) |runtime| {
        const handoff = try std.fs.path.join(allocator, &.{ runtime, "compute/public-source/handoff" });
        defer allocator.free(handoff);
        if (!std.mem.eql(u8, source.root(), handoff)) continue;
        if (source == .local_handoff and !std.mem.eql(u8, accepted.root, runtime))
            return error.InvalidPublicScope;
        return;
    }
    return error.InvalidPublicScope;
}
fn field(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidObject;
    return value.object.get(key) orelse error.MissingField;
}
fn equal(left: []const u8, right: []const u8) !void {
    if (!std.mem.eql(u8, left, right)) return error.ContextMismatch;
}
fn canonical(a: std.mem.Allocator, value: anytype) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    return controller.records.canonicalAlloc(a, raw);
}
fn scan(bytes: []const u8) !void {
    var scanner: copy.Scanner = .{};
    var offset: usize = 0;
    while (offset < bytes.len) {
        const end = @min(offset + 64 * 1024, bytes.len);
        try scanner.observe(bytes[offset..end]);
        offset = end;
    }
}
fn readImage(allocator: std.mem.Allocator, io: std.Io, retained: *const files.RetainedFile, cancel: ?*const std.atomic.Value(bool)) !core.sensitive.Buffer {
    const size = retained.file_snapshot.size;
    if (size == 0 or size > layout.max_total_bytes) return error.TooLarge;
    var result: core.sensitive.Buffer = .{
        .allocator = allocator,
        .storage = try allocator.alloc(u8, @intCast(size)),
        .length = @intCast(size),
    };
    errdefer result.deinit();
    var offset: usize = 0;
    while (offset < result.length) {
        try copy.checkCancellation(cancel);
        const end = @min(offset + 64 * 1024, result.length);
        if (try retained.file.readPositionalAll(io, result.storage[offset..end], offset) != end - offset)
            return error.FileChanged;
        offset = end;
    }
    var extra: [1]u8 = undefined;
    if (try retained.file.readPositionalAll(io, &extra, size) != 0) return error.FileChanged;
    try copy.verifyRetained(io, retained);
    return result;
}
fn expectedSlice(name: []const u8, bytes: []const u8) zip.ExpectedMember {
    return .{ .name = name, .size = bytes.len, .sha256 = zip.sha256(bytes), .limit = layout.max_json_bytes };
}
fn sliceEntry(name: []const u8, bytes: []const u8, reader: *std.Io.Reader) zip.Entry {
    return .{ .name = name, .size = bytes.len, .sha256 = zip.sha256(bytes), .crc32 = zip.crc32(bytes), .limit = layout.max_json_bytes, .reader = reader };
}
fn measure(io: std.Io, retained: *const files.RetainedFile, member: Member, cancel: ?*const std.atomic.Value(bool)) !u32 {
    try copy.verifyRetained(io, retained);
    if (retained.file_snapshot.size != member.size or member.size == 0 or member.size > member.limit) return error.SizeMismatch;
    var hasher = core.Sha256.init(.{});
    var crc = std.hash.Crc32.init();
    var scanner: copy.Scanner = .{};
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < member.size) {
        try copy.checkCancellation(cancel);
        const want: usize = @intCast(@min(buffer.len, member.size - offset));
        if (try retained.file.readPositionalAll(io, buffer[0..want], offset) != want) return error.FileChanged;
        try scanner.observe(buffer[0..want]);
        hasher.update(buffer[0..want]);
        crc.update(buffer[0..want]);
        offset += want;
    }
    if (try retained.file.readPositionalAll(io, buffer[0..1], offset) != 0) return error.FileChanged;
    try copy.verifyRetained(io, retained);
    if (!std.mem.eql(u8, &hasher.finalResult(), &member.sha256)) return error.DigestMismatch;
    return crc.final();
}
fn verifyManifest(io: std.Io, retained: *const files.RetainedFile, digest: [32]u8, cancel: ?*const std.atomic.Value(bool)) !void {
    const observed = try copy.hashRetained(io, retained, layout.max_json_bytes, cancel);
    try equal(&observed, &std.fmt.bytesToHex(digest, .lower));
}
fn inside(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or (std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/');
}
fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
fn reserve(io: std.Io, path: []const u8, started: ?*bool) !files.Directory {
    const parent = try files.FileParent.open(io, path, .private);
    defer parent.close(io);
    parent.directory.createDir(io, parent.name, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.OutputExists,
        else => return err,
    };
    if (started) |flag| flag.* = true;
    const directory = try files.Directory.open(io, path);
    errdefer directory.close(io);
    try syncDir(io, directory.dir);
    try parent.sync(io);
    return directory;
}
fn writeMember(io: std.Io, root: std.Io.Dir, relative: []const u8, bytes: []const u8) !void {
    var current = root;
    var close_current = false;
    defer if (close_current) current.close(io);
    var parts = std.mem.splitScalar(u8, relative, '/');
    var name = parts.next() orelse return error.InvalidName;
    while (parts.next()) |next| {
        current.createDir(io, name, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const child = try current.openDir(io, name, .{ .follow_symlinks = false, .iterate = true });
        errdefer child.close(io);
        try syncDir(io, current);
        if (close_current) current.close(io);
        current = child;
        close_current = true;
        name = next;
    }
    const file = try current.createFile(io, name, .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
    try syncDir(io, current);
}

const private_members = [_][]const u8{
    ".writer.lock",                               "bundle.json",
    "private/handoff-inspect.log",                "private/handoff-inspect-legacy.log",
    "evidence/command-handoff-inspect.json",      "evidence/command-handoff-inspect-legacy.json",
    "private/export/.writer.lock",                "private/export/handoff.json",
    "private/export/publication-intent.json",     "private/export/phase-output_reserved.json",
    "private/export/phase-artifacts_copied.json", "private/export/phase-boots_copied.json",
    "private/export/phase-evidence_copied.json",  "private/export/phase-source_revalidated.json",
    "private/export/phase-handoff_staged.json",   "private/export/phase-handoff_validated.json",
};
fn allowed(relative: []const u8, selected: []const Member, directory: bool) bool {
    for (selected) |member| {
        if ((!directory and std.mem.eql(u8, relative, member.name)) or
            (directory and member.name.len > relative.len and std.mem.startsWith(u8, member.name, relative) and member.name[relative.len] == '/'))
            return true;
    }
    for (private_members) |member| {
        if ((!directory and std.mem.eql(u8, relative, member)) or
            (directory and member.len > relative.len and std.mem.startsWith(u8, member, relative) and member[relative.len] == '/'))
            return true;
    }
    return false;
}
fn inspectTree(a: std.mem.Allocator, io: std.Io, directory: std.Io.Dir, prefix: []const u8, selected: []const Member) !void {
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        const relative = if (prefix.len == 0) try a.dupe(u8, entry.name) else try std.fs.path.join(a, &.{ prefix, entry.name });
        defer a.free(relative);
        if (entry.kind == .directory) {
            if (!allowed(relative, selected, true)) return error.UnexpectedMember;
            const child = try directory.openDir(io, entry.name, .{ .follow_symlinks = false, .iterate = true });
            defer child.close(io);
            try inspectTree(a, io, child, relative, selected);
        } else {
            if (entry.kind != .file or !allowed(relative, selected, false)) return error.UnexpectedMember;
            const file = try directory.openFile(io, entry.name, .{ .follow_symlinks = false });
            defer file.close(io);
            const snapshot = try files.snapshot(file);
            if (snapshot.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or snapshot.nlink != 1 or
                snapshot.uid != std.os.linux.geteuid() or snapshot.mode & 0o022 != 0)
                return error.UnsafeMember;
        }
    }
}

pub const Test = if (builtin.is_test) struct {
    // Substitute only the expensive AcceptedRun/validator process boundary.
    pub fn packFixture(invocation: Invocation) Outcome {
        return packWithBinding(invocation, false);
    }
    pub fn packAcceptedFixture(invocation: Invocation) Outcome {
        return packWithBinding(invocation, true);
    }
    fn packWithBinding(invocation: Invocation, bind_evidence: bool) Outcome {
        var attempt: Pack = .{ .invocation = invocation };
        const result = attempt.run(true, bind_evidence) catch |err| {
            const diagnostic: Diagnostic = .{ .phase = attempt.phase, .err = err, .publication = attempt.publication };
            return if (attempt.reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
        };
        return .{ .success = result };
    }
} else struct {};
