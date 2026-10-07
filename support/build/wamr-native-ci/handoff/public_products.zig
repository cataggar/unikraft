// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const controller = @import("wamr_controller");
const accepted = controller.accepted_run;
const validation = controller.import_validator_build;
const export_state = @import("export.zig");
const archive = @import("public_archive.zig");
const transport = @import("public_transport.zig");
const copy = @import("retained_copy.zig");
const layout = controller.handoff_contracts.layout;

pub const Phase = enum { inputs, export_handoff, private_validation, archive, reserved, materialized, copied, native_validation, publication, final_revalidation };
pub const Diagnostic = struct { phase: Phase, err: anyerror, publication: files.CommitStatus = .not_committed };
pub fn Outcome(comptime T: type) type {
    return union(enum) { success: T, refused: Diagnostic, poisoned: Diagnostic };
}

pub const ExportInvocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    repository: []const u8,
    runtime: ?[]const u8,
    handoff: []const u8,
    validation_output: []const u8,
    archive_output: []const u8,
    context: archive.Context,
    tools: validation.LocalTools,
    signal: ?*core.process.SignalCancellation = null,
};

pub fn exportArchive(inv: ExportInvocation) Outcome(archive.Published) {
    var phase: Phase = .inputs;
    var reserved = false;
    var scoped: ?core.process.SignalCancellation = null;
    defer if (scoped) |*signal| signal.deinit();
    var actual = inv;
    if (actual.signal == null) {
        scoped = core.process.SignalCancellation.install() catch |err|
            return .{ .refused = .{ .phase = .inputs, .err = err } };
        actual.signal = &scoped.?;
    }
    return exportRun(actual, &phase, &reserved) catch |err| {
        const diagnostic: Diagnostic = .{ .phase = phase, .err = err };
        return if (reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
}

fn exportRun(inv: ExportInvocation, phase: *Phase, reserved: *bool) !Outcome(archive.Published) {
    try inv.context.validate();
    if (inv.runtime) |runtime| {
        phase.* = .export_handoff;
        switch (export_state.run(.{
            .allocator = inv.allocator,
            .io = inv.io,
            .environ = inv.environ,
            .runtime_path = runtime,
            .repository_path = inv.repository,
            .output_path = inv.handoff,
            .signal = inv.signal,
        })) {
            .success => reserved.* = true,
            .refused => |diagnostic| return .{ .refused = .{
                .phase = phase.*,
                .err = diagnostic.err,
                .publication = diagnostic.publication,
            } },
            .poisoned => |diagnostic| return .{ .poisoned = .{
                .phase = phase.*,
                .err = diagnostic.err,
                .publication = diagnostic.publication,
            } },
        }
    }
    const directory = try files.Directory.open(inv.io, inv.handoff);
    defer directory.close(inv.io);
    var bundle = try accepted.PrivateBundle.open(
        inv.allocator,
        inv.io,
        &directory,
        inv.handoff,
        inv.repository,
        inv.tools,
        inv.signal,
    );
    defer bundle.deinit();
    const ci = try archive.Context.fromCI(inv.environ, inv.repository, bundle.evidence.source);
    inline for (.{ "repository", "run_id", "run_attempt", "source_revision", "source_tree", "wamr_revision" }) |key|
        if (!std.mem.eql(u8, @field(ci, key), @field(inv.context, key))) return error.ContextMismatch;
    phase.* = .private_validation;
    reserved.* = true;
    try validation.runPrivate(inv.allocator, inv.io, &bundle, inv.validation_output, inv.signal);
    try bundle.revalidate(inv.signal);
    phase.* = .archive;
    return switch (archive.pack(.{
        .allocator = inv.allocator,
        .io = inv.io,
        .source = .{ .private_bundle = &bundle },
        .context = inv.context,
        .environ = inv.environ,
        .output_path = inv.archive_output,
        .signal = inv.signal,
    })) {
        .success => |result| .{ .success = result },
        .refused, .poisoned => |diagnostic| .{ .poisoned = .{
            .phase = phase.*,
            .err = diagnostic.err,
            .publication = diagnostic.publication,
        } },
    };
}

pub const Input = union(enum) {
    historical_archive: struct { path: []const u8, context: archive.Context, digest: ?transport.InnerDigest },
    exact_download: struct {
        path: []const u8,
        container_path: []const u8,
        expected: transport.Expected,
        selection: transport.DownloadSelection,
    },
};
pub const ImportInvocation = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    input: Input,
    output: []const u8,
    tools: validation.LocalTools,
    signal: ?*core.process.SignalCancellation = null,
};
const Held = struct { file: files.RetainedFile, digest: [64]u8, limit: u64 };
const SealedDirectory = struct { directory: files.Directory, snapshot: files.Snapshot };

// Heap ownership keeps Download -> Archive -> Imported borrowing addresses
// stable. Deinitialization closes consumers first and never removes evidence.
pub const ImportedProduct = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    repository: []const u8 = "",
    output: []const u8 = "",
    historical: ?archive.Archive = null,
    download: ?transport.Download = null,
    materialized: ?archive.Imported = null,
    downloaded: ?transport.Imported = null,
    container: ?Held = null,
    directory: ?files.Directory = null,
    lock: ?files.Locked = null,
    candidate: ?Held = null,
    receipt: ?Held = null,
    members: std.ArrayList(Held) = .empty,
    sealed: std.ArrayList(SealedDirectory) = .empty,
    native: ?validation.RetainedValidation = null,
    bundle: ?accepted.PrivateBundle = null,
    final: ?Held = null,
    phase: Phase = .inputs,
    publication: files.CommitStatus = .not_committed,
    reserved: bool = false,

    fn metadata(self: *ImportedProduct) *const archive.Metadata {
        return if (self.download) |*owner| &owner.standalone.archive.metadata else &self.historical.?.metadata;
    }
    fn stage(self: *ImportedProduct) *archive.Imported {
        return if (self.downloaded) |*owner| &owner.stage else &self.materialized.?;
    }
    fn sourceArchive(self: *ImportedProduct) *archive.Archive {
        return if (self.download) |*owner| &owner.standalone.archive else &self.historical.?;
    }
    fn retain(self: *ImportedProduct, path: []const u8, limit: u64, cancel: ?*const std.atomic.Value(bool)) !Held {
        var file = try files.RetainedFile.open(self.io, path, .private);
        errdefer file.close(self.io);
        return .{ .file = file, .digest = try copy.hashRetained(self.io, &file, limit, cancel), .limit = limit };
    }
    fn verifyHeld(self: *ImportedProduct, held: *Held, cancel: ?*const std.atomic.Value(bool)) !void {
        const digest = try copy.hashRetained(self.io, &held.file, held.limit, cancel);
        if (!std.mem.eql(u8, &digest, &held.digest)) return error.InputChanged;
    }
    fn verifyInputs(self: *ImportedProduct, signal: ?*core.process.SignalCancellation) !void {
        const cancel = if (signal) |active| active.flag() else null;
        try copy.checkCancellation(cancel);
        if (self.container) |*held| try self.verifyHeld(held, cancel);
        if (self.downloaded) |*owner| try owner.revalidate(self.io, signal) else if (self.materialized) |*owner|
            try owner.revalidate(self.io, signal);
        if (self.download) |*owner| try owner.revalidate(self.io, cancel) else if (self.historical) |*owner|
            try owner.revalidate(self.io, cancel);
        for (self.members.items) |*held| try self.verifyHeld(held, cancel);
        if (self.candidate) |*held| try self.verifyHeld(held, cancel);
        if (self.receipt) |*held| try self.verifyHeld(held, cancel);
        if (self.native) |*owner| try owner.revalidate(self.io, self.repository, signal);
        if (self.directory != null and self.candidate != null) try self.verifyOutputTree();
        for (self.sealed.items) |held|
            if (!copy.sameCustodySnapshot(held.snapshot, try copy.directorySnapshot(held.directory.dir)))
                return error.OutputChanged;
    }
    pub fn revalidate(self: *ImportedProduct, signal: ?*core.process.SignalCancellation) !void {
        if (self.publication != .durable or self.bundle == null or self.final == null)
            return error.ImportNotPublished;
        try self.verifyInputs(signal);
        try self.bundle.?.revalidate(signal);
        try self.verifyHeld(&self.final.?, if (signal) |active| active.flag() else null);
        try self.verifyInputs(signal);
    }
    pub fn deinit(self: *ImportedProduct) void {
        if (self.bundle) |*owner| owner.deinit();
        if (self.native) |*owner| owner.deinit(self.io);
        if (self.final) |*held| held.file.close(self.io);
        if (self.candidate) |*held| held.file.close(self.io);
        if (self.receipt) |*held| held.file.close(self.io);
        for (self.members.items) |*held| held.file.close(self.io);
        self.members.deinit(self.allocator);
        for (self.sealed.items) |held| held.directory.close(self.io);
        self.sealed.deinit(self.allocator);
        if (self.lock) |*lock| lock.close(self.io);
        if (self.downloaded) |*owner| owner.deinit(self.io);
        if (self.materialized) |*owner| owner.deinit(self.io);
        if (self.download) |*owner| owner.deinit(self.io);
        if (self.historical) |*owner| owner.deinit(self.io);
        if (self.container) |*held| held.file.close(self.io);
        if (self.directory) |directory| directory.close(self.io);
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self);
    }
    fn verifyOutputTree(self: *ImportedProduct) !void {
        var iterator = self.directory.?.dir.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (entry.kind == .directory) {
                if (!std.mem.eql(u8, entry.name, "private") and !std.mem.eql(u8, entry.name, "artifacts") and
                    !std.mem.eql(u8, entry.name, "boots") and !std.mem.eql(u8, entry.name, "evidence"))
                    return error.UnexpectedMember;
                if (!std.mem.eql(u8, entry.name, "private")) {
                    const child = try self.directory.?.dir.openDir(self.io, entry.name, .{ .iterate = true, .follow_symlinks = false });
                    defer child.close(self.io);
                    try self.verifySelectedTree(child, entry.name);
                }
            } else if (entry.kind != .file) {
                return error.UnexpectedMember;
            } else {
                var allowed = false;
                for ([_][]const u8{ ".writer.lock", "portable-bundle.json", "public-source.json", "candidate-bundle.json" }) |name| {
                    if (std.mem.eql(u8, entry.name, name)) allowed = true;
                }
                if (self.receipt != null and std.mem.eql(u8, entry.name, "transport.json")) allowed = true;
                if (self.publication == .durable and std.mem.eql(u8, entry.name, "bundle.json")) allowed = true;
                if (!allowed) return error.UnexpectedMember;
            }
        }
    }
    fn verifySelectedTree(self: *ImportedProduct, directory: std.Io.Dir, prefix: []const u8) !void {
        var iterator = directory.iterate();
        while (try iterator.next(self.io)) |entry| {
            const relative = try std.fs.path.join(self.allocator, &.{ prefix, entry.name });
            defer self.allocator.free(relative);
            var allowed = false;
            for (self.metadata().selected) |member| {
                if (entry.kind == .file and std.mem.eql(u8, relative, member.name)) allowed = true;
                if (entry.kind == .directory and inside(member.name, relative) and member.name.len > relative.len) allowed = true;
            }
            if (!allowed) return error.UnexpectedMember;
            if (entry.kind == .directory) {
                const child = try directory.openDir(self.io, entry.name, .{ .iterate = true, .follow_symlinks = false });
                defer child.close(self.io);
                try self.verifySelectedTree(child, relative);
            }
        }
    }
};

pub fn importBundle(inv: ImportInvocation) Outcome(*ImportedProduct) {
    var scoped: ?core.process.SignalCancellation = null;
    defer if (scoped) |*signal| signal.deinit();
    var actual = inv;
    if (actual.signal == null) {
        scoped = core.process.SignalCancellation.install() catch |err|
            return .{ .refused = .{ .phase = .inputs, .err = err } };
        actual.signal = &scoped.?;
    }
    const owner = inv.allocator.create(ImportedProduct) catch |err|
        return .{ .refused = .{ .phase = .inputs, .err = err } };
    owner.* = .{ .allocator = inv.allocator, .io = inv.io, .arena = std.heap.ArenaAllocator.init(inv.allocator) };
    importRun(owner, actual) catch |err| {
        const diagnostic: Diagnostic = .{ .phase = owner.phase, .err = err, .publication = owner.publication };
        const reserved = owner.reserved;
        owner.deinit();
        return if (reserved) .{ .poisoned = diagnostic } else .{ .refused = diagnostic };
    };
    return .{ .success = owner };
}

fn importRun(owner: *ImportedProduct, inv: ImportInvocation) !void {
    const a = owner.arena.allocator();
    const cancel = if (inv.signal) |signal| signal.flag() else null;
    try copy.checkCancellation(cancel);
    try files.absoluteFilePath(inv.repository);
    try files.absoluteFilePath(inv.output);
    if (inside(inv.output, inv.repository) or inside(inv.repository, inv.output)) return error.AliasedOutput;
    owner.repository = try a.dupe(u8, inv.repository);
    owner.output = try a.dupe(u8, inv.output);
    switch (inv.input) {
        .historical_archive => |input| {
            owner.historical = try archive.Archive.open(inv.allocator, inv.io, input.path, input.context, if (input.digest) |digest| digest.bytes else null, cancel);
            if (owner.historical.?.metadata.compatibility != .frozen_tiny_v1) return error.ExactDownloadRequired;
            if (inside(inv.output, input.path) or inside(input.path, inv.output)) return error.AliasedOutput;
        },
        .exact_download => |input| {
            if (inside(inv.output, input.path) or inside(input.path, inv.output) or
                inside(inv.output, input.container_path) or inside(input.container_path, inv.output))
                return error.AliasedOutput;
            const path = try a.dupe(u8, input.container_path);
            owner.container = blk: {
                var container = try files.RetainedFile.open(inv.io, path, .artifact);
                errdefer container.close(inv.io);
                const digest = try copy.hashRetained(inv.io, &container, layout.max_total_bytes + 128 * 1024, cancel);
                if (!std.mem.eql(u8, &digest, &std.fmt.bytesToHex(input.expected.upload.container_digest.bytes, .lower)))
                    return error.ContainerDigestMismatch;
                break :blk .{ .file = container, .digest = digest, .limit = layout.max_total_bytes + 128 * 1024 };
            };
            owner.download = try transport.Download.open(inv.allocator, inv.io, input.path, input.expected, input.selection, cancel);
        },
    }
    const parent = try files.FileParent.open(inv.io, inv.output, .private);
    defer parent.close(inv.io);
    owner.phase = .reserved;
    parent.directory.createDir(inv.io, parent.name, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => return error.OutputExists,
        else => return err,
    };
    owner.reserved = true;
    owner.directory = try files.Directory.open(inv.io, owner.output);
    try syncDir(inv.io, owner.directory.?.dir);
    try parent.sync(inv.io);
    owner.lock = try owner.directory.?.lock(inv.io);
    try owner.directory.?.dir.createDir(inv.io, "private", .fromMode(0o700));
    const stage_path = try std.fs.path.join(a, &.{ owner.output, "private/materialized" });
    owner.phase = .materialized;
    if (owner.download) |*download|
        owner.downloaded = try download.materialize(inv.io, stage_path, cancel)
    else
        owner.materialized = try owner.historical.?.materialize(inv.io, stage_path, cancel);
    try owner.verifyInputs(inv.signal);
    owner.phase = .copied;
    var budget: copy.Budget = .{};
    for (owner.metadata().selected) |member| {
        const source_path = try std.fs.path.join(a, &.{ stage_path, member.name });
        var source = try files.RetainedFile.open(inv.io, source_path, .private);
        defer source.close(inv.io);
        const copied = try copy.copyRetained(inv.allocator, inv.io, &source, owner.directory.?.dir, owner.output, member.name, member.limit, &budget, .{
            .scan = .public_bundle,
            .cancel = cancel,
        });
        defer inv.allocator.free(copied.path);
        if (copied.size != member.size or !std.mem.eql(u8, &copied.sha256, &std.fmt.bytesToHex(member.sha256, .lower)))
            return error.CopyChanged;
        const path = try a.dupe(u8, copied.path);
        var held = try owner.retain(path, member.limit, cancel);
        errdefer held.file.close(inv.io);
        try owner.members.append(inv.allocator, held);
    }
    const candidate = try owner.metadata().rootBoundBundle(a, owner.output);
    try writeImmutable(inv.io, owner.directory.?.dir, "portable-bundle.json", owner.metadata().bundle);
    try writeImmutable(inv.io, owner.directory.?.dir, "public-source.json", owner.metadata().manifest);
    for ([_][]const u8{ "portable-bundle.json", "public-source.json" }) |name| {
        var held = try owner.retain(try std.fs.path.join(a, &.{ owner.output, name }), layout.max_json_bytes, cancel);
        errdefer held.file.close(inv.io);
        try owner.members.append(inv.allocator, held);
    }
    try writeImmutable(inv.io, owner.directory.?.dir, "candidate-bundle.json", candidate);
    owner.candidate = try owner.retain(try std.fs.path.join(a, &.{ owner.output, "candidate-bundle.json" }), layout.max_json_bytes, cancel);
    if (owner.download) |*download| {
        const receipt = try download.receipt(a, inv.io, cancel);
        try writeImmutable(inv.io, owner.directory.?.dir, "transport.json", receipt);
        owner.receipt = try owner.retain(try std.fs.path.join(a, &.{ owner.output, "transport.json" }), layout.max_json_bytes, cancel);
    }
    for ([_][]const u8{ "artifacts", "boots", "evidence" }) |name| {
        const directory = try files.Directory.open(inv.io, try std.fs.path.join(a, &.{ owner.output, name }));
        errdefer directory.close(inv.io);
        try owner.sealed.append(inv.allocator, .{ .directory = directory, .snapshot = try copy.directorySnapshot(directory.dir) });
    }
    for (controller.handoff_contracts.profile.modes(owner.metadata().compatibility)) |mode| {
        const relative = try std.fmt.allocPrint(a, "boots/{s}", .{@tagName(mode)});
        const directory = try files.Directory.open(inv.io, try std.fs.path.join(a, &.{ owner.output, relative }));
        errdefer directory.close(inv.io);
        try owner.sealed.append(inv.allocator, .{ .directory = directory, .snapshot = try copy.directorySnapshot(directory.dir) });
    }
    try owner.verifyInputs(inv.signal);
    owner.phase = .native_validation;
    owner.native = try validation.runImportedReader(
        inv.allocator,
        inv.io,
        &owner.stage().accepted,
        owner.repository,
        &owner.candidate.?.file,
        try std.fs.path.join(a, &.{ owner.output, "private/native-validation" }),
        inv.tools,
        inv.signal,
    );
    try owner.verifyInputs(inv.signal);
    owner.phase = .publication;
    try copy.checkCancellation(cancel);
    const commit = try owner.lock.?.createImmutable(inv.io, "bundle.json", candidate);
    owner.publication = commit.status;
    if (commit.status != .durable) return error.AmbiguousWrite;
    owner.phase = .final_revalidation;
    owner.final = try owner.retain(try std.fs.path.join(a, &.{ owner.output, "bundle.json" }), layout.max_json_bytes, cancel);
    if (!std.mem.eql(u8, &owner.final.?.digest, &owner.candidate.?.digest)) return error.CopyChanged;
    owner.bundle = try accepted.PrivateBundle.open(
        inv.allocator,
        inv.io,
        &owner.directory.?,
        owner.output,
        owner.repository,
        inv.tools,
        inv.signal,
    );
    try owner.revalidate(inv.signal);
}

fn inside(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or
        (path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/');
}
fn syncDir(io: std.Io, directory: std.Io.Dir) !void {
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
fn writeImmutable(io: std.Io, directory: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try directory.createFile(io, name, .{ .exclusive = true, .read = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
    try syncDir(io, directory);
}
