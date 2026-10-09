// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const types = @import("types.zig");
const contracts = @import("contracts.zig");
const files = core.private_files;
const copy = @import("wamr_handoff").retained_copy;

pub const Barrier = struct {
    context: *anyopaque,
    check: *const fn (*anyopaque) anyerror!void,
    pub fn revalidate(self: Barrier) !void {
        try self.check(self.context);
    }
};
pub const Record = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: files.RetainedFile,
    sha256: [64]u8,
    limit: u64,

    pub fn open(ctx: types.Context, path: []const u8, limit: u64) !Record {
        const owned = try ctx.allocator.dupe(u8, path);
        errdefer ctx.allocator.free(owned);
        var file = try files.RetainedFile.open(ctx.io, owned, .private);
        errdefer file.close(ctx.io);
        return .{
            .allocator = ctx.allocator,
            .io = ctx.io,
            .file = file,
            .limit = limit,
            .sha256 = try copy.hashRetained(ctx.io, &file, limit, if (ctx.signal) |s| s.flag() else null),
        };
    }
    pub fn artifact(self: *const Record) types.Artifact {
        return .{ .path = self.file.path, .size = self.file.file_snapshot.size, .sha256 = &self.sha256 };
    }
    pub fn revalidate(self: *Record, signal: ?*core.process.SignalCancellation) !void {
        const digest = try copy.hashRetained(self.io, &self.file, self.limit, if (signal) |s| s.flag() else null);
        if (!std.mem.eql(u8, &digest, &self.sha256)) return error.RecordChanged;
    }
    pub fn read(self: *Record, a: std.mem.Allocator, signal: ?*core.process.SignalCancellation) !core.sensitive.Buffer {
        try self.revalidate(signal);
        var bytes = try files.readSensitiveFile(self.io, a, self.file.file, @intCast(self.limit), .private);
        errdefer bytes.deinit();
        try self.revalidate(signal);
        return bytes;
    }
    pub fn deinit(self: *Record) void {
        const path = self.file.path;
        self.file.close(self.io);
        self.allocator.free(path);
        self.* = undefined;
    }
};

/// One create-only attempt. The retained lock anchors the complete output
/// parent walk; neither uncertain publication nor late refusal is resumable.
pub const Transaction = struct {
    ctx: types.Context,
    path: []const u8,
    parent: files.FileParent,
    lock: files.Locked,
    anchor: files.RetainedFile,
    deadline: core.process.Deadline,
    attempted: bool = false,
    published: ?Record = null,
    publication: files.CommitStatus = .not_committed,
    failures: core.diagnostics.Failures = .{},

    pub fn init(ctx: types.Context, path: []const u8) !Transaction {
        try copy.checkCancellation(if (ctx.signal) |s| s.flag() else null);
        var deadline = try core.process.Deadline.afterMilliseconds(contracts.policy.operation_seconds * 1000);
        if (ctx.publication_deadline) |outer| deadline.expires_ns = @min(deadline.expires_ns, outer.expires_ns);
        const owned = try ctx.allocator.dupe(u8, path);
        errdefer ctx.allocator.free(owned);
        const parent = try files.FileParent.open(ctx.io, owned, .private);
        errdefer parent.close(ctx.io);
        const existing = parent.openFile(ctx.io) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |file| {
            file.close(ctx.io);
            return error.PathAlreadyExists;
        }
        var lock = try (files.Directory{ .dir = parent.directory }).lock(ctx.io);
        errdefer lock.close(ctx.io);
        const anchor_path = try std.fs.path.join(ctx.allocator, &.{ std.fs.path.dirname(owned).?, ".writer.lock" });
        errdefer ctx.allocator.free(anchor_path);
        var anchor = try files.RetainedFile.open(ctx.io, anchor_path, .private);
        errdefer anchor.close(ctx.io);
        if (!files.sameSnapshot(try files.snapshot(lock.file.?), anchor.file_snapshot)) return error.OutputParentChanged;
        return .{ .ctx = ctx, .path = owned, .parent = parent, .lock = lock, .anchor = anchor, .deadline = deadline };
    }
    pub fn revalidate(self: *Transaction, barrier: Barrier) !void {
        try copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
        try self.anchor.verify(self.ctx.io);
        try barrier.revalidate();
        if (self.published) |*record| try record.revalidate(self.ctx.signal);
        try self.anchor.verify(self.ctx.io);
        try copy.checkCancellation(if (self.ctx.signal) |s| s.flag() else null);
    }
    pub fn publish(self: *Transaction, bytes: []const u8, barrier: Barrier) types.Outcome(void) {
        return self.publishImpl(bytes, barrier, null);
    }
    pub fn publishFault(self: *Transaction, bytes: []const u8, barrier: Barrier, fault: files.TestFault) types.Outcome(void) {
        if (!@import("builtin").is_test) @compileError("Authority faults are test-only");
        return self.publishImpl(bytes, barrier, fault);
    }
    fn publishImpl(self: *Transaction, bytes: []const u8, barrier: Barrier, fault: ?files.TestFault) types.Outcome(void) {
        if (self.attempted) return .{ .poisoned = self.diagnostic(.publication, error.TransactionSpent) };
        self.attempted = true;
        if (self.failures.primary != null or self.failures.cleanup != null or self.failures.recording != null)
            return .{ .refused = self.diagnostic(.validation, error.PreviousFailure) };
        var document = contracts.parseCanonical(self.ctx.allocator, bytes) catch |err| return .{ .refused = self.diagnostic(.construction, err) };
        document.deinit();
        self.progressCheck(barrier) catch |err| return .{ .refused = self.diagnostic(.freshness, err) };
        const original = self.publishAtomic(bytes, barrier, fault) catch |err| return .{ .poisoned = self.diagnostic(.publication, err) };
        if (self.publication != .durable or self.failures.primary != null or self.failures.cleanup != null or self.failures.recording != null)
            return .{ .poisoned = self.diagnostic(.publication, error.PublicationUncertain) };
        self.published = Record.open(self.ctx, self.path, contracts.json_limits.bytes) catch |err| return .{ .poisoned = self.diagnostic(.final_revalidation, err) };
        var expected_snapshot = original;
        const published_snapshot = self.published.?.file.file_snapshot;
        expected_snapshot.size = published_snapshot.size;
        expected_snapshot.nlink = 1;
        expected_snapshot.mtime = published_snapshot.mtime;
        expected_snapshot.ctime = published_snapshot.ctime;
        if (!files.sameSnapshot(expected_snapshot, published_snapshot))
            return .{ .poisoned = self.diagnostic(.final_revalidation, error.FileChanged) };
        const expected = std.fmt.bytesToHex(hash(bytes), .lower);
        if (self.published.?.file.file_snapshot.size != bytes.len or !std.mem.eql(u8, &expected, &self.published.?.sha256))
            return .{ .poisoned = self.diagnostic(.final_revalidation, error.RecordChanged) };
        self.progressCheck(barrier) catch |err| return .{ .poisoned = self.diagnostic(.final_revalidation, err) };
        return .{ .success = {} };
    }
    fn progressCheck(self: *Transaction, barrier: Barrier) !void {
        try self.ctx.io.checkCancel();
        try self.revalidate(barrier);
        if (try self.deadline.expired()) return error.DeadlineExceeded;
    }
    fn publishAtomic(self: *Transaction, bytes: []const u8, barrier: Barrier, fault: ?files.TestFault) !files.Snapshot {
        if (self.lock.file == null) return error.LockNotHeld;
        if (self.parent.name[0] == '.') return error.InvalidState;
        var atomic = self.parent.directory.createFileAtomic(self.ctx.io, self.parent.name, .{
            .permissions = .fromMode(0o600),
            .replace = false,
        }) catch |err| {
            self.failures.recording = .{ .stage = .state_record, .category = .local_io };
            return err;
        };
        defer {
            // Explicit cleanup is the only deletion attempt. Failed or
            // ambiguous named evidence must survive Atomic.deinit.
            atomic.file_exists = false;
            atomic.deinit(self.ctx.io);
        }
        var failure: ?anyerror = null;
        const original: ?files.Snapshot = self.writeAndPublish(&atomic, bytes, barrier, fault) catch |err| blk: {
            self.failures.recording = .{ .stage = .state_record, .category = .local_io };
            failure = err;
            break :blk null;
        };
        if (atomic.file_exists) {
            if (fault == .cleanup) {
                self.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
            } else {
                if (!atomic.file_open) {
                    self.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                    return failure orelse error.InvalidState;
                }
                self.verifyAtomic(&atomic, files.snapshot(atomic.file) catch |err| {
                    self.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                    return failure orelse err;
                }) catch |err| {
                    self.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                    return failure orelse err;
                };
                self.parent.directory.deleteFile(self.ctx.io, &std.fmt.hex(atomic.file_basename_hex)) catch |err| {
                    self.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                    return failure orelse err;
                };
                atomic.file_exists = false;
                self.parent.sync(self.ctx.io) catch |err| {
                    self.failures.cleanup = .{ .stage = .state_record, .category = .cleanup_failed };
                    return failure orelse err;
                };
            }
        }
        if (failure) |err| return err;
        return original.?;
    }
    fn verifyAtomic(self: *Transaction, atomic: *std.Io.File.Atomic, expected: files.Snapshot) !void {
        if (!files.sameSnapshot(expected, try files.snapshot(atomic.file))) return error.FileChanged;
        if (atomic.file_exists) {
            const named = try (files.Directory{ .dir = atomic.dir }).openFile(self.ctx.io, &std.fmt.hex(atomic.file_basename_hex));
            defer named.close(self.ctx.io);
            if (!files.sameSnapshot(expected, try files.snapshot(named)) or
                !files.sameSnapshot(expected, try files.snapshot(atomic.file)))
                return error.FileChanged;
        }
    }
    fn writeAndPublish(self: *Transaction, atomic: *std.Io.File.Atomic, bytes: []const u8, barrier: Barrier, fault: ?files.TestFault) !files.Snapshot {
        const snapshot = try files.snapshot(atomic.file);
        if (snapshot.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or
            snapshot.mode & 0o7777 != 0o600 or snapshot.uid != std.os.linux.geteuid() or
            snapshot.nlink > 1 or snapshot.size != 0)
            return error.UnsafeFile;
        var retained = snapshot;
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.progressCheck(barrier);
            try self.verifyAtomic(atomic, retained);
            const chunk = bytes[offset..@min(bytes.len, offset + 64 * 1024)];
            const count = try atomic.file.writePositional(self.ctx.io, &.{chunk}, offset);
            if (count == 0) return error.WriteNoProgress;
            if (count > chunk.len) return error.InvalidWriteCount;
            offset += count;
            const written = try files.snapshot(atomic.file);
            var expected = retained;
            expected.size = offset;
            expected.mtime = written.mtime;
            expected.ctime = written.ctime;
            if (!files.sameSnapshot(expected, written)) return error.FileChanged;
            retained = written;
            try self.verifyAtomic(atomic, retained);
        }
        try self.progressCheck(barrier);
        try self.verifyAtomic(atomic, retained);
        if (fault == .before_file_sync or fault == .cleanup) return error.PublicationUncertain;
        try atomic.file.sync(self.ctx.io);
        try self.progressCheck(barrier);
        try self.verifyAtomic(atomic, retained);
        if (fault == .before_rename) return error.PublicationUncertain;
        self.publication = .publication_unknown;
        if (fault == .publication) return error.PublicationUncertain;
        atomic.link(self.ctx.io) catch |err| {
            if (err == error.PathAlreadyExists) self.publication = .not_committed;
            return err;
        };
        self.publication = .visible_not_durable;
        if (fault == .after_rename) return error.PublicationUncertain;
        try self.progressCheck(barrier);
        try self.parent.sync(self.ctx.io);
        self.publication = .durable;
        return snapshot;
    }
    fn diagnostic(self: *const Transaction, phase: types.Phase, err: anyerror) types.Diagnostic {
        return .{ .phase = phase, .err = err, .publication = self.publication, .failures = self.failures };
    }
    pub fn deinit(self: *Transaction) void {
        if (self.published) |*record| record.deinit();
        const anchor_path = self.anchor.path;
        self.anchor.close(self.ctx.io);
        self.ctx.allocator.free(anchor_path);
        self.lock.close(self.ctx.io);
        self.parent.close(self.ctx.io);
        self.ctx.allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    core.Sha256.hash(bytes, &digest, .{});
    return digest;
}
pub fn combineFailures(first: core.diagnostics.Failures, second: core.diagnostics.Failures) core.diagnostics.Failures {
    return .{
        .primary = first.primary orelse second.primary,
        .cleanup = first.cleanup orelse second.cleanup,
        .recording = first.recording orelse second.recording,
    };
}
pub const Supervised = struct {
    result: core.process.CommandResult,
    freshness: ?anyerror = null,
    pub fn succeeded(self: Supervised) bool {
        return self.result.succeeded() and self.freshness == null;
    }
    pub fn deinit(self: *Supervised, a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};

/// The caller supplies retained executable/cwd, empty or closed environment,
/// capture limits and independent deadlines; no PATH or shell discovery.
/// A post-run custody failure never erases the child's primary/cleanup result.
/// The executing owner must initialize the shared process subreaper first.
pub fn supervise(ctx: types.Context, request: core.process.CommandRequest, barrier: Barrier) !Supervised {
    try copy.checkCancellation(if (ctx.signal) |s| s.flag() else null);
    try barrier.revalidate();
    var bound = request;
    if (ctx.signal) |signal| {
        if (request.cancel != null and request.cancel != signal.flag()) return error.UnboundCancellation;
        bound.cancel = signal.flag();
    }
    var result = try core.process.runCommand(ctx.allocator, ctx.io, bound);
    errdefer result.deinit(ctx.allocator);
    barrier.revalidate() catch |err| return .{ .result = result, .freshness = err };
    copy.checkCancellation(if (ctx.signal) |s| s.flag() else null) catch |err| return .{ .result = result, .freshness = err };
    return .{ .result = result };
}
