const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const f = @import("files.zig");
const fs = @import("import_files.zig");
const ic = @import("import_contracts.zig");
const m = @import("manifest.zig");
const package = @import("package.zig");
const p = c.core.private_files;
pub const Expectations = ic.Expectations;
pub const Receipt = ic.Receipt;
pub const Result = ic.Result;

const Input = struct {
    path: []const u8,
    directory: std.Io.Dir,
    before: p.Snapshot,
    manifest_file: fs.Held,
    image_file: fs.Held,
    manifest: m.Manifest,
    inspection: package.Inspection,

    fn open(a: std.mem.Allocator, io: std.Io, path: []const u8, expected: Expectations) !Input {
        try expected.validate();
        try p.absoluteFilePath(path);
        const dir = try p.openDirectory(io, path, .artifact);
        errdefer dir.close(io);
        const before = try p.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
        try fs.exactFiles(io, dir, &ic.input_names);
        const manifest_file = try fs.Held.open(io, dir, m.name, c.max_record, .artifact);
        errdefer manifest_file.close(io);
        if (!std.mem.eql(u8, &manifest_file.artifact.pin.sha256, &try c.sha(expected.manifest_sha256))) return error.HashMismatch;
        const manifest = try m.validate(a, try manifest_file.read(a, io, c.max_record), expected.source, try c.sha(expected.native_producer_sha256));
        const image_file = try fs.Held.open(io, dir, ic.image_name, c.vhd_bytes, .artifact);
        errdefer image_file.close(io);
        const inspection = try inspect(a, io, image_file, manifest);
        const input: Input = .{ .path = path, .directory = dir, .before = before, .manifest_file = manifest_file, .image_file = image_file, .manifest = manifest, .inspection = inspection };
        try input.verify(io);
        return input;
    }
    fn verify(self: Input, io: std.Io) !void {
        try self.manifest_file.verify(io, self.directory, m.name, .artifact);
        try self.image_file.verify(io, self.directory, ic.image_name, .artifact);
        try fs.exactFiles(io, self.directory, &ic.input_names);
        const current = try p.openDirectory(io, self.path, .artifact);
        defer current.close(io);
        if (!p.sameSnapshot(self.before, try p.snapshot(.{ .handle = current.handle, .flags = .{ .nonblocking = false } })))
            return error.ArtifactChanged;
    }
    fn close(self: Input, io: std.Io) void {
        self.image_file.close(io);
        self.manifest_file.close(io);
        self.directory.close(io);
    }
};

fn inspect(a: std.mem.Allocator, io: std.Io, image: fs.Held, manifest: m.Manifest) !package.Inspection {
    const inspection = try package.inspectVhd(a, io, image.artifact.file, .{
        .efi = try c.sha(manifest.artifacts.efi.sha256),
        .raw = try c.sha(manifest.artifacts.raw.sha256),
        .vhd = try c.sha(manifest.artifacts.vhd.sha256),
    });
    try f.same(a, manifest.packaging, inspection.packaging);
    return inspection;
}
fn clean(failures: c.core.diagnostics.Failures) bool {
    return failures.primary == null and failures.cleanup == null and failures.recording == null;
}
fn merge(to: *c.core.diagnostics.Failures, from: c.core.diagnostics.Failures) void {
    if (to.primary == null) to.primary = from.primary;
    if (to.cleanup == null) to.cleanup = from.cleanup;
    if (to.recording == null) to.recording = from.recording;
}
fn category(err: anyerror) c.core.diagnostics.Category {
    return switch (err) {
        error.PathAlreadyExists => .conflict,
        error.WouldBlock => .contention,
        error.FileNotFound => .not_found,
        error.UnsafeFile, error.UnsafePath, error.OutputInsideArtifact, error.InvalidArtifactShape => .unsafe_file,
        error.HashMismatch, error.ArtifactChanged, error.PayloadMismatch => .integrity,
        error.NoSpaceLeft, error.DiskQuota, error.InputOutput, error.AccessDenied, error.ReadFailed, error.WriteFailed, error.FileTooBig, error.Unexpected => .local_io,
        else => .invalid_response,
    };
}

/// A synchronous local filesystem leaf, with no process/network execution.
/// The caller must acquire the three expectations through an independent trust
/// channel. Files and partial outcomes are retained; a destination is never reused.
pub fn importPrepared(a: std.mem.Allocator, io: std.Io, artifact_dir: []const u8, destination: []const u8, expected: Expectations) Result {
    return importImpl(a, io, artifact_dir, destination, expected, null);
}

// Same compile-time-only fault boundary as core.private_files.commitFault.
pub const TestFault = enum {
    destination_creation,
    destination_sync,
    request,
    inspection,
    receipt_before_sync,
    receipt_publication,
    receipt_after_rename,
    receipt_cleanup,
    input_changed_after_copy,
    copied_manifest,
    inspection_record,
    request_after_receipt,
    receipt_record,
};
pub fn importFault(a: std.mem.Allocator, io: std.Io, artifact_dir: []const u8, destination: []const u8, expected: Expectations, fault: TestFault) Result {
    if (!builtin.is_test) @compileError("Import faults are available only to native tests");
    return importImpl(a, io, artifact_dir, destination, expected, fault);
}

fn importImpl(a: std.mem.Allocator, io: std.Io, artifact_dir: []const u8, destination: []const u8, expected: Expectations, fault: ?TestFault) Result {
    var result: Result = .{};
    var stage: c.core.diagnostics.Stage = .contract;
    perform(a, io, artifact_dir, destination, expected, fault, &result, &stage) catch |err| {
        if (clean(result.failures)) result.failures.primary = .{ .stage = stage, .category = category(err) };
    };
    if (!result.succeeded()) result.receipt_sha256 = null;
    return result;
}

fn perform(a: std.mem.Allocator, io: std.Io, artifact_dir: []const u8, destination: []const u8, expected: Expectations, fault: ?TestFault, result: *Result, stage: *c.core.diagnostics.Stage) !void {
    try expected.validate();
    try p.absoluteFilePath(destination);
    stage.* = .private_file;
    const self = try fs.Self.open(a, io);
    defer self.close(io);
    stage.* = .inspection;
    const input = try Input.open(a, io, artifact_dir, expected);
    defer input.close(io);
    const parent = try p.FileParent.open(io, destination, .artifact);
    defer parent.close(io);
    stage.* = .private_file;
    try fs.requireOutside(io, parent.directory, input.directory);
    parent.directory.createDir(io, parent.name, .fromMode(0o700)) catch |err| {
        result.destination = if (err == error.PathAlreadyExists) .not_committed else .publication_unknown;
        return err;
    };
    if (fault == .destination_creation) {
        result.destination = .publication_unknown;
        result.failures.primary = .{ .stage = .private_file, .category = .local_io };
        return;
    }
    result.destination = .visible_not_durable;
    if (fault == .destination_sync) {
        result.failures.recording = .{ .stage = .state_record, .category = .local_io };
        return;
    }
    parent.sync(io) catch {
        result.failures.recording = .{ .stage = .state_record, .category = .local_io };
        return;
    };
    result.destination = .durable;
    const root = try p.Directory.open(io, destination);
    defer root.close(io);
    var lock = root.lock(io) catch |err| {
        result.failures.recording = .{ .stage = .lock, .category = category(err) };
        return err;
    };
    defer lock.close(io);
    try fs.exactFiles(io, root.dir, &.{".writer.lock"});
    const importer = try self.producer(a);
    const request: ic.Request = .{ .expectations = expected, .importer = importer, .directory = try fs.directoryIdentity(root.dir) };
    try record(a, io, &lock, ic.request_name, request, if (fault == .request) .before_file_sync else null, result, false);
    try c.boot.files.copy(io, input.manifest_file.artifact, root.dir, m.name);
    try c.boot.files.copy(io, input.image_file.artifact, root.dir, ic.image_name);
    if (fault == .input_changed_after_copy) {
        if (!builtin.is_test) return error.InvalidFault;
        const changed = try input.directory.openFile(io, ic.image_name, .{ .mode = .read_write });
        defer changed.close(io);
        try changed.writePositionalAll(io, "synthetic input mutation", 1024);
    }
    const copied = try fs.Held.open(io, root.dir, ic.image_name, c.vhd_bytes, .private);
    defer copied.close(io);
    stage.* = .inspection;
    const inspection = try inspect(a, io, copied, input.manifest);
    try f.same(a, input.inspection, inspection);
    try input.verify(io);
    try copied.verify(io, root.dir, ic.image_name, .private);
    try self.verify(io);
    try record(a, io, &lock, ic.inspection_name, inspection, if (fault == .inspection) .cleanup else null, result, false);
    if (fault == .copied_manifest) try alterFixture(io, root.dir, m.name);
    if (fault == .inspection_record) try alterFixture(io, root.dir, ic.inspection_name);
    const receipt = try makeReceipt(a, io, &lock, request, input.manifest, inspection);
    try fs.exactFiles(io, root.dir, &.{ ".writer.lock", ic.request_name, m.name, ic.image_name, ic.inspection_name });
    try input.verify(io);
    try copied.verify(io, root.dir, ic.image_name, .private);
    try self.verify(io);
    const receipt_fault: ?p.TestFault = switch (fault orelse .destination_sync) {
        .receipt_before_sync => .before_file_sync,
        .receipt_publication => .publication,
        .receipt_after_rename => .after_rename,
        .receipt_cleanup => .cleanup,
        else => null,
    };
    // The receipt is the only publication point; failed/partial directories
    // retain their original stable lock and can never be silently adopted.
    try record(a, io, &lock, ic.receipt_name, receipt, receipt_fault, result, true);
    if (fault == .request_after_receipt) try alterFixture(io, root.dir, ic.request_name);
    if (fault == .receipt_record) try alterFixture(io, root.dir, ic.receipt_name);
    const published = try fs.Held.open(io, root.dir, ic.receipt_name, c.max_record, .private);
    defer published.close(io);
    if (!std.mem.eql(u8, &published.artifact.pin.sha256, &result.receipt_sha256.?)) return error.ArtifactChanged;
    try f.same(a, receipt, try makeReceipt(a, io, &lock, request, input.manifest, inspection));
    try fs.exactFiles(io, root.dir, &ic.output_names);
    const named_root = try p.Directory.open(io, destination);
    defer named_root.close(io);
    try f.same(a, request.directory, try fs.directoryIdentity(named_root.dir));
    try input.verify(io);
    try copied.verify(io, root.dir, ic.image_name, .private);
    try published.verify(io, root.dir, ic.receipt_name, .private);
    try self.verify(io);
}

fn alterFixture(io: std.Io, directory: std.Io.Dir, name: []const u8) !void {
    if (!builtin.is_test) return error.InvalidFault;
    const file = try directory.openFile(io, name, .{ .mode = .read_write });
    defer file.close(io);
    try file.writePositionalAll(io, "synthetic mutation", 0);
}

fn record(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, name: []const u8, value: anytype, fault: ?p.TestFault, result: *Result, receipt: bool) !void {
    const bytes = c.encode(a, value) catch |err| {
        result.failures.recording = .{ .stage = .state_record, .category = .local_io };
        return err;
    };
    defer a.free(bytes);
    const committed = if (builtin.is_test and fault != null) try lock.commitFault(io, name, bytes, fault.?) else lock.createImmutable(io, name, bytes) catch |err| {
        result.failures.recording = .{ .stage = .state_record, .category = .local_io };
        return err;
    };
    merge(&result.failures, committed.failures);
    if (receipt) result.publication = committed.status;
    if (committed.status != .durable or !clean(committed.failures)) return error.RecordingFailed;
    if (receipt) result.receipt_sha256 = c.hash(bytes);
}

fn makeReceipt(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, request: ic.Request, manifest: m.Manifest, inspection: package.Inspection) !Receipt {
    const root = lock.directory;
    const receipt: Receipt = .{
        .expectations = request.expectations,
        .importer = request.importer,
        .source_producer = .{ .sha256 = manifest.controller_sha256, .controller_revision = manifest.controller_revision, .miz_revision = manifest.artifacts.miz.revision },
        .directory = request.directory,
        .writer_lock = try fs.lockIdentity(a, io, lock),
        .request = try fs.fileIdentity(a, io, root, ic.request_name, c.max_record),
        .manifest = try fs.fileIdentity(a, io, root, m.name, c.max_record),
        .image = try fs.fileIdentity(a, io, root, ic.image_name, c.vhd_bytes),
        .inspection = try fs.fileIdentity(a, io, root, ic.inspection_name, c.max_record),
        .packaging = inspection.packaging,
        .acceptance = manifest.acceptance,
        .source_boot_claims = manifest.preflight,
    };
    try matchRecord(a, receipt.request.digest, request);
    try matchRecord(a, receipt.manifest.digest, manifest);
    try matchRecord(a, receipt.inspection.digest, inspection);
    try f.same(a, inspection.vhd, receipt.image.digest);
    return receipt;
}

fn matchRecord(a: std.mem.Allocator, actual: package.Digest, value: anytype) !void {
    const bytes = try c.encode(a, value);
    defer a.free(bytes);
    if (actual.size != bytes.len or !std.mem.eql(u8, actual.sha256, &std.fmt.bytesToHex(c.hash(bytes), .lower)))
        return error.ArtifactChanged;
}

/// Re-read the original private namespace against independently retained
/// expectations AND the receipt digest returned by a successful durable import.
/// No value is read from the receipt as a substitute for those caller inputs.
pub fn load(a: std.mem.Allocator, io: std.Io, destination: []const u8, expected: Expectations, expected_receipt_sha256: c.Hash) !Receipt {
    try expected.validate();
    const self = try fs.Self.open(a, io);
    defer self.close(io);
    const root = try p.Directory.open(io, destination);
    defer root.close(io);
    try fs.exactFiles(io, root.dir, &ic.output_names);
    var lock = try root.lock(io);
    defer lock.close(io);
    const receipt_file = try fs.Held.open(io, root.dir, ic.receipt_name, c.max_record, .private);
    defer receipt_file.close(io);
    if (!std.mem.eql(u8, &receipt_file.artifact.pin.sha256, &expected_receipt_sha256)) return error.HashMismatch;
    const receipt = try c.read(Receipt, a, try receipt_file.read(a, io, c.max_record));
    const request: ic.Request = .{ .expectations = expected, .importer = try self.producer(a), .directory = try fs.directoryIdentity(root.dir) };
    try f.same(a, expected, receipt.expectations);
    try f.same(a, request, try c.read(ic.Request, a, try root.read(io, a, ic.request_name, c.max_record, null)));
    const manifest_file = try fs.Held.open(io, root.dir, m.name, c.max_record, .private);
    defer manifest_file.close(io);
    if (!std.mem.eql(u8, &manifest_file.artifact.pin.sha256, &try c.sha(expected.manifest_sha256))) return error.HashMismatch;
    const manifest = try m.validate(a, try manifest_file.read(a, io, c.max_record), expected.source, try c.sha(expected.native_producer_sha256));
    const image = try fs.Held.open(io, root.dir, ic.image_name, c.vhd_bytes, .private);
    defer image.close(io);
    const inspection = try inspect(a, io, image, manifest);
    try f.same(a, inspection, try c.read(package.Inspection, a, try root.read(io, a, ic.inspection_name, c.max_record, null)));
    try f.same(a, try makeReceipt(a, io, &lock, request, manifest, inspection), receipt);
    try manifest_file.verify(io, root.dir, m.name, .private);
    try image.verify(io, root.dir, ic.image_name, .private);
    try receipt_file.verify(io, root.dir, ic.receipt_name, .private);
    try fs.exactFiles(io, root.dir, &ic.output_names);
    const named_root = try p.Directory.open(io, destination);
    defer named_root.close(io);
    try f.same(a, receipt.directory, try fs.directoryIdentity(named_root.dir));
    try self.verify(io);
    return receipt;
}
