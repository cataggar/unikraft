const std = @import("std");
const c = @import("contracts.zig");
const package = @import("package.zig");

pub const request_name = "import-request.json";
pub const inspection_name = "inspection.json";
pub const receipt_name = "import-receipt.json";
pub const image_name = "unikraft.vhd";
pub const input_names = [_][]const u8{ @import("manifest.zig").name, image_name };
pub const output_names = input_names ++ [_][]const u8{ ".writer.lock", request_name, inspection_name, receipt_name };

/// These must come from the caller's independently trusted channel, never from
/// reading the artifact or receipt. Ordinary structs confer no authority.
pub const Expectations = struct {
    manifest_sha256: []const u8,
    native_producer_sha256: []const u8,
    source: c.Source,
    pub fn validate(self: Expectations) !void {
        _ = try c.sha(self.manifest_sha256);
        _ = try c.sha(self.native_producer_sha256);
        try self.source.validate();
    }
};
pub const Producer = struct { executable: package.Digest, miz_revision: []const u8 = c.miz_revision };
pub const SourceProducer = struct { sha256: []const u8, controller_revision: u8 = 4, miz_revision: []const u8 = c.miz_revision };
pub const DirectoryIdentity = struct { device_major: u32, device_minor: u32, inode: u64, uid: u32, mode: u16 };
pub const FileIdentity = struct {
    digest: package.Digest,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    uid: u32,
    mode: u16,
    links: u32,
    modified_seconds: i64,
    modified_nanoseconds: u32,
    changed_seconds: i64,
    changed_nanoseconds: u32,
};
pub const Request = struct {
    schema: []const u8 = "unikraft.hyperv.public-import-request",
    schema_version: u8 = 1,
    phase: enum { importing } = .importing,
    authority: enum { not_admitted } = .not_admitted,
    expectations: Expectations,
    importer: Producer,
    directory: DirectoryIdentity,
};
pub const Receipt = struct {
    schema: []const u8 = "unikraft.hyperv.public-import",
    schema_version: u8 = 1,
    phase: enum { imported } = .imported,
    scope: enum { local_only } = .local_only,
    authority: enum { not_admitted } = .not_admitted,
    attestation: enum { not_verified } = .not_verified,
    boot_claim_origin: enum { source_manifest } = .source_manifest,
    expectations: Expectations,
    importer: Producer,
    source_producer: SourceProducer,
    directory: DirectoryIdentity,
    writer_lock: FileIdentity,
    request: FileIdentity,
    manifest: FileIdentity,
    image: FileIdentity,
    inspection: FileIdentity,
    packaging: package.Packaging,
    acceptance: std.json.Value,
    source_boot_claims: std.json.Value,
};
pub const Result = struct {
    destination: c.core.private_files.CommitStatus = .not_committed,
    publication: c.core.private_files.CommitStatus = .not_committed,
    receipt_sha256: ?c.Hash = null,
    failures: c.core.diagnostics.Failures = .{},

    pub fn succeeded(self: Result) bool {
        return self.destination == .durable and self.publication == .durable and self.receipt_sha256 != null and
            self.failures.primary == null and self.failures.cleanup == null and self.failures.recording == null;
    }
    pub fn deliveryFailed(self: Result) Result {
        var failed = self;
        failed.receipt_sha256 = null;
        failed.failures.recording = failed.failures.recording orelse .{ .stage = .state_record, .category = .local_io };
        return failed;
    }
    pub fn encode(self: Result, a: std.mem.Allocator) ![]u8 {
        return c.encode(a, .{
            .schema_version = @as(u8, 1),
            .scope = "public_local_import_only",
            .authority = "not_admitted",
            .attestation = "not_verified",
            .succeeded = self.succeeded(),
            .destination = self.destination,
            .publication = self.publication,
            .receipt_sha256 = if (self.receipt_sha256) |sha| try c.hex(a, sha) else null,
            .failures = self.failures,
        });
    }
};
