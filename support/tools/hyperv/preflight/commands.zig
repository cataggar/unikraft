const std = @import("std");
const core = @import("hyperv_core");
const c = @import("contract.zig");
const p = c.p;

pub const Signer = struct {
    pair: p.Ed25519.KeyPair,

    pub fn load(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, name: []const u8, expected: [32]u8) !Signer {
        var bytes = try directory.readSensitive(io, allocator, name, 32, null);
        defer bytes.deinit();
        if (bytes.bytes().len != 32) return error.InvalidSigningKey;
        return fromSeed(bytes.bytes()[0..32].*, expected);
    }
    pub fn fromSeed(seed: [32]u8, expected: [32]u8) !Signer {
        var pair = try p.Ed25519.KeyPair.generateDeterministic(seed);
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        if (!std.crypto.timing_safe.eql([32]u8, pair.public_key.toBytes(), expected)) return error.SigningAuthorityMismatch;
        return .{ .pair = pair };
    }
    pub fn deinit(self: *Signer) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    fn sign(self: *const Signer, allocator: std.mem.Allocator, body: anytype, domain: []const u8) ![]u8 {
        const canonical = try c.canonical(allocator, body);
        defer allocator.free(canonical);
        const message = try std.mem.concat(allocator, u8, &.{ domain, "\n", canonical });
        defer allocator.free(message);
        const signature = try self.pair.sign(message, null);
        const envelope = try c.canonical(allocator, .{ .body = body, .signature = @as([]const u8, &p.hex(signature.toBytes())) });
        errdefer allocator.free(envelope);
        var verified = try p.verify(allocator, envelope, self.pair.public_key.toBytes(), domain);
        verified.deinit();
        return envelope;
    }

    pub fn command(self: *const Signer, allocator: std.mem.Allocator, input: *const c.Input, admission: *const p.Admission, phase: p.Phase, vm: c.Uuid, nonce: c.Uuid, now: u64, acceptance_bytes: ?[]const u8) ![]u8 {
        const manifest = if (phase == .public) input.preparation.public else input.preparation.private;
        var document = try core.contracts.Document.parse(allocator, manifest.bytes, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
        defer document.deinit();
        var accepted: ?core.contracts.Document = null;
        defer if (accepted) |*value| value.deinit();
        if (acceptance_bytes) |bytes| accepted = try core.contracts.Document.parse(allocator, bytes, .{});
        const bytes = try self.sign(allocator, .{
            .schema = "uk-hyperv-host-command-v1",
            .run_id = @as([]const u8, &input.approved.authority.owner_run),
            .vm_id = @as([]const u8, &vm),
            .phase_nonce = @as([]const u8, &nonce),
            .phase = phase,
            .issued_at = now,
            .expires_at = input.approved.expires_at,
            .manifest_sha256 = @as([]const u8, &p.hex(manifest.sha256)),
            .runner_sha256 = @as([]const u8, &p.hex(admission.runner_sha256)),
            .image_sha256 = @as([]const u8, &p.hex(manifest.image_sha256)),
            .manifest = document.value(),
            .acceptance = if (accepted) |value| value.value() else @as(std.json.Value, .null),
        }, "uk-hyperv-host-command-v1");
        errdefer allocator.free(bytes);
        var parsed = try p.Command.parse(allocator, bytes, input.approved.public_key, admission, try input.scope(admission), try core.contracts.parseUuid(&vm), now);
        defer parsed.deinit();
        try matchArtifacts(input, &parsed);
        return bytes;
    }

    pub fn acceptance(self: *const Signer, allocator: std.mem.Allocator, input: *const c.Input, public: *const p.Command, receipt: p.Hash, boot: c.Uuid, now: u64) ![]u8 {
        return self.sign(allocator, .{
            .schema = "uk-hyperv-public-acceptance-v1",
            .run_id = @as([]const u8, &input.approved.authority.owner_run),
            .vm_id = @as([]const u8, &p.uuidText(public.vm_id)),
            .phase_nonce = @as([]const u8, &p.uuidText(public.phase_nonce)),
            .public_command_sha256 = @as([]const u8, &p.hex(public.verified.digest)),
            .public_evidence_sha256 = @as([]const u8, &p.hex(receipt)),
            .host_boot_id = @as([]const u8, &boot),
            .issued_at = now,
            .expires_at = input.approved.expires_at,
        }, "uk-hyperv-public-acceptance-v1");
    }

    pub fn completion(self: *const Signer, allocator: std.mem.Allocator, value: anytype) ![]u8 {
        return self.sign(allocator, value, "uk-hyperv-preflight-completion-v1");
    }
};

pub fn matchArtifacts(input: *const c.Input, command: *const p.Command) !void {
    var matched: usize = 0;
    for (command.artifacts) |record| {
        var found = false;
        for (input.preparation.files) |file| {
            if (!std.mem.eql(u8, file.artifact.name, record.name)) continue;
            if (file.artifact.role != record.role or file.artifact.size != record.size or
                !std.mem.eql(u8, &file.artifact.sha256, &record.sha256)) return error.PreparationMismatch;
            found = true;
        }
        if (!found) return error.PreparationMismatch;
        matched += 1;
    }
    var expected: usize = 0;
    for (input.preparation.files) |file| if (file.phase == command.phase or
        (command.phase == .private and file.phase == .public and file.artifact.role != .capability_raw))
    {
        expected += 1;
    };
    if (matched != expected) return error.PreparationMismatch;
}
