const std = @import("std");
pub const core = @import("hyperv_core");
pub const Hash = [32]u8;
pub const Uuid = [36]u8;
pub const max_record = 16 * 1024;
pub const output_limit = 64 * 1024;
pub const overhead = 4 * max_record + 2 * output_limit;
pub const max_control = 2097152;
pub const max_staging = 268435456;
pub const Operation = enum { preflight, persistence, cleanup };
pub const Kind = enum { production, synthetic };
pub const Namespace = struct { device_major: u32, device_minor: u32, inode: u64 };
pub const Identity = struct { pid: i32, start_ticks: u64, namespace: Namespace };
pub const Directory = struct { device_major: u32, device_minor: u32, inode: u64 };
pub const Expected = struct {
    kind: Kind,
    operation: Operation,
    attempt: Uuid,
    run: Uuid,
    context: Hash,
    implementation: Hash,
    public_key: [32]u8,

    pub fn validate(self: Expected) !void {
        _ = try core.contracts.parseUuid(&self.attempt);
        _ = try core.contracts.parseUuid(&self.run);
        if (std.mem.allEqual(u8, &self.context, 0) or std.mem.allEqual(u8, &self.implementation, 0) or
            std.mem.allEqual(u8, &self.public_key, 0)) return error.InvalidBinding;
    }
};
pub const Registration = struct {
    schema: []const u8,
    expected: Expected,
    nonce: Hash,
    boot: Uuid,
    owner: Identity,
    custodian: Identity,
    namespace_init: Identity,
    directory: Directory,
    worker_directory: Directory,
    deadline_ns: u64,
    registered_ns: u64,
    cleanup_ms: u32,
    control_reserved: u64,
};
pub const Cause = enum { completed, worker_failed, owner_died, cancelled, deadline, output_limit, initializer_failed };
pub const Seal = struct {
    schema: []const u8,
    registration: Hash,
    witness: enum { pid_namespace_init_reaped },
    cause: Cause,
    init_status: u32,
    worker_status: ?u32,
    stopped_ns: u64,
    failures: core.diagnostics.Failures,
};
pub const Proof = struct {
    registration: Hash,
    seal: Hash,
    expected: Expected,
    boot: Uuid,
    namespace_init: Identity,
    cause: Cause,
    failures: core.diagnostics.Failures,
};
pub const Signer = struct {
    seed: [32]u8,
    public_key: [32]u8,
    pub fn fromSeed(seed: [32]u8, expected: [32]u8) !Signer {
        var pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        if (!std.crypto.timing_safe.eql([32]u8, pair.public_key.toBytes(), expected)) return error.SigningKeyMismatch;
        return .{ .seed = seed, .public_key = expected };
    }
    pub fn load(a: std.mem.Allocator, io: std.Io, path: []const u8, expected: [32]u8) !Signer {
        var bytes = try core.private_files.readSensitiveAbsolute(io, a, path, 32, null);
        defer bytes.deinit();
        if (bytes.bytes().len != 32) return error.InvalidSigningKey;
        return fromSeed(bytes.bytes()[0..32].*, expected);
    }
    pub fn deinit(self: *Signer) void {
        std.crypto.secureZero(u8, &self.seed);
    }
    pub fn sign(self: *const Signer, a: std.mem.Allocator, value: anytype, domain: []const u8) ![]u8 {
        const body = try canonical(a, value);
        defer a.free(body);
        const message = try std.mem.concat(a, u8, &.{ domain, "\n", body });
        defer a.free(message);
        var pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.seed);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        const signature = try pair.sign(message, null);
        return canonical(a, .{ .body = value, .signature = signature.toBytes() });
    }
};
pub fn canonical(a: std.mem.Allocator, value: anytype) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(bytes);
    var doc = try core.contracts.Document.parse(a, bytes, .{ .bytes = max_record, .items = 1024 });
    defer doc.deinit();
    return doc.canonicalAlloc(a);
}
pub fn parse(comptime T: type, a: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    var doc = try core.contracts.Document.parse(a, bytes, .{ .bytes = max_record, .items = 1024 });
    defer doc.deinit();
    try doc.requireCanonical(a, bytes);
    return std.json.parseFromSlice(T, a, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
}
pub fn verify(comptime T: type, a: std.mem.Allocator, bytes: []const u8, key: [32]u8, domain: []const u8) !std.json.Parsed(T) {
    const Envelope = struct { body: T, signature: [64]u8 };
    const parsed = try parse(Envelope, a, bytes);
    defer parsed.deinit();
    const body = try canonical(a, parsed.value.body);
    defer a.free(body);
    var document = try core.contracts.Document.parse(a, bytes, .{ .bytes = max_record, .items = 1024 });
    defer document.deinit();
    const original = try canonical(a, document.value().object.get("body").?);
    defer a.free(original);
    if (!std.mem.eql(u8, body, original)) return error.IncompleteSignedBody;
    const message = try std.mem.concat(a, u8, &.{ domain, "\n", body });
    defer a.free(message);
    try std.crypto.sign.Ed25519.Signature.fromBytes(parsed.value.signature).verify(message, try std.crypto.sign.Ed25519.PublicKey.fromBytes(key));
    return parse(T, a, body);
}
pub fn hash(bytes: []const u8) Hash {
    var digest: Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
pub fn durable(result: core.private_files.CommitResult) !void {
    if (result.status != .durable or result.failures.primary != null or result.failures.cleanup != null or result.failures.recording != null)
        return error.RecordingFailed;
}
