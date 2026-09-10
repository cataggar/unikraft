const std = @import("std");
const c = @import("hyperv_core").contracts;

pub const max_control = 2 * 1024 * 1024;
pub const max_staging = 256 * 1024 * 1024;
pub const max_command = 64 * 1024;
pub const max_locator = 4096;
pub const max_record = 4096;
pub const emergency_control = 4096;
pub const startup_control = 8192;
pub const attempt_marker_bytes = 36;
pub const service_unit_bytes = @embedFile("uk-hyperv-host.service").len;
pub const max_artifact = 128 * 1024 * 1024;
pub const max_serial = 1024 * 1024;
pub const max_evidence = 8 * 1024 * 1024;
pub const attempt_ms = 60 * 60 * 1000;
pub const cleanup_ms = 120 * 1000;
pub const boot_ms = 120 * 1000;
pub const Hash = c.Sha256;
pub const Uuid = c.Uuid;
pub const Ed25519 = std.crypto.sign.Ed25519;
pub const Phase = enum { public, private };
pub const Role = enum { qemu, ovmf_code, ovmf_vars, capability_raw, raw, vhd, support };
pub const Policy = enum { platform_unavailable, platform_main_zero, guarded_v2 };

pub fn controlTotal(parts: []const u64) !u64 {
    var total: u64 = 0;
    for (parts) |size| {
        if (size > max_control - total) return error.ControlAllowanceExceeded;
        total += size;
    }
    return total;
}

pub fn startupControlBytes(admission_bytes: u64, locator_bytes: u64) !u64 {
    if (admission_bytes > max_command or locator_bytes > max_locator) return error.InvalidBudget;
    // Both startup ledger writes may occupy their full bounded record size.
    return controlTotal(&.{ admission_bytes, locator_bytes, startup_control, emergency_control, 2 * max_record });
}

pub const Scope = struct {
    account: []const u8,
    container: []const u8,
    run_id: Uuid,

    pub fn validate(self: Scope) !void {
        if (self.account.len < 3 or self.account.len > 24) return error.InvalidEndpoint;
        for (self.account) |ch| if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch)) return error.InvalidEndpoint;
        if (self.container.len < 3 or self.container.len > 63 or self.container[0] == '-' or self.container[self.container.len - 1] == '-') return error.InvalidEndpoint;
        var hyphen = false;
        for (self.container) |ch| {
            if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '-') return error.InvalidEndpoint;
            if (ch == '-' and hyphen) return error.InvalidEndpoint;
            hyphen = ch == '-';
        }
        try validUuid(self.run_id);
    }

    pub fn same(a: Scope, b: Scope) bool {
        return std.mem.eql(u8, a.account, b.account) and std.mem.eql(u8, a.container, b.container) and std.mem.eql(u8, &a.run_id, &b.run_id);
    }
};

pub const Verified = struct {
    allocator: std.mem.Allocator,
    document: c.Document,
    body: std.json.Value,
    canonical: []u8,
    digest: Hash,

    pub fn deinit(self: *Verified) void {
        self.allocator.free(self.canonical);
        self.document.deinit();
    }
};

pub fn hash(bytes: []const u8) Hash {
    var result: Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub fn hex(bytes: anytype) [bytes.len * 2]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

pub fn uuidText(bytes: Uuid) [36]u8 {
    const h = hex(bytes);
    var result: [36]u8 = undefined;
    _ = std.fmt.bufPrint(&result, "{s}-{s}-{s}-{s}-{s}", .{ h[0..8], h[8..12], h[12..16], h[16..20], h[20..32] }) catch unreachable;
    return result;
}

pub fn validUuid(bytes: Uuid) !void {
    const version = bytes[6] >> 4;
    if (version < 1 or version > 5 or bytes[8] >> 6 != 2) return error.InvalidUuid;
}

fn uuid(value: std.json.Value) !Uuid {
    const result = try c.parseUuid(try c.string(value));
    try validUuid(result);
    return result;
}

pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidContract;
    return value.object.get(name) orelse error.InvalidContract;
}

fn sha(value: std.json.Value) !Hash {
    return c.parseSha256(try c.string(value));
}

pub fn canonical(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    const json = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(json);
    var doc = try c.Document.parse(allocator, json, .{ .bytes = max_command, .items = 2048, .tokens = 16384 });
    defer doc.deinit();
    return doc.canonicalAlloc(allocator);
}

pub fn verify(allocator: std.mem.Allocator, bytes: []const u8, key: [32]u8, domain: []const u8) !Verified {
    var doc = try c.Document.parse(allocator, bytes, .{ .bytes = max_command, .items = 2048, .tokens = 16384 });
    errdefer doc.deinit();
    _ = try c.exactFields(doc.value(), &.{ "body", "signature" });
    const signature_hex = try c.string(try field(doc.value(), "signature"));
    if (signature_hex.len != 128) return error.InvalidSignature;
    var signature: [64]u8 = undefined;
    for (signature_hex) |ch| if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) return error.InvalidSignature;
    _ = std.fmt.hexToBytes(&signature, signature_hex) catch return error.InvalidSignature;
    const body = try field(doc.value(), "body");
    if (body != .object) return error.InvalidContract;
    const canonical_body = try canonical(allocator, body);
    errdefer allocator.free(canonical_body);
    const message = try std.mem.concat(allocator, u8, &.{ domain, "\n", canonical_body });
    defer allocator.free(message);
    const public_key = Ed25519.PublicKey.fromBytes(key) catch return error.InvalidSignature;
    Ed25519.Signature.fromBytes(signature).verify(message, public_key) catch return error.InvalidSignature;
    return .{ .allocator = allocator, .document = doc, .body = body, .canonical = canonical_body, .digest = hash(bytes) };
}

fn schema(value: std.json.Value, expected: []const u8) !void {
    if (!std.mem.eql(u8, try c.string(try field(value, "schema")), expected)) return error.InvalidContract;
}

fn expiry(value: std.json.Value, now: u64) !u64 {
    const issued = try c.integer(u64, try field(value, "issued_at"));
    const expires = try c.integer(u64, try field(value, "expires_at"));
    if (issued > now or expires <= now or expires <= issued or expires - issued > 3600) return error.StaleCommand;
    return expires;
}

pub const Admission = struct {
    verified: Verified,
    account: []const u8,
    container: []const u8,
    runner_sha256: Hash,
    host_image_sha256: Hash,
    guarded_producer_sha256: Hash,
    image_staging_bytes: u64,
    image_control_bytes: u64,
    expires_at: u64,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8, key: [32]u8, now: u64, runner: Hash, runner_size: u64) !Admission {
        var verified = try verify(allocator, bytes, key, "uk-hyperv-image-admission-v1");
        errdefer verified.deinit();
        const body = verified.body;
        _ = try c.exactFields(body, &.{ "schema", "account", "container", "runner_sha256", "host_image_sha256", "guarded_producer_sha256", "image_staging_bytes", "image_control_bytes", "issued_at", "expires_at", "region", "vm_size", "security_type", "os_disk_gib", "os_disk_sku", "inbound", "ssh", "public_ip", "data_disks", "nat", "control_bytes", "staging_bytes" });
        try schema(body, "uk-hyperv-image-admission-v1");
        const bound_runner = try sha(try field(body, "runner_sha256"));
        if (!std.mem.eql(u8, &runner, &bound_runner)) return error.RunnerMismatch;
        if (runner_size > max_control or try c.integer(u64, try field(body, "control_bytes")) != max_control) return error.ControlAllowanceExceeded;
        if (try c.integer(u64, try field(body, "staging_bytes")) != max_staging) return error.InvalidBudget;
        const staged = try c.integer(u64, try field(body, "image_staging_bytes"));
        const image_control = try c.integer(u64, try field(body, "image_control_bytes"));
        const known_controls = try controlTotal(&.{ runner_size, service_unit_bytes });
        if (image_control < known_controls or image_control > max_control or staged < image_control or staged > max_staging) return error.InvalidBudget;
        inline for (.{ .{ "region", "northeurope" }, .{ "vm_size", "Standard_D2s_v5" }, .{ "security_type", "Standard" }, .{ "os_disk_sku", "StandardSSD_LRS" } }) |pair| {
            if (!std.mem.eql(u8, try c.string(try field(body, pair[0])), pair[1])) return error.HostEnvelopeMismatch;
        }
        if (try c.integer(u64, try field(body, "os_disk_gib")) != 32 or try c.integer(u64, try field(body, "data_disks")) != 0) return error.HostEnvelopeMismatch;
        inline for (.{ "inbound", "ssh", "public_ip", "nat" }) |name| {
            const value = try field(body, name);
            if (value != .bool or value.bool) return error.HostEnvelopeMismatch;
        }
        return .{
            .verified = verified,
            .account = try c.string(try field(body, "account")),
            .container = try c.string(try field(body, "container")),
            .runner_sha256 = bound_runner,
            .host_image_sha256 = try sha(try field(body, "host_image_sha256")),
            .guarded_producer_sha256 = try sha(try field(body, "guarded_producer_sha256")),
            .image_staging_bytes = staged,
            .image_control_bytes = image_control,
            .expires_at = try expiry(body, now),
        };
    }

    pub fn deinit(self: *Admission) void {
        self.verified.deinit();
    }

    pub fn validateStartup(self: *const Admission, admission_bytes: u64, locator_bytes: u64) !void {
        const additional = try startupControlBytes(admission_bytes, locator_bytes);
        _ = try controlTotal(&.{ self.image_control_bytes, additional });
        if (self.image_staging_bytes > max_staging or additional > max_staging - self.image_staging_bytes) return error.StagingBudgetExceeded;
    }
};

pub const Artifact = struct {
    role: Role,
    name: []const u8,
    blob: []const u8,
    sha256: Hash,
    size: u64,
};

pub const Guarded = struct {
    run_id: []const u8,
    disk_id: []const u8,
    lun: u8,
    sectors: u64,
    solved_config_sha256: Hash,
    producer_sha256: Hash,

    pub fn validate(self: Guarded) !void {
        for ([_][]const u8{ self.run_id, self.disk_id }) |id| {
            if (id.len != 32) return error.InvalidGuardedContract;
            for (id) |ch| if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) return error.InvalidGuardedContract;
        }
        if (self.sectors <= 48 or self.sectors > @as(u64, std.math.maxInt(i64)) / 512) return error.InvalidGuardedContract;
    }
};

pub const Command = struct {
    verified: Verified,
    scope: Scope,
    vm_id: Uuid,
    phase_nonce: Uuid,
    phase: Phase,
    expires_at: u64,
    manifest_sha256: Hash,
    image_sha256: Hash,
    raw_size: u64,
    policy: Policy,
    guarded: ?Guarded,
    artifacts: []Artifact,
    infrastructure_sha256: Hash,
    acceptance: ?Acceptance,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8, key: [32]u8, admission: *const Admission, scope: Scope, vm_id: Uuid, now: u64) !Command {
        try scope.validate();
        if (!std.mem.eql(u8, scope.account, admission.account) or !std.mem.eql(u8, scope.container, admission.container) or now >= admission.expires_at) return error.NotAdmitted;
        var verified = try verify(allocator, bytes, key, "uk-hyperv-host-command-v1");
        errdefer verified.deinit();
        const body = verified.body;
        _ = try c.exactFields(body, &.{ "schema", "run_id", "vm_id", "phase_nonce", "phase", "issued_at", "expires_at", "manifest_sha256", "runner_sha256", "image_sha256", "manifest", "acceptance" });
        try schema(body, "uk-hyperv-host-command-v1");
        const expires_at = try expiry(body, now);
        if (expires_at > admission.expires_at) return error.NotAdmitted;
        const command_run = try uuid(try field(body, "run_id"));
        const command_vm = try uuid(try field(body, "vm_id"));
        if (!std.mem.eql(u8, &command_run, &scope.run_id) or !std.mem.eql(u8, &command_vm, &vm_id)) return error.ScopeMismatch;
        const runner = try sha(try field(body, "runner_sha256"));
        if (!std.mem.eql(u8, &runner, &admission.runner_sha256)) return error.RunnerMismatch;
        const phase = try c.enumeration(Phase, try field(body, "phase"));
        const manifest = try field(body, "manifest");
        _ = try c.exactFields(manifest, &.{ "raw_size", "policy", "guarded", "artifacts" });
        const manifest_bytes = try canonical(allocator, manifest);
        defer allocator.free(manifest_bytes);
        const manifest_hash = try sha(try field(body, "manifest_sha256"));
        if (!std.mem.eql(u8, &manifest_hash, &hash(manifest_bytes))) return error.ManifestMismatch;
        const raw_size = try c.integer(u64, try field(manifest, "raw_size"));
        if (raw_size < 1024 * 1024 or raw_size > max_artifact) return error.InvalidArtifact;
        const policy_string = try c.string(try field(manifest, "policy"));
        const policy: Policy = if (std.mem.eql(u8, policy_string, "platform-unavailable-v1"))
            .platform_unavailable
        else if (std.mem.eql(u8, policy_string, "platform-main-zero-v1"))
            .platform_main_zero
        else if (std.mem.eql(u8, policy_string, "guarded-v2-pristine-unavailable"))
            .guarded_v2
        else
            return error.InvalidPolicy;
        if (phase == .public and policy != .platform_unavailable) return error.InvalidPolicy;
        const guarded_value = try field(manifest, "guarded");
        var guarded: ?Guarded = null;
        if (policy == .guarded_v2) {
            _ = try c.exactFields(guarded_value, &.{ "run_id", "disk_id", "lun", "sectors", "solved_config_sha256", "producer_sha256" });
            const run = try c.string(try field(guarded_value, "run_id"));
            const disk = try c.string(try field(guarded_value, "disk_id"));
            const sectors = try c.integer(u64, try field(guarded_value, "sectors"));
            const producer = try sha(try field(guarded_value, "producer_sha256"));
            if (std.mem.allEqual(u8, &admission.guarded_producer_sha256, 0) or !std.mem.eql(u8, &producer, &admission.guarded_producer_sha256)) return error.ProducerNotAdmitted;
            guarded = .{ .run_id = run, .disk_id = disk, .lun = try c.integer(u8, try field(guarded_value, "lun")), .sectors = sectors, .solved_config_sha256 = try sha(try field(guarded_value, "solved_config_sha256")), .producer_sha256 = producer };
            try guarded.?.validate();
        } else if (guarded_value != .null) return error.InvalidGuardedContract;
        const records = try field(manifest, "artifacts");
        if (records != .array or records.array.items.len > 129) return error.InvalidArtifact;
        const artifacts = try allocator.alloc(Artifact, records.array.items.len);
        errdefer allocator.free(artifacts);
        var roles = [_]usize{0} ** @typeInfo(Role).@"enum".fields.len;
        var infrastructure = std.crypto.hash.sha2.Sha256.init(.{});
        infrastructure.update("uk-hyperv-host-infrastructure-v1\n");
        var total: u64 = 0;
        for (records.array.items, 0..) |record, index| {
            _ = try c.exactFields(record, &.{ "role", "name", "blob", "sha256", "size" });
            const role = try c.enumeration(Role, try field(record, "role"));
            const name = try c.string(try field(record, "name"));
            try validName(role, name);
            const blob = try c.string(try field(record, "blob"));
            const expected = try artifactBlob(allocator, scope.run_id, phase, name);
            defer allocator.free(expected);
            if (!std.mem.eql(u8, blob, expected)) return error.InvalidBlobScope;
            const size = try c.integer(u64, try field(record, "size"));
            if (size == 0 or size > max_artifact or total > max_staging - size) return error.InvalidArtifact;
            total += size;
            for (artifacts[0..index]) |prior| if (std.mem.eql(u8, prior.name, name) or std.mem.eql(u8, prior.blob, blob)) return error.DuplicateArtifact;
            artifacts[index] = .{ .role = role, .name = name, .blob = blob, .sha256 = try sha(try field(record, "sha256")), .size = size };
            roles[@intFromEnum(role)] += 1;
            if (role == .qemu or role == .ovmf_code or role == .ovmf_vars or role == .support) {
                // Blob phase differs, but immutable local infrastructure must not.
                var name_length: [8]u8 = undefined;
                std.mem.writeInt(u64, &name_length, name.len, .big);
                infrastructure.update(&.{@intFromEnum(role)});
                infrastructure.update(&name_length);
                infrastructure.update(@tagName(role));
                infrastructure.update(name);
                infrastructure.update(&artifacts[index].sha256);
                var number: [8]u8 = undefined;
                std.mem.writeInt(u64, &number, size, .big);
                infrastructure.update(&number);
            }
        }
        inline for (.{ Role.qemu, Role.ovmf_code, Role.ovmf_vars }) |role| if (roles[@intFromEnum(role)] != 1) return error.InvalidArtifact;
        if (roles[@intFromEnum(Role.support)] > 124) return error.InvalidArtifact;
        if (phase == .public) {
            if (roles[@intFromEnum(Role.capability_raw)] != 1 or roles[@intFromEnum(Role.raw)] != 0 or roles[@intFromEnum(Role.vhd)] != 0) return error.InvalidArtifact;
        } else if (roles[@intFromEnum(Role.capability_raw)] != 0 or roles[@intFromEnum(Role.raw)] != 1 or roles[@intFromEnum(Role.vhd)] != 1) return error.InvalidArtifact;
        const image_hash = try sha(try field(body, "image_sha256"));
        for (artifacts) |record| {
            if (record.role == .raw or record.role == .capability_raw) {
                if (record.size != raw_size or !std.mem.eql(u8, &record.sha256, &image_hash)) return error.ImageMismatch;
            }
            if (record.role == .vhd and record.size != raw_size + 512) return error.ImageMismatch;
        }
        const acceptance_value = try field(body, "acceptance");
        var acceptance: ?Acceptance = null;
        if (phase == .private) {
            const acceptance_bytes = try canonical(allocator, acceptance_value);
            defer allocator.free(acceptance_bytes);
            acceptance = try Acceptance.parse(allocator, acceptance_bytes, key, scope.run_id, vm_id, now);
        } else if (acceptance_value != .null) return error.PrematurePrivatePhase;
        return .{
            .verified = verified,
            .scope = scope,
            .vm_id = vm_id,
            .phase_nonce = try uuid(try field(body, "phase_nonce")),
            .phase = phase,
            .expires_at = expires_at,
            .manifest_sha256 = manifest_hash,
            .image_sha256 = image_hash,
            .raw_size = raw_size,
            .policy = policy,
            .guarded = guarded,
            .artifacts = artifacts,
            .infrastructure_sha256 = infrastructure.finalResult(),
            .acceptance = acceptance,
        };
    }

    pub fn artifact(self: *const Command, role: Role) Artifact {
        for (self.artifacts) |record| if (record.role == role) return record;
        unreachable;
    }

    pub fn deinit(self: *Command) void {
        self.verified.allocator.free(self.artifacts);
        self.verified.deinit();
    }
};

pub const Acceptance = struct {
    phase_nonce: Uuid,
    public_command_sha256: Hash,
    public_evidence_sha256: Hash,
    host_boot_id: Uuid,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8, key: [32]u8, run_id: Uuid, vm_id: Uuid, now: u64) !Acceptance {
        var verified = try verify(allocator, bytes, key, "uk-hyperv-public-acceptance-v1");
        defer verified.deinit();
        const value = verified.body;
        _ = try c.exactFields(value, &.{ "schema", "run_id", "vm_id", "phase_nonce", "public_command_sha256", "public_evidence_sha256", "host_boot_id", "issued_at", "expires_at" });
        try schema(value, "uk-hyperv-public-acceptance-v1");
        _ = try expiry(value, now);
        const bound_run = try uuid(try field(value, "run_id"));
        const bound_vm = try uuid(try field(value, "vm_id"));
        if (!std.mem.eql(u8, &run_id, &bound_run) or !std.mem.eql(u8, &vm_id, &bound_vm)) return error.ScopeMismatch;
        return .{
            .phase_nonce = try uuid(try field(value, "phase_nonce")),
            .public_command_sha256 = try sha(try field(value, "public_command_sha256")),
            .public_evidence_sha256 = try sha(try field(value, "public_evidence_sha256")),
            .host_boot_id = try uuid(try field(value, "host_boot_id")),
        };
    }
};

pub fn validName(role: Role, name: []const u8) !void {
    const fixed: ?[]const u8 = switch (role) {
        .qemu => "qemu/bin/qemu-system-x86_64",
        .ovmf_code => "OVMF_CODE.fd",
        .ovmf_vars => "OVMF_VARS.fd",
        .capability_raw => "capability.raw",
        .raw => "private.raw",
        .vhd => "private.vhd",
        .support => null,
    };
    if (fixed) |expected| {
        if (!std.mem.eql(u8, name, expected)) return error.InvalidArtifactName;
        return;
    }
    if (name.len > 240 or (!std.mem.startsWith(u8, name, "qemu/lib/") and !std.mem.startsWith(u8, name, "qemu/share/"))) return error.InvalidArtifactName;
    var parts = std.mem.splitScalar(u8, name, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidArtifactName;
        for (part) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '_' and ch != '-') return error.InvalidArtifactName;
    }
}

pub fn artifactBlob(allocator: std.mem.Allocator, run: Uuid, phase: Phase, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "runs/{s}/{s}/artifacts/{s}", .{ uuidText(run), @tagName(phase), name });
}
