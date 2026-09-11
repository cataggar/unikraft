const std = @import("std");
const core = @import("hyperv_core");
const az = @import("hyperv_azure");
const host = @import("hyperv_host");
pub const p = host.protocol;
pub const Hash = p.Hash;
pub const Uuid = az.scope.Uuid;
pub const max_state = 192 * 1024;
pub const max_operation_result = 4096;
pub const attempt_ms = 3600 * 1000;
pub const cleanup_ms = 20 * 60 * 1000;
pub const child_cleanup_ms = 120 * 1000;
pub const emergency_bytes = 4096;
pub const Kind = enum { production, synthetic };
pub const Lane = enum { primary, cleanup, recording };
pub const Phase = enum { prepared, running, cleaning, failed, cleaned, completed, synthetic_completed };
pub const Action = enum {
    metadata,
    create_group,
    deploy_host,
    inspect_host,
    grant_access,
    stage_public,
    publish_public,
    read_public,
    accept_public,
    stage_private,
    publish_private,
    read_private,
    deallocate,
    revoke_roles,
    revoke_sas,
    prove_sas_revoked,
    clear_firewall,
    delete_group,
    prove_group_absent,
    dispose_credentials,

    pub fn cleanup(self: Action) bool {
        return @intFromEnum(self) >= @intFromEnum(Action.deallocate);
    }
    pub fn mutation(self: Action) bool {
        return switch (self) {
            .metadata, .inspect_host, .read_public, .read_private, .prove_sas_revoked, .prove_group_absent => false,
            else => true,
        };
    }
    pub fn timeout(self: Action) u32 {
        return switch (self) {
            .deploy_host, .read_private, .delete_group => 600_000,
            .read_public, .stage_public, .stage_private => 300_000,
            else => 120_000,
        };
    }
};
pub const action_count = @typeInfo(Action).@"enum".fields.len;
pub const worker_output_reservation = 2 * (action_count + 4) * (max_operation_result + 1024);

pub const Debit = struct {
    staged: u64,
    control: u64,
    pub fn validate(self: Debit) !void {
        if (self.control > self.staged or self.control > p.max_control or self.staged > p.max_staging) return error.InvalidBudget;
    }
    pub fn add(self: Debit, other: Debit) !Debit {
        try self.validate();
        try other.validate();
        if (other.staged > p.max_staging - self.staged or other.control > p.max_control - self.control) return error.BudgetExceeded;
        return .{ .staged = self.staged + other.staged, .control = self.control + other.control };
    }
};

/// Disjoint reservations: the host starting debit already includes all producer
/// and controller reservations. Never add observed controller spending to it again.
pub const Budget = struct {
    producer: Debit,
    controller: Debit,
    host_baked: Debit,
    host_runtime: Debit,
    pub fn floor(self: Budget) !Debit {
        return (try self.producer.add(self.controller)).add(self.host_baked);
    }
    pub fn validate(self: Budget, admission: *const p.Admission) !void {
        const starting = try self.floor();
        _ = try starting.add(self.host_runtime);
        if (starting.staged != admission.image_staging_bytes or starting.control != admission.image_control_bytes or
            self.controller.control < emergency_bytes + worker_output_reservation or self.host_runtime.control < p.emergency_control)
            return error.InvalidBudgetPartition;
    }
};

pub const File = struct {
    phase: p.Phase,
    artifact: p.Artifact,
    path: []const u8,
};
pub const Manifest = struct { bytes: []const u8, sha256: Hash, image_sha256: Hash };
pub const NativeBinding = struct {
    implementation: Hash,
    preparation: Hash,
    source: Hash,
    dependencies: Hash,
    tool_runtime: Hash,
    operator_binary: Hash,
};

/// This is an in-process handoff, NOT a second preparation/build receipt format.
/// Its caller must have validated native preparation, physical source/tool
/// provenance, immutable artifacts and the exact reviewed implementation closure.
pub const Preparation = struct {
    binding: NativeBinding,
    input_manifest_sha256: Hash,
    input_root: []const u8,
    files: []const File,
    public: Manifest,
    private: Manifest,
};
pub const Approvals = struct {
    original_network_authority: Hash,
    immutable_image: Hash,
    image_publication_ledger: Hash,
    identity_rbac: Hash,
    uploader_route: Hash,
    native_provider: Hash,
    tls_bundle: Hash,
    independent_deadlines: Hash,
};
pub const Resources = struct {
    deployment: az.scope.Ref,
    vm: az.scope.Ref,
    disk: az.scope.Ref,
    nic: az.scope.Ref,
    nsg: az.scope.Ref,
    vnet: az.scope.Ref,
    subnet: az.scope.Ref,
    storage: az.scope.Ref,
    schedule: az.scope.Ref,
    input_role: Uuid,
    evidence_role: Uuid,
};
pub const Approved = struct {
    authority: az.scope.Authority,
    proofs: Approvals,
    resources: Resources,
    image: az.admission.Spec,
    image_id: []const u8,
    public_key: [32]u8,
    signed_host_admission: []const u8,
    runner_sha256: Hash,
    runner_bytes: u64,
    budget: Budget,
    credential_provider: enum { client_assertion, system_assigned, user_assigned },
    uploader_ipv4: [4]u8,
    not_before: u64,
    expires_at: u64,
    cleanup_expires_at: u64,
};

/// Approvals are verified caller authority, never Boolean JSON self-attestations.
/// The standalone production CLI cannot construct this boundary from argv/JSON.
pub const Input = struct {
    preparation: Preparation,
    approved: Approved,
    kind: Kind,

    pub fn validate(self: *const Input, allocator: std.mem.Allocator, now: u64) !p.Admission {
        const approved = &self.approved;
        try approved.authority.validate();
        try az.operations.publicIp(approved.uploader_ipv4);
        if (!std.mem.eql(u8, approved.authority.location, "northeurope") or now < approved.not_before or
            now >= approved.expires_at or approved.expires_at - approved.not_before > 3600 or
            approved.cleanup_expires_at <= approved.expires_at or approved.cleanup_expires_at - approved.expires_at > 1200)
            return error.AuthorityUnavailable;
        inline for (std.meta.fields(Approvals)) |field| try nonzero(@field(approved.proofs, field.name));
        inline for (std.meta.fields(NativeBinding)) |field| try nonzero(@field(self.preparation.binding, field.name));
        try nonzero(self.preparation.input_manifest_sha256);
        try core.private_files.absoluteFilePath(self.preparation.input_root);
        if (self.preparation.files.len < 6 or self.preparation.files.len > 131) return error.InvalidPreparation;
        const expected_kinds = .{ az.scope.Kind.deployment, .vm, .disk, .nic, .nsg, .vnet, .subnet, .storage, .schedule };
        inline for (.{ "deployment", "vm", "disk", "nic", "nsg", "vnet", "subnet", "storage", "schedule" }, expected_kinds) |name, kind| {
            const ref = @field(approved.resources, name);
            if (ref.kind != kind) return error.InvalidInventory;
            allocator.free(try ref.path(allocator, approved.authority));
        }
        _ = try az.scope.uuid(&approved.resources.input_role);
        _ = try az.scope.uuid(&approved.resources.evidence_role);
        if (std.mem.eql(u8, &approved.resources.input_role, &approved.resources.evidence_role)) return error.InvalidInventory;
        var image_scope = approved.authority;
        image_scope.group = approved.image.image_group;
        try approved.image.image.requireId(allocator, image_scope, approved.image_id);
        if (!std.mem.eql(u8, approved.image.sku, "Standard_D2s_v5") or approved.image.vcpus != 2 or approved.image.memory_mib != 8192)
            return error.HostEnvelopeMismatch;
        var admission = try p.Admission.parse(allocator, approved.signed_host_admission, approved.public_key, now, approved.runner_sha256, approved.runner_bytes);
        errdefer admission.deinit();
        if (admission.expires_at < approved.expires_at or !std.mem.eql(u8, admission.account, approved.resources.storage.name)) return error.AdmissionMismatch;
        try approved.budget.validate(&admission);
        inline for (.{ self.preparation.public, self.preparation.private }) |manifest| {
            try nonzero(manifest.sha256);
            try nonzero(manifest.image_sha256);
            if (!std.mem.eql(u8, &p.hash(manifest.bytes), &manifest.sha256)) return error.ManifestMismatch;
            var document = try core.contracts.Document.parse(allocator, manifest.bytes, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
            defer document.deinit();
            try document.requireCanonical(allocator, manifest.bytes);
        }
        for (self.preparation.files, 0..) |file, i| {
            try p.validName(file.artifact.role, file.artifact.name);
            try core.private_files.absoluteFilePath(file.path);
            const expected = try std.fs.path.join(allocator, &.{ self.preparation.input_root, file.artifact.name });
            defer allocator.free(expected);
            if (!std.mem.eql(u8, file.path, expected) or file.artifact.size == 0 or file.artifact.size > p.max_artifact)
                return error.InvalidPreparation;
            const private = file.artifact.role == .raw or file.artifact.role == .vhd;
            if (private != (file.phase == .private)) return error.PrematurePrivateTransfer;
            for (self.preparation.files[0..i]) |prior| if (std.mem.eql(u8, prior.path, file.path)) return error.DuplicateArtifact;
        }
        return admission;
    }

    pub fn scope(self: *const Input, admission: *const p.Admission) !p.Scope {
        const value: p.Scope = .{ .run_id = try core.contracts.parseUuid(&self.approved.authority.owner_run), .account = admission.account, .container = admission.container };
        try value.validate();
        return value;
    }
};

pub fn nonzero(hash: Hash) !void {
    if (std.mem.allEqual(u8, &hash, 0)) return error.MissingBinding;
}
pub fn canonical(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    var document = try core.contracts.Document.parse(allocator, raw, .{ .bytes = max_state, .string_bytes = p.max_command, .items = 2048, .tokens = 65536, .depth = 24 });
    defer document.deinit();
    return document.canonicalAlloc(allocator);
}
pub fn parse(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
    var document = try core.contracts.Document.parse(allocator, bytes, .{ .bytes = max_state, .string_bytes = p.max_command, .items = 2048, .tokens = 65536, .depth = 24 });
    defer document.deinit();
    try document.requireCanonical(allocator, bytes);
    if (@typeInfo(T) == .@"struct") {
        const value = document.value();
        if (value != .object) return error.ExpectedObject;
        inline for (std.meta.fields(T)) |field| {
            if (!value.object.contains(field.name)) return error.MissingField;
        }
    }
    return std.json.parseFromSlice(T, allocator, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false, .duplicate_field_behavior = .@"error" });
}
