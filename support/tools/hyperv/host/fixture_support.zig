const std = @import("std");
const host = @import("host");
const p = host.protocol;
pub const allocator = std.testing.allocator;
pub const io = std.testing.io;
pub const now: u64 = 1000;
pub const run_text = "01234567-89ab-4cde-8fab-0123456789ab";
pub const vm_text = "10234567-89ab-4cde-8fab-0123456789ab";
pub const public_nonce_text = "20234567-89ab-4cde-8fab-0123456789ab";
pub const private_nonce_text = "30234567-89ab-4cde-8fab-0123456789ab";
pub const runner_hash = hash: {
    @setEvalBranchQuota(10000);
    break :hash p.hash("synthetic-runner");
};
pub const producer_hash = hash: {
    @setEvalBranchQuota(10000);
    break :hash p.hash("synthetic-producer");
};

pub fn uuid(text: []const u8) p.Uuid {
    return host.core.contracts.parseUuid(text) catch unreachable;
}

pub fn scope() p.Scope {
    return .{ .account = "fixture", .container = "private", .run_id = uuid(run_text) };
}

pub fn keys() p.Ed25519.KeyPair {
    return p.Ed25519.KeyPair.generateDeterministic([_]u8{0x5a} ** 32) catch unreachable;
}

pub fn key() [32]u8 {
    return keys().public_key.toBytes();
}

pub fn json(value: anytype) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(bytes);
    var doc = try host.core.contracts.Document.parse(allocator, bytes, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
    defer doc.deinit();
    return doc.canonicalAlloc(allocator);
}

pub fn signBody(body: std.json.Value, domain: []const u8) ![]u8 {
    const canonical = try p.canonical(allocator, body);
    defer allocator.free(canonical);
    const message = try std.mem.concat(allocator, u8, &.{ domain, "\n", canonical });
    defer allocator.free(message);
    const signature = try keys().sign(message, null);
    const encoded = p.hex(signature.toBytes());
    return json(.{ .body = body, .signature = @as([]const u8, &encoded) });
}

pub fn sign(value: anytype, domain: []const u8) ![]u8 {
    const bytes = try json(value);
    defer allocator.free(bytes);
    var doc = try host.core.contracts.Document.parse(allocator, bytes, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
    defer doc.deinit();
    return signBody(doc.value(), domain);
}

pub const image_controls = 256 + p.service_unit_bytes + 128;
pub const AdmissionBudget = struct {
    image_staging_bytes: u64 = image_controls + 512,
    image_control_bytes: u64 = image_controls,
    control_bytes: u64 = p.max_control,
    staging_bytes: u64 = p.max_staging,
};

pub fn admissionBytes() ![]u8 {
    return admissionBytesWithBudget(.{});
}

pub fn admissionBytesWithBudget(budget: AdmissionBudget) ![]u8 {
    return sign(.{
        .schema = "uk-hyperv-image-admission-v1",
        .account = "fixture",
        .container = "private",
        .runner_sha256 = @as([]const u8, &p.hex(runner_hash)),
        .host_image_sha256 = @as([]const u8, &p.hex(p.hash("synthetic-host-image"))),
        .guarded_producer_sha256 = @as([]const u8, &p.hex(producer_hash)),
        .image_staging_bytes = budget.image_staging_bytes,
        .image_control_bytes = budget.image_control_bytes,
        .issued_at = 900,
        .expires_at = 2000,
        .region = "northeurope",
        .vm_size = "Standard_D2s_v5",
        .security_type = "Standard",
        .os_disk_gib = 32,
        .os_disk_sku = "StandardSSD_LRS",
        .inbound = false,
        .ssh = false,
        .public_ip = false,
        .data_disks = 0,
        .nat = false,
        .control_bytes = budget.control_bytes,
        .staging_bytes = budget.staging_bytes,
    }, "uk-hyperv-image-admission-v1");
}

pub fn admission() !p.Admission {
    const bytes = try admissionBytes();
    defer allocator.free(bytes);
    return p.Admission.parse(allocator, bytes, key(), now, runner_hash, 256);
}

pub const Artifact = struct {
    role: p.Role,
    name: []const u8,
    blob: []const u8,
    sha256: []const u8,
    size: u64,
};

pub fn command(phase: p.Phase, records: []const Artifact, image_hash: p.Hash, acceptance: ?std.json.Value) ![]u8 {
    const manifest = .{ .raw_size = 1048576, .policy = "platform-unavailable-v1", .guarded = null, .artifacts = records };
    const manifest_bytes = try json(manifest);
    defer allocator.free(manifest_bytes);
    const result = .{
        .schema = "uk-hyperv-host-command-v1",
        .run_id = run_text,
        .vm_id = vm_text,
        .phase_nonce = if (phase == .public) public_nonce_text else private_nonce_text,
        .phase = phase,
        .issued_at = 900,
        .expires_at = 2000,
        .manifest_sha256 = @as([]const u8, &p.hex(p.hash(manifest_bytes))),
        .runner_sha256 = @as([]const u8, &p.hex(runner_hash)),
        .image_sha256 = @as([]const u8, &p.hex(image_hash)),
        .manifest = manifest,
        .acceptance = acceptance,
    };
    return sign(result, "uk-hyperv-host-command-v1");
}

pub fn accepted(public: *const p.Command, receipt: p.Hash, boot: p.Uuid) ![]u8 {
    return sign(.{
        .schema = "uk-hyperv-public-acceptance-v1",
        .run_id = run_text,
        .vm_id = vm_text,
        .phase_nonce = public_nonce_text,
        .public_command_sha256 = @as([]const u8, &p.hex(public.verified.digest)),
        .public_evidence_sha256 = @as([]const u8, &p.hex(receipt)),
        .host_boot_id = @as([]const u8, &p.uuidText(boot)),
        .issued_at = 900,
        .expires_at = 2000,
    }, "uk-hyperv-public-acceptance-v1");
}

pub const Directory = struct {
    path: []u8,
    directory: host.core.private_files.Directory,

    pub fn create(label: []const u8) !Directory {
        const root_path = @import("test_options").test_root orelse return error.FixtureRootRequired;
        const root = try host.core.private_files.Directory.open(io, root_path);
        defer root.close(io);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(allocator, "{s}-{s}", .{ label, p.hex(nonce) });
        defer allocator.free(name);
        try root.dir.createDir(io, name, .fromMode(0o700));
        const path = try std.fs.path.join(allocator, &.{ root_path, name });
        errdefer allocator.free(path);
        return .{ .path = path, .directory = try host.files.durableDirectory(io, path) };
    }

    pub fn deinit(self: Directory) void {
        self.directory.close(io);
        allocator.free(self.path);
    }
};

pub fn clock(_: *anyopaque) !u64 {
    return now;
}
