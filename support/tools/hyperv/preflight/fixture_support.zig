const std = @import("std");
const pf = @import("preflight");
const c = pf.contract;
const p = c.p;
pub const now: u64 = 1800000000;
pub const run: c.Uuid = "01234567-89ab-4cde-8fab-0123456789ab".*;
pub const vm: c.Uuid = "10234567-89ab-4cde-8fab-0123456789ab".*;
pub const disk: c.Uuid = "20234567-89ab-4cde-8fab-0123456789ab".*;
pub const principal: c.Uuid = "30234567-89ab-4cde-8fab-0123456789ab".*;
pub const boot: c.Uuid = "40234567-89ab-4cde-8fab-0123456789ab".*;
pub const seed = [_]u8{0x47} ** 32;

pub const Context = struct {
    arena: std.heap.ArenaAllocator,
    io: std.Io,
    directory: pf.core.private_files.Directory,
    root: []const u8,
    input: c.Input,
    signer: pf.commands.Signer,
    last: pf.azure.transport.Failure = .{ .effect = .not_started, .diagnostic = .{ .stage = .admission, .category = .internal } },
    fail_action: ?c.Action = null,
    malformed_public: bool = false,
    recording_action: ?c.Action = null,
    pause_action: ?c.Action = null,
    orphan_action: ?c.Action = null,
    flood_action: ?c.Action = null,
    private_transfers: usize = 0,
    calls: [c.action_count]u8 = [_]u8{0} ** c.action_count,

    pub fn init(a: std.mem.Allocator, io: std.Io, directory: pf.core.private_files.Directory, root: []const u8) !Context {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        const pair = try p.Ed25519.KeyPair.generateDeterministic(seed);
        const key = pair.public_key.toBytes();
        const signer = try pf.commands.Signer.fromSeed(seed, key);
        const r: c.Resources = .{
            .deployment = .{ .kind = .deployment, .name = "fixture-host" },
            .vm = .{ .kind = .vm, .name = "fixture-vm" },
            .disk = .{ .kind = .disk, .name = "fixture-os" },
            .nic = .{ .kind = .nic, .name = "fixture-nic" },
            .nsg = .{ .kind = .nsg, .name = "fixture-nsg" },
            .vnet = .{ .kind = .vnet, .name = "fixture-vnet" },
            .subnet = .{ .kind = .subnet, .parent = "fixture-vnet", .name = "default" },
            .storage = .{ .kind = .storage, .name = "fixtureaccount" },
            .schedule = .{ .kind = .schedule, .name = "fixture-shutdown" },
            .input_role = "50234567-89ab-4cde-8fab-0123456789ab".*,
            .evidence_role = "60234567-89ab-4cde-8fab-0123456789ab".*,
        };
        const authority: pf.azure.scope.Authority = .{
            .tenant = "70234567-89ab-4cde-8fab-0123456789ab".*,
            .subscription = "80234567-89ab-4cde-8fab-0123456789ab".*,
            .principal = "90234567-89ab-4cde-8fab-0123456789ab".*,
            .client = "a0234567-89ab-4cde-8fab-0123456789ab".*,
            .group = "fixture-group",
            .location = "northeurope",
            .owner_run = run,
        };
        const budget: c.Budget = .{
            .producer = .{ .staged = 1024, .control = 512 },
            .controller = .{ .staged = 40 * 1024 * 1024, .control = 1500000 },
            .host_baked = .{ .staged = 256 + p.service_unit_bytes, .control = 256 + p.service_unit_bytes },
            .host_runtime = .{ .staged = 16 * 1024 * 1024, .control = 128 * 1024 },
        };
        const floor = try budget.floor();
        const hash = p.hash("synthetic-native-binding");
        const admission = try sign(scratch, .{
            .schema = "uk-hyperv-image-admission-v1",
            .account = r.storage.name,
            .container = "preflight",
            .runner_sha256 = @as([]const u8, &p.hex(hash)),
            .host_image_sha256 = @as([]const u8, &p.hex(p.hash("synthetic-image"))),
            .guarded_producer_sha256 = @as([]const u8, &p.hex(hash)),
            .image_staging_bytes = floor.staged,
            .image_control_bytes = floor.control,
            .issued_at = now - 60,
            .expires_at = now + 3300,
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
            .control_bytes = p.max_control,
            .staging_bytes = p.max_staging,
        }, "uk-hyperv-image-admission-v1");
        const names = [_][]const u8{ "qemu/bin/qemu-system-x86_64", "OVMF_CODE.fd", "OVMF_VARS.fd", "capability.raw", "private.raw", "private.vhd" };
        const roles = [_]p.Role{ .qemu, .ovmf_code, .ovmf_vars, .capability_raw, .raw, .vhd };
        const files = try scratch.alloc(c.File, names.len);
        for (files, names, roles, 0..) |*file, name, role, i| {
            const phase: p.Phase = if (i < 4) .public else .private;
            file.* = .{
                .phase = phase,
                .path = try std.fs.path.join(scratch, &.{ root, name }),
                .artifact = .{ .role = role, .name = name, .blob = try p.artifactBlob(scratch, try pf.core.contracts.parseUuid(&run), phase, name), .sha256 = p.hash(name), .size = if (i < 3) 256 else if (i == 5) 1049088 else 1048576 },
            };
        }
        const image_ref: pf.azure.scope.Ref = .{ .kind = .image, .name = "fixture-image" };
        var image_authority = authority;
        image_authority.group = "fixture-images";
        var result: Context = .{
            .arena = undefined,
            .io = io,
            .directory = directory,
            .root = root,
            .signer = signer,
            .input = .{
                .kind = .synthetic,
                .preparation = .{
                    .binding = .{ .implementation = hash, .preparation = hash, .source = hash, .dependencies = hash, .tool_runtime = hash, .operator_binary = hash },
                    .input_manifest_sha256 = hash,
                    .input_root = root,
                    .files = files,
                    .public = try manifest(scratch, files, .public, hash),
                    .private = try manifest(scratch, files, .private, hash),
                },
                .approved = .{
                    .authority = authority,
                    .resources = r,
                    .proofs = .{ .original_network_authority = hash, .immutable_image = hash, .image_publication_ledger = hash, .identity_rbac = hash, .uploader_route = hash, .native_provider = hash, .tls_bundle = hash, .independent_deadlines = hash },
                    .image = .{ .sku = "Standard_D2s_v5", .family = "standardDSv5Family", .vcpus = 2, .memory_mib = 8192, .require_nested_metadata = true, .image = image_ref, .image_group = image_authority.group, .image_response_sha256 = hash },
                    .image_id = try image_ref.path(scratch, image_authority),
                    .public_key = key,
                    .signed_host_admission = admission,
                    .runner_sha256 = hash,
                    .runner_bytes = 256,
                    .budget = budget,
                    .credential_provider = .client_assertion,
                    .uploader_ipv4 = .{ 203, 0, 113, 10 },
                    .not_before = now - 60,
                    .expires_at = now + 3300,
                    .cleanup_expires_at = now + 4500,
                },
            },
        };
        result.arena = arena;
        return result;
    }
    pub fn deinit(self: *Context) void {
        self.signer.deinit();
        self.arena.deinit();
    }
    pub fn backend(context: *anyopaque, _: *pf.journal.Store) !pf.engine.Backend {
        return .{ .context = context, .controlFn = control, .stageFn = stage, .publishFn = publish, .fetchFn = fetch, .releaseFn = release, .failureFn = failure };
    }
    pub fn resolved(self: *Context) !pf.worker.Resolved {
        return .{ .input = &self.input, .signer = &self.signer, .backend_context = self, .backendFn = backend, .now = now, .monotonic_ns = try pf.core.process.monotonicNanoseconds(), .operator_boot_id = boot };
    }
    fn before(self: *Context, action: c.Action) !void {
        self.calls[@intFromEnum(action)] += 1;
        self.last = .{ .effect = .not_started, .diagnostic = .{ .stage = .admission, .category = .internal } };
        if (self.orphan_action == action) {
            const child = std.os.linux.fork();
            if (std.os.linux.errno(child) != .SUCCESS) return error.FixtureFork;
            if (child == 0) while (true) {
                const duration: std.os.linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = std.os.linux.nanosleep(&duration, null);
            };
            const pid = try std.fmt.allocPrint(self.arena.allocator(), "{d}", .{child});
            try self.directory.dir.writeFile(self.io, .{ .sub_path = "synthetic-descendant.pid", .data = pid, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
            try self.io.sleep(.fromSeconds(60), .awake);
        }
        if (self.flood_action == action) while (true) {
            try std.Io.File.stdout().writeStreamingAll(self.io, "synthetic bounded output flood\n");
        };
        if (self.pause_action == action) try self.io.sleep(.fromSeconds(60), .awake);
        if (self.recording_action == action) {
            // The marker makes the next atomic state publication fail without
            // altering a journal implementation or installing a runtime bypass.
            try self.directory.dir.deleteFile(self.io, "state.json");
            try self.directory.dir.createDir(self.io, "state.json", .fromMode(0o700));
        }
        if (self.fail_action == action) {
            self.last = .{ .effect = .unknown, .diagnostic = .{ .stage = .arm, .category = .transport } };
            return error.SyntheticOperationFailure;
        }
    }
    fn marker(self: *Context, name: []const u8) !void {
        const file = try self.directory.dir.createFile(self.io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, &run);
        try file.sync(self.io);
        try pf.host.files.syncDirectory(self.io, self.directory.dir);
    }
    fn control(context: *anyopaque, action: c.Action, _: *const pf.journal.State) !pf.engine.Proof {
        const self: *Context = @ptrCast(@alignCast(context));
        try self.before(action);
        if (action == .create_group) try self.marker("synthetic-group");
        if (action == .delete_group) {
            const bytes = try self.directory.read(self.io, self.arena.allocator(), "synthetic-group", 36, p.hash(&run));
            if (bytes.len != 36) return error.OwnershipMismatch;
            try self.directory.dir.deleteFile(self.io, "synthetic-group");
            try pf.host.files.syncDirectory(self.io, self.directory.dir);
        }
        if (action == .prove_group_absent) {
            const file = self.directory.openFile(self.io, "synthetic-group") catch |err| switch (err) {
                error.FileNotFound => return .{ .digest = p.hash("synthetic-independent-absence"), .effect = .not_applicable },
                else => return err,
            };
            file.close(self.io);
            return error.GroupStillPresent;
        }
        return .{ .digest = p.hash(@tagName(action)), .effect = if (action.mutation()) .accepted else .not_applicable, .vm_id = if (action == .inspect_host) vm else null, .disk_id = if (action == .inspect_host) disk else null, .principal_id = if (action == .inspect_host) principal else null };
    }
    fn stage(context: *anyopaque, phase: p.Phase, state: *const pf.journal.State) !pf.engine.Proof {
        const self: *Context = @ptrCast(@alignCast(context));
        const action: c.Action = if (phase == .public) .stage_public else .stage_private;
        try self.before(action);
        if (phase == .private) {
            try pf.engine.requirePublic(state.*);
            self.private_transfers += 1;
        }
        try self.marker(if (phase == .public) "synthetic-public-transfer" else "synthetic-private-transfer");
        return .{ .digest = p.hash(@tagName(action)), .effect = .accepted };
    }
    fn publish(context: *anyopaque, phase: p.Phase, bytes: []const u8, _: *const pf.journal.State) !pf.engine.Proof {
        const self: *Context = @ptrCast(@alignCast(context));
        try self.before(if (phase == .public) .publish_public else .publish_private);
        var admission = try self.input.validate(self.arena.allocator(), now);
        defer admission.deinit();
        var command = try p.Command.parse(self.arena.allocator(), bytes, self.input.approved.public_key, &admission, try self.input.scope(&admission), try pf.core.contracts.parseUuid(&vm), now);
        defer command.deinit();
        if (command.phase != phase) return error.InvalidPhase;
        try self.marker(if (phase == .public) "synthetic-public-publication" else "synthetic-private-publication");
        return .{ .digest = p.hash(bytes), .effect = .accepted };
    }
    pub fn bundle(self: *Context, phase: p.Phase, state: *const pf.journal.State) !pf.evidence.Bundle {
        const a = self.arena.allocator();
        const bytes = try self.directory.read(self.io, a, pf.engine.commandName(phase), p.max_command, null);
        var admission = try self.input.validate(a, now);
        defer admission.deinit();
        var command = try p.Command.parse(a, bytes, self.input.approved.public_key, &admission, try self.input.scope(&admission), try pf.core.contracts.parseUuid(&vm), now);
        defer command.deinit();
        const count: usize = if (phase == .public) 2 else 4;
        const logs = try a.alloc([]const u8, count);
        const outcomes = try a.alloc(pf.host.boot.Outcome, count);
        var serial_bytes: u64 = 0;
        for (outcomes, logs, 0..) |*outcome, *log, i| {
            log.* = try serial(a, phase == .private, i % 2 == 1);
            serial_bytes += log.len;
            var launch = boot;
            launch[0] = "56789a"[i + @as(usize, if (phase == .public) 0 else 2)];
            outcome.* = .{ .evidence_kind = .synthetic_child, .index = @intCast(i + @as(usize, if (phase == .public) 0 else 2)), .host_boot_id = boot, .launch_id = launch, .image_sha256 = p.hex(command.artifact(if (phase == .public) .capability_raw else if (i < 2) .raw else .vhd).sha256), .serial_sha256 = p.hex(p.hash(log.*)), .serial_bytes = log.len, .legacy_apic = i % 2 == 1, .passed = true, .failures = .{} };
        }
        const floor = try self.input.approved.budget.floor();
        return .{ .logs = logs, .receipt = try c.canonical(a, .{
            .schema = "uk-hyperv-host-evidence-v1",
            .evidence_kind = "synthetic_child",
            .phase = phase,
            .run_id = @as([]const u8, &run),
            .vm_id = @as([]const u8, &vm),
            .phase_nonce = @as([]const u8, &p.uuidText(command.phase_nonce)),
            .host_boot_id = @as([]const u8, &boot),
            .command_sha256 = @as([]const u8, &p.hex(command.verified.digest)),
            .manifest_sha256 = @as([]const u8, &p.hex(command.manifest_sha256)),
            .runner_sha256 = @as([]const u8, &p.hex(admission.runner_sha256)),
            .image_sha256 = @as([]const u8, &p.hex(command.image_sha256)),
            .host_image_sha256 = @as([]const u8, &p.hex(admission.host_image_sha256)),
            .scope = "platform-only",
            .status = if (self.malformed_public and phase == .public) "FAIL" else "PASS",
            .boots = outcomes,
            .failures = pf.core.diagnostics.Failures{},
            .staging_bytes_reserved_before_receipt = floor.staged + @as(u64, if (phase == .public) 8192 else 16384),
            .control_bytes_reserved_before_receipt = floor.control + @as(u64, if (phase == .public) 1024 else 2048),
            .evidence_bytes_reserved_before_receipt = serial_bytes + @as(u64, if (phase == .public) 0 else state.public.?.host_evidence),
        }) };
    }
    fn fetch(context: *anyopaque, phase: p.Phase, _: c.Uuid, state: *const pf.journal.State) !pf.evidence.Bundle {
        const self: *Context = @ptrCast(@alignCast(context));
        try self.before(if (phase == .public) .read_public else .read_private);
        return self.bundle(phase, state);
    }
    // Bundle storage belongs to this fixture's arena.
    fn release(_: *anyopaque, _: pf.evidence.Bundle) void {}
    fn failure(context: *anyopaque) pf.azure.transport.Failure {
        return (@as(*Context, @ptrCast(@alignCast(context)))).last;
    }
};

pub fn manifest(a: std.mem.Allocator, files: []const c.File, phase: p.Phase, hash: p.Hash) !c.Manifest {
    const Artifact = struct { role: p.Role, name: []const u8, blob: []const u8, sha256: []const u8, size: u64 };
    var artifacts: std.ArrayList(Artifact) = .empty;
    var image_hash: p.Hash = undefined;
    for (files) |file| {
        if ((phase == .public and file.phase != .public) or (phase == .private and file.artifact.role == .capability_raw)) continue;
        const record = file.artifact;
        if (record.role == .raw or record.role == .capability_raw) image_hash = record.sha256;
        try artifacts.append(a, .{ .role = record.role, .name = record.name, .blob = try p.artifactBlob(a, try pf.core.contracts.parseUuid(&run), phase, record.name), .sha256 = try a.dupe(u8, &p.hex(record.sha256)), .size = record.size });
    }
    const Guarded = struct { run_id: []const u8, disk_id: []const u8, lun: u8, sectors: u64, solved_config_sha256: []const u8, producer_sha256: []const u8 };
    const guarded: ?Guarded = if (phase == .private) .{
        .run_id = "0123456789abcdef0123456789abcdef",
        .disk_id = "1123456789abcdef0123456789abcdef",
        .lun = 7,
        .sectors = 8192,
        .solved_config_sha256 = try a.dupe(u8, &p.hex(hash)),
        .producer_sha256 = try a.dupe(u8, &p.hex(hash)),
    } else null;
    const bytes = try c.canonical(a, .{ .raw_size = 1048576, .policy = if (phase == .public) "platform-unavailable-v1" else "guarded-v2-pristine-unavailable", .guarded = guarded, .artifacts = artifacts.items });
    return .{ .bytes = bytes, .sha256 = p.hash(bytes), .image_sha256 = image_hash };
}
pub fn sign(a: std.mem.Allocator, body: anytype, domain: []const u8) ![]u8 {
    const pair = try p.Ed25519.KeyPair.generateDeterministic(seed);
    const bytes = try c.canonical(a, body);
    defer a.free(bytes);
    const message = try std.mem.concat(a, u8, &.{ domain, "\n", bytes });
    defer a.free(message);
    const signature = try pair.sign(message, null);
    return c.canonical(a, .{ .body = body, .signature = @as([]const u8, &p.hex(signature.toBytes())) });
}
fn serial(a: std.mem.Allocator, guarded: bool, legacy: bool) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    try out.writer.writeAll("Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by fixture\nCalling main(\n");
    if (legacy) try out.writer.writeAll("Using legacy xAPIC MMIO\n");
    if (guarded) {
        try out.writer.writeAll("HYPERV_PERSISTENCE START PASS run=0123456789abcdef0123456789abcdef address=0:0:7 sectors=8192 sector_size=512\nHYPERV_PERSISTENCE SELECT UNAVAILABLE reason=no-devices writes=0 flushes=0\nUK_HYPERV_PLATFORM_READY\nUK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices\n");
    } else {
        try out.writer.writeAll("UK_HYPERV_PLATFORM_READY\n");
        for (pf.host.serial.unavailable_records) |line| try out.writer.print("{s}\n", .{line});
        try out.writer.print("{s}\n", .{pf.host.serial.unavailable_marker});
    }
    try out.writer.writeAll("main returned 2\n");
    return out.toOwnedSlice();
}
