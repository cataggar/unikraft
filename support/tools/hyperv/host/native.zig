const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const sdk = @import("azure_sdk_core");
const core = @import("hyperv_core");
const p = @import("protocol.zig");
const files = @import("files.zig");
const wire = @import("wire.zig");
const state = @import("state.zig");
const worker = @import("worker.zig");

pub const policy_root = "/etc/uk-hyperv-host";
pub const state_root = "/var/lib/uk-hyperv-host";
pub const artifact_root = state_root ++ "/artifacts";
pub const boot_root = state_root ++ "/boots";

pub fn wallSeconds(_: *anyopaque) !u64 {
    var now: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.REALTIME, &now)) != .SUCCESS or now.sec <= 0) return error.ClockUnavailable;
    return @intCast(now.sec);
}

pub fn monotonicMs(_: *anyopaque) !u64 {
    var now: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &now)) != .SUCCESS or now.sec < 0) return error.ClockUnavailable;
    return @as(u64, @intCast(now.sec)) * 1000 + @as(u64, @intCast(now.nsec)) / std.time.ns_per_ms;
}

pub const Image = struct {
    admission: p.Admission,
    runner_size: u64,
    policy_bytes: usize,

    pub fn load(allocator: std.mem.Allocator, io: std.Io, key: [32]u8) !Image {
        var clock: u8 = 0;
        const now = try wallSeconds(&clock);
        const self = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{ .mode = .read_only });
        defer self.close(io);
        const size = (try self.stat(io)).size;
        if (size > p.max_control) return error.ControlAllowanceExceeded;
        const digest = try files.digest(io, self, size);
        const directory = try core.private_files.Directory.open(io, policy_root);
        defer directory.close(io);
        const bytes = try directory.read(io, allocator, "admission.json", p.max_command, null);
        defer allocator.free(bytes);
        return .{ .admission = try p.Admission.parse(allocator, bytes, key, now, digest, size), .runner_size = size, .policy_bytes = bytes.len };
    }

    pub fn deinit(self: *Image) void {
        self.admission.deinit();
    }
};

fn requireSupervisor(allocator: std.mem.Allocator, io: std.Io, image: *const Image) !void {
    const parent = linux.getppid();
    if (parent <= 1 or linux.getpgid(0) != @as(usize, @intCast(linux.getpid()))) return error.SupervisorRequired;
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/exe", .{parent});
    defer allocator.free(path);
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only });
    defer file.close(io);
    if ((try file.stat(io)).size != image.runner_size or !std.mem.eql(u8, &try files.digest(io, file, image.runner_size), &image.admission.runner_sha256)) return error.SupervisorRequired;
}

pub fn validateBootState(record: state.Record, index: u8, boot_id: p.Uuid) !void {
    try record.validate();
    if (index >= 6 or record.stage != @as(state.Stage, if (index < 2) .public_intent else .private_intent) or
        record.boots_attempted != index + 1 or record.boots_passed != index or record.wire_inflight or
        !std.mem.eql(u8, &boot_id, &record.host_boot_id) or
        try (core.process.Deadline{ .expires_ns = record.deadline_ns }).expired()) return error.UnauthorizedBoot;
}

pub fn authorizeBootChild(init: std.process.Init, comptime key: [32]u8) !void {
    if (builtin.cpu.arch != .x86_64) return error.UnsupportedArchitecture;
    var image = try Image.load(init.gpa, init.io, key);
    defer image.deinit();
    try requireSupervisor(init.gpa, init.io, &image);
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const length = try files.cwdPath(init.io, &path);
    const prefix = boot_root ++ "/boot-";
    if (length != prefix.len + 1 or !std.mem.startsWith(u8, path[0..length], prefix) or path[length - 1] < '0' or path[length - 1] > '5') return error.InvalidWorkerDirectory;
    const index = path[length - 1] - '0';
    const directory = try core.private_files.Directory.open(init.io, state_root);
    defer directory.close(init.io);
    const bytes = try directory.read(init.io, init.gpa, "state.json", 4096, null);
    defer init.gpa.free(bytes);
    var doc = try core.contracts.Document.parse(init.gpa, bytes, .{});
    defer doc.deinit();
    try doc.requireCanonical(init.gpa, bytes);
    const parsed = try std.json.parseFromSlice(state.Record, init.gpa, bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    try validateBootState(parsed.value, index, try files.hostBootId(init.io));
    const phase: p.Phase = if (index < 2) .public else .private;
    const command_bytes = try directory.read(init.io, init.gpa, if (phase == .public) "public-intent.json" else "private-intent.json", p.max_command, null);
    defer init.gpa.free(command_bytes);
    var clock: u8 = 0;
    const scope: p.Scope = .{ .account = image.admission.account, .container = image.admission.container, .run_id = parsed.value.run_id };
    var command = try p.Command.parse(init.gpa, command_bytes, key, &image.admission, scope, parsed.value.vm_id, try wallSeconds(&clock));
    defer command.deinit();
    const nonce = if (phase == .public) parsed.value.public_nonce else parsed.value.private_nonce;
    if (nonce == null or !std.mem.eql(u8, &nonce.?, &command.phase_nonce)) return error.UnauthorizedBoot;
    if (phase == .private) {
        const accepted = command.acceptance orelse return error.MissingAcceptance;
        if (!std.mem.eql(u8, &accepted.public_evidence_sha256, &parsed.value.public_evidence_sha256.?) or
            !std.mem.eql(u8, &accepted.public_command_sha256, &parsed.value.public_command_sha256.?) or
            !std.mem.eql(u8, &accepted.phase_nonce, &parsed.value.public_nonce.?) or
            !std.mem.eql(u8, &accepted.host_boot_id, &parsed.value.host_boot_id)) return error.AcceptanceMismatch;
    }
}

pub const Locator = struct {
    document: core.contracts.Document,
    scope: p.Scope,
};

pub fn parseLocator(allocator: std.mem.Allocator, bytes: []const u8, admission: *const p.Admission) !Locator {
    var doc = try core.contracts.Document.parse(allocator, bytes, .{ .bytes = 4096, .string_bytes = 128, .items = 8, .tokens = 32, .depth = 2 });
    errdefer doc.deinit();
    const object = try core.contracts.exactFields(doc.value(), &.{ "account", "container", "run_id" });
    const scope: p.Scope = .{
        .account = try core.contracts.string(object.get("account").?),
        .container = try core.contracts.string(object.get("container").?),
        .run_id = try core.contracts.parseUuid(try core.contracts.string(object.get("run_id").?)),
    };
    try scope.validate();
    if (!std.mem.eql(u8, scope.account, admission.account) or !std.mem.eql(u8, scope.container, admission.container)) return error.NotAdmitted;
    return .{ .document = doc, .scope = scope };
}

pub const Action = enum { identify, command, download, publish };
pub const Job = struct {
    version: u8,
    action: Action,
    scope: p.Scope,
    vm_id: ?p.Uuid,
    phase: p.Phase,
    command_sha256: ?p.Hash,
    role: ?p.Role,
    artifact_name: ?[]const u8,
    evidence_name: ?[]const u8,
    payload_sha256: ?p.Hash,
    deadline_ns: u64,
};
pub const JobResult = struct {
    ok: bool = false,
    not_found: bool = false,
    vm_id: ?p.Uuid = null,
    publication: state.Publication = .not_started,
    failures: core.diagnostics.Failures = .{},
};

pub const Supervised = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_path: []const u8,
    self_executable: []const u8,
    locked: *core.private_files.Locked,
    store: ?*state.Store,
    scope: p.Scope,
    vm_id: ?p.Uuid,
    deadline: core.process.Deadline,
    last_failures: core.diagnostics.Failures = .{},
    next_call: u16 = 0,
    last_directory: ?[]u8 = null,

    pub fn deinit(self: *Supervised) void {
        if (self.last_directory) |path| self.allocator.free(path);
    }

    pub fn remote(self: *Supervised) worker.Remote {
        return .{ .context = self, .fetchFn = fetch, .downloadFn = download, .publishFn = publish, .failuresFn = failures };
    }

    fn job(self: *Supervised, action: Action, phase: p.Phase) Job {
        return .{ .version = 1, .action = action, .scope = self.scope, .vm_id = self.vm_id, .phase = phase, .command_sha256 = null, .role = null, .artifact_name = null, .evidence_name = null, .payload_sha256 = null, .deadline_ns = self.deadline.expires_ns };
    }

    fn encode(self: *Supervised, value: anytype) ![]u8 {
        const raw = try std.json.Stringify.valueAlloc(self.allocator, value, .{});
        defer self.allocator.free(raw);
        var doc = try core.contracts.Document.parse(self.allocator, raw, .{});
        defer doc.deinit();
        return doc.canonicalAlloc(self.allocator);
    }

    pub fn call(self: *Supervised, request: Job, payload: ?[]const u8) !JobResult {
        if (try self.deadline.expired()) return error.AttemptExpired;
        self.last_failures = .{};
        const encoded = try self.encode(request);
        defer self.allocator.free(encoded);
        const call_index = if (self.store) |store| store.record.wire_calls else self.next_call;
        if (call_index >= 256) return error.OperationLimit;
        if (self.store) |store| {
            const reserve: u64 = encoded.len + 4096 + @as(u64, if (request.action == .command) p.max_command else 0);
            try store.reserve(reserve, true, false);
            if (payload) |bytes| try store.reserve(bytes.len, request.evidence_name != null and std.mem.eql(u8, request.evidence_name.?, "receipt.json"), false);
            store.record.wire_calls += 1;
            store.record.wire_inflight = true;
            try store.save();
        } else self.next_call += 1;
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "wire-{d}", .{call_index});
        try self.locked.directory.dir.createDir(self.io, name, .fromMode(0o700));
        if (self.last_directory) |previous| self.allocator.free(previous);
        self.last_directory = try std.fs.path.join(self.allocator, &.{ self.directory_path, name });
        const directory = try files.durableDirectory(self.io, self.last_directory.?);
        defer directory.close(self.io);
        var lock = try directory.lock(self.io);
        defer lock.close(self.io);
        if (!files.isDurable(try lock.createImmutable(self.io, "job.json", encoded))) return error.StateNotDurable;
        if (payload) |bytes| {
            const result = try lock.createImmutable(self.io, "payload.bin", bytes);
            if (!files.isDurable(result)) return error.StateNotDurable;
        }
        lock.close(self.io);
        var environment: std.process.Environ.Map = .init(self.allocator);
        defer environment.deinit();
        var result = try core.process.run(self.allocator, self.io, .{
            .argv = &.{ self.self_executable, "--wire-child" },
            .environment = &environment,
            .cwd = directory.dir,
            .deadline = .{ .expires_ns = @min(self.deadline.expires_ns, request.deadline_ns) },
            .cleanup_ms = p.cleanup_ms,
            .stdout_limit = 0,
            .stderr_limit = 1024,
        });
        defer result.deinit(self.allocator);
        self.last_failures = result.failures;
        if (result.failures.primary != null or !result.cleanup_complete) {
            if (self.store) |store| store.fail(result.failures);
            return error.WireWorkerFailed;
        }
        const bytes = try directory.read(self.io, self.allocator, "result.json", 4096, null);
        defer self.allocator.free(bytes);
        var doc = try core.contracts.Document.parse(self.allocator, bytes, .{});
        defer doc.deinit();
        try doc.requireCanonical(self.allocator, bytes);
        const parsed = try std.json.parseFromSlice(JobResult, self.allocator, bytes, .{ .ignore_unknown_fields = false });
        defer parsed.deinit();
        const response = parsed.value;
        self.last_failures = response.failures;
        if (self.store) |store| {
            var unused: u64 = 4096 - bytes.len;
            if (request.action == .command) {
                if (response.ok) {
                    const command_file = try directory.openFile(self.io, "command.json");
                    defer command_file.close(self.io);
                    const size = (try command_file.stat(self.io)).size;
                    if (size > p.max_command) return error.ResponseLimit;
                    unused += p.max_command - size;
                } else if (response.not_found) unused += p.max_command;
            }
            store.record.staging_bytes -= unused;
            store.record.control_bytes -= unused;
            store.record.wire_inflight = false;
            try store.save();
        }
        return response;
    }

    fn fetch(context: *anyopaque, phase: p.Phase) ![]u8 {
        const self: *Supervised = @ptrCast(@alignCast(context));
        const result = try self.call(self.job(.command, phase), null);
        if (result.not_found) return error.NotFound;
        if (!result.ok) return error.CommandTransferFailed;
        const directory = try core.private_files.Directory.open(self.io, self.last_directory.?);
        defer directory.close(self.io);
        return directory.read(self.io, self.allocator, "command.json", p.max_command, null);
    }

    fn download(context: *anyopaque, command: *const p.Command, artifact: p.Artifact, destination: []const u8) !void {
        const self: *Supervised = @ptrCast(@alignCast(context));
        const expected = try std.fs.path.join(self.allocator, &.{ artifact_root, artifact.name });
        defer self.allocator.free(expected);
        if (!std.mem.eql(u8, destination, expected)) return error.InvalidDestination;
        var request = self.job(.download, command.phase);
        request.deadline_ns = try self.commandDeadline(command);
        request.command_sha256 = command.verified.digest;
        request.role = artifact.role;
        request.artifact_name = artifact.name;
        const result = try self.call(request, null);
        if (!result.ok) return error.ArtifactTransferFailed;
    }

    fn publish(context: *anyopaque, command: *const p.Command, name: []const u8, bytes: []const u8) wire.PublishResult {
        const self: *Supervised = @ptrCast(@alignCast(context));
        var request = self.job(.publish, command.phase);
        request.deadline_ns = self.commandDeadline(command) catch return .{ .publication = .not_started, .failure = .{ .stage = .blob_upload, .category = .timeout } };
        request.command_sha256 = command.verified.digest;
        request.evidence_name = name;
        request.payload_sha256 = p.hash(bytes);
        const result = self.call(request, bytes) catch {
            return .{ .publication = .unknown, .failure = .{ .stage = .blob_upload, .category = .ambiguous } };
        };
        return .{ .publication = result.publication, .failure = result.failures.recording };
    }

    fn failures(context: *anyopaque) core.diagnostics.Failures {
        const self: *Supervised = @ptrCast(@alignCast(context));
        return self.last_failures;
    }

    fn commandDeadline(self: *Supervised, command: *const p.Command) !u64 {
        var clock: u8 = 0;
        const now = try wallSeconds(&clock);
        if (now >= command.expires_at) return error.StaleCommand;
        const deadline = try core.process.Deadline.afterMilliseconds(@min(p.attempt_ms, (command.expires_at - now) * 1000));
        return @min(self.deadline.expires_ns, deadline.expires_ns);
    }
};

pub fn wireChild(init: std.process.Init, comptime key: [32]u8) !void {
    var image = try Image.load(init.gpa, init.io, key);
    defer image.deinit();
    try requireSupervisor(init.gpa, init.io, &image);
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const length = try files.cwdPath(init.io, &path);
    if (!std.mem.startsWith(u8, path[0..length], state_root ++ "/wire-")) return error.InvalidWorkerDirectory;
    const directory = try files.durableDirectory(init.io, path[0..length]);
    defer directory.close(init.io);
    var lock = try directory.lock(init.io);
    defer lock.close(init.io);
    const bytes = try directory.read(init.io, init.gpa, "job.json", 8192, null);
    defer init.gpa.free(bytes);
    var doc = try core.contracts.Document.parse(init.gpa, bytes, .{});
    defer doc.deinit();
    try doc.requireCanonical(init.gpa, bytes);
    const parsed = try std.json.parseFromSlice(Job, init.gpa, bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const request = parsed.value;
    if (request.version != 1 or request.deadline_ns == 0) return error.InvalidJob;
    try request.scope.validate();
    if (!std.mem.eql(u8, request.scope.account, image.admission.account) or !std.mem.eql(u8, request.scope.container, image.admission.container)) return error.NotAdmitted;
    const claim = try lock.createImmutable(init.io, "consumed", "");
    if (!files.isDurable(claim)) return error.StateNotDurable;
    var clock: u8 = 0;
    const http: std.http.Client = .{ .allocator = init.gpa, .io = init.io };
    var runtime: wire.NativeRuntime = .init(http);
    defer runtime.deinit();
    var cancellation: sdk.http.CancellationToken = .{};
    var client: wire.Client = .{
        .allocator = init.gpa,
        .io = init.io,
        .runtime = runtime.runtime(),
        .scope = request.scope,
        .budget = .{ .context = &clock, .now_ms = monotonicMs, .deadline_ms = request.deadline_ns / std.time.ns_per_ms, .cancellation = &cancellation },
    };
    defer client.deinit();
    const result = executeJob(init, key, &image.admission, request, &client, &lock) catch |err| JobResult{
        .not_found = err == error.NotFound and request.action == .command,
        .publication = if (request.action == .publish) .unknown else .not_started,
        .failures = .{ .primary = .{
            .stage = if (request.action == .identify) .credential else .host_phase,
            .category = switch (err) {
                error.NotFound => .not_found,
                error.AuthenticationFailed, error.InvalidTokenResponse => .authentication,
                error.AuthorizationFailed => .authorization,
                error.DeadlineExceeded => .timeout,
                error.Cancelled => .cancelled,
                error.ArtifactIntegrity, error.ScopeMismatch, error.VmIdentityChanged => .integrity,
                else => .invalid_response,
            },
        } },
    };
    const raw = try std.json.Stringify.valueAlloc(init.gpa, result, .{});
    defer init.gpa.free(raw);
    var result_doc = try core.contracts.Document.parse(init.gpa, raw, .{});
    defer result_doc.deinit();
    const output = try result_doc.canonicalAlloc(init.gpa);
    defer init.gpa.free(output);
    if (!files.isDurable(try lock.createImmutable(init.io, "result.json", output))) return error.StateNotDurable;
}

fn executeJob(init: std.process.Init, key: [32]u8, admission: *const p.Admission, request: Job, client: *wire.Client, locked: *core.private_files.Locked) !JobResult {
    if (request.action == .identify) return .{ .ok = true, .vm_id = try client.identify() };
    const vm_id = request.vm_id orelse return error.InvalidJob;
    var clock: u8 = 0;
    try client.authenticate(vm_id, try wallSeconds(&clock));
    if (request.action == .command) {
        const bytes = try client.command(request.phase, try wallSeconds(&clock));
        defer init.gpa.free(bytes);
        if (!files.isDurable(try locked.createImmutable(init.io, "command.json", bytes))) return error.StateNotDurable;
        return .{ .ok = true };
    }
    const directory = try files.durableDirectory(init.io, state_root);
    defer directory.close(init.io);
    const command_bytes = try directory.read(init.io, init.gpa, if (request.phase == .public) "public-intent.json" else "private-intent.json", p.max_command, request.command_sha256 orelse return error.InvalidJob);
    defer init.gpa.free(command_bytes);
    var command = try p.Command.parse(init.gpa, command_bytes, key, admission, request.scope, vm_id, try wallSeconds(&clock));
    defer command.deinit();
    if (request.action == .download) {
        const role = request.role orelse return error.InvalidJob;
        const name = request.artifact_name orelse return error.InvalidJob;
        var selected: ?p.Artifact = null;
        for (command.artifacts) |record| if (record.role == role and std.mem.eql(u8, record.name, name)) {
            selected = record;
        };
        const artifact = selected orelse return error.InvalidArtifact;
        const parent = try files.parent(init.gpa, init.io, artifact_root, artifact.name, false);
        defer parent.close(init.io);
        const checked = try parent.directory.openFile(init.io, parent.name);
        defer checked.close(init.io);
        if ((try checked.stat(init.io)).size != 0) return error.ArtifactAlreadyStaged;
        const file = try parent.directory.dir.openFile(init.io, parent.name, .{ .mode = .read_write, .follow_symlinks = false });
        defer file.close(init.io);
        if ((try file.stat(init.io)).inode != (try checked.stat(init.io)).inode) return error.ArtifactChanged;
        try client.download(artifact, request.phase, file, try wallSeconds(&clock));
        return .{ .ok = true };
    }
    if (request.action != .publish) return error.InvalidJob;
    const payload = try locked.directory.read(init.io, init.gpa, "payload.bin", p.max_serial, request.payload_sha256 orelse return error.InvalidJob);
    defer {
        std.crypto.secureZero(u8, payload);
        init.gpa.free(payload);
    }
    const result = client.publish(request.phase, command.phase_nonce, request.evidence_name orelse return error.InvalidJob, payload, try wallSeconds(&clock));
    return .{ .ok = result.publication == .complete, .publication = result.publication, .failures = .{ .recording = result.failure } };
}

pub fn run(init: std.process.Init, comptime key: [32]u8) !void {
    if (builtin.cpu.arch != .x86_64) return error.UnsupportedArchitecture;
    var image = try Image.load(init.gpa, init.io, key);
    defer image.deinit();
    const policy = try core.private_files.Directory.open(init.io, policy_root);
    defer policy.close(init.io);
    const locator_bytes = try policy.read(init.io, init.gpa, "locator.json", 4096, null);
    defer init.gpa.free(locator_bytes);
    var location = try parseLocator(init.gpa, locator_bytes, &image.admission);
    defer location.document.deinit();
    const directory = try files.durableDirectory(init.io, state_root);
    defer directory.close(init.io);
    var locked = try directory.lock(init.io);
    defer locked.close(init.io);
    try core.process.initialize();
    const start = try core.process.Deadline.afterMilliseconds(p.attempt_ms);
    const boot_id = try files.hostBootId(init.io);
    var supervised: Supervised = .{
        .allocator = init.gpa,
        .io = init.io,
        .directory_path = state_root,
        .self_executable = "/proc/self/exe",
        .locked = &locked,
        .store = null,
        .scope = location.scope,
        .vm_id = null,
        .deadline = start,
    };
    defer supervised.deinit();
    // An interrupted first identity probe cannot silently start a new attempt.
    const claim = try locked.createImmutable(init.io, "attempt-started", &p.uuidText(location.scope.run_id));
    if (!files.isDurable(claim)) return error.StateNotDurable;
    const identity = try supervised.call(supervised.job(.identify, .public), null);
    if (!identity.ok or identity.vm_id == null) return error.IdentityUnavailable;
    var initial = try state.Record.initial(location.scope.run_id, identity.vm_id.?, boot_id, image.admission.image_staging_bytes, image.admission.image_control_bytes);
    initial.deadline_ns = start.expires_ns;
    initial.wire_calls = supervised.next_call;
    var store = try state.Store.open(init.gpa, init.io, &locked, initial);
    try store.reserve(image.policy_bytes + locator_bytes.len + 8192, true, false);
    supervised.store = &store;
    supervised.vm_id = identity.vm_id;
    supervised.deadline = .{ .expires_ns = store.record.deadline_ns };
    for ([_][]const u8{ "artifacts", "boots" }) |name| {
        directory.dir.createDir(init.io, name, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        try files.syncDirectory(init.io, directory.dir);
    }
    var clock: u8 = 0;
    var engine: worker.Engine = .{
        .allocator = init.gpa,
        .io = init.io,
        .key = key,
        .admission = &image.admission,
        .scope = location.scope,
        .vm_id = identity.vm_id.?,
        .clock_context = &clock,
        .nowFn = wallSeconds,
        .remote = supervised.remote(),
        .store = &store,
        .runner = .{ .allocator = init.gpa, .io = init.io, .self_executable = "/proc/self/exe", .artifact_root = artifact_root, .work_root = boot_root, .attempt_deadline = supervised.deadline },
    };
    while (store.record.stage == .empty or store.record.stage == .public_done) {
        if (try supervised.deadline.expired() or try wallSeconds(&clock) >= image.admission.expires_at) {
            store.fail(.{ .primary = .{ .stage = .host_phase, .category = .timeout } });
            return error.AttemptExpired;
        }
        const phase: p.Phase = if (store.record.stage == .empty) .public else .private;
        const bytes = engine.remote.fetchFn(engine.remote.context, phase) catch |err| {
            if (err == error.NotFound) {
                try init.io.sleep(.fromSeconds(5), .awake);
                continue;
            }
            store.fail(supervised.last_failures);
            return err;
        };
        defer init.gpa.free(bytes);
        engine.execute(bytes) catch |err| {
            if (store.record.stage != .failed) store.fail(.{ .primary = .{ .stage = .host_phase, .category = .invalid_input } });
            return err;
        };
    }
    if (store.record.stage != .done) return error.PhaseFailed;
}
