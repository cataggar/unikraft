const std = @import("std");
const pf = @import("preflight");
const f = @import("fixture_support.zig");
const helpers = @import("tests.zig");
const blobs = @import("adapter_fixtures.zig");
const c = pf.contract;
const p = c.p;
const t = std.testing;
const a = t.allocator;
const io = t.io;

const RoleWire = struct {
    arena: std.heap.ArenaAllocator,
    mock: pf.sdk.http.MockTransport = .init(a, 404, ""),
    crypto: pf.sdk.crypto.StdCryptoProvider = .init(io),
    token: pf.azure.auth.Token,
    cancellation: pf.sdk.http.CancellationToken = .{},
    budget: pf.azure.transport.Budget = undefined,
    urls: [2][]const u8,
    paths: [2][]const u8,
    scope: []const u8,
    group: []const u8,
    group_url: []const u8,
    properties: [2]?[]const u8 = .{ null, null },
    missing_body: []const u8 = "{\"error\":{\"code\":\"RoleAssignmentNotFound\"}}",
    missing_status: u16 = 404,
    wrong_scope: bool = false,
    wrong_id: bool = false,
    calls: usize = 0,
    puts: usize = 0,
    deletes: usize = 0,
    seconds: i64 = f.now,
    millis: u64 = 1000,

    fn init(input: *const c.Input) !RoleWire {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        const authority = input.approved.authority;
        const account = try input.approved.resources.storage.path(scratch, authority);
        const scope = try std.fmt.allocPrint(scratch, "{s}/blobServices/default/containers/preflight", .{account});
        var paths: [2][]const u8 = undefined;
        var urls: [2][]const u8 = undefined;
        for (&paths, &urls, [_]c.Uuid{ input.approved.resources.input_role, input.approved.resources.evidence_role }) |*path, *url, id| {
            path.* = try std.fmt.allocPrint(scratch, "{s}/providers/Microsoft.Authorization/roleAssignments/{s}", .{ scope, id });
            url.* = try std.fmt.allocPrint(scratch, "{s}{s}?api-version=2022-04-01", .{ pf.azure.scope.arm_host, path.* });
        }
        const group_ref: pf.azure.scope.Ref = .{ .kind = .group, .name = authority.group };
        const group_path = try group_ref.path(scratch, authority);
        const group_url = try std.fmt.allocPrint(scratch, "{s}{s}?api-version={s}", .{ pf.azure.scope.arm_host, group_path, group_ref.kind.version() });
        const group = try c.canonical(scratch, .{ .id = group_path, .name = authority.group, .location = authority.location, .tags = .{ .@"uk-hyperv-run" = @as([]const u8, &authority.owner_run) }, .properties = .{ .provisioningState = "Succeeded" } });
        const token: pf.azure.auth.Token = .{ .value = try pf.azure.secret.Bytes.copy(a, "synthetic-token"), .expires_on = f.now + 86400, .tenant = authority.tenant, .subscription = authority.subscription, .principal = authority.principal, .client = authority.client };
        return .{ .arena = arena, .token = token, .paths = paths, .urls = urls, .scope = scope, .group = group, .group_url = group_url };
    }
    fn deinit(self: *RoleWire) void {
        self.token.deinit();
        self.mock.deinit();
        self.arena.deinit();
    }
    fn client(self: *RoleWire, input: *const c.Input) pf.azure.client.Client {
        self.budget = .{ .clock = .{ .context = self, .monotonicMsFn = mono, .unixSecondsFn = unix, .sleepMsFn = sleep }, .deadline_ms = 120000, .cancellation = &self.cancellation };
        return .{ .allocator = a, .authority = input.approved.authority, .token = &self.token, .channel = .{ .allocator = a, .budget = &self.budget, .runtime = .init(.{ .context = self, .vtable = &.{ .send = forbidden, .open = open } }, self.crypto.asProvider()) } };
    }
    fn mono(context: *anyopaque) u64 {
        return (@as(*RoleWire, @ptrCast(@alignCast(context)))).millis;
    }
    fn unix(context: *anyopaque) i64 {
        return (@as(*RoleWire, @ptrCast(@alignCast(context)))).seconds;
    }
    fn sleep(context: *anyopaque, ms: u32) !void {
        (@as(*RoleWire, @ptrCast(@alignCast(context)))).millis += ms;
    }
    fn forbidden(_: *anyopaque, _: *pf.sdk.http.Request) !pf.sdk.http.Response {
        return error.BufferedTransportForbidden;
    }
    fn open(context: *anyopaque, request: *pf.sdk.http.Request, options: pf.sdk.http.OpenOptions) !*pf.sdk.http.HttpOperation {
        const self: *RoleWire = @ptrCast(@alignCast(context));
        self.calls += 1;
        try t.expect(!request.retryable and request.redirect_policy == .not_allowed);
        try t.expect(request.getHeader("Authorization") != null);
        if (std.mem.eql(u8, request.url, self.group_url)) {
            try t.expectEqual(pf.sdk.http.Method.GET, request.method);
            self.mock.response_status = 200;
            self.mock.response_body = self.group;
            return self.mock.asTransport().open(request, options);
        }
        const index: usize = if (std.mem.eql(u8, request.url, self.urls[0])) 0 else if (std.mem.eql(u8, request.url, self.urls[1])) 1 else return error.WrongRoleScope;
        switch (request.method) {
            .PUT => {
                if (self.properties[index] != null) return error.ReplayedRole;
                try t.expectEqualStrings("*", request.getHeader("If-None-Match").?);
                self.properties[index] = try self.arena.allocator().dupe(u8, request.body.?);
                self.puts += 1;
                self.mock.response_status = 201;
                self.mock.response_body = "";
            },
            .DELETE => {
                if (self.properties[index] == null) return error.ReplayedRole;
                self.properties[index] = null;
                self.deletes += 1;
                self.mock.response_status = 204;
                self.mock.response_body = "";
            },
            .GET => {
                if (self.properties[index]) |bytes| {
                    var document = try pf.core.contracts.Document.parse(self.arena.allocator(), bytes, .{});
                    defer document.deinit();
                    var properties = document.value().object.get("properties").?;
                    try properties.object.put(self.arena.allocator(), "scope", .{ .string = if (self.wrong_scope) "/subscriptions/other" else self.scope });
                    self.mock.response_status = 200;
                    self.mock.response_body = try c.canonical(self.arena.allocator(), .{ .id = if (self.wrong_id) self.paths[1 - index] else self.paths[index], .properties = properties });
                } else {
                    self.mock.response_status = self.missing_status;
                    self.mock.response_body = self.missing_body;
                }
            },
            else => return error.UnexpectedMethod,
        }
        return self.mock.asTransport().open(request, options);
    }
};

test "review role-specific wire absence enables exact creation deletion and independent absence" {
    const directory = try helpers.Directory.create("review-role");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try helpers.prepare(&fixture);
    var state = try helpers.state(&fixture);
    state.principal_id = f.principal;
    var wire = try RoleWire.init(&fixture.input);
    defer wire.deinit();
    var client = wire.client(&fixture.input);
    var adapter: pf.adapters.arm.Adapter = .{ .client = &client, .input = &fixture.input };
    _ = try adapter.roles(&state, false);
    try t.expectEqual(@as(usize, 2), wire.puts);
    _ = try adapter.roles(&state, true);
    try t.expectEqual(@as(usize, 2), wire.deletes);
    _ = try adapter.roles(&state, true);
    try t.expectEqual(@as(usize, 14), wire.calls);
    try t.expectEqual(pf.core.diagnostics.ServiceCode.RoleAssignmentNotFound, adapter.failure.diagnostic.service_code);
    try t.expect(pf.adapters.arm.roleAbsent(adapter.failure));
    try t.expect(!pf.adapters.arm.absence(adapter.failure, true) and !pf.adapters.arm.absence(adapter.failure, false));
}

test "review role absence refuses authorization unknown malformed conflicting and resource 404 codes" {
    const directory = try helpers.Directory.create("review-role-negative");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try helpers.prepare(&fixture);
    var state = try helpers.state(&fixture);
    state.principal_id = f.principal;
    const Case = struct { status: u16 = 404, body: []const u8, header: ?[]const u8 = null, code: pf.core.diagnostics.ServiceCode };
    const cases = [_]Case{
        .{ .status = 403, .body = "{\"error\":{\"code\":\"RoleAssignmentNotFound\"}}", .code = .RoleAssignmentNotFound },
        .{ .body = "{\"error\":{\"code\":\"UnknownRole\"}}", .code = .unknown },
        .{ .body = "{\"error\":{\"code\":true}}", .code = .malformed },
        .{ .body = "{\"error\":{\"code\":\"ResourceNotFound\"}}", .code = .ResourceNotFound },
        .{ .body = "{\"error\":{\"code\":\"ResourceGroupNotFound\"}}", .code = .ResourceGroupNotFound },
        .{ .body = "{\"error\":{\"code\":\"RoleAssignmentNotFound\"}}", .header = "ResourceNotFound", .code = .conflicting },
    };
    for (cases) |case| for ([_]bool{ false, true }) |remove| {
        var wire = try RoleWire.init(&fixture.input);
        defer wire.deinit();
        wire.missing_body = case.body;
        wire.missing_status = case.status;
        var header: [1]pf.sdk.http.MockTransport.HeaderPair = undefined;
        if (case.header) |value| {
            header[0] = .{ .name = "x-ms-error-code", .value = value };
            wire.mock.response_headers_list = &header;
        }
        var client = wire.client(&fixture.input);
        var adapter: pf.adapters.arm.Adapter = .{ .client = &client, .input = &fixture.input };
        try t.expectError(error.ArmOperationFailed, adapter.roles(&state, remove));
        try t.expectEqual(case.code, adapter.failure.diagnostic.service_code);
        try t.expectEqual(@as(usize, 1), wire.calls);
        try t.expectEqual(@as(usize, 0), wire.puts + wire.deletes);
    };
    for ([_]bool{ false, true }) |wrong_id| {
        var wire = try RoleWire.init(&fixture.input);
        defer wire.deinit();
        var client = wire.client(&fixture.input);
        var adapter: pf.adapters.arm.Adapter = .{ .client = &client, .input = &fixture.input };
        _ = try adapter.roles(&state, false);
        wire.wrong_id = wrong_id;
        wire.wrong_scope = !wrong_id;
        try t.expectError(error.RoleMismatch, adapter.roles(&state, true));
        try t.expectEqual(@as(usize, 0), wire.deletes);
    }
}

test "review initial state cannot be published outside its reservation and every checkpoint copy is charged" {
    for ([_]bool{ false, true }) |sufficient| {
        const directory = try helpers.Directory.create("review-initial-budget");
        defer directory.deinit();
        var fixture = try f.Context.init(a, io, directory.value, directory.path);
        defer fixture.deinit();
        const base = c.emergency_bytes + c.worker_output_reservation;
        if (!sufficient) {
            fixture.input.approved.budget.controller.control = base + 16000;
            try fixture.refreshAdmission(f.now - 60);
            const authority = try c.canonical(a, fixture.input.approved);
            defer a.free(authority);
            // Leave 64 bytes after the admitted context; not enough for state.
            fixture.input.approved.budget.controller.control = base + authority.len + 64;
            try fixture.refreshAdmission(f.now - 60);
        }
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        if (!sufficient) {
            try t.expectError(error.RecordingBudgetExceeded, pf.journal.Store.prepare(a, io, &lock, &fixture.input, f.now));
            try t.expectError(error.FileNotFound, directory.value.openFile(io, "state.json"));
            try t.expectError(error.FileNotFound, directory.value.openFile(io, "recovery.json"));
            const authority = try directory.value.read(io, a, "admitted-context.json", c.max_state, null);
            defer a.free(authority);
            try t.expect(base + authority.len <= fixture.input.approved.budget.controller.control);
            try t.expectError(error.AttemptConsumed, pf.journal.Store.prepare(a, io, &lock, &fixture.input, f.now));
        } else {
            const store = try pf.journal.Store.prepare(a, io, &lock, &fixture.input, f.now);
            const authority = try directory.value.read(io, a, "admitted-context.json", c.max_state, null);
            defer a.free(authority);
            const final = try directory.value.read(io, a, "state.json", c.max_state, null);
            defer a.free(final);
            var initial_state = store.state;
            initial_state.spent.staged -= 2 * final.len;
            initial_state.spent.control -= 2 * final.len;
            const initial = try c.canonical(a, initial_state);
            defer a.free(initial);
            try t.expectEqual(base + authority.len + initial.len + 2 * final.len, store.state.spent.control);
            try t.expectEqual(store.state.spent.control, store.state.spent.staged);
            const recovered = try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input);
            try t.expectEqual(store.state.spent, recovered.state.spent);
        }
    }
}

// Override only the selected syscall; all real transfer/filesystem work still
// uses std.testing.io. No fault selector is linked into a production worker.
const IoFault = struct {
    table: std.Io.VTable = io.vtable.*,
    name: []const u8,
    deletion: bool,
    pending_sync: ?std.posix.fd_t = null,
    failures: usize = 0,
    threadlocal var active: ?*IoFault = null;

    fn install(self: *IoFault) std.Io {
        std.debug.assert(active == null);
        active = self;
        self.table.dirDeleteFile = deleteFile;
        self.table.fileSync = sync;
        return .{ .userdata = io.userdata, .vtable = &self.table };
    }
    fn deinit(_: *IoFault) void {
        active = null;
    }
    fn deleteFile(userdata: ?*anyopaque, dir: std.Io.Dir, name: []const u8) std.Io.Dir.DeleteFileError!void {
        const self = active.?;
        if (std.mem.eql(u8, name, self.name) and self.failures == 0) {
            if (self.deletion) {
                self.failures += 1;
                return error.AccessDenied;
            }
            self.pending_sync = dir.handle;
        }
        return io.vtable.dirDeleteFile(userdata, dir, name);
    }
    fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active.?;
        if (self.pending_sync == file.handle) {
            self.pending_sync = null;
            self.failures += 1;
            return error.InputOutput;
        }
        return io.vtable.fileSync(userdata, file);
    }
};

test "review original admission instant survives role and storage operations then expired execution cleanup" {
    const directory = try helpers.Directory.create("review-admission-clock");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try blobs.publicFiles(&fixture);
    try fixture.refreshAdmission(f.now - 50);
    try t.expectError(error.StaleCommand, fixture.input.validate(a, fixture.input.approved.not_before));
    try helpers.prepare(&fixture);
    try helpers.until(&fixture, .publish_public);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try t.expectEqual(f.now, store.state.admitted_at);
    try blobs.capability(&store);
    const source = try fixture.bundle(.public, &store.state);
    var blob: blobs.BlobWire = .{ .responses = &.{ source.receipt, source.logs[0], source.logs[1] } };
    defer blob.mock.deinit();
    var wire = try RoleWire.init(&fixture.input);
    defer wire.deinit();
    var client = wire.client(&fixture.input);
    var native: pf.adapters.Native = .{
        .store = &store,
        .arm_client = &client,
        .cleanup_token = &wire.token,
        .storage_adapter = .{ .store = &store, .runtime = blob.runtime(), .budget = try blob.budget(), .root = directory.path },
    };
    var roles: pf.adapters.arm.Adapter = .{ .client = &client, .input = &fixture.input };
    _ = try roles.roles(&store.state, false);
    const cwd = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer cwd.close(io);
    defer if (std.os.linux.errno(std.os.linux.fchdir(cwd.handle)) != .SUCCESS) @panic("fixture cwd restore");
    const backend = native.backend();
    _ = try backend.stageFn(backend.context, .public, &store.state);
    const command = try directory.value.read(io, a, "public-command.json", p.max_command, null);
    defer a.free(command);
    _ = try backend.publishFn(backend.context, .public, command, &store.state);
    const bundle = try backend.fetchFn(backend.context, .public, store.state.public_nonce, &store.state);
    defer backend.releaseFn(backend.context, bundle);
    try t.expectEqual(@as(usize, 8), blob.calls);

    wire.seconds = @intCast(fixture.input.approved.expires_at + 1);
    try t.expectError(error.AuthorityExpired, backend.stageFn(backend.context, .public, &store.state));
    try t.expectError(error.AuthorityExpired, backend.publishFn(backend.context, .public, command, &store.state));
    try t.expectError(error.AuthorityExpired, backend.fetchFn(backend.context, .public, store.state.public_nonce, &store.state));
    try t.expectError(error.AuthorityExpired, backend.controlFn(backend.context, .grant_access, &store.state));
    try t.expectEqual(@as(usize, 8), blob.calls);
    _ = try backend.controlFn(backend.context, .revoke_roles, &store.state);
    try t.expectEqual(@as(usize, 2), wire.deletes);
    blob.status = 403;
    blob.mock.response_headers_list = &.{.{ .name = "x-ms-error-code", .value = "AuthenticationFailed" }};
    _ = try backend.controlFn(backend.context, .prove_sas_revoked, &store.state);
    const recovered = try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input);
    try t.expectEqual(f.now, recovered.state.admitted_at);
    try t.expect(recovered.state.failures.primary == null and recovered.state.failures.cleanup == null and recovered.state.failures.recording == null);
    const calls = wire.calls + blob.calls;
    wire.seconds = @intCast(fixture.input.approved.cleanup_expires_at);
    try t.expectError(error.AuthorityExpired, backend.controlFn(backend.context, .revoke_roles, &store.state));
    try t.expectError(error.AuthorityExpired, backend.controlFn(backend.context, .prove_sas_revoked, &store.state));
    try t.expectEqual(calls, wire.calls + blob.calls);
}

test "review accepted and uncertain worker transfers survive subsequent credential deletion and fsync failures durably" {
    for ([_]bool{ false, true }) |uncertain| for ([_]bool{ false, true }) |deletion| {
        const directory = try helpers.Directory.create("review-transfer-cleanup");
        defer directory.deinit();
        var fixture = try f.Context.init(a, io, directory.value, directory.path);
        defer fixture.deinit();
        try blobs.publicFiles(&fixture);
        try helpers.prepare(&fixture);
        try helpers.until(&fixture, .grant_access);
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        var fault: IoFault = .{ .name = "capability", .deletion = deletion };
        const fault_io = fault.install();
        defer fault.deinit();
        var store = try pf.journal.Store.open(a, fault_io, &lock, &fixture.input);
        try blobs.capability(&store);
        var blob: blobs.BlobWire = .{};
        defer blob.mock.deinit();
        if (uncertain) blob.mock.stream_fail_upload_after = 37;
        var wire = try RoleWire.init(&fixture.input);
        defer wire.deinit();
        var client = wire.client(&fixture.input);
        var native: pf.adapters.Native = .{
            .store = &store,
            .arm_client = &client,
            .cleanup_token = &wire.token,
            .storage_adapter = .{ .store = &store, .runtime = blob.runtime(), .budget = try blob.budget(), .root = directory.path },
        };
        const cwd = try std.Io.Dir.cwd().openDir(io, ".", .{});
        defer cwd.close(io);
        defer if (std.os.linux.errno(std.os.linux.fchdir(cwd.handle)) != .SUCCESS) @panic("fixture cwd restore");
        var engine: pf.engine.Engine = .{ .store = &store, .backend = native.backend(), .signer = &fixture.signer, .now = f.now, .monotonic_ns = try pf.core.process.monotonicNanoseconds(), .owner_pid = std.os.linux.getppid(), .operator_boot_id = f.boot };
        try engine.step(false);
        try t.expectEqual(@as(usize, 1), fault.failures);
        try t.expectEqual(@as(usize, if (uncertain) 1 else 4), blob.calls);
        const recovered = try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input);
        try t.expectEqual(c.Phase.cleaning, recovered.state.phase);
        const entry = recovered.state.actions[@intFromEnum(c.Action.stage_public)];
        try t.expectEqual(pf.journal.Status.unknown, entry.status);
        try t.expectEqual(if (uncertain) pf.azure.transport.Effect.unknown else .accepted, entry.effect);
        try t.expectEqual(entry.effect, native.last.effect);
        try t.expect(recovered.state.failures.primary != null and recovered.state.failures.cleanup != null);
        if (!deletion) try t.expect(recovered.state.failures.recording != null);
        if (uncertain) try t.expectEqual(pf.core.diagnostics.Category.transport, recovered.state.failures.primary.?.category);
        try t.expectEqual(entry.effect, (try pf.journal.Store.open(a, io, &lock, &fixture.input)).state.actions[@intFromEnum(c.Action.stage_public)].effect);
    };
}

test "review expected revocation 403 cannot discharge output cleanup or sync failure and unknown statuses fail" {
    const Case = struct { fault: ?bool = null, status: u16 = 403, code: []const u8 = "AuthenticationFailed" };
    const cases = [_]Case{
        .{},                                           .{ .fault = true },                                 .{ .fault = false },
        .{ .status = 404, .code = "UnknownResource" }, .{ .status = 403, .code = "AuthorizationFailure" }, .{ .status = 200 },
    };
    for (cases) |case| {
        const directory = try helpers.Directory.create("review-revocation");
        defer directory.deinit();
        var fixture = try f.Context.init(a, io, directory.value, directory.path);
        defer fixture.deinit();
        try fixture.refreshAdmission(f.now - 50);
        try helpers.prepare(&fixture);
        try helpers.until(&fixture, .grant_access);
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        var fault: IoFault = .{ .name = "revocation-probe", .deletion = case.fault orelse false };
        const fault_io = if (case.fault != null) fault.install() else io;
        defer if (case.fault != null) fault.deinit();
        var store = try pf.journal.Store.open(a, fault_io, &lock, &fixture.input);
        try blobs.capability(&store);
        var blob: blobs.BlobWire = .{ .status = case.status };
        defer blob.mock.deinit();
        const headers = [_]pf.sdk.http.MockTransport.HeaderPair{.{ .name = "x-ms-error-code", .value = case.code }};
        blob.mock.response_headers_list = &headers;
        var wire = try RoleWire.init(&fixture.input);
        defer wire.deinit();
        wire.seconds = @intCast(fixture.input.approved.expires_at + 1);
        var client = wire.client(&fixture.input);
        var native: pf.adapters.Native = .{
            .store = &store,
            .arm_client = &client,
            .cleanup_token = &wire.token,
            .storage_adapter = .{ .store = &store, .runtime = blob.runtime(), .budget = try blob.budget(), .root = directory.path },
        };
        const backend = native.backend();
        if (case.fault == null and case.status == 403 and std.mem.eql(u8, case.code, "AuthenticationFailed")) {
            _ = try backend.controlFn(backend.context, .prove_sas_revoked, &store.state);
            try t.expect(store.state.failures.cleanup == null and store.state.failures.recording == null);
        } else {
            try t.expectError(error.DataPlaneRevocationUnproved, backend.controlFn(backend.context, .prove_sas_revoked, &store.state));
            if (case.fault != null) {
                try t.expectEqual(@as(usize, 1), fault.failures);
                try t.expectEqual(pf.core.diagnostics.Category.cleanup_failed, store.state.failures.cleanup.?.category);
                try store.save();
                try t.expect((try pf.journal.Store.openRecovery(a, io, &lock, &fixture.input)).state.failures.cleanup != null);
            }
        }
        try t.expectEqual(@as(usize, 1), blob.calls);
    }
}

test "review expected revocation authentication failure retains explicit recording and earlier primary lanes" {
    const directory = try helpers.Directory.create("review-revocation-lanes");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try helpers.prepare(&fixture);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    var blob: blobs.BlobWire = .{};
    defer blob.mock.deinit();
    var storage: pf.adapters.storage.Adapter = .{ .store = &store, .runtime = blob.runtime(), .budget = try blob.budget(), .root = directory.path };
    var outcome: pf.transfer.Outcome = .{
        .side_effect = .not_applicable,
        .diagnostic = .{ .stage = .download_open, .category = .authorization, .status = 403, .service = .{ .state = .known, .code = .AuthenticationFailed, .header = .known, .header_code = .AuthenticationFailed } },
    };
    try storage.requireRevocation(outcome);
    outcome.diagnostic.category = .transport;
    try t.expectError(error.DataPlaneRevocationUnproved, storage.requireRevocation(outcome));
    outcome.diagnostic.category = .authorization;
    const earlier: pf.core.diagnostics.Diagnostic = .{ .stage = .process_run, .category = .timeout };
    store.fail(.primary, earlier);
    const recording: pf.core.diagnostics.Diagnostic = .{ .stage = .state_record, .category = .local_io };
    outcome.failures.recording = recording;
    try t.expectError(error.DataPlaneRevocationUnproved, storage.requireRevocation(outcome));
    try t.expectEqual(recording, store.state.failures.recording.?);
    try t.expectEqual(earlier, store.state.failures.primary.?);
    outcome.failures = .{ .primary = .{ .stage = .private_file, .category = .local_io } };
    try t.expectError(error.DataPlaneRevocationUnproved, storage.requireRevocation(outcome));
    try t.expectEqual(outcome.failures.primary.?, store.state.failures.cleanup.?);
    try t.expectEqual(recording, store.state.failures.recording.?);
    try t.expectEqual(earlier, store.state.failures.primary.?);
}

test "review missing stale and substituted initial admission times fail normal and recovery loading" {
    const directory = try helpers.Directory.create("review-admission-binding");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try fixture.refreshAdmission(f.now - 50);
    try helpers.prepare(&fixture);
    try helpers.until(&fixture, .metadata);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    const bytes = try c.canonical(a, store.state);
    defer a.free(bytes);
    var document = try pf.core.contracts.Document.parse(a, bytes, .{});
    defer document.deinit();
    var value = document.value();
    try t.expect(value.object.swapRemove("admitted_at"));
    const missing = try c.canonical(a, value);
    defer a.free(missing);
    try t.expectError(error.MissingField, c.parse(pf.journal.State, a, missing));
    store.state.admitted_at = fixture.input.approved.not_before;
    try store.save();
    try t.expectError(error.StaleCommand, pf.journal.Store.open(a, io, &lock, &fixture.input));
    try t.expectError(error.StaleCommand, pf.journal.Store.openRecovery(a, io, &lock, &fixture.input));
    store.state.admitted_at = f.now - 1;
    try store.save();
    try t.expectError(error.InvalidIntent, pf.journal.Store.open(a, io, &lock, &fixture.input));
    try t.expectError(error.InvalidIntent, pf.journal.Store.openRecovery(a, io, &lock, &fixture.input));
    store.state.admitted_at = f.now + 1;
    try t.expectError(error.InvalidAdmissionTime, store.save());
}
