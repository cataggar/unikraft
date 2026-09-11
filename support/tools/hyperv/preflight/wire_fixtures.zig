const std = @import("std");
const pf = @import("preflight");
const f = @import("fixture_support.zig");
const c = pf.contract;
const t = std.testing;
const a = t.allocator;
const io = t.io;

const Wire = struct {
    mock: pf.sdk.http.MockTransport,
    crypto: pf.sdk.crypto.StdCryptoProvider = .init(io),
    calls: usize = 0,
    now_ms: u64 = 1000,
    token: pf.azure.auth.Token,
    budget: pf.azure.transport.Budget = undefined,
    cancellation: pf.sdk.http.CancellationToken = .{},
    group_flow: bool = false,
    group_exists: bool = false,
    group_body: []const u8 = "",
    group_url: []const u8 = "",
    fn init(authority: pf.azure.scope.Authority, status: u16, body: []const u8) !Wire {
        return .{ .mock = .init(a, status, body), .token = .{ .value = try pf.azure.secret.Bytes.copy(a, "synthetic-token"), .expires_on = f.now + 86400, .tenant = authority.tenant, .subscription = authority.subscription, .principal = authority.principal, .client = authority.client } };
    }
    fn deinit(self: *Wire) void {
        self.mock.deinit();
        self.token.deinit();
    }
    fn client(self: *Wire, authority: pf.azure.scope.Authority) pf.azure.client.Client {
        self.budget = .{ .clock = .{ .context = self, .monotonicMsFn = mono, .unixSecondsFn = unix, .sleepMsFn = sleep }, .deadline_ms = 120000, .cancellation = &self.cancellation };
        return .{ .allocator = a, .authority = authority, .token = &self.token, .channel = .{ .allocator = a, .budget = &self.budget, .runtime = .init(.{ .context = self, .vtable = &.{ .send = forbidden, .open = open } }, self.crypto.asProvider()) } };
    }
    fn mono(context: *anyopaque) u64 {
        return (@as(*Wire, @ptrCast(@alignCast(context)))).now_ms;
    }
    fn unix(_: *anyopaque) i64 {
        return f.now;
    }
    fn sleep(context: *anyopaque, ms: u32) !void {
        (@as(*Wire, @ptrCast(@alignCast(context)))).now_ms += ms;
    }
    fn forbidden(_: *anyopaque, _: *pf.sdk.http.Request) !pf.sdk.http.Response {
        return error.BufferedTransportForbidden;
    }
    fn open(context: *anyopaque, request: *pf.sdk.http.Request, options: pf.sdk.http.OpenOptions) !*pf.sdk.http.HttpOperation {
        const self: *Wire = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (request.retryable or request.redirect_policy != .not_allowed or request.getHeader("Authorization") == null or
            !std.mem.startsWith(u8, request.url, pf.azure.scope.arm_host ++ "/subscriptions/") or (!self.group_flow and request.method != .GET))
            return error.UnexpectedRequest;
        if (self.group_flow) {
            if (!std.ascii.startsWithIgnoreCase(request.url, self.group_url) or request.url.len <= self.group_url.len) return error.UnexpectedRequest;
            const suffix = request.url[self.group_url.len..];
            if (std.mem.startsWith(u8, suffix, "/resources?") and request.method == .GET) {
                self.mock.response_status = 200;
                self.mock.response_body = "{\"value\":[]}";
            } else if (suffix[0] == '?') {
                switch (request.method) {
                    .GET => {
                        self.mock.response_status = if (self.group_exists) 200 else 404;
                        self.mock.response_body = if (self.group_exists) self.group_body else "{\"error\":{\"code\":\"ResourceGroupNotFound\"}}";
                    },
                    .PUT => {
                        if (self.group_exists) return error.MutationReplay;
                        var body = try pf.core.contracts.Document.parse(a, request.body orelse return error.MissingGroupBody, .{});
                        defer body.deinit();
                        try t.expectEqualStrings(&f.run, try pf.azure.models.string(try pf.azure.models.field(body.value(), "tags"), "uk-hyperv-run"));
                        self.group_exists = true;
                        self.mock.response_status = 201;
                        self.mock.response_body = self.group_body;
                    },
                    .DELETE => {
                        if (!self.group_exists) return error.MutationReplay;
                        self.group_exists = false;
                        self.mock.response_status = 202;
                        self.mock.response_body = "";
                    },
                    else => return error.UnexpectedRequest,
                }
            } else return error.UnexpectedRequest;
        }
        return self.mock.asTransport().open(request, options);
    }
};

test "native ARM adapter distinguishes independent recognized absence from authorization and unknown 404" {
    const directory = try @import("tests.zig").Directory.create("wire-absence");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    const Case = struct { status: u16, body: []const u8, absent: bool };
    const cases = [_]Case{
        .{ .status = 403, .body = "{\"error\":{\"code\":\"AuthorizationFailure\",\"message\":\"SYNTHETIC_SECRET\"}}", .absent = false },
        .{ .status = 404, .body = "{\"error\":{\"code\":\"ResourceGroupNotFound\",\"message\":\"SYNTHETIC_SECRET\"}}", .absent = true },
        .{ .status = 404, .body = "{\"error\":{\"code\":\"UnknownFailure\",\"message\":\"SYNTHETIC_SECRET\"}}", .absent = false },
    };
    for (cases) |case| {
        var wire = try Wire.init(fixture.input.approved.authority, case.status, case.body);
        defer wire.deinit();
        var client = wire.client(fixture.input.approved.authority);
        var adapter: pf.adapters.arm.Adapter = .{ .client = &client, .input = &fixture.input };
        if (case.absent) try t.expect(try adapter.groupAbsent()) else try t.expectError(error.ArmOperationFailed, adapter.groupAbsent());
        try t.expectEqual(@as(usize, 1), wire.calls);
    }
}

test "native backend dispatch and cleanup authority expiry happen before transport" {
    const directory = try @import("tests.zig").Directory.create("native-adapter");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.prepare(a, io, &lock, &fixture.input, f.now);
    var wire = try Wire.init(fixture.input.approved.authority, 404, "{\"error\":{\"code\":\"ResourceGroupNotFound\"}}");
    defer wire.deinit();
    var client = wire.client(fixture.input.approved.authority);
    var native: pf.adapters.Native = .{
        .store = &store,
        .arm_client = &client,
        .cleanup_token = &wire.token,
        .storage_adapter = .{ .store = &store, .runtime = client.channel.runtime, .root = directory.path, .budget = .{ .context = &wire, .nowMsFn = nowMs, .deadline_ms = 120000, .cancellation = &wire.cancellation } },
    };
    const backend = native.backend();
    const proof = try backend.controlFn(backend.context, .prove_group_absent, &store.state);
    try t.expectEqual(pf.azure.transport.Effect.not_applicable, proof.effect);
    wire.token.expires_on = f.now + 1;
    try t.expectError(error.TokenExpired, backend.controlFn(backend.context, .prove_group_absent, &store.state));
    try t.expectEqual(@as(usize, 1), wire.calls);
}
fn nowMs(context: *anyopaque) !u64 {
    return (@as(*Wire, @ptrCast(@alignCast(context)))).now_ms;
}

test "native account SAS has exact historical scope and synthetic key only" {
    var encoded: [88]u8 = undefined;
    const key = [_]u8{0x51} ** 64;
    _ = std.base64.standard.Encoder.encode(&encoded, &key);
    var sas = try pf.adapters.storage.signSas(a, "fixtureaccount", &encoded, f.now + 3000);
    defer sas.deinit();
    try t.expect(pf.transfer.request.validSas(sas.bytes));
    try t.expect(std.mem.startsWith(u8, sas.bytes, "sv=2024-11-04&ss=b&srt=sco&sp=rcw&spr=https&se="));
    try t.expect(std.mem.indexOf(u8, sas.bytes, "&sig=") != null);
    try t.expectError(error.InvalidAccount, pf.adapters.storage.signSas(a, "other/host", &encoded, f.now));
}

test "concrete native group create delete absence and expired-authority local secret disposal" {
    const directory = try @import("tests.zig").Directory.create("group-lifecycle");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    const authority = fixture.input.approved.authority;
    const ref: pf.azure.scope.Ref = .{ .kind = .group, .name = authority.group };
    const path = try ref.path(a, authority);
    defer a.free(path);
    const url = try std.mem.concat(a, u8, &.{ pf.azure.scope.arm_host, path });
    defer a.free(url);
    const body = try c.canonical(a, .{ .id = path, .name = authority.group, .location = authority.location, .tags = .{ .@"uk-hyperv-run" = @as([]const u8, &authority.owner_run) }, .properties = .{ .provisioningState = "Succeeded" } });
    defer a.free(body);
    var wire = try Wire.init(authority, 404, "");
    defer wire.deinit();
    wire.group_flow = true;
    wire.group_body = body;
    wire.group_url = url;
    var client = wire.client(authority);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.prepare(a, io, &lock, &fixture.input, f.now);
    var native: pf.adapters.Native = .{
        .store = &store,
        .arm_client = &client,
        .cleanup_token = &wire.token,
        .storage_adapter = .{ .store = &store, .runtime = client.channel.runtime, .root = directory.path, .budget = .{ .context = &wire, .nowMsFn = nowMs, .deadline_ms = 120000, .cancellation = &wire.cancellation } },
    };
    const backend = native.backend();
    const created = try backend.controlFn(backend.context, .create_group, &store.state);
    try t.expectEqual(pf.azure.transport.Effect.accepted, created.effect);
    try t.expect(wire.group_exists);
    const removed = try backend.controlFn(backend.context, .delete_group, &store.state);
    try t.expectEqual(pf.azure.transport.Effect.accepted, removed.effect);
    const absent = try backend.controlFn(backend.context, .prove_group_absent, &store.state);
    try t.expectEqual(pf.azure.transport.Effect.not_applicable, absent.effect);
    try t.expect(!std.mem.eql(u8, &removed.digest, &absent.digest));
    try store.immutable("storage-capability", "synthetic", true);
    try store.immutable("caller-authority", "synthetic-caller-owned", true);
    for ([_][]const u8{ "transfer-public", "transfer-private" }) |name| {
        try directory.value.dir.createDir(io, name, .fromMode(0o700));
        const child = try directory.value.dir.openDir(io, name, .{ .follow_symlinks = false });
        defer child.close(io);
        try child.writeFile(io, .{ .sub_path = "capability", .data = "synthetic", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    }
    const calls = wire.calls;
    wire.token.expires_on = f.now;
    _ = try backend.controlFn(backend.context, .dispose_credentials, &store.state);
    try t.expectEqual(calls, wire.calls);
    try t.expectError(error.FileNotFound, directory.value.openFile(io, "storage-capability"));
    const retained = try directory.value.openFile(io, "caller-authority");
    retained.close(io);
    for ([_][]const u8{ "transfer-public", "transfer-private" }) |name| {
        const child = try directory.value.dir.openDir(io, name, .{ .follow_symlinks = false });
        defer child.close(io);
        try t.expectError(error.FileNotFound, child.openFile(io, "capability", .{}));
    }
}
