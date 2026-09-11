const std = @import("std");
const pf = @import("preflight");
const f = @import("fixture_support.zig");
const helpers = @import("tests.zig");
const c = pf.contract;
const p = c.p;
const t = std.testing;
const a = t.allocator;
const io = t.io;

test "specialized deployment has exact array types Standard envelope and closed outbound route" {
    const directory = try helpers.Directory.create("template");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    const bytes = try pf.adapters.arm.deploymentBody(a, &fixture.input);
    defer a.free(bytes);
    var doc = try pf.core.contracts.Document.parse(a, bytes, .{ .bytes = 32768, .items = 1024, .tokens = 8192 });
    defer doc.deinit();
    const field = pf.azure.models.field;
    const resources = try pf.azure.models.array(try field(try field(try field(doc.value(), "properties"), "template"), "resources"));
    try t.expectEqual(@as(usize, 6), resources.len);
    try pf.adapters.arm.validateNetwork(a, &fixture.input, .nsg, resources[0]);
    const subnet = (try pf.azure.models.array(try field(try field(resources[1], "properties"), "subnets")))[0];
    try t.expect(!try pf.azure.models.boolean(try field(try field(subnet, "properties"), "defaultOutboundAccess")));
    const storage = try field(resources[3], "properties");
    const acl = try field(storage, "networkAcls");
    try t.expectEqual(@as(usize, 0), (try pf.azure.models.array(try field(acl, "ipRules"))).len);
    try t.expectEqual(@as(usize, 0), (try pf.azure.models.array(try field(acl, "resourceAccessRules"))).len);
    try t.expectEqual(@as(usize, 1), (try pf.azure.models.array(try field(acl, "virtualNetworkRules"))).len);
    const vm = try field(resources[4], "properties");
    try t.expectEqualStrings("Standard", try pf.azure.models.string(try field(vm, "securityProfile"), "securityType"));
    const profile = try field(vm, "storageProfile");
    try t.expectEqual(@as(usize, 0), (try pf.azure.models.array(try field(profile, "dataDisks"))).len);
    try t.expectEqual(@as(u64, 32), try pf.core.contracts.integer(u64, try field(try field(profile, "osDisk"), "diskSizeGB")));
    // A missing agentless readback is a deployment/admission blocker, not true.
    try t.expectError(error.MissingField, pf.adapters.arm.validateAgentless(&fixture.input, resources[4]));
}

test "agentless property admission rejects missing metadata identity substitutions and enabled agents" {
    const directory = try helpers.Directory.create("agentless");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    const bytes = try c.canonical(a, .{
        .tags = .{ .@"uk-hyperv-run" = @as([]const u8, &f.run) },
        .identity = .{ .type = "SystemAssigned", .tenantId = @as([]const u8, &fixture.input.approved.authority.tenant), .principalId = @as([]const u8, &f.principal) },
        .properties = .{ .osProfile = .{ .linuxConfiguration = .{ .provisionVMAgent = false }, .allowExtensionOperations = false }, .storageProfile = .{ .imageReference = .{ .id = fixture.input.approved.image_id } } },
    });
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    try t.expectEqual(f.principal, try pf.adapters.arm.validateAgentless(&fixture.input, parsed.value));
    const os = &parsed.value.object.getPtr("properties").?.object.getPtr("osProfile").?.object;
    os.getPtr("allowExtensionOperations").?.* = .{ .bool = true };
    try t.expectError(error.AgentNotDisabled, pf.adapters.arm.validateAgentless(&fixture.input, parsed.value));
    os.getPtr("allowExtensionOperations").?.* = .{ .bool = false };
    parsed.value.object.getPtr("identity").?.object.getPtr("tenantId").?.* = .{ .string = &f.disk };
    try t.expectError(error.IdentityNotAdmitted, pf.adapters.arm.validateAgentless(&fixture.input, parsed.value));
    parsed.value.object.getPtr("identity").?.object.getPtr("tenantId").?.* = .{ .string = &fixture.input.approved.authority.tenant };
    _ = os.swapRemove("allowExtensionOperations");
    try t.expectError(error.MissingField, pf.adapters.arm.validateAgentless(&fixture.input, parsed.value));
}

test "role readback binds exact assignment id container scope principal definition and condition" {
    const path = "/subscriptions/fixture/resourceGroups/owned/providers/Microsoft.Storage/storageAccounts/owned/blobServices/default/containers/owned/providers/Microsoft.Authorization/roleAssignments/fixed";
    const scope = path[0..std.mem.indexOf(u8, path, "/providers/Microsoft.Authorization").?];
    const wanted = try c.canonical(a, .{ .properties = .{ .principalId = "synthetic", .roleDefinitionId = "reader", .condition = @as(?[]const u8, null) } });
    defer a.free(wanted);
    const actual = try c.canonical(a, .{ .id = path, .properties = .{ .scope = scope, .principalId = "synthetic", .roleDefinitionId = "reader" } });
    defer a.free(actual);
    try pf.adapters.arm.validateRole(a, actual, wanted, path);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, actual, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    parsed.value.object.getPtr("properties").?.object.getPtr("scope").?.* = .{ .string = "/subscriptions/other" };
    const substituted = try c.canonical(a, parsed.value);
    defer a.free(substituted);
    try t.expectError(error.RoleMismatch, pf.adapters.arm.validateRole(a, substituted, wanted, path));
    try t.expectError(error.RoleMismatch, pf.adapters.arm.validateRole(a, actual, wanted, path ++ "-other"));
}

const BlobWire = struct {
    mock: pf.sdk.http.MockTransport = .init(a, 201, ""),
    crypto: pf.sdk.crypto.StdCryptoProvider = .init(io),
    token: pf.sdk.http.CancellationToken = .{},
    responses: []const []const u8 = &.{},
    calls: usize = 0,
    downloads: usize = 0,
    status: ?u16 = null,
    fn runtime(self: *BlobWire) pf.sdk.http.HttpRuntime {
        return .init(.{ .context = self, .vtable = &.{ .send = forbidden, .open = open } }, self.crypto.asProvider());
    }
    fn budget(self: *BlobWire) !pf.transfer.Budget {
        return .{ .context = self, .nowMsFn = now, .deadline_ms = try now(self) + 300000, .cancellation = &self.token };
    }
    fn now(_: *anyopaque) !u64 {
        return try pf.core.process.monotonicNanoseconds() / std.time.ns_per_ms;
    }
    fn forbidden(_: *anyopaque, _: *pf.sdk.http.Request) !pf.sdk.http.Response {
        return error.BufferedTransportForbidden;
    }
    fn open(context: *anyopaque, request: *pf.sdk.http.Request, options: pf.sdk.http.OpenOptions) !*pf.sdk.http.HttpOperation {
        const self: *BlobWire = @ptrCast(@alignCast(context));
        if (!std.mem.startsWith(u8, request.url, "https://fixtureaccount.blob.core.windows.net/preflight/runs/" ++ f.run ++ "/") or
            request.retryable or request.redirect_policy != .not_allowed or request.getHeader("Authorization") != null)
            return error.InvalidFixtureRequest;
        self.calls += 1;
        if (request.method == .PUT) {
            try t.expectEqualStrings("*", request.getHeader("If-None-Match") orelse return error.NotCreateOnly);
            try t.expect(options.body != null and !options.body.?.isReplayable());
            self.mock.response_body = "";
            self.mock.response_status = self.status orelse 201;
        } else if (request.method == .GET) {
            self.mock.response_status = self.status orelse 200;
            self.mock.response_body = if (self.downloads < self.responses.len) self.responses[self.downloads] else "";
            self.downloads += 1;
        } else return error.InvalidFixtureRequest;
        self.mock.stream_upload_chunk_size = 37;
        self.mock.stream_response_chunk_size = 29;
        return self.mock.asTransport().open(request, options);
    }
};
fn capability(store: *pf.journal.Store) !void {
    try store.immutable("storage-capability", "sv=2024-11-04&sp=rcw&sig=SYNTHETIC%2BONLY%3D", true);
    try store.save();
}

test "native Blob command publication and evidence retrieval use bounded streaming create-only requests" {
    const directory = try helpers.Directory.create("blob-protocol");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try helpers.prepare(&fixture);
    try helpers.until(&fixture, .publish_public);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try capability(&store);
    const source = try fixture.bundle(.public, &store.state);
    var wire: BlobWire = .{ .responses = &.{ source.receipt, source.logs[0], source.logs[1] } };
    defer wire.mock.deinit();
    var storage: pf.adapters.storage.Adapter = .{ .store = &store, .runtime = wire.runtime(), .budget = try wire.budget(), .root = directory.path };
    const bytes = try directory.value.read(io, a, "public-command.json", p.max_command, null);
    defer a.free(bytes);
    try t.expectEqual(p.hash(bytes), try storage.publish(.public, bytes));
    try t.expectEqualSlices(u8, bytes, wire.mock.last_body.?);
    const bundle = try storage.fetch(.public, store.state.public_nonce);
    defer storage.release(bundle);
    try t.expectEqualSlices(u8, source.receipt, bundle.receipt);
    try t.expectEqualSlices(u8, source.logs[0], bundle.logs[0]);
    try t.expectEqual(@as(usize, 4), wire.calls);
    try t.expectEqual(@as(usize, 0), wire.mock.stream_finish_count);
    try t.expectError(error.PrematurePrivateTransfer, storage.stage(.private));
    try t.expectEqual(@as(usize, 4), wire.calls);
}

test "native Blob rejection redirect ambiguity overflow and malformed framing never retry mutations" {
    for ([_]u16{ 403, 409, 302 }) |status| {
        const directory = try helpers.Directory.create("blob-reject");
        defer directory.deinit();
        var fixture = try f.Context.init(a, io, directory.value, directory.path);
        defer fixture.deinit();
        try helpers.prepare(&fixture);
        var lock = try directory.value.lock(io);
        defer lock.close(io);
        var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
        try capability(&store);
        try store.immutable("public-command.json", "synthetic command", true);
        var wire: BlobWire = .{ .status = status };
        defer wire.mock.deinit();
        var storage: pf.adapters.storage.Adapter = .{ .store = &store, .runtime = wire.runtime(), .budget = try wire.budget(), .root = directory.path };
        try t.expectError(error.TransferFailed, storage.publish(.public, "synthetic command"));
        try t.expectEqual(@as(usize, 1), wire.calls);
    }
    const directory = try helpers.Directory.create("blob-oversize");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try helpers.prepare(&fixture);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try capability(&store);
    const oversized = try a.alloc(u8, p.max_command + 1);
    defer a.free(oversized);
    @memset(oversized, 'x');
    var wire: BlobWire = .{ .responses = &.{oversized} };
    defer wire.mock.deinit();
    var storage: pf.adapters.storage.Adapter = .{ .store = &store, .runtime = wire.runtime(), .budget = try wire.budget(), .root = directory.path };
    try t.expectError(error.TransferFailed, storage.fetch(.public, store.state.public_nonce));
    try t.expectEqual(@as(usize, 1), wire.calls);
    try t.expectError(error.FileNotFound, directory.value.openFile(io, "download-public-receipt"));
}

test "partial native command upload preserves ambiguity and conflicting lengths fail closed" {
    const directory = try helpers.Directory.create("blob-ambiguous");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    try helpers.prepare(&fixture);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try capability(&store);
    const bytes = [_]u8{'x'} ** 512;
    try store.immutable("public-command.json", &bytes, true);
    var wire: BlobWire = .{};
    defer wire.mock.deinit();
    wire.mock.stream_fail_upload_after = 37;
    var storage: pf.adapters.storage.Adapter = .{ .store = &store, .runtime = wire.runtime(), .budget = try wire.budget(), .root = directory.path };
    try t.expectError(error.TransferFailed, storage.publish(.public, &bytes));
    try t.expectEqual(@as(usize, 1), wire.calls);
    try t.expectEqual(pf.azure.transport.Effect.unknown, storage.last.effect);
    wire.mock.response_headers_list = &.{ .{ .name = "Content-Length", .value = "0" }, .{ .name = "Content-Length", .value = "1" } };
    try t.expectError(error.TransferFailed, storage.fetch(.public, store.state.public_nonce));
    try t.expectEqual(@as(usize, 2), wire.calls);
    try t.expectError(error.FileNotFound, directory.value.openFile(io, "download-public-receipt"));
}

test "merged native transfer worker stages public files once without a nested supervisor" {
    const directory = try helpers.Directory.create("native-stage");
    defer directory.deinit();
    var fixture = try f.Context.init(a, io, directory.value, directory.path);
    defer fixture.deinit();
    const scratch = fixture.arena.allocator();
    const files = try scratch.dupe(c.File, fixture.input.preparation.files);
    fixture.input.preparation.files = files;
    try directory.value.dir.createDir(io, "qemu", .fromMode(0o700));
    try directory.value.dir.createDir(io, "qemu/bin", .fromMode(0o700));
    for (files[0..4]) |*file| {
        const bytes = try scratch.alloc(u8, @intCast(file.artifact.size));
        @memset(bytes, 0xa5);
        file.artifact.sha256 = p.hash(bytes);
        try directory.value.dir.writeFile(io, .{ .sub_path = file.artifact.name, .data = bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    }
    fixture.input.preparation.public = try f.manifest(scratch, files, .public, fixture.input.preparation.binding.preparation);
    fixture.input.preparation.private = try f.manifest(scratch, files, .private, fixture.input.preparation.binding.preparation);
    try helpers.prepare(&fixture);
    var lock = try directory.value.lock(io);
    defer lock.close(io);
    var store = try pf.journal.Store.open(a, io, &lock, &fixture.input);
    try capability(&store);
    var wire: BlobWire = .{};
    defer wire.mock.deinit();
    var storage: pf.adapters.storage.Adapter = .{ .store = &store, .runtime = wire.runtime(), .budget = try wire.budget(), .root = directory.path };
    const cwd = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer cwd.close(io);
    defer if (std.os.linux.errno(std.os.linux.fchdir(cwd.handle)) != .SUCCESS) @panic("fixture cwd restore");
    _ = try storage.stage(.public);
    try t.expectEqual(@as(usize, 4), wire.calls);
    try t.expectError(error.PathAlreadyExists, storage.stage(.public));
    try t.expectEqual(@as(usize, 4), wire.calls);
}
