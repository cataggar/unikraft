const std = @import("std");
const sdk = @import("azure_sdk_core");
const foundation = @import("hyperv_core");
const s = @import("scope.zig");
const secret = @import("secret.zig");
const wire = @import("transport.zig");
const auth = @import("auth.zig");
const ops = @import("operations.zig");
const models = @import("models.zig");
const client = @import("client.zig");
const json = @import("json.zig");
const admission = @import("admission.zig");
const t = std.testing;
const a = t.allocator;
const sub = "11111111-1111-4111-8111-111111111111";
const tenant = "22222222-2222-4222-8222-222222222222";
const application = "33333333-3333-4333-8333-333333333333";
const principal = "44444444-4444-4444-8444-444444444444";
const run = "55555555-5555-4555-8555-555555555555";
const vm_uuid = "66666666-6666-4666-8666-666666666666";
const disk_uuid = "77777777-7777-4777-8777-777777777777";
const operation_uuid = "88888888-8888-4888-8888-888888888888";
const authority: s.Authority = .{
    .tenant = tenant.*,
    .subscription = sub.*,
    .principal = principal.*,
    .client = application.*,
    .group = "synthetic-group",
    .location = "northeurope",
    .owner_run = run.*,
};
const group_path = "/subscriptions/" ++ sub ++ "/resourceGroups/synthetic-group";
const group_url = s.arm_host ++ group_path ++ "?api-version=2021-04-01";
const vm_path = group_path ++ "/providers/Microsoft.Compute/virtualMachines/synthetic-vm";
const vm_url = s.arm_host ++ vm_path ++ "?api-version=2025-11-01";
const disk_path = group_path ++ "/providers/Microsoft.Compute/disks/synthetic-disk";
const disk_url = s.arm_host ++ disk_path ++ "?api-version=2025-01-02";
const disk_operation_path = "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/DiskOperations/" ++ operation_uuid;
const disk_operation_context = "SYNTHETIC_PRIVATE%2b%2F%3d" ++ "a" ** (2956 - "SYNTHETIC_PRIVATE%2b%2F%3d".len);
const disk_operation_query = "?p=SYNTHETIC_PRIVATE%2bstate%2Fvalue%3d&api-version=2025-01-02&t=638000000000000000&c=" ++ disk_operation_context ++ "&s=SYNTHETIC_PRIVATE+state/==&h=SYNTHETIC_PRIVATE%2Bsignature%2f%3D";
const disk_status_url = s.arm_host ++ disk_operation_path ++ disk_operation_query;
const disk_location_url = disk_status_url ++ "&monitor=true";
const account_path = group_path ++ "/providers/Microsoft.Storage/storageAccounts/syntheticaccount";
const account_url = s.arm_host ++ account_path ++ "?api-version=2023-05-01";
const group_json = "{\"id\":\"" ++ group_path ++ "\",\"name\":\"synthetic-group\",\"location\":\"northeurope\",\"tags\":{\"uk-hyperv-run\":\"" ++ run ++ "\"},\"properties\":{\"provisioningState\":\"Succeeded\"}}";
const vm_json = "{\"id\":\"" ++ vm_path ++ "\",\"name\":\"synthetic-vm\",\"location\":\"northeurope\",\"properties\":{\"vmId\":\"" ++ vm_uuid ++ "\",\"provisioningState\":\"Succeeded\",\"securityProfile\":{\"securityType\":\"Standard\"},\"hardwareProfile\":{\"vmSize\":\"Standard_D2s_v5\"},\"storageProfile\":{\"osDisk\":{\"managedDisk\":{\"id\":\"" ++ disk_path ++ "\"}},\"dataDisks\":[]},\"networkProfile\":{\"networkInterfaces\":[{\"id\":\"" ++ group_path ++ "/providers/Microsoft.Network/networkInterfaces/synthetic-nic\"}]}}}";
const disk_json = "{\"id\":\"" ++ disk_path ++ "\",\"name\":\"synthetic-disk\",\"location\":\"northeurope\",\"sku\":{\"name\":\"StandardSSD_LRS\"},\"properties\":{\"uniqueId\":\"" ++ disk_uuid ++ "\",\"diskSizeGB\":4,\"logicalSectorSize\":512,\"provisioningState\":\"Succeeded\",\"diskState\":\"Unattached\",\"creationData\":{\"createOption\":\"Empty\"}}}";
const upload_disk_json = "{\"id\":\"" ++ disk_path ++ "\",\"name\":\"synthetic-disk\",\"location\":\"northeurope\",\"sku\":{\"name\":\"StandardSSD_LRS\"},\"properties\":{\"uniqueId\":\"" ++ disk_uuid ++ "\",\"diskSizeGB\":4,\"logicalSectorSize\":512,\"provisioningState\":\"Succeeded\",\"diskState\":\"ReadyToUpload\",\"creationData\":{\"createOption\":\"Upload\",\"uploadSizeBytes\":4294967808}}}";
const storage_json = "{\"id\":\"" ++ account_path ++ "\",\"name\":\"syntheticaccount\",\"location\":\"northeurope\",\"kind\":\"StorageV2\",\"sku\":{\"name\":\"Standard_LRS\"},\"properties\":{\"supportsHttpsTrafficOnly\":true,\"allowBlobPublicAccess\":false,\"minimumTlsVersion\":\"TLS1_2\",\"publicNetworkAccess\":\"Enabled\",\"provisioningState\":\"Succeeded\",\"networkAcls\":{\"bypass\":\"None\",\"defaultAction\":\"Deny\",\"ipRules\":[],\"virtualNetworkRules\":[],\"resourceAccessRules\":[]}}}";
const vm_ref: s.Ref = .{ .kind = .vm, .name = "synthetic-vm" };
const disk_ref: s.Ref = .{ .kind = .disk, .name = "synthetic-disk" };
const account_ref: s.Ref = .{ .kind = .storage, .name = "syntheticaccount" };
const group_ref: s.Ref = .{ .kind = .group, .name = "synthetic-group" };
const disk_identity: ops.DiskIdentity = .{ .disk = disk_ref, .original_uuid = disk_uuid.*, .geometry = .{ .sectors = 8388608, .sector_size = 512 } };

test "persistence fixed network uses pinned create readback and rejects altered envelope" {
    inline for (std.meta.tags(@FieldType(ops.PersistenceNetwork, "kind"))) |kind| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        const definition: ops.PersistenceNetwork = .{ .prefix = "synthetic", .kind = kind };
        const plan = try ops.Plan.create(alloc, authority, .{ .persistence_network = definition });
        try t.expectEqualStrings("2024-05-01", plan.version);
        const properties = switch (kind) {
            .nsg => "\"securityRules\":[]",
            .vnet => "\"addressSpace\":{\"addressPrefixes\":[\"10.79.0.0/29\"]},\"subnets\":[{\"name\":\"default\",\"id\":\"" ++ group_path ++ "/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/default\",\"properties\":{\"addressPrefix\":\"10.79.0.0/29\",\"defaultOutboundAccess\":false,\"networkSecurityGroup\":{\"id\":\"" ++ group_path ++ "/providers/Microsoft.Network/networkSecurityGroups/synthetic-nsg\"}}}]",
            .nic => "\"enableIPForwarding\":false,\"enableAcceleratedNetworking\":false,\"ipConfigurations\":[{\"name\":\"primary\",\"properties\":{\"privateIPAllocationMethod\":\"Dynamic\",\"privateIPAddress\":\"10.79.0.4\",\"subnet\":{\"id\":\"" ++ group_path ++ "/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/default\"}}}]",
        };
        const body = try std.fmt.allocPrint(alloc, "{{\"id\":\"{s}\",\"name\":\"synthetic-{s}\",\"location\":\"northeurope\",\"tags\":{{\"uk-hyperv-run\":\"{s}\"}},\"properties\":{{\"provisioningState\":\"Succeeded\",{s}}}}}", .{ plan.path, @tagName(kind), run, properties });
        try models.requirePersistenceNetwork(alloc, authority, definition, try json.parse(alloc, body));
        const failed = try std.mem.replaceOwned(u8, alloc, body, "\"provisioningState\":\"Succeeded\"", "\"provisioningState\":\"Failed\"");
        try t.expectError(error.InvalidNetwork, models.requirePersistenceNetwork(alloc, authority, definition, try json.parse(alloc, failed)));
        try models.requireOwnedPersistenceNetwork(alloc, authority, definition, try json.parse(alloc, failed));
        const unowned = try std.mem.replaceOwned(u8, alloc, failed, run, vm_uuid);
        try t.expectError(error.ScopeMismatch, models.requireOwnedPersistenceNetwork(alloc, authority, definition, try json.parse(alloc, unowned)));
        const bad = try std.mem.replaceOwned(u8, alloc, body, switch (kind) {
            .nsg => "\"securityRules\":[]",
            .vnet => "\"defaultOutboundAccess\":false",
            .nic => "\"enableIPForwarding\":false",
        }, switch (kind) {
            .nsg => "\"securityRules\":[{}]",
            .vnet => "\"defaultOutboundAccess\":true",
            .nic => "\"enableIPForwarding\":true",
        });
        if (models.requirePersistenceNetwork(alloc, authority, definition, try json.parse(alloc, bad))) |_|
            return error.AcceptedAlteredPersistenceNetwork
        else |_| {}
        if (models.requireOwnedPersistenceNetwork(alloc, authority, definition, try json.parse(alloc, bad))) |_|
            return error.AcceptedUnownedCleanupNetwork
        else |_| {}
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = plan.url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = plan.url, .method = .PUT, .status = 201, .response = body, .body_contains = plan.body },
            .{ .url = plan.url, .response = body },
        });
        defer h.deinit();
        var arm = h.arm();
        var result = try requireOk(arm.execute(.{ .persistence_network = definition }));
        defer result.deinit();
        try t.expectEqual(.accepted, result.effect);
        try t.expectEqual(.succeeded, result.model.network.state.?);
    }
}

test "persistence guest VHD upload geometry is MiB aligned with GiB allocation ceiling" {
    const bytes = 66 * 1024 * 1024 + 512;
    try ops.uploadGeometry(1, bytes);
    try ops.uploadGeometry(4, 4294967808);
    for ([_]u64{ 0, 512, 1024, bytes - 1, bytes + 512, 1024 * 1024 * 1024 + 1024 * 1024 + 512 }) |wrong|
        try t.expectError(error.InvalidGeometry, ops.uploadGeometry(1, wrong));
    try t.expectError(error.InvalidGeometry, ops.uploadGeometry(4, bytes));
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const plan = try ops.Plan.create(alloc, authority, .{ .disk_create = .{ .name = disk_ref.name, .size_gib = 1, .upload_bytes = bytes, .linux_gen2 = true } });
    const properties = try models.field(try json.parse(alloc, plan.body.?), "properties");
    try t.expectEqual(@as(u64, bytes), try foundation.contracts.integer(u64, try models.field(try models.field(properties, "creationData"), "uploadSizeBytes")));
    try t.expectEqualStrings("Linux", try models.string(properties, "osType"));
    try t.expectEqualStrings("V2", try models.string(properties, "hyperVGeneration"));
    const smaller = try std.mem.replaceOwned(u8, alloc, upload_disk_json, "\"diskSizeGB\":4", "\"diskSizeGB\":1");
    const no_role = try std.mem.replaceOwned(u8, alloc, smaller, "4294967808", "69206528");
    const body = try std.mem.replaceOwned(u8, alloc, no_role, "\"diskSizeGB\":1", "\"diskSizeGB\":1,\"diskSizeBytes\":69206016,\"osType\":\"Linux\",\"hyperVGeneration\":\"V2\"");
    for ([_][]const u8{ body, no_role }) |response| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = disk_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = disk_url, .method = .PUT, .status = 201, .response = response, .body_contains = "\"uploadSizeBytes\":69206528" },
            .{ .url = disk_url, .response = response },
        });
        defer h.deinit();
        var arm = h.arm();
        const result = arm.execute(plan.operation);
        if (std.mem.eql(u8, response, body)) {
            var accepted = try requireOk(result);
            defer accepted.deinit();
            try t.expectEqual(@as(u64, bytes), accepted.model.disk.upload_bytes.?);
            try t.expectEqual(@as(u64, bytes - 512), accepted.model.disk.bytes);
            try t.expect(accepted.model.disk.linux_gen2);
        } else try requireFailure(result, .integrity, .accepted, 200);
    }
}

test "persistence VM selects full original attachment envelope without changing default VM" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var data = disk_identity;
    data.disk.name = "synthetic-data";
    data.original_uuid = operation_uuid.*;
    for ([_]bool{ false, true }) |persistence| {
        const plan = try ops.Plan.create(alloc, authority, .{ .deploy = .{ .name = "synthetic-deployment", .resources = &.{.{ .vm = .{
            .name = vm_ref.name,
            .size = "Standard_D2s_v5",
            .nic = .{ .kind = .nic, .name = "synthetic-nic" },
            .os_disk = disk_identity,
            .data_disk = data,
            .persistence_envelope = persistence,
        } }} } });
        const template = try models.field(try models.field(try json.parse(alloc, plan.body.?), "properties"), "template");
        const resources = try models.array(try models.field(template, "resources"));
        const properties = try models.field(resources[0], "properties");
        const storage = try models.field(properties, "storageProfile");
        const os = try models.field(storage, "osDisk");
        const disk = (try models.array(try models.field(storage, "dataDisks")))[0];
        try t.expectEqualStrings(if (persistence) "ReadOnly" else "None", try models.string(os, "caching"));
        try t.expectEqual(@as(u8, 7), try foundation.contracts.integer(u8, try models.field(disk, "lun")));
        if (persistence) {
            try t.expectEqualStrings("Detach", try models.string(os, "deleteOption"));
            try t.expectEqualStrings("Detach", try models.string(disk, "deleteOption"));
            try t.expect(!try models.boolean(try models.field(disk, "writeAcceleratorEnabled")));
            const nic = (try models.array(try models.field(try models.field(properties, "networkProfile"), "networkInterfaces")))[0];
            try t.expectEqualStrings("Delete", try models.string(try models.field(nic, "properties"), "deleteOption"));
        } else {
            try t.expect(os.object.get("deleteOption") == null and disk.object.get("writeAcceleratorEnabled") == null);
        }
    }
}

const Progress = struct {
    fragment: usize = 1,
    zero_first: bool = false,
    fail_read: bool = false,
    stop: enum { none, deadline, cancellation } = .none,
    on: enum { data, zero, eof, failure } = .data,
};

const Step = struct {
    url: []const u8,
    method: sdk.http.Method = .GET,
    status: u16 = 200,
    response: []const u8 = "",
    headers: []const sdk.http.MockTransport.HeaderPair = &.{},
    authorization: bool = true,
    body_contains: ?[]const u8 = null,
    body_absent: bool = false,
    fail: bool = false,
    cancel: bool = false,
    progress: ?Progress = null,
};
const Harness = struct {
    steps: []const Step,
    calls: usize = 0,
    broken: bool = false,
    now_ms: u64 = 1000,
    unix: i64 = 1_800_000_000,
    budget: wire.Budget = undefined,
    initialized: bool = false,
    cancellation: sdk.http.CancellationToken = .{},
    crypto: sdk.crypto.StdCryptoProvider = .init(t.io),
    token: auth.Token,
    mock: ?sdk.http.MockTransport = null,
    response_reader: ?ProgressReader = null,
    response_calls: usize = 0,
    response_calls_after_stop: usize = 0,
    response_bytes: usize = 0,

    fn init(steps: []const Step) !Harness {
        return .{ .steps = steps, .token = .{
            .value = try secret.Bytes.copy(a, "synthetic-arm-token"),
            .expires_on = 1_800_086_400,
            .tenant = authority.tenant,
            .subscription = authority.subscription,
            .principal = authority.principal,
            .client = authority.client,
        } };
    }
    fn channel(self: *Harness) wire.Channel {
        if (!self.initialized) {
            self.budget = .{
                .clock = .{ .context = self, .monotonicMsFn = monotonic, .unixSecondsFn = unixSeconds, .sleepMsFn = sleep },
                .deadline_ms = 120_000,
                .cancellation = &self.cancellation,
            };
            self.initialized = true;
        }
        return .{ .allocator = a, .budget = &self.budget, .runtime = .init(
            .{ .context = self, .vtable = &.{ .send = bufferedForbidden, .open = open } },
            self.crypto.asProvider(),
        ) };
    }
    fn arm(self: *Harness) client.Client {
        return .{ .allocator = a, .authority = authority, .token = &self.token, .channel = self.channel() };
    }
    fn deinit(self: *Harness) void {
        self.finishMock();
        self.token.deinit();
        if (self.broken or self.calls != self.steps.len) {
            std.debug.print("synthetic calls={d}/{d} request_mismatch={}\n", .{ self.calls, self.steps.len, self.broken });
            @panic("synthetic HTTP request contract mismatch");
        }
    }
    fn finishMock(self: *Harness) void {
        if (self.mock) |*mock| {
            if (mock.call_count != mock.stream_deinit_count or mock.stream_finish_count != 0 or
                mock.stream_abort_count + mock.stream_cancel_count != mock.call_count) self.broken = true;
            mock.deinit();
            self.mock = null;
            self.response_reader = null;
        }
    }
    fn monotonic(context: *anyopaque) u64 {
        const self: *Harness = @ptrCast(@alignCast(context));
        return self.now_ms;
    }
    fn unixSeconds(context: *anyopaque) i64 {
        const self: *Harness = @ptrCast(@alignCast(context));
        return self.unix;
    }
    fn sleep(context: *anyopaque, ms: u32) !void {
        const self: *Harness = @ptrCast(@alignCast(context));
        self.now_ms += ms;
        self.unix += @intCast(ms / 1000);
    }
    fn bufferedForbidden(context: *anyopaque, _: *sdk.http.Request) !sdk.http.Response {
        const self: *Harness = @ptrCast(@alignCast(context));
        self.broken = true;
        return error.BufferedTransportForbidden;
    }
    fn open(context: *anyopaque, request: *sdk.http.Request, options: sdk.http.OpenOptions) !*sdk.http.HttpOperation {
        const self: *Harness = @ptrCast(@alignCast(context));
        if (self.calls >= self.steps.len) {
            self.broken = true;
            return error.UnexpectedRequest;
        }
        const step = self.steps[self.calls];
        self.calls += 1;
        if (!std.mem.eql(u8, step.url, request.url) or step.method != request.method or request.retryable or
            request.redirect_policy != .not_allowed or request.operation_timeout_ms == null or options.cancellation == null or
            !std.mem.eql(u8, request.getHeader("Accept-Encoding") orelse "", "identity") or
            (step.authorization and !std.mem.eql(u8, request.getHeader("Authorization") orelse "", "Bearer synthetic-arm-token")) or
            (!step.authorization and request.getHeader("Authorization") != null))
        {
            self.broken = true;
            return error.UnexpectedRequest;
        }
        if (step.body_contains) |needle| if (std.mem.indexOf(u8, request.body orelse "", needle) == null) {
            self.broken = true;
            return error.UnexpectedBody;
        };
        if (step.body_absent and request.body != null) {
            self.broken = true;
            return error.UnexpectedBody;
        }
        if (step.fail) return error.SYNTHETIC_SECRET_must_not_escape;
        if (step.cancel) self.cancellation.cancel();
        self.finishMock();
        self.mock = sdk.http.MockTransport.init(a, step.status, step.response);
        self.mock.?.response_headers_list = step.headers;
        const operation = try self.mock.?.asTransport().open(request, options);
        if (step.progress) |progress| {
            self.response_reader = .{
                .owner = self,
                .body = step.response,
                .progress = progress,
                .reader = .{ .vtable = &.{ .stream = ProgressReader.stream }, .buffer = &.{}, .seek = 0, .end = 0 },
            };
            operation.body_reader = &self.response_reader.?.reader;
        }
        return operation;
    }
};

const ProgressReader = struct {
    owner: *Harness,
    body: []const u8,
    progress: Progress,
    reader: std.Io.Reader,
    offset: usize = 0,
    sent_zero: bool = false,

    fn stop(self: *ProgressReader, event: @FieldType(Progress, "on")) void {
        if (event != self.progress.on) return;
        switch (self.progress.stop) {
            .none => {},
            .deadline => self.owner.now_ms = self.owner.budget.deadline_ms,
            .cancellation => self.owner.cancellation.cancel(),
        }
    }

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ProgressReader = @fieldParentPtr("reader", reader);
        self.owner.response_calls += 1;
        if (self.owner.cancellation.isCancelled() or self.owner.now_ms >= self.owner.budget.deadline_ms) {
            self.owner.response_calls_after_stop += 1;
            return error.ReadFailed;
        }
        if (self.progress.zero_first and !self.sent_zero) {
            self.sent_zero = true;
            self.stop(.zero);
            return 0;
        }
        if (self.progress.fail_read) {
            self.stop(.failure);
            return error.ReadFailed;
        }
        if (self.offset == self.body.len) {
            self.stop(.eof);
            return error.EndOfStream;
        }
        const count = try writer.write(self.body[self.offset..][0..@min(limit.minInt(self.progress.fragment), self.body.len - self.offset)]);
        self.offset += count;
        self.owner.response_bytes += count;
        self.stop(.data);
        return count;
    }
};

fn requireOk(outcome: wire.Outcome(client.Result)) !client.Result {
    return switch (outcome) {
        .ok => |result| result,
        .failed => |failure| {
            std.debug.print("synthetic outcome={s}/{s}/{s}\n", .{ @tagName(failure.diagnostic.stage), @tagName(failure.diagnostic.category), @tagName(failure.effect) });
            return error.UnexpectedFailure;
        },
    };
}
fn requireFailure(outcome: anytype, category: foundation.diagnostics.Category, effect: wire.Effect, status: ?u16) !void {
    switch (outcome) {
        .ok => |value| {
            var owned = value;
            owned.deinit();
            return error.ExpectedFailure;
        },
        .failed => |failure| {
            try t.expectEqual(category, failure.diagnostic.category);
            try t.expectEqual(effect, failure.effect);
            try t.expectEqual(status, failure.diagnostic.http_status);
            var writer = std.Io.Writer.Allocating.init(a);
            defer writer.deinit();
            try failure.write(&writer.writer);
            const rendered = try foundation.contracts.Document.parse(a, writer.written(), .{});
            defer rendered.deinit();
            _ = try foundation.contracts.exactFields(rendered.value(), &.{ "diagnostic", "effect", "oauth_code" });
            try t.expect(std.mem.indexOf(u8, writer.written(), "SYNTHETIC_SECRET") == null);
            try t.expect(std.mem.indexOf(u8, writer.written(), "SYNTHETIC_PRIVATE") == null);
            try t.expect(std.mem.indexOf(u8, writer.written(), "sig=") == null);
        },
    }
}

test "typed scope refuses injection cross-subscription and noncanonical identities" {
    const arena = try secret.Arena.create(a);
    defer arena.destroy();
    const alloc = arena.allocator();
    try t.expectEqualStrings(vm_path, try vm_ref.path(alloc, authority));
    try t.expectError(error.InvalidName, (s.Ref{ .kind = .vm, .name = "../escape" }).path(alloc, authority));
    try t.expectError(error.InvalidName, (s.Ref{ .kind = .vm, .name = "vm?api-version=bad" }).path(alloc, authority));
    try t.expectError(error.ScopeMismatch, vm_ref.requireId(alloc, authority, "/subscriptions/" ++ tenant ++ "/resourceGroups/synthetic-group/providers/Microsoft.Compute/virtualMachines/synthetic-vm"));
    try t.expectError(error.InvalidIdentity, s.uuid("00000000-0000-0000-0000-000000000000"));
}

test "raw ARM VM and disk readback bind original UUID geometry and Standard security" {
    var h = try Harness.init(&.{ .{ .url = vm_url, .response = vm_json }, .{ .url = disk_url, .response = disk_json } });
    defer h.deinit();
    var arm = h.arm();
    var vm = try requireOk(arm.execute(.{ .get = vm_ref }));
    defer vm.deinit();
    try models.requireOriginalVm(vm.model, vm_uuid.*);
    try t.expectError(error.OriginalIdentityMismatch, models.requireOriginalVm(vm.model, disk_uuid.*));
    var disk = try requireOk(arm.execute(.{ .get = disk_ref }));
    defer disk.deinit();
    try models.requireOriginalDisk(disk.model, disk_identity);
}

test "403 is never absence and unknown service messages never enter diagnostics" {
    var h = try Harness.init(&.{.{ .url = group_url, .status = 403, .response = "{\"error\":{\"code\":\"NewDeniedCode\",\"message\":\"SYNTHETIC_SECRET?sig=private\"}}" }});
    defer h.deinit();
    var arm = h.arm();
    const result = arm.execute(.group_delete);
    try requireFailure(result, .authorization, .not_started, 403);
    try t.expectEqual(.unknown, result.failed.diagnostic.service_code);
}

test "group create issues one PUT then reads durable ownership and completion" {
    var h = try Harness.init(&.{
        .{ .url = group_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceGroupNotFound\"}}" },
        .{ .url = group_url, .method = .PUT, .status = 201, .response = group_json, .body_contains = "\"uk-hyperv-run\":\"" ++ run ++ "\"" },
        .{ .url = group_url, .response = group_json },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.group_create));
    defer result.deinit();
    try t.expectEqual(.succeeded, result.model.group);
    try t.expectEqual(.accepted, result.effect);
}

test "deallocate bounded LRO retains original identity and requires power readback" {
    const lro = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/operations/" ++ operation_uuid ++ "?api-version=2025-11-01";
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/deallocate?api-version=2025-11-01", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = lro }} },
        .{ .url = lro, .response = "{\"status\":\"Running\",\"percentComplete\":25.5}" },
        .{ .url = lro, .response = "{\"status\":\"Succeeded\"}" },
        .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/instanceView?api-version=2025-11-01", .response = "{\"statuses\":[{\"code\":\"PowerState/deallocated\"}]}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .deallocate = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }));
    defer result.deinit();
    try t.expectEqual(.accepted, result.effect);
}

test "cross-authority LRO refuses token forwarding and mutation is not replayed" {
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/start?api-version=2025-11-01", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = "https://untrusted.invalid/poll?api-version=2025-11-01" }} },
    });
    defer h.deinit();
    var arm = h.arm();
    try requireFailure(arm.execute(.{ .start = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }), .invalid_response, .accepted, 202);
}

test "transport ambiguity retains unknown effect and no mutation retry" {
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/endGetAccess?api-version=2025-01-02", .method = .POST, .fail = true },
    });
    defer h.deinit();
    var arm = h.arm();
    try requireFailure(arm.execute(.{ .revoke = disk_identity }), .transport, .unknown, null);
}

test "page continuation remains on exact version and collection scope" {
    const path = group_path ++ "/resources";
    const first = s.arm_host ++ path ++ "?api-version=2021-04-01";
    const second = s.arm_host ++ path ++ "?api-version=2021-04-01&$skiptoken=opaque%2Btoken";
    var h = try Harness.init(&.{
        .{ .url = first, .response = "{\"value\":[{\"id\":\"" ++ vm_path ++ "\"}],\"nextLink\":\"" ++ second ++ "\"}" },
        .{ .url = second, .response = "{\"value\":[{\"id\":\"" ++ disk_path ++ "\"}],\"nextLink\":null}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = switch (arm.list(.inventory)) {
        .ok => |value| value,
        .failed => return error.UnexpectedFailure,
    };
    defer result.deinit();
    try t.expectEqual(@as(u16, 2), result.pages);
    try t.expectEqualStrings("synthetic-vm", result.items[0].summary.id.name);
    try t.expectEqualStrings("synthetic-disk", result.items[1].summary.id.name);
}

test "request constructors use raw storage properties and fixed create-only deployment resources" {
    const arena = try secret.Arena.create(a);
    defer arena.destroy();
    const alloc = arena.allocator();
    const plan = try ops.Plan.create(alloc, authority, .{ .deploy = .{ .name = "synthetic-deployment", .resources = &.{
        .{ .storage = .{ .name = "syntheticaccount" } },
        .{ .disk = .{ .name = "synthetic-disk", .size_gib = 4, .upload_bytes = 4294967808 } },
    } } });
    const root = try json.parse(alloc, plan.body.?);
    const template = try models.field(try models.field(root, "properties"), "template");
    const resources = try models.array(try models.field(template, "resources"));
    try t.expectEqual(@as(usize, 2), resources.len);
    const properties = try models.field(resources[0], "properties");
    try t.expect(try models.boolean(try models.field(properties, "supportsHttpsTrafficOnly")));
    try t.expectEqual(@as(usize, 0), (try models.array(try models.field(try models.field(properties, "networkAcls"), "ipRules"))).len);
    try t.expectError(error.InvalidGeometry, ops.Plan.create(alloc, authority, .{ .disk_create = .{ .name = "disk", .size_gib = 4, .upload_bytes = 4294967296 } }));
}

test "explicit assertion provider exchanges only with selected tenant and audience" {
    const callback = struct {
        fn assertion(allocator: std.mem.Allocator) ![]u8 {
            return allocator.dupe(u8, "synthetic.header.signature");
        }
    }.assertion;
    var h = try Harness.init(&.{.{
        .url = s.login_host ++ "/" ++ tenant ++ "/oauth2/v2.0/token",
        .method = .POST,
        .authorization = false,
        .body_contains = "scope=https%3A%2F%2Fmanagement.azure.com%2F.default",
        .response = "{\"access_token\":\"synthetic-result-token\",\"expires_in\":7200,\"token_type\":\"Bearer\"}",
    }});
    defer h.deinit();
    var token = switch (auth.acquire(a, h.channel(), .{ .authority = authority, .provider = .{ .client_assertion = callback }, .minimum_validity_seconds = 3600 })) {
        .ok => |token| token,
        .failed => return error.UnexpectedFailure,
    };
    defer token.deinit();
    try t.expectEqual(@as(i64, h.unix + 7200), token.expires_on);
    try t.expectEqualStrings("synthetic-result-token", token.value.bytes);
}

test "managed identity selection is explicit and preserves IMDS client and resource binding" {
    var h = try Harness.init(&.{.{
        .url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com&client_id=" ++ application,
        .authorization = false,
        .response = "{\"access_token\":\"synthetic-managed-token\",\"expires_on\":\"1800007200\",\"token_type\":\"Bearer\",\"client_id\":\"" ++ application ++ "\",\"resource\":\"https://management.azure.com\"}",
    }});
    defer h.deinit();
    var token = switch (auth.acquire(a, h.channel(), .{ .authority = authority, .provider = .{ .managed_identity = .user_assigned }, .minimum_validity_seconds = 3600 })) {
        .ok => |token| token,
        .failed => return error.UnexpectedFailure,
    };
    defer token.deinit();
    try t.expectEqualStrings("synthetic-managed-token", token.value.bytes);
}

test "TLS requires explicit pinned nonempty trust material and no ambient fallback" {
    var h = try Harness.init(&.{});
    defer h.deinit();
    const clock = h.channel().budget.clock;
    try t.expectError(error.InvalidTrust, wire.NativeRuntime.init(a, t.io, &.{}, [_]u8{0} ** 32, clock));
    try t.expectError(error.TrustMismatch, wire.NativeRuntime.init(a, t.io, &.{"invalid-der"}, [_]u8{0} ** 32, clock));
}

test "missing Standard metadata bool-as-geometry and CLI disk aliases are refused" {
    const variants = [_]struct { source: []const u8, from: []const u8, to: []const u8, ref: s.Ref, url: []const u8 }{
        .{ .source = vm_json, .from = "\"securityProfile\":{\"securityType\":\"Standard\"},", .to = "", .ref = vm_ref, .url = vm_url },
        .{ .source = vm_json, .from = "\"Standard\"", .to = "\"TrustedLaunch\"", .ref = vm_ref, .url = vm_url },
        .{ .source = disk_json, .from = "\"diskSizeGB\":4", .to = "\"diskSizeGB\":true", .ref = disk_ref, .url = disk_url },
        .{ .source = disk_json, .from = "\"diskSizeGB\":4", .to = "\"diskSizeGB\":4.0", .ref = disk_ref, .url = disk_url },
        .{ .source = disk_json, .from = "\"diskSizeGB\":4", .to = "\"diskSizeGb\":4", .ref = disk_ref, .url = disk_url },
        .{ .source = disk_json, .from = "\"logicalSectorSize\":512", .to = "\"logicalSectorSize\":4096", .ref = disk_ref, .url = disk_url },
    };
    for (variants) |variant| {
        const body = try std.mem.replaceOwned(u8, a, variant.source, variant.from, variant.to);
        defer a.free(body);
        var h = try Harness.init(&.{.{ .url = variant.url, .response = body }});
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .get = variant.ref }), .invalid_response, .not_applicable, 200);
    }
}

test "wrong VM UUID is refused before POST even inside owned group" {
    var h = try Harness.init(&.{ .{ .url = group_url, .response = group_json }, .{ .url = vm_url, .response = vm_json } });
    defer h.deinit();
    var arm = h.arm();
    try requireFailure(arm.execute(.{ .start = .{ .vm = vm_ref, .original_uuid = disk_uuid.* } }), .integrity, .not_started, 200);
}

test "malformed or unknown-code 404 is not an independent absence proof" {
    for ([_][]const u8{ "", "<html>not an ARM result</html>", "{\"error\":{\"code\":\"UnknownRouterCode\"}}", "{\"error\":{\"code\":false}}" }) |body| {
        var h = try Harness.init(&.{.{ .url = group_url, .status = 404, .response = body }});
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.group_delete), .not_found, .not_started, 404);
    }
}

test "group deletion requires final named ARM absence and does not convert 403" {
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = group_url, .method = .DELETE, .status = 204 },
        .{ .url = group_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceGroupNotFound\"}}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.group_delete));
    defer result.deinit();
    try t.expectEqual(@as(u16, 404), result.reply.status);
    try t.expectEqual(.accepted, result.effect);

    var denied = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = group_url, .method = .DELETE, .status = 204 },
        .{ .url = group_url, .status = 403, .response = "{\"error\":{\"code\":\"AuthorizationFailure\"}}" },
    });
    defer denied.deinit();
    var denied_arm = denied.arm();
    try requireFailure(denied_arm.execute(.group_delete), .authorization, .accepted, 403);
}

test "LRO failure timeout and cross-subscription metadata never replay a mutation" {
    const good_url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/operations/" ++ operation_uuid ++ "?api-version=2025-11-01";
    var failed = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },                                                                                                                               .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/start?api-version=2025-11-01", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = good_url }} }, .{ .url = good_url, .response = "{\"status\":\"Failed\",\"error\":{\"code\":\"AllocationFailed\",\"message\":\"SYNTHETIC_SECRET\"}}" },
    });
    defer failed.deinit();
    var failed_arm = failed.arm();
    try requireFailure(failed_arm.execute(.{ .start = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }), .service, .accepted, 200);

    var timeout = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },                                                                                                                               .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/start?api-version=2025-11-01", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = good_url }} }, .{ .url = good_url, .response = "{\"status\":\"Running\"}" },
    });
    defer timeout.deinit();
    var timeout_arm = timeout.arm();
    timeout.budget.max_polls = 1;
    try requireFailure(timeout_arm.execute(.{ .start = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }), .timeout, .accepted, 200);

    const bad_url = s.arm_host ++ "/subscriptions/" ++ tenant ++ "/providers/Microsoft.Compute/locations/northeurope/operations/" ++ operation_uuid ++ "?api-version=2025-11-01";
    var cross = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },                                                                                                                              .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/start?api-version=2025-11-01", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = bad_url }} },
    });
    defer cross.deinit();
    var cross_arm = cross.arm();
    try requireFailure(cross_arm.execute(.{ .start = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }), .invalid_response, .accepted, 202);
}

test "pagination rejects sibling scope invalid version duplicate fields and cycles" {
    const first = s.arm_host ++ group_path ++ "/resources?api-version=2021-04-01";
    for ([_][]const u8{
        "https://untrusted.invalid/resources?api-version=2021-04-01",
        s.arm_host ++ "/subscriptions/" ++ sub ++ "/resourceGroups/foreign/resources?api-version=2021-04-01",
        s.arm_host ++ group_path ++ "/resources?api-version=2025-11-01",
        s.arm_host ++ group_path ++ "/resources?api-version=2021-04-01&api-version=2021-04-01",
    }) |next| {
        const body = try std.fmt.allocPrint(a, "{{\"value\":[],\"nextLink\":\"{s}\"}}", .{next});
        defer a.free(body);
        var h = try Harness.init(&.{.{ .url = first, .response = body }});
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.list(.inventory), .invalid_response, .not_applicable, 200);
    }
    var duplicate = try Harness.init(&.{.{ .url = first, .response = "{\"value\":[],\"value\":[]}" }});
    defer duplicate.deinit();
    var duplicate_arm = duplicate.arm();
    try requireFailure(duplicate_arm.list(.inventory), .invalid_response, .not_applicable, 200);
    var cyclic = try Harness.init(&.{.{ .url = first, .response = "{\"value\":[],\"nextLink\":\"" ++ first ++ "\"}" }});
    defer cyclic.deinit();
    var cyclic_arm = cyclic.arm();
    try requireFailure(cyclic_arm.list(.inventory), .invalid_input, .not_applicable, null);
}

test "body framing read size and cancellation bounds fail without additional requests" {
    for ([_]Step{
        .{ .url = group_url, .response = group_json, .headers = &.{.{ .name = "Content-Length", .value = "1" }} },
        .{ .url = group_url, .response = group_json, .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }} },
        .{ .url = group_url, .response = group_json, .headers = &.{ .{ .name = "Content-Length", .value = "99" }, .{ .name = "Content-Length", .value = "99" } } },
    }) |step| {
        var h = try Harness.init(&.{step});
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .get = group_ref }), .invalid_response, .not_applicable, 200);
    }
    var large = try Harness.init(&.{.{ .url = group_url, .response = group_json }});
    defer large.deinit();
    var large_arm = large.arm();
    large.budget.max_response_bytes = 32;
    try requireFailure(large_arm.execute(.{ .get = group_ref }), .output_limit, .not_applicable, 200);
    var cancelled = try Harness.init(&.{});
    defer cancelled.deinit();
    var cancelled_arm = cancelled.arm();
    cancelled.cancellation.cancel();
    try requireFailure(cancelled_arm.execute(.{ .get = group_ref }), .cancelled, .not_started, null);
}

test "ARM redirects and token expiry cannot forward bearer tokens" {
    var redirect = try Harness.init(&.{.{ .url = group_url, .status = 307, .headers = &.{.{ .name = "Location", .value = "https://untrusted.invalid/credential" }} }});
    defer redirect.deinit();
    var arm = redirect.arm();
    try requireFailure(arm.execute(.{ .get = group_ref }), .invalid_response, .not_applicable, 307);
    var expired = try Harness.init(&.{});
    defer expired.deinit();
    var expired_arm = expired.arm();
    expired.token.expires_on = expired.unix;
    try requireFailure(expired_arm.execute(.{ .get = group_ref }), .authentication, .not_started, null);
}

test "managed disk grant returns validated secret URI and revoke is a single operation" {
    const grant_body = "{\"accessSAS\":\"https://synthetic.blob.storage.azure.net:8443/disk/vhd?sig=SYNTHETIC_SECRET\"}";
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = upload_disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .body_contains = "\"durationInSeconds\":600", .response = grant_body },
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/endGetAccess?api-version=2025-01-02", .method = .POST, .status = 204 },
        .{ .url = disk_url, .response = disk_json },
    });
    defer h.deinit();
    var arm = h.arm();
    var grant = try requireOk(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }));
    defer grant.deinit();
    try t.expect(grant.model == .grant);
    try t.expectEqual(.accepted, grant.effect);
    var revoke = try requireOk(arm.execute(.{ .revoke = disk_identity }));
    defer revoke.deinit();
    try t.expectEqual(.accepted, revoke.effect);
}

test "boot diagnostics require original VM and refuse non-Blob SAS destinations" {
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },                                                                                                                                                                                                                                                                                 .{ .url = vm_url, .response = vm_json },
        .{ .url = s.arm_host ++ vm_path ++ "/retrieveBootDiagnosticsData?api-version=2025-11-01&sasUriExpirationTimeInMinutes=10", .method = .POST, .body_absent = true, .response = "{\"serialConsoleLogBlobUri\":\"https://synthetic.blob.core.windows.net/boot/serial?sig=SYNTHETIC_SECRET\",\"consoleScreenshotBlobUri\":null}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var boot = try requireOk(arm.execute(.{ .boot_diagnostics = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }));
    defer boot.deinit();
    try t.expect(boot.model == .boot);
    try t.expectError(error.InvalidSas, models.sasUri("https://untrusted.invalid/log?sig=private", false));
    try t.expectError(error.InvalidSas, models.sasUri("https://user@synthetic.blob.core.windows.net/log?sig=private", false));
    try t.expectError(error.InvalidSas, models.sasUri("http://synthetic.blob.core.windows.net/log?sig=private", false));
}

test "firewall preserves exact subnet allowlist and emits bare host IP not CIDR" {
    const subnet_path = group_path ++ "/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/synthetic-subnet";
    const with_subnet = try std.mem.replaceOwned(u8, a, storage_json, "\"virtualNetworkRules\":[]", "\"virtualNetworkRules\":[{\"id\":\"" ++ subnet_path ++ "\",\"action\":\"Allow\"}]");
    defer a.free(with_subnet);
    const after = try std.mem.replaceOwned(u8, a, with_subnet, "\"ipRules\":[]", "\"ipRules\":[{\"value\":\"203.0.113.7\",\"action\":\"Allow\"}]");
    defer a.free(after);
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },                                                              .{ .url = account_url, .response = with_subnet },
        .{ .url = account_url, .method = .PATCH, .body_contains = "\"value\":\"203.0.113.7\"", .response = after }, .{ .url = account_url, .response = after },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .firewall = .{
        .account = account_ref,
        .before_address = null,
        .address = .{ 203, 0, 113, 7 },
        .subnets = &.{.{ .kind = .subnet, .parent = "synthetic-vnet", .name = "synthetic-subnet" }},
    } }));
    defer result.deinit();
    try t.expectEqual(@as(usize, 1), result.model.storage.subnets.len);
    try t.expectEqualDeep(@as(?[4]u8, .{ 203, 0, 113, 7 }), result.model.storage.ip);
}

test "raw storage aliases and existing unexpected firewall rules are refused" {
    for ([_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "networkAcls", .to = "networkRuleSet" },
        .{ .from = "supportsHttpsTrafficOnly", .to = "enableHttpsTrafficOnly" },
    }) |change| {
        const body = try std.mem.replaceOwned(u8, a, storage_json, change.from, change.to);
        defer a.free(body);
        var h = try Harness.init(&.{.{ .url = account_url, .response = body }});
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .get = account_ref }), .invalid_response, .not_applicable, 200);
    }
    var mismatch = try Harness.init(&.{ .{ .url = group_url, .response = group_json }, .{ .url = account_url, .response = storage_json } });
    defer mismatch.deinit();
    var arm = mismatch.arm();
    try requireFailure(arm.execute(.{ .firewall = .{
        .account = account_ref,
        .before_address = .{ 203, 0, 113, 7 },
        .address = null,
        .subnets = &.{},
    } }), .invalid_response, .not_started, 200);
}

test "owned account keys remain private typed data across list and regeneration" {
    var first: [88]u8 = undefined;
    var second: [88]u8 = undefined;
    var third: [88]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&first, &([_]u8{0x11} ** 64));
    _ = std.base64.standard.Encoder.encode(&second, &([_]u8{0x22} ** 64));
    _ = std.base64.standard.Encoder.encode(&third, &([_]u8{0x33} ** 64));
    const body = try std.fmt.allocPrint(a, "{{\"keys\":[{{\"keyName\":\"key1\",\"value\":\"{s}\",\"permissions\":\"FULL\"}},{{\"keyName\":\"key2\",\"value\":\"{s}\",\"permissions\":\"FULL\"}}]}}", .{ first, second });
    defer a.free(body);
    const changed_body = try std.fmt.allocPrint(a, "{{\"keys\":[{{\"keyName\":\"key1\",\"value\":\"{s}\",\"permissions\":\"FULL\"}},{{\"keyName\":\"key2\",\"value\":\"{s}\",\"permissions\":\"FULL\"}}]}}", .{ third, second });
    defer a.free(changed_body);
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = s.arm_host ++ account_path ++ "/listKeys?api-version=2023-05-01", .method = .POST, .response = body },
        .{ .url = group_url, .response = group_json },
        .{ .url = s.arm_host ++ account_path ++ "/listKeys?api-version=2023-05-01", .method = .POST, .response = body },
        .{ .url = s.arm_host ++ account_path ++ "/regenerateKey?api-version=2023-05-01", .method = .POST, .body_contains = "\"keyName\":\"key1\"", .response = changed_body },
    });
    defer h.deinit();
    var arm = h.arm();
    var listed = try requireOk(arm.execute(.{ .list_keys = account_ref }));
    defer listed.deinit();
    try t.expectEqualStrings(&first, listed.model.keys.key1);
    var changed = try requireOk(arm.execute(.{ .regenerate_key = .{ .account = account_ref, .key = .key1, .previous = listed.model.keys.snapshot() } }));
    defer changed.deinit();
    try t.expectEqual(.accepted, changed.effect);
}

test "auth rejects missing expiry coercions duplicate fields and wrong audience" {
    const callback = struct {
        fn assertion(allocator: std.mem.Allocator) ![]u8 {
            return allocator.dupe(u8, "synthetic.header.signature");
        }
    }.assertion;
    for ([_][]const u8{
        "{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\"}",
        "{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\",\"expires_in\":true}",
        "{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"expires_in\":7200}",
        "{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"https://storage.azure.com/.default\"}",
        "{\"access_token\":\"synthetic-token\\nSYNTHETIC_SECRET\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
    }) |body| {
        var h = try Harness.init(&.{.{ .url = s.login_host ++ "/" ++ tenant ++ "/oauth2/v2.0/token", .method = .POST, .authorization = false, .response = body }});
        defer h.deinit();
        try requireFailure(auth.acquire(a, h.channel(), .{ .authority = authority, .provider = .{ .client_assertion = callback }, .minimum_validity_seconds = 300 }), .invalid_response, .not_applicable, 200);
    }
}

test "native managed credential errors are intercepted before SDK body logging" {
    var h = try Harness.init(&.{.{
        .url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com",
        .authorization = false,
        .status = 403,
        .response = "{\"error\":{\"code\":\"AuthorizationFailure\",\"message\":\"SYNTHETIC_SECRET\"}}",
    }});
    defer h.deinit();
    try requireFailure(auth.acquire(a, h.channel(), .{ .authority = authority, .provider = .{ .managed_identity = .system_assigned }, .minimum_validity_seconds = 300 }), .authorization, .not_applicable, 403);
}

test "auth redirect refuses replay and minimum cleanup lifetime is enforced" {
    const callback = struct {
        fn assertion(allocator: std.mem.Allocator) ![]u8 {
            return allocator.dupe(u8, "synthetic.header.signature");
        }
    }.assertion;
    var redirect = try Harness.init(&.{.{ .url = s.login_host ++ "/" ++ tenant ++ "/oauth2/v2.0/token", .method = .POST, .authorization = false, .status = 302, .headers = &.{.{ .name = "Location", .value = "https://untrusted.invalid/token" }} }});
    defer redirect.deinit();
    try requireFailure(auth.acquire(a, redirect.channel(), .{ .authority = authority, .provider = .{ .client_assertion = callback }, .minimum_validity_seconds = 300 }), .invalid_response, .not_applicable, 302);
    var expiry = try Harness.init(&.{.{ .url = s.login_host ++ "/" ++ tenant ++ "/oauth2/v2.0/token", .method = .POST, .authorization = false, .response = "{\"access_token\":\"synthetic-token\",\"token_type\":\"Bearer\",\"expires_in\":30}" }});
    defer expiry.deinit();
    try requireFailure(auth.acquire(a, expiry.channel(), .{ .authority = authority, .provider = .{ .client_assertion = callback }, .minimum_validity_seconds = 300 }), .authentication, .not_applicable, 200);
}

test "native subscription provider SKU quota and immutable image admission" {
    const image_path = group_path ++ "/providers/Microsoft.Compute/images/synthetic-image";
    const image_body = "{\"id\":\"" ++ image_path ++ "\",\"name\":\"synthetic-image\",\"location\":\"northeurope\",\"properties\":{\"hyperVGeneration\":\"V2\",\"provisioningState\":\"Succeeded\",\"storageProfile\":{\"osDisk\":{\"osType\":\"Linux\",\"osState\":\"Specialized\"}}}}";
    const sku_body = "{\"value\":[{\"resourceType\":\"virtualMachines\",\"name\":\"Standard_D2s_v5\",\"family\":\"standardDSv5Family\",\"locations\":[\"northeurope\"],\"restrictions\":[],\"capabilities\":[{\"name\":\"vCPUs\",\"value\":\"2\"},{\"name\":\"MemoryGB\",\"value\":\"8\"},{\"name\":\"HyperVGenerations\",\"value\":\"V1,V2\"},{\"name\":\"NestedVirtualizationEnabled\",\"value\":\"True\"}]}]}";
    const usage_body = "{\"value\":[{\"name\":{\"value\":\"standardDSv5Family\"},\"unit\":\"Count\",\"currentValue\":0,\"limit\":10},{\"name\":{\"value\":\"cores\"},\"unit\":\"Count\",\"currentValue\":2,\"limit\":20}]}";
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(image_body, &hash, .{});
    var h = try Harness.init(&.{
        .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "?api-version=2022-12-01", .response = "{\"subscriptionId\":\"" ++ sub ++ "\",\"state\":\"Enabled\"}" },
        .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute?api-version=2021-04-01", .response = "{\"namespace\":\"Microsoft.Compute\",\"registrationState\":\"Registered\",\"resourceTypes\":[{\"resourceType\":\"virtualMachines\",\"apiVersions\":[\"2025-11-01\"]}]}" },
        .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/skus?api-version=2021-07-01&$filter=location%20eq%20%27northeurope%27", .response = sku_body },
        .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/usages?api-version=2025-11-01", .response = usage_body },
        .{ .url = s.arm_host ++ image_path ++ "?api-version=2025-11-01", .response = image_body },
    });
    defer h.deinit();
    var arm = h.arm();
    var evidence = switch (admission.inspect(&arm, .{
        .sku = "Standard_D2s_v5",
        .family = "standardDSv5Family",
        .vcpus = 2,
        .memory_mib = 8192,
        .require_nested_metadata = true,
        .image = .{ .kind = .image, .name = "synthetic-image" },
        .image_group = authority.group,
        .image_response_sha256 = hash,
    })) {
        .ok => |value| value,
        .failed => return error.UnexpectedFailure,
    };
    defer evidence.deinit();
    try t.expectEqual(@as(?u32, 8192), evidence.skus.items[evidence.selected_sku].sku.memory_mib);
    try t.expect(evidence.image.model.image.generation2);
}

test "zeroizing allocator erases intermediate and final private copies" {
    const Spy = struct {
        clean: bool = true,
        frees: usize = 0,
        fn alloc(_: *anyopaque, length: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            return a.rawAlloc(length, alignment, ret);
        }
        fn free(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.clean = self.clean and std.mem.allEqual(u8, bytes, 0);
            self.frees += 1;
            a.rawFree(bytes, alignment, ret);
        }
    };
    var spy: Spy = .{};
    const parent: std.mem.Allocator = .{ .ptr = &spy, .vtable = &.{
        .alloc = Spy.alloc,
        .resize = std.mem.Allocator.noResize,
        .remap = std.mem.Allocator.noRemap,
        .free = Spy.free,
    } };
    const arena = try secret.Arena.create(parent);
    _ = try arena.allocator().dupe(u8, "SYNTHETIC_SECRET-intermediate");
    arena.destroy();
    var bytes = try secret.Bytes.copy(parent, "SYNTHETIC_SECRET-final");
    bytes.deinit();
    try t.expect(spy.clean);
    try t.expect(spy.frees >= 3);
}

test "disk Location LRO returns actual grant result without replaying POST" {
    const location = disk_location_url;
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = upload_disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{.{ .name = "Location", .value = location }} },
        .{ .url = location, .status = 202 },
        .{ .url = location, .status = 202, .response = "{\"status\":\"InProgress\",\"percentComplete\":12.5}" },
        .{ .url = location, .response = "{\"accessSAS\":\"https://synthetic.blob.storage.azure.net/disk/vhd?sig=SYNTHETIC_SECRET\"}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }));
    defer result.deinit();
    try t.expect(result.model == .grant);
    try t.expectEqual(.accepted, result.effect);
}

test "async grant separates operation status from final result Location" {
    const monitor = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/operationStatuses/" ++ operation_uuid ++ "?api-version=2025-01-02";
    const location = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/operationResults/" ++ operation_uuid ++ "?api-version=2025-01-02";
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = upload_disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{ .{ .name = "Azure-AsyncOperation", .value = monitor }, .{ .name = "Location", .value = location } } },
        .{ .url = monitor, .response = "{\"status\":\"Succeeded\"}" },
        .{ .url = location, .response = "{\"accessSAS\":\"https://synthetic.blob.storage.azure.net/disk/vhd?sig=SYNTHETIC_SECRET\"}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }));
    defer result.deinit();
    try t.expect(result.model == .grant);
}

test "grant refuses nonupload and already active disks before mutation" {
    const active = try std.mem.replaceOwned(u8, a, upload_disk_json, "ReadyToUpload", "ActiveUpload");
    defer a.free(active);
    for ([_][]const u8{ disk_json, active }) |body| {
        var h = try Harness.init(&.{ .{ .url = group_url, .response = group_json }, .{ .url = disk_url, .response = body } });
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }), .invalid_response, .not_started, 200);
    }
}

test "revoke observes original disk and never promotes an active grant to success" {
    const active = try std.mem.replaceOwned(u8, a, upload_disk_json, "ReadyToUpload", "ActiveUpload");
    defer a.free(active);
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = active },
        .{ .url = s.arm_host ++ disk_path ++ "/endGetAccess?api-version=2025-01-02", .method = .POST, .status = 204 },
        .{ .url = disk_url, .response = active },
    });
    defer h.deinit();
    var arm = h.arm();
    h.budget.max_polls = 1;
    try requireFailure(arm.execute(.{ .revoke = disk_identity }), .timeout, .accepted, 204);
}

test "disk creation is absence guarded and verified against exact geometry" {
    for ([_]u32{ 4, 8 }) |size| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = disk_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = disk_url, .method = .PUT, .status = 201, .body_contains = "\"logicalSectorSize\":512", .response = disk_json },
            .{ .url = disk_url, .response = disk_json },
        });
        defer h.deinit();
        var arm = h.arm();
        const outcome = arm.execute(.{ .disk_create = .{ .name = disk_ref.name, .size_gib = size } });
        if (size == 4) {
            var result = try requireOk(outcome);
            defer result.deinit();
            try t.expectEqual(.accepted, result.effect);
        } else try requireFailure(outcome, .integrity, .accepted, 200);
    }
}

test "deployment success independently checks created resource definitions" {
    const path = group_path ++ "/providers/Microsoft.Resources/deployments/synthetic-deployment";
    const url = s.arm_host ++ path ++ "?api-version=2021-04-01";
    const body = "{\"id\":\"" ++ path ++ "\",\"name\":\"synthetic-deployment\",\"properties\":{\"provisioningState\":\"Succeeded\"}}";
    for ([_]u32{ 4, 8 }) |size| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = disk_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = url, .method = .PUT, .status = 201, .body_contains = "\"apiVersion\":\"2025-01-02\"", .response = body },
            .{ .url = url, .response = body },
            .{ .url = disk_url, .response = disk_json },
        });
        defer h.deinit();
        var arm = h.arm();
        const outcome = arm.execute(.{ .deploy = .{ .name = "synthetic-deployment", .resources = &.{.{ .disk = .{ .name = disk_ref.name, .size_gib = size } }} } });
        if (size == 4) {
            var result = try requireOk(outcome);
            defer result.deinit();
            try t.expect(result.model == .deployment);
        } else try requireFailure(outcome, .integrity, .accepted, 200);
    }
}

test "schedule put verifies target enabled state and time before completion" {
    const path = group_path ++ "/providers/Microsoft.DevTestLab/schedules/synthetic-schedule";
    const url = s.arm_host ++ path ++ "?api-version=2018-09-15";
    const body = "{\"id\":\"" ++ path ++ "\",\"name\":\"synthetic-schedule\",\"location\":\"northeurope\",\"properties\":{\"taskType\":\"ComputeVmShutdownTask\",\"status\":\"Enabled\",\"targetResourceId\":\"" ++ vm_path ++ "\",\"timeZoneId\":\"UTC\",\"dailyRecurrence\":{\"time\":\"1900\"},\"notificationSettings\":{\"status\":\"Disabled\"}}}";
    for ([_][]const u8{ "1900", "1800" }) |time| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = url, .method = .PUT, .response = body },
            .{ .url = url, .response = body },
        });
        defer h.deinit();
        var arm = h.arm();
        const outcome = arm.execute(.{ .schedule_put = .{ .name = "synthetic-schedule", .vm = vm_ref, .time = time[0..4].* } });
        if (std.mem.eql(u8, time, "1900")) {
            var result = try requireOk(outcome);
            defer result.deinit();
            try t.expect(result.model.schedule.enabled);
        } else try requireFailure(outcome, .invalid_response, .accepted, 200);
    }
}

test "group deletion Location 204 requires independent named absence" {
    const location = s.arm_host ++ "/subscriptions/" ++ sub ++ "/operationresults/" ++ operation_uuid ++ "?api-version=2021-04-01";
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = group_url, .method = .DELETE, .status = 202, .headers = &.{.{ .name = "Location", .value = location }} },
        .{ .url = location, .status = 204 },
        .{ .url = group_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceGroupNotFound\"}}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.group_delete));
    defer result.deinit();
    try t.expectEqual(@as(u16, 404), result.reply.status);
    try t.expectEqual(.accepted, result.effect);
}

test "quota uses raw applicable LimitValue and binds subscription location and name" {
    const path = "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/providers/Microsoft.Quota/quotas/standardDSv5Family";
    const url = s.arm_host ++ path ++ "?api-version=2023-02-01";
    const body = "{\"id\":\"" ++ path ++ "\",\"type\":\"Microsoft.Quota/Quotas\",\"name\":\"standardDSv5Family\",\"properties\":{\"name\":{\"value\":\"standardDSv5Family\"},\"unit\":\"Count\",\"isQuotaApplicable\":true,\"limit\":{\"limitObjectType\":\"LimitValue\",\"value\":16}}}";
    var h = try Harness.init(&.{.{ .url = url, .response = body }});
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .quota = "standardDSv5Family" }));
    defer result.deinit();
    try t.expectEqual(@as(u64, 16), result.model.quota);
    const foreign = try std.mem.replaceOwned(u8, a, body, sub, tenant);
    defer a.free(foreign);
    var denied = try Harness.init(&.{.{ .url = url, .response = foreign }});
    defer denied.deinit();
    var denied_arm = denied.arm();
    try requireFailure(denied_arm.execute(.{ .quota = "standardDSv5Family" }), .invalid_response, .not_applicable, 200);
}

test "gallery version and definition have distinct raw shapes and explicit readonly source group" {
    const prefix = "/subscriptions/" ++ sub ++ "/resourceGroups/approved-images/providers/Microsoft.Compute/galleries/synthetic-gallery/images/synthetic-image";
    const version_path = prefix ++ "/versions/1.0.0";
    const definition = "{\"id\":\"" ++ prefix ++ "\",\"name\":\"synthetic-image\",\"location\":\"northeurope\",\"properties\":{\"hyperVGeneration\":\"V2\",\"osType\":\"Linux\",\"osState\":\"Specialized\",\"provisioningState\":\"Succeeded\"}}";
    const version = "{\"id\":\"" ++ version_path ++ "\",\"name\":\"1.0.0\",\"location\":\"northeurope\",\"properties\":{\"provisioningState\":\"Succeeded\",\"storageProfile\":{},\"publishingProfile\":{\"publishedDate\":\"2026-09-10T00:00:00Z\",\"targetRegions\":[{\"name\":\"northeurope\"}]}}}";
    var h = try Harness.init(&.{
        .{ .url = s.arm_host ++ version_path ++ "?api-version=2025-03-03", .response = version },
        .{ .url = s.arm_host ++ prefix ++ "?api-version=2025-03-03", .response = definition },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .image = .{ .group = "approved-images", .ref = .{ .kind = .gallery_version, .parent = "synthetic-gallery", .gallery_image = "synthetic-image", .name = "1.0.0" } } }));
    defer result.deinit();
    try t.expect(result.model.image_version.in_location);
    var image = try requireOk(arm.execute(.{ .image = .{ .group = "approved-images", .ref = .{ .kind = .gallery_image, .parent = "synthetic-gallery", .name = "synthetic-image" } } }));
    defer image.deinit();
    try t.expect(image.model.image.specialized_linux and image.model.image.generation2);
    try requireFailure(arm.execute(.{ .image = .{ .group = "approved-images", .ref = vm_ref } }), .invalid_input, .not_started, null);
}

test "unexpected read status and successful HTTP error envelope are not success" {
    var read = try Harness.init(&.{.{ .url = group_url, .status = 201, .response = group_json }});
    defer read.deinit();
    var read_arm = read.arm();
    try requireFailure(read_arm.execute(.{ .get = group_ref }), .invalid_response, .not_applicable, 201);
    var mutation = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/endGetAccess?api-version=2025-01-02", .method = .POST, .response = "{\"error\":{\"code\":\"InternalError\",\"message\":\"SYNTHETIC_SECRET\"}}" },
    });
    defer mutation.deinit();
    var arm = mutation.arm();
    try requireFailure(arm.execute(.{ .revoke = disk_identity }), .service, .accepted, 200);
}

test "native network inventory rejects malformed properties public IP and foreign subnet" {
    const path = group_path ++ "/providers/Microsoft.Network/networkInterfaces/synthetic-nic";
    const url = s.arm_host ++ path ++ "?api-version=2024-05-01";
    const prefix = "{\"id\":\"" ++ path ++ "\",\"name\":\"synthetic-nic\",\"location\":\"northeurope\",\"properties\":{\"enableIPForwarding\":false,\"ipConfigurations\":[{\"properties\":";
    const config = "{\"privateIPAddress\":\"10.20.1.4\",\"subnet\":{\"id\":\"" ++ group_path ++ "/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/synthetic-subnet\"}}";
    const valid = prefix ++ config ++ "}]}}";
    var h = try Harness.init(&.{.{ .url = url, .response = valid }});
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .get = .{ .kind = .nic, .name = "synthetic-nic" } }));
    defer result.deinit();
    try t.expectEqual(@as(usize, 1), result.model.network.entries);
    const public = try std.mem.replaceOwned(u8, a, valid, "\"privateIPAddress\"", "\"publicIPAddress\":{\"id\":\"unapproved\"},\"privateIPAddress\"");
    defer a.free(public);
    const foreign = try std.mem.replaceOwned(u8, a, valid, "/virtualNetworks/synthetic-vnet", "/virtualNetworks/../synthetic-vnet");
    defer a.free(foreign);
    for ([_][]const u8{ prefix ++ "true}]}}", public, foreign }) |body| {
        var denied = try Harness.init(&.{.{ .url = url, .response = body }});
        defer denied.deinit();
        var denied_arm = denied.arm();
        try requireFailure(denied_arm.execute(.{ .get = .{ .kind = .nic, .name = "synthetic-nic" } }), .invalid_response, .not_applicable, 200);
    }
}

test "schedule deletion cannot treat authorization failure as absence" {
    const url = s.arm_host ++ group_path ++ "/providers/Microsoft.DevTestLab/schedules/synthetic-schedule?api-version=2018-09-15";
    for ([_]u16{ 404, 403 }) |status| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = url, .method = .DELETE, .status = 204 },
            .{ .url = url, .status = status, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
        });
        defer h.deinit();
        var arm = h.arm();
        const outcome = arm.execute(.{ .schedule_delete = .{ .kind = .schedule, .name = "synthetic-schedule" } });
        if (status == 404) {
            var result = try requireOk(outcome);
            defer result.deinit();
            try t.expectEqual(.accepted, result.effect);
        } else try requireFailure(outcome, .authorization, .accepted, 403);
    }
}

test "key regeneration rejects unchanged selected key or changed other key" {
    var first: [88]u8 = undefined;
    var second: [88]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&first, &([_]u8{0x11} ** 64));
    _ = std.base64.standard.Encoder.encode(&second, &([_]u8{0x22} ** 64));
    const before: models.Keys = .{ .key1 = &first, .key2 = &second };
    const body = try std.fmt.allocPrint(a, "{{\"keys\":[{{\"keyName\":\"key1\",\"value\":\"{s}\",\"permissions\":\"FULL\"}},{{\"keyName\":\"key2\",\"value\":\"{s}\",\"permissions\":\"FULL\"}}]}}", .{ first, second });
    defer a.free(body);
    const wrong_other = try std.fmt.allocPrint(a, "{{\"keys\":[{{\"keyName\":\"key1\",\"value\":\"{s}\",\"permissions\":\"FULL\"}},{{\"keyName\":\"key2\",\"value\":\"{s}\",\"permissions\":\"FULL\"}}]}}", .{ second, first });
    defer a.free(wrong_other);
    for ([_][]const u8{ body, wrong_other }) |response| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = s.arm_host ++ account_path ++ "/listKeys?api-version=2023-05-01", .method = .POST, .response = body },
            .{ .url = s.arm_host ++ account_path ++ "/regenerateKey?api-version=2023-05-01", .method = .POST, .response = response },
        });
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .regenerate_key = .{ .account = account_ref, .key = .key1, .previous = before.snapshot() } }), .integrity, .accepted, 200);
    }
}

test "admission refuses unavailable provider versions without further requests" {
    const provider = "{\"namespace\":\"Microsoft.Compute\",\"registrationState\":\"Registered\",\"resourceTypes\":[{\"resourceType\":\"virtualMachines\",\"apiVersions\":[\"2020-01-01\"]}]}";
    var h = try Harness.init(&.{
        .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "?api-version=2022-12-01", .response = "{\"subscriptionId\":\"" ++ sub ++ "\",\"state\":\"Enabled\"}" },
        .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute?api-version=2021-04-01", .response = provider },
    });
    defer h.deinit();
    var arm = h.arm();
    try requireFailure(admission.inspect(&arm, .{
        .sku = "Standard_D2s_v5",
        .family = "standardDSv5Family",
        .vcpus = 2,
        .memory_mib = 8192,
        .require_nested_metadata = true,
        .image = .{ .kind = .image, .name = "synthetic-image" },
        .image_group = authority.group,
        .image_response_sha256 = [_]u8{0} ** 32,
    }), .unavailable, .not_applicable, null);
}

test "admission refuses quota exhaustion and unreviewed image bytes" {
    const image_path = group_path ++ "/providers/Microsoft.Compute/images/synthetic-image";
    const image = "{\"id\":\"" ++ image_path ++ "\",\"name\":\"synthetic-image\",\"location\":\"northeurope\",\"properties\":{\"hyperVGeneration\":\"V2\",\"provisioningState\":\"Succeeded\",\"storageProfile\":{\"osDisk\":{\"osType\":\"Linux\",\"osState\":\"Specialized\"}}}}";
    for ([_]bool{ false, true }) |exhausted| {
        const usage = if (exhausted)
            "{\"value\":[{\"name\":{\"value\":\"standardDSv5Family\"},\"unit\":\"Count\",\"currentValue\":2,\"limit\":2},{\"name\":{\"value\":\"cores\"},\"unit\":\"Count\",\"currentValue\":2,\"limit\":20}]}"
        else
            "{\"value\":[{\"name\":{\"value\":\"standardDSv5Family\"},\"unit\":\"Count\",\"currentValue\":0,\"limit\":2},{\"name\":{\"value\":\"cores\"},\"unit\":\"Count\",\"currentValue\":2,\"limit\":20}]}";
        const steps = [_]Step{
            .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "?api-version=2022-12-01", .response = "{\"subscriptionId\":\"" ++ sub ++ "\",\"state\":\"Enabled\"}" },
            .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute?api-version=2021-04-01", .response = "{\"namespace\":\"Microsoft.Compute\",\"registrationState\":\"Registered\",\"resourceTypes\":[{\"resourceType\":\"virtualMachines\",\"apiVersions\":[\"2025-11-01\"]}]}" },
            .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/skus?api-version=2021-07-01&$filter=location%20eq%20%27northeurope%27", .response = "{\"value\":[{\"resourceType\":\"virtualMachines\",\"name\":\"Standard_D2s_v5\",\"family\":\"standardDSv5Family\",\"locations\":[\"northeurope\"],\"restrictions\":[],\"capabilities\":[{\"name\":\"vCPUs\",\"value\":\"2\"},{\"name\":\"MemoryGB\",\"value\":\"8\"},{\"name\":\"HyperVGenerations\",\"value\":\"V2\"},{\"name\":\"NestedVirtualizationEnabled\",\"value\":\"True\"}]}]}" },
            .{ .url = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/usages?api-version=2025-11-01", .response = usage },
            .{ .url = s.arm_host ++ image_path ++ "?api-version=2025-11-01", .response = image },
        };
        var h = try Harness.init(steps[0..@as(usize, if (exhausted) 4 else 5)]);
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(admission.inspect(&arm, .{
            .sku = "Standard_D2s_v5",
            .family = "standardDSv5Family",
            .vcpus = 2,
            .memory_mib = 8192,
            .require_nested_metadata = true,
            .image = .{ .kind = .image, .name = "synthetic-image" },
            .image_group = authority.group,
            .image_response_sha256 = [_]u8{0} ** 32,
        }), .unavailable, .not_applicable, null);
    }
}

test "SKU pagination retains the selected region filter" {
    const path = "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/skus";
    const first = s.arm_host ++ path ++ "?api-version=2021-07-01&$filter=location%20eq%20%27northeurope%27";
    const next = s.arm_host ++ path ++ "?api-version=2021-07-01&$filter=location+eq+%27northeurope%27&$skiptoken=synthetic";
    var h = try Harness.init(&.{
        .{ .url = first, .response = "{\"value\":[],\"nextLink\":\"" ++ next ++ "\"}" },
        .{ .url = next, .response = "{\"value\":[]}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = switch (arm.list(.skus)) {
        .ok => |value| value,
        .failed => return error.UnexpectedFailure,
    };
    defer result.deinit();
    try t.expectEqual(@as(u16, 2), result.pages);
    var denied = try Harness.init(&.{.{ .url = first, .response = "{\"value\":[],\"nextLink\":\"" ++ s.arm_host ++ path ++ "?api-version=2021-07-01&$skiptoken=synthetic\"}" }});
    defer denied.deinit();
    var denied_arm = denied.arm();
    try requireFailure(denied_arm.list(.skus), .invalid_response, .not_applicable, 200);
}

test "raw OAuth string errors retain only enumerated credential diagnostics" {
    const callback = struct {
        fn assertion(allocator: std.mem.Allocator) ![]u8 {
            return allocator.dupe(u8, "synthetic.header.signature");
        }
    }.assertion;
    var h = try Harness.init(&.{.{
        .url = s.login_host ++ "/" ++ tenant ++ "/oauth2/v2.0/token",
        .method = .POST,
        .authorization = false,
        .status = 400,
        .response = "{\"error\":\"invalid_client\",\"error_description\":\"SYNTHETIC_SECRET\",\"error_codes\":[700027]}",
    }});
    defer h.deinit();
    const outcome = auth.acquire(a, h.channel(), .{
        .authority = authority,
        .provider = .{ .client_assertion = callback },
        .minimum_validity_seconds = 300,
    });
    try requireFailure(outcome, .authentication, .not_applicable, 400);
    try t.expectEqual(.invalid_client, outcome.failed.oauth_code);
}

test "VM deployment binds original disk identities before and after attachment" {
    const deployment_path = group_path ++ "/providers/Microsoft.Resources/deployments/synthetic-deployment";
    const deployment_url = s.arm_host ++ deployment_path ++ "?api-version=2021-04-01";
    const deployment = "{\"id\":\"" ++ deployment_path ++ "\",\"name\":\"synthetic-deployment\",\"properties\":{\"provisioningState\":\"Succeeded\"}}";
    const nic_path = group_path ++ "/providers/Microsoft.Network/networkInterfaces/synthetic-nic";
    const nic = "{\"id\":\"" ++ nic_path ++ "\",\"name\":\"synthetic-nic\",\"location\":\"northeurope\",\"properties\":{\"enableIPForwarding\":false,\"ipConfigurations\":[{\"properties\":{\"privateIPAddress\":\"10.20.1.4\",\"subnet\":{\"id\":\"" ++ group_path ++ "/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/synthetic-subnet\"}}}]}}";
    const attached = try std.mem.replaceOwned(u8, a, disk_json, "Unattached", "Attached");
    defer a.free(attached);
    const replacement = try std.mem.replaceOwned(u8, a, attached, disk_uuid, vm_uuid);
    defer a.free(replacement);
    for ([_]bool{ false, true }) |changed| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = deployment_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = vm_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
            .{ .url = disk_url, .response = disk_json },
            .{ .url = s.arm_host ++ nic_path ++ "?api-version=2024-05-01", .response = nic },
            .{ .url = deployment_url, .method = .PUT, .status = 201, .body_contains = "\"securityType\":\"Standard\"", .response = deployment },
            .{ .url = deployment_url, .response = deployment },
            .{ .url = vm_url, .response = vm_json },
            .{ .url = disk_url, .response = if (changed) replacement else attached },
        });
        defer h.deinit();
        var arm = h.arm();
        const outcome = arm.execute(.{ .deploy = .{ .name = "synthetic-deployment", .resources = &.{.{ .vm = .{
            .name = vm_ref.name,
            .os_disk = disk_identity,
            .nic = .{ .kind = .nic, .name = "synthetic-nic" },
            .size = "Standard_D2s_v5",
        } }} } });
        if (changed) {
            try requireFailure(outcome, .integrity, .accepted, 200);
        } else {
            var result = try requireOk(outcome);
            defer result.deinit();
            try t.expectEqual(@as(usize, 1), result.created.len);
            try t.expectEqual(.vm, result.created[0].kind);
            try t.expectEqualStrings(vm_uuid, &result.created[0].uuid.?);
        }
    }
}

test "typed request constructors encode exact raw strings arrays and numeric fields" {
    const arena = try secret.Arena.create(a);
    defer arena.destroy();
    const alloc = arena.allocator();
    const group = try ops.Plan.create(alloc, authority, .group_create);
    const group_body = try json.parse(alloc, group.body.?);
    try t.expectEqualStrings(run, try models.string(try models.field(group_body, "tags"), "uk-hyperv-run"));
    const schedule = try ops.Plan.create(alloc, authority, .{ .schedule_put = .{ .name = "synthetic-schedule", .vm = vm_ref, .time = "1900".* } });
    const schedule_properties = try models.field(try json.parse(alloc, schedule.body.?), "properties");
    try t.expectEqualStrings("1900", try models.string(try models.field(schedule_properties, "dailyRecurrence"), "time"));
    try t.expectEqualStrings(vm_path, try models.string(schedule_properties, "targetResourceId"));
    const disk = try ops.Plan.create(alloc, authority, .{ .disk_create = .{ .name = disk_ref.name, .size_gib = 4, .upload_bytes = 4294967808 } });
    const disk_properties = try models.field(try json.parse(alloc, disk.body.?), "properties");
    try t.expectEqual(@as(u32, 4), try foundation.contracts.integer(u32, try models.field(disk_properties, "diskSizeGB")));
    try t.expectEqual(@as(u64, 4294967808), try foundation.contracts.integer(u64, try models.field(try models.field(disk_properties, "creationData"), "uploadSizeBytes")));
    const deployment = try ops.Plan.create(alloc, authority, .{ .deploy = .{
        .name = "synthetic-deployment",
        .resources = &.{.{ .vm = .{ .name = vm_ref.name, .os_disk = disk_identity, .nic = .{ .kind = .nic, .name = "synthetic-nic" }, .size = "Standard_D2s_v5" } }},
    } });
    const properties = try models.field(try json.parse(alloc, deployment.body.?), "properties");
    const definitions = try models.array(try models.field(try models.field(properties, "template"), "resources"));
    const vm_properties = try models.field(definitions[0], "properties");
    try t.expectEqualStrings("Standard", try models.string(try models.field(vm_properties, "securityProfile"), "securityType"));
    const profile = try models.field(vm_properties, "storageProfile");
    try t.expectEqual(@as(usize, 0), (try models.array(try models.field(profile, "dataDisks"))).len);
    try t.expectEqualStrings(disk_path, try models.string(try models.field(try models.field(profile, "osDisk"), "managedDisk"), "id"));
    const nics = try models.array(try models.field(try models.field(vm_properties, "networkProfile"), "networkInterfaces"));
    try t.expectEqual(@as(usize, 1), nics.len);
}

test "response progress stops at cancellation or deadline without another read" {
    for ([_]u16{ 200, 403, 500 }) |status| {
        for ([_]@FieldType(Progress, "stop"){ .deadline, .cancellation }) |stop| {
            var h = try Harness.init(&.{.{
                .url = group_url,
                .method = .PUT,
                .authorization = false,
                .status = status,
                .response = if (status == 200) group_json else "{\"error\":{\"code\":\"AuthorizationFailed\",\"message\":\"SYNTHETIC_SECRET\"}}",
                .progress = .{ .stop = stop },
            }});
            defer h.deinit();
            const channel = h.channel();
            var request = sdk.http.Request.init(a, .PUT, group_url);
            defer request.deinit();
            try requireFailure(channel.send(&request, true, .arm), if (stop == .deadline) .timeout else .cancelled, if (status == 200) .accepted else if (status == 403) .rejected else .unknown, status);
            try t.expectEqual(@as(usize, 1), h.response_calls);
            try t.expectEqual(@as(usize, 1), h.response_bytes);
            try t.expectEqual(@as(usize, 0), h.response_calls_after_stop);
            try t.expectEqual(@as(usize, 1), h.mock.?.stream_cancel_count);
        }
    }
}

test "zero progress EOF and read failure still perform the post-read budget check" {
    for ([_]@FieldType(Progress, "on"){ .zero, .eof, .failure }) |event| {
        for ([_]@FieldType(Progress, "stop"){ .deadline, .cancellation }) |stop| {
            var h = try Harness.init(&.{.{
                .url = group_url,
                .method = .PUT,
                .authorization = false,
                .response = if (event == .eof) "" else group_json,
                .progress = .{ .stop = stop, .on = event, .zero_first = event == .zero, .fail_read = event == .failure },
            }});
            defer h.deinit();
            const channel = h.channel();
            var request = sdk.http.Request.init(a, .PUT, group_url);
            defer request.deinit();
            try requireFailure(channel.send(&request, true, .arm), if (stop == .deadline) .timeout else .cancelled, .accepted, 200);
            try t.expectEqual(@as(usize, 1), h.response_calls);
            try t.expectEqual(@as(usize, 0), h.response_bytes);
            try t.expectEqual(@as(usize, 0), h.response_calls_after_stop);
            try t.expectEqual(@as(usize, 1), h.mock.?.stream_cancel_count);
        }
    }
}

test "zero response progress is not EOF and success never invokes unbounded finish" {
    var h = try Harness.init(&.{.{
        .url = group_url,
        .response = group_json,
        .progress = .{ .zero_first = true, .fragment = 7 },
    }});
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .get = group_ref }));
    defer result.deinit();
    try t.expectEqual(.succeeded, result.model.group);
    try t.expectEqual(group_json.len, h.response_bytes);
    try t.expectEqual(@as(usize, (group_json.len + 6) / 7 + 2), h.response_calls);
    try t.expectEqual(@as(usize, 0), h.mock.?.stream_finish_count);
    try t.expectEqual(@as(usize, 1), h.mock.?.stream_abort_count);
}

test "response read failures are not EOF and release the operation without draining" {
    var h = try Harness.init(&.{.{ .url = group_url, .response = group_json, .progress = .{ .fail_read = true } }});
    defer h.deinit();
    var arm = h.arm();
    try requireFailure(arm.execute(.{ .get = group_ref }), .invalid_response, .not_applicable, 200);
    try t.expectEqual(@as(usize, 1), h.response_calls);
    try t.expectEqual(@as(usize, 0), h.mock.?.stream_finish_count);
    try t.expectEqual(@as(usize, 1), h.mock.?.stream_abort_count);
}

test "LRO progress cancellation preserves the accepted initiating mutation" {
    const monitor = s.arm_host ++ "/subscriptions/" ++ sub ++ "/providers/Microsoft.Compute/locations/northeurope/operations/" ++ operation_uuid ++ "?api-version=2025-11-01";
    for ([_]@FieldType(Progress, "stop"){ .deadline, .cancellation }) |stop| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = vm_url, .response = vm_json },
            .{ .url = s.arm_host ++ vm_path ++ "/deallocate?api-version=2025-11-01", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = monitor }} },
            .{ .url = monitor, .response = "{\"status\":\"InProgress\"}", .progress = .{ .stop = stop } },
        });
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .deallocate = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } }), if (stop == .deadline) .timeout else .cancelled, .accepted, 200);
        try t.expectEqual(@as(usize, 1), h.response_calls);
        try t.expectEqual(@as(usize, 0), h.response_calls_after_stop);
        try t.expectEqual(@as(usize, 1), h.mock.?.stream_cancel_count);
    }
}

test "service-sized signed DiskOperations grant preserves opaque encoding and Location monitor" {
    try t.expectEqual(@as(usize, 2956), disk_operation_context.len);
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = upload_disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{
            .{ .name = "Azure-AsyncOperation", .value = disk_status_url },
            .{ .name = "Location", .value = disk_location_url },
        } },
        .{ .url = disk_status_url, .response = "{\"status\":\"InProgress\"}" },
        .{ .url = disk_status_url, .response = "{\"status\":\"Succeeded\"}" },
        .{ .url = disk_location_url, .response = "{\"accessSAS\":\"https://synthetic.blob.storage.azure.net/disk/vhd?sig=SYNTHETIC_SECRET\"}" },
    });
    defer h.deinit();
    var arm = h.arm();
    var result = try requireOk(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }));
    defer result.deinit();
    try t.expect(result.model == .grant);
    try t.expectEqual(.accepted, result.effect);
}

test "signed DiskOperations create and revoke complete with scoped resource readback" {
    var h = try Harness.init(&.{
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .status = 404, .response = "{\"error\":{\"code\":\"ResourceNotFound\"}}" },
        .{ .url = disk_url, .method = .PUT, .status = 202, .headers = &.{
            .{ .name = "Azure-AsyncOperation", .value = disk_status_url },
            .{ .name = "Location", .value = disk_location_url },
        } },
        .{ .url = disk_status_url, .response = "{\"status\":\"Succeeded\"}" },
        .{ .url = disk_url, .response = upload_disk_json },
        .{ .url = group_url, .response = group_json },
        .{ .url = disk_url, .response = upload_disk_json },
        .{ .url = s.arm_host ++ disk_path ++ "/endGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{
            .{ .name = "Azure-AsyncOperation", .value = disk_status_url },
            .{ .name = "Location", .value = disk_location_url },
        } },
        .{ .url = disk_status_url, .response = "{\"status\":\"Succeeded\"}" },
        .{ .url = disk_url, .response = upload_disk_json },
    });
    defer h.deinit();
    var arm = h.arm();
    var created = try requireOk(arm.execute(.{ .disk_create = .{ .name = disk_ref.name, .size_gib = 4, .upload_bytes = 4294967808 } }));
    defer created.deinit();
    try t.expectEqual(.accepted, created.effect);
    var revoked = try requireOk(arm.execute(.{ .revoke = disk_identity }));
    defer revoked.deinit();
    try t.expectEqual(.accepted, revoked.effect);
    try t.expectEqual(.ready_to_upload, revoked.model.disk.access);
}

test "signed DiskOperations duplicate and unknown keys fail without forwarding" {
    for ([_][]const u8{ "p", "api-version", "t", "c", "s", "h", "%68", "extra" }) |key| {
        const bad = try std.fmt.allocPrint(a, "{s}&{s}=SYNTHETIC_PRIVATE", .{ disk_status_url, key });
        defer a.free(bad);
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = disk_url, .response = upload_disk_json },
            .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = bad }} },
        });
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }), .invalid_response, .accepted, 202);
    }
}

test "signed DiskOperations queries cannot escape endpoint scope or API version" {
    for ([_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "https://management.azure.com", .to = "https://untrusted.invalid" },
        .{ .from = "https://management.azure.com", .to = "https://management.azure.com@untrusted.invalid" },
        .{ .from = sub, .to = tenant },
        .{ .from = "Microsoft.Compute", .to = "Microsoft.Network" },
        .{ .from = "northeurope", .to = "westeurope" },
        .{ .from = "DiskOperations", .to = "operations" },
        .{ .from = "DiskOperations", .to = "DiskOperations%2fextra" },
        .{ .from = operation_uuid, .to = operation_uuid ++ "/extra" },
        .{ .from = "2025-01-02", .to = "2025-11-01" },
    }) |change| {
        const bad = try std.mem.replaceOwned(u8, a, disk_status_url, change.from, change.to);
        defer a.free(bad);
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = disk_url, .response = upload_disk_json },
            .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = bad }} },
        });
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }), .invalid_response, .accepted, 202);
    }
}

test "signed DiskOperations requires complete bounded opaque values and exact monitor role" {
    try s.diskOperationQuery(disk_status_url, "2025-01-02", .status);
    try s.diskOperationQuery(disk_location_url, "2025-01-02", .location);
    try t.expectError(error.UnsafeUrl, s.diskOperationQuery(disk_status_url, "2025-01-02", .location));
    try t.expectError(error.UnsafeUrl, s.diskOperationQuery(disk_location_url, "2025-01-02", .status));
    for ([_][]const u8{
        "?api-version=2025-01-02",
        "?p=x&api-version=2025-01-02&t=x&c=x&s=x",
        "?p=x&api-version=2025-01-02&t=x&c=x&s=x&h=",
        "?p=x&api-version=2025-01-02&t=x&c=x&s=x&h=%",
        "?p=x&api-version=2025-01-02&t=x&c=x&s=x&h=%GG",
    }) |query| {
        const bad = try std.fmt.allocPrint(a, "{s}{s}", .{ disk_operation_path, query });
        defer a.free(bad);
        try t.expectError(error.UnsafeUrl, s.diskOperationQuery(bad, "2025-01-02", .status));
    }
    try t.expectError(error.UnsafeUrl, s.diskOperationQuery(disk_status_url ++ "&monitor=false", "2025-01-02", .location));
    try t.expectError(error.UnsafeUrl, s.diskOperationQuery(disk_location_url ++ "&monitor=true", "2025-01-02", .location));
    try t.expectError(error.UnsafeUrl, s.queryVersion(disk_status_url, "2025-01-02", false));
}

test "signed DiskOperations opaque values remain bounded by the complete URL" {
    const prefix = s.arm_host ++ disk_operation_path ++ "?p=x&api-version=2025-01-02&t=x&c=";
    for ([_]struct { endpoint: s.DiskOperationEndpoint, suffix: []const u8 }{
        .{ .endpoint = .status, .suffix = "&s=x&h=x" },
        .{ .endpoint = .location, .suffix = "&s=x&h=x&monitor=true" },
    }) |case| {
        const value = try a.alloc(u8, 4096 - prefix.len - case.suffix.len + 1);
        defer a.free(value);
        @memset(value, 'a');
        const exact = try std.fmt.allocPrint(a, "{s}{s}{s}", .{ prefix, value[0 .. value.len - 1], case.suffix });
        defer a.free(exact);
        const over = try std.fmt.allocPrint(a, "{s}{s}{s}", .{ prefix, value, case.suffix });
        defer a.free(over);
        try t.expectEqual(@as(usize, 4096), exact.len);
        try t.expectEqual(@as(usize, 4097), over.len);
        try s.diskOperationQuery(exact, "2025-01-02", case.endpoint);
        try s.diskOperationQuery(try s.relativeUrl(exact), "2025-01-02", case.endpoint);
        try t.expectError(error.UnsafeUrl, s.relativeUrl(over));
        try t.expectError(error.UnsafeUrl, s.diskOperationQuery(over, "2025-01-02", case.endpoint));
    }
}

test "signed LRO poll failures retain accepted mutation and never become absence or replay" {
    for ([_]?u16{ null, 403, 404 }) |status| {
        var h = try Harness.init(&.{
            .{ .url = group_url, .response = group_json },
            .{ .url = disk_url, .response = upload_disk_json },
            .{ .url = s.arm_host ++ disk_path ++ "/beginGetAccess?api-version=2025-01-02", .method = .POST, .status = 202, .headers = &.{.{ .name = "Azure-AsyncOperation", .value = disk_status_url }} },
            .{ .url = disk_status_url, .fail = status == null, .status = status orelse 200, .response = "{\"error\":{\"code\":\"ResourceNotFound\",\"message\":\"SYNTHETIC_PRIVATE\"}}" },
        });
        defer h.deinit();
        var arm = h.arm();
        try requireFailure(arm.execute(.{ .grant = .{ .identity = disk_identity, .seconds = 600 } }), if (status == null) .transport else if (status == 403) .authorization else .not_found, .accepted, status);
    }
}

test "boot diagnostics initial query has exact ten-minute lifetime and no JSON body" {
    const arena = try secret.Arena.create(a);
    defer arena.destroy();
    const alloc = arena.allocator();
    var plan = try ops.Plan.create(alloc, authority, .{ .boot_diagnostics = .{ .vm = vm_ref, .original_uuid = vm_uuid.* } });
    try t.expectEqualStrings(s.arm_host ++ vm_path ++ "/retrieveBootDiagnosticsData?api-version=2025-11-01&sasUriExpirationTimeInMinutes=10", plan.url);
    try t.expect(plan.body == null);
    for ([_][]const u8{
        "?api-version=2025-11-01",
        "?api-version=2025-11-01&sasUriExpirationTimeInMinutes=120",
        "?api-version=2025-11-01&sasUriExpirationTimeInMinutes=10&sasUriExpirationTimeInMinutes=10",
        "?api-version=2025-11-01&sasUriExpirationTimeInMinutes=10&extra=true",
    }) |query| {
        plan.url = try std.fmt.allocPrint(alloc, "{s}{s}{s}", .{ s.arm_host, plan.path, query });
        try t.expectError(error.UnsafeUrl, plan.validateInitialUrl(alloc));
    }
    var ordinary = try ops.Plan.create(alloc, authority, .{ .get = vm_ref });
    ordinary.url = s.arm_host ++ vm_path ++ "?api-version=2025-11-01&sasUriExpirationTimeInMinutes=10";
    try t.expectError(error.UnsafeUrl, ordinary.validateInitialUrl(alloc));
    try t.expectError(error.UnsafeUrl, s.queryVersion(ordinary.url, "2025-11-01", false));
}

test "credential JSON and OAuth error progress cannot outread their budget" {
    const callback = struct {
        fn assertion(allocator: std.mem.Allocator) ![]u8 {
            return allocator.dupe(u8, "synthetic.header.signature");
        }
    }.assertion;
    for ([_]u16{ 200, 400 }) |status| {
        for ([_]@FieldType(Progress, "stop"){ .deadline, .cancellation }) |stop| {
            var h = try Harness.init(&.{.{
                .url = s.login_host ++ "/" ++ tenant ++ "/oauth2/v2.0/token",
                .method = .POST,
                .authorization = false,
                .status = status,
                .response = if (status == 200) "{\"access_token\":\"synthetic-token\",\"expires_in\":3600,\"token_type\":\"Bearer\"}" else "{\"error\":\"invalid_client\",\"error_description\":\"SYNTHETIC_SECRET\"}",
                .progress = .{ .stop = stop },
            }});
            defer h.deinit();
            try requireFailure(auth.acquire(a, h.channel(), .{
                .authority = authority,
                .provider = .{ .client_assertion = callback },
                .minimum_validity_seconds = 300,
            }), if (stop == .deadline) .timeout else .cancelled, .not_applicable, status);
            try t.expectEqual(@as(usize, 1), h.response_calls);
            try t.expectEqual(@as(usize, 0), h.response_calls_after_stop);
            try t.expectEqual(@as(usize, 1), h.mock.?.stream_cancel_count);
        }
    }
}
