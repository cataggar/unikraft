const std = @import("std");
const sdk = @import("azure_sdk_core");
const az = @import("hyperv_azure");
const core = @import("hyperv_core");
const c = @import("contract.zig");
const p = c.p;
const e = @import("engine.zig");
const j = @import("journal.zig");

pub const Adapter = struct {
    client: *az.client.Client,
    input: *const c.Input,
    failure: az.transport.Failure = .{ .effect = .not_started, .diagnostic = .{ .stage = .arm, .category = .internal } },

    pub fn execute(self: *Adapter, operation: az.operations.Operation) !az.client.Result {
        return switch (self.client.execute(operation)) {
            .ok => |value| value,
            .failed => |failure| {
                self.failure = failure;
                return error.ArmOperationFailed;
            },
        };
    }
    pub fn groupAbsent(self: *Adapter) !bool {
        var result = self.execute(.{ .get = .{ .kind = .group, .name = self.input.approved.authority.group } }) catch |err| {
            if (absence(self.failure, true)) return true;
            return err;
        };
        defer result.deinit();
        return false;
    }
    pub fn inventory(self: *Adapter, partial: bool) !p.Hash {
        var collection = switch (self.client.list(.inventory)) {
            .ok => |value| value,
            .failed => |failure| {
                self.failure = failure;
                return error.ArmOperationFailed;
            },
        };
        defer collection.deinit();
        const r = self.input.approved.resources;
        const expected = [_]az.scope.Ref{ r.vm, r.disk, r.nic, r.nsg, r.vnet, r.storage, r.schedule };
        var seen = [_]bool{false} ** expected.len;
        if ((!partial and collection.items.len != expected.len) or collection.items.len > expected.len) return error.InventoryMismatch;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for (collection.items) |item| {
            if (item != .summary) return error.InventoryMismatch;
            var index: ?usize = null;
            for (expected, 0..) |ref, i| if (same(ref, item.summary.id)) {
                index = i;
            };
            const i = index orelse return error.UnownedResource;
            if (seen[i]) return error.InventoryMismatch;
            seen[i] = true;
            var read = try self.execute(.{ .get = expected[i] });
            defer read.deinit();
            var document = try core.contracts.Document.parse(read.reply.arena.allocator(), read.reply.body, .{ .bytes = 1024 * 1024, .string_bytes = c.p.max_command, .items = 2048, .tokens = 65536 });
            defer document.deinit();
            if (expected[i].kind == .disk) {
                var vm = try self.execute(.{ .get = r.vm });
                defer vm.deinit();
                var vm_document = try core.contracts.Document.parse(self.client.allocator, vm.reply.body, .{ .bytes = 1024 * 1024, .tokens = 65536 });
                defer vm_document.deinit();
                try owner(self.input, vm_document.value());
                try validateOsDisk(self.client.allocator, self.input, vm.model, read.model, document.value());
            } else try owner(self.input, document.value());
            switch (expected[i].kind) {
                .nic, .nsg, .vnet => try validateNetwork(self.client.allocator, self.input, expected[i].kind, document.value()),
                else => {},
            }
            hash.update(read.reply.body);
        }
        return hash.finalResult();
    }
    pub fn inspectHost(self: *Adapter, state: *const j.State) !e.Proof {
        const r = self.input.approved.resources;
        const inventory_hash = try self.inventory(false);
        var vm = try self.execute(.{ .get = r.vm });
        defer vm.deinit();
        var disk = try self.execute(.{ .get = r.disk });
        defer disk.deinit();
        if (vm.model != .vm or disk.model != .disk or vm.model.vm.state != .succeeded or disk.model.disk.state != .succeeded or
            !std.mem.eql(u8, vm.model.vm.size, "Standard_D2s_v5") or vm.model.vm.data_disk != null or
            !same(vm.model.vm.os_disk, r.disk) or !same(vm.model.vm.nic, r.nic) or
            disk.model.disk.bytes != 32 * @as(u64, 1024 * 1024 * 1024) or disk.model.disk.access != .attached)
            return error.HostEnvelopeMismatch;
        if (state.vm_id) |id| try az.models.requireOriginalVm(vm.model, id);
        if (state.disk_id) |id| if (!std.mem.eql(u8, &id, &disk.model.disk.uuid)) return error.OriginalIdentityMismatch;
        var document = try core.contracts.Document.parse(vm.reply.arena.allocator(), vm.reply.body, .{ .bytes = 1024 * 1024, .string_bytes = c.p.max_command, .items = 2048, .tokens = 65536 });
        defer document.deinit();
        const principal = try validateAgentless(self.input, document.value());
        if (state.principal_id) |id| if (!std.mem.eql(u8, &id, &principal)) return error.OriginalIdentityMismatch;
        return .{ .digest = inventory_hash, .effect = .not_applicable, .vm_id = vm.model.vm.uuid, .disk_id = disk.model.disk.uuid, .principal_id = principal };
    }

    /// Only this reviewed specialized-image shape can be sent. No template,
    /// resource type, API version, URL or arbitrary command is supplied by a job.
    pub fn deploy(self: *Adapter) !e.Proof {
        var existing = try self.execute(.{ .get = .{ .kind = .group, .name = self.input.approved.authority.group } });
        defer existing.deinit();
        if (existing.model != .group or existing.model.group != .succeeded) return error.GroupNotReady;
        _ = try self.inventory(true);
        var collection = switch (self.client.list(.inventory)) {
            .ok => |value| value,
            .failed => |failure| {
                self.failure = failure;
                return error.ArmOperationFailed;
            },
        };
        defer collection.deinit();
        if (collection.items.len != 0) return error.GroupNotEmpty;
        const a = self.client.allocator;
        const body = try deploymentBody(a, self.input);
        defer a.free(body);
        var reply = try self.resourceRequest(.PUT, self.input.approved.resources.deployment, body);
        defer reply.deinit();
        if (reply.status != 200 and reply.status != 201 and reply.status != 202) return error.UnexpectedStatus;
        for (0..self.client.channel.budget.max_polls) |_| {
            var observed = self.execute(.{ .get = self.input.approved.resources.deployment }) catch |err| {
                self.failure.effect = .accepted;
                return err;
            };
            defer observed.deinit();
            if (observed.model != .deployment) return error.InvalidDeployment;
            if (observed.model.deployment == .succeeded) return .{ .digest = p.hash(observed.reply.body), .effect = .accepted };
            if (observed.model.deployment == .failed or observed.model.deployment == .canceled) return error.DeploymentFailed;
            try self.client.channel.budget.sleep(1000);
        }
        self.failure.effect = .accepted;
        return error.Deadline;
    }

    pub fn roles(self: *Adapter, state: *const j.State, remove: bool) !p.Hash {
        const principal = state.principal_id orelse return error.MissingHostIdentity;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for ([_]bool{ false, true }) |evidence_role| {
            const a = self.client.allocator;
            const path = try rolePath(a, self.input, evidence_role);
            defer a.free(path);
            const properties = try roleProperties(a, self.input, principal, evidence_role);
            defer a.free(properties);
            if (!remove) {
                var before = self.roleRequest(.GET, path, null) catch |err| {
                    if (!absence(self.failure, false)) return err;
                    var added = try self.roleRequest(.PUT, path, properties);
                    defer added.deinit();
                    if (added.status != 200 and added.status != 201) return error.RoleAssignmentFailed;
                    var observed = try self.roleRequest(.GET, path, null);
                    defer observed.deinit();
                    try validateRole(a, observed.body, properties, path);
                    hash.update(observed.body);
                    continue;
                };
                before.deinit();
                return error.RoleAlreadyExists;
            }
            var prior = self.roleRequest(.GET, path, null) catch |err| {
                if (absence(self.failure, false)) {
                    hash.update(path);
                    hash.update("absent");
                    continue;
                }
                return err;
            };
            defer prior.deinit();
            try validateRole(a, prior.body, properties, path);
            var removed = try self.roleRequest(.DELETE, path, null);
            defer removed.deinit();
            if (removed.status != 200 and removed.status != 202 and removed.status != 204) return error.RoleAssignmentFailed;
            var gone = false;
            for (0..self.client.channel.budget.max_polls) |_| {
                var observed = self.roleRequest(.GET, path, null) catch |err| {
                    if (absence(self.failure, false)) {
                        gone = true;
                        break;
                    }
                    return err;
                };
                observed.deinit();
                try self.client.channel.budget.sleep(1000);
            }
            if (!gone) return error.RoleStillPresent;
            hash.update(path);
            hash.update("independently-absent");
        }
        return hash.finalResult();
    }

    fn resourceRequest(self: *Adapter, method: sdk.http.Method, ref: az.scope.Ref, body: ?[]const u8) !az.transport.Reply {
        if (ref.kind != .deployment or !same(ref, self.input.approved.resources.deployment)) return error.InvalidOperation;
        const path = try ref.path(self.client.allocator, self.input.approved.authority);
        defer self.client.allocator.free(path);
        return self.send(method, path, ref.kind.version(), body);
    }
    fn roleRequest(self: *Adapter, method: sdk.http.Method, path: []const u8, body: ?[]const u8) !az.transport.Reply {
        return self.send(method, path, "2022-04-01", body);
    }
    fn send(self: *Adapter, method: sdk.http.Method, path: []const u8, version: []const u8, body: ?[]const u8) !az.transport.Reply {
        const arena = try az.secret.Arena.create(self.client.allocator);
        defer arena.destroy();
        const a = arena.allocator();
        try self.client.token.require(self.input.approved.authority, self.client.channel.budget.clock.unixSecondsFn(self.client.channel.budget.clock.context), 1);
        const url = try std.fmt.allocPrint(a, "{s}{s}?api-version={s}", .{ az.scope.arm_host, path, version });
        var request = sdk.http.Request.init(a, method, url);
        defer request.deinit();
        request.body = body;
        try request.setHeader("Authorization", try std.fmt.allocPrint(a, "Bearer {s}", .{self.client.token.value.bytes}));
        try request.setHeader("Accept", "application/json");
        if (body != null) try request.setHeader("Content-Type", "application/json");
        if (method == .PUT) try request.setHeader("If-None-Match", "*");
        var reply = switch (self.client.channel.send(&request, method != .GET, .arm)) {
            .ok => |value| value,
            .failed => |failure| {
                self.failure = failure;
                return error.ArmOperationFailed;
            },
        };
        errdefer reply.deinit();
        if (method != .GET) self.failure.effect = .accepted;
        // Poll only the known resource. Never follow a service-supplied authority.
        for ([_]?[]const u8{ reply.location, reply.async_operation, reply.operation_location }) |next| if (next) |raw| {
            const relative = try az.scope.relativeUrl(raw);
            const query = std.mem.indexOfScalar(u8, relative, '?') orelse return error.UnsafeOperationScope;
            if (!std.ascii.eqlIgnoreCase(relative[0..query], path) and
                !(std.ascii.startsWithIgnoreCase(relative[0..query], path) and relative[query - 1] != '/' and
                    relative.len > path.len and relative[path.len] == '/')) return error.UnsafeOperationScope;
            try az.scope.queryVersion(relative, version, false);
        };
        return reply;
    }
};

pub fn absence(failure: az.transport.Failure, group: bool) bool {
    return failure.diagnostic.http_status == 404 and failure.diagnostic.category == .not_found and
        (failure.diagnostic.service_code == .ResourceGroupNotFound or (!group and failure.diagnostic.service_code == .ResourceNotFound));
}
fn same(a: az.scope.Ref, b: az.scope.Ref) bool {
    return a.kind == b.kind and std.ascii.eqlIgnoreCase(a.name, b.name) and
        std.mem.eql(u8, a.parent orelse "", b.parent orelse "") and std.mem.eql(u8, a.gallery_image orelse "", b.gallery_image orelse "");
}
pub fn owner(input: *const c.Input, value: std.json.Value) !void {
    const tag = try az.models.string(try az.models.field(value, "tags"), "uk-hyperv-run");
    if (!std.mem.eql(u8, tag, &input.approved.authority.owner_run)) return error.OwnershipMismatch;
}
pub fn validateAgentless(input: *const c.Input, value: std.json.Value) !c.Uuid {
    try owner(input, value);
    const identity = try az.models.field(value, "identity");
    if (!std.mem.eql(u8, try az.models.string(identity, "type"), "SystemAssigned") or
        !std.mem.eql(u8, try az.models.string(identity, "tenantId"), &input.approved.authority.tenant)) return error.IdentityNotAdmitted;
    if (identity.object.get("userAssignedIdentities")) |extra| if (extra != .object or extra.object.count() != 0) return error.IdentityNotAdmitted;
    const principal = try az.scope.uuid(try az.models.string(identity, "principalId"));
    const properties = try az.models.field(value, "properties");
    const os = try az.models.field(properties, "osProfile");
    const linux = try az.models.field(os, "linuxConfiguration");
    if (try az.models.boolean(try az.models.field(linux, "provisionVMAgent")) or
        try az.models.boolean(try az.models.field(os, "allowExtensionOperations"))) return error.AgentNotDisabled;
    const reference = try az.models.field(try az.models.field(properties, "storageProfile"), "imageReference");
    if (!std.ascii.eqlIgnoreCase(try az.models.string(reference, "id"), input.approved.image_id)) return error.ImageMismatch;
    if (properties.object.get("extensions")) |extensions| if ((try az.models.array(extensions)).len != 0) return error.AgentNotDisabled;
    return principal;
}

fn rolePath(a: std.mem.Allocator, input: *const c.Input, evidence_role: bool) ![]u8 {
    const account = try input.approved.resources.storage.path(a, input.approved.authority);
    defer a.free(account);
    // Admission has already checked this container through the host contract.
    var admission = try input.validate(a, input.approved.not_before);
    defer admission.deinit();
    return std.fmt.allocPrint(a, "{s}/blobServices/default/containers/{s}/providers/Microsoft.Authorization/roleAssignments/{s}", .{ account, admission.container, if (evidence_role) input.approved.resources.evidence_role else input.approved.resources.input_role });
}
fn roleProperties(a: std.mem.Allocator, input: *const c.Input, principal: c.Uuid, evidence_role: bool) ![]u8 {
    const role = if (evidence_role) "ba92f5b4-2d11-453d-a403-e96b0029c9fe" else "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1";
    const definition = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers/Microsoft.Authorization/roleDefinitions/{s}", .{ input.approved.authority.subscription, role });
    defer a.free(definition);
    const condition = if (evidence_role) try std.fmt.allocPrint(a, "(@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringLike 'runs/{s}/evidence/*')", .{input.approved.authority.owner_run}) else null;
    defer if (condition) |value| a.free(value);
    return c.canonical(a, .{ .properties = .{
        .roleDefinitionId = definition,
        .principalId = @as([]const u8, &principal),
        .principalType = "ServicePrincipal",
        .conditionVersion = if (evidence_role) @as(?[]const u8, "2.0") else null,
        .condition = condition,
    } });
}
pub fn validateRole(a: std.mem.Allocator, bytes: []const u8, expected: []const u8, path: []const u8) !void {
    var want = try core.contracts.Document.parse(a, expected, .{});
    defer want.deinit();
    var actual = try core.contracts.Document.parse(a, bytes, .{});
    defer actual.deinit();
    if (!std.ascii.eqlIgnoreCase(try az.models.string(actual.value(), "id"), path)) return error.RoleMismatch;
    const properties = try az.models.field(actual.value(), "properties");
    const end = std.mem.indexOf(u8, path, "/providers/Microsoft.Authorization/roleAssignments/") orelse return error.RoleMismatch;
    if (!std.ascii.eqlIgnoreCase(try az.models.string(properties, "scope"), path[0..end])) return error.RoleMismatch;
    const wanted = try az.models.field(want.value(), "properties");
    for (wanted.object.keys(), wanted.object.values()) |name, value| {
        const observed = properties.object.get(name) orelse if (value == .null) continue else return error.RoleMismatch;
        if (value == .null) {
            if (observed != .null) return error.RoleMismatch;
        } else if (!std.mem.eql(u8, try core.contracts.string(value), try core.contracts.string(observed))) return error.RoleMismatch;
    }
}

pub fn validateOsDisk(a: std.mem.Allocator, input: *const c.Input, vm: az.models.Model, disk: az.models.Model, value: std.json.Value) !void {
    if (vm != .vm or disk != .disk or !same(vm.vm.os_disk, input.approved.resources.disk) or
        disk.disk.bytes != 32 * @as(u64, 1024 * 1024 * 1024) or disk.disk.access != .attached or
        !std.mem.eql(u8, try az.models.string(try az.models.field(value, "sku"), "name"), "StandardSSD_LRS"))
        return error.HostEnvelopeMismatch;
    // An implicit OS disk does not inherit VM tags. Ownership is its exact
    // approved disk reference and managedBy backlink, never an assumed tag.
    try input.approved.resources.vm.requireId(a, input.approved.authority, try az.models.string(value, "managedBy"));
}

const Rule = struct {
    name: []const u8,
    properties: struct {
        protocol: []const u8 = "*",
        sourcePortRange: []const u8 = "*",
        destinationPortRange: []const u8 = "*",
        sourceAddressPrefix: []const u8 = "*",
        destinationAddressPrefix: []const u8 = "*",
        access: []const u8,
        priority: u16,
        direction: []const u8,
    },
};
pub const rules = [_]Rule{
    .{ .name = "deny-inbound", .properties = .{ .access = "Deny", .priority = 100, .direction = "Inbound" } },
    .{ .name = "storage-https", .properties = .{ .access = "Allow", .priority = 110, .direction = "Outbound", .protocol = "Tcp", .destinationPortRange = "443", .destinationAddressPrefix = "Storage.NorthEurope" } },
    .{ .name = "azure-dns-udp", .properties = .{ .access = "Allow", .priority = 120, .direction = "Outbound", .protocol = "Udp", .destinationPortRange = "53", .destinationAddressPrefix = "168.63.129.16" } },
    .{ .name = "azure-dns-tcp", .properties = .{ .access = "Allow", .priority = 130, .direction = "Outbound", .protocol = "Tcp", .destinationPortRange = "53", .destinationAddressPrefix = "168.63.129.16" } },
    .{ .name = "native-imds", .properties = .{ .access = "Allow", .priority = 140, .direction = "Outbound", .protocol = "Tcp", .destinationPortRange = "80", .destinationAddressPrefix = "169.254.169.254" } },
    .{ .name = "deny-outbound", .properties = .{ .access = "Deny", .priority = 200, .direction = "Outbound" } },
};
pub fn validateNetwork(a: std.mem.Allocator, input: *const c.Input, kind: az.scope.Kind, value: std.json.Value) !void {
    const properties = try az.models.field(value, "properties");
    const r = input.approved.resources;
    switch (kind) {
        .nsg => {
            const observed = try az.models.array(try az.models.field(properties, "securityRules"));
            if (observed.len != rules.len) return error.RouteMismatch;
            for (rules) |wanted| {
                var count: usize = 0;
                for (observed) |item| if (std.mem.eql(u8, try az.models.string(item, "name"), wanted.name)) {
                    count += 1;
                    const actual = try az.models.field(item, "properties");
                    inline for (std.meta.fields(@TypeOf(wanted.properties))) |field| {
                        const raw = try az.models.field(actual, field.name);
                        if (field.type == u16) {
                            if (try core.contracts.integer(u16, raw) != @field(wanted.properties, field.name)) return error.RouteMismatch;
                        } else if (!std.mem.eql(u8, try core.contracts.string(raw), @field(wanted.properties, field.name))) return error.RouteMismatch;
                    }
                };
                if (count != 1) return error.RouteMismatch;
            }
        },
        .nic => {
            try r.nsg.requireId(a, input.approved.authority, try az.models.string(try az.models.field(properties, "networkSecurityGroup"), "id"));
            const configs = try az.models.array(try az.models.field(properties, "ipConfigurations"));
            if (configs.len != 1) return error.RouteMismatch;
            const config = try az.models.field(configs[0], "properties");
            try r.subnet.requireId(a, input.approved.authority, try az.models.string(try az.models.field(config, "subnet"), "id"));
        },
        .vnet => {
            const subnets = try az.models.array(try az.models.field(properties, "subnets"));
            if (subnets.len != 1) return error.RouteMismatch;
            try r.subnet.requireId(a, input.approved.authority, try az.models.string(subnets[0], "id"));
            const subnet = try az.models.field(subnets[0], "properties");
            if (!std.mem.eql(u8, try az.models.string(subnet, "addressPrefix"), "10.120.0.0/24") or
                try az.models.boolean(try az.models.field(subnet, "defaultOutboundAccess"))) return error.RouteMismatch;
            for ([_][]const u8{ "natGateway", "routeTable" }) |name| if (subnet.object.get(name)) |v| if (v != .null) return error.RouteMismatch;
            const endpoints = try az.models.array(try az.models.field(subnet, "serviceEndpoints"));
            if (endpoints.len != 1 or !std.mem.eql(u8, try az.models.string(endpoints[0], "service"), "Microsoft.Storage")) return error.RouteMismatch;
        },
        else => return error.InvalidOperation,
    }
}

pub fn deploymentBody(a: std.mem.Allocator, input: *const c.Input) ![]u8 {
    const arena = try az.secret.Arena.create(a);
    defer arena.destroy();
    const scratch = arena.allocator();
    const scope = input.approved.authority;
    const r = input.approved.resources;
    const tags = .{ .@"uk-hyperv-run" = @as([]const u8, &scope.owner_run) };
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    try out.writer.writeAll("{\"properties\":{\"mode\":\"Incremental\",\"template\":{\"$schema\":\"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#\",\"contentVersion\":\"1.0.0.0\",\"resources\":[");
    try std.json.Stringify.value(.{
        .type = "Microsoft.Network/networkSecurityGroups",
        .apiVersion = r.nsg.kind.version(),
        .name = r.nsg.name,
        .location = scope.location,
        .tags = tags,
        .properties = .{ .securityRules = rules },
    }, .{}, &out.writer);
    try out.writer.writeByte(',');
    try std.json.Stringify.value(.{
        .type = "Microsoft.Network/virtualNetworks",
        .apiVersion = r.vnet.kind.version(),
        .name = r.vnet.name,
        .location = scope.location,
        .tags = tags,
        .properties = .{ .addressSpace = .{ .addressPrefixes = &.{"10.120.0.0/24"} }, .subnets = &.{.{ .name = r.subnet.name, .properties = .{ .addressPrefix = "10.120.0.0/24", .defaultOutboundAccess = false, .serviceEndpoints = &.{.{ .service = "Microsoft.Storage", .locations = &.{"northeurope"} }} } }} },
    }, .{}, &out.writer);
    try out.writer.writeByte(',');
    try std.json.Stringify.value(.{
        .type = "Microsoft.Network/networkInterfaces",
        .apiVersion = r.nic.kind.version(),
        .name = r.nic.name,
        .location = scope.location,
        .tags = tags,
        .dependsOn = &.{ try r.vnet.path(scratch, scope), try r.nsg.path(scratch, scope) },
        .properties = .{ .enableIPForwarding = false, .networkSecurityGroup = .{ .id = try r.nsg.path(scratch, scope) }, .ipConfigurations = &.{.{ .name = "ipconfig1", .properties = .{ .privateIPAllocationMethod = "Dynamic", .subnet = .{ .id = try r.subnet.path(scratch, scope) } } }} },
    }, .{}, &out.writer);
    try out.writer.writeByte(',');
    try std.json.Stringify.value(.{
        .type = "Microsoft.Storage/storageAccounts",
        .apiVersion = r.storage.kind.version(),
        .name = r.storage.name,
        .location = scope.location,
        .tags = tags,
        .kind = "StorageV2",
        .dependsOn = &.{try r.vnet.path(scratch, scope)},
        .sku = .{ .name = "Standard_LRS" },
        .properties = .{ .supportsHttpsTrafficOnly = true, .allowBlobPublicAccess = false, .minimumTlsVersion = "TLS1_2", .publicNetworkAccess = "Enabled", .networkAcls = .{ .bypass = "None", .defaultAction = "Deny", .ipRules = [_]std.json.Value{}, .virtualNetworkRules = &.{.{ .id = try r.subnet.path(scratch, scope), .action = "Allow" }}, .resourceAccessRules = [_]std.json.Value{} } },
    }, .{}, &out.writer);
    try out.writer.writeByte(',');
    try std.json.Stringify.value(.{
        .type = "Microsoft.Compute/virtualMachines",
        .apiVersion = r.vm.kind.version(),
        .name = r.vm.name,
        .location = scope.location,
        .tags = tags,
        .identity = .{ .type = "SystemAssigned" },
        .dependsOn = &.{try r.nic.path(scratch, scope)},
        .properties = .{
            .hardwareProfile = .{ .vmSize = "Standard_D2s_v5" },
            .securityProfile = .{ .securityType = "Standard" },
            .storageProfile = .{ .imageReference = .{ .id = input.approved.image_id }, .osDisk = .{
                .name = r.disk.name,
                .createOption = "FromImage",
                .diskSizeGB = 32,
                .caching = "None",
                .deleteOption = "Detach",
                .managedDisk = .{ .storageAccountType = "StandardSSD_LRS" },
            }, .dataDisks = [_]std.json.Value{} },
            .networkProfile = .{ .networkInterfaces = &.{.{ .id = try r.nic.path(scratch, scope) }} },
            .diagnosticsProfile = .{ .bootDiagnostics = .{ .enabled = true } },
        },
    }, .{}, &out.writer);
    try out.writer.writeByte(',');
    const shutdown = std.time.epoch.EpochSeconds{ .secs = input.approved.expires_at };
    var time: [4]u8 = undefined;
    _ = try std.fmt.bufPrint(&time, "{d:0>2}{d:0>2}", .{ shutdown.getDaySeconds().getHoursIntoDay(), shutdown.getDaySeconds().getMinutesIntoHour() });
    try std.json.Stringify.value(.{
        .type = "Microsoft.DevTestLab/schedules",
        .apiVersion = r.schedule.kind.version(),
        .name = r.schedule.name,
        .location = scope.location,
        .tags = tags,
        .dependsOn = &.{try r.vm.path(scratch, scope)},
        .properties = .{ .status = "Enabled", .taskType = "ComputeVmShutdownTask", .targetResourceId = try r.vm.path(scratch, scope), .dailyRecurrence = .{ .time = @as([]const u8, &time) }, .timeZoneId = "UTC", .notificationSettings = .{ .status = "Disabled" } },
    }, .{}, &out.writer);
    try out.writer.writeAll("]}}}\n");
    if (out.written().len > 32768) return error.InvalidDeployment;
    return out.toOwnedSlice();
}
