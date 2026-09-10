const std = @import("std");
const sdk = @import("azure_sdk_core");
const s = @import("scope.zig");
const secret = @import("secret.zig");
const auth = @import("auth.zig");
const ops = @import("operations.zig");
const models = @import("models.zig");
const json = @import("json.zig");
const wire = @import("transport.zig");

pub const Created = struct { kind: s.Kind, name: []const u8, uuid: ?s.Uuid, disk_bytes: ?u64 };
pub const Result = struct {
    reply: wire.Reply,
    model: models.Model,
    effect: wire.Effect,
    created: []const Created = &.{},
    pub fn deinit(self: *Result) void {
        self.reply.deinit();
        self.* = undefined;
    }
};
pub const Collection = struct {
    arena: *secret.Arena,
    items: []const models.Model,
    pages: u16,
    pub fn deinit(self: *Collection) void {
        self.arena.destroy();
        self.* = undefined;
    }
};

/// Caller-serialized. Does not persist mutation intent, acquire credentials,
/// infer approval, or retry a mutation. Those are controller/parent obligations.
pub const Client = struct {
    allocator: std.mem.Allocator,
    authority: s.Authority,
    token: *const auth.Token,
    channel: wire.Channel,

    pub fn execute(self: *Client, operation: ops.Operation) wire.Outcome(Result) {
        const arena = secret.Arena.create(self.allocator) catch |err| return fail(err, .not_started, null);
        defer arena.destroy();
        const a = arena.allocator();
        const plan = ops.Plan.create(a, self.authority, operation) catch |err| return fail(err, .not_started, null);
        if (operation.isList()) return fail(error.UseListOperation, .not_started, null);

        if (operation == .group_create) {
            var current = self.read(.{ .get = .{ .kind = .group, .name = self.authority.group } });
            switch (current) {
                .ok => |*existing| {
                    const status = existing.reply.status;
                    existing.deinit();
                    return .{ .failed = .{ .effect = .not_started, .diagnostic = .{ .stage = .arm, .category = .conflict, .http_status = status } } };
                },
                .failed => |failure| if (!isAbsence(failure, .group)) return beforeMutation(failure, operation),
            }
        } else if (operation.isMutation() or operation == .list_keys or operation == .boot_diagnostics) {
            var group = switch (self.read(.{ .get = .{ .kind = .group, .name = self.authority.group } })) {
                .ok => |group| group,
                .failed => |failure| {
                    if ((operation == .group_delete or operation == .schedule_delete) and isAbsence(failure, .group))
                        return self.absent(.not_started);
                    return beforeMutation(failure, operation);
                },
            };
            defer group.deinit();
            if (group.model != .group or group.model.group != .succeeded) return fail(error.GroupNotReady, .not_started, group.reply.status);
        }
        switch (operation) {
            .disk_create => |disk| {
                if (self.requireAbsent(.{ .kind = .disk, .name = disk.name })) |failure| return .{ .failed = failure };
            },
            .deploy => |deployment| {
                if (self.requireAbsent(.{ .kind = .deployment, .name = deployment.name })) |failure| return .{ .failed = failure };
                for (deployment.resources) |resource| {
                    const ref: s.Ref = switch (resource) {
                        .disk => |disk| .{ .kind = .disk, .name = disk.name },
                        .vm => |vm| .{ .kind = .vm, .name = vm.name },
                        .storage => |storage| .{ .kind = .storage, .name = storage.name },
                    };
                    if (self.requireAbsent(ref)) |failure| return .{ .failed = failure };
                    if (resource == .vm) {
                        if (self.checkAttachment(resource.vm.os_disk, .not_started)) |failure| return .{ .failed = failure };
                        if (resource.vm.data_disk) |disk| if (self.checkAttachment(disk, .not_started)) |failure| return .{ .failed = failure };
                        var nic = switch (self.read(.{ .get = resource.vm.nic })) {
                            .ok => |value| value,
                            .failed => |failure| return beforeMutation(failure, operation),
                        };
                        defer nic.deinit();
                        if (nic.model != .network) return fail(error.InvalidNetwork, .not_started, nic.reply.status);
                    }
                }
            },
            .deallocate, .start, .boot_diagnostics => |action| {
                var current = switch (self.read(.{ .get = action.vm })) {
                    .ok => |value| value,
                    .failed => |failure| return beforeMutation(failure, operation),
                };
                defer current.deinit();
                models.requireOriginalVm(current.model, action.original_uuid) catch |err| return fail(err, .not_started, current.reply.status);
            },
            .grant, .revoke => {
                const identity = if (operation == .grant) operation.grant.identity else operation.revoke;
                var current = switch (self.read(.{ .get = identity.disk })) {
                    .ok => |value| value,
                    .failed => |failure| return beforeMutation(failure, operation),
                };
                defer current.deinit();
                models.requireOriginalDisk(current.model, identity) catch |err| return fail(err, .not_started, current.reply.status);
                if (operation == .grant and (current.model.disk.access != .ready_to_upload or current.model.disk.upload_bytes == null))
                    return fail(error.InvalidDiskState, .not_started, current.reply.status);
            },
            .firewall => |firewall| {
                var current = switch (self.read(.{ .get = firewall.account })) {
                    .ok => |value| value,
                    .failed => |failure| return beforeMutation(failure, operation),
                };
                defer current.deinit();
                if (current.model != .storage or !std.meta.eql(current.model.storage.ip, firewall.before_address))
                    return fail(error.FirewallScopeMismatch, .not_started, current.reply.status);
                sameSubnets(a, self.authority, current.model.storage.subnets, firewall.subnets) catch |err|
                    return fail(err, .not_started, current.reply.status);
            },
            .regenerate_key => |key| {
                var current = switch (self.read(.{ .list_keys = key.account })) {
                    .ok => |value| value,
                    .failed => |failure| return beforeMutation(failure, operation),
                };
                defer current.deinit();
                if (current.model != .keys or !std.crypto.timing_safe.eql([32]u8, current.model.keys.digest(.key1), key.previous.key1) or
                    !std.crypto.timing_safe.eql([32]u8, current.model.keys.digest(.key2), key.previous.key2))
                    return fail(error.HashMismatch, .not_started, current.reply.status);
            },
            else => {},
        }
        var reply = switch (self.exchange(plan, plan.url)) {
            .ok => |reply| reply,
            .failed => |failure| return .{ .failed = failure },
        };
        if (!operation.isMutation()) return self.decode(plan, reply, .not_applicable);
        return self.complete(a, plan, &reply);
    }

    /// A read is never automatically replayed. Reconciliation performs separately
    /// bounded observations; it does not repeat the initiating PUT/POST/DELETE.
    fn read(self: *Client, operation: ops.Operation) wire.Outcome(Result) {
        const arena = secret.Arena.create(self.allocator) catch |err| return fail(err, .not_started, null);
        defer arena.destroy();
        const plan = ops.Plan.create(arena.allocator(), self.authority, operation) catch |err| return fail(err, .not_started, null);
        if (operation.isMutation() or operation.isList()) return fail(error.InvalidRead, .not_started, null);
        const reply = switch (self.exchange(plan, plan.url)) {
            .ok => |reply| reply,
            .failed => |failure| return .{ .failed = failure },
        };
        return self.decode(plan, reply, .not_applicable);
    }

    pub fn list(self: *Client, operation: ops.Operation) wire.Outcome(Collection) {
        const arena = secret.Arena.create(self.allocator) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        var keep = false;
        defer if (!keep) arena.destroy();
        const a = arena.allocator();
        const plan = ops.Plan.create(a, self.authority, operation) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        if (!operation.isList()) return .{ .failed = wire.Failure.local(.arm, error.NotListOperation, .not_started, null) };
        var url = plan.url;
        var visited: std.ArrayList([]const u8) = .empty;
        var items: std.ArrayList(models.Model) = .empty;
        var pages: u16 = 0;
        var observed_items: usize = 0;
        while (true) {
            if (pages >= self.channel.budget.max_pages) return .{ .failed = wire.Failure.local(.arm, error.LimitExceeded, .not_applicable, null) };
            for (visited.items) |previous| if (std.mem.eql(u8, previous, url))
                return .{ .failed = wire.Failure.local(.arm, error.ContinuationCycle, .not_applicable, null) };
            visited.append(a, url) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, null) };
            var reply = switch (self.exchange(plan, url)) {
                .ok => |reply| reply,
                .failed => |failure| return .{ .failed = failure },
            };
            defer reply.deinit();
            pages += 1;
            if (reply.status != 200) return .{ .failed = wire.Failure.local(.arm, error.UnexpectedStatus, .not_applicable, reply.status) };
            const root = json.parse(a, reply.body) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, reply.status) };
            if (root != .object or root.object.count() > 2 or !root.object.contains("value") or
                (root.object.count() == 2 and !root.object.contains("nextLink"))) return .{ .failed = wire.Failure.local(.arm, error.InvalidPage, .not_applicable, reply.status) };
            const values = models.array(root.object.get("value").?) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, reply.status) };
            if (values.len > self.channel.budget.max_items -| observed_items) return .{ .failed = wire.Failure.local(.arm, error.LimitExceeded, .not_applicable, reply.status) };
            observed_items += values.len;
            for (values) |value| {
                if (operation == .skus) {
                    const resource_type = models.string(value, "resourceType") catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, reply.status) };
                    if (!std.mem.eql(u8, resource_type, "virtualMachines")) continue;
                }
                const model = models.parse(a, self.authority, operation, value) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, reply.status) };
                items.append(a, model) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, reply.status) };
            }
            const next = root.object.get("nextLink") orelse break;
            if (next == .null) break;
            if (next != .string) return .{ .failed = wire.Failure.local(.arm, error.InvalidPage, .not_applicable, reply.status) };
            url = s.continuationFiltered(a, plan.path, next.string, plan.version, plan.filter) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_applicable, reply.status) };
        }
        keep = true;
        return .{ .ok = .{ .arena = arena, .items = items.items, .pages = pages } };
    }

    fn exchange(self: *Client, plan: ops.Plan, url: []const u8) wire.Outcome(wire.Reply) {
        self.token.require(self.authority, self.channel.budget.clock.unixSecondsFn(self.channel.budget.clock.context), 1) catch |err|
            return .{ .failed = wire.Failure.local(.credential, err, .not_started, null) };
        const arena = secret.Arena.create(self.allocator) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        defer arena.destroy();
        const a = arena.allocator();
        var request = sdk.http.Request.init(a, plan.method, url);
        defer request.deinit();
        request.body = plan.body;
        const bearer = std.fmt.allocPrint(a, "Bearer {s}", .{self.token.value.bytes}) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        request.setHeader("Authorization", bearer) catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        request.setHeader("Accept", "application/json") catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        if (request.body != null) request.setHeader("Content-Type", "application/json") catch |err| return .{ .failed = wire.Failure.local(.arm, err, .not_started, null) };
        return self.channel.send(&request, plan.mutation, .arm);
    }

    fn decode(self: *Client, plan: ops.Plan, reply: wire.Reply, effect: wire.Effect) wire.Outcome(Result) {
        var owned = reply;
        var keep = false;
        defer if (!keep) owned.deinit();
        const allows_empty = plan.operation == .revoke or plan.operation == .deallocate or plan.operation == .start or
            plan.operation == .group_delete or plan.operation == .schedule_delete;
        if (owned.status != 200 and !(allows_empty and owned.status == 204)) return fail(error.UnexpectedStatus, effect, owned.status);
        var model: models.Model = .empty;
        if (owned.body.len != 0) {
            const value = json.parse(owned.arena.allocator(), owned.body) catch |err| return fail(err, effect, owned.status);
            model = models.parse(owned.arena.allocator(), self.authority, plan.operation, value) catch |err| return fail(err, effect, owned.status);
            if (plan.operation == .provider and (model != .provider or !std.mem.eql(u8, model.provider.namespace, plan.operation.provider.wire())))
                return fail(error.ProviderMismatch, effect, owned.status);
            if (plan.operation == .regenerate_key) {
                const key = plan.operation.regenerate_key;
                const other: ops.Key = if (key.key == .key1) .key2 else .key1;
                const selected_digest = if (key.key == .key1) key.previous.key1 else key.previous.key2;
                const other_digest = if (key.key == .key1) key.previous.key2 else key.previous.key1;
                if (model != .keys or std.crypto.timing_safe.eql([32]u8, model.keys.digest(key.key), selected_digest) or
                    !std.crypto.timing_safe.eql([32]u8, model.keys.digest(other), other_digest))
                    return fail(error.HashMismatch, effect, owned.status);
            }
        } else if (plan.operation != .revoke and plan.operation != .deallocate and plan.operation != .start and
            plan.operation != .group_delete and plan.operation != .schedule_delete) return fail(error.EmptyResponse, effect, owned.status);
        keep = true;
        return .{ .ok = .{ .reply = owned, .model = model, .effect = effect } };
    }

    fn complete(self: *Client, a: std.mem.Allocator, plan: ops.Plan, initial: *wire.Reply) wire.Outcome(Result) {
        var reply = initial.*;
        var handed_off = false;
        defer if (!handed_off) reply.deinit();
        if (reply.status != 200 and reply.status != 201 and reply.status != 202 and reply.status != 204)
            return fail(error.UnexpectedStatus, .accepted, reply.status);
        if (reply.body.len != 0) {
            const value = json.parse(a, reply.body) catch |err| return fail(err, .accepted, reply.status);
            if (value != .object) return fail(error.InvalidActionResponse, .accepted, reply.status);
            if (value.object.get("error")) |err| if (err != .null) return fail(error.RemoteFailed, .accepted, reply.status);
            const state_value = value.object.get("status") orelse state: {
                const properties = value.object.get("properties") orelse break :state null;
                if (properties != .object) return fail(error.InvalidActionResponse, .accepted, reply.status);
                break :state properties.object.get("provisioningState");
            };
            if (state_value) |raw| {
                const state = models.state(raw) catch |err| return fail(err, .accepted, reply.status);
                if (state == .failed or state == .canceled) return fail(error.RemoteFailed, .accepted, reply.status);
            }
        }
        const async_raw = reply.async_operation orelse reply.operation_location;
        if (reply.async_operation != null and reply.operation_location != null and !std.mem.eql(u8, reply.async_operation.?, reply.operation_location.?))
            return fail(error.ConflictingOperationUrl, .accepted, reply.status);
        const result_url = if (reply.location) |location| self.pollUrl(a, plan, location, .location) catch |err| return fail(err, .accepted, reply.status) else null;
        const resource_poll = async_raw == null and result_url == null and reply.status == 202;
        var poll_url: ?[]const u8 = if (async_raw) |raw| self.pollUrl(a, plan, raw, .status) catch |err| return fail(err, .accepted, reply.status) else null;
        if (poll_url == null and reply.status == 202) {
            if (result_url) |location| poll_url = location else if (plan.target) |target| poll_url = std.fmt.allocPrint(a, "{s}{s}?api-version={s}", .{ s.arm_host, target.path(a, self.authority) catch |err| return fail(err, .accepted, reply.status), plan.version }) catch |err| return fail(err, .accepted, reply.status) else return fail(error.MissingOperationUrl, .accepted, reply.status);
        }
        var polls: u16 = 0;
        while (poll_url) |url| {
            if (polls >= self.channel.budget.max_polls) return fail(error.LimitExceeded, .accepted, reply.status);
            self.channel.budget.sleep(reply.retry_ms orelse 1000) catch |err| return fail(err, .accepted, reply.status);
            polls += 1;
            var poll = plan;
            poll.method = .GET;
            poll.body = null;
            poll.mutation = false;
            const next = switch (self.exchange(poll, url)) {
                .ok => |next| next,
                .failed => |failure| {
                    if (resource_poll and (plan.operation == .group_delete or plan.operation == .schedule_delete) and
                        isAbsence(failure, plan.target.?.kind)) return self.absent(.accepted);
                    return accepted(failure);
                },
            };
            reply.deinit();
            reply = next;
            if (reply.status == 204 and (plan.operation == .revoke or plan.operation == .start or plan.operation == .deallocate or
                plan.operation == .group_delete or plan.operation == .schedule_delete)) break;
            if (reply.status != 200 and reply.status != 202) return fail(error.UnexpectedStatus, .accepted, reply.status);
            if (reply.status == 202 and reply.body.len == 0) continue;
            const value = json.parse(a, reply.body) catch |err| return fail(err, .accepted, reply.status);
            if (value == .object) if (value.object.get("error")) |err| if (err != .null)
                return fail(error.RemoteFailed, .accepted, reply.status);
            if (reply.status == 200 and value == .object and
                ((plan.operation == .grant and value.object.contains("accessSAS")) or
                    (plan.operation == .regenerate_key and value.object.contains("keys"))))
            {
                handed_off = true;
                return self.decode(plan, reply, .accepted);
            }
            const status_value = if (value == .object and value.object.contains("status")) value.object.get("status").? else models.field(models.field(value, "properties") catch |err| return fail(err, .accepted, reply.status), "provisioningState") catch |err| return fail(err, .accepted, reply.status);
            const state = models.state(status_value) catch |err| return fail(err, .accepted, reply.status);
            if (state == .failed or state == .canceled) return fail(error.RemoteFailed, .accepted, reply.status);
            if (state == .succeeded and reply.status == 200) break;
        }
        if (plan.operation == .grant or plan.operation == .regenerate_key) {
            // These operations return secrets, not a resource representation.
            // Missing async output is failure, never a replay of grant/regenerate.
            if (poll_url != null) {
                const value = json.parse(a, reply.body) catch |err| return fail(err, .accepted, reply.status);
                const output = output: {
                    const properties = value.object.get("properties") orelse break :output null;
                    if (properties != .object) return fail(error.InvalidActionResponse, .accepted, reply.status);
                    break :output properties.object.get("output");
                };
                if (output) |result| {
                    reply.body = std.json.Stringify.valueAlloc(reply.arena.allocator(), result, .{}) catch |err| return fail(err, .accepted, reply.status);
                } else if (result_url != null and !std.mem.eql(u8, result_url.?, poll_url.?)) {
                    var result_plan = plan;
                    result_plan.method = .GET;
                    result_plan.body = null;
                    result_plan.mutation = false;
                    const result = switch (self.exchange(result_plan, result_url.?)) {
                        .ok => |result| result,
                        .failed => |failure| return accepted(failure),
                    };
                    reply.deinit();
                    reply = result;
                } else return fail(error.MissingAsyncResult, .accepted, reply.status);
            }
            handed_off = true;
            return self.decode(plan, reply, .accepted);
        }
        // A successful LRO or submission does not establish resource completion.
        while (polls < self.channel.budget.max_polls) : (polls += 1) {
            const target = plan.target orelse return fail(error.MissingTarget, .accepted, reply.status);
            var current = switch (self.read(.{ .get = target })) {
                .ok => |current| current,
                .failed => |failure| {
                    if ((plan.operation == .group_delete or plan.operation == .schedule_delete) and isAbsence(failure, target.kind))
                        return self.absent(.accepted);
                    return accepted(failure);
                },
            };
            var current_keep = false;
            defer if (!current_keep) current.deinit();
            if (plan.operation == .group_delete or plan.operation == .schedule_delete) {
                self.channel.budget.sleep(1000) catch |err| return fail(err, .accepted, current.reply.status);
                continue;
            }
            const ready = switch (current.model) {
                .group, .deployment => |status| status == .succeeded,
                .disk => |disk| disk.state == .succeeded,
                .storage => |storage| storage.state == .succeeded,
                .schedule => true,
                .vm => |vm| vm.state == .succeeded,
                else => false,
            };
            const observed_state: ?models.State = switch (current.model) {
                .group, .deployment => |state| state,
                .vm => |vm| vm.state,
                .disk => |disk| disk.state,
                .storage => |storage| storage.state,
                else => null,
            };
            if (observed_state == .failed or observed_state == .canceled) return fail(error.RemoteFailed, .accepted, current.reply.status);
            if (ready) {
                if (plan.operation == .revoke) {
                    models.requireOriginalDisk(current.model, plan.operation.revoke) catch |err| return fail(err, .accepted, current.reply.status);
                    switch (current.model.disk.access) {
                        .unattached, .attached, .ready_to_upload => {},
                        .active_sas, .active_upload => {
                            self.channel.budget.sleep(1000) catch |err| return fail(err, .accepted, current.reply.status);
                            continue;
                        },
                        else => return fail(error.InvalidDiskState, .accepted, current.reply.status),
                    }
                }
                if (plan.operation == .disk_create and (current.model != .disk or current.model.disk.bytes !=
                    @as(u64, plan.operation.disk_create.size_gib) * 1024 * 1024 * 1024)) return fail(error.OriginalIdentityMismatch, .accepted, current.reply.status);
                if (plan.operation == .disk_create and current.model.disk.upload_bytes != plan.operation.disk_create.upload_bytes)
                    return fail(error.OriginalIdentityMismatch, .accepted, current.reply.status);
                if (plan.operation == .deallocate or plan.operation == .start) {
                    const action = if (plan.operation == .deallocate) plan.operation.deallocate else plan.operation.start;
                    models.requireOriginalVm(current.model, action.original_uuid) catch |err| return fail(err, .accepted, current.reply.status);
                    var power = switch (self.read(.{ .instance_view = action.vm })) {
                        .ok => |power| power,
                        .failed => |failure| return accepted(failure),
                    };
                    defer power.deinit();
                    if (power.model != .power) return fail(error.MissingPowerState, .accepted, power.reply.status);
                    const wanted: @FieldType(models.Model, "power") = if (plan.operation == .start) .running else .deallocated;
                    if (power.model.power != wanted) {
                        self.channel.budget.sleep(1000) catch |err| return fail(err, .accepted, power.reply.status);
                        continue;
                    }
                }
                if (plan.operation == .firewall) {
                    if (current.model != .storage or !std.meta.eql(current.model.storage.ip, plan.operation.firewall.address))
                        return fail(error.FirewallReadbackMismatch, .accepted, current.reply.status);
                    sameSubnets(a, self.authority, current.model.storage.subnets, plan.operation.firewall.subnets) catch |err|
                        return fail(err, .accepted, current.reply.status);
                }
                if (plan.operation == .schedule_put) {
                    const wanted = plan.operation.schedule_put;
                    if (current.model != .schedule or !current.model.schedule.enabled or
                        !std.mem.eql(u8, &current.model.schedule.time, &wanted.time))
                        return fail(error.ScheduleReadbackMismatch, .accepted, current.reply.status);
                    wanted.vm.requireId(a, self.authority, current.model.schedule.vm.path(a, self.authority) catch |err|
                        return fail(err, .accepted, current.reply.status)) catch |err| return fail(err, .accepted, current.reply.status);
                }
                if (plan.operation == .deploy) {
                    const output_allocator = current.reply.arena.allocator();
                    const created = output_allocator.alloc(Created, plan.operation.deploy.resources.len) catch |err|
                        return fail(err, .accepted, current.reply.status);
                    for (plan.operation.deploy.resources, created) |definition, *record| {
                        if (self.verifyCreated(output_allocator, definition, record)) |failure| return .{ .failed = failure };
                    }
                    current.created = created;
                }
                current.effect = .accepted;
                current_keep = true;
                return .{ .ok = current };
            }
            self.channel.budget.sleep(1000) catch |err| return fail(err, .accepted, current.reply.status);
        }
        return fail(error.LimitExceeded, .accepted, reply.status);
    }

    fn pollUrl(self: *Client, a: std.mem.Allocator, plan: ops.Plan, raw: []const u8, endpoint: s.DiskOperationEndpoint) ![]const u8 {
        const relative = try s.relativeUrl(raw);
        const path = relative[0..std.mem.indexOfScalar(u8, relative, '?').?];
        if (plan.operation == .group_delete) {
            const result_prefix = try std.fmt.allocPrint(a, "/subscriptions/{s}/operationresults/", .{self.authority.subscription});
            if (std.ascii.startsWithIgnoreCase(path, result_prefix)) {
                try s.queryVersion(relative, plan.version, false);
                _ = try s.uuid(path[result_prefix.len..]);
                return std.fmt.allocPrint(a, "{s}{s}", .{ s.arm_host, relative });
            }
        }
        if (plan.target) |target| {
            const expected = try target.path(a, self.authority);
            if (std.ascii.eqlIgnoreCase(path, expected)) {
                try s.queryVersion(relative, plan.version, false);
                return std.fmt.allocPrint(a, "{s}{s}", .{ s.arm_host, relative });
            }
            const prefix = try std.fmt.allocPrint(a, "{s}/operationStatuses/", .{expected});
            if (std.ascii.startsWithIgnoreCase(path, prefix)) {
                try s.queryVersion(relative, plan.version, false);
                _ = try s.uuid(path[prefix.len..]);
                return std.fmt.allocPrint(a, "{s}{s}", .{ s.arm_host, relative });
            }
        }
        const prefix = try std.fmt.allocPrint(a, "/subscriptions/{s}/providers/{s}/locations/{s}/", .{ self.authority.subscription, plan.provider, self.authority.location });
        if (!std.ascii.startsWithIgnoreCase(path, prefix)) return error.UnsafeOperationScope;
        const rest = path[prefix.len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.UnsafeOperationScope;
        const kind = rest[0..slash];
        if (std.ascii.eqlIgnoreCase(kind, "DiskOperations")) {
            if (plan.target == null or plan.target.?.kind != .disk) return error.UnsafeOperationScope;
            try s.diskOperationQuery(relative, plan.version, endpoint);
        } else {
            if (!std.ascii.eqlIgnoreCase(kind, "operations") and !std.ascii.eqlIgnoreCase(kind, "operationStatuses") and !std.ascii.eqlIgnoreCase(kind, "operationResults"))
                return error.UnsafeOperationScope;
            try s.queryVersion(relative, plan.version, false);
        }
        _ = try s.uuid(rest[slash + 1 ..]);
        return std.fmt.allocPrint(a, "{s}{s}", .{ s.arm_host, relative });
    }

    fn absent(self: *Client, effect: wire.Effect) wire.Outcome(Result) {
        const arena = secret.Arena.create(self.allocator) catch |err| return fail(err, effect, 404);
        return .{ .ok = .{ .reply = .{
            .arena = arena,
            .status = 404,
            .body = "",
            .async_operation = null,
            .operation_location = null,
            .location = null,
            .retry_ms = null,
        }, .model = .empty, .effect = effect } };
    }

    fn requireAbsent(self: *Client, ref: s.Ref) ?wire.Failure {
        var response = self.read(.{ .get = ref });
        return switch (response) {
            .ok => |*value| conflict: {
                const status = value.reply.status;
                value.deinit();
                break :conflict .{ .effect = .not_started, .diagnostic = .{ .stage = .arm, .category = .conflict, .http_status = status } };
            },
            .failed => |failure| if (isAbsence(failure, ref.kind)) null else .{ .effect = .not_started, .diagnostic = failure.diagnostic },
        };
    }

    fn checkAttachment(self: *Client, identity: ops.DiskIdentity, effect: wire.Effect) ?wire.Failure {
        var current = switch (self.read(.{ .get = identity.disk })) {
            .ok => |value| value,
            .failed => |failure| {
                var result = failure;
                result.effect = effect;
                return result;
            },
        };
        defer current.deinit();
        models.requireOriginalDisk(current.model, identity) catch |err| return wire.Failure.local(.arm, err, effect, current.reply.status);
        const disk = current.model.disk;
        if (disk.state != .succeeded or (if (effect == .not_started)
            disk.access != .unattached
        else
            disk.access != .attached and disk.access != .reserved)) return wire.Failure.local(.arm, error.InvalidDiskState, effect, current.reply.status);
        return null;
    }

    fn verifyCreated(self: *Client, a: std.mem.Allocator, definition: ops.Resource, output: *Created) ?wire.Failure {
        const ref: s.Ref = switch (definition) {
            .disk => |disk| .{ .kind = .disk, .name = disk.name },
            .vm => |vm| .{ .kind = .vm, .name = vm.name },
            .storage => |storage| .{ .kind = .storage, .name = storage.name },
        };
        var polls: u16 = 0;
        while (polls < self.channel.budget.max_polls) : (polls += 1) {
            var current = switch (self.read(.{ .get = ref })) {
                .ok => |value| value,
                .failed => |failure| return accepted(failure).failed,
            };
            defer current.deinit();
            const status: models.State = switch (current.model) {
                .disk => |disk| disk.state,
                .vm => |vm| vm.state,
                .storage => |storage| storage.state,
                else => return wire.Failure.local(.arm, error.InvalidResource, .accepted, current.reply.status),
            };
            if (status == .failed or status == .canceled) return wire.Failure.local(.arm, error.RemoteFailed, .accepted, current.reply.status);
            if (status != .succeeded) {
                self.channel.budget.sleep(1000) catch |err| return wire.Failure.local(.arm, err, .accepted, current.reply.status);
                continue;
            }
            compareDefinition(a, self.authority, definition, current.model) catch |err|
                return wire.Failure.local(.arm, err, .accepted, current.reply.status);
            if (definition == .vm) {
                if (self.checkAttachment(definition.vm.os_disk, .accepted)) |failure| return failure;
                if (definition.vm.data_disk) |disk| if (self.checkAttachment(disk, .accepted)) |failure| return failure;
            }
            output.* = .{
                .kind = ref.kind,
                .name = a.dupe(u8, ref.name) catch |err| return wire.Failure.local(.arm, err, .accepted, current.reply.status),
                .uuid = switch (current.model) {
                    .vm => |vm| vm.uuid,
                    .disk => |disk| disk.uuid,
                    else => null,
                },
                .disk_bytes = if (current.model == .disk) current.model.disk.bytes else null,
            };
            return null;
        }
        return wire.Failure.local(.arm, error.LimitExceeded, .accepted, null);
    }
};

fn compareDefinition(a: std.mem.Allocator, authority: s.Authority, definition: ops.Resource, actual: models.Model) !void {
    switch (definition) {
        .disk => |disk| {
            if (actual != .disk or actual.disk.bytes != @as(u64, disk.size_gib) * 1024 * 1024 * 1024 or actual.disk.upload_bytes != disk.upload_bytes)
                return error.OriginalIdentityMismatch;
        },
        .storage => {
            if (actual != .storage or !actual.storage.public_network or actual.storage.ip != null or actual.storage.subnets.len != 0)
                return error.FirewallReadbackMismatch;
        },
        .vm => |vm| {
            if (actual != .vm or !std.mem.eql(u8, actual.vm.size, vm.size) or
                (actual.vm.data_disk == null) != (vm.data_disk == null)) return error.OriginalIdentityMismatch;
            try vm.os_disk.disk.requireId(a, authority, try actual.vm.os_disk.path(a, authority));
            try vm.nic.requireId(a, authority, try actual.vm.nic.path(a, authority));
            if (vm.data_disk) |disk| try disk.disk.requireId(a, authority, try actual.vm.data_disk.?.path(a, authority));
        },
    }
}

fn fail(err: anyerror, effect: wire.Effect, status: ?u16) wire.Outcome(Result) {
    return .{ .failed = wire.Failure.local(.arm, err, effect, status) };
}
fn accepted(failure: wire.Failure) wire.Outcome(Result) {
    var result = failure;
    result.effect = .accepted;
    return .{ .failed = result };
}
fn beforeMutation(failure: wire.Failure, operation: ops.Operation) wire.Outcome(Result) {
    var result = failure;
    if (operation.isMutation()) result.effect = .not_started;
    return .{ .failed = result };
}

fn sameSubnets(a: std.mem.Allocator, authority: s.Authority, actual: []const s.Ref, expected: []const s.Ref) !void {
    if (actual.len != expected.len) return error.FirewallScopeMismatch;
    for (actual) |subnet| {
        const id = try subnet.path(a, authority);
        var found = false;
        for (expected) |wanted| if (std.ascii.eqlIgnoreCase(id, try wanted.path(a, authority))) {
            found = true;
        };
        if (!found) return error.FirewallScopeMismatch;
    }
}

fn isAbsence(failure: wire.Failure, kind: s.Kind) bool {
    if (failure.diagnostic.http_status != 404 or failure.diagnostic.category != .not_found) return false;
    return failure.diagnostic.service_code == .ResourceGroupNotFound or
        (kind != .group and failure.diagnostic.service_code == .ResourceNotFound);
}
