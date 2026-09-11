const std = @import("std");
const core = @import("hyperv_core");
const az = @import("hyperv_azure");
const transfer = @import("hyperv_transfer");
const c = @import("contract.zig");
const p = c.p;
const j = @import("journal.zig");
const e = @import("engine.zig");
const ev = @import("evidence.zig");
pub const arm = @import("arm.zig");
pub const storage = @import("storage.zig");

/// Initialized only after a trusted preparation/approval resolver. Credentials
/// are supplied explicitly in memory; no token, key or provider discovery exists.
pub const Native = struct {
    store: *j.Store,
    arm_client: *az.client.Client,
    storage_adapter: storage.Adapter,
    cleanup_token: *const az.auth.Token,
    last: az.transport.Failure = .{ .effect = .not_started, .diagnostic = .{ .stage = .admission, .category = .internal } },

    pub fn backend(self: *Native) e.Backend {
        return .{ .context = self, .controlFn = control, .stageFn = stage, .publishFn = publish, .fetchFn = fetch, .releaseFn = release, .failureFn = failure };
    }
    fn checked(self: *Native, action: c.Action) !arm.Adapter {
        const approved = &self.store.input.approved;
        const now = self.arm_client.channel.budget.clock.unixSecondsFn(self.arm_client.channel.budget.clock.context);
        if (now <= 0) return error.InvalidClock;
        const expiry = if (action.cleanup()) approved.cleanup_expires_at else approved.expires_at;
        if (now >= expiry) return error.AuthorityExpired;
        if (action.cleanup()) self.arm_client.token = self.cleanup_token;
        // Cleanup-capable authority must outlive the operation, not just its first HTTP read.
        const remaining: u32 = @intCast(approved.cleanup_expires_at - @as(u64, @intCast(now)));
        try self.arm_client.token.require(approved.authority, now, remaining);
        self.last = .{ .effect = .not_started, .diagnostic = .{ .stage = .admission, .category = .internal } };
        return .{ .client = self.arm_client, .input = self.store.input };
    }
    fn control(context: *anyopaque, action: c.Action, state: *const j.State) !e.Proof {
        const self: *Native = @ptrCast(@alignCast(context));
        if (action == .dispose_credentials) return self.dispose();
        var api = try self.checked(action);
        return self.controlChecked(&api, action, state) catch |err| {
            self.last = api.failure;
            // These adapters contain more than one request/effect. A later GET
            // rejection cannot erase an earlier accepted mutation in the action.
            switch (action) {
                .deploy_host, .grant_access, .deallocate, .revoke_roles, .revoke_sas, .clear_firewall, .delete_group => self.last.effect = .unknown,
                else => {},
            }
            return err;
        };
    }
    fn controlChecked(self: *Native, api: *arm.Adapter, action: c.Action, state: *const j.State) !e.Proof {
        const store = self.store;
        const input = store.input;
        const r = input.approved.resources;
        switch (action) {
            .metadata => {
                var metadata = switch (az.admission.inspect(self.arm_client, input.approved.image)) {
                    .ok => |value| value,
                    .failed => |failure_value| {
                        api.failure = failure_value;
                        return error.MetadataNotAdmitted;
                    },
                };
                defer metadata.deinit();
                return .{ .digest = p.hash(metadata.image.reply.body), .effect = .not_applicable };
            },
            .create_group => {
                var result = try api.execute(.group_create);
                defer result.deinit();
                return .{ .digest = p.hash(result.reply.body), .effect = result.effect };
            },
            .deploy_host => return api.deploy(),
            .inspect_host => return api.inspectHost(state),
            .grant_access => {
                _ = try api.inspectHost(state);
                var keys = try api.execute(.{ .list_keys = r.storage });
                defer keys.deinit();
                if (keys.model != .keys) return error.SigningKeyUnavailable;
                const snapshot = keys.model.keys.snapshot();
                const snapshot_bytes = try c.canonical(store.allocator, snapshot);
                defer store.allocator.free(snapshot_bytes);
                try store.immutable("storage-key-snapshot.json", snapshot_bytes, true);
                store.state.key_snapshot = snapshot;
                try store.save();
                var sas = try storage.signSas(store.allocator, r.storage.name, keys.model.keys.key1, input.approved.expires_at);
                defer sas.deinit();
                try store.immutable("storage-capability", sas.bytes, true);
                try store.save();
                var firewall = try api.execute(.{ .firewall = .{ .account = r.storage, .before_address = null, .address = input.approved.uploader_ipv4, .subnets = &.{r.subnet} } });
                defer firewall.deinit();
                var admission = try input.validate(store.allocator, input.approved.not_before);
                defer admission.deinit();
                const account = try std.fmt.allocPrint(store.allocator, "https://{s}.blob.core.windows.net", .{r.storage.name});
                defer store.allocator.free(account);
                var client: transfer.Client = .{ .allocator = store.allocator, .io = store.io, .runtime = self.storage_adapter.runtime, .budget = self.storage_adapter.budget };
                const created = client.createContainer(account, admission.container, sas.bytes);
                if (created.completion != .complete) {
                    self.last = .{ .effect = .unknown, .diagnostic = created.aggregateDiagnostic() };
                    api.failure = self.last;
                    return error.ContainerCreationFailed;
                }
                return .{ .digest = try api.roles(state, false), .effect = .accepted };
            },
            .deallocate => {
                if (try api.groupAbsent()) return self.absentProof(action);
                var vm = api.execute(.{ .get = r.vm }) catch |err| {
                    if (arm.absence(api.failure, false) and state.vm_id == null)
                        return .{ .digest = p.hash("independent-unobserved-vm-absence"), .effect = .not_applicable };
                    return err;
                };
                defer vm.deinit();
                if (state.vm_id == null) try self.reconcileVm(vm);
                const id = store.state.vm_id orelse return error.UnreconciledCompute;
                try az.models.requireOriginalVm(vm.model, id);
                var result = try api.execute(.{ .deallocate = .{ .vm = r.vm, .original_uuid = id } });
                defer result.deinit();
                return .{ .digest = p.hash(result.reply.body), .effect = result.effect };
            },
            .revoke_roles => {
                if (try api.groupAbsent()) return self.absentProof(action);
                if (state.actions[@intFromEnum(c.Action.grant_access)].status == .fresh)
                    return .{ .digest = p.hash("role-grant-not-started"), .effect = .not_started };
                return .{ .digest = try api.roles(state, true), .effect = .accepted };
            },
            .revoke_sas => {
                if (try api.groupAbsent()) return self.absentProof(action);
                if (state.actions[@intFromEnum(c.Action.grant_access)].status == .fresh)
                    return .{ .digest = p.hash("capability-not-issued"), .effect = .not_started };
                const snapshot = try self.loadSnapshot();
                var result = try api.execute(.{ .regenerate_key = .{ .account = r.storage, .key = .key1, .previous = snapshot } });
                defer result.deinit();
                if (result.model != .keys or std.mem.eql(u8, &result.model.keys.digest(.key1), &snapshot.key1) or
                    !std.mem.eql(u8, &result.model.keys.digest(.key2), &snapshot.key2)) return error.KeyRevocationUnproved;
                return .{ .digest = result.model.keys.digest(.key1), .effect = result.effect };
            },
            .prove_sas_revoked => {
                // Group absence is recorded distinctly. It is not a successful
                // key rotation or a signed data-plane rejection.
                if (try api.groupAbsent()) return self.absentProof(action);
                if (state.actions[@intFromEnum(c.Action.grant_access)].status == .fresh)
                    return .{ .digest = p.hash("capability-not-issued"), .effect = .not_applicable };
                try self.proveRevoked();
                return .{ .digest = p.hash("independent-old-capability-authentication-rejected"), .effect = .not_applicable };
            },
            .clear_firewall => {
                if (try api.groupAbsent()) return self.absentProof(action);
                var current = api.execute(.{ .get = r.storage }) catch |err| {
                    if (arm.absence(api.failure, false))
                        return .{ .digest = p.hash("independent-storage-absence"), .effect = .not_applicable };
                    return err;
                };
                defer current.deinit();
                if (current.model != .storage) return error.InvalidStorage;
                if (current.model.storage.ip) |ip| {
                    if (!std.meta.eql(ip, input.approved.uploader_ipv4)) return error.FirewallScopeMismatch;
                    var cleared = try api.execute(.{ .firewall = .{ .account = r.storage, .before_address = ip, .address = null, .subnets = &.{r.subnet} } });
                    defer cleared.deinit();
                    return .{ .digest = p.hash(cleared.reply.body), .effect = cleared.effect };
                }
                return .{ .digest = p.hash(current.reply.body), .effect = .not_started };
            },
            .delete_group => {
                if (try api.groupAbsent()) return self.absentProof(action);
                _ = try api.inventory(true);
                // Inventory is authoritative for partially-created resources.
                // A missing VM is not itself permission to skip inventory.
                if (state.vm_id) |id| {
                    var current = try api.execute(.{ .get = r.vm });
                    defer current.deinit();
                    try az.models.requireOriginalVm(current.model, id);
                }
                if (state.disk_id) |id| {
                    var current = try api.execute(.{ .get = r.disk });
                    defer current.deinit();
                    if (current.model != .disk or !std.mem.eql(u8, &current.model.disk.uuid, &id)) return error.OriginalIdentityMismatch;
                }
                var result = try api.execute(.group_delete);
                defer result.deinit();
                return .{ .digest = p.hash(result.reply.body), .effect = result.effect };
            },
            .prove_group_absent => {
                if (!try api.groupAbsent()) return error.GroupStillPresent;
                return self.absentProof(action);
            },
            .dispose_credentials => return self.dispose(),
            else => return error.InvalidOperation,
        }
    }
    fn reconcileVm(self: *Native, result: az.client.Result) !void {
        const store = self.store;
        if (result.model != .vm or result.model.vm.data_disk != null) return error.UnreconciledCompute;
        var document = try core.contracts.Document.parse(store.allocator, result.reply.body, .{ .bytes = 1024 * 1024, .tokens = 65536 });
        defer document.deinit();
        try arm.owner(store.input, document.value());
        const properties = try az.models.field(document.value(), "properties");
        const image = try az.models.field(try az.models.field(properties, "storageProfile"), "imageReference");
        if (!std.ascii.eqlIgnoreCase(try az.models.string(image, "id"), store.input.approved.image_id) or
            !std.mem.eql(u8, result.model.vm.size, "Standard_D2s_v5")) return error.UnreconciledCompute;
        const binding = try c.canonical(store.allocator, .{ .attempt = store.state.attempt, .vm_id = result.model.vm.uuid });
        defer store.allocator.free(binding);
        const prior = store.lock.directory.read(store.io, store.allocator, "reconciled-vm.json", 4096, null) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (prior) |bytes| store.allocator.free(bytes);
        if (prior) |bytes| {
            if (!std.mem.eql(u8, bytes, binding)) return error.OriginalIdentityMismatch;
        } else try store.immutable("reconciled-vm.json", binding, true);
        store.state.vm_id = result.model.vm.uuid;
        try store.save();
    }
    fn dispose(self: *Native) !e.Proof {
        const store = self.store;
        var failure_value: ?anyerror = null;
        for ([_][]const u8{ "storage-capability", "execution-token", "cleanup-token", "signer-copy" }) |name|
            removeCopy(store.io, store.lock.directory, name) catch |err| {
                if (failure_value == null) failure_value = err;
            };
        for ([_][]const u8{ "transfer-public", "transfer-private" }) |name| {
            const directory = core.private_files.Directory{ .dir = store.lock.directory.dir.openDir(store.io, name, .{ .follow_symlinks = false, .iterate = true }) catch |err| {
                if (err != error.FileNotFound and failure_value == null) failure_value = err;
                continue;
            } };
            defer directory.close(store.io);
            var lock = directory.lock(store.io) catch |err| {
                if (failure_value == null) failure_value = err;
                continue;
            };
            defer lock.close(store.io);
            removeCopy(store.io, directory, "capability") catch |err| {
                if (failure_value == null) failure_value = err;
            };
        }
        if (failure_value) |err| return err;
        return .{ .digest = p.hash("owned-capability-copies-disposed"), .effect = .accepted };
    }
    fn loadSnapshot(self: *Native) !az.operations.KeySnapshot {
        const store = self.store;
        const bytes = try store.lock.directory.read(store.io, store.allocator, "storage-key-snapshot.json", 4096, null);
        defer store.allocator.free(bytes);
        const parsed = try c.parse(az.operations.KeySnapshot, store.allocator, bytes);
        defer parsed.deinit();
        if (store.state.key_snapshot) |expected| if (!std.meta.eql(expected, parsed.value)) return error.SigningKeyMismatch;
        return parsed.value;
    }
    fn proveRevoked(self: *Native) !void {
        const store = self.store;
        const a = store.allocator;
        var sas = try store.lock.directory.readSensitive(store.io, a, "storage-capability", transfer.request.maximum_sas, null);
        defer sas.deinit();
        var admission = try store.input.validate(a, store.input.approved.not_before);
        defer admission.deinit();
        const account = try std.fmt.allocPrint(a, "https://{s}.blob.core.windows.net", .{admission.account});
        defer a.free(account);
        const blob = try std.fmt.allocPrint(a, "runs/{s}/commands/public.json", .{store.state.run_id});
        defer a.free(blob);
        const output = try std.fs.path.join(a, &.{ self.storage_adapter.root, "revocation-probe" });
        defer a.free(output);
        var client: transfer.Client = .{ .allocator = a, .io = store.io, .runtime = self.storage_adapter.runtime, .budget = self.storage_adapter.budget };
        // Even an unexpectedly successful probe creates a bounded local control
        // copy. Its reservation is retained on every outcome.
        try store.charge(p.max_command, true);
        try store.save();
        const result = client.downloadBlob(.{ .account_url = account, .container = admission.container, .name = blob, .sas = sas.bytes() }, .{ .path = output, .maximum = p.max_command });
        const failure_value = result.aggregateDiagnostic();
        if (result.completion == .complete or failure_value.http_status != 403 or failure_value.service_code != .AuthenticationFailed)
            return error.DataPlaneRevocationUnproved;
    }
    fn absentProof(self: *Native, action: c.Action) e.Proof {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&self.store.state.authority_sha256);
        hash.update(@tagName(action));
        hash.update("independent-owned-group-absence");
        return .{ .digest = hash.finalResult(), .effect = .not_applicable };
    }
    fn stage(context: *anyopaque, phase: p.Phase, _: *const j.State) !e.Proof {
        const self: *Native = @ptrCast(@alignCast(context));
        _ = try self.checked(if (phase == .public) .stage_public else .stage_private);
        const hash = self.storage_adapter.stage(phase) catch |err| {
            self.last = self.storage_adapter.last;
            return err;
        };

        return .{ .digest = hash, .effect = .accepted };
    }
    fn publish(context: *anyopaque, phase: p.Phase, bytes: []const u8, _: *const j.State) !e.Proof {
        const self: *Native = @ptrCast(@alignCast(context));
        _ = try self.checked(if (phase == .public) .publish_public else .publish_private);
        const hash = self.storage_adapter.publish(phase, bytes) catch |err| {
            self.last = self.storage_adapter.last;
            return err;
        };
        return .{ .digest = hash, .effect = .accepted };
    }
    fn fetch(context: *anyopaque, phase: p.Phase, nonce: c.Uuid, _: *const j.State) !ev.Bundle {
        const self: *Native = @ptrCast(@alignCast(context));
        _ = try self.checked(if (phase == .public) .read_public else .read_private);
        return self.storage_adapter.fetch(phase, nonce) catch |err| {
            self.last = self.storage_adapter.last;
            return err;
        };
    }
    fn release(context: *anyopaque, bundle: ev.Bundle) void {
        const self: *Native = @ptrCast(@alignCast(context));
        self.storage_adapter.release(bundle);
    }
    fn failure(context: *anyopaque) az.transport.Failure {
        const self: *Native = @ptrCast(@alignCast(context));
        return self.last;
    }
};

fn removeCopy(io: std.Io, directory: core.private_files.Directory, name: []const u8) !void {
    const file = directory.openFile(io, name) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    file.close(io);
    try directory.dir.deleteFile(io, name);
    try @import("hyperv_host").files.syncDirectory(io, directory.dir);
}

pub fn acquireApproved(allocator: std.mem.Allocator, input: *const c.Input, channel: az.transport.Channel, config: az.auth.Config) az.transport.Outcome(az.auth.Token) {
    const now = channel.budget.clock.unixSecondsFn(channel.budget.clock.context);
    const expected = input.approved.authority;
    const actual = config.authority;
    const same_authority = std.mem.eql(u8, &actual.tenant, &expected.tenant) and
        std.mem.eql(u8, &actual.subscription, &expected.subscription) and std.mem.eql(u8, &actual.principal, &expected.principal) and
        std.mem.eql(u8, &actual.client, &expected.client) and std.mem.eql(u8, &actual.owner_run, &expected.owner_run) and
        std.mem.eql(u8, actual.group, expected.group) and std.mem.eql(u8, actual.location, expected.location);
    if (now <= 0 or now >= input.approved.cleanup_expires_at or !same_authority)
        return .{ .failed = .{ .effect = .not_started, .diagnostic = .{ .stage = .credential, .category = .authorization } } };
    const matches = switch (input.approved.credential_provider) {
        .client_assertion => config.provider == .client_assertion,
        .system_assigned => config.provider == .managed_identity and config.provider.managed_identity == .system_assigned,
        .user_assigned => config.provider == .managed_identity and config.provider.managed_identity == .user_assigned,
    };
    if (!matches or config.minimum_validity_seconds < input.approved.cleanup_expires_at - @as(u64, @intCast(now)))
        return .{ .failed = .{ .effect = .not_started, .diagnostic = .{ .stage = .credential, .category = .authorization } } };
    return az.auth.acquire(allocator, channel, config);
}
