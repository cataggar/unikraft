const std = @import("std");
const sdk = @import("azure_sdk_core");
const contracts = @import("hyperv_core").contracts;
const scope = @import("scope.zig");
const secret = @import("secret.zig");
const wire = @import("transport.zig");

/// No environment/default/CLI provider and no implicit provider fallback.
/// A callback must produce an already signed assertion using explicitly selected
/// native authority; this module neither invents a tenant/app nor signs fake JWTs.
pub const Provider = union(enum) {
    client_assertion: sdk.identity.client_assertion.AssertionCallback,
    managed_identity: enum { system_assigned, user_assigned },
};

pub const Config = struct {
    authority: scope.Authority,
    provider: Provider,
    minimum_validity_seconds: u32,

    pub fn validate(self: Config) !void {
        try self.authority.validate();
        if (self.minimum_validity_seconds == 0 or self.minimum_validity_seconds > 24 * 60 * 60)
            return error.InvalidCredentialLifetime;
    }
};

pub const Token = struct {
    value: secret.Bytes,
    expires_on: i64,
    tenant: scope.Uuid,
    subscription: scope.Uuid,
    principal: scope.Uuid,
    client: scope.Uuid,
    audience: enum { public_arm } = .public_arm,

    pub fn require(self: *const Token, authority: scope.Authority, now: i64, remaining: u32) !void {
        if (now <= 0 or self.expires_on <= now or self.expires_on - now < remaining) return error.TokenExpired;
        inline for (.{ "tenant", "subscription", "principal", "client" }) |field| {
            if (!std.mem.eql(u8, &@field(self, field), &@field(authority, field))) return error.AuthorityMismatch;
        }
        try validateToken(self.value.bytes);
    }

    pub fn deinit(self: *Token) void {
        self.value.deinit();
        self.* = undefined;
    }
};

pub fn acquire(allocator: std.mem.Allocator, channel: wire.Channel, config: Config) wire.Outcome(Token) {
    config.validate() catch |err| return .{ .failed = wire.Failure.local(.credential, err, .not_started, null) };
    const arena = secret.Arena.create(allocator) catch |err| return .{ .failed = wire.Failure.local(.credential, err, .not_started, null) };
    defer arena.destroy();
    var gateway: Gateway = .{ .channel = channel, .config = config, .allocator = arena.allocator() };
    const runtime = sdk.http.HttpRuntime.init(
        .{ .context = &gateway, .vtable = &.{ .send = Gateway.send } },
        channel.runtime.crypto,
    );
    const got = switch (config.provider) {
        .client_assertion => |callback| assertion: {
            var credential = sdk.identity.ClientAssertionCredential.init(
                arena.allocator(),
                &config.authority.tenant,
                &config.authority.client,
                callback,
            );
            credential.authority_host = scope.login_host;
            break :assertion credential.asCredential().getToken(.{ .scopes = &.{scope.arm_scope} }, .none, runtime);
        },
        .managed_identity => |selection| managed: {
            var credential = sdk.identity.ManagedIdentityCredential.init(arena.allocator());
            if (selection == .user_assigned) credential.withClientId(&config.authority.client);
            break :managed credential.asCredential().getToken(.{ .scopes = &.{scope.arm_scope} }, .none, runtime);
        },
    };
    var token = got catch |err| return .{ .failed = gateway.failure orelse wire.Failure.local(.credential, err, .not_started, null) };
    defer token.deinit();
    const expiry = gateway.expiry orelse return .{ .failed = wire.Failure.local(.credential, error.InvalidTokenResponse, .not_applicable, 200) };
    const owned = secret.Bytes.copy(allocator, token.token) catch |err| return .{ .failed = wire.Failure.local(.credential, err, .not_applicable, 200) };
    var result: Token = .{
        .value = owned,
        .expires_on = expiry,
        .tenant = config.authority.tenant,
        .subscription = config.authority.subscription,
        .principal = config.authority.principal,
        .client = config.authority.client,
    };
    result.require(config.authority, channel.budget.clock.unixSecondsFn(channel.budget.clock.context), config.minimum_validity_seconds) catch |err| {
        result.deinit();
        return .{ .failed = wire.Failure.local(.credential, err, .not_applicable, 200) };
    };
    return .{ .ok = result };
}

const Gateway = struct {
    channel: wire.Channel,
    config: Config,
    allocator: std.mem.Allocator,
    expiry: ?i64 = null,
    failure: ?wire.Failure = null,
    used: bool = false,

    fn send(context: *anyopaque, request: *sdk.http.Request) !sdk.http.Response {
        const self: *Gateway = @ptrCast(@alignCast(context));
        self.validateRequest(request) catch |err| {
            self.failure = wire.Failure.local(.credential, err, .not_started, null);
            return error.AuthenticationFailed;
        };
        var reply = switch (self.channel.send(request, false, .credential)) {
            .failed => |failure| {
                self.failure = failure;
                // Never return an error response to providers that log its body.
                return error.AuthenticationFailed;
            },
            .ok => |reply| reply,
        };
        defer reply.deinit();
        if (reply.status != 200) {
            self.failure = wire.Failure.local(.credential, error.InvalidTokenResponse, .not_applicable, reply.status);
            return error.AuthenticationFailed;
        }
        self.expiry = self.validateResponse(reply.body) catch |err| {
            self.failure = wire.Failure.local(.credential, err, .not_applicable, reply.status);
            return error.AuthenticationFailed;
        };
        return .{
            .status_code = 200,
            .headers = .init(self.allocator),
            .body = try self.allocator.dupe(u8, reply.body),
            .allocator = self.allocator,
        };
    }

    fn validateRequest(self: *Gateway, request: *sdk.http.Request) !void {
        if (self.used or request.getHeader("Authorization") != null) return error.InvalidCredentialRequest;
        self.used = true;
        const expected = switch (self.config.provider) {
            .client_assertion => try std.fmt.allocPrint(self.allocator, "{s}/{s}/oauth2/v2.0/token", .{ scope.login_host, self.config.authority.tenant }),
            .managed_identity => |selection| if (selection == .user_assigned)
                try std.fmt.allocPrint(self.allocator, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={s}&client_id={s}", .{ scope.arm_resource, self.config.authority.client })
            else
                try std.fmt.allocPrint(self.allocator, "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={s}", .{scope.arm_resource}),
        };
        if (!std.mem.eql(u8, expected, request.url)) return error.UnsafeCredentialAuthority;
        switch (self.config.provider) {
            .client_assertion => {
                if (request.method != .POST or request.body == null or request.body.?.len > 64 * 1024)
                    return error.InvalidCredentialRequest;
            },
            .managed_identity => {
                if (request.method != .GET or request.body != null or
                    !std.mem.eql(u8, request.getHeader("Metadata") orelse "", "true")) return error.InvalidCredentialRequest;
            },
        }
    }

    fn validateResponse(self: *Gateway, body: []const u8) !i64 {
        if (body.len > 64 * 1024) return error.InvalidTokenResponse;
        const document = try contracts.Document.parse(self.allocator, body, .{ .bytes = 64 * 1024, .string_bytes = 16 * 1024, .depth = 4, .items = 16 });
        defer document.deinit();
        const value = document.value();
        if (value != .object) return error.InvalidTokenResponse;
        const object = value.object;
        for (object.keys()) |key| {
            const allowed = switch (self.config.provider) {
                .client_assertion => &[_][]const u8{ "access_token", "token_type", "expires_in", "ext_expires_in", "scope" },
                .managed_identity => &[_][]const u8{ "access_token", "token_type", "expires_on", "expires_in", "not_before", "resource", "client_id" },
            };
            var known = false;
            for (allowed) |field| if (std.mem.eql(u8, field, key)) {
                known = true;
            };
            if (!known) return error.InvalidTokenResponse;
        }
        try validateToken(try contracts.string(object.get("access_token") orelse return error.InvalidTokenResponse));
        if (!std.ascii.eqlIgnoreCase(try contracts.string(object.get("token_type") orelse return error.InvalidTokenResponse), "Bearer"))
            return error.InvalidTokenResponse;
        const now = self.channel.budget.clock.unixSecondsFn(self.channel.budget.clock.context);
        if (now <= 0) return error.InvalidClock;
        const expiry: i64 = switch (self.config.provider) {
            .client_assertion => token: {
                const seconds = try contracts.integer(u32, object.get("expires_in") orelse return error.InvalidTokenResponse);
                if (seconds == 0 or seconds > 86400) return error.InvalidTokenResponse;
                if (object.get("ext_expires_in")) |extra| {
                    if (try contracts.integer(u32, extra) > 86400) return error.InvalidTokenResponse;
                }
                if (object.get("scope")) |selected| if (!std.mem.eql(u8, try contracts.string(selected), scope.arm_scope))
                    return error.InvalidTokenResponse;
                break :token try std.math.add(i64, now, seconds);
            },
            .managed_identity => token: {
                const resource = try contracts.string(object.get("resource") orelse return error.InvalidTokenResponse);
                if ((!std.mem.eql(u8, resource, scope.arm_resource) and !std.mem.eql(u8, resource, scope.arm_resource ++ "/")) or
                    !std.mem.eql(u8, try contracts.string(object.get("client_id") orelse return error.InvalidTokenResponse), &self.config.authority.client))
                    return error.InvalidTokenResponse;
                const expiry = object.get("expires_on") orelse return error.InvalidTokenResponse;
                const seconds = if (expiry == .string) try wire.unsigned(expiry.string) else try contracts.integer(u64, expiry);
                if (seconds > std.math.maxInt(i64)) return error.InvalidTokenResponse;
                if (object.get("expires_in")) |remaining| {
                    const n = if (remaining == .string) try wire.unsigned(remaining.string) else try contracts.integer(u64, remaining);
                    if (n == 0 or n > 86400) return error.InvalidTokenResponse;
                }
                if (object.get("not_before")) |start| {
                    const n = if (start == .string) try wire.unsigned(start.string) else try contracts.integer(u64, start);
                    if (n > now) return error.InvalidTokenResponse;
                }
                break :token @intCast(seconds);
            },
        };
        if (expiry <= now or expiry - now > 86400 or expiry - now < self.config.minimum_validity_seconds)
            return error.TokenExpired;
        return expiry;
    }
};

fn validateToken(bytes: []const u8) !void {
    if (bytes.len == 0 or bytes.len > 16 * 1024) return error.InvalidToken;
    for (bytes) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "-._~+/=", c) == null)
        return error.InvalidToken;
}
