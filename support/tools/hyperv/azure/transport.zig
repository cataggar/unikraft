const std = @import("std");
const sdk = @import("azure_sdk_core");
const foundation = @import("hyperv_core");
const secret = @import("secret.zig");
const d = foundation.diagnostics;

pub const Effect = enum { not_started, accepted, rejected, unknown, not_applicable };
pub const OAuthCode = enum {
    unavailable,
    unknown,
    invalid_client,
    invalid_grant,
    invalid_request,
    invalid_scope,
    unauthorized_client,
    unsupported_grant_type,
    temporarily_unavailable,
    server_error,
    interaction_required,
    consent_required,
};
pub const Failure = struct {
    diagnostic: d.Diagnostic,
    effect: Effect,
    oauth_code: OAuthCode = .unavailable,

    pub fn write(self: Failure, writer: *std.Io.Writer) !void {
        try writer.writeAll("{\"diagnostic\":");
        try self.diagnostic.write(writer);
        try writer.print(",\"effect\":\"{s}\",\"oauth_code\":\"{s}\"}}\n", .{ @tagName(self.effect), @tagName(self.oauth_code) });
    }

    pub fn local(stage: d.Stage, err: anyerror, effect: Effect, status: ?u16) Failure {
        return .{ .effect = effect, .diagnostic = .{
            .stage = stage,
            .category = switch (err) {
                error.Deadline, error.LimitExceeded => .timeout,
                error.Cancelled => .cancelled,
                error.TokenExpired => .authentication,
                error.BodyTooLarge, error.HeadersTooLarge => .output_limit,
                error.Transport => .transport,
                error.RemoteFailed => .service,
                error.OriginalIdentityMismatch, error.HashMismatch => .integrity,
                error.OutOfMemory => .local_io,
                else => if (status != null) .invalid_response else .invalid_input,
            },
            .http_status = status,
        } };
    }
};

pub fn Outcome(comptime T: type) type {
    return union(enum) { ok: T, failed: Failure };
}

pub const Clock = struct {
    context: *anyopaque,
    monotonicMsFn: *const fn (*anyopaque) u64,
    unixSecondsFn: *const fn (*anyopaque) i64,
    sleepMsFn: *const fn (*anyopaque, u32) anyerror!void,
};

pub const NativeClock = struct {
    io: std.Io,
    pub fn clock(self: *NativeClock) Clock {
        return .{ .context = self, .monotonicMsFn = monotonic, .unixSecondsFn = unix, .sleepMsFn = sleep };
    }
    fn monotonic(context: *anyopaque) u64 {
        const self: *NativeClock = @ptrCast(@alignCast(context));
        return @intCast(@divTrunc(std.Io.Timestamp.now(self.io, .awake).nanoseconds, std.time.ns_per_ms));
    }
    fn unix(context: *anyopaque) i64 {
        const self: *NativeClock = @ptrCast(@alignCast(context));
        return std.Io.Timestamp.now(self.io, .real).toSeconds();
    }
    fn sleep(context: *anyopaque, ms: u32) !void {
        const self: *NativeClock = @ptrCast(@alignCast(context));
        try std.Io.sleep(self.io, .fromMilliseconds(ms), .awake);
    }
};

pub const Budget = struct {
    clock: Clock,
    deadline_ms: u64,
    cancellation: ?*const sdk.http.CancellationToken = null,
    max_requests: u16 = 64,
    max_response_bytes: usize = 1024 * 1024,
    max_total_bytes: usize = 8 * 1024 * 1024,
    max_pages: u16 = 16,
    max_polls: u16 = 32,
    max_items: usize = 512,
    requests: u16 = 0,
    bytes: usize = 0,

    pub fn check(self: *const Budget) !void {
        if (self.max_requests == 0 or self.max_requests > 256 or self.max_pages == 0 or self.max_pages > 64 or
            self.max_polls == 0 or self.max_polls > 128 or self.max_items == 0 or self.max_items > 4096 or
            self.max_response_bytes == 0 or self.max_response_bytes > 4 * 1024 * 1024 or
            self.max_total_bytes == 0 or self.max_total_bytes > 32 * 1024 * 1024) return error.InvalidBudget;
        if (self.cancellation) |token| if (token.isCancelled()) return error.Cancelled;
        const now = self.clock.monotonicMsFn(self.clock.context);
        if (now >= self.deadline_ms) return error.Deadline;
        if (self.deadline_ms - now > 24 * 60 * 60 * 1000) return error.InvalidBudget;
    }

    pub fn beforeRequest(self: *Budget) !u64 {
        try self.check();
        if (self.requests >= self.max_requests) return error.LimitExceeded;
        const now = self.clock.monotonicMsFn(self.clock.context);
        if (now >= self.deadline_ms) return error.Deadline;
        self.requests += 1;
        return self.deadline_ms - now;
    }

    pub fn sleep(self: *Budget, ms: u32) !void {
        try self.check();
        const now = self.clock.monotonicMsFn(self.clock.context);
        if (now >= self.deadline_ms or ms > 60_000 or ms >= self.deadline_ms - now) return error.Deadline;
        try self.clock.sleepMsFn(self.clock.context, ms);
        try self.check();
    }
};

pub const Reply = struct {
    arena: *secret.Arena,
    status: u16,
    body: []const u8,
    async_operation: ?[]const u8,
    operation_location: ?[]const u8,
    location: ?[]const u8,
    retry_ms: ?u32,

    pub fn deinit(self: *Reply) void {
        self.arena.destroy();
        self.* = undefined;
    }
};

pub const Channel = struct {
    allocator: std.mem.Allocator,
    runtime: sdk.http.HttpRuntime,
    budget: *Budget,

    pub fn send(self: Channel, request: *sdk.http.Request, mutation: bool, stage: d.Stage) Outcome(Reply) {
        request.retryable = false;
        request.redirect_policy = .not_allowed;
        request.operation_timeout_ms = self.budget.beforeRequest() catch |err|
            return .{ .failed = Failure.local(stage, err, .not_started, null) };
        var pipeline = sdk.http.HttpPipeline.init(self.runtime, &.{});
        const operation = pipeline.open(request, .{ .cancellation = self.budget.cancellation }) catch |err|
            return .{ .failed = Failure.local(stage, if (err == error.OperationCancelled) error.Cancelled else error.Transport, if (mutation and request.transport_started) .unknown else if (mutation) .not_started else .not_applicable, null) };
        defer operation.deinit();
        const status = operation.status_code;
        const effect: Effect = if (!mutation) .not_applicable else if (status >= 200 and status < 300) .accepted else if (status >= 400 and status < 500 and status != 408) .rejected else .unknown;
        if (status < 100 or status > 599) return .{ .failed = Failure.local(stage, error.InvalidStatus, effect, null) };
        const arena = secret.Arena.create(self.allocator) catch |err| return .{ .failed = Failure.local(stage, err, effect, status) };
        var keep = false;
        defer if (!keep) arena.destroy();
        const a = arena.allocator();
        const reply = self.read(a, operation, arena) catch |err| return .{ .failed = Failure.local(stage, err, effect, status) };
        if (status < 200 or status >= 300) {
            var failure: Failure = .{ .effect = effect, .diagnostic = .{
                .stage = stage,
                .category = switch (status) {
                    401 => .authentication,
                    403 => .authorization,
                    404 => .not_found,
                    408, 504 => .timeout,
                    409, 412 => .conflict,
                    429 => .throttled,
                    300...399 => .invalid_response,
                    else => .service,
                },
                .http_status = status,
            } };
            const header = uniqueHeader(operation, "x-ms-error-code") catch {
                failure.diagnostic.service_code = .conflicting;
                return .{ .failed = failure };
            };
            if (reply.body.len != 0) {
                const document = foundation.contracts.Document.parse(a, reply.body, .{
                    .bytes = self.budget.max_response_bytes,
                    .string_bytes = @min(self.budget.max_response_bytes, 16 * 1024),
                }) catch {
                    failure.diagnostic.service_code = .malformed;
                    return .{ .failed = failure };
                };
                defer document.deinit();
                const body_code: ?[]const u8 = code: {
                    const root = document.value();
                    if (root != .object) {
                        failure.diagnostic.service_code = .malformed;
                        return .{ .failed = failure };
                    }
                    const e = root.object.get("error") orelse break :code null;
                    if (stage == .credential and e == .string) {
                        const oauth = std.meta.stringToEnum(OAuthCode, e.string) orelse .unknown;
                        failure.oauth_code = if (oauth == .unavailable) .unknown else oauth;
                        failure.diagnostic.service_code = d.reconcileServiceCodes(header, e.string);
                        if (status >= 400 and status < 500) failure.diagnostic.category = .authentication;
                        return .{ .failed = failure };
                    }
                    if (e != .object) {
                        failure.diagnostic.service_code = .malformed;
                        return .{ .failed = failure };
                    }
                    const value = e.object.get("code") orelse break :code null;
                    if (value != .string) {
                        failure.diagnostic.service_code = .malformed;
                        return .{ .failed = failure };
                    }
                    break :code value.string;
                };
                failure.diagnostic.service_code = d.reconcileServiceCodes(header, body_code);
            } else failure.diagnostic.service_code = d.classifyServiceCode(header);
            return .{ .failed = failure };
        }
        keep = true;
        return .{ .ok = reply };
    }

    fn readProgress(self: Channel, operation: *sdk.http.HttpOperation, buffer: []u8) !usize {
        self.budget.check() catch |err| {
            operation.cancel();
            return err;
        };
        var slices = [_][]u8{buffer};
        const result = operation.body_reader.readVec(&slices);
        self.budget.check() catch |err| {
            operation.cancel();
            return err;
        };
        return result;
    }

    fn read(self: Channel, allocator: std.mem.Allocator, operation: *sdk.http.HttpOperation, arena: *secret.Arena) !Reply {
        try self.budget.check();
        var header_bytes: usize = 0;
        if (operation.response_headers.entries.items.len > 64 or operation.headers.count() > 64) return error.HeadersTooLarge;
        for (operation.response_headers.entries.items) |entry| header_bytes += entry.name.len + entry.value.len;
        var iter = operation.headers.iterator();
        while (iter.next()) |entry| header_bytes += entry.key_ptr.len + entry.value_ptr.len;
        if (header_bytes > 16 * 1024) return error.HeadersTooLarge;
        if (try uniqueHeader(operation, "Content-Encoding")) |encoding| {
            if (!std.ascii.eqlIgnoreCase(encoding, "identity")) return error.InvalidEncoding;
        }
        const declared = if (try uniqueHeader(operation, "Content-Length")) |raw| try unsigned(raw) else null;
        if (declared) |length| if (length > self.budget.max_response_bytes) return error.BodyTooLarge;
        const bytes = try allocator.alloc(u8, self.budget.max_response_bytes + 1);
        var used: usize = 0;
        _ = try operation.reader();
        while (true) {
            // readSliceShort hides repeated progress; zero readVec progress is not EOF.
            const n = self.readProgress(operation, bytes[used..@min(bytes.len, used + 4096)]) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            used += n;
            if (used > self.budget.max_response_bytes or n > self.budget.max_total_bytes -| self.budget.bytes) return error.BodyTooLarge;
            self.budget.bytes += n;
        }
        if (declared) |length| if (length != used) return error.TruncatedResponse;
        if (operation.bodyError() != null) return error.TruncatedResponse;
        try self.budget.check();
        // SDK finish drains without our budget. Close locally after guarded EOF.
        operation.abort();
        const retry_ms: ?u32 = if (try uniqueHeader(operation, "Retry-After")) |raw| retry: {
            const seconds = try unsigned(raw);
            if (seconds > 60) return error.InvalidRetryAfter;
            break :retry @intCast(seconds * 1000);
        } else null;
        return .{
            .arena = arena,
            .status = operation.status_code,
            .body = bytes[0..used],
            .async_operation = try copyHeader(allocator, operation, "Azure-AsyncOperation"),
            .operation_location = try copyHeader(allocator, operation, "Operation-Location"),
            .location = try copyHeader(allocator, operation, "Location"),
            .retry_ms = retry_ms,
        };
    }
};

fn copyHeader(allocator: std.mem.Allocator, operation: *sdk.http.HttpOperation, key: []const u8) !?[]const u8 {
    const value = try uniqueHeader(operation, key) orelse return null;
    if (value.len == 0 or value.len > 4096) return error.InvalidHeader;
    return try allocator.dupe(u8, value);
}

fn uniqueHeader(operation: *sdk.http.HttpOperation, key: []const u8) !?[]const u8 {
    var found: ?[]const u8 = null;
    for (operation.response_headers.entries.items) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.name, key)) continue;
        if (found != null) return error.DuplicateHeader;
        found = entry.value;
    }
    var mapped: ?[]const u8 = null;
    var iter = operation.headers.iterator();
    while (iter.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, key)) continue;
        if (mapped != null) return error.DuplicateHeader;
        mapped = entry.value_ptr.*;
    }
    if (found != null and mapped != null and !std.mem.eql(u8, found.?, mapped.?)) return error.ConflictingHeader;
    return found orelse mapped;
}

pub fn unsigned(raw: []const u8) !u64 {
    if (raw.len == 0 or raw.len > 20 or (raw.len > 1 and raw[0] == '0')) return error.InvalidInteger;
    for (raw) |c| if (!std.ascii.isDigit(c)) return error.InvalidInteger;
    return std.fmt.parseInt(u64, raw, 10);
}

/// No ambient trust rescan, proxy discovery, TLS key logging, or system CA read.
/// The caller supplies DER certificates and the approved concatenated-byte hash.
pub const NativeRuntime = struct {
    http: sdk.http.StdHttpTransport,
    crypto: sdk.crypto.StdCryptoProvider,
    trust_sha256: [32]u8,
    zero: *secret.Allocator,
    clock: Clock,

    pub fn init(parent: std.mem.Allocator, io: std.Io, certs: []const []const u8, expected: [32]u8, clock: Clock) !NativeRuntime {
        const now = clock.unixSecondsFn(clock.context);
        if (certs.len == 0 or certs.len > 64 or now <= 0) return error.InvalidTrust;
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        var total: usize = 0;
        for (certs) |cert| {
            if (cert.len == 0 or cert.len > 64 * 1024) return error.InvalidTrust;
            total += cert.len;
            if (total > 1024 * 1024) return error.InvalidTrust;
            sha.update(cert);
        }
        if (!std.crypto.timing_safe.eql([32]u8, sha.finalResult(), expected)) return error.TrustMismatch;
        const zero = try parent.create(secret.Allocator);
        zero.* = .{ .parent = parent };
        errdefer parent.destroy(zero);
        const allocator = zero.allocator();
        var bundle: std.crypto.Certificate.Bundle = .empty;
        errdefer bundle.deinit(allocator);
        for (certs) |cert| {
            const start: u32 = @intCast(bundle.bytes.items.len);
            try bundle.bytes.appendSlice(allocator, cert);
            const parsed = try std.crypto.Certificate.parse(.{ .buffer = bundle.bytes.items, .index = start });
            if (now < parsed.validity.not_before or now > parsed.validity.not_after) return error.InvalidTrust;
            try bundle.parseCert(allocator, start, now);
        }
        if (bundle.map.count() == 0) return error.InvalidTrust;
        return .{
            .http = .initWithClient(allocator, .{
                .allocator = allocator,
                .io = io,
                .ca_bundle = bundle,
                .now = .{ .nanoseconds = @as(i96, now) * std.time.ns_per_s },
                .read_buffer_size = 16 * 1024,
            }),
            .crypto = .init(io),
            .trust_sha256 = expected,
            .zero = zero,
            .clock = clock,
        };
    }

    pub fn runtime(self: *NativeRuntime) sdk.http.HttpRuntime {
        return .init(.{ .context = self, .vtable = &.{ .send = bufferedForbidden, .open = open } }, self.crypto.asProvider());
    }
    pub fn deinit(self: *NativeRuntime) !void {
        if (self.http.shared_client) |shared| if (shared.references.load(.acquire) != 1) return error.ActiveOperations;
        self.http.deinit();
        const parent = self.zero.parent;
        std.crypto.secureZero(u8, std.mem.asBytes(self.zero));
        parent.destroy(self.zero);
        self.* = undefined;
    }
    fn bufferedForbidden(_: *anyopaque, _: *sdk.http.Request) !sdk.http.Response {
        return error.BufferedTransportForbidden;
    }
    fn open(context: *anyopaque, request: *sdk.http.Request, options: sdk.http.OpenOptions) !*sdk.http.HttpOperation {
        const self: *NativeRuntime = @ptrCast(@alignCast(context));
        const now = self.clock.unixSecondsFn(self.clock.context);
        if (now <= 0) return error.InvalidClock;
        const timestamp: std.Io.Timestamp = .{ .nanoseconds = @as(i96, now) * std.time.ns_per_s };
        if (self.http.shared_client) |shared| shared.client.now = timestamp else self.http.client.now = timestamp;
        return self.http.asTransport().open(request, options);
    }
};
