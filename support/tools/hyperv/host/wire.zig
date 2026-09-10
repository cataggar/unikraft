const std = @import("std");
const core = @import("hyperv_core");
const sdk = @import("azure_sdk_core");
const p = @import("protocol.zig");
const Publication = @import("state.zig").Publication;

pub const imds_vm = "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text";
pub const imds_region = "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text";
pub const imds_size = "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text";
pub const imds_token = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F";
pub const max_token_response = 32 * 1024;

pub const Budget = struct {
    context: *anyopaque,
    now_ms: *const fn (*anyopaque) anyerror!u64,
    deadline_ms: u64,
    cancellation: *sdk.http.CancellationToken,

    pub fn remaining(self: Budget) !u64 {
        if (self.cancellation.isCancelled()) return error.Cancelled;
        const now = try self.now_ms(self.context);
        if (now >= self.deadline_ms) return error.DeadlineExceeded;
        return self.deadline_ms - now;
    }
};

pub const NativeRuntime = struct {
    transport: sdk.http.StdHttpTransport,
    crypto: sdk.crypto.StdCryptoProvider,

    pub fn init(http: std.http.Client) NativeRuntime {
        return .{ .transport = .initWithClient(http.allocator, http), .crypto = .init(http.io) };
    }

    pub fn runtime(self: *NativeRuntime) sdk.http.HttpRuntime {
        return .init(self.transport.asTransport(), self.crypto.asProvider());
    }

    pub fn deinit(self: *NativeRuntime) void {
        self.transport.deinit();
    }
};

pub const Token = struct {
    bytes: []u8,
    expires_at: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Token) void {
        std.crypto.secureZero(u8, self.bytes);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const PublishResult = struct {
    publication: Publication,
    failure: ?core.diagnostics.Diagnostic = null,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runtime: sdk.http.HttpRuntime,
    budget: Budget,
    scope: p.Scope,
    token: ?Token = null,

    pub fn deinit(self: *Client) void {
        if (self.token) |*token| token.deinit();
        self.token = null;
    }

    pub fn identify(self: *Client) !p.Uuid {
        const bytes = try self.getSmall(imds_vm, 64, true);
        defer self.allocator.free(bytes);
        const id = try core.contracts.parseUuid(std.mem.trim(u8, bytes, "\r\n"));
        try p.validUuid(id);
        const region = try self.getSmall(imds_region, 64, true);
        defer self.allocator.free(region);
        const size = try self.getSmall(imds_size, 64, true);
        defer self.allocator.free(size);
        if (!std.mem.eql(u8, std.mem.trim(u8, region, "\r\n"), "northeurope") or !std.mem.eql(u8, std.mem.trim(u8, size, "\r\n"), "Standard_D2s_v5")) return error.HostEnvelopeMismatch;
        return id;
    }

    pub fn authenticate(self: *Client, expected_vm: p.Uuid, now: u64) !void {
        try self.scope.validate();
        const observed = try self.identify();
        if (!std.mem.eql(u8, &observed, &expected_vm)) return error.VmIdentityChanged;
        if (self.token != null) return error.CredentialAlreadyAcquired;
        const bytes = try self.getSmall(imds_token, max_token_response, true);
        defer {
            std.crypto.secureZero(u8, bytes);
            self.allocator.free(bytes);
        }
        // The SDK convenience credential buffers and logs failures. Use its
        // streaming transport, but parse this one fixed IMDS protocol locally.
        var doc = try core.contracts.Document.parse(self.allocator, bytes, .{ .bytes = max_token_response, .string_bytes = 16384, .items = 16, .tokens = 64, .depth = 2 });
        defer {
            eraseStrings(doc.value());
            doc.deinit();
        }
        const value = doc.value();
        if (value != .object) return error.InvalidTokenResponse;
        for (value.object.keys()) |name| {
            var allowed = false;
            inline for (.{ "access_token", "client_id", "expires_in", "expires_on", "ext_expires_in", "not_before", "resource", "token_type" }) |field| if (std.mem.eql(u8, name, field)) {
                allowed = true;
            };
            if (!allowed) return error.InvalidTokenResponse;
        }
        const token = try core.contracts.string(try p.field(value, "access_token"));
        if (token.len == 0 or token.len > 16384) return error.InvalidTokenResponse;
        for (token) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') return error.InvalidTokenResponse;
        if (!std.mem.eql(u8, try core.contracts.string(try p.field(value, "token_type")), "Bearer")) return error.InvalidTokenResponse;
        const resource = try core.contracts.string(try p.field(value, "resource"));
        if (!std.mem.eql(u8, resource, "https://storage.azure.com/") and !std.mem.eql(u8, resource, "https://storage.azure.com")) return error.InvalidTokenResponse;
        const expiry_value = try p.field(value, "expires_on");
        const expires = if (expiry_value == .string) try decimal(expiry_value.string) else try core.contracts.integer(u64, expiry_value);
        if (expires <= now or expires - now < 60 or expires - now > 86400) return error.InvalidTokenResponse;
        self.token = .{ .allocator = self.allocator, .bytes = try self.allocator.dupe(u8, token), .expires_at = expires };
    }

    pub fn command(self: *Client, phase: p.Phase, now: u64) ![]u8 {
        try self.authorized(now);
        const name = try std.fmt.allocPrint(self.allocator, "runs/{s}/commands/{s}.json", .{ p.uuidText(self.scope.run_id), @tagName(phase) });
        defer self.allocator.free(name);
        const url = try self.blobUrl(name);
        defer self.allocator.free(url);
        return self.getSmall(url, p.max_command, false);
    }

    pub fn download(self: *Client, artifact: p.Artifact, phase: p.Phase, file: std.Io.File, now: u64) !void {
        try self.authorized(now);
        try p.validName(artifact.role, artifact.name);
        const expected = try p.artifactBlob(self.allocator, self.scope.run_id, phase, artifact.name);
        defer self.allocator.free(expected);
        if (!std.mem.eql(u8, artifact.blob, expected) or artifact.size == 0 or artifact.size > p.max_artifact) return error.InvalidBlobScope;
        const url = try self.blobUrl(expected);
        defer self.allocator.free(url);
        var request = sdk.http.Request.init(self.allocator, .GET, url);
        defer destroyRequest(&request);
        try self.headers(&request, false);
        const operation = try self.open(&request, null);
        defer operation.deinit();
        try requireStatus(operation, 200);
        try framing(operation, artifact.size, artifact.size);
        var buffer: [32 * 1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        var size: u64 = 0;
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        while (true) {
            _ = try self.budget.remaining();
            const count = try (try operation.reader()).readSliceShort(buffer[0..@min(buffer.len, artifact.size - size + 1)]);
            if (count == 0) break;
            if (count > artifact.size - size) return error.ResponseLimit;
            try file.writePositionalAll(self.io, buffer[0..count], size);
            sha.update(buffer[0..count]);
            size += count;
        }
        if (size != artifact.size or !std.mem.eql(u8, &sha.finalResult(), &artifact.sha256)) return error.ArtifactIntegrity;
        _ = try self.budget.remaining();
        try operation.finish();
        try file.sync(self.io);
    }

    pub fn publish(self: *Client, phase: p.Phase, nonce: p.Uuid, name: []const u8, bytes: []const u8, now: u64) PublishResult {
        return self.publishImpl(phase, nonce, name, bytes, now) catch .{ .publication = .not_started, .failure = .{ .stage = .blob_upload, .category = .invalid_input } };
    }

    fn publishImpl(self: *Client, phase: p.Phase, nonce: p.Uuid, name: []const u8, bytes: []const u8, now: u64) !PublishResult {
        try self.authorized(now);
        try p.validUuid(nonce);
        if (bytes.len > p.max_serial or bytes.len == 0) return error.EvidenceLimit;
        if (!std.mem.eql(u8, name, "receipt.json")) {
            if (name.len != 10 or !std.mem.startsWith(u8, name, "boot-") or !std.mem.endsWith(u8, name, ".log") or name[5] < '0' or name[5] > '5') return error.InvalidEvidenceRole;
            if ((phase == .public and name[5] > '1') or (phase == .private and name[5] < '2')) return error.InvalidEvidenceRole;
        }
        const path = try std.fmt.allocPrint(self.allocator, "runs/{s}/evidence/{s}/{s}/{s}", .{ p.uuidText(self.scope.run_id), @tagName(phase), p.uuidText(nonce), name });
        defer self.allocator.free(path);
        const url = try self.blobUrl(path);
        defer self.allocator.free(url);
        var request = sdk.http.Request.init(self.allocator, .PUT, url);
        defer destroyRequest(&request);
        try self.headers(&request, false);
        try request.setHeader("If-None-Match", "*");
        try request.setHeader("x-ms-blob-type", "BlockBlob");
        var length: [24]u8 = undefined;
        try request.setHeader("Content-Length", try std.fmt.bufPrint(&length, "{d}", .{bytes.len}));
        var md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(bytes, &md5, .{});
        var encoded: [24]u8 = undefined;
        try request.setHeader("Content-MD5", std.base64.standard.Encoder.encode(&encoded, &md5));
        var reader = std.Io.Reader.fixed(bytes);
        const operation = self.open(&request, .{ .reader = &reader, .content_length = bytes.len }) catch {
            return .{ .publication = if (request.transport_started) .unknown else .not_started, .failure = .{ .stage = .blob_upload, .category = if (request.transport_started) .ambiguous else .transport } };
        };
        defer operation.deinit();
        if (operation.status_code != 201) return .{
            .publication = if (operation.status_code == 401 or operation.status_code == 403 or operation.status_code == 409 or operation.status_code == 412) .rejected else .unknown,
            .failure = .{ .stage = .blob_upload, .category = if (operation.status_code == 401) .authentication else if (operation.status_code == 403) .authorization else if (operation.status_code == 409 or operation.status_code == 412) .conflict else .ambiguous, .http_status = operation.status_code },
        };
        self.emptyResponse(operation) catch return .{ .publication = .unknown, .failure = .{ .stage = .blob_upload, .category = .ambiguous, .http_status = 201 } };
        return .{ .publication = .complete };
    }

    fn emptyResponse(self: *Client, operation: *sdk.http.HttpOperation) !void {
        try framing(operation, null, 0);
        _ = try self.budget.remaining();
        var extra: [1]u8 = undefined;
        if (try (try operation.reader()).readSliceShort(&extra) != 0) return error.ResponseLimit;
        _ = try self.budget.remaining();
        try operation.finish();
    }

    fn authorized(self: *Client, now: u64) !void {
        try self.scope.validate();
        const token = self.token orelse return error.NotAuthenticated;
        if (now >= token.expires_at) return error.TokenExpired;
        _ = try self.budget.remaining();
    }

    fn blobUrl(self: *Client, name: []const u8) ![]u8 {
        try self.scope.validate();
        return std.fmt.allocPrint(self.allocator, "https://{s}.blob.core.windows.net/{s}/{s}", .{ self.scope.account, self.scope.container, name });
    }

    fn headers(self: *Client, request: *sdk.http.Request, metadata: bool) !void {
        request.retryable = false;
        request.redirect_policy = .not_allowed;
        try request.setHeader("Accept-Encoding", "identity");
        if (metadata) {
            try request.setHeader("Metadata", "true");
        } else {
            const token = self.token orelse return error.NotAuthenticated;
            const authorization = try std.mem.concat(self.allocator, u8, &.{ "Bearer ", token.bytes });
            defer {
                std.crypto.secureZero(u8, authorization);
                self.allocator.free(authorization);
            }
            try request.setHeader("Authorization", authorization);
            try request.setHeader("x-ms-version", "2024-11-04");
            try request.setHeader("Content-Type", "application/octet-stream");
        }
    }

    fn open(self: *Client, request: *sdk.http.Request, body: ?sdk.http.StreamingRequestBody) !*sdk.http.HttpOperation {
        if (self.runtime.transport.vtable.open == null) return error.StreamingRequired;
        request.operation_timeout_ms = try self.budget.remaining();
        request.retryable = false;
        request.redirect_policy = .not_allowed;
        // No retry, logging, credential or redirect policy is installed.
        const operation = try self.runtime.transport.open(request, .{ .body = body, .cancellation = self.budget.cancellation });
        if (operation.status_code < 100 or operation.status_code > 599) {
            operation.deinit();
            return error.InvalidResponse;
        }
        return operation;
    }

    fn getSmall(self: *Client, url: []const u8, maximum: usize, metadata: bool) ![]u8 {
        var request = sdk.http.Request.init(self.allocator, .GET, url);
        defer destroyRequest(&request);
        try self.headers(&request, metadata);
        const operation = try self.open(&request, null);
        defer operation.deinit();
        try requireStatus(operation, 200);
        try framing(operation, null, maximum);
        const bytes = try self.allocator.alloc(u8, maximum + 1);
        defer {
            std.crypto.secureZero(u8, bytes);
            self.allocator.free(bytes);
        }
        var used: usize = 0;
        while (used < bytes.len) {
            _ = try self.budget.remaining();
            const count = try (try operation.reader()).readSliceShort(bytes[used..@min(bytes.len, used + 4096)]);
            if (count == 0) break;
            used += count;
            if (used > maximum) return error.ResponseLimit;
        }
        if (try uniqueHeader(operation, "Content-Length")) |length| if (try decimal(length) != used) return error.InvalidResponse;
        _ = try self.budget.remaining();
        try operation.finish();
        return self.allocator.dupe(u8, bytes[0..used]);
    }
};

fn eraseStrings(value: std.json.Value) void {
    switch (value) {
        .string, .number_string => |text| std.crypto.secureZero(u8, @constCast(text)),
        .array => |array| for (array.items) |item| eraseStrings(item),
        .object => |object| for (object.values()) |item| eraseStrings(item),
        else => {},
    }
}

fn destroyRequest(request: *sdk.http.Request) void {
    if (request.getHeader("Authorization")) |value| std.crypto.secureZero(u8, @constCast(value));
    request.deinit();
}

fn decimal(value: []const u8) !u64 {
    if (value.len == 0 or value.len > 20) return error.InvalidResponse;
    for (value) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidResponse;
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidResponse;
}

fn uniqueHeader(operation: *const sdk.http.HttpOperation, name: []const u8) !?[]const u8 {
    var found: ?[]const u8 = null;
    for (operation.response_headers.entries.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            if (found != null or header.value.len > 256) return error.AmbiguousHeader;
            found = header.value;
        }
    }
    const value = found orelse operation.getHeader(name) orelse return null;
    if (value.len > 256) return error.AmbiguousHeader;
    return value;
}

fn framing(operation: *const sdk.http.HttpOperation, required: ?u64, maximum: u64) !void {
    if (try uniqueHeader(operation, "Content-Encoding")) |encoding| if (!std.mem.eql(u8, encoding, "identity")) return error.InvalidEncoding;
    const length = try uniqueHeader(operation, "Content-Length");
    if (try uniqueHeader(operation, "Transfer-Encoding")) |encoding| {
        if (length != null or !std.ascii.eqlIgnoreCase(encoding, "chunked")) return error.AmbiguousHeader;
    }
    if (length) |value| {
        const size = try decimal(value);
        if (size > maximum or (required != null and size != required.?)) return error.ResponseLimit;
    } else if (required != null) return error.InvalidResponse;
}

fn requireStatus(operation: *const sdk.http.HttpOperation, expected: u16) !void {
    if (operation.status_code == expected) return;
    if (operation.status_code >= 300 and operation.status_code < 400) return error.RedirectRejected;
    return switch (operation.status_code) {
        401 => error.AuthenticationFailed,
        403 => error.AuthorizationFailed,
        404 => error.NotFound,
        else => error.HttpRejected,
    };
}
