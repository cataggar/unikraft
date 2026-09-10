const std = @import("std");
const sdk = @import("azure_sdk_core");
const host = @import("host");
const p = host.protocol;
const w = host.wire;
const f = @import("fixture_support.zig");
const a = std.testing.allocator;
const io = std.testing.io;
const t = std.testing;
const command_url = "https://fixture.blob.core.windows.net/private/runs/" ++ f.run_text ++ "/commands/public.json";
const evidence_url = "https://fixture.blob.core.windows.net/private/runs/" ++ f.run_text ++ "/evidence/public/" ++ f.public_nonce_text ++ "/receipt.json";

pub const Step = struct {
    url: []const u8,
    method: sdk.http.Method = .GET,
    metadata: bool = false,
    status: u16 = 200,
    response: []const u8 = "",
    headers: []const sdk.http.ResponseHeader = &.{},
    request_body: ?[]const u8 = null,
    fail_open: bool = false,
    fail_after: ?usize = null,
    cancel_after: ?usize = null,
    deadline_after: ?usize = null,
};

pub const Mock = struct {
    steps: []const Step,
    calls: usize = 0,
    reads: usize = 0,
    response_bytes: usize = 0,
    aborts: usize = 0,
    finishes: usize = 0,
    cancellation: sdk.http.CancellationToken = .{},
    time: u64 = 1,
    crypto: sdk.crypto.StdCryptoProvider = .init(io),

    pub fn client(self: *Mock) w.Client {
        return .{ .allocator = a, .io = io, .scope = f.scope(), .runtime = .init(.{ .context = self, .vtable = &.{ .send = send, .open = open } }, self.crypto.asProvider()), .budget = .{ .context = self, .now_ms = clock, .deadline_ms = 10000, .cancellation = &self.cancellation } };
    }

    pub fn authenticated(self: *Mock) !w.Client {
        var result = self.client();
        result.token = .{ .allocator = a, .bytes = try a.dupe(u8, "SYNTHETIC_TOKEN"), .expires_at = 2000 };
        return result;
    }

    fn clock(context: *anyopaque) !u64 {
        const self: *Mock = @ptrCast(@alignCast(context));
        return self.time;
    }

    fn send(_: *anyopaque, _: *sdk.http.Request) !sdk.http.Response {
        return error.BufferedTransportForbidden;
    }

    fn open(context: *anyopaque, request: *sdk.http.Request, options: sdk.http.OpenOptions) !*sdk.http.HttpOperation {
        const self: *Mock = @ptrCast(@alignCast(context));
        try t.expect(self.calls < self.steps.len);
        const step = &self.steps[self.calls];
        self.calls += 1;
        try t.expectEqualStrings(step.url, request.url);
        try t.expectEqual(step.method, request.method);
        try t.expect(!request.retryable);
        try t.expectEqual(sdk.http.RedirectPolicy.not_allowed, request.redirect_policy);
        try t.expect(request.operation_timeout_ms != null);
        try t.expect(options.cancellation != null);
        if (step.metadata) {
            try t.expect(request.getHeader("Authorization") == null);
            try t.expectEqualStrings("true", request.getHeader("Metadata").?);
        } else {
            try t.expectEqualStrings("Bearer SYNTHETIC_TOKEN", request.getHeader("Authorization").?);
            try t.expect(request.getHeader("Metadata") == null);
        }
        if (step.method == .PUT) {
            try t.expectEqualStrings("*", request.getHeader("If-None-Match").?);
            try t.expectEqualStrings("BlockBlob", request.getHeader("x-ms-blob-type").?);
            const body = options.body orelse return error.MissingBody;
            try t.expect(!body.isReplayable());
            const expected = step.request_body orelse return error.MissingExpectedBody;
            try t.expectEqual(expected.len, body.content_length.?);
            const buffer = try a.alloc(u8, expected.len + 1);
            defer a.free(buffer);
            const count = try body.reader.readSliceShort(buffer);
            try t.expectEqualStrings(expected, buffer[0..count]);
            var md5: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(expected, &md5, .{});
            var encoded: [24]u8 = undefined;
            try t.expectEqualStrings(std.base64.standard.Encoder.encode(&encoded, &md5), request.getHeader("Content-MD5").?);
        }
        if (step.fail_open) return error.SYNTHETIC_SECRET_NOT_FOR_LOGS;
        const operation = try a.create(Operation);
        var headers = sdk.http.ResponseHeaders.init(a);
        errdefer headers.deinit();
        for (step.headers) |header| try headers.append(header.name, header.value);
        operation.* = .{
            .mock = self,
            .step = step,
            .reader = .{ .vtable = &.{ .stream = Operation.stream }, .buffer = &.{}, .seek = 0, .end = 0 },
            .operation = undefined,
        };
        operation.operation = .{
            .status_code = step.status,
            .headers = std.StringHashMap([]const u8).init(a),
            .response_headers = headers,
            .body_reader = &operation.reader,
            .finishFn = Operation.finish,
            .abortFn = Operation.abort,
            .cancelFn = Operation.abort,
            .deinitFn = Operation.deinit,
        };
        return &operation.operation;
    }
};

const Operation = struct {
    mock: *Mock,
    step: *const Step,
    reader: std.Io.Reader,
    operation: sdk.http.HttpOperation,
    offset: usize = 0,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Operation = @alignCast(@fieldParentPtr("reader", reader));
        self.mock.reads += 1;
        if (self.mock.cancellation.isCancelled() or self.mock.time >= 10000) return error.ReadFailed;
        if (self.step.fail_after) |offset| if (self.offset >= offset) return error.ReadFailed;
        if (self.offset == self.step.response.len) return error.EndOfStream;
        const count = try writer.write(self.step.response[self.offset..][0..@min(limit.minInt(137), self.step.response.len - self.offset)]);
        self.offset += count;
        self.mock.response_bytes += count;
        if (self.step.cancel_after) |offset| if (self.offset >= offset) {
            self.mock.cancellation.cancel();
        };
        if (self.step.deadline_after) |offset| if (self.offset >= offset) {
            self.mock.time = 10000;
        };
        return count;
    }

    fn finish(operation: *sdk.http.HttpOperation) !void {
        const self: *Operation = @alignCast(@fieldParentPtr("operation", operation));
        try t.expectEqual(self.step.response.len, self.offset);
        self.mock.finishes += 1;
    }

    fn abort(operation: *sdk.http.HttpOperation) void {
        const self: *Operation = @alignCast(@fieldParentPtr("operation", operation));
        self.mock.aborts += 1;
    }

    fn deinit(operation: *sdk.http.HttpOperation) void {
        const self: *Operation = @alignCast(@fieldParentPtr("operation", operation));
        self.operation.response_headers.deinit();
        self.operation.headers.deinit();
        a.destroy(self);
    }
};

const identity_steps = [_]Step{
    .{ .url = w.imds_vm, .metadata = true, .response = f.vm_text ++ "\n" },
    .{ .url = w.imds_region, .metadata = true, .response = "northeurope" },
    .{ .url = w.imds_size, .metadata = true, .response = "Standard_D2s_v5" },
};

test "native explicit IMDS identity and managed identity without ambient sources" {
    const token = "{\"access_token\":\"SYNTHETIC_TOKEN\",\"expires_on\":\"2000\",\"token_type\":\"Bearer\",\"resource\":\"https://storage.azure.com/\"}";
    const steps = identity_steps ++ [_]Step{.{ .url = w.imds_token, .metadata = true, .response = token }};
    var mock: Mock = .{ .steps = &steps };
    var client = mock.client();
    defer client.deinit();
    try client.authenticate(f.uuid(f.vm_text), f.now);
    try t.expectEqualStrings("SYNTHETIC_TOKEN", client.token.?.bytes);
    try t.expectEqual(@as(usize, 4), mock.calls);
}

test "IMDS UUID binding rejects changed VM before acquiring token" {
    var mock: Mock = .{ .steps = &identity_steps };
    var client = mock.client();
    defer client.deinit();
    try t.expectError(error.VmIdentityChanged, client.authenticate(f.uuid(f.run_text), f.now));
    try t.expectEqual(@as(usize, 3), mock.calls);
    try t.expect(client.token == null);
}

test "IMDS redirect and credential failure never consume raw error bodies" {
    const statuses = [_]u16{ 302, 401, 403, 500 };
    for (statuses) |status| {
        const steps = identity_steps ++ [_]Step{.{ .url = w.imds_token, .metadata = true, .status = status, .response = "SYNTHETIC_SECRET_NOT_FOR_LOGS", .headers = &.{.{ .name = "Location", .value = "https://evil.invalid/steal" }} }};
        var mock: Mock = .{ .steps = &steps };
        var client = mock.client();
        defer client.deinit();
        if (client.authenticate(f.uuid(f.vm_text), f.now)) |_| return error.AcceptedCredentialFailure else |_| {}
        try t.expect(client.token == null);
        try t.expectEqual(@as(usize, f.vm_text.len + 1 + "northeurope".len + "Standard_D2s_v5".len), mock.response_bytes);
    }
}

test "credential JSON rejects duplicates wrong resource unsafe token and stale expiry" {
    const responses = [_][]const u8{
        "{\"access_token\":\"a\",\"access_token\":\"b\",\"expires_on\":\"2000\",\"token_type\":\"Bearer\",\"resource\":\"https://storage.azure.com/\"}",
        "{\"access_token\":\"a\",\"expires_on\":\"2000\",\"token_type\":\"Bearer\",\"resource\":\"https://evil.invalid/\"}",
        "{\"access_token\":\"a b\",\"expires_on\":\"2000\",\"token_type\":\"Bearer\",\"resource\":\"https://storage.azure.com/\"}",
        "{\"access_token\":\"a\",\"expires_on\":\"999\",\"token_type\":\"Bearer\",\"resource\":\"https://storage.azure.com/\"}",
    };
    for (responses) |response| {
        const steps = identity_steps ++ [_]Step{.{ .url = w.imds_token, .metadata = true, .response = response }};
        var mock: Mock = .{ .steps = &steps };
        var client = mock.client();
        defer client.deinit();
        if (client.authenticate(f.uuid(f.vm_text), f.now)) |_| return error.AcceptedMalformedCredential else |_| {}
        try t.expect(client.token == null);
    }
}

test "bounded command retrieval rejects redirects encoding ambiguity and oversize" {
    const large = try a.alloc(u8, p.max_command + 1);
    defer a.free(large);
    @memset(large, 'x');
    const cases = [_]Step{
        .{ .url = command_url, .status = 302, .headers = &.{.{ .name = "Location", .value = "https://evil.invalid/" }} },
        .{ .url = command_url, .headers = &.{ .{ .name = "Content-Length", .value = "0" }, .{ .name = "content-length", .value = "0" } } },
        .{ .url = command_url, .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }} },
        .{ .url = command_url, .response = large },
        .{ .url = command_url, .response = "x", .headers = &.{.{ .name = "Content-Length", .value = "2" }} },
    };
    for (cases) |step| {
        var mock: Mock = .{ .steps = &.{step} };
        var client = try mock.authenticated();
        defer client.deinit();
        if (client.command(.public, f.now)) |bytes| {
            a.free(bytes);
            return error.AcceptedInvalidCommandResponse;
        } else |_| {}
        try t.expectEqual(@as(usize, 1), mock.calls);
    }
    var mock: Mock = .{ .steps = &.{.{ .url = command_url, .response = large[0..p.max_command] }} };
    var client = try mock.authenticated();
    defer client.deinit();
    const bytes = try client.command(.public, f.now);
    defer a.free(bytes);
    try t.expectEqual(p.max_command, bytes.len);
}

test "create-only publication preserves rejected versus unknown outcomes" {
    const cases = [_]struct { step: Step, expected: host.state.Publication }{
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 201, .request_body = "{}\n" }, .expected = .complete },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 412, .request_body = "{}\n", .response = "SECRET" }, .expected = .rejected },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 403, .request_body = "{}\n", .response = "SECRET" }, .expected = .rejected },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 500, .request_body = "{}\n", .response = "SECRET" }, .expected = .unknown },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 999, .request_body = "{}\n" }, .expected = .unknown },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 201, .request_body = "{}\n", .response = "unexpected" }, .expected = .unknown },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .fail_open = true, .request_body = "{}\n" }, .expected = .unknown },
        .{ .step = .{ .url = evidence_url, .method = .PUT, .status = 201, .fail_after = 0, .request_body = "{}\n" }, .expected = .unknown },
    };
    for (cases) |case| {
        var mock: Mock = .{ .steps = &.{case.step} };
        var client = try mock.authenticated();
        defer client.deinit();
        const result = client.publish(.public, f.uuid(f.public_nonce_text), "receipt.json", "{}\n", f.now);
        try t.expectEqual(case.expected, result.publication);
        try t.expectEqual(@as(usize, 1), mock.calls);
        if (case.expected != .complete) try t.expect(result.failure != null);
    }
}

test "endpoint role expiration cancellation and deadline prevent transport" {
    var mock: Mock = .{ .steps = &.{} };
    var client = try mock.authenticated();
    defer client.deinit();
    client.scope.account = "fixture@evil";
    try t.expectError(error.InvalidEndpoint, client.command(.public, f.now));
    client.scope = f.scope();
    try t.expectError(error.TokenExpired, client.command(.public, 2000));
    try t.expectEqual(host.state.Publication.not_started, client.publish(.public, f.uuid(f.public_nonce_text), "boot-5.log", "x", f.now).publication);
    mock.cancellation.cancel();
    try t.expectError(error.Cancelled, client.command(.public, f.now));
    mock.cancellation = .{};
    mock.time = 10000;
    try t.expectError(error.DeadlineExceeded, client.command(.public, f.now));
    try t.expectEqual(@as(usize, 0), mock.calls);
}

test "streaming artifact verifies exact bytes length digest and scope" {
    const fixture = try f.Directory.create("wire-download");
    defer fixture.deinit();
    const body = try a.alloc(u8, 70001);
    defer a.free(body);
    for (body, 0..) |*byte, i| byte.* = @truncate(i);
    const name = "runs/" ++ f.run_text ++ "/public/artifacts/capability.raw";
    const record: p.Artifact = .{ .role = .capability_raw, .name = "capability.raw", .blob = name, .sha256 = p.hash(body), .size = body.len };
    var mock: Mock = .{ .steps = &.{.{ .url = "https://fixture.blob.core.windows.net/private/" ++ name, .response = body, .headers = &.{.{ .name = "Content-Length", .value = "70001" }} }} };
    var client = try mock.authenticated();
    defer client.deinit();
    const destination = try fixture.directory.dir.createFile(io, "artifact", .{ .read = true, .exclusive = true, .permissions = .fromMode(0o600) });
    defer destination.close(io);
    try client.download(record, .public, destination, f.now);
    const actual = try fixture.directory.read(io, a, "artifact", body.len, record.sha256);
    defer a.free(actual);
    try t.expectEqualSlices(u8, body, actual);
    try t.expectError(error.InvalidBlobScope, client.download(record, .private, destination, f.now));
    try t.expectEqual(@as(usize, 1), mock.calls);
}

test "artifact truncation excess digest mismatch cancellation and deadline fail closed" {
    const fixture = try f.Directory.create("wire-negative");
    defer fixture.deinit();
    const body = [_]u8{0x5a} ** 1024;
    const name = "runs/" ++ f.run_text ++ "/public/artifacts/capability.raw";
    const url = "https://fixture.blob.core.windows.net/private/" ++ name;
    const steps = [_]Step{
        .{ .url = url, .response = body[0..1023] },
        .{ .url = url, .response = &body },
        .{ .url = url, .response = &body, .cancel_after = 1 },
        .{ .url = url, .response = &body, .deadline_after = 1 },
    };
    for (steps, 0..) |base, index| {
        var step = base;
        step.headers = &.{.{ .name = "Content-Length", .value = "1024" }};
        var mock: Mock = .{ .steps = &.{step} };
        var client = try mock.authenticated();
        defer client.deinit();
        var filename: [16]u8 = undefined;
        const file = try fixture.directory.dir.createFile(io, try std.fmt.bufPrint(&filename, "file-{d}", .{index}), .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        const record: p.Artifact = .{ .role = .capability_raw, .name = "capability.raw", .blob = name, .sha256 = if (index == 1) p.hash("wrong") else p.hash(&body), .size = body.len };
        if (client.download(record, .public, file, f.now)) |_| return error.AcceptedBadArtifact else |_| {}
        try t.expectEqual(@as(usize, 1), mock.calls);
        try t.expectEqual(@as(usize, 0), mock.finishes);
    }
}
