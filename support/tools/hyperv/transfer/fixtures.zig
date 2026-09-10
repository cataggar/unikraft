const std = @import("std");
const core = @import("azure_sdk_core");
const transfer = @import("client.zig");
const d = @import("diagnostic.zig");
const files = @import("files.zig");
const contract = @import("request.zig");
const testing = std.testing;
const allocator = testing.allocator;
const io = testing.io;

const account = "https://synthetic.blob.core.windows.net";
const sas = "sv=2024-11-04&sp=rcw&sig=FIXTURE%2BONLY%3D";
const blob_url = account ++ "/fixture/input?" ++ sas;
const container_url = account ++ "/fixture?" ++ sas ++ "&restype=container";
const disk_endpoint = "https://md-fixture.blob.storage.azure.net:8443/upload/vhd";
const disk_url = disk_endpoint ++ "?" ++ sas;
const blob: transfer.Blob = .{ .account_url = account, .container = "fixture", .name = "input", .sas = sas };
const disk: transfer.Disk = .{ .endpoint = disk_endpoint, .sas = sas };
const deadline_ms = 1_000_000;

const Header = core.http.ResponseHeader;
const Step = struct {
    method: core.http.Method = .PUT,
    url: []const u8 = blob_url,
    request_headers: []const Header = &.{},
    absent_headers: []const []const u8 = &.{},
    body: ?[]const u8 = null,
    length: u64 = 0,
    verify_md5: bool = false,
    status: u16 = 201,
    headers: []const Header = &.{},
    response: []const u8 = "",
    fragment: usize = 137,
    fail_open_after: ?usize = null,
    response_failure_after: ?usize = null,
    cancel_after_response: ?usize = null,
    deadline_after_response: ?usize = null,
    zero_progress_once: bool = false,
    before: ?*const fn (*Mock) anyerror!void = null,
    after: ?*const fn (*Mock) anyerror!void = null,
};

const Clock = struct {
    now_ms: u64 = 0,
    advance: u64 = 0,
    fn now(context: *anyopaque) u64 {
        const self: *Clock = @ptrCast(@alignCast(context));
        const value = self.now_ms;
        self.now_ms += self.advance;
        return value;
    }
};

const Mock = struct {
    steps: []const Step,
    calls: usize = 0,
    bytes_read: u64 = 0,
    response_bytes: usize = 0,
    response_calls: usize = 0,
    response_calls_after_stop: usize = 0,
    aborted: usize = 0,
    cancelled: usize = 0,
    source_path: ?[]const u8 = null,
    clock: Clock = .{},
    token: core.http.CancellationToken = .{},
    provider: core.crypto.StdCryptoProvider = .init(io),

    fn client(self: *Mock) transfer.Client {
        return .{
            .allocator = allocator,
            .io = io,
            .runtime = .init(.{ .context = self, .vtable = &.{ .send = send, .open = open } }, self.provider.asProvider()),
            .budget = .{ .context = &self.clock, .nowMsFn = Clock.now, .deadline_ms = deadline_ms, .cancellation = &self.token },
        };
    }

    fn send(_: *anyopaque, _: *core.http.Request) !core.http.Response {
        return error.BufferedPathForbidden;
    }

    fn open(context: *anyopaque, request: *core.http.Request, options: core.http.OpenOptions) !*core.http.HttpOperation {
        const self: *Mock = @ptrCast(@alignCast(context));
        try testing.expect(self.calls < self.steps.len);
        const step = &self.steps[self.calls];
        self.calls += 1;
        try testing.expectEqual(step.method, request.method);
        try testing.expectEqualStrings(step.url, request.url);
        try testing.expect(!request.retryable);
        try testing.expectEqual(core.http.RedirectPolicy.not_allowed, request.redirect_policy);
        try testing.expect(request.operation_timeout_ms != null);
        try testing.expect(options.cancellation != null);
        try testing.expect(request.getHeader("Authorization") == null);
        for (step.request_headers) |header| {
            try testing.expectEqualStrings(header.value, request.getHeader(header.name) orelse return error.MissingFixtureHeader);
        }
        for (step.absent_headers) |name| try testing.expect(request.getHeader(name) == null);
        if (step.before) |callback| try callback(self);
        if (step.fail_open_after == 0) return error.SYNTHETIC_SECRET_should_never_be_rendered;
        var received: u64 = 0;
        var md5 = std.crypto.hash.Md5.init(.{});
        if (options.body) |body| {
            try testing.expectEqual(step.length, body.content_length.?);
            try testing.expect(!body.isReplayable());
            var buffer: [7001]u8 = undefined;
            while (true) {
                const count = try body.reader.readSliceShort(&buffer);
                if (count == 0) break;
                if (step.body) |expected| {
                    if (received + count > expected.len) return error.RequestBodyTooLong;
                    try testing.expectEqualSlices(u8, expected[@intCast(received)..][0..count], buffer[0..count]);
                }
                md5.update(buffer[0..count]);
                received += count;
                self.bytes_read += count;
                if (step.fail_open_after) |limit| if (received >= limit) return error.SYNTHETIC_SECRET_should_never_be_rendered;
                if (received > step.length) return error.RequestBodyTooLong;
            }
            if (received != step.length) return error.RequestBodyTooShort;
        } else if (request.body) |bytes| {
            received = bytes.len;
            try testing.expectEqual(step.length, received);
            md5.update(bytes);
        }
        if (step.verify_md5) {
            var encoded: [24]u8 = undefined;
            var hash: [16]u8 = undefined;
            md5.final(&hash);
            try testing.expectEqualStrings(
                std.base64.standard.Encoder.encode(&encoded, &hash),
                request.getHeader("Content-MD5").?,
            );
        }
        if (step.after) |callback| try callback(self);
        const op = try allocator.create(MockOperation);
        errdefer allocator.destroy(op);
        op.* = .{
            .mock = self,
            .step = step,
            .operation = undefined,
            .reader = .{ .vtable = &.{ .stream = MockOperation.stream }, .buffer = &.{}, .seek = 0, .end = 0 },
        };
        var headers = core.http.ResponseHeaders.init(allocator);
        errdefer headers.deinit();
        for (step.headers) |header| try headers.append(header.name, header.value);
        op.operation = .{
            .status_code = step.status,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .response_headers = headers,
            .body_reader = &op.reader,
            .finishFn = MockOperation.finish,
            .abortFn = MockOperation.abort,
            .cancelFn = MockOperation.cancel,
            .deinitFn = MockOperation.deinit,
        };
        return &op.operation;
    }
};

const MockOperation = struct {
    mock: *Mock,
    step: *const Step,
    operation: core.http.HttpOperation,
    reader: std.Io.Reader,
    offset: usize = 0,
    zero_progress_sent: bool = false,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *MockOperation = @alignCast(@fieldParentPtr("reader", reader));
        self.mock.response_calls += 1;
        if (self.mock.token.isCancelled() or self.mock.clock.now_ms >= deadline_ms) {
            self.mock.response_calls_after_stop += 1;
            return error.ReadFailed;
        }
        if (self.step.response_failure_after) |offset| if (self.offset >= offset) return error.ReadFailed;
        if (self.step.zero_progress_once and !self.zero_progress_sent) {
            self.zero_progress_sent = true;
            return 0;
        }
        if (self.offset == self.step.response.len) return error.EndOfStream;
        const wanted = @min(limit.minInt(self.step.fragment), self.step.response.len - self.offset);
        const count = try writer.write(self.step.response[self.offset..][0..wanted]);
        self.offset += count;
        self.mock.response_bytes += count;
        if (self.step.cancel_after_response) |offset| if (self.offset >= offset) self.mock.token.cancel();
        if (self.step.deadline_after_response) |offset| if (self.offset >= offset) {
            self.mock.clock.now_ms = deadline_ms;
        };
        return count;
    }
    fn finish(_: *core.http.HttpOperation) !void {
        return error.UnboundedFinishForbidden;
    }
    fn abort(operation: *core.http.HttpOperation) void {
        const self: *MockOperation = @alignCast(@fieldParentPtr("operation", operation));
        self.mock.aborted += 1;
    }
    fn cancel(operation: *core.http.HttpOperation) void {
        const self: *MockOperation = @alignCast(@fieldParentPtr("operation", operation));
        self.mock.cancelled += 1;
    }
    fn deinit(operation: *core.http.HttpOperation) void {
        const self: *MockOperation = @alignCast(@fieldParentPtr("operation", operation));
        self.operation.response_headers.deinit();
        self.operation.headers.deinit();
        allocator.destroy(self);
    }
};

const Fixture = struct {
    path: [:0]u8,
    dir: std.Io.Dir,
    name: []const u8,

    fn init(name: []const u8) !Fixture {
        try std.Io.Dir.cwd().createDir(io, name, .fromMode(0o700));
        errdefer std.Io.Dir.cwd().deleteDir(io, name) catch {};
        const dir = try std.Io.Dir.cwd().openDir(io, name, .{ .follow_symlinks = false });
        errdefer dir.close(io);
        const path = try std.Io.Dir.cwd().realPathFileAlloc(io, name, allocator);
        return .{ .path = path, .dir = dir, .name = name };
    }
    fn deinit(self: Fixture) void {
        self.dir.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.name) catch {};
        allocator.free(self.path);
    }
    fn file(self: Fixture, name: []const u8, bytes: []const u8, mode: u32) ![]u8 {
        try self.dir.writeFile(io, .{ .sub_path = name, .data = bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(mode) } });
        const handle = try self.dir.openFile(io, name, .{});
        defer handle.close(io);
        // Creation applies umask; permission-refusal fixtures need exact modes.
        try handle.setPermissions(io, .fromMode(mode));
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.path, name });
    }
    fn input(self: Fixture, bytes: []const u8) !files.Input {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
        return .{ .path = try self.file("source", bytes, 0o600), .size = bytes.len, .sha256 = hash };
    }
    fn destination(self: Fixture) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/download", .{self.path});
    }
};

fn expectFailure(outcome: d.Outcome, category: d.Category, side_effect: d.Certainty, status: ?u16) !void {
    try testing.expectEqual(d.Completion.failed, outcome.completion);
    try testing.expectEqual(category, outcome.diagnostic.category);
    try testing.expectEqual(side_effect, outcome.side_effect);
    try testing.expectEqual(status, outcome.diagnostic.status);
}

test "native runtime is a real Core streaming transport" {
    var native = transfer.NativeRuntime.init(.{ .allocator = allocator, .io = io });
    defer native.deinit();
    try testing.expect(native.runtime().transport.vtable.open != null);
}

test "container create exact wire and no replay on conflict" {
    var mock: Mock = .{ .steps = &.{
        .{ .url = container_url, .request_headers = &.{.{ .name = "x-ms-version", .value = transfer.container_api_version }} },
        .{ .url = container_url, .status = 409, .response = "<Error><Code>ContainerAlreadyExists</Code><Message>private secret</Message></Error>", .zero_progress_once = true },
    } };
    var client = mock.client();
    try testing.expectEqual(d.Completion.complete, client.createContainer(account, "fixture", sas).completion);
    const rejected = client.createContainer(account, "fixture", sas);
    try expectFailure(rejected, .condition, .rejected, 409);
    try testing.expectEqual(d.ServiceCode.ContainerAlreadyExists, rejected.diagnostic.service.code.?);
    try testing.expectEqual(@as(usize, 2), mock.calls);
}

test "create-only block wire streams across uneven boundaries with MD5 and full SHA256" {
    const fixture = try Fixture.init("block-wire");
    defer fixture.deinit();
    const bytes = try allocator.alloc(u8, 4 * files.buffer_size + 127);
    defer allocator.free(bytes);
    for (bytes, 0..) |*byte, i| byte.* = @truncate(i * 13);
    const input = try fixture.input(bytes);
    defer allocator.free(input.path);
    var mock: Mock = .{ .steps = &.{.{
        .length = bytes.len,
        .body = bytes,
        .verify_md5 = true,
        .request_headers = &.{
            .{ .name = "If-None-Match", .value = "*" },
            .{ .name = "x-ms-blob-type", .value = "BlockBlob" },
            .{ .name = "x-ms-version", .value = transfer.block_api_version },
        },
    }} };
    var client = mock.client();
    const result = client.uploadBlock(blob, input);
    try testing.expectEqual(d.Completion.complete, result.completion);
    try testing.expectEqual(input.size, result.bytes_streamed);
    try testing.expectEqual(input.size, result.bytes_accepted);
    try testing.expectEqualSlices(u8, &input.sha256, &result.sha256.?);
    try testing.expectEqual(@as(usize, 1), mock.calls);
}

test "transport entry is unknown even at zero bytes and after partial body" {
    const fixture = try Fixture.init("unknown-upload");
    defer fixture.deinit();
    const bytes = [_]u8{0x5a} ** 32768;
    const input = try fixture.input(&bytes);
    defer allocator.free(input.path);
    for ([_]usize{ 0, 7001 }) |failure| {
        var mock: Mock = .{ .steps = &.{.{ .length = bytes.len, .fail_open_after = failure }} };
        var client = mock.client();
        const result = client.uploadBlock(blob, input);
        try expectFailure(result, .transport, .unknown, null);
        try testing.expectEqual(@as(usize, 1), mock.calls);
        if (failure == 0) try testing.expectEqual(@as(u64, 0), result.bytes_streamed);
    }
}

test "known conditional rejection survives failed error body and secret redaction" {
    const fixture = try Fixture.init("condition-redaction");
    defer fixture.deinit();
    const input = try fixture.input("synthetic");
    defer allocator.free(input.path);
    var mock: Mock = .{ .steps = &.{.{
        .length = input.size,
        .status = 412,
        .headers = &.{.{ .name = "x-ms-error-code", .value = "ConditionNotMet" }},
        .response = "SYNTHETIC_SECRET https://private.blob.core.windows.net/private?sig=SYNTHETIC_SECRET",
        .response_failure_after = 0,
    }} };
    var client = mock.client();
    const result = client.uploadBlock(blob, input);
    try expectFailure(result, .condition, .rejected, 412);
    try testing.expectEqual(d.MetadataState.malformed, result.diagnostic.service.body);
    var text: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&text);
    try result.write(&writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "SYNTHETIC_SECRET") == null);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "https") == null);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "sig=") == null);
}

test "header XML JSON absent unknown malformed and conflicting metadata are explicit" {
    const cases = [_]struct { headers: []const Header, body: []const u8, state: d.MetadataState, code: ?d.ServiceCode = null }{
        .{ .headers = &.{}, .body = "", .state = .absent },
        .{ .headers = &.{.{ .name = "x-ms-error-code", .value = "BlobNotFound" }}, .body = "", .state = .known, .code = .BlobNotFound },
        .{ .headers = &.{}, .body = "<?xml version=\"1.0\"?><Error><Code>AuthorizationSourceIPMismatch</Code><Message>PRIVATE</Message></Error>", .state = .known, .code = .AuthorizationSourceIPMismatch },
        .{ .headers = &.{}, .body = "{\"error\":{\"code\":\"AuthenticationFailed\",\"message\":\"PRIVATE\"}}", .state = .known, .code = .AuthenticationFailed },
        .{ .headers = &.{}, .body = "{\"code\":\"NewServiceCode\",\"message\":\"PRIVATE\"}", .state = .unknown },
        .{ .headers = &.{.{ .name = "x-ms-error-code", .value = "BlobNotFound" }}, .body = "{\"code\":\"ContainerNotFound\"}", .state = .conflicting },
        .{ .headers = &.{ .{ .name = "x-ms-error-code", .value = "BlobNotFound" }, .{ .name = "X-MS-ERROR-CODE", .value = "ContainerNotFound" } }, .body = "", .state = .conflicting },
        .{ .headers = &.{}, .body = "{\"code\":\"BlobNotFound\",\"code\":\"BlobNotFound\"}", .state = .malformed },
        .{ .headers = &.{}, .body = "<Error><Message><Code>BlobNotFound</Code></Message></Error>", .state = .absent },
        .{ .headers = &.{}, .body = "<Error><Code>BlobNotFound</Code><Code>ContainerNotFound</Code></Error>", .state = .conflicting },
        .{ .headers = &.{}, .body = "<!DOCTYPE Error [<!ENTITY x SYSTEM 'private'>]><Error><Code>&x;</Code></Error>", .state = .malformed },
        .{ .headers = &.{.{ .name = "x-ms-error-code", .value = "sig=PRIVATE" }}, .body = "", .state = .malformed },
        .{ .headers = &.{}, .body = "<Error><Code>BlobNotFound</Oops></Error>", .state = .malformed },
    };
    for (cases) |case| {
        var operation: core.http.HttpOperation = undefined;
        operation.headers = std.StringHashMap([]const u8).init(allocator);
        defer operation.headers.deinit();
        operation.response_headers = core.http.ResponseHeaders.init(allocator);
        defer operation.response_headers.deinit();
        for (case.headers) |header| try operation.response_headers.append(header.name, header.value);
        const result = d.extract(&operation, case.body, false);
        try testing.expectEqual(case.state, result.state);
        try testing.expectEqual(case.code, result.code);
    }
}

test "redirect is returned without following and error bodies are capped" {
    const huge = [_]u8{'X'} ** (d.max_error_body + 4000);
    var mock: Mock = .{ .steps = &.{.{
        .url = container_url,
        .status = 307,
        .headers = &.{.{ .name = "Location", .value = "https://forbidden.invalid/?sig=PRIVATE" }},
        .response = &huge,
    }} };
    var client = mock.client();
    const result = client.createContainer(account, "fixture", sas);
    try expectFailure(result, .redirect, .rejected, 307);
    try testing.expectEqual(@as(usize, d.max_error_body + 1), mock.response_bytes);
    try testing.expectEqual(@as(usize, 1), mock.calls);
    try testing.expectEqual(d.MetadataState.malformed, result.diagnostic.service.body);
}

fn shrink(mock: *Mock) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, mock.source_path.?, .{ .mode = .write_only });
    defer file.close(io);
    try file.setLength(io, 1);
}
fn grow(mock: *Mock) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, mock.source_path.?, .{ .mode = .write_only });
    defer file.close(io);
    const length = (try file.stat(io)).size;
    try file.writePositionalAll(io, "X", length);
}
fn replaceBytes(mock: *Mock) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, mock.source_path.?, .{ .mode = .write_only });
    defer file.close(io);
    try file.writePositionalAll(io, "changed!!", 0);
}
fn cancel(mock: *Mock) !void {
    mock.token.cancel();
}

fn expire(mock: *Mock) !void {
    mock.clock.now_ms = deadline_ms;
}

test "short growing or modified input never becomes successful" {
    for ([_]*const fn (*Mock) anyerror!void{ shrink, grow, replaceBytes }) |mutate| {
        const fixture = try Fixture.init("mutating-input");
        defer fixture.deinit();
        const input = try fixture.input("synthetic");
        defer allocator.free(input.path);
        var mock: Mock = .{ .source_path = input.path, .steps = &.{.{ .length = input.size, .before = mutate }} };
        var client = mock.client();
        const result = client.uploadBlock(blob, input);
        try testing.expectEqual(d.Completion.failed, result.completion);
        try testing.expectEqual(@as(usize, 1), mock.calls);
        try testing.expect(result.side_effect == .unknown or result.side_effect == .accepted);
    }
}

test "post-upload modification preserves accepted status separately from failed validation" {
    const fixture = try Fixture.init("post-upload-change");
    defer fixture.deinit();
    const input = try fixture.input("synthetic");
    defer allocator.free(input.path);
    var mock: Mock = .{ .source_path = input.path, .steps = &.{.{ .length = input.size, .after = grow }} };
    var client = mock.client();
    const result = client.uploadBlock(blob, input);
    try expectFailure(result, .input_changed, .accepted, 201);
    try testing.expectEqual(input.size, result.bytes_accepted);
}

test "deadline cancellation before mutation and after accepted response" {
    var mock: Mock = .{ .steps = &.{} };
    var client = mock.client();
    client.budget.deadline_ms = 0;
    try expectFailure(client.createContainer(account, "fixture", sas), .deadline, .not_started, null);
    try testing.expectEqual(@as(usize, 0), mock.calls);
    client.budget.deadline_ms = 100;
    mock.token.cancel();
    try expectFailure(client.createContainer(account, "fixture", sas), .cancelled, .not_started, null);
    var after: Mock = .{ .steps = &.{.{ .url = container_url, .after = cancel }} };
    var after_client = after.client();
    try expectFailure(after_client.createContainer(account, "fixture", sas), .cancelled, .accepted, 201);
}

test "bounded download private exclusive file exact hash and integrity" {
    const fixture = try Fixture.init("download-ok");
    defer fixture.deinit();
    const destination = try fixture.destination();
    defer allocator.free(destination);
    const bytes = "bounded synthetic download";
    var md5: [16]u8 = undefined;
    var md5_text: [24]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &md5, .{});
    const md5_value = std.base64.standard.Encoder.encode(&md5_text, &md5);
    var mock: Mock = .{ .steps = &.{.{
        .method = .GET,
        .status = 200,
        .response = bytes,
        .fragment = 3,
        .zero_progress_once = true,
        .headers = &.{ .{ .name = "Content-Length", .value = "26" }, .{ .name = "Content-MD5", .value = md5_value } },
    }} };
    var client = mock.client();
    const result = client.downloadBlob(blob, .{ .path = destination, .maximum = bytes.len });
    try testing.expectEqual(d.Completion.complete, result.completion);
    try testing.expectEqual(@as(u64, bytes.len), result.bytes_downloaded);
    const actual = try files.readPrivate(allocator, io, destination, bytes.len);
    defer allocator.free(actual);
    try testing.expectEqualStrings(bytes, actual);
    const existing = client.downloadBlob(blob, .{ .path = destination, .maximum = bytes.len });
    try testing.expectEqual(d.Completion.failed, existing.completion);
    try testing.expectEqual(@as(usize, 1), mock.calls);
}

test "download excess short body integrity and midstream failures remove only owned partial" {
    const cases = [_]struct { response: []const u8, maximum: u64, headers: []const Header = &.{}, failure: ?usize = null, category: d.Category }{
        .{ .response = "123456", .maximum = 5, .category = .response_limit },
        .{ .response = "123", .maximum = 5, .headers = &.{.{ .name = "Content-Length", .value = "5" }}, .category = .malformed_response },
        .{ .response = "12345", .maximum = 5, .headers = &.{.{ .name = "Content-MD5", .value = "AAAAAAAAAAAAAAAAAAAAAA==" }}, .category = .integrity },
        .{ .response = "12345", .maximum = 5, .failure = 2, .category = .transport },
        .{ .response = "123", .maximum = 5, .headers = &.{.{ .name = "Content-Length", .value = "999" }}, .category = .malformed_response },
        .{ .response = "123", .maximum = 5, .headers = &.{ .{ .name = "Content-Length", .value = "3" }, .{ .name = "content-length", .value = "4" } }, .category = .malformed_response },
        .{ .response = "123", .maximum = 5, .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }}, .category = .malformed_response },
    };
    for (cases) |case| {
        const fixture = try Fixture.init("download-fail");
        defer fixture.deinit();
        const destination = try fixture.destination();
        defer allocator.free(destination);
        var mock: Mock = .{ .steps = &.{.{
            .method = .GET,
            .status = 200,
            .response = case.response,
            .headers = case.headers,
            .response_failure_after = case.failure,
            .fragment = 1,
        }} };
        var client = mock.client();
        const result = client.downloadBlob(blob, .{ .path = destination, .maximum = case.maximum });
        try expectFailure(result, case.category, .not_applicable, 200);
        try testing.expect(!result.cleanup_failed);
        try testing.expectError(error.FileNotFound, fixture.dir.statFile(io, "download", .{}));
        try testing.expect(mock.response_bytes <= case.maximum + 1);
    }
}

test "managed disk page wire alignment chunk boundary SHA256 and footer readback" {
    const fixture = try Fixture.init("page-wire");
    defer fixture.deinit();
    const bytes = try allocator.alloc(u8, transfer.page_chunk_size + 512);
    defer allocator.free(bytes);
    for (bytes, 0..) |*byte, i| byte.* = @truncate(i * 17);
    const input = try fixture.input(bytes);
    defer allocator.free(input.path);
    const footer = bytes[transfer.page_chunk_size..];
    var md5: [16]u8 = undefined;
    var encoded: [24]u8 = undefined;
    std.crypto.hash.Md5.hash(footer, &md5, .{});
    const steps = [_]Step{
        .{ .url = disk_url ++ "&comp=page", .length = transfer.page_chunk_size, .body = bytes[0..transfer.page_chunk_size], .verify_md5 = true, .request_headers = &.{ .{ .name = "x-ms-version", .value = "2020-10-02" }, .{ .name = "x-ms-range", .value = "bytes=0-4194303" }, .{ .name = "x-ms-page-write", .value = "update" } }, .absent_headers = &.{ "x-ms-blob-type", "If-None-Match" } },
        .{ .url = disk_url ++ "&comp=page", .length = 512, .body = footer, .verify_md5 = true, .request_headers = &.{.{ .name = "x-ms-range", .value = "bytes=4194304-4194815" }} },
        .{ .method = .GET, .url = disk_url, .status = 206, .response = footer, .zero_progress_once = true, .request_headers = &.{ .{ .name = "x-ms-range", .value = "bytes=4194304-4194815" }, .{ .name = "x-ms-range-get-content-md5", .value = "true" } }, .headers = &.{ .{ .name = "Content-Length", .value = "512" }, .{ .name = "Content-Range", .value = "bytes 4194304-4194815/4194816" }, .{ .name = "Content-MD5", .value = std.base64.standard.Encoder.encode(&encoded, &md5) } } },
    };
    var mock: Mock = .{ .steps = &steps };
    var client = mock.client();
    const result = client.uploadPages(disk, input);
    try testing.expectEqual(d.Completion.complete, result.completion);
    try testing.expectEqual(input.size, result.bytes_streamed);
    try testing.expectEqual(input.size, result.bytes_accepted);
    try testing.expectEqualSlices(u8, &input.sha256, &result.sha256.?);
    try testing.expect(result.footer_sha256 != null);
    try testing.expectEqual(@as(usize, 3), mock.calls);
}

test "managed disk partial known rejection and unknown later update never replay" {
    const fixture = try Fixture.init("page-incomplete");
    defer fixture.deinit();
    const bytes = try allocator.alloc(u8, transfer.page_chunk_size + 512);
    defer allocator.free(bytes);
    @memset(bytes, 0x71);
    const input = try fixture.input(bytes);
    defer allocator.free(input.path);
    for ([_]bool{ false, true }) |unknown| {
        var mock: Mock = .{ .steps = &.{
            .{ .url = disk_url ++ "&comp=page", .length = transfer.page_chunk_size },
            .{ .url = disk_url ++ "&comp=page", .length = 512, .status = 412, .fail_open_after = if (unknown) 0 else null },
        } };
        var client = mock.client();
        const result = client.uploadPages(disk, input);
        try expectFailure(result, if (unknown) .transport else .condition, if (unknown) .unknown else .incomplete, if (unknown) null else 412);
        try testing.expectEqual(@as(u64, transfer.page_chunk_size), result.bytes_accepted);
        try testing.expectEqual(@as(usize, 2), mock.calls);
    }
}

test "footer mismatch keeps accepted page updates and actual readback status" {
    const fixture = try Fixture.init("footer-mismatch");
    defer fixture.deinit();
    const bytes = [_]u8{0x7a} ** 512;
    const wrong = [_]u8{0x79} ** 512;
    const input = try fixture.input(&bytes);
    defer allocator.free(input.path);
    var md5: [16]u8 = undefined;
    var encoded: [24]u8 = undefined;
    std.crypto.hash.Md5.hash(&wrong, &md5, .{});
    var mock: Mock = .{ .steps = &.{
        .{ .url = disk_url ++ "&comp=page", .length = 512 },
        .{ .method = .GET, .url = disk_url, .status = 206, .response = &wrong, .headers = &.{ .{ .name = "Content-Length", .value = "512" }, .{ .name = "Content-Range", .value = "bytes 0-511/512" }, .{ .name = "Content-MD5", .value = std.base64.standard.Encoder.encode(&encoded, &md5) } } },
    } };
    var client = mock.client();
    try expectFailure(client.uploadPages(disk, input), .footer_mismatch, .accepted, 206);
}

const good_request =
    \\{"schema":"unikraft.hyperv.private-preflight-blob-worker","schema_version":1,"action":"upload","account_url":"https://synthetic.blob.core.windows.net","container":"fixture","files":[{"blob":"input","path":"/synthetic/input","size":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],"create_container":true}
;

test "strict request duplicate fields unknown fields bool float overflow and nesting" {
    var parsed = try contract.Request.parse(allocator, good_request);
    defer parsed.deinit();
    try testing.expectEqual(contract.Action.upload, parsed.action);
    const changes = [_][2][]const u8{
        .{ "\"schema_version\":1", "\"schema_version\":true" },
        .{ "\"schema_version\":1", "\"schema_version\":1.0" },
        .{ "\"schema_version\":1", "\"schema_version\":1e0" },
        .{ "\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1" },
        .{ "\"schema_version\":1", "\"schema_version\":1,\"unexpected\":false" },
        .{ "\"size\":0", "\"size\":false" },
        .{ "\"size\":0", "\"size\":-1" },
        .{ "\"size\":0", "\"size\":18446744073709551616" },
        .{ "\"size\":0", "\"size\":268435457" },
        .{ "\"blob\":\"input\"", "\"blob\":\"../input\"" },
        .{ "\"path\":\"/synthetic/input\"", "\"path\":\"relative\"" },
        .{ "\"action\":\"upload\"", "\"action\":\"delete\"" },
        .{ "\"account_url\":\"https://synthetic.blob.core.windows.net\"", "\"account_url\":\"https://synthetic.blob.core.windows.net.evil.invalid\"" },
    };
    for (changes) |change| {
        const raw = try std.mem.replaceOwned(u8, allocator, good_request, change[0], change[1]);
        defer allocator.free(raw);
        try testing.expectError(error.InvalidContract, contract.Request.parse(allocator, raw));
    }
    try testing.expectError(error.InvalidContract, contract.Request.parse(allocator, "[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]"));
}

test "private request and SAS files refuse symlink public mode directory and oversize" {
    const fixture = try Fixture.init("request-files");
    defer fixture.deinit();
    const request_path = try fixture.file("request", good_request, 0o600);
    defer allocator.free(request_path);
    var request = try contract.Request.load(allocator, io, request_path);
    defer request.deinit();
    const sas_path = try fixture.file("sas", sas, 0o600);
    defer allocator.free(sas_path);
    const token = try contract.loadSas(allocator, io, sas_path);
    defer {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    }
    try testing.expectEqualStrings(sas, token);
    const public = try fixture.file("public", good_request, 0o644);
    defer allocator.free(public);
    try testing.expectError(error.UnsafeFile, contract.Request.load(allocator, io, public));
    try fixture.dir.symLink(io, "request", "link", .{});
    const link = try std.fmt.allocPrint(allocator, "{s}/link", .{fixture.path});
    defer allocator.free(link);
    try testing.expectError(error.SymLinkLoop, contract.Request.load(allocator, io, link));
    try testing.expectError(error.UnsafeFile, files.readPrivate(allocator, io, fixture.path, 100));
    try testing.expectError(error.UnsafeFile, files.readPrivate(allocator, io, request_path, 1));
}

test "bad endpoints protocol injection geometry and hash refuse transport" {
    const fixture = try Fixture.init("refused-contracts");
    defer fixture.deinit();
    const input = try fixture.input("synthetic");
    defer allocator.free(input.path);
    var mock: Mock = .{ .steps = &.{} };
    var client = mock.client();
    var wrong_hash = input;
    wrong_hash.sha256[0] ^= 1;
    try expectFailure(client.uploadBlock(blob, wrong_hash), .input_changed, .not_started, null);
    try expectFailure(client.uploadPages(disk, input), .invalid_contract, .not_started, null);
    for ([_][]const u8{
        "http://fixture.blob.core.windows.net/c/b",
        "https://fixture.blob.core.windows.net.evil.invalid/c/b",
        "https://user@fixture.blob.core.windows.net/c/b",
        "https://fixture.blob.core.windows.net:444/c/b",
        "https://fixture.blob.core.windows.net/c/b?sig=x",
        "https://fixture.blob.core.windows.net/c/b#x",
        "https://fixture.blob.core.windows.net/c/../b",
    }) |endpoint| {
        try testing.expectError(error.InvalidContract, contract.diskUri(allocator, endpoint, sas));
    }
    for ([_][]const u8{ "sig=x&comp=page", "sig=x&sig=y", "sig=x\n", "?sig=x", "sig=%GG", "sig=" }) |bad_sas| {
        try testing.expect(!contract.validSas(bad_sas));
    }
    try testing.expectEqual(@as(usize, 0), mock.calls);
}

test "private worker executes strict empty block batch and preserves created container on unknown" {
    const fixture = try Fixture.init("private-worker");
    defer fixture.deinit();
    const input = try fixture.input("");
    defer allocator.free(input.path);
    const raw = try std.mem.replaceOwned(u8, allocator, good_request, "/synthetic/input", input.path);
    defer allocator.free(raw);
    const request_path = try fixture.file("request", raw, 0o600);
    defer allocator.free(request_path);
    const sas_path = try fixture.file("sas", sas, 0o600);
    defer allocator.free(sas_path);
    for ([_]bool{ false, true }) |unknown| {
        var mock: Mock = .{ .steps = &.{
            .{ .url = container_url },
            .{ .length = 0, .verify_md5 = true, .fail_open_after = if (unknown) 0 else null, .request_headers = &.{
                .{ .name = "If-None-Match", .value = "*" },
                .{ .name = "Content-Length", .value = "0" },
                .{ .name = "Content-MD5", .value = "1B2M2Y8AsgTpgAmY7PhCfg==" },
            } },
        } };
        var client = mock.client();
        const result = client.executePrivate(request_path, sas_path);
        if (unknown) {
            try expectFailure(result, .transport, .unknown, null);
        } else {
            try testing.expectEqual(d.Completion.complete, result.completion);
            try testing.expectEqual(d.Certainty.accepted, result.side_effect);
        }
        try testing.expectEqual(@as(usize, 2), mock.calls);
        try testing.expectEqual(@as(u64, 0), result.bytes_streamed);
    }
}

test "worker validates all record contracts before first container mutation" {
    const fixture = try Fixture.init("invalid-batch");
    defer fixture.deinit();
    const bad = try std.mem.replaceOwned(u8, allocator, good_request, "\"size\":0", "\"size\":true");
    defer allocator.free(bad);
    const path = try fixture.file("request", bad, 0o600);
    defer allocator.free(path);
    var mock: Mock = .{ .steps = &.{} };
    var client = mock.client();
    const result = client.executePrivate(path, "/unread/sas");
    try expectFailure(result, .invalid_contract, .not_started, null);
    try testing.expectEqual(d.Stage.request_file, result.diagnostic.stage);
    try testing.expectEqual(@as(usize, 0), mock.calls);
}

test "FIFO symlink ancestor wrong size and nonprivate output directory refuse without transport" {
    const fixture = try Fixture.init("unsafe-files");
    defer fixture.deinit();
    const input = try fixture.input("fixture");
    defer allocator.free(input.path);
    var wrong_size = input;
    wrong_size.size += 1;
    var mock: Mock = .{ .steps = &.{} };
    var client = mock.client();
    try expectFailure(client.uploadBlock(blob, wrong_size), .input_changed, .not_started, null);
    try testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.mknodat(
        fixture.dir.handle,
        "fifo",
        std.os.linux.S.IFIFO | 0o600,
        0,
    )));
    const fifo = try std.fmt.allocPrint(allocator, "{s}/fifo", .{fixture.path});
    defer allocator.free(fifo);
    try testing.expectError(error.UnsafeFile, files.openRegular(io, fifo, true));
    try fixture.dir.createDir(io, "nested", .fromMode(0o700));
    try fixture.dir.symLink(io, "nested", "alias", .{ .is_directory = true });
    const alias = try std.fmt.allocPrint(allocator, "{s}/alias/input", .{fixture.path});
    defer allocator.free(alias);
    if (files.Parent.open(io, alias, false)) |parent| {
        parent.close(io);
        return error.SymlinkAncestorWasAccepted;
    } else |_| {}
    try fixture.dir.createDir(io, "public", .fromMode(0o755));
    {
        const directory = try fixture.dir.openDir(io, "public", .{ .follow_symlinks = false, .iterate = true });
        defer directory.close(io);
        try directory.setPermissions(io, .fromMode(0o755));
    }
    const public = try std.fmt.allocPrint(allocator, "{s}/public/output", .{fixture.path});
    defer allocator.free(public);
    try expectFailure(client.downloadBlob(blob, .{ .path = public, .maximum = 100 }), .unsafe_file, .not_started, null);
    try testing.expectEqual(@as(usize, 0), mock.calls);
}

test "fragmented downloads stop reader calls immediately on cancellation or deadline" {
    const fixture = try Fixture.init("download-cancel");
    defer fixture.deinit();
    const destination = try fixture.destination();
    defer allocator.free(destination);
    const bytes = [_]u8{0x41} ** 32768;
    for ([_]bool{ false, true }) |timed| {
        var mock: Mock = .{ .steps = &.{.{
            .method = .GET,
            .status = 200,
            .response = &bytes,
            .fragment = 1,
            .cancel_after_response = if (timed) null else 1,
            .deadline_after_response = if (timed) 1 else null,
        }} };
        var client = mock.client();
        const result = client.downloadBlob(blob, .{ .path = destination, .maximum = bytes.len });
        try testing.expectEqual(@as(usize, 0), mock.response_calls_after_stop);
        try testing.expectEqual(@as(usize, 1), mock.response_calls);
        try testing.expectEqual(@as(usize, 1), mock.response_bytes);
        try expectFailure(result, if (timed) .deadline else .cancelled, .not_applicable, 200);
        try testing.expectError(error.FileNotFound, fixture.dir.statFile(io, "download", .{}));
        try testing.expectEqual(@as(usize, 1), mock.cancelled);
    }
    var empty: Mock = .{ .steps = &.{.{ .method = .GET, .status = 200, .response = "" }} };
    var empty_client = empty.client();
    const result = empty_client.downloadBlob(blob, .{ .path = destination, .maximum = 0 });
    try testing.expectEqual(d.Completion.complete, result.completion);
    try testing.expectEqual(@as(u64, 0), result.bytes_downloaded);
}

test "fragmented footer stops reader calls immediately on cancellation or deadline" {
    const fixture = try Fixture.init("footer-stop");
    defer fixture.deinit();
    const bytes = [_]u8{0x58} ** 512;
    const input = try fixture.input(&bytes);
    defer allocator.free(input.path);
    var md5: [16]u8 = undefined;
    var encoded: [24]u8 = undefined;
    std.crypto.hash.Md5.hash(&bytes, &md5, .{});
    const md5_text = std.base64.standard.Encoder.encode(&encoded, &md5);
    for ([_]bool{ false, true }) |timed| {
        var mock: Mock = .{ .steps = &.{
            .{ .url = disk_url ++ "&comp=page", .length = 512 },
            .{
                .method = .GET,
                .url = disk_url,
                .status = 206,
                .response = &bytes,
                .fragment = 1,
                .cancel_after_response = if (timed) null else 1,
                .deadline_after_response = if (timed) 1 else null,
                .headers = &.{
                    .{ .name = "Content-Length", .value = "512" },
                    .{ .name = "Content-Range", .value = "bytes 0-511/512" },
                    .{ .name = "Content-MD5", .value = md5_text },
                },
            },
        } };
        var client = mock.client();
        const result = client.uploadPages(disk, input);
        try testing.expectEqual(@as(usize, 0), mock.response_calls_after_stop);
        try testing.expectEqual(@as(usize, 2), mock.response_calls);
        try testing.expectEqual(@as(usize, 1), mock.response_bytes);
        try expectFailure(result, if (timed) .deadline else .cancelled, .accepted, 206);
        try testing.expectEqual(d.Stage.footer_readback, result.diagnostic.stage);
        try testing.expectEqual(@as(u64, 512), result.bytes_accepted);
        try testing.expectEqual(@as(usize, 1), mock.cancelled);
    }
}

test "fragmented error extraction stops reader calls without losing rejection certainty" {
    for ([_]bool{ false, true }) |timed| {
        var mock: Mock = .{ .steps = &.{.{
            .url = container_url,
            .status = 403,
            .headers = &.{.{ .name = "x-ms-error-code", .value = "AuthorizationFailure" }},
            .response = "<Error><Code>AuthorizationFailure</Code><Message>private</Message></Error>",
            .fragment = 1,
            .cancel_after_response = if (timed) null else 1,
            .deadline_after_response = if (timed) 1 else null,
        }} };
        var client = mock.client();
        const result = client.createContainer(account, "fixture", sas);
        try testing.expectEqual(@as(usize, 0), mock.response_calls_after_stop);
        try testing.expectEqual(@as(usize, 1), mock.response_calls);
        try testing.expectEqual(@as(usize, 1), mock.response_bytes);
        try expectFailure(result, .authorization, .rejected, 403);
        try testing.expectEqual(d.MetadataState.known, result.diagnostic.service.header);
        try testing.expectEqual(d.MetadataState.malformed, result.diagnostic.service.body);
        try testing.expectEqual(@as(usize, 1), mock.cancelled);
    }
}

test "page deadline at transport entry is unknown and growing source stays accepted but fails verification" {
    const fixture = try Fixture.init("page-local-failure");
    defer fixture.deinit();
    const bytes = [_]u8{0x6b} ** 512;
    const input = try fixture.input(&bytes);
    defer allocator.free(input.path);
    var timed: Mock = .{ .steps = &.{.{ .url = disk_url ++ "&comp=page", .length = 512, .before = expire }} };
    var timed_client = timed.client();
    try expectFailure(timed_client.uploadPages(disk, input), .deadline, .unknown, null);
    try testing.expectEqual(@as(usize, 1), timed.calls);
    var growing: Mock = .{ .source_path = input.path, .steps = &.{.{ .url = disk_url ++ "&comp=page", .length = 512, .after = grow }} };
    var growing_client = growing.client();
    const result = growing_client.uploadPages(disk, input);
    try expectFailure(result, .input_changed, .accepted, null);
    try testing.expectEqual(@as(u64, 512), result.bytes_accepted);
    try testing.expectEqual(@as(usize, 1), growing.calls);
}

test "accepted response body failure and unexpected 2xx do not erase status or side effects" {
    for ([_]Step{
        .{ .url = container_url, .status = 202 },
        .{ .url = container_url, .status = 201, .response_failure_after = 0 },
        .{ .url = container_url, .status = 201, .response = "unexpected private response" },
        .{ .url = container_url, .status = 201, .response = "unexpected private response", .zero_progress_once = true },
    }) |step| {
        var mock: Mock = .{ .steps = &.{step} };
        var client = mock.client();
        const result = client.createContainer(account, "fixture", sas);
        try testing.expectEqual(d.Completion.failed, result.completion);
        try testing.expectEqual(d.Certainty.accepted, result.side_effect);
        try testing.expectEqual(@as(?u16, step.status), result.diagnostic.status);
        try testing.expectEqual(@as(usize, 1), mock.calls);
    }
}

test "buffered-only runtime is refused before transport" {
    var mock: Mock = .{ .steps = &.{} };
    var client = mock.client();
    client.runtime.transport.vtable = &.{ .send = Mock.send };
    try expectFailure(client.createContainer(account, "fixture", sas), .invalid_contract, .not_started, null);
    try testing.expectEqual(@as(usize, 0), mock.calls);
}

test "footer refuses missing integrity wrong range excess and truncated data" {
    const fixture = try Fixture.init("footer-contracts");
    defer fixture.deinit();
    const bytes = [_]u8{0x68} ** 512;
    const extra = [_]u8{0x68} ** 513;
    const input = try fixture.input(&bytes);
    defer allocator.free(input.path);
    var md5: [16]u8 = undefined;
    var encoded: [24]u8 = undefined;
    std.crypto.hash.Md5.hash(&bytes, &md5, .{});
    const md5_text = std.base64.standard.Encoder.encode(&encoded, &md5);
    const cases = [_]struct { md5: bool = true, range: []const u8 = "bytes 0-511/512", response: []const u8, category: d.Category }{
        .{ .md5 = false, .response = &bytes, .category = .integrity },
        .{ .range = "bytes 512-1023/1024", .response = &bytes, .category = .malformed_response },
        .{ .response = &extra, .category = .response_limit },
        .{ .response = bytes[0..511], .category = .malformed_response },
    };
    for (cases) |case| {
        var headers = [_]Header{
            .{ .name = "Content-Length", .value = "512" },
            .{ .name = "Content-Range", .value = case.range },
            .{ .name = "Content-MD5", .value = md5_text },
        };
        var mock: Mock = .{ .steps = &.{
            .{ .url = disk_url ++ "&comp=page", .length = 512 },
            .{ .method = .GET, .url = disk_url, .status = 206, .response = case.response, .headers = headers[0..@as(usize, if (case.md5) 3 else 2)] },
        } };
        var client = mock.client();
        try expectFailure(client.uploadPages(disk, input), case.category, .accepted, 206);
        try testing.expectEqual(@as(usize, 2), mock.calls);
    }
}

test "managed disk private worker binds strict geometry hash and separate SAS channel" {
    const fixture = try Fixture.init("disk-private-worker");
    defer fixture.deinit();
    const bytes = [_]u8{0x4d} ** 512;
    const input = try fixture.input(&bytes);
    defer allocator.free(input.path);
    const hash = std.fmt.bytesToHex(input.sha256, .lower);
    const raw = try std.fmt.allocPrint(
        allocator,
        "{{\"schema\":\"{s}\",\"schema_version\":1,\"endpoint\":\"{s}\",\"path\":\"{s}\",\"size\":512,\"sha256\":\"{s}\"}}",
        .{ contract.disk_schema, disk_endpoint, input.path, hash },
    );
    defer allocator.free(raw);
    const request_path = try fixture.file("request", raw, 0o600);
    defer allocator.free(request_path);
    const sas_path = try fixture.file("sas", sas, 0o600);
    defer allocator.free(sas_path);
    var md5: [16]u8 = undefined;
    var encoded: [24]u8 = undefined;
    std.crypto.hash.Md5.hash(&bytes, &md5, .{});
    var mock: Mock = .{ .steps = &.{
        .{ .url = disk_url ++ "&comp=page", .length = 512, .verify_md5 = true },
        .{ .method = .GET, .url = disk_url, .status = 206, .response = &bytes, .headers = &.{
            .{ .name = "Content-Length", .value = "512" },
            .{ .name = "Content-Range", .value = "bytes 0-511/512" },
            .{ .name = "Content-MD5", .value = std.base64.standard.Encoder.encode(&encoded, &md5) },
        } },
    } };
    var client = mock.client();
    try testing.expectEqual(d.Completion.complete, client.uploadPagesPrivate(request_path, sas_path).completion);
    for ([_][2][]const u8{
        .{ "\"size\":512", "\"size\":511" },
        .{ "\"size\":512", "\"size\":512.0" },
        .{ "\"size\":512", "\"size\":true" },
        .{ "\"size\":512", "\"size\":4294968320" },
        .{ "\"size\":512", "\"size\":512,\"sas\":\"not-in-the-request\"" },
    }) |change| {
        const bad = try std.mem.replaceOwned(u8, allocator, raw, change[0], change[1]);
        defer allocator.free(bad);
        try testing.expectError(error.InvalidContract, contract.DiskRequest.parse(allocator, bad));
    }
}
