const std = @import("std");
const core = @import("azure_sdk_core");
const common = @import("azure_sdk_storage_common");
const d = @import("diagnostic.zig");
const files = @import("files.zig");
const contract = @import("request.zig");

pub const block_api_version = "2024-11-04";
pub const container_api_version = "2024-11-04";
pub const download_api_version = "2024-11-04";
pub const page_api_version = "2020-10-02";
pub const page_chunk_size = 4 * 1024 * 1024;
pub const maximum_disk_bytes = contract.maximum_disk_bytes;

pub const Budget = struct {
    context: *anyopaque,
    nowMsFn: *const fn (*anyopaque) anyerror!u64,
    deadline_ms: u64,
    cancellation: *const core.http.CancellationToken,

    pub fn check(self: *const Budget) !void {
        if (self.cancellation.isCancelled()) return error.Cancelled;
        if (try self.nowMsFn(self.context) >= self.deadline_ms) return error.Deadline;
    }

    pub fn guard(self: *Budget) files.Guard {
        return .{ .context = self, .checkFn = checkOpaque };
    }

    fn checkOpaque(context: *anyopaque) !void {
        const self: *Budget = @ptrCast(@alignCast(context));
        try self.check();
    }
};

/// A real Core native HTTPS runtime, not a fixture transport. The caller owns
/// trust-store configuration, its allocator and an independent worker deadline.
pub const NativeRuntime = struct {
    transport: core.http.StdHttpTransport,
    crypto: core.crypto.StdCryptoProvider,

    pub fn init(http_client: std.http.Client) NativeRuntime {
        return .{
            .transport = .initWithClient(http_client.allocator, http_client),
            .crypto = .init(http_client.io),
        };
    }

    pub fn runtime(self: *NativeRuntime) core.http.HttpRuntime {
        return .init(self.transport.asTransport(), self.crypto.asProvider());
    }

    pub fn deinit(self: *NativeRuntime) void {
        self.transport.deinit();
    }
};

pub const Blob = struct { account_url: []const u8, container: []const u8, name: []const u8, sas: []const u8 };
pub const Disk = struct { endpoint: []const u8, sas: []const u8 };
pub const Download = struct { path: []const u8, maximum: u64 };
pub const Event = union(enum) {
    begin: struct { stage: d.Stage, mutation: bool, bytes: u64 },
    end: struct { transport_started: bool, status: ?u16 },
};
pub const Observer = struct {
    context: *anyopaque,
    notifyFn: *const fn (*anyopaque, Event) anyerror!void,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runtime: core.http.HttpRuntime,
    budget: Budget,
    observer: ?Observer = null,

    pub fn createContainer(self: *Client, account: []const u8, container: []const u8, sas: []const u8) d.Outcome {
        var uri = contract.blobUri(self.allocator, account, container, null, sas) catch return d.Outcome.fail(.contract, .invalid_contract);
        defer eraseUri(&uri);
        const url = uri.appendProtocolQuery(self.allocator, &.{.{ .name = "restype", .value = "container" }}) catch return d.Outcome.fail(.container_create, .allocation);
        defer self.erase(url);
        var request = core.http.Request.init(self.allocator, .PUT, url);
        defer request.deinit();
        request.body = "";
        self.headers(&request, container_api_version, 0) catch return d.Outcome.fail(.container_create, .allocation);
        return self.mutation(&request, null, .container_create, 0);
    }

    pub fn uploadBlock(self: *Client, target: Blob, input: files.Input) d.Outcome {
        if (input.size > contract.maximum_file) return d.Outcome.fail(.contract, .invalid_contract);
        var uri = contract.blobUri(self.allocator, target.account_url, target.container, target.name, target.sas) catch return d.Outcome.fail(.contract, .invalid_contract);
        defer eraseUri(&uri);
        var source = files.SealedInput.open(self.io, input, self.budget.guard()) catch |err| return d.Outcome.fail(.input_hash, localCategory(err));
        defer source.close();
        var reader: files.InputReader = .{ .source = &source, .guard = self.budget.guard() };
        var request = core.http.Request.init(self.allocator, .PUT, uri.bytes);
        defer request.deinit();
        var encoded: [24]u8 = undefined;
        self.headers(&request, block_api_version, input.size) catch return d.Outcome.fail(.block_put, .allocation);
        request.setHeader("x-ms-blob-type", "BlockBlob") catch return d.Outcome.fail(.block_put, .allocation);
        request.setHeader("If-None-Match", "*") catch return d.Outcome.fail(.block_put, .allocation);
        request.setHeader("Content-MD5", std.base64.standard.Encoder.encode(&encoded, &source.fingerprint.md5)) catch return d.Outcome.fail(.block_put, .allocation);
        var outcome = self.mutation(&request, .knownLength(&reader.interface, input.size), .block_put, input.size);
        outcome.bytes_streamed = reader.offset;
        if (outcome.completion != .complete) {
            if (reader.failure) |err| outcome.diagnostic.category = localCategory(err);
            return outcome;
        }
        const streamed_hash = reader.sha.finalResult();
        if (reader.offset != input.size or !std.mem.eql(u8, &streamed_hash, &input.sha256)) {
            outcome.completion = .failed;
            outcome.diagnostic.stage = .input_verify;
            outcome.diagnostic.category = .input_changed;
            return outcome;
        }
        source.verify(self.budget.guard()) catch |err| {
            outcome.completion = .failed;
            outcome.diagnostic.stage = .input_verify;
            outcome.diagnostic.category = localCategory(err);
            return outcome;
        };
        outcome.sha256 = streamed_hash;
        return outcome;
    }

    pub fn downloadBlob(self: *Client, target: Blob, output: Download) d.Outcome {
        if (output.maximum > contract.maximum_file) return d.Outcome.fail(.contract, .invalid_contract);
        var uri = contract.blobUri(self.allocator, target.account_url, target.container, target.name, target.sas) catch return d.Outcome.fail(.contract, .invalid_contract);
        defer eraseUri(&uri);
        self.budget.check() catch |err| return d.Outcome.fail(.output_create, localCategory(err));
        const parent = files.Parent.open(self.io, output.path, .private) catch return d.Outcome.fail(.output_create, .unsafe_file);
        defer parent.close(self.io);
        const file = parent.dir().createFile(self.io, parent.name, .{
            .exclusive = true,
            .truncate = false,
            .permissions = .fromMode(0o600),
        }) catch return d.Outcome.fail(.output_create, .unsafe_file);
        defer file.close(self.io);
        var outcome = self.downloadToFile(uri.bytes, output.maximum, file);
        if (outcome.completion == .complete) {
            parent.sync(self.io) catch {
                outcome.completion = .failed;
                outcome.diagnostic.stage = .output_sync;
                outcome.diagnostic.category = .local_io;
            };
            if (outcome.completion == .complete) self.budget.check() catch |err| {
                outcome.completion = .failed;
                outcome.diagnostic.stage = .output_sync;
                outcome.diagnostic.category = localCategory(err);
            };
        }
        if (outcome.completion != .complete) {
            parent.dir().deleteFile(self.io, parent.name) catch {
                outcome.cleanup_failed = true;
            };
            parent.sync(self.io) catch {
                outcome.cleanup_failed = true;
            };
        }
        return outcome;
    }

    fn downloadToFile(self: *Client, url: []const u8, maximum: u64, file: std.Io.File) d.Outcome {
        var request = core.http.Request.init(self.allocator, .GET, url);
        defer request.deinit();
        self.headers(&request, download_api_version, null) catch return d.Outcome.fail(.download_open, .allocation);
        var outcome = d.Outcome.fail(.download_open, .transport);
        outcome.side_effect = .not_applicable;
        const operation = self.open(&request, null, .download_open, false, &outcome) orelse return outcome;
        defer operation.deinit();
        if (operation.status_code != 200) {
            self.reject(operation, &outcome);
            return outcome;
        }
        if (!validEncoding(operation) or !validLength(operation, null, maximum)) {
            outcome.diagnostic.category = .malformed_response;
            return outcome;
        }
        const expected = contentLength(operation) catch {
            outcome.diagnostic.category = .malformed_response;
            return outcome;
        };
        const expected_md5 = responseMd5(operation) catch {
            outcome.diagnostic.category = .integrity;
            return outcome;
        };
        var digest = std.crypto.hash.sha2.Sha256.init(.{});
        var md5 = std.crypto.hash.Md5.init(.{});
        var buffer: [files.buffer_size]u8 = undefined;
        outcome.diagnostic.stage = .download_read;
        while (true) {
            const wanted: usize = @intCast(@min(buffer.len, maximum - outcome.bytes_downloaded + 1));
            const count = self.readResponse(operation, buffer[0..wanted]) catch |err| switch (err) {
                error.EndOfStream => break,
                else => {
                    outcome.diagnostic.category = if (err == error.ReadFailed) .transport else localCategory(err);
                    return outcome;
                },
            };
            if (count == 0) continue;
            if (count > maximum - outcome.bytes_downloaded) {
                outcome.diagnostic.category = .response_limit;
                return outcome;
            }
            file.writeStreamingAll(self.io, buffer[0..count]) catch {
                outcome.diagnostic.category = .local_io;
                return outcome;
            };
            digest.update(buffer[0..count]);
            md5.update(buffer[0..count]);
            outcome.bytes_downloaded += count;
        }
        if (expected) |size| if (size != outcome.bytes_downloaded) {
            outcome.diagnostic.category = .malformed_response;
            return outcome;
        };
        if (expected_md5) |value| {
            var actual: [16]u8 = undefined;
            md5.final(&actual);
            if (!std.mem.eql(u8, &value, &actual)) {
                outcome.diagnostic.category = .integrity;
                return outcome;
            }
        }
        self.budget.check() catch |err| {
            outcome.diagnostic.category = localCategory(err);
            return outcome;
        };
        // EOF has already been consumed under a cap. Abort rather than invoke
        // an SDK finish helper that may drain another unbounded body.
        operation.abort();
        file.sync(self.io) catch {
            outcome.diagnostic.stage = .output_sync;
            outcome.diagnostic.category = .local_io;
            return outcome;
        };
        self.budget.check() catch |err| {
            outcome.diagnostic.stage = .output_sync;
            outcome.diagnostic.category = localCategory(err);
            return outcome;
        };
        outcome.completion = .complete;
        outcome.diagnostic.stage = .finished;
        outcome.diagnostic.category = .none;
        outcome.sha256 = digest.finalResult();
        return outcome;
    }

    pub fn uploadPages(self: *Client, target: Disk, input: files.Input) d.Outcome {
        if (input.size < 512 or input.size % 512 != 0 or input.size > maximum_disk_bytes)
            return d.Outcome.fail(.contract, .invalid_contract);
        var uri = contract.diskUri(self.allocator, target.endpoint, target.sas) catch return d.Outcome.fail(.contract, .invalid_contract);
        defer eraseUri(&uri);
        var source = files.SealedInput.open(self.io, input, self.budget.guard()) catch |err| return d.Outcome.fail(.input_hash, localCategory(err));
        defer source.close();
        const page_url = uri.appendProtocolQuery(self.allocator, &.{.{ .name = "comp", .value = "page" }}) catch return d.Outcome.fail(.page_put, .allocation);
        defer self.erase(page_url);
        const chunk = self.allocator.alloc(u8, page_chunk_size) catch return d.Outcome.fail(.page_put, .allocation);
        defer {
            std.crypto.secureZero(u8, chunk);
            self.allocator.free(chunk);
        }
        var footer: [512]u8 = undefined;
        if ((source.file.readPositionalAll(self.io, &footer, input.size - footer.len) catch 0) != footer.len)
            return d.Outcome.fail(.input_hash, .input_changed);
        var outcome = d.Outcome.fail(.page_put, .local_io);
        var digest = std.crypto.hash.sha2.Sha256.init(.{});
        var offset: u64 = 0;
        while (offset < input.size) {
            if (offset > 0) outcome.side_effect = .incomplete;
            self.budget.check() catch |err| return failAfter(outcome, .page_put, localCategory(err));
            const length: usize = @intCast(@min(input.size - offset, chunk.len));
            const count = source.file.readPositionalAll(self.io, chunk[0..length], offset) catch return failAfter(outcome, .page_put, .local_io);
            if (count != length) return failAfter(outcome, .input_verify, .input_changed);
            digest.update(chunk[0..length]);
            var request = core.http.Request.init(self.allocator, .PUT, page_url);
            defer request.deinit();
            self.headers(&request, page_api_version, length) catch return failAfter(outcome, .page_put, .allocation);
            var range: [64]u8 = undefined;
            const value = std.fmt.bufPrint(&range, "bytes={d}-{d}", .{ offset, offset + length - 1 }) catch unreachable;
            request.setHeader("x-ms-range", value) catch return failAfter(outcome, .page_put, .allocation);
            request.setHeader("x-ms-page-write", "update") catch return failAfter(outcome, .page_put, .allocation);
            var md5: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(chunk[0..length], &md5, .{});
            var encoded: [24]u8 = undefined;
            request.setHeader("Content-MD5", std.base64.standard.Encoder.encode(&encoded, &md5)) catch return failAfter(outcome, .page_put, .allocation);
            // A per-page fixed reader exposes exactly this page's boundary.
            // The full-file EOF probe and SHA-256 check are separate below.
            var reader: files.PageReader = .{ .bytes = chunk[0..length], .guard = self.budget.guard() };
            var current = self.mutation(&request, .knownLength(&reader.interface, length), .page_put, length);
            current.bytes_streamed = outcome.bytes_streamed + reader.offset;
            current.bytes_accepted += outcome.bytes_accepted;
            if (current.completion != .complete) {
                if (reader.failure) |err| current.diagnostic.category = localCategory(err);
                if (current.side_effect == .rejected or current.side_effect == .not_started) {
                    if (outcome.bytes_accepted > 0) current.side_effect = .incomplete;
                }
                if (current.side_effect == .accepted and current.bytes_accepted < input.size) current.side_effect = .incomplete;
                return current;
            }
            if (reader.offset != length) return failAfter(current, .input_verify, .input_changed);
            outcome = current;
            offset += length;
        }
        var extra: [1]u8 = undefined;
        if ((source.file.readPositionalAll(self.io, &extra, input.size) catch 1) != 0)
            return failAfter(outcome, .input_verify, .input_changed);
        const actual_hash = digest.finalResult();
        if (!std.mem.eql(u8, &actual_hash, &input.sha256)) return failAfter(outcome, .input_verify, .input_changed);
        source.verify(self.budget.guard()) catch |err| return failAfter(outcome, .input_verify, localCategory(err));
        outcome.sha256 = actual_hash;
        self.readFooter(uri.bytes, input.size, &footer, &outcome);
        return outcome;
    }

    fn readFooter(self: *Client, url: []const u8, size: u64, expected: *const [512]u8, outcome: *d.Outcome) void {
        var request = core.http.Request.init(self.allocator, .GET, url);
        defer request.deinit();
        self.headers(&request, page_api_version, null) catch {
            outcome.* = failAfter(outcome.*, .footer_readback, .allocation);
            return;
        };
        var range: [64]u8 = undefined;
        const value = std.fmt.bufPrint(&range, "bytes={d}-{d}", .{ size - 512, size - 1 }) catch unreachable;
        request.setHeader("x-ms-range", value) catch {
            outcome.* = failAfter(outcome.*, .footer_readback, .allocation);
            return;
        };
        request.setHeader("x-ms-range-get-content-md5", "true") catch {
            outcome.* = failAfter(outcome.*, .footer_readback, .allocation);
            return;
        };
        const prior = outcome.*;
        outcome.completion = .failed;
        const operation = self.open(&request, null, .footer_readback, false, outcome) orelse {
            outcome.side_effect = prior.side_effect;
            return;
        };
        defer operation.deinit();
        if (operation.status_code != 206) {
            self.reject(operation, outcome);
            outcome.side_effect = prior.side_effect;
            return;
        }
        var expected_range: [80]u8 = undefined;
        const content_range = std.fmt.bufPrint(&expected_range, "bytes {d}-{d}/{d}", .{ size - 512, size - 1, size }) catch unreachable;
        const observed_range = uniqueHeader(operation, "Content-Range") catch null;
        if (!validEncoding(operation) or !validLength(operation, 512, 512) or observed_range == null or !std.mem.eql(u8, content_range, observed_range.?)) {
            outcome.diagnostic.category = .malformed_response;
            return;
        }
        const expected_md5 = (responseMd5(operation) catch null) orelse {
            outcome.diagnostic.category = .integrity;
            return;
        };
        var actual: [513]u8 = undefined;
        var length: usize = 0;
        while (length < actual.len) {
            const count = self.readResponse(operation, actual[length..]) catch |err| switch (err) {
                error.EndOfStream => break,
                else => {
                    outcome.diagnostic.category = if (err == error.ReadFailed) .transport else localCategory(err);
                    return;
                },
            };
            length += count;
        }
        if (length != 512) {
            outcome.diagnostic.category = if (length > 512) .response_limit else .malformed_response;
            return;
        }
        var actual_md5: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(actual[0..512], &actual_md5, .{});
        if (!std.mem.eql(u8, &expected_md5, &actual_md5)) {
            outcome.diagnostic.category = .integrity;
            return;
        }
        if (!std.mem.eql(u8, expected, actual[0..512])) {
            outcome.diagnostic.category = .footer_mismatch;
            return;
        }
        self.budget.check() catch |err| {
            outcome.diagnostic.category = localCategory(err);
            return;
        };
        outcome.completion = .complete;
        outcome.diagnostic.stage = .finished;
        outcome.diagnostic.category = .none;
        var footer_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(actual[0..512], &footer_hash, .{});
        outcome.footer_sha256 = footer_hash;
    }

    /// Execute only an already validated batch. Earlier accepted operations are
    /// never replayed when a later member fails.
    pub fn execute(self: *Client, request: *const contract.Request, sas: []const u8) d.Outcome {
        if (!contract.validSas(sas)) return d.Outcome.fail(.contract, .invalid_contract);
        var aggregate = d.Outcome.fail(.contract, .invalid_contract);
        var mutation_accepted = false;
        if (request.create_container) {
            aggregate = self.createContainer(request.account_url, request.container, sas);
            if (aggregate.completion != .complete) return aggregate;
            mutation_accepted = true;
        }
        for (request.records, 0..) |record, index| {
            var result = switch (record) {
                .upload => |item| self.uploadBlock(.{ .account_url = request.account_url, .container = request.container, .name = item.blob, .sas = sas }, item.input),
                .download => |item| self.downloadBlob(.{ .account_url = request.account_url, .container = request.container, .name = item.blob, .sas = sas }, .{ .path = item.path, .maximum = item.maximum }),
            };
            result.bytes_streamed += aggregate.bytes_streamed;
            result.bytes_accepted += aggregate.bytes_accepted;
            result.bytes_downloaded += aggregate.bytes_downloaded;
            if (result.completion != .complete) {
                if (mutation_accepted and (result.side_effect == .not_started or result.side_effect == .rejected)) result.side_effect = .incomplete;
                if (request.action == .upload and result.side_effect == .accepted and index + 1 < request.records.len) result.side_effect = .incomplete;
                return result;
            }
            if (request.action == .upload) mutation_accepted = true;
            aggregate = result;
        }
        // A batch has no single file/footer digest.
        aggregate.sha256 = null;
        aggregate.footer_sha256 = null;
        return aggregate;
    }

    pub fn executePrivate(self: *Client, request_path: []const u8, sas_path: []const u8) d.Outcome {
        self.budget.check() catch |err| return d.Outcome.fail(.request_file, localCategory(err));
        var request = contract.Request.load(self.allocator, self.io, request_path) catch |err|
            return d.Outcome.fail(.request_file, if (err == error.InvalidContract) .invalid_contract else localCategory(err));
        defer request.deinit();
        var sas = contract.loadSas(self.allocator, self.io, sas_path) catch |err|
            return d.Outcome.fail(.request_file, if (err == error.InvalidContract) .invalid_contract else localCategory(err));
        defer sas.deinit();
        return self.execute(&request, sas.bytes());
    }

    pub fn uploadPagesPrivate(self: *Client, request_path: []const u8, sas_path: []const u8) d.Outcome {
        self.budget.check() catch |err| return d.Outcome.fail(.request_file, localCategory(err));
        var request = contract.DiskRequest.load(self.allocator, self.io, request_path) catch |err|
            return d.Outcome.fail(.request_file, if (err == error.InvalidContract) .invalid_contract else localCategory(err));
        defer request.deinit();
        var sas = contract.loadSas(self.allocator, self.io, sas_path) catch |err|
            return d.Outcome.fail(.request_file, if (err == error.InvalidContract) .invalid_contract else localCategory(err));
        defer sas.deinit();
        return self.uploadPages(.{ .endpoint = request.endpoint, .sas = sas.bytes() }, request.input);
    }

    fn headers(self: *Client, request: *core.http.Request, version: []const u8, length: ?u64) !void {
        _ = self;
        request.retryable = false;
        request.redirect_policy = .not_allowed;
        try request.setHeader("x-ms-version", version);
        try request.setHeader("Accept-Encoding", "identity");
        try request.setHeader("Content-Type", "application/octet-stream");
        if (length) |size| {
            var buffer: [24]u8 = undefined;
            try request.setHeader("Content-Length", try std.fmt.bufPrint(&buffer, "{d}", .{size}));
        }
    }

    fn open(self: *Client, request: *core.http.Request, body: ?core.http.StreamingRequestBody, stage: d.Stage, mutation_request: bool, outcome: *d.Outcome) ?*core.http.HttpOperation {
        outcome.diagnostic = .{ .stage = stage, .category = .transport };
        self.budget.check() catch |err| {
            outcome.diagnostic.category = localCategory(err);
            return null;
        };
        // A buffered-only runtime is unsuitable even for GET: it could allocate
        // an entire response before the transfer layer enforces its cap.
        if (self.runtime.transport.vtable.open == null) {
            outcome.diagnostic.category = .invalid_contract;
            return null;
        }
        request.retryable = false;
        request.redirect_policy = .not_allowed;
        const now = self.budget.nowMsFn(self.budget.context) catch |err| {
            outcome.diagnostic.category = localCategory(err);
            return null;
        };
        if (now >= self.budget.deadline_ms) {
            outcome.diagnostic.category = .deadline;
            return null;
        }
        request.operation_timeout_ms = self.budget.deadline_ms - now;
        const length = if (body) |stream| stream.content_length orelse 0 else if (request.body) |bytes| bytes.len else 0;
        if (!self.notify(.{ .begin = .{ .stage = stage, .mutation = mutation_request, .bytes = length } }, outcome)) {
            outcome.diagnostic.category = .none;
            return null;
        }
        self.budget.check() catch |err| {
            outcome.diagnostic.category = localCategory(err);
            _ = self.notify(.{ .end = .{ .transport_started = false, .status = null } }, outcome);
            return null;
        };
        var pipeline = core.http.HttpPipeline.init(self.runtime, &.{});
        const operation = pipeline.open(request, .{ .body = body, .cancellation = self.budget.cancellation }) catch |err| {
            outcome.diagnostic.category = switch (err) {
                error.OperationCancelled, error.Cancelled => .cancelled,
                error.RequestBodyTooShort, error.RequestBodyTooLong => .input_changed,
                else => .transport,
            };
            if (mutation_request and request.transport_started) outcome.side_effect = .unknown;
            _ = self.notify(.{ .end = .{ .transport_started = request.transport_started, .status = null } }, outcome);
            return null;
        };
        outcome.diagnostic.status = operation.status_code;
        if (mutation_request) outcome.side_effect = if (operation.isSuccess()) .accepted else .rejected;
        if (mutation_request and operation.isSuccess()) outcome.bytes_accepted = length;
        outcome.diagnostic.category = if (operation.isSuccess()) .none else d.statusCategory(operation.status_code);
        if (!self.notify(.{ .end = .{ .transport_started = true, .status = operation.status_code } }, outcome)) {
            operation.deinit();
            return null;
        }
        return operation;
    }

    fn notify(self: *Client, event: Event, outcome: *d.Outcome) bool {
        const observer = self.observer orelse return true;
        observer.notifyFn(observer.context, event) catch {
            outcome.failures.record(.recording, .{ .stage = .state_record, .category = .local_io }) catch unreachable;
            return false;
        };
        return true;
    }

    fn mutation(self: *Client, request: *core.http.Request, body: ?core.http.StreamingRequestBody, stage: d.Stage, accepted_bytes: u64) d.Outcome {
        var outcome = d.Outcome.fail(stage, .transport);
        const operation = self.open(request, body, stage, true, &outcome) orelse return outcome;
        defer operation.deinit();
        if (operation.isSuccess()) outcome.bytes_accepted = accepted_bytes;
        if (operation.status_code != 201) {
            self.reject(operation, &outcome);
            return outcome;
        }
        self.budget.check() catch |err| {
            operation.cancel();
            outcome.diagnostic.category = localCategory(err);
            return outcome;
        };
        if (!validEncoding(operation) or !validLength(operation, null, 0)) {
            outcome.diagnostic.category = .malformed_response;
            return outcome;
        }
        var extra: [1]u8 = undefined;
        while (true) {
            const count = self.readResponse(operation, &extra) catch |err| switch (err) {
                error.EndOfStream => break,
                else => {
                    outcome.diagnostic.category = if (err == error.ReadFailed) .transport else localCategory(err);
                    return outcome;
                },
            };
            if (count != 0) {
                outcome.diagnostic.category = .response_limit;
                return outcome;
            }
        }
        self.budget.check() catch |err| {
            outcome.diagnostic.category = localCategory(err);
            return outcome;
        };
        outcome.completion = .complete;
        outcome.diagnostic.category = .none;
        return outcome;
    }

    fn reject(self: *Client, operation: *core.http.HttpOperation, outcome: *d.Outcome) void {
        outcome.diagnostic.category = d.statusCategory(operation.status_code);
        var buffer: [d.max_error_body + 1]u8 = undefined;
        var used: usize = 0;
        var failed = false;
        while (used < buffer.len) {
            const count = self.readResponse(operation, buffer[used..]) catch |err| switch (err) {
                error.EndOfStream => break,
                else => {
                    failed = true;
                    break;
                },
            };
            used += count;
        }
        outcome.diagnostic.service = d.extract(operation, buffer[0..@min(used, d.max_error_body)], failed or used > d.max_error_body);
        std.crypto.secureZero(u8, &buffer);
    }

    // readSliceShort fills its destination through repeated progress reads.
    // Guard a single readVec call instead; zero progress is not EOF.
    fn readResponse(self: *Client, operation: *core.http.HttpOperation, buffer: []u8) !usize {
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

    fn erase(self: *Client, bytes: []u8) void {
        std.crypto.secureZero(u8, bytes);
        self.allocator.free(bytes);
    }
};

fn eraseUri(uri: *common.sas.CompleteSasUri) void {
    std.crypto.secureZero(u8, uri.bytes);
    uri.deinit();
}

fn localCategory(err: anyerror) d.Category {
    return switch (err) {
        error.Cancelled, error.OperationCancelled => .cancelled,
        error.Deadline => .deadline,
        error.InputChanged => .input_changed,
        error.OutOfMemory => .allocation,
        error.UnsafeFile, error.UnsafePath, error.SymLinkLoop, error.FileNotFound, error.NotDir, error.AccessDenied => .unsafe_file,
        else => .local_io,
    };
}

fn failAfter(previous: d.Outcome, stage: d.Stage, category: d.Category) d.Outcome {
    var result = previous;
    result.completion = .failed;
    result.diagnostic = .{ .stage = stage, .category = category };
    return result;
}

fn uniqueHeader(operation: *const core.http.HttpOperation, name: []const u8) !?[]const u8 {
    var found: ?[]const u8 = null;
    for (operation.response_headers.entries.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            if (header.value.len > 128) return error.MalformedResponse;
            if (found) |value| if (!std.mem.eql(u8, value, header.value)) return error.MalformedResponse;
            found = header.value;
        }
    }
    const result = found orelse operation.getHeader(name) orelse return null;
    if (result.len > 128) return error.MalformedResponse;
    return result;
}

fn contentLength(operation: *const core.http.HttpOperation) !?u64 {
    const value = try uniqueHeader(operation, "Content-Length") orelse return null;
    if (value.len == 0) return error.MalformedResponse;
    for (value) |c| if (!std.ascii.isDigit(c)) return error.MalformedResponse;
    return std.fmt.parseInt(u64, value, 10) catch error.MalformedResponse;
}

fn validLength(operation: *const core.http.HttpOperation, required: ?u64, maximum: u64) bool {
    const value = contentLength(operation) catch return false;
    if (value) |size| {
        if (size > maximum) return false;
        if (required) |expected| return size == expected;
    } else if (required != null) return false;
    return true;
}

fn validEncoding(operation: *const core.http.HttpOperation) bool {
    const value = uniqueHeader(operation, "Content-Encoding") catch return false;
    return value == null or std.mem.eql(u8, value.?, "identity");
}

fn responseMd5(operation: *const core.http.HttpOperation) !?[16]u8 {
    const value = try uniqueHeader(operation, "Content-MD5") orelse return null;
    if (value.len != 24 or value[22] != '=' or value[23] != '=') return error.MalformedResponse;
    var result: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&result, value);
    return result;
}
