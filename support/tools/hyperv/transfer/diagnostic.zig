const std = @import("std");
const core = @import("azure_sdk_core");
const shared = @import("hyperv_core");
const contracts = shared.contracts;

pub const max_error_body = 8192;
pub const Stage = enum { contract, request_file, input_open, input_hash, container_create, block_put, page_put, download_open, download_read, output_create, output_sync, input_verify, footer_readback, finished };
pub const Category = enum { none, invalid_contract, unsafe_file, input_changed, local_io, allocation, cancelled, deadline, transport, redirect, condition, authentication, authorization, not_found, throttled, service, unexpected_status, response_limit, malformed_response, integrity, footer_mismatch };
pub const Certainty = enum { not_started, accepted, rejected, unknown, incomplete, not_applicable };
pub const Completion = enum { complete, failed };
pub const MetadataState = shared.diagnostics.MetadataState;
pub const ServiceCode = shared.diagnostics.ServiceCode;
pub const Metadata = struct {
    state: MetadataState = .absent,
    code: ?ServiceCode = null,
    header: MetadataState = .absent,
    body: MetadataState = .absent,
    header_code: ?ServiceCode = null,
    body_code: ?ServiceCode = null,

    pub fn validate(self: Metadata) !void {
        try validateCode(self.state, self.code);
        try validateCode(self.header, self.header_code);
        try validateCode(self.body, self.body_code);
        if (self.header == .absent) {
            if (self.state != self.body or self.code != self.body_code) return error.InvalidOutcome;
        } else if (self.body == .absent) {
            if (self.state != self.header or self.code != self.header_code) return error.InvalidOutcome;
        } else if (self.header == .conflicting or self.body == .conflicting) {
            if (self.state != .conflicting) return error.InvalidOutcome;
        } else if (self.header == .known and self.body == .known) {
            if (self.header_code == self.body_code) {
                if (self.state != .known or self.code != self.header_code) return error.InvalidOutcome;
            } else if (self.state != .conflicting) return error.InvalidOutcome;
        } else if (self.header == .malformed or self.body == .malformed) {
            if (self.state != .malformed and self.state != .conflicting) return error.InvalidOutcome;
        } else if (self.header == .unknown and self.body == .unknown) {
            if (self.state != .unknown and self.state != .conflicting) return error.InvalidOutcome;
        } else if (self.state != .conflicting) return error.InvalidOutcome;
    }
};
pub const Diagnostic = struct {
    stage: Stage,
    category: Category,
    status: ?u16 = null,
    service: Metadata = .{},
};
pub const Outcome = struct {
    completion: Completion = .failed,
    side_effect: Certainty = .not_started,
    diagnostic: Diagnostic = .{ .stage = .contract, .category = .invalid_contract },
    /// Bytes supplied to the transport, not a claim about bytes on the wire.
    bytes_streamed: u64 = 0,
    /// Bytes covered by accepted update response heads, even if validation fails.
    bytes_accepted: u64 = 0,
    bytes_downloaded: u64 = 0,
    sha256: ?[32]u8 = null,
    footer_sha256: ?[32]u8 = null,
    cleanup_failed: bool = false,
    failures: shared.diagnostics.Failures = .{},

    pub fn fail(stage: Stage, category: Category) Outcome {
        return .{ .diagnostic = .{ .stage = stage, .category = category } };
    }

    /// This is the only diagnostic rendering surface. All text is compile-time
    /// enum vocabulary; never pass an SDK error, request or response to a logger.
    pub fn write(self: Outcome, writer: *std.Io.Writer) !void {
        try self.writeValue(writer);
        try writer.writeByte('\n');
    }

    pub fn writeValue(self: Outcome, writer: *std.Io.Writer) !void {
        try self.validate();
        try writer.writeAll("{\"body_code\":");
        try std.json.Stringify.value(self.diagnostic.service.body_code, .{}, writer);
        try writer.print(",\"body_metadata\":\"{s}\",\"bytes_accepted\":{d},\"bytes_downloaded\":{d},\"bytes_streamed\":{d},\"category\":\"{s}\",\"cleanup_failed\":{s},\"completion\":\"{s}\",\"failures\":", .{
            @tagName(self.diagnostic.service.body), self.bytes_accepted,                          self.bytes_downloaded,     self.bytes_streamed,
            @tagName(self.diagnostic.category),     if (self.cleanup_failed) "true" else "false", @tagName(self.completion),
        });
        try self.failures.writeValue(writer);
        try writer.writeAll(",\"footer_sha256\":");
        try writeHash(self.footer_sha256, writer);
        try writer.writeAll(",\"header_code\":");
        try std.json.Stringify.value(self.diagnostic.service.header_code, .{}, writer);
        try writer.print(",\"header_metadata\":\"{s}\",\"metadata\":\"{s}\",\"schema_version\":2,\"service_code\":", .{
            @tagName(self.diagnostic.service.header), @tagName(self.diagnostic.service.state),
        });
        try std.json.Stringify.value(self.diagnostic.service.code, .{}, writer);
        try writer.writeAll(",\"sha256\":");
        try writeHash(self.sha256, writer);
        try writer.print(",\"side_effect\":\"{s}\",\"stage\":\"{s}\",\"status\":", .{ @tagName(self.side_effect), @tagName(self.diagnostic.stage) });
        try std.json.Stringify.value(self.diagnostic.status, .{}, writer);
        try writer.writeByte('}');
    }

    pub fn parse(value: std.json.Value) !Outcome {
        const object = try contracts.exactFields(value, &.{
            "schema_version", "completion",      "side_effect",      "stage",        "category",      "status",
            "metadata",       "header_metadata", "body_metadata",    "service_code", "header_code",   "body_code",
            "bytes_streamed", "bytes_accepted",  "bytes_downloaded", "sha256",       "footer_sha256", "cleanup_failed",
            "failures",
        });
        if (try contracts.integer(u32, object.get("schema_version").?) != 2) return error.InvalidOutcome;
        const status = object.get("status").?;
        const cleanup = object.get("cleanup_failed").?;
        if (cleanup != .bool) return error.InvalidOutcome;
        const result: Outcome = .{
            .completion = try contracts.enumeration(Completion, object.get("completion").?),
            .side_effect = try contracts.enumeration(Certainty, object.get("side_effect").?),
            .diagnostic = .{
                .stage = try contracts.enumeration(Stage, object.get("stage").?),
                .category = try contracts.enumeration(Category, object.get("category").?),
                .status = if (status == .null) null else try contracts.integer(u16, status),
                .service = .{
                    .state = try contracts.enumeration(MetadataState, object.get("metadata").?),
                    .header = try contracts.enumeration(MetadataState, object.get("header_metadata").?),
                    .body = try contracts.enumeration(MetadataState, object.get("body_metadata").?),
                    .code = try parseCode(object.get("service_code").?),
                    .header_code = try parseCode(object.get("header_code").?),
                    .body_code = try parseCode(object.get("body_code").?),
                },
            },
            .bytes_streamed = try contracts.integer(u64, object.get("bytes_streamed").?),
            .bytes_accepted = try contracts.integer(u64, object.get("bytes_accepted").?),
            .bytes_downloaded = try contracts.integer(u64, object.get("bytes_downloaded").?),
            .sha256 = try parseHash(object.get("sha256").?),
            .footer_sha256 = try parseHash(object.get("footer_sha256").?),
            .cleanup_failed = cleanup.bool,
            .failures = try shared.diagnostics.Failures.parse(object.get("failures").?),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: Outcome) !void {
        const metadata = self.diagnostic.service;
        try metadata.validate();
        if (self.diagnostic.status) |status| {
            if (status < 100 or status > 599) return error.InvalidOutcome;
        } else if (metadata.state != .absent or metadata.header != .absent or metadata.body != .absent) return error.InvalidOutcome;
        if (self.completion == .complete and
            (self.diagnostic.category != .none or self.diagnostic.status == null or
                self.diagnostic.status.? < 200 or self.diagnostic.status.? >= 300 or self.cleanup_failed or
                (self.side_effect != .accepted and self.side_effect != .not_applicable) or
                self.failures.primary != null or self.failures.cleanup != null or self.failures.recording != null))
            return error.InvalidOutcome;
        if (self.completion == .failed and self.diagnostic.category == .none and !self.cleanup_failed and
            self.failures.primary == null and self.failures.cleanup == null and self.failures.recording == null)
            return error.InvalidOutcome;
    }

    pub fn failureSummary(self: Outcome) !shared.diagnostics.Failures {
        var result = self.failures;
        if (self.completion == .failed and self.diagnostic.category != .none)
            try result.record(.primary, self.aggregateDiagnostic());
        if (self.cleanup_failed) try result.record(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
        return result;
    }

    pub fn aggregateDiagnostic(self: Outcome) shared.diagnostics.Diagnostic {
        return .{
            .stage = switch (self.diagnostic.stage) {
                .contract => .contract,
                .request_file, .input_open, .input_hash, .input_verify, .output_create, .output_sync => .private_file,
                .container_create, .block_put => .blob_upload,
                .page_put, .footer_readback => .page_upload,
                .download_open, .download_read => .blob_download,
                .finished => .transfer_worker,
            },
            .category = switch (self.diagnostic.category) {
                .none => .unavailable,
                .invalid_contract => .invalid_input,
                .unsafe_file => .unsafe_file,
                .input_changed, .integrity, .footer_mismatch => .integrity,
                .local_io => .local_io,
                .allocation => .internal,
                .cancelled => .cancelled,
                .deadline => .timeout,
                .transport => .transport,
                .redirect, .unexpected_status, .malformed_response => .invalid_response,
                .condition => .conflict,
                .authentication => .authentication,
                .authorization => .authorization,
                .not_found => .not_found,
                .throttled => .throttled,
                .service => .service,
                .response_limit => .output_limit,
            },
            .http_status = self.diagnostic.status,
            .service_code = switch (self.diagnostic.service.state) {
                .absent => .unavailable,
                .known => self.diagnostic.service.code.?,
                .unknown => .unknown,
                .malformed => .malformed,
                .conflicting => .conflicting,
            },
        };
    }
};

pub fn writeHash(hash: ?[32]u8, writer: *std.Io.Writer) !void {
    if (hash) |value| try writer.print("\"{s}\"", .{std.fmt.bytesToHex(value, .lower)}) else try writer.writeAll("null");
}

pub fn parseHash(value: std.json.Value) !?[32]u8 {
    return if (value == .null) null else try contracts.parseSha256(try contracts.string(value));
}

fn parseCode(value: std.json.Value) !?ServiceCode {
    if (value == .null) return null;
    const code = try contracts.enumeration(ServiceCode, value);
    try validateCode(.known, code);
    return code;
}

fn validateCode(state: MetadataState, code: ?ServiceCode) !void {
    if (state != .known) {
        if (code != null) return error.InvalidOutcome;
        return;
    }
    switch (code orelse return error.InvalidOutcome) {
        .unavailable, .unknown, .malformed, .conflicting => return error.InvalidOutcome,
        else => {},
    }
}

pub fn statusCategory(status: u16) Category {
    return switch (status) {
        300...399 => .redirect,
        401 => .authentication,
        403 => .authorization,
        404 => .not_found,
        409, 412 => .condition,
        408, 429, 503 => .throttled,
        else => if (status >= 400 and status < 600) .service else .unexpected_status,
    };
}

const Candidate = struct {
    state: MetadataState = .absent,
    raw: ?[]const u8 = null,
    code: ?ServiceCode = null,

    fn add(self: *Candidate, value: []const u8) void {
        const code = shared.diagnostics.classifyServiceCode(value);
        const next: Candidate = switch (code) {
            .unavailable => .{ .state = .absent },
            .unknown => .{ .state = .unknown, .raw = value },
            .malformed => .{ .state = .malformed, .raw = value },
            .conflicting => .{ .state = .conflicting },
            else => .{ .state = .known, .raw = value, .code = code },
        };
        self.merge(next);
    }

    fn merge(self: *Candidate, other: Candidate) void {
        if (self.state == .conflicting or other.state == .absent) return;
        if (self.state == .absent) {
            self.* = other;
            return;
        }
        if (other.state == .conflicting or
            (self.raw != null and other.raw != null and !std.mem.eql(u8, self.raw.?, other.raw.?)))
        {
            self.* = .{ .state = .conflicting };
        } else if (self.state == .malformed or other.state == .malformed) {
            self.* = .{ .state = .malformed };
        }
    }
};

pub fn extract(operation: *const core.http.HttpOperation, body: []const u8, truncated: bool) Metadata {
    var header: Candidate = .{};
    var count: usize = 0;
    var total: usize = 0;
    for (operation.response_headers.entries.items) |entry| {
        count += 1;
        if (entry.name.len > 128 or entry.value.len > 4096 or count > 64) {
            header.merge(.{ .state = .malformed });
            break;
        }
        total += entry.name.len + entry.value.len;
        if (total > 16384) {
            header.merge(.{ .state = .malformed });
            break;
        }
        if (std.ascii.eqlIgnoreCase(entry.name, "x-ms-error-code")) header.add(entry.value);
    }
    if (operation.response_headers.entries.items.len == 0) {
        if (operation.getHeader("x-ms-error-code")) |value| header.add(value);
    }
    var storage: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &storage);
    var allocator = std.heap.FixedBufferAllocator.init(&storage);
    var parsed: ?std.json.Parsed(std.json.Value) = null;
    defer if (parsed) |*value| value.deinit();
    const content = std.mem.trim(u8, body, " \r\n\t");
    var body_code: Candidate = .{};
    if (truncated or content.len > max_error_body) {
        body_code.state = .malformed;
    } else if (content.len > 0) {
        if (content[0] == '<') {
            body_code = xmlCode(content);
        } else if (content[0] == '{' and boundedJson(content)) {
            parsed = std.json.parseFromSlice(std.json.Value, allocator.allocator(), content, .{
                .max_value_len = max_error_body,
                .duplicate_field_behavior = .@"error",
            }) catch null;
            if (parsed) |value| {
                body_code = jsonCode(value.value);
            } else body_code.state = .malformed;
        } else body_code.state = .malformed;
    }
    var combined = header;
    combined.merge(body_code);
    return .{
        .state = combined.state,
        .code = if (combined.state == .known) combined.code else null,
        .header = header.state,
        .body = body_code.state,
        .header_code = if (header.state == .known) header.code else null,
        .body_code = if (body_code.state == .known) body_code.code else null,
    };
}

pub fn boundedJson(bytes: []const u8) bool {
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    for (bytes) |c| {
        if (quoted) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') quoted = false;
        } else switch (c) {
            '"' => quoted = true,
            '{', '[' => {
                depth += 1;
                if (depth > 16) return false;
            },
            '}', ']' => {
                if (depth == 0) return false;
                depth -= 1;
            },
            else => {},
        }
    }
    return !quoted and depth == 0;
}

fn jsonCode(value: std.json.Value) Candidate {
    if (value != .object) return .{ .state = .malformed };
    var result: Candidate = .{};
    if (value.object.get("code")) |code| {
        if (code == .string) result.add(code.string) else result.merge(.{ .state = .malformed });
    }
    if (value.object.get("error")) |inner| {
        if (inner == .object) {
            if (inner.object.get("code")) |code| {
                if (code == .string) result.add(code.string) else result.merge(.{ .state = .malformed });
            }
        } else result.merge(.{ .state = .malformed });
    }
    return result;
}

fn xmlCode(bytes: []const u8) Candidate {
    var result: Candidate = .{};
    var stack: [16][]const u8 = undefined;
    var depth: usize = 0;
    var index: usize = 0;
    var root_seen = false;
    while (index < bytes.len) {
        if (bytes[index] != '<') return .{ .state = .malformed };
        if (index == 0 and std.mem.startsWith(u8, bytes, "<?xml ")) {
            const end = std.mem.indexOf(u8, bytes, "?>") orelse return .{ .state = .malformed };
            index = end + 2;
            while (index < bytes.len and std.ascii.isWhitespace(bytes[index])) : (index += 1) {}
            continue;
        }
        const end = std.mem.indexOfScalarPos(u8, bytes, index, '>') orelse return .{ .state = .malformed };
        const tag = bytes[index + 1 .. end];
        if (tag.len == 0 or std.mem.indexOfAny(u8, tag, "<!?'\"&") != null) return .{ .state = .malformed };
        if (tag[0] == '/') {
            if (depth == 0 or !std.mem.eql(u8, stack[depth - 1], tag[1..])) return .{ .state = .malformed };
            depth -= 1;
        } else {
            if (depth == 0) {
                if (root_seen or !std.mem.eql(u8, tag, "Error")) return .{ .state = .malformed };
                root_seen = true;
            }
            if (depth == stack.len or std.mem.indexOfAny(u8, tag, " /\r\n\t") != null) return .{ .state = .malformed };
            stack[depth] = tag;
            depth += 1;
        }
        index = end + 1;
        const next = std.mem.indexOfScalarPos(u8, bytes, index, '<') orelse bytes.len;
        const text = bytes[index..next];
        if (depth == 2 and std.mem.eql(u8, stack[1], "Code") and tag[0] != '/') {
            result.add(text);
            if (!std.mem.startsWith(u8, bytes[next..], "</Code>")) return .{ .state = .malformed };
        } else if (depth == 0 and std.mem.trim(u8, text, " \r\n\t").len != 0) return .{ .state = .malformed };
        index = next;
    }
    if (!root_seen or depth != 0) return .{ .state = .malformed };
    return result;
}
