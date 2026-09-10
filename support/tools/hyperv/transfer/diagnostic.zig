const std = @import("std");
const core = @import("azure_sdk_core");

pub const max_error_body = 8192;
pub const Stage = enum { contract, request_file, input_open, input_hash, container_create, block_put, page_put, download_open, download_read, output_create, output_sync, input_verify, footer_readback, finished };
pub const Category = enum { none, invalid_contract, unsafe_file, input_changed, local_io, allocation, cancelled, deadline, transport, redirect, condition, authentication, authorization, not_found, throttled, service, unexpected_status, response_limit, malformed_response, integrity, footer_mismatch };
pub const Certainty = enum { not_started, accepted, rejected, unknown, incomplete, not_applicable };
pub const Completion = enum { complete, failed };
pub const MetadataState = enum { absent, known, unknown, malformed, conflicting };
pub const ServiceCode = enum {
    AuthenticationFailed,
    AuthorizationFailure,
    AuthorizationPermissionMismatch,
    AuthorizationSourceIPMismatch,
    AuthorizationProtocolMismatch,
    AuthorizationServiceMismatch,
    KeyBasedAuthenticationNotPermitted,
    ConditionNotMet,
    BlobAlreadyExists,
    ContainerAlreadyExists,
    BlobNotFound,
    ContainerNotFound,
    ResourceNotFound,
    Md5Mismatch,
    InvalidMd5,
    InvalidHeaderValue,
    InvalidRange,
    InvalidPageRange,
    InvalidBlobType,
    InvalidQueryParameterValue,
    MissingRequiredHeader,
    LeaseIdMissing,
    LeaseIdMismatchWithBlob,
    LeaseAlreadyPresent,
    PendingCopyOperation,
    ServerBusy,
    OperationTimedOut,
    InternalError,
};
pub const Metadata = struct {
    state: MetadataState = .absent,
    code: ?ServiceCode = null,
    header: MetadataState = .absent,
    body: MetadataState = .absent,
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

    pub fn fail(stage: Stage, category: Category) Outcome {
        return .{ .diagnostic = .{ .stage = stage, .category = category } };
    }

    /// This is the only diagnostic rendering surface. All text is compile-time
    /// enum vocabulary; never pass an SDK error, request or response to a logger.
    pub fn write(self: Outcome, writer: *std.Io.Writer) !void {
        try writer.print(
            "{{\"schema\":1,\"completion\":\"{s}\",\"side_effect\":\"{s}\",\"stage\":\"{s}\",\"category\":\"{s}\",\"status\":",
            .{ @tagName(self.completion), @tagName(self.side_effect), @tagName(self.diagnostic.stage), @tagName(self.diagnostic.category) },
        );
        if (self.diagnostic.status) |status| try writer.print("{d}", .{status}) else try writer.writeAll("null");
        try writer.print(",\"metadata\":\"{s}\",\"header_metadata\":\"{s}\",\"body_metadata\":\"{s}\",\"service_code\":", .{
            @tagName(self.diagnostic.service.state), @tagName(self.diagnostic.service.header), @tagName(self.diagnostic.service.body),
        });
        if (self.diagnostic.service.code) |code| try writer.print("\"{s}\"", .{@tagName(code)}) else try writer.writeAll("null");
        try writer.print(",\"bytes_streamed\":{d},\"bytes_accepted\":{d},\"bytes_downloaded\":{d},\"cleanup_failed\":{s}}}\n", .{
            self.bytes_streamed, self.bytes_accepted, self.bytes_downloaded, if (self.cleanup_failed) "true" else "false",
        });
    }
};

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
        var next: Candidate = .{ .state = .unknown, .raw = value };
        if (value.len == 0 or value.len > 128) {
            next.state = .malformed;
        } else {
            for (value) |c| {
                if (!std.ascii.isAlphanumeric(c) and c != '_') next.state = .malformed;
            }
        }
        if (next.state != .malformed) {
            next.code = std.meta.stringToEnum(ServiceCode, value);
            if (next.code != null) next.state = .known;
        }
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
    return .{ .state = combined.state, .code = if (combined.state == .known) combined.code else null, .header = header.state, .body = body_code.state };
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
