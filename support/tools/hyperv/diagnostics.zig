const std = @import("std");
const contracts = @import("contracts.zig");

pub const Stage = enum {
    contract,
    private_file,
    lock,
    state_record,
    process_spawn,
    process_run,
    process_cleanup,
    credential,
    admission,
    arm,
    blob_upload,
    blob_download,
    page_upload,
    serial_evidence,
    host_phase,
    cleanup,
    inspection,
};
pub const Category = enum {
    unavailable,
    invalid_input,
    invalid_response,
    unsafe_file,
    contention,
    local_io,
    spawn_failed,
    child_failed,
    output_limit,
    timeout,
    cancelled,
    transport,
    authentication,
    authorization,
    not_found,
    conflict,
    throttled,
    service,
    integrity,
    ambiguous,
    cleanup_failed,
    internal,
};
pub const ServiceCode = enum {
    unavailable,
    unknown,
    malformed,
    conflicting,
    AuthenticationFailed,
    AuthorizationFailure,
    AuthorizationPermissionMismatch,
    AuthorizationSourceIPMismatch,
    AuthorizationProtocolMismatch,
    InvalidAuthenticationInfo,
    InvalidHeaderValue,
    InvalidQueryParameterValue,
    InvalidResourceName,
    InvalidUri,
    MissingRequiredHeader,
    ContainerAlreadyExists,
    ContainerNotFound,
    BlobAlreadyExists,
    BlobNotFound,
    ResourceNotFound,
    ResourceGroupNotFound,
    ConditionNotMet,
    LeaseIdMissing,
    LeaseIdMismatchWithBlobOperation,
    LeaseAlreadyPresent,
    ServerBusy,
    InternalError,
    OperationTimedOut,
    RequestBodyTooLarge,
    Md5Mismatch,
    Crc64Mismatch,
    InvalidMd5,
    InvalidRange,
    InvalidPageRange,
    TooManyRequests,
    QuotaExceeded,
    SubscriptionNotFound,
    MissingSubscriptionRegistration,
    SkuNotAvailable,
    AllocationFailed,
};

/// These fields cannot hold response bodies, exception strings, paths, IDs, or secrets.
pub const Diagnostic = struct {
    stage: Stage,
    category: Category,
    http_status: ?u16 = null,
    service_code: ServiceCode = .unavailable,

    pub fn validate(self: Diagnostic) !void {
        if (self.http_status) |status| {
            if (status < 100 or status > 599) return error.InvalidHttpStatus;
        } else if (self.service_code != .unavailable) return error.UnobservedServiceCode;
    }

    pub fn parse(value: std.json.Value) !Diagnostic {
        const object = try contracts.exactFields(value, &.{ "stage", "category", "http_status", "service_code" });
        const status = object.get("http_status").?;
        const result: Diagnostic = .{
            .stage = try contracts.enumeration(Stage, object.get("stage").?),
            .category = try contracts.enumeration(Category, object.get("category").?),
            .http_status = if (status == .null) null else try contracts.integer(u16, status),
            .service_code = try contracts.enumeration(ServiceCode, object.get("service_code").?),
        };
        try result.validate();
        return result;
    }

    pub fn write(self: Diagnostic, writer: *std.Io.Writer) !void {
        try self.validate();
        try writer.writeAll("{\"category\":");
        try std.json.Stringify.value(@tagName(self.category), .{}, writer);
        try writer.writeAll(",\"http_status\":");
        try std.json.Stringify.value(self.http_status, .{}, writer);
        try writer.writeAll(",\"service_code\":");
        try std.json.Stringify.value(@tagName(self.service_code), .{}, writer);
        try writer.writeAll(",\"stage\":");
        try std.json.Stringify.value(@tagName(self.stage), .{}, writer);
        try writer.writeByte('}');
    }
};

/// First failure in each independent lane wins; cleanup must never erase primary.
pub const Failures = struct {
    primary: ?Diagnostic = null,
    cleanup: ?Diagnostic = null,
    recording: ?Diagnostic = null,

    pub fn parse(value: std.json.Value) !Failures {
        const object = try contracts.exactFields(value, &.{ "schema_version", "primary", "cleanup", "recording" });
        if (try contracts.integer(u32, object.get("schema_version").?) != 1) return error.UnknownSchema;
        return .{
            .primary = try parseOptional(object.get("primary").?),
            .cleanup = try parseOptional(object.get("cleanup").?),
            .recording = try parseOptional(object.get("recording").?),
        };
    }

    pub fn record(self: *Failures, lane: enum { primary, cleanup, recording }, diagnostic: Diagnostic) !void {
        try diagnostic.validate();
        const target = switch (lane) {
            .primary => &self.primary,
            .cleanup => &self.cleanup,
            .recording => &self.recording,
        };
        if (target.* == null) target.* = diagnostic;
    }

    pub fn write(self: Failures, writer: *std.Io.Writer) !void {
        try writer.writeAll("{\"cleanup\":");
        try optional(self.cleanup, writer);
        try writer.writeAll(",\"primary\":");
        try optional(self.primary, writer);
        try writer.writeAll(",\"recording\":");
        try optional(self.recording, writer);
        try writer.writeAll(",\"schema_version\":1}\n");
    }
};

fn parseOptional(value: std.json.Value) !?Diagnostic {
    return if (value == .null) null else try Diagnostic.parse(value);
}

fn optional(value: ?Diagnostic, writer: *std.Io.Writer) !void {
    if (value) |diagnostic| try diagnostic.write(writer) else try writer.writeAll("null");
}

/// Raw codes are inspected transiently and never copied into the diagnostic.
pub fn classifyServiceCode(raw: ?[]const u8) ServiceCode {
    const source = raw orelse return .unavailable;
    if (source.len == 0 or source.len > 96) return .malformed;
    for (source) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return .malformed;
    }
    const parsed = std.meta.stringToEnum(ServiceCode, source) orelse return .unknown;
    return switch (parsed) {
        .unavailable, .unknown, .malformed, .conflicting => .unknown,
        else => parsed,
    };
}

pub fn reconcileServiceCodes(header: ?[]const u8, body: ?[]const u8) ServiceCode {
    if (header != null and body != null and !std.mem.eql(u8, header.?, body.?)) return .conflicting;
    return classifyServiceCode(header orelse body);
}
