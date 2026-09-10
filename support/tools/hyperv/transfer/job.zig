const std = @import("std");
const core = @import("hyperv_core");
const request = @import("request.zig");

pub const Kind = enum { blob, pages };
pub const intent_name = "transfer-intent.json";
pub const started_name = "transfer-started.json";
pub const state_name = "transfer-state.json";
pub const supervised_name = "transfer-supervised.json";

pub fn filename(name: []const u8) !void {
    try core.private_files.basename(name);
    if (name[0] == '.') return error.InvalidJob;
    for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '-')
        return error.InvalidJob;
    for ([_][]const u8{ intent_name, started_name, state_name, supervised_name }) |reserved|
        if (std.mem.eql(u8, name, reserved)) return error.InvalidJob;
}

pub const Job = struct {
    document: core.contracts.SensitiveDocument,
    binding: [32]u8,
    kind: Kind,
    request_name: []const u8,
    sas_name: []const u8,
    timeout_ms: u32,
    cleanup_ms: u32,

    pub fn load(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, name: []const u8) !Job {
        try filename(name);
        var raw = try directory.readSensitive(io, allocator, name, 8192, null);
        defer raw.deinit();
        const document = try core.contracts.SensitiveDocument.parse(allocator, raw.bytes(), .{ .bytes = 8192 });
        errdefer document.deinit();
        const object = try core.contracts.exactFields(document.value(), &.{
            "contract", "schema_version", "kind", "request", "sas", "timeout_ms", "cleanup_ms",
        });
        if (!std.mem.eql(u8, try core.contracts.string(object.get("contract").?), "uk.hyperv.transfer-job") or
            try core.contracts.integer(u32, object.get("schema_version").?) != 1) return error.InvalidJob;
        const request_name = try core.contracts.string(object.get("request").?);
        const sas_name = try core.contracts.string(object.get("sas").?);
        try filename(request_name);
        try filename(sas_name);
        if (std.mem.eql(u8, request_name, sas_name) or std.mem.eql(u8, request_name, name) or std.mem.eql(u8, sas_name, name))
            return error.InvalidJob;
        const timeout_ms = try core.contracts.integer(u32, object.get("timeout_ms").?);
        const cleanup_ms = try core.contracts.integer(u32, object.get("cleanup_ms").?);
        if (timeout_ms == 0 or timeout_ms > 60 * 60 * 1000 or cleanup_ms < 100 or cleanup_ms > 30 * 60 * 1000)
            return error.InvalidJob;
        return .{
            .document = document,
            .binding = hash(raw.bytes()),
            .kind = try core.contracts.enumeration(Kind, object.get("kind").?),
            .request_name = request_name,
            .sas_name = sas_name,
            .timeout_ms = timeout_ms,
            .cleanup_ms = cleanup_ms,
        };
    }

    pub fn deinit(self: Job) void {
        self.document.deinit();
    }
};

pub const Plan = struct {
    bytes: u64,
    download_bytes: u64,
    mutations: u64,
    requests: u64,

    pub fn validate(self: Plan, kind: Kind) !void {
        if (self.requests == 0 or self.requests > 1026 or self.mutations > self.requests or
            self.bytes > 128 * @as(u64, request.maximum_file) or
            self.download_bytes > 128 * @as(u64, request.maximum_file)) return error.InvalidJob;
        switch (kind) {
            .blob => {
                if (self.mutations == 0) {
                    if (self.bytes != 0) return error.InvalidJob;
                } else if (self.mutations != self.requests or self.download_bytes != 0) return error.InvalidJob;
            },
            .pages => {
                if (self.bytes < 512 or self.bytes > request.maximum_disk_bytes or self.bytes % 512 != 0 or
                    self.mutations != (self.bytes - 1) / (4 * 1024 * 1024) + 1 or
                    self.requests != self.mutations + 1 or self.download_bytes != 512) return error.InvalidJob;
            },
        }
    }

    pub fn parse(value: std.json.Value) !Plan {
        const o = try core.contracts.exactFields(value, &.{ "bytes", "download_bytes", "mutations", "requests" });
        const result: Plan = .{
            .bytes = try core.contracts.integer(u64, o.get("bytes").?),
            .download_bytes = try core.contracts.integer(u64, o.get("download_bytes").?),
            .mutations = try core.contracts.integer(u64, o.get("mutations").?),
            .requests = try core.contracts.integer(u64, o.get("requests").?),
        };
        if (result.requests == 0 or result.requests > 1026 or result.mutations > result.requests or
            result.bytes > 128 * @as(u64, request.maximum_file) or
            result.download_bytes > 128 * @as(u64, request.maximum_file)) return error.InvalidJob;
        return result;
    }
};

pub const Spec = struct {
    binding: [32]u8,
    value: union(Kind) { blob: request.Request, pages: request.DiskRequest },

    pub fn load(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory, job: Job) !Spec {
        var raw = try directory.readSensitive(io, allocator, job.request_name, request.maximum_request, null);
        defer raw.deinit();
        return .{
            .binding = hash(raw.bytes()),
            .value = switch (job.kind) {
                .blob => .{ .blob = try request.Request.parse(allocator, raw.bytes()) },
                .pages => .{ .pages = try request.DiskRequest.parse(allocator, raw.bytes()) },
            },
        };
    }

    pub fn deinit(self: *Spec) void {
        switch (self.value) {
            .blob => |*value| value.deinit(),
            .pages => |*value| value.deinit(),
        }
    }

    pub fn plan(self: Spec) Plan {
        switch (self.value) {
            .pages => |value| {
                const pages = std.math.divCeil(u64, value.input.size, 4 * 1024 * 1024) catch unreachable;
                return .{ .requests = pages + 1, .mutations = pages, .bytes = value.input.size, .download_bytes = 512 };
            },
            .blob => |value| {
                var result: Plan = .{
                    .requests = value.records.len + @as(u64, @intFromBool(value.create_container)),
                    .mutations = if (value.action == .upload) value.records.len + @as(u64, @intFromBool(value.create_container)) else 0,
                    .bytes = 0,
                    .download_bytes = 0,
                };
                for (value.records) |record| switch (record) {
                    .upload => |item| result.bytes += item.input.size,
                    .download => |item| result.download_bytes += item.maximum,
                };
                return result;
            },
        }
    }
};

pub fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
