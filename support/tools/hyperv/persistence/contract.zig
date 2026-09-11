const std = @import("std");
const core = @import("hyperv_core");
const azure = @import("hyperv_azure");
const local = @import("local.zig");

pub const data_bytes: u64 = 4 * 1024 * 1024 * 1024;
pub const data_sectors = 8388608;
pub const stage_limit = 256 * 1024 * 1024;
pub const control_limit = 2 * 1024 * 1024;
pub const serial_limit = 4 * 1024 * 1024;
pub const Contract = struct {
    contract: []const u8 = "uk.hyperv.persistence-input",
    schema_version: u8 = 1,
    run_id: local.Id,
    disk_id: local.Id,
    sectors: u64 = data_sectors,
    sector_size: u16 = 512,
    lun: u8 = 7,
    authority: azure.scope.Authority,
    cleanup_authority: azure.scope.Authority,
    prefix: []const u8,
    guest: File,
    data: File,
    bindings: Bindings,
    runtime_seconds: u32,
    cleanup_seconds: u32,
    operation_ms: u32,
    grant_seconds: u32 = 600,
    stage_bytes: u64,
    control_bytes: u64,

    pub fn validate(self: Contract) !void {
        if (!std.mem.eql(u8, self.contract, "uk.hyperv.persistence-input") or self.schema_version != 1)
            return error.UnknownSchema;
        try local.hex(&self.run_id, true);
        try local.hex(&self.disk_id, true);
        if (std.mem.eql(u8, &self.run_id, &self.disk_id)) return error.IdentityCollision;
        if (self.sectors != data_sectors or self.sector_size != 512 or self.lun != 7) return error.InvalidGeometry;
        try self.authority.validate();
        try self.cleanup_authority.validate();
        inline for (.{ "tenant", "subscription", "owner_run" }) |field| {
            if (!std.mem.eql(u8, &@field(self.authority, field), &@field(self.cleanup_authority, field))) return error.AuthorityMismatch;
        }
        if (!std.mem.eql(u8, self.authority.group, self.cleanup_authority.group) or
            !std.mem.eql(u8, self.authority.location, self.cleanup_authority.location)) return error.AuthorityMismatch;
        if (!std.mem.eql(u8, self.authority.location, "northeurope")) return error.InvalidEnvelope;
        try azure.scope.name(self.prefix);
        if (self.prefix.len < 6 or self.prefix.len > 32 or
            self.authority.group.len != self.prefix.len + 3 or
            !std.mem.startsWith(u8, self.authority.group, self.prefix) or
            !std.mem.endsWith(u8, self.authority.group, "-rg")) return error.InvalidEnvelope;
        if (self.runtime_seconds < 60 or self.runtime_seconds > 3600 or self.cleanup_seconds < 60 or
            self.cleanup_seconds > 1800 or self.operation_ms == 0 or self.operation_ms > 600000 or
            self.operation_ms > @as(u64, self.runtime_seconds) * 1000 or
            self.grant_seconds < 60 or self.grant_seconds > self.cleanup_seconds) return error.InvalidBudget;
        if (self.stage_bytes > stage_limit or self.control_bytes > control_limit or self.control_bytes > self.stage_bytes or
            self.guest.size > self.stage_bytes - self.control_bytes) return error.InvalidLedger;
        try self.guest.validate();
        try self.data.validate();
        if (self.data.size != data_bytes + 512 or self.guest.size < 1024 * 1024 + 512 or
            self.guest.size > stage_limit or (self.guest.size - 512) % (1024 * 1024) != 0 or
            std.mem.eql(u8, self.guest.path, self.data.path)) return error.InvalidGeometry;
        inline for (std.meta.fields(Bindings)) |field| try local.hex(&@field(self.bindings, field.name), true);
    }
};

pub const File = struct {
    path: []const u8,
    size: u64,
    sha256: local.Hash,
    footer_sha256: local.Hash,
    pub fn validate(self: File) !void {
        if (!std.fs.path.isAbsolute(self.path) or self.path.len > 4096 or
            std.mem.indexOfAny(u8, self.path, "\x00\r\n?#") != null) return error.InvalidFileBinding;
        try local.hex(&self.sha256, true);
        try local.hex(&self.footer_sha256, true);
    }
};
pub const Bindings = struct {
    source: local.Hash,
    producer: local.Hash,
    preparation: local.Hash,
    preflight: local.Hash,
    image: local.Hash,
    authority: local.Hash,
    route: local.Hash,
    trust: local.Hash,
};

/// This in-process capability is supplied by the integrated production loader,
/// not deserialized from a receipt, boolean, hash, CLI flag or worker response.
pub const TrustedInputs = struct {
    context: *anyopaque,
    validateFn: *const fn (*anyopaque, Contract, local.Hash, Lane) anyerror!void,
    pub const Lane = enum { execution, cleanup };
    pub fn validate(self: TrustedInputs, input: Contract, binding: local.Hash, lane: Lane) !void {
        try input.validate();
        try self.validateFn(self.context, input, binding, lane);
    }
};

pub fn requireProductionBindings() error{PreparationAndCompletedPreflightBindingsUnavailable}!void {
    return error.PreparationAndCompletedPreflightBindingsUnavailable;
}

pub fn load(allocator: std.mem.Allocator, io: std.Io, directory: core.private_files.Directory) !local.Document(Contract) {
    const bytes = try directory.read(io, allocator, "contract.json", local.maximum, null);
    defer allocator.free(bytes);
    const document = try local.Document(Contract).load(allocator, bytes);
    errdefer document.deinit();
    try document.value.validate();
    return document;
}
