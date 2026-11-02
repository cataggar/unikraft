// SPDX-License-Identifier: BSD-3-Clause
pub const input = @import("input.zig");
pub const base64 = @import("base64.zig");
pub const serial = @import("local_boot_serial");
pub const records = @import("records.zig");
pub const tiny = @import("tiny.zig");
pub const coremark = @import("coremark.zig");
pub const optional = @import("optional.zig");
pub const sampler = @import("sampler.zig");

const std = @import("std");

pub const Request = union(enum) {
    tiny: tiny.LegacyApic,
    workload: optional.Mode,
};

pub const Validation = struct {
    raw_serial_bytes: usize,
    raw_serial_sha256: [32]u8,
    compute: ?tiny.Result = null,
    prepared: ?records.PreparedIdentity = null,

    pub fn deinit(self: *Validation) void {
        if (self.prepared) |*identity| identity.deinit();
        self.* = undefined;
    }
};

/// Both files are read as bounded, immutable snapshots before parsing. The tiny
/// result borrows strings from the retained prepared identity until deinit.
pub fn validate(
    allocator: std.mem.Allocator,
    io: std.Io,
    log_path: []const u8,
    identity_path: []const u8,
    request: Request,
) !Validation {
    var identity_input = try input.read(allocator, io, identity_path, .identity);
    defer identity_input.deinit();
    var log_input = try input.read(allocator, io, log_path, switch (request) {
        .tiny => .tiny_serial,
        .workload => .optional_serial,
    });
    defer log_input.deinit();
    switch (request) {
        .tiny => |legacy| {
            var prepared = try records.PreparedIdentity.parse(allocator, identity_input.bytes);
            errdefer prepared.deinit();
            const result = try tiny.checkSerial(allocator, log_input.bytes, prepared.value, .{
                .legacy_apic = legacy,
            });
            return .{
                .raw_serial_bytes = log_input.bytes.len,
                .raw_serial_sha256 = log_input.sha256,
                .compute = result,
                .prepared = prepared,
            };
        },
        .workload => |mode| {
            var prepared = try records.OptionalIdentity.parse(allocator, identity_input.bytes);
            defer prepared.deinit();
            const result = try optional.checkSerial(allocator, log_input.bytes, prepared, mode);
            if (result.raw_serial_bytes != log_input.bytes.len or
                !std.mem.eql(u8, &result.raw_serial_sha256, &log_input.sha256))
                return error.RawSerialChanged;
            return .{
                .raw_serial_bytes = result.raw_serial_bytes,
                .raw_serial_sha256 = result.raw_serial_sha256,
            };
        },
    }
}
