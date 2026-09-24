// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");
const core = @import("hyperv_core");

// Test-only differential process; no installed or production CLI.
pub fn main(init: std.process.Init) void {
    const a = init.arena.allocator();
    const args = init.minimal.args.toSlice(a) catch std.process.exit(1);
    if (args.len == 3 and std.mem.eql(u8, args[1], "coremark-output")) {
        const output = hex(a, args[2]) catch std.process.exit(1);
        validator.coremark.validateOutput(output) catch std.process.exit(1);
        return;
    }
    if (args.len != 4) std.process.exit(1);
    const identity_bytes = hex(a, args[2]) catch std.process.exit(1);
    var identity = validator.records.PreparedIdentity.parse(a, identity_bytes) catch std.process.exit(1);
    defer identity.deinit();
    const raw = hex(a, args[3]) catch std.process.exit(1);
    const options: validator.tiny.Options =
        if (std.mem.eql(u8, args[1], "direct")) .{ .scope = .direct } else if (std.mem.eql(u8, args[1], "app")) .{} else if (std.mem.eql(u8, args[1], "app-required")) .{ .legacy_apic = .required } else if (std.mem.eql(u8, args[1], "app-forbidden")) .{ .legacy_apic = .forbidden } else std.process.exit(1);
    const result = validator.tiny.checkSerial(a, raw, identity.value, options) catch std.process.exit(1);
    const normalized = validator.serial.normalizeWithOptions(a, raw, .tiny) catch std.process.exit(1);
    var record_sequence: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, normalized, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, validator.tiny.prefix) or
            std.mem.startsWith(u8, line, validator.tiny.wasi_prefix) or
            std.mem.eql(u8, line, validator.tiny.marker))
            record_sequence.append(a, line) catch std.process.exit(1);
    }
    var digest: [32]u8 = undefined;
    core.Sha256.hash(raw, &digest, .{});
    var writer = std.Io.File.stdout().writer(init.io, &.{});
    std.json.Stringify.value(.{
        .result = result,
        .raw_serial_bytes = raw.len,
        .raw_serial_sha256 = std.fmt.bytesToHex(digest, .lower),
        .record_sequence = record_sequence.items,
    }, .{}, &writer.interface) catch std.process.exit(1);
    writer.interface.flush() catch std.process.exit(1);
}

fn hex(a: std.mem.Allocator, source: []const u8) ![]u8 {
    if (source.len % 2 != 0 or source.len > 64 * 1024) return error.InputLimit;
    const bytes = try a.alloc(u8, source.len / 2);
    _ = try std.fmt.hexToBytes(bytes, source);
    return bytes;
}
