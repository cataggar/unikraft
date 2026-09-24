// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");

// Test-only differential process; never installed or invoked by production.
pub fn main(init: std.process.Init) void {
    const a = init.arena.allocator();
    const args = init.minimal.args.toSlice(a) catch std.process.exit(1);
    if (args.len != 4) std.process.exit(1);
    const mode = std.meta.stringToEnum(validator.optional.Mode, args[1]) orelse std.process.exit(1);
    const identity_raw = hex(a, args[2]) catch std.process.exit(1);
    var identity = validator.records.OptionalIdentity.parse(a, identity_raw) catch std.process.exit(1);
    defer identity.deinit();
    const raw = hex(a, args[3]) catch std.process.exit(1);
    const result = validator.optional.checkSerial(a, raw, identity, mode) catch std.process.exit(1);
    const normalized = validator.serial.normalizeWithOptions(a, raw, .optional) catch std.process.exit(1);
    var sequence: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, normalized, '\n');
    while (lines.next()) |line|
        if (std.mem.startsWith(u8, line, "WAMR_"))
            sequence.append(a, line) catch std.process.exit(1);
    var writer = std.Io.File.stdout().writer(init.io, &.{});
    std.json.Stringify.value(.{
        .raw_serial_bytes = result.raw_serial_bytes,
        .raw_serial_sha256 = std.fmt.bytesToHex(result.raw_serial_sha256, .lower),
        .record_sequence = sequence.items,
    }, .{}, &writer.interface) catch std.process.exit(1);
    writer.interface.flush() catch std.process.exit(1);
}

fn hex(a: std.mem.Allocator, source: []const u8) ![]u8 {
    if (source.len % 2 != 0 or source.len > 128 * 1024) return error.InputLimit;
    const bytes = try a.alloc(u8, source.len / 2);
    _ = try std.fmt.hexToBytes(bytes, source);
    return bytes;
}
