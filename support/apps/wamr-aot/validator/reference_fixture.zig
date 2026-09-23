// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");

// Test-only process interface for differential comparison, never installed.
pub fn main(init: std.process.Init) void {
    const allocator = init.arena.allocator();
    const arguments = init.minimal.args.toSlice(allocator) catch std.process.exit(1);
    if (arguments.len == 3 and std.mem.eql(u8, arguments[1], "base64")) {
        const decoded = validator.base64.decode(allocator, arguments[2], 4096) catch std.process.exit(1);
        var output = std.Io.File.stdout().writer(init.io, &.{});
        output.interface.writeAll(decoded) catch std.process.exit(1);
        output.interface.flush() catch std.process.exit(1);
        return;
    }
    if (arguments.len != 3 or arguments[2].len % 2 != 0 or arguments[2].len > 65536)
        std.process.exit(1);
    const mode: validator.serial.Normalization = if (std.mem.eql(u8, arguments[1], "tiny"))
        .tiny
    else if (std.mem.eql(u8, arguments[1], "optional"))
        .optional
    else
        std.process.exit(1);
    const raw = allocator.alloc(u8, arguments[2].len / 2) catch std.process.exit(1);
    _ = std.fmt.hexToBytes(raw, arguments[2]) catch std.process.exit(1);
    const normalized = validator.serial.normalizeWithOptions(allocator, raw, mode) catch std.process.exit(1);
    var stdout = std.Io.File.stdout().writer(init.io, &.{});
    stdout.interface.writeAll(normalized) catch std.process.exit(1);
    stdout.interface.flush() catch std.process.exit(1);
}
