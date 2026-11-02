// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");

// Compile-only native API exercise; this program is never installed or run.
pub fn main(init: std.process.Init) void {
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch return;
    if (args.len != 2) return;
    var input = validator.input.read(allocator, init.io, args[1], .identity) catch return;
    defer input.deinit();
    const decoded = validator.base64.decode(allocator, input.bytes, 4096) catch return;
    defer allocator.free(decoded);
    const text = validator.serial.normalizeWithOptions(allocator, input.bytes, .tiny) catch return;
    allocator.free(text);
}
