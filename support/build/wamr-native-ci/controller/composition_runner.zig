// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const runner = @import("default_test_runner");

pub const std_options = runner.std_options;

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch @panic("cannot read test arguments");
    if (args.len == 2 and std.mem.eql(u8, args[1], "--identity")) {
        @import("main.zig").main(init);
        return;
    }
    runner.main(init.minimal);
}
