// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");

comptime {
    const baseline = std.Target.x86.cpu.x86_64_v2.toCpu(.x86_64);
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux or
        builtin.abi != .gnu or
        !std.mem.eql(u8, builtin.cpu.model.name, baseline.model.name) or
        !builtin.cpu.features.eql(baseline.features))
        @compileError("uk-wamr-native-ci requires exactly x86_64-linux-gnu/x86_64_v2");
}

pub fn main(init: std.process.Init) void {
    @import("main.zig").main(init);
}
