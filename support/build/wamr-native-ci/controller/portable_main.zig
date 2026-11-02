// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const controller = @import("wamr_controller");

comptime {
    if (controller.profile.compiledCpuBaseline(builtin.target) == null)
        @compileError("uk-wamr-native-ci requires exactly x86_64-linux-gnu/x86_64_v2 or x86_64_v3");
}

pub fn main(init: std.process.Init) void {
    @import("main.zig").main(init);
}
