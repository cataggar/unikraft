// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const native_make_environment = @import("native_make_environment");

pub const MakeEnvironment = native_make_environment.Contract;

pub fn encodeMakeEnvironment(
    allocator: std.mem.Allocator,
    environment: MakeEnvironment,
) ![]u8 {
    return native_make_environment.encode(allocator, environment);
}
