// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const profile = @import("profile.zig");

pub fn portableQuery() std.Target.Query {
    const target = profile.executable_target[0];
    const cpu = profile.executable_target[1];
    comptime {
        if (!std.mem.startsWith(u8, target, "-Dtarget=") or
            !std.mem.startsWith(u8, cpu, "-Dcpu="))
            @compileError("invalid controller executable target flags");
    }
    return std.Target.Query.parse(.{
        .arch_os_abi = target["-Dtarget=".len..],
        .cpu_features = cpu["-Dcpu=".len..],
    }) catch unreachable;
}

pub fn permitsInstall(requested: std.Target.Query, optimize: std.builtin.OptimizeMode) bool {
    return requested.eql(portableQuery()) and optimize == .ReleaseSafe;
}
