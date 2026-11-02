// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const fixtures = @import("local_acceptance_tests.zig");

pub fn main(init: std.process.Init) !void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const a = init.arena.allocator();
    try fixtures.runWorker(a, init.io, try init.minimal.args.toSlice(a));
}
