//! Uninstalled, unprivileged probe of the same root-gated shared hooks.
const std = @import("std");
pub const namespace_fixture_observer = @import("namespace_internal_observer.zig");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3) return error.InvalidProbeArguments;
    const mode = std.meta.stringToEnum(@import("namespace_tests.zig").InternalProbe, args[1]) orelse return error.InvalidProbeArguments;
    const directory = try @import("files.zig").Directory.open(a, init.io, args[2]);
    defer directory.close(a, init.io);
    try @import("namespace_tests.zig").internalProbe(a, init.io, directory, mode);
}
