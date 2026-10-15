// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const input = @import("native-config-input.zig");

pub fn build(b: *std.Build) void {
    const path = b.option([]const u8, "config", "Tracked configuration input").?;
    const source = input.read(b, path) catch |err| {
        b.getInstallStep().dependOn(&b.addFail(@errorName(err)).step);
        return;
    };
    const generated = b.addWriteFiles().add("config-source", source);
    b.getInstallStep().dependOn(&b.addInstallFile(generated, "config-source").step);
}
