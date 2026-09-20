// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const azure_runtime = @import("azure_runtime.zig");

pub fn main(init: std.process.Init) void {
    execute(init) catch {
        std.Io.File.stderr().writeStreamingAll(
            init.io,
            "OVERFLOW_OWNER_FIXTURE_FAILED\n",
        ) catch {};
        std.process.exit(1);
    };
}

fn execute(init: std.process.Init) !void {
    try azure_runtime.ensureNamespace(init);

    const files = core.private_files;
    const path = "/usr/bin/bash";
    var artifact = try files.RetainedFile.open(init.io, path, .artifact);
    defer artifact.close(init.io);
    try artifact.verify(init.io);
    if (!files.isNamespaceOverflowUid(artifact.file_snapshot.uid))
        return error.ExpectedOverflowOwner;

    if (files.RetainedFile.open(init.io, path, .tool)) |value| {
        var tool = value;
        tool.close(init.io);
        return error.OverflowToolAccepted;
    } else |err| switch (err) {
        error.UnsafeFile => {},
        else => return err,
    }
}
