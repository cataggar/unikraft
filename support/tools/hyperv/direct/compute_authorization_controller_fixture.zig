// SPDX-License-Identifier: BSD-3-Clause
//! Offline phase gate for authorization custody tests; never installed.
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("controller.zig");
const custody = @import("custody.zig");
const direct = @import("compute.zig");
const runtime = @import("runtime.zig");

pub const wamr_direct_compute = true;

const GatedNative = struct {
    ready: []const u8,
    release: []const u8,

    pub const References = controller.Native.References;

    pub fn references(
        _: GatedNative,
        io: std.Io,
        scope: direct.Scope,
        programs: runtime.Programs,
    ) !References {
        return (controller.Native{}).references(io, scope, programs);
    }

    pub fn environment(
        _: GatedNative,
        allocator: std.mem.Allocator,
        operator: *const std.process.Environ.Map,
    ) !runtime.Environment {
        return (controller.Native{}).environment(allocator, operator);
    }

    pub fn checkHashFault(
        _: GatedNative,
        store: *custody.Store,
        name: []const u8,
    ) !u8 {
        return (controller.Native{}).checkHashFault(store, name);
    }

    pub fn sleep(_: GatedNative, io: std.Io, milliseconds: u64) !void {
        return (controller.Native{}).sleep(io, milliseconds);
    }

    pub fn beforeStartup(self: GatedNative, io: std.Io) !void {
        const ready_parent = try core.private_files.FileParent.open(io, self.ready, .private);
        defer ready_parent.close(io);
        const ready = try ready_parent.directory.createFile(
            io,
            ready_parent.name,
            .{
                .read = true,
                .exclusive = true,
                .permissions = .fromMode(0o600),
            },
        );
        defer ready.close(io);
        try ready.writePositionalAll(io, "ready\n", 0);
        try ready.sync(io);
        try ready_parent.sync(io);

        const release_parent = try core.private_files.FileParent.open(io, self.release, .private);
        defer release_parent.close(io);
        while (true) {
            const release = release_parent.openFile(io) catch |err| switch (err) {
                error.FileNotFound => {
                    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
                    continue;
                },
                else => return err,
            };
            release.close(io);
            break;
        }
    }
};

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const status = run(init) catch |err| {
        @import("launcher.zig").report(init, err);
        std.process.exit(1);
    };
    var writer = std.Io.File.stderr().writerStreaming(init.io, &.{});
    writer.interface.writeAll(if (status == 0)
        "Authorization fixture unexpectedly completed.\n"
    else
        "Authorization fixture refused; inspect private attempt records.\n") catch
        std.process.exit(1);
    std.process.exit(status);
}

fn run(init: std.process.Init) !u8 {
    const ready = init.environ_map.get("UK_WAMR_AUTHORIZATION_GATE_READY") orelse
        return error.MissingFixtureGate;
    const release = init.environ_map.get("UK_WAMR_AUTHORIZATION_GATE_RELEASE") orelse
        return error.MissingFixtureGate;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    return controller.execute(
        GatedNative,
        GatedNative{ .ready = ready, .release = release },
        init,
        try controller.Inputs.parse(args[1..]),
    );
}
