// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const azure_runtime = @import("azure_runtime.zig");
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    execute(init) catch |err| {
        const stderr = std.Io.File.stderr();
        stderr.writeStreamingAll(
            init.io,
            "OVERFLOW_OWNER_FIXTURE_FAILED:",
        ) catch {};
        stderr.writeStreamingAll(init.io, @errorName(err)) catch {};
        stderr.writeStreamingAll(init.io, "\n") catch {};
        std.process.exit(1);
    };
}

fn execute(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len == 2 and
        std.mem.eql(u8, arguments[1], "--child-marker-controller"))
    {
        azure_runtime.ensureNamespace(init) catch |err| switch (err) {
            error.AzureRuntimeNamespaceMarkerInvalid => return,
            else => return err,
        };
        return error.ChildMarkerAcceptedByController;
    }
    if (arguments.len == 2 and
        std.mem.eql(u8, arguments[1], "--forged-marker"))
    {
        if (init.environ_map.get(core.private_files.namespace_marker) != null) {
            core.private_files.enterUserNamespaceFromEnvironment(
                init.io,
                init.environ_map,
            ) catch |err| switch (err) {
                error.InvalidNamespaceParentMap => return,
                else => return err,
            };
            return error.ForgedMarkerAccepted;
        }
        return forgeMarker();
    }
    try azure_runtime.ensureNamespace(init);
    if (arguments.len == 2 and
        std.mem.eql(u8, arguments[1], "--system-preload"))
        return systemPreload();

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

fn systemPreload() !void {
    if (linux.errno(linux.mount(
        "tmpfs",
        "/etc",
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        @intFromPtr("mode=0700,size=4096,nr_inodes=2"),
    )) != .SUCCESS) return error.PreloadFixtureMountFailed;
    const file = linux.openat(linux.AT.FDCWD, "/etc/ld.so.preload", .{
        .ACCMODE = .WRONLY,
        .CLOEXEC = true,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
    }, 0o600);
    if (linux.errno(file) != .SUCCESS)
        return error.PreloadFixtureCreateFailed;
    _ = linux.close(@intCast(file));
    azure_runtime.Test.rejectLoaderPreload() catch |err| switch (err) {
        error.SystemLoaderPreloadPresent => return,
        else => return err,
    };
    return error.SystemPreloadAccepted;
}

fn forgeMarker() !void {
    const uid = linux.geteuid();
    const gid = linux.getegid();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS)
        return error.ForkFailed;
    if (forked == 0) {
        createNamespace(uid, gid) catch linux.exit_group(126);
        const marked = linux.fork();
        if (linux.errno(marked) != .SUCCESS)
            linux.exit_group(126);
        if (marked == 0) execMarked(uid, gid);
        linux.exit_group(waitFor(marked) catch 126);
    }
    if (try waitFor(forked) != 0)
        return error.ForgedMarkerWasNotRejected;
}

fn createNamespace(uid: u32, gid: u32) !void {
    if (linux.errno(linux.unshare(linux.CLONE.NEWUSER)) != .SUCCESS)
        return error.NamespaceUnavailable;
    var uid_buffer: [64]u8 = undefined;
    var gid_buffer: [64]u8 = undefined;
    try writeMap("/proc/self/setgroups", "deny\n");
    try writeMap(
        "/proc/self/uid_map",
        try std.fmt.bufPrint(&uid_buffer, "0 {d} 1\n", .{uid}),
    );
    try writeMap(
        "/proc/self/gid_map",
        try std.fmt.bufPrint(&gid_buffer, "0 {d} 1\n", .{gid}),
    );
    if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS or
        linux.errno(linux.mount(
            null,
            "/",
            null,
            linux.MS.REC | linux.MS.PRIVATE,
            0,
        )) != .SUCCESS)
        return error.NamespaceUnavailable;
}

fn execMarked(uid: u32, gid: u32) noreturn {
    var uid_buffer: [64:0]u8 = undefined;
    var gid_buffer: [64:0]u8 = undefined;
    var parent_buffer: [64:0]u8 = undefined;
    const uid_entry = std.fmt.bufPrintZ(
        &uid_buffer,
        core.private_files.namespace_uid ++ "={d}",
        .{uid},
    ) catch linux.exit_group(126);
    const gid_entry = std.fmt.bufPrintZ(
        &gid_buffer,
        core.private_files.namespace_gid ++ "={d}",
        .{gid},
    ) catch linux.exit_group(126);
    const parent_entry = std.fmt.bufPrintZ(
        &parent_buffer,
        core.private_files.namespace_parent ++ "={d}",
        .{linux.getppid()},
    ) catch linux.exit_group(126);
    const arguments = [_:null]?[*:0]const u8{
        "/proc/self/exe",
        "--forged-marker",
    };
    const environment = [_:null]?[*:0]const u8{
        core.private_files.namespace_marker ++ "=" ++
            core.private_files.namespace_controller,
        uid_entry.ptr,
        gid_entry.ptr,
        parent_entry.ptr,
    };
    _ = linux.execve(
        "/proc/self/exe",
        &arguments,
        &environment,
    );
    linux.exit_group(126);
}

fn writeMap(path: [*:0]const u8, bytes: []const u8) !void {
    const opened = linux.openat(linux.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS)
        return error.NamespaceUnavailable;
    defer _ = linux.close(@intCast(opened));
    if (linux.write(@intCast(opened), bytes.ptr, bytes.len) != bytes.len)
        return error.NamespaceUnavailable;
}

fn waitFor(pid: usize) !u8 {
    while (true) {
        var status: u32 = 0;
        const waited = linux.waitpid(@intCast(pid), &status, 0);
        switch (linux.errno(waited)) {
            .SUCCESS => {
                if (!linux.W.IFEXITED(status))
                    return error.ChildFailed;
                return linux.W.EXITSTATUS(status);
            },
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
}
