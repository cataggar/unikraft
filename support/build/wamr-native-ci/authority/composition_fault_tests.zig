// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const authority = @import("root.zig");
const Fixture = @import("composition_tests.zig").Fixture;
const a = std.testing.allocator;
const io = std.testing.io;
const linux = std.os.linux;
var target: ?linux.fd_t = null;
var target_identity: core.private_files.Snapshot = undefined;
var calls: u8 = 0;
var mode: enum { zero, overrun, short, sync, cancel, replace, manifest_replace, failure_zero, failure_cancel, failure_short } = .zero;
var active_fixture: ?*Fixture = null;

fn write(userdata: ?*anyopaque, file: std.Io.File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) std.Io.File.WritePositionalError!usize {
    const failure_mode = mode == .failure_zero or mode == .failure_cancel or mode == .failure_short;
    if (target == null and offset == 0 and data.len != 0 and
        (if (failure_mode)
            std.mem.indexOf(u8, data[0], "uk.wamr.azure-runtime-source-failure") != null
        else
            std.mem.startsWith(u8, data[0], @import("contracts.zig").manifest.header)))
    {
        target = file.handle;
        target_identity = core.private_files.snapshot(file) catch return error.InputOutput;
    }
    if (!matches(file)) return io.vtable.fileWritePositional(userdata, file, header, data, splat, offset);
    calls +|= 1;
    if (mode == .zero or mode == .failure_zero) {
        // The unfixed write-all loop fails on its next call instead of hanging.
        if (calls == 1) return 0;
        return error.InputOutput;
    }
    if (mode == .overrun) return data[0].len + 1;
    if (mode == .failure_cancel and calls > 8) return error.InputOutput;
    const result = try io.vtable.fileWritePositional(userdata, file, &.{}, &.{data[0][0..@min(7, data[0].len)]}, 1, offset);
    if (mode == .cancel and calls == 3) {
        if (linux.errno(linux.kill(linux.getpid(), .INT)) != .SUCCESS) return error.InputOutput;
    }
    if (mode == .replace and calls == 1) {
        const fixture = active_fixture.?;
        fixture.dir.rename("azure", fixture.dir, "original-azure", io) catch return error.InputOutput;
        const replacement = fixture.dir.createFile(io, "azure", .{ .exclusive = true, .permissions = .fromMode(0o500) }) catch return error.InputOutput;
        defer replacement.close(io);
        replacement.writeStreamingAll(io, "not executable Python; source-negative only\n") catch return error.InputOutput;
    }
    if (mode == .manifest_replace and calls == 1) {
        const fixture = active_fixture.?;
        fixture.dir.rename("output/azure-runtime.manifest", fixture.dir, "output/original-manifest", io) catch return error.InputOutput;
        const replacement = fixture.dir.createFile(io, "output/azure-runtime.manifest", .{ .exclusive = true, .permissions = .fromMode(0o600) }) catch return error.InputOutput;
        defer replacement.close(io);
        replacement.writeStreamingAll(io, data[0][0..result]) catch return error.InputOutput;
    }
    return result;
}
fn checkCancel(userdata: ?*anyopaque) std.Io.Cancelable!void {
    if (mode == .failure_cancel and calls >= 3) return error.Canceled;
    try io.vtable.checkCancel(userdata);
}
fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    if (mode == .sync and matches(file)) {
        target = null;
        return error.InputOutput;
    }
    return io.vtable.fileSync(userdata, file);
}

fn matches(file: std.Io.File) bool {
    if (target != file.handle) return false;
    const snapshot = core.private_files.snapshot(file) catch return false;
    return snapshot.ino == target_identity.ino and snapshot.dev_major == target_identity.dev_major and snapshot.dev_minor == target_identity.dev_minor;
}

test "joined manifest writer refuses zero or overreported progress and fsync uncertainty but completes actual short writes" {
    for (0..4) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        calls = 0;
        target = null;
        mode = switch (case) {
            0 => .zero,
            1 => .overrun,
            2 => .short,
            else => .sync,
        };
        var table = io.vtable.*;
        table.fileWritePositional = write;
        table.fileSync = sync;
        const injected: std.Io = .{ .userdata = io.userdata, .vtable = &table };
        const outcome = authority.prepare.run(.{ .allocator = a, .io = injected }, fixture.request, fixture.discovery());
        try std.testing.expect(outcome == .poisoned);
        const diagnostic = outcome.poisoned;
        try std.testing.expectEqual(if (case == 0) error.ManifestWriteNoProgress else if (case == 1) error.InvalidManifestWriteProgress else if (case == 2) error.InvalidElf else error.InputOutput, diagnostic.err);
        try std.testing.expectEqual(if (case == 2) core.private_files.CommitStatus.durable else core.private_files.CommitStatus.visible_not_durable, diagnostic.publications.manifest);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, diagnostic.publications.output);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.failure);
        if (case < 2) try std.testing.expectEqual(@as(u8, 1), calls);
        if (case == 2) try std.testing.expect(calls > 3);
    }
}

test "joined manifest short writes refuse cancellation and source or manifest replacement before further progress" {
    for (0..3) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        active_fixture = &fixture;
        defer active_fixture = null;
        var cancellation = try core.process.SignalCancellation.install();
        defer cancellation.deinit();
        calls = 0;
        target = null;
        mode = if (case == 0) .cancel else if (case == 1) .replace else .manifest_replace;
        var table = io.vtable.*;
        table.fileWritePositional = write;
        const injected: std.Io = .{ .userdata = io.userdata, .vtable = &table };
        const outcome = authority.prepare.run(.{ .allocator = a, .io = injected, .signal = &cancellation }, fixture.request, fixture.discovery());
        try std.testing.expect(outcome == .poisoned);
        try std.testing.expectEqual(if (case == 0) error.Cancelled else if (case == 1) error.FileChanged else error.ManifestChanged, outcome.poisoned.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.visible_not_durable, outcome.poisoned.publications.manifest);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.poisoned.publications.pending);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.poisoned.publications.output);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publications.failure);
        try std.testing.expectEqual(@as(u8, if (case == 0) 3 else 1), calls);
    }
}

test "joined refusal transaction bounds zero progress and IO cancellation without replacing the primary failure" {
    for (0..3) |case| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        calls = 0;
        target = null;
        mode = switch (case) {
            0 => .failure_zero,
            1 => .failure_cancel,
            else => .failure_short,
        };
        var table = io.vtable.*;
        table.fileWritePositional = write;
        table.checkCancel = checkCancel;
        const injected: std.Io = .{ .userdata = io.userdata, .vtable = &table };
        const outcome = authority.prepare.run(.{ .allocator = a, .io = injected }, fixture.request, fixture.discovery());
        try std.testing.expect(outcome == .poisoned);
        try std.testing.expectEqual(error.InvalidElf, outcome.poisoned.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publications.manifest);
        try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publications.pending);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.poisoned.publications.output);
        if (case == 2) {
            try std.testing.expect(outcome.poisoned.recording_error == null);
            try std.testing.expectEqual(core.private_files.CommitStatus.durable, outcome.poisoned.publications.failure);
            try std.testing.expect(calls > 3);
        } else {
            try std.testing.expect(outcome.poisoned.recording_error != null);
            try std.testing.expectEqual(if (case == 0) error.WriteNoProgress else error.Canceled, outcome.poisoned.recording_error.?);
            try std.testing.expectEqual(@as(u8, if (case == 0) 1 else 3), calls);
            try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.poisoned.publications.failure);
        }
    }
}

test "joined expired publication deadline retains the primary refusal and durably records through a fresh deadline" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const expired: core.process.Deadline = .{ .expires_ns = 0 };
    const outcome = authority.prepare.run(.{
        .allocator = a,
        .io = io,
        .publication_deadline = expired,
    }, fixture.request, fixture.discovery());
    try std.testing.expect(outcome == .poisoned);
    const failure = outcome.poisoned;
    try std.testing.expectEqual(error.DeadlineExceeded, failure.err);
    try std.testing.expectEqual(authority.types.Phase.publication, failure.phase);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, failure.publications.copy);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, failure.publications.manifest);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, failure.publications.pending);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, failure.publications.output);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, failure.publications.failure);
    try std.testing.expect(failure.recording_error == null);
    const bytes = try fixture.dir.readFileAlloc(io, "output/azure-runtime.failure.json", a, .limited(4096));
    defer a.free(bytes);
    var document = try core.contracts.Document.parse(a, bytes, authority.contracts.json_limits);
    defer document.deinit();
    try std.testing.expectEqualStrings("DeadlineExceeded", document.value().object.get("err").?.string);
    try std.testing.expectEqualStrings("publication", document.value().object.get("phase").?.string);
}
