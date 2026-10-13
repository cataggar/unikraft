// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const controller = @import("wamr_controller");
const plan = @import("plan.zig");
const tx = @import("transaction.zig");

test {
    std.testing.refAllDecls(plan);
    _ = @import("foundation_tests.zig");
}

test "physical private receipt cannot acquire imported candidate authority" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const parent = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "plan-receipt-negative-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("plan negative fixture cleanup failed");
    const path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name });
    defer a.free(path);
    const dir = try core.private_files.Directory.open(io, path);
    defer dir.close(io);
    const receipt = try dir.dir.createFile(io, "transport.json", .{ .permissions = .fromMode(0o600) });
    defer receipt.close(io);
    try receipt.writeStreamingAll(
        io,
        "{\"artifact_id\":\"1\",\"container_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"inner_zip_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"repository\":\"cataggar/unikraft\",\"run_attempt\":\"1\",\"run_id\":\"1\",\"schema\":\"uk.wamr.public-source-transport\",\"source_revision\":\"0123456789012345678901234567890123456789\",\"source_tree\":\"0123456789012345678901234567890123456789\",\"version\":2}\n",
    );
    try std.testing.expectError(error.FileNotFound, controller.accepted_run.PrivateBundle.open(
        a,
        io,
        &dir,
        path,
        path,
        .{ .git = "/absent/git", .supervisor = "/absent/controller", .validator = "/absent/validator" },
        null,
    ));
    try std.testing.expectError(error.FileNotFound, dir.dir.openFile(io, "plan.json", .{}));
    try std.testing.expectError(error.FileNotFound, dir.dir.openFile(io, "approval-template.json", .{}));
}

const RecordChecks = struct {
    first: *tx.Record,
    second: *tx.Record,
    fn check(raw: *anyopaque) !void {
        const self: *RecordChecks = @ptrCast(@alignCast(raw));
        try self.first.revalidate(null);
        try self.second.revalidate(null);
    }
};

test "real descriptor-supervised plan validator preserves malformed-record refusal and cleanup" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const ctx: @import("types.zig").Context = .{ .allocator = a, .io = io };
    const parent = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "plan-validator-negative-{d}", .{std.os.linux.getpid()});
    defer a.free(name);
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("plan validator fixture cleanup failed");
    const dir = try parent.openDir(io, name, .{});
    defer dir.close(io);
    for ([_][]const u8{ "plan.json", "template.json" }) |file_name| {
        const file = try dir.createFile(io, file_name, .{ .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, "{}\n");
    }
    const first_path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name, "plan.json" });
    defer a.free(first_path);
    const second_path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name, "template.json" });
    defer a.free(second_path);
    var first = try tx.Record.open(ctx, first_path, 65536);
    defer first.deinit();
    var second = try tx.Record.open(ctx, second_path, 65536);
    defer second.deinit();
    var checks: RecordChecks = .{ .first = &first, .second = &second };
    try std.testing.expectError(error.UnexpectedFields, @import("types.zig").compute.verifyPlan(a, io, first_path, second_path));
    const validator_path = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").validator, a);
    defer a.free(validator_path);
    var validator = try core.private_files.RetainedFile.open(io, validator_path, .tool);
    defer validator.close(io);
    const executable = try core.process.Executable.fromFile(io, validator.file);
    defer executable.close(io);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try core.process.initialize();
    const primary = try core.process.Deadline.afterMilliseconds(5000);
    var result = try tx.supervise(ctx, .{
        .executable = executable,
        .argv = &.{ validator.path, "plan", first_path, second_path },
        .environment = &environment,
        .cwd = dir,
        .primary_deadline = primary,
        .cleanup_deadline = .{ .expires_ns = primary.expires_ns + 5 * std.time.ns_per_s },
        .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
    }, .{ .context = &checks, .check = RecordChecks.check });
    defer result.deinit(a);
    try std.testing.expect(!result.succeeded());
    try std.testing.expectEqual(@as(u8, 1), result.result.primary.exited);
    try std.testing.expectEqualStrings("", result.result.stdout);
    try std.testing.expectEqualStrings("WAMR direct validation refused: UnexpectedFields\n", result.result.stderr);
    try std.testing.expect(result.result.cleanup_complete and result.freshness == null);
    try RecordChecks.check(&checks);
}
