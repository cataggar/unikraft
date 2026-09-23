// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const testing = std.testing;
const options = @import("test_options");
const build_tool = @import("wamr_aot_build");

const allocator = testing.allocator;
const io = testing.io;

test "installed foundation executable has a stable version and bounded refusal" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const version = try std.process.run(allocator, io, .{
        .argv = &.{ cli, "--version" },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
    });
    defer allocator.free(version.stdout);
    defer allocator.free(version.stderr);
    try testing.expectEqual(@as(u8, 0), version.term.exited);
    try testing.expectEqualStrings("uk-wamr-aot-build foundation/1\n", version.stdout);
    try testing.expectEqualStrings("", version.stderr);

    const repository = "/private/path-must-not-be-echoed";
    const refused = try std.process.run(allocator, io, .{
        .argv = &.{ cli, "verify", "--repository", repository },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
    });
    defer allocator.free(refused.stdout);
    defer allocator.free(refused.stderr);
    try testing.expectEqual(@as(u8, 2), refused.term.exited);
    try testing.expectEqualStrings("", refused.stdout);
    try testing.expectEqualStrings(
        "wamr_aot_build_failed category=foundation_only\n",
        refused.stderr,
    );
    try testing.expect(std.mem.indexOf(u8, refused.stderr, repository) == null);
}

test "tool selection preserves override PATH and retained-fd precedence" {
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.process_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("WAMR_CI_TOOL_FIXTURE_TOOL", fixture);
    var explicit = try build_tool.process.resolveTool(
        allocator,
        io,
        &environment,
        "fixture-tool",
    );
    defer explicit.close(allocator, io);
    try testing.expectEqualStrings(fixture, explicit.path);

    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    try temporary.dir.symLink(io, fixture, "fixture-tool", .{});
    const search = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(search);
    _ = environment.swapRemove("WAMR_CI_TOOL_FIXTURE_TOOL");
    try environment.put("PATH", search);
    var selected = try build_tool.process.resolveTool(
        allocator,
        io,
        &environment,
        "fixture-tool",
    );
    defer selected.close(allocator, io);
    try testing.expectEqualStrings(fixture, selected.path);

    const invalid_overrides = [_][]const u8{
        "",
        "relative",
        search,
        "/definitely/missing/wamr-aot-tool",
    };
    for (invalid_overrides) |invalid| {
        try environment.put("WAMR_CI_TOOL_FIXTURE_TOOL", invalid);
        try testing.expectError(
            error.InvalidToolOverride,
            build_tool.process.resolveTool(allocator, io, &environment, "fixture-tool"),
        );
    }

    try temporary.dir.createDir(io, "first", .fromMode(0o700));
    try temporary.dir.createDir(io, "second", .fromMode(0o700));
    const script = try temporary.dir.createFile(io, "first/fixture-tool", .{
        .permissions = .fromMode(0o700),
    });
    defer script.close(io);
    try script.setPermissions(io, .fromMode(0o700));
    try script.writePositionalAll(io, "#!/bin/false\n", 0);
    try temporary.dir.symLink(io, fixture, "second/fixture-tool", .{});
    const first = try std.fs.path.join(allocator, &.{ search, "first" });
    defer allocator.free(first);
    const second = try std.fs.path.join(allocator, &.{ search, "second" });
    defer allocator.free(second);
    const ordered_path = try std.mem.join(allocator, ":", &.{ first, second });
    defer allocator.free(ordered_path);
    _ = environment.swapRemove("WAMR_CI_TOOL_FIXTURE_TOOL");
    try environment.put("PATH", ordered_path);
    try testing.expectError(
        error.UnsupportedExecutableFormat,
        build_tool.process.resolveTool(allocator, io, &environment, "fixture-tool"),
    );

    const retained_file = try std.Io.Dir.openFileAbsolute(io, fixture, .{});
    defer retained_file.close(io);
    var retained_buffer: [64]u8 = undefined;
    const retained_path = try std.fmt.bufPrint(
        &retained_buffer,
        "/proc/self/fd/{d}",
        .{retained_file.handle},
    );
    try environment.put("WAMR_CI_TOOL_FIXTURE_TOOL", retained_path);
    var retained = try build_tool.process.resolveTool(
        allocator,
        io,
        &environment,
        "fixture-tool",
    );
    defer retained.close(allocator, io);
    try testing.expectEqualStrings(retained_path, retained.path);
}

test "supervised tool wrapper distinguishes success exit signal overflow and timeout" {
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.process_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("WAMR_CI_TOOL_FIXTURE", fixture);
    var tool = try build_tool.process.resolveTool(allocator, io, &environment, "fixture");
    defer tool.close(allocator, io);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try build_tool.process.initialize();

    var success = try run(&tool, &environment, temporary.dir, "success", 2000, 1024);
    defer success.deinit(allocator);
    try build_tool.process.requireSuccess(success);
    try testing.expectEqualStrings("fixture-success\n", success.stdout);

    var failure = try run(&tool, &environment, temporary.dir, "failure", 2000, 1024);
    defer failure.deinit(allocator);
    try testing.expectEqual(@as(u8, 7), failure.primary.exited);
    try testing.expectError(error.ToolFailed, build_tool.process.requireSuccess(failure));
    try testing.expectEqualStrings("private-fixture-failure\n", failure.stderr);

    var signalled = try run(&tool, &environment, temporary.dir, "signal", 2000, 1024);
    defer signalled.deinit(allocator);
    try testing.expect(signalled.primary == .signal);
    try testing.expectError(error.ToolFailed, build_tool.process.requireSuccess(signalled));

    var overflow = try run(&tool, &environment, temporary.dir, "stdout-flood", 2000, 64);
    defer overflow.deinit(allocator);
    try testing.expectEqual(.output_overflow, overflow.primary);
    try testing.expectError(error.ToolFailed, build_tool.process.requireSuccess(overflow));

    var timeout = try run(&tool, &environment, temporary.dir, "sleep", 20, 1024);
    defer timeout.deinit(allocator);
    try testing.expectEqual(.timeout, timeout.primary);
    try testing.expectError(error.ToolFailed, build_tool.process.requireSuccess(timeout));

    var recovered = try run(&tool, &environment, temporary.dir, "success", 2000, 1024);
    defer recovered.deinit(allocator);
    try build_tool.process.requireSuccess(recovered);
}

test "extractor accepts the repository's actual Git archive PAX stream" {
    const git = try std.process.run(allocator, io, .{
        .argv = &.{
            "git",
            "archive",
            "--format=tar",
            "HEAD",
            "support/apps/wamr-aot/fixture.zig",
        },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(git.stdout);
    defer allocator.free(git.stderr);
    try testing.expectEqual(@as(u8, 0), git.term.exited);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const archive = try temporary.dir.createFile(io, "git.tar", .{
        .permissions = .fromMode(0o600),
    });
    defer archive.close(io);
    try archive.setPermissions(io, .fromMode(0o600));
    try archive.writePositionalAll(io, git.stdout, 0);
    const archive_path = try temporary.dir.realPathFileAlloc(io, "git.tar", allocator);
    defer allocator.free(archive_path);
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    const destination = try std.fs.path.join(allocator, &.{ base, "export" });
    defer allocator.free(destination);
    _ = try build_tool.files.extractGitArchive(
        allocator,
        io,
        archive_path,
        destination,
        .{},
    );
    const extracted = try temporary.dir.readFileAlloc(
        io,
        "export/support/apps/wamr-aot/fixture.zig",
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(extracted);
    const source_path = try std.fs.path.join(
        allocator,
        &.{ options.repository_root, "support/apps/wamr-aot/fixture.zig" },
    );
    defer allocator.free(source_path);
    const source = try std.Io.Dir.cwd().readFileAlloc(
        io,
        source_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(source);
    try testing.expectEqualSlices(u8, source, extracted);
}

fn run(
    tool: *const build_tool.process.Tool,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
    mode: []const u8,
    timeout_ms: u64,
    output_limit: usize,
) !build_tool.process.CommandResult {
    return build_tool.process.run(allocator, io, tool.*, .{
        .argv = &.{ tool.path, mode },
        .environment = environment,
        .cwd = cwd,
        .primary_deadline = try build_tool.process.Deadline.afterMilliseconds(timeout_ms),
        .cleanup_deadline = try build_tool.process.Deadline.afterMilliseconds(5000),
        .stdout_bytes = output_limit,
        .stderr_bytes = output_limit,
    });
}
