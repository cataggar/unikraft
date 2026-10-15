const std = @import("std");
const options = @import("test_options");

fn ignoredSource(allocator: std.mem.Allocator) ![]u8 {
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ options.git_executable, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z" },
        .cwd = .{ .path = options.repository_root },
        .stdout_limit = .limited(32 * 1024),
        .stderr_limit = .limited(32 * 1024),
    });
    errdefer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try std.testing.expectEqual(@as(usize, 0), result.stderr.len);
    return result.stdout;
}

test "install-controller rejects incompatible build flags without creating output" {
    const allocator = std.testing.allocator;
    const ignored = try ignoredSource(allocator);
    defer allocator.free(ignored);
    const package = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, options.miz_package, allocator);
    defer allocator.free(package);
    const packages = std.fs.path.dirname(package) orelse return error.MissingPackageRoot;
    const cache = try std.fs.path.join(allocator, &.{ options.fixture_root, "install-target-work", "cache" });
    defer allocator.free(cache);
    const global = try std.fs.path.join(allocator, &.{ options.fixture_root, "install-target-work", "global" });
    defer allocator.free(global);
    const runtime = try std.fs.path.join(allocator, &.{ options.repository_root, ".d/controller-invalid-target" });
    defer allocator.free(runtime);
    const runtime_flag = try allocator.print("-Dcontroller-runtime={s}", .{runtime});
    defer allocator.free(runtime_flag);
    const build_file = try std.fs.path.join(allocator, &.{
        options.repository_root, "support/build/wamr-native-ci/build.zig",
    });
    defer allocator.free(build_file);
    var environ_map = try std.testing.environ.createMap(allocator);
    defer environ_map.deinit();
    try environ_map.put("ZIG_GLOBAL_CACHE_DIR", global);
    for ([_]struct { triple: []const u8, cpu: []const u8 }{
        .{ .triple = "-Dtarget=x86_64-linux-musl", .cpu = "-Dcpu=x86_64_v2" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64_v3" },
    }) |bad| {
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{
                options.zig_executable, "build",              "--build-file",
                build_file,             "install-controller", bad.triple,
                bad.cpu,                "-Doptimize=safe",    runtime_flag,
                "--system",             packages,             "--cache-dir",
                cache,
            },
            .cwd = .{ .path = options.repository_root },
            .environ_map = &environ_map,
            .stdout_limit = .limited(32 * 1024),
            .stderr_limit = .limited(32 * 1024),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        if (std.mem.indexOf(u8, result.stderr, "install-controller requires") == null)
            std.debug.print("incompatible controller install: {s}\n", .{result.stderr});
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "install-controller requires -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v2") != null);
        try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(std.testing.io, runtime, .{}));
        const after = try ignoredSource(allocator);
        defer allocator.free(after);
        try std.testing.expectEqualStrings(ignored, after);
    }
}
