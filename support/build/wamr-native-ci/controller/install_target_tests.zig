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

fn configureGlobalCacheDir(allocator: std.mem.Allocator, environ_map: *std.process.Environ.Map, fallback: []const u8) !void {
    if (environ_map.get("ZIG_GLOBAL_CACHE_DIR")) |existing| {
        if (std.fs.path.isAbsolute(existing) and
            !std.mem.eql(u8, existing, options.repository_root) and
            !(std.mem.startsWith(u8, existing, options.repository_root) and
                existing.len > options.repository_root.len and
                existing[options.repository_root.len] == '/'))
        {
            return;
        }
    }
    try environ_map.put("ZIG_GLOBAL_CACHE_DIR", fallback);
    _ = allocator;
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
    try configureGlobalCacheDir(allocator, &environ_map, global);
    for ([_]struct { triple: []const u8, cpu: []const u8 }{
        .{ .triple = "-Dtarget=x86_64-linux-musl", .cpu = "-Dcpu=x86_64_v2" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=native" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64_v1" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64_v4" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64_v2+avx2" },
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
        if (std.mem.eql(u8, bad.cpu, "-Dcpu=x86_64_v1")) {
            try std.testing.expect(std.mem.indexOf(u8, result.stderr, "x86_64_v1") != null);
        } else {
            if (std.mem.indexOf(u8, result.stderr, "install-controller requires") == null)
                std.debug.print("incompatible controller install: {s}\n", .{result.stderr});
            try std.testing.expect(std.mem.indexOf(u8, result.stderr, "install-controller requires -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v2") != null);
        }
        try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(std.testing.io, runtime, .{}));
        const after = try ignoredSource(allocator);
        defer allocator.free(after);
        try std.testing.expectEqualStrings(ignored, after);
    }
}

test "install-controller installs v2 default and v3 opt-in with matching describe target" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const package = try std.Io.Dir.cwd().realPathFileAlloc(io, options.miz_package, allocator);
    defer allocator.free(package);
    const packages = std.fs.path.dirname(package) orelse return error.MissingPackageRoot;
    const cache = try std.fs.path.join(allocator, &.{ options.fixture_root, "install-target-work", "cache" });
    defer allocator.free(cache);
    const global = try std.fs.path.join(allocator, &.{ options.fixture_root, "install-target-work", "global" });
    defer allocator.free(global);
    const build_file = try std.fs.path.join(allocator, &.{
        options.repository_root, "support/build/wamr-native-ci/build.zig",
    });
    defer allocator.free(build_file);
    var environ_map = try std.testing.environ.createMap(allocator);
    defer environ_map.deinit();
    try configureGlobalCacheDir(allocator, &environ_map, global);
    const work_root = try std.fs.path.join(allocator, &.{ options.fixture_root, "install-target-work" });
    defer allocator.free(work_root);
    const work_parent = try std.Io.Dir.openDirAbsolute(io, work_root, .{ .iterate = true });
    defer work_parent.close(io);
    for ([_]struct { name: []const u8, cpu: []const u8 }{
        .{ .name = "install-target-v2", .cpu = "-Dcpu=x86_64_v2" },
        .{ .name = "install-target-v3", .cpu = "-Dcpu=x86_64_v3" },
    }) |entry| {
        work_parent.deleteTree(io, entry.name) catch {};
        try work_parent.createDir(io, entry.name, .fromMode(0o700));
        defer work_parent.deleteTree(io, entry.name) catch {};
        const runtime = try std.fs.path.join(allocator, &.{ work_root, entry.name });
        defer allocator.free(runtime);
        const runtime_flag = try allocator.print("-Dcontroller-runtime={s}", .{runtime});
        defer allocator.free(runtime_flag);
        const build_result = try std.process.run(allocator, io, .{
            .argv = &.{
                options.zig_executable,    "build",              "--build-file",
                build_file,                "install-controller", "-Dtarget=x86_64-linux-gnu",
                entry.cpu,                 "-Doptimize=safe",    runtime_flag,
                "--system",                packages,             "--cache-dir",
                cache,                     "-j2",
            },
            .cwd = .{ .path = options.repository_root },
            .environ_map = &environ_map,
            .stdout_limit = .limited(32 * 1024),
            .stderr_limit = .limited(32 * 1024),
        });
        defer allocator.free(build_result.stdout);
        defer allocator.free(build_result.stderr);
        if (build_result.term != .exited or build_result.term.exited != 0)
            std.debug.print("install-controller ({s}) failed: {s}\n", .{ entry.cpu, build_result.stderr });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, build_result.term);
        const installed_cli = try std.fs.path.join(allocator, &.{ runtime, "controller/bin/uk-wamr-native-ci" });
        defer allocator.free(installed_cli);
        const target_out = try std.process.run(allocator, io, .{
            .argv = &.{ installed_cli, "describe", "--output", "target-v1" },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer allocator.free(target_out.stdout);
        defer allocator.free(target_out.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, target_out.term);
        const expected_target = try allocator.print("-Dtarget=x86_64-linux-gnu {s}\n", .{entry.cpu});
        defer allocator.free(expected_target);
        try std.testing.expectEqualStrings(expected_target, target_out.stdout);
        const json_out = try std.process.run(allocator, io, .{
            .argv = &.{ installed_cli, "describe", "--output", "json-v1" },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer allocator.free(json_out.stdout);
        defer allocator.free(json_out.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, json_out.term);
        try std.testing.expect(std.mem.indexOf(u8, json_out.stdout, entry.cpu) != null);
    }
}
