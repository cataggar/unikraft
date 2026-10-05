const std = @import("std");
const options = @import("test_options");

test "install-controller rejects incompatible build flags without creating output" {
    const allocator = std.testing.allocator;
    const runtime = try std.fs.path.join(allocator, &.{ options.repository_root, ".d/controller-invalid-target" });
    defer allocator.free(runtime);
    const runtime_flag = try allocator.print("-Dcontroller-runtime={s}", .{runtime});
    defer allocator.free(runtime_flag);
    const build_file = try std.fs.path.join(allocator, &.{
        options.repository_root, "support/build/wamr-native-ci/build.zig",
    });
    defer allocator.free(build_file);
    const cache = try std.fs.path.join(allocator, &.{ options.fixture_root, "invalid-controller-install-cache" });
    defer allocator.free(cache);
    for ([_]struct { triple: []const u8, cpu: []const u8 }{
        .{ .triple = "-Dtarget=x86_64-linux-musl", .cpu = "-Dcpu=x86_64_v2" },
        .{ .triple = "-Dtarget=x86_64-linux-gnu", .cpu = "-Dcpu=x86_64_v3" },
    }) |bad| {
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{
                options.zig_executable, "build",       "--build-file",
                build_file,             "--cache-dir", cache,
                "install-controller",   bad.triple,    bad.cpu,
                "-Doptimize=safe",      runtime_flag,
            },
            .cwd = .{ .path = options.repository_root },
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
    }
}
