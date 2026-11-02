const std = @import("std");
const linux = std.os.linux;

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| {
        try std.Io.Dir.cwd().createDirPath(io, parent);
    }
    var file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn ensurePrivateDir(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, path);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false, .iterate = true });
    defer dir.close(io);
    if (linux.errno(linux.fchmod(dir.handle, 0o700)) != .SUCCESS) return error.ChmodFailed;
}

fn pathExists(a: std.mem.Allocator, path: []const u8) !bool {
    const path_z = try a.allocSentinel(u8, path.len, 0);
    @memcpy(path_z, path);
    var stx: linux.Statx = undefined;
    return switch (linux.errno(linux.statx(
        linux.AT.FDCWD,
        path_z,
        linux.AT.SYMLINK_NOFOLLOW,
        .BASIC_STATS,
        &stx,
    ))) {
        .SUCCESS => true,
        .NOENT => false,
        else => return error.StatxFailed,
    };
}

fn runConfigureCacheTest(
    a: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    zig: []const u8,
    build_zig_source: []const u8,
    root: []const u8,
    cache: []const u8,
) !void {
    const global_cache = try std.fs.path.join(a, &.{ cache, "global" });
    const local_cache = try std.fs.path.join(a, &.{ cache, "local" });
    var env = try base_env.clone(a);
    try env.put("ZIG_GLOBAL_CACHE_DIR", global_cache);

    const package = try std.fs.path.join(a, &.{ root, "support/tools/hyperv/public_image" });
    try std.Io.Dir.cwd().createDirPath(io, package);

    const build_zig_bytes = try std.Io.Dir.cwd().readFileAlloc(io, build_zig_source, a, .limited(1024 * 1024));
    try writeFile(io, try std.fs.path.join(a, &.{ package, "build.zig" }), build_zig_bytes);
    try writeFile(
        io,
        try std.fs.path.join(a, &.{ package, "configure_cache_tests.zig" }),
        "const std = @import(\"std\"); pub fn main(_: std.process.Init) !void {}\n",
    );
    try writeFile(
        io,
        try std.fs.path.join(a, &.{ package, "build.zig.zon" }),
        ".{ .name = .unikraft_hyperv_public_image, .version = \"0.1.0\", " ++
            ".fingerprint = 0xa451ae17f463e7f9, .minimum_zig_version = \"0.17.0\", " ++
            ".dependencies = .{ .miz_source = .{ .path = \"../../../../miz\" } }, .paths = .{\"\"}\n}\n",
    );

    const miz = try std.fs.path.join(a, &.{ root, "miz" });
    try std.Io.Dir.cwd().createDirPath(io, miz);
    try writeFile(
        io,
        try std.fs.path.join(a, &.{ miz, "build.zig.zon" }),
        ".{ .name = .miz, .version = \"0.0.0\", .fingerprint = 0xbba1c9adc2f802c1, .paths = .{\"\"}\n}\n",
    );
    try writeFile(io, try std.fs.path.join(a, &.{ miz, "root.zig" }), "");
    try writeFile(
        io,
        try std.fs.path.join(a, &.{ miz, "build.zig" }),
        "const std = @import(\"std\"); pub fn build(b: *std.Build) void { " ++
            "_ = b.addModule(\"miz\", .{ .root_source_file = b.path(\"root.zig\"), " ++
            ".target = b.standardTargetOptions(.{}), .optimize = b.standardOptimizeOption(.{}) }); }\n",
    );

    const hyperv_dir = try std.fs.path.join(a, &.{ root, "support/tools/hyperv" });
    try writeFile(io, try std.fs.path.join(a, &.{ hyperv_dir, "core.zig" }), "");
    try writeFile(io, try std.fs.path.join(a, &.{ hyperv_dir, "local_boot/root.zig" }), "");
    try writeFile(io, try std.fs.path.join(a, &.{ hyperv_dir, "sha256_clear_upper.S" }), "");
    try writeFile(io, try std.fs.path.join(a, &.{ root, "support/build/kconfig.zig" }), "");
    try writeFile(io, try std.fs.path.join(a, &.{ root, "support/build/postprocess-elf.zig" }), "");
    try writeFile(io, try std.fs.path.join(a, &.{ package, "root.zig" }), "pub const pins = @import(\"producer_pins\");\n");
    try writeFile(
        io,
        try std.fs.path.join(a, &.{ package, "main.zig" }),
        "const std = @import(\"std\"); pub fn main(init: std.process.Init) !void { " ++
            "const pin = @import(\"public_image\").pins.peer_sha256; " ++
            "var bytes: [65]u8 = undefined; " ++
            "@memcpy(bytes[0..64], &std.fmt.bytesToHex(pin, .lower)); bytes[64] = '\\n'; " ++
            "try std.Io.File.stdout().writeStreamingAll(init.io, &bytes); }\n",
    );

    const peer = try std.fs.path.join(a, &.{ root, "support/scripts/hyperv-network-peer.py" });
    const pkg_build = try std.fs.path.join(a, &.{ package, "build.zig" });
    const out_prefix = try std.fs.path.join(a, &.{ root, "out" });
    const installed_bin = try std.fs.path.join(a, &.{ root, "out/bin/uk-hyperv-public-image" });

    for ([_][]const u8{ "debug", "safe" }) |mode| {
        const opt_arg = try std.fmt.allocPrint(a, "-Doptimize={s}", .{mode});
        const argv = [_][]const u8{
            zig,
            "build",
            "--build-file",
            pkg_build,
            "--cache-dir",
            local_cache,
            "--prefix",
            out_prefix,
            "-j2",
            "install",
            "--summary",
            "failures",
            opt_arg,
        };
        for ([_][]const u8{ "# reviewed peer A\n", "# reviewed peer B\n" }) |payload| {
            try writeFile(io, peer, payload);
            const build_res = try std.process.run(a, io, .{
                .argv = &argv,
                .environ_map = &env,
                .stdout_limit = .limited(1024 * 1024),
                .stderr_limit = .limited(1024 * 1024),
            });
            switch (build_res.term) {
                .exited => |code| if (code != 0) {
                    std.debug.print("configure build failed:\n{s}{s}\n", .{ build_res.stdout, build_res.stderr });
                    return error.ConfigureBuildFailed;
                },
                else => return error.ConfigureBuildFailed,
            }
            const pin_res = try std.process.run(a, io, .{
                .argv = &.{installed_bin},
                .environ_map = &env,
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            switch (pin_res.term) {
                .exited => |code| if (code != 0) return error.PinBinaryFailed,
                else => return error.PinBinaryFailed,
            }
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
            const want_hex = std.fmt.bytesToHex(digest, .lower);
            const actual_pin = std.mem.trim(u8, pin_res.stdout, " \t\r\n");
            if (!std.mem.eql(u8, actual_pin, &want_hex)) return error.StaleConfigureTimePeerCommitment;
        }
        try std.Io.Dir.cwd().deleteFile(io, peer);
        const refused = try std.process.run(a, io, .{
            .argv = &argv,
            .environ_map = &env,
            .stdout_limit = .limited(1024 * 1024),
            .stderr_limit = .limited(1024 * 1024),
        });
        const combined = try std.fmt.allocPrint(a, "{s}{s}", .{ refused.stdout, refused.stderr });
        const exited_zero = switch (refused.term) {
            .exited => |code| code == 0,
            else => false,
        };
        if (exited_zero or std.mem.indexOf(u8, combined, "public peer source unavailable") == null)
            return error.DeletedPeerSourceNotRefused;
    }

    const global_stat = try std.Io.Dir.cwd().statFile(io, global_cache, .{ .follow_symlinks = false });
    if (global_stat.kind != .directory) return error.GlobalCacheNotCreated;
    try std.Io.File.stdout().writeStreamingAll(
        io,
        "public-image debug/safe warm configure caches update peer bytes and refuse deletion\n",
    );
}

pub fn main(init: std.process.Init) !void {
    _ = linux.syscall1(.umask, 0o077);
    const a = init.arena.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(a);
    if (argv.len != 3 and argv.len != 4) {
        std.debug.print("usage: configure_cache_tests ZIG BUILD_FILE_OR_FRESH_PROJECT_DIRECTORY [FRESH_CACHE_DIRECTORY]\n", .{});
        return error.InvalidUsage;
    }
    const zig = try std.Io.Dir.cwd().realPathFileAlloc(io, argv[1], a);
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", a);

    if (argv.len == 3 and std.mem.endsWith(u8, argv[2], "build.zig") and try pathExists(a, argv[2])) {
        const build_zig = try std.Io.Dir.cwd().realPathFileAlloc(io, argv[2], a);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const root_name = try std.fmt.allocPrint(a, ".zig17-peer-cache-test-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        const root = try std.fs.path.join(a, &.{ cwd, root_name });
        const cache = try std.fs.path.join(a, &.{ root, ".cache" });
        try ensurePrivateDir(io, root);
        defer std.Io.Dir.cwd().deleteTree(io, root) catch {};
        try ensurePrivateDir(io, cache);
        try runConfigureCacheTest(a, io, init.environ_map, zig, build_zig, root, cache);
        return;
    }

    const root = try std.fs.path.resolve(a, &.{ cwd, argv[2] });
    if (try pathExists(a, root)) return error.FixtureDirectoryAlreadyExists;
    const root_prefix = try std.fmt.allocPrint(a, "{s}/", .{cwd});
    if (!std.mem.startsWith(u8, root, root_prefix)) return error.FixtureOutsideCurrentProject;

    const cache = if (argv.len == 4)
        try std.fs.path.resolve(a, &.{ cwd, argv[3] })
    else
        try std.fs.path.join(a, &.{ root, ".cache" });
    const cache_prefix = try std.fmt.allocPrint(a, "{s}/", .{cache});
    if (std.mem.eql(u8, cache, root) or std.mem.startsWith(u8, root, cache_prefix))
        return error.CacheContainsFixture;
    if (try pathExists(a, cache)) return error.CacheDirectoryAlreadyExists;

    const build_zig = if (try pathExists(a, "support/tools/hyperv/public_image/build.zig"))
        try std.Io.Dir.cwd().realPathFileAlloc(io, "support/tools/hyperv/public_image/build.zig", a)
    else
        try std.Io.Dir.cwd().realPathFileAlloc(io, "build.zig", a);

    try ensurePrivateDir(io, root);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};
    try ensurePrivateDir(io, cache);
    defer std.Io.Dir.cwd().deleteTree(io, cache) catch {};
    try runConfigureCacheTest(a, io, init.environ_map, zig, build_zig, root, cache);
}
