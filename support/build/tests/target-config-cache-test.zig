const std = @import("std");
const linux = std.os.linux;

const Options = struct {
    base: ?[]const u8 = null,
    work_dir: ?[]const u8 = null,
    zig: ?[]const u8 = null,
    packages: ?[]const u8 = null,
};

fn parseArgs(a: std.mem.Allocator, args: std.process.Args) !Options {
    const argv = try args.toSlice(a);
    var opts: Options = .{};
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 >= argv.len) return error.MissingOptionValue;
        const flag = argv[index];
        const value = argv[index + 1];
        if (std.mem.eql(u8, flag, "--base") or std.mem.eql(u8, flag, "--root")) {
            opts.base = value;
        } else if (std.mem.eql(u8, flag, "--work-dir")) {
            opts.work_dir = value;
        } else if (std.mem.eql(u8, flag, "--zig")) {
            opts.zig = value;
        } else if (std.mem.eql(u8, flag, "--packages")) {
            opts.packages = value;
        } else {
            return error.UnknownOption;
        }
    }
    return opts;
}

fn ensurePrivateDir(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, path);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false, .iterate = true });
    defer dir.close(io);
    if (linux.errno(linux.fchmod(dir.handle, 0o700)) != .SUCCESS) return error.ChmodFailed;
}

fn writeModeFile(io: std.Io, path: []const u8, contents: []const u8, mode: u32) !void {
    if (std.fs.path.dirname(path)) |parent| {
        try std.Io.Dir.cwd().createDirPath(io, parent);
    }
    var file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(io);
    if (linux.errno(linux.fchmod(file.handle, mode)) != .SUCCESS) return error.ChmodFailed;
    try file.writeStreamingAll(io, contents);
}

fn copyFileContents(a: std.mem.Allocator, io: std.Io, src: []const u8, dst: []const u8) !void {
    const data = try std.Io.Dir.cwd().readFileAlloc(io, src, a, .limited(4 * 1024 * 1024));
    try writeModeFile(io, dst, data, 0o600);
}

fn toZ(a: std.mem.Allocator, s: []const u8) ![:0]const u8 {
    const buf = try a.allocSentinel(u8, s.len, 0);
    @memcpy(buf, s);
    return buf;
}

fn statTimestamps(a: std.mem.Allocator, path: []const u8) ![2]linux.timespec {
    const path_z = try toZ(a, path);
    var stx: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        linux.AT.FDCWD,
        path_z,
        linux.AT.SYMLINK_NOFOLLOW,
        .BASIC_STATS,
        &stx,
    )) != .SUCCESS) return error.StatxFailed;
    return .{
        .{ .sec = stx.atime.sec, .nsec = stx.atime.nsec },
        .{ .sec = stx.mtime.sec, .nsec = stx.mtime.nsec },
    };
}

fn applyTimestamps(a: std.mem.Allocator, path: []const u8, times: [2]linux.timespec) !void {
    const path_z = try toZ(a, path);
    if (linux.errno(linux.utimensat(linux.AT.FDCWD, path_z, &times, 0)) != .SUCCESS)
        return error.UtimensFailed;
}

fn chmodPath(a: std.mem.Allocator, path: []const u8, mode: u32) !void {
    const path_z = try toZ(a, path);
    if (linux.errno(linux.fchmodat(linux.AT.FDCWD, path_z, mode)) != .SUCCESS)
        return error.ChmodFailed;
}

fn pathExists(a: std.mem.Allocator, path: []const u8) !bool {
    const path_z = try toZ(a, path);
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

fn writeConfig(a: std.mem.Allocator, io: std.Io, path: []const u8, name: []const u8) !void {
    const text = try std.fmt.allocPrint(
        a,
        "CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_KVM=y\nCONFIG_KVM_BOOT_PROTO_MULTIBOOT=y\nCONFIG_UK_NAME=\"{s}\"\n",
        .{name},
    );
    try writeModeFile(io, path, text, 0o600);
}

fn buildEnvironment(
    a: std.mem.Allocator,
    base_env: *const std.process.Environ.Map,
    work: []const u8,
    packages: []const u8,
) !std.process.Environ.Map {
    var env = try base_env.clone(a);
    try env.put("ZIG_GLOBAL_CACHE_DIR", try std.fs.path.join(a, &.{ work, "global-cache" }));
    try env.put("ZIG_LOCAL_CACHE_DIR", try std.fs.path.join(a, &.{ work, "local-cache" }));
    try env.put("ZIG_LOCAL_PKG_DIR", packages);
    try env.put("TMPDIR", try std.fs.path.join(a, &.{ work, "tmp" }));
    try env.put("XDG_CACHE_HOME", try std.fs.path.join(a, &.{ work, "tool-cache" }));
    return env;
}

fn expectBuild(
    a: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    zig: []const u8,
    cwd: []const u8,
    work: []const u8,
    packages: []const u8,
    extra_args: []const []const u8,
    diagnostic: ?[]const u8,
) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ zig, "build", "--system", packages });
    try argv.appendSlice(a, extra_args);
    try argv.appendSlice(a, &.{ "--summary", "failures" });

    var env = try buildEnvironment(a, base_env, work, packages);
    const res = try std.process.run(a, io, .{
        .argv = argv.items,
        .cwd = .{ .path = cwd },
        .environ_map = &env,
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
    });
    const combined = try std.fmt.allocPrint(a, "{s}{s}", .{ res.stdout, res.stderr });
    const exited_zero = switch (res.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (diagnostic) |want| {
        if (exited_zero or std.mem.indexOf(u8, combined, want) == null) {
            std.debug.print("expected refusal '{s}':\n{s}\n", .{ want, combined });
            return error.ExpectedRefusalNotObserved;
        }
        return;
    }
    if (!exited_zero) {
        std.debug.print("unexpected build failure:\n{s}\n", .{combined});
        return error.UnexpectedBuildFailure;
    }
}

fn runBuild(
    a: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    zig: []const u8,
    base: []const u8,
    work: []const u8,
    packages: []const u8,
    config: []const u8,
) !void {
    const app_arg = try std.fmt.allocPrint(a, "-Dapp={s}", .{work});
    const out_arg = try std.fmt.allocPrint(a, "-Doutput={s}/output", .{work});
    const cfg_arg = try std.fmt.allocPrint(a, "-Dconfig={s}", .{config});
    const prefix = try std.fs.path.join(a, &.{ work, "install" });
    try expectBuild(
        a,
        io,
        base_env,
        zig,
        base,
        work,
        packages,
        &.{ "target-config-header", app_arg, out_arg, cfg_arg, "--prefix", prefix },
        null,
    );
}

fn trackedConfig(
    a: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    zig: []const u8,
    base: []const u8,
    work: []const u8,
    packages: []const u8,
) !void {
    const fixture = try std.fs.path.join(a, &.{ work, "configure-fixture" });
    try ensurePrivateDir(io, fixture);
    try copyFileContents(
        a,
        io,
        try std.fs.path.join(a, &.{ base, "support/build/tests/configure-cache/build.zig" }),
        try std.fs.path.join(a, &.{ fixture, "build.zig" }),
    );
    try copyFileContents(
        a,
        io,
        try std.fs.path.join(a, &.{ base, "support/build/native-config-input.zig" }),
        try std.fs.path.join(a, &.{ fixture, "native-config-input.zig" }),
    );

    const config = try std.fs.path.join(a, &.{ fixture, "same-path.config" });
    const installed = try std.fs.path.join(a, &.{ work, "install/config-source" });
    const cfg_arg = try std.fmt.allocPrint(a, "-Dconfig={s}", .{config});
    const prefix = try std.fs.path.join(a, &.{ work, "install" });
    const args = [_][]const u8{ cfg_arg, "--prefix", prefix };

    try writeModeFile(io, config, "first\n", 0o600);
    try expectBuild(a, io, base_env, zig, fixture, work, packages, &args, null);
    try expectBuild(a, io, base_env, zig, fixture, work, packages, &args, null);

    const original_times = try statTimestamps(a, config);
    const replacement = try std.fs.path.join(a, &.{ fixture, "replacement.config" });
    try writeModeFile(io, replacement, "other\n", 0o600);
    try applyTimestamps(a, replacement, original_times);
    try std.Io.Dir.cwd().rename(replacement, std.Io.Dir.cwd(), config, io);

    try expectBuild(a, io, base_env, zig, fixture, work, packages, &args, null);
    const installed_text = try std.Io.Dir.cwd().readFileAlloc(io, installed, a, .limited(64 * 1024));
    if (!std.mem.eql(u8, installed_text, "other\n")) return error.StaleConfigureTimeConfig;

    try std.Io.Dir.cwd().deleteFile(io, config);
    try expectBuild(a, io, base_env, zig, fixture, work, packages, &args, "FileNotFound");
}

fn liveTrustFixture(
    a: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    zig: []const u8,
    base: []const u8,
    work: []const u8,
    packages: []const u8,
    backend_dir: []const u8,
) !void {
    const app = try std.fs.path.join(a, &.{ work, "application" });
    try ensurePrivateDir(io, app);
    const recorded = try std.fs.path.join(a, &.{ work, "make-argv" });
    const source = try std.fs.path.join(a, &.{ backend_dir, "record-make.c" });
    const make_bin = try std.fs.path.join(a, &.{ backend_dir, "record-make" });
    const c_source = try std.fmt.allocPrint(
        a,
        \\#include <stdio.h>
        \\int main(int argc, char **argv) {{
        \\FILE *output = fopen("{s}", "w");
        \\if (!output) return 1;
        \\for (int i = 1; i < argc; ++i) fprintf(output, "%s\n", argv[i]);
        \\return fclose(output) != 0;
        \\}}
        \\
    ,
        .{recorded},
    );
    try writeModeFile(io, source, c_source, 0o600);

    var env = try buildEnvironment(a, base_env, work, packages);
    const cc_res = try std.process.run(a, io, .{
        .argv = &.{ zig, "cc", "-O2", source, "-o", make_bin },
        .cwd = .{ .path = base },
        .environ_map = &env,
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(256 * 1024),
    });
    switch (cc_res.term) {
        .exited => |code| if (code != 0) return error.CompileRecordMakeFailed,
        else => return error.CompileRecordMakeFailed,
    }
    try chmodPath(a, make_bin, 0o700);

    const tool = try std.fs.path.join(a, &.{ work, "wamr-tool" });
    try writeModeFile(io, tool, "#!/bin/sh\nexit 0\n", 0o700);

    const args = [_][]const u8{
        "objs",
        try std.fmt.allocPrint(a, "-Dapp={s}", .{app}),
        try std.fmt.allocPrint(a, "-Doutput={s}/output", .{work}),
        try std.fmt.allocPrint(a, "-Dmake-command={s}", .{make_bin}),
        try std.fmt.allocPrint(a, "-Dwamr-aot-tool={s}", .{tool}),
        "-Dmake-arg=AR=zig ar",
    };
    try expectBuild(a, io, base_env, zig, base, work, packages, &args, null);
    try expectBuild(a, io, base_env, zig, base, work, packages, &args, null);

    const recorded_text = try std.Io.Dir.cwd().readFileAlloc(io, recorded, a, .limited(64 * 1024));
    var saw_ar = false;
    var saw_objs = false;
    var lines = std.mem.splitScalar(u8, recorded_text, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "AR=zig ar")) saw_ar = true;
        if (std.mem.eql(u8, line, "objs")) saw_objs = true;
    }
    if (!saw_ar or !saw_objs) return error.UnexpectedMakeInvocation;
    try std.Io.Dir.cwd().deleteFile(io, recorded);

    const empty_packages = try std.fs.path.join(a, &.{ work, "empty-packages" });
    try ensurePrivateDir(io, empty_packages);
    try expectBuild(
        a,
        io,
        base_env,
        zig,
        base,
        work,
        empty_packages,
        &args,
        "package not found at",
    );
    if (try pathExists(a, recorded)) return error.MakeRanWithMissingPackages;

    const original_times = try statTimestamps(a, tool);
    try chmodPath(a, tool, 0o600);
    try applyTimestamps(a, tool, original_times);
    try expectBuild(
        a,
        io,
        base_env,
        zig,
        base,
        work,
        packages,
        &args,
        "executable regular file",
    );
    if (try pathExists(a, recorded)) return error.MakeRanWithNonExecutableTool;

    try chmodPath(a, tool, 0o700);
    try expectBuild(a, io, base_env, zig, base, work, packages, &args, null);
    try std.Io.Dir.cwd().deleteFile(io, recorded);

    const original_tool = try std.fs.path.join(a, &.{ work, "original-wamr-tool" });
    try std.Io.Dir.cwd().rename(tool, std.Io.Dir.cwd(), original_tool, io);
    try std.Io.Dir.cwd().symLink(io, original_tool, tool, .{});
    try expectBuild(
        a,
        io,
        base_env,
        zig,
        base,
        work,
        packages,
        &args,
        "existing canonical executable",
    );
    if (try pathExists(a, recorded)) return error.MakeRanWithSymlinkedTool;
    try std.Io.Dir.cwd().deleteFile(io, tool);
    try std.Io.Dir.cwd().rename(original_tool, std.Io.Dir.cwd(), tool, io);

    const original_app = try std.fs.path.join(a, &.{ work, "original-application" });
    try std.Io.Dir.cwd().rename(app, std.Io.Dir.cwd(), original_app, io);
    try writeModeFile(io, app, "not a directory\n", 0o600);
    try expectBuild(
        a,
        io,
        base_env,
        zig,
        base,
        work,
        packages,
        &args,
        "NotDirectory",
    );
    if (try pathExists(a, recorded)) return error.MakeRanWithReplacedAppDir;
}

fn liveTrust(
    a: std.mem.Allocator,
    io: std.Io,
    base_env: *const std.process.Environ.Map,
    zig: []const u8,
    base: []const u8,
    work: []const u8,
    packages: []const u8,
) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(work, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const backend_dir = try std.fmt.allocPrint(a, "{s}/.target-config-backend-{s}", .{ base, hex[0..16] });
    std.Io.Dir.cwd().deleteTree(io, backend_dir) catch {};
    try ensurePrivateDir(io, backend_dir);
    defer std.Io.Dir.cwd().deleteTree(io, backend_dir) catch {};
    try liveTrustFixture(a, io, base_env, zig, base, work, packages, backend_dir);
}

pub fn main(init: std.process.Init) !void {
    _ = linux.syscall1(.umask, 0o077);
    const a = init.arena.allocator();
    const io = init.io;
    const opts = try parseArgs(a, init.minimal.args);
    const base_arg = opts.base orelse return error.MissingBase;
    const work_arg = opts.work_dir orelse return error.MissingWorkDir;
    const zig = opts.zig orelse return error.MissingZig;
    const packages_arg = opts.packages orelse return error.MissingPackages;

    const base = try std.Io.Dir.cwd().realPathFileAlloc(io, base_arg, a);
    const packages = try std.Io.Dir.cwd().realPathFileAlloc(io, packages_arg, a);
    const pkg_stat = try std.Io.Dir.cwd().statFile(io, packages, .{ .follow_symlinks = false });
    if (pkg_stat.kind != .directory) return error.RootPackageDepotNotDirectory;

    std.Io.Dir.cwd().deleteTree(io, work_arg) catch {};
    try ensurePrivateDir(io, work_arg);
    const work = try std.Io.Dir.cwd().realPathFileAlloc(io, work_arg, a);
    for ([_][]const u8{ "global-cache", "local-cache", "tmp", "tool-cache", "install" }) |name| {
        try ensurePrivateDir(io, try std.fs.path.join(a, &.{ work, name }));
    }

    const config = try std.fs.path.join(a, &.{ work, "same-path.config" });
    const installed = try std.fs.path.join(a, &.{ work, "install/target-config-header.h" });

    try writeConfig(a, io, config, "cache-first");
    try runBuild(a, io, init.environ_map, zig, base, work, packages, config);
    const first = try std.Io.Dir.cwd().readFileAlloc(io, installed, a, .limited(256 * 1024));
    if (std.mem.indexOf(u8, first, "#define CONFIG_UK_NAME \"cache-first\"") == null)
        return error.InitialTargetHeaderMismatch;

    const marker = try std.fs.path.join(a, &.{ work, "output/.unikraft-zig-build" });
    try writeModeFile(io, marker, "unikraft-zig-build-v1\n", 0o600);
    try writeConfig(a, io, config, "cache-second");
    try runBuild(a, io, init.environ_map, zig, base, work, packages, config);
    const second = try std.Io.Dir.cwd().readFileAlloc(io, installed, a, .limited(256 * 1024));
    if (std.mem.indexOf(u8, second, "#define CONFIG_UK_NAME \"cache-second\"") == null)
        return error.UpdatedTargetHeaderMismatch;
    if (std.mem.eql(u8, first, second))
        return error.TargetHeaderDidNotChange;

    try trackedConfig(a, io, init.environ_map, zig, base, work, packages);
    try liveTrust(a, io, init.environ_map, zig, base, work, packages);
}
