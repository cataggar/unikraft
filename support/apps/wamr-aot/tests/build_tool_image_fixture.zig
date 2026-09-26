// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        stderr.interface.print("image_fixture_failed {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(9);
    };
}

fn run(init: std.process.Init) !void {
    _ = linux.syscall1(.umask, 0o077);
    const allocator = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(allocator);
    try record(init, allocator, arguments);

    if (contains(arguments, "--print-datadir")) {
        try failIfSelected(init, "bison-data");
        const path = init.environ_map.get("WAMR_IMAGE_FIXTURE_BISON_DATA") orelse
            return error.MissingBisonData;
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.print("{s}\n", .{path});
        return;
    }
    if (contains(arguments, "diff")) {
        try failIfSelected(init, "git-clean");
        if (init.environ_map.get("WAMR_IMAGE_FIXTURE_DIRTY") != null)
            std.process.exit(1);
        return;
    }
    if (contains(arguments, "rev-parse")) {
        try failIfSelected(init, "git-revision");
        const revision = init.environ_map.get("WAMR_IMAGE_FIXTURE_REVISION") orelse
            "0123456789abcdef0123456789abcdef01234567";
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.print("{s}\n", .{revision});
        return;
    }
    if (arguments.len >= 3 and
        std.mem.eql(u8, arguments[1], "build") and
        (contains(arguments, "olddefconfig") or contains(arguments, "native-images")))
    {
        const stage = if (contains(arguments, "olddefconfig"))
            "olddefconfig"
        else
            "native-images";
        try failIfSelected(init, stage);
        const app = prefixed(arguments, "-Dapp=") orelse return error.MissingApp;
        const config = prefixed(arguments, "-Dconfig=") orelse return error.MissingConfig;
        if (std.mem.eql(u8, stage, "olddefconfig")) {
            const source = try std.fs.path.join(allocator, &.{ app, ".config" });
            const bytes = try std.Io.Dir.cwd().readFileAlloc(
                init.io,
                source,
                allocator,
                .limited(1024 * 1024),
            );
            if (contains(arguments, "-Dci-portable-config=true")) {
                const seed = try std.Io.Dir.cwd().readFileAlloc(
                    init.io,
                    config,
                    allocator,
                    .limited(1024 * 1024),
                );
                if (std.mem.indexOf(
                    u8,
                    seed,
                    "# CONFIG_LIBUKLIBID_INFO_COMPILEDATE is not set\n",
                ) == null) return error.MissingPortableSeed;
            }
            try writeFile(init.io, config, bytes, 0o600, true);
            return;
        }
        for ([_]struct { name: []const u8, contents: []const u8 }{
            .{ .name = "wamr_hyperv-x86_64-efi", .contents = "fixture-efi\n" },
            .{ .name = "wamr_hyperv-x86_64-efi.dbg", .contents = "fixture-debug-elf\n" },
            .{ .name = "wamr_hyperv-x86_64-efi.bootinfo", .contents = "fixture-bootinfo\n" },
        }) |output| {
            const path = try std.fs.path.join(allocator, &.{ app, "build", output.name });
            try writeFile(init.io, path, output.contents, 0o600, true);
        }
        if (init.environ_map.get("WAMR_IMAGE_FIXTURE_REWRITE_CONFIG")) |value| {
            if (!std.mem.eql(u8, value, "1")) return error.InvalidArguments;
            const bytes = try std.Io.Dir.cwd().readFileAlloc(
                init.io,
                config,
                allocator,
                .limited(1024 * 1024),
            );
            try writeFile(init.io, config, bytes, 0o600, true);
        }
        if (init.environ_map.get("WAMR_IMAGE_FIXTURE_MUTATE")) |mutation| {
            const path = if (std.mem.eql(u8, mutation, "config"))
                config
            else if (std.mem.eql(u8, mutation, "runtime"))
                try std.fs.path.join(
                    allocator,
                    &.{ app, "build", "artifacts", "identity.json" },
                )
            else if (std.mem.eql(u8, mutation, "application"))
                try std.fs.path.join(allocator, &.{ app, "build-tool-image.zig" })
            else
                return error.InvalidMutation;
            try appendFile(init.io, path, "mutated\n");
        }
        return;
    }
    return error.InvalidArguments;
}

fn record(
    init: std.process.Init,
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const path = init.environ_map.get("WAMR_IMAGE_FIXTURE_LOG") orelse return;
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(init.io, ".", allocator);
    const file = try std.Io.Dir.openFileAbsolute(init.io, path, .{
        .mode = .read_write,
        .follow_symlinks = false,
    });
    defer file.close(init.io);
    const stat = try file.stat(init.io);
    var line = std.Io.Writer.Allocating.init(allocator);
    defer line.deinit();
    try line.writer.print(
        "{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}",
        .{
            cwd,
            init.environ_map.get("TMPDIR") orelse "",
            init.environ_map.get("XDG_CACHE_HOME") orelse "",
            init.environ_map.get("XDG_CONFIG_HOME") orelse "",
            init.environ_map.get("ZIG_GLOBAL_CACHE_DIR") orelse "",
            init.environ_map.get("ZIG_LOCAL_CACHE_DIR") orelse "",
            init.environ_map.get("BISON_PKGDATADIR") orelse "",
        },
    );
    for (arguments) |argument| try line.writer.print("\t{s}", .{argument});
    try line.writer.writeByte('\n');
    try file.writePositionalAll(init.io, line.written(), stat.size);
    try file.sync(init.io);
}

fn failIfSelected(init: std.process.Init, stage: []const u8) !void {
    const selected = init.environ_map.get("WAMR_IMAGE_FIXTURE_FAIL") orelse return;
    if (std.mem.eql(u8, selected, stage)) {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        try stderr.interface.print("private image fixture failure at {s}\n", .{stage});
        return error.InjectedFailure;
    }
}

fn contains(arguments: []const []const u8, expected: []const u8) bool {
    for (arguments) |argument|
        if (std.mem.eql(u8, argument, expected)) return true;
    return false;
}

fn prefixed(arguments: []const []const u8, prefix: []const u8) ?[]const u8 {
    for (arguments) |argument|
        if (std.mem.startsWith(u8, argument, prefix)) return argument[prefix.len..];
    return null;
}

fn writeFile(
    io: std.Io,
    path: []const u8,
    contents: []const u8,
    mode: u16,
    replace: bool,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
    const file = try std.Io.Dir.createFileAbsolute(io, path, .{
        .truncate = replace,
        .exclusive = !replace,
        .permissions = .fromMode(mode),
    });
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
    try file.setLength(io, contents.len);
    try file.setPermissions(io, .fromMode(mode));
    try file.sync(io);
}

fn appendFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{
        .mode = .read_write,
        .follow_symlinks = false,
    });
    defer file.close(io);
    const stat = try file.stat(io);
    try file.writePositionalAll(io, contents, stat.size);
    try file.sync(io);
}
