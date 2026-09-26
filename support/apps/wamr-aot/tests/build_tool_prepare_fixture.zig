// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        stderr.interface.print("prepare_fixture_failed {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(9);
    };
}

fn run(init: std.process.Init) !void {
    _ = linux.syscall1(.umask, 0o077);
    const allocator = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(allocator);
    try recordEnvironment(init, allocator, arguments);
    if (arguments.len >= 3 and std.mem.eql(u8, arguments[1], "ar")) {
        if (arguments.len == 4 and std.mem.eql(u8, arguments[2], "t")) {
            try failIfSelected(init, "runtime-archive-members");
            const cache = init.environ_map.get("ZIG_LOCAL_CACHE_DIR") orelse
                return error.MissingCache;
            var stdout = std.Io.File.stdout().writer(init.io, &.{});
            if (init.environ_map.get("WAMR_PREPARE_FIXTURE_INVALID_MEMBER") != null)
                try stdout.interface.writeAll("unexpected.o\n")
            else
                try stdout.interface.print(
                    "{s}/o/0123456789abcdef0123456789abcdef/libwamr-aot_zcu.o\n",
                    .{cache},
                );
            return;
        }
        if (arguments.len == 5 and std.mem.eql(u8, arguments[2], "x") and
            std.mem.startsWith(u8, arguments[3], "--output="))
        {
            try failIfSelected(init, "runtime-archive-extract");
            const bytes = try std.Io.Dir.cwd().readFileAlloc(
                init.io,
                arguments[4],
                allocator,
                .limited(1024 * 1024),
            );
            const member = if (std.mem.indexOf(u8, bytes, "\nmember-name=")) |index|
                bytes[0 .. index + 1]
            else
                bytes;
            const output = try std.fs.path.join(allocator, &.{
                arguments[3]["--output=".len..], "libwamr-aot_zcu.o",
            });
            try writeFile(init.io, output, member, 0o600);
            return;
        }
        if (arguments.len == 5 and std.mem.eql(u8, arguments[2], "rcsD") and
            std.mem.eql(u8, arguments[4], "libwamr-aot_zcu.o"))
        {
            try failIfSelected(init, "runtime-archive-repack");
            const bytes = try std.Io.Dir.cwd().readFileAlloc(
                init.io,
                arguments[4],
                allocator,
                .limited(1024 * 1024),
            );
            try writeFile(init.io, arguments[3], bytes, 0o600);
            return;
        }
        return error.InvalidArguments;
    }
    if (arguments.len == 4 and std.mem.eql(u8, arguments[1], "--strip-debug")) {
        try failIfSelected(init, "runtime-strip");
        const bytes = try std.Io.Dir.cwd().readFileAlloc(
            init.io,
            arguments[2],
            allocator,
            .limited(1024 * 1024),
        );
        try writeFile(init.io, arguments[3], bytes, 0o600);
        return;
    }
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "version")) {
        try failIfSelected(init, "version");
        var stdout = std.Io.File.stdout().writer(init.io, &.{});
        try stdout.interface.writeAll("0.16.0\n");
        return;
    }
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "compile")) {
        try failIfSelected(init, "wamrc");
        const output = optionAfter(arguments, "-o") orelse return error.MissingOutput;
        const input = arguments[arguments.len - 3];
        const bytes = try std.Io.Dir.cwd().readFileAlloc(
            init.io,
            input,
            allocator,
            .limited(1024 * 1024),
        );
        const encoded = try std.fmt.allocPrint(allocator, "fixture-cwasm:{s}", .{bytes});
        try writeFile(init.io, output, encoded, 0o600);
        return;
    }
    if (contains(arguments, "build-exe")) {
        try failIfSelected(init, "build-exe");
        const emit = prefixed(arguments, "-femit-bin=") orelse return error.MissingOutput;
        const payload = if (containsSubstring(arguments, "/tests/unikraft-jit/"))
            "fixture-matched-wasm"
        else
            "fixture-tiny-wasm";
        try writeFile(init.io, emit, payload, 0o700);
        return;
    }
    if (contains(arguments, "build")) {
        const prefix = optionAfter(arguments, "--prefix") orelse return error.MissingPrefix;
        if (contains(arguments, "native-aot-fixture")) {
            try failIfSelected(init, "compiler-build");
            const compiler = try std.fs.path.join(allocator, &.{ prefix, "bin", "wamrc" });
            try copySelf(init.io, compiler);
            return;
        }
        if (prefixed(arguments, "-Dvariant=") != null) {
            try failIfSelected(init, "workload-build");
            const variant = prefixed(arguments, "-Dvariant=").?;
            const coremark = prefixed(arguments, "-Dcoremark=").?;
            const library = try std.fs.path.join(
                allocator,
                &.{ prefix, "lib", "libwamr-aot.a" },
            );
            const member_name = if (init.environ_map.get(
                "WAMR_PREPARE_FIXTURE_ARCHIVE_PATH_DEPENDENT",
            ) != null)
                try std.fmt.allocPrint(
                    allocator,
                    "member-name={s}\n",
                    .{init.environ_map.get("ZIG_LOCAL_CACHE_DIR") orelse return error.MissingCache},
                )
            else
                "";
            const payload = try std.fmt.allocPrint(
                allocator,
                "fixture-library variant={s} coremark={s}\n{s}",
                .{ variant, coremark, member_name },
            );
            try writeFile(init.io, library, payload, 0o600);
            if (std.mem.eql(u8, variant, "jit") or
                std.mem.eql(u8, variant, "sample-aot"))
            {
                const matched = try std.fs.path.join(allocator, &.{ prefix, "matched.wasm" });
                const mismatch = init.environ_map.get("WAMR_PREPARE_FIXTURE_MISMATCH") != null;
                try writeFile(
                    init.io,
                    matched,
                    if (mismatch) "mismatched-workload" else "fixture-matched-wasm",
                    0o600,
                );
            }
            return;
        }
        try failIfSelected(init, "runtime-build");
        return;
    }
    return error.InvalidArguments;
}

fn recordEnvironment(
    init: std.process.Init,
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const path = init.environ_map.get("WAMR_PREPARE_FIXTURE_LOG") orelse return;
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
        "{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n",
        .{
            stageName(arguments),
            cwd,
            init.environ_map.get("TMPDIR") orelse "",
            init.environ_map.get("XDG_CACHE_HOME") orelse "",
            init.environ_map.get("XDG_CONFIG_HOME") orelse "",
            init.environ_map.get("ZIG_GLOBAL_CACHE_DIR") orelse "",
            init.environ_map.get("ZIG_LOCAL_CACHE_DIR") orelse "",
            init.environ_map.get("ZIG_LIB_DIR") orelse "",
        },
    );
    try file.writePositionalAll(init.io, line.written(), stat.size);
    try file.sync(init.io);
}

fn stageName(arguments: []const []const u8) []const u8 {
    if (arguments.len >= 3 and std.mem.eql(u8, arguments[1], "ar"))
        return if (std.mem.eql(u8, arguments[2], "t"))
            "runtime-archive-members"
        else if (std.mem.eql(u8, arguments[2], "x"))
            "runtime-archive-extract"
        else if (std.mem.eql(u8, arguments[2], "rcsD"))
            "runtime-archive-repack"
        else
            "invalid";
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "--strip-debug"))
        return "runtime-strip";
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "version"))
        return "version";
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "compile"))
        return "wamrc";
    if (contains(arguments, "build-exe"))
        return if (containsSubstring(arguments, "/tests/unikraft-jit/"))
            "matched-wasm"
        else
            "tiny-wasm";
    if (contains(arguments, "native-aot-fixture"))
        return "compiler-build";
    if (prefixed(arguments, "-Dvariant=") != null)
        return "workload-build";
    if (contains(arguments, "build"))
        return "runtime-build";
    return "invalid";
}

fn failIfSelected(init: std.process.Init, stage: []const u8) !void {
    const selected = init.environ_map.get("WAMR_PREPARE_FIXTURE_FAIL") orelse return;
    if (std.mem.eql(u8, selected, stage)) {
        var stderr = std.Io.File.stderr().writer(init.io, &.{});
        try stderr.interface.print("private fixture failure at {s}\n", .{stage});
        return error.InjectedFailure;
    }
}

fn contains(arguments: []const []const u8, expected: []const u8) bool {
    for (arguments) |argument|
        if (std.mem.eql(u8, argument, expected)) return true;
    return false;
}

fn containsSubstring(arguments: []const []const u8, expected: []const u8) bool {
    for (arguments) |argument|
        if (std.mem.indexOf(u8, argument, expected) != null) return true;
    return false;
}

fn optionAfter(arguments: []const []const u8, option: []const u8) ?[]const u8 {
    for (arguments[0..arguments.len -| 1], 0..) |argument, index|
        if (std.mem.eql(u8, argument, option)) return arguments[index + 1];
    return null;
}

fn prefixed(arguments: []const []const u8, prefix: []const u8) ?[]const u8 {
    for (arguments) |argument|
        if (std.mem.startsWith(u8, argument, prefix)) return argument[prefix.len..];
    return null;
}

fn copySelf(io: std.Io, destination: []const u8) !void {
    const source = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});
    defer source.close(io);
    const stat = try source.stat(io);
    if (stat.kind != .file) return error.InvalidExecutable;
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(destination).?);
    const output = try std.Io.Dir.createFileAbsolute(io, destination, .{
        .exclusive = true,
        .permissions = .fromMode(0o700),
    });
    defer output.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stat.size) {
        const count = try source.readPositionalAll(
            io,
            buffer[0..@min(buffer.len, stat.size - offset)],
            offset,
        );
        if (count == 0) return error.UnexpectedEof;
        try output.writePositionalAll(io, buffer[0..count], offset);
        offset += count;
    }
    try output.setLength(io, stat.size);
    try output.setPermissions(io, .fromMode(0o700));
    try output.sync(io);
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8, mode: u16) !void {
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
    const file = try std.Io.Dir.createFileAbsolute(io, path, .{
        .exclusive = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
    try file.setLength(io, contents.len);
    try file.setPermissions(io, .fromMode(mode));
    try file.sync(io);
}
