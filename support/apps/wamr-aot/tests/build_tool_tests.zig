// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
const testing = std.testing;
const core = @import("hyperv_core");
const build_tool = @import("wamr_aot_build");

const allocator = testing.allocator;
const io = testing.io;

test "CLI grammar retains the four commands and exact option combinations" {
    const prepare = try build_tool.parseArguments(&.{
        "prepare",
        "--repository",
        "/d/unikraft",
        "--source=/d/wamr",
        "--variant",
        "jit",
        "--jit-mode=fast",
        "--development-revision",
        "0123456789abcdef0123456789abcdef01234567",
    });
    try testing.expectEqual(.prepare, prepare.command);
    try testing.expectEqual(.jit, prepare.variant);
    try testing.expectEqual(.fast, prepare.jit_mode.?);
    try testing.expectEqualStrings("/d/wamr", prepare.source.?);

    const archive = try build_tool.parseArguments(&.{
        "prepare",
        "--repository=/d/unikraft",
        "--source-archive",
        "/d/custody/wamr.tar",
        "--coremark",
    });
    try testing.expect(archive.coremark);
    try testing.expectEqual(.tiny, archive.variant);

    inline for (.{ "verify", "olddefconfig", "native-images" }) |command| {
        const parsed = try build_tool.parseArguments(&.{ command, "--repository", "/d/unikraft" });
        try testing.expect(parsed.source == null);
    }
}

test "CLI grammar rejects missing duplicates unsafe paths and incompatible modes" {
    const invalid = [_][]const []const u8{
        &.{"prepare"},
        &.{ "prepare", "--repository", "/d/repo" },
        &.{ "prepare", "--repository", "/d/repo", "--source", "/d/a", "--source-archive", "/d/b" },
        &.{ "prepare", "--repository", "/d/repo", "--source", "/d/a", "--variant", "jit" },
        &.{ "prepare", "--repository", "/d/repo", "--source", "/d/a", "--jit-mode", "fast" },
        &.{ "prepare", "--repository", "/d/repo", "--source", "/d/a", "--variant", "snapshot", "--coremark" },
        &.{ "prepare", "--repository", "/d/repo", "--source-archive", "/d/a", "--development-revision", "0123456789abcdef0123456789abcdef01234567" },
        &.{ "verify", "--repository", "/d/repo", "--coremark" },
        &.{ "verify", "--repository", "/d/repo", "--variant", "tiny" },
        &.{ "verify", "--repository", "relative" },
        &.{ "verify", "--repository", "/d/repo", "--repository", "/d/other" },
        &.{ "prepare", "--repository", "/d/repo", "--source", "/d/a", "--development-revision", "ABCDEF0123456789abcdef0123456789abcdef01" },
        &.{ "unknown", "--repository", "/d/repo" },
    };
    for (invalid) |arguments| {
        if (build_tool.parseArguments(arguments)) |_| {
            return error.ExpectedInvalidArguments;
        } else |_| {}
    }
}

test "Python-compatible JSON emits recursively sorted compact and pretty bytes" {
    const raw =
        "{\"z\":[true,null],\"a\":{\"\\u00e9\":\"\\ud83d\\ude00\",\"c\":2},\"escape\":\"\\b\\f\\n\\r\\t\"}";
    var document = try core.contracts.Document.parse(allocator, raw, .{});
    defer document.deinit();
    const compact = try build_tool.json.valueAlloc(allocator, document.value(), .compact);
    defer allocator.free(compact);
    try testing.expectEqualStrings(
        "{\"a\":{\"c\":2,\"\\u00e9\":\"\\ud83d\\ude00\"},\"escape\":\"\\b\\f\\n\\r\\t\",\"z\":[true,null]}\n",
        compact,
    );
    const pretty = try build_tool.json.valueAlloc(allocator, document.value(), .pretty);
    defer allocator.free(pretty);
    try testing.expectEqualStrings(
        "{\n" ++
            "  \"a\": {\n" ++
            "    \"c\": 2,\n" ++
            "    \"\\u00e9\": \"\\ud83d\\ude00\"\n" ++
            "  },\n" ++
            "  \"escape\": \"\\b\\f\\n\\r\\t\",\n" ++
            "  \"z\": [\n" ++
            "    true,\n" ++
            "    null\n" ++
            "  ]\n" ++
            "}\n",
        pretty,
    );
}

test "Python-compatible JSON preserves filesystem surrogateescape bytes" {
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    try build_tool.json.writeString(&output.writer, "valid-\xc3\xa9-invalid-\xff");
    const bytes = try output.toOwnedSlice();
    defer allocator.free(bytes);
    try testing.expectEqualStrings("\"valid-\\u00e9-invalid-\\udcff\"", bytes);
}

test "JSON parser rejects duplicate and bounded malformed inputs" {
    try testing.expectError(
        error.DuplicateField,
        build_tool.json.parse(
            allocator,
            "{\"a\":1,\"a\":2}",
            .{ .bytes = 64, .depth = 4, .string_bytes = 16, .items = 8, .tokens = 16 },
        ),
    );
    try testing.expectError(
        error.InputTooLarge,
        build_tool.json.parse(
            allocator,
            "{\"oversized\":true}",
            .{ .bytes = 4, .depth = 4, .string_bytes = 4, .items = 8, .tokens = 16 },
        ),
    );
    try testing.expectError(
        error.TooDeep,
        build_tool.json.parse(
            allocator,
            "[[[1]]]",
            .{ .bytes = 64, .depth = 2, .string_bytes = 16, .items = 8, .tokens = 16 },
        ),
    );
}

test "C embedding and identity header retain historical exact bytes" {
    var payload: [17]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);
    const embedded = try build_tool.prepare.embeddedSourceAlloc(allocator, &.{
        .{ .name = "wamr_fixture", .bytes = &payload },
    });
    defer allocator.free(embedded);
    try testing.expectEqualStrings(
        "/* Generated by prepare.py from matching trusted native bytes. */\n" ++
            "#include <stddef.h>\n" ++
            "const unsigned char wamr_fixture[] = {\n" ++
            "0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,\n" ++
            "0x10\n" ++
            "};\n" ++
            "const size_t wamr_fixture_size = sizeof(wamr_fixture);\n",
        embedded,
    );
    const header = try build_tool.prepare.identityHeaderAlloc(allocator, .{
        .revision = "a" ** 40,
        .variant = .snapshot,
        .jit_mode = null,
        .source_tree_sha256 = "b" ** 64,
        .compiler_sha256 = "c" ** 64,
        .coremark = false,
        .wasm_sha256 = "d" ** 64,
        .cwasm_sha256 = "e" ** 64,
        .library_sha256 = "f" ** 64,
    });
    defer allocator.free(header);
    try testing.expectEqualStrings(
        "#define WAMR_REVISION \"" ++ "a" ** 40 ++ "\"\n" ++
            "#define WAMR_APP_VARIANT 1\n" ++
            "#define WAMR_JIT_BOOT_MODE 0\n" ++
            "#define WAMR_SOURCE_TREE_SHA256 \"" ++ "b" ** 64 ++ "\"\n" ++
            "#define WAMR_COMPILER_SHA256 \"" ++ "c" ** 64 ++ "\"\n" ++
            "#define WAMR_HAS_COREMARK 0\n" ++
            "#define WAMR_WASM_SHA256 \"" ++ "d" ** 64 ++ "\"\n" ++
            "#define WAMR_CWASM_SHA256 \"" ++ "e" ** 64 ++ "\"\n" ++
            "#define WAMR_LIBRARY_SHA256 \"" ++ "f" ** 64 ++ "\"\n",
        header,
    );
}

test "native Make environment uses the shared encoder" {
    const encoded = try build_tool.image.encodeMakeEnvironment(allocator, .{
        .bison_data = "/native/bison",
        .m4 = "/native/m4",
        .schema = .unikraft_native_make_environment_v1,
        .shell = "/native/bash",
        .tmp = "/private/tmp",
        .xdg_cache = "/private/cache",
        .xdg_config = "/private/config",
        .zig_global_cache = "/private/zig-global",
        .zig_local_cache = "/private/zig-local",
    });
    defer allocator.free(encoded);
    try testing.expectEqualStrings(
        "{\"bison_data\":\"/native/bison\",\"m4\":\"/native/m4\",\"schema\":\"unikraft_native_make_environment_v1\",\"shell\":\"/native/bash\",\"tmp\":\"/private/tmp\",\"xdg_cache\":\"/private/cache\",\"xdg_config\":\"/private/config\",\"zig_global_cache\":\"/private/zig-global\",\"zig_local_cache\":\"/private/zig-local\"}\n",
        encoded,
    );
}

test "private file helpers set explicit modes and reject hard-linked state" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    try build_tool.files.writePrivateCreate(io, temporary.dir, "record.json", "{}\n");
    const file = try temporary.dir.openFile(io, "record.json", .{});
    defer file.close(io);
    const stat = try file.stat(io);
    try testing.expectEqual(@as(u16, 0o600), stat.permissions.toMode() & 0o7777);
    const digest = try build_tool.files.hashStableFile(io, file, 1024);
    var expected_digest: [32]u8 = undefined;
    core.Sha256.hash("{}\n", &expected_digest, .{});
    try testing.expectEqualSlices(
        u8,
        &std.fmt.bytesToHex(expected_digest, .lower),
        &digest,
    );
    const name = try allocator.dupeZ(u8, "record.json");
    defer allocator.free(name);
    if (linux.errno(linux.linkat(
        temporary.dir.handle,
        name,
        temporary.dir.handle,
        "second.json",
        0,
    )) != .SUCCESS) return error.LinkFixtureFailed;
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "record.json" });
    defer allocator.free(path);
    try testing.expectError(error.UnsafeFile, core.private_files.openAbsolute(io, path, .private));
}

test "repository boundary requires a canonical root and exact app location" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    try privatePath(temporary.dir, "repo");
    try privatePath(temporary.dir, "repo/support");
    try privatePath(temporary.dir, "repo/support/apps");
    try privatePath(temporary.dir, "repo/support/apps/wamr-aot");
    const base = try temporary.dir.realPathFileAlloc(io, "repo", allocator);
    defer allocator.free(base);
    const repository = try build_tool.files.Repository.open(allocator, io, base);
    repository.close(allocator, io);
    try temporary.dir.symLink(io, "repo", "alias", .{ .is_directory = true });
    const alias = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(alias);
    const alias_path = try std.fs.path.join(allocator, &.{ alias, "alias" });
    defer allocator.free(alias_path);
    try testing.expectError(
        error.UnsafeRepository,
        build_tool.files.Repository.open(allocator, io, alias_path),
    );
}

test "Git archive extraction preserves file modes links and exact source recipe" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    var tar = Tar.init(allocator);
    defer tar.deinit();
    try tar.entry("src/", '5', 0o775, "", "");
    try tar.entry("src/a.txt", '0', 0o664, "", "abc");
    try tar.entry("run", '0', 0o775, "", "#!");
    try tar.entry("alias", '2', 0o777, "src/a.txt", "");
    try tar.entry("copy", '1', 0o644, "src/a.txt", "");
    const long_path = "source/with/a/pax/path.txt";
    try tar.paxPath(long_path);
    try tar.entry("placeholder", '0', 0o644, "", "pax");
    try tar.finish();
    const archive = try writeArchive(temporary.dir, "source.tar", tar.bytes.items);
    defer allocator.free(archive);
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    const destination = try std.fs.path.join(allocator, &.{ base, "export" });
    defer allocator.free(destination);
    const result = try build_tool.files.extractGitArchive(
        allocator,
        io,
        archive,
        destination,
        .{},
    );
    try testing.expectEqual(@as(usize, 6), result.entries);
    try testing.expectEqual(@as(usize, 3), result.files);
    try testing.expectEqual(@as(usize, 1), result.symbolic_links);
    try testing.expectEqual(@as(usize, 1), result.hard_links);
    try testing.expectEqual(@as(u64, 3 + 2 + 3), result.file_bytes);
    try expectFile(temporary.dir, "export/src/a.txt", "abc", 0o644);
    try expectFile(temporary.dir, "export/run", "#!", 0o755);
    try expectFile(temporary.dir, "export/source/with/a/pax/path.txt", "pax", 0o644);

    var identity = try build_tool.files.sourceIdentity(allocator, io, destination, .{});
    defer identity.deinit(allocator);
    try testing.expectEqual(@as(usize, 5), identity.files);
    try testing.expectEqualStrings(
        "{\"alias\":{\"bytes\":3,\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}," ++
            "\"copy\":{\"bytes\":3,\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}," ++
            "\"run\":{\"bytes\":2,\"sha256\":\"3612ddaf46e149a4f583faf0face846585148f59e0ce2645594df83b5dc807e8\"}," ++
            "\"source/with/a/pax/path.txt\":{\"bytes\":3,\"sha256\":\"327fb97d65cd3e8a4455360fe34d4480ee7e2774149c849e0c018f68a297eb86\"}," ++
            "\"src/a.txt\":{\"bytes\":3,\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}}\n",
        identity.bytes,
    );
    var digest: [32]u8 = undefined;
    core.Sha256.hash(identity.bytes[0 .. identity.bytes.len - 1], &digest, .{});
    try testing.expectEqualSlices(
        u8,
        &std.fmt.bytesToHex(digest, .lower),
        &identity.sha256,
    );
}

test "Git archive extraction rejects traversal links duplicates types modes and truncation" {
    const cases = [_]ArchiveCase{
        .{ .name = "traversal", .entry = .{ .path = "../escape", .kind = '0', .mode = 0o644, .data = "x" }, .expected = error.UnsafeArchivePath },
        .{ .name = "absolute", .entry = .{ .path = "/escape", .kind = '0', .mode = 0o644, .data = "x" }, .expected = error.UnsafeArchivePath },
        .{ .name = "escaping-symlink", .entry = .{ .path = "a/link", .kind = '2', .mode = 0o777, .link = "../../escape" }, .expected = error.EscapingArchiveLink },
        .{ .name = "escaping-hardlink", .entry = .{ .path = "copy", .kind = '1', .mode = 0o644, .link = "../escape" }, .expected = error.EscapingArchiveLink },
        .{ .name = "fifo", .entry = .{ .path = "fifo", .kind = '6', .mode = 0o644 }, .expected = error.UnsupportedArchiveType },
        .{ .name = "mode", .entry = .{ .path = "file", .kind = '0', .mode = 0o600, .data = "x" }, .expected = error.UnsupportedArchiveMode },
    };
    for (cases) |case| {
        var temporary = testing.tmpDir(.{ .iterate = true });
        defer temporary.cleanup();
        try temporary.dir.setPermissions(io, .fromMode(0o700));
        var tar = Tar.init(allocator);
        defer tar.deinit();
        try tar.entry(case.entry.path, case.entry.kind, case.entry.mode, case.entry.link, case.entry.data);
        try tar.finish();
        try expectArchiveError(&temporary, case.name, tar.bytes.items, case.expected);
    }

    {
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("pax", 'x', 0o644, "", "8 path=x\n");
            try tar.entry("x", '0', 0o644, "", "x");
            try tar.finish();
            try expectArchiveError(&temporary, "malformed-pax", tar.bytes.items, error.MalformedPax);
        }
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("file", '0', 0o644, "", "x");
            try tar.finish();
            tar.bytes.items[0] = 'F';
            try expectArchiveError(
                &temporary,
                "checksum",
                tar.bytes.items,
                error.ArchiveChecksumMismatch,
            );
        }
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("node", '0', 0o644, "", "x");
            try tar.entry("node/child", '0', 0o644, "", "x");
            try tar.finish();
            try expectArchiveError(&temporary, "type-change", tar.bytes.items, error.NotDir);
        }
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("a", '0', 0o644, "", "a");
            try tar.entry("b", '0', 0o644, "", "b");
            try tar.finish();
            const archive = try writeArchive(temporary.dir, "fixture.tar", tar.bytes.items);
            defer allocator.free(archive);
            const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
            defer allocator.free(base);
            const destination = try std.fs.path.join(allocator, &.{ base, "entry-limit" });
            defer allocator.free(destination);
            try testing.expectError(
                error.ArchiveEntryLimit,
                build_tool.files.extractGitArchive(
                    allocator,
                    io,
                    archive,
                    destination,
                    .{ .entries = 1 },
                ),
            );
        }
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("a/b", '0', 0o644, "", "ab");
            try tar.finish();
            const archive = try writeArchive(temporary.dir, "fixture.tar", tar.bytes.items);
            defer allocator.free(archive);
            const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
            defer allocator.free(base);
            const depth_destination = try std.fs.path.join(allocator, &.{ base, "depth-limit" });
            defer allocator.free(depth_destination);
            try testing.expectError(
                error.ArchiveDepthLimit,
                build_tool.files.extractGitArchive(
                    allocator,
                    io,
                    archive,
                    depth_destination,
                    .{ .depth = 1 },
                ),
            );
        }
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("long", '0', 0o644, "", "1234");
            try tar.finish();
            const archive = try writeArchive(temporary.dir, "fixture.tar", tar.bytes.items);
            defer allocator.free(archive);
            const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
            defer allocator.free(base);
            inline for (.{
                .{ "file-limit", build_tool.files.ArchiveLimits{ .file_bytes = 3 }, error.ArchiveByteLimit },
                .{ "path-limit", build_tool.files.ArchiveLimits{ .path_bytes = 3 }, error.UnsafeArchivePath },
                .{ "archive-limit", build_tool.files.ArchiveLimits{ .archive_bytes = 1024 }, error.ArchiveTooLarge },
            }) |case| {
                const destination = try std.fs.path.join(allocator, &.{ base, case[0] });
                defer allocator.free(destination);
                try testing.expectError(
                    case[2],
                    build_tool.files.extractGitArchive(
                        allocator,
                        io,
                        archive,
                        destination,
                        case[1],
                    ),
                );
            }
        }
        {
            var temporary = testing.tmpDir(.{ .iterate = true });
            defer temporary.cleanup();
            try temporary.dir.setPermissions(io, .fromMode(0o700));
            var tar = Tar.init(allocator);
            defer tar.deinit();
            try tar.entry("a", '0', 0o644, "", "aa");
            try tar.entry("b", '0', 0o644, "", "bb");
            try tar.finish();
            const archive = try writeArchive(temporary.dir, "fixture.tar", tar.bytes.items);
            defer allocator.free(archive);
            const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
            defer allocator.free(base);
            const destination = try std.fs.path.join(allocator, &.{ base, "total-limit" });
            defer allocator.free(destination);
            try testing.expectError(
                error.ArchiveByteLimit,
                build_tool.files.extractGitArchive(
                    allocator,
                    io,
                    archive,
                    destination,
                    .{ .total_file_bytes = 3 },
                ),
            );
        }
    }

    var duplicate_tmp = testing.tmpDir(.{ .iterate = true });
    defer duplicate_tmp.cleanup();
    try duplicate_tmp.dir.setPermissions(io, .fromMode(0o700));
    var duplicate = Tar.init(allocator);
    defer duplicate.deinit();
    try duplicate.entry("same", '0', 0o644, "", "a");
    try duplicate.entry("same", '0', 0o644, "", "b");
    try duplicate.finish();
    try expectArchiveError(&duplicate_tmp, "duplicate", duplicate.bytes.items, error.DuplicateArchiveEntry);

    var truncated_tmp = testing.tmpDir(.{ .iterate = true });
    defer truncated_tmp.cleanup();
    try truncated_tmp.dir.setPermissions(io, .fromMode(0o700));
    var truncated = Tar.init(allocator);
    defer truncated.deinit();
    try truncated.entry("file", '0', 0o644, "", "x");
    try truncated.finish();
    try expectArchiveError(
        &truncated_tmp,
        "truncated",
        truncated.bytes.items[0 .. truncated.bytes.items.len - 1],
        error.TruncatedArchive,
    );
}

test "archive interruption preserves partial private evidence and reruns refuse" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const payload = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(payload);
    @memset(payload, 'x');
    var tar = Tar.init(allocator);
    defer tar.deinit();
    try tar.entry("large", '0', 0o644, "", payload);
    try tar.finish();
    const archive = try writeArchive(temporary.dir, "source.tar", tar.bytes.items);
    defer allocator.free(archive);
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    const destination = try std.fs.path.join(allocator, &.{ base, "partial" });
    defer allocator.free(destination);
    try testing.expectError(
        error.InjectedInterruption,
        build_tool.files.extractGitArchiveFault(
            allocator,
            io,
            archive,
            destination,
            .{},
            .{ .interrupt_after_archive_bytes = 512 + 64 * 1024 },
        ),
    );
    const stat = try temporary.dir.statFile(io, "partial/large", .{});
    try testing.expectEqual(@as(u64, 64 * 1024), stat.size);
    try testing.expectError(
        error.PathAlreadyExists,
        build_tool.files.extractGitArchive(allocator, io, archive, destination, .{}),
    );
}

test "retained archive detects mutation after selection" {
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const path = try writeArchive(temporary.dir, "selected.tar", "fixture");
    defer allocator.free(path);
    var retained = try build_tool.files.RetainedFile.open(io, path, .artifact);
    defer retained.close(io);
    const changed = try temporary.dir.openFile(io, "selected.tar", .{ .mode = .read_write });
    defer changed.close(io);
    try changed.writePositionalAll(io, "X", 0);
    try testing.expectError(error.FileChanged, retained.verify(io));
}

const ArchiveEntry = struct {
    path: []const u8,
    kind: u8,
    mode: u32,
    link: []const u8 = "",
    data: []const u8 = "",
};

const ArchiveCase = struct {
    name: []const u8,
    entry: ArchiveEntry,
    expected: anyerror,
};

const Tar = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8),

    fn init(a: std.mem.Allocator) Tar {
        return .{ .allocator = a, .bytes = .empty };
    }

    fn deinit(self: *Tar) void {
        self.bytes.deinit(self.allocator);
    }

    fn entry(
        self: *Tar,
        name: []const u8,
        kind: u8,
        mode: u32,
        link: []const u8,
        contents: []const u8,
    ) !void {
        var header: [512]u8 = [_]u8{0} ** 512;
        if (name.len > 100 or link.len > 100) return error.FixturePathTooLong;
        @memcpy(header[0..name.len], name);
        putOctal(header[100..108], mode);
        putOctal(header[108..116], linux.geteuid());
        putOctal(header[116..124], linux.getegid());
        putOctal(header[124..136], contents.len);
        putOctal(header[136..148], 0);
        @memset(header[148..156], ' ');
        header[156] = kind;
        @memcpy(header[157..][0..link.len], link);
        @memcpy(header[257..263], "ustar\x00");
        @memcpy(header[263..265], "00");
        var checksum: u64 = 0;
        for (header) |byte| checksum += byte;
        putChecksum(header[148..156], checksum);
        try self.bytes.appendSlice(self.allocator, &header);
        try self.bytes.appendSlice(self.allocator, contents);
        const padding = std.mem.alignForward(usize, contents.len, 512) - contents.len;
        try self.bytes.appendNTimes(self.allocator, 0, padding);
    }

    fn paxPath(self: *Tar, path: []const u8) !void {
        var length = path.len + " path=\n".len + 1;
        while (true) {
            const digits = decimalDigits(length);
            const adjusted = path.len + " path=\n".len + digits;
            if (adjusted == length) break;
            length = adjusted;
        }
        const record = try std.fmt.allocPrint(self.allocator, "{d} path={s}\n", .{ length, path });
        defer self.allocator.free(record);
        try self.entry("pax-header", 'x', 0o644, "", record);
    }

    fn finish(self: *Tar) !void {
        try self.bytes.appendNTimes(self.allocator, 0, 1024);
    }
};

fn putOctal(field: []u8, value: u64) void {
    @memset(field, '0');
    field[field.len - 1] = 0;
    var remaining = value;
    var index = field.len - 1;
    while (index > 0 and remaining != 0) {
        index -= 1;
        field[index] = @intCast('0' + remaining % 8);
        remaining /= 8;
    }
}

fn putChecksum(field: []u8, value: u64) void {
    @memset(field, '0');
    field[field.len - 1] = ' ';
    field[field.len - 2] = 0;
    var remaining = value;
    var index = field.len - 2;
    while (index > 0 and remaining != 0) {
        index -= 1;
        field[index] = @intCast('0' + remaining % 8);
        remaining /= 8;
    }
}

fn decimalDigits(value: usize) usize {
    var result: usize = 1;
    var remaining = value;
    while (remaining >= 10) : (remaining /= 10) result += 1;
    return result;
}

fn writeArchive(directory: std.Io.Dir, name: []const u8, bytes: []const u8) ![:0]u8 {
    const file = try directory.createFile(io, name, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    try file.writePositionalAll(io, bytes, 0);
    try file.setLength(io, bytes.len);
    return directory.realPathFileAlloc(io, name, allocator);
}

fn expectArchiveError(
    temporary: *testing.TmpDir,
    name: []const u8,
    bytes: []const u8,
    expected: anyerror,
) !void {
    const archive = try writeArchive(temporary.dir, "fixture.tar", bytes);
    defer allocator.free(archive);
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    const destination = try std.fs.path.join(allocator, &.{ base, name });
    defer allocator.free(destination);
    try testing.expectError(
        expected,
        build_tool.files.extractGitArchive(allocator, io, archive, destination, .{}),
    );
}

fn expectFile(
    directory: std.Io.Dir,
    path: []const u8,
    expected: []const u8,
    mode: u16,
) !void {
    const bytes = try directory.readFileAlloc(io, path, allocator, .limited(1024));
    defer allocator.free(bytes);
    try testing.expectEqualStrings(expected, bytes);
    const stat = try directory.statFile(io, path, .{});
    try testing.expectEqual(mode, stat.permissions.toMode() & 0o7777);
}

fn privatePath(directory: std.Io.Dir, path: []const u8) !void {
    try directory.createDir(io, path, .fromMode(0o700));
    const opened = try directory.openDir(io, path, .{ .iterate = true });
    defer opened.close(io);
    try opened.setPermissions(io, .fromMode(0o700));
}
