// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
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
    try testing.expectEqualStrings("uk-wamr-aot-build prepare-verify/1\n", version.stdout);
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
    try testing.expectEqualStrings("wamr_aot_build_failed category=local_failure\n", refused.stderr);
    try testing.expect(std.mem.indexOf(u8, refused.stderr, repository) == null);
}

test "native prepare and verify cover every variant with create-only output" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.prepare_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const archive = try sourceArchive(&temporary);
    defer allocator.free(archive);
    const cases = [_]PrepareCase{
        .{ .name = "tiny" },
        .{ .name = "tiny-coremark", .coremark = true },
        .{ .name = "snapshot", .variant = "snapshot" },
        .{ .name = "sample-aot", .variant = "sample-aot" },
        .{ .name = "jit-fast", .variant = "jit", .jit_mode = "fast" },
        .{ .name = "jit-full", .variant = "jit", .jit_mode = "full" },
    };
    for (cases) |case| {
        const repository = try fixtureRepository(&temporary, case.name);
        defer allocator.free(repository);
        var environment = try fixtureEnvironment(fixture);
        defer environment.deinit();
        const result = try runPrepare(
            cli,
            repository,
            archive,
            case,
            &environment,
        );
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.term != .exited)
            std.debug.print("prepare case {s} terminated {any}\nstdout={s}\nstderr={s}\n", .{
                case.name,
                result.term,
                result.stdout,
                result.stderr,
            });
        try expectExit(result.term, 0);
        try testing.expectEqualStrings("", result.stdout);
        try testing.expectEqualStrings("", result.stderr);
        const identity_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/artifacts/identity.json" },
        );
        defer allocator.free(identity_path);
        const identity = try std.Io.Dir.cwd().readFileAlloc(
            io,
            identity_path,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(identity);
        var document = try build_tool.json.parse(allocator, identity, .{
            .bytes = 1024 * 1024,
            .items = 4096,
            .tokens = 65536,
        });
        defer document.deinit();
        const fields = document.value().object;
        try testing.expect(std.mem.startsWith(u8, identity, "{\n"));
        try testing.expect(std.mem.endsWith(u8, identity, "\n}\n"));
        try testing.expectEqualStrings("1", fields.get("schema_version").?.number_string);
        try testing.expectEqualStrings(build_tool.revision, fields.get("wamr_revision").?.string);
        try testing.expectEqualStrings(
            case.variant,
            fields.get("variant").?.string,
        );
        if (case.jit_mode) |mode|
            try testing.expectEqualStrings(mode, fields.get("jit_mode").?.string)
        else
            try testing.expect(fields.get("jit_mode").? == .null);
        try testing.expectEqual(case.coremark, fields.get("minimal_wasi").?.bool);
        const files = fields.get("files").?.object;
        try testing.expectEqualStrings(
            "5e43618eda26c083b511b9570d347123affd2b1a14bfc22be766e95c1c8153f8",
            files.get("tiny.wasm").?.string,
        );
        try testing.expectEqualStrings(
            "64af337c6a3ad81ac353b47602b535340d605da1eb6d3fac48125685df659225",
            files.get("tiny.cwasm").?.string,
        );
        const library = if (case.coremark)
            "fixture-library variant=tiny coremark=true\n"
        else
            try std.fmt.allocPrint(
                allocator,
                "fixture-library variant={s} coremark=false\n",
                .{case.variant},
            );
        defer if (!case.coremark) allocator.free(library);
        const library_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/artifacts/libwamr-aot.a" },
        );
        defer allocator.free(library_path);
        try expectGoldenFile(library_path, library, 0o600);
        const wasm_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/artifacts/tiny.wasm" },
        );
        defer allocator.free(wasm_path);
        try expectGoldenFile(wasm_path, "fixture-tiny-wasm", 0o700);
        const cwasm_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/artifacts/tiny.cwasm" },
        );
        defer allocator.free(cwasm_path);
        try expectGoldenFile(cwasm_path, "fixture-cwasm:fixture-tiny-wasm", 0o600);
        const identity_file = try std.Io.Dir.openFileAbsolute(io, identity_path, .{});
        defer identity_file.close(io);
        try testing.expectEqual(@as(u16, 0o600), (try identity_file.stat(io)).permissions.toMode() & 0o7777);
        const verified = try runCli(
            cli,
            &.{ cli, "verify", "--repository", repository },
            &environment,
        );
        defer allocator.free(verified.stdout);
        defer allocator.free(verified.stderr);
        try expectExit(verified.term, 0);

        const collision = try runPrepare(
            cli,
            repository,
            archive,
            case,
            &environment,
        );
        defer allocator.free(collision.stdout);
        defer allocator.free(collision.stderr);
        try expectExit(collision.term, 2);
        const after_collision = try std.Io.Dir.cwd().readFileAlloc(
            io,
            identity_path,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(after_collision);
        try testing.expectEqualSlices(u8, identity, after_collision);

        if (std.mem.eql(u8, case.name, "tiny"))
            try tamperRefusals(cli, repository, &environment);
    }
}

test "runtime identity is byte-identical across separate source roots" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.prepare_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const archive = try sourceArchive(&temporary);
    defer allocator.free(archive);
    var first: ?[]u8 = null;
    defer if (first) |bytes| allocator.free(bytes);
    var first_raw_library: ?[]u8 = null;
    defer if (first_raw_library) |bytes| allocator.free(bytes);
    inline for (.{ "source-python", "source-native" }) |name| {
        const repository = try fixtureRepository(&temporary, name);
        defer allocator.free(repository);
        var environment = try fixtureEnvironment(fixture);
        defer environment.deinit();
        try environment.put("WAMR_PREPARE_FIXTURE_ARCHIVE_PATH_DEPENDENT", "1");
        const prepared = try runPrepare(
            cli,
            repository,
            archive,
            .{ .name = name },
            &environment,
        );
        defer allocator.free(prepared.stdout);
        defer allocator.free(prepared.stderr);
        try expectExit(prepared.term, 0);
        const verified = try runCli(
            cli,
            &.{ cli, "verify", "--repository", repository },
            &environment,
        );
        defer allocator.free(verified.stdout);
        defer allocator.free(verified.stderr);
        try expectExit(verified.term, 0);
        const raw_path = try std.fs.path.join(allocator, &.{
            repository,
            "support/apps/wamr-aot/build/workload-consumer/out/lib/libwamr-aot.a",
        });
        defer allocator.free(raw_path);
        const raw_library = try std.Io.Dir.cwd().readFileAlloc(
            io,
            raw_path,
            allocator,
            .limited(1024 * 1024),
        );
        if (first_raw_library) |original| {
            defer allocator.free(raw_library);
            try testing.expect(!std.mem.eql(u8, original, raw_library));
        } else {
            first_raw_library = raw_library;
        }
        const identity_path = try std.fs.path.join(allocator, &.{
            repository, "support/apps/wamr-aot/build/artifacts/identity.json",
        });
        defer allocator.free(identity_path);
        const identity = try std.Io.Dir.cwd().readFileAlloc(
            io,
            identity_path,
            allocator,
            .limited(1024 * 1024),
        );
        try testing.expect(std.mem.indexOf(u8, identity, repository) == null);
        try testing.expect(std.mem.indexOf(u8, identity, "\"<zig>\"") != null);
        try testing.expect(std.mem.indexOf(u8, identity, "\"<objcopy>\"") != null);
        try testing.expect(std.mem.indexOf(u8, identity, "\"<app>\"") != null);
        if (first) |original| {
            defer allocator.free(identity);
            try testing.expect(std.mem.eql(u8, original, identity));
        } else {
            first = identity;
        }
    }
}

test "prepare failures retain private diagnostics without a success identity" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.prepare_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const archive = try sourceArchive(&temporary);
    defer allocator.free(archive);

    inline for (.{
        .{ "child-failure", "workload-build", false },
        .{ "runtime-strip-failure", "runtime-strip", false },
        .{ "runtime-members-failure", "runtime-archive-members", false },
        .{ "runtime-extract-failure", "runtime-archive-extract", false },
        .{ "runtime-repack-failure", "runtime-archive-repack", false },
        .{ "runtime-member-invalid", "", false },
        .{ "matched-mismatch", "", true },
    }) |case| {
        const repository = try fixtureRepository(&temporary, case[0]);
        defer allocator.free(repository);
        var environment = try fixtureEnvironment(fixture);
        defer environment.deinit();
        if (case[1].len != 0)
            try environment.put("WAMR_PREPARE_FIXTURE_FAIL", case[1]);
        if (case[2])
            try environment.put("WAMR_PREPARE_FIXTURE_MISMATCH", "1");
        if (std.mem.eql(u8, case[0], "runtime-member-invalid"))
            try environment.put("WAMR_PREPARE_FIXTURE_INVALID_MEMBER", "1");
        const result = try runPrepare(
            cli,
            repository,
            archive,
            .{ .name = case[0], .variant = if (case[2]) "sample-aot" else "tiny" },
            &environment,
        );
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try expectExit(result.term, 2);
        if (std.mem.startsWith(u8, case[1], "runtime-"))
            try testing.expectEqualStrings(
                "wamr_aot_build_failed category=command_failed\n",
                result.stderr,
            );
        const identity_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/artifacts/identity.json" },
        );
        defer allocator.free(identity_path);
        try testing.expectError(
            error.FileNotFound,
            std.Io.Dir.openFileAbsolute(io, identity_path, .{}),
        );
        const diagnostics_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/native-environment/diagnostics" },
        );
        defer allocator.free(diagnostics_path);
        const diagnostics = try std.Io.Dir.openDirAbsolute(
            io,
            diagnostics_path,
            .{ .iterate = true, .follow_symlinks = false },
        );
        defer diagnostics.close(io);
        var iterator = diagnostics.iterate();
        try testing.expect((try iterator.next(io)) != null);
    }
}

test "development checkout selection is explicit and cannot masquerade as supported lineage" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(io, options.prepare_fixture, allocator);
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const archive = try sourceArchive(&temporary);
    defer allocator.free(archive);
    const base = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(base);
    const checkout = try std.fs.path.join(allocator, &.{ base, "checkout" });
    defer allocator.free(checkout);
    _ = try build_tool.files.extractGitArchive(allocator, io, archive, checkout, .{});
    var git_environment = std.process.Environ.Map.init(allocator);
    defer git_environment.deinit();
    try git_environment.put("PATH", "/usr/bin:/bin");
    try git_environment.put("GIT_AUTHOR_NAME", "Fixture");
    try git_environment.put("GIT_AUTHOR_EMAIL", "fixture@example.invalid");
    try git_environment.put("GIT_COMMITTER_NAME", "Fixture");
    try git_environment.put("GIT_COMMITTER_EMAIL", "fixture@example.invalid");
    for ([_][]const []const u8{
        &.{ "git", "init", "--quiet" },
        &.{ "git", "add", "." },
        &.{ "git", "commit", "--quiet", "-m", "fixture" },
    }) |arguments| {
        const result = try std.process.run(allocator, io, .{
            .argv = arguments,
            .cwd = .{ .path = checkout },
            .environ_map = &git_environment,
            .stdout_limit = .limited(1024),
            .stderr_limit = .limited(4096),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try expectExit(result.term, 0);
    }
    const head = try std.process.run(allocator, io, .{
        .argv = &.{ "git", "rev-parse", "HEAD" },
        .cwd = .{ .path = checkout },
        .environ_map = &git_environment,
        .stdout_limit = .limited(128),
        .stderr_limit = .limited(1024),
    });
    defer allocator.free(head.stdout);
    defer allocator.free(head.stderr);
    try expectExit(head.term, 0);
    const revision = std.mem.trim(u8, head.stdout, "\r\n");
    try testing.expectEqual(@as(usize, 40), revision.len);

    const repository = try fixtureRepository(&temporary, "development");
    defer allocator.free(repository);
    var environment = try fixtureEnvironment(fixture);
    defer environment.deinit();
    const git_path = try std.Io.Dir.cwd().realPathFileAlloc(io, options.git_executable, allocator);
    defer allocator.free(git_path);
    try environment.put("WAMR_CI_TOOL_GIT", git_path);
    const prepared = try runCli(
        cli,
        &.{ cli, "prepare", "--repository", repository, "--source", checkout, "--development-revision", revision },
        &environment,
    );
    defer allocator.free(prepared.stdout);
    defer allocator.free(prepared.stderr);
    if (prepared.term != .exited or prepared.term.exited != 0)
        std.debug.print("development prepare term={any} stderr={s}\n", .{ prepared.term, prepared.stderr });
    try expectExit(prepared.term, 0);
    const identity_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/artifacts/identity.json" },
    );
    defer allocator.free(identity_path);
    const identity = try std.Io.Dir.cwd().readFileAlloc(io, identity_path, allocator, .limited(1024 * 1024));
    defer allocator.free(identity);
    var document = try build_tool.json.parse(allocator, identity, .{ .bytes = 1024 * 1024 });
    defer document.deinit();
    const fields = document.value().object;
    try testing.expectEqualStrings(revision, fields.get("wamr_revision").?.string);
    try testing.expectEqualStrings(build_tool.development_scope, fields.get("scope").?.string);
    try testing.expect(fields.get("development_only").?.bool);
    const verified = try runCli(cli, &.{ cli, "verify", "--repository", repository }, &environment);
    defer allocator.free(verified.stdout);
    defer allocator.free(verified.stderr);
    try expectExit(verified.term, 0);
}

test "portable CI config reaches only opted-in image builds" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(io, options.image_fixture, allocator);
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const repository = try imageRepository(&temporary, "image");
    defer allocator.free(repository);
    try temporary.dir.createDir(io, "bison-data", .fromMode(0o700));
    const bison_data = try temporary.dir.realPathFileAlloc(io, "bison-data", allocator);
    defer allocator.free(bison_data);
    const log = try temporary.dir.createFile(io, "image.log", .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    log.close(io);
    const log_path = try temporary.dir.realPathFileAlloc(io, "image.log", allocator);
    defer allocator.free(log_path);
    var environment = try imageEnvironment(fixture, bison_data, log_path);
    defer environment.deinit();
    try environment.put("WAMR_CI_EXECUTABLE_PATH", cli);

    const argv = &.{ cli, "olddefconfig", "--repository", repository };
    const ordinary = try runCli(cli, argv, &environment);
    defer allocator.free(ordinary.stdout);
    defer allocator.free(ordinary.stderr);
    try expectExit(ordinary.term, 0);
    const ordinary_log = try std.Io.Dir.cwd().readFileAlloc(io, log_path, allocator, .limited(1024 * 1024));
    defer allocator.free(ordinary_log);
    try testing.expect(std.mem.indexOf(u8, ordinary_log, "-Dci-portable-config=true") == null);

    try environment.put("WAMR_CI_PORTABLE_CONFIG", "1");
    const portable = try runCli(cli, argv, &environment);
    defer allocator.free(portable.stdout);
    defer allocator.free(portable.stderr);
    try expectExit(portable.term, 0);
    const portable_log = try std.Io.Dir.cwd().readFileAlloc(io, log_path, allocator, .limited(1024 * 1024));
    defer allocator.free(portable_log);
    try testing.expect(std.mem.indexOf(u8, portable_log, "\t-Dci-portable-config=true\t") != null);

    try environment.put("WAMR_CI_PORTABLE_CONFIG", "invalid");
    const invalid = try runCli(cli, argv, &environment);
    defer allocator.free(invalid.stdout);
    defer allocator.free(invalid.stderr);
    try testing.expect(invalid.term == .exited and invalid.term.exited != 0);
    const failure_path = try std.fs.path.join(allocator, &.{
        repository, "support/apps/wamr-aot/build/native-environment/failure-error-name.txt",
    });
    defer allocator.free(failure_path);
    const failure = try std.Io.Dir.cwd().readFileAlloc(io, failure_path, allocator, .limited(128));
    defer allocator.free(failure);
    try testing.expectEqualStrings("InvalidPortableConfig", failure);
}

test "native image commands preserve config plans identities and failed publication" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.image_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const repository = try imageRepository(&temporary, "image");
    defer allocator.free(repository);
    try temporary.dir.createDir(io, "bison-data", .fromMode(0o700));
    const bison_data = try temporary.dir.realPathFileAlloc(
        io,
        "bison-data",
        allocator,
    );
    defer allocator.free(bison_data);
    const log = try temporary.dir.createFile(io, "image.log", .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    log.close(io);
    const log_path = try temporary.dir.realPathFileAlloc(io, "image.log", allocator);
    defer allocator.free(log_path);
    var environment = try imageEnvironment(fixture, bison_data, log_path);
    defer environment.deinit();
    try environment.put("WAMR_CI_EXECUTABLE_PATH", cli);

    const configured = try runCli(
        cli,
        &.{ cli, "olddefconfig", "--repository", repository },
        &environment,
    );
    defer allocator.free(configured.stdout);
    defer allocator.free(configured.stderr);
    if (configured.term != .exited or configured.term.exited != 0)
        std.debug.print(
            "olddefconfig failed term={any}\nstdout={s}\nstderr={s}\n",
            .{ configured.term, configured.stdout, configured.stderr },
        );
    try expectExit(configured.term, 0);
    try testing.expectEqualStrings("", configured.stdout);
    try testing.expectEqualStrings("", configured.stderr);
    try environment.put("WAMR_IMAGE_FIXTURE_REWRITE_CONFIG", "1");
    const expected_config =
        "CONFIG_FIXTURE=y\n\n" ++
        "CONFIG_STACK_SIZE_PAGE_ORDER=8\n" ++
        "CONFIG_APPWAMRAOT_JIT_BOOT_MODE=0\n";
    inline for (.{
        "support/apps/wamr-aot/.config",
        "support/apps/wamr-aot/build/.config",
    }) |relative| {
        const path = try std.fs.path.join(allocator, &.{ repository, relative });
        defer allocator.free(path);
        const contents = try std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(contents);
        try testing.expectEqualStrings(expected_config, contents);
    }

    const built = try runCli(
        cli,
        &.{ cli, "native-images", "--repository", repository },
        &environment,
    );
    defer allocator.free(built.stdout);
    defer allocator.free(built.stderr);
    if (built.term != .exited or built.term.exited != 0)
        std.debug.print(
            "native-images failed term={any}\nstdout={s}\nstderr={s}\n",
            .{ built.term, built.stdout, built.stderr },
        );
    try expectExit(built.term, 0);
    try testing.expectEqualStrings("", built.stdout);
    try testing.expectEqualStrings("", built.stderr);
    const identity_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/image-identity.json" },
    );
    defer allocator.free(identity_path);
    const identity = try std.Io.Dir.cwd().readFileAlloc(
        io,
        identity_path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(identity);
    try build_tool.image.validateIdentityBytes(allocator, identity);
    var document = try build_tool.json.parse(allocator, identity, .{
        .bytes = 4 * 1024 * 1024,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    const fields = document.value().object;
    try testing.expect(std.mem.startsWith(u8, identity, "{\n"));
    try testing.expect(std.mem.endsWith(u8, identity, "\n}\n"));
    try testing.expectEqualStrings("1", fields.get("schema_version").?.number_string);
    const image_files = fields.get("files").?.object;
    inline for (.{
        .{ "wamr_hyperv-x86_64-efi", "fixture-efi\n", "17c858bee604bc476724bfdc9246bcf461a14e8f45f9b557fff2134d8cf62128" },
        .{ "wamr_hyperv-x86_64-efi.dbg", "fixture-debug-elf\n", "cbfce9471d38cfd632471afcab99720ed27933c60d5ee5a33ac722c4f196aa98" },
        .{ "wamr_hyperv-x86_64-efi.bootinfo", "fixture-bootinfo\n", "540bd9e9ccf99a4de8b0d3eecc3aa56e5aa3d6247097bb3819bcd53c24068225" },
    }) |golden| {
        try testing.expectEqualStrings(golden[2], image_files.get(golden[0]).?.string);
        const path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build", golden[0] },
        );
        defer allocator.free(path);
        try expectGoldenFile(path, golden[1], 0o600);
    }
    try testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef01234567",
        fields.get("unikraft_revision").?.string,
    );
    const command = fields.get("command").?.array;
    try testing.expect(command.items.len > 2);
    var found_bridge = false;
    for (command.items) |argument| {
        if (std.mem.startsWith(
            u8,
            argument.string,
            "-Dwamr-aot-tool=",
        )) found_bridge = true;
    }
    try testing.expect(found_bridge);
    const root_state = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/native-environment" },
    );
    defer allocator.free(root_state);
    const log_bytes = try std.Io.Dir.cwd().readFileAlloc(io, log_path, allocator, .limited(1024 * 1024));
    defer allocator.free(log_bytes);
    try testing.expect(std.mem.indexOf(u8, log_bytes, "--print-datadir") != null);
    const root_argv = try std.fmt.allocPrint(
        allocator,
        "{s}\tbuild\tnative-images\t-j2\t--cache-dir\t{s}/zig_local_cache\t--global-cache-dir\t{s}/zig_global_cache",
        .{ fixture, root_state, root_state },
    );
    defer allocator.free(root_argv);
    try testing.expect(std.mem.indexOf(u8, log_bytes, root_argv) != null);
    try testing.expect(std.mem.indexOf(u8, log_bytes, "-Dnative-profile=hyperv-x86_64-efi-wamr") != null);
    const root_line_start = std.mem.lastIndexOf(u8, log_bytes, root_argv).?;
    const root_line = log_bytes[0..root_line_start];
    const root_line_start_index = if (std.mem.lastIndexOfScalar(u8, root_line, '\n')) |index| index + 1 else 0;
    var root_fields = std.mem.splitScalar(u8, root_line[root_line_start_index..], '\t');
    try testing.expectEqualStrings(repository, root_fields.next().?);
    const expected_tmp = try std.fmt.allocPrint(allocator, "{s}/tmp", .{root_state});
    defer allocator.free(expected_tmp);
    try testing.expectEqualStrings(expected_tmp, root_fields.next().?);
    inline for (0..5) |_| try testing.expectEqualStrings("", root_fields.next().?);
    const identity_file = try std.Io.Dir.openFileAbsolute(io, identity_path, .{});
    defer identity_file.close(io);
    try testing.expectEqual(
        @as(u16, 0o600),
        (try identity_file.stat(io)).permissions.toMode() & 0o7777,
    );

    try environment.put("WAMR_IMAGE_FIXTURE_FAIL", "native-images");
    const failed = try runCli(
        cli,
        &.{ cli, "native-images", "--repository", repository },
        &environment,
    );
    defer allocator.free(failed.stdout);
    defer allocator.free(failed.stderr);
    try expectExit(failed.term, 2);
    try testing.expectEqualStrings(
        "wamr_aot_build_failed category=command_failed\n",
        failed.stderr,
    );
    const after_failure = try std.Io.Dir.cwd().readFileAlloc(
        io,
        identity_path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(after_failure);
    try testing.expectEqualSlices(u8, identity, after_failure);

    _ = environment.swapRemove("WAMR_IMAGE_FIXTURE_FAIL");
    try environment.put("WAMR_IMAGE_FIXTURE_DIRTY", "1");
    const dirty = try runCli(
        cli,
        &.{ cli, "native-images", "--repository", repository },
        &environment,
    );
    defer allocator.free(dirty.stdout);
    defer allocator.free(dirty.stderr);
    try expectExit(dirty.term, 2);
    try testing.expectEqualStrings(
        "wamr_aot_build_failed category=unsupported_input\n",
        dirty.stderr,
    );
    const after_dirty = try std.Io.Dir.cwd().readFileAlloc(
        io,
        identity_path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(after_dirty);
    try testing.expectEqualSlices(u8, identity, after_dirty);
}

test "native image commands reject config runtime and application mutation" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.image_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    try temporary.dir.createDir(io, "bison-data", .fromMode(0o700));
    const bison_data = try temporary.dir.realPathFileAlloc(
        io,
        "bison-data",
        allocator,
    );
    defer allocator.free(bison_data);

    inline for (.{ "config", "runtime", "application" }) |mutation| {
        const repository = try imageRepository(&temporary, mutation);
        defer allocator.free(repository);
        const log_name = try std.fmt.allocPrint(
            allocator,
            "{s}.log",
            .{mutation},
        );
        defer allocator.free(log_name);
        const log = try temporary.dir.createFile(io, log_name, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        log.close(io);
        const log_path = try temporary.dir.realPathFileAlloc(
            io,
            log_name,
            allocator,
        );
        defer allocator.free(log_path);
        var environment = try imageEnvironment(fixture, bison_data, log_path);
        defer environment.deinit();
        const configured = try runCli(
            cli,
            &.{ cli, "olddefconfig", "--repository", repository },
            &environment,
        );
        defer allocator.free(configured.stdout);
        defer allocator.free(configured.stderr);
        try expectExit(configured.term, 0);
        if (std.mem.eql(u8, mutation, "config"))
            try environment.put("WAMR_IMAGE_FIXTURE_REWRITE_CONFIG", "1");
        try environment.put("WAMR_IMAGE_FIXTURE_MUTATE", mutation);
        const built = try runCli(
            cli,
            &.{ cli, "native-images", "--repository", repository },
            &environment,
        );
        defer allocator.free(built.stdout);
        defer allocator.free(built.stderr);
        try expectExit(built.term, 2);
        try testing.expectEqualStrings(
            "wamr_aot_build_failed category=unsupported_input\n",
            built.stderr,
        );
        if (std.mem.eql(u8, mutation, "config")) {
            const guard_path = try std.fs.path.join(
                allocator,
                &.{ repository, "support/apps/wamr-aot/build/native-environment/failure-image-guard.txt" },
            );
            defer allocator.free(guard_path);
            const guard = try std.Io.Dir.cwd().readFileAlloc(
                io,
                guard_path,
                allocator,
                .limited(96),
            );
            defer allocator.free(guard);
            try testing.expectEqualStrings("config-after-root-changed-bytes", guard);
        }
        try testing.expect(std.mem.indexOf(u8, built.stderr, repository) == null);
        const identity_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/image-identity.json" },
        );
        defer allocator.free(identity_path);
        try testing.expectError(
            error.FileNotFound,
            std.Io.Dir.openFileAbsolute(io, identity_path, .{}),
        );
    }
}

test "native config refuses a supplied executable that differs from the running image" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.image_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const repository = try imageRepository(&temporary, "wrong-executable");
    defer allocator.free(repository);
    var environment = try imageEnvironment(fixture, ".", "/dev/null");
    defer environment.deinit();
    try environment.put("WAMR_CI_EXECUTABLE_PATH", fixture);
    const result = try runCli(
        cli,
        &.{ cli, "olddefconfig", "--repository", repository },
        &environment,
    );
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try expectExit(result.term, 2);
    try testing.expectEqualStrings(
        "wamr_aot_build_failed category=unsupported_input\n",
        result.stderr,
    );
    var wrong = try build_tool.process.openTool(
        allocator,
        io,
        "wrong-image",
        fixture,
    );
    defer wrong.close(allocator, io);
    const retained_path = try std.fmt.allocPrint(
        allocator,
        "/proc/{d}/fd/{d}",
        .{ linux.getpid(), wrong.executable.file.handle },
    );
    defer allocator.free(retained_path);
    try environment.put("WAMR_CI_EXECUTABLE_PATH", cli);
    try environment.put("WAMR_CI_RETAINED_EXECUTABLE", retained_path);
    const wrong_retained = try runCli(
        cli,
        &.{ cli, "olddefconfig", "--repository", repository },
        &environment,
    );
    defer allocator.free(wrong_retained.stdout);
    defer allocator.free(wrong_retained.stderr);
    try expectExit(wrong_retained.term, 2);
    try testing.expectEqualStrings(
        "wamr_aot_build_failed category=unsupported_input\n",
        wrong_retained.stderr,
    );
    const guard_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/native-environment/failure-image-guard.txt" },
    );
    defer allocator.free(guard_path);
    const guard = try std.Io.Dir.cwd().readFileAlloc(
        io,
        guard_path,
        allocator,
        .limited(96),
    );
    defer allocator.free(guard);
    try testing.expectEqualStrings("retained-identity", guard);
}

test "native config binds a supervisor snapshot to its retained physical executable" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.image_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const repository = try imageRepository(&temporary, "supervised-snapshot");
    defer allocator.free(repository);
    try temporary.dir.createDir(io, "bison-data", .fromMode(0o700));
    const bison_data = try temporary.dir.realPathFileAlloc(
        io,
        "bison-data",
        allocator,
    );
    defer allocator.free(bison_data);
    const log = try temporary.dir.createFile(io, "snapshot.log", .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    log.close(io);
    const log_path = try temporary.dir.realPathFileAlloc(
        io,
        "snapshot.log",
        allocator,
    );
    defer allocator.free(log_path);
    var environment = try imageEnvironment(fixture, bison_data, log_path);
    defer environment.deinit();
    try environment.put("WAMR_CI_EXECUTABLE_PATH", cli);
    var tool = try build_tool.process.openTool(
        allocator,
        io,
        "wamr-aot-build",
        cli,
    );
    defer tool.close(allocator, io);
    const retained_path = try std.fmt.allocPrint(
        allocator,
        "/proc/{d}/fd/{d}",
        .{ linux.getpid(), tool.executable.file.handle },
    );
    defer allocator.free(retained_path);
    try environment.put("WAMR_CI_RETAINED_EXECUTABLE", retained_path);
    try build_tool.process.initialize();
    var result = try build_tool.process.run(allocator, io, tool, .{
        .argv = &.{ cli, "olddefconfig", "--repository", repository },
        .environment = &environment,
        .cwd = temporary.dir,
        .primary_deadline = try build_tool.process.Deadline.afterMilliseconds(60000),
        .cleanup_deadline = try build_tool.process.Deadline.afterMilliseconds(90000),
        .stdout_bytes = 1024,
        .stderr_bytes = 1024,
    });
    defer result.deinit(allocator);
    try build_tool.process.requireSuccess(result);
    try testing.expectEqualStrings("", result.stdout);
    try testing.expectEqualStrings("", result.stderr);
}

test "native config tool failures retain only private compiled error and role" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.image_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    const repository = try imageRepository(&temporary, "invalid-tool");
    defer allocator.free(repository);
    const log_path = try std.fs.path.join(
        allocator,
        &.{ repository, "image.log" },
    );
    defer allocator.free(log_path);
    var environment = try imageEnvironment(
        fixture,
        "relative/bison-data-does-not-exist",
        log_path,
    );
    defer environment.deinit();
    try environment.put("WAMR_CI_TOOL_MAKE", "relative/make-does-not-exist");
    const result = try runCli(
        cli,
        &.{ cli, "olddefconfig", "--repository", repository },
        &environment,
    );
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try expectExit(result.term, 2);
    try testing.expectEqualStrings(
        "wamr_aot_build_failed category=local_failure\n",
        result.stderr,
    );
    const error_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/native-environment/failure-error-name.txt" },
    );
    defer allocator.free(error_path);
    const error_name = try std.Io.Dir.cwd().readFileAlloc(
        io,
        error_path,
        allocator,
        .limited(96),
    );
    defer allocator.free(error_name);
    try testing.expectEqualStrings("InvalidToolOverride", error_name);
    const role_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/native-environment/failure-tool-role.txt" },
    );
    defer allocator.free(role_path);
    const role = try std.Io.Dir.cwd().readFileAlloc(
        io,
        role_path,
        allocator,
        .limited(96),
    );
    defer allocator.free(role);
    try testing.expectEqualStrings("make", role);
}

test "native Bison override, default query, and invalid-override refusals" {
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(cli);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        options.image_fixture,
        allocator,
    );
    defer allocator.free(fixture);
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    try temporary.dir.createDir(io, "bison-data", .fromMode(0o700));
    const bison_data = try temporary.dir.realPathFileAlloc(io, "bison-data", allocator);
    defer allocator.free(bison_data);
    const bison_file = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(bison_file);
    const file_override = try std.fs.path.join(allocator, &.{ bison_file, "not-a-directory" });
    defer allocator.free(file_override);
    try writeAbsolute(file_override, "file", 0o600);
    const missing_override = try std.fs.path.join(allocator, &.{ bison_file, "absent-bison-data" });
    defer allocator.free(missing_override);

    for ([_]struct { name: []const u8, override: ?[]const u8, query: bool, success: bool }{
        .{ .name = "explicit", .override = bison_data, .query = false, .success = true },
        .{ .name = "default", .override = null, .query = true, .success = true },
        .{ .name = "empty", .override = "", .query = false, .success = false },
        .{ .name = "relative", .override = "relative", .query = false, .success = false },
        .{ .name = "file", .override = file_override, .query = false, .success = false },
        .{ .name = "missing", .override = missing_override, .query = false, .success = false },
    }) |case| {
        const repository = try imageRepository(&temporary, case.name);
        defer allocator.free(repository);
        const log_path = try std.fs.path.join(allocator, &.{ repository, "image.log" });
        defer allocator.free(log_path);
        try writeAbsolute(log_path, "", 0o600);
        var environment = try imageEnvironment(fixture, bison_data, log_path);
        defer environment.deinit();
        try environment.put("WAMR_CI_EXECUTABLE_PATH", cli);
        if (case.override) |value| try environment.put("BISON_PKGDATADIR", value);
        const result = try runCli(
            cli,
            &.{ cli, "olddefconfig", "--repository", repository },
            &environment,
        );
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try expectExit(result.term, if (case.success) 0 else 2);
        const log_bytes = try std.Io.Dir.cwd().readFileAlloc(
            io,
            log_path,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(log_bytes);
        try testing.expectEqual(case.query, std.mem.indexOf(u8, log_bytes, "--print-datadir") != null);
        const config_path = try std.fs.path.join(
            allocator,
            &.{ repository, "support/apps/wamr-aot/build/.config" },
        );
        defer allocator.free(config_path);
        if (case.success) {
            try expectGoldenFile(
                config_path,
                "CONFIG_FIXTURE=y\n\nCONFIG_STACK_SIZE_PAGE_ORDER=8\nCONFIG_APPWAMRAOT_JIT_BOOT_MODE=0\n",
                0o600,
            );
        } else {
            try testing.expectEqualStrings("", log_bytes);
            try testing.expectError(error.FileNotFound, std.Io.Dir.openFileAbsolute(io, config_path, .{}));
        }
    }
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

test "supervised wrapper supports retained execution named argv and stdout files" {
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
    const output = try temporary.dir.createFile(io, "stdout", .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    try build_tool.process.initialize();
    var result = try build_tool.process.run(allocator, io, tool, .{
        .argv = &.{ "fixture-tool", "success" },
        .allow_named_argv0 = true,
        .environment = &environment,
        .cwd = temporary.dir,
        .primary_deadline = try build_tool.process.Deadline.afterMilliseconds(2000),
        .cleanup_deadline = try build_tool.process.Deadline.afterMilliseconds(5000),
        .stdout_file = output,
        .snapshot_executable = false,
        .stdout_bytes = 1024,
        .stderr_bytes = 1024,
    });
    defer result.deinit(allocator);
    try build_tool.process.requireSuccess(result);
    try testing.expectEqualStrings("", result.stdout);
    const written = try temporary.dir.readFileAlloc(
        io,
        "stdout",
        allocator,
        .limited(1024),
    );
    defer allocator.free(written);
    try testing.expectEqualStrings("fixture-success\n", written);
    const stat = try output.stat(io);
    try testing.expectEqual(@as(u16, 0o600), stat.permissions.toMode() & 0o7777);
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

const PrepareCase = struct {
    name: []const u8,
    variant: []const u8 = "tiny",
    jit_mode: ?[]const u8 = null,
    coremark: bool = false,
};

fn runPrepare(
    cli: []const u8,
    repository: []const u8,
    archive: []const u8,
    case: PrepareCase,
    environment: *const std.process.Environ.Map,
) !std.process.RunResult {
    var arguments: std.ArrayList([]const u8) = .empty;
    defer arguments.deinit(allocator);
    try arguments.appendSlice(allocator, &.{
        cli,
        "prepare",
        "--repository",
        repository,
        "--source-archive",
        archive,
    });
    if (!std.mem.eql(u8, case.variant, "tiny"))
        try arguments.appendSlice(allocator, &.{ "--variant", case.variant });
    if (case.coremark) try arguments.append(allocator, "--coremark");
    if (case.jit_mode) |mode|
        try arguments.appendSlice(allocator, &.{ "--jit-mode", mode });
    return runCli(cli, arguments.items, environment);
}

fn runCli(
    cli: []const u8,
    arguments: []const []const u8,
    environment: *const std.process.Environ.Map,
) !std.process.RunResult {
    _ = cli;
    return std.process.run(allocator, io, .{
        .argv = arguments,
        .environ_map = environment,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
}

fn fixtureEnvironment(fixture: []const u8) !std.process.Environ.Map {
    var environment = std.process.Environ.Map.init(allocator);
    errdefer environment.deinit();
    try environment.put("WAMR_CI_TOOL_ZIG", fixture);
    try environment.put("WAMR_CI_TOOL_LLVM_OBJCOPY", fixture);
    try environment.put("ZIG_LIB_DIR", options.zig_lib_dir);
    try environment.put("PATH", "/usr/bin:/bin");
    return environment;
}

fn fixtureRepository(temporary: *testing.TmpDir, name: []const u8) ![:0]u8 {
    const relative = try std.fmt.allocPrint(
        allocator,
        "{s}/support/apps/wamr-aot",
        .{name},
    );
    defer allocator.free(relative);
    try temporary.dir.createDirPath(io, relative);
    var components = std.mem.splitScalar(u8, relative, '/');
    var current = try temporary.dir.openDir(io, ".", .{ .iterate = true });
    defer current.close(io);
    while (components.next()) |component| {
        const next = try current.openDir(io, component, .{
            .iterate = true,
            .follow_symlinks = false,
        });
        try next.setPermissions(io, .fromMode(0o700));
        current.close(io);
        current = next;
    }
    inline for (.{
        "fixture.zig",
        "build-tool-prepare.zig",
        "workloads.build.zig",
        "snapshot.zig",
        "sampler.zig",
        "native-services.zig",
        "workloads.h",
        "platform.h",
        "wasi.zig",
    }) |file| try copyFixtureSource(temporary.dir, relative, file);
    return temporary.dir.realPathFileAlloc(io, name, allocator);
}

fn imageRepository(temporary: *testing.TmpDir, name: []const u8) ![:0]u8 {
    const relative = try std.fmt.allocPrint(
        allocator,
        "{s}/support/apps/wamr-aot",
        .{name},
    );
    defer allocator.free(relative);
    try temporary.dir.createDirPath(io, relative);
    var components = std.mem.splitScalar(u8, relative, '/');
    var current = try temporary.dir.openDir(io, ".", .{ .iterate = true });
    defer current.close(io);
    while (components.next()) |component| {
        const next = try current.openDir(io, component, .{
            .iterate = true,
            .follow_symlinks = false,
        });
        try next.setPermissions(io, .fromMode(0o700));
        current.close(io);
        current = next;
    }
    try copyFixtureSource(temporary.dir, relative, "build-tool-image.zig");
    const defconfig = try std.fs.path.join(
        allocator,
        &.{ relative, "defconfig" },
    );
    defer allocator.free(defconfig);
    const defconfig_file = try temporary.dir.createFile(io, defconfig, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer defconfig_file.close(io);
    try defconfig_file.writePositionalAll(io, "CONFIG_FIXTURE=y\n", 0);
    try defconfig_file.setPermissions(io, .fromMode(0o600));
    const artifacts = try std.fs.path.join(
        allocator,
        &.{ relative, "build/artifacts" },
    );
    defer allocator.free(artifacts);
    try temporary.dir.createDirPath(io, artifacts);
    var private_components = std.mem.splitScalar(u8, artifacts, '/');
    var private_current = try temporary.dir.openDir(io, ".", .{ .iterate = true });
    defer private_current.close(io);
    while (private_components.next()) |component| {
        const next = try private_current.openDir(io, component, .{
            .iterate = true,
            .follow_symlinks = false,
        });
        try next.setPermissions(io, .fromMode(0o700));
        private_current.close(io);
        private_current = next;
    }
    const identity = try std.fs.path.join(
        allocator,
        &.{ artifacts, "identity.json" },
    );
    defer allocator.free(identity);
    const identity_file = try temporary.dir.createFile(io, identity, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer identity_file.close(io);
    try identity_file.writePositionalAll(
        io,
        "{\n  \"jit_mode\": null,\n  \"variant\": \"snapshot\"\n}\n",
        0,
    );
    try identity_file.setPermissions(io, .fromMode(0o600));
    return temporary.dir.realPathFileAlloc(io, name, allocator);
}

fn imageEnvironment(
    fixture: []const u8,
    bison_data: []const u8,
    log_path: []const u8,
) !std.process.Environ.Map {
    var environment = std.process.Environ.Map.init(allocator);
    errdefer environment.deinit();
    inline for (.{
        "ZIG",
        "MAKE",
        "LLVM_NM",
        "LLVM_OBJCOPY",
        "LLVM_OBJDUMP",
        "LLVM_READELF",
        "LLVM_STRIP",
        "BISON",
        "FLEX",
        "M4",
        "BASH",
        "CP",
        "MKDIR",
        "PYTHON3",
        "READLINK",
        "GIT",
    }) |name| {
        try environment.put("WAMR_CI_TOOL_" ++ name, fixture);
    }
    try environment.put("PATH", "/usr/bin:/bin");
    try environment.put("WAMR_IMAGE_FIXTURE_BISON_DATA", bison_data);
    try environment.put("WAMR_IMAGE_FIXTURE_LOG", log_path);
    try environment.put(
        "WAMR_IMAGE_FIXTURE_REVISION",
        "0123456789abcdef0123456789abcdef01234567",
    );
    return environment;
}

fn copyFixtureSource(
    destination_root: std.Io.Dir,
    app_relative: []const u8,
    name: []const u8,
) !void {
    const source_path = try std.fs.path.join(
        allocator,
        &.{ options.repository_root, "support/apps/wamr-aot", name },
    );
    defer allocator.free(source_path);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        source_path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(bytes);
    const destination = try std.fs.path.join(allocator, &.{ app_relative, name });
    defer allocator.free(destination);
    const file = try destination_root.createFile(io, destination, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.setPermissions(io, .fromMode(0o600));
}

fn tamperRefusals(
    cli: []const u8,
    repository: []const u8,
    environment: *const std.process.Environ.Map,
) !void {
    inline for (.{
        "support/apps/wamr-aot/build/artifacts/tiny.cwasm",
        "support/apps/wamr-aot/build/artifacts/identity.h",
        "support/apps/wamr-aot/fixture.zig",
    }) |relative| {
        const path = try std.fs.path.join(allocator, &.{ repository, relative });
        defer allocator.free(path);
        const original = try std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(4 * 1024 * 1024),
        );
        defer allocator.free(original);
        const file = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write });
        try file.writePositionalAll(io, "X", 0);
        file.close(io);
        try expectVerifyRefusal(cli, repository, environment);
        const restore = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write });
        defer restore.close(io);
        try restore.writePositionalAll(io, original, 0);
        try restore.setLength(io, original.len);
    }

    const identity_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/artifacts/identity.json" },
    );
    defer allocator.free(identity_path);
    const identity = try std.Io.Dir.cwd().readFileAlloc(
        io,
        identity_path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(identity);
    inline for (.{
        .{ "\"schema_version\": 1", "\"schema_version\": 2" },
        .{ "\"variant\": \"tiny\"", "\"variant\": \"xxxx\"" },
        .{ "\"-j2\"", "\"-j3\"" },
        .{ "\"<zig>\"", "\"zig\"" },
        .{ "\"<objcopy>\"", "\"objcopy\"" },
        .{ "\"rcsD\"", "\"rcsU\"" },
        .{ "\"<app>/build/scratch/libwamr-aot.stripped.a\"", "\"<app>/build/scratch/other.a\"" },
        .{ "\"-fPIC\"", "\"-fBAD\"" },
        .{ "\"wamrc\":", "\"../x?\":" },
    }) |mutation| {
        const changed = try replaceOnceAlloc(identity, mutation[0], mutation[1]);
        defer allocator.free(changed);
        try writeAbsolute(identity_path, changed, 0o600);
        try expectVerifyRefusal(cli, repository, environment);
        try writeAbsolute(identity_path, identity, 0o600);
    }
    const duplicate = try replaceOnceAlloc(
        identity,
        "\"schema_version\": 1",
        "\"schema_version\": 1,\n  \"schema_version\": 1",
    );
    defer allocator.free(duplicate);
    try writeAbsolute(identity_path, duplicate, 0o600);
    try expectVerifyRefusal(cli, repository, environment);
    try writeAbsolute(identity_path, identity, 0o600);

    const artifact_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/artifacts/tiny.cwasm" },
    );
    defer allocator.free(artifact_path);
    const artifact = try std.Io.Dir.openFileAbsolute(io, artifact_path, .{});
    try artifact.setPermissions(io, .fromMode(0o644));
    artifact.close(io);
    try expectVerifyRefusal(cli, repository, environment);
    const private_artifact = try std.Io.Dir.openFileAbsolute(io, artifact_path, .{});
    try private_artifact.setPermissions(io, .fromMode(0o600));
    private_artifact.close(io);

    const extra_path = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/artifacts/unexpected" },
    );
    defer allocator.free(extra_path);
    try writeAbsolute(extra_path, "unexpected", 0o600);
    try expectVerifyRefusal(cli, repository, environment);
    try std.Io.Dir.deleteFileAbsolute(io, extra_path);

    const source_extra = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/wamr-source/unexpected" },
    );
    defer allocator.free(source_extra);
    try writeAbsolute(source_extra, "unexpected", 0o600);
    try expectVerifyRefusal(cli, repository, environment);
    try std.Io.Dir.deleteFileAbsolute(io, source_extra);

    const identity_link = try std.fs.path.join(
        allocator,
        &.{ repository, "support/apps/wamr-aot/build/artifacts/identity-link.json" },
    );
    defer allocator.free(identity_link);
    const identity_z = try allocator.dupeZ(u8, identity_path);
    defer allocator.free(identity_z);
    const link_z = try allocator.dupeZ(u8, identity_link);
    defer allocator.free(link_z);
    if (linux.errno(linux.linkat(
        linux.AT.FDCWD,
        identity_z,
        linux.AT.FDCWD,
        link_z,
        0,
    )) != .SUCCESS) return error.LinkFixtureFailed;
    try expectVerifyRefusal(cli, repository, environment);
    try std.Io.Dir.deleteFileAbsolute(io, identity_link);
}

fn expectVerifyRefusal(
    cli: []const u8,
    repository: []const u8,
    environment: *const std.process.Environ.Map,
) !void {
    const refused = try runCli(
        cli,
        &.{ cli, "verify", "--repository", repository },
        environment,
    );
    defer allocator.free(refused.stdout);
    defer allocator.free(refused.stderr);
    try expectExit(refused.term, 2);
    try testing.expectEqualStrings("", refused.stdout);
    try testing.expect(std.mem.startsWith(
        u8,
        refused.stderr,
        "wamr_aot_build_failed category=",
    ));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, refused.stderr, "\n"));
    try testing.expect(std.mem.indexOf(u8, refused.stderr, repository) == null);
}

fn replaceOnceAlloc(
    source: []const u8,
    needle: []const u8,
    replacement: []const u8,
) ![]u8 {
    const index = std.mem.indexOf(u8, source, needle) orelse
        return error.MissingFixtureText;
    const result = try allocator.alloc(
        u8,
        source.len - needle.len + replacement.len,
    );
    @memcpy(result[0..index], source[0..index]);
    @memcpy(result[index..][0..replacement.len], replacement);
    @memcpy(
        result[index + replacement.len ..],
        source[index + needle.len ..],
    );
    return result;
}

fn writeAbsolute(path: []const u8, contents: []const u8, mode: u16) !void {
    const file = std.Io.Dir.createFileAbsolute(io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    }) catch |err| switch (err) {
        error.PathAlreadyExists => try std.Io.Dir.openFileAbsolute(
            io,
            path,
            .{ .mode = .read_write },
        ),
        else => return err,
    };
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
    try file.setLength(io, contents.len);
    try file.setPermissions(io, .fromMode(mode));
    try file.sync(io);
}

fn expectGoldenFile(path: []const u8, expected: []const u8, mode: u16) !void {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    try testing.expectEqual(mode, (try file.stat(io)).permissions.toMode() & 0o7777);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    try testing.expectEqualStrings(expected, bytes);
}

fn sourceArchive(temporary: *testing.TmpDir) ![:0]u8 {
    var tar = Tar.init(allocator);
    defer tar.deinit();
    inline for (.{
        .{ "include/wamr_aot.h", "fixture-header" },
        .{ "tests/benchmarks/loop-passes/unroll4.wasm", "compute-wasm" },
        .{ "tests/benchmarks/loop-passes/iv_store.wasm", "memory-wasm" },
        .{ "tests/benchmarks/coremark/coremark_wasi.wasm", "coremark-wasm" },
        .{ "tests/benchmarks/coremark/coremark_wasi_nofp.wasm", "coremark-nofp-wasm" },
        .{ "tests/unikraft-jit/fixture.zig", "fixture-source" },
        .{ "build.zig", "fixture-build" },
    }) |entry| try tar.entry(entry[0], entry[1]);
    try tar.finish();
    const file = try temporary.dir.createFile(io, "source.tar", .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writePositionalAll(io, tar.bytes.items, 0);
    try file.setPermissions(io, .fromMode(0o600));
    return temporary.dir.realPathFileAlloc(io, "source.tar", allocator);
}

fn expectExit(term: std.process.Child.Term, expected: u8) !void {
    switch (term) {
        .exited => |code| try testing.expectEqual(expected, code),
        else => return error.UnexpectedTermination,
    }
}

const Tar = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8),

    fn init(a: std.mem.Allocator) Tar {
        return .{ .allocator = a, .bytes = .empty };
    }

    fn deinit(self: *Tar) void {
        self.bytes.deinit(self.allocator);
    }

    fn entry(self: *Tar, name: []const u8, contents: []const u8) !void {
        var header: [512]u8 = [_]u8{0} ** 512;
        if (name.len > 100) return error.FixturePathTooLong;
        @memcpy(header[0..name.len], name);
        putOctal(header[100..108], 0o644);
        putOctal(header[108..116], linux.geteuid());
        putOctal(header[116..124], linux.getegid());
        putOctal(header[124..136], contents.len);
        putOctal(header[136..148], 0);
        @memset(header[148..156], ' ');
        header[156] = '0';
        @memcpy(header[257..263], "ustar\x00");
        @memcpy(header[263..265], "00");
        var checksum: u64 = 0;
        for (header) |byte| checksum += byte;
        putChecksum(header[148..156], checksum);
        try self.bytes.appendSlice(self.allocator, &header);
        try self.bytes.appendSlice(self.allocator, contents);
        try self.bytes.appendNTimes(
            self.allocator,
            0,
            std.mem.alignForward(usize, contents.len, 512) - contents.len,
        );
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
