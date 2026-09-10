const std = @import("std");
const core = @import("hyperv");
const contracts = core.contracts;
const diagnostics = core.diagnostics;
const files = core.private_files;
const process = core.process;
const linux = std.os.linux;
const options = @import("test_options");
const testing = std.testing;
const allocator = testing.allocator;
const io = testing.io;

fn parse(source: []const u8) !contracts.Document {
    return contracts.Document.parse(allocator, source, .{});
}

test "strict JSON rejects duplicate decoded keys at every depth" {
    for ([_][]const u8{
        "{\"a\":1,\"a\":2}",
        "{\"a\":1,\"\\u0061\":2}",
        "{\"x\":[{\"a\":1,\"a\":2}]}",
    }) |source| try testing.expectError(error.DuplicateField, parse(source));
}

test "integer grammar does not silently accept floats exponents negative zero or constants" {
    for ([_][]const u8{ "1.0", "1e0", "-0", "1e9999" }) |source|
        try testing.expectError(error.ExpectedInteger, parse(source));
    for ([_][]const u8{ "NaN", "Infinity", "01", "+1", "null true", "\"\xff\"", "\"\\ud800\"", "\"\\udc00\"" }) |source| {
        const document = parse(source) catch continue;
        document.deinit();
        return error.InvalidJsonAccepted;
    }
    try testing.expectError(error.IntegerOverflow, parse("18446744073709551616"));
    try testing.expectError(error.IntegerOverflow, parse("-9223372036854775809"));
}

test "exact numeric types reject booleans strings signed mismatch and overflow" {
    for ([_][]const u8{ "true", "\"7\"", "null" }) |source| {
        const document = try parse(source);
        defer document.deinit();
        try testing.expectError(error.ExpectedInteger, contracts.integer(u64, document.value()));
    }
    const large = try parse("18446744073709551615");
    defer large.deinit();
    try testing.expectEqual(std.math.maxInt(u64), try contracts.integer(u64, large.value()));
    try testing.expectError(error.IntegerOverflow, contracts.integer(i64, large.value()));
    const negative = try parse("-9223372036854775808");
    defer negative.deinit();
    try testing.expectEqual(std.math.minInt(i64), try contracts.integer(i64, negative.value()));
    try testing.expectError(error.IntegerOverflow, contracts.integer(u64, negative.value()));
}

test "JSON bounds apply before arbitrary allocations and recursion" {
    try testing.expectError(error.InputTooLarge, contracts.Document.parse(allocator, "null", .{ .bytes = 3, .string_bytes = 3 }));
    try testing.expectError(error.TooDeep, contracts.Document.parse(allocator, "[[[]]]", .{ .depth = 2 }));
    try testing.expectError(error.ValueTooLong, contracts.Document.parse(allocator, "\"abcd\"", .{ .string_bytes = 3 }));
    try testing.expectError(error.TooManyItems, contracts.Document.parse(allocator, "[0,1,2]", .{ .items = 2 }));
    try testing.expectError(error.TooManyItems, contracts.Document.parse(allocator, "{\"a\":0,\"b\":1}", .{ .items = 1 }));
    try testing.expectError(error.TooManyTokens, contracts.Document.parse(allocator, "[0,1,2]", .{ .tokens = 3 }));
    try testing.expectError(error.InvalidLimits, contracts.Document.parse(allocator, "null", .{ .depth = 33 }));
}

test "canonical JSON sorts all keys and has exactly one newline" {
    const document = try parse(" { \"z\":[ { \"b\":2, \"a\":\"\\u0061\" } ], \"a\":18446744073709551615 } ");
    defer document.deinit();
    const canonical = try document.canonicalAlloc(allocator);
    defer allocator.free(canonical);
    try testing.expectEqualStrings("{\"a\":18446744073709551615,\"z\":[{\"a\":\"a\",\"b\":2}]}\n", canonical);
    try document.requireCanonical(allocator, canonical);
    try testing.expectError(error.NonCanonical, document.requireCanonical(allocator, canonical[0 .. canonical.len - 1]));
}

const binding =
    "{\"byte_length\":4096,\"contract\":\"uk.hyperv.input-binding\"," ++
    "\"run_id\":\"12345678-1234-4234-8234-123456789abc\",\"schema_version\":1," ++
    "\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}\n";

test "input binding exact fields schema UUID SHA and integer shape" {
    const document = try parse(binding);
    defer document.deinit();
    try document.requireCanonical(allocator, binding);
    const value = try contracts.InputBinding.parse(document.value());
    try testing.expectEqual(@as(u64, 4096), value.byte_length);
    try testing.expectError(error.UnexpectedFields, contracts.exactFields(document.value(), &.{"byte_length"}));
    for ([_][]const u8{
        "{}",
        "{\"byte_length\":true,\"contract\":\"uk.hyperv.input-binding\",\"run_id\":\"12345678-1234-4234-8234-123456789abc\",\"schema_version\":1,\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
        "{\"byte_length\":1,\"contract\":\"uk.hyperv.input-binding\",\"run_id\":\"12345678-1234-4234-8234-123456789abc\",\"schema_version\":2,\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}",
    }) |source| {
        const bad = try parse(source);
        defer bad.deinit();
        _ = contracts.InputBinding.parse(bad.value()) catch continue;
        return error.BadBindingAccepted;
    }
}

test "UUID and SHA are strict lowercase fixed width and geometry cannot overflow" {
    _ = try contracts.parseUuid("12345678-1234-4234-8234-123456789abc");
    for ([_][]const u8{
        "12345678-1234-4234-8234-123456789ABC",
        "12345678123442348234123456789abc",
        "{12345678-1234-4234-8234-123456789abc}",
        "12345678_1234-4234-8234-123456789abc",
    }) |source| try testing.expectError(error.InvalidUuid, contracts.parseUuid(source));
    try testing.expectError(error.InvalidSha256, contracts.parseSha256("abc"));
    try testing.expectError(error.InvalidSha256, contracts.parseSha256("ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"));
    try testing.expectEqual(@as(u64, 4294967296), try (contracts.Geometry{ .sectors = 8388608, .sector_size = 512 }).byteSize());
    try testing.expectError(error.InvalidGeometry, (contracts.Geometry{ .sectors = 8388608, .sector_size = 4096 }).byteSize());
    try testing.expectError(error.InvalidGeometry, (contracts.Geometry{ .sectors = 0, .sector_size = 512 }).byteSize());
    try testing.expectError(error.IntegerOverflow, (contracts.Geometry{ .sectors = std.math.maxInt(u64), .sector_size = 512 }).byteSize());
}

test "diagnostics have explicit missing unknown malformed and conflicting service semantics" {
    try testing.expectEqual(.unavailable, diagnostics.classifyServiceCode(null));
    try testing.expectEqual(.unknown, diagnostics.classifyServiceCode("NewServiceCode"));
    try testing.expectEqual(.unknown, diagnostics.classifyServiceCode("unavailable"));
    try testing.expectEqual(.malformed, diagnostics.classifyServiceCode("synthetic?sig=secret"));
    try testing.expectEqual(.AuthorizationFailure, diagnostics.classifyServiceCode("AuthorizationFailure"));
    try testing.expectEqual(.conflicting, diagnostics.reconcileServiceCodes("BlobNotFound", "AuthorizationFailure"));
    try testing.expectEqual(.BlobNotFound, diagnostics.reconcileServiceCodes(null, "BlobNotFound"));
    try testing.expectEqual(.BlobNotFound, diagnostics.reconcileServiceCodes("BlobNotFound", "BlobNotFound"));
    try testing.expectError(error.InvalidHttpStatus, (diagnostics.Diagnostic{ .stage = .arm, .category = .service, .http_status = 99 }).validate());
    try testing.expectError(error.UnobservedServiceCode, (diagnostics.Diagnostic{ .stage = .arm, .category = .service, .service_code = .unknown }).validate());
}

test "diagnostic parser rejects unknown fields unknown enums wrong numeric shapes and secret payloads" {
    for ([_][]const u8{
        "{\"stage\":\"arm\",\"category\":\"service\",\"http_status\":403,\"service_code\":\"AuthorizationFailure\",\"message\":\"secret\"}",
        "{\"stage\":\"/private/path\",\"category\":\"service\",\"http_status\":403,\"service_code\":\"AuthorizationFailure\"}",
        "{\"stage\":\"arm\",\"category\":\"service\",\"http_status\":true,\"service_code\":\"AuthorizationFailure\"}",
        "{\"stage\":\"arm\",\"category\":\"service\",\"http_status\":600,\"service_code\":\"unknown\"}",
        "{\"stage\":\"arm\",\"category\":\"service\",\"http_status\":null,\"service_code\":\"unknown\"}",
        "{\"stage\":\"arm\",\"category\":\"service\",\"http_status\":403,\"service_code\":\"UnknownProviderCode\"}",
    }) |source| {
        const document = try parse(source);
        defer document.deinit();
        _ = diagnostics.Diagnostic.parse(document.value()) catch continue;
        return error.UnsafeDiagnosticAccepted;
    }
}

test "primary cleanup and recording retain independent first errors without raw values" {
    var failures: diagnostics.Failures = .{};
    try failures.record(.primary, .{ .stage = .blob_upload, .category = .authorization, .http_status = 403, .service_code = .AuthorizationFailure });
    try failures.record(.primary, .{ .stage = .cleanup, .category = .timeout });
    try failures.record(.cleanup, .{ .stage = .cleanup, .category = .timeout });
    try failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
    try testing.expectEqual(.authorization, failures.primary.?.category);
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try failures.write(&writer.writer);
    const document = try parse(writer.written());
    defer document.deinit();
    try document.requireCanonical(allocator, writer.written());
    try testing.expectEqual(@as(?u16, 403), failures.primary.?.http_status);
    try testing.expectEqual(.timeout, failures.cleanup.?.category);
    try testing.expectEqual(.local_io, failures.recording.?.category);
    const decoded = try diagnostics.Failures.parse(document.value());
    try testing.expectEqualDeep(failures, decoded);
}

const Fixture = struct {
    root: files.Directory,
    directory: files.Directory,
    name: [32]u8,

    fn init() !Fixture {
        const path = options.test_root orelse return error.MissingExplicitTestRoot;
        var root = try files.Directory.open(io, path);
        errdefer root.close(io);
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try root.dir.createDir(io, &name, .fromMode(0o700));
        errdefer root.dir.deleteDir(io, &name) catch {};
        const directory = try root.dir.openDir(io, &name, .{ .follow_symlinks = false, .iterate = true });
        return .{ .root = root, .directory = .{ .dir = directory }, .name = name };
    }

    fn deinit(self: *Fixture) void {
        self.directory.close(io);
        self.root.dir.deleteTree(io, &self.name) catch @panic("native fixture cleanup failed");
        self.root.close(io);
    }
};

test "private atomic state is durable owner-only bounded and hash-bound" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const result = try lock.commit(io, "state.json", binding);
    try testing.expectEqual(.durable, result.status);
    try testing.expect(result.failures.recording == null);
    var digest: contracts.Sha256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(binding, &digest, .{});
    const bytes = try fixture.directory.read(io, allocator, "state.json", 4096, digest);
    defer allocator.free(bytes);
    try testing.expectEqualStrings(binding, bytes);
    try testing.expectError(error.HashMismatch, fixture.directory.read(io, allocator, "state.json", 4096, [_]u8{0} ** 32));
    try testing.expectError(error.FileTooLarge, fixture.directory.read(io, allocator, "state.json", 1, null));
    try testing.expectError(error.UnsafePath, fixture.directory.openFile(io, "../state.json"));
    try testing.expectError(error.InvalidState, lock.commit(io, ".writer.lock", "bad"));
}

test "exclusive lock survives writes and release retains its stable inode" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    const inode = (try lock.file.?.stat(io)).inode;
    try testing.expectError(error.WouldBlock, fixture.directory.lock(io));
    _ = try lock.commit(io, "state.json", "{}\n");
    try testing.expectError(error.WouldBlock, fixture.directory.lock(io));
    lock.close(io);
    try testing.expectError(error.LockNotHeld, lock.commit(io, "state.json", "{}\n"));
    var next = try fixture.directory.lock(io);
    defer next.close(io);
    try testing.expectEqual(inode, (try next.file.?.stat(io)).inode);
}

test "immutable input creation is exclusive and never overwrites earlier content" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const created = try lock.createImmutable(io, "input.json", binding);
    try testing.expectEqual(.durable, created.status);
    try testing.expectError(error.PathAlreadyExists, lock.createImmutable(io, "input.json", "new\n"));
    const bytes = try fixture.directory.read(io, allocator, "input.json", 4096, null);
    defer allocator.free(bytes);
    try testing.expectEqualStrings(binding, bytes);
}

test "private directory traversal rejects symlink components noncanonical paths and unsafe modes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ options.test_root.?, fixture.name });
    defer allocator.free(path);
    const alias = try std.fmt.allocPrint(allocator, "{s}/alias", .{path});
    defer allocator.free(alias);
    try testing.expectEqual(.SUCCESS, linux.errno(linux.symlinkat(".", fixture.directory.dir.handle, "alias")));
    if (files.Directory.open(io, alias)) |directory| {
        directory.close(io);
        return error.SymlinkAccepted;
    } else |_| {}
    const traversal = try std.fmt.allocPrint(allocator, "{s}/../{s}", .{ path, fixture.name });
    defer allocator.free(traversal);
    try testing.expectError(error.UnsafePath, files.Directory.open(io, traversal));
    try fixture.directory.dir.setPermissions(io, .fromMode(0o750));
    try testing.expectError(error.UnsafeFile, files.Directory.open(io, path));
    try fixture.directory.dir.setPermissions(io, .fromMode(0o700));
}

test "private file checks refuse symlinks hard links FIFO directories and broad permissions" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    _ = try lock.commit(io, "state.json", "{}\n");
    const fd = fixture.directory.dir.handle;
    try testing.expectEqual(.SUCCESS, linux.errno(linux.symlinkat("state.json", fd, "alias")));
    try testing.expectError(error.UnsafeFile, fixture.directory.openFile(io, "alias"));
    try testing.expectError(error.UnsafeFile, lock.commit(io, "alias", "bad"));
    try testing.expectEqual(.SUCCESS, linux.errno(linux.linkat(fd, "state.json", fd, "hard", 0)));
    try testing.expectError(error.UnsafeFile, fixture.directory.openFile(io, "state.json"));
    try fixture.directory.dir.deleteFile(io, "hard");
    try testing.expectEqual(.SUCCESS, linux.errno(linux.mknodat(fd, "fifo", linux.S.IFIFO | 0o600, 0)));
    try testing.expectError(error.UnsafeFile, fixture.directory.openFile(io, "fifo"));
    try fixture.directory.dir.createDir(io, "directory", .fromMode(0o700));
    try testing.expectError(error.UnsafeFile, fixture.directory.openFile(io, "directory"));
    const file = try fixture.directory.openFile(io, "state.json");
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    try testing.expectError(error.UnsafeFile, fixture.directory.openFile(io, "state.json"));
}

test "failed atomic writes retain old state and distinguish visible nondurable updates" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    _ = try lock.commit(io, "state.json", "old\n");
    for ([_]files.TestFault{ .before_file_sync, .before_rename, .cleanup }) |fault| {
        const failed = try lock.commitFault(io, "state.json", "new\n", fault);
        try testing.expectEqual(.not_committed, failed.status);
        try testing.expect(failed.failures.recording != null);
        try testing.expectEqual(fault == .cleanup, failed.failures.cleanup != null);
        const old = try fixture.directory.read(io, allocator, "state.json", 16, null);
        defer allocator.free(old);
        try testing.expectEqualStrings("old\n", old);
    }
    const publication = try lock.commitFault(io, "state.json", "new\n", .publication);
    try testing.expectEqual(.publication_unknown, publication.status);
    try testing.expect(publication.failures.recording != null);
    const uncertain = try lock.commitFault(io, "state.json", "new\n", .after_rename);
    try testing.expectEqual(.visible_not_durable, uncertain.status);
    try testing.expect(uncertain.failures.recording != null);
    const new = try fixture.directory.read(io, allocator, "state.json", 16, null);
    defer allocator.free(new);
    try testing.expectEqualStrings("new\n", new);
    var iterator = fixture.directory.dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |_| count += 1;
    try testing.expectEqual(@as(usize, 2), count);
}

fn child(mode: []const u8, milliseconds: u64, output_limit: usize) !process.Result {
    try process.initialize();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.process_fixture, allocator);
    defer allocator.free(executable);
    return process.run(allocator, io, .{
        .argv = &.{ executable, mode },
        .environment = &environment,
        .cwd = .cwd(),
        .deadline = try process.Deadline.afterMilliseconds(milliseconds),
        .stdout_limit = output_limit,
        .stderr_limit = output_limit,
    });
}

fn noChildren() !void {
    var status: u32 = 0;
    try testing.expectEqual(.CHILD, linux.errno(linux.waitpid(-1, &status, linux.W.NOHANG)));
}

test "native process captures bounded stdout and redacts failed stderr" {
    var success = try child("success", 2000, 15);
    defer success.deinit(allocator);
    try testing.expectEqualStrings("native-fixture\n", success.stdout);
    try testing.expect(success.failures.primary == null);
    try testing.expect(success.cleanup_complete);
    var failed = try child("failure", 2000, 1024);
    defer failed.deinit(allocator);
    try testing.expectEqual(.child_failed, failed.failures.primary.?.category);
    try testing.expectEqual(@as(u8, 7), failed.termination.?.exited);
    try testing.expectEqual(@as(usize, 0), failed.stdout.len);
    try testing.expect(std.mem.allEqual(u8, failed.storage, 0));
    try noChildren();
}

test "both streams have independent hard caps with no failed output exposure" {
    for ([_][]const u8{ "success", "stdout-flood", "stderr-flood" }) |mode| {
        var result = try child(mode, 2000, 13);
        defer result.deinit(allocator);
        try testing.expectEqual(.output_limit, result.failures.primary.?.category);
        try testing.expect(result.cleanup_complete);
        try testing.expect(result.failures.cleanup == null);
        try testing.expectEqual(@as(usize, 0), result.stdout.len);
    }
    try noChildren();
}

test "timeout has separate cleanup budget and reaps process trees" {
    for ([_][]const u8{ "sleep", "tree", "ignore-term" }) |mode| {
        var result = try child(mode, 150, 1024);
        defer result.deinit(allocator);
        try testing.expectEqual(.timeout, result.failures.primary.?.category);
        try testing.expect(result.failures.cleanup == null);
        try testing.expect(result.cleanup_complete);
        if (std.mem.eql(u8, mode, "ignore-term")) try testing.expectEqual(.KILL, result.termination.?.signal);
        try noChildren();
    }
}

test "private locks do not leak through exec and environment inheritance is absent" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const fd = try std.fmt.allocPrint(allocator, "{d}", .{lock.file.?.handle});
    defer allocator.free(fd);
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.process_fixture, allocator);
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try process.initialize();
    var result = try process.run(allocator, io, .{
        .argv = &.{ executable, "fd-closed", fd },
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(2000),
    });
    defer result.deinit(allocator);
    try testing.expect(result.failures.primary == null);
    try testing.expectEqualStrings("closed\n", result.stdout);
    try testing.expectError(error.WouldBlock, fixture.directory.lock(io));
    var empty = try child("empty-environment", 2000, 1024);
    defer empty.deinit(allocator);
    try testing.expect(empty.failures.primary == null);
    try noChildren();
}

test "running child cancellation still terminates and reaps under the cleanup budget" {
    var flag = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, struct {
        fn cancel(cancel_flag: *std.atomic.Value(bool)) void {
            const duration: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = linux.nanosleep(&duration, null);
            cancel_flag.store(true, .release);
        }
    }.cancel, .{&flag});
    defer thread.join();
    try process.initialize();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.process_fixture, allocator);
    defer allocator.free(executable);
    var result = try process.run(allocator, io, .{
        .argv = &.{ executable, "tree" },
        .environment = &environment,
        .cwd = .cwd(),
        .deadline = try process.Deadline.afterMilliseconds(2000),
        .cancel = &flag,
    });
    defer result.deinit(allocator);
    try testing.expectEqual(.cancelled, result.failures.primary.?.category);
    try testing.expect(result.cleanup_complete);
    try testing.expect(result.failures.cleanup == null);
    try noChildren();
}

test "successful parent exit cannot strand a grandchild holding output pipes" {
    var result = try child("orphan", 2000, 1024);
    defer result.deinit(allocator);
    try testing.expect(result.failures.primary == null);
    try testing.expect(result.cleanup_complete);
    const pid = try std.fmt.parseInt(linux.pid_t, std.mem.trim(u8, result.stdout, "\n"), 10);
    try testing.expectEqual(.SRCH, linux.errno(linux.kill(pid, @enumFromInt(0))));
    try noChildren();
}

test "expired cancelled and missing executables never report success" {
    try process.initialize();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var cancel = std.atomic.Value(bool).init(true);
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.process_fixture, allocator);
    defer allocator.free(executable);
    var expired = try process.run(allocator, io, .{
        .argv = &.{ executable, "success" },
        .environment = &environment,
        .cwd = .cwd(),
        .deadline = .{ .expires_ns = 0 },
    });
    defer expired.deinit(allocator);
    try testing.expectEqual(.timeout, expired.failures.primary.?.category);
    try testing.expect(std.mem.allEqual(u8, expired.storage, 0));
    var cancelled = try process.run(allocator, io, .{
        .argv = &.{ executable, "success" },
        .environment = &environment,
        .cwd = .cwd(),
        .deadline = try process.Deadline.afterMilliseconds(2000),
        .cancel = &cancel,
    });
    defer cancelled.deinit(allocator);
    try testing.expectEqual(.cancelled, cancelled.failures.primary.?.category);
    try testing.expect(std.mem.allEqual(u8, cancelled.storage, 0));
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const missing = try std.fmt.allocPrint(allocator, "{s}/nonexistent-native-fixture", .{options.test_root.?});
    defer allocator.free(missing);
    var absent = try process.run(allocator, io, .{
        .argv = &.{missing},
        .environment = &environment,
        .cwd = fixture.directory.dir,
        .deadline = try process.Deadline.afterMilliseconds(2000),
    });
    defer absent.deinit(allocator);
    try testing.expectEqual(.spawn_failed, absent.failures.primary.?.category);
    try testing.expect(absent.cleanup_complete);
    try testing.expect(std.mem.allEqual(u8, absent.storage, 0));
    try noChildren();
}

test "exec permission and format failures are bounded reaped and have no shell fallback" {
    try process.initialize();
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    _ = try lock.commit(io, "not-executable", "synthetic-nonnative-content\n");
    const executable = try std.fmt.allocPrint(allocator, "{s}/{s}/not-executable", .{ options.test_root.?, fixture.name });
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const file = try fixture.directory.openFile(io, "not-executable");
    defer file.close(io);
    for ([_]u32{ 0o600, 0o700 }) |mode| {
        try file.setPermissions(io, .fromMode(mode));
        var result = try process.run(allocator, io, .{
            .argv = &.{executable},
            .environment = &environment,
            .cwd = fixture.directory.dir,
            .deadline = try process.Deadline.afterMilliseconds(2000),
        });
        defer result.deinit(allocator);
        try testing.expectEqual(.spawn_failed, result.failures.primary.?.category);
        try testing.expect(result.cleanup_complete);
        try testing.expectEqual(@as(usize, 0), result.stdout.len);
        try noChildren();
    }
}

const WipeObserver = struct {
    allocated: usize = 0,
    freed: usize = 0,
    dirty_frees: usize = 0,
    remaining: ?usize = null,

    fn asAllocator(self: *WipeObserver) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocate,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = release,
        } };
    }
    fn allocate(context: *anyopaque, length: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *WipeObserver = @ptrCast(@alignCast(context));
        if (self.remaining) |remaining| {
            if (remaining == 0) return null;
            self.remaining = remaining - 1;
        }
        const memory = allocator.rawAlloc(length, alignment, address) orelse return null;
        self.allocated += 1;
        @memset(memory[0..length], 0xa5);
        return memory;
    }
    fn release(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *WipeObserver = @ptrCast(@alignCast(context));
        self.freed += 1;
        if (!std.mem.allEqual(u8, memory, 0)) self.dirty_frees += 1;
        allocator.rawFree(memory, alignment, address);
    }
    fn verify(self: WipeObserver) !void {
        try testing.expectEqual(self.allocated, self.freed);
        try testing.expectEqual(@as(usize, 0), self.dirty_frees);
    }
};

test "sensitive reader wipes successful and hash-rejected buffers before release" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    _ = try lock.commit(io, "sas", "sig=SYNTHETIC_SECRET");
    var observer: WipeObserver = .{};
    var secret = try fixture.directory.readSensitive(io, observer.asAllocator(), "sas", 64, null);
    try testing.expectEqualStrings("sig=SYNTHETIC_SECRET", secret.bytes());
    secret.deinit();
    try testing.expectError(error.HashMismatch, fixture.directory.readSensitive(io, observer.asAllocator(), "sas", 64, [_]u8{0} ** 32));
    try observer.verify();
}

test "sensitive JSON clears scanner decoded strings arenas canonical copies and partial parses" {
    for ([_][]const u8{
        " {\"token\":\"SYNTHETIC_SECRET\",\"nested\":[\"\\u0053ECRET\"]} ",
        "{\"token\":\"SYNTHETIC_SECRET\",\"token\":\"different\"}",
        "{\"token\":\"SYNTHETIC_SECRET\",\"broken\":[}",
    }) |source| {
        var observer: WipeObserver = .{};
        if (contracts.SensitiveDocument.parse(observer.asAllocator(), source, .{})) |document| {
            defer document.deinit();
            try testing.expectError(error.NonCanonical, document.requireCanonical(source));
        } else |_| {}
        try observer.verify();
    }
    var baseline: WipeObserver = .{};
    try sensitiveCanonicalLifecycle(baseline.asAllocator());
    try baseline.verify();
    for (0..baseline.allocated + 1) |limit| {
        var observer: WipeObserver = .{ .remaining = limit };
        sensitiveCanonicalLifecycle(observer.asAllocator()) catch |err|
            try testing.expect(err == error.OutOfMemory or err == error.WriteFailed);
        try observer.verify();
    }
}

fn sensitiveCanonicalLifecycle(backing: std.mem.Allocator) !void {
    const source = "{\"token\":\"SYNTHETIC_SECRET\"}\n";
    const document = try contracts.SensitiveDocument.parse(backing, source, .{});
    defer document.deinit();
    try document.requireCanonical(source);
}

test "sensitive allocator never relocates secret storage without a wiping free" {
    var observer: WipeObserver = .{};
    var wiping: core.sensitive.Allocator = .{ .backing = observer.asAllocator() };
    const secure = wiping.allocator();
    var bytes = try secure.dupe(u8, "SYNTHETIC_SECRET");
    bytes = try secure.realloc(bytes, 4096);
    bytes = try secure.realloc(bytes, 3);
    secure.free(bytes);
    try observer.verify();
}

test "shared service allowlist uses documented storage codes and rejects the old lease alias" {
    inline for (.{
        diagnostics.ServiceCode.LeaseIdMismatchWithBlobOperation,
        diagnostics.ServiceCode.AuthorizationServiceMismatch,
        diagnostics.ServiceCode.KeyBasedAuthenticationNotPermitted,
        diagnostics.ServiceCode.InvalidBlobType,
        diagnostics.ServiceCode.PendingCopyOperation,
    }) |code| try testing.expectEqual(code, diagnostics.classifyServiceCode(@tagName(code)));
    try testing.expectEqual(.unknown, diagnostics.classifyServiceCode("LeaseIdMismatchWithBlob"));
    try testing.expectEqual(.unknown, diagnostics.classifyServiceCode("New_Service_Code"));
}
