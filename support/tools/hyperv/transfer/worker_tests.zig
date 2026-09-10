const std = @import("std");
const core = @import("hyperv");
const worker = core.transfer.worker;
const protocol = worker.protocol;
const options = @import("test_options");
const testing = std.testing;
const allocator = testing.allocator;
const io = testing.io;
const linux = std.os.linux;

const Fixture = struct {
    root: core.private_files.Directory,
    directory: core.private_files.Directory,
    name: [32]u8,
    path: []u8,

    fn init(mode: []const u8, kind: core.transfer.job.Kind, size: usize, download: bool, timeout_ms: u32) !Fixture {
        const root_path = options.test_root orelse return error.MissingTestRoot;
        const root = try core.private_files.Directory.open(io, root_path);
        errdefer root.close(io);
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try root.dir.createDir(io, &name, .fromMode(0o700));
        errdefer root.dir.deleteTree(io, &name) catch {};
        const dir = try root.dir.openDir(io, &name, .{ .follow_symlinks = false, .iterate = true });
        errdefer dir.close(io);
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root_path, name });
        errdefer allocator.free(path);
        const fixture: Fixture = .{ .root = root, .directory = .{ .dir = dir }, .name = name, .path = path };
        try fixture.put("fixture-mode", mode);
        try fixture.put("sas", "sv=2024-11-04&sp=rcw&sig=SYNTHETIC%2BONLY%3D");
        const bytes = try allocator.alloc(u8, size);
        defer allocator.free(bytes);
        @memset(bytes, 0x5a);
        try fixture.put("source", bytes);
        const digest = std.fmt.bytesToHex(core.transfer.job.hash(bytes), .lower);
        const request = if (kind == .pages)
            try std.fmt.allocPrint(allocator, "{{\"schema\":\"unikraft.hyperv.managed-disk-page-worker\",\"schema_version\":1,\"endpoint\":\"https://fixture.blob.storage.azure.net/upload/vhd\",\"path\":\"{s}/source\",\"size\":{d},\"sha256\":\"{s}\"}}", .{ path, size, digest })
        else if (download)
            try std.fmt.allocPrint(allocator, "{{\"schema\":\"unikraft.hyperv.private-preflight-blob-worker\",\"schema_version\":1,\"action\":\"download\",\"account_url\":\"https://fixture.blob.core.windows.net\",\"container\":\"fixture\",\"files\":[{{\"blob\":\"input\",\"path\":\"{s}/download\",\"maximum\":128}}],\"create_container\":false}}", .{path})
        else
            try std.fmt.allocPrint(allocator, "{{\"schema\":\"unikraft.hyperv.private-preflight-blob-worker\",\"schema_version\":1,\"action\":\"upload\",\"account_url\":\"https://fixture.blob.core.windows.net\",\"container\":\"fixture\",\"files\":[{{\"blob\":\"input\",\"path\":\"{s}/source\",\"size\":{d},\"sha256\":\"{s}\"}}],\"create_container\":false}}", .{ path, size, digest });
        defer allocator.free(request);
        try fixture.put("request.json", request);
        const job = try std.fmt.allocPrint(allocator, "{{\"contract\":\"uk.hyperv.transfer-job\",\"schema_version\":1,\"kind\":\"{s}\",\"request\":\"request.json\",\"sas\":\"sas\",\"timeout_ms\":{d},\"cleanup_ms\":1000}}", .{ @tagName(kind), timeout_ms });
        defer allocator.free(job);
        try fixture.put("job.json", job);
        return fixture;
    }

    fn put(self: Fixture, name: []const u8, bytes: []const u8) !void {
        const file = try self.directory.dir.createFile(io, name, .{ .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.setPermissions(io, .fromMode(0o600));
        try file.writeStreamingAll(io, bytes);
    }

    fn run(self: Fixture, cancel: ?*const std.atomic.Value(bool)) worker.Report {
        const executable = std.Io.Dir.cwd().realPathFileAlloc(io, options.worker_fixture, allocator) catch
            @panic("native worker fixture executable is unavailable");
        defer allocator.free(executable);
        return worker.supervise(allocator, io, self.path, "job.json", .{
            .executable = executable,
            .cancel = cancel,
        });
    }

    fn createContainer(self: Fixture) !void {
        var original = try self.directory.readSensitive(io, allocator, "request.json", 8192, null);
        defer original.deinit();
        const changed = try mutateOne(original.bytes(), "\"create_container\":false", "\"create_container\":true");
        defer allocator.free(changed);
        try self.put("request.json", changed);
    }

    fn useDownload(self: Fixture) !void {
        const request = try std.fmt.allocPrint(allocator, "{{\"schema\":\"unikraft.hyperv.private-preflight-blob-worker\",\"schema_version\":1,\"action\":\"download\",\"account_url\":\"https://fixture.blob.core.windows.net\",\"container\":\"fixture\",\"files\":[{{\"blob\":\"input\",\"path\":\"{s}/download\",\"maximum\":128}}],\"create_container\":false}}", .{self.path});
        defer allocator.free(request);
        try self.put("request.json", request);
    }

    fn deinit(self: Fixture) void {
        self.directory.close(io);
        self.root.dir.deleteTree(io, &self.name) catch @panic("worker fixture cleanup failed");
        self.root.close(io);
        allocator.free(self.path);
    }
};

fn mutateOne(raw: []const u8, before: []const u8, after: []const u8) ![]u8 {
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, raw, before));
    return std.mem.replaceOwned(u8, allocator, raw, before, after);
}

fn noChildren() !void {
    var status: u32 = 0;
    try testing.expectEqual(linux.E.CHILD, linux.errno(linux.waitpid(-1, &status, linux.W.NOHANG)));
}

fn safeReport(report: worker.Report) !void {
    var bytes: [protocol.maximum_result]u8 = undefined;
    var writer = std.Io.Writer.fixed(&bytes);
    try report.write(&writer);
    for ([_][]const u8{ "SYNTHETIC", "sig=", "https://", ".blob.", "source", "request.json" }) |secret|
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), secret) == null);
    const document = try core.contracts.SensitiveDocument.parse(allocator, writer.buffered(), .{ .bytes = protocol.maximum_result });
    defer document.deinit();
    try document.requireCanonical(writer.buffered());
}

fn reportContext(report: protocol.Report) protocol.Intent {
    return .{
        .attempt_id = report.attempt_id.?,
        .job_sha256 = report.job_sha256.?,
        .kind = report.kind.?,
        .plan = report.admitted_plan.?,
        .request_sha256 = [_]u8{0} ** 32,
        .sas_sha256 = [_]u8{0} ** 32,
        .parent_pid = 1,
        .deadline_ns = 0,
    };
}

fn unavailableReport(report: protocol.Report, category: core.diagnostics.Category) !void {
    try testing.expect(!report.succeeded());
    try testing.expectEqual(category, report.failures.primary.?.category);
    try testing.expectEqual(.unknown, report.side_effect);
    try testing.expect(report.progress == null);
    try testing.expect(report.failures.cleanup == null and report.failures.recording == null);
    try safeReport(report);
    if (report.admitted_plan != null) try roundtrip(report, reportContext(report));
}

fn captureCli(fixture: Fixture, internal: bool) !core.sensitive.Buffer {
    const wrapper = try std.Io.Dir.cwd().realPathFileAlloc(io, options.worker_fixture, allocator);
    defer allocator.free(wrapper);
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try core.process.initialize();
    var child = try core.process.run(allocator, io, .{
        .argv = &.{ wrapper, "__capture-cli", executable, if (internal) "__transfer-worker" else "transfer", fixture.path, "job.json" },
        .cwd = fixture.directory.dir,
        .environment = &environment,
        .deadline = try core.process.Deadline.afterMilliseconds(5000),
    });
    defer child.deinit(allocator);
    try testing.expect(child.cleanup_complete);
    try testing.expectEqual(@as(u8, if (internal) 0 else 1), child.termination.?.exited);
    try testing.expectEqual(@as(usize, 0), child.stdout.len);
    return fixture.directory.readSensitive(io, allocator, "cli-output.json", protocol.maximum_result, null);
}

fn capturedContext(value: std.json.Value, plan: core.transfer.job.Plan) !protocol.Intent {
    const fields = value.object;
    return .{
        .attempt_id = try core.contracts.parseSha256(try core.contracts.string(fields.get("attempt_id").?)),
        .job_sha256 = try core.contracts.parseSha256(try core.contracts.string(fields.get("job_sha256").?)),
        .kind = try core.contracts.enumeration(core.transfer.job.Kind, fields.get("kind").?),
        .plan = plan,
        .request_sha256 = [_]u8{0} ** 32,
        .sas_sha256 = [_]u8{0} ** 32,
        .parent_pid = 1,
        .deadline_ns = 0,
    };
}

test "repeated downloads and new read-only plans retain uncertainty about consumed attempts" {
    for ([_]struct { download: bool, size: usize }{
        .{ .download = true, .size = 0 },
        .{ .download = false, .size = 0 },
        .{ .download = false, .size = 17 },
    }) |case| {
        const fixture = try Fixture.init("pass", .blob, case.size, case.download, 5000);
        defer fixture.deinit();
        const first = fixture.run(null);
        try testing.expect(first.succeeded());
        var original = try fixture.directory.readSensitive(io, allocator, core.transfer.job.supervised_name, protocol.maximum_result, null);
        defer original.deinit();
        const intent = try protocol.Intent.load(allocator, io, fixture.directory);
        if (!case.download) {
            try fixture.useDownload();
            var held = try fixture.directory.lock(io);
            defer held.close(io);
            const contended = fixture.run(null);
            try testing.expectEqual(@as(u64, 0), contended.admitted_plan.?.mutations);
            try unavailableReport(contended, .contention);
        }
        const repeated = fixture.run(null);
        try testing.expectEqual(@as(u64, 0), repeated.admitted_plan.?.mutations);
        try testing.expect(repeated.attempt_id != null and repeated.job_sha256 != null);
        try unavailableReport(repeated, .conflict);
        try testing.expectEqualDeep(intent, try protocol.Intent.load(allocator, io, fixture.directory));
        var retained = try fixture.directory.readSensitive(io, allocator, core.transfer.job.supervised_name, protocol.maximum_result, null);
        defer retained.deinit();
        try testing.expectEqualSlices(u8, original.bytes(), retained.bytes());
        var invocations = try fixture.directory.readSensitive(io, allocator, "invocations", 32, null);
        defer invocations.deinit();
        try testing.expectEqualStrings("1", invocations.bytes());
        try noChildren();
    }
}

test "read-only supervisor lock contention produces a serializable admission failure" {
    const fixture = try Fixture.init("pass", .blob, 0, true, 5000);
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const result = fixture.run(null);
    try testing.expectEqual(@as(u64, 0), result.admitted_plan.?.mutations);
    try unavailableReport(result, .contention);
    try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, "invocations", .{}));
    try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, core.transfer.job.intent_name, .{}));
    try noChildren();
}

test "public CLI emits conflict and contention reports instead of generic invalid input" {
    for ([_]enum { repeated_download, changed_plan, contention }{ .repeated_download, .changed_plan, .contention }) |case| {
        const fixture = try Fixture.init("pass", .blob, if (case == .changed_plan) 17 else 0, case != .changed_plan, 5000);
        defer fixture.deinit();
        if (case != .contention) try testing.expect(fixture.run(null).succeeded());
        if (case == .changed_plan) {
            try fixture.useDownload();
            try fixture.put("download", "synthetic no-network guard");
        }
        var lock: ?core.private_files.Locked = if (case == .contention) try fixture.directory.lock(io) else null;
        defer if (lock) |*held| held.close(io);
        var raw = try captureCli(fixture, false);
        defer raw.deinit();
        const document = try core.contracts.SensitiveDocument.parse(allocator, raw.bytes(), .{});
        defer document.deinit();
        const intent = try capturedContext(document.value(), .{ .bytes = 0, .download_bytes = 128, .mutations = 0, .requests = 1 });
        const report = try protocol.Report.parse(allocator, raw.bytes(), intent);
        try unavailableReport(report, if (case == .contention) .contention else .conflict);
        var definition = try fixture.directory.readSensitive(io, allocator, "job.json", 8192, null);
        defer definition.deinit();
        try testing.expectEqualDeep(core.transfer.job.hash(definition.bytes()), report.job_sha256.?);
        if (case != .contention) {
            const retained = try protocol.Intent.load(allocator, io, fixture.directory);
            try testing.expectEqual(@as(u64, if (case == .changed_plan) 1 else 0), retained.plan.mutations);
        }
        try noChildren();
    }
}

test "native child consumed and contended paths serialize original failure categories" {
    for ([_]bool{ false, true }) |contended| {
        const fixture = try Fixture.init("pass", .blob, 0, true, 5000);
        defer fixture.deinit();
        if (!contended) try testing.expect(fixture.run(null).succeeded());
        var lock: ?core.private_files.Locked = if (contended) try fixture.directory.lock(io) else null;
        defer if (lock) |*held| held.close(io);
        var raw = try captureCli(fixture, true);
        defer raw.deinit();
        const document = try core.contracts.SensitiveDocument.parse(allocator, raw.bytes(), .{});
        defer document.deinit();
        try document.requireCanonical(raw.bytes());
        const fields = document.value().object;
        const failures = try core.diagnostics.Failures.parse(fields.get("failures").?);
        try testing.expectEqual(if (contended) core.diagnostics.Category.contention else .conflict, failures.primary.?.category);
        const outcome = try core.transfer.Outcome.parse(fields.get("outcome").?);
        try testing.expectEqual(.unknown, outcome.side_effect);
        try testing.expectEqual(.failed, outcome.completion);
        try testing.expect(fields.get("progress").? == .null);
        if (!contended) {
            const intent = try protocol.Intent.load(allocator, io, fixture.directory);
            const report = try protocol.Report.parse(allocator, raw.bytes(), intent);
            try unavailableReport(report, .conflict);
            try testing.expectEqual(@as(u64, 0), report.admitted_plan.?.mutations);
        } else {
            try testing.expect(fields.get("attempt_id").? == .null);
        }
        try noChildren();
    }
}
test "real native worker uploads downloads and reads page footer through supervised protocol" {
    for ([_]struct { kind: core.transfer.job.Kind, size: usize, download: bool }{
        .{ .kind = .blob, .size = 17001, .download = false },
        .{ .kind = .blob, .size = 0, .download = true },
        .{ .kind = .pages, .size = 512, .download = false },
    }) |case| {
        const fixture = try Fixture.init("pass", case.kind, case.size, case.download, 5000);
        defer fixture.deinit();
        const result = fixture.run(null);
        try testing.expect(result.succeeded());
        try testing.expectEqual(@as(?bool, true), result.process_cleanup_complete);
        try testing.expectEqual(@as(u64, if (case.kind == .pages) 2 else 1), result.progress.?.requests_attempted);
        try testing.expectEqual(@as(u64, if (case.download) 0 else case.size), result.progress.?.bytes_confirmed);
        if (case.kind == .pages) try testing.expect(result.outcome.?.footer_sha256 != null);
        var durable = try fixture.directory.readSensitive(io, allocator, core.transfer.job.supervised_name, protocol.maximum_result, null);
        defer durable.deinit();
        try testing.expect(std.mem.indexOf(u8, durable.bytes(), "\"delivery_complete\":true") != null);
        try safeReport(result);
        try noChildren();
    }
}

test "unavailable read-only progress remains unknown through validation and recovery" {
    const intent: protocol.Intent = .{
        .attempt_id = [_]u8{1} ** 32,
        .job_sha256 = [_]u8{2} ** 32,
        .kind = .blob,
        .plan = .{ .bytes = 0, .download_bytes = 128, .mutations = 0, .requests = 1 },
        .request_sha256 = [_]u8{3} ** 32,
        .sas_sha256 = [_]u8{4} ** 32,
        .parent_pid = 1,
        .deadline_ns = 0,
    };
    var report = protocol.Report.initial(intent);
    report.progress = null;
    report.side_effect = .unknown;
    try report.failures.record(.primary, .{ .stage = .transfer_worker, .category = .conflict });
    try report.failures.record(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
    try roundtrip(report, intent);
    var buffer: [protocol.maximum_result]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try report.write(&writer);
    const recovered = try protocol.Report.recover(allocator, writer.buffered(), intent);
    try testing.expectEqualDeep(report, recovered);
    const corrupt = try mutateOne(writer.buffered(), "\"phase\":\"prepared\"", "\"phase\":\"in_flight\"");
    defer allocator.free(corrupt);
    try testing.expectError(error.InvalidReport, protocol.Report.parse(allocator, corrupt, intent));
    const rejected = try protocol.Report.recover(allocator, corrupt, intent);
    try testing.expectEqual(.unknown, rejected.side_effect);
    try testing.expect(rejected.progress == null);
    try testing.expectEqualDeep(report.failures.primary, rejected.failures.primary);
    try testing.expectEqualDeep(report.failures.cleanup, rejected.failures.cleanup);
    try testing.expect(rejected.failures.recording != null);
    for ([_]core.transfer.diagnostic.Certainty{ .not_started, .not_applicable, .accepted, .rejected, .incomplete }) |effect| {
        var invalid = report;
        invalid.side_effect = effect;
        try testing.expectError(error.InvalidReport, invalid.validate());
        try testing.expect(!invalid.succeeded());
    }
    var invalid = report;
    invalid.phase = .finished;
    invalid.delivery_complete = true;
    invalid.outcome = core.transfer.Outcome.fail(.request_file, .condition);
    invalid.outcome.?.side_effect = .unknown;
    invalid.outcome.?.bytes_accepted = 1;
    try testing.expectError(error.InvalidReport, invalid.validate());
    const known_read_only = protocol.Report.initial(intent);
    try testing.expectEqual(.not_applicable, known_read_only.side_effect);
    try roundtrip(known_read_only, intent);
}

test "sealed artifacts keep nonprivate mode and hard-link policy distinct from SAS files" {
    const fixture = try Fixture.init("pass", .blob, 4096, false, 5000);
    defer fixture.deinit();
    const file = try fixture.directory.openFile(io, "source");
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    try file.hardLink(io, fixture.directory.dir, "source-link", .{});
    try testing.expect(fixture.run(null).succeeded());
    try testing.expectError(error.UnsafeFile, fixture.directory.openFile(io, "source"));
    try noChildren();
}

test "partial page side effects retain attempted confirmed and consumed-attempt state" {
    const fixture = try Fixture.init("partial", .pages, 4 * 1024 * 1024 + 512, false, 5000);
    defer fixture.deinit();
    const result = fixture.run(null);
    try testing.expect(!result.succeeded());
    try testing.expectEqual(.unknown, result.side_effect);
    try testing.expectEqual(@as(u64, 2), result.progress.?.mutations_attempted);
    try testing.expectEqual(@as(u64, 1), result.progress.?.mutations_confirmed);
    try testing.expectEqual(@as(u64, 4 * 1024 * 1024 + 512), result.progress.?.bytes_attempted);
    try testing.expectEqual(@as(u64, 4 * 1024 * 1024), result.progress.?.bytes_confirmed);
    try testing.expectEqual(result.progress.?.bytes_confirmed, result.outcome.?.bytes_accepted);
    try testing.expectEqual(.transport, result.failures.primary.?.category);
    const repeated = fixture.run(null);
    try testing.expectEqual(.conflict, repeated.failures.primary.?.category);
    try testing.expectEqual(.unknown, repeated.side_effect);
    var invocations = try fixture.directory.readSensitive(io, allocator, "invocations", 32, null);
    defer invocations.deinit();
    try testing.expectEqualStrings("1", invocations.bytes());
    try safeReport(result);
    try noChildren();
}

test "hard parent deadline stops a native blocked transport and keeps pending effects unknown" {
    const fixture = try Fixture.init("blocked", .blob, 4096, false, 1500);
    defer fixture.deinit();
    const result = fixture.run(null);
    try testing.expect(!result.succeeded());
    try testing.expectEqual(.timeout, result.failures.primary.?.category);
    try testing.expectEqual(@as(?bool, true), result.process_cleanup_complete);
    try testing.expectEqual(.unknown, result.side_effect);
    try testing.expect(result.outcome == null);
    try testing.expect(result.progress.?.pending);
    try testing.expectEqual(@as(u64, 1), result.progress.?.mutations_attempted);
    try testing.expectEqual(@as(u64, 0), result.progress.?.mutations_confirmed);
    _ = try fixture.directory.dir.statFile(io, "entered", .{});
    try safeReport(result);
    try noChildren();
}

test "cancellation terminates a native blocked worker under an independent cleanup budget" {
    const fixture = try Fixture.init("blocked", .blob, 4096, false, 5000);
    defer fixture.deinit();
    var cancelled = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, struct {
        fn cancel(directory: std.Io.Dir, flag: *std.atomic.Value(bool)) void {
            var tries: usize = 0;
            while (tries < 400) : (tries += 1) {
                if (directory.statFile(io, "entered", .{})) |_| break else |_| {}
                const duration: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
                _ = linux.nanosleep(&duration, null);
            }
            flag.store(true, .release);
        }
    }.cancel, .{ fixture.directory.dir, &cancelled });
    defer thread.join();
    const result = fixture.run(&cancelled);
    try testing.expectEqual(.cancelled, result.failures.primary.?.category);
    try testing.expectEqual(@as(?bool, true), result.process_cleanup_complete);
    try testing.expectEqual(.unknown, result.side_effect);
    try testing.expect(result.progress.?.pending);
    _ = try fixture.directory.dir.statFile(io, "entered", .{});
    try safeReport(result);
    try noChildren();
}

test "malformed stale or excessive native output never substitutes successful delivery" {
    for ([_][]const u8{ "malformed", "stale", "flood" }) |mode| {
        const fixture = try Fixture.init(mode, .blob, 17, false, 5000);
        defer fixture.deinit();
        const result = fixture.run(null);
        try testing.expect(!result.succeeded());
        try testing.expect(!result.delivery_complete);
        try testing.expectEqual(.accepted, result.side_effect);
        const expected: core.diagnostics.Category = if (std.mem.eql(u8, mode, "flood")) .output_limit else if (std.mem.eql(u8, mode, "stale")) .integrity else .invalid_response;
        try testing.expectEqual(expected, result.failures.primary.?.category);
        try testing.expectEqual(.complete, result.outcome.?.completion);
        try testing.expectEqual(@as(u64, 17), result.progress.?.bytes_confirmed);
        try safeReport(result);
        try noChildren();
    }
}

test "native stderr and error bodies stay private while source metadata survives" {
    const clean = try Fixture.init("stderr_secret", .blob, 17, false, 5000);
    defer clean.deinit();
    const clean_result = clean.run(null);
    try testing.expect(clean_result.succeeded());
    try safeReport(clean_result);
    const fixture = try Fixture.init("metadata", .blob, 17, false, 5000);
    defer fixture.deinit();
    const result = fixture.run(null);
    try testing.expectEqual(.rejected, result.side_effect);
    try testing.expectEqual(@as(?u16, 403), result.outcome.?.diagnostic.status);
    try testing.expectEqual(.known, result.outcome.?.diagnostic.service.header);
    try testing.expectEqual(.malformed, result.outcome.?.diagnostic.service.body);
    try testing.expectEqual(.AuthorizationServiceMismatch, result.outcome.?.diagnostic.service.header_code.?);
    try testing.expectEqual(.malformed, result.failures.primary.?.service_code);
    try safeReport(result);
    try noChildren();
}

test "native transfer primary cleanup and recording failures occupy independent lanes" {
    const cleanup = try Fixture.init("cleanup_failure", .blob, 0, true, 5000);
    defer cleanup.deinit();
    const failed = cleanup.run(null);
    try testing.expectEqual(.integrity, failed.failures.primary.?.category);
    try testing.expectEqual(.cleanup_failed, failed.failures.cleanup.?.category);
    try testing.expect(failed.failures.recording == null);
    try testing.expect(failed.outcome.?.cleanup_failed);
    const recording = try Fixture.init("recording_failure", .blob, 17, false, 5000);
    defer recording.deinit();
    const result = recording.run(null);
    try testing.expect(!result.succeeded());
    try testing.expectEqual(.accepted, result.side_effect);
    try testing.expectEqual(@as(u64, 17), result.progress.?.bytes_confirmed);
    try testing.expect(result.failures.primary == null);
    try testing.expectEqual(.local_io, result.failures.recording.?.category);
    try safeReport(result);
    try noChildren();
}

test "worker refuses request substitution after private parent admission" {
    const fixture = try Fixture.init("changed_request", .blob, 17, false, 5000);
    defer fixture.deinit();
    const result = fixture.run(null);
    try testing.expectEqual(.not_started, result.side_effect);
    try testing.expectEqual(.integrity, result.failures.primary.?.category);
    try testing.expectEqual(@as(u64, 0), result.progress.?.requests_attempted);
    try noChildren();
}

test "strict worker result protocol rejects extra fields numeric coercions and inconsistent success" {
    const fixture = try Fixture.init("pass", .blob, 17, false, 5000);
    defer fixture.deinit();
    const result = fixture.run(null);
    try testing.expect(result.succeeded());
    var bytes: [protocol.maximum_result]u8 = undefined;
    var writer = std.Io.Writer.fixed(&bytes);
    try result.write(&writer);
    const intent = try protocol.Intent.load(allocator, io, fixture.directory);
    for ([_][2][]const u8{
        .{ "\"schema_version\":1", "\"schema_version\":true" },
        .{ "\"bytes_confirmed\":17", "\"bytes_confirmed\":17.0" },
        .{ "\"bytes_confirmed\":17", "\"bytes_confirmed\":0" },
        .{ "\"bytes_accepted\":17", "\"bytes_accepted\":0" },
        .{ "\"bytes_streamed\":17", "\"bytes_streamed\":0" },
        .{ "\"status\":201", "\"status\":403" },
        .{ "\"status\":201},\"phase\"", "\"status\":200},\"phase\"" },
        .{ "\"status\":201},\"schema_version\"", "\"status\":200},\"schema_version\"" },
        .{ "\"contract\":\"uk.hyperv.transfer-report\"", "\"contract\":\"uk.hyperv.transfer-report\",\"message\":\"SYNTHETIC_SECRET\"" },
    }) |change| {
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), change[0]) != null);
        const raw = try std.mem.replaceOwned(u8, allocator, writer.buffered(), change[0], change[1]);
        defer allocator.free(raw);
        if (protocol.Report.parse(allocator, raw, intent)) |_| return error.InvalidReportAccepted else |_| {}
    }
    var inconsistent = result;
    inconsistent.outcome.?.bytes_accepted = 0;
    try testing.expect(!inconsistent.succeeded());
    try testing.expectError(error.InvalidReport, inconsistent.write(&writer));
    inconsistent = result;
    inconsistent.progress.?.mutations_confirmed = 0;
    try testing.expect(!inconsistent.succeeded());
    inconsistent = result;
    inconsistent.admitted_plan = null;
    try testing.expect(!inconsistent.succeeded());
    try noChildren();
}

test "native recovery rejects pending no-mutation claims including zero-byte mutations" {
    for ([_]struct { size: usize, container: bool }{
        .{ .size = 17, .container = false },
        .{ .size = 0, .container = false },
        .{ .size = 0, .container = true },
    }) |case| {
        const fixture = try Fixture.init("pending_forgery", .blob, case.size, false, 1500);
        defer fixture.deinit();
        if (case.container) try fixture.createContainer();
        const result = fixture.run(null);
        try testing.expectEqual(.timeout, result.failures.primary.?.category);
        try testing.expectEqual(.invalid_response, result.failures.recording.?.category);
        try testing.expectEqual(.unknown, result.side_effect);
        try testing.expect(result.progress.?.pending_mutation);
        try testing.expectEqual(@as(u64, 1), result.progress.?.mutations_attempted);
        try testing.expectEqual(@as(u64, 0), result.progress.?.mutations_confirmed);
        try testing.expectEqual(@as(u64, if (case.container) 0 else case.size), result.progress.?.bytes_attempted);
        var raw = try fixture.directory.readSensitive(io, allocator, core.transfer.job.state_name, protocol.maximum_result, null);
        defer raw.deinit();
        const intent = try protocol.Intent.load(allocator, io, fixture.directory);
        try testing.expectError(error.InvalidReport, protocol.Report.parse(allocator, raw.bytes(), intent));
        try testing.expect(!result.succeeded());
        try safeReport(result);
        try noChildren();
    }
}

test "native counter forgery cannot succeed and recovery preserves confirmed progress" {
    const fixture = try Fixture.init("counter_forgery", .blob, 17, false, 5000);
    defer fixture.deinit();
    const result = fixture.run(null);
    try testing.expect(!result.succeeded());
    try testing.expectEqual(.invalid_response, result.failures.primary.?.category);
    try testing.expectEqual(.invalid_response, result.failures.recording.?.category);
    try testing.expectEqual(.accepted, result.side_effect);
    try testing.expectEqual(@as(u64, 17), result.progress.?.bytes_confirmed);
    try testing.expectEqual(@as(u64, 1), result.progress.?.mutations_confirmed);
    try testing.expect(result.outcome == null);
    try testing.expect(!result.delivery_complete);
    try safeReport(result);
    try noChildren();
}

test "native zero-byte rejected partial and short-reader controls preserve distinct counter meanings" {
    const Case = struct {
        mode: []const u8,
        size: usize = 0,
        container: bool = false,
        effect: core.transfer.diagnostic.Certainty,
        confirmed: u64,
        accepted: u64 = 0,
        streamed: u64 = 0,
        complete: bool = false,
    };
    for ([_]Case{
        .{ .mode = "pass", .effect = .accepted, .confirmed = 1, .complete = true },
        .{ .mode = "pass", .container = true, .effect = .accepted, .confirmed = 2, .complete = true },
        .{ .mode = "reject", .effect = .rejected, .confirmed = 0 },
        .{ .mode = "reject_second", .container = true, .effect = .incomplete, .confirmed = 1 },
        .{ .mode = "partial", .container = true, .effect = .unknown, .confirmed = 1 },
        .{ .mode = "container_body_failure", .size = 17, .container = true, .effect = .incomplete, .confirmed = 1 },
        .{ .mode = "early_accept", .size = 17, .effect = .accepted, .confirmed = 1, .accepted = 17 },
        .{ .mode = "short_source", .size = 17, .effect = .unknown, .confirmed = 0 },
        .{ .mode = "growing_source", .size = 17, .effect = .unknown, .confirmed = 0, .streamed = 18 },
    }) |case| {
        const fixture = try Fixture.init(case.mode, .blob, case.size, false, 5000);
        defer fixture.deinit();
        if (case.container) try fixture.createContainer();
        const result = fixture.run(null);
        try testing.expectEqual(case.effect, result.side_effect);
        try testing.expectEqual(case.confirmed, result.progress.?.mutations_confirmed);
        try testing.expectEqual(case.accepted, result.outcome.?.bytes_accepted);
        try testing.expectEqual(case.streamed, result.outcome.?.bytes_streamed);
        try testing.expectEqual(case.complete, result.succeeded());
        try testing.expect(result.failures.recording == null);
        try safeReport(result);
        try noChildren();
    }
}

test "read-only failures and pending footer reads do not invent mutation uncertainty" {
    for ([_]struct { mode: []const u8, pages: bool, pre_open: bool = false }{
        .{ .mode = "pass", .pages = false, .pre_open = true },
        .{ .mode = "disconnect", .pages = false },
        .{ .mode = "blocked", .pages = false },
        .{ .mode = "block_footer", .pages = true },
    }) |case| {
        const fixture = try Fixture.init(case.mode, if (case.pages) .pages else .blob, if (case.pages) 512 else 0, !case.pages, 1500);
        defer fixture.deinit();
        if (case.pre_open) try fixture.put("download", "existing");
        const result = fixture.run(null);
        try testing.expect(!result.succeeded());
        try testing.expectEqual(if (case.pages) core.transfer.diagnostic.Certainty.accepted else .not_applicable, result.side_effect);
        try testing.expectEqual(@as(u64, if (case.pages) 1 else 0), result.progress.?.mutations_confirmed);
        try testing.expect(result.failures.recording == null);
        try safeReport(result);
        try noChildren();
    }
}

test "installed CLI exposes supervised transfers and refuses unsupervised worker execution" {
    const fixture = try Fixture.init("pass", .blob, 17, false, 5000);
    defer fixture.deinit();
    try core.process.initialize();
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    const executable = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, allocator);
    defer allocator.free(executable);
    var help = try core.process.run(allocator, io, .{
        .argv = &.{ executable, "--help" },
        .cwd = fixture.directory.dir,
        .environment = &environment,
        .deadline = try core.process.Deadline.afterMilliseconds(3000),
    });
    defer help.deinit(allocator);
    try testing.expect(help.failures.primary == null);
    try testing.expect(std.mem.indexOf(u8, help.stdout, "transfer PRIVATE_DIRECTORY JOB_BASENAME") != null);
    var inspection = try core.process.run(allocator, io, .{
        .argv = &.{ executable, "inspect-json", fixture.path, "request.json" },
        .cwd = fixture.directory.dir,
        .environment = &environment,
        .deadline = try core.process.Deadline.afterMilliseconds(3000),
    });
    defer inspection.deinit(allocator);
    try testing.expect(inspection.failures.primary == null);
    try testing.expectEqualStrings("{\"canonical\":false,\"valid\":true}\n", inspection.stdout);
    var refused = try core.process.run(allocator, io, .{
        .argv = &.{ executable, "__transfer-worker", "job.json" },
        .cwd = fixture.directory.dir,
        .environment = &environment,
        .deadline = try core.process.Deadline.afterMilliseconds(3000),
    });
    defer refused.deinit(allocator);
    try testing.expect(refused.failures.primary == null);
    const document = try core.contracts.SensitiveDocument.parse(allocator, refused.stdout, .{});
    defer document.deinit();
    const outcome = try core.transfer.Outcome.parse(document.value().object.get("outcome").?);
    try testing.expectEqual(.failed, outcome.completion);
    try testing.expectEqual(.not_started, outcome.side_effect);
    try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, "entered", .{}));
    // Exercise the public CLI and its real native worker without reaching HTTP.
    try fixture.directory.dir.deleteFile(io, "source");
    var public = try core.process.run(allocator, io, .{
        .argv = &.{ executable, "transfer", fixture.path, "job.json" },
        .cwd = fixture.directory.dir,
        .environment = &environment,
        .deadline = try core.process.Deadline.afterMilliseconds(10000),
    });
    defer public.deinit(allocator);
    try testing.expect(public.failures.primary != null);
    try testing.expect(public.cleanup_complete);
    const intent = try protocol.Intent.load(allocator, io, fixture.directory);
    var final_bytes = try fixture.directory.readSensitive(io, allocator, core.transfer.job.supervised_name, protocol.maximum_result, null);
    defer final_bytes.deinit();
    const final = try protocol.Report.parse(allocator, final_bytes.bytes(), intent);
    try testing.expect(!final.succeeded());
    try testing.expectEqual(.not_started, final.side_effect);
    try testing.expectEqual(@as(u64, 0), final.progress.?.requests_attempted);
    try testing.expectEqual(.input_hash, final.outcome.?.diagnostic.stage);
    try safeReport(final);
    try noChildren();
}

test "invalid private jobs and unsafe SAS modes fail before child execution" {
    for ([_][2][]const u8{
        .{ "\"schema_version\":1", "\"schema_version\":2" },
        .{ "\"kind\":\"blob\"", "\"kind\":\"blob\",\"token\":\"SYNTHETIC_SECRET\"" },
        .{ "\"sas\":\"sas\"", "\"sas\":\"request.json\"" },
        .{ "\"request\":\"request.json\"", "\"request\":\"../request.json\"" },
        .{ "\"request\":\"request.json\"", "\"request\":\"transfer-state.json\"" },
        .{ "\"timeout_ms\":5000", "\"timeout_ms\":true" },
        .{ "\"timeout_ms\":5000", "\"timeout_ms\":5e3" },
        .{ "\"timeout_ms\":5000", "\"timeout_ms\":3600001" },
        .{ "\"cleanup_ms\":1000", "\"cleanup_ms\":0" },
    }) |change| {
        const fixture = try Fixture.init("pass", .blob, 17, false, 5000);
        defer fixture.deinit();
        var original = try fixture.directory.readSensitive(io, allocator, "job.json", 8192, null);
        defer original.deinit();
        const changed = try std.mem.replaceOwned(u8, allocator, original.bytes(), change[0], change[1]);
        defer allocator.free(changed);
        try fixture.put("job.json", changed);
        const result = fixture.run(null);
        try testing.expect(!result.succeeded());
        try testing.expectEqual(.not_started, result.side_effect);
        try testing.expect(result.failures.primary != null);
        try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, "invocations", .{}));
    }
    const fixture = try Fixture.init("pass", .blob, 17, false, 5000);
    defer fixture.deinit();
    const sas = try fixture.directory.openFile(io, "sas");
    try sas.setPermissions(io, .fromMode(0o644));
    sas.close(io);
    const result = fixture.run(null);
    try testing.expectEqual(.unsafe_file, result.failures.primary.?.category);
    try testing.expectEqual(.not_started, result.side_effect);
    try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, "invocations", .{}));
    try noChildren();
}

test "durable admission recording failure prevents native transport and has its own lane" {
    const fixture = try Fixture.init("pass", .blob, 17, false, 5000);
    defer fixture.deinit();
    try fixture.directory.dir.createDir(io, core.transfer.job.state_name, .fromMode(0o700));
    const result = fixture.run(null);
    try testing.expect(!result.succeeded());
    try testing.expectEqual(.not_started, result.side_effect);
    try testing.expect(result.failures.primary == null);
    try testing.expect(result.failures.recording != null);
    try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, "invocations", .{}));
    try noChildren();
}

test "post-child lock failure preserves timeout or confirmed success and adds recording failure" {
    for ([_][]const u8{ "blocked_lock_failure", "final_lock_failure" }) |mode| {
        const fixture = try Fixture.init(mode, .blob, 17, false, 1500);
        defer fixture.deinit();
        const result = fixture.run(null);
        try testing.expect(!result.succeeded());
        try testing.expectEqual(@as(?bool, true), result.process_cleanup_complete);
        try testing.expect(result.failures.recording != null);
        if (std.mem.eql(u8, mode, "blocked_lock_failure")) {
            try testing.expectEqual(.timeout, result.failures.primary.?.category);
            try testing.expectEqual(.unknown, result.side_effect);
            try testing.expect(result.progress == null);
        } else {
            try testing.expect(result.failures.primary == null);
            try testing.expectEqual(.accepted, result.side_effect);
            try testing.expectEqual(@as(u64, 17), result.progress.?.bytes_confirmed);
            try testing.expectEqual(.complete, result.outcome.?.completion);
        }
        try testing.expectError(error.FileNotFound, fixture.directory.dir.statFile(io, core.transfer.job.supervised_name, .{}));
        try safeReport(result);
        try noChildren();
    }
}

test "outcome v2 preserves independent source metadata certainty and failure lanes" {
    const d = core.transfer.diagnostic;
    for ([_]d.Metadata{
        .{ .state = .malformed, .header = .known, .header_code = .AuthorizationServiceMismatch, .body = .malformed },
        .{ .state = .unknown, .body = .unknown },
        .{ .state = .conflicting, .header = .known, .header_code = .LeaseIdMismatchWithBlobOperation, .body = .known, .body_code = .PendingCopyOperation },
        .{},
    }) |metadata| {
        var outcome = d.Outcome.fail(.input_verify, .input_changed);
        outcome.diagnostic.status = 403;
        outcome.diagnostic.service = metadata;
        outcome.side_effect = .accepted;
        outcome.bytes_accepted = 17;
        outcome.bytes_streamed = 17;
        outcome.cleanup_failed = true;
        try outcome.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
        var buffer: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try outcome.write(&writer);
        const document = try core.contracts.SensitiveDocument.parse(allocator, writer.buffered(), .{});
        defer document.deinit();
        try document.requireCanonical(writer.buffered());
        const parsed = try d.Outcome.parse(document.value());
        try testing.expectEqualDeep(outcome, parsed);
        const failures = try parsed.failureSummary();
        try testing.expect(failures.primary != null and failures.cleanup != null and failures.recording != null);
        try testing.expectEqual(@as(?u16, 403), failures.primary.?.http_status);
    }
    try testing.expectError(error.InvalidOutcome, (d.Metadata{
        .state = .known,
        .code = .InvalidBlobType,
        .header = .known,
        .header_code = .PendingCopyOperation,
    }).validate());
}

fn emit(journal: *protocol.Journal, event: core.transfer.client.Event) !void {
    const observer = journal.observer();
    try observer.notifyFn(observer.context, event);
}

fn roundtrip(report: protocol.Report, intent: protocol.Intent) !void {
    var bytes: [protocol.maximum_result]u8 = undefined;
    var writer = std.Io.Writer.fixed(&bytes);
    try report.write(&writer);
    try testing.expectEqualDeep(report, try protocol.Report.parse(allocator, writer.buffered(), intent));
}

fn rejectSingleFields(report: protocol.Report, intent: protocol.Intent, changes: []const [2][]const u8) !void {
    var bytes: [protocol.maximum_result]u8 = undefined;
    var writer = std.Io.Writer.fixed(&bytes);
    try report.write(&writer);
    for (changes) |change| {
        const raw = try mutateOne(writer.buffered(), change[0], change[1]);
        defer allocator.free(raw);
        try testing.expectError(error.InvalidReport, protocol.Report.parse(allocator, raw, intent));
        const recovered = try protocol.Report.recover(allocator, raw, intent);
        try testing.expect(!recovered.succeeded());
        try testing.expect(recovered.failures.recording != null);
        try testing.expect(recovered.outcome == null);
        try recovered.validate();
    }
}

test "journal phase matrix validates serial transitions rollback heads and zero-byte prefixes" {
    const intent: protocol.Intent = .{
        .attempt_id = [_]u8{1} ** 32,
        .job_sha256 = [_]u8{2} ** 32,
        .request_sha256 = [_]u8{3} ** 32,
        .sas_sha256 = [_]u8{4} ** 32,
        .deadline_ns = 1000,
        .parent_pid = 1,
        .kind = .blob,
        .plan = .{ .bytes = 17, .download_bytes = 0, .mutations = 2, .requests = 2 },
    };
    for ([_]struct { started: bool, status: ?u16, effect: core.transfer.diagnostic.Certainty }{
        .{ .started = false, .status = null, .effect = .incomplete },
        .{ .started = true, .status = null, .effect = .unknown },
        .{ .started = true, .status = 412, .effect = .incomplete },
        .{ .started = true, .status = 201, .effect = .accepted },
    }) |case| {
        const fixture = try Fixture.init("pass", .blob, 17, false, 5000);
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        var journal: protocol.Journal = .{
            .io = io,
            .lock = &lock,
            .plan = intent.plan,
            .report = .initial(intent),
        };
        try journal.persist();
        try roundtrip(journal.report, intent);
        try rejectSingleFields(journal.report, intent, &.{
            .{ "\"phase\":\"prepared\"", "\"phase\":\"observed\"" },
            .{ "\"side_effect\":\"not_started\"", "\"side_effect\":\"unknown\"" },
            .{ "\"requests_attempted\":0", "\"requests_attempted\":1" },
        });
        try emit(&journal, .{ .begin = .{ .stage = .container_create, .mutation = true, .bytes = 0 } });
        try roundtrip(journal.report, intent);
        try rejectSingleFields(journal.report, intent, &.{
            .{ "\"side_effect\":\"unknown\"", "\"side_effect\":\"not_started\"" },
            .{ "\"side_effect\":\"unknown\"", "\"side_effect\":\"accepted\"" },
            .{ "\"side_effect\":\"unknown\"", "\"side_effect\":\"rejected\"" },
            .{ "\"side_effect\":\"unknown\"", "\"side_effect\":\"incomplete\"" },
            .{ "\"side_effect\":\"unknown\"", "\"side_effect\":\"not_applicable\"" },
            .{ "\"phase\":\"in_flight\"", "\"phase\":\"observed\"" },
            .{ "\"pending\":true", "\"pending\":false" },
            .{ "\"pending_mutation\":true", "\"pending_mutation\":false" },
            .{ "\"pending_bytes\":0", "\"pending_bytes\":1" },
            .{ "\"mutations_attempted\":1", "\"mutations_attempted\":0" },
            .{ "\"mutations_confirmed\":0", "\"mutations_confirmed\":1" },
            .{ "\"responses_observed\":0", "\"responses_observed\":1" },
            .{ "\"previous_effect\":\"not_started\"", "\"previous_effect\":\"accepted\"" },
            .{ "\"status\":null", "\"status\":201" },
        });
        const pending = journal.report;
        try testing.expectError(error.InvalidProgress, emit(&journal, .{ .end = .{ .transport_started = false, .status = 201 } }));
        try testing.expectEqualDeep(pending, journal.report);
        try emit(&journal, .{ .end = .{ .transport_started = true, .status = 201 } });
        try roundtrip(journal.report, intent);
        try testing.expectEqual(.incomplete, journal.report.side_effect);
        try testing.expectEqual(@as(u64, 0), journal.report.progress.?.bytes_confirmed);
        try rejectSingleFields(journal.report, intent, &.{
            .{ "\"side_effect\":\"incomplete\"", "\"side_effect\":\"not_started\"" },
            .{ "\"side_effect\":\"incomplete\"", "\"side_effect\":\"accepted\"" },
            .{ "\"mutations_confirmed\":1", "\"mutations_confirmed\":0" },
            .{ "\"status\":201", "\"status\":412" },
        });
        try emit(&journal, .{ .begin = .{ .stage = .block_put, .mutation = true, .bytes = 17 } });
        try roundtrip(journal.report, intent);
        try rejectSingleFields(journal.report, intent, &.{
            .{ "\"previous_effect\":\"incomplete\"", "\"previous_effect\":\"not_started\"" },
            .{ "\"bytes_attempted\":17", "\"bytes_attempted\":0" },
            .{ "\"pending_bytes\":17", "\"pending_bytes\":0" },
            .{ "\"mutations_confirmed\":1", "\"mutations_confirmed\":0" },
        });
        try emit(&journal, .{ .end = .{ .transport_started = case.started, .status = case.status } });
        try testing.expectEqual(case.effect, journal.report.side_effect);
        try roundtrip(journal.report, intent);
        if (case.started and case.status != 201) {
            const stopped = journal.report;
            try testing.expectError(error.InvalidProgress, emit(&journal, .{ .begin = .{ .stage = .block_put, .mutation = true, .bytes = 0 } }));
            try testing.expectEqualDeep(stopped, journal.report);
        }
        var outcome = core.transfer.Outcome.fail(.block_put, .transport);
        outcome.side_effect = case.effect;
        outcome.diagnostic.status = case.status;
        outcome.bytes_accepted = if (case.status == 201) 17 else 0;
        outcome.bytes_streamed = if (case.status != null) 17 else 0;
        if (case.status == 201) {
            outcome.completion = .complete;
            outcome.diagnostic.category = .none;
        }
        const finished = journal.finish(outcome);
        try roundtrip(finished, intent);
        try testing.expect(finished.failures.recording == null);
        if (case.status == 201) {
            var parent = finished;
            parent.process_cleanup_complete = true;
            try testing.expect(parent.succeeded());
        }
    }
}

test "recovery preserves each existing failure lane and discards invalid progress conservatively" {
    const fixture = try Fixture.init("metadata", .blob, 17, false, 5000);
    defer fixture.deinit();
    _ = fixture.run(null);
    const intent = try protocol.Intent.load(allocator, io, fixture.directory);
    var raw = try fixture.directory.readSensitive(io, allocator, core.transfer.job.state_name, protocol.maximum_result, null);
    defer raw.deinit();
    var original = try protocol.Report.parse(allocator, raw.bytes(), intent);
    try original.failures.record(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
    try original.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
    var bytes: [protocol.maximum_result]u8 = undefined;
    var writer = std.Io.Writer.fixed(&bytes);
    try original.write(&writer);
    const bad_outcome = try mutateOne(writer.buffered(), "\"bytes_accepted\":0", "\"bytes_accepted\":1");
    defer allocator.free(bad_outcome);
    const recovered = try protocol.Report.recover(allocator, bad_outcome, intent);
    try testing.expectEqualDeep(original.failures, recovered.failures);
    try testing.expectEqualDeep(original.progress, recovered.progress);
    try testing.expectEqual(.rejected, recovered.side_effect);
    try testing.expect(recovered.outcome == null);
    const bad_progress = try mutateOne(writer.buffered(), "\"mutations_attempted\":1", "\"mutations_attempted\":0");
    defer allocator.free(bad_progress);
    const uncertain = try protocol.Report.recover(allocator, bad_progress, intent);
    try testing.expectEqualDeep(original.failures, uncertain.failures);
    try testing.expectEqual(.unknown, uncertain.side_effect);
    try testing.expect(uncertain.progress == null);
    try uncertain.validate();
    var parent = protocol.Report.initial(intent);
    try parent.failures.record(.primary, .{ .stage = .transfer_worker, .category = .timeout });
    const prior = parent.failures.primary.?;
    parent.retain(recovered);
    try testing.expectEqualDeep(prior, parent.failures.primary.?);
    try testing.expectEqualDeep(original.failures.cleanup, parent.failures.cleanup);
    try testing.expectEqualDeep(original.failures.recording, parent.failures.recording);
    try noChildren();
}

test "write-ahead recording refusal rolls back unentered zero-byte and payload mutations" {
    for ([_]u64{ 0, 17 }) |size| {
        const fixture = try Fixture.init("pass", .blob, @intCast(size), false, 5000);
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const intent: protocol.Intent = .{
            .attempt_id = [_]u8{1} ** 32,
            .job_sha256 = [_]u8{2} ** 32,
            .request_sha256 = [_]u8{3} ** 32,
            .sas_sha256 = [_]u8{4} ** 32,
            .deadline_ns = 1000,
            .parent_pid = 1,
            .kind = .blob,
            .plan = .{ .bytes = size, .download_bytes = 0, .mutations = 1, .requests = 1 },
        };
        var journal: protocol.Journal = .{
            .io = io,
            .lock = &lock,
            .plan = intent.plan,
            .report = .initial(intent),
        };
        try journal.persist();
        try fixture.directory.dir.deleteFile(io, core.transfer.job.state_name);
        try fixture.directory.dir.createDir(io, core.transfer.job.state_name, .fromMode(0o700));
        try testing.expectError(error.RecordingFailed, emit(&journal, .{ .begin = .{
            .stage = if (size == 0) .container_create else .block_put,
            .mutation = true,
            .bytes = size,
        } }));
        try testing.expect(journal.report.progress.?.pending_mutation);
        var outcome = core.transfer.Outcome.fail(.block_put, .none);
        try outcome.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
        const result = journal.finish(outcome);
        try testing.expectEqual(.not_started, result.side_effect);
        try testing.expectEqual(@as(u64, 0), result.progress.?.mutations_attempted);
        try testing.expectEqual(@as(u64, 0), result.progress.?.bytes_attempted);
        try testing.expect(result.failures.primary == null and result.failures.recording != null);
        try roundtrip(result, intent);
    }
}
