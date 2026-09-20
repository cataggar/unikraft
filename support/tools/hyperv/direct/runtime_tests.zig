const std = @import("std");
const runtime = @import("runtime.zig");
const validator = @import("main.zig");
const core = @import("hyperv_core");
const support = @import("process_test_support");
const testing = std.testing;
const allocator = testing.allocator;
const io = testing.io;
const linux = std.os.linux;

fn timingScope() validator.Scope {
    var scope = std.mem.zeroes(validator.Scope);
    scope.runtime_seconds = 60;
    scope.cleanup_seconds = 60;
    scope.operation_seconds = 10;
    scope.approval.expires_unix = 100;
    return scope;
}

test "scope timing keeps approval wall expiry independent from monotonic cleanup" {
    var scope = timingScope();
    var budgets = try runtime.Budgets.Test.start(scope, 0, 1);
    const first = try runtime.Budgets.Test.call(budgets, .primary, .azure, 0, 99);
    try testing.expectEqual(@as(u64, 10 * std.time.ns_per_s), first.deadline.expires_ns);
    try testing.expectEqual(@as(u64, 13 * std.time.ns_per_s), first.cleanup_deadline.expires_ns);
    try testing.expectError(error.ApprovalExpired, runtime.Budgets.Test.call(budgets, .primary, .azure, 0, 100));
    const tail = try runtime.Budgets.Test.call(budgets, .primary, .validator, 59 * std.time.ns_per_s, 1);
    try testing.expectEqual(@as(u64, 60 * std.time.ns_per_s), tail.deadline.expires_ns);
    try testing.expectError(error.BudgetExhausted, runtime.Budgets.Test.call(budgets, .primary, .azure, 60 * std.time.ns_per_s, 1));
    try testing.expectError(error.CleanupNotStarted, runtime.Budgets.Test.call(budgets, .cleanup, .azure, 0, 100));
    try runtime.Budgets.Test.cleanup(&budgets, 60 * std.time.ns_per_s);
    _ = try runtime.Budgets.Test.call(budgets, .cleanup, .azure, 60 * std.time.ns_per_s, 500);
    try testing.expectError(error.ApprovalExpired, runtime.Budgets.Test.call(budgets, .primary, .azure, 60 * std.time.ns_per_s, 1));
    try testing.expectError(error.CleanupAlreadyStarted, runtime.Budgets.Test.cleanup(&budgets, 61 * std.time.ns_per_s));
    try testing.expectError(error.BudgetExhausted, runtime.Budgets.Test.call(budgets, .cleanup, .azure, 120 * std.time.ns_per_s, 1));
    scope.runtime_seconds = 3601;
    try testing.expectError(error.InvalidBudget, runtime.Budgets.Test.start(scope, 0, 1));
    scope.runtime_seconds = 3600;
    scope.operation_seconds = 601;
    try testing.expectError(error.InvalidBudget, runtime.Budgets.Test.start(scope, 0, 1));
    scope.operation_seconds = 600;
    scope.cleanup_seconds = 1801;
    try testing.expectError(error.InvalidBudget, runtime.Budgets.Test.start(scope, 0, 1));
}

test "native transfer preserves five second cleanup seven second reserve and eight second minimum" {
    const budgets = try runtime.Budgets.Test.start(timingScope(), 0, 1);
    const regular = try runtime.Budgets.Test.call(budgets, .primary, .uploader, 0, 1);
    try testing.expectEqual(@as(?u32, 3000), regular.worker_timeout_ms);
    try testing.expectEqual(@as(u64, 13 * std.time.ns_per_s), regular.cleanup_deadline.expires_ns);
    const minimum = try runtime.Budgets.Test.call(budgets, .primary, .uploader, 52 * std.time.ns_per_s, 1);
    try testing.expectEqual(@as(?u32, 1000), minimum.worker_timeout_ms);
    try testing.expectEqual(@as(u32, 5000), runtime.transfer_cleanup_ms);
    try testing.expectError(error.InsufficientTransferBudget, runtime.Budgets.Test.call(budgets, .primary, .uploader, 52 * std.time.ns_per_s + std.time.ns_per_ms, 1));
}

test "optional diagnostics leave two full operations plus termination and reaping" {
    var budgets = try runtime.Budgets.Test.start(timingScope(), 0, 1);
    try runtime.Budgets.Test.cleanup(&budgets, 0);
    const diagnostic = try runtime.Budgets.Test.call(budgets, .diagnostic, .azure, 0, 500);
    try testing.expectEqual(@as(u64, 10 * std.time.ns_per_s), diagnostic.deadline.expires_ns);
    try testing.expectEqual(@as(u64, 13 * std.time.ns_per_s), diagnostic.cleanup_deadline.expires_ns);
    const tail = try runtime.Budgets.Test.call(budgets, .diagnostic, .azure, 30 * std.time.ns_per_s, 500);
    try testing.expectEqual(@as(u64, 31 * std.time.ns_per_s), tail.deadline.expires_ns);
    try testing.expectEqual(@as(u64, 34 * std.time.ns_per_s), tail.cleanup_deadline.expires_ns);
    for ([_]u64{ 31, 36, 37 }) |second|
        try testing.expectError(error.BudgetExhausted, runtime.Budgets.Test.call(budgets, .diagnostic, .azure, second * std.time.ns_per_s, 500));
}

test "diagnostic execution TERM and reaping fit thirty seconds before two complete cleanup calls" {
    var scope = timingScope();
    scope.operation_seconds = 30;
    scope.cleanup_seconds = 120;
    var budgets = try runtime.Budgets.Test.start(scope, 0, 1);
    try runtime.Budgets.Test.cleanup(&budgets, 0);
    const start = 24 * std.time.ns_per_s;
    const diagnostic = try runtime.Budgets.Test.call(budgets, .diagnostic, .azure, start, 500);
    try testing.expectEqual(@as(u64, 27 * std.time.ns_per_s), diagnostic.deadline.expires_ns - start);
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), diagnostic.cleanup_deadline.expires_ns - start);
    try testing.expectEqual(@as(u64, 3 * std.time.ns_per_s), diagnostic.cleanup_deadline.expires_ns - diagnostic.deadline.expires_ns);

    const deletion = try runtime.Budgets.Test.call(budgets, .cleanup, .azure, diagnostic.cleanup_deadline.expires_ns, 500);
    try testing.expectEqual(@as(u64, 84 * std.time.ns_per_s), deletion.deadline.expires_ns);
    const deletion_reaped = deletion.deadline.expires_ns + 3 * std.time.ns_per_s;
    try testing.expect(deletion_reaped <= deletion.cleanup_deadline.expires_ns);
    const absence = try runtime.Budgets.Test.call(budgets, .cleanup, .azure, deletion_reaped, 500);
    try testing.expectEqual(@as(u64, 117 * std.time.ns_per_s), absence.deadline.expires_ns);
    try testing.expectEqual(absence.cleanup_deadline.expires_ns, absence.deadline.expires_ns + 3 * std.time.ns_per_s);
}

test "explicit selected operator environment excludes ambient secrets paths and runtime hooks" {
    var source = std.process.Environ.Map.init(allocator);
    defer source.deinit();
    try source.put("HOME", "/private/operator");
    try source.put("AZURE_CONFIG_DIR", "/private/operator/azure");
    try source.put("HTTPS_PROXY", "https://proxy.invalid:443");
    try source.put("PRIVATE_SECRET", "never-inherit");
    try source.put("SAS", "?sig=never-inherit");
    try source.put("PATH", "/never/discover");
    try source.put("PYTHONPATH", "/never/discover");
    inline for (.{ "AZ_PYTHON", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "LD_PRELOAD", "LD_LIBRARY_PATH" }) |key|
        try source.put(key, "/never/inherit");
    try source.put("LC_ALL", "other");
    try source.put("AZURE_CORE_COLLECT_TELEMETRY", "1");
    var environment = try runtime.Environment.init(allocator, &source);
    defer environment.deinit();
    try testing.expectEqualStrings("/private/operator/azure", environment.azure.get("AZURE_CONFIG_DIR").?);
    try testing.expectEqualStrings("C", environment.azure.get("LC_ALL").?);
    try testing.expectEqualStrings("0", environment.azure.get("AZURE_CORE_COLLECT_TELEMETRY").?);
    try testing.expectEqualStrings("1", environment.azure.get("PYTHONDONTWRITEBYTECODE").?);
    for ([_][]const u8{ "PRIVATE_SECRET", "SAS", "PATH", "PYTHONPATH", "AZ_PYTHON", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "LD_PRELOAD", "LD_LIBRARY_PATH" }) |key|
        try testing.expect(environment.azure.get(key) == null);
    try testing.expect(environment.native.get("HOME") == null);
    try source.put("HTTPS_PROXY", "https://proxy.invalid?sig=secret");
    try testing.expectError(error.SecretArgument, runtime.Environment.init(allocator, &source));
}

test "local version executes self contained and explicitly pinned interpreter under clean environment" {
    const launcher = @import("launcher.zig");
    const custody = @import("custody.zig");
    for ([_]bool{ false, true }) |python| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const executable = try support.executable();
        defer allocator.free(executable);
        var operator = std.process.Environ.Map.init(allocator);
        defer operator.deinit();
        try operator.put("HOME", support.options.test_root.?);
        inline for (.{ "AZ_PYTHON", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "PRIVATE_SECRET" }) |key|
            try operator.put(key, "/never/inherit");
        var environment = try runtime.Environment.init(allocator, &operator);
        defer environment.deinit();
        const interpreter = try launcher.selectInterpreter(io, &environment, if (python) executable else null, null);
        var cancellation = try core.process.SignalCancellation.install();
        defer cancellation.deinit();
        var scope = timingScope();
        scope.approval.expires_unix = std.math.maxInt(u64);
        var budgets = try runtime.Budgets.start(scope);
        const adapter: runtime.Runtime = .{
            .allocator = allocator,
            .io = io,
            .programs = .{ .azure = executable, .uploader = executable, .validator = executable, .azure_python = if (python) executable else null },
            .environment = &environment,
            .budgets = &budgets,
            .cancellation = &cancellation,
            .interpreter = interpreter,
        };
        try adapter.initialize();
        var status: launcher.Status = .{};
        try launcher.check(adapter, &lock, try custody.Reference.tool(io, executable), &status);
        try testing.expect(status.child.?.succeeded());
        try testing.expect(status.recording_error == null);
        try testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "consumed.json"));
        try support.noChildren();
    }
}

test "pinned interpreter changed in place or replaced refuses before child creation" {
    const launcher = @import("launcher.zig");
    for ([_]bool{ false, true }) |replace| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}/python", .{ support.options.test_root.?, fixture.name });
        defer allocator.free(path);
        var file = try fixture.directory.dir.createFile(io, "python", .{ .permissions = .fromMode(0o700) });
        try file.writePositionalAll(io, "synthetic interpreter", 0);
        file.close(io);
        var operator = std.process.Environ.Map.init(allocator);
        defer operator.deinit();
        try operator.put("HOME", support.options.test_root.?);
        var environment = try runtime.Environment.init(allocator, &operator);
        defer environment.deinit();
        const interpreter = try launcher.selectInterpreter(io, &environment, path, null);
        if (replace) try fixture.directory.dir.deleteFile(io, "python");
        file = try fixture.directory.dir.createFile(io, "python", .{ .permissions = .fromMode(0o700) });
        try file.writePositionalAll(io, if (replace) "synthetic interpreter" else "changed interpreter", 0);
        file.close(io);
        var cancellation = try core.process.SignalCancellation.install();
        defer cancellation.deinit();
        var scope = timingScope();
        scope.approval.expires_unix = std.math.maxInt(u64);
        var budgets = try runtime.Budgets.start(scope);
        const executable = try support.executable();
        defer allocator.free(executable);
        const adapter: runtime.Runtime = .{
            .allocator = allocator,
            .io = io,
            .programs = .{ .azure = executable, .uploader = executable, .validator = executable, .azure_python = path },
            .environment = &environment,
            .budgets = &budgets,
            .cancellation = &cancellation,
            .interpreter = interpreter,
        };
        try testing.expectError(error.ReferenceChanged, adapter.version(&lock));
        try testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "cli-version.stdout"));
        try support.noChildren();
    }
}

test "local version parser requires complete exact bounded Azure version schema" {
    const launcher = @import("launcher.zig");
    const valid = "{\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}";
    try launcher.validateVersion(allocator, valid);
    for ([_][]const u8{
        "",                                                                                                                                      "{}",                                                                                                           "null",                                                                                                           "true",                                                                                                                        "[]", valid ++ valid, "noise" ++ valid,
        "{\"azure-cli\":\"2.80.0\",\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}", "{\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.81.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}", "{\"azure-cli\":\"-2.80.0\",\"azure-cli-core\":\"-2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}", "{\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":[],\"extra\":true}",
    }) |invalid| try testing.expectError(error.CliVersionInvalid, launcher.validateVersion(allocator, invalid));
    try testing.expectError(error.CliVersionInvalid, launcher.validateVersion(allocator, &([_]u8{'x'} ** 4097)));
}

test "uploader uses the original native job parser and checks actual file budgets before spawning" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var source = std.process.Environ.Map.init(allocator);
    defer source.deinit();
    try source.put("HOME", support.options.test_root.?);
    var environment = try runtime.Environment.init(allocator, &source);
    defer environment.deinit();
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    var scope = timingScope();
    scope.approval.expires_unix = std.math.maxInt(u64);
    var budgets = try runtime.Budgets.start(scope);
    const adapter: runtime.Runtime = .{
        .allocator = allocator,
        .io = io,
        .programs = .{ .azure = executable, .uploader = executable, .validator = executable },
        .environment = &environment,
        .budgets = &budgets,
        .cancellation = &cancellation,
    };
    try adapter.initialize();
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ support.options.test_root.?, fixture.name });
    defer allocator.free(path);
    const base = "{\"contract\":\"uk.hyperv.transfer-job\",\"schema_version\":1,\"kind\":\"pages\",\"request\":\"request.json\",\"sas\":\"sas.txt\",";
    const invalid = try lock.createImmutable(io, "invalid-job.json", base ++ "\"timeout_ms\":4000,\"cleanup_ms\":5000}");
    try testing.expectEqual(.durable, invalid.status);
    try testing.expectError(error.InsufficientTransferBudget, adapter.run(.primary, .uploader, &.{ "transfer", path, "invalid-job.json" }, &lock, "bad-out", "bad-err"));
    try testing.expectError(error.FileNotFound, fixture.directory.openFile(io, "bad-out"));
    const cleanup = try lock.createImmutable(io, "bad-cleanup.json", base ++ "\"timeout_ms\":1000,\"cleanup_ms\":6000}");
    try testing.expectEqual(.durable, cleanup.status);
    try testing.expectError(error.InsufficientTransferBudget, adapter.run(.primary, .uploader, &.{ "transfer", path, "bad-cleanup.json" }, &lock, "bad-out", "bad-err"));
    const duplicate = try lock.createImmutable(io, "duplicate.json", base ++ "\"timeout_ms\":1000,\"timeout_ms\":1000,\"cleanup_ms\":5000}");
    try testing.expectEqual(.durable, duplicate.status);
    try testing.expectError(error.DuplicateField, adapter.run(.primary, .uploader, &.{ "transfer", path, "duplicate.json" }, &lock, "bad-out", "bad-err"));
    const valid = try lock.createImmutable(io, "job.json", base ++ "\"timeout_ms\":1000,\"cleanup_ms\":5000}");
    try testing.expectEqual(.durable, valid.status);
    const captured = try adapter.run(.primary, .uploader, &.{ "transfer", path, "job.json" }, &lock, "out", "err");
    try captured.requireSuccess();
    var raw = try fixture.read("out");
    defer raw.deinit();
    try testing.expectEqualStrings("{\"fixture_only\":true}\n", raw.bytes());
    try support.noChildren();
}

test "HUP INT TERM latch cancellation without suppressing budgeted owned cleanup" {
    for ([_]linux.SIG{ .HUP, .INT, .TERM }) |signal| {
        var fixture = try support.Fixture.init();
        defer fixture.deinit();
        var lock = try fixture.directory.lock(io);
        defer lock.close(io);
        const executable = try support.executable();
        defer allocator.free(executable);
        var source = std.process.Environ.Map.init(allocator);
        defer source.deinit();
        try source.put("HOME", support.options.test_root.?);
        var environment = try runtime.Environment.init(allocator, &source);
        defer environment.deinit();
        var cancellation = try core.process.SignalCancellation.install();
        defer cancellation.deinit();
        var scope = timingScope();
        scope.approval.expires_unix = std.math.maxInt(u64);
        var budgets = try runtime.Budgets.start(scope);
        const adapter: runtime.Runtime = .{
            .allocator = allocator,
            .io = io,
            .programs = .{ .azure = executable, .uploader = executable, .validator = executable },
            .environment = &environment,
            .budgets = &budgets,
            .cancellation = &cancellation,
        };
        try adapter.initialize();
        const sender = try std.Thread.spawn(.{}, struct {
            fn send(number: linux.SIG, pid: linux.pid_t) void {
                const duration: linux.timespec = .{ .sec = 0, .nsec = 150 * std.time.ns_per_ms };
                _ = linux.nanosleep(&duration, null);
                _ = linux.kill(pid, number);
            }
        }.send, .{ signal, linux.getpid() });
        const result = try adapter.run(.primary, .validator, &.{"partial"}, &lock, "out", "err");
        sender.join();
        try testing.expectEqual(.cancelled, result.execution.failures.primary.?.category);
        try testing.expect(result.execution.cleanup_complete);
        try testing.expectEqual(@as(?u8, @intCast(@intFromEnum(signal))), cancellation.signal());
        try testing.expectError(error.Cancelled, adapter.run(.primary, .azure, &.{"environment"}, &lock, "forbidden", "forbidden-err"));
        try budgets.beginCleanup();
        budgets.expires_unix = 0;
        const cleanup = try adapter.run(.cleanup, .azure, &.{"environment"}, &lock, "cleanup-out", "cleanup-err");
        try cleanup.requireSuccess();
        try testing.expect(cancellation.flag().load(.acquire));
        try testing.expectError(error.SecretArgument, adapter.run(.cleanup, .azure, &.{"https://storage.invalid?sig=secret"}, &lock, "secret", "secret-err"));
        try support.noChildren();
    }
}

test "nested outer budget exhaustion never extends the deadline to finish a report" {
    var fixture = try support.Fixture.init();
    defer fixture.deinit();
    var lock = try fixture.directory.lock(io);
    defer lock.close(io);
    const executable = try support.executable();
    defer allocator.free(executable);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var cancel = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, support.cancelAfter, .{ &cancel, @as(u32, 200) });
    defer thread.join();
    const start = try core.process.monotonicNanoseconds();
    const result = try core.process.runPrivate(allocator, io, &lock, "out", "err", .{
        .process = .{
            .argv = &.{ executable, "nested", "5200" },
            .environment = &environment,
            .cwd = fixture.directory.dir,
            .deadline = try core.process.Deadline.afterMilliseconds(10000),
            .cleanup_ms = 8000,
            .cancel = &cancel,
        },
        .term_grace_ms = 7000,
        .cleanup_deadline = .{ .expires_ns = start + 2000 * std.time.ns_per_ms },
        .nested_supervisor = true,
    });
    try testing.expect((try core.process.monotonicNanoseconds()) - start < 2200 * std.time.ns_per_ms);
    try testing.expectEqual(.cancelled, result.execution.failures.primary.?.category);
    try testing.expectEqual(.KILL, result.execution.termination.?.signal);
    try testing.expect(result.execution.cleanup_complete);
    try testing.expect(!result.succeeded());
    try support.noChildren();
}
