// SPDX-License-Identifier: BSD-3-Clause
//! Local startup only. No scope, reservation, subscription or resource command.
const std = @import("std");
const core = @import("hyperv_core");
const custody = @import("custody.zig");
const runtime = @import("runtime.zig");
const local = @import("controller_io.zig");
const azure_runtime = @import("azure_runtime.zig");

pub fn selectInterpreter(
    io: std.Io,
    environment: *runtime.Environment,
    path: ?[]const u8,
    closure: ?azure_runtime.Contract,
) !?custody.Reference {
    if (path) |value| {
        const reference = try custody.Reference.tool(io, value);
        if (reference.metadata.mode & 0o022 != 0) return error.UnsafeInterpreter;
        if (closure) |runtime_closure| {
            try environment.azure.put("PYTHONHOME", runtime_closure.root);
            try environment.azure.put(
                "AZURE_EXTENSION_DIR",
                runtime_closure.extensions,
            );
            try environment.azure.put(
                "AZURE_EXTENSION_USE_DYNAMIC_INSTALL",
                "no",
            );
        }
        return reference;
    }
    if (closure != null) return error.InterpreterNotSelected;
    return null;
}

fn versionString(value: []const u8) !void {
    if (value.len == 0 or value.len > 32) return error.CliVersionInvalid;
    var parts = std.mem.splitScalar(u8, value, '.');
    var count: usize = 0;
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 8) return error.CliVersionInvalid;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return error.CliVersionInvalid;
        count += 1;
    }
    if (count != 3) return error.CliVersionInvalid;
}

pub fn validateVersion(a: std.mem.Allocator, bytes: []const u8) !void {
    if (bytes.len == 0 or bytes.len > 4096) return error.CliVersionInvalid;
    const parsed = std.json.parseFromSlice(struct {
        @"azure-cli": []const u8,
        @"azure-cli-core": []const u8,
        @"azure-cli-telemetry": []const u8,
        extensions: std.json.Value,
    }, a, bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.CliVersionInvalid,
    };
    defer parsed.deinit();
    const value = parsed.value;
    try versionString(value.@"azure-cli");
    try versionString(value.@"azure-cli-telemetry");
    if (!std.mem.eql(u8, value.@"azure-cli", value.@"azure-cli-core") or
        value.extensions != .object or value.extensions.object.count() > 64) return error.CliVersionInvalid;
    var it = value.extensions.object.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.len == 0 or entry.key_ptr.len > 128 or entry.value_ptr.* != .string)
            return error.CliVersionInvalid;
        for (entry.key_ptr.*) |byte|
            if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.CliVersionInvalid;
        try versionString(entry.value_ptr.string);
    }
}

pub const Status = struct {
    child: ?core.process.PrivateResult = null,
    recording_error: ?anyerror = null,

    pub fn exit(self: Status, err: anyerror, cancellation: *const core.process.SignalCancellation) u8 {
        if (self.child) |child| {
            const code = runtime.processExit(child, cancellation);
            if (code != 0) return code;
        }
        return runtime.errorExit(err, cancellation);
    }

    pub fn report(self: Status, writer: *std.Io.Writer, err: anyerror, code: u8) !void {
        try std.json.Stringify.value(.{
            .phase = "local-cli-startup",
            .authority = "not_admitted",
            .reason = @errorName(err),
            .exit = code,
            .termination = if (self.child) |child| child.execution.termination else null,
            .failures = if (self.child) |child| child.execution.failures else null,
            .cleanup_complete = if (self.child) |child| child.execution.cleanup_complete else null,
            .capture = if (self.child) |child| child.capture else null,
            .recording_error = if (self.recording_error) |failure| @errorName(failure) else null,
        }, .{}, writer);
        try writer.writeByte('\n');
    }
};

pub fn check(adapter: runtime.Runtime, writer: *core.private_files.Locked, azure: custody.Reference, status: *Status) !void {
    try azure.verify(adapter.io);
    try adapter.verifyInterpreter();
    const result = try adapter.version(writer);
    status.child = result;
    // Preserve primary, cleanup and recording failures independently before
    // interpreting output. Child bytes never appear in the public diagnostic.
    {
        errdefer |err| status.recording_error = err;
        const record = try custody.encode(adapter.allocator, .{
            .schema = "uk.hyperv.local-cli-startup",
            .version = @as(u8, 1),
            .authority = "not_admitted",
            .capture = result.capture,
            .stdout_bytes = result.stdout_bytes,
            .stderr_bytes = result.stderr_bytes,
            .cleanup_complete = result.execution.cleanup_complete,
            .failures = result.execution.failures,
            .termination = result.execution.termination,
            .azure = azure,
            .interpreter = adapter.interpreter,
        });
        defer adapter.allocator.free(record);
        try custody.requireDurable(try writer.createImmutable(adapter.io, "cli-version.process.json", record));
    }
    if (!result.execution.cleanup_complete or result.execution.unreaped_group != null) return error.CliStartupCleanupFailed;
    if (!result.succeeded()) return error.CliStartupFailed;
    if (result.stderr_bytes != 0) return error.CliStartupStderr;
    try azure.verify(adapter.io);
    try adapter.verifyInterpreter();
    var bytes = try writer.directory.readSensitive(adapter.io, adapter.allocator, "cli-version.stdout", 4096, null);
    defer bytes.deinit();
    try validateVersion(adapter.allocator, bytes.bytes());
}

pub fn standalone(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len != 2 and args.len != 4 and args.len != 6)
        return error.InvalidArguments;
    if (args.len == 4 and !std.mem.eql(u8, args[2], "--az-python")) return error.InvalidArguments;
    if (args.len == 6 and
        (!std.mem.eql(u8, args[2], "--az-python") or
            !std.mem.eql(u8, args[4], "--azure-runtime")))
        return error.InvalidArguments;
    var closure = if (args.len == 6)
        try azure_runtime.load(init.gpa, init.io, args[5])
    else
        null;
    defer if (closure) |*value| value.deinit();
    if (closure) |value| try azure_runtime.verify(
        init.gpa,
        init.io,
        value.value.value,
    );
    const programs: runtime.Programs = .{
        .azure = args[1],
        .uploader = args[1],
        .validator = args[1],
        .azure_python = if (args.len >= 4) args[3] else null,
        .azure_runtime = if (args.len == 6) args[5] else null,
    };
    try programs.validate();
    const directory = try core.private_files.Directory.open(init.io, args[0]);
    defer directory.close(init.io);
    var writer = try directory.lock(init.io);
    defer writer.close(init.io);
    var environment = try runtime.Environment.init(init.gpa, init.environ_map);
    defer environment.deinit();
    const interpreter = try selectInterpreter(
        init.io,
        &environment,
        programs.azure_python,
        if (closure) |value| value.value.value else null,
    );
    defer if (interpreter) |value| value.close(init.io);
    const azure = try custody.Reference.tool(init.io, programs.azure);
    defer azure.close(init.io);
    const tool_references: [3]custody.Reference = .{ azure, azure, azure };
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    var budgets: runtime.Budgets = .{
        .execution = try core.process.Deadline.afterMilliseconds(30000),
        .expires_unix = std.math.maxInt(u64),
        .operation_ms = 30000,
        .cleanup_ms = 3000,
    };
    const adapter: runtime.Runtime = .{
        .allocator = init.gpa,
        .io = init.io,
        .programs = programs,
        .environment = &environment,
        .budgets = &budgets,
        .cancellation = &cancellation,
        .interpreter = interpreter,
        .tool_references = &tool_references,
        .azure_runtime = if (closure) |value| value.value.value else null,
    };
    try adapter.initialize();
    try local.verifyDirectory(init.io, directory, args[0]);
    try local.verifyLock(init.io, &writer);
    var status: Status = .{};
    check(adapter, &writer, azure, &status) catch |err| {
        const code = status.exit(err, &cancellation);
        var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
        status.report(&stderr.interface, err, code) catch {};
        return code;
    };
    try local.verifyDirectory(init.io, directory, args[0]);
    try local.verifyLock(init.io, &writer);
    var out = std.Io.File.stdout().writerStreaming(init.io, &.{});
    try out.interface.writeAll("Local CLI startup passed; authority=not_admitted; no reservations or Azure resource calls.\n");
    return 0;
}

pub fn report(init: std.process.Init, err: anyerror) void {
    var out = std.Io.File.stderr().writerStreaming(init.io, &.{});
    out.interface.print("direct refused: phase=pre-admission reason={s}; attempt records may not exist\n", .{@errorName(err)}) catch {};
}
