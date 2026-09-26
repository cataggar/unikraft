// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const process = core.process;
const Sha256 = core.Sha256;
const linux = std.os.linux;
const plan = @import("command_plan.zig");
const records = @import("records.zig");

const Value = std.json.Value;
const Allocator = std.mem.Allocator;
pub const transport_result_max_bytes = 12 * 1024 * 1024;

pub const Outcome = struct {
    accepted: bool,
    poisoned: bool,
    primary: process.CommandPrimary,
    bytes: usize,
    stdout: []const u8 = &.{},
    stderr_bytes: usize = 0,
};

pub const Request = struct {
    roots: plan.Roots,
    stage: plan.Stage,
    private_dir: std.Io.Dir,
    evidence_dir: std.Io.Dir,
    cancel: ?*const std.atomic.Value(bool) = null,
    test_seconds: ?u32 = null,
    test_output_limit: ?usize = null,
    test_replacement: ?[]const u8 = null,
    capture_stdout: bool = false,
    private_record: bool = false,
};

fn json(allocator: Allocator, value: anytype) !Value {
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    const parsed = try std.json.parseFromSlice(Value, allocator, raw, .{ .allocate = .alloc_always });
    return parsed.value;
}

fn object() Value {
    return .{ .object = .empty };
}

fn put(allocator: Allocator, value: *Value, name: []const u8, member: Value) !void {
    try value.object.put(allocator, name, member);
}

fn array(allocator: Allocator, values: []const Value) !Value {
    var result = Value{ .array = std.array_list.Managed(Value).init(allocator) };
    try result.array.appendSlice(values);
    return result;
}

fn binding(allocator: Allocator, item: plan.Binding) !Value {
    return switch (item) {
        .literal => |literal| json(allocator, .{ .kind = "literal", .value = literal }),
        .path => |path| json(allocator, .{
            .kind = "path",
            .role = path.role,
            .relative = path.relative,
        }),
    };
}

fn identity(allocator: Allocator, source: process.ExecutableIdentity) !Value {
    const sha256 = std.fmt.bytesToHex(source.content_sha256, .lower);
    return json(allocator, .{
        .device_major = source.device_major,
        .device_minor = source.device_minor,
        .inode = source.inode,
        .size = source.size,
        .mode = source.mode,
        .uid = source.uid,
        .mtime_seconds = source.mtime_seconds,
        .mtime_nanoseconds = source.mtime_nanoseconds,
        .ctime_seconds = source.ctime_seconds,
        .ctime_nanoseconds = source.ctime_nanoseconds,
        .content_sha256 = sha256[0..],
    });
}

fn identified(allocator: Allocator, role: []const u8, executable: process.ExecutableIdentity) !Value {
    var result = object();
    try put(allocator, &result, "path", try binding(allocator, .{ .path = .{ .role = role } }));
    try put(allocator, &result, "identity", try identity(allocator, executable));
    return result;
}

fn canonical(allocator: Allocator, value: Value) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    return records.canonicalAlloc(allocator, raw);
}

/// The native result contains base64 for both independent 4 MiB streams;
/// public evidence still uses the ordinary 4 MiB record encoder.
pub fn canonicalTransport(allocator: Allocator, value: Value) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try core.contracts.writeCanonical(allocator, value, &writer.writer);
    try writer.writer.writeByte('\n');
    const encoded = try writer.toOwnedSlice();
    if (encoded.len > transport_result_max_bytes) {
        allocator.free(encoded);
        return error.CommandResultTooLarge;
    }
    return encoded;
}

fn hash(allocator: Allocator, value: Value) !Value {
    const encoded = try canonical(allocator, value);
    const digest = records.fileIdentity(encoded);
    return json(allocator, std.fmt.bytesToHex(digest, .lower));
}

fn bytesDigest(allocator: Allocator, bytes: []const u8) !Value {
    return json(allocator, std.fmt.bytesToHex(records.fileIdentity(bytes), .lower));
}

fn stream(allocator: Allocator, bytes: []const u8, status: process.CommandStreamStatus) !Value {
    return json(allocator, .{
        .bytes = bytes.len,
        .sha256 = std.fmt.bytesToHex(records.fileIdentity(bytes), .lower),
        .digest_scope = if (bytes.len == 0) "reproducible_empty" else "transport_authenticated_observation",
        .status = @tagName(status),
    });
}

fn kind(allocator: Allocator, primary: process.CommandPrimary) !Value {
    return switch (primary) {
        .exited => |code| json(allocator, .{ .kind = "exited", .code = @as(?u32, code) }),
        .signal => |signal| json(allocator, .{ .kind = "signal", .code = @as(?u32, @intFromEnum(signal)) }),
        .unknown => |code| json(allocator, .{ .kind = "unknown", .code = @as(?u32, code) }),
        else => json(allocator, .{ .kind = @tagName(primary), .code = @as(?u32, null) }),
    };
}

fn termination(allocator: Allocator, value: ?std.process.Child.Term) !Value {
    const item = value orelse return json(allocator, .{ .kind = @as(?[]const u8, null), .code = @as(?u32, null) });
    return switch (item) {
        .exited => |code| json(allocator, .{ .kind = "exited", .code = @as(?u32, code) }),
        .signal => |signal| json(allocator, .{ .kind = "signal", .code = @as(?u32, @intFromEnum(signal)) }),
        .stopped => |signal| json(allocator, .{ .kind = "stopped", .code = @as(?u32, @intFromEnum(signal)) }),
        .unknown => |code| json(allocator, .{ .kind = "unknown", .code = @as(?u32, code) }),
    };
}

fn commitment(stdout: []const u8, stderr: []const u8) [64]u8 {
    var state = Sha256.init(.{});
    state.update("uk.wamr.command-output-v1\x00");
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, stdout.len, .big);
    state.update(&length);
    const stdout_hash = records.fileIdentity(stdout);
    state.update(&stdout_hash);
    std.mem.writeInt(u64, &length, stderr.len, .big);
    state.update(&length);
    const stderr_hash = records.fileIdentity(stderr);
    state.update(&stderr_hash);
    return std.fmt.bytesToHex(state.finalResult(), .lower);
}

pub fn markers(allocator: Allocator, bytes: []const u8) !Value {
    const allowlist = [_][]const u8{
        "AccessDenied",              "BrokenPipe",                   "FileNotFound",          "FileTooBig",                        "InputOutput",
        "InvalidEnumTag",            "InvalidNativeMakeEnvironment", "InvalidNativeMakePath", "InvalidPath",                       "MissingField",
        "ModuleNotFound",            "NameTooLong",                  "NoSpaceLeft",           "NoncanonicalNativeMakeEnvironment", "NotDir",
        "OutOfMemory",               "PathAlreadyExists",            "PermissionDenied",      "ReadOnlyFileSystem",                "SystemResources",
        "TooManySymbolicLinkLevels", "UnexpectedToken",              "UnsafeFile",            "UnsafeNativeMakeTool",              "UnsupportedNativeMakeHost",
        "UnsupportedTarget",
    };
    var result: std.ArrayList(Value) = .empty;
    for (allowlist) |word| {
        var index: usize = 0;
        while (std.mem.indexOfPos(u8, bytes, index, word)) |at| {
            const before_ok = at == 0 or !wordByte(bytes[at - 1]);
            const end = at + word.len;
            if (before_ok and (end == bytes.len or !wordByte(bytes[end]))) {
                try result.append(allocator, try json(allocator, word));
                break;
            }
            index = end;
        }
    }
    return array(allocator, result.items);
}

fn wordByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

fn create(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

pub fn openPinnedTool(io: std.Io, path: []const u8, role: []const u8) !files.RetainedFile {
    const large_roles = [_][]const u8{
        "tool:zig",        "tool:llvm-nm",      "tool:llvm-objcopy",
        "tool:llvm-objdump", "tool:llvm-readelf", "tool:llvm-strip",
    };
    var large = false;
    for (large_roles) |name| if (std.mem.eql(u8, name, role)) {
        large = true;
        break;
    };
    if (!large)
        return files.RetainedFile.open(io, path, .tool);
    var retained = try files.RetainedFile.open(io, path, .artifact);
    errdefer retained.close(io);
    const value = retained.file_snapshot;
    if (value.mode & linux.S.IFMT != linux.S.IFREG or
        (value.uid != 0 and value.uid != linux.geteuid()) or value.mode & 0o111 == 0 or
        value.mode & 0o6022 != 0 or value.nlink != 1 or
        value.size == 0 or value.size > 256 * 1024 * 1024)
        return error.UnsafeFile;
    return retained;
}

/// The public command record is constructed from the direct shared supervisor
/// result, not from child-controlled text or a subprocess protocol response.
pub fn execute(allocator: Allocator, io: std.Io, request: Request) !Outcome {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var selected = plan.spec(request.stage);
    if (request.test_seconds != null or request.test_output_limit != null or request.test_replacement != null) {
        if (!builtin.is_test) return error.TestOnlyOverride;
        selected.seconds = request.test_seconds orelse selected.seconds;
        selected.output_limit = request.test_output_limit orelse selected.output_limit;
        if (selected.seconds == 0 or selected.output_limit > 8 * 1024 * 1024)
            return error.InvalidTestBound;
    }
    const env_bindings = try plan.environment(a, request.stage);
    const executable_path = try request.roots.get(selected.executable);
    var pinned = try openPinnedTool(io, executable_path, selected.executable);
    defer pinned.close(io);
    var executable = try process.Executable.fromFile(io, pinned.file);
    defer executable.close(io);
    var supervisor = try files.RetainedFile.open(io, request.roots.supervisor, .tool);
    defer supervisor.close(io);
    var controller_executable = try process.Executable.fromFile(io, supervisor.file);
    defer controller_executable.close(io);

    const cwd = try files.openDirectory(io, request.roots.source_root, .artifact);
    defer cwd.close(io);
    var env = std.process.Environ.Map.init(a);
    defer env.deinit();
    var env_public: std.ArrayList(Value) = .empty;
    var env_native: std.ArrayList(Value) = .empty;
    var retained_public: std.ArrayList(Value) = .empty;
    var retained_native: std.ArrayList(Value) = .empty;
    const Retained = struct {
        path: []const u8,
        file: files.RetainedFile,
        identity: process.ExecutableIdentity,
    };
    var pinned_environment: std.ArrayList(Retained) = .empty;
    defer for (pinned_environment.items) |*item| item.file.close(io);
    for (env_bindings) |entry| {
        const resolved = try plan.path(a, entry.value, request.roots);
        try env.put(entry.name, resolved);
        try env_public.append(a, try json(a, .{ .name = entry.name, .value = try binding(a, entry.value) }));
        try env_native.append(a, try json(a, .{ .name = entry.name, .value = resolved }));
        if (entry.value != .path) continue;
        if (!(std.mem.eql(u8, entry.name, "M4") or
            std.mem.eql(u8, entry.name, "WAMR_CI_GIT") or
            std.mem.eql(u8, entry.name, "WAMR_CI_SUPERVISOR") or
            std.mem.eql(u8, entry.name, "WAMR_CI_LAUNCH_EXECUTABLE") or
            std.mem.eql(u8, entry.name, "WAMR_CI_PYTHON") or
            std.mem.startsWith(u8, entry.name, "WAMR_CI_TOOL_") or
            std.mem.eql(u8, entry.name, "WAMR_CI_LOG_VALIDATE"))) continue;
        var file = try openPinnedTool(io, resolved, entry.value.path.role);
        errdefer file.close(io);
        if (file.file_snapshot.mode & 0o111 == 0) {
            file.close(io);
            continue;
        }
        var retained = try process.Executable.fromFile(io, file.file);
        defer retained.close(io);
        const item = try json(a, .{
            .name = entry.name,
            .path = try binding(a, entry.value),
            .identity = try identity(a, retained.identity),
        });
        try retained_public.append(a, item);
        try retained_native.append(a, try json(a, .{
            .name = entry.name,
            .path = resolved,
            .identity = try identity(a, retained.identity),
        }));
        try pinned_environment.append(a, .{ .path = resolved, .file = file, .identity = retained.identity });
    }
    var argv_abs: std.ArrayList([]const u8) = .empty;
    var argv_public: std.ArrayList(Value) = .empty;
    var argv_native: std.ArrayList(Value) = .empty;
    for (selected.argv) |entry| {
        const resolved = try plan.path(a, entry, request.roots);
        try argv_abs.append(a, resolved);
        try argv_public.append(a, try binding(a, entry));
        try argv_native.append(a, try json(a, resolved));
    }
    const issued = try process.monotonicNanoseconds();
    const timeout = @as(u64, selected.seconds) * std.time.ns_per_s;
    const primary: process.Deadline = .{ .expires_ns = try std.math.add(u64, issued, timeout) };
    const cleanup: process.Deadline = .{ .expires_ns = try std.math.add(u64, primary.expires_ns, 10 * std.time.ns_per_s) };
    const limits = plan.limits(selected);
    const limits_public = try json(a, limits);
    const native_request = try json(a, .{
        .schema = "uk.wamr.command-supervisor-request",
        .version = 1,
        .executable = executable_path,
        .argv = try array(a, argv_native.items),
        .environment = try array(a, env_native.items),
        .cwd = request.roots.source_root,
        .retained_executables = try array(a, retained_native.items),
        .primary_deadline_ns = primary.expires_ns,
        .cleanup_deadline_ns = cleanup.expires_ns,
        .limits = limits_public,
    });
    const request_bytes = try canonical(a, native_request);
    if (request_bytes.len > 1024 * 1024) return error.CommandRequestTooLarge;

    try process.initialize();
    var result = try process.runCommand(allocator, io, .{
        .executable = executable,
        .argv = argv_abs.items,
        .environment = &env,
        .cwd = cwd,
        .primary_deadline = primary,
        .cleanup_deadline = cleanup,
        .cancel = request.cancel,
        .snapshot_executable = false,
        .limits = limits,
    });
    defer result.deinit(allocator);
    if (request.test_replacement) |replacement| {
        if (!builtin.is_test) return error.TestOnlyOverride;
        try std.Io.Dir.renameAbsolute(replacement, executable_path, io);
    }
    const stable = blk: {
        pinned.verify(io) catch break :blk false;
        supervisor.verify(io) catch break :blk false;
        var after = process.Executable.open(io, executable_path) catch break :blk false;
        defer after.close(io);
        if (!std.meta.eql(executable.identity, after.identity)) break :blk false;
        for (pinned_environment.items) |item| {
            item.file.verify(io) catch break :blk false;
            var fresh = process.Executable.open(io, item.path) catch break :blk false;
            defer fresh.close(io);
            if (!std.meta.eql(item.identity, fresh.identity)) break :blk false;
        }
        break :blk true;
    };
    if (!stable) {
        result.executable_stable = false;
        if (result.succeeded() or result.primary == .exited)
            result.primary = .executable_changed;
    }
    const combined = try std.mem.concat(a, u8, &.{ result.stdout, result.stderr });
    const capped = combined[0..@min(combined.len, selected.output_limit + 1)];
    const log_name = try std.fmt.allocPrint(a, "{s}.log", .{@tagName(request.stage)});
    try create(io, request.private_dir, log_name, capped);

    const primary_value = try kind(a, result.primary);
    const termination_value = try termination(a, result.termination);
    const stdout_hash = try bytesDigest(a, result.stdout);
    const stderr_hash = try bytesDigest(a, result.stderr);
    const output_sha = commitment(result.stdout, result.stderr);
    if (result.stdout.len > 4 * 1024 * 1024 or result.stderr.len > 4 * 1024 * 1024 or
        std.base64.standard.Encoder.calcSize(result.stdout.len) +
            std.base64.standard.Encoder.calcSize(result.stderr.len) >= transport_result_max_bytes)
        return error.CommandResultTooLarge;
    const native_command = try json(a, .{
        .started_ns = result.started_ns,
        .primary_completed_ns = result.primary_completed_ns,
        .completed_ns = result.completed_ns,
        .executable = try identity(a, result.executable),
        .executable_stable = result.executable_stable,
        .primary = primary_value,
        .termination = termination_value,
        .primary_deadline_reached = result.primary_deadline_reached,
        .cancellation_observed = result.cancellation_observed,
        .stdout_bytes = result.stdout.len,
        .stderr_bytes = result.stderr.len,
        .stdout_sha256 = stdout_hash,
        .stderr_sha256 = stderr_hash,
        .output_sha256 = output_sha,
        .stdout_status = @tagName(result.stdout_status),
        .stderr_status = @tagName(result.stderr_status),
        .stdout_base64 = try base64(a, result.stdout),
        .stderr_base64 = try base64(a, result.stderr),
        .descendants = result.descendants,
        .cleanup = @tagName(result.cleanup),
        .cleanup_complete = result.cleanup_complete,
        .poisoned = !result.cleanup_complete,
        .primary_events = result.primary_events,
        .cleanup_events = result.cleanup_events,
        .reap_events = result.reap_events,
        .retained_executables = try array(a, retained_native.items),
    });
    const native_result = try json(a, .{
        .schema = "uk.wamr.command-supervisor-result",
        .version = 1,
        .request_bytes = request_bytes.len,
        .request_sha256 = try bytesDigest(a, request_bytes),
        .controller_error = @as(?[]const u8, null),
        .command = native_command,
    });
    const result_bytes = try canonicalTransport(a, native_result);
    const public_request = try json(a, .{
        .schema = "uk.wamr.command-supervisor-request",
        .version = 1,
        .binding_schema = "uk.wamr.supervised-command-binding",
        .binding_version = 1,
        .stage = @tagName(request.stage),
        .argv = try array(a, argv_public.items),
        .environment = try array(a, env_public.items),
        .cwd = try binding(a, .{ .path = .{ .role = "source" } }),
        .supervisor = try identified(a, "command-supervisor", controller_executable.identity),
        .native_executable = try identified(a, selected.executable, executable.identity),
        .command_executable = try identified(a, selected.executable, executable.identity),
        .interpreter = @as(?Value, null),
        .retained_executables = try array(a, retained_public.items),
        .issued_ns = issued,
        .primary_deadline_ns = primary.expires_ns,
        .cleanup_deadline_ns = cleanup.expires_ns,
        .timeout_ns = timeout,
        .limits = limits_public,
    });
    var request_binding = try json(a, public_request);
    try put(a, &request_binding, "canonical_sha256", try hash(a, public_request));
    try put(a, &request_binding, "argv_sha256", try hash(a, try array(a, argv_public.items)));
    try put(a, &request_binding, "environment_sha256", try hash(a, try array(a, env_public.items)));
    try put(a, &request_binding, "cwd_sha256", try hash(a, try binding(a, .{ .path = .{ .role = "source" } })));

    const output_hash = try bytesDigest(a, combined);
    const summary = try json(a, .{
        .cancellation_observed = result.cancellation_observed,
        .cleanup = @tagName(result.cleanup),
        .cleanup_complete = result.cleanup_complete,
        .cleanup_events = result.cleanup_events,
        .descendants = result.descendants,
        .executable = try identity(a, result.executable),
        .executable_stable = result.executable_stable,
        .poisoned = !result.cleanup_complete,
        .primary = primary_value,
        .primary_deadline_reached = result.primary_deadline_reached,
        .primary_events = result.primary_events,
        .reap_events = result.reap_events,
        .retained_executables = try array(a, retained_public.items),
        .stderr = try stream(a, result.stderr, result.stderr_status),
        .stdout = try stream(a, result.stdout, result.stdout_status),
        .output = .{
            .bytes = combined.len,
            .combined_sha256 = output_hash,
            .commitment_sha256 = output_sha,
            .digest_scope = if (combined.len == 0) "reproducible_empty" else "transport_authenticated_observation",
        },
        .timing = .{
            .started_ns = result.started_ns,
            .primary_completed_ns = result.primary_completed_ns,
            .completed_ns = result.completed_ns,
            .primary_elapsed_ns = result.primary_completed_ns - result.started_ns,
            .cleanup_elapsed_ns = result.completed_ns - result.primary_completed_ns,
            .total_elapsed_ns = result.completed_ns - result.started_ns,
        },
        .termination = termination_value,
    });
    const transport_scope = "direct_producer_or_trusted_inner_zip";
    const result_core = try json(a, .{
        .schema = "uk.wamr.command-supervisor-result",
        .version = 1,
        .request_canonical_sha256 = request_binding.object.get("canonical_sha256").?,
        .controller_error = @as(?[]const u8, null),
        .native_request = .{ .bytes = request_bytes.len, .sha256 = try bytesDigest(a, request_bytes), .digest_scope = transport_scope },
        .native_result = .{ .bytes = result_bytes.len, .sha256 = try bytesDigest(a, result_bytes), .digest_scope = transport_scope },
        .command = summary,
    });
    var public_result = try json(a, result_core);
    try put(a, &public_result, "canonical_sha256", try hash(a, result_core));
    const known_markers = try markers(a, capped);
    const command_record = try json(a, .{
        .scope = "command_diagnostic_not_acceptance",
        .stage = @tagName(request.stage),
        .exit_code = switch (result.primary) {
            .exited => |code| @as(i32, code),
            else => -1,
        },
        .bytes = capped.len,
        .sha256 = try bytesDigest(a, capped),
        .sha256_scope = if (capped.len == 0) "reproducible_empty" else "transport_authenticated_observation",
        .over_limit = combined.len > selected.output_limit,
        .known_error_markers = known_markers,
        .supervisor = .{
            .schema = "uk.wamr.command-supervisor-result",
            .version = 1,
            .bootstrap = false,
            .request = request_binding,
            .result = public_result,
        },
    });
    const record_name = try std.fmt.allocPrint(a, "command-{s}.json", .{@tagName(request.stage)});
    if (plan.isValidator(request.stage) != request.private_record)
        return error.InvalidCommandRecordLocation;
    try create(io, request.evidence_dir, record_name, try canonical(a, command_record));
    const accepted = result.succeeded() and stable and combined.len <= selected.output_limit and
        known_markers.array.items.len == 0 and
        (!plan.isValidator(request.stage) or result.stderr.len == 0) and
        (request.cancel == null or !request.cancel.?.load(.acquire));
    return .{
        .accepted = accepted,
        .poisoned = !result.cleanup_complete or !stable,
        .primary = result.primary,
        .bytes = capped.len,
        .stdout = if (request.capture_stdout) try allocator.dupe(u8, result.stdout) else &.{},
        .stderr_bytes = result.stderr.len,
    };
}

fn base64(allocator: Allocator, bytes: []const u8) ![]const u8 {
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    return std.base64.standard.Encoder.encode(encoded, bytes);
}
