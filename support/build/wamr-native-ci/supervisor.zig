// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const build_options = @import("build_options");
const core = @import("hyperv_core");
const contracts = core.contracts;
const process = core.process;

const schema = "uk.wamr.command-supervisor-result";
const version = 1;
const version_text = "uk.wamr.command-supervisor/1 process-command/1\n";
const max_request_bytes = 1024 * 1024;
const max_capture_bytes = 4 * 1024 * 1024;
const max_string_bytes = 4096;
const retained_executable_environment = "WAMR_CI_RETAINED_EXECUTABLE";
const executable_path_environment = "WAMR_CI_EXECUTABLE_PATH";
const launch_executable_environment = "WAMR_CI_LAUNCH_EXECUTABLE";
const output_commitment_domain = "uk.wamr.command-output-v1\x00";

const Environment = struct {
    name: []const u8,
    value: []const u8,
};

const RetainedRequest = struct {
    name: []const u8,
    path: []const u8,
};

const Limits = struct {
    stdout_bytes: usize,
    stderr_bytes: usize,
    descendants: u16 = 64,
    primary_events: u32 = 1_000_000,
    cleanup_events: u32 = 1_000_000,
    proc_entries_per_scan: u32 = 262_144,
    reap_events: u16 = 512,
    term_grace_ms: u32 = 1000,
};

const Request = struct {
    schema: []const u8,
    version: u8,
    executable: []const u8,
    argv: []const []const u8,
    environment: []const Environment,
    retained_executables: []const RetainedRequest,
    cwd: []const u8,
    primary_deadline_ns: u64,
    cleanup_deadline_ns: u64,
    limits: Limits,
};

const Primary = struct {
    code: ?u32 = null,
    kind: []const u8,
};

const Termination = struct {
    code: ?u32 = null,
    kind: ?[]const u8 = null,
};

const ExecutableIdentity = struct {
    content_sha256: []const u8,
    ctime_nanoseconds: u32,
    ctime_seconds: i64,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mode: u16,
    mtime_nanoseconds: u32,
    mtime_seconds: i64,
    size: u64,
    uid: u32,
};

const Descendants = struct {
    adopted: u16,
    identity_validated: u16,
    limit_exceeded: bool,
    observed: u16,
    untracked: bool,
};

const RetainedIdentity = struct {
    identity: ExecutableIdentity,
    name: []const u8,
    path: []const u8,
};

const Command = struct {
    cancellation_observed: bool,
    cleanup: []const u8,
    cleanup_complete: bool,
    cleanup_events: u32,
    completed_ns: u64,
    descendants: Descendants,
    executable: ExecutableIdentity,
    executable_stable: bool,
    output_sha256: []const u8,
    poisoned: bool,
    primary: Primary,
    primary_completed_ns: u64,
    primary_deadline_reached: bool,
    primary_events: u32,
    reap_events: u16,
    retained_executables: []const RetainedIdentity,
    started_ns: u64,
    stderr_base64: []const u8,
    stderr_bytes: u64,
    stderr_sha256: []const u8,
    stderr_status: []const u8,
    stdout_base64: []const u8,
    stdout_bytes: u64,
    stdout_sha256: []const u8,
    stdout_status: []const u8,
    termination: Termination,
};

const Envelope = struct {
    command: ?Command = null,
    controller_error: ?[]const u8 = null,
    request_bytes: ?u64 = null,
    request_sha256: ?[]const u8 = null,
    schema: []const u8 = schema,
    version: u8 = version,
};

pub fn main(init: std.process.Init) void {
    run(init) catch {
        var writer = std.Io.File.stderr().writer(init.io, &.{});
        writer.interface.writeAll("command_supervisor_internal_error\n") catch {};
        std.process.exit(3);
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len >= 3 and std.mem.eql(u8, args[1], "--launch-retained"))
        return launchRetained(init, allocator, args[2..]);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--version")) {
        var writer = std.Io.File.stdout().writer(init.io, &.{});
        try writer.interface.writeAll(version_text);
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--identity")) {
        var writer = std.Io.File.stdout().writer(init.io, &.{});
        try writer.interface.print(
            "{{\"protocol\":\"uk.wamr.command-supervisor/1 process-command/1\"," ++
                "\"schema\":\"uk.wamr.command-supervisor-identity\"," ++
                "\"source_content_closure_sha256\":\"{s}\",\"version\":1}}\n",
            .{build_options.source_closure_sha256},
        );
        return;
    }
    if (args.len != 1) {
        try emit(init, .{ .controller_error = "invalid_invocation" });
        return;
    }

    const raw = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        "/proc/self/fd/0",
        allocator,
        .limited(max_request_bytes),
    ) catch {
        try emit(init, .{ .controller_error = "invalid_request" });
        return;
    };
    var document = contracts.Document.parse(allocator, raw, .{
        .bytes = max_request_bytes,
        .depth = 12,
        .string_bytes = max_string_bytes,
        .items = 4096,
        .tokens = 16384,
    }) catch {
        try emit(init, .{ .controller_error = "invalid_request" });
        return;
    };
    defer document.deinit();
    document.requireCanonical(allocator, raw) catch {
        try emit(init, .{ .controller_error = "noncanonical_request" });
        return;
    };
    const parsed = std.json.parseFromSlice(Request, allocator, raw, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch {
        try emit(init, .{ .controller_error = "invalid_request" });
        return;
    };
    defer parsed.deinit();
    const request = parsed.value;
    validateRequest(request) catch {
        try emit(init, .{ .controller_error = "invalid_request" });
        return;
    };

    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    for (request.environment) |entry| environment.put(entry.name, entry.value) catch {
        try emitBound(init, raw, .{ .controller_error = "local_io" });
        return;
    };
    const retained = allocator.alloc(process.Executable, request.retained_executables.len) catch {
        try emitBound(init, raw, .{ .controller_error = "local_io" });
        return;
    };
    var retained_count: usize = 0;
    defer for (retained[0..retained_count]) |opened| opened.close(init.io);
    for (request.retained_executables, 0..) |entry, index| {
        const original = environment.get(entry.name) orelse {
            try emitBound(init, raw, .{ .controller_error = "invalid_request" });
            return;
        };
        if (!std.mem.eql(u8, original, entry.path)) {
            try emitBound(init, raw, .{ .controller_error = "invalid_request" });
            return;
        }
        retained[index] = process.Executable.open(init.io, entry.path) catch |err| {
            try emitBound(init, raw, .{ .controller_error = executableError(err) });
            return;
        };
        retained_count += 1;
        const retained_path = std.fmt.allocPrint(
            allocator,
            "/proc/{d}/fd/{d}",
            .{ std.os.linux.getpid(), retained[index].file.handle },
        ) catch {
            try emitBound(init, raw, .{ .controller_error = "local_io" });
            return;
        };
        environment.put(entry.name, retained_path) catch {
            try emitBound(init, raw, .{ .controller_error = "local_io" });
            return;
        };
    }
    var cwd = std.Io.Dir.cwd().openDir(init.io, request.cwd, .{
        .follow_symlinks = false,
    }) catch {
        try emitBound(init, raw, .{ .controller_error = "cwd_unavailable" });
        return;
    };
    defer cwd.close(init.io);
    var executable = process.Executable.open(init.io, request.executable) catch |err| {
        try emitBound(init, raw, .{ .controller_error = executableError(err) });
        return;
    };
    defer executable.close(init.io);
    const executable_path = std.fmt.allocPrint(
        allocator,
        "/proc/{d}/fd/{d}",
        .{ std.os.linux.getpid(), executable.file.handle },
    ) catch {
        try emitBound(init, raw, .{ .controller_error = "local_io" });
        return;
    };
    environment.put(
        retained_executable_environment,
        executable_path,
    ) catch {
        try emitBound(init, raw, .{ .controller_error = "local_io" });
        return;
    };
    environment.put(
        executable_path_environment,
        request.executable,
    ) catch {
        try emitBound(init, raw, .{ .controller_error = "local_io" });
        return;
    };
    process.initialize() catch {
        try emitBound(init, raw, .{ .controller_error = "supervisor_unavailable" });
        return;
    };
    var result = process.runCommand(allocator, init.io, .{
        .executable = executable,
        .argv = request.argv,
        .environment = &environment,
        .cwd = cwd,
        .primary_deadline = .{ .expires_ns = request.primary_deadline_ns },
        .cleanup_deadline = .{ .expires_ns = request.cleanup_deadline_ns },
        .limits = .{
            .stdout_bytes = request.limits.stdout_bytes,
            .stderr_bytes = request.limits.stderr_bytes,
            .descendants = request.limits.descendants,
            .primary_events = request.limits.primary_events,
            .cleanup_events = request.limits.cleanup_events,
            .proc_entries_per_scan = request.limits.proc_entries_per_scan,
            .reap_events = request.limits.reap_events,
            .term_grace_ms = request.limits.term_grace_ms,
        },
    }) catch {
        try emitBound(init, raw, .{ .controller_error = "supervisor_unavailable" });
        return;
    };
    defer result.deinit(allocator);

    const stdout_encoded = try allocator.alloc(u8, base64Size(result.stdout.len));
    _ = std.base64.standard.Encoder.encode(stdout_encoded, result.stdout);
    const stderr_encoded = try allocator.alloc(u8, base64Size(result.stderr.len));
    _ = std.base64.standard.Encoder.encode(stderr_encoded, result.stderr);
    const stdout_digest = sha256Digest(result.stdout);
    const stdout_sha256 = std.fmt.bytesToHex(stdout_digest, .lower);
    const stderr_digest = sha256Digest(result.stderr);
    const stderr_sha256 = std.fmt.bytesToHex(stderr_digest, .lower);
    const output_sha256 = std.fmt.bytesToHex(outputCommitment(
        result.stdout.len,
        stdout_digest,
        result.stderr.len,
        stderr_digest,
    ), .lower);
    const content_sha256 = std.fmt.bytesToHex(result.executable.content_sha256, .lower);
    const retained_result = try allocator.alloc(
        RetainedIdentity,
        request.retained_executables.len,
    );
    for (request.retained_executables, retained, retained_result) |entry, opened, *item| {
        const digest = try allocator.dupe(
            u8,
            &std.fmt.bytesToHex(opened.identity.content_sha256, .lower),
        );
        item.* = .{
            .identity = executableIdentity(opened.identity, digest),
            .name = entry.name,
            .path = entry.path,
        };
    }
    try emitBound(init, raw, .{ .command = .{
        .cancellation_observed = result.cancellation_observed,
        .cleanup = @tagName(result.cleanup),
        .cleanup_complete = result.cleanup_complete,
        .cleanup_events = result.cleanup_events,
        .completed_ns = result.completed_ns,
        .descendants = .{
            .adopted = result.descendants.adopted,
            .identity_validated = result.descendants.identity_validated,
            .limit_exceeded = result.descendants.limit_exceeded,
            .observed = result.descendants.observed,
            .untracked = result.descendants.untracked,
        },
        .executable = executableIdentity(result.executable, &content_sha256),
        .executable_stable = result.executable_stable,
        .output_sha256 = &output_sha256,
        .poisoned = !result.cleanup_complete,
        .primary = primary(result.primary),
        .primary_completed_ns = result.primary_completed_ns,
        .primary_deadline_reached = result.primary_deadline_reached,
        .primary_events = result.primary_events,
        .reap_events = result.reap_events,
        .retained_executables = retained_result,
        .started_ns = result.started_ns,
        .stderr_base64 = stderr_encoded,
        .stderr_bytes = @intCast(result.stderr.len),
        .stderr_sha256 = &stderr_sha256,
        .stderr_status = @tagName(result.stderr_status),
        .stdout_base64 = stdout_encoded,
        .stdout_bytes = @intCast(result.stdout.len),
        .stdout_sha256 = &stdout_sha256,
        .stdout_status = @tagName(result.stdout_status),
        .termination = termination(result.termination),
    } });
}

fn launchRetained(
    init: std.process.Init,
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !void {
    const path = init.environ_map.get(launch_executable_environment) orelse
        return error.InvalidLaunch;
    const prefix = try std.fmt.allocPrint(
        allocator,
        "/proc/{d}/fd/",
        .{std.os.linux.getppid()},
    );
    if (!std.mem.startsWith(u8, path, prefix) or path.len == prefix.len)
        return error.InvalidLaunch;
    for (path[prefix.len..]) |byte| if (!std.ascii.isDigit(byte))
        return error.InvalidLaunch;
    const path_z = try allocator.dupeZ(u8, path);
    const opened = std.os.linux.openat(
        std.os.linux.AT.FDCWD,
        path_z,
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    );
    if (std.os.linux.errno(opened) != .SUCCESS) return error.InvalidLaunch;
    const descriptor: std.os.linux.fd_t = @intCast(opened);
    defer _ = std.os.linux.close(descriptor);

    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    var entries = init.environ_map.iterator();
    while (entries.next()) |entry| {
        const name = entry.key_ptr.*;
        if (std.mem.eql(u8, name, launch_executable_environment) or
            std.mem.eql(u8, name, retained_executable_environment) or
            std.mem.eql(u8, name, executable_path_environment))
            continue;
        try environment.put(name, entry.value_ptr.*);
    }
    const block = try environment.createPosixBlock(
        allocator,
        .{ .zig_progress_fd = -1 },
    );
    const pointers = try allocator.allocSentinel(
        ?[*:0]const u8,
        args.len,
        null,
    );
    for (args, 0..) |argument, index|
        pointers[index] = (try allocator.dupeZ(u8, argument)).ptr;
    _ = std.os.linux.execveat(
        descriptor,
        "",
        pointers.ptr,
        block.slice.ptr,
        .{ .EMPTY_PATH = true, .SYMLINK_NOFOLLOW = true },
    );
    return error.LaunchUnavailable;
}

fn validateRequest(request: Request) !void {
    if (!std.mem.eql(u8, request.schema, "uk.wamr.command-supervisor-request") or
        request.version != version or request.executable.len == 0 or
        request.executable.len > max_string_bytes or
        request.executable[0] != '/' or request.cwd.len == 0 or request.cwd[0] != '/' or
        request.cwd.len > max_string_bytes or
        request.argv.len == 0 or request.argv.len > 4096 or
        !std.mem.eql(u8, request.argv[0], request.executable) or
        request.environment.len > 512 or
        request.retained_executables.len > 128 or
        request.primary_deadline_ns == 0 or
        request.cleanup_deadline_ns <= request.primary_deadline_ns or
        request.limits.stdout_bytes == 0 or
        request.limits.stdout_bytes > max_capture_bytes or
        request.limits.stderr_bytes == 0 or
        request.limits.stderr_bytes > max_capture_bytes or
        request.limits.descendants == 0 or request.limits.descendants > 256 or
        request.limits.primary_events < 16 or request.limits.primary_events > 10_000_000 or
        request.limits.cleanup_events < 32 or request.limits.cleanup_events > 10_000_000 or
        request.limits.proc_entries_per_scan < 16 or
        request.limits.proc_entries_per_scan > 1_000_000 or
        request.limits.reap_events < request.limits.descendants + 3 or
        request.limits.reap_events > 1024 or
        request.limits.term_grace_ms == 0 or request.limits.term_grace_ms > 10_000)
        return error.InvalidRequest;
    for (request.argv) |argument| {
        if (argument.len > max_string_bytes or
            std.mem.indexOfScalar(u8, argument, 0) != null)
            return error.InvalidRequest;
    }
    var previous: ?[]const u8 = null;
    for (request.environment) |entry| {
        if (entry.name.len == 0 or entry.name.len > max_string_bytes or
            entry.value.len > max_string_bytes or
            std.mem.indexOfScalar(u8, entry.name, '=') != null or
            std.mem.indexOfScalar(u8, entry.name, 0) != null or
            std.mem.indexOfScalar(u8, entry.value, 0) != null or
            std.mem.eql(u8, entry.name, retained_executable_environment) or
            std.mem.eql(u8, entry.name, executable_path_environment))
            return error.InvalidRequest;
        if (previous) |name| if (std.mem.order(u8, name, entry.name) != .lt)
            return error.InvalidRequest;
        previous = entry.name;
    }
    previous = null;
    for (request.retained_executables) |entry| {
        if (entry.name.len == 0 or entry.name.len > max_string_bytes or
            entry.path.len == 0 or entry.path.len > max_string_bytes or
            entry.path[0] != '/' or
            std.mem.indexOfAny(u8, entry.name, "=\x00") != null or
            std.mem.indexOfScalar(u8, entry.path, 0) != null)
            return error.InvalidRequest;
        if (previous) |name| if (std.mem.order(u8, name, entry.name) != .lt)
            return error.InvalidRequest;
        previous = entry.name;
    }
    for (request.retained_executables) |entry| {
        var found = false;
        for (request.environment) |environment| {
            if (!std.mem.eql(u8, entry.name, environment.name)) continue;
            if (!std.mem.eql(u8, entry.path, environment.value))
                return error.InvalidRequest;
            found = true;
            break;
        }
        if (!found) return error.InvalidRequest;
    }
}

fn executableError(err: anyerror) []const u8 {
    return switch (err) {
        error.ExecutableUnavailable => "exec_unavailable",
        error.InvalidExecutable => "exec_invalid",
        error.UnsupportedExecutableFormat => "exec_unsupported",
        error.ExecutableIdentityChanged => "exec_changed",
        else => "local_io",
    };
}

fn executableIdentity(
    value: process.ExecutableIdentity,
    content_sha256: []const u8,
) ExecutableIdentity {
    return .{
        .content_sha256 = content_sha256,
        .ctime_nanoseconds = value.ctime_nanoseconds,
        .ctime_seconds = value.ctime_seconds,
        .device_major = value.device_major,
        .device_minor = value.device_minor,
        .inode = value.inode,
        .mode = value.mode,
        .mtime_nanoseconds = value.mtime_nanoseconds,
        .mtime_seconds = value.mtime_seconds,
        .size = value.size,
        .uid = value.uid,
    };
}

fn primary(value: process.CommandPrimary) Primary {
    return switch (value) {
        .exited => |code| .{ .kind = "exited", .code = code },
        .signal => |signal| .{ .kind = "signal", .code = @intFromEnum(signal) },
        .unknown => |status| .{ .kind = "unknown", .code = status },
        inline else => |_, tag| .{ .kind = @tagName(tag) },
    };
}

fn termination(value: ?std.process.Child.Term) Termination {
    return if (value) |term| switch (term) {
        .exited => |code| .{ .kind = "exited", .code = code },
        .signal => |signal| .{ .kind = "signal", .code = @intFromEnum(signal) },
        .stopped => |signal| .{ .kind = "stopped", .code = @intFromEnum(signal) },
        .unknown => |status| .{ .kind = "unknown", .code = status },
    } else .{};
}

fn base64Size(length: usize) usize {
    return ((length + 2) / 3) * 4;
}

fn sha256Digest(value: []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var result: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &result, .{});
    return result;
}

fn outputCommitment(
    stdout_bytes: usize,
    stdout_sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    stderr_bytes: usize,
    stderr_sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,
) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(output_commitment_domain);
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(stdout_bytes), .big);
    hash.update(&encoded);
    hash.update(&stdout_sha256);
    std.mem.writeInt(u64, &encoded, @intCast(stderr_bytes), .big);
    hash.update(&encoded);
    hash.update(&stderr_sha256);
    var result: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hash.final(&result);
    return result;
}

fn emitBound(init: std.process.Init, raw: []const u8, envelope: Envelope) !void {
    const request_sha256 = std.fmt.bytesToHex(sha256Digest(raw), .lower);
    var bound = envelope;
    bound.request_bytes = @intCast(raw.len);
    bound.request_sha256 = &request_sha256;
    try emit(init, bound);
}

fn emit(init: std.process.Init, envelope: Envelope) !void {
    const allocator = init.arena.allocator();
    const encoded = try std.json.Stringify.valueAlloc(allocator, envelope, .{});
    var writer = std.Io.File.stdout().writer(init.io, &.{});
    try writer.interface.writeAll(encoded);
    try writer.interface.writeByte('\n');
}
