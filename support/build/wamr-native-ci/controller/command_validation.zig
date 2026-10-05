// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const contracts = core.contracts;
const Sha256 = core.Sha256;
const plan = @import("command_plan.zig");
const records = @import("records.zig");

const handoff_controller_role = "native:handoff-inspect-controller";

pub const EvidenceContext = enum { local_runtime, trusted_inner_zip };
pub const ValidatedCommand = struct {
    stage: plan.Stage,
    output_bytes: u64,
    output_sha256: [64]u8,
};

fn get(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidCommand;
    return value.object.get(key) orelse error.InvalidCommand;
}

fn text(value: std.json.Value) ![]const u8 {
    return contracts.string(value);
}

fn num(comptime T: type, value: std.json.Value) !T {
    return contracts.integer(T, value) catch |err| switch (err) {
        error.IntegerOverflow => error.InvalidCommand,
        else => err,
    };
}

fn eq(a: []const u8, b: []const u8) !void {
    if (!std.mem.eql(u8, a, b)) return error.InvalidCommand;
}

fn yes(value: std.json.Value, expected: bool) !void {
    if (value != .bool or value.bool != expected) return error.InvalidCommand;
}

fn exact(value: std.json.Value, keys: []const []const u8) !void {
    _ = try contracts.exactFields(value, keys);
}

fn digest(a: std.mem.Allocator, value: std.json.Value) ![64]u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    const encoded = try records.canonicalAlloc(a, raw);
    return std.fmt.bytesToHex(records.fileIdentity(encoded), .lower);
}

fn requireDigest(value: std.json.Value) ![]const u8 {
    const raw = try text(value);
    _ = try contracts.parseSha256(raw);
    return raw;
}

fn unchecked(a: std.mem.Allocator, value: std.json.Value, skipped: []const []const u8) !std.json.Value {
    if (value != .object) return error.InvalidCommand;
    var out = std.json.Value{ .object = .empty };
    var iterator = value.object.iterator();
    while (iterator.next()) |entry| {
        var remove = false;
        for (skipped) |name| if (std.mem.eql(u8, entry.key_ptr.*, name)) {
            remove = true;
            break;
        };
        if (!remove) try out.object.put(a, entry.key_ptr.*, entry.value_ptr.*);
    }
    return out;
}

fn binding(a: std.mem.Allocator, item: plan.Binding) !std.json.Value {
    const raw = switch (item) {
        .literal => |value| try std.json.Stringify.valueAlloc(a, .{ .kind = "literal", .value = value }, .{}),
        .path => |value| try std.json.Stringify.valueAlloc(a, .{ .kind = "path", .role = value.role, .relative = value.relative }, .{}),
    };
    return std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{ .allocate = .alloc_always });
}

fn matchBinding(a: std.mem.Allocator, observed: std.json.Value, expected: plan.Binding) !void {
    const encoded = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, observed, .{}));
    const want = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, try binding(a, expected), .{}));
    try eq(encoded, want);
}

const PlanVariant = enum { native, historical_native, historical_import };

fn matchPlan(
    a: std.mem.Allocator,
    request: std.json.Value,
    stage: plan.Stage,
    variant: PlanVariant,
    context: EvidenceContext,
) !void {
    const selected = plan.spec(stage);
    const argv = try get(request, "argv");
    const historical = variant == .historical_import;
    const wrapper = historical and (stage == .adapter or stage == .@"local-boot-tool");
    const historical_fixture: []const plan.Binding = &.{
        .{ .path = .{ .role = "tool:python3" } },
        .{ .literal = "-m" },
        .{ .literal = "unittest" },
        .{ .literal = "discover" },
        .{ .literal = "-s" },
        .{ .path = .{ .role = "source", .relative = "support/build/wamr-native-ci/tests" } },
        .{ .literal = "-v" },
    };
    const expected_argv = if (historical and stage == .fixtures) historical_fixture else selected.argv;
    const historical_cache = variant != .native and
        (stage == .@"public-validator-build" or stage == .@"import-validator-build");
    if (argv != .array or argv.array.items.len != expected_argv.len +
        @as(usize, @intFromBool(wrapper)) * 2 + @as(usize, @intFromBool(historical_cache)) * 2)
        return error.InvalidCommand;
    if (wrapper) {
        try matchBinding(a, argv.array.items[0], .{ .path = .{ .role = "command-supervisor" } });
        try matchBinding(a, argv.array.items[1], .{ .literal = "--launch-retained" });
    }
    var observed_index: usize = if (wrapper) 2 else 0;
    for (expected_argv, 0..) |expected, index| {
        if (historical_cache and expected == .literal and std.mem.eql(u8, expected.literal, "--prefix")) {
            try matchBinding(a, argv.array.items[observed_index], .{ .literal = "--global-cache-dir" });
            try matchBinding(a, argv.array.items[observed_index + 1], .{ .path = .{ .role = "work", .relative = "global-cache" } });
            observed_index += 2;
        }
        const selected_binding: plan.Binding = if (historical and stage == .@"local-boot-tool" and index == 7)
            .{ .path = .{ .role = "work", .relative = "tools" } }
        else if (variant != .native and expected == .literal and std.mem.eql(u8, expected.literal, "-Doptimize=safe"))
            .{ .literal = "-Doptimize=ReleaseSafe" }
        else
            expected;
        try matchBinding(a, argv.array.items[observed_index], selected_binding);
        observed_index += 1;
    }
    if (observed_index != argv.array.items.len) return error.InvalidCommand;
    const environment = try get(request, "environment");
    const expected = try plan.environment(a, stage);
    defer plan.freeEnvironment(a, expected);
    if (environment != .array or environment.array.items.len != expected.len)
        return error.InvalidCommand;
    for (environment.array.items, expected) |observed, entry| {
        try exact(observed, &.{ "name", "value" });
        try eq(try text(try get(observed, "name")), entry.name);
        try matchBinding(a, try get(observed, "value"), entry.value);
    }
    try matchBinding(a, try get(request, "cwd"), .{ .path = .{ .role = "source" } });
    const supervisor = try get(request, "supervisor");
    if (context == .local_runtime and stage == .@"handoff-inspect") {
        matchIdentified(a, supervisor, "command-supervisor") catch |err| {
            if (err == error.OutOfMemory) return err;
            try matchIdentified(a, supervisor, handoff_controller_role);
        };
    } else {
        try matchIdentified(a, supervisor, "command-supervisor");
    }
    try matchIdentified(a, try get(request, "native_executable"), if (wrapper) "command-supervisor" else if (historical and stage == .fixtures) "tool:python3" else selected.executable);
    try matchIdentified(a, try get(request, "command_executable"), if (historical and stage == .fixtures) "tool:python3" else selected.executable);
    const interpreter = try get(request, "interpreter");
    if (historical and stage == .fixtures) {
        try matchIdentified(a, interpreter, "tool:python3");
    } else if (interpreter != .null) return error.InvalidCommand;
    const limits = try get(request, "limits");
    const expected_limits = if (historical)
        try std.json.Stringify.valueAlloc(a, .{
            .cleanup_events = 1_000_000,
            .descendants = 64,
            .primary_events = 1_000_000,
            .proc_entries_per_scan = 262_144,
            .reap_events = 512,
            .stderr_bytes = @max(1, @min((if (plan.isValidator(stage)) @as(usize, 8192) else selected.output_limit) + 1, 4 * 1024 * 1024)),
            .stdout_bytes = @max(1, @min((if (plan.isValidator(stage)) @as(usize, 8192) else selected.output_limit) + 1, 4 * 1024 * 1024)),
            .term_grace_ms = 1000,
        }, .{})
    else
        try std.json.Stringify.valueAlloc(a, plan.limits(selected), .{});
    const actual = try std.json.Stringify.valueAlloc(a, limits, .{});
    try eq(try records.canonicalAlloc(a, actual), try records.canonicalAlloc(a, expected_limits));
    const timeout = @as(u64, selected.seconds) * std.time.ns_per_s;
    if (try num(u64, try get(request, "timeout_ns")) != timeout)
        return error.InvalidCommand;
}

fn matchIdentified(a: std.mem.Allocator, value: std.json.Value, role: []const u8) !void {
    try exact(value, &.{ "path", "identity" });
    try matchBinding(a, try get(value, "path"), .{ .path = .{ .role = role } });
    try identity(try get(value, "identity"));
}

fn identity(value: std.json.Value) !void {
    try exact(value, &.{
        "content_sha256", "ctime_nanoseconds", "ctime_seconds", "device_major",
        "device_minor",   "inode",             "mode",          "mtime_nanoseconds",
        "mtime_seconds",  "size",              "uid",
    });
    _ = try requireDigest(try get(value, "content_sha256"));
    if (try num(u64, try get(value, "inode")) == 0 or
        try num(u64, try get(value, "size")) == 0 or
        try num(u32, try get(value, "mtime_nanoseconds")) >= std.time.ns_per_s or
        try num(u32, try get(value, "ctime_nanoseconds")) >= std.time.ns_per_s)
        return error.InvalidCommand;
    _ = try num(u32, try get(value, "device_major"));
    _ = try num(u32, try get(value, "device_minor"));
    _ = try num(u16, try get(value, "mode"));
    _ = try num(u32, try get(value, "uid"));
    _ = try num(i64, try get(value, "mtime_seconds"));
    _ = try num(i64, try get(value, "ctime_seconds"));
}

fn pair(value: std.json.Value) !void {
    try exact(value, &.{ "kind", "code" });
    try eq(try text(try get(value, "kind")), "exited");
    if (try num(u8, try get(value, "code")) != 0) return error.InvalidCommand;
}

fn stream(value: std.json.Value, max: usize) !u64 {
    try exact(value, &.{ "bytes", "sha256", "digest_scope", "status" });
    const size = try num(u64, try get(value, "bytes"));
    if (size > max) return error.InvalidCommand;
    const hash = try requireDigest(try get(value, "sha256"));
    try eq(try text(try get(value, "digest_scope")), if (size == 0) "reproducible_empty" else "transport_authenticated_observation");
    try eq(try text(try get(value, "status")), "complete");
    if (size == 0) {
        const empty = std.fmt.bytesToHex(records.fileIdentity(""), .lower);
        try eq(hash, &empty);
    }
    return size;
}

fn outputCommitment(stdout: std.json.Value, stderr: std.json.Value) ![64]u8 {
    var hash = Sha256.init(.{});
    hash.update("uk.wamr.command-output-v1\x00");
    for ([_]std.json.Value{ stdout, stderr }) |item| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, try num(u64, try get(item, "bytes")), .big);
        hash.update(&length);
        const parsed = try contracts.parseSha256(try text(try get(item, "sha256")));
        hash.update(&parsed);
    }
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn retainedEnvironment(name: []const u8) bool {
    return std.mem.eql(u8, name, "M4") or
        std.mem.eql(u8, name, "WAMR_CI_GIT") or
        std.mem.eql(u8, name, "WAMR_CI_SUPERVISOR") or
        std.mem.eql(u8, name, "WAMR_CI_LAUNCH_EXECUTABLE") or
        std.mem.eql(u8, name, "WAMR_CI_PYTHON") or
        std.mem.eql(u8, name, "WAMR_CI_LOG_VALIDATE") or
        std.mem.startsWith(u8, name, "WAMR_CI_TOOL_");
}

fn matchRetained(a: std.mem.Allocator, request: std.json.Value, command: std.json.Value, stage: plan.Stage) !void {
    const retained = try get(request, "retained_executables");
    if (retained != .array or retained.array.items.len > 64) return error.InvalidCommand;
    const expected_bindings = try plan.environment(a, stage);
    defer plan.freeEnvironment(a, expected_bindings);
    var expected: std.StringHashMap(void) = .init(a);
    defer expected.deinit();
    for (expected_bindings) |entry| {
        if (entry.value == .path and retainedEnvironment(entry.name))
            try expected.put(entry.name, {});
    }
    if (retained.array.items.len != expected.count()) return error.InvalidCommand;
    const copied = try get(command, "retained_executables");
    const first = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, retained, .{}));
    const second = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, copied, .{}));
    try eq(first, second);
    const environment = try get(request, "environment");
    var previous: []const u8 = "";
    for (retained.array.items) |entry| {
        try exact(entry, &.{ "name", "path", "identity" });
        const name = try text(try get(entry, "name"));
        if (name.len == 0 or !std.mem.lessThan(u8, previous, name))
            return error.InvalidCommand;
        if (!expected.contains(name)) return error.InvalidCommand;
        previous = name;
        var found = false;
        for (environment.array.items) |env| {
            if (!std.mem.eql(u8, try text(try get(env, "name")), name)) continue;
            const actual = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, try get(entry, "path"), .{}));
            const retained_path = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, try get(env, "value"), .{}));
            try eq(actual, retained_path);
            found = true;
            break;
        }
        if (!found) return error.InvalidCommand;
        try identity(try get(entry, "identity"));
    }
}

/// Both transports carry the identical producer binding; imported native bytes
/// are authenticated by the already verified trusted inner ZIP, not by logs.
pub fn validate(
    a: std.mem.Allocator,
    record: std.json.Value,
    stage: plan.Stage,
    context: EvidenceContext,
) !ValidatedCommand {
    return validateWithProfile(a, record, stage, context);
}

pub fn validateLegacyV1(
    a: std.mem.Allocator,
    record: std.json.Value,
    stage: plan.Stage,
    context: EvidenceContext,
) !ValidatedCommand {
    if (context != .local_runtime or stage != .@"handoff-inspect-legacy")
        return error.InvalidCommand;
    return validateWithProfile(a, record, stage, context);
}

fn validateWithProfile(
    a: std.mem.Allocator,
    record: std.json.Value,
    stage: plan.Stage,
    context: EvidenceContext,
) !ValidatedCommand {
    try exact(record, &.{
        "scope",      "stage",               "exit_code",  "bytes", "sha256", "sha256_scope",
        "over_limit", "known_error_markers", "supervisor",
    });
    try eq(try text(try get(record, "scope")), "command_diagnostic_not_acceptance");
    try eq(try text(try get(record, "stage")), @tagName(stage));
    if (try num(u8, try get(record, "exit_code")) != 0) return error.InvalidCommand;
    const size = try num(u64, try get(record, "bytes"));
    const hash = try requireDigest(try get(record, "sha256"));
    try eq(try text(try get(record, "sha256_scope")), if (size == 0) "reproducible_empty" else "transport_authenticated_observation");
    if (size == 0) {
        const empty = std.fmt.bytesToHex(records.fileIdentity(""), .lower);
        try eq(hash, &empty);
    }
    try yes(try get(record, "over_limit"), false);
    const markers = try get(record, "known_error_markers");
    if (markers != .array or markers.array.items.len != 0) return error.InvalidCommand;
    const supervisor = try get(record, "supervisor");
    try exact(supervisor, &.{ "schema", "version", "bootstrap", "request", "result" });
    try eq(try text(try get(supervisor, "schema")), "uk.wamr.command-supervisor-result");
    if (try num(u8, try get(supervisor, "version")) != 1) return error.InvalidCommand;
    try yes(try get(supervisor, "bootstrap"), false);
    const request = try get(supervisor, "request");
    try exact(request, &.{
        "schema",              "version",     "binding_schema",       "binding_version",  "stage",
        "argv",                "environment", "cwd",                  "supervisor",       "native_executable",
        "command_executable",  "interpreter", "retained_executables", "issued_ns",        "primary_deadline_ns",
        "cleanup_deadline_ns", "timeout_ns",  "limits",               "canonical_sha256", "argv_sha256",
        "environment_sha256",  "cwd_sha256",
    });
    try eq(try text(try get(request, "schema")), "uk.wamr.command-supervisor-request");
    try eq(try text(try get(request, "binding_schema")), "uk.wamr.supervised-command-binding");
    try eq(try text(try get(request, "stage")), @tagName(stage));
    if (try num(u8, try get(request, "version")) != 1 or
        try num(u8, try get(request, "binding_version")) != 1) return error.InvalidCommand;
    const variant: PlanVariant = blk: {
        matchPlan(a, request, stage, .native, context) catch |err| {
            if (context == .local_runtime or err == error.OutOfMemory) return err;
            if (matchPlan(a, request, stage, .historical_native, context)) |_| {
                break :blk .historical_native;
            } else |legacy_err| if (legacy_err == error.OutOfMemory) return legacy_err;
            try matchPlan(a, request, stage, .historical_import, context);
            break :blk .historical_import;
        };
        break :blk .native;
    };
    if (size > (if (variant == .historical_import and plan.isValidator(stage)) @as(usize, 8192) else plan.spec(stage).output_limit))
        return error.InvalidCommand;
    const limits = try get(request, "limits");
    const issued = try num(u64, try get(request, "issued_ns"));
    const primary_deadline = try num(u64, try get(request, "primary_deadline_ns"));
    const cleanup_deadline = try num(u64, try get(request, "cleanup_deadline_ns"));
    const scheduled_primary = std.math.add(u64, issued, try num(u64, try get(request, "timeout_ns"))) catch return error.InvalidCommand;
    const scheduled_cleanup = std.math.add(u64, primary_deadline, 10 * std.time.ns_per_s) catch return error.InvalidCommand;
    if (scheduled_primary != primary_deadline or scheduled_cleanup != cleanup_deadline)
        return error.InvalidCommand;
    for ([_]struct { key: []const u8, value: std.json.Value }{
        .{ .key = "argv_sha256", .value = try get(request, "argv") },
        .{ .key = "environment_sha256", .value = try get(request, "environment") },
        .{ .key = "cwd_sha256", .value = try get(request, "cwd") },
        .{ .key = "canonical_sha256", .value = try unchecked(a, request, &.{ "canonical_sha256", "argv_sha256", "environment_sha256", "cwd_sha256" }) },
    }) |entry| {
        const expected = try digest(a, entry.value);
        try eq(try requireDigest(try get(request, entry.key)), &expected);
    }
    const result = try get(supervisor, "result");
    try exact(result, &.{
        "schema",         "version",       "request_canonical_sha256", "controller_error",
        "native_request", "native_result", "command",                  "canonical_sha256",
    });
    try eq(try text(try get(result, "schema")), "uk.wamr.command-supervisor-result");
    if (try num(u8, try get(result, "version")) != 1 or
        try get(result, "controller_error") != .null)
        return error.InvalidCommand;
    try eq(try text(try get(result, "request_canonical_sha256")), try text(try get(request, "canonical_sha256")));
    for ([_]struct { key: []const u8, max: usize }{
        .{ .key = "native_request", .max = 1024 * 1024 },
        .{ .key = "native_result", .max = 12 * 1024 * 1024 },
    }) |entry| {
        const transport = try get(result, entry.key);
        try exact(transport, &.{ "bytes", "sha256", "digest_scope" });
        const length = try num(u64, try get(transport, "bytes"));
        if (length == 0 or length > entry.max) return error.InvalidCommand;
        _ = try requireDigest(try get(transport, "sha256"));
        try eq(try text(try get(transport, "digest_scope")), "direct_producer_or_trusted_inner_zip");
    }
    const expected_result = try digest(a, try unchecked(a, result, &.{"canonical_sha256"}));
    try eq(try requireDigest(try get(result, "canonical_sha256")), &expected_result);
    const command = try get(result, "command");
    try exact(command, &.{
        "cancellation_observed", "cleanup",              "cleanup_complete",         "cleanup_events",
        "descendants",           "executable",           "executable_stable",        "output",
        "poisoned",              "primary",              "primary_deadline_reached", "primary_events",
        "reap_events",           "retained_executables", "stderr",                   "stdout",
        "timing",                "termination",
    });
    try yes(try get(command, "cancellation_observed"), false);
    try yes(try get(command, "cleanup_complete"), true);
    try yes(try get(command, "executable_stable"), true);
    try yes(try get(command, "poisoned"), false);
    try yes(try get(command, "primary_deadline_reached"), false);
    try eq(try text(try get(command, "cleanup")), "complete");
    try pair(try get(command, "primary"));
    try pair(try get(command, "termination"));
    try sameJson(a, try get(command, "executable"), try get(try get(request, "native_executable"), "identity"));
    try matchRetained(a, request, command, stage);
    for ([_][]const u8{ "primary_events", "cleanup_events", "reap_events" }) |name| {
        if (try num(u64, try get(command, name)) >
            try num(u64, try get(limits, name))) return error.InvalidCommand;
    }
    const descendants = try get(command, "descendants");
    try exact(descendants, &.{ "adopted", "identity_validated", "limit_exceeded", "observed", "untracked" });
    const observed = try num(u16, try get(descendants, "observed"));
    const primary_events = try num(u32, try get(command, "primary_events"));
    const cleanup_events = try num(u32, try get(command, "cleanup_events"));
    const reap_events = try num(u16, try get(command, "reap_events"));
    if (observed > try num(u16, try get(limits, "descendants")) or
        try num(u16, try get(descendants, "identity_validated")) != observed or
        try num(u16, try get(descendants, "adopted")) > observed or
        primary_events < core.process.command_complete_primary_events_min or
        cleanup_events < core.process.command_complete_cleanup_events_min or
        reap_events != observed + 2) return error.InvalidCommand;
    try yes(try get(descendants, "limit_exceeded"), false);
    try yes(try get(descendants, "untracked"), false);
    const stdout = try get(command, "stdout");
    const stderr = try get(command, "stderr");
    const stdout_size = try stream(stdout, try num(usize, try get(limits, "stdout_bytes")));
    const stderr_size = try stream(stderr, try num(usize, try get(limits, "stderr_bytes")));
    const output = try get(command, "output");
    try exact(output, &.{ "bytes", "combined_sha256", "commitment_sha256", "digest_scope" });
    if (try num(u64, try get(output, "bytes")) != size or
        stdout_size + stderr_size != size) return error.InvalidCommand;
    const combined_hash = try requireDigest(try get(output, "combined_sha256"));
    try eq(combined_hash, hash);
    if (size == 0) {
        const empty = std.fmt.bytesToHex(records.fileIdentity(""), .lower);
        try eq(combined_hash, &empty);
    }
    try eq(try text(try get(output, "digest_scope")), try text(try get(record, "sha256_scope")));
    const committed = try outputCommitment(stdout, stderr);
    try eq(try text(try get(output, "commitment_sha256")), &committed);
    const timing = try get(command, "timing");
    try exact(timing, &.{
        "started_ns",         "primary_completed_ns", "completed_ns",
        "primary_elapsed_ns", "cleanup_elapsed_ns",   "total_elapsed_ns",
    });
    const started = try num(u64, try get(timing, "started_ns"));
    const completed_primary = try num(u64, try get(timing, "primary_completed_ns"));
    const completed = try num(u64, try get(timing, "completed_ns"));
    if (started < issued or completed_primary < started or
        completed < completed_primary or completed_primary >= primary_deadline or
        completed > cleanup_deadline or
        try num(u64, try get(timing, "primary_elapsed_ns")) != completed_primary - started or
        try num(u64, try get(timing, "cleanup_elapsed_ns")) != completed - completed_primary or
        try num(u64, try get(timing, "total_elapsed_ns")) != completed - started)
        return error.InvalidCommand;
    var output_hash: [64]u8 = undefined;
    @memcpy(&output_hash, hash);
    return .{ .stage = stage, .output_bytes = size, .output_sha256 = output_hash };
}

fn sameJson(a: std.mem.Allocator, first: std.json.Value, second: std.json.Value) !void {
    const left = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, first, .{}));
    const right = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, second, .{}));
    try eq(left, right);
}
