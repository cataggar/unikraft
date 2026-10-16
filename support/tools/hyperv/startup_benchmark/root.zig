// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");

pub const Allocator = std.mem.Allocator;
pub const Io = std.Io;

pub const schema_version = "uk.hyperv.startup-benchmark.v1";
pub const default_min_trials: usize = 10;

pub const Error = error{
    InvalidArguments,
    InvalidBootTimingRecord,
    NonMonotonicMilestones,
    InvalidBootId,
    StaleOrDuplicateBootId,
    BootIdMismatchWithSerial,
    ProbeTimeout,
    InvalidHttpResponse,
    InvalidStartupReport,
    MissingLifecycleCategory,
    InsufficientTrials,
};

pub const BootTimingMilestones = struct {
    boot_id: [16]u8,
    t_efi_pre_exit_ns: u64,
    t_time_init_ns: u64,
    t_vmbus_ready_ns: u64,
    t_net_ready_ns: u64,
    t_http_ready_ns: u64,
    efi_to_time_ns: u64,
    time_to_vmbus_ns: u64,
    vmbus_to_net_ns: u64,
    net_to_http_ns: u64,
    guest_internal_init_ns: u64,
};

pub const ProbeReadyResult = struct {
    boot_id: [16]u8,
    elapsed_ns: u64,
    attempts: u32,
};

pub const CategoryStats = struct {
    trials_count: usize,
    min_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    max_ns: u64,
};

pub const TargetLifecycleSummary = struct {
    create_to_http_ready_ns: CategoryStats,
    start_from_deallocated_to_http_ready_ns: CategoryStats,
    guest_restart_to_http_ready_ns: CategoryStats,
    guest_internal_init_ns: CategoryStats,
};

pub const ValidatedStartupReport = struct {
    vm_size: []const u8,
    location: []const u8,
    min_trials_required: usize,
    unikraft: TargetLifecycleSummary,
    linux_baseline: TargetLifecycleSummary,
    unique_boot_ids_verified: usize,
};

pub fn isValidBootIdHex(value: []const u8) bool {
    if (value.len != 16) return false;
    for (value) |ch| {
        const ok = (ch >= '0' and ch <= '9') or
            (ch >= 'a' and ch <= 'f') or
            (ch >= 'A' and ch <= 'F');
        if (!ok) return false;
    }
    return true;
}

pub fn validateBootIdFreshness(candidate: [16]u8, prior_boot_ids: []const [16]u8) Error!void {
    if (!isValidBootIdHex(&candidate)) return error.InvalidBootId;
    for (prior_boot_ids) |prev| {
        if (std.ascii.eqlIgnoreCase(&candidate, &prev))
            return error.StaleOrDuplicateBootId;
    }
}

pub fn parseBootTimingRecord(line: []const u8) Error!BootTimingMilestones {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    const marker = std.mem.indexOf(u8, trimmed, "UK_HYPERV_BOOT_TIMING ") orelse
        return error.InvalidBootTimingRecord;
    const payload = trimmed[marker + "UK_HYPERV_BOOT_TIMING ".len ..];

    var boot_id: ?[16]u8 = null;
    var t_efi: ?u64 = null;
    var t_time: ?u64 = null;
    var t_vmbus: ?u64 = null;
    var t_net: ?u64 = null;
    var t_http: ?u64 = null;

    var tokens = std.mem.tokenizeScalar(u8, payload, ' ');
    while (tokens.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return error.InvalidBootTimingRecord;
        const key = tok[0..eq];
        const val = tok[eq + 1 ..];

        if (std.mem.eql(u8, key, "boot_id")) {
            if (!isValidBootIdHex(val)) return error.InvalidBootId;
            var id: [16]u8 = undefined;
            @memcpy(&id, val[0..16]);
            boot_id = id;
        } else if (std.mem.eql(u8, key, "t_efi_pre_exit")) {
            t_efi = std.fmt.parseInt(u64, val, 10) catch return error.InvalidBootTimingRecord;
        } else if (std.mem.eql(u8, key, "t_time_init")) {
            t_time = std.fmt.parseInt(u64, val, 10) catch return error.InvalidBootTimingRecord;
        } else if (std.mem.eql(u8, key, "t_vmbus_ready")) {
            t_vmbus = std.fmt.parseInt(u64, val, 10) catch return error.InvalidBootTimingRecord;
        } else if (std.mem.eql(u8, key, "t_net_ready")) {
            t_net = std.fmt.parseInt(u64, val, 10) catch return error.InvalidBootTimingRecord;
        } else if (std.mem.eql(u8, key, "t_http_ready")) {
            t_http = std.fmt.parseInt(u64, val, 10) catch return error.InvalidBootTimingRecord;
        }
    }

    const id = boot_id orelse return error.InvalidBootTimingRecord;
    const efi = t_efi orelse return error.InvalidBootTimingRecord;
    const tim = t_time orelse return error.InvalidBootTimingRecord;
    const vmb = t_vmbus orelse return error.InvalidBootTimingRecord;
    const net = t_net orelse return error.InvalidBootTimingRecord;
    const htp = t_http orelse return error.InvalidBootTimingRecord;

    if (!(efi <= tim and tim <= vmb and vmb <= net and net <= htp))
        return error.NonMonotonicMilestones;

    return .{
        .boot_id = id,
        .t_efi_pre_exit_ns = efi,
        .t_time_init_ns = tim,
        .t_vmbus_ready_ns = vmb,
        .t_net_ready_ns = net,
        .t_http_ready_ns = htp,
        .efi_to_time_ns = tim - efi,
        .time_to_vmbus_ns = vmb - tim,
        .vmbus_to_net_ns = net - vmb,
        .net_to_http_ns = htp - net,
        .guest_internal_init_ns = htp - efi,
    };
}

pub fn verifySerialAndHttpBootId(
    serial_milestones: BootTimingMilestones,
    http_boot_id: [16]u8,
    prior_boot_ids: []const [16]u8,
) Error!void {
    try validateBootIdFreshness(http_boot_id, prior_boot_ids);
    if (!std.ascii.eqlIgnoreCase(&serial_milestones.boot_id, &http_boot_id))
        return error.BootIdMismatchWithSerial;
}

pub fn probeUntilHttpReady(
    io: Io,
    address: Io.net.IpAddress,
    prior_boot_ids: []const [16]u8,
    timeout_ms: u64,
    retry_interval_ms: u64,
) Error!ProbeReadyResult {
    const start_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
    const timeout_ns = timeout_ms * 1_000_000;
    var attempts: u32 = 0;

    while (true) {
        const now_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
        if (now_ns >= start_ns and now_ns - start_ns > timeout_ns)
            return error.ProbeTimeout;

        attempts += 1;
        if (trySingleHttpProbe(io, address)) |boot_id| {
            try validateBootIdFreshness(boot_id, prior_boot_ids);
            const ready_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
            return .{
                .boot_id = boot_id,
                .elapsed_ns = if (ready_ns >= start_ns) ready_ns - start_ns else 0,
                .attempts = attempts,
            };
        } else |err| switch (err) {
            error.InvalidBootId => return error.InvalidBootId,
            else => {},
        }

        if (retry_interval_ms > 0) {
            Io.sleep(io, .fromMilliseconds(@intCast(retry_interval_ms)), .awake) catch {};
        }
    }
}

fn trySingleHttpProbe(io: Io, address: Io.net.IpAddress) ![16]u8 {
    var stream = try Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    defer stream.close(io);

    const req =
        "GET / HTTP/1.1\r\n" ++
        "Host: startup-probe.local\r\n" ++
        "Connection: close\r\n" ++
        "\r\n";
    var wbuf: [256]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    try writer.interface.writeAll(req);
    try writer.interface.flush();

    var raw_resp: [2048]u8 = undefined;
    var filled: usize = 0;
    var reader = stream.reader(io, &.{});

    while (filled < raw_resp.len) {
        var slice = [_][]u8{raw_resp[filled..]};
        const n = reader.interface.readVec(&slice) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        filled += n;
        if (std.mem.indexOf(u8, raw_resp[0..filled], "\r\n\r\n")) |hdr_end| {
            if (filled >= hdr_end + 4 + 1024) break;
        }
    }

    const hdr_end = std.mem.indexOf(u8, raw_resp[0..filled], "\r\n\r\n") orelse
        return error.InvalidHttpResponse;
    const header_block = raw_resp[0..hdr_end];
    const body_len = filled - (hdr_end + 4);
    if (body_len != 1024) return error.InvalidHttpResponse;

    var lines = std.mem.splitSequence(u8, header_block, "\r\n");
    const status_line = lines.next() orelse return error.InvalidHttpResponse;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 200")) return error.InvalidHttpResponse;

    var content_len_ok = false;
    var boot_id: ?[16]u8 = null;

    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            const len = std.fmt.parseInt(usize, val, 10) catch return error.InvalidHttpResponse;
            content_len_ok = (len == 1024);
        } else if (std.ascii.eqlIgnoreCase(name, "X-Unikraft-Boot-Id") or
            std.ascii.eqlIgnoreCase(name, "X-Linux-Boot-Id"))
        {
            if (!isValidBootIdHex(val)) return error.InvalidBootId;
            var id: [16]u8 = undefined;
            @memcpy(&id, val[0..16]);
            boot_id = id;
        }
    }

    if (!content_len_ok) return error.InvalidHttpResponse;
    return boot_id orelse error.InvalidBootId;
}

pub fn validateStartupBenchmarkReport(
    allocator: Allocator,
    raw_json: []const u8,
    min_trials_required: usize,
) !ValidatedStartupReport {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidStartupReport,
    };

    const schema = try jsonRequiredString(root, "schema_version");
    if (!std.mem.eql(u8, schema, schema_version)) return error.InvalidStartupReport;

    const vm_size = try allocator.dupe(u8, try jsonRequiredString(root, "vm_size"));
    errdefer allocator.free(vm_size);
    const location = try allocator.dupe(u8, try jsonRequiredString(root, "location"));
    errdefer allocator.free(location);

    var seen_boot_ids: std.ArrayList([16]u8) = .empty;
    defer seen_boot_ids.deinit(allocator);

    const uk_obj = switch (root.get("unikraft") orelse return error.InvalidStartupReport) {
        .object => |obj| obj,
        else => return error.InvalidStartupReport,
    };
    const lx_obj = switch (root.get("linux_baseline") orelse return error.InvalidStartupReport) {
        .object => |obj| obj,
        else => return error.InvalidStartupReport,
    };

    const uk_summary = try parseTargetLifecycle(allocator, uk_obj, min_trials_required, &seen_boot_ids);
    const lx_summary = try parseTargetLifecycle(allocator, lx_obj, min_trials_required, &seen_boot_ids);

    // Guest internal initialization must be strictly smaller than cold deallocated start-to-HTTP ready
    if (uk_summary.guest_internal_init_ns.p50_ns >= uk_summary.start_from_deallocated_to_http_ready_ns.p50_ns)
        return error.InvalidStartupReport;

    return .{
        .vm_size = vm_size,
        .location = location,
        .min_trials_required = min_trials_required,
        .unikraft = uk_summary,
        .linux_baseline = lx_summary,
        .unique_boot_ids_verified = seen_boot_ids.items.len,
    };
}

pub fn freeValidatedReport(allocator: Allocator, report: ValidatedStartupReport) void {
    allocator.free(report.vm_size);
    allocator.free(report.location);
}

fn parseTargetLifecycle(
    allocator: Allocator,
    target_obj: std.json.ObjectMap,
    min_trials_required: usize,
    seen_boot_ids: *std.ArrayList([16]u8),
) !TargetLifecycleSummary {
    const create_stats = try parseCategory(allocator, target_obj, "create_to_http_ready_ns", min_trials_required, true, seen_boot_ids);
    const dealloc_stats = try parseCategory(allocator, target_obj, "start_from_deallocated_to_http_ready_ns", min_trials_required, true, seen_boot_ids);
    const restart_stats = try parseCategory(allocator, target_obj, "guest_restart_to_http_ready_ns", min_trials_required, true, seen_boot_ids);
    const internal_stats = try parseCategory(allocator, target_obj, "guest_internal_init_ns", min_trials_required, false, seen_boot_ids);

    return .{
        .create_to_http_ready_ns = create_stats,
        .start_from_deallocated_to_http_ready_ns = dealloc_stats,
        .guest_restart_to_http_ready_ns = restart_stats,
        .guest_internal_init_ns = internal_stats,
    };
}

fn parseCategory(
    allocator: Allocator,
    target_obj: std.json.ObjectMap,
    key: []const u8,
    min_trials_required: usize,
    record_fresh_boot_ids: bool,
    seen_boot_ids: *std.ArrayList([16]u8),
) !CategoryStats {
    const cat_val = target_obj.get(key) orelse return error.MissingLifecycleCategory;
    const cat_obj = switch (cat_val) {
        .object => |obj| obj,
        else => return error.InvalidStartupReport,
    };

    const trials_val = cat_obj.get("trials") orelse return error.InvalidStartupReport;
    const trials = switch (trials_val) {
        .array => |arr| arr.items,
        else => return error.InvalidStartupReport,
    };
    if (trials.len < min_trials_required) return error.InsufficientTrials;

    const samples = try allocator.alloc(u64, trials.len);
    defer allocator.free(samples);

    for (trials, 0..) |trial_val, idx| {
        const trial_obj = switch (trial_val) {
            .object => |obj| obj,
            else => return error.InvalidStartupReport,
        };
        const duration_ns = try jsonRequiredU64(trial_obj, "duration_ns");
        if (duration_ns == 0) return error.InvalidStartupReport;
        samples[idx] = duration_ns;

        const boot_str = try jsonRequiredString(trial_obj, "boot_id");
        if (!isValidBootIdHex(boot_str)) return error.InvalidBootId;
        var id: [16]u8 = undefined;
        @memcpy(&id, boot_str[0..16]);

        if (record_fresh_boot_ids) {
            try validateBootIdFreshness(id, seen_boot_ids.items);
            try seen_boot_ids.append(allocator, id);
        }
    }

    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const min_ns = samples[0];
    const p50_ns = samples[((samples.len - 1) * 50) / 100];
    const p95_ns = samples[((samples.len - 1) * 95) / 100];
    const max_ns = samples[samples.len - 1];

    if (!(min_ns <= p50_ns and p50_ns <= p95_ns and p95_ns <= max_ns))
        return error.InvalidStartupReport;

    return .{
        .trials_count = trials.len,
        .min_ns = min_ns,
        .p50_ns = p50_ns,
        .p95_ns = p95_ns,
        .max_ns = max_ns,
    };
}

pub fn renderMarkdownReport(allocator: Allocator, report: ValidatedStartupReport) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try out.writer.print(
        \\# Azure Start-to-Service vs Guest Internal Initialization Report
        \\
        \\- **Schema**: `{s}`
        \\- **VM Size**: `{s}` (`{s}`)
        \\- **Trials per Category**: `>= {d}`
        \\- **Unique Fresh Boot IDs Verified**: `{d}`
        \\
        \\| Lifecycle Category | Target | Trials | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) |
        \\|---|---|---:|---:|---:|---:|---:|
        \\
    , .{
        schema_version,
        report.vm_size,
        report.location,
        report.min_trials_required,
        report.unique_boot_ids_verified,
    });

    try appendRow(&out.writer, "1. `create_to_http_ready_ns`", "Unikraft", report.unikraft.create_to_http_ready_ns);
    try appendRow(&out.writer, "1. `create_to_http_ready_ns`", "Ubuntu 24.04", report.linux_baseline.create_to_http_ready_ns);
    try appendRow(&out.writer, "2. `start_from_deallocated_to_http_ready_ns`", "Unikraft", report.unikraft.start_from_deallocated_to_http_ready_ns);
    try appendRow(&out.writer, "2. `start_from_deallocated_to_http_ready_ns`", "Ubuntu 24.04", report.linux_baseline.start_from_deallocated_to_http_ready_ns);
    try appendRow(&out.writer, "3. `guest_restart_to_http_ready_ns`", "Unikraft", report.unikraft.guest_restart_to_http_ready_ns);
    try appendRow(&out.writer, "3. `guest_restart_to_http_ready_ns`", "Ubuntu 24.04", report.linux_baseline.guest_restart_to_http_ready_ns);
    try appendRow(&out.writer, "4. `guest_internal_init_ns`", "Unikraft", report.unikraft.guest_internal_init_ns);
    try appendRow(&out.writer, "4. `guest_internal_init_ns`", "Ubuntu 24.04", report.linux_baseline.guest_internal_init_ns);

    return try out.toOwnedSlice();
}

fn appendRow(writer: *std.Io.Writer, category: []const u8, target: []const u8, s: CategoryStats) !void {
    try writer.print(
        "| {s} | {s} | {d} | {d:.2} | {d:.2} | {d:.2} | {d:.2} |\n",
        .{
            category,
            target,
            s.trials_count,
            nsToMs(s.min_ns),
            nsToMs(s.p50_ns),
            nsToMs(s.p95_ns),
            nsToMs(s.max_ns),
        },
    );
}

fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

fn jsonRequiredString(object: std.json.ObjectMap, key: []const u8) Error![]const u8 {
    const val = object.get(key) orelse return error.InvalidStartupReport;
    return switch (val) {
        .string => |s| if (s.len > 0) s else error.InvalidStartupReport,
        else => error.InvalidStartupReport,
    };
}

fn jsonRequiredU64(object: std.json.ObjectMap, key: []const u8) Error!u64 {
    const val = object.get(key) orelse return error.InvalidStartupReport;
    return switch (val) {
        .integer => |n| if (n >= 0) @intCast(n) else error.InvalidStartupReport,
        else => error.InvalidStartupReport,
    };
}
