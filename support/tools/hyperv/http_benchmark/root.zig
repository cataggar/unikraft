// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");

pub const Allocator = std.mem.Allocator;
pub const Io = std.Io;

pub const schema_version = "uk.hyperv.http-benchmark.v1";
pub const canonical_body_bytes: usize = 1024;
pub const boot_id_header_name = "X-Unikraft-Boot-Id";
pub const expected_concurrency_tiers = [_]u32{ 1, 8, 32, 64 };

pub const Error = error{
    InvalidArguments,
    InvalidHttpResponse,
    InvalidStatusCode,
    InvalidContentLength,
    InvalidConnectionHeader,
    InvalidBootIdHeader,
    InvalidBodyPayload,
    InvalidTelemetryRecord,
    InvalidBenchmarkReport,
    MissingConcurrencyTier,
    TopologyMismatch,
};

pub const ParsedHttpResponse = struct {
    status_code: u16,
    content_length: usize,
    keep_alive: bool,
    boot_id: [16]u8,
    header_bytes: usize,
    body: []const u8,
};

pub const UnikraftServiceStats = struct {
    phase: []const u8,
    boot_id: [16]u8,
    elapsed_ms: u64,
    requests: u64,
    bytes_tx: u64,
    bytes_rx: u64,
    active_conns: u32,
    peak_conns: u32,
    total_conns: u64,
    errors: u64,
    status_200: u64,
    status_400: u64,
    status_413: u64,
    netvsc_tx_packets: u64,
    netvsc_rx_packets: u64,
    netvsc_RingFull: u64,
    ukalloc_cur_alloc_size: u64,
    ukalloc_max_alloc_size: u64,
    ukalloc_cur_nb_allocs: u64,
    ukalloc_tot_nb_allocs: u64,
    ukalloc_tot_nb_frees: u64,
};

pub const LinuxServiceStats = struct {
    phase: []const u8,
    boot_id: [16]u8,
    elapsed_ms: u64,
    requests: u64,
    bytes_tx: u64,
    bytes_rx: u64,
    active_conns: u32,
    peak_conns: u32,
    total_conns: u64,
    errors: u64,
    status_200: u64,
    status_400: u64,
    status_413: u64,
    rss_bytes: u64,
    max_rss_bytes: u64,
};

pub const LoadSampleSummary = struct {
    concurrency: u32,
    requests: u64,
    bytes_rx: u64,
    errors: u64,
    elapsed_ns: u64,
    rps: f64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    boot_id: [16]u8,
};

pub const TierComparison = struct {
    concurrency: u32,
    duration_seconds: u32,
    unikraft_rps: f64,
    linux_rps: f64,
    unikraft_p50_us: f64,
    unikraft_p95_us: f64,
    unikraft_p99_us: f64,
    unikraft_p999_us: f64,
    linux_p50_us: f64,
    linux_p95_us: f64,
    linux_p99_us: f64,
    linux_p999_us: f64,
    unikraft_errors: u64,
    linux_errors: u64,
};

pub const ValidatedComparisonReport = struct {
    vm_size: []const u8,
    location: []const u8,
    subnet_cidr: []const u8,
    accelerated_networking: bool,
    unikraft_boot_id: [16]u8,
    linux_boot_id: [16]u8,
    unikraft_idle_heap_bytes: u64,
    unikraft_load_peak_heap_bytes: u64,
    linux_idle_rss_bytes: u64,
    linux_load_peak_rss_bytes: u64,
    tiers: [expected_concurrency_tiers.len]TierComparison,
};

pub fn fillExpectedBody(out: *[canonical_body_bytes]u8) void {
    const prefix = "unikraft-hyperv-http-1k-payload-line-";
    const suffix = ":0123456789abcdef0123456\n";
    const hex = "0123456789abcdef";

    for (0..16) |line| {
        const dst = out[line * 64 .. (line + 1) * 64];
        @memcpy(dst[0..prefix.len], prefix);
        dst[37] = hex[(line / 10) % 10];
        dst[38] = hex[line % 10];
        @memcpy(dst[39 .. 39 + suffix.len], suffix);
    }
}

pub fn isValidBootIdHex(value: []const u8) bool {
    if (value.len != 16) return false;
    for (value) |ch| {
        const valid = (ch >= '0' and ch <= '9') or
            (ch >= 'a' and ch <= 'f') or
            (ch >= 'A' and ch <= 'F');
        if (!valid) return false;
    }
    return true;
}

pub fn parseHttpResponse(raw: []const u8, validate_body: bool) Error!ParsedHttpResponse {
    const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const header_bytes = header_end + 4;
    const header_block = raw[0..header_end];

    var lines = std.mem.splitSequence(u8, header_block, "\r\n");
    const status_line = lines.next() orelse return error.InvalidHttpResponse;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 ")) return error.InvalidHttpResponse;
    if (status_line.len < "HTTP/1.1 200".len) return error.InvalidHttpResponse;
    const status_code = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.InvalidStatusCode;

    var content_length: ?usize = null;
    var keep_alive: ?bool = null;
    var boot_id: ?[16]u8 = null;

    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHttpResponse;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const val = std.mem.trim(u8, line[colon + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            content_length = std.fmt.parseInt(usize, val, 10) catch return error.InvalidContentLength;
        } else if (std.ascii.eqlIgnoreCase(name, "Connection")) {
            if (std.ascii.eqlIgnoreCase(val, "keep-alive")) {
                keep_alive = true;
            } else if (std.ascii.eqlIgnoreCase(val, "close")) {
                keep_alive = false;
            } else {
                return error.InvalidConnectionHeader;
            }
        } else if (std.ascii.eqlIgnoreCase(name, boot_id_header_name)) {
            if (!isValidBootIdHex(val)) return error.InvalidBootIdHeader;
            var id: [16]u8 = undefined;
            @memcpy(&id, val[0..16]);
            boot_id = id;
        }
    }

    const expected_len = content_length orelse return error.InvalidContentLength;
    const ka = keep_alive orelse return error.InvalidConnectionHeader;
    const bid = boot_id orelse return error.InvalidBootIdHeader;
    if (raw.len < header_bytes + expected_len) return error.InvalidHttpResponse;

    const body = raw[header_bytes .. header_bytes + expected_len];
    if (validate_body and status_code == 200) {
        if (expected_len != canonical_body_bytes) return error.InvalidContentLength;
        var canonical: [canonical_body_bytes]u8 = undefined;
        fillExpectedBody(&canonical);
        if (!std.mem.eql(u8, body, &canonical)) return error.InvalidBodyPayload;
    }

    return .{
        .status_code = status_code,
        .content_length = expected_len,
        .keep_alive = ka,
        .boot_id = bid,
        .header_bytes = header_bytes,
        .body = body,
    };
}

pub fn parseUnikraftStats(line: []const u8) Error!UnikraftServiceStats {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "UK_HYPERV_HTTP_SERVICE_STATS "))
        return error.InvalidTelemetryRecord;

    var stats: UnikraftServiceStats = .{
        .phase = "",
        .boot_id = @splat('0'),
        .elapsed_ms = 0,
        .requests = 0,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .active_conns = 0,
        .peak_conns = 0,
        .total_conns = 0,
        .errors = 0,
        .status_200 = 0,
        .status_400 = 0,
        .status_413 = 0,
        .netvsc_tx_packets = 0,
        .netvsc_rx_packets = 0,
        .netvsc_RingFull = 0,
        .ukalloc_cur_alloc_size = 0,
        .ukalloc_max_alloc_size = 0,
        .ukalloc_cur_nb_allocs = 0,
        .ukalloc_tot_nb_allocs = 0,
        .ukalloc_tot_nb_frees = 0,
    };
    var has_phase = false;
    var has_boot_id = false;

    var tokens = std.mem.tokenizeScalar(u8, trimmed["UK_HYPERV_HTTP_SERVICE_STATS ".len..], ' ');
    while (tokens.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return error.InvalidTelemetryRecord;
        const key = tok[0..eq];
        const val = tok[eq + 1 ..];

        if (std.mem.eql(u8, key, "phase")) {
            stats.phase = val;
            has_phase = val.len > 0;
        } else if (std.mem.eql(u8, key, "boot_id")) {
            if (!isValidBootIdHex(val)) return error.InvalidBootIdHeader;
            @memcpy(&stats.boot_id, val[0..16]);
            has_boot_id = true;
        } else if (std.mem.eql(u8, key, "elapsed_ms")) {
            stats.elapsed_ms = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "requests")) {
            stats.requests = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "bytes_tx")) {
            stats.bytes_tx = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "bytes_rx")) {
            stats.bytes_rx = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "active_conns")) {
            stats.active_conns = std.fmt.parseInt(u32, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "peak_conns")) {
            stats.peak_conns = std.fmt.parseInt(u32, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "total_conns")) {
            stats.total_conns = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "errors")) {
            stats.errors = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "status_200")) {
            stats.status_200 = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "status_400")) {
            stats.status_400 = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "status_413")) {
            stats.status_413 = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "netvsc_tx_packets")) {
            stats.netvsc_tx_packets = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "netvsc_rx_packets")) {
            stats.netvsc_rx_packets = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "netvsc_ring_full")) {
            stats.netvsc_RingFull = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "ukalloc_cur_alloc_size")) {
            stats.ukalloc_cur_alloc_size = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "ukalloc_max_alloc_size")) {
            stats.ukalloc_max_alloc_size = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "ukalloc_cur_nb_allocs")) {
            stats.ukalloc_cur_nb_allocs = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "ukalloc_tot_nb_allocs")) {
            stats.ukalloc_tot_nb_allocs = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "ukalloc_tot_nb_frees")) {
            stats.ukalloc_tot_nb_frees = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        }
    }

    if (!has_phase or !has_boot_id) return error.InvalidTelemetryRecord;
    return stats;
}

pub fn parseLinuxStats(line: []const u8) Error!LinuxServiceStats {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "LINUX_HTTP_SERVICE_STATS "))
        return error.InvalidTelemetryRecord;

    var stats: LinuxServiceStats = .{
        .phase = "",
        .boot_id = @splat('0'),
        .elapsed_ms = 0,
        .requests = 0,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .active_conns = 0,
        .peak_conns = 0,
        .total_conns = 0,
        .errors = 0,
        .status_200 = 0,
        .status_400 = 0,
        .status_413 = 0,
        .rss_bytes = 0,
        .max_rss_bytes = 0,
    };
    var has_phase = false;
    var has_boot_id = false;

    var tokens = std.mem.tokenizeScalar(u8, trimmed["LINUX_HTTP_SERVICE_STATS ".len..], ' ');
    while (tokens.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return error.InvalidTelemetryRecord;
        const key = tok[0..eq];
        const val = tok[eq + 1 ..];

        if (std.mem.eql(u8, key, "phase")) {
            stats.phase = val;
            has_phase = val.len > 0;
        } else if (std.mem.eql(u8, key, "boot_id")) {
            if (!isValidBootIdHex(val)) return error.InvalidBootIdHeader;
            @memcpy(&stats.boot_id, val[0..16]);
            has_boot_id = true;
        } else if (std.mem.eql(u8, key, "elapsed_ms")) {
            stats.elapsed_ms = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "requests")) {
            stats.requests = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "bytes_tx")) {
            stats.bytes_tx = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "bytes_rx")) {
            stats.bytes_rx = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "active_conns")) {
            stats.active_conns = std.fmt.parseInt(u32, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "peak_conns")) {
            stats.peak_conns = std.fmt.parseInt(u32, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "total_conns")) {
            stats.total_conns = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "errors")) {
            stats.errors = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "status_200")) {
            stats.status_200 = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "status_400")) {
            stats.status_400 = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "status_413")) {
            stats.status_413 = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "rss_bytes")) {
            stats.rss_bytes = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        } else if (std.mem.eql(u8, key, "max_rss_bytes")) {
            stats.max_rss_bytes = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTelemetryRecord;
        }
    }

    if (!has_phase or !has_boot_id) return error.InvalidTelemetryRecord;
    return stats;
}

pub fn runKeepAliveSession(
    allocator: Allocator,
    io: Io,
    address: Io.net.IpAddress,
    concurrency: u32,
    requests_per_conn: u32,
) !LoadSampleSummary {
    if (concurrency == 0 or requests_per_conn == 0) return error.InvalidArguments;
    const total_requests = @as(usize, concurrency) * @as(usize, requests_per_conn);
    const latencies = try allocator.alloc(u64, total_requests);
    defer allocator.free(latencies);

    const streams = try allocator.alloc(Io.net.Stream, concurrency);
    defer allocator.free(streams);

    var opened: usize = 0;
    defer {
        for (streams[0..opened]) |*stream| stream.close(io);
    }
    while (opened < concurrency) : (opened += 1) {
        streams[opened] = try Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    }

    const start_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
    var sample_idx: usize = 0;
    var total_bytes_rx: u64 = 0;
    var boot_id: [16]u8 = @splat('0');
    var have_boot_id = false;

    const keep_alive_req =
        "GET / HTTP/1.1\r\n" ++
        "Host: benchmark.local\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n";
    const close_req =
        "GET / HTTP/1.1\r\n" ++
        "Host: benchmark.local\r\n" ++
        "Connection: close\r\n" ++
        "\r\n";

    var round: u32 = 0;
    while (round < requests_per_conn) : (round += 1) {
        const is_last = (round + 1 == requests_per_conn);
        const req_bytes = if (is_last) close_req else keep_alive_req;

        for (streams) |*stream| {
            const req_start_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
            var wbuf: [512]u8 = undefined;
            var writer = stream.writer(io, &wbuf);
            try writer.interface.writeAll(req_bytes);
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
                    const hdr_bytes = hdr_end + 4;
                    if (filled >= hdr_bytes + canonical_body_bytes) break;
                }
            }

            const parsed = try parseHttpResponse(raw_resp[0..filled], true);
            if (parsed.status_code != 200) return error.InvalidStatusCode;
            if (parsed.keep_alive != !is_last) return error.InvalidConnectionHeader;
            if (!have_boot_id) {
                boot_id = parsed.boot_id;
                have_boot_id = true;
            } else if (!std.mem.eql(u8, &boot_id, &parsed.boot_id)) {
                return error.InvalidBootIdHeader;
            }

            const req_end_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
            latencies[sample_idx] = if (req_end_ns >= req_start_ns) req_end_ns - req_start_ns else 0;
            sample_idx += 1;
            total_bytes_rx += filled;
        }
    }

    const end_ns: u64 = @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
    const elapsed_ns = if (end_ns > start_ns) end_ns - start_ns else 1;

    std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
    const p50_ns = percentileSorted(latencies, 500);
    const p95_ns = percentileSorted(latencies, 950);
    const p99_ns = percentileSorted(latencies, 990);
    const p999_ns = percentileSorted(latencies, 999);
    const rps = (@as(f64, @floatFromInt(total_requests)) * 1_000_000_000.0) /
        @as(f64, @floatFromInt(elapsed_ns));

    return .{
        .concurrency = concurrency,
        .requests = total_requests,
        .bytes_rx = total_bytes_rx,
        .errors = 0,
        .elapsed_ns = elapsed_ns,
        .rps = rps,
        .p50_ns = p50_ns,
        .p95_ns = p95_ns,
        .p99_ns = p99_ns,
        .p999_ns = p999_ns,
        .boot_id = boot_id,
    };
}

fn percentileSorted(sorted: []const u64, permille: usize) u64 {
    if (sorted.len == 0) return 0;
    const idx = ((sorted.len - 1) * permille) / 1000;
    return sorted[idx];
}

pub fn validateComparisonReport(allocator: Allocator, raw_json: []const u8) !ValidatedComparisonReport {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidBenchmarkReport,
    };

    const schema = try jsonRequiredString(root, "schema_version");
    if (!std.mem.eql(u8, schema, schema_version)) return error.InvalidBenchmarkReport;

    const topology = switch (root.get("topology") orelse return error.InvalidBenchmarkReport) {
        .object => |obj| obj,
        else => return error.InvalidBenchmarkReport,
    };
    const vm_size = try allocator.dupe(u8, try jsonRequiredString(topology, "vm_size"));
    errdefer allocator.free(vm_size);
    const location = try allocator.dupe(u8, try jsonRequiredString(topology, "location"));
    errdefer allocator.free(location);
    const subnet_cidr = try allocator.dupe(u8, try jsonRequiredString(topology, "subnet_cidr"));
    errdefer allocator.free(subnet_cidr);
    const accelerated = try jsonRequiredBool(topology, "accelerated_networking");

    const unikraft_vm = switch (topology.get("unikraft_vm") orelse return error.TopologyMismatch) {
        .object => |obj| obj,
        else => return error.TopologyMismatch,
    };
    const linux_vm = switch (topology.get("linux_baseline_vm") orelse return error.TopologyMismatch) {
        .object => |obj| obj,
        else => return error.TopologyMismatch,
    };
    const loadgen_vm = switch (topology.get("loadgen_vm") orelse return error.TopologyMismatch) {
        .object => |obj| obj,
        else => return error.TopologyMismatch,
    };

    if (!std.mem.eql(u8, try jsonRequiredString(unikraft_vm, "vm_size"), vm_size) or
        !std.mem.eql(u8, try jsonRequiredString(linux_vm, "vm_size"), vm_size) or
        !std.mem.eql(u8, try jsonRequiredString(loadgen_vm, "vm_size"), vm_size))
    {
        return error.TopologyMismatch;
    }
    if ((try jsonRequiredBool(unikraft_vm, "accelerated_networking")) != accelerated or
        (try jsonRequiredBool(linux_vm, "accelerated_networking")) != accelerated or
        (try jsonRequiredBool(loadgen_vm, "accelerated_networking")) != accelerated)
    {
        return error.TopologyMismatch;
    }

    const uk_boot_str = try jsonRequiredString(unikraft_vm, "boot_id");
    const linux_boot_str = try jsonRequiredString(linux_vm, "boot_id");
    if (!isValidBootIdHex(uk_boot_str) or !isValidBootIdHex(linux_boot_str))
        return error.InvalidBootIdHeader;

    var uk_boot_id: [16]u8 = undefined;
    var linux_boot_id: [16]u8 = undefined;
    @memcpy(&uk_boot_id, uk_boot_str[0..16]);
    @memcpy(&linux_boot_id, linux_boot_str[0..16]);

    const memory = switch (root.get("memory") orelse return error.InvalidBenchmarkReport) {
        .object => |obj| obj,
        else => return error.InvalidBenchmarkReport,
    };
    const uk_idle_heap = try jsonRequiredU64(memory, "unikraft_idle_heap_bytes");
    const uk_peak_heap = try jsonRequiredU64(memory, "unikraft_load_peak_heap_bytes");
    const linux_idle_rss = try jsonRequiredU64(memory, "linux_idle_rss_bytes");
    const linux_peak_rss = try jsonRequiredU64(memory, "linux_load_peak_rss_bytes");
    if (uk_peak_heap < uk_idle_heap or linux_peak_rss < linux_idle_rss)
        return error.InvalidBenchmarkReport;

    const tiers_arr = switch (root.get("concurrency_tiers") orelse return error.InvalidBenchmarkReport) {
        .array => |arr| arr.items,
        else => return error.InvalidBenchmarkReport,
    };
    if (tiers_arr.len != expected_concurrency_tiers.len) return error.MissingConcurrencyTier;

    var tiers: [expected_concurrency_tiers.len]TierComparison = undefined;
    for (expected_concurrency_tiers, 0..) |expected_c, idx| {
        const item = switch (tiers_arr[idx]) {
            .object => |obj| obj,
            else => return error.InvalidBenchmarkReport,
        };
        const c: u32 = @intCast(try jsonRequiredU64(item, "concurrency"));
        if (c != expected_c) return error.MissingConcurrencyTier;
        const duration_s: u32 = @intCast(try jsonRequiredU64(item, "duration_seconds"));
        if (duration_s == 0) return error.InvalidBenchmarkReport;

        const uk_obj = switch (item.get("unikraft") orelse return error.InvalidBenchmarkReport) {
            .object => |obj| obj,
            else => return error.InvalidBenchmarkReport,
        };
        const lx_obj = switch (item.get("linux_baseline") orelse return error.InvalidBenchmarkReport) {
            .object => |obj| obj,
            else => return error.InvalidBenchmarkReport,
        };

        const uk_rps = try jsonRequiredF64(uk_obj, "rps");
        const lx_rps = try jsonRequiredF64(lx_obj, "rps");
        const uk_p50 = try jsonRequiredF64(uk_obj, "p50_us");
        const uk_p95 = try jsonRequiredF64(uk_obj, "p95_us");
        const uk_p99 = try jsonRequiredF64(uk_obj, "p99_us");
        const uk_p999 = try jsonRequiredF64(uk_obj, "p999_us");
        const lx_p50 = try jsonRequiredF64(lx_obj, "p50_us");
        const lx_p95 = try jsonRequiredF64(lx_obj, "p95_us");
        const lx_p99 = try jsonRequiredF64(lx_obj, "p99_us");
        const lx_p999 = try jsonRequiredF64(lx_obj, "p999_us");
        const uk_err = try jsonRequiredU64(uk_obj, "errors");
        const lx_err = try jsonRequiredU64(lx_obj, "errors");

        if (uk_rps <= 0 or lx_rps <= 0) return error.InvalidBenchmarkReport;
        if (!(uk_p50 <= uk_p95 and uk_p95 <= uk_p99 and uk_p99 <= uk_p999))
            return error.InvalidBenchmarkReport;
        if (!(lx_p50 <= lx_p95 and lx_p95 <= lx_p99 and lx_p99 <= lx_p999))
            return error.InvalidBenchmarkReport;
        if (uk_err != 0 or lx_err != 0)
            return error.InvalidBenchmarkReport;

        tiers[idx] = .{
            .concurrency = c,
            .duration_seconds = duration_s,
            .unikraft_rps = uk_rps,
            .linux_rps = lx_rps,
            .unikraft_p50_us = uk_p50,
            .unikraft_p95_us = uk_p95,
            .unikraft_p99_us = uk_p99,
            .unikraft_p999_us = uk_p999,
            .linux_p50_us = lx_p50,
            .linux_p95_us = lx_p95,
            .linux_p99_us = lx_p99,
            .linux_p999_us = lx_p999,
            .unikraft_errors = uk_err,
            .linux_errors = lx_err,
        };
    }

    return .{
        .vm_size = vm_size,
        .location = location,
        .subnet_cidr = subnet_cidr,
        .accelerated_networking = accelerated,
        .unikraft_boot_id = uk_boot_id,
        .linux_boot_id = linux_boot_id,
        .unikraft_idle_heap_bytes = uk_idle_heap,
        .unikraft_load_peak_heap_bytes = uk_peak_heap,
        .linux_idle_rss_bytes = linux_idle_rss,
        .linux_load_peak_rss_bytes = linux_peak_rss,
        .tiers = tiers,
    };
}

pub fn freeValidatedReport(allocator: Allocator, report: ValidatedComparisonReport) void {
    allocator.free(report.vm_size);
    allocator.free(report.location);
    allocator.free(report.subnet_cidr);
}

pub fn renderMarkdownReport(allocator: Allocator, report: ValidatedComparisonReport) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try out.writer.print(
        \\# Hyper-V Persistent HTTP/1.1 Benchmark Report
        \\
        \\- **Schema**: `{s}`
        \\- **VM Size**: `{s}` (`{s}`, subnet `{s}`, accelerated networking: `{}`)
        \\- **Unikraft Boot ID**: `{s}`
        \\- **Linux Baseline Boot ID**: `{s}`
        \\- **Unikraft Heap (idle / peak)**: `{d}` B / `{d}` B
        \\- **Linux Baseline RSS (idle / peak)**: `{d}` B / `{d}` B
        \\
        \\| Concurrency | Duration (s) | Unikraft RPS | Linux RPS | Unikraft p50/p95/p99/p99.9 (us) | Linux p50/p95/p99/p99.9 (us) | Errors (UK/Linux) |
        \\|---:|---:|---:|---:|---:|---:|---:|
        \\
    , .{
        schema_version,
        report.vm_size,
        report.location,
        report.subnet_cidr,
        report.accelerated_networking,
        report.unikraft_boot_id[0..],
        report.linux_boot_id[0..],
        report.unikraft_idle_heap_bytes,
        report.unikraft_load_peak_heap_bytes,
        report.linux_idle_rss_bytes,
        report.linux_load_peak_rss_bytes,
    });

    for (report.tiers) |tier| {
        try out.writer.print(
            "| {d} | {d} | {d:.1} | {d:.1} | {d:.1} / {d:.1} / {d:.1} / {d:.1} | {d:.1} / {d:.1} / {d:.1} / {d:.1} | {d} / {d} |\n",
            .{
                tier.concurrency,
                tier.duration_seconds,
                tier.unikraft_rps,
                tier.linux_rps,
                tier.unikraft_p50_us,
                tier.unikraft_p95_us,
                tier.unikraft_p99_us,
                tier.unikraft_p999_us,
                tier.linux_p50_us,
                tier.linux_p95_us,
                tier.linux_p99_us,
                tier.linux_p999_us,
                tier.unikraft_errors,
                tier.linux_errors,
            },
        );
    }

    return try out.toOwnedSlice();
}

fn jsonRequiredString(object: std.json.ObjectMap, key: []const u8) Error![]const u8 {
    const val = object.get(key) orelse return error.InvalidBenchmarkReport;
    return switch (val) {
        .string => |s| if (s.len > 0) s else error.InvalidBenchmarkReport,
        else => error.InvalidBenchmarkReport,
    };
}

fn jsonRequiredBool(object: std.json.ObjectMap, key: []const u8) Error!bool {
    const val = object.get(key) orelse return error.InvalidBenchmarkReport;
    return switch (val) {
        .bool => |b| b,
        else => error.InvalidBenchmarkReport,
    };
}

fn jsonRequiredU64(object: std.json.ObjectMap, key: []const u8) Error!u64 {
    const val = object.get(key) orelse return error.InvalidBenchmarkReport;
    return switch (val) {
        .integer => |n| if (n >= 0) @intCast(n) else error.InvalidBenchmarkReport,
        else => error.InvalidBenchmarkReport,
    };
}

fn jsonRequiredF64(object: std.json.ObjectMap, key: []const u8) Error!f64 {
    const val = object.get(key) orelse return error.InvalidBenchmarkReport;
    return switch (val) {
        .float => |f| f,
        .integer => |n| @floatFromInt(n),
        else => error.InvalidBenchmarkReport,
    };
}
