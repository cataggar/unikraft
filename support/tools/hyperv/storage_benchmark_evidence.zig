// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const schema_version: u32 = 1;
pub const matrix_patterns = [_][]const u8{ "seq", "strided" };
pub const matrix_req_bytes = [_]u32{ 4096, 16384, 65536, 131072 };
pub const matrix_queue_depths = [_]u32{ 1, 2, 4, 8, 16, 32 };
pub const matrix_cell_count: usize =
    matrix_patterns.len * matrix_req_bytes.len * matrix_queue_depths.len;
pub const max_trials: usize = 10;

pub const EnvironmentKind = enum {
    private_nested_kvm,
    azure_gen2,

    pub fn asText(self: EnvironmentKind) []const u8 {
        return switch (self) {
            .private_nested_kvm => "private-nested-kvm",
            .azure_gen2 => "azure-gen2",
        };
    }
};

pub const Provenance = struct {
    commit_sha: [40]u8,
    config_sha256: [64]u8,
    image_sha256: [64]u8,
    environment_kind: EnvironmentKind,
    host_or_sku: []const u8,
    storage_backing: []const u8,
};

pub const ExpectedContract = struct {
    sectors: u64 = 8388608,
    sector_size: u32 = 512,
    lun: u8 = 7,
    identity_policy: u8 = 2,
    max_transfer_bytes: u32 = 131072,
    configured_queue_depth: u32 = 32,
    max_transfer_pages: u32 = 33,
    max_slots: u32 = 32,
    warmup_ops: u32 = 64,
    steady_ops: u32 = 256,
    trials: u32 = 3,
    expected_pre_seed_crc32: ?u32 = null,
    expected_pre_fixture_crc32: ?u32 = null,
};

pub const LatencyStats = struct {
    min_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    mean_ns: u64,

    pub fn validateOrder(self: LatencyStats) !void {
        if (self.min_ns > self.p50_ns or
            self.p50_ns > self.p95_ns or
            self.p95_ns > self.p99_ns or
            self.p99_ns > self.max_ns or
            self.mean_ns < self.min_ns or
            self.mean_ns > self.max_ns)
        {
            return error.InvalidLatencyPercentiles;
        }
    }
};

pub const TrialRecord = struct {
    cell: u32,
    pattern: [8]u8,
    pattern_len: u8,
    req_bytes: u32,
    req_sectors: u32,
    qd: u32,
    trial: u32,
    warmup_ops: u32,
    samples: u32,
    bytes_read: u64,
    elapsed_ns: u64,
    iops: u64,
    bytes_per_s: u64,
    max_in_flight: u32,
    saturation_count: u32,
    sub_comp: LatencyStats,
    comp_res: LatencyStats,

    pub fn patternSlice(self: *const TrialRecord) []const u8 {
        return self.pattern[0..self.pattern_len];
    }
};

pub const CellRecord = struct {
    cell: u32,
    pattern: [8]u8,
    pattern_len: u8,
    req_bytes: u32,
    req_sectors: u32,
    qd: u32,
    trials_count: u32,
    warmup_ops: u32,
    total_samples: u32,
    total_bytes: u64,
    max_in_flight: u32,
    saturation_count: u32,
    min_iops: u64,
    median_iops: u64,
    max_iops: u64,
    min_bytes_per_s: u64,
    median_bytes_per_s: u64,
    max_bytes_per_s: u64,
    trials: [max_trials]TrialRecord,

    pub fn patternSlice(self: *const CellRecord) []const u8 {
        return self.pattern[0..self.pattern_len];
    }
};

pub const BeginRecord = struct {
    schema: u32,
    blkdev_id: u16,
    controller: u16,
    channel: u32,
    path_id: u8,
    target_id: u8,
    lun: u8,
    identity_policy: u8,
    sectors: u64,
    sector_size: u32,
    max_transfer_bytes: u32,
    configured_queue_depth: u32,
    max_transfer_pages: u32,
    max_slots: u32,
    warmup_ops: u32,
    steady_ops: u32,
    trials: u32,
    discovery_ns: u64,
    pre_seed_crc32: u32,
    pre_fixture_crc32: u32,
};

pub const OkRecord = struct {
    schema: u32,
    lun: u8,
    cells: u32,
    total_trials: u32,
    total_warmup_ops: u64,
    total_steady_ops: u64,
    total_bytes_read: u64,
    global_max_in_flight: u32,
    total_saturation_count: u64,
    pre_seed_crc32: u32,
    post_seed_crc32: u32,
    pre_fixture_crc32: u32,
    post_fixture_crc32: u32,
    post_seed_verified: u8,
    alloc_ifstats: u8,
    alloc_steady_allocs: u64,
    alloc_steady_frees: u64,
    alloc_steady_enomem: u64,
    alloc_cur_mem_bytes: u64,
    alloc_max_mem_bytes: u64,
};

pub const BenchmarkEvidence = struct {
    provenance: Provenance,
    transcript_sha256: [64]u8,
    begin: BeginRecord,
    cells: [matrix_cell_count]CellRecord,
    ok: OkRecord,
};

fn validateLowerHex(slice: []const u8) !void {
    var all_zero = true;
    for (slice) |c| {
        const is_digit = c >= '0' and c <= '9';
        const is_hex = c >= 'a' and c <= 'f';
        if (!is_digit and !is_hex) return error.InvalidProvenance;
        if (c != '0') all_zero = false;
    }
    if (all_zero) return error.InvalidProvenance;
}

pub fn validateProvenance(p: Provenance) !void {
    try validateLowerHex(&p.commit_sha);
    try validateLowerHex(&p.config_sha256);
    try validateLowerHex(&p.image_sha256);
    if (p.host_or_sku.len == 0 or p.storage_backing.len == 0)
        return error.InvalidProvenance;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const lut = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (digest, 0..) |b, i| {
        out[i * 2] = lut[b >> 4];
        out[i * 2 + 1] = lut[b & 0x0f];
    }
    return out;
}

fn kvValue(token: []const u8, key: []const u8) ![]const u8 {
    if (token.len <= key.len + 1) return error.MalformedRecord;
    if (!std.mem.startsWith(u8, token, key)) return error.MalformedRecord;
    if (token[key.len] != '=') return error.MalformedRecord;
    return token[key.len + 1 ..];
}

fn parseDec(comptime T: type, text: []const u8) !T {
    if (text.len == 0) return error.MalformedRecord;
    return std.fmt.parseUnsigned(T, text, 10) catch error.MalformedRecord;
}

fn parseHex32(text: []const u8) !u32 {
    if (text.len != 8) return error.MalformedRecord;
    for (text) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f')))
            return error.MalformedRecord;
    }
    return std.fmt.parseUnsigned(u32, text, 16) catch error.MalformedRecord;
}

fn splitExact(comptime N: usize, line: []const u8, sep: u8) ![N][]const u8 {
    var out: [N][]const u8 = undefined;
    var it = std.mem.splitScalar(u8, line, sep);
    for (0..N) |i| {
        const part = it.next() orelse return error.MalformedRecord;
        if (part.len == 0) return error.MalformedRecord;
        out[i] = part;
    }
    if (it.next() != null) return error.MalformedRecord;
    return out;
}

fn expectedCellParams(cell_idx: usize) struct {
    pattern: []const u8,
    req_bytes: u32,
    qd: u32,
} {
    const per_pattern = matrix_req_bytes.len * matrix_queue_depths.len;
    const p_idx = cell_idx / per_pattern;
    const rem = cell_idx % per_pattern;
    const r_idx = rem / matrix_queue_depths.len;
    const q_idx = rem % matrix_queue_depths.len;
    return .{
        .pattern = matrix_patterns[p_idx],
        .req_bytes = matrix_req_bytes[r_idx],
        .qd = matrix_queue_depths[q_idx],
    };
}

pub fn parseAndValidate(
    transcript: []const u8,
    expected: ExpectedContract,
    provenance: Provenance,
) !BenchmarkEvidence {
    try validateProvenance(provenance);
    if (expected.trials == 0 or expected.trials > max_trials or
        expected.steady_ops == 0 or expected.warmup_ops == 0)
        return error.InvalidExpectedContract;
    if (transcript.len == 0 or transcript.len > 512 * 1024)
        return error.InvalidTranscriptLength;
    if (!std.unicode.utf8ValidateSlice(transcript))
        return error.InvalidTranscriptEncoding;

    var begin_opt: ?BeginRecord = null;
    var ok_opt: ?OkRecord = null;
    var saw_final_pass = false;
    var cells: [matrix_cell_count]CellRecord = undefined;
    var pending_trials: [max_trials]TrialRecord = undefined;
    var expected_cell_idx: usize = 0;
    var expected_trial_idx: u32 = 0;
    var global_max_inflight: u32 = 0;
    var total_saturation: u64 = 0;
    var total_warmup_ops: u64 = 0;
    var total_steady_ops: u64 = 0;
    var total_bytes_read: u64 = 0;

    var lines = std.mem.splitScalar(u8, transcript, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;

        if (std.mem.indexOf(u8, line, "FINAL FAIL") != null or
            std.mem.indexOf(u8, line, "FINAL UNAVAILABLE") != null or
            std.mem.indexOf(u8, line, "Unikraft Crash") != null or
            std.mem.indexOf(u8, line, "Assertion failure") != null or
            std.mem.indexOf(u8, line, "Exception Type") != null)
        {
            return error.GuestBenchmarkFailed;
        }

        if (std.mem.startsWith(u8, line, "UK_HYPERV_STORAGE_BENCHMARK_BEGIN ")) {
            if (begin_opt != null or expected_cell_idx != 0 or expected_trial_idx != 0)
                return error.InvalidRecordOrder;
            const t = try splitExact(21, line, ' ');
            const schema = try parseDec(u32, try kvValue(t[1], "schema"));
            const blkdev_id = try parseDec(u16, try kvValue(t[2], "id"));
            const controller = try parseDec(u16, try kvValue(t[3], "controller"));
            const channel = try parseDec(u32, try kvValue(t[4], "channel"));
            const addr = try splitExact(3, try kvValue(t[5], "address"), ':');
            const path_id = try parseDec(u8, addr[0]);
            const target_id = try parseDec(u8, addr[1]);
            const lun = try parseDec(u8, addr[2]);
            const policy = try parseDec(u8, try kvValue(t[6], "identity_policy"));
            const session_state = try kvValue(t[7], "session_state");
            const write_auth = try parseDec(u8, try kvValue(t[8], "write_authorized"));
            const sectors = try parseDec(u64, try kvValue(t[9], "sectors"));
            const sector_size = try parseDec(u32, try kvValue(t[10], "sector_size"));
            const max_transfer_bytes = try parseDec(u32, try kvValue(t[11], "max_transfer_bytes"));
            const configured_qd = try parseDec(u32, try kvValue(t[12], "configured_queue_depth"));
            const max_transfer_pages = try parseDec(u32, try kvValue(t[13], "max_transfer_pages"));
            const max_slots = try parseDec(u32, try kvValue(t[14], "max_slots"));
            const warmup_ops = try parseDec(u32, try kvValue(t[15], "warmup_ops"));
            const steady_ops = try parseDec(u32, try kvValue(t[16], "steady_ops"));
            const trials = try parseDec(u32, try kvValue(t[17], "trials"));
            const discovery_ns = try parseDec(u64, try kvValue(t[18], "discovery_ns"));
            const pre_seed_crc32 = try parseHex32(try kvValue(t[19], "pre_seed_crc32"));
            const pre_fixture_crc32 = try parseHex32(try kvValue(t[20], "pre_fixture_crc32"));

            if (schema != schema_version)
                return error.UnsupportedSchema;
            if (!std.mem.eql(u8, session_state, "read_only") or write_auth != 0)
                return error.WriteAuthorizationForbidden;
            if (path_id != 0 or target_id != 0 or lun != expected.lun or
                policy != expected.identity_policy or
                sectors != expected.sectors or
                sector_size != expected.sector_size or
                max_transfer_bytes != expected.max_transfer_bytes or
                configured_qd != expected.configured_queue_depth or
                max_transfer_pages != expected.max_transfer_pages or
                max_slots != expected.max_slots or
                warmup_ops != expected.warmup_ops or
                steady_ops != expected.steady_ops or
                trials != expected.trials)
            {
                return error.ContractMismatch;
            }
            if (expected.expected_pre_seed_crc32) |exp_seed| {
                if (pre_seed_crc32 != exp_seed) return error.SeedDigestMismatch;
            }
            if (expected.expected_pre_fixture_crc32) |exp_fix| {
                if (pre_fixture_crc32 != exp_fix) return error.FixtureDigestMismatch;
            }

            begin_opt = .{
                .schema = schema,
                .blkdev_id = blkdev_id,
                .controller = controller,
                .channel = channel,
                .path_id = path_id,
                .target_id = target_id,
                .lun = lun,
                .identity_policy = policy,
                .sectors = sectors,
                .sector_size = sector_size,
                .max_transfer_bytes = max_transfer_bytes,
                .configured_queue_depth = configured_qd,
                .max_transfer_pages = max_transfer_pages,
                .max_slots = max_slots,
                .warmup_ops = warmup_ops,
                .steady_ops = steady_ops,
                .trials = trials,
                .discovery_ns = discovery_ns,
                .pre_seed_crc32 = pre_seed_crc32,
                .pre_fixture_crc32 = pre_fixture_crc32,
            };
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_STORAGE_BENCHMARK_TRIAL ")) {
            const begin = begin_opt orelse return error.InvalidRecordOrder;
            if (ok_opt != null or expected_cell_idx >= matrix_cell_count or
                expected_trial_idx >= begin.trials)
                return error.InvalidRecordOrder;

            const t = try splitExact(27, line, ' ');
            const cell = try parseDec(u32, try kvValue(t[1], "cell"));
            const pat = try kvValue(t[2], "pattern");
            const req_bytes = try parseDec(u32, try kvValue(t[3], "req_bytes"));
            const req_sectors = try parseDec(u32, try kvValue(t[4], "req_sectors"));
            const qd = try parseDec(u32, try kvValue(t[5], "qd"));
            const trial = try parseDec(u32, try kvValue(t[6], "trial"));
            const warmup_ops = try parseDec(u32, try kvValue(t[7], "warmup_ops"));
            const samples = try parseDec(u32, try kvValue(t[8], "samples"));
            const bytes_read = try parseDec(u64, try kvValue(t[9], "bytes_read"));
            const elapsed_ns = try parseDec(u64, try kvValue(t[10], "elapsed_ns"));
            const iops = try parseDec(u64, try kvValue(t[11], "iops"));
            const bytes_per_s = try parseDec(u64, try kvValue(t[12], "bytes_per_s"));
            const max_in_flight = try parseDec(u32, try kvValue(t[13], "max_in_flight"));
            const sat_count = try parseDec(u32, try kvValue(t[14], "saturation_count"));

            const sub_comp = LatencyStats{
                .min_ns = try parseDec(u64, try kvValue(t[15], "sub_comp_min_ns")),
                .p50_ns = try parseDec(u64, try kvValue(t[16], "sub_comp_p50_ns")),
                .p95_ns = try parseDec(u64, try kvValue(t[17], "sub_comp_p95_ns")),
                .p99_ns = try parseDec(u64, try kvValue(t[18], "sub_comp_p99_ns")),
                .max_ns = try parseDec(u64, try kvValue(t[19], "sub_comp_max_ns")),
                .mean_ns = try parseDec(u64, try kvValue(t[20], "sub_comp_mean_ns")),
            };
            const comp_res = LatencyStats{
                .min_ns = try parseDec(u64, try kvValue(t[21], "comp_res_min_ns")),
                .p50_ns = try parseDec(u64, try kvValue(t[22], "comp_res_p50_ns")),
                .p95_ns = try parseDec(u64, try kvValue(t[23], "comp_res_p95_ns")),
                .p99_ns = try parseDec(u64, try kvValue(t[24], "comp_res_p99_ns")),
                .max_ns = try parseDec(u64, try kvValue(t[25], "comp_res_max_ns")),
                .mean_ns = try parseDec(u64, try kvValue(t[26], "comp_res_mean_ns")),
            };

            const exp_cell = expectedCellParams(expected_cell_idx);
            if (cell != expected_cell_idx or
                !std.mem.eql(u8, pat, exp_cell.pattern) or
                req_bytes != exp_cell.req_bytes or
                req_sectors * begin.sector_size != req_bytes or
                qd != exp_cell.qd or
                trial != expected_trial_idx or
                warmup_ops != begin.warmup_ops or
                samples != begin.steady_ops or
                bytes_read != @as(u64, samples) * @as(u64, req_bytes) or
                elapsed_ns == 0)
            {
                return error.MatrixCellMismatch;
            }
            if (max_in_flight == 0 or max_in_flight > qd or
                max_in_flight > begin.configured_queue_depth)
            {
                return error.InvalidInFlightCount;
            }
            try sub_comp.validateOrder();
            try comp_res.validateOrder();

            var rec = TrialRecord{
                .cell = cell,
                .pattern = @splat(0),
                .pattern_len = @intCast(pat.len),
                .req_bytes = req_bytes,
                .req_sectors = req_sectors,
                .qd = qd,
                .trial = trial,
                .warmup_ops = warmup_ops,
                .samples = samples,
                .bytes_read = bytes_read,
                .elapsed_ns = elapsed_ns,
                .iops = iops,
                .bytes_per_s = bytes_per_s,
                .max_in_flight = max_in_flight,
                .saturation_count = sat_count,
                .sub_comp = sub_comp,
                .comp_res = comp_res,
            };
            @memcpy(rec.pattern[0..pat.len], pat);
            pending_trials[expected_trial_idx] = rec;
            expected_trial_idx += 1;
            if (max_in_flight > global_max_inflight)
                global_max_inflight = max_in_flight;
            total_saturation += sat_count;
            total_steady_ops += samples;
            total_bytes_read += bytes_read;
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_STORAGE_BENCHMARK_CELL ")) {
            const begin = begin_opt orelse return error.InvalidRecordOrder;
            if (ok_opt != null or expected_cell_idx >= matrix_cell_count or
                expected_trial_idx != begin.trials)
                return error.InvalidRecordOrder;

            const t = try splitExact(18, line, ' ');
            const cell = try parseDec(u32, try kvValue(t[1], "cell"));
            const pat = try kvValue(t[2], "pattern");
            const req_bytes = try parseDec(u32, try kvValue(t[3], "req_bytes"));
            const req_sectors = try parseDec(u32, try kvValue(t[4], "req_sectors"));
            const qd = try parseDec(u32, try kvValue(t[5], "qd"));
            const trials_count = try parseDec(u32, try kvValue(t[6], "trials"));
            const warmup_ops = try parseDec(u32, try kvValue(t[7], "warmup_ops"));
            const total_samples = try parseDec(u32, try kvValue(t[8], "total_samples"));
            const total_bytes = try parseDec(u64, try kvValue(t[9], "total_bytes"));
            const max_in_flight = try parseDec(u32, try kvValue(t[10], "max_in_flight"));
            const sat_count = try parseDec(u32, try kvValue(t[11], "saturation_count"));
            const min_iops = try parseDec(u64, try kvValue(t[12], "min_iops"));
            const median_iops = try parseDec(u64, try kvValue(t[13], "median_iops"));
            const max_iops = try parseDec(u64, try kvValue(t[14], "max_iops"));
            const min_bw = try parseDec(u64, try kvValue(t[15], "min_bytes_per_s"));
            const median_bw = try parseDec(u64, try kvValue(t[16], "median_bytes_per_s"));
            const max_bw = try parseDec(u64, try kvValue(t[17], "max_bytes_per_s"));

            const exp_cell = expectedCellParams(expected_cell_idx);
            if (cell != expected_cell_idx or
                !std.mem.eql(u8, pat, exp_cell.pattern) or
                req_bytes != exp_cell.req_bytes or
                req_sectors * begin.sector_size != req_bytes or
                qd != exp_cell.qd or
                trials_count != begin.trials or
                warmup_ops != begin.warmup_ops or
                total_samples != begin.trials * begin.steady_ops or
                total_bytes != @as(u64, total_samples) * @as(u64, req_bytes) or
                min_iops > median_iops or median_iops > max_iops or
                min_bw > median_bw or median_bw > max_bw)
            {
                return error.MatrixCellMismatch;
            }

            var calc_max_inflight: u32 = 0;
            var calc_sat: u32 = 0;
            for (0..begin.trials) |ti| {
                if (pending_trials[ti].max_in_flight > calc_max_inflight)
                    calc_max_inflight = pending_trials[ti].max_in_flight;
                calc_sat += pending_trials[ti].saturation_count;
            }
            if (max_in_flight != calc_max_inflight or sat_count != calc_sat)
                return error.CellAggregationMismatch;

            var cell_rec = CellRecord{
                .cell = cell,
                .pattern = @splat(0),
                .pattern_len = @intCast(pat.len),
                .req_bytes = req_bytes,
                .req_sectors = req_sectors,
                .qd = qd,
                .trials_count = trials_count,
                .warmup_ops = warmup_ops,
                .total_samples = total_samples,
                .total_bytes = total_bytes,
                .max_in_flight = max_in_flight,
                .saturation_count = sat_count,
                .min_iops = min_iops,
                .median_iops = median_iops,
                .max_iops = max_iops,
                .min_bytes_per_s = min_bw,
                .median_bytes_per_s = median_bw,
                .max_bytes_per_s = max_bw,
                .trials = pending_trials,
            };
            @memcpy(cell_rec.pattern[0..pat.len], pat);
            cells[expected_cell_idx] = cell_rec;
            expected_cell_idx += 1;
            expected_trial_idx = 0;
            total_warmup_ops += warmup_ops;
            total_bytes_read += @as(u64, warmup_ops) * @as(u64, req_bytes);
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_STORAGE_BENCHMARK_OK ")) {
            const begin = begin_opt orelse return error.InvalidRecordOrder;
            if (ok_opt != null or expected_cell_idx != matrix_cell_count or
                expected_trial_idx != 0)
                return error.InvalidRecordOrder;

            const t = try splitExact(23, line, ' ');
            const schema = try parseDec(u32, try kvValue(t[1], "schema"));
            const lun = try parseDec(u8, try kvValue(t[2], "lun"));
            const session_state = try kvValue(t[3], "session_state");
            const write_auth = try parseDec(u8, try kvValue(t[4], "write_authorized"));
            const cells_count = try parseDec(u32, try kvValue(t[5], "cells"));
            const total_trials = try parseDec(u32, try kvValue(t[6], "total_trials"));
            const warmup_tot = try parseDec(u64, try kvValue(t[7], "total_warmup_ops"));
            const steady_tot = try parseDec(u64, try kvValue(t[8], "total_steady_ops"));
            const bytes_tot = try parseDec(u64, try kvValue(t[9], "total_bytes_read"));
            const glob_inflight = try parseDec(u32, try kvValue(t[10], "global_max_in_flight"));
            const sat_tot = try parseDec(u64, try kvValue(t[11], "total_saturation_count"));
            const pre_seed = try parseHex32(try kvValue(t[12], "pre_seed_crc32"));
            const post_seed = try parseHex32(try kvValue(t[13], "post_seed_crc32"));
            const pre_fix = try parseHex32(try kvValue(t[14], "pre_fixture_crc32"));
            const post_fix = try parseHex32(try kvValue(t[15], "post_fixture_crc32"));
            const post_verified = try parseDec(u8, try kvValue(t[16], "post_seed_verified"));
            const alloc_ifstats = try parseDec(u8, try kvValue(t[17], "alloc_ifstats"));
            const alloc_allocs = try parseDec(u64, try kvValue(t[18], "alloc_steady_allocs"));
            const alloc_frees = try parseDec(u64, try kvValue(t[19], "alloc_steady_frees"));
            const alloc_enomem = try parseDec(u64, try kvValue(t[20], "alloc_steady_enomem"));
            const alloc_cur = try parseDec(u64, try kvValue(t[21], "alloc_cur_mem_bytes"));
            const alloc_max = try parseDec(u64, try kvValue(t[22], "alloc_max_mem_bytes"));

            if (schema != schema_version)
                return error.UnsupportedSchema;
            if (!std.mem.eql(u8, session_state, "read_only") or write_auth != 0)
                return error.WriteAuthorizationForbidden;
            if (lun != begin.lun or
                cells_count != matrix_cell_count or
                total_trials != matrix_cell_count * begin.trials or
                warmup_tot != total_warmup_ops or
                steady_tot != total_steady_ops or
                bytes_tot != total_bytes_read or
                glob_inflight != global_max_inflight or
                sat_tot != total_saturation)
            {
                return error.SummaryLedgerMismatch;
            }
            if (post_verified != 1 or
                pre_seed != begin.pre_seed_crc32 or
                post_seed != pre_seed or
                pre_fix != begin.pre_fixture_crc32 or
                post_fix != pre_fix)
            {
                return error.PostBenchmarkSeedDrift;
            }
            if (alloc_ifstats != 1 or alloc_allocs != 0 or alloc_frees != 0 or
                alloc_enomem != 0)
            {
                return error.SteadyStateAllocatorChurn;
            }

            ok_opt = .{
                .schema = schema,
                .lun = lun,
                .cells = cells_count,
                .total_trials = total_trials,
                .total_warmup_ops = warmup_tot,
                .total_steady_ops = steady_tot,
                .total_bytes_read = bytes_tot,
                .global_max_in_flight = glob_inflight,
                .total_saturation_count = sat_tot,
                .pre_seed_crc32 = pre_seed,
                .post_seed_crc32 = post_seed,
                .pre_fixture_crc32 = pre_fix,
                .post_fixture_crc32 = post_fix,
                .post_seed_verified = post_verified,
                .alloc_ifstats = alloc_ifstats,
                .alloc_steady_allocs = alloc_allocs,
                .alloc_steady_frees = alloc_frees,
                .alloc_steady_enomem = alloc_enomem,
                .alloc_cur_mem_bytes = alloc_cur,
                .alloc_max_mem_bytes = alloc_max,
            };
        } else if (std.mem.eql(u8, line, "HYPERV_STORAGE_BENCHMARK FINAL PASS")) {
            if (ok_opt == null or saw_final_pass)
                return error.InvalidRecordOrder;
            saw_final_pass = true;
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_STORAGE_BENCHMARK_") or
            std.mem.startsWith(u8, line, "HYPERV_STORAGE_BENCHMARK FINAL "))
        {
            return error.UnknownBenchmarkRecord;
        }
    }

    if (begin_opt == null or ok_opt == null or !saw_final_pass or
        expected_cell_idx != matrix_cell_count)
    {
        return error.IncompleteTranscript;
    }

    return .{
        .provenance = provenance,
        .transcript_sha256 = sha256Hex(transcript),
        .begin = begin_opt.?,
        .cells = cells,
        .ok = ok_opt.?,
    };
}

pub fn emitJsonReport(
    allocator: std.mem.Allocator,
    ev: *const BenchmarkEvidence,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;

    try w.print(
        "{{\n" ++
            "  \"schema\": {d},\n" ++
            "  \"provenance\": {{\n" ++
            "    \"commit_sha\": \"{s}\",\n" ++
            "    \"config_sha256\": \"{s}\",\n" ++
            "    \"image_sha256\": \"{s}\",\n" ++
            "    \"transcript_sha256\": \"{s}\",\n" ++
            "    \"environment_kind\": \"{s}\",\n" ++
            "    \"host_or_sku\": \"{s}\",\n" ++
            "    \"storage_backing\": \"{s}\"\n" ++
            "  }},\n" ++
            "  \"target\": {{\n" ++
            "    \"blkdev_id\": {d},\n" ++
            "    \"controller\": {d},\n" ++
            "    \"channel\": {d},\n" ++
            "    \"address\": \"{d}:{d}:{d}\",\n" ++
            "    \"identity_policy\": {d},\n" ++
            "    \"session_state\": \"read_only\",\n" ++
            "    \"write_authorized\": 0,\n" ++
            "    \"sectors\": {d},\n" ++
            "    \"sector_size\": {d},\n" ++
            "    \"max_transfer_bytes\": {d},\n" ++
            "    \"configured_queue_depth\": {d},\n" ++
            "    \"max_transfer_pages\": {d},\n" ++
            "    \"max_slots\": {d},\n" ++
            "    \"discovery_ns\": {d}\n" ++
            "  }},\n" ++
            "  \"verification\": {{\n" ++
            "    \"pre_seed_crc32\": \"{x:0>8}\",\n" ++
            "    \"post_seed_crc32\": \"{x:0>8}\",\n" ++
            "    \"pre_fixture_crc32\": \"{x:0>8}\",\n" ++
            "    \"post_fixture_crc32\": \"{x:0>8}\",\n" ++
            "    \"post_seed_verified\": true,\n" ++
            "    \"alloc_ifstats\": {d},\n" ++
            "    \"alloc_steady_allocs\": {d},\n" ++
            "    \"alloc_steady_frees\": {d},\n" ++
            "    \"alloc_steady_enomem\": {d},\n" ++
            "    \"global_max_in_flight\": {d},\n" ++
            "    \"total_saturation_count\": {d}\n" ++
            "  }},\n" ++
            "  \"cells\": [\n",
        .{
            ev.begin.schema,
            ev.provenance.commit_sha,
            ev.provenance.config_sha256,
            ev.provenance.image_sha256,
            ev.transcript_sha256,
            ev.provenance.environment_kind.asText(),
            ev.provenance.host_or_sku,
            ev.provenance.storage_backing,
            ev.begin.blkdev_id,
            ev.begin.controller,
            ev.begin.channel,
            ev.begin.path_id,
            ev.begin.target_id,
            ev.begin.lun,
            ev.begin.identity_policy,
            ev.begin.sectors,
            ev.begin.sector_size,
            ev.begin.max_transfer_bytes,
            ev.begin.configured_queue_depth,
            ev.begin.max_transfer_pages,
            ev.begin.max_slots,
            ev.begin.discovery_ns,
            ev.ok.pre_seed_crc32,
            ev.ok.post_seed_crc32,
            ev.ok.pre_fixture_crc32,
            ev.ok.post_fixture_crc32,
            ev.ok.alloc_ifstats,
            ev.ok.alloc_steady_allocs,
            ev.ok.alloc_steady_frees,
            ev.ok.alloc_steady_enomem,
            ev.ok.global_max_in_flight,
            ev.ok.total_saturation_count,
        },
    );

    for (&ev.cells, 0..) |*cell, idx| {
        const t0 = &cell.trials[0];
        try w.print(
            "    {{\n" ++
                "      \"cell\": {d},\n" ++
                "      \"pattern\": \"{s}\",\n" ++
                "      \"req_bytes\": {d},\n" ++
                "      \"qd\": {d},\n" ++
                "      \"max_in_flight\": {d},\n" ++
                "      \"saturation_count\": {d},\n" ++
                "      \"median_iops\": {d},\n" ++
                "      \"median_bytes_per_s\": {d},\n" ++
                "      \"trial0_sub_comp_p50_ns\": {d},\n" ++
                "      \"trial0_sub_comp_p95_ns\": {d},\n" ++
                "      \"trial0_sub_comp_p99_ns\": {d},\n" ++
                "      \"trial0_comp_res_p50_ns\": {d},\n" ++
                "      \"trial0_comp_res_p95_ns\": {d},\n" ++
                "      \"trial0_comp_res_p99_ns\": {d}\n" ++
                "    }}{s}\n",
            .{
                cell.cell,
                cell.patternSlice(),
                cell.req_bytes,
                cell.qd,
                cell.max_in_flight,
                cell.saturation_count,
                cell.median_iops,
                cell.median_bytes_per_s,
                t0.sub_comp.p50_ns,
                t0.sub_comp.p95_ns,
                t0.sub_comp.p99_ns,
                t0.comp_res.p50_ns,
                t0.comp_res.p95_ns,
                t0.comp_res.p99_ns,
                if (idx + 1 < matrix_cell_count) "," else "",
            },
        );
    }
    try w.writeAll("  ]\n}\n");
    return out.toOwnedSlice();
}

pub fn emitMarkdownReport(
    allocator: std.mem.Allocator,
    ev: *const BenchmarkEvidence,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;

    try w.print(
        "# Hyper-V StorVSC Bounded Block-I/O Baseline Report\n\n" ++
            "- **Environment**: `{s}` (`{s}`)\n" ++
            "- **Storage Backing**: `{s}`\n" ++
            "- **Commit SHA**: `{s}`\n" ++
            "- **Config SHA-256**: `{s}`\n" ++
            "- **Image SHA-256**: `{s}`\n" ++
            "- **Transcript SHA-256**: `{s}`\n" ++
            "- **Target**: `address={d}:{d}:{d} sectors={d} sector_size={d} session_state=read_only write_authorized=0`\n" ++
            "- **Seed & Fixture Verification**: `pre_seed={x:0>8} post_seed={x:0>8} pre_fixture={x:0>8} post_fixture={x:0>8} verified=true`\n" ++
            "- **Steady-State Allocator Stats**: `allocs={d} frees={d} enomem={d}`\n\n" ++
            "| Cell | Pattern | Req Bytes | Target QD | Max In-Flight | Sat | Median IOPS | Median B/s | Sub->Comp p50/p95/p99 (ns) | Comp->Res p50/p95/p99 (ns) |\n" ++
            "| ---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |\n",
        .{
            ev.provenance.environment_kind.asText(),
            ev.provenance.host_or_sku,
            ev.provenance.storage_backing,
            ev.provenance.commit_sha,
            ev.provenance.config_sha256,
            ev.provenance.image_sha256,
            ev.transcript_sha256,
            ev.begin.path_id,
            ev.begin.target_id,
            ev.begin.lun,
            ev.begin.sectors,
            ev.begin.sector_size,
            ev.ok.pre_seed_crc32,
            ev.ok.post_seed_crc32,
            ev.ok.pre_fixture_crc32,
            ev.ok.post_fixture_crc32,
            ev.ok.alloc_steady_allocs,
            ev.ok.alloc_steady_frees,
            ev.ok.alloc_steady_enomem,
        },
    );

    for (&ev.cells) |*cell| {
        const t0 = &cell.trials[0];
        try w.print(
            "| {d} | {s} | {d} | {d} | {d} | {d} | {d} | {d} | {d}/{d}/{d} | {d}/{d}/{d} |\n",
            .{
                cell.cell,
                cell.patternSlice(),
                cell.req_bytes,
                cell.qd,
                cell.max_in_flight,
                cell.saturation_count,
                cell.median_iops,
                cell.median_bytes_per_s,
                t0.sub_comp.p50_ns,
                t0.sub_comp.p95_ns,
                t0.sub_comp.p99_ns,
                t0.comp_res.p50_ns,
                t0.comp_res.p95_ns,
                t0.comp_res.p99_ns,
            },
        );
    }
    return out.toOwnedSlice();
}
