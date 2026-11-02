// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const evidence = @import("storage_benchmark_evidence");
const t = std.testing;
const a = t.allocator;

const default_contract = evidence.ExpectedContract{
    .sectors = 8388608,
    .sector_size = 512,
    .lun = 7,
    .identity_policy = 2,
    .max_transfer_bytes = 131072,
    .configured_queue_depth = 32,
    .max_transfer_pages = 33,
    .max_slots = 32,
    .warmup_ops = 4,
    .steady_ops = 8,
    .trials = 2,
    .expected_pre_seed_crc32 = 0xaabbccdd,
    .expected_pre_fixture_crc32 = 0x11223344,
};

const default_provenance = evidence.Provenance{
    .commit_sha = "6d173dc1a671e62cff0670ad1dfdcd6012345678".*,
    .config_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".*,
    .image_sha256 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".*,
    .environment_kind = .private_nested_kvm,
    .host_or_sku = "nested-kvm-ws2022-gen2",
    .storage_backing = "vhdx-nvme-4gib-lun7",
};

fn buildValidTranscript(alloc: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll(
        "UK_HYPERV_STORAGE_BENCHMARK_BEGIN schema=1 id=0 controller=0 channel=7 " ++
            "address=0:0:7 identity_policy=2 session_state=read_only write_authorized=0 " ++
            "sectors=8388608 sector_size=512 max_transfer_bytes=131072 " ++
            "configured_queue_depth=32 max_transfer_pages=33 max_slots=32 " ++
            "warmup_ops=4 steady_ops=8 trials=2 discovery_ns=25000 " ++
            "pre_seed_crc32=aabbccdd pre_fixture_crc32=11223344\n",
    );

    var cell_idx: u32 = 0;
    var total_warmup_ops: u64 = 0;
    var total_steady_ops: u64 = 0;
    var total_bytes_read: u64 = 0;
    var global_max_inflight: u32 = 0;
    var total_sat: u64 = 0;

    for (evidence.matrix_patterns) |pat| {
        for (evidence.matrix_req_bytes) |req_bytes| {
            const req_sectors = req_bytes / 512;
            for (evidence.matrix_queue_depths) |qd| {
                const sat: u32 = if (qd == 32) 1 else 0;
                const bytes_per_trial: u64 = 8 * @as(u64, req_bytes);
                total_warmup_ops += 4;
                total_bytes_read += 4 * @as(u64, req_bytes);
                if (qd > global_max_inflight)
                    global_max_inflight = qd;

                for (0..2) |trial| {
                    total_steady_ops += 8;
                    total_bytes_read += bytes_per_trial;
                    total_sat += sat;
                    try w.print(
                        "UK_HYPERV_STORAGE_BENCHMARK_TRIAL cell={d} pattern={s} " ++
                            "req_bytes={d} req_sectors={d} qd={d} trial={d} " ++
                            "warmup_ops=4 samples=8 bytes_read={d} elapsed_ns=100000 " ++
                            "iops=80000 bytes_per_s={d} max_in_flight={d} saturation_count={d} " ++
                            "sub_comp_min_ns=1000 sub_comp_p50_ns=2000 sub_comp_p95_ns=3000 " ++
                            "sub_comp_p99_ns=4000 sub_comp_max_ns=5000 sub_comp_mean_ns=2500 " ++
                            "comp_res_min_ns=100 comp_res_p50_ns=200 comp_res_p95_ns=300 " ++
                            "comp_res_p99_ns=400 comp_res_max_ns=500 comp_res_mean_ns=250\n",
                        .{
                            cell_idx,
                            pat,
                            req_bytes,
                            req_sectors,
                            qd,
                            trial,
                            bytes_per_trial,
                            bytes_per_trial * 10000,
                            qd,
                            sat,
                        },
                    );
                }

                try w.print(
                    "UK_HYPERV_STORAGE_BENCHMARK_CELL cell={d} pattern={s} " ++
                        "req_bytes={d} req_sectors={d} qd={d} trials=2 warmup_ops=4 " ++
                        "total_samples=16 total_bytes={d} max_in_flight={d} " ++
                        "saturation_count={d} min_iops=80000 median_iops=80000 " ++
                        "max_iops=80000 min_bytes_per_s={d} median_bytes_per_s={d} " ++
                        "max_bytes_per_s={d}\n",
                    .{
                        cell_idx,
                        pat,
                        req_bytes,
                        req_sectors,
                        qd,
                        16 * @as(u64, req_bytes),
                        qd,
                        sat * 2,
                        bytes_per_trial * 10000,
                        bytes_per_trial * 10000,
                        bytes_per_trial * 10000,
                    },
                );
                cell_idx += 1;
            }
        }
    }

    try w.print(
        "UK_HYPERV_STORAGE_BENCHMARK_OK schema=1 lun=7 session_state=read_only " ++
            "write_authorized=0 cells=48 total_trials=96 total_warmup_ops={d} " ++
            "total_steady_ops={d} total_bytes_read={d} global_max_in_flight={d} " ++
            "total_saturation_count={d} pre_seed_crc32=aabbccdd post_seed_crc32=aabbccdd " ++
            "pre_fixture_crc32=11223344 post_fixture_crc32=11223344 post_seed_verified=1 " ++
            "alloc_ifstats=1 alloc_steady_allocs=0 alloc_steady_frees=0 " ++
            "alloc_steady_enomem=0 alloc_cur_mem_bytes=16384 alloc_max_mem_bytes=4505600\n" ++
            "HYPERV_STORAGE_BENCHMARK FINAL PASS\n",
        .{
            total_warmup_ops,
            total_steady_ops,
            total_bytes_read,
            global_max_inflight,
            total_sat,
        },
    );
    return out.toOwnedSlice();
}

test "storage benchmark parser validates full 48-cell matrix and emits JSON and Markdown reports" {
    const transcript = try buildValidTranscript(a);
    defer a.free(transcript);

    const parsed = try evidence.parseAndValidate(
        transcript,
        default_contract,
        default_provenance,
    );
    try t.expectEqual(@as(u32, 48), parsed.ok.cells);
    try t.expectEqual(@as(u32, 96), parsed.ok.total_trials);
    try t.expectEqual(@as(u32, 32), parsed.ok.global_max_in_flight);
    try t.expectEqual(@as(u64, 0), parsed.ok.alloc_steady_allocs);
    try t.expectEqual(@as(u8, 1), parsed.ok.post_seed_verified);

    const json = try evidence.emitJsonReport(a, &parsed);
    defer a.free(json);
    try t.expect(std.mem.indexOf(u8, json, "\"session_state\": \"read_only\"") != null);
    try t.expect(std.mem.indexOf(u8, json, "\"write_authorized\": 0") != null);
    try t.expect(std.mem.indexOf(u8, json, "\"environment_kind\": \"private-nested-kvm\"") != null);
    try t.expect(std.mem.indexOf(u8, json, "\"cell\": 47") != null);

    const md = try evidence.emitMarkdownReport(a, &parsed);
    defer a.free(md);
    try t.expect(std.mem.indexOf(u8, md, "# Hyper-V StorVSC Bounded Block-I/O Baseline Report") != null);
    try t.expect(std.mem.indexOf(u8, md, "| 47 | strided | 131072 | 32 |") != null);
}

test "storage benchmark parser refuses write authorization, seed drift, percentile inversions, and bad provenance" {
    const transcript = try buildValidTranscript(a);
    defer a.free(transcript);

    const mutations = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "session_state=read_only", .to = "session_state=read_write" },
        .{ .from = "write_authorized=0", .to = "write_authorized=1" },
        .{ .from = "address=0:0:7", .to = "address=0:0:1" },
        .{ .from = "sectors=8388608", .to = "sectors=4194304" },
        .{ .from = "post_seed_crc32=aabbccdd", .to = "post_seed_crc32=aabbccde" },
        .{ .from = "post_fixture_crc32=11223344", .to = "post_fixture_crc32=11223345" },
        .{ .from = "post_seed_verified=1", .to = "post_seed_verified=0" },
        .{ .from = "alloc_steady_allocs=0", .to = "alloc_steady_allocs=1" },
        .{ .from = "alloc_steady_enomem=0", .to = "alloc_steady_enomem=1" },
        .{ .from = "sub_comp_p50_ns=2000 sub_comp_p95_ns=3000", .to = "sub_comp_p50_ns=3500 sub_comp_p95_ns=3000" },
        .{ .from = "comp_res_p95_ns=300 comp_res_p99_ns=400", .to = "comp_res_p95_ns=450 comp_res_p99_ns=400" },
        .{ .from = "qd=1 trial=0 warmup_ops=4 samples=8 bytes_read=32768 elapsed_ns=100000 iops=80000 bytes_per_s=327680000 max_in_flight=1", .to = "qd=1 trial=0 warmup_ops=4 samples=8 bytes_read=32768 elapsed_ns=100000 iops=80000 bytes_per_s=327680000 max_in_flight=2" },
        .{ .from = "HYPERV_STORAGE_BENCHMARK FINAL PASS", .to = "HYPERV_STORAGE_BENCHMARK FINAL FAIL reason=sweep rc=-5" },
    };

    for (mutations) |m| {
        const corrupted = try std.mem.replaceOwned(u8, a, transcript, m.from, m.to);
        defer a.free(corrupted);
        if (evidence.parseAndValidate(corrupted, default_contract, default_provenance)) |_| {
            return error.AcceptedInvalidBenchmarkTranscript;
        } else |_| {}
    }

    var bad_prov = default_provenance;
    bad_prov.commit_sha = @splat('0');
    try t.expectError(
        error.InvalidProvenance,
        evidence.parseAndValidate(transcript, default_contract, bad_prov),
    );
    bad_prov = default_provenance;
    bad_prov.host_or_sku = "";
    try t.expectError(
        error.InvalidProvenance,
        evidence.parseAndValidate(transcript, default_contract, bad_prov),
    );
}
