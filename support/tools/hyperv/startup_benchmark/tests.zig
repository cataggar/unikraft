// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const startup = @import("startup_benchmark");
const test_options = @import("test_options");

test "parseBootTimingRecord validates monotonic milestones and serial/HTTP boot_id match" {
    const line =
        "[    0.042100] UK_HYPERV_BOOT_TIMING boot_id=aabbccdd11223344 " ++
        "t_efi_pre_exit=12500000 t_time_init=14200000 " ++
        "t_vmbus_ready=28900000 t_net_ready=41500000 " ++
        "t_http_ready=42100000 " ++
        "efi_to_time_ns=1700000 time_to_vmbus_ns=14700000 " ++
        "vmbus_to_net_ns=12600000 net_to_http_ns=600000 " ++
        "guest_internal_init_ns=29600000";

    const m = try startup.parseBootTimingRecord(line);
    try std.testing.expectEqualStrings("aabbccdd11223344", &m.boot_id);
    try std.testing.expectEqual(@as(u64, 12_500_000), m.t_efi_pre_exit_ns);
    try std.testing.expectEqual(@as(u64, 42_100_000), m.t_http_ready_ns);
    try std.testing.expectEqual(@as(u64, 29_600_000), m.guest_internal_init_ns);

    const prior = [_][16]u8{"0011223344556677".*};
    try startup.verifySerialAndHttpBootId(m, "aabbccdd11223344".*, &prior);

    // Stale boot ID must be rejected
    const stale_prior = [_][16]u8{"aabbccdd11223344".*};
    try std.testing.expectError(
        error.StaleOrDuplicateBootId,
        startup.verifySerialAndHttpBootId(m, "aabbccdd11223344".*, &stale_prior),
    );

    // Non-monotonic milestones must be rejected
    const bad_line =
        "UK_HYPERV_BOOT_TIMING boot_id=aabbccdd11223344 " ++
        "t_efi_pre_exit=20000000 t_time_init=14200000 " ++
        "t_vmbus_ready=28900000 t_net_ready=41500000 t_http_ready=42100000";
    try std.testing.expectError(
        error.NonMonotonicMilestones,
        startup.parseBootTimingRecord(bad_line),
    );
}

test "probeUntilHttpReady measures start-to-HTTP ready and rejects stale boot IDs" {
    const io = std.testing.io;

    var probe = try std.Io.net.IpAddress.listen(&(try std.Io.net.IpAddress.parse("127.0.0.1", 0)), io, .{});
    const port = probe.socket.address.getPort();
    probe.deinit(io);

    var port_buf: [16]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});

    var server_proc = try std.process.spawn(io, .{
        .argv = &.{
            test_options.http_server,
            "--bind",
            "127.0.0.1",
            "--port",
            port_str,
            "--max-conns",
            "8",
            "--duration-ms",
            "5000",
            "--max-requests",
            "2",
            "--boot-id",
            "deadbeefcafe1234",
        },
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer server_proc.kill(io);

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const prior = [_][16]u8{"1111222233334444".*};
    const res = try startup.probeUntilHttpReady(io, addr, &prior, 3000, 10);
    try std.testing.expectEqualStrings("deadbeefcafe1234", &res.boot_id);
    try std.testing.expect(res.attempts >= 1);

    // Second probe treating "deadbeefcafe1234" as a prior boot ID must fail with StaleOrDuplicateBootId
    const stale_prior = [_][16]u8{ "1111222233334444".*, "deadbeefcafe1234".* };
    try std.testing.expectError(
        error.StaleOrDuplicateBootId,
        startup.probeUntilHttpReady(io, addr, &stale_prior, 3000, 10),
    );
}

test "validateStartupBenchmarkReport validates 4 lifecycle categories and N>=10 unique boot IDs" {
    const allocator = std.testing.allocator;

    var json_buf: std.Io.Writer.Allocating = .init(allocator);
    defer json_buf.deinit();

    try json_buf.writer.writeAll(
        \\{
        \\  "schema_version": "uk.hyperv.startup-benchmark.v1",
        \\  "vm_size": "Standard_D2s_v5",
        \\  "location": "westeurope",
        \\  "unikraft": {
    );
    try writeCategoryJson(&json_buf.writer, "create_to_http_ready_ns", 0x1000, 18_500_000_000, true);
    try writeCategoryJson(&json_buf.writer, "start_from_deallocated_to_http_ready_ns", 0x2000, 9_200_000_000, true);
    try writeCategoryJson(&json_buf.writer, "guest_restart_to_http_ready_ns", 0x3000, 1_450_000_000, true);
    try writeCategoryJson(&json_buf.writer, "guest_internal_init_ns", 0x3000, 32_000_000, false);
    try json_buf.writer.writeAll(
        \\  },
        \\  "linux_baseline": {
    );
    try writeCategoryJson(&json_buf.writer, "create_to_http_ready_ns", 0x4000, 29_500_000_000, true);
    try writeCategoryJson(&json_buf.writer, "start_from_deallocated_to_http_ready_ns", 0x5000, 16_800_000_000, true);
    try writeCategoryJson(&json_buf.writer, "guest_restart_to_http_ready_ns", 0x6000, 6_400_000_000, true);
    try writeCategoryJson(&json_buf.writer, "guest_internal_init_ns", 0x6000, 3_100_000_000, false);
    try json_buf.writer.writeAll("  }\n}\n");

    const raw_json = try json_buf.toOwnedSlice();
    defer allocator.free(raw_json);

    const report = try startup.validateStartupBenchmarkReport(allocator, raw_json, 10);
    defer startup.freeValidatedReport(allocator, report);

    try std.testing.expectEqual(@as(usize, 60), report.unique_boot_ids_verified);
    try std.testing.expect(report.unikraft.guest_internal_init_ns.p50_ns < report.unikraft.start_from_deallocated_to_http_ready_ns.p50_ns);

    const md = try startup.renderMarkdownReport(allocator, report);
    defer allocator.free(md);
    try std.testing.expect(std.mem.indexOf(u8, md, "create_to_http_ready_ns") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "start_from_deallocated_to_http_ready_ns") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "guest_restart_to_http_ready_ns") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "guest_internal_init_ns") != null);
}

fn writeCategoryJson(
    writer: *std.Io.Writer,
    name: []const u8,
    boot_prefix: u32,
    base_ns: u64,
    trailing_comma: bool,
) !void {
    try writer.print("    \"{s}\": {{ \"trials\": [", .{name});
    for (0..10) |idx| {
        const sep = if (idx + 1 < 10) ", " else "";
        try writer.print(
            "{{ \"trial\": {d}, \"boot_id\": \"{x:0>8}{x:0>8}\", \"duration_ns\": {d} }}{s}",
            .{ idx + 1, boot_prefix, idx + 1, base_ns + idx * 500_000, sep },
        );
    }
    try writer.print("] }}{s}\n", .{if (trailing_comma) "," else ""});
}
