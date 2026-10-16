// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const bench = @import("http_benchmark");
const test_options = @import("test_options");

test "deterministic 1024-byte body matches HTTP response parser" {
    var body: [bench.canonical_body_bytes]u8 = undefined;
    bench.fillExpectedBody(&body);
    try std.testing.expectEqual(@as(usize, 1024), body.len);
    try std.testing.expect(std.mem.startsWith(u8, &body, "unikraft-hyperv-http-1k-payload-line-00:"));
    try std.testing.expectEqual(@as(u8, '\n'), body[63]);
    try std.testing.expectEqual(@as(u8, '\n'), body[1023]);

    var raw_resp: [1536]u8 = undefined;
    const hdr =
        "HTTP/1.1 200 OK\r\n" ++
        "Server: unikraft-hyperv-http/1.0\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n" ++
        "Content-Length: 1024\r\n" ++
        "Connection: keep-alive\r\n" ++
        "X-Unikraft-Boot-Id: 0123456789abcdef\r\n" ++
        "\r\n";
    @memcpy(raw_resp[0..hdr.len], hdr);
    @memcpy(raw_resp[hdr.len .. hdr.len + body.len], &body);

    const parsed = try bench.parseHttpResponse(raw_resp[0 .. hdr.len + body.len], true);
    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqual(@as(usize, 1024), parsed.content_length);
    try std.testing.expect(parsed.keep_alive);
    try std.testing.expectEqualStrings("0123456789abcdef", &parsed.boot_id);
}

test "parseUnikraftStats and parseLinuxStats extract serial and stdout telemetry" {
    const uk_line =
        "UK_HYPERV_HTTP_SERVICE_STATS phase=final boot_id=a1b2c3d4e5f60718 " ++
        "elapsed_ms=60000 requests=180000 bytes_tx=216000000 bytes_rx=14400000 " ++
        "active_conns=0 peak_conns=64 total_conns=64 errors=0 " ++
        "status_200=180000 status_400=0 status_413=0 " ++
        "netvsc_tx_packets=180100 netvsc_rx_packets=180100 netvsc_ring_full=0 " ++
        "ukalloc_cur_alloc_size=98304 ukalloc_max_alloc_size=131072 " ++
        "ukalloc_cur_nb_allocs=42 ukalloc_tot_nb_allocs=48 ukalloc_tot_nb_frees=6";

    const uk = try bench.parseUnikraftStats(uk_line);
    try std.testing.expectEqualStrings("final", uk.phase);
    try std.testing.expectEqualStrings("a1b2c3d4e5f60718", &uk.boot_id);
    try std.testing.expectEqual(@as(u64, 180000), uk.requests);
    try std.testing.expectEqual(@as(u32, 64), uk.peak_conns);
    try std.testing.expectEqual(@as(u64, 131072), uk.ukalloc_max_alloc_size);

    const lx_line =
        "LINUX_HTTP_SERVICE_STATS phase=final boot_id=fedcba9876543210 " ++
        "elapsed_ms=60000 requests=175000 bytes_tx=210000000 bytes_rx=14000000 " ++
        "active_conns=0 peak_conns=64 total_conns=64 errors=0 " ++
        "status_200=175000 status_400=0 status_413=0 " ++
        "rss_bytes=2457600 max_rss_bytes=2621440";

    const lx = try bench.parseLinuxStats(lx_line);
    try std.testing.expectEqualStrings("final", lx.phase);
    try std.testing.expectEqualStrings("fedcba9876543210", &lx.boot_id);
    try std.testing.expectEqual(@as(u64, 175000), lx.requests);
    try std.testing.expectEqual(@as(u64, 2457600), lx.rss_bytes);
    try std.testing.expectEqual(@as(u64, 2621440), lx.max_rss_bytes);
}

test "matched Linux epoll HTTP/1.1 server serves keep-alive 1024-byte responses" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var probe = try std.Io.net.IpAddress.listen(&(try std.Io.net.IpAddress.parse("127.0.0.1", 0)), io, .{});
    const port = probe.socket.address.getPort();
    probe.deinit(io);

    var port_buf: [16]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});

    var server_proc = try std.process.spawn(io, .{
        .argv = &.{
            test_options.linux_server,
            "--bind",
            "127.0.0.1",
            "--port",
            port_str,
            "--max-conns",
            "16",
            "--duration-ms",
            "5000",
            "--max-requests",
            "12",
            "--boot-id",
            "cafe0123456789ab",
        },
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer server_proc.kill(io);

    var retry: usize = 0;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var summary: ?bench.LoadSampleSummary = null;
    while (retry < 30) : (retry += 1) {
        if (bench.runKeepAliveSession(allocator, io, addr, 3, 4)) |res| {
            summary = res;
            break;
        } else |_| {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
    }

    const res = summary orelse return error.ServerDidNotStart;
    try std.testing.expectEqual(@as(u64, 12), res.requests);
    try std.testing.expectEqualStrings("cafe0123456789ab", &res.boot_id);
    try std.testing.expect(res.p99_ns >= res.p50_ns);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_reader = server_proc.stdout.?.reader(io, &stdout_buf);
    const stdout = try stdout_reader.interface.allocRemaining(allocator, .limited(64 * 1024));
    defer allocator.free(stdout);
    const term = try server_proc.wait(io);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
    try std.testing.expect(std.mem.indexOf(u8, stdout, "LINUX_HTTP_SERVER_COMPLETE") != null);
}

test "validateComparisonReport validates same-VNet topology and renders Markdown" {
    const allocator = std.testing.allocator;
    const report_json =
        \\{
        \\  "schema_version": "uk.hyperv.http-benchmark.v1",
        \\  "topology": {
        \\    "vm_size": "Standard_D2s_v5",
        \\    "location": "westeurope",
        \\    "subnet_cidr": "10.42.0.0/24",
        \\    "accelerated_networking": false,
        \\    "unikraft_vm": {
        \\      "name": "uk-http-vm",
        \\      "private_ip": "10.42.0.4",
        \\      "vm_size": "Standard_D2s_v5",
        \\      "accelerated_networking": false,
        \\      "boot_id": "1122334455667788"
        \\    },
        \\    "linux_baseline_vm": {
        \\      "name": "linux-http-vm",
        \\      "private_ip": "10.42.0.5",
        \\      "vm_size": "Standard_D2s_v5",
        \\      "accelerated_networking": false,
        \\      "boot_id": "8877665544332211"
        \\    },
        \\    "loadgen_vm": {
        \\      "name": "loadgen-vm",
        \\      "private_ip": "10.42.0.6",
        \\      "vm_size": "Standard_D2s_v5",
        \\      "accelerated_networking": false
        \\    }
        \\  },
        \\  "memory": {
        \\    "unikraft_idle_heap_bytes": 98304,
        \\    "unikraft_load_peak_heap_bytes": 131072,
        \\    "linux_idle_rss_bytes": 2097152,
        \\    "linux_load_peak_rss_bytes": 2621440
        \\  },
        \\  "concurrency_tiers": [
        \\    {
        \\      "concurrency": 1,
        \\      "duration_seconds": 60,
        \\      "unikraft": { "rps": 4850.5, "p50_us": 190.0, "p95_us": 260.0, "p99_us": 340.0, "p999_us": 510.0, "errors": 0 },
        \\      "linux_baseline": { "rps": 4420.2, "p50_us": 210.0, "p95_us": 295.0, "p99_us": 390.0, "p999_us": 620.0, "errors": 0 }
        \\    },
        \\    {
        \\      "concurrency": 8,
        \\      "duration_seconds": 60,
        \\      "unikraft": { "rps": 26400.0, "p50_us": 280.0, "p95_us": 420.0, "p99_us": 590.0, "p999_us": 890.0, "errors": 0 },
        \\      "linux_baseline": { "rps": 24100.0, "p50_us": 310.0, "p95_us": 465.0, "p99_us": 640.0, "p999_us": 980.0, "errors": 0 }
        \\    },
        \\    {
        \\      "concurrency": 32,
        \\      "duration_seconds": 60,
        \\      "unikraft": { "rps": 54200.0, "p50_us": 540.0, "p95_us": 810.0, "p99_us": 1120.0, "p999_us": 1750.0, "errors": 0 },
        \\      "linux_baseline": { "rps": 49800.0, "p50_us": 590.0, "p95_us": 880.0, "p99_us": 1240.0, "p999_us": 1950.0, "errors": 0 }
        \\    },
        \\    {
        \\      "concurrency": 64,
        \\      "duration_seconds": 60,
        \\      "unikraft": { "rps": 61800.0, "p50_us": 980.0, "p95_us": 1450.0, "p99_us": 2050.0, "p999_us": 3100.0, "errors": 0 },
        \\      "linux_baseline": { "rps": 56900.0, "p50_us": 1060.0, "p95_us": 1580.0, "p99_us": 2250.0, "p999_us": 3450.0, "errors": 0 }
        \\    }
        \\  ]
        \\}
    ;

    const validated = try bench.validateComparisonReport(allocator, report_json);
    defer bench.freeValidatedReport(allocator, validated);

    const md = try bench.renderMarkdownReport(allocator, validated);
    defer allocator.free(md);
    try std.testing.expect(std.mem.indexOf(u8, md, "uk.hyperv.http-benchmark.v1") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "| 64 | 60 |") != null);
}
