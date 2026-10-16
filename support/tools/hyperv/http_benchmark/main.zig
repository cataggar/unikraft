// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const bench = @import("http_benchmark");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) return error.InvalidArguments;
    const subcmd = args[1];

    if (std.mem.eql(u8, subcmd, "validate-report")) {
        var report_path: ?[]const u8 = null;
        var markdown_out: ?[]const u8 = null;
        var idx: usize = 2;
        while (idx < args.len) : (idx += 1) {
            if (std.mem.eql(u8, args[idx], "--report") and idx + 1 < args.len) {
                idx += 1;
                report_path = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--markdown-out") and idx + 1 < args.len) {
                idx += 1;
                markdown_out = args[idx];
            } else {
                return error.InvalidArguments;
            }
        }
        const path = report_path orelse return error.InvalidArguments;
        const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024));
        defer allocator.free(raw);

        const validated = try bench.validateComparisonReport(allocator, raw);
        defer bench.freeValidatedReport(allocator, validated);

        if (markdown_out) |md_path| {
            const md = try bench.renderMarkdownReport(allocator, validated);
            defer allocator.free(md);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = md_path, .data = md });
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "probe")) {
        var host: []const u8 = "127.0.0.1";
        var port: u16 = 8080;
        var concurrency: u32 = 1;
        var requests_per_conn: u32 = 4;
        var idx: usize = 2;
        while (idx < args.len) : (idx += 1) {
            if (std.mem.eql(u8, args[idx], "--host") and idx + 1 < args.len) {
                idx += 1;
                host = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--port") and idx + 1 < args.len) {
                idx += 1;
                port = try std.fmt.parseInt(u16, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--concurrency") and idx + 1 < args.len) {
                idx += 1;
                concurrency = try std.fmt.parseInt(u32, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--requests-per-conn") and idx + 1 < args.len) {
                idx += 1;
                requests_per_conn = try std.fmt.parseInt(u32, args[idx], 10);
            } else {
                return error.InvalidArguments;
            }
        }
        const addr = try std.Io.net.IpAddress.parse(host, port);
        const summary = try bench.runKeepAliveSession(allocator, io, addr, concurrency, requests_per_conn);
        var buf: [512]u8 = undefined;
        var stdout = std.Io.File.stdout().writer(io, &buf);
        try stdout.interface.print(
            "HTTP_BENCHMARK_PROBE boot_id={s} concurrency={d} requests={d} bytes_rx={d} rps={d:.1} p50_ns={d} p95_ns={d} p99_ns={d} p999_ns={d}\n",
            .{
                summary.boot_id[0..],
                summary.concurrency,
                summary.requests,
                summary.bytes_rx,
                summary.rps,
                summary.p50_ns,
                summary.p95_ns,
                summary.p99_ns,
                summary.p999_ns,
            },
        );
        try stdout.interface.flush();
        return;
    }

    return error.InvalidArguments;
}
