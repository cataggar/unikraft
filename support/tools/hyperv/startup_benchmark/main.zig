// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const startup = @import("startup_benchmark");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) return error.InvalidArguments;
    const subcmd = args[1];

    if (std.mem.eql(u8, subcmd, "validate-report")) {
        var report_path: ?[]const u8 = null;
        var markdown_out: ?[]const u8 = null;
        var min_trials: usize = startup.default_min_trials;
        var idx: usize = 2;
        while (idx < args.len) : (idx += 1) {
            if (std.mem.eql(u8, args[idx], "--report") and idx + 1 < args.len) {
                idx += 1;
                report_path = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--markdown-out") and idx + 1 < args.len) {
                idx += 1;
                markdown_out = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--min-trials") and idx + 1 < args.len) {
                idx += 1;
                min_trials = try std.fmt.parseInt(usize, args[idx], 10);
            } else {
                return error.InvalidArguments;
            }
        }
        const path = report_path orelse return error.InvalidArguments;
        const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(8 * 1024 * 1024));
        defer allocator.free(raw);

        const validated = try startup.validateStartupBenchmarkReport(allocator, raw, min_trials);
        defer startup.freeValidatedReport(allocator, validated);

        if (markdown_out) |md_path| {
            const md = try startup.renderMarkdownReport(allocator, validated);
            defer allocator.free(md);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = md_path, .data = md });
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "probe-ready")) {
        var host: []const u8 = "127.0.0.1";
        var port: u16 = 8080;
        var timeout_ms: u64 = 60_000;
        var retry_ms: u64 = 25;
        var prior_list: std.ArrayList([16]u8) = .empty;
        defer prior_list.deinit(allocator);

        var idx: usize = 2;
        while (idx < args.len) : (idx += 1) {
            if (std.mem.eql(u8, args[idx], "--host") and idx + 1 < args.len) {
                idx += 1;
                host = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--port") and idx + 1 < args.len) {
                idx += 1;
                port = try std.fmt.parseInt(u16, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--timeout-ms") and idx + 1 < args.len) {
                idx += 1;
                timeout_ms = try std.fmt.parseInt(u64, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--retry-ms") and idx + 1 < args.len) {
                idx += 1;
                retry_ms = try std.fmt.parseInt(u64, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--reject-boot-id") and idx + 1 < args.len) {
                idx += 1;
                const bid = args[idx];
                if (!startup.isValidBootIdHex(bid)) return error.InvalidBootId;
                var id: [16]u8 = undefined;
                @memcpy(&id, bid[0..16]);
                try prior_list.append(allocator, id);
            } else {
                return error.InvalidArguments;
            }
        }

        const addr = try std.Io.net.IpAddress.parse(host, port);
        const res = try startup.probeUntilHttpReady(io, addr, prior_list.items, timeout_ms, retry_ms);
        var buf: [256]u8 = undefined;
        var stdout = std.Io.File.stdout().writer(io, &buf);
        try stdout.interface.print(
            "STARTUP_HTTP_READY boot_id={s} elapsed_ns={d} attempts={d}\n",
            .{ res.boot_id[0..], res.elapsed_ns, res.attempts },
        );
        try stdout.interface.flush();
        return;
    }

    return error.InvalidArguments;
}
