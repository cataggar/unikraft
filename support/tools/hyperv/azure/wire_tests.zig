const std = @import("std");
const sdk = @import("azure_sdk_core");
const wire = @import("transport.zig");
const diagnostics = @import("hyperv_core").diagnostics;
const t = std.testing;
const request_target = "/synthetic-header-capture?p=SYNTHETIC_PRIVATE%2b%2F%3d&h=SYNTHETIC_PRIVATE+/==";

const Capture = struct {
    server: *std.Io.net.Server,
    compressed: bool,
    header_count: usize = 0,
    identity: bool = true,
    failure: ?anyerror = null,

    fn run(self: *Capture) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn serve(self: *Capture) !void {
        const stream = try self.server.accept(t.io);
        defer stream.close(t.io);
        var read_buffer: [8192]u8 = undefined;
        var reader = std.Io.net.Stream.Reader.init(stream, t.io, &read_buffer);
        var lines: usize = 0;
        var bytes: usize = 0;
        while (true) {
            const raw = (try reader.interface.takeDelimiter('\n')) orelse return error.IncompleteRequest;
            bytes += raw.len;
            lines += 1;
            if (bytes > 8192 or lines > 64) return error.RequestHeadersTooLarge;
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (lines == 1 and !std.mem.eql(u8, line, "GET " ++ request_target ++ " HTTP/1.1")) return error.UnexpectedRequestTarget;
            if (line.len == 0) break;
            if (std.ascii.startsWithIgnoreCase(line, "accept-encoding:")) {
                self.header_count += 1;
                self.identity = self.identity and std.mem.eql(u8, std.mem.trim(u8, line["accept-encoding:".len..], " \t"), "identity");
            }
        }
        var write_buffer: [1024]u8 = undefined;
        var writer = std.Io.net.Stream.Writer.init(stream, t.io, &write_buffer);
        if (self.compressed) {
            const empty_gzip = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            try writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 20\r\nConnection: close\r\n\r\n" ++ empty_gzip);
        } else {
            try writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        }
        try writer.interface.flush();
    }
};

test "native SDK wire has one identity Accept-Encoding for ARM and credential channels" {
    for ([_]diagnostics.Stage{ .arm, .credential }) |stage| {
        for ([_]bool{ false, true }) |compressed| {
            const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
            var server = try address.listen(t.io, .{ .reuse_address = true });
            defer server.deinit(t.io);
            var capture: Capture = .{ .server = &server, .compressed = compressed };
            var serving = try t.io.concurrent(Capture.run, .{&capture});
            defer serving.cancel(t.io);

            const url = try std.fmt.allocPrint(t.allocator, "http://127.0.0.1:{d}" ++ request_target, .{server.socket.address.getPort()});
            defer t.allocator.free(url);
            var native = sdk.http.StdHttpTransport.init(t.allocator, t.io);
            defer native.deinit();
            var crypto = sdk.crypto.StdCryptoProvider.init(t.io);
            var clock: wire.NativeClock = .{ .io = t.io };
            const clock_api = clock.clock();
            var budget: wire.Budget = .{
                .clock = clock_api,
                .deadline_ms = clock_api.monotonicMsFn(clock_api.context) + 5000,
            };
            const channel: wire.Channel = .{
                .allocator = t.allocator,
                .runtime = .init(native.asTransport(), crypto.asProvider()),
                .budget = &budget,
            };
            var request = sdk.http.Request.init(t.allocator, .GET, url);
            defer request.deinit();
            if (stage == .credential) try request.setHeader("accept-encoding", "gzip");
            var result = channel.send(&request, false, stage);
            defer if (result == .ok) result.ok.deinit();

            // Cancellation also releases an accept blocked by a pre-connect failure.
            if (result == .ok or result.failed.diagnostic.http_status != null) serving.await(t.io) else serving.cancel(t.io);
            if (capture.failure) |err| return err;
            try t.expectEqual(@as(usize, 1), capture.header_count);
            try t.expect(capture.identity);
            if (compressed) {
                try t.expect(result == .failed);
                try t.expectEqual(.invalid_response, result.failed.diagnostic.category);
                try t.expectEqual(@as(?u16, 200), result.failed.diagnostic.http_status);
            } else {
                try t.expect(result == .ok);
                try t.expectEqualStrings("{}", result.ok.body);
            }
        }
    }
}
