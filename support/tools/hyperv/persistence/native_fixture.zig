//! Injected HTTP fixtures only; never imported by an installed executable.
const std = @import("std");
const core = @import("hyperv_core");
const sdk = @import("azure_sdk_core");
const azure = @import("hyperv_azure");
const transfer = @import("hyperv_transfer");
const p = @import("root.zig");
const f = @import("fixture_support.zig");
const t = std.testing;

const endpoint = "https://synthetic.blob.storage.azure.net/disk/vhd?sig=SYNTHETIC_PRIVATE";
const Wire = struct {
    mock: sdk.http.MockTransport,
    cancellation: sdk.http.CancellationToken = .{},
    cancel_on_open: bool = false,
    fn open(context: *anyopaque, request: *sdk.http.Request, options: sdk.http.OpenOptions) !*sdk.http.HttpOperation {
        const self: *Wire = @ptrCast(@alignCast(context));
        try t.expectEqualStrings(endpoint, request.url);
        try t.expectEqual(.GET, request.method);
        try t.expectEqualStrings("2020-10-02", request.getHeader("x-ms-version").?);
        try t.expectEqualStrings("bytes=0-511", request.getHeader("Range").?);
        try t.expectEqualStrings("identity", request.getHeader("Accept-Encoding").?);
        try t.expect(!request.retryable and request.redirect_policy == .not_allowed);
        try t.expect(request.getHeader("Authorization") == null and options.cancellation != null);
        const result = try self.mock.asTransport().open(request, options);
        if (self.cancel_on_open) self.cancellation.cancel();
        return result;
    }
    fn send(_: *anyopaque, _: *sdk.http.Request) !sdk.http.Response {
        return error.BufferedTransportForbidden;
    }
    fn now(_: *anyopaque) u64 {
        return 1000;
    }
    fn unix(_: *anyopaque) i64 {
        return 1000;
    }
    fn sleep(_: *anyopaque, _: u32) !void {
        return error.UnexpectedSleep;
    }
    fn transferNow(_: *anyopaque) !u64 {
        return 1000;
    }
};

pub fn probes(a: std.mem.Allocator, io: std.Io, root: []const u8) !void {
    for ([_]enum { denied, conflicting, malformed, excess, cancelled }{
        .denied, .conflicting, .malformed, .excess, .cancelled,
    }) |mode| {
        var work = try f.Fixture.init(a, io, root);
        defer work.deinit();
        var lock = try work.directory.lock(io);
        defer lock.close(io);
        try t.expectEqual(.durable, (try lock.createImmutable(io, "data-grant", endpoint)).status);
        var wire: Wire = .{ .mock = .init(a, 403, switch (mode) {
            .malformed => "<Error><Code>AuthenticationFailed",
            .conflicting => "<Error><Code>AuthorizationFailure</Code></Error>",
            .excess => "X" ** 8193,
            else => "<Error><Code>AuthenticationFailed</Code></Error>",
        }), .cancel_on_open = mode == .cancelled };
        defer wire.mock.deinit();
        wire.mock.response_headers_list = &.{.{ .name = "x-ms-error-code", .value = "AuthenticationFailed" }};
        var crypto = sdk.crypto.StdCryptoProvider.init(io);
        const runtime = sdk.http.HttpRuntime.init(.{ .context = &wire, .vtable = &.{ .send = Wire.send, .open = Wire.open } }, crypto.asProvider());
        var budget: azure.transport.Budget = .{
            .clock = .{ .context = &wire, .monotonicMsFn = Wire.now, .unixSecondsFn = Wire.unix, .sleepMsFn = Wire.sleep },
            .deadline_ms = 3000,
            .cancellation = &wire.cancellation,
        };
        const authority = f.input().authority;
        var token: azure.auth.Token = .{ .value = try azure.secret.Bytes.copy(a, "synthetic-only-token"), .expires_on = 4000, .tenant = authority.tenant, .subscription = authority.subscription, .principal = authority.principal, .client = authority.client };
        defer token.deinit();
        var arm: azure.client.Client = .{ .allocator = a, .authority = authority, .token = &token, .channel = .{ .allocator = a, .budget = &budget, .runtime = runtime } };
        var blobs: transfer.Client = .{ .allocator = a, .io = io, .runtime = runtime, .budget = .{ .context = &wire, .nowMsFn = Wire.transferNow, .deadline_ms = 3000, .cancellation = &wire.cancellation } };
        var native: p.native.Context = .{ .allocator = a, .io = io, .arm = &arm, .blobs = &blobs, .secrets = work.directory, .output = work.directory, .output_lock = &lock, .output_path = work.path };
        const job = try f.makeJob(a, .data_access_closed, 3000 * std.time.ns_per_ms);
        const result = try native.execute(job);
        try result.validate();
        try t.expectEqual(@as(?u16, 403), result.http_status);
        try t.expectEqual(mode == .denied, result.complete);
        if (mode == .denied) {
            try t.expect(result.access_closed);
            try t.expectEqual(.known, result.access_metadata.?.header);
            try t.expectEqual(.known, result.access_metadata.?.body);
        } else {
            try t.expect(result.failures.primary != null and !result.access_closed);
            if (mode == .conflicting) try t.expectEqual(.conflicting, result.access_metadata.?.state);
        }
        const public = try p.local.encode(a, result);
        defer a.free(public);
        try t.expect(std.mem.indexOf(u8, public, "SYNTHETIC_PRIVATE") == null);
        try t.expect(std.mem.indexOf(u8, public, "https://") == null);
        try t.expectEqual(@as(usize, 1), wire.mock.call_count);
        try t.expectEqual(@as(usize, 1), wire.mock.stream_deinit_count);
    }
}
