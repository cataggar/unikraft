const std = @import("std");
const host = @import("host");

test "production host call compiles without observer or measurement dependencies" {
    var remote: host.native.Supervised = undefined;
    remote.deadline = .{ .expires_ns = 0 };
    try std.testing.expectError(error.AttemptExpired, remote.call(undefined, null));
    try std.testing.expect(!@hasDecl(host, "host_timing"));
}
