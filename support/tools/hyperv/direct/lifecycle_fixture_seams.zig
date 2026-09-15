// SPDX-License-Identifier: BSD-3-Clause
//! Test-only seams for a future in-process controller fixture adapter. Neither
//! a production clock environment switch nor permission to bypass admission.
const std = @import("std");
const f = @import("lifecycle_fixture_support.zig");

pub const Clock = struct {
    monotonic_ns: u64 = 0,
    wall_seconds: i64,

    pub fn advance(self: *Clock, milliseconds: u64) !void {
        self.monotonic_ns = try std.math.add(u64, self.monotonic_ns, try std.math.mul(u64, milliseconds, std.time.ns_per_ms));
    }
};

pub const HashRole = enum { candidate, boot1, capture, scope, admission, other };
pub const HashResult = struct { digest: [64]u8, exit: u8 };

/// The digest remains plausible even on failure. A native test adapter must
/// propagate `exit` instead of treating the digest as fresh/cached authority.
pub fn hash(scenario: []const u8, role: HashRole, boot2_reads: u8, bytes: []const u8) HashResult {
    const failed = (f.eq(scenario, "cache-hash-error") and role == .candidate) or
        (boot2_reads >= 2 and ((f.eq(scenario, "cache-binding-hash-error") and role == .boot1) or
            (f.eq(scenario, "cache-admission-hash-error") and role == .admission)));
    return .{ .digest = f.hash(bytes), .exit = if (failed) 17 else 0 };
}

pub fn selfCheck() !void {
    var clock: Clock = .{ .wall_seconds = 1000 };
    try clock.advance(1000);
    try f.expect(clock.monotonic_ns == std.time.ns_per_s and clock.wall_seconds == 1000);
    for ([_]HashRole{ .candidate, .boot1, .admission }) |role| {
        const name = switch (role) {
            .candidate => "cache-hash-error",
            .boot1 => "cache-binding-hash-error",
            .admission => "cache-admission-hash-error",
            else => unreachable,
        };
        const failure = hash(name, role, 2, "native real hash");
        try f.expect(failure.exit == 17 and f.eq(&failure.digest, &f.hash("native real hash")));
        const early = hash(name, role, 1, "native real hash");
        try f.expect(early.exit == @as(u8, if (role == .candidate) 17 else 0));
        try f.expect(hash("success", role, 2, "native real hash").exit == 0);
    }
}
