// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const records = @import("records.zig");

pub const Scenario = enum { ok, nonzero, partial, signal, overflow, timeout, cancelled };

pub const Observation = struct {
    name: []const u8,
    primary: []const u8,
    exit_code: i32,
    stdout_bytes: usize,
    stdout_sha256: []const u8,
    stderr_bytes: usize,
    stderr_sha256: []const u8,
    cleanup_complete: bool,
    executable_stable: bool,
};

fn expected(allocator: std.mem.Allocator) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var results: [std.enums.values(Scenario).len]Observation = undefined;
    for (std.enums.values(Scenario), 0..) |scenario, index| {
        const stdout = switch (scenario) {
            .ok => "native fixture ok\n",
            .partial => "partial private output\n",
            .overflow => &([_]u8{'X'} ** 33),
            else => "",
        };
        const stderr = switch (scenario) {
            .nonzero => "PermissionDenied /private/secret\n",
            else => "",
        };
        const stdout_hash = std.fmt.bytesToHex(records.fileIdentity(stdout), .lower);
        const stderr_hash = std.fmt.bytesToHex(records.fileIdentity(stderr), .lower);
        results[index] = .{
            .name = @tagName(scenario),
            .primary = switch (scenario) {
                .ok, .nonzero, .partial => "exited",
                .signal => "signal",
                .overflow => "output_overflow",
                .timeout => "timeout",
                .cancelled => "cancelled",
            },
            .exit_code = switch (scenario) {
                .ok => 0,
                .nonzero => 7,
                .partial => 9,
                else => -1,
            },
            .stdout_bytes = stdout.len,
            .stdout_sha256 = try a.dupe(u8, &stdout_hash),
            .stderr_bytes = stderr.len,
            .stderr_sha256 = try a.dupe(u8, &stderr_hash),
            .cleanup_complete = true,
            .executable_stable = true,
        };
    }
    return encode(allocator, &results);
}

pub fn encode(allocator: std.mem.Allocator, results: []const Observation) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "uk.wamr.native-ci-fixtures",
        .schema_version = 1,
        .production_modes = 6,
        .build_stages = 6,
        .status = "passed",
        .scenarios = results,
    }, .{});
    defer allocator.free(raw);
    return records.canonicalAlloc(allocator, raw);
}

pub fn verify(allocator: std.mem.Allocator, raw: []const u8) !void {
    if (raw.len > 8192) return error.FixtureChanged;
    const observed = records.canonicalAlloc(allocator, raw) catch return error.FixtureChanged;
    defer allocator.free(observed);
    const pinned = try expected(allocator);
    defer allocator.free(pinned);
    if (!std.mem.eql(u8, observed, raw) or !std.mem.eql(u8, observed, pinned))
        return error.FixtureChanged;
}
