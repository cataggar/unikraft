const std = @import("std");
const gate = @import("equivalence");
const options = @import("strip_options");
const t = std.testing;
const a = t.allocator;
const io = t.io;

test "synthetic QEMU selection preserves both raw pairs and labels only test artifacts" {
    if (!options.stripped) {
        try t.expectEqualStrings(options.raw_plain, options.plain);
        try t.expectEqualStrings(options.raw_diagnostic, options.diagnostic);
        try t.expect(options.report == null);
        return;
    }
    const plain = try gate.Pair.openWithPolicy(a, io, options.raw_plain, options.plain, .file_offset_relayout);
    defer plain.close(a, io);
    const diagnostic = try gate.Pair.openWithPolicy(a, io, options.raw_diagnostic, options.diagnostic, .file_offset_relayout);
    defer diagnostic.close(a, io);
    for ([_]gate.Pair{ plain, diagnostic }) |pair| {
        try t.expect(pair.content.size_reduction > 0);
        try t.expect(pair.content.removed_debug_sections > 0);
        try t.expect(pair.content.loaded_file_bytes > 0);
        try pair.recheck(io);
    }
    try t.expect(!std.mem.eql(u8, &plain.candidate.hash, &diagnostic.candidate.hash));
    if (options.report) |path| try gate.publish(a, io, path, .{
        .schema = "hyperv_local_boot_fixture_stripping_v1",
        .authority = "synthetic_only_not_admitted",
        .layout_policy = gate.LayoutPolicy.file_offset_relayout,
        .plain_qemu_fixture = .{ .raw = plain.raw.proof(), .candidate = plain.candidate.proof(), .content = plain.content },
        .diagnostic_qemu_fixture = .{ .raw = diagnostic.raw.proof(), .candidate = diagnostic.candidate.proof(), .content = diagnostic.content },
        .production_cli_modified = false,
    });
}

fn refused(args: []const []const u8) !void {
    const result = try std.process.run(a, io, .{
        .argv = args,
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
    });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try t.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try t.expectEqual(@as(usize, 0), result.stdout.len);
    try t.expect(std.mem.startsWith(u8, result.stderr, "fixture_debug_equivalence_failed: "));
}

test "synthetic QEMU verifier refuses alias substitution and unknown policy" {
    try refused(&.{ options.verifier, "pair", options.raw_plain, options.raw_plain, "--layout-policy", "file_offset_relayout" });
    try refused(&.{ options.verifier, "pair", options.raw_plain, options.diagnostic, "--layout-policy", "file_offset_relayout" });
    try refused(&.{ options.verifier, "pair", options.raw_plain, options.plain, "--layout-policy", "unchecked" });
    try refused(&.{ options.verifier, "pair", options.raw_plain, options.plain, "--external", options.plain });
}
