const std = @import("std");
const gate = @import("equivalence");
const options = @import("sample_options");
const t = std.testing;
const a = t.allocator;
const io = t.io;

fn readData(path: []const u8, expected_size: u64, expected_hash: []const u8) !gate.Pinned {
    const file = try gate.core.private_files.openAbsolute(io, path, .artifact);
    errdefer file.close(io);
    const before = try gate.core.private_files.snapshot(file);
    try t.expectEqual(@as(u16, 0o400), before.mode & 0o7777);
    try t.expectEqual(expected_size, before.size);
    const bytes = try a.alloc(u8, @intCast(before.size));
    errdefer a.free(bytes);
    try t.expectEqual(bytes.len, try file.readPositionalAll(io, bytes, 0));
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    try t.expectEqualStrings(expected_hash, &std.fmt.bytesToHex(hash, .lower));
    // Test-only construction reuses the complete descriptor/hash/path recheck.
    // The executable admission constructor below must still reject this data.
    const result: gate.Pinned = .{ .file = file, .path = path, .before = before, .bytes = bytes, .hash = hash };
    try result.recheck(io);
    return result;
}

test "copied x64 Debug helper is data only and requires explicit file offset relayout" {
    const raw = try readData(options.raw, 25161272, "2a9498e84fbf331c22bdad5eeca974a27b4eac30cdf3339b6805116beb916c65");
    defer raw.close(a, io);
    const candidate = try readData(options.candidate, 6851600, "9bd072607e01c4adbf880e4df0fac53e6c16e157adde519e4d86906fd2396f3d");
    defer candidate.close(a, io);
    try t.expectError(error.UnsafeExecutable, gate.Pinned.open(a, io, options.raw));
    try t.expectError(error.UnsafeExecutable, gate.Pinned.open(a, io, options.candidate));
    try t.expectError(error.ProgramHeadersChanged, gate.compare(a, raw.bytes, candidate.bytes));
    const content = try gate.compareWithPolicy(a, raw.bytes, candidate.bytes, .file_offset_relayout);
    try t.expectEqual(std.elf.EM.X86_64, content.machine);
    try t.expectEqual(@as(usize, 4), content.load_segments);
    var changed: usize = 0;
    for (content.program_mappings.slice()) |mapping| {
        if (mapping.changed) changed += 1;
    }
    try t.expectEqual(@as(usize, 4), changed);
    try raw.recheck(io);
    try candidate.recheck(io);
    if (options.report) |path| try gate.publish(a, io, path, .{
        .schema = "hyperv_fixture_debug_relayout_sample_v2",
        .authority = "synthetic_only_not_admitted",
        .passed = true,
        .synthetic = true,
        .admitted = false,
        .qualification_only = true,
        .executed = false,
        .strict_rejected = true,
        .layout_policy = gate.LayoutPolicy.file_offset_relayout,
        .pair = gate.PairProof{ .role = .namespace_helper, .raw = raw.proof(), .candidate = candidate.proof(), .content = content },
    });
}
