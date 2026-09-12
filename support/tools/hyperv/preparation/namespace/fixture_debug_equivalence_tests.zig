const std = @import("std");
const gate = @import("equivalence");
const t = std.testing;
const a = t.allocator;
const io = t.io;

fn integer(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn image(raw: bool, machine: u16) [768]u8 {
    var bytes = [_]u8{0} ** 768;
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    integer(u16, &bytes, 16, 2);
    integer(u16, &bytes, 18, machine);
    integer(u32, &bytes, 20, 1);
    integer(u64, &bytes, 24, 0x400080);
    integer(u64, &bytes, 32, 64);
    integer(u64, &bytes, 40, if (raw) 512 else 320);
    integer(u16, &bytes, 52, 64);
    integer(u16, &bytes, 54, 56);
    integer(u16, &bytes, 56, 1);
    integer(u16, &bytes, 58, 64);
    integer(u16, &bytes, 60, if (raw) 4 else 3);
    integer(u16, &bytes, 62, if (raw) 3 else 2);
    integer(u32, &bytes, 64, std.elf.PT_LOAD);
    integer(u32, &bytes, 68, std.elf.PF_R | std.elf.PF_X);
    integer(u64, &bytes, 80, 0x400000);
    integer(u64, &bytes, 88, 0x400000);
    integer(u64, &bytes, 96, 256);
    integer(u64, &bytes, 104, 256);
    integer(u64, &bytes, 112, 4096);
    @memset(bytes[128..144], 0x90);
    const names = "\x00.text\x00.debug_info\x00.shstrtab\x00";
    const strings: usize = if (raw) 320 else 256;
    @memcpy(bytes[strings..][0..names.len], names);
    const table: usize = if (raw) 512 else 320;
    const text = table + 64;
    integer(u32, &bytes, text, 1);
    integer(u32, &bytes, text + 4, std.elf.SHT_PROGBITS);
    integer(u64, &bytes, text + 8, std.elf.SHF_ALLOC | std.elf.SHF_EXECINSTR);
    integer(u64, &bytes, text + 16, 0x400080);
    integer(u64, &bytes, text + 24, 128);
    integer(u64, &bytes, text + 32, 16);
    integer(u64, &bytes, text + 48, 16);
    if (raw) {
        @memset(bytes[256..320], 0xd7);
        const debug = table + 128;
        integer(u32, &bytes, debug, 7);
        integer(u32, &bytes, debug + 4, std.elf.SHT_PROGBITS);
        integer(u64, &bytes, debug + 24, 256);
        integer(u64, &bytes, debug + 32, 64);
        integer(u64, &bytes, debug + 48, 1);
    }
    const str = table + (if (raw) @as(usize, 192) else 128);
    integer(u32, &bytes, str, 19);
    integer(u32, &bytes, str + 4, std.elf.SHT_STRTAB);
    integer(u64, &bytes, str + 24, strings);
    integer(u64, &bytes, str + 32, names.len);
    integer(u64, &bytes, str + 48, 1);
    return bytes;
}

fn requireRejected(raw: []const u8, candidate: []const u8) !void {
    if (gate.compare(a, raw, candidate)) |_| return error.AcceptedNonEquivalentElf else |_| {}
}

test "debug equivalence preserves ELF64 loaded bytes and records only locator normalization" {
    for ([_]u16{ @intFromEnum(std.elf.EM.AARCH64), @intFromEnum(std.elf.EM.X86_64) }) |machine| {
        const raw = image(true, machine);
        const candidate = image(false, machine);
        const proof = try gate.compare(a, &raw, candidate[0..512]);
        try t.expectEqual(@as(usize, 1), proof.load_segments);
        try t.expectEqual(@as(u64, 256), proof.loaded_file_bytes);
        try t.expectEqual(@as(u64, 64), proof.removed_debug_bytes);
        try t.expectEqual(@as(u64, 256), proof.size_reduction);
        try t.expectEqual(@as(usize, 3), proof.normalization.len);
        const offsets = [_]usize{ 40, 60, 62 };
        const widths = [_]usize{ 8, 2, 2 };
        for (proof.normalization, offsets, widths) |field, offset, width| {
            try t.expect(field.changed);
            try t.expectEqual(offset, field.offset);
            try t.expectEqual(width, field.width);
        }
        const json = try std.json.Stringify.valueAlloc(a, proof, .{});
        defer a.free(json);
        try t.expect(std.mem.indexOf(u8, json, "\"loaded_content_sha256\":\"") != null);
    }
}

test "debug equivalence rejects loaded changes entry headers and normalization neighbors" {
    const raw = image(true, @intFromEnum(std.elf.EM.AARCH64));
    const good = image(false, @intFromEnum(std.elf.EM.AARCH64));
    for ([_]usize{ 4, 5, 7, 18, 24, 32, 48, 52, 54, 56, 58, 68, 88, 140, 250 }) |offset| {
        var bad = good;
        bad[offset] ^= 1;
        try requireRejected(&raw, bad[0..512]);
    }
    var load_changed = good;
    load_changed[140] ^= 1;
    try t.expectError(error.LoadedContentChanged, gate.compare(a, &raw, load_changed[0..512]));
}

test "debug equivalence validates both section tables before normalization and actual removal" {
    const raw = image(true, @intFromEnum(std.elf.EM.AARCH64));
    const good = image(false, @intFromEnum(std.elf.EM.AARCH64));
    var bad = good;
    integer(u64, &bad, 40, 500);
    try requireRejected(&raw, bad[0..512]);
    bad = good;
    integer(u16, &bad, 60, 0);
    try requireRejected(&raw, bad[0..512]);
    bad = good;
    integer(u16, &bad, 62, 65535);
    try requireRejected(&raw, bad[0..512]);
    bad = good;
    integer(u64, &bad, 40, 128);
    try requireRejected(&raw, bad[0..512]);
    try t.expectError(error.DebugDataRetained, gate.compare(a, &raw, &raw));
    var loaded_debug = raw;
    integer(u64, &loaded_debug, 512 + 128 + 24, 144);
    try t.expectError(error.LoadedDebugData, gate.compare(a, &loaded_debug, good[0..512]));
    var absent_debug = raw;
    @memcpy(absent_debug[320 + 7 ..][0..6], ".other");
    try t.expectError(error.NoDebugData, gate.compare(a, &absent_debug, good[0..512]));
}

test "debug equivalence pins identity hashes and rejects symlinks and input mutation" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory);
    const raw_path = try std.fs.path.join(a, &.{ directory, "raw" });
    defer a.free(raw_path);
    const candidate_path = try std.fs.path.join(a, &.{ directory, "candidate" });
    defer a.free(candidate_path);
    const link_path = try std.fs.path.join(a, &.{ directory, "link" });
    defer a.free(link_path);
    const raw = image(true, @intFromEnum(std.elf.EM.AARCH64));
    const candidate = image(false, @intFromEnum(std.elf.EM.AARCH64));
    try temporary.dir.writeFile(io, .{ .sub_path = "raw", .data = &raw, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try temporary.dir.writeFile(io, .{ .sub_path = "candidate", .data = candidate[0..512], .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    const pair = try gate.Pair.open(a, io, raw_path, candidate_path);
    defer pair.close(a, io);
    try pair.recheck(io);
    try temporary.dir.symLink(io, "raw", "link", .{});
    if (gate.Pinned.open(a, io, link_path)) |value| {
        value.close(a, io);
        return error.AcceptedSymlink;
    } else |_| {}
    const writer = try temporary.dir.openFile(io, "candidate", .{ .mode = .read_write });
    defer writer.close(io);
    try writer.writePositionalAll(io, &.{0x91}, 140);
    try t.expectError(error.InputChanged, pair.recheck(io));
    const held = try gate.Pinned.open(a, io, raw_path);
    defer held.close(a, io);
    try temporary.dir.rename("raw", temporary.dir, "old", io);
    try temporary.dir.writeFile(io, .{ .sub_path = "raw", .data = &raw, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try t.expectError(error.InputChanged, held.recheck(io));
}

test "debug equivalence reports are private bounded create-only and non-admitting" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(path);
    const output = try std.fs.path.join(a, &.{ path, "proof.json" });
    defer a.free(output);
    const value = .{ .schema = "synthetic_fixture_test", .authority = "synthetic_only_not_admitted" };
    try gate.publish(a, io, output, value);
    try t.expectError(error.PathAlreadyExists, gate.publish(a, io, output, value));
    const file = try temporary.dir.openFile(io, "proof.json", .{});
    defer file.close(io);
    const before = try gate.core.private_files.snapshot(file);
    try t.expectEqual(@as(u16, 0o600), before.mode & 0o777);
    const oversize = try std.fs.path.join(a, &.{ path, "oversize.json" });
    defer a.free(oversize);
    try t.expectError(error.ReportTooLarge, gate.publish(a, io, oversize, "x" ** gate.max_report_bytes));
    try t.expectError(error.FileNotFound, temporary.dir.openFile(io, "oversize.json", .{}));
}
