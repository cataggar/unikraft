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
        try t.expect(std.mem.indexOf(u8, json, "\"mapped_loaded_content_sha256\":\"") != null);
        try t.expectEqual(gate.LayoutPolicy.identical_program_headers, proof.layout_policy);
        try t.expectEqualStrings(&proof.raw_program_headers_sha256, &proof.candidate_program_headers_sha256);
        try t.expectEqualStrings(&proof.raw_program_headers_sha256, &proof.normalized_program_headers_sha256);
        try t.expectEqual(@as(usize, 1), proof.program_mappings.len);
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
    const proof: gate.SuiteProof = .{
        .pairs = .{ pair.proof(.namespace_helper), pair.proof(.namespace_fixture) },
    };
    const json = try std.json.Stringify.valueAlloc(a, proof, .{});
    defer a.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try t.expectEqual(@as(usize, 9), object.count());
    try t.expectEqualStrings("hyperv_fixture_debug_stripping_v2", object.get("schema").?.string);
    try t.expectEqualStrings("identical_program_headers", object.get("layout_policy").?.string);
    try t.expectEqualStrings("synthetic_only_not_admitted", object.get("authority").?.string);
    try t.expect(object.get("passed").?.bool and object.get("synthetic").?.bool and object.get("qualification_only").?.bool);
    try t.expect(!object.get("admitted").?.bool);
    try t.expect(object.get("external_fixture").? == .null);
    const pairs = object.get("pairs").?.array.items;
    try t.expectEqual(@as(usize, 2), pairs.len);
    for (pairs, [_][]const u8{ "namespace_helper", "namespace_fixture" }) |item, role| {
        try t.expectEqualStrings(role, item.object.get("role").?.string);
        for ([_][]const u8{ "raw", "candidate" }, [_]gate.Pinned{ pair.raw, pair.candidate }) |field, input| {
            const file = item.object.get(field).?.object;
            try t.expectEqual(@as(i64, @intCast(input.bytes.len)), file.get("size").?.integer);
            try t.expectEqualStrings(&std.fmt.bytesToHex(input.hash, .lower), file.get("sha256").?.string);
            try t.expect(file.get("stable_identity_and_hash").?.bool);
        }
    }
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

fn program(bytes: []u8, index: usize, kind: u32, flags: u32, offset: u64, address: u64, size: u64, memory: u64, alignment: u64) void {
    const start = 64 + index * 56;
    integer(u32, bytes, start, kind);
    integer(u32, bytes, start + 4, flags);
    integer(u64, bytes, start + 8, offset);
    integer(u64, bytes, start + 16, address);
    integer(u64, bytes, start + 24, address);
    integer(u64, bytes, start + 32, size);
    integer(u64, bytes, start + 40, memory);
    integer(u64, bytes, start + 48, alignment);
}

fn relayoutImage(raw: bool, machine: u16) [524288]u8 {
    var bytes = [_]u8{0} ** 524288;
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    integer(u16, &bytes, 16, 2);
    integer(u16, &bytes, 18, machine);
    integer(u32, &bytes, 20, 1);
    integer(u64, &bytes, 24, 0x402080);
    integer(u64, &bytes, 32, 64);
    const table: usize = if (raw) 0x70000 else 0x34000;
    integer(u64, &bytes, 40, table);
    integer(u16, &bytes, 52, 64);
    integer(u16, &bytes, 54, 56);
    integer(u16, &bytes, 56, 7);
    integer(u16, &bytes, 58, 64);
    integer(u16, &bytes, 60, if (raw) 6 else 5);
    integer(u16, &bytes, 62, if (raw) 5 else 4);
    const ro: usize = if (raw) 0x60000 else 0x30000;
    const rx: usize = if (raw) 0x40000 else 0x10000;
    const rw: usize = if (raw) 0x30000 else 0x20000;
    program(&bytes, 0, std.elf.PT_PHDR, std.elf.PF_R, 64, 0x400040, 7 * 56, 7 * 56, 8);
    program(&bytes, 1, std.elf.PT_LOAD, std.elf.PF_R, 0, 0x400000, 512, 512, 4096);
    program(&bytes, 2, std.elf.PT_LOAD, std.elf.PF_R, ro, 0x401000, 256, 256, 256);
    program(&bytes, 3, std.elf.PT_LOAD, std.elf.PF_R | std.elf.PF_X, rx, 0x402000, 512, 512, 256);
    program(&bytes, 4, std.elf.PT_LOAD, std.elf.PF_R | std.elf.PF_W, rw, 0x403000, 512, 768, 256);
    program(&bytes, 5, std.elf.PT_GNU_EH_FRAME, std.elf.PF_R, ro + 64, 0x401040, 16, 16, 8);
    program(&bytes, 6, std.elf.PT_GNU_STACK, std.elf.PF_R | std.elf.PF_W, 0, 0, 0, 0, 16);
    @memset(bytes[ro..][0..256], 0x71);
    @memset(bytes[rx..][0..512], 0x92);
    @memset(bytes[rw..][0..512], 0x53);
    const names = "\x00.text\x00.rodata\x00.data\x00.debug_info\x00.shstrtab\x00";
    const strings: usize = if (raw) 0x64000 else 0x32000;
    @memcpy(bytes[strings..][0..names.len], names);
    for ([_]usize{ 1, 7, 15 }, [_]usize{ rx, ro, rw }, [_]u64{ 0x402000, 0x401000, 0x403000 }, [_]u64{ 512, 256, 512 }, 1..) |name, offset, address, size, index| {
        const start = table + index * 64;
        integer(u32, &bytes, start, @intCast(name));
        integer(u32, &bytes, start + 4, std.elf.SHT_PROGBITS);
        integer(u64, &bytes, start + 8, std.elf.SHF_ALLOC);
        integer(u64, &bytes, start + 16, address);
        integer(u64, &bytes, start + 24, offset);
        integer(u64, &bytes, start + 32, size);
        integer(u64, &bytes, start + 48, 16);
    }
    if (raw) {
        @memset(bytes[0x62000..0x62200], 0xd7);
        const start = table + 4 * 64;
        integer(u32, &bytes, start, 21);
        integer(u32, &bytes, start + 4, std.elf.SHT_PROGBITS);
        integer(u64, &bytes, start + 24, 0x62000);
        integer(u64, &bytes, start + 32, 512);
        integer(u64, &bytes, start + 48, 1);
    }
    const str = table + (if (raw) @as(usize, 5) else 4) * 64;
    integer(u32, &bytes, str, 33);
    integer(u32, &bytes, str + 4, std.elf.SHT_STRTAB);
    integer(u64, &bytes, str + 24, strings);
    integer(u64, &bytes, str + 32, names.len);
    integer(u64, &bytes, str + 48, 1);
    return bytes;
}

fn requireRelayoutRejected(raw: []const u8, candidate: []const u8) !void {
    if (gate.compareWithPolicy(a, raw, candidate, .file_offset_relayout)) |_|
        return error.AcceptedNonEquivalentRelayout
    else |_| {}
}

test "file relayout requires explicit policy and maps overlapping PHDR LOAD and EH records coherently" {
    for ([_]u16{ @intFromEnum(std.elf.EM.AARCH64), @intFromEnum(std.elf.EM.X86_64) }) |machine| {
        const raw = relayoutImage(true, machine);
        const candidate = relayoutImage(false, machine);
        try t.expectError(error.ProgramHeadersChanged, gate.compare(a, &raw, candidate[0..0x40000]));
        const proof = try gate.compareWithPolicy(a, &raw, candidate[0..0x40000], .file_offset_relayout);
        try t.expectEqual(gate.LayoutPolicy.file_offset_relayout, proof.layout_policy);
        try t.expectEqual(@as(usize, 4), proof.load_segments);
        try t.expectEqual(@as(u64, 1792), proof.loaded_file_bytes);
        try t.expectEqual(@as(usize, 7), proof.program_mappings.len);
        try t.expect(!std.mem.eql(u8, &proof.raw_program_headers_sha256, &proof.candidate_program_headers_sha256));
        try t.expect(!std.mem.eql(u8, &proof.raw_program_headers_sha256, &proof.normalized_program_headers_sha256));
        var changes: usize = 0;
        for (proof.program_mappings.slice(), 0..) |mapping, index| {
            try t.expectEqual(index, mapping.index);
            try t.expectEqual(@as(u64, 64 + index * 56 + 8), mapping.offset_field_file_offset);
            try t.expectEqual(@as(u8, 8), mapping.offset_field_width);
            if (mapping.changed) changes += 1;
        }
        try t.expectEqual(@as(usize, 4), changes);
        const json = try std.json.Stringify.valueAlloc(a, proof, .{});
        defer a.free(json);
        const parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
        defer parsed.deinit();
        const mappings = parsed.value.object.get("program_mappings").?.array.items;
        try t.expectEqual(@as(usize, 7), mappings.len);
        try t.expectEqualStrings("file_offset_relayout", parsed.value.object.get("layout_policy").?.string);
        try t.expectEqual(@as(usize, 8), mappings[2].object.count());
        try t.expectEqual(@as(i64, 0x60000), mappings[2].object.get("raw_offset").?.integer);
        try t.expectEqual(@as(i64, 0x30000), mappings[2].object.get("candidate_offset").?.integer);
        try t.expectEqualStrings(&proof.program_mappings.records[2].logical_mapping_sha256, mappings[2].object.get("logical_mapping_sha256").?.string);
    }
}

test "file relayout preserves strict unchanged offsets and rejects header layout permissions code and data changes" {
    const old_raw = image(true, @intFromEnum(std.elf.EM.AARCH64));
    const old_candidate = image(false, @intFromEnum(std.elf.EM.AARCH64));
    const unchanged = try gate.compareWithPolicy(a, &old_raw, old_candidate[0..512], .file_offset_relayout);
    try t.expect(!unchanged.program_mappings.records[0].changed);
    const raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    const good = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    for ([_]usize{
        0,           4,               5,                7,                16,               18,               20,               24,    32,      48,      52,      54, 56, 58,
        64 + 2 * 56, 64 + 2 * 56 + 4, 64 + 2 * 56 + 16, 64 + 2 * 56 + 24, 64 + 2 * 56 + 32, 64 + 2 * 56 + 40, 64 + 2 * 56 + 48, 0x1f0, 0x10080, 0x20080, 0x30080,
    }) |offset| {
        var bad = good;
        bad[offset] ^= 1;
        try requireRelayoutRejected(&raw, bad[0..0x40000]);
    }
    var reordered = good;
    const saved: [56]u8 = reordered[64 + 2 * 56 ..][0..56].*;
    @memcpy(reordered[64 + 2 * 56 ..][0..56], reordered[64 + 3 * 56 ..][0..56]);
    @memcpy(reordered[64 + 3 * 56 ..][0..56], &saved);
    try t.expectError(error.ProgramHeadersChanged, gate.compareWithPolicy(a, &raw, reordered[0..0x40000], .file_offset_relayout));
}

test "file relayout rejects misaligned out of bounds zero byte unknown and anchored offsets" {
    const raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    const good = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    var bad = good;
    integer(u64, &bad, 64 + 2 * 56 + 8, 0x30001);
    try t.expectError(error.InvalidLoadAlignment, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    integer(u64, &bad, 64 + 2 * 56 + 8, 0x90000);
    try t.expectError(error.Truncated, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    bad = good;
    integer(u64, &bad, 64 + 6 * 56 + 8, 16);
    try t.expectError(error.UnmovableProgramOffset, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    bad = good;
    integer(u64, &bad, 64 + 8, 128);
    try t.expectError(error.InvalidPhdrMapping, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    for ([_]u32{ std.elf.PT_NULL, 0x12345678 }) |kind| {
        var before = raw;
        bad = good;
        program(&before, 5, kind, std.elf.PF_R, 0x60040, 0, 16, 16, 8);
        program(&bad, 5, kind, std.elf.PF_R, 0x30040, 0, 16, 16, 8);
        try t.expectError(error.UnmovableProgramOffset, gate.compareWithPolicy(a, &before, bad[0..0x40000], .file_offset_relayout));
    }
    for ([_]u64{ 32, 184 }) |offset| {
        var before = raw;
        bad = good;
        program(&before, 6, std.elf.PT_NOTE, std.elf.PF_R, offset, 0, 8, 8, 8);
        program(&bad, 6, std.elf.PT_NOTE, std.elf.PF_R, offset + 8, 0, 8, 8, 8);
        try t.expectError(error.MetadataMappingChanged, gate.compareWithPolicy(a, &before, bad[0..0x40000], .file_offset_relayout));
    }
    bad = good;
    integer(u16, &bad, 56, gate.max_programs + 1);
    try t.expectError(error.UnsupportedElfTables, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
}

test "file relayout rejects ambiguous loads and changed nonload backing aliases" {
    const raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    const good = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    var bad = good;
    integer(u64, &bad, 64 + 3 * 56 + 8, 0x20000);
    integer(u64, &bad, 0x34000 + 64 + 24, 0x20000);
    try t.expectError(error.AmbiguousLoadMapping, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    bad = good;
    integer(u64, &bad, 64 + 5 * 56 + 8, 0x30050);
    try t.expectError(error.UnmappedProgramRecord, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    for ([_]u64{ 0x30050, 0x33000 }) |offset| {
        var before = raw;
        bad = good;
        program(&before, 5, std.elf.PT_NOTE, std.elf.PF_R, 0x60040, 0, 16, 16, 8);
        program(&bad, 5, std.elf.PT_NOTE, std.elf.PF_R, offset, 0, 16, 16, 8);
        @memset(bad[@intCast(offset)..][0..16], 0x71);
        try t.expectError(error.ProgramBackingChanged, gate.compareWithPolicy(a, &before, bad[0..0x40000], .file_offset_relayout));
    }
}

test "file relayout compares nonload program bytes outside every LOAD" {
    var raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    var candidate = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    program(&raw, 6, std.elf.PT_NOTE, std.elf.PF_R, 0x65000, 0, 16, 16, 8);
    program(&candidate, 6, std.elf.PT_NOTE, std.elf.PF_R, 0x33000, 0, 16, 16, 8);
    @memset(raw[0x65000..][0..16], 0x36);
    @memset(candidate[0x33000..][0..16], 0x36);
    const proof = try gate.compareWithPolicy(a, &raw, candidate[0..0x40000], .file_offset_relayout);
    try t.expect(proof.program_mappings.records[6].changed);
    try t.expectEqual(@as(usize, 4), proof.load_segments);
    candidate[0x33007] ^= 1;
    try t.expectError(error.LoadedContentChanged, gate.compareWithPolicy(a, &raw, candidate[0..0x40000], .file_offset_relayout));
}

test "file relayout preserves target page residues and validates nonload alignment and address bounds" {
    const raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    const good = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    for ([_]u64{ 0x30100, 0x31000 }) |offset| {
        var bad = good;
        integer(u64, &bad, 64 + 2 * 56 + 8, offset);
        integer(u64, &bad, 64 + 5 * 56 + 8, offset + 64);
        integer(u64, &bad, 0x34000 + 2 * 64 + 24, offset);
        @memset(bad[@intCast(offset)..][0..256], 0x71);
        const expected = if (offset == 0x30100) error.InvalidLoadPageAlignment else error.LoadPageOffsetChanged;
        try t.expectError(expected, gate.compareWithPolicy(a, &raw, bad[0..0x40000], .file_offset_relayout));
    }
    var before = raw;
    var bad = good;
    integer(u64, &before, 64 + 5 * 56 + 48, 6);
    integer(u64, &bad, 64 + 5 * 56 + 48, 6);
    try t.expectError(error.InvalidProgramAlignment, gate.compareWithPolicy(a, &before, bad[0..0x40000], .file_offset_relayout));
    before = raw;
    bad = good;
    integer(u64, &before, 64 + 2 * 56 + 24, std.math.maxInt(u64) - 128);
    integer(u64, &bad, 64 + 2 * 56 + 24, std.math.maxInt(u64) - 128);
    try t.expectError(error.IntegerOverflow, gate.compareWithPolicy(a, &before, bad[0..0x40000], .file_offset_relayout));
}

test "file relayout does not normalize executable or allocated program header bytes" {
    var raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    var candidate = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    integer(u64, &raw, 24, 0x4000b8);
    integer(u64, &candidate, 24, 0x4000b8);
    integer(u32, &raw, 64 + 56 + 4, std.elf.PF_R | std.elf.PF_X);
    integer(u32, &candidate, 64 + 56 + 4, std.elf.PF_R | std.elf.PF_X);
    try t.expectError(error.EntryInProgramHeaders, gate.compareWithPolicy(a, &raw, candidate[0..0x40000], .file_offset_relayout));
    raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    candidate = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    for ([_]*[524288]u8{ &raw, &candidate }, [_]usize{ 0x70000, 0x34000 }) |bytes, table| {
        integer(u64, bytes, table + 64 + 16, 0x4000b8);
        integer(u64, bytes, table + 64 + 24, 0xb8);
        integer(u64, bytes, table + 64 + 32, 8);
    }
    try t.expectError(error.AllocatedProgramHeaders, gate.compareWithPolicy(a, &raw, candidate[0..0x40000], .file_offset_relayout));
    raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    candidate = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    integer(u32, &raw, 64 + 56 + 4, std.elf.PF_R | std.elf.PF_X);
    integer(u32, &candidate, 64 + 56 + 4, std.elf.PF_R | std.elf.PF_X);
    try t.expectError(error.ExecutableProgramHeaderNormalization, gate.compareWithPolicy(a, &raw, candidate[0..0x40000], .file_offset_relayout));
}

test "file relayout pins still reject mutation and mapping proof growth remains bounded" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory);
    const raw_path = try std.fs.path.join(a, &.{ directory, "raw" });
    defer a.free(raw_path);
    const candidate_path = try std.fs.path.join(a, &.{ directory, "candidate" });
    defer a.free(candidate_path);
    const raw = relayoutImage(true, @intFromEnum(std.elf.EM.AARCH64));
    const candidate = relayoutImage(false, @intFromEnum(std.elf.EM.AARCH64));
    try temporary.dir.writeFile(io, .{ .sub_path = "raw", .data = &raw, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try temporary.dir.writeFile(io, .{ .sub_path = "candidate", .data = candidate[0..0x40000], .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    const pair = try gate.Pair.openWithPolicy(a, io, raw_path, candidate_path, .file_offset_relayout);
    defer pair.close(a, io);
    try pair.recheck(io);
    var proof: gate.SuiteProof = .{ .layout_policy = .file_offset_relayout, .pairs = .{ pair.proof(.namespace_helper), pair.proof(.namespace_fixture) } };
    for (&proof.pairs) |*item| {
        for (&item.content.program_mappings.records) |*mapping| mapping.* = pair.content.program_mappings.records[2];
        item.content.program_mappings.len = gate.max_programs;
    }
    const report = try std.fs.path.join(a, &.{ directory, "oversize.json" });
    defer a.free(report);
    try t.expectError(error.ReportTooLarge, gate.publish(a, io, report, proof));
    try t.expectError(error.FileNotFound, temporary.dir.openFile(io, "oversize.json", .{}));
    const writer = try temporary.dir.openFile(io, "candidate", .{ .mode = .read_write });
    defer writer.close(io);
    try writer.writePositionalAll(io, &.{0x91}, 0x10080);
    try t.expectError(error.InputChanged, pair.recheck(io));
}
