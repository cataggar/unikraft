// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const format = @import("postprocess-elf.zig");
const transform = @import("postprocess-image.zig");
const runner = @import("native-postprocess-runner.zig");
const testing = std.testing;
const base = 0x400000;
const section_table = 0x7000;
const symbol_table = 0x6600;
const strings_offset = 0x6200;
const names_offset = 0x6000;
const names = "\x00.shstrtab\x00.strtab\x00.symtab\x00.text\x00.data\x00.dynamic\x00.rela.dyn\x00.uk_reloc\x00.uk_bootinfo\x00.bss\x00";
const symbol_names = "\x00_base_addr\x00_uk_reloc_start\x00_uk_reloc_end\x00__bss_start\x00uk_efi_entry64\x00target\x00target_uk_reloc_data8_phys_0\x00target_uk_reloc_pte_attr0_0\x00negative\x00negative_uk_reloc_imm4_0\x00_start16_uk_reloc_data8_0\x00";

pub fn fixture(endian: std.builtin.Endian, machine: std.elf.EM) [0x7400]u8 {
    var bytes = @as([0x7400]u8, @splat(0));
    @memset(bytes[280..0x1000], 0x5a);
    @memset(bytes[0x1000..0x2200], 0xcc);
    @memcpy(bytes[0..4], "\x7fELF");
    bytes[4] = 2;
    bytes[5] = if (endian == .little) 1 else 2;
    bytes[6] = 1;
    put(u16, &bytes, 16, 3, endian);
    put(u16, &bytes, 18, @backingInt(machine), endian);
    put(u32, &bytes, 20, 1, endian);
    put(u64, &bytes, 24, base + 0x1010, endian);
    put(u64, &bytes, 32, 64, endian);
    put(u64, &bytes, 40, section_table, endian);
    put(u16, &bytes, 52, 64, endian);
    put(u16, &bytes, 54, 56, endian);
    put(u16, &bytes, 56, 3, endian);
    put(u16, &bytes, 58, 64, endian);
    put(u16, &bytes, 60, 11, endian);
    put(u16, &bytes, 62, 1, endian);
    program(&bytes, 0, 1, 5, 0x1000, base + 0x1000, 0x1000, 0x1000, endian);
    program(&bytes, 1, 1, 6, 0x2000, base + 0x2000, 0x3000, 0x6000, endian);
    program(&bytes, 2, 2, 6, 0x2200, base + 0x2200, 32, 32, endian);
    @memcpy(bytes[names_offset..][0..names.len], names);
    @memcpy(bytes[strings_offset..][0..symbol_names.len], symbol_names);
    section(&bytes, 1, ".shstrtab", 3, 0, names_offset, names.len, 0, 0, endian);
    section(&bytes, 2, ".strtab", 3, 0, strings_offset, symbol_names.len, 0, 0, endian);
    section(&bytes, 3, ".symtab", 2, 0, symbol_table, 12 * 24, 0, 24, endian);
    put(u32, &bytes, section_table + 3 * 64 + 40, 2, endian);
    put(u32, &bytes, section_table + 3 * 64 + 44, 1, endian);
    section(&bytes, 4, ".text", 1, 6, 0x1000, 0x1000, base + 0x1000, 0, endian);
    section(&bytes, 5, ".data", 1, 3, 0x2000, 0x100, base + 0x2000, 0, endian);
    section(&bytes, 6, ".dynamic", 6, 3, 0x2200, 32, base + 0x2200, 16, endian);
    section(&bytes, 7, ".rela.dyn", 4, 2, 0x2300, 72, base + 0x2300, 24, endian);
    section(&bytes, 8, ".uk_reloc", 1, 2, 0x2400, 256, base + 0x2400, 0, endian);
    section(&bytes, 9, ".uk_bootinfo", 1, 3, 0x3000, 0x300, base + 0x3000, 0, endian);
    section(&bytes, 10, ".bss", 8, 3, 0x5000, 0x3000, base + 0x5000, 0, endian);
    symbol(&bytes, 1, "_base_addr", base, endian);
    symbol(&bytes, 2, "_uk_reloc_start", base + 0x2400, endian);
    symbol(&bytes, 3, "_uk_reloc_end", base + 0x2500, endian);
    symbol(&bytes, 4, "__bss_start", base + 0x5000, endian);
    symbol(&bytes, 5, "uk_efi_entry64", base + 0x1010, endian);
    symbol(&bytes, 6, "target", base + 0x2100, endian);
    symbol(&bytes, 7, "target_uk_reloc_data8_phys_0", base + 0x2010, endian);
    symbol(&bytes, 8, "target_uk_reloc_pte_attr0_0", 3, endian);
    symbol(&bytes, 9, "negative", base - 8, endian);
    symbol(&bytes, 10, "negative_uk_reloc_imm4_0", base + 0x1020, endian);
    symbol(&bytes, 11, "_start16_uk_reloc_data8_0", base + 0x2020, endian);
    put(i64, &bytes, 0x2200, std.elf.DT_RELACOUNT, endian);
    put(u64, &bytes, 0x2208, 3, endian);
    const relative: u64 = if (machine == .X86_64) 8 else 1027;
    for ([_]u64{ 0x2010, 0x2018, 0x5000 }, [_]i64{ 0x2030, 0x1110, 0x2020 }, 0..) |offset, value, index| {
        put(u64, &bytes, 0x2300 + 24 * index, base + offset, endian);
        put(u64, &bytes, 0x2308 + 24 * index, relative, endian);
        put(i64, &bytes, 0x2310 + 24 * index, base + value, endian);
    }
    return bytes;
}

fn put(comptime T: type, bytes: []u8, offset: usize, value: T, endian: std.builtin.Endian) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, endian);
}

fn program(bytes: []u8, index: usize, kind: u32, flags: u32, offset: u64, address: u64, file_size: u64, memory_size: u64, endian: std.builtin.Endian) void {
    const pos = 64 + index * 56;
    put(u32, bytes, pos, kind, endian);
    put(u32, bytes, pos + 4, flags, endian);
    put(u64, bytes, pos + 8, offset, endian);
    put(u64, bytes, pos + 16, address, endian);
    put(u64, bytes, pos + 24, address, endian);
    put(u64, bytes, pos + 32, file_size, endian);
    put(u64, bytes, pos + 40, memory_size, endian);
    put(u64, bytes, pos + 48, if (kind == 1) 4096 else 8, endian);
}

fn section(bytes: []u8, index: usize, name: []const u8, kind: u32, flags: u64, offset: u64, size: u64, address: u64, entry_size: u64, endian: std.builtin.Endian) void {
    const pos = section_table + index * 64;
    put(u32, bytes, pos, @intCast(std.mem.indexOf(u8, names, name).?), endian);
    put(u32, bytes, pos + 4, kind, endian);
    put(u64, bytes, pos + 8, flags, endian);
    put(u64, bytes, pos + 16, address, endian);
    put(u64, bytes, pos + 24, offset, endian);
    put(u64, bytes, pos + 32, size, endian);
    put(u64, bytes, pos + 48, 1, endian);
    put(u64, bytes, pos + 56, entry_size, endian);
}

fn symbol(bytes: []u8, index: usize, name: []const u8, value: u64, endian: std.builtin.Endian) void {
    const pos = symbol_table + index * 24;
    put(u32, bytes, pos, @intCast(std.mem.indexOf(u8, symbol_names, name).?), endian);
    bytes[pos + 4] = 0x10;
    put(u16, bytes, pos + 6, std.elf.SHN_ABS, endian);
    put(u64, bytes, pos + 8, value, endian);
}

fn arm64LinuxFixture() [0x7400]u8 {
    var bytes = fixture(.little, .AARCH64);
    const extra_names = "_start_ram_addr\x00_libkvmplat_entry\x00";
    const start_ram_off = symbol_names.len;
    const entry_off = start_ram_off + "_start_ram_addr\x00".len;
    @memcpy(bytes[strings_offset + start_ram_off ..][0..extra_names.len], extra_names);
    put(u64, &bytes, section_table + 2 * 64 + 32, symbol_names.len + extra_names.len, .little);
    put(u64, &bytes, section_table + 3 * 64 + 32, 14 * 24, .little);
    symbol(&bytes, 1, "_base_addr", 0x40200040, .little);
    const pos12 = symbol_table + 12 * 24;
    put(u32, &bytes, pos12, @intCast(start_ram_off), .little);
    bytes[pos12 + 4] = 0x10;
    put(u16, &bytes, pos12 + 6, std.elf.SHN_ABS, .little);
    put(u64, &bytes, pos12 + 8, 0x40000000, .little);
    const pos13 = symbol_table + 13 * 24;
    put(u32, &bytes, pos13, @intCast(entry_off), .little);
    bytes[pos13 + 4] = 0x10;
    put(u16, &bytes, pos13 + 6, std.elf.SHN_ABS, .little);
    put(u64, &bytes, pos13 + 8, 0x40200080, .little);
    return bytes;
}

test "ELF64 parsing uses standard ELF structs and handles both byte orders and extended counts" {
    for ([_]std.builtin.Endian{ .little, .big }) |endian| {
        for ([_]std.elf.EM{ .X86_64, .AARCH64 }) |machine| {
            var bytes = fixture(endian, machine);
            put(u16, &bytes, 60, 0, endian);
            put(u16, &bytes, 56, 0xffff, endian);
            put(u16, &bytes, 62, 0xffff, endian);
            put(u64, &bytes, section_table + 32, 11, endian);
            put(u32, &bytes, section_table + 40, 1, endian);
            put(u32, &bytes, section_table + 44, 3, endian);
            var image = try format.Image.parse(testing.allocator, &bytes);
            defer image.deinit();
            try testing.expectEqual(base, try image.symbol("_base_addr"));
            try testing.expectEqual(11, image.sections.len);
            try testing.expectEqual(3, image.programs.len);
            try testing.expectEqual(0x2400, (try image.section(".uk_reloc")).header.sh_offset);
        }
    }
}

test "ELF bounds and malformed formats fail instead of trapping" {
    var bytes = fixture(.little, .X86_64);
    for ([_]usize{ 0, 16, 63 }) |length|
        try testing.expectError(error.EndOfStream, format.Image.parse(testing.allocator, bytes[0..length]));
    for ([_]usize{ 64, 128, 0x730 }) |length|
        try testing.expectError(error.Truncated, format.Image.parse(testing.allocator, bytes[0..length]));
    const mutations = [_]struct { offset: usize, value: u64, width: u8, expected: anyerror }{
        .{ .offset = 0, .value = 0, .width = 1, .expected = error.InvalidElfMagic },
        .{ .offset = 4, .value = 9, .width = 1, .expected = error.InvalidElfClass },
        .{ .offset = 4, .value = 1, .width = 1, .expected = error.UnsupportedClass },
        .{ .offset = 5, .value = 9, .width = 1, .expected = error.InvalidElfEndian },
        .{ .offset = 6, .value = 9, .width = 1, .expected = error.InvalidElfVersion },
        .{ .offset = 18, .value = 3, .width = 2, .expected = error.UnsupportedArchitecture },
        .{ .offset = 20, .value = 2, .width = 4, .expected = error.InvalidElfHeader },
        .{ .offset = 40, .value = std.math.maxInt(u64), .width = 8, .expected = error.Truncated },
        .{ .offset = 54, .value = 1, .width = 2, .expected = error.InvalidProgramTable },
        .{ .offset = 58, .value = 1, .width = 2, .expected = error.InvalidSectionTable },
        .{ .offset = section_table + 1 * 64 + 24, .value = 0x8000, .width = 8, .expected = error.Truncated },
        .{ .offset = section_table + 3 * 64 + 40, .value = 99, .width = 4, .expected = error.InvalidStringTable },
        .{ .offset = section_table + 3 * 64 + 56, .value = 0, .width = 8, .expected = error.InvalidSymbolTable },
        .{ .offset = section_table + 4 * 64, .value = 999, .width = 4, .expected = error.InvalidStringTable },
        .{ .offset = symbol_table + 24, .value = 999, .width = 4, .expected = error.InvalidStringTable },
        .{ .offset = symbol_table + 24 + 6, .value = std.elf.SHN_COMMON, .width = 2, .expected = error.CommonSymbol },
        .{ .offset = 64 + 32, .value = 0x2000, .width = 8, .expected = error.InvalidLoadSegment },
        .{ .offset = 64 + 16, .value = std.math.maxInt(u64), .width = 8, .expected = error.IntegerOverflow },
        .{ .offset = 64 + 48, .value = 3, .width = 8, .expected = error.InvalidLoadAlignment },
    };
    for (mutations) |mutation| {
        bytes = fixture(.little, .X86_64);
        switch (mutation.width) {
            1 => bytes[mutation.offset] = @intCast(mutation.value),
            2 => put(u16, &bytes, mutation.offset, @intCast(mutation.value), .little),
            4 => put(u32, &bytes, mutation.offset, @intCast(mutation.value), .little),
            8 => put(u64, &bytes, mutation.offset, mutation.value, .little),
            else => unreachable,
        }
        try testing.expectError(mutation.expected, format.Image.parse(testing.allocator, &bytes));
    }
}

test "empty SYMTAB and DYNSYM fail before the COMMON validator for both byte orders" {
    for ([_]std.builtin.Endian{ .little, .big }) |endian| {
        for ([_]u32{ std.elf.SHT_SYMTAB, std.elf.SHT_DYNSYM }) |kind| {
            var bytes = fixture(endian, .X86_64);
            put(u32, &bytes, section_table + 3 * 64 + 4, kind, endian);
            put(u64, &bytes, section_table + 3 * 64 + 32, 0, endian);
            put(u32, &bytes, section_table + 3 * 64 + 44, 0, endian);
            try testing.expectError(error.InvalidSymbolTable, format.Image.parse(testing.allocator, &bytes));
            put(u64, &bytes, section_table + 3 * 64 + 32, 24, endian);
            put(u32, &bytes, section_table + 3 * 64 + 44, 1, endian);
            var null_only = try format.Image.parse(testing.allocator, &bytes);
            defer null_only.deinit();
            try testing.expectEqual(0, null_only.symbols.len);
        }
    }
}

test "relocation blob is byte exact including override ordering PTE flags signed values filter and sentinel" {
    for ([_]std.builtin.Endian{ .little, .big }) |endian| {
        for ([_]std.elf.EM{ .X86_64, .AARCH64 }) |machine| {
            const bytes = fixture(endian, machine);
            var image = try format.Image.parse(testing.allocator, &bytes);
            defer image.deinit();
            const actual = try transform.relocations(testing.allocator, image);
            defer testing.allocator.free(actual);
            var expected = @as([100]u8, @splat(0));
            put(u32, &expected, 0, 0x0badb0b0, endian);
            for ([_]u64{ 0x2018, 0x2010, 0x1020 }, [_]i64{ 0x1110, 0x2103, -8 }, [_]u32{ 8, 8, 4 }, [_]u32{ 0, 1, 0 }, 0..) |offset, value, size, flags, index| {
                put(u64, &expected, 4 + index * 24, offset, endian);
                put(i64, &expected, 12 + index * 24, value, endian);
                put(u32, &expected, 20 + index * 24, size, endian);
                put(u32, &expected, 24 + index * 24, flags, endian);
            }
            try testing.expectEqualSlices(u8, &expected, actual);
        }
    }
}

test "binary-search symbol lookup detects duplicates and pre-indexed relocations preserve pte_attr data and imm parity" {
    const base_bytes = fixture(.little, .X86_64);
    var parsed = try format.Image.parse(testing.allocator, &base_bytes);
    defer parsed.deinit();
    const expected_symbols = [_]struct { name: []const u8, value: u64 }{
        .{ .name = "__bss_start", .value = base + 0x5000 },
        .{ .name = "_base_addr", .value = base },
        .{ .name = "_start16_uk_reloc_data8_0", .value = base + 0x2020 },
        .{ .name = "_uk_reloc_end", .value = base + 0x2500 },
        .{ .name = "_uk_reloc_start", .value = base + 0x2400 },
        .{ .name = "negative", .value = base - 8 },
        .{ .name = "negative_uk_reloc_imm4_0", .value = base + 0x1020 },
        .{ .name = "target", .value = base + 0x2100 },
        .{ .name = "target_uk_reloc_data8_phys_0", .value = base + 0x2010 },
        .{ .name = "target_uk_reloc_pte_attr0_0", .value = 3 },
        .{ .name = "uk_efi_entry64", .value = base + 0x1010 },
    };
    for (expected_symbols) |item|
        try testing.expectEqual(item.value, try parsed.symbol(item.name));
    for ([_][]const u8{ "", "000_before", "middle_missing", "zzz_after" }) |missing|
        try testing.expectError(error.MissingSymbol, parsed.symbol(missing));

    for ([_][]const u8{ "__bss_start", "negative", "uk_efi_entry64" }) |dup_name| {
        var dup_bytes = fixture(.little, .X86_64);
        put(u32, &dup_bytes, symbol_table + 11 * 24, @intCast(std.mem.indexOf(u8, symbol_names, dup_name).?), .little);
        var dup_image = try format.Image.parse(testing.allocator, &dup_bytes);
        defer dup_image.deinit();
        try testing.expectError(error.DuplicateSymbol, dup_image.symbol(dup_name));
    }

    var reloc_bytes = fixture(.little, .X86_64);
    // Replace the third dynamic relocation (at .bss) with a second dynamic
    // relocation at 0x2010 so only the first at 0x2010 is consumed by .data.
    put(u64, &reloc_bytes, 0x2300 + 24 * 2, base + 0x2010, .little);
    put(i64, &reloc_bytes, 0x2310 + 24 * 2, base + 0x2040, .little);
    var reloc_image = try format.Image.parse(testing.allocator, &reloc_bytes);
    defer reloc_image.deinit();
    const actual = try transform.relocations(testing.allocator, reloc_image);
    defer testing.allocator.free(actual);
    var expected = @as([124]u8, @splat(0));
    put(u32, &expected, 0, 0x0badb0b0, .little);
    for (
        [_]u64{ 0x2018, 0x2010, 0x2010, 0x1020 },
        [_]i64{ 0x1110, 0x2040, 0x2103, -8 },
        [_]u32{ 8, 8, 8, 4 },
        [_]u32{ 0, 0, 1, 0 },
        0..,
    ) |offset, value, size, flags, index| {
        put(u64, &expected, 4 + index * 24, offset, .little);
        put(i64, &expected, 12 + index * 24, value, .little);
        put(u32, &expected, 20 + index * 24, size, .little);
        put(u32, &expected, 24 + index * 24, flags, .little);
    }
    try testing.expectEqualSlices(u8, &expected, actual);
}

test "required sections symbols relocation formats and reservation errors fail closed" {
    const mutations = [_]struct { offset: usize, value: u64, width: u8, expected: anyerror }{
        .{ .offset = section_table + 6 * 64, .value = 0, .width = 4, .expected = error.MissingSection },
        .{ .offset = section_table + 5 * 64, .value = std.mem.indexOf(u8, names, ".text").?, .width = 4, .expected = error.DuplicateSection },
        .{ .offset = symbol_table + 24, .value = 0, .width = 4, .expected = error.MissingSymbol },
        .{ .offset = symbol_table + 6 * 24, .value = 1, .width = 4, .expected = error.DuplicateSymbol },
        .{ .offset = 0x2200, .value = 0, .width = 8, .expected = error.MissingRelocationCount },
        .{ .offset = 0x2208, .value = 4, .width = 8, .expected = error.RelocationCountMismatch },
        .{ .offset = 0x2308, .value = 1, .width = 8, .expected = error.UnsupportedRelocation },
        .{ .offset = 0x2308, .value = 0x100000008, .width = 8, .expected = error.UnsupportedRelocation },
        .{ .offset = section_table + 7 * 64 + 56, .value = 8, .width = 8, .expected = error.InvalidRelocationTable },
        .{ .offset = section_table + 8 * 64 + 8, .value = 0, .width = 8, .expected = error.SectionNotLoaded },
        .{ .offset = section_table + 8 * 64 + 32, .value = 64, .width = 8, .expected = error.RelocationCapacity },
        .{ .offset = symbol_table + 2 * 24 + 8, .value = base + 0x2401, .width = 8, .expected = error.RelocationSectionBounds },
        .{ .offset = 0x2300 + 24, .value = base + 0x800, .width = 8, .expected = error.RelocationOutsideImage },
    };
    for (mutations) |mutation| {
        var bytes = fixture(.little, .X86_64);
        if (mutation.width == 4)
            put(u32, &bytes, mutation.offset, @intCast(mutation.value), .little)
        else
            put(u64, &bytes, mutation.offset, mutation.value, .little);
        var image = try format.Image.parse(testing.allocator, &bytes);
        defer image.deinit();
        try testing.expectError(mutation.expected, transform.relocations(testing.allocator, image));
    }
}

test "relocations reject malformed manual widths and missing symbol targets" {
    var bytes = fixture(.little, .X86_64);
    const width_offset = strings_offset + std.mem.indexOf(u8, symbol_names, "_uk_reloc_data8").? + "_uk_reloc_data".len;
    bytes[width_offset] = '3';
    var bad_width = try format.Image.parse(testing.allocator, &bytes);
    defer bad_width.deinit();
    try testing.expectError(error.InvalidRelocationWidth, transform.relocations(testing.allocator, bad_width));
    bytes = fixture(.little, .X86_64);
    put(u32, &bytes, symbol_table + 6 * 24, 0, .little);
    var missing = try format.Image.parse(testing.allocator, &bytes);
    defer missing.deinit();
    try testing.expectError(error.MissingSymbol, transform.relocations(testing.allocator, missing));
}

test "ELF string terminators and relocation dynamic metadata are checked" {
    var bytes = fixture(.little, .X86_64);
    bytes[names_offset + names.len - 1] = 'x';
    try testing.expectError(error.InvalidStringTable, format.Image.parse(testing.allocator, &bytes));
    bytes = fixture(.little, .X86_64);
    bytes[strings_offset + symbol_names.len - 1] = 'x';
    try testing.expectError(error.InvalidStringTable, format.Image.parse(testing.allocator, &bytes));
    bytes = fixture(.little, .X86_64);
    put(u64, &bytes, section_table + 6 * 64 + 32, 48, .little);
    put(i64, &bytes, 0x2210, std.elf.DT_RELAENT, .little);
    put(u64, &bytes, 0x2218, 16, .little);
    var image = try format.Image.parse(testing.allocator, &bytes);
    defer image.deinit();
    try testing.expectError(error.InvalidDynamicSection, transform.relocations(testing.allocator, image));
}

test "bootinfo exact header region layout byte order names and zero fill" {
    for ([_]bool{ false, true }) |with_names| {
        for ([_]std.builtin.Endian{ .little, .big }) |endian| {
            const bytes = fixture(endian, .X86_64);
            var image = try format.Image.parse(testing.allocator, &bytes);
            defer image.deinit();
            const actual = try transform.bootinfo(testing.allocator, image, "/build/guest.name.elf", with_names);
            defer testing.allocator.free(actual);
            var expected = @as([0x300]u8, @splat(0));
            put(u32, &expected, 0, 0xb007b0b0, endian);
            expected[4] = 1;
            put(u32, &expected, 72, if (with_names) 8 else 14, endian);
            put(u32, &expected, 76, 2, endian);
            for ([_]u64{ base + 0x1000, base + 0x2000 }, [_]u64{ 0x1000, 0x6000 }, [_]u16{ 5, 3 }, 0..) |address, size, flags, index| {
                const offset = 80 + index * @as(usize, if (with_names) 80 else 48);
                put(u64, &expected, offset, address, endian);
                put(u64, &expected, offset + 8, address, endian);
                put(u64, &expected, offset + 24, size, endian);
                put(u64, &expected, offset + 32, size / 4096, endian);
                put(u16, &expected, offset + 40, 4, endian);
                put(u16, &expected, offset + 42, flags, endian);
                if (with_names) @memcpy(expected[offset + 44 ..][0..10], "guest.name");
            }
            try testing.expectEqualSlices(u8, &expected, actual);
        }
    }
}

test "bootinfo rejects conflicting page-rounded overlaps and insufficient capacity" {
    var bytes = fixture(.little, .X86_64);
    put(u64, &bytes, 64 + 40, 0x1001, .little);
    var image = try format.Image.parse(testing.allocator, &bytes);
    defer image.deinit();
    try testing.expectError(error.IncompatibleLoadOverlap, transform.bootinfo(testing.allocator, image, "guest", false));
    put(u32, &bytes, 64 + 4, 6, .little);
    var same_flags = try format.Image.parse(testing.allocator, &bytes);
    defer same_flags.deinit();
    const merged = try transform.bootinfo(testing.allocator, same_flags, "guest", false);
    defer testing.allocator.free(merged);
    try testing.expectEqual(1, try format.integer(u32, merged, 76, .little));
    try testing.expectEqual(0x7000, try format.integer(u64, merged, 104, .little));
    bytes = fixture(.little, .X86_64);
    put(u64, &bytes, section_table + 9 * 64 + 32, 80, .little);
    var small = try format.Image.parse(testing.allocator, &bytes);
    defer small.deinit();
    try testing.expectError(error.BootinfoCapacity, transform.bootinfo(testing.allocator, small, "guest", false));
}

test "EFI wrapper matches every byte including historical size fields and preserved header padding" {
    for ([_]std.elf.EM{ .X86_64, .AARCH64 }) |machine| {
        const bytes = fixture(.little, machine);
        var image = try format.Image.parse(testing.allocator, &bytes);
        defer image.deinit();
        const actual = try transform.efi(testing.allocator, image, image);
        defer testing.allocator.free(actual);
        var expected = @as([0x8400]u8, @splat(0));
        @memcpy(expected[0..bytes.len], &bytes);
        @memset(expected[0..280], 0);
        @memcpy(expected[4096..], &bytes);
        @memcpy(expected[0..2], "MZ");
        @memcpy(expected[64..68], "PE\x00\x00");
        put(u32, &expected, 60, 64, .little);
        put(u16, &expected, 68, if (machine == .X86_64) 0x8664 else 0xaa64, .little);
        put(u16, &expected, 70, 2, .little);
        put(u16, &expected, 84, 112, .little);
        put(u16, &expected, 86, 0x206, .little);
        put(u16, &expected, 88, 0x20b, .little);
        put(u32, &expected, 92, 0x1000, .little);
        put(u32, &expected, 96, 0x2000, .little);
        put(u32, &expected, 100, 0x4000, .little);
        put(u32, &expected, 104, 0x2010, .little);
        put(u32, &expected, 108, 0x2000, .little);
        put(u64, &expected, 112, base, .little);
        put(u32, &expected, 120, 4096, .little);
        put(u32, &expected, 124, 4096, .little);
        put(u32, &expected, 144, 0xa000, .little);
        put(u32, &expected, 148, 4096, .little);
        put(u16, &expected, 156, 10, .little);
        for (0..2) |index| {
            const offset = 200 + 40 * index;
            @memcpy(expected[offset..][0..8], "\x00RDHP_KU");
            put(u32, &expected, offset + 8, if (index == 0) 0x1000 else 0x6000, .little);
            put(u32, &expected, offset + 12, if (index == 0) 0x2000 else 0x3000, .little);
            put(u32, &expected, offset + 16, if (index == 0) 0x1000 else 0x3000, .little);
            put(u32, &expected, offset + 20, if (index == 0) 0x2000 else 0x3000, .little);
            put(u32, &expected, offset + 36, 0xe0d00040, .little);
        }
        try testing.expectEqualSlices(u8, &expected, actual);
    }
}

test "EFI rejects wrong endian missing entry architecture mismatch and overflowing PE fields" {
    var bytes = fixture(.little, .X86_64);
    var image = try format.Image.parse(testing.allocator, &bytes);
    defer image.deinit();
    const other_bytes = fixture(.big, .X86_64);
    var other = try format.Image.parse(testing.allocator, &other_bytes);
    defer other.deinit();
    try testing.expectError(error.UnsupportedEfiEndian, transform.efi(testing.allocator, other, image));
    other.header.endian = .little;
    other.header.machine = .AARCH64;
    try testing.expectError(error.ArchitectureMismatch, transform.efi(testing.allocator, other, image));
    // Find the entry by name instead of relying on nm sort order.
    for (image.symbols) |*sym| {
        if (std.mem.eql(u8, sym.name, "uk_efi_entry64")) sym.header.st_value = base + 0x7000;
    }
    try testing.expectError(error.InvalidEfiEntry, transform.efi(testing.allocator, image, image));
    for (image.symbols) |*sym| {
        if (std.mem.eql(u8, sym.name, "uk_efi_entry64")) sym.header.st_value = base + 0x1010;
    }
    image.programs[1].memsz = 0x100000000;
    try testing.expectError(error.PeFieldOverflow, transform.efi(testing.allocator, image, image));
    for (image.programs) |*ph| ph.type = .NULL;
    try testing.expectError(error.MissingLoadSegments, transform.efi(testing.allocator, image, image));
}

test "multiboot prepends ELF32 and multiboot headers and adjusts program and section offsets" {
    const bytes = fixture(.little, .X86_64);
    const actual = try transform.multiboot(testing.allocator, &bytes);
    defer testing.allocator.free(actual);
    const prepend_offset: usize = 64 + 3 * 32;
    const shoff: usize = prepend_offset + bytes.len;
    try testing.expectEqual(shoff + 11 * 40, actual.len);
    try testing.expectEqualSlices(u8, "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", actual[0..16]);
    try testing.expectEqual(@as(u16, 3), try format.integer(u16, actual, 16, .little));
    try testing.expectEqual(@as(u16, 3), try format.integer(u16, actual, 18, .little));
    try testing.expectEqual(@as(u32, 1), try format.integer(u32, actual, 20, .little));
    try testing.expectEqualSlices(u8, bytes[24..28], actual[24..28]);
    try testing.expectEqual(@as(u32, 64), try format.integer(u32, actual, 28, .little));
    try testing.expectEqual(@as(u32, @intCast(shoff)), try format.integer(u32, actual, 32, .little));
    try testing.expectEqual(@as(u16, 52), try format.integer(u16, actual, 40, .little));
    try testing.expectEqual(@as(u16, 32), try format.integer(u16, actual, 42, .little));
    try testing.expectEqual(@as(u16, 3), try format.integer(u16, actual, 44, .little));
    try testing.expectEqual(@as(u16, 40), try format.integer(u16, actual, 46, .little));
    try testing.expectEqual(@as(u16, 11), try format.integer(u16, actual, 48, .little));
    try testing.expectEqual(@as(u16, 1), try format.integer(u16, actual, 50, .little));
    try testing.expectEqual(@as(u32, 0x1BADB002), try format.integer(u32, actual, 52, .little));
    try testing.expectEqual(@as(u32, 0x00000003), try format.integer(u32, actual, 56, .little));
    try testing.expectEqual(@as(u32, 0xE4524FFB), try format.integer(u32, actual, 60, .little));
    for ([_]u32{ 0x1000, 0x2000, 0x2200 }, 0..) |orig_off, idx| {
        const phdr_pos = 64 + idx * 32;
        try testing.expectEqual(orig_off + @as(u32, @intCast(prepend_offset)), try format.integer(u32, actual, phdr_pos + 4, .little));
    }
    try testing.expectEqualSlices(u8, &bytes, actual[prepend_offset..shoff]);
    for (0..11) |idx| {
        const orig_sh_off = try format.integer(u32, &bytes, section_table + idx * 64 + 24, .little);
        const shdr_pos = shoff + idx * 40;
        try testing.expectEqual(orig_sh_off + @as(u32, @intCast(prepend_offset)), try format.integer(u32, actual, shdr_pos + 16, .little));
    }
    const arm_bytes = fixture(.little, .AARCH64);
    try testing.expectError(error.UnsupportedArchitecture, transform.multiboot(testing.allocator, &arm_bytes));
}

test "linuxHeader prepends arm64 boot header with branch offset and 2MiB-aligned image size" {
    const elf_bytes = arm64LinuxFixture();
    var elf_image = try format.Image.parse(testing.allocator, &elf_bytes);
    defer elf_image.deinit();
    const raw = "arm64-raw-image-payload";
    const actual = try transform.linuxHeader(testing.allocator, raw, elf_image);
    defer testing.allocator.free(actual);
    try testing.expectEqual(64 + raw.len, actual.len);
    try testing.expectEqual(@as(u32, 0x91005A4D), try format.integer(u32, actual, 0, .little));
    try testing.expectEqual(@as(u32, 0x1400001f), try format.integer(u32, actual, 4, .little));
    try testing.expectEqual(@as(u64, 0x200000), try format.integer(u64, actual, 8, .little));
    try testing.expectEqual(@as(u64, 0x200000), try format.integer(u64, actual, 16, .little));
    try testing.expectEqual(@as(u64, 0xA), try format.integer(u64, actual, 24, .little));
    try testing.expectEqualSlices(u8, &(@as([24]u8, @splat(0))), actual[32..56]);
    try testing.expectEqualSlices(u8, "ARM\x64", actual[56..60]);
    try testing.expectEqual(@as(u32, 0x40), try format.integer(u32, actual, 60, .little));
    try testing.expectEqualSlices(u8, raw, actual[64..]);

    const x86_bytes = fixture(.little, .X86_64);
    var x86_image = try format.Image.parse(testing.allocator, &x86_bytes);
    defer x86_image.deinit();
    try testing.expectError(error.UnsupportedArchitecture, transform.linuxHeader(testing.allocator, raw, x86_image));

    for (elf_image.symbols) |*sym| {
        if (std.mem.eql(u8, sym.name, "_libkvmplat_entry")) sym.header.st_value = 0x40200082;
    }
    try testing.expectError(error.InvalidEntryOffset, transform.linuxHeader(testing.allocator, raw, elf_image));
    for (elf_image.symbols) |*sym| {
        if (std.mem.eql(u8, sym.name, "_libkvmplat_entry")) sym.header.st_value = 0x40200080;
        if (std.mem.eql(u8, sym.name, "_base_addr")) sym.header.st_value = 0x40000020;
    }
    try testing.expectError(error.InvalidSymbolAddress, transform.linuxHeader(testing.allocator, raw, elf_image));
}

test "runner execute handles multiboot and linux-header end-to-end" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try temporary.dir.realPath(testing.io, &root_buf);
    const root = root_buf[0..root_len];

    const mb_in = try std.fs.path.join(testing.allocator, &.{ root, "mb-in.elf" });
    defer testing.allocator.free(mb_in);
    const mb_out = try std.fs.path.join(testing.allocator, &.{ root, "mb-out.elf" });
    defer testing.allocator.free(mb_out);
    const x86_bytes = fixture(.little, .X86_64);
    try runner.write(testing.io, mb_in, &x86_bytes);
    try runner.execute(testing.allocator, testing.io, &.{ "multiboot", mb_in, mb_out });
    const mb_actual = try runner.read(testing.allocator, testing.io, mb_out);
    defer testing.allocator.free(mb_actual);
    const mb_expected = try transform.multiboot(testing.allocator, &x86_bytes);
    defer testing.allocator.free(mb_expected);
    try testing.expectEqualSlices(u8, mb_expected, mb_actual);

    const linux_bin = try std.fs.path.join(testing.allocator, &.{ root, "linux-in.bin" });
    defer testing.allocator.free(linux_bin);
    const linux_elf = try std.fs.path.join(testing.allocator, &.{ root, "linux-in.elf" });
    defer testing.allocator.free(linux_elf);
    const linux_out = try std.fs.path.join(testing.allocator, &.{ root, "linux-out.img" });
    defer testing.allocator.free(linux_out);
    const raw = "raw-binary-image";
    const arm_bytes = arm64LinuxFixture();
    try runner.write(testing.io, linux_bin, raw);
    try runner.write(testing.io, linux_elf, &arm_bytes);
    try runner.execute(testing.allocator, testing.io, &.{ "linux-header", linux_bin, linux_elf, linux_out });
    const linux_actual = try runner.read(testing.allocator, testing.io, linux_out);
    defer testing.allocator.free(linux_actual);
    var arm_image = try format.Image.parse(testing.allocator, &arm_bytes);
    defer arm_image.deinit();
    const linux_expected = try transform.linuxHeader(testing.allocator, raw, arm_image);
    defer testing.allocator.free(linux_expected);
    try testing.expectEqualSlices(u8, linux_expected, linux_actual);
}

test "native tool argv quoting is preserved without a shell or Python fallback" {
    const args = try runner.splitCommand(testing.allocator, " '/native tools/llvm-objcopy' --flag=\"two words\" '' plain\\ space \"a\\qb\"");
    defer runner.freeCommand(testing.allocator, args);
    try testing.expectEqual(5, args.len);
    for (args, [_][]const u8{ "/native tools/llvm-objcopy", "--flag=two words", "", "plain space", "a\\qb" }) |actual, expected|
        try testing.expectEqualStrings(expected, actual);
    for ([_][]const u8{ "", " ", "''", "'unclosed", "tool\\", "tool\\\x00" }) |input|
        try testing.expectError(error.InvalidToolCommand, runner.splitCommand(testing.allocator, input));
    try testing.expectError(error.UnsupportedTransformation, runner.execute(testing.allocator, testing.io, &.{"gzip"}));
    try testing.expectError(error.InvalidArguments, runner.execute(testing.allocator, testing.io, &.{"multiboot"}));
    try testing.expectError(error.InvalidArguments, runner.execute(testing.allocator, testing.io, &.{ "multiboot", "--script", "old.py", "in", "out" }));
    try testing.expectError(error.InvalidArguments, runner.execute(testing.allocator, testing.io, &.{ "linux-header", "--nm", "llvm-nm", "in.bin", "in.elf", "out" }));
    try testing.expectError(error.InvalidArguments, runner.execute(testing.allocator, testing.io, &.{ "efi", "--script", "old.py", "in", "debug", "out" }));
    try testing.expectError(error.InvalidArguments, runner.execute(testing.allocator, testing.io, &.{ "bootinfo", "--arch", "mips", "--objcopy", "tool", "in", "side", "out" }));
}

fn allocationFixture(allocator: std.mem.Allocator) !void {
    const bytes = fixture(.little, .X86_64);
    var image = try format.Image.parse(allocator, &bytes);
    defer image.deinit();
    const reloc = try transform.relocations(allocator, image);
    defer allocator.free(reloc);
    const boot = try transform.bootinfo(allocator, image, "guest.elf", true);
    defer allocator.free(boot);
    const mb = try transform.multiboot(allocator, &bytes);
    defer allocator.free(mb);
    const efi = try transform.efi(allocator, image, image);
    defer allocator.free(efi);
    const arm_bytes = arm64LinuxFixture();
    var arm_image = try format.Image.parse(allocator, &arm_bytes);
    defer arm_image.deinit();
    const linux = try transform.linuxHeader(allocator, "raw", arm_image);
    defer allocator.free(linux);
    const command = try runner.splitCommand(allocator, "'/native tools/objcopy' --flag value");
    defer runner.freeCommand(allocator, command);
}

test "native parsers and transforms release allocations on every allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationFixture, .{});
}
