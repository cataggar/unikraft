// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, 2023, Unikraft GmbH and The Unikraft Authors.

//! Native equivalents of the reached mkukreloc, mkbootinfo, multiboot, mkefi
//! and mklinux actions.
//! LLVM strip/objcopy remain responsible for ELF layout-changing operations.
const std = @import("std");
const elf = std.elf;
const format = @import("postprocess-elf.zig");
const Image = format.Image;
const add = format.add;
const sub = format.subtract;

const Relocation = struct {
    offset: u64,
    value: i64,
    size: u32,
    flags: u32,
};

const RelocSymbol = struct {
    target: []const u8,
    kind: enum { data, imm, pte_attr },
    size: u32,
    physical: bool,
};

fn relocSymbol(name: []const u8) !?RelocSymbol {
    if (std.mem.indexOf(u8, name, "_start16") != null) return null;
    const marker = "_uk_reloc_";
    const index = std.mem.lastIndexOf(u8, name, marker) orelse return null;
    var rest = name[index + marker.len ..];
    const kind: @FieldType(RelocSymbol, "kind") = if (std.mem.startsWith(u8, rest, "data")) blk: {
        rest = rest[4..];
        break :blk .data;
    } else if (std.mem.startsWith(u8, rest, "imm")) blk: {
        rest = rest[3..];
        break :blk .imm;
    } else if (std.mem.startsWith(u8, rest, "pte_attr")) blk: {
        rest = rest[8..];
        break :blk .pte_attr;
    } else return null;
    if (index == 0) return error.InvalidRelocationSymbol;
    var digits: usize = 0;
    while (digits < rest.len and std.ascii.isDigit(rest[digits])) : (digits += 1) {}
    if (digits == 0 or digits > 2 or digits == rest.len or rest[digits] != '_')
        return error.InvalidRelocationSymbol;
    const size = try std.fmt.parseInt(u32, rest[0..digits], 10);
    if ((kind == .pte_attr and size != 0) or
        (kind != .pte_attr and size != 2 and size != 4 and size != 8))
        return error.InvalidRelocationWidth;
    return .{
        .target = name[0..index],
        .kind = kind,
        .size = size,
        .physical = std.mem.indexOf(u8, name, "_phys") != null,
    };
}

fn relativeValue(value: i128, base: u64) !i64 {
    return std.math.cast(i64, value - @as(i128, base)) orelse error.InvalidRelocationValue;
}

pub fn relocations(allocator: std.mem.Allocator, image: Image) ![]u8 {
    const base = try image.symbol("_base_addr");
    const dynamic = try image.section(".dynamic");
    const rela = try image.section(".rela.dyn");
    _ = try image.section(".text");
    const target = try image.section(".uk_reloc");
    const bss = try image.section(".bss");
    if (dynamic.header.sh_type != elf.SHT_DYNAMIC or rela.header.sh_type != elf.SHT_RELA or
        bss.header.sh_type != elf.SHT_NOBITS) return error.InvalidSectionType;
    try image.requireLoadedSection(target);
    if (dynamic.header.sh_entsize != @sizeOf(elf.Elf64_Dyn) or
        dynamic.header.sh_size % @sizeOf(elf.Elf64_Dyn) != 0)
        return error.InvalidDynamicSection;
    if (rela.header.sh_entsize != @sizeOf(elf.Elf64_Rela) or
        rela.header.sh_size % @sizeOf(elf.Elf64_Rela) != 0)
        return error.InvalidRelocationTable;
    for (image.sections) |section| {
        const sh = section.header;
        if (sh.sh_flags & elf.SHF_ALLOC == 0 or sh.sh_size == 0 or
            std.mem.eql(u8, section.name, ".rela.dyn")) continue;
        if (sh.sh_type == elf.SHT_REL or sh.sh_type == elf.SHT_RELA or sh.sh_type == 19)
            return error.UnsupportedRelocation;
    }

    const dynamic_bytes = try image.sectionData(dynamic);
    var count: ?u64 = null;
    var terminated = false;
    var position: usize = 0;
    while (position < dynamic_bytes.len) : (position += @sizeOf(elf.Elf64_Dyn)) {
        const tag = try format.integer(i64, dynamic_bytes, position, image.header.endian);
        const value = try format.integer(u64, dynamic_bytes, position + 8, image.header.endian);
        if (tag == elf.DT_NULL) {
            terminated = true;
            break;
        }
        if (tag == elf.DT_RELACOUNT) {
            if (count != null) return error.InvalidDynamicSection;
            count = value;
        }
        if ((tag == elf.DT_RELSZ or tag == elf.DT_RELRSZ or tag == elf.DT_PLTRELSZ) and value != 0)
            return error.UnsupportedRelocation;
        if ((tag == elf.DT_RELA and value != rela.header.sh_addr) or
            (tag == elf.DT_RELASZ and value != rela.header.sh_size) or
            (tag == elf.DT_RELAENT and value != @sizeOf(elf.Elf64_Rela)))
            return error.InvalidDynamicSection;
    }
    if (!terminated) return error.InvalidDynamicSection;
    const expected = count orelse return error.MissingRelocationCount;
    if (expected == 0) return error.MissingRelocationCount;
    if (expected != rela.header.sh_size / @sizeOf(elf.Elf64_Rela))
        return error.RelocationCountMismatch;

    const OffsetQueue = struct {
        head: usize,
        tail: usize,
    };
    const IndexedRelocSymbol = struct {
        symbol: format.Symbol,
        parsed: RelocSymbol,
    };
    const no_next = std.math.maxInt(usize);

    var entries: std.ArrayList(Relocation) = .empty;
    defer entries.deinit(allocator);
    var consumed: std.ArrayList(bool) = .empty;
    defer consumed.deinit(allocator);
    var next_at_offset: std.ArrayList(usize) = .empty;
    defer next_at_offset.deinit(allocator);
    var by_offset: std.AutoHashMapUnmanaged(u64, OffsetQueue) = .empty;
    defer by_offset.deinit(allocator);

    const relative_type: u32 = if (image.header.machine == .X86_64) 8 else 1027;
    for (0..try format.asUsize(expected)) |index| {
        const entry = try format.structure(elf.Elf64_Rela, image.bytes, rela.header.sh_offset + index * @sizeOf(elf.Elf64_Rela), image.header.endian);
        if (@as(u32, @truncate(entry.r_info)) != relative_type or entry.r_info >> 32 != 0)
            return error.UnsupportedRelocation;
        const offset = try sub(entry.r_offset, base);
        const slot = entries.items.len;
        try entries.append(allocator, .{
            .offset = offset,
            .value = try relativeValue(entry.r_addend, base),
            .size = 8,
            .flags = 0,
        });
        try consumed.append(allocator, false);
        try next_at_offset.append(allocator, no_next);
        const gop = try by_offset.getOrPut(allocator, offset);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .head = slot, .tail = slot };
        } else {
            next_at_offset.items[gop.value_ptr.tail] = slot;
            gop.value_ptr.tail = slot;
        }
    }

    var data_symbols: std.ArrayList(IndexedRelocSymbol) = .empty;
    defer data_symbols.deinit(allocator);
    var imm_symbols: std.ArrayList(IndexedRelocSymbol) = .empty;
    defer imm_symbols.deinit(allocator);
    var pte_attrs: std.StringHashMapUnmanaged(u64) = .empty;
    defer pte_attrs.deinit(allocator);
    for (image.symbols) |symbol| {
        const parsed = (try relocSymbol(symbol.name)) orelse continue;
        switch (parsed.kind) {
            .data => try data_symbols.append(allocator, .{ .symbol = symbol, .parsed = parsed }),
            .imm => try imm_symbols.append(allocator, .{ .symbol = symbol, .parsed = parsed }),
            .pte_attr => {
                const gop = try pte_attrs.getOrPut(allocator, parsed.target);
                if (!gop.found_existing) gop.value_ptr.* = symbol.header.st_value;
            },
        }
    }

    // nm sorts by name; the legacy helper processes all data entries before
    // immediate entries, replacing the first dynamic relocation at that offset.
    for ([_][]const IndexedRelocSymbol{ data_symbols.items, imm_symbols.items }) |group| {
        for (group) |item| {
            var value: i128 = @as(i128, try image.symbol(item.parsed.target)) - @as(i128, base);
            var flags: u32 = @intFromBool(item.parsed.physical);
            if (pte_attrs.get(item.parsed.target)) |attr_value| {
                value += attr_value;
                flags |= 1;
            }
            const offset = try sub(item.symbol.header.st_value, base);
            const reloc: Relocation = .{
                .offset = offset,
                .value = std.math.cast(i64, value) orelse return error.InvalidRelocationValue,
                .size = item.parsed.size,
                .flags = flags,
            };
            if (by_offset.getPtr(offset)) |queue| {
                const victim = queue.head;
                consumed.items[victim] = true;
                const next = next_at_offset.items[victim];
                if (next == no_next) {
                    _ = by_offset.remove(offset);
                } else {
                    queue.head = next;
                }
            }
            const slot = entries.items.len;
            try entries.append(allocator, reloc);
            try consumed.append(allocator, false);
            try next_at_offset.append(allocator, no_next);
            const gop = try by_offset.getOrPut(allocator, offset);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .head = slot, .tail = slot };
            } else {
                next_at_offset.items[gop.value_ptr.tail] = slot;
                gop.value_ptr.tail = slot;
            }
        }
    }

    const limit = try sub(bss.header.sh_addr, base);
    var kept: usize = 0;
    for (entries.items, consumed.items) |entry, is_consumed| {
        if (is_consumed) continue;
        // Discard dummy trace relocations at/after .bss, as mkukreloc does.
        if (entry.offset >= limit) continue;
        if (!image.containsMemory(try add(base, entry.offset), entry.size))
            return error.RelocationOutsideImage;
        entries.items[kept] = entry;
        kept += 1;
    }
    const start = try image.symbol("_uk_reloc_start");
    const end = try image.symbol("_uk_reloc_end");
    if (start != target.header.sh_addr or end < start) return error.RelocationSectionBounds;
    const required = try add(4, std.math.mul(u64, try add(kept, 1), 24) catch return error.IntegerOverflow);
    if (required > @min(target.header.sh_size, end - start)) return error.RelocationCapacity;
    const result = try allocator.alloc(u8, try format.asUsize(required));
    @memset(result, 0);
    put(u32, result, 0, 0x0badb0b0, image.header.endian);
    for (entries.items[0..kept], 0..) |entry, index| {
        const offset = 4 + 24 * index;
        put(u64, result, offset, entry.offset, image.header.endian);
        put(i64, result, offset + 8, entry.value, image.header.endian);
        put(u32, result, offset + 16, entry.size, image.header.endian);
        put(u32, result, offset + 20, entry.flags, image.header.endian);
    }
    return result;
}

const Region = struct {
    base: u64,
    size: u64,
    flags: u32,
};

fn regionLessThan(_: void, a: Region, b: Region) bool {
    return a.base < b.base;
}

pub fn bootinfo(allocator: std.mem.Allocator, image: Image, input_name: []const u8, names: bool) ![]u8 {
    const target = try image.section(".uk_bootinfo");
    try image.requireLoadedSection(target);
    if (target.header.sh_size < 80) return error.BootinfoCapacity;
    const descriptor_size: u64 = if (names) 80 else 48;
    const capacity = (target.header.sh_size - 80) / descriptor_size;
    if (capacity > std.math.maxInt(u32)) return error.BootinfoCapacity;
    var regions: std.ArrayList(Region) = .empty;
    defer regions.deinit(allocator);
    for (image.programs) |ph| {
        if (ph.type != .LOAD) continue;
        const size = (try add(ph.memsz, 4095)) & ~@as(u64, 4095);
        if (size == 0) continue;
        _ = try add(ph.vaddr, size);
        try regions.append(allocator, .{ .base = ph.vaddr, .size = size, .flags = @as(u32, @bitCast(ph.flags)) & 7 });
    }
    std.mem.sort(Region, regions.items, {}, regionLessThan);
    var kept: usize = 0;
    for (regions.items) |region| {
        if (kept != 0) {
            const previous = &regions.items[kept - 1];
            const previous_end = try add(previous.base, previous.size);
            if (region.base < previous_end) {
                if (region.flags != previous.flags) return error.IncompatibleLoadOverlap;
                previous.size = @max(previous_end, try add(region.base, region.size)) - previous.base;
                continue;
            }
        }
        regions.items[kept] = region;
        kept += 1;
    }
    if (kept > capacity) return error.BootinfoCapacity;
    var region_name = @as([36]u8, @splat(0));
    if (names) {
        const basename = std.fs.path.basename(input_name);
        const dot = std.mem.lastIndexOfScalar(u8, basename, '.');
        const stem = if (dot != null and dot.? > 0) basename[0..dot.?] else basename;
        for (stem) |c| if (c > 127) return error.NonAsciiRegionName;
        const length = @min(stem.len, 35);
        @memcpy(region_name[0..length], stem[0..length]);
    }
    const result = try allocator.alloc(u8, try format.asUsize(target.header.sh_size));
    @memset(result, 0);
    const endian = image.header.endian;
    put(u32, result, 0, 0xb007b0b0, endian);
    result[4] = 1;
    put(u32, result, 72, @intCast(capacity), endian);
    put(u32, result, 76, @intCast(kept), endian);
    for (regions.items[0..kept], 0..) |region, index| {
        const offset = 80 + index * try format.asUsize(descriptor_size);
        put(u64, result, offset, region.base, endian);
        put(u64, result, offset + 8, region.base, endian);
        put(u64, result, offset + 24, region.size, endian);
        put(u64, result, offset + 32, region.size >> 12, endian);
        put(u16, result, offset + 40, 4, endian);
        const flags: u16 = @as(u16, @intFromBool(region.flags & elf.PF_R != 0)) |
            (@as(u16, @intFromBool(region.flags & elf.PF_W != 0)) << 1) |
            (@as(u16, @intFromBool(region.flags & elf.PF_X != 0)) << 2);
        put(u16, result, offset + 42, flags, endian);
        if (names) @memcpy(result[offset + 44 ..][0..36], &region_name);
    }
    return result;
}

fn programLessThan(_: void, a: elf.Elf64.Phdr, b: elf.Elf64.Phdr) bool {
    // Overflow has already been checked by Image.parse.
    return a.vaddr + a.memsz < b.vaddr + b.memsz;
}

pub fn efi(allocator: std.mem.Allocator, image: Image, debug: Image) ![]u8 {
    if (image.header.endian != .little or debug.header.endian != .little)
        return error.UnsupportedEfiEndian;
    if (image.header.machine != debug.header.machine) return error.ArchitectureMismatch;
    const base = try debug.symbol("_base_addr");
    const bss = try debug.symbol("__bss_start");
    const entry = try debug.symbol("uk_efi_entry64");
    var programs: std.ArrayList(elf.Elf64.Phdr) = .empty;
    defer programs.deinit(allocator);
    var executable_entry = false;
    for (image.programs) |ph| {
        if (ph.type != .LOAD) continue;
        if (ph.vaddr < base) return error.InvalidAddress;
        if (@as(u32, @bitCast(ph.flags)) & elf.PF_X != 0 and entry >= ph.vaddr and entry - ph.vaddr < ph.memsz)
            executable_entry = true;
        try programs.append(allocator, ph);
    }
    if (programs.items.len == 0) return error.MissingLoadSegments;
    if (!executable_entry) return error.InvalidEfiEntry;
    if (programs.items.len > std.math.maxInt(u16)) return error.TooManyPeSections;
    std.mem.sort(elf.Elf64.Phdr, programs.items, {}, programLessThan);
    const last = programs.items[programs.items.len - 1];
    const end = try add(last.vaddr, last.memsz);
    if (bss < base or bss > end) return error.InvalidBssAddress;
    const table_end = 200 + 40 * programs.items.len;
    // Retain mkefi's extra section slot and *next* page alignment, even when
    // the header size is already page aligned.
    const headers = ((table_end + 40) & ~@as(usize, 4095)) + 4096;
    const adjusted_end = try add(end, headers);
    const uninitialized = try sub(adjusted_end, bss);
    var code_size: u64 = 0;
    var data_size: u64 = 0;
    var code_base: u64 = 0;
    for (programs.items) |ph| {
        if (@as(u32, @bitCast(ph.flags)) & (elf.PF_R | elf.PF_X) == (elf.PF_R | elf.PF_X)) {
            code_size = try add(code_size, ph.memsz);
            code_base = try add(try sub(ph.vaddr, base), headers);
        } else if (@as(u32, @bitCast(ph.flags)) & elf.PF_R != 0) {
            data_size = try add(data_size, ph.memsz);
        }
    }
    // These legacy fields include the header page in BSS accounting and twice
    // in SizeOfImage. Changing that policy is separate from this native port.
    data_size = try sub(data_size, uninitialized);
    const result = try allocator.alloc(u8, try format.asUsize(try add(headers, image.bytes.len)));
    errdefer allocator.free(result);
    // mkefi edits a copy in place: bytes between its section table and the
    // inserted ELF are the original ELF bytes, not newly zeroed padding.
    @memset(result[0..table_end], 0);
    const middle_end = @min(headers, image.bytes.len);
    if (middle_end > table_end) {
        @memcpy(result[table_end..middle_end], image.bytes[table_end..middle_end]);
    }
    if (headers > middle_end) {
        @memset(result[middle_end..headers], 0);
    }
    @memcpy(result[headers..], image.bytes);
    @memcpy(result[0..2], "MZ");
    put(u32, result, 60, 64, .little);
    @memcpy(result[64..68], "PE\x00\x00");
    put(u16, result, 68, if (image.header.machine == .X86_64) 0x8664 else 0xaa64, .little);
    put(u16, result, 70, @intCast(programs.items.len), .little);
    put(u16, result, 84, 112, .little);
    put(u16, result, 86, 0x206, .little);
    put(u16, result, 88, 0x20b, .little);
    try pe32(result, 92, code_size);
    try pe32(result, 96, data_size);
    try pe32(result, 100, uninitialized);
    try pe32(result, 104, try add(try sub(entry, base), headers));
    try pe32(result, 108, code_base);
    put(u64, result, 112, base, .little);
    put(u32, result, 120, 4096, .little);
    put(u32, result, 124, 4096, .little);
    try pe32(result, 144, try add(headers, try sub(adjusted_end, base)));
    try pe32(result, 148, headers);
    put(u16, result, 156, 10, .little);
    for (programs.items, 0..) |ph, index| {
        const offset = 200 + 40 * index;
        put(u64, result, offset, 0x554b5f5048445200, .little);
        try pe32(result, offset + 8, ph.memsz);
        try pe32(result, offset + 12, try add(try sub(ph.vaddr, base), headers));
        try pe32(result, offset + 16, ph.filesz);
        try pe32(result, offset + 20, try add(ph.offset, headers));
        put(u32, result, offset + 36, 0xe0d00040, .little);
    }
    return result;
}

pub fn multiboot(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var image = try format.Image.parse(allocator, input);
    defer image.deinit();
    if (image.header.machine != .X86_64) return error.UnsupportedArchitecture;
    const endian = image.header.endian;
    const e_phoff = try format.integer(u64, input, 32, endian);
    const e_shoff = try format.integer(u64, input, 40, endian);
    const e_phentsize = try format.integer(u16, input, 54, endian);
    const e_phnum = try format.integer(u16, input, 56, endian);
    const e_shentsize = try format.integer(u16, input, 58, endian);
    const e_shnum = try format.integer(u16, input, 60, endian);
    if (e_phnum == elf.PN_XNUM or e_shnum == 0) return error.InvalidElfHeader;

    const elf32_ehdr_len: usize = 52;
    const elf32_phdr_len: usize = 32;
    const elf32_shdr_len: usize = 40;
    const multiboot_header_end_off: usize = elf32_ehdr_len + 12;
    const prepend_offset: u64 = multiboot_header_end_off + @as(u64, elf32_phdr_len) * @as(u64, e_phnum);
    const shoff_u64 = try add(prepend_offset, input.len);
    const shoff32 = std.math.cast(u32, shoff_u64) orelse return error.IntegerOverflow;
    const shdrs_bytes = std.math.mul(u64, elf32_shdr_len, e_shnum) catch return error.IntegerOverflow;
    const total_len = try format.asUsize(try add(shoff_u64, shdrs_bytes));

    const result = try allocator.alloc(u8, total_len);
    errdefer allocator.free(result);
    @memset(result, 0);

    @memcpy(result[0..16], "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    @memcpy(result[16..18], input[16..18]);
    put(u16, result, 18, 3, endian);
    @memcpy(result[20..24], input[20..24]);
    @memcpy(result[24..28], input[24..28]);
    put(u32, result, 28, multiboot_header_end_off, endian);
    put(u32, result, 32, shoff32, endian);
    @memcpy(result[36..40], input[48..52]);
    put(u16, result, 40, elf32_ehdr_len, endian);
    put(u16, result, 42, elf32_phdr_len, endian);
    @memcpy(result[44..46], input[56..58]);
    put(u16, result, 46, elf32_shdr_len, endian);
    @memcpy(result[48..50], input[60..62]);
    @memcpy(result[50..52], input[62..64]);

    const mb_magic: u32 = 0x1BADB002;
    const mb_flags: u32 = 0x00000003;
    const mb_checksum: u32 = @bitCast(-@as(i32, @intCast(mb_magic + mb_flags)));
    put(u32, result, 52, mb_magic, .little);
    put(u32, result, 56, mb_flags, .little);
    put(u32, result, 60, mb_checksum, .little);

    for (0..e_phnum) |index| {
        const elf64_phdr = try format.range(input, e_phoff + index * @as(u64, e_phentsize), e_phentsize);
        const elf32_phdr = result[multiboot_header_end_off + index * elf32_phdr_len ..][0..elf32_phdr_len];
        @memcpy(elf32_phdr[0..4], elf64_phdr[0..4]);
        const old_off = try format.integer(u32, elf64_phdr, 8, endian);
        const new_off = std.math.cast(u32, try add(prepend_offset, old_off)) orelse return error.IntegerOverflow;
        put(u32, elf32_phdr, 4, new_off, endian);
        @memcpy(elf32_phdr[8..12], elf64_phdr[16..20]);
        @memcpy(elf32_phdr[12..16], elf64_phdr[24..28]);
        @memcpy(elf32_phdr[16..20], elf64_phdr[32..36]);
        @memcpy(elf32_phdr[20..24], elf64_phdr[40..44]);
        @memcpy(elf32_phdr[24..28], elf64_phdr[4..8]);
        @memcpy(elf32_phdr[28..32], elf64_phdr[48..52]);
    }

    const prepend_usize = try format.asUsize(prepend_offset);
    @memcpy(result[prepend_usize..][0..input.len], input);

    const shoff_usize = try format.asUsize(shoff_u64);
    for (0..e_shnum) |index| {
        const elf64_shdr = try format.range(input, e_shoff + index * @as(u64, e_shentsize), e_shentsize);
        const elf32_shdr = result[shoff_usize + index * elf32_shdr_len ..][0..elf32_shdr_len];
        @memcpy(elf32_shdr[0..4], elf64_shdr[0..4]);
        @memcpy(elf32_shdr[4..8], elf64_shdr[4..8]);
        @memcpy(elf32_shdr[8..12], elf64_shdr[8..12]);
        @memcpy(elf32_shdr[12..16], elf64_shdr[16..20]);
        const old_off = try format.integer(u32, elf64_shdr, 24, endian);
        const new_off = std.math.cast(u32, try add(prepend_offset, old_off)) orelse return error.IntegerOverflow;
        put(u32, elf32_shdr, 16, new_off, endian);
        @memcpy(elf32_shdr[20..24], elf64_shdr[32..36]);
        @memcpy(elf32_shdr[24..28], elf64_shdr[40..44]);
        @memcpy(elf32_shdr[28..32], elf64_shdr[44..48]);
        @memcpy(elf32_shdr[32..36], elf64_shdr[48..52]);
        @memcpy(elf32_shdr[36..40], elf64_shdr[56..60]);
    }
    return result;
}

pub fn linuxHeader(allocator: std.mem.Allocator, raw_binary: []const u8, elf_image: Image) ![]u8 {
    if (elf_image.header.machine != .AARCH64) return error.UnsupportedArchitecture;
    const ram_base = try elf_image.symbol("_start_ram_addr");
    const img_base = try elf_image.symbol("_base_addr");
    const entry = try elf_image.symbol("_libkvmplat_entry");

    const hdr_size: u64 = 64;
    if (img_base < hdr_size - 4 or img_base < try add(ram_base, hdr_size))
        return error.InvalidSymbolAddress;
    const pc = img_base - hdr_size + 4;
    if (entry < pc) return error.InvalidEntryOffset;
    const offs = entry - pc;
    if (offs > ((1 << 26) / 2 - 1) or (offs & 3) != 0)
        return error.InvalidEntryOffset;
    const code0: u32 = 0x91005A4D;
    const code1: u32 = (0b101 << 26) | @as(u32, @intCast(offs / 4));
    const load_offs: u64 = (img_base - ram_base) - hdr_size;
    const total_size = try std.math.add(u64, raw_binary.len, hdr_size);
    const image_size: u64 = std.mem.alignForward(u64, total_size, 1 << 21);
    const kernel_flags: u64 = 0xA;

    const out = try allocator.alloc(u8, try format.asUsize(total_size));
    @memset(out[0..64], 0);
    put(u32, out, 0, code0, .little);
    put(u32, out, 4, code1, .little);
    put(u64, out, 8, load_offs, .little);
    put(u64, out, 16, image_size, .little);
    put(u64, out, 24, kernel_flags, .little);
    put(u32, out, 56, 0x644D5241, .little);
    put(u32, out, 60, 0x00000040, .little);
    @memcpy(out[64..], raw_binary);
    return out;
}

fn pe32(bytes: []u8, offset: usize, value: u64) !void {
    put(u32, bytes, offset, std.math.cast(u32, value) orelse return error.PeFieldOverflow, .little);
}

pub fn put(comptime T: type, bytes: []u8, offset: usize, value: T, endian: std.builtin.Endian) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, endian);
}

pub fn diagnostic(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingSection, error.DuplicateSection => "required ELF section not found or duplicated (.dynamic, .rela.dyn, .text, .uk_reloc, .bss or .uk_bootinfo)",
        error.MissingSymbol, error.DuplicateSymbol => "required ELF symbol not found or duplicated",
        error.MissingRelocationCount => "could not find count of relocation entries",
        error.RelocationCountMismatch => ".rela.dyn entry count does not match .dynamic RELACOUNT",
        error.RelocationSectionBounds => ".uk_reloc linker symbols do not match its bounds",
        error.RelocationCapacity => ".uk_reloc has insufficient reserved space including signature and sentinel",
        error.SectionNotLoaded => "section must be allocated in the loaded image",
        error.IncompatibleLoadOverlap => "overlapping ELF LOAD segments have incompatible flags",
        error.BootinfoCapacity => ".uk_bootinfo has insufficient memory region capacity",
        error.UnsupportedRelocation => "unsupported relocation type; refusing to drop a relocation",
        error.UnsupportedArchitecture => "unsupported ELF architecture; expected x86_64 or arm64",
        error.UnsupportedEfiEndian => "EFI requires little-endian ELF inputs",
        error.ArchitectureMismatch => "ELF architecture does not match the selected architecture or debug image",
        error.InvalidEfiEntry => "uk_efi_entry64 is outside executable ELF LOAD segments",
        error.InvalidSymbolAddress => "invalid Linux boot header symbol address",
        error.InvalidEntryOffset => "Linux boot header entry branch offset is out of range or misaligned",
        error.PeFieldOverflow => "ELF metadata does not fit a PE32+ header field",
        error.ToolFailed => "native strip/objcopy tool failed",
        error.InvalidArguments => "invalid native post-processing arguments",
        error.UnsupportedTransformation => "unsupported native post-processing action; no interpreter fallback is available",
        error.InPlaceMutation => "output aliases an input file; refusing in-place mutation",
        error.AliasedOutputs => "post-processing outputs alias each other",
        error.OutputSymlink => "post-processing output must not be a symlink",
        error.InputChanged => "post-processing input identity changed before publication",
        else => "native post-processing failed",
    };
}
