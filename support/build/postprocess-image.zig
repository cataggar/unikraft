// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, 2023, Unikraft GmbH and The Unikraft Authors.

//! Native equivalents of the reached mkukreloc, mkbootinfo and mkefi actions.
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

    var entries: std.ArrayList(Relocation) = .empty;
    defer entries.deinit(allocator);
    const relative_type: u32 = if (image.header.machine == .X86_64) 8 else 1027;
    for (0..try format.asUsize(expected)) |index| {
        const entry = try format.structure(elf.Elf64_Rela, image.bytes, rela.header.sh_offset + index * @sizeOf(elf.Elf64_Rela), image.header.endian);
        if (@as(u32, @truncate(entry.r_info)) != relative_type or entry.r_info >> 32 != 0)
            return error.UnsupportedRelocation;
        try entries.append(allocator, .{
            .offset = try sub(entry.r_offset, base),
            .value = try relativeValue(entry.r_addend, base),
            .size = 8,
            .flags = 0,
        });
    }

    // nm sorts by name; the legacy helper processes all data entries before
    // immediate entries, replacing the first dynamic relocation at that offset.
    for ([_]@FieldType(RelocSymbol, "kind"){ .data, .imm }) |kind| {
        for (image.symbols) |symbol| {
            const parsed = (try relocSymbol(symbol.name)) orelse continue;
            if (parsed.kind != kind) continue;
            var value: i128 = @as(i128, try image.symbol(parsed.target)) - @as(i128, base);
            var flags: u32 = @intFromBool(parsed.physical);
            for (image.symbols) |attribute| {
                const attr = (try relocSymbol(attribute.name)) orelse continue;
                if (attr.kind == .pte_attr and std.mem.eql(u8, attr.target, parsed.target)) {
                    value += attribute.header.st_value;
                    flags |= 1;
                }
            }
            const offset = try sub(symbol.header.st_value, base);
            for (entries.items, 0..) |entry, index| {
                if (entry.offset == offset) {
                    _ = entries.orderedRemove(index);
                    break;
                }
            }
            try entries.append(allocator, .{
                .offset = offset,
                .value = std.math.cast(i64, value) orelse return error.InvalidRelocationValue,
                .size = parsed.size,
                .flags = flags,
            });
        }
    }

    const limit = try sub(bss.header.sh_addr, base);
    var kept: usize = 0;
    for (entries.items) |entry| {
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
        if (ph.p_type != elf.PT_LOAD) continue;
        const size = (try add(ph.p_memsz, 4095)) & ~@as(u64, 4095);
        if (size == 0) continue;
        _ = try add(ph.p_vaddr, size);
        try regions.append(allocator, .{ .base = ph.p_vaddr, .size = size, .flags = ph.p_flags & 7 });
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
    var region_name = [_]u8{0} ** 36;
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

fn programLessThan(_: void, a: elf.Elf64_Phdr, b: elf.Elf64_Phdr) bool {
    // Overflow has already been checked by Image.parse.
    return a.p_vaddr + a.p_memsz < b.p_vaddr + b.p_memsz;
}

pub fn efi(allocator: std.mem.Allocator, image: Image, debug: Image) ![]u8 {
    if (image.header.endian != .little or debug.header.endian != .little)
        return error.UnsupportedEfiEndian;
    if (image.header.machine != debug.header.machine) return error.ArchitectureMismatch;
    const base = try debug.symbol("_base_addr");
    const bss = try debug.symbol("__bss_start");
    const entry = try debug.symbol("uk_efi_entry64");
    var programs: std.ArrayList(elf.Elf64_Phdr) = .empty;
    defer programs.deinit(allocator);
    var executable_entry = false;
    for (image.programs) |ph| {
        if (ph.p_type != elf.PT_LOAD) continue;
        if (ph.p_vaddr < base) return error.InvalidAddress;
        if (ph.p_flags & elf.PF_X != 0 and entry >= ph.p_vaddr and entry - ph.p_vaddr < ph.p_memsz)
            executable_entry = true;
        try programs.append(allocator, ph);
    }
    if (programs.items.len == 0) return error.MissingLoadSegments;
    if (!executable_entry) return error.InvalidEfiEntry;
    if (programs.items.len > std.math.maxInt(u16)) return error.TooManyPeSections;
    std.mem.sort(elf.Elf64_Phdr, programs.items, {}, programLessThan);
    const last = programs.items[programs.items.len - 1];
    const end = try add(last.p_vaddr, last.p_memsz);
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
        if (ph.p_flags & (elf.PF_R | elf.PF_X) == (elf.PF_R | elf.PF_X)) {
            code_size = try add(code_size, ph.p_memsz);
            code_base = try add(try sub(ph.p_vaddr, base), headers);
        } else if (ph.p_flags & elf.PF_R != 0) {
            data_size = try add(data_size, ph.p_memsz);
        }
    }
    // These legacy fields include the header page in BSS accounting and twice
    // in SizeOfImage. Changing that policy is separate from this native port.
    data_size = try sub(data_size, uninitialized);
    const result = try allocator.alloc(u8, try format.asUsize(try add(headers, image.bytes.len)));
    errdefer allocator.free(result);
    @memset(result, 0);
    // mkefi edits a copy in place: bytes between its section table and the
    // inserted ELF are the original ELF bytes, not newly zeroed padding.
    @memcpy(result[0..image.bytes.len], image.bytes);
    @memset(result[0..table_end], 0);
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
        try pe32(result, offset + 8, ph.p_memsz);
        try pe32(result, offset + 12, try add(try sub(ph.p_vaddr, base), headers));
        try pe32(result, offset + 16, ph.p_filesz);
        try pe32(result, offset + 20, try add(ph.p_offset, headers));
        put(u32, result, offset + 36, 0xe0d00040, .little);
    }
    return result;
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
        error.PeFieldOverflow => "ELF metadata does not fit a PE32+ header field",
        error.ToolFailed => "native strip/objcopy tool failed",
        error.InvalidArguments => "invalid native post-processing arguments",
        error.UnsupportedTransformation => "unsupported native post-processing action; no interpreter fallback is available",
        else => "native post-processing failed",
    };
}
