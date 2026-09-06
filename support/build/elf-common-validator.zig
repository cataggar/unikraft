// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");

const ElfClass = enum {
    elf32,
    elf64,
};

const Endian = enum {
    little,
    big,
};

const Section = struct {
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    entry_size: usize,
};

pub const ValidationError = error{
    NotElf,
    UnsupportedClass,
    UnsupportedEndian,
    Truncated,
    InvalidSectionTable,
    InvalidSymbolTable,
    InvalidStringTable,
};

pub fn findCommonSymbol(bytes: []const u8) ValidationError!?[]const u8 {
    if (bytes.len < 16 or !std.mem.eql(u8, bytes[0..4], "\x7fELF")) {
        return error.NotElf;
    }
    const class: ElfClass = switch (bytes[4]) {
        1 => .elf32,
        2 => .elf64,
        else => return error.UnsupportedClass,
    };
    const endian: Endian = switch (bytes[5]) {
        1 => .little,
        2 => .big,
        else => return error.UnsupportedEndian,
    };
    const section_offset_field: usize = if (class == .elf32) 32 else 40;
    const section_offset_width: usize = if (class == .elf32) 4 else 8;
    const section_entry_size_field: usize = if (class == .elf32) 46 else 58;
    const section_count_field: usize = if (class == .elf32) 48 else 60;

    const section_offset = try toUsize(try readField(
        u64,
        bytes,
        section_offset_field,
        section_offset_width,
        endian,
    ));
    const section_entry_size = try toUsize(try readField(
        u64,
        bytes,
        section_entry_size_field,
        2,
        endian,
    ));
    var section_count = try toUsize(try readField(
        u64,
        bytes,
        section_count_field,
        2,
        endian,
    ));
    const minimum_section_size: usize = if (class == .elf32) 40 else 64;
    if (section_entry_size < minimum_section_size) return error.InvalidSectionTable;

    if (section_count == 0) {
        const section_zero = try sectionAt(
            bytes,
            class,
            endian,
            section_offset,
            section_entry_size,
            0,
        );
        section_count = section_zero.size;
    }
    if (section_count == 0) return null;
    try validateTableBounds(bytes.len, section_offset, section_entry_size, section_count);

    for (0..section_count) |section_index| {
        const symbol_section = try sectionAt(
            bytes,
            class,
            endian,
            section_offset,
            section_entry_size,
            section_index,
        );
        if (symbol_section.kind != 2 and symbol_section.kind != 11) continue;

        const minimum_symbol_size: usize = if (class == .elf32) 16 else 24;
        if (symbol_section.entry_size < minimum_symbol_size or symbol_section.entry_size == 0) {
            return error.InvalidSymbolTable;
        }
        if (symbol_section.size % symbol_section.entry_size != 0) {
            return error.InvalidSymbolTable;
        }
        try validateRange(bytes.len, symbol_section.offset, symbol_section.size);
        if (symbol_section.link >= section_count) return error.InvalidStringTable;

        const strings = try sectionAt(
            bytes,
            class,
            endian,
            section_offset,
            section_entry_size,
            symbol_section.link,
        );
        if (strings.kind != 3) return error.InvalidStringTable;
        try validateRange(bytes.len, strings.offset, strings.size);
        const string_bytes = bytes[strings.offset..][0..strings.size];

        const symbol_count = symbol_section.size / symbol_section.entry_size;
        for (1..symbol_count) |symbol_index| {
            const symbol_offset = symbol_section.offset + symbol_index * symbol_section.entry_size;
            const section_index_offset: usize = if (class == .elf32) 14 else 6;
            const name_offset = try toUsize(try readField(
                u64,
                bytes,
                symbol_offset,
                4,
                endian,
            ));
            const section_index_value = try readField(
                u16,
                bytes,
                symbol_offset + section_index_offset,
                2,
                endian,
            );
            if (section_index_value != 0xfff2) continue;
            if (name_offset >= string_bytes.len) return error.InvalidStringTable;
            const tail = string_bytes[name_offset..];
            const name_length = std.mem.indexOfScalar(u8, tail, 0) orelse
                return error.InvalidStringTable;
            return tail[0..name_length];
        }
    }
    return null;
}

fn sectionAt(
    bytes: []const u8,
    class: ElfClass,
    endian: Endian,
    table_offset: usize,
    entry_size: usize,
    index: usize,
) ValidationError!Section {
    if (entry_size == 0 or index > (std.math.maxInt(usize) - table_offset) / entry_size) {
        return error.InvalidSectionTable;
    }
    const offset = table_offset + index * entry_size;
    try validateRange(bytes.len, offset, entry_size);
    const data_offset_field: usize = if (class == .elf32) 16 else 24;
    const size_field: usize = if (class == .elf32) 20 else 32;
    const link_field: usize = if (class == .elf32) 24 else 40;
    const entry_size_field: usize = if (class == .elf32) 36 else 56;
    const word_width: usize = if (class == .elf32) 4 else 8;
    return .{
        .kind = @intCast(try readField(u64, bytes, offset + 4, 4, endian)),
        .offset = try toUsize(try readField(
            u64,
            bytes,
            offset + data_offset_field,
            word_width,
            endian,
        )),
        .size = try toUsize(try readField(
            u64,
            bytes,
            offset + size_field,
            word_width,
            endian,
        )),
        .link = try toUsize(try readField(
            u64,
            bytes,
            offset + link_field,
            4,
            endian,
        )),
        .entry_size = try toUsize(try readField(
            u64,
            bytes,
            offset + entry_size_field,
            word_width,
            endian,
        )),
    };
}

fn readField(
    comptime T: type,
    bytes: []const u8,
    offset: usize,
    width: usize,
    endian: Endian,
) ValidationError!T {
    try validateRange(bytes.len, offset, width);
    var value: T = 0;
    for (bytes[offset..][0..width], 0..) |byte, index| {
        const shift_index = if (endian == .little) index else width - index - 1;
        value |= @as(T, byte) << @intCast(shift_index * 8);
    }
    return value;
}

fn validateRange(length: usize, offset: usize, size: usize) ValidationError!void {
    if (offset > length or size > length - offset) return error.Truncated;
}

fn validateTableBounds(
    length: usize,
    offset: usize,
    entry_size: usize,
    count: usize,
) ValidationError!void {
    if (entry_size == 0 or count > (std.math.maxInt(usize) - offset) / entry_size) {
        return error.InvalidSectionTable;
    }
    validateRange(length, offset, entry_size * count) catch
        return error.InvalidSectionTable;
}

fn toUsize(value: u64) ValidationError!usize {
    return std.math.cast(usize, value) orelse error.Truncated;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 4) {
        std.debug.print(
            "usage: elf-common-validator COMPONENT INPUT SUCCESS-STAMP\n",
            .{},
        );
        std.process.exit(2);
    }

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        args[2],
        allocator,
        .limited(1024 * 1024 * 1024),
    ) catch |err| {
        std.debug.print(
            "error: unable to validate partial link for library '{s}': cannot read '{s}': {s}\n",
            .{ args[1], args[2], @errorName(err) },
        );
        std.process.exit(2);
    };
    const common = findCommonSymbol(bytes) catch |err| {
        std.debug.print(
            "error: unable to validate partial link for library '{s}': '{s}' is not a valid supported ELF object: {s}\n",
            .{ args[1], args[2], @errorName(err) },
        );
        std.process.exit(2);
    };
    if (common) |symbol| {
        std.debug.print(
            "error: library '{s}' partial link contains COMMON symbol '{s}'; compile tentative definitions with -fno-common or fix the defining source before native Zig linking\n",
            .{ args[1], if (symbol.len == 0) "<unnamed>" else symbol },
        );
        std.process.exit(1);
    }

    var stamp = std.Io.Dir.cwd().createFile(init.io, args[3], .{}) catch |err| {
        std.debug.print("error: unable to write ELF validation stamp '{s}': {s}\n", .{
            args[3],
            @errorName(err),
        });
        std.process.exit(2);
    };
    stamp.close(init.io);
}

fn putLittle(bytes: []u8, offset: usize, value: anytype) void {
    const T = @TypeOf(value);
    for (0..@sizeOf(T)) |index| {
        bytes[offset + index] = @truncate(value >> @intCast(index * 8));
    }
}

fn syntheticElf64(common_section_index: u16) [312]u8 {
    var bytes = [_]u8{0} ** 312;
    @memcpy(bytes[0..4], "\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    putLittle(bytes[40..], 0, @as(u64, 64));
    putLittle(bytes[58..], 0, @as(u16, 64));
    putLittle(bytes[60..], 0, @as(u16, 3));

    const symtab = 64 + 64;
    putLittle(bytes[symtab..], 4, @as(u32, 2));
    putLittle(bytes[symtab..], 24, @as(u64, 256));
    putLittle(bytes[symtab..], 32, @as(u64, 48));
    putLittle(bytes[symtab..], 40, @as(u32, 2));
    putLittle(bytes[symtab..], 56, @as(u64, 24));

    const strtab = 64 + 128;
    putLittle(bytes[strtab..], 4, @as(u32, 3));
    putLittle(bytes[strtab..], 24, @as(u64, 304));
    putLittle(bytes[strtab..], 32, @as(u64, 8));

    putLittle(bytes[280..], 0, @as(u32, 1));
    putLittle(bytes[280..], 6, common_section_index);
    @memcpy(bytes[304..312], "\x00common\x00");
    return bytes;
}

test "findCommonSymbol reports the offending symbol" {
    const bytes = syntheticElf64(0xfff2);
    try std.testing.expectEqualStrings("common", (try findCommonSymbol(&bytes)).?);
}

test "findCommonSymbol accepts an ELF without COMMON symbols" {
    const bytes = syntheticElf64(1);
    try std.testing.expect((try findCommonSymbol(&bytes)) == null);
}

test "findCommonSymbol rejects truncated ELF tables safely" {
    var bytes = syntheticElf64(0xfff2);
    putLittle(bytes[40..], 0, @as(u64, 300));
    try std.testing.expectError(error.InvalidSectionTable, findCommonSymbol(&bytes));
}
