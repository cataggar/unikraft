// SPDX-License-Identifier: BSD-3-Clause

//! Bounded ET_REL indexing using the standard library's ELF readers.
//! This is an object contract, not a linked-image or boot proof.
const std = @import("std");
const elf = std.elf;

pub const maximum_file = 64 * 1024 * 1024;
pub const maximum_sections = 4096;
pub const maximum_symbols = 65536;
pub const maximum_relocations = 262144;
pub const Section = struct { header: elf.Elf64_Shdr, name: []const u8, index: usize };
pub const Symbol = struct { entry: elf.Elf64_Sym, name: []const u8, index: usize };

pub const Object = struct {
    allocator: std.mem.Allocator,
    bytes: []const u8,
    header: elf.Header,
    sections: []Section,
    symbols: []Symbol,
    symbol_section: usize,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Object {
        if (bytes.len > maximum_file) return error.ObjectTooLarge;
        var reader = std.Io.Reader.fixed(bytes);
        const header = try elf.Header.read(&reader);
        if (!header.is_64 or header.endian != .little or header.type != .REL or header.machine != .X86_64)
            return error.UnsupportedObject;
        if (std.mem.readInt(u32, bytes[20..24], .little) != 1 or
            std.mem.readInt(u16, bytes[52..54], .little) != 64 or
            header.entry != 0 or header.phnum != 0 or header.phoff != 0 or
            header.shentsize != @sizeOf(elf.Elf64_Shdr) or header.shnum == 0 or
            header.shnum > maximum_sections or header.shstrndx == 0 or header.shstrndx >= header.shnum)
            return error.InvalidElfHeader;
        _ = try region(bytes, header.shoff, @as(u64, header.shnum) * header.shentsize);
        const sections = try allocator.alloc(Section, header.shnum);
        errdefer allocator.free(sections);
        var iterator = header.iterateSectionHeadersBuffer(bytes);
        var symtab: ?usize = null;
        for (sections, 0..) |*section_entry, index| {
            const sh = (try iterator.next()) orelse return error.InvalidSectionTable;
            section_entry.* = .{ .header = sh, .name = "", .index = index };
            if (index == 0) {
                if (!std.meta.eql(sh, std.mem.zeroes(elf.Elf64_Shdr))) return error.InvalidSectionTable;
                continue;
            }
            if (sh.sh_addralign != 0 and !std.math.isPowerOfTwo(sh.sh_addralign)) return error.InvalidAlignment;
            if (sh.sh_type != @intFromEnum(elf.SHT.NOBITS))
                _ = try region(bytes, sh.sh_offset, sh.sh_size);
            if (sh.sh_type == @intFromEnum(elf.SHT.SYMTAB)) {
                if (symtab != null) return error.DuplicateSymbolTable;
                symtab = index;
            }
            if (sh.sh_type == @intFromEnum(elf.SHT.DYNSYM) or sh.sh_type == @intFromEnum(elf.SHT.SYMTAB_SHNDX))
                return error.UnsupportedSymbolTable;
        }
        const names_header = sections[header.shstrndx].header;
        if (names_header.sh_type != @intFromEnum(elf.SHT.STRTAB)) return error.InvalidStringTable;
        const names = try region(bytes, names_header.sh_offset, names_header.sh_size);
        for (sections) |*section_entry| section_entry.name = try string(names, section_entry.header.sh_name);
        const symbol_section = symtab orelse return error.MissingSymbolTable;
        const sh = sections[symbol_section].header;
        if (sh.sh_entsize != @sizeOf(elf.Elf64_Sym) or sh.sh_size == 0 or sh.sh_size % sh.sh_entsize != 0 or
            sh.sh_size / sh.sh_entsize > maximum_symbols or sh.sh_link >= sections.len or sh.sh_info > sh.sh_size / sh.sh_entsize)
            return error.InvalidSymbolTable;
        const strings = sections[sh.sh_link].header;
        if (strings.sh_type != @intFromEnum(elf.SHT.STRTAB)) return error.InvalidStringTable;
        const table = try region(bytes, strings.sh_offset, strings.sh_size);
        const symbols = try allocator.alloc(Symbol, @intCast(sh.sh_size / sh.sh_entsize));
        errdefer allocator.free(symbols);
        var symbol_reader = std.Io.Reader.fixed(try region(bytes, sh.sh_offset, sh.sh_size));
        for (symbols, 0..) |*symbol_entry, index| {
            const entry = try symbol_reader.takeStruct(elf.Elf64_Sym, .little);
            if (index == 0 and !std.meta.eql(entry, std.mem.zeroes(elf.Elf64_Sym))) return error.InvalidSymbolTable;
            if (entry.st_shndx == elf.SHN_HIRESERVE) return error.UnsupportedSymbolTable;
            if (entry.st_shndx < elf.SHN_LORESERVE and entry.st_shndx >= sections.len) return error.InvalidSymbolTable;
            symbol_entry.* = .{ .entry = entry, .name = try string(table, entry.st_name), .index = index };
        }
        const result: Object = .{
            .allocator = allocator,
            .bytes = bytes,
            .header = header,
            .sections = sections,
            .symbols = symbols,
            .symbol_section = symbol_section,
        };
        try result.validateRelocations();
        return result;
    }

    pub fn deinit(self: Object) void {
        self.allocator.free(self.symbols);
        self.allocator.free(self.sections);
    }

    pub fn section(self: Object, name: []const u8) !Section {
        var found: ?Section = null;
        for (self.sections) |candidate| if (std.mem.eql(u8, candidate.name, name)) {
            if (found != null) return error.DuplicateSection;
            found = candidate;
        };
        return found orelse error.MissingSection;
    }

    pub fn symbol(self: Object, name: []const u8) !Symbol {
        var found: ?Symbol = null;
        for (self.symbols) |candidate| if (std.mem.eql(u8, candidate.name, name)) {
            if (found != null) return error.DuplicateSymbol;
            found = candidate;
        };
        return found orelse error.MissingExport;
    }

    pub fn definition(self: Object, name: []const u8, object: bool) !Symbol {
        const found = try self.symbol(name);
        const entry = found.entry;
        if (entry.st_bind() != elf.STB_GLOBAL or entry.st_type() != (if (object) elf.STT_OBJECT else elf.STT_FUNC) or
            entry.st_other != 0 or entry.st_shndx == elf.SHN_UNDEF or entry.st_shndx >= self.sections.len)
            return error.InvalidExport;
        const sh = self.sections[entry.st_shndx].header;
        if (entry.st_size == 0 or entry.st_value > sh.sh_size or entry.st_size > sh.sh_size - entry.st_value)
            return error.InvalidExport;
        if (!object and (sh.sh_type != @intFromEnum(elf.SHT.PROGBITS) or
            sh.sh_flags & (elf.SHF_ALLOC | elf.SHF_EXECINSTR | elf.SHF_WRITE) != elf.SHF_ALLOC | elf.SHF_EXECINSTR))
            return error.InvalidExport;
        return found;
    }

    pub fn noUndefined(self: Object) !void {
        for (self.symbols[1..]) |value| {
            if (value.entry.st_shndx == elf.SHN_UNDEF) return error.UndefinedSymbol;
        }
    }

    pub fn reference(self: Object, name: []const u8) !Symbol {
        const found = try self.symbol(name);
        if (found.entry.st_shndx != elf.SHN_UNDEF or found.entry.st_bind() != elf.STB_GLOBAL or
            found.entry.st_other != 0) return error.InvalidMappingReference;
        for (self.sections) |section_| {
            const sh = section_.header;
            if (sh.sh_type != @intFromEnum(elf.SHT.RELA)) continue;
            const target = self.sections[sh.sh_info].header;
            if (target.sh_type != @intFromEnum(elf.SHT.PROGBITS) or
                target.sh_flags & (elf.SHF_ALLOC | elf.SHF_EXECINSTR | elf.SHF_WRITE) != elf.SHF_ALLOC | elf.SHF_EXECINSTR) continue;
            var reader = std.Io.Reader.fixed(try region(self.bytes, sh.sh_offset, sh.sh_size));
            while (reader.seek < reader.end) {
                const relocation = try reader.takeStruct(elf.Elf64_Rela, .little);
                if (relocation.r_info >> 32 == found.index and @as(u32, @truncate(relocation.r_info)) != 0) return found;
            }
        }
        return error.MissingMappingRelocation;
    }

    fn validateRelocations(self: Object) !void {
        var total: u64 = 0;
        for (self.sections) |section_| {
            const sh = section_.header;
            if (sh.sh_type == @intFromEnum(elf.SHT.REL)) return error.UnsupportedRelocation;
            if (sh.sh_type != @intFromEnum(elf.SHT.RELA)) continue;
            if (sh.sh_link != self.symbol_section or sh.sh_info == 0 or sh.sh_info >= self.sections.len or
                sh.sh_entsize != @sizeOf(elf.Elf64_Rela) or sh.sh_size % sh.sh_entsize != 0)
                return error.InvalidRelocation;
            const count = sh.sh_size / sh.sh_entsize;
            if (count > maximum_relocations - total) return error.TooManyRelocations;
            total += count;
            const target = self.sections[sh.sh_info].header;
            var reader = std.Io.Reader.fixed(try region(self.bytes, sh.sh_offset, sh.sh_size));
            while (reader.seek < reader.end) {
                const relocation = try reader.takeStruct(elf.Elf64_Rela, .little);
                if (relocation.r_info >> 32 >= self.symbols.len or relocation.r_offset >= target.sh_size)
                    return error.InvalidRelocation;
            }
        }
    }
};

pub fn region(bytes: []const u8, offset: u64, size: u64) ![]const u8 {
    if (offset > bytes.len or size > bytes.len - offset) return error.TruncatedObject;
    return bytes[@intCast(offset)..][0..@intCast(size)];
}

fn string(table: []const u8, offset: u32) ![]const u8 {
    if (table.len == 0 or table[0] != 0 or offset >= table.len) return error.InvalidStringTable;
    const tail = table[offset..];
    const length = std.mem.indexOfScalar(u8, tail[0..@min(tail.len, 4097)], 0) orelse return error.InvalidStringTable;
    if (length > 4096) return error.SymbolNameTooLong;
    return tail[0..length];
}
