// SPDX-License-Identifier: BSD-3-Clause

//! Bounds-checked ELF64 view shared by the native image transformations.
const std = @import("std");
const common = @import("elf-common-validator.zig");
const elf = std.elf;
const shn_xindex = 0xffff;

pub const Section = struct {
    header: elf.Elf64_Shdr,
    name: []const u8,
};

pub const Symbol = struct {
    header: elf.Elf64_Sym,
    name: []const u8,
};

pub const Image = struct {
    allocator: std.mem.Allocator,
    bytes: []const u8,
    header: elf.Header,
    sections: []Section,
    programs: []elf.Elf64_Phdr,
    symbols: []Symbol,

    pub fn deinit(self: *Image) void {
        self.allocator.free(self.sections);
        self.allocator.free(self.programs);
        self.allocator.free(self.symbols);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Image {
        var reader = std.Io.Reader.fixed(bytes);
        const header = try elf.Header.read(&reader);
        if (!header.is_64) return error.UnsupportedClass;
        if (header.machine != .X86_64 and header.machine != .AARCH64)
            return error.UnsupportedArchitecture;
        if (header.type != .EXEC and header.type != .DYN)
            return error.UnsupportedElfType;
        if (try integer(u32, bytes, 20, header.endian) != 1 or
            try integer(u16, bytes, 52, header.endian) != @sizeOf(elf.Elf64_Ehdr))
            return error.InvalidElfHeader;
        if (header.shoff == 0 or header.shentsize != @sizeOf(elf.Elf64_Shdr))
            return error.InvalidSectionTable;

        const zero = try structure(elf.Elf64_Shdr, bytes, header.shoff, header.endian);
        if (zero.sh_type != elf.SHT_NULL) return error.InvalidSectionTable;
        const section_count = if (header.shnum == 0) zero.sh_size else header.shnum;
        const program_count = if (header.phnum == elf.PN_XNUM) zero.sh_info else header.phnum;
        const names_index = if (header.shstrndx == shn_xindex) zero.sh_link else header.shstrndx;
        if (section_count == 0 or names_index == 0 or names_index >= section_count)
            return error.InvalidSectionTable;
        try table(bytes, header.shoff, section_count, @sizeOf(elf.Elf64_Shdr));
        if (program_count != 0) {
            if (header.phoff == 0 or header.phentsize != @sizeOf(elf.Elf64_Phdr))
                return error.InvalidProgramTable;
            try table(bytes, header.phoff, program_count, @sizeOf(elf.Elf64_Phdr));
        }
        const sections = try allocator.alloc(Section, try asUsize(section_count));
        errdefer allocator.free(sections);
        const programs = try allocator.alloc(elf.Elf64_Phdr, try asUsize(program_count));
        errdefer allocator.free(programs);
        var symbols: std.ArrayList(Symbol) = .empty;
        errdefer symbols.deinit(allocator);

        for (sections, 0..) |*item, index| {
            item.* = .{
                .header = try structure(elf.Elf64_Shdr, bytes, header.shoff + index * @sizeOf(elf.Elf64_Shdr), header.endian),
                .name = "",
            };
            const sh = item.header;
            if (index == 0) continue;
            if (sh.sh_type != elf.SHT_NOBITS) _ = try range(bytes, sh.sh_offset, sh.sh_size);
            _ = try add(sh.sh_addr, sh.sh_size);
            if (sh.sh_addralign != 0 and !std.math.isPowerOfTwo(sh.sh_addralign))
                return error.InvalidSectionAlignment;
        }
        const names = sections[try asUsize(names_index)].header;
        if (names.sh_type != elf.SHT_STRTAB) return error.InvalidStringTable;
        const name_bytes = try range(bytes, names.sh_offset, names.sh_size);
        for (sections) |*item| item.name = try string(name_bytes, item.header.sh_name);

        for (programs, 0..) |*program, index| {
            program.* = try structure(elf.Elf64_Phdr, bytes, header.phoff + index * @sizeOf(elf.Elf64_Phdr), header.endian);
            _ = try range(bytes, program.p_offset, program.p_filesz);
            _ = try add(program.p_vaddr, program.p_memsz);
            if (program.p_type == elf.PT_LOAD) {
                if (program.p_filesz > program.p_memsz) return error.InvalidLoadSegment;
                if (program.p_align > 1 and
                    (!std.math.isPowerOfTwo(program.p_align) or
                        program.p_vaddr % program.p_align != program.p_offset % program.p_align))
                    return error.InvalidLoadAlignment;
            }
        }

        for (sections) |item| {
            const sh = item.header;
            if (sh.sh_type != elf.SHT_SYMTAB and sh.sh_type != elf.SHT_DYNSYM) continue;
            if (sh.sh_size == 0 or sh.sh_entsize != @sizeOf(elf.Elf64_Sym) or sh.sh_size % sh.sh_entsize != 0)
                return error.InvalidSymbolTable;
            if (sh.sh_link >= sections.len) return error.InvalidStringTable;
            const strings = sections[sh.sh_link].header;
            if (strings.sh_type != elf.SHT_STRTAB) return error.InvalidStringTable;
            const string_bytes = try range(bytes, strings.sh_offset, strings.sh_size);
            const count = sh.sh_size / sh.sh_entsize;
            if (sh.sh_info > count) return error.InvalidSymbolTable;
            for (0..try asUsize(count)) |index| {
                const sym = try structure(elf.Elf64_Sym, bytes, sh.sh_offset + index * sh.sh_entsize, header.endian);
                const name = try string(string_bytes, sym.st_name);
                if (sym.st_shndx == shn_xindex) return error.UnsupportedSymbolIndex;
                if (sym.st_shndx < elf.SHN_LORESERVE and sym.st_shndx >= sections.len)
                    return error.InvalidSymbolTable;
                // nm's default view uses the full symbol table, not .dynsym.
                if (sh.sh_type == elf.SHT_SYMTAB and sym.st_shndx != elf.SHN_UNDEF)
                    try symbols.append(allocator, .{ .header = sym, .name = name });
            }
        }
        if (try common.findCommonSymbol(bytes) != null) return error.CommonSymbol;
        std.mem.sort(Symbol, symbols.items, {}, symbolLessThan);
        return .{
            .allocator = allocator,
            .bytes = bytes,
            .header = header,
            .sections = sections,
            .programs = programs,
            .symbols = try symbols.toOwnedSlice(allocator),
        };
    }

    pub fn section(self: Image, name: []const u8) !Section {
        var found: ?Section = null;
        for (self.sections) |item| {
            if (!std.mem.eql(u8, name, item.name)) continue;
            if (found != null) return error.DuplicateSection;
            found = item;
        }
        return found orelse error.MissingSection;
    }

    pub fn symbol(self: Image, name: []const u8) !u64 {
        var found: ?u64 = null;
        for (self.symbols) |item| {
            if (!std.mem.eql(u8, name, item.name)) continue;
            if (found != null) return error.DuplicateSymbol;
            found = item.header.st_value;
        }
        return found orelse error.MissingSymbol;
    }

    pub fn sectionData(self: Image, item: Section) ![]const u8 {
        if (item.header.sh_type == elf.SHT_NOBITS) return error.InvalidSectionType;
        return range(self.bytes, item.header.sh_offset, item.header.sh_size);
    }

    pub fn requireLoadedSection(self: Image, item: Section) !void {
        const sh = item.header;
        if (sh.sh_flags & elf.SHF_ALLOC == 0 or sh.sh_type == elf.SHT_NOBITS)
            return error.SectionNotLoaded;
        for (self.programs) |ph| {
            if (ph.p_type != elf.PT_LOAD or sh.sh_addr < ph.p_vaddr or sh.sh_offset < ph.p_offset)
                continue;
            const delta = sh.sh_addr - ph.p_vaddr;
            if (delta == sh.sh_offset - ph.p_offset and delta <= ph.p_filesz and
                sh.sh_size <= ph.p_filesz - delta) return;
        }
        return error.SectionNotLoaded;
    }

    pub fn containsMemory(self: Image, address: u64, size: u64) bool {
        for (self.programs) |ph| {
            if (ph.p_type != elf.PT_LOAD or address < ph.p_vaddr) continue;
            const delta = address - ph.p_vaddr;
            if (delta <= ph.p_memsz and size <= ph.p_memsz - delta) return true;
        }
        return false;
    }
};

fn symbolLessThan(_: void, a: Symbol, b: Symbol) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

pub fn range(bytes: []const u8, offset: u64, size: u64) ![]const u8 {
    if (offset > bytes.len or size > bytes.len - offset) return error.Truncated;
    return bytes[try asUsize(offset)..][0..try asUsize(size)];
}

fn table(bytes: []const u8, offset: u64, count: u64, width: u64) !void {
    const size = std.math.mul(u64, count, width) catch return error.IntegerOverflow;
    _ = try range(bytes, offset, size);
}

pub fn structure(comptime T: type, bytes: []const u8, offset: u64, endian: std.builtin.Endian) !T {
    var reader = std.Io.Reader.fixed(try range(bytes, offset, @sizeOf(T)));
    return reader.takeStruct(T, endian);
}

pub fn integer(comptime T: type, bytes: []const u8, offset: u64, endian: std.builtin.Endian) !T {
    return std.mem.readInt(T, (try range(bytes, offset, @sizeOf(T)))[0..@sizeOf(T)], endian);
}

pub fn string(bytes: []const u8, offset: u64) ![]const u8 {
    if (offset >= bytes.len) return error.InvalidStringTable;
    const tail = bytes[try asUsize(offset)..];
    const length = std.mem.indexOfScalar(u8, tail, 0) orelse return error.InvalidStringTable;
    return tail[0..length];
}

pub fn asUsize(value: u64) !usize {
    return std.math.cast(usize, value) orelse error.IntegerOverflow;
}

pub fn add(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch error.IntegerOverflow;
}

pub fn subtract(a: u64, b: u64) !u64 {
    return std.math.sub(u64, a, b) catch error.InvalidAddress;
}
