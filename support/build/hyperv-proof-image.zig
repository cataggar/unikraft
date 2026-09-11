// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const elf = @import("postprocess-elf.zig");
pub const disasm = @import("hyperv-proof-disasm.zig");
pub const Function = struct { start: u64, end: u64, name: []const u8 };

pub const Model = struct {
    image: elf.Image,
    symbols: disasm.Symbols,
    program: disasm.Program,
    functions: []Function,

    pub fn init(allocator: std.mem.Allocator, bytes: []const u8, nm: []const u8, assembly: []const u8) !Model {
        var image = try elf.Image.parse(allocator, bytes);
        errdefer image.deinit();
        if (image.header.machine != .X86_64 or image.header.endian != .little)
            return error.UnsupportedImageArchitecture;
        if (image.programs.len == 0) return error.MissingLoadSegments;
        var symbols = try disasm.Symbols.parse(allocator, nm);
        errdefer symbols.deinit();
        var program = try disasm.Program.parse(allocator, assembly);
        errdefer program.deinit();
        const functions = try functionRanges(allocator, image);
        errdefer allocator.free(functions);
        const model: Model = .{ .image = image, .symbols = symbols, .program = program, .functions = functions };
        try model.validateEvidence();
        return model;
    }

    pub fn deinit(self: *Model) void {
        self.image.allocator.free(self.functions);
        self.program.deinit();
        self.symbols.deinit();
        self.image.deinit();
    }

    fn validateEvidence(self: Model) !void {
        for (self.image.symbols) |item| {
            const kind = item.header.st_info & 15;
            if (item.name.len == 0 or kind == std.elf.STT_FILE or kind == std.elf.STT_SECTION) continue;
            const entries = self.symbols.entries.get(item.name) orelse return error.IncompleteNmOutput;
            var found = false;
            for (entries.items) |entry| {
                if (entry.address == item.header.st_value) found = true;
            }
            if (!found) return error.NmAddressMismatch;
            if (kind != std.elf.STT_FUNC or item.header.st_size == 0) continue;
            var cursor = item.header.st_value;
            const end = try elf.add(cursor, item.header.st_size);
            while (cursor < end) {
                const index = self.program.instruction_index.get(cursor) orelse return error.IncompleteDisassembly;
                cursor = try elf.add(cursor, self.program.instructions.items[index].size);
                if (cursor > end) return error.IncompleteDisassembly;
            }
        }
        for (self.program.instructions.items) |instruction| {
            const original = try self.executableBytes(instruction.address, instruction.size);
            if (!std.mem.eql(u8, original, instruction.bytes[0..instruction.size]))
                return error.DisassemblyBytesMismatch;
            try verifyBranchEncoding(instruction);
        }
    }

    pub fn maybeSymbol(self: Model, name: []const u8) !?elf.Symbol {
        var result: ?elf.Symbol = null;
        for (self.image.symbols) |item| {
            if (!std.mem.eql(u8, item.name, name)) continue;
            if (result != null) return error.DuplicateSymbol;
            result = item;
        }
        return result;
    }

    pub fn symbol(self: Model, name: []const u8) !elf.Symbol {
        return (try self.maybeSymbol(name)) orelse error.MissingSymbol;
    }

    pub fn address(self: Model, name: []const u8) !u64 {
        return (try self.symbol(name)).header.st_value;
    }

    pub fn namedKind(self: Model, name: []const u8, accepted: []const u8) !elf.Symbol {
        const result = try self.symbol(name);
        const entries = self.symbols.entries.get(name) orelse return error.MissingNmSymbol;
        if (entries.items.len != 1 or entries.items[0].address != result.header.st_value)
            return error.DuplicateSymbol;
        if (std.mem.indexOfScalar(u8, accepted, entries.items[0].kind) == null)
            return error.WrongSymbolKind;
        if (result.header.st_info >> 4 == std.elf.STB_WEAK)
            return error.WeakSymbol;
        return result;
    }

    pub fn strong(self: Model, name: []const u8) !u64 {
        const result = try self.namedKind(name, "T");
        if (result.header.st_info >> 4 != std.elf.STB_GLOBAL) return error.WeakSymbol;
        _ = try self.executableBytes(result.header.st_value, 1);
        return result.header.st_value;
    }

    pub fn body(self: Model, name: []const u8) ![]const disasm.Instruction {
        return self.bodyAt(try self.address(name));
    }

    pub fn functionAt(self: Model, pc: u64) !Function {
        var lo: usize = 0;
        var hi = self.functions.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.functions[mid].start <= pc) lo = mid + 1 else hi = mid;
        }
        if (lo == 0 or pc >= self.functions[lo - 1].end) return error.MissingFunctionExtent;
        return self.functions[lo - 1];
    }

    pub fn bodyAt(self: Model, pc: u64) ![]const disasm.Instruction {
        const extent = try self.functionAt(pc);
        const first = self.program.instruction_index.get(pc) orelse return error.MissingDisassembly;
        var last = first;
        var cursor = pc;
        while (cursor < extent.end) : (last += 1) {
            if (last >= self.program.instructions.items.len) return error.IncompleteDisassembly;
            const instruction = self.program.instructions.items[last];
            if (instruction.address != cursor) return error.IncompleteDisassembly;
            cursor = try elf.add(cursor, instruction.size);
        }
        if (cursor != extent.end) return error.IncompleteDisassembly;
        return self.program.instructions.items[first..last];
    }

    pub fn dataAt(self: Model, address_value: u64, size: u64) ![]const u8 {
        var result: ?[]const u8 = null;
        for (self.image.programs) |header| {
            if (header.p_type != std.elf.PT_LOAD or address_value < header.p_vaddr) continue;
            const delta = address_value - header.p_vaddr;
            if (delta > header.p_filesz or size > header.p_filesz - delta) continue;
            if (result != null) return error.AmbiguousLoadAddress;
            result = try elf.range(self.image.bytes, try elf.add(header.p_offset, delta), size);
        }
        return result orelse error.AddressOutsideLoadedImage;
    }

    pub fn executableBytes(self: Model, address_value: u64, size: u64) ![]const u8 {
        for (self.image.sections) |section| {
            const header = section.header;
            if (header.sh_flags & (std.elf.SHF_ALLOC | std.elf.SHF_EXECINSTR) != (std.elf.SHF_ALLOC | std.elf.SHF_EXECINSTR) or address_value < header.sh_addr)
                continue;
            const delta = address_value - header.sh_addr;
            if (delta <= header.sh_size and size <= header.sh_size - delta) {
                try self.image.requireLoadedSection(section);
                for (self.image.programs) |program| {
                    if (program.p_type != std.elf.PT_LOAD or program.p_flags & std.elf.PF_X == 0 or address_value < program.p_vaddr) continue;
                    const offset = address_value - program.p_vaddr;
                    if (offset <= program.p_filesz and size <= program.p_filesz - offset)
                        return self.dataAt(address_value, size);
                }
                return error.AddressOutsideExecutableSegment;
            }
        }
        return error.AddressOutsideExecutableSection;
    }

    pub fn pointer(self: Model, address_value: u64) !u64 {
        const bytes = try self.dataAt(address_value, 8);
        return (try self.relocatedPointer(address_value)) orelse std.mem.readInt(u64, bytes[0..8], .little);
    }

    pub fn relocatedPointer(self: Model, address_value: u64) !?u64 {
        var relocated: ?u64 = null;
        for (self.image.sections) |section| {
            const sh = section.header;
            if ((sh.sh_type == std.elf.SHT_REL or sh.sh_type == std.elf.SHT_RELR) and sh.sh_flags & std.elf.SHF_ALLOC != 0)
                return error.UnsupportedPointerRelocation;
            if (sh.sh_type != std.elf.SHT_RELA or sh.sh_flags & std.elf.SHF_ALLOC == 0) continue;
            if (sh.sh_entsize != 24 or sh.sh_size % 24 != 0) return error.InvalidRelocationTable;
            for (0..try elf.asUsize(sh.sh_size / 24)) |index| {
                const entry = try elf.structure(std.elf.Elf64_Rela, self.image.bytes, sh.sh_offset + index * 24, .little);
                if (entry.r_offset != address_value) continue;
                if (relocated != null) return error.AmbiguousPointerRelocation;
                if (entry.r_info != 8) return error.UnsupportedPointerRelocation;
                relocated = @bitCast(entry.r_addend);
            }
        }
        return relocated;
    }

    pub fn directCall(self: Model, caller: []const u8, callee: []const u8, tails: bool) !?u64 {
        const destination = try self.address(callee);
        for (try self.body(caller)) |instruction| {
            if (!(instruction.isCall() or (tails and std.mem.startsWith(u8, instruction.op, "j"))) or instruction.indirect()) continue;
            if (try instruction.target() == destination) return instruction.address;
        }
        return null;
    }

    pub fn hasNameAt(self: Model, address_value: u64, fragment: []const u8) bool {
        for (self.image.symbols) |item| {
            if (item.header.st_value == address_value and std.mem.indexOf(u8, item.name, fragment) != null) return true;
        }
        return false;
    }
};

fn rangeLessThan(_: void, a: Function, b: Function) bool {
    return a.start < b.start or (a.start == b.start and a.end > b.end);
}

fn functionRanges(allocator: std.mem.Allocator, image: elf.Image) ![]Function {
    var ranges: std.ArrayList(Function) = .empty;
    defer ranges.deinit(allocator);
    for (image.symbols) |item| {
        if (item.header.st_info & 15 != std.elf.STT_FUNC or item.header.st_size == 0) continue;
        try ranges.append(allocator, .{
            .start = item.header.st_value,
            .end = try elf.add(item.header.st_value, item.header.st_size),
            .name = item.name,
        });
    }
    std.mem.sort(Function, ranges.items, {}, rangeLessThan);
    var count: usize = 0;
    for (ranges.items) |item| {
        if (count != 0 and item.start < ranges.items[count - 1].end) {
            if (item.end <= ranges.items[count - 1].end) continue;
            return error.AmbiguousFunctionExtent;
        }
        ranges.items[count] = item;
        count += 1;
    }
    return allocator.dupe(Function, ranges.items[0..count]);
}

fn verifyBranchEncoding(instruction: disasm.Instruction) !void {
    if (instruction.unknown()) return;
    const bytes = instruction.bytes[0..instruction.size];
    var index: usize = 0;
    while (index < bytes.len) : (index += 1) {
        if (bytes[index] >= 0x40 and bytes[index] <= 0x4f) continue;
        switch (bytes[index]) {
            0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65 => continue,
            else => break,
        }
    }
    if (index == bytes.len) return error.InvalidInstruction;
    const opcode = bytes[index];
    const width: usize = if (opcode == 0xe8 or opcode == 0xe9)
        4
    else if (opcode == 0xeb or (opcode >= 0x70 and opcode <= 0x7f) or (opcode >= 0xe0 and opcode <= 0xe3))
        1
    else if (opcode == 0x0f and index + 1 < bytes.len and bytes[index + 1] >= 0x80 and bytes[index + 1] <= 0x8f) blk: {
        index += 1;
        break :blk 4;
    } else 0;
    if (width != 0) {
        if (index + 1 + width != bytes.len or !instruction.isBranch() or instruction.indirect())
            return error.DisassemblyTargetMismatch;
        const displacement: i64 = if (width == 1)
            @as(i8, @bitCast(bytes[bytes.len - 1]))
        else
            std.mem.readInt(i32, bytes[bytes.len - 4 ..][0..4], .little);
        const destination = instruction.address +% instruction.size +% @as(u64, @bitCast(displacement));
        if (try instruction.target() != destination)
            return error.DisassemblyTargetMismatch;
    } else if (instruction.isBranch() and !instruction.indirect()) {
        // Far/indirect transfers without a reviewed concrete target are never
        // admitted as direct IRQ edges.
        if (!std.mem.startsWith(u8, instruction.op, "ljmp")) return error.UnsupportedBranchEncoding;
    }
}
