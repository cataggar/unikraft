// SPDX-License-Identifier: BSD-3-Clause

//! Bounded parsers for the configured native NM and AT&T objdump decoders.
//! Addresses, instruction bytes and symbol coverage are checked against ELF
//! independently by hyperv-proof-image.zig.
const std = @import("std");

pub const NmEntry = struct { address: u64, kind: u8 };
pub const Symbols = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(std.ArrayList(NmEntry)),

    pub fn parse(allocator: std.mem.Allocator, text: []const u8) !Symbols {
        if (text.len == 0 or text[text.len - 1] != '\n' or std.mem.indexOfScalar(u8, text, 0) != null)
            return error.MalformedNmOutput;
        var result: Symbols = .{ .allocator = allocator, .entries = .init(allocator) };
        errdefer result.deinit();
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            var tokens = std.mem.tokenizeAny(u8, line, " \t");
            const first = tokens.next().?;
            if (first.len == 1 and (first[0] == 'U' or first[0] == 'w' or first[0] == 'v')) {
                if (tokens.next() == null) return error.MalformedNmOutput;
                continue;
            }
            const address = hex(first) catch return error.MalformedNmOutput;
            const kind = tokens.next() orelse return error.MalformedNmOutput;
            if (kind.len != 1 or !std.ascii.isAlphabetic(kind[0])) return error.MalformedNmOutput;
            const name = std.mem.trim(u8, tokens.rest(), " \t");
            if (name.len == 0) return error.MalformedNmOutput;
            const entry = try result.entries.getOrPut(name);
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            try entry.value_ptr.append(allocator, .{ .address = address, .kind = kind[0] });
        }
        if (result.entries.count() == 0) return error.MalformedNmOutput;
        return result;
    }

    pub fn deinit(self: *Symbols) void {
        var iterator = self.entries.valueIterator();
        while (iterator.next()) |entry| entry.deinit(self.allocator);
        self.entries.deinit();
    }
};

pub const Instruction = struct {
    address: u64,
    bytes: [15]u8 = @splat(0),
    size: u8 = 0,
    op: []const u8,
    operands: []const u8 = "",
    annotated_reference: ?u64 = null,

    pub fn isCall(self: Instruction) bool {
        return std.mem.startsWith(u8, self.op, "call");
    }

    pub fn isJump(self: Instruction) bool {
        return std.mem.eql(u8, self.op, "jmp") or std.mem.eql(u8, self.op, "jmpq") or
            std.mem.eql(u8, self.op, "jmpl");
    }

    pub fn stops(self: Instruction) bool {
        return std.mem.startsWith(u8, self.op, "ret") or std.mem.startsWith(u8, self.op, "iret") or
            std.mem.eql(u8, self.op, "ud2");
    }

    pub fn isBranch(self: Instruction) bool {
        return self.isCall() or std.mem.startsWith(u8, self.op, "j") or
            std.mem.startsWith(u8, self.op, "ljmp") or std.mem.startsWith(u8, self.op, "lcall") or
            std.mem.startsWith(u8, self.op, "loop");
    }

    pub fn isBarrier(self: Instruction) bool {
        return self.isBranch() or std.mem.startsWith(u8, self.op, "ret") or
            std.mem.startsWith(u8, self.op, "iret") or std.mem.startsWith(u8, self.op, "ljmp") or
            std.mem.eql(u8, self.op, "sysret") or std.mem.eql(u8, self.op, "syscall");
    }

    pub fn unknown(self: Instruction) bool {
        return self.op.len == 0 or self.op[0] == '(' or self.op[0] == '<' or self.op[0] == '.';
    }

    pub fn indirect(self: Instruction) bool {
        return std.mem.startsWith(u8, self.operands, "*");
    }

    pub fn target(self: Instruction) !u64 {
        if (!self.isBranch() or self.indirect()) return error.UnresolvedEdge;
        var tokens = std.mem.tokenizeAny(u8, self.operands, " \t");
        const address = hex(tokens.next() orelse return error.UnresolvedEdge) catch return error.UnresolvedEdge;
        if (tokens.next()) |label| {
            if (label.len < 3 or label[0] != '<' or label[label.len - 1] != '>') return error.UnresolvedEdge;
        }
        return address;
    }

    pub fn reference(self: Instruction) ?u64 {
        if (!std.mem.startsWith(u8, self.op, "mov") and !std.mem.startsWith(u8, self.op, "lea")) return null;
        if (self.annotated_reference) |value| return value;
        if (std.mem.indexOfScalar(u8, self.operands, '#')) |comment| {
            var tokens = std.mem.tokenizeAny(u8, self.operands[comment + 1 ..], " \t");
            if (tokens.next()) |address| return hex(address) catch null;
        }
        var operands = std.mem.splitScalar(u8, self.operands, ',');
        return immediate(std.mem.trim(u8, operands.first(), " \t"));
    }
};

pub const Function = struct {
    address: u64,
    name: []const u8,
    first: usize,
    count: usize = 0,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    functions: std.ArrayList(Function) = .empty,
    instructions: std.ArrayList(Instruction) = .empty,
    function_index: std.AutoHashMap(u64, usize),
    instruction_index: std.AutoHashMap(u64, usize),

    pub fn parse(allocator: std.mem.Allocator, text: []const u8) !Program {
        if (text.len == 0 or text[text.len - 1] != '\n' or std.mem.indexOfScalar(u8, text, 0) != null)
            return error.MalformedDisassembly;
        var result: Program = .{
            .allocator = allocator,
            .function_index = .init(allocator),
            .instruction_index = .init(allocator),
        };
        errdefer result.deinit();
        var current: ?usize = null;
        var saw_format = false;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "#")) {
                if (current == null or result.instructions.items.len == 0) return error.MalformedDisassembly;
                var comment = std.mem.tokenizeAny(u8, line[1..], " \t");
                result.instructions.items[result.instructions.items.len - 1].annotated_reference =
                    hex(comment.next() orelse return error.MalformedDisassembly) catch return error.MalformedDisassembly;
                continue;
            }
            if (std.mem.indexOf(u8, line, "file format ")) |offset| {
                if (!std.mem.eql(u8, line[offset + "file format ".len ..], "elf64-x86-64"))
                    return error.UnsupportedDisassemblyArchitecture;
                if (saw_format) return error.MalformedDisassembly;
                saw_format = true;
                continue;
            }
            if (std.mem.startsWith(u8, line, "Disassembly of section ") and line[line.len - 1] == ':') {
                current = null;
                continue;
            }
            if (std.mem.endsWith(u8, line, ">:")) {
                const marker = std.mem.indexOf(u8, line, " <") orelse return error.MalformedDisassembly;
                const address = hex(line[0..marker]) catch return error.MalformedDisassembly;
                const name = line[marker + 2 .. line.len - 2];
                if (name.len == 0) return error.MalformedDisassembly;
                if (result.function_index.get(address)) |index| {
                    if (result.functions.items[index].count != 0) return error.DuplicateDisassembly;
                    result.functions.items[index].name = name;
                    current = index;
                } else {
                    current = result.functions.items.len;
                    try result.function_index.put(address, current.?);
                    try result.functions.append(allocator, .{ .address = address, .name = name, .first = result.instructions.items.len });
                }
                continue;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedDisassembly;
            const address = hex(line[0..colon]) catch return error.MalformedDisassembly;
            const owner = current orelse return error.MalformedDisassembly;
            var instruction: Instruction = .{ .address = address, .op = "" };
            var tokens = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t");
            var opcode: ?[]const u8 = null;
            while (tokens.next()) |token| {
                if (token.len == 2 and std.ascii.isHex(token[0]) and std.ascii.isHex(token[1])) {
                    if (instruction.size == 15) return error.MalformedDisassembly;
                    instruction.bytes[instruction.size] = @intCast(try hex(token));
                    instruction.size += 1;
                } else {
                    opcode = token;
                    break;
                }
            }
            if (instruction.size == 0) return error.MalformedDisassembly;
            if (opcode == null) {
                if (result.functions.items[owner].count == 0) return error.MalformedDisassembly;
                const previous = &result.instructions.items[result.instructions.items.len - 1];
                if (previous.size < 7 or instruction.size > 15 - previous.size or
                    address != std.math.add(u64, previous.address, previous.size) catch return error.MalformedDisassembly)
                    return error.MalformedDisassembly;
                @memcpy(previous.bytes[previous.size..][0..instruction.size], instruction.bytes[0..instruction.size]);
                previous.size += instruction.size;
                continue;
            }
            while (opcode) |op| {
                if (!isPrefix(op)) break;
                opcode = tokens.next();
            }
            instruction.op = opcode orelse ".prefix";
            instruction.operands = std.mem.trim(u8, tokens.rest(), " \t");
            const function = &result.functions.items[owner];
            if (function.count != 0) {
                const previous = &result.instructions.items[result.instructions.items.len - 1];
                // LLVM can print LOCK separately from its integer RMW opcode.
                if (previous.size == 1 and previous.bytes[0] == 0xf0 and std.mem.eql(u8, previous.op, ".prefix") and
                    address == previous.address + 1 and instruction.size < 15 and lockable(instruction))
                {
                    @memcpy(previous.bytes[1..][0..instruction.size], instruction.bytes[0..instruction.size]);
                    previous.size += instruction.size;
                    previous.op = instruction.op;
                    previous.operands = instruction.operands;
                    previous.annotated_reference = instruction.annotated_reference;
                    continue;
                }
            }
            if (function.count == 0 and address != function.address) return error.IncompleteDisassembly;
            if (function.count != 0) {
                const previous = result.instructions.items[result.instructions.items.len - 1];
                if (address != std.math.add(u64, previous.address, previous.size) catch return error.MalformedDisassembly)
                    return error.IncompleteDisassembly;
            }
            const entry = try result.instruction_index.getOrPut(address);
            if (entry.found_existing) return error.DuplicateDisassembly;
            entry.value_ptr.* = result.instructions.items.len;
            try result.instructions.append(allocator, instruction);
            function.count += 1;
        }
        if (!saw_format or result.instructions.items.len == 0) return error.MalformedDisassembly;
        return result;
    }

    pub fn deinit(self: *Program) void {
        self.functions.deinit(self.allocator);
        self.instructions.deinit(self.allocator);
        self.function_index.deinit();
        self.instruction_index.deinit();
    }

    pub fn body(self: Program, address: u64) ![]const Instruction {
        const index = self.function_index.get(address) orelse return error.MissingDisassembly;
        const function = self.functions.items[index];
        if (function.count == 0) return error.MissingDisassembly;
        return self.instructions.items[function.first..][0..function.count];
    }
};

fn lockable(instruction: Instruction) bool {
    const operands = splitOperands(instruction);
    const destination = if (operands) |parts| parts[1] else instruction.operands;
    if (std.mem.indexOfScalar(u8, destination, '(') == null) return false;
    for ([_][]const u8{ "add", "adc", "and", "btc", "btr", "bts", "cmpxchg", "dec", "inc", "neg", "not", "or", "sbb", "sub", "xadd", "xchg", "xor" }) |op|
        if (std.mem.startsWith(u8, instruction.op, op)) return true;
    return false;
}

pub fn splitOperands(instruction: Instruction) ?[2][]const u8 {
    const operands = Operands.parse(instruction) catch return null;
    if (operands.len != 2) return null;
    return .{ operands.items[0], operands.items[1] };
}

pub const Operands = struct {
    items: [4][]const u8 = @splat(""),
    len: usize = 0,

    pub fn parse(instruction: Instruction) !Operands {
        const text = instruction.operands[0 .. std.mem.indexOfScalar(u8, instruction.operands, '#') orelse instruction.operands.len];
        var result: Operands = .{};
        if (std.mem.trim(u8, text, " \t").len == 0) return result;
        var depth: usize = 0;
        var start: usize = 0;
        for (text, 0..) |c, i| {
            if (c == '(') depth += 1;
            if (c == ')') {
                if (depth == 0) return error.MalformedOperands;
                depth -= 1;
            }
            if (c == ',' and depth == 0) {
                try result.append(text[start..i]);
                start = i + 1;
            }
        }
        if (depth != 0) return error.MalformedOperands;
        try result.append(text[start..]);
        return result;
    }
    fn append(self: *Operands, text: []const u8) !void {
        if (self.len == self.items.len) return error.UnsupportedOperandCount;
        const item = std.mem.trim(u8, text, " \t");
        if (item.len == 0) return error.MalformedOperands;
        self.items[self.len] = item;
        self.len += 1;
    }
};

fn isPrefix(op: []const u8) bool {
    for ([_][]const u8{ "lock", "rep", "repz", "repe", "repne", "repnz", "bnd", "notrack", "data16", "addr32", "cs", "ds", "es", "ss", "fs", "gs" }) |prefix|
        if (std.mem.eql(u8, op, prefix)) return true;
    return std.mem.startsWith(u8, op, "rex");
}

pub fn hex(text: []const u8) !u64 {
    const digits = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    if (digits.len == 0 or digits.len > 16) return error.InvalidHex;
    for (digits) |c| if (!std.ascii.isHex(c)) return error.InvalidHex;
    return std.fmt.parseInt(u64, digits, 16);
}

pub fn immediate(operand: []const u8) ?u64 {
    if (operand.len < 2 or operand[0] != '$') return null;
    const value = std.mem.trim(u8, operand[1..], " \t");
    if (value.len != 0 and value[0] == '-')
        return @bitCast(std.fmt.parseInt(i64, value, 0) catch return null);
    return std.fmt.parseInt(u64, value, 0) catch null;
}

pub fn register(operand: []const u8) ?u4 {
    const value = std.mem.trim(u8, operand, " \t");
    for ([_][]const u8{ "%al", "%cl", "%dl", "%bl", "%spl", "%bpl", "%sil", "%dil", "%r8b", "%r9b", "%r10b", "%r11b", "%r12b", "%r13b", "%r14b", "%r15b" }, 0..) |name, index|
        if (std.mem.eql(u8, value, name)) return @intCast(index);
    for ([_][]const u8{ "%ah", "%ch", "%dh", "%bh" }, 0..) |name, index|
        if (std.mem.eql(u8, value, name)) return @intCast(index);
    const names = [_][3][]const u8{
        .{ "%rax", "%eax", "%ax" },    .{ "%rcx", "%ecx", "%cx" },
        .{ "%rdx", "%edx", "%dx" },    .{ "%rbx", "%ebx", "%bx" },
        .{ "%rsp", "%esp", "%sp" },    .{ "%rbp", "%ebp", "%bp" },
        .{ "%rsi", "%esi", "%si" },    .{ "%rdi", "%edi", "%di" },
        .{ "%r8", "%r8d", "%r8w" },    .{ "%r9", "%r9d", "%r9w" },
        .{ "%r10", "%r10d", "%r10w" }, .{ "%r11", "%r11d", "%r11w" },
        .{ "%r12", "%r12d", "%r12w" }, .{ "%r13", "%r13d", "%r13w" },
        .{ "%r14", "%r14d", "%r14w" }, .{ "%r15", "%r15d", "%r15w" },
    };
    for (names, 0..) |aliases, index| for (aliases) |name| {
        if (std.mem.eql(u8, value, name)) return @intCast(index);
    };
    return null;
}

pub fn registerWidth(operand: []const u8) ?u8 {
    const index = register(operand) orelse return null;
    const value = std.mem.trim(u8, operand, " \t");
    if (index < 8) {
        if (value.len == 4 and value[1] == 'r') return 64;
        if (value.len == 4 and value[1] == 'e') return 32;
        if (std.mem.endsWith(u8, value, "l") or std.mem.endsWith(u8, value, "h")) return 8;
        return 16;
    }
    return switch (value[value.len - 1]) {
        'b' => 8,
        'w' => 16,
        'd' => 32,
        else => 64,
    };
}

test "NM refuses malformed truncated empty and ambiguous-format tool output" {
    for ([_][]const u8{ "", "0000 T fn", "garbage\n", "0000 TT fn\n", "0000 T\n", "xyz T fn\n" }) |text|
        try std.testing.expectError(error.MalformedNmOutput, Symbols.parse(std.testing.allocator, text));
    var symbols = try Symbols.parse(std.testing.allocator, "000010 T hook\n000011 t hook\n                 U optional\n");
    defer symbols.deinit();
    try std.testing.expectEqual(2, symbols.entries.get("hook").?.items.len);
}

test "objdump parses bytes prefixes symbol aliases and local branch addresses" {
    var program = try Program.parse(std.testing.allocator, "image: file format elf64-x86-64\nDisassembly of section .text:\n" ++
        "000010 <alias>:\n000010 <entry>:\n  10: f3 c3 rep retq\n" ++
        "000012 <tail>:\n  12: eb fc jmp 0x10 <alias>\n");
    defer program.deinit();
    try std.testing.expectEqualStrings("retq", (try program.body(0x10))[0].op);
    try std.testing.expectEqual(0x10, try (try program.body(0x12))[0].target());
    try std.testing.expect((try program.body(0x10))[0].isBarrier());
}

test "objdump rejects omitted bytes gaps duplicate instructions and bad architecture" {
    const prefix = "image: file format elf64-x86-64\n10 <entry>:\n";
    inline for ([_][]const u8{ " 10: retq\n", " 10: c3\n", " ...\n", " 10: c3 retq" }) |bad|
        try std.testing.expectError(error.MalformedDisassembly, Program.parse(std.testing.allocator, prefix ++ bad));
    try std.testing.expectError(error.IncompleteDisassembly, Program.parse(std.testing.allocator, prefix ++ " 11: c3 retq\n"));
    try std.testing.expectError(error.IncompleteDisassembly, Program.parse(std.testing.allocator, prefix ++ " 10: 90 nop\n 12: c3 retq\n"));
    try std.testing.expectError(error.UnsupportedDisassemblyArchitecture, Program.parse(std.testing.allocator, "image: file format elf64-littleaarch64\n"));
}
