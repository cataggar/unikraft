// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const assembly = @import("hyperv-proof-disasm.zig");

pub fn sized(op: []const u8, base: []const u8) bool {
    return std.mem.eql(u8, op, base) or (op.len == base.len + 1 and
        std.mem.startsWith(u8, op, base) and std.mem.indexOfScalar(u8, "bwlq", op[op.len - 1]) != null);
}

pub fn vectorBytes(operand: []const u8) ?u8 {
    const text = std.mem.trim(u8, operand[0 .. std.mem.indexOfScalar(u8, operand, '{') orelse operand.len], " \t");
    for ([_][]const u8{ "%xmm", "%ymm", "%zmm" }, [_]u8{ 16, 32, 64 }) |prefix, width| {
        if (!std.mem.startsWith(u8, text, prefix)) continue;
        const index = std.fmt.parseInt(u8, text[prefix.len..], 10) catch return null;
        return if (index < 32) width else null;
    }
    return null;
}

pub fn vectorIndex(operand: []const u8) ?u5 {
    _ = vectorBytes(operand) orelse return null;
    const end = std.mem.indexOfScalar(u8, operand, '{') orelse operand.len;
    return std.fmt.parseInt(u5, std.mem.trim(u8, operand[4..end], " \t"), 10) catch null;
}

pub fn vectorMove(op: []const u8) bool {
    const name = if (std.mem.startsWith(u8, op, "v")) op[1..] else op;
    for ([_][]const u8{ "movups", "movupd", "movaps", "movapd", "movdqa", "movdqu", "movdqa32", "movdqa64", "movdqu8", "movdqu16", "movdqu32", "movdqu64", "movntps", "movntpd", "movntdq", "movss", "movsd" }) |item|
        if (std.mem.eql(u8, name, item)) return true;
    return false;
}

pub fn writeBytes(instruction: assembly.Instruction, source_operand: []const u8) !u8 {
    const op = instruction.op;
    if (vectorMove(op)) {
        if (std.mem.endsWith(u8, op, "ss")) return 4;
        if (std.mem.endsWith(u8, op, "sd")) return 8;
        return vectorBytes(source_operand) orelse error.UnsupportedMemoryWidth;
    }
    if (std.mem.eql(u8, op, "cmpxchg16b")) return 16;
    if (std.mem.eql(u8, op, "cmpxchg8b")) return 8;
    if (std.mem.eql(u8, op, "mov") or std.mem.eql(u8, op, "movabs"))
        return if (assembly.registerWidth(source_operand)) |bits| bits / 8 else error.UnsupportedMemoryWidth;
    if (op.len == 0) return error.UnsupportedMemoryWidth;
    return switch (op[op.len - 1]) {
        'b' => 1,
        'w' => 2,
        'l' => 4,
        'q' => 8,
        else => error.UnsupportedMemoryWidth,
    };
}

pub fn vectorArithmetic(op: []const u8) bool {
    const name = if (std.mem.startsWith(u8, op, "v")) op[1..] else op;
    for ([_][]const u8{ "xorps", "xorpd", "pxor", "pxord", "pxorq" }) |item|
        if (std.mem.eql(u8, name, item)) return true;
    return false;
}

pub fn binary(op: []const u8) bool {
    for ([_][]const u8{ "mov", "movabs", "lea", "add", "adc", "sub", "sbb", "and", "or", "xor", "sal", "sar", "shl", "shr", "rol", "ror", "rcl", "rcr", "xchg", "xadd", "cmpxchg", "imul", "bsf", "bsr", "bswap", "popcnt", "tzcnt", "lzcnt", "bt", "btc", "btr", "bts" }) |base|
        if (sized(op, base)) return true;
    for ([_][]const u8{ "movzbl", "movzbq", "movzbw", "movzwl", "movzwq", "movsbw", "movsbl", "movsbq", "movswl", "movswq", "movslq" }) |name|
        if (std.mem.eql(u8, name, op)) return true;
    return condition(op, "cmov") != null;
}

pub fn condition(op: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, op, prefix)) return null;
    const suffix = op[prefix.len..];
    for ([_][]const u8{ "a", "ae", "b", "be", "c", "e", "g", "ge", "l", "le", "na", "nae", "nb", "nbe", "nc", "ne", "ng", "nge", "nl", "nle", "no", "np", "ns", "nz", "o", "p", "pe", "po", "s", "z" }) |code| {
        if (std.mem.eql(u8, suffix, code)) return code;
        if (std.mem.eql(u8, prefix, "cmov") and suffix.len == code.len + 1 and
            std.mem.startsWith(u8, suffix, code) and std.mem.indexOfScalar(u8, "wlq", suffix[suffix.len - 1]) != null) return code;
    }
    return null;
}

pub fn readBits(instruction: assembly.Instruction) u8 {
    const op = instruction.op;
    if (std.mem.startsWith(u8, op, "movz") or std.mem.startsWith(u8, op, "movs")) {
        if (op.len > 4) return if (op[4] == 'b') 8 else if (op[4] == 'w') 16 else if (op[4] == 'l') 32 else 64;
    }
    if (op.len == 0) return 64;
    return switch (op[op.len - 1]) {
        'b' => 8,
        'w' => 16,
        'l' => 32,
        else => 64,
    };
}
