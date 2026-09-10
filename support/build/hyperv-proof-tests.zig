// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const proofs = @import("hyperv-image-proofs.zig");
const assembly = @import("hyperv-proof-disasm.zig");
const Instruction = assembly.Instruction;

fn instruction(op: []const u8, operands: []const u8) Instruction {
    return .{ .address = 0, .op = op, .operands = operands };
}

fn controls() [8]Instruction {
    return .{
        instruction("movl", "$0x20, %eax"),
        instruction("movq", "%rax, %cr4"),
        instruction("xorl", "%edx, %edx"),
        instruction("movl", "$0x900, %eax"),
        instruction("movl", "$0xc0000080, %ecx"),
        instruction("wrmsr", ""),
        instruction("movl", "$0x80010001, %eax"),
        instruction("movq", "%rax, %cr0"),
    };
}

test "IRQ register and implicit state families include x87 MMX SSE AVX mask and tile state" {
    for ([_][]const u8{ "%xmm0", "%xmm31", "%ymm15", "%zmm31", "%mm7", "%st", "%st(0)", "%st(7)", "%k0", "%k7", "%tmm0" }) |reg| {
        try std.testing.expect(proofs.forbiddenRegisters(instruction("movq", reg)));
    }
    for ([_][]const u8{ "fadd", "fldz", "fninit", "fwait", "fxsave64", "frstor", "vzeroupper", "vzeroall", "emms", "ldmxcsr", "stmxcsr", "xsave", "xsavec", "xsaves64", "xrstors64", "kmovq", "kandw", "korw", "kxorq", "knotw", "kshiftlw", "ktestw", "kunpckbw" }) |op| {
        try std.testing.expect(proofs.forbiddenRegisters(instruction(op, "")));
    }
    for ([_][]const u8{ "%rax", "%eax", "%r15", "%cr0", "%cr4", "%fs", "%xmm_no", "%k80", "symbol_xmm0" }) |reg| {
        try std.testing.expect(!proofs.forbiddenRegisters(instruction("movq", reg)));
    }
}

test "terminal logs are exempt only with straight-line UD2 and no returning edge" {
    try std.testing.expect(proofs.terminalAssertion(&.{
        instruction("callq", "0x10 <_uk_printk>"), instruction("nop", ""), instruction("ud2", ""),
    }, 0));
    for ([_][]const u8{ "jmp", "jne", "callq", "retq", "loop", "loopne", "iretq" }) |op| {
        try std.testing.expect(!proofs.terminalAssertion(&.{
            instruction("callq", "0x10 <_uk_printk>"), instruction(op, ""), instruction("ud2", ""),
        }, 0));
    }
    try std.testing.expect(!proofs.terminalAssertion(&.{instruction("call", "0x10 <_uk_printk>")}, 0));
}

test "AP paging preserves every legacy required control and rejects clobbering" {
    const good = controls();
    try proofs.pagingControls(&good);
    const mutations = [_]struct { index: usize, replacement: Instruction, err: anyerror }{
        .{ .index = 0, .replacement = instruction("movl", "$0, %eax"), .err = error.MissingCr4Pae },
        .{ .index = 1, .replacement = instruction("movq", "%rbx, %cr4"), .err = error.OverwrittenPagingControl },
        .{ .index = 2, .replacement = instruction("movl", "$1, %edx"), .err = error.MissingEferNxeLme },
        .{ .index = 3, .replacement = instruction("movl", "$0x100, %eax"), .err = error.MissingEferNxeLme },
        .{ .index = 3, .replacement = instruction("movl", "$0x800, %eax"), .err = error.MissingEferNxeLme },
        .{ .index = 4, .replacement = instruction("movl", "$0xc0000081, %ecx"), .err = error.MissingEferNxeLme },
        .{ .index = 6, .replacement = instruction("movl", "$0x80000001, %eax"), .err = error.MissingCr0PeWpPg },
        .{ .index = 6, .replacement = instruction("movl", "$0x10001, %eax"), .err = error.MissingCr0PeWpPg },
        .{ .index = 6, .replacement = instruction("movl", "$0x80010000, %eax"), .err = error.MissingCr0PeWpPg },
    };
    for (mutations) |mutation| {
        var changed = good;
        changed[mutation.index] = mutation.replacement;
        try std.testing.expectError(mutation.err, proofs.pagingControls(&changed));
    }
}

test "callback bindings require actual full-width stores and track register clobbers" {
    const materialize = instruction("leaq", "0x10(%rip), %rdi # 0x1234 <callback>");
    const store = instruction("movq", "%rdi, 0x10(%rax)");
    try std.testing.expect(proofs.callbackStored(&.{ materialize, store }, 0x1234, true));
    try std.testing.expect(proofs.callbackStored(&.{instruction("movq", "$0x1234, 0x10(%rax)")}, 0x1234, false));
    try std.testing.expect(!proofs.callbackStored(&.{instruction("movq", "$0x1234, 0x10(%rax)")}, 0x1234, true));
    try std.testing.expect(!proofs.callbackStored(&.{ materialize, instruction("retq", "") }, 0x1234, true));
    try std.testing.expect(!proofs.callbackStored(&.{ materialize, instruction("movl", "%edi, 0x10(%rax)") }, 0x1234, true));
    for ([_]Instruction{
        instruction("movb", "$0, %dil"),         instruction("incq", "%rdi"),
        instruction("popq", "%rdi"),             instruction("xchgq", "%rdi, %rax"),
        instruction("xaddq", "%rdi, %rax"),      instruction("movw", "$0, %di"),
        instruction("callq", "0x10 <clobber>"),  instruction("jne", "0x10 <join>"),
        instruction("cmpxchgq", "%rdi, (%rbx)"), instruction("movsq", "(%rsi), (%rdi)"),
        instruction("unmodeled", ""),            instruction("cpuid", ""),
        instruction("popcntq", "%rax, %rdi"),
    }) |clobber| {
        try std.testing.expect(!proofs.callbackStored(&.{ materialize, clobber, store }, 0x1234, true));
    }
    try std.testing.expect(proofs.callbackStored(&.{
        materialize,                          instruction("movq", "%rdi, %r12"),
        instruction("callq", "0x10 <other>"), instruction("movq", "%r12, 0x10(%rax)"),
    }, 0x1234, true));
    const narrow = [_]Instruction{ materialize, instruction("movl", "%edi, %edi"), store };
    try std.testing.expect(proofs.callbackStored(&narrow, 0x1234, false));
    try std.testing.expect(!proofs.callbackStored(&narrow, 0x1234, true));
    var values: [16]?u64 = @splat(null);
    proofs.updateRegisters(&values, instruction("movabsq", "$0xffffffffffffffff, %rax"));
    try std.testing.expectEqual(std.math.maxInt(u64), values[0]);
    proofs.updateRegisters(&values, instruction("movl", "%eax, %edi"));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u32)), values[7]);
    proofs.updateRegisters(&values, instruction("divq", "%r12"));
    try std.testing.expect(values[0] == null);
    try std.testing.expectEqual(std.math.maxInt(u64), assembly.immediate("$-1"));
}

test "AP controls reject legacy EDX and AND clobbers and retain harmless post-enable decoding" {
    const good = controls();
    for ([_]struct { index: usize, inserted: Instruction }{
        .{ .index = 3, .inserted = instruction("movl", "$1, %edx") },
        .{ .index = 4, .inserted = instruction("andl", "$0xfffff7ff, %eax") },
    }) |mutation| {
        var changed: std.ArrayList(Instruction) = .empty;
        defer changed.deinit(std.testing.allocator);
        try changed.appendSlice(std.testing.allocator, good[0..mutation.index]);
        try changed.append(std.testing.allocator, mutation.inserted);
        try changed.appendSlice(std.testing.allocator, good[mutation.index..]);
        try std.testing.expectError(error.MissingEferNxeLme, proofs.pagingControls(changed.items));
    }
    const after = good ++ [_]Instruction{instruction("(bad)", "")};
    try proofs.pagingControls(&after);
    const before = [_]Instruction{instruction("(bad)", "")} ++ good;
    try std.testing.expectError(error.UnreviewedPagingControlFlow, proofs.pagingControls(&before));
    const order = good[6..8].* ++ good[0..6].*;
    try std.testing.expectError(error.UnreviewedPagingControlFlow, proofs.pagingControls(&order));
}

test "native disassembly supports LLVM continuation annotations and GNU wrapped bytes" {
    var program = try assembly.Program.parse(std.testing.allocator, "image: file format elf64-x86-64\n10 <entry>:\n" ++
        " 10: 48 c7 05 00 00 00 00 34 12 00 00 movq $0x1234, 0x0(%rip) # imm = 0x1234\n" ++
        " # 0x1b\n" ++
        " 1b: 66 66 66 66 66 66 2e data16 cs nopw 0x0(%rax,%rax,1)\n" ++
        " 22: 0f 1f 84 00 00 00 00 00\n" ++
        " 2a: f3 c3 rep retq\n");
    defer program.deinit();
    const body = try program.body(0x10);
    try std.testing.expectEqual(3, body.len);
    try std.testing.expectEqual(15, body[1].size);
    try std.testing.expectEqual(0x1b, body[0].reference());
    try std.testing.expectEqualStrings("nopw", body[1].op);
    try std.testing.expect(body[2].isBarrier());
}
test "AP controls reject inserted branches clobbers missing and duplicate writes" {
    const good = controls();
    for ([_]usize{ 0, 1, 3, 4, 5, 7 }) |position| {
        var changed: std.ArrayList(Instruction) = .empty;
        defer changed.deinit(std.testing.allocator);
        try changed.appendSlice(std.testing.allocator, good[0..position]);
        try changed.append(std.testing.allocator, if (position == 0) instruction("jmp", "0x10 <skip>") else instruction("xorl", "%eax, %eax"));
        try changed.appendSlice(std.testing.allocator, good[position..]);
        try std.testing.expectError(
            if (position == 0) error.UnreviewedPagingControlFlow else if (position == 1) error.MissingCr4Pae else if (position == 7) error.MissingCr0PeWpPg else error.MissingEferNxeLme,
            proofs.pagingControls(changed.items),
        );
    }
    try std.testing.expectError(error.MissingEferNxeLme, proofs.pagingControls(&.{}));
    var repeated = good ++ [_]Instruction{instruction("wrmsr", "")};
    try std.testing.expectError(error.MissingEferNxeLme, proofs.pagingControls(&repeated));
    repeated = good ++ [_]Instruction{instruction("movq", "%rax, %cr0")};
    try std.testing.expectError(error.OverwrittenPagingControl, proofs.pagingControls(&repeated));
}
