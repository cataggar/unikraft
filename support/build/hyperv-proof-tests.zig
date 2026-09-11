// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const proofs = @import("hyperv-image-proofs.zig");
const assembly = @import("hyperv-proof-disasm.zig");
const Instruction = assembly.Instruction;
const flow = @import("hyperv-proof-flow.zig");

const Trace = struct {
    instructions: []Instruction,
    analysis: flow.Analysis,
    fn deinit(self: *Trace) void {
        self.analysis.deinit();
        std.testing.allocator.free(self.instructions);
    }
};

fn trace(ops: []const Instruction, initial: flow.State, slot: flow.Slot) !Trace {
    const instructions = try std.testing.allocator.alloc(Instruction, ops.len + 1);
    errdefer std.testing.allocator.free(instructions);
    @memcpy(instructions[0..ops.len], ops);
    instructions[ops.len] = instruction("retq", "");
    for (instructions, 0..) |*item, i| {
        item.address = i + 1;
        item.size = 1;
    }
    return .{ .instructions = instructions, .analysis = try flow.Analysis.run(std.testing.allocator, instructions, initial, .{ .slot = slot }) };
}

fn stored(ops: []const Instruction, pie: bool) !bool {
    var initial = flow.State.entry(1);
    initial.regs[3] = .{ .kind = .result, .id = 123 };
    var result = try trace(ops, initial, .{ .field = 16 });
    defer result.deinit();
    const last = ops.len - 1;
    return result.analysis.seen[last] and result.analysis.after[last].get(initial.regs[3].plus(16)).addressIs(0x1234, pie);
}

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

test "review regression high-byte reads cannot borrow the low byte" {
    var state = flow.State.entry(1);
    state.regs[0] = .{ .kind = .integer, .id = 0x100 };
    const value = flow.source(state, instruction("testb", "%ah, %ah"), "%ah");
    try std.testing.expect(value.kind == .unknown or
        (value.kind == .integer and value.id == 1 and value.upper == null));
}

test "review regression masked stack stores cannot retain old pointer facts" {
    var state = flow.State.entry(1);
    const location = state.regs[4].plus(16);
    try state.store(location, .{ .kind = .address, .id = 0x1234 }, 8, .none);
    flow.step(&state, instruction("vmovdqu64", "%zmm0, 16(%rsp) {%k1}"), .{}) catch |err| switch (err) {
        error.UnsupportedProvenanceInstruction, error.UnsupportedMemoryWidth => return,
        else => return err,
    };
    try std.testing.expect(state.get(location).kind == .unknown);
}

test "review regression narrowed stack aliases cannot preserve overwritten facts" {
    var state = flow.State.entry(1);
    const location = state.regs[4].plus(16);
    try state.store(location, .{ .kind = .address, .id = 0x1234 }, 8, .none);
    for ([_]Instruction{
        instruction("leaq", "16(%rsp), %rax"),
        instruction("movl", "%eax, %eax"),
        instruction("movq", "$0, (%rax)"),
    }) |op| {
        flow.step(&state, op, .{}) catch |err| switch (err) {
            error.UnsupportedProvenanceInstruction, error.UnprovenMemoryFootprint => return,
            else => return err,
        };
    }
    try std.testing.expect(state.get(location).kind == .unknown);
}

test "own stack narrowing refuses copies extensions partial writes and vector transfers" {
    for ([_]Instruction{
        instruction("movl", "%eax, %eax"),
        instruction("movl", "%eax, %ecx"),
        instruction("movw", "%ax, %cx"),
        instruction("movb", "%al, %cl"),
        instruction("movb", "%ah, %cl"),
        instruction("movzbl", "%al, %ecx"),
        instruction("movzbq", "%ah, %rcx"),
        instruction("movzwl", "%ax, %ecx"),
        instruction("movzwq", "%ax, %rcx"),
        instruction("movslq", "%eax, %rcx"),
        instruction("movsbq", "%al, %rcx"),
        instruction("movl", "%esp, %ecx"),
        instruction("leal", "16(%rsp), %ecx"),
        instruction("movl", "%eax, 32(%rsp)"),
        instruction("movb", "$1, %al"),
        instruction("movw", "$1, %ax"),
        instruction("movb", "$1, %ah"),
        instruction("movq", "%rax, %xmm0"),
    }) |op| {
        var state = flow.State.entry(1);
        state.regs[0] = state.regs[4].plus(16);
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, op, .{}));
    }
}

test "own stack unsupported arithmetic and implicit writes cannot discard aliases" {
    for ([_]Instruction{
        instruction("andq", "$0xffffffff, %rax"),
        instruction("orq", "$0, %rax"),
        instruction("shrq", "$0, %rax"),
        instruction("addl", "$0, %eax"),
        instruction("imulq", "$2, %rax, %rcx"),
        instruction("imull", "$1, %eax, %ecx"),
        instruction("imulq", "%rcx, %rax"),
        instruction("mulq", "%rcx"),
        instruction("idivq", "%rcx"),
        instruction("mulxq", "%rax, %rcx, %rsi"),
        instruction("xchgq", "%rax, %rcx"),
        instruction("xaddq", "%rax, %rcx"),
        instruction("cmpxchgq", "%rcx, 32(%rsp)"),
        instruction("cmpxchg16b", "32(%rsp)"),
        instruction("incq", "%rax"),
        instruction("negq", "%rax"),
        instruction("notq", "%rax"),
        instruction("bswapq", "%rax"),
        instruction("sete", "%al"),
        instruction("cltd", ""),
    }) |op| {
        var state = flow.State.entry(1);
        state.regs[0] = state.regs[4].plus(16);
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, op, .{}));
    }
    var state = flow.State.entry(1);
    state.regs[2] = state.regs[4].plus(16);
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("cwtd", ""), .{}));
    state.regs[1] = state.regs[4];
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("loop", "1"), .{}));
}

test "own stack full width aliases offsets spills and independent replacements stay supported" {
    var state = flow.State.entry(1);
    const slot = state.regs[4].plus(16);
    const callback: flow.Value = .{ .kind = .address, .id = 0x1234 };
    try state.store(slot, callback, 8, .none);
    for ([_]Instruction{
        instruction("leaq", "8(%rsp), %rax"),
        instruction("addq", "$16, %rax"),
        instruction("subq", "$8, %rax"),
        instruction("movq", "%rax, 32(%rsp)"),
        instruction("movq", "32(%rsp), %rcx"),
        instruction("imulq", "$1, %rcx, %rax"),
    }) |op| try flow.step(&state, op, .{});
    try std.testing.expect(state.regs[0].samePointer(slot));
    try flow.step(&state, instruction("movq", "$0, (%rax)"), .{});
    try std.testing.expect(!state.get(slot).addressIs(0x1234, true));
    try std.testing.expect(!state.escaped_stack);

    for ([_]Instruction{
        instruction("movl", "$0, %eax"),
        instruction("movq", "$0, %rax"),
        instruction("xorl", "%eax, %eax"),
        instruction("xorq", "%rax, %rax"),
        instruction("imulq", "$0, %rax, %rax"),
    }) |op| {
        state.regs[0] = slot;
        try flow.step(&state, op, .{});
        try std.testing.expect(state.regs[0].isZero());
    }
    state.regs[2] = slot;
    try flow.step(&state, instruction("cmpxchgq", "%rsi, 48(%rsp)"), .{});
    try std.testing.expect(state.regs[2].samePointer(slot));
}

test "own stack spill narrowing and unsupported address reads never yield harmless scalars" {
    var initial = flow.State.entry(1);
    try initial.store(initial.regs[4].plus(32), initial.regs[4].plus(16), 8, .none);
    for ([_]Instruction{
        instruction("movl", "32(%rsp), %ecx"),
        instruction("movl", "33(%rsp), %ecx"),
        instruction("movzbl", "39(%rsp), %ecx"),
        instruction("movzwq", "31(%rsp), %rcx"),
        instruction("movq", "33(%rsp), %rcx"),
        instruction("movzbl", "32(%rsp), %ecx"),
        instruction("movzwq", "32(%rsp), %rcx"),
        instruction("movslq", "32(%rsp), %rcx"),
        instruction("movq", "%ss:32(%rsp), %rcx"),
        instruction("movq", "32(%esp), %rcx"),
        instruction("movq", "32(%rsp,%rdi), %rcx"),
        instruction("leaq", "32(%rsp,%rdi), %rcx"),
    }) |op| {
        var state = initial;
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, op, .{}));
    }
    var state = initial;
    try state.store(state.regs[4].plus(32), .{ .kind = .integer, .id = 0x1234 }, 8, .none);
    try flow.step(&state, instruction("movzwq", "32(%rsp), %rcx"), .{});
    try std.testing.expectEqual(0x1234, state.regs[1].id);
    try std.testing.expect(!state.escaped_stack);
    try flow.step(&state, instruction("movl", "40(%rsp), %esi"), .{});
    try std.testing.expectEqual(.integer, state.regs[6].kind);
    try flow.step(&state, instruction("movl", "64(%rsp), %esi"), .{});
    try std.testing.expectEqual(.integer, state.regs[6].kind);
    try std.testing.expect(!state.escaped_stack);
    try flow.step(&state, instruction("movq", "%gs:16(%rip), %rax"), .{});
    try std.testing.expectEqual(.unknown, state.regs[0].kind);
    try std.testing.expect(!state.escaped_stack);
}

test "own stack slice tests cannot prune branches or conditionally manufacture aliases" {
    const NoCalls = struct {
        fn call(_: ?*anyopaque, _: Instruction, _: flow.State, _: flow.Options) ![]flow.State {
            return error.UnexpectedCall;
        }
    };
    for ([_][]const u8{ "%eax", "%ax", "%al", "%ah" }, [_][]const u8{ "testl", "testw", "testb", "testb" }) |reg, op| {
        var initial = flow.State.entry(1);
        initial.regs[0] = initial.regs[4].plus(16);
        const operands = try std.fmt.allocPrint(std.testing.allocator, "{s}, {s}", .{ reg, reg });
        defer std.testing.allocator.free(operands);
        var result = try trace(&.{
            instruction(op, operands), instruction("je", "4 <zero>"),
            instruction("retq", ""),   instruction("nop", ""),
        }, initial, .none);
        defer result.deinit();
        try std.testing.expect(result.analysis.seen[2] and result.analysis.seen[3]);
    }
    for ([_]bool{ false, true }) |take| {
        var initial = flow.State.entry(1);
        initial.regs[7] = .{ .kind = .integer, .id = @intFromBool(!take) };
        initial.regs[0] = if (take) initial.regs[4].plus(16) else .{ .kind = .integer };
        initial.regs[1] = if (take) .{ .kind = .integer } else initial.regs[4].plus(16);
        const ops = [_]Instruction{
            .{ .address = 1, .size = 1, .op = "testq", .operands = "%rdi, %rdi" },
            .{ .address = 2, .size = 1, .op = "cmovel", .operands = "%eax, %ecx" },
            .{ .address = 3, .size = 1, .op = "retq" },
        };
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, @import("hyperv-proof-paths.zig").run(std.testing.allocator, &ops, initial, .{}, NoCalls.call));
        initial.regs[0] = .{ .kind = .integer, .id = 0x123456789 };
        initial.regs[1] = .{ .kind = .integer, .id = 0xabcdef012 };
        const results = try @import("hyperv-proof-paths.zig").run(std.testing.allocator, &ops, initial, .{}, NoCalls.call);
        defer std.testing.allocator.free(results);
        try std.testing.expectEqual(1, results.len);
        try std.testing.expectEqual(@as(u64, if (take) 0x23456789 else 0xbcdef012), results[0].regs[1].id);
        try std.testing.expectEqual(64, results[0].regs[1].bits);
    }
}

test "own stack origin survives joins offset overflow and indexed address evaluation" {
    for ([_]bool{ false, true }) |reverse| {
        var left = flow.State.entry(1);
        var right = left;
        left.regs[0] = left.regs[4].plus(16);
        right.regs[0] = .{ .kind = .integer, .id = 32 };
        var state = if (reverse) right else left;
        _ = state.merge(if (reverse) left else right);
        const value = state.regs[0];
        try std.testing.expect(!value.samePointer(value));
        try std.testing.expect(!value.isZero());
        try std.testing.expectError(error.UnprovenMemoryFootprint, flow.step(&state, instruction("movq", "$0, (%rax)"), .{}));
        try std.testing.expectError(error.UnprovenMemoryFootprint, flow.step(&state, instruction("movq", "$0, 16(%rsp,%rax)"), .{}));
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("movl", "%eax, %ecx"), .{}));
        state.regs[7] = value;
        try flow.unknownCall(&state, instruction("callq", ""), .{});
        try std.testing.expect(state.escaped_stack);
    }
    var state = flow.State.entry(1);
    state.regs[0] = state.regs[4].plus(std.math.maxInt(i64));
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("addq", "$1, %rax"), .{}));
}

test "own stack memory remnants and incoming only spills retain possible escape" {
    for ([_]bool{ false, true }) |reverse| {
        var state = flow.State.entry(1);
        var incoming = state;
        const slot = state.regs[4].plus(16);
        const spill = state.regs[4].plus(32);
        try incoming.store(spill, slot, 8, .none);
        if (reverse) std.mem.swap(flow.State, &state, &incoming);
        _ = state.merge(incoming);
        flow.step(&state, instruction("movl", "32(%rsp), %eax"), .{}) catch |err| {
            try std.testing.expectEqual(error.UnsupportedProvenanceInstruction, err);
            continue;
        };
        try state.store(slot, .{ .kind = .address, .id = 0x1234 }, 8, .none);
        try flow.step(&state, instruction("movq", "$0, (%rax)"), .{});
        try std.testing.expect(!state.get(slot).addressIs(0x1234, true));
    }
    for ([_]Instruction{
        instruction("movb", "$0, 32(%rsp)"),
        instruction("movb", "$0, 39(%rsp)"),
        instruction("vmovdqu8", "%zmm0, 32(%rsp) {%k1}"),
        instruction("movdqu", "24(%rsp), %xmm0"),
    }) |op| {
        var state = flow.State.entry(1);
        const slot = state.regs[4].plus(16);
        try state.store(state.regs[4].plus(32), slot, 8, .none);
        try state.store(slot, .{ .kind = .address, .id = 0x1234 }, 8, .none);
        try flow.step(&state, op, .{});
        try std.testing.expect(state.escaped_stack);
        try state.store(.{}, .{}, 8, .none);
        try std.testing.expectEqual(.unknown, state.get(slot).kind);
    }
}

test "own stack conservative escape preserves bounded heap globals and distinct frame slots" {
    var state = flow.State.entry(1);
    const slot = state.regs[4].plus(16);
    const spill = state.regs[4].plus(32);
    const callback: flow.Value = .{ .kind = .address, .id = 0x1234 };
    try state.store(slot, callback, 8, .none);
    try state.store(spill, slot, 8, .none);
    try state.store(spill, .{ .kind = .integer }, 1, .none);
    try std.testing.expect(state.escaped_stack);
    state.globals = &.{.{ .start = 0x2000, .end = 0x2100 }};
    try state.store(.{ .kind = .heap, .id = 9, .size = 128 }, .{}, 64, .none);
    try state.store(.{ .kind = .address, .id = 0x2000 }, .{}, 128, .none);
    try state.store(state.regs[4].plus(64), .{}, 8, .none);
    try std.testing.expect(state.get(slot).addressIs(0x1234, true));
    try flow.unknownCall(&state, instruction("callq", ""), .{});
    try std.testing.expectEqual(.unknown, state.get(slot).kind);
}

test "own stack partial overwrites expose only possible surviving pointer bytes" {
    for ([_]i64{ 24, 25, 31, 32, 33, 39, 40 }) |offset| {
        for ([_]u64{ 1, 4, 8, 16 }) |width| {
            var state = flow.State.entry(1);
            const spill = state.regs[4].plus(32);
            try state.store(spill, state.regs[4].plus(16), 8, .none);
            try state.store(state.regs[4].plus(offset), .{ .kind = .integer }, width, .none);
            const overlap = offset < 40 and offset + @as(i64, @intCast(width)) > 32;
            const covers = offset <= 32 and offset + @as(i64, @intCast(width)) >= 40;
            try std.testing.expectEqual(overlap and !covers, state.escaped_stack);
        }
    }
}

test "high byte aliases read their own slice without inventing unknown bits" {
    const highs = [_][]const u8{ "%ah", "%ch", "%dh", "%bh" };
    const lows = [_][]const u8{ "%al", "%cl", "%dl", "%bl" };
    for (highs, lows, 0..) |high, low, reg| {
        try std.testing.expectEqual(reg, assembly.register(high).?);
        try std.testing.expectEqual(8, assembly.registerBitOffset(high));
        try std.testing.expectEqual(0, assembly.registerBitOffset(low));
        for ([_]u64{ 0x100, 1, 0x1234, 0xff00, 0x8877665544332211 }) |value| {
            var state = flow.State.entry(1);
            state.regs[reg] = .{ .kind = .integer, .id = value };
            try std.testing.expectEqual((value >> 8) & 255, flow.source(state, instruction("movzbl", ""), high).id);
            try std.testing.expectEqual(value & 255, flow.source(state, instruction("movzbl", ""), low).id);
        }
        var state = flow.State.entry(1);
        state.regs[reg] = .{ .kind = .integer, .id = 0x34, .bits = 8 };
        try std.testing.expectEqual(.unknown, flow.source(state, instruction("testb", ""), high).kind);
        state.regs[reg] = .{ .kind = .integer, .id = 0x1234, .bits = 16 };
        try std.testing.expectEqual(0x12, flow.source(state, instruction("testb", ""), high).id);
        state.regs[reg] = .{ .kind = .integer, .upper = 65535 };
        try std.testing.expectEqual(.unknown, flow.source(state, instruction("testb", ""), high).kind);
        state.regs[reg] = .{ .kind = .address, .id = 0x100 };
        try std.testing.expectEqual(.unknown, flow.source(state, instruction("testb", ""), high).kind);
    }
}

test "high byte writes preserve low and upper slices without claiming full knowledge" {
    for ([_][]const u8{ "%ah", "%ch", "%dh", "%bh" }, 0..) |high, reg| {
        const move = try std.fmt.allocPrint(std.testing.allocator, "$0xaa, {s}", .{high});
        defer std.testing.allocator.free(move);
        var state = flow.State.entry(1);
        state.regs[reg] = .{ .kind = .integer, .id = 0x1122334455667788 };
        try flow.step(&state, instruction("movb", move), .{});
        try std.testing.expectEqual(0x112233445566aa88, state.regs[reg].id);
        try std.testing.expectEqual(64, state.regs[reg].bits);
        state.regs[reg] = .{ .kind = .integer, .id = 0x34, .bits = 8 };
        try flow.step(&state, instruction("movb", move), .{});
        try std.testing.expectEqual(0xaa34, state.regs[reg].id);
        try std.testing.expectEqual(16, state.regs[reg].bits);
        try std.testing.expect(!state.regs[reg].isZero());
        state.regs[reg] = .{ .kind = .heap, .id = 9, .size = 128 };
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("movb", move), .{}));
    }
}

test "high byte TEST CMP MOVZX and conditional writes use the correct flags and slices" {
    for ([_][]const u8{ "%ah", "%ch", "%dh", "%bh" }, 0..) |high, reg| {
        for ([_]u64{ 0x100, 1 }) |value| {
            for ([_][]const u8{ "testb", "cmpb" }) |op| {
                const operands = try std.fmt.allocPrint(std.testing.allocator, "{s}, {s}", .{ if (std.mem.eql(u8, op, "testb")) high else "$0", high });
                defer std.testing.allocator.free(operands);
                var initial = flow.State.entry(1);
                initial.regs[reg] = .{ .kind = .integer, .id = value };
                var result = try trace(&.{
                    instruction(op, operands), instruction("je", "4 <zero>"),
                    instruction("retq", ""),   instruction("nop", ""),
                }, initial, .none);
                defer result.deinit();
                try std.testing.expectEqual(value == 1, result.analysis.seen[3]);
                try std.testing.expectEqual(value == 0x100, result.analysis.seen[2]);
            }
            const operands = try std.fmt.allocPrint(std.testing.allocator, "{s}, %esi", .{high});
            defer std.testing.allocator.free(operands);
            var initial = flow.State.entry(1);
            initial.regs[reg] = .{ .kind = .integer, .id = value };
            var result = try trace(&.{instruction("movzbl", operands)}, initial, .none);
            defer result.deinit();
            try std.testing.expectEqual(value >> 8, result.analysis.after[0].regs[6].id);
            try std.testing.expectEqual(64, result.analysis.after[0].regs[6].bits);
        }
        const sign_operands = try std.fmt.allocPrint(std.testing.allocator, "{s}, {s}", .{ high, high });
        defer std.testing.allocator.free(sign_operands);
        var initial = flow.State.entry(1);
        initial.regs[reg] = .{ .kind = .integer, .id = 0x8000 };
        var sign = try trace(&.{
            instruction("testb", sign_operands), instruction("js", "4 <negative>"),
            instruction("retq", ""),             instruction("nop", ""),
        }, initial, .none);
        defer sign.deinit();
        try std.testing.expect(sign.analysis.seen[3]);
        try std.testing.expect(!sign.analysis.seen[2]);
    }
    const NoCalls = struct {
        fn call(_: ?*anyopaque, _: Instruction, _: flow.State, _: flow.Options) ![]flow.State {
            return error.UnexpectedCall;
        }
    };
    var initial = flow.State.entry(1);
    initial.regs[0] = .{ .kind = .integer, .id = 0x12 };
    initial.regs[7] = .{ .kind = .integer };
    const ops = [_]Instruction{
        .{ .address = 1, .size = 1, .op = "testq", .operands = "%rdi, %rdi" },
        .{ .address = 2, .size = 1, .op = "sete", .operands = "%ah" },
        .{ .address = 3, .size = 1, .op = "retq" },
    };
    const results = try @import("hyperv-proof-paths.zig").run(std.testing.allocator, &ops, initial, .{}, NoCalls.call);
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(1, results.len);
    try std.testing.expectEqual(0x112, results[0].regs[0].id);
    for ([_][]const u8{ "%ah", "%ch", "%dh", "%bh" }) |high| {
        var ap = controls();
        const operands = try std.fmt.allocPrint(std.testing.allocator, "$0x20, {s}", .{high});
        defer std.testing.allocator.free(operands);
        ap[0] = instruction("movb", operands);
        try std.testing.expectError(error.MissingCr4Pae, proofs.pagingControls(&ap));
    }
}

test "masked stores invalidate every possible written byte without manufacturing zero or aliases" {
    for ([_][]const u8{ "%xmm0", "%ymm0", "%zmm0" }, [_]i64{ 16, 32, 64 }) |reg, width| {
        for ([_]i64{ 16 - width, 17 - width, 16, 24 }) |offset| {
            var state = flow.State.entry(1);
            const slot = state.regs[4].plus(16);
            const other = state.regs[4].plus(128);
            try state.store(slot, .{ .kind = .address, .id = 0x1234 }, 8, .none);
            try state.store(other, .{ .kind = .integer, .id = 91 }, 8, .none);
            state.vector_zero[0] = 64;
            const operands = try std.fmt.allocPrint(std.testing.allocator, "{s}, {d}(%rsp) {{%k1}}", .{ reg, offset });
            defer std.testing.allocator.free(operands);
            try flow.step(&state, instruction("vmovdqu64", operands), .{});
            const overlaps = offset < 24 and offset + width > 16;
            try std.testing.expectEqual(!overlaps, state.get(slot).addressIs(0x1234, true));
            if (overlaps) try std.testing.expectEqual(.unknown, state.get(slot).kind);
            try std.testing.expectEqual(91, state.get(other).id);
        }
    }
    var state = flow.State.entry(1);
    state.escaped_stack = true;
    state.regs[3] = .{ .kind = .heap, .id = 1, .size = 256 };
    const slot = state.regs[4].plus(16);
    try state.store(slot, .{ .kind = .address, .id = 0x1234 }, 8, .none);
    try flow.step(&state, instruction("vmovdqu64", "%zmm0, 128(%rbx){%k7}"), .{});
    try std.testing.expect(state.get(slot).addressIs(0x1234, true));
}

test "unsupported memory syntax and implicit footprints refuse instead of preserving stack evidence" {
    for ([_][]const u8{
        "%fs:16(%rsp)",    "%gs:16(%rsp)",    "16(%esp)",             "16(%ah)",
        "16(%rsp,%eax,1)", "16(%rsp,%rax,3)", "16(%rsp,%rax,1,%rbx)", "16(%rsp) trailing",
        "16(%rsp) {%k0}",  "16(%rsp) {%k8}",  "16(%rsp) {%k1}{z}",
    }) |destination| {
        var state = flow.State.entry(1);
        try state.store(state.regs[4].plus(16), .{ .kind = .address, .id = 0x1234 }, 8, .none);
        const operands = try std.fmt.allocPrint(std.testing.allocator, "%zmm0, {s}", .{destination});
        defer std.testing.allocator.free(operands);
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("vmovdqu64", operands), .{}));
    }
    for ([_]u8{ 0x67, 0x64, 0x65, 0x2e }) |prefix| {
        var state = flow.State.entry(1);
        var store = instruction("movq", "%rax, 16(%rsp)");
        store.size = 6;
        @memcpy(store.bytes[0..6], &[_]u8{ prefix, 0x48, 0x89, 0x44, 0x24, 0x10 });
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, store, .{}));
    }
    for ([_][]const u8{ "movsq", "stosq" }) |op| {
        var state = flow.State.entry(1);
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction(op, ""), .{}));
    }
    var state = flow.State.entry(1);
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, flow.step(&state, instruction("movq", "%rdi, 16(%rsp,%rax)"), .{}));
}

test "narrow pointer loads and partial scalars cannot supply full ABI values" {
    var initial = flow.State.entry(1);
    initial.regs[3] = .{ .kind = .heap, .id = 1, .size = 128 };
    try initial.store(initial.regs[3].plus(16), .{ .kind = .address, .id = 0x1234 }, 8, .{ .field = 16 });
    for ([_][]const u8{ "movzbq", "movzwq", "movl", "movzbl" }) |op| {
        var result = try trace(&.{instruction(op, if (std.mem.eql(u8, op, "movl") or std.mem.eql(u8, op, "movzbl")) "16(%rbx), %edi" else "16(%rbx), %rdi")}, initial, .{ .field = 16 });
        defer result.deinit();
        try std.testing.expect(!result.analysis.after[0].regs[7].addressIs(0x1234, true));
    }
    initial.regs[2] = .{ .kind = .integer, .bits = 8 };
    try std.testing.expect(!initial.regs[2].isZero());
    try std.testing.expectEqual(.unknown, flow.source(initial, instruction("callq", ""), "%rdx").kind);
    for ([_]Instruction{ instruction("andq", "$0xffff, %rdx"), instruction("addq", "$0, %rdx") }) |arithmetic| {
        var result = try trace(&.{arithmetic}, initial, .none);
        defer result.deinit();
        try std.testing.expect(!result.analysis.after[0].regs[2].isZero());
    }
    initial.regs[0] = .{ .kind = .integer, .id = 0x2000 };
    initial.regs[2] = .{ .kind = .integer, .id = 0x2000, .depth = 1 };
    try std.testing.expectEqual(.unknown, flow.source(initial, instruction("movq", ""), "(%rax)").kind);
    try std.testing.expectEqual(.unknown, flow.source(initial, instruction("callq", ""), "%rdx").kind);
}

test "CMPXCHG does not borrow CMP flags and CALL overwrites reused stack slots" {
    var changed = try trace(&.{
        instruction("movq", "$1, %rax"),     instruction("movq", "$2, %rbx"),
        instruction("movq", "$2, %rcx"),     instruction("cmpxchgq", "%rbx, %rcx"),
        instruction("jne", "7 <reachable>"), instruction("ud2", ""),
        instruction("nop", ""),
    }, flow.State.entry(1), .none);
    defer changed.deinit();
    try std.testing.expect(changed.analysis.seen[6]);
    const initial = flow.State.entry(1);
    var calls = try trace(&.{
        instruction("leaq", "0x1232(%rip), %rdi"), instruction("pushq", "%rdi"),
        instruction("popq", "%rdi"),               instruction("callq", "10 <helper>"),
    }, initial, .none);
    defer calls.deinit();
    try std.testing.expect(calls.analysis.after[3].get(initial.regs[4].plus(-8)).addressIs(5, true));
}

test "list links and merge-masked vector results remain conservative" {
    const cursor: flow.Value = .{ .kind = .scheduler_list, .id = 42, .size = 160, .link = 152 };
    for ([_]flow.Value{ .{}, .{ .kind = .integer, .bits = 8 }, .{ .kind = .address, .id = 0x1234 } }) |bad| {
        var state: flow.State = .{};
        try std.testing.expectError(error.InvalidSchedulerListLink, state.store(cursor.plus(152), bad, 8, .{ .field = 40 }));
    }
    var state: flow.State = .{};
    try std.testing.expectError(error.InvalidSchedulerListLink, state.store(cursor.plus(153), .{ .kind = .integer }, 1, .{ .field = 40 }));
    var masked = try trace(&.{
        instruction("vpxord", "%zmm0, %zmm0, %zmm0 {%k1}"),
        instruction("vmovdqu64", "%zmm0, 16(%rsp)"),
        instruction("movq", "16(%rsp), %rdx"),
    }, flow.State.entry(1), .none);
    defer masked.deinit();
    try std.testing.expect(!masked.analysis.after[2].regs[2].isZero());
}

test "flags are snapshots and multioperand arithmetic cannot retain stale comparisons" {
    var narrow = try trace(&.{
        instruction("movl", "$0xffffffff, %eax"), instruction("cmpl", "$-1, %eax"),
        instruction("je", "5 <taken>"),           instruction("ud2", ""),
        instruction("nop", ""),
    }, .{}, .none);
    defer narrow.deinit();
    try std.testing.expect(narrow.analysis.seen[4]);
    try std.testing.expect(!narrow.analysis.seen[3]);
    var snapshot = try trace(&.{
        instruction("movl", "$2, %eax"), instruction("cmpl", "$1, %eax"),
        instruction("movl", "$0, %eax"), instruction("jne", "6 <taken>"),
        instruction("ud2", ""),          instruction("nop", ""),
    }, .{}, .none);
    defer snapshot.deinit();
    try std.testing.expect(snapshot.analysis.seen[5]);
    try std.testing.expect(!snapshot.analysis.seen[4]);
    var changed_flags = try trace(&.{
        instruction("movl", "$2, %eax"),        instruction("cmpl", "$1, %eax"),
        instruction("imulq", "$0, %rdi, %rdi"), instruction("je", "6 <possible>"),
        instruction("ud2", ""),                 instruction("nop", ""),
    }, .{}, .none);
    defer changed_flags.deinit();
    try std.testing.expect(changed_flags.analysis.seen[5]);
}

test "zeroed vector stack arguments survive disjoint allocated member writes" {
    var initial = flow.State.entry(1);
    initial.regs[3] = .{ .kind = .heap, .id = 99, .size = 128 };
    initial.escaped_stack = true;
    var result = try trace(&.{
        instruction("xorps", "%xmm0, %xmm0"), instruction("movups", "%xmm0, 16(%rsp)"),
        instruction("movq", "$0, 40(%rbx)"),  instruction("movq", "24(%rsp), %rax"),
    }, initial, .{ .field = 40 });
    defer result.deinit();
    try std.testing.expect(result.analysis.after[3].regs[0].isZero());
    initial.regs[0] = .{ .kind = .integer, .id = 8 };
    const location = flow.memory(initial, instruction("lea", ""), "(%rax,%rbx)");
    try std.testing.expect(location.samePointer(initial.regs[3].plus(8)));
}

test "registered list nodes protect all callback slots and never regain overwritten constants" {
    const object: flow.Value = .{ .kind = .heap, .id = 42, .size = 256 };
    const cursor: flow.Value = .{ .kind = .scheduler_list, .id = 42, .size = 160, .link = 152 };
    var state: flow.State = .{};
    try state.store(object.plus(40), .{ .kind = .address, .id = 0x1234 }, 8, .{ .field = 40 });
    try state.store(cursor.plus(152), object, 8, .{ .field = 40 });
    try std.testing.expect(state.get(object.plus(40)).addressIs(0x1234, true));
    try std.testing.expectError(error.InvalidRegisteredSchedulerWrite, state.store(cursor.plus(40), .{}, 8, .{ .field = 40 }));
    try std.testing.expect(!cursor.samePointer(cursor));
    const constant: flow.Value = .{ .kind = .address, .id = 0x2000 };
    try std.testing.expect(state.canReadInitial(constant, 8));
    try state.store(constant.plus(-1), .{}, 2, .none);
    try std.testing.expect(!state.canReadInitial(constant, 8));
    try std.testing.expect(state.canReadInitial(constant.plus(8), 8));
}

test "reviewed logging formats cannot write through percent n or unknown conversions" {
    const check = @import("hyperv-proof-binding.zig").printFormat;
    try check("scheduler %p: %08x %llu %.3s %%n");
    for ([_][]const u8{ "%n", "%hn", "%lln", "%1$n", "%q", "%" }) |format|
        try std.testing.expectError(error.UnprovenPrintFormat, check(format));
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
        .{ .index = 2, .replacement = instruction("xorb", "%dh, %dh"), .err = error.MissingEferNxeLme },
        .{ .index = 3, .replacement = instruction("movl", "$0x100, %eax"), .err = error.MissingEferNxeLme },
        .{ .index = 3, .replacement = instruction("movb", "$9, %ah"), .err = error.MissingEferNxeLme },
        .{ .index = 3, .replacement = instruction("movl", "$0x800, %eax"), .err = error.MissingEferNxeLme },
        .{ .index = 4, .replacement = instruction("movl", "$0xc0000081, %ecx"), .err = error.MissingEferNxeLme },
        .{ .index = 4, .replacement = instruction("movb", "$0x80, %ch"), .err = error.MissingEferNxeLme },
        .{ .index = 6, .replacement = instruction("movl", "$0x80000001, %eax"), .err = error.MissingCr0PeWpPg },
        .{ .index = 6, .replacement = instruction("movl", "$0x10001, %eax"), .err = error.MissingCr0PeWpPg },
        .{ .index = 6, .replacement = instruction("movb", "$1, %ah"), .err = error.MissingCr0PeWpPg },
        .{ .index = 6, .replacement = instruction("movl", "$0x80010000, %eax"), .err = error.MissingCr0PeWpPg },
    };
    for (mutations) |mutation| {
        var changed = good;
        changed[mutation.index] = mutation.replacement;
        try std.testing.expectError(mutation.err, proofs.pagingControls(&changed));
    }
}

test "callback bindings require actual full-width stores and track register clobbers" {
    const materialize = instruction("leaq", "0x1232(%rip), %rdi # 0x1234 <callback>");
    const store = instruction("movq", "%rdi, 0x10(%rbx)");
    try std.testing.expect(try stored(&.{ materialize, store }, true));
    try std.testing.expect(try stored(&.{instruction("movq", "$0x1234, 0x10(%rbx)")}, false));
    try std.testing.expect(!try stored(&.{instruction("movq", "$0x1234, 0x10(%rbx)")}, true));
    try std.testing.expect(!try stored(&.{ materialize, instruction("retq", "") }, true));
    try std.testing.expect(!try stored(&.{ materialize, instruction("movl", "%edi, 0x10(%rbx)") }, true));
    try std.testing.expect(!try stored(&.{ materialize, instruction("movq", "%rdi, 0x18(%rbx)") }, true));
    for ([_]Instruction{
        instruction("movb", "$0, %dil"),        instruction("incq", "%rdi"),
        instruction("popq", "%rdi"),            instruction("xchgq", "%rdi, %rax"),
        instruction("xaddq", "%rdi, %rax"),     instruction("movw", "$0, %di"),
        instruction("callq", "0x10 <clobber>"), instruction("cmpxchgq", "%rsi, %rdi"),
        instruction("popcntq", "%rax, %rdi"),
    }) |clobber| {
        try std.testing.expect(!try stored(&.{ materialize, clobber, store }, true));
    }
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, stored(&.{
        materialize, instruction("movsq", "(%rsi), (%rdi)"), store,
    }, true));
    try std.testing.expect(try stored(&.{
        materialize,                          instruction("movq", "%rdi, %r12"),
        instruction("callq", "0x10 <other>"), instruction("movq", "%r12, 0x10(%rbx)"),
    }, true));
    const narrow = [_]Instruction{ materialize, instruction("movl", "%edi, %edi"), store };
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, stored(&.{ materialize, instruction("unmodeled", ""), store }, true));
    try std.testing.expect(!try stored(&narrow, true));
    var result = try trace(&.{
        instruction("movabsq", "$0xffffffffffffffff, %rax"),
        instruction("movl", "%eax, %edi"),
        instruction("divq", "%r12"),
    }, .{}, .none);
    defer result.deinit();
    try std.testing.expectEqual(std.math.maxInt(u64), result.analysis.after[0].regs[0].id);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u32)), result.analysis.after[1].regs[7].id);
    try std.testing.expectEqual(.unknown, result.analysis.after[2].regs[0].kind);
    try std.testing.expectEqual(std.math.maxInt(u64), assembly.immediate("$-1"));
}

test "CFG rejects skipped materialization and meets every predecessor at a call" {
    for ([_][]const u8{ "jmp", "jne" }) |op| {
        var result = try trace(&.{
            instruction(op, "4 <register>"),
            instruction("leaq", "0x1231(%rip), %rdi"),
            instruction("nop", ""),
            instruction("callq", "10 <register>"),
        }, flow.State.entry(1), .none);
        defer result.deinit();
        try std.testing.expect(!result.analysis.before[3].regs[7].addressIs(0x1234, true));
        try std.testing.expectEqual(!std.mem.eql(u8, op, "jmp"), result.analysis.seen[1]);
    }

    var result = try trace(&.{
        instruction("jne", "3 <join>"),            instruction("nop", ""),
        instruction("leaq", "0x1230(%rip), %rdi"), instruction("callq", "10 <register>"),
    }, .{}, .none);
    defer result.deinit();
    try std.testing.expect(result.analysis.before[3].regs[7].addressIs(0x1234, true));
}

test "all IMUL operands and implicit register writes affect provenance" {
    const parsed = try assembly.Operands.parse(instruction("imulq", "$0, %rdi, %rdi"));
    try std.testing.expectEqual(3, parsed.len);
    try std.testing.expectEqualStrings("%rdi", parsed.items[2]);
    try std.testing.expect(assembly.splitOperands(instruction("imulq", "$0, %rdi, %rdi")) == null);
    const memory = try assembly.Operands.parse(instruction("imulq", "$2, 8(%rax,%rcx,4), %rdi"));
    try std.testing.expectEqual(3, memory.len);
    const materialize = instruction("leaq", "0x1232(%rip), %rdi");
    for ([_][]const u8{ "$0, %rdi, %rdi", "$2, %rdi, %rdi" }) |operands| {
        var result = try trace(&.{ materialize, instruction("imulq", operands), instruction("callq", "10 <register>") }, .{}, .none);
        defer result.deinit();
        try std.testing.expect(!result.analysis.before[2].regs[7].addressIs(0x1234, true));
    }
    var valid = try trace(&.{ materialize, instruction("imulq", "$1, %rdi, %rdi"), instruction("callq", "10 <register>") }, .{}, .none);
    defer valid.deinit();
    try std.testing.expect(valid.analysis.before[2].regs[7].addressIs(0x1234, true));
    var numeric = try trace(&.{ instruction("movq", "$7, %rax"), instruction("imulq", "$2, %rax, %rdx") }, .{}, .none);
    defer numeric.deinit();
    try std.testing.expectEqual(14, numeric.analysis.after[1].regs[2].id);
    for ([_]Instruction{ instruction("mulq", "%rdi"), instruction("divq", "(%rdi)"), instruction("cpuid", ""), instruction("rdtscp", "") }) |writer| {
        var initial = flow.State.entry(1);
        for ([_]usize{ 0, 2 }) |reg| initial.regs[reg] = .{ .kind = .address, .id = 0x1234 };
        var result = try trace(&.{writer}, initial, .none);
        defer result.deinit();
        try std.testing.expect(!result.analysis.after[0].regs[0].addressIs(0x1234, true));
        try std.testing.expect(!result.analysis.after[0].regs[2].addressIs(0x1234, true));
    }
    for ([_]Instruction{ instruction("unmodeled", "%rax, %rdi"), instruction("unmodeled", "$0, %rax, %rdi") }) |unknown|
        try std.testing.expectError(error.UnsupportedProvenanceInstruction, trace(&.{ materialize, unknown }, .{}, .none));
}

test "vector memory writes use full XMM YMM ZMM and scalar widths" {
    const materialize = instruction("leaq", "0x1232(%rip), %rdi");
    const store = instruction("movq", "%rdi, 0x10(%rbx)");
    for ([_][]const u8{ "%xmm0", "%ymm0", "%zmm0" }, [_]i64{ 16, 32, 64 }) |reg, width| {
        for ([_]i64{ 16 - width, 17 - width, 16, 23, 24 }) |offset| {
            const operand = try std.fmt.allocPrint(std.testing.allocator, "{s}, {d}(%rbx)", .{ reg, offset });
            defer std.testing.allocator.free(operand);
            const op = if (width == 64) "vmovdqu64" else "vmovdqu";
            const overlap = offset < 24 and offset + width > 16;
            try std.testing.expectEqual(!overlap, try stored(&.{ materialize, store, instruction(op, operand) }, true));
        }
    }
    try std.testing.expect(!try stored(&.{ materialize, store, instruction("vpxor", "%ymm0, %ymm0, %ymm0"), instruction("vmovdqu", "%ymm0, -8(%rbx)") }, true));
    try std.testing.expect(try stored(&.{ materialize, store, instruction("movss", "%xmm0, 12(%rbx)") }, true));
    try std.testing.expect(!try stored(&.{ materialize, store, instruction("movsd", "%xmm0, 12(%rbx)") }, true));
    try std.testing.expectError(error.UnsupportedProvenanceInstruction, stored(&.{ materialize, store, instruction("unknown_vector_store", "%zmm0, (%rbx)") }, true));
}

test "only justified allocated objects separate from globals and retain member pointers" {
    const regions = [_]flow.Region{.{ .start = 0x2000, .end = 0x2010 }};
    const callback: flow.Value = .{ .kind = .address, .id = 0x1234 };
    const slot: flow.Slot = .{ .field = 40 };
    for ([_]bool{ false, true }) |fresh| {
        const object: flow.Value = .{ .kind = if (fresh) .heap else .result, .id = 99, .size = 128 };
        var state: flow.State = .{ .globals = &regions };
        try state.store(object.plus(40), callback, 8, slot);
        try state.store(.{ .kind = .address, .id = 0x2000, .upper = 0x2008 }, object, 8, slot);
        try std.testing.expectEqual(fresh, state.get(object.plus(40)).addressIs(0x1234, true));
        if (fresh) {
            try state.store(object.plus(96), object.plus(88), 8, slot);
            try state.store(state.get(object.plus(96)), object, 8, slot);
            try std.testing.expect(state.get(object.plus(40)).addressIs(0x1234, true));
            try state.store(object.plus(96), object.plus(40), 8, slot);
            try state.store(state.get(object.plus(96)), object, 8, slot);
            try std.testing.expect(!state.get(object.plus(40)).addressIs(0x1234, true));
        }
    }
}
test "CFG retains loop-invariant provenance and bounds analysis resources" {
    var result = try trace(&.{
        instruction("leaq", "0x1232(%rip), %rdi"),
        instruction("testl", "%eax, %eax"),
        instruction("jne", "2 <loop>"),
        instruction("callq", "10 <register>"),
    }, .{}, .none);
    defer result.deinit();
    try std.testing.expect(result.analysis.before[3].regs[7].addressIs(0x1234, true));
    var counted = try trace(&.{
        instruction("leaq", "0x1232(%rip), %rcx"), instruction("loop", "3 <next>"),
        instruction("movq", "%rcx, %rdi"),
    }, .{}, .none);
    defer counted.deinit();
    try std.testing.expect(!counted.analysis.after[2].regs[7].addressIs(0x1234, true));
    const oversized = try std.testing.allocator.alloc(Instruction, flow.max_instructions + 1);
    defer std.testing.allocator.free(oversized);
    try std.testing.expectError(error.ControlFlowLimit, flow.Graph.init(std.testing.allocator, oversized));
    var state: flow.State = .{};
    for (0..state.cells.len) |i|
        try state.store(.{ .kind = .stack, .offset = @intCast(i * 8) }, .{ .kind = .integer, .id = 1 }, 8, .none);
    try std.testing.expectError(error.ProvenanceMemoryLimit, state.store(.{ .kind = .stack, .offset = 4096 }, .{ .kind = .integer }, 8, .none));
}

test "CFG refuses unknown exits and constructor allocation cycles" {
    for ([_]Instruction{ instruction("jne", "20 <outside>"), instruction("jmp", "*%rax") }) |branch|
        try std.testing.expectError(error.UnsupportedControlFlow, trace(&.{branch}, .{}, .none));
    const last = [_]Instruction{.{ .address = 1, .size = 1, .op = "nop", .operands = "" }};
    try std.testing.expectError(error.UnterminatedBindingFunction, flow.Analysis.run(std.testing.allocator, &last, .{}, .{}));
    const cycle = [_]Instruction{
        .{ .address = 1, .size = 1, .op = "callq", .operands = "10 <allocate>" },
        .{ .address = 2, .size = 1, .op = "jmp", .operands = "1 <again>" },
    };
    try std.testing.expectError(error.CyclicSchedulerBinding, flow.Analysis.run(std.testing.allocator, &cycle, .{}, .{ .reject_call_cycles = true }));
    var budget: usize = flow.max_work;
    const returning = [_]Instruction{.{ .address = 1, .size = 1, .op = "retq", .operands = "" }};
    try std.testing.expectError(error.ControlFlowLimit, flow.Analysis.run(std.testing.allocator, &returning, .{}, .{ .work_counter = &budget }));
}

test "only live full-width null tests refine object aliases" {
    var initial = flow.State.entry(1);
    initial.regs[0] = .{ .kind = .result, .id = 99 };
    initial.regs[3] = initial.regs[0];
    for ([_]Instruction{ instruction("testq", "%rax, %rax"), instruction("testl", "%eax, %eax"), instruction("testb", "%al, %al") }) |test_op| {
        var result = try trace(&.{ test_op, instruction("je", "4 <null>"), instruction("retq", ""), instruction("nop", "") }, initial, .none);
        defer result.deinit();
        try std.testing.expectEqual(std.mem.eql(u8, test_op.op, "testq"), result.analysis.before[3].regs[3].isZero());
    }
    for ([_]Instruction{ instruction("popfq", ""), instruction("incq", "%rdx"), instruction("callq", "10 <clobber>") }) |flags| {
        var result = try trace(&.{
            instruction("testq", "%rax, %rax"), flags,                  instruction("je", "5 <unknown>"),
            instruction("retq", ""),            instruction("nop", ""),
        }, initial, .none);
        defer result.deinit();
        try std.testing.expect(!result.analysis.before[4].regs[3].isZero());
    }
}

test "slot overwrites unpublish register and spilled aliases including nullable summaries" {
    const object: flow.Value = .{ .kind = .result, .id = 99 };
    const callback: flow.Value = .{ .kind = .address, .id = 0x1234 };
    const slot: flow.Slot = .{ .field = 16 };
    var initial = flow.State.entry(1);
    initial.regs[3] = object;
    try initial.store(object.plus(16), callback, 8, slot);
    initial.cells[0].key.bound = true;
    initial.markBound(object);
    const spill = initial.regs[4].plus(-8);
    try initial.store(spill, initial.regs[3], 8, slot);
    var changed = initial;
    try changed.store(object.plus(16), .{ .kind = .integer }, 8, slot);
    try std.testing.expect(!changed.regs[3].bound);
    try std.testing.expect(!changed.get(spill).bound);
    changed = initial;
    try flow.unknownCall(&changed, instruction("callq", "10 <unknown>"), .{ .slot = slot });
    try std.testing.expect(!changed.regs[3].bound);
    try std.testing.expect(!changed.get(spill).bound);
    changed = initial;
    changed.cells = @splat(.{});
    changed.regs[3].nullable = true;
    try changed.store(object.plus(16), .{ .kind = .integer }, 8, slot);
    try std.testing.expect(!changed.regs[3].bound);
    changed = initial;
    try changed.store(object.plus(16), callback, 8, slot);
    try std.testing.expect(changed.regs[3].bound);
}

test "unescaped stack spills survive calls but escaped spills and exchange writes do not" {
    const materialize = instruction("leaq", "0x1232(%rip), %rdi");
    const store = instruction("movq", "%rdi, 0x10(%rbx)");
    try std.testing.expect(try stored(&.{
        materialize,                 instruction("pushq", "%rdi"), instruction("callq", "10 <other>"),
        instruction("popq", "%rdi"), store,
    }, true));
    try std.testing.expect(!try stored(&.{
        materialize,                          instruction("pushq", "%rdi"), instruction("movq", "%rsp, %rdi"),
        instruction("callq", "10 <escaped>"), instruction("popq", "%rdi"),  store,
    }, true));
    try std.testing.expect(!try stored(&.{ materialize, store, instruction("xchgq", "0x10(%rbx), %rcx") }, true));
    try std.testing.expect(!try stored(&.{ materialize, instruction("xaddq", "%rdi, 0x18(%rbx)"), store }, true));
    var initial = flow.State.entry(1);
    initial.regs[12] = initial.regs[7];
    var loaded = try trace(&.{
        instruction("movq", "8(%rdi), %rbx"), instruction("callq", "10 <mutate>"),
        instruction("movq", "8(%r12), %rax"),
    }, initial, .none);
    defer loaded.deinit();
    try std.testing.expect(!loaded.analysis.after[2].regs[0].samePointer(loaded.analysis.after[2].regs[3]));
}

test "split LOCK is normalized only with a contiguous integer memory RMW" {
    var program = try assembly.Program.parse(std.testing.allocator, "image: file format elf64-x86-64\n10 <irq>:\n" ++
        " 10: f0 lock\n 11: 49 83 0c 24 01 orq $1, (%r12)\n 16: c3 retq\n");
    defer program.deinit();
    try std.testing.expectEqual(2, program.instructions.items.len);
    try std.testing.expectEqualStrings("orq", program.instructions.items[0].op);
    try std.testing.expectEqual(6, program.instructions.items[0].size);
    try std.testing.expect(!proofs.forbiddenRegisters(program.instructions.items[0]));
    var invalid = try assembly.Program.parse(std.testing.allocator, "image: file format elf64-x86-64\n10 <irq>:\n" ++
        " 10: f0 lock\n 11: 83 c8 01 orl $1, %eax\n 14: c3 retq\n");
    defer invalid.deinit();
    try std.testing.expect(invalid.instructions.items[0].unknown());
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
