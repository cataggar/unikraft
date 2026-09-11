// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const flow = @import("hyperv-proof-flow.zig");
const assembly = @import("hyperv-proof-disasm.zig");
const machine = @import("hyperv-proof-instructions.zig");

pub const Call = *const fn (?*anyopaque, assembly.Instruction, flow.State, flow.Options) anyerror![]flow.State;
const Item = struct { index: usize, state: flow.State, called: std.StaticBitSet(flow.max_instructions) };

pub fn run(allocator: std.mem.Allocator, instructions: []const assembly.Instruction, initial: flow.State, options: flow.Options, call: Call) ![]flow.State {
    var graph = try flow.Graph.init(allocator, instructions);
    defer graph.deinit();
    var work: std.ArrayList(Item) = .empty;
    defer work.deinit(allocator);
    var seen: std.ArrayList(Item) = .empty;
    defer seen.deinit(allocator);
    var returns: std.ArrayList(flow.State) = .empty;
    errdefer returns.deinit(allocator);
    try work.append(allocator, .{ .index = 0, .state = initial, .called = .initEmpty() });
    while (work.pop()) |item| {
        const pc = instructions[item.index];
        var duplicate = false;
        for (seen.items) |old| {
            if (old.index == item.index and std.meta.eql(old.state, item.state) and old.called.eql(item.called)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (seen.items.len >= 2048 or work.items.len >= 512) return error.ProvenancePathLimit;
        try seen.append(allocator, item);
        if (options.work_counter) |counter| {
            if (counter.* >= flow.max_work) return error.ControlFlowLimit;
            counter.* += 1;
        }
        var called = item.called;
        const tail = pc.isJump() and graph.edges[item.index][0] == null;
        var outputs: []flow.State = undefined;
        if (pc.isCall() or tail) {
            if (called.isSet(item.index)) return error.CyclicSchedulerBinding;
            called.set(item.index);
            var state = item.state;
            try flow.callReturnAddress(&state, pc, options);
            outputs = try call(options.hook_context, pc, state, options);
        } else if (std.mem.startsWith(u8, pc.op, "cmov") or std.mem.startsWith(u8, pc.op, "set")) {
            const is_set = std.mem.startsWith(u8, pc.op, "set");
            const operands = try assembly.Operands.parse(pc);
            const target = operands.items[operands.len - 1];
            _ = assembly.register(target) orelse return error.UnsupportedProvenanceInstruction;
            var choices: std.ArrayList(flow.State) = .empty;
            errdefer choices.deinit(allocator);
            if (operands.len != @as(usize, if (is_set) 1 else 2)) return error.UnsupportedProvenanceInstruction;
            const condition = machine.condition(pc.op, if (is_set) "set" else "cmov") orelse return error.UnsupportedProvenanceInstruction;
            const branch_op = if (std.mem.eql(u8, condition, "e") or std.mem.eql(u8, condition, "z")) "je" else if (std.mem.eql(u8, condition, "ne") or std.mem.eql(u8, condition, "nz")) "jne" else "j-unknown";
            for ([_]bool{ false, true }) |take| {
                var state = flow.branch(item.state, branch_op, take) orelse continue;
                if (is_set) {
                    try flow.writeOperand(&state, target, .{ .kind = .integer, .id = @intFromBool(take) });
                } else if (take) {
                    try flow.writeOperand(&state, target, flow.source(state, pc, operands.items[0]));
                }
                try choices.append(allocator, state);
            }
            outputs = try choices.toOwnedSlice(allocator);
        } else {
            var state = item.state;
            flow.step(&state, pc, options) catch |err| {
                std.debug.print("instruction 0x{x}: {s} {s}: {s}\n", .{ pc.address, pc.op, pc.operands, @errorName(err) });
                return err;
            };
            outputs = try allocator.dupe(flow.State, &.{state});
        }
        defer allocator.free(outputs);
        for (outputs) |state| {
            if (tail or std.mem.startsWith(u8, pc.op, "ret")) {
                try returns.append(allocator, state);
                continue;
            }
            if (pc.stops()) continue;
            if (pc.isBranch() and !pc.isCall() and !pc.isJump() and graph.edges[item.index][0] == null) return error.UnsupportedControlFlow;
            if (item.index + 1 == instructions.len and !pc.isJump()) return error.UnterminatedBindingFunction;
            for (graph.edges[item.index], 0..) |edge, edge_index| {
                const next = edge orelse continue;
                const outgoing = flow.branch(state, pc.op, edge_index == 0) orelse continue;
                try work.append(allocator, .{ .index = next, .state = outgoing, .called = called });
            }
        }
    }
    return returns.toOwnedSlice(allocator);
}
