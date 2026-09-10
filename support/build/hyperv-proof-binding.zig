// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const Model = @import("hyperv-proof-image.zig").Model;
const assembly = @import("hyperv-proof-disasm.zig");
const flow = @import("hyperv-proof-flow.zig");

pub fn arguments(model: Model, caller: []const u8, callee: []const u8, reg: u4, expected: []const u64) !bool {
    var analysis = try flow.Analysis.run(model.image.allocator, try model.body(caller), flow.State.entry(1), .{});
    defer analysis.deinit();
    const found = try model.image.allocator.alloc(bool, expected.len);
    defer model.image.allocator.free(found);
    @memset(found, false);
    const target = try model.address(callee);
    for (analysis.graph.instructions, 0..) |instruction, i| {
        if (!analysis.seen[i] or !(instruction.isCall() or instruction.isJump()) or instruction.indirect()) continue;
        if (try instruction.target() != target) continue;
        var accepted = false;
        for (expected, 0..) |address, j| {
            if (analysis.before[i].regs[reg].addressIs(address, model.image.header.type == .DYN)) {
                found[j] = true;
                accepted = true;
            }
        }
        if (!accepted) return false;
    }
    return std.mem.allEqual(bool, found, true);
}

fn indirectLocation(state: flow.State, instruction: assembly.Instruction) flow.Value {
    const operand = std.mem.trim(u8, instruction.operands[1..], " \t");
    if (assembly.register(operand)) |reg| return state.regs[reg].location() orelse .{};
    return flow.memory(state, instruction, operand);
}

fn consumerSlot(model: Model) !flow.Slot {
    var analysis = try flow.Analysis.run(model.image.allocator, try model.body("uk_thread_wake_isr"), flow.State.entry(1), .{});
    defer analysis.deinit();
    var slot: ?flow.Slot = null;
    for (analysis.graph.instructions, 0..) |instruction, i| {
        if (!analysis.seen[i] or !instruction.isCall() or !instruction.indirect()) continue;
        if (slot != null) return error.UnreviewedIndirectCount;
        const state = analysis.before[i];
        const location = indirectLocation(state, instruction);
        if (location.kind == .address and location.depth == 0) {
            if (!model.image.containsMemory(location.id, 8)) return error.InvalidCallbackSlot;
            slot = .{ .absolute = location.id };
        } else {
            const object = state.regs[7];
            const member = object.location() orelse return error.InvalidCallbackSlot;
            const thread = flow.State.entry(1).regs[7];
            if (member.offset < 0 or @mod(member.offset, 8) != 0 or member.offset > 4096 or
                !member.samePointer(thread.plus(member.offset))) return error.InvalidCallbackSlot;
            const offset = std.math.sub(i64, location.offset, object.offset) catch return error.InvalidCallbackSlot;
            if (object.kind == .unknown or offset < 0 or @mod(offset, 8) != 0 or offset > 4096 or
                !location.samePointer(object.plus(offset)) or
                !state.regs[6].samePointer(thread))
                return error.InvalidCallbackSlot;
            slot = .{ .field = offset };
        }
    }
    return slot orelse error.MissingSchedulerCallbackBinding;
}

pub fn scheduler(model: Model) !void {
    var engine = try Engine.init(model, try consumerSlot(model));
    defer engine.deinit();
    var count: usize = 0;
    for ([_][]const u8{ "uk_schedcoop_create", "uk_schedcoop_create_on" }) |name| {
        const symbol = (try model.maybeSymbol(name)) orelse continue;
        count += 1;
        const context = try engine.context(0, symbol.header.st_value);
        const result = try engine.analyze(symbol.header.st_value, flow.State.entry(context), context);
        const valid = switch (engine.slot) {
            .absolute => |address| result.get(.{ .kind = .address, .id = address }).addressIs(engine.callback, engine.pie),
            .field => result.regs[0].bound,
            .none => false,
        };
        if (!valid) return error.MissingSchedulerCallbackBinding;
    }
    if (count == 0) return error.MissingSchedulerConstructor;
}

const Engine = struct {
    model: Model,
    slot: flow.Slot,
    callback: u64,
    registration: ?u64,
    pie: bool,
    candidates: std.AutoHashMap(u64, void),
    contexts: std.AutoHashMap([2]u64, u64),
    active: std.ArrayList(u64) = .empty,
    work: usize = 0,
    steps: usize = 0,

    fn init(model: Model, slot: flow.Slot) !Engine {
        const allocator = model.image.allocator;
        var engine: Engine = .{
            .model = model,
            .slot = slot,
            .callback = try model.address("schedcoop_thread_woken_isr"),
            .registration = if (try model.maybeSymbol("uk_sched_register")) |symbol| symbol.header.st_value else null,
            .pie = model.image.header.type == .DYN,
            .candidates = .init(allocator),
            .contexts = .init(allocator),
        };
        errdefer engine.deinit();
        if (slot == .field and engine.registration == null) return error.MissingSchedulerRegistration;
        if (slot == .field) _ = try model.strong("uk_sched_register");
        if (model.functions.len > 16384) return error.ControlFlowLimit;
        for (model.functions) |function| {
            for (try model.bodyAt(function.start)) |instruction| {
                const immediate = if (flow.pair(instruction)) |operands| assembly.immediate(operands[0]) else null;
                if (instruction.reference() == engine.callback or immediate == engine.callback or
                    ((instruction.isCall() or instruction.isJump()) and !instruction.indirect() and
                        engine.registration != null and try instruction.target() == engine.registration.?))
                    try engine.candidates.put(function.start, {});
            }
        }
        var changed = true;
        var rounds: usize = 0;
        while (changed) {
            changed = false;
            rounds += 1;
            if (rounds > 32) return error.ControlFlowLimit;
            for (model.functions) |function| {
                if (engine.candidates.contains(function.start)) continue;
                for (try model.bodyAt(function.start)) |instruction| {
                    if (!(instruction.isCall() or instruction.isJump()) or instruction.indirect()) continue;
                    if (engine.candidates.contains(try instruction.target())) {
                        try engine.candidates.put(function.start, {});
                        changed = true;
                        break;
                    }
                }
            }
        }
        return engine;
    }
    fn deinit(self: *Engine) void {
        self.active.deinit(self.model.image.allocator);
        self.contexts.deinit();
        self.candidates.deinit();
    }
    fn context(self: *Engine, parent: u64, pc: u64) !u64 {
        const entry = try self.contexts.getOrPut(.{ parent, pc });
        if (!entry.found_existing) {
            if (self.contexts.count() > 256) return error.ControlFlowLimit;
            entry.value_ptr.* = self.contexts.count();
        }
        return entry.value_ptr.*;
    }
    fn slotAddress(self: Engine, object: flow.Value) flow.Value {
        return switch (self.slot) {
            .absolute => |address| .{ .kind = .address, .id = address },
            .field => |offset| object.plus(offset),
            .none => .{},
        };
    }
    fn publish(self: Engine, state: *flow.State) bool {
        const object = state.regs[7];
        if (object.kind == .unknown) return false;
        const location = self.slotAddress(object);
        if (!state.get(location).addressIs(self.callback, self.pie)) return false;
        state.markBound(object);
        for (&state.cells) |*cell| if (cell.key.samePointer(location)) {
            cell.key.bound = true;
        };
        return true;
    }
    fn callHook(context_ptr: ?*anyopaque, instruction: assembly.Instruction, state: *flow.State, options: flow.Options) !void {
        const self: *Engine = @ptrCast(@alignCast(context_ptr.?));
        self.work += 1;
        if (self.work > 8192) return error.ControlFlowLimit;
        const target: ?u64 = if (instruction.indirect()) null else try instruction.target();
        if (target != null and target == self.registration) {
            _ = self.publish(state);
            flow.clobberCall(state, instruction, options);
            return;
        }
        var relevant = target != null and self.candidates.contains(target.?);
        for ([_]usize{ 7, 6, 2, 1, 8, 9 }) |reg| {
            const argument = state.regs[reg];
            if (argument.addressIs(self.callback, self.pie) or argument.bound or
                state.get(self.slotAddress(argument)).addressIs(self.callback, self.pie)) relevant = true;
        }
        if (target != null and relevant) {
            const context_id = try self.context(options.context, instruction.address);
            const result = try self.analyze(target.?, state.*, context_id);
            const previous = state.regs;
            flow.clobberCall(state, instruction, options);
            state.cells = result.cells;
            state.regs[0] = result.regs[0];
            state.escaped_stack = state.escaped_stack or result.escaped_stack;
            for ([_]usize{ 3, 5, 12, 13, 14, 15 }) |reg| {
                const location = self.slotAddress(previous[reg]);
                state.regs[reg].bound = false;
                for (state.cells) |cell| if (cell.key.samePointer(location)) {
                    state.regs[reg].bound = cell.key.bound and cell.value.addressIs(self.callback, self.pie);
                };
            }
        } else {
            // Unknown callees cannot establish bindings or preserve exposed slots.
            try flow.unknownCall(state, instruction, options);
        }
    }
    fn analyze(self: *Engine, address: u64, initial: flow.State, context_id: u64) !flow.State {
        if (self.active.items.len == 16 or std.mem.indexOfScalar(u64, self.active.items, address) != null)
            return error.MissingSchedulerCallbackBinding;
        try self.active.append(self.model.image.allocator, address);
        defer _ = self.active.pop();
        var entry = initial;
        entry.regs[4] = .{ .kind = .stack, .context = context_id };
        var analysis = try flow.Analysis.run(self.model.image.allocator, try self.model.bodyAt(address), entry, .{
            .context = context_id,
            .pie = self.pie,
            .slot = self.slot,
            .hook_context = self,
            .call_hook = callHook,
            .work_counter = &self.steps,
            .reject_call_cycles = true,
        });
        defer analysis.deinit();
        var result: ?flow.State = null;
        for (analysis.graph.instructions, 0..) |instruction, i| {
            if (!analysis.seen[i]) continue;
            if ((instruction.isCall() or instruction.isJump()) and !instruction.indirect() and
                self.registration != null and try instruction.target() == self.registration.?)
            {
                var before = analysis.before[i];
                if (!self.publish(&before)) return error.MissingSchedulerCallbackBinding;
            }
            const external_tail = instruction.isJump() and analysis.graph.edges[i][0] == null;
            if (!std.mem.startsWith(u8, instruction.op, "ret") and !external_tail) {
                if (!instruction.stops() and analysis.graph.edges[i][0] == null and analysis.graph.edges[i][1] == null)
                    return error.UnterminatedBindingFunction;
                continue;
            }
            var output = analysis.after[i];
            for (&output.cells) |*cell| if (cell.key.kind == .stack and cell.key.context == context_id) {
                cell.* = .{};
            };
            if (result) |*existing| {
                _ = existing.merge(output);
            } else result = output;
        }
        return result orelse error.MissingSchedulerCallbackBinding;
    }
};
