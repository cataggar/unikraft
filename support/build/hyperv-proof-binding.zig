// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const Model = @import("hyperv-proof-image.zig").Model;
const assembly = @import("hyperv-proof-disasm.zig");
const flow = @import("hyperv-proof-flow.zig");
const paths = @import("hyperv-proof-paths.zig");
const machine = @import("hyperv-proof-instructions.zig");

pub fn printFormat(format: []const u8) !void {
    var i: usize = 0;
    while (i < format.len) : (i += 1) {
        if (format[i] != '%') continue;
        i += 1;
        if (i == format.len) return error.UnprovenPrintFormat;
        if (format[i] == '%') continue;
        while (i < format.len and std.mem.indexOfScalar(u8, "#0- +'.*123456789hlLjzt", format[i]) != null) : (i += 1) {}
        if (i == format.len or std.mem.indexOfScalar(u8, "diouxXfFeEgGaAcsp", format[i]) == null)
            return error.UnprovenPrintFormat;
    }
}

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
    if (assembly.register(operand) != null) return flow.source(state, instruction, operand).location() orelse .{};
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
        var entry = flow.State.entry(context);
        // Valid startup allocator arguments; their allocation results remain nullable.
        for ([_]usize{ 7, 6, 2, 1 }) |reg| entry.regs[reg] = .{ .kind = .allocator, .id = reg, .context = context };
        entry.globals = engine.globals.items;
        const results = try engine.analyze(symbol.header.st_value, entry, context);
        defer model.image.allocator.free(results);
        var bound_return = false;
        for (results) |result| {
            if (engine.slot == .field and result.regs[0].isZero()) continue;
            const valid = switch (engine.slot) {
                .absolute => |address| result.get(.{ .kind = .address, .id = address }).addressIs(engine.callback, engine.pie),
                .field => result.regs[0].bound,
                .none => false,
            };
            if (!valid) return error.MissingSchedulerCallbackBinding;
            bound_return = true;
        }
        if (!bound_return) return error.MissingSchedulerCallbackBinding;
    }
    if (count == 0) return error.MissingSchedulerConstructor;
}

const Engine = struct {
    model: Model,
    slot: flow.Slot,
    callback: u64,
    registration: ?u64,
    list_head: ?u64 = null,
    list_next: i64 = 0,
    pie: bool,
    contexts: std.AutoHashMap([2]u64, u64),
    active: std.ArrayList(u64) = .empty,
    work: usize = 0,
    steps: usize = 0,
    globals: std.ArrayList(flow.Region) = .empty,

    fn init(model: Model, slot: flow.Slot) !Engine {
        const allocator = model.image.allocator;
        var engine: Engine = .{
            .model = model,
            .slot = slot,
            .callback = try model.address("schedcoop_thread_woken_isr"),
            .registration = if (try model.maybeSymbol("uk_sched_register")) |symbol| symbol.header.st_value else null,
            .pie = model.image.header.type == .DYN,
            .contexts = .init(allocator),
        };
        errdefer engine.deinit();
        for (model.image.symbols) |symbol| {
            if (symbol.header.st_info & 15 == std.elf.STT_OBJECT and symbol.header.st_size != 0 and model.image.containsMemory(symbol.header.st_value, symbol.header.st_size))
                try engine.globals.append(allocator, .{ .start = symbol.header.st_value, .end = try std.math.add(u64, symbol.header.st_value, symbol.header.st_size) });
        }
        for (model.image.sections) |section| {
            if (std.mem.eql(u8, section.name, ".got"))
                try engine.globals.append(allocator, .{ .start = section.header.sh_addr, .end = try std.math.add(u64, section.header.sh_addr, section.header.sh_size) });
        }
        if (slot == .field and engine.registration == null) return error.MissingSchedulerRegistration;
        if (slot == .field) _ = try model.strong("uk_sched_register");
        if (model.functions.len > 16384) return error.ControlFlowLimit;
        if (slot == .field) {
            if (try model.maybeSymbol("uk_sched_head")) |head| {
                if (head.header.st_size != 8 or !model.image.containsMemory(head.header.st_value, 8)) return error.InvalidSchedulerListLayout;
                engine.list_head = head.header.st_value;
                var analysis = try flow.Analysis.run(allocator, try model.body("uk_sched_register"), flow.State.entry(1), .{});
                defer analysis.deinit();
                var found = false;
                for (analysis.graph.instructions, 0..) |instruction, index| {
                    if (!analysis.seen[index] or !machine.sized(instruction.op, "mov")) continue;
                    const operands = flow.pair(instruction) orelse continue;
                    if (assembly.immediate(operands[0]) != 0) continue;
                    const location = flow.memory(analysis.before[index], instruction, operands[1]);
                    if (!location.samePointer(flow.State.entry(1).regs[7].plus(location.offset))) continue;
                    if (found or location.offset < slot.field + 8 or location.offset > 4096) return error.InvalidSchedulerListLayout;
                    engine.list_next = location.offset;
                    found = true;
                }
                if (!found) return error.InvalidSchedulerListLayout;
            }
        }
        return engine;
    }
    fn deinit(self: *Engine) void {
        self.active.deinit(self.model.image.allocator);
        self.contexts.deinit();
        self.globals.deinit(self.model.image.allocator);
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
    fn one(self: *Engine, state: flow.State) ![]flow.State {
        return self.model.image.allocator.dupe(flow.State, &.{state});
    }
    fn callStates(context_ptr: ?*anyopaque, instruction: assembly.Instruction, input: flow.State, options: flow.Options) ![]flow.State {
        const self: *Engine = @ptrCast(@alignCast(context_ptr.?));
        var local = input;
        const state = &local;
        self.work += 1;
        if (self.work > 8192) return error.ControlFlowLimit;
        var target: ?u64 = if (instruction.indirect()) null else try instruction.target();
        if (instruction.indirect()) {
            const location = indirectLocation(state.*, instruction);
            if (location.kind == .allocator and location.depth == 0 and
                location.samePointer(state.regs[7].plus(location.offset - state.regs[7].offset)))
            {
                const offset = location.offset - state.regs[7].offset;
                if (offset == 0 or offset == 8 or offset == 32) {
                    const argument_rsi = flow.source(state.*, instruction, "%rsi");
                    const argument_rdx = flow.source(state.*, instruction, "%rdx");
                    var size = if (offset == 0) argument_rsi else argument_rdx;
                    if (offset == 8) {
                        if (argument_rsi.kind != .integer or argument_rsi.upper != null or size.kind != .integer) return error.UnprovenAllocationSize;
                        size.id = try std.math.mul(u64, size.id, argument_rsi.id);
                        if (size.upper) |upper| size.upper = try std.math.mul(u64, upper, argument_rsi.id);
                    }
                    if (size.kind != .integer or size.id == 0 or size.high() > 16 * 1024 * 1024) {
                        return error.UnprovenAllocationSize;
                    }
                    const alignment: u64 = if (offset == 32) argument_rsi.id else 16;
                    if (offset == 32 and (argument_rsi.kind != .integer or argument_rsi.upper != null or !std.math.isPowerOfTwo(alignment))) return error.UnprovenAllocationSize;
                    flow.clobberCall(state, instruction, options);
                    state.regs[0] = .{ .kind = .heap, .id = instruction.address, .context = options.context, .size = size.id, .alignment = alignment, .aligned = alignment, .nullable = true };
                    return self.one(state.*);
                }
                if (offset == 40) {
                    const released = flow.source(state.*, instruction, "%rsi");
                    if (!released.isZero()) try state.store(released, .{}, if (released.kind == .heap) released.size else std.math.maxInt(u64), self.slot);
                    flow.clobberCall(state, instruction, options);
                    return self.one(state.*);
                }
            }
            const value = state.get(location);
            if (value.kind == .address and value.depth == 0 and !value.nullable) target = value.id;
        }
        if (target != null and target == self.registration) {
            if (!self.publish(state)) return error.MissingSchedulerCallbackBinding;
            if (self.list_head) |head| {
                const object = state.regs[7];
                if (object.kind != .heap or object.depth != 0 or object.offset != 0 or !flow.inHeap(object, @intCast(self.list_next + 8))) return error.UnsupportedSchedulerListRoot;
                const location: flow.Value = .{ .kind = .address, .id = head };
                const previous = state.get(location);
                if (!state.canReadInitial(location, 8) and !previous.isZero() and
                    !(previous.depth == 0 and previous.offset == 0 and previous.upper == null and
                        (previous.kind == .scheduler_list or (previous.kind == .heap and previous.bound and !previous.nullable))))
                    return error.InvalidSchedulerListHead;
                try state.store(location, .{
                    .kind = .scheduler_list,
                    .id = object.id,
                    .context = object.context,
                    .link = self.list_next,
                    .size = @intCast(self.list_next + 8),
                    .nullable = true,
                }, 8, self.slot);
            }
        }
        if (target) |callee| {
            if (try self.model.maybeSymbol("_uk_printk")) |symbol| {
                if (callee == symbol.header.st_value) {
                    if (@import("hyperv-image-proofs.zig").terminalAssertion(try self.model.bodyAt(instruction.address), 0)) {
                        try flow.unknownCall(state, instruction, options);
                        return self.one(state.*);
                    }
                    _ = try self.model.strong("_uk_printk");
                    const format = state.regs[8];
                    if (format.kind != .address or format.depth != 0 or format.upper != null) return error.UnprovenPrintFormat;
                    var valid = false;
                    for (self.model.image.sections) |section| {
                        if (section.header.sh_flags & std.elf.SHF_ALLOC == 0 or section.header.sh_flags & std.elf.SHF_WRITE != 0 or format.id < section.header.sh_addr) continue;
                        const offset = format.id - section.header.sh_addr;
                        if (offset >= section.header.sh_size) continue;
                        const data = try self.model.dataAt(format.id, @min(4096, section.header.sh_size - offset));
                        const end = std.mem.indexOfScalar(u8, data, 0) orelse return error.UnprovenPrintFormat;
                        if (!state.canReadInitial(format, end + 1)) return error.UnprovenPrintFormat;
                        try printFormat(data[0..end]);
                        valid = true;
                    }
                    if (!valid) return error.UnprovenPrintFormat;
                    flow.clobberCall(state, instruction, options);
                    return self.one(state.*);
                }
            }
            if (try self.model.maybeSymbol("uk_plat_native_ectx_init")) |symbol| {
                if (callee == symbol.header.st_value) {
                    _ = try self.model.strong("uk_plat_native_ectx_init");
                    const destination = state.regs[7];
                    const end = destination.upper orelse if (destination.offset >= 0) @as(u64, @intCast(destination.offset)) else std.math.maxInt(u64);
                    if (!flow.inHeap(destination, 2688) or destination.aligned < 64 or end > destination.size or 2688 > destination.size - end)
                        return error.UnprovenEctxFootprint;
                    try state.store(destination, .{}, 2688, self.slot);
                    flow.clobberCall(state, instruction, options);
                    return self.one(state.*);
                }
            }
            for ([_][]const u8{ "memset", "memcpy", "memmove", "memset_isr", "memcpy_isr" }) |name| {
                const symbol = (try self.model.maybeSymbol(name)) orelse continue;
                if (callee != symbol.header.st_value) continue;
                _ = try self.model.strong(name);
                const destination = state.regs[7];
                const size = flow.source(state.*, instruction, "%rdx");
                if (size.kind != .integer or size.upper != null or size.id > 16 * 1024 * 1024) return error.UnprovenMemoryFootprint;
                if (size.id != 0) try state.store(destination, .{}, size.id, self.slot);
                const returned = state.regs[7];
                flow.clobberCall(state, instruction, options);
                state.regs[0] = returned;
                return self.one(state.*);
            }
        }
        if (target != null) {
            if (try self.model.maybeSymbol("_uk_printk")) |printk| {
                if (target.? == printk.header.st_value and @import("hyperv-image-proofs.zig").terminalAssertion(try self.model.bodyAt(instruction.address), 0)) {
                    try flow.unknownCall(state, instruction, options);
                    return self.one(state.*);
                }
            }
            const context_id = try self.context(options.context, instruction.address);
            var entering = state.*;
            if (instruction.isCall()) entering.regs[4] = entering.regs[4].plus(-8);
            const results = self.analyze(target.?, entering, context_id) catch |err| {
                std.debug.print("helper 0x{x} from 0x{x}: {s}\n", .{ target.?, instruction.address, @errorName(err) });
                return err;
            };

            const previous = state.regs;
            flow.clobberCall(state, instruction, options);
            for (results) |*result| {
                var returning = state.*;
                returning.cells = result.cells;
                returning.constant_writes = result.constant_writes;
                returning.constants_unknown = result.constants_unknown;
                returning.regs[0] = result.regs[0];
                returning.escaped_stack = returning.escaped_stack or result.escaped_stack;
                for ([_]usize{ 3, 5, 12, 13, 14, 15 }) |reg| {
                    const location = self.slotAddress(previous[reg]);
                    returning.regs[reg].bound = false;
                    for (returning.cells) |cell| if (cell.key.samePointer(location)) {
                        returning.regs[reg].bound = cell.key.bound and cell.value.addressIs(self.callback, self.pie);
                    };
                }
                result.* = returning;
            }
            return results;
        } else {
            // Unknown callees cannot establish bindings or preserve exposed slots.
            try flow.unknownCall(state, instruction, options);
        }
        return self.one(state.*);
    }
    fn constantRead(ptr: ?*anyopaque, location: flow.Value, width: u8) !?flow.Value {
        const self: *Engine = @ptrCast(@alignCast(ptr.?));
        if (location.kind != .address or location.depth != 0 or location.upper != null) return null;
        if (width == 8) {
            if (try self.model.relocatedPointer(location.id)) |pointer|
                return .{ .kind = if (self.model.image.containsMemory(pointer, 1)) .address else .integer, .id = pointer };
        }
        for (0..7 + @as(usize, width)) |i| {
            const candidate = if (i < 7) std.math.sub(u64, location.id, 7 - i) catch continue else std.math.add(u64, location.id, i - 7) catch continue;
            if (try self.model.relocatedPointer(candidate) != null) return null;
        }
        for (self.model.image.sections) |section| {
            if (section.header.sh_flags & std.elf.SHF_ALLOC == 0 or
                (section.header.sh_flags & std.elf.SHF_WRITE != 0 and !std.mem.eql(u8, section.name, ".got"))) continue;
            if (location.id < section.header.sh_addr or location.id - section.header.sh_addr >= section.header.sh_size) continue;
            if (width == 8) {
                const pointer = try self.model.pointer(location.id);
                return .{ .kind = if (self.model.image.containsMemory(pointer, 1)) .address else .integer, .id = pointer };
            }
            const bytes = try self.model.dataAt(location.id, width);
            const integer: u64 = switch (width) {
                1 => bytes[0],
                2 => std.mem.readInt(u16, bytes[0..2], .little),
                4 => std.mem.readInt(u32, bytes[0..4], .little),
                else => return error.UnsupportedMemoryWidth,
            };
            return .{ .kind = .integer, .id = integer };
        }
        return null;
    }
    fn analyze(self: *Engine, address: u64, initial: flow.State, context_id: u64) ![]flow.State {
        if (self.active.items.len == 16 or std.mem.indexOfScalar(u64, self.active.items, address) != null)
            return error.MissingSchedulerCallbackBinding;
        try self.active.append(self.model.image.allocator, address);
        defer _ = self.active.pop();
        const results = try paths.run(self.model.image.allocator, try self.model.bodyAt(address), initial, .{
            .context = context_id,
            .pie = self.pie,
            .slot = self.slot,
            .hook_context = self,
            .work_counter = &self.steps,
            .reject_call_cycles = true,
            .constant_context = self,
            .constant_read = constantRead,
        }, callStates);
        for (results) |*output| {
            for (&output.cells) |*cell| if (cell.key.kind == .stack and cell.key.context == initial.regs[4].context and cell.key.offset < initial.regs[4].offset) {
                cell.* = .{};
            };
        }
        return results;
    }
};
