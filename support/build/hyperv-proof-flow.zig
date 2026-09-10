// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const assembly = @import("hyperv-proof-disasm.zig");
pub const Instruction = assembly.Instruction;

pub const max_instructions = 8192;
pub const max_work = 131072;
pub const Graph = struct {
    allocator: std.mem.Allocator,
    instructions: []const Instruction,
    edges: [][2]?usize,
    reachable: []bool,

    pub fn init(allocator: std.mem.Allocator, instructions: []const Instruction) !Graph {
        if (instructions.len == 0) return error.MissingDisassembly;
        if (instructions.len > max_instructions) return error.ControlFlowLimit;
        const edges = try allocator.alloc([2]?usize, instructions.len);
        errdefer allocator.free(edges);
        const reachable = try allocator.alloc(bool, instructions.len);
        errdefer allocator.free(reachable);
        @memset(reachable, false);
        var index = std.AutoHashMap(u64, usize).init(allocator);
        defer index.deinit();
        for (instructions, 0..) |item, i| try index.put(item.address, i);
        for (instructions, 0..) |item, i| {
            edges[i] = .{ null, null };
            if (item.stops()) continue;
            const next: ?usize = if (i + 1 < instructions.len) i + 1 else null;
            if (item.isBranch() and !item.isCall()) {
                if (!item.indirect()) edges[i][0] = index.get(try item.target());
                if (!item.isJump()) edges[i][1] = next;
            } else edges[i][0] = next;
        }
        var pending: std.ArrayList(usize) = .empty;
        defer pending.deinit(allocator);
        try pending.append(allocator, 0);
        while (pending.pop()) |i| {
            if (reachable[i]) continue;
            reachable[i] = true;
            for (edges[i]) |successor| if (successor) |j| try pending.append(allocator, j);
        }
        return .{ .allocator = allocator, .instructions = instructions, .edges = edges, .reachable = reachable };
    }

    pub fn deinit(self: *Graph) void {
        self.allocator.free(self.edges);
        self.allocator.free(self.reachable);
    }
};

pub const Value = struct {
    kind: enum { unknown, integer, address, argument, result, stack } = .unknown,
    id: u64 = 0,
    context: u64 = 0,
    offset: i64 = 0,
    loads: [2]i64 = @splat(0),
    load_sites: [2]u64 = @splat(0),
    depth: u8 = 0,
    nullable: bool = false,
    bound: bool = false,

    pub fn equal(a: Value, b: Value) bool {
        return std.meta.eql(a, b);
    }
    pub fn samePointer(a: Value, b: Value) bool {
        var x = a;
        var y = b;
        x.nullable = false;
        y.nullable = false;
        x.bound = false;
        y.bound = false;
        return x.kind != .unknown and equal(x, y);
    }
    pub fn plus(self: Value, delta: i64) Value {
        var result = self;
        if (self.kind == .unknown) return .{};
        if (self.depth == 0 and (self.kind == .address or self.kind == .integer)) {
            result.id +%= @bitCast(delta);
        } else result.offset = std.math.add(i64, self.offset, delta) catch return .{};
        if (delta != 0) result.bound = false;
        return result;
    }
    pub fn load(self: Value, site: u64) Value {
        if (self.kind == .unknown or self.depth == self.loads.len) return .{};
        var result = self;
        result.loads[result.depth] = result.offset;
        result.load_sites[result.depth] = site;
        result.depth += 1;
        result.offset = 0;
        result.bound = false;
        return result;
    }
    pub fn location(self: Value) ?Value {
        if (self.depth == 0) return null;
        var result = self;
        result.depth -= 1;
        result.offset = result.loads[result.depth];
        result.loads[result.depth] = 0;
        result.load_sites[result.depth] = 0;
        return result;
    }
    pub fn addressIs(self: Value, address: u64, pie: bool) bool {
        return self.depth == 0 and self.offset == 0 and self.id == address and
            (self.kind == .address or (!pie and self.kind == .integer));
    }
    pub fn isZero(self: Value) bool {
        return self.kind == .integer and self.depth == 0 and self.id == 0;
    }
};

fn meet(a: Value, b: Value) Value {
    if (Value.equal(a, b)) return a;
    if (a.samePointer(b)) {
        var result = a;
        result.nullable = a.nullable or b.nullable;
        result.bound = a.bound and b.bound;
        return result;
    }
    // Keep the non-null return object's proof when joining allocation failure.
    if (a.isZero() and b.bound) {
        var result = b;
        result.nullable = true;
        return result;
    }
    if (b.isZero() and a.bound) return meet(b, a);
    return .{};
}

pub const Cell = struct { key: Value = .{}, value: Value = .{} };
pub const Slot = union(enum) { none, absolute: u64, field: i64 };
pub const State = struct {
    regs: [16]Value = @splat(.{}),
    cells: [48]Cell = @splat(.{}),
    escaped_stack: bool = false,
    zero_test: ?Value = null,

    pub fn entry(context: u64) State {
        var state: State = .{};
        for ([_]usize{ 7, 6, 2, 1, 8, 9 }) |reg|
            state.regs[reg] = .{ .kind = .argument, .id = reg, .context = context };
        state.regs[4] = .{ .kind = .stack, .context = context };
        return state;
    }
    pub fn get(self: State, key: Value) Value {
        for (self.cells) |cell| if (cell.key.samePointer(key)) return cell.value;
        return .{};
    }
    pub fn store(self: *State, key: Value, value: Value, width: u8, slot: Slot) !void {
        if (value.kind == .stack and key.kind != .stack) self.escaped_stack = true;
        const field_offset: i64 = switch (slot) {
            .field => |offset| offset,
            else => 0,
        };
        for (&self.regs) |*reg| {
            if (reg.bound and self.invalidates(reg.*, field_offset, key, value, width)) reg.bound = false;
        }
        for (&self.cells) |*cell| {
            if (cell.value.bound and self.invalidates(cell.value, field_offset, key, value, width)) cell.value.bound = false;
        }
        for (&self.cells) |*cell| {
            if (cell.key.kind == .unknown) continue;
            if (self.escaped_stack and key.kind != .stack and cell.key.kind == .stack) {
                cell.value = .{};
                continue;
            }
            if (mayOverlap(cell.key, key, width)) {
                if (cell.key.bound and !(cell.key.samePointer(key) and width == 8 and Value.equal(cell.value, value))) {
                    cell.key.bound = false;
                }
                cell.value = .{};
            }
        }
        if (width != 8 or key.kind == .unknown) return;
        const relevant = key.kind == .stack or switch (slot) {
            .none => false,
            .absolute => |address| key.addressIs(address, true),
            .field => |offset| key.depth == 0 and (key.kind == .address or
                (key.offset == offset and (key.kind == .argument or key.kind == .result))),
        };
        if (!relevant) return;
        for (&self.cells) |*cell| {
            if (cell.key.samePointer(key)) {
                cell.value = value;
                return;
            }
        }
        for (&self.cells) |*cell| {
            if (cell.key.kind == .unknown) {
                cell.* = .{ .key = key, .value = value };
                return;
            }
        }
        return error.ProvenanceMemoryLimit;
    }
    fn invalidates(self: State, object: Value, offset: i64, key: Value, value: Value, width: u8) bool {
        const location = object.plus(offset);
        const previous = self.get(location);
        return mayOverlap(location, key, width) and !(location.samePointer(key) and width == 8 and
            previous.kind != .unknown and Value.equal(previous, value));
    }
    pub fn merge(self: *State, incoming: State) bool {
        var changed = incoming.escaped_stack and !self.escaped_stack;
        self.escaped_stack = self.escaped_stack or incoming.escaped_stack;
        if (!std.meta.eql(self.zero_test, incoming.zero_test) and self.zero_test != null) {
            self.zero_test = null;
            changed = true;
        }
        for (&self.regs, incoming.regs) |*old, value| {
            const combined = meet(old.*, value);
            changed = changed or !Value.equal(old.*, combined);
            old.* = combined;
        }
        for (&self.cells) |*cell| {
            if (cell.key.kind == .unknown) continue;
            const combined = meet(cell.value, incoming.get(cell.key));
            changed = changed or !Value.equal(cell.value, combined);
            cell.value = combined;
            var published = false;
            for (incoming.cells) |other| if (other.key.samePointer(cell.key)) {
                published = other.key.bound;
            };
            if (cell.key.bound and !published) {
                cell.key.bound = false;
                changed = true;
            }
        }
        return changed;
    }
    pub fn markBound(self: *State, object: Value) void {
        for (&self.regs) |*value| if (value.samePointer(object)) {
            value.bound = true;
        };
        for (&self.cells) |*cell| if (cell.value.samePointer(object)) {
            cell.value.bound = true;
        };
    }
};

fn mayOverlap(cell: Value, destination: Value, width: u8) bool {
    if (destination.kind == .unknown) return cell.kind != .stack;
    if (cell.kind == .stack or destination.kind == .stack) {
        if (cell.kind != destination.kind or cell.context != destination.context) return false;
    }
    var a = cell;
    var b = destination;
    const x: i128 = if (a.kind == .address and a.depth == 0) a.id else a.offset;
    const y: i128 = if (b.kind == .address and b.depth == 0) b.id else b.offset;
    if (a.kind == .address and a.depth == 0) a.id = 0 else a.offset = 0;
    if (b.kind == .address and b.depth == 0) b.id = 0 else b.offset = 0;
    if (!a.samePointer(b)) return true;
    return x < y + width and y < x + 8;
}

pub fn pair(instruction: Instruction) ?[2][]const u8 {
    return assembly.splitOperands(instruction);
}

pub fn memory(state: State, instruction: Instruction, operand: []const u8) Value {
    var text = std.mem.trim(u8, operand[0 .. std.mem.indexOfScalar(u8, operand, '#') orelse operand.len], " \t");
    if (std.mem.startsWith(u8, text, "*")) text = text[1..];
    if (std.mem.indexOfScalar(u8, text, ':') != null) return .{};
    const open = std.mem.indexOfScalar(u8, text, '(') orelse {
        return .{ .kind = .address, .id = assembly.hex(text) catch return .{} };
    };
    if (!std.mem.endsWith(u8, text, ")")) return .{};
    const displacement = if (open == 0) 0 else std.fmt.parseInt(i64, text[0..open], 0) catch return .{};
    var fields = std.mem.splitScalar(u8, text[open + 1 .. text.len - 1], ',');
    const base = fields.next().?;
    var value: Value = if (std.mem.eql(u8, base, "%rip"))
        .{ .kind = .address, .id = instruction.address + instruction.size }
    else if (assembly.register(base)) |reg|
        state.regs[reg]
    else
        return .{};
    value = value.plus(displacement);
    if (fields.next()) |index| {
        const reg = assembly.register(index) orelse return .{};
        const scale = std.fmt.parseInt(i64, fields.next() orelse "1", 10) catch return .{};
        if (scale != 1 and scale != 2 and scale != 4 and scale != 8) return .{};
        const index_value = state.regs[reg];
        if (index_value.kind != .integer or index_value.depth != 0) return .{};
        const delta = std.math.mul(i64, @bitCast(index_value.id), scale) catch return .{};
        value = value.plus(delta);
    }
    return value;
}

fn source(state: State, instruction: Instruction, operand: []const u8) Value {
    if (assembly.register(operand)) |reg| return state.regs[reg];
    if (assembly.immediate(operand)) |integer| return .{ .kind = .integer, .id = integer };
    const location = memory(state, instruction, operand);
    const stored = state.get(location);
    return if (stored.kind == .unknown) location.load(instruction.address) else stored;
}

pub const Options = struct {
    context: u64 = 1,
    pie: bool = false,
    slot: Slot = .none,
    hook_context: ?*anyopaque = null,
    call_hook: ?*const fn (?*anyopaque, Instruction, *State, Options) anyerror!void = null,
    work_counter: ?*usize = null,
    reject_call_cycles: bool = false,
};

pub fn clobberCall(state: *State, instruction: Instruction, options: Options) void {
    state.zero_test = null;
    for (&state.cells) |*cell| {
        if (cell.key.kind == .result and cell.key.id == instruction.address and cell.key.context == options.context)
            cell.* = .{};
    }

    for (&state.regs) |*value| {
        if (value.kind == .result and value.id == instruction.address and value.context == options.context)
            value.bound = false;
    }
    for ([_]usize{ 0, 1, 2, 6, 7, 8, 9, 10, 11 }) |reg| state.regs[reg] = .{};
    state.regs[0] = .{ .kind = .result, .id = instruction.address, .context = options.context };
}

pub fn unknownCall(state: *State, instruction: Instruction, options: Options) !void {
    for ([_]usize{ 7, 6, 2, 1, 8, 9 }) |reg| {
        if (state.regs[reg].kind == .stack) state.escaped_stack = true;
    }
    try state.store(.{}, .{}, 16, options.slot);
    if (state.escaped_stack) {
        for (&state.cells) |*cell| {
            if (cell.key.kind == .stack) cell.value = .{};
        }
    }
    clobberCall(state, instruction, options);
}

fn step(state: *State, instruction: Instruction, options: Options) !void {
    const op = instruction.op;
    if (instruction.unknown()) return error.UnsupportedProvenanceInstruction;
    if (instruction.isCall()) {
        if (options.call_hook) |hook| try hook(options.hook_context, instruction, state, options) else try unknownCall(state, instruction, options);
        return;
    }
    if (instruction.isBranch() or instruction.stops()) {
        if (std.mem.startsWith(u8, op, "loop")) state.regs[1] = .{};
        return;
    }
    if (std.mem.startsWith(u8, op, "test") or std.mem.startsWith(u8, op, "cmp")) {
        state.zero_test = null;
        if (pair(instruction)) |operands| {
            if (assembly.register(operands[1])) |reg| {
                if (assembly.registerWidth(operands[1]) == 64 and
                    ((std.mem.startsWith(u8, op, "test") and std.mem.eql(u8, operands[0], operands[1])) or
                        (std.mem.startsWith(u8, op, "cmp") and assembly.immediate(operands[0]) == 0)))
                    state.zero_test = state.regs[reg];
            }
        }
    } else if (!std.mem.startsWith(u8, op, "mov") and !std.mem.startsWith(u8, op, "lea") and
        !std.mem.startsWith(u8, op, "nop") and !std.mem.startsWith(u8, op, "push") and !std.mem.startsWith(u8, op, "pop"))
        state.zero_test = null;
    for ([_][]const u8{ "movsb", "movsw", "movsl", "movsq", "stosb", "stosw", "stosl", "stosq", "lodsb", "lodsw", "lodsl", "lodsq" }) |string_op| {
        if (std.mem.eql(u8, op, string_op)) {
            for ([_]usize{ 0, 1, 6, 7 }) |reg| state.regs[reg] = .{};
            try state.store(.{}, .{}, 16, options.slot);
            return;
        }
    }
    for ([_][]const u8{ "cmp", "cmpb", "cmpw", "cmpl", "cmpq", "test", "testb", "testw", "testl", "testq", "nop", "nopl", "nopw", "endbr64", "pause", "cli", "sti", "cld", "std", "clc", "stc", "cmc", "lfence", "sfence", "mfence", "wrmsr" }) |neutral|
        if (std.mem.eql(u8, op, neutral)) return;
    if (std.mem.eql(u8, op, "pushq") or std.mem.eql(u8, op, "push") or std.mem.eql(u8, op, "pushfq")) {
        const value = source(state.*, instruction, instruction.operands);
        state.regs[4] = state.regs[4].plus(-8);
        try state.store(state.regs[4], value, 8, options.slot);
        return;
    }
    if (std.mem.eql(u8, op, "popq") or std.mem.eql(u8, op, "pop") or std.mem.eql(u8, op, "popfq")) {
        if (std.mem.eql(u8, op, "popfq")) state.zero_test = null;
        const value = state.get(state.regs[4]);
        if (assembly.register(instruction.operands)) |reg| state.regs[reg] = value else if (!std.mem.eql(u8, op, "popfq"))
            try state.store(memory(state.*, instruction, instruction.operands), value, 8, options.slot);
        state.regs[4] = state.regs[4].plus(8);
        return;
    }
    if (pair(instruction)) |operands| {
        const destination = assembly.register(operands[1]);
        const exchange_location = if (std.mem.startsWith(u8, op, "xchg") or std.mem.startsWith(u8, op, "xadd"))
            memory(state.*, instruction, operands[0])
        else
            Value{};
        var value = source(state.*, instruction, operands[0]);
        if (std.mem.startsWith(u8, op, "lea")) value = memory(state.*, instruction, operands[0]);
        if (std.mem.eql(u8, op, "xor") or std.mem.eql(u8, op, "xorl") or std.mem.eql(u8, op, "xorq")) {
            if (std.mem.eql(u8, operands[0], operands[1])) value = .{ .kind = .integer } else value = .{};
        } else if (std.mem.eql(u8, op, "addq") or std.mem.eql(u8, op, "subq")) {
            if (destination) |reg| {
                const delta = assembly.immediate(operands[0]);
                value = if (delta) |n| state.regs[reg].plus(if (op[0] == 's') -%@as(i64, @bitCast(n)) else @bitCast(n)) else .{};
            }
        } else if (!std.mem.eql(u8, op, "mov") and !std.mem.eql(u8, op, "movq") and
            !std.mem.eql(u8, op, "movl") and !std.mem.eql(u8, op, "movabsq") and
            !std.mem.eql(u8, op, "movabs") and !std.mem.startsWith(u8, op, "lea")) value = .{};
        if (destination) |reg| {
            const width = assembly.registerWidth(operands[1]).?;
            if (width < 64) {
                if (width == 32 and value.kind == .integer and value.depth == 0)
                    value.id = @as(u32, @truncate(value.id))
                else
                    value = .{};
            }
            state.regs[reg] = value;
        } else if (std.mem.indexOfScalar(u8, operands[1], '%') != null and
            (std.mem.startsWith(u8, operands[1], "%xmm") or std.mem.startsWith(u8, operands[1], "%ymm")))
        {
            // Constructor SIMD writes only the explicit vector destination.
        } else {
            const width: u8 = if (std.mem.eql(u8, op, "movq") or std.mem.eql(u8, op, "mov")) 8 else if (std.mem.endsWith(u8, op, "b")) 1 else if (std.mem.endsWith(u8, op, "w")) 2 else if (std.mem.endsWith(u8, op, "l")) 4 else 16;
            if (!std.mem.startsWith(u8, op, "mov")) value = .{};
            try state.store(memory(state.*, instruction, operands[1]), value, width, options.slot);
        }
        if (std.mem.startsWith(u8, op, "xchg") or std.mem.startsWith(u8, op, "xadd")) {
            if (assembly.register(operands[0])) |reg_source|
                state.regs[reg_source] = .{}
            else
                try state.store(exchange_location, .{}, 16, options.slot);
        }
        if (std.mem.startsWith(u8, op, "cmpxchg")) {
            state.regs[0] = .{};
            state.regs[2] = .{};
        }
        return;
    }
    if (assembly.register(instruction.operands)) |reg| {
        state.regs[reg] = .{};
        if (std.mem.startsWith(u8, op, "mul") or std.mem.startsWith(u8, op, "div") or std.mem.startsWith(u8, op, "idiv") or std.mem.startsWith(u8, op, "imul")) {
            state.regs[0] = .{};
            state.regs[2] = .{};
        }
        return;
    }
    state.* = .{};
}

pub const Analysis = struct {
    graph: Graph,
    before: []State,
    after: []State,
    seen: []bool,

    pub fn run(allocator: std.mem.Allocator, instructions: []const Instruction, initial: State, options: Options) !Analysis {
        var graph = try Graph.init(allocator, instructions);
        errdefer graph.deinit();
        for (instructions, 0..) |item, i| {
            if (graph.reachable[i] and item.isBranch() and !item.isCall() and !item.isJump() and graph.edges[i][0] == null)
                return error.UnsupportedControlFlow;
            if (graph.reachable[i] and item.isJump() and item.indirect()) return error.UnsupportedControlFlow;
            if (graph.reachable[i] and i + 1 == instructions.len and !item.stops() and !item.isJump())
                return error.UnterminatedBindingFunction;
            if (options.reject_call_cycles and graph.reachable[i]) {
                for (graph.edges[i]) |edge| if (edge) |target| {
                    if (target > i) continue;
                    // Allocation-site identities cannot distinguish loop iterations.
                    for (instructions[target .. i + 1]) |member|
                        if (member.isCall()) return error.CyclicSchedulerBinding;
                };
            }
        }
        const before = try allocator.alloc(State, instructions.len);
        errdefer allocator.free(before);
        const after = try allocator.alloc(State, instructions.len);
        errdefer allocator.free(after);
        const seen = try allocator.alloc(bool, instructions.len);
        errdefer allocator.free(seen);
        @memset(seen, false);
        before[0] = initial;
        seen[0] = true;
        var pending: std.ArrayList(usize) = .empty;
        defer pending.deinit(allocator);
        try pending.append(allocator, 0);
        var work: usize = 0;
        while (pending.pop()) |index| {
            work += 1;
            if (work > max_work) return error.ControlFlowLimit;
            if (options.work_counter) |counter| {
                if (counter.* >= max_work) return error.ControlFlowLimit;
                counter.* += 1;
            }
            var state = before[index];
            try step(&state, instructions[index], options);
            if (instructions[index].isJump() and !instructions[index].indirect() and graph.edges[index][0] == null) {
                if (options.call_hook) |hook| try hook(options.hook_context, instructions[index], &state, options);
            }
            after[index] = state;
            for (graph.edges[index], 0..) |successor, edge_index| {
                const next = successor orelse continue;
                var outgoing = state;
                const op = instructions[index].op;
                const equal = std.mem.eql(u8, op, "je") or std.mem.eql(u8, op, "jz");
                const unequal = std.mem.eql(u8, op, "jne") or std.mem.eql(u8, op, "jnz");
                if ((equal or unequal) and state.zero_test != null) {
                    const tested = state.zero_test.?;
                    const zero_edge = if (equal) edge_index == 0 else edge_index == 1;
                    if (tested.kind == .integer and tested.depth == 0 and tested.isZero() != zero_edge) continue;
                    for (&outgoing.regs) |*value| {
                        if (!value.samePointer(tested)) continue;
                        if (zero_edge) value.* = .{ .kind = .integer } else value.nullable = false;
                    }
                    for (&outgoing.cells) |*cell| {
                        if (!cell.value.samePointer(tested)) continue;
                        if (zero_edge) cell.value = .{ .kind = .integer } else cell.value.nullable = false;
                    }
                }
                if (!seen[next]) {
                    seen[next] = true;
                    before[next] = outgoing;
                    try pending.append(allocator, next);
                } else if (before[next].merge(outgoing)) try pending.append(allocator, next);
            }
        }
        return .{ .graph = graph, .before = before, .after = after, .seen = seen };
    }
    pub fn deinit(self: *Analysis) void {
        const allocator = self.graph.allocator;
        allocator.free(self.before);
        allocator.free(self.after);
        allocator.free(self.seen);
        self.graph.deinit();
    }
};
