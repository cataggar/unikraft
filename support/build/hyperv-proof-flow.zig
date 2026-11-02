// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const assembly = @import("hyperv-proof-disasm.zig");
const machine = @import("hyperv-proof-instructions.zig");
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
    kind: enum { unknown, integer, address, argument, result, stack, lost_stack, allocator, heap, scheduler_list } = .unknown,
    id: u64 = 0,
    context: u64 = 0,
    offset: i64 = 0,
    loads: [2]i64 = @splat(0),
    load_sites: [2]u64 = @splat(0),
    depth: u8 = 0,
    nullable: bool = false,
    bound: bool = false,
    upper: ?u64 = null,
    size: u64 = 0,
    alignment: u64 = 1,
    aligned: u64 = 1,
    bits: u8 = 64,
    link: i64 = 0,

    pub fn equal(a: Value, b: Value) bool {
        return std.meta.eql(a, b);
    }
    fn ownStack(self: Value) bool {
        return self.kind == .lost_stack or (self.kind == .stack and self.depth == 0);
    }
    pub fn samePointer(a: Value, b: Value) bool {
        var x = a;
        var y = b;
        x.nullable = false;
        y.nullable = false;
        x.bound = false;
        y.bound = false;
        x.aligned = 1;
        y.aligned = 1;
        // A list set denotes potentially different nodes, never an exact alias.
        return x.kind != .unknown and x.kind != .lost_stack and x.kind != .scheduler_list and x.upper == null and equal(x, y);
    }
    pub fn plus(self: Value, delta: i64) Value {
        var result = self;
        if (self.kind == .unknown) return .{};
        if (self.kind == .lost_stack) return self;
        if (self.depth == 0 and (self.kind == .address or self.kind == .integer)) {
            result.id +%= @bitCast(delta);
            if (result.upper) |upper| result.upper = std.math.add(u64, upper, @bitCast(delta)) catch return .{};
        } else result.offset = std.math.add(i64, self.offset, delta) catch return if (self.ownStack()) .{ .kind = .lost_stack } else .{};
        if (self.kind == .heap and self.upper != null) {
            result.upper = if (delta < 0) std.math.sub(u64, self.upper.?, @intCast(-delta)) catch return .{} else std.math.add(u64, self.upper.?, @intCast(delta)) catch return .{};
        }
        if (delta != 0) result.bound = false;
        if (delta != 0 and self.kind == .heap) result.aligned = std.math.gcd(self.aligned, @abs(delta));
        return result;
    }
    pub fn load(self: Value, site: u64) Value {
        if (self.kind == .lost_stack) return self;
        if (self.kind == .scheduler_list and self.depth == 0 and self.offset == self.link) {
            var next = self;
            next.offset = 0;
            next.nullable = true;
            return next;
        }
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
        return self.bits == 64 and self.depth == 0 and self.offset == 0 and self.upper == null and !self.nullable and self.id == address and
            (self.kind == .address or (!pie and self.kind == .integer));
    }
    pub fn isZero(self: Value) bool {
        return self.bits == 64 and self.kind == .integer and self.depth == 0 and self.upper == null and self.id == 0;
    }
    pub fn high(self: Value) u64 {
        return self.upper orelse self.id;
    }
};

fn meet(a: Value, b: Value) Value {
    if (Value.equal(a, b)) return a;
    if (a.kind == .integer and b.kind == .integer and a.depth == 0 and b.depth == 0 and a.bits == 64 and b.bits == 64)
        return .{ .kind = .integer, .id = @min(a.id, b.id), .upper = @max(a.upper orelse a.id, b.upper orelse b.id) };
    if (a.samePointer(b)) {
        var result = a;
        result.nullable = a.nullable or b.nullable;
        result.bound = a.bound and b.bound;
        result.aligned = @min(a.aligned, b.aligned);
        return result;
    }
    // Keep the non-null return object's proof when joining allocation failure.
    if (a.isZero() and (b.bound or b.kind == .heap)) {
        var result = b;
        result.nullable = true;
        return result;
    }
    if (b.isZero() and (a.bound or a.kind == .heap)) return meet(b, a);
    if (a.ownStack() or b.ownStack()) return .{ .kind = .lost_stack };
    return .{};
}

pub const Cell = struct { key: Value = .{}, value: Value = .{} };
pub const Slot = union(enum) { none, absolute: u64, field: i64 };
pub const Region = struct { start: u64, end: u64 };
pub fn inHeap(key: Value, width: u64) bool {
    if (key.kind != .heap or key.bits != 64 or key.depth != 0 or key.nullable or key.offset < 0) return false;
    const last = key.upper orelse @as(u64, @intCast(key.offset));
    return last <= key.size and width <= key.size - last;
}
pub const State = struct {
    regs: [16]Value = @splat(.{}),
    vector_zero: [32]u8 = @splat(0),
    cells: [192]Cell = @splat(.{}),
    escaped_stack: bool = false,
    zero_test: ?Value = null,
    sign_test: ?bool = null,
    comparison: ?struct { reg: u4, left: Value, right: Value, width: u8 } = null,
    globals: []const Region = &.{},
    constant_writes: [64]Region = @splat(.{ .start = 0, .end = 0 }),
    constants_unknown: bool = false,

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
    fn exposeStackCells(self: *State, location: Value, width: u64) void {
        for (self.cells) |cell| {
            if (cell.value.ownStack() and self.overlaps(cell.key, location, width)) {
                self.escaped_stack = true;
                return;
            }
        }
    }
    pub fn global(self: State, key: Value, width: u64) bool {
        if (key.kind != .address or key.depth != 0) return false;
        for (self.globals) |region|
            if (key.id >= region.start and key.id < region.end and (key.upper orelse key.id) <= region.end and width <= region.end - (key.upper orelse key.id)) return true;
        return false;
    }
    pub fn overlaps(self: State, cell: Value, destination: Value, width: u64) bool {
        if (inList(destination, width) and self.global(cell, 8)) return false;
        if (inList(destination, width) and inHeap(cell, 8)) {
            if (cell.id != destination.id or cell.context != destination.context) return false;
            return cell.offset < destination.offset + @as(i64, @intCast(width)) and destination.offset < cell.offset + 8;
        }
        if (inHeap(cell, 8) and self.global(destination, width)) return false;
        if (inHeap(destination, width) and self.global(cell, 8)) return false;
        if (inHeap(cell, 8) and inHeap(destination, width) and
            (cell.id != destination.id or cell.context != destination.context) and
            cell.size != 0 and destination.size != 0) return false;
        return mayOverlap(cell, destination, width);
    }
    fn recordWrite(self: *State, region: Region) void {
        for (&self.constant_writes) |*old| {
            if (old.end == 0 or (region.start <= old.end and region.end >= old.start)) {
                old.* = if (old.end == 0) region else .{ .start = @min(old.start, region.start), .end = @max(old.end, region.end) };
                return;
            }
        }
        self.constants_unknown = true;
    }
    pub fn canReadInitial(self: State, location: Value, width: u64) bool {
        if (self.constants_unknown or location.kind != .address or location.depth != 0 or location.upper != null) return false;
        const end = std.math.add(u64, location.id, width) catch return false;
        for (self.constant_writes) |written|
            if (location.id < written.end and end > written.start) return false;
        return true;
    }
    pub fn store(self: *State, key: Value, value: Value, width: u64, slot: Slot) !void {
        if (width == 0) return;
        if (key.kind == .lost_stack) return error.UnprovenMemoryFootprint;
        if (value.kind == .lost_stack or (value.ownStack() and width < 8)) return error.UnsupportedProvenanceInstruction;
        if (key.kind == .address and key.depth == 0) {
            const end = std.math.add(u64, key.upper orelse key.id, width) catch return error.UnprovenMemoryFootprint;
            self.recordWrite(.{ .start = key.id, .end = end });
        } else if (!(key.kind == .stack and key.depth == 0) and !inHeap(key, width) and !inList(key, width)) {
            self.constants_unknown = true;
        }
        if (value.kind == .stack and key.kind != .stack) self.escaped_stack = true;
        const field_offset: i64 = switch (slot) {
            .field => |offset| offset,
            else => 0,
        };
        if (key.kind == .scheduler_list and slot == .field and
            (!inList(key, width) or (key.offset < field_offset + 8 and @as(i128, key.offset) + width > field_offset)))
            return error.InvalidRegisteredSchedulerWrite;
        if (key.kind == .scheduler_list and key.offset < key.link + 8 and @as(i128, key.offset) + width > key.link) {
            const valid_link = value.isZero() or (value.depth == 0 and value.offset == 0 and value.upper == null and
                value.bits == 64 and value.id == key.id and value.context == key.context and
                ((value.kind == .heap and !value.nullable) or
                    (value.kind == .scheduler_list and value.link == key.link and value.size == key.size)));
            if (key.offset != key.link or width != 8 or !valid_link) return error.InvalidSchedulerListLink;
        }
        for (&self.regs) |*reg| {
            if (reg.bound and self.invalidates(reg.*, field_offset, key, value, width)) reg.bound = false;
        }
        for (&self.cells) |*cell| {
            if (cell.value.bound and self.invalidates(cell.value, field_offset, key, value, width)) cell.value.bound = false;
        }
        for (&self.cells) |*cell| {
            if (cell.key.kind == .unknown) continue;
            if (self.escaped_stack and key.kind != .stack and cell.key.kind == .stack and
                !inHeap(key, width) and !self.global(key, width) and !inList(key, width))
            {
                cell.value = .{};
                continue;
            }
            if (self.overlaps(cell.key, key, width)) {
                // A partial overwrite can leave a recoverable stack pointer in
                // otherwise unknown bytes. Later opaque writes must account for it.
                if (cell.value.ownStack() and !coversCell(key, width, cell.key)) self.escaped_stack = true;
                if (cell.key.bound and !(cell.key.samePointer(key) and width == 8 and Value.equal(cell.value, value))) {
                    cell.key.bound = false;
                }
                cell.value = .{};
            }
        }
        if ((width != 8 and !(width <= 4 and std.math.isPowerOfTwo(width) and value.kind == .integer)) or key.kind == .unknown or key.upper != null) return;
        var stored_value = value;
        if (width < 8) stored_value.bits = @intCast(width * 8);
        const relevant = key.kind == .stack or switch (slot) {
            .none => false,
            .absolute => |address| key.addressIs(address, true),
            .field => |offset| key.depth == 0 and (key.kind == .heap or key.kind == .address or
                (key.offset == offset and (key.kind == .argument or key.kind == .result))),
        };
        if (!relevant) return;
        for (&self.cells) |*cell| {
            if (cell.key.samePointer(key)) {
                cell.value = stored_value;
                return;
            }
        }
        for (&self.cells) |*cell| {
            if (cell.key.kind == .unknown or (cell.value.kind == .unknown and !cell.key.bound)) {
                cell.* = .{ .key = key, .value = stored_value };
                return;
            }
        }
        return error.ProvenanceMemoryLimit;
    }
    fn invalidates(self: State, object: Value, offset: i64, key: Value, value: Value, width: u64) bool {
        const location = object.plus(offset);
        const previous = self.get(location);
        return self.overlaps(location, key, width) and !(location.samePointer(key) and width == 8 and
            previous.kind != .unknown and Value.equal(previous, value));
    }
    pub fn merge(self: *State, incoming: State) bool {
        var changed = incoming.escaped_stack and !self.escaped_stack;
        self.escaped_stack = self.escaped_stack or incoming.escaped_stack;
        for (&self.vector_zero, incoming.vector_zero) |*old, zero| {
            changed = changed or old.* > zero;
            old.* = @min(old.*, zero);
        }
        const old_writes = self.constant_writes;
        const old_unknown = self.constants_unknown;
        self.constants_unknown = self.constants_unknown or incoming.constants_unknown;
        for (incoming.constant_writes) |region| if (region.end != 0) self.recordWrite(region);
        changed = changed or !std.meta.eql(old_writes, self.constant_writes) or old_unknown != self.constants_unknown;
        if (!std.meta.eql(self.zero_test, incoming.zero_test) and self.zero_test != null) {
            self.zero_test = null;
            changed = true;
        }
        if (!std.meta.eql(self.comparison, incoming.comparison) and self.comparison != null) {
            self.comparison = null;
            changed = true;
        }
        if (self.sign_test != incoming.sign_test and self.sign_test != null) {
            self.sign_test = null;
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
        // The must-cell intersection can omit an incoming-only stack alias.
        // Retain its possible escape even when no exact cell survives the join.
        if (!self.escaped_stack) for (incoming.cells) |cell| {
            if (cell.value.ownStack() and !self.get(cell.key).ownStack()) {
                self.escaped_stack = true;
                changed = true;
                break;
            }
        };
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

fn inList(key: Value, width: u64) bool {
    return key.kind == .scheduler_list and key.bits == 64 and key.depth == 0 and key.upper == null and key.offset >= 0 and
        @as(u64, @intCast(key.offset)) <= key.size and width <= key.size - @as(u64, @intCast(key.offset));
}

fn mayOverlap(cell: Value, destination: Value, width: u64) bool {
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

fn coversCell(destination: Value, width: u64, cell: Value) bool {
    var a = destination;
    var b = cell;
    const start: i128 = if (a.kind == .address and a.depth == 0) a.id else a.offset;
    const offset: i128 = if (b.kind == .address and b.depth == 0) b.id else b.offset;
    if (a.kind == .address and a.depth == 0) a.id = 0 else a.offset = 0;
    if (b.kind == .address and b.depth == 0) b.id = 0 else b.offset = 0;
    return a.samePointer(b) and start <= offset and start + width >= offset + 8;
}

pub fn pair(instruction: Instruction) ?[2][]const u8 {
    return assembly.splitOperands(instruction);
}

pub fn memory(state: State, instruction: Instruction, operand: []const u8) Value {
    return checkedMemory(state, instruction, operand) catch .{};
}

fn checkedMemory(state: State, instruction: Instruction, operand: []const u8) error{UnsupportedProvenanceInstruction}!Value {
    const text = std.mem.trim(u8, operand[0 .. std.mem.indexOfScalar(u8, operand, '#') orelse operand.len], " \t");
    if (instruction.hasAddressOverride() or std.mem.indexOfAny(u8, text, ":{}*") != null)
        return error.UnsupportedProvenanceInstruction;
    const open = std.mem.indexOfScalar(u8, text, '(') orelse {
        return .{ .kind = .address, .id = std.fmt.parseInt(u64, text, 0) catch return error.UnsupportedProvenanceInstruction };
    };
    if (!std.mem.endsWith(u8, text, ")")) return error.UnsupportedProvenanceInstruction;
    const displacement = if (open == 0) 0 else std.fmt.parseInt(i64, text[0..open], 0) catch return error.UnsupportedProvenanceInstruction;
    var fields = std.mem.splitScalar(u8, text[open + 1 .. text.len - 1], ',');
    const base = std.mem.trim(u8, fields.next().?, " \t");
    const index_text = fields.next();
    const scale_text = fields.next();
    if (fields.next() != null) return error.UnsupportedProvenanceInstruction;
    const rip = std.mem.eql(u8, base, "%rip");
    const base_reg = if (base.len != 0 and !rip) assembly.register(base) orelse return error.UnsupportedProvenanceInstruction else null;
    if ((base_reg != null and assembly.registerWidth(base) != 64) or
        (base.len == 0 and index_text == null) or (rip and index_text != null))
        return error.UnsupportedProvenanceInstruction;
    const index_reg = if (index_text) |index| assembly.register(index) orelse return error.UnsupportedProvenanceInstruction else null;
    if (index_text) |index| if (assembly.registerWidth(index) != 64) {
        return error.UnsupportedProvenanceInstruction;
    };
    const scale = if (scale_text) |text_scale| std.fmt.parseInt(i64, std.mem.trim(u8, text_scale, " \t"), 10) catch return error.UnsupportedProvenanceInstruction else 1;
    if (scale != 1 and scale != 2 and scale != 4 and scale != 8) return error.UnsupportedProvenanceInstruction;
    const base_value: Value = if (rip)
        .{ .kind = .address, .id = std.math.add(u64, instruction.address, instruction.size) catch return error.UnsupportedProvenanceInstruction }
    else if (base_reg) |reg| state.regs[reg] else .{ .kind = .integer };
    const index_value: Value = if (index_reg) |reg| state.regs[reg] else .{ .kind = .integer };
    if (base_value.bits != 64 or index_value.bits != 64) return error.UnsupportedProvenanceInstruction;
    if (base_value.kind == .lost_stack or index_value.kind == .lost_stack) return .{ .kind = .lost_stack };
    const result = evaluateMemory(state, base_value.plus(displacement), if (index_reg != null) index_value else null, scale);
    if (result.kind == .unknown and (base_value.kind == .stack or index_value.kind == .stack))
        return error.UnsupportedProvenanceInstruction;
    return result;
}

fn evaluateMemory(state: State, base: Value, index: ?Value, scale: i64) Value {
    var value = base;
    if (index) |index_value| {
        if (scale == 1 and value.kind == .integer and value.depth == 0 and value.upper == null and
            index_value.depth == 0 and (index_value.kind == .heap or index_value.kind == .address or index_value.kind == .stack))
            return index_value.plus(@bitCast(value.id));
        if (index_value.kind != .integer or index_value.depth != 0) return .{};
        if (index_value.upper) |upper| {
            if (value.kind != .address or value.upper != null or upper > 8192) return .{};
            const max_offset = std.math.mul(u64, upper, @intCast(scale)) catch return .{};
            const last = std.math.add(u64, value.id, max_offset) catch return .{};
            const first = std.math.add(u64, value.id, std.math.mul(u64, index_value.id, @intCast(scale)) catch return .{}) catch return .{};
            var bounded = false;
            for (state.globals) |region|
                if (value.id >= region.start and last < region.end) {
                    bounded = true;
                };
            return if (bounded) .{ .kind = .address, .id = first, .upper = last } else .{};
        }
        const delta = std.math.mul(i64, @bitCast(index_value.id), scale) catch return .{};
        value = value.plus(delta);
    }
    return value;
}

fn storeOperand(instruction: Instruction, operand: []const u8) !struct { address: []const u8, masked: bool } {
    const text = std.mem.trim(u8, operand, " \t");
    const mask = std.mem.indexOfScalar(u8, text, '{') orelse return .{ .address = text, .masked = false };
    const decoration = text[mask..];
    if (!machine.vectorMove(instruction.op) or decoration.len != 5 or !std.mem.startsWith(u8, decoration, "{%k") or
        decoration[3] < '1' or decoration[3] > '7' or decoration[4] != '}')
        return error.UnsupportedProvenanceInstruction;
    return .{ .address = std.mem.trim(u8, text[0..mask], " \t"), .masked = true };
}

fn undecodedRead(state: State, operand: []const u8) Value {
    // This only retains possible origin on failed reads; it never authorizes
    // a memory write or interprets an undecoded address as an exact location.
    var tokens = std.mem.tokenizeAny(u8, operand, " \t(),:{}*+");
    while (tokens.next()) |token| {
        if (assembly.register(token)) |reg| if (state.regs[reg].ownStack()) return .{ .kind = .lost_stack };
    }
    return .{};
}

pub fn source(state: State, instruction: Instruction, operand: []const u8) Value {
    if (assembly.register(operand)) |reg| {
        var value = state.regs[reg];
        const width = assembly.registerWidth(operand).?;
        const shift = assembly.registerBitOffset(operand);
        if (value.kind == .lost_stack or (width < 64 and value.ownStack())) return .{ .kind = .lost_stack };
        if (value.kind == .integer) {
            if (value.depth != 0 or @as(u16, width) + shift > value.bits or (shift != 0 and value.upper != null)) return .{};
            const mask: u64 = if (width == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(width)) - 1;
            if (value.upper == null) {
                value.id = (value.id >> shift) & mask;
                value.bits = 64;
            } else if (value.high() > mask) value = .{ .kind = .integer, .id = 0, .upper = mask } else value.bits = 64;
        } else if (width < 64) return .{};
        return value;
    }
    if (assembly.immediate(operand)) |integer| return .{ .kind = .integer, .id = integer };
    if (operand.len == 0 or machine.vectorIndex(operand) != null) return .{};
    const location = checkedMemory(state, instruction, operand) catch return undecodedRead(state, operand);
    if (location.kind == .lost_stack) return location;
    const stored = state.get(location);
    for (state.cells) |cell| {
        if (cell.value.ownStack() and !cell.key.samePointer(location) and
            state.overlaps(cell.key, location, machine.readBits(instruction) / 8))
            return .{ .kind = .lost_stack };
    }
    if (stored.kind == .lost_stack or (machine.readBits(instruction) < 64 and stored.ownStack())) return .{ .kind = .lost_stack };
    if (stored.kind == .integer) {
        const width = machine.readBits(instruction);
        if (stored.depth != 0 or width > stored.bits) return .{};
        var value = stored;
        value.bits = 64;
        if (width < 64 and value.upper == null) value.id &= (@as(u64, 1) << @intCast(width)) - 1;
        return value;
    }
    if (machine.readBits(instruction) < 64) return .{};
    if (stored.kind == .unknown and location.kind == .integer) return .{};
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
    constant_context: ?*anyopaque = null,
    constant_read: ?*const fn (?*anyopaque, Value, u8) anyerror!?Value = null,
};

pub fn callReturnAddress(state: *State, instruction: Instruction, options: Options) !void {
    if (instruction.isCall())
        try state.store(state.regs[4].plus(-8), .{ .kind = .address, .id = try std.math.add(u64, instruction.address, instruction.size) }, 8, options.slot);
}

pub fn clobberCall(state: *State, instruction: Instruction, options: Options) void {
    state.vector_zero = @splat(0);
    state.zero_test = null;
    state.comparison = null;
    state.sign_test = null;
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

pub fn writeRegister(state: *State, reg: u4, width: u8, incoming: Value) !void {
    if (incoming.kind == .lost_stack or (width < 64 and incoming.ownStack()) or
        (width < 32 and state.regs[reg].ownStack())) return error.UnsupportedProvenanceInstruction;
    var value = incoming;
    if (width == 64) {
        state.regs[reg] = value;
        return;
    }
    const mask = (@as(u64, 1) << @intCast(width)) - 1;
    if (value.kind == .integer and value.depth == 0) {
        if (value.upper == null) value.id &= mask else if (value.high() > mask) value = .{ .kind = .integer, .id = 0, .upper = mask };
        if (width == 32) {
            value.bits = 64;
        } else if (state.regs[reg].kind == .integer and state.regs[reg].upper == null and value.upper == null) {
            value.id |= state.regs[reg].id & ~mask;
            value.bits = state.regs[reg].bits;
        } else value.bits = width;
    } else value = if (width == 32) .{ .kind = .integer, .id = 0, .upper = mask } else .{};
    state.regs[reg] = value;
}

pub fn writeOperand(state: *State, operand: []const u8, incoming: Value) !void {
    const reg = assembly.register(operand) orelse return error.UnsupportedProvenanceInstruction;
    if (assembly.registerBitOffset(operand) == 0) {
        try writeRegister(state, reg, assembly.registerWidth(operand).?, incoming);
        return;
    }
    const previous = state.regs[reg];
    if (previous.kind != .integer or previous.depth != 0 or previous.upper != null or previous.bits < 8 or
        incoming.kind != .integer or incoming.depth != 0 or incoming.upper != null or incoming.bits < 8)
        return error.UnsupportedProvenanceInstruction;
    const previous_mask: u64 = if (previous.bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(previous.bits)) - 1;
    state.regs[reg] = .{
        .kind = .integer,
        .id = (previous.id & previous_mask & ~@as(u64, 0xff00)) | ((incoming.id & 0xff) << 8),
        .bits = @max(previous.bits, 16),
    };
}

pub fn unknownCall(state: *State, instruction: Instruction, options: Options) !void {
    for ([_]usize{ 7, 6, 2, 1, 8, 9 }) |reg| {
        if (state.regs[reg].kind == .stack or state.regs[reg].kind == .lost_stack) state.escaped_stack = true;
    }
    try state.store(.{}, .{}, 16, options.slot);
    if (state.escaped_stack) {
        for (&state.cells) |*cell| {
            if (cell.key.kind == .stack) cell.value = .{};
        }
    }
    clobberCall(state, instruction, options);
}

pub fn step(state: *State, instruction: Instruction, options: Options) !void {
    const op = instruction.op;
    if (instruction.unknown()) return error.UnsupportedProvenanceInstruction;
    if (instruction.isCall()) {
        try callReturnAddress(state, instruction, options);
        if (options.call_hook) |hook| try hook(options.hook_context, instruction, state, options) else try unknownCall(state, instruction, options);
        return;
    }
    if (instruction.isBranch() or instruction.stops()) {
        if (std.mem.startsWith(u8, op, "loop")) {
            if (state.regs[1].ownStack()) return error.UnsupportedProvenanceInstruction;
            state.regs[1] = .{};
        }
        return;
    }
    const all = try assembly.Operands.parse(instruction);
    if (machine.vectorArithmetic(op)) {
        const vex = std.mem.startsWith(u8, op, "v");
        if (all.len != @as(usize, if (vex) 3 else 2)) return error.UnsupportedProvenanceInstruction;
        const destination = all.items[all.len - 1];
        const reg = machine.vectorIndex(destination) orelse return error.UnsupportedProvenanceInstruction;
        state.vector_zero[reg] = if (std.mem.indexOfScalar(u8, instruction.operands, '{') == null and
            std.mem.eql(u8, all.items[0], all.items[1])) machine.vectorBytes(destination).? else 0;
        return;
    }
    if (all.len >= 3) {
        if (machine.sized(op, "imul") and all.len == 3) {
            const reg = assembly.register(all.items[2]) orelse return error.UnsupportedProvenanceInstruction;
            const factor = assembly.immediate(all.items[0]) orelse return error.UnsupportedProvenanceInstruction;
            var value = source(state.*, instruction, all.items[1]);
            if (value.ownStack() and factor != 0 and (factor != 1 or assembly.registerWidth(all.items[2]) != 64))
                return error.UnsupportedProvenanceInstruction;
            if (factor == 0) value = .{ .kind = .integer } else if (factor != 1) {
                if (value.kind == .integer and value.depth == 0 and value.upper == null) value.id *%= factor else value = .{};
            }
            if (assembly.registerWidth(all.items[2]) != 64) {
                if (assembly.registerWidth(all.items[2]) == 32 and value.kind == .integer)
                    value.id = @as(u32, @truncate(value.id))
                else
                    value = .{};
            }
            try writeRegister(state, reg, assembly.registerWidth(all.items[2]).?, value);
        } else if (machine.sized(op, "mulx") and all.len == 3) {
            if (state.regs[2].ownStack() or source(state.*, instruction, all.items[0]).ownStack())
                return error.UnsupportedProvenanceInstruction;
            state.regs[assembly.register(all.items[1]) orelse return error.UnsupportedProvenanceInstruction] = .{};
            state.regs[assembly.register(all.items[2]) orelse return error.UnsupportedProvenanceInstruction] = .{};
        } else return error.UnsupportedProvenanceInstruction;
        state.zero_test = null;
        state.comparison = null;
        state.sign_test = null;
        return;
    }
    if (std.mem.eql(u8, op, "vzeroupper") or std.mem.eql(u8, op, "vzeroall")) {
        state.vector_zero = @splat(if (std.mem.eql(u8, op, "vzeroall")) 32 else 0);
        return;
    }
    if (std.mem.eql(u8, op, "cpuid")) {
        if (source(state.*, instruction, "%eax").ownStack() or source(state.*, instruction, "%ecx").ownStack())
            return error.UnsupportedProvenanceInstruction;
        for ([_]usize{ 0, 1, 2, 3 }) |reg| state.regs[reg] = .{};
        return;
    }
    if (std.mem.eql(u8, op, "rdtsc") or std.mem.eql(u8, op, "rdtscp")) {
        state.regs[0] = .{};
        state.regs[2] = .{};
        if (std.mem.eql(u8, op, "rdtscp")) state.regs[1] = .{};
        return;
    }
    if (std.mem.eql(u8, op, "cqto") or std.mem.eql(u8, op, "cltd") or std.mem.eql(u8, op, "cwtd")) {
        if (state.regs[0].ownStack() or (std.mem.eql(u8, op, "cwtd") and state.regs[2].ownStack()))
            return error.UnsupportedProvenanceInstruction;
        state.regs[2] = .{};
        return;
    }
    if (all.len == 1 and (machine.sized(op, "mul") or machine.sized(op, "imul") or machine.sized(op, "div") or machine.sized(op, "idiv"))) {
        if (state.regs[0].ownStack() or state.regs[2].ownStack() or source(state.*, instruction, all.items[0]).ownStack())
            return error.UnsupportedProvenanceInstruction;
        state.regs[0] = .{};
        state.regs[2] = .{};
        state.zero_test = null;
        state.comparison = null;
        state.sign_test = null;
        return;
    }
    if (std.mem.eql(u8, op, "cmpxchg8b") or std.mem.eql(u8, op, "cmpxchg16b")) {
        for ([_]usize{ 0, 1, 2, 3 }) |reg| if (state.regs[reg].ownStack()) return error.UnsupportedProvenanceInstruction;
        if (source(state.*, instruction, instruction.operands).ownStack()) return error.UnsupportedProvenanceInstruction;
        try state.store(try checkedMemory(state.*, instruction, instruction.operands), .{}, try machine.writeBytes(instruction, ""), options.slot);
        state.regs[0] = .{};
        state.regs[2] = .{};
        state.zero_test = null;
        state.comparison = null;
        state.sign_test = null;
        return;
    }
    if (machine.sized(op, "test") or machine.sized(op, "cmp")) {
        state.zero_test = null;
        state.comparison = null;
        state.sign_test = null;
        if (pair(instruction)) |operands| {
            if (assembly.register(operands[1])) |reg| {
                var right = source(state.*, instruction, operands[0]);
                if (right.kind == .unknown or right.depth != 0) {
                    if (options.constant_read) |read| {
                        const location = memory(state.*, instruction, operands[0]);
                        const width = assembly.registerWidth(operands[1]).? / 8;
                        if (state.canReadInitial(location, width)) {
                            if (try read(options.constant_context, location, width)) |constant| right = constant;
                        }
                    }
                }
                const tested = source(state.*, instruction, operands[1]);
                const operand_width = assembly.registerWidth(operands[1]).?;
                if (right.kind == .integer and right.depth == 0 and right.upper == null and operand_width < 64)
                    right.id &= (@as(u64, 1) << @intCast(operand_width)) - 1;
                if (std.mem.startsWith(u8, op, "cmp")) state.comparison = .{ .reg = reg, .left = tested, .right = right, .width = assembly.registerWidth(operands[1]).? };
                if ((assembly.registerWidth(operands[1]) == 64 or tested.kind == .integer) and
                    ((std.mem.startsWith(u8, op, "test") and std.mem.eql(u8, operands[0], operands[1])) or
                        (std.mem.startsWith(u8, op, "cmp") and assembly.immediate(operands[0]) == 0)))
                    state.zero_test = tested;
                if (tested.kind == .integer and tested.upper == null and right.kind == .integer and right.upper == null) {
                    const width = assembly.registerWidth(operands[1]).?;
                    const flag_value = if (std.mem.startsWith(u8, op, "test")) tested.id & right.id else tested.id -% right.id;
                    if (std.mem.startsWith(u8, op, "test")) state.zero_test = .{ .kind = .integer, .id = flag_value };
                    state.sign_test = flag_value & (@as(u64, 1) << @intCast(width - 1)) != 0;
                }
            } else if (machine.sized(op, "test")) {
                const tested = source(state.*, instruction, operands[1]);
                const right = source(state.*, instruction, operands[0]);
                const width = if (std.mem.eql(u8, op, "test"))
                    assembly.registerWidth(operands[0])
                else
                    @as(?u8, machine.readBits(instruction));
                var result: ?u64 = if (tested.isZero() or right.isZero()) 0 else null;
                if (width) |bits| {
                    const mask: u64 = if (bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(bits)) - 1;
                    const known_tested = tested.kind == .integer and tested.depth == 0 and tested.upper == null and tested.bits >= bits;
                    const known_right = right.kind == .integer and right.depth == 0 and right.upper == null and right.bits >= bits;
                    if (known_tested and known_right)
                        result = tested.id & right.id & mask
                    else if ((known_tested and tested.id & mask == 0) or (known_right and right.id & mask == 0))
                        result = 0;
                }
                if (result) |value| {
                    // TEST constrains its AND result, never the memory operand.
                    state.zero_test = .{ .kind = .integer, .id = value };
                    state.sign_test = if (width) |bits| value & (@as(u64, 1) << @intCast(bits - 1)) != 0 else false;
                }
            } else if (assembly.immediate(operands[0]) == 0) {
                state.zero_test = source(state.*, instruction, operands[1]);
            }
        }
    } else if (!std.mem.startsWith(u8, op, "mov") and !std.mem.startsWith(u8, op, "lea") and
        !std.mem.startsWith(u8, op, "nop") and !std.mem.startsWith(u8, op, "push") and !std.mem.startsWith(u8, op, "pop"))
    {
        state.zero_test = null;
        state.comparison = null;
        state.sign_test = null;
    }
    for ([_][]const u8{ "movsb", "movsw", "movsl", "movsq", "stosb", "stosw", "stosl", "stosq", "lodsb", "lodsw", "lodsl", "lodsq" }) |string_op| {
        if (std.mem.eql(u8, op, string_op)) {
            return error.UnsupportedProvenanceInstruction;
        }
    }
    for ([_][]const u8{ "cmp", "cmpb", "cmpw", "cmpl", "cmpq", "test", "testb", "testw", "testl", "testq", "nop", "nopl", "nopw", "endbr64", "pause", "cli", "sti", "cld", "std", "clc", "stc", "cmc", "lfence", "sfence", "mfence", "wrmsr" }) |neutral|
        if (std.mem.eql(u8, op, neutral)) return;
    if (std.mem.eql(u8, op, "pushq") or std.mem.eql(u8, op, "push") or std.mem.eql(u8, op, "pushfq")) {
        if (assembly.register(instruction.operands) != null and assembly.registerWidth(instruction.operands) != 64)
            return error.UnsupportedProvenanceInstruction;
        const value = source(state.*, instruction, instruction.operands);
        state.regs[4] = state.regs[4].plus(-8);
        try state.store(state.regs[4], value, 8, options.slot);
        return;
    }
    if (std.mem.eql(u8, op, "popq") or std.mem.eql(u8, op, "pop") or std.mem.eql(u8, op, "popfq")) {
        if (assembly.register(instruction.operands) != null and assembly.registerWidth(instruction.operands) != 64)
            return error.UnsupportedProvenanceInstruction;
        if (std.mem.eql(u8, op, "popfq")) {
            state.zero_test = null;
            state.comparison = null;
            state.sign_test = null;
        }
        const value = state.get(state.regs[4]);
        state.regs[4] = state.regs[4].plus(8);
        if (assembly.register(instruction.operands)) |reg| state.regs[reg] = value else if (!std.mem.eql(u8, op, "popfq"))
            try state.store(try checkedMemory(state.*, instruction, instruction.operands), value, 8, options.slot);
        return;
    }
    if (pair(instruction)) |operands| {
        const destination = assembly.register(operands[1]);
        if (!machine.binary(op) and !machine.vectorMove(op) and !machine.vectorArithmetic(op))
            return error.UnsupportedProvenanceInstruction;
        if ((machine.sized(op, "xchg") or machine.sized(op, "xadd")) and
            (assembly.registerBitOffset(operands[0]) != 0 or assembly.registerBitOffset(operands[1]) != 0))
            return error.UnsupportedProvenanceInstruction;
        const exchange_location = if ((std.mem.startsWith(u8, op, "xchg") or std.mem.startsWith(u8, op, "xadd")) and assembly.register(operands[0]) == null)
            try checkedMemory(state.*, instruction, operands[0])
        else
            Value{};
        var value = if (std.mem.startsWith(u8, op, "lea"))
            try checkedMemory(state.*, instruction, operands[0])
        else
            source(state.*, instruction, operands[0]);
        const move = machine.sized(op, "mov") or std.mem.startsWith(u8, op, "movabs") or
            std.mem.startsWith(u8, op, "movz") or std.mem.startsWith(u8, op, "lea") or machine.vectorMove(op);
        const stack_input = value.ownStack() or (!move and source(state.*, instruction, operands[1]).ownStack());
        const clears = machine.sized(op, "xor") and destination != null and std.mem.eql(u8, operands[0], operands[1]);
        if (std.mem.startsWith(u8, op, "cmpxchg") and state.regs[0].ownStack()) return error.UnsupportedProvenanceInstruction;
        if ((value.kind == .unknown or value.depth != 0) and !std.mem.startsWith(u8, op, "lea") and assembly.register(operands[0]) == null and assembly.immediate(operands[0]) == null) {
            if (options.constant_read) |read| {
                const bytes: u8 = machine.readBits(instruction) / 8;
                const location = memory(state.*, instruction, operands[0]);
                if (state.canReadInitial(location, bytes)) {
                    if (try read(options.constant_context, location, bytes)) |constant| value = constant;
                }
            }
        }
        if (machine.sized(op, "xor")) {
            if (std.mem.eql(u8, operands[0], operands[1])) value = .{ .kind = .integer } else value = .{};
        } else if (machine.sized(op, "or") and destination != null) {
            const old = source(state.*, instruction, operands[1]);
            if (old.kind == .integer and old.upper == null and value.kind == .integer and value.upper == null)
                value = .{ .kind = .integer, .id = old.id | value.id }
            else
                value = .{};
            state.zero_test = value;
        } else if (std.mem.startsWith(u8, op, "cmov")) {
            if (destination != null) value = meet(source(state.*, instruction, operands[1]), value);
        } else if (std.mem.eql(u8, op, "addq") or std.mem.eql(u8, op, "subq")) {
            if (destination != null) {
                const old = source(state.*, instruction, operands[1]);
                if (op[0] == 's' and value.kind == .address and value.depth == 0 and old.kind == .address and old.depth == 0 and value.upper == null and old.upper == null)
                    value = .{ .kind = .integer, .id = old.id -% value.id }
                else if (value.kind == .integer and value.upper == null)
                    value = old.plus(if (op[0] == 's') -%@as(i64, @bitCast(value.id)) else @bitCast(value.id))
                else if (op[0] == 'a' and old.kind == .integer and old.upper == null)
                    value = value.plus(@bitCast(old.id))
                else
                    value = .{};
            }
        } else if (std.mem.startsWith(u8, op, "and") and destination != null and value.kind == .integer and value.upper == null) {
            const old = source(state.*, instruction, operands[1]);
            if (old.kind == .integer and old.upper == null) value = .{ .kind = .integer, .id = old.id & value.id } else if (old.kind == .integer) value = .{ .kind = .integer, .id = 0, .upper = value.id } else if ((old.kind == .heap or old.kind == .stack) and value.id != 0 and @popCount(~value.id + 1) == 1) {
                const mask = value.id;
                value = old;
                value.offset = @bitCast(@as(u64, @bitCast(old.offset)) & mask);
                if (old.alignment < ~mask + 1) {
                    const gap = (~mask + 1) - old.alignment;
                    if (old.offset < 0) return error.UnprovenPointerAlignment;
                    const lower = @as(u64, @intCast(old.offset)) & ~(old.alignment - 1);
                    value.upper = (old.upper orelse @as(u64, @intCast(old.offset))) & ~(old.alignment - 1);
                    value.offset = @intCast(std.math.sub(u64, lower, gap) catch return error.UnprovenPointerAlignment);
                    if (value.offset < 0) return error.UnprovenPointerAlignment;
                }
                value.aligned = ~mask + 1;
            } else value = .{};
        } else if (!machine.sized(op, "mov") and !std.mem.eql(u8, op, "movabsq") and
            !std.mem.eql(u8, op, "movabs") and !std.mem.startsWith(u8, op, "movz") and !std.mem.startsWith(u8, op, "lea")) value = .{};
        if (stack_input and !clears and !value.ownStack()) return error.UnsupportedProvenanceInstruction;
        if (destination != null) {
            try writeOperand(state, operands[1], value);
        } else if (machine.vectorIndex(operands[1])) |reg| {
            if (value.ownStack()) return error.UnsupportedProvenanceInstruction;
            if (assembly.register(operands[0]) == null and machine.vectorIndex(operands[0]) == null) {
                const location = try checkedMemory(state.*, instruction, operands[0]);
                const width = if (machine.vectorMove(op))
                    try machine.writeBytes(instruction, operands[1])
                else
                    machine.readBits(instruction) / 8;
                state.exposeStackCells(location, width);
            }
            state.vector_zero[reg] = 0;
        } else {
            const width = try machine.writeBytes(instruction, operands[0]);
            if (!std.mem.startsWith(u8, op, "mov")) value = .{};
            const target = try storeOperand(instruction, operands[1]);
            const location = try checkedMemory(state.*, instruction, target.address);
            if (target.masked) state.exposeStackCells(location, width);
            try state.store(location, if (target.masked) .{} else value, width, options.slot);
            if (!target.masked and location.kind == .stack and machine.vectorMove(op)) {
                if (machine.vectorIndex(operands[0])) |reg| {
                    if (state.vector_zero[reg] >= width) {
                        var offset: u8 = 0;
                        while (offset < width) : (offset += 8)
                            try state.store(location.plus(offset), .{ .kind = .integer }, @min(8, width - offset), options.slot);
                    }
                }
            }
        }
        if (std.mem.startsWith(u8, op, "xchg") or std.mem.startsWith(u8, op, "xadd")) {
            if (assembly.register(operands[0])) |reg_source|
                state.regs[reg_source] = .{}
            else
                try state.store(exchange_location, .{}, try machine.writeBytes(instruction, operands[1]), options.slot);
        }
        if (std.mem.startsWith(u8, op, "cmpxchg")) {
            state.regs[0] = .{};
        }
        return;
    }
    if (all.len == 1 and assembly.register(instruction.operands) == null and
        (machine.sized(op, "inc") or machine.sized(op, "dec") or machine.sized(op, "neg") or machine.sized(op, "not")))
    {
        if (source(state.*, instruction, instruction.operands).ownStack()) return error.UnsupportedProvenanceInstruction;
        try state.store(try checkedMemory(state.*, instruction, instruction.operands), .{}, try machine.writeBytes(instruction, ""), options.slot);
        return;
    }
    if (assembly.register(instruction.operands)) |reg| {
        if (assembly.registerBitOffset(instruction.operands) != 0) return error.UnsupportedProvenanceInstruction;
        if (!machine.sized(op, "inc") and !machine.sized(op, "dec") and !machine.sized(op, "neg") and !machine.sized(op, "not") and !machine.sized(op, "bswap") and machine.condition(op, "set") == null)
            return error.UnsupportedProvenanceInstruction;
        if (state.regs[reg].ownStack()) return error.UnsupportedProvenanceInstruction;
        state.regs[reg] = .{};
        if (std.mem.startsWith(u8, op, "mul") or std.mem.startsWith(u8, op, "div") or std.mem.startsWith(u8, op, "idiv") or std.mem.startsWith(u8, op, "imul")) {
            state.regs[0] = .{};
            state.regs[2] = .{};
        }
        return;
    }
    return error.UnsupportedProvenanceInstruction;
}

pub fn branch(state: State, op: []const u8, taken: bool) ?State {
    var outgoing = state;
    const equal = std.mem.eql(u8, op, "je") or std.mem.eql(u8, op, "jz");
    const unequal = std.mem.eql(u8, op, "jne") or std.mem.eql(u8, op, "jnz");
    if (state.sign_test) |negative| {
        if ((std.mem.eql(u8, op, "js") and negative != taken) or (std.mem.eql(u8, op, "jns") and negative == taken)) return null;
    }
    if (state.comparison) |comparison| {
        var left = comparison.left;
        const unchanged = Value.equal(state.regs[comparison.reg], left);
        const right = comparison.right;
        if (left.depth == 0 and right.depth == 0 and right.upper == null and
            ((left.kind == .integer and right.kind == .integer) or (left.kind == .address and right.kind == .address)))
        {
            const above = std.mem.eql(u8, op, "ja");
            const below_equal = std.mem.eql(u8, op, "jbe");
            const above_equal = std.mem.eql(u8, op, "jae");
            const below = std.mem.eql(u8, op, "jb");
            if (left.upper == null) {
                const decision: ?bool = if (above) left.id > right.id else if (below_equal) left.id <= right.id else if (above_equal) left.id >= right.id else if (below) left.id < right.id else if (equal) left.id == right.id else if (unequal) left.id != right.id else null;
                if (decision) |yes| if (yes != taken) {
                    return null;
                };
            } else if ((above and !taken) or (below_equal and taken)) {
                if (left.id > right.id) return null;
                left.upper = @min(left.high(), right.id);
                if (unchanged) outgoing.regs[comparison.reg] = left;
            } else if ((above_equal and taken) or (below and !taken)) {
                if (left.high() < right.id) return null;
                left.id = @max(left.id, right.id);
                if (unchanged) outgoing.regs[comparison.reg] = left;
            }
        }
    }
    if ((equal or unequal) and state.zero_test != null) {
        const tested = state.zero_test.?;
        const zero_edge = if (equal) taken else !taken;
        if (tested.kind == .integer and tested.depth == 0 and tested.upper == null and tested.isZero() != zero_edge) return null;
        if ((tested.kind == .heap or tested.kind == .allocator) and !tested.nullable and zero_edge) return null;
        for (&outgoing.regs) |*value| {
            if (!value.samePointer(tested)) continue;
            if (zero_edge) value.* = .{ .kind = .integer } else value.nullable = false;
        }
        for (&outgoing.cells) |*cell| {
            if (!cell.value.samePointer(tested)) continue;
            if (zero_edge) cell.value = .{ .kind = .integer } else cell.value.nullable = false;
        }
    }
    return outgoing;
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
                const outgoing = branch(state, instructions[index].op, edge_index == 0) orelse continue;
                if (!seen[next]) {
                    seen[next] = true;
                    before[next] = outgoing;
                    try pending.append(allocator, next);
                } else if (before[next].merge(outgoing)) try pending.append(allocator, next);
            }
        }
        if (options.reject_call_cycles) {
            for (instructions, 0..) |_, i| {
                if (!seen[i]) continue;
                for (graph.edges[i]) |edge| if (edge) |target| {
                    if (target > i) continue;
                    for (instructions[target .. i + 1], target..) |member, j|
                        if (seen[j] and member.isCall()) return error.CyclicSchedulerBinding;
                };
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
