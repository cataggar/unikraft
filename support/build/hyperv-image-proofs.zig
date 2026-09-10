// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const model_module = @import("hyperv-proof-image.zig");
const Model = model_module.Model;
const assembly = model_module.disasm;
const Instruction = assembly.Instruction;
const protocol = @import("vmbus_protocol");

pub const Diagnostic = struct { subject: []const u8 = "" };
pub const IrqReport = struct { functions: usize, indirect: usize, fatal_logs: usize };
pub const Driver = enum { storvsc, netvsc };

pub const irq_roots = [_][]const u8{
    "hyperv_message_irq",   "hyperv_timer_irq",   "hyperv_time_mark_pending",
    "hyperv_vmbus_message", "hyperv_vmbus_event", "hyperv_vmbus_event_word",
};
const indirect_callers = [_][]const u8{
    "uk_plat_native_except_irq_handler", "uk_intctlr_irq_handle", "uk_thread_wake_isr",
};
const indirect_targets = [_][]const []const u8{
    &.{"uk_intctlr_xpic_handle_irq"}, irq_roots[0..3], &.{"schedcoop_thread_woken_isr"},
};

pub fn smp(model: Model, max_cpus: u32, diagnostic: *Diagnostic) !void {
    if (max_cpus == 0) return error.InvalidMaxCpus;
    for ([_][]const u8{
        "ukplat_lcpu_startup_hook", "ukplat_lcpu_init_hook",   "ukplat_lcpu_fini_hook",
        "hyperv_vmbus_shutdown",    "hyperv_vmbus_fini",       "hyperv_vmbus_message",
        "hyperv_vmbus_event",       "hyperv_vmbus_event_word",
    }) |name| {
        diagnostic.subject = name;
        _ = try model.strong(name);
    }
    for ([_][2][]const u8{
        .{ "uk_boot_entry", "ukplat_lcpu_startup_hook" },
        .{ "uk_lcpu_init", "ukplat_lcpu_init_hook" },
        .{ "lcpu_halt", "ukplat_lcpu_fini_hook" },
    }) |edge| {
        diagnostic.subject = edge[0];
        if (try model.directCall(edge[0], edge[1], false) == null) return error.MissingStrongHookCall;
    }
    for ([_][]const u8{ "hyperv_vmbus_message", "hyperv_vmbus_event_word", "hyperv_vmbus_shutdown" }) |name| {
        diagnostic.subject = name;
        const target = try model.address(name);
        var found = false;
        for (model.program.instructions.items) |instruction| {
            if (instruction.isCall() and !instruction.indirect() and try instruction.target() == target) found = true;
        }
        if (!found) return error.MissingLinkedCall;
    }
    if (max_cpus > 1) {
        diagnostic.subject = "ukplat_lcpu_startup_hook";
        if (try model.directCall("ukplat_lcpu_startup_hook", "uk_lcpu_start", false) == null)
            return error.MissingMultiCpuStartCall;
    }
}

pub fn forbiddenRegisters(instruction: Instruction) bool {
    const op = instruction.op;
    if (std.mem.startsWith(u8, op, "f") or std.mem.startsWith(u8, op, "v")) return true;
    for ([_][]const u8{ "emms", "ldmxcsr", "stmxcsr" }) |state|
        if (std.mem.eql(u8, op, state)) return true;
    for ([_][]const u8{ "xsave", "xrstor", "lxsave", "lxrstor", "kmov", "kand", "kor", "kxor", "knot", "kshift", "ktest", "kunpck" }) |state|
        if (std.mem.startsWith(u8, op, state)) return true;
    var index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, instruction.operands, index, '%')) |percent| {
        index = percent + 1;
        var end = index;
        while (end < instruction.operands.len and (std.ascii.isAlphanumeric(instruction.operands[end]) or instruction.operands[end] == '_')) : (end += 1) {}
        const reg = instruction.operands[index..end];
        if (std.mem.eql(u8, reg, "st")) return true;
        if (reg.len == 2 and reg[0] == 'k' and reg[1] >= '0' and reg[1] <= '7') return true;
        for ([_][]const u8{ "xmm", "ymm", "zmm", "mm", "tmm" }) |prefix| {
            if (!std.mem.startsWith(u8, reg, prefix) or reg.len == prefix.len) continue;
            var digits = true;
            for (reg[prefix.len..]) |c| if (!std.ascii.isDigit(c)) {
                digits = false;
            };
            if (digits) return true;
        }
        index = end;
    }
    return false;
}

pub fn terminalAssertion(instructions: []const Instruction, index: usize) bool {
    for (instructions[index + 1 ..]) |instruction| {
        if (std.mem.eql(u8, instruction.op, "ud2")) return true;
        if (instruction.isBarrier() or instruction.unknown()) return false;
    }
    return false;
}

fn operands(instruction: Instruction) ?[2][]const u8 {
    const code = instruction.operands[0 .. std.mem.indexOfScalar(u8, instruction.operands, '#') orelse instruction.operands.len];
    const comma = std.mem.lastIndexOfScalar(u8, code, ',') orelse return null;
    return .{ std.mem.trim(u8, code[0..comma], " \t"), std.mem.trim(u8, code[comma + 1 ..], " \t") };
}

fn immediateTo(instruction: Instruction, destination: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, instruction.op, "mov")) return null;
    const pair = operands(instruction) orelse return null;
    if (!std.mem.eql(u8, pair[1], destination)) return null;
    return assembly.immediate(pair[0]);
}

pub fn pagingControls(instructions: []const Instruction) !void {
    var cr0: ?usize = null;
    var cr4: ?usize = null;
    var msr: ?usize = null;
    for (instructions, 0..) |instruction, index| {
        if (std.mem.eql(u8, instruction.op, "wrmsr")) {
            if (msr != null) return error.MissingEferNxeLme;
            msr = index;
        }
        if (!std.mem.startsWith(u8, instruction.op, "mov")) continue;
        const pair = operands(instruction) orelse continue;
        const cr = if (std.mem.eql(u8, pair[1], "%cr0"))
            &cr0
        else if (std.mem.eql(u8, pair[1], "%cr4"))
            &cr4
        else
            continue;
        if (cr.* != null or index == 0 or
            !(std.mem.eql(u8, pair[0], "%eax") or std.mem.eql(u8, pair[0], "%rax")))
            return error.OverwrittenPagingControl;
        cr.* = index;
    }
    const efer_index = msr orelse return error.MissingEferNxeLme;
    if (efer_index < 3) return error.MissingEferNxeLme;
    const clear = instructions[efer_index - 3];
    const pair = operands(clear) orelse return error.MissingEferNxeLme;
    const efer = immediateTo(instructions[efer_index - 2], "%eax") orelse return error.MissingEferNxeLme;
    if (!std.mem.startsWith(u8, clear.op, "xor") or !std.mem.eql(u8, pair[0], "%edx") or
        !std.mem.eql(u8, pair[1], "%edx") or efer & 0x900 != 0x900 or
        immediateTo(instructions[efer_index - 1], "%ecx") != 0xc0000080)
        return error.MissingEferNxeLme;
    const pae_index = cr4 orelse return error.MissingCr4Pae;
    const paging_index = cr0 orelse return error.MissingCr0PeWpPg;
    const pae = immediateTo(instructions[pae_index - 1], "%eax") orelse return error.MissingCr4Pae;
    const paging = immediateTo(instructions[paging_index - 1], "%eax") orelse return error.MissingCr0PeWpPg;
    if (pae & 0x20 == 0) return error.MissingCr4Pae;
    if (paging & 0x80010001 != 0x80010001) return error.MissingCr0PeWpPg;
    if (efer_index >= paging_index or pae_index >= paging_index) return error.UnreviewedPagingControlFlow;
    for (instructions[0..paging_index]) |instruction|
        if (instruction.unknown() or instruction.isBarrier() or std.mem.eql(u8, instruction.op, "ud2") or std.mem.eql(u8, instruction.op, "hlt"))
            return error.UnreviewedPagingControlFlow;
}

fn instructionLessThan(_: void, a: Instruction, b: Instruction) bool {
    return a.address < b.address;
}

fn fixedSmp(model: Model, diagnostic: *Diagnostic) !void {
    const prepare = try model.maybeSymbol("uk_boot_fixed_smp_prepare");
    const entry = try model.maybeSymbol("uk_boot_fixed_smp_lcpu_entry");
    if (prepare == null and entry == null) return;
    if (prepare == null or entry == null) return error.IncompleteFixedSmp;
    diagnostic.subject = "ukplat_lcpu_count";
    _ = try model.strong("ukplat_lcpu_count");
    for ([_][2][]const u8{
        .{ "uk_boot_entry", "ukplat_lcpu_count" },
        .{ "ukplat_lcpu_count", "uk_acpi_cpu_count" },
        .{ "uk_boot_fixed_smp_lcpu_entry", "uk_lcpu_init" },
    }) |edge| {
        diagnostic.subject = edge[0];
        if (try model.directCall(edge[0], edge[1], true) == null) return error.MissingFixedSmpBinding;
    }
    const get = try model.maybeSymbol("uk_paging_pt_get_active");
    const activate = try model.maybeSymbol("uk_paging_pt_activate_lcpu");
    if (get == null and activate == null) return;
    if (get == null or activate == null) return error.IncompletePagingBinding;
    diagnostic.subject = "lcpu_start32";
    const start = try model.address("lcpu_start32");
    const end = try model.address("lcpu_start64");
    if (start >= end) return error.InvalidApStartupRange;
    var instructions: std.ArrayList(Instruction) = .empty;
    defer instructions.deinit(model.image.allocator);
    for (model.program.instructions.items) |instruction| {
        if (instruction.address >= start and instruction.address < end)
            try instructions.append(model.image.allocator, instruction);
    }
    std.mem.sort(Instruction, instructions.items, {}, instructionLessThan);
    try pagingControls(instructions.items);
    diagnostic.subject = "uk_boot_fixed_smp_lcpu_entry";
    const init = (try model.directCall(diagnostic.subject, "uk_lcpu_init", true)).?;
    const get_active = (try model.directCall(diagnostic.subject, "uk_paging_pt_get_active", true)) orelse return error.MissingPagingActivation;
    const set_active = (try model.directCall(diagnostic.subject, "uk_paging_pt_activate_lcpu", true)) orelse return error.MissingPagingActivation;
    if (!(init < get_active and get_active < set_active)) return error.PagingInitializationOrder;
}

pub fn updateRegisters(values: *[16]?u64, instruction: Instruction) void {
    if (instruction.isCall()) {
        for ([_]usize{ 0, 1, 2, 6, 7, 8, 9, 10, 11 }) |index| values[index] = null;
        return;
    }
    if (instruction.isBarrier() or instruction.unknown()) {
        values.* = @splat(null);
        return;
    }
    for ([_][]const u8{ "cmp", "cmpb", "cmpw", "cmpl", "cmpq", "test", "testb", "testw", "testl", "testq", "nop", "nopl", "nopw", "endbr64", "endbr32", "pause", "cld", "std", "clc", "stc", "cmc", "lfence", "sfence", "mfence", "wrmsr", "cli", "sti" }) |neutral|
        if (std.mem.eql(u8, instruction.op, neutral)) return;
    if (std.mem.startsWith(u8, instruction.op, "push") or
        (std.mem.startsWith(u8, instruction.op, "pop") and !std.mem.startsWith(u8, instruction.op, "popcnt")))
    {
        values[4] = null;
        if (std.mem.startsWith(u8, instruction.op, "pop")) {
            if (assembly.register(instruction.operands)) |destination| values[destination] = null;
        }
        return;
    }
    // Only model reviewed GP writers; unknown/implicit writers kill provenance.
    for ([_][]const u8{ "cmpxchg", "movs", "lods", "stos", "scas", "cmps" }) |implicit| {
        if (std.mem.startsWith(u8, instruction.op, implicit)) {
            values.* = @splat(null);
            return;
        }
    }
    var reviewed = false;
    for ([_][]const u8{ "mov", "lea", "add", "adc", "sub", "sbb", "and", "or", "xor", "shl", "shr", "sal", "sar", "rol", "ror", "inc", "dec", "neg", "not", "bsf", "bsr", "bswap", "lzcnt", "tzcnt", "popcnt", "set", "cmov", "bts", "btr", "btc", "xchg", "xadd", "mul", "imul", "div", "idiv" }) |prefix| {
        if (std.mem.startsWith(u8, instruction.op, prefix)) reviewed = true;
    }
    if (!reviewed) {
        values.* = @splat(null);
        return;
    }
    if (std.mem.startsWith(u8, instruction.op, "mul") or std.mem.startsWith(u8, instruction.op, "div") or
        std.mem.startsWith(u8, instruction.op, "imul") or std.mem.startsWith(u8, instruction.op, "idiv"))
    {
        values[0] = null;
        values[2] = null;
    }
    const pair = operands(instruction) orelse {
        if (!std.mem.startsWith(u8, instruction.op, "push")) {
            if (assembly.register(instruction.operands)) |destination| values[destination] = null;
        }
        return;
    };
    if (std.mem.startsWith(u8, instruction.op, "xchg") or std.mem.startsWith(u8, instruction.op, "xadd")) {
        if (assembly.register(pair[0])) |source| values[source] = null;
    }
    const destination = assembly.register(pair[1]) orelse return;
    const supported = std.mem.eql(u8, instruction.op, "mov") or std.mem.eql(u8, instruction.op, "movq") or
        std.mem.eql(u8, instruction.op, "movl") or std.mem.eql(u8, instruction.op, "movabsq") or std.mem.eql(u8, instruction.op, "movabs") or
        std.mem.eql(u8, instruction.op, "lea") or std.mem.eql(u8, instruction.op, "leaq") or std.mem.eql(u8, instruction.op, "leal");
    const width = assembly.registerWidth(pair[1]).?;
    if (!supported or width < 32) {
        values[destination] = null;
        return;
    }
    var value: ?u64 = if (std.mem.startsWith(u8, instruction.op, "lea"))
        instruction.reference()
    else if (assembly.register(pair[0])) |source|
        values[source]
    else
        assembly.immediate(pair[0]);
    if (value != null and width == 32) value = @as(u32, @truncate(value.?));
    values[destination] = value;
}

fn updatePointerRegisters(values: *[16]?u64, instruction: Instruction, position_independent: bool) void {
    updateRegisters(values, instruction);
    if (!position_independent) return;
    const pair = operands(instruction) orelse return;
    const destination = assembly.register(pair[1]) orelse return;
    if (std.mem.startsWith(u8, instruction.op, "mov") and assembly.immediate(pair[0]) != null) {
        values[destination] = null;
        return;
    }
    if (assembly.registerWidth(pair[1]).? < 64 and
        !std.mem.startsWith(u8, instruction.op, "cmp") and !std.mem.startsWith(u8, instruction.op, "test"))
        values[destination] = null;
}

pub fn callbackStored(instructions: []const Instruction, callback: u64, position_independent: bool) bool {
    var values: [16]?u64 = @splat(null);
    for (instructions) |instruction| {
        if (operands(instruction)) |pair| {
            const value = if (assembly.register(pair[0])) |source| values[source] else assembly.immediate(pair[0]);
            const wide = std.mem.eql(u8, instruction.op, "movq") or
                (std.mem.eql(u8, instruction.op, "mov") and assembly.registerWidth(pair[0]) == 64);
            const absolute: ?u64 = assembly.hex(pair[1]) catch null;
            if (wide and value == callback and (!position_independent or assembly.register(pair[0]) != null) and assembly.register(pair[1]) == null and
                (std.mem.indexOfScalar(u8, pair[1], '(') != null or absolute != null))
                return true;
        }
        updatePointerRegisters(&values, instruction, position_independent);
    }
    return false;
}

fn boundArgument(model: Model, caller: []const u8, callee: []const u8, argument_register: u4, value: u64) !bool {
    const destination = try model.address(callee);
    var values: [16]?u64 = @splat(null);
    for (try model.body(caller)) |instruction| {
        if ((instruction.isCall() or std.mem.eql(u8, instruction.op, "jmp") or std.mem.eql(u8, instruction.op, "jmpq")) and
            !instruction.indirect() and try instruction.target() == destination and values[argument_register] == value)
            return true;
        updatePointerRegisters(&values, instruction, model.image.header.type == .DYN);
    }
    return false;
}

fn schedcoopCallbacks(model: Model, diagnostic: *Diagnostic) !void {
    const callback = try model.address("schedcoop_thread_woken_isr");
    var constructors: usize = 0;
    for ([_][]const u8{ "uk_schedcoop_create", "uk_schedcoop_create_on" }) |name| {
        const constructor = (try model.maybeSymbol(name)) orelse continue;
        constructors += 1;
        diagnostic.subject = name;
        var pending: std.ArrayList(u64) = .empty;
        defer pending.deinit(model.image.allocator);
        var visited = std.AutoHashMap(u64, void).init(model.image.allocator);
        defer visited.deinit();
        try pending.append(model.image.allocator, constructor.header.st_value);
        var bound = false;
        while (pending.pop()) |address| {
            const entry = try visited.getOrPut(address);
            if (entry.found_existing) continue;
            const instructions = try model.program.body(address);
            if (callbackStored(instructions, callback, model.image.header.type == .DYN)) bound = true;
            for (instructions) |instruction| {
                if (!instruction.isBranch() or instruction.indirect()) continue;
                const destination = try instruction.target();
                if (model.hasNameAt(destination, "schedcoop_create"))
                    try pending.append(model.image.allocator, destination);
            }
        }
        if (!bound) return error.MissingSchedulerCallbackBinding;
    }
    if (constructors == 0) return error.MissingSchedulerConstructor;
}

fn irqRegistrations(model: Model, diagnostic: *Diagnostic) !void {
    diagnostic.subject = "ukplat_time_init";
    if (!try boundArgument(model, diagnostic.subject, "uk_intctlr_time_pending_register", 7, try model.address(irq_roots[2])))
        return error.MissingSynicCallbackBinding;
    for (irq_roots[0..2]) |callback| {
        if (!try boundArgument(model, diagnostic.subject, "uk_intctlr_irq_register", 6, try model.address(callback)))
            return error.MissingSynicCallbackBinding;
    }
}

pub fn irq(model: Model, diagnostic: *Diagnostic) !IrqReport {
    for (irq_roots[3..]) |name| {
        diagnostic.subject = name;
        _ = try model.strong(name);
    }
    diagnostic.subject = "native_except_event_irq";
    const prefix = "_uk_event_native_except_event_irq_";
    var handlers: usize = 0;
    for (model.image.symbols) |symbol| {
        if (!std.mem.startsWith(u8, symbol.name, prefix)) continue;
        const rest = symbol.name[prefix.len..];
        const separator = std.mem.indexOfScalar(u8, rest, '_') orelse continue;
        if (separator == 0) continue;
        for (rest[0..separator]) |c| if (!std.ascii.isDigit(c)) return error.UnreviewedNativeIrqEvent;
        handlers += 1;
        if (!std.mem.eql(u8, rest[separator + 1 ..], "uk_intctlr_xpic_handle_irq") or symbol.header.st_size != 8 or
            try model.pointer(symbol.header.st_value) != try model.address("uk_intctlr_xpic_handle_irq"))
            return error.UnreviewedNativeIrqEvent;
    }
    if (handlers != 1) return error.UnreviewedNativeIrqEvent;
    try fixedSmp(model, diagnostic);
    var pending: std.ArrayList(u64) = .empty;
    defer pending.deinit(model.image.allocator);
    var visited = std.AutoHashMap(u64, void).init(model.image.allocator);
    defer visited.deinit();
    var counts = [_]usize{0} ** 3;
    var fatal_logs: usize = 0;
    try pending.append(model.image.allocator, try model.address(indirect_callers[0]));
    const printk = try model.maybeSymbol("_uk_printk");
    while (pending.pop()) |address| {
        const visit = try visited.getOrPut(address);
        if (visit.found_existing) continue;
        const instructions = try model.program.body(address);
        const function = model.program.functions.items[model.program.function_index.get(address).?];
        diagnostic.subject = function.name;
        for (instructions, 0..) |instruction, index| {
            if (instruction.unknown()) return error.UnsupportedIrqInstruction;
            if (forbiddenRegisters(instruction)) return error.UnsavedFpSimd;
            if (!instruction.isBranch()) continue;
            if (instruction.indirect()) {
                var caller: ?usize = null;
                for (indirect_callers, 0..) |name, caller_index| {
                    if (try model.address(name) == address) caller = caller_index;
                }
                if (caller == null or !instruction.isCall()) return error.UnreviewedIndirectEdge;
                if (caller.? == 2) try schedcoopCallbacks(model, diagnostic);
                if (caller.? == 1) try irqRegistrations(model, diagnostic);
                counts[caller.?] += 1;
                for (indirect_targets[caller.?]) |callback|
                    try pending.append(model.image.allocator, try model.address(callback));
                continue;
            }
            const destination = try instruction.target();
            var local = false;
            for (instructions) |candidate| if (candidate.address == destination) {
                local = true;
            };
            if (local) continue;
            if (printk != null and destination == printk.?.header.st_value and terminalAssertion(instructions, index)) {
                fatal_logs += 1;
                continue;
            }
            try pending.append(model.image.allocator, destination);
        }
    }
    for (irq_roots ++ [_][]const u8{
        "hyperv_synic_message_take_page", "hyperv_synic_event_take_word_page",
        "vmbus_protocol_state",           "vmbus_protocol_generation",
        "vmbus_protocol_version",         "uk_thread_wake_isr",
        "schedcoop_thread_woken_isr",
    }) |name| {
        diagnostic.subject = name;
        if (!visited.contains(try model.address(name))) return error.MissingIrqReachability;
    }
    if (!std.mem.eql(usize, &counts, &.{ 1, 2, 1 })) return error.UnreviewedIndirectCount;
    return .{ .functions = visited.count(), .indirect = 4, .fatal_logs = fatal_logs };
}

pub fn drivers(model: Model, required: []const Driver, diagnostic: *Diagnostic) !void {
    if (required.len == 0) return error.MissingDriverRequirement;
    diagnostic.subject = "_vmbus_register_driver";
    _ = try model.strong(diagnostic.subject);
    const start = try model.address("uk_ctortab_start");
    const end = try model.address("uk_ctortab_end");
    if (start >= end or start % 8 != 0 or (end - start) % 8 != 0) return error.InvalidConstructorTable;
    _ = try model.dataAt(start, end - start);
    for (model.image.sections) |section| {
        if (std.mem.startsWith(u8, section.name, ".uk_ctortab") and !std.mem.eql(u8, section.name, ".uk_ctortab"))
            return error.OrphanedConstructorSection;
    }
    for (required) |driver| {
        const name = @tagName(driver);
        diagnostic.subject = name;
        const allocator = model.image.allocator;
        const constructor = try std.fmt.allocPrint(allocator, "lib{s}_vmbus_register_driver", .{name});
        defer allocator.free(constructor);
        const entry = try std.fmt.allocPrint(allocator, "__uk_ctortab1_{s}", .{constructor});
        defer allocator.free(entry);
        const ctor = try model.namedKind(constructor, "Tt");
        const record = try model.namedKind(entry, "Dd");
        const offset = record.header.st_value;
        if (record.header.st_size != 8 or offset % 8 != 0 or offset < start or offset >= end or end - offset < 8)
            return error.ConstructorEntryOutsideTable;
        if (try model.pointer(offset) != ctor.header.st_value) return error.ConstructorPointerMismatch;
        if (try model.directCall(constructor, "_vmbus_register_driver", true) == null) return error.MissingDriverRegistrationCall;
        const descriptor_name = try std.fmt.allocPrint(allocator, "{s}_driver", .{name});
        defer allocator.free(descriptor_name);
        const ids_name = try std.fmt.allocPrint(allocator, "{s}_device_ids", .{name});
        defer allocator.free(ids_name);
        const descriptor = try model.symbol(descriptor_name);
        const ids = try model.symbol(ids_name);
        if (descriptor.header.st_size != 40 or ids.header.st_size != 32) return error.DriverAbiMismatch;
        const address = descriptor.header.st_value;
        if (try model.pointer(address + 8) != ids.header.st_value) return error.DriverIdsPointerMismatch;
        const guid = if (driver == .storvsc) protocol.storage_guid.bytes else protocol.network_guid.bytes;
        const id_bytes = try model.dataAt(ids.header.st_value, 32);
        if (!std.mem.eql(u8, id_bytes[0..16], &guid) or !std.mem.allEqual(u8, id_bytes[16..32], 0))
            return error.DriverIdMismatch;
        const driver_name = try std.fmt.allocPrint(allocator, "hyperv-{s}\x00", .{name});
        defer allocator.free(driver_name);
        if (!std.mem.eql(u8, try model.dataAt(try model.pointer(address), driver_name.len), driver_name))
            return error.DriverNameMismatch;
        for ([_][]const u8{ "add_device", "remove_device" }, 0..) |suffix, index| {
            const callback = try std.fmt.allocPrint(allocator, "{s}_{s}", .{ name, suffix });
            defer allocator.free(callback);
            const pointer = try model.pointer(address + 16 + index * 8);
            if (pointer != try model.address(callback)) return error.DriverCallbackMismatch;
            _ = try model.executableBytes(pointer, 1);
        }
        const removed = try model.pointer(address + 32);
        if (removed != 0) _ = try model.executableBytes(removed, 1);
        if (!try boundArgument(model, constructor, "_vmbus_register_driver", 7, address))
            return error.DriverArgumentMismatch;
    }
}
