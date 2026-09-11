// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const format = @import("postprocess-elf.zig");
const tool = @import("hyperv-proof-tool.zig");
const commands = @import("native-postprocess-runner.zig");
const model_module = @import("hyperv-proof-image.zig");
const assembly = @import("hyperv-proof-disasm.zig");
const flow = @import("hyperv-proof-flow.zig");

const Fixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    native: []const u8,
    nm: []const u8,
    objdump: []const u8,
    cpus: []const u8,
    root: []const u8,
    bytes: []const u8,
    model: model_module.Model,
    cases: usize = 0,

    fn cli(self: *Fixture, arguments: []const []const u8, code: u8, diagnostic: ?[]const u8) !void {
        const argv = try self.allocator.alloc([]const u8, arguments.len + 1);
        argv[0] = self.native;
        @memcpy(argv[1..], arguments);
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = argv,
            .stdout_limit = .limited(1024 * 1024),
            .stderr_limit = .limited(1024 * 1024),
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        const correct = switch (result.term) {
            .exited => |actual| actual == code,
            else => false,
        };
        if (!correct or (diagnostic != null and std.mem.indexOf(u8, result.stderr, diagnostic.?) == null)) {
            std.debug.print("fixture expected exit {d}, diagnostic {s}: {any}\n{s}{s}\n", .{
                code, diagnostic orelse "(none)", result.term, result.stdout, result.stderr,
            });
            return error.IncorrectProofResult;
        }
        try std.testing.expect(std.mem.indexOf(u8, if (code == 0) result.stdout else result.stderr, if (code == 0) "PASS:" else "FAIL:") != null);
        if (code != 0) try std.testing.expect(std.mem.indexOf(u8, result.stdout, "PASS:") == null);
        self.cases += 1;
    }

    fn check(self: *Fixture, path: []const u8, mode: []const u8, code: u8, diagnostic: ?[]const u8) !void {
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(self.allocator, &.{ mode, "--image", path, "--nm", self.nm, "--objdump", self.objdump });
        if (std.mem.eql(u8, mode, "smp")) try args.appendSlice(self.allocator, &.{ "--max-cpus", self.cpus });
        if (std.mem.eql(u8, mode, "drivers")) try args.appendSlice(self.allocator, &.{ "--require-driver", "storvsc", "--require-driver", "netvsc" });
        try self.cli(args.items, code, diagnostic);
    }

    fn edit(self: Fixture) ![]u8 {
        return self.allocator.dupe(u8, self.bytes);
    }

    fn save(self: *Fixture, name: []const u8, bytes: []const u8) ![]const u8 {
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{d}-{s}", .{ self.root, self.cases, name });
        try commands.write(self.io, path, bytes);
        return path;
    }

    fn refuse(self: *Fixture, name: []const u8, bytes: []const u8, mode: []const u8, diagnostic: ?[]const u8) !void {
        const path = try self.save(name, bytes);
        self.check(path, mode, 1, diagnostic) catch |err| {
            std.debug.print("mutation: {s}\n", .{name});
            return err;
        };
    }

    fn at(self: Fixture, address: u64, size: usize) !usize {
        const slice = try self.model.dataAt(address, size);
        return @intFromPtr(slice.ptr) - @intFromPtr(self.bytes.ptr);
    }

    fn symbolOffset(self: Fixture, name: []const u8) !usize {
        for (self.model.image.sections) |section| {
            const header = section.header;
            if (header.sh_type != std.elf.SHT_SYMTAB) continue;
            const strings = try self.model.image.sectionData(self.model.image.sections[header.sh_link]);
            for (0..@intCast(header.sh_size / 24)) |index| {
                const offset = header.sh_offset + index * 24;
                const item = try format.structure(std.elf.Elf64_Sym, self.bytes, offset, .little);
                if (std.mem.eql(u8, try format.string(strings, item.st_name), name)) return @intCast(offset);
            }
        }
        return error.MissingFixtureSymbol;
    }

    fn rename(self: Fixture, bytes: []u8, name: []const u8) !void {
        for (self.model.image.sections) |section| {
            const header = section.header;
            if (header.sh_type != std.elf.SHT_SYMTAB) continue;
            const offset = try self.symbolOffset(name);
            const name_offset = try format.integer(u32, self.bytes, offset, .little);
            bytes[@intCast(self.model.image.sections[header.sh_link].header.sh_offset + name_offset)] = 'X';
            return;
        }
        return error.MissingFixtureSymbol;
    }

    fn pointer(self: Fixture, bytes: []u8, address: u64, value: u64) !void {
        for (self.model.image.sections) |section| {
            const header = section.header;
            if (header.sh_type != std.elf.SHT_RELA or header.sh_flags & std.elf.SHF_ALLOC == 0) continue;
            for (0..@intCast(header.sh_size / 24)) |index| {
                const offset = header.sh_offset + index * 24;
                if (try format.integer(u64, self.bytes, offset, .little) == address) {
                    std.mem.writeInt(u64, bytes[@intCast(offset + 16)..][0..8], value, .little);
                    return;
                }
            }
        }
        std.mem.writeInt(u64, bytes[try self.at(address, 8)..][0..8], value, .little);
    }

    fn edge(self: Fixture, caller: []const u8, callee: []const u8) !assembly.Instruction {
        const address = (try self.model.directCall(caller, callee, true)) orelse return error.MissingFixtureEdge;
        return self.model.program.instructions.items[self.model.program.instruction_index.get(address).?];
    }

    fn redirect(self: Fixture, bytes: []u8, instruction: assembly.Instruction, destination: u64) !void {
        try std.testing.expect(instruction.size == 5 and (instruction.bytes[0] == 0xe8 or instruction.bytes[0] == 0xe9));
        const delta: i32 = @intCast(@as(i128, destination) - instruction.address - instruction.size);
        std.mem.writeInt(i32, bytes[try self.at(instruction.address + 1, 4)..][0..4], delta, .little);
    }

    fn nop(self: Fixture, bytes: []u8, instruction: assembly.Instruction) !void {
        @memset(bytes[try self.at(instruction.address, instruction.size)..][0..instruction.size], 0x90);
    }

    fn returnBody(self: Fixture, bytes: []u8, name: []const u8) !void {
        const item = try self.model.symbol(name);
        const offset = try self.at(item.header.st_value, @intCast(item.header.st_size));
        @memset(bytes[offset..][0..@intCast(item.header.st_size)], 0x90);
        bytes[offset] = 0xc3;
    }
};

fn mock(init: std.process.Init, args: []const []const u8) !void {
    if (args.len < 4) return error.InvalidMockArguments;
    if (std.mem.eql(u8, args[2], "exit")) {
        try std.Io.File.stderr().writeStreamingAll(init.io, "intentional native decoder failure\n");
        std.process.exit(7);
    }
    if (std.mem.eql(u8, args[2], "empty")) return;
    if (std.mem.eql(u8, args[2], "malformed"))
        return std.Io.File.stdout().writeStreamingAll(init.io, "not a decoder record\n");
    if (!std.mem.eql(u8, args[2], "replay")) return error.InvalidMockArguments;
    const bytes = try commands.read(init.arena.allocator(), init.io, args[3]);
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len > 1 and std.mem.eql(u8, args[1], "--mock")) return mock(init, args);
    if (args.len != 9) return error.InvalidArguments;
    const native = args[1];
    const image_path = args[2];
    const object_path = args[3];
    const nm = args[4];
    const objdump = args[5];
    const cpus = args[7];
    const root = args[8];
    try std.Io.Dir.cwd().createDirPath(init.io, root);
    const object_bytes = try commands.read(allocator, init.io, object_path);
    try std.testing.expectError(error.UnsupportedElfType, format.Image.parse(allocator, object_bytes));
    var object = try format.Image.parseWithOptions(allocator, object_bytes, .{ .allow_relocatable = true });
    defer object.deinit();
    try std.testing.expectEqual(std.elf.ET.REL, object.header.type);
    try std.testing.expectEqual(std.elf.EM.X86_64, object.header.machine);
    var ids: usize = 0;
    for (object.symbols) |item| {
        if (!std.mem.eql(u8, item.name, "storvsc_device_ids") and !std.mem.eql(u8, item.name, "netvsc_device_ids")) continue;
        try std.testing.expectEqual(32, item.header.st_size);
        ids += 1;
    }
    try std.testing.expectEqual(2, ids);
    const object_nm = try tool.toolOutput(allocator, init.io, nm, &.{ "-a", object_path }, 1024 * 1024);
    var symbols = try @import("hyperv-proof-disasm.zig").Symbols.parse(allocator, object_nm);
    defer symbols.deinit();
    for ([_][]const u8{ "hyperv_vmbus_message", "hyperv_vmbus_event", "hyperv_vmbus_event_word", "hyperv_vmbus_shutdown", "hyperv_vmbus_fini" }) |name| {
        const entries = symbols.entries.get(name) orelse return error.MissingObjectSymbol;
        try std.testing.expectEqual(1, entries.items.len);
        try std.testing.expectEqual(@as(u8, 'T'), entries.items[0].kind);
    }
    const bytes = try commands.read(allocator, init.io, image_path);
    const nm_text = try tool.toolOutput(allocator, init.io, nm, &.{ "-a", image_path }, 1024 * 1024);
    const dump = try tool.toolOutput(allocator, init.io, objdump, &.{ "-d", "--disassemble-zeroes", image_path }, 4 * 1024 * 1024);
    var fixture: Fixture = .{
        .allocator = allocator,
        .io = init.io,
        .native = native,
        .nm = nm,
        .objdump = objdump,
        .cpus = cpus,
        .root = root,
        .bytes = bytes,
        .model = try model_module.Model.init(allocator, bytes, nm_text, dump),
    };
    defer fixture.model.deinit();
    if (std.mem.eql(u8, args[6], "fixed-static")) {
        try std.testing.expectEqual(std.elf.ET.EXEC, fixture.model.image.header.type);
        for ([_][]const u8{ "libstorvsc_vmbus_register_driver", "libnetvsc_vmbus_register_driver" }) |constructor|
            try std.testing.expect(!(try fixture.edge(constructor, "_vmbus_register_driver")).isCall());
    } else {
        try std.testing.expectEqual(std.elf.ET.DYN, fixture.model.image.header.type);
    }
    if (std.mem.eql(u8, args[6], "fixed") or std.mem.eql(u8, args[6], "fixed-static"))
        try std.testing.expectEqual(try fixture.model.address("lcpu_start32"), try fixture.model.address("x86_start16_end"));
    for ([_][]const u8{ "smp", "irq", "drivers" }) |mode| try fixture.check(image_path, mode, 0, null);
    try fixture.check(object_path, "irq", 1, "UnsupportedImageType");
    if (std.mem.eql(u8, args[6], "fixed")) {
        try mutations(&fixture);
        try reviewRegressions(&fixture);
        try operandRegressions(&fixture);
        try processCases(&fixture, args[0], image_path, nm_text, dump);
    }

    if (std.mem.eql(u8, args[6], "fixed-object")) try objectRegressions(&fixture);
    if (std.mem.eql(u8, args[6], "fixed-heap")) try heapRegressions(&fixture);
    if (std.mem.eql(u8, args[6], "single"))
        try fixture.cli(&.{ "smp", "--image", image_path, "--max-cpus", "2", "--nm", nm, "--objdump", objdump }, 1, null);
    const report = try std.fmt.allocPrint(allocator, "PASS: {s}: {d} native CLI cases; real C/Zig object + linked ELF, never executed as a guest\n", .{ args[6], fixture.cases });
    try commands.write(init.io, try std.fs.path.join(allocator, &.{ root, "summary.txt" }), report);
    try std.Io.File.stdout().writeStreamingAll(init.io, report);
}

fn heapRegressions(f: *Fixture) !void {
    const hook = try f.edge("schedcoop_create", "proof_heap_hook");
    for ([_][]const u8{ "proof_heap_preserve", "proof_heap_overwrite" }, [_]u8{ 0, 1 }) |name, status| {
        const bytes = try f.edit();
        try f.redirect(bytes, hook, try f.model.address(name));
        const path = try f.save(name, bytes);
        try f.check(path, "irq", status, if (status == 1) "MissingSchedulerCallbackBinding" else null);
    }
    var maps: usize = 0;
    for (try f.model.body("proof_sched_map")) |instruction| {
        const pair = flow.pair(instruction) orelse continue;
        if (!std.mem.eql(u8, instruction.op, "movq") or !std.mem.eql(u8, pair[0], "%rdi") or std.mem.indexOfScalar(u8, pair[1], '(') == null) continue;
        try std.testing.expect(instruction.size >= 4);
        const bytes = try f.edit();
        const offset = try f.at(instruction.address, instruction.size);
        @memset(bytes[offset..][0..instruction.size], 0x90);
        @memcpy(bytes[offset..][0..4], &[_]u8{ 0x48, 0x89, 0x7f, 0x18 });
        try f.refuse("cpu-map-store-redirected-into-callback", bytes, "irq", "MissingSchedulerCallbackBinding");
        maps += 1;
    }
    try std.testing.expectEqual(1, maps);
    var queues: usize = 0;
    var methods: usize = 0;
    for (try f.model.body("schedcoop_create")) |instruction| {
        const pair = flow.pair(instruction) orelse continue;
        const queue_lea = std.mem.eql(u8, instruction.op, "leaq") and std.mem.startsWith(u8, pair[0], "0x20(");
        const queue_add = std.mem.eql(u8, instruction.op, "addq") and assembly.immediate(pair[0]) == 32;
        if (queue_lea or queue_add) {
            const bytes = try f.edit();
            const displacement = try f.at(instruction.address + instruction.size - 1, 1);
            try std.testing.expectEqual(0x20, bytes[displacement]);
            bytes[displacement] = 0x18;
            try f.refuse("queue-member-redirected-into-callback", bytes, "irq", "MissingSchedulerCallbackBinding");
            queues += 1;
        }
        if (std.mem.eql(u8, instruction.op, "leaq") and instruction.reference() == try f.model.address("proof_thread_add")) {
            const bytes = try f.edit();
            const delta: i32 = @intCast(@as(i128, try f.model.address("proof_heap_overwrite")) - instruction.address - instruction.size);
            std.mem.writeInt(i32, bytes[try f.at(instruction.address + instruction.size - 4, 4)..][0..4], delta, .little);
            try f.refuse("thread-add-member-resolves-overwriting-helper", bytes, "irq", "MissingSchedulerCallbackBinding");
            methods += 1;
        }
    }
    try std.testing.expectEqual(1, queues);
    try std.testing.expectEqual(1, methods);
}

fn constructorCase(f: *Fixture, name: []const u8, status: u8, diagnostic: ?[]const u8) !void {
    const bytes = try f.edit();
    const body = (try f.model.symbol(name)).header;
    const constructor = try f.symbolOffset("libstorvsc_vmbus_register_driver");
    std.mem.writeInt(u64, bytes[constructor + 8 ..][0..8], body.st_value, .little);
    std.mem.writeInt(u64, bytes[constructor + 16 ..][0..8], body.st_size, .little);
    try f.pointer(bytes, try f.model.address("__uk_ctortab1_libstorvsc_vmbus_register_driver"), body.st_value);
    try f.check(try f.save(name, bytes), "drivers", status, diagnostic);
}

fn operandRegressions(f: *Fixture) !void {
    for ([_][]const u8{ "proof_imul_one", "proof_imul_zero" }, [_]u8{ 0, 1 }) |name, status|
        try constructorCase(f, name, status, if (status == 1) "DriverArgumentMismatch" else null);
    for ([_][]const u8{ "ah", "ch", "dh", "bh", "high_write" }) |alias| {
        try constructorCase(f, try std.fmt.allocPrint(f.allocator, "proof_{s}_zero", .{alias}), 0, null);
        try constructorCase(f, try std.fmt.allocPrint(f.allocator, "proof_{s}_nonzero", .{alias}), 1, "DriverArgumentMismatch");
    }
    try constructorCase(f, "proof_masked_stack_disjoint", 0, null);
    try constructorCase(f, "proof_masked_stack_overlap", 1, "DriverArgumentMismatch");
    try constructorCase(f, "proof_masked_stack_not_zero", 1, "DriverArgumentMismatch");
    try constructorCase(f, "proof_segment_stack_store", 1, "UnsupportedProvenanceInstruction");
    try constructorCase(f, "proof_addr32_stack_store", 1, "UnsupportedProvenanceInstruction");
    const hook = try f.edge("schedcoop_create", "proof_callback_hook");
    for ([_][]const u8{
        "proof_xmm_before",  "proof_xmm_overlap", "proof_ymm_before",
        "proof_ymm_overlap", "proof_ymm_exact",   "proof_ymm_after",
        "proof_zmm_before",  "proof_zmm_overlap", "proof_zmm_after",
    }, [_]u8{ 0, 1, 0, 1, 1, 0, 0, 1, 0 }) |name, status| {
        const bytes = try f.edit();
        try f.redirect(bytes, hook, try f.model.address(name));
        const path = try f.save(name, bytes);
        try f.check(path, "irq", status, if (status == 1) "MissingSchedulerCallbackBinding" else null);
    }
}
fn interiorLabel(f: Fixture, bytes: []u8, name: []const u8, address: u64) !void {
    const item = try f.model.symbol(name);
    const offset = try f.symbolOffset("proof_ctor_writable");
    bytes[offset + 4] = @as(u8, std.elf.STB_GLOBAL) << 4;
    std.mem.writeInt(u16, bytes[offset + 6 ..][0..2], item.header.st_shndx, .little);
    std.mem.writeInt(u64, bytes[offset + 8 ..][0..8], address, .little);
    std.mem.writeInt(u64, bytes[offset + 16 ..][0..8], 0, .little);
}

fn bypass(f: Fixture, bytes: []u8, caller: []const u8, callee: []const u8) !void {
    const start = try f.model.address(caller);
    const target = (try f.edge(caller, callee)).address;
    const offset = try f.at(start, 2);
    try std.testing.expectEqualSlices(u8, &.{ 0x66, 0x90 }, bytes[offset..][0..2]);
    bytes[offset] = 0xeb;
    bytes[offset + 1] = @bitCast(@as(i8, @intCast(@as(i128, target) - start - 2)));
}

fn reviewRegressions(f: *Fixture) !void {
    const callback_name = "schedcoop_thread_woken_isr";
    const callback = try f.model.symbol(callback_name);
    {
        const bytes = try f.edit();
        try interiorLabel(f.*, bytes, callback_name, callback.header.st_value + 2);
        const path = try f.save("valid-interior-fallthrough-label", bytes);
        try f.check(path, "irq", 0, null);
        const symbol_offset = try f.symbolOffset("proof_ctor_writable");
        bytes[symbol_offset + 4] |= std.elf.STT_FUNC;
        std.mem.writeInt(u64, bytes[symbol_offset + 16 ..][0..8], callback.header.st_size - 2, .little);
        try f.check(try f.save("valid-nested-function-alias", bytes), "irq", 0, null);
        std.mem.writeInt(u64, bytes[symbol_offset + 16 ..][0..8], callback.header.st_size, .little);
        try f.refuse("partially-overlapping-function-extents", bytes, "irq", "AmbiguousFunctionExtent");
    }
    {
        const bytes = try f.edit();
        const start = try f.at(callback.header.st_value, @intCast(callback.header.st_size));
        try std.testing.expect(callback.header.st_size >= 7);
        @memset(bytes[start..][0..@intCast(callback.header.st_size)], 0x90);
        @memcpy(bytes[start + 2 ..][0..4], &[_]u8{ 0x66, 0x0f, 0xef, 0xc0 });
        bytes[start + 6] = 0xc3;
        try f.refuse("simd-before-label-mutation", bytes, "irq", "UnsavedFpSimd");
        const executed = try f.allocator.dupe(u8, bytes[start..][0..@intCast(callback.header.st_size)]);
        try interiorLabel(f.*, bytes, callback_name, callback.header.st_value + 2);
        try std.testing.expectEqualSlices(u8, executed, bytes[start..][0..executed.len]);
        try f.refuse("single-symbol-cannot-hide-simd", bytes, "irq", "UnsavedFpSimd");
        for ([_]u8{ 0xf4, 0xcc }) |opcode| {
            bytes[start] = opcode;
            try f.refuse("halt-or-trap-resume-cannot-hide-simd", bytes, "irq", "UnsavedFpSimd");
        }
        @memset(bytes[start..][0..@intCast(callback.header.st_size)], 0x90);
        @memcpy(bytes[start..][0..5], &[_]u8{ 0xf0, 0x83, 0xc8, 0x01, 0xc3 });
        try interiorLabel(f.*, bytes, callback_name, callback.header.st_value + 4);
        try f.refuse("invalid-register-lock-remains-unknown", bytes, "irq", "UnsupportedIrqInstruction");
    }
    var stores: usize = 0;
    for (try f.model.body("schedcoop_create")) |instruction| {
        const operands = flow.pair(instruction) orelse continue;
        if (!flow.memory(.{}, instruction, operands[1]).addressIs(try f.model.address("wake_callback"), true)) continue;
        const bytes = try f.edit();
        try std.testing.expectEqual(7, instruction.size);
        const target = try f.model.address("registered_driver");
        const delta: i32 = @intCast(@as(i128, target) - instruction.address - instruction.size);
        std.mem.writeInt(i32, bytes[try f.at(instruction.address + instruction.size - 4, 4)..][0..4], delta, .little);
        try f.refuse("single-store-displacement-wrong-object", bytes, "irq", "MissingSchedulerCallbackBinding");
        stores += 1;
    }
    try std.testing.expectEqual(1, stores);
    for ([_][3][]const u8{
        .{ "libstorvsc_vmbus_register_driver", "_vmbus_register_driver", "drivers" },
        .{ "ukplat_time_init", "uk_intctlr_time_pending_register", "irq" },
    }) |case| {
        const bytes = try f.edit();
        try bypass(f.*, bytes, case[0], case[1]);
        try f.refuse("single-jump-bypasses-argument", bytes, case[2], if (std.mem.eql(u8, case[2], "drivers")) "DriverArgumentMismatch" else "MissingSynicCallbackBinding");
    }
}

fn objectRegressions(f: *Fixture) !void {
    const initializer = try f.model.body("proof_sched_initialize");
    var stores: usize = 0;
    for (initializer) |instruction| {
        const operands = flow.pair(instruction) orelse continue;
        if (!std.mem.eql(u8, operands[1], "0x18(%rdi)")) continue;
        const bytes = try f.edit();
        try std.testing.expectEqual(4, instruction.size);
        bytes[try f.at(instruction.address + 3, 1)] = 0x10;
        try f.refuse("object-initializer-wrong-field", bytes, "irq", "MissingSchedulerCallbackBinding");
        stores += 1;
    }
    try std.testing.expectEqual(1, stores);
    var guards: usize = 0;
    for (try f.model.body("schedcoop_create")) |instruction| {
        if (!std.mem.eql(u8, instruction.op, "testq") or !std.mem.eql(u8, instruction.operands, "%rax, %rax")) continue;
        const bytes = try f.edit();
        const offset = try f.at(instruction.address, 3);
        try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x85, 0xc0 }, bytes[offset..][0..3]);
        bytes[offset] = 0x40;
        try f.refuse("object-null-test-must-be-pointer-width", bytes, "irq", "MissingSchedulerCallbackBinding");
        guards += 1;
    }
    try std.testing.expectEqual(1, guards);
    {
        const bytes = try f.edit();
        try bypass(f.*, bytes, "proof_sched_initialize", "uk_sched_register");
        try f.refuse("object-initializer-bypasses-store", bytes, "irq", "MissingSchedulerCallbackBinding");
    }
    {
        const bytes = try f.edit();
        const start = try f.model.address("proof_sched_initialize");
        try interiorLabel(f.*, bytes, "proof_sched_initialize", start + 2);
        const path = try f.save("valid-shared-initializer-label", bytes);
        try f.check(path, "irq", 0, null);
    }
}

fn mutations(f: *Fixture) !void {
    for ([_][]const u8{
        "ukplat_lcpu_startup_hook", "ukplat_lcpu_init_hook",   "ukplat_lcpu_fini_hook",
        "hyperv_vmbus_shutdown",    "hyperv_vmbus_fini",       "hyperv_vmbus_message",
        "hyperv_vmbus_event",       "hyperv_vmbus_event_word",
    }) |name| {
        const bytes = try f.edit();
        const offset = try f.symbolOffset(name);
        bytes[offset + 4] = (@as(u8, std.elf.STB_WEAK) << 4) | std.elf.STT_FUNC;
        try f.refuse(name, bytes, "smp", "WrongSymbolKind");
        for (@import("hyperv-image-proofs.zig").irq_roots[3..]) |root| {
            if (std.mem.eql(u8, root, name)) try f.refuse(name, bytes, "irq", "WrongSymbolKind");
        }
    }
    for ([_][2][]const u8{
        .{ "uk_boot_entry", "ukplat_lcpu_startup_hook" }, .{ "uk_lcpu_init", "ukplat_lcpu_init_hook" },
        .{ "lcpu_halt", "ukplat_lcpu_fini_hook" },        .{ "ukplat_lcpu_startup_hook", "uk_lcpu_start" },
    }) |names| {
        const bytes = try f.edit();
        const edge = try f.edge(names[0], names[1]);
        bytes[try f.at(edge.address, 1)] = 0xe9;
        try f.refuse("smp-tail-is-not-call", bytes, "smp", null);
    }
    for ([_][]const u8{ "hyperv_vmbus_message", "hyperv_vmbus_event_word", "hyperv_vmbus_shutdown" }) |name| {
        const bytes = try f.edit();
        for (f.model.program.instructions.items) |instruction| {
            if (instruction.isCall() and !instruction.indirect() and try instruction.target() == try f.model.address(name))
                try f.nop(bytes, instruction);
        }
        try f.refuse("missing-global-linked-call", bytes, "smp", "MissingLinkedCall");
    }
    for ([_][]const u8{ "ukplat_lcpu_count", "hyperv_vmbus_message", "_vmbus_register_driver" }) |name| {
        const bytes = try f.edit();
        const source = try f.symbolOffset(name);
        const duplicate = try f.symbolOffset("storvsc_add_device");
        @memcpy(bytes[duplicate..][0..4], bytes[source..][0..4]);
        bytes[duplicate + 4] = std.elf.STT_FUNC;
        try f.refuse("localized-duplicate", bytes, if (name[0] == '_') "drivers" else "irq", "DuplicateSymbol");
    }
    {
        const bytes = try f.edit();
        bytes[(try f.symbolOffset("_vmbus_register_driver")) + 4] = (@as(u8, std.elf.STB_WEAK) << 4) | std.elf.STT_FUNC;
        try f.refuse("weak-driver-registration", bytes, "drivers", "WrongSymbolKind");
    }
    for ([_][2][]const u8{
        .{ "uk_boot_entry", "ukplat_lcpu_count" },           .{ "ukplat_lcpu_count", "uk_acpi_cpu_count" },
        .{ "uk_boot_fixed_smp_lcpu_entry", "uk_lcpu_init" },
    }) |names| {
        const edge = try f.edge(names[0], names[1]);
        var bytes = try f.edit();
        try f.nop(bytes, edge);
        try f.refuse("missing-fixed-binding", bytes, "irq", "MissingFixedSmpBinding");
        bytes = try f.edit();
        try f.redirect(bytes, edge, try f.model.address("lcpu_halt"));
        try f.refuse("wrong-fixed-binding", bytes, "irq", "MissingFixedSmpBinding");
    }
    {
        const bytes = try f.edit();
        const edge = try f.edge("uk_boot_fixed_smp_lcpu_entry", "uk_lcpu_init");
        try f.nop(bytes, edge);
        @memcpy(bytes[try f.at(edge.address, 2)..][0..2], &[_]u8{ 0xff, 0xd0 });
        try f.refuse("indirect-ap-init", bytes, "irq", "MissingFixedSmpBinding");
    }
    for ([_][]const u8{ "uk_paging_pt_get_active", "uk_paging_pt_activate_lcpu" }) |name| {
        var bytes = try f.edit();
        try f.rename(bytes, name);
        try f.refuse("incomplete-paging", bytes, "irq", "IncompletePagingBinding");
        bytes = try f.edit();
        try f.nop(bytes, try f.edge("uk_boot_fixed_smp_lcpu_entry", name));
        try f.refuse("missing-paging-call", bytes, "irq", "MissingPagingActivation");
    }
    for ([_][2][]const u8{
        .{ "uk_lcpu_init", "uk_paging_pt_get_active" },
        .{ "uk_paging_pt_get_active", "uk_paging_pt_activate_lcpu" },
    }) |names| {
        const bytes = try f.edit();
        try f.redirect(bytes, try f.edge("uk_boot_fixed_smp_lcpu_entry", names[0]), try f.model.address(names[1]));
        try f.redirect(bytes, try f.edge("uk_boot_fixed_smp_lcpu_entry", names[1]), try f.model.address(names[0]));
        try f.refuse("paging-call-order", bytes, "irq", "PagingInitializationOrder");
    }
    const ap_start = try f.model.address("lcpu_start32");
    const ap_end = try f.model.address("lcpu_start64");
    var controls: usize = 0;
    for (f.model.program.instructions.items) |instruction| {
        if (instruction.address < ap_start or instruction.address >= ap_end) continue;
        if (instruction.bytes[0] != 0xb8 and instruction.bytes[0] != 0xb9) continue;
        const immediate = std.mem.readInt(u32, instruction.bytes[1..5], .little);
        if (immediate != 0x20 and immediate != 0x900 and immediate != 0xc0000080 and immediate != 0x80010001) continue;
        const bytes = try f.edit();
        @memset(bytes[try f.at(instruction.address + 1, 4)..][0..4], 0);
        try f.refuse("ap-control-immediate", bytes, "irq", null);
        controls += 1;
    }
    try std.testing.expectEqual(4, controls);
    for ([_][]const u8{ "uk_schedcoop_create", "uk_schedcoop_create_on" }) |name| {
        const bytes = try f.edit();
        try f.returnBody(bytes, name);
        try f.refuse("every-constructor-must-bind", bytes, "irq", "MissingSchedulerCallbackBinding");
    }
    {
        const bytes = try f.edit();
        try f.rename(bytes, "uk_schedcoop_create");
        try f.rename(bytes, "uk_schedcoop_create_on");
        try f.refuse("missing-constructors", bytes, "irq", "MissingSchedulerConstructor");
    }
    {
        const bytes = try f.edit();
        try f.redirect(bytes, try f.edge("uk_schedcoop_create", "schedcoop_create"), try f.model.address("uk_schedcoop_create_on"));
        try f.redirect(bytes, try f.edge("uk_schedcoop_create_on", "schedcoop_create"), try f.model.address("uk_schedcoop_create"));
        try f.refuse("cyclic-wrappers", bytes, "irq", "MissingSchedulerCallbackBinding");
    }
    {
        const bytes = try f.edit();
        try f.redirect(bytes, try f.edge("uk_schedcoop_create_on", "schedcoop_create"), 0x200000);
        try f.refuse("unresolved-wrapper", bytes, "irq", null);
    }
    var registrations: usize = 0;
    for (try f.model.body("ukplat_time_init")) |instruction| {
        const reference = instruction.reference() orelse continue;
        var callback = false;
        for (@import("hyperv-image-proofs.zig").irq_roots[0..3]) |name| {
            if (reference == try f.model.address(name)) callback = true;
        }
        if (!callback) continue;
        const bytes = try f.edit();
        try f.nop(bytes, instruction);
        try f.refuse("missing-real-registration-argument", bytes, "irq", "MissingSynicCallbackBinding");
        const narrow = try f.edit();
        try std.testing.expectEqual(0x48, instruction.bytes[0]);
        try std.testing.expectEqual(0x8d, instruction.bytes[1]);
        narrow[try f.at(instruction.address, 1)] &= 0xf7;
        try f.refuse("narrowed-pie-registration-argument", narrow, "irq", "MissingSynicCallbackBinding");
        registrations += 1;
    }
    try std.testing.expectEqual(3, registrations);
    {
        const bytes = try f.edit();
        try f.nop(bytes, try f.edge("hyperv_timer_irq", "uk_thread_wake_isr"));
        try f.refuse("missing-irq-reachability", bytes, "irq", "MissingIrqReachability");
    }
    for ([_][]const u8{ "uk_intctlr_irq_handle", "uk_thread_wake_isr" }) |name| {
        var found = false;
        for (try f.model.body(name)) |instruction| {
            if (!instruction.isCall() or !instruction.indirect()) continue;
            const bytes = try f.edit();
            if (std.mem.eql(u8, name, "uk_intctlr_irq_handle")) {
                try f.nop(bytes, instruction);
                try f.refuse("indirect-count", bytes, "irq", "UnreviewedIndirectCount");
            } else {
                const offset = try f.at(instruction.address, instruction.size);
                try std.testing.expectEqual(0xff, bytes[offset]);
                bytes[offset + 1] = (bytes[offset + 1] & 0xc7) | 0x20;
                try f.refuse("indirect-tail", bytes, "irq", "UnreviewedIndirectEdge");
            }
            found = true;
            break;
        }
        try std.testing.expect(found);
    }
    {
        const edge = try f.edge("hyperv_message_irq", "hyperv_synic_message_take_page");
        var bytes = try f.edit();
        try f.nop(bytes, edge);
        @memcpy(bytes[try f.at(edge.address, 2)..][0..2], &[_]u8{ 0xff, 0xd0 });
        try f.refuse("unreviewed-indirect-caller", bytes, "irq", "UnreviewedIndirectEdge");
        bytes = try f.edit();
        try f.nop(bytes, edge);
        @memcpy(bytes[try f.at(edge.address, 4)..][0..4], &[_]u8{ 0x66, 0x0f, 0xef, 0xc0 });
        try f.refuse("simd-in-asserting-caller", bytes, "irq", "UnsavedFpSimd");
    }
    var traps: usize = 0;
    for (try f.model.body("hyperv_message_irq")) |instruction| {
        if (!std.mem.eql(u8, instruction.op, "ud2")) continue;
        const bytes = try f.edit();
        @memcpy(bytes[try f.at(instruction.address, 2)..][0..2], &[_]u8{ 0xc3, 0x90 });
        try f.refuse("returning-printk", bytes, "irq", "UnsavedFpSimd");
        traps += 1;
    }
    try std.testing.expectEqual(1, traps);
    var events: usize = 0;
    for (f.model.image.symbols) |item| {
        if (!std.mem.startsWith(u8, item.name, "_uk_event_native_except_event_irq_") or
            !std.mem.endsWith(u8, item.name, "_uk_intctlr_xpic_handle_irq")) continue;
        var bytes = try f.edit();
        try f.pointer(bytes, item.header.st_value, try f.model.address("hyperv_message_irq"));
        try f.refuse("native-event-pointer", bytes, "irq", "UnreviewedNativeIrqEvent");
        bytes = try f.edit();
        try f.rename(bytes, item.name);
        try f.refuse("missing-native-event", bytes, "irq", "UnreviewedNativeIrqEvent");
        bytes = try f.edit();
        const duplicate = try f.symbolOffset("storvsc_driver");
        @memcpy(bytes[duplicate..][0..4], bytes[try f.symbolOffset(item.name)..][0..4]);
        std.mem.writeInt(u64, bytes[duplicate + 8 ..][0..8], item.header.st_value, .little);
        std.mem.writeInt(u64, bytes[duplicate + 16 ..][0..8], 8, .little);
        try f.refuse("extra-native-event", bytes, "irq", "UnreviewedNativeIrqEvent");
        events += 1;
    }
    try std.testing.expectEqual(1, events);
    for ([_][]const u8{ "storvsc", "netvsc" }) |driver| {
        const ctor = try std.fmt.allocPrint(f.allocator, "lib{s}_vmbus_register_driver", .{driver});
        const entry = try std.fmt.allocPrint(f.allocator, "__uk_ctortab1_{s}", .{ctor});
        const descriptor = try std.fmt.allocPrint(f.allocator, "{s}_driver", .{driver});
        const ids = try std.fmt.allocPrint(f.allocator, "{s}_device_ids", .{driver});
        var bytes = try f.edit();
        try f.pointer(bytes, try f.model.address(entry), try f.model.address("_vmbus_register_driver"));
        try f.refuse("ctor-pointer", bytes, "drivers", "ConstructorPointerMismatch");
        bytes = try f.edit();
        try f.nop(bytes, try f.edge(ctor, "_vmbus_register_driver"));
        try f.refuse("ctor-call", bytes, "drivers", "MissingDriverRegistrationCall");
        for ([_][]const u8{ entry, descriptor, ids }) |name| {
            bytes = try f.edit();
            std.mem.writeInt(u64, bytes[(try f.symbolOffset(name)) + 16 ..][0..8], 1, .little);
            try f.refuse("driver-abi-size", bytes, "drivers", null);
        }
        for ([_]u64{ 0, 8, 16, 24, 32 }) |offset| {
            bytes = try f.edit();
            try f.pointer(bytes, (try f.model.address(descriptor)) + offset, 1);
            try f.refuse("driver-pointer", bytes, "drivers", null);
        }
        for ([_]u64{ 0, 16 }) |offset| {
            bytes = try f.edit();
            bytes[try f.at((try f.model.address(ids)) + offset, 1)] ^= 0x80;
            try f.refuse("driver-guid-or-sentinel", bytes, "drivers", "DriverIdMismatch");
        }
        var arguments: usize = 0;
        for (try f.model.body(ctor)) |instruction| {
            if (instruction.reference() != try f.model.address(descriptor)) continue;
            bytes = try f.edit();
            try f.nop(bytes, instruction);
            try f.refuse("actual-driver-argument", bytes, "drivers", "DriverArgumentMismatch");
            bytes = try f.edit();
            try std.testing.expectEqual(0x48, instruction.bytes[0]);
            try std.testing.expectEqual(0x8d, instruction.bytes[1]);
            bytes[try f.at(instruction.address, 1)] &= 0xf7;
            try f.refuse("narrowed-pie-driver-argument", bytes, "drivers", "DriverArgumentMismatch");
            arguments += 1;
        }
        try std.testing.expectEqual(1, arguments);
        bytes = try f.edit();
        std.mem.writeInt(u64, bytes[(try f.symbolOffset(entry)) + 8 ..][0..8], try f.model.address("uk_ctortab_end"), .little);
        try f.refuse("ctor-outside-table", bytes, "drivers", "ConstructorEntryOutsideTable");
    }
    {
        const bytes = try f.edit();
        std.mem.writeInt(u64, bytes[(try f.symbolOffset("uk_ctortab_end")) + 8 ..][0..8], try f.model.address("uk_ctortab_start"), .little);
        try f.refuse("empty-ctor-table", bytes, "drivers", "InvalidConstructorTable");
    }
    const ctor_address = try f.model.address("__uk_ctortab1_libstorvsc_vmbus_register_driver");
    var relocation_cases: usize = 0;
    for (f.model.image.sections) |section| {
        const header = section.header;
        if (header.sh_type != std.elf.SHT_RELA or header.sh_flags & std.elf.SHF_ALLOC == 0) continue;
        for (0..@intCast(header.sh_size / 24)) |index| {
            const offset = header.sh_offset + index * 24;
            if (try format.integer(u64, f.bytes, offset, .little) != ctor_address) continue;
            var bytes = try f.edit();
            std.mem.writeInt(u64, bytes[@intCast(offset + 8)..][0..8], 1, .little);
            try f.refuse("unsupported-pointer-relocation", bytes, "drivers", "UnsupportedPointerRelocation");
            bytes = try f.edit();
            const other = header.sh_offset + @as(u64, if (index == 0) 1 else 0) * 24;
            std.mem.writeInt(u64, bytes[@intCast(other)..][0..8], ctor_address, .little);
            std.mem.writeInt(u64, bytes[@intCast(other + 8)..][0..8], 8, .little);
            try f.refuse("ambiguous-pointer-relocation", bytes, "drivers", "AmbiguousPointerRelocation");
            relocation_cases += 2;
        }
    }
    try std.testing.expectEqual(2, relocation_cases);
    {
        const image = f.model.image;
        const names = image.sections[image.header.shstrndx].header;
        const old = try image.sectionData(image.sections[image.header.shstrndx]);
        const suffix = ".uk_ctortab1\x00";
        const bytes = try f.allocator.alloc(u8, f.bytes.len + old.len + suffix.len);
        @memcpy(bytes[0..f.bytes.len], f.bytes);
        @memcpy(bytes[f.bytes.len..][0..old.len], old);
        @memcpy(bytes[f.bytes.len + old.len ..], suffix);
        const header = image.header.shoff + @as(u64, image.header.shstrndx) * 64;
        std.mem.writeInt(u64, bytes[@intCast(header + 24)..][0..8], f.bytes.len, .little);
        std.mem.writeInt(u64, bytes[@intCast(header + 32)..][0..8], names.sh_size + suffix.len, .little);
        for (image.sections, 0..) |section, index| {
            if (std.mem.eql(u8, section.name, ".uk_ctortab"))
                std.mem.writeInt(u32, bytes[@intCast(image.header.shoff + index * 64)..][0..4], @intCast(old.len), .little);
        }
        try f.refuse("orphan-ctor-section", bytes, "drivers", "OrphanedConstructorSection");
    }
}

fn processCases(f: *Fixture, self: []const u8, image: []const u8, nm_text: []const u8, dump: []const u8) !void {
    try f.cli(&.{ "smp", "--image", image, "--max-cpus", " 4\r", "--nm", f.nm, "--objdump", f.objdump }, 0, null);
    for ([_][]const u8{ "0", "-1", "4294967296", "invalid" }) |value|
        try f.cli(&.{ "smp", "--image", image, "--max-cpus", value }, 2, "InvalidMaxCpus");
    try f.cli(&.{ "smp", "--image", image }, 2, "InvalidArguments");
    try f.cli(&.{ "drivers", "--image", image }, 2, "MissingDriverRequirement");
    try f.cli(&.{ "drivers", "--image", image, "--require-driver", "unknown" }, 2, "InvalidArguments");
    try f.cli(&.{ "irq", "--image", image, "--image", image }, 2, "InvalidArguments");
    try f.cli(&.{ "drivers", "--image", image, "--nm", f.nm, "--objdump", f.objdump, "--require-driver", "storvsc", "--require-driver", "storvsc" }, 0, null);
    for ([_][]const u8{ "storvsc", "netvsc" }) |driver| {
        const bytes = try f.edit();
        bytes[try f.at(try f.model.address(if (std.mem.eql(u8, driver, "storvsc")) "netvsc_device_ids" else "storvsc_device_ids"), 1)] ^= 1;
        const path = try f.save("unrequired-driver-guid", bytes);
        try f.cli(&.{ "drivers", "--image", path, "--nm", f.nm, "--objdump", f.objdump, "--require-driver", driver }, 0, null);
    }
    for ([_][]const u8{ "--nm", "--objdump" }) |option| {
        for ([_][]const u8{ "exit", "empty", "malformed" }) |kind| {
            const command = try std.fmt.allocPrint(f.allocator, "\"{s}\" --mock {s}", .{ self, kind });
            try f.cli(&.{ "irq", "--image", image, "--nm", if (std.mem.eql(u8, option, "--nm")) command else f.nm, "--objdump", if (std.mem.eql(u8, option, "--objdump")) command else f.objdump }, 1, if (std.mem.eql(u8, kind, "exit")) "ProofToolFailed" else if (std.mem.eql(u8, kind, "empty")) "EmptyProofToolOutput" else "Malformed");
        }
        const text = if (std.mem.eql(u8, option, "--nm")) nm_text else dump;
        var length = text.len;
        while (length > 0 and text[length - 1] == '\n') : (length -= 1) {}
        const path = try f.save("truncated-tool-output", text[0..length]);
        const command = try std.fmt.allocPrint(f.allocator, "\"{s}\" --mock replay \"{s}\"", .{ self, path });
        try f.cli(&.{ "irq", "--image", image, "--nm", if (std.mem.eql(u8, option, "--nm")) command else f.nm, "--objdump", if (std.mem.eql(u8, option, "--objdump")) command else f.objdump }, 1, "Malformed");
    }
    {
        const changed = try f.allocator.dupe(u8, nm_text);
        const label = std.mem.indexOf(u8, nm_text, " T ukplat_lcpu_startup_hook\n").?;
        const start = if (std.mem.lastIndexOfScalar(u8, nm_text[0..label], '\n')) |newline| newline + 1 else 0;
        changed[start] = if (changed[start] == '0') '1' else '0';
        const path = try f.save("wrong-nm-address", changed);
        const command = try std.fmt.allocPrint(f.allocator, "\"{s}\" --mock replay \"{s}\"", .{ self, path });
        try f.cli(&.{ "irq", "--image", image, "--nm", command, "--objdump", f.objdump }, 1, "NmAddressMismatch");
        const end = std.mem.indexOfScalarPos(u8, nm_text, start, '\n').? + 1;
        const omitted = try std.mem.concat(f.allocator, u8, &.{ nm_text[0..start], nm_text[end..] });
        const missing_path = try f.save("incomplete-nm-symbols", omitted);
        const missing_command = try std.fmt.allocPrint(f.allocator, "\"{s}\" --mock replay \"{s}\"", .{ self, missing_path });
        try f.cli(&.{ "irq", "--image", image, "--nm", missing_command, "--objdump", f.objdump }, 1, "IncompleteNmOutput");
    }
    {
        const label = std.mem.indexOf(u8, dump, " <ukplat_time_init>:\n").?;
        const start = std.mem.lastIndexOfScalar(u8, dump[0..label], '\n').? + 1;
        const path = try f.save("incomplete-disassembly-at-line-boundary", dump[0..start]);
        const command = try std.fmt.allocPrint(f.allocator, "\"{s}\" --mock replay \"{s}\"", .{ self, path });
        try f.cli(&.{ "irq", "--image", image, "--nm", f.nm, "--objdump", command }, 1, "IncompleteDisassembly");
    }
    for ([_]bool{ false, true }) |branch| {
        const instruction = if (branch)
            try f.edge("uk_boot_entry", "ukplat_lcpu_startup_hook")
        else
            f.model.program.instructions.items[0];
        const marker = try std.fmt.allocPrint(f.allocator, "{x}:", .{instruction.address});
        const start = std.mem.indexOf(u8, dump, marker).? + marker.len;
        const changed = try f.allocator.dupe(u8, dump);
        var position = start;
        if (branch) {
            position = std.mem.indexOfPos(u8, dump, position, "0x").? + 2;
        } else {
            while (changed[position] == ' ' or changed[position] == '\t') : (position += 1) {}
        }
        changed[position] = if (changed[position] == '0') '1' else '0';
        const path = try f.save("inconsistent-disassembly", changed);
        const command = try std.fmt.allocPrint(f.allocator, "\"{s}\" --mock replay \"{s}\"", .{ self, path });
        try f.cli(&.{ "irq", "--image", image, "--nm", f.nm, "--objdump", command }, 1, if (branch) "DisassemblyTargetMismatch" else "DisassemblyBytesMismatch");
    }
    {
        const bytes = try f.edit();
        for (f.model.image.programs, 0..) |program, index| {
            if (program.p_type == std.elf.PT_LOAD and program.p_flags & std.elf.PF_X != 0)
                std.mem.writeInt(u32, bytes[@intCast(f.model.image.header.phoff + index * 56 + 4)..][0..4], std.elf.PF_R, .little);
        }
        try f.refuse("non-executable-load-segment", bytes, "irq", "AddressOutsideExecutableSegment");
    }
    for ([_]usize{ 0, 4, 5, 18 }) |offset| {
        const bytes = try f.edit();
        bytes[offset] = if (offset == 18) 183 else if (offset == 4) 1 else if (offset == 5) 2 else 0;
        try f.refuse("unsupported-or-malformed-elf", bytes, "irq", null);
    }
    try f.refuse("truncated-elf", f.bytes[0 .. f.bytes.len - 1], "irq", null);
    {
        const bytes = try f.edit();
        for (f.model.image.sections, 0..) |section, index| {
            if (section.header.sh_type != std.elf.SHT_SYMTAB) continue;
            std.mem.writeInt(u64, bytes[@intCast(f.model.image.header.shoff + index * 64 + 32)..][0..8], 0, .little);
        }
        try f.refuse("zero-entry-symtab-no-panic", bytes, "irq", null);
    }
}
