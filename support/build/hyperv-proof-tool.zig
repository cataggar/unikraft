// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const model_module = @import("hyperv-proof-image.zig");
const proofs = @import("hyperv-image-proofs.zig");
const commands = @import("native-postprocess-runner.zig");

pub fn main(init: std.process.Init) void {
    var diagnostic: proofs.Diagnostic = .{};
    execute(init, &diagnostic) catch |err| {
        std.debug.print("FAIL: Hyper-V linked-image proof: {s}: {s}\n", .{ diagnostic.subject, @errorName(err) });
        std.process.exit(switch (err) {
            error.InvalidArguments, error.InvalidToolCommand, error.InvalidMaxCpus, error.MissingDriverRequirement => 2,
            else => 1,
        });
    };
}

fn execute(init: std.process.Init, diagnostic: *proofs.Diagnostic) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) return error.InvalidArguments;
    const mode = args[1];
    if (!std.mem.eql(u8, mode, "smp") and !std.mem.eql(u8, mode, "irq") and !std.mem.eql(u8, mode, "drivers"))
        return error.InvalidArguments;
    var image: ?[]const u8 = null;
    var nm: ?[]const u8 = null;
    var objdump: ?[]const u8 = null;
    var cpus: ?u32 = null;
    var required: std.ArrayList(proofs.Driver) = .empty;
    var index: usize = 2;
    while (index < args.len) : (index += 2) {
        if (index + 1 == args.len) return error.InvalidArguments;
        const key = args[index];
        const value = args[index + 1];
        if (value.len == 0) return error.InvalidArguments;
        if (std.mem.eql(u8, key, "--max-cpus")) {
            if (!std.mem.eql(u8, mode, "smp") or cpus != null) return error.InvalidArguments;
            cpus = std.fmt.parseInt(u32, std.mem.trim(u8, value, " \t\r\n"), 10) catch return error.InvalidMaxCpus;
            if (cpus.? == 0) return error.InvalidMaxCpus;
        } else if (std.mem.eql(u8, key, "--require-driver")) {
            if (!std.mem.eql(u8, mode, "drivers")) return error.InvalidArguments;
            const driver = std.meta.stringToEnum(proofs.Driver, value) orelse return error.InvalidArguments;
            if (std.mem.indexOfScalar(proofs.Driver, required.items, driver) == null)
                try required.append(allocator, driver);
        } else {
            const destination = if (std.mem.eql(u8, key, "--image"))
                &image
            else if (std.mem.eql(u8, key, "--nm"))
                &nm
            else if (std.mem.eql(u8, key, "--objdump"))
                &objdump
            else
                return error.InvalidArguments;
            if (destination.* != null) return error.InvalidArguments;
            destination.* = value;
        }
    }
    if (image == null or (std.mem.eql(u8, mode, "smp") and cpus == null))
        return error.InvalidArguments;
    if (std.mem.eql(u8, mode, "drivers") and required.items.len == 0) return error.MissingDriverRequirement;
    diagnostic.subject = image.?;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, image.?, allocator, .limited(1024 * 1024 * 1024));
    var reader = std.Io.Reader.fixed(bytes);
    const header = try std.elf.Header.read(&reader);
    if (!header.is_64 or header.machine != .X86_64 or header.endian != .little)
        return error.UnsupportedImageArchitecture;
    if (header.type != .EXEC and header.type != .DYN) return error.UnsupportedImageType;
    {
        // Refuse malformed tables before handing the image to native decoders.
        var image_view = try @import("postprocess-elf.zig").Image.parse(allocator, bytes);
        image_view.deinit();
    }
    const symbols = try toolOutput(allocator, init.io, nm orelse "llvm-nm", &.{ "-a", image.? }, 64 * 1024 * 1024);
    const assembly = try toolOutput(allocator, init.io, objdump orelse "llvm-objdump", &.{ "-d", "--disassemble-zeroes", image.? }, 256 * 1024 * 1024);
    var model = try model_module.Model.init(allocator, bytes, symbols, assembly);
    defer model.deinit();
    if (std.mem.eql(u8, mode, "smp")) {
        try proofs.smp(model, cpus.?, diagnostic);
    } else if (std.mem.eql(u8, mode, "irq")) {
        const report = try proofs.irq(model, diagnostic);
        const message = try std.fmt.allocPrint(allocator, "PASS: {d} returning IRQ functions, no FP/SIMD; {d} reviewed indirect call sites; {d} terminal assertion log calls excluded\n", .{ report.functions, report.indirect, report.fatal_logs });
        try std.Io.File.stdout().writeStreamingAll(init.io, message);
    } else {
        try proofs.drivers(model, required.items, diagnostic);
    }
    try std.Io.File.stdout().writeStreamingAll(init.io, "PASS: native Hyper-V linked-image proof only; not boot or live-host evidence\n");
}

pub fn toolOutput(allocator: std.mem.Allocator, io: std.Io, command: []const u8, tail: []const []const u8, limit: usize) ![]const u8 {
    const prefix = try commands.splitCommand(allocator, command);
    defer commands.freeCommand(allocator, prefix);
    const args = try allocator.alloc([]const u8, prefix.len + tail.len);
    defer allocator.free(args);
    @memcpy(args[0..prefix.len], prefix);
    @memcpy(args[prefix.len..], tail);
    const result = try std.process.run(allocator, io, .{
        .argv = args,
        .stdout_limit = .limited(limit),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);
    const succeeded = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!succeeded or result.stdout.len == 0) {
        std.debug.print("native proof decoder ({s}): {any}\n{s}", .{ command, result.term, result.stderr });
        return if (succeeded) error.EmptyProofToolOutput else error.ProofToolFailed;
    }
    return result.stdout;
}
