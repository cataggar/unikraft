// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const validator = @import("wamr_log_validator");
const contracts = @import("hyperv_core").contracts;

const usage = "usage: uk-wamr-log-validate tiny --log L --identity I [--legacy-apic required|forbidden] [--output json-v1]\n" ++
    "       uk-wamr-log-validate workload --mode snapshot|aot|fast|full --log L --identity I [--output json-v1]\n";

const Command = struct {
    request: validator.Request,
    log: []const u8,
    identity: []const u8,
    json: bool,
};

pub fn main(init: std.process.Init) void {
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch {
        refused(init.io, "arguments");
    };
    const command = parse(args) catch {
        var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
        stderr.interface.writeAll(usage) catch {};
        std.process.exit(2);
    };
    run(allocator, init.io, command) catch |err| refused(init.io, category(err));
}

fn parse(args: []const []const u8) !Command {
    if (args.len < 2) return error.InvalidUsage;
    const tiny = std.mem.eql(u8, args[1], "tiny");
    if (!tiny and !std.mem.eql(u8, args[1], "workload")) return error.InvalidUsage;
    var log: ?[]const u8 = null;
    var identity: ?[]const u8 = null;
    var mode: ?validator.optional.Mode = null;
    var legacy: ?validator.tiny.LegacyApic = null;
    var output = false;
    if ((args.len - 2) % 2 != 0) return error.InvalidUsage;
    var index: usize = 2;
    while (index < args.len) : (index += 2) {
        const flag = args[index];
        const value = args[index + 1];
        if (value.len == 0 or std.mem.startsWith(u8, value, "--")) return error.InvalidUsage;
        if (std.mem.eql(u8, flag, "--log")) {
            if (log != null) return error.InvalidUsage;
            log = value;
        } else if (std.mem.eql(u8, flag, "--identity")) {
            if (identity != null) return error.InvalidUsage;
            identity = value;
        } else if (std.mem.eql(u8, flag, "--mode") and !tiny) {
            if (mode != null) return error.InvalidUsage;
            mode = std.meta.stringToEnum(validator.optional.Mode, value) orelse return error.InvalidUsage;
        } else if (std.mem.eql(u8, flag, "--legacy-apic") and tiny) {
            if (legacy != null) return error.InvalidUsage;
            legacy = if (std.mem.eql(u8, value, "required")) .required else if (std.mem.eql(u8, value, "forbidden")) .forbidden else return error.InvalidUsage;
        } else if (std.mem.eql(u8, flag, "--output")) {
            if (output or !std.mem.eql(u8, value, "json-v1")) return error.InvalidUsage;
            output = true;
        } else return error.InvalidUsage;
    }
    if (log == null or identity == null or (tiny and mode != null) or (!tiny and mode == null))
        return error.InvalidUsage;
    return .{
        .request = if (tiny) .{ .tiny = legacy orelse .ignored } else .{ .workload = mode.? },
        .log = log.?,
        .identity = identity.?,
        .json = output,
    };
}

fn run(allocator: std.mem.Allocator, io: std.Io, command: Command) !void {
    var result = try validator.validate(allocator, io, command.log, command.identity, command.request);
    defer result.deinit();
    var stdout = std.Io.File.stdout().writerStreaming(io, &.{});
    if (!command.json) {
        try stdout.interface.writeAll(switch (command.request) {
            .tiny => "Compute records match; no hardware or benchmark qualification.\n",
            .workload => "Optional workload correctness records valid; no boot or measurement qualification.\n",
        });
        return;
    }
    const hash = std.fmt.bytesToHex(result.raw_serial_sha256, .lower);
    const bytes = switch (command.request) {
        .tiny => try std.json.Stringify.valueAlloc(allocator, .{
            .schema = "uk.wamr.log-validation",
            .schema_version = 1,
            .mode = "tiny",
            .raw_serial_bytes = result.raw_serial_bytes,
            .raw_serial_sha256 = hash[0..],
            .compute = result.compute.?,
        }, .{}),
        .workload => |mode| try std.json.Stringify.valueAlloc(allocator, .{
            .schema = "uk.wamr.log-validation",
            .schema_version = 1,
            .mode = @tagName(mode),
            .raw_serial_bytes = result.raw_serial_bytes,
            .raw_serial_sha256 = hash[0..],
        }, .{}),
    };
    if (command.request == .tiny) {
        const document = try contracts.Document.parse(allocator, bytes, .{
            .bytes = 64 * 1024, .depth = 32, .items = 4096, .tokens = 65536,
        });
        defer document.deinit();
        try stdout.interface.writeAll(try document.canonicalAlloc(allocator));
    } else {
        try stdout.interface.writeAll(bytes);
        try stdout.interface.writeByte('\n');
    }
}

fn category(err: anyerror) []const u8 {
    return switch (err) {
        error.UnsafePath, error.UnsafeFile, error.InputUnavailable, error.IncompleteMetadata, error.FileChanged => "input-snapshot",
        error.InputLimit, error.SerialLimit, error.SerialLineLimit => "input-bound",
        error.InvalidSerial, error.TruncatedSerial => "serial-framing",
        error.EvidenceIncomplete, error.ForbiddenMarker, error.LegacyApicMismatch, error.InvalidCompletion, error.InvalidMainReturn, error.IncompleteTranscript, error.TranscriptNoise, error.UnanchoredRecord => "transcript",
        else => "record",
    };
}

fn refused(io: std.Io, reason: []const u8) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.print("WAMR_LOG_VALIDATION_REFUSED category={s} reason=invalid\n", .{reason}) catch {};
    std.process.exit(1);
}
