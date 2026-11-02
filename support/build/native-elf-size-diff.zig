// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The Unikraft Authors.

//! Compare section sizes and defined-symbol counts between two ELF files.
//!
//! Usage:
//!   native-elf-size-diff [--readelf CMD] [--nm CMD] [--json] <baseline.elf> <lto.elf>
//!
//! Metrics: file_size, .text, .rodata, .data, .bss, symbol_count.

const std = @import("std");

pub const tracked_sections = [_][]const u8{ ".text", ".rodata", ".data", ".bss" };
pub const metrics_order = [_][]const u8{
    "file_size",
    ".text",
    ".rodata",
    ".data",
    ".bss",
    "symbol_count",
};

pub const Arguments = struct {
    readelf: ?[]const u8 = null,
    nm: ?[]const u8 = null,
    emit_json: bool = false,
    baseline: []const u8,
    lto: []const u8,
};

pub fn parseArguments(a: std.mem.Allocator, args: []const []const u8) !Arguments {
    var readelf: ?[]const u8 = null;
    var nm: ?[]const u8 = null;
    var emit_json = false;
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(a);

    var i: usize = 0;
    var positional_only = false;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!positional_only and std.mem.eql(u8, arg, "--")) {
            positional_only = true;
            continue;
        }
        if (!positional_only and std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--json")) {
                emit_json = true;
            } else if (std.mem.eql(u8, arg, "--readelf")) {
                i += 1;
                if (i >= args.len) return error.InvalidArguments;
                readelf = args[i];
            } else if (std.mem.eql(u8, arg, "--nm")) {
                i += 1;
                if (i >= args.len) return error.InvalidArguments;
                nm = args[i];
            } else {
                return error.InvalidArguments;
            }
            continue;
        }
        try positional.append(a, arg);
    }

    if (positional.items.len != 2) return error.InvalidArguments;
    if (positional.items[0].len == 0 or positional.items[1].len == 0) return error.InvalidArguments;

    return .{
        .readelf = readelf,
        .nm = nm,
        .emit_json = emit_json,
        .baseline = positional.items[0],
        .lto = positional.items[1],
    };
}

/// POSIX shlex-style argv splitting; never passes commands through a shell.
pub fn splitCommand(a: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (words.items) |w| a.free(w);
        words.deinit(a);
    }
    var word: std.ArrayList(u8) = .empty;
    defer word.deinit(a);
    var quote: ?u8 = null;
    var started = false;
    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        const c = text[index];
        if (c == 0) return error.InvalidToolCommand;
        if (quote == null and (c == ' ' or c == '\t' or c == '\r' or c == '\n')) {
            if (started) {
                const copy = try a.dupe(u8, word.items);
                errdefer a.free(copy);
                try words.append(a, copy);
                word.clearRetainingCapacity();
                started = false;
            }
            continue;
        }
        started = true;
        if (quote == null and (c == '\'' or c == '"')) {
            quote = c;
        } else if (quote != null and c == quote.?) {
            quote = null;
        } else if (c == '\\' and quote != '\'') {
            index += 1;
            if (index == text.len) return error.InvalidToolCommand;
            const next = text[index];
            if (next == 0) return error.InvalidToolCommand;
            if (quote == '"' and next != '"' and next != '\\') try word.append(a, '\\');
            try word.append(a, next);
        } else {
            try word.append(a, c);
        }
    }
    if (quote != null) return error.InvalidToolCommand;
    if (started) {
        const copy = try a.dupe(u8, word.items);
        errdefer a.free(copy);
        try words.append(a, copy);
    }
    if (words.items.len == 0 or words.items[0].len == 0) return error.InvalidToolCommand;
    return words.toOwnedSlice(a);
}

pub fn resolveToolCommand(
    a: std.mem.Allocator,
    arg_value: ?[]const u8,
    env: *const std.process.Environ.Map,
    env_var: []const u8,
    default_cmd: []const u8,
) ![][]const u8 {
    if (arg_value) |val| {
        return splitCommand(a, val);
    }
    if (env.get(env_var)) |env_val| {
        if (std.mem.trim(u8, env_val, " \t\r\n").len > 0) {
            return splitCommand(a, env_val);
        }
    }
    return splitCommand(a, default_cmd);
}

fn isDigitsOnly(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn isHexToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

/// Parse wide-format `readelf -SW` output into a map of `{section_name: byte_size}`.
/// Matches lines of the form: `^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+(\S+)`
/// Returns `error.MalformedSectionSize` if a matched header line has a non-hex size field.
pub fn parseReadelfSections(a: std.mem.Allocator, raw: []const u8) !std.StringHashMap(u64) {
    var sections = std.StringHashMap(u64).init(a);
    errdefer sections.deinit();

    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |raw_line| {
        const trimmed = std.mem.trimStart(u8, raw_line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] != '[') continue;
        const close_idx = std.mem.indexOfScalar(u8, trimmed, ']') orelse continue;
        const nr_str = std.mem.trimStart(u8, trimmed[1..close_idx], " \t");
        if (!isDigitsOnly(nr_str)) continue;
        if (close_idx + 1 >= trimmed.len or !std.ascii.isWhitespace(trimmed[close_idx + 1])) continue;

        var tokens = std.mem.tokenizeAny(u8, trimmed[close_idx + 1 ..], " \t\r");
        const name = tokens.next() orelse continue;
        _ = tokens.next() orelse continue; // Type
        const address = tokens.next() orelse continue;
        const off = tokens.next() orelse continue;
        const size_hex = tokens.next() orelse continue;

        if (!isHexToken(address) or !isHexToken(off)) continue;

        const size = std.fmt.parseInt(u64, size_hex, 16) catch return error.MalformedSectionSize;
        try sections.put(name, size);
    }

    return sections;
}

/// Count non-empty lines in `nm --defined-only` output.
pub fn countDefinedSymbolsOutput(raw: []const u8) u64 {
    var count: u64 = 0;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r\n\x0b\x0c").len > 0) {
            count += 1;
        }
    }
    return count;
}

pub const Metrics = struct {
    file_size: u64,
    text: u64,
    rodata: u64,
    data: u64,
    bss: u64,
    symbol_count: u64,

    pub fn get(self: Metrics, name: []const u8) u64 {
        if (std.mem.eql(u8, name, "file_size")) return self.file_size;
        if (std.mem.eql(u8, name, ".text")) return self.text;
        if (std.mem.eql(u8, name, ".rodata")) return self.rodata;
        if (std.mem.eql(u8, name, ".data")) return self.data;
        if (std.mem.eql(u8, name, ".bss")) return self.bss;
        if (std.mem.eql(u8, name, "symbol_count")) return self.symbol_count;
        unreachable;
    }
};

pub const MetricDelta = struct {
    baseline: u64,
    lto: u64,
    delta: i64,
    pct: ?f64,
    pct_basis_points: ?i64,
};

pub fn computeDelta(baseline_val: u64, lto_val: u64) MetricDelta {
    const delta: i64 = @as(i64, @intCast(lto_val)) - @as(i64, @intCast(baseline_val));
    if (baseline_val == 0) {
        return .{
            .baseline = baseline_val,
            .lto = lto_val,
            .delta = delta,
            .pct = null,
            .pct_basis_points = null,
        };
    }
    const raw_pct = (@as(f64, @floatFromInt(delta)) / @as(f64, @floatFromInt(baseline_val))) * 100.0;
    const basis_points: i64 = @intFromFloat(@round(raw_pct * 100.0));
    const rounded_pct: f64 = if (basis_points == 0) 0.0 else @as(f64, @floatFromInt(basis_points)) / 100.0;
    return .{
        .baseline = baseline_val,
        .lto = lto_val,
        .delta = delta,
        .pct = rounded_pct,
        .pct_basis_points = basis_points,
    };
}

pub const Comparison = struct {
    items: [metrics_order.len]MetricDelta,

    pub fn get(self: Comparison, name: []const u8) MetricDelta {
        for (metrics_order, 0..) |key, idx| {
            if (std.mem.eql(u8, key, name)) return self.items[idx];
        }
        unreachable;
    }
};

pub fn compare(baseline_metrics: Metrics, lto_metrics: Metrics) Comparison {
    var items: [metrics_order.len]MetricDelta = undefined;
    for (metrics_order, 0..) |key, idx| {
        items[idx] = computeDelta(baseline_metrics.get(key), lto_metrics.get(key));
    }
    return .{ .items = items };
}

fn writeJsonEscapedString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\x08' => try writer.writeAll("\\b"),
            '\x0c' => try writer.writeAll("\\f"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const hex = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c});
                    try writer.writeAll(hex);
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

pub fn formatJson(
    a: std.mem.Allocator,
    baseline_path: []const u8,
    lto_path: []const u8,
    comparison: Comparison,
) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();

    try out.writer.writeAll("{\n  \"baseline\": ");
    try writeJsonEscapedString(&out.writer, baseline_path);
    try out.writer.writeAll(",\n  \"lto\": ");
    try writeJsonEscapedString(&out.writer, lto_path);
    try out.writer.writeAll(",\n  \"metrics\": {\n");

    for (metrics_order, 0..) |key, idx| {
        const m = comparison.items[idx];
        try out.writer.writeAll("    ");
        try writeJsonEscapedString(&out.writer, key);
        try out.writer.writeAll(": {\n");
        try out.writer.writeAll(try a.print("      \"baseline\": {d},\n", .{m.baseline}));
        try out.writer.writeAll(try a.print("      \"lto\": {d},\n", .{m.lto}));
        try out.writer.writeAll(try a.print("      \"delta\": {d},\n", .{m.delta}));
        if (m.pct_basis_points) |bp| {
            const sign = if (bp < 0) "-" else "";
            const abs_bp: u64 = @abs(bp);
            const whole = abs_bp / 100;
            const frac = abs_bp % 100;
            if (frac == 0) {
                try out.writer.writeAll(try a.print("      \"pct\": {s}{d}.0\n", .{ sign, whole }));
            } else if (frac % 10 == 0) {
                try out.writer.writeAll(try a.print("      \"pct\": {s}{d}.{d}\n", .{ sign, whole, frac / 10 }));
            } else {
                try out.writer.writeAll(try a.print("      \"pct\": {s}{d}.{d:0>2}\n", .{ sign, whole, frac }));
            }
        } else {
            try out.writer.writeAll("      \"pct\": null\n");
        }
        try out.writer.writeAll(if (idx + 1 < metrics_order.len) "    },\n" else "    }\n");
    }

    try out.writer.writeAll("  }\n}\n");
    return out.toOwnedSlice();
}

pub fn formatTable(a: std.mem.Allocator, comparison: Comparison) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();

    const header = try a.print("{s:<16}{s:>14}{s:>14}{s:>12}{s:>10}\n", .{
        "Metric",
        "Baseline",
        "LTO",
        "Delta",
        "%Delta",
    });
    try out.writer.writeAll(header);
    try out.writer.writeAll("------------------------------------------------------------------\n");

    for (metrics_order, 0..) |key, idx| {
        const m = comparison.items[idx];
        const delta_sign: u8 = if (m.delta < 0) '-' else '+';
        const delta_str = try a.print("{c}{d}", .{ delta_sign, @abs(m.delta) });
        const pct_str = if (m.pct_basis_points) |bp| blk: {
            const pct_sign: u8 = if (bp < 0) '-' else '+';
            const abs_bp: u64 = @abs(bp);
            break :blk try a.print("{c}{d}.{d:0>2}%", .{ pct_sign, abs_bp / 100, abs_bp % 100 });
        } else "N/A";

        try out.writer.writeAll(try a.print("{s:<16}{d:>14}{d:>14}{s:>12}{s:>10}\n", .{
            key,
            m.baseline,
            m.lto,
            delta_str,
            pct_str,
        }));
    }

    return out.toOwnedSlice();
}

fn runToolOutput(
    a: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    tool_cmd: []const []const u8,
    extra_args: []const []const u8,
) ![]const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, tool_cmd);
    try argv.appendSlice(a, extra_args);

    const res = std.process.run(a, io, .{
        .argv = argv.items,
        .environ_map = env,
        .stdout_limit = .limited(32 * 1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }) catch |err| switch (err) {
        error.FileNotFound => blk: {
            if (std.mem.eql(u8, argv.items[0], "llvm-readelf")) {
                argv.items[0] = "readelf";
                break :blk try std.process.run(a, io, .{
                    .argv = argv.items,
                    .environ_map = env,
                    .stdout_limit = .limited(32 * 1024 * 1024),
                    .stderr_limit = .limited(1024 * 1024),
                });
            }
            if (std.mem.eql(u8, argv.items[0], "llvm-nm")) {
                argv.items[0] = "nm";
                break :blk try std.process.run(a, io, .{
                    .argv = argv.items,
                    .environ_map = env,
                    .stdout_limit = .limited(32 * 1024 * 1024),
                    .stderr_limit = .limited(1024 * 1024),
                });
            }
            return err;
        },
        else => return err,
    };
    switch (res.term) {
        .exited => |code| if (code != 0) return error.ToolExitedNonZero,
        else => return error.ToolExitedNonZero,
    }
    return res.stdout;
}

pub fn gatherMetrics(
    a: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    readelf_cmd: []const []const u8,
    nm_cmd: []const []const u8,
    elf_path: []const u8,
) !Metrics {
    const stat = try std.Io.Dir.cwd().statFile(io, elf_path, .{});
    const readelf_out = try runToolOutput(a, io, env, readelf_cmd, &.{ "-SW", elf_path });
    var sections = try parseReadelfSections(a, readelf_out);
    defer sections.deinit();
    const nm_out = try runToolOutput(a, io, env, nm_cmd, &.{ "--defined-only", elf_path });
    const sym_count = countDefinedSymbolsOutput(nm_out);

    return .{
        .file_size = stat.size,
        .text = sections.get(".text") orelse 0,
        .rodata = sections.get(".rodata") orelse 0,
        .data = sections.get(".data") orelse 0,
        .bss = sections.get(".bss") orelse 0,
        .symbol_count = sym_count,
    };
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const raw_args = try init.minimal.args.toSlice(a);
    const parsed = try parseArguments(a, raw_args[1..]);

    const readelf_cmd = try resolveToolCommand(a, parsed.readelf, init.environ_map, "READELF", "readelf");
    const nm_cmd = try resolveToolCommand(a, parsed.nm, init.environ_map, "NM", "nm");

    const baseline_metrics = try gatherMetrics(a, io, init.environ_map, readelf_cmd, nm_cmd, parsed.baseline);
    const lto_metrics = try gatherMetrics(a, io, init.environ_map, readelf_cmd, nm_cmd, parsed.lto);

    const comparison = compare(baseline_metrics, lto_metrics);
    const output = if (parsed.emit_json)
        try formatJson(a, parsed.baseline, parsed.lto, comparison)
    else
        try formatTable(a, comparison);

    var stdout = std.Io.File.stdout().writer(io, &.{});
    try stdout.interface.writeAll(output);
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("error: elf-size-diff: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

const sample_readelf_a =
    \\Section Headers:
    \\  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    \\  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
    \\  [ 1] .text             PROGBITS        0000000000401000 001000 001000 00  AX  0   0 16
    \\  [ 2] .rodata           PROGBITS        0000000000402000 002000 000200 00   A  0   0  8
    \\  [ 3] .data             PROGBITS        0000000000403000 003000 000100 00  WA  0   0  8
    \\  [ 4] .bss              NOBITS          0000000000403100 003100 000080 00  WA  0   0  8
    \\
;

const sample_readelf_b =
    \\Section Headers:
    \\  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    \\  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
    \\  [ 1] .text             PROGBITS        0000000000401000 001000 000c00 00  AX  0   0 16
    \\  [ 2] .rodata           PROGBITS        0000000000402000 002000 000200 00   A  0   0  8
    \\  [ 3] .data             PROGBITS        0000000000403000 003000 000100 00  WA  0   0  8
    \\
;

const sample_readelf_bad =
    \\Section Headers:
    \\  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    \\  [ 1] .text             PROGBITS        0000000000401000 001000 ZZZZZZ 00  AX  0   0 16
    \\
;

test "parseReadelfSections parses valid headers and rejects malformed size" {
    const a = std.testing.allocator;
    var secs_a = try parseReadelfSections(a, sample_readelf_a);
    defer secs_a.deinit();
    try std.testing.expectEqual(@as(u64, 0x1000), secs_a.get(".text").?);
    try std.testing.expectEqual(@as(u64, 0x200), secs_a.get(".rodata").?);
    try std.testing.expectEqual(@as(u64, 0x100), secs_a.get(".data").?);
    try std.testing.expectEqual(@as(u64, 0x80), secs_a.get(".bss").?);

    var secs_b = try parseReadelfSections(a, sample_readelf_b);
    defer secs_b.deinit();
    try std.testing.expectEqual(@as(u64, 0x0c00), secs_b.get(".text").?);
    try std.testing.expect(secs_b.get(".bss") == null);

    try std.testing.expectError(error.MalformedSectionSize, parseReadelfSections(a, sample_readelf_bad));
}

test "countDefinedSymbolsOutput counts non-empty lines" {
    try std.testing.expectEqual(
        @as(u64, 3),
        countDefinedSymbolsOutput("0000000000401000 T sym0\n\n0000000000401010 T sym1\n  0000000000401020 T sym2  \n"),
    );
    try std.testing.expectEqual(@as(u64, 0), countDefinedSymbolsOutput("   \n\n"));
}

test "computeDelta handles negative positive zero and zero-baseline cases" {
    const neg = computeDelta(1000, 800);
    try std.testing.expectEqual(@as(i64, -200), neg.delta);
    try std.testing.expectApproxEqAbs(@as(f64, -20.0), neg.pct.?, 0.001);

    const pos = computeDelta(800, 1000);
    try std.testing.expectEqual(@as(i64, 200), pos.delta);
    try std.testing.expectApproxEqAbs(@as(f64, 25.0), pos.pct.?, 0.001);

    const zero = computeDelta(500, 500);
    try std.testing.expectEqual(@as(i64, 0), zero.delta);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), zero.pct.?, 0.001);

    const zero_base_zero = computeDelta(0, 0);
    try std.testing.expectEqual(@as(i64, 0), zero_base_zero.delta);
    try std.testing.expect(zero_base_zero.pct == null);

    const zero_base_nonzero = computeDelta(0, 100);
    try std.testing.expectEqual(@as(i64, 100), zero_base_nonzero.delta);
    try std.testing.expect(zero_base_nonzero.pct == null);

    const third = computeDelta(300, 400);
    try std.testing.expectApproxEqAbs(@as(f64, 33.33), third.pct.?, 0.001);
}

test "formatJson and formatTable produce valid expected output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const base_m: Metrics = .{
        .file_size = 2048,
        .text = 0x1000,
        .rodata = 0x200,
        .data = 0x100,
        .bss = 0,
        .symbol_count = 10,
    };
    const lto_m: Metrics = .{
        .file_size = 1600,
        .text = 0x0c00,
        .rodata = 0x200,
        .data = 0x100,
        .bss = 0,
        .symbol_count = 8,
    };
    const comp = compare(base_m, lto_m);

    const json_str = try formatJson(a, "dir with spaces/baseline.elf", "dir with spaces/lto.elf", comp);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json_str, .{});
    defer parsed.deinit();

    const root_obj = parsed.value.object;
    try std.testing.expectEqualStrings("dir with spaces/baseline.elf", root_obj.get("baseline").?.string);
    try std.testing.expectEqualStrings("dir with spaces/lto.elf", root_obj.get("lto").?.string);

    const metrics_obj = root_obj.get("metrics").?.object;
    for (metrics_order) |key| {
        try std.testing.expect(metrics_obj.contains(key));
    }
    const fs_obj = metrics_obj.get("file_size").?.object;
    try std.testing.expectEqual(@as(i64, 2048), fs_obj.get("baseline").?.integer);
    try std.testing.expectEqual(@as(i64, 1600), fs_obj.get("lto").?.integer);
    try std.testing.expectEqual(@as(i64, -448), fs_obj.get("delta").?.integer);
    try std.testing.expectApproxEqAbs(@as(f64, -21.88), fs_obj.get("pct").?.float, 0.001);

    const bss_obj = metrics_obj.get(".bss").?.object;
    try std.testing.expect(bss_obj.get("pct").? == .null);

    const table_str = try formatTable(a, comp);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "Metric") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "Baseline") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "LTO") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "Delta") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "%Delta") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "file_size") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "-21.88%") != null);
    try std.testing.expect(std.mem.indexOf(u8, table_str, "N/A") != null);
}

test "parseArguments and resolveToolCommand" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try parseArguments(a, &.{
        "--json",
        "--readelf",
        "llvm-readelf",
        "--nm",
        "llvm-nm",
        "base.elf",
        "lto.elf",
    });
    try std.testing.expect(parsed.emit_json);
    try std.testing.expectEqualStrings("llvm-readelf", parsed.readelf.?);
    try std.testing.expectEqualStrings("llvm-nm", parsed.nm.?);
    try std.testing.expectEqualStrings("base.elf", parsed.baseline);
    try std.testing.expectEqualStrings("lto.elf", parsed.lto);

    var env = std.process.Environ.Map.init(a);
    try env.put("READELF", "/custom/readelf --wide");
    const resolved_env = try resolveToolCommand(a, null, &env, "READELF", "readelf");
    try std.testing.expectEqual(@as(usize, 2), resolved_env.len);
    try std.testing.expectEqualStrings("/custom/readelf", resolved_env[0]);
    try std.testing.expectEqualStrings("--wide", resolved_env[1]);

    const resolved_default = try resolveToolCommand(a, null, &env, "NM", "nm");
    try std.testing.expectEqual(@as(usize, 1), resolved_default.len);
    try std.testing.expectEqualStrings("nm", resolved_default[0]);
}
