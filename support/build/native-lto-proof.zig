// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, The Unikraft Authors.

//! Prove Zig 0.16 performs cross-translation-unit LTO.
//!
//! Compiles two tiny C translation units with and without -flto (all other
//! compiler/linker flags are identical), links them, runs both binaries to
//! confirm they exit 0, then asserts:
//!   - baseline: lto_proof_callee is a defined symbol
//!   - lto:      lto_proof_callee is absent (inlined and eliminated by LTO)

const std = @import("std");

pub const callee_src =
    \\/* lto-proof: callee in its own translation unit */
    \\int lto_proof_callee(void) {
    \\    return 42;
    \\}
    \\
;

pub const caller_src =
    \\/* lto-proof: caller in its own translation unit */
    \\extern int lto_proof_callee(void);
    \\
    \\int main(void) {
    \\    return lto_proof_callee() - 42;
    \\}
    \\
;

pub const proof_symbol = "lto_proof_callee";

pub const Arguments = struct {
    work_dir: []const u8,
    zig: []const u8,
    nm: []const u8 = "nm",
};

pub fn parseArguments(args: []const []const u8) !Arguments {
    var work_dir: ?[]const u8 = null;
    var zig: ?[]const u8 = null;
    var nm: []const u8 = "nm";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--work-dir")) {
            i += 1;
            if (i >= args.len or args[i].len == 0) return error.InvalidArguments;
            work_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--zig")) {
            i += 1;
            if (i >= args.len or args[i].len == 0) return error.InvalidArguments;
            zig = args[i];
        } else if (std.mem.eql(u8, arg, "--nm")) {
            i += 1;
            if (i >= args.len or args[i].len == 0) return error.InvalidArguments;
            nm = args[i];
        } else {
            return error.InvalidArguments;
        }
    }

    return .{
        .work_dir = work_dir orelse return error.InvalidArguments,
        .zig = zig orelse return error.InvalidArguments,
        .nm = nm,
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

pub const VariantPlan = struct {
    commands: [3][]const []const u8,
    output_elf: []const u8,
};

/// Construct compilation and link argv slices for one variant.
/// Purely constructs paths and arguments; executes nothing.
/// `-flto` is the only flag that differs between variants.
pub fn buildCommands(
    a: std.mem.Allocator,
    work_dir: []const u8,
    zig_cmd: []const []const u8,
    use_lto: bool,
) !VariantPlan {
    const suffix = if (use_lto) "lto" else "baseline";
    const callee_c = try std.fs.path.join(a, &.{ work_dir, "callee.c" });
    const caller_c = try std.fs.path.join(a, &.{ work_dir, "caller.c" });
    const callee_obj_name = try a.print("callee-{s}.o", .{suffix});
    const caller_obj_name = try a.print("caller-{s}.o", .{suffix});
    const output_elf_name = try a.print("{s}.elf", .{suffix});
    const callee_obj = try std.fs.path.join(a, &.{ work_dir, callee_obj_name });
    const caller_obj = try std.fs.path.join(a, &.{ work_dir, caller_obj_name });
    const output_elf = try std.fs.path.join(a, &.{ work_dir, output_elf_name });

    const flags: []const []const u8 = if (use_lto) &.{ "-O2", "-flto" } else &.{"-O2"};

    var cmd0: std.ArrayList([]const u8) = .empty;
    try cmd0.appendSlice(a, zig_cmd);
    try cmd0.append(a, "cc");
    try cmd0.appendSlice(a, flags);
    try cmd0.appendSlice(a, &.{ "-c", callee_c, "-o", callee_obj });

    var cmd1: std.ArrayList([]const u8) = .empty;
    try cmd1.appendSlice(a, zig_cmd);
    try cmd1.append(a, "cc");
    try cmd1.appendSlice(a, flags);
    try cmd1.appendSlice(a, &.{ "-c", caller_c, "-o", caller_obj });

    var cmd2: std.ArrayList([]const u8) = .empty;
    try cmd2.appendSlice(a, zig_cmd);
    try cmd2.append(a, "cc");
    try cmd2.appendSlice(a, flags);
    try cmd2.appendSlice(a, &.{ callee_obj, caller_obj, "-o", output_elf });

    return .{
        .commands = .{
            try cmd0.toOwnedSlice(a),
            try cmd1.toOwnedSlice(a),
            try cmd2.toOwnedSlice(a),
        },
        .output_elf = output_elf,
    };
}

/// Parse `nm --defined-only` output into a set of defined symbol names.
pub fn parseDefinedSymbols(a: std.mem.Allocator, nm_stdout: []const u8) !std.StringHashMap(void) {
    var names = std.StringHashMap(void).init(a);
    errdefer names.deinit();

    var lines = std.mem.splitScalar(u8, nm_stdout, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n\x0b\x0c");
        if (line.len == 0) continue;
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r\n\x0b\x0c");
        var count: usize = 0;
        var last: []const u8 = "";
        while (tokens.next()) |tok| {
            count += 1;
            last = tok;
        }
        if (count >= 2) {
            try names.put(last, {});
        }
    }
    return names;
}

pub fn definedSymbolNames(
    a: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    nm_cmd: []const []const u8,
    elf_path: []const u8,
) !std.StringHashMap(void) {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, nm_cmd);
    try argv.appendSlice(a, &.{ "--defined-only", elf_path });

    const res = std.process.run(a, io, .{
        .argv = argv.items,
        .environ_map = env,
        .stdout_limit = .limited(16 * 1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }) catch |err| switch (err) {
        error.FileNotFound => blk: {
            if (std.mem.eql(u8, argv.items[0], "llvm-nm")) {
                argv.items[0] = "nm";
                break :blk try std.process.run(a, io, .{
                    .argv = argv.items,
                    .environ_map = env,
                    .stdout_limit = .limited(16 * 1024 * 1024),
                    .stderr_limit = .limited(1024 * 1024),
                });
            }
            return err;
        },
        else => return err,
    };
    switch (res.term) {
        .exited => |code| if (code != 0) return error.NmFailed,
        else => return error.NmFailed,
    }
    return parseDefinedSymbols(a, res.stdout);
}

pub fn verifyRunsOk(
    a: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    elf_path: []const u8,
) !void {
    const res = try std.process.run(a, io, .{
        .argv = &.{elf_path},
        .environ_map = env,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    switch (res.term) {
        .exited => |code| if (code != 0) return error.BinaryExitedNonZero,
        else => return error.BinaryExitedNonZero,
    }
}

/// Return a slice of failure messages; an empty slice means the proof passed.
pub fn checkProofResult(
    a: std.mem.Allocator,
    baseline_syms: std.StringHashMap(void),
    lto_syms: std.StringHashMap(void),
    symbol: []const u8,
) ![]const []const u8 {
    var failures: std.ArrayList([]const u8) = .empty;
    errdefer failures.deinit(a);

    if (!baseline_syms.contains(symbol)) {
        try failures.append(
            a,
            try a.print("'{s}' absent from baseline binary (expected retained without LTO)", .{symbol}),
        );
    }
    if (lto_syms.contains(symbol)) {
        try failures.append(
            a,
            try a.print("'{s}' still present in LTO binary (expected LTO to eliminate it)", .{symbol}),
        );
    }
    return failures.toOwnedSlice(a);
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const raw_args = try init.minimal.args.toSlice(a);
    const parsed = try parseArguments(raw_args[1..]);
    const nm_cmd = try splitCommand(a, parsed.nm);

    try std.Io.Dir.cwd().createDirPath(io, parsed.work_dir);
    const work_dir = try std.Io.Dir.cwd().realPathFileAlloc(io, parsed.work_dir, a);

    var env = try init.environ_map.clone(a);
    try env.put("ZIG_GLOBAL_CACHE_DIR", try std.fs.path.join(a, &.{ work_dir, "zig-global-cache" }));
    try env.put("ZIG_LOCAL_CACHE_DIR", try std.fs.path.join(a, &.{ work_dir, "zig-local-cache" }));

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fs.path.join(a, &.{ work_dir, "callee.c" }),
        .data = callee_src,
    });
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fs.path.join(a, &.{ work_dir, "caller.c" }),
        .data = caller_src,
    });

    const zig_cmd: []const []const u8 = &.{parsed.zig};
    const baseline_plan = try buildCommands(a, work_dir, zig_cmd, false);
    const lto_plan = try buildCommands(a, work_dir, zig_cmd, true);

    for ([_]VariantPlan{ baseline_plan, lto_plan }) |plan| {
        for (plan.commands) |argv| {
            const res = try std.process.run(a, io, .{
                .argv = argv,
                .environ_map = &env,
                .stdout_limit = .limited(16 * 1024 * 1024),
                .stderr_limit = .limited(16 * 1024 * 1024),
            });
            switch (res.term) {
                .exited => |code| if (code != 0) {
                    std.debug.print("FAIL: command exited with status {d}: {s}\n", .{
                        code,
                        std.mem.trim(u8, res.stderr, " \t\r\n"),
                    });
                    return error.CompileFailed;
                },
                else => return error.CompileFailed,
            }
        }
    }

    try verifyRunsOk(a, io, &env, baseline_plan.output_elf);
    try verifyRunsOk(a, io, &env, lto_plan.output_elf);

    const baseline_syms = try definedSymbolNames(a, io, &env, nm_cmd, baseline_plan.output_elf);
    const lto_syms = try definedSymbolNames(a, io, &env, nm_cmd, lto_plan.output_elf);

    const failures = try checkProofResult(a, baseline_syms, lto_syms, proof_symbol);
    if (failures.len != 0) {
        var stderr = std.Io.File.stderr().writer(io, &.{});
        for (failures) |msg| {
            try stderr.interface.writeAll(try a.print("FAIL: {s}\n", .{msg}));
        }
        std.process.exit(1);
    }

    var stdout = std.Io.File.stdout().writer(io, &.{});
    try stdout.interface.writeAll(try a.print(
        "PASS: cross-TU LTO proof for '{s}'\n" ++
            "  baseline ({s}): symbol retained\n" ++
            "  lto      ({s}): symbol eliminated\n",
        .{
            proof_symbol,
            std.fs.path.basename(baseline_plan.output_elf),
            std.fs.path.basename(lto_plan.output_elf),
        },
    ));
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("FAIL: lto-proof: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn containsArg(argv: []const []const u8, needle: []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, needle)) return true;
    }
    return false;
}

test "buildCommands flag invariants and path preservation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const base_plan = try buildCommands(a, "/work/dir with spaces", &.{ "/path/to zig", "--extra" }, false);
    const lto_plan = try buildCommands(a, "/work/dir with spaces", &.{ "/path/to zig", "--extra" }, true);

    try std.testing.expect(!std.mem.eql(u8, base_plan.output_elf, lto_plan.output_elf));
    try std.testing.expectEqualStrings("baseline.elf", std.fs.path.basename(base_plan.output_elf));
    try std.testing.expectEqualStrings("lto.elf", std.fs.path.basename(lto_plan.output_elf));

    for (base_plan.commands, lto_plan.commands) |base_cmd, lto_cmd| {
        try std.testing.expect(!containsArg(base_cmd, "-flto"));
        try std.testing.expect(containsArg(lto_cmd, "-flto"));
        try std.testing.expectEqualStrings("/path/to zig", base_cmd[0]);
        try std.testing.expectEqualStrings("--extra", base_cmd[1]);
        try std.testing.expectEqualStrings("cc", base_cmd[2]);

        for (base_cmd) |arg| {
            if (std.mem.startsWith(u8, arg, "-")) {
                try std.testing.expect(containsArg(lto_cmd, arg));
            }
        }
        for (lto_cmd) |arg| {
            if (std.mem.startsWith(u8, arg, "-") and !std.mem.eql(u8, arg, "-flto")) {
                try std.testing.expect(containsArg(base_cmd, arg));
            }
        }
    }
}

test "parseDefinedSymbols extracts defined symbol names" {
    const a = std.testing.allocator;
    var syms = try parseDefinedSymbols(
        a,
        "0000000001001000 T main\n0000000001001020 T lto_proof_callee\n\n",
    );
    defer syms.deinit();
    try std.testing.expect(syms.contains("main"));
    try std.testing.expect(syms.contains("lto_proof_callee"));
    try std.testing.expect(!syms.contains("absent"));

    var empty = try parseDefinedSymbols(a, "   \n\n");
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.count());
}

test "checkProofResult reports missing baseline and retained LTO symbols" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var both = std.StringHashMap(void).init(a);
    try both.put("main", {});
    try both.put(proof_symbol, {});

    var main_only = std.StringHashMap(void).init(a);
    try main_only.put("main", {});

    const pass = try checkProofResult(a, both, main_only, proof_symbol);
    try std.testing.expectEqual(@as(usize, 0), pass.len);

    const missing_base = try checkProofResult(a, main_only, main_only, proof_symbol);
    try std.testing.expectEqual(@as(usize, 1), missing_base.len);
    try std.testing.expect(std.mem.indexOf(u8, missing_base[0], "baseline") != null);

    const retained_lto = try checkProofResult(a, both, both, proof_symbol);
    try std.testing.expectEqual(@as(usize, 1), retained_lto.len);
    try std.testing.expect(std.mem.indexOf(u8, retained_lto[0], "LTO") != null);

    const both_fail = try checkProofResult(a, main_only, both, proof_symbol);
    try std.testing.expectEqual(@as(usize, 2), both_fail.len);
}

test "parseArguments and splitCommand validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try parseArguments(&.{
        "--work-dir", "/work/lto",
        "--zig",      "/opt/zig/zig",
        "--nm",       "llvm-nm --format=bsd",
    });
    try std.testing.expectEqualStrings("/work/lto", parsed.work_dir);
    try std.testing.expectEqualStrings("/opt/zig/zig", parsed.zig);
    try std.testing.expectEqualStrings("llvm-nm --format=bsd", parsed.nm);

    const nm_parts = try splitCommand(a, parsed.nm);
    try std.testing.expectEqual(@as(usize, 2), nm_parts.len);
    try std.testing.expectEqualStrings("llvm-nm", nm_parts[0]);
    try std.testing.expectEqualStrings("--format=bsd", nm_parts[1]);

    try std.testing.expectError(error.InvalidArguments, parseArguments(&.{ "--work-dir", "/work/lto" }));
    try std.testing.expectError(error.InvalidArguments, parseArguments(&.{ "--zig", "zig" }));
    try std.testing.expectError(error.InvalidToolCommand, splitCommand(a, "   "));
}
