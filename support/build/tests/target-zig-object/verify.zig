const std = @import("std");

fn runOutput(a: std.mem.Allocator, io: std.Io, argv: []const []const u8) ![]const u8 {
    const res = std.process.run(a, io, .{
        .argv = argv,
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
    }) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const fallback = if (std.mem.eql(u8, argv[0], "llvm-readelf"))
                "readelf"
            else if (std.mem.eql(u8, argv[0], "llvm-nm"))
                "nm"
            else
                return err;
            const retry_argv = try a.dupe([]const u8, argv);
            retry_argv[0] = fallback;
            break :blk try std.process.run(a, io, .{
                .argv = retry_argv,
                .stdout_limit = .limited(4 * 1024 * 1024),
                .stderr_limit = .limited(4 * 1024 * 1024),
            });
        },
        else => return err,
    };
    switch (res.term) {
        .exited => |code| if (code != 0) {
            std.debug.print("command failed: {s}\n", .{res.stderr});
            return error.CommandFailed;
        },
        else => return error.CommandFailed,
    }
    return res.stdout;
}

fn ensureNonEmptyRegularFile(io: std.Io, path: []const u8) !void {
    const st = try std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (st.kind != .file or st.size == 0) return error.InvalidArtifactFile;
}

fn expectedMachine(arch: []const u8) ![]const u8 {
    if (std.mem.eql(u8, arch, "x86_64")) return "Advanced Micro Devices X86-64";
    if (std.mem.eql(u8, arch, "arm64") or std.mem.eql(u8, arch, "aarch64")) return "AArch64";
    return error.UnsupportedArch;
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(a);

    var readelf: ?[]const u8 = null;
    var nm: ?[]const u8 = null;
    var expect_stripped = false;
    var positional_object: ?[]const u8 = null;
    var arch: ?[]const u8 = null;
    var elf: ?[]const u8 = null;
    var image_lds: ?[]const u8 = null;
    var object_flag: ?[]const u8 = null;
    var expect_symbols: std.ArrayList([]const u8) = .empty;
    var forbid_symbols: std.ArrayList([]const u8) = .empty;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--expect-stripped")) {
            expect_stripped = true;
        } else if (std.mem.eql(u8, arg, "--readelf")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            readelf = argv[i];
        } else if (std.mem.eql(u8, arg, "--nm")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            nm = argv[i];
        } else if (std.mem.eql(u8, arg, "--arch")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            arch = argv[i];
        } else if (std.mem.eql(u8, arg, "--elf")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            elf = argv[i];
        } else if (std.mem.eql(u8, arg, "--image-lds")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            image_lds = argv[i];
        } else if (std.mem.eql(u8, arg, "--object")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            object_flag = argv[i];
        } else if (std.mem.eql(u8, arg, "--expect-symbol")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            try expect_symbols.append(a, argv[i]);
        } else if (std.mem.eql(u8, arg, "--forbid-symbol")) {
            i += 1;
            if (i >= argv.len) return error.MissingOptionValue;
            try forbid_symbols.append(a, argv[i]);
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            positional_object = arg;
        } else {
            return error.UnknownOption;
        }
    }

    const readelf_cmd = readelf orelse return error.MissingReadelf;
    const nm_cmd = nm orelse return error.MissingNm;

    if (elf) |elf_path| {
        if (object_flag) |obj_path| try ensureNonEmptyRegularFile(io, obj_path);
        if (image_lds) |lds_path| try ensureNonEmptyRegularFile(io, lds_path);
        const header = try runOutput(a, io, &.{ readelf_cmd, "-h", elf_path });
        if (arch) |arch_name| {
            const machine = try expectedMachine(arch_name);
            if (std.mem.indexOf(u8, header, machine) == null) return error.UnexpectedMachineHeader;
        }
        const nm_out = try runOutput(a, io, &.{ nm_cmd, "--defined-only", elf_path });
        var defined: std.StringHashMapUnmanaged(void) = .empty;
        var lines = std.mem.splitScalar(u8, nm_out, '\n');
        while (lines.next()) |line| {
            var tok = std.mem.tokenizeAny(u8, line, " \t\r");
            _ = tok.next() orelse continue;
            _ = tok.next() orelse continue;
            const sym = tok.next() orelse continue;
            try defined.put(a, sym, {});
        }
        for (expect_symbols.items) |sym| {
            if (!defined.contains(sym)) return error.MissingExpectedSymbol;
        }
        for (forbid_symbols.items) |sym| {
            if (defined.contains(sym)) return error.ForbiddenSymbolPresent;
        }
        return;
    }

    const object = positional_object orelse object_flag orelse return error.MissingObject;
    const header = try runOutput(a, io, &.{ readelf_cmd, "--file-header", object });
    if (std.mem.indexOf(u8, header, "ELF64") == null or
        std.mem.indexOf(u8, header, "X86-64") == null or
        std.mem.indexOf(u8, header, "REL (Relocatable file)") == null)
    {
        std.debug.print("unexpected target object header:\n{s}\n", .{header});
        return error.UnexpectedTargetObjectHeader;
    }
    if (expect_stripped) {
        const sections = try runOutput(a, io, &.{ readelf_cmd, "--sections", object });
        if (std.mem.indexOf(u8, sections, ".debug_") != null) {
            std.debug.print("portable target object retains checkout-dependent DWARF\n", .{});
            return error.UnstrippedDebugSections;
        }
    }

    const symbols = try runOutput(a, io, &.{ nm_cmd, "--format=posix", object });
    if (std.mem.indexOf(u8, symbols, "issue34_zig_target_value") == null) {
        std.debug.print("target object does not export issue34_zig_target_value\n", .{});
        return error.MissingTargetSymbol;
    }

    const undefined_out = try runOutput(a, io, &.{ nm_cmd, "--undefined-only", "--format=posix", object });
    if (std.mem.trim(u8, undefined_out, " \t\r\n").len != 0) {
        std.debug.print("target object has unresolved runtime or libc symbols:\n{s}\n", .{undefined_out});
        return error.UnresolvedSymbols;
    }
}
