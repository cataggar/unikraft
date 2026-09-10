// SPDX-License-Identifier: BSD-3-Clause

//! Preserve per-library objcopy localization at the flat LTO link boundary.
const std = @import("std");
const Set = std.StringHashMap(void);
const Symbols = std.StringHashMap(u8);

pub const Library = struct {
    name: []const u8,
    export_files: std.ArrayList([]const u8) = .empty,
    inputs: std.ArrayList([]const u8) = .empty,
};

pub const Arguments = struct {
    nm: []const u8 = "",
    output: []const u8 = "",
    force_keep_output: ?[]const u8 = null,
    libraries: std.ArrayList(Library) = .empty,
};

pub fn parseArguments(a: std.mem.Allocator, args: []const []const u8) !Arguments {
    var result: Arguments = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        if (i + 1 == args.len) return error.InvalidArguments;
        const key = args[i];
        const value = args[i + 1];
        if (std.mem.eql(u8, key, "--nm")) {
            result.nm = value;
        } else if (std.mem.eql(u8, key, "--output")) {
            result.output = value;
        } else if (std.mem.eql(u8, key, "--force-keep-output")) {
            result.force_keep_output = value;
        } else if (std.mem.eql(u8, key, "--library")) {
            try result.libraries.append(a, .{ .name = value });
        } else {
            if (result.libraries.items.len == 0) return error.InvalidArguments;
            const library = &result.libraries.items[result.libraries.items.len - 1];
            if (std.mem.eql(u8, key, "--input")) {
                try library.inputs.append(a, value);
            } else if (std.mem.eql(u8, key, "--export-file")) {
                try library.export_files.append(a, value);
            } else return error.InvalidArguments;
        }
    }
    if (result.nm.len == 0 or result.output.len == 0) return error.InvalidArguments;
    return result;
}

pub fn addExports(exports: *Set, source: []const u8) !void {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r\n\x0b\x0c");
        if (line.len == 0 or line[0] == '#') continue;
        try exports.put(line, {});
    }
}

fn isUndefined(kind: u8) bool {
    return kind == 'U' or kind == 'w' or kind == 'v';
}

fn isWeak(kind: u8) bool {
    return kind == 'W' or kind == 'V';
}

pub fn dominant(a: u8, b: u8) u8 {
    for ([_]u8{ a, b }) |kind| {
        if (!isUndefined(kind) and !isWeak(kind)) return kind;
    }
    for ([_]u8{ a, b }) |kind| {
        if (!isUndefined(kind)) return kind;
    }
    return a;
}

pub const NmDiagnostic = struct { line: usize = 0, text: []const u8 = "" };

pub fn parseNm(a: std.mem.Allocator, source: []const u8, diagnostic: *NmDiagnostic) !Symbols {
    var symbols = Symbols.init(a);
    errdefer symbols.deinit();
    var lines = std.mem.splitScalar(u8, source, '\n');
    var number: usize = 0;
    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r\n\x0b\x0c");
        if (line.len == 0) continue;
        var words = std.mem.tokenizeAny(u8, line, " \t\r\n\x0b\x0c");
        const name = words.next().?;
        const kind = words.next();
        if (kind != null and kind.?.len == 1 and
            (std.ascii.isAlphabetic(kind.?[0]) or kind.?[0] == '?'))
        {
            const entry = try symbols.getOrPut(name);
            entry.value_ptr.* = if (entry.found_existing)
                dominant(entry.value_ptr.*, kind.?[0])
            else
                kind.?[0];
        } else if (line.len > 1 and line[line.len - 1] == ':') {
            continue;
        } else {
            diagnostic.* = .{ .line = number, .text = line };
            return error.InvalidNmOutput;
        }
    }
    return symbols;
}

pub const LibrarySymbols = struct {
    name: []const u8,
    has_policy: bool,
    exports: Set,
    defined: Set,
    undefined: Set,

    pub fn init(a: std.mem.Allocator, name: []const u8, has_policy: bool) LibrarySymbols {
        return .{
            .name = name,
            .has_policy = has_policy,
            .exports = Set.init(a),
            .defined = Set.init(a),
            .undefined = Set.init(a),
        };
    }

    pub fn addNm(self: *LibrarySymbols, symbols: Symbols) !void {
        var iterator = symbols.iterator();
        while (iterator.next()) |entry| {
            if (isUndefined(entry.value_ptr.*)) {
                try self.undefined.put(entry.key_ptr.*, {});
            } else {
                try self.defined.put(entry.key_ptr.*, {});
            }
        }
    }

    pub fn isPrivate(self: LibrarySymbols, name: []const u8) bool {
        return self.has_policy and !self.exports.contains(name);
    }
};

pub const Policy = struct { globals: []const []const u8, errors: []const []const u8 };

fn sortedKeys(a: std.mem.Allocator, set: Set) ![][]const u8 {
    const keys = try a.alloc([]const u8, set.count());
    var iterator = set.keyIterator();
    var i: usize = 0;
    while (iterator.next()) |key| : (i += 1) keys[i] = key.*;
    std.mem.sort([]const u8, keys, {}, lessString);
    return keys;
}

fn lessString(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

pub fn validate(a: std.mem.Allocator, libraries: []const LibrarySymbols) !Policy {
    var globals = Set.init(a);
    defer globals.deinit();
    var all_definitions = Set.init(a);
    defer all_definitions.deinit();
    var errors: std.ArrayList([]const u8) = .empty;
    for (libraries) |library| {
        var iterator = library.defined.keyIterator();
        while (iterator.next()) |name| {
            try all_definitions.put(name.*, {});
            if (!library.isPrivate(name.*)) try globals.put(name.*, {});
        }
    }
    const definitions = try sortedKeys(a, all_definitions);
    defer a.free(definitions);
    for (definitions) |symbol| {
        var providers: std.ArrayList([]const u8) = .empty;
        defer providers.deinit(a);
        var has_private = false;
        var private_owner: ?[]const u8 = null;
        for (libraries) |library| {
            if (!library.defined.contains(symbol)) continue;
            const private = library.isPrivate(symbol);
            has_private = has_private or private;
            if (private_owner == null) private_owner = library.name;
            try providers.append(a, try std.fmt.allocPrint(a, "{s}({s})", .{
                library.name, if (private) "private" else "global",
            }));
        }
        if (providers.items.len > 1 and has_private) {
            std.mem.sort([]const u8, providers.items, {}, lessString);
            try errors.append(a, try std.fmt.allocPrint(a, "symbol '{s}' has conflicting definitions that flat linking cannot represent: {s}", .{ symbol, try std.mem.join(a, ", ", providers.items) }));
        }
        if (!globals.contains(symbol)) {
            for (libraries) |library| {
                if (library.undefined.contains(symbol) and !library.defined.contains(symbol) and
                    !std.mem.eql(u8, library.name, private_owner.?))
                {
                    try errors.append(a, try std.fmt.allocPrint(a, "library '{s}' references private symbol '{s}' defined only in '{s}'", .{ library.name, symbol, private_owner.? }));
                }
            }
        }
    }
    std.mem.sort([]const u8, errors.items, {}, lessString);
    return .{ .globals = try sortedKeys(a, globals), .errors = try errors.toOwnedSlice(a) };
}

fn quote(writer: *std.Io.Writer, name: []const u8) !void {
    try writer.writeByte('"');
    for (name) |byte| {
        if (byte == '\\' or byte == '"') try writer.writeByte('\\');
        try writer.writeByte(byte);
    }
    try writer.writeByte('"');
}

fn identifier(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name, 0..) |byte, i| {
        if (std.ascii.isAlphabetic(byte) or std.mem.indexOfScalar(u8, "_.$", byte) != null) continue;
        if (i > 0 and std.ascii.isDigit(byte)) continue;
        return false;
    }
    return true;
}

pub fn versionScript(a: std.mem.Allocator, globals: []const []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    // Retain the historical marker for byte-identical version-script artifacts.
    try out.writer.writeAll("/* Generated by lto-symbol-policy.py -- do not edit. */\n{\n  global:\n");
    for (globals) |symbol| {
        try out.writer.writeAll("    ");
        if (identifier(symbol)) try out.writer.writeAll(symbol) else try quote(&out.writer, symbol);
        try out.writer.writeAll(";\n");
    }
    try out.writer.writeAll("  local:\n    *;\n};\n");
    return out.toOwnedSlice();
}

pub fn forceKeep(a: std.mem.Allocator, exports: Set) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    const symbols = try sortedKeys(a, exports);
    defer a.free(symbols);
    for (symbols) |symbol| {
        const argument = try std.fmt.allocPrint(a, "-Wl,-u,{s}", .{symbol});
        defer a.free(argument);
        try quote(&out.writer, argument);
        try out.writer.writeByte('\n');
    }
    return out.toOwnedSlice();
}

fn read(io: std.Io, a: std.mem.Allocator, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(64 * 1024 * 1024));
}

fn write(io: std.Io, path: []const u8, contents: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(path) orelse ".");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = contents });
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    const parsed = try parseArguments(a, args[1..]);
    var libraries: std.ArrayList(LibrarySymbols) = .empty;
    var force_keep = Set.init(a);
    for (parsed.libraries.items) |spec| {
        var library = LibrarySymbols.init(a, spec.name, spec.export_files.items.len != 0);
        for (spec.export_files.items) |path| {
            const contents = try read(io, a, path);
            try addExports(&library.exports, contents);
            try addExports(&force_keep, contents);
        }
        for (spec.inputs.items) |path| {
            const nm = std.process.run(a, io, .{
                .argv = &.{ parsed.nm, "-g", "--format=posix", path },
                .stdout_limit = .limited(64 * 1024 * 1024),
                .stderr_limit = .limited(1024 * 1024),
            }) catch |err| {
                std.debug.print("error: nm failed for '{s}': {s}\n", .{ path, @errorName(err) });
                return err;
            };
            if (nm.term != .exited or nm.term.exited != 0) {
                std.debug.print("error: nm failed for '{s}':\n  command: {s} -g --format=posix {s}\n  stderr: {s}\n", .{
                    path, parsed.nm, path, std.mem.trim(u8, nm.stderr, " \r\n\t"),
                });
                return error.NmFailed;
            }
            var diagnostic: NmDiagnostic = .{};
            const symbols = parseNm(a, nm.stdout, &diagnostic) catch |err| {
                std.debug.print("error: unrecognized nm output for '{s}' line {d}: {s}\n", .{
                    path, diagnostic.line, diagnostic.text,
                });
                return err;
            };
            try library.addNm(symbols);
        }
        try libraries.append(a, library);
    }
    const policy = try validate(a, libraries.items);
    if (policy.errors.len != 0) {
        std.debug.print("error: LTO symbol-policy violations detected:\n", .{});
        for (policy.errors) |message| std.debug.print("  {s}\n", .{message});
        std.process.exit(1);
    }
    try write(io, parsed.output, try versionScript(a, policy.globals));
    if (parsed.force_keep_output) |path| try write(io, path, try forceKeep(a, force_keep));
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("error: LTO symbol policy: {s}\n", .{@errorName(err)});
        std.process.exit(if (err == error.InvalidArguments) 3 else 2);
    };
}

test "nm archives weak and strong dominance and malformed diagnostics" {
    const a = std.testing.allocator;
    var diagnostic: NmDiagnostic = .{};
    var symbols = try parseNm(a, "lib.a(a.o):\nfoo U\nfoo W 1 2\nfoo T 3 4\nweak w\nweak V 0 0\n", &diagnostic);
    defer symbols.deinit();
    try std.testing.expectEqual(@as(u8, 'T'), symbols.get("foo").?);
    try std.testing.expectEqual(@as(u8, 'V'), symbols.get("weak").?);
    try std.testing.expectEqual(@as(u8, 'U'), dominant('U', 'v'));
    try std.testing.expectError(error.InvalidNmOutput, parseNm(a, "ok T\nbad line here\n", &diagnostic));
    try std.testing.expectEqual(@as(usize, 2), diagnostic.line);
    try std.testing.expectEqualStrings("bad line here", diagnostic.text);
    try std.testing.expectError(error.InvalidNmOutput, parseNm(a, "foo TT\n", &diagnostic));
}

test "ordered CLI library groups and invalid arguments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try parseArguments(a, &.{
        "--library", "a",          "--export-file", "exports.uk", "--input", "a.o",
        "--nm",      "llvm-nm",    "--library",     "b",          "--input", "b.a",
        "--output",  "policy.lds",
    });
    try std.testing.expectEqual(@as(usize, 2), args.libraries.items.len);
    try std.testing.expectEqualStrings("exports.uk", args.libraries.items[0].export_files.items[0]);
    try std.testing.expectEqualStrings("b.a", args.libraries.items[1].inputs.items[0]);
    inline for (.{ &.{"--library"}, &.{ "--input", "a.o" }, &.{ "--unknown", "value" }, &.{ "--nm", "nm" } }) |invalid| {
        try std.testing.expectError(error.InvalidArguments, parseArguments(a, invalid));
    }
}

test "localization private references collisions global coexistence and internal references" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var first = LibrarySymbols.init(a, "first", true);
    try addExports(&first.exports, "# ignored\napi\nundefined_export\napi\n");
    try first.defined.put("api", {});
    try first.defined.put("private", {});
    try first.undefined.put("private", {});
    var second = LibrarySymbols.init(a, "second", false);
    try second.defined.put("global", {});
    var policy = try validate(a, &.{ first, second });
    try std.testing.expectEqual(@as(usize, 0), policy.errors.len);
    try std.testing.expectEqualSlices([]const u8, &.{ "api", "global" }, policy.globals);
    try second.undefined.put("private", {});
    policy = try validate(a, &.{ first, second });
    try std.testing.expectEqual(@as(usize, 1), policy.errors.len);
    try std.testing.expectEqualStrings("library 'second' references private symbol 'private' defined only in 'first'", policy.errors[0]);
    try second.defined.put("private", {});
    policy = try validate(a, &.{ first, second });
    try std.testing.expectEqual(@as(usize, 1), policy.errors.len);
    try std.testing.expectEqualStrings("symbol 'private' has conflicting definitions that flat linking cannot represent: first(private), second(global)", policy.errors[0]);
    try first.exports.put("private", {});
    policy = try validate(a, &.{ first, second });
    try std.testing.expectEqual(@as(usize, 0), policy.errors.len);
    second.has_policy = true;
    first.has_policy = true;
    _ = first.exports.remove("private");
    policy = try validate(a, &.{ first, second });
    try std.testing.expectEqual(@as(usize, 1), policy.errors.len);
    try std.testing.expect(std.mem.indexOf(u8, policy.errors[0], "second(private)") != null);
}

test "version script exact bytes escaping and force keep exports independent of definitions" {
    const a = std.testing.allocator;
    const script = try versionScript(a, &.{ "api", "name@v1", "quote\"slash\\" });
    defer a.free(script);
    try std.testing.expectEqualStrings(
        "/* Generated by lto-symbol-policy.py -- do not edit. */\n{\n  global:\n" ++
            "    api;\n    \"name@v1\";\n    \"quote\\\"slash\\\\\";\n  local:\n    *;\n};\n",
        script,
    );
    var exports = Set.init(a);
    defer exports.deinit();
    try addExports(&exports, "undefined_export\napi\n# ignored\napi\nquote\"slash\\\n");
    const response = try forceKeep(a, exports);
    defer a.free(response);
    try std.testing.expectEqualStrings(
        "\"-Wl,-u,api\"\n\"-Wl,-u,quote\\\"slash\\\\\"\n\"-Wl,-u,undefined_export\"\n",
        response,
    );
}
