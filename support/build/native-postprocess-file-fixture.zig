// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const runner = @import("native-postprocess-runner.zig");
const Files = @import("postprocess-files.zig").Files;
const fixture = @import("native-postprocess-tests.zig").fixture;
const testing = std.testing;

const Action = enum { strip, binary, reloc, bootinfo, efi, database };
const Alias = struct { path: []const u8, err: []const u8 };
const old_output = "existing distinct output";

const Case = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    native: []const u8,
    objcopy: []const u8,
    strip: []const u8,
    architecture: []const u8,
    database: []const u8,
    input: []const u8,
    debug: []const u8,

    fn args(self: Case, action: Action, side: []const u8, output: []const u8) ![]const []const u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(self.allocator, self.native);
        const prefix: []const []const u8 = switch (action) {
            .strip => &.{ "strip", "--tool", self.strip },
            .binary => &.{ "objcopy-binary", "--tool", self.objcopy },
            .reloc => &.{ "uk-reloc", "--objcopy", self.objcopy },
            .bootinfo => &.{ "bootinfo", "--objcopy", self.objcopy, "--arch", self.architecture },
            .efi => &.{"efi"},
            .database => &.{ "compile-database", "--search-root", self.database },
        };
        try argv.appendSlice(self.allocator, prefix);
        try argv.append(self.allocator, self.input);
        switch (action) {
            .efi => try argv.append(self.allocator, self.debug),
            .reloc, .bootinfo => try argv.append(self.allocator, side),
            else => {},
        }
        try argv.append(self.allocator, output);
        return argv.toOwnedSlice(self.allocator);
    }

    fn reject(self: Case, action: Action, side: []const u8, output: []const u8, err: []const u8) !void {
        try rejected(self.allocator, self.io, try self.args(action, side, output), .inherit, err);
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    native: []const u8,
    objcopy: []const u8,
    strip: []const u8,
    parent: []const u8,
    machine: std.elf.EM,
) !void {
    const root = try join(allocator, parent, "file identity fixtures");
    try std.Io.Dir.cwd().createDirPath(io, try join(allocator, root, "sub"));
    const database = try join(allocator, root, "database");
    try std.Io.Dir.cwd().createDirPath(io, database);
    try std.Io.Dir.cwd().symLink(io, root, try join(allocator, root, "via-directory"), .{ .is_directory = true });
    const input = try join(allocator, root, "image.elf");
    const debug = try join(allocator, root, "debug.elf");
    const side = try join(allocator, root, "side.bin");
    const output = try join(allocator, root, "output.elf");
    const bytes = fixture(.little, machine);
    try runner.write(io, input, &bytes);
    try runner.write(io, debug, &bytes);
    try runner.write(io, side, old_output);
    try runner.write(io, output, old_output);
    const case: Case = .{
        .allocator = allocator,
        .io = io,
        .native = native,
        .objcopy = objcopy,
        .strip = strip,
        .architecture = if (machine == .X86_64) "x86_64" else "arm64",
        .database = database,
        .input = input,
        .debug = debug,
    };
    const input_aliases = try aliases(allocator, io, root, "image.elf");
    const debug_aliases = try aliases(allocator, io, root, "debug.elf");
    for (std.enums.values(Action)) |action| {
        for (input_aliases) |alias| {
            try case.reject(action, side, alias.path, alias.err);
            if (action == .reloc or action == .bootinfo)
                try case.reject(action, alias.path, output, alias.err);
            try equal(allocator, io, input, &bytes);
            try equal(allocator, io, alias.path, &bytes);
            try equal(allocator, io, debug, &bytes);
            try equal(allocator, io, side, old_output);
            try equal(allocator, io, output, old_output);
        }
        if (action == .efi) {
            for (debug_aliases) |alias| {
                try case.reject(action, side, alias.path, alias.err);
                try equal(allocator, io, debug, &bytes);
                try equal(allocator, io, alias.path, &bytes);
            }
        }
    }

    const absolute_native = try std.Io.Dir.cwd().realPathFileAlloc(io, native, allocator);
    try rejected(allocator, io, &.{ absolute_native, "efi", "./image.elf", "debug.elf", "image.elf" }, .{ .path = root }, "InPlaceMutation");
    try equal(allocator, io, input, &bytes);

    // Also reject output/output aliases, including a destination not yet created.
    const output_aliases = try aliases(allocator, io, root, "output.elf");
    for ([_]Action{ .reloc, .bootinfo }) |action| {
        for (output_aliases) |alias| {
            try case.reject(action, alias.path, output, if (std.mem.eql(u8, alias.err, "OutputSymlink")) "OutputSymlink" else "AliasedOutputs");
            try equal(allocator, io, alias.path, old_output);
            try equal(allocator, io, output, old_output);
        }
        const missing = try join(allocator, root, "not created");
        try case.reject(action, missing, try join(allocator, root, "sub/../not created"), "AliasedOutputs");
        try testing.expectError(error.FileNotFound, runner.read(allocator, io, missing));
    }

    // No output symlink is followed, including links to unrelated files or
    // dangling targets. A failure must preserve the link itself as well.
    const dangling_target = try join(allocator, root, "absent target");
    const dangling = try join(allocator, root, "dangling output");
    try std.Io.Dir.cwd().symLink(io, dangling_target, dangling, .{});
    try case.reject(.efi, side, dangling, "OutputSymlink");
    try testing.expectEqual(std.Io.File.Kind.sym_link, (try std.Io.Dir.cwd().statFile(io, dangling, .{ .follow_symlinks = false })).kind);
    try testing.expectError(error.FileNotFound, runner.read(allocator, io, dangling_target));

    const fragment = try join(allocator, database, "input.ukcmpdb.json");
    try runner.write(io, fragment, "{\"file\":\"one.c\"},\n");
    const fragment_alias = try join(allocator, root, "fragment alias.json");
    try std.Io.Dir.cwd().hardLink(fragment, .cwd(), fragment_alias, io, .{});
    try case.reject(.database, side, fragment_alias, "InPlaceMutation");
    try equal(allocator, io, fragment, "{\"file\":\"one.c\"},\n");
    try equal(allocator, io, fragment_alias, "{\"file\":\"one.c\"},\n");

    // Rebuilding every operation into existing distinct regular outputs is
    // legitimate, including using one ELF as both read-only EFI inputs.
    for (std.enums.values(Action)) |action| {
        const good_output = try join(allocator, root, try std.fmt.allocPrint(allocator, "rebuilt-{s}", .{@tagName(action)}));
        const good_side = try std.fmt.allocPrint(allocator, "{s}.side", .{good_output});
        try runner.write(io, good_output, old_output);
        try runner.write(io, good_side, old_output);
        const backup = try std.fmt.allocPrint(allocator, "{s}.backup", .{good_output});
        try std.Io.Dir.cwd().hardLink(good_output, .cwd(), backup, io, .{});
        var rebuild = case;
        if (action == .efi) rebuild.debug = input_aliases[4].path;
        const argv = try rebuild.args(action, good_side, good_output);
        try runner.run(io, argv);
        const expected_output = try runner.read(allocator, io, good_output);
        const expected_side = try runner.read(allocator, io, good_side);
        try runner.run(io, argv);
        try equal(allocator, io, good_output, expected_output);
        try equal(allocator, io, good_side, expected_side);
        try equal(allocator, io, backup, old_output);

        if (action == .strip or action == .binary or action == .reloc or action == .bootinfo) {
            var failing = case;
            failing.objcopy = try std.fmt.allocPrint(allocator, "{s} --invalid-fixture-option", .{objcopy});
            failing.strip = try std.fmt.allocPrint(allocator, "{s} --invalid-fixture-option", .{strip});
            try failing.reject(action, good_side, good_output, "ToolFailed");
            try equal(allocator, io, good_output, expected_output);
            try equal(allocator, io, good_side, expected_side);
        }
        try equal(allocator, io, input, &bytes);
        try equal(allocator, io, debug, &bytes);
    }
    try publicationAliases(allocator, io, input, &bytes, root);
    try emptySymbols(allocator, io, case, root, machine);
    var directory = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    var entries = directory.iterate();
    while (try entries.next(io)) |entry|
        try testing.expect(!std.mem.startsWith(u8, entry.name, ".native-postprocess-"));
}

fn aliases(allocator: std.mem.Allocator, io: std.Io, root: []const u8, basename: []const u8) ![6]Alias {
    const source = try join(allocator, root, basename);
    const hard = try std.fmt.allocPrint(allocator, "{s}/hard-{s}", .{ root, basename });
    const sym = try std.fmt.allocPrint(allocator, "{s}/symbolic-{s}", .{ root, basename });
    try std.Io.Dir.cwd().hardLink(source, .cwd(), hard, io, .{});
    try std.Io.Dir.cwd().symLink(io, source, sym, .{});
    return .{
        .{ .path = source, .err = "InPlaceMutation" },
        .{ .path = try std.fmt.allocPrint(allocator, "{s}/./{s}", .{ root, basename }), .err = "InPlaceMutation" },
        .{ .path = try std.fmt.allocPrint(allocator, "{s}/sub/../{s}", .{ root, basename }), .err = "InPlaceMutation" },
        .{ .path = hard, .err = "InPlaceMutation" },
        .{ .path = sym, .err = "OutputSymlink" },
        .{ .path = try std.fmt.allocPrint(allocator, "{s}/via-directory/{s}", .{ root, basename }), .err = "InPlaceMutation" },
    };
}

fn publicationAliases(allocator: std.mem.Allocator, io: std.Io, input: []const u8, bytes: []const u8, root: []const u8) !void {
    for ([_]bool{ false, true }) |symlink| {
        const output = try join(allocator, root, if (symlink) "changed symlink" else "changed hardlink");
        const side = try std.fmt.allocPrint(allocator, "{s}.side", .{output});
        try runner.write(io, output, old_output);
        try runner.write(io, side, old_output);
        {
            var files = try Files.init(allocator, io, &.{input}, &.{ side, output });
            defer files.deinit();
            try files.write(0, "new side");
            try files.write(1, "new image");
            try std.Io.Dir.cwd().deleteFile(io, output);
            if (symlink)
                try std.Io.Dir.cwd().symLink(io, input, output, .{})
            else
                try std.Io.Dir.cwd().hardLink(input, .cwd(), output, io, .{});
            if (symlink)
                try testing.expectError(error.OutputSymlink, files.commit())
            else
                try testing.expectError(error.InPlaceMutation, files.commit());
        }
        try equal(allocator, io, input, bytes);
        try equal(allocator, io, output, bytes);
        try equal(allocator, io, side, old_output);
        if (symlink) try testing.expectEqual(std.Io.File.Kind.sym_link, (try std.Io.Dir.cwd().statFile(io, output, .{ .follow_symlinks = false })).kind);
    }
}

fn emptySymbols(allocator: std.mem.Allocator, io: std.Io, case: Case, root: []const u8, machine: std.elf.EM) !void {
    for ([_]std.builtin.Endian{ .little, .big }) |endian| {
        for ([_]u32{ std.elf.SHT_SYMTAB, std.elf.SHT_DYNSYM }) |kind| {
            var bytes = fixture(endian, machine);
            const header = 0x7000 + 3 * 64;
            std.mem.writeInt(u32, bytes[header + 4 ..][0..4], kind, endian);
            std.mem.writeInt(u64, bytes[header + 32 ..][0..8], 0, endian);
            std.mem.writeInt(u32, bytes[header + 44 ..][0..4], 0, endian);
            const input = try join(allocator, root, try std.fmt.allocPrint(allocator, "empty-{s}-{d}.elf", .{ @tagName(endian), kind }));
            const output = try std.fmt.allocPrint(allocator, "{s}.out", .{input});
            try runner.write(io, input, &bytes);
            try runner.write(io, output, old_output);
            var invalid = case;
            invalid.input = input;
            try invalid.reject(.strip, "", output, "InvalidSymbolTable");
            try equal(allocator, io, input, &bytes);
            try equal(allocator, io, output, old_output);
        }
    }
}

fn rejected(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8, cwd: std.process.Child.Cwd, err: []const u8) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = args,
        .cwd = cwd,
        .stderr_limit = .limited(64 * 1024),
        .stdout_limit = .limited(64 * 1024),
    });
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, err) != null);
}

fn join(allocator: std.mem.Allocator, parent: []const u8, name: []const u8) ![]const u8 {
    return std.fs.path.join(allocator, &.{ parent, name });
}

fn equal(allocator: std.mem.Allocator, io: std.Io, path: []const u8, expected: []const u8) !void {
    try testing.expectEqualSlices(u8, expected, try runner.read(allocator, io, path));
}
