// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
const format = @import("postprocess-elf.zig");
const transform = @import("postprocess-image.zig");
const Files = @import("postprocess-files.zig").Files;

const limit = 1024 * 1024 * 1024;

pub fn main(init: std.process.Init) void {
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch |err| {
        fail(err);
    };
    execute(allocator, init.io, args[1..]) catch |err| {
        fail(err);
    };
}

fn fail(err: anyerror) noreturn {
    std.debug.print("error: {s}: {s}\n", .{ transform.diagnostic(err), @errorName(err) });
    std.process.exit(if (err == error.InvalidArguments or err == error.InvalidToolCommand or
        err == error.UnsupportedTransformation) 2 else 1);
}

const Options = struct {
    action: []const u8,
    tool: ?[]const u8 = null,
    objcopy: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    search_root: ?[]const u8 = null,
    names: bool = false,
    remove: std.ArrayList([]const u8) = .empty,
    positional: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        self.remove.deinit(allocator);
        self.positional.deinit(allocator);
    }

    fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Options {
        if (args.len == 0) return error.InvalidArguments;
        var result: Options = .{ .action = args[0] };
        errdefer result.deinit(allocator);
        var index: usize = 1;
        var positional_only = false;
        while (index < args.len) : (index += 1) {
            const arg = args[index];
            if (!positional_only and std.mem.eql(u8, arg, "--")) {
                positional_only = true;
                continue;
            }
            if (positional_only or !std.mem.startsWith(u8, arg, "--")) {
                try result.positional.append(allocator, arg);
                continue;
            }
            if (std.mem.eql(u8, arg, "--names")) {
                if (result.names) return error.InvalidArguments;
                result.names = true;
                continue;
            }
            index += 1;
            if (index == args.len) return error.InvalidArguments;
            const value = args[index];
            if (std.mem.eql(u8, arg, "--remove-section")) {
                try result.remove.append(allocator, value);
                continue;
            }
            const destination = if (std.mem.eql(u8, arg, "--tool"))
                &result.tool
            else if (std.mem.eql(u8, arg, "--objcopy"))
                &result.objcopy
            else if (std.mem.eql(u8, arg, "--arch"))
                &result.arch
            else if (std.mem.eql(u8, arg, "--search-root"))
                &result.search_root
            else
                return error.InvalidArguments;
            if (destination.* != null or value.len == 0) return error.InvalidArguments;
            destination.* = value;
        }
        return result;
    }
};

pub fn execute(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    var options = try Options.parse(allocator, args);
    defer options.deinit(allocator);
    const paths = options.positional.items;
    const action = options.action;
    const strip = std.mem.eql(u8, action, "strip");
    const binary = std.mem.eql(u8, action, "objcopy-binary");
    const reloc = std.mem.eql(u8, action, "uk-reloc");
    const boot = std.mem.eql(u8, action, "bootinfo");
    const efi = std.mem.eql(u8, action, "efi");
    const database = std.mem.eql(u8, action, "compile-database");
    if (!strip and !binary and !reloc and !boot and !efi and !database)
        return error.UnsupportedTransformation;
    if (paths.len != (if (reloc or boot or efi) @as(usize, 3) else @as(usize, 2)))
        return error.InvalidArguments;
    if ((options.tool != null) != (strip or binary) or
        (options.objcopy != null) != (reloc or boot) or
        (options.arch != null) != boot or
        (options.search_root != null) != database or
        (options.names and !boot) or
        (options.remove.items.len != 0 and !strip)) return error.InvalidArguments;
    if (boot and !std.mem.eql(u8, options.arch.?, "x86_64") and
        !std.mem.eql(u8, options.arch.?, "arm64")) return error.InvalidArguments;
    const input_count: usize = if (efi) 2 else 1;
    var files = try Files.init(allocator, io, paths[0..input_count], paths[input_count..]);
    defer files.deinit();

    if (database) {
        const contents = try compileDatabaseChecked(allocator, io, options.search_root.?, &files);
        defer allocator.free(contents);
        try files.write(0, contents);
        try files.commit();
        return;
    }
    const input = try files.readInput(0);
    defer allocator.free(input);
    var image = try format.Image.parse(allocator, input);
    defer image.deinit();

    if (strip or binary) {
        var command: std.ArrayList([]const u8) = .empty;
        defer command.deinit(allocator);
        const tool = try splitCommand(allocator, options.tool.?);
        defer freeCommand(allocator, tool);
        try command.appendSlice(allocator, tool);
        if (strip) {
            try command.append(allocator, "-s");
            for (options.remove.items) |section| {
                try command.appendSlice(allocator, &.{ "-R", section });
            }
            try command.appendSlice(allocator, &.{ paths[0], "-o", files.path(0) });
        } else {
            try command.appendSlice(allocator, &.{ "-O", "binary", paths[0], files.path(0) });
        }
        try run(io, command.items);
        try files.commit();
        return;
    }
    if (efi) {
        const debug_bytes = try files.readInput(1);
        defer allocator.free(debug_bytes);
        var debug = try format.Image.parse(allocator, debug_bytes);
        defer debug.deinit();
        const result = try transform.efi(allocator, image, debug);
        defer allocator.free(result);
        try files.write(0, result);
        try files.commit();
        return;
    }
    if (boot) {
        const machine: std.elf.EM = if (std.mem.eql(u8, options.arch.?, "x86_64"))
            .X86_64
        else
            .AARCH64;
        if (image.header.machine != machine) return error.ArchitectureMismatch;
    }
    const blob = if (reloc)
        try transform.relocations(allocator, image)
    else
        try transform.bootinfo(allocator, image, paths[0], options.names);
    defer allocator.free(blob);
    try files.write(0, blob);
    const tool = try splitCommand(allocator, options.objcopy.?);
    defer freeCommand(allocator, tool);
    var command: std.ArrayList([]const u8) = .empty;
    defer command.deinit(allocator);
    try command.appendSlice(allocator, tool);
    const update = try std.fmt.allocPrint(allocator, "--update-section={s}={s}", .{
        if (reloc) ".uk_reloc" else ".uk_bootinfo", files.path(0),
    });
    defer allocator.free(update);
    if (reloc) {
        // Keep the exact legacy copy + in-place objcopy sequence.
        try files.write(1, input);
        try command.appendSlice(allocator, &.{ update, files.path(1) });
    } else {
        try command.appendSlice(allocator, &.{ paths[0], update, files.path(1) });
    }
    try run(io, command.items);
    try files.commit();
}

pub fn read(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit));
}

pub fn write(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .replace = true });
    defer file.deinit(io);
    try file.file.writePositionalAll(io, bytes, 0);
    try file.replace(io);
}

pub fn run(io: std.Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{ .argv = argv });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.ToolFailed,
        else => return error.ToolFailed,
    }
}

/// POSIX shlex-style argv decoding; never passes commands through a shell.
pub fn splitCommand(allocator: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (words.items) |word| allocator.free(word);
        words.deinit(allocator);
    }
    var word: std.ArrayList(u8) = .empty;
    defer word.deinit(allocator);
    var quote: ?u8 = null;
    var started = false;
    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        const c = text[index];
        if (c == 0) return error.InvalidToolCommand;
        if (quote == null and (c == ' ' or c == '\t' or c == '\r' or c == '\n')) {
            if (started) {
                try appendWord(allocator, &words, word.items);
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
            if (quote == '"' and next != '"' and next != '\\') try word.append(allocator, '\\');
            try word.append(allocator, next);
        } else {
            try word.append(allocator, c);
        }
    }
    if (quote != null) return error.InvalidToolCommand;
    if (started) try appendWord(allocator, &words, word.items);
    if (words.items.len == 0 or words.items[0].len == 0) return error.InvalidToolCommand;
    return words.toOwnedSlice(allocator);
}

fn appendWord(allocator: std.mem.Allocator, words: *std.ArrayList([]const u8), word: []const u8) !void {
    const copy = try allocator.dupe(u8, word);
    errdefer allocator.free(copy);
    try words.append(allocator, copy);
}

pub fn freeCommand(allocator: std.mem.Allocator, words: [][]const u8) void {
    for (words) |word| allocator.free(word);
    allocator.free(words);
}

pub fn compileDatabase(allocator: std.mem.Allocator, io: std.Io, root: []const u8) ![]u8 {
    return compileDatabaseChecked(allocator, io, root, null);
}

fn compileDatabaseChecked(allocator: std.mem.Allocator, io: std.Io, root: []const u8, files: ?*Files) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "[\n");
    try collectDatabase(allocator, io, root, &result, 0, files);
    while (result.items.len > 2 and (result.items[result.items.len - 1] == ',' or
        result.items[result.items.len - 1] == '\n')) _ = result.pop();
    try result.appendSlice(allocator, "\n]\n");
    return result.toOwnedSlice(allocator);
}

fn collectDatabase(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: *std.ArrayList(u8), depth: usize, files: ?*Files) !void {
    if (depth > 64) return error.DirectoryDepthExceeded;
    var directory = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    var children: std.ArrayList([]const u8) = .empty;
    defer {
        for (children.items) |child| allocator.free(child);
        children.deinit(allocator);
    }
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        const kind = if (entry.kind == .sym_link)
            (try directory.statFile(io, entry.name, .{})).kind
        else
            entry.kind;
        if (kind == .directory) {
            const child = try std.fs.path.join(allocator, &.{ root, entry.name });
            errdefer allocator.free(child);
            try children.append(allocator, child);
        } else if (std.mem.endsWith(u8, entry.name, ".ukcmpdb.json")) {
            const file = try directory.openFile(io, entry.name, .{});
            defer file.close(io);
            if (files) |guard| try guard.addInput(file);
            var reader = file.reader(io, &.{});
            const contents = try reader.interface.allocRemaining(allocator, .limited(64 * 1024 * 1024));
            defer allocator.free(contents);
            if (!std.unicode.utf8ValidateSlice(contents)) return error.InvalidCompileDatabaseEncoding;
            if (contents.len > 64 * 1024 * 1024 -| result.items.len) return error.CompileDatabaseTooLarge;
            var index: usize = 0;
            while (index < contents.len) : (index += 1) {
                const c = contents[index];
                try result.append(allocator, if (c == '\r') '\n' else c);
                if (c == '\r' and index + 1 < contents.len and contents[index + 1] == '\n')
                    index += 1;
            }
        }
    }
    for (children.items) |child| try collectDatabase(allocator, io, child, result, depth + 1, files);
}
