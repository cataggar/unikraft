// SPDX-License-Identifier: GPL-2.0

//! Native metadata exporter. The existing C Kconfig parser owns the model;
//! olddefconfig remains the solver and native-config-tool reads solved values.
const std = @import("std");
const builtin = @import("builtin");
const kconfig = @import("kconfig.zig");
const facade_paths = @import("zig-facade-paths.zig");

extern "c" fn uk_kconfig_metadata([*:0]const u8, *const fn ([*:0]const u8, [*:0]const u8) callconv(.c) void) void;
extern "c" fn setenv([*:0]const u8, [*:0]const u8, c_int) c_int;
extern "c" fn chdir([*:0]const u8) c_int;

const Options = struct {
    base: []const u8 = "",
    app: []const u8 = "",
    output: []const u8 = "",
    config: []const u8 = "",
    metadata: []const u8 = "",
    image_name: ?[]const u8 = null,
    libraries: std.ArrayList([]const u8) = .empty,
    platforms: std.ArrayList([]const u8) = .empty,
    exclusions: std.ArrayList([]const u8) = .empty,
};

fn options(a: std.mem.Allocator, args: []const []const u8) !Options {
    var result: Options = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        if (i + 1 == args.len) return error.InvalidArguments;
        const key = args[i];
        const value = args[i + 1];
        if (std.mem.eql(u8, key, "--base")) {
            result.base = value;
        } else if (std.mem.eql(u8, key, "--app")) {
            result.app = value;
        } else if (std.mem.eql(u8, key, "--output")) {
            result.output = value;
        } else if (std.mem.eql(u8, key, "--config")) {
            result.config = value;
        } else if (std.mem.eql(u8, key, "--metadata")) {
            result.metadata = value;
        } else if (std.mem.eql(u8, key, "--image-name")) {
            result.image_name = value;
        } else if (std.mem.eql(u8, key, "--external-library")) {
            try result.libraries.append(a, value);
        } else if (std.mem.eql(u8, key, "--external-platform")) {
            try result.platforms.append(a, value);
        } else if (std.mem.eql(u8, key, "--exclude")) {
            try result.exclusions.append(a, value);
        } else return error.InvalidArguments;
    }
    if (result.base.len == 0 or result.app.len == 0 or result.output.len == 0 or
        result.config.len == 0 or result.metadata.len == 0) return error.InvalidArguments;
    return result;
}

pub const Version = struct { full: []const u8, codename: []const u8 };

pub fn versionAlloc(a: std.mem.Allocator, source: []const u8, raw_suffix: []const u8) !Version {
    const suffix = std.mem.trimEnd(u8, raw_suffix, "\r\n");
    if (std.mem.indexOfAny(u8, suffix, "\r\n") != null) return error.MultilineVersionSuffix;
    var values = std.StringHashMap([]const u8).init(a);
    defer values.deinit();
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "UK_")) continue;
        var cursor: usize = 3;
        while (cursor < line.len and std.ascii.isUpper(line[cursor])) cursor += 1;
        if (cursor == 3) continue;
        const name = line[0..cursor];
        skipSpace(line, &cursor);
        if (cursor < line.len and (line[cursor] == ':' or line[cursor] == '?')) cursor += 1;
        if (cursor == line.len or line[cursor] != '=') continue;
        try values.put(name, std.mem.trim(u8, line[cursor + 1 ..], " \t\r\x0b\x0c"));
    }
    const major = values.get("UK_VERSION") orelse return error.MissingVersion;
    const minor = values.get("UK_SUBVERSION") orelse return error.MissingVersion;
    if (major.len == 0 or minor.len == 0) return error.MissingVersion;
    const extra = values.get("UK_EXTRAVERSION") orelse "";
    return .{
        .full = try std.fmt.allocPrint(a, "{s}.{s}{s}{s}{s}", .{
            major, minor, if (extra.len != 0) "." else "", extra, suffix,
        }),
        .codename = values.get("UK_CODENAME") orelse "",
    };
}

fn rawConfig(a: std.mem.Allocator, source: []const u8) !std.StringHashMap([]const u8) {
    var values = std.StringHashMap([]const u8).init(a);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (!std.mem.startsWith(u8, line, "CONFIG_")) continue;
        const equal = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const name = line[7..equal];
        if (name.len == 0) continue;
        for (name) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '_') break;
        } else {
            try values.put(name, line[equal + 1 ..]);
        }
    }
    return values;
}

pub fn unquoteAlloc(a: std.mem.Allocator, value: []const u8) !?[]const u8 {
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return null;
    var result: std.ArrayList(u8) = .empty;
    var i: usize = 1;
    while (i < value.len - 1) : (i += 1) {
        if (value[i] == '\\' and i + 1 < value.len - 1) i += 1;
        try result.append(a, value[i]);
    }
    return try result.toOwnedSlice(a);
}

fn hostArch() []const u8 {
    return switch (builtin.cpu.arch) {
        .aarch64, .aarch64_be => "arm64",
        .arm, .armeb, .thumb, .thumbeb => "arm",
        .x86_64 => "x86_64",
        .x86 => "x86",
        else => @tagName(builtin.cpu.arch),
    };
}

fn targetArch(values: std.StringHashMap([]const u8)) []const u8 {
    inline for (.{ .{ "ARCH_X86_64", "x86_64" }, .{ "ARCH_ARM_64", "arm64" }, .{ "ARCH_ARM_32", "arm" } }) |pair| {
        if (std.mem.eql(u8, values.get(pair[0]) orelse "", "y")) return pair[1];
    }
    return hostArch();
}

fn imageName(override: ?[]const u8, configured: ?[]const u8, app: []const u8) []const u8 {
    if (override) |name| {
        if (name.len != 0) return name;
    }
    if (configured) |name| {
        if (name.len != 0) return name;
    }
    return std.fs.path.basename(app);
}

fn setEnv(a: std.mem.Allocator, name: [:0]const u8, value: []const u8) !void {
    if (setenv(name, try a.dupeZ(u8, value), 1) != 0) return error.SetEnvironmentFailed;
}

fn read(io: std.Io, a: std.mem.Allocator, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(64 * 1024 * 1024));
}

fn join(a: std.mem.Allocator, root: []const u8, path: []const u8) ![]const u8 {
    return std.fs.path.join(a, &.{ root, path });
}

// The C parser has process-global state; this executable loads exactly one model.
var model: *kconfig.Metadata = undefined;
var model_error: ?anyerror = null;
fn emitSymbol(name: [*:0]const u8, kind: [*:0]const u8) callconv(.c) void {
    if (model_error != null) return;
    const value: kconfig.SymbolType = if (std.mem.eql(u8, std.mem.span(kind), "bool"))
        .boolean
    else if (std.mem.eql(u8, std.mem.span(kind), "tristate"))
        .tristate
    else if (std.mem.eql(u8, std.mem.span(kind), "string"))
        .string
    else if (std.mem.eql(u8, std.mem.span(kind), "int"))
        .integer
    else
        .hex;
    model.addSymbol(std.mem.span(name), value) catch |err| {
        model_error = err;
    };
}

fn skipSpace(source: []const u8, cursor: *usize) void {
    while (cursor.* < source.len and std.ascii.isWhitespace(source[cursor.*])) cursor.* += 1;
}

fn consume(source: []const u8, cursor: *usize, token: []const u8) bool {
    skipSpace(source, cursor);
    if (!std.mem.startsWith(u8, source[cursor.*..], token)) return false;
    cursor.* += token.len;
    return true;
}

pub fn addPlatforms(metadata: *kconfig.Metadata, source: []const u8) !usize {
    var position: usize = 0;
    var count: usize = 0;
    while (std.mem.indexOfPos(u8, source, position, "addplat_s")) |start| {
        position = start + "addplat_s".len;
        var cursor = position;
        if (!consume(source, &cursor, ",")) continue;
        skipSpace(source, &cursor);
        const name_start = cursor;
        while (cursor < source.len and (std.ascii.isAlphanumeric(source[cursor]) or
            std.mem.indexOfScalar(u8, "_.+-", source[cursor]) != null)) cursor += 1;
        const name = source[name_start..cursor];
        if (name.len == 0 or !consume(source, &cursor, ",") or
            !consume(source, &cursor, "$(") or !consume(source, &cursor, "CONFIG_")) continue;
        const symbol_start = cursor;
        while (cursor < source.len and (std.ascii.isAlphanumeric(source[cursor]) or source[cursor] == '_')) cursor += 1;
        const symbol = source[symbol_start..cursor];
        if (symbol.len == 0 or !consume(source, &cursor, ")")) continue;
        if (metadata.typeOf(symbol) == null) return error.UndefinedPlatformSymbol;
        try metadata.addPlatform(symbol, name);
        count += 1;
        position = cursor;
    }
    return count;
}

fn canonical(a: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(io, path, a);
}

fn canonicalAllowMissing(a: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    return (try facade_paths.canonicalizeNearestExisting(a, io, try std.fs.path.resolve(a, &.{path}))).path;
}

fn platformMetadata(a: std.mem.Allocator, io: std.Io, opts: Options, metadata: *kconfig.Metadata) !void {
    var roots: std.ArrayList([]const u8) = .empty;
    const internal = try join(a, opts.base, "plat");
    var dir = std.Io.Dir.cwd().openDir(io, internal, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (dir) |*directory| {
        defer directory.close(io);
        var iterator = directory.iterate();
        while (try iterator.next(io)) |entry| {
            const path = try join(a, internal, entry.name);
            var child = std.Io.Dir.cwd().openDir(io, path, .{}) catch continue;
            child.close(io);
            try roots.append(a, path);
        }
    }
    std.mem.sort([]const u8, roots.items, {}, lessString);
    const internal_count = roots.items.len;
    for (opts.platforms.items) |path| try roots.append(a, try canonicalAllowMissing(a, io, path));
    var excluded = std.StringHashMap(void).init(a);
    for (opts.exclusions.items) |path| {
        try excluded.put(try canonicalAllowMissing(a, io, path), {});
    }
    for (roots.items, 0..) |root, i| {
        if (excluded.contains(try canonicalAllowMissing(a, io, root))) continue;
        const source = read(io, a, try join(a, root, "Makefile.uk")) catch |err| {
            if (i < internal_count and (err == error.FileNotFound or err == error.IsDir)) continue;
            return err;
        };
        const count = try addPlatforms(metadata, source);
        if (i >= internal_count and count == 0) return error.MissingPlatformRegistration;
    }
}

fn lessString(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

pub fn render(a: std.mem.Allocator, metadata: *kconfig.Metadata) ![]const u8 {
    std.mem.sort(kconfig.SymbolMetadata, metadata.symbols.items, {}, struct {
        fn less(_: void, lhs: kconfig.SymbolMetadata, rhs: kconfig.SymbolMetadata) bool {
            return std.mem.lessThan(u8, lhs.name, rhs.name);
        }
    }.less);
    std.mem.sort(kconfig.Platform, metadata.platforms.items, {}, struct {
        fn less(_: void, lhs: kconfig.Platform, rhs: kconfig.Platform) bool {
            return std.mem.lessThan(u8, lhs.symbol, rhs.symbol);
        }
    }.less);
    var output: std.Io.Writer.Allocating = .init(a);
    try output.writer.writeAll("unikraft-native-config-metadata-v1\n");
    for (metadata.symbols.items) |symbol| {
        const kind = switch (symbol.symbol_type) {
            .boolean => "bool",
            .tristate => "tristate",
            .string => "string",
            .integer => "int",
            .hex => "hex",
        };
        try output.writer.print("symbol\t{s}\t{s}\n", .{ symbol.name, kind });
    }
    for (metadata.platforms.items) |platform| {
        try output.writer.print("platform\t{s}\t{s}\n", .{ platform.symbol, platform.name });
    }
    return output.toOwnedSlice();
}

fn run(init: std.process.Init, args: []const []const u8) !void {
    const a = init.arena.allocator();
    const io = init.io;
    var opts = try options(a, args);
    opts.base = try canonical(a, io, opts.base);
    opts.app = try canonical(a, io, opts.app);
    opts.config = try canonical(a, io, opts.config);
    try std.Io.Dir.cwd().createDirPath(io, opts.output);
    opts.output = try canonical(a, io, opts.output);
    opts.metadata = try canonicalAllowMissing(a, io, opts.metadata);
    // Resolve external roots before the C parser changes its working directory.
    for (opts.platforms.items) |*path| path.* = try canonicalAllowMissing(a, io, path.*);
    for (opts.libraries.items) |*path| path.* = try canonicalAllowMissing(a, io, path.*);
    for (opts.exclusions.items) |*path| path.* = try canonicalAllowMissing(a, io, path.*);
    const values = try rawConfig(a, try read(io, a, opts.config));
    const suffix = try std.process.run(a, io, .{
        .argv = &.{try join(a, opts.base, "support/scripts/gitsha1")},
        .cwd = .{ .path = opts.base },
    });
    if (suffix.term != .exited or suffix.term.exited != 0) return error.VersionHelperFailed;
    const version = try versionAlloc(a, try read(io, a, try join(a, opts.base, "version.mk")), suffix.stdout);
    const configured_name = try unquoteAlloc(a, values.get("UK_NAME") orelse "");
    const image_name = imageName(opts.image_name, configured_name, opts.app);
    const kconfig_dir = try join(a, opts.output, "native-config/kconfig");
    try std.Io.Dir.cwd().createDirPath(io, kconfig_dir);
    const environment = .{
        .{ "CONFIG_", "CONFIG_" },                                                            .{ "KCONFIG_CONFIG", opts.config },
        .{ "HOST_ARCH", hostArch() },                                                         .{ "BUILD_DIR", opts.output },
        .{ "UK_BASE", opts.base },                                                            .{ "UK_APP", opts.app },
        .{ "UK_CONFIG", opts.config },                                                        .{ "UK_FULLVERSION", version.full },
        .{ "UK_CODENAME", version.codename },                                                 .{ "UK_ARCH", targetArch(values) },
        .{ "KCONFIG_DIR", kconfig_dir },                                                      .{ "KCONFIG_LIB_BASE", try join(a, opts.base, "lib") },
        .{ "KCONFIG_ELIB_DIRS", try std.mem.join(a, ":", opts.libraries.items) },             .{ "KCONFIG_PLAT_BASE", try join(a, opts.base, "plat") },
        .{ "KCONFIG_EPLAT_DIRS", try std.mem.join(a, ":", opts.platforms.items) },            .{ "KCONFIG_DRIV_BASE", try join(a, opts.base, "drivers") },
        .{ "KCONFIG_EAPP_DIR", if (!std.mem.eql(u8, opts.app, opts.base)) opts.app else "" }, .{ "KCONFIG_EXCLUDEDIRS", try std.mem.join(a, ":", opts.exclusions.items) },
        .{ "UK_NAME", image_name },
    };
    inline for (environment) |pair| try setEnv(a, pair[0], pair[1]);
    if (chdir(try a.dupeZ(u8, opts.base)) != 0) return error.ChangeDirectoryFailed;
    var metadata = kconfig.Metadata.init(a);
    defer metadata.deinit();
    model = &metadata;
    uk_kconfig_metadata(try a.dupeZ(u8, try join(a, opts.base, "Config.uk")), emitSymbol);
    if (model_error) |err| return err;
    try platformMetadata(a, io, opts, &metadata);
    const contents = try render(a, &metadata);
    const existing = read(io, a, opts.metadata) catch null;
    if (existing) |old| {
        if (std.mem.eql(u8, old, contents)) return;
    }
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(opts.metadata) orelse ".");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = opts.metadata, .data = contents });
}

fn mainImpl(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len > 1 and std.mem.eql(u8, args[1], "--internal-model")) {
        return run(init, args[2..]);
    }
    // conf_parse exits on invalid syntax. Isolate that unchanged C behavior so
    // all public metadata failures keep exit status 2 and warnings stay quiet.
    const argv = try std.mem.concat(a, []const u8, &.{
        &.{ args[0], "--internal-model" }, args[1..],
    });
    const result = try std.process.run(a, init.io, .{
        .argv = argv,
        .stdout_limit = .limited(64 * 1024 * 1024),
        .stderr_limit = .limited(64 * 1024 * 1024),
    });
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("{s}", .{result.stderr});
        return error.MetadataWorkerFailed;
    }
}

pub fn main(init: std.process.Init) void {
    mainImpl(init) catch |err| {
        std.debug.print("error: unable to export native configuration metadata: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

test "version metadata retains zero extra, codename, dirty suffix and rejects multiline" {
    const a = std.testing.allocator;
    const source = "UK_VERSION = 1\nUK_SUBVERSION := 2\nUK_EXTRAVERSION ?= 0\nUK_CODENAME = Test Moon\n";
    const version = try versionAlloc(a, source, "~abc-custom\r\n");
    defer a.free(version.full);
    try std.testing.expectEqualStrings("1.2.0~abc-custom", version.full);
    try std.testing.expectEqualStrings("Test Moon", version.codename);
    const release = try versionAlloc(a, "UK_VERSION=1\nUK_SUBVERSION=2\n", "");
    defer a.free(release.full);
    try std.testing.expectEqualStrings("1.2", release.full);
    try std.testing.expectError(error.MultilineVersionSuffix, versionAlloc(a, source, "a\nb\n"));
    try std.testing.expectError(error.MissingVersion, versionAlloc(a, "UK_VERSION=1\n", ""));
    try std.testing.expectError(error.MissingVersion, versionAlloc(a, "UK_VERSION: =1\nUK_SUBVERSION=2\n", ""));
}

test "raw config preserves last assignment, escaped image name and target precedence" {
    const a = std.testing.allocator;
    var values = try rawConfig(a, "CONFIG_ARCH_X86_64=n\nCONFIG_ARCH_X86_64=y\r\nCONFIG_ARCH_ARM_64=y\n");
    defer values.deinit();
    try std.testing.expectEqualStrings("x86_64", targetArch(values));
    const name = (try unquoteAlloc(a, "\"test\\\"\\\\name\"")).?;
    defer a.free(name);
    try std.testing.expectEqualStrings("test\"\\name", name);
    try std.testing.expectEqual(null, try unquoteAlloc(a, "unquoted"));
    try std.testing.expectEqualStrings("override", imageName("override", "configured", "/fixture/app"));
    try std.testing.expectEqualStrings("configured", imageName("", "configured", "/fixture/app"));
    try std.testing.expectEqualStrings("app", imageName("", "", "/fixture/app"));
}

test "platform metadata validates authoritative model and bijective registrations" {
    var metadata = kconfig.Metadata.init(std.testing.allocator);
    defer metadata.deinit();
    try metadata.addSymbol("PLAT_ACME", .boolean);
    try metadata.addSymbol("PLAT_OTHER", .boolean);
    try std.testing.expectEqual(@as(usize, 1), try addPlatforms(&metadata, "$(eval $(call addplat_s , acme-1, $( CONFIG_PLAT_ACME )))"));
    try std.testing.expectError(error.DuplicateMetadata, addPlatforms(&metadata, "addplat_s,acme-1,$(CONFIG_PLAT_ACME)"));
    try std.testing.expectError(error.ConflictingMetadata, addPlatforms(&metadata, "addplat_s,other,$(CONFIG_PLAT_ACME)"));
    try std.testing.expectError(error.ConflictingMetadata, addPlatforms(&metadata, "addplat_s,acme-1,$(CONFIG_PLAT_OTHER)"));
    try std.testing.expectError(error.UndefinedPlatformSymbol, addPlatforms(&metadata, "addplat_s,bad,$(CONFIG_MISSING)"));
    const rendered = try render(std.testing.allocator, &metadata);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "unikraft-native-config-metadata-v1\nsymbol\tPLAT_ACME\tbool\nsymbol\tPLAT_OTHER\tbool\nplatform\tPLAT_ACME\tacme-1\n",
        rendered,
    );
}
