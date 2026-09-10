// SPDX-License-Identifier: BSD-3-Clause

//! Native subprocess fixtures. All mutable paths are supplied by std.Build.
const std = @import("std");
const kconfig = @import("kconfig.zig");

const Fixture = struct {
    a: std.mem.Allocator,
    io: std.Io,
    root: []const u8,

    fn path(self: Fixture, name: []const u8) ![]const u8 {
        return std.fs.path.join(self.a, &.{ self.root, name });
    }

    fn write(self: Fixture, name: []const u8, contents: []const u8, executable: bool) ![]const u8 {
        const output = try self.path(name);
        try std.Io.Dir.cwd().createDirPath(self.io, std.fs.path.dirname(output).?);
        const file = try std.Io.Dir.cwd().createFile(self.io, output, .{
            .permissions = .fromMode(if (executable) 0o700 else 0o600),
        });
        defer file.close(self.io);
        try file.writePositionalAll(self.io, contents, 0);
        return output;
    }

    fn read(self: Fixture, path_: []const u8) ![]const u8 {
        return std.Io.Dir.cwd().readFileAlloc(self.io, path_, self.a, .limited(64 * 1024 * 1024));
    }

    fn expectRun(self: Fixture, argv: []const []const u8, expected: u8) !void {
        const result = try std.process.run(self.a, self.io, .{ .argv = argv });
        if (result.term != .exited or result.term.exited != expected) {
            std.debug.print("fixture expected exit {d}: {s}\nstdout: {s}\nstderr: {s}\n", .{
                expected, argv[0], result.stdout, result.stderr,
            });
            return error.UnexpectedExitStatus;
        }
    }
};

fn metadataFixtures(f: Fixture, tool: []const u8, config_tool: []const u8) !void {
    const base = try f.path("base");
    _ = try f.write("base/version.mk", "UK_VERSION = 1\nUK_SUBVERSION = 2\nUK_EXTRAVERSION = 0\nUK_CODENAME = Test Moon\n", false);
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nprintf '%s\\n' '~fixture'\n", true);
    _ = try f.write("base/Config.uk",
        \\config ARCH_X86_64
        \\ bool
        \\config PLAT_ACME
        \\ bool
        \\config HAVE_BOOTENTRY
        \\ bool
        \\config UK_NAME
        \\ string
        \\config VALUE_HEX
        \\ hex
        \\config VALUE_INT
        \\ int
        \\config INVISIBLE
        \\ tristate
        \\ depends on n
        \\choice NAMED_CHOICE
        \\ prompt "Named choice"
        \\ bool
        \\config CHOICE_VALUE
        \\ bool "Choice value"
        \\endchoice
        \\source "$(UK_BASE)/version/$(UK_FULLVERSION)/Config.uk"
        \\source "$(UK_BASE)/names/$(UK_NAME)/Config.uk"
        \\source "$(UK_BASE)/codename/$(UK_CODENAME)/Config.uk"
        \\
    , false);
    _ = try f.write("base/version/1.2.0~fixture/Config.uk", "config VERSION_PATH\n string\n", false);
    _ = try f.write("base/names/fixture/Config.uk", "config NAME_PATH\n string\n", false);
    _ = try f.write("base/codename/Test Moon/Config.uk", "config CODENAME_PATH\n string\n", false);
    const config = try f.write("config", "CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_ACME=y\nCONFIG_HAVE_BOOTENTRY=y\n" ++
        "CONFIG_UK_NAME=\"fixture\"\nCONFIG_VALUE_HEX=DEAD\nCONFIG_VALUE_INT=-10\nCONFIG_INVISIBLE=y\n", false);
    const original_config = try f.read(config);
    const platform = try f.path("external");
    _ = try f.write("external/Makefile.uk", "$(eval $(call addplat_s,acme,$(CONFIG_PLAT_ACME)))\n", false);
    const output = try f.path("metadata-output");
    const metadata_path = try f.path("metadata-output/metadata.tsv");
    const argv = [_][]const u8{
        tool,         "--base",      base,                  "--app",  base, "--output", output, "--config", config,
        "--metadata", metadata_path, "--external-platform", platform,
    };
    try f.expectRun(&argv, 0);
    const contents = try f.read(metadata_path);
    var metadata = try kconfig.Metadata.parse(f.a, contents);
    try std.testing.expectEqual(kconfig.SymbolType.hex, metadata.typeOf("VALUE_HEX").?);
    try std.testing.expectEqual(kconfig.SymbolType.integer, metadata.typeOf("VALUE_INT").?);
    try std.testing.expectEqual(kconfig.SymbolType.tristate, metadata.typeOf("INVISIBLE").?);
    for ([_][]const u8{ "VERSION_PATH", "NAME_PATH", "CODENAME_PATH" }) |name| {
        try std.testing.expectEqual(kconfig.SymbolType.string, metadata.typeOf(name).?);
    }
    try std.testing.expectEqual(null, metadata.typeOf("NAMED_CHOICE"));
    try std.testing.expectEqualStrings("acme", metadata.platforms.items[0].name);
    const stat_before = try std.Io.Dir.cwd().statFile(f.io, metadata_path, .{});
    try f.expectRun(&argv, 0);
    const stat_after = try std.Io.Dir.cwd().statFile(f.io, metadata_path, .{});
    try std.testing.expectEqual(stat_before.mtime, stat_after.mtime);
    try std.testing.expectEqualStrings(contents, try f.read(metadata_path));
    try std.testing.expectEqualStrings(original_config, try f.read(config));
    const header = try f.path("config.h");
    try f.expectRun(&.{ config_tool, "validate", config, metadata_path }, 0);
    try f.expectRun(&.{ config_tool, "header", config, metadata_path, header }, 0);
    const header_contents = try f.read(header);
    try std.testing.expect(std.mem.indexOf(u8, header_contents, "#define CONFIG_VALUE_HEX 0xDEAD\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, header_contents, "#define CONFIG_VALUE_INT -10\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, header_contents, "#define CONFIG_INVISIBLE 1\n") != null);

    const duplicate = try std.mem.concat(f.a, []const u8, &.{ &argv, &.{ "--external-platform", platform } });
    try f.expectRun(duplicate, 2);
    try std.testing.expectEqualStrings(contents, try f.read(metadata_path));
    const excluded = try std.mem.concat(f.a, []const u8, &.{ &argv, &.{ "--exclude", platform } });
    try f.expectRun(excluded, 0);
    const without_platform = try kconfig.Metadata.parse(f.a, try f.read(metadata_path));
    try std.testing.expectEqual(@as(usize, 0), without_platform.platforms.items.len);
    const missing_platform = try f.path("excluded-missing-platform");
    const excluded_missing = try std.mem.concat(f.a, []const u8, &.{
        &argv, &.{ "--external-platform", missing_platform, "--exclude", missing_platform },
    });
    try f.expectRun(excluded_missing, 0);

    _ = try f.write("external/Makefile.uk", "addplat_s,bad,$(CONFIG_MISSING)\n", false);
    try f.expectRun(&argv, 2);
    _ = try f.write("external/Makefile.uk", "# no registration\n", false);
    try f.expectRun(&argv, 2);
    try std.Io.Dir.cwd().deleteFile(f.io, try f.path("external/Makefile.uk"));
    try f.expectRun(&argv, 2);
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nprintf 'one\\ntwo\\n'\n", true);
    try f.expectRun(&argv, 2);
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nexit 7\n", true);
    try f.expectRun(&argv, 2);
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nprintf '%s\\n' '~fixture'\n", true);
    _ = try f.write("base/Config.uk", "invalid kconfig syntax\n", false);
    try f.expectRun(&argv, 2);
    _ = try f.write("base/Config.uk", "source \"missing-Kconfig-source\"\n", false);
    try f.expectRun(&argv, 2);
    try std.testing.expectEqualStrings(original_config, try f.read(config));
}

fn policyFixtures(f: Fixture, tool: []const u8) !void {
    const nm = try f.write("nm",
        \\#!/bin/sh
        \\test "$1" = "-g" && test "$2" = "--format=posix" || exit 8
        \\case "$3" in
        \\  first.o) printf 'api T\nprivate T\nlocal_ref U\nlocal_ref T\n';;
        \\  second.o) printf 'api U\napp T\n';;
        \\  private-reference.o) printf 'private U\n';;
        \\  private-provider.o) printf 'private W\n';;
        \\  archive.a) printf 'archive.a(member.o):\napi U\napi W\napi T\n';;
        \\  malformed.o) printf 'valid T\nnot-a-symbol\n';;
        \\  failed.o) printf 'fixture nm failure\n' >&2; exit 4;;
        \\  *) exit 9;;
        \\esac
        \\
    , true);
    const exports = try f.write("exports.uk", "# comment\napi\nrequired_but_undefined\napi\n", false);
    const output = try f.path("policy.lds");
    const force_keep = try f.path("force-keep.rsp");
    const args = [_][]const u8{
        tool,        "--nm",      nm,              "--output", output,     "--force-keep-output", force_keep,
        "--library", "first",     "--export-file", exports,    "--input",  "first.o",             "--input",
        "archive.a", "--library", "second",        "--input",  "second.o",
    };
    try f.expectRun(&args, 0);
    const expected_script =
        "/* Generated by lto-symbol-policy.py -- do not edit. */\n{\n  global:\n" ++
        "    api;\n    app;\n  local:\n    *;\n};\n";
    try std.testing.expectEqualStrings(expected_script, try f.read(output));
    try std.testing.expectEqualStrings("\"-Wl,-u,api\"\n\"-Wl,-u,required_but_undefined\"\n", try f.read(force_keep));
    const private_reference = try std.mem.concat(f.a, []const u8, &.{ &args, &.{ "--input", "private-reference.o" } });
    try f.expectRun(private_reference, 1);
    const private_conflict = try std.mem.concat(f.a, []const u8, &.{ &args, &.{ "--input", "private-provider.o" } });
    try f.expectRun(private_conflict, 1);
    try std.testing.expectEqualStrings(expected_script, try f.read(output));
    for ([_][]const u8{ "malformed.o", "failed.o" }) |input| {
        const failure = try std.mem.concat(f.a, []const u8, &.{ &args, &.{ "--input", input } });
        try f.expectRun(failure, 2);
    }
    try f.expectRun(&.{ tool, "--nm", try f.path("missing-nm"), "--output", output, "--library", "first", "--input", "first.o" }, 2);
    try f.expectRun(&.{ tool, "--nm", nm, "--output", output, "--library", "first", "--export-file", try f.path("missing-exports") }, 2);
    try f.expectRun(&.{ tool, "--nm", nm, "--output", output, "--input", "first.o" }, 3);
    try f.expectRun(&.{ tool, "--nm", nm, "--output", output, "--library" }, 3);
    try std.testing.expectEqualStrings(expected_script, try f.read(output));
    try f.expectRun(&.{ tool, "--nm", nm, "--output", output }, 0);
    try std.testing.expectEqualStrings(
        "/* Generated by lto-symbol-policy.py -- do not edit. */\n{\n  global:\n  local:\n    *;\n};\n",
        try f.read(output),
    );
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5) return error.InvalidArguments;
    const fixture: Fixture = .{ .a = init.arena.allocator(), .io = init.io, .root = args[4] };
    try metadataFixtures(fixture, args[1], args[2]);
    try policyFixtures(fixture, args[3]);
}
