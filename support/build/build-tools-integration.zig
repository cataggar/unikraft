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
        try self.expectDiagnostic(argv, expected, "");
    }

    fn expectDiagnostic(self: Fixture, argv: []const []const u8, expected: u8, diagnostic: []const u8) !void {
        const result = try std.process.run(self.a, self.io, .{ .argv = argv });
        if (result.term != .exited or result.term.exited != expected) {
            std.debug.print("fixture expected exit {d}: {s}\nstdout: {s}\nstderr: {s}\n", .{
                expected, argv[0], result.stdout, result.stderr,
            });
            return error.UnexpectedExitStatus;
        }
        if (std.mem.indexOf(u8, result.stderr, diagnostic) == null) {
            std.debug.print("fixture expected diagnostic '{s}', got:\n{s}\n", .{ diagnostic, result.stderr });
            return error.MissingDiagnostic;
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
    // Model and version failures must not be masked by the missing platform.
    const model_argv = argv[0 .. argv.len - 2];
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nprintf 'one\\ntwo\\n'\n", true);
    try f.expectDiagnostic(model_argv, 2, "MultilineVersionSuffix");
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nexit 7\n", true);
    try f.expectDiagnostic(model_argv, 2, "VersionHelperFailed");
    _ = try f.write("base/support/scripts/gitsha1", "#!/bin/sh\nprintf '%s\\n' '~fixture'\n", true);
    _ = try f.write("base/Config.uk", "invalid kconfig syntax\n", false);
    try f.expectDiagnostic(model_argv, 2, "unknown statement");
    _ = try f.write("base/Config.uk", "# Empty model is a valid control.\n", false);
    try f.expectRun(model_argv, 0);
    const empty_model = "unikraft-native-config-metadata-v1\n";
    try std.testing.expectEqualStrings(empty_model, try f.read(metadata_path));
    var fresh_argv = argv;
    fresh_argv[10] = try f.path("missing-source-new.tsv");
    for ([_][]const u8{ "missing-Kconfig-source", "missing-Kconfig-*.uk" }) |source| {
        _ = try f.write("base/Config.uk", try std.fmt.allocPrint(f.a, "source \"{s}\"\n", .{source}), false);
        const diagnostic = try std.fmt.allocPrint(f.a, "metadata source \"{s}\": no matching files", .{source});
        try f.expectDiagnostic(model_argv, 2, diagnostic);
        try std.testing.expectEqualStrings(empty_model, try f.read(metadata_path));
        try f.expectDiagnostic(fresh_argv[0 .. fresh_argv.len - 2], 2, diagnostic);
        try std.testing.expectError(error.FileNotFound, f.read(fresh_argv[10]));
    }
    _ = try f.write("base/parts/a.uk", "config PART_A\n bool\n", false);
    _ = try f.write("base/parts/b.uk", "config PART_B\n int\n", false);
    _ = try f.write("base/Config.uk", "source \"parts/*.uk\"\n", false);
    try f.expectRun(model_argv, 0);
    try std.testing.expectEqualStrings(
        "unikraft-native-config-metadata-v1\nsymbol\tPART_A\tbool\nsymbol\tPART_B\tint\n",
        try f.read(metadata_path),
    );
    try std.testing.expectEqualStrings(original_config, try f.read(config));
}

fn longRootPaths(f: Fixture, tool: []const u8, config_tool: []const u8, repository: []const u8) !void {
    var output = try f.path("long-root-output");
    for (0..8) |_| {
        output = try std.fs.path.join(f.a, &.{ output, "nested-metadata-output-0123456789" });
    }
    const submenu = try std.fs.path.join(f.a, &.{ output, "native-config", "kconfig", "plats.uk" });
    try std.testing.expect(submenu.len > 255);
    const config = try std.fs.path.join(f.a, &.{ repository, "support/build/tests/native-config/x86_64-acme.config" });
    const platform = try std.fs.path.join(f.a, &.{ repository, "support/build/tests/native-config/external-platform/provider" });
    const metadata_path = try std.fs.path.join(f.a, &.{ output, "metadata.tsv" });
    try f.expectRun(&.{
        tool,         "--base",      repository,            "--app",  repository, "--output", output, "--config", config,
        "--metadata", metadata_path, "--external-platform", platform,
    }, 0);
    const submenu_contents = try f.read(submenu);
    try std.testing.expect(std.mem.indexOf(u8, submenu_contents, platform) != null);
    var metadata = try kconfig.Metadata.parse(f.a, try f.read(metadata_path));
    try std.testing.expectEqual(kconfig.SymbolType.boolean, metadata.typeOf("PLAT_ACME").?);
    var found = false;
    for (metadata.platforms.items) |registration| {
        if (std.mem.eql(u8, registration.name, "acme")) found = true;
    }
    try std.testing.expect(found);
    try f.expectRun(&.{ config_tool, "validate", config, metadata_path }, 0);
}

fn shellBoundaries(f: Fixture, tool: []const u8) !void {
    const base = try f.path("shell-base");
    _ = try f.write("shell-base/version.mk", "UK_VERSION=1\nUK_SUBVERSION=2\n", false);
    _ = try f.write("shell-base/support/scripts/gitsha1", "#!/bin/sh\nexit 0\n", true);
    _ = try f.write("shell-base/emit-output", "#!/bin/sh\nhead -c \"$1\" /dev/zero | tr '\\000' x\n", true);
    const config = try f.write("shell.config", "# No solved values are changed.\n", false);
    const metadata_path = try f.path("shell-output/metadata.tsv");
    const argv = [_][]const u8{
        tool,       "--base", base,         "--app",       base, "--output", try f.path("shell-output"),
        "--config", config,   "--metadata", metadata_path,
    };
    const limit = 1024 * 1024;
    for ([_]usize{ 256, limit }) |size| {
        _ = try f.write("shell-base/Config.uk", try std.fmt.allocPrint(f.a, "config SHELL_VALUE\n string\n default \"$(shell,$(UK_BASE)/emit-output {d})\"\n", .{size}), false);
        try f.expectRun(&argv, 0);
        try std.testing.expectEqualStrings(
            "unikraft-native-config-metadata-v1\nsymbol\tSHELL_VALUE\tstring\n",
            try f.read(metadata_path),
        );
    }
    const original_metadata = try f.read(metadata_path);
    _ = try f.write("shell-base/Config.uk", try std.fmt.allocPrint(f.a, "config SHELL_VALUE\n string\n default \"$(shell,$(UK_BASE)/emit-output {d})\"\n", .{limit + 1}), false);
    try f.expectDiagnostic(&argv, 2, "metadata shell output exceeds 1048576-byte limit");
    try std.testing.expectEqualStrings(original_metadata, try f.read(metadata_path));
    _ = try f.write("shell-base/Config.uk", "config SHELL_VALUE\n string\n default \"$(shell,printf '\\000')\"\n", false);
    try f.expectDiagnostic(&argv, 2, "metadata shell output contains a NUL byte");
    try std.testing.expectEqualStrings(original_metadata, try f.read(metadata_path));
    _ = try f.write("shell-base/Config.uk", "source \"$(shell,printf 'line\\nbreak\\n\\n')\"\n", false);
    _ = try f.write("shell-base/line break", "config NEWLINE_SOURCE\n bool\n", false);
    try f.expectRun(&argv, 0);
    try std.testing.expectEqualStrings(
        "unikraft-native-config-metadata-v1\nsymbol\tNEWLINE_SOURCE\tbool\n",
        try f.read(metadata_path),
    );
}

fn legacySolver(f: Fixture, tool: []const u8) !void {
    const source = try f.write("legacy/Config.uk", "source \"missing-Kconfig-source\"\nconfig LEGACY_VALUE\n string\n default \"$(shell,printf '%0300d' 0)\"\n", false);
    const output = try f.path("legacy/solved.config");
    var environment = std.process.Environ.Map.init(f.a);
    defer environment.deinit();
    try environment.put("CONFIG_", "CONFIG_");
    try environment.put("KCONFIG_CONFIG", output);
    try environment.put("KCONFIG_AUTOCONFIG", try f.path("legacy/auto.conf"));
    try environment.put("KCONFIG_AUTOHEADER", try f.path("legacy/autoconf.h"));
    try environment.put("KCONFIG_TRISTATE", try f.path("legacy/tristate.conf"));
    const result = try std.process.run(f.a, f.io, .{
        .argv = &.{ tool, "--olddefconfig", source },
        .cwd = .{ .path = try f.path("legacy") },
        .environ_map = &environment,
    });
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("legacy solver fixture failed:\n{s}\n{s}\n", .{ result.stdout, result.stderr });
        return error.UnexpectedExitStatus;
    }
    const solved = try f.read(output);
    const expected = try std.mem.concat(f.a, u8, &.{ "CONFIG_LEGACY_VALUE=\"", "0" ** 255, "\"\n" });
    try std.testing.expect(std.mem.indexOf(u8, solved, expected) != null);
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
    if (args.len != 7) return error.InvalidArguments;
    const fixture: Fixture = .{ .a = init.arena.allocator(), .io = init.io, .root = args[4] };
    try metadataFixtures(fixture, args[1], args[2]);
    try longRootPaths(fixture, args[1], args[2], args[5]);
    try shellBoundaries(fixture, args[1]);
    const legacy_tool = try std.Io.Dir.cwd().realPathFileAlloc(init.io, args[6], init.arena.allocator());
    try legacySolver(fixture, legacy_tool);
    try policyFixtures(fixture, args[3]);
}
