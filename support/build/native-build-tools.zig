// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");

pub fn metadataTool(b: *std.Build, root: std.Build.LazyPath) *std.Build.Step.Compile {
    const tool = b.addExecutable(.{
        .name = "unikraft-native-config-metadata",
        .root_module = b.createModule(.{
            .root_source_file = root.path(b, "support/build/native-config-metadata.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
        }),
    });
    const flags = c_flags ++ [_][]const u8{"-DUK_KCONFIG_METADATA=1"};
    addKconfigSources(b, root, tool.root_module, flags);
    tool.root_module.addCSourceFile(.{
        .file = root.path(b, "support/build/native-kconfig-bridge.c"),
        .flags = flags,
    });
    return tool;
}

pub fn legacyConfigFixture(b: *std.Build, root: std.Build.LazyPath) *std.Build.Step.Compile {
    const tool = b.addExecutable(.{
        .name = "unikraft-legacy-kconfig-fixture",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
        }),
    });
    addKconfigSources(b, root, tool.root_module, c_flags);
    tool.root_module.addCSourceFile(.{
        .file = root.path(b, "support/kconfig/conf.c"),
        .flags = c_flags,
    });
    return tool;
}

// The unchanged Kconfig list.h uses null-derived offsetof and a synthetic
// container around its list sentinel. Exempt those two C checks only;
// retain all parser assertions, other C checks, and Zig safety.
const c_flags: []const []const u8 = &.{"-fno-sanitize=null,object-size"};

fn addKconfigSources(
    b: *std.Build,
    root: std.Build.LazyPath,
    module: *std.Build.Module,
    flags: []const []const u8,
) void {
    const parser = b.addSystemCommand(&.{ "bison", "--debug", "--defines" });
    parser.addArg("-o");
    const parser_c = parser.addOutputFileArg("parser.tab.c");
    parser.addFileArg(root.path(b, "support/kconfig/parser.y"));
    const lexer = b.addSystemCommand(&.{"flex"});
    lexer.addArg("-o");
    const lexer_c = lexer.addOutputFileArg("lexer.lex.c");
    lexer.addFileArg(root.path(b, "support/kconfig/lexer.l"));
    module.addIncludePath(root.path(b, "support/kconfig"));
    module.addIncludePath(parser_c.dirname());
    module.addCSourceFile(.{ .file = parser_c, .flags = flags });
    module.addCSourceFile(.{ .file = lexer_c, .flags = flags });
    module.addCSourceFiles(.{
        .root = root,
        .flags = flags,
        .files = &.{
            "support/kconfig/confdata.c",
            "support/kconfig/expr.c",
            "support/kconfig/preprocess.c",
            "support/kconfig/symbol.c",
        },
    });
}
