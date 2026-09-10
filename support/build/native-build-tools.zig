// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");

pub fn metadataTool(b: *std.Build, root: std.Build.LazyPath) *std.Build.Step.Compile {
    const parser = b.addSystemCommand(&.{ "bison", "--debug", "--defines" });
    parser.addArg("-o");
    const parser_c = parser.addOutputFileArg("parser.tab.c");
    parser.addFileArg(root.path(b, "support/kconfig/parser.y"));
    const lexer = b.addSystemCommand(&.{"flex"});
    lexer.addArg("-o");
    const lexer_c = lexer.addOutputFileArg("lexer.lex.c");
    lexer.addFileArg(root.path(b, "support/kconfig/lexer.l"));
    const tool = b.addExecutable(.{
        .name = "unikraft-native-config-metadata",
        .root_module = b.createModule(.{
            .root_source_file = root.path(b, "support/build/native-config-metadata.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
        }),
    });
    tool.root_module.addIncludePath(root.path(b, "support/kconfig"));
    tool.root_module.addIncludePath(parser_c.dirname());
    // The unchanged Kconfig list.h uses null-derived offsetof and a synthetic
    // container around its list sentinel. Exempt those two C checks only;
    // retain all parser assertions, other C checks, and Zig safety.
    const c_flags = &.{"-fno-sanitize=null,object-size"};
    tool.root_module.addCSourceFile(.{ .file = parser_c, .flags = c_flags });
    tool.root_module.addCSourceFile(.{ .file = lexer_c, .flags = c_flags });
    tool.root_module.addCSourceFiles(.{
        .root = root,
        .flags = c_flags,
        .files = &.{
            "support/build/native-kconfig-bridge.c",
            "support/kconfig/confdata.c",
            "support/kconfig/expr.c",
            "support/kconfig/preprocess.c",
            "support/kconfig/symbol.c",
        },
    });
    return tool;
}
