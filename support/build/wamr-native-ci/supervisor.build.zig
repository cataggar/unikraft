// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const native_owner = b.option(bool, "native-source-owner", "Use the compiled native standalone source owner, not a historical identity") orelse false;
    const source_closure = b.option(
        []const u8,
        "source-closure-sha256",
        "Exact supervised source content closure",
    );
    if (native_owner and source_closure != null)
        @panic("native-source-owner cannot accept a substituted source-closure-sha256");
    if (!native_owner and source_closure == null)
        @panic("source-closure-sha256 is required");
    const historical_closure = source_closure orelse "";
    if (!native_owner and historical_closure.len != 64)
        @panic("source-closure-sha256 must be lowercase SHA-256");
    for (historical_closure) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            @panic("source-closure-sha256 must be lowercase SHA-256");
    }
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "source_closure_sha256", historical_closure);
    build_options.addOption(bool, "native_source_owner", native_owner);
    const core = b.createModule(.{
        .root_source_file = b.path("../../tools/hyperv/core.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.cpu.arch == .x86_64)
        core.addAssemblyFile(b.path("../../tools/hyperv/sha256_clear_upper.S"));
    const source = sourceClosureModule(b, target, optimize);
    const supervisor = b.addExecutable(.{
        .name = "wamr-ci-supervisor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("supervisor.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "build_options", .module = build_options.createModule() },
                .{ .name = "hyperv_core", .module = core },
                .{ .name = "supervisor_source_closure", .module = source },
            },
        }),
    });
    b.installArtifact(supervisor);
}

fn sourceClosureModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
) *std.Build.Module {
    const source_file = b.path("../../controller_source_closure.zig");
    b.dependOnFileContents(source_file);
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        b.graph.io,
        b.root.joinString(b.allocator, "../../controller_source_closure.zig") catch @panic("OOM"),
        b.allocator,
        .limited(1024 * 1024),
    ) catch |err| std.debug.panic("read controller source closure: {s}", .{@errorName(err)});
    const text = b.allocator.dupeSentinel(u8, bytes, 0) catch @panic("OOM");
    const module = b.createModule(.{
        .root_source_file = source_file,
        .target = target,
        .optimize = optimize,
    });
    var tokenizer = std.zig.Tokenizer.init(text);
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid)
            @panic("invalid controller source inventory");
        if (token.tag != .builtin or
            !std.mem.eql(u8, text[token.loc.start..token.loc.end], "@embedFile"))
            continue;
        if (tokenizer.next().tag != .l_paren)
            @panic("invalid controller source embed");
        const literal = tokenizer.next();
        if (literal.tag != .string_literal or tokenizer.next().tag != .r_paren)
            @panic("controller source embeds must name literal files");
        const name = std.zig.string_literal.parseAlloc(b.allocator, text[literal.loc.start..literal.loc.end]) catch
            @panic("invalid controller source embed name");
        if (module.import_table.contains(name))
            continue;
        module.addImport(name, b.createModule(.{
            .root_source_file = b.path(b.fmt("../../{s}", .{name})),
            .target = target,
            .optimize = optimize,
        }));
    }
    return module;
}
