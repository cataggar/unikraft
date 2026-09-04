const builtin = @import("builtin");
const std = @import("std");

const supported_zig = std.SemanticVersion{ .major = 0, .minor = 16, .patch = 0 };

comptime {
    if (builtin.zig_version.order(supported_zig) != .eq) {
        @compileError("the Unikraft build facade requires Zig 0.16.0");
    }
}

const Verbosity = enum {
    @"0",
    @"1",
    @"2",
};

const PartialLinkerType = enum {
    driver,
    raw,
};

const MakeOptions = struct {
    command: []const u8,
    app: []const u8,
    output: ?[]const u8,
    config: ?[]const u8,
    image_name: ?[]const u8,
    external_libraries: ?[]const u8,
    external_platforms: ?[]const u8,
    exclusions: ?[]const u8,
    verbosity: ?Verbosity,
    cross_compile: ?[]const u8,
    compiler: ?[]const u8,
    linker: ?[]const u8,
    partial_linker: ?[]const u8,
    partial_linker_type: ?PartialLinkerType,
    compiler_targeted: ?bool,
    host_cc: ?[]const u8,
    host_cxx: ?[]const u8,
    host_cflags: ?[]const u8,
    forwarded: []const []const u8,
};

const Target = struct {
    name: []const u8,
    make_target: []const u8,
    description: []const u8,
};

const targets = [_]Target{
    .{ .name = "all", .make_target = "all", .description = "Build everything (GNU Make backend)" },
    .{ .name = "images", .make_target = "images", .description = "Build kernel images" },
    .{ .name = "libs", .make_target = "libs", .description = "Build libraries and their objects" },
    .{ .name = "objs", .make_target = "objs", .description = "Build objects only" },
    .{ .name = "preprocess", .make_target = "preprocess", .description = "Run preprocessing steps" },
    .{ .name = "prepare", .make_target = "prepare", .description = "Run preparation steps" },
    .{ .name = "fetch", .make_target = "fetch", .description = "Fetch, extract, and patch remote code" },
    .{ .name = "menuconfig", .make_target = "menuconfig", .description = "Open the interactive configuration menu" },
    .{ .name = "defconfig", .make_target = "defconfig", .description = "Create a configuration using defaults" },
    .{ .name = "oldconfig", .make_target = "oldconfig", .description = "Resolve new configuration symbols interactively" },
    .{ .name = "olddefconfig", .make_target = "olddefconfig", .description = "Resolve new configuration symbols using defaults" },
    .{ .name = "syncconfig", .make_target = "syncconfig", .description = "Synchronize configuration and dependencies" },
    .{ .name = "savedefconfig", .make_target = "savedefconfig", .description = "Save a minimal default configuration" },
    .{ .name = "clean", .make_target = "clean", .description = "Remove configured build products" },
    .{ .name = "properclean", .make_target = "properclean", .description = "Remove the build output directory" },
    .{ .name = "distclean", .make_target = "distclean", .description = "Remove build output and configuration" },
};

pub fn build(b: *std.Build) void {
    const root = b.pathFromRoot(".");
    const options = MakeOptions{
        .command = b.option([]const u8, "make-command", "GNU Make executable (default: make)") orelse "make",
        .app = resolvePath(b.allocator, root, b.option([]const u8, "app", "Application directory (Make A=)") orelse root),
        .output = resolveOptionalPath(b, root, "output", "Build output directory (Make O=)"),
        .config = resolveOptionalPath(b, root, "config", "Configuration file (Make C=)"),
        .image_name = b.option([]const u8, "image-name", "Image/application name override (Make N=)"),
        .external_libraries = resolvePathList(
            b.allocator,
            root,
            b.option([]const []const u8, "external-lib", "External library path; may be repeated (Make L=)"),
        ),
        .external_platforms = resolvePathList(
            b.allocator,
            root,
            b.option([]const []const u8, "external-platform", "External platform path; may be repeated (Make P=)"),
        ),
        .exclusions = resolvePathList(
            b.allocator,
            root,
            b.option([]const []const u8, "exclude", "Excluded component path; may be repeated (Make E=)"),
        ),
        .verbosity = b.option(Verbosity, "verbose", "Make verbosity: 0, 1, or 2 (Make V=)"),
        .cross_compile = b.option([]const u8, "cross-compile", "Cross-toolchain prefix (Make CROSS_COMPILE=)"),
        .compiler = b.option([]const u8, "compiler", "C compiler command (Make COMPILER=)"),
        .linker = b.option([]const u8, "linker", "Final linker driver command (Make LINKER=)"),
        .partial_linker = b.option([]const u8, "partial-linker", "Relocatable linker command (Make PARTIAL_LINKER=)"),
        .partial_linker_type = b.option(PartialLinkerType, "partial-linker-type", "Relocatable linker interface: driver or raw"),
        .compiler_targeted = b.option(bool, "compiler-targeted", "Compiler command already selects its target"),
        .host_cc = b.option([]const u8, "host-cc", "Host C compiler command (Make HOSTCC=)"),
        .host_cxx = b.option([]const u8, "host-cxx", "Host C++ compiler command (Make HOSTCXX=)"),
        .host_cflags = b.option([]const u8, "host-cflags", "Host compiler flags (Make HOSTCFLAGS=)"),
        .forwarded = b.option([]const []const u8, "make-arg", "Additional NAME=VALUE Make assignment; may be repeated") orelse &.{},
    };

    var invalid_assignment: ?[]const u8 = null;
    for (options.forwarded) |assignment| {
        validateForwardedAssignment(assignment) catch {
            invalid_assignment = assignment;
            break;
        };
    }

    if (invalid_assignment) |assignment| {
        const fail = b.addFail(b.fmt(
            "invalid -Dmake-arg '{s}': expected an unreserved NAME=VALUE assignment",
            .{assignment},
        ));
        for (targets) |target| {
            const step = b.step(target.name, target.description);
            step.dependOn(&fail.step);
            if (std.mem.eql(u8, target.name, "all")) {
                b.default_step = step;
            }
        }
        return;
    }

    for (targets) |target| {
        const run = addMakeCommand(b, root, target.make_target, options);
        const step = b.step(target.name, target.description);
        step.dependOn(&run.step);
        if (std.mem.eql(u8, target.name, "all")) {
            b.default_step = step;
        }
    }

    const facade_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("build.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_facade_tests = b.addRunArtifact(facade_tests);
    const test_step = b.step("test", "Test facade path and Make argument construction");
    test_step.dependOn(&run_facade_tests.step);
}

fn resolveOptionalPath(
    b: *std.Build,
    root: []const u8,
    name: []const u8,
    description: []const u8,
) ?[]const u8 {
    const value = b.option([]const u8, name, description) orelse return null;
    return resolvePath(b.allocator, root, value);
}

fn resolvePath(allocator: std.mem.Allocator, root: []const u8, path: []const u8) []const u8 {
    return std.fs.path.resolve(allocator, &.{ root, path }) catch @panic("out of memory");
}

fn resolvePathList(
    allocator: std.mem.Allocator,
    root: []const u8,
    paths: ?[]const []const u8,
) ?[]const u8 {
    const values = paths orelse return null;
    if (values.len == 0) return null;

    var resolved = std.array_list.Managed([]const u8).init(allocator);
    defer resolved.deinit();
    defer for (resolved.items) |path| allocator.free(path);
    for (values) |path| {
        resolved.append(resolvePath(allocator, root, path)) catch @panic("out of memory");
    }
    return std.mem.join(allocator, ":", resolved.items) catch @panic("out of memory");
}

fn addMakeCommand(
    b: *std.Build,
    root: []const u8,
    target: []const u8,
    options: MakeOptions,
) *std.Build.Step.Run {
    const argv = makeArguments(b.allocator, target, options);
    const run = b.addSystemCommand(argv);
    run.setCwd(.{ .cwd_relative = root });
    return run;
}

fn makeArguments(
    allocator: std.mem.Allocator,
    target: []const u8,
    options: MakeOptions,
) []const []const u8 {
    var argv = std.array_list.Managed([]const u8).init(allocator);
    argv.append(options.command) catch @panic("out of memory");
    argv.append("--no-print-directory") catch @panic("out of memory");
    argv.append(target) catch @panic("out of memory");

    appendAssignment(allocator, &argv, "A", options.app);
    appendOptionalAssignment(allocator, &argv, "O", options.output);
    appendOptionalAssignment(allocator, &argv, "C", options.config);
    appendOptionalAssignment(allocator, &argv, "N", options.image_name);
    appendOptionalAssignment(allocator, &argv, "L", options.external_libraries);
    appendOptionalAssignment(allocator, &argv, "P", options.external_platforms);
    appendOptionalAssignment(allocator, &argv, "E", options.exclusions);

    if (options.verbosity) |value| {
        appendAssignment(allocator, &argv, "V", @tagName(value));
    }
    appendOptionalAssignment(allocator, &argv, "CROSS_COMPILE", options.cross_compile);
    appendOptionalAssignment(allocator, &argv, "COMPILER", options.compiler);
    appendOptionalAssignment(allocator, &argv, "LINKER", options.linker);
    appendOptionalAssignment(allocator, &argv, "PARTIAL_LINKER", options.partial_linker);
    if (options.partial_linker_type) |value| {
        appendAssignment(allocator, &argv, "PARTIAL_LINKER_TYPE", @tagName(value));
    }
    if (options.compiler_targeted) |value| {
        appendAssignment(allocator, &argv, "COMPILER_TARGETED", if (value) "y" else "n");
    }
    appendOptionalAssignment(allocator, &argv, "HOSTCC", options.host_cc);
    appendOptionalAssignment(allocator, &argv, "HOSTCXX", options.host_cxx);
    appendOptionalAssignment(allocator, &argv, "HOSTCFLAGS", options.host_cflags);

    for (options.forwarded) |assignment| {
        argv.append(assignment) catch @panic("out of memory");
    }
    return argv.toOwnedSlice() catch @panic("out of memory");
}

fn appendOptionalAssignment(
    allocator: std.mem.Allocator,
    argv: *std.array_list.Managed([]const u8),
    name: []const u8,
    value: ?[]const u8,
) void {
    appendAssignment(allocator, argv, name, value orelse return);
}

fn appendAssignment(
    allocator: std.mem.Allocator,
    argv: *std.array_list.Managed([]const u8),
    name: []const u8,
    value: []const u8,
) void {
    argv.append(std.fmt.allocPrint(allocator, "{s}={s}", .{ name, value }) catch @panic("out of memory")) catch
        @panic("out of memory");
}

fn validateForwardedAssignment(assignment: []const u8) error{InvalidAssignment}!void {
    const separator = std.mem.indexOfScalar(u8, assignment, '=') orelse return error.InvalidAssignment;
    const name = assignment[0..separator];
    if (name.len == 0 or !isMakeNameStart(name[0])) return error.InvalidAssignment;
    for (name[1..]) |character| {
        if (!isMakeNameContinue(character)) return error.InvalidAssignment;
    }
    if (isReservedAssignment(name)) return error.InvalidAssignment;
}

fn isMakeNameStart(character: u8) bool {
    return std.ascii.isAlphabetic(character) or character == '_';
}

fn isMakeNameContinue(character: u8) bool {
    return isMakeNameStart(character) or std.ascii.isDigit(character);
}

fn isReservedAssignment(name: []const u8) bool {
    const reserved = [_][]const u8{
        "A",
        "O",
        "C",
        "N",
        "L",
        "P",
        "E",
        "V",
        "CROSS_COMPILE",
        "COMPILER",
        "LINKER",
        "PARTIAL_LINKER",
        "PARTIAL_LINKER_TYPE",
        "COMPILER_TARGETED",
        "HOSTCC",
        "HOSTCXX",
        "HOSTCFLAGS",
    };
    for (reserved) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
}

test "Make arguments preserve spaces as single arguments" {
    const options = MakeOptions{
        .command = "gmake",
        .app = "/workspace/app with spaces",
        .output = "/workspace/output with spaces",
        .config = "/workspace/configs/test config",
        .image_name = "hello",
        .external_libraries = "/workspace/lib one:/workspace/lib two",
        .external_platforms = null,
        .exclusions = null,
        .verbosity = .@"2",
        .cross_compile = null,
        .compiler = "zig cc -target x86_64-freestanding-none",
        .linker = null,
        .partial_linker = "zig ld.lld",
        .partial_linker_type = .raw,
        .compiler_targeted = true,
        .host_cc = "zig cc",
        .host_cxx = "zig c++",
        .host_cflags = "-fno-sanitize=null",
        .forwarded = &.{"AR=zig ar"},
    };
    const actual = makeArguments(std.testing.allocator, "images", options);
    defer {
        for (actual[3 .. actual.len - 1]) |argument| std.testing.allocator.free(argument);
        std.testing.allocator.free(actual);
    }

    const expected = [_][]const u8{
        "gmake",
        "--no-print-directory",
        "images",
        "A=/workspace/app with spaces",
        "O=/workspace/output with spaces",
        "C=/workspace/configs/test config",
        "N=hello",
        "L=/workspace/lib one:/workspace/lib two",
        "V=2",
        "COMPILER=zig cc -target x86_64-freestanding-none",
        "PARTIAL_LINKER=zig ld.lld",
        "PARTIAL_LINKER_TYPE=raw",
        "COMPILER_TARGETED=y",
        "HOSTCC=zig cc",
        "HOSTCXX=zig c++",
        "HOSTCFLAGS=-fno-sanitize=null",
        "AR=zig ar",
    };
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |expected_argument, actual_argument| {
        try std.testing.expectEqualStrings(expected_argument, actual_argument);
    }
}

test "path lists resolve from the repository root" {
    const actual = resolvePathList(
        std.testing.allocator,
        "/workspace/unikraft",
        &.{ "libs/lib one", "/opt/platform" },
    ).?;
    defer std.testing.allocator.free(actual);

    try std.testing.expectEqualStrings(
        "/workspace/unikraft/libs/lib one:/opt/platform",
        actual,
    );
}

test "forwarded Make assignments require safe unreserved names" {
    try validateForwardedAssignment("AR=zig ar");
    try validateForwardedAssignment("UK_CFLAGS=-std=gnu17");
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("not-an-assignment"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("-j=8"));
    try std.testing.expectError(error.InvalidAssignment, validateForwardedAssignment("A=../app"));
}
