const std = @import("std");
const facade_paths = @import("zig-facade-paths.zig");
const kconfig = @import("kconfig.zig");

pub const Inputs = struct {
    base: []const u8,
    application: ?[]const u8 = null,
    output: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
    config: ?[]const u8 = null,
    external_libraries: []const []const u8 = &.{},
    external_platforms: []const []const u8 = &.{},
    exclusions: []const []const u8 = &.{},
    image_name: ?[]const u8 = null,
};

pub const Context = struct {
    allocator: std.mem.Allocator,
    base: []const u8,
    application: []const u8,
    output: []const u8,
    output_exists: bool,
    prefix: []const u8,
    config: []const u8,
    external_libraries: []const []const u8,
    external_platforms: []const []const u8,
    exclusions: []const []const u8,
    image_name: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        inputs: Inputs,
        parsed_config: ?*const kconfig.Document,
    ) !Context {
        const base_lexical = try absolutePath(allocator, null, inputs.base);
        defer allocator.free(base_lexical);
        const base_result = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            base_lexical,
        );
        errdefer allocator.free(base_result.path);
        if (!base_result.exists) return error.BaseDoesNotExist;
        try requireDirectory(io, base_result.path);

        const application_lexical = try absolutePath(
            allocator,
            base_result.path,
            inputs.application orelse base_result.path,
        );
        defer allocator.free(application_lexical);
        const application_result = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            application_lexical,
        );
        errdefer allocator.free(application_result.path);
        if (!application_result.exists) return error.ApplicationDoesNotExist;
        try requireDirectory(io, application_result.path);

        const output_default = try std.fs.path.join(allocator, &.{ application_result.path, "build" });
        defer allocator.free(output_default);
        const output_lexical = try absolutePath(
            allocator,
            base_result.path,
            inputs.output orelse output_default,
        );
        defer allocator.free(output_lexical);
        const output_result = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            output_lexical,
        );
        errdefer allocator.free(output_result.path);

        const prefix_lexical = try absolutePath(
            allocator,
            base_result.path,
            inputs.prefix orelse output_result.path,
        );
        defer allocator.free(prefix_lexical);
        const prefix_result = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            prefix_lexical,
        );
        errdefer allocator.free(prefix_result.path);

        const config_default = try std.fs.path.join(allocator, &.{ application_result.path, ".config" });
        defer allocator.free(config_default);
        const config_lexical = try absolutePath(
            allocator,
            base_result.path,
            inputs.config orelse config_default,
        );
        defer allocator.free(config_lexical);
        const config_result = try facade_paths.canonicalizeNearestExisting(
            allocator,
            io,
            config_lexical,
        );
        errdefer allocator.free(config_result.path);

        const libraries = try canonicalRoots(allocator, io, base_result.path, inputs.external_libraries);
        errdefer freeRoots(allocator, libraries);
        const platforms = try canonicalRoots(allocator, io, base_result.path, inputs.external_platforms);
        errdefer freeRoots(allocator, platforms);
        const exclusions = try canonicalRoots(allocator, io, base_result.path, inputs.exclusions);
        errdefer freeRoots(allocator, exclusions);

        const configured_name = if (parsed_config) |config|
            try config.getString("UK_NAME")
        else
            null;
        const image_name = try allocator.dupe(
            u8,
            inputs.image_name orelse configured_name orelse std.fs.path.basename(application_result.path),
        );

        return .{
            .allocator = allocator,
            .base = base_result.path,
            .application = application_result.path,
            .output = output_result.path,
            .output_exists = output_result.exists,
            .prefix = prefix_result.path,
            .config = config_result.path,
            .external_libraries = libraries,
            .external_platforms = platforms,
            .exclusions = exclusions,
            .image_name = image_name,
        };
    }

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.base);
        self.allocator.free(self.application);
        self.allocator.free(self.output);
        self.allocator.free(self.prefix);
        self.allocator.free(self.config);
        freeRoots(self.allocator, self.external_libraries);
        freeRoots(self.allocator, self.external_platforms);
        freeRoots(self.allocator, self.exclusions);
        self.allocator.free(self.image_name);
        self.* = undefined;
    }

    pub fn headerPath(self: *const Context) ![]const u8 {
        return std.fs.path.join(self.allocator, &.{ self.prefix, "include", "uk", "bits", "config.h" });
    }
};

fn absolutePath(
    allocator: std.mem.Allocator,
    base: ?[]const u8,
    path: []const u8,
) ![]const u8 {
    if (std.fs.path.isAbsolute(path)) return std.fs.path.resolve(allocator, &.{path});
    const root = base orelse return error.BaseMustBeAbsolute;
    return std.fs.path.resolve(allocator, &.{ root, path });
}

fn requireDirectory(io: std.Io, path: []const u8) !void {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
    if (stat.kind != .directory) return error.NotDirectory;
}

fn canonicalRoots(
    allocator: std.mem.Allocator,
    io: std.Io,
    base: []const u8,
    roots: []const []const u8,
) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, roots.len);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |root| allocator.free(root);
        allocator.free(result);
    }
    for (roots, 0..) |root, index| {
        const lexical = try absolutePath(allocator, base, root);
        defer allocator.free(lexical);
        const canonical = try facade_paths.canonicalizeNearestExisting(allocator, io, lexical);
        if (!canonical.exists) {
            allocator.free(canonical.path);
            return error.RootDoesNotExist;
        }
        requireDirectory(io, canonical.path) catch |err| {
            allocator.free(canonical.path);
            return err;
        };
        result[index] = canonical.path;
        initialized += 1;
    }
    return result;
}

fn freeRoots(allocator: std.mem.Allocator, roots: []const []const u8) void {
    for (roots) |root| allocator.free(root);
    allocator.free(roots);
}

test "context uses canonical facade identities and config image name" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var parse_diagnostic: kconfig.Diagnostic = .{};
    var config = try kconfig.parse(allocator, "CONFIG_UK_NAME=\"fixture\"\n", &parse_diagnostic);
    defer config.deinit();

    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(cwd);
    var context = try Context.init(allocator, io, .{
        .base = cwd,
        .prefix = "native-prefix",
        .external_libraries = &.{cwd},
        .external_platforms = &.{cwd},
        .exclusions = &.{cwd},
    }, &config);
    defer context.deinit();
    try std.testing.expectEqualStrings(cwd, context.base);
    try std.testing.expectEqualStrings(cwd, context.application);
    try std.testing.expectEqualStrings("fixture", context.image_name);
    try std.testing.expect(facade_paths.isDescendant(context.application, context.output));
    try std.testing.expect(facade_paths.isDescendant(context.base, context.prefix));
    try std.testing.expectEqualStrings(cwd, context.external_libraries[0]);
    try std.testing.expectEqualStrings(cwd, context.external_platforms[0]);
    try std.testing.expectEqualStrings(cwd, context.exclusions[0]);
}
