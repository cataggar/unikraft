//! Uninstalled host helper. Paths in this argv protocol are private custody data.
const std = @import("std");
const schema = @import("fixture_build_schema.zig");
const evidence = @import("fixture_build_evidence.zig");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("persistence_fixture_build_refused: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    const parsed = try parse(allocator, args);
    switch (parsed.mode) {
        .baseline => try evidence.baseline(allocator, init.io, parsed.root, parsed.request.?, args[0]),
        .prepare => try evidence.prepare(allocator, init.io, parsed.root, parsed.request.?),
        .collect => try evidence.collect(allocator, init.io, parsed.root),
    }
}

pub const Parsed = struct {
    mode: enum { baseline, prepare, collect },
    root: []const u8,
    request: ?schema.Request,
};

pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Parsed {
    if (args.len < 3 or args.len > 18 + 3 * schema.max_modules) return error.InvalidArguments;
    var total: usize = 0;
    for (args) |arg| {
        if (arg.len > schema.max_metadata_bytes) return error.InvalidArguments;
        total += arg.len;
    }
    if (total > 256 * 1024) return error.InvalidArguments;
    const mode = std.meta.stringToEnum(@FieldType(Parsed, "mode"), args[1]) orelse return error.InvalidArguments;
    try absolute(args[0]);
    try absolute(args[2]);
    if (mode == .collect) {
        if (args.len != 3) return error.InvalidArguments;
        const retained = try std.fs.path.join(allocator, &.{ args[2], "collector" });
        defer allocator.free(retained);
        if (!std.mem.eql(u8, args[0], retained)) return error.InvalidArguments;
        return .{ .mode = mode, .root = args[2], .request = null };
    }
    if (args.len < 18 or (args.len - 18) % 3 != 0) return error.InvalidArguments;
    try schema.validateIdentity(args[3]);
    try schema.validateIdentity(args[4]);
    if (args[5].len == 0 or args[5].len > schema.max_metadata_bytes) return error.InvalidArguments;
    const configured = try std.json.parseFromSlice(std.json.Value, allocator, args[5], .{});
    defer configured.deinit();
    if (configured.value != .object) return error.InvalidArguments;
    if (mode == .baseline) {
        if (args[6].len != 0) return error.InvalidArguments;
    } else try absolute(args[6]);
    for (args[7..18]) |path| try absolute(path);
    const modules = try allocator.alloc(schema.Module, (args.len - 18) / 3);
    errdefer allocator.free(modules);
    for (modules, 0..) |*module, index| {
        const offset = 18 + index * 3;
        try schema.validateModuleName(args[offset]);
        if (index != 0 and std.mem.order(u8, modules[index - 1].name, args[offset]) != .lt)
            return error.InvalidArguments;
        try absolute(args[offset + 1]);
        try absolute(args[offset + 2]);
        module.* = .{ .name = args[offset], .root = args[offset + 1], .scope = args[offset + 2] };
    }
    if (modules.len == 0) return error.InvalidArguments;
    return .{
        .mode = mode,
        .root = args[2],
        .request = .{
            .source_commit = args[3],
            .source_tree = args[4],
            .configured_json = args[5],
            .parent = args[6],
            .raw_worker = args[7],
            .selected_worker = args[8],
            .compiler = args[9],
            .compiler_lib = args[10],
            .main_options = args[11],
            .main_source = args[12],
            .repository_hyperv = args[13],
            .repository_build = args[14],
            .worker_proof = args[15],
            .fixture_log = args[16],
            .invocation_exit = args[17],
            .modules = modules,
        },
    };
}

fn absolute(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path) or path.len < 2 or path.len > 4096 or
        std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidArguments;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return error.InvalidArguments;
    }
}
