const std = @import("std");
const elf = @import("producer_elf");
const options = @import("exclusion_options");
const schema = @import("fixture_build_schema.zig");
const t = std.testing;

test "actual default parent and production CLI contain no evidence section or symbol" {
    for ([_][]const u8{ options.default_parent, options.production_cli }) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(t.io, path, t.allocator, .limited(schema.max_parent_bytes));
        defer t.allocator.free(bytes);
        var image = try elf.Image.parse(t.allocator, bytes);
        defer image.deinit();
        try t.expectError(error.MissingSection, image.section(schema.section_name));
        for (image.symbols) |symbol|
            try t.expect(!std.mem.eql(u8, symbol.name, "uk_persistence_fixture_parent_build"));
        try absentMaterial(bytes);
    }
}

test "actual default production archive and generated options exclude evidence material" {
    for ([_][]const u8{ options.production_library, options.default_options }) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(t.io, path, t.allocator, .limited(schema.max_parent_bytes));
        defer t.allocator.free(bytes);
        try absentMaterial(bytes);
    }
}

fn absentMaterial(bytes: []const u8) !void {
    for ([_][]const u8{
        schema.section_name,
        "uk_persistence_fixture_parent_build",
        "fixture_parent_metadata.zig",
        "fixture_build_capture.zig",
        "fixture_build_evidence.zig",
        "pub const fixture_build_evidence",
        "hyperv_persistence_fixture_parent_build_v1",
    }) |marker| try t.expect(std.mem.indexOf(u8, bytes, marker) == null);
}
