const std = @import("std");
const builtin = @import("builtin");
const metadata = @import("fixture_parent_metadata.zig");
const schema = @import("fixture_build_schema.zig");
const t = std.testing;

test "static serialization is bounded JSON with explicit compilation origin" {
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, &metadata.payload, .{});
    defer parsed.deinit();
    const value = parsed.value;
    try t.expect(metadata.payload.len > 0 and metadata.payload.len <= schema.max_metadata_bytes);
    try t.expectEqualStrings("hyperv_persistence_fixture_parent_build_v1", value.object.get("schema").?.string);
    try t.expectEqualStrings("persistence_main_test_parent", value.object.get("role").?.string);
    try t.expectEqualStrings("actual_tests_zig_compile_builtin", value.object.get("origin").?.string);
    try t.expectEqualStrings(@tagName(builtin.mode), value.object.get("observed").?.object.get("mode").?.string);
    try t.expectEqual(builtin.is_test, value.object.get("observed").?.object.get("is_test").?.bool);
    try noPaths(value);
}

test "native transport is a single aligned ELF note wrapping the unchanged JSON payload" {
    const transport = std.mem.asBytes(&metadata.transport);
    const header = metadata.transport.header;
    try t.expectEqual(schema.note_name.len, header.n_namesz);
    try t.expectEqual(metadata.payload.len, header.n_descsz);
    try t.expectEqual(schema.note_type, header.n_type);
    try t.expectEqualStrings(schema.note_name, &metadata.transport.name);
    try t.expectEqualSlices(u8, &metadata.payload, metadata.transport.description[0..header.n_descsz]);
    try t.expectEqual(@as(usize, 0), transport.len % schema.note_alignment);
    try t.expectEqual(schema.note_prefix_bytes + metadata.transport.description.len, transport.len);
    try t.expect(transport.len <= schema.max_note_bytes);
    for (metadata.transport.description[header.n_descsz..]) |byte| try t.expectEqual(@as(u8, 0), byte);
    const source = @embedFile("fixture_parent_metadata.zig");
    try t.expect(std.mem.indexOf(u8, source, "linksection(schema.section_name)") != null);
    try t.expect(std.mem.indexOf(u8, source, ".section =") == null);
}

test "CPU serialization preserves model baseline and every resolved feature and bit" {
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, &metadata.payload, .{});
    defer parsed.deinit();
    const target = parsed.value.object.get("observed").?.object.get("target").?;
    const cpu = target.object.get("cpu").?;
    const model = cpu.object.get("model").?;
    try t.expectEqualStrings(@tagName(builtin.target.cpu.arch), cpu.object.get("arch").?.string);
    try t.expectEqualStrings(builtin.target.cpu.model.name, model.object.get("name").?.string);
    if (builtin.target.cpu.model.llvm_name) |name| {
        try t.expectEqualStrings(name, model.object.get("llvm_name").?.string);
    } else try t.expect(model.object.get("llvm_name").? == .null);
    try features(cpu.object.get("features").?, builtin.target.cpu.features);
    try features(model.object.get("baseline_features").?, builtin.target.cpu.model.features);
    try t.expectEqualStrings(@tagName(builtin.target.os.tag), target.object.get("os").?.object.get("tag").?.string);
    try t.expectEqualStrings(@tagName(builtin.target.os.tag.versionRangeTag()), target.object.get("os").?.object.get("version_range_kind").?.string);
    try t.expectEqualStrings(@tagName(builtin.target.abi), target.object.get("abi").?.string);
    try t.expectEqualStrings(@tagName(builtin.target.ofmt), target.object.get("ofmt").?.string);
}

test "compiler unavailable declarations are disclosed rather than converted to false" {
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, &metadata.payload, .{});
    defer parsed.deinit();
    const observed = parsed.value.object.get("observed").?;
    const unavailable = observed.object.get("not_exposed_by_builtin").?.array.items;
    var expected: usize = 0;
    inline for (metadata.observed_declarations) |name| {
        if (@hasDecl(builtin, name)) {
            try t.expect(observed.object.contains(name));
        } else {
            try t.expect(!observed.object.contains(name));
            try t.expectEqualStrings(name, unavailable[expected].string);
            expected += 1;
        }
    }
    try t.expectEqual(expected, unavailable.len);
}

test "default production roots and original test cases do not acquire evidence execution" {
    for ([_][]const u8{ @embedFile("main.zig"), @embedFile("root.zig"), @embedFile("worker_fixture.zig") }) |source| {
        try t.expect(std.mem.indexOf(u8, source, "fixture_parent_metadata") == null);
        try t.expect(std.mem.indexOf(u8, source, "fixture_build_capture") == null);
        try t.expect(std.mem.indexOf(u8, source, "fixture_build_evidence") == null);
    }
    const source = @embedFile("tests.zig");
    try t.expect(std.mem.indexOf(u8, source, "if (@hasDecl(options, \"fixture_build_evidence\") and options.fixture_build_evidence)") != null);
    try t.expectEqual(@as(usize, 35), std.mem.count(u8, source, "\ntest \""));
    try t.expect(std.mem.indexOf(u8, source, "fixture_build_capture") == null);
    try t.expect(std.mem.indexOf(u8, source, ".collect(") == null);
}

test "source identity and module labels use strict fixed public alphabets" {
    try schema.validateIdentity("0123456789abcdef0123456789abcdef01234567");
    for ([_][]const u8{ "", "0" ** 39, "0" ** 41, "A" ** 40, "/" ** 40 }) |value|
        try t.expectError(error.InvalidSourceIdentity, schema.validateIdentity(value));
    try schema.validateModuleName("azure_sdk_core");
    for ([_][]const u8{ "", "../main", "/main", "name-token", "x" ** 65 }) |value|
        try t.expectError(error.InvalidModuleName, schema.validateModuleName(value));
}

test "private capture protocol binds fixed roles and only prepare accepts a parent" {
    const capture = @import("fixture_build_capture.zig");
    var args = captureArgs();
    const baseline = try capture.parse(t.allocator, &args);
    defer t.allocator.free(baseline.request.?.modules);
    try t.expectEqual(.baseline, baseline.mode);
    try t.expectEqualStrings("", baseline.request.?.parent);
    try t.expectEqualStrings("/private/raw", baseline.request.?.raw_worker);
    try t.expectEqualStrings("/private/selected", baseline.request.?.selected_worker);
    try t.expectEqualStrings("/private/zig_lib", baseline.request.?.compiler_lib);
    try t.expectEqualStrings("/private/options.zig", baseline.request.?.main_options);
    args[1] = "prepare";
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &args));
    args[6] = "/private/actual_parent";
    const prepared = try capture.parse(t.allocator, &args);
    defer t.allocator.free(prepared.request.?.modules);
    try t.expectEqualStrings("/private/actual_parent", prepared.request.?.parent);
    const collected = try capture.parse(t.allocator, &.{ "/private/root/collector", "collect", "/private/root" });
    try t.expect(collected.request == null);
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &.{ "/private/cache/collector", "collect", "/private/root" }));
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &.{ "/private/collector", "collect", "/private/root", "extra" }));
}

test "private capture protocol refuses unsafe paths identities ordering and argument bounds" {
    const capture = @import("fixture_build_capture.zig");
    for ([_]usize{ 0, 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20 }) |index| {
        for ([_][]const u8{ "relative", "/private/../other", "/private/./other", "/private//other", "/private/other/", "/private/\x00other" }) |path| {
            var args = captureArgs();
            args[index] = path;
            try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &args));
        }
    }
    var args = captureArgs();
    args[6] = "/private/unexpected_parent";
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &args));
    args = captureArgs();
    args[3] = "A" ** 40;
    try t.expectError(error.InvalidSourceIdentity, capture.parse(t.allocator, &args));
    args = captureArgs();
    args[5] = "[]";
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &args));
    args[5] = "x" ** (schema.max_metadata_bytes + 1);
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &args));
    args = captureArgs();
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, args[0..20]));
    const duplicate = args ++ [_][]const u8{ "main", "/private/other.zig", "/private/scope" };
    try t.expectError(error.InvalidArguments, capture.parse(t.allocator, &duplicate));
}

fn captureArgs() [21][]const u8 {
    return .{
        "/private/collector", "baseline",              "/private/root",
        "0" ** 40,            "1" ** 40,               "{}",
        "",                   "/private/raw",          "/private/selected",
        "/private/zig",       "/private/zig_lib",      "/private/options.zig",
        "/private/tests.zig", "/private/hyperv",       "/private/build",
        "/private/proof",     "/private/fixtures.log", "/private/fixture-build-exit.txt",
        "main",               "/private/tests.zig",    "/private/hyperv",
    };
}

fn features(value: std.json.Value, expected: std.Target.Cpu.Feature.Set) !void {
    const all = builtin.target.cpu.arch.allFeaturesList();
    try t.expectEqual(@as(i64, @intCast(all.len)), value.object.get("available_feature_count").?.integer);
    try t.expectEqual(@bitSizeOf(usize), value.object.get("word_bit_width").?.integer);
    const words = value.object.get("bitset_words").?.array.items;
    try t.expectEqual(expected.ints.len, words.len);
    for (words, expected.ints) |word, bits| {
        const actual: u64 = switch (word) {
            .integer => |number| @intCast(number),
            .number_string => |number| try std.fmt.parseInt(u64, number, 10),
            else => return error.InvalidFeatureWord,
        };
        try t.expectEqual(bits, actual);
    }
    const names = value.object.get("names").?.array.items;
    var index: usize = 0;
    for (all, 0..) |feature, bit| {
        if (!expected.isEnabled(@intCast(bit))) continue;
        try t.expectEqualStrings(feature.name, names[index].string);
        index += 1;
    }
    try t.expectEqual(@as(usize, expected.count()), index);
    try t.expectEqual(index, names.len);
}

fn noPaths(value: std.json.Value) !void {
    switch (value) {
        .string => |string| {
            try t.expect(std.mem.indexOfScalar(u8, string, '/') == null);
            try t.expect(std.mem.indexOf(u8, string, "HOME") == null);
        },
        .array => |array| for (array.items) |item| try noPaths(item),
        .object => |object| for (object.values()) |item| try noPaths(item),
        else => {},
    }
}
