//! Static data for the actual, opt-in persistence test compilation.
const std = @import("std");
const builtin = @import("builtin");
const schema = @import("fixture_build_schema.zig");

pub const observed_declarations = .{
    "zig_version",               "zig_version_string",
    "zig_backend",               "mode",
    "is_test",                   "output_mode",
    "link_mode",                 "object_format",
    "single_threaded",           "link_libc",
    "link_libcpp",               "error_return_tracing",
    "position_independent_code", "position_independent_executable",
    "strip_debug_info",          "code_model",
    "omit_frame_pointer",        "valgrind_support",
    "sanitize_thread",           "sanitize_c",
    "fuzz",                      "stack_check",
    "stack_protector",           "red_zone",
    "unwind_tables",             "dwarf_format",
};

pub const Features = struct {
    arch: std.Target.Cpu.Arch,
    set: std.Target.Cpu.Feature.Set,

    pub fn jsonStringify(self: Features, j: *std.json.Stringify) !void {
        const all = self.arch.allFeaturesList();
        try j.beginObject();
        try j.objectField("available_feature_count");
        try j.write(all.len);
        try j.objectField("word_bit_width");
        try j.write(@bitSizeOf(usize));
        try j.objectField("bitset_words");
        try j.write(self.set.ints);
        try j.objectField("names");
        try j.beginArray();
        for (all, 0..) |feature, index| {
            if (self.set.isEnabled(@intCast(index))) try j.write(feature.name);
        }
        try j.endArray();
        try j.endObject();
    }
};

pub const Target = struct {
    value: std.Target,

    pub fn jsonStringify(self: Target, j: *std.json.Stringify) !void {
        const value = self.value;
        try j.beginObject();
        try j.objectField("cpu");
        try j.write(.{
            .arch = value.cpu.arch,
            .model = .{
                .name = value.cpu.model.name,
                .llvm_name = value.cpu.model.llvm_name,
                .baseline_features = Features{ .arch = value.cpu.arch, .set = value.cpu.model.features },
            },
            .features = Features{ .arch = value.cpu.arch, .set = value.cpu.features },
        });
        try j.objectField("os");
        try j.beginObject();
        try j.objectField("tag");
        try j.write(value.os.tag);
        const range = value.os.tag.versionRangeTag();
        try j.objectField("version_range_kind");
        try j.write(range);
        try j.objectField("version_range");
        switch (range) {
            .none => try j.write(null),
            inline else => |tag| try j.write(@field(value.os.version_range, @tagName(tag))),
        }
        try j.endObject();
        try j.objectField("abi");
        try j.write(value.abi);
        try j.objectField("ofmt");
        try j.write(value.ofmt);
        try j.objectField("dynamic_linker_present");
        try j.write(value.dynamic_linker.get() != null);
        try j.objectField("dynamic_linker_path");
        try j.write("omitted_path");
        try j.objectField("dynamic_linker_sha256");
        if (value.dynamic_linker.get()) |path| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(path, &digest, .{});
            try j.write(std.fmt.bytesToHex(digest, .lower));
        } else try j.write(null);
        try j.endObject();
    }
};

const Observed = struct {
    pub fn jsonStringify(_: Observed, j: *std.json.Stringify) !void {
        try j.beginObject();
        try j.objectField("target");
        try j.write(Target{ .value = builtin.target });
        inline for (observed_declarations) |name| {
            if (@hasDecl(builtin, name)) {
                try j.objectField(name);
                try j.write(@field(builtin, name));
            }
        }
        try j.objectField("not_exposed_by_builtin");
        try j.beginArray();
        inline for (observed_declarations) |name| {
            if (!@hasDecl(builtin, name)) try j.write(name);
        }
        try j.endArray();
        try j.endObject();
    }
};

const Encoded = struct { bytes: [schema.max_metadata_bytes]u8, len: usize };

fn encode() Encoded {
    @setEvalBranchQuota(4_000_000);
    var result: Encoded = undefined;
    var writer = std.Io.Writer.fixed(&result.bytes);
    std.json.Stringify.value(.{
        .schema = "hyperv_persistence_fixture_parent_build_v1",
        .role = "persistence_main_test_parent",
        .origin = "actual_tests_zig_compile_builtin",
        .observed = Observed{},
    }, .{}, &writer) catch @compileError("persistence parent metadata exceeds its fixed bound");
    result.len = writer.end;
    return result;
}

const encoded = encode();
pub const payload = encoded.bytes[0..encoded.len].*;

pub fn exportSection() void {
    @export(&payload, .{
        .name = "uk_persistence_fixture_parent_build",
        .section = schema.section_name,
        .linkage = .strong,
    });
}
