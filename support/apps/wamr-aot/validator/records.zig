// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const c = @import("hyperv_core").contracts;

pub const Identity = struct {
    wamr_revision: []const u8,
    minimal_wasi: bool,
    tiny_wasm: []const u8,
    tiny_cwasm: []const u8,
    runtime: []const u8,
    coremark_wasm: []const u8 = "",
    coremark_cwasm: []const u8 = "",
    nofp_wasm: []const u8 = "",
    nofp_cwasm: []const u8 = "",
};

pub const PreparedIdentity = struct {
    document: c.Document,
    value: Identity,

    pub fn parse(allocator: std.mem.Allocator, source: []const u8) !PreparedIdentity {
        var document = try c.Document.parse(allocator, source, .{
            .bytes = 64 * 1024,
            .string_bytes = 8192,
            .items = 4096,
        });
        errdefer document.deinit();
        const fields = try object(document.value());
        const files = try object(try get(fields, "files"));
        const minimal_wasi = try boolean(try get(fields, "minimal_wasi"));
        var identity: Identity = .{
            .wamr_revision = try c.string(try get(fields, "wamr_revision")),
            .minimal_wasi = minimal_wasi,
            .tiny_wasm = try sha(files, "tiny.wasm"),
            .tiny_cwasm = try sha(files, "tiny.cwasm"),
            .runtime = try sha(files, "libwamr-aot.a"),
        };
        if (minimal_wasi) {
            identity.coremark_wasm = try sha(files, "coremark.wasm");
            identity.coremark_cwasm = try sha(files, "coremark.cwasm");
            identity.nofp_wasm = try sha(files, "coremark-nofp.wasm");
            identity.nofp_cwasm = try sha(files, "coremark-nofp.cwasm");
        }
        return .{ .document = document, .value = identity };
    }

    pub fn deinit(self: *PreparedIdentity) void {
        self.document.deinit();
        self.* = undefined;
    }
};

pub const OptionalIdentity = struct {
    document: c.Document,
    variant: []const u8,
    revision: []const u8,
    source_tree: []const u8,
    files: std.json.ObjectMap,
    jit_mode: ?[]const u8,

    pub fn parse(allocator: std.mem.Allocator, source: []const u8) !OptionalIdentity {
        var document = try c.Document.parse(allocator, source, .{
            .bytes = 64 * 1024,
            .string_bytes = 8192,
            .items = 4096,
        });
        errdefer document.deinit();
        const fields = try object(document.value());
        const files = try object(try get(fields, "files"));
        const variant = try c.string(try get(fields, "variant"));
        const revision = try c.string(try get(fields, "wamr_revision"));
        const source_tree = try c.string(try get(fields, "source_tree_sha256"));
        _ = try c.parseSha256(source_tree);
        const jit_mode: ?[]const u8 = if (fields.get("jit_mode")) |value| switch (value) {
            .null => null,
            .string => |mode| mode,
            else => return error.InvalidMode,
        } else if (std.mem.eql(u8, variant, "snapshot")) null else return error.MissingField;
        _ = try sha(files, "libwamr-aot.a");
        _ = try sha(files, "wamrc");
        if (std.mem.eql(u8, variant, "snapshot")) {
            inline for (.{ "compute.wasm", "compute.cwasm", "memory.wasm", "memory.cwasm" }) |name|
                _ = try sha(files, name);
        } else {
            _ = try sha(files, "matched.wasm");
            if (std.mem.eql(u8, variant, "sample-aot")) _ = try sha(files, "matched.cwasm");
        }
        return .{
            .document = document,
            .variant = variant,
            .revision = revision,
            .source_tree = source_tree,
            .files = files,
            .jit_mode = jit_mode,
        };
    }

    pub fn deinit(self: *OptionalIdentity) void {
        self.document.deinit();
        self.* = undefined;
    }

    pub fn file(self: OptionalIdentity, name: []const u8) ![]const u8 {
        return sha(self.files, name);
    }
};

pub fn parseDocument(allocator: std.mem.Allocator, source: []const u8) !c.Document {
    return c.Document.parse(allocator, source, .{
        .bytes = 16 * 1024,
        .string_bytes = 8192,
    });
}

pub fn object(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |fields| fields,
        else => error.ExpectedObject,
    };
}

pub fn get(fields: std.json.ObjectMap, name: []const u8) !std.json.Value {
    return fields.get(name) orelse error.MissingField;
}

pub fn boolean(value: std.json.Value) !bool {
    return switch (value) {
        .bool => |flag| flag,
        else => error.ExpectedBoolean,
    };
}

pub fn equal(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) return error.WrongRecordValue;
}

pub fn stringEquals(fields: std.json.ObjectMap, name: []const u8, expected: []const u8) !void {
    try equal(try c.string(try get(fields, name)), expected);
}

pub fn intEquals(fields: std.json.ObjectMap, name: []const u8, expected: u64) !void {
    if (try c.integer(u64, try get(fields, name)) != expected) return error.WrongRecordValue;
}

pub fn trueField(fields: std.json.ObjectMap, name: []const u8) !void {
    if (!try boolean(try get(fields, name))) return error.WrongRecordValue;
}

fn sha(files: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const text = try c.string(try get(files, name));
    _ = try c.parseSha256(text);
    return text;
}
