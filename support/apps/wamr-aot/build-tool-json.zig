// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");

pub const Style = enum { compact, pretty };
pub const Document = core.contracts.Document;
pub const Limits = core.contracts.Limits;

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    limits: Limits,
) !Document {
    return Document.parse(allocator, source, limits);
}

pub fn stringifyAlloc(
    allocator: std.mem.Allocator,
    value: anytype,
    style: Style,
) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    var document = try core.contracts.Document.parse(allocator, raw, .{
        .bytes = 4 * 1024 * 1024,
        .depth = 32,
        .string_bytes = 64 * 1024,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    return valueAlloc(allocator, document.value(), style);
}

pub fn valueAlloc(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    style: Style,
) ![]u8 {
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    try writeValue(allocator, &output.writer, value, style, 0);
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

pub fn writeString(writer: *std.Io.Writer, bytes: []const u8) !void {
    try writer.writeByte('"');
    var index: usize = 0;
    while (index < bytes.len) {
        const byte = bytes[index];
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0x08 => try writer.writeAll("\\b"),
            0x0c => try writer.writeAll("\\f"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x00...0x07, 0x0b, 0x0e...0x1f => try writeUnicodeEscape(writer, byte),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7f => try writer.writeByte(byte),
            else => {
                const decoded = decodeUtf8(bytes[index..]);
                if (decoded) |scalar| {
                    if (scalar.value <= 0xffff) {
                        try writeUnicodeEscape(writer, scalar.value);
                    } else {
                        const adjusted = scalar.value - 0x10000;
                        try writeUnicodeEscape(writer, 0xd800 + (adjusted >> 10));
                        try writeUnicodeEscape(writer, 0xdc00 + (adjusted & 0x3ff));
                    }
                    index += scalar.length - 1;
                } else {
                    try writeUnicodeEscape(writer, 0xdc00 + @as(u21, byte));
                }
            },
        }
        index += 1;
    }
    try writer.writeByte('"');
}

fn writeValue(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    value: std.json.Value,
    style: Style,
    depth: usize,
) anyerror!void {
    switch (value) {
        .object => |object| {
            const keys = try allocator.dupe([]const u8, object.keys());
            defer allocator.free(keys);
            std.mem.sort([]const u8, keys, {}, lessBytes);
            try writer.writeByte('{');
            if (keys.len != 0) {
                for (keys, 0..) |key, index| {
                    if (index != 0) try writer.writeByte(',');
                    if (style == .pretty) {
                        try writer.writeByte('\n');
                        try indent(writer, depth + 1);
                    }
                    try writeString(writer, key);
                    try writer.writeByte(':');
                    if (style == .pretty) try writer.writeByte(' ');
                    try writeValue(allocator, writer, object.get(key).?, style, depth + 1);
                }
                if (style == .pretty) {
                    try writer.writeByte('\n');
                    try indent(writer, depth);
                }
            }
            try writer.writeByte('}');
        },
        .array => |array| {
            try writer.writeByte('[');
            if (array.items.len != 0) {
                for (array.items, 0..) |child, index| {
                    if (index != 0) try writer.writeByte(',');
                    if (style == .pretty) {
                        try writer.writeByte('\n');
                        try indent(writer, depth + 1);
                    }
                    try writeValue(allocator, writer, child, style, depth + 1);
                }
                if (style == .pretty) {
                    try writer.writeByte('\n');
                    try indent(writer, depth);
                }
            }
            try writer.writeByte(']');
        },
        .string => |string| try writeString(writer, string),
        .number_string => |number| try writer.writeAll(number),
        .integer => |integer| try writer.print("{d}", .{integer}),
        .float => |float| try writer.print("{d}", .{float}),
        .bool => |boolean| try writer.writeAll(if (boolean) "true" else "false"),
        .null => try writer.writeAll("null"),
    }
}

fn lessBytes(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn indent(writer: *std.Io.Writer, depth: usize) !void {
    for (0..depth * 2) |_| try writer.writeByte(' ');
}

fn writeUnicodeEscape(writer: *std.Io.Writer, value: u21) !void {
    const digits = "0123456789abcdef";
    try writer.writeAll("\\u");
    try writer.writeByte(digits[(value >> 12) & 0xf]);
    try writer.writeByte(digits[(value >> 8) & 0xf]);
    try writer.writeByte(digits[(value >> 4) & 0xf]);
    try writer.writeByte(digits[value & 0xf]);
}

const Scalar = struct { value: u21, length: usize };

fn decodeUtf8(bytes: []const u8) ?Scalar {
    const first = bytes[0];
    if (first >= 0xc2 and first <= 0xdf and bytes.len >= 2 and continuation(bytes[1])) {
        return .{
            .value = (@as(u21, first & 0x1f) << 6) | (bytes[1] & 0x3f),
            .length = 2,
        };
    }
    if (first >= 0xe0 and first <= 0xef and bytes.len >= 3 and
        continuation(bytes[1]) and continuation(bytes[2]) and
        !(first == 0xe0 and bytes[1] < 0xa0) and
        !(first == 0xed and bytes[1] >= 0xa0))
    {
        return .{
            .value = (@as(u21, first & 0x0f) << 12) |
                (@as(u21, bytes[1] & 0x3f) << 6) |
                (bytes[2] & 0x3f),
            .length = 3,
        };
    }
    if (first >= 0xf0 and first <= 0xf4 and bytes.len >= 4 and
        continuation(bytes[1]) and continuation(bytes[2]) and continuation(bytes[3]) and
        !(first == 0xf0 and bytes[1] < 0x90) and
        !(first == 0xf4 and bytes[1] >= 0x90))
    {
        return .{
            .value = (@as(u21, first & 0x07) << 18) |
                (@as(u21, bytes[1] & 0x3f) << 12) |
                (@as(u21, bytes[2] & 0x3f) << 6) |
                (bytes[3] & 0x3f),
            .length = 4,
        };
    }
    return null;
}

fn continuation(byte: u8) bool {
    return byte & 0xc0 == 0x80;
}
