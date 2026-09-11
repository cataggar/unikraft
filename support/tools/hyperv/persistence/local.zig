const std = @import("std");
const c = @import("hyperv_core").contracts;

pub const maximum = 256 * 1024;
pub const Hash = [64]u8;
pub const Id = [32]u8;

pub fn hash(bytes: []const u8) Hash {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn hex(bytes: []const u8, nonzero: bool) !void {
    var any = false;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidHex;
        any = any or byte != '0';
    }
    if (nonzero and !any) return error.NilIdentity;
}

pub fn parse(comptime T: type, value: std.json.Value) !T {
    return switch (@typeInfo(T)) {
        .@"struct" => result: {
            if (@hasDecl(T, "parse")) break :result T.parse(value);
            const fields = std.meta.fields(T);
            var names: [fields.len][]const u8 = undefined;
            inline for (fields, 0..) |field, index| names[index] = field.name;
            const object = try c.exactFields(value, &names);
            var out: T = undefined;
            inline for (fields) |field| @field(out, field.name) = try parse(field.type, object.get(field.name).?);
            break :result out;
        },
        .array => |array| result: {
            if (array.child == u8) {
                const text = try c.string(value);
                if (text.len != array.len) return error.InvalidWidth;
                break :result text[0..array.len].*;
            }
            if (value != .array or value.array.items.len != array.len) return error.InvalidArray;
            var out: T = undefined;
            for (&out, value.array.items) |*item, raw| item.* = try parse(array.child, raw);
            break :result out;
        },
        .pointer => |pointer| if (pointer.size == .slice and pointer.child == u8) c.string(value) else @compileError("unsupported local pointer"),
        .int => c.integer(T, value),
        .bool => if (value == .bool) value.bool else error.ExpectedBoolean,
        .@"enum" => c.enumeration(T, value),
        .optional => |optional| if (value == .null) null else try parse(optional.child, value),
        else => @compileError("unsupported local contract type"),
    };
}

pub fn encode(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try write(&writer.writer, value);
    const document = try c.Document.parse(allocator, writer.written(), .{ .bytes = maximum, .items = 256, .tokens = 32768 });
    defer document.deinit();
    return document.canonicalAlloc(allocator);
}

fn write(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .@"struct" => {
            if (@hasDecl(T, "writeValue")) return value.writeValue(writer);
            if (@hasDecl(T, "write")) return value.write(writer);
            try writer.writeByte('{');
            inline for (std.meta.fields(T), 0..) |field, index| {
                if (index != 0) try writer.writeByte(',');
                try std.json.Stringify.value(field.name, .{}, writer);
                try writer.writeByte(':');
                try write(writer, @field(value, field.name));
            }
            try writer.writeByte('}');
        },
        .optional => if (value) |present| try write(writer, present) else try writer.writeAll("null"),
        .array => |array| {
            if (array.child == u8) return std.json.Stringify.value(value[0..], .{}, writer);
            try writer.writeByte('[');
            for (value, 0..) |item, index| {
                if (index != 0) try writer.writeByte(',');
                try write(writer, item);
            }
            try writer.writeByte(']');
        },
        else => try std.json.Stringify.value(value, .{}, writer),
    }
}
pub fn Document(comptime T: type) type {
    return struct {
        document: c.Document,
        value: T,
        binding: Hash,
        pub fn load(allocator: std.mem.Allocator, bytes: []const u8) !@This() {
            const document = try c.Document.parse(allocator, bytes, .{ .bytes = maximum, .items = 256, .tokens = 32768 });
            errdefer document.deinit();
            try document.requireCanonical(allocator, bytes);
            return .{ .document = document, .value = try parse(T, document.value()), .binding = hash(bytes) };
        }
        pub fn deinit(self: @This()) void {
            self.document.deinit();
        }
    };
}
