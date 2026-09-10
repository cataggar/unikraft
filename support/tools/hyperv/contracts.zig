const std = @import("std");
const sensitive = @import("sensitive.zig");

pub const Limits = struct {
    bytes: usize = 256 * 1024,
    depth: usize = 16,
    string_bytes: usize = 4096,
    items: usize = 256,
    tokens: usize = 8192,

    fn validate(self: Limits) !void {
        if (self.bytes == 0 or self.bytes > 4 * 1024 * 1024 or
            self.depth == 0 or self.depth > 32 or self.string_bytes > self.bytes or
            self.items == 0 or self.items > 4096 or self.tokens == 0 or self.tokens > 65536)
            return error.InvalidLimits;
    }
};

pub const Document = struct {
    parsed: std.json.Parsed(std.json.Value),

    pub fn parse(allocator: std.mem.Allocator, source: []const u8, limits: Limits) !Document {
        try limits.validate();
        if (source.len > limits.bytes) return error.InputTooLarge;
        try scanBounds(allocator, source, limits);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, source, .{
            .duplicate_field_behavior = .@"error",
            .ignore_unknown_fields = false,
            .max_value_len = limits.string_bytes,
            .allocate = .alloc_always,
            .parse_numbers = false,
        });
        errdefer parsed.deinit();
        try checkItems(parsed.value, limits.items);
        return .{ .parsed = parsed };
    }

    pub fn deinit(self: Document) void {
        self.parsed.deinit();
    }

    pub fn value(self: Document) std.json.Value {
        return self.parsed.value;
    }

    /// Native canonical JSON is compact UTF-8, byte-sorted keys, and one final LF.
    pub fn canonicalAlloc(self: Document, allocator: std.mem.Allocator) ![]u8 {
        var writer = std.Io.Writer.Allocating.init(allocator);
        defer writer.deinit();
        try writeCanonical(allocator, self.value(), &writer.writer);
        try writer.writer.writeByte('\n');
        return writer.toOwnedSlice();
    }

    pub fn requireCanonical(self: Document, allocator: std.mem.Allocator, source: []const u8) !void {
        const canonical = try self.canonicalAlloc(allocator);
        defer allocator.free(canonical);
        if (!std.mem.eql(u8, canonical, source)) return error.NonCanonical;
    }
};

/// Scanner temporaries, decoded keys/strings and parser arenas all use a wiping
/// allocator, including failure paths. The caller still owns the source bytes.
pub const SensitiveDocument = struct {
    document: Document,
    owner: *sensitive.Allocator,

    pub fn parse(allocator: std.mem.Allocator, source: []const u8, limits: Limits) !SensitiveDocument {
        const owner = try allocator.create(sensitive.Allocator);
        owner.* = .{ .backing = allocator };
        errdefer destroyOwner(owner);
        return .{ .document = try Document.parse(owner.allocator(), source, limits), .owner = owner };
    }

    pub fn value(self: SensitiveDocument) std.json.Value {
        return self.document.value();
    }

    pub fn requireCanonical(self: SensitiveDocument, source: []const u8) !void {
        try self.document.requireCanonical(self.owner.allocator(), source);
    }

    pub fn deinit(self: SensitiveDocument) void {
        self.document.deinit();
        destroyOwner(self.owner);
    }

    fn destroyOwner(owner: *sensitive.Allocator) void {
        const allocator = owner.backing;
        std.crypto.secureZero(u8, std.mem.asBytes(owner));
        allocator.rawFree(std.mem.asBytes(owner), .of(sensitive.Allocator), @returnAddress());
    }
};

fn scanBounds(allocator: std.mem.Allocator, source: []const u8, limits: Limits) !void {
    var scanner = std.json.Scanner.initCompleteInput(allocator, source);
    defer scanner.deinit();
    var depth: usize = 0;
    var count: usize = 0;
    while (true) {
        const token = try scanner.nextAllocMax(allocator, .alloc_always, limits.string_bytes);
        defer switch (token) {
            .allocated_string, .allocated_number => |bytes| allocator.free(bytes),
            else => {},
        };
        count += 1;
        if (count > limits.tokens) return error.TooManyTokens;
        switch (token) {
            .object_begin, .array_begin => {
                depth += 1;
                if (depth > limits.depth) return error.TooDeep;
            },
            .object_end, .array_end => {
                if (depth == 0) return error.InvalidJson;
                depth -= 1;
            },
            .number, .allocated_number => |bytes| {
                const number = try decimal(i128, bytes);
                if (number < std.math.minInt(i64) or number > std.math.maxInt(u64))
                    return error.IntegerOverflow;
            },
            .end_of_document => return,
            else => {},
        }
    }
}

fn checkItems(value: std.json.Value, maximum: usize) anyerror!void {
    switch (value) {
        .object => |object| {
            if (object.count() > maximum) return error.TooManyItems;
            for (object.values()) |child| try checkItems(child, maximum);
        },
        .array => |array| {
            if (array.items.len > maximum) return error.TooManyItems;
            for (array.items) |child| try checkItems(child, maximum);
        },
        else => {},
    }
}

fn writeCanonical(allocator: std.mem.Allocator, value: std.json.Value, writer: *std.Io.Writer) anyerror!void {
    switch (value) {
        .object => |object| {
            const keys = try allocator.dupe([]const u8, object.keys());
            defer allocator.free(keys);
            std.mem.sort([]const u8, keys, {}, struct {
                fn less(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.less);
            try writer.writeByte('{');
            for (keys, 0..) |key, i| {
                if (i != 0) try writer.writeByte(',');
                try std.json.Stringify.value(key, .{}, writer);
                try writer.writeByte(':');
                try writeCanonical(allocator, object.get(key).?, writer);
            }
            try writer.writeByte('}');
        },
        .array => |array| {
            try writer.writeByte('[');
            for (array.items, 0..) |child, i| {
                if (i != 0) try writer.writeByte(',');
                try writeCanonical(allocator, child, writer);
            }
            try writer.writeByte(']');
        },
        .number_string => |number| try writer.writeAll(number),
        else => try std.json.Stringify.value(value, .{}, writer),
    }
}

pub fn exactFields(value: std.json.Value, fields: []const []const u8) !std.json.ObjectMap {
    const object = switch (value) {
        .object => |object| object,
        else => return error.ExpectedObject,
    };
    if (object.count() != fields.len) return error.UnexpectedFields;
    for (fields, 0..) |field, i| {
        for (fields[0..i]) |previous| if (std.mem.eql(u8, previous, field)) return error.InvalidFieldSet;
        if (!object.contains(field)) return error.UnexpectedFields;
    }
    return object;
}

pub fn string(value: std.json.Value) ![]const u8 {
    return switch (value) {
        .string => |bytes| bytes,
        else => error.ExpectedString,
    };
}

pub fn enumeration(comptime T: type, value: std.json.Value) !T {
    return std.meta.stringToEnum(T, try string(value)) orelse error.InvalidEnum;
}

pub fn integer(comptime T: type, value: std.json.Value) !T {
    return switch (value) {
        .number_string => |number| decimal(T, number),
        else => error.ExpectedInteger,
    };
}

fn decimal(comptime T: type, source: []const u8) !T {
    if (source.len == 0) return error.ExpectedInteger;
    const digits = if (source[0] == '-') source[1..] else source;
    if (digits.len == 0) return error.ExpectedInteger;
    for (digits) |byte| if (byte < '0' or byte > '9') return error.ExpectedInteger;
    if (digits.len > 1 and digits[0] == '0') return error.ExpectedInteger;
    if (source[0] == '-' and digits[0] == '0') return error.ExpectedInteger;
    return std.fmt.parseInt(T, source, 10) catch return error.IntegerOverflow;
}

pub const Sha256 = [32]u8;
pub const Uuid = [16]u8;

pub fn parseSha256(source: []const u8) !Sha256 {
    if (source.len != 64) return error.InvalidSha256;
    var result: Sha256 = undefined;
    for (source, 0..) |byte, i| {
        if (!lowerHex(byte)) return error.InvalidSha256;
        if (i % 2 == 0) result[i / 2] = hex(byte) << 4 else result[i / 2] |= hex(byte);
    }
    return result;
}

/// Canonical UUID spelling only; version/variant/identity policy belongs to the caller.
pub fn parseUuid(source: []const u8) !Uuid {
    if (source.len != 36) return error.InvalidUuid;
    var result: Uuid = undefined;
    var digit: usize = 0;
    for (source, 0..) |byte, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (byte != '-') return error.InvalidUuid;
        } else {
            if (!lowerHex(byte)) return error.InvalidUuid;
            if (digit % 2 == 0) result[digit / 2] = hex(byte) << 4 else result[digit / 2] |= hex(byte);
            digit += 1;
        }
    }
    return result;
}

fn lowerHex(byte: u8) bool {
    return (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f');
}

fn hex(byte: u8) u8 {
    return if (byte <= '9') byte - '0' else byte - 'a' + 10;
}

pub const Geometry = struct {
    sectors: u64,
    sector_size: u16,

    pub fn byteSize(self: Geometry) !u64 {
        if (self.sector_size != 512 or self.sectors == 0) return error.InvalidGeometry;
        return std.math.mul(u64, self.sectors, self.sector_size) catch error.IntegerOverflow;
    }
};

/// An immutable local input binding, not execution admission or a completed handoff.
pub const InputBinding = struct {
    run_id: Uuid,
    sha256: Sha256,
    byte_length: u64,

    pub fn parse(value: std.json.Value) !InputBinding {
        const object = try exactFields(value, &.{ "schema_version", "contract", "run_id", "sha256", "byte_length" });
        if (try integer(u32, object.get("schema_version").?) != 1) return error.UnknownSchema;
        if (!std.mem.eql(u8, try string(object.get("contract").?), "uk.hyperv.input-binding"))
            return error.UnknownContract;
        return .{
            .run_id = try parseUuid(try string(object.get("run_id").?)),
            .sha256 = try parseSha256(try string(object.get("sha256").?)),
            .byte_length = try integer(u64, object.get("byte_length").?),
        };
    }
};
