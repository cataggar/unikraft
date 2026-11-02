const std = @import("std");

/// ARM progress metadata can contain decimals. Unlike owned integer-only core
/// contracts, preserve their lexical form; consumed integer fields still use
/// core.contracts.integer, never JSON float-to-integer coercion.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Value {
    if (bytes.len > 4 * 1024 * 1024) return error.BodyTooLarge;
    var scanner = std.json.Scanner.initCompleteInput(allocator, bytes);
    defer scanner.deinit();
    var depth: usize = 0;
    var tokens: usize = 0;
    while (true) {
        const token = try scanner.next();
        tokens += 1;
        if (tokens > 65536) return error.TooManyTokens;
        switch (token) {
            .object_begin, .array_begin => {
                depth += 1;
                if (depth > 32) return error.TooDeep;
            },
            .object_end, .array_end => {
                if (depth == 0) return error.InvalidJson;
                depth -= 1;
            },
            .end_of_document => break,
            else => {},
        }
    }
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
        .parse_numbers = false,
        .max_value_len = 16 * 1024,
    });
}
