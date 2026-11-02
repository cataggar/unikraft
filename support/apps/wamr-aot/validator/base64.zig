// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

/// Standard padded base64 with one explicit decoded-size ceiling. The caller
/// owns the returned bytes, including the allocated zero-length result.
pub fn decode(allocator: std.mem.Allocator, text: []const u8, maximum: usize) ![]u8 {
    if (maximum > 64 * 1024 * 1024) return error.Base64Limit;
    if (text.len > (maximum / 3 + @intFromBool(maximum % 3 != 0)) * 4)
        return error.Base64Limit;
    const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
    if (size > maximum) return error.Base64Limit;
    const result = try allocator.alloc(u8, size);
    errdefer allocator.free(result);
    std.base64.standard.Decoder.decode(result, text) catch return error.InvalidBase64;
    const canonical = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(size));
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, text, std.base64.standard.Encoder.encode(canonical, result)))
        return error.InvalidBase64;
    return result;
}
