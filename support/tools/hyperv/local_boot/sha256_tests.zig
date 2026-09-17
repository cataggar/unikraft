const std = @import("std");
const Sha256 = @import("sha256.zig").Sha256;
const Standard = std.crypto.hash.sha2.Sha256;
const t = std.testing;

test "native file SHA256 retains standard known digests" {
    for ([_]struct { input: []const u8, sha: []const u8 }{
        .{ .input = "", .sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        .{ .input = "abc", .sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        .{ .input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", .sha = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    }) |case| {
        var actual: [32]u8 = undefined;
        Sha256.hash(case.input, &actual, .{});
        try t.expectEqualStrings(case.sha, &std.fmt.bytesToHex(actual, .lower));
    }
}

test "native file SHA256 streaming peek and continuation preserve every byte" {
    var bytes: [2 * 32768 + 65]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i *% 131 +% 17);
    for ([_]usize{ 0, 1, 31, 32, 55, 56, 63, 64, 65, 127, 128, 32767, 32768, 32769, bytes.len }) |length| {
        var expected: [32]u8 = undefined;
        Standard.hash(bytes[0..length], &expected, .{});
        for ([_]usize{ 1, 7, 55, 64, 65, 32768 }) |chunk| {
            var hash = Sha256.init(.{});
            const prefix = @min(chunk, length);
            hash.update(bytes[0..prefix]);
            var expected_prefix: [32]u8 = undefined;
            Standard.hash(bytes[0..prefix], &expected_prefix, .{});
            try t.expectEqualSlices(u8, &expected_prefix, &hash.peek());
            var offset = prefix;
            while (offset < length) {
                const end = @min(offset + chunk, length);
                hash.update(bytes[offset..end]);
                offset = end;
            }
            try t.expectEqualSlices(u8, &expected, &hash.peek());
            try t.expectEqualSlices(u8, &expected, &hash.finalResult());
        }
    }
}
