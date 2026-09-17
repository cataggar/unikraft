const std = @import("std");
const builtin = @import("builtin");
const Standard = std.crypto.hash.sha2.Sha256;

extern fn hyperv_sha256_clear_upper() callconv(.c) void;

fn clearUpper() void {
    if (@inComptime()) return;
    if (comptime builtin.zig_backend == .stage2_x86_64 and
        builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }))
    {
        hyperv_sha256_clear_upper();
    }
}

/// Shared standard SHA-256 implementation with all Debug runtime checks.
/// Its legacy SHA instructions must not inherit dirty upper AVX registers
/// from self-hosted code, which does not insert the usual ABI transition fence.
pub const Sha256 = struct {
    inner: Standard,
    pub const block_length = Standard.block_length;
    pub const digest_length = Standard.digest_length;
    pub const Options = Standard.Options;

    pub fn init(options: Options) Sha256 {
        return .{ .inner = Standard.init(options) };
    }
    pub fn update(self: *Sha256, bytes: []const u8) void {
        clearUpper();
        self.inner.update(bytes);
    }
    pub fn final(self: *Sha256, out: *[digest_length]u8) void {
        clearUpper();
        self.inner.final(out);
    }
    pub fn finalResult(self: *Sha256) [digest_length]u8 {
        var out: [digest_length]u8 = undefined;
        self.final(&out);
        return out;
    }
    pub fn peek(self: Sha256) [digest_length]u8 {
        var copy = self;
        return copy.finalResult();
    }
    pub fn hash(bytes: []const u8, out: *[digest_length]u8, options: Options) void {
        var self = init(options);
        self.update(bytes);
        self.final(out);
    }
};
