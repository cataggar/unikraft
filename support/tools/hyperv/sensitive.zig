const std = @import("std");

/// Keep this adapter alive while any allocation made through it is alive.
/// Refusing resize/remap forces relocation through our wiping free operation.
pub const Allocator = struct {
    backing: std.mem.Allocator,

    pub fn allocator(self: *Allocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocate,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = release,
        } };
    }

    fn allocate(context: *anyopaque, length: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *Allocator = @ptrCast(@alignCast(context));
        return self.backing.rawAlloc(length, alignment, address);
    }

    fn release(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *Allocator = @ptrCast(@alignCast(context));
        std.crypto.secureZero(u8, memory);
        self.backing.rawFree(memory, alignment, address);
    }
};

pub const Buffer = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    length: usize,

    pub fn bytes(self: Buffer) []const u8 {
        return self.storage[0..self.length];
    }

    pub fn deinit(self: *Buffer) void {
        std.crypto.secureZero(u8, self.storage);
        if (self.storage.len != 0) self.allocator.rawFree(self.storage, .of(u8), @returnAddress());
        self.* = undefined;
    }
};
