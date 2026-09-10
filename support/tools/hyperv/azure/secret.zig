const std = @import("std");

/// Declining resize/remap makes every released copy go through zeroizing free.
/// This allocator context must outlive every allocation made through it.
pub const Allocator = struct {
    parent: std.mem.Allocator,
    used: std.atomic.Value(usize) = .init(0),
    limit: usize = 64 * 1024 * 1024,

    pub fn allocator(self: *Allocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = free,
        } };
    }

    fn alloc(context: *anyopaque, length: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *Allocator = @ptrCast(@alignCast(context));
        if (length > self.limit) return null;
        const previous = self.used.fetchAdd(length, .acq_rel);
        if (previous > self.limit - length) {
            _ = self.used.fetchSub(length, .acq_rel);
            return null;
        }
        const result = self.parent.rawAlloc(length, alignment, ret) orelse {
            _ = self.used.fetchSub(length, .acq_rel);
            return null;
        };
        @memset(result[0..length], 0);
        return result;
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *Allocator = @ptrCast(@alignCast(context));
        std.crypto.secureZero(u8, memory);
        _ = self.used.fetchSub(memory.len, .acq_rel);
        self.parent.rawFree(memory, alignment, ret);
    }
};

/// Heap-stable arena: parsed strings, tokens, headers, and intermediate copies
/// are all erased before their backing allocations return to the parent.
pub const Arena = struct {
    zero: Allocator,
    memory: std.heap.ArenaAllocator,

    pub fn create(parent: std.mem.Allocator) !*Arena {
        const self = try parent.create(Arena);
        self.zero = .{ .parent = parent };
        self.memory = .init(self.zero.allocator());
        return self;
    }

    pub fn allocator(self: *Arena) std.mem.Allocator {
        return self.memory.allocator();
    }

    pub fn destroy(self: *Arena) void {
        const parent = self.zero.parent;
        self.memory.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        parent.destroy(self);
    }
};

pub const Bytes = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    pub fn copy(allocator: std.mem.Allocator, source: []const u8) !Bytes {
        return .{ .allocator = allocator, .bytes = try allocator.dupe(u8, source) };
    }

    pub fn deinit(self: *Bytes) void {
        std.crypto.secureZero(u8, self.bytes);
        // Allocator.free poisons the slice in debug builds after our wipe.
        if (self.bytes.len != 0) self.allocator.rawFree(self.bytes, .of(u8), @returnAddress());
        self.* = undefined;
    }
};
