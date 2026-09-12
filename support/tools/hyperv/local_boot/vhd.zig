const std = @import("std");
const core = @import("hyperv_core");
const c = @import("config.zig");

/// Only a complete fixed VHD is accepted. QEMU receives the full container
/// through its vpc opening interface, never a raw prefix/slice.
pub fn footer(bytes: *const [512]u8, file_size: u64) !u64 {
    const size = std.mem.readInt(u64, bytes[48..56], .big);
    if (!std.mem.eql(u8, bytes[0..8], "conectix") or
        std.mem.readInt(u32, bytes[8..12], .big) != 2 or
        std.mem.readInt(u32, bytes[12..16], .big) != 0x10000 or
        std.mem.readInt(u64, bytes[16..24], .big) != std.math.maxInt(u64) or
        std.mem.readInt(u64, bytes[40..48], .big) != size or
        std.mem.readInt(u32, bytes[60..64], .big) != 2 or
        size == 0 or size > c.max_input or size % (1024 * 1024) != 0 or
        file_size != size + 512 or bytes[84] != 0) return error.InvalidFixedVhd;
    var sum: u32 = 0;
    for (bytes, 0..) |byte, i| if (i < 64 or i >= 68) {
        sum +%= byte;
    };
    if (std.mem.readInt(u32, bytes[64..68], .big) != ~sum) return error.InvalidFixedVhd;
    if (std.mem.allEqual(u8, bytes[68..84], 0) or !std.mem.allEqual(u8, bytes[85..], 0)) return error.InvalidFixedVhd;
    const cylinders: u64 = std.mem.readInt(u16, bytes[56..58], .big);
    const heads: u64 = bytes[58];
    const sectors: u64 = bytes[59];
    const geometry = cylinders * heads * sectors;
    const exact = size / 512;
    if (cylinders == 0 or heads == 0 or heads > 16 or sectors == 0 or
        geometry > exact or exact - geometry >= heads * sectors) return error.InvalidFixedVhd;
    // Pinned QEMU's vpc reader uses CHS for these legacy creators. Its QAPI
    // opening interface has no size-selection override; never round the disk.
    for ([_][]const u8{ "vpc ", "vs  ", "qemu" }) |creator|
        if (std.mem.eql(u8, bytes[28..32], creator) and geometry != exact) return error.InvalidFixedVhd;
    return size;
}

pub fn validate(io: std.Io, file: std.Io.File) !u64 {
    const before = try core.private_files.snapshot(file);
    if (before.size < 512) return error.InvalidFixedVhd;
    var bytes: [512]u8 = undefined;
    if (try file.readPositionalAll(io, &bytes, before.size - 512) != bytes.len) return error.InvalidFixedVhd;
    const size = try footer(&bytes, before.size);
    if (!core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.ArtifactChanged;
    return size;
}
