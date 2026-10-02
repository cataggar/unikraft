// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const layout = @import("layout.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Crc32 = std.hash.Crc32;

pub const max_members = layout.max_members;
pub const max_archive_bytes = layout.max_total_bytes;

pub const version_needed: u16 = 20;
pub const create_system_unix: u8 = 3;
pub const version_made_by: u16 = (@as(u16, create_system_unix) << 8) | version_needed;
pub const flags: u16 = 0;
pub const method_stored: u16 = 0;
pub const dos_time_midnight: u16 = 0;
pub const dos_date_1980_01_01: u16 = 0x0021;
pub const internal_attr: u16 = 0;
pub const external_attr_regular_0600: u32 = @as(u32, 0o100600) << 16;

const local_sig: u32 = 0x04034b50;
const central_sig: u32 = 0x02014b50;
const eocd_sig: u32 = 0x06054b50;
const eocd_sig_bytes = [_]u8{ 'P', 'K', 5, 6 };
const local_header_len: usize = 30;
const central_header_len: usize = 46;
const eocd_len: usize = 22;

pub const ZipError = error{
    InvalidZip,
    InvalidName,
    DuplicateName,
    NameCollision,
    TooManyMembers,
    TooLarge,
    Truncated,
    PrependedBytes,
    TrailingBytes,
    MultipleEndRecords,
    ArchiveComment,
    MemberComment,
    ExtraField,
    UnsupportedCompression,
    Encrypted,
    DataDescriptor,
    UnsupportedFlags,
    Zip64,
    WrongMode,
    WrongCreateSystem,
    WrongVersion,
    WrongTimestamp,
    WrongInternalAttributes,
    DiskUnsupported,
    OrderMismatch,
    NameMismatch,
    HeaderMismatch,
    SizeMismatch,
    CrcMismatch,
    DigestMismatch,
    Overlap,
    OutOfBounds,
    UnexpectedMemberCount,
};

pub const WriteError = ZipError || std.Io.Writer.Error || std.Io.Reader.ShortError;

pub const Entry = struct {
    name: []const u8,
    reader: *std.Io.Reader,
    size: u64,
    crc32: u32,
    sha256: [Sha256.digest_length]u8,
    limit: u64,
};

pub const SliceEntry = struct {
    name: []const u8,
    bytes: []const u8,
    limit: u64,
};

pub const ExpectedMember = struct {
    name: []const u8,
    size: u64,
    sha256: [Sha256.digest_length]u8,
    limit: u64,
};

pub const ExpectedArchive = struct {
    members: []const ExpectedMember,
    archive_sha256: [Sha256.digest_length]u8,
};

const MemberMeta = struct {
    name: []const u8,
    size: u32,
    crc32: u32,
    sha256: [Sha256.digest_length]u8,
    local_offset: u32,
    limit: u64,
};

pub fn sha256(bytes: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

pub fn crc32(bytes: []const u8) u32 {
    return Crc32.hash(bytes);
}

pub fn writeArchive(writer: *std.Io.Writer, entries: []const Entry, archive_sha256: *[Sha256.digest_length]u8) WriteError!void {
    if (entries.len > max_members) return error.TooManyMembers;
    try validateEntryNames(entries);

    var out = CountingWriter.init(writer);
    var metas: [max_members]MemberMeta = undefined;
    var total_uncompressed: u64 = 0;
    var buffer: [64 * 1024]u8 = undefined;

    for (entries, 0..) |entry, i| {
        if (entry.size > entry.limit) return error.TooLarge;
        if (entry.size > std.math.maxInt(u32)) return error.Zip64;
        total_uncompressed = addBounded(total_uncompressed, entry.size) catch return error.TooLarge;
        if (total_uncompressed > max_archive_bytes) return error.TooLarge;
        const local_offset = try u32FromPos(out.pos);
        const size: u32 = @intCast(entry.size);
        metas[i] = .{
            .name = entry.name,
            .size = size,
            .crc32 = entry.crc32,
            .sha256 = entry.sha256,
            .local_offset = local_offset,
            .limit = entry.limit,
        };
        try writeLocalHeader(&out, entry.name, size, entry.crc32);
        try streamEntryData(&out, entry, &buffer);
    }

    const central_offset = try u32FromPos(out.pos);
    for (metas[0..entries.len]) |meta| try writeCentralHeader(&out, meta);
    const central_size_u64 = out.pos - central_offset;
    const central_size = try u32FromU64(central_size_u64);
    try writeEndRecord(&out, @intCast(entries.len), central_size, central_offset);
    if (out.pos > max_archive_bytes) return error.TooLarge;
    out.final(archive_sha256);
}

pub fn writeArchiveFile(io: std.Io, dir: std.Io.Dir, path: []const u8, entries: []const Entry, archive_sha256: *[Sha256.digest_length]u8) !void {
    const file = try dir.createFile(io, path, .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    var keep = false;
    errdefer if (!keep) dir.deleteFile(io, path) catch {};
    defer file.close(io);
    var file_buffer: [8 * 1024]u8 = undefined;
    var file_writer = file.writer(io, &file_buffer);
    try writeArchive(&file_writer.interface, entries, archive_sha256);
    try file_writer.flush();
    try file.sync(io);
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
    keep = true;
}

pub fn expectedFromEntries(entries: []const Entry, out: []ExpectedMember) ZipError![]const ExpectedMember {
    if (out.len < entries.len) return error.InvalidZip;
    if (entries.len > max_members) return error.TooManyMembers;
    try validateEntryNames(entries);
    var total: u64 = 0;
    for (entries, 0..) |entry, i| {
        if (entry.size > entry.limit) return error.TooLarge;
        total = addBounded(total, entry.size) catch return error.TooLarge;
        if (total > max_archive_bytes) return error.TooLarge;
        out[i] = .{
            .name = entry.name,
            .size = entry.size,
            .sha256 = entry.sha256,
            .limit = entry.limit,
        };
    }
    return out[0..entries.len];
}

pub fn expectedFromSlices(entries: []const SliceEntry, out: []ExpectedMember) ZipError![]const ExpectedMember {
    if (out.len < entries.len) return error.InvalidZip;
    if (entries.len > max_members) return error.TooManyMembers;
    try validateSliceEntryNames(entries);
    var total: u64 = 0;
    for (entries, 0..) |entry, i| {
        if (entry.bytes.len > entry.limit) return error.TooLarge;
        total = addBounded(total, entry.bytes.len) catch return error.TooLarge;
        if (total > max_archive_bytes) return error.TooLarge;
        out[i] = .{
            .name = entry.name,
            .size = entry.bytes.len,
            .sha256 = sha256(entry.bytes),
            .limit = entry.limit,
        };
    }
    return out[0..entries.len];
}

pub fn verifyArchive(bytes: []const u8, expected: ExpectedArchive) ZipError!void {
    if (bytes.len > max_archive_bytes) return error.TooLarge;
    try validateExpectedMembers(expected.members);
    try parseAndVerify(bytes, expected.members);
    if (!std.mem.eql(u8, &sha256(bytes), &expected.archive_sha256)) return error.DigestMismatch;
}

pub fn validateName(name: []const u8) ZipError!void {
    if (name.len == 0 or name.len > std.math.maxInt(u16)) return error.InvalidName;
    if (name[0] == '/' or name[name.len - 1] == '/') return error.InvalidName;
    if (name.len >= 2 and std.ascii.isAlphabetic(name[0]) and name[1] == ':') return error.InvalidName;
    if (std.mem.startsWith(u8, name, "//")) return error.InvalidName;

    var segment_len: usize = 0;
    var segment_start: usize = 0;
    for (name, 0..) |byte, i| {
        if (byte < 0x20 or byte == 0x7f or byte >= 0x80 or byte == 0) return error.InvalidName;
        if (byte == '\\') return error.InvalidName;
        if (!allowedNameByte(byte)) return error.InvalidName;
        if (byte == '/') {
            try validateSegment(name[segment_start..i], segment_len);
            segment_start = i + 1;
            segment_len = 0;
        } else {
            segment_len += 1;
        }
    }
    try validateSegment(name[segment_start..], segment_len);
}

fn validateSegment(segment: []const u8, len: usize) ZipError!void {
    if (len == 0) return error.InvalidName;
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.InvalidName;
}

fn allowedNameByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '/';
}

fn validateEntryNames(entries: []const Entry) ZipError!void {
    var names: [max_members][]const u8 = undefined;
    for (entries, 0..) |entry, i| {
        try validateName(entry.name);
        try checkNameCollision(names[0..i], entry.name);
        names[i] = entry.name;
    }
}

fn validateSliceEntryNames(entries: []const SliceEntry) ZipError!void {
    var names: [max_members][]const u8 = undefined;
    for (entries, 0..) |entry, i| {
        try validateName(entry.name);
        try checkNameCollision(names[0..i], entry.name);
        names[i] = entry.name;
    }
}

fn validateExpectedMembers(members: []const ExpectedMember) ZipError!void {
    if (members.len > max_members) return error.TooManyMembers;
    var names: [max_members][]const u8 = undefined;
    var total: u64 = 0;
    for (members, 0..) |member, i| {
        try validateName(member.name);
        try checkNameCollision(names[0..i], member.name);
        names[i] = member.name;
        if (member.size > member.limit) return error.TooLarge;
        total = addBounded(total, member.size) catch return error.TooLarge;
        if (total > max_archive_bytes) return error.TooLarge;
    }
}

fn checkNameCollision(previous: []const []const u8, name: []const u8) ZipError!void {
    for (previous) |other| {
        if (std.mem.eql(u8, other, name)) return error.DuplicateName;
        if (asciiCaseEql(other, name)) return error.NameCollision;
    }
}

fn asciiCaseEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    return true;
}

fn parseAndVerify(bytes: []const u8, expected: []const ExpectedMember) ZipError!void {
    if (bytes.len < eocd_len) return error.Truncated;
    const last_eocd = bytes.len - eocd_len;
    if (!std.mem.eql(u8, bytes[last_eocd..][0..4], &eocd_sig_bytes)) {
        if (std.mem.lastIndexOf(u8, bytes, &eocd_sig_bytes) != null) return error.TrailingBytes;
        return error.InvalidZip;
    }

    const eocd = parseEocd(bytes[last_eocd..][0..eocd_len]);
    if (eocd.comment_len != 0) return error.ArchiveComment;
    if (last_eocd + eocd_len != bytes.len) return error.TrailingBytes;
    if (eocd.disk_number != 0 or eocd.central_directory_disk != 0) return error.DiskUnsupported;
    if (eocd.record_count_disk == 0xffff or eocd.record_count_total == 0xffff or
        eocd.central_size == 0xffffffff or eocd.central_offset == 0xffffffff)
        return error.Zip64;
    if (eocd.record_count_disk != eocd.record_count_total) return error.DiskUnsupported;
    if (eocd.record_count_total > max_members) return error.TooManyMembers;
    if (eocd.record_count_total != expected.len) return error.UnexpectedMemberCount;
    const cd_offset: usize = @intCast(eocd.central_offset);
    const cd_size: usize = @intCast(eocd.central_size);
    if (cd_offset > last_eocd or cd_size > last_eocd - cd_offset) return error.OutOfBounds;
    if (cd_offset + cd_size != last_eocd) {
        if (cd_offset + cd_size + eocd_len <= bytes.len and
            std.mem.eql(u8, bytes[cd_offset + cd_size ..][0..4], &eocd_sig_bytes))
            return error.MultipleEndRecords;
        return error.OutOfBounds;
    }

    var central_pos = cd_offset;
    var local_end: usize = 0;
    var seen: [max_members][]const u8 = undefined;
    var total_uncompressed: u64 = 0;

    for (expected, 0..) |member, i| {
        if (central_pos + central_header_len > last_eocd) return error.Truncated;
        const central = parseCentral(bytes[central_pos..][0..central_header_len]);
        try validateCentralMeta(central);
        if (central.filename_len == 0) return error.InvalidName;
        if (central.extra_len != 0) return error.ExtraField;
        if (central.comment_len != 0) return error.MemberComment;
        if (central.compressed_size == 0xffffffff or central.uncompressed_size == 0xffffffff or
            central.local_offset == 0xffffffff or central.disk_number_start == 0xffff)
            return error.Zip64;
        if (central.compressed_size != central.uncompressed_size) return error.SizeMismatch;
        const central_name_start = central_pos + central_header_len;
        const central_name_end = central_name_start + @as(usize, central.filename_len);
        const central_end = central_name_end + @as(usize, central.extra_len) + @as(usize, central.comment_len);
        if (central_end > last_eocd) return error.Truncated;
        const name = bytes[central_name_start..central_name_end];
        try validateName(name);
        try checkNameCollision(seen[0..i], name);
        seen[i] = name;
        if (!std.mem.eql(u8, name, member.name)) return error.OrderMismatch;
        if (central.uncompressed_size != member.size) return error.SizeMismatch;
        if (member.size > member.limit) return error.TooLarge;
        total_uncompressed = addBounded(total_uncompressed, member.size) catch return error.TooLarge;
        if (total_uncompressed > max_archive_bytes) return error.TooLarge;
        if (central.local_offset != local_end) {
            if (i == 0 and central.local_offset > 0) return error.PrependedBytes;
            if (central.local_offset < local_end) return error.Overlap;
            return error.OutOfBounds;
        }
        local_end = try verifyLocal(bytes, cd_offset, local_end, central, name, member);
        central_pos = central_end;
    }
    if (central_pos != last_eocd) return error.InvalidZip;
    if (local_end != cd_offset) return error.OutOfBounds;
}

fn verifyLocal(
    bytes: []const u8,
    cd_offset: usize,
    local_offset: usize,
    central: Central,
    central_name: []const u8,
    expected: ExpectedMember,
) ZipError!usize {
    if (local_offset + local_header_len > cd_offset) return error.Truncated;
    const local = parseLocal(bytes[local_offset..][0..local_header_len]);
    try validateLocalMeta(local);
    if (local.filename_len == 0) return error.InvalidName;
    if (local.extra_len != 0) return error.ExtraField;
    if (local.compressed_size == 0xffffffff or local.uncompressed_size == 0xffffffff) return error.Zip64;
    if (local.compressed_size != local.uncompressed_size) return error.SizeMismatch;
    if (local.version_needed != central.version_needed or local.flags != central.flags or
        local.method != central.method or local.mod_time != central.mod_time or
        local.mod_date != central.mod_date or local.crc32 != central.crc32 or
        local.compressed_size != central.compressed_size or local.uncompressed_size != central.uncompressed_size)
        return error.HeaderMismatch;
    const name_start = local_offset + local_header_len;
    const name_end = name_start + @as(usize, local.filename_len);
    const data_start = name_end + @as(usize, local.extra_len);
    if (data_start > cd_offset) return error.Truncated;
    const local_name = bytes[name_start..name_end];
    try validateName(local_name);
    if (!std.mem.eql(u8, local_name, central_name)) return error.NameMismatch;
    const data_len: usize = @intCast(local.uncompressed_size);
    if (data_len > cd_offset - data_start) return error.OutOfBounds;
    const data_end = data_start + data_len;
    const data = bytes[data_start..data_end];
    if (Crc32.hash(data) != local.crc32) return error.CrcMismatch;
    if (!std.mem.eql(u8, &sha256(data), &expected.sha256)) return error.DigestMismatch;
    return data_end;
}

fn validateLocalMeta(local: Local) ZipError!void {
    if (local.signature != local_sig) return error.InvalidZip;
    try validateCommonMeta(local.version_needed, local.flags, local.method, local.mod_time, local.mod_date);
}

fn validateCentralMeta(central: Central) ZipError!void {
    if (central.signature != central_sig) return error.InvalidZip;
    if (central.version_made_by != version_made_by) {
        if (@as(u8, @intCast(central.version_made_by >> 8)) != create_system_unix) return error.WrongCreateSystem;
        return error.WrongVersion;
    }
    try validateCommonMeta(central.version_needed, central.flags, central.method, central.mod_time, central.mod_date);
    if (central.disk_number_start != 0) return error.DiskUnsupported;
    if (central.internal_attr != internal_attr) return error.WrongInternalAttributes;
    if (central.external_attr != external_attr_regular_0600) return error.WrongMode;
}

fn validateCommonMeta(needed: u16, gp_flags: u16, method: u16, time: u16, date: u16) ZipError!void {
    if (needed == 0xffff) return error.Zip64;
    if (needed != version_needed) return error.WrongVersion;
    if ((gp_flags & 0x0001) != 0) return error.Encrypted;
    if ((gp_flags & 0x0008) != 0) return error.DataDescriptor;
    if (gp_flags != flags) return error.UnsupportedFlags;
    if (method != method_stored) return error.UnsupportedCompression;
    if (time != dos_time_midnight or date != dos_date_1980_01_01) return error.WrongTimestamp;
}

const Local = struct {
    signature: u32,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    filename_len: u16,
    extra_len: u16,
};

const Central = struct {
    signature: u32,
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    filename_len: u16,
    extra_len: u16,
    comment_len: u16,
    disk_number_start: u16,
    internal_attr: u16,
    external_attr: u32,
    local_offset: u32,
};

const Eocd = struct {
    disk_number: u16,
    central_directory_disk: u16,
    record_count_disk: u16,
    record_count_total: u16,
    central_size: u32,
    central_offset: u32,
    comment_len: u16,
};

fn parseLocal(bytes: []const u8) Local {
    return .{
        .signature = readU32(bytes[0..4]),
        .version_needed = readU16(bytes[4..6]),
        .flags = readU16(bytes[6..8]),
        .method = readU16(bytes[8..10]),
        .mod_time = readU16(bytes[10..12]),
        .mod_date = readU16(bytes[12..14]),
        .crc32 = readU32(bytes[14..18]),
        .compressed_size = readU32(bytes[18..22]),
        .uncompressed_size = readU32(bytes[22..26]),
        .filename_len = readU16(bytes[26..28]),
        .extra_len = readU16(bytes[28..30]),
    };
}

fn parseCentral(bytes: []const u8) Central {
    return .{
        .signature = readU32(bytes[0..4]),
        .version_made_by = readU16(bytes[4..6]),
        .version_needed = readU16(bytes[6..8]),
        .flags = readU16(bytes[8..10]),
        .method = readU16(bytes[10..12]),
        .mod_time = readU16(bytes[12..14]),
        .mod_date = readU16(bytes[14..16]),
        .crc32 = readU32(bytes[16..20]),
        .compressed_size = readU32(bytes[20..24]),
        .uncompressed_size = readU32(bytes[24..28]),
        .filename_len = readU16(bytes[28..30]),
        .extra_len = readU16(bytes[30..32]),
        .comment_len = readU16(bytes[32..34]),
        .disk_number_start = readU16(bytes[34..36]),
        .internal_attr = readU16(bytes[36..38]),
        .external_attr = readU32(bytes[38..42]),
        .local_offset = readU32(bytes[42..46]),
    };
}

fn parseEocd(bytes: []const u8) Eocd {
    if (readU32(bytes[0..4]) != eocd_sig) return .{
        .disk_number = 1,
        .central_directory_disk = 1,
        .record_count_disk = 0,
        .record_count_total = 0,
        .central_size = 0,
        .central_offset = 0,
        .comment_len = 0,
    };
    return .{
        .disk_number = readU16(bytes[4..6]),
        .central_directory_disk = readU16(bytes[6..8]),
        .record_count_disk = readU16(bytes[8..10]),
        .record_count_total = readU16(bytes[10..12]),
        .central_size = readU32(bytes[12..16]),
        .central_offset = readU32(bytes[16..20]),
        .comment_len = readU16(bytes[20..22]),
    };
}

fn writeLocalHeader(out: *CountingWriter, name: []const u8, size: u32, crc: u32) WriteError!void {
    try out.writeU32(local_sig);
    try out.writeU16(version_needed);
    try out.writeU16(flags);
    try out.writeU16(method_stored);
    try out.writeU16(dos_time_midnight);
    try out.writeU16(dos_date_1980_01_01);
    try out.writeU32(crc);
    try out.writeU32(size);
    try out.writeU32(size);
    try out.writeU16(@intCast(name.len));
    try out.writeU16(0);
    try out.writeAll(name);
}

fn writeCentralHeader(out: *CountingWriter, meta: MemberMeta) WriteError!void {
    try out.writeU32(central_sig);
    try out.writeU16(version_made_by);
    try out.writeU16(version_needed);
    try out.writeU16(flags);
    try out.writeU16(method_stored);
    try out.writeU16(dos_time_midnight);
    try out.writeU16(dos_date_1980_01_01);
    try out.writeU32(meta.crc32);
    try out.writeU32(meta.size);
    try out.writeU32(meta.size);
    try out.writeU16(@intCast(meta.name.len));
    try out.writeU16(0);
    try out.writeU16(0);
    try out.writeU16(0);
    try out.writeU16(internal_attr);
    try out.writeU32(external_attr_regular_0600);
    try out.writeU32(meta.local_offset);
    try out.writeAll(meta.name);
}

fn writeEndRecord(out: *CountingWriter, count: u16, central_size: u32, central_offset: u32) WriteError!void {
    try out.writeU32(eocd_sig);
    try out.writeU16(0);
    try out.writeU16(0);
    try out.writeU16(count);
    try out.writeU16(count);
    try out.writeU32(central_size);
    try out.writeU32(central_offset);
    try out.writeU16(0);
}

fn streamEntryData(out: *CountingWriter, entry: Entry, buffer: []u8) WriteError!void {
    var remaining = entry.size;
    var crc = Crc32.init();
    var member_sha = Sha256.init(.{});
    while (remaining > 0) {
        const chunk_len: usize = @intCast(@min(remaining, buffer.len));
        const read = try entry.reader.readSliceShort(buffer[0..chunk_len]);
        if (read == 0) return error.SizeMismatch;
        const chunk = buffer[0..read];
        crc.update(chunk);
        member_sha.update(chunk);
        try out.writeAll(chunk);
        remaining -= read;
    }
    var extra: [1]u8 = undefined;
    if (try entry.reader.readSliceShort(&extra) != 0) return error.SizeMismatch;
    if (crc.final() != entry.crc32) return error.CrcMismatch;
    var actual_sha: [Sha256.digest_length]u8 = undefined;
    member_sha.final(&actual_sha);
    if (!std.mem.eql(u8, &actual_sha, &entry.sha256)) return error.DigestMismatch;
}

const CountingWriter = struct {
    inner: *std.Io.Writer,
    archive_sha: Sha256,
    pos: u64,

    fn init(inner: *std.Io.Writer) CountingWriter {
        return .{ .inner = inner, .archive_sha = Sha256.init(.{}), .pos = 0 };
    }

    fn writeAll(self: *CountingWriter, bytes: []const u8) std.Io.Writer.Error!void {
        try self.inner.writeAll(bytes);
        self.archive_sha.update(bytes);
        self.pos += bytes.len;
    }

    fn writeU16(self: *CountingWriter, value: u16) std.Io.Writer.Error!void {
        var buffer: [2]u8 = undefined;
        std.mem.writeInt(u16, &buffer, value, .little);
        try self.writeAll(&buffer);
    }

    fn writeU32(self: *CountingWriter, value: u32) std.Io.Writer.Error!void {
        var buffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &buffer, value, .little);
        try self.writeAll(&buffer);
    }

    fn final(self: *CountingWriter, out: *[Sha256.digest_length]u8) void {
        self.archive_sha.final(out);
    }
};

fn readU16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .little);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn u32FromPos(pos: u64) ZipError!u32 {
    if (pos > std.math.maxInt(u32)) return error.Zip64;
    return @intCast(pos);
}

fn u32FromU64(value: u64) ZipError!u32 {
    if (value > std.math.maxInt(u32)) return error.Zip64;
    return @intCast(value);
}

fn addBounded(current: u64, item: anytype) ZipError!u64 {
    return std.math.add(u64, current, @as(u64, @intCast(item))) catch error.TooLarge;
}
