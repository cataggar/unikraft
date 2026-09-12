const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");

pub const total_limit = c.total_cap;
pub const control_limit = c.control_cap;
pub const maximum_entries = 256;

pub const Role = enum {
    raw,
    vhd,
    boot_disk,
    qemu,
    qemu_support,
    firmware_code,
    firmware_vars,
    firmware_working_copy,
    native_control,
    producer_control,
    publication_control,
    publication_reservation,
    baked_control,
    evidence,

    pub fn isControl(self: Role) bool {
        return switch (self) {
            .native_control, .producer_control, .publication_control, .publication_reservation, .baked_control => true,
            else => false,
        };
    }
};

/// Each physical copy/staging destination has its own id and artifact path.
/// Sharing source bytes never exempts a copy, including baked host controls.
pub const Entry = struct {
    id: []const u8,
    role: Role,
    artifact: []const u8,
    source: ?c.File,
    reserved: u64,
};

pub const Totals = struct {
    used: u64,
    control: u64,
    reserved: u64,
    total_remaining: u64,
};

fn validateEntry(entry: Entry) !void {
    try c.relative(entry.id);
    try c.relative(entry.artifact);
    if (entry.id.len > 128) return error.InvalidLedgerEntry;
    if (entry.role == .evidence or entry.role == .publication_reservation) {
        if (entry.source != null or entry.reserved == 0) return error.InvalidLedgerEntry;
    } else {
        const source = entry.source orelse return error.MissingByteBinding;
        try c.relative(source.path);
        _ = try c.sha(&source.sha256);
        if (entry.reserved != 0 or source.size == 0 or source.mode & 0o7022 != 0 or
            source.mode & ~@as(u16, 0o7777) != 0)
            return error.InvalidLedgerEntry;
    }
}

/// Arithmetic only: admission must also check the caller's complete closure
/// with validateLedger, or use recompute to remeasure its descriptor-bound files.
pub fn compute(entries: []const Entry) !Totals {
    if (entries.len == 0 or entries.len > maximum_entries) return error.InvalidLedgerCount;
    var totals: Totals = .{ .used = 0, .control = 0, .reserved = 0, .total_remaining = 0 };
    for (entries, 0..) |entry, i| {
        try validateEntry(entry);
        for (entries[0..i]) |previous| {
            if (std.mem.eql(u8, entry.id, previous.id)) return error.DuplicateLedgerId;
            if (std.mem.eql(u8, entry.artifact, previous.artifact)) return error.DuplicateLedgerArtifact;
        }
        if (entry.source) |source| {
            totals.used = try std.math.add(u64, totals.used, source.size);
            if (entry.role.isControl()) totals.control = try std.math.add(u64, totals.control, source.size);
        } else {
            totals.reserved = try std.math.add(u64, totals.reserved, entry.reserved);
            if (entry.role.isControl()) totals.control = try std.math.add(u64, totals.control, entry.reserved);
        }
    }
    const total = try std.math.add(u64, totals.used, totals.reserved);
    if (totals.control > control_limit) return error.ControlLimitExceeded;
    if (total > total_limit) return error.LimitExceeded;
    totals.total_remaining = total_limit - total;
    return totals;
}

fn find(entries: []const Entry, id: []const u8) ?Entry {
    for (entries) |entry| if (std.mem.eql(u8, entry.id, id)) return entry;
    return null;
}

fn requireEntry(actual: Entry, expected: Entry) !void {
    if (!std.mem.eql(u8, actual.id, expected.id) or actual.role != expected.role or
        !std.mem.eql(u8, actual.artifact, expected.artifact) or actual.reserved != expected.reserved)
        return error.LedgerClosureMismatch;
    if (actual.source) |source| {
        try fs.requireFile(source, expected.source orelse return error.LedgerClosureMismatch);
    } else if (expected.source != null) return error.LedgerClosureMismatch;
}

/// expected is the caller's independently assembled, complete artifact closure,
/// not a list copied from the receipt being admitted. Order is immaterial.
pub fn validateLedger(entries: []const Entry, expected: []const Entry) !Totals {
    _ = try compute(expected);
    const totals = try compute(entries);
    if (entries.len != expected.len) return error.LedgerClosureMismatch;
    for (expected) |entry| try requireEntry(
        find(entries, entry.id) orelse return error.LedgerClosureMismatch,
        entry,
    );
    return totals;
}

/// Allocations, including strings in returned entries, may be arena-scoped.
pub fn record(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: fs.Directory,
    id: []const u8,
    role: Role,
    artifact: []const u8,
    source_path: []const u8,
) !Entry {
    if (role == .evidence or role == .publication_reservation) return error.InvalidLedgerEntry;
    const entry: Entry = .{
        .id = try allocator.dupe(u8, id),
        .role = role,
        .artifact = try allocator.dupe(u8, artifact),
        .source = try directory.record(allocator, io, source_path, total_limit, .artifact),
        .reserved = 0,
    };
    try validateEntry(entry);
    return entry;
}

/// A reservation has no invented hash for evidence that has not yet been made.
pub fn reserve(id: []const u8, artifact: []const u8, bytes: u64) !Entry {
    const entry: Entry = .{ .id = id, .role = .evidence, .artifact = artifact, .source = null, .reserved = bytes };
    try validateEntry(entry);
    return entry;
}

pub const Binding = struct {
    id: []const u8,
    directory: fs.Directory,
};

/// Recompute, rather than trust serialized totals or source sizes/hashes.
/// Exactly one trusted source-directory binding is required per non-reservation
/// logical id; copies of the same source must each remain in the closure.
pub fn recompute(
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: []const Entry,
    expected: []const Entry,
    bindings: []const Binding,
) !Totals {
    _ = try validateLedger(entries, expected);
    if (bindings.len > maximum_entries) return error.InvalidLedgerCount;
    var actual: [maximum_entries]Entry = undefined;
    var bound_count: usize = 0;
    for (expected, 0..) |entry, i| {
        actual[i] = entry;
        const source = entry.source orelse continue;
        var directory: ?fs.Directory = null;
        for (bindings) |binding| {
            if (std.mem.eql(u8, binding.id, entry.id)) {
                if (directory != null) return error.DuplicateLedgerId;
                directory = binding.directory;
            }
        }
        const observed = try (directory orelse return error.MissingByteBinding).record(
            allocator,
            io,
            source.path,
            total_limit,
            .artifact,
        );
        try fs.requireFile(observed, source);
        actual[i].source = observed;
        bound_count += 1;
    }
    if (bound_count != bindings.len) return error.LedgerClosureMismatch;
    return validateLedger(actual[0..expected.len], expected);
}

fn fixture(id: []const u8, role: Role, bytes: u64) Entry {
    return .{
        .id = id,
        .role = role,
        .artifact = id,
        .source = .{ .path = id, .sha256 = c.digest("public synthetic bytes"), .size = bytes, .mode = 0o600 },
        .reserved = 0,
    };
}

test "budget includes baked producer publication controls and every copy" {
    var entries = [_]Entry{
        fixture("raw", .raw, c.image_bytes),
        fixture("qemu", .qemu, 4096),
        fixture("support", .qemu_support, 512),
        fixture("code", .firmware_code, 4096),
        fixture("vars", .firmware_vars, 4096),
        fixture("vars-working", .firmware_working_copy, 4096),
        fixture("native", .native_control, 1024),
        fixture("producer", .producer_control, 512),
        fixture("publication", .publication_control, 512),
        fixture("baked", .baked_control, 1024),
        try reserve("evidence", "evidence", 8192),
    };
    entries[5].source = entries[4].source;
    entries[9].source = entries[6].source;
    const totals = try validateLedger(&entries, &entries);
    try std.testing.expectEqual(@as(u64, 3072), totals.control);
    try std.testing.expectEqual(c.image_bytes + 19968, totals.used);
    try std.testing.expectEqual(@as(u64, 8192), totals.reserved);
    try std.testing.expectEqual(total_limit - totals.used - totals.reserved, totals.total_remaining);
}

test "budget accepts exact limits and rejects one byte beyond either cap" {
    try std.testing.expectEqual(@as(u64, 8388608), control_limit);
    try std.testing.expectEqual(@as(u64, 268435456), total_limit);
    var entries = [_]Entry{
        fixture("raw", .raw, total_limit - control_limit - 1),
        fixture("native", .native_control, control_limit),
        try reserve("evidence", "evidence", 1),
    };
    try std.testing.expectEqual(@as(u64, 0), (try compute(&entries)).total_remaining);
    entries[0].source.?.size += 1;
    try std.testing.expectError(error.LimitExceeded, compute(&entries));
    entries[0].source.?.size -= 2;
    entries[1].source.?.size += 1;
    try std.testing.expectError(error.ControlLimitExceeded, compute(&entries));
}

test "budget rejects arithmetic overflow in charged reserved and combined bytes" {
    var entries = [_]Entry{
        fixture("first", .raw, std.math.maxInt(u64)),
        fixture("second", .boot_disk, 1),
    };
    try std.testing.expectError(error.Overflow, compute(&entries));
    entries[0] = try reserve("first", "first", std.math.maxInt(u64));
    entries[1] = try reserve("second", "second", 1);
    try std.testing.expectError(error.Overflow, compute(&entries));
    entries[1] = fixture("second", .raw, 1);
    try std.testing.expectError(error.Overflow, compute(&entries));
}

test "budget rejects duplicate ids artifacts zero records and excessive entries" {
    var entries = [_]Entry{ fixture("one", .raw, 1), fixture("one", .raw, 1) };
    try std.testing.expectError(error.DuplicateLedgerId, compute(&entries));
    entries[1].id = "two";
    try std.testing.expectError(error.DuplicateLedgerArtifact, compute(&entries));
    entries[1].artifact = "two";
    entries[1].source.?.size = 0;
    try std.testing.expectError(error.InvalidLedgerEntry, compute(&entries));
    entries[1].source = null;
    try std.testing.expectError(error.MissingByteBinding, compute(&entries));
    try std.testing.expectError(error.InvalidLedgerCount, compute(&.{}));
    const excessive = [_]Entry{fixture("one", .raw, 1)} ** (maximum_entries + 1);
    try std.testing.expectError(error.InvalidLedgerCount, compute(&excessive));
    try std.testing.expectError(error.InvalidLedgerEntry, reserve("evidence", "evidence", 0));
}

test "budget closure rejects omitted or relabeled controls and changed byte bindings" {
    const expected = [_]Entry{
        fixture("raw", .raw, c.image_bytes),
        fixture("native", .native_control, 1),
        fixture("producer", .producer_control, 1),
        fixture("publication", .publication_control, 1),
        fixture("baked", .baked_control, 1),
    };
    for (1..expected.len) |omitted| {
        var partial: [expected.len - 1]Entry = undefined;
        var next: usize = 0;
        for (expected, 0..) |entry, i| {
            if (i == omitted) continue;
            partial[next] = entry;
            next += 1;
        }
        try std.testing.expectError(error.LedgerClosureMismatch, validateLedger(&partial, &expected));
    }
    var changed = expected;
    changed[4].role = .qemu_support;
    try std.testing.expectError(error.LedgerClosureMismatch, validateLedger(&changed, &expected));
    changed = expected;
    changed[3].source.?.sha256 = c.digest("different public synthetic bytes");
    try std.testing.expectError(error.HashMismatch, validateLedger(&changed, &expected));
    changed = expected;
    changed[2].source.?.size += 1;
    try std.testing.expectError(error.HashMismatch, validateLedger(&changed, &expected));
}

test "budget admission remeasures actual synthetic bytes instead of trusting receipt sizes and hashes" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture_dir = std.testing.tmpDir(.{ .iterate = true });
    defer fixture_dir.cleanup();
    try fixture_dir.dir.setPermissions(io, .fromMode(0o700));
    const file = try fixture_dir.dir.createFile(io, "control", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, "public fixture", 0);
    try file.sync(io);
    const directory: fs.Directory = .{ .dir = fixture_dir.dir, .path = "" };
    const entries = [_]Entry{
        try record(allocator, io, directory, "baked", .baked_control, "host/control", "control"),
        try record(allocator, io, directory, "staged", .publication_control, "staging/control", "control"),
        try reserve("evidence", "evidence", 1),
    };
    const bindings = [_]Binding{
        .{ .id = "baked", .directory = directory },
        .{ .id = "staged", .directory = directory },
    };
    const totals = try recompute(allocator, io, &entries, &entries, &bindings);
    try std.testing.expectEqual(@as(u64, 28), totals.used);
    try std.testing.expectEqual(@as(u64, 28), totals.control);
    try std.testing.expectError(error.MissingByteBinding, recompute(allocator, io, &entries, &entries, bindings[0..1]));
    try file.writePositionalAll(io, "changed bytes!", 0);
    try file.sync(io);
    try std.testing.expectError(error.HashMismatch, recompute(allocator, io, &entries, &entries, &bindings));
}

test "approved eight MiB controls remeasure copies and reservations inside the unchanged total" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture_dir = std.testing.tmpDir(.{ .iterate = true });
    defer fixture_dir.cleanup();
    try fixture_dir.dir.setPermissions(io, .fromMode(0o700));
    const file = try fixture_dir.dir.createFile(io, "public-control", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    try file.setLength(io, 3 * 1024 * 1024);
    try file.sync(io);
    const directory: fs.Directory = .{ .dir = fixture_dir.dir, .path = "" };
    const entries = [_]Entry{
        try record(allocator, io, directory, "producer", .producer_control, "staging/producer", "public-control"),
        try record(allocator, io, directory, "baked", .baked_control, "image/producer", "public-control"),
        .{ .id = "publication", .role = .publication_reservation, .artifact = "publication", .source = null, .reserved = 2 * 1024 * 1024 },
    };
    const bindings = [_]Binding{
        .{ .id = "producer", .directory = directory },
        .{ .id = "baked", .directory = directory },
    };
    const totals = try recompute(allocator, io, &entries, &entries, &bindings);
    try std.testing.expectEqual(@as(u64, 6 * 1024 * 1024), totals.used);
    try std.testing.expectEqual(@as(u64, 8388608), totals.control);
    try std.testing.expectEqual(@as(u64, 268435456 - 8388608), totals.total_remaining);
    var changed = entries;
    changed[2].reserved += 1;
    try std.testing.expectError(error.ControlLimitExceeded, recompute(allocator, io, &changed, &entries, &bindings));
    changed = entries;
    changed[1].role = .qemu_support;
    try std.testing.expectError(error.LedgerClosureMismatch, recompute(allocator, io, &changed, &entries, &bindings));
    try std.testing.expectError(error.MissingByteBinding, recompute(allocator, io, &entries, &entries, bindings[0..1]));
}
