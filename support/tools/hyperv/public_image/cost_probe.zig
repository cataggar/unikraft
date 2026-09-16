//! Bounded observations of fresh synthetic files, never admission or a guest boot.
const std = @import("std");
const builtin = @import("builtin");
const image = @import("public_image");
const measurement = @import("synthetic_measurement");
const options = @import("test_options");
const fixtures = @import("import_fixture.zig");
extern fn hyperv_public_cost_clear_upper() callconv(.c) void;
const Phase = enum {
    entry,
    package_begin,
    package_end,
    raw_digest_begin,
    raw_digest_end,
    raw_clear_upper_digest_begin,
    raw_clear_upper_digest_end,
    qemu_digest_begin,
    qemu_digest_end,
    producer_digest_begin,
    producer_digest_end,
    child_open_begin,
    child_open_end,
    child_verify_begin,
    child_verify_end,
};

fn mark(io: std.Io, phase: Phase, bytes: u64) !void {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(.{
        .schema_version = @as(u8, 1),
        .scope = "synthetic_observation_only",
        .authority = "none",
        .phase = phase,
        .bytes = bytes,
        .self_bytes = try measurement.selfExecutableBytes(io),
        .cpu_model = builtin.cpu.model.name,
        .sample = try measurement.capture(),
    }, .{}, &writer);
    std.debug.print("public-image synthetic cost: {s}\n", .{writer.buffered()});
}

fn digest(io: std.Io, path: []const u8, begin: Phase, end: Phase) ![32]u8 {
    const file = try image.core.private_files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const before = try image.core.private_files.snapshot(file);
    try mark(io, begin, before.size);
    const sha = try image.boot.files.digest(io, file, before);
    try mark(io, end, before.size);
    std.debug.print("public-image synthetic digest: phase={s} sha256={s}\n", .{ @tagName(end), std.fmt.bytesToHex(sha, .lower) });
    return sha;
}

fn clearedDigest(io: std.Io, path: []const u8, expected: [32]u8) !void {
    const p = image.core.private_files;
    const file = try p.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const before = try p.snapshot(file);
    try mark(io, .raw_clear_upper_digest_begin, before.size);
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [32768]u8 = undefined;
    var position: u64 = 0;
    while (position < before.size) {
        const length: usize = @intCast(@min(buffer.len, before.size - position));
        if (try file.readPositionalAll(io, buffer[0..length], position) != length) return error.ArtifactChanged;
        if (comptime builtin.cpu.arch == .x86_64 and builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 })) {
            hyperv_public_cost_clear_upper();
        }
        sha.update(buffer[0..length]);
        position += length;
    }
    if (try file.readPositionalAll(io, buffer[0..1], position) != 0 or
        !p.sameSnapshot(before, try p.snapshot(file))) return error.ArtifactChanged;
    const actual = sha.finalResult();
    if (!std.mem.eql(u8, &actual, &expected)) return error.DigestMismatch;
    try mark(io, .raw_clear_upper_digest_end, before.size);
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    try mark(io, .entry, 0);
    try mark(io, .package_begin, image.contracts.vhd_bytes);
    const f = try fixtures.Fixture.init(a, io, options.test_root orelse return error.MissingFixtureRoot);
    defer f.deinit(a);
    try mark(io, .package_end, image.contracts.vhd_bytes);
    const raw = try image.files.path(a, f.path, "package/unikraft.raw");
    const qemu = try std.Io.Dir.cwd().realPathFileAlloc(io, options.fixture, a);
    const cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, a);
    const raw_sha = try digest(io, raw, .raw_digest_begin, .raw_digest_end);
    try clearedDigest(io, raw, raw_sha);
    _ = try digest(io, qemu, .qemu_digest_begin, .qemu_digest_end);
    _ = try digest(io, cli, .producer_digest_begin, .producer_digest_end);
    try f.dir.dir.writeFile(io, .{ .sub_path = "code.fd", .data = "synthetic firmware", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    try f.dir.dir.writeFile(io, .{ .sub_path = "vars.fd", .data = "synthetic variables", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    const config: image.boot.config.Config = .{
        .raw_disk = raw,
        .qemu = qemu,
        .ovmf_code = try image.files.path(a, f.path, "code.fd"),
        .ovmf_vars = try image.files.path(a, f.path, "vars.fd"),
        .work_dir = f.path,
        .expect = image.contracts.platform_marker,
    };
    try mark(io, .child_open_begin, image.contracts.raw_bytes);
    const set = try image.boot.files.Set.open(io, config);
    defer set.close(io);
    try mark(io, .child_open_end, image.contracts.raw_bytes);
    try mark(io, .child_verify_begin, image.contracts.raw_bytes);
    try set.verify(io, config);
    try mark(io, .child_verify_end, image.contracts.raw_bytes);
}
