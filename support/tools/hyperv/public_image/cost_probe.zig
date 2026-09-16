//! Bounded observations of fresh synthetic files, never admission or a guest boot.
const std = @import("std");
const image = @import("public_image");
const measurement = @import("synthetic_measurement");
const options = @import("test_options");
const fixtures = @import("import_fixture.zig");
const Phase = enum {
    entry,
    package_begin,
    package_end,
    raw_digest_begin,
    raw_digest_end,
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
        .sample = try measurement.capture(),
    }, .{}, &writer);
    std.debug.print("public-image synthetic cost: {s}\n", .{writer.buffered()});
}

fn digest(io: std.Io, path: []const u8, begin: Phase, end: Phase) !void {
    const file = try image.core.private_files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const before = try image.core.private_files.snapshot(file);
    try mark(io, begin, before.size);
    const sha = try image.boot.files.digest(io, file, before);
    try mark(io, end, before.size);
    std.debug.print("public-image synthetic digest: phase={s} sha256={s}\n", .{ @tagName(end), std.fmt.bytesToHex(sha, .lower) });
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
    try digest(io, raw, .raw_digest_begin, .raw_digest_end);
    try digest(io, qemu, .qemu_digest_begin, .qemu_digest_end);
    try digest(io, cli, .producer_digest_begin, .producer_digest_end);
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
