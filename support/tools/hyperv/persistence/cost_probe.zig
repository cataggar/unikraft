//! Measurements of the actual selected synthetic worker, never authority.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const transfer = @import("hyperv_transfer");
const local = @import("local.zig");
const measurement = @import("synthetic_measurement");
const options = @import("test_options");
const Phase = enum { entry, selection_begin, selection_end, dirty_selection_begin, dirty_selection_end, seal_begin, seal_end, verify_begin, verify_end };

fn mark(io: std.Io, phase: Phase, bytes: u64, checks: usize) !void {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(.{
        .schema_version = @as(u8, 1),
        .scope = "synthetic_observation_only",
        .authority = "none",
        .phase = phase,
        .worker_bytes = bytes,
        .guard_checks = checks,
        .cpu_model = builtin.cpu.model.name,
        .self_bytes = try measurement.selfExecutableBytes(io),
        .sample = try measurement.capture(),
    }, .{}, &writer);
    std.debug.print("persistence synthetic cost: {s}\n", .{writer.buffered()});
}

const Guard = struct {
    checks: usize = 0,
    fn check(context: *anyopaque) !void {
        const self: *Guard = @ptrCast(@alignCast(context));
        self.checks += 1;
    }
    fn guard(self: *Guard) transfer.files.Guard {
        return .{ .context = self, .checkFn = check };
    }
};

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    try mark(io, .entry, 0, 0);
    const path = try std.Io.Dir.cwd().realPathFileAlloc(io, options.worker, a);
    const file = try core.private_files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const before = try core.private_files.snapshot(file);
    if (before.size == 0 or before.size > 32 * 1024 * 1024) return error.InvalidSyntheticWorker;
    const bytes = try a.alloc(u8, @intCast(before.size));
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.InputChanged;
    var extra: [1]u8 = undefined;
    if (try file.readPositionalAll(io, &extra, before.size) != 0 or
        !core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.InputChanged;
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &expected, .{});
    var expected_md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &expected_md5, .{});
    try mark(io, .selection_begin, before.size, 0);
    const selected = try core.contracts.parseSha256(&local.hash(bytes));
    try mark(io, .selection_end, before.size, 0);
    try mark(io, .dirty_selection_begin, before.size, 0);
    if (comptime builtin.cpu.arch == .x86_64 and builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }))
        asm volatile ("vpcmpeqd %%ymm0, %%ymm0, %%ymm0" ::: .{ .ymm0 = true });
    const dirty_selected = try core.contracts.parseSha256(&local.hash(bytes));
    try mark(io, .dirty_selection_end, before.size, 0);
    if (!std.mem.eql(u8, &expected, &selected) or !std.mem.eql(u8, &expected, &dirty_selected))
        return error.DigestMismatch;
    // Observe each real hash guard; this probe neither executes a worker nor
    // replaces the unchanged operation deadline exercised by the full suite.
    var guard: Guard = .{};
    try mark(io, .seal_begin, before.size, guard.checks);
    const sealed = try transfer.files.SealedInput.open(io, .{ .path = path, .size = before.size, .sha256 = selected }, guard.guard());
    defer sealed.close();
    try mark(io, .seal_end, before.size, guard.checks);
    if (!std.mem.eql(u8, &sealed.fingerprint.sha256, &expected) or
        !std.mem.eql(u8, &sealed.fingerprint.md5, &expected_md5)) return error.DigestMismatch;
    try mark(io, .verify_begin, before.size, guard.checks);
    try sealed.verify(guard.guard());
    try mark(io, .verify_end, before.size, guard.checks);
    std.debug.print("persistence synthetic digest: sha256={s} md5={s}\n", .{
        std.fmt.bytesToHex(expected, .lower), std.fmt.bytesToHex(expected_md5, .lower),
    });
}
