//! Process-local sampling for synthetic fixtures, not execution or authority proof.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Sample = struct {
    backend: std.builtin.CompilerBackend,
    arch: std.Target.Cpu.Arch,
    optimize: std.builtin.OptimizeMode,
    aarch64_sha2: bool,
    x86_sha: bool,
    x86_avx2: bool,
    monotonic_ns: u64,
    process_cpu_ns: u64,
};

pub fn capture() !Sample {
    return .{
        .backend = builtin.zig_backend,
        .arch = builtin.cpu.arch,
        .optimize = builtin.mode,
        .aarch64_sha2 = builtin.cpu.arch == .aarch64 and builtin.cpu.has(.aarch64, .sha2),
        .x86_sha = builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .sha),
        .x86_avx2 = builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .avx2),
        .monotonic_ns = try clock(.MONOTONIC),
        .process_cpu_ns = try clock(.PROCESS_CPUTIME_ID),
    };
}

fn clock(id: linux.clockid_t) !u64 {
    var timestamp: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(id, &timestamp)) != .SUCCESS or timestamp.sec < 0 or
        timestamp.nsec < 0 or timestamp.nsec >= std.time.ns_per_s) return error.DiagnosticClockUnavailable;
    return std.math.add(u64, try std.math.mul(u64, @intCast(timestamp.sec), std.time.ns_per_s), @intCast(timestamp.nsec));
}

pub fn selfExecutableBytes(io: std.Io) !u64 {
    const file = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.size == 0) return error.InvalidDiagnosticExecutable;
    return stat.size;
}
