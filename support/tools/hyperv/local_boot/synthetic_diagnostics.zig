const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const linux = std.os.linux;

pub const enabled = builtin.is_test or (@hasDecl(@import("root"), "local_boot_synthetic_diagnostics") and
    @import("root").local_boot_synthetic_diagnostics);
pub const file_name = "synthetic-local-boot-phases-v1";
pub const slot_size = 512;
pub const Phase = enum {
    artifact_hash_begin,
    artifact_hash_end,
    firmware_copy_begin,
    firmware_copy_end,
    final_verify_begin,
    final_verify_end,
    exec_handoff,
    mock_entry,
};
pub const slot_count = @typeInfo(Phase).@"enum".fields.len;
pub const max_bytes = slot_count * slot_size;
pub const max_log_bytes = max_bytes + 256;

pub const Record = struct {
    schema_version: u8 = 1,
    scope: enum { synthetic_observation_only } = .synthetic_observation_only,
    authority: enum { none } = .none,
    phase: Phase,
    backend: std.builtin.CompilerBackend,
    arch: std.Target.Cpu.Arch,
    optimize: std.builtin.OptimizeMode,
    aarch64_sha2: bool,
    x86_sha: bool,
    x86_avx2: bool,
    fixture_bytes: u64,
    monotonic_ns: u64,
    process_cpu_ns: u64,

    pub fn observe(phase: Phase, fixture_bytes: u64) !Record {
        return .{
            .phase = phase,
            .backend = builtin.zig_backend,
            .arch = builtin.cpu.arch,
            .optimize = builtin.mode,
            .aarch64_sha2 = builtin.cpu.arch == .aarch64 and builtin.cpu.has(.aarch64, .sha2),
            .x86_sha = builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .sha),
            .x86_avx2 = builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .avx2),
            .fixture_bytes = fixture_bytes,
            .monotonic_ns = try clock(.MONOTONIC),
            .process_cpu_ns = try clock(.PROCESS_CPUTIME_ID),
        };
    }

    pub fn encode(self: Record) ![slot_size]u8 {
        if (self.schema_version != 1 or self.fixture_bytes == 0) return error.InvalidDiagnostic;
        var slot = [_]u8{0} ** slot_size;
        var writer: std.Io.Writer = .fixed(&slot);
        try std.json.Stringify.value(self, .{}, &writer);
        try writer.writeByte('\n');
        return slot;
    }
};

fn clock(id: linux.clockid_t) !u64 {
    var timestamp: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(id, &timestamp)) != .SUCCESS or timestamp.sec < 0 or
        timestamp.nsec < 0 or timestamp.nsec >= std.time.ns_per_s) return error.DiagnosticClockUnavailable;
    return std.math.add(u64, try std.math.mul(u64, @intCast(timestamp.sec), std.time.ns_per_s), @intCast(timestamp.nsec));
}

// Fixed slots preserve a complete prefix if termination interrupts a write.
// These writes deliberately do not add fsyncs or claim crash-durable evidence.
pub const Trace = struct {
    file: std.Io.File,
    fixture_bytes: u64,
    next: usize = 0,

    pub fn create(io: std.Io, work: core.private_files.Directory, fixture_bytes: u64) !Trace {
        if (!enabled) @compileError("Synthetic diagnostics require a dedicated fixture root");
        if (fixture_bytes == 0) return error.InvalidDiagnostic;
        const file = try work.dir.createFile(io, file_name, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        return .{ .file = file, .fixture_bytes = fixture_bytes };
    }

    pub fn mark(self: *Trace, io: std.Io, comptime phase: Phase) !void {
        if (!enabled) @compileError("Synthetic diagnostics require a dedicated fixture root");
        if (phase == .mock_entry) @compileError("Mock entry is recorded by the separately exec'd fixture");
        if (@intFromEnum(phase) != self.next) return error.DiagnosticPhaseOrder;
        const slot = try (try Record.observe(phase, self.fixture_bytes)).encode();
        try self.file.writePositionalAll(io, &slot, self.next * slot_size);
        self.next += 1;
    }

    pub fn close(self: Trace, io: std.Io) void {
        self.file.close(io);
    }
};

pub fn mockEntry(io: std.Io, work: core.private_files.Directory) !void {
    if (!enabled) @compileError("Synthetic diagnostics require a dedicated fixture root");
    const executable = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});
    defer executable.close(io);
    const record = try Record.observe(.mock_entry, (try core.private_files.snapshot(executable)).size);
    // openFile validates private ownership/type first; the second descriptor is
    // compared before any write and never follows a final-component symlink.
    const checked = try work.openFile(io, file_name);
    defer checked.close(io);
    const before = try core.private_files.snapshot(checked);
    const offset = @as(usize, @intFromEnum(Phase.mock_entry)) * slot_size;
    if (before.size != offset) return error.DiagnosticPhaseOrder;
    const opened = linux.openat(work.dir.handle, file_name, .{
        .ACCMODE = .WRONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.DiagnosticOpenFailed;
    const file: std.Io.File = .{ .handle = @intCast(opened), .flags = .{ .nonblocking = true } };
    defer file.close(io);
    if (!core.private_files.sameSnapshot(before, try core.private_files.snapshot(file))) return error.DiagnosticChanged;
    const slot = try record.encode();
    try file.writePositionalAll(io, &slot, offset);
}

pub const Observation = struct {
    records: [slot_count]Record = undefined,
    count: usize = 0,
    tail: enum { aligned_prefix, partial_slot, invalid_slot } = .aligned_prefix,

    pub fn slice(self: *const Observation) []const Record {
        return self.records[0..self.count];
    }
};

pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Observation {
    if (bytes.len > max_bytes) return error.DiagnosticTooLarge;
    var result: Observation = .{};
    if (bytes.len % slot_size != 0) result.tail = .partial_slot;
    for (0..bytes.len / slot_size) |index| {
        const slot = bytes[index * slot_size ..][0..slot_size];
        const parsed = std.json.parseFromSlice(Record, a, std.mem.trimEnd(u8, slot, "\x00"), .{
            .ignore_unknown_fields = false,
        }) catch {
            result.tail = .invalid_slot;
            break;
        };
        defer parsed.deinit();
        const record = parsed.value;
        const canonical = record.encode() catch {
            result.tail = .invalid_slot;
            break;
        };
        if (@intFromEnum(record.phase) != index or !std.mem.eql(u8, slot, &canonical) or
            (index != 0 and (record.monotonic_ns < result.records[index - 1].monotonic_ns or
                record.process_cpu_ns < result.records[index - 1].process_cpu_ns or
                record.fixture_bytes != result.records[0].fixture_bytes)))
        {
            result.tail = .invalid_slot;
            break;
        }
        result.records[index] = record;
        result.count += 1;
    }
    return result;
}

pub fn read(a: std.mem.Allocator, io: std.Io, work: core.private_files.Directory) !Observation {
    const bytes = try work.read(io, a, file_name, max_bytes, null);
    defer a.free(bytes);
    return decode(a, bytes);
}
