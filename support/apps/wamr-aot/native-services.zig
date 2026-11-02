// SPDX-License-Identifier: BSD-3-Clause
//! Translate the existing C adapter's actual capabilities, never Linux shims.
const std = @import("std");
pub const c = @import("workloads_c");

pub const clock_method = "hyperv-reference-monotonic";
pub const clock_resolution_ns: u64 = 100;
pub const wasi_clock_resolutions: [4]u64 = @splat(clock_resolution_ns);
pub const memory_method = "native-vma-owned-4k-data-frames-including-none";

/// Normalizes a raw CPU brand string (such as x86_64 CPUID leaves
/// 0x80000002..0x80000004) using the same token character set as the Linux
/// producer (`[A-Za-z0-9_.:+-]`, replacing any other byte with `'_'` after
/// trimming NUL padding and ASCII whitespace).
pub fn normalizeCpuModelToken(raw: []const u8, out: []u8) []const u8 {
    if (out.len == 0) return "unknown";
    const end = std.mem.indexOfScalar(u8, raw, 0) orelse raw.len;
    const trimmed = std.mem.trim(u8, raw[0..end], " \t\r\n");
    if (trimmed.len == 0) return "unknown";
    const len = @min(trimmed.len, out.len);
    for (trimmed[0..len], 0..) |ch, i| {
        out[i] = if (std.ascii.isAlphanumeric(ch) or std.mem.indexOfScalar(u8, "_.:+-", ch) != null)
            ch
        else
            '_';
    }
    return out[0..len];
}

pub fn cpuidBrandToken(out: *[48]u8) []const u8 {
    if (@import("builtin").cpu.arch != .x86_64) return "unknown";
    const max_leaf = cpuidLeaf(0x80000000);
    if (max_leaf[0] < 0x80000004) return "x86_64";
    var raw: [48]u8 = undefined;
    inline for (.{ 0x80000002, 0x80000003, 0x80000004 }, 0..) |leaf, idx| {
        const regs = cpuidLeaf(leaf);
        inline for (0..4) |reg_idx| {
            std.mem.writeInt(
                u32,
                raw[idx * 16 + reg_idx * 4 ..][0..4],
                regs[reg_idx],
                .little,
            );
        }
    }
    return normalizeCpuModelToken(&raw, out);
}

fn cpuidLeaf(leaf: u32) [4]u32 {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (@as(u32, 0)),
    );
    return .{ eax, ebx, ecx, edx };
}

pub fn Services(comptime aot: type) type {
    return struct {
        const Self = @This();
        config: *const c.wamr_aot_config,
        observed_max_frame_bytes: usize = 0,
        observed_max_reserved_bytes: usize = 0,
        observed_max_allocation_bytes: usize = 0,
        observation_count: usize = 0,

        fn cast(raw: *anyopaque) *Self {
            return @ptrCast(@alignCast(raw));
        }

        pub fn allocator(self: *Self) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{
                .alloc = allocate,
                .resize = std.mem.Allocator.noResize,
                .remap = std.mem.Allocator.noRemap,
                .free = free,
            } };
        }

        fn allocate(raw: *anyopaque, n: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
            const self = cast(raw);
            const config = self.config;
            defer _ = self.pages();
            return @ptrCast(config.alloc.?(config.context, n, alignment.toByteUnits()));
        }

        fn free(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, _: usize) void {
            const self = cast(raw);
            const config = self.config;
            defer _ = self.pages();
            config.free.?(config.context, bytes.ptr, bytes.len, alignment.toByteUnits());
        }

        pub fn platform(self: *Self) aot.Platform {
            return .{ .context = self, .reserve = reserve, .commit = commit, .protect = protect, .unmap = unmap, .monotonic_ns = clock };
        }

        fn reserve(raw: *anyopaque, n: usize) aot.PlatformError![*]align(4096) u8 {
            const self = cast(raw);
            const config = self.config;
            defer _ = self.pages();
            const address = config.reserve.?(config.context, n) orelse return error.OutOfMemory;
            return @ptrCast(@alignCast(address));
        }

        fn commit(raw: *anyopaque, address: [*]align(4096) u8, n: usize) aot.PlatformError!void {
            const self = cast(raw);
            const config = self.config;
            defer _ = self.pages();
            if (config.commit.?(config.context, address, n) != 0) return error.OutOfMemory;
        }

        fn protect(raw: *anyopaque, address: [*]align(4096) u8, n: usize, protection: aot.platform.Protection) aot.PlatformError!void {
            const self = cast(raw);
            const config = self.config;
            defer _ = self.pages();
            const mode: u32 = switch (protection) {
                .none => c.WAMR_AOT_NONE,
                .read_write => c.WAMR_AOT_RW,
                .read_execute => c.WAMR_AOT_RX,
            };
            if (config.protect.?(config.context, address, n, mode) != 0) return error.ProtectionFailed;
        }

        fn unmap(raw: *anyopaque, address: [*]align(4096) u8, n: usize) void {
            const self = cast(raw);
            const config = self.config;
            defer _ = self.pages();
            config.unmap.?(config.context, address, n);
        }

        fn clock(raw: *anyopaque) aot.PlatformError!u64 {
            const config = cast(raw).config;
            var now: u64 = 0;
            if (config.monotonic_ns.?(config.context, &now) != 0 or now == std.math.maxInt(u64))
                return error.ClockFailed;
            return now;
        }

        pub fn pages(self: *Self) c.struct_wamr_workload_pages {
            var result: c.struct_wamr_workload_pages = undefined;
            c.wamr_workload_observe(self.config.context, &result);
            self.observation_count += 1;
            self.observed_max_frame_bytes = @max(self.observed_max_frame_bytes, result.frame_bytes);
            self.observed_max_reserved_bytes = @max(self.observed_max_reserved_bytes, result.reserved_bytes);
            self.observed_max_allocation_bytes = @max(self.observed_max_allocation_bytes, result.allocation_bytes);
            return result;
        }

        pub fn observations(self: *Self) struct {
            after_teardown: c.struct_wamr_workload_pages,
            observed_max_frame_bytes: usize,
            observed_max_reserved_bytes: usize,
            observed_max_allocation_bytes: usize,
            observation_count: usize,
        } {
            const final = self.pages();
            return .{
                .after_teardown = final,
                .observed_max_frame_bytes = self.observed_max_frame_bytes,
                .observed_max_reserved_bytes = self.observed_max_reserved_bytes,
                .observed_max_allocation_bytes = self.observed_max_allocation_bytes,
                .observation_count = self.observation_count,
            };
        }

        pub fn benchmarkPages(self: *Self, comptime bench: type) bench.Pages {
            const Adapter = struct {
                fn sample(raw: ?*anyopaque) anyerror!bench.Footprint {
                    const s = cast(raw orelse return error.InvalidContext);
                    const current = s.pages();
                    return .{
                        .reserved_address_bytes = current.reserved_bytes,
                        .retained_committed_bytes = current.frame_bytes,
                    };
                }
            };
            return .{
                .context = self,
                .method = memory_method,
                .sample = Adapter.sample,
            };
        }

        pub fn benchmarkClock(self: *Self, comptime bench: type) bench.Clock {
            const Adapter = struct {
                fn read(raw: ?*anyopaque, _: bench.wasi.ClockId, _: u64) bench.wasi.ClockResult {
                    const s = cast(raw orelse return .{ .failure = .inval });
                    return .{ .timestamp_ns = s.platform().monotonicNs() catch return .{ .failure = .overflow } };
                }
            };
            return .{
                .source = clock_method,
                .resolution_ns = clock_resolution_ns,
                .wasi_clock = .{
                    .userdata = self,
                    .read = Adapter.read,
                    .resolution_ns = wasi_clock_resolutions,
                },
            };
        }
    };
}

pub fn transmit(writer: *std.Io.Writer) !void {
    const bytes = writer.buffered();
    if (c.wamr_workload_write(bytes.ptr, bytes.len) != 0) return error.SerialWriteFailed;
    writer.end = 0;
}

pub fn writeJson(writer: *std.Io.Writer, marker: []const u8, value: anytype) !void {
    try writer.writeAll(marker);
    try std.json.Stringify.value(value, .{}, writer);
    try writer.writeByte('\n');
    try transmit(writer);
}

pub fn identify(bytes: []const u8, storage: *[64]u8) []const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    storage.* = std.fmt.bytesToHex(hash, .lower);
    return storage;
}

pub fn factsRecord(writer: *std.Io.Writer, facts: *const c.struct_wamr_workload_facts, variant: []const u8, observations: anytype) !void {
    try writeJson(writer, "WAMR_NATIVE_WORKLOAD_BUILD=", .{
        .version = 1,
        .correctness_only = true,
        .variant = variant,
        .wamr_revision = std.mem.span(facts.revision),
        .source_tree_sha256 = std.mem.span(facts.source_tree_sha256),
        .runtime_sha256 = std.mem.span(facts.runtime_sha256),
        .compiler_sha256 = std.mem.span(facts.compiler_sha256),
        .clock = .{ .method = "hyperv-reference-monotonic", .resolution_ns = 100 },
        .memory_method = "native-vma-owned-4k-data-frames-including-none",
        .memory_coverage = "code-and-linear-pages-only",
        .excludes = .{ "allocator-backing", "image", "native-stack", "page-tables", "other-kernel-allocations" },
        .allocator_quantity = "caller-and-adapter-requested-bytes-not-backing",
        .sampling = "callback-boundaries-observed-max-not-peak",
        .memory = observations,
    });
}
