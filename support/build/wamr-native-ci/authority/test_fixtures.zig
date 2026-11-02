// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = @import("contracts.zig");
const types = @import("types.zig");
const records = @import("records.zig");
const runtime_copy = @import("runtime_copy.zig");
const linux = std.os.linux;

pub fn goldenRecord(a: std.mem.Allocator, name: []const u8) ![]const u8 {
    if (!@import("builtin").is_test) @compileError("Authority fixtures are test-only");
    var golden = try contracts.parseCanonical(a, @embedFile("goldens/contracts.json"));
    defer golden.deinit();
    const bytes = golden.value().object.get("canonical_records").?.object.get(name).?.string;
    var record = try contracts.parseCanonical(a, bytes);
    defer record.deinit();
    const allocator = record.parsed.arena.allocator();
    const root = &record.parsed.value.object;
    // Frozen wire fixtures use UID 1000; constructor policy requires the live
    // owner. Rebind only that identity and the resulting exact record bindings.
    if (root.getPtr("ledger")) |ledger| {
        ledger.object.getPtr("directory").?.object.getPtr("uid").?.* = .{
            .integer = core.private_files.hostUid(std.os.linux.geteuid()),
        };
    }
    if (root.getPtr("plan_sha256")) |digest| {
        const plan = try goldenRecord(a, "plan");
        defer a.free(plan);
        digest.* = .{ .string = try sha256(allocator, plan) };
    }
    if (root.getPtr("plan")) |artifact| {
        const plan = try goldenRecord(a, "plan");
        defer a.free(plan);
        try bind(allocator, artifact, plan);
    }
    if (root.getPtr("authorization")) |artifact| {
        const authorization = try goldenRecord(a, "authorization_approved");
        defer a.free(authorization);
        try bind(allocator, artifact, authorization);
    }
    return record.canonicalAlloc(a);
}

fn sha256(a: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    core.Sha256.hash(bytes, &digest, .{});
    return a.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn bind(a: std.mem.Allocator, artifact: *std.json.Value, bytes: []const u8) !void {
    artifact.object.getPtr("sha256").?.* = .{ .string = try sha256(a, bytes) };
    artifact.object.getPtr("size").?.* = .{ .integer = @intCast(bytes.len) };
}

pub fn namedAtomic(_: ?*anyopaque, dir: std.Io.Dir, destination: []const u8, options: std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
    if (!@import("builtin").is_test) @compileError("Authority fixtures are test-only");
    std.debug.assert(!options.make_path and std.mem.indexOfScalar(u8, destination, '/') == null);
    const name: u64 = 0xa170c;
    const file = dir.createFile(std.testing.io, &std.fmt.hex(name), .{
        .exclusive = true,
        .permissions = options.permissions,
    }) catch |err| std.debug.panic("named atomic fixture creation failed: {s}", .{@errorName(err)});
    return .{
        .file = file,
        .file_basename_hex = name,
        .dest_sub_path = destination,
        .file_open = true,
        .file_exists = true,
        .close_dir_on_deinit = false,
        .dir = dir,
    };
}

const sdk = "a53205d77be3b880eb8f8b96679512ba58e2331a";
const source_rev = "2830293aaf1df37877cddf4dae97f5cf255b9ae2";
const source_tree = "1234567890abcdef1234567890abcdef12345678";
const modes = [_][]const u8{
    "raw-x2apic",   "raw-legacy-apic",
    "qcow2-x2apic", "qcow2-legacy-apic",
    "vpc-x2apic",   "vpc-legacy-apic",
};
const roles = [_][]const u8{
    "efi",                         "debug_elf",                   "bootinfo",
    "raw",                         "qcow2",                       "vhd",
    "runtime",                     "compiler",                    "wasm",
    "cwasm",                       "config",                      "runtime_identity",
    "image_identity",              "local_result",                "package",
    "build",                       "build_start",                 "boot_inputs",
    "qcow2_finalization_intent",   "qcow2_finalization",          "qcow2_acceptance",
    "fixed_vhd_derivation_intent", "fixed_vhd_derivation_gate",   "fixed_vhd_derivation",
    "final_inspection",            "cleanup",
};
const stages = [_][]const u8{
    "adapter",          "config",            "derive-fixed-vhd", "finalize-qcow2",
    "fixtures",         "inspect",           "local-boot-tool",  "native-image",
    "package",          "prepare",           "qcow2-legacy-apic", "qcow2-x2apic",
    "raw-legacy-apic",  "raw-x2apic",        "vpc-legacy-apic",  "vpc-x2apic",
};
const evidence_names = [_][]const u8{
    "boot-inputs.json",
    "build-start.json",
    "build.json",
    "command-adapter.json",
    "command-config.json",
    "command-derive-fixed-vhd.json",
    "command-finalize-qcow2.json",
    "command-fixtures.json",
    "command-inspect.json",
    "command-local-boot-tool.json",
    "command-native-image.json",
    "command-package.json",
    "command-prepare.json",
    "command-qcow2-legacy-apic.json",
    "command-qcow2-x2apic.json",
    "command-raw-legacy-apic.json",
    "command-raw-x2apic.json",
    "command-vpc-legacy-apic.json",
    "command-vpc-x2apic.json",
    "final-inspection.json",
    "fixed-vhd-derivation-gate.json",
    "fixed-vhd-derivation-intent.json",
    "fixed-vhd-derivation.json",
    "package.json",
    "qcow2-acceptance.json",
    "qcow2-finalization-intent.json",
    "qcow2-finalization.json",
    "qcow2-legacy-apic-compute.json",
    "qcow2-x2apic-compute.json",
    "raw-legacy-apic-compute.json",
    "raw-x2apic-compute.json",
    "vpc-legacy-apic-compute.json",
    "vpc-x2apic-compute.json",
};
const record_roles = [_][2][]const u8{
    .{ "build-start.json", "build_start" },
    .{ "build.json", "build" },
    .{ "boot-inputs.json", "boot_inputs" },
    .{ "package.json", "package" },
    .{ "qcow2-finalization-intent.json", "qcow2_finalization_intent" },
    .{ "qcow2-finalization.json", "qcow2_finalization" },
    .{ "qcow2-acceptance.json", "qcow2_acceptance" },
    .{ "fixed-vhd-derivation-intent.json", "fixed_vhd_derivation_intent" },
    .{ "fixed-vhd-derivation-gate.json", "fixed_vhd_derivation_gate" },
    .{ "fixed-vhd-derivation.json", "fixed_vhd_derivation" },
};

const Limits = struct {
    max_input_bytes: u64 = 66 * 1024 * 1024,
    max_output_bytes: u64 = 66 * 1024 * 1024 + 512,
    max_virtual_bytes: u64 = 66 * 1024 * 1024,
    max_partition_array_bytes: u64 = 1024 * 1024,
    max_metadata_bytes: u64 = 128 * 1024,
    max_metadata_work: u64 = 8194,
    max_work_bytes: u64 = 4 * 66 * 1024 * 1024,
    max_memory_bytes: u64 = 512 * 1024 * 1024,
    max_workload_bytes: u64 = 64 * 1024 * 1024,
};

const Pin = struct {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: u32,
    ctime_seconds: i64,
    ctime_nanoseconds: u32,
    sha256: [32]u16,
};

const Observed = struct {
    path: []const u8,
    sha256: []const u8,
    file_bytes: u64,
    allocated: struct {
        state: []const u8 = "available",
        bytes: u64,
    },
    virtual_bytes: u64,
    metadata: [9]u64,
};

const BootHashes = struct {
    request_sha256: []const u8,
    report_sha256: []const u8,
    serial_sha256: []const u8,
    compute_sha256: []const u8,
};

fn modeFd(fd: linux.fd_t, mode: u32) !void {
    if (linux.errno(linux.fchmod(fd, mode)) != .SUCCESS) return error.FixtureMode;
}

fn makeRemovable(io: std.Io, directory: std.Io.Dir) !void {
    try modeFd(directory.handle, 0o700);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const child = try directory.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
        defer child.close(io);
        try makeRemovable(io, child);
    }
}

pub fn cleanupAuthorizationFixture(io: std.Io, root_path: []const u8) !void {
    if (!@import("builtin").is_test) @compileError("Authority fixtures are test-only");
    if (std.Io.Dir.openDirAbsolute(io, root_path, .{ .iterate = true, .follow_symlinks = false })) |dir| {
        defer dir.close(io);
        try makeRemovable(io, dir);
    } else |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    }
    const parent_path = std.fs.path.dirname(root_path) orelse return error.InvalidPath;
    const parent = try std.Io.Dir.openDirAbsolute(io, parent_path, .{});
    defer parent.close(io);
    try parent.deleteTree(io, std.fs.path.basename(root_path));
}

fn writeMode(io: std.Io, dir: std.Io.Dir, sub_path: []const u8, bytes: []const u8, mode: u32) !void {
    const file = try dir.createFile(io, sub_path, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    if (mode != 0o600) try modeFd(file.handle, mode);
}

fn canonicalBytes(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    var doc = try core.contracts.Document.parse(a, raw, contracts.json_limits);
    defer doc.deinit();
    return doc.canonicalAlloc(a);
}

fn canonicalJson(a: std.mem.Allocator, value: anytype) ![]const u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    return canonicalBytes(a, raw);
}

fn writeJson(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8, value: anytype) ![]const u8 {
    const bytes = try canonicalJson(a, value);
    try writeMode(io, dir, sub_path, bytes, 0o600);
    return bytes;
}

fn metadataFor(io: std.Io, path: []const u8) ![9]u64 {
    const file = try files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const stx = try files.snapshot(file);
    const dev = (@as(u64, stx.dev_major) << 8) | @as(u64, stx.dev_minor);
    const mtime_ns = @as(u64, @intCast(stx.mtime.sec)) * 1_000_000_000 + @as(u64, stx.mtime.nsec);
    const ctime_ns = @as(u64, @intCast(stx.ctime.sec)) * 1_000_000_000 + @as(u64, stx.ctime.nsec);
    return .{ dev, stx.ino, stx.mode, stx.uid, stx.gid, stx.nlink, stx.size, mtime_ns, ctime_ns };
}

fn observedFor(io: std.Io, path: []const u8, digest: []const u8, virtual_bytes: u64) !Observed {
    const file = try files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const stx = try files.snapshot(file);
    return .{
        .path = path,
        .sha256 = digest,
        .file_bytes = stx.size,
        .allocated = .{ .bytes = stx.blocks * 512 },
        .virtual_bytes = virtual_bytes,
        .metadata = try metadataFor(io, path),
    };
}

fn pinFor(io: std.Io, path: []const u8, digest: []const u8) !Pin {
    const file = try files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const stx = try files.snapshot(file);
    const parsed = try core.contracts.parseSha256(digest);
    var hash_u16: [32]u16 = undefined;
    for (parsed, 0..) |b, i| hash_u16[i] = b;
    return .{
        .device_major = stx.dev_major,
        .device_minor = stx.dev_minor,
        .inode = stx.ino,
        .mode = stx.mode,
        .uid = stx.uid,
        .gid = stx.gid,
        .nlink = stx.nlink,
        .size = stx.size,
        .mtime_seconds = stx.mtime.sec,
        .mtime_nanoseconds = stx.mtime.nsec,
        .ctime_seconds = stx.ctime.sec,
        .ctime_nanoseconds = stx.ctime.nsec,
        .sha256 = hash_u16,
    };
}

fn artifactFor(a: std.mem.Allocator, io: std.Io, path: []const u8, known_sha256: ?[]const u8) !types.compute.Artifact {
    const policy: files.FilePolicy = if (known_sha256 == null and std.mem.endsWith(u8, path, "fixture")) .tool else .artifact;
    const file = try files.openAbsolute(io, path, policy);
    defer file.close(io);
    const stx = try files.snapshot(file);
    const digest = if (known_sha256) |d|
        try a.dupe(u8, d)
    else blk: {
        const RuntimeCache = types.runtime.DigestCache;
        const HandoffCache = @import("wamr_handoff").retained_copy.DigestCache;
        const bhash = RuntimeCache.computeBoundaryHash(io, file, stx.size);
        if (bhash) |bh| {
            if (RuntimeCache.get(stx, 1, bh)) |cached| {
                break :blk try a.dupe(u8, &std.fmt.bytesToHex(cached.digest, .lower));
            }
        }
        var hasher = core.Sha256.init(.{});
        var buf: [65536]u8 = undefined;
        var offset: u64 = 0;
        while (offset < stx.size) {
            const amount: usize = @intCast(@min(@as(u64, buf.len), stx.size - offset));
            if (try file.readPositionalAll(io, buf[0..amount], offset) != amount) return error.FixtureFailed;
            hasher.update(buf[0..amount]);
            offset += amount;
        }
        const raw_digest = hasher.finalResult();
        if (bhash) |bh| {
            RuntimeCache.put(stx, 1, bh, raw_digest, 0, 0);
            HandoffCache.put(stx, 1, bh, raw_digest, 0, HandoffCache.flag_scan_checked);
        }
        break :blk try a.dupe(u8, &std.fmt.bytesToHex(raw_digest, .lower));
    };
    return .{
        .path = try a.dupe(u8, path),
        .size = stx.size,
        .sha256 = digest,
    };
}

fn runToolJson(a: std.mem.Allocator, io: std.Io, argv: []const []const u8) ![]const u8 {
    var env = std.process.Environ.Map.init(a);
    defer env.deinit();
    const res = try std.process.run(a, io, .{
        .argv = argv,
        .environ_map = &env,
        .stdout_limit = .limited(65536),
        .stderr_limit = .limited(65536),
    });
    defer a.free(res.stdout);
    defer a.free(res.stderr);
    if (res.term != .exited or res.term.exited != 0) return error.FixtureFailed;
    return canonicalBytes(a, res.stdout);
}

const SparseChunk = struct {
    offset: u64,
    bytes: []const u8,
};

const CachedPackage = struct {
    valid: bool = false,
    tool_meta: [9]u64 = @splat(0),
    package_bytes: []const u8 = "",
    finalization_bytes: []const u8 = "",
    derivation_bytes: []const u8 = "",
    qcow2_bytes: []const u8 = "",
    raw_size: u64 = 0,
    raw_chunks: []const SparseChunk = &.{},
    vhd_size: u64 = 0,
    vhd_chunks: []const SparseChunk = &.{},
};

var cached_pkg_lock: std.atomic.Value(u32) = .init(0);
var cached_pkg: CachedPackage = .{};

fn captureSparseFile(io: std.Io, dir: std.Io.Dir, name: []const u8, out_size: *u64) ![]const SparseChunk {
    const page = std.heap.page_allocator;
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    const stx = try files.snapshot(file);
    out_size.* = stx.size;
    var list: std.ArrayList(SparseChunk) = .empty;
    var buf: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stx.size) {
        const want: usize = @intCast(@min(@as(u64, buf.len), stx.size - offset));
        if (try file.readPositionalAll(io, buf[0..want], offset) != want) return error.FixtureFailed;
        if (std.mem.indexOfNone(u8, buf[0..want], &.{0}) != null) {
            try list.append(page, .{
                .offset = offset,
                .bytes = try page.dupe(u8, buf[0..want]),
            });
        }
        offset += want;
    }
    return list.toOwnedSlice(page);
}

fn writeSparseFile(io: std.Io, dir: std.Io.Dir, name: []const u8, size: u64, chunks: []const SparseChunk) !void {
    const file = try dir.createFile(io, name, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    for (chunks) |chunk| {
        try file.writePositionalAll(io, chunk.bytes, chunk.offset);
    }
    if (std.os.linux.errno(std.os.linux.ftruncate(file.handle, @intCast(size))) != .SUCCESS)
        return error.FixtureFailed;
}

fn seedArtifactDigestCache(io: std.Io, dir: std.Io.Dir, name: []const u8, sha256_hex: []const u8, vhd_raw_sha256_hex: ?[]const u8) void {
    const DigestCache = @import("wamr_handoff").retained_copy.DigestCache;
    const RuntimeCache = types.runtime.DigestCache;
    const file = dir.openFile(io, name, .{}) catch return;
    defer file.close(io);
    const snap = files.snapshot(file) catch return;
    const bh = DigestCache.computeBoundaryHash(io, file, snap.size) orelse return;
    const digest = core.contracts.parseSha256(sha256_hex) catch return;
    DigestCache.put(snap, 1, bh, digest, 0, DigestCache.flag_scan_checked);
    RuntimeCache.put(snap, 1, bh, digest, 0, RuntimeCache.flag_scan_checked);
    if (vhd_raw_sha256_hex) |raw_hex| {
        const raw_digest = core.contracts.parseSha256(raw_hex) catch return;
        DigestCache.put(snap, 2, bh, raw_digest, 0, 0);
        RuntimeCache.put(snap, 2, bh, raw_digest, 0, 0);
    }
}

pub fn buildAuthorizationFixture(
    a: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    package_tool: []const u8,
    native_tool: []const u8,
) !types.Plan {
    if (!@import("builtin").is_test) @compileError("Authority fixtures are test-only");
    try cleanupAuthorizationFixture(io, root_path);
    try std.Io.Dir.cwd().createDir(io, root_path, .fromMode(0o700));
    const root_dir = try std.Io.Dir.openDirAbsolute(io, root_path, .{ .iterate = true });
    defer root_dir.close(io);
    for ([_][]const u8{ "artifacts", "evidence", "boots", "state", "ledger", "runtime-src" }) |sub|
        try root_dir.createDir(io, sub, .fromMode(0o700));

    const artifacts_dir = try root_dir.openDir(io, "artifacts", .{});
    defer artifacts_dir.close(io);
    const evidence_dir = try root_dir.openDir(io, "evidence", .{});
    defer evidence_dir.close(io);
    const boots_dir = try root_dir.openDir(io, "boots", .{});
    defer boots_dir.close(io);
    const state_dir = try root_dir.openDir(io, "state", .{});
    defer state_dir.close(io);

    var efi_bytes: [512]u8 = @splat(0);
    efi_bytes[0..2].* = "MZ".*;
    std.mem.writeInt(u32, efi_bytes[0x3c..0x40], 0x80, .little);
    efi_bytes[0x80..0x84].* = "PE\x00\x00".*;
    std.mem.writeInt(u16, efi_bytes[0x84..0x86], 0x8664, .little);
    std.mem.writeInt(u16, efi_bytes[0x86..0x88], 1, .little);
    std.mem.writeInt(u16, efi_bytes[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u16, efi_bytes[0x98..0x9a], 0x20b, .little);
    std.mem.writeInt(u16, efi_bytes[0xdc..0xde], 10, .little);
    try writeMode(io, root_dir, "workload.efi", &efi_bytes, 0o600);
    try writeMode(io, artifacts_dir, "efi", &efi_bytes, 0o600);
    const efi_sha256 = try sha256(a, &efi_bytes);
    const efi_size: u64 = efi_bytes.len;

    const workload_path = try std.fs.path.join(a, &.{ root_path, "workload.efi" });
    const state_path = try std.fs.path.join(a, &.{ root_path, "state" });
    const artifacts_path = try std.fs.path.join(a, &.{ root_path, "artifacts" });
    const evidence_path = try std.fs.path.join(a, &.{ root_path, "evidence" });

    const tool_meta = try metadataFor(io, package_tool);
    while (cached_pkg_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
    const use_cache = cached_pkg.valid and std.meta.eql(cached_pkg.tool_meta, tool_meta);
    cached_pkg_lock.store(0, .release);

    const package_bytes = if (use_cache)
        try a.dupe(u8, cached_pkg.package_bytes)
    else
        try runToolJson(a, io, &.{ package_tool, "package", workload_path, state_path });
    try writeMode(io, evidence_dir, "package.json", package_bytes, 0o600);
    try writeMode(io, artifacts_dir, "package", package_bytes, 0o600);
    var pkg_doc = try contracts.parseCanonical(a, package_bytes);
    defer pkg_doc.deinit();
    const raw_obj = pkg_doc.value().object.get("image").?.object.get("raw").?.object;
    const raw_sha256 = try a.dupe(u8, raw_obj.get("sha256").?.string);
    const raw_size = try core.contracts.integer(u64, raw_obj.get("size").?);

    const finalize_intent_bytes = try writeJson(a, io, root_dir, "finalize-intent.json", .{
        .schema = "uk.wamr.compute-qcow2-finalization-intent",
        .schema_version = @as(u8, 1),
        .source_path = try std.fs.path.join(a, &.{ state_path, "unikraft.raw" }),
        .expected_source_sha256 = raw_sha256,
        .expected_source_bytes = raw_size,
        .expected_virtual_bytes = raw_size,
        .expected_workload_sha256 = efi_sha256,
        .expected_workload_bytes = efi_size,
        .timeout_ms = @as(u32, 120_000),
        .limits = Limits{},
    });
    try writeMode(io, evidence_dir, "qcow2-finalization-intent.json", finalize_intent_bytes, 0o600);
    try writeMode(io, artifacts_dir, "qcow2_finalization_intent", finalize_intent_bytes, 0o600);

    const finalize_intent_path = try std.fs.path.join(a, &.{ root_path, "finalize-intent.json" });
    const finalization_bytes = if (use_cache)
        try a.dupe(u8, cached_pkg.finalization_bytes)
    else
        try runToolJson(a, io, &.{ package_tool, "finalize-qcow2", finalize_intent_path, state_path });
    try writeMode(io, evidence_dir, "qcow2-finalization.json", finalization_bytes, 0o600);
    try writeMode(io, artifacts_dir, "qcow2_finalization", finalization_bytes, 0o600);
    var fin_doc = try contracts.parseCanonical(a, finalization_bytes);
    defer fin_doc.deinit();
    const qcow2_out = fin_doc.value().object.get("output").?.object;
    const qcow2_sha256 = try a.dupe(u8, qcow2_out.get("sha256").?.string);
    const qcow2_size = try core.contracts.integer(u64, qcow2_out.get("file_bytes").?);
    const producer_sha256 = try a.dupe(u8, fin_doc.value().object.get("provenance").?.object.get("producer_sha256").?.string);

    const derive_intent_bytes = try writeJson(a, io, root_dir, "derive-intent.json", .{
        .schema = "uk.wamr.compute-fixed-vhd-derivation-intent",
        .schema_version = @as(u8, 1),
        .source_path = try std.fs.path.join(a, &.{ state_path, "unikraft.qcow2" }),
        .accepted_qcow2_sha256 = qcow2_sha256,
        .expected_source_bytes = qcow2_size,
        .expected_capacity_bytes = raw_size,
        .timeout_ms = @as(u32, 120_000),
        .limits = Limits{},
    });
    try writeMode(io, evidence_dir, "fixed-vhd-derivation-intent.json", derive_intent_bytes, 0o600);
    try writeMode(io, artifacts_dir, "fixed_vhd_derivation_intent", derive_intent_bytes, 0o600);

    const derive_intent_path = try std.fs.path.join(a, &.{ root_path, "derive-intent.json" });
    const derivation_bytes = if (use_cache)
        try a.dupe(u8, cached_pkg.derivation_bytes)
    else
        try runToolJson(a, io, &.{ package_tool, "derive-fixed-vhd", derive_intent_path, state_path });
    try writeMode(io, evidence_dir, "fixed-vhd-derivation.json", derivation_bytes, 0o600);
    try writeMode(io, artifacts_dir, "fixed_vhd_derivation", derivation_bytes, 0o600);
    var der_doc = try contracts.parseCanonical(a, derivation_bytes);
    defer der_doc.deinit();
    const vhd_out = der_doc.value().object.get("output").?.object;
    const vhd_sha256 = try a.dupe(u8, vhd_out.get("sha256").?.string);
    const vhd_size = try core.contracts.integer(u64, vhd_out.get("file_bytes").?);

    if (use_cache) {
        try writeSparseFile(io, artifacts_dir, "raw", cached_pkg.raw_size, cached_pkg.raw_chunks);
        try writeMode(io, artifacts_dir, "qcow2", cached_pkg.qcow2_bytes, 0o600);
        try writeSparseFile(io, artifacts_dir, "vhd", cached_pkg.vhd_size, cached_pkg.vhd_chunks);
    } else {
        inline for (.{
            .{ "unikraft.raw", "raw" },
            .{ "unikraft.qcow2", "qcow2" },
            .{ "unikraft-derived.vhd", "vhd" },
        }) |pair| {
            try state_dir.rename(pair[0], artifacts_dir, pair[1], io);
            const f = try artifacts_dir.openFile(io, pair[1], .{});
            defer f.close(io);
            try modeFd(f.handle, 0o600);
        }
        const page = std.heap.page_allocator;
        while (cached_pkg_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        defer cached_pkg_lock.store(0, .release);
        if (!cached_pkg.valid) {
            const qcow2_file = try artifacts_dir.openFile(io, "qcow2", .{});
            defer qcow2_file.close(io);
            const qcow2_stx = try files.snapshot(qcow2_file);
            const qcow2_buf = try page.alloc(u8, @intCast(qcow2_stx.size));
            if (try qcow2_file.readPositionalAll(io, qcow2_buf, 0) != qcow2_buf.len) return error.FixtureFailed;
            var cap_raw_size: u64 = 0;
            const cap_raw_chunks = try captureSparseFile(io, artifacts_dir, "raw", &cap_raw_size);
            var cap_vhd_size: u64 = 0;
            const cap_vhd_chunks = try captureSparseFile(io, artifacts_dir, "vhd", &cap_vhd_size);
            cached_pkg = .{
                .valid = true,
                .tool_meta = tool_meta,
                .package_bytes = try page.dupe(u8, package_bytes),
                .finalization_bytes = try page.dupe(u8, finalization_bytes),
                .derivation_bytes = try page.dupe(u8, derivation_bytes),
                .qcow2_bytes = qcow2_buf,
                .raw_size = cap_raw_size,
                .raw_chunks = cap_raw_chunks,
                .vhd_size = cap_vhd_size,
                .vhd_chunks = cap_vhd_chunks,
            };
        }
    }
    seedArtifactDigestCache(io, artifacts_dir, "raw", raw_sha256, null);
    seedArtifactDigestCache(io, artifacts_dir, "qcow2", qcow2_sha256, null);
    seedArtifactDigestCache(io, artifacts_dir, "vhd", vhd_sha256, raw_sha256);

    inline for (.{ "debug_elf", "bootinfo", "runtime", "compiler", "wasm", "cwasm", "config" }) |name|
        try writeMode(io, artifacts_dir, name, "fixture-" ++ name ++ "\n", 0o600);
    try writeMode(io, artifacts_dir, "runtime_identity", "{\"fixture\":true}\n", 0o600);
    try writeMode(io, artifacts_dir, "image_identity", "{\"fixture\":true}\n", 0o600);
    try writeMode(io, artifacts_dir, "cleanup", "primary=0 cleanup=0\n", 0o600);

    const identity: types.compute.Identity = .{
        .wamr_revision = sdk,
        .wasm_sha256 = try sha256(a, "fixture-wasm\n"),
        .cwasm_sha256 = try sha256(a, "fixture-cwasm\n"),
        .runtime_sha256 = try sha256(a, "fixture-runtime\n"),
        .compiler_sha256 = try sha256(a, "fixture-compiler\n"),
        .config_sha256 = try sha256(a, "fixture-config\n"),
    };

    const build_bytes = try writeJson(a, io, evidence_dir, "build.json", .{
        .source = .{ .revision = source_rev, .tree = source_tree },
        .runtime = .{
            .wamr_revision = sdk,
            .minimal_wasi = false,
            .compiler_profile = "unikraft-x86_64",
            .zig_version = "0.16.0",
            .files = .{
                .@"tiny.wasm" = identity.wasm_sha256,
                .@"tiny.cwasm" = identity.cwasm_sha256,
                .wamrc = identity.compiler_sha256,
                .@"libwamr-aot.a" = identity.runtime_sha256,
            },
        },
        .image = .{
            .unikraft_revision = source_rev,
            .runtime_inputs_sha256 = try sha256(a, "{\"fixture\":true}\n"),
            .solved_config_sha256 = identity.config_sha256,
            .files = .{
                .@"wamr_hyperv-x86_64-efi" = efi_sha256,
                .@"wamr_hyperv-x86_64-efi.dbg" = try sha256(a, "fixture-debug_elf\n"),
                .@"wamr_hyperv-x86_64-efi.bootinfo" = try sha256(a, "fixture-bootinfo\n"),
            },
        },
    });
    try writeMode(io, artifacts_dir, "build", build_bytes, 0o600);

    const build_start_bytes = try writeJson(a, io, evidence_dir, "build-start.json", .{
        .source = .{ .revision = source_rev, .tree = source_tree },
    });
    try writeMode(io, artifacts_dir, "build_start", build_start_bytes, 0o600);

    const boot_inputs_bytes = try writeJson(a, io, evidence_dir, "boot-inputs.json", .{
        .files = .{
            .package_tool = .{
                .path = package_tool,
                .sha256 = producer_sha256,
                .metadata = try metadataFor(io, package_tool),
            },
        },
    });
    try writeMode(io, artifacts_dir, "boot_inputs", boot_inputs_bytes, 0o600);

    for (stages) |stage_name| {
        const name = try a.print("command-{s}.json", .{stage_name});
        _ = try writeJson(a, io, evidence_dir, name, .{ .stage = stage_name });
    }

    const efi_path = try std.fs.path.join(a, &.{ artifacts_path, "efi" });
    const raw_path = try std.fs.path.join(a, &.{ artifacts_path, "raw" });
    const qcow2_path = try std.fs.path.join(a, &.{ artifacts_path, "qcow2" });
    const vhd_path = try std.fs.path.join(a, &.{ artifacts_path, "vhd" });
    const config_path = try std.fs.path.join(a, &.{ artifacts_path, "config" });
    const runtime_art_path = try std.fs.path.join(a, &.{ artifacts_path, "runtime" });

    const efi_pin = try pinFor(io, efi_path, efi_sha256);
    const config_pin = try pinFor(io, config_path, identity.config_sha256);
    const runtime_pin = try pinFor(io, runtime_art_path, identity.runtime_sha256);
    const raw_pin = try pinFor(io, raw_path, raw_sha256);
    const qcow2_pin = try pinFor(io, qcow2_path, qcow2_sha256);
    const vhd_pin = try pinFor(io, vhd_path, vhd_sha256);

    const compute_result: types.compute.Result = .{
        .version = 1,
        .workload = .tiny,
        .wamr_revision = sdk,
        .wasm_sha256 = identity.wasm_sha256,
        .cwasm_sha256 = identity.cwasm_sha256,
        .runtime_sha256 = identity.runtime_sha256,
        .platform_status = 0,
        .checks = 2,
        .answer = 42,
        .terminal = 1,
        .detail = 2,
        .reserved_bytes = 0,
        .frame_bytes = 0,
        .accessible_bytes = 0,
        .allocation_bytes = 0,
        .system_page_table_bytes = 4096,
        .error_name = "",
    };
    const result_line = try canonicalJson(a, compute_result);
    const result_compact = std.mem.trimEnd(u8, result_line, "\n");

    var boot_records: [6]types.compute.BootV2 = undefined;
    var boot_hashes: [6]BootHashes = undefined;
    inline for (modes, 0..) |mode_name, index| {
        try boots_dir.createDir(io, mode_name, .fromMode(0o700));
        const mode_dir = try boots_dir.openDir(io, mode_name, .{});
        defer mode_dir.close(io);
        const mode_path = try std.fs.path.join(a, &.{ root_path, "boots", mode_name });

        const image_path = if (index < 2) raw_path else if (index < 4) qcow2_path else vhd_path;
        const image_pin = if (index < 2) raw_pin else if (index < 4) qcow2_pin else vhd_pin;
        const kind = if (index < 2) "raw_disk" else if (index < 4) "qcow2" else "fixed_vhd";
        const pins = [4]Pin{ image_pin, efi_pin, config_pin, runtime_pin };

        const req_bytes = try writeJson(a, io, mode_dir, "request", .{
            .schema_version = @as(u8, 2),
            .supervisor_pid = @as(u32, 12345),
            .config = .{
                .source = .{ .kind = kind, .path = image_path },
                .expect = "WAMR_NATIVE_AOT_OK answer=42 teardown=0",
                .expect_main_return = @as(i32, 0),
                .cpus = @as(u8, 1),
                .timeout_ms = @as(u32, 60000),
                .disable_x2apic = (index % 2 == 1),
            },
            .pins = pins,
        });
        const req_sha256 = try sha256(a, req_bytes);

        const serial_bytes = try a.print(
            "synthetic boot {d}\n{s}Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by\nCalling main(0, 0)\nWAMR_NATIVE_COMPUTE={s}\nWAMR_NATIVE_AOT_OK answer=42 teardown=0\n[    1.000001] Info: [libukboot] main returned 0\n",
            .{ index, if (index % 2 == 1) "Using legacy xAPIC MMIO\n" else "", result_compact },
        );
        try writeMode(io, mode_dir, "serial", serial_bytes, 0o600);
        const serial_sha256 = try sha256(a, serial_bytes);

        const report_val = .{
            .schema_version = @as(u8, 1),
            .scope = "public_local_qemu_only",
            .acceptance = "not_established",
            .passed = true,
            .consumed = true,
            .cleanup_complete = true,
            .input_unchanged = true,
            .serial_valid = true,
            .serial_limit_reached = false,
            .serial_bytes = @as(u64, serial_bytes.len),
            .serial_sha256 = serial_sha256,
            .termination = .{ .exited = @as(u8, 0) },
            .failures = .{
                .primary = @as(?[]const u8, null),
                .cleanup = @as(?[]const u8, null),
                .recording = @as(?[]const u8, null),
            },
        };
        const rep_bytes = try writeJson(a, io, mode_dir, "report", report_val);
        const rep_sha256 = try sha256(a, rep_bytes);

        const comp_bytes = try writeJson(a, io, mode_dir, "compute", .{
            .scope = "local_native_compute_only",
            .report = report_val,
            .input_pins = pins,
            .request_sha256 = req_sha256,
            .report_sha256 = rep_sha256,
            .compute = compute_result,
        });
        try writeMode(io, evidence_dir, mode_name ++ "-compute.json", comp_bytes, 0o600);
        const comp_sha256 = try sha256(a, comp_bytes);

        boot_hashes[index] = .{
            .request_sha256 = req_sha256,
            .report_sha256 = rep_sha256,
            .serial_sha256 = serial_sha256,
            .compute_sha256 = comp_sha256,
        };
        boot_records[index] = .{
            .mode = @enumFromInt(index),
            .serial = .{
                .path = try std.fs.path.join(a, &.{ mode_path, "serial" }),
                .size = serial_bytes.len,
                .sha256 = serial_sha256,
            },
            .request = .{
                .path = try std.fs.path.join(a, &.{ mode_path, "request" }),
                .size = req_bytes.len,
                .sha256 = req_sha256,
            },
            .report = .{
                .path = try std.fs.path.join(a, &.{ mode_path, "report" }),
                .size = rep_bytes.len,
                .sha256 = rep_sha256,
            },
            .compute = .{
                .path = try std.fs.path.join(a, &.{ mode_path, "compute" }),
                .size = comp_bytes.len,
                .sha256 = comp_sha256,
            },
        };
    }

    const qcow2_obs = try observedFor(io, qcow2_path, qcow2_sha256, raw_size);
    const acceptance_bytes = try writeJson(a, io, evidence_dir, "qcow2-acceptance.json", .{
        .schema = "uk.wamr.compute-qcow2-acceptance",
        .schema_version = @as(u8, 1),
        .profile = "qcow2-derived-vhd",
        .status = "accepted",
        .source = .{ .revision = source_rev, .tree = source_tree },
        .accepted_qcow2 = qcow2_obs,
        .modes = modes[0..4],
        .boots = .{
            .@"raw-x2apic" = boot_hashes[0],
            .@"raw-legacy-apic" = boot_hashes[1],
            .@"qcow2-x2apic" = boot_hashes[2],
            .@"qcow2-legacy-apic" = boot_hashes[3],
        },
        .finalization_sha256 = try sha256(a, finalization_bytes),
        .build_sha256 = try sha256(a, build_bytes),
        .boot_inputs_sha256 = try sha256(a, boot_inputs_bytes),
    });
    try writeMode(io, artifacts_dir, "qcow2_acceptance", acceptance_bytes, 0o600);

    const gate_bytes = try writeJson(a, io, evidence_dir, "fixed-vhd-derivation-gate.json", .{
        .schema = "uk.wamr.compute-fixed-vhd-derivation-gate",
        .schema_version = @as(u8, 1),
        .profile = "qcow2-derived-vhd",
        .status = "accepted_qcow2_only",
        .accepted_qcow2_sha256 = qcow2_sha256,
        .derived_output_absent = true,
        .qcow2_acceptance_sha256 = try sha256(a, acceptance_bytes),
        .derivation_intent_sha256 = try sha256(a, derive_intent_bytes),
    });
    try writeMode(io, artifacts_dir, "fixed_vhd_derivation_gate", gate_bytes, 0o600);

    const inspection_bytes = try writeJson(a, io, evidence_dir, "final-inspection.json", .{
        .schema = "uk.wamr.compute-image-chain-inspection",
        .schema_version = @as(u8, 1),
        .profile = "qcow2-derived-vhd",
        .status = "complete",
        .source = .{ .revision = source_rev, .tree = source_tree },
        .artifacts = .{
            .efi = try observedFor(io, efi_path, efi_sha256, efi_size),
            .raw = try observedFor(io, raw_path, raw_sha256, raw_size),
            .qcow2 = qcow2_obs,
            .vhd = try observedFor(io, vhd_path, vhd_sha256, vhd_size - 512),
        },
        .modes = modes,
        .boots = .{
            .@"raw-x2apic" = boot_hashes[0],
            .@"raw-legacy-apic" = boot_hashes[1],
            .@"qcow2-x2apic" = boot_hashes[2],
            .@"qcow2-legacy-apic" = boot_hashes[3],
            .@"vpc-x2apic" = boot_hashes[4],
            .@"vpc-legacy-apic" = boot_hashes[5],
        },
        .records = .{
            .@"build-start.json" = try sha256(a, build_start_bytes),
            .@"build.json" = try sha256(a, build_bytes),
            .@"boot-inputs.json" = try sha256(a, boot_inputs_bytes),
            .@"package.json" = try sha256(a, package_bytes),
            .@"qcow2-finalization-intent.json" = try sha256(a, finalize_intent_bytes),
            .@"qcow2-finalization.json" = try sha256(a, finalization_bytes),
            .@"qcow2-acceptance.json" = try sha256(a, acceptance_bytes),
            .@"fixed-vhd-derivation-intent.json" = try sha256(a, derive_intent_bytes),
            .@"fixed-vhd-derivation-gate.json" = try sha256(a, gate_bytes),
            .@"fixed-vhd-derivation.json" = try sha256(a, derivation_bytes),
        },
    });
    try writeMode(io, artifacts_dir, "final_inspection", inspection_bytes, 0o600);

    var evidence_items: [evidence_names.len]types.compute.Artifact = undefined;
    var records_map: std.json.ObjectMap = .empty;
    for (evidence_names, 0..) |ev_name, i| {
        const ev_path = try std.fs.path.join(a, &.{ evidence_path, ev_name });
        evidence_items[i] = try artifactFor(a, io, ev_path, null);
        try records_map.put(a, ev_name, .{ .string = evidence_items[i].sha256 });
    }
    _ = try writeJson(a, io, artifacts_dir, "local_result", .{
        .schema_version = @as(u8, 2),
        .profile = "qcow2-derived-vhd",
        .scope = "local_native_compute_only",
        .passed = true,
        .hardware_acceptance = "not_established",
        .cloud_authority = "not_admitted",
        .benchmark = "not_measured",
        .workload = "tiny",
        .modes = modes,
        .records = std.json.Value{ .object = records_map },
    });

    var role_artifacts: [roles.len]types.compute.Artifact = undefined;
    for (roles, 0..) |role_name, i| {
        const role_path = try std.fs.path.join(a, &.{ artifacts_path, role_name });
        const known: ?[]const u8 = if (std.mem.eql(u8, role_name, "raw"))
            raw_sha256
        else if (std.mem.eql(u8, role_name, "qcow2"))
            qcow2_sha256
        else if (std.mem.eql(u8, role_name, "vhd"))
            vhd_sha256
        else
            null;
        role_artifacts[i] = try artifactFor(a, io, role_path, known);
    }

    const run_id: types.compute.RunIdentity = .{
        .repository = "cataggar/unikraft",
        .run_id = "1234567",
        .run_attempt = "1",
    };
    const lineage: types.compute.Lineage = .{
        .raw_sha256 = raw_sha256,
        .accepted_qcow2_sha256 = qcow2_sha256,
        .derived_vhd_sha256 = vhd_sha256,
        .qcow2_finalization_sha256 = role_artifacts[19].sha256,
        .qcow2_acceptance_sha256 = role_artifacts[20].sha256,
        .fixed_vhd_derivation_gate_sha256 = role_artifacts[22].sha256,
        .fixed_vhd_derivation_sha256 = role_artifacts[23].sha256,
        .final_inspection_sha256 = role_artifacts[24].sha256,
    };
    const bundle_v2: types.compute.BundleV2 = .{
        .schema = "uk.wamr.local-image-handoff",
        .version = 2,
        .profile = .@"qcow2-derived-vhd",
        .authority = .not_admitted,
        .source_revision = source_rev,
        .source_tree = source_tree,
        .run = run_id,
        .identity = identity,
        .lineage = lineage,
        .artifacts = role_artifacts,
        .boots = boot_records,
        .evidence = evidence_items,
    };
    const bundle_bytes = try writeJson(a, io, root_dir, "bundle.json", bundle_v2);
    const bundle_art: types.compute.Artifact = .{
        .path = try std.fs.path.join(a, &.{ root_path, "bundle.json" }),
        .size = bundle_bytes.len,
        .sha256 = try sha256(a, bundle_bytes),
    };

    const transport_bytes = try writeJson(a, io, root_dir, "transport.json", .{
        .schema = "uk.wamr.public-source-transport",
        .version = @as(u8, 2),
        .repository = run_id.repository,
        .run_id = run_id.run_id,
        .run_attempt = run_id.run_attempt,
        .source_revision = source_rev,
        .source_tree = source_tree,
        .artifact_id = "12345",
        .inner_zip_sha256 = &@as([64]u8, @splat('1')),
        .container_digest = &@as([64]u8, @splat('2')),
    });
    const transport_art: types.compute.Artifact = .{
        .path = try std.fs.path.join(a, &.{ root_path, "transport.json" }),
        .size = transport_bytes.len,
        .sha256 = try sha256(a, transport_bytes),
    };

    const imported_bytes = try writeJson(a, io, root_dir, "imported.json", .{
        .schema = "uk.wamr.direct-compute-admission",
        .version = @as(u8, 2),
        .profile = "qcow2-derived-vhd",
        .authority = "not_admitted",
        .source_revision = source_rev,
        .source_tree = source_tree,
        .run = run_id,
        .lineage = lineage,
        .public_bundle = bundle_art,
        .transport = transport_art,
    });
    const imported_art: types.compute.Artifact = .{
        .path = try std.fs.path.join(a, &.{ root_path, "imported.json" }),
        .size = imported_bytes.len,
        .sha256 = try sha256(a, imported_bytes),
    };

    // Stage synthetic Azure runtime closure via native runtime_copy.Stage.
    const rt_src = try root_dir.openDir(io, "runtime-src", .{});
    defer rt_src.close(io);
    for ([_][]const u8{ "python3.11", "python3.11/encodings", "packages", "packages/azure", "data" }) |sub|
        try rt_src.createDir(io, sub, .fromMode(0o700));
    try writeMode(io, rt_src, "launcher", "synthetic-launcher\n", 0o500);
    try writeMode(io, rt_src, "python", "synthetic-interpreter\n", 0o500);
    try writeMode(io, rt_src, "ld-synthetic.so", "synthetic-loader\n", 0o500);
    try writeMode(io, rt_src, "python3.11/os.py", "synthetic-os\n", 0o600);
    try writeMode(io, rt_src, "python3.11/encodings/__init__.py", "synthetic-encodings\n", 0o600);
    try writeMode(io, rt_src, "packages/azure/__init__.py", "synthetic-azure\n", 0o600);
    try writeMode(io, rt_src, "data/fixed.txt", "synthetic-data\n", 0o600);

    const rt_src_path = try std.fs.path.join(a, &.{ root_path, "runtime-src" });
    const rt_out_path = try std.fs.path.join(a, &.{ root_path, "azure-runtime" });
    const loader_src_path = try std.fs.path.join(a, &.{ rt_src_path, "ld-synthetic.so" });
    var loader_retained = try files.RetainedFile.open(io, loader_src_path, .artifact);
    defer loader_retained.close(io);
    var deps = [1]types.LoaderSource{.{ .file = &loader_retained, .executable = true }};
    var stage = try runtime_copy.Stage.init(
        .{ .allocator = std.testing.allocator, .io = io },
        .{
            .output = rt_out_path,
            .azure = try std.fs.path.join(a, &.{ rt_src_path, "launcher" }),
            .az_python = try std.fs.path.join(a, &.{ rt_src_path, "python" }),
            .stdlib = try std.fs.path.join(a, &.{ rt_src_path, "python3.11" }),
            .package_root = &.{try std.fs.path.join(a, &.{ rt_src_path, "packages" })},
            .data_root = &.{try std.fs.path.join(a, &.{ rt_src_path, "data" })},
        },
        .{ .dynamic_loader = &loader_retained, .dependencies = &deps },
    );
    defer stage.deinit();
    if (stage.copyStage() != .staged) return error.FixtureFailed;
    const draft = try stage.manifestInputs();
    const rt_out_dir = try root_dir.openDir(io, "azure-runtime", .{});
    defer rt_out_dir.close(io);
    try writeMode(io, rt_out_dir, "azure-runtime.manifest", draft.bytes, 0o600);
    var manifest_retained = try files.RetainedFile.open(io, draft.manifest.path, .private);
    defer manifest_retained.close(io);
    const commitments = try draft.bindManifest(.{ .allocator = a, .io = io }, &manifest_retained);
    const runtime_contract_draft: types.runtime.Contract = .{
        .schema = "uk.wamr.azure-cli-runtime-closure",
        .version = 1,
        .canonicalization = "utf8-byte-sorted-keys-compact-lf-v1",
        .root = (try stage.layout()).root,
        .python_version = "3.11",
        .extensions = (try stage.layout()).extensions,
        .launcher = draft.launcher,
        .interpreter = draft.interpreter,
        .dynamic_loader = draft.dynamic_loader,
        .manifest = draft.manifest,
        .limits = runtime_copy.canonicalLimits(),
        .observed = draft.observed,
        .content_sha256 = &commitments.content_sha256,
        .metadata_sha256 = &commitments.metadata_sha256,
        .parents_sha256 = &commitments.parents_sha256,
        .loader_dependencies = draft.loader_dependencies,
        .commands = &types.runtime.commands,
        .isolation = .{
            .python_home = .closure_root,
            .module_layout = .flat_python_home_v1,
            .extensions = .closure_empty,
            .dynamic_extension_install = .disabled,
            .user_site = .disabled,
            .site_import = .disabled,
            .bytecode_writes = .disabled,
            .path_environment = .forbidden,
            .startup_hooks = .forbidden,
            .loader_environment = .retained_readonly_root,
            .host_loader_fallback = .forbidden,
            .package_restore = .forbidden_after_custody,
        },
    };
    const runtime_bytes = try records.runtimeBytes(a, runtime_contract_draft);
    try writeMode(io, rt_out_dir, "azure-runtime.json", runtime_bytes, 0o600);
    const runtime_contract = (try records.parse(types.runtime.Contract, a, runtime_bytes)).value;
    const runtime_doc_art: types.compute.Artifact = .{
        .path = try std.fs.path.join(a, &.{ rt_out_path, "azure-runtime.json" }),
        .size = runtime_bytes.len,
        .sha256 = try sha256(a, runtime_bytes),
    };

    var plan = (try records.parse(types.Plan, a, try goldenRecord(a, "plan"))).value;
    const native_art = try artifactFor(a, io, native_tool, null);
    plan.source_revision = source_rev;
    plan.source_tree = source_tree;
    plan.run = run_id;
    plan.identity = identity;
    plan.lineage = lineage;
    plan.bundle = imported_art;
    plan.public_bundle = bundle_art;
    plan.transport = transport_art;
    plan.qcow2 = role_artifacts[4];
    plan.os_vhd = role_artifacts[5];
    plan.ledger_path = try std.fs.path.join(a, &.{ root_path, "ledger" });
    plan.artifact_id = "12345";
    plan.inner_zip_sha256 = &@as([64]u8, @splat('1'));
    plan.container_digest = &@as([64]u8, @splat('2'));
    plan.azure_runtime = runtime_contract;
    plan.azure_runtime_document = runtime_doc_art;
    plan.tools = .{
        .azure = .{
            .path = runtime_contract.launcher.path,
            .size = runtime_contract.launcher.size,
            .sha256 = runtime_contract.launcher.sha256,
        },
        .az_python = .{
            .path = runtime_contract.interpreter.path,
            .size = runtime_contract.interpreter.size,
            .sha256 = runtime_contract.interpreter.sha256,
        },
        .uploader = native_art,
        .validator = native_art,
        .supervisor = native_art,
    };

    const candidate_val: types.compute.CandidateScope = .{
        .schema = "uk.wamr.direct-compute",
        .version = 2,
        .purpose = .@"qcow2-derived-vhd",
        .authority = .not_admitted,
        .approval = .{
            .direct_specialized_gen2 = false,
            .os_only_private = false,
            .two_boots_only = false,
            .cleanup_owned_group = false,
            .exact_image_and_local_bundle_reviewed = false,
            .fresh_final_approval = false,
            .approved_unix = 0,
            .expires_unix = 0,
        },
        .attempt_id = plan.attempt_id,
        .subscription = plan.subscription,
        .location = plan.location,
        .prefix = plan.prefix,
        .vm_size = plan.vm_size,
        .serial_mode = plan.serial_mode,
        .runtime_seconds = plan.runtime_seconds,
        .cleanup_seconds = plan.cleanup_seconds,
        .operation_seconds = plan.operation_seconds,
        .poll_seconds = plan.poll_seconds,
        .source_revision = plan.source_revision,
        .source_tree = plan.source_tree,
        .identity = plan.identity,
        .os_vhd = plan.os_vhd,
        .bundle = plan.bundle,
    };
    const candidate_bytes = try writeJson(a, io, root_dir, "candidate.json", candidate_val);
    plan.candidate = .{
        .path = try std.fs.path.join(a, &.{ root_path, "candidate.json" }),
        .size = candidate_bytes.len,
        .sha256 = try sha256(a, candidate_bytes),
    };
    return plan;
}
