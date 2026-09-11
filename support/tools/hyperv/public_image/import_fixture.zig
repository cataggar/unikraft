//! Public synthetic artifact factory. No guest, QEMU, attestation or authority.
const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const p = image.core.private_files;
pub const source: c.Source = .{
    .repository = "cataggar/unikraft",
    .repository_id = 123,
    .workflow_ref = "cataggar/unikraft/.github/workflows/integration.yaml@refs/heads/main",
    .run_id = 456,
    .run_attempt = 1,
    .head_sha = "0123456789abcdef0123456789abcdef01234567",
};
pub fn syntheticEfi() [512]u8 {
    var bytes = [_]u8{0} ** 512;
    bytes[0..2].* = "MZ".*;
    std.mem.writeInt(u32, bytes[0x3c..0x40], 0x80, .little);
    bytes[0x80..0x84].* = "PE\x00\x00".*;
    std.mem.writeInt(u16, bytes[0x84..0x86], 0x8664, .little);
    std.mem.writeInt(u16, bytes[0x86..0x88], 1, .little);
    std.mem.writeInt(u16, bytes[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u16, bytes[0x98..0x9a], 0x20b, .little);
    std.mem.writeInt(u16, bytes[0xdc..0xde], 10, .little);
    return bytes;
}
pub const Fixture = struct {
    arena: *std.heap.ArenaAllocator,
    a: std.mem.Allocator,
    io: std.Io,
    root: p.Directory,
    dir: p.Directory,
    artifact: p.Directory,
    name: []const u8,
    path: []const u8,
    artifact_path: []const u8,
    expected: image.importer.Expectations,
    manifest: image.manifest.Manifest,
    bytes: []const u8,
    pub fn init(backing: std.mem.Allocator, io: std.Io, root_path: []const u8) !Fixture {
        const arena = try backing.create(std.heap.ArenaAllocator);
        arena.* = .init(backing);
        errdefer {
            arena.deinit();
            backing.destroy(arena);
        }
        const a = arena.allocator();
        const root = try p.Directory.open(io, root_path);
        errdefer root.close(io);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(a, "import,fixture-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        const path = try image.files.path(a, root_path, name);
        const dir = try image.files.create(io, path);
        errdefer dir.close(io);
        const package_dir = try image.files.create(io, try image.files.path(a, path, "package"));
        defer package_dir.close(io);
        try dir.dir.writeFile(io, .{ .sub_path = "synthetic.efi", .data = &syntheticEfi(), .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        const efi = try image.files.record(a, io, try image.files.path(a, path, "synthetic.efi"), c.max_efi, false);
        const packaged = try image.package.build(a, io, package_dir, efi);
        try image.files.cleanupStage(io, package_dir, "package-stage");
        const artifact_path = try image.files.path(a, path, "artifact");
        const artifact = try image.files.create(io, artifact_path);
        errdefer artifact.close(io);
        try image.files.copy(io, packaged.vhd, artifact, "unikraft.vhd");
        const producer_sha = try c.hex(a, c.hash("public synthetic independently expected source producer"));
        const acceptance = try image.network.raw(a);
        // These are synthetic source-manifest claims, not manufactured engine.State
        // records and not observations of a real or simulated guest boot.
        const manifest: image.manifest.Manifest = .{
            .controller_sha256 = producer_sha,
            .source = source,
            .acceptance = acceptance,
            .artifacts = .{ .efi = .{ .sha256 = packaged.efi.sha256 }, .raw = .{ .sha256 = packaged.raw.sha256, .size = c.raw_bytes }, .vhd = .{ .sha256 = packaged.vhd.sha256, .size = c.vhd_bytes }, .miz = .{ .sha256 = producer_sha, .revision = c.miz_revision } },
            .packaging = packaged.packaging,
            .preflight = try image.manifest.preflight(a, c.platform_marker, acceptance),
        };
        const bytes = try c.encode(a, manifest);
        try artifact.dir.writeFile(io, .{ .sub_path = image.manifest.name, .data = bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        return .{
            .arena = arena,
            .a = a,
            .io = io,
            .root = root,
            .dir = dir,
            .artifact = artifact,
            .name = name,
            .path = path,
            .artifact_path = artifact_path,
            .manifest = manifest,
            .bytes = bytes,
            .expected = .{ .manifest_sha256 = try c.hex(a, c.hash(bytes)), .native_producer_sha256 = producer_sha, .source = source },
        };
    }
    pub fn deinit(self: Fixture, backing: std.mem.Allocator) void {
        self.artifact.close(self.io);
        self.dir.close(self.io);
        self.root.dir.deleteTree(self.io, self.name) catch @panic("owned import fixture cleanup failed");
        self.root.close(self.io);
        self.arena.deinit();
        backing.destroy(self.arena);
    }
    pub fn destination(self: Fixture, name: []const u8) ![]const u8 {
        return image.files.path(self.a, self.path, name);
    }
    pub fn run(self: Fixture, name: []const u8) !image.importer.Result {
        return image.importer.importPrepared(self.a, self.io, self.artifact_path, try self.destination(name), self.expected);
    }
    pub fn writeManifest(self: Fixture, bytes: []const u8) !image.importer.Expectations {
        try rewrite(self.io, self.artifact, image.manifest.name, bytes);
        var expected = self.expected;
        expected.manifest_sha256 = try c.hex(self.a, c.hash(bytes));
        return expected;
    }
    pub fn coherentImage(self: Fixture, manifest: image.manifest.Manifest) !image.importer.Expectations {
        var changed = manifest;
        const file = try self.artifact.openFile(self.io, "unikraft.vhd");
        defer file.close(self.io);
        var raw_hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [32768]u8 = undefined;
        var offset: u64 = 0;
        while (offset < c.raw_bytes) {
            const n: usize = @intCast(@min(buffer.len, c.raw_bytes - offset));
            if (try file.readPositionalAll(self.io, buffer[0..n], offset) != n) return error.ShortFixture;
            raw_hash.update(buffer[0..n]);
            offset += n;
        }
        changed.artifacts.raw.sha256 = try c.hex(self.a, raw_hash.finalResult());
        changed.artifacts.vhd.sha256 = try c.hex(self.a, try image.boot.files.digest(self.io, file, try p.snapshot(file)));
        return self.writeManifest(try c.encode(self.a, changed));
    }
    pub fn efiOffset(self: Fixture) !u64 {
        const file = try self.artifact.openFile(self.io, "unikraft.vhd");
        defer file.close(self.io);
        var buffer: [32768 + 511]u8 = undefined;
        var offset: u64 = 0;
        while (offset < c.raw_bytes) : (offset += 32768) {
            const n = try file.readPositionalAll(self.io, &buffer, offset);
            if (std.mem.indexOf(u8, buffer[0..n], &syntheticEfi())) |at| return offset + at;
        }
        return error.NoSyntheticEfi;
    }
};
pub fn rewrite(io: std.Io, dir: p.Directory, name: []const u8, bytes: []const u8) !void {
    try dir.dir.writeFile(io, .{ .sub_path = name, .data = bytes, .flags = .{ .permissions = .fromMode(0o600) } });
}
