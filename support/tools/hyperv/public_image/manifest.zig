const std = @import("std");
const c = @import("contracts.zig");
const f = @import("files.zig");
const engine = @import("engine.zig");
const network = @import("network.zig");
const p = c.core.private_files;
pub const name = "prepared-image-manifest.json";
pub const Manifest = struct {
    schema: []const u8 = "unikraft.hyperv.prepared-image",
    schema_version: u8 = 2,
    controller_revision: u8 = 4,
    controller_sha256: []const u8,
    source: c.Source,
    acceptance: std.json.Value,
    artifacts: struct {
        efi: struct { sha256: []const u8 },
        raw: struct { sha256: []const u8, size: u64 },
        vhd: struct { sha256: []const u8, size: u64 },
        miz: struct { sha256: []const u8, revision: []const u8 },
    },
    packaging: @import("package.zig").Packaging,
    preflight: std.json.Value,
};
fn outcome(a: std.mem.Allocator, legacy: bool, is_network: bool) !std.json.Value {
    const apic = if (legacy) "legacy-xapic" else "x2apic";
    return if (is_network) network.value(a, .{ .platform_ready = true, .io_ready = false, .apic_path = apic, .network_config = "matched" }) else network.value(a, .{ .platform_ready = true, .io_ready = false, .apic_path = apic });
}
pub fn preflight(a: std.mem.Allocator, marker: []const u8, acceptance: std.json.Value) !std.json.Value {
    const mode = try network.parse(acceptance) != null;
    const modes = .{ .x2apic = try outcome(a, false, mode), .@"legacy-apic" = try outcome(a, true, mode) };
    return network.value(a, .{ .scope = "platform-only", .platform_marker = marker, .boots = .{ .raw = modes, .vhd = modes } });
}
pub fn build(a: std.mem.Allocator, state: c.State, source: c.Source) ![]u8 {
    try source.validate();
    if (state.phase != .prepared or !engine.clean(state.failures) or state.package == null) return error.NotPrepared;
    for (state.boots, 0..) |boot, index| if (boot == null or boot.?.index != index) return error.IncompleteMatrix;
    const package = state.package.?;
    const manifest: Manifest = .{
        .controller_sha256 = state.inputs.producer.sha256,
        .source = source,
        .acceptance = state.acceptance,
        .artifacts = .{
            .efi = .{ .sha256 = package.efi.sha256 },
            .raw = .{ .sha256 = package.raw.sha256, .size = package.raw.size },
            .vhd = .{ .sha256 = package.vhd.sha256, .size = package.vhd.size },
            .miz = .{ .sha256 = state.inputs.producer.sha256, .revision = c.miz_revision },
        },
        .packaging = package.packaging,
        .preflight = try preflight(a, state.input.expect, state.acceptance),
    };
    const bytes = try c.encode(a, manifest);
    _ = try validate(a, bytes, source, try c.sha(state.inputs.producer.sha256));
    return bytes;
}
pub fn validate(a: std.mem.Allocator, bytes: []const u8, source: c.Source, producer: c.Hash) !Manifest {
    const result = try c.read(Manifest, a, bytes);
    if (!std.mem.eql(u8, result.schema, "unikraft.hyperv.prepared-image") or result.schema_version != 2 or result.controller_revision != 4)
        return error.UnsupportedController;
    try source.validate();
    try result.source.validate();
    try f.same(a, source, result.source);
    if (!std.mem.eql(u8, &try c.sha(result.controller_sha256), &producer) or
        !std.mem.eql(u8, result.artifacts.miz.sha256, result.controller_sha256) or
        !std.mem.eql(u8, result.artifacts.miz.revision, c.miz_revision) or
        result.artifacts.raw.size != c.raw_bytes or result.artifacts.vhd.size != c.vhd_bytes) return error.InvalidManifest;
    _ = try c.sha(result.artifacts.efi.sha256);
    _ = try c.sha(result.artifacts.raw.sha256);
    _ = try c.sha(result.artifacts.vhd.sha256);
    try f.same(a, @as(@import("package.zig").Packaging, .{ .@"boot-file-sha256" = result.artifacts.efi.sha256 }), result.packaging);
    try network.validate(a, result.acceptance);
    if (result.preflight != .object) return error.InvalidManifest;
    const marker = try c.core.contracts.string(result.preflight.object.get("platform_marker") orelse return error.InvalidManifest);
    try c.boot.config.marker(marker);
    try f.same(a, try preflight(a, marker, result.acceptance), result.preflight);
    return result;
}
pub const Result = struct { sha256: ?c.Hash = null, failures: c.core.diagnostics.Failures = .{} };
pub fn publish(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, self_executable: []const u8, target: []const u8, source: c.Source) Result {
    var result: Result = .{};
    publishImpl(a, io, lock, self_executable, target, source, &result) catch {
        result.failures.primary = .{ .stage = .inspection, .category = .invalid_response };
    };
    if (!engine.clean(result.failures)) result.sha256 = null;
    return result;
}
fn publishImpl(a: std.mem.Allocator, io: std.Io, lock: *p.Locked, self_executable: []const u8, target: []const u8, source: c.Source, result: *Result) !void {
    try source.validate();
    try p.absoluteFilePath(target);
    const state = try engine.load(a, io, lock, self_executable);
    if (std.mem.startsWith(u8, target, state.input.state_dir) and
        (target.len == state.input.state_dir.len or target[state.input.state_dir.len] == '/')) return error.OutputInsideEvidence;
    const encoded = try build(a, state, source);
    const parent = try p.FileParent.open(io, target, .artifact);
    defer parent.close(io);
    const stage_name = try std.fmt.allocPrint(a, ".{s}.native-stage", .{parent.name});
    try p.basename(stage_name);
    try parent.directory.createDir(io, stage_name, .fromMode(0o700));
    var published = false;
    defer if (!published) f.cleanupStage(io, .{ .dir = parent.directory }, stage_name) catch {
        result.failures.cleanup = .{ .stage = .cleanup, .category = .cleanup_failed };
    };
    const stage_path = try f.path(a, std.fs.path.dirname(target).?, stage_name);
    const stage = try p.Directory.open(io, stage_path);
    defer stage.close(io);
    try f.copy(io, state.package.?.vhd, stage, "unikraft.vhd");
    const output = try stage.dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer output.close(io);
    try output.writePositionalAll(io, encoded, 0);
    try output.sync(io);
    try f.sync(io, stage.dir);
    try parent.directory.renamePreserve(stage_name, parent.directory, parent.name, io);
    published = true;
    parent.sync(io) catch {
        result.failures.recording = .{ .stage = .state_record, .category = .local_io };
        return;
    };
    result.sha256 = c.hash(encoded);
}
