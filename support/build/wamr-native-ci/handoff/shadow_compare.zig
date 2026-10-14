// SPDX-License-Identifier: BSD-3-Clause
//! Test witness only: equality after explicitly enumerated output-path rebasing.
const std = @import("std");
const core = @import("hyperv_core");
const contracts = @import("contracts.zig");
const c = core.contracts;

pub const Roots = struct {
    bundle: []const u8,
    candidate: []const u8,
};

pub const Records = struct {
    bundle: []const u8,
    transport: []const u8,
    admission: []const u8,
    candidate: []const u8,
    result: []const u8,
};

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.ExpectedObject;
    return value.object.get(name) orelse error.MissingField;
}

fn canonical(a: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    try c.writeCanonical(a, value, &out.writer);
    try out.writer.writeByte('\n');
    return out.toOwnedSlice();
}

fn equal(a: std.mem.Allocator, value: std.json.Value, raw: []const u8) !void {
    const bytes = try canonical(a, value);
    defer a.free(bytes);
    if (!std.mem.eql(u8, bytes, raw)) return error.RecordDifference;
}

fn rebaseArtifact(a: std.mem.Allocator, item: *std.json.Value, from: []const u8, to: []const u8) !void {
    const path = try c.string(try field(item.*, "path"));
    if (!std.mem.startsWith(u8, path, from) or path.len <= from.len or path[from.len] != '/')
        return error.UnlistedRebase;
    const replacement = try std.mem.concat(a, u8, &.{ to, path[from.len..] });
    item.object.getPtr("path").?.* = .{ .string = replacement };
}

fn rebaseBundle(a: std.mem.Allocator, value: *std.json.Value, from: []const u8, to: []const u8) !void {
    for (value.object.getPtr("artifacts").?.array.items) |*item| try rebaseArtifact(a, item, from, to);
    for (value.object.getPtr("evidence").?.array.items) |*item| try rebaseArtifact(a, item, from, to);
    for (value.object.getPtr("boots").?.array.items) |*boot|
        for ([_][]const u8{ "serial", "request", "report", "compute" }) |key|
            try rebaseArtifact(a, boot.object.getPtr(key).?, from, to);
}

pub fn compareBundle(a: std.mem.Allocator, native_raw: []const u8, python_raw: []const u8, native_root: []const u8, python_root: []const u8) !void {
    var native = try contracts.parseCanonical(a, native_raw);
    defer native.deinit();
    var python = try contracts.parseCanonical(a, python_raw);
    defer python.deinit();
    if (try contracts.validateLocalImageHandoffWithRoot(native.value(), native_root) != .tiny_qcow2_derived_vhd_v2 or
        try contracts.validateLocalImageHandoffWithRoot(python.value(), python_root) != .tiny_qcow2_derived_vhd_v2)
        return error.ExpectedV2;
    // Replacements are allocated in the parsed arena, not leaked into the caller.
    var value = python.value();
    try rebaseBundle(python.parsed.arena.allocator(), &value, python_root, native_root);
    try equal(a, value, native_raw);
}

fn binding(item: std.json.Value, path: []const u8, raw: []const u8) !void {
    const fields = try c.exactFields(item, &contracts.schema_fields.artifact);
    var digest: [32]u8 = undefined;
    core.Sha256.hash(raw, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, try c.string(fields.get("path").?), path) or
        !std.mem.eql(u8, try c.string(fields.get("sha256").?), &hex) or
        try c.integer(u64, fields.get("size").?) != raw.len)
        return error.DependentCommitment;
}

fn replaceBinding(a: std.mem.Allocator, item: *std.json.Value, path: []const u8, raw: []const u8) !void {
    var digest: [32]u8 = undefined;
    core.Sha256.hash(raw, &digest, .{});
    item.object.getPtr("path").?.* = .{ .string = try a.dupe(u8, path) };
    item.object.getPtr("sha256").?.* = .{ .string = try a.dupe(u8, &std.fmt.bytesToHex(digest, .lower)) };
    item.object.getPtr("size").?.* = .{ .number_string = try std.fmt.allocPrint(a, "{d}", .{raw.len}) };
}

fn documentPath(a: std.mem.Allocator, root: []const u8, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}/{s}", .{ root, name });
}

fn sameField(a: std.mem.Allocator, left: std.json.Value, right: std.json.Value, name: []const u8) !void {
    const bytes = try canonical(a, try field(left, name));
    defer a.free(bytes);
    try equal(a, try field(right, name), bytes);
}

fn checkBindings(a: std.mem.Allocator, roots: Roots, records: Records, admission: std.json.Value, candidate: std.json.Value) !void {
    const bundle_path = try documentPath(a, roots.bundle, "bundle.json");
    defer a.free(bundle_path);
    const transport_path = try documentPath(a, roots.bundle, "transport.json");
    defer a.free(transport_path);
    const admission_path = try std.mem.concat(a, u8, &.{ roots.candidate, ".admission.json" });
    defer a.free(admission_path);
    try binding(try field(admission, "public_bundle"), bundle_path, records.bundle);
    try binding(try field(admission, "transport"), transport_path, records.transport);
    try binding(try field(candidate, "bundle"), admission_path, records.admission);
    var bundle = try contracts.parseCanonical(a, records.bundle);
    defer bundle.deinit();
    var transport = try contracts.parseCanonical(a, records.transport);
    defer transport.deinit();
    for ([_][]const u8{ "source_revision", "source_tree" }) |key| {
        try sameField(a, bundle.value(), admission, key);
        try sameField(a, bundle.value(), candidate, key);
        try sameField(a, bundle.value(), transport.value(), key);
    }
    for ([_][]const u8{ "lineage", "run", "profile" }) |key|
        try sameField(a, bundle.value(), admission, key);
    for ([_][]const u8{ "repository", "run_id", "run_attempt" }) |key|
        try sameField(a, try field(bundle.value(), "run"), transport.value(), key);
    try sameField(a, bundle.value(), candidate, "identity");
    const vhd = bundle.value().object.get("artifacts").?.array.items[5];
    const vhd_bytes = try canonical(a, vhd);
    defer a.free(vhd_bytes);
    try equal(a, try field(candidate, "os_vhd"), vhd_bytes);
    var result = try contracts.parseCanonical(a, records.result);
    defer result.deinit();
    const typed_result = try std.json.parseFromSlice(@import("wamr_tiny_contract").Result, a, records.result, .{
        .ignore_unknown_fields = false,
        .duplicate_field_behavior = .@"error",
    });
    defer typed_result.deinit();
    for ([_][]const u8{ "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256" }) |key|
        try sameField(a, try field(bundle.value(), "identity"), result.value(), key);
}

pub fn compare(a: std.mem.Allocator, native_roots: Roots, python_roots: Roots, native: Records, python: Records) !void {
    try compareBundle(a, native.bundle, python.bundle, native_roots.bundle, python_roots.bundle);
    var nt = try contracts.parseCanonical(a, native.transport);
    defer nt.deinit();
    var pt = try contracts.parseCanonical(a, python.transport);
    defer pt.deinit();
    try contracts.validatePublicSourceTransportV2(nt.value());
    try contracts.validatePublicSourceTransportV2(pt.value());
    // Transport, source, run, attempt and payload identities never rebase.
    if (!std.mem.eql(u8, native.transport, python.transport)) return error.TransportDifference;
    var na = try contracts.parseCanonical(a, native.admission);
    defer na.deinit();
    var pa = try contracts.parseCanonical(a, python.admission);
    defer pa.deinit();
    try contracts.validateDirectComputeAdmissionV2(na.value());
    try contracts.validateDirectComputeAdmissionV2(pa.value());
    var nc = try contracts.parseCanonical(a, native.candidate);
    defer nc.deinit();
    var pc = try contracts.parseCanonical(a, python.candidate);
    defer pc.deinit();
    if (try contracts.validateDirectComputeCandidate(nc.value()) != .tiny_qcow2_derived_vhd_v2 or
        try contracts.validateDirectComputeCandidate(pc.value()) != .tiny_qcow2_derived_vhd_v2)
        return error.ExpectedV2;
    try checkBindings(a, native_roots, native, na.value(), nc.value());
    try checkBindings(a, python_roots, python, pa.value(), pc.value());
    var admission = pa.value();
    const aa = pa.parsed.arena.allocator();
    try replaceBinding(aa, admission.object.getPtr("public_bundle").?, try documentPath(aa, native_roots.bundle, "bundle.json"), native.bundle);
    try replaceBinding(aa, admission.object.getPtr("transport").?, try documentPath(aa, native_roots.bundle, "transport.json"), native.transport);
    try equal(a, admission, native.admission);
    var candidate = pc.value();
    const ca = pc.parsed.arena.allocator();
    try rebaseArtifact(ca, candidate.object.getPtr("os_vhd").?, python_roots.bundle, native_roots.bundle);
    try replaceBinding(ca, candidate.object.getPtr("bundle").?, try std.mem.concat(ca, u8, &.{ native_roots.candidate, ".admission.json" }), native.admission);
    try equal(a, candidate, native.candidate);
    var nr = try contracts.parseCanonical(a, native.result);
    defer nr.deinit();
    var pr = try contracts.parseCanonical(a, python.result);
    defer pr.deinit();
    if (!std.mem.eql(u8, native.result, python.result)) return error.ResultDifference;
}

pub fn compareRequest(a: std.mem.Allocator, raw: []const u8) !void {
    var request = try c.Document.parse(a, raw, .{ .bytes = 1024 * 1024, .string_bytes = 65536, .items = 256, .tokens = 8192 });
    defer request.deinit();
    try request.requireCanonical(a, raw);
    const fields = try c.exactFields(request.value(), &.{ "mode", "native_roots", "python_roots", "native", "python" });
    const mode = try c.string(fields.get("mode").?);
    const native_roots = try rootsFrom(fields.get("native_roots").?);
    const python_roots = try rootsFrom(fields.get("python_roots").?);
    if (std.mem.eql(u8, mode, "bundle")) {
        const n = try c.exactFields(fields.get("native").?, &.{"bundle"});
        const p = try c.exactFields(fields.get("python").?, &.{"bundle"});
        return compareBundle(a, try c.string(n.get("bundle").?), try c.string(p.get("bundle").?), native_roots.bundle, python_roots.bundle);
    }
    if (!std.mem.eql(u8, mode, "candidate")) return error.InvalidMode;
    try compare(a, native_roots, python_roots, try recordsFrom(fields.get("native").?), try recordsFrom(fields.get("python").?));
}

fn rootsFrom(value: std.json.Value) !Roots {
    const fields = try c.exactFields(value, &.{ "bundle", "candidate" });
    const roots: Roots = .{ .bundle = try c.string(fields.get("bundle").?), .candidate = try c.string(fields.get("candidate").?) };
    try core.private_files.absoluteFilePath(roots.bundle);
    try core.private_files.absoluteFilePath(roots.candidate);
    return roots;
}

fn recordsFrom(value: std.json.Value) !Records {
    const fields = try c.exactFields(value, &.{ "bundle", "transport", "admission", "candidate", "result" });
    return .{
        .bundle = try c.string(fields.get("bundle").?),
        .transport = try c.string(fields.get("transport").?),
        .admission = try c.string(fields.get("admission").?),
        .candidate = try c.string(fields.get("candidate").?),
        .result = try c.string(fields.get("result").?),
    };
}

test "synthetic only: root rebasing never changes source or accepts noncanonical records" {
    const golden = @embedFile("goldens/root-bound-v2.json");
    const root = "/opt/wamr-handoff-golden-stage";
    try compareBundle(std.testing.allocator, golden, golden, root, root);
    var changed = try contracts.parseCanonical(std.testing.allocator, golden);
    defer changed.deinit();
    var value = changed.value();
    try rebaseBundle(changed.parsed.arena.allocator(), &value, root, "/different");
    const rebased = try canonical(std.testing.allocator, value);
    defer std.testing.allocator.free(rebased);
    try compareBundle(std.testing.allocator, rebased, golden, "/different", root);
    value.object.getPtr("source_revision").?.* = .{ .string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    const drifted = try canonical(std.testing.allocator, value);
    defer std.testing.allocator.free(drifted);
    try std.testing.expectError(error.RecordDifference, compareBundle(std.testing.allocator, drifted, golden, "/different", root));
    try std.testing.expectError(error.NonCanonical, compareBundle(std.testing.allocator, golden[0 .. golden.len - 1], golden, root, root));
}
