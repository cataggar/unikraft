const std = @import("std");
const qualification = @import("qualification");
const gate = qualification.gate;
const options = @import("strip_options");
const t = std.testing;
const a = t.allocator;
const io = t.io;

fn selected(report: ?[]const u8) !qualification.Options {
    if (!options.qualified) return error.QualificationRequired;
    return .{
        .raw = options.raw,
        .candidate = options.candidate,
        .layout_policy = if (options.file_relayout) .file_offset_relayout else .identical_program_headers,
        .report = report,
    };
}

test "persistence stripping argument policy is explicit closed and absolute" {
    const defaults = try qualification.Options.parse(&.{ "verifier", "/raw", "/candidate" });
    try t.expectEqual(.identical_program_headers, defaults.layout_policy);
    try t.expect(defaults.report == null);
    const explicit = try qualification.Options.parse(&.{ "verifier", "/raw", "/candidate", "--report", "/proof", "--layout-policy", "file_offset_relayout" });
    try t.expectEqual(.file_offset_relayout, explicit.layout_policy);
    try t.expectEqualStrings("/proof", explicit.report.?);
    for ([_][]const []const u8{
        &.{ "verifier", "/raw" },
        &.{ "verifier", "/raw", "/candidate", "--report" },
        &.{ "verifier", "/raw", "/candidate", "--external", "/other" },
        &.{ "verifier", "/raw", "/candidate", "--layout-policy", "automatic" },
        &.{ "verifier", "/raw", "/candidate", "--layout-policy", "file_offset_relayout", "--layout-policy", "identical_program_headers" },
        &.{ "verifier", "/raw", "/candidate", "--report", "/first", "--report", "/second" },
    }) |args| try t.expectError(error.InvalidArguments, qualification.Options.parse(args));
    for ([_][]const []const u8{
        &.{ "verifier", "raw", "/candidate" },
        &.{ "verifier", "/raw", "candidate" },
        &.{ "verifier", "/raw", "/candidate", "--report", "proof" },
    }) |args| try t.expectError(error.UnsafePath, qualification.Options.parse(args));
}

test "persistence stripping proof names exactly one worker and retains literal pins" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const directory_path = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory_path);
    const path = try std.fs.path.join(a, &.{ directory_path, "proof.json" });
    defer a.free(path);
    try qualification.qualify(a, io, try selected(path));
    const directory = try gate.core.private_files.Directory.open(io, directory_path);
    defer directory.close(io);
    const bytes = try directory.read(io, a, "proof.json", gate.max_report_bytes, null);
    defer a.free(bytes);
    const document = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer document.deinit();
    const object = document.value.object;
    try t.expectEqual(@as(usize, 8), object.count());
    try t.expectEqualStrings("hyperv_persistence_fixture_debug_stripping_v1", object.get("schema").?.string);
    try t.expectEqualStrings("synthetic_only_not_admitted", object.get("authority").?.string);
    try t.expect(object.get("passed").?.bool and object.get("synthetic").?.bool and object.get("qualification_only").?.bool);
    try t.expect(!object.get("admitted").?.bool);
    try t.expect(object.get("pairs") == null and object.get("external_fixture") == null);
    try t.expectEqual(@as(usize, 2), std.meta.fields(gate.Role).len);
    const worker = object.get("worker").?.object;
    try t.expectEqual(@as(usize, 4), worker.count());
    try t.expectEqualStrings("persistence_worker", worker.get("role").?.string);
    const policy = (try selected(null)).layout_policy;
    try t.expectEqualStrings(@tagName(policy), object.get("layout_policy").?.string);
    const pair = try gate.Pair.openWithPolicy(a, io, options.raw, options.candidate, policy);
    defer pair.close(a, io);
    for ([_][]const u8{ "raw", "candidate" }, [_]gate.Pinned{ pair.raw, pair.candidate }) |field, input| {
        const pin = worker.get(field).?.object;
        try t.expectEqualStrings(input.path, pin.get("path").?.string);
        try t.expectEqual(input.bytes.len, @as(usize, @intCast(pin.get("size").?.integer)));
        try t.expectEqualStrings(&std.fmt.bytesToHex(input.hash, .lower), pin.get("sha256").?.string);
        try t.expect(pin.get("stable_identity_and_hash").?.bool);
    }
    try t.expect(pair.content.size_reduction > 0 and pair.content.removed_debug_bytes > 0);
    const file = try directory.openFile(io, "proof.json");
    defer file.close(io);
    const snapshot = try gate.core.private_files.snapshot(file);
    try t.expectEqual(@as(u16, 0o600), snapshot.mode & 0o777);
    try t.expectEqual(@as(u32, 1), snapshot.nlink);
    try pair.recheck(io);
}

test "persistence stripping is checked without a report and cannot overwrite reports or inputs" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory);
    const path = try std.fs.path.join(a, &.{ directory, "proof.json" });
    defer a.free(path);
    const pair = try gate.Pair.openWithPolicy(a, io, options.raw, options.candidate, (try selected(null)).layout_policy);
    defer pair.close(a, io);
    try qualification.qualify(a, io, try selected(null));
    try qualification.qualify(a, io, try selected(path));
    try t.expectError(error.PathAlreadyExists, qualification.qualify(a, io, try selected(path)));
    try t.expectError(error.PathAlreadyExists, qualification.qualify(a, io, try selected(options.raw)));
    try t.expectError(error.PathAlreadyExists, qualification.qualify(a, io, try selected(options.candidate)));
    var alias = try selected(null);
    alias.candidate = alias.raw;
    try t.expectError(error.NotDistinctFiles, qualification.qualify(a, io, alias));
    try pair.recheck(io);
}

test "persistence stripping refuses a symlink report without replacing its target" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory);
    const path = try std.fs.path.join(a, &.{ directory, "link.json" });
    defer a.free(path);
    try temporary.dir.writeFile(io, .{ .sub_path = "retained", .data = "retained\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    try temporary.dir.symLink(io, "retained", "link.json", .{});
    try t.expectError(error.PathAlreadyExists, qualification.qualify(a, io, try selected(path)));
    const bytes = try temporary.dir.readFileAlloc(io, "retained", a, .limited(64));
    defer a.free(bytes);
    try t.expectEqualStrings("retained\n", bytes);
}

test "persistence stripping rejects changed loaded bytes before publishing" {
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(io, ".", a);
    defer a.free(directory);
    const path = try std.fs.path.join(a, &.{ directory, "proof.json" });
    defer a.free(path);
    const bad_path = try std.fs.path.join(a, &.{ directory, "changed-candidate" });
    defer a.free(bad_path);
    var request = try selected(path);
    const pair = try gate.Pair.openWithPolicy(a, io, request.raw, request.candidate, request.layout_policy);
    defer pair.close(a, io);
    const bytes = try a.dupe(u8, pair.candidate.bytes);
    defer a.free(bytes);
    var changed = false;
    for (pair.content.program_mappings.slice()) |mapping| {
        const logical = mapping.logical_mapping;
        if (logical.type != std.elf.PT_LOAD or pair.content.entry < logical.virtual_address) continue;
        const delta = pair.content.entry - logical.virtual_address;
        if (delta >= logical.file_bytes) continue;
        bytes[@intCast(mapping.candidate_offset + delta)] ^= 1;
        changed = true;
        break;
    }
    try t.expect(changed);
    try temporary.dir.writeFile(io, .{ .sub_path = "changed-candidate", .data = bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    request.candidate = bad_path;
    try t.expectError(error.LoadedContentChanged, qualification.qualify(a, io, request));
    try t.expectError(error.FileNotFound, temporary.dir.openFile(io, "proof.json", .{}));
    try pair.recheck(io);
}
