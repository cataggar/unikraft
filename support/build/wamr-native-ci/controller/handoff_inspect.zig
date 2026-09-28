// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;
const accepted_run = @import("accepted_run.zig");
const adapter = @import("command_adapter.zig");
const plan = @import("command_plan.zig");
const physical = @import("custody_files.zig");
const records = @import("records.zig");

const image = "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi";

fn inputPath(accepted: *accepted_run.AcceptedRun, role: []const u8, expected: ?[]const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    for (accepted.runtime_inputs) |input| {
        if (!std.mem.eql(u8, input.role, role)) continue;
        if (found != null or (expected != null and !std.mem.eql(u8, input.path, expected.?)))
            return error.InputChanged;
        found = input.path;
    }
    return found orelse error.MissingInput;
}

pub fn bind(accepted: *accepted_run.AcceptedRun, output: []const u8) !plan.Roots {
    if (accepted.context != .local_runtime or accepted.repository == null or
        accepted.compatibility != .tiny_v2_qcow2_derived_vhd)
        return error.InvalidContext;
    try files.absoluteFilePath(output);
    const a = accepted.arena.allocator();
    const repository = accepted.repository.?;
    const compute = try std.fs.path.join(a, &.{ accepted.root, "compute" });
    var tools: [@import("input_custody.zig").host_tools.len][]const u8 = undefined;
    for (@import("input_custody.zig").host_tools, 0..) |tool, i| {
        const role = try std.fmt.allocPrint(a, "tool:{s}", .{tool});
        tools[i] = try inputPath(accepted, role, null);
    }
    const package_tool = try std.fs.path.join(a, &.{ compute, "tools/bin/wamr-ci-package" });
    const efi = try std.fs.path.join(a, &.{ repository, image });
    const supervisor = try std.fs.path.join(a, &.{ compute, "supervisor/bin/wamr-ci-supervisor" });
    return .{
        .source_root = repository,
        .runtime = accepted.root,
        .work = output,
        .compute = compute,
        .zig = tools[9],
        .producer = try inputPath(accepted, "native:wamr-aot-build", null),
        .supervisor = try inputPath(accepted, "command-supervisor", supervisor),
        .package_tool = try inputPath(accepted, "package_tool", package_tool),
        .validator = try inputPath(accepted, "native:wamr-log-validate", null),
        .efi = try inputPath(accepted, "efi", efi),
        .tools = tools,
    };
}

fn value(value_: std.json.Value, key: []const u8) !std.json.Value {
    if (value_ != .object) return error.InvalidInspection;
    return value_.object.get(key) orelse error.InvalidInspection;
}

pub fn matchPackage(a: std.mem.Allocator, observed_raw: []const u8, package_raw: []const u8) !void {
    var observed = try contracts.Document.parse(a, observed_raw, .{ .bytes = 64 * 1024, .depth = 32, .items = 4096, .tokens = 65536 });
    defer observed.deinit();
    try observed.requireCanonical(a, observed_raw);
    var package = try contracts.Document.parse(a, package_raw, .{ .bytes = 64 * 1024, .depth = 32, .items = 4096, .tokens = 65536 });
    defer package.deinit();
    try package.requireCanonical(a, package_raw);
    const actual = observed.value();
    const expected = package.value();
    const producer = try contracts.string(try value(actual, "producer_sha256"));
    if (!std.mem.eql(u8, producer, try contracts.string(try value(expected, "producer_sha256"))))
        return error.PackageChanged;
    const actual_image = try value(actual, "image");
    const expected_image = try value(expected, "image");
    if (actual_image != .object or expected_image != .object) return error.InvalidInspection;
    for (expected_image.object.keys(), expected_image.object.values()) |key, field| {
        const current = try value(actual_image, key);
        const current_json = try std.json.Stringify.valueAlloc(a, current, .{});
        defer a.free(current_json);
        const expected_json = try std.json.Stringify.valueAlloc(a, field, .{});
        defer a.free(expected_json);
        const first = try records.canonicalAlloc(a, current_json);
        defer a.free(first);
        const second = try records.canonicalAlloc(a, expected_json);
        defer a.free(second);
        if (!std.mem.eql(u8, first, second)) return error.PackageChanged;
    }
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
    output: []const u8,
    cancel: ?*const std.atomic.Value(bool),
) !@import("command_validation.zig").ValidatedCommand {
    if (accepted.context != .local_runtime or accepted.repository == null)
        return error.InvalidContext;
    try accepted.revalidate();
    const roots = try bind(accepted, output);
    var original_tool = try files.RetainedFile.open(io, roots.package_tool, .tool);
    defer original_tool.close(io);
    var original_efi = try accepted.pinArtifact(.efi);
    defer original_efi.close(io);
    var original_package = try accepted.pinArtifact(.package);
    defer original_package.close(io);
    var original = try files.readSensitiveFile(io, allocator, original_package.file, 64 * 1024, .private);
    defer original.deinit();

    const parent_path = std.fs.path.dirname(output) orelse return error.UnsafePath;
    const name = std.fs.path.basename(output);
    try files.basename(name);
    const parent = try files.openDirectory(io, parent_path, .private);
    defer parent.close(io);
    try parent.createDir(io, name, .fromMode(0o700));
    const work = try files.openDirectory(io, output, .private);
    defer work.close(io);
    try work.createDir(io, "private", .fromMode(0o700));
    try work.createDir(io, "evidence", .fromMode(0o700));
    const private = try work.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);

    const outcome = try adapter.execute(allocator, io, .{
        .roots = roots,
        .stage = .@"handoff-inspect",
        .private_dir = private,
        .evidence_dir = evidence,
        .cancel = cancel,
        .capture_stdout = true,
    });
    defer allocator.free(outcome.stdout);
    if (outcome.poisoned) return error.CleanupPoisoned;
    if (!outcome.accepted or outcome.stderr_bytes != 0 or outcome.stdout.len == 0)
        return error.StageRefused;
    try matchPackage(allocator, outcome.stdout, original.bytes());

    const record_path = try std.fs.path.join(allocator, &.{ output, "evidence/command-handoff-inspect.json" });
    defer allocator.free(record_path);
    const record = try physical.readFile(io, record_path, records.max_record_bytes, true);
    const raw = try allocator.alloc(u8, @intCast(record.bytes));
    defer allocator.free(raw);
    var pinned_record = try files.RetainedFile.open(io, record_path, .private);
    defer pinned_record.close(io);
    if (try pinned_record.file.readPositionalAll(io, raw, 0) != raw.len)
        return error.CommandOutputChanged;
    const observed_sha256 = std.fmt.bytesToHex(records.fileIdentity(raw), .lower);
    if (!std.meta.eql(record.metadata, physical.metadata(pinned_record.file_snapshot)) or
        !std.mem.eql(u8, &record.sha256, &observed_sha256))
        return error.CommandOutputChanged;
    try pinned_record.verify(io);
    const checked = try accepted_run.validateLocalHandoffCommand(accepted, raw);
    const stdout_sha256 = std.fmt.bytesToHex(records.fileIdentity(outcome.stdout), .lower);
    if (checked.output_bytes != outcome.stdout.len or
        !std.mem.eql(u8, &checked.output_sha256, &stdout_sha256))
        return error.CommandOutputChanged;
    try accepted.revalidate();
    try pinned_record.verify(io);
    try original_tool.verify(io);
    try original_efi.verify(io);
    try original_package.verify(io);
    return checked;
}
