// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const accepted_run = @import("accepted_run.zig");
const adapter = @import("command_adapter.zig");
const handoff_inspect = @import("handoff_inspect.zig");
const physical = @import("custody_files.zig");
const records = @import("records.zig");

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
    output: []const u8,
    signal: ?*core.process.SignalCancellation,
) !@import("command_validation.zig").ValidatedCommand {
    if (accepted.context != .local_runtime or accepted.repository == null or
        accepted.compatibility != .tiny_v2_qcow2_derived_vhd)
        return error.InvalidContext;
    try accepted.revalidateWithSignal(signal);
    const roots = try handoff_inspect.bind(accepted, output);
    var zig = try adapter.openPinnedTool(io, roots.zig, "tool:zig");
    defer zig.close(io);
    var supervisor = try files.RetainedFile.open(io, roots.supervisor, .tool);
    defer supervisor.close(io);

    const parent_path = std.fs.path.dirname(output) orelse return error.UnsafePath;
    const name = std.fs.path.basename(output);
    try files.basename(name);
    const parent = try files.openDirectory(io, parent_path, .private);
    defer parent.close(io);
    try parent.createDir(io, name, .fromMode(0o700));
    const work = try files.openDirectory(io, output, .private);
    defer work.close(io);
    for ([_][]const u8{ "private", "evidence", "public-source", "cache", "global-cache" }) |entry|
        try work.createDir(io, entry, .fromMode(0o700));
    const private = try work.openDir(io, "private", .{ .iterate = true });
    defer private.close(io);
    const evidence = try work.openDir(io, "evidence", .{ .iterate = true });
    defer evidence.close(io);

    const outcome = try adapter.execute(allocator, io, .{
        .roots = roots,
        .stage = .@"public-validator-build",
        .private_dir = private,
        .evidence_dir = evidence,
        .cancel = if (signal) |active| active.flag() else null,
    });
    if (outcome.poisoned) return error.CleanupPoisoned;
    if (!outcome.accepted) return error.StageRefused;

    const validator_path = try std.fs.path.join(allocator, &.{ output, "public-source/tools/bin/uk-wamr-direct-validate" });
    defer allocator.free(validator_path);
    var validator = try files.RetainedFile.open(io, validator_path, .tool);
    defer validator.close(io);
    const validator_record = try physical.readFile(io, validator_path, 64 * 1024 * 1024, false);
    if (validator_record.bytes < 20 or validator_record.bytes > 64 * 1024 * 1024 or
        !std.meta.eql(validator_record.metadata, physical.metadata(validator.file_snapshot)))
        return error.InvalidValidator;
    var header: [20]u8 = undefined;
    if (try validator.file.readPositionalAll(io, &header, 0) != header.len or
        !std.mem.eql(u8, header[0..4], "\x7fELF") or header[4] != 2 or header[5] != 1 or
        header[18] != 62 or header[19] != 0)
        return error.InvalidValidator;

    const checked = try validateCommandEvidence(allocator, io, accepted, output, outcome.bytes);
    try accepted.revalidateWithSignal(signal);
    const rechecked = try validateCommandEvidence(allocator, io, accepted, output, outcome.bytes);
    if (!std.meta.eql(checked, rechecked)) return error.CommandOutputChanged;
    try zig.verify(io);
    try supervisor.verify(io);
    try validator.verify(io);
    return checked;
}

pub fn validateCommandEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    accepted: *accepted_run.AcceptedRun,
    output: []const u8,
    expected_bytes: usize,
) !@import("command_validation.zig").ValidatedCommand {
    const record_path = try std.fs.path.join(allocator, &.{ output, "evidence/command-public-validator-build.json" });
    defer allocator.free(record_path);
    const record = try physical.readFile(io, record_path, records.max_record_bytes, true);
    var pinned = try files.RetainedFile.open(io, record_path, .private);
    defer pinned.close(io);
    const raw = try allocator.alloc(u8, @intCast(record.bytes));
    defer allocator.free(raw);
    if (try pinned.file.readPositionalAll(io, raw, 0) != raw.len)
        return error.CommandOutputChanged;
    const observed_sha256 = std.fmt.bytesToHex(records.fileIdentity(raw), .lower);
    if (!std.meta.eql(record.metadata, physical.metadata(pinned.file_snapshot)) or
        !std.mem.eql(u8, &record.sha256, &observed_sha256)) return error.CommandOutputChanged;
    try pinned.verify(io);
    const checked = try accepted_run.validateLocalPostRunCommand(
        accepted, raw, .@"public-validator-build",
    );
    const log_path = try std.fs.path.join(allocator, &.{ output, "private/public-validator-build.log" });
    defer allocator.free(log_path);
    const log = try physical.readFile(io, log_path, 8 * 1024 * 1024 + 1, true);
    if (checked.output_bytes != expected_bytes or checked.output_bytes != log.bytes or
        !std.mem.eql(u8, &checked.output_sha256, &log.sha256))
        return error.CommandOutputChanged;
    try pinned.verify(io);
    return checked;
}
