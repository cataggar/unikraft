const std = @import("std");
const image = @import("public_image");
const c = image.contracts;

pub fn main(init: std.process.Init) void {
    const code = execute(init) catch |err| {
        const category: image.core.diagnostics.Category = switch (err) {
            error.WouldBlock => .contention,
            error.PathAlreadyExists => .conflict,
            error.FileNotFound => .not_found,
            error.UnsafeFile, error.UnsafePath, error.InvalidArtifact, error.InvalidExecutable => .unsafe_file,
            error.SourceChanged, error.ArtifactChanged, error.HashMismatch => .integrity,
            error.NotPrepared, error.IncompleteMatrix, error.InvalidMatrix, error.RecordMismatch => .invalid_response,
            error.RecordingFailed, error.WriteFailed, error.ReadFailed => .local_io,
            else => .invalid_input,
        };
        emit(init, .{ .scope = "public_local_packaging_only", .failures = image.core.diagnostics.Failures{
            .primary = .{ .stage = .contract, .category = category },
        } }, true) catch std.process.exit(3);
        std.process.exit(2);
    };
    std.process.exit(code);
}
fn execute(init: std.process.Init) !u8 {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--exec")) {
        image.boot.child.execute(init) catch return 126;
        return 126;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--package-worker")) {
        image.worker.execute(init) catch return 126;
        return 0;
    }
    if (args.len < 2 or args.len > 40 or (args.len - 2) % 2 != 0) return error.InvalidArguments;
    var map = std.StringHashMap([]const u8).init(a);
    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        if (args[i].len > 64 or args[i + 1].len > 4095) return error.InvalidArguments;
        const entry = try map.getOrPut(args[i]);
        if (entry.found_existing) return error.DuplicateArgument;
        entry.value_ptr.* = args[i + 1];
    }
    const self = try std.Io.Dir.cwd().realPathFileAlloc(init.io, "/proc/self/exe", a);
    const state_dir = try take(&map, "--state-dir");
    if (std.mem.eql(u8, args[1], "prepare")) {
        const timeout = optional(&map, "--timeout") orelse "30";
        const input: c.Input = .{
            .efi = try take(&map, "--efi"),
            .qemu = try take(&map, "--qemu"),
            .ovmf_code = try take(&map, "--ovmf-code"),
            .ovmf_vars = try take(&map, "--ovmf-vars"),
            .state_dir = state_dir,
            .solved_config = optional(&map, "--solved-config"),
            .expect = optional(&map, "--expect") orelse c.platform_marker,
            .timeout_ms = try image.boot.config.timeout(timeout),
        };
        if (map.count() != 0) return error.UnknownArgument;
        try image.core.process.initialize();
        const state = try image.engine.prepare(a, init.io, input, .{ .self_executable = self });
        try emit(init, .{ .scope = "public_local_packaging_only", .phase = state.phase, .failures = state.failures }, state.phase != .prepared);
        return if (state.phase == .prepared) 0 else 1;
    }
    if (!std.mem.eql(u8, args[1], "validate-matrix") and !std.mem.eql(u8, args[1], "export-prepared")) return error.InvalidCommand;
    const root = try image.core.private_files.Directory.open(init.io, state_dir);
    defer root.close(init.io);
    var lock = try root.lock(init.io);
    defer lock.close(init.io);
    if (std.mem.eql(u8, args[1], "validate-matrix")) {
        if (map.count() != 0) return error.UnknownArgument;
        const state = try image.engine.load(a, init.io, &lock, self);
        try emit(init, try image.manifest.preflight(a, state.input.expect, state.acceptance), false);
        return 0;
    }
    const artifact_dir = try take(&map, "--artifact-dir");
    const source: c.Source = .{
        .repository = try take(&map, "--source-repository"),
        .repository_id = try positive(try take(&map, "--source-repository-id")),
        .workflow_ref = try take(&map, "--source-workflow-ref"),
        .job = try take(&map, "--source-job"),
        .run_id = try positive(try take(&map, "--source-run-id")),
        .run_attempt = try positive(try take(&map, "--source-run-attempt")),
        .head_sha = try take(&map, "--source-head-sha"),
    };
    if (map.count() != 0) return error.UnknownArgument;
    const result = image.manifest.publish(a, init.io, &lock, self, artifact_dir, source);
    if (result.sha256) |hash| {
        var out = std.Io.File.stdout().writer(init.io, &.{});
        try out.interface.print("{s}\n", .{std.fmt.bytesToHex(hash, .lower)});
        return 0;
    }
    try emit(init, .{ .scope = "public_local_packaging_only", .failures = result.failures }, true);
    return 1;
}
fn optional(map: *std.StringHashMap([]const u8), key: []const u8) ?[]const u8 {
    return if (map.fetchRemove(key)) |entry| entry.value else null;
}
fn take(map: *std.StringHashMap([]const u8), key: []const u8) ![]const u8 {
    return optional(map, key) orelse error.MissingArgument;
}
fn positive(text: []const u8) !u64 {
    const number = try image.core.contracts.integer(u64, .{ .number_string = text });
    if (number == 0) return error.InvalidNumber;
    return number;
}
fn emit(init: std.process.Init, data: anytype, stderr: bool) !void {
    var output = (if (stderr) std.Io.File.stderr() else std.Io.File.stdout()).writer(init.io, &.{});
    try output.interface.writeAll(try c.encode(init.arena.allocator(), data));
}
