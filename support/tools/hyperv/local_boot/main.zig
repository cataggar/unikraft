const std = @import("std");
const boot = @import("local_boot");

pub fn main(init: std.process.Init) void {
    const code = execute(init) catch |err| {
        const category: boot.core.diagnostics.Category = switch (err) {
            error.WouldBlock => .contention,
            error.WorkspaceConsumed, error.PathAlreadyExists => .conflict,
            error.UnsafeFile, error.UnsafePath, error.InvalidArtifact, error.InvalidExecutable => .unsafe_file,
            error.RecordingFailed => .local_io,
            error.FileNotFound => .not_found,
            error.InvalidSource,
            error.InvalidCpuCount,
            error.InvalidTimeout,
            error.InvalidMarker,
            error.TooManyMarkers,
            error.DuplicateMarker,
            error.ConflictingMarker,
            error.InvalidNumber,
            error.TooManyArguments,
            error.InvalidArgument,
            error.UnknownArgument,
            error.DuplicateArgument,
            error.MissingArgument,
            error.InputInsideWorkspace,
            => .invalid_input,
            else => .local_io,
        };
        var report: boot.runner.Report = .{};
        report.failures.primary = .{ .stage = .contract, .category = category };
        emit(init, report) catch std.process.exit(3);
        std.process.exit(2);
    };
    std.process.exit(code);
}

fn execute(init: std.process.Init) !u8 {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--exec")) {
        boot.child.execute(init) catch {
            // Fixed text only, to the retained log if redirection was reached.
            var writer = std.Io.File.stderr().writer(init.io, &.{});
            writer.interface.writeAll("local_boot_child_failed\n") catch {};
            return 126;
        };
        return 126;
    }
    const config = try boot.config.parse(a, args[1..]);
    try boot.core.process.initialize();
    const self = try std.Io.Dir.cwd().realPathFileAlloc(init.io, "/proc/self/exe", a);
    const report = try boot.runner.run(a, init.io, config, .{ .self_executable = self });
    try emit(init, report);
    return if (report.succeeded()) 0 else 1;
}

fn emit(init: std.process.Init, report: boot.runner.Report) !void {
    const encoded = try report.encode(init.arena.allocator());
    var writer = std.Io.File.stdout().writer(init.io, &.{});
    try writer.interface.writeAll(encoded);
}
