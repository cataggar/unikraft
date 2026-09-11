const std = @import("std");
const pf = @import("preflight");
const f = @import("fixture_support.zig");

pub fn main(init: std.process.Init) void {
    dispatch(init) catch {
        std.Io.File.stderr().writeStreamingAll(init.io, "synthetic preflight worker failed\n") catch std.process.exit(3);
        std.process.exit(2);
    };
}
fn dispatch(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3) return error.InvalidCommand;
    const mode: pf.worker.Mode = if (std.mem.eql(u8, args[1], "--worker-prepare")) .prepare else if (std.mem.eql(u8, args[1], "--worker-step")) .step else if (std.mem.eql(u8, args[1], "--worker-cleanup")) .cleanup else if (std.mem.eql(u8, args[1], "--worker-inspect")) .inspect else if (std.mem.eql(u8, args[1], "--worker-plan")) .plan else if (std.mem.eql(u8, args[1], "--worker-plan-cleanup")) .plan_cleanup else return error.InvalidCommand;
    const directory = try pf.core.private_files.Directory.openWorkerCwd(init.io);
    defer directory.close(init.io);
    var path_buffer: [4096]u8 = undefined;
    const path_length = try pf.host.files.cwdPath(init.io, &path_buffer);
    var fixture = try f.Context.init(init.gpa, init.io, directory, path_buffer[0..path_length]);
    defer fixture.deinit();
    const fault = directory.read(init.io, init.gpa, "fixture-fault", 128, null) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (fault) |bytes| init.gpa.free(bytes);
    if (fault) |bytes| {
        if (std.mem.eql(u8, bytes, "deadline")) fixture.pause_action = .create_group else if (std.mem.eql(u8, bytes, "public-failure")) fixture.malformed_public = true else if (std.mem.eql(u8, bytes, "recording")) fixture.recording_action = .create_group else if (std.mem.eql(u8, bytes, "orphan")) fixture.orphan_action = .create_group else if (std.mem.eql(u8, bytes, "flood")) fixture.flood_action = .create_group else return error.InvalidFixture;
    }
    const cause = if (args.len == 3 and !std.mem.eql(u8, args[2], "none"))
        std.meta.stringToEnum(pf.core.diagnostics.Category, args[2]) orelse return error.InvalidCause
    else
        null;
    const result = try pf.worker.execute(.synthetic, init.gpa, init.io, mode, directory, try fixture.resolved(), cause);
    const bytes = try pf.contract.canonical(init.gpa, result);
    defer init.gpa.free(bytes);
    if (bytes.len > pf.contract.max_operation_result) return error.OutputLimit;
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
}
