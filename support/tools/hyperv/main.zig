const std = @import("std");
const core = @import("hyperv");

pub const std_options: std.Options = .{ .logFn = safeLog };
fn safeLog(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, arguments: anytype) void {
    _ = format;
    _ = arguments;
    std.log.defaultLog(level, scope, "native diagnostic suppressed", .{});
}

pub fn main(init: std.process.Init) void {
    inspect(init) catch |err| {
        var failures: core.diagnostics.Failures = .{};
        failures.primary = .{
            .stage = .inspection,
            .category = switch (err) {
                error.UnsafeFile, error.UnsafePath => .unsafe_file,
                error.FileNotFound, error.FileOpenFailed => .local_io,
                else => .invalid_input,
            },
        };
        var buffer: [1024]u8 = undefined;
        var writer = std.Io.File.stderr().writer(init.io, &buffer);
        failures.write(&writer.interface) catch {};
        writer.interface.flush() catch {};
        std.process.exit(1);
    };
}

fn inspect(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len == 3 and std.mem.eql(u8, args[1], "__transfer-worker")) {
        const report = core.transfer.worker.executeNative(std.heap.page_allocator, init.io, args[2]);
        var buffer: [core.transfer.worker.protocol.maximum_result]u8 = undefined;
        var writer = std.Io.File.stdout().writer(init.io, &buffer);
        try report.write(&writer.interface);
        try writer.interface.flush();
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "transfer")) {
        var wiping: core.sensitive.Allocator = .{ .backing = std.heap.page_allocator };
        const executable = try std.process.executablePathAlloc(init.io, wiping.allocator());
        defer wiping.allocator().free(executable);
        const report = core.transfer.worker.supervise(wiping.allocator(), init.io, args[2], args[3], .{ .executable = executable });
        var buffer: [core.transfer.worker.protocol.maximum_result]u8 = undefined;
        var writer = std.Io.File.stdout().writer(init.io, &buffer);
        try report.write(&writer.interface);
        try writer.interface.flush();
        if (!report.succeeded()) std.process.exit(1);
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
        var writer = std.Io.File.stdout().writer(init.io, &.{});
        try writer.interface.writeAll(
            "uk-hyperv inspect-json|validate-binding|inspect-diagnostic PRIVATE_DIRECTORY BASENAME\n" ++
                "uk-hyperv transfer PRIVATE_DIRECTORY JOB_BASENAME\n" ++
                "Transfer requires a fresh private job and explicit SAS file; no ambient credentials or retries.\n",
        );
        return;
    }
    if (args.len != 4) return error.InvalidCommand;
    const json = std.mem.eql(u8, args[1], "inspect-json");
    const binding = std.mem.eql(u8, args[1], "validate-binding");
    const diagnostic = std.mem.eql(u8, args[1], "inspect-diagnostic");
    if (!json and !binding and !diagnostic) return error.InvalidCommand;
    const directory = try core.private_files.Directory.open(init.io, args[2]);
    defer directory.close(init.io);
    var contents = try directory.readSensitive(init.io, allocator, args[3], 256 * 1024, null);
    defer contents.deinit();
    const document = try core.contracts.SensitiveDocument.parse(allocator, contents.bytes(), .{});
    defer document.deinit();
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stdout().writer(init.io, &buffer);
    if (json) {
        const canonical = if (document.requireCanonical(contents.bytes())) |_| true else |err| switch (err) {
            error.NonCanonical => false,
            else => return err,
        };
        try writer.interface.print("{{\"canonical\":{s},\"valid\":true}}\n", .{
            if (canonical) "true" else "false",
        });
    } else {
        try document.requireCanonical(contents.bytes());
        if (binding) {
            _ = try core.contracts.InputBinding.parse(document.value());
            try writer.interface.writeAll("{\"contract\":\"uk.hyperv.input-binding\",\"schema_version\":1,\"valid\":true}\n");
        } else {
            const parsed = try core.diagnostics.Diagnostic.parse(document.value());
            try parsed.write(&writer.interface);
            try writer.interface.writeByte('\n');
        }
    }
    try writer.interface.flush();
}
