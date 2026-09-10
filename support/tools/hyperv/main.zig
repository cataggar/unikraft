const std = @import("std");
const core = @import("hyperv");

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
    if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
        var writer = std.Io.File.stdout().writer(init.io, &.{});
        try writer.interface.writeAll(
            "uk-hyperv inspect-json|validate-binding|inspect-diagnostic PRIVATE_DIRECTORY BASENAME\n" ++
                "Local read-only inspection only; no cloud, run, cleanup, or host commands.\n",
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
    const contents = try directory.read(init.io, allocator, args[3], 256 * 1024, null);
    defer allocator.free(contents);
    const document = try core.contracts.Document.parse(allocator, contents, .{});
    defer document.deinit();
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stdout().writer(init.io, &buffer);
    if (json) {
        const canonical = try document.canonicalAlloc(allocator);
        defer allocator.free(canonical);
        try writer.interface.print("{{\"canonical\":{s},\"valid\":true}}\n", .{
            if (std.mem.eql(u8, canonical, contents)) "true" else "false",
        });
    } else {
        try document.requireCanonical(allocator, contents);
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
