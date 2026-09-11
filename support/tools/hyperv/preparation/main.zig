const std = @import("std");
const preparation = @import("preparation");
const core = preparation.contracts.core;

const PackageRequest = struct {
    input_directory: []const u8,
    efi: preparation.contracts.File,
};

pub fn main(init: std.process.Init) void {
    var failures: core.diagnostics.Failures = .{};
    execute(init, &failures) catch |err| {
        if (failures.primary == null) failures.primary = preparation.contracts.failure(err).primary;
        var buffer: [2048]u8 = undefined;
        var output = std.Io.File.stderr().writer(init.io, &buffer);
        failures.write(&output.interface) catch {};
        output.interface.flush() catch {};
        std.process.exit(1);
    };
}

fn execute(init: std.process.Init, failures: *core.diagnostics.Failures) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
        var output = std.Io.File.stdout().writer(init.io, &.{});
        try output.interface.writeAll(
            "uk-hyperv-prepare synthetic-seed PRIVATE_DIRECTORY REQUEST_BASENAME\n" ++
                "uk-hyperv-prepare package PRIVATE_DIRECTORY REQUEST_BASENAME\n" ++
                "uk-hyperv-prepare inspect-receipt PRIVATE_DIRECTORY BASENAME EXPECTED_SHA256\n" ++
                "Local native primitives only; no build, completed-state, acceptance, or cloud approval is implied.\n",
        );
        return;
    }
    if (args.len == 5 and std.mem.eql(u8, args[1], "inspect-receipt")) {
        const directory = try preparation.files.openPrivate(init.io, args[2]);
        defer directory.close(init.io);
        const bytes = try directory.read(init.io, allocator, args[3], 4 * 1024 * 1024, null);
        defer allocator.free(bytes);
        const receipt = try preparation.receipts.parse(allocator, bytes, try preparation.contracts.sha(args[4]));
        defer receipt.deinit();
        var output = std.Io.File.stdout().writer(init.io, &.{});
        try output.interface.print("{{\"authority\":\"not_admitted\",\"inspection\":\"shape_and_binding_only\",\"phase\":\"{s}\"}}\n", .{
            @tagName(receipt.value.phase),
        });
        return;
    }
    if (args.len != 4 or (!std.mem.eql(u8, args[1], "synthetic-seed") and !std.mem.eql(u8, args[1], "package")))
        return error.InvalidCommand;
    const directory = try preparation.files.openPrivate(init.io, args[2]);
    defer directory.close(init.io);
    var lock = try directory.lock(init.io);
    defer lock.close(init.io);
    const bytes = try directory.read(init.io, allocator, args[3], 4096, null);
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    if (std.mem.eql(u8, args[1], "package")) {
        const request = try preparation.contracts.parse(PackageRequest, allocator, bytes);
        defer request.deinit();
        const input = try preparation.files.Directory.open(allocator, init.io, request.value.input_directory);
        defer input.close(allocator, init.io);
        const result = preparation.package.package(allocator, init.io, &lock, input, request.value.efi);
        if (result.primary) |err| failures.primary = preparation.contracts.failure(err).primary;
        if (result.cleanup != null) failures.cleanup = .{ .stage = .private_file, .category = .cleanup_failed };
        if (!result.succeeded()) return error.PackageFailed;
        const report = try preparation.contracts.canonical(allocator, result.report.?);
        defer allocator.free(report);
        const published = try preparation.files.publish(&lock, init.io, "package.inspection.json", report);
        if (published.failures.recording) |value| try failures.record(.recording, value);
        if (published.failures.cleanup) |value| try failures.record(.cleanup, value);
        if (published.status != .durable or published.failures.cleanup != null) return error.PublicationIncomplete;
        var output = std.Io.File.stdout().writer(init.io, &.{});
        try output.interface.writeAll("{\"authority\":\"not_admitted\",\"inspection\":\"native_package\",\"state\":\"packaged\"}\n");
        return;
    }
    const parsed = try preparation.contracts.parse(preparation.seed.Parameters, allocator, bytes);
    defer parsed.deinit();
    var products = try preparation.seed.render(allocator, parsed.value);
    defer products.deinit();
    for ([_][]const u8{ "synthetic.raw", "synthetic.vhd", "synthetic.config", "synthetic.json" }, [_][]const u8{ products.raw, products.vhd, products.config, products.manifest }) |name, contents| {
        const result = try preparation.files.publish(&lock, init.io, name, contents);
        if (result.failures.recording) |value| try failures.record(.recording, value);
        if (result.failures.cleanup) |value| try failures.record(.cleanup, value);
        if (result.status != .durable or result.failures.cleanup != null) return error.PublicationIncomplete;
    }
    var output = std.Io.File.stdout().writer(init.io, &.{});
    try output.interface.writeAll("{\"scope\":\"synthetic_only\",\"state\":\"prepared\"}\n");
}
