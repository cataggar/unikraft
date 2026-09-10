// SPDX-License-Identifier: BSD-3-Clause

//! Native end-to-end fixtures: exercise real objcopy/strip, never a fake copy
//! tool or an interpreter oracle. All artifacts stay in the build output.
const std = @import("std");
const fixture = @import("native-postprocess-tests.zig").fixture;
const format = @import("postprocess-elf.zig");
const transform = @import("postprocess-image.zig");
const runner = @import("native-postprocess-runner.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len == 4 and std.mem.eql(u8, args[1], "generate")) {
        const bytes = fixture(.little, if (std.mem.eql(u8, args[2], "x86_64")) .X86_64 else .AARCH64);
        try runner.write(init.io, args[3], &bytes);
        return;
    }
    if (args.len == 10 and std.mem.eql(u8, args[1], "verify-graph")) {
        try verifyGraph(allocator, init.io, args[2..]);
        return;
    }
    if (args.len != 6) return error.InvalidArguments;
    const native = args[1];
    const objcopy = args[2];
    const strip = args[3];
    const root = args[4];
    const machine: std.elf.EM = if (std.mem.eql(u8, args[5], "x86_64")) .X86_64 else .AARCH64;
    const io = init.io;
    const paths = try allocator.alloc([]const u8, 12);
    for ([_][]const u8{
        "original debug.elf", "relocations.bin", "relocated debug.elf",
        "stripped image.elf", "boot info.bin",   "boot image.elf",
        "final image.efi",    "reference.elf",   "compile commands.json",
        "raw image.bin",      "invalid.elf",     "must not exist.elf",
    }, paths) |name, *path| path.* = try std.fs.path.join(allocator, &.{ root, name });
    try std.Io.Dir.cwd().createDirPath(io, root);
    const original = fixture(.little, machine);
    try runner.write(io, paths[0], &original);
    var source_image = try format.Image.parse(allocator, &original);
    defer source_image.deinit();
    const expected_relocations = try transform.relocations(allocator, source_image);
    try runner.run(io, &.{ native, "uk-reloc", "--objcopy", objcopy, paths[0], paths[1], paths[2] });
    try equalFile(allocator, io, paths[0], &original);
    try equalFile(allocator, io, paths[1], expected_relocations);
    var relocated = try readImage(allocator, io, paths[2]);
    defer relocated.deinit();
    try std.testing.expectEqualSlices(u8, expected_relocations, try relocated.sectionData(try relocated.section(".uk_reloc")));
    const update_reloc = try std.fmt.allocPrint(allocator, "--update-section=.uk_reloc={s}", .{paths[1]});
    try runner.write(io, paths[7], &original);
    try tool(io, allocator, objcopy, &.{ update_reloc, paths[7] });
    try equalFile(allocator, io, paths[7], relocated.bytes);

    const removed = [_][]const u8{ ".dynamic", ".gnu.hash", ".hash", ".dynsym", ".dynstr", ".rela.dyn" };
    var strip_args: std.ArrayList([]const u8) = .empty;
    try strip_args.appendSlice(allocator, &.{ native, "strip", "--tool", strip });
    for (removed) |name| try strip_args.appendSlice(allocator, &.{ "--remove-section", name });
    try strip_args.appendSlice(allocator, &.{ paths[2], paths[3] });
    try runner.run(io, strip_args.items);
    var stripped = try readImage(allocator, io, paths[3]);
    defer stripped.deinit();
    try std.testing.expectEqual(0, stripped.symbols.len);
    for (removed) |name| try std.testing.expectError(error.MissingSection, stripped.section(name));
    try std.testing.expectEqualSlices(u8, expected_relocations, try stripped.sectionData(try stripped.section(".uk_reloc")));
    strip_args.clearRetainingCapacity();
    try strip_args.append(allocator, "-s");
    for (removed) |name| try strip_args.appendSlice(allocator, &.{ "-R", name });
    try strip_args.appendSlice(allocator, &.{ paths[2], "-o", paths[7] });
    try tool(io, allocator, strip, strip_args.items);
    try equalFile(allocator, io, paths[7], stripped.bytes);

    const architecture = if (machine == .X86_64) "x86_64" else "arm64";
    const expected_bootinfo = try transform.bootinfo(allocator, stripped, paths[3], true);
    try runner.run(io, &.{ native, "bootinfo", "--objcopy", objcopy, "--arch", architecture, "--names", paths[3], paths[4], paths[5] });
    try equalFile(allocator, io, paths[4], expected_bootinfo);
    var boot = try readImage(allocator, io, paths[5]);
    defer boot.deinit();
    try std.testing.expectEqualSlices(u8, expected_bootinfo, try boot.sectionData(try boot.section(".uk_bootinfo")));
    const update_boot = try std.fmt.allocPrint(allocator, "--update-section=.uk_bootinfo={s}", .{paths[4]});
    try tool(io, allocator, objcopy, &.{ paths[3], update_boot, paths[7] });
    try equalFile(allocator, io, paths[7], boot.bytes);
    const expected_efi = try transform.efi(allocator, boot, relocated);
    try runner.run(io, &.{ native, "efi", paths[5], paths[2], paths[6] });
    try equalFile(allocator, io, paths[6], expected_efi);
    try equalFile(allocator, io, paths[0], &original);
    try equalFile(allocator, io, paths[2], relocated.bytes);
    try equalFile(allocator, io, paths[3], stripped.bytes);
    try equalFile(allocator, io, paths[5], boot.bytes);

    try runner.run(io, &.{ native, "objcopy-binary", "--tool", objcopy, paths[5], paths[9] });
    try tool(io, allocator, objcopy, &.{ "-O", "binary", paths[5], paths[7] });
    try equalFile(allocator, io, paths[9], try runner.read(allocator, io, paths[7]));

    const database_root = try std.fs.path.join(allocator, &.{ root, "compile inputs" });
    const nested = try std.fs.path.join(allocator, &.{ database_root, "nested" });
    const hidden = try std.fs.path.join(allocator, &.{ database_root, ".hidden" });
    const empty = try std.fs.path.join(allocator, &.{ database_root, "empty" });
    try std.Io.Dir.cwd().createDirPath(io, nested);
    try std.Io.Dir.cwd().createDirPath(io, hidden);
    try std.Io.Dir.cwd().createDirPath(io, empty);
    const first = "{\"directory\":\"/one\",\"file\":\"one.c\",\"command\":\"cc one.c\"},\n";
    const second = "{\"directory\":\"/two\",\"file\":\"two.c\",\"arguments\":[\"cc\",\"two.c\"]},\n";
    try runner.write(io, try std.fs.path.join(allocator, &.{ database_root, "first.ukcmpdb.json" }), first[0 .. first.len - 1] ++ "\r\n");
    try runner.write(io, try std.fs.path.join(allocator, &.{ nested, "second.ukcmpdb.json" }), second[0 .. second.len - 1] ++ "\r");
    try runner.write(io, try std.fs.path.join(allocator, &.{ hidden, "ignored.ukcmpdb.json" }), "must not be collected");
    try runner.write(io, try std.fs.path.join(allocator, &.{ database_root, ".ignored.ukcmpdb.json" }), "must not be collected");
    try runner.run(io, &.{ native, "compile-database", "--search-root", database_root, paths[6], paths[8] });
    try equalFile(allocator, io, paths[8], "[\n" ++ first ++ second[0 .. second.len - 2] ++ "\n]\n");
    try std.testing.expectEqualStrings("[\n\n]\n", try runner.compileDatabase(allocator, io, empty));

    try runner.write(io, paths[10], "not ELF");
    var bad = try std.process.spawn(io, .{ .argv = &.{ native, "strip", "--tool", strip, paths[10], paths[11] }, .stderr = .ignore });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, try bad.wait(io));
    try std.testing.expectError(error.FileNotFound, runner.read(allocator, io, paths[11]));
    const failing_strip = try std.fmt.allocPrint(allocator, "{s} --deliberately-invalid-native-fixture-option", .{strip});
    var failed_tool = try std.process.spawn(io, .{
        .argv = &.{ native, "strip", "--tool", failing_strip, paths[0], paths[11] },
        .stderr = .ignore,
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, try failed_tool.wait(io));
    try std.testing.expectError(error.FileNotFound, runner.read(allocator, io, paths[11]));
    try @import("native-postprocess-file-fixture.zig").run(allocator, io, native, objcopy, strip, root, machine);
}

fn verifyGraph(allocator: std.mem.Allocator, io: std.Io, paths: []const []const u8) !void {
    var original = try readImage(allocator, io, paths[0]);
    defer original.deinit();
    const expected = fixture(.little, original.header.machine);
    try std.testing.expectEqualSlices(u8, &expected, original.bytes);
    const relocations = try transform.relocations(allocator, original);
    try equalFile(allocator, io, paths[1], relocations);
    var debug = try readImage(allocator, io, paths[2]);
    defer debug.deinit();
    try std.testing.expectEqualSlices(u8, relocations, try debug.sectionData(try debug.section(".uk_reloc")));
    var stripped = try readImage(allocator, io, paths[3]);
    defer stripped.deinit();
    try std.testing.expectEqual(0, stripped.symbols.len);
    const bootinfo = try transform.bootinfo(allocator, stripped, paths[3], false);
    try equalFile(allocator, io, paths[4], bootinfo);
    var boot = try readImage(allocator, io, paths[5]);
    defer boot.deinit();
    try std.testing.expectEqualSlices(u8, bootinfo, try boot.sectionData(try boot.section(".uk_bootinfo")));
    try equalFile(allocator, io, paths[6], try transform.efi(allocator, boot, debug));
    const database = try runner.read(allocator, io, paths[7]);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, database, .{});
    if (parsed.value != .array) return error.InvalidCompileDatabase;
}

fn equalFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, expected: []const u8) !void {
    try std.testing.expectEqualSlices(u8, expected, try runner.read(allocator, io, path));
}

fn readImage(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !format.Image {
    return format.Image.parse(allocator, try runner.read(allocator, io, path));
}

fn tool(io: std.Io, allocator: std.mem.Allocator, command: []const u8, tail: []const []const u8) !void {
    const words = try runner.splitCommand(allocator, command);
    const argv = try allocator.alloc([]const u8, words.len + tail.len);
    @memcpy(argv[0..words.len], words);
    @memcpy(argv[words.len..], tail);
    try runner.run(io, argv);
}
