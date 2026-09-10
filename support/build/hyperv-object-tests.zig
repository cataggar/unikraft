// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const proof = @import("hyperv-object-proofs.zig");
const format = proof.format;
const testing = std.testing;

test "all five legacy assertion sets and mapping references are retained" {
    try testing.expectEqual(@as(usize, 24), proof.required(.@"hyperv-runtime").len);
    try testing.expectEqual(@as(usize, 14), proof.required(.@"vmbus-protocol").len);
    try testing.expectEqual(@as(usize, 9), proof.required(.@"vmbus-channel").len);
    try testing.expectEqual(@as(usize, 20), proof.required(.@"storvsc-core").len);
    try testing.expectEqual(@as(usize, 13), proof.required(.@"netvsc-protocol").len);
    try testing.expectEqual(@as(usize, 5), proof.mapping_names.len);
}

test "CLI requires exact options and retains each mapping argument in order" {
    var parsed = try proof.Options.parse(testing.allocator, &.{
        "storvsc-core", "--object", "core.o", "--mapping-api-object", "one.o", "--mapping-api-object", "two.o",
    });
    defer parsed.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), parsed.mappings.items.len);
    try testing.expectEqualStrings("one.o", parsed.mappings.items[0]);
    try testing.expectEqualStrings("two.o", parsed.mappings.items[1]);
    for ([_][]const []const u8{
        &.{},                                                         &.{"unknown"},                                                    &.{"vmbus-channel"},                                                 &.{ "vmbus-channel", "--object" },
        &.{ "vmbus-channel", "--object", "" },                        &.{ "vmbus-channel", "--object", "a", "--object", "b" },          &.{ "vmbus-channel", "--object", "a", "--mapping-api-object", "b" }, &.{ "vmbus-channel", "--object", "a", "--readelf", "b" },
        &.{ "vmbus-channel", "--object", "--nm" },                    &.{ "vmbus-channel", "--object", "a\x00b" },                      &.{ "vmbus-channel", "--object", "a", "--object", "b" },             &.{ "vmbus-channel", "--object", "a", "--mapping-api-object", "b" },
        &.{ "vmbus-channel", "--object", "a", "--readelf", "b" },     &.{ "vmbus-channel", "--object", "a", "--nm", "a", "--nm", "b" }, &.{ "vmbus-channel", "--object", "a", "--timeout-ms", "0" },         &.{ "vmbus-channel", "--object", "a", "--timeout-ms", "30001" },
        &.{ "hyperv-runtime", "--object", "a", "--unexpected", "b" },
    }) |args| try testing.expectError(error.InvalidArguments, proof.Options.parse(testing.allocator, args));
}

test "ELF parsing rejects short bad magic and unsupported object headers" {
    const short = [_]u8{0} ** 64;
    for (0..64) |length| {
        if (format.Object.parse(testing.allocator, short[0..length])) |object| {
            object.deinit();
            return error.AcceptedTruncatedHeader;
        } else |_| {}
    }
    try testing.expectError(error.InvalidElfMagic, format.Object.parse(testing.allocator, &short));
}

test "nm output bound is checked before parsing" {
    const bytes = try testing.allocator.alloc(u8, proof.tools.output_limit + 1);
    defer testing.allocator.free(bytes);
    try testing.expectError(error.ToolOutputLimit, proof.checkNm(undefined, bytes, &.{}, false));
    try testing.expectError(error.ToolOutputLimit, proof.checkSections(undefined, bytes));
}

test "mapping argument and path bounds reject excess input" {
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(testing.allocator);
    try args.appendSlice(testing.allocator, &.{ "storvsc-core", "--object", "core.o" });
    for (0..32) |_| try args.appendSlice(testing.allocator, &.{ "--mapping-api-object", "mapping.o" });
    var valid = try proof.Options.parse(testing.allocator, args.items);
    defer valid.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 32), valid.mappings.items.len);
    try args.appendSlice(testing.allocator, &.{ "--mapping-api-object", "mapping.o" });
    try testing.expectError(error.InvalidArguments, proof.Options.parse(testing.allocator, args.items));
    const too_long = [_]u8{'x'} ** 4097;
    try testing.expectError(error.InvalidArguments, proof.Options.parse(testing.allocator, &.{ "hyperv-runtime", "--object", &too_long }));
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    root: []const u8,
    verifier: []const u8,
    fake: []const u8,
    nm: []const u8,
    readelf: []const u8,
    objcopy: []const u8,
    zig: []const u8,
    environment: *const std.process.Environ.Map,
    cases: usize = 0,

    fn path(self: Fixture, name: []const u8) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.root, name });
    }

    fn write(self: Fixture, name: []const u8, bytes: []const u8) ![]u8 {
        const path_ = try self.path(name);
        errdefer self.allocator.free(path_);
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path_, .data = bytes });
        return path_;
    }

    fn command(self: Fixture, argv: []const []const u8) !void {
        const runner = try proof.tools.Tools.init(self.allocator, self.io, self.environment, 30000);
        var environment = std.process.Environ.Map.init(self.allocator);
        defer environment.deinit();
        for ([_][]const u8{ "HOME", "TMPDIR", "ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR" }) |key| {
            const scratch = try self.path(key);
            defer self.allocator.free(scratch);
            try std.Io.Dir.cwd().createDirPath(self.io, scratch);
            try environment.put(key, scratch);
        }
        var result = try proof.tools.process.run(self.allocator, self.io, .{
            .argv = argv,
            .cwd = .cwd(),
            .environment = &environment,
            .deadline = runner.deadline,
            .stdout_limit = proof.tools.output_limit,
            .stderr_limit = 64 * 1024,
        });
        defer result.deinit(self.allocator);
        try proof.tools.checkResult(result);
    }

    fn expect(self: *Fixture, args: []const []const u8, exit_code: u8, diagnostic: []const u8) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.append(self.allocator, self.verifier);
        try argv.appendSlice(self.allocator, args);
        var empty = std.process.Environ.Map.init(self.allocator);
        defer empty.deinit();
        // The executable is already built/resolved. LLVM descendants are bounded
        // and reaped by the verifier's shared native supervisor.
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .cwd = .{ .dir = self.directory },
            .environ_map = &empty,
            .stdout_limit = .limited(8192),
            .stderr_limit = .limited(8192),
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (result.term != .exited or result.term.exited != exit_code) {
            std.debug.print("fixture case {d}: unexpected CLI termination\n", .{self.cases + 1});
            return error.UnexpectedCliExit;
        }
        if (std.mem.indexOf(u8, result.stderr, diagnostic) == null) return error.MissingCliDiagnostic;
        if (args.len == 1 and std.mem.eql(u8, args[0], "architecture-notice"))
            try testing.expectEqualStrings(proof.architecture_notice, result.stdout);
        for ([_][]const u8{ self.root, "SYNTHETIC_SECRET", "private/path" }) |secret| {
            if (std.mem.indexOf(u8, result.stderr, secret) != null or std.mem.indexOf(u8, result.stdout, secret) != null)
                return error.UnsafeDiagnostic;
        }
        self.cases += 1;
    }

    fn check(self: *Fixture, profile: proof.Profile, object: []const u8, expected: u8, diagnostic: []const u8) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{ @tagName(profile), "--object", object, "--nm", self.nm });
        if (profile == .@"hyperv-runtime") try argv.appendSlice(self.allocator, &.{ "--readelf", self.readelf });
        try self.expect(argv.items, expected, diagnostic);
    }

    fn renamed(self: Fixture, object: []const u8, before: []const u8, after: []const u8, output: []const u8) ![]u8 {
        const path_ = try self.path(output);
        errdefer self.allocator.free(path_);
        const flag = try std.fmt.allocPrint(self.allocator, "--redefine-sym={s}={s}", .{ before, after });
        defer self.allocator.free(flag);
        try self.command(&.{ self.objcopy, flag, object, path_ });
        return path_;
    }
};

pub fn main(init: std.process.Init) void {
    integration(init) catch |err| {
        std.debug.print("error: object proof fixture: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn integration(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 16) return error.InvalidFixtureArguments;
    const io = init.io;
    const resolver = try proof.tools.Tools.init(allocator, io, init.environ_map, 30000);
    const verifier = try resolver.resolve(args[1]);
    defer allocator.free(verifier);
    const fake = try resolver.resolve(args[2]);
    defer allocator.free(fake);
    const nm = try resolver.resolve(args[3]);
    defer allocator.free(nm);
    const readelf = try resolver.resolve(args[4]);
    defer allocator.free(readelf);
    const objcopy = try resolver.resolve(args[5]);
    defer allocator.free(objcopy);
    const zig = try resolver.resolve(args[6]);
    defer allocator.free(zig);
    try std.Io.Dir.cwd().createDirPath(io, args[7]);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(io, args[7], allocator);
    defer allocator.free(root);
    const directory = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    var inputs: [8][]u8 = undefined;
    var loaded: usize = 0;
    defer for (inputs[0..loaded]) |input| allocator.free(input);
    for (args[8..], 0..) |input, index| {
        inputs[index] = try std.Io.Dir.cwd().realPathFileAlloc(io, input, allocator);
        loaded += 1;
    }
    var fixture: Fixture = .{
        .allocator = allocator,
        .io = io,
        .directory = directory,
        .root = root,
        .verifier = verifier,
        .fake = fake,
        .nm = nm,
        .readelf = readelf,
        .objcopy = objcopy,
        .zig = zig,
        .environment = init.environ_map,
    };
    const profiles = [_]proof.Profile{ .@"hyperv-runtime", .@"vmbus-protocol", .@"vmbus-channel", .@"storvsc-core", .@"netvsc-protocol" };
    for (profiles, inputs[0..5]) |profile, path_| {
        try fixture.check(profile, path_, 0, "");
        const symbol = proof.required(profile)[proof.required(profile).len - 1];
        const prefix = try std.fmt.allocPrint(allocator, "{s}_prefix_collision", .{symbol});
        defer allocator.free(prefix);
        const renamed = try fixture.renamed(path_, symbol, prefix, "prefix.o");
        defer allocator.free(renamed);
        try fixture.check(profile, renamed, 1, "MissingExport");
        const missing = try fixture.renamed(path_, symbol, "object_proof_missing", "missing.o");
        defer allocator.free(missing);
        try fixture.check(profile, missing, 1, "MissingExport");
        const local = try fixture.path("local.o");
        defer allocator.free(local);
        const localize = try std.fmt.allocPrint(allocator, "--localize-symbol={s}", .{symbol});
        defer allocator.free(localize);
        try fixture.command(&.{ objcopy, localize, path_, local });
        try fixture.check(profile, local, 1, "InvalidExport");
        const weak = try fixture.path("weak.o");
        defer allocator.free(weak);
        const weaken = try std.fmt.allocPrint(allocator, "--weaken-symbol={s}", .{symbol});
        defer allocator.free(weaken);
        try fixture.command(&.{ objcopy, weaken, path_, weak });
        try fixture.check(profile, weak, 1, "InvalidExport");
        const unresolved = try fixture.path("unresolved.o");
        defer allocator.free(unresolved);
        try fixture.command(&.{ zig, "cc", "-target", "x86_64-freestanding-none", "-nostdlib", "-r", path_, inputs[7], "-o", unresolved });
        try fixture.check(profile, unresolved, 1, "UndefinedSymbol");
        try exportFixtures(&fixture, profile, path_);
    }
    try pageFixtures(&fixture, inputs[0]);
    try mappingFixtures(&fixture, inputs[3], inputs[5], inputs[6]);
    try malformedFixtures(&fixture, inputs[0]);
    try toolFixtures(&fixture, inputs[2], inputs[0]);
    try fixture.expect(&.{}, 2, "InvalidArguments");
    try fixture.expect(&.{ "vmbus-channel", "--object" }, 2, "InvalidArguments");
    try fixture.expect(&.{ "vmbus-channel", "--object", inputs[2], "--object", inputs[2] }, 2, "InvalidArguments");
    try fixture.expect(&.{ "vmbus-channel", "--object", inputs[2], "--mapping-api-object", inputs[5] }, 2, "InvalidArguments");
    try fixture.expect(&.{ "architecture-notice", "--object", inputs[0] }, 2, "InvalidArguments");
    try fixture.expect(&.{"--help"}, 0, "");
    try fixture.expect(&.{"architecture-notice"}, 0, "");
    var out = std.Io.File.stdout().writer(io, &.{});
    try out.interface.print("Object proofs: {d} native CLI cases passed; no boot proof or architecture skip credit.\n", .{fixture.cases});
    const summary = try std.fmt.allocPrint(allocator, "{d} native CLI cases passed; no boot proof or architecture skip credit.\n", .{fixture.cases});
    defer allocator.free(summary);
    const result_path = try fixture.write("result.txt", summary);
    defer allocator.free(result_path);
}

fn exportFixtures(f: *Fixture, profile: proof.Profile, input: []const u8) !void {
    const bytes = try proof.readObject(f.allocator, f.io, input);
    defer f.allocator.free(bytes);
    const object = try format.Object.parse(f.allocator, bytes);
    defer object.deinit();
    const names = proof.required(profile);
    const name = names[names.len - 1];
    const symbol = try object.symbol(name);
    const offset = @as(usize, @intCast(object.sections[object.symbol_section].header.sh_offset)) + symbol.index * 24;
    for ([_]struct { field: usize, width: usize, value: u64, diagnostic: []const u8 }{
        .{ .field = 4, .width = 1, .value = 0x11, .diagnostic = "InvalidExport" },
        .{ .field = 5, .width = 1, .value = 2, .diagnostic = "InvalidExport" },
        .{ .field = 6, .width = 2, .value = std.elf.SHN_ABS, .diagnostic = "InvalidExport" },
        .{ .field = 6, .width = 2, .value = std.elf.SHN_COMMON, .diagnostic = "CommonSymbol" },
        .{ .field = 16, .width = 8, .value = 0, .diagnostic = "InvalidExport" },
        .{ .field = 8, .width = 8, .value = std.math.maxInt(u64), .diagnostic = "InvalidExport" },
    }) |change| {
        const bad = try f.allocator.dupe(u8, bytes);
        defer f.allocator.free(bad);
        const value = std.mem.toBytes(std.mem.nativeToLittle(u64, change.value));
        @memcpy(bad[offset + change.field ..][0..change.width], value[0..change.width]);
        const path_ = try f.write("export-property.o", bad);
        defer f.allocator.free(path_);
        try f.check(profile, path_, 1, change.diagnostic);
    }
    const duplicate = try f.renamed(input, name, names[0], "duplicate-export.o");
    defer f.allocator.free(duplicate);
    try f.check(profile, duplicate, 1, "DuplicateSymbol");
    var nm = try (try proof.tools.Tools.init(f.allocator, f.io, f.environment, 30000)).run(&.{ f.nm, "--format=posix", "--no-demangle", "-n", input });
    defer nm.deinit(f.allocator);
    try proof.checkNm(object, nm.stdout, names, false);
    const collided = try std.fmt.allocPrint(f.allocator, "{s}_collision", .{name});
    defer f.allocator.free(collided);
    const missing = try std.mem.replaceOwned(u8, f.allocator, nm.stdout, name, collided);
    defer f.allocator.free(missing);
    try testing.expectError(error.MissingNmSymbol, proof.checkNm(object, missing, names, false));
    const extra = try std.fmt.allocPrint(f.allocator, "{s}\n{s} T 0 0\n", .{ nm.stdout, name });
    defer f.allocator.free(extra);
    try testing.expectError(error.DuplicateNmSymbol, proof.checkNm(object, extra, names, false));
}

fn pageFixtures(f: *Fixture, input: []const u8) !void {
    const bytes = try proof.readObject(f.allocator, f.io, input);
    defer f.allocator.free(bytes);
    const object = try format.Object.parse(f.allocator, bytes);
    defer object.deinit();
    for (proof.pages) |page| {
        const section = try object.section(page.name);
        const prefix = try std.fmt.allocPrint(f.allocator, "--rename-section={s}={s}_collision", .{ page.name, page.name });
        defer f.allocator.free(prefix);
        const output = try f.path("page-name.o");
        defer f.allocator.free(output);
        try f.command(&.{ f.objcopy, prefix, input, output });
        try f.check(.@"hyperv-runtime", output, 1, "MissingSection");
        for ([_]struct { field: usize, value: u64, width: usize = 8 }{
            .{ .field = 32, .value = 4095 },
            .{ .field = 48, .value = 2048 },
            .{ .field = 8, .value = std.elf.SHF_ALLOC | std.elf.SHF_EXECINSTR },
            .{ .field = 8, .value = if (page.nobits) std.elf.SHF_ALLOC else std.elf.SHF_ALLOC | std.elf.SHF_WRITE },
            .{ .field = 4, .value = @intFromEnum(if (page.nobits) std.elf.SHT.PROGBITS else .NOBITS), .width = 4 },
        }) |change| {
            const bad = try f.allocator.dupe(u8, bytes);
            defer f.allocator.free(bad);
            const offset = @as(usize, @intCast(object.header.shoff)) + section.index * 64 + change.field;
            if (change.width == 4) {
                std.mem.writeInt(u32, bad[offset..][0..4], @intCast(change.value), .little);
            } else std.mem.writeInt(u64, bad[offset..][0..8], change.value, .little);
            const path_ = try f.write("page-property.o", bad);
            defer f.allocator.free(path_);
            try f.check(.@"hyperv-runtime", path_, 1, "");
        }
        const symbol = try object.symbol(page.symbol);
        const storage = try f.allocator.dupe(u8, bytes);
        defer f.allocator.free(storage);
        const symbol_offset = @as(usize, @intCast(object.sections[object.symbol_section].header.sh_offset)) + symbol.index * 24;
        std.mem.writeInt(u64, storage[symbol_offset + 16 ..][0..8], 4095, .little);
        const storage_path = try f.write("page-storage.o", storage);
        defer f.allocator.free(storage_path);
        try f.check(.@"hyperv-runtime", storage_path, 1, "InvalidPageStorage");
    }
    var section_output = try (try proof.tools.Tools.init(f.allocator, f.io, f.environment, 30000)).run(&.{ f.readelf, "-SW", input });
    defer section_output.deinit(f.allocator);
    try proof.checkSections(object, section_output.stdout);
    const spoof = try std.mem.replaceOwned(u8, f.allocator, section_output.stdout, "001000", "000fff");
    defer f.allocator.free(spoof);
    try testing.expectError(error.InconsistentReadelfOutput, proof.checkSections(object, spoof));
}

fn mappingFixtures(f: *Fixture, core: []const u8, c: []const u8, cpp: []const u8) !void {
    try f.expect(&.{ "storvsc-core", "--object", core, "--nm", f.nm, "--mapping-api-object", c, "--mapping-api-object", cpp }, 0, "");
    try f.expect(&.{ "storvsc-core", "--object", core, "--nm", f.nm, "--mapping-api-object", cpp, "--mapping-api-object", c, "--mapping-api-object", cpp }, 0, "");
    for (proof.mapping_names) |name| {
        const mangled = try std.fmt.allocPrint(f.allocator, "{s}_mangled", .{name});
        defer f.allocator.free(mangled);
        const bad = try f.renamed(cpp, name, mangled, "bad-mapping.o");
        defer f.allocator.free(bad);
        try f.expect(&.{ "storvsc-core", "--object", core, "--nm", f.nm, "--mapping-api-object", c, "--mapping-api-object", bad }, 1, "MissingExport");
        try f.expect(&.{ "storvsc-core", "--object", core, "--nm", f.nm, "--mapping-api-object", bad, "--mapping-api-object", cpp }, 1, "MissingExport");
    }
    const detached = try f.path("no-mapping-relocations.o");
    defer f.allocator.free(detached);
    try f.command(&.{ f.objcopy, "--remove-section=.rela.text", cpp, detached });
    try f.expect(&.{ "storvsc-core", "--object", core, "--nm", f.nm, "--mapping-api-object", detached }, 1, "MissingMappingRelocation");
    const bytes = try proof.readObject(f.allocator, f.io, cpp);
    defer f.allocator.free(bytes);
    const object = try format.Object.parse(f.allocator, bytes);
    defer object.deinit();
    const symbol = try object.symbol(proof.mapping_names[0]);
    const offset = @as(usize, @intCast(object.sections[object.symbol_section].header.sh_offset)) + symbol.index * 24;
    for ([_]struct { field: usize, value: u8 }{
        .{ .field = 4, .value = 0x20 },
        .{ .field = 5, .value = 2 },
        .{ .field = 6, .value = 1 },
    }) |change| {
        const bad = try f.allocator.dupe(u8, bytes);
        defer f.allocator.free(bad);
        bad[offset + change.field] = change.value;
        const path_ = try f.write("mapping-property.o", bad);
        defer f.allocator.free(path_);
        try f.expect(&.{ "storvsc-core", "--object", core, "--nm", f.nm, "--mapping-api-object", path_ }, 1, "InvalidMappingReference");
    }
}

fn malformedFixtures(f: *Fixture, input: []const u8) !void {
    const bytes = try proof.readObject(f.allocator, f.io, input);
    defer f.allocator.free(bytes);
    for ([_]usize{ 0, 4, 16, 63, bytes.len - 1 }) |size| {
        const truncated = try f.write("truncated.o", bytes[0..size]);
        defer f.allocator.free(truncated);
        try f.check(.@"hyperv-runtime", truncated, 1, "");
    }
    for ([_]struct { offset: usize, byte: u8 }{
        .{ .offset = 0, .byte = 'X' },  .{ .offset = 4, .byte = 1 },
        .{ .offset = 5, .byte = 2 },    .{ .offset = 16, .byte = 2 },
        .{ .offset = 18, .byte = 183 }, .{ .offset = 58, .byte = 1 },
    }) |change| {
        const bad = try f.allocator.dupe(u8, bytes);
        defer f.allocator.free(bad);
        bad[change.offset] = change.byte;
        const path_ = try f.write("malformed.o", bad);
        defer f.allocator.free(path_);
        try f.check(.@"hyperv-runtime", path_, 1, "");
    }
    for ([_]struct { offset: usize, value: u64, width: usize }{
        .{ .offset = 40, .value = std.math.maxInt(u64), .width = 8 },
        .{ .offset = 60, .value = 4097, .width = 2 },
        .{ .offset = 60, .value = 0, .width = 2 },
        .{ .offset = 62, .value = 0xffff, .width = 2 },
    }) |change| {
        const bad = try f.allocator.dupe(u8, bytes);
        defer f.allocator.free(bad);
        const value = std.mem.toBytes(std.mem.nativeToLittle(u64, change.value));
        @memcpy(bad[change.offset..][0..change.width], value[0..change.width]);
        const path_ = try f.write("malformed-table.o", bad);
        defer f.allocator.free(path_);
        try f.check(.@"hyperv-runtime", path_, 1, "");
    }
    const oversized = try f.path("oversized.o");
    defer f.allocator.free(oversized);
    const file = try std.Io.Dir.cwd().createFile(f.io, oversized, .{});
    defer file.close(f.io);
    try file.setLength(f.io, format.maximum_file + 1);
    try f.check(.@"hyperv-runtime", oversized, 1, "ObjectTooLarge");
    try f.check(.@"hyperv-runtime", f.root, 1, "InvalidObjectFile");
}

fn toolFixtures(f: *Fixture, input: []const u8, runtime: []const u8) !void {
    const absent = try f.path("absent-tool");
    defer f.allocator.free(absent);
    try f.expect(&.{ "vmbus-channel", "--object", input, "--nm", absent }, 1, "");
    const bad_tool = try f.write("bad-tool", "not a native executable\n");
    defer f.allocator.free(bad_tool);
    const executable = try std.Io.Dir.cwd().openFile(f.io, bad_tool, .{});
    defer executable.close(f.io);
    try executable.setPermissions(f.io, .fromMode(0o700));
    try f.expect(&.{ "vmbus-channel", "--object", input, "--nm", bad_tool }, 1, "ToolFailed");
    for ([_]struct { mode: []const u8, diagnostic: []const u8 }{
        .{ .mode = "fail", .diagnostic = "ToolFailed" },
        .{ .mode = "silent", .diagnostic = "MissingNmSymbol" },
        .{ .mode = "malformed", .diagnostic = "InvalidNmOutput" },
        .{ .mode = "stdout-limit", .diagnostic = "ToolOutputLimit" },
        .{ .mode = "stderr-limit", .diagnostic = "ToolOutputLimit" },
        .{ .mode = "hang", .diagnostic = "ToolTimeout" },
    }) |case| {
        const mode = try f.write("tool-mode", case.mode);
        defer f.allocator.free(mode);
        try f.expect(&.{ "vmbus-channel", "--object", input, "--nm", f.fake, "--timeout-ms", if (std.mem.eql(u8, case.mode, "hang")) "50" else "5000" }, 1, case.diagnostic);
    }
    const mode = try f.write("tool-mode", "silent");
    defer f.allocator.free(mode);
    try f.expect(&.{ "hyperv-runtime", "--object", runtime, "--nm", f.nm, "--readelf", f.fake }, 1, "MissingReadelfSection");
}
