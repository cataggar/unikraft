// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const probes = @import("runtime_probes.zig");
const types = @import("types.zig");
const records = @import("records.zig");
const tx = @import("transaction.zig");
const a = std.testing.allocator;
const io = std.testing.io;
const linux = std.os.linux;
const t = std.testing;
const fixture_path = if (@hasDecl(@import("test_options"), "probe_fixture"))
    @import("test_options").probe_fixture
else
    @import("test_options").process_fixture;

pub const Synthetic = struct {
    role: probes.ElfRole,
    interpreter: []const u8 = "/native/ld-linux-x86-64.so.2",
    needed: []const []const u8 = &.{},
    soname: ?[]const u8 = null,
    alternate: ?i64 = null,
};
fn integer(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}
fn program(bytes: []u8, index: usize, kind: u32, offset: u64, size: u64, flags: u32) void {
    const at = 64 + index * 56;
    integer(u32, bytes, at, kind);
    integer(u32, bytes, at + 4, flags);
    integer(u64, bytes, at + 8, offset);
    integer(u64, bytes, at + 16, 0x400000 + offset);
    integer(u64, bytes, at + 32, size);
    integer(u64, bytes, at + 40, size);
    integer(u64, bytes, at + 48, if (kind == std.elf.PT_LOAD) 0x1000 else 8);
}
fn dynamic(bytes: []u8, index: usize, tag: i64, value: u64) void {
    integer(i64, bytes, 0x200 + index * 16, tag);
    integer(u64, bytes, 0x208 + index * 16, value);
}
/// Data-only images: never made executable, sealed, or accepted as a runtime.
pub fn synthetic(config: Synthetic) ![2048]u8 {
    var bytes = [_]u8{0} ** 2048;
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    integer(u16, &bytes, 16, 3);
    integer(u16, &bytes, 18, @intFromEnum(std.elf.EM.X86_64));
    integer(u32, &bytes, 20, 1);
    integer(u64, &bytes, 24, 0x400080);
    integer(u64, &bytes, 32, 64);
    integer(u16, &bytes, 52, 64);
    integer(u16, &bytes, 54, 56);
    integer(u16, &bytes, 56, if (config.role == .interpreter) 3 else 2);
    program(&bytes, 0, std.elf.PT_LOAD, 0, bytes.len, std.elf.PF_R | std.elf.PF_X);
    program(&bytes, 1, std.elf.PT_DYNAMIC, 0x200, 96, std.elf.PF_R);
    if (config.role == .interpreter) {
        if (config.interpreter.len >= 256) return error.InvalidSynthetic;
        @memcpy(bytes[0x100..][0..config.interpreter.len], config.interpreter);
        program(&bytes, 2, std.elf.PT_INTERP, 0x100, config.interpreter.len + 1, std.elf.PF_R);
    }
    var cursor: usize = 1;
    var entry: usize = 2;
    for (config.needed) |name| {
        @memcpy(bytes[0x380 + cursor ..][0..name.len], name);
        dynamic(&bytes, entry, std.elf.DT_NEEDED, cursor);
        cursor += name.len + 1;
        entry += 1;
    }
    if (config.soname) |name| {
        @memcpy(bytes[0x380 + cursor ..][0..name.len], name);
        dynamic(&bytes, entry, std.elf.DT_SONAME, cursor);
        cursor += name.len + 1;
        entry += 1;
    }
    if (config.alternate) |tag| {
        @memcpy(bytes[0x380 + cursor ..][0.."$ORIGIN/lib".len], "$ORIGIN/lib");
        dynamic(&bytes, entry, tag, cursor);
        cursor += "$ORIGIN/lib".len + 1;
        entry += 1;
    }
    if (entry >= 6) return error.InvalidSynthetic;
    dynamic(&bytes, 0, std.elf.DT_STRTAB, 0x400380);
    dynamic(&bytes, 1, std.elf.DT_STRSZ, cursor);
    return bytes;
}

test "data-only x86 ELF interpreter and dynamic needed parse independently of host" {
    const bytes = try synthetic(.{ .role = .interpreter, .needed = &.{"libalpha.so"} });
    var info = try probes.inspectElf(a, &bytes, .interpreter);
    defer info.deinit();
    try t.expectEqualStrings("/native/" ++ probes.loader_basename, info.interpreter.?);
    try t.expectEqualStrings("libalpha.so", info.needed[0]);
    const loader_bytes = try synthetic(.{ .role = .loader, .soname = probes.loader_basename });
    var loader = try probes.inspectElf(a, &loader_bytes, .loader);
    defer loader.deinit();
    try t.expectEqualStrings(probes.loader_basename, loader.soname.?);
    var executable_libc = try probes.inspectElf(a, &bytes, .library);
    defer executable_libc.deinit();
    try t.expectEqualStrings(info.interpreter.?, executable_libc.interpreter.?);
}

test "ELF interpreter architecture format entry and program bounds refuse" {
    const original = try synthetic(.{ .role = .interpreter });
    {
        var bytes = original;
        integer(u16, &bytes, 18, @intFromEnum(std.elf.EM.AARCH64));
        try t.expectError(error.InvalidElf, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        var bytes = original;
        bytes[5] = 2;
        try t.expectError(error.InvalidElf, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        var bytes = original;
        integer(u64, &bytes, 24, 0x500000);
        try t.expectError(error.InvalidEntry, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        var bytes = original;
        integer(u16, &bytes, 56, 1025);
        try t.expectError(error.InvalidElf, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        var bytes = original;
        integer(u64, &bytes, 32, std.math.maxInt(u64));
        try t.expectError(error.Truncated, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        var bytes = original;
        integer(u16, &bytes, 56, 2);
        try t.expectError(error.MissingInterpreter, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        var bytes = original;
        @memcpy(bytes[120..176], bytes[176..232]);
        try t.expectError(error.InvalidInterpreter, probes.inspectElf(a, &bytes, .interpreter));
    }
    {
        const bytes = try synthetic(.{ .role = .interpreter, .interpreter = "/native/wrong-loader" });
        try t.expectError(error.InvalidInterpreter, probes.inspectElf(a, &bytes, .interpreter));
    }
    try t.expectError(error.InvalidElf, probes.inspectElf(a, "not ELF", .interpreter));
    try t.expectError(error.Truncated, probes.inspectElf(a, original[0..2047], .interpreter));
}

test "ELF frozen alternate lookup includes ORIGIN RPATH RUNPATH and auxiliary filter tags" {
    for ([_]i64{ std.elf.DT_RPATH, std.elf.DT_RUNPATH, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff }) |tag| {
        const bytes = try synthetic(.{ .role = .library, .alternate = tag });
        try t.expectError(error.AlternateLookupForbidden, probes.inspectElf(a, &bytes, .library));
    }
}

const token_names = [_][]const u8{
    "$ORIGIN.so", "${ORIGIN}.so", "$LIB.so", "${LIB}.so", "$PLATFORM.so", "${PLATFORM}.so",
};

test "ELF dependency and SONAME tokens cannot turn literal basenames into loader paths" {
    // Multiarch glibc can expand "$LIB.so" to "lib/x86_64-linux-gnu.so",
    // a relative path outside the declared loader directory. No image is run.
    for (token_names) |name| {
        try core.private_files.basename(name);
        for ([_]probes.ElfRole{ .interpreter, .native_extension }) |role| {
            const bytes = try synthetic(.{ .role = role, .needed = &.{name} });
            try t.expectError(error.InvalidDependencyName, probes.inspectElf(a, &bytes, role));
        }
        const bytes = try synthetic(.{ .role = .library, .soname = name });
        try t.expectError(error.InvalidDependencyName, probes.inspectElf(a, &bytes, .library));
    }
}

test "ELF dynamic strings duplicates mapping and terminator bounds refuse" {
    {
        const bytes = try synthetic(.{ .role = .library, .needed = &.{ "libalpha.so", "libalpha.so" } });
        try t.expectError(error.DuplicateDependency, probes.inspectElf(a, &bytes, .library));
    }
    {
        const bytes = try synthetic(.{ .role = .library, .needed = &.{"../libalpha.so"} });
        try t.expectError(error.UnsafePath, probes.inspectElf(a, &bytes, .library));
    }
    {
        var bytes = try synthetic(.{ .role = .library, .needed = &.{"libalpha.so"} });
        dynamic(&bytes, 2, std.elf.DT_NEEDED, 4096);
        try t.expectError(error.InvalidStringTable, probes.inspectElf(a, &bytes, .library));
    }
    {
        var bytes = try synthetic(.{ .role = .library });
        dynamic(&bytes, 1, std.elf.DT_STRSZ, 16 * 1024 * 1024 + 1);
        try t.expectError(error.InvalidDynamic, probes.inspectElf(a, &bytes, .library));
    }
    {
        var bytes = try synthetic(.{ .role = .library });
        integer(u16, &bytes, 56, 3);
        program(&bytes, 2, std.elf.PT_LOAD, 0, bytes.len, std.elf.PF_R);
        try t.expectError(error.AmbiguousLoad, probes.inspectElf(a, &bytes, .library));
    }
    {
        var bytes = try synthetic(.{ .role = .library });
        integer(u64, &bytes, 120 + 32, 4097 * 16);
        try t.expectError(error.Truncated, probes.inspectElf(a, &bytes, .library));
    }
    {
        var bytes = try synthetic(.{ .role = .library });
        dynamic(&bytes, 0, std.elf.DT_STRTAB, 0x4007ff);
        dynamic(&bytes, 1, std.elf.DT_STRSZ, 2);
        try t.expectError(error.UnloadedDynamic, probes.inspectElf(a, &bytes, .library));
    }
    {
        var bytes = try synthetic(.{ .role = .library });
        for (2..6) |index| dynamic(&bytes, index, 21, 0);
        try t.expectError(error.InvalidDynamic, probes.inspectElf(a, &bytes, .library));
    }
    {
        const bytes = try synthetic(.{ .role = .loader, .needed = &.{"libalpha.so"}, .soname = probes.loader_basename });
        try t.expectError(error.InvalidLoader, probes.inspectElf(a, &bytes, .loader));
    }
}

const Fixture = struct {
    parent: std.Io.Dir,
    dir: std.Io.Dir,
    name: []u8,
    path: []u8,
    fn init() !Fixture {
        const parent = try std.Io.Dir.openDirAbsolute(io, @import("test_options").fixture_root, .{});
        errdefer parent.close(io);
        const name = try std.fmt.allocPrint(a, "runtime-probes-{d}", .{linux.getpid()});
        errdefer a.free(name);
        try parent.createDir(io, name, .fromMode(0o700));
        errdefer parent.deleteTree(io, name) catch @panic("probe fixture cleanup");
        const dir = try parent.openDir(io, name, .{ .iterate = true });
        errdefer dir.close(io);
        return .{ .parent = parent, .dir = dir, .name = name, .path = try std.fs.path.join(a, &.{ @import("test_options").fixture_root, name }) };
    }
    fn deinit(self: Fixture) void {
        self.dir.close(io);
        self.parent.deleteTree(io, self.name) catch @panic("probe fixture cleanup");
        self.parent.close(io);
        a.free(self.name);
        a.free(self.path);
    }
    fn write(self: Fixture, name: []const u8, bytes: []const u8) !void {
        const file = try self.dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
    }
    fn retained(self: Fixture, name: []const u8) !OwnedSource {
        const path = try std.fs.path.join(a, &.{ self.path, name });
        errdefer a.free(path);
        return .{ .path = path, .file = try core.private_files.RetainedFile.open(io, path, .artifact) };
    }
};
const OwnedSource = struct {
    path: []u8,
    file: core.private_files.RetainedFile,
    fn deinit(self: *OwnedSource) void {
        self.file.close(io);
        a.free(self.path);
    }
};

test "discovery closes explicit retained DSO chain refuses missing and distinct basename bytes" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const loader_path = try std.fs.path.join(a, &.{ fixture.path, probes.loader_basename });
    defer a.free(loader_path);
    try fixture.write(probes.loader_basename, &(try synthetic(.{ .role = .loader, .soname = probes.loader_basename })));
    try fixture.write("python", &(try synthetic(.{ .role = .interpreter, .interpreter = loader_path, .needed = &.{"libalpha.so"} })));
    try fixture.write("libalpha.so", &(try synthetic(.{ .role = .library, .needed = &.{"libbeta.so"}, .soname = "libalpha.so" })));
    try fixture.write("libbeta.so", &(try synthetic(.{ .role = .library, .soname = "libbeta.so" })));
    var loader = try fixture.retained(probes.loader_basename);
    defer loader.deinit();
    var python = try fixture.retained("python");
    defer python.deinit();
    var alpha = try fixture.retained("libalpha.so");
    defer alpha.deinit();
    var beta = try fixture.retained("libbeta.so");
    defer beta.deinit();
    const ctx: types.Context = .{ .allocator = a, .io = io };
    const input: probes.DiscoveryInput = .{ .interpreter = &python.file, .dynamic_loader = &loader.file, .native_roots = &.{}, .candidates = &.{ &alpha.file, &beta.file } };
    var discovered = try probes.discover(ctx, input);
    defer discovered.deinit();
    try t.expectEqual(@as(usize, 3), discovered.inventory.dependencies.len);
    var missing = input;
    missing.candidates = &.{&alpha.file};
    try t.expectError(error.MissingDependency, probes.discover(ctx, missing));
    try fixture.dir.createDir(io, "second", .fromMode(0o700));
    const second = try fixture.dir.openDir(io, "second", .{});
    defer second.close(io);
    const duplicate_file = try second.createFile(io, "libalpha.so", .{ .permissions = .fromMode(0o600) });
    try duplicate_file.writeStreamingAll(io, &(try synthetic(.{ .role = .library, .soname = "libalpha.so" })));
    duplicate_file.close(io);
    var collision = try fixture.retained("second/libalpha.so");
    defer collision.deinit();
    var colliding = input;
    colliding.candidates = &.{ &alpha.file, &beta.file, &collision.file };
    try t.expectError(error.LoaderBasenameCollision, probes.discover(ctx, colliding));
    const alpha_bytes = try synthetic(.{ .role = .library, .needed = &.{"libbeta.so"}, .soname = "libalpha.so" });
    try fixture.write("libalpha.so.1.2", &alpha_bytes);
    var versioned = try fixture.retained("libalpha.so.1.2");
    defer versioned.deinit();
    var aliased = input;
    aliased.candidates = &.{ &versioned.file, &beta.file };
    aliased.candidate_names = &.{ "libalpha.so", "libbeta.so" };
    var named = try probes.discover(ctx, aliased);
    defer named.deinit();
    try t.expectEqualStrings("libalpha.so", named.names[1]);
    try t.expectEqualStrings(versioned.file.path, named.inventory.dependencies[1].file.path);
    aliased.candidates = &.{ &alpha.file, &versioned.file, &beta.file };
    aliased.candidate_names = &.{ "libalpha.so", "libalpha.so", "libbeta.so" };
    var identical = try probes.discover(ctx, aliased);
    defer identical.deinit();
    try t.expectEqual(@as(usize, 3), identical.names.len);
    aliased.candidate_names = &.{"libalpha.so"};
    try t.expectError(error.InvalidDependencyNames, probes.discover(ctx, aliased));
    try fixture.write("extension.so", &(try synthetic(.{ .role = .native_extension, .needed = &.{"libmissing.so"} })));
    var extension = try fixture.retained("extension.so");
    defer extension.deinit();
    var unclosed = input;
    unclosed.native_roots = &.{&extension.file};
    try t.expectError(error.MissingDependency, probes.discover(ctx, unclosed));
}

test "discovery rejects tokenized explicit and source-basename placements before inventory" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const loader_path = try std.fs.path.join(a, &.{ fixture.path, probes.loader_basename });
    defer a.free(loader_path);
    try fixture.write("python", &(try synthetic(.{ .role = .interpreter, .interpreter = loader_path })));
    try fixture.write(probes.loader_basename, &(try synthetic(.{ .role = .loader, .soname = probes.loader_basename })));
    const library_bytes = try synthetic(.{ .role = .library, .soname = "libalpha.so" });
    try fixture.write("libalpha.so", &library_bytes);
    try fixture.write("$LIB.so", &library_bytes);
    var python = try fixture.retained("python");
    defer python.deinit();
    var loader = try fixture.retained(probes.loader_basename);
    defer loader.deinit();
    var library = try fixture.retained("libalpha.so");
    defer library.deinit();
    var tokenized_source = try fixture.retained("$LIB.so");
    defer tokenized_source.deinit();
    var input: probes.DiscoveryInput = .{
        .interpreter = &python.file,
        .dynamic_loader = &loader.file,
        .native_roots = &.{},
        .candidates = &.{&library.file},
    };
    const ctx: types.Context = .{ .allocator = a, .io = io };
    for (token_names) |name| {
        input.candidate_names = &.{name};
        try t.expectError(error.InvalidDependencyName, probes.discover(ctx, input));
    }
    input.candidate_names = null;
    input.candidates = &.{&tokenized_source.file};
    try t.expectError(error.InvalidDependencyName, probes.discover(ctx, input));
}

test "retained ELF source rejects same bytes inode replacement and ancestor rename" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const path = try std.fs.path.join(a, &.{ fixture.path, probes.loader_basename });
    defer a.free(path);
    const bytes = try synthetic(.{ .role = .interpreter, .interpreter = path });
    try fixture.write("python", &bytes);
    try fixture.write(probes.loader_basename, &(try synthetic(.{ .role = .loader, .soname = probes.loader_basename })));
    var python = try fixture.retained("python");
    defer python.deinit();
    var loader = try fixture.retained(probes.loader_basename);
    defer loader.deinit();
    try fixture.dir.rename("python", fixture.dir, "old-python", io);
    try fixture.write("python", &bytes);
    const input: probes.DiscoveryInput = .{ .interpreter = &python.file, .dynamic_loader = &loader.file, .native_roots = &.{}, .candidates = &.{} };
    try t.expectError(error.FileChanged, probes.discover(.{ .allocator = a, .io = io }, input));
    try fixture.dir.rename("python", fixture.dir, "new-python", io);
    try fixture.dir.rename("old-python", fixture.dir, "python", io);
    var current = try fixture.retained("python");
    defer current.deinit();
    const loader_bytes = try synthetic(.{ .role = .loader, .soname = probes.loader_basename });
    try fixture.dir.rename(probes.loader_basename, fixture.dir, "old-loader", io);
    try fixture.write(probes.loader_basename, &loader_bytes);
    var loader_replaced = input;
    loader_replaced.interpreter = &current.file;
    try t.expectError(error.FileChanged, probes.discover(.{ .allocator = a, .io = io }, loader_replaced));
    try fixture.dir.rename(probes.loader_basename, fixture.dir, "new-loader", io);
    try fixture.dir.rename("old-loader", fixture.dir, probes.loader_basename, io);
    var current_loader = try fixture.retained(probes.loader_basename);
    defer current_loader.deinit();
    const moved = try std.fmt.allocPrint(a, "{s}-moved", .{fixture.name});
    defer a.free(moved);
    try fixture.parent.rename(fixture.name, fixture.parent, moved, io);
    defer fixture.parent.deleteTree(io, moved) catch @panic("moved probe fixture cleanup");
    try fixture.parent.createDir(io, fixture.name, .fromMode(0o700));
    var replaced = input;
    replaced.interpreter = &current.file;
    replaced.dynamic_loader = &current_loader.file;
    try t.expectError(error.FileChanged, probes.discover(.{ .allocator = a, .io = io }, replaced));
}

test "native source hard links and sparse over-limit DSOs cannot enter inventory" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const loader_path = try std.fs.path.join(a, &.{ fixture.path, probes.loader_basename });
    defer a.free(loader_path);
    try fixture.write("python", &(try synthetic(.{ .role = .interpreter, .interpreter = loader_path })));
    try fixture.write(probes.loader_basename, &(try synthetic(.{ .role = .loader, .soname = probes.loader_basename })));
    try fixture.write("libalpha.so", &(try synthetic(.{ .role = .library, .soname = "libalpha.so" })));
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.linkat(fixture.dir.handle, "libalpha.so", fixture.dir.handle, "linked.so", 0)));
    var python = try fixture.retained("python");
    defer python.deinit();
    var loader = try fixture.retained(probes.loader_basename);
    defer loader.deinit();
    var alpha = try fixture.retained("libalpha.so");
    defer alpha.deinit();
    var input: probes.DiscoveryInput = .{ .interpreter = &python.file, .dynamic_loader = &loader.file, .native_roots = &.{}, .candidates = &.{&alpha.file} };
    const ctx: types.Context = .{ .allocator = a, .io = io };
    try t.expectError(error.InvalidNativeSource, probes.discover(ctx, input));
    const file = try fixture.dir.createFile(io, "oversized.so", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.ftruncate(file.handle, types.runtime.max_file_bytes + 1)));
    var oversized = try fixture.retained("oversized.so");
    defer oversized.deinit();
    input.candidates = &.{&oversized.file};
    try t.expectError(error.InvalidNativeSource, probes.discover(ctx, input));
}

test "copied structural home refuses mutable modes lib64 substitution and missing stdlib" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    var parsed = try goldenRuntime(allocator);
    defer parsed.deinit();
    var contract = parsed.value;
    const root_path = try std.fs.path.join(allocator, &.{ fixture.path, "runtime" });
    const loader_path = try std.fs.path.join(allocator, &.{ root_path, "loader", probes.loader_basename });
    const layout: types.RuntimeLayout = .{
        .output = fixture.path,
        .root = root_path,
        .launcher = try std.fs.path.join(allocator, &.{ root_path, "bootstrap", "azure-cli" }),
        .interpreter = try std.fs.path.join(allocator, &.{ root_path, "bin", "python" }),
        .extensions = try std.fs.path.join(allocator, &.{ root_path, "extensions" }),
        .loader_directory = std.fs.path.dirname(loader_path).?,
        .startup_config = try std.fs.path.join(allocator, &.{ fixture.path, "startup-config" }),
        .python_version = contract.python_version,
    };
    contract.root = root_path;
    contract.launcher.path = layout.launcher;
    contract.interpreter.path = layout.interpreter;
    contract.extensions = layout.extensions;
    contract.dynamic_loader.path = loader_path;
    contract.manifest.path = try std.fs.path.join(allocator, &.{ fixture.path, "azure-runtime.manifest" });
    const dependencies = try allocator.dupe(types.runtime.Artifact, contract.loader_dependencies);
    for (dependencies) |*dependency|
        dependency.path = try std.fs.path.join(allocator, &.{ layout.loader_directory, std.fs.path.basename(dependency.path) });
    contract.loader_dependencies = dependencies;
    try fixture.dir.createDir(io, "runtime", .fromMode(0o700));
    const root = try fixture.dir.openDir(io, "runtime", .{ .iterate = true });
    defer root.close(io);
    defer _ = linux.fchmod(root.handle, 0o700);
    const ctx: types.Context = .{ .allocator = a, .io = io };
    try t.expectError(error.InvalidCopiedMode, probes.requireCopiedLayout(ctx, root, layout, contract));
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(root.handle, 0o500)));
    try t.expectError(error.FileNotFound, probes.requireCopiedLayout(ctx, root, layout, contract));
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(root.handle, 0o700)));
    try root.createDir(io, "lib64", .fromMode(0o500));
    defer root.deleteTree(io, "lib64") catch @panic("lib64 fixture cleanup");
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(root.handle, 0o500)));
    try t.expectError(error.InvalidRuntimeLayout, probes.requireCopiedLayout(ctx, root, layout, contract));
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(root.handle, 0o700)));
}

fn goldenRuntime(allocator: std.mem.Allocator) !std.json.Parsed(types.runtime.Contract) {
    var document = try @import("contracts.zig").parseCanonical(allocator, @embedFile("goldens/contracts.json"));
    defer document.deinit();
    return records.parse(types.runtime.Contract, allocator, document.value().object.get("canonical_records").?.object.get("azure_runtime").?.string);
}
fn goldenLayout(contract: types.runtime.Contract) types.RuntimeLayout {
    const root = contract.root;
    return .{
        .output = root[0 .. root.len - "/runtime".len],
        .root = root,
        .launcher = contract.launcher.path,
        .interpreter = contract.interpreter.path,
        .extensions = contract.extensions,
        .loader_directory = std.fs.path.dirname(contract.dynamic_loader.path).?,
        .startup_config = "/golden/authority/output/runtime-prep/startup-config",
        .python_version = contract.python_version,
    };
}

test "all closed commands plus loader version imports preserve frozen flags and clean environment" {
    var parsed = try goldenRuntime(a);
    defer parsed.deinit();
    var layout = goldenLayout(parsed.value);
    const config = try std.fs.path.join(a, &.{ layout.output, "startup-config" });
    defer a.free(config);
    layout.startup_config = config;
    var env = try probes.environment(a, layout, parsed.value);
    defer env.deinit();
    try t.expectEqualStrings(layout.root, env.get("PYTHONHOME").?);
    for ([_][]const u8{ "PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONPATH", "PYTHONSTARTUP", "HTTP_PROXY", "AZURE_CLIENT_SECRET" }) |key|
        try t.expect(env.get(key) == null);
    for (parsed.value.commands, 0..) |command, index| {
        const argv = try probes.arguments(a, layout, parsed.value, .{ .command = @intCast(index) });
        defer a.free(argv);
        try t.expectEqual(@as(usize, 12 + command.len + (if (index == 0) @as(usize, 3) else 1)), argv.len);
        try t.expectEqualStrings(parsed.value.dynamic_loader.path, argv[0]);
        const prefix = [_][]const u8{ "--inhibit-cache", "--inhibit-rpath", "", "--library-path", layout.loader_directory, layout.interpreter, "-s", "-S", "-B", "-P", layout.launcher };
        for (prefix, argv[1..12]) |expected, actual| try t.expectEqualStrings(expected, actual);
        for (command, argv[12 .. 12 + command.len]) |expected, actual| try t.expectEqualStrings(expected, actual);
        if (index == 0) {
            for ([_][]const u8{ "--output", "json", "--only-show-errors" }, argv[argv.len - 3 ..]) |expected, actual| try t.expectEqualStrings(expected, actual);
        } else try t.expectEqualStrings("--help", argv[argv.len - 1]);
    }
    for ([_]probes.Step{ .loader_listing, .python_version, .imports }) |step| {
        const argv = try probes.arguments(a, layout, parsed.value, step);
        defer a.free(argv);
        if (step == .loader_listing) {
            try t.expectEqualStrings("--list", argv[6]);
            try t.expectEqualStrings(layout.interpreter, argv[7]);
        } else {
            try t.expectEqualStrings("-s", argv[7]);
            try t.expectEqualStrings("-P", argv[10]);
            try t.expectEqualStrings(if (step == .imports) "-c" else "--version", argv[11]);
        }
    }
    try t.expectError(error.UnknownProbe, probes.arguments(a, layout, parsed.value, .{ .command = 16 }));
    var oversized = parsed.value;
    oversized.interpreter.size = 64 * 1024 * 1024 + 1;
    try t.expectError(error.InvalidRuntimeLayout, probes.arguments(a, layout, oversized, .python_version));
    layout.loader_directory = "/outside";
    try t.expectError(error.InvalidRuntimeLayout, probes.arguments(a, layout, parsed.value, .imports));
}

test "copied token placements refuse before ELF evidence command construction or probing" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var parsed = try goldenRuntime(a);
    defer parsed.deinit();
    var layout = goldenLayout(parsed.value);
    const config = try std.fs.path.join(a, &.{ layout.output, "startup-config" });
    defer a.free(config);
    layout.startup_config = config;
    const declarations = try a.alloc(types.runtime.Artifact, parsed.value.loader_dependencies.len + 1);
    defer a.free(declarations);
    @memcpy(declarations[1..], parsed.value.loader_dependencies);
    for (token_names) |name| {
        const path = try std.fs.path.join(a, &.{ layout.loader_directory, name });
        defer a.free(path);
        declarations[0] = parsed.value.dynamic_loader;
        declarations[0].path = path;
        var contract = parsed.value;
        contract.loader_dependencies = declarations;
        contract.observed.loader_files = @intCast(declarations.len);
        try contract.validate();
        try t.expectError(error.InvalidDependencyName, probes.arguments(a, layout, contract, .loader_listing));
        try t.expectError(error.InvalidDependencyName, probes.environment(a, layout, contract));
        var checks: Checks = .{};
        try t.expectError(error.InvalidDependencyName, probes.inspectCopied(.{ .allocator = a, .io = io }, .{
            .root = fixture.dir,
            .layout = layout,
            .contract = contract,
            .barrier = checks.barrier(),
        }));
    }
}

test "library path cannot expand a matching literal copied-runtime root" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();
    var parsed = try goldenRuntime(allocator);
    defer parsed.deinit();
    var contract = parsed.value;
    const output = try std.fs.path.join(allocator, &.{ goldenLayout(contract).output, "$LIB" });
    const root = try std.fs.path.join(allocator, &.{ output, "runtime" });
    const layout: types.RuntimeLayout = .{
        .output = output,
        .root = root,
        .launcher = try std.fs.path.join(allocator, &.{ root, "bootstrap", "azure-cli" }),
        .interpreter = try std.fs.path.join(allocator, &.{ root, "bin", "python" }),
        .extensions = try std.fs.path.join(allocator, &.{ root, "extensions" }),
        .loader_directory = try std.fs.path.join(allocator, &.{ root, "loader" }),
        .startup_config = try std.fs.path.join(allocator, &.{ output, "startup-config" }),
        .python_version = contract.python_version,
    };
    contract.root = root;
    contract.launcher.path = layout.launcher;
    contract.interpreter.path = layout.interpreter;
    contract.extensions = layout.extensions;
    contract.manifest.path = try std.fs.path.join(allocator, &.{ output, "azure-runtime.manifest" });
    contract.dynamic_loader.path = try std.fs.path.join(allocator, &.{ layout.loader_directory, probes.loader_basename });
    const dependencies = try allocator.dupe(types.runtime.Artifact, contract.loader_dependencies);
    for (dependencies) |*dependency|
        dependency.path = try std.fs.path.join(allocator, &.{ layout.loader_directory, std.fs.path.basename(dependency.path) });
    contract.loader_dependencies = dependencies;
    try contract.validate();
    try t.expectError(error.InvalidRuntimePath, probes.arguments(a, layout, contract, .loader_listing));
}

test "copied loader listing refuses escape alias missing duplicate malformed and traversal" {
    var parsed = try goldenRuntime(a);
    defer parsed.deinit();
    var layout = goldenLayout(parsed.value);
    const config = try std.fs.path.join(a, &.{ layout.output, "startup-config" });
    defer a.free(config);
    layout.startup_config = config;
    const required = try a.alloc(bool, parsed.value.loader_dependencies.len);
    defer a.free(required);
    @memset(required, true);
    var listing: std.Io.Writer.Allocating = .init(a);
    defer listing.deinit();
    try listing.writer.writeAll("linux-vdso.so.1 (0x7ff)\n");
    for (parsed.value.loader_dependencies) |dependency|
        try listing.writer.print("\t{s} => {s} (0x1234)\n", .{ std.fs.path.basename(dependency.path), dependency.path });
    const interpreter_path_sha256 = tx.hash("/lib64/" ++ probes.loader_basename);
    try t.expectEqual(@as(u16, @intCast(parsed.value.loader_dependencies.len)), try probes.validateListing(a, listing.written(), layout, parsed.value, required, interpreter_path_sha256));
    try t.expectError(error.LoaderEscapedClosure, probes.validateListing(a, "libc.so.6 => /host/libc.so.6 (0x1234)\n", layout, parsed.value, required, interpreter_path_sha256));
    try t.expectError(error.UnsafePath, probes.validateListing(a, "libc.so.6 => /host/libc.so.6/../libc.so.6 (0x1234)\n", layout, parsed.value, required, interpreter_path_sha256));
    try t.expectError(error.InvalidLoaderListing, probes.validateListing(a, "libc.so.6 => not found\n", layout, parsed.value, required, interpreter_path_sha256));
    try t.expectError(error.IncompleteLoaderListing, probes.validateListing(a, "linux-vdso.so.1 (0x1)\n", layout, parsed.value, required, interpreter_path_sha256));
    const duplicate = try std.mem.concat(a, u8, &.{ listing.written(), listing.written() });
    defer a.free(duplicate);
    try t.expectError(error.InvalidLoaderListing, probes.validateListing(a, duplicate, layout, parsed.value, required, interpreter_path_sha256));
    const missing = try std.fmt.allocPrint(a, "{s} (0x1)\n", .{parsed.value.dynamic_loader.path});
    defer a.free(missing);
    if (required.len > 1) try t.expectError(error.IncompleteLoaderListing, probes.validateListing(a, missing, layout, parsed.value, required, interpreter_path_sha256));
    const wrong_interpreter = try std.fmt.allocPrint(a, "/other/{s} => {s} (0x1)\n", .{ probes.loader_basename, parsed.value.dynamic_loader.path });
    defer a.free(wrong_interpreter);
    try t.expectError(error.InvalidLoaderListing, probes.validateListing(a, wrong_interpreter, layout, parsed.value, required, interpreter_path_sha256));
    const oversized = try a.alloc(u8, 1024 * 1024 + 1);
    defer a.free(oversized);
    @memset(oversized, 'x');
    try t.expectError(error.InvalidLoaderListing, probes.validateListing(a, oversized, layout, parsed.value, required, interpreter_path_sha256));
}

test "version import command output checks do not accept empty partial or wrong version" {
    try probes.Test.pythonVersion("Python 3.12.9\n", "", "3.12");
    try t.expectError(error.InvalidPythonVersion, probes.Test.pythonVersion("Python 3.13.1\n", "", "3.12"));
    try t.expectError(error.InvalidPythonVersion, probes.Test.pythonVersion("Python 3.12.", "", "3.12"));
    try t.expectError(error.InvalidCommandProbe, probes.Test.command(a, 1, ""));
    try t.expectError(error.InvalidCommandProbe, probes.Test.command(a, 1, "\xff"));
    try t.expectError(error.UnexpectedFields, probes.Test.command(a, 0, "{\"azure-cli\":\"2\"}"));
    try probes.Test.command(a, 0, "{\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}\n");
}

const Checks = struct {
    count: usize = 0,
    fail_at: ?usize = null,
    fn check(raw: *anyopaque) !void {
        const self: *Checks = @ptrCast(@alignCast(raw));
        self.count += 1;
        if (self.fail_at == self.count) return error.SourceChanged;
    }
    fn barrier(self: *Checks) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

test "probe adapter preserves exit overflow timeout signal session escape cleanup and bounded redaction" {
    try core.process.initialize();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const path = try std.Io.Dir.cwd().realPathFileAlloc(io, fixture_path, a);
    defer a.free(path);
    const executable = try core.process.Executable.open(io, path);
    defer executable.close(io);
    for (std.enums.values(probes.Test.Fault)) |fault| {
        if (fault == .cancelled) continue;
        var checks: Checks = .{};
        const result = try probes.Test.fault(.{ .allocator = a, .io = io }, executable, fixture.dir, path, checks.barrier(), fault);
        try t.expectEqual(core.process.CommandCleanup.complete, result.cleanup);
        try t.expect(result.cleanup_complete);
        try t.expect(!result.supervision_passed);
        try t.expect(result.stdout_bytes + result.stderr_bytes <= 4096);
        try t.expect(std.mem.indexOf(u8, result.stdout_redacted, "never-publish") == null);
        try t.expect(std.mem.indexOf(u8, result.stderr_redacted, "never-publish") == null);
        switch (fault) {
            .exit => try t.expectEqual(@as(u8, 29), result.primary.exited),
            .overflow => try t.expect(result.primary == .output_overflow),
            .timeout => try t.expect(result.primary == .timeout),
            .signal => try t.expectEqual(linux.SIG.USR1, result.primary.signal),
            .stdin_environment => try t.expectEqual(@as(u8, 17), result.primary.exited),
            .escaped_descendant => {
                try t.expectEqual(@as(u8, 0), result.primary.exited);
                try t.expect(result.descendants.observed > 0);
                const file = try fixture.dir.openFile(io, "escaped-pid", .{});
                defer file.close(io);
                var buffer: [32]u8 = undefined;
                const count = try file.readPositionalAll(io, &buffer, 0);
                const pid = try std.fmt.parseInt(linux.pid_t, std.mem.trim(u8, buffer[0..count], "\n"), 10);
                try t.expectEqual(linux.E.SRCH, linux.errno(linux.kill(pid, @enumFromInt(0))));
            },
            .cancelled => unreachable,
        }
    }
}

fn cancelReady(dir: std.Io.Dir, failed: *std.atomic.Value(bool)) void {
    const deadline = core.process.Deadline.afterMilliseconds(3000) catch {
        failed.store(true, .release);
        return;
    };
    while (!(deadline.expired() catch true)) {
        const opened = linux.openat(dir.handle, "cancel-ready", .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true }, 0);
        if (linux.errno(opened) == .SUCCESS) {
            _ = linux.close(@intCast(opened));
            if (linux.errno(linux.kill(linux.getpid(), .TERM)) != .SUCCESS) failed.store(true, .release);
            return;
        }
        var fds: [0]linux.pollfd = .{};
        _ = linux.poll(&fds, 0, 1);
    }
    failed.store(true, .release);
}

test "in-flight cancellation cleans the retained child without success evidence" {
    try core.process.initialize();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const path = try std.Io.Dir.cwd().realPathFileAlloc(io, fixture_path, a);
    defer a.free(path);
    const executable = try core.process.Executable.open(io, path);
    defer executable.close(io);
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    var failed: std.atomic.Value(bool) = .init(false);
    const thread = try std.Thread.spawn(.{}, cancelReady, .{ fixture.dir, &failed });
    defer thread.join();
    var checks: Checks = .{};
    const result = try probes.Test.fault(.{ .allocator = a, .io = io, .signal = &cancellation }, executable, fixture.dir, path, checks.barrier(), .cancelled);
    try t.expect(!failed.load(.acquire));
    try t.expect(result.primary == .cancelled);
    try t.expect(result.cancellation_observed and result.cleanup_complete);
    try t.expectEqual(core.process.CommandCleanup.complete, result.cleanup);
    try t.expect(!result.supervision_passed);
}

test "probe cancellation and post-run freshness never erase the original child failure" {
    try core.process.initialize();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const path = try std.Io.Dir.cwd().realPathFileAlloc(io, fixture_path, a);
    defer a.free(path);
    const executable = try core.process.Executable.open(io, path);
    defer executable.close(io);
    var checks: Checks = .{ .fail_at = 2 };
    const result = try probes.Test.fault(.{ .allocator = a, .io = io }, executable, fixture.dir, path, checks.barrier(), .exit);
    try t.expectEqual(@as(u8, 29), result.primary.exited);
    try t.expectEqual(error.SourceChanged, result.freshness.?);
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.kill(linux.getpid(), .INT)));
    checks = .{};
    try t.expectError(error.Cancelled, probes.Test.fault(.{ .allocator = a, .io = io, .signal = &cancellation }, executable, fixture.dir, path, checks.barrier(), .exit));
}

test "genuine copied x86 Python Azure closure is absent source-only without substitution" {
    // No genuine input is supplied on this source lane, on any architecture.
    // Synthetic ELF and the fault child above are not qualifying runtime input.
    return error.SkipZigTest;
}
