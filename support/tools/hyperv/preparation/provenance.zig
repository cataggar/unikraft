const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const runtime = @import("runtime.zig");

pub const miz_package_hash = "miz-0.2.0-Z3lHlPw00wAx7bBDTJjcF1O3Vva6085mA_DZS2uWdwzL";
pub const Dependency = struct {
    name: []const u8,
    package_hash: []const u8,
    content: runtime.Tool,
};
pub const Record = struct {
    schema: enum { hyperv_native_producer_provenance_v1 },
    source: c.Source,
    host_target: enum { aarch64_linux, x86_64_linux },
    guest_target: enum { x86_64_freestanding_none },
    compiler_version: []const u8,
    producer: runtime.Tool,
    compiler: runtime.Tool,
    git: runtime.Tool,
    dependencies: []const Dependency,
    trust: runtime.Tool,
};
pub const Dependencies = struct { name: []const u8, directory: fs.Directory };
pub const Bindings = struct {
    producer: fs.Directory,
    compiler: fs.Directory,
    git: fs.Directory,
    dependencies: []const Dependencies,
    trust: fs.Directory,
};

pub fn validate(record: Record) !void {
    try c.objectId(record.source.head);
    try c.objectId(record.source.tree);
    _ = try c.sha(&record.source.tree_sha256);
    _ = try c.sha(&record.source.physical.sha256);
    if (record.source.physical.files == 0 or record.source.head.len != record.source.tree.len) return error.InvalidProvenance;
    if (!std.mem.eql(u8, record.compiler_version, c.compiler_version) or
        !std.mem.eql(u8, record.compiler.origin.revision, c.compiler_version)) return error.CompilerMismatch;
    if (record.producer.role != .preparation or record.compiler.role != .zig or record.git.role != .git or
        record.trust.role != .trust or record.trust.target != .data) return error.InvalidProvenance;
    if (record.producer.executable == null or record.compiler.executable == null or record.git.executable == null or
        record.producer.target != record.compiler.target or record.git.target != record.producer.target or
        !std.mem.eql(u8, @tagName(record.host_target), @tagName(record.producer.target))) return error.CompilerMismatch;
    if (!std.meta.eql(record.producer.origin.source_sha256, record.source.physical.sha256) or
        !std.meta.eql(record.producer.origin.producer_sha256, record.compiler.executable.?.sha256)) return error.UnreviewedInput;
    if (record.dependencies.len == 0 or record.dependencies.len > 128 or record.trust.tree.files == 0) return error.IncompleteProvenance;
    var miz_found = false;
    for (record.dependencies, 0..) |dependency, i| {
        try c.core.private_files.basename(dependency.name);
        try c.core.private_files.basename(dependency.package_hash);
        if (dependency.content.target != .data or dependency.content.role != .dependencies or
            dependency.content.origin.scheme != .zig_package or dependency.content.tree.files == 0)
            return error.IncompleteProvenance;
        for (record.dependencies[0..i]) |previous| {
            if (std.mem.eql(u8, dependency.name, previous.name) or std.mem.eql(u8, dependency.package_hash, previous.package_hash))
                return error.InvalidProvenance;
        }
        if (std.mem.eql(u8, dependency.name, "miz_source")) {
            if (!std.mem.eql(u8, dependency.package_hash, miz_package_hash) or
                !std.mem.eql(u8, dependency.content.origin.revision, c.miz_revision)) return error.UnreviewedInput;
            miz_found = true;
        }
    }
    if (!miz_found) return error.IncompleteProvenance;
    inline for (.{ "producer", "compiler", "git", "trust" }) |name|
        try validateTool(@field(record, name));
    for (record.dependencies) |dependency| try validateTool(dependency.content);
}

fn validateFile(file: c.File, executable: bool) !void {
    try c.relative(file.path);
    _ = try c.sha(&file.sha256);
    if (file.size == 0 or file.mode & 0o7022 != 0 or file.mode & ~@as(u16, 0o7777) != 0 or
        (executable and file.mode & 0o111 == 0)) return error.InvalidRuntime;
}

fn validateTool(tool: runtime.Tool) !void {
    _ = try c.sha(&tool.tree.sha256);
    _ = try c.sha(&tool.origin.source_sha256);
    _ = try c.sha(&tool.origin.producer_sha256);
    if (tool.origin.revision.len == 0 or tool.origin.revision.len > 256 or tool.libraries.len > 256)
        return error.InvalidRuntime;
    var files: usize = 0;
    var bytes: u64 = 0;
    if (tool.executable) |executable| {
        if (tool.target == .data) return error.InvalidRuntime;
        try validateFile(executable, true);
        files += 1;
        bytes = executable.size;
    } else if (tool.target != .data or tool.loader != null or tool.libraries.len != 0) return error.InvalidRuntime;
    if (tool.loader) |loader| {
        try validateFile(loader, true);
        if (std.mem.eql(u8, loader.path, tool.executable.?.path)) return error.InvalidRuntime;
        files += 1;
        bytes = try std.math.add(u64, bytes, loader.size);
    } else if (tool.libraries.len != 0) return error.InvalidRuntime;
    for (tool.libraries, 0..) |library, i| {
        try validateFile(library, false);
        if (std.mem.eql(u8, library.path, tool.executable.?.path) or std.mem.eql(u8, library.path, tool.loader.?.path))
            return error.InvalidRuntime;
        for (tool.libraries[0..i]) |previous|
            if (std.mem.eql(u8, library.path, previous.path)) return error.InvalidRuntime;
        files += 1;
        bytes = try std.math.add(u64, bytes, library.size);
    }
    if (tool.tree.files < files or tool.tree.bytes < bytes) return error.InvalidRuntime;
}

/// The independent expected hash covers the *complete* dependency list. A
/// freshly measured list is review material, never its own approval.
pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    record: Record,
    bindings: Bindings,
    reviewed_sha256: c.Sha,
) !void {
    try validate(record);
    const canonical = try c.canonical(allocator, record);
    defer allocator.free(canonical);
    if (!std.meta.eql(c.digest(canonical), reviewed_sha256)) return error.UnreviewedInput;
    if (bindings.dependencies.len != record.dependencies.len) return error.IncompleteProvenance;
    inline for (.{ "producer", "compiler", "git", "trust" }) |name|
        try (runtime.Bound{ .directory = @field(bindings, name), .contract = @field(record, name) }).validate(allocator, io);
    for (record.dependencies) |dependency| {
        var directory: ?fs.Directory = null;
        for (bindings.dependencies) |binding| {
            if (!std.mem.eql(u8, dependency.name, binding.name)) continue;
            if (directory != null) return error.IncompleteProvenance;
            directory = binding.directory;
        }
        try (runtime.Bound{ .directory = directory orelse return error.IncompleteProvenance, .contract = dependency.content }).validate(allocator, io);
    }
}

/// A receipt producer must bind the native executable that is actually running,
/// not an unrelated reviewed binary supplied by the caller.
pub fn requireCurrentExecutable(io: std.Io, record: Record) !void {
    if (!std.mem.eql(u8, c.compiler_version, builtin.zig_version_string)) return error.CompilerMismatch;
    const host = if (builtin.cpu.arch == .aarch64) "aarch64_linux" else if (builtin.cpu.arch == .x86_64) "x86_64_linux" else return error.CompilerMismatch;
    if (!std.mem.eql(u8, host, @tagName(record.host_target))) return error.CompilerMismatch;
    const executable = record.producer.executable orelse return error.InvalidProvenance;
    const file = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});
    defer file.close(io);
    const before = try fs.metadata(file);
    if (before.size != executable.size or !std.meta.eql(try fs.hashFile(io, file, before.size), executable.sha256) or
        !std.meta.eql(before, try fs.metadata(file))) return error.UnreviewedInput;
}
