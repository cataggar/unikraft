const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const runtime = @import("runtime.zig");

pub const miz_package_hash = c.miz_package_hash;
pub const Dependency = struct {
    name: []const u8,
    package_hash: []const u8,
    content: runtime.Tool,
};
pub const Record = struct {
    schema: enum { hyperv_native_producer_provenance_v2 },
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
    repository: fs.Directory,
    producer: fs.Directory,
    compiler: fs.Directory,
    git: fs.Directory,
    dependencies: []const Dependencies,
    trust: fs.Directory,
};

pub fn requirePackages(allocator: std.mem.Allocator, aggregate: runtime.Tool, dependencies: []const Dependency) !void {
    if (aggregate.role != .dependencies or aggregate.origin.payload != .zig_packages) return error.IncompleteProvenance;
    const packages = aggregate.origin.payload.zig_packages.packages;
    if (packages.len != dependencies.len) return error.IncompleteProvenance;
    for (dependencies) |dependency| {
        if (dependency.content.origin.payload != .zig_packages or dependency.content.origin.payload.zig_packages.packages.len != 1)
            return error.IncompleteProvenance;
        const singleton = dependency.content.origin.payload.zig_packages.packages[0];
        var found = false;
        for (packages) |package| if (std.mem.eql(u8, package.package_hash, dependency.package_hash)) {
            if (found or !std.mem.eql(u8, package.locator, singleton.locator) or
                !std.meta.eql(try runtime.origin.hash(allocator, package.revision), try runtime.origin.hash(allocator, singleton.revision)) or
                !std.meta.eql(try runtime.origin.hash(allocator, package.declaration), try runtime.origin.hash(allocator, singleton.declaration)))
                return error.UnreviewedInput;
            found = true;
        };
        if (!found) return error.IncompleteProvenance;
    }
}

pub fn requireDeclarationRoots(origin: runtime.Origin, repository: fs.Directory, dependencies: []const Dependencies) !void {
    if (origin.payload != .zig_packages) return;
    for (origin.payload.zig_packages.packages) |package| {
        if (std.mem.startsWith(u8, package.declaration.file.path, ".d/") or
            std.mem.startsWith(u8, package.declaration.file.path, ".git/")) return error.InvalidPackageDeclaration;
        var found = std.mem.eql(u8, package.declaration.directory.path, repository.path);
        if (found) try package.declaration.directory.require(try runtime.origin.Identity.directory(repository));
        for (dependencies) |dependency| if (std.mem.eql(u8, package.declaration.directory.path, dependency.directory.path)) {
            if (found) return error.InvalidPackageDeclaration;
            try package.declaration.directory.require(try runtime.origin.Identity.directory(dependency.directory));
            found = true;
        };
        if (!found) return error.InvalidPackageDeclaration;
    }
}

pub fn validate(record: Record) !void {
    try c.objectId(record.source.head);
    try c.objectId(record.source.tree);
    _ = try c.sha(&record.source.tree_sha256);
    _ = try c.sha(&record.source.physical.sha256);
    if (record.source.physical.files == 0 or record.source.head.len != record.source.tree.len) return error.InvalidProvenance;
    if (!std.mem.eql(u8, record.compiler_version, c.compiler_version) or
        record.compiler.origin.payload != .distribution or
        !std.mem.eql(u8, try record.compiler.origin.revision(), c.compiler_version)) return error.CompilerMismatch;
    if (record.producer.role != .preparation or record.compiler.role != .zig or record.git.role != .git or
        record.trust.role != .trust or record.trust.target != .data) return error.InvalidProvenance;
    if (record.producer.executable == null or record.compiler.executable == null or record.git.executable == null or
        record.producer.target != record.compiler.target or record.git.target != record.producer.target or
        !std.mem.eql(u8, @tagName(record.host_target), @tagName(record.producer.target))) return error.CompilerMismatch;
    try record.producer.origin.requireLocal(record.source, record.compiler.executable.?);
    if (record.dependencies.len == 0 or record.dependencies.len > 128 or record.trust.tree.files == 0) return error.IncompleteProvenance;
    var miz_found = false;
    for (record.dependencies, 0..) |dependency, i| {
        try c.core.private_files.basename(dependency.name);
        try c.core.private_files.basename(dependency.package_hash);
        if (dependency.content.target != .data or dependency.content.role != .dependencies or
            dependency.content.origin.payload != .zig_packages or dependency.content.tree.files == 0)
            return error.IncompleteProvenance;
        if (dependency.content.origin.payload.zig_packages.packages.len != 1 or
            !std.mem.eql(u8, dependency.content.origin.payload.zig_packages.packages[0].package_hash, dependency.package_hash))
            return error.IncompleteProvenance;
        for (record.dependencies[0..i]) |previous| {
            if (std.mem.eql(u8, dependency.name, previous.name) or std.mem.eql(u8, dependency.package_hash, previous.package_hash))
                return error.InvalidProvenance;
        }
        if (std.mem.eql(u8, dependency.name, "miz_source")) {
            if (!std.mem.eql(u8, dependency.package_hash, miz_package_hash) or
                !std.mem.eql(u8, try dependency.content.origin.revision(), c.miz_revision) or
                dependency.content.origin.payload.zig_packages.packages[0].revision != .git_commit) return error.UnreviewedInput;
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
    try runtime.origin.validate(tool.origin, tool.role, tool.target);
    if (tool.libraries.len > 256)
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
    for (record.dependencies) |dependency| try requireDeclarationRoots(dependency.content.origin, bindings.repository, bindings.dependencies);
    inline for (.{ "producer", "compiler", "git", "trust" }) |name| {
        const evidence = @field(record, name).evidence;
        try runtime.origin.requireSeparate(evidence, &.{ bindings.repository.path, bindings.producer.path, bindings.compiler.path, bindings.git.path, bindings.trust.path });
        for (bindings.dependencies) |dependency| try runtime.origin.requireSeparate(evidence, &.{dependency.directory.path});
    }
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
