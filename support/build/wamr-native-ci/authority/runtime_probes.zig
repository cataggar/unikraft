// SPDX-License-Identifier: BSD-3-Clause
//! Source-only Azure preparation component, not an installed command or admission.
//! Discovery borrows independently retained source files. Copied inspection
//! requires a real immutable manifest and the existing direct runtime Contract.
//! The owning preparation helper must enter the direct runtime's private mount
//! namespace, initialize the process subreaper, then seal the verified stage.
//! runSealed borrows that seal and never publishes an accepted runtime record.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const types = @import("types.zig");
const tx = @import("transaction.zig");
const runtime = types.runtime;
const files = core.private_files;
const process = core.process;
const elf = @import("producer_elf");
pub const Context = types.Context;

pub const loader_basename = "ld-linux-x86-64.so.2";
const output_limit = 1024 * 1024;
const command_ms = 30_000;
const cleanup_ms = 5_000;
const total_ms = 600_000;

pub const ElfRole = enum { interpreter, loader, library, native_extension };
pub const ElfInfo = struct {
    allocator: std.mem.Allocator,
    interpreter: ?[]const u8 = null,
    soname: ?[]const u8 = null,
    needed: []const []const u8 = &.{},
    entry: u64,

    pub fn deinit(self: *ElfInfo) void {
        if (self.interpreter) |value| self.allocator.free(value);
        if (self.soname) |value| self.allocator.free(value);
        for (self.needed) |value| self.allocator.free(value);
        self.allocator.free(self.needed);
        self.* = undefined;
    }
};

/// Program-header parsing also supports stripped ELF files. Architecture is
/// always the frozen x86_64 target, independently of the machine running tests.
pub fn inspectElf(a: std.mem.Allocator, bytes: []const u8, role: ElfRole) !ElfInfo {
    if (bytes.len < 64 or bytes.len > runtime.max_file_bytes or
        !std.mem.eql(u8, bytes[0..6], "\x7fELF\x02\x01") or bytes[6] != 1 or
        (bytes[7] != 0 and bytes[7] != 3) or bytes[8] != 0)
        return error.InvalidElf;
    const kind = try elf.integer(u16, bytes, 16, .little);
    if ((kind != 2 and kind != 3) or
        try elf.integer(u16, bytes, 18, .little) != @intFromEnum(std.elf.EM.X86_64) or
        try elf.integer(u32, bytes, 20, .little) != 1 or
        try elf.integer(u16, bytes, 52, .little) != 64)
        return error.InvalidElf;
    if ((role == .loader or role == .library or role == .native_extension) and kind != 3)
        return error.InvalidElf;
    const phoff = try elf.integer(u64, bytes, 32, .little);
    const phnum = try elf.integer(u16, bytes, 56, .little);
    if (phoff < 64 or phnum == 0 or phnum > 1024 or
        try elf.integer(u16, bytes, 54, .little) != 56)
        return error.InvalidElf;
    _ = try elf.range(bytes, phoff, @as(u64, phnum) * 56);
    var programs: [1024]std.elf.Elf64_Phdr = undefined;
    var dynamic: ?std.elf.Elf64_Phdr = null;
    var result: ElfInfo = .{ .allocator = a, .entry = try elf.integer(u64, bytes, 24, .little) };
    errdefer result.deinit();
    var entry_loaded = false;
    var loads: usize = 0;
    for (programs[0..phnum], 0..) |*ph, index| {
        ph.* = try elf.structure(std.elf.Elf64_Phdr, bytes, phoff + index * 56, .little);
        _ = try elf.range(bytes, ph.p_offset, ph.p_filesz);
        _ = try elf.add(ph.p_vaddr, ph.p_memsz);
        switch (ph.p_type) {
            std.elf.PT_LOAD => {
                loads += 1;
                if (ph.p_filesz > ph.p_memsz or ph.p_flags & ~@as(u32, 7) != 0 or
                    (ph.p_align > 1 and (!std.math.isPowerOfTwo(ph.p_align) or
                        ph.p_offset % ph.p_align != ph.p_vaddr % ph.p_align)))
                    return error.InvalidElf;
                if (ph.p_flags & std.elf.PF_X != 0 and result.entry >= ph.p_vaddr and
                    result.entry - ph.p_vaddr < ph.p_filesz)
                    entry_loaded = true;
            },
            std.elf.PT_INTERP => {
                if (result.interpreter != null or ph.p_filesz < 2 or ph.p_filesz > 4096)
                    return error.InvalidInterpreter;
                const value = try elf.range(bytes, ph.p_offset, ph.p_filesz);
                if (value[value.len - 1] != 0 or std.mem.indexOfScalar(u8, value[0 .. value.len - 1], 0) != null)
                    return error.InvalidInterpreter;
                try absolutePath(value[0 .. value.len - 1]);
                if (!std.mem.eql(u8, std.fs.path.basename(value[0 .. value.len - 1]), loader_basename))
                    return error.InvalidInterpreter;
                result.interpreter = try a.dupe(u8, value[0 .. value.len - 1]);
            },
            std.elf.PT_DYNAMIC => {
                if (dynamic != null or ph.p_filesz == 0 or ph.p_filesz % 16 != 0 or ph.p_filesz / 16 > 4096)
                    return error.InvalidDynamic;
                dynamic = ph.*;
            },
            else => {},
        }
    }
    if (loads == 0 or ((role == .interpreter or role == .loader) and (result.entry == 0 or !entry_loaded)))
        return error.InvalidEntry;
    if (role == .interpreter and result.interpreter == null) return error.MissingInterpreter;
    // glibc's libc DSO is itself executable and may name the same interpreter.
    if (role == .loader and result.interpreter != null) return error.InvalidInterpreter;
    const dyn = dynamic orelse return error.MissingDynamic;
    if (try mappedOffset(programs[0..phnum], dyn.p_vaddr, dyn.p_filesz) != dyn.p_offset)
        return error.InvalidDynamic;
    var string_address: ?u64 = null;
    var string_size: ?u64 = null;
    var ended = false;
    var entries: [4096]std.elf.Elf64_Dyn = undefined;
    var count: usize = 0;
    while (count < dyn.p_filesz / 16) : (count += 1) {
        const entry = try elf.structure(std.elf.Elf64_Dyn, bytes, dyn.p_offset + count * 16, .little);
        entries[count] = entry;
        switch (entry.d_tag) {
            std.elf.DT_NULL => {
                ended = true;
                break;
            },
            std.elf.DT_STRTAB => {
                if (string_address != null) return error.InvalidDynamic;
                string_address = entry.d_val;
            },
            std.elf.DT_STRSZ => {
                if (string_size != null) return error.InvalidDynamic;
                string_size = entry.d_val;
            },
            // Azure's frozen policy forbids even an otherwise contained $ORIGIN.
            std.elf.DT_RPATH, std.elf.DT_RUNPATH, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff => return error.AlternateLookupForbidden,
            else => {},
        }
    }
    if (!ended or string_address == null or string_size == null or string_size.? == 0 or string_size.? > 16 * 1024 * 1024)
        return error.InvalidDynamic;
    const strings = try elf.range(bytes, try mappedOffset(programs[0..phnum], string_address.?, string_size.?), string_size.?);
    var needed: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (needed.items) |name| a.free(name);
        needed.deinit(a);
    }
    for (entries[0..count]) |entry| switch (entry.d_tag) {
        std.elf.DT_NEEDED => {
            const name = try elf.string(strings, entry.d_val);
            try dependencyName(name);
            for (needed.items) |previous| if (std.mem.eql(u8, previous, name)) return error.DuplicateDependency;
            if (needed.items.len >= runtime.max_loader_files) return error.LoaderLimit;
            try needed.append(a, try a.dupe(u8, name));
        },
        std.elf.DT_SONAME => {
            if (result.soname != null) return error.InvalidDynamic;
            const name = try elf.string(strings, entry.d_val);
            try dependencyName(name);
            result.soname = try a.dupe(u8, name);
        },
        else => {},
    };
    result.needed = try needed.toOwnedSlice(a);
    if (role == .loader and (result.needed.len != 0 or result.soname == null or
        !std.mem.eql(u8, result.soname.?, loader_basename)))
        return error.InvalidLoader;
    return result;
}

fn mappedOffset(programs: []const std.elf.Elf64_Phdr, address: u64, size: u64) !u64 {
    var result: ?u64 = null;
    for (programs) |ph| {
        if (ph.p_type != std.elf.PT_LOAD or address < ph.p_vaddr) continue;
        const delta = address - ph.p_vaddr;
        if (delta > ph.p_filesz or size > ph.p_filesz - delta) continue;
        if (result != null) return error.AmbiguousLoad;
        result = try elf.add(ph.p_offset, delta);
    }
    return result orelse error.UnloadedDynamic;
}

fn dependencyName(value: []const u8) !void {
    try files.basename(value);
    // glibc expands dynamic tokens before lookup, even in slash-free names.
    if (value.len > 255 or !std.unicode.utf8ValidateSlice(value) or
        std.mem.indexOfAny(u8, value, "$\\\t\r\n:") != null)
        return error.InvalidDependencyName;
}

fn absolutePath(value: []const u8) !void {
    try files.absoluteFilePath(value);
    if (!std.unicode.utf8ValidateSlice(value) or std.mem.indexOfAny(u8, value, "\t\r\n:\\") != null)
        return error.InvalidRuntimePath;
}

fn checkCancellation(ctx: types.Context) !void {
    if (ctx.signal) |signal| if (signal.flag().load(.acquire)) return error.Cancelled;
}

fn readRetained(ctx: types.Context, file: *files.RetainedFile) !core.sensitive.Buffer {
    try checkCancellation(ctx);
    try file.verify(ctx.io);
    if (file.file_snapshot.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or
        file.file_snapshot.mode & 0o7022 != 0 or file.file_snapshot.nlink != 1 or
        (file.file_snapshot.uid != 0 and file.file_snapshot.uid != std.os.linux.geteuid()) or
        file.file_snapshot.size == 0 or file.file_snapshot.size > runtime.max_file_bytes)
        return error.InvalidNativeSource;
    var bytes = try readElfFile(ctx, file.file);
    errdefer bytes.deinit();
    if (bytes.bytes().len != file.file_snapshot.size) return error.FileChanged;
    try file.verify(ctx.io);
    try checkCancellation(ctx);
    return bytes;
}

fn readElfFile(ctx: types.Context, file: std.Io.File) !core.sensitive.Buffer {
    const before = try files.snapshot(file);
    if (before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or before.nlink != 1 or
        before.mode & 0o7022 != 0 or before.size == 0 or before.size > runtime.max_file_bytes or
        (before.uid != 0 and before.uid != std.os.linux.geteuid()))
        return error.InvalidNativeSource;
    var result: core.sensitive.Buffer = .{
        .allocator = ctx.allocator,
        .storage = try ctx.allocator.alloc(u8, @intCast(before.size)),
        .length = @intCast(before.size),
    };
    errdefer result.deinit();
    var offset: usize = 0;
    while (offset < result.length) {
        try checkCancellation(ctx);
        const amount = @min(64 * 1024, result.length - offset);
        const read = std.os.linux.pread(file.handle, result.storage[offset..].ptr, amount, @intCast(offset));
        switch (std.os.linux.errno(read)) {
            .SUCCESS => {
                if (read == 0 or read > amount) return error.FileChanged;
                offset += read;
            },
            .INTR => continue,
            else => return error.NativeReadFailed,
        }
    }
    if (!files.sameSnapshot(before, try files.snapshot(file))) return error.FileChanged;
    return result;
}

fn openRegular(ctx: types.Context, dir: std.Io.Dir, name: []const u8) !std.Io.File {
    try files.basename(name);
    var buffer: [256:0]u8 = undefined;
    if (name.len > 255) return error.InvalidDependencyName;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    const opened = std.os.linux.openat(dir.handle, buffer[0..name.len :0], .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
    }, 0);
    if (std.os.linux.errno(opened) != .SUCCESS) return error.NativeOpenFailed;
    const file: std.Io.File = .{ .handle = @intCast(opened), .flags = .{ .nonblocking = true } };
    errdefer file.close(ctx.io);
    if ((try files.snapshot(file)).mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG)
        return error.UnsafeCopiedEntry;
    return file;
}

pub const DiscoveryInput = struct {
    interpreter: *files.RetainedFile,
    dynamic_loader: *files.RetainedFile,
    native_roots: []const *files.RetainedFile,
    /// Explicit, independently retained canonical DSO candidates. No host PATH,
    /// ldd output, Python metadata or opportunistic loader search is authority.
    candidates: []const *files.RetainedFile,
    /// DT_NEEDED placement names, when canonical sources have versioned names
    /// (libz.so.1 -> libz.so.1.2.13). Omitted only for basename-named sources.
    candidate_names: ?[]const []const u8 = null,
};
pub const Discovery = struct {
    allocator: std.mem.Allocator,
    inventory: types.LoaderInventory,
    digests: [][32]u8,
    /// Owned safe destination basenames, aligned with inventory.dependencies.
    /// The copy owner must use its named-inventory constructor, not basename
    /// normalization of these canonical source paths.
    names: []const []const u8,

    pub fn deinit(self: *Discovery) void {
        self.allocator.free(self.inventory.dependencies);
        self.allocator.free(self.digests);
        for (self.names) |name| self.allocator.free(name);
        self.allocator.free(self.names);
        self.* = undefined;
    }
};
const Source = struct {
    file: *files.RetainedFile,
    name: []const u8,
    info: ElfInfo,
    digest: [32]u8,
    fn lessThan(_: void, left: Source, right: Source) bool {
        const order = std.mem.order(u8, left.name, right.name);
        if (order != .eq) return order == .lt;
        return std.mem.lessThan(u8, left.file.path, right.file.path);
    }
};

/// Basename collisions are allowed only for identical independently hashed
/// bytes. The byte-sorted canonical path wins, matching deterministic copying.
/// Every explicit candidate is included and its transitive dependencies checked.
pub fn discover(ctx: types.Context, input: DiscoveryInput) !Discovery {
    if (input.candidates.len > runtime.max_loader_files or input.native_roots.len > runtime.max_files)
        return error.LoaderLimit;
    if (input.candidate_names) |names| if (names.len != input.candidates.len) return error.InvalidDependencyNames;
    for (input.candidates, 0..) |file, index|
        try dependencyName(if (input.candidate_names) |names| names[index] else std.fs.path.basename(file.path));
    var interpreter_bytes = try readRetained(ctx, input.interpreter);
    defer interpreter_bytes.deinit();
    var interpreter = try inspectElf(ctx.allocator, interpreter_bytes.bytes(), .interpreter);
    defer interpreter.deinit();
    const canonical_loader = try std.Io.Dir.cwd().realPathFileAlloc(ctx.io, interpreter.interpreter.?, ctx.allocator);
    defer ctx.allocator.free(canonical_loader);
    if (!std.mem.eql(u8, canonical_loader, input.dynamic_loader.path) or
        !std.mem.eql(u8, std.fs.path.basename(input.dynamic_loader.path), loader_basename))
        return error.InvalidLoaderSource;
    var sources: std.ArrayList(Source) = .empty;
    defer {
        for (sources.items) |*source| source.info.deinit();
        sources.deinit(ctx.allocator);
    }
    try appendSource(ctx, &sources, input.dynamic_loader, loader_basename, .loader);
    for (input.candidates, 0..) |file, index| {
        const name = if (input.candidate_names) |names| names[index] else std.fs.path.basename(file.path);
        if (file == input.dynamic_loader and std.mem.eql(u8, name, loader_basename)) continue;
        try appendSource(ctx, &sources, file, name, if (std.mem.eql(u8, name, loader_basename)) .loader else .library);
    }
    std.mem.sort(Source, sources.items, {}, Source.lessThan);
    var unique: std.ArrayList(types.LoaderSource) = .empty;
    errdefer unique.deinit(ctx.allocator);
    var digests: std.ArrayList([32]u8) = .empty;
    errdefer digests.deinit(ctx.allocator);
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |name| ctx.allocator.free(name);
        names.deinit(ctx.allocator);
    }
    for (sources.items) |source| {
        var found: ?usize = null;
        for (names.items, 0..) |previous, index| if (std.mem.eql(u8, source.name, previous)) {
            found = index;
            break;
        };
        if (found) |index| {
            if (!std.crypto.timing_safe.eql([32]u8, digests.items[index], source.digest))
                return error.LoaderBasenameCollision;
            if (source.file == input.dynamic_loader) unique.items[index].file = input.dynamic_loader;
            continue;
        }
        try unique.append(ctx.allocator, .{ .file = source.file, .executable = std.mem.eql(u8, source.name, loader_basename) });
        try digests.append(ctx.allocator, source.digest);
        const name = try ctx.allocator.dupe(u8, source.name);
        errdefer ctx.allocator.free(name);
        try names.append(ctx.allocator, name);
    }
    try requireNeeded(interpreter, names.items);
    for (sources.items) |source| try requireNeeded(source.info, names.items);
    for (input.native_roots) |file| {
        var bytes = try readRetained(ctx, file);
        defer bytes.deinit();
        if (!std.mem.startsWith(u8, bytes.bytes(), "\x7fELF")) continue;
        var info = try inspectElf(ctx.allocator, bytes.bytes(), if (file == input.interpreter) .interpreter else .native_extension);
        defer info.deinit();
        try requireNeeded(info, names.items);
    }
    // Recheck all borrowed path/ancestor identities before returning an inventory.
    try input.interpreter.verify(ctx.io);
    try input.dynamic_loader.verify(ctx.io);
    for (input.native_roots) |file| try file.verify(ctx.io);
    for (sources.items) |source| try source.file.verify(ctx.io);
    try checkCancellation(ctx);
    const dependencies = try unique.toOwnedSlice(ctx.allocator);
    errdefer ctx.allocator.free(dependencies);
    const owned_digests = try digests.toOwnedSlice(ctx.allocator);
    errdefer ctx.allocator.free(owned_digests);
    return .{
        .allocator = ctx.allocator,
        .inventory = .{ .dynamic_loader = input.dynamic_loader, .dependencies = dependencies },
        .digests = owned_digests,
        .names = try names.toOwnedSlice(ctx.allocator),
    };
}

fn appendSource(ctx: types.Context, sources: *std.ArrayList(Source), file: *files.RetainedFile, name: []const u8, role: ElfRole) !void {
    if (sources.items.len >= runtime.max_loader_files) return error.LoaderLimit;
    try absolutePath(file.path);
    try dependencyName(name);
    var bytes = try readRetained(ctx, file);
    defer bytes.deinit();
    var info = try inspectElf(ctx.allocator, bytes.bytes(), role);
    errdefer info.deinit();
    try sources.append(ctx.allocator, .{ .file = file, .name = name, .info = info, .digest = tx.hash(bytes.bytes()) });
}

fn requireNeeded(info: ElfInfo, names: []const []const u8) !void {
    for (info.needed) |name| {
        var found = false;
        for (names) |available| if (std.mem.eql(u8, name, available)) {
            found = true;
            break;
        };
        if (!found) return error.MissingDependency;
    }
}

pub const CopiedInput = struct {
    /// Borrowed 0500 staged root; every parent/file owner outlives inspection.
    root: std.Io.Dir,
    layout: types.RuntimeLayout,
    contract: runtime.Contract,
    barrier: tx.Barrier,
};
pub const ElfEvidence = struct {
    native_files: u32,
    loader_files: u16,
    needed_edges: u32,
    interpreter_sha256: [32]u8,
    interpreter_path_sha256: [32]u8,
    /// Ordinals in the independently verified contract's loader_dependencies.
    interpreter_closure: [runtime.max_loader_files]bool,
};

fn requireLayout(layout: types.RuntimeLayout, contract: runtime.Contract) !void {
    try contract.validate();
    for (contract.loader_dependencies) |dependency|
        try dependencyName(std.fs.path.basename(dependency.path));
    inline for (.{ "output", "root", "launcher", "interpreter", "extensions", "loader_directory", "startup_config" }) |field|
        try absolutePath(@field(layout, field));
    // --library-path also expands these tokens; the retained path must be literal.
    if (std.mem.indexOfScalar(u8, layout.loader_directory, '$') != null)
        return error.InvalidRuntimePath;
    if (contract.launcher.size > 64 * 1024 * 1024 or contract.interpreter.size > 64 * 1024 * 1024 or
        contract.dynamic_loader.size > 64 * 1024 * 1024 or
        !std.mem.eql(u8, layout.root, contract.root) or
        !std.mem.eql(u8, layout.launcher, contract.launcher.path) or
        !std.mem.eql(u8, layout.interpreter, contract.interpreter.path) or
        !std.mem.eql(u8, layout.extensions, contract.extensions) or
        !std.mem.eql(u8, layout.python_version, contract.python_version) or
        !exactChild(layout.output, layout.root, "/runtime") or
        !exactChild(layout.output, layout.startup_config, "/startup-config") or
        !exactChild(layout.root, layout.loader_directory, "/loader") or
        !exactChild(layout.loader_directory, contract.dynamic_loader.path, "/" ++ loader_basename))
        return error.InvalidRuntimeLayout;
}

fn exactChild(parent: []const u8, child: []const u8, suffix: []const u8) bool {
    return child.len == parent.len + suffix.len and std.mem.startsWith(u8, child, parent) and
        std.mem.eql(u8, child[parent.len..], suffix);
}

/// Independently verify the canonical manifest/closure before executable use.
pub fn inspectCopied(ctx: types.Context, input: CopiedInput) !ElfEvidence {
    try checkCancellation(ctx);
    try input.barrier.revalidate();
    try requireLayout(input.layout, input.contract);
    const named = try std.Io.Dir.openDirAbsolute(ctx.io, input.contract.root, .{ .follow_symlinks = false, .iterate = true });
    defer named.close(ctx.io);
    if (!files.sameSnapshot(try directorySnapshot(named), try directorySnapshot(input.root))) return error.CopiedRootChanged;
    try requireCopiedLayout(ctx, input.root, input.layout, input.contract);
    try runtime.verify(ctx.allocator, ctx.io, input.contract);
    const evidence = try inspectTree(ctx, input.root, input.layout, input.contract);
    try input.barrier.revalidate();
    try runtime.verify(ctx.allocator, ctx.io, input.contract);
    try checkCancellation(ctx);
    return evidence;
}

/// Structural check only: this is not manifest verification or runtime admission.
/// No lib64 fallback, mutable root, or symlink in the Python home walk is allowed.
pub fn requireCopiedLayout(ctx: types.Context, root: std.Io.Dir, layout: types.RuntimeLayout, contract: runtime.Contract) !void {
    try requireLayout(layout, contract);
    try checkCancellation(ctx);
    if ((try directorySnapshot(root)).mode & 0o7777 != 0o500) return error.InvalidCopiedMode;
    const lib64 = root.openDir(ctx.io, "lib64", .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return error.InvalidRuntimeLayout,
    };
    if (lib64) |dir| {
        dir.close(ctx.io);
        return error.InvalidRuntimeLayout;
    }
    const lib = try root.openDir(ctx.io, "lib", .{ .follow_symlinks = false });
    defer lib.close(ctx.io);
    const library_name = try std.fmt.allocPrint(ctx.allocator, "python{s}", .{contract.python_version});
    defer ctx.allocator.free(library_name);
    const library = try lib.openDir(ctx.io, library_name, .{ .follow_symlinks = false });
    defer library.close(ctx.io);
    if ((try directorySnapshot(lib)).mode & 0o7777 != 0o500 or
        (try directorySnapshot(library)).mode & 0o7777 != 0o500)
        return error.InvalidCopiedMode;
}

/// Destructive namespace operations belong only to the preparation helper, not
/// the CLI controller's caller namespace. A real manifest is mandatory.
pub fn sealCopied(ctx: types.Context, input: CopiedInput) !runtime.Sealed {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux)
        return error.CompatibleRuntimeUnavailable;
    _ = try inspectCopied(ctx, input);
    const sealed = try runtime.seal(ctx.allocator, ctx.io, input.contract);
    errdefer sealed.close(ctx.io);
    try checkCancellation(ctx);
    return sealed;
}

fn directorySnapshot(dir: std.Io.Dir) !files.Snapshot {
    return files.snapshot(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
}

fn sameDirectory(left: files.Snapshot, right: files.Snapshot) bool {
    return left.dev_major == right.dev_major and left.dev_minor == right.dev_minor and
        left.ino == right.ino and left.mode == right.mode and left.uid == right.uid;
}

fn inspectTree(ctx: types.Context, root: std.Io.Dir, layout: types.RuntimeLayout, contract: runtime.Contract) !ElfEvidence {
    try requireCopiedLayout(ctx, root, layout, contract);
    var evidence: ElfEvidence = .{
        .native_files = 0,
        .loader_files = @intCast(contract.loader_dependencies.len),
        .needed_edges = 0,
        .interpreter_sha256 = try core.contracts.parseSha256(contract.interpreter.sha256),
        .interpreter_path_sha256 = undefined,
        .interpreter_closure = [_]bool{false} ** runtime.max_loader_files,
    };
    var bounds: WalkBounds = .{};
    try walkElf(ctx, root, "", 0, layout, contract, &evidence, &bounds);
    if (evidence.native_files < 2) return error.IncompleteElfClosure;
    evidence.interpreter_path_sha256 = try interpreterClosure(ctx, root, contract, &evidence.interpreter_closure);
    return evidence;
}

const WalkBounds = struct {
    files: u32 = 0,
    directories: u32 = 1,
    bytes: u64 = 0,
};

fn interpreterClosure(ctx: types.Context, root: std.Io.Dir, contract: runtime.Contract, required: *[runtime.max_loader_files]bool) ![32]u8 {
    const bin = try root.openDir(ctx.io, "bin", .{ .follow_symlinks = false });
    defer bin.close(ctx.io);
    const python = try openRegular(ctx, bin, "python");
    defer python.close(ctx.io);
    var bytes = try readElfFile(ctx, python);
    defer bytes.deinit();
    var info = try inspectElf(ctx.allocator, bytes.bytes(), .interpreter);
    defer info.deinit();
    try addRequired(info, contract, required);
    const loader_dir = try root.openDir(ctx.io, "loader", .{ .follow_symlinks = false });
    defer loader_dir.close(ctx.io);
    var inspected = [_]bool{false} ** runtime.max_loader_files;
    for (contract.loader_dependencies, 0..) |dependency, index|
        if (std.mem.eql(u8, dependency.path, contract.dynamic_loader.path)) {
            required[index] = true;
        };
    var changed = true;
    while (changed) {
        changed = false;
        for (contract.loader_dependencies, 0..) |dependency, index| {
            if (!required[index] or inspected[index]) continue;
            inspected[index] = true;
            changed = true;
            const file = try openRegular(ctx, loader_dir, std.fs.path.basename(dependency.path));
            defer file.close(ctx.io);
            var dependency_bytes = try readElfFile(ctx, file);
            defer dependency_bytes.deinit();
            var dependency_info = try inspectElf(ctx.allocator, dependency_bytes.bytes(), if (std.mem.eql(u8, dependency.path, contract.dynamic_loader.path)) .loader else .library);
            defer dependency_info.deinit();
            try addRequired(dependency_info, contract, required);
        }
    }
    return tx.hash(info.interpreter.?);
}

fn addRequired(info: ElfInfo, contract: runtime.Contract, required: *[runtime.max_loader_files]bool) !void {
    for (info.needed) |name| {
        var found = false;
        for (contract.loader_dependencies, 0..) |dependency, index| if (std.mem.eql(u8, name, std.fs.path.basename(dependency.path))) {
            required[index] = true;
            found = true;
            break;
        };
        if (!found) return error.MissingDependency;
    }
}

fn walkElf(ctx: types.Context, dir: std.Io.Dir, prefix: []const u8, depth: u8, layout: types.RuntimeLayout, contract: runtime.Contract, evidence: *ElfEvidence, bounds: *WalkBounds) !void {
    try checkCancellation(ctx);
    if (depth > runtime.max_depth) return error.RuntimeDepth;
    var iterator = dir.iterate();
    while (try iterator.next(ctx.io)) |entry| {
        try files.basename(entry.name);
        const relative = try std.fs.path.join(ctx.allocator, &.{ prefix, entry.name });
        defer ctx.allocator.free(relative);
        if (prefix.len == 0 and std.mem.eql(u8, entry.name, "lib64")) return error.InvalidRuntimeLayout;
        if (entry.kind == .directory) {
            bounds.directories += 1;
            if (bounds.directories > runtime.max_directories) return error.RuntimeDirectoryLimit;
            const child = try dir.openDir(ctx.io, entry.name, .{ .follow_symlinks = false, .iterate = true });
            defer child.close(ctx.io);
            if ((try directorySnapshot(child)).mode & 0o7777 != 0o500) return error.InvalidCopiedMode;
            try walkElf(ctx, child, relative, depth + 1, layout, contract, evidence, bounds);
        } else if (entry.kind == .file) {
            const file = try openRegular(ctx, dir, entry.name);
            defer file.close(ctx.io);
            const snapshot = try files.snapshot(file);
            if (snapshot.mode & 0o7777 != 0o400 and snapshot.mode & 0o7777 != 0o500) return error.InvalidCopiedMode;
            if (std.mem.eql(u8, relative, "bootstrap/azure-cli") and snapshot.mode & 0o7777 != 0o500)
                return error.InvalidCopiedMode;
            if (snapshot.nlink != 1 or snapshot.size == 0 or snapshot.size > runtime.max_file_bytes or
                (snapshot.uid != 0 and snapshot.uid != std.os.linux.geteuid()))
                return error.UnsafeCopiedEntry;
            bounds.files += 1;
            bounds.bytes = try std.math.add(u64, bounds.bytes, snapshot.size);
            if (bounds.files > runtime.max_files or bounds.bytes > runtime.max_bytes) return error.RuntimeFileLimit;
            const is_interpreter = std.mem.eql(u8, relative, "bin/python");
            const is_loader = std.mem.startsWith(u8, relative, "loader/");
            if (!is_interpreter and !is_loader and std.mem.indexOf(u8, entry.name, ".so") == null) continue;
            var bytes = try readElfFile(ctx, file);
            defer bytes.deinit();
            if (!files.sameSnapshot(snapshot, try files.snapshot(file))) return error.FileChanged;
            if (!std.mem.startsWith(u8, bytes.bytes(), "\x7fELF") and !is_interpreter and !is_loader) continue;
            var role: ElfRole = if (is_interpreter) .interpreter else .native_extension;
            if (is_loader) {
                var declared = false;
                for (contract.loader_dependencies) |artifact| if (exactChild(layout.loader_directory, artifact.path, relative["loader".len..])) {
                    declared = true;
                    if (artifact.size != bytes.bytes().len or !std.crypto.timing_safe.eql([32]u8, tx.hash(bytes.bytes()), try core.contracts.parseSha256(artifact.sha256)))
                        return error.CopiedDependencyChanged;
                    break;
                };
                if (!declared) return error.UndeclaredLoaderFile;
                role = if (std.mem.eql(u8, entry.name, loader_basename)) .loader else .library;
            }
            if ((role == .loader or role == .interpreter) and snapshot.mode & 0o7777 != 0o500) return error.InvalidCopiedMode;
            if (is_loader and role == .library and snapshot.mode & 0o7777 != 0o400) return error.InvalidCopiedMode;
            var info = try inspectElf(ctx.allocator, bytes.bytes(), role);
            defer info.deinit();
            for (info.needed) |name| {
                var found = false;
                for (contract.loader_dependencies) |dependency| if (std.mem.eql(u8, name, std.fs.path.basename(dependency.path))) {
                    found = true;
                    break;
                };
                if (!found) return error.MissingDependency;
                evidence.needed_edges = try std.math.add(u32, evidence.needed_edges, 1);
            }
            evidence.native_files += 1;
            if (evidence.native_files > runtime.max_files) return error.RuntimeFileLimit;
        } else return error.UnsafeCopiedEntry;
    }
}

pub const Step = union(enum) { loader_listing, python_version, imports, command: u8 };
const step_count = runtime.commands.len + 3;

/// Closed argv construction; the caller cannot select extra Azure operations.
pub fn arguments(a: std.mem.Allocator, layout: types.RuntimeLayout, contract: runtime.Contract, step: Step) ![][]const u8 {
    try requireLayout(layout, contract);
    var argv: std.ArrayList([]const u8) = .empty;
    errdefer argv.deinit(a);
    try argv.appendSlice(a, &.{
        contract.dynamic_loader.path, "--inhibit-cache", "--inhibit-rpath", "", "--library-path", layout.loader_directory,
    });
    if (step == .loader_listing) {
        try argv.appendSlice(a, &.{ "--list", layout.interpreter });
    } else {
        try argv.appendSlice(a, &.{ layout.interpreter, "-s", "-S", "-B", "-P" });
        switch (step) {
            .python_version => try argv.append(a, "--version"),
            .imports => try argv.appendSlice(a, &.{ "-c", import_script }),
            .command => |index| {
                if (index >= runtime.commands.len) return error.UnknownProbe;
                try argv.append(a, layout.launcher);
                try argv.appendSlice(a, runtime.commands[index]);
                try argv.appendSlice(a, if (index == 0) &.{ "--output", "json", "--only-show-errors" } else &.{"--help"});
            },
            else => unreachable,
        }
    }
    return argv.toOwnedSlice(a);
}

const import_script =
    "import encodings,json,ssl,ctypes,azure.cli.core," ++
    "azure.cli.command_modules.resource,azure.cli.command_modules.vm\n" ++
    "print('UK-WAMR-AZURE-IMPORTS-1')\n";

pub fn environment(a: std.mem.Allocator, layout: types.RuntimeLayout, contract: runtime.Contract) !std.process.Environ.Map {
    try requireLayout(layout, contract);
    var env = std.process.Environ.Map.init(a);
    errdefer env.deinit();
    try env.put("HOME", layout.output);
    try env.put("AZURE_CONFIG_DIR", layout.startup_config);
    try env.put("LC_ALL", "C");
    try env.put("AZURE_CORE_COLLECT_TELEMETRY", "0");
    try env.put("AZURE_EXTENSION_DIR", layout.extensions);
    try env.put("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "no");
    try env.put("PYTHONHOME", layout.root);
    try env.put("PYTHONNOUSERSITE", "1");
    try env.put("PYTHONSAFEPATH", "1");
    try env.put("PYTHONDONTWRITEBYTECODE", "1");
    return env;
}

pub const CommandEvidence = struct {
    primary: process.CommandPrimary,
    termination: ?std.process.Child.Term,
    cleanup: process.CommandCleanup,
    cleanup_complete: bool,
    stdout_status: process.CommandStreamStatus,
    stderr_status: process.CommandStreamStatus,
    descendants: process.CommandDescendants,
    executable: process.ExecutableIdentity,
    executable_stable: bool,
    cancellation_observed: bool,
    primary_deadline_reached: bool,
    started_ns: u64,
    primary_completed_ns: u64,
    completed_ns: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_sha256: [32]u8,
    stderr_sha256: [32]u8,
    freshness: ?anyerror,
    /// Whole-stream redaction: no child text, path, credential or UTF8 fragment.
    stdout_redacted: []const u8,
    stderr_redacted: []const u8,
    supervision_passed: bool,
};
fn supervisionPassed(result: tx.Supervised) bool {
    return result.succeeded() and result.result.descendants.observed == 0 and
        result.result.descendants.adopted == 0;
}
fn commandEvidence(result: tx.Supervised) CommandEvidence {
    const r = result.result;
    return .{
        .primary = r.primary,
        .termination = r.termination,
        .cleanup = r.cleanup,
        .cleanup_complete = r.cleanup_complete,
        .stdout_status = r.stdout_status,
        .stderr_status = r.stderr_status,
        .descendants = r.descendants,
        .executable = r.executable,
        .executable_stable = r.executable_stable,
        .cancellation_observed = r.cancellation_observed,
        .primary_deadline_reached = r.primary_deadline_reached,
        .started_ns = r.started_ns,
        .primary_completed_ns = r.primary_completed_ns,
        .completed_ns = r.completed_ns,
        .stdout_bytes = r.stdout.len,
        .stderr_bytes = r.stderr.len,
        .stdout_sha256 = tx.hash(r.stdout),
        .stderr_sha256 = tx.hash(r.stderr),
        .freshness = result.freshness,
        .stdout_redacted = if (r.stdout.len == 0) "" else "[redacted]",
        .stderr_redacted = if (r.stderr.len == 0) "" else "[redacted]",
        .supervision_passed = supervisionPassed(result),
    };
}
pub const Failure = struct {
    step: ?Step,
    cause: anyerror,
    command: ?CommandEvidence = null,
    completed_steps: u8,
};
pub const Evidence = struct {
    elf: ElfEvidence,
    probes: [step_count]CommandEvidence,
    loader_entries: u16,
    content_sha256: [32]u8,
    metadata_sha256: [32]u8,
    parents_sha256: [32]u8,
    manifest_sha256: [32]u8,
};
pub const Result = union(enum) { complete: Evidence, refused: Failure };

pub const SealedInput = struct {
    /// A real direct seal, never constructed by test hooks or child metadata.
    sealed: *const runtime.Sealed,
    layout: types.RuntimeLayout,
    contract: runtime.Contract,
    /// Retained 0700 output directory (cwd/HOME), outside the readonly root.
    cwd: std.Io.Dir,
    /// Independent source-owner barrier, compatible with the helper's overlay.
    /// Do not use the parent's named-stage barrier after sealing in its namespace.
    barrier: tx.Barrier,
};
const SealedChecks = struct {
    ctx: types.Context,
    input: SealedInput,
    fn check(raw: *anyopaque) !void {
        const self: *SealedChecks = @ptrCast(@alignCast(raw));
        try checkCancellation(self.ctx);
        try self.input.barrier.revalidate();
        try self.input.sealed.verify(self.ctx.allocator, self.ctx.io, self.input.contract);
        const named = try std.Io.Dir.openDirAbsolute(self.ctx.io, self.input.layout.output, .{ .follow_symlinks = false });
        defer named.close(self.ctx.io);
        const cwd = try directorySnapshot(self.input.cwd);
        if (cwd.mode & 0o7777 != 0o700 or !sameDirectory(cwd, try directorySnapshot(named)))
            return error.ProbeCwdChanged;
        const config = try self.input.cwd.openDir(self.ctx.io, "startup-config", .{ .follow_symlinks = false });
        defer config.close(self.ctx.io);
        if ((try directorySnapshot(config)).mode & 0o7777 != 0o700) return error.InvalidStartupConfig;
    }
    fn barrier(self: *SealedChecks) tx.Barrier {
        return .{ .context = self, .check = check };
    }
};

/// Call only in the owning helper's isolated namespace. On non-x86 hosts this
/// refuses without executing a host Python or manufacturing runtime evidence.
pub fn runSealed(ctx: types.Context, input: SealedInput) Result {
    requireLayout(input.layout, input.contract) catch |err| return refusal(null, err, null, 0);
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux)
        return refusal(null, error.CompatibleRuntimeUnavailable, null, 0);
    var checks: SealedChecks = .{ .ctx = ctx, .input = input };
    checks.barrier().revalidate() catch |err| return refusal(null, err, null, 0);
    const elf_evidence = inspectTree(ctx, input.sealed.root, input.layout, input.contract) catch |err| return refusal(null, err, null, 0);
    var env = environment(ctx.allocator, input.layout, input.contract) catch |err| return refusal(null, err, null, 0);
    defer env.deinit();
    const outer = process.Deadline.afterMilliseconds(total_ms) catch |err| return refusal(null, err, null, 0);
    var evidence: Evidence = undefined;
    evidence.elf = elf_evidence;
    evidence.content_sha256 = core.contracts.parseSha256(input.contract.content_sha256) catch |err| return refusal(null, err, null, 0);
    evidence.metadata_sha256 = core.contracts.parseSha256(input.contract.metadata_sha256) catch |err| return refusal(null, err, null, 0);
    evidence.parents_sha256 = core.contracts.parseSha256(input.contract.parents_sha256) catch |err| return refusal(null, err, null, 0);
    evidence.manifest_sha256 = core.contracts.parseSha256(input.contract.manifest.sha256) catch |err| return refusal(null, err, null, 0);
    for (0..step_count) |index| {
        const step: Step = switch (index) {
            0 => .loader_listing,
            1 => .python_version,
            2 => .imports,
            else => .{ .command = @intCast(index - 3) },
        };
        const argv = arguments(ctx.allocator, input.layout, input.contract, step) catch |err| return refusal(step, err, null, @intCast(index));
        defer ctx.allocator.free(argv);
        var supervised = execute(ctx, input.sealed.loader, input.cwd, &env, argv, checks.barrier(), outer, command_ms, output_limit) catch |err|
            return refusal(step, err, null, @intCast(index));
        defer supervised.deinit(ctx.allocator);
        const summary = commandEvidence(supervised);
        if (!summary.supervision_passed) return refusal(step, error.RuntimeProbeFailed, summary, @intCast(index));
        switch (step) {
            .loader_listing => evidence.loader_entries = validateListing(ctx.allocator, supervised.result.stdout, input.layout, input.contract, elf_evidence.interpreter_closure[0..input.contract.loader_dependencies.len], elf_evidence.interpreter_path_sha256) catch |err|
                return refusal(step, err, summary, @intCast(index)),
            .python_version => validatePythonVersion(supervised.result.stdout, supervised.result.stderr, input.contract.python_version) catch |err|
                return refusal(step, err, summary, @intCast(index)),
            .imports => if (!std.mem.eql(u8, supervised.result.stdout, "UK-WAMR-AZURE-IMPORTS-1\n"))
                return refusal(step, error.InvalidImportProbe, summary, @intCast(index)),
            .command => |command| validateCommand(ctx.allocator, command, supervised.result.stdout) catch |err|
                return refusal(step, err, summary, @intCast(index)),
        }
        evidence.probes[index] = summary;
    }
    checks.barrier().revalidate() catch |err| return refusal(null, err, null, step_count);
    return .{ .complete = evidence };
}

fn refusal(step: ?Step, cause: anyerror, command: ?CommandEvidence, completed: u8) Result {
    return .{ .refused = .{ .step = step, .cause = cause, .command = command, .completed_steps = completed } };
}

fn execute(ctx: types.Context, executable: process.Executable, cwd: std.Io.Dir, env: *const std.process.Environ.Map, argv: []const []const u8, barrier: tx.Barrier, outer: process.Deadline, milliseconds: u32, cap: usize) !tx.Supervised {
    const now = try process.monotonicNanoseconds();
    if (now >= outer.expires_ns) return error.BudgetExhausted;
    const primary: process.Deadline = .{ .expires_ns = @min(outer.expires_ns, try std.math.add(u64, now, @as(u64, milliseconds) * std.time.ns_per_ms)) };
    return tx.supervise(ctx, .{
        .executable = executable,
        .argv = argv,
        .cwd = cwd,
        .environment = env,
        .primary_deadline = primary,
        .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, primary.expires_ns, cleanup_ms * std.time.ns_per_ms) },
        .capture = .{ .merged = cap },
        .limits = .{ .stdout_bytes = cap, .stderr_bytes = cap },
        .snapshot_executable = true,
    }, barrier);
}

fn validatePythonVersion(stdout: []const u8, stderr: []const u8, version: []const u8) !void {
    const value = if (stdout.len != 0) stdout else stderr;
    if (value.len > 128 or !std.mem.startsWith(u8, value, "Python ") or !std.mem.endsWith(u8, value, "\n"))
        return error.InvalidPythonVersion;
    const text = value["Python ".len .. value.len - 1];
    if (text.len <= version.len + 1 or !std.mem.startsWith(u8, text, version) or text[version.len] != '.')
        return error.InvalidPythonVersion;
    for (text[version.len + 1 ..]) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidPythonVersion;
}

fn validateCommand(a: std.mem.Allocator, index: u8, output: []const u8) !void {
    if (output.len == 0 or !std.unicode.utf8ValidateSlice(output) or std.mem.indexOfScalar(u8, output, 0) != null)
        return error.InvalidCommandProbe;
    if (index != 0) return;
    var document = try core.contracts.Document.parse(a, output, .{ .bytes = output_limit, .depth = 16, .items = 4096, .string_bytes = 64 * 1024 });
    defer document.deinit();
    const object = try core.contracts.exactFields(document.value(), &.{ "azure-cli", "azure-cli-core", "azure-cli-telemetry", "extensions" });
    for ([_][]const u8{ "azure-cli", "azure-cli-core", "azure-cli-telemetry" }) |name| {
        const value = object.get(name).?;
        if (value != .string or value.string.len == 0 or value.string.len > 128) return error.InvalidCommandProbe;
    }
    const extensions = object.get("extensions").?;
    if (extensions != .object or extensions.object.count() != 0) return error.InvalidCommandProbe;
}

/// Loader text is only a cross-check against independently verified artifacts;
/// it is never used to discover, copy or authorize an unretained dependency.
pub fn validateListing(a: std.mem.Allocator, bytes: []const u8, layout: types.RuntimeLayout, contract: runtime.Contract, required: []const bool, interpreter_path_sha256: [32]u8) !u16 {
    try requireLayout(layout, contract);
    if (required.len != contract.loader_dependencies.len) return error.IncompleteLoaderListing;
    if (bytes.len == 0 or bytes.len > output_limit or !std.unicode.utf8ValidateSlice(bytes) or std.mem.indexOfScalar(u8, bytes, 0) != null)
        return error.InvalidLoaderListing;
    var seen = try a.alloc(bool, contract.loader_dependencies.len);
    defer a.free(seen);
    @memset(seen, false);
    var vdso = false;
    var count: u16 = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;
        const tail = std.mem.lastIndexOf(u8, line, " (0x") orelse return error.InvalidLoaderListing;
        if (line[line.len - 1] != ')' or line.len - tail < 6 or line.len - tail > 21)
            return error.InvalidLoaderListing;
        for (line[tail + 4 .. line.len - 1]) |byte| if (!std.ascii.isHex(byte)) return error.InvalidLoaderListing;
        const body = line[0..tail];
        if (std.mem.eql(u8, body, "linux-vdso.so.1")) {
            if (vdso) return error.InvalidLoaderListing;
            vdso = true;
            continue;
        }
        const arrow = std.mem.indexOf(u8, body, " => ");
        const path = if (arrow) |offset| body[offset + 4 ..] else body;
        try absolutePath(path);
        if (!std.mem.startsWith(u8, path, layout.loader_directory) or path.len <= layout.loader_directory.len + 1 or
            path[layout.loader_directory.len] != '/' or std.mem.indexOfScalar(u8, path[layout.loader_directory.len + 1 ..], '/') != null)
            return error.LoaderEscapedClosure;
        var found = false;
        for (contract.loader_dependencies, 0..) |dependency, index| {
            if (!std.mem.eql(u8, dependency.path, path)) continue;
            if (seen[index]) return error.InvalidLoaderListing;
            if (arrow) |offset| {
                const name = body[0..offset];
                if (!std.mem.eql(u8, name, std.fs.path.basename(path))) {
                    if (!std.mem.eql(u8, std.fs.path.basename(path), loader_basename))
                        return error.InvalidLoaderListing;
                    try absolutePath(name);
                    if (!std.mem.eql(u8, name, contract.dynamic_loader.path) and
                        !std.crypto.timing_safe.eql([32]u8, tx.hash(name), interpreter_path_sha256))
                        return error.InvalidLoaderListing;
                }
            }
            seen[index] = true;
            found = true;
            count += 1;
            break;
        }
        if (!found) return error.LoaderEscapedClosure;
    }
    if (count == 0) return error.IncompleteLoaderListing;
    var loader_seen = false;
    for (contract.loader_dependencies, seen, required) |dependency, present, obligation| {
        if (obligation and !present) return error.IncompleteLoaderListing;
        if (std.mem.eql(u8, dependency.path, contract.dynamic_loader.path)) {
            loader_seen = present;
        }
    }
    if (!loader_seen) return error.IncompleteLoaderListing;
    return count;
}

pub const Test = struct {
    pub const Fault = enum { exit, overflow, timeout, signal, escaped_descendant, stdin_environment, cancelled };
    /// Exercises the same retained-command adapter, never a copied runtime or a
    /// successful preparation. Even a fixture exit-zero cannot produce Evidence.
    pub fn fault(ctx: types.Context, executable: process.Executable, cwd: std.Io.Dir, path: []const u8, barrier: tx.Barrier, selected: Fault) !CommandEvidence {
        if (!builtin.is_test) @compileError("Runtime probe fixtures are test-only");
        var env = std.process.Environ.Map.init(ctx.allocator);
        defer env.deinit();
        var result = try execute(ctx, executable, cwd, &env, &.{ path, @tagName(selected) }, barrier, try process.Deadline.afterMilliseconds(10_000), if (selected == .cancelled) 3000 else 150, 4096);
        defer result.deinit(ctx.allocator);
        return commandEvidence(result);
    }
    pub fn pythonVersion(stdout: []const u8, stderr: []const u8, version: []const u8) !void {
        if (!builtin.is_test) @compileError("Test-only");
        return validatePythonVersion(stdout, stderr, version);
    }
    pub fn command(a: std.mem.Allocator, index: u8, output: []const u8) !void {
        if (!builtin.is_test) @compileError("Test-only");
        return validateCommand(a, index, output);
    }
};
