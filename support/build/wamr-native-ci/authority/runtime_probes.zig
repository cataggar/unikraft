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
    var programs: [1024]std.elf.Elf64.Phdr = undefined;
    var dynamic: ?std.elf.Elf64.Phdr = null;
    var result: ElfInfo = .{ .allocator = a, .entry = try elf.integer(u64, bytes, 24, .little) };
    errdefer result.deinit();
    var entry_loaded = false;
    var loads: usize = 0;
    for (programs[0..phnum], 0..) |*ph, index| {
        ph.* = try elf.structure(std.elf.Elf64.Phdr, bytes, phoff + index * 56, .little);
        _ = try elf.range(bytes, ph.offset, ph.filesz);
        _ = try elf.add(ph.vaddr, ph.memsz);
        switch (ph.type) {
            .LOAD => {
                loads += 1;
                if (ph.filesz > ph.memsz or @as(u32, @bitCast(ph.flags)) & ~@as(u32, 7) != 0 or
                    (ph.@"align" > 1 and (!std.math.isPowerOfTwo(ph.@"align") or
                        ph.offset % ph.@"align" != ph.vaddr % ph.@"align")))
                    return error.InvalidElf;
                if (ph.flags.X and result.entry >= ph.vaddr and
                    result.entry - ph.vaddr < ph.filesz)
                    entry_loaded = true;
            },
            .INTERP => {
                if (result.interpreter != null or ph.filesz < 2 or ph.filesz > 4096)
                    return error.InvalidInterpreter;
                const value = try elf.range(bytes, ph.offset, ph.filesz);
                if (value[value.len - 1] != 0 or std.mem.indexOfScalar(u8, value[0 .. value.len - 1], 0) != null)
                    return error.InvalidInterpreter;
                try absolutePath(value[0 .. value.len - 1]);
                if (!std.mem.eql(u8, std.fs.path.basename(value[0 .. value.len - 1]), loader_basename))
                    return error.InvalidInterpreter;
                result.interpreter = try a.dupe(u8, value[0 .. value.len - 1]);
            },
            .DYNAMIC => {
                if (dynamic != null or ph.filesz == 0 or ph.filesz % 16 != 0 or ph.filesz / 16 > 4096)
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
    if (try mappedOffset(programs[0..phnum], dyn.vaddr, dyn.filesz) != dyn.offset)
        return error.InvalidDynamic;
    var string_address: ?u64 = null;
    var string_size: ?u64 = null;
    var ended = false;
    var entries: [4096]std.elf.Elf64_Dyn = undefined;
    var count: usize = 0;
    while (count < dyn.filesz / 16) : (count += 1) {
        const entry = try elf.structure(std.elf.Elf64_Dyn, bytes, dyn.offset + count * 16, .little);
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

fn mappedOffset(programs: []const std.elf.Elf64.Phdr, address: u64, size: u64) !u64 {
    var result: ?u64 = null;
    for (programs) |ph| {
        if (ph.type != .LOAD or address < ph.vaddr) continue;
        const delta = address - ph.vaddr;
        if (delta > ph.filesz or size > ph.filesz - delta) continue;
        if (result != null) return error.AmbiguousLoad;
        result = try elf.add(ph.offset, delta);
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
pub const StandaloneDiscovery = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    retained: std.ArrayList(*files.RetainedFile) = .empty,
    input: DiscoveryInput = undefined,

    pub fn deinit(self: *StandaloneDiscovery, io: std.Io) void {
        for (self.retained.items) |file| file.close(io);
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn init(ctx: types.Context, request: types.PrepareRuntime) !StandaloneDiscovery {
        try checkCancellation(ctx);
        try absolutePath(request.output);
        try absolutePath(request.azure);
        try absolutePath(request.az_python);
        try absolutePath(request.stdlib);
        try absolutePath(request.validator);
        for (request.package_root) |path| try absolutePath(path);
        for (request.data_root) |path| try absolutePath(path);
        for (request.native_dependency, 0..) |path, index| {
            try absolutePath(path);
            for (request.native_dependency[0..index]) |prior|
                if (std.mem.eql(u8, path, prior)) return error.DuplicateSource;
        }

        var self: StandaloneDiscovery = .{
            .allocator = ctx.allocator,
            .arena = std.heap.ArenaAllocator.init(ctx.allocator),
        };
        errdefer self.deinit(ctx.io);
        const arena = self.arena.allocator();

        var opened_by_path: std.StringHashMapUnmanaged(*files.RetainedFile) = .empty;
        const interpreter = try self.openRetained(ctx.io, &opened_by_path, request.az_python);
        var interpreter_bytes = try readRetained(ctx, interpreter);
        defer interpreter_bytes.deinit();
        var interpreter_info = try inspectElf(arena, interpreter_bytes.bytes(), .interpreter);
        defer interpreter_info.deinit();

        const loader_path = try std.Io.Dir.cwd().realPathFileAlloc(ctx.io, interpreter_info.interpreter.?, arena);
        try absolutePath(loader_path);
        if (!std.mem.eql(u8, std.fs.path.basename(loader_path), loader_basename))
            return error.InvalidLoaderSource;
        const dynamic_loader = try self.openRetained(ctx.io, &opened_by_path, loader_path);

        var native_roots: std.ArrayList(*files.RetainedFile) = .empty;
        var needed_queue: std.ArrayList([]const u8) = .empty;
        var queued_names: std.StringHashMapUnmanaged(void) = .empty;
        try queued_names.put(arena, loader_basename, {});

        try self.scanSourceTree(ctx, &opened_by_path, &native_roots, &needed_queue, &queued_names, request.stdlib);
        for (request.package_root) |root_path|
            try self.scanSourceTree(ctx, &opened_by_path, &native_roots, &needed_queue, &queued_names, root_path);
        for (request.data_root) |root_path|
            try self.scanSourceTree(ctx, &opened_by_path, &native_roots, &needed_queue, &queued_names, root_path);

        for (interpreter_info.needed) |needed_name|
            try enqueueNeeded(arena, &needed_queue, &queued_names, needed_name);

        var candidates: std.ArrayList(*files.RetainedFile) = .empty;
        var candidate_names: std.ArrayList([]const u8) = .empty;
        var satisfied_names: std.StringHashMapUnmanaged(void) = .empty;
        try satisfied_names.put(arena, loader_basename, {});
        var soname_providers: std.StringHashMapUnmanaged(*files.RetainedFile) = .empty;

        for (request.native_dependency) |dep_path| {
            if (candidates.items.len >= runtime.max_loader_files) return error.LoaderLimit;
            const dep_file = try self.openRetained(ctx.io, &opened_by_path, dep_path);
            const dep_basename = std.fs.path.basename(dep_path);
            try dependencyName(dep_basename);
            var dep_bytes = try readRetained(ctx, dep_file);
            defer dep_bytes.deinit();
            var dep_info = try inspectElf(
                arena,
                dep_bytes.bytes(),
                if (std.mem.eql(u8, dep_basename, loader_basename)) .loader else .library,
            );
            defer dep_info.deinit();
            for (dep_info.needed) |needed_name|
                try enqueueNeeded(arena, &needed_queue, &queued_names, needed_name);
            const owned_name = try arena.dupe(u8, dep_basename);
            try candidates.append(arena, dep_file);
            try candidate_names.append(arena, owned_name);
            try satisfied_names.put(arena, owned_name, {});
            if (dep_info.soname) |soname| {
                if (!std.mem.eql(u8, soname, dep_basename) and !soname_providers.contains(soname)) {
                    try soname_providers.put(arena, try arena.dupe(u8, soname), dep_file);
                }
            }
        }

        var search_dirs: std.ArrayList([]const u8) = .empty;
        for (request.native_dependency) |dep_path| {
            if (std.fs.path.dirname(dep_path)) |dir_path|
                try addSearchDir(arena, &search_dirs, request, dir_path);
        }
        if (std.fs.path.dirname(request.az_python)) |py_dir| {
            try addSearchDir(arena, &search_dirs, request, py_dir);
            try addSearchDir(arena, &search_dirs, request, try std.fs.path.join(arena, &.{ py_dir, "lib" }));
            if (std.fs.path.dirname(py_dir)) |prefix| {
                if (!std.mem.eql(u8, prefix, "/")) {
                    try addSearchDir(arena, &search_dirs, request, try std.fs.path.join(arena, &.{ prefix, "lib" }));
                    try addSearchDir(arena, &search_dirs, request, try std.fs.path.join(arena, &.{ prefix, "lib64" }));
                }
            }
        }
        if (std.fs.path.dirname(request.stdlib)) |stdlib_parent|
            try addSearchDir(arena, &search_dirs, request, stdlib_parent);
        if (std.fs.path.dirname(interpreter_info.interpreter.?)) |interp_dir|
            try addSearchDir(arena, &search_dirs, request, interp_dir);
        if (std.fs.path.dirname(loader_path)) |loader_dir|
            try addSearchDir(arena, &search_dirs, request, loader_dir);
        if (isSystemLoaderPath(interpreter_info.interpreter.?)) {
            for ([_][]const u8{
                "/lib/x86_64-linux-gnu",
                "/usr/lib/x86_64-linux-gnu",
                "/lib64",
                "/usr/lib64",
                "/lib",
                "/usr/lib",
            }) |sys_dir| {
                try addSearchDir(arena, &search_dirs, request, sys_dir);
            }
        }

        var cursor: usize = 0;
        while (cursor < needed_queue.items.len) : (cursor += 1) {
            try checkCancellation(ctx);
            const needed_name = needed_queue.items[cursor];
            try dependencyName(needed_name);
            if (satisfied_names.contains(needed_name)) continue;
            if (candidates.items.len >= runtime.max_loader_files) return error.LoaderLimit;

            if (soname_providers.get(needed_name)) |provider| {
                const owned_name = try arena.dupe(u8, needed_name);
                try candidates.append(arena, provider);
                try candidate_names.append(arena, owned_name);
                try satisfied_names.put(arena, owned_name, {});
                continue;
            }

            const resolved_path = (try self.resolveCandidatePath(
                ctx,
                &opened_by_path,
                request,
                search_dirs.items,
                needed_name,
            )) orelse return error.MissingDependency;
            const dso_file = try self.openRetained(ctx.io, &opened_by_path, resolved_path);
            var dso_bytes = try readRetained(ctx, dso_file);
            defer dso_bytes.deinit();
            var dso_info = try inspectElf(arena, dso_bytes.bytes(), .library);
            defer dso_info.deinit();
            for (dso_info.needed) |transitive|
                try enqueueNeeded(arena, &needed_queue, &queued_names, transitive);
            const owned_name = try arena.dupe(u8, needed_name);
            try candidates.append(arena, dso_file);
            try candidate_names.append(arena, owned_name);
            try satisfied_names.put(arena, owned_name, {});
        }

        self.input = .{
            .interpreter = interpreter,
            .dynamic_loader = dynamic_loader,
            .native_roots = try native_roots.toOwnedSlice(arena),
            .candidates = try candidates.toOwnedSlice(arena),
            .candidate_names = try candidate_names.toOwnedSlice(arena),
        };
        return self;
    }

    fn openRetained(
        self: *StandaloneDiscovery,
        io: std.Io,
        opened_by_path: *std.StringHashMapUnmanaged(*files.RetainedFile),
        path: []const u8,
    ) !*files.RetainedFile {
        if (opened_by_path.get(path)) |existing| return existing;
        const arena = self.arena.allocator();
        const owned_path = try arena.dupe(u8, path);
        const ptr = try arena.create(files.RetainedFile);
        ptr.* = try files.RetainedFile.open(io, owned_path, .artifact);
        errdefer ptr.close(io);
        try self.retained.append(arena, ptr);
        try opened_by_path.put(arena, owned_path, ptr);
        return ptr;
    }

    fn scanSourceTree(
        self: *StandaloneDiscovery,
        ctx: types.Context,
        opened_by_path: *std.StringHashMapUnmanaged(*files.RetainedFile),
        native_roots: *std.ArrayList(*files.RetainedFile),
        needed_queue: *std.ArrayList([]const u8),
        queued_names: *std.StringHashMapUnmanaged(void),
        root_path: []const u8,
    ) !void {
        var root_dir = try files.openDirectory(ctx.io, root_path, .artifact);
        defer root_dir.close(ctx.io);
        try self.scanSourceDir(ctx, opened_by_path, native_roots, needed_queue, queued_names, root_dir, root_path, 0);
    }

    fn scanSourceDir(
        self: *StandaloneDiscovery,
        ctx: types.Context,
        opened_by_path: *std.StringHashMapUnmanaged(*files.RetainedFile),
        native_roots: *std.ArrayList(*files.RetainedFile),
        needed_queue: *std.ArrayList([]const u8),
        queued_names: *std.StringHashMapUnmanaged(void),
        dir: std.Io.Dir,
        dir_path: []const u8,
        depth: usize,
    ) !void {
        try checkCancellation(ctx);
        if (depth > runtime.max_depth) return error.RuntimeLimit;
        const arena = self.arena.allocator();
        var names: std.ArrayList([]const u8) = .empty;
        var iterator = dir.iterate();
        while (try iterator.next(ctx.io)) |entry| {
            try checkCancellation(ctx);
            try files.basename(entry.name);
            if (!std.unicode.utf8ValidateSlice(entry.name)) return error.UnsafePath;
            try names.append(arena, try arena.dupe(u8, entry.name));
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, left: []const u8, right: []const u8) bool {
                return std.mem.order(u8, left, right) == .lt;
            }
        }.less);
        for (names.items) |name| {
            try checkCancellation(ctx);
            const path_file = try dir.openFile(ctx.io, name, .{ .path_only = true, .follow_symlinks = false });
            defer path_file.close(ctx.io);
            const before = try files.snapshot(path_file);
            switch (before.mode & std.os.linux.S.IFMT) {
                std.os.linux.S.IFDIR => {
                    var child_dir = try dir.openDir(ctx.io, name, .{ .iterate = true, .follow_symlinks = false });
                    defer child_dir.close(ctx.io);
                    const child_path = try std.fs.path.join(arena, &.{ dir_path, name });
                    try self.scanSourceDir(ctx, opened_by_path, native_roots, needed_queue, queued_names, child_dir, child_path, depth + 1);
                },
                std.os.linux.S.IFREG => {
                    if (std.mem.indexOf(u8, name, ".so") != null) {
                        if (native_roots.items.len >= runtime.max_files) return error.LoaderLimit;
                        const member_path = try std.fs.path.join(arena, &.{ dir_path, name });
                        if (opened_by_path.contains(member_path)) return error.DuplicateSource;
                        const retained = try self.openRetained(ctx.io, opened_by_path, member_path);
                        try native_roots.append(arena, retained);
                        var bytes = try readRetained(ctx, retained);
                        defer bytes.deinit();
                        if (std.mem.startsWith(u8, bytes.bytes(), "\x7fELF")) {
                            var info = try inspectElf(arena, bytes.bytes(), .native_extension);
                            defer info.deinit();
                            for (info.needed) |needed_name|
                                try enqueueNeeded(arena, needed_queue, queued_names, needed_name);
                        }
                    }
                },
                else => return error.UnsafeSource,
            }
        }
    }

    fn resolveCandidatePath(
        self: *StandaloneDiscovery,
        ctx: types.Context,
        opened_by_path: *std.StringHashMapUnmanaged(*files.RetainedFile),
        request: types.PrepareRuntime,
        search_dirs: []const []const u8,
        needed_name: []const u8,
    ) !?[]const u8 {
        const arena = self.arena.allocator();
        for (search_dirs) |dir_path| {
            const candidate = try std.fs.path.join(arena, &.{ dir_path, needed_name });
            const resolved = std.Io.Dir.cwd().realPathFileAlloc(ctx.io, candidate, arena) catch continue;
            if (!isDisjointFromTrees(request, resolved)) continue;
            try absolutePath(resolved);
            return resolved;
        }
        for (search_dirs) |dir_path| {
            if (isSystemLoaderPath(dir_path)) continue;
            var dir = std.Io.Dir.openDirAbsolute(ctx.io, dir_path, .{ .iterate = true }) catch continue;
            defer dir.close(ctx.io);
            var entries: std.ArrayList([]const u8) = .empty;
            var it = dir.iterate();
            while (it.next(ctx.io) catch null) |entry| {
                if (std.mem.indexOf(u8, entry.name, ".so") == null) continue;
                try entries.append(arena, try arena.dupe(u8, entry.name));
            }
            std.mem.sort([]const u8, entries.items, {}, struct {
                fn less(_: void, left: []const u8, right: []const u8) bool {
                    return std.mem.order(u8, left, right) == .lt;
                }
            }.less);
            for (entries.items) |entry_name| {
                const candidate = try std.fs.path.join(arena, &.{ dir_path, entry_name });
                const resolved = std.Io.Dir.cwd().realPathFileAlloc(ctx.io, candidate, arena) catch continue;
                if (!isDisjointFromTrees(request, resolved)) continue;
                if (std.mem.eql(u8, resolved, request.az_python) or std.mem.eql(u8, resolved, request.azure)) continue;
                absolutePath(resolved) catch continue;
                const dso = self.openRetained(ctx.io, opened_by_path, resolved) catch continue;
                var bytes = readRetained(ctx, dso) catch continue;
                defer bytes.deinit();
                if (!std.mem.startsWith(u8, bytes.bytes(), "\x7fELF")) continue;
                var info = inspectElf(arena, bytes.bytes(), .library) catch continue;
                defer info.deinit();
                if (info.soname) |soname| {
                    if (std.mem.eql(u8, soname, needed_name)) return resolved;
                }
            }
        }
        return null;
    }
};

fn enqueueNeeded(
    arena: std.mem.Allocator,
    needed_queue: *std.ArrayList([]const u8),
    queued_names: *std.StringHashMapUnmanaged(void),
    name: []const u8,
) !void {
    if (queued_names.contains(name)) return;
    const owned = try arena.dupe(u8, name);
    try queued_names.put(arena, owned, {});
    try needed_queue.append(arena, owned);
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    return std.mem.eql(u8, parent, child) or
        (child.len > parent.len and std.mem.startsWith(u8, child, parent) and child[parent.len] == '/');
}

fn isDisjointFromTrees(request: types.PrepareRuntime, path: []const u8) bool {
    if (pathContains(request.output, path) or pathContains(path, request.output)) return false;
    if (pathContains(request.stdlib, path) or pathContains(path, request.stdlib)) return false;
    for (request.package_root) |root_path|
        if (pathContains(root_path, path) or pathContains(path, root_path)) return false;
    for (request.data_root) |root_path|
        if (pathContains(root_path, path) or pathContains(path, root_path)) return false;
    return true;
}

fn isSystemLoaderPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/lib") or
        std.mem.eql(u8, path, "/lib64") or
        std.mem.eql(u8, path, "/usr/lib") or
        std.mem.eql(u8, path, "/usr/lib64") or
        std.mem.startsWith(u8, path, "/lib/") or
        std.mem.startsWith(u8, path, "/lib64/") or
        std.mem.startsWith(u8, path, "/usr/lib/") or
        std.mem.startsWith(u8, path, "/usr/lib64/");
}

fn addSearchDir(
    arena: std.mem.Allocator,
    search_dirs: *std.ArrayList([]const u8),
    request: types.PrepareRuntime,
    dir_path: []const u8,
) !void {
    if (dir_path.len < 2 or dir_path[0] != '/') return;
    if (pathContains(request.output, dir_path) or pathContains(request.stdlib, dir_path)) return;
    for (request.package_root) |root_path| if (pathContains(root_path, dir_path)) return;
    for (request.data_root) |root_path| if (pathContains(root_path, dir_path)) return;
    for (search_dirs.items) |existing| if (std.mem.eql(u8, existing, dir_path)) return;
    try search_dirs.append(arena, try arena.dupe(u8, dir_path));
}
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

fn hashFileBytes(snapshot: files.Snapshot, bytes: []const u8) [32]u8 {
    if (bytes.len >= runtime.DigestCache.min_size) {
        const w = runtime.DigestCache.probe_window;
        const mid: usize = if (bytes.len >= 2 * 1024 * 1024) 1024 * 1024 else (bytes.len / 2) & ~@as(usize, 4095);
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(bytes[0..w]);
        hasher.update(bytes[mid .. mid + w]);
        hasher.update(bytes[bytes.len - w .. bytes.len]);
        const bh = hasher.final();
        if (runtime.DigestCache.get(snapshot, 1, bh)) |cached| return cached.digest;
        const digest = tx.hash(bytes);
        runtime.DigestCache.put(snapshot, 1, bh, digest, 0, 0);
        return digest;
    }
    return tx.hash(bytes);
}

fn appendSource(ctx: types.Context, sources: *std.ArrayList(Source), file: *files.RetainedFile, name: []const u8, role: ElfRole) !void {
    if (sources.items.len >= runtime.max_loader_files) return error.LoaderLimit;
    try absolutePath(file.path);
    try dependencyName(name);
    var bytes = try readRetained(ctx, file);
    defer bytes.deinit();
    var info = try inspectElf(ctx.allocator, bytes.bytes(), role);
    errdefer info.deinit();
    try sources.append(ctx.allocator, .{ .file = file, .name = name, .info = info, .digest = hashFileBytes(file.file_snapshot, bytes.bytes()) });
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
    const library_name = try ctx.allocator.print("python{s}", .{contract.python_version});
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
        .interpreter_closure = @as([runtime.max_loader_files]bool, @splat(false)),
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
    var inspected = @as([runtime.max_loader_files]bool, @splat(false));
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
                    const actual_digest = hashFileBytes(snapshot, bytes.bytes());
                    if (artifact.size != bytes.bytes().len or !std.crypto.timing_safe.eql([32]u8, actual_digest, try core.contracts.parseSha256(artifact.sha256)))
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
