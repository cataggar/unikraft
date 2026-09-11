const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const elf = @import("producer_elf");
const paths = @import("facade_paths");

const ElfInfo = struct {
    needed: []const []const u8,
    soname: ?[]const u8 = null,
    interpreter: ?[]const u8 = null,
};

pub const Role = enum { git, zig, make, bison, flex, m4, llvm, miz, qemu, firmware, bison_data, dependencies, trust, preparation };
pub const Origin = struct {
    scheme: enum { git, zig_package, authenticated_distribution },
    revision: []const u8,
    source_sha256: c.Sha,
    producer_sha256: c.Sha,
};
pub const Tool = struct {
    role: Role,
    origin: Origin,
    target: enum { aarch64_linux, x86_64_linux, data },
    tree: c.Tree,
    executable: ?c.File,
    loader: ?c.File,
    libraries: []const c.File,
};

pub const Bound = struct {
    directory: fs.Directory,
    contract: Tool,

    pub fn validate(self: Bound, backing_allocator: std.mem.Allocator, io: std.Io) !void {
        var arena = std.heap.ArenaAllocator.init(backing_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        if (self.contract.libraries.len > 256) return error.LimitExceeded;
        _ = try c.sha(&self.contract.origin.source_sha256);
        _ = try c.sha(&self.contract.origin.producer_sha256);
        if (self.contract.origin.revision.len == 0 or self.contract.origin.revision.len > 256) return error.UnreviewedInput;
        if (self.contract.role == .miz and !std.mem.eql(u8, self.contract.origin.revision, c.miz_revision)) return error.UnreviewedInput;
        const observed = try fs.inventory(allocator, io, self.directory, 100000, 4 * 1024 * 1024 * 1024);
        try fs.requireTree(observed.tree, self.contract.tree);
        const loader_info: ?ElfInfo = if (self.contract.loader) |loader| blk: {
            try fs.requireFile(try self.directory.record(allocator, io, loader.path, 64 * 1024 * 1024, .executable), loader);
            const info = try self.checkElf(allocator, io, loader, false);
            if (info.needed.len != 0 or info.interpreter != null or info.soname == null) return error.IncompleteRuntime;
            break :blk info;
        } else null;
        if (self.contract.executable) |executable| {
            if (self.contract.target == .data) return error.InvalidRuntime;
            try fs.requireFile(try self.directory.record(allocator, io, executable.path, 1024 * 1024 * 1024, .executable), executable);
            const info = try self.checkElf(allocator, io, executable, true);
            if (loader_info == null and (info.needed.len != 0 or info.interpreter != null)) return error.IncompleteRuntime;
            if (loader_info) |loader| {
                if (info.interpreter) |interpreter| {
                    if (!std.mem.eql(u8, std.fs.path.basename(interpreter), loader.soname.?)) return error.InvalidRuntime;
                }
            }
            for (info.needed) |name| if (!hasLibrary(self.contract, name) and
                !(loader_info != null and std.mem.eql(u8, name, loader_info.?.soname.?))) return error.IncompleteRuntime;
        } else if (self.contract.target != .data or self.contract.loader != null or self.contract.libraries.len != 0) return error.InvalidRuntime;
        if (self.contract.loader) |loader| {
            for (self.contract.libraries, 0..) |library, i| {
                try c.relative(library.path);
                if (!std.mem.startsWith(u8, library.path, "lib/") or
                    std.mem.indexOfScalar(u8, library.path[4..], '/') != null or
                    std.mem.eql(u8, library.path, loader.path) or
                    std.mem.eql(u8, std.fs.path.basename(library.path), loader_info.?.soname.?) or
                    std.mem.eql(u8, library.path, self.contract.executable.?.path)) return error.InvalidRuntime;
                for (self.contract.libraries[0..i]) |previous| if (std.mem.eql(u8, library.path, previous.path)) return error.InvalidRuntime;
                try fs.requireFile(try self.directory.record(allocator, io, library.path, 256 * 1024 * 1024, .artifact), library);
                const info = try self.checkElf(allocator, io, library, false);
                if (info.interpreter != null and !std.mem.eql(u8, std.fs.path.basename(info.interpreter.?), loader_info.?.soname.?))
                    return error.InvalidRuntime;
                if (info.soname == null or !std.mem.eql(u8, info.soname.?, std.fs.path.basename(library.path))) return error.InvalidRuntime;
                for (info.needed) |name| {
                    // The interpreter is relocated as lib/loader, not under its SONAME.
                    if (!hasLibrary(self.contract, name) and !std.mem.eql(u8, name, loader_info.?.soname.?))
                        return error.IncompleteRuntime;
                }
            }
        } else if (self.contract.libraries.len != 0) return error.InvalidRuntime;
        if (self.contract.role == .git) {
            if (self.contract.executable == null or self.contract.loader == null or self.contract.libraries.len == 0 or
                !std.mem.eql(u8, self.contract.executable.?.path, "bin/git") or
                !std.mem.eql(u8, self.contract.loader.?.path, "lib/loader") or
                observed.entries.len != self.contract.libraries.len + 2) return error.IncompleteRuntime;
        }
        const named = try fs.Directory.open(allocator, io, self.directory.path);
        defer named.close(allocator, io);
        if (!std.meta.eql(try directoryMetadata(self.directory.dir), try directoryMetadata(named.dir))) return error.SourceChanged;
    }

    fn checkElf(self: Bound, allocator: std.mem.Allocator, io: std.Io, record: c.File, executable: bool) !ElfInfo {
        const bytes = try self.directory.read(allocator, io, record.path, 1024 * 1024 * 1024, if (executable) .executable else .artifact);
        defer allocator.free(bytes);
        if (bytes.len != record.size or !std.crypto.timing_safe.eql(c.Sha, c.digest(bytes), record.sha256)) return error.HashMismatch;
        var image = try elf.Image.parse(allocator, bytes);
        defer image.deinit();
        const expected: std.elf.EM = switch (self.contract.target) {
            .aarch64_linux => .AARCH64,
            .x86_64_linux => .X86_64,
            .data => return error.InvalidRuntime,
        };
        if (image.header.machine != expected) return error.InvalidRuntime;
        if (executable and self.contract.role != .qemu and expected != (if (builtin.cpu.arch == .aarch64) std.elf.EM.AARCH64 else std.elf.EM.X86_64))
            return error.InvalidRuntime;
        var result: ElfInfo = .{ .needed = &.{} };
        var dynamic: ?std.elf.Elf64_Phdr = null;
        for (image.programs) |program| switch (program.p_type) {
            std.elf.PT_INTERP => {
                if (self.contract.loader == null) return error.IncompleteRuntime;
                if (result.interpreter != null or program.p_filesz < 2 or program.p_filesz > 4096) return error.InvalidRuntime;
                const value = try elf.range(bytes, program.p_offset, program.p_filesz);
                if (value[value.len - 1] != 0 or std.mem.indexOfScalar(u8, value[0 .. value.len - 1], 0) != null)
                    return error.InvalidRuntime;
                try absolutePath(value[0 .. value.len - 1]);
                result.interpreter = try allocator.dupe(u8, value[0 .. value.len - 1]);
            },
            std.elf.PT_DYNAMIC => {
                if (dynamic != null) return error.InvalidRuntime;
                dynamic = program;
            },
            else => {},
        };
        var needed: std.ArrayList([]const u8) = .empty;
        var dynamic_count: usize = 0;
        for (image.sections) |section| {
            if (section.header.sh_type != std.elf.SHT_DYNAMIC) continue;
            dynamic_count += 1;
            if (dynamic_count != 1 or dynamic == null or section.header.sh_offset != dynamic.?.p_offset or
                section.header.sh_addr != dynamic.?.p_vaddr or section.header.sh_size != dynamic.?.p_filesz or
                section.header.sh_size == 0 or section.header.sh_size % @sizeOf(std.elf.Elf64_Dyn) != 0 or
                section.header.sh_entsize != @sizeOf(std.elf.Elf64_Dyn) or section.header.sh_link >= image.sections.len)
                return error.InvalidRuntime;
            try image.requireLoadedSection(section);
            const string_section = image.sections[section.header.sh_link];
            if (string_section.header.sh_type != std.elf.SHT_STRTAB) return error.InvalidRuntime;
            try image.requireLoadedSection(string_section);
            const strings = try image.sectionData(string_section);
            var string_address: ?u64 = null;
            var string_size: ?u64 = null;
            var ended = false;
            var offset: u64 = 0;
            while (offset < section.header.sh_size) : (offset += @sizeOf(std.elf.Elf64_Dyn)) {
                const entry = try elf.structure(std.elf.Elf64_Dyn, bytes, section.header.sh_offset + offset, image.header.endian);
                switch (entry.d_tag) {
                    std.elf.DT_NULL => {
                        ended = true;
                        break;
                    },
                    std.elf.DT_NEEDED => {
                        const name = try elf.string(strings, entry.d_val);
                        try c.core.private_files.basename(name);
                        for (needed.items) |previous| if (std.mem.eql(u8, previous, name)) return error.InvalidRuntime;
                        if (needed.items.len >= 256) return error.LimitExceeded;
                        try needed.append(allocator, try allocator.dupe(u8, name));
                    },
                    std.elf.DT_SONAME => {
                        if (result.soname != null) return error.InvalidRuntime;
                        const name = try elf.string(strings, entry.d_val);
                        try c.core.private_files.basename(name);
                        result.soname = try allocator.dupe(u8, name);
                    },
                    std.elf.DT_STRTAB => {
                        if (string_address != null) return error.InvalidRuntime;
                        string_address = entry.d_val;
                    },
                    std.elf.DT_STRSZ => {
                        if (string_size != null) return error.InvalidRuntime;
                        string_size = entry.d_val;
                    },
                    std.elf.DT_RPATH, std.elf.DT_RUNPATH => try self.originPaths(allocator, record.path, try elf.string(strings, entry.d_val)),
                    0x6ffffefb, 0x6ffffefc, 0x7fffffff, 0x7ffffffd => return error.AmbientRuntimeForbidden,
                    else => {},
                }
            }
            if (!ended or string_address != string_section.header.sh_addr or string_size != strings.len) return error.InvalidRuntime;
        }
        if (dynamic != null and dynamic_count != 1) return error.InvalidRuntime;
        result.needed = try needed.toOwnedSlice(allocator);
        return result;
    }
    fn originPaths(self: Bound, allocator: std.mem.Allocator, object: []const u8, value: []const u8) !void {
        if (value.len == 0 or value.len > 4096) return error.AmbientRuntimeForbidden;
        var list = std.mem.splitScalar(u8, value, ':');
        while (list.next()) |item| {
            if (!std.mem.startsWith(u8, item, "$ORIGIN/")) return error.AmbientRuntimeForbidden;
            const suffix = item["$ORIGIN/".len..];
            for (suffix) |ch| if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, "/._+-", ch) == null)
                return error.AmbientRuntimeForbidden;
            const directory = try std.fs.path.resolve(allocator, &.{ self.directory.path, std.fs.path.dirname(object) orelse ".", suffix });
            defer allocator.free(directory);
            if (!paths.isDescendant(self.directory.path, directory)) return error.AmbientRuntimeForbidden;
            const relative = directory[self.directory.path.len + 1 ..];
            if (!std.mem.eql(u8, relative, "lib") and !std.mem.startsWith(u8, relative, "lib/")) return error.AmbientRuntimeForbidden;
            try c.relative(relative);
        }
    }
    pub fn prefix(self: Bound, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
        const executable = self.contract.executable orelse return error.InvalidRuntime;
        try absolutePath(self.directory.path);
        try c.relative(executable.path);
        var result: std.ArrayList([]const u8) = .empty;
        if (self.contract.loader) |loader| {
            try c.relative(loader.path);
            try result.appendSlice(allocator, &.{
                try std.fs.path.join(allocator, &.{ self.directory.path, loader.path }),
                "--inhibit-cache",
                "--library-path",
                try std.fs.path.join(allocator, &.{ self.directory.path, "lib" }),
            });
        }
        try result.append(allocator, try std.fs.path.join(allocator, &.{ self.directory.path, executable.path }));
        return result;
    }
};

fn directoryMetadata(dir: std.Io.Dir) !fs.Metadata {
    return fs.metadata(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
}

fn absolutePath(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path) or path.len < 2 or path.len > 4096 or
        path[path.len - 1] == '/' or std.mem.indexOfAny(u8, path, ":\x00\r\n\t") != null) return error.UnsafePath;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| try c.core.private_files.basename(part);
}

fn hasLibrary(tool: Tool, name: []const u8) bool {
    for (tool.libraries) |library| if (std.mem.eql(u8, std.fs.path.basename(library.path), name)) return true;
    return false;
}

pub const Environment = struct {
    scratch: []const u8,
    path: []const u8,
    bison_data: ?[]const u8 = null,
    m4: ?[]const u8 = null,

    pub fn create(self: Environment, allocator: std.mem.Allocator) !std.process.Environ.Map {
        try absolutePath(self.scratch);
        try absolutePath(self.path);
        if (self.bison_data) |path| try absolutePath(path);
        if (self.m4) |path| try absolutePath(path);
        var result = std.process.Environ.Map.init(allocator);
        try result.put("PATH", self.path);
        inline for (.{ "HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR" }, .{ "home", "tmp", "cache", "config", "zig-global", "zig-local" }) |key, suffix| {
            try result.put(key, try std.fs.path.join(allocator, &.{ self.scratch, suffix }));
        }
        try result.put("LC_ALL", "C");
        try result.put("GIT_CONFIG_NOSYSTEM", "1");
        try result.put("GIT_CONFIG_GLOBAL", "/dev/null");
        try result.put("GIT_CONFIG_SYSTEM", "/dev/null");
        try result.put("GIT_ATTR_NOSYSTEM", "1");
        try result.put("GIT_NO_REPLACE_OBJECTS", "1");
        try result.put("GIT_OPTIONAL_LOCKS", "0");
        try result.put("GIT_TERMINAL_PROMPT", "0");
        try result.put("GIT_PROTOCOL_FROM_USER", "0");
        try result.put("GIT_ALLOW_PROTOCOL", "");
        try result.put("GIT_NO_LAZY_FETCH", "1");
        try result.put("GIT_PAGER", "");
        try result.put("GIT_EXTERNAL_DIFF", "");
        try result.put("GIT_EXEC_PATH", try std.fs.path.join(allocator, &.{ self.scratch, "disabled-git-exec" }));
        try result.put("OPENSSL_CONF", "/dev/null");
        try result.put("OPENSSL_MODULES", try std.fs.path.join(allocator, &.{ self.scratch, "disabled-openssl" }));
        if (self.bison_data) |path| try result.put("BISON_PKGDATADIR", path);
        if (self.m4) |path| try result.put("M4", path);
        return result;
    }
};

pub const GitCommand = union(enum) {
    head,
    root,
    index,
    flags,
    replacements,
    common_directory,
    git_directory,
    format,
    tree: []const u8,
    commit: []const u8,
};

pub const Git = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runtime: Bound,
    environment: Environment,
    deadline: c.core.process.Deadline,
    failures: c.Failure = .{},

    pub fn validate(self: *Git) !void {
        if (self.runtime.contract.role != .git) return error.InvalidRuntime;
        try self.runtime.validate(self.allocator, self.io);
        const loader = self.runtime.contract.loader orelse return error.IncompleteRuntime;
        const executable = self.runtime.contract.executable orelse return error.IncompleteRuntime;
        const args = [_][]const u8{
            try std.fs.path.join(self.allocator, &.{ self.runtime.directory.path, loader.path }),
            "--inhibit-cache",
            "--library-path",
            try std.fs.path.join(self.allocator, &.{ self.runtime.directory.path, "lib" }),
            "--list",
            try std.fs.path.join(self.allocator, &.{ self.runtime.directory.path, executable.path }),
        };
        const output = try self.execute(&args, self.runtime.directory.dir, 64 * 1024);
        try self.resolution(output);
    }

    pub fn command(self: *Git, repository: fs.Directory, operation: GitCommand) ![]u8 {
        var args = try self.runtime.prefix(self.allocator);
        try args.appendSlice(self.allocator, &.{
            "--no-replace-objects", "--no-pager",                    "-c", "core.fsmonitor=false",      "-c", "core.hooksPath=/dev/null",
            "-c",                   "core.attributesFile=/dev/null", "-c", "core.untrackedCache=false", "-c", "core.sparseCheckout=false",
            "-c",                   "core.useReplaceRefs=false",     "-c", "maintenance.auto=false",    "-c", "protocol.allow=never",
            "-c",                   "fetch.writeCommitGraph=false",  "-C", repository.path,
        });
        switch (operation) {
            .head => try args.appendSlice(self.allocator, &.{ "rev-parse", "--verify", "HEAD^{commit}" }),
            .root => try args.appendSlice(self.allocator, &.{ "rev-parse", "--show-toplevel" }),
            .format => try args.appendSlice(self.allocator, &.{ "rev-parse", "--show-object-format" }),
            .common_directory => try args.appendSlice(self.allocator, &.{ "rev-parse", "--path-format=absolute", "--git-common-dir" }),
            .git_directory => try args.appendSlice(self.allocator, &.{ "rev-parse", "--absolute-git-dir" }),
            .index => try args.appendSlice(self.allocator, &.{ "ls-files", "--stage", "-z" }),
            .flags => try args.appendSlice(self.allocator, &.{ "ls-files", "-v", "-z" }),
            .replacements => try args.appendSlice(self.allocator, &.{ "for-each-ref", "--format=%(refname)", "refs/replace/" }),
            .tree => |oid| {
                try c.objectId(oid);
                try args.appendSlice(self.allocator, &.{ "ls-tree", "-r", "--full-tree", "-z", oid });
            },
            .commit => |oid| {
                try c.objectId(oid);
                try args.appendSlice(self.allocator, &.{ "cat-file", "commit", oid });
            },
        }
        return self.execute(args.items, repository.dir, 4 * 1024 * 1024);
    }

    fn execute(self: *Git, args: []const []const u8, cwd: std.Io.Dir, limit: usize) ![]u8 {
        var environment = try self.environment.create(self.allocator);
        defer environment.deinit();
        var result = try c.core.process.run(self.allocator, self.io, .{
            .argv = args,
            .environment = &environment,
            .cwd = cwd,
            .deadline = self.deadline,
            .stdout_limit = limit,
            .stderr_limit = 64 * 1024,
        });
        defer result.deinit(self.allocator);
        if (result.failures.primary != null or result.failures.cleanup != null or !result.cleanup_complete) {
            if (result.failures.primary) |failure| try self.failures.record(.primary, failure);
            if (result.failures.cleanup) |failure| try self.failures.record(.cleanup, failure);
            return error.CommandFailed;
        }
        return self.allocator.dupe(u8, result.stdout);
    }

    fn resolution(self: *Git, output: []const u8) !void {
        var found: std.StringHashMap(void) = .init(self.allocator);
        defer found.deinit();
        if (output.len == 0 or output.len > 64 * 1024) return error.InvalidRuntimeResolution;
        const loader_info = try self.runtime.checkElf(self.allocator, self.io, self.runtime.contract.loader.?, false);
        const executable_info = try self.runtime.checkElf(self.allocator, self.io, self.runtime.contract.executable.?, true);
        var vdso = false;
        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            const address = std.mem.lastIndexOf(u8, line, " (0x") orelse return error.InvalidRuntimeResolution;
            if (!std.mem.endsWith(u8, line, ")")) return error.InvalidRuntimeResolution;
            const digits = line[address + 4 .. line.len - 1];
            if (digits.len == 0 or digits.len > 16) return error.InvalidRuntimeResolution;
            for (digits) |ch| if (!std.ascii.isHex(ch)) return error.InvalidRuntimeResolution;
            const mapping = line[0..address];
            if (std.mem.eql(u8, mapping, "linux-vdso.so.1")) {
                if (vdso) return error.InvalidRuntimeResolution;
                vdso = true;
                continue;
            }
            const separator = std.mem.indexOf(u8, mapping, " => ");
            const path = if (separator) |index| mapping[index + 4 ..] else mapping;
            if (!std.fs.path.isAbsolute(path)) return error.AmbientRuntimeForbidden;
            const canonical = try std.fs.path.resolve(self.allocator, &.{path});
            if (!paths.isDescendant(self.runtime.directory.path, canonical)) return error.AmbientRuntimeForbidden;
            const relative = canonical[self.runtime.directory.path.len + 1 ..];
            try c.relative(relative);
            const is_loader = std.mem.eql(u8, relative, self.runtime.contract.loader.?.path);
            var known = is_loader;
            for (self.runtime.contract.libraries) |library| known = known or std.mem.eql(u8, library.path, relative);
            if (!known or found.contains(relative)) return error.IncompleteRuntime;
            if (!is_loader and (separator == null or !std.mem.eql(u8, mapping[0..separator.?], std.fs.path.basename(relative))))
                return error.InvalidRuntimeResolution;
            if (is_loader and separator != null and !std.mem.eql(u8, mapping[0..separator.?], loader_info.soname.?) and
                !(executable_info.interpreter != null and std.mem.eql(u8, mapping[0..separator.?], executable_info.interpreter.?)))
                return error.InvalidRuntimeResolution;
            // Re-open the resolved spelling without following any runtime symlinks.
            const resolved = try self.runtime.directory.openFile(self.io, relative, .artifact);
            resolved.close(self.io);
            try found.put(relative, {});
        }
        if (found.count() != self.runtime.contract.libraries.len + 1) return error.IncompleteRuntime;
    }
};

/// Public installed ELF inputs are copied into an independent, disposable test
/// runtime. No production/runtime discovery or inherited environment is used.
pub const TestFixture = struct {
    temporary: std.testing.TmpDir,
    root: fs.Directory,
    repository: fs.Directory,
    git: Git,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !TestFixture {
        if (!builtin.is_test) @compileError("Synthetic fixture is test-only");
        if (builtin.cpu.arch != .aarch64 or builtin.os.tag != .linux) return error.SkipZigTest;
        try c.core.process.initialize();
        var temporary = std.testing.tmpDir(.{ .iterate = true });
        errdefer temporary.cleanup();
        try temporary.dir.setPermissions(io, .fromMode(0o700));
        const root_path = try temporary.dir.realPathFileAlloc(io, ".", allocator);
        const root = try fs.Directory.open(allocator, io, root_path);
        errdefer root.close(allocator, io);
        for ([_][]const u8{
            "runtime",    "runtime/bin", "runtime/lib",       "repository",       "home",           "tmp", "cache", "config",
            "zig-global", "zig-local",   "disabled-git-exec", "disabled-openssl", "empty-template",
        }) |name| try root.dir.createDir(io, name, .fromMode(0o700));
        const runtime_path = try std.fs.path.join(allocator, &.{ root.path, "runtime" });
        const directory = try fs.Directory.open(allocator, io, runtime_path);
        errdefer directory.close(allocator, io);
        const inputs = [_]struct { source: []const u8, destination: []const u8, mode: u16 }{
            .{ .source = "/home/g/.pixi/envs/git/bin/git", .destination = "bin/git", .mode = 0o755 },
            .{ .source = "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", .destination = "lib/loader", .mode = 0o755 },
            .{ .source = "/home/g/.pixi/envs/git/lib/libpcre2-8.so.0", .destination = "lib/libpcre2-8.so.0", .mode = 0o644 },
            .{ .source = "/home/g/.pixi/envs/git/lib/libz.so.1", .destination = "lib/libz.so.1", .mode = 0o644 },
            .{ .source = "/home/g/.pixi/envs/git/lib/libiconv.so.2", .destination = "lib/libiconv.so.2", .mode = 0o644 },
            .{ .source = "/home/g/.pixi/envs/git/lib/libcrypto.so.3", .destination = "lib/libcrypto.so.3", .mode = 0o644 },
            .{ .source = "/usr/lib/aarch64-linux-gnu/libpthread.so.0", .destination = "lib/libpthread.so.0", .mode = 0o644 },
            .{ .source = "/usr/lib/aarch64-linux-gnu/libc.so.6", .destination = "lib/libc.so.6", .mode = 0o644 },
            .{ .source = "/usr/lib/aarch64-linux-gnu/libdl.so.2", .destination = "lib/libdl.so.2", .mode = 0o644 },
        };
        for (inputs) |input| {
            const canonical = try std.Io.Dir.cwd().realPathFileAlloc(io, input.source, allocator);
            if (!std.mem.startsWith(u8, canonical, "/home/g/.pixi/envs/git/") and
                !std.mem.startsWith(u8, canonical, "/usr/lib/aarch64-linux-gnu/")) return error.UnsafePath;
            const public = try fs.Directory.open(allocator, io, std.fs.path.dirname(canonical).?);
            defer public.close(allocator, io);
            const bytes = try public.read(allocator, io, std.fs.path.basename(canonical), 64 * 1024 * 1024, .artifact);
            defer allocator.free(bytes);
            const file = try directory.dir.createFile(io, input.destination, .{ .exclusive = true, .permissions = .fromMode(input.mode) });
            defer file.close(io);
            try file.writePositionalAll(io, bytes, 0);
            try file.setPermissions(io, .fromMode(input.mode));
        }
        const inventory = try fs.inventory(allocator, io, directory, 32, 128 * 1024 * 1024);
        var libraries: std.ArrayList(c.File) = .empty;
        for (inventory.entries) |record| if (!std.mem.eql(u8, record.path, "bin/git") and !std.mem.eql(u8, record.path, "lib/loader")) {
            try libraries.append(allocator, record);
        };
        const repository = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ root.path, "repository" }));
        errdefer repository.close(allocator, io);
        var result: TestFixture = .{
            .temporary = temporary,
            .root = root,
            .repository = repository,
            .git = .{
                .allocator = allocator,
                .io = io,
                .runtime = .{
                    .directory = directory,
                    .contract = .{
                        .role = .git,
                        .origin = .{
                            .scheme = .authenticated_distribution,
                            .revision = "public-installed-synthetic-runtime",
                            .source_sha256 = c.digest("synthetic runtime fixture input"),
                            .producer_sha256 = c.digest("synthetic runtime fixture producer"),
                        },
                        .target = .aarch64_linux,
                        .tree = inventory.tree,
                        .executable = try directory.record(allocator, io, "bin/git", 64 * 1024 * 1024, .executable),
                        .loader = try directory.record(allocator, io, "lib/loader", 64 * 1024 * 1024, .executable),
                        .libraries = try libraries.toOwnedSlice(allocator),
                    },
                },
                .environment = .{ .scratch = root.path, .path = try std.fs.path.join(allocator, &.{ directory.path, "bin" }) },
                .deadline = try c.core.process.Deadline.afterMilliseconds(120000),
            },
        };
        try result.git.validate();
        return result;
    }

    pub fn deinit(self: *TestFixture) void {
        self.git.runtime.directory.close(self.git.allocator, self.git.io);
        self.repository.close(self.git.allocator, self.git.io);
        self.root.close(self.git.allocator, self.git.io);
        self.temporary.cleanup();
    }

    pub fn setup(self: *TestFixture, arguments: []const []const u8) ![]u8 {
        var argv = try self.git.runtime.prefix(self.git.allocator);
        try argv.appendSlice(self.git.allocator, &.{
            "--no-replace-objects", "--no-pager",           "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
            "-c",                   "core.fsmonitor=false", "-c", "protocol.allow=never",     "-C", self.repository.path,
        });
        try argv.appendSlice(self.git.allocator, arguments);
        var environment = try self.git.environment.create(self.git.allocator);
        defer environment.deinit();
        try environment.put("GIT_AUTHOR_NAME", "Synthetic Fixture");
        try environment.put("GIT_AUTHOR_EMAIL", "synthetic@example.invalid");
        try environment.put("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z");
        try environment.put("GIT_COMMITTER_NAME", "Synthetic Fixture");
        try environment.put("GIT_COMMITTER_EMAIL", "synthetic@example.invalid");
        try environment.put("GIT_COMMITTER_DATE", "2001-01-01T00:00:00Z");
        try environment.put("GIT_CONFIG_SYSTEM", "/dev/null");
        var result = try c.core.process.run(self.git.allocator, self.git.io, .{
            .argv = argv.items,
            .environment = &environment,
            .cwd = self.repository.dir,
            .deadline = self.git.deadline,
        });
        defer result.deinit(self.git.allocator);
        if (result.failures.primary != null or result.failures.cleanup != null or !result.cleanup_complete)
            return error.SyntheticGitSetupFailed;
        return self.git.allocator.dupe(u8, result.stdout);
    }

    pub fn write(self: *TestFixture, path: []const u8, bytes: []const u8, mode: u16) !void {
        const file = try self.repository.dir.createFile(self.git.io, path, .{ .permissions = .fromMode(mode) });
        defer file.close(self.git.io);
        try file.setPermissions(self.git.io, .fromMode(mode));
        try file.writePositionalAll(self.git.io, bytes, 0);
    }
};

test "runtime environment is explicit and rejects search path injection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var environment = try (Environment{ .scratch = "/synthetic/scratch", .path = "/synthetic/runtime/bin" }).create(allocator);
    defer environment.deinit();
    try std.testing.expectEqualStrings("/synthetic/scratch/home", environment.get("HOME").?);
    try std.testing.expectEqualStrings("/dev/null", environment.get("GIT_CONFIG_GLOBAL").?);
    try std.testing.expectEqualStrings("1", environment.get("GIT_NO_REPLACE_OBJECTS").?);
    for ([_][]const u8{ "LD_PRELOAD", "LD_LIBRARY_PATH", "GIT_CONFIG_COUNT", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "SSH_AUTH_SOCK" }) |name|
        try std.testing.expect(environment.get(name) == null);
    for ([_][]const u8{ "/safe:/ambient/bin", "/safe/../ambient", "/safe//bin", "/safe\nbin" }) |path|
        try std.testing.expectError(error.UnsafePath, (Environment{ .scratch = "/synthetic", .path = path }).create(allocator));
}

test "runtime native process execution preserves redacted failure ownership" {
    const io = std.testing.io;
    try c.core.process.initialize();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const scratch = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    var git: Git = .{
        .allocator = allocator,
        .io = io,
        .runtime = undefined,
        .environment = .{ .scratch = scratch, .path = scratch },
        .deadline = try c.core.process.Deadline.afterMilliseconds(10000),
    };
    const executable = @import("test_options").process_fixture;
    const output = try git.execute(&.{ executable, "progress" }, temporary.dir, 4096);
    try std.testing.expectEqualStrings("{\"fixture\":\"native-progress\"}", output);
    try std.testing.expectError(error.CommandFailed, git.execute(&.{ executable, "failure" }, temporary.dir, 4096));
    try std.testing.expect(git.failures.primary != null and git.failures.cleanup == null);
}

test "runtime real relocated Git binds all ELF bytes modes and transitive dependencies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try TestFixture.init(allocator, std.testing.io);
    defer fixture.deinit();
    try std.testing.expectEqual(@as(usize, 7), fixture.git.runtime.contract.libraries.len);
    try std.testing.expect(std.mem.startsWith(u8, try fixture.setup(&.{"--version"}), "git version "));
    const original = fixture.git.runtime.contract;
    fixture.git.runtime.contract.libraries = original.libraries[1..];
    try std.testing.expectError(error.IncompleteRuntime, fixture.git.validate());
    fixture.git.runtime.contract = original;
    const duplicate = try allocator.alloc(c.File, original.libraries.len + 1);
    @memcpy(duplicate[0..original.libraries.len], original.libraries);
    duplicate[original.libraries.len] = duplicate[0];
    fixture.git.runtime.contract.libraries = duplicate;
    try std.testing.expectError(error.InvalidRuntime, fixture.git.validate());
    fixture.git.runtime.contract = original;
    var no_transitive: std.ArrayList(c.File) = .empty;
    for (original.libraries) |library| if (!std.mem.eql(u8, library.path, "lib/libdl.so.2")) {
        try no_transitive.append(allocator, library);
    };
    fixture.git.runtime.contract.libraries = no_transitive.items;
    try std.testing.expectError(error.IncompleteRuntime, fixture.git.validate());
    fixture.git.runtime.contract = original;
    fixture.git.runtime.contract.target = .x86_64_linux;
    try std.testing.expectError(error.InvalidRuntime, fixture.git.validate());
    fixture.git.runtime.contract = original;
    try std.testing.expectError(error.AmbientRuntimeForbidden, fixture.git.runtime.originPaths(allocator, "bin/git", "/usr/lib"));
    try std.testing.expectError(error.AmbientRuntimeForbidden, fixture.git.runtime.originPaths(allocator, "bin/git", "$ORIGIN/../../outside"));
    try std.testing.expectError(error.AmbientRuntimeForbidden, fixture.git.runtime.originPaths(allocator, "bin/git", "$ORIGIN/../lib:"));
    try std.testing.expectError(error.AmbientRuntimeForbidden, fixture.git.resolution("libc.so.6 => /usr/lib/libc.so.6 (0x1234)\n"));
    const incomplete = try std.fmt.allocPrint(allocator, "{s}/lib/loader (0x1234)\n", .{fixture.git.runtime.directory.path});
    try std.testing.expectError(error.IncompleteRuntime, fixture.git.resolution(incomplete));
    try std.testing.expectError(error.IncompleteRuntime, fixture.git.resolution(try std.mem.concat(allocator, u8, &.{ incomplete, incomplete })));
    try std.testing.expectError(error.InvalidRuntimeResolution, fixture.git.resolution("linux-vdso.so.1 (0xNOTHEX)\n"));
    const executable = try fixture.git.runtime.directory.dir.openFile(std.testing.io, "bin/git", .{ .mode = .read_write });
    defer executable.close(std.testing.io);
    try executable.setPermissions(std.testing.io, .fromMode(0o700));
    try std.testing.expectError(error.HashMismatch, fixture.git.validate());
    try executable.setPermissions(std.testing.io, .fromMode(0o755));
    try executable.writePositionalAll(std.testing.io, "X", 0);
    try std.testing.expectError(error.HashMismatch, fixture.git.validate());
}

test "runtime rehashed ambient ELF search metadata and undeclared runtime extras still fail closed" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fixture = try TestFixture.init(allocator, io);
    defer fixture.deinit();
    const original = fixture.git.runtime.contract;
    const directory = fixture.git.runtime.directory;
    const bytes = try directory.read(allocator, io, "bin/git", 64 * 1024 * 1024, .executable);
    var image = try elf.Image.parse(allocator, bytes);
    defer image.deinit();
    var search_offset: ?u64 = null;
    for (image.sections) |section| {
        if (section.header.sh_type != std.elf.SHT_DYNAMIC) continue;
        var offset: u64 = 0;
        while (offset < section.header.sh_size) : (offset += @sizeOf(std.elf.Elf64_Dyn)) {
            const dynamic = try elf.structure(std.elf.Elf64_Dyn, bytes, section.header.sh_offset + offset, image.header.endian);
            if (dynamic.d_tag == std.elf.DT_RPATH or dynamic.d_tag == std.elf.DT_RUNPATH)
                search_offset = image.sections[section.header.sh_link].header.sh_offset + dynamic.d_val;
        }
    }
    try std.testing.expect(search_offset != null);
    const file = try directory.dir.openFile(io, "bin/git", .{ .mode = .read_write, .follow_symlinks = false });
    defer file.close(io);
    try file.writePositionalAll(io, "/", search_offset.?);
    fixture.git.runtime.contract.executable = try directory.record(allocator, io, "bin/git", 64 * 1024 * 1024, .executable);
    fixture.git.runtime.contract.tree = (try fs.inventory(allocator, io, directory, 32, 128 * 1024 * 1024)).tree;
    try std.testing.expectError(error.AmbientRuntimeForbidden, fixture.git.validate());
    try file.writePositionalAll(io, bytes[@intCast(search_offset.?)..][0..1], search_offset.?);
    fixture.git.runtime.contract = original;
    try fixture.git.validate();
    const extra = try directory.dir.createFile(io, "unreviewed", .{ .exclusive = true, .permissions = .fromMode(0o644) });
    defer extra.close(io);
    try extra.writePositionalAll(io, "unreviewed extra runtime file", 0);
    try std.testing.expectError(error.HashMismatch, fixture.git.validate());
    fixture.git.runtime.contract.tree = (try fs.inventory(allocator, io, directory, 32, 128 * 1024 * 1024)).tree;
    try std.testing.expectError(error.IncompleteRuntime, fixture.git.validate());
}
