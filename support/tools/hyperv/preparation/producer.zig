// SPDX-License-Identifier: BSD-3-Clause
//! Fixed local producer commands, not receipts or an arbitrary command runner.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const runtime = @import("runtime.zig");
const source = @import("source.zig");
const process = c.core.process;
const paths = @import("facade_paths");
const ns = @import("namespace.zig");
const env = @import("environment.zig");
const git_entry = @import("git_entry.zig");

pub const Step = enum { configure, inspect, build };
pub const profile = "hyperv-x86_64-efi-netvsc";
pub const inspection_limit = 1024 * 1024;

pub const LlvmPaths = struct {
    nm: []const u8,
    objcopy: []const u8,
    objdump: []const u8,
    readelf: []const u8,
    strip: []const u8,
};

pub const CommandPaths = struct {
    repository: []const u8,
    config: []const u8,
    output: []const u8,
    scratch: []const u8,
    packages: []const u8,
    zig: []const u8,
    make: []const u8,
    llvm: LlvmPaths,
    native_make_environment: ?[]const u8 = null,
};

pub const Plan = struct {
    step: Step,
    cwd: []const u8,
    argv: []const []const u8,
};

/// Allocations belong to the caller's arena. There are no extra-argument,
/// alternate-application, environment-inheritance, or Make-lock override hooks.
pub fn plan(allocator: std.mem.Allocator, step: Step, command: CommandPaths) !Plan {
    inline for (.{ "repository", "config", "output", "scratch", "packages", "zig", "make" }) |field|
        try commandPath(@field(command, field));
    inline for (std.meta.fields(LlvmPaths)) |field| try commandPath(@field(command.llvm, field.name));
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(allocator, &.{
        command.zig,
        "build",
        switch (step) {
            .configure => "olddefconfig",
            .inspect => "config-inspect",
            .build => "native-images",
        },
        "-j2",
        "--system",
        command.packages,
        "--cache-dir",
        try std.fs.path.join(allocator, &.{ command.scratch, "zig-local" }),
        "--global-cache-dir",
        try std.fs.path.join(allocator, &.{ command.scratch, "zig-global" }),
        "--prefix",
        command.output,
        try std.fmt.allocPrint(allocator, "-Dapp={s}/support/apps/hyperv-acceptance", .{command.repository}),
        try std.fmt.allocPrint(allocator, "-Dconfig={s}", .{command.config}),
        try std.fmt.allocPrint(allocator, "-Doutput={s}", .{command.output}),
        "-Dnative-profile=" ++ profile,
        try std.fmt.allocPrint(allocator, "-Dmake-command={s}", .{command.make}),
        try std.fmt.allocPrint(allocator, "-Dcompiler={s} cc -target " ++ c.guest_target, .{command.zig}),
        "-Dcompiler-targeted=true",
        try std.fmt.allocPrint(allocator, "-Dhost-cc={s} cc", .{command.zig}),
        try std.fmt.allocPrint(allocator, "-Dhost-cxx={s} c++", .{command.zig}),
        "-Dhost-cflags=-fno-sanitize=null",
        try std.fmt.allocPrint(allocator, "-Dmake-arg=AR={s} ar", .{command.zig}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=NM={s}", .{command.llvm.nm}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=OBJCOPY={s}", .{command.llvm.objcopy}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=OBJDUMP={s}", .{command.llvm.objdump}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=READELF={s}", .{command.llvm.readelf}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=STRIP={s}", .{command.llvm.strip}),
        "-Dmake-arg=UK_CFLAGS=-std=gnu17",
        "-Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt",
    });
    if (command.native_make_environment) |path| {
        try commandPath(path);
        try args.append(allocator, try std.fmt.allocPrint(allocator, "-Dnative-make-environment={s}", .{path}));
    }
    return .{ .step = step, .cwd = command.repository, .argv = try args.toOwnedSlice(allocator) };
}

fn commandPath(value: []const u8) !void {
    if (!std.fs.path.isAbsolute(value) or value.len < 2 or value.len > 4096) return error.UnsafePath;
    // These paths also occur inside Make/compiler command strings.
    try c.relative(value[1..]);
}

/// Namespace /bin aliases point at validated native ELF closures. Dynamic
/// loaders and libraries are declared by runtime.Bound, never host-discovered.
pub const Alias = enum {
    zig,
    make,
    git,
    bison,
    yacc,
    flex,
    lex,
    m4,
    @"llvm-nm",
    @"llvm-objcopy",
    @"llvm-objdump",
    @"llvm-readelf",
    @"llvm-strip",
    sh,
    bash,
    cp,
    mv,
    rm,
    mkdir,
    rmdir,
    touch,
    ln,
    cat,
    sed,
    awk,
    gawk,
    grep,
    find,
    sort,
    head,
    tail,
    cut,
    tr,
    wc,
    xargs,
    basename,
    dirname,
    readlink,
    realpath,
    printf,
    echo,
    @"test",
    date,
    uname,
    hostname,
    whoami,
    which,
    expr,
    diff,
    cmp,
    env,
    true,
    false,
    ls,
    tee,
    seq,
    stat,
    nproc,
    sleep,
    od,
    gzip,
    tar,
    chmod,
    install,
    id,
    timeout,
    dd,
    getconf,
    sha256sum,
    @"llvm-readobj",
};

pub const Native = struct { name: Alias, bound: runtime.Bound };

pub const Workspace = struct {
    directory: fs.Directory,
    output: fs.Directory,
    scratch: fs.Directory,
    /// Relative to directory; solving may change this file, never its identity
    /// fields in the parent-owned guarded configuration contract.
    config: c.File,
};

/// External review must establish that all selected children (including Make's
/// shell, its absolute-path helpers, and native TLS) use this closed runtime.
/// A PATH inventory alone does not establish an executed-tool closure.
pub const Tools = struct {
    /// Retained in the review binding, not an executable alias inventory.
    /// The namespace creates its own /bin; no host PATH is inherited.
    path: ?fs.Directory = null,
    native: []const Native,
    git: runtime.Bound,
    packages: runtime.Bound,
    bison_data: runtime.Bound,
    trust: runtime.Bound,
    trust_bundle: c.File,
};

pub const ProofKind = enum { smp, irq, drivers };

/// No current approval is built in. The independent expected binding must
/// include this attestation and the exact reviewed root-build/source hashes.
pub const NativeProof = struct {
    schema: enum { hyperv_native_elf_proofs_v2 },
    source_sha256: c.Sha,
    root_build: c.File,
    builder: c.File,
    tool: c.File,
    modes: [3]ProofKind,
};

pub const NativeExecution = struct {
    schema: enum { closed_native_facade_runtime_v1 },
    source_sha256: c.Sha,
    root_build: c.File,
    facade: c.File,
    makefile: c.File,
    /// /bin/sh is supplied by the namespace before Make's first $(shell).
    make_default_shell: []const u8,
    /// Required by v3: source of the helper's native /bin/git personality.
    git_entry_source: ?c.File = null,
    compiler_version: []const u8,
};

pub const Inputs = struct {
    repository: fs.Directory,
    /// Parent obtains this with source.inspect using the complete bound Git,
    /// and repeats that full physical-source inspection after execute.
    observed_source: c.Source,
    workspace: Workspace,
    tools: Tools,
    native_execution: ?NativeExecution,
    native_proof: ?NativeProof,
    isolation: ?ns.Inputs = null,
};

pub const Expected = struct {
    source: c.Source,
    /// Independently reviewed, immutable digest; never approve a fresh
    /// describe() result merely because it was measured on this machine.
    binding_sha256: c.Sha,
};

const DirectoryIdentity = ns.Identity;
const ToolBinding = ns.Tool;
const NativeBinding = struct { name: Alias, tool: ToolBinding };

pub const Binding = struct {
    schema: enum { hyperv_local_native_producer_binding_v3 },
    source: c.Source,
    repository: DirectoryIdentity,
    workspace: DirectoryIdentity,
    output: DirectoryIdentity,
    scratch: DirectoryIdentity,
    config: c.File,
    path: ?DirectoryIdentity,
    native: []const NativeBinding,
    git: ToolBinding,
    packages: ToolBinding,
    bison_data: ToolBinding,
    trust: ToolBinding,
    trust_bundle: c.File,
    native_execution: ?NativeExecution,
    native_proof: ?NativeProof,
    isolation: ?ns.Binding,
};

/// A measurement for separate review, not admission. Does not spawn children,
/// manufacture a proof approval, or restore packages.
pub fn describe(allocator: std.mem.Allocator, inputs: Inputs) !Binding {
    if (inputs.tools.native.len > std.meta.fields(Alias).len) return error.LimitExceeded;
    const native = try allocator.alloc(NativeBinding, inputs.tools.native.len);
    for (inputs.tools.native, native) |item, *binding| binding.* = .{ .name = item.name, .tool = toolBinding(item.bound) };
    return .{
        .schema = .hyperv_local_native_producer_binding_v3,
        .source = inputs.observed_source,
        .repository = try directoryIdentity(inputs.repository),
        .workspace = try directoryIdentity(inputs.workspace.directory),
        .output = try directoryIdentity(inputs.workspace.output),
        .scratch = try directoryIdentity(inputs.workspace.scratch),
        .config = inputs.workspace.config,
        .path = if (inputs.tools.path) |path| try directoryIdentity(path) else null,
        .native = native,
        .git = toolBinding(inputs.tools.git),
        .packages = toolBinding(inputs.tools.packages),
        .bison_data = toolBinding(inputs.tools.bison_data),
        .trust = toolBinding(inputs.tools.trust),
        .trust_bundle = inputs.tools.trust_bundle,
        .native_execution = inputs.native_execution,
        .native_proof = inputs.native_proof,
        .isolation = if (inputs.isolation) |isolation| try ns.describe(allocator, isolation) else null,
    };
}

pub fn bindingDigest(allocator: std.mem.Allocator, binding: Binding) !c.Sha {
    const bytes = try c.canonical(allocator, binding);
    defer allocator.free(bytes);
    return c.digest(bytes);
}

fn toolBinding(bound: runtime.Bound) ToolBinding {
    return .{ .path = bound.directory.path, .contract = bound.contract };
}

fn directoryIdentity(directory: fs.Directory) !DirectoryIdentity {
    try commandPath(directory.path);
    const metadata = try fs.metadata(.{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } });
    if (metadata.mode & std.os.linux.S.IFMT != std.os.linux.S.IFDIR) return error.UnsafeFile;
    return .{ .path = directory.path, .device = metadata.device, .inode = metadata.inode, .mode = metadata.mode, .uid = metadata.uid };
}

fn requireDirectory(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, private: bool) !void {
    const held = try directoryIdentity(directory);
    if (private and (held.mode & 0o7777 != 0o700 or held.uid != std.os.linux.geteuid())) return error.UnsafeFile;
    const named = try fs.Directory.open(allocator, io, directory.path);
    defer named.close(allocator, io);
    const actual = try directoryIdentity(named);
    if (held.device != actual.device or held.inode != actual.inode or held.mode != actual.mode or held.uid != actual.uid)
        return error.SourceChanged;
}

fn nativeTool(tools: Tools, name: Alias) !runtime.Bound {
    for (tools.native) |item| if (item.name == name) return item.bound;
    return error.DependencyUnavailable;
}

fn executablePath(allocator: std.mem.Allocator, bound: runtime.Bound) ![]const u8 {
    const executable = bound.contract.executable orelse return error.DependencyUnavailable;
    const path = try std.fs.path.join(allocator, &.{ bound.directory.path, executable.path });
    try commandPath(path);
    return path;
}

pub fn commandPaths(allocator: std.mem.Allocator, inputs: Inputs) !CommandPaths {
    return .{
        .repository = inputs.repository.path,
        .config = try std.fs.path.join(allocator, &.{ inputs.workspace.directory.path, inputs.workspace.config.path }),
        .output = inputs.workspace.output.path,
        .scratch = inputs.workspace.scratch.path,
        .packages = inputs.tools.packages.directory.path,
        .zig = try executablePath(allocator, try nativeTool(inputs.tools, .zig)),
        .make = try executablePath(allocator, try nativeTool(inputs.tools, .make)),
        .llvm = .{
            .nm = try executablePath(allocator, try nativeTool(inputs.tools, .@"llvm-nm")),
            .objcopy = try executablePath(allocator, try nativeTool(inputs.tools, .@"llvm-objcopy")),
            .objdump = try executablePath(allocator, try nativeTool(inputs.tools, .@"llvm-objdump")),
            .readelf = try executablePath(allocator, try nativeTool(inputs.tools, .@"llvm-readelf")),
            .strip = try executablePath(allocator, try nativeTool(inputs.tools, .@"llvm-strip")),
        },
        .native_make_environment = if (inputs.isolation) |isolation|
            try std.fs.path.join(allocator, &.{ inputs.workspace.directory.path, (isolation.make_environment orelse return error.MissingMakeEnvironment).path })
        else
            null,
    };
}

fn overlaps(a: []const u8, b: []const u8) bool {
    return paths.isSameOrAncestor(a, b) or paths.isSameOrAncestor(b, a);
}

fn validateWorkspace(allocator: std.mem.Allocator, io: std.Io, inputs: Inputs, after: bool, step: Step) !void {
    const workspace = inputs.workspace;
    try requireDirectory(allocator, io, inputs.repository, false);
    for ([_]fs.Directory{ workspace.directory, workspace.output, workspace.scratch }) |directory|
        try requireDirectory(allocator, io, directory, true);
    if (!paths.isDescendant(workspace.directory.path, workspace.output.path) or
        !paths.isDescendant(workspace.directory.path, workspace.scratch.path) or
        overlaps(workspace.output.path, workspace.scratch.path) or
        paths.isSameOrAncestor(workspace.directory.path, inputs.repository.path))
        return error.UnsafePath;
    try c.relative(workspace.config.path);
    const config_path = try std.fs.path.join(allocator, &.{ workspace.directory.path, workspace.config.path });
    if (overlaps(config_path, workspace.output.path) or overlaps(config_path, workspace.scratch.path)) return error.UnsafePath;
    const config = try workspace.directory.record(allocator, io, workspace.config.path, 1024 * 1024, .private);
    if (!after or step != .configure) try fs.requireFile(config, workspace.config);
    const scratch_names = [_][]const u8{
        "tmp", "cache", "config", "zig-global", "zig-local", "disabled-git-exec", "disabled-openssl",
    };
    for (scratch_names) |name| {
        const directory = try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ workspace.scratch.path, name }));
        defer directory.close(allocator, io);
        try requireDirectory(allocator, io, directory, true);
        if (std.mem.startsWith(u8, name, "disabled-")) {
            var iterator = directory.dir.iterate();
            if (try iterator.next(io) != null) return error.UnsafeFile;
        }
    }
}

fn requireData(bound: runtime.Bound, role: runtime.Role) !void {
    if (bound.contract.role != role or bound.contract.target != .data or bound.contract.executable != null or
        bound.contract.loader != null or bound.contract.libraries.len != 0) return error.InvalidRuntime;
}

pub const required_aliases = [_]Alias{ .zig, .make, .bison, .flex, .m4, .@"llvm-nm", .@"llvm-objcopy", .@"llvm-objdump", .@"llvm-readelf", .@"llvm-strip", .sh, .bash };

fn aliasRole(name: Alias) runtime.Role {
    return switch (name) {
        .zig => .zig,
        .make => .make,
        .bison, .yacc => .bison,
        .flex, .lex => .flex,
        .m4 => .m4,
        .@"llvm-nm", .@"llvm-objcopy", .@"llvm-objdump", .@"llvm-readelf", .@"llvm-strip", .@"llvm-readobj" => .llvm,
        .git => .git,
        else => .preparation,
    };
}

pub fn validateBindingStructure(allocator: std.mem.Allocator, binding: Binding) !void {
    try validateNativeStructure(allocator, binding.native, binding.git);
    inline for (.{ "packages", "bison_data", "trust" }, .{ runtime.Role.dependencies, .bison_data, .trust }) |name, role| {
        const tool = @field(binding, name).contract;
        if (tool.role != role or tool.target != .data or tool.executable != null or tool.loader != null or
            tool.libraries.len != 0 or tool.tree.files == 0) return error.InvalidRuntime;
    }
    const execution = binding.native_execution orelse return error.DependencyUnavailable;
    const isolation = binding.isolation orelse return error.DependencyUnavailable;
    if (isolation.make_environment == null or isolation.git_policy == null) return error.DependencyUnavailable;
    if (isolation.helper.contract.role != .preparation or isolation.helper.contract.executable == null or
        isolation.helper.contract.loader != null or isolation.helper.contract.libraries.len != 0 or
        !std.meta.eql(isolation.helper.contract.origin.source_sha256, binding.source.physical.sha256))
        return error.UnreviewedInput;
    for (binding.native) |native| if (native.name == .zig) {
        if (!std.meta.eql(isolation.helper.contract.origin.producer_sha256, native.tool.contract.executable.?.sha256))
            return error.UnreviewedInput;
    };
    const entry = execution.git_entry_source orelse return error.DependencyUnavailable;
    if (!std.mem.eql(u8, entry.path, "support/tools/hyperv/preparation/git_entry.zig")) return error.UnreviewedInput;
    if (!std.mem.eql(u8, execution.make_default_shell, "/bin/sh") or
        !std.mem.eql(u8, execution.compiler_version, c.compiler_version)) return error.UnreviewedInput;
}

fn validateNativeStructure(allocator: std.mem.Allocator, native_tools: []const NativeBinding, git: ToolBinding) !void {
    if (native_tools.len == 0 or native_tools.len > std.meta.fields(Alias).len) return error.DependencyUnavailable;
    var seen = std.EnumSet(Alias).initEmpty();
    for (native_tools) |native| {
        if (seen.contains(native.name)) return error.InvalidRuntime;
        seen.insert(native.name);
        const tool = native.tool;
        if (tool.contract.role != aliasRole(native.name) or tool.contract.executable == null) return error.DependencyUnavailable;
        try commandPath(tool.path);
        try c.relative(tool.contract.executable.?.path);
        if (native.name == .zig and (tool.contract.origin.scheme != .zig_package or
            !std.mem.eql(u8, tool.contract.origin.revision, c.compiler_version))) return error.UnreviewedInput;
        if (native.name == .git and !std.mem.eql(u8, try c.canonical(allocator, tool), try c.canonical(allocator, git)))
            return error.UnreviewedInput;
    }
    for (required_aliases) |name| if (!seen.contains(name)) return error.DependencyUnavailable;
    if (git.contract.role != .git or git.contract.executable == null) return error.InvalidRuntime;
}

pub fn bindingEnvironment(allocator: std.mem.Allocator, binding: Binding) !env.Record {
    var m4: ?[]const u8 = null;
    for (binding.native) |native| if (native.name == .m4) {
        if (m4 != null) return error.InvalidRuntime;
        const executable = native.tool.contract.executable orelse return error.InvalidRuntime;
        m4 = try std.fs.path.join(allocator, &.{ native.tool.path, executable.path });
    };
    return .{
        .workspace = binding.scratch.path,
        .bison_pkgdatadir = binding.bison_data.path,
        .m4 = m4 orelse return error.DependencyUnavailable,
        .git_exec_path = try std.fs.path.join(allocator, &.{ binding.scratch.path, "disabled-git-exec" }),
        .trust_bundle = try std.fs.path.join(allocator, &.{ binding.trust.path, binding.trust_bundle.path }),
    };
}

pub fn bindingMakeEnvironment(allocator: std.mem.Allocator, binding: Binding) !env.MakeRecord {
    const policy = try bindingEnvironment(allocator, binding);
    var shell: ?[]const u8 = null;
    for (binding.native) |native| if (native.name == .bash) {
        if (shell != null) return error.InvalidRuntime;
        const executable = native.tool.contract.executable orelse return error.InvalidRuntime;
        shell = try std.fs.path.join(allocator, &.{ native.tool.path, executable.path });
    };
    return .{
        .schema = .unikraft_native_make_environment_v1,
        .bison_data = policy.bison_pkgdatadir,
        .m4 = policy.m4,
        .shell = shell orelse return error.DependencyUnavailable,
        .tmp = try std.fs.path.join(allocator, &.{ policy.workspace, "tmp" }),
        .xdg_cache = try std.fs.path.join(allocator, &.{ policy.workspace, "cache" }),
        .xdg_config = try std.fs.path.join(allocator, &.{ policy.workspace, "config" }),
        .zig_global_cache = try std.fs.path.join(allocator, &.{ policy.workspace, "zig-global" }),
        .zig_local_cache = try std.fs.path.join(allocator, &.{ policy.workspace, "zig-local" }),
    };
}

pub fn bindingGitPolicy(allocator: std.mem.Allocator, binding: Binding) !git_entry.Record {
    return .{
        .schema = .hyperv_native_git_entry_v1,
        .repository = binding.repository.path,
        .runtime_directory = binding.git.path,
        .runtime = binding.git.contract,
        .environment = try bindingEnvironment(allocator, binding),
        .account = (binding.isolation orelse return error.DependencyUnavailable).account,
    };
}

pub fn validatePolicyFiles(allocator: std.mem.Allocator, io: std.Io, binding: Binding) !void {
    const isolation = binding.isolation orelse return error.DependencyUnavailable;
    const make_file = isolation.make_environment orelse return error.MissingMakeEnvironment;
    const git_file = isolation.git_policy orelse return error.MissingGitPolicy;
    const files = [_]c.File{ isolation.environment, make_file, git_file };
    const workspace = try fs.Directory.open(allocator, io, binding.workspace.path);
    defer workspace.close(allocator, io);
    try binding.workspace.require(try ns.Identity.directory(workspace));
    for (files, 0..) |file, i| {
        for (files[0..i]) |previous| if (std.mem.eql(u8, file.path, previous.path)) return error.InvalidState;
        try fs.requireFile(try workspace.record(allocator, io, file.path, git_entry.maximum_bytes, .private), file);
    }
    const original = try env.load(allocator, io, try std.fs.path.join(allocator, &.{ workspace.path, isolation.environment.path }), isolation.environment.sha256);
    defer original.deinit();
    if (!std.mem.eql(u8, try c.canonical(allocator, original.value), try c.canonical(allocator, try bindingEnvironment(allocator, binding))))
        return error.UnreviewedInput;
    const make = try env.loadMake(allocator, io, try std.fs.path.join(allocator, &.{ workspace.path, make_file.path }), make_file.sha256);
    defer make.deinit();
    if (!std.mem.eql(u8, try c.canonical(allocator, make.value), try c.canonical(allocator, try bindingMakeEnvironment(allocator, binding))))
        return error.UnreviewedInput;
    const bytes = try workspace.read(allocator, io, git_file.path, git_entry.maximum_bytes, .private);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), git_file.sha256)) return error.HashMismatch;
    const git = try git_entry.parse(allocator, bytes);
    defer git.deinit();
    if (!std.mem.eql(u8, try c.canonical(allocator, git.value), try c.canonical(allocator, try bindingGitPolicy(allocator, binding))))
        return error.UnreviewedInput;
}

test "producer rejects every missing mandatory native alias wrong role compiler and duplicate before IO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: [required_aliases.len]NativeBinding = undefined;
    for (required_aliases, &native) |name, *entry| {
        entry.* = .{ .name = name, .tool = .{ .path = "/public/synthetic/runtime", .contract = .{
            .role = aliasRole(name),
            .origin = .{ .scheme = .zig_package, .revision = c.compiler_version, .source_sha256 = c.digest("shape"), .producer_sha256 = c.digest("shape") },
            .target = .x86_64_linux,
            .tree = .{ .sha256 = c.digest("shape"), .files = 1, .bytes = 1 },
            .executable = .{ .path = "bin/tool", .size = 1, .mode = 0o700, .sha256 = c.digest("shape") },
            .loader = null,
            .libraries = &.{},
        } } };
    }
    var git = native[0].tool;
    git.contract.role = .git;
    try validateNativeStructure(allocator, &native, git);
    for (0..native.len) |missing| {
        var reduced: std.ArrayList(NativeBinding) = .empty;
        for (native, 0..) |entry, i| if (i != missing) try reduced.append(allocator, entry);
        try std.testing.expectError(error.DependencyUnavailable, validateNativeStructure(allocator, reduced.items, git));
    }
    var changed = native;
    changed[0].tool.contract.role = .qemu;
    try std.testing.expectError(error.DependencyUnavailable, validateNativeStructure(allocator, &changed, git));
    changed = native;
    changed[0].tool.contract.origin.revision = "0.15.2";
    try std.testing.expectError(error.UnreviewedInput, validateNativeStructure(allocator, &changed, git));
    changed = native;
    changed[1] = changed[0];
    try std.testing.expectError(error.InvalidRuntime, validateNativeStructure(allocator, &changed, git));
}

fn validateTools(allocator: std.mem.Allocator, io: std.Io, inputs: Inputs) !void {
    const tools = inputs.tools;
    if (tools.path) |path| try requireDirectory(allocator, io, path, true);
    if (tools.native.len == 0 or tools.native.len > std.meta.fields(Alias).len) return error.DependencyUnavailable;
    for (tools.native, 0..) |item, index| {
        for (tools.native[0..index]) |previous| if (item.name == previous.name) return error.InvalidRuntime;
        const expected_role = aliasRole(item.name);
        if (item.bound.contract.role != expected_role or item.bound.contract.executable == null)
            return error.DependencyUnavailable;
        if (item.name == .zig and (item.bound.contract.origin.scheme != .zig_package or
            !std.mem.eql(u8, item.bound.contract.origin.revision, c.compiler_version)))
            return error.UnreviewedInput;
        _ = try executablePath(allocator, item.bound);
        if (item.name == .git) {
            try fs.requireDirectoryIdentity(item.bound.directory, tools.git.directory);
            if (!std.meta.eql(try bindingToolDigest(allocator, item.bound), try bindingToolDigest(allocator, tools.git)))
                return error.InvalidRuntime;
        }
        try item.bound.validate(allocator, io);
    }
    for (required_aliases) |name|
        _ = try nativeTool(tools, name);
    if (tools.git.contract.role != .git) return error.InvalidRuntime;
    try requireData(tools.packages, .dependencies);
    try requireData(tools.bison_data, .bison_data);
    try requireData(tools.trust, .trust);
    if (tools.packages.contract.tree.files == 0 or tools.bison_data.contract.tree.files == 0 or
        tools.trust.contract.tree.files == 0) return error.DependencyUnavailable;
    for ([_]runtime.Bound{ tools.git, tools.packages, tools.bison_data, tools.trust }) |bound|
        try bound.validate(allocator, io);
    try fs.requireFile(try tools.trust.directory.record(allocator, io, tools.trust_bundle.path, 16 * 1024 * 1024, .artifact), tools.trust_bundle);
    if (tools.trust_bundle.size == 0) return error.DependencyUnavailable;
    for (tools.native) |item| try disjointRuntime(inputs, item.bound.directory.path);
    if (tools.path) |path| try disjointRuntime(inputs, path.path);
    for ([_]fs.Directory{ tools.git.directory, tools.packages.directory, tools.bison_data.directory, tools.trust.directory }) |directory|
        try disjointRuntime(inputs, directory.path);
}

fn disjointRuntime(inputs: Inputs, path: []const u8) !void {
    try commandPath(path);
    const config_path = inputs.workspace.config.path;
    if (overlaps(path, inputs.workspace.output.path) or overlaps(path, inputs.workspace.scratch.path) or
        paths.isSameOrAncestor(path, inputs.workspace.directory.path)) return error.UnsafePath;
    // All workspace-local immutable trees must also be outside the config.
    if (paths.isDescendant(inputs.workspace.directory.path, path)) {
        const relative = path[inputs.workspace.directory.path.len + 1 ..];
        if (std.mem.eql(u8, relative, config_path) or
            (std.mem.startsWith(u8, config_path, relative) and config_path.len > relative.len and config_path[relative.len] == '/'))
            return error.UnsafePath;
    }
}

const old_proofs = [_][]const u8{
    "hyperv-smp-link-test.py", "hyperv-irq-register-test.py", "hyperv-driver-registration-test.py",
};

/// Tokenization ignores dormant comments and unrelated root steps. This is an
/// explicit veto of the old *selected* proof gate, not Python reachability
/// analysis and not a substitute for the immutable native-execution review.
pub fn rejectLegacyProofs(allocator: std.mem.Allocator, root_build: []const u8) !void {
    const body = try functionBody(allocator, root_build, "finishNativeImages");
    var tokenizer = std.zig.Tokenizer.init(body);
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) return error.DependencyUnavailable;
        if (token.tag != .string_literal) continue;
        const value = std.zig.string_literal.parseAlloc(allocator, body[token.loc.start..token.loc.end]) catch
            return error.DependencyUnavailable;
        for (old_proofs) |name| if (std.mem.eql(u8, std.fs.path.basename(value), name))
            return error.DependencyUnavailable;
    }
}

fn functionBody(allocator: std.mem.Allocator, bytes: []const u8, name: []const u8) ![:0]const u8 {
    if (bytes.len > 1024 * 1024) return error.LimitExceeded;
    const text = try allocator.dupeZ(u8, bytes);
    var tokenizer = std.zig.Tokenizer.init(text);
    var found: ?[:0]const u8 = null;
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) return error.DependencyUnavailable;
        if (token.tag != .keyword_fn) continue;
        const identifier = tokenizer.next();
        if (identifier.tag != .identifier or !std.mem.eql(u8, text[identifier.loc.start..identifier.loc.end], name)) continue;
        if (found != null) return error.DependencyUnavailable;
        var opening = tokenizer.next();
        while (opening.tag != .l_brace) : (opening = tokenizer.next())
            if (opening.tag == .eof or opening.tag == .invalid or opening.tag == .semicolon) return error.DependencyUnavailable;
        var depth: usize = 1;
        while (depth != 0) {
            const next = tokenizer.next();
            switch (next.tag) {
                .l_brace => depth += 1,
                .r_brace => depth -= 1,
                .eof, .invalid => return error.DependencyUnavailable,
                else => {},
            }
            if (depth == 0) found = try allocator.dupeZ(u8, text[opening.loc.end..next.loc.start]);
        }
    }
    return found orelse error.DependencyUnavailable;
}

fn nativeSourceFile(record: c.File) !void {
    try c.relative(record.path);
    if (!std.mem.endsWith(u8, record.path, ".zig") or record.size == 0 or record.mode & 0o7022 != 0)
        return error.DependencyUnavailable;
    _ = try c.sha(&record.sha256);
}

fn requireSequences(allocator: std.mem.Allocator, source_text: []const u8, sequences: []const [:0]const u8) !void {
    if (source_text.len > 1024 * 1024) return error.LimitExceeded;
    const text = try allocator.dupeZ(u8, source_text);
    defer allocator.free(text);
    var tokens: std.ArrayList(std.zig.Token) = .empty;
    defer tokens.deinit(allocator);
    var tokenizer = std.zig.Tokenizer.init(text);
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) return error.DependencyUnavailable;
        if (tokens.items.len == 65536) return error.LimitExceeded;
        try tokens.append(allocator, token);
    }
    for (sequences) |sequence| {
        var matches: usize = 0;
        for (0..tokens.items.len) |start| {
            var expected = std.zig.Tokenizer.init(sequence);
            var index = start;
            while (true) : (index += 1) {
                const wanted = expected.next();
                if (wanted.tag == .eof) {
                    matches += 1;
                    break;
                }
                if (index == tokens.items.len) break;
                const actual = tokens.items[index];
                if (actual.tag != wanted.tag or
                    !std.mem.eql(u8, text[actual.loc.start..actual.loc.end], sequence[wanted.loc.start..wanted.loc.end])) break;
            }
        }
        if (matches != 1) return error.DependencyUnavailable;
    }
}

pub fn requireNativeProof(allocator: std.mem.Allocator, root_build: []const u8, expected_source: c.Source, proof: ?NativeProof) !void {
    // Deliberately first: callers cannot bless a selected Python gate by
    // submitting a purported native attestation.
    try rejectLegacyProofs(allocator, root_build);
    const native = proof orelse return error.DependencyUnavailable;
    try nativeSourceFile(native.root_build);
    if (!std.mem.eql(u8, native.root_build.path, "build.zig") or native.root_build.size != root_build.len or
        !std.crypto.timing_safe.eql(c.Sha, native.root_build.sha256, c.digest(root_build)) or
        !std.crypto.timing_safe.eql(c.Sha, native.source_sha256, expected_source.tree_sha256))
        return error.UnreviewedInput;
    try nativeSourceFile(native.builder);
    try nativeSourceFile(native.tool);
    if (!std.mem.eql(u8, native.builder.path, "support/build/hyperv-proof-build.zig") or
        !std.mem.eql(u8, native.tool.path, "support/build/hyperv-proof-tool.zig")) return error.DependencyUnavailable;
    for (native.modes, 0..) |mode, index|
        if (@intFromEnum(mode) != index) return error.DependencyUnavailable;
    try requireSequences(allocator, root_build, &.{
        \\const hyperv_proof_build = @import("support/build/hyperv-proof-build.zig");
    });
    const body = try functionBody(allocator, root_build, "finishNativeImages");
    try requireSequences(allocator, body, &.{
        \\const proof_tool = hyperv_proof_build.tool(b, b.path("."));
        ,
        \\const check = b.addRunArtifact(proof_tool);
        \\check.addArgs(&.{ "smp", "--image" });
        \\check.addFileArg(link_output);
        ,
        \\const irq_check = b.addRunArtifact(proof_tool);
        \\irq_check.addArgs(&.{ "irq", "--image" });
        \\irq_check.addFileArg(link_output);
        ,
        \\const driver_check = b.addRunArtifact(proof_tool);
        \\driver_check.addArgs(&.{ "drivers", "--image" });
        \\driver_check.addFileArg(link_output);
        ,
        "gate.step.dependOn(&check.step);",
        "gate.step.dependOn(&irq_check.step);",
        "gate.step.dependOn(&driver_check.step);",
        "gate.addFileArg(link_output);",
        \\validated_link_output = gate.addOutputFileArg("hyperv-validated-final.dbg");
    });
}

/// The complete physical source/provenance review remains mandatory. This
/// recognizes the supported shared-tool wiring, not arbitrary Zig semantics.
pub fn requireNativeProofFiles(allocator: std.mem.Allocator, io: std.Io, repository: fs.Directory, expected_source: c.Source, proof: ?NativeProof) !void {
    const native = proof orelse return error.DependencyUnavailable;
    const root = try repository.read(allocator, io, "build.zig", 1024 * 1024, .source);
    defer allocator.free(root);
    try requireNativeProof(allocator, root, expected_source, native);
    for ([_]c.File{ native.root_build, native.builder, native.tool }) |file|
        try fs.requireFile(try repository.record(allocator, io, file.path, 1024 * 1024, .source), file);
    const builder = try repository.read(allocator, io, native.builder.path, 1024 * 1024, .source);
    defer allocator.free(builder);
    try requireSequences(allocator, try functionBody(allocator, builder, "tool"), &.{
        \\return b.addExecutable(.{
        \\    .name = "hyperv-image-proof",
        \\    .root_module = module(b, root, "support/build/hyperv-proof-tool.zig", b.graph.host, .ReleaseSafe),
        \\});
    });
    try requireSequences(allocator, try functionBody(allocator, builder, "module"), &.{
        \\const result = b.createModule(.{
        \\    .root_source_file = root.path(b, source),
        \\    .target = target,
        \\    .optimize = optimize,
        \\    .pic = true,
        \\});
        ,
        \\result.addImport("vmbus_protocol", b.createModule(.{
        \\    .root_source_file = root.path(b, "drivers/hyperv/vmbus/vmbus_protocol.zig"),
    });
    const tool = try repository.read(allocator, io, native.tool.path, 1024 * 1024, .source);
    defer allocator.free(tool);
    try requireSequences(allocator, tool, &.{
        \\const proofs = @import("hyperv-image-proofs.zig");
    });
    try requireSequences(allocator, try functionBody(allocator, tool, "execute"), &.{
        "try proofs.smp(model, cpus.?, diagnostic);",
        "const report = try proofs.irq(model, diagnostic);",
        "try proofs.drivers(model, required.items, diagnostic);",
    });
}

fn validateSelection(allocator: std.mem.Allocator, io: std.Io, inputs: Inputs, step: Step) !void {
    if (step == .build) try requireNativeProofFiles(allocator, io, inputs.repository, inputs.observed_source, inputs.native_proof);
    const execution = inputs.native_execution orelse return error.DependencyUnavailable;
    if (!std.crypto.timing_safe.eql(c.Sha, execution.source_sha256, inputs.observed_source.tree_sha256) or
        !std.mem.eql(u8, execution.compiler_version, c.compiler_version)) return error.UnreviewedInput;
    try nativeSourceFile(execution.root_build);
    if (!std.mem.eql(u8, execution.root_build.path, "build.zig")) return error.DependencyUnavailable;
    const root_record = try inputs.repository.record(allocator, io, "build.zig", 1024 * 1024, .source);
    try fs.requireFile(root_record, execution.root_build);
    if (step == .build) try fs.requireFile(root_record, inputs.native_proof.?.root_build);
    try nativeSourceFile(execution.facade);
    if (!std.mem.eql(u8, execution.facade.path, "support/build/zig-facade-runner.zig")) return error.DependencyUnavailable;
    try fs.requireFile(try inputs.repository.record(allocator, io, execution.facade.path, 1024 * 1024, .source), execution.facade);
    if (!std.mem.eql(u8, execution.makefile.path, "Makefile")) return error.DependencyUnavailable;
    try fs.requireFile(try inputs.repository.record(allocator, io, "Makefile", 1024 * 1024, .source), execution.makefile);
    try commandPath(execution.make_default_shell);
    if (!std.mem.eql(u8, execution.make_default_shell, "/bin/sh"))
        return error.UnreviewedInput;
    const entry = execution.git_entry_source orelse return error.DependencyUnavailable;
    try nativeSourceFile(entry);
    if (!std.mem.eql(u8, entry.path, "support/tools/hyperv/preparation/git_entry.zig")) return error.DependencyUnavailable;
    try fs.requireFile(try inputs.repository.record(allocator, io, entry.path, 1024 * 1024, .source), entry);
}

fn bindingToolDigest(allocator: std.mem.Allocator, bound: runtime.Bound) !c.Sha {
    return c.digest(try c.canonical(allocator, toolBinding(bound)));
}

pub fn environmentRecord(allocator: std.mem.Allocator, io: std.Io, inputs: Inputs) !env.Record {
    const binding = try describe(allocator, inputs);
    try validatePolicyFiles(allocator, io, binding);
    return bindingEnvironment(allocator, binding);
}

/// Safe process observation for the parent to embed in its own state contract.
/// No stdout, stderr, paths, exception strings, or recovery PIDs belong here.
pub const Observation = struct {
    step: Step,
    termination: ?std.process.Child.Term,
    failures: c.Failure,
    cleanup_complete: bool,
};

pub const Outcome = struct {
    step: Step,
    /// Owned storage, bounded stdout, exact termination, enum-only diagnostics,
    /// and private unresolved-cleanup metadata are retained without translation.
    child: process.Result,
    /// The transport/helper exit is not the payload termination.
    helper_termination: ?std.process.Child.Term = null,

    pub fn namespaceStatus(self: *Outcome, result: anyerror!ns.Status) void {
        self.helper_termination = self.child.termination;
        self.child.termination = null;
        const status = result catch {
            if (self.child.failures.recording == null)
                self.child.failures.recording = .{ .stage = .state_record, .category = .invalid_response };
            self.discardOutput();
            return;
        };
        self.child.termination = status.termination();
        if (self.child.failures.primary == null) {
            self.child.failures.primary = switch (status.primary) {
                .unknown => null,
                .exited => if (status.code == 0) null else .{ .stage = .process_run, .category = .child_failed },
                .signaled => .{ .stage = .process_run, .category = .child_failed },
                .spawn_failed => .{ .stage = .process_spawn, .category = .spawn_failed },
                .setup_failed => .{ .stage = .process_spawn, .category = .unavailable },
            };
        }
        if (status.cleanup == .failed) {
            self.child.cleanup_complete = false;
            if (self.child.failures.cleanup == null)
                self.child.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
        }
        if (status.recording != .complete and self.child.failures.recording == null)
            self.child.failures.recording = .{ .stage = .state_record, .category = .invalid_response };
        if (!self.succeeded()) self.discardOutput();
    }

    fn discardOutput(self: *Outcome) void {
        std.crypto.secureZero(u8, self.child.storage);
        self.child.stdout = &.{};
    }

    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        self.child.deinit(allocator);
        self.* = undefined;
    }

    pub fn observation(self: Outcome) Observation {
        return .{
            .step = self.step,
            .termination = self.child.termination,
            .failures = self.child.failures,
            .cleanup_complete = self.child.cleanup_complete,
        };
    }

    pub fn succeeded(self: Outcome) bool {
        return self.child.termination != null and self.child.termination.? == .exited and
            self.child.termination.?.exited == 0 and self.child.cleanup_complete and
            self.child.failures.primary == null and self.child.failures.cleanup == null and self.child.failures.recording == null;
    }
};

fn admissionFailure(allocator: std.mem.Allocator, step: Step, err: anyerror) !Outcome {
    return .{ .step = step, .child = .{ .storage = try allocator.alloc(u8, 0), .failures = c.failure(err) } };
}

fn supervisorFailure(allocator: std.mem.Allocator, step: Step, err: anyerror) !Outcome {
    var result: Outcome = .{ .step = step, .child = .{ .storage = try allocator.alloc(u8, 0) } };
    recordSupervisorFailure(&result, err);
    return result;
}

fn recordSupervisorFailure(result: *Outcome, err: anyerror) void {
    if (err == error.UnresolvedCleanup) {
        result.child.cleanup_complete = false;
        result.child.failures.cleanup = .{ .stage = .process_cleanup, .category = .cleanup_failed };
    } else {
        result.child.failures.primary = .{ .stage = .process_spawn, .category = switch (err) {
            error.SupervisorBusy => .contention,
            error.SubreaperRequired, error.SubreaperUnavailable => .unavailable,
            error.InvalidOptions => .invalid_input,
            else => .local_io,
        } };
    }
}

/// Dedicated-supervisor entry only. The parent retains its workspace writer
/// lock and performs full source.inspect/require before AND after this call.
/// This initializes core process ownership, executes once, then revalidates
/// immutable inputs even after failure. It never publishes or advances state.
pub fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    step: Step,
    inputs: Inputs,
    expected: Expected,
    deadline: process.Deadline,
) !Outcome {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    preflight(scratch, io, step, inputs, expected) catch |err| return admissionFailure(allocator, step, err);
    // Allocate the return value before publishing anything. All later failures
    // flow through the same independent, exact-resource cleanup path.
    var outcome: Outcome = .{ .step = step, .child = .{ .storage = try allocator.alloc(u8, 0) } };
    var resources: NamespaceResources = .{ .directory = inputs.workspace.scratch.dir };
    executePrepared(allocator, scratch, io, step, inputs, expected, deadline, &resources, &outcome) catch |err| {
        if (outcome.child.failures.primary == null)
            outcome.child.failures.primary = .{ .stage = .private_file, .category = switch (err) {
                error.PathAlreadyExists => .conflict,
                error.SourceChanged => .integrity,
                error.UnsafePath, error.UnsafeFile => .unsafe_file,
                else => .local_io,
            } };
        outcome.discardOutput();
    };
    resources.cleanup(io, &outcome);
    return outcome;
}

fn executePrepared(allocator: std.mem.Allocator, scratch: std.mem.Allocator, io: std.Io, step: Step, inputs: Inputs, expected: Expected, deadline: process.Deadline, resources: *NamespaceResources, outcome: *Outcome) !void {
    const binding = try describe(scratch, inputs);
    try resources.createRoot(io);
    const root = try ns.Identity.of(
        try std.fs.path.join(scratch, &.{ inputs.workspace.scratch.path, "namespace-root" }),
        .{ .handle = resources.root.?.handle, .flags = .{ .nonblocking = false } },
    );
    const bytes = try c.canonical(scratch, ns.Request{ .step = step, .binding = binding, .root = root });
    try resources.publishRequest(io, bytes);
    const status_file = try ns.StatusFile.create();
    defer status_file.close();
    const argv = [_][]const u8{
        try executablePath(scratch, inputs.isolation.?.helper),
        try std.fs.path.join(scratch, &.{ inputs.workspace.scratch.path, "namespace-request.json" }),
        try scratch.dupe(u8, &c.digest(bytes)),
        try std.fmt.allocPrint(scratch, "{d}", .{status_file.fd}),
    };
    var controlled = std.process.Environ.Map.init(scratch);
    defer controlled.deinit();
    process.initialize() catch |err| {
        recordSupervisorFailure(outcome, err);
        return;
    };
    const previous_mask = std.os.linux.syscall1(.umask, 0o077);
    defer _ = std.os.linux.syscall1(.umask, previous_mask);
    const child = process.run(allocator, io, .{
        .argv = &argv,
        .environment = &controlled,
        .cwd = inputs.repository.dir,
        .deadline = deadline,
        .stdout_limit = if (step == .inspect) inspection_limit else 64 * 1024,
        .stderr_limit = 1024 * 1024,
    }) catch |err| {
        recordSupervisorFailure(outcome, err);
        return;
    };
    outcome.child.deinit(allocator);
    outcome.child = child;
    outcome.namespaceStatus(status_file.read());
    postflight(scratch, io, step, inputs, expected) catch |err| {
        if (outcome.child.failures.primary == null) outcome.child.failures.primary = c.failure(err).primary;
        outcome.discardOutput();
    };
}

pub const NamespaceResources = struct {
    directory: std.Io.Dir,
    request: ?std.Io.File = null,
    root: ?std.Io.Dir = null,
    root_created: bool = false,

    pub fn createRoot(self: *NamespaceResources, io: std.Io) !void {
        try self.directory.createDir(io, "namespace-root", .fromMode(0o700));
        self.root_created = true;
        self.root = try self.directory.openDir(io, "namespace-root", .{ .follow_symlinks = false });
    }

    pub fn publishRequest(self: *NamespaceResources, io: std.Io, bytes: []const u8) !void {
        self.request = try self.directory.createFile(io, "namespace-request.json", .{ .exclusive = true, .permissions = .fromMode(0o600) });
        try self.request.?.writeStreamingAll(io, bytes);
        try self.request.?.sync(io);
    }

    pub fn cleanup(self: *NamespaceResources, io: std.Io, outcome: *Outcome) void {
        // Attempt both removals independently, even if the first is refused.
        if (self.request) |file| {
            self.remove(io, file, false) catch cleanupFailed(outcome);
            file.close(io);
            self.request = null;
        }
        if (self.root_created) {
            if (self.root) |dir| {
                self.remove(io, .{ .handle = dir.handle, .flags = .{ .nonblocking = false } }, true) catch cleanupFailed(outcome);
                dir.close(io);
            } else cleanupFailed(outcome);
            self.root = null;
            self.root_created = false;
        }
    }

    fn remove(self: NamespaceResources, io: std.Io, held: std.Io.File, directory: bool) !void {
        const name = if (directory) "namespace-root" else "namespace-request.json";
        const named = self.directory.openFile(io, name, .{ .path_only = true, .follow_symlinks = false }) catch |err| {
            if (err == error.FileNotFound) {
                if ((try fs.metadata(held)).links == 0) return;
                return error.SourceChanged;
            }
            return err;
        };
        defer named.close(io);
        const before = try fs.metadata(held);
        const after = try fs.metadata(named);
        if (before.device != after.device or before.inode != after.inode or before.mode != after.mode or before.uid != after.uid)
            return error.SourceChanged;
        if (directory) try self.directory.deleteDir(io, name) else try self.directory.deleteFile(io, name);
        if ((try fs.metadata(held)).links != 0) return error.SourceChanged;
    }

    fn cleanupFailed(outcome: *Outcome) void {
        outcome.child.cleanup_complete = false;
        if (outcome.child.failures.cleanup == null)
            outcome.child.failures.cleanup = .{ .stage = .private_file, .category = .cleanup_failed };
        outcome.discardOutput();
    }
};

pub fn preflight(allocator: std.mem.Allocator, io: std.Io, step: Step, inputs: Inputs, expected: Expected) !void {
    // This veto precedes even a Git/loader subprocess.
    try validateSelection(allocator, io, inputs, step);
    try source.require(inputs.observed_source, expected.source);
    try validateBindingStructure(allocator, try describe(allocator, inputs));
    _ = try c.sha(&expected.binding_sha256);
    if (!std.crypto.timing_safe.eql(c.Sha, expected.binding_sha256, try bindingDigest(allocator, try describe(allocator, inputs))))
        return error.UnreviewedInput;
    try validateWorkspace(allocator, io, inputs, false, step);
    try validateTools(allocator, io, inputs);
    try ns.validate(allocator, io, inputs.isolation orelse return error.DependencyUnavailable, inputs.repository, inputs.workspace.directory);
    _ = try environmentRecord(allocator, io, inputs);
}

fn postflight(allocator: std.mem.Allocator, io: std.Io, step: Step, inputs: Inputs, expected: Expected) !void {
    try validateWorkspace(allocator, io, inputs, true, step);
    try validateTools(allocator, io, inputs);
    try validateSelection(allocator, io, inputs, step);
    try ns.validate(allocator, io, inputs.isolation orelse return error.DependencyUnavailable, inputs.repository, inputs.workspace.directory);
    _ = try environmentRecord(allocator, io, inputs);
    // describe uses the original config contract; only configure may change its
    // contents. Directory identity excludes mtime/ctime of mutable work areas.
    if (!std.crypto.timing_safe.eql(c.Sha, expected.binding_sha256, try bindingDigest(allocator, try describe(allocator, inputs))))
        return error.SourceChanged;
}

/// Namespace-helper reconstruction. All paths are descriptor-opened again and
/// the complete binding is revalidated by preflight before namespace entry.
pub fn reopenBinding(allocator: std.mem.Allocator, io: std.Io, binding: Binding) !Inputs {
    const natives = try allocator.alloc(Native, binding.native.len);
    for (binding.native, natives) |item, *native|
        native.* = .{ .name = item.name, .bound = try reopenTool(allocator, io, item.tool) };
    return .{
        .repository = try fs.Directory.open(allocator, io, binding.repository.path),
        .observed_source = binding.source,
        .workspace = .{
            .directory = try fs.Directory.open(allocator, io, binding.workspace.path),
            .output = try fs.Directory.open(allocator, io, binding.output.path),
            .scratch = try fs.Directory.open(allocator, io, binding.scratch.path),
            .config = binding.config,
        },
        .tools = .{
            .path = if (binding.path) |path| try fs.Directory.open(allocator, io, path.path) else null,
            .native = natives,
            .git = try reopenTool(allocator, io, binding.git),
            .packages = try reopenTool(allocator, io, binding.packages),
            .bison_data = try reopenTool(allocator, io, binding.bison_data),
            .trust = try reopenTool(allocator, io, binding.trust),
            .trust_bundle = binding.trust_bundle,
        },
        .native_execution = binding.native_execution,
        .native_proof = binding.native_proof,
        .isolation = if (binding.isolation) |isolation| try ns.reopen(allocator, io, isolation) else null,
    };
}
fn reopenTool(allocator: std.mem.Allocator, io: std.Io, tool: ToolBinding) !runtime.Bound {
    return .{ .directory = try fs.Directory.open(allocator, io, tool.path), .contract = tool.contract };
}

const fixture_paths: CommandPaths = .{
    .repository = "/reviewed/repository",
    .config = "/private/work/input.config",
    .output = "/private/work/build",
    .scratch = "/private/work/scratch",
    .packages = "/reviewed/packages",
    .zig = "/reviewed/native/bin/zig",
    .make = "/reviewed/native/bin/make",
    .llvm = .{
        .nm = "/reviewed/native/bin/llvm-nm",
        .objcopy = "/reviewed/native/bin/llvm-objcopy",
        .objdump = "/reviewed/native/bin/llvm-objdump",
        .readelf = "/reviewed/native/bin/llvm-readelf",
        .strip = "/reviewed/native/bin/llvm-strip",
    },
};

test "producer exact native argv fixes targets flags packages and existing Make facade" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_]Step{ .configure, .inspect, .build }, [_][]const u8{ "olddefconfig", "config-inspect", "native-images" }) |step, goal| {
        const command = try plan(arena.allocator(), step, fixture_paths);
        const expected = [_][]const u8{
            "/reviewed/native/bin/zig",                                  "build",                                                goal,                                                   "-j2",                                              "--system",                                  "/reviewed/packages",
            "--cache-dir",                                               "/private/work/scratch/zig-local",                      "--global-cache-dir",                                   "/private/work/scratch/zig-global",                 "--prefix",                                  "/private/work/build",
            "-Dapp=/reviewed/repository/support/apps/hyperv-acceptance", "-Dconfig=/private/work/input.config",                  "-Doutput=/private/work/build",                         "-Dnative-profile=hyperv-x86_64-efi-netvsc",        "-Dmake-command=/reviewed/native/bin/make",  "-Dcompiler=/reviewed/native/bin/zig cc -target x86_64-freestanding-none",
            "-Dcompiler-targeted=true",                                  "-Dhost-cc=/reviewed/native/bin/zig cc",                "-Dhost-cxx=/reviewed/native/bin/zig c++",              "-Dhost-cflags=-fno-sanitize=null",                 "-Dmake-arg=AR=/reviewed/native/bin/zig ar", "-Dmake-arg=NM=/reviewed/native/bin/llvm-nm",
            "-Dmake-arg=OBJCOPY=/reviewed/native/bin/llvm-objcopy",      "-Dmake-arg=OBJDUMP=/reviewed/native/bin/llvm-objdump", "-Dmake-arg=READELF=/reviewed/native/bin/llvm-readelf", "-Dmake-arg=STRIP=/reviewed/native/bin/llvm-strip", "-Dmake-arg=UK_CFLAGS=-std=gnu17",           "-Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt",
        };
        try std.testing.expectEqual(step, command.step);
        try std.testing.expectEqualStrings(fixture_paths.repository, command.cwd);
        try std.testing.expectEqual(expected.len, command.argv.len);
        for (expected, command.argv) |want, actual| try std.testing.expectEqualStrings(want, actual);
    }
}

test "producer rejects spaces shell metacharacters and ambiguous compiler paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "/tool with space/zig", "/tool;id/zig", "/tool$HOME/zig", "/tool`id`/zig", "/tool'quote/zig", "/tool\"quote/zig", "/tool\\escape/zig", "/tool|pipe/zig", "/tool&and/zig", "/tool(a)/zig", "/tool\nline/zig", "/tool:search/zig", "/tool/../zig", "/tool//zig", "zig", "/tool/zig/" }) |bad| {
        var command = fixture_paths;
        command.zig = bad;
        try std.testing.expectError(error.UnsafePath, plan(arena.allocator(), .build, command));
        command = fixture_paths;
        command.llvm.nm = bad;
        try std.testing.expectError(error.UnsafePath, plan(arena.allocator(), .inspect, command));
        command = fixture_paths;
        command.make = bad;
        try std.testing.expectError(error.UnsafePath, plan(arena.allocator(), .configure, command));
    }
}

test "producer exact dedicated environment arguments do not enter the Make override channel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var command = fixture_paths;
    command.native_make_environment = "/private/work/make-environment.json";
    const selected = try plan(arena.allocator(), .configure, command);
    try std.testing.expectEqualStrings("-Dnative-make-environment=/private/work/make-environment.json", selected.argv[selected.argv.len - 1]);
    for (selected.argv) |arg| {
        try std.testing.expect(!std.mem.startsWith(u8, arg, "-Dpreparation-environment"));
        inline for (.{ "UMASK", "SHELL", "CONFIG_SHELL", "M4", "BISON_PKGDATADIR", "TMPDIR", "ZIG_LOCAL_CACHE_DIR", "ZIG_GLOBAL_CACHE_DIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME" }) |name|
            try std.testing.expect(!std.mem.startsWith(u8, arg, "-Dmake-arg=" ++ name ++ "="));
    }
}

test "producer vetoes selected Python proofs before any child or claimed native approval" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for (old_proofs) |name| {
        const root = try std.fmt.allocPrint(arena.allocator(), "fn finishNativeImages() void {{ const p = \"support/build/tests/{s}\"; }}", .{name});
        try std.testing.expectError(error.DependencyUnavailable, rejectLegacyProofs(arena.allocator(), root));
        // observed_source and proof must not be evaluated before the veto.
        try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(arena.allocator(), root, undefined, null));
    }
    const unrelated =
        \\fn unrelated() void { const p = "support/build/tests/hyperv-smp-link-test.py"; }
        \\fn finishNativeImages() void {
        \\    // "support/build/tests/hyperv-smp-link-test.py" is dormant.
        \\}
    ;
    try rejectLegacyProofs(arena.allocator(), unrelated);
    try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(arena.allocator(), unrelated, undefined, null));
    try std.testing.expectError(error.DependencyUnavailable, rejectLegacyProofs(arena.allocator(), "fn noSelectedGate() void {}"));
}

test "producer native proof selection is source-bound ordered and separately reviewable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    // Parser fixture for the merged shared-tool shape, not a build approval.
    const root =
        \\const hyperv_proof_build = @import("support/build/hyperv-proof-build.zig");
        \\fn finishNativeImages() void {
        \\    const proof_tool = hyperv_proof_build.tool(b, b.path("."));
        \\    const check = b.addRunArtifact(proof_tool);
        \\    check.addArgs(&.{ "smp", "--image" });
        \\    check.addFileArg(link_output);
        \\    const irq_check = b.addRunArtifact(proof_tool);
        \\    irq_check.addArgs(&.{ "irq", "--image" });
        \\    irq_check.addFileArg(link_output);
        \\    const driver_check = b.addRunArtifact(proof_tool);
        \\    driver_check.addArgs(&.{ "drivers", "--image" });
        \\    driver_check.addFileArg(link_output);
        \\    gate.step.dependOn(&check.step);
        \\    gate.step.dependOn(&irq_check.step);
        \\    gate.step.dependOn(&driver_check.step);
        \\    gate.addFileArg(link_output);
        \\    validated_link_output = gate.addOutputFileArg("hyperv-validated-final.dbg");
        \\}
    ;
    const fixture_source: c.Source = .{
        .scheme = .git_physical_native_v1,
        .head = "1111111111111111111111111111111111111111",
        .tree = "2222222222222222222222222222222222222222",
        .tree_sha256 = c.digest("synthetic proof-selection source"),
        .physical = .{ .sha256 = c.digest("synthetic physical tree"), .files = 4, .bytes = 1000 },
    };
    const proof: NativeProof = .{
        .schema = .hyperv_native_elf_proofs_v2,
        .source_sha256 = fixture_source.tree_sha256,
        .root_build = .{ .path = "build.zig", .sha256 = c.digest(root), .size = root.len, .mode = 0o644 },
        .builder = .{ .path = "support/build/hyperv-proof-build.zig", .sha256 = c.digest("synthetic builder"), .size = 1, .mode = 0o644 },
        .tool = .{ .path = "support/build/hyperv-proof-tool.zig", .sha256 = c.digest("synthetic tool"), .size = 1, .mode = 0o644 },
        .modes = .{ .smp, .irq, .drivers },
    };
    try requireNativeProof(allocator, root, fixture_source, proof);
    var changed = proof;
    changed.source_sha256 = c.digest("different source");
    try std.testing.expectError(error.UnreviewedInput, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.root_build.sha256 = c.digest("different root");
    try std.testing.expectError(error.UnreviewedInput, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.modes[1] = .smp;
    try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.builder.path = "elsewhere/hyperv-proof-build.zig";
    try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.tool.path = "support/build/not-selected.zig";
    try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(allocator, root, fixture_source, changed));
}

test "producer outcome preserves nonzero deadline cleanup and recording lanes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try process.initialize();
    var environment_map = std.process.Environ.Map.init(allocator);
    defer environment_map.deinit();
    const fixture = @import("test_options").process_fixture;
    // Only this tiny native process is executed, never a guest or root build.
    var failed: Outcome = .{ .step = .build, .child = try process.run(allocator, io, .{
        .argv = &.{ fixture, "failure" },
        .environment = &environment_map,
        .cwd = std.Io.Dir.cwd(),
        .deadline = try process.Deadline.afterMilliseconds(5000),
    }) };
    defer failed.deinit(allocator);
    try std.testing.expect(!failed.succeeded());
    try std.testing.expectEqual(@as(u8, 19), failed.child.termination.?.exited);
    try std.testing.expectEqual(.child_failed, failed.child.failures.primary.?.category);
    try std.testing.expectEqual(@as(usize, 0), failed.child.stdout.len);
    try std.testing.expect(failed.child.cleanup_complete);
    try std.testing.expect(failed.child.failures.cleanup == null);
    var progress: Outcome = .{ .step = .inspect, .child = try process.run(allocator, io, .{
        .argv = &.{ fixture, "progress" },
        .environment = &environment_map,
        .cwd = std.Io.Dir.cwd(),
        .deadline = try process.Deadline.afterMilliseconds(5000),
    }) };
    defer progress.deinit(allocator);
    try std.testing.expect(progress.succeeded());
    try std.testing.expectEqualStrings("{\"fixture\":\"native-progress\"}", progress.child.stdout);
    const observation = try c.canonical(allocator, progress.observation());
    defer allocator.free(observation);
    try std.testing.expect(std.mem.indexOf(u8, observation, "native-progress") == null);
    try std.testing.expect(std.mem.indexOf(u8, observation, "stdout") == null);
    var expired: Outcome = .{ .step = .configure, .child = try process.run(allocator, io, .{
        .argv = &.{ fixture, "progress" },
        .environment = &environment_map,
        .cwd = std.Io.Dir.cwd(),
        .deadline = .{ .expires_ns = 0 },
    }) };
    defer expired.deinit(allocator);
    try std.testing.expectEqual(.timeout, expired.child.failures.primary.?.category);
    try std.testing.expect(expired.child.termination == null);
    try std.testing.expect(expired.child.failures.cleanup == null);
    // Synthetic lane composition tests the wrapper, not a fabricated OS cleanup
    // failure. Real cleanup/poison tests belong to core.process.
    try failed.child.failures.record(.cleanup, .{ .stage = .process_cleanup, .category = .cleanup_failed });
    try failed.child.failures.record(.recording, .{ .stage = .state_record, .category = .local_io });
    try std.testing.expectEqual(.child_failed, failed.child.failures.primary.?.category);
    try std.testing.expectEqual(.cleanup_failed, failed.child.failures.cleanup.?.category);
    try std.testing.expectEqual(.local_io, failed.child.failures.recording.?.category);
    try std.testing.expect(!failed.succeeded());
    var unresolved = try supervisorFailure(allocator, .configure, error.UnresolvedCleanup);
    defer unresolved.deinit(allocator);
    try std.testing.expect(!unresolved.child.cleanup_complete);
    try std.testing.expect(unresolved.child.termination == null);
    try std.testing.expectEqual(.cleanup_failed, unresolved.child.failures.cleanup.?.category);
}
