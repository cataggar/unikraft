// SPDX-License-Identifier: BSD-3-Clause
//! Fixed local producer commands, not receipts or an arbitrary command runner.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const runtime = @import("runtime.zig");
const source = @import("source.zig");
const process = c.core.process;
const paths = @import("facade_paths");

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
    return .{ .step = step, .cwd = command.repository, .argv = try args.toOwnedSlice(allocator) };
}

fn commandPath(value: []const u8) !void {
    if (!std.fs.path.isAbsolute(value) or value.len < 2 or value.len > 4096) return error.UnsafePath;
    // These paths also occur inside Make/compiler command strings.
    try c.relative(value[1..]);
}

/// Each PATH entry must be a provisioned, reviewed, static native ELF. In
/// particular `git` is a fixed native relocated-Git entry, NOT bin/git from an
/// installed distribution and NOT a shell wrapper. No dispatcher is supplied
/// by this module; missing provisioned entries are a dependency failure.
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
    path: fs.Directory,
    native: []const Native,
    git: runtime.Bound,
    packages: runtime.Bound,
    bison_data: runtime.Bound,
    trust: runtime.Bound,
    trust_bundle: c.File,
};

pub const ProofKind = enum { smp, irq, drivers };
pub const ProofInput = struct { kind: ProofKind, file: c.File };

/// No current approval is built in. The independent expected binding must
/// include this attestation and the exact reviewed root-build/source hashes.
pub const NativeProof = struct {
    schema: enum { hyperv_native_elf_proofs_v1 },
    source_sha256: c.Sha,
    root_build: c.File,
    inputs: [3]ProofInput,
};

pub const NativeExecution = struct {
    schema: enum { closed_native_facade_runtime_v1 },
    source_sha256: c.Sha,
    root_build: c.File,
    facade: c.File,
    makefile: c.File,
    /// Provisioned GNU Make must select this native shell even for $(shell)
    /// before the repository Makefile assigns SHELL. A stock /bin/sh default
    /// is not covered by merely putting a reviewed shell on PATH.
    make_default_shell: []const u8,
    /// A source-bound native implementation, with no arbitrary executable
    /// selector, which reinstalls the Git isolation contract for Make children.
    git_entry_source: c.File,
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
};

pub const Expected = struct {
    source: c.Source,
    /// Independently reviewed, immutable digest; never approve a fresh
    /// describe() result merely because it was measured on this machine.
    binding_sha256: c.Sha,
};

const DirectoryIdentity = struct {
    path: []const u8,
    device: u64,
    inode: u64,
    mode: u16,
    uid: u32,
};
const ToolBinding = struct { path: []const u8, contract: runtime.Tool };
const NativeBinding = struct { name: Alias, tool: ToolBinding };

pub const Binding = struct {
    schema: enum { hyperv_local_native_producer_binding_v1 },
    source: c.Source,
    repository: DirectoryIdentity,
    workspace: DirectoryIdentity,
    output: DirectoryIdentity,
    scratch: DirectoryIdentity,
    config: c.File,
    path: DirectoryIdentity,
    native: []const NativeBinding,
    git: ToolBinding,
    packages: ToolBinding,
    bison_data: ToolBinding,
    trust: ToolBinding,
    trust_bundle: c.File,
    native_execution: ?NativeExecution,
    native_proof: ?NativeProof,
};

/// A measurement for separate review, not admission. Does not spawn children,
/// manufacture a proof approval, or restore packages.
pub fn describe(allocator: std.mem.Allocator, inputs: Inputs) !Binding {
    if (inputs.tools.native.len > std.meta.fields(Alias).len) return error.LimitExceeded;
    const native = try allocator.alloc(NativeBinding, inputs.tools.native.len);
    for (inputs.tools.native, native) |item, *binding| binding.* = .{ .name = item.name, .tool = toolBinding(item.bound) };
    return .{
        .schema = .hyperv_local_native_producer_binding_v1,
        .source = inputs.observed_source,
        .repository = try directoryIdentity(inputs.repository),
        .workspace = try directoryIdentity(inputs.workspace.directory),
        .output = try directoryIdentity(inputs.workspace.output),
        .scratch = try directoryIdentity(inputs.workspace.scratch),
        .config = inputs.workspace.config,
        .path = try directoryIdentity(inputs.tools.path),
        .native = native,
        .git = toolBinding(inputs.tools.git),
        .packages = toolBinding(inputs.tools.packages),
        .bison_data = toolBinding(inputs.tools.bison_data),
        .trust = toolBinding(inputs.tools.trust),
        .trust_bundle = inputs.tools.trust_bundle,
        .native_execution = inputs.native_execution,
        .native_proof = inputs.native_proof,
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
        "home", "tmp", "cache", "config", "zig-global", "zig-local", "disabled-git-exec", "disabled-openssl",
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

fn validateTools(allocator: std.mem.Allocator, io: std.Io, inputs: Inputs) !void {
    const tools = inputs.tools;
    try requireDirectory(allocator, io, tools.path, true);
    if (tools.native.len == 0 or tools.native.len > std.meta.fields(Alias).len) return error.DependencyUnavailable;
    for (tools.native, 0..) |item, index| {
        for (tools.native[0..index]) |previous| if (item.name == previous.name) return error.InvalidRuntime;
        const expected_role: runtime.Role = switch (item.name) {
            .zig => .zig,
            .make => .make,
            .bison, .yacc => .bison,
            .flex, .lex => .flex,
            .m4 => .m4,
            .@"llvm-nm", .@"llvm-objcopy", .@"llvm-objdump", .@"llvm-readelf", .@"llvm-strip" => .llvm,
            else => .preparation,
        };
        if (item.bound.contract.role != expected_role or item.bound.contract.executable == null or
            item.bound.contract.loader != null or item.bound.contract.libraries.len != 0)
            return error.DependencyUnavailable;
        if (item.name == .zig and (item.bound.contract.origin.scheme != .zig_package or
            !std.mem.eql(u8, item.bound.contract.origin.revision, c.compiler_version)))
            return error.UnreviewedInput;
        const executable = try executablePath(allocator, item.bound);
        const alias = try std.fs.path.join(allocator, &.{ tools.path.path, @tagName(item.name) });
        if (!std.mem.eql(u8, executable, alias)) return error.InvalidRuntime;
        try item.bound.validate(allocator, io);
    }
    inline for (.{ Alias.zig, .make, .git, .bison, .flex, .m4, .@"llvm-nm", .@"llvm-objcopy", .@"llvm-objdump", .@"llvm-readelf", .@"llvm-strip", .sh, .bash }) |name|
        _ = try nativeTool(tools, name);
    var count: usize = 0;
    var iterator = tools.path.dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) return error.InvalidRuntime;
        const name = std.meta.stringToEnum(Alias, entry.name) orelse return error.InvalidRuntime;
        _ = try nativeTool(tools, name);
        count += 1;
    }
    if (count != tools.native.len) return error.InvalidRuntime;
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
    for ([_]fs.Directory{ tools.path, tools.git.directory, tools.packages.directory, tools.bison_data.directory, tools.trust.directory }) |directory|
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

pub fn requireNativeProof(allocator: std.mem.Allocator, root_build: []const u8, expected_source: c.Source, proof: ?NativeProof) !void {
    // Deliberately first: callers cannot bless the current Python gate by
    // submitting a purported native attestation.
    try rejectLegacyProofs(allocator, root_build);
    const native = proof orelse return error.DependencyUnavailable;
    try nativeSourceFile(native.root_build);
    if (!std.mem.eql(u8, native.root_build.path, "build.zig") or native.root_build.size != root_build.len or
        !std.crypto.timing_safe.eql(c.Sha, native.root_build.sha256, c.digest(root_build)) or
        !std.crypto.timing_safe.eql(c.Sha, native.source_sha256, expected_source.tree_sha256))
        return error.UnreviewedInput;
    const body = try functionBody(allocator, root_build, "finishNativeImages");
    for (native.inputs, 0..) |input, index| {
        if (@intFromEnum(input.kind) != index) return error.DependencyUnavailable;
        try nativeSourceFile(input.file);
        if (!std.mem.startsWith(u8, input.file.path, "support/build/")) return error.DependencyUnavailable;
        for (native.inputs[0..index]) |previous| if (std.mem.eql(u8, input.file.path, previous.file.path))
            return error.DependencyUnavailable;
        var selected = false;
        var tokenizer = std.zig.Tokenizer.init(body);
        while (true) {
            const token = tokenizer.next();
            if (token.tag == .eof) break;
            if (token.tag != .string_literal) continue;
            const value = std.zig.string_literal.parseAlloc(allocator, body[token.loc.start..token.loc.end]) catch
                return error.DependencyUnavailable;
            selected = selected or std.mem.eql(u8, value, input.file.path);
        }
        if (!selected) return error.DependencyUnavailable;
    }
}

fn validateSelection(allocator: std.mem.Allocator, io: std.Io, inputs: Inputs, step: Step) !void {
    const root_build = try inputs.repository.read(allocator, io, "build.zig", 1024 * 1024, .source);
    if (step == .build) try requireNativeProof(allocator, root_build, inputs.observed_source, inputs.native_proof);
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
    const facade = try inputs.repository.read(allocator, io, execution.facade.path, 1024 * 1024, .source);
    const environment_body = try functionBody(allocator, facade, "controlledMakeEnvironment");
    // The current facade restores passwd HOME and discards Git/Bison/cache
    // isolation. A reviewed PATH cannot repair that or its absolute shell use.
    if (std.mem.indexOf(u8, environment_body, "canonical_home") != null) return error.DependencyUnavailable;
    try fs.requireFile(try inputs.repository.record(allocator, io, execution.facade.path, 1024 * 1024, .source), execution.facade);
    if (!std.mem.eql(u8, execution.makefile.path, "Makefile")) return error.DependencyUnavailable;
    const makefile = try inputs.repository.read(allocator, io, "Makefile", 1024 * 1024, .source);
    // The present Makefile selects an ambient shell and restores umask 0022,
    // making C Kconfig's replacement configuration non-private. Neither is
    // repaired by just forwarding more facade environment variables.
    if (std.mem.indexOf(u8, makefile, "/bin/bash") != null or
        std.mem.indexOf(u8, makefile, "UMASK = 0022") != null) return error.DependencyUnavailable;
    try fs.requireFile(try inputs.repository.record(allocator, io, "Makefile", 1024 * 1024, .source), execution.makefile);
    try commandPath(execution.make_default_shell);
    if (!std.mem.eql(u8, execution.make_default_shell, try executablePath(allocator, try nativeTool(inputs.tools, .sh))))
        return error.UnreviewedInput;
    try nativeSourceFile(execution.git_entry_source);
    if (!std.mem.startsWith(u8, execution.git_entry_source.path, "support/build/") and
        !std.mem.startsWith(u8, execution.git_entry_source.path, "support/tools/hyperv/preparation/"))
        return error.DependencyUnavailable;
    try fs.requireFile(try inputs.repository.record(allocator, io, execution.git_entry_source.path, 1024 * 1024, .source), execution.git_entry_source);
    if (step == .build) {
        for (inputs.native_proof.?.inputs) |input|
            try fs.requireFile(try inputs.repository.record(allocator, io, input.file.path, 1024 * 1024, .source), input.file);
    }
}

fn environment(allocator: std.mem.Allocator, inputs: Inputs) !std.process.Environ.Map {
    var result = try (runtime.Environment{
        .scratch = inputs.workspace.scratch.path,
        .path = inputs.tools.path.path,
        .bison_data = inputs.tools.bison_data.directory.path,
        .m4 = try executablePath(allocator, try nativeTool(inputs.tools, .m4)),
    }).create(allocator);
    const trust = try std.fs.path.join(allocator, &.{ inputs.tools.trust.directory.path, inputs.tools.trust_bundle.path });
    try commandPath(trust);
    try result.put("SSL_CERT_FILE", trust);
    try result.put("SSL_CERT_DIR", inputs.tools.trust.directory.path);
    try result.put("GIT_SSL_CAINFO", trust);
    try result.put("GIT_SSL_CAPATH", inputs.tools.trust.directory.path);
    try result.put("BASH", try executablePath(allocator, try nativeTool(inputs.tools, .bash)));
    try result.put("SHELL", try executablePath(allocator, try nativeTool(inputs.tools, .sh)));
    try result.put("CONFIG_SHELL", try executablePath(allocator, try nativeTool(inputs.tools, .sh)));
    return result;
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
    return result;
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
    const command = plan(scratch, step, commandPaths(scratch, inputs) catch |err|
        return admissionFailure(allocator, step, err)) catch |err| return admissionFailure(allocator, step, err);
    const zig = nativeTool(inputs.tools, .zig) catch |err| return admissionFailure(allocator, step, err);
    const prefix = zig.prefix(scratch) catch |err| return admissionFailure(allocator, step, err);
    if (prefix.items.len != 1 or !std.mem.eql(u8, prefix.items[0], command.argv[0]))
        return admissionFailure(allocator, step, error.DependencyUnavailable);
    var controlled = environment(scratch, inputs) catch |err| return admissionFailure(allocator, step, err);
    defer controlled.deinit();
    process.initialize() catch |err| return supervisorFailure(allocator, step, err);
    const previous_mask = std.os.linux.syscall1(.umask, 0o077);
    defer _ = std.os.linux.syscall1(.umask, previous_mask);
    var outcome: Outcome = .{
        .step = step,
        .child = process.run(allocator, io, .{
            .argv = command.argv,
            .environment = &controlled,
            .cwd = inputs.repository.dir,
            .deadline = deadline,
            .stdout_limit = if (step == .inspect) inspection_limit else 64 * 1024,
            .stderr_limit = 1024 * 1024,
        }) catch |err| return supervisorFailure(allocator, step, err),
    };
    postflight(scratch, io, step, inputs, expected) catch |err| {
        if (outcome.child.failures.primary == null) outcome.child.failures.primary = c.failure(err).primary;
        std.crypto.secureZero(u8, outcome.child.storage);
        outcome.child.stdout = &.{};
    };
    return outcome;
}

fn preflight(allocator: std.mem.Allocator, io: std.Io, step: Step, inputs: Inputs, expected: Expected) !void {
    // This veto precedes even a Git/loader subprocess.
    try validateSelection(allocator, io, inputs, step);
    try source.require(inputs.observed_source, expected.source);
    _ = try c.sha(&expected.binding_sha256);
    if (!std.crypto.timing_safe.eql(c.Sha, expected.binding_sha256, try bindingDigest(allocator, try describe(allocator, inputs))))
        return error.UnreviewedInput;
    try validateWorkspace(allocator, io, inputs, false, step);
    try validateTools(allocator, io, inputs);
}

fn postflight(allocator: std.mem.Allocator, io: std.Io, step: Step, inputs: Inputs, expected: Expected) !void {
    try validateWorkspace(allocator, io, inputs, true, step);
    try validateTools(allocator, io, inputs);
    try validateSelection(allocator, io, inputs, step);
    // describe uses the original config contract; only configure may change its
    // contents. Directory identity excludes mtime/ctime of mutable work areas.
    if (!std.crypto.timing_safe.eql(c.Sha, expected.binding_sha256, try bindingDigest(allocator, try describe(allocator, inputs))))
        return error.SourceChanged;
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
    // Only a parser fixture: these strings are not existing approved drivers.
    const root =
        \\fn finishNativeImages() void {
        \\    _ = "support/build/fixture-smp.zig";
        \\    _ = "support/build/fixture-irq.zig";
        \\    _ = "support/build/fixture-drivers.zig";
        \\}
    ;
    const fixture_source: c.Source = .{
        .scheme = .git_physical_native_v1,
        .head = "1111111111111111111111111111111111111111",
        .tree = "2222222222222222222222222222222222222222",
        .tree_sha256 = c.digest("synthetic proof-selection source"),
        .physical = .{ .sha256 = c.digest("synthetic physical tree"), .files = 4, .bytes = 1000 },
    };
    var proof: NativeProof = .{
        .schema = .hyperv_native_elf_proofs_v1,
        .source_sha256 = fixture_source.tree_sha256,
        .root_build = .{ .path = "build.zig", .sha256 = c.digest(root), .size = root.len, .mode = 0o644 },
        .inputs = undefined,
    };
    for ([_]ProofKind{ .smp, .irq, .drivers }, [_][]const u8{
        "support/build/fixture-smp.zig", "support/build/fixture-irq.zig", "support/build/fixture-drivers.zig",
    }, &proof.inputs) |kind, path, *input| input.* = .{
        .kind = kind,
        .file = .{ .path = path, .sha256 = c.digest("synthetic proof input"), .size = 1, .mode = 0o644 },
    };
    try requireNativeProof(allocator, root, fixture_source, proof);
    var changed = proof;
    changed.source_sha256 = c.digest("different source");
    try std.testing.expectError(error.UnreviewedInput, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.root_build.sha256 = c.digest("different root");
    try std.testing.expectError(error.UnreviewedInput, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.inputs[1].kind = .smp;
    try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.inputs[1].file.path = "elsewhere/fixture-irq.zig";
    try std.testing.expectError(error.DependencyUnavailable, requireNativeProof(allocator, root, fixture_source, changed));
    changed = proof;
    changed.inputs[1].file.path = "support/build/not-selected.zig";
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
