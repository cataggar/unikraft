// SPDX-License-Identifier: BSD-3-Clause
//! Canonical, bounded Azure CLI Python/module closure verification.
const std = @import("std");
const core = @import("hyperv_core");
const files = core.private_files;
const linux = std.os.linux;

pub const max_files: u32 = 16_384;
pub const max_directories: u32 = 4_096;
pub const max_bytes: u64 = 2 * 1024 * 1024 * 1024;
pub const max_depth: u8 = 32;
pub const max_file_bytes: u64 = 256 * 1024 * 1024;
pub const max_loader_files: u16 = 256;
pub const max_manifest_bytes: u64 = 32 * 1024 * 1024;
const max_parent_directories: usize = max_depth + 2;

pub const Artifact = struct {
    path: []const u8,
    size: u64,
    sha256: []const u8,
};

pub const Limits = struct {
    files: u32,
    directories: u32,
    bytes: u64,
    depth: u8,
    file_bytes: u64,
    loader_files: u16,
};

pub const Observed = struct {
    files: u32,
    directories: u32,
    bytes: u64,
    depth: u8,
    loader_files: u16,
};

pub const Isolation = struct {
    python_home: enum { closure_root },
    module_layout: enum { flat_python_home_v1 },
    extensions: enum { closure_empty },
    dynamic_extension_install: enum { disabled },
    user_site: enum { disabled },
    site_import: enum { disabled },
    bytecode_writes: enum { disabled },
    path_environment: enum { forbidden },
    startup_hooks: enum { forbidden },
    loader_environment: enum { retained_readonly_root },
    host_loader_fallback: enum { forbidden },
    package_restore: enum { forbidden_after_custody },
};

pub const commands = [_][]const []const u8{
    &.{"version"},
    &.{ "group", "exists" },
    &.{ "group", "create" },
    &.{ "group", "show" },
    &.{ "group", "delete" },
    &.{ "disk", "create" },
    &.{ "disk", "show" },
    &.{ "disk", "grant-access" },
    &.{ "disk", "revoke-access" },
    &.{ "deployment", "group", "create" },
    &.{ "vm", "deallocate" },
    &.{ "vm", "start" },
    &.{ "vm", "show" },
    &.{ "vm", "get-instance-view" },
    &.{ "vm", "boot-diagnostics", "get-boot-log" },
    &.{ "resource", "list" },
};

pub const Contract = struct {
    schema: []const u8,
    version: u8,
    canonicalization: []const u8,
    root: []const u8,
    python_version: []const u8,
    extensions: []const u8,
    launcher: Artifact,
    interpreter: Artifact,
    dynamic_loader: Artifact,
    manifest: Artifact,
    limits: Limits,
    observed: Observed,
    content_sha256: []const u8,
    metadata_sha256: []const u8,
    parents_sha256: []const u8,
    loader_dependencies: []Artifact,
    commands: []const []const []const u8,
    isolation: Isolation,

    pub fn validate(self: Contract) !void {
        if (!std.mem.eql(u8, self.schema, "uk.wamr.azure-cli-runtime-closure") or
            self.version != 1 or
            !std.mem.eql(u8, self.canonicalization, "utf8-byte-sorted-keys-compact-lf-v1") or
            !pythonVersion(self.python_version))
            return error.InvalidAzureRuntime;
        try files.absoluteFilePath(self.root);
        if (pathDepth(self.root) > max_depth) return error.InvalidAzureRuntime;
        try files.absoluteFilePath(self.extensions);
        try artifact(self.launcher);
        try artifact(self.interpreter);
        try artifact(self.dynamic_loader);
        try artifact(self.manifest);
        if (!exactChild(self.root, self.launcher.path, "/bootstrap/azure-cli") or
            !exactChild(self.root, self.interpreter.path, "/bin/python") or
            !loaderChild(self.root, self.dynamic_loader.path) or
            !exactChild(self.root, self.extensions, "/extensions") or
            !exactManifest(self.root, self.manifest.path) or
            self.launcher.size > max_file_bytes or
            self.interpreter.size > max_file_bytes or
            self.dynamic_loader.size > max_file_bytes or
            self.manifest.size > max_manifest_bytes)
            return error.InvalidAzureRuntime;
        if (!std.meta.eql(self.limits, Limits{
            .files = max_files,
            .directories = max_directories,
            .bytes = max_bytes,
            .depth = max_depth,
            .file_bytes = max_file_bytes,
            .loader_files = max_loader_files,
        })) return error.InvalidAzureRuntime;
        if (self.observed.files == 0 or self.observed.files > self.limits.files or
            self.observed.directories == 0 or self.observed.directories > self.limits.directories or
            self.observed.bytes == 0 or self.observed.bytes > self.limits.bytes or
            self.observed.depth > self.limits.depth or
            self.observed.loader_files != self.loader_dependencies.len or
            self.observed.loader_files > self.limits.loader_files)
            return error.InvalidAzureRuntime;
        _ = try core.contracts.parseSha256(self.content_sha256);
        _ = try core.contracts.parseSha256(self.metadata_sha256);
        _ = try core.contracts.parseSha256(self.parents_sha256);
        var previous: ?[]const u8 = null;
        var loader_found = false;
        for (self.loader_dependencies) |dependency| {
            try artifact(dependency);
            if (!loaderChild(self.root, dependency.path) or
                dependency.size > self.limits.file_bytes or
                (previous != null and std.mem.order(u8, previous.?, dependency.path) != .lt))
                return error.InvalidAzureRuntime;
            if (sameArtifact(dependency, self.dynamic_loader))
                loader_found = true;
            previous = dependency.path;
        }
        if (!loader_found or self.commands.len != commands.len)
            return error.InvalidAzureRuntime;
        for (self.commands, commands) |actual, expected| {
            if (actual.len != expected.len) return error.InvalidAzureRuntime;
            for (actual, expected) |actual_part, expected_part|
                if (!std.mem.eql(u8, actual_part, expected_part))
                    return error.InvalidAzureRuntime;
        }
        if (self.isolation.python_home != .closure_root or
            self.isolation.module_layout != .flat_python_home_v1 or
            self.isolation.extensions != .closure_empty or
            self.isolation.dynamic_extension_install != .disabled or
            self.isolation.user_site != .disabled or
            self.isolation.site_import != .disabled or
            self.isolation.bytecode_writes != .disabled or
            self.isolation.path_environment != .forbidden or
            self.isolation.startup_hooks != .forbidden or
            self.isolation.loader_environment != .retained_readonly_root or
            self.isolation.host_loader_fallback != .forbidden or
            self.isolation.package_restore != .forbidden_after_custody)
            return error.InvalidAzureRuntime;
    }
};

pub const Parsed = struct {
    bytes: core.sensitive.Buffer,
    value: std.json.Parsed(Contract),

    pub fn deinit(self: *Parsed) void {
        self.value.deinit();
        self.bytes.deinit();
        self.* = undefined;
    }
};

pub fn ensureNamespace(init: std.process.Init) !void {
    if (init.environ_map.get(files.namespace_marker)) |marker| {
        if (!std.mem.eql(u8, marker, files.namespace_controller))
            return error.AzureRuntimeNamespaceMarkerInvalid;
        files.enterUserNamespaceFromEnvironment(init.io, init.environ_map) catch
            return error.AzureRuntimeNamespaceMarkerInvalid;
        return;
    }
    files.verifyInitialNamespace(init.io) catch
        return error.AzureRuntimeNamespaceUnavailable;
    const allocator = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(allocator);
    const argv = try allocator.allocSentinel(
        ?[*:0]const u8,
        arguments.len,
        null,
    );
    for (arguments, 0..) |argument, index|
        argv[index] = (try allocator.dupeZ(u8, argument)).ptr;

    var environment = std.process.Environ.Map.init(allocator);
    var entries = init.environ_map.iterator();
    while (entries.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, files.namespace_marker)) continue;
        if (std.mem.eql(u8, entry.key_ptr.*, files.namespace_uid)) continue;
        if (std.mem.eql(u8, entry.key_ptr.*, files.namespace_gid)) continue;
        if (std.mem.eql(u8, entry.key_ptr.*, files.namespace_parent)) continue;
        try environment.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    try environment.put(files.namespace_marker, files.namespace_controller);
    const uid = linux.geteuid();
    const gid = linux.getegid();
    var uid_value_buffer: [32]u8 = undefined;
    try environment.put(
        files.namespace_uid,
        try std.fmt.bufPrint(&uid_value_buffer, "{d}", .{uid}),
    );
    var gid_value_buffer: [32]u8 = undefined;
    try environment.put(
        files.namespace_gid,
        try std.fmt.bufPrint(&gid_value_buffer, "{d}", .{gid}),
    );
    var parent_value_buffer: [32]u8 = undefined;
    try environment.put(
        files.namespace_parent,
        try std.fmt.bufPrint(
            &parent_value_buffer,
            "{d}",
            .{linux.getpid()},
        ),
    );
    const block = try environment.createPosixBlock(
        allocator,
        .{ .zig_progress_fd = -1 },
    );
    var uid_buffer: [64]u8 = undefined;
    const uid_map = try std.fmt.bufPrint(
        &uid_buffer,
        "{d} {d} 1\n",
        .{ 0, uid },
    );
    var gid_buffer: [64]u8 = undefined;
    const gid_map = try std.fmt.bufPrint(
        &gid_buffer,
        "{d} {d} 1\n",
        .{ 0, gid },
    );

    var report: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&report, .{ .CLOEXEC = true })) != .SUCCESS)
        return error.AzureRuntimeNamespaceReportUnavailable;
    // A report descriptor overlapping stdio would be closed by the child's own
    // exec, discarding the very diagnostic the pipe exists to carry.
    if (report[0] < 3 or report[1] < 3) {
        _ = linux.close(report[0]);
        _ = linux.close(report[1]);
        return error.AzureRuntimeNamespaceReportUnavailable;
    }

    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) {
        _ = linux.close(report[0]);
        _ = linux.close(report[1]);
        return error.AzureRuntimeNamespaceForkFailed;
    }
    if (forked == 0) {
        _ = linux.close(report[0]);
        if (childNamespace(uid_map, gid_map)) |stage| childRefusal(report[1], stage);
        _ = linux.execve("/proc/self/exe", argv.ptr, block.slice.ptr);
        childRefusal(report[1], .reexec);
    }
    _ = linux.close(report[1]);
    const observed = readNamespaceReport(report[0]);
    _ = linux.close(report[0]);
    const status = try waitNamespaceChild(@intCast(forked));
    switch (observed) {
        .reexecuted => std.process.exit(status),
        .refused => |stage| {
            reportHostRestriction(init.io, stage);
            return stage.refusal();
        },
        .lost => return error.AzureRuntimeNamespaceReportLost,
    }
}

/// Every step the forked controller performs before re-executing inside its
/// own user namespace. A hardened host denies exactly one of them, so the
/// child names the step instead of exiting without any diagnostic at all.
pub const NamespaceStage = enum(u8) {
    user_namespace = 1,
    setgroups_control = 2,
    uid_map = 3,
    gid_map = 4,
    mapped_identity = 5,
    mount_namespace = 6,
    reexec = 7,

    /// Whether the host's unprivileged user namespace policy governs the step.
    pub fn hostGoverned(self: NamespaceStage) bool {
        return switch (self) {
            .user_namespace,
            .setgroups_control,
            .uid_map,
            .gid_map,
            .mapped_identity,
            => true,
            .mount_namespace, .reexec => false,
        };
    }

    pub fn refusal(self: NamespaceStage) NamespaceRefusal {
        return switch (self) {
            .user_namespace => error.AzureRuntimeNamespaceUserDenied,
            .setgroups_control => error.AzureRuntimeNamespaceSetgroupsDenied,
            .uid_map => error.AzureRuntimeNamespaceUidMapDenied,
            .gid_map => error.AzureRuntimeNamespaceGidMapDenied,
            .mapped_identity => error.AzureRuntimeNamespaceIdentityDenied,
            .mount_namespace => error.AzureRuntimeNamespaceMountDenied,
            .reexec => error.AzureRuntimeNamespaceReexecDenied,
        };
    }

    pub fn fromCode(code: u8) ?NamespaceStage {
        inline for (@typeInfo(NamespaceStage).@"enum".fields) |field|
            if (field.value == code) return @field(NamespaceStage, field.name);
        return null;
    }
};

pub const NamespaceRefusal = error{
    AzureRuntimeNamespaceUserDenied,
    AzureRuntimeNamespaceSetgroupsDenied,
    AzureRuntimeNamespaceUidMapDenied,
    AzureRuntimeNamespaceGidMapDenied,
    AzureRuntimeNamespaceIdentityDenied,
    AzureRuntimeNamespaceMountDenied,
    AzureRuntimeNamespaceReexecDenied,
};

/// What the close-on-exec report pipe observed for the forked controller.
pub const NamespaceReport = union(enum) {
    /// The write end closed without a code: the child reached its re-exec.
    reexecuted,
    refused: NamespaceStage,
    /// The report was unreadable or carried a code no stage claims.
    lost,
};

pub fn readNamespaceReport(descriptor: linux.fd_t) NamespaceReport {
    var byte: [1]u8 = undefined;
    while (true) {
        const count = linux.read(descriptor, &byte, byte.len);
        switch (linux.errno(count)) {
            .SUCCESS => {
                if (count == 0) return .reexecuted;
                return if (NamespaceStage.fromCode(byte[0])) |stage|
                    .{ .refused = stage }
                else
                    .lost;
            },
            .INTR => continue,
            else => return .lost,
        }
    }
}

fn childRefusal(descriptor: linux.fd_t, stage: NamespaceStage) noreturn {
    const marker = [_]u8{@intFromEnum(stage)};
    _ = linux.write(descriptor, &marker, marker.len);
    linux.exit_group(126);
}

fn waitNamespaceChild(pid: linux.pid_t) !u8 {
    while (true) {
        var status: u32 = 0;
        const waited = linux.waitpid(pid, &status, 0);
        switch (linux.errno(waited)) {
            .SUCCESS => {
                if (linux.W.IFEXITED(status)) return linux.W.EXITSTATUS(status);
                if (linux.W.IFSIGNALED(status)) return @intCast(@min(
                    255,
                    128 + @intFromEnum(linux.W.TERMSIG(status)),
                ));
                return 1;
            },
            .INTR => continue,
            else => return error.AzureRuntimeNamespaceWaitFailed,
        }
    }
}

pub const userns_restriction_path =
    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// The refused stage alone cannot distinguish a broken host from a deliberately
/// hardened one, so name the policy that withheld the namespace.
fn reportHostRestriction(io: std.Io, stage: NamespaceStage) void {
    if (!stage.hostGoverned()) return;
    var buffer: [16]u8 = undefined;
    const restriction = hostUserNamespaceRestriction(&buffer) orelse return;
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.print(
        "azure runtime namespace withheld by host policy: {s}={s}\n",
        .{ userns_restriction_path, restriction },
    ) catch {};
}

/// The host's unprivileged user namespace restriction, when it both exposes one
/// and has it enabled. Only decimal values are reported, never raw file bytes.
fn hostUserNamespaceRestriction(buffer: []u8) ?[]const u8 {
    const opened = linux.openat(linux.AT.FDCWD, userns_restriction_path, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return null;
    const descriptor: linux.fd_t = @intCast(opened);
    defer _ = linux.close(descriptor);
    const count = linux.read(descriptor, buffer.ptr, buffer.len);
    if (linux.errno(count) != .SUCCESS) return null;
    const value = std.mem.trim(u8, buffer[0..count], " \t\r\n");
    if (value.len == 0 or std.mem.eql(u8, value, "0")) return null;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return null;
    return value;
}

fn childNamespace(uid_map: []const u8, gid_map: []const u8) ?NamespaceStage {
    if (linux.errno(linux.unshare(linux.CLONE.NEWUSER)) != .SUCCESS)
        return .user_namespace;
    writeMap("/proc/self/setgroups", "deny\n") catch return .setgroups_control;
    writeMap("/proc/self/uid_map", uid_map) catch return .uid_map;
    writeMap("/proc/self/gid_map", gid_map) catch return .gid_map;
    if (linux.geteuid() != 0 or linux.getegid() != 0)
        return .mapped_identity;
    if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS or
        linux.errno(linux.mount(
            null,
            "/",
            null,
            linux.MS.REC | linux.MS.PRIVATE,
            0,
        )) != .SUCCESS)
        return .mount_namespace;
    return null;
}

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !Parsed {
    var bytes = files.readSensitiveAbsolute(
        io,
        allocator,
        path,
        64 * 1024,
        null,
    ) catch return error.AzureRuntimeDocumentUnavailable;
    errdefer bytes.deinit();
    const document = try core.contracts.Document.parse(allocator, bytes.bytes(), .{
        .bytes = 64 * 1024,
        .items = 4096,
    });
    defer document.deinit();
    try document.requireCanonical(allocator, bytes.bytes());
    const parsed = try std.json.parseFromValue(
        Contract,
        allocator,
        document.value(),
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    );
    errdefer parsed.deinit();
    try parsed.value.validate();
    return .{ .bytes = bytes, .value = parsed };
}

pub fn equal(a: Contract, b: Contract) bool {
    if (!std.mem.eql(u8, a.schema, b.schema) or
        a.version != b.version or
        !std.mem.eql(u8, a.canonicalization, b.canonicalization) or
        !std.mem.eql(u8, a.root, b.root) or
        !std.mem.eql(u8, a.python_version, b.python_version) or
        !std.mem.eql(u8, a.extensions, b.extensions) or
        !sameArtifact(a.launcher, b.launcher) or
        !sameArtifact(a.interpreter, b.interpreter) or
        !sameArtifact(a.dynamic_loader, b.dynamic_loader) or
        !sameArtifact(a.manifest, b.manifest) or
        !std.meta.eql(a.limits, b.limits) or
        !std.meta.eql(a.observed, b.observed) or
        !std.mem.eql(u8, a.content_sha256, b.content_sha256) or
        !std.mem.eql(u8, a.metadata_sha256, b.metadata_sha256) or
        !std.mem.eql(u8, a.parents_sha256, b.parents_sha256) or
        !std.meta.eql(a.isolation, b.isolation) or
        a.loader_dependencies.len != b.loader_dependencies.len or
        a.commands.len != b.commands.len)
        return false;
    for (a.loader_dependencies, b.loader_dependencies) |left, right|
        if (!sameArtifact(left, right)) return false;
    for (a.commands, b.commands) |left, right| {
        if (left.len != right.len) return false;
        for (left, right) |left_part, right_part|
            if (!std.mem.eql(u8, left_part, right_part)) return false;
    }
    return true;
}

pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    contract: Contract,
) !void {
    try contract.validate();
    const root = try openDirectoryAbsolute(io, contract.root);
    defer root.close(io);
    try verifyRoot(allocator, io, root, contract, true);
    const parent_result = try parentDigest(allocator, io, contract);
    const parent_hex = std.fmt.bytesToHex(parent_result, .lower);
    if (!std.mem.eql(u8, &parent_hex, contract.parents_sha256))
        return error.AzureRuntimeChanged;
}

const ParentCustody = struct {
    directory: std.Io.Dir,
    snapshot: files.Snapshot,
};

pub const Sealed = struct {
    source: std.Io.Dir,
    source_snapshot: files.Snapshot,
    parents: [max_parent_directories]ParentCustody,
    parent_count: usize,
    root: std.Io.Dir,
    root_snapshot: files.Snapshot,
    loader: core.process.Executable,

    pub fn close(self: Sealed, io: std.Io) void {
        self.loader.close(io);
        self.root.close(io);
        for (self.parents[0..self.parent_count]) |parent|
            parent.directory.close(io);
        self.source.close(io);
    }

    pub fn verify(
        self: Sealed,
        allocator: std.mem.Allocator,
        io: std.Io,
        contract: Contract,
    ) !void {
        if (!files.sameSnapshot(self.source_snapshot, try files.snapshot(.{
            .handle = self.source.handle,
            .flags = .{ .nonblocking = false },
        }))) return error.AzureRuntimeChanged;
        try verifyRoot(allocator, io, self.source, contract, true);
        for (self.parents[0..self.parent_count]) |parent|
            if (!sameParentIdentity(parent.snapshot, try files.snapshot(.{
                .handle = parent.directory.handle,
                .flags = .{ .nonblocking = false },
            }))) return error.AzureRuntimeChanged;
        if (!files.sameSnapshot(self.root_snapshot, try files.snapshot(.{
            .handle = self.root.handle,
            .flags = .{ .nonblocking = false },
        }))) return error.AzureRuntimeChanged;
        try verifyRoot(allocator, io, self.root, contract, false);
    }
};

pub fn seal(
    allocator: std.mem.Allocator,
    io: std.Io,
    contract: Contract,
) !Sealed {
    contract.validate() catch return error.AzureRuntimeSealContract;
    const source = openDirectoryAbsolute(io, contract.root) catch
        return error.AzureRuntimeSealSource;
    errdefer source.close(io);
    const source_snapshot = try files.snapshot(.{
        .handle = source.handle,
        .flags = .{ .nonblocking = false },
    });
    verifyRoot(allocator, io, source, contract, true) catch
        return error.AzureRuntimeSealSourceContent;
    var parents: [max_parent_directories]ParentCustody = undefined;
    const parent_count = retainParents(
        allocator,
        io,
        contract,
        &parents,
    ) catch
        return error.AzureRuntimeSealParents;
    errdefer for (parents[0..parent_count]) |parent|
        parent.directory.close(io);

    const root_path = try allocator.dupeZ(u8, contract.root);
    defer allocator.free(root_path);
    var options_buffer: [160]u8 = undefined;
    const mount_bytes = try std.math.add(
        u64,
        contract.observed.bytes,
        64 * 1024 * 1024,
    );
    const inode_count = try std.math.add(
        u64,
        @as(u64, contract.observed.files) + contract.observed.directories,
        1024,
    );
    const options = try std.fmt.bufPrintZ(
        &options_buffer,
        "mode=0700,size={d},nr_inodes={d}",
        .{ mount_bytes, inode_count },
    );
    if (linux.errno(linux.mount(
        "tmpfs",
        root_path,
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(options.ptr),
    )) != .SUCCESS) return error.AzureRuntimeMountCreateUnavailable;

    const destination = openDirectoryAbsolute(io, contract.root) catch
        return error.AzureRuntimeSealDestination;
    errdefer destination.close(io);
    var counts: Counts = .{ .directories = 1 };
    copyTree(io, source, destination, 0, contract.limits, &counts) catch
        return error.AzureRuntimeSealCopy;
    if (counts.files != contract.observed.files or
        counts.directories != contract.observed.directories or
        counts.bytes != contract.observed.bytes or
        counts.depth != contract.observed.depth)
        return error.AzureRuntimeChanged;
    if (linux.errno(linux.fchmod(
        destination.handle,
        @intCast(sourceMode(source) & 0o777),
    )) != .SUCCESS or
        linux.errno(linux.fsync(destination.handle)) != .SUCCESS)
        return error.AzureRuntimeCopyFailed;
    verifyRoot(allocator, io, destination, contract, false) catch
        return error.AzureRuntimeSealDestinationContent;
    readonlyMount(destination.handle) catch
        return error.AzureRuntimeMountReadonlyUnavailable;
    rejectSystemLoaderPreload() catch
        return error.AzureRuntimeLoaderIsolationUnavailable;
    maskHostLoaderDirectories() catch
        return error.AzureRuntimeLoaderIsolationUnavailable;
    try dropNamespaceAuthority();

    const loader_relative = contract.dynamic_loader.path[contract.root.len + 1 ..];
    const loader_file = destination.openFile(io, loader_relative, .{
        .follow_symlinks = false,
    }) catch return error.AzureRuntimeSealLoader;
    defer loader_file.close(io);
    const loader = core.process.Executable.fromFile(io, loader_file) catch
        return error.AzureRuntimeSealLoaderExecutable;
    errdefer loader.close(io);
    const root_snapshot = try files.snapshot(.{
        .handle = destination.handle,
        .flags = .{ .nonblocking = false },
    });
    const result: Sealed = .{
        .source = source,
        .source_snapshot = source_snapshot,
        .parents = parents,
        .parent_count = parent_count,
        .root = destination,
        .root_snapshot = root_snapshot,
        .loader = loader,
    };
    try result.verify(allocator, io, contract);
    return result;
}

fn sourceMode(directory: std.Io.Dir) u32 {
    return (files.snapshot(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    }) catch return 0).mode;
}

fn copyTree(
    io: std.Io,
    source: std.Io.Dir,
    destination: std.Io.Dir,
    depth: u8,
    limits: Limits,
    counts: *Counts,
) !void {
    const before = try files.snapshot(.{
        .handle = source.handle,
        .flags = .{ .nonblocking = false },
    });
    try validateDirectory(before);
    var iterator = source.iterate();
    var buffer: [64 * 1024]u8 = undefined;
    while (try iterator.next(io)) |item| {
        try files.basename(item.name);
        const held = try source.openFile(io, item.name, .{
            .path_only = true,
            .follow_symlinks = false,
        });
        defer held.close(io);
        const snapshot = try files.snapshot(held);
        switch (snapshot.mode & linux.S.IFMT) {
            linux.S.IFDIR => {
                try validateDirectory(snapshot);
                if (counts.directories >= limits.directories or
                    depth >= limits.depth)
                    return error.AzureRuntimeLimit;
                counts.directories += 1;
                counts.depth = @max(counts.depth, depth + 1);
                try destination.createDir(
                    io,
                    item.name,
                    .fromMode(0o700),
                );
                const source_child = try source.openDir(io, item.name, .{
                    .follow_symlinks = false,
                    .iterate = true,
                });
                defer source_child.close(io);
                const destination_child = try destination.openDir(
                    io,
                    item.name,
                    .{ .follow_symlinks = false, .iterate = true },
                );
                defer destination_child.close(io);
                if (!files.sameSnapshot(snapshot, try files.snapshot(.{
                    .handle = source_child.handle,
                    .flags = .{ .nonblocking = false },
                }))) return error.AzureRuntimeChanged;
                try copyTree(
                    io,
                    source_child,
                    destination_child,
                    depth + 1,
                    limits,
                    counts,
                );
                if (linux.errno(linux.fchmod(
                    destination_child.handle,
                    @intCast(snapshot.mode & 0o777),
                )) != .SUCCESS or
                    linux.errno(linux.fsync(destination_child.handle)) != .SUCCESS)
                    return error.AzureRuntimeCopyFailed;
            },
            linux.S.IFREG => {
                try validateFile(snapshot, limits.file_bytes);
                if (counts.files >= limits.files or
                    snapshot.size > limits.bytes -| counts.bytes)
                    return error.AzureRuntimeLimit;
                counts.files += 1;
                counts.bytes += snapshot.size;
                const source_file = try source.openFile(io, item.name, .{
                    .follow_symlinks = false,
                });
                defer source_file.close(io);
                if (!files.sameSnapshot(snapshot, try files.snapshot(source_file)))
                    return error.AzureRuntimeChanged;
                const destination_file = try destination.createFile(
                    io,
                    item.name,
                    .{
                        .read = true,
                        .exclusive = true,
                        .permissions = .fromMode(0o600),
                    },
                );
                defer destination_file.close(io);
                var offset: u64 = 0;
                while (offset < snapshot.size) {
                    const amount: usize = @intCast(@min(
                        @as(u64, buffer.len),
                        snapshot.size - offset,
                    ));
                    if (try source_file.readPositionalAll(
                        io,
                        buffer[0..amount],
                        offset,
                    ) != amount) return error.AzureRuntimeChanged;
                    try destination_file.writePositionalAll(
                        io,
                        buffer[0..amount],
                        offset,
                    );
                    offset += amount;
                }
                if (try source_file.readPositionalAll(
                    io,
                    buffer[0..1],
                    snapshot.size,
                ) != 0 or
                    !files.sameSnapshot(snapshot, try files.snapshot(source_file)))
                    return error.AzureRuntimeChanged;
                try destination_file.setPermissions(
                    io,
                    .fromMode(@intCast(snapshot.mode & 0o777)),
                );
                try destination_file.sync(io);
            },
            else => return error.UnsafeAzureRuntime,
        }
        if (!files.sameSnapshot(snapshot, try files.snapshot(held)))
            return error.AzureRuntimeChanged;
    }
    if (!files.sameSnapshot(before, try files.snapshot(.{
        .handle = source.handle,
        .flags = .{ .nonblocking = false },
    }))) return error.AzureRuntimeChanged;
}

fn writeMap(path: [*:0]const u8, bytes: []const u8) !void {
    const opened = linux.openat(linux.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS)
        return error.AzureRuntimeUserNamespaceUnavailable;
    defer _ = linux.close(@intCast(opened));
    if (linux.write(@intCast(opened), bytes.ptr, bytes.len) != bytes.len)
        return error.AzureRuntimeUserNamespaceUnavailable;
}

const MountAttributes = extern struct {
    set: u64,
    clear: u64 = 0,
    propagation: u64 = 0,
    userns: u64 = 0,
};

fn readonlyMount(descriptor: linux.fd_t) !void {
    const attributes: MountAttributes = .{ .set = 1 | 2 | 4 };
    if (linux.errno(linux.syscall5(
        .mount_setattr,
        @intCast(descriptor),
        @intFromPtr(""),
        linux.AT.EMPTY_PATH,
        @intFromPtr(&attributes),
        @sizeOf(MountAttributes),
    )) != .SUCCESS) return error.AzureRuntimeMountUnavailable;
}

fn maskHostLoaderDirectories() !void {
    inline for (.{
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/local/lib64",
    }) |path| {
        const result = linux.mount(
            "tmpfs",
            path,
            "tmpfs",
            linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV |
                linux.MS.NOEXEC,
            @intFromPtr("mode=000,size=4096,nr_inodes=1"),
        );
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .NOENT, .NOTDIR => {},
            else => return error.AzureRuntimeMountUnavailable,
        }
    }
}

fn rejectSystemLoaderPreload() !void {
    try rejectLoaderPreloadPath("/etc/ld.so.preload");
}

fn rejectLoaderPreloadPath(path: [*:0]const u8) !void {
    const opened = linux.openat(linux.AT.FDCWD, path, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    switch (linux.errno(opened)) {
        .NOENT => return,
        .SUCCESS => {
            _ = linux.close(@intCast(opened));
            return error.SystemLoaderPreloadPresent;
        },
        else => return error.SystemLoaderPreloadUnavailable,
    }
}

pub const Test = struct {
    pub fn rejectLoaderPreload(path: [*:0]const u8) !void {
        try rejectLoaderPreloadPath(path);
    }
};

fn dropNamespaceAuthority() !void {
    if (linux.errno(linux.prctl(
        @intFromEnum(linux.PR.SET_NO_NEW_PRIVS),
        1,
        0,
        0,
        0,
    )) != .SUCCESS or
        linux.errno(linux.prctl(47, 4, 0, 0, 0)) != .SUCCESS)
        return error.AzureRuntimeIsolationUnavailable;
    const Header = extern struct { version: u32, pid: i32 };
    var header: Header = .{ .version = 0x20080522, .pid = 0 };
    const data = [_]linux.cap_user_data_t{
        std.mem.zeroes(linux.cap_user_data_t),
    } ** 2;
    if (linux.errno(linux.syscall2(
        .capset,
        @intFromPtr(&header),
        @intFromPtr(&data),
    )) != .SUCCESS or
        linux.errno(linux.prctl(
            @intFromEnum(linux.PR.SET_DUMPABLE),
            0,
            0,
            0,
            0,
        )) != .SUCCESS)
        return error.AzureRuntimeIsolationUnavailable;
}

fn verifyRoot(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    contract: Contract,
    verify_metadata: bool,
) !void {
    var entries: std.ArrayList(Entry) = .empty;
    defer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit(allocator);
    }
    const root_snapshot = try files.snapshot(.{
        .handle = root.handle,
        .flags = .{ .nonblocking = false },
    });
    try validateDirectory(root_snapshot);
    try entries.append(allocator, .{
        .path = try allocator.dupe(u8, "."),
        .snapshot = root_snapshot,
        .sha256 = null,
    });
    var counts: Counts = .{ .directories = 1 };
    try walk(
        allocator,
        io,
        root,
        "",
        0,
        contract.limits,
        &entries,
        &counts,
    );
    std.mem.sort(Entry, entries.items, {}, Entry.lessThan);
    _ = try requireRootArtifact(entries.items, contract.root, contract.launcher);
    _ = try requireRootArtifact(entries.items, contract.root, contract.interpreter);
    _ = try requireRootArtifact(entries.items, contract.root, contract.dynamic_loader);

    var content = core.Sha256.init(.{});
    var metadata = core.Sha256.init(.{});
    for (entries.items) |entry| {
        hashContent(&content, entry);
        hashMetadata(&metadata, "M", entry.path, entry.snapshot);
    }
    for (contract.loader_dependencies) |dependency| {
        const observed = try requireRootArtifact(
            entries.items,
            contract.root,
            dependency,
        );
        const digest = try core.contracts.parseSha256(dependency.sha256);
        hashExternalContent(&content, "L", dependency.path, observed.size, digest);
        hashMetadata(&metadata, "L", dependency.path, observed);
    }
    const manifest_observed = try inspectArtifactIdentity(
        io,
        contract.manifest,
        max_manifest_bytes,
    );
    hashExternalContent(
        &content,
        "A",
        contract.manifest.path,
        manifest_observed.size,
        try core.contracts.parseSha256(contract.manifest.sha256),
    );
    hashMetadata(&metadata, "A", contract.manifest.path, manifest_observed);
    const content_result = std.fmt.bytesToHex(content.finalResult(), .lower);
    const metadata_result = std.fmt.bytesToHex(metadata.finalResult(), .lower);
    if (!std.mem.eql(u8, &content_result, contract.content_sha256) or
        (verify_metadata and
            !std.mem.eql(u8, &metadata_result, contract.metadata_sha256)) or
        counts.files != contract.observed.files or
        counts.directories != contract.observed.directories or
        counts.bytes != contract.observed.bytes or
        counts.depth != contract.observed.depth)
        return error.AzureRuntimeChanged;
}

fn requireRootArtifact(
    entries: []const Entry,
    root: []const u8,
    item: Artifact,
) !files.Snapshot {
    if (item.path.len <= root.len + 1 or
        !std.mem.startsWith(u8, item.path, root) or
        item.path[root.len] != '/')
        return error.InvalidAzureRuntime;
    const relative = item.path[root.len + 1 ..];
    for (entries) |entry| {
        if (!std.mem.eql(u8, entry.path, relative)) continue;
        if (entry.sha256 == null or entry.snapshot.size != item.size or
            !std.crypto.timing_safe.eql(
                core.contracts.Sha256,
                entry.sha256.?,
                try core.contracts.parseSha256(item.sha256),
            ))
            return error.AzureRuntimeChanged;
        return entry.snapshot;
    }
    return error.AzureRuntimeChanged;
}

const Counts = struct {
    files: u32 = 0,
    directories: u32 = 0,
    bytes: u64 = 0,
    depth: u8 = 0,
};

fn sameParentIdentity(a: files.Snapshot, b: files.Snapshot) bool {
    return a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.ino == b.ino and a.mode == b.mode and
        a.uid == b.uid and a.gid == b.gid;
}

const Entry = struct {
    path: []u8,
    snapshot: files.Snapshot,
    sha256: ?core.contracts.Sha256,

    fn lessThan(_: void, a: Entry, b: Entry) bool {
        return std.mem.order(u8, a.path, b.path) == .lt;
    }
};

fn walk(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: std.Io.Dir,
    prefix: []const u8,
    depth: u8,
    limits: Limits,
    entries: *std.ArrayList(Entry),
    counts: *Counts,
) !void {
    const before = try files.snapshot(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    });
    try validateDirectory(before);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |item| {
        try files.basename(item.name);
        const relative = if (prefix.len == 0)
            try allocator.dupe(u8, item.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, item.name });
        errdefer allocator.free(relative);
        if (relative.len > 4095) return error.AzureRuntimeLimit;
        const path_file = try directory.openFile(io, item.name, .{
            .path_only = true,
            .follow_symlinks = false,
        });
        defer path_file.close(io);
        const snapshot = try files.snapshot(path_file);
        var digest: ?core.contracts.Sha256 = null;
        switch (snapshot.mode & linux.S.IFMT) {
            linux.S.IFDIR => {
                try validateDirectory(snapshot);
                if (counts.directories >= limits.directories or depth >= limits.depth)
                    return error.AzureRuntimeLimit;
                counts.directories += 1;
                counts.depth = @max(counts.depth, depth + 1);
                const child = try directory.openDir(io, item.name, .{
                    .follow_symlinks = false,
                    .iterate = true,
                });
                defer child.close(io);
                if (!files.sameSnapshot(snapshot, try files.snapshot(.{
                    .handle = child.handle,
                    .flags = .{ .nonblocking = false },
                }))) return error.AzureRuntimeChanged;
                try walk(
                    allocator,
                    io,
                    child,
                    relative,
                    depth + 1,
                    limits,
                    entries,
                    counts,
                );
            },
            linux.S.IFREG => {
                try validateFile(snapshot, limits.file_bytes);
                if (counts.files >= limits.files or
                    snapshot.size > limits.bytes -| counts.bytes)
                    return error.AzureRuntimeLimit;
                counts.files += 1;
                counts.bytes += snapshot.size;
                const file = try directory.openFile(io, item.name, .{
                    .follow_symlinks = false,
                });
                defer file.close(io);
                if (!files.sameSnapshot(snapshot, try files.snapshot(file)))
                    return error.AzureRuntimeChanged;
                digest = try hashFile(io, file, snapshot);
            },
            else => return error.UnsafeAzureRuntime,
        }
        if (!files.sameSnapshot(snapshot, try files.snapshot(path_file)))
            return error.AzureRuntimeChanged;
        try entries.append(allocator, .{
            .path = relative,
            .snapshot = snapshot,
            .sha256 = digest,
        });
    }
    if (!files.sameSnapshot(before, try files.snapshot(.{
        .handle = directory.handle,
        .flags = .{ .nonblocking = false },
    }))) return error.AzureRuntimeChanged;
}

fn hashFile(
    io: std.Io,
    file: std.Io.File,
    expected: files.Snapshot,
) !core.contracts.Sha256 {
    var hash = core.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < expected.size) {
        const amount: usize = @intCast(@min(@as(u64, buffer.len), expected.size - offset));
        if (try file.readPositionalAll(io, buffer[0..amount], offset) != amount)
            return error.AzureRuntimeChanged;
        hash.update(buffer[0..amount]);
        offset += amount;
    }
    if (try file.readPositionalAll(io, buffer[0..1], expected.size) != 0 or
        !files.sameSnapshot(expected, try files.snapshot(file)))
        return error.AzureRuntimeChanged;
    return hash.finalResult();
}

fn hashContent(hash: *core.Sha256, entry: Entry) void {
    var buffer: [8192]u8 = undefined;
    const kind: u8 = if (entry.sha256 == null) 'D' else 'F';
    const line = if (entry.sha256) |value| line: {
        const digest = std.fmt.bytesToHex(value, .lower);
        break :line std.fmt.bufPrint(
            &buffer,
            "C\t{c}\t{s}\t{d}\t{s}\n",
            .{ kind, entry.path, entry.snapshot.size, &digest },
        ) catch unreachable;
    } else std.fmt.bufPrint(
        &buffer,
        "C\t{c}\t{s}\t{d}\t-\n",
        .{ kind, entry.path, 0 },
    ) catch unreachable;
    hash.update(line);
}

fn hashExternalContent(
    hash: *core.Sha256,
    comptime kind: []const u8,
    path: []const u8,
    size: u64,
    digest: core.contracts.Sha256,
) void {
    var buffer: [8192]u8 = undefined;
    const encoded = std.fmt.bytesToHex(digest, .lower);
    const line = std.fmt.bufPrint(
        &buffer,
        "C\t" ++ kind ++ "\t{s}\t{d}\t{s}\n",
        .{ path, size, &encoded },
    ) catch unreachable;
    hash.update(line);
}

fn hashMetadata(
    hash: *core.Sha256,
    comptime tag: []const u8,
    path: []const u8,
    value: files.Snapshot,
) void {
    var buffer: [8192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        tag ++ "\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n",
        .{
            path,
            value.dev_major,
            value.dev_minor,
            value.ino,
            value.mode,
            files.hostUid(value.uid),
            files.hostGid(value.gid),
            value.nlink,
            value.size,
            value.mtime.sec,
            value.mtime.nsec,
            value.ctime.sec,
            value.ctime.nsec,
        },
    ) catch unreachable;
    hash.update(line);
}

fn parentDigest(
    allocator: std.mem.Allocator,
    io: std.Io,
    contract: Contract,
) !core.contracts.Sha256 {
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    try addParents(allocator, &paths, contract.root);
    for (contract.loader_dependencies) |dependency|
        try addParents(allocator, &paths, dependency.path);
    std.mem.sort([]u8, paths.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    var hash = core.Sha256.init(.{});
    var previous: ?[]const u8 = null;
    for (paths.items) |path| {
        if (previous != null and std.mem.eql(u8, previous.?, path)) continue;
        const directory = try openDirectoryAbsolute(io, path);
        defer directory.close(io);
        const observed = try files.snapshot(.{
            .handle = directory.handle,
            .flags = .{ .nonblocking = false },
        });
        try validateParentDirectory(path, observed);
        hashParent(&hash, path, observed);
        previous = path;
    }
    return hash.finalResult();
}

fn retainParents(
    allocator: std.mem.Allocator,
    io: std.Io,
    contract: Contract,
    retained: *[max_parent_directories]ParentCustody,
) !usize {
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    try addParents(allocator, &paths, contract.root);
    for (contract.loader_dependencies) |dependency|
        try addParents(allocator, &paths, dependency.path);
    std.mem.sort([]u8, paths.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    var count: usize = 0;
    errdefer for (retained[0..count]) |parent|
        parent.directory.close(io);
    var hash = core.Sha256.init(.{});
    var previous: ?[]const u8 = null;
    for (paths.items) |path| {
        if (previous != null and std.mem.eql(u8, previous.?, path)) continue;
        if (count >= retained.len) return error.AzureRuntimeLimit;
        const directory = try openDirectoryAbsolute(io, path);
        errdefer directory.close(io);
        const observed = try files.snapshot(.{
            .handle = directory.handle,
            .flags = .{ .nonblocking = false },
        });
        try validateParentDirectory(path, observed);
        hashParent(&hash, path, observed);
        retained[count] = .{
            .directory = directory,
            .snapshot = observed,
        };
        count += 1;
        previous = path;
    }
    const digest = std.fmt.bytesToHex(hash.finalResult(), .lower);
    if (!std.mem.eql(u8, &digest, contract.parents_sha256))
        return error.AzureRuntimeChanged;
    return count;
}

fn hashParent(
    hash: *core.Sha256,
    path: []const u8,
    value: files.Snapshot,
) void {
    var buffer: [8192]u8 = undefined;
    const uid = if (std.mem.eql(u8, path, "/") or
        files.isNamespaceOverflowUid(value.uid)) 0 else files.hostUid(value.uid);
    const gid = if (std.mem.eql(u8, path, "/") or
        files.isNamespaceOverflowGid(value.gid)) 0 else files.hostGid(value.gid);
    const line = std.fmt.bufPrint(
        &buffer,
        "P\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n",
        .{
            path,
            value.dev_major,
            value.dev_minor,
            value.ino,
            value.mode,
            uid,
            gid,
        },
    ) catch unreachable;
    hash.update(line);
}

fn validateParentDirectory(path: []const u8, value: files.Snapshot) !void {
    if (std.mem.eql(u8, path, "/")) {
        if (value.mode & linux.S.IFMT != linux.S.IFDIR or
            value.mode & 0o022 != 0)
            return error.UnsafeAzureRuntime;
        return;
    }
    if (files.isNamespaceOverflowUid(value.uid)) {
        if (value.mode & linux.S.IFMT != linux.S.IFDIR or
            value.mode & 0o022 != 0)
            return error.UnsafeAzureRuntime;
        return;
    }
    try validateDirectory(value);
}

fn addParents(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]u8),
    input: []const u8,
) !void {
    const parent = std.fs.path.dirname(input) orelse return error.UnsafePath;
    try paths.append(allocator, try allocator.dupe(u8, "/"));
    if (parent.len == 1) return;
    var offset: usize = 1;
    var parts = std.mem.splitScalar(u8, parent[1..], '/');
    while (parts.next()) |part| {
        offset += part.len;
        try paths.append(allocator, try allocator.dupe(u8, parent[0..offset]));
        offset += 1;
    }
}

fn inspectArtifact(
    io: std.Io,
    item: Artifact,
    maximum: u64,
) !void {
    _ = try inspectArtifactIdentity(io, item, maximum);
}

fn inspectArtifactIdentity(
    io: std.Io,
    item: Artifact,
    maximum: u64,
) !files.Snapshot {
    try artifact(item);
    if (item.size > maximum) return error.AzureRuntimeLimit;
    var retained = try files.RetainedFile.open(io, item.path, .artifact);
    defer retained.close(io);
    const before = retained.file_snapshot;
    try validateFile(before, maximum);
    if (before.size != item.size) return error.AzureRuntimeChanged;
    const digest = try hashFile(io, retained.file, before);
    if (!std.crypto.timing_safe.eql(
        core.contracts.Sha256,
        digest,
        try core.contracts.parseSha256(item.sha256),
    )) return error.AzureRuntimeChanged;
    try retained.verify(io);
    return before;
}

fn validateDirectory(value: files.Snapshot) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFDIR or
        value.uid != 0 and value.uid != linux.geteuid() or
        value.mode & 0o022 != 0)
        return error.UnsafeAzureRuntime;
}

fn openDirectoryAbsolute(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!std.mem.eql(u8, path, "/"))
        try files.absoluteFilePath(path);
    return std.Io.Dir.openDirAbsolute(io, path, .{
        .follow_symlinks = false,
        .iterate = true,
    });
}

fn validateFile(value: files.Snapshot, maximum: u64) !void {
    if (value.mode & linux.S.IFMT != linux.S.IFREG or
        (value.uid != 0 and value.uid != linux.geteuid()) or
        value.mode & 0o7022 != 0 or value.nlink != 1 or
        value.size == 0 or value.size > maximum)
        return error.UnsafeAzureRuntime;
}

fn artifact(item: Artifact) !void {
    try files.absoluteFilePath(item.path);
    if (item.size == 0) return error.InvalidAzureRuntime;
    _ = try core.contracts.parseSha256(item.sha256);
}

fn sameArtifact(a: Artifact, b: Artifact) bool {
    return std.mem.eql(u8, a.path, b.path) and
        a.size == b.size and
        std.mem.eql(u8, a.sha256, b.sha256);
}

fn exactChild(root: []const u8, path: []const u8, suffix: []const u8) bool {
    return path.len == root.len + suffix.len and
        std.mem.startsWith(u8, path, root) and
        std.mem.eql(u8, path[root.len..], suffix);
}

fn exactManifest(root: []const u8, path: []const u8) bool {
    const parent = std.fs.path.dirname(root) orelse return false;
    const name = "/azure-runtime.manifest";
    return path.len == parent.len + name.len and
        std.mem.startsWith(u8, path, parent) and
        std.mem.eql(u8, path[parent.len..], name);
}

fn pathDepth(path: []const u8) usize {
    var depth: usize = 0;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |_| depth += 1;
    return depth;
}

fn loaderChild(root: []const u8, path: []const u8) bool {
    const prefix = "/loader/";
    if (path.len <= root.len + prefix.len or
        !std.mem.startsWith(u8, path, root) or
        !std.mem.startsWith(u8, path[root.len..], prefix))
        return false;
    return std.mem.indexOfScalar(u8, path[root.len + prefix.len ..], '/') == null;
}

fn pythonVersion(value: []const u8) bool {
    if (value.len < 3 or value.len > 16) return false;
    var parts = std.mem.splitScalar(u8, value, '.');
    var count: usize = 0;
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 3) return false;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return false;
        count += 1;
    }
    return count == 2;
}
