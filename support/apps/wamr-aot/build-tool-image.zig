// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
const contract = @import("build-tool-contract.zig");
const core = @import("hyperv_core");
const paths = @import("facade_paths");
const native_make_environment = @import("native_make_environment");

pub const MakeEnvironment = native_make_environment.Contract;

const empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const maximum_identity_bytes = 4 * 1024 * 1024;
const maximum_source_bytes: u64 = 512 * 1024 * 1024;
const olddefconfig_milliseconds = 10 * 60 * 1000;
const native_images_milliseconds = 30 * 60 * 1000;
const cleanup_slack_milliseconds = 30 * 1000;
const image_names = [_][]const u8{
    "wamr_hyperv-x86_64-efi",
    "wamr_hyperv-x86_64-efi.dbg",
    "wamr_hyperv-x86_64-efi.bootinfo",
};
const manifest_tool_names = [_][]const u8{
    "zig",
    "make",
    "llvm-nm",
    "llvm-objcopy",
    "llvm-objdump",
    "llvm-readelf",
    "llvm-strip",
    "bison",
    "flex",
};

pub fn encodeMakeEnvironment(
    allocator: std.mem.Allocator,
    environment: MakeEnvironment,
) ![]u8 {
    return native_make_environment.encode(allocator, environment);
}

pub fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    inherited: *const std.process.Environ.Map,
    executable_path: []const u8,
    arguments: contract.Arguments,
) !void {
    if (arguments.command != .olddefconfig and arguments.command != .native_images)
        return error.InvalidArguments;
    var repository = try contract.files.Repository.open(
        allocator,
        io,
        arguments.repository,
    );
    defer repository.close(allocator, io);
    executeOpen(
        allocator,
        io,
        inherited,
        executable_path,
        repository,
        arguments.command,
    ) catch |err| {
        if (contract.files.ensurePrivateDirectory(
            io,
            repository.app.dir,
            "build",
        )) |build| {
            defer build.close(io);
            if (contract.files.ensurePrivateDirectory(
                io,
                build,
                "native-environment",
            )) |state| {
                defer state.close(io);
                contract.files.writePrivateAtomicReplace(
                    io,
                    state,
                    "failure-error-name.txt",
                    @errorName(err),
                ) catch {};
            } else |_| {}
        } else |_| {}
        return err;
    };
}

const Stage = enum {
    bison_data,
    root_olddefconfig,
    root_native_images,
    git_clean,
    git_revision,

    fn name(self: Stage) []const u8 {
        return switch (self) {
            .bison_data => "bison-data",
            .root_olddefconfig => "root-olddefconfig",
            .root_native_images => "root-native-images",
            .git_clean => "git-clean",
            .git_revision => "git-revision",
        };
    }
};

const Diagnostics = struct {
    directory: std.Io.Dir,
    index: usize = 0,

    fn open(io: std.Io, build: std.Io.Dir) !Diagnostics {
        const state = try contract.files.ensurePrivateDirectory(
            io,
            build,
            "native-environment",
        );
        defer state.close(io);
        const diagnostics = try contract.files.ensurePrivateDirectory(
            io,
            state,
            "diagnostics",
        );
        defer diagnostics.close(io);
        var name_buffer: [96]u8 = undefined;
        for (0..1000) |suffix| {
            const name = if (suffix == 0)
                try std.fmt.bufPrint(&name_buffer, "image-{d}", .{linux.getpid()})
            else
                try std.fmt.bufPrint(
                    &name_buffer,
                    "image-{d}-{d}",
                    .{ linux.getpid(), suffix },
                );
            const directory = contract.files.createPrivateDirectory(
                io,
                diagnostics,
                name,
            ) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            return .{ .directory = directory };
        }
        return error.DiagnosticDirectoryUnavailable;
    }

    fn close(self: *Diagnostics, io: std.Io) void {
        self.directory.close(io);
        self.* = undefined;
    }

    fn record(
        self: *Diagnostics,
        allocator: std.mem.Allocator,
        io: std.Io,
        stage: Stage,
        argv: []const []const u8,
        cwd: []const u8,
        result: contract.process.CommandResult,
    ) !void {
        var prefix_buffer: [96]u8 = undefined;
        const prefix = try std.fmt.bufPrint(
            &prefix_buffer,
            "{d:0>3}-{s}",
            .{ self.index, stage.name() },
        );
        self.index += 1;
        var stdout_name_buffer: [128]u8 = undefined;
        var stderr_name_buffer: [128]u8 = undefined;
        var result_name_buffer: [128]u8 = undefined;
        const stdout_name = try std.fmt.bufPrint(
            &stdout_name_buffer,
            "{s}.stdout",
            .{prefix},
        );
        const stderr_name = try std.fmt.bufPrint(
            &stderr_name_buffer,
            "{s}.stderr",
            .{prefix},
        );
        const result_name = try std.fmt.bufPrint(
            &result_name_buffer,
            "{s}.json",
            .{prefix},
        );
        try contract.files.writePrivateCreate(
            io,
            self.directory,
            stdout_name,
            result.stdout,
        );
        try contract.files.writePrivateCreate(
            io,
            self.directory,
            stderr_name,
            result.stderr,
        );
        const encoded = try commandResultAlloc(
            allocator,
            stage,
            argv,
            cwd,
            result,
        );
        defer allocator.free(encoded);
        try contract.files.writePrivateCreate(
            io,
            self.directory,
            result_name,
            encoded,
        );
    }

    fn recordLaunchError(
        self: *Diagnostics,
        allocator: std.mem.Allocator,
        io: std.Io,
        stage: Stage,
        err: anyerror,
    ) !void {
        var name_buffer: [128]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "{d:0>3}-{s}.launch-error.txt",
            .{ self.index, stage.name() },
        );
        self.index += 1;
        const contents = try std.fmt.allocPrint(
            allocator,
            "{s}\n",
            .{@errorName(err)},
        );
        defer allocator.free(contents);
        try contract.files.writePrivateCreate(
            io,
            self.directory,
            name,
            contents,
        );
    }
};

const Runner = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    primary_deadline: contract.process.Deadline,
    cleanup_deadline: contract.process.Deadline,
    diagnostics: *Diagnostics,

    fn run(
        self: *Runner,
        tool: contract.process.Tool,
        stage: Stage,
        argv: []const []const u8,
        environment: *const std.process.Environ.Map,
        cwd: std.Io.Dir,
        cwd_path: []const u8,
        stdout_bytes: usize,
    ) !contract.process.CommandResult {
        var result = contract.process.run(self.allocator, self.io, tool, .{
            .argv = argv,
            .environment = environment,
            .cwd = cwd,
            .primary_deadline = self.primary_deadline,
            .cleanup_deadline = self.cleanup_deadline,
            .snapshot_executable = false,
            .stdout_bytes = stdout_bytes,
        }) catch |err| {
            self.diagnostics.recordLaunchError(
                self.allocator,
                self.io,
                stage,
                err,
            ) catch return error.DiagnosticWriteFailed;
            return commandFailure(stage);
        };
        errdefer result.deinit(self.allocator);
        self.diagnostics.record(
            self.allocator,
            self.io,
            stage,
            argv,
            cwd_path,
            result,
        ) catch return error.DiagnosticWriteFailed;
        return result;
    }

    fn runSuccess(
        self: *Runner,
        tool: contract.process.Tool,
        stage: Stage,
        argv: []const []const u8,
        environment: *const std.process.Environ.Map,
        cwd: std.Io.Dir,
        cwd_path: []const u8,
        stdout_bytes: usize,
    ) !contract.process.CommandResult {
        var result = try self.run(
            tool,
            stage,
            argv,
            environment,
            cwd,
            cwd_path,
            stdout_bytes,
        );
        errdefer result.deinit(self.allocator);
        if (!result.succeeded()) return commandFailure(stage);
        return result;
    }
};

const SelectedTools = struct {
    zig: contract.process.Tool,
    make: contract.process.Tool,
    llvm_nm: contract.process.Tool,
    llvm_objcopy: contract.process.Tool,
    llvm_objdump: contract.process.Tool,
    llvm_readelf: contract.process.Tool,
    llvm_strip: contract.process.Tool,
    bison: contract.process.Tool,
    flex: contract.process.Tool,
    m4: contract.process.Tool,
    bash: contract.process.Tool,
    cp: contract.process.Tool,
    mkdir: contract.process.Tool,
    python3: contract.process.Tool,
    readlink: contract.process.Tool,

    fn resolve(
        allocator: std.mem.Allocator,
        io: std.Io,
        environment: *const std.process.Environ.Map,
        state: std.Io.Dir,
    ) !SelectedTools {
        var zig = try resolveSelectedTool(allocator, io, environment, state, "zig");
        errdefer zig.close(allocator, io);
        var make = try resolveSelectedTool(allocator, io, environment, state, "make");
        errdefer make.close(allocator, io);
        var llvm_nm = try resolveSelectedTool(allocator, io, environment, state, "llvm-nm");
        errdefer llvm_nm.close(allocator, io);
        var llvm_objcopy = try resolveSelectedTool(allocator, io, environment, state, "llvm-objcopy");
        errdefer llvm_objcopy.close(allocator, io);
        var llvm_objdump = try resolveSelectedTool(allocator, io, environment, state, "llvm-objdump");
        errdefer llvm_objdump.close(allocator, io);
        var llvm_readelf = try resolveSelectedTool(allocator, io, environment, state, "llvm-readelf");
        errdefer llvm_readelf.close(allocator, io);
        var llvm_strip = try resolveSelectedTool(allocator, io, environment, state, "llvm-strip");
        errdefer llvm_strip.close(allocator, io);
        var bison = try resolveSelectedTool(allocator, io, environment, state, "bison");
        errdefer bison.close(allocator, io);
        var flex = try resolveSelectedTool(allocator, io, environment, state, "flex");
        errdefer flex.close(allocator, io);
        var m4 = try resolveSelectedTool(allocator, io, environment, state, "m4");
        errdefer m4.close(allocator, io);
        var bash = try resolveSelectedTool(allocator, io, environment, state, "bash");
        errdefer bash.close(allocator, io);
        var cp = try resolveSelectedTool(allocator, io, environment, state, "cp");
        errdefer cp.close(allocator, io);
        var mkdir = try resolveSelectedTool(allocator, io, environment, state, "mkdir");
        errdefer mkdir.close(allocator, io);
        var python3 = try resolveSelectedTool(allocator, io, environment, state, "python3");
        errdefer python3.close(allocator, io);
        var readlink = try resolveSelectedTool(allocator, io, environment, state, "readlink");
        errdefer readlink.close(allocator, io);
        return .{
            .zig = zig,
            .make = make,
            .llvm_nm = llvm_nm,
            .llvm_objcopy = llvm_objcopy,
            .llvm_objdump = llvm_objdump,
            .llvm_readelf = llvm_readelf,
            .llvm_strip = llvm_strip,
            .bison = bison,
            .flex = flex,
            .m4 = m4,
            .bash = bash,
            .cp = cp,
            .mkdir = mkdir,
            .python3 = python3,
            .readlink = readlink,
        };
    }

    fn close(self: *SelectedTools, allocator: std.mem.Allocator, io: std.Io) void {
        inline for (std.meta.fields(SelectedTools)) |field|
            @field(self, field.name).close(allocator, io);
        self.* = undefined;
    }

    fn manifest(self: *const SelectedTools, name: []const u8) [64]u8 {
        const identity = if (std.mem.eql(u8, name, "zig"))
            self.zig.executable.identity
        else if (std.mem.eql(u8, name, "make"))
            self.make.executable.identity
        else if (std.mem.eql(u8, name, "llvm-nm"))
            self.llvm_nm.executable.identity
        else if (std.mem.eql(u8, name, "llvm-objcopy"))
            self.llvm_objcopy.executable.identity
        else if (std.mem.eql(u8, name, "llvm-objdump"))
            self.llvm_objdump.executable.identity
        else if (std.mem.eql(u8, name, "llvm-readelf"))
            self.llvm_readelf.executable.identity
        else if (std.mem.eql(u8, name, "llvm-strip"))
            self.llvm_strip.executable.identity
        else if (std.mem.eql(u8, name, "bison"))
            self.bison.executable.identity
        else if (std.mem.eql(u8, name, "flex"))
            self.flex.executable.identity
        else
            unreachable;
        return std.fmt.bytesToHex(identity.content_sha256, .lower);
    }

    fn same(left: *const SelectedTools, right: *const SelectedTools) bool {
        inline for (std.meta.fields(SelectedTools)) |field| {
            if (!std.meta.eql(
                @field(left, field.name).executable.identity,
                @field(right, field.name).executable.identity,
            )) return false;
            if (!std.mem.eql(
                u8,
                @field(left, field.name).path,
                @field(right, field.name).path,
            )) return false;
        }
        return true;
    }
};

fn resolveSelectedTool(
    allocator: std.mem.Allocator,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    state: std.Io.Dir,
    name: []const u8,
) !contract.process.Tool {
    return contract.process.resolveTool(allocator, io, environment, name) catch |err| {
        contract.files.writePrivateAtomicReplace(
            io,
            state,
            "failure-tool-role.txt",
            name,
        ) catch {};
        return err;
    };
}

fn imageInputChanged(io: std.Io, state: std.Io.Dir, guard: []const u8) anyerror {
    contract.files.writePrivateAtomicReplace(
        io,
        state,
        "failure-image-guard.txt",
        guard,
    ) catch {};
    return error.ImageInputChanged;
}

fn configInputChanged(
    io: std.Io,
    state: std.Io.Dir,
    path: []const u8,
    before: [64]u8,
) anyerror {
    var current = contract.files.RetainedFile.open(io, path, .private) catch
        return imageInputChanged(io, state, "config-unavailable");
    defer current.close(io);
    const observed = digestRetained(io, current) catch
        return imageInputChanged(io, state, "config-unstable");
    const same = std.mem.eql(u8, &before, &observed);
    return imageInputChanged(io, state, if (same)
        "config-after-identity-same-bytes"
    else
        "config-after-identity-changed-bytes");
}

fn rebindConfigAfterRoot(
    io: std.Io,
    state: std.Io.Dir,
    path: []const u8,
    previous: contract.files.RetainedFile,
    before: [64]u8,
) !contract.files.RetainedFile {
    var current = contract.files.RetainedFile.open(io, path, .private) catch
        return imageInputChanged(io, state, "config-unavailable");
    errdefer current.close(io);
    const observed = digestRetained(io, current) catch
        return imageInputChanged(io, state, "config-unstable");
    if (!std.mem.eql(u8, &before, &observed))
        return imageInputChanged(io, state, "config-after-root-changed-bytes");
    if (current.file_snapshot.mode != previous.file_snapshot.mode or
        current.file_snapshot.uid != previous.file_snapshot.uid or
        current.file_snapshot.size != previous.file_snapshot.size)
        return imageInputChanged(io, state, "config-after-root-changed-metadata");
    return current;
}

const NamedDigest = struct {
    name: []u8,
    sha256: [64]u8,
    mode: u16,

    fn less(_: void, left: NamedDigest, right: NamedDigest) bool {
        return std.mem.lessThan(u8, left.name, right.name);
    }
};

fn executeOpen(
    allocator: std.mem.Allocator,
    io: std.Io,
    inherited: *const std.process.Environ.Map,
    executable_path: []const u8,
    repository: contract.files.Repository,
    command: contract.Command,
) !void {
    const previous_umask = linux.syscall1(.umask, 0o077);
    defer _ = linux.syscall1(.umask, previous_umask);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const build_path = try std.fs.path.join(a, &.{ repository.app.path, "build" });
    const state_path = try std.fs.path.join(
        a,
        &.{ build_path, "native-environment" },
    );
    const build = try contract.files.ensurePrivateDirectory(
        io,
        repository.app.dir,
        "build",
    );
    defer build.close(io);
    const state = try contract.files.ensurePrivateDirectory(
        io,
        build,
        "native-environment",
    );
    defer state.close(io);
    var diagnostics = try Diagnostics.open(io, build);
    defer diagnostics.close(io);

    const duration: u64 = if (command == .olddefconfig)
        olddefconfig_milliseconds
    else
        native_images_milliseconds;
    var runner: Runner = .{
        .allocator = allocator,
        .io = io,
        .primary_deadline = try contract.process.Deadline.afterMilliseconds(duration),
        .cleanup_deadline = try contract.process.Deadline.afterMilliseconds(
            duration + cleanup_slack_milliseconds,
        ),
        .diagnostics = &diagnostics,
    };
    var tools = try SelectedTools.resolve(allocator, io, inherited, state);
    defer tools.close(allocator, io);
    var self_tool = contract.process.openTool(
        allocator,
        io,
        "wamr-aot-tool",
        executable_path,
    ) catch |err| {
        contract.files.writePrivateAtomicReplace(
            io,
            state,
            "failure-tool-role.txt",
            "wamr-aot-tool",
        ) catch {};
        return err;
    };
    defer self_tool.close(allocator, io);
    const running_file = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{
        .mode = .read_only,
        .follow_symlinks = true,
    });
    defer running_file.close(io);
    var running = try core.process.Executable.fromFile(io, running_file);
    defer running.close(io);
    // The supervisor executes a private byte-for-byte snapshot with a different inode.
    if (self_tool.executable.identity.size != running.identity.size or
        !std.mem.eql(
            u8,
            &self_tool.executable.identity.content_sha256,
            &running.identity.content_sha256,
        ))
        return imageInputChanged(io, state, "running-bytes");
    if (inherited.get("WAMR_CI_RETAINED_EXECUTABLE")) |retained_path| {
        if (!contract.process.retainedDescriptorPath(retained_path))
            return imageInputChanged(io, state, "retained-path");
        const retained_file = std.Io.Dir.openFileAbsolute(io, retained_path, .{
            .mode = .read_only,
            .follow_symlinks = true,
        }) catch return imageInputChanged(io, state, "retained-open");
        defer retained_file.close(io);
        var retained = core.process.Executable.fromFile(io, retained_file) catch
            return imageInputChanged(io, state, "retained-validation");
        defer retained.close(io);
        if (!std.meta.eql(self_tool.executable.identity, retained.identity))
            return imageInputChanged(io, state, "retained-identity");
    } else if (!std.meta.eql(self_tool.executable.identity, running.identity)) {
        return imageInputChanged(io, state, "direct-identity");
    }

    const private_paths = try createEnvironmentDirectories(
        a,
        io,
        state,
        state_path,
    );
    const cwd_path = try std.process.currentPathAlloc(io, a);
    const selected_bison_data = try bisonData(
        a,
        allocator,
        io,
        inherited,
        tools.bison,
        &runner,
        cwd_path,
    );
    const make_environment: MakeEnvironment = .{
        .bison_data = selected_bison_data,
        .m4 = tools.m4.path,
        .schema = .unikraft_native_make_environment_v1,
        .shell = tools.bash.path,
        .tmp = private_paths.tmp,
        .xdg_cache = private_paths.xdg_cache,
        .xdg_config = private_paths.xdg_config,
        .zig_global_cache = private_paths.zig_global_cache,
        .zig_local_cache = private_paths.zig_local_cache,
    };
    const environment_bytes = try encodeMakeEnvironment(allocator, make_environment);
    defer allocator.free(environment_bytes);
    try contract.files.writePrivateAtomicReplace(
        io,
        state,
        "environment.json",
        environment_bytes,
    );
    try verifyMakeEnvironment(
        allocator,
        io,
        state_path,
        environment_bytes,
    );

    try ensureAppConfig(allocator, io, repository, build_path);

    const portable_config = if (inherited.get("WAMR_CI_PORTABLE_CONFIG")) |flag|
        if (std.mem.eql(u8, flag, "1"))
            true
        else
            return error.InvalidPortableConfig
    else
        false;

    var root_environment = try cloneEnvironment(allocator, inherited);
    defer root_environment.deinit();
    try root_environment.put("TMPDIR", make_environment.tmp);
    const environment_path = try std.fs.path.join(
        a,
        &.{ state_path, "environment.json" },
    );
    const config_path = try std.fs.path.join(
        a,
        &.{ repository.app.path, "build", ".config" },
    );
    const root_arguments = try rootCommand(
        a,
        command,
        executable_path,
        repository,
        environment_path,
        config_path,
        make_environment,
        &tools,
        portable_config,
    );

    var config_input: ?contract.files.RetainedFile = null;
    defer if (config_input) |*file| file.close(io);
    var config_before_hash: ?[64]u8 = null;
    var runtime_input: ?contract.files.RetainedFile = null;
    defer if (runtime_input) |*file| file.close(io);
    var application_before: ?[]NamedDigest = null;
    defer if (application_before) |records| freeNamedDigests(allocator, records);
    if (command == .native_images) {
        config_input = try contract.files.RetainedFile.open(io, config_path, .private);
        config_before_hash = try digestRetained(io, config_input.?);
        const runtime_path = try std.fs.path.join(
            a,
            &.{ build_path, "artifacts", "identity.json" },
        );
        runtime_input = try contract.files.RetainedFile.open(io, runtime_path, .private);
        application_before = try applicationIdentities(
            allocator,
            io,
            repository.app,
        );
    }

    const stage: Stage = if (command == .olddefconfig)
        .root_olddefconfig
    else
        .root_native_images;
    var root_result = try runner.runSuccess(
        tools.zig,
        stage,
        root_arguments,
        &root_environment,
        repository.root.dir,
        repository.root.path,
        contract.process.maximum_diagnostic_bytes,
    );
    defer root_result.deinit(allocator);

    var tools_after = try SelectedTools.resolve(allocator, io, inherited, state);
    defer tools_after.close(allocator, io);
    if (!SelectedTools.same(&tools, &tools_after))
        return imageInputChanged(io, state, "tools-after-root");
    var self_after = contract.process.openTool(
        allocator,
        io,
        "wamr-aot-tool",
        executable_path,
    ) catch |err| {
        contract.files.writePrivateAtomicReplace(
            io,
            state,
            "failure-tool-role.txt",
            "wamr-aot-tool",
        ) catch {};
        return err;
    };
    defer self_after.close(allocator, io);
    if (!std.meta.eql(
        self_tool.executable.identity,
        self_after.executable.identity,
    )) return imageInputChanged(io, state, "self-after-root");

    if (command == .olddefconfig) {
        var solved = try contract.files.RetainedFile.open(io, config_path, .private);
        defer solved.close(io);
        if (solved.file_snapshot.size == 0 or
            solved.file_snapshot.size > maximum_identity_bytes)
            return error.InvalidSolvedConfig;
        try solved.verify(io);
        return;
    }

    config_input.?.verify(io) catch {
        const rebound = try rebindConfigAfterRoot(
            io,
            state,
            config_path,
            config_input.?,
            config_before_hash.?,
        );
        config_input.?.close(io);
        config_input = rebound;
    };
    runtime_input.?.verify(io) catch
        return imageInputChanged(io, state, "runtime-after-root");
    const application_after = try applicationIdentities(
        allocator,
        io,
        repository.app,
    );
    defer freeNamedDigests(allocator, application_after);
    if (!sameNamedDigests(application_before.?, application_after))
        return imageInputChanged(io, state, "application-after-root");

    var git = try contract.process.resolveTool(allocator, io, inherited, "git");
    defer git.close(allocator, io);
    var git_environment = try gitEnvironment(allocator, inherited);
    defer git_environment.deinit();
    try requireCleanGit(
        allocator,
        &runner,
        git,
        &git_environment,
        repository,
    );
    const revision = try gitRevision(
        allocator,
        &runner,
        git,
        &git_environment,
        repository,
    );
    defer allocator.free(revision);

    const file_identities = try imageIdentities(
        allocator,
        io,
        build_path,
    );
    defer freeNamedDigests(allocator, file_identities);
    const solved_config_sha256 = try digestRetained(io, config_input.?);
    const runtime_inputs_sha256 = try digestRetained(io, runtime_input.?);
    const manifest = try identityManifestAlloc(
        allocator,
        revision,
        root_arguments,
        application_after,
        &tools,
        file_identities,
        solved_config_sha256,
        runtime_inputs_sha256,
    );
    defer allocator.free(manifest);
    try validateIdentityBytes(allocator, manifest);
    try verifyIdentityValues(
        allocator,
        manifest,
        revision,
        root_arguments,
        application_after,
        &tools,
        file_identities,
        solved_config_sha256,
        runtime_inputs_sha256,
    );
    try contract.files.writePrivateAtomicReplace(
        io,
        build,
        "image-identity.json",
        manifest,
    );
    const identity_path = try std.fs.path.join(
        a,
        &.{ build_path, "image-identity.json" },
    );
    var published = try contract.files.RetainedFile.open(
        io,
        identity_path,
        .private,
    );
    defer published.close(io);
    const published_bytes = try readRetained(
        allocator,
        io,
        published,
        maximum_identity_bytes,
    );
    defer allocator.free(published_bytes);
    if (!std.mem.eql(u8, manifest, published_bytes))
        return error.ImageIdentityMismatch;
    try verifyIdentityValues(
        allocator,
        published_bytes,
        revision,
        root_arguments,
        application_after,
        &tools,
        file_identities,
        solved_config_sha256,
        runtime_inputs_sha256,
    );
    try published.verify(io);
    config_input.?.verify(io) catch
        return configInputChanged(
            io,
            state,
            config_path,
            config_before_hash.?,
        );
    runtime_input.?.verify(io) catch
        return imageInputChanged(io, state, "runtime-after-identity");
    const final_applications = try applicationIdentities(
        allocator,
        io,
        repository.app,
    );
    defer freeNamedDigests(allocator, final_applications);
    if (!sameNamedDigests(application_after, final_applications))
        return imageInputChanged(io, state, "application-after-identity");
    const final_images = try imageIdentities(allocator, io, build_path);
    defer freeNamedDigests(allocator, final_images);
    if (!sameNamedDigests(file_identities, final_images))
        return imageInputChanged(io, state, "images-after-identity");
    var final_tools = try SelectedTools.resolve(allocator, io, inherited, state);
    defer final_tools.close(allocator, io);
    if (!SelectedTools.same(&tools, &final_tools))
        return imageInputChanged(io, state, "tools-after-identity");
    var final_self = try contract.process.openTool(
        allocator,
        io,
        "wamr-aot-tool",
        executable_path,
    );
    defer final_self.close(allocator, io);
    if (!std.meta.eql(
        self_tool.executable.identity,
        final_self.executable.identity,
    )) return imageInputChanged(io, state, "self-after-identity");
}

const EnvironmentPaths = struct {
    tmp: []const u8,
    xdg_cache: []const u8,
    xdg_config: []const u8,
    zig_global_cache: []const u8,
    zig_local_cache: []const u8,
};

fn createEnvironmentDirectories(
    allocator: std.mem.Allocator,
    io: std.Io,
    state: std.Io.Dir,
    state_path: []const u8,
) !EnvironmentPaths {
    var result: EnvironmentPaths = undefined;
    inline for (.{
        .{ "tmp", "tmp" },
        .{ "xdg_cache", "xdg_cache" },
        .{ "xdg_config", "xdg_config" },
        .{ "zig_global_cache", "zig_global_cache" },
        .{ "zig_local_cache", "zig_local_cache" },
    }) |entry| {
        const directory = try contract.files.ensurePrivateDirectory(
            io,
            state,
            entry[1],
        );
        directory.close(io);
        @field(result, entry[0]) = try std.fs.path.join(
            allocator,
            &.{ state_path, entry[1] },
        );
    }
    return result;
}

fn bisonData(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    io: std.Io,
    inherited: *const std.process.Environ.Map,
    bison: contract.process.Tool,
    runner: *Runner,
    cwd_path: []const u8,
) ![]const u8 {
    if (inherited.get("BISON_PKGDATADIR")) |configured|
        return validateBisonData(arena, io, configured);
    var result = try runner.runSuccess(
        bison,
        .bison_data,
        &.{ bison.path, "--print-datadir" },
        inherited,
        std.Io.Dir.cwd(),
        cwd_path,
        4096,
    );
    defer result.deinit(allocator);
    return validateBisonData(
        arena,
        io,
        std.mem.trim(u8, result.stdout, " \t\r\n"),
    );
}

fn validateBisonData(
    allocator: std.mem.Allocator,
    io: std.Io,
    configured: []const u8,
) ![]const u8 {
    if (!std.fs.path.isAbsolute(configured))
        return error.InvalidBisonData;
    const canonical = try paths.canonicalizeNearestExisting(
        allocator,
        io,
        configured,
    );
    defer allocator.free(canonical.path);
    if (!canonical.exists or !std.mem.eql(u8, canonical.path, configured))
        return error.InvalidBisonData;
    const directory = std.Io.Dir.openDirAbsolute(io, configured, .{
        .follow_symlinks = false,
        .iterate = true,
    }) catch return error.InvalidBisonData;
    defer directory.close(io);
    return allocator.dupe(u8, configured);
}

fn verifyMakeEnvironment(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    expected: []const u8,
) !void {
    const path = try std.fs.path.join(
        allocator,
        &.{ state_path, "environment.json" },
    );
    defer allocator.free(path);
    var retained = try contract.files.RetainedFile.open(io, path, .private);
    defer retained.close(io);
    const bytes = try readRetained(
        allocator,
        io,
        retained,
        native_make_environment.maximum_bytes,
    );
    defer allocator.free(bytes);
    if (!std.mem.eql(u8, expected, bytes))
        return error.NativeMakeEnvironmentChanged;
    var parsed = try native_make_environment.parse(allocator, bytes);
    defer parsed.deinit();
    try retained.verify(io);
}

fn ensureAppConfig(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: contract.files.Repository,
    build_path: []const u8,
) !void {
    if (repository.app.dir.statFile(
        io,
        ".config",
        .{ .follow_symlinks = false },
    )) |stat| {
        if (stat.kind != .file) return error.UnsafeConfig;
        const existing = try repository.app.openFile(io, ".config", .source);
        existing.close(io);
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const defconfig = try repository.app.read(
        allocator,
        io,
        "defconfig",
        maximum_identity_bytes,
        .source,
    );
    defer allocator.free(defconfig);
    const identity_path = try std.fs.path.join(
        allocator,
        &.{ build_path, "artifacts", "identity.json" },
    );
    defer allocator.free(identity_path);
    var identity = try contract.files.RetainedFile.open(
        io,
        identity_path,
        .private,
    );
    defer identity.close(io);
    const identity_bytes = try readRetained(
        allocator,
        io,
        identity,
        maximum_identity_bytes,
    );
    defer allocator.free(identity_bytes);
    var document = try contract.json.parse(allocator, identity_bytes, .{
        .bytes = maximum_identity_bytes,
        .depth = 32,
        .string_bytes = 64 * 1024,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    const fields = switch (document.value()) {
        .object => |object| object,
        else => return error.InvalidIdentity,
    };
    const variant = if (fields.get("variant")) |value|
        try core.contracts.string(value)
    else
        "tiny";
    var contents = std.Io.Writer.Allocating.init(allocator);
    defer contents.deinit();
    try contents.writer.writeAll(defconfig);
    if (!std.mem.eql(u8, variant, "tiny")) {
        const jit_value = fields.get("jit_mode") orelse return error.InvalidIdentity;
        const mode: u8 = switch (jit_value) {
            .null => 0,
            .string => |value| if (std.mem.eql(u8, value, "fast"))
                1
            else if (std.mem.eql(u8, value, "full"))
                2
            else
                return error.InvalidIdentity,
            else => return error.InvalidIdentity,
        };
        try contents.writer.print(
            "\nCONFIG_STACK_SIZE_PAGE_ORDER=8\n" ++
                "CONFIG_APPWAMRAOT_JIT_BOOT_MODE={d}\n",
            .{mode},
        );
    }
    try contract.files.writePrivateCreate(
        io,
        repository.app.dir,
        ".config",
        contents.written(),
    );
    try identity.verify(io);
}

fn rootCommand(
    allocator: std.mem.Allocator,
    command: contract.Command,
    executable_path: []const u8,
    repository: contract.files.Repository,
    environment_path: []const u8,
    config_path: []const u8,
    make_environment: MakeEnvironment,
    tools: *const SelectedTools,
    portable_config: bool,
) ![]const []const u8 {
    var arguments: std.ArrayList([]const u8) = .empty;
    try arguments.appendSlice(allocator, &.{
        tools.zig.path,
        "build",
        if (command == .olddefconfig) "olddefconfig" else "native-images",
        "-j2",
        "--cache-dir",
        make_environment.zig_local_cache,
        "--global-cache-dir",
        make_environment.zig_global_cache,
        try std.fmt.allocPrint(allocator, "-Dapp={s}", .{repository.app.path}),
        try std.fmt.allocPrint(
            allocator,
            "-Dnative-make-environment={s}",
            .{environment_path},
        ),
        try std.fmt.allocPrint(allocator, "-Dconfig={s}", .{config_path}),
        try std.fmt.allocPrint(allocator, "-Dmake-command={s}", .{tools.make.path}),
        try std.fmt.allocPrint(allocator, "-Dbison-command={s}", .{tools.bison.path}),
        try std.fmt.allocPrint(allocator, "-Dflex-command={s}", .{tools.flex.path}),
        try std.fmt.allocPrint(
            allocator,
            "-Dcompiler={s} cc -target x86_64-freestanding-none",
            .{tools.zig.path},
        ),
        "-Dcompiler-targeted=true",
        try std.fmt.allocPrint(allocator, "-Dhost-cc={s} cc", .{tools.zig.path}),
        try std.fmt.allocPrint(allocator, "-Dhost-cxx={s} c++", .{tools.zig.path}),
        "-Dhost-cflags=-fno-sanitize=null",
        try std.fmt.allocPrint(allocator, "-Dmake-arg=AR={s} ar", .{tools.zig.path}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=CP={s} -f", .{tools.cp.path}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=MKDIR={s}", .{tools.mkdir.path}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=PYTHON={s}", .{tools.python3.path}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=READLINK={s}", .{tools.readlink.path}),
        "-Dmake-arg=HOSTOSENV=Linux",
        "-Dmake-arg=WGET_VERSION=unavailable",
        "-Dmake-arg=WGET=false",
        try std.fmt.allocPrint(allocator, "-Dmake-arg=ZIG={s}", .{tools.zig.path}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=YACC={s}", .{tools.bison.path}),
        try std.fmt.allocPrint(allocator, "-Dmake-arg=LEX={s}", .{tools.flex.path}),
        "-Dmake-arg=KCONFIG_OVERWRITECONFIG=1",
        "-Dmake-arg=UK_CFLAGS=-std=gnu17",
        "-Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt",
    });
    if (portable_config)
        try arguments.append(allocator, "-Dci-portable-config=true");
    inline for (.{
        .{ "NM", "llvm_nm" },
        .{ "OBJCOPY", "llvm_objcopy" },
        .{ "OBJDUMP", "llvm_objdump" },
        .{ "READELF", "llvm_readelf" },
        .{ "STRIP", "llvm_strip" },
    }) |entry| {
        try arguments.append(
            allocator,
            try std.fmt.allocPrint(
                allocator,
                "-Dmake-arg={s}={s}",
                .{ entry[0], @field(tools, entry[1]).path },
            ),
        );
    }
    try arguments.append(
        allocator,
        try std.fmt.allocPrint(
            allocator,
            "-Dwamr-aot-tool={s}",
            .{executable_path},
        ),
    );
    if (command == .native_images)
        try arguments.append(
            allocator,
            "-Dnative-profile=hyperv-x86_64-efi-wamr",
        );
    return arguments.toOwnedSlice(allocator);
}

fn applicationIdentities(
    allocator: std.mem.Allocator,
    io: std.Io,
    app: contract.files.SourceDirectory,
) ![]NamedDigest {
    var records: std.ArrayList(NamedDigest) = .empty;
    errdefer {
        for (records.items) |record| allocator.free(record.name);
        records.deinit(allocator);
    }
    var iterator = app.dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        switch (entry.kind) {
            .directory => continue,
            .file => {},
            else => return error.UnsafeApplicationSource,
        }
        const record = try app.record(
            allocator,
            io,
            entry.name,
            maximum_source_bytes,
            .source,
        );
        defer allocator.free(record.path);
        try records.append(allocator, .{
            .name = try allocator.dupe(u8, entry.name),
            .sha256 = record.sha256,
            .mode = record.mode,
        });
    }
    std.mem.sort(NamedDigest, records.items, {}, NamedDigest.less);
    return records.toOwnedSlice(allocator);
}

fn imageIdentities(
    allocator: std.mem.Allocator,
    io: std.Io,
    build_path: []const u8,
) ![]NamedDigest {
    const records = try allocator.alloc(NamedDigest, image_names.len);
    var count: usize = 0;
    errdefer {
        for (records[0..count]) |record| allocator.free(record.name);
        allocator.free(records);
    }
    for (image_names, 0..) |name, index| {
        const path = try std.fs.path.join(allocator, &.{ build_path, name });
        defer allocator.free(path);
        records[index] = .{
            .name = try allocator.dupe(u8, name),
            .sha256 = undefined,
            .mode = undefined,
        };
        count += 1;
        const identity = try fileIdentity(io, path, maximum_source_bytes);
        records[index].sha256 = identity.sha256;
        records[index].mode = identity.mode;
    }
    return records;
}

fn freeNamedDigests(allocator: std.mem.Allocator, records: []NamedDigest) void {
    for (records) |record| allocator.free(record.name);
    allocator.free(records);
}

fn sameNamedDigests(left: []const NamedDigest, right: []const NamedDigest) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a.name, b.name) or
            !std.mem.eql(u8, &a.sha256, &b.sha256) or
            a.mode != b.mode)
            return false;
    }
    return true;
}

fn requireCleanGit(
    allocator: std.mem.Allocator,
    runner: *Runner,
    git: contract.process.Tool,
    environment: *const std.process.Environ.Map,
    repository: contract.files.Repository,
) !void {
    const arguments = [_][]const u8{
        git.path,
        "--no-pager",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "core.pager=cat",
        "diff",
        "--quiet",
        "--no-ext-diff",
        "HEAD",
        "--",
    };
    var result = try runner.run(
        git,
        .git_clean,
        &arguments,
        environment,
        repository.root.dir,
        repository.root.path,
        64 * 1024,
    );
    defer result.deinit(allocator);
    if (result.succeeded()) return;
    if (result.primary == .exited and result.primary.exited == 1)
        return error.DirtyImageSource;
    return error.GitCleanCommandFailed;
}

fn gitRevision(
    allocator: std.mem.Allocator,
    runner: *Runner,
    git: contract.process.Tool,
    environment: *const std.process.Environ.Map,
    repository: contract.files.Repository,
) ![]u8 {
    const arguments = [_][]const u8{
        git.path,
        "--no-pager",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "core.pager=cat",
        "rev-parse",
        "HEAD",
    };
    var result = try runner.runSuccess(
        git,
        .git_revision,
        &arguments,
        environment,
        repository.root.dir,
        repository.root.path,
        65,
    );
    defer result.deinit(allocator);
    const revision = std.mem.trim(u8, result.stdout, " \t\r\n");
    try contract.validateRevision(revision);
    return allocator.dupe(u8, revision);
}

fn gitEnvironment(
    allocator: std.mem.Allocator,
    inherited: *const std.process.Environ.Map,
) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();
    var iterator = inherited.iterator();
    while (iterator.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "GIT_") or
            std.mem.eql(u8, entry.key_ptr.*, "LD_AUDIT") or
            std.mem.eql(u8, entry.key_ptr.*, "LD_LIBRARY_PATH") or
            std.mem.eql(u8, entry.key_ptr.*, "LD_PRELOAD"))
            continue;
        try result.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    try result.put("GIT_CONFIG_GLOBAL", "/dev/null");
    try result.put("GIT_CONFIG_NOSYSTEM", "1");
    try result.put("GIT_NO_REPLACE_OBJECTS", "1");
    try result.put("GIT_OPTIONAL_LOCKS", "0");
    try result.put("GIT_PAGER", "cat");
    try result.put("GIT_TERMINAL_PROMPT", "0");
    try result.put("PAGER", "cat");
    return result;
}

fn cloneEnvironment(
    allocator: std.mem.Allocator,
    inherited: *const std.process.Environ.Map,
) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();
    var iterator = inherited.iterator();
    while (iterator.next()) |entry|
        try result.put(entry.key_ptr.*, entry.value_ptr.*);
    return result;
}

fn identityManifestAlloc(
    allocator: std.mem.Allocator,
    revision: []const u8,
    command: []const []const u8,
    applications: []const NamedDigest,
    tools: *const SelectedTools,
    files: []const NamedDigest,
    solved_config_sha256: [64]u8,
    runtime_inputs_sha256: [64]u8,
) ![]u8 {
    var raw = std.Io.Writer.Allocating.init(allocator);
    defer raw.deinit();
    try raw.writer.writeByte('{');
    try jsonFieldName(&raw.writer, "schema_version", false);
    try raw.writer.writeAll("1");
    try jsonFieldName(&raw.writer, "command", true);
    try writeStringArray(&raw.writer, command);
    try jsonFieldName(&raw.writer, "scope", true);
    try contract.json.writeString(
        &raw.writer,
        "native-build-only-not-boot-or-hardware-qualification",
    );
    try jsonFieldName(&raw.writer, "unikraft_revision", true);
    try contract.json.writeString(&raw.writer, revision);
    try jsonFieldName(&raw.writer, "unikraft_diff_sha256", true);
    try contract.json.writeString(&raw.writer, empty_sha256);
    try jsonFieldName(&raw.writer, "application_sources", true);
    try writeNamedDigests(&raw.writer, applications);
    try jsonFieldName(&raw.writer, "tools", true);
    try raw.writer.writeByte('{');
    for (manifest_tool_names, 0..) |name, index| {
        if (index != 0) try raw.writer.writeByte(',');
        try contract.json.writeString(&raw.writer, name);
        try raw.writer.writeByte(':');
        const sha = tools.manifest(name);
        try contract.json.writeString(&raw.writer, &sha);
    }
    try raw.writer.writeByte('}');
    try jsonFieldName(&raw.writer, "files", true);
    try writeNamedDigests(&raw.writer, files);
    try jsonFieldName(&raw.writer, "solved_config_sha256", true);
    try contract.json.writeString(&raw.writer, &solved_config_sha256);
    try jsonFieldName(&raw.writer, "runtime_inputs_sha256", true);
    try contract.json.writeString(&raw.writer, &runtime_inputs_sha256);
    try raw.writer.writeByte('}');
    const compact = try raw.toOwnedSlice();
    defer allocator.free(compact);
    var document = try contract.json.parse(allocator, compact, .{
        .bytes = maximum_identity_bytes,
        .depth = 16,
        .string_bytes = 64 * 1024,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    return contract.json.valueAlloc(allocator, document.value(), .pretty);
}

pub fn validateIdentityBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !void {
    var document = try contract.json.parse(allocator, bytes, .{
        .bytes = maximum_identity_bytes,
        .depth = 16,
        .string_bytes = 64 * 1024,
        .items = 4096,
        .tokens = 65536,
    });
    defer document.deinit();
    const fields = try core.contracts.exactFields(document.value(), &.{
        "schema_version",
        "command",
        "scope",
        "unikraft_revision",
        "unikraft_diff_sha256",
        "application_sources",
        "tools",
        "files",
        "solved_config_sha256",
        "runtime_inputs_sha256",
    });
    if (try core.contracts.integer(u8, fields.get("schema_version").?) != 1)
        return error.ImageIdentityMismatch;
    if (!std.mem.eql(
        u8,
        try core.contracts.string(fields.get("scope").?),
        "native-build-only-not-boot-or-hardware-qualification",
    )) return error.ImageIdentityMismatch;
    try contract.validateRevision(
        try core.contracts.string(fields.get("unikraft_revision").?),
    );
    inline for (.{
        "unikraft_diff_sha256",
        "solved_config_sha256",
        "runtime_inputs_sha256",
    }) |name| try requireSha256(
        try core.contracts.string(fields.get(name).?),
    );
    const command = switch (fields.get("command").?) {
        .array => |array| array,
        else => return error.ExpectedArray,
    };
    if (command.items.len == 0 or command.items.len > 128)
        return error.ImageIdentityMismatch;
    for (command.items) |argument|
        _ = try core.contracts.string(argument);
    inline for (.{ "application_sources", "tools", "files" }) |name| {
        const entries = switch (fields.get(name).?) {
            .object => |object| object,
            else => return error.ExpectedObject,
        };
        var iterator = entries.iterator();
        while (iterator.next()) |entry| {
            if (entry.key_ptr.*.len == 0 or
                std.mem.indexOfScalar(u8, entry.key_ptr.*, '/') != null)
                return error.ImageIdentityMismatch;
            try requireSha256(try core.contracts.string(entry.value_ptr.*));
        }
    }
    const canonical = try contract.json.valueAlloc(
        allocator,
        document.value(),
        .pretty,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.ImageIdentityMismatch;
}

fn verifyIdentityValues(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    revision: []const u8,
    command: []const []const u8,
    applications: []const NamedDigest,
    tools: *const SelectedTools,
    files: []const NamedDigest,
    solved_config_sha256: [64]u8,
    runtime_inputs_sha256: [64]u8,
) !void {
    try validateIdentityBytes(allocator, bytes);
    const expected = try identityManifestAlloc(
        allocator,
        revision,
        command,
        applications,
        tools,
        files,
        solved_config_sha256,
        runtime_inputs_sha256,
    );
    defer allocator.free(expected);
    if (!std.mem.eql(u8, expected, bytes))
        return error.ImageIdentityMismatch;
}

fn readRetained(
    allocator: std.mem.Allocator,
    io: std.Io,
    retained: contract.files.RetainedFile,
    maximum: u64,
) ![]u8 {
    if (retained.file_snapshot.size == 0 or
        retained.file_snapshot.size > maximum or
        retained.file_snapshot.size > std.math.maxInt(usize))
        return error.FileTooLarge;
    const bytes = try allocator.alloc(
        u8,
        @intCast(retained.file_snapshot.size),
    );
    errdefer allocator.free(bytes);
    if (try retained.file.readPositionalAll(io, bytes, 0) != bytes.len)
        return error.FileChanged;
    try retained.verify(io);
    return bytes;
}

fn digestRetained(
    io: std.Io,
    retained: contract.files.RetainedFile,
) ![64]u8 {
    const digest = try contract.files.hashStableFile(
        io,
        retained.file,
        maximum_source_bytes,
    );
    try retained.verify(io);
    return digest;
}

const FileIdentity = struct {
    sha256: [64]u8,
    mode: u16,
};

fn fileIdentity(
    io: std.Io,
    path: []const u8,
    maximum: u64,
) !FileIdentity {
    var retained = try contract.files.RetainedFile.open(io, path, .artifact);
    defer retained.close(io);
    const snapshot = retained.file_snapshot;
    if (snapshot.mode & linux.S.IFMT != linux.S.IFREG or
        snapshot.mode & 0o7022 != 0 or
        snapshot.uid != linux.geteuid() or snapshot.nlink != 1)
        return error.UnsafeImageArtifact;
    const digest = try contract.files.hashStableFile(io, retained.file, maximum);
    try retained.verify(io);
    return .{ .sha256 = digest, .mode = snapshot.mode & 0o7777 };
}

fn jsonFieldName(
    writer: *std.Io.Writer,
    name: []const u8,
    comma: bool,
) !void {
    if (comma) try writer.writeByte(',');
    try contract.json.writeString(writer, name);
    try writer.writeByte(':');
}

fn writeStringArray(
    writer: *std.Io.Writer,
    values: []const []const u8,
) !void {
    try writer.writeByte('[');
    for (values, 0..) |value, index| {
        if (index != 0) try writer.writeByte(',');
        try contract.json.writeString(writer, value);
    }
    try writer.writeByte(']');
}

fn writeNamedDigests(
    writer: *std.Io.Writer,
    records: []const NamedDigest,
) !void {
    try writer.writeByte('{');
    for (records, 0..) |record, index| {
        if (index != 0) try writer.writeByte(',');
        try contract.json.writeString(writer, record.name);
        try writer.writeByte(':');
        try contract.json.writeString(writer, &record.sha256);
    }
    try writer.writeByte('}');
}

fn requireSha256(value: []const u8) !void {
    _ = try core.contracts.parseSha256(value);
}

fn commandFailure(stage: Stage) anyerror {
    return switch (stage) {
        .bison_data => error.BisonDataCommandFailed,
        .root_olddefconfig, .root_native_images => error.RootBuildCommandFailed,
        .git_clean => error.GitCleanCommandFailed,
        .git_revision => error.GitRevisionCommandFailed,
    };
}

fn commandResultAlloc(
    allocator: std.mem.Allocator,
    stage: Stage,
    argv: []const []const u8,
    cwd: []const u8,
    result: contract.process.CommandResult,
) ![]u8 {
    var raw = std.Io.Writer.Allocating.init(allocator);
    defer raw.deinit();
    try raw.writer.writeAll("{\"argv\":");
    try writeStringArray(&raw.writer, argv);
    try raw.writer.writeAll(",\"cleanup\":");
    try contract.json.writeString(&raw.writer, @tagName(result.cleanup));
    try raw.writer.print(
        ",\"cleanup_complete\":{s},\"cleanup_events\":{d},\"completed_ns\":{d}," ++
            "\"cwd\":",
        .{
            if (result.cleanup_complete) "true" else "false",
            result.cleanup_events,
            result.completed_ns,
        },
    );
    try contract.json.writeString(&raw.writer, cwd);
    try raw.writer.print(
        ",\"descendants\":{{\"adopted\":{d},\"identity_validated\":{d}," ++
            "\"limit_exceeded\":{s},\"observed\":{d},\"untracked\":{s}}}," ++
            "\"executable_stable\":{s},\"primary\":",
        .{
            result.descendants.adopted,
            result.descendants.identity_validated,
            if (result.descendants.limit_exceeded) "true" else "false",
            result.descendants.observed,
            if (result.descendants.untracked) "true" else "false",
            if (result.executable_stable) "true" else "false",
        },
    );
    try writePrimary(&raw.writer, result.primary);
    try raw.writer.print(
        ",\"primary_completed_ns\":{d},\"primary_deadline_reached\":{s}," ++
            "\"primary_events\":{d},\"reap_events\":{d},\"stage\":",
        .{
            result.primary_completed_ns,
            if (result.primary_deadline_reached) "true" else "false",
            result.primary_events,
            result.reap_events,
        },
    );
    try contract.json.writeString(&raw.writer, stage.name());
    try raw.writer.writeAll(",\"stderr_status\":");
    try contract.json.writeString(&raw.writer, @tagName(result.stderr_status));
    try raw.writer.print(",\"started_ns\":{d},\"stdout_status\":", .{result.started_ns});
    try contract.json.writeString(&raw.writer, @tagName(result.stdout_status));
    try raw.writer.print(
        ",\"cancellation_observed\":{s}}}",
        .{if (result.cancellation_observed) "true" else "false"},
    );
    const compact = try raw.toOwnedSlice();
    defer allocator.free(compact);
    var document = try contract.json.parse(allocator, compact, .{
        .bytes = maximum_identity_bytes,
        .depth = 16,
        .string_bytes = 64 * 1024,
        .items = 1024,
        .tokens = 8192,
    });
    defer document.deinit();
    return contract.json.valueAlloc(allocator, document.value(), .pretty);
}

fn writePrimary(
    writer: *std.Io.Writer,
    primary: contract.process.CommandPrimary,
) !void {
    try writer.writeByte('{');
    switch (primary) {
        .exited => |code| try writer.print("\"exited\":{d}", .{code}),
        .signal => |signal| try writer.print(
            "\"signal\":{d}",
            .{@intFromEnum(signal)},
        ),
        .unknown => |status| try writer.print("\"unknown\":{d}", .{status}),
        else => try contract.json.writeString(writer, @tagName(primary)),
    }
    try writer.writeByte('}');
}

test "image identity parser rejects malformed unknown and unsafe records" {
    const allocator = std.testing.allocator;
    const base =
        \\{
        \\  "application_sources": {},
        \\  "command": ["zig"],
        \\  "files": {},
        \\  "runtime_inputs_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\  "schema_version": 1,
        \\  "scope": "native-build-only-not-boot-or-hardware-qualification",
        \\  "solved_config_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\  "tools": {},
        \\  "unikraft_diff_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        \\  "unikraft_revision": "0123456789abcdef0123456789abcdef01234567"
        \\}
        \\
    ;
    try validateIdentityBytes(allocator, base);
    for ([_][]const u8{
        "{}\n",
        "{\"schema_version\":1,\"schema_version\":1}\n",
        "{\"unknown\":true}\n",
    }) |invalid|
        try std.testing.expectError(
            error.MissingField,
            validateIdentityBytes(allocator, invalid),
        );
    const unsafe = try std.mem.replaceOwned(
        u8,
        allocator,
        base,
        "\"application_sources\": {}",
        "\"application_sources\": {\"../escape\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
    );
    defer allocator.free(unsafe);
    try std.testing.expectError(
        error.ImageIdentityMismatch,
        validateIdentityBytes(allocator, unsafe),
    );
}
