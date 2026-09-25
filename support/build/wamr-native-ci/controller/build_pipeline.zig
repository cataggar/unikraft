// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const process = core.process;
const Sha256 = core.Sha256;
const plan = @import("command_plan.zig");
const adapter = @import("command_adapter.zig");
const custody = @import("source_custody.zig");
const physical = @import("custody_files.zig");
const inputs = @import("input_custody.zig");
const dependencies = @import("dependency_custody.zig");
const records = @import("records.zig");
const fixture_contract = @import("fixture_contract.zig");
const profile = @import("profile.zig");
const limits = @import("custody_limits.zig");

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    runtime: []const u8,
    repository: []const u8,
    wamr: []const u8,
    compute: []const u8,
    git: []const u8,
    tools: [inputs.host_tools.len][]const u8,
    roots: plan.Roots,
    signal: *const process.SignalCancellation,
    source: ?custody.Source = null,
    dependency: ?dependencies.Document = null,
    bootstrap_inputs: ?inputs.Custody = null,
    bootstrap_files: []const inputs.Binding = &.{},
    bootstrap_trees: []const inputs.Binding = &.{},
    consumer: ?inputs.Production = null,
    command_records: [std.meta.fields(plan.Stage).len]?physical.File = .{null} ** std.meta.fields(plan.Stage).len,
    build_start_record: ?physical.File = null,
    fixture_report: ?physical.File = null,
    test_before_publication: ?*const fn (*Context) void = null,
    failed_stage: []const u8 = "startup",
    failed_operation: []const u8 = "",
};

pub const Invocation = struct { context: *Context };
pub const RuntimeBound = struct { context: *Context, runtime: files.Directory };
pub const SlotsReserved = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const SourceCustodied = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const WamrArchiveSealed = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const DependenciesRestored = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const BootstrapInputsBound = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const AdapterBuilt = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const LocalBootBuilt = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const InputsBaselined = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const NativeFixturesPassed = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const ProducerPrepared = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const ConfigSolved = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const NativeImageBuilt = struct { context: *Context, runtime: files.Directory, work: files.Directory };
pub const BuildAccepted = struct { context: *Context };

pub fn installCancellation() !process.SignalCancellation {
    return process.SignalCancellation.install();
}

fn next(state: anytype, comptime Type: type) Type {
    return .{ .context = state.context, .runtime = state.runtime, .work = state.work };
}

fn cancelled(context: *const Context) !void {
    if (context.signal.flag().load(.acquire)) return error.Cancelled;
}

fn subpath(context: *Context, name: []const u8) ![]const u8 {
    return std.fs.path.join(context.allocator, &.{ context.compute, name });
}

fn join(context: *Context, parts: []const []const u8) ![]const u8 {
    return std.fs.path.join(context.allocator, parts);
}

fn create(io: std.Io, directory: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try directory.createFile(io, name, .{
        .exclusive = true,
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
    try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn read(context: *Context, path: []const u8, max: usize, private: bool) ![]const u8 {
    var retained = try files.RetainedFile.open(context.io, path, if (private) .private else .artifact);
    defer retained.close(context.io);
    var data = try files.readSensitiveFile(context.io, context.allocator, retained.file, max, if (private) .private else .artifact);
    defer data.deinit();
    try retained.verify(context.io);
    return context.allocator.dupe(u8, data.bytes());
}

pub fn readAcceptedRecord(context: *Context, name: []const u8) ![]const u8 {
    const relative = try std.fs.path.join(context.allocator, &.{ "evidence", name });
    defer context.allocator.free(relative);
    const path = try subpath(context, relative);
    defer context.allocator.free(path);
    return read(context, path, records.max_record_bytes, true);
}

fn evidence(context: *Context, name: []const u8, value: anytype) !void {
    try cancelled(context);
    const raw = try std.json.Stringify.valueAlloc(context.allocator, value, .{});
    defer context.allocator.free(raw);
    const encoded = try records.canonicalAlloc(context.allocator, raw);
    defer context.allocator.free(encoded);
    const evidence_path = try subpath(context, "evidence");
    defer context.allocator.free(evidence_path);
    const evidence_dir = try files.openDirectory(context.io, evidence_path, .private);
    defer evidence_dir.close(context.io);
    if (builtin.is_test) if (context.test_before_publication) |fault| fault(context);
    try cancelled(context);
    try create(context.io, evidence_dir, name, encoded);
}

fn contextDir(context: *Context, relative: []const u8) !std.Io.Dir {
    const path = try subpath(context, relative);
    return files.openDirectory(context.io, path, .private);
}

fn findTool(context: *Context, name: []const u8) ![]const u8 {
    const path = std.process.Environ.getPosix(context.environ, "PATH") orelse return error.MissingPath;
    var components = std.mem.splitScalar(u8, path, ':');
    while (components.next()) |component| {
        if (component.len == 0 or component[0] != '/') continue;
        const candidate = try join(context, &.{ component, name });
        const resolved = std.Io.Dir.realPathFileAbsoluteAlloc(context.io, candidate, context.allocator) catch continue;
        var executable = process.Executable.open(context.io, resolved) catch continue;
        executable.close(context.io);
        return resolved;
    }
    return error.ToolUnavailable;
}

pub fn bind(invocation: Invocation) !RuntimeBound {
    const context = invocation.context;
    try cancelled(context);
    const runtime = try @import("layout.zig").runtime(context.io, context.runtime);
    errdefer runtime.close(context.io);
    const bison_path = try join(context, &.{ context.runtime, "bison" });
    if (!std.mem.eql(u8, std.process.Environ.getPosix(context.environ, "BISON_PKGDATADIR") orelse "", bison_path))
        return error.BisonPathChanged;
    _ = try inputs.bison(context.allocator, context.io, bison_path);
    for (inputs.host_tools, 0..) |tool, index| {
        context.tools[index] = try findTool(context, tool);
        if (std.mem.eql(u8, tool, "git")) context.git = context.tools[index];
    }
    const own_path = try join(context, &.{ context.runtime, "controller/bin/uk-wamr-native-ci" });
    const self_path = try std.process.executablePathAlloc(context.io, context.allocator);
    if (!std.mem.eql(u8, own_path, self_path)) return error.UnboundController;
    try custody.verifyPhysical(context.io, context.allocator, context.repository);
    context.roots = .{
        .runtime = context.runtime,
        .source_root = context.repository,
        .work = context.compute,
        .zig = context.tools[9],
        .producer = try subpath(context, "tools/bin/uk-wamr-aot-build"),
        .fixture_runner = try subpath(context, "tools/bin/wamr-native-ci-fixtures"),
        .supervisor = own_path,
        .package_tool = try subpath(context, "tools/bin/wamr-ci-package"),
        .validator = try subpath(context, "tools/bin/uk-wamr-log-validate"),
        .supervisor_fixture = try subpath(context, "tools/bin/wamr-ci-supervisor-fixture"),
        .tools = context.tools,
    };
    return .{ .context = context, .runtime = runtime };
}

fn absent(io: std.Io, path: []const u8) !void {
    if (files.openAbsolute(io, path, .artifact)) |opened| {
        opened.close(io);
        return error.PriorOutput;
    } else |err| if (err != error.FileNotFound) return err;
}

fn createSourceOutputs(context: *Context) !void {
    const io = context.io;
    const a = context.allocator;
    const app = try join(context, &.{ context.repository, "support/apps/wamr-aot" });
    const cache = try join(context, &.{ context.repository, ".zig-cache" });
    const build = try join(context, &.{ app, "build" });
    const config = try join(context, &.{ app, ".config" });
    const backup = try join(context, &.{ app, ".config.old" });
    try absent(io, cache);
    try absent(io, build);
    try absent(io, config);
    try absent(io, backup);
    const root = try files.openDirectory(io, context.repository, .artifact);
    defer root.close(io);
    try root.createDir(io, ".zig-cache", .fromMode(0o700));
    const app_dir = try files.openDirectory(io, app, .artifact);
    defer app_dir.close(io);
    try app_dir.createDir(io, "build", .fromMode(0o700));
    const build_dir = try files.openDirectory(io, build, .private);
    defer build_dir.close(io);
    const definition = try read(context, try std.fs.path.join(a, &.{ app, "defconfig" }), limits.mib, false);
    try create(io, build_dir, ".config", definition);
    try create(io, app_dir, ".config", definition);
}

pub fn reserve(bound: RuntimeBound) !SlotsReserved {
    const context = bound.context;
    try cancelled(context);
    try bound.runtime.dir.createDir(context.io, "compute", .fromMode(0o700));
    const work = try files.Directory.open(context.io, context.compute);
    errdefer work.close(context.io);
    for ([_][]const u8{
        "private",  "evidence", "scratch",          "cache",   "global-cache",
        "fixtures", "tools",    "local-boot-tools", "package", "public-source",
    }) |directory| try work.dir.createDir(context.io, directory, .fromMode(0o700));
    const global = try contextDir(context, "global-cache");
    defer global.close(context.io);
    try global.createDir(context.io, "tmp", .fromMode(0o700));
    for (profile.production_modes) |mode| {
        const name = try std.fmt.allocPrint(context.allocator, "boot-{s}", .{@tagName(mode)});
        try work.dir.createDir(context.io, name, .fromMode(0o700));
    }
    try createSourceOutputs(context);
    return .{ .context = context, .runtime = bound.runtime, .work = work };
}

pub fn captureSource(reserved: SlotsReserved) !SourceCustodied {
    const context = reserved.context;
    try cancelled(context);
    context.source = try custody.source(context.allocator, context.io, context.repository, context.git);
    return next(reserved, SourceCustodied);
}

pub fn sealSource(state: SourceCustodied) !WamrArchiveSealed {
    const context = state.context;
    try cancelled(context);
    context.failed_stage = "wamr-archive";
    try state.runtime.dir.createDir(context.io, "custody", .fromMode(0o700));
    _ = try custody.sealWamr(context.allocator, context.io, context.wamr, context.runtime, context.git);
    return next(state, WamrArchiveSealed);
}

fn runBootstrap(context: *Context, stage: []const u8, argv: []const []const u8, cwd: []const u8, timeout: u32, bound: usize) ![]const u8 {
    try cancelled(context);
    try requireBootstrapInputs(context);
    try process.initialize();
    const io = context.io;
    var executable = try process.Executable.open(io, argv[0]);
    defer executable.close(io);
    const directory = try files.openDirectory(io, cwd, .private);
    defer directory.close(io);
    var env = std.process.Environ.Map.init(context.allocator);
    defer env.deinit();
    for ([_]struct { key: []const u8, val: []const u8 }{
        .{ .key = "HOME", .val = context.compute },
        .{ .key = "LANG", .val = "C" },
        .{ .key = "LC_ALL", .val = "C" },
        .{ .key = "PATH", .val = "/usr/bin:/bin" },
        .{ .key = "ZIG_LOCAL_CACHE_DIR", .val = try subpath(context, "cache") },
        .{ .key = "ZIG_GLOBAL_CACHE_DIR", .val = try subpath(context, "global-cache") },
    }) |item| try env.put(item.key, item.val);
    const primary = try process.Deadline.afterMilliseconds(@as(u64, timeout) * 1000);
    var result = try process.runCommand(context.allocator, io, .{
        .executable = executable,
        .argv = argv,
        .environment = &env,
        .cwd = directory,
        .primary_deadline = primary,
        .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, primary.expires_ns, 10 * std.time.ns_per_s) },
        .cancel = context.signal.flag(),
        .snapshot_executable = false,
        .limits = .{ .stdout_bytes = @min(bound + 1, 4 * limits.mib), .stderr_bytes = 4 * 1024, .term_grace_ms = 1000 },
    });
    defer result.deinit(context.allocator);
    const combined = try std.mem.concat(context.allocator, u8, &.{ result.stdout, result.stderr });
    const log_dir = try contextDir(context, "private");
    defer log_dir.close(io);
    try create(io, log_dir, try std.fmt.allocPrint(context.allocator, "{s}.log", .{stage}), combined[0..@min(combined.len, bound + 1)]);
    if (!result.cleanup_complete or !result.executable_stable) return error.CleanupPoisoned;
    if (!result.succeeded() or combined.len > bound) return error.BootstrapCommandFailed;
    try requireBootstrapInputs(context);
    return context.allocator.dupe(u8, result.stdout);
}

fn freezeBootstrapInputs(context: *Context) !void {
    const a = context.allocator;
    const files_bound = try a.alloc(inputs.Binding, inputs.host_tools.len + 2);
    files_bound[0] = .{ .role = "command-supervisor", .path = context.roots.supervisor };
    files_bound[1] = .{ .role = "wamr-source-archive", .path = try join(context, &.{ context.runtime, "custody/wamr-source.tar" }) };
    for (inputs.host_tools, context.tools, 0..) |name, path, i|
        files_bound[i + 2] = .{ .role = try std.fmt.allocPrint(a, "tool:{s}", .{name}), .path = path };
    const trees_bound = try a.alloc(inputs.Binding, 3);
    trees_bound[0] = .{ .role = "bison", .path = try join(context, &.{ context.runtime, "bison" }) };
    trees_bound[1] = .{ .role = "zig", .path = std.fs.path.dirname(context.roots.zig) orelse return error.UnsafePath };
    trees_bound[2] = .{ .role = "python-stdlib", .path = try pythonStdlib(context) };
    context.bootstrap_inputs = try inputs.capture(a, context.io, files_bound, trees_bound);
    context.bootstrap_files = files_bound;
    context.bootstrap_trees = trees_bound;
}

fn requireBootstrapInputs(context: *Context) !void {
    try inputs.requireSame(context.allocator, context.io, context.bootstrap_inputs orelse return error.UnboundInputs, context.bootstrap_files, context.bootstrap_trees);
}

fn restoreDependencies(context: *Context) !void {
    const a = context.allocator;
    const io = context.io;
    context.failed_operation = "create-restore";
    const restore_root = try subpath(context, "dependencies");
    const work = try files.openDirectory(io, context.compute, .private);
    defer work.close(io);
    try work.createDir(io, "dependencies", .fromMode(0o700));
    const dir = try files.openDirectory(io, restore_root, .private);
    defer dir.close(io);
    context.failed_operation = "tracked-manifests";
    const manifests = try dependencies.sourceManifests(a, io, context.repository, context.git);
    defer for (manifests) |manifest| manifest.deinit(a);
    for (manifests, [_][]const u8{ "build.zig", "build.zig.zon" }) |manifest, name|
        try create(io, dir, name, manifest.content);
    try dependencies.pinnedManifest(a, manifests[1].content);
    try dir.createDir(io, "zig-pkg", .fromMode(0o700));
    context.failed_operation = "fetch-pinned-package";
    _ = try runBootstrap(context, "dependency-restore", &.{
        context.roots.zig,                    "build",       "--build-file",                try join(context, &.{ restore_root, "build.zig" }),
        "--fetch=all",                        "--cache-dir", try subpath(context, "cache"), "--global-cache-dir",
        try subpath(context, "global-cache"), "-j2",
    }, restore_root, 900, 8 * limits.mib);
    const packages = try join(context, &.{ restore_root, "zig-pkg" });
    context.failed_operation = "inventory-packages";
    var listing = try dependencies.packageSet(a, io, packages);
    defer listing.deinit(a);
    const hash_work = try subpath(context, "dependency-hash-work");
    try work.createDir(io, "dependency-hash-work", .fromMode(0o700));
    const hash_dir = try files.openDirectory(io, hash_work, .private);
    defer hash_dir.close(io);
    try create(io, hash_dir, "build.zig", manifests[0].content);
    try create(io, hash_dir, "build.zig.zon", manifests[1].content);
    try hash_dir.createDir(io, "zig-pkg", .fromMode(0o700));
    try work.createDir(io, "dependency-hash-cache", .fromMode(0o700));
    context.failed_operation = "verify-package-hashes";
    for (listing.packages, 0..) |package, index| {
        const name = try std.fmt.allocPrint(a, "dependency-hash-{d:0>3}", .{index});
        const raw = try runBootstrap(context, name, &.{
            context.roots.zig,                             "fetch",                                         "--global-cache-dir",
            try subpath(context, "dependency-hash-cache"), try join(context, &.{ packages, package.name }),
        }, hash_work, 300, 511);
        if (!std.mem.eql(u8, raw, try std.fmt.allocPrint(a, "{s}\n", .{package.name})))
            return error.PackageHashMismatch;
    }
    context.failed_operation = "record-dependencies";
    context.dependency = try dependencies.capture(a, io, context.repository, context.git, context.compute);
}

pub fn restore(state: WamrArchiveSealed) !DependenciesRestored {
    const context = state.context;
    context.failed_stage = "dependency-restore";
    context.failed_operation = "bind-bootstrap-inputs";
    try freezeBootstrapInputs(context);
    try restoreDependencies(context);
    context.failed_operation = "verify-bootstrap-inputs";
    try requireBootstrapInputs(context);
    return next(state, DependenciesRestored);
}

pub fn bootstrap(state: DependenciesRestored) !BootstrapInputsBound {
    const context = state.context;
    context.failed_stage = "bootstrap";
    try custody.verifyPhysical(context.io, context.allocator, context.repository);
    try requireSource(context);
    try requireBootstrapInputs(context);
    try dependencies.requireDocument(context.allocator, context.io, context.repository, context.git, context.compute, context.dependency.?);
    return next(state, BootstrapInputsBound);
}

pub fn requireSource(context: *Context) !void {
    try cancelled(context);
    const actual = try custody.source(context.allocator, context.io, context.repository, context.git);
    try cancelled(context);
    const before = context.source.?;
    if (!before.same(actual)) return error.SourceChanged;
}

fn runStage(state: anytype, selected: plan.Stage, check_consumer: bool) !void {
    const context = state.context;
    context.failed_stage = @tagName(selected);
    try cancelled(context);
    try requireBuildEvidence(context);
    try requireSource(context);
    try dependencies.requireDocument(context.allocator, context.io, context.repository, context.git, context.compute, context.dependency.?);
    if (check_consumer) try requireConsumer(context) else try requireBootstrapInputs(context);
    const private = try contextDir(context, "private");
    defer private.close(context.io);
    const evidence_dir = try contextDir(context, "evidence");
    defer evidence_dir.close(context.io);
    const result = try adapter.execute(context.allocator, context.io, .{
        .roots = context.roots,
        .stage = selected,
        .private_dir = private,
        .evidence_dir = evidence_dir,
        .cancel = context.signal.flag(),
    });
    if (result.poisoned) return error.CleanupPoisoned;
    if (!result.accepted) return error.StageRefused;
    const record_path = try subpath(context, try std.fmt.allocPrint(context.allocator, "evidence/command-{s}.json", .{@tagName(selected)}));
    context.command_records[@intFromEnum(selected)] = try physical.readFile(context.io, record_path, limits.tracked_file, true);
    try requireBuildEvidence(context);
    try requireSource(context);
    try dependencies.requireDocument(context.allocator, context.io, context.repository, context.git, context.compute, context.dependency.?);
    if (check_consumer) try requireConsumer(context) else try requireBootstrapInputs(context);
}

pub fn requireBuildEvidence(context: *Context) !void {
    for (std.enums.values(plan.Stage), context.command_records) |stage, expected| {
        try cancelled(context);
        const recorded = expected orelse continue;
        const relative = try std.fmt.allocPrint(context.allocator, "evidence/command-{s}.json", .{@tagName(stage)});
        defer context.allocator.free(relative);
        const path = try subpath(context, relative);
        defer context.allocator.free(path);
        const current = try physical.readFile(context.io, path, limits.tracked_file, true);
        if (!std.meta.eql(current, recorded)) return error.CommandEvidenceChanged;
    }
    if (context.build_start_record) |recorded| {
        try cancelled(context);
        const path = try subpath(context, "evidence/build-start.json");
        defer context.allocator.free(path);
        const current = try physical.readFile(context.io, path, limits.tracked_file, true);
        if (!std.meta.eql(current, recorded)) return error.BuildStartChanged;
    }
    if (context.fixture_report) |recorded| {
        try cancelled(context);
        const path = try subpath(context, "fixtures/native-scenarios.json");
        defer context.allocator.free(path);
        const current = try physical.readFile(context.io, path, 8192, true);
        if (!std.meta.eql(current, recorded)) return error.FixtureChanged;
    }
}

pub fn requireConsumer(context: *Context) !void {
    try cancelled(context);
    const observed = context.consumer orelse return error.UnboundInputs;
    try inputs.requireProduction(context.allocator, context.io, .{
        .runtime = context.runtime,
        .tools = context.tools,
        .python_stdlib = try pythonStdlib(context),
    }, observed.custody);
    try cancelled(context);
}

fn pythonStdlib(context: *Context) ![]const u8 {
    const python = context.tools[1];
    try process.initialize();
    var executable = try process.Executable.open(context.io, python);
    defer executable.close(context.io);
    const cwd = try files.openDirectory(context.io, context.repository, .artifact);
    defer cwd.close(context.io);
    var env = std.process.Environ.Map.init(context.allocator);
    defer env.deinit();
    try env.put("PYTHONDONTWRITEBYTECODE", "1");
    const deadline = try process.Deadline.afterMilliseconds(30_000);
    var result = try process.runCommand(context.allocator, context.io, .{
        .executable = executable,
        .argv = &.{ python, "-c", "import sysconfig; print(sysconfig.get_path('stdlib'))" },
        .environment = &env,
        .cwd = cwd,
        .primary_deadline = deadline,
        .cleanup_deadline = .{ .expires_ns = try std.math.add(u64, deadline.expires_ns, 10 * std.time.ns_per_s) },
        .cancel = context.signal.flag(),
        .snapshot_executable = false,
        .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
    });
    defer result.deinit(context.allocator);
    if (!result.succeeded() or result.stderr.len != 0 or
        result.stdout.len < 2 or result.stdout[result.stdout.len - 1] != '\n')
        return error.InvalidPythonStdlib;
    return context.allocator.dupe(u8, result.stdout[0 .. result.stdout.len - 1]);
}

pub fn buildAdapter(state: BootstrapInputsBound) !AdapterBuilt {
    try runStage(state, .adapter, false);
    return next(state, AdapterBuilt);
}

pub fn baseline(state: LocalBootBuilt) !InputsBaselined {
    const context = state.context;
    context.failed_stage = "build-start";
    try requireBuildEvidence(context);
    try requireBootstrapInputs(context);
    context.consumer = try inputs.captureProduction(context.allocator, context.io, .{
        .runtime = context.runtime,
        .tools = context.tools,
        .python_stdlib = try pythonStdlib(context),
    });
    try requireBootstrapInputs(context);
    const document = try buildStart(context);
    try evidence(context, "build-start.json", document);
    context.build_start_record = try physical.readFile(context.io, try subpath(context, "evidence/build-start.json"), limits.tracked_file, true);
    try requireBuildEvidence(context);
    return next(state, InputsBaselined);
}

fn buildStart(context: *Context) !std.json.Value {
    const a = context.allocator;
    var value = std.json.Value{ .object = .empty };
    const origin = context.source.?;
    const source_id = try typedValue(a, .{ .revision = origin.revision, .tree = origin.tree });
    try value.object.put(a, "source", source_id);
    try value.object.put(a, "source_custody", try typedValue(a, origin.custody));
    var tools = std.json.Value{ .object = .empty };
    for (inputs.host_tools, context.tools) |name, path| {
        const item = try physical.readFile(context.io, path, limits.tracked_file, false);
        try tools.object.put(a, name, .{ .string = try a.dupe(u8, &item.sha256) });
    }
    try value.object.put(a, "tools", tools);
    try value.object.put(a, "bison_data", try typedValue(a, try inputs.bison(a, context.io, try join(context, &.{ context.runtime, "bison" }))));
    const dep = try context.dependency.?.canonical(a);
    try value.object.put(a, "dependencies", try rawValue(a, dep));
    const consumer = try context.consumer.?.custody.canonical(a);
    try value.object.put(a, "consumer_inputs", try rawValue(a, consumer));
    try value.object.put(a, "command_supervisor", try supervisorState(context));
    return value;
}

fn typedValue(allocator: std.mem.Allocator, typed: anytype) !std.json.Value {
    return rawValue(allocator, try std.json.Stringify.valueAlloc(allocator, typed, .{}));
}

fn rawValue(allocator: std.mem.Allocator, raw: []const u8) !std.json.Value {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{ .allocate = .alloc_always });
    return parsed.value;
}

fn supervisorState(context: *Context) !std.json.Value {
    const a = context.allocator;
    const source_map = try supervisorSourceMap(context);
    const runtime_map = try supervisorRuntimeMap(context);
    return typedValue(a, .{
        .schema = "uk.wamr.command-supervisor",
        .version = 1,
        .protocol = "uk.wamr.command-supervisor/1 process-command/1",
        .source_map = source_map,
        .runtime_map = runtime_map,
    });
}

const Map = struct {
    count: usize,
    bytes: usize,
    content_closure_sha256: [64]u8,
    physical_closure_sha256: [64]u8,
    records: std.json.Value,
};
const MapEntry = struct { name: []const u8, file: physical.File };

fn guardedMap(context: *Context, domain: []const u8, sorted: []const MapEntry) !Map {
    const a = context.allocator;
    var content = Sha256.init(.{});
    content.update(try std.fmt.allocPrint(a, "{s}-content\x00", .{domain}));
    var physical_hash = Sha256.init(.{});
    physical_hash.update(try std.fmt.allocPrint(a, "{s}-physical\x00", .{domain}));
    var result = std.json.Value{ .object = .empty };
    var total: usize = 0;
    for (sorted) |entry| {
        try limits.addBounded(&total, @intCast(entry.file.bytes), limits.tracked_bytes);
        try physical.bind(a, &content, .{ entry.name, entry.file.bytes, entry.file.sha256 });
        try physical.bind(a, &physical_hash, .{ entry.name, entry.file.metadata });
        try result.object.put(a, entry.name, try typedValue(a, .{
            .bytes = entry.file.bytes,
            .sha256 = entry.file.sha256,
            .metadata = entry.file.metadata,
        }));
    }
    return .{
        .count = sorted.len,
        .bytes = total,
        .content_closure_sha256 = physical.hex(&content),
        .physical_closure_sha256 = physical.hex(&physical_hash),
        .records = result,
    };
}

fn supervisorSourceMap(context: *Context) !Map {
    const a = context.allocator;
    var entries: std.ArrayList(MapEntry) = .empty;
    for (custody.closure) |entry| {
        const file = try physical.readFile(context.io, try join(context, &.{ context.repository, entry.name }), limits.tracked_file, false);
        try entries.append(a, .{ .name = entry.name, .file = file });
    }
    return guardedMap(context, "uk.wamr.command-supervisor-source-v1", entries.items);
}

fn supervisorRuntimeMap(context: *Context) !Map {
    const a = context.allocator;
    var entries: std.ArrayList(MapEntry) = .empty;
    const binary = try physical.readFile(context.io, context.roots.supervisor, limits.tracked_file, false);
    try entries.append(a, .{ .name = "executable", .file = binary });
    const runtime_paths = try inputs.executableRuntimePaths(a, context.io, context.roots.supervisor);
    for (runtime_paths) |path| {
        const role = try std.fmt.allocPrint(a, "runtime:{s}", .{path});
        try entries.append(a, .{ .name = role, .file = try physical.readFile(context.io, path, limits.tracked_file, false) });
    }
    return guardedMap(context, "uk.wamr.command-supervisor-runtime-v1", entries.items);
}

pub fn buildLocalBoot(state: AdapterBuilt) !LocalBootBuilt {
    try runStage(state, .@"local-boot-tool", false);
    return next(state, LocalBootBuilt);
}

pub fn testFixtures(state: InputsBaselined) !NativeFixturesPassed {
    try runStage(state, .fixtures, true);
    const context = state.context;
    const path = try subpath(context, "fixtures/native-scenarios.json");
    const output = try read(context, path, 8192, true);
    try fixture_contract.verify(context.allocator, output);
    context.fixture_report = try physical.readFile(context.io, path, 8192, true);
    try requireBuildEvidence(context);
    return next(state, NativeFixturesPassed);
}

pub fn prepare(state: NativeFixturesPassed) !ProducerPrepared {
    try runStage(state, .prepare, true);
    try verifyRuntimeIdentity(state.context);
    return next(state, ProducerPrepared);
}

fn verifyRuntimeIdentity(context: *Context) !void {
    try cancelled(context);
    const a = context.allocator;
    const artifact_dir = try join(context, &.{ context.repository, "support/apps/wamr-aot/build/artifacts" });
    const raw = try read(context, try join(context, &.{ artifact_dir, "identity.json" }), limits.mib, false);
    const parsed = try core.contracts.Document.parse(a, raw, .{});
    defer parsed.deinit();
    try admitPreparedIdentity(parsed.value());
    const artifacts = parsed.value().object.get("files").?.object;
    for ([_][]const u8{ "embedded.c", "identity.h", "libwamr-aot.a", "tiny.cwasm", "tiny.wasm", "wamr_aot.h", "wamrc" }) |name| {
        try cancelled(context);
        const digest = try core.contracts.parseSha256(try core.contracts.string(artifacts.get(name).?));
        const file = try physical.readFile(context.io, try join(context, &.{ artifact_dir, name }), limits.tracked_file, false);
        if (!std.meta.eql(digest, try core.contracts.parseSha256(&file.sha256))) return error.ArtifactChanged;
    }
}

pub fn admitPreparedIdentity(value: std.json.Value) !void {
    if (value != .object) return error.InvalidProducer;
    const object = value.object;
    const revision = try core.contracts.string(object.get("wamr_revision") orelse return error.InvalidProducer);
    const jit = object.get("jit_mode") orelse std.json.Value.null;
    const development = object.get("development_only") orelse std.json.Value{ .bool = false };
    const wasi = object.get("minimal_wasi") orelse return error.InvalidProducer;
    if (!std.mem.eql(u8, revision, limits.wamr_revision) or
        !std.mem.eql(u8, try core.contracts.string(object.get("variant") orelse std.json.Value{ .string = "tiny" }), "tiny") or
        !std.mem.eql(u8, try core.contracts.string(object.get("compiler_profile") orelse return error.InvalidProducer), "unikraft-x86_64") or
        !std.mem.eql(u8, try core.contracts.string(object.get("zig_version") orelse return error.InvalidProducer), "0.16.0") or
        jit != .null)
        return error.InvalidProducer;
    if (development != .bool or development.bool or wasi != .bool or wasi.bool)
        return error.InvalidProducer;
    const artifacts = (object.get("files") orelse return error.InvalidProducer);
    if (artifacts != .object or artifacts.object.count() != 7) return error.InvalidProducer;
    for ([_][]const u8{ "embedded.c", "identity.h", "libwamr-aot.a", "tiny.cwasm", "tiny.wasm", "wamr_aot.h", "wamrc" }) |name| {
        _ = try core.contracts.parseSha256(try core.contracts.string(artifacts.object.get(name) orelse return error.InvalidProducer));
    }
}

pub fn solveConfig(state: ProducerPrepared) !ConfigSolved {
    const context = state.context;
    try runStage(state, .config, true);
    const app = try join(context, &.{ context.repository, "support/apps/wamr-aot" });
    try absent(context.io, try join(context, &.{ app, ".config.old" }));
    const solved = try read(context, try join(context, &.{ app, "build/.config" }), limits.mib, true);
    const app_dir = try files.openDirectory(context.io, app, .artifact);
    defer app_dir.close(context.io);
    const before_parent = try files.snapshot(.{ .handle = app_dir.handle, .flags = .{ .nonblocking = false } });
    const destination = try app_dir.openFile(context.io, ".config", .{
        .mode = .read_write,
        .follow_symlinks = false,
    });
    defer destination.close(context.io);
    const before = try files.snapshot(destination);
    if (before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or
        before.uid != std.os.linux.geteuid() or before.mode & 0o7777 != 0o600 or before.nlink != 1)
        return error.UnsafeConfig;
    try destination.setLength(context.io, 0);
    try destination.writePositionalAll(context.io, solved, 0);
    try destination.sync(context.io);
    const named = try app_dir.openFile(context.io, ".config", .{ .follow_symlinks = false });
    defer named.close(context.io);
    if (!files.sameSnapshot(try files.snapshot(destination), try files.snapshot(named)) or
        !files.sameSnapshot(before_parent, try files.snapshot(.{ .handle = app_dir.handle, .flags = .{ .nonblocking = false } })))
        return error.ConfigChanged;
    const retained = try read(context, try join(context, &.{ app, ".config" }), limits.mib, false);
    if (!std.mem.eql(u8, retained, solved)) return error.ConfigChanged;
    return next(state, ConfigSolved);
}

pub fn nativeImage(state: ConfigSolved) !NativeImageBuilt {
    try runStage(state, .@"native-image", true);
    const context = state.context;
    const app = try join(context, &.{ context.repository, "support/apps/wamr-aot" });
    const solved = try read(context, try join(context, &.{ app, "build/.config" }), limits.mib, true);
    if (!std.mem.eql(u8, solved, try read(context, try join(context, &.{ app, ".config" }), limits.mib, false)))
        return error.ConfigChanged;
    return next(state, NativeImageBuilt);
}

pub fn acceptBuild(state: NativeImageBuilt) !BuildAccepted {
    const context = state.context;
    context.failed_stage = "build";
    try publishBuild(context, try buildValue(context));
    return .{ .context = context };
}

pub fn buildValue(context: *Context) !std.json.Value {
    try cancelled(context);
    try requireBuildEvidence(context);
    try requireSource(context);
    try requireConsumer(context);
    try dependencies.requireDocument(context.allocator, context.io, context.repository, context.git, context.compute, context.dependency.?);
    try cancelled(context);
    try verifyRuntimeIdentity(context);
    const a = context.allocator;
    const app = try join(context, &.{ context.repository, "support/apps/wamr-aot" });
    const image = try read(context, try join(context, &.{ app, "build/image-identity.json" }), limits.mib, false);
    const parsed = try core.contracts.Document.parse(a, image, .{});
    defer parsed.deinit();
    const value = parsed.value().object;
    if (try core.contracts.integer(u8, value.get("schema_version") orelse return error.InvalidImage) != 1 or
        !std.mem.eql(u8, try core.contracts.string(value.get("unikraft_revision") orelse return error.InvalidImage), context.source.?.revision))
        return error.InvalidImage;
    const empty_hash = std.fmt.bytesToHex(records.fileIdentity(""), .lower);
    if (!std.mem.eql(u8, try core.contracts.string(value.get("unikraft_diff_sha256") orelse return error.InvalidImage), &empty_hash))
        return error.DirtyImageSource;
    const app_identity = try read(context, try join(context, &.{ app, "build/artifacts/identity.json" }), limits.mib, false);
    const runtime_hash = try core.contracts.parseSha256(try core.contracts.string(value.get("runtime_inputs_sha256") orelse return error.InvalidImage));
    if (!std.meta.eql(runtime_hash, records.fileIdentity(app_identity))) return error.ImageInputsChanged;
    const solved = try read(context, try join(context, &.{ app, "build/.config" }), limits.mib, false);
    if (!std.mem.eql(u8, solved, try read(context, try join(context, &.{ app, ".config" }), limits.mib, false)))
        return error.ConfigChanged;
    const solved_hash = std.fmt.bytesToHex(records.fileIdentity(solved), .lower);
    if (!std.mem.eql(u8, try core.contracts.string(value.get("solved_config_sha256") orelse return error.InvalidImage), &solved_hash))
        return error.ConfigChanged;
    const image_files = value.get("files") orelse return error.InvalidImage;
    if (image_files != .object or image_files.object.count() != 3) return error.InvalidImage;
    const efi = "wamr_hyperv-x86_64-efi";
    for ([_][]const u8{ efi, efi ++ ".dbg", efi ++ ".bootinfo" }) |name| {
        try cancelled(context);
        const digest = try core.contracts.parseSha256(try core.contracts.string(image_files.object.get(name) orelse return error.InvalidImage));
        const file = try physical.readFile(context.io, try join(context, &.{ app, "build", name }), limits.tracked_file, false);
        if (!std.meta.eql(digest, try core.contracts.parseSha256(&file.sha256))) return error.ImageChanged;
    }
    const app_sources = value.get("application_sources") orelse return error.InvalidImage;
    if (app_sources != .object) return error.InvalidImage;
    const app_dir = try files.openDirectory(context.io, app, .artifact);
    defer app_dir.close(context.io);
    var iterator = app_dir.iterate();
    var count: usize = 0;
    while (try iterator.next(context.io)) |entry| {
        try cancelled(context);
        if (entry.name[0] == '.' or entry.kind == .directory) continue;
        const path = try join(context, &.{ app, entry.name });
        const expected = try core.contracts.parseSha256(try core.contracts.string(app_sources.object.get(entry.name) orelse return error.AppSourceChanged));
        const actual = try physical.readFile(context.io, path, limits.tracked_file, false);
        if (!std.meta.eql(expected, try core.contracts.parseSha256(&actual.sha256))) return error.AppSourceChanged;
        count += 1;
    }
    if (count != app_sources.object.count()) return error.AppSourceChanged;
    const image_tools = value.get("tools") orelse return error.InvalidImage;
    if (image_tools != .object or image_tools.object.count() != 9) return error.InvalidImage;
    for ([_][]const u8{ "zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf", "llvm-strip", "bison", "flex" }) |name| {
        try cancelled(context);
        const selected = try core.contracts.parseSha256(try core.contracts.string(image_tools.object.get(name) orelse return error.ImageToolsChanged));
        for (inputs.host_tools, context.tools) |known, path| {
            if (!std.mem.eql(u8, name, known)) continue;
            const actual = try physical.readFile(context.io, path, limits.tracked_file, false);
            if (!std.meta.eql(selected, try core.contracts.parseSha256(&actual.sha256))) return error.ImageToolsChanged;
            break;
        }
    }
    for ([_][]const u8{
        "CONFIG_APPWAMRAOT=y", "CONFIG_ARCH_X86_64=y", "CONFIG_PLAT_HYPERV=y",
        "CONFIG_LIBUKVMEM=y",  "CONFIG_LIBUKPAGING=y", "CONFIG_UKPLAT_CPU_MAXCOUNT=1",
    }) |setting| if (countLine(solved, setting) != 1) return error.InvalidConfig;
    for ([_][]const u8{
        "CONFIG_APPHYPERVACCEPTANCE=y", "CONFIG_APPHYPERVSMPWORKLOAD=y",
        "CONFIG_LIBSTORVSC=y",          "CONFIG_LIBNETVSC=y",
        "CONFIG_LIBLWIP=y",
    }) |setting| if (countLine(solved, setting) != 0) return error.InvalidConfig;
    return typedValue(a, .{
        .source = .{ .revision = context.source.?.revision, .tree = context.source.?.tree },
        .runtime = try rawValue(a, app_identity),
        .image = try rawValue(a, image),
    });
}

/// Reconstruct the frozen build state from its actual source, dependency,
/// executable and image inputs; boot never republishes build evidence.
pub fn loadAccepted(context: *Context) !void {
    const a = context.allocator;
    const io = context.io;
    try cancelled(context);
    const expected = try readAcceptedRecord(context, "build-start.json");
    const document = try core.contracts.Document.parse(a, expected, .{ .bytes = records.max_record_bytes, .items = 4096, .tokens = 65536, .depth = 32 });
    defer document.deinit();
    try document.requireCanonical(a, expected);
    const original = try core.contracts.exactFields(document.value(), &.{
        "source", "source_custody", "tools", "bison_data", "dependencies", "consumer_inputs", "command_supervisor",
    });
    const consumer = original.get("consumer_inputs").?;
    if (consumer != .object) return error.InvalidInputCustody;
    const selected = consumer.object.get("files") orelse return error.InvalidInputCustody;
    if (selected != .object) return error.InvalidInputCustody;
    for (inputs.host_tools, 0..) |name, index| {
        const role = try std.fmt.allocPrint(a, "tool:{s}", .{name});
        const record = selected.object.get(role) orelse return error.MissingTool;
        if (record != .object) return error.InvalidInputCustody;
        context.tools[index] = try a.dupe(u8, try core.contracts.string(record.object.get("path") orelse return error.MissingTool));
    }
    context.git = context.tools[0];
    const own = try join(context, &.{ context.runtime, "controller/bin/uk-wamr-native-ci" });
    if (!std.mem.eql(u8, own, try std.process.executablePathAlloc(io, a)))
        return error.UnboundController;
    context.roots = .{
        .runtime = context.runtime, .source_root = context.repository, .work = context.compute,
        .zig = context.tools[9], .producer = try subpath(context, "tools/bin/uk-wamr-aot-build"),
        .fixture_runner = try subpath(context, "tools/bin/wamr-native-ci-fixtures"),
        .supervisor = own, .package_tool = try subpath(context, "tools/bin/wamr-ci-package"),
        .validator = try subpath(context, "tools/bin/uk-wamr-log-validate"),
        .supervisor_fixture = try subpath(context, "tools/bin/wamr-ci-supervisor-fixture"),
        .tools = context.tools,
    };
    try custody.verifyPhysical(io, a, context.repository);
    context.source = try custody.source(a, io, context.repository, context.git);
    context.dependency = try dependencies.capture(a, io, context.repository, context.git, context.compute);
    context.consumer = try inputs.captureProduction(a, io, .{
        .runtime = context.runtime, .tools = context.tools,
        .python_stdlib = try pythonStdlib(context),
    });
    const reproduced = try typedValue(a, try buildStart(context));
    const encoded = try std.json.Stringify.valueAlloc(a, reproduced, .{});
    const canonical = try records.canonicalAlloc(a, encoded);
    if (!std.mem.eql(u8, expected, canonical)) return error.BuildStartChanged;
    context.build_start_record = try physical.readFile(io, try subpath(context, "evidence/build-start.json"), limits.tracked_file, true);
    for ([_]plan.Stage{ .adapter, .@"local-boot-tool", .fixtures, .prepare, .config, .@"native-image" }) |stage| {
        const name = try std.fmt.allocPrint(a, "evidence/command-{s}.json", .{@tagName(stage)});
        const path = try subpath(context, name);
        const raw = try read(context, path, records.max_record_bytes, true);
        const command = try core.contracts.Document.parse(a, raw, .{ .bytes = records.max_record_bytes });
        defer command.deinit();
        try command.requireCanonical(a, raw);
        if (command.value() != .object) return error.InvalidCommand;
        const object = command.value().object;
        if (!std.mem.eql(u8, try core.contracts.string(object.get("stage") orelse return error.InvalidCommand), @tagName(stage)) or
            try core.contracts.integer(i32, object.get("exit_code") orelse return error.InvalidCommand) != 0)
            return error.BuildStageRefused;
        context.command_records[@intFromEnum(stage)] = try physical.readFile(io, path, limits.tracked_file, true);
    }
    try revalidateAccepted(context);
}

pub fn revalidateAccepted(context: *Context) !void {
    const actual = try readAcceptedRecord(context, "build.json");
    const value = try buildValue(context);
    const encoded = try std.json.Stringify.valueAlloc(context.allocator, value, .{});
    if (!std.mem.eql(u8, actual, try records.canonicalAlloc(context.allocator, encoded)))
        return error.BuildChanged;
}

pub fn publishBuild(context: *Context, value: anytype) !void {
    try cancelled(context);
    try evidence(context, "build.json", value);
}

fn countLine(bytes: []const u8, target: []const u8) usize {
    var found: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| if (std.mem.eql(u8, line, target)) {
        found += 1;
    };
    return found;
}

pub fn run(context: *Context) !BuildAccepted {
    var bound = try bind(.{ .context = context });
    defer bound.runtime.close(context.io);
    var reserved = try reserve(bound);
    defer reserved.work.close(context.io);
    return acceptBuild(try nativeImage(try solveConfig(try prepare(try testFixtures(
        try baseline(try buildLocalBoot(try buildAdapter(try bootstrap(
            try restore(try sealSource(try captureSource(reserved))),
        )))),
    )))));
}
