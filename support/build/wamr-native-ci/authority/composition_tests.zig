// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const authority = @import("root.zig");
const synthetic = @import("runtime_probes_tests.zig").synthetic;
const a = std.testing.allocator;
const io = std.testing.io;
const linux = std.os.linux;
const options = @import("test_options");

test "source handler dispatch never acquires missing retained authority or commitments" {
    const ctx: authority.handlers.Context = .{ .retained = .{ .allocator = a, .io = io } };
    try std.testing.expectEqual(error.MissingImportedContext, authority.handlers.run(ctx, .{ .plan = .{} }).plan.refused.err);
    try std.testing.expectEqual(error.MissingDiscoveryContext, authority.handlers.run(ctx, .{ .@"prepare-azure-runtime" = .{} }).prepare.refused.err);
    try std.testing.expectEqual(error.MissingIndependentCommitments, authority.handlers.run(ctx, .{ .admit = .{} }).admission.refused.err);
    const now: i128 = std.Io.Clock.real.now(io).toSeconds();
    const command: authority.types.AuthorizationCommand = .{
        .recorded_unix = now - 1,
        .expires_unix = now,
        .approver = "source-only",
        .reference = "not permission",
    };
    try std.testing.expectEqual(error.ApprovalExpired, authority.handlers.run(ctx, .{ .@"record-authorization" = command }).authorization.refused.err);

    var parsed_prepare = try authority.cli.parse(a, &.{
        "prepare-azure-runtime",
        "--output=/explicit/output",
        "--azure=/explicit/azure",
        "--az-python=/explicit/python",
        "--stdlib=/explicit/stdlib",
        "--validator=/explicit/validator",
        "--package-root=/explicit/packages",
    });
    defer parsed_prepare.deinit();
    try std.testing.expectEqual(error.MissingDiscoveryContext, authority.handlers.run(ctx, parsed_prepare.result.command).prepare.refused.err);

    var parsed_plan = try authority.cli.parse(a, &.{
        "plan",
        "--bundle=/explicit/bundle.json",
        "--output=/explicit/plan.json",
        "--approval-template=/explicit/template.json",
        "--candidate-output=/explicit/candidate.json",
        "--campaign-id=00000000-0000-4000-8000-000000000010",
        "--ledger=/explicit/ledger",
        "--subscription=00000000-0000-4000-8000-000000000001",
        "--prefix=not-admitted-candidate",
        "--maximum-authorized-cost-microusd=15000000",
        "--azure=/explicit/azure",
        "--uploader=/explicit/uploader",
        "--validator=/explicit/validator",
        "--supervisor=/explicit/supervisor",
        "--az-python=/explicit/python",
        "--azure-runtime=/explicit/azure-runtime.json",
    });
    defer parsed_plan.deinit();
    try std.testing.expectEqual(error.MissingImportedContext, authority.handlers.run(ctx, parsed_plan.result.command).plan.refused.err);

    var parsed_admit = try authority.cli.parse(a, &.{
        "admit",
        "--plan=/explicit/plan.json",
        "--authorization=/explicit/authorization.json",
        "--output=/explicit/admission.json",
        "--azure=/explicit/azure",
        "--uploader=/explicit/uploader",
        "--validator=/explicit/validator",
        "--supervisor=/explicit/supervisor",
        "--az-python=/explicit/python",
        "--azure-runtime=/explicit/azure-runtime.json",
    });
    defer parsed_admit.deinit();
    try std.testing.expectEqual(error.MissingIndependentCommitments, authority.handlers.run(ctx, parsed_admit.result.command).admission.refused.err);
}

pub const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    parent: std.Io.Dir,
    dir: std.Io.Dir,
    name: []const u8,
    path: []const u8,
    interpreter: core.private_files.RetainedFile,
    loader: core.private_files.RetainedFile,
    request: authority.types.PrepareRuntime,

    pub fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        const name = try allocator.print("composition-{d}", .{linux.getpid()});
        const parent = try core.private_files.openDirectory(io, options.fixture_root, .private);
        errdefer parent.close(io);
        try parent.createDir(io, name, .fromMode(0o700));
        const dir = try parent.openDir(io, name, .{ .iterate = true });
        errdefer dir.close(io);
        const path = try std.fs.path.join(allocator, &.{ options.fixture_root, name });
        const loader_path = try std.fs.path.join(allocator, &.{ path, authority.runtime_probes.loader_basename });
        const interpreter_path = try std.fs.path.join(allocator, &.{ path, "python" });
        try write(dir, authority.runtime_probes.loader_basename, &(try synthetic(.{
            .role = .loader,
            .soname = authority.runtime_probes.loader_basename,
        })), 0o500);
        try write(dir, "python", &(try synthetic(.{ .role = .interpreter, .interpreter = loader_path })), 0o500);
        try write(dir, "azure", "not executable Python; source-negative only\n", 0o500);
        try dir.createDir(io, "python3.11", .fromMode(0o700));
        const library = try dir.openDir(io, "python3.11", .{});
        defer library.close(io);
        try write(library, "os.py", "source-negative stdlib\n", 0o600);
        // Schema-valid bytes are not executable closure evidence. Enumeration
        // of the copied tree must catch this without running synthetic ELF.
        try write(library, "_invalid.so", "\x7fELFdata-only invalid ELF\n", 0o600);
        var interpreter = try core.private_files.RetainedFile.open(io, interpreter_path, .artifact);
        errdefer interpreter.close(io);
        const loader = try core.private_files.RetainedFile.open(io, loader_path, .artifact);
        const request: authority.types.PrepareRuntime = .{
            .output = try std.fs.path.join(allocator, &.{ path, "output" }),
            .azure = try std.fs.path.join(allocator, &.{ path, "azure" }),
            .az_python = interpreter_path,
            .stdlib = try std.fs.path.join(allocator, &.{ path, "python3.11" }),
            .validator = try std.Io.Dir.cwd().realPathFileAlloc(io, options.validator, allocator),
        };
        return .{
            .arena = arena,
            .parent = parent,
            .dir = dir,
            .name = name,
            .path = path,
            .interpreter = interpreter,
            .loader = loader,
            .request = request,
        };
    }
    pub fn discovery(self: *Fixture) authority.runtime_probes.DiscoveryInput {
        return .{ .interpreter = &self.interpreter, .dynamic_loader = &self.loader, .native_roots = &.{}, .candidates = &.{} };
    }
    pub fn deinit(self: *Fixture) void {
        self.interpreter.close(io);
        self.loader.close(io);
        removable(self.dir) catch @panic("composition mode cleanup failed");
        self.dir.close(io);
        self.parent.deleteTree(io, self.name) catch @panic("composition cleanup failed");
        self.parent.close(io);
        self.arena.deinit();
    }
};
fn write(dir: std.Io.Dir, name: []const u8, bytes: []const u8, mode: u32) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    if (linux.errno(linux.fchmod(file.handle, mode)) != .SUCCESS) return error.FixtureMode;
    try file.sync(io);
}
fn removable(dir: std.Io.Dir) !void {
    if (linux.errno(linux.fchmod(dir.handle, 0o700)) != .SUCCESS) return error.FixtureMode;
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const child = try dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
        defer child.close(io);
        try removable(child);
    }
}
fn absent(dir: std.Io.Dir, path: []const u8) !void {
    const file = dir.openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    file.close(io);
    return error.UnexpectedPublication;
}

test "joined actual prepare retains physical manifest and refusal but never publishes a synthetic runtime" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const outcome = authority.handlers.run(.{
        .retained = .{ .allocator = a, .io = io },
        .discovery = fixture.discovery(),
    }, .{ .@"prepare-azure-runtime" = fixture.request }).prepare;
    const diagnostic = switch (outcome) {
        .poisoned => |failure| failure,
        .refused => return error.UnexpectedEarlyRefusal,
        .success => |owner| {
            owner.deinit();
            return error.SyntheticRuntimeAccepted;
        },
    };
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.copy);
    try std.testing.expectEqual(error.InvalidElf, diagnostic.err);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.manifest);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.pending);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, diagnostic.publications.output);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.failure);
    try std.testing.expect(diagnostic.recording_error == null);
    try absent(fixture.dir, "output/azure-runtime.json");
    var manifest = try core.private_files.RetainedFile.open(io, try std.fs.path.join(fixture.arena.allocator(), &.{ fixture.path, "output/azure-runtime.manifest" }), .private);
    defer manifest.close(io);
    try std.testing.expect(manifest.file_snapshot.size > 0);
    const second = authority.prepare.run(.{ .allocator = a, .io = io }, fixture.request, fixture.discovery());
    try std.testing.expectEqual(error.PathAlreadyExists, second.refused.err);
    try absent(fixture.dir, "output/azure-runtime.json");
}

test "joined prepare mismatched explicit interpreter cancellation and discovery mutation precede copy" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var request = fixture.request;
    request.az_python = fixture.request.azure;
    const ctx: authority.types.Context = .{ .allocator = a, .io = io };
    try std.testing.expectEqual(error.DiscoveryInterpreterMismatch, authority.prepare.run(ctx, request, fixture.discovery()).refused.err);
    try absent(fixture.dir, "output");
    var cancellation = try core.process.SignalCancellation.install();
    defer cancellation.deinit();
    if (linux.errno(linux.kill(linux.getpid(), .INT)) != .SUCCESS) return error.FixtureSignal;
    try std.testing.expectEqual(error.Cancelled, authority.prepare.run(.{ .allocator = a, .io = io, .signal = &cancellation }, fixture.request, fixture.discovery()).refused.err);
    try absent(fixture.dir, "output");
}

fn replaceDiscoveredInterpreter(raw: *anyopaque) !void {
    const fixture: *Fixture = @ptrCast(@alignCast(raw));
    const bytes = try fixture.dir.readFileAlloc(io, "python", a, .limited(65536));
    defer a.free(bytes);
    try write(fixture.dir, "replacement-python", bytes, 0o500);
    try fixture.dir.rename("replacement-python", fixture.dir, "python", io);
}

test "joined discovery refuses same-byte interpreter replacement before COPY acquires publication custody" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const hooks: authority.prepare.Test.Hooks = .{
        .context = &fixture,
        .after_discovery = replaceDiscoveredInterpreter,
    };
    const outcome = authority.prepare.Test.run(.{ .allocator = a, .io = io }, fixture.request, fixture.discovery(), &hooks);
    try std.testing.expect(outcome == .refused);
    try std.testing.expectEqual(error.FileChanged, outcome.refused.err);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.refused.publications.copy);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.refused.publications.manifest);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, outcome.refused.publications.output);
    try absent(fixture.dir, "output");
}

test "joined prepare with closed copied ELF tree passes native validator and copied inspection before isolated helper refuses synthetic runtime" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const allocator = fixture.arena.allocator();
    const loader_path = try std.fs.path.join(allocator, &.{ fixture.path, authority.runtime_probes.loader_basename });
    try fixture.dir.deleteFile(io, "python");
    try write(fixture.dir, "python", &(try synthetic(.{
        .role = .interpreter,
        .interpreter = loader_path,
        .needed = &.{"libalpha.so"},
    })), 0o500);
    fixture.interpreter.close(io);
    fixture.interpreter = try core.private_files.RetainedFile.open(io, fixture.request.az_python, .artifact);

    try write(fixture.dir, "libalpha.so", &(try synthetic(.{
        .role = .library,
        .needed = &.{"libbeta.so"},
        .soname = "libalpha.so",
    })), 0o400);
    try write(fixture.dir, "libbeta.so", &(try synthetic(.{
        .role = .library,
        .soname = "libbeta.so",
    })), 0o400);
    var alpha = try core.private_files.RetainedFile.open(io, try std.fs.path.join(allocator, &.{ fixture.path, "libalpha.so" }), .artifact);
    defer alpha.close(io);
    var beta = try core.private_files.RetainedFile.open(io, try std.fs.path.join(allocator, &.{ fixture.path, "libbeta.so" }), .artifact);
    defer beta.close(io);

    const library = try fixture.dir.openDir(io, "python3.11", .{ .iterate = true });
    defer library.close(io);
    try library.deleteFile(io, "_invalid.so");
    try library.createDir(io, "encodings", .fromMode(0o700));
    const encodings = try library.openDir(io, "encodings", .{});
    defer encodings.close(io);
    try write(encodings, "__init__.py", "source-negative encodings\n", 0o600);
    try write(library, "_ext.so", &(try synthetic(.{
        .role = .native_extension,
        .needed = &.{"libbeta.so"},
    })), 0o400);
    var ext = try core.private_files.RetainedFile.open(io, try std.fs.path.join(allocator, &.{ fixture.request.stdlib, "_ext.so" }), .artifact);
    defer ext.close(io);

    try fixture.dir.createDir(io, "packages", .fromMode(0o700));
    const packages = try fixture.dir.openDir(io, "packages", .{ .iterate = true });
    defer packages.close(io);
    try packages.createDir(io, "azure", .fromMode(0o700));
    const azure_pkg = try packages.openDir(io, "azure", .{});
    defer azure_pkg.close(io);
    try write(azure_pkg, "__init__.py", "source-negative azure\n", 0o600);
    const package_root = try std.fs.path.join(allocator, &.{ fixture.path, "packages" });

    var parsed_prepare = try authority.cli.parse(a, &.{
        "prepare-azure-runtime",
        try std.fmt.allocPrint(allocator, "--output={s}", .{fixture.request.output}),
        try std.fmt.allocPrint(allocator, "--azure={s}", .{fixture.request.azure}),
        try std.fmt.allocPrint(allocator, "--az-python={s}", .{fixture.request.az_python}),
        try std.fmt.allocPrint(allocator, "--stdlib={s}", .{fixture.request.stdlib}),
        try std.fmt.allocPrint(allocator, "--validator={s}", .{fixture.request.validator}),
        try std.fmt.allocPrint(allocator, "--package-root={s}", .{package_root}),
    });
    defer parsed_prepare.deinit();

    const outcome = authority.handlers.run(.{
        .retained = .{ .allocator = a, .io = io },
        .discovery = .{
            .interpreter = &fixture.interpreter,
            .dynamic_loader = &fixture.loader,
            .native_roots = &.{&ext},
            .candidates = &.{ &alpha, &beta },
        },
    }, parsed_prepare.result.command).prepare;
    const diagnostic = switch (outcome) {
        .poisoned => |failure| failure,
        .refused => return error.UnexpectedEarlyRefusal,
        .success => |owner| {
            owner.deinit();
            return error.SyntheticRuntimeAccepted;
        },
    };
    try std.testing.expectEqual(authority.types.Phase.validation, diagnostic.phase);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.copy);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.manifest);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.pending);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, diagnostic.publications.validation);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, diagnostic.publications.output);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.failure);
    try std.testing.expect(diagnostic.recording_error == null);
    try std.testing.expectEqual(core.diagnostics.Stage.process_run, diagnostic.failures.primary.?.stage);
    try std.testing.expectEqual(core.diagnostics.Category.child_failed, diagnostic.failures.primary.?.category);
    try std.testing.expect(diagnostic.failures.cleanup == null);
    try std.testing.expect(diagnostic.helper_cleanup_complete);
    try std.testing.expect(diagnostic.native_validation != null);
    try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, diagnostic.native_validation.?.primary);
    try std.testing.expect(diagnostic.native_validation.?.cleanup_complete);
    try std.testing.expect(diagnostic.probes != null);
    try std.testing.expectEqual(@as(u8, 0), diagnostic.probes.?.completed_steps);
    try absent(fixture.dir, "output/azure-runtime.validation.json");
    try absent(fixture.dir, "output/azure-runtime.json");

    const failure_bytes = try fixture.dir.readFileAlloc(io, "output/azure-runtime.failure.json", a, .limited(16384));
    defer a.free(failure_bytes);
    var failure_doc = try core.contracts.Document.parse(a, failure_bytes, authority.contracts.json_limits);
    defer failure_doc.deinit();
    try std.testing.expectEqualStrings("validation", failure_doc.value().object.get("phase").?.string);
    try std.testing.expect(failure_doc.value().object.get("helper_cleanup_complete").?.bool);
    try std.testing.expectEqualStrings("0", failure_doc.value().object.get("completed_steps").?.number_string);
    try std.testing.expect(failure_doc.value().object.get("native_validation").?.object.get("process").?.object.get("cleanup_complete").?.bool);
}

fn resolveHostLibrary(allocator: std.mem.Allocator, primary_dir: []const u8, name: []const u8) ![]const u8 {
    const search_dirs = [_][]const u8{
        primary_dir,
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib64",
    };
    for (search_dirs) |dir_path| {
        const candidate = try std.fs.path.join(allocator, &.{ dir_path, name });
        if (std.Io.Dir.cwd().realPathFileAlloc(io, candidate, allocator)) |resolved| {
            return resolved;
        } else |_| {}
    }
    return error.HostLibraryNotFound;
}

fn noopBarrierCheck(_: *anyopaque) !void {}

test "CLI prepare-azure-runtime stages real x86_64 ELF Python closure and executes all 19 closed probes" {
    if (@import("builtin").cpu.arch != .x86_64 or @import("builtin").os.tag != .linux) return;

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();

    const host_python = std.Io.Dir.cwd().realPathFileAlloc(io, "/usr/bin/python3", allocator) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    const host_python_bytes = try std.Io.Dir.cwd().readFileAlloc(io, host_python, allocator, .limited(authority.types.runtime.max_file_bytes));
    var host_python_info = authority.runtime_probes.inspectElf(a, host_python_bytes, .interpreter) catch return;
    defer host_python_info.deinit();
    const host_loader = try std.Io.Dir.cwd().realPathFileAlloc(io, host_python_info.interpreter.?, allocator);
    const host_loader_dir = std.fs.path.dirname(host_loader) orelse return error.InvalidInterpreter;

    const name = try allocator.print("composition-real-elf-{d}", .{linux.getpid()});
    const parent = try core.private_files.openDirectory(io, options.fixture_root, .private);
    defer parent.close(io);
    parent.deleteTree(io, name) catch {};
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch {};
    const dir = try parent.openDir(io, name, .{ .iterate = true });
    defer {
        removable(dir) catch {};
        dir.close(io);
    }
    const fixture_path = try std.fs.path.join(allocator, &.{ options.fixture_root, name });
    const interpreter_path = try std.fs.path.join(allocator, &.{ fixture_path, "python" });

    try write(dir, "python", host_python_bytes, 0o500);

    var interpreter = try core.private_files.RetainedFile.open(io, interpreter_path, .artifact);
    defer interpreter.close(io);
    var loader = try core.private_files.RetainedFile.open(io, host_loader, .artifact);
    defer loader.close(io);

    var queue: std.ArrayList([]const u8) = .empty;
    var seen_names: std.StringHashMapUnmanaged(void) = .empty;
    try seen_names.put(allocator, authority.runtime_probes.loader_basename, {});
    for (host_python_info.needed) |needed_name| {
        if (!seen_names.contains(needed_name)) {
            try seen_names.put(allocator, try allocator.dupe(u8, needed_name), {});
            try queue.append(allocator, try allocator.dupe(u8, needed_name));
        }
    }

    var candidate_files: std.ArrayList(core.private_files.RetainedFile) = .empty;
    defer for (candidate_files.items) |*file| file.close(io);

    var queue_index: usize = 0;
    while (queue_index < queue.items.len) : (queue_index += 1) {
        const dso_name = queue.items[queue_index];
        const resolved_dso = try resolveHostLibrary(allocator, host_loader_dir, dso_name);
        const dso_bytes = try std.Io.Dir.cwd().readFileAlloc(io, resolved_dso, allocator, .limited(authority.types.runtime.max_file_bytes));
        var dso_info = authority.runtime_probes.inspectElf(a, dso_bytes, .library) catch return;
        defer dso_info.deinit();
        for (dso_info.needed) |transitive| {
            if (!seen_names.contains(transitive)) {
                try seen_names.put(allocator, try allocator.dupe(u8, transitive), {});
                try queue.append(allocator, try allocator.dupe(u8, transitive));
            }
        }
        try write(dir, dso_name, dso_bytes, 0o400);
        const staged_dso_path = try std.fs.path.join(allocator, &.{ fixture_path, dso_name });
        try candidate_files.append(allocator, try core.private_files.RetainedFile.open(io, staged_dso_path, .artifact));
    }

    var candidate_ptrs = try allocator.alloc(*core.private_files.RetainedFile, candidate_files.items.len);
    for (candidate_files.items, 0..) |*file, index| candidate_ptrs[index] = file;

    const ctx: authority.types.Context = .{ .allocator = a, .io = io };
    try core.process.initialize();
    var noop_ctx: u8 = 0;
    const noop_barrier: authority.transaction.Barrier = .{ .context = &noop_ctx, .check = noopBarrierCheck };

    const version_exec = try core.process.Executable.fromFile(io, loader.file);
    defer version_exec.close(io);
    var version_env = std.process.Environ.Map.init(a);
    defer version_env.deinit();
    try version_env.put("LC_ALL", "C");
    const now_ns = try core.process.monotonicNanoseconds();
    var version_run = try authority.transaction.supervise(ctx, .{
        .executable = version_exec,
        .argv = &.{
            host_loader,
            "--inhibit-cache",
            "--inhibit-rpath",
            "",
            "--library-path",
            fixture_path,
            interpreter_path,
            "-s",
            "-S",
            "-B",
            "-P",
            "--version",
        },
        .cwd = dir,
        .environment = &version_env,
        .primary_deadline = .{ .expires_ns = now_ns + 30 * std.time.ns_per_s },
        .cleanup_deadline = .{ .expires_ns = now_ns + 35 * std.time.ns_per_s },
        .capture = .{ .merged = 4096 },
        .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
        .snapshot_executable = true,
    }, noop_barrier);
    defer version_run.deinit(a);
    try std.testing.expect(version_run.succeeded());
    const version_raw = if (version_run.result.stdout.len != 0) version_run.result.stdout else version_run.result.stderr;
    try std.testing.expect(std.mem.startsWith(u8, version_raw, "Python "));
    const version_body = std.mem.trimEnd(u8, version_raw["Python ".len..], "\r\n");
    const first_dot = std.mem.indexOfScalar(u8, version_body, '.') orelse return error.InvalidPythonVersion;
    const second_dot = std.mem.indexOfScalarPos(u8, version_body, first_dot + 1, '.') orelse return error.InvalidPythonVersion;
    const python_version = try allocator.dupe(u8, version_body[0..second_dot]);
    const stdlib_name = try std.fmt.allocPrint(allocator, "python{s}", .{python_version});

    try dir.createDir(io, stdlib_name, .fromMode(0o700));
    const stdlib_dir = try dir.openDir(io, stdlib_name, .{ .iterate = true });
    defer stdlib_dir.close(io);
    try stdlib_dir.createDir(io, "encodings", .fromMode(0o700));
    const encodings_dir = try stdlib_dir.openDir(io, "encodings", .{});
    defer encodings_dir.close(io);
    try write(encodings_dir, "__init__.py",
        \\import _codecs
        \\
        \\class IncrementalEncoder:
        \\    def __init__(self, errors="strict"):
        \\        self.errors = errors
        \\    def encode(self, input, final=False):
        \\        return _codecs.utf_8_encode(input, self.errors)[0]
        \\
        \\class IncrementalDecoder:
        \\    def __init__(self, errors="strict"):
        \\        self.errors = errors
        \\    def decode(self, input, final=False):
        \\        return _codecs.utf_8_decode(input, self.errors, final)[0]
        \\
        \\class CodecInfo(tuple):
        \\    def __new__(cls, name, encode, decode, incrementalencoder=None, incrementaldecoder=None):
        \\        self = tuple.__new__(cls, (encode, decode, None, None))
        \\        self.name = name
        \\        self.encode = encode
        \\        self.decode = decode
        \\        self.incrementalencoder = incrementalencoder
        \\        self.incrementaldecoder = incrementaldecoder
        \\        return self
        \\
        \\def search_function(encoding):
        \\    if encoding in ("utf-8", "utf8", "utf_8", "ascii", "latin-1", "iso8859-1"):
        \\        return CodecInfo("utf-8", _codecs.utf_8_encode, _codecs.utf_8_decode, IncrementalEncoder, IncrementalDecoder)
        \\    return None
        \\
        \\_codecs.register(search_function)
        \\
    , 0o600);
    try write(stdlib_dir, "linecache.py", "def _register_code(*args):\n    pass\n", 0o600);
    for ([_][]const u8{ "os.py", "json.py", "ssl.py", "ctypes.py" }) |mod_name|
        try write(stdlib_dir, mod_name, "x = 1\n", 0o600);

    try dir.createDir(io, "packages", .fromMode(0o700));
    const packages_dir = try dir.openDir(io, "packages", .{ .iterate = true });
    defer packages_dir.close(io);
    for ([_][]const u8{
        "azure",
        "azure/cli",
        "azure/cli/core",
        "azure/cli/command_modules",
        "azure/cli/command_modules/resource",
        "azure/cli/command_modules/vm",
    }) |subpath| {
        try packages_dir.createDir(io, subpath, .fromMode(0o700));
        const subdir = try packages_dir.openDir(io, subpath, .{ .iterate = true });
        defer subdir.close(io);
        try write(subdir, "__init__.py", "x = 1\n", 0o600);
    }

    try write(dir, "azure",
        \\import sys
        \\if sys.argv[1:2] == ["version"]:
        \\    print('{"azure-cli":"2.61.0","azure-cli-core":"2.61.0","azure-cli-telemetry":"1.1.0","extensions":{}}')
        \\else:
        \\    print("Command help: " + " ".join(sys.argv[1:]))
        \\
    , 0o500);

    const output_path = try std.fs.path.join(allocator, &.{ fixture_path, "output" });
    const azure_path = try std.fs.path.join(allocator, &.{ fixture_path, "azure" });
    const stdlib_path = try std.fs.path.join(allocator, &.{ fixture_path, stdlib_name });
    const package_root = try std.fs.path.join(allocator, &.{ fixture_path, "packages" });
    const validator_path = try std.Io.Dir.cwd().realPathFileAlloc(io, options.validator, allocator);

    var parsed_prepare = try authority.cli.parse(a, &.{
        "prepare-azure-runtime",
        try std.fmt.allocPrint(allocator, "--output={s}", .{output_path}),
        try std.fmt.allocPrint(allocator, "--azure={s}", .{azure_path}),
        try std.fmt.allocPrint(allocator, "--az-python={s}", .{interpreter_path}),
        try std.fmt.allocPrint(allocator, "--stdlib={s}", .{stdlib_path}),
        try std.fmt.allocPrint(allocator, "--validator={s}", .{validator_path}),
        try std.fmt.allocPrint(allocator, "--package-root={s}", .{package_root}),
    });
    defer parsed_prepare.deinit();

    const outcome = authority.handlers.run(.{
        .retained = ctx,
        .discovery = .{
            .interpreter = &interpreter,
            .dynamic_loader = &loader,
            .native_roots = &.{},
            .candidates = candidate_ptrs,
        },
    }, parsed_prepare.result.command).prepare;

    switch (outcome) {
        .success => |prepared| {
            defer prepared.deinit();
            const res = try prepared.result();
            try std.testing.expectEqual(@as(u32, @intCast(candidate_files.items.len + 2)), res.evidence.elf.native_files);
            try std.testing.expectEqual(@as(u16, @intCast(candidate_files.items.len + 1)), res.evidence.loader_entries);
            try std.testing.expectEqual(@as(usize, 19), res.evidence.probes.len);
            try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, res.native_validations[0].primary);
            try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, res.native_validations[1].primary);
            return;
        },
        .refused => return error.UnexpectedEarlyRefusal,
        .poisoned => |diagnostic| {
            try std.testing.expectEqual(authority.types.Phase.validation, diagnostic.phase);
            try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.copy);
            try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.manifest);
            try std.testing.expectEqual(core.private_files.CommitStatus.durable, diagnostic.publications.pending);
            try std.testing.expect(diagnostic.native_validation != null);
            try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, diagnostic.native_validation.?.primary);
            try std.testing.expect(diagnostic.native_validation.?.cleanup_complete);
            try std.testing.expect(diagnostic.helper_cleanup_complete);
        },
    }

    const pending_path = try std.fs.path.join(allocator, &.{ output_path, "azure-runtime.pending.json" });
    var parsed_pending = try authority.types.runtime.load(a, io, pending_path);
    defer parsed_pending.deinit();
    const contract = parsed_pending.value.value;

    const layout: authority.types.RuntimeLayout = .{
        .output = output_path,
        .root = contract.root,
        .python_version = contract.python_version,
        .launcher = contract.launcher.path,
        .interpreter = contract.interpreter.path,
        .loader_directory = try std.fs.path.join(allocator, &.{ contract.root, "loader" }),
        .extensions = contract.extensions,
        .startup_config = try std.fs.path.join(allocator, &.{ output_path, "startup-config" }),
    };

    const runtime_dir = try std.Io.Dir.openDirAbsolute(io, contract.root, .{ .iterate = true, .follow_symlinks = false });
    defer runtime_dir.close(io);
    const elf_evidence = try authority.runtime_probes.inspectCopied(ctx, .{
        .root = runtime_dir,
        .layout = layout,
        .contract = contract,
        .barrier = noop_barrier,
    });
    try std.testing.expectEqual(@as(u32, @intCast(candidate_files.items.len + 2)), elf_evidence.native_files);
    try std.testing.expect(elf_evidence.needed_edges >= candidate_files.items.len);
    try std.testing.expectEqualSlices(u8, &authority.transaction.hash(host_python_info.interpreter.?), &elf_evidence.interpreter_path_sha256);

    var copied_loader = try core.private_files.RetainedFile.open(io, contract.dynamic_loader.path, .tool);
    defer copied_loader.close(io);
    const copied_loader_exec = try core.process.Executable.fromFile(io, copied_loader.file);
    defer copied_loader_exec.close(io);
    const probe_cwd = try core.private_files.openDirectory(io, layout.output, .private);
    defer probe_cwd.close(io);
    var probe_env = try authority.runtime_probes.environment(a, layout, contract);
    defer probe_env.deinit();

    const step_count = authority.types.runtime.commands.len + 3;
    try std.testing.expectEqual(@as(usize, 19), step_count);
    for (0..step_count) |index| {
        const step: authority.runtime_probes.Step = switch (index) {
            0 => .loader_listing,
            1 => .python_version,
            2 => .imports,
            else => .{ .command = @intCast(index - 3) },
        };
        const argv = try authority.runtime_probes.arguments(a, layout, contract, step);
        defer a.free(argv);
        const step_now = try core.process.monotonicNanoseconds();
        var supervised = try authority.transaction.supervise(ctx, .{
            .executable = copied_loader_exec,
            .argv = argv,
            .cwd = probe_cwd,
            .environment = &probe_env,
            .primary_deadline = .{ .expires_ns = step_now + 30 * std.time.ns_per_s },
            .cleanup_deadline = .{ .expires_ns = step_now + 35 * std.time.ns_per_s },
            .capture = .{ .merged = 1024 * 1024 },
            .limits = .{ .stdout_bytes = 1024 * 1024, .stderr_bytes = 1024 * 1024 },
            .snapshot_executable = true,
        }, noop_barrier);
        defer supervised.deinit(a);
        try std.testing.expect(supervised.succeeded());
        try std.testing.expectEqual(@as(u32, 0), supervised.result.descendants.observed);
        try std.testing.expectEqual(@as(u32, 0), supervised.result.descendants.adopted);
        switch (step) {
            .loader_listing => {
                const entries = try authority.runtime_probes.validateListing(
                    a,
                    supervised.result.stdout,
                    layout,
                    contract,
                    elf_evidence.interpreter_closure[0..contract.loader_dependencies.len],
                    elf_evidence.interpreter_path_sha256,
                );
                try std.testing.expectEqual(@as(u16, @intCast(candidate_files.items.len + 1)), entries);
            },
            .python_version => try authority.runtime_probes.Test.pythonVersion(
                supervised.result.stdout,
                supervised.result.stderr,
                contract.python_version,
            ),
            .imports => {
                try std.testing.expectEqualStrings("UK-WAMR-AZURE-IMPORTS-1\n", supervised.result.stdout);
                try std.testing.expectEqual(@as(usize, 0), supervised.result.stderr.len);
            },
            .command => |cmd_idx| try authority.runtime_probes.Test.command(a, cmd_idx, supervised.result.stdout),
        }
    }
}

