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
    try std.testing.expectEqual(error.UnsafePath, authority.handlers.run(ctx, .{ .@"prepare-azure-runtime" = .{} }).prepare.refused.err);
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
    try std.testing.expectEqual(error.FileNotFound, authority.handlers.run(ctx, parsed_prepare.result.command).prepare.refused.err);

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
    try writeWithDigest(dir, name, bytes, mode, null);
}
fn writeWithDigest(dir: std.Io.Dir, name: []const u8, bytes: []const u8, mode: u32, known_digest: ?[32]u8) !void {
    const file = try dir.createFile(io, name, .{ .read = true, .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    if (linux.errno(linux.fchmod(file.handle, mode)) != .SUCCESS) return error.FixtureMode;
    const RuntimeCache = authority.types.runtime.DigestCache;
    if (bytes.len >= RuntimeCache.min_size) {
        const snap = try core.private_files.snapshot(file);
        if (RuntimeCache.computeBoundaryHash(io, file, snap.size)) |bh| {
            const digest = known_digest orelse authority.transaction.hash(bytes);
            RuntimeCache.put(snap, 1, bh, digest, 0, 0);
            const HandoffCache = @import("wamr_handoff").retained_copy.DigestCache;
            HandoffCache.put(snap, 1, bh, digest, 0, HandoffCache.flag_scan_checked);
        }
    }
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

    const standalone_output = try std.fs.path.join(allocator, &.{ fixture.path, "output-standalone" });
    const beta_path = try std.fs.path.join(allocator, &.{ fixture.path, "libbeta.so" });
    var standalone_parsed = try authority.cli.parse(a, &.{
        "prepare-azure-runtime",
        try std.fmt.allocPrint(allocator, "--output={s}", .{standalone_output}),
        try std.fmt.allocPrint(allocator, "--azure={s}", .{fixture.request.azure}),
        try std.fmt.allocPrint(allocator, "--az-python={s}", .{fixture.request.az_python}),
        try std.fmt.allocPrint(allocator, "--stdlib={s}", .{fixture.request.stdlib}),
        try std.fmt.allocPrint(allocator, "--validator={s}", .{fixture.request.validator}),
        try std.fmt.allocPrint(allocator, "--package-root={s}", .{package_root}),
        try std.fmt.allocPrint(allocator, "--native-dependency={s}", .{beta_path}),
    });
    defer standalone_parsed.deinit();

    const standalone_outcome = authority.handlers.run(.{
        .retained = .{ .allocator = a, .io = io },
    }, standalone_parsed.result.command).prepare;
    const standalone_diag = switch (standalone_outcome) {
        .poisoned => |failure| failure,
        .refused => return error.UnexpectedEarlyRefusal,
        .success => |owner| {
            owner.deinit();
            return error.SyntheticRuntimeAccepted;
        },
    };
    try std.testing.expectEqual(authority.types.Phase.validation, standalone_diag.phase);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, standalone_diag.publications.copy);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, standalone_diag.publications.manifest);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, standalone_diag.publications.pending);
    try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, standalone_diag.publications.output);
    try std.testing.expectEqual(core.private_files.CommitStatus.durable, standalone_diag.publications.failure);
    try std.testing.expect(standalone_diag.native_validation != null);
    try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, standalone_diag.native_validation.?.primary);
    try absent(fixture.dir, "output-standalone/azure-runtime.json");

    try fixture.dir.deleteFile(io, "libbeta.so");
    var missing_dep_parsed = try authority.cli.parse(a, &.{
        "prepare-azure-runtime",
        try std.fmt.allocPrint(allocator, "--output={s}-missing", .{standalone_output}),
        try std.fmt.allocPrint(allocator, "--azure={s}", .{fixture.request.azure}),
        try std.fmt.allocPrint(allocator, "--az-python={s}", .{fixture.request.az_python}),
        try std.fmt.allocPrint(allocator, "--stdlib={s}", .{fixture.request.stdlib}),
        try std.fmt.allocPrint(allocator, "--validator={s}", .{fixture.request.validator}),
        try std.fmt.allocPrint(allocator, "--package-root={s}", .{package_root}),
    });
    defer missing_dep_parsed.deinit();
    const missing_dep_outcome = authority.handlers.run(.{
        .retained = .{ .allocator = a, .io = io },
    }, missing_dep_parsed.result.command).prepare;
    try std.testing.expectEqual(error.MissingDependency, missing_dep_outcome.refused.err);
    try absent(fixture.dir, "output-standalone-missing");
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

const CachedDso = struct {
    name: []const u8,
    bytes: []const u8,
    digest: [32]u8,
};

const GoldenHostElf = struct {
    valid: bool = false,
    unavailable: bool = false,
    python_bytes: []const u8 = "",
    python_digest: [32]u8 = @splat(0),
    interpreter_str: []const u8 = "",
    host_loader: []const u8 = "",
    python_version: ?[]const u8 = null,
    dsos: []const CachedDso = &.{},
};

var golden_host_elf_lock: std.atomic.Value(u32) = .init(0);
var golden_host_elf: GoldenHostElf = .{};

fn parsePythonMinorFromName(name: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, name, "python3.")) return null;
    const after = name["python3.".len..];
    var end: usize = 0;
    while (end < after.len and std.ascii.isDigit(after[end])) : (end += 1) {}
    if (end == 0) return null;
    return name["python".len .. "python3.".len + end];
}

fn loadGoldenHostElf() !?GoldenHostElf {
    while (golden_host_elf_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
    defer golden_host_elf_lock.store(0, .release);
    if (golden_host_elf.valid) return golden_host_elf;
    if (golden_host_elf.unavailable) return null;

    const page = std.heap.page_allocator;
    const host_python = std.Io.Dir.cwd().realPathFileAlloc(io, "/usr/bin/python3", page) catch |err| switch (err) {
        error.FileNotFound => {
            golden_host_elf.unavailable = true;
            return null;
        },
        else => return err,
    };
    const host_python_bytes = try std.Io.Dir.cwd().readFileAlloc(io, host_python, page, .limited(authority.types.runtime.max_file_bytes));
    var host_python_info = authority.runtime_probes.inspectElf(page, host_python_bytes, .interpreter) catch {
        golden_host_elf.unavailable = true;
        return null;
    };
    defer host_python_info.deinit();
    const interpreter_str = try page.dupe(u8, host_python_info.interpreter.?);
    const host_loader = try std.Io.Dir.cwd().realPathFileAlloc(io, interpreter_str, page);
    const host_loader_dir = std.fs.path.dirname(host_loader) orelse return error.InvalidInterpreter;

    var queue: std.ArrayList([]const u8) = .empty;
    var seen_names: std.StringHashMapUnmanaged(void) = .empty;
    try seen_names.put(page, authority.runtime_probes.loader_basename, {});
    for (host_python_info.needed) |needed_name| {
        if (!seen_names.contains(needed_name)) {
            const duped = try page.dupe(u8, needed_name);
            try seen_names.put(page, duped, {});
            try queue.append(page, duped);
        }
    }

    var dsos: std.ArrayList(CachedDso) = .empty;
    var queue_index: usize = 0;
    while (queue_index < queue.items.len) : (queue_index += 1) {
        const dso_name = queue.items[queue_index];
        const resolved_dso = try resolveHostLibrary(page, host_loader_dir, dso_name);
        const dso_bytes = try std.Io.Dir.cwd().readFileAlloc(io, resolved_dso, page, .limited(authority.types.runtime.max_file_bytes));
        var dso_info = authority.runtime_probes.inspectElf(page, dso_bytes, .library) catch {
            golden_host_elf.unavailable = true;
            return null;
        };
        defer dso_info.deinit();
        for (dso_info.needed) |transitive| {
            if (!seen_names.contains(transitive)) {
                const duped = try page.dupe(u8, transitive);
                try seen_names.put(page, duped, {});
                try queue.append(page, duped);
            }
        }
        try dsos.append(page, .{
            .name = dso_name,
            .bytes = dso_bytes,
            .digest = authority.transaction.hash(dso_bytes),
        });
    }

    const py_ver = if (parsePythonMinorFromName(std.fs.path.basename(host_python))) |ver|
        try page.dupe(u8, ver)
    else
        null;

    golden_host_elf = .{
        .valid = true,
        .python_bytes = host_python_bytes,
        .python_digest = authority.transaction.hash(host_python_bytes),
        .interpreter_str = interpreter_str,
        .host_loader = host_loader,
        .python_version = py_ver,
        .dsos = try dsos.toOwnedSlice(page),
    };
    return golden_host_elf;
}

test "CLI prepare-azure-runtime stages real x86_64 ELF Python closure and executes all 19 closed probes" {
    if (@import("builtin").cpu.arch != .x86_64 or @import("builtin").os.tag != .linux) return;

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const allocator = arena.allocator();

    const cached_elf = (try loadGoldenHostElf()) orelse return;
    const host_loader = cached_elf.host_loader;

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

    try writeWithDigest(dir, "python", cached_elf.python_bytes, 0o500, cached_elf.python_digest);

    var loader = try core.private_files.RetainedFile.open(io, host_loader, .artifact);
    defer loader.close(io);

    for (cached_elf.dsos) |dso| {
        try writeWithDigest(dir, dso.name, dso.bytes, 0o400, dso.digest);
    }

    const ctx: authority.types.Context = .{ .allocator = a, .io = io };
    try core.process.initialize();
    var noop_ctx: u8 = 0;
    const noop_barrier: authority.transaction.Barrier = .{ .context = &noop_ctx, .check = noopBarrierCheck };

    const python_version = if (cached_elf.python_version) |ver|
        ver
    else blk: {
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
        break :blk try allocator.dupe(u8, version_body[0..second_dot]);
    };
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
    }, parsed_prepare.result.command).prepare;

    const runtime_json_path = try std.fs.path.join(allocator, &.{ output_path, "azure-runtime.json" });
    switch (outcome) {
        .success => |prepared| {
            defer prepared.deinit();
            const res = try prepared.result();
            try std.testing.expectEqual(@as(u32, @intCast(cached_elf.dsos.len + 2)), res.evidence.elf.native_files);
            try std.testing.expectEqual(@as(u16, @intCast(cached_elf.dsos.len + 1)), res.evidence.loader_entries);
            try std.testing.expectEqual(@as(usize, 19), res.evidence.probes.len);
            try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, res.native_validations[0].primary);
            try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 0 }, res.native_validations[1].primary);
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
            try std.testing.expectEqual(@as(u32, @intCast(cached_elf.dsos.len + 2)), elf_evidence.native_files);
            try std.testing.expect(elf_evidence.needed_edges >= cached_elf.dsos.len);
            try std.testing.expectEqualSlices(u8, &authority.transaction.hash(cached_elf.interpreter_str), &elf_evidence.interpreter_path_sha256);

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
                        try std.testing.expectEqual(@as(u16, @intCast(cached_elf.dsos.len + 1)), entries);
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

            const out_dir = try std.Io.Dir.openDirAbsolute(io, output_path, .{ .follow_symlinks = false });
            defer out_dir.close(io);
            const pending_bytes = try out_dir.readFileAlloc(io, "azure-runtime.pending.json", allocator, .limited(65536));
            try write(out_dir, "azure-runtime.json", pending_bytes, 0o600);
        },
    }

    var parsed_runtime = try authority.types.runtime.load(a, io, runtime_json_path);
    defer parsed_runtime.deinit();
    const published_contract = parsed_runtime.value.value;

    var validator_retained = try core.private_files.RetainedFile.open(io, validator_path, .tool);
    defer validator_retained.close(io);
    const validator_exec = try core.process.Executable.fromFile(io, validator_retained.file);
    defer validator_exec.close(io);
    var validator_env = std.process.Environ.Map.init(a);
    defer validator_env.deinit();

    {
        const val_now = try core.process.monotonicNanoseconds();
        var val_res = try authority.transaction.supervise(ctx, .{
            .executable = validator_exec,
            .argv = &.{ validator_path, "azure-runtime", runtime_json_path },
            .cwd = dir,
            .environment = &validator_env,
            .primary_deadline = .{ .expires_ns = val_now + 30 * std.time.ns_per_s },
            .cleanup_deadline = .{ .expires_ns = val_now + 35 * std.time.ns_per_s },
            .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
            .snapshot_executable = true,
        }, noop_barrier);
        defer val_res.deinit(a);
        try std.testing.expect(val_res.succeeded());
        try std.testing.expectEqualStrings("", val_res.result.stdout);
        try std.testing.expectEqualStrings("", val_res.result.stderr);
        try std.testing.expectEqual(@as(u32, 0), val_res.result.descendants.observed);
    }

    const auth_chain_path = try std.fs.path.join(allocator, &.{ fixture_path, "auth-chain" });
    const package_tool = try std.Io.Dir.cwd().realPathFileAlloc(io, options.authorization_package, allocator);
    const native_tool = try std.Io.Dir.cwd().realPathFileAlloc(io, options.process_fixture, allocator);
    var plan_val = try @import("test_fixtures.zig").buildAuthorizationFixture(allocator, io, auth_chain_path, package_tool, native_tool);
    defer @import("test_fixtures.zig").cleanupAuthorizationFixture(io, auth_chain_path) catch {};

    plan_val.ledger = try authority.types.compute.ledgerProposal(
        allocator,
        io,
        plan_val.ledger_path,
        plan_val.campaign_id,
        plan_val.ledger.ledger_id,
    );
    const runtime_bytes = parsed_runtime.bytes.bytes();
    const runtime_sha256 = std.fmt.bytesToHex(authority.transaction.hash(runtime_bytes), .lower);
    plan_val.azure_runtime = published_contract;
    plan_val.azure_runtime_document = .{
        .path = runtime_json_path,
        .size = runtime_bytes.len,
        .sha256 = &runtime_sha256,
    };
    plan_val.tools.azure = .{
        .path = published_contract.launcher.path,
        .size = published_contract.launcher.size,
        .sha256 = published_contract.launcher.sha256,
    };
    plan_val.tools.az_python = .{
        .path = published_contract.interpreter.path,
        .size = published_contract.interpreter.size,
        .sha256 = published_contract.interpreter.sha256,
    };

    const auth_chain_dir = try std.Io.Dir.openDirAbsolute(io, auth_chain_path, .{ .follow_symlinks = false });
    defer auth_chain_dir.close(io);
    const plan_bytes = try authority.records.planBytes(allocator, plan_val);
    const plan_sha256 = std.fmt.bytesToHex(authority.transaction.hash(plan_bytes), .lower);
    const template_val = try authority.records.approvalTemplate(plan_val, &plan_sha256);
    const template_bytes = try authority.records.templateBytes(allocator, plan_val, &plan_sha256, template_val);
    auth_chain_dir.deleteFile(io, "plan.json") catch {};
    auth_chain_dir.deleteFile(io, "template.json") catch {};
    try write(auth_chain_dir, "plan.json", plan_bytes, 0o600);
    try write(auth_chain_dir, "template.json", template_bytes, 0o600);

    const plan_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "plan.json" });
    const template_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "template.json" });
    const denied_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "denied.json" });
    const approved_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "approved.json" });
    const admission_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "admission.json" });
    const serial_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "boots/raw-x2apic/serial" });
    auth_chain_dir.deleteFile(io, "denied.json") catch {};
    auth_chain_dir.deleteFile(io, "approved.json") catch {};
    auth_chain_dir.deleteFile(io, "admission.json") catch {};

    {
        const val_now = try core.process.monotonicNanoseconds();
        var val_res = try authority.transaction.supervise(ctx, .{
            .executable = validator_exec,
            .argv = &.{ validator_path, "plan", plan_path, template_path },
            .cwd = dir,
            .environment = &validator_env,
            .primary_deadline = .{ .expires_ns = val_now + 30 * std.time.ns_per_s },
            .cleanup_deadline = .{ .expires_ns = val_now + 35 * std.time.ns_per_s },
            .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
            .snapshot_executable = true,
        }, noop_barrier);
        defer val_res.deinit(a);
        try std.testing.expect(val_res.succeeded());
        try std.testing.expectEqualStrings("", val_res.result.stdout);
        try std.testing.expectEqualStrings("", val_res.result.stderr);
    }

    const now_unix: i128 = std.Io.Clock.real.now(io).toSeconds();
    const denied_artifact: authority.types.Artifact = blk: {
        var parsed_denied = try authority.cli.parse(a, &.{
            "record-authorization",
            try std.fmt.allocPrint(allocator, "--plan={s}", .{plan_path}),
            try std.fmt.allocPrint(allocator, "--template={s}", .{template_path}),
            try std.fmt.allocPrint(allocator, "--output={s}", .{denied_path}),
            "--decision=denied",
            "--approver=real-elf-operator",
            "--reference=real-elf-closure-denied-reference",
            try std.fmt.allocPrint(allocator, "--recorded-unix={d}", .{now_unix - 1}),
            try std.fmt.allocPrint(allocator, "--expires-unix={d}", .{now_unix + 600}),
            try std.fmt.allocPrint(allocator, "--azure={s}", .{plan_val.tools.azure.path}),
            try std.fmt.allocPrint(allocator, "--uploader={s}", .{plan_val.tools.uploader.path}),
            try std.fmt.allocPrint(allocator, "--validator={s}", .{plan_val.tools.validator.path}),
            try std.fmt.allocPrint(allocator, "--supervisor={s}", .{plan_val.tools.supervisor.path}),
            try std.fmt.allocPrint(allocator, "--az-python={s}", .{plan_val.tools.az_python.path}),
            try std.fmt.allocPrint(allocator, "--azure-runtime={s}", .{plan_val.azure_runtime_document.path}),
        });
        defer parsed_denied.deinit();

        const denied_outcome = authority.handlers.run(.{ .retained = ctx }, parsed_denied.result.command).authorization;
        const recorded_denied = switch (denied_outcome) {
            .success => |owner| owner,
            .refused, .poisoned => return error.RealElfDeniedAuthorizationRefused,
        };
        defer recorded_denied.deinit();
        try recorded_denied.revalidate();
        try std.testing.expectEqual(authority.types.Decision.denied, recorded_denied.value().decision);
        const raw = recorded_denied.artifact();
        break :blk .{
            .path = denied_path,
            .size = raw.size,
            .sha256 = try allocator.dupe(u8, raw.sha256),
        };
    };

    var parsed_auth = try authority.cli.parse(a, &.{
        "record-authorization",
        try std.fmt.allocPrint(allocator, "--plan={s}", .{plan_path}),
        try std.fmt.allocPrint(allocator, "--template={s}", .{template_path}),
        try std.fmt.allocPrint(allocator, "--output={s}", .{approved_path}),
        "--decision=approved",
        "--approver=real-elf-operator",
        "--reference=real-elf-closure-reference",
        try std.fmt.allocPrint(allocator, "--recorded-unix={d}", .{now_unix - 1}),
        try std.fmt.allocPrint(allocator, "--expires-unix={d}", .{now_unix + 600}),
        try std.fmt.allocPrint(allocator, "--azure={s}", .{plan_val.tools.azure.path}),
        try std.fmt.allocPrint(allocator, "--uploader={s}", .{plan_val.tools.uploader.path}),
        try std.fmt.allocPrint(allocator, "--validator={s}", .{plan_val.tools.validator.path}),
        try std.fmt.allocPrint(allocator, "--supervisor={s}", .{plan_val.tools.supervisor.path}),
        try std.fmt.allocPrint(allocator, "--az-python={s}", .{plan_val.tools.az_python.path}),
        try std.fmt.allocPrint(allocator, "--azure-runtime={s}", .{plan_val.azure_runtime_document.path}),
    });
    defer parsed_auth.deinit();

    const auth_outcome = authority.handlers.run(.{ .retained = ctx }, parsed_auth.result.command).authorization;
    const recorded_auth = switch (auth_outcome) {
        .success => |owner| owner,
        .refused, .poisoned => return error.RealElfAuthorizationRefused,
    };
    defer recorded_auth.deinit();
    try recorded_auth.revalidate();
    try std.testing.expectEqual(authority.types.Decision.approved, recorded_auth.value().decision);

    inline for (.{ denied_path, approved_path }) |auth_path| {
        const val_now = try core.process.monotonicNanoseconds();
        var val_res = try authority.transaction.supervise(ctx, .{
            .executable = validator_exec,
            .argv = &.{ validator_path, "authorization", plan_path, auth_path },
            .cwd = dir,
            .environment = &validator_env,
            .primary_deadline = .{ .expires_ns = val_now + 30 * std.time.ns_per_s },
            .cleanup_deadline = .{ .expires_ns = val_now + 35 * std.time.ns_per_s },
            .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
            .snapshot_executable = true,
        }, noop_barrier);
        defer val_res.deinit(a);
        try std.testing.expect(val_res.succeeded());
        try std.testing.expectEqualStrings("", val_res.result.stdout);
        try std.testing.expectEqualStrings("", val_res.result.stderr);
    }

    {
        const val_now = try core.process.monotonicNanoseconds();
        var val_res = try authority.transaction.supervise(ctx, .{
            .executable = validator_exec,
            .argv = &.{ validator_path, "authorization", plan_path, template_path },
            .cwd = dir,
            .environment = &validator_env,
            .primary_deadline = .{ .expires_ns = val_now + 30 * std.time.ns_per_s },
            .cleanup_deadline = .{ .expires_ns = val_now + 35 * std.time.ns_per_s },
            .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
            .snapshot_executable = true,
        }, noop_barrier);
        defer val_res.deinit(a);
        try std.testing.expect(!val_res.succeeded());
        try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 1 }, val_res.result.primary);
        try std.testing.expectEqualStrings("", val_res.result.stdout);
        try std.testing.expectEqualStrings("WAMR direct validation refused: UnexpectedFields\n", val_res.result.stderr);
    }

    const plan_artifact: authority.types.Artifact = .{
        .path = plan_path,
        .size = plan_bytes.len,
        .sha256 = &plan_sha256,
    };
    const approved_artifact = recorded_auth.artifact();

    // CLI admit refuses denied authorization on the real ELF closure before candidate custody.
    {
        const denied_admit_out = try std.fs.path.join(allocator, &.{ auth_chain_path, "denied-admission.json" });
        var parsed_denied_admit = try authority.cli.parse(a, &.{
            "admit",
            try std.fmt.allocPrint(allocator, "--plan={s}", .{plan_path}),
            try std.fmt.allocPrint(allocator, "--authorization={s}", .{denied_path}),
            try std.fmt.allocPrint(allocator, "--output={s}", .{denied_admit_out}),
            try std.fmt.allocPrint(allocator, "--azure={s}", .{plan_val.tools.azure.path}),
            try std.fmt.allocPrint(allocator, "--uploader={s}", .{plan_val.tools.uploader.path}),
            try std.fmt.allocPrint(allocator, "--validator={s}", .{plan_val.tools.validator.path}),
            try std.fmt.allocPrint(allocator, "--supervisor={s}", .{plan_val.tools.supervisor.path}),
            try std.fmt.allocPrint(allocator, "--az-python={s}", .{plan_val.tools.az_python.path}),
            try std.fmt.allocPrint(allocator, "--azure-runtime={s}", .{plan_val.azure_runtime_document.path}),
        });
        defer parsed_denied_admit.deinit();
        const denied_admit_outcome = authority.handlers.run(.{
            .retained = ctx,
            .plan_commitment = plan_artifact,
            .authorization_commitment = denied_artifact,
        }, parsed_denied_admit.result.command).admission;
        try std.testing.expect(denied_admit_outcome == .refused);
        try std.testing.expectEqual(authority.types.Phase.inputs, denied_admit_outcome.refused.phase);
        try std.testing.expectEqual(error.NotAuthorized, denied_admit_outcome.refused.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, denied_admit_outcome.refused.publication);
    }

    // CLI admit refuses mismatched tool bindings on the real ELF closure.
    {
        const bad_tool_admit_out = try std.fs.path.join(allocator, &.{ auth_chain_path, "bad-tool-admission.json" });
        var parsed_bad_tool_admit = try authority.cli.parse(a, &.{
            "admit",
            try std.fmt.allocPrint(allocator, "--plan={s}", .{plan_path}),
            try std.fmt.allocPrint(allocator, "--authorization={s}", .{approved_path}),
            try std.fmt.allocPrint(allocator, "--output={s}", .{bad_tool_admit_out}),
            try std.fmt.allocPrint(allocator, "--azure={s}", .{plan_val.tools.azure.path}),
            "--uploader=/wrong/uploader",
            try std.fmt.allocPrint(allocator, "--validator={s}", .{plan_val.tools.validator.path}),
            try std.fmt.allocPrint(allocator, "--supervisor={s}", .{plan_val.tools.supervisor.path}),
            try std.fmt.allocPrint(allocator, "--az-python={s}", .{plan_val.tools.az_python.path}),
            try std.fmt.allocPrint(allocator, "--azure-runtime={s}", .{plan_val.azure_runtime_document.path}),
        });
        defer parsed_bad_tool_admit.deinit();
        const bad_tool_admit_outcome = authority.handlers.run(.{
            .retained = ctx,
            .plan_commitment = plan_artifact,
            .authorization_commitment = approved_artifact,
        }, parsed_bad_tool_admit.result.command).admission;
        try std.testing.expect(bad_tool_admit_outcome == .refused);
        try std.testing.expectEqual(authority.types.Phase.inputs, bad_tool_admit_outcome.refused.phase);
        try std.testing.expectEqual(error.ToolBindingMismatch, bad_tool_admit_outcome.refused.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, bad_tool_admit_outcome.refused.publication);
    }

    // CLI admit with approved authorization and matching tool bindings validates inputs and reaches custody.
    {
        const no_owner_admit_out = try std.fs.path.join(allocator, &.{ auth_chain_path, "no-owner-admission.json" });
        var parsed_admit = try authority.cli.parse(a, &.{
            "admit",
            try std.fmt.allocPrint(allocator, "--plan={s}", .{plan_path}),
            try std.fmt.allocPrint(allocator, "--authorization={s}", .{approved_path}),
            try std.fmt.allocPrint(allocator, "--output={s}", .{no_owner_admit_out}),
            try std.fmt.allocPrint(allocator, "--azure={s}", .{plan_val.tools.azure.path}),
            try std.fmt.allocPrint(allocator, "--uploader={s}", .{plan_val.tools.uploader.path}),
            try std.fmt.allocPrint(allocator, "--validator={s}", .{plan_val.tools.validator.path}),
            try std.fmt.allocPrint(allocator, "--supervisor={s}", .{plan_val.tools.supervisor.path}),
            try std.fmt.allocPrint(allocator, "--az-python={s}", .{plan_val.tools.az_python.path}),
            try std.fmt.allocPrint(allocator, "--azure-runtime={s}", .{plan_val.azure_runtime_document.path}),
        });
        defer parsed_admit.deinit();
        const admit_outcome = authority.handlers.run(.{
            .retained = ctx,
            .plan_commitment = plan_artifact,
            .authorization_commitment = approved_artifact,
        }, parsed_admit.result.command).admission;
        try std.testing.expect(admit_outcome == .refused);
        try std.testing.expectEqual(authority.types.Phase.custody, admit_outcome.refused.phase);
        try std.testing.expectEqual(error.MissingCandidateOwner, admit_outcome.refused.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, admit_outcome.refused.publication);
    }

    // Produce canonical v2 admission.json bound to the real ELF runtime closure and validate all admission modes.
    const admission_now_unix: u64 = @intCast(now_unix);
    const admission_val = try authority.records.admission(
        plan_val,
        plan_artifact,
        recorded_auth.value(),
        approved_artifact,
        admission_now_unix,
    );
    const admission_bytes = try authority.records.admissionBytes(allocator, admission_val, admission_now_unix);
    try write(auth_chain_dir, "admission.json", admission_bytes, 0o600);

    inline for (.{
        &[_][]const u8{ validator_path, "admission", admission_path },
        &[_][]const u8{ validator_path, "stored-scope", admission_path },
        &[_][]const u8{ validator_path, "inputs", admission_path },
        &[_][]const u8{ validator_path, "ledger", admission_path, plan_val.ledger_path },
        &[_][]const u8{ validator_path, "ledger-proposal", plan_val.ledger_path, plan_val.campaign_id, plan_val.ledger.ledger_id },
        &[_][]const u8{ validator_path, "serial", admission_path, serial_path },
    }) |val_argv| {
        const val_now = try core.process.monotonicNanoseconds();
        var val_res = try authority.transaction.supervise(ctx, .{
            .executable = validator_exec,
            .argv = val_argv,
            .cwd = dir,
            .environment = &validator_env,
            .primary_deadline = .{ .expires_ns = val_now + 30 * std.time.ns_per_s },
            .cleanup_deadline = .{ .expires_ns = val_now + 35 * std.time.ns_per_s },
            .limits = .{ .stdout_bytes = 16 * 1024, .stderr_bytes = 4096 },
            .snapshot_executable = true,
        }, noop_barrier);
        defer val_res.deinit(a);
        try std.testing.expect(val_res.succeeded());
        try std.testing.expectEqualStrings("", val_res.result.stderr);
        if (std.mem.eql(u8, val_argv[1], "ledger-proposal")) {
            try std.testing.expect(std.mem.indexOf(u8, val_res.result.stdout, "\"schema\":\"uk.wamr.azure-campaign-ledger-binding\"") != null);
        } else if (std.mem.eql(u8, val_argv[1], "serial")) {
            try std.testing.expect(std.mem.indexOf(u8, val_res.result.stdout, "\"workload\":\"tiny\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, val_res.result.stdout, "\"answer\":42") != null);
        } else {
            try std.testing.expectEqualStrings("", val_res.result.stdout);
        }
    }

    // Post-publication tamper refusal: mutating a copied DSO in the real ELF closure
    // refuses inspectCopied, record-authorization, and uk-wamr-direct-validate.
    {
        var dso_index: usize = 0;
        for (published_contract.loader_dependencies, 0..) |dep, idx| {
            if (!std.mem.eql(u8, dep.path, published_contract.dynamic_loader.path)) {
                dso_index = idx;
                break;
            }
        }
        const dso_path = published_contract.loader_dependencies[dso_index].path;
        const dso_dir_path = std.fs.path.dirname(dso_path) orelse return error.InvalidPath;
        const dso_name = std.fs.path.basename(dso_path);
        const dso_dir = try std.Io.Dir.openDirAbsolute(io, dso_dir_path, .{ .iterate = true, .follow_symlinks = false });
        defer dso_dir.close(io);
        const dso_ro = try dso_dir.openFile(io, dso_name, .{ .follow_symlinks = false });
        if (linux.errno(linux.fchmod(dso_ro.handle, 0o600)) != .SUCCESS) {
            dso_ro.close(io);
            return error.FixtureMode;
        }
        dso_ro.close(io);
        const dso_rw = try dso_dir.openFile(io, dso_name, .{ .mode = .read_write, .follow_symlinks = false });
        var first_byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try dso_rw.readPositionalAll(io, &first_byte, 0));
        const flipped: [1]u8 = .{first_byte[0] ^ 0xff};
        try dso_rw.writePositionalAll(io, &flipped, 0);
        try dso_rw.sync(io);
        if (linux.errno(linux.fchmod(dso_rw.handle, 0o400)) != .SUCCESS) {
            dso_rw.close(io);
            return error.FixtureMode;
        }
        dso_rw.close(io);

        const runtime_dir = try std.Io.Dir.openDirAbsolute(io, published_contract.root, .{ .iterate = true, .follow_symlinks = false });
        defer runtime_dir.close(io);
        const layout: authority.types.RuntimeLayout = .{
            .output = output_path,
            .root = published_contract.root,
            .python_version = published_contract.python_version,
            .launcher = published_contract.launcher.path,
            .interpreter = published_contract.interpreter.path,
            .loader_directory = dso_dir_path,
            .extensions = published_contract.extensions,
            .startup_config = try std.fs.path.join(allocator, &.{ output_path, "startup-config" }),
        };
        try std.testing.expectError(error.AzureRuntimeChanged, authority.runtime_probes.inspectCopied(ctx, .{
            .root = runtime_dir,
            .layout = layout,
            .contract = published_contract,
            .barrier = noop_barrier,
        }));

        const tampered_auth_path = try std.fs.path.join(allocator, &.{ auth_chain_path, "tampered-dso-approved.json" });
        var parsed_tampered_auth = try authority.cli.parse(a, &.{
            "record-authorization",
            try std.fmt.allocPrint(allocator, "--plan={s}", .{plan_path}),
            try std.fmt.allocPrint(allocator, "--template={s}", .{template_path}),
            try std.fmt.allocPrint(allocator, "--output={s}", .{tampered_auth_path}),
            "--decision=approved",
            "--approver=real-elf-operator",
            "--reference=real-elf-closure-reference",
            try std.fmt.allocPrint(allocator, "--recorded-unix={d}", .{now_unix - 1}),
            try std.fmt.allocPrint(allocator, "--expires-unix={d}", .{now_unix + 600}),
            try std.fmt.allocPrint(allocator, "--azure={s}", .{plan_val.tools.azure.path}),
            try std.fmt.allocPrint(allocator, "--uploader={s}", .{plan_val.tools.uploader.path}),
            try std.fmt.allocPrint(allocator, "--validator={s}", .{plan_val.tools.validator.path}),
            try std.fmt.allocPrint(allocator, "--supervisor={s}", .{plan_val.tools.supervisor.path}),
            try std.fmt.allocPrint(allocator, "--az-python={s}", .{plan_val.tools.az_python.path}),
            try std.fmt.allocPrint(allocator, "--azure-runtime={s}", .{plan_val.azure_runtime_document.path}),
        });
        defer parsed_tampered_auth.deinit();
        const tampered_outcome = authority.handlers.run(.{ .retained = ctx }, parsed_tampered_auth.result.command).authorization;
        try std.testing.expect(tampered_outcome == .refused);
        try std.testing.expectEqual(authority.types.Phase.custody, tampered_outcome.refused.phase);
        try std.testing.expectEqual(error.HashMismatch, tampered_outcome.refused.err);
        try std.testing.expectEqual(core.private_files.CommitStatus.not_committed, tampered_outcome.refused.publication);

        inline for (.{
            &[_][]const u8{ validator_path, "azure-runtime", runtime_json_path },
            &[_][]const u8{ validator_path, "plan", plan_path, template_path },
            &[_][]const u8{ validator_path, "authorization", plan_path, denied_path },
            &[_][]const u8{ validator_path, "authorization", plan_path, approved_path },
            &[_][]const u8{ validator_path, "admission", admission_path },
        }) |val_argv| {
            const val_now = try core.process.monotonicNanoseconds();
            var val_res = try authority.transaction.supervise(ctx, .{
                .executable = validator_exec,
                .argv = val_argv,
                .cwd = dir,
                .environment = &validator_env,
                .primary_deadline = .{ .expires_ns = val_now + 30 * std.time.ns_per_s },
                .cleanup_deadline = .{ .expires_ns = val_now + 35 * std.time.ns_per_s },
                .limits = .{ .stdout_bytes = 4096, .stderr_bytes = 4096 },
                .snapshot_executable = true,
            }, noop_barrier);
            defer val_res.deinit(a);
            try std.testing.expect(!val_res.succeeded());
            try std.testing.expectEqual(core.process.CommandPrimary{ .exited = 1 }, val_res.result.primary);
            try std.testing.expectEqualStrings("", val_res.result.stdout);
            try std.testing.expectEqualStrings("WAMR direct validation refused: AzureRuntimeChanged\n", val_res.result.stderr);
        }
    }
}

