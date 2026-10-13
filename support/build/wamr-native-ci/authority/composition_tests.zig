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
        const name = try std.fmt.allocPrint(allocator, "composition-{d}", .{linux.getpid()});
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
