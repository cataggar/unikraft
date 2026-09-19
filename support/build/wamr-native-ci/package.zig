//! Packaging only: use the existing miz/worker/proof machinery, not the
//! hardware application's return-2 preparation or its export contract.
const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const f = image.files;

const Command = enum { package, inspect };
const Args = struct { command: Command, efi: []const u8, state: []const u8 };

fn parse(args: []const []const u8) !Args {
    if (args.len != 4) return error.InvalidArguments;
    const command = std.meta.stringToEnum(Command, args[1]) orelse return error.InvalidArguments;
    try image.core.private_files.absoluteFilePath(args[2]);
    try image.core.private_files.absoluteFilePath(args[3]);
    return .{ .command = command, .efi = args[2], .state = args[3] };
}

fn openEmptyState(io: std.Io, path: []const u8) !image.core.private_files.Directory {
    const root = try image.core.private_files.Directory.open(io, path);
    errdefer root.close(io);
    var entries = root.dir.iterate();
    if (try entries.next(io) != null) return error.StateAlreadyUsed;
    return root;
}

pub fn main(init: std.process.Init) void {
    execute(init) catch {
        // No paths, guest bytes, environment, or raw operating-system errors.
        std.Io.File.stderr().writeStreamingAll(init.io, "WAMR_CI_PACKAGE_FAILED\n") catch {};
        std.process.exit(1);
    };
}

fn execute(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--package-worker"))
        return image.worker.execute(init);
    const input = try parse(args);
    const inherited_path = init.environ_map.get("WAMR_CI_EXECUTABLE_PATH");
    const inherited_executable = init.environ_map.get("WAMR_CI_RETAINED_EXECUTABLE");
    const retained_self = inherited_path != null and inherited_executable != null and
        std.mem.eql(u8, args[0], inherited_path.?);
    const self_path = if (retained_self)
        inherited_path.?
    else
        try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", a);
    const self_executable = if (retained_self) inherited_executable.? else self_path;
    const efi = try f.record(a, io, input.efi, c.max_efi, false);
    const producer = try f.record(a, io, self_path, c.max_tool, true);
    const root = if (input.command == .package)
        try openEmptyState(io, input.state)
    else
        try image.core.private_files.Directory.open(io, input.state);
    defer root.close(io);
    var lock = try root.lock(io);
    var release = true;
    defer if (release) lock.close(io);

    if (input.command == .package) {
        const job: image.worker.Job = .{
            .supervisor_pid = @intCast(std.os.linux.getpid()),
            .state_dir = input.state,
            .efi = efi,
            .producer = producer,
        };
        try f.immutable(a, io, &lock, "package-job.json", job);
        try image.core.process.initialize();
        var environment: std.process.Environ.Map = .init(a);
        defer environment.deinit();
        try environment.put("TMPDIR", input.state);
        try environment.put("WAMR_CI_EXECUTABLE_PATH", self_path);
        try environment.put(
            "WAMR_CI_RETAINED_EXECUTABLE",
            self_executable,
        );
        var result = try image.core.process.run(a, io, .{
            .argv = &.{ self_executable, "--package-worker" },
            .environment = &environment,
            .cwd = root.dir,
            .deadline = try image.core.process.Deadline.afterMilliseconds(c.package_timeout_ms),
            .cleanup_ms = image.boot.config.cleanup_ms,
            .stdout_limit = 0,
            .stderr_limit = 0,
        });
        defer result.deinit(a);
        release = result.cleanup_complete;
        try f.immutable(a, io, &lock, "supervision.json", .{
            .failures = result.failures,
            .cleanup_complete = result.cleanup_complete,
            .termination = result.termination,
        });
        if (!release or !image.engine.clean(result.failures) or result.termination == null or
            result.termination.? != .exited or result.termination.?.exited != 0)
            return error.PackageFailed;
    } else {
        const supervision = try root.read(io, a, "supervision.json", c.max_record, null);
        const Supervision = struct {
            failures: image.core.diagnostics.Failures,
            cleanup_complete: bool,
            termination: ?std.process.Child.Term,
        };
        try f.same(a, Supervision{
            .failures = image.core.diagnostics.Failures{},
            .cleanup_complete = true,
            .termination = @as(?std.process.Child.Term, .{ .exited = 0 }),
        }, try c.read(Supervision, a, supervision));
    }

    const job = try c.read(image.worker.Job, a, try root.read(io, a, "package-job.json", c.max_record, null));
    if (job.schema_version != 1 or job.supervisor_pid == 0 or !std.mem.eql(u8, input.state, job.state_dir))
        return error.InvalidJob;
    try f.same(a, efi, job.efi);
    try f.same(a, producer, job.producer);
    if ((try root.read(io, a, "package-launched", 1, null)).len != 0) return error.InvalidLaunch;
    const observed = try image.package.observe(a, io, root, efi);
    try f.same(a, observed, try c.read(image.package.Report, a, try root.read(io, a, "package-report.json", c.max_record, null)));
    const copied = try f.record(a, io, try f.path(a, input.state, "BOOTX64.EFI"), c.max_efi, false);
    if (copied.size != efi.size or !std.mem.eql(u8, copied.sha256, efi.sha256)) return error.WrongEfi;
    if (input.command == .package) try f.cleanupStage(io, root, "package-stage");
    const vhd = try root.openFile(io, "unikraft.vhd");
    defer vhd.close(io);
    const inspection = try image.package.inspectVhd(a, io, vhd, .{
        .efi = try c.sha(efi.sha256),
        .raw = try c.sha(observed.raw.sha256),
        .vhd = try c.sha(observed.vhd.sha256),
    });
    try f.verify(a, io, producer, c.max_tool, true);
    const bytes = try c.encode(a, .{
        .schema_version = @as(u8, 1),
        .scope = "public_local_compute_packaging_only",
        .acceptance = "not_established",
        .producer_sha256 = producer.sha256,
        .image = inspection,
    });
    try std.Io.File.stdout().writeStreamingAll(io, bytes);
}

test "only package and physical inspect with explicit paths" {
    const a = try parse(&.{ "tool", "package", "/efi", "/new-state" });
    try std.testing.expectEqual(Command.package, a.command);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "tool", "prepare", "/efi", "/state" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "tool", "package", "/efi", "/state", "--skip" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "tool", "--package-worker" }));
    try std.testing.expectError(error.UnsafePath, parse(&.{ "tool", "inspect", "relative", "/state" }));
}
