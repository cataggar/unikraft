// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("wamr_controller");
const files = @import("hyperv_core").private_files;
const options = @import("test_options");

fn python(a: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    const argv = try a.alloc([]const u8, args.len + 3);
    argv[0] = options.python_executable;
    argv[1] = "-B";
    argv[2] = try std.fs.path.join(a, &.{ options.repository_root, "support/build/wamr-native-ci/tests/local_acceptance_fixture.py" });
    @memcpy(argv[3..], args);
    const result = try std.process.run(a, io, .{
        .argv = argv,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(8192),
    });
    if (result.term != .exited or result.term.exited != 0)
        std.debug.print("complete local fixture: {s}\n", .{result.stderr});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
}

pub fn stageGit(a: std.mem.Allocator, io: std.Io, target: []const u8) !void {
    try python(a, io, &.{ "stage-git", options.git_executable, target });
}

pub fn stagePython(a: std.mem.Allocator, io: std.Io, source: []const u8, target: []const u8) !void {
    try python(a, io, &.{ "stage-python", source, target });
}

fn open(io: std.Io, directory: *const files.Directory, runtime: []const u8, repository: []const u8) !controller.accepted_run.AcceptedRun {
    return controller.accepted_run.openAndValidateReadOnlyWithSignal(
        std.testing.allocator,
        io,
        .empty,
        directory,
        runtime,
        repository,
        null,
    );
}

fn cli(a: std.mem.Allocator, io: std.Io, runtime: []const u8, repository: []const u8) !std.process.RunResult {
    return std.process.run(a, io, .{
        .argv = &.{ options.host_controller_cli, "readonly-records", "--runtime", runtime, "--output", "handoff-v1" },
        .cwd = .{ .path = repository },
        .stdout_limit = .limited(2 * 1024 * 1024),
        .stderr_limit = .limited(4096),
    });
}

fn compareHandoff(a: std.mem.Allocator, accepted: *controller.accepted_run.AcceptedRun, encoded: []const u8) !void {
    const expected = try std.json.parseFromSliceLeaky(std.json.Value, a, try accepted.handoffV1(), .{ .parse_numbers = false });
    const actual = try std.json.parseFromSliceLeaky(std.json.Value, a, encoded, .{ .parse_numbers = false });
    for (expected.object.keys()) |key| {
        if (std.mem.eql(u8, key, "runtime_inputs")) continue;
        const first = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, expected.object.get(key).?, .{}));
        const second = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, actual.object.get(key).?, .{}));
        try std.testing.expectEqualStrings(first, second);
    }
    const expected_inputs = expected.object.get("runtime_inputs").?.array.items;
    const actual_inputs = actual.object.get("runtime_inputs").?.array.items;
    try std.testing.expectEqual(expected_inputs.len, actual_inputs.len);
    var found = false;
    for (expected_inputs, actual_inputs) |first, second| {
        const role = first.object.get("role").?.string;
        try std.testing.expectEqualStrings(role, second.object.get("role").?.string);
        if (std.mem.eql(u8, role, controller.accepted_run.handoff_controller_role)) {
            found = true;
            try std.testing.expectEqualStrings(options.host_controller_cli, second.object.get("path").?.string);
            const file = try controller.custody_files.readFile(accepted.io, options.host_controller_cli, 64 * 1024 * 1024, false);
            try std.testing.expectEqualStrings(&file.sha256, second.object.get("snapshot").?.object.get("sha256").?.string);
        } else {
            try std.testing.expectEqualStrings(
                try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, first, .{})),
                try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, second, .{})),
            );
        }
    }
    try std.testing.expect(found);
}

fn diagnoseInputs(a: std.mem.Allocator, io: std.Io, runtime: []const u8) !void {
    const path = try std.fs.path.join(a, &.{ runtime, "compute/evidence/build-start.json" });
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(controller.records.max_record_bytes));
    const start = try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{ .parse_numbers = false });
    const expected = start.object.get("consumer_inputs").?;
    const file_map = expected.object.get("files").?.object;
    const tree_map = expected.object.get("trees").?.object;
    const bindings = try a.alloc(controller.input_custody.Binding, file_map.count());
    const trees = try a.alloc(controller.input_custody.Binding, tree_map.count());
    for (file_map.keys(), file_map.values(), bindings) |role, value, *binding|
        binding.* = .{ .role = role, .path = value.object.get("path").?.string };
    for (tree_map.keys(), tree_map.values(), trees) |role, value, *binding|
        binding.* = .{ .role = role, .path = value.object.get("path").?.string };
    var captured = try controller.input_custody.capture(a, io, bindings, trees);
    defer captured.deinit(a);
    const actual = try std.json.parseFromSliceLeaky(std.json.Value, a, try captured.canonical(a), .{ .parse_numbers = false });
    for ([_][]const u8{ "files", "trees", "directories" }) |kind| {
        const map = expected.object.get(kind).?.object;
        for (map.keys(), map.values()) |name, value| {
            const first = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, value, .{}));
            const second = try controller.records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, actual.object.get(kind).?.object.get(name).?, .{}));
            if (!std.mem.eql(u8, first, second))
                std.debug.print("local custody diff {s} {s}\nexpected: {s}actual: {s}", .{ kind, name, first, second });
        }
    }
}

const Fixture = struct {
    revision: []const u8,
    work: []const u8,
    repository: []const u8,
    runtime: []const u8,
    stage: []const u8,

    fn prepare(self: Fixture, io: std.Io) !void {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();
        try python(a, io, &.{
            "prepare",                options.repository_root,    self.stage,             self.work,               self.revision,
            options.git_executable,   options.python_executable,  options.zig_executable, options.command_fixture, options.miz_package,
            options.host_package_cli, options.host_log_validator, options.host_aot_build,
        });
        std.debug.print("complete local {s}: prepared\n", .{self.revision});
    }

    fn cancellation(self: Fixture, io: std.Io) !void {
        const directory = try controller.layout.runtime(io, self.runtime);
        defer directory.close(io);
        var signal = try controller.build_pipeline.installCancellation();
        defer signal.deinit();
        try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.kill(std.os.linux.getpid(), .INT)));
        try std.testing.expectError(error.Cancelled, controller.accepted_run.openAndValidateReadOnlyWithSignal(
            std.testing.allocator,
            io,
            .empty,
            &directory,
            self.runtime,
            self.repository,
            &signal,
        ));
    }

    fn qualify(self: Fixture, io: std.Io) !void {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const revision = self.revision;
        const work = self.work;
        const repository = self.repository;
        const runtime = self.runtime;
        const root = try std.Io.Dir.openDirAbsolute(io, work, .{});
        defer root.close(io);
        const directory = try controller.layout.runtime(io, runtime);
        defer directory.close(io);
        const v2 = std.mem.eql(u8, revision, "e98623f780fa23d05b5797004e4b88160404eb1b");
        var accepted = try open(io, &directory, runtime, repository);
        defer accepted.deinit();
        {
            try std.testing.expectEqual(controller.accepted_run.EvidenceContext.local_runtime, accepted.context);
            try std.testing.expectEqual(controller.accepted_run.LocalProducer.python, accepted.local_producer);
            try std.testing.expectEqual(@as(usize, if (v2) 33 else 20), accepted.records.len);
            try std.testing.expect(accepted.runtime_inputs.len > 25);
            accepted.revalidate() catch |err| {
                try diagnoseInputs(a, io, runtime);
                return err;
            };
            const emitted = try cli(a, io, runtime, repository);
            if (emitted.term != .exited or emitted.term.exited != 0)
                std.debug.print("complete local CLI: {s}\n", .{emitted.stderr});
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, emitted.term);
            try std.testing.expectEqualStrings("", emitted.stderr);
            try compareHandoff(a, &accepted, emitted.stdout);
            if (v2) {
                const raw = try root.readFileAlloc(io, ".d/wamr-native-runtime/compute/evidence/build-start.json", a, .limited(controller.records.max_record_bytes));
                const start = try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{ .parse_numbers = false });
                const source_map = start.object.get("command_supervisor").?.object.get("source_map").?;
                _ = try controller.import_supervisor_identity.verifyGitSource(std.testing.allocator, io, accepted.source, repository, options.git_executable, source_map, null);
                const source_records = source_map.object.get("records").?;
                source_records.object.values()[0].object.getPtr("sha256").?.* = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" };
                try std.testing.expectError(error.ImportIdentityChanged, controller.import_supervisor_identity.verifyGitSource(std.testing.allocator, io, accepted.source, repository, options.git_executable, source_map, null));
            }
        }
        try std.testing.expectError(
            if (v2) error.UnsupportedLocalProducer else error.UnsupportedLocalLegacyRun,
            controller.accepted_run.openAndValidate(std.testing.allocator, io, .empty, &directory, runtime, repository),
        );
        if (!v2) {
            const output = try std.fs.path.join(a, &.{ work, "refused-export" });
            try std.testing.expectError(error.MissingInput, controller.handoff_inspect.run(a, io, &accepted, output, true, null));
            try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(io, output, .{}));
            const refused = try std.process.run(a, io, .{
                .argv = &.{ options.host_controller_cli, "handoff-inspect-legacy", "--runtime", runtime, "--output", output },
                .cwd = .{ .path = repository },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, refused.term);
            try std.testing.expectEqualStrings("", refused.stdout);
            if (std.mem.indexOf(u8, refused.stderr, "MissingInput") == null) {
                std.debug.print("unexpected missing-supervisor refusal {s}: {s}\n", .{ revision, refused.stderr });
                try diagnoseInputs(a, io, runtime);
            }
            try std.testing.expect(std.mem.indexOf(u8, refused.stderr, "MissingInput") != null);
            try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(io, output, .{}));
            const export_refused = try std.process.run(a, io, .{
                .argv = &.{ options.host_controller_cli, "private-export", "--runtime", runtime, "--output", output },
                .cwd = .{ .path = repository },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
            });
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, export_refused.term);
            try std.testing.expectEqualStrings("", export_refused.stdout);
            try std.testing.expect(std.mem.indexOf(u8, export_refused.stderr, "MissingInput") != null);
            try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(io, output, .{}));
        } else {
            try python(a, io, &.{
                "private-cli",               options.repository_root,  work,
                options.host_controller_cli, options.import_validator,
            });
        }
        const cases = [_]struct { name: []const u8, expected: anyerror, v2_only: bool = false }{
            .{ .name = "source-custody", .expected = error.RecordedCustodyChanged },
            .{ .name = "dependency-custody", .expected = error.RecordedCustodyChanged },
            .{ .name = "bison-custody", .expected = error.RecordedCustodyChanged },
            .{ .name = "extra-tool", .expected = error.UnexpectedInputRole },
            .{ .name = "missing-tool", .expected = error.InvalidInputCustody },
            .{ .name = "boot-path", .expected = error.UnexpectedInputPath },
            .{ .name = "runtime-path-build", .expected = error.UnexpectedInputPath },
            .{ .name = "runtime-path-boot", .expected = error.UnexpectedInputPath },
            .{ .name = "boot-pin", .expected = error.InvalidBootPins },
            .{ .name = "serial", .expected = error.EvidenceChanged },
            .{ .name = "command-identity", .expected = error.InvalidCommandIdentity, .v2_only = true },
            .{ .name = "supervisor-source", .expected = error.RecordedCustodyChanged, .v2_only = true },
            .{ .name = "supervisor-runtime", .expected = error.RecordedCustodyChanged, .v2_only = true },
            .{ .name = "command-log", .expected = error.CommandOutputChanged, .v2_only = true },
            .{ .name = "image-chain", .expected = error.InvalidImageChain, .v2_only = true },
            .{ .name = "historical-object", .expected = error.GitExited },
            .{ .name = "input-runtime", .expected = error.RecordedCustodyChanged },
            .{ .name = "dirty-source", .expected = error.DirtySource },
        };
        for (cases) |case| {
            if (case.v2_only and !v2) continue;
            const expected = if (!v2 and std.mem.eql(u8, case.name, "source-custody")) error.EvidenceChanged else case.expected;
            try python(a, io, &.{ "mutate", work, case.name });
            std.debug.print("local refusal {s} {s}: {s}\n", .{ revision, case.name, @errorName(expected) });
            const outcome = open(io, &directory, runtime, repository);
            if (outcome) |value| {
                var unexpected = value;
                unexpected.deinit();
                return error.UnexpectedLocalAcceptance;
            } else |err| {
                if (err != expected) {
                    std.debug.print("unexpected local refusal {s} {s}: {s}, expected {s}\n", .{ revision, case.name, @errorName(err), @errorName(expected) });
                    try diagnoseInputs(a, io, runtime);
                }
                try std.testing.expectEqual(expected, err);
            }
            if (std.mem.eql(u8, case.name, "input-runtime")) {
                try std.testing.expectError(error.RecordedCustodyChanged, accepted.revalidate());
                const role = try root.readFileAlloc(io, "mutated-runtime-role", a, .limited(4096));
                try std.testing.expectError(error.InputChanged, accepted.pinInput(role));
            }
            const refused = try cli(a, io, runtime, repository);
            try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, refused.term);
            try std.testing.expectEqualStrings("", refused.stdout);
            try std.testing.expect(std.mem.indexOf(u8, refused.stderr, @errorName(expected)) != null);
        }
        std.debug.print("complete local {s}: constructor, recheck, CLI and refusals passed\n", .{revision});
    }
};

fn together(io: std.Io, fixtures: []const Fixture, comptime operation: fn (Fixture, std.Io) anyerror!void) !void {
    var index: usize = 0;
    while (index < fixtures.len) : (index += 2) {
        if (index + 1 == fixtures.len) {
            try operation(fixtures[index], io);
            return;
        }
        var other = try io.concurrent(operation, .{ fixtures[index + 1], io });
        defer _ = other.cancel(io) catch {};
        const first_result = operation(fixtures[index], io);
        const other_result = other.await(io);
        try first_result;
        try other_result;
    }
}

pub fn workerFailure(a: std.mem.Allocator, io: std.Io) !void {
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{});
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "complete-local-workers-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("complete local worker cleanup failed");
    const path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    const probe = struct {
        fn run(fixture: Fixture, worker_io: std.Io) !void {
            const directory = try std.Io.Dir.openDirAbsolute(worker_io, fixture.work, .{});
            defer directory.close(worker_io);
            try std.Io.sleep(worker_io, .fromMilliseconds(20), .awake);
            const file = try directory.createFile(worker_io, "drained", .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer file.close(worker_io);
            try file.writeStreamingAll(worker_io, "joined\n");
        }
    };
    const fixtures = [_]Fixture{
        .{ .revision = "", .work = try std.fs.path.join(a, &.{ path, "unavailable" }), .repository = "", .runtime = "", .stage = "" },
        .{ .revision = "", .work = path, .repository = "", .runtime = "", .stage = "" },
    };
    try std.testing.expectError(error.FileNotFound, together(io, &fixtures, probe.run));
    const directory = try std.Io.Dir.openDirAbsolute(io, path, .{});
    defer directory.close(io);
    try std.testing.expectEqualStrings("joined\n", try directory.readFileAlloc(io, "drained", a, .limited(64)));
    try directory.deleteFile(io, "drained");
    const reversed = [_]Fixture{ fixtures[1], fixtures[0] };
    try std.testing.expectError(error.FileNotFound, together(io, &reversed, probe.run));
    try std.testing.expectEqualStrings("joined\n", try directory.readFileAlloc(io, "drained", a, .limited(64)));
}

pub fn qualify(a: std.mem.Allocator, io: std.Io, stage: []const u8) !void {
    const parent = try std.Io.Dir.openDirAbsolute(io, options.fixture_root, .{ .iterate = true });
    defer parent.close(io);
    const name = try std.fmt.allocPrint(a, "complete-local-{d}", .{std.os.linux.getpid()});
    try parent.createDir(io, name, .fromMode(0o700));
    defer parent.deleteTree(io, name) catch @panic("complete local fixture cleanup failed");
    const root = try parent.openDir(io, name, .{ .iterate = true });
    defer root.close(io);
    const root_path = try std.fs.path.join(a, &.{ options.fixture_root, name });
    const revisions = [_][]const u8{
        "e98623f780fa23d05b5797004e4b88160404eb1b",
        "0711a0b6bf2285a4ba6ab6dd3bd4088478d665e1",
        "c9c00535399354063486957611bf6e09c8ae4592",
        "3c6d5d98dc5736d86e97884184b26be39c3f11d5",
    };
    var fixtures: std.ArrayList(Fixture) = .empty;
    defer fixtures.deinit(a);
    for (revisions) |revision| {
        if (options.local_fixture_source.len != 0 and !std.mem.eql(u8, options.local_fixture_source, revision)) continue;
        // All common custody ancestors exist before any worker captures inputs.
        try root.createDir(io, revision, .fromMode(0o700));
        const work = try std.fs.path.join(a, &.{ root_path, revision });
        try fixtures.append(a, .{
            .revision = revision,
            .work = work,
            .repository = try std.fs.path.join(a, &.{ work, "producer" }),
            .runtime = try std.fs.path.join(a, &.{ work, ".d/wamr-native-runtime" }),
            .stage = stage,
        });
    }
    try std.testing.expect(fixtures.items.len != 0);
    try together(io, fixtures.items, Fixture.prepare);
    // Signal dispositions belong to the process, not the concurrent workers.
    for (fixtures.items) |fixture| try fixture.cancellation(io);
    try together(io, fixtures.items, Fixture.qualify);
}
