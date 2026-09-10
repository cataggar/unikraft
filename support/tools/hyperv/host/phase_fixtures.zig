const std = @import("std");
const host = @import("host");
const p = host.protocol;
const f = @import("fixture_support.zig");
const wf = @import("wire_fixtures.zig");
const a = std.testing.allocator;
const io = std.testing.io;
const t = std.testing;

const Assets = struct {
    arena: std.heap.ArenaAllocator,
    executable_path: []const u8,
    qemu: []const u8,
    raw: []u8,
    vhd: []u8,
    code: [32]u8 = [_]u8{0xcc} ** 32,
    vars: [512]u8 = [_]u8{0xa5} ** 512,

    fn init(mode: u8) !Assets {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        const executable_path = try std.Io.Dir.cwd().realPathFileAlloc(io, @import("test_options").child_fixture, scratch);
        const executable = try std.Io.Dir.openFileAbsolute(io, executable_path, .{ .mode = .read_only });
        defer executable.close(io);
        const size = (try executable.stat(io)).size;
        if (size > p.max_artifact) return error.FixtureTooLarge;
        const bytes = try scratch.alloc(u8, @intCast(size));
        if (try executable.readPositionalAll(io, bytes, 0) != size) return error.FixtureChanged;
        const raw = try scratch.alloc(u8, 1048576);
        @memset(raw, 0);
        raw[0] = mode;
        const vhd = try scratch.alloc(u8, raw.len + 512);
        @memcpy(vhd[0..raw.len], raw);
        @memset(vhd[raw.len..], 0);
        @memcpy(vhd[raw.len..][0..8], "conectix");
        return .{ .arena = arena, .executable_path = executable_path, .qemu = bytes, .raw = raw, .vhd = vhd };
    }

    fn body(self: *Assets, role: p.Role) []const u8 {
        return switch (role) {
            .qemu => self.qemu,
            .ovmf_code => &self.code,
            .ovmf_vars => &self.vars,
            .raw, .capability_raw => self.raw,
            .vhd => self.vhd,
            .support => unreachable,
        };
    }

    fn records(self: *Assets, phase: p.Phase) ![]f.Artifact {
        const scratch = self.arena.allocator();
        const roles: []const p.Role = if (phase == .public) &.{ .qemu, .ovmf_code, .ovmf_vars, .capability_raw } else &.{ .qemu, .ovmf_code, .ovmf_vars, .raw, .vhd };
        const output = try scratch.alloc(f.Artifact, roles.len);
        for (roles, output) |role, *record| {
            const name: []const u8 = switch (role) {
                .qemu => "qemu/bin/qemu-system-x86_64",
                .ovmf_code => "OVMF_CODE.fd",
                .ovmf_vars => "OVMF_VARS.fd",
                .raw => "private.raw",
                .vhd => "private.vhd",
                .capability_raw => "capability.raw",
                .support => unreachable,
            };
            const bytes = self.body(role);
            record.* = .{ .role = role, .name = name, .blob = try p.artifactBlob(scratch, f.uuid(f.run_text), phase, name), .sha256 = try scratch.dupe(u8, &p.hex(p.hash(bytes))), .size = bytes.len };
        }
        return output;
    }
};

test "generated child fixture resolves absolute and cwd-relative cache paths" {
    var assets = try Assets.init(0);
    defer assets.arena.deinit();
    try t.expect(std.fs.path.isAbsolute(assets.executable_path));
    var cwd_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_size = try host.files.cwdPath(io, &cwd_buffer);
    const cwd = cwd_buffer[0..cwd_size];
    const relative = try std.fs.path.relative(a, cwd, null, cwd, assets.executable_path);
    defer a.free(relative);
    try t.expect(!std.fs.path.isAbsolute(relative));
    const from_relative = try std.Io.Dir.cwd().realPathFileAlloc(io, relative, a);
    defer a.free(from_relative);
    const from_absolute = try std.Io.Dir.cwd().realPathFileAlloc(io, assets.executable_path, a);
    defer a.free(from_absolute);
    try t.expectEqualStrings(assets.executable_path, from_relative);
    try t.expectEqualStrings(assets.executable_path, from_absolute);
}

const Fixture = struct {
    directory: f.Directory,
    locked: host.core.private_files.Locked,
    store: host.state.Store,
    admitted: p.Admission,
    assets: Assets,
    artifact_root: []u8,
    work_root: []u8,
    downloads: usize = 0,
    private_downloads: usize = 0,
    publications: usize = 0,
    fail_publication: ?usize = null,
    public_receipt: ?[]u8 = null,
    published: std.StringHashMap(void),
    clock: u8 = 0,
    boot_timeout_ms: u32 = 2000,

    fn init(mode: u8) !*Fixture {
        try host.core.process.initialize();
        const self = try a.create(Fixture);
        errdefer a.destroy(self);
        self.* = undefined;
        self.directory = try f.Directory.create("phase");
        errdefer self.directory.deinit();
        self.locked = try self.directory.directory.lock(io);
        errdefer self.locked.close(io);
        self.admitted = try f.admission();
        errdefer self.admitted.deinit();
        self.assets = try Assets.init(mode);
        errdefer self.assets.arena.deinit();
        self.artifact_root = try std.fs.path.join(a, &.{ self.directory.path, "artifacts" });
        errdefer a.free(self.artifact_root);
        self.work_root = try std.fs.path.join(a, &.{ self.directory.path, "boots" });
        errdefer a.free(self.work_root);
        try self.directory.directory.dir.createDir(io, "artifacts", .fromMode(0o700));
        try self.directory.directory.dir.createDir(io, "boots", .fromMode(0o700));
        const initial = try host.state.Record.initial(f.uuid(f.run_text), f.uuid(f.vm_text), try hostBootId(), self.admitted.image_staging_bytes, self.admitted.image_control_bytes);
        self.store = try host.state.Store.open(a, io, &self.locked, initial);
        self.downloads = 0;
        self.private_downloads = 0;
        self.publications = 0;
        self.fail_publication = null;
        self.public_receipt = null;
        self.published = std.StringHashMap(void).init(a);
        self.clock = 0;
        self.boot_timeout_ms = 2000;
        return self;
    }

    fn deinit(self: *Fixture) void {
        if (self.public_receipt) |bytes| a.free(bytes);
        self.published.deinit();
        self.assets.arena.deinit();
        self.admitted.deinit();
        self.locked.close(io);
        self.directory.deinit();
        a.free(self.artifact_root);
        a.free(self.work_root);
        a.destroy(self);
    }

    fn engine(self: *Fixture) host.worker.Engine {
        return .{
            .allocator = a,
            .io = io,
            .key = f.key(),
            .admission = &self.admitted,
            .scope = f.scope(),
            .vm_id = f.uuid(f.vm_text),
            .clock_context = &self.clock,
            .nowFn = f.clock,
            .store = &self.store,
            .remote = .{ .context = self, .fetchFn = fetch, .downloadFn = download, .publishFn = publish, .failuresFn = failures },
            .runner = .{ .allocator = a, .io = io, .self_executable = self.assets.executable_path, .artifact_root = self.artifact_root, .work_root = self.work_root, .attempt_deadline = .{ .expires_ns = self.store.record.deadline_ns }, .boot_timeout_ms = self.boot_timeout_ms, .cleanup_timeout_ms = 200, .evidence_kind = .synthetic_child },
        };
    }

    fn command(self: *Fixture, phase: p.Phase, acceptance: ?std.json.Value) ![]u8 {
        return f.command(phase, try self.assets.records(phase), p.hash(self.assets.raw), acceptance);
    }

    fn privateCommand(self: *Fixture, public_bytes: []const u8, digest: p.Hash) ![]u8 {
        var public = try p.Command.parse(a, public_bytes, f.key(), &self.admitted, f.scope(), f.uuid(f.vm_text), f.now);
        defer public.deinit();
        const accepted = try f.accepted(&public, digest, self.store.record.host_boot_id);
        defer a.free(accepted);
        var doc = try host.core.contracts.Document.parse(a, accepted, .{});
        defer doc.deinit();
        return self.command(.private, doc.value());
    }

    fn fetch(_: *anyopaque, _: p.Phase) ![]u8 {
        return error.FixtureDoesNotPoll;
    }

    fn download(context: *anyopaque, signed: *const p.Command, artifact: p.Artifact, path: []const u8) !void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        self.downloads += 1;
        if (artifact.role == .raw or artifact.role == .vhd) {
            try t.expectEqual(host.state.Stage.private_intent, self.store.record.stage);
            try t.expect(self.store.record.public_evidence_sha256 != null);
            self.private_downloads += 1;
        }
        const body = self.assets.body(artifact.role);
        const url = try std.fmt.allocPrint(a, "https://fixture.blob.core.windows.net/private/{s}", .{artifact.blob});
        defer a.free(url);
        var length: [24]u8 = undefined;
        var mock: wf.Mock = .{ .steps = &.{.{ .url = url, .response = body, .headers = &.{.{ .name = "Content-Length", .value = try std.fmt.bufPrint(&length, "{d}", .{body.len}) }} }} };
        var client = try mock.authenticated();
        defer client.deinit();
        const file = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write, .follow_symlinks = false });
        defer file.close(io);
        try client.download(artifact, signed.phase, file, f.now);
        try t.expectEqual(@as(usize, 1), mock.calls);
    }

    fn publish(context: *anyopaque, signed: *const p.Command, name: []const u8, bytes: []const u8) host.wire.PublishResult {
        const self: *Fixture = @ptrCast(@alignCast(context));
        return self.publishChecked(signed, name, bytes) catch .{ .publication = .unknown, .failure = .{ .stage = .blob_upload, .category = .ambiguous } };
    }

    fn publishChecked(self: *Fixture, signed: *const p.Command, name: []const u8, bytes: []const u8) !host.wire.PublishResult {
        self.publications += 1;
        if (signed.phase == .public and std.mem.eql(u8, name, "receipt.json")) {
            try t.expect(self.public_receipt == null);
            self.public_receipt = try a.dupe(u8, bytes);
        }
        const url = try std.fmt.allocPrint(self.assets.arena.allocator(), "https://fixture.blob.core.windows.net/private/runs/{s}/evidence/{s}/{s}/{s}", .{ f.run_text, @tagName(signed.phase), p.uuidText(signed.phase_nonce), name });
        const duplicate = self.published.contains(url);
        if (!duplicate) try self.published.put(url, {});
        var mock: wf.Mock = .{ .steps = &.{.{ .url = url, .method = .PUT, .request_body = bytes, .status = if (duplicate) 412 else 201, .fail_open = self.fail_publication == self.publications }} };
        var client = try mock.authenticated();
        defer client.deinit();
        return client.publish(signed.phase, signed.phase_nonce, name, bytes, f.now);
    }

    fn failures(_: *anyopaque) host.core.diagnostics.Failures {
        return .{};
    }
};

fn hostBootId() !p.Uuid {
    const file = try std.Io.Dir.openFileAbsolute(io, "/proc/sys/kernel/random/boot_id", .{ .mode = .read_only });
    defer file.close(io);
    var bytes: [38]u8 = undefined;
    const count = try file.readPositionalAll(io, &bytes, 0);
    return host.core.contracts.parseUuid(std.mem.trim(u8, bytes[0..count], "\n"));
}

fn mutated(bytes: []const u8, field: []const u8, value: std.json.Value) ![]u8 {
    var doc = try host.core.contracts.Document.parse(a, bytes, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
    defer doc.deinit();
    const body = try p.field(doc.value(), "body");
    body.object.getPtr(field).?.* = value;
    return f.signBody(body, "uk-hyperv-host-command-v1");
}

test "real supervised children public two private four exact acceptance no seventh boot" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    var engine = fixture.engine();
    const public = try fixture.command(.public, null);
    defer a.free(public);
    try engine.execute(public);
    try t.expectEqual(host.state.Stage.public_done, fixture.store.record.stage);
    try t.expectEqual(@as(u8, 2), fixture.store.record.boots_attempted);
    try t.expectEqual(@as(usize, 0), fixture.private_downloads);
    try t.expectEqual(@as(usize, 3), fixture.publications);
    const wrong_private = try fixture.privateCommand(public, p.hash("wrong-evidence"));
    defer a.free(wrong_private);
    try t.expectError(error.AcceptanceMismatch, engine.execute(wrong_private));
    try t.expectEqual(@as(usize, 0), fixture.private_downloads);
    const private = try fixture.privateCommand(public, p.hash(fixture.public_receipt.?));
    defer a.free(private);
    try engine.execute(private);
    try t.expectEqual(host.state.Stage.done, fixture.store.record.stage);
    try t.expectEqual(@as(u8, 6), fixture.store.record.boots_attempted);
    try t.expectEqual(@as(u8, 6), fixture.store.record.boots_passed);
    try t.expectEqual(@as(usize, 2), fixture.private_downloads);
    try t.expectEqual(@as(usize, 8), fixture.publications);
    try t.expectError(error.PrematurePrivatePhase, engine.execute(private));
    try t.expectError(error.DuplicatePhase, engine.execute(public));
    try t.expectEqual(@as(u8, 6), fixture.store.record.boots_attempted);
    try t.expectEqualSlices(u8, &try hostBootId(), &fixture.store.record.host_boot_id);
    try t.expect(fixture.store.record.staging_bytes < p.max_staging);
    try t.expect(fixture.store.record.control_bytes < p.max_control);
    var launches: [6][36]u8 = undefined;
    for (0..6) |index| {
        const path = try std.fmt.allocPrint(a, "{s}/boot-{d}", .{ fixture.work_root, index });
        defer a.free(path);
        const directory = try host.core.private_files.Directory.open(io, path);
        defer directory.close(io);
        try t.expectError(error.FileNotFound, directory.openFile(io, "disk.img"));
        try t.expectError(error.FileNotFound, directory.openFile(io, "OVMF_VARS.fd"));
        const record = try directory.read(io, a, "outcome.json", 4096, null);
        defer a.free(record);
        try t.expect(std.mem.indexOf(u8, record, "\"passed\":true") != null);
        const parsed = try std.json.parseFromSlice(host.boot.Outcome, a, record, .{});
        defer parsed.deinit();
        try t.expectEqual(host.boot.EvidenceKind.synthetic_child, parsed.value.evidence_kind);
        try t.expectEqualStrings(&p.uuidText(try hostBootId()), &parsed.value.host_boot_id);
        try p.validUuid(try host.core.contracts.parseUuid(&parsed.value.launch_id));
        for (launches[0..index]) |previous| try t.expect(!std.mem.eql(u8, &previous, &parsed.value.launch_id));
        launches[index] = parsed.value.launch_id;
    }
}

test "signed stale wrong VM run runner manifest image nonce and unauthorized commands cannot boot" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    var engine = fixture.engine();
    const public = try fixture.command(.public, null);
    defer a.free(public);
    const cases = [_]struct { field: []const u8, value: std.json.Value }{
        .{ .field = "expires_at", .value = .{ .number_string = "999" } },
        .{ .field = "issued_at", .value = .{ .number_string = "1001" } },
        .{ .field = "vm_id", .value = .{ .string = f.run_text } },
        .{ .field = "run_id", .value = .{ .string = f.vm_text } },
        .{ .field = "phase_nonce", .value = .{ .string = "00000000-0000-0000-0000-000000000000" } },
        .{ .field = "runner_sha256", .value = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" } },
        .{ .field = "manifest_sha256", .value = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" } },
        .{ .field = "image_sha256", .value = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" } },
    };
    for (cases) |case| {
        const bytes = try mutated(public, case.field, case.value);
        defer a.free(bytes);
        if (engine.execute(bytes)) |_| return error.AcceptedInvalidCommand else |_| {}
    }
    engine.key = [_]u8{0x42} ** 32;
    try t.expectError(error.InvalidSignature, engine.execute(public));
    try t.expectEqual(@as(u8, 0), fixture.store.record.boots_attempted);
    try t.expectEqual(@as(usize, 0), fixture.downloads);
}

test "private transfer gate rejects valid signed premature phase and missing acceptance" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    var engine = fixture.engine();
    const public = try fixture.command(.public, null);
    defer a.free(public);
    const private = try fixture.privateCommand(public, p.hash("not-published"));
    defer a.free(private);
    try t.expectError(error.PrematurePrivatePhase, engine.execute(private));
    const missing = try fixture.command(.private, null);
    defer a.free(missing);
    if (engine.execute(missing)) |_| return error.AcceptedMissingAcceptance else |_| {}
    try t.expectEqual(@as(usize, 0), fixture.downloads);
    try t.expectEqual(@as(u8, 0), fixture.store.record.boots_attempted);
}

test "durably consumed phase and marker interruption prevent restarted boots" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    const bytes = try fixture.command(.public, null);
    defer a.free(bytes);
    var command = try p.Command.parse(a, bytes, f.key(), &fixture.admitted, f.scope(), f.uuid(f.vm_text), f.now);
    defer command.deinit();
    try fixture.store.begin(&command, bytes);
    try t.expectError(error.InterruptedIntent, host.state.Store.open(a, io, &fixture.locked, fixture.store.record));
    var engine = fixture.engine();
    try t.expectError(error.DuplicatePhase, engine.execute(bytes));
    try t.expectEqual(@as(u8, 0), fixture.store.record.boots_attempted);
    try t.expectEqual(@as(usize, 0), fixture.downloads);
    const second = try Fixture.init(0);
    defer second.deinit();
    try second.store.immutable("public-intent.json", bytes);
    var second_engine = second.engine();
    try t.expectError(error.PathAlreadyExists, second_engine.execute(bytes));
    try t.expectEqual(@as(usize, 0), second.downloads);
}

test "failed public receipt publication blocks private even with signed acceptance" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    fixture.fail_publication = 3;
    var engine = fixture.engine();
    const public = try fixture.command(.public, null);
    defer a.free(public);
    try t.expectError(error.EvidencePublicationFailed, engine.execute(public));
    try t.expectEqual(host.state.Stage.failed, fixture.store.record.stage);
    try t.expectEqual(host.state.Publication.unknown, fixture.store.record.publication);
    try t.expect(fixture.store.record.failures.recording != null);
    try t.expectEqual(@as(u8, 2), fixture.store.record.boots_passed);
    const private = try fixture.privateCommand(public, p.hash(fixture.public_receipt.?));
    defer a.free(private);
    try t.expectError(error.PrematurePrivatePhase, engine.execute(private));
    try t.expectEqual(@as(usize, 0), fixture.private_downloads);
}

test "actual child exit failure missing serial timeout and output ceiling stop public phase" {
    for ([_]u8{ 1, 2, 3, 4 }) |mode| {
        const fixture = try Fixture.init(mode);
        defer fixture.deinit();
        if (mode == 3) fixture.boot_timeout_ms = 200;
        var engine = fixture.engine();
        const public = try fixture.command(.public, null);
        defer a.free(public);
        try t.expectError(error.PhaseFailed, engine.execute(public));
        try t.expectEqual(host.state.Stage.failed, fixture.store.record.stage);
        try t.expectEqual(@as(u8, 1), fixture.store.record.boots_attempted);
        try t.expectEqual(@as(u8, 0), fixture.store.record.boots_passed);
        try t.expectEqual(@as(usize, 0), fixture.private_downloads);
        try t.expect(fixture.store.record.failures.primary != null);
        if (mode == 3) try t.expectEqual(host.core.diagnostics.Category.timeout, fixture.store.record.failures.primary.?.category);
        const private = try fixture.privateCommand(public, p.hash(fixture.public_receipt.?));
        defer a.free(private);
        try t.expectError(error.PrematurePrivatePhase, engine.execute(private));
    }
}

test "native wire child hard deadline persists interrupted operation separately" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    var remote: host.native.Supervised = .{
        .allocator = a,
        .io = io,
        .directory_path = fixture.directory.path,
        .self_executable = fixture.assets.executable_path,
        .locked = &fixture.locked,
        .store = &fixture.store,
        .scope = f.scope(),
        .vm_id = f.uuid(f.vm_text),
        .deadline = try host.core.process.Deadline.afterMilliseconds(200),
    };
    defer remote.deinit();
    const job: host.native.Job = .{ .version = 1, .action = .command, .scope = f.scope(), .vm_id = f.uuid(f.vm_text), .phase = .public, .command_sha256 = null, .role = null, .artifact_name = null, .evidence_name = null, .payload_sha256 = null, .deadline_ns = remote.deadline.expires_ns };
    try t.expectError(error.WireWorkerFailed, remote.call(job, null));
    try t.expect(fixture.store.record.wire_inflight);
    try t.expectEqual(host.core.diagnostics.Category.timeout, fixture.store.record.failures.primary.?.category);
    try t.expectError(error.InterruptedIntent, host.state.Store.open(a, io, &fixture.locked, fixture.store.record));
    try t.expectEqual(@as(u8, 0), fixture.store.record.boots_attempted);
    const operation = try host.files.durableDirectory(io, remote.last_directory.?);
    defer operation.close(io);
    const started = try operation.openFile(io, "fixture-wire-started");
    started.close(io);
}

test "separate primary cleanup recording outcomes persist without overwriting" {
    for ([_]u8{ 6, 7, 8 }) |mode| {
        const fixture = try Fixture.init(mode);
        defer fixture.deinit();
        var engine = fixture.engine();
        const public = try fixture.command(.public, null);
        defer a.free(public);
        try t.expectError(error.PhaseFailed, engine.execute(public));
        const failures = fixture.store.record.failures;
        if (mode != 6) {
            try t.expectEqual(host.core.diagnostics.Category.child_failed, failures.primary.?.category);
            try t.expectEqual(host.core.diagnostics.Category.cleanup_failed, failures.cleanup.?.category);
        }
        if (mode != 7) try t.expect(failures.recording != null);
        try t.expectEqual(@as(u8, 1), fixture.store.record.boots_attempted);
        try t.expectEqual(@as(u8, 0), fixture.store.record.boots_passed);
        const persisted = try fixture.directory.directory.read(io, a, "state.json", 4096, null);
        defer a.free(persisted);
        const parsed = try std.json.parseFromSlice(host.state.Record, a, persisted, .{});
        defer parsed.deinit();
        try t.expectEqualDeep(failures, parsed.value.failures);
    }
}

test "successful child cannot strand native descendants" {
    const fixture = try Fixture.init(5);
    defer fixture.deinit();
    var engine = fixture.engine();
    const public = try fixture.command(.public, null);
    defer a.free(public);
    try engine.execute(public);
    for (0..2) |index| {
        const path = try std.fmt.allocPrint(a, "{s}/boot-{d}", .{ fixture.work_root, index });
        defer a.free(path);
        const directory = try host.files.durableDirectory(io, path);
        defer directory.close(io);
        const bytes = try directory.read(io, a, "descendant.pid", 32, null);
        defer a.free(bytes);
        const pid = try std.fmt.parseInt(std.os.linux.pid_t, bytes, 10);
        const observed = std.os.linux.kill(pid, @enumFromInt(0));
        try t.expectEqual(std.os.linux.E.SRCH, std.os.linux.errno(observed));
    }
}

test "staging and control boundaries and direct stale helper refuse new boots" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    const boot_id = fixture.store.record.host_boot_id;
    try t.expectError(error.UnauthorizedBoot, host.native.validateBootState(fixture.store.record, 0, boot_id));
    const bytes = try fixture.command(.public, null);
    defer a.free(bytes);
    var command = try p.Command.parse(a, bytes, f.key(), &fixture.admitted, f.scope(), f.uuid(f.vm_text), f.now);
    defer command.deinit();
    try fixture.store.begin(&command, bytes);
    _ = try fixture.store.bootIntent(.public);
    try host.native.validateBootState(fixture.store.record, 0, boot_id);
    try t.expectError(error.UnauthorizedBoot, host.native.validateBootState(fixture.store.record, 1, boot_id));
    try t.expectError(error.UnauthorizedBoot, host.native.validateBootState(fixture.store.record, 6, boot_id));
    try t.expectError(error.UnauthorizedBoot, host.native.validateBootState(fixture.store.record, 0, f.uuid(f.vm_text)));
    fixture.store.fail(.{ .primary = .{ .stage = .host_phase, .category = .timeout } });
    try t.expectError(error.UnauthorizedBoot, host.native.validateBootState(fixture.store.record, 0, boot_id));
    try t.expectError(error.StagingBudgetExceeded, fixture.store.reserve(p.max_staging, false, false));
    try t.expectError(error.ControlAllowanceExceeded, fixture.store.reserve(p.max_control, true, false));
    try t.expectError(error.EvidenceBudgetExceeded, fixture.store.reserve(p.max_evidence + 1, false, true));
}

test "manifest role duplication forbidden paths missing images and size bounds precede transfer" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    var engine = fixture.engine();
    const original = try fixture.assets.records(.public);
    const records = try a.dupe(f.Artifact, original);
    defer a.free(records);
    const cases = [_]u8{ 0, 1, 2, 3, 4 };
    for (cases) |case| {
        @memcpy(records, original);
        var selected = records;
        switch (case) {
            0 => records[3] = records[0],
            1 => records[3].name = "../private.raw",
            2 => selected = records[0..3],
            3 => records[3].size = p.max_artifact + 1,
            4 => records[3].blob = "runs/other/private/artifacts/private.raw",
            else => unreachable,
        }

        const bytes = try f.command(.public, selected, p.hash(fixture.assets.raw), null);
        defer a.free(bytes);
        if (engine.execute(bytes)) |_| return error.AcceptedBadManifest else |_| {}
    }
    try t.expectEqual(@as(usize, 0), fixture.downloads);
    try t.expectEqual(@as(u8, 0), fixture.store.record.boots_attempted);
}

fn signedManifest(body: std.json.Value) ![]u8 {
    const bytes = try p.canonical(a, try p.field(body, "manifest"));
    defer a.free(bytes);
    const digest = p.hex(p.hash(bytes));
    const field = body.object.getPtr("manifest_sha256").?;
    const previous = field.*;
    defer field.* = previous;
    field.* = .{ .string = &digest };
    return f.signBody(body, "uk-hyperv-host-command-v1");
}

test "signed guarded producer contract and main-zero private policy remain native gates" {
    const fixture = try Fixture.init(0);
    defer fixture.deinit();
    const public = try fixture.command(.public, null);
    defer a.free(public);
    const private = try fixture.privateCommand(public, p.hash("not-yet-published"));
    defer a.free(private);
    var doc = try host.core.contracts.Document.parse(a, private, .{ .bytes = p.max_command, .items = 2048, .tokens = 16384 });
    defer doc.deinit();
    const body = try p.field(doc.value(), "body");
    const manifest = try p.field(body, "manifest");
    const guarded_json = try f.json(.{
        .run_id = "0123456789abcdef0123456789abcdef",
        .disk_id = "fedcba9876543210fedcba9876543210",
        .lun = 17,
        .sectors = 4096,
        .solved_config_sha256 = @as([]const u8, &p.hex(f.runner_hash)),
        .producer_sha256 = @as([]const u8, &p.hex(f.producer_hash)),
    });
    defer a.free(guarded_json);
    var guarded = try host.core.contracts.Document.parse(a, guarded_json, .{});
    defer guarded.deinit();
    manifest.object.getPtr("guarded").?.* = guarded.value();
    manifest.object.getPtr("policy").?.* = .{ .string = "guarded-v2-pristine-unavailable" };
    const signed = try signedManifest(body);
    defer a.free(signed);
    var command = try p.Command.parse(a, signed, f.key(), &fixture.admitted, f.scope(), f.uuid(f.vm_text), f.now);
    defer command.deinit();
    try t.expectEqual(p.Policy.guarded_v2, command.policy);
    try t.expectEqual(@as(u64, 4096), command.guarded.?.sectors);
    guarded.value().object.getPtr("producer_sha256").?.* = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" };
    const bad = try signedManifest(body);
    defer a.free(bad);
    try t.expectError(error.ProducerNotAdmitted, p.Command.parse(a, bad, f.key(), &fixture.admitted, f.scope(), f.uuid(f.vm_text), f.now));
    manifest.object.getPtr("guarded").?.* = .null;
    manifest.object.getPtr("policy").?.* = .{ .string = "platform-main-zero-v1" };
    const main_zero = try signedManifest(body);
    defer a.free(main_zero);
    var zero = try p.Command.parse(a, main_zero, f.key(), &fixture.admitted, f.scope(), f.uuid(f.vm_text), f.now);
    defer zero.deinit();
    try t.expectEqual(p.Policy.platform_main_zero, zero.policy);
    try t.expectEqual(@as(usize, 0), fixture.downloads);
}
