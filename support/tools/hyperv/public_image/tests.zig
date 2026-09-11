const std = @import("std");
const image = @import("public_image");
const c = image.contracts;
const t = std.testing;
const a = t.allocator;
const io = t.io;
const options = @import("test_options");
const serial_fixture = @import("fixture.zig");
const config_text = "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION=y\n" ++
    "CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4=\"10.77.0.20\"\nCONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=42001\n" ++
    "CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT=42002\nCONFIG_APPHYPERVACCEPTANCE_NONCE=\"0123456789abcdef\"\n";
const source: c.Source = .{
    .repository = "cataggar/unikraft",
    .repository_id = 123,
    .workflow_ref = "cataggar/unikraft/.github/workflows/integration.yaml@refs/heads/main",
    .run_id = 456,
    .run_attempt = 1,
    .head_sha = "0123456789abcdef0123456789abcdef01234567",
};
fn efi() [512]u8 {
    var bytes = [_]u8{0} ** 512;
    bytes[0..2].* = "MZ".*;
    std.mem.writeInt(u32, bytes[0x3c..0x40], 0x80, .little);
    bytes[0x80..0x84].* = "PE\x00\x00".*;
    std.mem.writeInt(u16, bytes[0x84..0x86], 0x8664, .little);
    std.mem.writeInt(u16, bytes[0x86..0x88], 1, .little);
    std.mem.writeInt(u16, bytes[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u16, bytes[0x98..0x9a], 0x20b, .little);
    std.mem.writeInt(u16, bytes[0xdc..0xde], 10, .little);
    return bytes;
}
const Fixture = struct {
    arena: *std.heap.ArenaAllocator,
    root: image.core.private_files.Directory,
    dir: image.core.private_files.Directory,
    name: []const u8,
    path: []const u8,
    cli: []const u8,
    input: c.Input,
    fn init(mode: u8, network: bool) !Fixture {
        try image.core.process.initialize();
        const arena = try a.create(std.heap.ArenaAllocator);
        arena.* = .init(a);
        const alloc = arena.allocator();
        const root_path = options.test_root orelse return error.MissingFixtureRoot;
        const root = try image.core.private_files.Directory.open(io, root_path);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(alloc, "public,case-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        const path = try image.files.path(alloc, root_path, name);
        const dir = try image.files.create(io, path);
        try dir.dir.writeFile(io, .{ .sub_path = "public,image.efi", .data = &efi(), .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.writeFile(io, .{ .sub_path = "code,template.fd", .data = "synthetic firmware", .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.writeFile(io, .{ .sub_path = "vars,template.fd", .data = &.{ 0xa5, mode }, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        if (network) try dir.dir.writeFile(io, .{ .sub_path = "solved.config", .data = config_text, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        return .{
            .arena = arena,
            .root = root,
            .dir = dir,
            .name = name,
            .path = path,
            .cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, alloc),
            .input = .{
                .efi = try image.files.path(alloc, path, "public,image.efi"),
                .state_dir = try image.files.path(alloc, path, "state"),
                .qemu = try std.Io.Dir.cwd().realPathFileAlloc(io, options.fixture, alloc),
                .ovmf_code = try image.files.path(alloc, path, "code,template.fd"),
                .ovmf_vars = try image.files.path(alloc, path, "vars,template.fd"),
                .solved_config = if (network) try image.files.path(alloc, path, "solved.config") else null,
                .timeout_ms = 10_000,
            },
        };
    }
    fn deinit(self: Fixture) void {
        self.dir.close(io);
        self.root.dir.deleteTree(io, self.name) catch @panic("owned synthetic fixture cleanup failed");
        self.root.close(io);
        self.arena.deinit();
        a.destroy(self.arena);
    }
    fn prepare(self: Fixture) !c.State {
        return image.engine.prepare(self.arena.allocator(), io, self.input, .{ .self_executable = self.cli });
    }
    fn stateDir(self: Fixture) !image.core.private_files.Directory {
        return image.core.private_files.Directory.open(io, self.input.state_dir);
    }
};
test "native miz creates exact raw GPT fixed VHD genuine four-mode wire and durable exact export" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const state = try f.prepare();
    if (state.phase != .prepared) std.debug.print("synthetic failure: {any}\n", .{state.failures});
    try t.expectEqual(c.Phase.prepared, state.phase);
    try t.expectEqual(@as(u64, c.raw_bytes), state.package.?.raw.size);
    try t.expectEqual(@as(u64, c.vhd_bytes), state.package.?.vhd.size);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    const loaded = try image.engine.load(alloc, io, &lock, f.cli);
    try t.expectEqual(c.Phase.prepared, loaded.phase);
    const target = try image.files.path(alloc, f.path, "export");
    const published = image.manifest.publish(alloc, io, &lock, f.cli, target, source);
    try t.expect(image.engine.clean(published.failures));
    try t.expect(published.sha256 != null);
    const exported = try image.core.private_files.Directory.open(io, target);
    defer exported.close(io);
    const bytes = try exported.read(io, alloc, image.manifest.name, c.max_record, published.sha256);
    const manifest = try image.manifest.validate(alloc, bytes, source, try c.sha(state.inputs.producer.sha256));
    try t.expectEqual(@as(u8, 4), manifest.controller_revision);
    const exported_disk = try image.files.record(alloc, io, try image.files.path(alloc, target, "unikraft.vhd"), c.vhd_bytes, false);
    try t.expectEqualStrings(state.package.?.vhd.sha256, exported_disk.sha256);
    try t.expectEqual(state.package.?.vhd.size, exported_disk.size);
    var incorrect = manifest;
    incorrect.controller_revision = 3;
    try t.expectError(error.UnsupportedController, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    incorrect = manifest;
    incorrect.artifacts.vhd.size -= 512;
    try t.expectError(error.InvalidManifest, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    incorrect = manifest;
    incorrect.source.run_attempt += 1;
    try t.expectError(error.RecordMismatch, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    incorrect = manifest;
    incorrect.packaging.@"virtual-size" += 512;
    try t.expectError(error.RecordMismatch, image.manifest.validate(alloc, try c.encode(alloc, incorrect), source, try c.sha(state.inputs.producer.sha256)));
    var entries = exported.dir.iterate();
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        try t.expect(std.mem.eql(u8, entry.name, "unikraft.vhd") or std.mem.eql(u8, entry.name, image.manifest.name));
        count += 1;
    }
    try t.expectEqual(@as(usize, 2), count);
    try t.expect(image.manifest.publish(alloc, io, &lock, f.cli, target, source).sha256 == null);
    try t.expectError(error.PathAlreadyExists, f.prepare());
}
test "direct native package structurally validates synthetic PE raw and fixed VHD" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const root = try image.files.create(io, f.input.state_dir);
    defer root.close(io);
    const input = try image.files.record(alloc, io, f.input.efi, c.max_efi, false);
    const report = try image.package.build(alloc, io, root, input);
    try t.expectEqual(@as(u64, c.vhd_bytes), report.vhd.size);
    try image.files.cleanupStage(io, root, "package-stage");
}
test "native input and private evidence permissions and malformed PE refuse" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const file = try f.dir.dir.openFile(io, "public,image.efi", .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o666));
    if (f.prepare()) |_| return error.AcceptedWritableImage else |_| {}
    try file.setPermissions(io, .fromMode(0o644));
    try file.writePositionalAll(io, "BAD", 0);
    const state = try f.prepare();
    try t.expectEqual(c.Phase.failed, state.phase);
    try t.expect(state.package == null);
    const root = try f.stateDir();
    defer root.close(io);
    const state_file = try root.openFile(io, "state.json");
    defer state_file.close(io);
    try state_file.setPermissions(io, .fromMode(0o644));
    if (root.read(io, f.arena.allocator(), "state.json", c.max_record, null)) |_| return error.AcceptedPublicState else |_| {}
}
test "native solved-config transcript and all four public network configuration-only boots" {
    const f = try Fixture.init(0, true);
    defer f.deinit();
    const state = try f.prepare();
    try t.expectEqual(c.Phase.prepared, state.phase);
    const config = (try image.network.parse(state.acceptance)).?;
    try t.expectEqual(@as(u32, 1760), config.transcript.tcp_bytes);
    try t.expectEqual(@as(u32, 3408), config.transcript.udp_bytes);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    _ = try image.engine.load(f.arena.allocator(), io, &lock, f.cli);
}
test "public serial rejects colliding return APIC mismatch live IO and duplicate network config" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const raw = try image.network.raw(alloc);
    const config: image.boot.config.Config = .{ .raw_disk = "/public/raw", .qemu = "/public/qemu", .ovmf_code = "/public/code", .ovmf_vars = "/public/vars", .work_dir = "/public/work", .expect = c.platform_marker, .expect_main_return = 2 };
    const good = serial_fixture.prefix ++ serial_fixture.application ++ serial_fixture.terminal;
    try image.network.serial(alloc, good, config, raw);
    for ([_][]const u8{ "main returned 20", "main returned 0", "main returned 2 trailing", "spoof main returned 2" }) |replacement| {
        const bad = try std.mem.replaceOwned(u8, alloc, good, serial_fixture.terminal, replacement);
        if (image.network.serial(alloc, bad, config, raw)) |_| return error.AcceptedBadSerial else |_| {}
    }
    for ([_][]const u8{ "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY", c.legacy_marker, "HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS" }) |extra| {
        const bad = try std.fmt.allocPrint(alloc, "{s}{s}\n", .{ good, extra });
        if (image.network.serial(alloc, bad, config, raw)) |_| return error.AcceptedBadSerial else |_| {}
    }
    const net = try image.network.fromConfig(alloc, config_text);
    const marker = try image.network.marker(alloc, (try image.network.parse(net)).?);
    const network_good = try std.fmt.allocPrint(alloc, "{s}{s}{s}\n{s}", .{ serial_fixture.prefix, serial_fixture.application, marker, serial_fixture.terminal });
    try image.network.serial(alloc, network_good, config, net);
    for ([_][]const u8{
        try std.fmt.allocPrint(alloc, "{s}{s}\n", .{ good, marker }),
        try std.fmt.allocPrint(alloc, "{s}{s}{s}\n{s}\n{s}", .{ serial_fixture.prefix, serial_fixture.application, marker, marker, serial_fixture.terminal }),
        try std.mem.replaceOwned(u8, alloc, network_good, "nonce=0123456789abcdef", "nonce=1123456789abcdef"),
        good,
    }) |bad| if (image.network.serial(alloc, bad, config, net)) |_| return error.AcceptedBadNetwork else |_| {};
}

test "source provenance exact canonical integers repository workflow revision job and hashes" {
    try source.validate();
    for ([_][]const u8{
        "",                                                                 "other/repo/.github/workflows/a.yaml@refs/heads/main",
        "cataggar/unikraft/.github/workflows/.yaml@refs/heads/main",        "cataggar/unikraft/.github/workflows/a.yaml@main",
        "cataggar/unikraft/.github/workflows/a.yaml@refs/heads/../main",    "cataggar/unikraft/.github/workflows/a.yaml@refs/",
        "cataggar/unikraft/.github/workflows/a.yaml@refs/heads/main@extra",
    }) |workflow| {
        var bad = source;
        bad.workflow_ref = workflow;
        try t.expectError(error.InvalidSource, bad.validate());
    }
    for ([_][]const u8{ "", "x/y/z", "https://example.test/repo", "x/\nrepo" }) |repository| {
        var bad = source;
        bad.repository = repository;
        try t.expectError(error.InvalidSource, bad.validate());
    }
    var bad = source;
    bad.job = "other-job";
    try t.expectError(error.InvalidSource, bad.validate());
    bad = source;
    bad.run_attempt = 0;
    try t.expectError(error.InvalidSource, bad.validate());
    bad = source;
    bad.head_sha = "A" ** 40;
    try t.expectError(error.InvalidSource, bad.validate());
}
test "solved config missing duplicate typed noncanonical network settings refuse" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    for ([_][]const u8{
        "",                                                                                 config_text ++ "CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT=42001\n",
        try std.mem.replaceOwned(u8, alloc, config_text, "10.77.0.20", "8.8.8.8"),          try std.mem.replaceOwned(u8, alloc, config_text, "10.77.0.20", "010.77.0.20"),
        try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=42002"),               try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=\"42001\""),
        try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=0"),                   try std.mem.replaceOwned(u8, alloc, config_text, "=42001", "=65536"),
        try std.mem.replaceOwned(u8, alloc, config_text, "APPLICATION=y", "APPLICATION=n"), try std.mem.replaceOwned(u8, alloc, config_text, "0123456789abcdef", "short"),
    }) |bad| if (image.network.fromConfig(alloc, bad)) |_| return error.AcceptedBadConfig else |_| {};
    const with_other = config_text ++ "CONFIG_UNRELATED_INTEGER=12345\nCONFIG_UNRELATED_HEX=deadbeef\n";
    const accepted = try image.network.fromConfig(alloc, with_other);
    try t.expectEqualStrings(try c.hex(alloc, c.hash(with_other)), (try image.network.parse(accepted)).?.solved_config_sha256);
    const upper = try std.mem.replaceOwned(u8, alloc, config_text, "abcdef", "ABCDEF");
    try t.expectEqualStrings("0123456789abcdef", (try image.network.parse(try image.network.fromConfig(alloc, upper))).?.nonce);
}
test "native partial matrix nonzero bad markers input mutation and independent failure evidence" {
    for ([_]u8{ 1, 2, 3, 6, 7, 9, 10, 11, 12 }) |mode| {
        const f = try Fixture.init(mode, mode == 12);
        defer f.deinit();
        const state = try f.prepare();
        try t.expectEqual(c.Phase.failed, state.phase);
        try t.expect(!image.engine.clean(state.failures));
        if (mode == 6) {
            try t.expect(state.failures.cleanup != null);
            try t.expect(state.failures.primary == null);
        }
        if (mode == 7) try t.expect(state.failures.recording != null);
        if (mode == 9) try t.expectEqual(image.core.diagnostics.Category.integrity, state.failures.primary.?.category);
        if (mode == 1) {
            try t.expect(state.boots[0] != null and state.boots[1] != null and state.boots[2] == null and state.boots[3] == null);
        } else try t.expect(state.boots[0] == null);
        const root = try f.stateDir();
        defer root.close(io);
        var lock = try root.lock(io);
        defer lock.close(io);
        try t.expectError(error.NotPrepared, image.engine.load(f.arena.allocator(), io, &lock, f.cli));
        const log = try root.read(io, f.arena.allocator(), "local-raw-x2apic-serial.log", image.boot.config.max_serial, null);
        try t.expect(log.len > 0 and std.mem.indexOf(u8, log, "synthetic stderr retained") != null);
        try t.expectError(error.PathAlreadyExists, f.prepare());
    }
}
test "native hard deadline output limit cancellation and descendant group cleanup" {
    for ([_]u8{ 4, 5, 8 }) |mode| {
        var f = try Fixture.init(mode, false);
        defer f.deinit();
        f.input.timeout_ms = 3000;
        const state = try f.prepare();
        if (mode == 8) {
            try t.expectEqual(c.Phase.prepared, state.phase);
            for (0..4) |index| {
                const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(f.arena.allocator(), state, index)).work_dir);
                defer work.close(io);
                const pid_text = try work.read(io, f.arena.allocator(), "descendant.pid", 16, null);
                const pid = try std.fmt.parseInt(u32, pid_text, 10);
                try t.expectEqual(std.os.linux.E.SRCH, std.os.linux.errno(std.os.linux.syscall2(.kill, pid, 0)));
            }
        } else {
            try t.expectEqual(c.Phase.failed, state.phase);
            if (mode == 4) try t.expectEqual(image.core.diagnostics.Category.timeout, state.failures.primary.?.category);
            const root = try f.stateDir();
            defer root.close(io);
            const bytes = try root.read(io, f.arena.allocator(), "local-raw-x2apic-serial.log", image.boot.config.max_serial, null);
            try t.expect(bytes.len > 0 and bytes.len <= image.boot.config.max_serial);
            if (mode == 5) {
                const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(f.arena.allocator(), state, 0)).work_dir);
                defer work.close(io);
                const report = try image.boot.runner.Report.decode(f.arena.allocator(), try work.read(io, f.arena.allocator(), "report.json", c.max_record, null));
                try t.expect(report.serial_limit_reached and report.serial_bytes == image.boot.config.max_serial);
            }
        }
    }
    const f = try Fixture.init(0, false);
    defer f.deinit();
    var cancel = std.atomic.Value(bool).init(true);
    const cancelled = try image.engine.prepare(f.arena.allocator(), io, f.input, .{ .self_executable = f.cli, .cancel = &cancel });
    try t.expectEqual(c.Phase.failed, cancelled.phase);
    try t.expectEqual(image.core.diagnostics.Category.cancelled, cancelled.failures.primary.?.category);
    try t.expect(cancelled.package == null);
}
test "physical loader rejects incomplete tampered matrix requests logs packages and source bytes" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const state = try f.prepare();
    try t.expectEqual(c.Phase.prepared, state.phase);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    var changed = state;
    changed.phase = .preparing;
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, changed)));
    try t.expectError(error.NotPrepared, image.engine.load(alloc, io, &lock, f.cli));
    changed = state;
    changed.boots[3] = null;
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, changed)));
    try t.expectError(error.IncompleteMatrix, image.engine.load(alloc, io, &lock, f.cli));
    try image.files.durable(try lock.commit(io, "state.json", try c.encode(alloc, state)));
    for ([_][]const u8{ "BOOTX64.EFI", "unikraft.raw", "unikraft.vhd" }) |name| {
        const file = try root.openFile(io, name);
        defer file.close(io);
        try file.setPermissions(io, .fromMode(0o644));
        if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedPublicPreparedFile else |_| {}
        try file.setPermissions(io, .fromMode(0o600));
    }
    for ([_][]const u8{ "prepare.json", "packaging.json", "package-report.json", "local-raw-x2apic-serial.log", "BOOTX64.EFI", "unikraft.raw", "unikraft.vhd" }) |name| {
        const file = try root.dir.openFile(io, name, .{ .mode = .read_write });
        defer file.close(io);
        const pos: u64 = if (std.mem.eql(u8, name, "unikraft.vhd")) c.vhd_bytes - 1 else 0;
        var original: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &original, pos);
        try file.writePositionalAll(io, &.{original[0] ^ 1}, pos);
        if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedTamperedEvidence else |_| {}
        try file.writePositionalAll(io, &original, pos);
    }
    const work = try image.core.private_files.Directory.open(io, (try image.engine.bootConfig(alloc, state, 2)).work_dir);
    defer work.close(io);
    for ([_][]const u8{ "request.json", "report.json", image.boot.config.log_name }) |name| {
        const file = try work.dir.openFile(io, name, .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, 0);
        try file.writePositionalAll(io, &.{byte[0] ^ 1}, 0);
        if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedTamperedEvidence else |_| {}
        try file.writePositionalAll(io, &byte, 0);
    }
    _ = try image.engine.load(alloc, io, &lock, f.cli);
    const valid = try c.encode(alloc, state);
    const duplicate = try std.fmt.allocPrint(alloc, "{{\"phase\":\"prepared\",{s}", .{valid[1..]});
    try image.files.durable(try lock.commit(io, "state.json", duplicate));
    if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedDuplicate else |_| {}
    const azure = try std.fmt.allocPrint(alloc, "{{\"resource_group\":\"not-authorized\",{s}", .{valid[1..]});
    try image.files.durable(try lock.commit(io, "state.json", azure));
    if (image.engine.load(alloc, io, &lock, f.cli)) |_| return error.AcceptedUnknownFields else |_| {}
}
fn command(f: Fixture, args: []const []const u8) !std.process.RunResult {
    var environment: std.process.Environ.Map = .init(f.arena.allocator());
    defer environment.deinit();
    try environment.put("TMPDIR", f.path);
    try environment.put("PUBLIC_SENTINEL_NOT_FOR_QEMU", "synthetic");
    return std.process.run(f.arena.allocator(), io, .{ .argv = args, .cwd = .{ .dir = f.dir.dir }, .environ_map = &environment, .stdout_limit = .limited(c.max_record), .stderr_limit = .limited(c.max_record) });
}
test "actual native CLI prepare matrix exact export digest and refusal boundaries" {
    const f = try Fixture.init(0, false);
    defer f.deinit();
    const alloc = f.arena.allocator();
    const prepare_args = [_][]const u8{ f.cli, "prepare", "--efi", f.input.efi, "--qemu", f.input.qemu, "--ovmf-code", f.input.ovmf_code, "--ovmf-vars", f.input.ovmf_vars, "--state-dir", f.input.state_dir, "--timeout", "10" };
    for ([_][]const []const u8{ &.{ "--timeout", "0" }, &.{ "--timeout", "NaN" }, &.{ "--miz", "/unused" }, &.{ "--fixture-mode", "success" }, &.{ "--state-dir", f.input.state_dir }, &.{ "--cpus", "2" } }) |extra| {
        const failed = try command(f, try std.mem.concat(alloc, []const u8, &.{ &prepare_args, extra }));
        try t.expect(failed.term == .exited and failed.term.exited != 0 and failed.stdout.len == 0);
        try t.expect(std.mem.indexOf(u8, failed.stderr, f.input.efi) == null);
    }
    const prepared = try command(f, &prepare_args);
    try t.expect(prepared.term == .exited and prepared.term.exited == 0);
    const matrix = try command(f, &.{ f.cli, "validate-matrix", "--state-dir", f.input.state_dir });
    try t.expect(matrix.term == .exited and matrix.term.exited == 0);
    const target = try image.files.path(alloc, f.path, "artifact");
    const exported = try command(f, &.{ f.cli, "export-prepared", "--state-dir", f.input.state_dir, "--artifact-dir", target, "--source-repository", source.repository, "--source-repository-id", "123", "--source-workflow-ref", source.workflow_ref, "--source-job", source.job, "--source-run-id", "456", "--source-run-attempt", "1", "--source-head-sha", source.head_sha });
    try t.expect(exported.term == .exited and exported.term.exited == 0 and exported.stderr.len == 0);
    try t.expectEqual(@as(usize, 65), exported.stdout.len);
    const digest = try c.sha(exported.stdout[0..64]);
    try t.expectEqual(@as(u8, '\n'), exported.stdout[64]);
    const output = try image.core.private_files.Directory.open(io, target);
    defer output.close(io);
    _ = try output.read(io, alloc, image.manifest.name, c.max_record, digest);
    const root = try f.stateDir();
    defer root.close(io);
    var lock = try root.lock(io);
    defer lock.close(io);
    const locked = try command(f, &.{ f.cli, "validate-matrix", "--state-dir", f.input.state_dir });
    try t.expect(locked.term == .exited and locked.term.exited != 0);
}
