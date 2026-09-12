const std = @import("std");
const boot = @import("local_boot");
const core = boot.core;
const t = std.testing;
const a = t.allocator;
const io = t.io;
const options = @import("test_options");
const fixture_log = @import("fixture.zig").log;
const diagnostics = @import("synthetic_diagnostics");

fn unitConfig() boot.config.Config {
    return .{ .image = "/synthetic/image", .ovmf_code = "/synthetic/code", .ovmf_vars = "/synthetic/vars", .qemu = "/synthetic/qemu", .work_dir = "/synthetic/work", .expect = "Hello world!" };
}

test "legacy application and each required milestone including terminal" {
    const config = unitConfig();
    try boot.serial.validate(a, fixture_log, config);
    try boot.serial.validate(a, std.mem.trimEnd(u8, fixture_log, "\n"), config);
    for (boot.serial.milestones ++ [_][]const u8{ "Hello world!", "main returned 0" }) |marker| {
        const missing = try std.mem.replaceOwned(u8, a, fixture_log, marker, "missing");
        defer a.free(missing);
        if (boot.serial.validate(a, missing, config)) |_| return error.AcceptedMissingMilestone else |_| {}
    }
}

test "crash after application or return is never success" {
    for ([_][]const u8{ "Unikraft Crash", "Assertion failure", "Exception Type" }) |failure| {
        const bad = try std.mem.concat(a, u8, &.{ fixture_log, failure, "\n" });
        defer a.free(bad);
        try t.expectError(error.GuestCrash, boot.serial.validate(a, bad, unitConfig()));
    }
}

test "terminal exact signed value anchored envelope and feature combinations" {
    const terminal = "[    0.123456] Info: [libukboot] <boot.c @  544> main returned 0";
    for ([_][]const u8{
        "main returned 0",
        "Info: [libukboot] main returned 0",
        "[123456.000001] Info: <main> {r:0x1234,f:0} [libukboot] <boot.c @  544> main returned 0",
        "Info: <init> [libukboot] <boot.c @    1> main returned 0",
        "Info: <<n/a>> [libukboot] main returned 0",
        "Info: <0xffff800012345678> [libukboot] <boot.c @ 10000> main returned 0",
        "\x1b[0m\x1b[32m[    0.123456] \x1b[0mInfo: [libukboot] <boot.c @  544> \x00main returned 0\r\n\x1b[0m\x00",
    }) |valid| {
        const text = try std.mem.replaceOwned(u8, a, fixture_log, terminal, valid);
        defer a.free(text);
        try boot.serial.validate(a, text, unitConfig());
    }
    for ([_]i32{ -2147483648, -1, 2, 2147483647 }) |value| {
        var config = unitConfig();
        config.expect_main_return = value;
        const replacement = try std.fmt.allocPrint(a, "main returned {d}", .{value});
        defer a.free(replacement);
        const text = try std.mem.replaceOwned(u8, a, fixture_log, "main returned 0", replacement);
        defer a.free(text);
        try boot.serial.validate(a, text, config);
    }
    for ([_][]const u8{
        "main returned 10",                                  "main returned -1",                                 "main returned 00",                                   "main returned +0",
        "main returned 0 suffix",                            "main returned 0.0",                                "main returned 2147483648",                           "spoof main returned 0",
        "prefix " ++ terminal,                               "Info: [libother] <boot.c @  544> main returned 0", "Info: [libukboot] <spoof.c @  544> main returned 0", "[0.123456] Info: [libukboot] main returned 0",
        "[    0.12345] Info: [libukboot] main returned 0",   "Info: <spoof> [libukboot] main returned 0",        "Info: {r:123,f:0} [libukboot] main returned 0",      "Info: [libukboot] <boot.c @ 0544> main returned 0",
        "Info: [libukboot] <boot.c @    0> main returned 0",
    }) |invalid| {
        const text = try std.mem.replaceOwned(u8, a, fixture_log, terminal, invalid);
        defer a.free(text);
        if (boot.serial.validate(a, text, unitConfig())) |_| return error.AcceptedInvalidReturn else |_| {}
    }
    const duplicate = try std.mem.concat(a, u8, &.{ fixture_log, "main returned 0\n" });
    defer a.free(duplicate);
    try t.expectError(error.DuplicateMainReturn, boot.serial.validate(a, duplicate, unitConfig()));
}

test "milestone and repeated required-marker order forbidden markers and bounds" {
    var config = unitConfig();
    config.required = &.{ "at GPA", "synthetic IRQs", "Hello world!" };
    config.forbidden = &.{"no-such-marker"};
    try boot.serial.validate(a, fixture_log, config);
    config.required = &.{ "synthetic IRQs", "at GPA" };
    try t.expectError(error.ReorderedRequired, boot.serial.validate(a, fixture_log, config));
    config.required = &.{"not-present"};
    try t.expectError(error.MissingRequired, boot.serial.validate(a, fixture_log, config));
    config.required = &.{};
    config.forbidden = &.{"synthetic IRQs"};
    try t.expectError(error.ForbiddenMarker, boot.serial.validate(a, fixture_log, config));
    const swapped = try std.mem.replaceOwned(u8, a, fixture_log, "Calling main(1, ['synthetic'])\nHello world!", "Hello world!\nCalling main(1, ['synthetic'])");
    defer a.free(swapped);
    try t.expectError(error.ReorderedMilestone, boot.serial.validate(a, swapped, unitConfig()));
    const early = try std.mem.concat(a, u8, &.{ "main returned 0\n", fixture_log });
    defer a.free(early);
    try t.expectError(error.DuplicateMainReturn, boot.serial.validate(a, early, unitConfig()));
    for ([_][]const u8{ "\x1b[0", "\x1b", "\x01", "\xff" }) |suffix| {
        const invalid = try std.mem.concat(a, u8, &.{ fixture_log, suffix });
        defer a.free(invalid);
        try t.expectError(error.InvalidSerial, boot.serial.validate(a, invalid, unitConfig()));
    }
    const long = try std.mem.concat(a, u8, &.{ "x" ** 8193, "\n", fixture_log });
    defer a.free(long);
    try t.expectError(error.SerialLineLimit, boot.serial.validate(a, long, unitConfig()));
}

const base_args = [_][]const u8{ "--image", "/synthetic/image", "--ovmf-code", "/synthetic/code", "--ovmf-vars", "/synthetic/vars", "--qemu", "/synthetic/qemu", "--work-dir", "/synthetic/work", "--expect", "Hello world!" };
test "CLI defaults exact decimal timeout and CPU bounds" {
    const defaults = try boot.config.parse(a, &base_args);
    defer a.free(defaults.required);
    defer a.free(defaults.forbidden);
    try t.expectEqual(@as(u8, 1), defaults.cpus);
    try t.expectEqual(@as(u32, 30_000), defaults.timeout_ms);
    try t.expectEqual(@as(i32, 0), defaults.expect_main_return);
    for ([_][]const u8{ "1", "2", "8" }) |cpus| {
        const args = base_args ++ [_][]const u8{ "--cpus", cpus };
        const parsed = try boot.config.parse(a, &args);
        defer a.free(parsed.required);
        defer a.free(parsed.forbidden);
        try t.expectEqual(try boot.config.integer(u8, cpus), parsed.cpus);
    }
    for ([_]struct { text: []const u8, ms: u32 }{
        .{ .text = "0.001", .ms = 1 },         .{ .text = "0.5", .ms = 500 },
        .{ .text = "30", .ms = 30_000 },       .{ .text = "60.25", .ms = 60_250 },
        .{ .text = "120.000", .ms = 120_000 },
    }) |value| try t.expectEqual(value.ms, try boot.config.timeout(value.text));
    for ([_][]const u8{ "0", "-1", "NaN", "inf", "1e2", ".5", "1.", "0.0001", "120.001", "121", "999999999999999999" }) |value| {
        if (boot.config.timeout(value)) |_| return error.AcceptedInvalidTimeout else |_| {}
    }
}

test "CLI rejects invalid source counts paths markers repetitions and unknown controls" {
    for ([_][]const []const u8{
        &.{ "--cpus", "0" },                     &.{ "--cpus", "9" },                                          &.{ "--cpus", "-1" },
        &.{ "--cpus", "2", "--disable-x2apic" }, &.{"--cpus"},                                                 &.{ "--raw-disk", "/synthetic/raw" },
        &.{ "--qemu", "/duplicate" },            &.{ "--timeout", "NaN" },                                     &.{ "--timeout", "0" },
        &.{ "--fixture-mode", "success" },       &.{"--disable-x2apic=1"},                                     &.{ "--require-marker", "" },
        &.{ "--forbid-marker", "Hello" },        &.{ "--require-marker", "same", "--require-marker", "same" }, &.{ "--require-marker", "line\nbreak" },
    }) |extra| {
        const args = try std.mem.concat(a, []const u8, &.{ &base_args, extra });
        defer a.free(args);
        if (boot.config.parse(a, args)) |parsed| {
            a.free(parsed.required);
            a.free(parsed.forbidden);
            return error.AcceptedInvalidCli;
        } else |_| {}
    }
    var config = unitConfig();
    for ([_][]const u8{ "qemu", "/path/../qemu", "/path//qemu", "/path/qemu/", "/path/\x00qemu" }) |path| {
        config.qemu = path;
        if (config.validate()) |_| return error.AcceptedUnsafePath else |_| {}
    }
    config = unitConfig();
    config.required = &([_][]const u8{"marker"} ** 33);
    try t.expectError(error.TooManyMarkers, config.validate());
    config = unitConfig();
    config.expect = "x" ** 513;
    try t.expectError(error.InvalidMarker, config.validate());
    const args = base_args ++ [_][]const u8{ "--require-marker", "first", "--require-marker", "second", "--forbid-marker", "third" };
    const parsed = try boot.config.parse(a, &args);
    defer a.free(parsed.required);
    defer a.free(parsed.forbidden);
    try t.expectEqualSlices([]const u8, &.{ "first", "second" }, parsed.required);
}

const Fixture = struct {
    arena: *std.heap.ArenaAllocator,
    root: core.private_files.Directory,
    directory: core.private_files.Directory,
    name: []const u8,
    path: []const u8,
    cli: []const u8,
    config: boot.config.Config,

    fn init(mode: u8, raw_disk: bool) !Fixture {
        try core.process.initialize();
        const arena = try a.create(std.heap.ArenaAllocator);
        arena.* = .init(a);
        errdefer {
            arena.deinit();
            a.destroy(arena);
        }
        const alloc = arena.allocator();
        const root_path = options.test_root orelse return error.MissingFixtureRoot;
        const root = try core.private_files.Directory.open(io, root_path);
        errdefer root.close(io);
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.allocPrint(alloc, "case-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        try root.dir.createDir(io, name, .fromMode(0o700));
        const path = try std.fs.path.join(alloc, &.{ root_path, name });
        const dir = try core.private_files.Directory.open(io, path);
        errdefer dir.close(io);
        var bytes = [_]u8{0x43} ** 2048;
        bytes[0] = mode;
        try dir.dir.writeFile(io, .{ .sub_path = "public,source.raw", .data = &bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.writeFile(io, .{ .sub_path = "code,template.fd", .data = "synthetic OVMF code", .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.writeFile(io, .{ .sub_path = "vars,template.fd", .data = &([_]u8{0xa5} ** 128), .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        try dir.dir.createDir(io, "work", .fromMode(0o700));
        const source = try std.fs.path.join(alloc, &.{ path, "public,source.raw" });
        return .{
            .arena = arena,
            .root = root,
            .directory = dir,
            .name = name,
            .path = path,
            .cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.cli, alloc),
            .config = .{
                .image = if (raw_disk) null else source,
                .raw_disk = if (raw_disk) source else null,
                .ovmf_code = try std.fs.path.join(alloc, &.{ path, "code,template.fd" }),
                .ovmf_vars = try std.fs.path.join(alloc, &.{ path, "vars,template.fd" }),
                .qemu = try std.Io.Dir.cwd().realPathFileAlloc(io, options.fixture, alloc),
                .work_dir = try std.fs.path.join(alloc, &.{ path, "work" }),
                .expect = "Hello world!",
                .timeout_ms = 3000,
            },
        };
    }

    fn deinit(self: Fixture) void {
        self.directory.close(io);
        self.root.dir.deleteTree(io, self.name) catch @panic("fixture cleanup failed");
        self.root.close(io);
        self.arena.deinit();
        a.destroy(self.arena);
    }

    fn run(self: Fixture) !boot.runner.Report {
        const report = try boot.runner.run(self.arena.allocator(), io, self.config, .{ .self_executable = self.cli });
        if (report.serial_bytes == 0) {
            std.debug.print("native local fixture before serial: {s}", .{try report.encode(self.arena.allocator())});
        }
        return report;
    }

    fn work(self: Fixture) !core.private_files.Directory {
        return core.private_files.Directory.open(io, self.config.work_dir);
    }

    fn storedReport(self: Fixture, work_dir: core.private_files.Directory) ![]const u8 {
        const alloc = self.arena.allocator();
        const bytes = try work_dir.read(io, alloc, "report.json", boot.config.max_record, null);
        const report = try boot.runner.Report.decode(alloc, bytes);
        return report.encode(alloc);
    }

    fn emitPhases(self: Fixture, work_dir: core.private_files.Directory) !void {
        const observation = try diagnostics.read(self.arena.allocator(), io, work_dir);
        var buffer: [diagnostics.max_log_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try std.json.Stringify.value(.{
            .schema_version = @as(u8, 1),
            .scope = "synthetic_observation_only",
            .authority = "none",
            .tail = observation.tail,
            .records = observation.slice(),
        }, .{}, &writer);
        std.debug.print("native local synthetic phases: {s}\n", .{writer.buffered()});
    }

    fn retainDiagnostics(self: Fixture) void {
        const work_dir = self.work() catch {
            std.debug.print("native local synthetic diagnostics: {{\"status\":\"workspace_unavailable\"}}\n", .{});
            return;
        };
        defer work_dir.close(io);
        self.emitPhases(work_dir) catch |err| {
            std.debug.print("native local synthetic phases: {{\"status\":\"{s}\"}}\n", .{
                if (err == error.FileNotFound) "absent" else "invalid_or_unavailable",
            });
        };
        if (self.storedReport(work_dir)) |encoded| {
            std.debug.print("native local stored report: {s}", .{encoded});
        } else |err| {
            std.debug.print("native local stored report: {{\"status\":\"{s}\"}}\n", .{
                if (err == error.FileNotFound) "absent" else "invalid_or_unavailable",
            });
        }
    }

    fn cliArgs(self: Fixture) ![]const []const u8 {
        return self.arena.allocator().dupe([]const u8, &.{
            self.cli,              if (self.config.raw_disk != null) "--raw-disk" else "--image", self.config.source(),
            "--ovmf-code",         self.config.ovmf_code,                                         "--ovmf-vars",
            self.config.ovmf_vars, "--qemu",                                                      self.config.qemu,
            "--work-dir",          self.config.work_dir,                                          "--expect",
            self.config.expect,    "--cpus",                                                      try std.fmt.allocPrint(self.arena.allocator(), "{d}", .{self.config.cpus}),
            "--timeout",           "3",
        });
    }
};

fn fixedFooter() [512]u8 {
    var bytes = [_]u8{0} ** 512;
    bytes[0..8].* = "conectix".*;
    std.mem.writeInt(u32, bytes[8..12], 2, .big);
    std.mem.writeInt(u32, bytes[12..16], 0x10000, .big);
    std.mem.writeInt(u64, bytes[16..24], std.math.maxInt(u64), .big);
    bytes[28..32].* = "miz ".*;
    std.mem.writeInt(u64, bytes[40..48], 1024 * 1024, .big);
    std.mem.writeInt(u64, bytes[48..56], 1024 * 1024, .big);
    bytes[56..60].* = .{ 0, 30, 4, 17 };
    std.mem.writeInt(u32, bytes[60..64], 2, .big);
    bytes[68] = 1;
    checksumFooter(&bytes);
    return bytes;
}
fn checksumFooter(bytes: *[512]u8) void {
    @memset(bytes[64..68], 0);
    var sum: u32 = 0;
    for (bytes) |byte| sum +%= byte;
    std.mem.writeInt(u32, bytes[64..68], ~sum, .big);
}
test "fixed VHD requires complete immutable-sized fixed footer checksum geometry and reserved fields" {
    const good = fixedFooter();
    try t.expectEqual(@as(u64, 1024 * 1024), try boot.vhd.footer(&good, 1024 * 1024 + 512));
    for ([_]usize{ 0, 8, 12, 16, 40, 48, 56, 58, 59, 60, 84, 90 }) |offset| {
        var bad = good;
        bad[offset] ^= 0xff;
        checksumFooter(&bad);
        try t.expectError(error.InvalidFixedVhd, boot.vhd.footer(&bad, 1024 * 1024 + 512));
    }
    var bad = good;
    bad[64] ^= 1;
    try t.expectError(error.InvalidFixedVhd, boot.vhd.footer(&bad, 1024 * 1024 + 512));
    try t.expectError(error.InvalidFixedVhd, boot.vhd.footer(&good, 1024 * 1024 + 511));
    try t.expectError(error.InvalidFixedVhd, boot.vhd.footer(&good, 1024 * 1024 + 513));
    bad = good;
    @memset(bad[68..84], 0);
    checksumFooter(&bad);
    try t.expectError(error.InvalidFixedVhd, boot.vhd.footer(&bad, 1024 * 1024 + 512));
}
test "fixed VHD legacy creators cannot expose a rounded CHS size" {
    const good = fixedFooter();
    for ([_][]const u8{ "miz ", "qem2", "test", "\x00\x00\x00\x00" }) |creator| {
        var current_size = good;
        @memcpy(current_size[28..32], creator);
        checksumFooter(&current_size);
        try t.expectEqual(@as(u64, 1024 * 1024), try boot.vhd.footer(&current_size, 1024 * 1024 + 512));
    }
    for ([_][]const u8{ "vpc ", "vs  ", "qemu" }) |creator| {
        var legacy = good;
        @memcpy(legacy[28..32], creator);
        checksumFooter(&legacy);
        const before = legacy;
        try t.expectError(error.InvalidFixedVhd, boot.vhd.footer(&legacy, 1024 * 1024 + 512));
        try t.expectEqualSlices(u8, &before, &legacy);
        // 17 MiB has exact standard CHS geometry: 512 cylinders, 4 heads, 17 sectors.
        std.mem.writeInt(u64, legacy[40..48], 17 * 1024 * 1024, .big);
        std.mem.writeInt(u64, legacy[48..56], 17 * 1024 * 1024, .big);
        legacy[56..60].* = .{ 2, 0, 4, 17 };
        checksumFooter(&legacy);
        try t.expectEqual(@as(u64, 17 * 1024 * 1024), try boot.vhd.footer(&legacy, 17 * 1024 * 1024 + 512));
    }
}
test "fixed VHD CLI exclusivity and genuine vpc wire without raw slicing" {
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const args = [_][]const u8{ "--fixed-vhd", "/synthetic/disk,one.vhd" } ++ base_args[2..].*;
    const config = try boot.config.parse(alloc, &args);
    try t.expect(config.image == null and config.raw_disk == null and config.fixed_vhd != null);
    const command_args = try boot.child.arguments(alloc, config, 1024 * 1024 + 512, 64);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, command_args[15], .{});
    defer parsed.deinit();
    const block = parsed.value.object;
    try t.expectEqualStrings("vpc", block.get("driver").?.string);
    try t.expect(block.get("read-only").?.bool);
    try t.expect(!block.contains("force-size") and !block.contains("force_size_calc") and !block.contains("force-size-calc"));
    try t.expect(!block.contains("offset") and !block.contains("size"));
    try t.expectEqualStrings("/proc/self/fd/64", block.get("file").?.object.get("filename").?.string);
    for ([_][]const u8{ "--image", "--raw-disk", "--fixed-vhd" }) |extra| {
        const duplicate = try std.mem.concat(alloc, []const u8, &.{ &args, &.{ extra, "/synthetic/other" } });
        if (boot.config.parse(alloc, duplicate)) |_| return error.AcceptedSourceConflict else |_| {}
    }
}
test "native QEMU fixture validates every argument CPU default and explicit SMP readonly raw source" {
    for ([_]u8{ 1, 2, 8 }) |cpus| {
        for ([_]bool{ false, true }) |raw_disk| {
            var f = try Fixture.init(0, raw_disk);
            defer f.deinit();
            errdefer f.retainDiagnostics();
            f.config.cpus = cpus;
            const original = try boot.files.Set.open(io, f.config);
            defer original.close(io);
            const report = try f.run();
            try t.expect(report.succeeded());
            try t.expectEqual(@as(u8, 0), report.termination.?.exited);
            try original.verify(io, f.config);
            const work = try f.work();
            defer work.close(io);
            const log = try work.read(io, a, boot.config.log_name, boot.config.max_serial, null);
            defer a.free(log);
            try t.expect(std.mem.indexOf(u8, log, "synthetic stderr retained\n") != null);
            try t.expect(std.mem.indexOf(u8, log, fixture_log) != null);
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(log, &hash, .{});
            try t.expectEqual(hash, report.serial_sha256.?);
            try t.expectEqual(log.len, report.serial_bytes);
            try t.expectError(error.FileNotFound, work.openFile(io, "OVMF_CODE.fd"));
            try t.expectError(error.FileNotFound, work.openFile(io, "OVMF_VARS.fd"));
            try t.expectError(error.FileNotFound, work.dir.openDir(io, "esp", .{}));
            const encoded = try work.read(io, a, "report.json", boot.config.max_record, null);
            defer a.free(encoded);
            try t.expect(std.mem.indexOf(u8, encoded, "\"acceptance\":\"not_established\"") != null);
            try t.expectError(error.WorkspaceConsumed, f.run());
        }
    }
}

test "native legacy APIC exactly one CPU" {
    var f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    f.config.disable_x2apic = true;
    try t.expect((try f.run()).succeeded());
}

test "success predicate requires real zero termination and complete nonlimited serial" {
    const f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    const good = try f.run();
    try t.expect(good.succeeded());
    var changed = good;
    changed.termination = .{ .exited = 10 };
    try t.expect(!changed.succeeded());
    changed = good;
    changed.termination = null;
    try t.expect(!changed.succeeded());
    changed = good;
    changed.serial_bytes = 0;
    try t.expect(!changed.succeeded());
    changed = good;
    changed.serial_sha256 = null;
    try t.expect(!changed.succeeded());
    changed = good;
    changed.serial_limit_reached = true;
    try t.expect(!changed.succeeded());
    changed = good;
    changed.serial_bytes = boot.config.max_serial;
    try t.expect(!changed.succeeded());
}

test "native child nonzero crash missing reordered and prefix-colliding return retain logs" {
    for ([_]u8{ 1, 2, 6, 10, 11, 12 }) |mode| {
        const f = try Fixture.init(mode, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const report = try f.run();
        try t.expect(!report.succeeded());
        try t.expect(report.failures.primary != null);
        try t.expect(report.cleanup_complete and report.input_unchanged);
        try t.expect(report.serial_bytes != 0);
        const work = try f.work();
        defer work.close(io);
        const log = try work.read(io, a, boot.config.log_name, boot.config.max_serial, null);
        defer a.free(log);
        try t.expect(std.mem.indexOf(u8, log, "synthetic stderr retained") != null);
        if (mode == 1) {
            try t.expectEqual(.child_failed, report.failures.primary.?.category);
            try t.expectEqual(@as(u8, 19), report.termination.?.exited);
            try t.expect(report.serial_valid);
        }
    }
}

test "native hard timeout and serial file limit retain bounded evidence" {
    for ([_]u8{ 3, 4 }) |mode| {
        var f = try Fixture.init(mode, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        f.config.timeout_ms = 1200;
        const start = try core.process.monotonicNanoseconds();
        const report = try f.run();
        const elapsed = (try core.process.monotonicNanoseconds()) - start;
        try t.expect(elapsed < 6 * std.time.ns_per_s);
        try t.expect(!report.succeeded() and report.cleanup_complete);
        try t.expect(report.serial_bytes > 0 and report.serial_bytes <= boot.config.max_serial);
        if (mode == 3) try t.expectEqual(.timeout, report.failures.primary.?.category) else {
            try t.expectEqual(@as(u64, boot.config.max_serial), report.serial_bytes);
            try t.expect(report.serial_limit_reached);
        }
        const work = try f.work();
        defer work.close(io);
        try t.expectError(error.FileNotFound, work.openFile(io, "OVMF_VARS.fd"));
        try t.expectError(error.WorkspaceConsumed, f.run());
    }
}

test "native successful leader cannot strand descendant" {
    const f = try Fixture.init(5, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    const report = try f.run();
    try t.expect(report.succeeded());
    const work = try f.work();
    defer work.close(io);
    const bytes = try work.read(io, a, "descendant.pid", 32, null);
    defer a.free(bytes);
    const pid = try std.fmt.parseInt(std.os.linux.pid_t, bytes, 10);
    try t.expectEqual(std.os.linux.E.SRCH, std.os.linux.errno(std.os.linux.syscall2(.kill, @intCast(pid), 0)));
}

fn cancelAfterInvocation(work: core.private_files.Directory, flag: *std.atomic.Value(bool)) void {
    var count: usize = 0;
    while (count < 500) : (count += 1) {
        const fd = std.os.linux.openat(work.dir.handle, "fixture-invoked", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (std.os.linux.errno(fd) == .SUCCESS) {
            _ = std.os.linux.close(@intCast(fd));
            flag.store(true, .release);
            return;
        }
        const duration: std.os.linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = std.os.linux.nanosleep(&duration, null);
    }
    flag.store(true, .release);
}
test "native cancellation interrupts blocking child and preserves its evidence" {
    var f = try Fixture.init(3, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    f.config.timeout_ms = 8000;
    const work = try f.work();
    defer work.close(io);
    var flag = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, cancelAfterInvocation, .{ work, &flag });
    defer thread.join();
    const report = try boot.runner.run(f.arena.allocator(), io, f.config, .{ .self_executable = f.cli, .cancel = &flag });
    try t.expectEqual(.cancelled, report.failures.primary.?.category);
    try t.expect(report.cleanup_complete and report.serial_bytes > 0);
}

test "native cleanup recording and primary failures remain independent" {
    for ([_]u8{ 7, 8, 14 }) |mode| {
        const f = try Fixture.init(mode, false);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const report = try f.run();
        try t.expect(!report.succeeded());
        if (mode == 7 or mode == 14) try t.expect(report.failures.cleanup != null);
        if (mode == 8 or mode == 14) try t.expect(report.failures.recording != null);
        if (mode == 14) try t.expectEqual(.child_failed, report.failures.primary.?.category);
        try t.expect(report.serial_bytes != 0 and report.input_unchanged);
    }
}

test "full raw input hash detects writes away from its first byte" {
    const f = try Fixture.init(9, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    const report = try f.run();
    try t.expect(!report.succeeded() and !report.input_unchanged);
    try t.expectEqual(.integrity, report.failures.primary.?.category);
    try t.expect(report.serial_valid);
}

test "artifact snapshots reject shrinking growing replacement empty and over-limit input" {
    for ([_]u8{ 0, 1, 2 }) |mode| {
        const f = try Fixture.init(0, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const original = try boot.files.Set.open(io, f.config);
        defer original.close(io);
        if (mode == 2) {
            try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.renameat(f.directory.dir.handle, "public,source.raw", f.directory.dir.handle, "old.raw")));
            var bytes = [_]u8{0x43} ** 2048;
            bytes[0] = 0;
            try f.directory.dir.writeFile(io, .{ .sub_path = "public,source.raw", .data = &bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o644) } });
        } else {
            const file = try f.directory.dir.openFile(io, "public,source.raw", .{ .mode = .read_write });
            defer file.close(io);
            try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.ftruncate(file.handle, if (mode == 0) 2047 else 2049)));
        }
        try t.expectError(error.ArtifactChanged, original.verify(io, f.config));
    }
    for ([_]i64{ 0, boot.config.max_input + 1 }) |size| {
        const f = try Fixture.init(0, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const file = try f.directory.dir.openFile(io, "public,source.raw", .{ .mode = .read_write });
        defer file.close(io);
        try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.ftruncate(file.handle, size)));
        try t.expectError(error.InvalidArtifact, f.run());
        const work = try f.work();
        defer work.close(io);
        try t.expectError(error.FileNotFound, work.openFile(io, "request.json"));
    }
}

test "typed child records reject unknown duplicate incomplete malformed and rebound inputs" {
    for ([_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 }) |mode| {
        const f = try Fixture.init(0, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const alloc = f.arena.allocator();
        const work = try f.work();
        defer work.close(io);
        var lock = try work.lock(io);
        defer lock.close(io);
        const originals = try boot.files.Set.open(io, f.config);
        defer originals.close(io);
        var request: boot.runner.Request = .{ .supervisor_pid = @intCast(std.os.linux.getpid()), .config = f.config, .pins = originals.pins() };
        if (mode == 4) request.supervisor_pid = 1;
        if (mode == 5) request.pins[0].sha256[31] ^= 1;
        if (mode == 6) request.config.cpus = 9;
        const encoded = try boot.config.encode(alloc, request);
        const record = switch (mode) {
            0 => try std.mem.replaceOwned(u8, alloc, encoded, "\"schema_version\":1", "\"schema_version\":1,\"argv\":[]"),
            1 => try std.mem.replaceOwned(u8, alloc, encoded, "\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1"),
            2 => try std.mem.replaceOwned(u8, alloc, encoded, "\"cpus\":1,", ""),
            3 => encoded[0 .. encoded.len - 3],
            7 => try std.mem.replaceOwned(u8, alloc, encoded, "\"timeout_ms\":3000", "\"timeout_ms\":3000.0"),
            else => encoded,
        };
        try boot.files.durable(try lock.createImmutable(io, "request.json", record));
        var env: std.process.Environ.Map = .init(alloc);
        defer env.deinit();
        var result = try core.process.run(alloc, io, .{
            .argv = &.{ f.cli, "--exec" },
            .environment = &env,
            .cwd = work.dir,
            .deadline = try core.process.Deadline.afterMilliseconds(3000),
            .stdout_limit = 1024,
            .stderr_limit = 1024,
        });
        defer result.deinit(alloc);
        try t.expect(result.failures.primary != null and result.cleanup_complete);
        try t.expectError(error.FileNotFound, work.openFile(io, "fixture-invoked"));
        if (mode != 5) try t.expectError(error.FileNotFound, work.openFile(io, "launched"));
    }
}

test "pre-cancelled request consumes once without executing QEMU" {
    const f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    var cancelled = std.atomic.Value(bool).init(true);
    const report = try boot.runner.run(f.arena.allocator(), io, f.config, .{ .self_executable = f.cli, .cancel = &cancelled });
    try t.expect(report.consumed and !report.succeeded());
    try t.expectEqual(.cancelled, report.failures.primary.?.category);
    const work = try f.work();
    defer work.close(io);
    try t.expectError(error.FileNotFound, work.openFile(io, "launched"));
    try t.expectError(error.WorkspaceConsumed, f.run());
}

test "private workspace lock and artifact policy reject unsafe files before execution" {
    const f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    const work = try f.work();
    defer work.close(io);
    var lock = try work.lock(io);
    try t.expectError(error.WouldBlock, f.run());
    lock.close(io);
    try work.dir.setPermissions(io, .fromMode(0o755));
    try t.expectError(error.UnsafeFile, f.run());
    try work.dir.setPermissions(io, .fromMode(0o700));
    try f.directory.dir.symLink(io, "public,source.raw", "linked.raw", .{});
    var config = f.config;
    config.raw_disk = try std.fs.path.join(f.arena.allocator(), &.{ f.path, "linked.raw" });
    try t.expectError(error.UnsafeFile, boot.runner.run(f.arena.allocator(), io, config, .{ .self_executable = f.cli }));
    try f.directory.dir.writeFile(io, .{ .sub_path = "script", .data = "#!/bin/sh\nexit 0\n", .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    config = f.config;
    config.qemu = try std.fs.path.join(f.arena.allocator(), &.{ f.path, "script" });
    try t.expectError(error.InvalidExecutable, boot.runner.run(f.arena.allocator(), io, config, .{ .self_executable = f.cli }));
    try t.expectEqual(.SUCCESS, std.os.linux.errno(std.os.linux.mknodat(f.directory.dir.handle, "fifo", std.os.linux.S.IFIFO | 0o600, 0)));
    config = f.config;
    config.raw_disk = try std.fs.path.join(f.arena.allocator(), &.{ f.path, "fifo" });
    try t.expectError(error.UnsafeFile, boot.runner.run(f.arena.allocator(), io, config, .{ .self_executable = f.cli }));
    config.raw_disk = f.path;
    try t.expectError(error.UnsafeFile, boot.runner.run(f.arena.allocator(), io, config, .{ .self_executable = f.cli }));
    config.raw_disk = try std.fs.path.join(f.arena.allocator(), &.{ f.config.work_dir, "source" });
    try t.expectError(error.InputInsideWorkspace, boot.runner.run(f.arena.allocator(), io, config, .{ .self_executable = f.cli }));
    try t.expectError(error.FileNotFound, work.openFile(io, "launched"));
}

test "actual CLI serializes public-only success and failure without paths or logs" {
    for ([_]u8{ 0, 1 }) |mode| {
        var f = try Fixture.init(mode, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        f.config.cpus = 2;
        var env: std.process.Environ.Map = .init(a);
        defer env.deinit();
        try env.put("SYNTHETIC_UNINHERITED", "SYNTHETIC_SECRET");
        const result = try std.process.run(a, io, .{
            .argv = try f.cliArgs(),
            .cwd = .{ .dir = f.directory.dir },
            .environ_map = &env,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try t.expect(result.term == .exited);
        try t.expectEqual(@as(u8, if (mode == 0) 0 else 1), result.term.exited);
        try t.expectEqual(@as(usize, 0), result.stderr.len);
        for ([_][]const u8{ f.path, "SYNTHETIC_SECRET", "Hello world!", "synthetic stderr" }) |forbidden|
            try t.expect(std.mem.indexOf(u8, result.stdout, forbidden) == null);
        var doc = try core.contracts.Document.parse(a, result.stdout, .{});
        defer doc.deinit();
        try doc.requireCanonical(a, result.stdout);
        try t.expectEqual(mode == 0, doc.value().object.get("passed").?.bool);
        try t.expectEqualStrings("public_local_qemu_only", doc.value().object.get("scope").?.string);
        try t.expectEqualStrings("not_established", doc.value().object.get("acceptance").?.string);
    }
}

test "actual CLI expected nonzero guest return and repeated marker flags reach validator" {
    for ([_]bool{ false, true }) |forbidden| {
        const f = try Fixture.init(11, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const args = try std.mem.concat(f.arena.allocator(), []const u8, &.{
            try f.cliArgs(),
            &.{ "--expect-main-return", "10", "--require-marker", "at GPA", "--require-marker", "synthetic IRQs" },
            if (forbidden) &.{ "--forbid-marker", "synthetic stderr" } else &.{},
        });
        var env: std.process.Environ.Map = .init(a);
        defer env.deinit();
        const result = try std.process.run(a, io, .{
            .argv = args,
            .cwd = .{ .dir = f.directory.dir },
            .environ_map = &env,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try t.expect(result.term == .exited);
        try t.expectEqual(@as(u8, if (forbidden) 1 else 0), result.term.exited);
        if (forbidden) {
            const work = try f.work();
            defer work.close(io);
            const log = try work.read(io, a, boot.config.log_name, boot.config.max_serial, null);
            defer a.free(log);
            try t.expect(std.mem.indexOf(u8, log, "synthetic stderr") != null);
        }
    }
}

test "actual CLI refuses missing source invalid flags and standalone worker" {
    const f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    for ([_][]const []const u8{ &.{}, &.{"--fixture-mode"}, &.{ "--qemu", "SYNTHETIC_SECRET" }, &.{"--exec"} }) |extra| {
        const args = try std.mem.concat(a, []const u8, &.{ &.{f.cli}, extra });
        defer a.free(args);
        var env: std.process.Environ.Map = .init(a);
        defer env.deinit();
        const result = try std.process.run(a, io, .{
            .argv = args,
            .cwd = .{ .dir = f.directory.dir },
            .environ_map = &env,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try t.expect(result.term == .exited and result.term.exited != 0);
        try t.expect(std.mem.indexOf(u8, result.stdout, f.path) == null);
        try t.expect(std.mem.indexOf(u8, result.stdout, "SYNTHETIC_SECRET") == null);
    }
}

test "actual CLI rejects invalid CPU conflicting sources and legacy SMP before workspace admission" {
    for ([_]u8{ 0, 9, 2 }) |cpus| {
        var f = try Fixture.init(0, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        f.config.cpus = cpus;
        const argv = try f.cliArgs();
        const args = if (cpus == 2) try std.mem.concat(f.arena.allocator(), []const u8, &.{ argv, &.{"--disable-x2apic"} }) else argv;
        var env: std.process.Environ.Map = .init(a);
        defer env.deinit();
        const result = try std.process.run(a, io, .{
            .argv = args,
            .cwd = .{ .dir = f.directory.dir },
            .environ_map = &env,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        });
        defer a.free(result.stdout);
        defer a.free(result.stderr);
        try t.expectEqual(@as(u8, 2), result.term.exited);
        const work = try f.work();
        defer work.close(io);
        try t.expectError(error.FileNotFound, work.openFile(io, "request.json"));
    }
    const f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    const argv = try f.cliArgs();
    const args = try std.mem.concat(f.arena.allocator(), []const u8, &.{ argv, &.{ "--image", f.config.source() } });
    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    const result = try std.process.run(a, io, .{ .argv = args, .cwd = .{ .dir = f.directory.dir }, .environ_map = &env, .stdout_limit = .limited(4096), .stderr_limit = .limited(4096) });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try t.expectEqual(@as(u8, 2), result.term.exited);
    const work = try f.work();
    defer work.close(io);
    try t.expectError(error.FileNotFound, work.openFile(io, "request.json"));
}

test "synthetic phase codec bounds partial writes malformed records and authority" {
    var bytes: [diagnostics.max_bytes]u8 = undefined;
    inline for (@typeInfo(diagnostics.Phase).@"enum".fields, 0..) |field, index| {
        const record = try diagnostics.Record.observe(@enumFromInt(field.value), std.math.maxInt(u64));
        @memcpy(bytes[index * diagnostics.slot_size ..][0..diagnostics.slot_size], &try record.encode());
    }
    const complete = try diagnostics.decode(a, &bytes);
    try t.expectEqual(diagnostics.slot_count, complete.count);
    try t.expectEqual(.aligned_prefix, complete.tail);
    const partial = try diagnostics.decode(a, bytes[0 .. 2 * diagnostics.slot_size + 17]);
    try t.expectEqual(@as(usize, 2), partial.count);
    try t.expectEqual(.partial_slot, partial.tail);
    try t.expectEqual(@as(usize, 0), (try diagnostics.decode(a, &.{})).count);
    try t.expectError(error.DiagnosticTooLarge, diagnostics.decode(a, &([_]u8{0} ** (diagnostics.max_bytes + 1))));
    bytes[2 * diagnostics.slot_size] = '!';
    const malformed = try diagnostics.decode(a, &bytes);
    try t.expectEqual(@as(usize, 2), malformed.count);
    try t.expectEqual(.invalid_slot, malformed.tail);
    const json = std.mem.trimEnd(u8, bytes[0..diagnostics.slot_size], "\x00");
    if (boot.runner.Report.decode(a, json)) |_| return error.DiagnosticGrantedAuthority else |_| {}
    const injected = try std.mem.replaceOwned(u8, a, json, "\"none\"", "\"SYNTHETIC_SECRET\"");
    defer a.free(injected);
    var invalid = [_]u8{0} ** diagnostics.slot_size;
    @memcpy(invalid[0..injected.len], injected);
    const rejected = try diagnostics.decode(a, &invalid);
    try t.expectEqual(@as(usize, 0), rejected.count);
    try t.expectEqual(.invalid_slot, rejected.tail);
    const encoded = try std.json.Stringify.valueAlloc(a, rejected.slice(), .{});
    defer a.free(encoded);
    try t.expect(std.mem.indexOf(u8, encoded, "SYNTHETIC_SECRET") == null);
}

test "synthetic native phase times sizes serial separation and teardown" {
    const name = block: {
        const f = try Fixture.init(0, true);
        defer f.deinit();
        errdefer f.retainDiagnostics();
        const report = try f.run();
        try t.expect(report.succeeded());
        const work = try f.work();
        defer work.close(io);
        const metadata = try work.openFile(io, diagnostics.file_name);
        defer metadata.close(io);
        try t.expectEqual(@as(u64, diagnostics.max_bytes), (try core.private_files.snapshot(metadata)).size);
        const observed = try diagnostics.read(a, io, work);
        try t.expectEqual(diagnostics.slot_count, observed.count);
        try t.expectEqual(.aligned_prefix, observed.tail);
        const executable = try core.private_files.openAbsolute(io, f.config.qemu, .artifact);
        defer executable.close(io);
        const size = (try core.private_files.snapshot(executable)).size;
        const expected = try diagnostics.Record.observe(.mock_entry, size);
        for (observed.slice()) |record| {
            try t.expectEqual(size, record.fixture_bytes);
            try t.expectEqual(expected.backend, record.backend);
            try t.expectEqual(expected.arch, record.arch);
            try t.expectEqual(expected.optimize, record.optimize);
            try t.expectEqual(expected.aarch64_sha2, record.aarch64_sha2);
            try t.expectEqual(expected.x86_sha, record.x86_sha);
            try t.expectEqual(expected.x86_avx2, record.x86_avx2);
            try t.expect(record.monotonic_ns > 0 and record.process_cpu_ns > 0);
            try t.expectEqual(.none, record.authority);
        }
        try t.expectError(error.DiagnosticPhaseOrder, diagnostics.mockEntry(io, work));
        const serial = try work.read(io, a, boot.config.log_name, boot.config.max_serial, null);
        defer a.free(serial);
        try t.expect(std.mem.indexOf(u8, serial, "synthetic_observation_only") == null);
        try t.expect(std.mem.indexOf(u8, serial, "monotonic_ns") == null);
        const saved = try f.storedReport(work);
        try t.expectEqualStrings(try report.encode(f.arena.allocator()), saved);
        try t.expect(std.mem.indexOf(u8, saved, "monotonic_ns") == null);
        break :block try a.dupe(u8, f.name);
    };
    defer a.free(name);
    const root = try core.private_files.Directory.open(io, options.test_root.?);
    defer root.close(io);
    try t.expectError(error.FileNotFound, root.dir.openDir(io, name, .{}));
}

test "synthetic writers refuse reuse phase overflow and oversized metadata never admits work" {
    const f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    const work = try f.work();
    defer work.close(io);
    var trace = try diagnostics.Trace.create(io, work, 1234);
    defer trace.close(io);
    try t.expectError(error.PathAlreadyExists, diagnostics.Trace.create(io, work, 1234));
    try t.expectError(error.DiagnosticPhaseOrder, trace.mark(io, .artifact_hash_end));
    inline for (@typeInfo(diagnostics.Phase).@"enum".fields[0 .. diagnostics.slot_count - 1]) |field|
        try trace.mark(io, @enumFromInt(field.value));
    try t.expectError(error.DiagnosticPhaseOrder, trace.mark(io, .exec_handoff));
    try trace.file.writePositionalAll(io, "!", diagnostics.max_bytes);
    try t.expectError(error.FileTooLarge, diagnostics.read(a, io, work));
    try t.expectError(error.WorkspaceConsumed, f.run());
    try t.expectError(error.FileNotFound, work.openFile(io, "request.json"));
    try t.expectError(error.FileNotFound, work.openFile(io, "launched"));
    try work.dir.writeFile(io, .{
        .sub_path = "report.json",
        .data = "SYNTHETIC_SECRET is not a stored report",
        .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
    });
    if (f.storedReport(work)) |_| return error.AcceptedInvalidStoredReport else |_| {}
    f.retainDiagnostics();
}

test "synthetic CLI failure retention reads stored JSON without consulting failed streams" {
    const f = try Fixture.init(1, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    var environment: std.process.Environ.Map = .init(a);
    defer environment.deinit();
    const result = try std.process.run(a, io, .{
        .argv = try f.cliArgs(),
        .cwd = .{ .dir = f.directory.dir },
        .environ_map = &environment,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    defer a.free(result.stdout);
    defer a.free(result.stderr);
    try t.expect(result.term == .exited);
    try t.expectEqual(@as(u8, 1), result.term.exited);
    const work = try f.work();
    defer work.close(io);
    const report = try boot.runner.Report.decode(a, try f.storedReport(work));
    try t.expect(!report.succeeded() and report.cleanup_complete and report.serial_valid);
    try t.expectEqual(.child_failed, report.failures.primary.?.category);
    try t.expectEqual(@as(u8, 19), report.termination.?.exited);
    try t.expectEqual(diagnostics.slot_count, (try diagnostics.read(a, io, work)).count);
    f.retainDiagnostics();
}

test "installed production CLI and plain native fixture have no diagnostic seam" {
    var f = try Fixture.init(0, true);
    defer f.deinit();
    errdefer f.retainDiagnostics();
    f.cli = try std.Io.Dir.cwd().realPathFileAlloc(io, options.production_cli, f.arena.allocator());
    f.config.qemu = try std.Io.Dir.cwd().realPathFileAlloc(io, options.plain_fixture, f.arena.allocator());
    try t.expect((try f.run()).succeeded());
    const work = try f.work();
    defer work.close(io);
    try t.expectError(error.FileNotFound, work.openFile(io, diagnostics.file_name));
}
