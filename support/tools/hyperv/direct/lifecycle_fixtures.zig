// SPDX-License-Identifier: BSD-3-Clause
//! Native offline lifecycle runner. `reference` is a frozen development-only
//! Bash comparison scaffold, not a native controller fallback or CI closure.
//!
//! CLI: --backend reference|native --controller ABSOLUTE --root FRESH_PRIVATE
//!      --fake ABSOLUTE --validator ABSOLUTE [--case NAME,NAME] [--compare ROOT]
//! `--inventory` emits each frozen case's actual assertion functions.
//! Both executables use the direct build's existing hyperv_core/preparation/
//! evidence imports. The native controller retains its ordinary six arguments.
//! Its test-only hash adapter can import lifecycle_fixture_seams.zig; the three
//! hash-fault cases intentionally fail without that adapter, never silently skip.
const std = @import("std");
const f = @import("lifecycle_fixture_support.zig");
const inventory = @import("lifecycle_fixture_cases.zig");
const validation = @import("main.zig");
const eq = f.eq;
const one = f.oneOf;
const starts = f.starts;
const expect = f.expect;
const Case = inventory.Case;
const Backend = enum { reference, native };
const Config = struct {
    backend: Backend,
    controller: []const u8,
    root: []const u8,
    fake: []const u8,
    validator: []const u8,
    selected: ?[]const u8 = null,
    compare: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) void {
    f.privateUmask();
    run(init) catch |err| {
        var out = std.Io.File.stderr().writerStreaming(init.io, &.{});
        out.interface.print("native lifecycle fixtures failed: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}
fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = (try init.minimal.args.toSlice(a))[1..];
    var out = std.Io.File.stdout().writerStreaming(init.io, &.{});
    if (args.len == 1 and eq(args[0], "--inventory")) {
        for (inventory.all_cases) |case| try out.interface.print("{s}\t{s}\n", .{ case.name, inventory.assertionNames(case.assertions) });
        return;
    }
    try @import("lifecycle_fixture_seams.zig").selfCheck();
    var options: std.StringHashMap([]const u8) = .init(a);
    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        try expect(i + 1 < args.len and one(args[i], &.{ "--backend", "--controller", "--root", "--fake", "--validator", "--case", "--compare" }) and !options.contains(args[i]));
        try options.put(args[i], args[i + 1]);
    }
    const cfg: Config = .{
        .backend = std.meta.stringToEnum(Backend, options.get("--backend") orelse return error.BackendRequired) orelse return error.InvalidBackend,
        .controller = options.get("--controller") orelse return error.ControllerRequired,
        .root = options.get("--root") orelse return error.FreshRootRequired,
        .fake = options.get("--fake") orelse return error.FakeRequired,
        .validator = options.get("--validator") orelse return error.ValidatorRequired,
        .selected = options.get("--case"),
        .compare = options.get("--compare"),
    };
    if (cfg.selected) |selected| {
        var selected_names = std.mem.splitScalar(u8, selected, ',');
        var seen: std.StringHashMap(void) = .init(a);
        while (selected_names.next()) |name| {
            try expect(!seen.contains(name));
            var known = false;
            for (inventory.all_cases) |case| if (eq(case.name, name)) {
                known = true;
            };
            try expect(known);
            try seen.put(name, {});
        }
    }
    inline for (.{ cfg.controller, cfg.root, cfg.fake, cfg.validator }) |path| try f.files.absoluteFilePath(path);
    try expect(std.mem.indexOf(u8, cfg.root, "/.d/") != null);
    try checkExecutable(init.io, cfg.fake, true);
    try checkExecutable(init.io, cfg.validator, true);
    try expect(eq(std.fs.path.basename(cfg.validator), "uk-hyperv-direct-validate"));
    try checkExecutable(init.io, cfg.controller, cfg.backend == .native);
    if (cfg.backend == .reference) {
        const file = try f.files.openAbsolute(init.io, cfg.controller, .artifact);
        defer file.close(init.io);
        const size = (try file.stat(init.io)).size;
        try expect(size < 65536);
        const bytes = try a.alloc(u8, @intCast(size));
        try expect(try file.readPositionalAll(init.io, bytes, 0) == bytes.len);
        try expect(eq(&f.hash(bytes), "ef2d06e605a2463fcbec3642792b52a247a133c263e93a2ca1247a09aad2d350"));
        try out.interface.writeAll("REFERENCE ONLY: native fixtures, frozen Bash controller; no native-production closure claim.\n");
    }
    const parent = try f.files.Directory.open(init.io, std.fs.path.dirname(cfg.root).?);
    defer parent.close(init.io);
    try parent.dir.createDir(init.io, std.fs.path.basename(cfg.root), .fromMode(0o700));
    const base: f.Context = .{ .a = a, .io = init.io, .root = cfg.root };
    try base.write("ISOLATED_OFFLINE_FIXTURE", f.marker);
    try template(base);
    try base.writeJson("runner.json", .{ .backend = cfg.backend, .controller = cfg.controller, .legacy_case_count = inventory.cases.len, .process_case_count = inventory.process_cases.len });
    var count: usize = 0;
    var failed: usize = 0;
    for (inventory.all_cases) |case| {
        if (cfg.selected) |selected| if (!selectedCase(selected, case.name)) continue;
        var arena: std.heap.ArenaAllocator = .init(a);
        defer arena.deinit();
        const c: f.Context = .{ .a = arena.allocator(), .io = init.io, .root = try base.path(case.name) };
        try base.mkdir(case.name);
        runCase(c, cfg, case) catch |err| {
            failed += 1;
            try out.interface.print("FAIL {s}: {s}\n", .{ case.name, @errorName(err) });
            try c.writeJson("assertion-failure.json", .{ .case = case.name, .assertions = case.assertions, .err = @errorName(err) });
        };
        count += 1;
        if (!try c.exists("assertion-failure.json")) try out.interface.print("PASS {s}\n", .{case.name});
    }
    try expect(count > 0);
    try base.writeJson("fixture-summary.json", .{ .backend = cfg.backend, .cases = count, .failed = failed });
    try out.interface.print("{d}/{d} native fixture cases passed ({s}; no cloud/network/disks).\n", .{ count - failed, count, @tagName(cfg.backend) });
    if (failed != 0) return error.LifecycleParityFailed;
}

fn checkExecutable(io: std.Io, path: []const u8, elf: bool) !void {
    const file = try f.files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const stat = try f.files.snapshot(file);
    try expect(stat.mode & 0o111 != 0);
    if (elf) {
        var magic: [4]u8 = undefined;
        try expect(try file.readPositionalAll(io, &magic, 0) == 4 and eq(&magic, "\x7fELF"));
    }
}
fn selectedCase(selected: []const u8, name: []const u8) bool {
    var names = std.mem.splitScalar(u8, selected, ',');
    while (names.next()) |candidate| if (eq(candidate, name)) return true;
    return false;
}
fn artifact(c: f.Context, name: []const u8, size: u64) !validation.Artifact {
    return .{ .path = try c.path(name), .size = size, .sha256 = f.image_sha };
}
fn setup(c: f.Context, cfg: Config, name: []const u8) !void {
    try c.mkdir("ledger");
    try c.write("ISOLATED_OFFLINE_FIXTURE", f.marker);
    try c.write("scenario", try std.mem.concat(c.a, u8, &.{ name, "\n" }));
    try c.write("fake-cloud.json", "{\"exists\":false,\"boots\":0,\"power\":\"deallocated\"}\n");
    try c.write("calls", "");
    var scope: validation.Scope = .{
        .schema = "uk.hyperv.direct-two-boot",
        .version = 1,
        .approval = .{
            .destructive_data_disk = !eq(name, "unapproved"),
            .direct_specialized_gen2 = true,
            .two_boots_only = true,
            .cleanup_owned_group = true,
            .original_seed_reviewed = true,
            .guarded_native_image_reviewed = true,
            .expires_unix = if (eq(name, "expired")) 1 else @intCast(f.now(c.io) + 3600),
        },
        .attempt_id = f.owner,
        .subscription = f.subscription,
        .location = "fixture",
        .prefix = f.prefix,
        .vm_size = "Standard_D2s_v5",
        .run_id = "1" ** 32,
        .disk_id = "2" ** 32,
        .controller = .SCSI,
        .lun = 7,
        .sectors = if (eq(name, "wrong-geometry")) 4096 else 8388608,
        .sector_size = 512,
        .serial_mode = .per_boot,
        .runtime_seconds = 60,
        .cleanup_seconds = if (eq(name, "diagnostics-timeout")) 180 else 60,
        .operation_seconds = if (one(name, &.{ "diagnostics-timeout", "diagnostics-no-budget" })) 40 else 10,
        .poll_seconds = 1,
        .os_vhd = try artifact(c, "os.vhd", 1049088),
        .seed_raw = try artifact(c, "seed.raw", 4294967296),
        .seed_vhd = try artifact(c, "seed.vhd", 4294967808),
        .manifest = try artifact(c, "seed.json", 1),
        .config = try artifact(c, "config", 1),
    };
    var first: []const u8 = f.serialLog(1);
    var second: []const u8 = f.serialLog(2);
    if (eq(name, "boot1-missing-platform")) first = try std.mem.replaceOwned(u8, c.a, first, "UK_HYPERV_PLATFORM_READY\n", "");
    if (eq(name, "boot2-missing-platform")) second = try std.mem.replaceOwned(u8, c.a, second, "UK_HYPERV_PLATFORM_READY\n", "");
    if (one(name, &.{ "cumulative-serial", "cumulative-cached-then-fresh", "cumulative-prefix-drift", "cumulative-different-boot1" })) {
        scope.serial_mode = .cumulative;
        if (!eq(name, "cumulative-different-boot1")) second = try std.mem.concat(c.a, u8, &.{ first, second });
    }
    if (starts(name, "azure-") or one(name, &.{ "per-boot-azure-log", "cumulative-azure-log" })) {
        scope.serial_mode = if (eq(name, "per-boot-azure-log")) .per_boot else if (eq(name, "cumulative-azure-log")) .cumulative else .azure_cumulative;
        if (one(name, &.{ "azure-interior-nul", "azure-interior-nul-removed" })) first = try std.mem.concat(c.a, u8, &.{ "provider\x00banner \t\x1b[0m\n", first });
        try c.write("boot1-body.log", first);
        const body = first;
        first = try std.mem.concat(c.a, u8, &.{ first, "\x00" ** 464 });
        const changes = .{
            .{ "azure-wrong-identity", "4" ** 32, "5" ** 32 },
            .{ "azure-writes", ":0:0:receipt-verified", ":1:0:receipt-verified" },
            .{ "azure-flushes", ":0:0:receipt-verified", ":0:1:receipt-verified" },
            .{ "azure-failure", "FINAL PASS rc=0", "FINAL FAIL rc=1" },
            .{ "azure-missing-platform", "UK_HYPERV_PLATFORM_READY\n", "" },
        };
        inline for (changes) |change| if (eq(name, change[0])) {
            second = try std.mem.replaceOwned(u8, c.a, second, change[1], change[2]);
        };
        try c.write("boot2-body.log", second);
        second = try std.mem.concat(c.a, u8, &.{ if (eq(name, "azure-full-prefix")) first else body, second, "\x00\x00" });
    }
    try c.write("boot1.log", first);
    try c.write("boot2.log", second);
    try c.writeJson("scope.json", scope);
    if (one(name, &.{ "cache-hash-error", "cache-binding-hash-error", "cache-admission-hash-error" }) and cfg.backend == .reference) {
        try c.mkdir("hash-tools");
        const source = try f.files.openAbsolute(c.io, cfg.fake, .artifact);
        defer source.close(c.io);
        const size = (try source.stat(c.io)).size;
        try expect(size <= 64 * 1024 * 1024);
        const bytes = try c.a.alloc(u8, @intCast(size));
        try expect(try source.readPositionalAll(c.io, bytes, 0) == size);
        const target = try c.create("hash-tools/sha256sum");
        defer target.close(c.io);
        try target.writeStreamingAll(c.io, bytes);
        try target.setPermissions(c.io, .fromMode(0o700));
        try target.sync(c.io);
    }
}
fn execute(c: f.Context, cfg: Config, attempt: []const u8, label: []const u8) !u8 {
    var environment = std.process.Environ.Map.init(c.a);
    try environment.put("UK_DIRECT_FIXTURE_ROOT", c.root);
    try environment.put("UK_DIRECT_FIXTURE_VALIDATOR", cfg.validator);
    try environment.put("LC_ALL", "C");
    // Only the explicitly selected frozen reference has shell/coreutils on PATH.
    // Native controller test executables must use explicit executable paths.
    try environment.put("PATH", if (cfg.backend == .reference)
        (if (try c.exists("hash-tools")) try std.mem.concat(c.a, u8, &.{ try c.path("hash-tools"), ":/usr/bin:/bin" }) else "/usr/bin:/bin")
    else
        "");
    const stdout = try c.create(try std.mem.concat(c.a, u8, &.{ label, ".stdout" }));
    defer stdout.close(c.io);
    const stderr = try c.create(try std.mem.concat(c.a, u8, &.{ label, ".stderr" }));
    defer stderr.close(c.io);
    const argv: []const []const u8 = &.{ cfg.controller, try c.path("scope.json"), try c.path(attempt), try c.path("ledger"), cfg.fake, cfg.fake, cfg.fake };
    for (argv) |arg| try expect(std.mem.indexOf(u8, arg, f.sentinel) == null);
    var child = try std.process.spawn(c.io, .{
        .argv = argv,
        .environ_map = &environment,
        .stdin = .ignore,
        .stdout = .{ .file = stdout },
        .stderr = .{ .file = stderr },
    });
    if (eq(std.mem.trimEnd(u8, try c.read("scenario"), "\n"), "process-signal-term")) {
        var ready = false;
        for (0..100) |_| {
            if (try c.exists("process.pid")) {
                ready = true;
                break;
            }
            try std.Io.sleep(c.io, .fromMilliseconds(100), .awake);
        }
        if (!ready) {
            child.kill(c.io);
            return error.SignalFixtureNotReady;
        }
        try expect(std.os.linux.errno(std.os.linux.kill(child.id.?, .TERM)) == .SUCCESS);
    }
    const status = switch (try child.wait(c.io)) {
        .exited => |code| code,
        .signal => |signal| @as(u8, @intCast(128 + @intFromEnum(signal))),
        else => return error.ControllerTermination,
    };
    try stdout.sync(c.io);
    try stderr.sync(c.io);
    try c.writeJson(try std.mem.concat(c.a, u8, &.{ label, ".exit.json" }), .{ .status = status });
    return status;
}
fn runCase(c: f.Context, cfg: Config, case: Case) !void {
    try setup(c, cfg, case.name);
    const result = try execute(c, cfg, "attempt", "public");
    if (case.assertions == .inadmissible_no_claim) {
        try expect(result != 0 and (try c.read("calls")).len == 0);
        try expect(!try c.exists("ledger/attempt-" ++ f.owner));
        try privacy(c, "attempt");
        inline for (.{ "public.stdout", "public.stderr" }) |path| try expect(std.mem.indexOf(u8, try c.read(path), f.sentinel) == null);
        if (cfg.compare) |other| {
            const reference: f.Context = .{ .a = c.a, .io = c.io, .root = try std.fs.path.join(c.a, &.{ other, case.name }) };
            try reference.validate();
            try expect(try f.num(try reference.document("public.exit.json"), "status") == result);
            try expect((try reference.read("calls")).len == 0 and !try reference.exists("ledger/attempt-" ++ f.owner));
            try compareScopes(c, reference);
        }
        return;
    }
    const outcome = try c.document("attempt/outcome.json");
    try common(c, case, result, outcome);
    if (case.assertions == .accepted_custody) {
        try accepted(c, case.name, outcome);
        if (eq(case.name, "success")) {
            const second = try execute(c, cfg, "second-attempt", "second");
            const refusal = try c.document("second-attempt/outcome.json");
            try expect(second != 0 and !try f.yes(refusal, "accepted") and try f.num(refusal, "reserved_boots") == 0);
        }
        const calls_before = try c.read("calls");
        const retry = try execute(c, cfg, "attempt", "retry");
        try expect(retry != 0 and eq(calls_before, try c.read("calls")));
        try privacy(c, "second-attempt");
        inline for (.{ "second.stdout", "second.stderr", "retry.stdout", "retry.stderr" }) |path|
            if (try c.exists(path)) try expect(std.mem.indexOf(u8, try c.read(path), f.sentinel) == null);
    } else {
        try refused(c, case.name, result, outcome);
        if (case.assertions == .refused_serial_custody) try serialRefusal(c, case.name, result, outcome);
        try refusedCustody(c, case.name);
    }
    if (cfg.compare) |other| try compare(c, .{ .a = c.a, .io = c.io, .root = try std.fs.path.join(c.a, &.{ other, case.name }) });
}

fn linesWith(bytes: []const u8, prefix: []const u8) usize {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var count: usize = 0;
    while (lines.next()) |line| if (starts(line, prefix)) {
        count += 1;
    };
    return count;
}
fn linePosition(bytes: []const u8, prefix: []const u8) !usize {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var position: usize = 0;
    var result: ?usize = null;
    while (lines.next()) |line| : (position += 1) if (starts(line, prefix)) {
        result = position;
    };
    return result orelse error.MissingCall;
}
fn sameFile(c: f.Context, first: []const u8, second: []const u8) !void {
    try expect(eq(try c.read(first), try c.read(second)));
}
fn absent(c: f.Context, paths: []const []const u8) !void {
    for (paths) |path| try expect(!try c.exists(path));
}
fn diagnostic(c: f.Context, file: []const u8, line: []const u8) !void {
    const bytes = try c.read(file);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |candidate| if (eq(candidate, line)) return;
    return error.MissingExpectedDiagnostic;
}
fn decodedEquals(c: f.Context, wrapper: []const u8, raw: []const u8) !void {
    try expect(eq(try f.string(try c.document(wrapper)), try c.read(raw)));
}
fn privacy(c: f.Context, relative: []const u8) anyerror!void {
    if (!try c.exists(relative)) return;
    const dir = try f.files.Directory.open(c.io, try c.path(relative));
    defer dir.close(c.io);
    var iterator = dir.dir.iterate();
    while (try iterator.next(c.io)) |entry| {
        const child = try std.fs.path.join(c.a, &.{ relative, entry.name });
        switch (entry.kind) {
            .directory => try privacy(c, child),
            .file => {
                const bytes = try c.read(child); // nofollow, single-link, uid and 0600
                try expect(std.mem.indexOf(u8, bytes, f.sentinel) == null);
            },
            else => return error.UnsafeFixtureEntry,
        }
    }
}
fn common(c: f.Context, case: Case, result: u8, outcome: std.json.Value) !void {
    const success = case.assertions == .accepted_custody;
    try expect((result == 0) == success and try f.yes(outcome, "accepted") == success);
    const primary = try f.num(outcome, "primary_exit");
    if (primary != 0) try expect(primary == result);
    try outcomeContract(case, result, outcome);
    try mutations(c, case);
    try privacy(c, "attempt");
    try privacy(c, "ledger");
    try absent(c, &.{ "attempt/upload-os/sas.txt", "attempt/upload-data/sas.txt" });
    inline for (.{ "public.stdout", "public.stderr" }) |file| try expect(std.mem.indexOf(u8, try c.read(file), f.sentinel) == null);
    const state = try c.document("fake-cloud.json");
    if (state.object.get("boot2_reads")) |reads| try expect(try f.number(reads) <= 60);
    if (!one(case.name, &.{ "bad-input", "preexisting-group" })) {
        try expect(try c.exists("ledger/attempt-" ++ f.owner));
        try sameFile(c, "scope.json", "ledger/" ++ "1" ** 32 ++ "-" ++ "2" ** 32 ++ "/consumed.json");
        try expect(try c.exists("ledger/sha256-" ++ f.image_sha));
    }
}

fn outcomeContract(case: Case, result: u8, outcome: std.json.Value) !void {
    const name = case.name;
    const last = lastMutation(case);
    const boots: i64 = if (last < 10) 0 else if (last >= 12 or eq(name, "boot1-mutated-before-start")) 2 else 1;
    try expect(try f.num(outcome, "reserved_boots") == boots);
    try expect(try f.yes(outcome, "group_creation_attempted") == (last > 0));
    const cleanup_failed = noDelete(name) or one(name, &.{ "bad-input", "revoke-failure", "delete-failure", "diagnostics-delete-failure", "diagnostics-read-delete-failure" });
    try expect(try f.num(outcome, "cleanup_exit") == @as(i64, if (cleanup_failed) 1 else 0));
    const complete = case.assertions == .accepted_custody or one(name, &.{ "cleanup-unowned", "foreign-resource", "delete-failure" });
    try expect(try f.yes(outcome, "persistence_evidence_complete") == complete);
    const primary = try f.num(outcome, "primary_exit");
    if (complete) {
        try expect(primary == 0 and result == @as(u8, if (cleanup_failed) 1 else 0));
        return;
    }
    if (eq(name, "process-output-overflow")) {
        try expect(primary != 0);
        return;
    }
    if (one(name, &.{ "stale-boot1-log", "azure-padding-only" })) {
        // Legacy bounded sleep can win the final deadline race (124), or the
        // serial loop can observe its exhausted deadline/poll count first (1).
        try expect(primary == 1 or primary == 124);
        return;
    }
    const expected: i64 = if (one(name, &.{ "both-grants", "unknown-grant", "numeric-exponent", "malformed-power" })) 5 else if (eq(name, "upload-failure")) 12 else if (one(name, &.{ "cache-hash-error", "cache-binding-hash-error", "cache-admission-hash-error" })) 17 else if (eq(name, "ambiguous-grant")) 18 else if (eq(name, "revoke-failure")) 19 else if (eq(name, "ambiguous-deploy")) 20 else if (eq(name, "ambiguous-deallocate")) 21 else if (eq(name, "ambiguous-start")) 22 else if (eq(name, "process-signal-term")) 143 else 1;
    try expect(primary == expected);
}

const mutation_order = [_][]const u8{
    "group create fixture-direct-rg",
    "disk create fixture-direct-os",
    "disk grant-access fixture-direct-os",
    "transfer",
    "disk revoke-access fixture-direct-os",
    "disk create fixture-direct-data",
    "disk grant-access fixture-direct-data",
    "transfer",
    "disk revoke-access fixture-direct-data",
    "deployment group fixture-direct",
    "vm deallocate fixture-direct-vm",
    "vm start fixture-direct-vm",
    "vm deallocate fixture-direct-vm",
};
fn mutation(line: []const u8) bool {
    for (mutation_order) |item| if (eq(line, item)) return true;
    return starts(line, "group delete ");
}
fn noDelete(name: []const u8) bool {
    return one(name, &.{ "cleanup-unowned", "foreign-resource", "identity-drift", "diagnostics-unowned-group", "diagnostics-foreign-resource", "diagnostics-vm-identity-drift", "diagnostics-disk-identity-drift" });
}
fn lastMutation(case: Case) usize {
    const name = case.name;
    if (one(name, &.{ "bad-input", "preexisting-group" }) or case.assertions == .inadmissible_no_claim) return 0;
    if (eq(name, "numeric-exponent")) return 2;
    if (one(name, &.{ "both-grants", "unknown-grant", "duplicate-grant", "ambiguous-grant" })) return 3;
    if (eq(name, "upload-failure")) return 4;
    if (eq(name, "revoke-failure")) return 5;
    if (starts(name, "process-")) return 10;
    if (case.assertions == .accepted_custody or one(name, &.{ "cleanup-unowned", "foreign-resource", "delete-failure", "final-attached", "final-stopped" })) return 13;
    if (one(name, &.{ "ambiguous-deallocate", "boot1-mutated-before-start", "retained-attached", "retained-unattached", "retained-stopped" })) return 11;
    if (case.assertions == .failure_diagnostics or one(name, &.{
        "ambiguous-deploy",   "attachment-mismatch",  "serial-failure",         "running-reserved", "boot1-missing-platform",
        "stopped-bad-serial", "azure-all-zero-boot1", "azure-incomplete-boot1",
    })) return 10;
    return 12;
}
fn mutations(c: f.Context, case: Case) !void {
    const calls = try c.read("calls");
    const last = lastMutation(case);
    var expected: std.ArrayList([]const u8) = .empty;
    try expected.appendSlice(c.a, mutation_order[0..last]);
    if (one(case.name, &.{ "both-grants", "unknown-grant", "duplicate-grant", "ambiguous-grant", "upload-failure", "revoke-failure" }))
        try expected.append(c.a, "disk revoke-access fixture-direct-os");
    if (last > 0 and !noDelete(case.name)) try expected.append(c.a, "group delete fixture-direct-rg");
    var lines = std.mem.splitScalar(u8, calls, '\n');
    var index: usize = 0;
    while (lines.next()) |line| if (mutation(line)) {
        if (index >= expected.items.len or !eq(line, expected.items[index])) return error.MutationOrderMismatch;
        index += 1;
    };
    if (index != expected.items.len) return error.MutationCountMismatch;
    try expect(linesWith(calls, "group create ") <= 1 and linesWith(calls, "deployment group ") <= 1 and linesWith(calls, "vm start ") <= 1 and linesWith(calls, "group delete ") <= 1);
}

fn checkHash(c: f.Context, record: std.json.Value, key: []const u8, file: []const u8) !void {
    const observed = try c.digest(file);
    try expect(eq(try f.str(record, key), &observed));
}
fn custody(c: f.Context) !void {
    const first = try c.document("attempt/boot1-capture.json");
    const second = try c.document("attempt/boot2-capture.json");
    const admission = try c.document("attempt/boot2-admission.json");
    inline for (.{ .{ first, "1" }, .{ second, "2" } }) |pair| {
        const record = pair[0];
        try expect(eq(try f.str(record, "schema"), "uk.hyperv.direct-serial-capture") and try f.num(record, "version") == 1);
        try expect(try f.num(record, "boot") == if (eq(pair[1], "1")) @as(i64, 1) else @as(i64, 2));
        const poll = try f.num(record, "poll");
        try expect(poll > 0 and poll <= 60);
        try checkHash(c, record, "serial_sha256", "attempt/boot" ++ pair[1] ++ ".log");
        try checkHash(c, record, "cli_wrapper_sha256", try std.fmt.allocPrint(c.a, "attempt/boot{s}-serial-{d}.json", .{ pair[1], poll }));
        try checkHash(c, record, "vm_observation_sha256", "attempt/boot" ++ pair[1] ++ "-vm.json");
        try decodedEquals(c, try std.fmt.allocPrint(c.a, "attempt/boot{s}-serial-{d}.json", .{ pair[1], poll }), "attempt/boot" ++ pair[1] ++ ".log");
    }
    try expect(eq(try f.str(first, "boot2_admission_sha256"), ""));
    try checkHash(c, second, "boot2_admission_sha256", "attempt/boot2-admission.json");
    try expect(eq(try f.str(admission, "schema"), "uk.hyperv.direct-boot2-admission") and try f.num(admission, "version") == 1 and try f.num(admission, "reserved_boots") == 2);
    try checkHash(c, admission, "boot1_capture_sha256", "attempt/boot1-capture.json");
    inline for (.{ .{ "retained_vm_sha256", "retained-vm.json" }, .{ "retained_os_sha256", "retained-os.json" }, .{ "retained_data_sha256", "retained-data.json" }, .{ "deallocated_power_sha256", "retained-power.json" } }) |binding|
        try checkHash(c, admission, binding[0], "attempt/" ++ binding[1]);
    const scope = try c.document("scope.json");
    inline for (.{ first, second, admission }) |record| {
        try checkHash(c, record, "scope_sha256", "scope.json");
        try checkHash(c, record, "original_boot1_sha256", "attempt/boot1.log");
        inline for (.{ .{ "vm_id", f.vm_id }, .{ "os_id", f.os_id }, .{ "data_id", f.data_id }, .{ "vm_uuid", "original-vm" }, .{ "os_uuid", "original-os" }, .{ "data_uuid", "original-data" } }) |binding|
            try expect(eq(try f.str(record, binding[0]), binding[1]));
    }
    try expect(eq(try f.str(first, "serial_mode"), try f.str(scope, "serial_mode")) and eq(try f.str(second, "serial_mode"), try f.str(scope, "serial_mode")));
    try sameFile(c, "scope.json", "attempt/scope.json");
}
fn noDiagnostics(outcome: std.json.Value) !void {
    const d = try f.field(outcome, "failure_diagnostics");
    try expect(!try f.yes(d, "attempted") and (try f.field(d, "exit")) == .null and !try f.yes(d, "decoded"));
}
fn diagnostics(outcome: std.json.Value, exit: i64, decoded: bool) !void {
    const d = try f.field(outcome, "failure_diagnostics");
    try expect(try f.yes(d, "attempted") and try f.num(d, "exit") == exit and try f.yes(d, "decoded") == decoded);
}
fn cached(outcome: std.json.Value, reads: i64) !void {
    const freshness = try f.field(outcome, "boot2_freshness");
    try expect(try f.num(freshness, "cached_reads") == reads);
    if (reads > 0) try expect(eq(try f.str(freshness, "cached_reason"), "identical-pinned-boot1")) else try expect((try f.field(freshness, "cached_reason")) == .null);
}
fn accepted(c: f.Context, name: []const u8, outcome: std.json.Value) !void {
    try expect(try f.num(outcome, "reserved_boots") == 2 and try f.num(outcome, "primary_exit") == 0 and try f.num(outcome, "cleanup_exit") == 0);
    try expect(try f.yes(outcome, "persistence_evidence_complete") and try f.yes(outcome, "owned_group_absent"));
    try noDiagnostics(outcome);
    try custody(c);
    const calls = try c.read("calls");
    try expect(linesWith(calls, "failure diagnostics") == 0);
    inline for (.{ "boot1", "boot2", "retained", "final" }) |phase| {
        const retained = one(phase, &.{ "retained", "final" });
        const stopped = (eq(phase, "boot1") and one(name, &.{ "stopped-boot1", "stopped-both" })) or (eq(phase, "boot2") and one(name, &.{ "stopped-boot2", "stopped-both" }));
        inline for (.{ "os", "data" }) |role| {
            const disk = try c.document(try std.fmt.allocPrint(c.a, "attempt/{s}-{s}.json", .{ phase, role }));
            try expect(eq(try f.str(disk, "diskState"), if (retained) "Reserved" else "Attached") and eq(try f.str(disk, "managedBy"), f.vm_id));
        }
        const power = try c.document(try std.fmt.allocPrint(c.a, "attempt/{s}-power.json", .{phase}));
        const statuses = try f.field(try f.field(power, "instanceView"), "statuses");
        var found: usize = 0;
        for (statuses.array.items) |status| {
            const code = try f.str(status, "code");
            if (starts(code, "PowerState/")) {
                found += 1;
                try expect(eq(code, if (retained) "PowerState/deallocated" else if (stopped) "PowerState/stopped" else "PowerState/running"));
            }
        }
        try expect(found == 1);
    }
    const cache = one(name, &.{ "cached-then-fresh", "cumulative-cached-then-fresh", "azure-cached-then-fresh", "azure-no-advance-then-fresh" });
    try cached(outcome, if (cache) 1 else 0);
    if (cache) {
        const advancing = eq(name, "azure-no-advance-then-fresh");
        const expected_reads: i64 = if (advancing) 4 else 2;
        try expect(try f.num(try c.document("fake-cloud.json"), "boot2_reads") == expected_reads);
        try expect(try f.num(try c.document("attempt/boot2-capture.json"), "poll") == expected_reads);
        try expect(linesWith(calls, "validator serial") == @as(usize, @intCast(expected_reads)));
        try decodedEquals(c, "attempt/boot2-serial-1.json", if (advancing) "boot1-body.log" else "attempt/boot1.log");
        if (advancing) {
            try expect(eq(try f.string(try c.document("attempt/boot2-serial-2.json")), try std.mem.concat(c.a, u8, &.{ try c.read("boot1-body.log"), "\x00" })));
            try decodedEquals(c, "attempt/boot2-serial-3.json", "attempt/boot1.log");
        }
    }
    try sameFile(c, "boot1.log", "attempt/boot1.log");
    try sameFile(c, "boot2.log", "attempt/boot2.log");
}

fn refused(c: f.Context, name: []const u8, result: u8, outcome: std.json.Value) !void {
    const calls = try c.read("calls");
    const starts_count = linesWith(calls, "vm start ");
    const primary = try f.num(outcome, "primary_exit");
    const cleanup = try f.num(outcome, "cleanup_exit");
    if (starts(name, "process-")) {
        try expect(starts_count == 0 and cleanup == 0 and try f.yes(outcome, "owned_group_absent"));
        try absent(c, &.{ "attempt/boot1.log", "attempt/boot2-admission.json" });
        try noDiagnostics(outcome);
        const pid = try std.fmt.parseInt(std.os.linux.pid_t, std.mem.trimEnd(u8, try c.read("process.pid"), "\n"), 10);
        try expect(pid > 1 and std.os.linux.errno(std.os.linux.kill(pid, @enumFromInt(0))) == .SRCH);
        if (eq(name, "process-signal-term")) try expect(result == 143 and primary == 143);
        if (eq(name, "process-output-overflow")) {
            const output = try c.read("attempt/deployment.json");
            try expect(output.len > 0 and output.len <= 8 * 1024 * 1024);
        }
    }
    if (one(name, &.{ "boot1-mutated-before-start", "running-reserved", "retained-attached", "retained-unattached" })) try expect(starts_count == 0);
    if (one(name, &.{ "final-attached", "unexpected-boot2-power", "final-stopped" })) try expect(starts_count == 1);
    if (one(name, &.{ "stopped-bad-serial", "unexpected-boot1-power", "malformed-power", "retained-stopped" }) or starts(name, "diagnostics-")) {
        try expect(starts_count == 0);
        try absent(c, &.{"attempt/boot2-admission.json"});
    }
    if (one(name, &.{ "boot1-missing-platform", "boot2-missing-platform" })) {
        const boots: i64 = if (eq(name, "boot1-missing-platform")) 1 else 2;
        try expect(starts_count == boots - 1 and try f.num(outcome, "reserved_boots") == boots and cleanup == 0);
        try diagnostic(c, "attempt/serial-check.stderr", "direct validation failed: PlatformNotReady");
    }
    if (noDelete(name)) {
        try expect(linesWith(calls, "group delete ") == 0 and cleanup != 0);
        try noDiagnostics(outcome);
    } else if (eq(name, "preexisting-group")) {
        try expect(linesWith(calls, "group create ") == 0);
    } else if (eq(name, "bad-input")) {
        try expect(calls.len == 0 and !try c.exists("ledger/attempt-" ++ f.owner));
    } else if (eq(name, "delete-failure")) {
        try expect(primary == 0 and cleanup != 0);
    } else if (one(name, &.{ "diagnostics-delete-failure", "diagnostics-read-delete-failure" })) {
        try expect(primary == 1 and cleanup != 0 and !try f.yes(outcome, "owned_group_absent"));
    } else try expect(primary != 0 and try f.yes(outcome, "owned_group_absent"));

    const d = try f.field(outcome, "failure_diagnostics");
    const diagnostic_count = linesWith(calls, "failure diagnostics");
    if (try f.yes(d, "attempted")) {
        try expect(diagnostic_count == 1);
        _ = try c.read("attempt/failure-boot-diagnostics.json");
        _ = try c.read("attempt/failure-boot-diagnostics.stderr");
        const inventory_position = try linePosition(calls, "resource list ");
        const disk_position = try linePosition(calls, "disk show ");
        const vm_position = try linePosition(calls, "vm show ");
        const diagnostic_position = try linePosition(calls, "failure diagnostics");
        const deletion_position = try linePosition(calls, "group delete ");
        try expect(inventory_position < disk_position and disk_position < vm_position and vm_position < diagnostic_position and diagnostic_position < deletion_position);
    } else {
        try expect(diagnostic_count == 0);
        try absent(c, &.{"attempt/failure-boot-diagnostics.json"});
        try noDiagnostics(outcome);
    }
    if (one(name, &.{ "unexpected-boot1-power", "malformed-power" }) or starts(name, "diagnostics-")) {
        try absent(c, &.{ "attempt/boot1.log", "attempt/boot1-capture.json", "attempt/boot2-capture.json" });
        try expect(linesWith(calls, "validator serial") == 0 and linesWith(calls, "vm boot-diagnostics ") == diagnostic_count);
    }
    if (eq(name, "malformed-power")) {
        try expect(result == 5);
        try diagnostic(c, "attempt/driver.stderr", "direct observation failed: boot1-power.json");
    }
    if (one(name, &.{ "diagnostics-power-failure", "unexpected-boot1-power", "unexpected-boot2-power", "stopped-bad-serial" })) {
        try expect(primary != 0 and cleanup == 0);
        try diagnostics(outcome, 0, true);
    }
    if (one(name, &.{ "diagnostics-read-failure", "diagnostics-read-delete-failure" })) {
        try diagnostics(outcome, 23, false);
        try diagnostic(c, "attempt/failure-boot-diagnostics.stderr", "fixture diagnostic read failure");
    }
    if (eq(name, "diagnostics-decode-failure")) {
        try expect(primary == 1 and cleanup == 0);
        try diagnostics(outcome, 5, false);
        try expect((try c.read("attempt/failure-boot-diagnostics-decode.stderr")).len > 0);
        try expect(eq(try f.str(try c.document("attempt/failure-boot-diagnostics.json"), "unexpected"), "not a JSON string"));
    }
    if (eq(name, "diagnostics-timeout")) {
        try expect(primary == 1 and cleanup == 0);
        try diagnostics(outcome, 124, false);
        try boundedTimestamps(c, "delete.seconds", "diagnostics.seconds", 30);
    }
    if (eq(name, "diagnostics-no-budget")) {
        try expect(cleanup == 0 and try f.yes(outcome, "owned_group_absent"));
        try diagnostic(c, "attempt/driver.stderr", "failure boot diagnostics skipped: cleanup budget");
    }
    if (one(name, &.{ "retained-stopped", "final-stopped" })) {
        const phase = if (eq(name, "retained-stopped")) "retained" else "final";
        inline for (.{ "os", "data" }) |role| {
            const disk = try c.document(try std.fmt.allocPrint(c.a, "attempt/{s}-{s}.json", .{ phase, role }));
            try expect(eq(try f.str(disk, "diskState"), "Reserved"));
        }
        try diagnostic(c, "attempt/driver.stderr", try std.fmt.allocPrint(c.a, "direct observation failed: {s}-power.json", .{phase}));
    }
    if (eq(name, "diagnostics-power-failure")) try sameFile(c, "boot1.log", "attempt/failure-boot-diagnostics.log");
    const reads = try f.num(try f.field(outcome, "boot2_freshness"), "cached_reads");
    try expect(reads >= 0 and linesWith(try c.read("attempt/driver.stderr"), "Boot2 cached read ") == reads);
    const child_statuses = .{
        .{ "upload-failure", 12 },   .{ "ambiguous-grant", 18 },      .{ "revoke-failure", 19 },
        .{ "ambiguous-deploy", 20 }, .{ "ambiguous-deallocate", 21 }, .{ "ambiguous-start", 22 },
    };
    inline for (child_statuses) |pair| if (eq(name, pair[0])) try expect(result == pair[1] and primary == pair[1]);
}
fn boundedTimestamps(c: f.Context, end: []const u8, start: []const u8, maximum: i64) !void {
    const end_time = try std.fmt.parseInt(i64, std.mem.trim(u8, try c.read(end), " \n"), 10);
    const start_time = try std.fmt.parseInt(i64, std.mem.trim(u8, try c.read(start), " \n"), 10);
    try expect(end_time >= start_time and end_time - start_time <= maximum);
}
fn serialRefusal(c: f.Context, name: []const u8, result: u8, outcome: std.json.Value) !void {
    const calls = try c.read("calls");
    const reads = try f.num(try f.field(outcome, "boot2_freshness"), "cached_reads");
    const state = try c.document("fake-cloud.json");
    const parses = linesWith(calls, "validator serial");
    if (one(name, &.{ "stale-boot1-log", "azure-padding-only" })) {
        const boot2_reads = try f.num(state, "boot2_reads");
        try expect(boot2_reads > 0 and boot2_reads <= 60);
        if (eq(name, "stale-boot1-log")) {
            try expect(reads > 0 and reads <= boot2_reads and parses == 1);
        } else {
            try expect(reads == 0 and parses > 1 and parses <= boot2_reads + 1);
        }
        const scope = try c.document("scope.json");
        try expect(try f.num(scope, "runtime_seconds") == 60 and try f.num(scope, "poll_seconds") == 1);
        try boundedTimestamps(c, "cleanup.seconds", "boot2-start.seconds", 60);
        try sameFile(c, "boot2.log", "attempt/failure-boot-diagnostics.log");
    } else if (one(name, &.{ "azure-all-zero-boot1", "azure-incomplete-boot1" })) {
        try expect(linesWith(calls, "vm start ") == 0 and try f.num(state, "serial_reads") == 2 and parses == 2);
        try absent(c, &.{ "attempt/boot2-admission.json", "attempt/boot1.log", "attempt/boot1-capture.json" });
        try expect(try f.num(outcome, "reserved_boots") == 1 and try f.num(outcome, "cleanup_exit") == 0 and !try f.yes(outcome, "accepted"));
        try sameFile(c, "boot1.log", "attempt/failure-boot-diagnostics.log");
    } else if (starts(name, "azure-") or one(name, &.{ "per-boot-azure-log", "cumulative-azure-log" })) {
        try expect(reads == 0 and parses == 2 and try f.num(state, "boot2_reads") == 1);
        const err: []const u8 = if (starts(name, "azure-prefix-") or one(name, &.{ "azure-interior-nul-removed", "azure-missing-prefix", "cumulative-azure-log" }))
            "SerialPrefixChanged"
        else if (one(name, &.{ "azure-wrong-boot", "per-boot-azure-log" }))
            "WrongBootState"
        else if (eq(name, "azure-wrong-identity"))
            "IdentityDrift"
        else if (one(name, &.{ "azure-writes", "azure-flushes" }))
            "WrongIoLedger"
        else if (eq(name, "azure-failure"))
            "GuestFailure"
        else if (eq(name, "azure-missing-platform"))
            "PlatformNotReady"
        else
            return error.MissingSerialAssertion;
        try diagnostic(c, "attempt/serial-check.stderr", try std.mem.concat(c.a, u8, &.{ "direct validation failed: ", err }));
    } else if (one(name, &.{ "different-boot1-log", "cumulative-different-boot1" })) {
        try expect(reads == 0 and parses == 2 and try f.num(state, "boot2_reads") == 1);
        const stderr = try c.read("attempt/serial-check.stderr");
        try expect(one(stderr, &.{ "direct validation failed: WrongBootState\n", "direct validation failed: SerialPrefixChanged\n" }));
    } else if (eq(name, "cache-hash-error")) {
        try expect(result == 17 and reads == 0 and parses == 1 and try f.num(state, "boot2_reads") == 1);
    } else if (starts(name, "cache-")) {
        try expect(reads == 1 and try f.num(state, "boot2_reads") == 2);
        try expect(parses == @as(usize, if (one(name, &.{ "cache-then-wrong-identity", "cache-then-failure" })) 2 else 1));
        if (one(name, &.{ "cache-binding-hash-error", "cache-admission-hash-error" })) try expect(result == 17);
    } else return error.MissingSerialAssertion;
    if (!one(name, &.{ "azure-all-zero-boot1", "azure-incomplete-boot1" })) {
        try expect(linesWith(calls, "vm start ") == 1 and linesWith(calls, "vm deallocate ") == 1);
        try absent(c, &.{ "attempt/boot2.log", "attempt/boot2-capture.json" });
        try expect(try f.num(outcome, "reserved_boots") == 2 and try f.num(outcome, "primary_exit") != 0 and try f.num(outcome, "cleanup_exit") == 0 and !try f.yes(outcome, "accepted"));
        try diagnostics(outcome, 0, true);
        if (starts(name, "azure-") or one(name, &.{ "per-boot-azure-log", "cumulative-azure-log" })) try sameFile(c, "boot1.log", "attempt/boot1.log");
    }
}

fn compare(c: f.Context, other: f.Context) !void {
    try other.validate();
    const left = try c.document("attempt/outcome.json");
    const right = try other.document("attempt/outcome.json");
    // Do not compare JSON formatting or timestamps, and do not erase hashes or
    // identities. Acceptance has already independently checked every hash edge.
    inline for (.{ "phase", "accepted", "primary_exit", "cleanup_exit", "reserved_boots", "persistence_evidence_complete", "owned_group_absent", "group_creation_attempted", "failure_diagnostics" }) |key| {
        try expect(jsonEqual(try f.field(left, key), try f.field(right, key)));
    }
    const left_exit = try c.document("public.exit.json");
    const right_exit = try other.document("public.exit.json");
    try expect(try f.num(left_exit, "status") == try f.num(right_exit, "status"));
    try compareScopes(c, other);
    var expected: std.ArrayList([]const u8) = .empty;
    var reference_lines = std.mem.splitScalar(u8, try other.read("calls"), '\n');
    while (reference_lines.next()) |line| if (mutation(line)) try expected.append(c.a, line);
    var lines = std.mem.splitScalar(u8, try c.read("calls"), '\n');
    var count: usize = 0;
    while (lines.next()) |line| if (mutation(line)) {
        try expect(count < expected.items.len and eq(line, expected.items[count]));
        count += 1;
    };
    try expect(count == expected.items.len);
    if (try f.yes(left, "accepted")) try custody(other);
    const scenario = std.mem.trimEnd(u8, try c.read("scenario"), "\n");
    if (!try f.yes(left, "accepted")) try refusedCustody(other, scenario);
    if (!eq(scenario, "stale-boot1-log")) {
        try expect(jsonEqual(try f.field(left, "boot2_freshness"), try f.field(right, "boot2_freshness")));
    }
}

fn compareScopes(c: f.Context, other: f.Context) !void {
    var left = (try validation.parse(validation.Scope, c.a, try c.read("scope.json"))).value;
    var right = (try validation.parse(validation.Scope, c.a, try other.read("scope.json"))).value;
    // Only the declared generated wall-clock expiry and isolated path roots
    // differ. Artifact hashes, sizes, all identities and budgets remain exact.
    left.approval.expires_unix = 0;
    right.approval.expires_unix = 0;
    inline for (.{ "os_vhd", "seed_raw", "seed_vhd", "manifest", "config" }) |name| {
        try c.confined(@field(left, name).path);
        try other.confined(@field(right, name).path);
        @field(left, name).path = @field(left, name).path[c.root.len + 1 ..];
        @field(right, name).path = @field(right, name).path[other.root.len + 1 ..];
    }
    try expect(eq(try f.json(c.a, left), try f.json(c.a, right)));
}

fn jsonEqual(left: std.json.Value, right: std.json.Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .null => true,
        .bool => |v| v == right.bool,
        .integer => |v| v == right.integer,
        .float => |v| v == right.float,
        .number_string => |v| eq(v, right.number_string),
        .string => |v| eq(v, right.string),
        .array => |v| blk: {
            if (v.items.len != right.array.items.len) break :blk false;
            for (v.items, right.array.items) |a, b| if (!jsonEqual(a, b)) break :blk false;
            break :blk true;
        },
        .object => |v| blk: {
            if (v.count() != right.object.count()) break :blk false;
            var iterator = v.iterator();
            while (iterator.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse break :blk false;
                if (!jsonEqual(entry.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn template(c: f.Context) !void {
    const repository = c.root[0..std.mem.indexOf(u8, c.root, "/.d/").?];
    const path = try std.mem.concat(c.a, u8, &.{ repository, "/support/azure/hyperv-direct-two-boot.json" });
    const file = try f.files.openAbsolute(c.io, path, .artifact);
    defer file.close(c.io);
    const size = (try file.stat(c.io)).size;
    try expect(size < 65536);
    const bytes = try c.a.alloc(u8, @intCast(size));
    try expect(try file.readPositionalAll(c.io, bytes, 0) == bytes.len);
    const resources = try f.field(try f.parse(c.a, bytes), "resources");
    try expect(resources == .array and resources.array.items.len == 4);
    var vm: ?std.json.Value = null;
    for (resources.array.items) |resource| {
        const kind = try f.str(resource, "type");
        try expect(std.mem.indexOf(u8, kind, "publicIPAddresses") == null);
        if (eq(kind, "Microsoft.Compute/virtualMachines")) {
            try expect(vm == null);
            vm = try f.field(resource, "properties");
        }
    }
    const machine = vm orelse return error.TemplateMissingVm;
    try expect(!machine.object.contains("osProfile"));
    try expect(eq(try f.str(try f.field(machine, "securityProfile"), "securityType"), "Standard"));
    const storage = try f.field(machine, "storageProfile");
    try expect(eq(try f.str(storage, "diskControllerType"), "SCSI"));
    const os = try f.field(storage, "osDisk");
    try expect(eq(try f.str(os, "createOption"), "Attach") and eq(try f.str(os, "caching"), "ReadOnly") and eq(try f.str(os, "deleteOption"), "Detach"));
    const data = try f.field(storage, "dataDisks");
    try expect(data == .array and data.array.items.len == 1);
    const disk = data.array.items[0];
    try expect(try f.num(disk, "lun") == 7 and eq(try f.str(disk, "caching"), "None") and eq(try f.str(disk, "deleteOption"), "Detach"));
    try expect(try f.yes(try f.field(try f.field(machine, "diagnosticsProfile"), "bootDiagnostics"), "enabled"));
}

fn originalFile(c: f.Context, relative: []const u8) ![]const u8 {
    const saved = try std.mem.concat(c.a, u8, &.{ "tamper-original-", std.fs.path.basename(relative) });
    return if (try c.exists(saved)) saved else relative;
}
fn originalHash(c: f.Context, record: std.json.Value, key: []const u8, relative: []const u8) !void {
    try checkHash(c, record, key, try originalFile(c, relative));
}
fn refusedCustody(c: f.Context, name: []const u8) !void {
    if (try c.exists("attempt/boot2-capture.json")) {
        try custody(c);
        return;
    }
    if (!try c.exists("attempt/boot1-capture.json")) return;
    const capture_path = try originalFile(c, "attempt/boot1-capture.json");
    const first = try c.document(capture_path);
    try expect(try f.num(first, "boot") == 1 and eq(try f.str(first, "schema"), "uk.hyperv.direct-serial-capture"));
    try originalHash(c, first, "serial_sha256", "attempt/boot1.log");
    try checkHash(c, first, "scope_sha256", "scope.json");
    try originalHash(c, first, "original_boot1_sha256", "attempt/boot1.log");
    try checkHash(c, first, "vm_observation_sha256", "attempt/boot1-vm.json");
    const poll = try f.num(first, "poll");
    try expect(poll > 0 and poll <= 60);
    try checkHash(c, first, "cli_wrapper_sha256", try std.fmt.allocPrint(c.a, "attempt/boot1-serial-{d}.json", .{poll}));
    try decodedEquals(c, try std.fmt.allocPrint(c.a, "attempt/boot1-serial-{d}.json", .{poll}), try originalFile(c, "attempt/boot1.log"));
    try sameFile(c, "boot1.log", try originalFile(c, "attempt/boot1.log"));
    inline for (.{ .{ "vm_id", f.vm_id }, .{ "os_id", f.os_id }, .{ "data_id", f.data_id }, .{ "vm_uuid", "original-vm" }, .{ "os_uuid", "original-os" }, .{ "data_uuid", "original-data" } }) |binding|
        try expect(eq(try f.str(first, binding[0]), binding[1]));
    if (try c.exists("attempt/boot2-admission.json")) {
        const admission = try c.document(try originalFile(c, "attempt/boot2-admission.json"));
        try expect(try f.num(admission, "reserved_boots") == 2);
        try checkHash(c, admission, "scope_sha256", "scope.json");
        try originalHash(c, admission, "original_boot1_sha256", "attempt/boot1.log");
        try originalHash(c, admission, "boot1_capture_sha256", "attempt/boot1-capture.json");
        inline for (.{ .{ "retained_vm_sha256", "retained-vm.json" }, .{ "retained_os_sha256", "retained-os.json" }, .{ "retained_data_sha256", "retained-data.json" }, .{ "deallocated_power_sha256", "retained-power.json" } }) |binding|
            try checkHash(c, admission, binding[0], "attempt/" ++ binding[1]);
        inline for (.{ "vm_id", "os_id", "data_id", "vm_uuid", "os_uuid", "data_uuid" }) |key|
            try expect(eq(try f.str(first, key), try f.str(admission, key)));
    }
    const changed: ?[]const u8 = if (one(name, &.{ "boot1-mutated-before-start", "boot1-mutated-after-start", "cache-boot1-mutated" })) "boot1.log" else if (eq(name, "cache-capture-mutated")) "boot1-capture.json" else if (eq(name, "cache-scope-mutated")) "scope.json" else if (one(name, &.{ "boot2-admission-mutated", "cache-admission-mutated" })) "boot2-admission.json" else null;
    if (changed) |file| {
        const relative = try std.mem.concat(c.a, u8, &.{ "attempt/", file });
        const original = try c.read(try originalFile(c, relative));
        const observed = try c.read(relative);
        const suffix: []const u8 = if (one(name, &.{ "boot1-mutated-before-start", "boot1-mutated-after-start" })) "benign-looking appended line\n" else if (eq(name, "cache-boot1-mutated")) "changed during cache wait\n" else " \n";
        try expect(eq(observed, try std.mem.concat(c.a, u8, &.{ original, suffix })) and !eq(&f.hash(original), &f.hash(observed)));
    }
}
