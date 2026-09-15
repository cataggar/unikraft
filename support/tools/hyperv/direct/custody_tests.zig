// SPDX-License-Identifier: BSD-3-Clause
//! Native synthetic filesystem tests. Requires an explicit, owner-private root.
const std = @import("std");
const core = @import("hyperv_core");
const custody = @import("custody.zig");
const direct = @import("main.zig");
const options = @import("test_options");
const files = core.private_files;
const t = std.testing;
const a = t.allocator;
const io = t.io;
const linux = std.os.linux;

const ids: custody.Identities = .{
    .vm_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/fixture-rg/providers/Microsoft.Compute/virtualMachines/fixture-vm",
    .vm_uuid = "fixture-vm-uuid",
    .os_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/fixture-rg/providers/Microsoft.Compute/disks/fixture-os",
    .os_uuid = "fixture-os-uuid",
    .data_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/fixture-rg/providers/Microsoft.Compute/disks/fixture-data",
    .data_uuid = "fixture-data-uuid",
};

fn sampleScope(mode: custody.SerialMode) custody.Scope {
    return .{
        .schema = "uk.hyperv.direct-two-boot",
        .version = 1,
        .approval = .{
            .destructive_data_disk = true,
            .direct_specialized_gen2 = true,
            .two_boots_only = true,
            .cleanup_owned_group = true,
            .original_seed_reviewed = true,
            .guarded_native_image_reviewed = true,
            .expires_unix = 9999999999,
        },
        .attempt_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        .subscription = "11111111-1111-1111-1111-111111111111",
        .location = "eastus",
        .prefix = "fixture",
        .vm_size = "Standard_D2s_v5",
        .run_id = "11111111111111111111111111111111",
        .disk_id = "22222222222222222222222222222222",
        .controller = .SCSI,
        .lun = 7,
        .sectors = 8388608,
        .sector_size = 512,
        .serial_mode = mode,
        .runtime_seconds = 60,
        .cleanup_seconds = 60,
        .operation_seconds = 10,
        .poll_seconds = 1,
        .os_vhd = .{ .path = "/synthetic/os.vhd", .size = 1049088, .sha256 = "a" ** 64 },
        .seed_raw = .{ .path = "/synthetic/seed.raw", .size = 4294967296, .sha256 = "b" ** 64 },
        .seed_vhd = .{ .path = "/synthetic/seed.vhd", .size = 4294967808, .sha256 = "c" ** 64 },
        .manifest = .{ .path = "/synthetic/manifest.json", .size = 16, .sha256 = "d" ** 64 },
        .config = .{ .path = "/synthetic/config", .size = 16, .sha256 = "e" ** 64 },
    };
}

const Fixture = struct {
    root: files.Directory,
    directory: files.Directory,
    path: []u8,
    name: [32]u8,

    fn init() !Fixture {
        const root_path = options.test_root orelse return error.MissingExplicitTestRoot;
        const root = try files.Directory.open(io, root_path);
        errdefer root.close(io);
        var random: [16]u8 = undefined;
        io.random(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        try root.dir.createDir(io, &name, .fromMode(0o700));
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ root_path, name });
        errdefer a.free(path);
        const directory = try files.Directory.open(io, path);
        errdefer directory.close(io);
        try directory.dir.createDir(io, "ledger", .fromMode(0o700));
        return .{ .root = root, .directory = directory, .path = path, .name = name };
    }

    fn deinit(self: *Fixture) void {
        self.directory.close(io);
        self.root.dir.deleteTree(io, &self.name) catch @panic("custody fixture cleanup failed");
        self.root.close(io);
        a.free(self.path);
    }

    fn join(self: Fixture, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(a, "{s}/{s}", .{ self.path, name });
    }

    fn store(self: Fixture, name: []const u8, scope: custody.Scope) !custody.Store {
        const bytes = try custody.encode(a, scope);
        defer a.free(bytes);
        const original = try std.fmt.allocPrint(a, " \n{s} \n", .{bytes});
        defer a.free(original);
        try write(self.directory, "source.json", original);
        return self.fromSource(name);
    }

    fn fromSource(self: Fixture, name: []const u8) !custody.Store {
        const source = try self.join("source.json");
        defer a.free(source);
        const path = try self.join(name);
        defer a.free(path);
        const ledger = try self.join("ledger");
        defer a.free(ledger);
        return custody.Store.create(a, io, source, path, ledger);
    }
};

fn write(directory: files.Directory, name: []const u8, bytes: []const u8) !void {
    const file = try directory.dir.createFile(io, name, .{
        .read = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
}

fn expectFile(directory: files.Directory, name: []const u8, expected: []const u8) !void {
    var bytes = try directory.readSensitive(io, a, name, custody.cli_limit, null);
    defer bytes.deinit();
    try t.expectEqualStrings(expected, bytes.bytes());
}

fn expectMissing(directory: files.Directory, name: []const u8) !void {
    try t.expectError(error.FileNotFound, directory.openFile(io, name));
}

fn expectDirectory(fixture: Fixture, name: []const u8) !void {
    const path = try fixture.join(name);
    defer a.free(path);
    const dir = try files.Directory.open(io, path);
    dir.close(io);
}

fn hex(bytes: []const u8) [64]u8 {
    var digest: custody.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

const first_raw = "UK_HYPERV_PLATFORM_READY\n" ++
    "HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512\n" ++
    "HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=0\n" ++
    "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444\n" ++
    "HYPERV_PERSISTENCE BOOT1_WRITE PASS run=11111111111111111111111111111111\n" ++
    "UK_HYPERV_PERSISTENCE_IO:1:1:11111111111111111111111111111111:5:3:receipt-verified\n" ++
    "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:11111111111111111111111111111111\n" ++
    "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
const padded_raw = first_raw ++ "\x00" ** 464;
const second_raw = "UK_HYPERV_PLATFORM_READY\n" ++
    "HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512\n" ++
    "HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=2\n" ++
    "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444\n" ++
    "HYPERV_PERSISTENCE BOOT2_READ PASS run=11111111111111111111111111111111\n" ++
    "UK_HYPERV_PERSISTENCE_IO:1:2:11111111111111111111111111111111:0:0:receipt-verified\n" ++
    "UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:11111111111111111111111111111111\n" ++
    "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
const evidence_input: @import("evidence").EvidenceInput = .{
    .run_id = "11111111111111111111111111111111".*,
    .disk_id = "22222222222222222222222222222222".*,
    .sectors = 8388608,
    .lun = 7,
};

fn boot1(store: *custody.Store) !void {
    try store.event(.@"local-admission");
    try store.consume();
    try store.event(.@"seed-consumed");
    try store.reserveBoot1();
    try store.event(.@"boot1-deploy-intent");
    try write(store.directory, "boot1-candidate.log", padded_raw);
    try write(store.directory, "boot1-serial-1.json", "\"synthetic-wrapper-1\"");
    try write(store.directory, "boot1-vm.json", "{\"vm\":\"synthetic-boot1\"}");
    const sources = try store.captureSources(1, 1);
    _ = try direct.serialFirst(padded_raw, store.scope.value.serial_mode, evidence_input);
    try store.capture(1, 1, ids, sources, 0);
    try store.event(.@"boot1-evidence-complete");
}

fn retainedFiles(store: *custody.Store) !custody.Retained {
    try write(store.directory, "retained-vm.json", "{\"vm\":\"retained\"}");
    try write(store.directory, "retained-os.json", "{\"os\":\"retained\"}");
    try write(store.directory, "retained-data.json", "{\"data\":\"retained\"}");
    try write(store.directory, "retained-power.json", "{\"power\":\"deallocated\"}");
    return store.retainedSnapshots();
}

fn admitted(store: *custody.Store) !void {
    try boot1(store);
    try store.event(.@"deallocate-intent");
    try store.admitBoot2(ids, try retainedFiles(store));
    try store.verifyBoot2Admission();
}

fn complete(store: *custody.Store) !void {
    try admitted(store);
    try store.event(.@"boot2-start-intent");
    const raw = switch (store.scope.value.serial_mode) {
        .per_boot => second_raw,
        .cumulative => padded_raw ++ second_raw,
        .azure_cumulative => first_raw ++ second_raw,
    };
    try write(store.directory, "boot2-candidate.log", raw);
    try write(store.directory, "boot2-serial-2.json", "\"synthetic-wrapper-2\"");
    try write(store.directory, "boot2-vm.json", "{\"vm\":\"synthetic-boot2\"}");
    const sources = try store.captureSources(2, 2);
    const first = try direct.serialFirst(padded_raw, store.scope.value.serial_mode, evidence_input);
    try direct.serialSecond(raw, store.scope.value.serial_mode, evidence_input, first);
    try t.expectEqual(.fresh, try store.freshness(sources.serial));
    try store.capture(2, 2, ids, sources, 0);
    try store.event(.@"boot2-evidence-complete");
    try store.event(.@"final-deallocate-intent");
    try store.verifyBoot1();
    try store.event(.@"persistence-evidence-complete");
}

const success: custody.Completion = .{
    .phase = .@"persistence-evidence-complete",
    .primary_exit = 0,
    .cleanup_exit = 0,
    .persistence_evidence_complete = true,
    .owned_group_absent = true,
    .group_creation_attempted = true,
    .final_input_exit = 0,
};

test "fresh scope is copied byte for byte and the exact three ledger claims are durable" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    try t.expectError(error.SeedNotConsumed, store.requireConsumed());
    try expectFile(store.directory, "scope.json", store.scope_bytes.bytes());
    try t.expectEqualStrings(&hex(store.scope_bytes.bytes()), &store.scope_pin.hex());
    try store.consume();
    try store.requireConsumed();
    try expectDirectory(fixture, "ledger/attempt-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    try expectDirectory(fixture, "ledger/11111111111111111111111111111111-22222222222222222222222222222222");
    try expectDirectory(fixture, "ledger/sha256-" ++ "c" ** 64);
    const consumed_path = try fixture.join("ledger/11111111111111111111111111111111-22222222222222222222222222222222");
    defer a.free(consumed_path);
    const consumed_dir = try files.Directory.open(io, consumed_path);
    defer consumed_dir.close(io);
    try expectFile(consumed_dir, "consumed.json", store.scope_bytes.bytes());
    try t.expectError(error.PathAlreadyExists, store.consume());
    try t.expectError(error.CustodyPoisoned, store.requireConsumed());
    try t.expectError(error.PathAlreadyExists, fixture.fromSource("attempt"));
}

test "immutable collisions at each ledger identity never roll back earlier reservations" {
    for (0..3) |collision| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const names = [_][]const u8{
            "attempt-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111111111111111111111111111-22222222222222222222222222222222",
            "sha256-" ++ "c" ** 64,
        };
        const ledger_path = try fixture.join("ledger");
        defer a.free(ledger_path);
        const ledger = try files.Directory.open(io, ledger_path);
        defer ledger.close(io);
        try ledger.dir.createDir(io, names[collision], .fromMode(0o700));
        var store = try fixture.store("attempt", sampleScope(.cumulative));
        defer store.close();
        try t.expectError(error.PathAlreadyExists, store.consume());
        try t.expect(!store.consumed and !store.healthy);
        for (names[0 .. collision + 1]) |name| {
            const path = try std.fmt.allocPrint(a, "ledger/{s}", .{name});
            defer a.free(path);
            try expectDirectory(fixture, path);
        }
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
    }
}

test "all partial reservation and sync failures leave consumed refusal markers" {
    for ([_]custody.TestFault{
        .directory_sync, .after_first_reservation, .after_identity_reservation, .ledger_sync,
    }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        store.injectFault(fault);
        try t.expectError(error.Injected, store.consume());
        try expectDirectory(fixture, "ledger/attempt-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        try t.expect(!store.consumed);
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
        var retry = try fixture.store("different-attempt-path", sampleScope(.per_boot));
        defer retry.close();
        try t.expectError(error.PathAlreadyExists, retry.consume());
    }
}

test "immutable commit outcomes require durable status and all independent failure lanes clear" {
    for ([_]files.CommitStatus{ .not_committed, .publication_unknown, .visible_not_durable }) |status| {
        if (custody.requireDurable(.{ .status = status })) |_| return error.AcceptedNondurable else |_| {}
    }
    try custody.requireDurable(.{ .status = .durable });
    inline for (.{ "primary", "cleanup", "recording" }) |field| {
        var result: files.CommitResult = .{ .status = .durable };
        @field(result.failures, field) = .{ .stage = .state_record, .category = .local_io };
        try t.expectError(error.CommitFailed, custody.requireDurable(result));
    }
    for ([_]files.TestFault{ .before_file_sync, .before_rename, .publication, .after_rename, .cleanup }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        store.injectFault(.{ .record = fault });
        const expected = switch (fault) {
            .publication => error.PublicationUnknown,
            .after_rename => error.VisibleNotDurable,
            else => error.NotCommitted,
        };
        try t.expectError(expected, store.consume());
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
        try expectDirectory(fixture, "ledger/sha256-" ++ "c" ** 64);
        const path = try fixture.join("ledger/11111111111111111111111111111111-22222222222222222222222222222222");
        defer a.free(path);
        const directory = try files.Directory.open(io, path);
        defer directory.close(io);
        if (fault == .after_rename) try expectFile(directory, "consumed.json", store.scope_bytes.bytes()) else try expectMissing(directory, "consumed.json");
    }
}

test "append-only events preserve hyphenated phase and reserved boots and refuse tamper" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    try store.event(.@"local-admission");
    try store.consume();
    try store.reserveBoot1();
    try store.event(.@"boot1-deploy-intent");
    try expectFile(store.directory, "events.jsonl", "{\"phase\":\"local-admission\",\"reserved_boots\":0}\n{\"phase\":\"boot1-deploy-intent\",\"reserved_boots\":1}\n");
    try write(store.directory, "events.jsonl", "{\"phase\":\"tamper\"}\n");
    try t.expectError(error.FileChanged, store.event(.@"boot1-evidence-complete"));
    try t.expectEqual(.@"boot1-evidence-complete", store.phase);
    try t.expect(!store.healthy);
    inline for (std.meta.fields(custody.Phase)) |field| {
        const bytes = try custody.encode(a, custody.Event{ .phase = @enumFromInt(field.value), .reserved_boots = 2 });
        defer a.free(bytes);
        try t.expect(std.mem.indexOf(u8, bytes, field.name) != null);
        try t.expect(std.mem.indexOfScalar(u8, field.name, '_') == null);
    }
}

test "failed event append or sync cannot authorize effects and retains partial records" {
    for ([_]custody.TestFault{ .event_write, .event_sync }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try store.consume();
        store.injectFault(fault);
        try t.expectError(error.Injected, store.event(.@"group-create-intent"));
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
        const file = try store.directory.openFile(io, "events.jsonl");
        defer file.close(io);
        try t.expect((try files.snapshot(file)).size > 0);
        try t.expectEqual(.@"group-create-intent", store.phase);
    }
}

test "all serial modes retain the complete Boot1 raw bytes and exact capture schema" {
    inline for (.{ custody.SerialMode.per_boot, .cumulative, .azure_cumulative }) |mode| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(mode));
        defer store.close();
        try boot1(&store);
        try expectFile(store.directory, "boot1.log", padded_raw);
        try t.expectEqualStrings(&hex(padded_raw), &store.boot1.?.serial.hex());
        const first = try direct.serialFirst(padded_raw, mode, evidence_input);
        if (mode == .azure_cumulative) try t.expect(!std.mem.eql(u8, &first.sha256, &store.boot1.?.serial.hex()));
        var bytes = try store.directory.readSensitive(io, a, "boot1-capture.json", 65536, null);
        defer bytes.deinit();
        const document = try core.contracts.Document.parse(a, bytes.bytes(), .{});
        defer document.deinit();
        _ = try core.contracts.exactFields(document.value(), &.{
            "schema",             "version",      "boot",                  "poll",                  "serial_mode",            "serial_sha256",
            "cli_wrapper_sha256", "scope_sha256", "vm_id",                 "vm_uuid",               "os_id",                  "os_uuid",
            "data_id",            "data_uuid",    "vm_observation_sha256", "original_boot1_sha256", "boot2_admission_sha256",
        });
        const parsed = try direct.parse(custody.CaptureRecord, a, bytes.bytes());
        defer parsed.deinit();
        const capture = parsed.value;
        try t.expectEqualStrings("uk.hyperv.direct-serial-capture", capture.schema);
        try t.expectEqual(@as(u8, 1), capture.version);
        try t.expectEqual(@as(u8, 1), capture.boot);
        try t.expectEqual(@as(u8, 1), capture.poll);
        try t.expectEqual(mode, capture.serial_mode);
        try t.expectEqualStrings(&hex(padded_raw), capture.serial_sha256);
        try t.expectEqualStrings(&hex("\"synthetic-wrapper-1\""), capture.cli_wrapper_sha256);
        try t.expectEqualStrings(&hex("{\"vm\":\"synthetic-boot1\"}"), capture.vm_observation_sha256);
        try t.expectEqualStrings(&store.scope_pin.hex(), capture.scope_sha256);
        try t.expectEqualStrings(capture.serial_sha256, capture.original_boot1_sha256);
        try t.expectEqualStrings("", capture.boot2_admission_sha256);
        inline for (std.meta.fields(custody.Identities)) |field| try t.expectEqualStrings(@field(ids, field.name), @field(capture, field.name));
    }
}

test "Boot2 admission and capture bind all retained observations and original capture" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.azure_cumulative));
    defer store.close();
    try complete(&store);
    var admission_bytes = try store.directory.readSensitive(io, a, "boot2-admission.json", 65536, null);
    defer admission_bytes.deinit();
    const document = try core.contracts.Document.parse(a, admission_bytes.bytes(), .{});
    defer document.deinit();
    _ = try core.contracts.exactFields(document.value(), &.{
        "schema",             "version",            "reserved_boots",       "scope_sha256",             "original_boot1_sha256", "boot1_capture_sha256",
        "vm_id",              "vm_uuid",            "os_id",                "os_uuid",                  "data_id",               "data_uuid",
        "retained_vm_sha256", "retained_os_sha256", "retained_data_sha256", "deallocated_power_sha256",
    });
    const parsed = try direct.parse(custody.AdmissionRecord, a, admission_bytes.bytes());
    defer parsed.deinit();
    const admission = parsed.value;
    try t.expectEqualStrings("uk.hyperv.direct-boot2-admission", admission.schema);
    try t.expectEqual(@as(u8, 1), admission.version);
    try t.expectEqual(@as(u8, 2), admission.reserved_boots);
    try t.expectEqualStrings(&store.scope_pin.hex(), admission.scope_sha256);
    try t.expectEqualStrings(&store.boot1.?.serial.hex(), admission.original_boot1_sha256);
    try t.expectEqualStrings(&store.boot1.?.capture.hex(), admission.boot1_capture_sha256);
    try t.expectEqualStrings(&hex("{\"vm\":\"retained\"}"), admission.retained_vm_sha256);
    try t.expectEqualStrings(&hex("{\"os\":\"retained\"}"), admission.retained_os_sha256);
    try t.expectEqualStrings(&hex("{\"data\":\"retained\"}"), admission.retained_data_sha256);
    try t.expectEqualStrings(&hex("{\"power\":\"deallocated\"}"), admission.deallocated_power_sha256);
    inline for (std.meta.fields(custody.Identities)) |field| try t.expectEqualStrings(@field(ids, field.name), @field(admission, field.name));
    var capture_bytes = try store.directory.readSensitive(io, a, "boot2-capture.json", 65536, null);
    defer capture_bytes.deinit();
    const capture = try direct.parse(custody.CaptureRecord, a, capture_bytes.bytes());
    defer capture.deinit();
    try t.expectEqualStrings(&store.boot2.?.admission.hex(), capture.value.boot2_admission_sha256);
    try t.expectEqualStrings(&hex(padded_raw), capture.value.original_boot1_sha256);
    try t.expectEqualStrings(&hex(first_raw ++ second_raw), capture.value.serial_sha256);
    try t.expectEqualStrings(&hex("\"synthetic-wrapper-2\""), capture.value.cli_wrapper_sha256);
    try t.expectEqualStrings(&hex("{\"vm\":\"synthetic-boot2\"}"), capture.value.vm_observation_sha256);
    try t.expectEqual(@as(u8, 2), capture.value.boot);
    try t.expectEqual(@as(u8, 2), capture.value.poll);
}

test "admission failure preserves two reserved boots and preceding deallocate phase" {
    for ([_]files.TestFault{ .before_file_sync, .publication, .after_rename }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try boot1(&store);
        try store.event(.@"deallocate-intent");
        const retained = try retainedFiles(&store);
        store.injectFault(.{ .record = fault });
        if (store.admitBoot2(ids, retained)) |_| return error.AdmittedNondurable else |_| {}
        try t.expectEqual(@as(u8, 2), store.reserved_boots);
        try t.expectEqual(.@"deallocate-intent", store.phase);
        try t.expect(store.boot2 == null);
        try t.expectError(error.CustodyPoisoned, store.verifyBoot2Admission());
    }
}

test "capture refuses unvalidated serial substituted sources identities and immutable collisions" {
    for (0..6) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try store.consume();
        try store.reserveBoot1();
        try write(store.directory, "boot1-candidate.log", padded_raw);
        try write(store.directory, "boot1-serial-1.json", "\"wrapper\"");
        try write(store.directory, "boot1-vm.json", "{}");
        const sources = try store.captureSources(1, 1);
        switch (which) {
            0 => try write(store.directory, "boot1-candidate.log", "tamper"),
            1 => try write(store.directory, "boot1-serial-1.json", "\"tamper\""),
            2 => try write(store.directory, "boot1-vm.json", "{\"tamper\":true}"),
            3 => try write(store.directory, "boot1-capture.json", "original"),
            4 => try write(store.directory, "boot1.log", "original"),
            else => {},
        }
        if (store.capture(1, 1, ids, sources, if (which == 5) 1 else 0)) |_| return error.BadCaptureAccepted else |err| {
            try t.expectEqual(switch (which) {
                3, 4 => error.PathAlreadyExists,
                5 => error.SerialNotValidated,
                else => error.FileChanged,
            }, err);
        }
        try t.expect(store.boot1 == null and !store.healthy);
        if (which == 3) try expectFile(store.directory, "boot1-capture.json", "original");
        if (which == 4) try expectFile(store.directory, "boot1.log", "original");
    }
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    try boot1(&store);
    var changed = ids;
    changed.data_uuid = "different";
    try t.expectError(error.IdentityChanged, store.admitBoot2(changed, try retainedFiles(&store)));
    try expectMissing(store.directory, "boot2-admission.json");
}

test "scope raw Boot1 capture admission and retained tamper prevent the Boot2 gate" {
    for ([_][]const u8{
        "scope.json",       "boot1.log",        "boot1-capture.json", "boot2-admission.json",
        "retained-vm.json", "retained-os.json", "retained-data.json", "retained-power.json",
    }) |name| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.cumulative));
        defer store.close();
        try admitted(&store);
        try write(store.directory, name, "tamper");
        try t.expectError(error.FileChanged, store.verifyBoot2Admission());
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
    }
}

test "native failed hashes including plausible final digest never count as cached or fresh" {
    for ([_]custody.TestFault{ .hash_read, .hash_after_digest }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.azure_cumulative));
        defer store.close();
        try admitted(&store);
        try write(store.directory, "boot2-candidate.log", padded_raw);
        const candidate = try store.pinFile("boot2-candidate.log", custody.cli_limit);
        store.injectFault(fault);
        if (store.freshness(candidate)) |_| return error.FailedHashAccepted else |err| try t.expect(err == error.InjectedReadFailure or err == error.InjectedHashFailure);
        try t.expectEqual(@as(u8, 0), store.cached_reads);
        try t.expectError(error.CustodyPoisoned, store.verifyBoot2Admission());
    }
}

test "freshness compares complete raw hashes rather than the Azure unpadded prefix" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.azure_cumulative));
    defer store.close();
    try admitted(&store);
    try write(store.directory, "boot2-candidate.log", padded_raw);
    try t.expectEqual(.cached, try store.freshness(try store.pinFile("boot2-candidate.log", custody.cli_limit)));
    try write(store.directory, "boot2-candidate.log", first_raw);
    try t.expectEqual(.fresh, try store.freshness(try store.pinFile("boot2-candidate.log", custody.cli_limit)));
    try t.expectEqual(@as(u8, 1), store.cached_reads);
    var completion = success;
    completion.primary_exit = 1;
    completion.persistence_evidence_complete = false;
    completion.phase = .@"boot2-start-intent";
    const result = store.finish(completion);
    try t.expectEqualStrings("identical-pinned-boot1", result.outcome.boot2_freshness.cached_reason.?);
    try t.expectEqual(@as(u8, 1), result.exit_code);
}

test "large raw publication is streaming immutable bounded and not a disk or diagnostics path" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    const data = try a.alloc(u8, custody.cli_limit);
    defer a.free(data);
    @memset(data, 0x42);
    try write(store.directory, "cli-raw.json", data);
    const source = try store.pinFile("cli-raw.json", custody.cli_limit);
    const published = try store.publishRaw("cli-raw.json", "raw-evidence.json", source);
    try t.expectEqual(source.sha256, published.sha256);
    try expectFile(store.directory, "raw-evidence.json", data);
    try t.expectError(error.PathAlreadyExists, store.publishRaw("cli-raw.json", "raw-evidence.json", source));
}

test "raw publication failures poison the writer and never establish canonical capture" {
    for ([_]custody.TestFault{ .raw_file_sync, .raw_publication, .raw_directory_sync }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try store.consume();
        try store.reserveBoot1();
        try write(store.directory, "boot1-candidate.log", padded_raw);
        try write(store.directory, "boot1-serial-1.json", "\"wrapper\"");
        try write(store.directory, "boot1-vm.json", "{}");
        const sources = try store.captureSources(1, 1);
        store.injectFault(fault);
        if (store.capture(1, 1, ids, sources, 0)) |_| return error.NondurableCapture else |_| {}
        try t.expect(store.boot1 == null);
        try expectMissing(store.directory, "boot1-capture.json");
        if (fault == .raw_directory_sync) try expectFile(store.directory, "boot1.log", padded_raw) else try expectMissing(store.directory, "boot1.log");
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
    }
}

test "private paths modes symlinks hardlinks and initial validation errors fail closed" {
    for (0..5) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const source = try custody.encode(a, sampleScope(.per_boot));
        defer a.free(source);
        try write(fixture.directory, "source.json", source);
        switch (which) {
            0 => {
                const file = try fixture.directory.openFile(io, "source.json");
                defer file.close(io);
                try file.setPermissions(io, .fromMode(0o644));
            },
            1 => try t.expectEqual(.SUCCESS, linux.errno(linux.linkat(fixture.directory.dir.handle, "source.json", fixture.directory.dir.handle, "hard", 0))),
            2 => {
                try fixture.directory.dir.deleteFile(io, "source.json");
                try t.expectEqual(.SUCCESS, linux.errno(linux.symlinkat("absent", fixture.directory.dir.handle, "source.json")));
            },
            3 => try write(fixture.directory, "source.json", "{\"serial_mode\":\"invalid\"}"),
            else => {
                const bad = try std.mem.replaceOwned(u8, a, source, "\"per_boot\"", "\"invalid\"");
                defer a.free(bad);
                try write(fixture.directory, "source.json", bad);
            },
        }
        if (fixture.fromSource("attempt")) |value| {
            var unexpected = value;
            unexpected.close();
            return error.UnsafeScopeAccepted;
        } else |_| {}
        try expectDirectory(fixture, "attempt");
        try t.expectError(error.PathAlreadyExists, fixture.fromSource("attempt"));
    }
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const unsafe = try fixture.join("unsafe");
    defer a.free(unsafe);
    try fixture.directory.dir.createDir(io, "unsafe", .fromMode(0o700));
    const dir = try files.Directory.open(io, unsafe);
    defer dir.close(io);
    try dir.dir.setPermissions(io, .fromMode(0o777));
    defer dir.dir.setPermissions(io, .fromMode(0o700)) catch {};
    try t.expectError(error.UnsafeFile, fixture.store("unsafe/attempt", sampleScope(.per_boot)));
    try t.expectEqual(.SUCCESS, linux.errno(linux.symlinkat("ledger", fixture.directory.dir.handle, "alias")));
    if (fixture.fromSource("alias/attempt")) |value| {
        var unexpected = value;
        unexpected.close();
        return error.SymlinkParentAccepted;
    } else |_| {}
}

test "input and tool references retain the artifact versus private policy distinction" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try write(fixture.directory, "artifact", "fixture");
    const path = try fixture.join("artifact");
    defer a.free(path);
    const file = try fixture.directory.openFile(io, "artifact");
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o755));
    try t.expectEqual(.SUCCESS, linux.errno(linux.linkat(fixture.directory.dir.handle, "artifact", fixture.directory.dir.handle, "artifact-hard", 0)));
    const item: custody.Artifact = .{ .path = path, .size = 7, .sha256 = "a" ** 64 };
    const artifact = try custody.Reference.artifact(io, item, .artifact);
    const tool = try custody.Reference.tool(io, path);
    try artifact.verify(io);
    try tool.verify(io);
    try t.expectError(error.UnsafeFile, custody.Reference.artifact(io, item, .private));
    try write(fixture.directory, "artifact", "changed");
    try t.expectError(error.ReferenceChanged, artifact.verify(io));
    try t.expectError(error.ReferenceChanged, tool.verify(io));
    try file.setPermissions(io, .fromMode(0o644));
    try t.expectError(error.NotExecutable, custody.Reference.tool(io, path));
}

fn capabilities(store: *custody.Store) !void {
    for ([_][]const u8{ "upload-os", "upload-data" }) |name| {
        try store.directory.dir.createDir(io, name, .fromMode(0o700));
        const dir = try store.directory.dir.openDir(io, name, .{ .follow_symlinks = false });
        defer dir.close(io);
        try write(.{ .dir = dir }, "sas.txt", "sig=SYNTHETIC_ONLY");
    }
    for ([_][]const u8{ "grant-os.json", "grant-os.stderr", "grant-data.json", "grant-data.stderr" }) |name|
        try write(store.directory, name, "SYNTHETIC_ONLY");
}

test "final outcome exact schema requires durable complete evidence and independent cleanup" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    try complete(&store);
    try capabilities(&store);
    const inode = (try files.snapshot(store.writer.file.?)).ino;
    const result = store.finish(success);
    try t.expectEqual(@as(u8, 0), result.exit_code);
    try t.expect(result.outcome.accepted);
    try t.expectEqual(.durable, result.recording.status);
    try t.expect(result.recording_error == null and result.cleanup_error == null);
    try expectFile(store.directory, "outcome.json", "{\"phase\":\"persistence-evidence-complete\",\"primary_exit\":0,\"cleanup_exit\":0,\"reserved_boots\":2," ++
        "\"persistence_evidence_complete\":true,\"owned_group_absent\":true,\"group_creation_attempted\":true," ++
        "\"failure_diagnostics\":{\"attempted\":false,\"exit\":null,\"decoded\":false}," ++
        "\"boot2_freshness\":{\"cached_reads\":0,\"cached_reason\":null},\"accepted\":true}\n");
    try expectMissing(store.directory, "grant-os.json");
    try expectMissing(store.directory, "grant-data.json");
    try expectMissing(store.directory, "grant-os.stderr");
    try expectMissing(store.directory, "grant-data.stderr");
    for ([_][]const u8{ "upload-os", "upload-data" }) |name| {
        const child = try store.directory.dir.openDir(io, name, .{ .follow_symlinks = false });
        defer child.close(io);
        try expectMissing(.{ .dir = child }, "sas.txt");
    }
    store.writer.close(io);
    var next = try store.directory.lock(io);
    defer next.close(io);
    try t.expectEqual(inode, (try files.snapshot(next.file.?)).ino);
    const repeated = store.finish(success);
    try t.expectEqual(@as(u8, 1), repeated.exit_code);
    try t.expectEqual(error.AlreadyFinished, repeated.recording_error.?);
}

test "failed or visible unsynced accepted outcome never returns successful process status" {
    for ([_]files.TestFault{ .before_file_sync, .before_rename, .publication, .after_rename, .cleanup }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try complete(&store);
        store.injectFault(.{ .record = fault });
        const result = store.finish(success);
        try t.expectEqual(@as(u8, 1), result.exit_code);
        try t.expect(result.recording_error != null);
        if (fault == .after_rename) {
            var bytes = try store.directory.readSensitive(io, a, "outcome.json", 65536, null);
            defer bytes.deinit();
            try t.expect(std.mem.indexOf(u8, bytes.bytes(), "\"accepted\":true") != null);
        }
    }
}

test "primary provider validator signal and cleanup exits remain independent" {
    for ([_]u8{ 1, 2, 7, 124, 125, 129, 130, 143 }) |primary| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        var completion = success;
        completion.phase = .@"local-admission";
        completion.primary_exit = primary;
        completion.cleanup_exit = 1;
        completion.persistence_evidence_complete = false;
        completion.owned_group_absent = false;
        completion.group_creation_attempted = false;
        completion.failure_diagnostics = .{ .attempted = true, .exit = 7, .decoded = false };
        const result = store.finish(completion);
        try t.expectEqual(primary, result.exit_code);
        try t.expectEqual(primary, result.outcome.primary_exit);
        try t.expectEqual(@as(u8, 1), result.outcome.cleanup_exit);
        try t.expectEqual(@as(?u8, 7), result.outcome.failure_diagnostics.exit);
        try t.expect(!result.outcome.accepted);
        try t.expectEqual(.durable, result.recording.status);
    }
}

test "final errors absent evidence failed validation collisions and capabilities deny acceptance" {
    for (0..9) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        if (which != 0) try complete(&store);
        var completion = success;
        switch (which) {
            0 => {},
            1 => completion.final_input_exit = 1,
            2 => completion.final_input_exit = null,
            3 => completion.owned_group_absent = false,
            4 => try write(store.directory, "boot2.log", "tamper"),
            5 => try write(store.directory, "outcome.json", "original"),
            6 => {
                try capabilities(&store);
                store.injectFault(.capability_unlink);
            },
            7 => store.injectFault(.capability_sync),
            8 => completion.cleanup_exit = 1,
            else => unreachable,
        }
        const result = store.finish(completion);
        try t.expectEqual(@as(u8, 1), result.exit_code);
        if (which != 5) try t.expect(!result.outcome.accepted);
        if (which == 5) {
            try t.expectEqual(error.PathAlreadyExists, result.recording_error.?);
            try expectFile(store.directory, "outcome.json", "original");
        }
        if (which == 6) {
            try t.expect(result.cleanup_error != null);
            try expectMissing(store.directory, "grant-data.json");
        }
    }
}

test "capability cleanup refuses unsafe links while removing other independent secrets" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    try capabilities(&store);
    try store.directory.dir.deleteFile(io, "grant-os.json");
    try t.expectEqual(.SUCCESS, linux.errno(linux.symlinkat("scope.json", store.directory.dir.handle, "grant-os.json")));
    try t.expectError(error.UnsafeFile, store.removeCapabilities());
    try expectFile(store.directory, "scope.json", store.scope_bytes.bytes());
    try expectMissing(store.directory, "grant-data.json");
    try expectMissing(store.directory, "grant-data.stderr");
    try expectMissing(store.directory, "grant-os.stderr");
}

test "initial directory scope publication and hash failures leave an unusable fresh attempt" {
    for ([_]custody.TestFault{
        .directory_sync,
        .{ .record = .before_file_sync },
        .{ .record = .publication },
        .{ .record = .after_rename },
        .hash_read,
        .hash_after_digest,
    }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        const bytes = try custody.encode(a, sampleScope(.per_boot));
        defer a.free(bytes);
        try write(fixture.directory, "source.json", bytes);
        const source = try fixture.join("source.json");
        defer a.free(source);
        const attempt = try fixture.join("attempt");
        defer a.free(attempt);
        const ledger = try fixture.join("ledger");
        defer a.free(ledger);
        if (custody.Store.createFault(a, io, source, attempt, ledger, fault)) |value| {
            var unexpected = value;
            unexpected.close();
            return error.FailedInitialCustodyAccepted;
        } else |_| {}
        try expectDirectory(fixture, "attempt");
        try t.expectError(error.PathAlreadyExists, fixture.fromSource("attempt"));
    }
}

test "invalid capture polls and boots cannot produce canonical records" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    for ([_][2]u8{ .{ 0, 1 }, .{ 3, 1 }, .{ 1, 0 }, .{ 2, 61 } }) |pair|
        try t.expectError(error.InvalidCaptureIndex, store.captureSources(pair[0], pair[1]));
    try expectMissing(store.directory, "boot1.log");
    try expectMissing(store.directory, "boot1-capture.json");
    try expectMissing(store.directory, "boot2-admission.json");
}

test "raw byte limits and failure-only diagnostics cannot establish evidence" {
    for (0..3) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try write(store.directory, "failure-boot-diagnostics.log", padded_raw);
        const diagnostic = try store.pinFile("failure-boot-diagnostics.log", custody.cli_limit);
        switch (which) {
            0 => try t.expectError(error.InvalidEvidenceName, store.publishRaw("failure-boot-diagnostics.log", "boot1.log", diagnostic)),
            1 => {
                var large = diagnostic;
                large.metadata.size = custody.cli_limit + 1;
                try t.expectError(error.FileTooLarge, store.publishRaw("candidate.log", "boot1.log", large));
            },
            2 => try t.expectError(error.InvalidEvidenceName, store.publishRaw("candidate.log", ".writer.lock", diagnostic)),
            else => unreachable,
        }
        try expectMissing(store.directory, "boot1.log");
        try expectMissing(store.directory, "boot1-capture.json");
    }
}

test "Boot2 identities and duplicate capture or admission cannot be rebound" {
    for (0..3) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try complete(&store);
        const sources = try store.captureSources(2, 2);
        var changed = ids;
        changed.vm_uuid = "changed-vm";
        switch (which) {
            0 => try t.expectError(error.IdentityChanged, store.capture(2, 2, changed, sources, 0)),
            1 => try t.expectError(error.PathAlreadyExists, store.capture(2, 2, ids, sources, 0)),
            2 => try t.expectError(error.BootAlreadyReserved, store.admitBoot2(ids, try store.retainedSnapshots())),
            else => unreachable,
        }
        try t.expect(!store.healthy);
        try expectFile(store.directory, "boot1.log", padded_raw);
    }
}

test "full input references and execution tools detect size metadata and permission drift" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try write(fixture.directory, "small-input", "fixture");
    try write(fixture.directory, "tool", "fixture-tool");
    const tool_file = try fixture.directory.openFile(io, "tool");
    defer tool_file.close(io);
    try tool_file.setPermissions(io, .fromMode(0o700));
    const input_path = try fixture.join("small-input");
    defer a.free(input_path);
    const tool_path = try fixture.join("tool");
    defer a.free(tool_path);
    var scope = sampleScope(.per_boot);
    inline for (.{ "os_vhd", "seed_raw", "seed_vhd", "manifest", "config" }) |field|
        @field(scope, field) = .{ .path = input_path, .size = 7, .sha256 = "a" ** 64 };
    const references = try custody.References.capture(io, scope, tool_path, tool_path, tool_path);
    try references.verify(io);
    try write(fixture.directory, "small-input", "changed-size");
    try t.expectError(error.ReferenceChanged, references.verify(io));
    try t.expectError(error.ArtifactChanged, custody.References.capture(io, scope, tool_path, tool_path, tool_path));
}

test "private ledger and attempt directory modes are rechecked before mutations" {
    for (0..2) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        const directory = if (which == 0) store.ledger else store.directory;
        try directory.dir.setPermissions(io, .fromMode(0o750));
        defer directory.dir.setPermissions(io, .fromMode(0o700)) catch {};
        try t.expectError(error.UnsafeFile, store.consume());
        try t.expect(!store.healthy and !store.consumed);
    }
}

test "final hash errors and a primary failure survive outcome recording failures" {
    for (0..2) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        var completion = success;
        completion.primary_exit = 143;
        completion.persistence_evidence_complete = false;
        store.injectFault(if (which == 0) .hash_after_digest else .{ .record = .after_rename });
        const result = store.finish(completion);
        try t.expectEqual(@as(u8, 143), result.exit_code);
        try t.expect(result.recording_error != null);
        try t.expect(!result.outcome.accepted);
    }
}

fn failedCompletion(phase: custody.Phase, primary: u8) custody.Completion {
    var completion = success;
    completion.phase = phase;
    completion.primary_exit = primary;
    completion.persistence_evidence_complete = false;
    completion.failure_diagnostics = .{ .attempted = true, .exit = 0, .decoded = true };
    return completion;
}

fn expectIndependentCleanup(result: custody.FinalResult, primary: u8) !void {
    try t.expectEqual(primary, result.exit_code);
    try t.expectEqual(primary, result.outcome.primary_exit);
    try t.expectEqual(@as(u8, 0), result.outcome.cleanup_exit);
    try t.expect(!result.outcome.accepted);
    try t.expect(result.outcome.owned_group_absent);
    try t.expectEqual(.durable, result.recording.status);
    try t.expect(result.recording_error == null and result.cleanup_error == null);
}

test "primary raw capture admission scope and hash refusals preserve independently successful cleanup" {
    inline for (.{ custody.SerialMode.per_boot, .cumulative, .azure_cumulative }) |mode| {
        for (0..6) |which| {
            var fixture = try Fixture.init();
            defer fixture.deinit();
            var store = try fixture.store("attempt", sampleScope(mode));
            defer store.close();
            try admitted(&store);
            try store.event(.@"boot2-start-intent");
            const prior_phase = store.phase;
            const lock_inode = (try files.snapshot(store.writer.file.?)).ino;
            switch (which) {
                0 => try write(store.directory, "boot1.log", "changed during cache wait\n"),
                1, 2 => {
                    const name = if (which == 1) "boot1-capture.json" else "boot2-admission.json";
                    var original = try store.directory.readSensitive(io, a, name, 65536, null);
                    defer original.deinit();
                    const changed = try std.fmt.allocPrint(a, "{s} \n", .{original.bytes()});
                    defer a.free(changed);
                    try write(store.directory, name, changed);
                },
                3 => {
                    const changed = try std.mem.replaceOwned(u8, a, store.scope_bytes.bytes(), "\"prefix\":\"fixture\"", "\"prefix\":\"changed\"");
                    defer a.free(changed);
                    try write(store.directory, "scope.json", changed);
                },
                4 => store.injectFault(.hash_read),
                5 => store.injectFault(.hash_after_digest),
                else => unreachable,
            }
            try t.expectError(switch (which) {
                4 => error.InjectedReadFailure,
                5 => error.InjectedHashFailure,
                else => error.FileChanged,
            }, store.verifyBoot2Admission());
            try t.expect(!store.healthy);
            try t.expect(store.recording_failure == null);
            try store.event(.@"cleanup-intent");
            try store.event(.@"cleanup-delete-intent");
            // A cleanup append is not a reset or authorization for any primary phase.
            inline for (std.meta.fields(custody.Phase)) |field| {
                const phase: custody.Phase = @enumFromInt(field.value);
                if (phase != .@"cleanup-intent" and phase != .@"cleanup-delete-intent")
                    try t.expectError(error.CustodyPoisoned, store.event(phase));
            }
            try t.expectError(error.CustodyPoisoned, store.requireConsumed());
            try t.expectError(error.CustodyPoisoned, store.verifyBoot2Admission());
            try t.expectError(error.CustodyPoisoned, store.admitBoot2(ids, store.boot2.?.retained));
            try t.expectError(error.CustodyPoisoned, store.capture(2, 1, ids, undefined, 0));
            try t.expectEqual(@as(u8, 2), store.reserved_boots);
            try t.expectEqualStrings("fixture", store.scope.value.prefix);
            try t.expectEqualStrings(sampleScope(mode).attempt_id, store.scope.value.attempt_id);
            inline for (std.meta.fields(custody.Identities)) |field|
                try t.expectEqualStrings(@field(ids, field.name), @field(store.identities.?, field.name));
            const primary: u8 = if (which >= 4) 17 else 1;
            const result = store.finish(failedCompletion(prior_phase, primary));
            try expectIndependentCleanup(result, primary);
            try t.expectEqual(prior_phase, result.outcome.phase);
            try t.expectEqual(lock_inode, (try files.snapshot(store.writer.file.?)).ino);
            var bytes = try store.directory.readSensitive(io, a, "outcome.json", 65536, null);
            defer bytes.deinit();
            const parsed = try direct.parse(custody.Outcome, a, bytes.bytes());
            defer parsed.deinit();
            try t.expectEqual(@as(u8, 0), parsed.value.cleanup_exit);
            try t.expectEqual(primary, parsed.value.primary_exit);
            try t.expectEqual(@as(u8, 2), parsed.value.reserved_boots);
            try t.expectEqual(.@"boot2-start-intent", parsed.value.phase);
            try t.expect(!parsed.value.accepted and !parsed.value.persistence_evidence_complete);
        }
    }
}

test "Boot1 tamper before admission reserves no start authority but does not poison cleanup events" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.azure_cumulative));
    defer store.close();
    try boot1(&store);
    try store.event(.@"deallocate-intent");
    const retained = try retainedFiles(&store);
    try write(store.directory, "boot1.log", "changed");
    try t.expectError(error.FileChanged, store.admitBoot2(ids, retained));
    try t.expectEqual(@as(u8, 2), store.reserved_boots);
    try t.expect(store.boot2 == null);
    try expectMissing(store.directory, "boot2-admission.json");
    try store.event(.@"cleanup-intent");
    try store.event(.@"cleanup-delete-intent");
    try t.expectError(error.CustodyPoisoned, store.event(.@"boot2-start-intent"));
    try expectIndependentCleanup(store.finish(failedCompletion(.@"deallocate-intent", 1)), 1);
}

test "writer and event safety are independently revalidated after primary evidence refusal" {
    for (0..8) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try admitted(&store);
        try write(store.directory, "boot1.log", "tamper");
        try t.expectError(error.FileChanged, store.verifyBoot2Admission());
        switch (which) {
            0 => try write(store.directory, "events.jsonl", "untrusted event\n"),
            1 => {
                try store.directory.dir.deleteFile(io, "events.jsonl");
                try t.expectEqual(.SUCCESS, linux.errno(linux.symlinkat("scope.json", store.directory.dir.handle, "events.jsonl")));
            },
            2 => try store.directory.dir.setPermissions(io, .fromMode(0o750)),
            3 => try store.writer.file.?.setPermissions(io, .fromMode(0o644)),
            4 => try t.expectEqual(.SUCCESS, linux.errno(linux.linkat(store.directory.dir.handle, ".writer.lock", store.directory.dir.handle, "lock-alias", 0))),
            5 => {
                try t.expectEqual(.SUCCESS, linux.errno(linux.renameat(store.directory.dir.handle, ".writer.lock", store.directory.dir.handle, "retired-lock")));
                try write(store.directory, ".writer.lock", "");
            },
            6 => store.writer.close(io),
            7 => try store.directory.dir.deleteFile(io, ".writer.lock"),
            else => unreachable,
        }
        defer store.directory.dir.setPermissions(io, .fromMode(0o700)) catch {};
        if (store.event(.@"cleanup-intent")) |_| return error.UnsafeCleanupAppend else |_| {}
        try t.expect(store.recording_failure != null);
        const result = store.finish(failedCompletion(.@"deallocate-intent", 17));
        try t.expectEqual(@as(u8, 17), result.exit_code);
        try t.expectEqual(@as(u8, 17), result.outcome.primary_exit);
        try t.expectEqual(@as(u8, 1), result.outcome.cleanup_exit);
        try t.expect(result.recording_error != null);
        try t.expect(!result.outcome.accepted);
        if (which == 5) try t.expectEqual(error.WriterLockChanged, result.recording_error.?);
        if (which <= 1) try t.expectEqual(.durable, result.recording.status) else try t.expectEqual(.not_committed, result.recording.status);
    }
}

test "cleanup event failures and undetected event drift cannot disappear into a primary failure" {
    for (0..3) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try admitted(&store);
        try write(store.directory, "boot1.log", "tamper");
        try t.expectError(error.FileChanged, store.verifyBoot2Admission());
        if (which == 2) {
            try write(store.directory, "events.jsonl", "tamper");
        } else {
            store.injectFault(if (which == 0) .event_write else .event_sync);
            try t.expectError(error.Injected, store.event(.@"cleanup-intent"));
            if (store.event(.@"cleanup-delete-intent")) |_| return error.ResumedPartialEvent else |_| {}
        }
        const result = store.finish(failedCompletion(.@"deallocate-intent", 1));
        try t.expectEqual(@as(u8, 1), result.exit_code);
        try t.expectEqual(@as(u8, 1), result.outcome.cleanup_exit);
        try t.expect(result.recording_error != null);
        try t.expectEqual(.durable, result.recording.status);
        try t.expect(!result.outcome.accepted);
    }
}

test "reservation and admission recording uncertainty remains independent nonzero custody failure" {
    for ([_]custody.TestFault{
        .directory_sync,
        .after_first_reservation,
        .after_identity_reservation,
        .ledger_sync,
        .{ .record = .before_file_sync },
        .{ .record = .publication },
        .{ .record = .after_rename },
    }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        if (fault == .record) {
            try boot1(&store);
            const retained = try retainedFiles(&store);
            store.injectFault(fault);
            if (store.admitBoot2(ids, retained)) |_| return error.AcceptedUncertainAdmission else |_| {}
        } else {
            store.injectFault(fault);
            if (store.consume()) |_| return error.AcceptedUncertainReservation else |_| {}
        }
        try t.expect(store.recording_failure != null);
        // An intact event writer can record cleanup, without forgetting the failure.
        try store.event(.@"cleanup-intent");
        try store.event(.@"cleanup-delete-intent");
        try t.expectError(error.CustodyPoisoned, store.requireConsumed());
        const result = store.finish(failedCompletion(.@"deallocate-intent", 17));
        try t.expectEqual(@as(u8, 17), result.exit_code);
        try t.expectEqual(@as(u8, 1), result.outcome.cleanup_exit);
        try t.expect(result.recording_error != null);
        try t.expectEqual(.durable, result.recording.status);
    }
}

test "raw publication failures remain recording failures even when event cleanup is safe" {
    for ([_]custody.TestFault{ .raw_file_sync, .raw_publication, .raw_directory_sync }) |fault| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try store.consume();
        try write(store.directory, "candidate.log", padded_raw);
        const candidate = try store.pinFile("candidate.log", custody.cli_limit);
        store.injectFault(fault);
        if (store.publishRaw("candidate.log", "boot1.log", candidate)) |_| return error.AcceptedUncertainPublication else |_| {}
        try store.event(.@"cleanup-intent");
        const result = store.finish(failedCompletion(.@"boot1-deploy-intent", 1));
        try t.expectEqual(@as(u8, 1), result.outcome.primary_exit);
        try t.expectEqual(@as(u8, 1), result.outcome.cleanup_exit);
        try t.expect(result.recording_error != null and !result.outcome.accepted);
    }
}

test "capability final input and outcome failures are not masked by primary tamper" {
    for (0..6) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try admitted(&store);
        try write(store.directory, "boot1.log", "tamper");
        try t.expectError(error.FileChanged, store.verifyBoot2Admission());
        try store.event(.@"cleanup-intent");
        try store.event(.@"cleanup-delete-intent");
        var completion = failedCompletion(.@"deallocate-intent", 17);
        switch (which) {
            0, 1 => {
                try capabilities(&store);
                store.injectFault(if (which == 0) .capability_unlink else .capability_sync);
                try t.expectError(error.Injected, store.removeCapabilities());
                try store.removeCapabilities();
            },
            2 => completion.final_input_exit = 1,
            3 => completion.final_input_exit = null,
            4 => store.injectFault(.{ .record = .publication }),
            5 => store.injectFault(.{ .record = .after_rename }),
            else => unreachable,
        }
        const result = store.finish(completion);
        try t.expectEqual(@as(u8, 17), result.exit_code);
        try t.expectEqual(@as(u8, 17), result.outcome.primary_exit);
        try t.expect(!result.outcome.accepted);
        if (which < 4) {
            try t.expectEqual(@as(u8, 1), result.outcome.cleanup_exit);
            try t.expectEqual(.durable, result.recording.status);
            if (which < 2) try t.expect(result.cleanup_error != null);
        } else {
            try t.expect(result.recording_error != null);
            try t.expectEqual(if (which == 4) files.CommitStatus.publication_unknown else .visible_not_durable, result.recording.status);
        }
    }
}

test "a successful primary status cannot accept uncertain evidence even with clean independent cleanup" {
    for (0..2) |which| {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var store = try fixture.store("attempt", sampleScope(.per_boot));
        defer store.close();
        try complete(&store);
        try write(store.directory, "boot1.log", "tamper");
        if (which == 0) try t.expectError(error.FileChanged, store.verifyBoot1());
        try store.event(.@"cleanup-intent");
        try store.event(.@"cleanup-delete-intent");
        const result = store.finish(success);
        try t.expectEqual(@as(u8, 0), result.outcome.primary_exit);
        try t.expectEqual(@as(u8, 0), result.outcome.cleanup_exit);
        try t.expectEqual(@as(u8, 1), result.exit_code);
        try t.expect(!result.outcome.accepted);
        try t.expect(result.evidence_error != null);
        try t.expect(result.recording_error == null and result.cleanup_error == null);
        try t.expectEqual(.durable, result.recording.status);
    }
}

test "healthy primary completion still accepts after independently recorded cleanup intents" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store = try fixture.store("attempt", sampleScope(.per_boot));
    defer store.close();
    try complete(&store);
    try store.event(.@"cleanup-intent");
    try store.event(.@"cleanup-delete-intent");
    const result = store.finish(success);
    try t.expectEqual(@as(u8, 0), result.exit_code);
    try t.expect(result.outcome.accepted);
    try t.expect(result.evidence_error == null and result.recording_error == null and result.cleanup_error == null);
}
