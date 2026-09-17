const std = @import("std");
const p = @import("root.zig");
const core = @import("hyperv_core");
const f = @import("fixture_support.zig");
const options = @import("test_options");
comptime {
    if (@hasDecl(options, "fixture_build_evidence") and options.fixture_build_evidence)
        @import("fixture_parent_metadata.zig").exportSection();
}
const timing = @import("fixture_timing.zig");
const t = std.testing;
const a = t.allocator;
fn fixture() !f.Fixture {
    return f.Fixture.init(a, t.io, options.test_root orelse return error.MissingFixtureRoot);
}
test "production receipt and provider integration remains closed" {
    try std.testing.expectError(error.PreparationAndCompletedPreflightBindingsUnavailable, p.contract.requireProductionBindings());
}
test "concrete native adapter issues bounded private SAS denial probes" {
    try @import("native_fixture.zig").probes(a, t.io, options.test_root orelse return error.MissingFixtureRoot);
}
test "native disk readback requires exact VHD logical bytes Gen2 role and original attachment" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const job = try f.makeJob(alloc, .deploy_boot1, (try core.process.Deadline.afterMilliseconds(1000)).expires_ns);
    const azure = @import("hyperv_azure");
    const expected_vm = try (azure.scope.Ref{ .kind = .vm, .name = "synthetic-vm" }).path(alloc, job.input.authority);
    for ([_]bool{ true, false }) |os| {
        const logical = if (os) job.input.guest.size - 512 else job.input.data.size - 512;
        const raw = try std.fmt.allocPrint(alloc, "{{\"managedBy\":null,\"properties\":{{\"diskSizeBytes\":{d}{s}}}}}", .{ logical, if (os) @as([]const u8, ",\"osType\":\"Linux\",\"hyperVGeneration\":\"V2\"") else "" });
        const json = try std.json.parseFromSliceLeaky(std.json.Value, alloc, raw, .{ .allocate = .alloc_always, .parse_numbers = false });
        try p.native.requireDiskReadback(alloc, job, os, json, .detached);
        try t.expectError(error.InvalidAttachment, p.native.requireDiskReadback(alloc, job, os, json, .attached));
        var attached = json;
        try attached.object.put(alloc, "managedBy", .{ .string = expected_vm });
        try p.native.requireDiskReadback(alloc, job, os, attached, .attached);
        try p.native.requireDiskReadback(alloc, job, os, attached, .cleanup);
        try attached.object.put(alloc, "managedBy", .{ .string = "/wrong-original-vm" });
        if (p.native.requireDiskReadback(alloc, job, os, attached, .cleanup)) |_| return error.AcceptedWrongAttachment else |_| {}
        try attached.object.put(alloc, "managedBy", .null);
        const props = attached.object.getPtr("properties").?;
        try props.object.put(alloc, "diskSizeBytes", .{ .number_string = try std.fmt.allocPrint(alloc, "{d}", .{logical + 512}) });
        try t.expectError(error.WrongGeometry, p.native.requireDiskReadback(alloc, job, os, attached, .detached));
        try props.object.put(alloc, "diskSizeBytes", .{ .number_string = try std.fmt.allocPrint(alloc, "{d}", .{logical}) });
        if (os) try props.object.put(alloc, "hyperVGeneration", .{ .string = "V1" }) else try props.object.put(alloc, "osType", .{ .string = "Linux" });
        try t.expectError(error.InvalidDiskRole, p.native.requireDiskReadback(alloc, job, os, attached, .detached));
    }
}
test "native persistence declarations compile" {
    std.testing.refAllDecls(p.native.Context);
    std.testing.refAllDecls(p.native.Session);
    std.testing.refAllDecls(p.engine);
    std.testing.refAllDecls(p.worker.Supervisor);
}

test "storage identity is independent of cloud ownership UUID without weakening authority binding" {
    const input = f.input();
    try input.validate();
    const owner = try core.contracts.parseUuid(&input.authority.owner_run);
    try t.expect(!std.mem.eql(u8, &std.fmt.bytesToHex(owner, .lower), &input.run_id));
    const bytes = try p.local.encode(a, input);
    defer a.free(bytes);
    const parsed = try p.local.Document(p.contract.Contract).load(a, bytes);
    defer parsed.deinit();
    try parsed.value.validate();
    try t.expectEqual(input.run_id, parsed.value.run_id);
    try t.expectEqual(input.authority.owner_run, parsed.value.authority.owner_run);
    var changed = input;
    changed.cleanup_authority.owner_run = "99999999-9999-4999-8999-999999999999".*;
    try t.expectError(error.AuthorityMismatch, changed.validate());
    changed = input;
    changed.run_id = [_]u8{'0'} ** 32;
    try t.expectError(error.NilIdentity, changed.validate());
    changed = input;
    changed.run_id[0] = 'A';
    try t.expectError(error.InvalidHex, changed.validate());
    try t.expectError(error.PreparationAndCompletedPreflightBindingsUnavailable, p.contract.requireProductionBindings());
}

test "strict canonical input preserves original identities geometry and separate ledgers" {
    const input = f.input();
    try input.validate();
    const bytes = try p.local.encode(a, input);
    defer a.free(bytes);
    const document = try p.local.Document(p.contract.Contract).load(a, bytes);
    defer document.deinit();
    try document.value.validate();
    try t.expectEqualSlices(u8, &input.run_id, &document.value.run_id);
    try t.expectEqual(@as(u64, 4294967808), document.value.data.size);
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "\"lun\":7", .after = "\"lun\":8" },
        .{ .before = "\"sectors\":8388608", .after = "\"sectors\":8388607" },
        .{ .before = "\"sector_size\":512", .after = "\"sector_size\":4096" },
        .{ .before = "\"sectors\":8388608", .after = "\"sectors\":true" },
        .{ .before = "\"sectors\":8388608", .after = "\"sectors\":8.388608e6" },
        .{ .before = "\"schema_version\":1", .after = "\"schema_version\":4" },
        .{ .before = "\"schema_version\":1", .after = "\"schema_version\":1,\"schema_version\":1" },
        .{ .before = "\"schema_version\":1", .after = "\"schema_version\":1,\"completed\":true" },
        .{ .before = "\"northeurope\"", .after = "\"westeurope\"" },
    }) |mutation| {
        const bad = try std.mem.replaceOwned(u8, a, bytes, mutation.before, mutation.after);
        defer a.free(bad);
        try rejectedInput(bad);
    }
    var changed = input;
    changed.control_bytes = p.contract.control_limit + 1;
    try t.expectError(error.InvalidLedger, changed.validate());
    changed = input;
    changed.stage_bytes = p.contract.stage_limit + 1;
    try t.expectError(error.InvalidLedger, changed.validate());
    changed = input;
    changed.data.size += 512;
    try t.expectError(error.InvalidGeometry, changed.validate());
    changed = input;
    changed.cleanup_seconds = 1801;
    try t.expectError(error.InvalidBudget, changed.validate());
    changed = input;
    changed.guest.sha256 = [_]u8{'0'} ** 64;
    try t.expectError(error.NilIdentity, changed.validate());
    changed = input;
    changed.disk_id = changed.run_id;
    try t.expectError(error.IdentityCollision, changed.validate());
    changed = input;
    changed.guest.path = "/synthetic?sig=forbidden";
    try t.expectError(error.InvalidFileBinding, changed.validate());
}
fn rejectedInput(bytes: []const u8) !void {
    const parsed = p.local.Document(p.contract.Contract).load(a, bytes) catch return;
    defer parsed.deinit();
    parsed.value.validate() catch return;
    return error.AcceptedInvalidInput;
}

test "actual C serial order identity IO counts and unchanged complete prefix" {
    const first = try f.segment(a, 1, 5);
    defer a.free(first);
    const boot1 = try p.evidence.parse(first, 1, f.input(), null);
    const full = try f.serial(a, .serial_boot2, .good);
    defer a.free(full);
    const suffix = try p.evidence.boot2Suffix(full, boot1);
    const boot2 = try p.evidence.parse(suffix, 2, f.input(), boot1);
    try t.expectEqual(@as(u8, 0), boot2.writes);
    try t.expectEqual(@as(u8, 0), boot2.flushes);
    try t.expectEqualDeep(boot1.identity, boot2.identity);
    try t.expectError(error.EvidenceIncomplete, p.evidence.parse(first[0 .. first.len - 1], 1, f.input(), null));
    try t.expectError(error.InvalidEvidenceOrder, p.evidence.parse("HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n", 1, f.input(), null));
    for ([_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "address=0:0:7", .to = "address=0:0:8" },
        .{ .from = "sectors=8388608", .to = "sectors=8388607" },
        .{ .from = ":0:3:7:8388608:512:", .to = ":0:3:8:8388608:512:" },
        .{ .from = ":5:3:receipt-verified", .to = ":5:2:receipt-verified" },
        .{ .from = "receipt-verified", .to = "receipt-written" },
        .{ .from = "main returned 0", .to = "main returned 2" },
        .{ .from = "BOOT1_WRITE", .to = "BOOT2_READ" },
        .{ .from = ":4:1:3:0:11223344", .to = ":65:1:3:0:11223344" },
    }) |mutation| {
        const bad = try std.mem.replaceOwned(u8, a, first, mutation.from, mutation.to);
        defer a.free(bad);
        if (p.evidence.parse(bad, 1, f.input(), null)) |_| return error.AcceptedInvalidEvidence else |_| {}
    }
    const twice = try std.mem.concat(a, u8, &.{ first, first });
    defer a.free(twice);
    try t.expectError(error.InvalidEvidenceOrder, p.evidence.parse(twice, 1, f.input(), null));
    const mutated = try f.serial(a, .serial_boot2, .prefix_changed);
    defer a.free(mutated);
    try t.expectError(error.SerialPrefixChanged, p.evidence.boot2Suffix(mutated, boot1));
    const writes = try f.segment(a, 2, 1);
    defer a.free(writes);
    try t.expectError(error.WrongIoLedger, p.evidence.parse(writes, 2, f.input(), boot1));
    const flush = try std.mem.replaceOwned(u8, a, suffix, ":0:0:receipt-verified", ":0:1:receipt-verified");
    defer a.free(flush);
    try t.expectError(error.WrongIoLedger, p.evidence.parse(flush, 2, f.input(), boot1));
    const wrong_target = try std.mem.replaceOwned(u8, a, suffix, ":0:3:7:", ":0:4:7:");
    defer a.free(wrong_target);
    try t.expectError(error.IdentityDrift, p.evidence.parse(wrong_target, 2, f.input(), boot1));
    const wrong_vpd = try std.mem.replaceOwned(u8, a, suffix, "11223344", "11223345");
    defer a.free(wrong_vpd);
    try t.expectError(error.IdentityDrift, p.evidence.parse(wrong_vpd, 2, f.input(), boot1));
    const decorated = try std.fmt.allocPrint(a, "\x1b[32m\x00{s}\x1b[0m\n", .{first});
    defer a.free(decorated);
    _ = try p.evidence.parse(decorated, 1, f.input(), null);
    const excessive = try std.mem.concat(a, u8, &.{ "x" ** 8193, "\n", first });
    defer a.free(excessive);
    try t.expectError(error.SerialLineTooLong, p.evidence.parse(excessive, 1, f.input(), null));
    const candidates = try std.mem.replaceOwned(u8, a, first, "HYPERV_PERSISTENCE SELECT", "HYPERV_PERSISTENCE CANDIDATE_REJECT PASS reason=boot-signature id=0\n" ** 17 ++ "HYPERV_PERSISTENCE SELECT");
    defer a.free(candidates);
    try t.expectError(error.InvalidCandidateOrder, p.evidence.parse(candidates, 1, f.input(), null));
}

test "ukboot terminal supports ukprint feature combinations and exact raw boot prefix" {
    const first = try f.segment(a, 1, 5);
    defer a.free(first);
    const second = try f.segment(a, 2, 0);
    defer a.free(second);
    const bare = try std.mem.replaceOwned(u8, a, first, f.terminal, "main returned 0");
    defer a.free(bare);
    _ = try p.evidence.parse(bare, 1, f.input(), null);
    for ([_][]const u8{ "", "[    0.000000] ", "[123456.999999] " }) |timestamp| {
        for ([_][]const u8{ "", "<main> ", "<init> ", "<<n/a>> ", "<0xffff800012345678> " }) |thread| {
            for ([_][]const u8{ "", "{r:0xffff800000012345,f:0} ", "{r:0,f:0x1234} " }) |caller| {
                for ([_][]const u8{ "", "<boot.c @    1> ", "<boot.c @  544> ", "<boot.c @ 9999> ", "<boot.c @ 10000> " }) |source| {
                    const terminal = try std.fmt.allocPrint(a, "{s}Info: {s}{s}[libukboot] {s}main returned 0", .{ timestamp, thread, caller, source });
                    defer a.free(terminal);
                    const bytes = try std.mem.replaceOwned(u8, a, first, f.terminal, terminal);
                    defer a.free(bytes);
                    const evidence = try p.evidence.parse(bytes, 1, f.input(), null);
                    try t.expectEqual(bytes.len, evidence.bytes);
                    try t.expectEqual(p.local.hash(bytes), evidence.sha256);
                    const full = try std.mem.concat(a, u8, &.{ bytes, second });
                    defer a.free(full);
                    const suffix = try p.evidence.boot2Suffix(full, evidence);
                    try t.expectEqualStrings(second, suffix);
                    _ = try p.evidence.parse(suffix, 2, f.input(), evidence);
                }
            }
        }
    }
    // console.c writes LVLC_RESET with sizeof(), including NUL, before and
    // after the body. Its configured CR insertion precedes the LF.
    const colored = "\x1b[0m\x1b[32m[    0.123456] " ++
        "\x1b[0m\x1b[1m\x1b[32mInfo:\x1b[0m " ++
        "\x1b[0m\x1b[34m<main> \x1b[0m\x1b[31m{r:0x1234,f:0} " ++
        "\x1b[0m\x1b[33m[libukboot] \x1b[0m\x1b[36m<boot.c @  544> " ++
        "\x1b[0m\x00main returned 0\r\n\x1b[0m\x00";
    for ([_][]const u8{ colored, "[    0.123456] Info: [libukboot] <boot.c @  544> \x00main returned 0\r\n\x00" }) |terminal| {
        const bytes = try std.mem.replaceOwned(u8, a, first, f.terminal ++ "\n", terminal);
        defer a.free(bytes);
        const evidence = try p.evidence.parse(bytes, 1, f.input(), null);
        try t.expectEqual(bytes.len, evidence.bytes);
        try t.expectEqual(p.local.hash(bytes), evidence.sha256);
        const full = try std.mem.concat(a, u8, &.{ bytes, second });
        defer a.free(full);
        _ = try p.evidence.parse(try p.evidence.boot2Suffix(full, evidence), 2, f.input(), evidence);
        full[bytes.len - 1] = 1;
        try t.expectError(error.SerialPrefixChanged, p.evidence.boot2Suffix(full, evidence));
        const truncated = try std.mem.replaceOwned(u8, a, bytes, "\r\n", "\r");
        defer a.free(truncated);
        try t.expectError(error.EvidenceIncomplete, p.evidence.parse(truncated, 1, f.input(), null));
    }
}

test "ukboot terminal refuses nonzero duplicate reordered spoofed and truncated logs" {
    const first = try f.segment(a, 1, 5);
    defer a.free(first);
    for ([_][]const u8{ "main returned -1", "main returned 1", "main returned 00", "main returned +0", "main returned 0 extra" }) |body| {
        const bad = try std.mem.replaceOwned(u8, a, first, "main returned 0", body);
        defer a.free(bad);
        try t.expectError(error.GuestFailure, p.evidence.parse(bad, 1, f.input(), null));
    }
    const duplicate = try std.mem.concat(a, u8, &.{ first, f.terminal, "\n" });
    defer a.free(duplicate);
    try t.expectError(error.InvalidEvidenceOrder, p.evidence.parse(duplicate, 1, f.input(), null));
    const early = try std.mem.concat(a, u8, &.{ f.terminal, "\n", first });
    defer a.free(early);
    try t.expectError(error.InvalidEvidenceOrder, p.evidence.parse(early, 1, f.input(), null));
    for ([_][]const u8{
        "spoof " ++ f.terminal,
        "Info: [libukboot] prefix main returned 0",
        "Info: [libother] <boot.c @  544> main returned 0",
        "Info: [libukboot] <other.c @  544> main returned 0",
        "Info: <boot.c @  544> main returned 0",
        "Info: main returned 0",
        "ERR:  [libukboot] <boot.c @  544> main returned 0",
        "[0.123456] Info: [libukboot] main returned 0",
        "[00000.123456] Info: [libukboot] main returned 0",
        "[    0.12345] Info: [libukboot] main returned 0",
        "[    0.1234567] Info: [libukboot] main returned 0",
        "[    0.12345x] Info: [libukboot] main returned 0",
        "[18446744073709551616.123456] Info: [libukboot] main returned 0",
        "Info: [libukboot] <boot.c @ 544> main returned 0",
        "Info: [libukboot] <boot.c @ 0544> main returned 0",
        "Info: [libukboot] <boot.c @    0> main returned 0",
        "Info: [libukboot] <boot.c @ 100000> main returned 0",
        "Info: [libukboot] <boot.c @  54x> main returned 0",
        "Info: <spoof> [libukboot] main returned 0",
        "Info: <main> <main> [libukboot] main returned 0",
        "Info: {r:0x1,f:0} <main> [libukboot] main returned 0",
        "Info: {r:1,f:0} [libukboot] main returned 0",
        "Info: {r:0x01,f:0} [libukboot] main returned 0",
        "Info: {r:0x10000000000000000,f:0} [libukboot] main returned 0",
        "Info: {r:0x1,f:0,g:0} [libukboot] main returned 0",
        "Info: <" ++ "x" ** 256 ++ "> [libukboot] main returned 0",
    }) |terminal| {
        const bad = try std.mem.replaceOwned(u8, a, first, f.terminal, terminal);
        defer a.free(bad);
        try t.expectError(error.EvidenceIncomplete, p.evidence.parse(bad, 1, f.input(), null));
    }
    for ([_][]const u8{ "\x1b[0", "\x1b[", "\x1b[31m", "\x00partial", " ", "\r" }) |tail| {
        const truncated = try std.mem.concat(a, u8, &.{ first, tail });
        defer a.free(truncated);
        try t.expectError(error.EvidenceIncomplete, p.evidence.parse(truncated, 1, f.input(), null));
    }
    const prefixed_protocol = try std.mem.replaceOwned(u8, a, first, "HYPERV_PERSISTENCE FINAL PASS rc=0", "Info: [libukboot] HYPERV_PERSISTENCE FINAL PASS rc=0");
    defer a.free(prefixed_protocol);
    try t.expectError(error.InvalidEvidenceOrder, p.evidence.parse(prefixed_protocol, 1, f.input(), null));
    const unrelated = try std.mem.concat(a, u8, &.{ "[    0.123455] Info: [libother] unrelated status\n", first });
    defer a.free(unrelated);
    _ = try p.evidence.parse(unrelated, 1, f.input(), null);
}

test "synthetic admitted model executes exactly deployment boot one and sole restart" {
    var work = try fixture();
    defer work.deinit();
    const binding = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a };
    const state = try p.engine.execute(a, t.io, work.directory, model.options(), false);
    try t.expect(state.succeeded());
    try t.expectEqual(@as(u8, 2), state.boot_count);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.deploy_boot1)]);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.start_boot2)]);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.cleanup_absence)]);
    try t.expectError(error.AttemptConsumed, p.engine.execute(a, t.io, work.directory, model.options(), false));
    const persisted = try p.engine.loadState(a, t.io, work.directory, binding);
    try t.expect(persisted.succeeded());
    const first = try work.directory.read(t.io, a, "boot1.serial", p.contract.serial_limit, null);
    defer a.free(first);
    try t.expectEqualStrings(&p.local.hash(first), &state.boot1.?.sha256);
    var contradictory = persisted;
    contradictory.boot_count = 1;
    try t.expectError(error.InvalidBootCount, contradictory.validate());
    contradictory = persisted;
    contradictory.records[@intFromEnum(p.model.Step.observe_deallocated)].progress = .unissued;
    try t.expectError(error.InvalidRestartIntent, contradictory.validate());
    contradictory = persisted;
    contradictory.group_absent = false;
    try t.expectError(error.InvalidCleanup, contradictory.validate());
}

test "wrong serial and identity fail while cleanup retains independent absence" {
    for ([_]f.Mode{ .boot2_write, .prefix_changed, .wrong_vm }) |mode| {
        var work = try fixture();
        defer work.deinit();
        _ = try p.engine.prepare(a, t.io, work.directory, f.input());
        var model = f.Model{ .allocator = a, .mode = mode };
        const state = try p.engine.execute(a, t.io, work.directory, model.options(), false);
        try t.expect(!state.succeeded());
        try t.expect(state.failures.primary != null);
        try t.expect(state.group_absent);
        try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.start_boot2)]);
        try t.expect(state.boot2 == null);
    }
}

test "ambiguous upload is consumed without replay and access is cleaned independently" {
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a, .mode = .unknown_upload };
    const state = try p.engine.execute(a, t.io, work.directory, model.options(), false);
    try t.expect(state.consumed);
    try t.expectEqual(@as(u8, 0), state.boot_count);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.data_upload)]);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.cleanup_data_revoke)]);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.cleanup_data_access)]);
    try t.expectEqual(.unknown, state.records[@intFromEnum(p.model.Step.data_upload)].effect);
    try t.expectError(error.AttemptConsumed, p.engine.execute(a, t.io, work.directory, model.options(), false));
}

test "403 is not absence and independent cleanup authority cannot be borrowed" {
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a, .mode = .deny_absence };
    const state = try p.engine.execute(a, t.io, work.directory, model.options(), false);
    try t.expect(state.cleanup_required);
    try t.expect(!state.group_absent);
    try t.expect(state.failures.cleanup != null);
    var denied = try fixture();
    defer denied.deinit();
    _ = try p.engine.prepare(a, t.io, denied.directory, f.input());
    var expired = f.Model{ .allocator = a, .fail_at = .data_grant, .denied_cleanup = true };
    const failed = try p.engine.execute(a, t.io, denied.directory, expired.options(), false);
    try t.expect(failed.failures.primary != null);
    try t.expect(failed.failures.cleanup != null);
    try t.expect(failed.cleanup_required);
    try t.expectEqual(@as(u8, 0), expired.calls[@intFromEnum(p.model.Step.cleanup_delete)]);
}

test "private metadata prepared state lock and source binding cannot rearm consumption" {
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a };
    {
        var held = try work.directory.lock(t.io);
        defer held.close(t.io);
        try t.expectError(error.WouldBlock, p.engine.execute(a, t.io, work.directory, model.options(), false));
    }
    const file = try work.directory.openFile(t.io, "contract.json");
    defer file.close(t.io);
    try file.setPermissions(t.io, .fromMode(0o644));
    if (p.engine.execute(a, t.io, work.directory, model.options(), false)) |_| return error.AcceptedPublicContract else |_| {}
    try file.setPermissions(t.io, .fromMode(0o600));
    model.denied_execution = true;
    try t.expectError(error.SyntheticAuthorityExpired, p.engine.execute(a, t.io, work.directory, model.options(), false));
    const original = try work.directory.read(t.io, a, "contract.json", p.local.maximum, null);
    defer a.free(original);
    const changed = try std.mem.replaceOwned(u8, a, original, "\"operation_ms\":1000", "\"operation_ms\":999");
    defer a.free(changed);
    var lock = try work.directory.lock(t.io);
    defer lock.close(t.io);
    try t.expectEqual(.durable, (try lock.commit(t.io, "contract.json", changed)).status);
    const input = try p.contract.load(a, t.io, work.directory);
    defer input.deinit();
    try t.expectError(error.ContractSubstitution, p.engine.loadState(a, t.io, work.directory, input.binding));
}

const Provision = struct {
    mode: f.Mode,
    delay_ms: u16 = 0,
    fn call(context: *anyopaque, _: p.model.Job, directory: core.private_files.Directory) !void {
        const self: *Provision = @ptrCast(@alignCast(context));
        if (self.delay_ms != 0) try std.Io.sleep(t.io, .fromMilliseconds(self.delay_ms), .awake);
        var lock = try directory.lock(t.io);
        defer lock.close(t.io);
        const saved = try lock.createImmutable(t.io, "fixture-mode", @tagName(self.mode));
        if (saved.status != .durable) return error.RecordingFailed;
    }
};
fn executable(path: []const u8) !@import("hyperv_transfer").files.Input {
    const selection = timing.Selection.begin(options.persistence_timing and std.mem.eql(u8, path, options.worker));
    var selected_bytes: u64 = 0;
    defer selection.end(selected_bytes);
    const resolved = try std.Io.Dir.cwd().realPathFileAlloc(t.io, path, a);
    defer a.free(resolved);
    const absolute = try a.dupe(u8, resolved);
    errdefer a.free(absolute);
    const bytes = try std.Io.Dir.cwd().readFileAlloc(t.io, absolute, a, .limited(32 * 1024 * 1024));
    defer a.free(bytes);
    selected_bytes = bytes.len;
    return .{ .path = absolute, .size = bytes.len, .sha256 = try core.contracts.parseSha256(&p.local.hash(bytes)) };
}
fn reportNativeFailure(mode: f.Mode, state: p.model.State) void {
    std.debug.print("native fixture {s}: failures={any}, boots={d}, consumed={}, cleanup={}, group_absent={}\n", .{
        @tagName(mode), state.failures, state.boot_count, state.consumed, state.process_cleanup_complete, state.group_absent,
    });
    for (state.records, 0..) |record, index| {
        if (record.progress != .failed and record.progress != .intent) continue;
        std.debug.print("  {s}: progress={s}, effect={s}\n", .{
            @tagName(@as(p.model.Step, @enumFromInt(index))), @tagName(record.progress), @tagName(record.effect),
        });
    }
}
test "real native leaf workers deliver bound private results and exact serial model" {
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a };
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    var provision = Provision{ .mode = .good };
    var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = provision.mode, .enabled = options.persistence_timing };
    var supervisor = p.worker.Supervisor{ .allocator = a, .io = t.io, .directory = work.directory, .root_path = work.path, .executable = binary, .provision = .{ .context = &provision, .call = Provision.call }, .observer = trace.observer() };
    defer supervisor.deinit();
    var runtime_options = model.options();
    runtime_options.driver = supervisor.driver();
    const state = try p.engine.execute(a, t.io, work.directory, runtime_options, false);
    errdefer reportNativeFailure(.good, state);
    try t.expect(state.succeeded());
    try t.expectEqual(@as(u8, 2), state.boot_count);
}

test "blocked native worker is killed and malformed delivery retains accepted effects" {
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    for ([_]f.Mode{ .block_upload, .malformed_output, .secret_failure }) |mode| {
        var work = try fixture();
        defer work.deinit();
        _ = try p.engine.prepare(a, t.io, work.directory, f.input());
        var model = f.Model{ .allocator = a };
        var provision = Provision{ .mode = mode };
        var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = provision.mode, .enabled = options.persistence_timing };
        var supervisor = p.worker.Supervisor{ .allocator = a, .io = t.io, .directory = work.directory, .root_path = work.path, .executable = binary, .provision = .{ .context = &provision, .call = Provision.call }, .observer = trace.observer() };
        defer supervisor.deinit();
        var runtime_options = model.options();
        runtime_options.driver = supervisor.driver();
        const before = try core.process.monotonicNanoseconds();
        const state = try p.engine.execute(a, t.io, work.directory, runtime_options, false);
        errdefer reportNativeFailure(mode, state);
        try t.expect(!state.succeeded());
        try t.expect(state.consumed and state.process_cleanup_complete);
        try t.expect(state.failures.primary != null);
        try t.expect(state.group_absent);
        try t.expectEqual(@as(u8, 0), state.boot_count);
        try t.expect(try core.process.monotonicNanoseconds() - before < 20 * std.time.ns_per_s);
        const record = state.records[@intFromEnum(p.model.Step.data_upload)];
        try t.expectEqual(if (mode == .malformed_output) @import("hyperv_transfer").diagnostic.Certainty.accepted else .unknown, record.effect);
        const serialized = try p.local.encode(a, state);
        defer a.free(serialized);
        try t.expect(std.mem.indexOf(u8, serialized, "SYNTHETIC_SECRET") == null);
        try t.expect(std.mem.indexOf(u8, serialized, "sig=") == null);
    }
}

test "production CLI rejects PREPARED standalone legacy synthetic and claimed completed inputs" {
    const binary = try executable(options.cli);
    defer a.free(binary.path);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try core.process.initialize();
    for ([_][]const u8{ "PREPARED", "receipt.json", "legacy", "synthetic", "COMPLETED" }) |source| {
        var result = try core.process.run(a, t.io, .{
            .argv = &.{ binary.path, "run", source },
            .environment = &environment,
            .cwd = .cwd(),
            .deadline = try core.process.Deadline.afterMilliseconds(1000),
            .stdout_limit = 2048,
            .stderr_limit = 2048,
        });
        defer result.deinit(a);
        try t.expect(result.cleanup_complete and result.failures.primary != null);
        try t.expectEqual(@as(usize, 0), result.stdout.len);
    }
}

const RecordingFault = struct {
    calls: usize = 0,
    at: usize,
    every: bool = false,
    fn fail(context: *anyopaque) !void {
        const self: *RecordingFault = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (self.every or self.calls == self.at) return error.SyntheticRecordingFailure;
    }
};
test "consumed marker crash window cannot inspect unconsumed or accept unknown state schema" {
    var work = try fixture();
    defer work.deinit();
    const binding = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a };
    var fault: RecordingFault = .{ .at = 0, .every = true };
    var runtime = model.options();
    runtime.record_hook = .{ .context = &fault, .call = RecordingFault.fail };
    _ = try p.engine.execute(a, t.io, work.directory, runtime, false);
    const state = try p.engine.loadState(a, t.io, work.directory, binding);
    try t.expect(state.consumed and state.cleanup_required and state.failures.recording != null);
    try t.expectEqual(@as(u8, 0), model.calls[@intFromEnum(p.model.Step.group_create)]);
    try t.expectError(error.AttemptConsumed, p.engine.execute(a, t.io, work.directory, model.options(), false));
    const binary = try executable(options.cli);
    defer a.free(binary.path);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try core.process.initialize();
    var inspected = try core.process.run(a, t.io, .{
        .argv = &.{ binary.path, "inspect", work.path },
        .environment = &environment,
        .cwd = .cwd(),
        .deadline = try core.process.Deadline.afterMilliseconds(1000),
        .stdout_limit = 2048,
        .stderr_limit = 2048,
    });
    defer inspected.deinit(a);
    try t.expect(inspected.cleanup_complete and inspected.failures.primary == null);
    try t.expect(std.mem.indexOf(u8, inspected.stdout, "\"consumed\":true") != null);
    try t.expect(std.mem.indexOf(u8, inspected.stdout, "\"production_admission\":\"unavailable\"") != null);
    try t.expect(std.mem.indexOf(u8, inspected.stdout, "synthetic-rg") == null);
    const raw = try work.directory.read(t.io, a, "state.json", p.local.maximum, null);
    defer a.free(raw);
    const bad = try std.mem.replaceOwned(u8, a, raw, "uk.hyperv.persistence-state", "uk.hyperv.not-a-valid-state");
    defer a.free(bad);
    var lock = try work.directory.lock(t.io);
    defer lock.close(t.io);
    try t.expectEqual(.durable, (try lock.commit(t.io, "state.json", bad)).status);
    try t.expectError(error.UnknownSchema, p.engine.loadState(a, t.io, work.directory, binding));
}
test "durability failure consumes admission before effects and retains accepted sole restart" {
    for ([_]usize{ 2, 41 }) |at| {
        var work = try fixture();
        defer work.deinit();
        _ = try p.engine.prepare(a, t.io, work.directory, f.input());
        var model = f.Model{ .allocator = a };
        var fault: RecordingFault = .{ .at = at };
        var runtime = model.options();
        runtime.record_hook = .{ .context = &fault, .call = RecordingFault.fail };
        const state = try p.engine.execute(a, t.io, work.directory, runtime, false);
        try t.expect(state.consumed and !state.succeeded() and state.failures.recording != null);
        try t.expectEqual(@as(u8, if (at == 2) 0 else 1), model.calls[@intFromEnum(p.model.Step.start_boot2)]);
        if (at == 2) try t.expectEqual(@as(u8, 0), model.calls[@intFromEnum(p.model.Step.group_create)]);
        try t.expectError(error.AttemptConsumed, p.engine.execute(a, t.io, work.directory, model.options(), false));
    }
}

test "all failure lanes remain independent and cleanup process failures stay cleanup" {
    var lanes: core.diagnostics.Failures = .{ .primary = .{ .stage = .arm, .category = .transport }, .recording = .{ .stage = .state_record, .category = .local_io } };
    p.model.mergeStep(&lanes, .{ .primary = .{ .stage = .process_run, .category = .timeout } }, .cleanup_delete);
    try t.expectEqual(.transport, lanes.primary.?.category);
    try t.expectEqual(.timeout, lanes.cleanup.?.category);
    try t.expectEqual(.local_io, lanes.recording.?.category);
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a, .mode = .unknown_upload, .denied_cleanup = true };
    var fault: RecordingFault = .{ .at = 19 };
    var runtime = model.options();
    runtime.record_hook = .{ .context = &fault, .call = RecordingFault.fail };
    const state = try p.engine.execute(a, t.io, work.directory, runtime, false);
    try t.expect(state.failures.primary != null and state.failures.cleanup != null and state.failures.recording != null);
}

test "serialized upload models reject counter disagreement and sealed serial replacement" {
    var work = try fixture();
    defer work.deinit();
    const binding = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a };
    const state = try p.engine.execute(a, t.io, work.directory, model.options(), false);
    var bad = state;
    bad.records[@intFromEnum(p.model.Step.data_upload)].transfer.?.bytes_accepted = 0;
    try t.expectError(error.InvalidTransfer, bad.validate());
    bad = state;
    bad.records[@intFromEnum(p.model.Step.data_upload)].page_report.?.plan.bytes -= 512;
    if (bad.validate()) |_| return error.AcceptedInvalidProgress else |_| {}
    bad = state;
    bad.records[@intFromEnum(p.model.Step.observe_final_deallocated)].progress = .failed;
    try t.expect(!bad.succeeded());
    var lock = try work.directory.lock(t.io);
    defer lock.close(t.io);
    try t.expectEqual(.durable, (try lock.commit(t.io, "boot1.serial", "replaced synthetic serial\n")).status);
    if (p.engine.loadState(a, t.io, work.directory, binding)) |_| return error.AcceptedReplacedSerial else |_| {}
}

test "partial native page checkpoint survives killed delivery without claiming full upload" {
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    for ([_]f.Mode{ .partial_pages, .output_limit }) |mode| {
        var work = try fixture();
        defer work.deinit();
        _ = try p.engine.prepare(a, t.io, work.directory, f.input());
        var model = f.Model{ .allocator = a };
        var provision: Provision = .{ .mode = mode };
        var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = provision.mode, .enabled = options.persistence_timing };
        var supervisor: p.worker.Supervisor = .{ .allocator = a, .io = t.io, .directory = work.directory, .root_path = work.path, .executable = binary, .provision = .{ .context = &provision, .call = Provision.call }, .observer = trace.observer() };
        defer supervisor.deinit();
        var runtime = model.options();
        runtime.driver = supervisor.driver();
        const state = try p.engine.execute(a, t.io, work.directory, runtime, false);
        errdefer reportNativeFailure(mode, state);
        try t.expect(!state.succeeded() and state.consumed and state.group_absent and state.process_cleanup_complete);
        const record = state.records[@intFromEnum(p.model.Step.data_upload)];
        try t.expectEqual(.unknown, record.effect);
        if (mode == .partial_pages) {
            try t.expectEqual(@as(u64, 4194304), record.page_report.?.progress.?.bytes_confirmed);
            try t.expectEqual(@as(u64, 8388608), record.page_report.?.progress.?.bytes_attempted);
            try t.expect(record.transfer == null);
        }
    }
}

const CancelWhenReady = struct {
    directory: std.Io.Dir,
    flag: *std.atomic.Value(bool),
    deadline: core.process.Deadline,
    failure: ?anyerror = null,

    fn run(self: *CancelWhenReady) void {
        self.waitReady() catch |err| {
            self.failure = err;
        };
        self.flag.store(true, .release);
    }

    fn waitReady(self: *CancelWhenReady) !void {
        while (!try self.deadline.expired()) {
            const ready = self.directory.openFile(t.io, "worker-08-0/cancel-ready", .{
                .follow_symlinks = false,
            }) catch |err| switch (err) {
                error.FileNotFound => {
                    try std.Io.sleep(t.io, .fromMilliseconds(10), .awake);
                    continue;
                },
                else => return err,
            };
            defer ready.close(t.io);
            var bytes: [6]u8 = undefined;
            const count = try ready.readPositionalAll(t.io, &bytes, 0);
            if (!std.mem.eql(u8, bytes[0..count], "ready\n")) return error.InvalidWorkerReadiness;
            return;
        }
        return error.WorkerReadinessTimeout;
    }
};
test "direct native cancellation interrupts blocked leaf and proves child termination" {
    var work = try fixture();
    defer work.deinit();
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    var cancelled = std.atomic.Value(bool).init(false);
    // Startup deliberately outlasts the former fixed 500-ms cancellation delay.
    var provision: Provision = .{ .mode = .block_upload, .delay_ms = 750 };
    var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = provision.mode, .enabled = options.persistence_timing };
    var supervisor: p.worker.Supervisor = .{ .allocator = a, .io = t.io, .directory = work.directory, .root_path = work.path, .executable = binary, .cancellation = &cancelled, .provision = .{ .context = &provision, .call = Provision.call }, .observer = trace.observer() };
    defer supervisor.deinit();
    const deadline = try core.process.Deadline.afterMilliseconds(5000);
    var cancellation: CancelWhenReady = .{ .directory = work.directory.dir, .flag = &cancelled, .deadline = deadline };
    const driver = supervisor.driver();
    const job = try f.makeJob(a, .data_upload, deadline.expires_ns);
    var reply = blk: {
        const thread = try std.Thread.spawn(.{}, CancelWhenReady.run, .{&cancellation});
        defer thread.join();
        break :blk try driver.executeFn(driver.context, job);
    };
    defer reply.deinit();
    if (cancellation.failure) |err| return err;
    try t.expect(reply.value.process_cleanup_complete and !reply.value.complete);
    try t.expectEqual(.cancelled, reply.value.failures.primary.?.category);
    const started = try work.directory.dir.openFile(t.io, "worker-08-0/started.json", .{});
    started.close(t.io);
}

test "cleanup recovery requires bound parent reaping proof and never replays mutations" {
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    var model = f.Model{ .allocator = a };
    var provision: Provision = .{ .mode = .partial_pages };
    var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = provision.mode, .enabled = options.persistence_timing };
    var supervisor: p.worker.Supervisor = .{ .allocator = a, .io = t.io, .directory = work.directory, .root_path = work.path, .executable = binary, .provision = .{ .context = &provision, .call = Provision.call }, .observer = trace.observer() };
    defer supervisor.deinit();
    var runtime = model.options();
    runtime.driver = supervisor.driver();
    var state = try p.engine.execute(a, t.io, work.directory, runtime, false);
    timing.recoverySnapshot(options.persistence_timing, .recovery_initial, state);
    state.phase = .running;
    state.cleanup_required = true;
    state.cleanup_deadline_ns = null;
    state.group_absent = false;
    state.secrets_disposed = false;
    state.data_access_pending = true;
    for (state.records[@intFromEnum(p.model.Step.data_upload)..]) |*record| record.* = .{};
    state.records[@intFromEnum(p.model.Step.data_upload)] = .{ .progress = .intent, .effect = .unknown };
    timing.recoverySnapshot(options.persistence_timing, .recovery_rewritten, state);
    try state.validate();
    timing.recoverySnapshot(options.persistence_timing, .recovery_validated, state);
    const driver = supervisor.driver();
    var recovered = state;
    try driver.recoverFn.?(driver.context, &recovered);
    try t.expect(recovered.process_cleanup_complete);
    try t.expectEqual(@as(u64, 4194304), recovered.records[8].page_report.?.progress.?.bytes_confirmed);
    const repeated = try f.makeJob(a, .data_upload, (try core.process.Deadline.afterMilliseconds(1000)).expires_ns);
    try t.expectError(error.MutationReplay, driver.executeFn(driver.context, repeated));
    try work.directory.dir.deleteFile(t.io, "worker-08-0/supervised.json");
    var unresolved = state;
    try t.expectError(error.ProcessRecoveryRequired, driver.recoverFn.?(driver.context, &unresolved));
    try t.expect(!unresolved.process_cleanup_complete and unresolved.consumed and unresolved.cleanup_required);
}

test "explicit token lifetime and cleanup principal cannot borrow execution identity" {
    const azure = @import("hyperv_azure");
    const authority = f.input().authority;
    var token: azure.auth.Token = .{ .value = try azure.secret.Bytes.copy(a, "synthetic-only-token"), .expires_on = 2000, .tenant = authority.tenant, .subscription = authority.subscription, .principal = authority.principal, .client = authority.client };
    defer token.deinit();
    try token.require(authority, 1000, 1000);
    try t.expectError(error.TokenExpired, token.require(authority, 1000, 1001));
    var cleanup_authority = authority;
    cleanup_authority.principal = "99999999-9999-4999-8999-999999999999".*;
    try t.expectError(error.AuthorityMismatch, token.require(cleanup_authority, 1000, 1));
}

test "cleanup-only recovery keeps deadline and SAS obligations without replaying delete or upload" {
    var work = try fixture();
    defer work.deinit();
    _ = try p.engine.prepare(a, t.io, work.directory, f.input());
    var model = f.Model{ .allocator = a, .mode = .unknown_upload, .fail_at = .cleanup_data_access };
    const failed = try p.engine.execute(a, t.io, work.directory, model.options(), false);
    try t.expect(failed.group_absent and failed.data_access_pending and failed.cleanup_required);
    try t.expect(!failed.secrets_disposed);
    try t.expectEqual(@as(u8, 0), model.calls[@intFromEnum(p.model.Step.cleanup_dispose)]);
    model.fail_at = null;
    const recovered = try p.engine.execute(a, t.io, work.directory, model.options(), true);
    try t.expect(!recovered.cleanup_required and recovered.secrets_disposed and !recovered.data_access_pending);
    try t.expectEqual(failed.cleanup_deadline_ns, recovered.cleanup_deadline_ns);
    try t.expect(recovered.failures.primary != null and recovered.failures.cleanup != null);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.data_upload)]);
    try t.expectEqual(@as(u8, 1), model.calls[@intFromEnum(p.model.Step.cleanup_delete)]);
    try t.expectEqual(@as(u8, 2), model.calls[@intFromEnum(p.model.Step.cleanup_data_access)]);
}

test "failed native creation delivery retains UUID and refuses cleanup replacement" {
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    for ([_]f.Mode{ .malformed_create, .replaced_after_create, .unstarted_grant }) |mode| {
        var work = try fixture();
        defer work.deinit();
        const binding = try p.engine.prepare(a, t.io, work.directory, f.input());
        var model = f.Model{ .allocator = a };
        var provision: Provision = .{ .mode = mode };
        var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = provision.mode, .enabled = options.persistence_timing };
        var supervisor: p.worker.Supervisor = .{ .allocator = a, .io = t.io, .directory = work.directory, .root_path = work.path, .executable = binary, .provision = .{ .context = &provision, .call = Provision.call }, .observer = trace.observer() };
        defer supervisor.deinit();
        var runtime = model.options();
        runtime.driver = supervisor.driver();
        const state = try p.engine.execute(a, t.io, work.directory, runtime, false);
        errdefer reportNativeFailure(mode, state);
        try t.expect(!state.succeeded() and state.failures.primary != null and state.consumed);
        try t.expectEqual(f.ids.os, state.originals.os);
        const saved = try p.engine.loadState(a, t.io, work.directory, binding);
        try t.expectEqual(state.originals.os, saved.originals.os);
        if (mode == .replaced_after_create) {
            try t.expect(!state.group_absent and state.cleanup_required);
            try t.expectEqual(.unissued, state.records[@intFromEnum(p.model.Step.cleanup_delete)].progress);
        } else try t.expect(state.group_absent and !state.cleanup_required);
        if (mode == .unstarted_grant) {
            try t.expect(!state.data_access_pending and state.secrets_disposed);
            try t.expectEqual(.not_started, state.records[@intFromEnum(p.model.Step.data_grant)].effect);
            try t.expectEqual(.skipped, state.records[@intFromEnum(p.model.Step.cleanup_data_revoke)].progress);
            try t.expectEqual(.skipped, state.records[@intFromEnum(p.model.Step.cleanup_data_access)].progress);
        }
    }
}

test "strict result serialization rejects contradictory absence and zero-byte mutation claims" {
    const job = try f.makeJob(a, .group_create, (try core.process.Deadline.afterMilliseconds(1000)).expires_ns);
    var result = try p.native.initial(a, job);
    result.complete = true;
    result.effect = .unknown;
    try t.expectError(error.ContradictoryResult, result.validate());
    result.effect = .accepted;
    try result.validate();
    const bytes = try p.local.encode(a, result);
    defer a.free(bytes);
    const raw = try std.mem.replaceOwned(u8, a, bytes, "\"effect\":\"accepted\"", "\"effect\":\"not_started\"");
    defer a.free(raw);
    const parsed = try p.local.Document(p.model.Result).load(a, raw);
    defer parsed.deinit();
    try t.expectError(error.ContradictoryResult, parsed.value.validate());
    result.step = .cleanup_absence;
    result.effect = .not_applicable;
    result.observation.group = .absent;
    result.http_status = 404;
    result.service_code = .malformed;
    try t.expectError(error.InvalidAbsence, result.validate());
    result.service_code = .ResourceGroupNotFound;
    try result.validate();
    result.http_status = 403;
    try t.expectError(error.InvalidAbsence, result.validate());
}

fn timingHeader() !timing.Header {
    return .{ .identity = .from(try f.makeJob(a, .os_create, 1000000000)), .worker_bytes = 4096, .mode = .malformed_create, .sequence = 1 };
}

test "persistence timing canonical bounded schema rejects invalid and cross-process records" {
    const header = try timingHeader();
    const record = try timing.Record.observe(header, .child_entry, null);
    var bytes = [_]u8{0} ** timing.max_bytes;
    @memcpy(bytes[0..timing.slot_size], &try header.encode());
    @memcpy(bytes[timing.slot_size..][0..timing.slot_size], &try record.encode());
    const end = 2 * timing.slot_size;
    const prefix = try timing.decode(a, bytes[0..end], header);
    try t.expectEqual(.prefix, prefix.status);
    try t.expectEqual(@as(usize, 1), prefix.count);
    try t.expectEqual(.partial_slot, (try timing.decode(a, bytes[0 .. end + 1], header)).status);
    try t.expectEqual(.empty, (try timing.decode(a, bytes[0..timing.slot_size], header)).status);
    try t.expectError(error.DiagnosticOverflow, timing.decode(a, &([_]u8{0} ** (timing.max_bytes + 1)), header));
    try t.expectError(error.InvalidDiagnostic, timing.decode(a, bytes[0 .. timing.slot_size - 1], header));
    var other = header;
    other.identity.nonce[0] = '9';
    try t.expectError(error.InvalidDiagnostic, timing.decode(a, bytes[0..end], other));
    other = header;
    other.identity.deadline_ns += 1;
    try t.expectError(error.InvalidDiagnostic, timing.decode(a, bytes[0..end], other));
    for ([_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "\"schema_version\":1", .to = "\"schema_version\":2" },
        .{ .from = "\"schema_version\":1", .to = "\"schema_version\":1,\"schema_version\":1" },
        .{ .from = "\"authority\":\"none\"", .to = "\"authority\":\"accepted\"" },
        .{ .from = "\"child_entry\"", .to = "\"unknown_stage\"" },
        .{ .from = "\"worker_bytes\":4096", .to = "\"worker_bytes\":0" },
        .{ .from = "\"worker_bytes\":4096", .to = "\"worker_bytes\":4096,\"secret\":\"SYNTHETIC_SECRET\"" },
    }) |mutation| {
        const slot = try record.encode();
        const bad = try std.mem.replaceOwned(u8, a, std.mem.trimEnd(u8, &slot, "\x00"), mutation.from, mutation.to);
        defer a.free(bad);
        @memset(bytes[timing.slot_size..end], 0);
        @memcpy(bytes[timing.slot_size..][0..bad.len], bad);
        const rejected = try timing.decode(a, bytes[0..end], header);
        try t.expectEqual(.invalid, rejected.status);
        try t.expectEqual(@as(usize, 0), rejected.count);
    }
    var records: timing.Records = .{ .child = true };
    try records.push(record);
    try t.expectError(error.InvalidDiagnostic, records.push(record));
    var next = record;
    next.stage = .child_job_begin;
    next.sample.process_cpu_ns = record.sample.process_cpu_ns - 1;
    try t.expectError(error.InvalidDiagnostic, records.push(next));
    next = record;
    next.stage = .parent_end;
    try t.expectError(error.InvalidDiagnostic, records.push(next));
    records = .{ .child = true };
    for (0..timing.child_slots) |index| {
        next = record;
        next.stage = @enumFromInt(timing.parent_slots + index);
        try records.push(next);
    }
    try t.expectError(error.DiagnosticOverflow, records.push(next));
}

test "persistence timing private sidecar is identity-bound and cleanup-gated" {
    var work = try fixture();
    defer work.deinit();
    const header = try timingHeader();
    const sidecar = try timing.Sidecar.create(t.io, work.directory, header);
    defer sidecar.close(t.io);
    const record = try timing.Record.observe(header, .child_entry, null);
    try sidecar.file.writePositionalAll(t.io, &try record.encode(), timing.slot_size);
    try t.expectError(error.DiagnosticCleanupUnconfirmed, sidecar.read(a, t.io, work.directory, false));
    // No process exists in this unit: exercise the post-cleanup reader directly.
    try t.expectEqual(@as(usize, 1), (try sidecar.read(a, t.io, work.directory, true)).count);
    try t.expectError(error.PathAlreadyExists, timing.Sidecar.create(t.io, work.directory, header));
    try work.directory.dir.deleteFile(t.io, timing.file_name);
    const replacement = try timing.Sidecar.create(t.io, work.directory, header);
    defer replacement.close(t.io);
    try t.expectError(error.InvalidDiagnostic, sidecar.read(a, t.io, work.directory, true));
}

test "persistence timing shared observer refuses sidecar reads without cleanup" {
    var work = try fixture();
    defer work.deinit();
    const header = try timingHeader();
    var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = header.mode, .enabled = true, .emit_log = false };
    const observer = trace.observer();
    p.worker.Observer.emit(observer, .{ .stage = .parent_begin, .identity = header.identity, .worker_bytes = header.worker_bytes });
    p.worker.Observer.emit(observer, .{ .stage = .provision_begin, .directory = work.directory });
    // An invalid file would be rejected if the callback attempted to read it.
    try trace.sidecar.?.file.writePositionalAll(t.io, "invalid", 0);
    p.worker.Observer.emit(observer, .{ .stage = .process_return, .cleanup_complete = false });
    p.worker.Observer.emit(observer, .{ .stage = .parent_end });
    try t.expectEqual(.cleanup_unconfirmed, trace.child_records.status);
    try t.expectEqual(@as(usize, 0), trace.child_records.count);
    try t.expect(trace.sidecar == null);
}

test "persistence timing default off is inert and shared sealing failure keeps exact deadline" {
    var work = try fixture();
    defer work.deinit();
    var provision: Provision = .{ .mode = .good };
    var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = .good, .emit_log = false };
    try t.expect(trace.observer() == null);
    var supervisor: p.worker.Supervisor = .{
        .allocator = a,
        .io = t.io,
        .directory = work.directory,
        .root_path = work.path,
        .executable = .{ .path = "/synthetic-never-opened", .size = 4096, .sha256 = [_]u8{1} ** 32 },
        .provision = .{ .context = &provision, .call = Provision.call },
    };
    defer supervisor.deinit();
    try t.expect(supervisor.observer == null);
    const driver = supervisor.driver();
    const job = try f.makeJob(a, .os_create, 1);
    try t.expectError(error.Deadline, driver.executeFn(driver.context, job));
    try t.expectEqual(@as(u16, 0), trace.sequence);
    try t.expectEqual(@as(usize, 0), trace.records.count);
    trace.enabled = true;
    supervisor.observer = trace.observer();
    try t.expectError(error.Deadline, driver.executeFn(driver.context, job));
    try t.expectEqual(.ok, trace.records.status);
    try t.expectEqual(.not_started, trace.child_records.status);
    try t.expectEqual(@as(usize, 4), trace.records.count);
    for ([_]timing.Stage{ .parent_begin, .seal_begin, .parent_error, .parent_end }, trace.records.values[0..4]) |stage, record| {
        try t.expectEqual(stage, record.stage);
        try t.expectEqual(@as(u64, 1), record.deadline_ns);
        try t.expectEqual(@as(u32, 1000), record.operation_ms);
    }
    try t.expectError(error.FileNotFound, work.directory.openFile(t.io, timing.file_name));
    while (trace.sequence < timing.max_jobs) {
        p.worker.Observer.emit(trace.observer(), .{ .stage = .parent_begin, .identity = .from(job), .worker_bytes = 4096 });
        p.worker.Observer.emit(trace.observer(), .{ .stage = .parent_end });
    }
    p.worker.Observer.emit(trace.observer(), .{ .stage = .parent_begin, .identity = .from(job), .worker_bytes = 4096 });
    try t.expect(trace.overflow_reported);
    try t.expectEqual(timing.max_jobs, trace.sequence);
}

const TimingProvision = struct {
    remove_timing: bool,
    fn call(context: *anyopaque, job: p.model.Job, directory: core.private_files.Directory) !void {
        const self: *TimingProvision = @ptrCast(@alignCast(context));
        var provision: Provision = .{ .mode = .malformed_create };
        try Provision.call(&provision, job, directory);
        if (self.remove_timing and options.persistence_timing) try directory.dir.deleteFile(t.io, timing.file_name);
    }
};

test "persistence timing native malformed delivery preserves failure even when diagnostics are missing" {
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    for ([_]bool{ false, true }) |remove_timing| {
        var work = try fixture();
        defer work.deinit();
        var provision: TimingProvision = .{ .remove_timing = remove_timing };
        var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = .malformed_create, .enabled = options.persistence_timing };
        var supervisor: p.worker.Supervisor = .{
            .allocator = a,
            .io = t.io,
            .directory = work.directory,
            .root_path = work.path,
            .executable = binary,
            .provision = .{ .context = &provision, .call = TimingProvision.call },
            .observer = trace.observer(),
        };
        defer supervisor.deinit();
        const driver = supervisor.driver();
        const job = try f.makeJob(a, .os_create, (try core.process.Deadline.afterMilliseconds(1000)).expires_ns);
        var reply = try driver.executeFn(driver.context, job);
        defer reply.deinit();
        try t.expect(!reply.value.complete and reply.value.process_cleanup_complete);
        try t.expectEqual(.invalid_response, reply.value.failures.primary.?.category);
        try t.expectEqual(.accepted, reply.value.effect);
        if (options.persistence_timing) {
            try t.expectEqual(.ok, trace.records.status);
            try t.expectEqual(if (remove_timing) timing.Status.missing else .prefix, trace.child_records.status);
            if (!remove_timing) {
                try t.expectEqual(.child_fixture_ack_end, trace.child_records.values[trace.child_records.count - 1].stage);
                try t.expectEqual(.child_entry, trace.child_records.values[0].stage);
            }

            try t.expectEqual(.parent_end, trace.records.values[trace.records.count - 1].stage);
        } else {
            try t.expectEqual(@as(usize, 0), trace.records.count);
            const directory = try core.private_files.Directory.open(t.io, supervisor.directories[@intFromEnum(job.step)].?);
            defer directory.close(t.io);
            try t.expectError(error.FileNotFound, directory.openFile(t.io, timing.file_name));
        }
    }
}

test "persistence timing shared child success timeout and checkpoint stages survive cleanup" {
    const binary = try executable(options.worker);
    defer a.free(binary.path);
    for ([_]f.Mode{ .good, .block_upload, .secret_failure, .partial_pages }) |mode| {
        var work = try fixture();
        defer work.deinit();
        var provision: Provision = .{ .mode = mode };
        var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = mode, .enabled = options.persistence_timing };
        var supervisor: p.worker.Supervisor = .{
            .allocator = a,
            .io = t.io,
            .directory = work.directory,
            .root_path = work.path,
            .executable = binary,
            .provision = .{ .context = &provision, .call = Provision.call },
            .observer = trace.observer(),
        };
        defer supervisor.deinit();
        const driver = supervisor.driver();
        const job = try f.makeJob(a, if (mode == .good) .group_create else .data_upload, (try core.process.Deadline.afterMilliseconds(1000)).expires_ns);
        var reply = try driver.executeFn(driver.context, job);
        defer reply.deinit();
        try t.expect(reply.value.process_cleanup_complete);
        try t.expectEqual(mode == .good, reply.value.complete);
        if (mode != .good) try t.expectEqual(if (mode == .block_upload) core.diagnostics.Category.timeout else .child_failed, reply.value.failures.primary.?.category);
        if (mode == .partial_pages) try t.expectEqual(@as(u64, 4194304), reply.value.page_report.?.progress.?.bytes_confirmed);
        if (options.persistence_timing) {
            try t.expectEqual(.ok, trace.records.status);
            try t.expectEqual(if (mode == .good) timing.Status.complete else .prefix, trace.child_records.status);
            const last = trace.child_records.values[trace.child_records.count - 1];
            try t.expectEqual(switch (mode) {
                .good => timing.Stage.child_end,
                .partial_pages => .child_fixture_checkpoint,
                else => .child_backend_begin,
            }, last.stage);
            for (trace.records.values[0..trace.records.count]) |record| {
                try t.expectEqual(job.deadline_ns, record.deadline_ns);
                try t.expectEqual(@as(u32, 1000), record.operation_ms);
                if (record.stage == .process_return) try t.expectEqual(true, record.cleanup_complete.?);
            }
        } else try t.expectEqual(@as(usize, 0), trace.records.count);
    }
}

test "persistence timing bounded report survives fixture cleanup for success and failure prefixes" {
    var trace: timing.Parent = .{ .allocator = a, .io = t.io, .mode = .good, .enabled = true, .emit_log = false };
    const header = try timingHeader();
    trace.sequence = header.sequence;
    {
        var work = try fixture();
        defer work.deinit();
        const sidecar = try timing.Sidecar.create(t.io, work.directory, header);
        defer sidecar.close(t.io);
        for (0..timing.child_slots) |index| {
            var record = try timing.Record.observe(header, @enumFromInt(timing.parent_slots + index), null);
            record.sample.monotonic_ns = index;
            record.sample.process_cpu_ns = index;
            try sidecar.file.writePositionalAll(t.io, &try record.encode(), (index + 1) * timing.slot_size);
        }
        trace.child_records = try sidecar.read(a, t.io, work.directory, true);
    }
    try t.expectEqual(timing.Status.complete, trace.child_records.status);
    for (0..timing.parent_slots) |index| {
        const stage: timing.Stage = @enumFromInt(index);
        var record = try timing.Record.observe(header, stage, if (stage == .process_return) true else null);
        record.sample.monotonic_ns = index;
        record.sample.process_cpu_ns = index;
        try trace.records.push(record);
    }
    var buffer: [timing.report_bytes]u8 = undefined;
    const complete = try trace.encodeReport(&buffer);
    try t.expect(complete.len <= timing.report_bytes);
    try t.expectEqual(timing.parent_slots + timing.child_slots + 1, std.mem.count(u8, complete, "\n"));
    for ([_][]const u8{ "nonce", "parent_pid", "input_sha256", "SYNTHETIC_SECRET" }) |forbidden|
        try t.expect(std.mem.indexOf(u8, complete, forbidden) == null);
    trace.child_records = .{ .child = true, .status = .not_started };
    trace.records.count = 2;
    const prefix = try trace.encodeReport(&buffer);
    try t.expectEqual(@as(usize, 3), std.mem.count(u8, prefix, "\n"));
    try t.expect(std.mem.indexOf(u8, prefix, "child_status=not_started") != null);
    try t.expectEqual(timing.max_jobs * timing.report_bytes + timing.slot_size, timing.collector_log_bytes);
    trace.records.count = timing.parent_slots + 1;
    try t.expectError(error.DiagnosticOverflow, trace.encodeReport(&buffer));
}
