const std = @import("std");
const host = @import("host");
const timing = @import("host_timing");
const f = @import("fixture_support.zig");
const a = std.testing.allocator;
const io = std.testing.io;
const t = std.testing;

test "host timing closed slots scope order and aggregate bounds" {
    const child = timing.Child.capture().record.?;
    const bytes = try child.encode();
    try t.expectEqualDeep(child, try timing.decodeRecord(a, &bytes));
    try t.expectError(error.InvalidHostTiming, timing.decodeRecord(a, bytes[0 .. bytes.len - 1]));
    var malformed = bytes;
    malformed[malformed.len - 1] = 1;
    try t.expectError(error.InvalidHostTiming, timing.decodeRecord(a, &malformed));
    var invalid = child;
    invalid.scope = .parent;
    try t.expectError(error.InvalidHostTiming, invalid.encode());
    invalid = child;
    invalid.cleanup_complete = true;
    try t.expectError(error.InvalidHostTiming, invalid.encode());
    var parent: timing.Parent = .init(.success, 1);
    const stages: []const timing.Stage = &.{
        .call_enter,      .request_encoded, .reservation_ready, .state_ready,
        .operation_ready, .job_ready,       .process_call,      .process_return,
        .call_success,
    };
    for (stages) |stage| parent.mark(stage, if (stage == .process_return) true else null);
    try t.expectEqual(@as(?timing.Fault, null), parent.fault);
    try t.expectEqual(@as(usize, timing.parent_slots), parent.records.count);
    try t.expectError(error.HostTimingOverflow, parent.records.push(child));
    var records: timing.Records = .{};
    try t.expectError(error.InvalidHostTiming, records.push(child));
    try records.push(parent.records.values[0]);
    try t.expectError(error.InvalidHostTiming, records.push(parent.records.values[0]));
    try t.expectError(error.InvalidHostTiming, records.push(parent.records.values[2]));
    var regressed = parent.records.values[1];
    regressed.sample.process_cpu_ns = 0;
    try t.expectError(error.InvalidHostTiming, records.push(regressed));
    regressed = parent.records.values[1];
    regressed.sample.monotonic_ns = 0;
    try t.expectError(error.InvalidHostTiming, records.push(regressed));
    var terminal = parent.records.values[1];
    terminal.stage = .call_error;
    try records.push(terminal);
    try t.expectError(error.InvalidHostTiming, records.push(parent.records.values[2]));
    var report: timing.Report = .{
        .parent = parent.records,
        .child = child,
        .summary = .{
            .fixture = .success,
            .parent_records = parent.records.count,
            .parent_fault = null,
            .cleanup = .complete,
            .child = .entry,
            .deadline_ns = 1,
            .fixture_bytes = 1,
        },
    };
    var buffer: [timing.max_bytes]u8 = undefined;
    const output = try report.encode(&buffer);
    try t.expect(output.len <= timing.max_bytes);
    try t.expectEqual(@as(usize, 11), std.mem.count(u8, output, "\n"));
    try t.expectEqual(@as(usize, 67584), timing.aggregate_bytes);
    for ([_][]const u8{ "argv", "environment", "run_id", "vm_id", "path", "nonce" }) |forbidden|
        try t.expect(std.mem.indexOf(u8, output, forbidden) == null);
    report.summary.parent_records += 1;
    try t.expectError(error.InvalidHostTiming, report.encode(&buffer));
}

test "host timing rejects unknown labels fields and noncanonical slots" {
    const record = timing.Child.capture().record.?;
    const encoded = try record.encode();
    const plain = std.mem.trimEnd(u8, &encoded, "\x00");
    var doc = try host.core.contracts.Document.parse(a, plain, .{});
    defer doc.deinit();
    try doc.parsed.value.object.put(doc.parsed.arena.allocator(), "private_path", .{ .string = "SYNTHETIC_SECRET" });
    var bytes = try timing.encodeSlot(doc.value());
    if (timing.decodeRecord(a, &bytes)) |_| return error.AcceptedUnknownField else |_| {}
    _ = doc.parsed.value.object.swapRemove("private_path");
    doc.value().object.getPtr("stage").?.* = .{ .string = "spawn_completed" };
    bytes = try timing.encodeSlot(doc.value());
    if (timing.decodeRecord(a, &bytes)) |_| return error.AcceptedUnknownStage else |_| {}
    doc.value().object.getPtr("stage").?.* = .{ .string = "child_entry" };
    doc.value().object.getPtr("authority").?.* = .{ .string = "accepted" };
    bytes = try timing.encodeSlot(doc.value());
    if (timing.decodeRecord(a, &bytes)) |_| return error.AcceptedAuthority else |_| {}
    bytes = [_]u8{0} ** timing.slot_bytes;
    bytes[0] = ' ';
    @memcpy(bytes[1..][0..plain.len], plain);
    try t.expectError(error.InvalidHostTiming, timing.decodeRecord(a, &bytes));
}

test "host timing cleanup gates reads and retains missing invalid and overflow status" {
    const directory = try f.Directory.create("timing-read");
    defer directory.deinit();
    var parent: timing.Parent = .init(.setup_refusal, 1);
    parent.mark(.call_enter, null);
    parent.mark(.call_error, null);
    try t.expectEqual(timing.ChildStatus.not_called, parent.collect(a, io, directory.path).summary.child);
    parent.cleanup = .unconfirmed;
    try t.expectEqual(timing.ChildStatus.cleanup_unconfirmed, parent.collect(a, io, directory.path).summary.child);
    parent.cleanup = .incomplete;
    try t.expectEqual(timing.ChildStatus.cleanup_unconfirmed, parent.collect(a, io, directory.path).summary.child);
    parent.cleanup = .complete;
    try t.expectEqual(timing.ChildStatus.missing, parent.collect(a, io, directory.path).summary.child);
    try directory.directory.dir.writeFile(io, .{ .sub_path = timing.child_name, .data = "partial", .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    try t.expectEqual(timing.ChildStatus.invalid, parent.collect(a, io, directory.path).summary.child);
    try directory.directory.dir.deleteFile(io, timing.child_name);
    const oversized = [_]u8{0} ** (timing.slot_bytes + 1);
    try directory.directory.dir.writeFile(io, .{ .sub_path = timing.child_name, .data = &oversized, .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    try t.expectEqual(timing.ChildStatus.overflow, parent.collect(a, io, directory.path).summary.child);
    try directory.directory.dir.deleteFile(io, timing.child_name);
    const child = timing.Child.capture().record.?;
    try directory.directory.dir.writeFile(io, .{ .sub_path = timing.child_name, .data = &try child.encode(), .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) } });
    const report = parent.collect(a, io, directory.path);
    try t.expectEqual(timing.ChildStatus.entry, report.summary.child);
    try t.expectEqualDeep(child, report.child.?);
    try report.write(io, directory.path);
    try t.expectError(error.PathAlreadyExists, report.write(io, directory.path));
    try directory.directory.dir.deleteFile(io, timing.child_name);
    const retained = try directory.directory.read(io, a, "synthetic-host-timing-setup_refusal-v1.jsonl", timing.max_bytes, null);
    defer a.free(retained);
    try t.expect(std.mem.indexOf(u8, retained, "\"child\":\"entry\"") != null);
    try t.expect(std.mem.indexOf(u8, retained, "\"stage\":\"call_error\"") != null);
}

test "host timing process scope reuse and observer faults retain parent prefix" {
    var parent: timing.Parent = .init(.observer_refusal, 1);
    parent.start();
    defer parent.stop();
    timing.begin(1);
    var other: timing.Parent = .init(.observer_refusal, 1);
    other.start();
    try t.expectEqual(timing.Fault.reused, other.fault.?);
    timing.mark(.job_ready);
    try t.expectEqual(timing.Fault.invalid, parent.fault.?);
    try t.expectEqual(@as(usize, 1), parent.records.count);
    timing.mark(.process_call);
    try t.expectEqual(timing.Cleanup.unconfirmed, parent.cleanup);
    timing.returned(true);
    try t.expectEqual(timing.Cleanup.complete, parent.cleanup);
    parent.pid = 0;
    timing.mark(.call_error);
    try t.expectEqual(timing.Fault.process_changed, parent.fault.?);
    try t.expectEqual(@as(usize, 1), parent.records.count);
}
