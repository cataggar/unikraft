const std = @import("std");
const host = @import("host");
const p = host.protocol;
const f = @import("fixture_support.zig");
const a = std.testing.allocator;
const io = std.testing.io;
const t = std.testing;

fn image(budget: f.AdmissionBudget, runner_size: u64) !host.native.Image {
    const bytes = try f.admissionBytesWithBudget(budget);
    defer a.free(bytes);
    return .{
        .admission = try p.Admission.parse(a, bytes, f.key(), f.now, f.runner_hash, runner_size),
        .runner_size = runner_size,
        .policy_bytes = bytes.len,
    };
}

fn startupImage(control_total: u64, staging_total: u64, locator_bytes: usize) !host.native.Image {
    var policy_bytes: usize = 0;
    for (0..8) |_| {
        const startup = try p.startupControlBytes(policy_bytes, locator_bytes);
        var result = try image(.{
            .image_control_bytes = control_total - startup,
            .image_staging_bytes = staging_total - startup,
        }, 256);
        if (result.policy_bytes == policy_bytes) return result;
        policy_bytes = result.policy_bytes;
        result.deinit();
    }
    return error.UnstableFixtureSize;
}

fn initial(control: u64, staged: u64) !host.state.Record {
    return host.state.Record.initial(f.uuid(f.run_text), f.uuid(f.vm_text), f.uuid(f.public_nonce_text), staged, control);
}

test "native-only control cap is 2 MiB and complete subtotals have no exemption" {
    try t.expectEqual(@as(u64, 2097152), p.max_control);
    try t.expectEqual(@as(u64, 268435456), p.max_staging);
    const runner: u64 = 800 * 1024;
    const unit: u64 = p.service_unit_bytes;
    const other = p.max_control - runner - unit;
    try t.expectEqual(p.max_control, try p.controlTotal(&.{ runner, unit, other }));
    try t.expectError(error.ControlAllowanceExceeded, p.controlTotal(&.{ runner, unit, other + 1 }));
    try t.expectError(error.ControlAllowanceExceeded, p.controlTotal(&.{ p.max_control, unit }));
    try t.expectError(error.ControlAllowanceExceeded, p.controlTotal(&.{ 1, std.math.maxInt(u64) }));
}

test "signed image accounting rejects omitted unit underreported totals and policy changes" {
    var admitted = try image(.{}, 256);
    defer admitted.deinit();
    try t.expectEqual(f.image_controls, admitted.admission.image_control_bytes);
    try t.expectEqual(f.image_controls + 512, admitted.admission.image_staging_bytes);
    try t.expectError(error.InvalidBudget, image(.{ .image_control_bytes = 256 + p.service_unit_bytes - 1 }, 256));
    try t.expectError(error.InvalidBudget, image(.{ .image_control_bytes = p.max_control + 1, .image_staging_bytes = p.max_control + 1 }, 256));
    try t.expectError(error.InvalidBudget, image(.{ .image_staging_bytes = f.image_controls - 1 }, 256));
    try t.expectError(error.InvalidBudget, image(.{ .image_staging_bytes = p.max_staging + 1 }, 256));
    try t.expectError(error.ControlAllowanceExceeded, image(.{}, p.max_control + 1));
    try t.expectError(error.ControlAllowanceExceeded, image(.{ .control_bytes = 524288 }, 256));
    try t.expectError(error.ControlAllowanceExceeded, image(.{ .control_bytes = p.max_control + 1 }, 256));
    try t.expectError(error.InvalidBudget, image(.{ .staging_bytes = p.max_staging + 1 }, 256));
}

test "pre-network startup gate includes metadata emergency and both bounded ledger writes" {
    const locator_bytes = 123;
    var exact = try startupImage(p.max_control, p.max_staging, locator_bytes);
    defer exact.deinit();
    const startup = try p.startupControlBytes(exact.policy_bytes, locator_bytes);
    try t.expectEqual(exact.policy_bytes + locator_bytes + p.startup_control + p.emergency_control + 2 * p.max_record, startup);
    try t.expectEqual(p.max_control, exact.admission.image_control_bytes + startup);
    try t.expectEqual(p.max_staging, exact.admission.image_staging_bytes + startup);
    try exact.validateStartup(locator_bytes);

    var controls_over = try startupImage(p.max_control + 1, p.max_staging, locator_bytes);
    defer controls_over.deinit();
    try t.expectError(error.ControlAllowanceExceeded, controls_over.validateStartup(locator_bytes));
    var staging_over = try startupImage(p.max_control, p.max_staging + 1, locator_bytes);
    defer staging_over.deinit();
    try t.expectError(error.StagingBudgetExceeded, staging_over.validateStartup(locator_bytes));
    var no_startup_room = try image(.{ .image_control_bytes = p.max_control, .image_staging_bytes = p.max_control }, 256);
    defer no_startup_room.deinit();
    try t.expectError(error.ControlAllowanceExceeded, no_startup_room.validateStartup(locator_bytes));
    try t.expectError(error.InvalidBudget, exact.validateStartup(p.max_locator + 1));
    try t.expectError(error.InvalidBudget, p.startupControlBytes(p.max_command + 1, locator_bytes));
}

test "emergency reservation is included and never substitutes for ledger space" {
    const controls = p.max_control - p.emergency_control;
    const staged = p.max_staging - p.emergency_control;
    const record = try initial(controls, staged);
    try t.expectEqual(p.max_control, record.control_bytes);
    try t.expectEqual(p.max_staging, record.staging_bytes);
    try t.expectError(error.InvalidBudget, initial(controls + 1, staged));
    try t.expectError(error.InvalidBudget, initial(controls, staged + 1));
    const directory = try f.Directory.create("budget-emergency");
    defer directory.deinit();
    var lock = try directory.directory.lock(io);
    defer lock.close(io);
    try t.expectError(error.RecordingBudgetExceeded, host.state.Store.open(a, io, &lock, record));
    try t.expectError(error.FileNotFound, directory.directory.openFile(io, "state.json"));
}

test "ledger-inclusive exact total commits and one byte over preserves prior state" {
    const directory = try f.Directory.create("budget-ledger");
    defer directory.deinit();
    var lock = try directory.directory.lock(io);
    defer lock.close(io);
    var store = try host.state.Store.open(a, io, &lock, try initial(f.image_controls, f.image_controls + 512));
    const before = store.record;
    var final_record = before;
    final_record.control_bytes = p.max_control;
    final_record.staging_bytes = p.max_staging;
    const exact_bytes = try store.encode(final_record);
    defer a.free(exact_bytes);

    store.record.control_bytes = p.max_control - exact_bytes.len;
    store.record.staging_bytes = p.max_staging - exact_bytes.len;
    try store.save();
    try t.expectEqual(p.max_control, store.record.control_bytes);
    try t.expectEqual(p.max_staging, store.record.staging_bytes);
    const persisted = try directory.directory.read(io, a, "state.json", p.max_record, p.hash(exact_bytes));
    defer a.free(persisted);
    try t.expectEqualSlices(u8, exact_bytes, persisted);

    store.record = before;
    store.record.control_bytes = p.max_control - exact_bytes.len + 1;
    store.record.staging_bytes = p.max_staging - exact_bytes.len;
    try t.expectError(error.RecordingBudgetExceeded, store.save());
    store.record = before;
    store.record.control_bytes = p.max_control - exact_bytes.len;
    store.record.staging_bytes = p.max_staging - exact_bytes.len + 1;
    try t.expectError(error.RecordingBudgetExceeded, store.save());
    const unchanged = try directory.directory.read(io, a, "state.json", p.max_record, p.hash(exact_bytes));
    defer a.free(unchanged);
    try t.expectEqualSlices(u8, exact_bytes, unchanged);
}

test "later control reservations count their ledger writes at the boundary" {
    const directory = try f.Directory.create("budget-reserve");
    defer directory.deinit();
    var lock = try directory.directory.lock(io);
    defer lock.close(io);
    var store = try host.state.Store.open(a, io, &lock, try initial(f.image_controls, f.image_controls));
    var final_record = store.record;
    final_record.control_bytes = p.max_control;
    final_record.staging_bytes = p.max_control;
    const bytes = try store.encode(final_record);
    defer a.free(bytes);
    const remaining = p.max_control - store.record.control_bytes;
    try store.reserve(remaining - bytes.len, true, false);
    try t.expectEqual(p.max_control, store.record.control_bytes);
    try t.expectEqual(p.max_control, store.record.staging_bytes);
    try t.expectError(error.ControlAllowanceExceeded, store.reserve(1, true, false));
    // Even a zero-byte payload needs a new accounted state version.
    try t.expectError(error.RecordingBudgetExceeded, store.reserve(0, true, false));
}
