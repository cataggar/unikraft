const std = @import("std");
const host = @import("host");
const f = @import("fixture_support.zig");
const a = std.testing.allocator;
const t = std.testing;
const prefix = "Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by\nCalling main(\n";

fn unavailable(main: []const u8, extra: []const u8) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(a);
    defer writer.deinit();
    try writer.writer.writeAll(prefix ++ "UK_HYPERV_PLATFORM_READY\n");
    for (host.serial.unavailable_records) |record| {
        try writer.writer.writeAll(record);
        try writer.writer.writeByte('\n');
    }
    try writer.writer.writeAll(host.serial.unavailable_marker ++ "\n");
    try writer.writer.writeAll(main);
    try writer.writer.writeByte('\n');
    try writer.writer.writeAll(extra);
    return writer.toOwnedSlice();
}

test "exact capability legacy APIC and main-return gates reject false positive serial" {
    const valid = [_][]const u8{ "main returned 2", "[ 1.2] Info: [app] <main.c:9>: main returned 2", "Info: main returned 2", "[component] main returned 2", "[.5] main returned 2", "[1.] main returned 2", "[..] main returned 2" };
    for (valid) |main| {
        const bytes = try unavailable(main, "");
        defer a.free(bytes);
        try host.serial.validate(a, bytes, .platform_unavailable, false, null);
    }
    const bad = [_][]const u8{ "main returned 0", "prefix main returned 2", "Info:main returned 2", "[app]main returned 2", "[1 ] main returned 2", "<main.c> : main returned 2", "main returned +2", "main returned 2 trailing" };
    for (bad) |main| {
        const bytes = try unavailable(main, "");
        defer a.free(bytes);
        if (host.serial.validate(a, bytes, .platform_unavailable, false, null)) |_| return error.AcceptedInvalidMainReturn else |_| {}
    }
    const forbidden = [_][]const u8{ "Hyper-V SynIC:\n", "UK_HYPERV_PLATFORM_READY\n", "main returned 2\n", "Unikraft Crash\n", "Assertion failure\n", "Exception Type\n", "Using legacy xAPIC MMIO\n", "UK_HYPERV_IO_READY\n", "UK_HYPERV_NET_APP_ARP\n", "HYPERV_STORAGE READ PASS\n", "FAIL\n" };
    for (forbidden) |extra| {
        const bytes = try unavailable("main returned 2", extra);
        defer a.free(bytes);
        if (host.serial.validate(a, bytes, .platform_unavailable, false, null)) |_| return error.AcceptedForbiddenSerial else |_| {}
    }
    const legacy = try unavailable("main returned 2", "Using legacy xAPIC MMIO\n");
    defer a.free(legacy);
    try host.serial.validate(a, legacy, .platform_unavailable, true, null);
    const plain = try unavailable("main returned 2", "");
    defer a.free(plain);
    try t.expectError(error.InvalidBootEvidence, host.serial.validate(a, plain, .platform_unavailable, true, null));
}

test "ANSI NUL bounded normalization and exact unavailable ordered records" {
    const bytes = try unavailable("\x1b[32mmain returned 2\x1b[0m\x00", "");
    defer a.free(bytes);
    try host.serial.validate(a, bytes, .platform_unavailable, false, null);
    const extra = try unavailable("main returned 2", host.serial.unavailable_records[1] ++ "\n");
    defer a.free(extra);
    try t.expectError(error.InvalidUnavailableEvidence, host.serial.validate(a, extra, .platform_unavailable, false, null));
    const over = try a.alloc(u8, host.protocol.max_serial + 1);
    defer a.free(over);
    @memset(over, 'x');
    try t.expectError(error.SerialLimit, host.serial.validate(a, over, .platform_unavailable, false, null));
}

test "platform main-zero excludes live IO and unavailable evidence" {
    try host.serial.validate(a, prefix ++ "UK_HYPERV_PLATFORM_READY\nmain returned 0\n", .platform_main_zero, false, null);
    try t.expectError(error.UnexpectedUnavailable, host.serial.validate(a, prefix ++ "UK_HYPERV_PLATFORM_READY\nmain returned 0\nUNAVAILABLE\n", .platform_main_zero, false, null));
}

test "guarded persistence requires exact identity zero IO and strict marker order" {
    const guarded: host.protocol.Guarded = .{ .run_id = "0123456789abcdef0123456789abcdef", .disk_id = "fedcba9876543210fedcba9876543210", .lun = 17, .sectors = 4096, .solved_config_sha256 = f.runner_hash, .producer_sha256 = f.producer_hash };
    const start = "HYPERV_PERSISTENCE START PASS run=0123456789abcdef0123456789abcdef address=0:0:17 sectors=4096 sector_size=512\n";
    const select = "HYPERV_PERSISTENCE SELECT UNAVAILABLE reason=no-devices writes=0 flushes=0\n";
    const tail = "UK_HYPERV_PLATFORM_READY\nUK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices\nmain returned 2\n";
    try host.serial.validate(a, prefix ++ start ++ select ++ tail, .guarded_v2, false, guarded);
    try t.expectError(error.InvalidGuardedEvidence, host.serial.validate(a, prefix ++ select ++ start ++ tail, .guarded_v2, false, guarded));
    try t.expectError(error.UnexpectedGuardedActivity, host.serial.validate(a, prefix ++ start ++ select ++ tail ++ "HYPERV_STORAGE READ PASS\n", .guarded_v2, false, guarded));
    try t.expectError(error.InvalidGuardedContract, host.serial.validate(a, prefix ++ start ++ select ++ tail, .guarded_v2, false, null));
    var bad = guarded;
    bad.disk_id = "short";
    try t.expectError(error.InvalidGuardedContract, host.serial.validate(a, prefix ++ start ++ select ++ tail, .guarded_v2, false, bad));
    bad = guarded;
    bad.sectors = 48;
    try t.expectError(error.InvalidGuardedContract, host.serial.validate(a, prefix ++ start ++ select ++ tail, .guarded_v2, false, bad));
}
