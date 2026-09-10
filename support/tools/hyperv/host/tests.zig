const std = @import("std");
const host = @import("host");
const p = host.protocol;
const f = @import("fixture_support.zig");

test {
    _ = @import("wire_fixtures.zig");
    _ = @import("phase_fixtures.zig");
    _ = @import("serial_fixtures.zig");
}

test "scope and native Ed25519 reject untrusted configuration" {
    const run = try host.core.contracts.parseUuid("01234567-89ab-4cde-8fab-0123456789ab");
    try (p.Scope{ .account = "fixture", .container = "private", .run_id = run }).validate();
    try std.testing.expectError(error.InvalidEndpoint, (p.Scope{ .account = "fixture.evil", .container = "private", .run_id = run }).validate());
    try std.testing.expectError(error.InvalidSignature, p.verify(std.testing.allocator, "{\"body\":{},\"signature\":\"00\"}", [_]u8{0} ** 32, "uk-hyperv-host-command-v1"));
}

test "image authority requires correct signature runner envelope and control allowance" {
    const bytes = try f.admissionBytes();
    defer std.testing.allocator.free(bytes);
    var admitted = try f.admission();
    defer admitted.deinit();
    try std.testing.expectError(error.InvalidSignature, p.Admission.parse(std.testing.allocator, bytes, [_]u8{1} ** 32, f.now, f.runner_hash, 256));
    try std.testing.expectError(error.RunnerMismatch, p.Admission.parse(std.testing.allocator, bytes, f.key(), f.now, p.hash("wrong"), 256));
    try std.testing.expectError(error.ControlAllowanceExceeded, p.Admission.parse(std.testing.allocator, bytes, f.key(), f.now, f.runner_hash, p.max_control + 1));
    try std.testing.expectError(error.StaleCommand, p.Admission.parse(std.testing.allocator, bytes, f.key(), 2000, f.runner_hash, 256));
    try std.testing.expectError(error.InvalidSignature, p.verify(std.testing.allocator, bytes, f.key(), "uk-hyperv-host-command-v1"));
}

test "bootstrap locator cannot carry credentials alternate endpoints or trust roots" {
    var admitted = try f.admission();
    defer admitted.deinit();
    var valid = try host.native.parseLocator(std.testing.allocator, "{\"account\":\"fixture\",\"container\":\"private\",\"run_id\":\"" ++ f.run_text ++ "\"}", &admitted);
    defer valid.document.deinit();
    const invalid = [_][]const u8{
        "{\"account\":\"other\",\"container\":\"private\",\"run_id\":\"" ++ f.run_text ++ "\"}",
        "{\"account\":\"fixture\",\"container\":\"private\",\"run_id\":\"" ++ f.run_text ++ "\",\"key\":\"untrusted\"}",
        "{\"account\":\"fixture\",\"container\":\"private\",\"run_id\":\"" ++ f.run_text ++ "\",\"sas\":\"SYNTHETIC_SECRET\"}",
        "{\"account\":\"fixture\",\"container\":\"private\",\"run_id\":\"" ++ f.run_text ++ "\",\"imds_url\":\"http://evil.invalid/\"}",
    };
    for (invalid) |bytes| {
        if (host.native.parseLocator(std.testing.allocator, bytes, &admitted)) |parsed| {
            parsed.document.deinit();
            return error.AcceptedUntrustedLocator;
        } else |_| {}
    }
}
