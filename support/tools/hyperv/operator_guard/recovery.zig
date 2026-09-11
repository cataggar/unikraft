const std = @import("std");
const r = @import("records.zig");
const k = @import("kernel.zig");

/// A private signed kernel witness is necessary. PID absence, a free lock,
/// missing output, or a caller's claim can never synthesize that witness.
pub fn load(a: std.mem.Allocator, io: std.Io, directory: r.core.private_files.Directory, expected: r.Expected) !r.Proof {
    return (inspect(a, io, directory, expected)).proof orelse error.ProcessRecoveryRequired;
}
pub const Inspection = struct {
    proof: ?r.Proof = null,
    failures: r.core.diagnostics.Failures = .{},
    reason: enum { stopped, pending, rejected, local_io } = .stopped,
};
pub fn inspect(a: std.mem.Allocator, io: std.Io, directory: r.core.private_files.Directory, expected: r.Expected) Inspection {
    const proof = loadChecked(a, io, directory, expected) catch |err| {
        var result: Inspection = .{ .reason = .rejected };
        switch (err) {
            error.MissingRegistration, error.MissingSeal, error.WriterStillActive => {
                result.reason = .pending;
                result.failures.cleanup = .{ .stage = .process_cleanup, .category = .ambiguous };
            },
            error.AccessDenied, error.InputOutput, error.ReadFailed, error.FileChanged, error.SystemResources => {
                result.reason = .local_io;
                result.failures.recording = .{ .stage = .state_record, .category = .local_io };
            },
            else => result.failures.primary = .{ .stage = .admission, .category = .integrity },
        }
        return result;
    };
    return .{ .proof = proof, .failures = proof.failures };
}
fn loadChecked(a: std.mem.Allocator, io: std.Io, directory: r.core.private_files.Directory, expected: r.Expected) !r.Proof {
    try expected.validate();
    const proc = try k.openProc();
    defer k.close(proc);
    const bytes = directory.read(io, a, "custody-registration.json", r.max_record, null) catch |err| switch (err) {
        error.FileNotFound => return error.MissingRegistration,
        else => return err,
    };
    defer a.free(bytes);
    const registration = try r.verify(r.Registration, a, bytes, expected.public_key, "uk-operator-custody-registration-v1");
    defer registration.deinit();
    const value = registration.value;
    if (!std.mem.eql(u8, value.schema, "uk-operator-custody-registration-v1") or !std.meta.eql(value.expected, expected) or
        !std.mem.eql(u8, &value.boot, &try k.boot(proc)) or !std.meta.eql(value.directory, try k.directory(directory.dir.handle)) or
        value.custodian.pid <= 1 or value.namespace_init.pid <= 1 or value.owner.pid <= 1 or
        value.custodian.start_ticks == 0 or value.namespace_init.start_ticks == 0 or
        value.registered_ns == 0 or value.registered_ns >= value.deadline_ns or
        value.cleanup_ms < 100 or value.cleanup_ms > 1200000 or
        std.meta.eql(value.namespace_init.namespace, value.custodian.namespace))
        return error.InvalidRegistration;
    try expected.budget.reserve(value.control_reserved);
    const claim_bytes = try directory.read(io, a, "custody-claim.json", r.max_record, null);
    defer a.free(claim_bytes);
    const Claim = struct { nonce: r.Hash, expected: r.Expected };
    const claim = try r.parse(Claim, a, claim_bytes);
    defer claim.deinit();
    if (!std.meta.eql(claim.value.expected, expected) or !std.mem.eql(u8, &claim.value.nonce, &value.nonce)) return error.InvalidClaim;
    const seal_bytes = directory.read(io, a, "custody-seal.json", r.max_record, null) catch |err| switch (err) {
        error.FileNotFound => return error.MissingSeal,
        else => return err,
    };
    defer a.free(seal_bytes);
    const sealed = try r.verify(r.Seal, a, seal_bytes, expected.public_key, "uk-operator-custody-seal-v1");
    defer sealed.deinit();
    const seal = sealed.value;
    if (!std.mem.eql(u8, seal.schema, "uk-operator-custody-seal-v1") or
        !std.mem.eql(u8, &seal.registration, &r.hash(bytes)) or seal.stopped_ns < value.registered_ns or seal.stopped_ns > try k.now() or
        seal.failures.cleanup != null or seal.failures.recording != null) return error.InvalidSeal;
    if (seal.cause == .completed and (seal.failures.primary != null or seal.worker_status == null or
        !k.linux.W.IFEXITED(seal.worker_status.?) or k.linux.W.EXITSTATUS(seal.worker_status.?) != 0 or
        !k.linux.W.IFEXITED(seal.init_status) or k.linux.W.EXITSTATUS(seal.init_status) != 0))
        return error.InvalidSeal;
    // A signed namespace witness can survive custodian exit. If the process
    // still exists, pin it and reject active or substituted writer identities.
    const descriptor = k.linux.pidfd_open(value.custodian.pid, 0);
    switch (k.linux.errno(descriptor)) {
        .SRCH => {},
        .SUCCESS => {
            const retained: i32 = @intCast(descriptor);
            defer k.close(retained);
            if (try k.startTicks(proc, value.custodian.pid) != value.custodian.start_ticks or !try k.readable(retained))
                return error.WriterStillActive;
        },
        else => return error.ProcessRecoveryRequired,
    }
    return .{ .registration = r.hash(bytes), .seal = r.hash(seal_bytes), .expected = expected, .boot = value.boot, .namespace_init = value.namespace_init, .cause = seal.cause, .failures = seal.failures };
}

pub fn awaitStopped(a: std.mem.Allocator, io: std.Io, directory: r.core.private_files.Directory, expected: r.Expected, deadline: r.core.process.Deadline) !r.Proof {
    while (!try deadline.expired()) {
        const result = inspect(a, io, directory, expected);
        if (result.proof) |proof| return proof;
        if (result.reason != .pending) return error.ProcessRecoveryRequired;
        k.pause();
    }
    return error.ProcessRecoveryRequired;
}
