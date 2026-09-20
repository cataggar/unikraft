// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const compute = @import("compute.zig");
pub const wamr_direct_compute = true;

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    core.private_files.enterUserNamespaceFromEnvironment(
        init.environ_map,
    ) catch std.process.exit(1);
    run(init) catch |err| {
        if (err == error.EvidenceIncomplete) std.process.exit(2);
        var writer = std.Io.File.stderr().writerStreaming(init.io, &.{});
        writer.interface.print("WAMR direct validation refused: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 3) return error.InvalidCommand;
    if (args.len == 3 and std.mem.eql(u8, args[1], "handoff")) {
        var bytes = try core.private_files.readSensitiveAbsolute(init.io, a, args[2], 65536, null);
        defer bytes.deinit();
        try compute.verifyHandoff(a, init.io, bytes.bytes());
        var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
        try writer.interface.writeAll("Compute handoff revalidated; authority=not_admitted.\n");
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "candidate")) {
        const candidate = try compute.loadCandidateScope(a, init.io, args[2]);
        defer candidate.deinit();
        if (candidate.value.authority != .not_admitted) return error.InvalidScope;
        try compute.inspect(a, init.io, candidate.value);
        var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
        try writer.interface.writeAll("Compute candidate revalidated; authority=not_admitted.\n");
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "azure-runtime"))
        return compute.verifyAzureRuntime(a, init.io, args[2]);
    if (args.len == 3 and std.mem.eql(u8, args[1], "legacy-scope")) {
        const candidate = try compute.loadCandidateScope(a, init.io, args[2]);
        defer candidate.deinit();
        return candidate.value.validate();
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "plan"))
        return compute.verifyPlan(a, init.io, args[2], args[3]);
    if (args.len == 4 and std.mem.eql(u8, args[1], "authorization"))
        return compute.verifyAuthorization(a, init.io, args[2], args[3], true);
    if (args.len == 5 and std.mem.eql(u8, args[1], "ledger-proposal")) {
        const proposal = try compute.ledgerProposal(a, init.io, args[2], args[3], args[4]);
        const bytes = try compute.ledgerBindingBytes(a, proposal);
        var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
        try writer.interface.writeAll(bytes);
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "admission"))
        return compute.verifyAdmission(a, init.io, args[2], true);
    if (args.len == 3 and std.mem.eql(u8, args[1], "scope")) {
        return compute.verifyAdmission(a, init.io, args[2], true);
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "stored-scope")) {
        const scope = try compute.loadScope(a, init.io, args[2]);
        defer scope.deinit();
        const now = std.Io.Clock.real.now(init.io).toSeconds();
        if (now < 0) return error.InvalidClock;
        return scope.value.current(@intCast(now));
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "ledger")) {
        const scope = try compute.loadScope(a, init.io, args[2]);
        defer scope.deinit();
        if (!std.mem.eql(u8, scope.value.ledger_path, args[3])) return error.WrongAdmissionInput;
        const dir = try core.private_files.Directory.open(init.io, args[3]);
        dir.close(init.io);
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "legacy-ledger")) {
        const scope = try compute.loadCandidateScope(a, init.io, args[2]);
        defer scope.deinit();
        try scope.value.validate();
        const dir = try core.private_files.Directory.open(init.io, args[3]);
        dir.close(init.io);
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "json")) {
        var bytes = try core.private_files.readSensitiveAbsolute(init.io, a, args[3], 65536, null);
        defer bytes.deinit();
        const doc = try core.contracts.SensitiveDocument.parse(a, bytes.bytes(), .{ .bytes = 65536 });
        defer doc.deinit();
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "inputs")) {
        const scope = compute.loadScope(a, init.io, args[2]) catch {
            const candidate = try compute.loadCandidateScope(a, init.io, args[2]);
            defer candidate.deinit();
            return compute.inspect(a, init.io, candidate.value);
        };
        defer scope.deinit();
        return compute.inspectAdmission(a, init.io, scope.value);
    }
    if ((args.len == 4 or args.len == 5) and std.mem.eql(u8, args[1], "serial")) {
        var scope_bytes = try core.private_files.readSensitiveAbsolute(init.io, a, args[2], 65536, null);
        defer scope_bytes.deinit();
        const document = try core.contracts.SensitiveDocument.parse(a, scope_bytes.bytes(), .{ .bytes = 65536, .items = 4096 });
        defer document.deinit();
        const object = switch (document.value()) {
            .object => |object| object,
            else => return error.InvalidScope,
        };
        const schema = try core.contracts.string(object.get("schema") orelse return error.InvalidScope);
        if (std.mem.eql(u8, schema, "uk.wamr.azure-execution-admission")) {
            try document.requireCanonical(scope_bytes.bytes());
            const scope = try compute.parse(compute.Admission, a, scope_bytes.bytes());
            defer scope.deinit();
            try scope.value.validate();
            return serial(init, a, args, scope.value.identity, scope.value.serial_mode);
        }
        const candidate = try compute.parse(compute.CandidateScope, a, scope_bytes.bytes());
        defer candidate.deinit();
        try candidate.value.validateCandidate();
        return serial(init, a, args, candidate.value.identity, candidate.value.serial_mode);
    }
    return error.InvalidCommand;
}

fn serial(init: std.process.Init, a: std.mem.Allocator, args: []const []const u8, identity: compute.Identity, mode: compute.SerialMode) !void {
    var first = try core.private_files.readSensitiveAbsolute(init.io, a, args[3], 4 * 1024 * 1024, null);
    defer first.deinit();
    var result = try compute.checkSerial(a, first.bytes(), identity);
    if (args.len == 5) {
        var second = try core.private_files.readSensitiveAbsolute(init.io, a, args[4], 4 * 1024 * 1024, null);
        defer second.deinit();
        result = try compute.checkSerial(a, try compute.secondBytes(second.bytes(), first.bytes(), mode), identity);
    }
    var writer = std.Io.File.stdout().writerStreaming(init.io, &.{});
    try std.json.Stringify.value(result, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
}
