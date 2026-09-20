// SPDX-License-Identifier: BSD-3-Clause
//! Native, non-resumable two-boot lifecycle. No cloud authority is discovered.
const std = @import("std");
const core = @import("hyperv_core");
const profile = @import("profile.zig");
const direct = profile.contract;
const runtime = @import("runtime.zig");
const custody = @import("custody.zig");
const observations = @import("observations.zig");
const local = @import("controller_io.zig");
const process = core.process;
const files = core.private_files;
const Role = observations.Role;
const Lane = runtime.Lane;
const launcher = @import("launcher.zig");

pub const Inputs = struct {
    scope: []const u8,
    attempt: []const u8,
    ledger: []const u8,
    programs: runtime.Programs,

    pub fn parse(args: []const []const u8) !Inputs {
        const fixed: usize = if (profile.authorization) 7 else 6;
        if (comptime profile.authorization) {
            if (args.len != 9 or !std.mem.eql(u8, args[7], "--az-python"))
                return error.InvalidArguments;
        } else if (args.len != 6 and args.len != 8) {
            return error.InvalidArguments;
        } else if (args.len == 8 and !std.mem.eql(u8, args[6], "--az-python")) {
            return error.InvalidArguments;
        }
        for (args[0..fixed]) |arg| {
            try files.absoluteFilePath(arg);
            if (std.mem.indexOfAny(u8, arg, "\r\n") != null) return error.InvalidArguments;
        }
        const result: Inputs = .{
            .scope = args[0],
            .attempt = args[1],
            .ledger = args[2],
            .programs = .{
                .azure = args[3],
                .uploader = args[4],
                .validator = args[5],
                .supervisor = if (profile.authorization) args[6] else null,
                .azure_python = if (profile.authorization) args[8] else if (args.len == 8) args[7] else null,
            },
        };
        try result.programs.validate();
        return result;
    }
};

/// Frozen jq compatibility: false=1, filter runtime error=5, malformed JSON=4.
/// Malformed grants first pass the native JSON child and retain its exit.
pub fn observationExit(err: anyerror) u8 {
    return switch (observations.failureClass(err)) {
        .filter_error => 5,
        .malformed => 4,
        .refused, .capture, .local => 1,
    };
}

pub const CallPolicy = enum { required, serial_poll, serial_parser };

pub fn primaryStatus(policy: CallPolicy, code: u8) ?u8 {
    return if (policy == .required and code != 0) code else null;
}

pub fn recordCaptureFailure(store: *custody.Store, lane: Lane, primary: *u8, capture: process.CaptureState, status: u8) ?anyerror {
    const err = switch (capture) {
        .io_failed => error.CaptureIoFailed,
        .durability_failed => error.CaptureDurabilityFailed,
        .complete, .partial, .overflow => return null,
    };
    std.debug.assert(status != 0);
    store.recordingFailed(err);
    if (lane == .primary and primary.* == 0) primary.* = status;
    return err;
}

pub fn checkScopeEvidence(store: *custody.Store, primary: *u8) !void {
    store.verifyScope() catch |err| {
        if (primary.* == 0) primary.* = 1;
        return err;
    };
}

pub fn finalExit(result: custody.FinalResult, signal: ?u8) u8 {
    custody.requireDurable(result.recording) catch
        return if (result.outcome.primary_exit != 0) result.outcome.primary_exit else 1;
    if (result.exit_code == 0 and (result.evidence_error != null or result.recording_error != null or
        result.cleanup_error != null or !result.outcome.accepted)) return 1;
    if (result.exit_code == 0) {
        if (signal) |number| return 128 + number;
    }
    return result.exit_code;
}

pub const errorExit = runtime.errorExit;
pub const processExit = runtime.processExit;

pub const ChildTermination = struct { exit: ?u8 = null, signal: ?u32 = null, stopped: ?u32 = null, unknown: ?u32 = null };

pub fn childTermination(result: process.PrivateResult) ChildTermination {
    return if (result.execution.termination) |termination| switch (termination) {
        .exited => |code| .{ .exit = code },
        .signal => |signal| .{ .signal = @intFromEnum(signal) },
        .stopped => |signal| .{ .stopped = @intFromEnum(signal) },
        .unknown => |status| .{ .unknown = status },
    } else .{};
}

pub const Native = struct {
    pub const References = custody.References;

    pub fn references(_: Native, io: std.Io, scope: direct.Scope, programs: runtime.Programs) !References {
        var refs = try References.capture(io, scope, programs.azure, programs.uploader, programs.validator);
        if (programs.azure_python) |path| refs.interpreter = try custody.Reference.tool(io, path);
        return refs;
    }

    pub fn environment(_: Native, a: std.mem.Allocator, operator: *const std.process.Environ.Map) !runtime.Environment {
        return runtime.Environment.init(a, operator);
    }

    // The offline adapter can inject failure; Store always performs real hashing.
    pub fn checkHashFault(_: Native, _: *custody.Store, _: []const u8) !u8 {
        return 0;
    }

    pub fn sleep(_: Native, io: std.Io, milliseconds: u64) !void {
        try std.Io.sleep(io, .fromMilliseconds(@intCast(milliseconds)), .awake);
    }
};

/// The installed entry point instantiates Native only. Offline hooks live in a
/// separate, non-installed executable, never in a CLI/config/environment mode.
pub fn execute(comptime Hooks: type, hooks: Hooks, init: std.process.Init, inputs: Inputs) !u8 {
    const a = init.arena.allocator();
    const Admission = if (profile.authorization) direct.Admission else void;
    var admitted: ?std.json.Parsed(Admission) = null;
    defer if (admitted) |*value| value.deinit();
    if (comptime profile.authorization) {
        admitted = try direct.preAdmission(
            a,
            init.io,
            inputs.scope,
            inputs.ledger,
            inputs.programs.azure,
            inputs.programs.uploader,
            inputs.programs.validator,
            inputs.programs.supervisor.?,
            inputs.programs.azure_python.?,
        );
        try custody.checkEligibility(init.io, admitted.?.value, inputs.ledger);
    }
    var cancellation = try process.SignalCancellation.install();
    defer cancellation.deinit();
    var environment = try hooks.environment(a, init.environ_map);
    defer environment.deinit();
    const interpreter = try launcher.selectInterpreter(init.io, &environment, inputs.programs.azure_python);
    const tools: [3]custody.Reference = .{
        try custody.Reference.tool(init.io, inputs.programs.azure),
        try custody.Reference.tool(init.io, inputs.programs.uploader),
        try custody.Reference.tool(init.io, inputs.programs.validator),
    };
    const supervisor = if (inputs.programs.supervisor) |path|
        try custody.Reference.tool(init.io, path)
    else
        null;
    if (comptime profile.authorization) {
        const scope = admitted.?.value;
        inline for (.{ "azure", "uploader", "validator" }, 0..) |name, index| {
            try direct.inspectArtifact(init.io, @field(scope.tools, name));
            try tools[index].verify(init.io);
        }
        try direct.inspectArtifact(init.io, scope.tools.supervisor);
        try supervisor.?.verify(init.io);
        try direct.inspectArtifact(init.io, scope.tools.az_python);
        try interpreter.?.verify(init.io);
    }
    const source = try files.openAbsolute(init.io, inputs.scope, .private);
    defer source.close(init.io);
    const source_pin: custody.Reference = .{ .path = inputs.scope, .policy = .private, .metadata = try files.snapshot(source) };
    var store = try custody.Store.create(init.gpa, init.io, inputs.scope, inputs.attempt, inputs.ledger);
    defer store.close();
    try source_pin.verify(init.io);
    var budgets = runtime.Budgets.start(store.scope.value) catch return 1;
    const expected = try observations.Expectations.init(a, store.scope.value);
    defer expected.deinit();
    var controller: Controller(Hooks) = .{
        .a = a,
        .temporary = init.gpa,
        .io = init.io,
        .inputs = inputs,
        .hooks = hooks,
        .store = &store,
        .expected = expected,
        .source = source_pin,
        .tools = tools,
        .supervisor = supervisor,
        .runtime = .{
            .allocator = init.gpa,
            .io = init.io,
            .programs = inputs.programs,
            .environment = &environment,
            .budgets = &budgets,
            .cancellation = &cancellation,
            .interpreter = interpreter,
        },
    };
    try controller.runtime.initialize();
    controller.primary() catch |err| {
        if (controller.primary_exit == 0) controller.primary_exit = errorExit(err, &cancellation);
        controller.log("direct controller refused: {s}\n", .{@errorName(err)});
    };
    // A signal arriving between child calls still belongs to the primary lane.
    if (controller.primary_exit == 0 and cancellation.flag().load(.acquire))
        controller.primary_exit = errorExit(error.Cancelled, &cancellation);
    const phase = store.phase;
    controller.cleanup();
    if (controller.primary_exit == 0 and cancellation.flag().load(.acquire))
        controller.primary_exit = errorExit(error.Cancelled, &cancellation);
    controller.writeLog();
    const final = store.finish(.{
        .phase = phase,
        .primary_exit = controller.primary_exit,
        .cleanup_exit = controller.cleanup_exit,
        .persistence_evidence_complete = controller.complete,
        .owned_group_absent = controller.absent,
        .group_creation_attempted = controller.group_intended,
        .failure_diagnostics = controller.diagnostics,
        .final_input_exit = controller.final_input_exit,
    });
    return finalExit(final, cancellation.signal());
}

pub const testing = if (@import("builtin").is_test) struct {
    pub const State = Controller(Native);

    pub fn cleanup(state: *State) void {
        state.cleanup();
    }
} else struct {};

fn Controller(comptime Hooks: type) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        temporary: std.mem.Allocator,
        io: std.Io,
        inputs: Inputs,
        hooks: Hooks,
        store: *custody.Store,
        expected: observations.Expectations,
        source: custody.Reference,
        runtime: runtime.Runtime,
        references: ?Hooks.References = null,
        tools: ?[3]custody.Reference = null,
        supervisor: ?custody.Reference = null,
        primary_exit: u8 = 0,
        cleanup_exit: u8 = 0,
        final_input_exit: ?u8 = null,
        poisoned: bool = false,
        group_intended: bool = false,
        granted: [2]bool = .{ false, false },
        disk_uuids: [2]?[]const u8 = .{ null, null },
        vm_uuid: ?[]const u8 = null,
        boot_vm: [2]?custody.FileSnapshot = .{ null, null },
        final_observations: ?custody.Retained = null,
        complete: bool = false,
        absent: bool = false,
        diagnostics: custody.Diagnostics = .{},
        log_bytes: std.ArrayList(u8) = .empty,
        log_failed: bool = false,

        fn fmt(self: *Self, comptime format: []const u8, args: anytype) ![]const u8 {
            return std.fmt.allocPrint(self.a, format, args);
        }

        fn path(self: *Self, name: []const u8) ![]const u8 {
            return self.fmt("{s}/{s}", .{ self.inputs.attempt, name });
        }

        fn log(self: *Self, comptime format: []const u8, args: anytype) void {
            const bytes = self.fmt(format, args) catch {
                self.log_failed = true;
                return;
            };
            self.log_bytes.appendSlice(self.a, bytes) catch {
                self.log_failed = true;
            };
        }

        fn writeLog(self: *Self) void {
            if (self.log_failed) self.cleanup_exit = 1;
            custody.requireDurable(self.store.writer.createImmutable(self.io, "driver.stderr", self.log_bytes.items) catch {
                self.cleanup_exit = 1;
                return;
            }) catch {
                self.cleanup_exit = 1;
            };
        }

        fn event(self: *Self, phase: custody.Phase) !void {
            try self.store.event(phase);
        }

        fn stopped(self: *Self) !void {
            if (self.runtime.cancellation.flag().load(.acquire)) return error.Cancelled;
        }

        fn verifyTools(self: *Self) !void {
            try local.verifyDirectory(self.io, self.store.directory, self.inputs.attempt);
            try local.verifyDirectory(self.io, self.store.ledger, self.inputs.ledger);
            try local.verifyLock(self.io, &self.store.writer);
            if (self.tools) |tools| {
                for (tools) |tool| try tool.verify(self.io);
            } else return error.MissingToolReferences;
            if (self.supervisor) |tool| try tool.verify(self.io);
            try self.runtime.verifyInterpreter();
        }

        fn verifyPrimary(self: *Self) !void {
            try self.stopped();
            try self.source.verify(self.io);
            try self.store.verifyScope();
            if (self.references) |references| try references.verify(self.io);
            try self.verifyTools();
        }

        fn call(self: *Self, lane: Lane, role: runtime.Role, label: []const u8, args: []const []const u8, extension: []const u8) !u8 {
            return self.callWithPolicy(lane, role, .required, label, args, extension);
        }

        fn callWithPolicy(self: *Self, lane: Lane, role: runtime.Role, policy: CallPolicy, label: []const u8, args: []const []const u8, extension: []const u8) !u8 {
            if (self.poisoned) return error.UnresolvedCleanup;
            if (lane == .primary) try self.verifyPrimary() else try self.verifyTools();
            const result = self.runtime.run(lane, role, args, &self.store.writer, try self.fmt("{s}.{s}", .{ label, extension }), try self.fmt("{s}.stderr", .{label})) catch |err| {
                if (err == error.UnresolvedCleanup) self.poisoned = true;
                return err;
            };
            if (!result.execution.cleanup_complete or result.execution.unreaped_group != null) self.poisoned = true;
            const status = processExit(result, self.runtime.cancellation);
            // Preserve child failures before any local recording or recheck.
            // Poll failures and serial parser statuses have their own policy.
            if (lane == .primary) {
                if (primaryStatus(policy, status)) |code| self.primary_exit = code;
            }
            const capture_error = recordCaptureFailure(self.store, lane, &self.primary_exit, result.capture, status);
            // Process/capture/cleanup lanes remain visible even on child exits.
            {
                errdefer |err| {
                    self.store.recordingFailed(err);
                    self.cleanup_exit = 1;
                }
                const record = try custody.encode(self.a, .{
                    .role = role,
                    .lane = lane,
                    .policy = policy,
                    .exit = status,
                    .termination = childTermination(result),
                    .capture = result.capture,
                    .stdout_bytes = result.stdout_bytes,
                    .stderr_bytes = result.stderr_bytes,
                    .cleanup_complete = result.execution.cleanup_complete,
                    .failures = result.execution.failures,
                });
                try custody.requireDurable(try self.store.writer.createImmutable(self.io, try self.fmt("{s}.process.json", .{label}), record));
            }
            if (capture_error) |err| return err;
            if (lane == .primary) try self.verifyPrimary() else try self.verifyTools();
            if (self.poisoned) return error.UnresolvedCleanup;
            return status;
        }

        fn required(self: *Self, code: u8) !void {
            if (code != 0) {
                self.primary_exit = code;
                return error.ChildFailed;
            }
        }

        fn az(self: *Self, lane: Lane, label: []const u8, args: []const []const u8) !u8 {
            return self.azWithPolicy(lane, .required, label, args);
        }

        fn azWithPolicy(self: *Self, lane: Lane, policy: CallPolicy, label: []const u8, args: []const []const u8) !u8 {
            if (lane == .primary) try self.store.requireConsumed();
            const tail: []const []const u8 = &.{ "--subscription", self.expected.scope.subscription, "--only-show-errors", "--output", "json" };
            const arguments = try std.mem.concat(self.a, []const u8, &.{ args, tail });
            return self.callWithPolicy(lane, .azure, policy, label, arguments, "json");
        }

        fn azRequired(self: *Self, label: []const u8, args: []const []const u8) !void {
            try self.required(try self.az(.primary, label, args));
        }

        fn validate(self: *Self, lane: Lane, label: []const u8, verb: enum { scope, inputs, json, serial }, extra: []const []const u8) !u8 {
            const command = if (profile.legacy_fixture and verb == .scope) "legacy-scope" else @tagName(verb);
            const args = try std.mem.concat(self.a, []const u8, &.{ &.{ command, try self.path("scope.json") }, extra });
            return self.callWithPolicy(lane, .validator, if (verb == .serial) .serial_parser else .required, label, args, "stdout");
        }

        const Read = struct {
            document: observations.Document,
            pin: custody.FileSnapshot,
            fn deinit(self: Read) void {
                self.document.deinit();
            }
            fn value(self: Read) std.json.Value {
                return self.document.value();
            }
        };

        fn read(self: *Self, label: []const u8) !Read {
            const name = try self.fmt("{s}.json", .{label});
            const pin = try self.store.pinFile(name, custody.cli_limit);
            var bytes = try self.store.directory.readSensitive(self.io, self.temporary, name, custody.cli_limit, pin.sha256);
            defer bytes.deinit();
            const document = observations.Document.parse(self.temporary, .{ .complete = bytes.bytes() }) catch |err| return self.refused(label, err);
            errdefer document.deinit();
            try self.store.verifyFile(name, pin, custody.cli_limit);
            return .{ .document = document, .pin = pin };
        }

        fn refused(self: *Self, label: []const u8, err: anyerror) anyerror {
            self.log("direct observation failed: {s}.json\n", .{label});
            // Only primary callers use the stored primary exit.
            if (self.runtime.budgets.cleanup == null) self.primary_exit = observationExit(err);
            return err;
        }

        fn groupName(self: *Self) ![]const u8 {
            return self.fmt("{s}-rg", .{self.expected.scope.prefix});
        }

        fn vmName(self: *Self) ![]const u8 {
            return self.fmt("{s}-vm", .{self.expected.scope.prefix});
        }

        fn diskName(self: *Self, role: Role) ![]const u8 {
            return self.fmt("{s}-{s}", .{ self.expected.scope.prefix, @tagName(role) });
        }

        fn groupAbsent(self: *Self, lane: Lane, label: []const u8) !void {
            const status = self.az(lane, label, &.{ "group", "exists", "--name", try self.groupName() }) catch |err| {
                if (lane == .primary and !self.runtime.cancellation.flag().load(.acquire)) self.primary_exit = 1;
                return err;
            };
            if (status != 0) {
                if (lane == .primary) self.primary_exit = 1; // reference `group_absent || die`
                return error.GroupAbsenceUncertain;
            }
            const document = self.read(label) catch |err| {
                if (lane == .primary) self.primary_exit = 1;
                return err;
            };
            defer document.deinit();
            observations.freshAbsence(document.value()) catch |err| {
                const failure = self.refused(label, err);
                if (lane == .primary) self.primary_exit = 1;
                return failure;
            };
        }

        fn tags(self: *Self) ![]const []const u8 {
            const scope = self.expected.scope;
            return self.a.dupe([]const u8, &.{
                "--tags",
                try self.fmt("uk-direct-run={s}", .{scope.attempt_id}),
                try self.fmt("unikraft-run={s}", .{scope.prefix}),
                try self.fmt("image-sha256={s}", .{scope.os_vhd.sha256}),
                "managed-by=unikraft-hyperv",
            });
        }

        fn primary(self: *Self) !void {
            try self.required(try self.call(.primary, .validator, "source-scope-check", &.{
                if (comptime profile.legacy_fixture) "legacy-scope" else "scope",
                self.inputs.scope,
            }, "stdout"));
            try self.required(try self.call(.primary, .validator, "ledger-check", &.{
                if (comptime profile.legacy_fixture) "legacy-ledger" else "ledger",
                self.inputs.scope,
                self.inputs.ledger,
            }, "stdout"));
            try self.required(try self.validate(.primary, "scope-check", .scope, &.{}));
            try self.event(.@"local-admission");
            self.references = try self.hooks.references(self.io, self.expected.scope, self.inputs.programs);
            try self.required(try self.validate(.primary, "input-check", .inputs, &.{}));
            var startup: launcher.Status = .{};
            launcher.check(self.runtime, &self.store.writer, self.tools.?[0], &startup) catch |err| {
                if (startup.child) |child| {
                    const status = processExit(child, self.runtime.cancellation);
                    if (status != 0) self.primary_exit = status;
                    _ = recordCaptureFailure(self.store, .primary, &self.primary_exit, child.capture, status);
                    if (!child.execution.cleanup_complete or child.execution.unreaped_group != null) self.poisoned = true;
                }
                if (startup.recording_error) |failure| {
                    self.store.recordingFailed(failure);
                    self.cleanup_exit = 1;
                }
                if (err == error.UnresolvedCleanup or err == error.CliStartupCleanupFailed) self.poisoned = true;
                self.log("local CLI startup refused before consumption: {s}\n", .{@errorName(err)});
                return err;
            };
            try self.verifyPrimary();
            _ = try self.runtime.budgets.call(.primary, .azure);
            try self.store.consume();
            try self.event(if (profile.compute) .@"attempt-consumed" else .@"seed-consumed");
            try self.groupAbsent(.primary, "group-before");
            try self.event(.@"group-create-intent");
            self.group_intended = true;
            const group_args = try std.mem.concat(self.a, []const u8, &.{
                &.{ "group", "create", "--name", try self.groupName(), "--location", self.expected.scope.location },
                try self.tags(),
            });
            try self.azRequired("group-created", group_args);
            {
                const doc = try self.read("group-created");
                defer doc.deinit();
                observations.group(doc.value(), self.expected) catch |err| return self.refused("group-created", err);
            }
            try self.upload(.os);
            if (!profile.compute) try self.upload(.data);
            try self.deployment();
            const first = try self.observe("boot1", .allocated);
            self.boot_vm[0] = first.vm;
            try self.serial(1);
            try self.event(.@"boot1-evidence-complete");
            try self.event(.@"deallocate-intent");
            try self.vmOperation("deallocated", .deallocate);
            const retained = try self.observe("retained", .deallocated);
            try self.required(try self.validate(.primary, "retained-input-check", .inputs, &.{}));
            _ = self.runtime.budgets.call(.primary, .azure) catch |err| {
                if (err == error.ApprovalExpired) self.primary_exit = 1;
                return err;
            };
            // admitBoot2 reserves before inspecting the original Boot1 binding.
            try self.store.admitBoot2(self.identities(), retained);
            try self.event(.@"boot2-start-intent");
            try self.verifyAdmission();
            try self.vmOperation("started", .start);
            const second = try self.observe("boot2", .allocated);
            self.boot_vm[1] = second.vm;
            try self.serial(2);
            try self.event(.@"boot2-evidence-complete");
            try self.event(.@"final-deallocate-intent");
            try self.vmOperation("final-deallocated", .deallocate);
            self.final_observations = try self.observe("final", .deallocated);
            try self.verifyFinal();
            try self.store.verifyBoot1();
            try self.verifyPrimary();
            self.complete = true;
            try self.event(if (profile.compute) .@"compute-evidence-complete" else .@"persistence-evidence-complete");
        }

        fn upload(self: *Self, role: Role) !void {
            const index = @intFromEnum(role);
            const name = @tagName(role);
            const artifact = self.expected.artifact(role);
            const upload_name = try self.fmt("upload-{s}", .{name});
            const upload_path = try self.path(upload_name);
            const upload_dir = try local.directory(self.io, self.store.directory, upload_name);
            defer upload_dir.close(self.io);
            var writer = try upload_dir.lock(self.io);
            defer writer.close(self.io);
            try self.event(if (role == .os) .@"os-create-intent" else .@"data-create-intent");
            const args = try std.mem.concat(self.a, []const u8, &.{
                &.{ "disk", "create", "--resource-group", try self.groupName(), "--name", try self.diskName(role), "--location", self.expected.scope.location, "--upload-type", "Upload", "--upload-size-bytes", try self.fmt("{d}", .{artifact.size}), "--sku", "StandardSSD_LRS" },
                if (role == .os) &.{ "--os-type", "Linux", "--hyper-v-generation", "V2" } else &.{},
                try self.tags(),
            });
            try self.azRequired(try self.fmt("{s}-created", .{name}), args);
            const before = try self.fmt("{s}-before-upload", .{name});
            try self.diskShow(.primary, before, role);
            {
                const doc = try self.read(before);
                defer doc.deinit();
                const observed = observations.uploadReady(doc.value(), self.expected, role, null) catch |err| return self.refused(before, err);
                self.disk_uuids[index] = try self.a.dupe(u8, observed.unique_id);
            }
            self.granted[index] = true; // An ambiguous grant still needs revoke.
            try self.event(if (role == .os) .@"os-grant-intent" else .@"data-grant-intent");
            const grant_label = try self.fmt("grant-{s}", .{name});
            try self.azRequired(grant_label, &.{ "disk", "grant-access", "--resource-group", try self.groupName(), "--name", try self.diskName(role), "--access-level", "Write", "--duration-in-seconds", "1800" });
            const grant_name = try self.fmt("{s}.json", .{grant_label});
            const grant_pin = try self.store.pinFile(grant_name, 65536);
            try self.required(try self.validate(.primary, try self.fmt("{s}-grant-check", .{name}), .json, &.{try self.path(grant_name)}));
            try self.store.verifyFile(grant_name, grant_pin, 65536);
            {
                var bytes = try self.store.directory.readSensitive(self.io, self.temporary, grant_name, 65536, grant_pin.sha256);
                defer bytes.deinit();
                const grant = observations.Grant.parse(self.temporary, .{ .complete = bytes.bytes() }) catch |err| return self.refused(grant_label, err);
                defer grant.deinit();
                try grant.writePrivateFiles(self.temporary, self.io, &writer, artifact);
            }
            // Round down to a complete second, leaving room for durable local
            // handoff. Runtime independently rechecks the remaining budget.
            const budget = try self.runtime.budgets.call(.primary, .uploader);
            const timeout = (budget.worker_timeout_ms.? / 1000) * 1000;
            if (timeout < 1000) return error.InsufficientTransferBudget;
            const job = try custody.encode(self.a, .{
                .contract = "uk.hyperv.transfer-job",
                .schema_version = @as(u8, 1),
                .kind = "pages",
                .request = "request.json",
                .sas = "sas.txt",
                .timeout_ms = timeout,
                .cleanup_ms = runtime.transfer_cleanup_ms,
            });
            try custody.requireDurable(try writer.createImmutable(self.io, "job.json", job));
            var pins: [3]custody.FileSnapshot = undefined;
            const names = [_][]const u8{ "job.json", "request.json", "sas.txt" };
            for (names, &pins) |entry, *snapshot| snapshot.* = try local.pin(self.temporary, self.io, upload_dir, entry, 65536);
            try local.verifyDirectory(self.io, upload_dir, upload_path);
            try local.verifyLock(self.io, &writer);
            const lock_pin = try files.snapshot(writer.file.?);
            try self.event(if (role == .os) .@"os-native-upload-intent" else .@"data-native-upload-intent");
            // The native uploader owns this same stable lock during transfer;
            // retaining it here would make the real pages supervisor refuse.
            writer.close(self.io);
            const status = try self.call(.primary, .uploader, try self.fmt("{s}-transfer", .{name}), &.{ "transfer", upload_path, "job.json" }, "json");
            try local.verifyDirectory(self.io, upload_dir, upload_path);
            writer = try upload_dir.lock(self.io);
            if (!files.sameSnapshot(lock_pin, try files.snapshot(writer.file.?))) return error.LockChanged;
            for (names, pins) |entry, snapshot| try local.verify(self.temporary, self.io, upload_dir, entry, snapshot, 65536);
            try self.required(status);
            try self.event(if (role == .os) .@"os-revoke-intent" else .@"data-revoke-intent");
            try self.azRequired(try self.fmt("{s}-revoked", .{name}), &.{ "disk", "revoke-access", "--resource-group", try self.groupName(), "--name", try self.diskName(role) });
            const after = try self.fmt("{s}-after-upload", .{name});
            try self.diskShow(.primary, after, role);
            {
                const doc = try self.read(after);
                defer doc.deinit();
                _ = observations.afterUpload(doc.value(), self.expected, role, self.disk_uuids[index].?) catch |err| return self.refused(after, err);
            }
            self.granted[index] = false;
            try self.store.removeCapabilities();
        }

        fn deployment(self: *Self) !void {
            const s = self.expected.scope;
            const common = .{
                .namePrefix = .{ .value = s.prefix },
                .location = .{ .value = s.location },
                .ownerRun = .{ .value = s.attempt_id },
                .imageSha256 = .{ .value = s.os_vhd.sha256 },
                .osDiskId = .{ .value = self.expected.os_id },
                .vmSize = .{ .value = s.vm_size },
            };
            const parameters = try custody.encode(self.a, .{ .parameters = if (profile.compute) common else .{
                .namePrefix = common.namePrefix,
                .location = common.location,
                .ownerRun = common.ownerRun,
                .imageSha256 = common.imageSha256,
                .osDiskId = common.osDiskId,
                .vmSize = common.vmSize,
                .dataDiskId = .{ .value = self.expected.data_id },
            } });
            try custody.requireDurable(try self.store.writer.createImmutable(self.io, "deployment-parameters.json", parameters));
            try custody.requireDurable(try self.store.writer.createImmutable(self.io, "deployment-template.json", @embedFile("direct_arm_template")));
            const parameters_pin = try self.store.pinFile("deployment-parameters.json", custody.record_limit);
            const template_pin = try self.store.pinFile("deployment-template.json", custody.record_limit);
            try self.store.reserveBoot1();
            try self.event(.@"boot1-deploy-intent");
            try self.azRequired("deployment", &.{
                "deployment",      "group",                                   "create",       "--resource-group",                                                   try self.groupName(), "--name", s.prefix,
                "--template-file", try self.path("deployment-template.json"), "--parameters", try self.fmt("@{s}", .{try self.path("deployment-parameters.json")}),
            });
            try self.store.verifyFile("deployment-parameters.json", parameters_pin, custody.record_limit);
            try self.store.verifyFile("deployment-template.json", template_pin, custody.record_limit);
        }

        fn vmOperation(self: *Self, label: []const u8, operation: enum { deallocate, start }) !void {
            try self.azRequired(label, &.{ "vm", @tagName(operation), "--resource-group", try self.groupName(), "--name", try self.vmName() });
        }

        fn diskShow(self: *Self, lane: Lane, label: []const u8, role: Role) !void {
            const status = try self.az(lane, label, &.{ "disk", "show", "--resource-group", try self.groupName(), "--name", try self.diskName(role) });
            if (status != 0) {
                if (lane == .primary) self.primary_exit = status;
                return error.ChildFailed;
            }
        }

        fn observe(self: *Self, label: []const u8, allocation: observations.Allocation) !custody.Retained {
            const vm_label = try self.fmt("{s}-vm", .{label});
            try self.azRequired(vm_label, &.{ "vm", "show", "--resource-group", try self.groupName(), "--name", try self.vmName() });
            const vm_doc = try self.read(vm_label);
            defer vm_doc.deinit();
            const observed = observations.vm(vm_doc.value(), self.expected, self.vm_uuid) catch |err| return self.refused(vm_label, err);
            if (self.vm_uuid == null) self.vm_uuid = try self.a.dupe(u8, observed.unique_id);
            var disks: [2]custody.FileSnapshot = undefined;
            inline for (profile.roles) |role_name| {
                const role: Role = role_name;
                const disk_label = try self.fmt("{s}-{s}", .{ label, @tagName(role) });
                try self.diskShow(.primary, disk_label, role);
                const doc = try self.read(disk_label);
                defer doc.deinit();
                _ = observations.retainedDisk(doc.value(), self.expected, role, allocation, self.disk_uuids[@intFromEnum(role)].?) catch |err| return self.refused(disk_label, err);
                disks[@intFromEnum(role)] = doc.pin;
            }
            const power_label = try self.fmt("{s}-power", .{label});
            try self.azRequired(power_label, &.{ "vm", "get-instance-view", "--resource-group", try self.groupName(), "--name", try self.vmName() });
            const power_doc = try self.read(power_label);
            defer power_doc.deinit();
            _ = observations.power(power_doc.value(), allocation) catch |err| return self.refused(power_label, err);
            return .{ .vm = vm_doc.pin, .os = disks[0], .data = if (profile.compute) null else disks[1], .power = power_doc.pin };
        }

        fn identities(self: *Self) custody.Identities {
            return .{
                .vm_id = self.expected.vm_id,
                .vm_uuid = self.vm_uuid.?,
                .os_id = self.expected.os_id,
                .os_uuid = self.disk_uuids[0].?,
                .data_id = if (profile.compute) null else self.expected.data_id,
                .data_uuid = if (profile.compute) null else self.disk_uuids[1].?,
            };
        }

        fn verifyFinal(self: *Self) !void {
            const retained = self.final_observations orelse return error.MissingFinalObservation;
            inline for (profile.retained) |name|
                try self.store.verifyFile("final-" ++ name ++ ".json", @field(retained, name), custody.cli_limit);
        }

        fn hashHook(self: *Self, name: []const u8) !void {
            const status = try self.hooks.checkHashFault(self.store, name);
            if (status != 0) {
                self.primary_exit = status;
                return error.HashFailed;
            }
        }

        fn verifyAdmission(self: *Self) !void {
            try self.hashHook("boot1.log");
            try self.hashHook("boot1-capture.json");
            try self.hashHook("scope.json");
            try self.hashHook("boot2-admission.json");
            try self.store.verifyBoot2Admission();
        }

        fn serial(self: *Self, boot: u8) !void {
            const candidate: local.Scratch = if (boot == 1) .@"boot1-candidate.log" else .@"boot2-candidate.log";
            const vm_name = try self.fmt("boot{d}-vm.json", .{boot});
            for (1..61) |count| {
                try self.stopped();
                if (try self.runtime.budgets.execution.expired()) return error.SerialExhausted;
                if (boot == 2) try self.verifyAdmission();
                const label = try self.fmt("boot{d}-serial-{d}", .{ boot, count });
                // Provider read failures may poll again; local admission or
                // custody failures abort instead of admitting another call.
                const status = try self.azWithPolicy(.primary, .serial_poll, label, &.{ "vm", "boot-diagnostics", "get-boot-log", "--resource-group", try self.groupName(), "--name", try self.vmName() });
                if (status == 0) {
                    const wrapper_name = try self.fmt("{s}.json", .{label});
                    const wrapper_pin = try self.store.pinFile(wrapper_name, custody.cli_limit);
                    var bytes = try self.store.directory.readSensitive(self.io, self.temporary, wrapper_name, custody.cli_limit, wrapper_pin.sha256);
                    defer bytes.deinit();
                    const decoded = observations.Diagnostics.decode(self.temporary, .{ .complete = bytes.bytes() }, .primary) catch |err| return self.refused(label, err);
                    defer decoded.deinit();
                    try local.scratch(self.io, &self.store.writer, candidate, try decoded.evidenceBytes(), &self.store.cleanup_failure);
                    try self.store.verifyFile(wrapper_name, wrapper_pin, custody.cli_limit);
                    try self.store.verifyFile(vm_name, self.boot_vm[boot - 1].?, custody.cli_limit);
                    const sources = try self.store.captureSources(boot, @intCast(count));
                    var result: u8 = 2;
                    var cached = false;
                    if (boot == 2) {
                        try self.verifyAdmission();
                        try self.hashHook(@tagName(candidate));
                        cached = (try self.store.freshness(sources.serial)) == .cached;
                    }
                    if (cached) {
                        self.log("Boot2 cached read {d}: identical-pinned-boot1; waiting for fresh bytes\n", .{count});
                    } else {
                        const serial_label = try self.fmt("serial-check-{d}-{d}", .{ boot, count });
                        const extra: []const []const u8 = if (boot == 1) &.{try self.path(@tagName(candidate))} else &.{ try self.path("boot1.log"), try self.path(@tagName(candidate)) };
                        result = try self.validate(.primary, serial_label, .serial, extra);
                        // Compatibility aliases are mutable scratch, never the
                        // immutable validator captures used to audit a poll.
                        inline for (.{ local.Scratch.@"serial-check.stdout", local.Scratch.@"serial-check.stderr" }) |alias| {
                            const suffix = if (alias == .@"serial-check.stdout") "stdout" else "stderr";
                            var output = try self.store.directory.readSensitive(self.io, self.temporary, try self.fmt("{s}.{s}", .{ serial_label, suffix }), custody.cli_limit, null);
                            defer output.deinit();
                            try local.scratch(self.io, &self.store.writer, alias, output.bytes(), &self.store.cleanup_failure);
                        }
                    }
                    if (result == 0) {
                        try self.store.capture(boot, @intCast(count), self.identities(), sources, 0);
                        return;
                    }
                    if (result != 2) {
                        // The reference serial loop intentionally collapses a
                        // parser rejection (not an incomplete poll) to die(1).
                        self.primary_exit = 1;
                        return error.SerialRejected;
                    }
                }
                const budget = try self.runtime.budgets.call(.primary, .validator);
                const now = try process.monotonicNanoseconds();
                const available = if (budget.deadline.expires_ns > now) (budget.deadline.expires_ns - now) / std.time.ns_per_ms else 0;
                const delay: u64 = @as(u64, self.expected.scope.poll_seconds) * 1000;
                var slept: u64 = 0;
                while (slept < @min(delay, available)) {
                    try self.stopped();
                    const step = @min(100, @min(delay, available) - slept);
                    try self.hooks.sleep(self.io, step);
                    slept += step;
                }
                if (available < delay) return error.BudgetExhausted;
            }
            return error.SerialExhausted;
        }

        fn cleanup(self: *Self) void {
            defer self.finalCustody();
            self.runtime.budgets.beginCleanup() catch {
                self.cleanup_exit = 1;
                return;
            };
            self.event(.@"cleanup-intent") catch {
                self.cleanup_exit = 1;
            };
            if (self.group_intended and !self.poisoned) self.cleanupGroup() catch {
                self.cleanup_exit = 1;
            };
            if (self.poisoned) self.cleanup_exit = 1;
            self.store.removeCapabilities() catch {
                self.cleanup_exit = 1;
            };
            if (!self.poisoned) {
                self.final_input_exit = self.validate(.cleanup, "final-input-check", .inputs, &.{}) catch |err| blk: {
                    self.cleanup_exit = 1;
                    self.log("final input validation unavailable: {s}\n", .{@errorName(err)});
                    break :blk null;
                };
            }
        }

        fn finalCustody(self: *Self) void {
            // These local checks remain mandatory when supervision is poisoned
            // or the cleanup budget cannot start; they never launch children.
            self.source.verify(self.io) catch |err| {
                self.cleanup_exit = 1;
                self.log("final source custody failed: {s}\n", .{@errorName(err)});
            };
            if (self.references) |references| references.verify(self.io) catch |err| {
                self.cleanup_exit = 1;
                self.log("final input custody failed: {s}\n", .{@errorName(err)});
            };
            checkScopeEvidence(self.store, &self.primary_exit) catch |err| {
                self.log("final scope evidence refused: {s}\n", .{@errorName(err)});
            };
            // Proof rechecks never rewrite the independently bounded
            // final-input result, including an already known refusal.
            if (self.complete) self.verifyFinal() catch |err| {
                if (self.primary_exit == 0) self.primary_exit = 1;
                self.log("final primary evidence refused: {s}\n", .{@errorName(err)});
            };
        }

        fn cleanupGroup(self: *Self) !void {
            const group_owned = blk: {
                const status = try self.az(.cleanup, "cleanup-group", &.{ "group", "show", "--name", try self.groupName() });
                if (status != 0) break :blk false;
                const doc = self.read("cleanup-group") catch break :blk false;
                defer doc.deinit();
                observations.group(doc.value(), self.expected) catch break :blk false;
                break :blk true;
            };
            if (!group_owned) {
                try self.groupAbsent(.cleanup, "cleanup-absent");
                self.absent = true;
                return;
            }
            inline for (profile.roles) |role_name| {
                const role: Role = role_name;
                if (self.granted[@intFromEnum(role)])
                    self.cleanupRevoke(role) catch {
                        self.cleanup_exit = 1;
                    };
                if (self.poisoned) return error.UnresolvedCleanup;
            }
            if (try self.az(.cleanup, "cleanup-inventory", &.{ "resource", "list", "--resource-group", try self.groupName() }) != 0) return error.InventoryUncertain;
            {
                const doc = try self.read("cleanup-inventory");
                defer doc.deinit();
                _ = try observations.inventory(doc.value(), self.expected);
            }
            inline for (profile.roles) |role_name| {
                const role: Role = role_name;
                if (self.disk_uuids[@intFromEnum(role)]) |uuid| {
                    const label = try self.fmt("cleanup-{s}-identity", .{@tagName(role)});
                    try self.diskShow(.cleanup, label, role);
                    const doc = try self.read(label);
                    defer doc.deinit();
                    try observations.cleanupDisk(doc.value(), self.expected, role, uuid);
                }
            }
            if (self.vm_uuid) |uuid| {
                if (try self.az(.cleanup, "cleanup-vm-identity", &.{ "vm", "show", "--resource-group", try self.groupName(), "--name", try self.vmName() }) != 0) return error.IdentityUncertain;
                const doc = try self.read("cleanup-vm-identity");
                defer doc.deinit();
                try observations.cleanupVm(doc.value(), self.expected, uuid);
            }
            if (self.primary_exit != 0 and self.store.reserved_boots > 0 and self.vm_uuid != null and self.disk_uuids[0] != null and (profile.compute or self.disk_uuids[1] != null))
                self.failureDiagnostics();
            if (self.poisoned) return error.UnresolvedCleanup;
            self.event(.@"cleanup-delete-intent") catch {
                self.cleanup_exit = 1;
            };
            const deletion = self.az(.cleanup, "cleanup-delete", &.{ "group", "delete", "--name", try self.groupName(), "--yes" }) catch 1;
            if (deletion != 0) self.cleanup_exit = 1;
            try self.groupAbsent(.cleanup, "cleanup-absent");
            self.absent = true;
        }

        fn cleanupRevoke(self: *Self, role: Role) !void {
            const label = try self.fmt("cleanup-{s}-observed", .{@tagName(role)});
            try self.diskShow(.cleanup, label, role);
            const doc = try self.read(label);
            defer doc.deinit();
            try observations.cleanupRevoke(doc.value(), self.expected, role, self.disk_uuids[@intFromEnum(role)]);
            const status = try self.az(.cleanup, try self.fmt("cleanup-{s}-revoke", .{@tagName(role)}), &.{ "disk", "revoke-access", "--resource-group", try self.groupName(), "--name", try self.diskName(role) });
            if (status != 0) return error.RevokeFailed;
            self.granted[@intFromEnum(role)] = false;
        }

        fn failureDiagnostics(self: *Self) void {
            const window = self.runtime.budgets.call(.diagnostic, .azure) catch {
                self.log("failure boot diagnostics skipped: cleanup budget\n", .{});
                return;
            };
            self.diagnostics.attempted = true;
            self.diagnostics.exit = self.az(.diagnostic, "failure-boot-diagnostics", &.{
                "vm", "boot-diagnostics", "get-boot-log", "--resource-group", self.groupName() catch return, "--name", self.vmName() catch return,
            }) catch |err| errorExit(err, self.runtime.cancellation);
            if (self.diagnostics.exit.? != 0) return;
            self.decodeFailure(window.cleanup_deadline) catch |err| {
                self.diagnostics.exit = if (err == error.BudgetExhausted) 124 else observationExit(err);
                const bytes = custody.encode(self.a, .{ .failure = @errorName(err) }) catch return;
                custody.requireDurable(self.store.writer.createImmutable(self.io, "failure-boot-diagnostics-decode.stderr", bytes) catch {
                    self.cleanup_exit = 1;
                    return;
                }) catch {
                    self.cleanup_exit = 1;
                };
                return;
            };
            self.diagnostics.decoded = true;
        }

        fn decodeFailure(self: *Self, deadline: process.Deadline) !void {
            if (try deadline.expired()) return error.BudgetExhausted;
            var bytes = try self.store.directory.readSensitive(self.io, self.temporary, "failure-boot-diagnostics.json", custody.cli_limit, null);
            defer bytes.deinit();
            const decoded = try observations.Diagnostics.decode(self.temporary, .{ .complete = bytes.bytes() }, .failure_only);
            defer decoded.deinit();
            if (try deadline.expired()) return error.BudgetExhausted;
            try local.immutableRaw(self.io, &self.store.writer, "failure-boot-diagnostics.log", decoded.privateBytes(), &self.store.cleanup_failure);
            if (try deadline.expired()) return error.BudgetExhausted;
            try custody.requireDurable(try self.store.writer.createImmutable(self.io, "failure-boot-diagnostics-decode.stderr", ""));
        }
    };
}
