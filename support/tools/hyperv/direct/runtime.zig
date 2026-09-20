// SPDX-License-Identifier: BSD-3-Clause
//! Bounded child adapter only; this module is not a lifecycle entry point.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const validator = @import("profile.zig").contract;
const transfer_job = @import("transfer_job");
const process = core.process;
const custody = @import("custody.zig");
const azure_runtime = @import("azure_runtime.zig");

pub const Role = enum { azure, uploader, validator };
pub const Lane = enum { primary, cleanup, diagnostic };
pub const output_limit = process.private_output_limit;
pub const transfer_cleanup_ms = 5000;
pub const transfer_reserve_ms = 7000;
pub const minimum_transfer_ms = 8000;
pub const term_grace_ms = 2000;
const reap_ms = 1000;

pub fn errorExit(err: anyerror, cancellation: *const process.SignalCancellation) u8 {
    return switch (err) {
        error.Cancelled => if (cancellation.signal()) |signal| 128 + signal else 130,
        error.ApprovalExpired => 125,
        error.BudgetExhausted => 124,
        else => 1,
    };
}

pub fn processExit(result: process.PrivateResult, cancellation: *const process.SignalCancellation) u8 {
    if (result.execution.failures.primary) |failure| {
        if (failure.category == .cancelled) return errorExit(error.Cancelled, cancellation);
        if (failure.category == .timeout) return 124;
        // Match the reference's file-size refusal, not the supervisor's TERM.
        // The actual child termination remains independent in process records.
        if (failure.category == .output_limit) return 128 + @intFromEnum(std.os.linux.SIG.XFSZ);
    }
    if (result.execution.termination) |termination| switch (termination) {
        .exited => |code| if (code != 0) return code,
        .signal => |signal| return @intCast(@min(255, 128 + @intFromEnum(signal))),
        else => {},
    };
    return if (result.succeeded()) 0 else 1;
}

pub const Programs = struct {
    azure: []const u8,
    uploader: []const u8,
    validator: []const u8,
    supervisor: ?[]const u8 = null,
    azure_python: ?[]const u8 = null,
    azure_runtime: ?[]const u8 = null,

    pub fn validate(self: Programs) !void {
        inline for (.{ "azure", "uploader", "validator" }) |field| {
            try core.private_files.absoluteFilePath(@field(self, field));
            try publicArgument(@field(self, field));
        }
        if (self.azure_python) |path_value| {
            try core.private_files.absoluteFilePath(path_value);
            try publicArgument(path_value);
        }
        if (self.supervisor) |path_value| {
            try core.private_files.absoluteFilePath(path_value);
            try publicArgument(path_value);
        }
        if (self.azure_runtime) |path_value| {
            try core.private_files.absoluteFilePath(path_value);
            try publicArgument(path_value);
        }
    }

    fn path(self: Programs, role: Role) []const u8 {
        return switch (role) {
            .azure => self.azure,
            .uploader => self.uploader,
            .validator => self.validator,
        };
    }
};

/// Only operator configuration is selected, not the controller's ambient
/// credentials, tool search path, language runtime hooks, or SAS values.
pub const Environment = struct {
    azure: std.process.Environ.Map,
    native: std.process.Environ.Map,

    pub fn init(allocator: std.mem.Allocator, operator: *const std.process.Environ.Map) !Environment {
        var result: Environment = .{
            .azure = .init(allocator),
            .native = .init(allocator),
        };
        errdefer result.deinit();
        for ([_][]const u8{
            "HOME",               "AZURE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
            "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE",    "SSL_CERT_DIR",    "HTTP_PROXY",
            "HTTPS_PROXY",        "ALL_PROXY",        "NO_PROXY",        "http_proxy",
            "https_proxy",        "all_proxy",        "no_proxy",
        }) |key| {
            if (operator.get(key)) |value| {
                try publicArgument(value);
                try result.azure.put(key, value);
            }
        }
        // Without an explicit home or config directory the CLI could silently
        // choose a different operator account through platform defaults.
        if (result.azure.get("HOME") == null and result.azure.get("AZURE_CONFIG_DIR") == null)
            return error.OperatorConfigurationRequired;
        inline for (.{ "HOME", "AZURE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR" }) |key| {
            if (result.azure.get(key)) |value| {
                if (!std.fs.path.isAbsolute(value)) return error.InvalidOperatorConfiguration;
            }
        }
        try result.azure.put("LC_ALL", "C");
        try result.azure.put("AZURE_CORE_COLLECT_TELEMETRY", "0");
        try result.azure.put("PYTHONDONTWRITEBYTECODE", "1");
        try result.azure.put("PYTHONNOUSERSITE", "1");
        try result.azure.put("PYTHONSAFEPATH", "1");
        try result.native.put("LC_ALL", "C");
        try result.native.put(
            core.private_files.namespace_marker,
            core.private_files.namespace_child,
        );
        inline for (.{
            core.private_files.namespace_uid,
            core.private_files.namespace_gid,
        }) |key| {
            if (operator.get(key)) |value|
                try result.native.put(key, value);
        }
        var parent_buffer: [32]u8 = undefined;
        try result.native.put(
            core.private_files.namespace_parent,
            try std.fmt.bufPrint(
                &parent_buffer,
                "{d}",
                .{std.os.linux.getpid()},
            ),
        );
        return result;
    }

    pub fn deinit(self: *Environment) void {
        self.azure.deinit();
        self.native.deinit();
        self.* = undefined;
    }
};

pub const CallBudget = struct {
    deadline: process.Deadline,
    cleanup_deadline: process.Deadline,
    worker_timeout_ms: ?u32 = null,
};

pub const Budgets = struct {
    execution: process.Deadline,
    cleanup: ?process.Deadline = null,
    expires_unix: u64,
    operation_ms: u32,
    cleanup_ms: u32,

    /// Scope parsing/admission stays in the existing read-only validator.
    pub fn start(scope: validator.Scope) !Budgets {
        return startAt(scope, try process.monotonicNanoseconds(), try unixSeconds());
    }

    fn startAt(scope: validator.Scope, monotonic_ns: u64, unix: u64) !Budgets {
        if (scope.runtime_seconds < 60 or scope.runtime_seconds > 3600 or
            scope.cleanup_seconds < 60 or scope.cleanup_seconds > 1800 or
            scope.operation_seconds < 10 or scope.operation_seconds > 600) return error.InvalidBudget;
        if (unix >= scope.approval.expires_unix) return error.ApprovalExpired;
        return .{
            .execution = .{ .expires_ns = try std.math.add(u64, monotonic_ns, @as(u64, scope.runtime_seconds) * std.time.ns_per_s) },
            .expires_unix = scope.approval.expires_unix,
            .operation_ms = scope.operation_seconds * 1000,
            .cleanup_ms = scope.cleanup_seconds * 1000,
        };
    }

    pub fn beginCleanup(self: *Budgets) !void {
        try self.beginCleanupAt(try process.monotonicNanoseconds());
    }

    fn beginCleanupAt(self: *Budgets, monotonic_ns: u64) !void {
        if (self.cleanup != null) return error.CleanupAlreadyStarted;
        self.cleanup = .{ .expires_ns = try std.math.add(u64, monotonic_ns, @as(u64, self.cleanup_ms) * std.time.ns_per_ms) };
    }

    pub fn call(self: Budgets, lane: Lane, role: Role) !CallBudget {
        return self.callAt(lane, role, try process.monotonicNanoseconds(), if (lane == .primary) try unixSeconds() else 0);
    }

    fn callAt(self: Budgets, lane: Lane, role: Role, monotonic_ns: u64, unix: u64) !CallBudget {
        if (lane == .primary and (self.cleanup != null or unix >= self.expires_unix))
            return error.ApprovalExpired;
        const outer = if (lane == .primary) self.execution else self.cleanup orelse return error.CleanupNotStarted;
        if (monotonic_ns >= outer.expires_ns) return error.BudgetExhausted;
        var remaining_ms = (outer.expires_ns - monotonic_ns) / std.time.ns_per_ms;
        if (lane == .diagnostic) {
            const termination_ms = term_grace_ms + reap_ms;
            const reserve = (@as(u64, self.operation_ms) + termination_ms) * 2;
            if (remaining_ms <= reserve) return error.BudgetExhausted;
            const window_ms = @min(30000, remaining_ms - reserve);
            if (window_ms <= termination_ms) return error.BudgetExhausted;
            remaining_ms = window_ms - termination_ms;
        }
        const milliseconds: u64 = @min(self.operation_ms, remaining_ms);
        if (milliseconds == 0) return error.BudgetExhausted;
        if (role == .uploader and (lane != .primary or milliseconds < minimum_transfer_ms))
            return error.InsufficientTransferBudget;
        const execution_end = monotonic_ns + milliseconds * std.time.ns_per_ms;
        return .{
            .deadline = .{ .expires_ns = execution_end },
            .cleanup_deadline = .{ .expires_ns = if (lane == .primary)
                try std.math.add(u64, execution_end, (term_grace_ms + reap_ms) * std.time.ns_per_ms)
            else if (lane == .diagnostic)
                monotonic_ns + (milliseconds + term_grace_ms + reap_ms) * std.time.ns_per_ms
            else
                outer.expires_ns },
            .worker_timeout_ms = if (role == .uploader) @intCast(milliseconds - transfer_reserve_ms) else null,
        };
    }

    pub const Test = struct {
        pub fn start(scope: validator.Scope, monotonic_ns: u64, unix: u64) !Budgets {
            if (!builtin.is_test) @compileError("Synthetic clocks are test-only");
            return startAt(scope, monotonic_ns, unix);
        }
        pub fn cleanup(self: *Budgets, monotonic_ns: u64) !void {
            if (!builtin.is_test) @compileError("Synthetic clocks are test-only");
            return self.beginCleanupAt(monotonic_ns);
        }
        pub fn call(self: Budgets, lane: Lane, role: Role, monotonic_ns: u64, unix: u64) !CallBudget {
            if (!builtin.is_test) @compileError("Synthetic clocks are test-only");
            return self.callAt(lane, role, monotonic_ns, unix);
        }
    };
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    programs: Programs,
    environment: *const Environment,
    budgets: *Budgets,
    cancellation: *const process.SignalCancellation,
    interpreter: ?custody.Reference = null,
    tool_references: ?*const [3]custody.Reference = null,
    azure_runtime: ?azure_runtime.Contract = null,
    azure_custody: ?*const azure_runtime.Sealed = null,

    pub fn verifyInterpreter(self: Runtime) !void {
        if (self.programs.azure_python) |path| {
            const reference = self.interpreter orelse return error.InterpreterNotPinned;
            if (!std.mem.eql(u8, path, reference.path))
                return error.InterpreterChanged;
            try reference.verify(self.io);
        } else if (self.interpreter != null)
            return error.UnexpectedInterpreter;
        if (self.azure_runtime) |closure| {
            const runtime_custody = self.azure_custody orelse
                return error.AzureRuntimeNotPinned;
            var root_buffer: [64]u8 = undefined;
            const root = try std.fmt.bufPrint(
                &root_buffer,
                "/proc/self/fd/{d}",
                .{runtime_custody.root.handle},
            );
            var extensions_buffer: [80]u8 = undefined;
            const extensions = try std.fmt.bufPrint(
                &extensions_buffer,
                "{s}/extensions",
                .{root},
            );
            if (self.programs.azure_runtime == null or
                !std.mem.eql(
                    u8,
                    closure.interpreter.path,
                    self.programs.azure_python orelse
                        return error.InterpreterNotSelected,
                ) or
                !std.mem.eql(u8, closure.launcher.path, self.programs.azure) or
                !std.mem.eql(
                    u8,
                    root,
                    self.environment.azure.get("PYTHONHOME") orelse
                        return error.InterpreterNotSelected,
                ) or
                !std.mem.eql(
                    u8,
                    extensions,
                    self.environment.azure.get("AZURE_EXTENSION_DIR") orelse
                        return error.InterpreterNotSelected,
                ) or
                !std.mem.eql(
                    u8,
                    "no",
                    self.environment.azure.get(
                        "AZURE_EXTENSION_USE_DYNAMIC_INSTALL",
                    ) orelse return error.InterpreterNotSelected,
                ))
                return error.InterpreterChanged;
            try runtime_custody.verify(self.allocator, self.io, closure);
        } else if (self.programs.azure_runtime != null or
            self.environment.azure.get("PYTHONHOME") != null or
            self.azure_custody != null)
            return error.UnexpectedInterpreter;
    }

    pub fn initialize(self: Runtime) !void {
        try self.programs.validate();
        try self.verifyInterpreter();
        if (self.tool_references) |references|
            for (references) |reference| try reference.verify(self.io);
        try process.initialize();
    }

    /// Arguments exclude argv[0]. Azure callers supply the explicit subscription,
    /// --only-show-errors and --output json along with their typed operation.
    /// Uploader argv must be exactly "transfer", PRIVATE_DIRECTORY, JOB_BASENAME.
    /// Its immutable job must use cleanup_ms=5000 and a timeout no larger than
    /// Budgets.call's worker_timeout_ms; the native job parser verifies it here.
    /// The selected uploader must install SignalCancellation and pass its flag
    /// to transfer.worker.supervise; no signal-unsafe IO handler is needed.
    pub fn run(
        self: Runtime,
        lane: Lane,
        role: Role,
        arguments: []const []const u8,
        lock: *core.private_files.Locked,
        stdout_name: []const u8,
        stderr_name: []const u8,
    ) !process.PrivateResult {
        return self.runBounded(lane, role, arguments, lock, stdout_name, stderr_name, false);
    }

    pub fn version(self: Runtime, lock: *core.private_files.Locked) !process.PrivateResult {
        return self.runBounded(.primary, .azure, &.{ "version", "--output", "json", "--only-show-errors" }, lock, "cli-version.stdout", "cli-version.stderr", true);
    }

    fn runBounded(
        self: Runtime,
        lane: Lane,
        role: Role,
        arguments: []const []const u8,
        lock: *core.private_files.Locked,
        stdout_name: []const u8,
        stderr_name: []const u8,
        version_only: bool,
    ) !process.PrivateResult {
        try self.programs.validate();
        try self.verifyInterpreter();
        var budget = try self.budgets.call(lane, role);
        if (version_only) {
            const limit = try process.Deadline.afterMilliseconds(30000);
            budget.deadline.expires_ns = @min(budget.deadline.expires_ns, limit.expires_ns);
            budget.cleanup_deadline.expires_ns = @min(budget.cleanup_deadline.expires_ns, budget.deadline.expires_ns + (term_grace_ms + reap_ms) * std.time.ns_per_ms);
        }
        if (lane == .primary and self.cancellation.flag().load(.acquire)) return error.Cancelled;
        const closure_launch = role == .azure and self.azure_runtime != null;
        const maximum_arguments: usize = if (closure_launch) 115 else 127;
        if (arguments.len > maximum_arguments)
            return error.InvalidArguments;
        if (closure_launch) try azureCommand(arguments);
        var argv: [128][]const u8 = undefined;
        var argument_offset: usize = 1;
        var root_path: [64]u8 = undefined;
        var loader_path: [80]u8 = undefined;
        var interpreter_path: [80]u8 = undefined;
        var launcher_path: [96]u8 = undefined;
        if (closure_launch) {
            _ = self.interpreter orelse return error.InterpreterNotPinned;
            const closure = self.azure_runtime orelse
                return error.AzureRuntimeNotPinned;
            const retained = self.azure_custody orelse
                return error.AzureRuntimeNotPinned;
            const root = try std.fmt.bufPrint(
                &root_path,
                "/proc/self/fd/{d}",
                .{retained.root.handle},
            );
            argv[0] = closure.dynamic_loader.path;
            argv[1] = "--inhibit-cache";
            argv[2] = "--inhibit-rpath";
            argv[3] = "";
            argv[4] = "--library-path";
            argv[5] = try std.fmt.bufPrint(
                &loader_path,
                "{s}/loader",
                .{root},
            );
            argv[6] = try std.fmt.bufPrint(
                &interpreter_path,
                "{s}/bin/python",
                .{root},
            );
            argv[7] = "-s";
            argv[8] = "-S";
            argv[9] = "-B";
            argv[10] = "-P";
            argv[11] = try std.fmt.bufPrint(
                &launcher_path,
                "{s}/bootstrap/azure-cli",
                .{root},
            );
            argument_offset = 12;
        } else {
            argv[0] = self.programs.path(role);
        }
        for (arguments, argument_offset..) |argument, i| {
            try publicArgument(argument);
            argv[i] = argument;
        }
        if (role == .uploader) {
            if (arguments.len != 3 or !std.mem.eql(u8, arguments[0], "transfer")) return error.InvalidArguments;
            try core.private_files.absoluteFilePath(arguments[1]);
            const directory = try core.private_files.Directory.open(self.io, arguments[1]);
            defer directory.close(self.io);
            const job = try transfer_job.Job.load(self.allocator, self.io, directory, arguments[2]);
            defer job.deinit();
            budget = try self.budgets.call(lane, role);
            if (job.kind != .pages or job.cleanup_ms != transfer_cleanup_ms or job.timeout_ms < 1000 or
                job.timeout_ms > budget.worker_timeout_ms.?) return error.InsufficientTransferBudget;
        }
        const reference = if (self.tool_references) |references|
            references[@intFromEnum(role)]
        else
            null;
        if (reference) |value| try value.verify(self.io);
        const executable = if (closure_launch)
            (self.azure_custody orelse
                return error.AzureRuntimeNotPinned).loader
        else if (reference) |value|
            value.native
        else
            null;
        const inherited_descriptor = if (closure_launch)
            (self.azure_custody orelse
                return error.AzureRuntimeNotPinned).root.handle
        else
            null;
        const result = process.runPrivate(self.allocator, self.io, lock, stdout_name, stderr_name, .{
            .process = .{
                .argv = argv[0 .. arguments.len + argument_offset],
                .environment = if (role == .azure) &self.environment.azure else &self.environment.native,
                .cwd = lock.directory.dir,
                .deadline = budget.deadline,
                .cleanup_ms = if (role == .uploader) transfer_reserve_ms + reap_ms else term_grace_ms + reap_ms,
                .stdout_limit = if (version_only) 4096 else output_limit,
                .stderr_limit = if (version_only) 4096 else output_limit,
                .cancel = if (lane == .primary) self.cancellation.flag() else null,
                .inherited_descriptor = inherited_descriptor,
            },
            .executable = executable,
            .term_grace_ms = if (role == .uploader) transfer_reserve_ms else term_grace_ms,
            .cleanup_deadline = budget.cleanup_deadline,
            .nested_supervisor = role == .uploader,
        }) catch |err| {
            if (reference) |value| try value.verify(self.io);
            try self.verifyInterpreter();
            return err;
        };
        if (reference) |value| try value.verify(self.io);
        try self.verifyInterpreter();
        return result;
    }
};

fn publicArgument(value: []const u8) !void {
    if (value.len > 64 * 1024 or std.mem.indexOfAny(u8, value, "?\x00&") != null or
        std.ascii.indexOfIgnoreCase(value, "sig=") != null or
        std.ascii.indexOfIgnoreCase(value, "sas-token") != null) return error.SecretArgument;
}

fn azureCommand(arguments: []const []const u8) !void {
    for (azure_runtime.commands) |command| {
        if (arguments.len < command.len) continue;
        var matches = true;
        for (arguments[0..command.len], command) |actual, expected| {
            if (!std.mem.eql(u8, actual, expected)) {
                matches = false;
                break;
            }
        }
        if (matches) return;
    }
    return error.AzureCommandNotApproved;
}

fn unixSeconds() !u64 {
    var timestamp: std.os.linux.timespec = undefined;
    if (std.os.linux.errno(std.os.linux.clock_gettime(.REALTIME, &timestamp)) != .SUCCESS or timestamp.sec < 0)
        return error.ClockUnavailable;
    return @intCast(timestamp.sec);
}
