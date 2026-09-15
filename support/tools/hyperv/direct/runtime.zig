// SPDX-License-Identifier: BSD-3-Clause
//! Bounded child adapter only; this module is not a lifecycle entry point.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const validator = @import("direct_validator");
const transfer_job = @import("transfer_job");
const process = core.process;

pub const Role = enum { azure, uploader, validator };
pub const Lane = enum { primary, cleanup, diagnostic };
pub const output_limit = process.private_output_limit;
pub const transfer_cleanup_ms = 5000;
pub const transfer_reserve_ms = 7000;
pub const minimum_transfer_ms = 8000;
pub const term_grace_ms = 2000;
const reap_ms = 1000;

pub const Programs = struct {
    azure: []const u8,
    uploader: []const u8,
    validator: []const u8,

    pub fn validate(self: Programs) !void {
        inline for (.{ "azure", "uploader", "validator" }) |field| {
            try core.private_files.absoluteFilePath(@field(self, field));
            try publicArgument(@field(self, field));
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
        try result.native.put("LC_ALL", "C");
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
            const reserve = @as(u64, self.operation_ms) * 2 + term_grace_ms + reap_ms;
            if (remaining_ms <= reserve) return error.BudgetExhausted;
            remaining_ms = @min(28000, remaining_ms - reserve);
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

    pub fn initialize(self: Runtime) !void {
        try self.programs.validate();
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
        try self.programs.validate();
        var budget = try self.budgets.call(lane, role);
        if (lane == .primary and self.cancellation.flag().load(.acquire)) return error.Cancelled;
        if (arguments.len > 127) return error.InvalidArguments;
        var argv: [128][]const u8 = undefined;
        argv[0] = self.programs.path(role);
        for (arguments, 1..) |argument, i| {
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
        return process.runPrivate(self.allocator, self.io, lock, stdout_name, stderr_name, .{
            .process = .{
                .argv = argv[0 .. arguments.len + 1],
                .environment = if (role == .azure) &self.environment.azure else &self.environment.native,
                .cwd = lock.directory.dir,
                .deadline = budget.deadline,
                .cleanup_ms = if (role == .uploader) transfer_reserve_ms + reap_ms else term_grace_ms + reap_ms,
                .stdout_limit = output_limit,
                .stderr_limit = output_limit,
                .cancel = if (lane == .primary) self.cancellation.flag() else null,
            },
            .term_grace_ms = if (role == .uploader) transfer_reserve_ms else term_grace_ms,
            .cleanup_deadline = budget.cleanup_deadline,
            .nested_supervisor = role == .uploader,
        });
    }
};

fn publicArgument(value: []const u8) !void {
    if (value.len > 64 * 1024 or std.mem.indexOfAny(u8, value, "?\x00&") != null or
        std.ascii.indexOfIgnoreCase(value, "sig=") != null or
        std.ascii.indexOfIgnoreCase(value, "sas-token") != null) return error.SecretArgument;
}

fn unixSeconds() !u64 {
    var timestamp: std.os.linux.timespec = undefined;
    if (std.os.linux.errno(std.os.linux.clock_gettime(.REALTIME, &timestamp)) != .SUCCESS or timestamp.sec < 0)
        return error.ClockUnavailable;
    return @intCast(timestamp.sec);
}
