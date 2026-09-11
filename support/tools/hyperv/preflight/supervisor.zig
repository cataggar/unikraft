const std = @import("std");
const core = @import("hyperv_core");
const c = @import("contract.zig");
const worker = @import("worker.zig");

pub const Options = struct {
    executable: []const u8,
    directory: core.private_files.Directory,
    attempt_deadline: core.process.Deadline,
    cleanup_deadline: core.process.Deadline,
    kind: c.Kind,
    operation_ms: u32 = 600_000,
    child_cleanup_ms: u32 = c.child_cleanup_ms,
    cancel: ?*const std.atomic.Value(bool) = null,
};
pub const Result = struct {
    last: ?worker.Report = null,
    failures: core.diagnostics.Failures = .{},
    process_cleanup_complete: bool = true,
    unreaped_group: ?std.os.linux.pid_t = null,
};

/// A dedicated process supervisor. Never call from a supervised engine worker:
/// each operation is a sibling process group, and no child may create another.
/// Caller retains prevalidated cwd/executable and independent cleanup authority.
pub fn run(a: std.mem.Allocator, io: std.Io, options: Options, cleanup_only: bool) !Result {
    try core.process.initialize();
    const now = try core.process.monotonicNanoseconds();
    if (options.operation_ms == 0 or options.operation_ms > 600_000 or
        options.child_cleanup_ms < 100 or options.child_cleanup_ms > c.child_cleanup_ms or
        options.cleanup_deadline.expires_ns <= now or options.cleanup_deadline.expires_ns - now > @as(u64, c.attempt_ms + c.cleanup_ms) * std.time.ns_per_ms)
        return error.InvalidDeadline;
    if (!cleanup_only and (options.attempt_deadline.expires_ns <= now or options.attempt_deadline.expires_ns - now > @as(u64, c.attempt_ms) * std.time.ns_per_ms))
        return error.InvalidDeadline;
    if (!cleanup_only and options.cleanup_deadline.expires_ns <= options.attempt_deadline.expires_ns) return error.InvalidDeadline;
    var result: Result = .{};
    var cleanup = cleanup_only;
    var recover = cleanup_only;
    var cleanup_ceiling: ?core.process.Deadline = null;
    var cause: ?core.diagnostics.Category = null;
    var planning = true;
    var planned_deadline: ?core.process.Deadline = null;
    var planned_ms: u32 = options.operation_ms;
    for (0..2 * (c.action_count + 4)) |_| {
        if (cleanup and cleanup_ceiling == null) {
            const maximum = try core.process.Deadline.afterMilliseconds(c.cleanup_ms);
            cleanup_ceiling = .{ .expires_ns = @min(maximum.expires_ns, options.cleanup_deadline.expires_ns) };
        }
        var ceiling = if (cleanup) cleanup_ceiling.? else options.attempt_deadline;
        if (!planning) ceiling.expires_ns = @min(ceiling.expires_ns, planned_deadline.?.expires_ns);
        if (try ceiling.expired()) {
            if (cleanup) {
                try result.failures.record(.cleanup, .{ .stage = .cleanup, .category = .timeout });
                return result;
            }
            cleanup = true;
            recover = true;
            planning = true;
            cause = .timeout;
            try result.failures.record(.primary, .{ .stage = .process_run, .category = .timeout });
            continue;
        }
        const operation = try core.process.Deadline.afterMilliseconds(if (planning) @min(options.operation_ms, 5000) else @min(options.operation_ms, planned_ms));
        var deadline: core.process.Deadline = .{ .expires_ns = @min(operation.expires_ns, ceiling.expires_ns) };
        var reap_ms = options.child_cleanup_ms;
        if (cleanup) {
            const remaining_ms = (ceiling.expires_ns -| try core.process.monotonicNanoseconds()) / std.time.ns_per_ms;
            reap_ms = @intCast(@min(@as(u64, reap_ms), remaining_ms / 2));
            if (reap_ms < 100) {
                try result.failures.record(.cleanup, .{ .stage = .cleanup, .category = .timeout });
                return result;
            }
            deadline.expires_ns = @min(deadline.expires_ns, ceiling.expires_ns - @as(u64, reap_ms) * std.time.ns_per_ms);
        }
        // Conservatively include the failing worker and its reaping in cleanup.
        // No observed failure starts a fresh twenty-minute budget after reaping.
        const failure_ceiling = try core.process.Deadline.afterMilliseconds(c.cleanup_ms);
        var environment = std.process.Environ.Map.init(a);
        defer environment.deinit();
        const mode = if (planning) (if (recover) "--worker-plan-cleanup" else "--worker-plan") else (if (recover) "--worker-cleanup" else "--worker-step");
        const args = [_][]const u8{ options.executable, mode, if (cause) |value| @tagName(value) else "none" };
        var child = try core.process.run(a, io, .{
            .argv = &args,
            .environment = &environment,
            .cwd = options.directory.dir,
            .deadline = deadline,
            .cleanup_ms = reap_ms,
            .stdout_limit = c.max_operation_result,
            .stderr_limit = 1024,
            .cancel = if (cleanup) null else options.cancel,
        });
        defer child.deinit(a);
        if (!child.cleanup_complete) {
            result.process_cleanup_complete = false;
            result.unreaped_group = child.unreaped_group;
            try result.failures.record(.cleanup, child.failures.cleanup orelse .{ .stage = .process_cleanup, .category = .cleanup_failed });
            // The core is poisoned and writer ownership must not transfer.
            return result;
        }
        if (child.failures.primary) |failure| {
            try result.failures.record(if (cleanup) .cleanup else .primary, failure);
            if (!cleanup) cleanup_ceiling = .{ .expires_ns = @min(failure_ceiling.expires_ns, options.cleanup_deadline.expires_ns) };
            cleanup = true;
            recover = true;
            cause = failure.category;
            planning = true;
            continue;
        }
        const parsed = c.parse(worker.Report, a, child.stdout) catch {
            try result.failures.record(if (cleanup) .cleanup else .primary, .{ .stage = .process_run, .category = .invalid_response });
            if (!cleanup) cleanup_ceiling = .{ .expires_ns = @min(failure_ceiling.expires_ns, options.cleanup_deadline.expires_ns) };
            cleanup = true;
            recover = true;
            cause = .invalid_response;
            planning = true;
            continue;
        };
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.schema, "uk-hyperv-preflight-worker-result-v1") or parsed.value.kind != options.kind)
            return error.InvalidWorkerResult;
        var report = parsed.value;
        report.schema = "uk-hyperv-preflight-worker-result-v1";
        result.last = report;
        if (report.failures.primary) |failure| try result.failures.record(.primary, failure);
        if (report.failures.cleanup) |failure| try result.failures.record(.cleanup, failure);
        if (report.failures.recording) |failure| try result.failures.record(.recording, failure);
        if (!report.more) return result;
        if (!cleanup and (report.failures.primary != null or report.failures.recording != null))
            cleanup_ceiling = .{ .expires_ns = @min(failure_ceiling.expires_ns, options.cleanup_deadline.expires_ns) };
        cleanup = cleanup or report.phase == .cleaning or report.failures.primary != null or report.failures.recording != null;
        recover = recover or report.failures.recording != null;
        if (planning) {
            planned_deadline = .{ .expires_ns = report.deadline_ns orelse return error.InvalidWorkerResult };
            planned_ms = report.operation_ms orelse return error.InvalidWorkerResult;
            if (planned_ms == 0 or planned_ms > 600_000) return error.InvalidWorkerResult;
            if (cleanup and cleanup_ceiling != null) cleanup_ceiling.?.expires_ns = @min(cleanup_ceiling.?.expires_ns, planned_deadline.?.expires_ns);
            planning = false;
        } else {
            planning = true;
            cause = null;
        }
    }
    try result.failures.record(.cleanup, .{ .stage = .cleanup, .category = .output_limit });
    return result;
}
