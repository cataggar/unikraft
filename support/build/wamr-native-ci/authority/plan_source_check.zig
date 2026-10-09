// SPDX-License-Identifier: BSD-3-Clause
const plan = @import("plan.zig");
const types = @import("types.zig");
const candidate = @import("wamr_handoff").candidate;

export fn authorityPlanRun(ctx: *const types.Context, command: *const types.PlanCommand, source: *candidate.Finalized) u16 {
    return switch (plan.run(ctx.*, command.*, source)) {
        .success => |owner| blk: {
            defer owner.deinit();
            _ = owner.result() catch |err| break :blk @intFromError(err);
            break :blk 0;
        },
        .refused, .poisoned => |diagnostic| @intFromError(diagnostic.err),
    };
}
