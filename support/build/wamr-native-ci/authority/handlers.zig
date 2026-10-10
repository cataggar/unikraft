// SPDX-License-Identifier: BSD-3-Clause
//! Explicit retained caller inputs only; this is not standalone owner acquisition.
const types = @import("types.zig");
const prepare = @import("prepare.zig");
const plan = @import("plan.zig");
const authorization = @import("authorization.zig");
const admission = @import("admission.zig");
const handoff = @import("wamr_handoff");

pub const Context = struct {
    retained: types.Context,
    live_finalized: ?*handoff.candidate.Finalized = null,
    discovery: ?@import("runtime_probes.zig").DiscoveryInput = null,
    plan_commitment: ?types.Artifact = null,
    authorization_commitment: ?types.Artifact = null,
};
pub const Outcome = union(enum) {
    prepare: prepare.Outcome,
    plan: plan.Outcome,
    authorization: types.Outcome(*authorization.Recorded),
    admission: admission.Outcome,
};

pub fn run(ctx: Context, command: types.Command) Outcome {
    return switch (command) {
        .@"prepare-azure-runtime" => |request| .{ .prepare = if (ctx.discovery) |discovery|
            prepare.run(ctx.retained, request, discovery)
        else
            .{ .refused = .{ .phase = .inputs, .err = error.MissingDiscoveryContext } } },
        .plan => |request| .{ .plan = if (ctx.live_finalized) |owner|
            plan.run(ctx.retained, request, owner)
        else
            .{ .refused = .{ .phase = .inputs, .err = error.MissingImportedContext, .outputs = .{}, .failures = .{}, .process = null } } },
        .@"record-authorization" => |request| .{ .authorization = authorization.run(ctx.retained, request) },
        .admit => |request| .{ .admission = if (ctx.plan_commitment == null or ctx.authorization_commitment == null)
            .{ .refused = .{ .phase = .inputs, .err = error.MissingIndependentCommitments } }
        else
            admission.run(.{
                .base = ctx.retained,
                .candidate = ctx.live_finalized,
                .plan_commitment = ctx.plan_commitment.?,
                .authorization_commitment = ctx.authorization_commitment.?,
            }, request) },
    };
}
