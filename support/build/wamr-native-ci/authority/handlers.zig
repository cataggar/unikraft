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
    prepared_plan: ?*plan.Prepared = null,
    recorded_authorization: ?*authorization.Recorded = null,
};
pub const CandidateSource = struct {
    product: *handoff.public_products.ImportedProduct,
    validation_output: []const u8,
    settings: handoff.candidate.Settings = .{},
};
pub const Outcome = union(enum) {
    prepare: prepare.Outcome,
    plan: plan.Outcome,
    authorization: types.Outcome(*authorization.Recorded),
    admission: admission.Outcome,
};

pub fn createCandidate(
    ctx: types.Context,
    source: CandidateSource,
    output: []const u8,
) handoff.candidate.Outcome {
    return handoff.candidate.create(.{
        .allocator = ctx.allocator,
        .io = ctx.io,
        .source = .{ .imported_product = source.product },
        .output = output,
        .validation_output = source.validation_output,
        .settings = source.settings,
        .signal = ctx.signal,
    });
}

pub fn openCandidate(
    ctx: types.Context,
    source: CandidateSource,
    output: []const u8,
) handoff.candidate.Outcome {
    return handoff.candidate.open(.{
        .allocator = ctx.allocator,
        .io = ctx.io,
        .source = .{ .imported_product = source.product },
        .output = output,
        .validation_output = source.validation_output,
        .signal = ctx.signal,
    });
}

pub fn run(ctx: Context, command: types.Command) Outcome {
    return switch (command) {
        .@"prepare-azure-runtime" => |request| .{ .prepare = if (ctx.discovery) |discovery|
            prepare.run(ctx.retained, request, discovery)
        else
            prepare.runStandalone(ctx.retained, request) },
        .plan => |request| .{ .plan = if (ctx.live_finalized) |owner|
            plan.run(ctx.retained, request, owner)
        else
            .{ .refused = .{ .phase = .inputs, .err = error.MissingImportedContext, .outputs = .{}, .failures = .{}, .process = null } } },
        .@"record-authorization" => |request| .{ .authorization = authorization.run(ctx.retained, request) },
        .admit => |request| .{ .admission = admit: {
            const plan_commitment: ?types.Artifact = if (ctx.plan_commitment) |artifact|
                artifact
            else if (ctx.prepared_plan) |owner| blk: {
                const res = owner.result() catch |err|
                    break :admit .{ .refused = .{ .phase = .inputs, .err = err } };
                break :blk res.plan_artifact;
            } else null;
            const authorization_commitment: ?types.Artifact = if (ctx.authorization_commitment) |artifact|
                artifact
            else if (ctx.recorded_authorization) |owner| blk: {
                owner.revalidate() catch |err|
                    break :admit .{ .refused = .{ .phase = .inputs, .err = err } };
                break :blk owner.artifact();
            } else null;
            if (plan_commitment == null or authorization_commitment == null)
                break :admit .{ .refused = .{ .phase = .inputs, .err = error.MissingIndependentCommitments } };
            break :admit admission.run(.{
                .base = ctx.retained,
                .candidate = ctx.live_finalized,
                .plan_commitment = plan_commitment.?,
                .authorization_commitment = authorization_commitment.?,
            }, request);
        } },
    };
}
