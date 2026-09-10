const std = @import("std");
const wire = @import("transport.zig");
const s = @import("scope.zig");
const client = @import("client.zig");
const models = @import("models.zig");

pub const Spec = struct {
    sku: []const u8,
    family: []const u8,
    vcpus: u32,
    memory_mib: u32,
    require_nested_metadata: bool,
    image: s.Ref,
    image_group: []const u8,
    image_response_sha256: [32]u8,
    definition_response_sha256: ?[32]u8 = null,
};
pub const Evidence = struct {
    skus: client.Collection,
    usage: client.Collection,
    image: client.Result,
    definition: ?client.Result,
    selected_sku: usize,
    family_quota: usize,
    total_quota: usize,

    pub fn deinit(self: *Evidence) void {
        self.skus.deinit();
        self.usage.deinit();
        self.image.deinit();
        if (self.definition) |*definition| definition.deinit();
        self.* = undefined;
    }
};

/// Read-only metadata admission, not authorization to allocate or proof of
/// nested boots. Image hashes bind exact reviewed REST response bytes.
pub fn inspect(arm: *client.Client, spec: Spec) wire.Outcome(Evidence) {
    s.name(spec.sku) catch return unavailable();
    s.name(spec.family) catch return unavailable();
    if (spec.vcpus == 0 or spec.memory_mib == 0 or (spec.image.kind != .image and spec.image.kind != .gallery_version))
        return unavailable();
    var subscription = switch (arm.execute(.subscription)) {
        .ok => |value| value,
        .failed => |failure| return .{ .failed = failure },
    };
    defer subscription.deinit();
    if (subscription.model != .subscription or !subscription.model.subscription.enabled) return unavailable();
    var provider = switch (arm.execute(.{ .provider = .compute })) {
        .ok => |value| value,
        .failed => |failure| return .{ .failed = failure },
    };
    defer provider.deinit();
    if (provider.model != .provider or !provider.model.provider.registered or !provider.model.provider.compute_version) return unavailable();
    var skus = switch (arm.list(.skus)) {
        .ok => |value| value,
        .failed => |failure| return .{ .failed = failure },
    };
    var keep = false;
    defer if (!keep) skus.deinit();
    var selected: ?usize = null;
    for (skus.items, 0..) |model, i| {
        if (model != .sku) return unavailable();
        const sku = model.sku;
        if (!std.mem.eql(u8, sku.name, spec.sku)) continue;
        if (selected != null or !std.mem.eql(u8, sku.family, spec.family) or sku.vcpus != spec.vcpus or
            sku.memory_mib != spec.memory_mib or sku.restricted or !sku.in_location or sku.generation2 != .yes or
            sku.nested == .no or (spec.require_nested_metadata and sku.nested != .yes)) return unavailable();
        selected = i;
    }
    if (selected == null) return unavailable();
    var usage = switch (arm.list(.usage)) {
        .ok => |value| value,
        .failed => |failure| return .{ .failed = failure },
    };
    defer if (!keep) usage.deinit();
    var family: ?usize = null;
    var total: ?usize = null;
    for (usage.items, 0..) |model, i| {
        if (model != .usage) return unavailable();
        const quota = model.usage;
        const is_family = std.ascii.eqlIgnoreCase(quota.name, spec.family);
        const is_total = std.ascii.eqlIgnoreCase(quota.name, "cores");
        if (!is_family and !is_total) continue;
        if (quota.current > quota.limit or spec.vcpus > quota.limit - quota.current) return unavailable();
        if (is_family) {
            if (family != null) return unavailable();
            family = i;
        }
        if (is_total) {
            if (total != null) return unavailable();
            total = i;
        }
    }
    if (family == null or total == null) return unavailable();
    var image = switch (arm.execute(.{ .image = .{ .ref = spec.image, .group = spec.image_group } })) {
        .ok => |value| value,
        .failed => |failure| return .{ .failed = failure },
    };
    defer if (!keep) image.deinit();
    if (!hashMatches(image.reply.body, spec.image_response_sha256)) return unavailable();
    var definition: ?client.Result = null;
    defer if (!keep) {
        if (definition) |*result| result.deinit();
    };
    if (spec.image.kind == .image) {
        if (image.model != .image or !image.model.image.generation2 or !image.model.image.specialized_linux or image.model.image.state != .succeeded or spec.definition_response_sha256 != null)
            return unavailable();
    } else {
        if (image.model != .image_version or image.model.image_version.state != .succeeded or !image.model.image_version.in_location)
            return unavailable();
        const digest = spec.definition_response_sha256 orelse return unavailable();
        definition = switch (arm.execute(.{ .image = .{ .group = spec.image_group, .ref = .{
            .kind = .gallery_image,
            .parent = spec.image.parent,
            .name = spec.image.gallery_image orelse return unavailable(),
        } } })) {
            .ok => |value| value,
            .failed => |failure| return .{ .failed = failure },
        };
        if (!hashMatches(definition.?.reply.body, digest) or definition.?.model != .image or
            !definition.?.model.image.generation2 or !definition.?.model.image.specialized_linux or definition.?.model.image.state != .succeeded) return unavailable();
    }
    keep = true;
    return .{ .ok = .{
        .skus = skus,
        .usage = usage,
        .image = image,
        .definition = definition,
        .selected_sku = selected.?,
        .family_quota = family.?,
        .total_quota = total.?,
    } };
}
fn hashMatches(bytes: []const u8, expected: [32]u8) bool {
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    return std.crypto.timing_safe.eql([32]u8, actual, expected);
}
fn unavailable() wire.Outcome(Evidence) {
    return .{ .failed = .{ .effect = .not_applicable, .diagnostic = .{
        .stage = .admission,
        .category = .unavailable,
    } } };
}
