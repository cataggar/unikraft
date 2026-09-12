const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const source = @import("source.zig");
const runtime = @import("runtime.zig");
const provenance = @import("provenance.zig");
const config = @import("config.zig");
const producer = @import("producer.zig");
const packaging = @import("package.zig");
const private = c.core.private_files;

pub const Execution = struct {
    step: producer.Step,
    exit_code: u8,
    cleanup_complete: bool,
    admitted_binding_sha256: c.Sha,
};
pub const Receipt = struct {
    schema: enum { hyperv_artifact_preparation_native_v2 },
    phase: c.Phase,
    purpose: c.Purpose,
    run_id: c.Identity,
    guard: config.Guard,
    source_before: c.Source,
    source_after: c.Source,
    provenance: provenance.Record,
    reviewed_provenance_sha256: c.Sha,
    config_before: c.File,
    config_after: c.File,
    parent_sha256: ?c.Sha,
    execution: ?Execution,
    efi: ?c.File,
    packaging: ?packaging.PackageReport,
    authority: enum { not_admitted },
};

/// Shape and internal consistency only, not proof of execution or approval.
pub fn validate(receipt: Receipt) !void {
    _ = try c.identity(&receipt.run_id);
    if (!std.meta.eql(receipt.run_id, receipt.guard.run_id)) return error.IdentityChanged;
    try config.validateGuardPurpose(receipt.guard, receipt.purpose);
    try source.require(receipt.source_after, receipt.source_before);
    try source.require(receipt.provenance.source, receipt.source_before);
    try provenance.validate(receipt.provenance);
    _ = try c.sha(&receipt.reviewed_provenance_sha256);
    try fileContract(receipt.config_before);
    try fileContract(receipt.config_after);
    if (receipt.config_before.mode != 0o600 or receipt.config_after.mode != 0o600) return error.UnsafeFile;
    if (receipt.parent_sha256) |sha| _ = try c.sha(&sha);
    if (receipt.execution) |execution| {
        _ = try c.sha(&execution.admitted_binding_sha256);
        if (execution.exit_code != 0 or !execution.cleanup_complete) return error.IncompleteExecution;
    }
    switch (receipt.phase) {
        .prepared => {
            if (receipt.parent_sha256 != null or receipt.execution != null or receipt.efi != null or receipt.packaging != null)
                return error.InvalidPhase;
            try fs.requireFile(receipt.config_after, receipt.config_before);
        },
        .configured => {
            if (receipt.parent_sha256 == null or receipt.execution == null or receipt.execution.?.step != .configure or
                receipt.efi != null or receipt.packaging != null) return error.InvalidPhase;
        },
        .built => {
            if (receipt.parent_sha256 == null or receipt.execution == null or receipt.execution.?.step != .build or
                receipt.efi == null or receipt.packaging != null) return error.InvalidPhase;
            try fs.requireFile(receipt.config_after, receipt.config_before);
            try fileContract(receipt.efi.?);
        },
        .packaged => {
            if (receipt.parent_sha256 == null or receipt.execution != null or receipt.efi == null or receipt.packaging == null)
                return error.InvalidPhase;
            try fs.requireFile(receipt.config_after, receipt.config_before);
            try packaging.validateReport(receipt.packaging.?);
            try fs.requireFile(receipt.efi.?, receipt.packaging.?.efi);
        },
    }
}

fn fileContract(file: c.File) !void {
    try c.relative(file.path);
    _ = try c.sha(&file.sha256);
    if (file.size == 0 or file.mode & 0o7022 != 0 or file.mode & ~@as(u16, 0o7777) != 0) return error.InvalidFile;
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8, expected_sha256: c.Sha) !std.json.Parsed(Receipt) {
    if (!std.meta.eql(c.digest(bytes), expected_sha256)) return error.HashMismatch;
    const parsed = try c.parse(Receipt, allocator, bytes);
    errdefer parsed.deinit();
    try validate(parsed.value);
    try requireReviewed(allocator, parsed.value);
    return parsed;
}

fn requireReviewed(allocator: std.mem.Allocator, receipt: Receipt) !void {
    const canonical_provenance = try c.canonical(allocator, receipt.provenance);
    defer allocator.free(canonical_provenance);
    if (!std.meta.eql(c.digest(canonical_provenance), receipt.reviewed_provenance_sha256)) return error.UnreviewedInput;
}

pub const Link = struct { receipt: Receipt, sha256: c.Sha };

/// Checks both canonical hashes; the caller must independently select the link.
pub fn requireLink(allocator: std.mem.Allocator, link: Link) !void {
    try validate(link.receipt);
    try requireReviewed(allocator, link.receipt);
    const bytes = try c.canonical(allocator, link.receipt);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), link.sha256)) return error.ReceiptSubstitution;
}

pub fn requireParent(allocator: std.mem.Allocator, child: Receipt, parent: Link) !void {
    try requireLink(allocator, parent);
    try validate(child);
    try requireReviewed(allocator, child);
    if (child.parent_sha256 == null or !std.meta.eql(child.parent_sha256.?, parent.sha256) or
        child.purpose != parent.receipt.purpose or !std.meta.eql(child.guard, parent.receipt.guard) or
        !std.meta.eql(child.reviewed_provenance_sha256, parent.receipt.reviewed_provenance_sha256))
        return error.ReceiptSubstitution;
    try source.require(child.source_before, parent.receipt.source_after);
    try fs.requireFile(child.config_before, parent.receipt.config_after);
    const correct = switch (child.phase) {
        .prepared => false,
        .configured => parent.receipt.phase == .prepared,
        .built => parent.receipt.phase == .configured,
        .packaged => parent.receipt.phase == .built,
    };
    if (!correct) return error.InvalidPhase;
    if (child.phase == .packaged) try fs.requireFile(child.efi.?, parent.receipt.efi.?);
}

fn sameTool(allocator: std.mem.Allocator, actual: runtime.Tool, expected: runtime.Tool) !void {
    const left = try c.canonical(allocator, actual);
    defer allocator.free(left);
    const right = try c.canonical(allocator, expected);
    defer allocator.free(right);
    if (!std.mem.eql(u8, left, right)) return error.UnreviewedInput;
}

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    git: *runtime.Git,
    repository: fs.Directory,
    review: provenance.Record,
    bindings: provenance.Bindings,
    reviewed_provenance_sha256: c.Sha,
    guard: config.Guard,
    purpose: c.Purpose,
    /// Required by input-v2 generation; never inferred from untrusted receipt paths.
    configuration_directory: ?fs.Directory = null,
    failures: c.Failure = .{},

    /// Pure context binding; physical self/source checks remain in verify.
    pub fn requireReceiptBinding(self: *Context, receipt: Receipt) !void {
        try validate(receipt);
        if (receipt.purpose != self.purpose or !std.meta.eql(receipt.guard, self.guard) or
            !std.meta.eql(receipt.reviewed_provenance_sha256, self.reviewed_provenance_sha256))
            return error.ReceiptSubstitution;
        try requireReviewed(self.allocator, receipt);
    }

    pub fn verify(self: *Context) !c.Source {
        try fs.requireDirectoryIdentity(self.repository, self.bindings.repository);
        try self.requireGitBinding();
        try config.validateGuardPurpose(self.guard, self.purpose);
        try provenance.verify(self.allocator, self.io, self.review, self.bindings, self.reviewed_provenance_sha256);
        try provenance.requireCurrentExecutable(self.io, self.review);
        const actual = source.inspect(self.git, self.repository) catch |err| {
            if (self.git.failures.primary) |value| try self.failures.record(.primary, value);
            if (self.git.failures.cleanup) |value| try self.failures.record(.cleanup, value);
            return err;
        };
        try source.require(actual, self.review.source);
        return actual;
    }

    pub fn requireGitBinding(self: *Context) !void {
        try fs.requireDirectoryIdentity(self.git.runtime.directory, self.bindings.git);
        try sameTool(self.allocator, self.git.runtime.contract, self.review.git);
    }

    pub fn requireProducerBinding(self: *Context, inputs: producer.Inputs) !void {
        try fs.requireDirectoryIdentity(inputs.repository, self.repository);
        try fs.requireDirectoryIdentity(inputs.tools.git.directory, self.bindings.git);
        try sameTool(self.allocator, inputs.tools.git.contract, self.review.git);
        try fs.requireDirectoryIdentity(inputs.tools.trust.directory, self.bindings.trust);
        try sameTool(self.allocator, inputs.tools.trust.contract, self.review.trust);
        var found_compiler = false;
        for (inputs.tools.native) |native| if (native.name == .zig) {
            if (found_compiler) return error.UnreviewedInput;
            found_compiler = true;
            try fs.requireDirectoryIdentity(native.bound.directory, self.bindings.compiler);
            try sameTool(self.allocator, native.bound.contract, self.review.compiler);
        };
        if (!found_compiler) return error.UnreviewedInput;
        try provenance.requirePackages(self.allocator, inputs.tools.packages.contract, self.review.dependencies);
        try provenance.requireDeclarationRoots(inputs.tools.packages.contract.origin, self.repository, self.bindings.dependencies);
        if (self.bindings.dependencies.len != self.review.dependencies.len) return error.UnreviewedInput;
        for (self.review.dependencies) |dependency| {
            const path = try std.fs.path.join(self.allocator, &.{ inputs.tools.packages.directory.path, dependency.package_hash });
            defer self.allocator.free(path);
            const actual = try fs.Directory.open(self.allocator, self.io, path);
            defer actual.close(self.allocator, self.io);
            var found = false;
            for (self.bindings.dependencies) |binding| if (std.mem.eql(u8, binding.name, dependency.name)) {
                if (found) return error.UnreviewedInput;
                try fs.requireDirectoryIdentity(actual, binding.directory);
                found = true;
            };
            if (!found) return error.UnreviewedInput;
        }
        var iterator = inputs.tools.packages.directory.dir.iterate();
        var count: usize = 0;
        while (try iterator.next(self.io)) |item| {
            if (item.kind != .directory) return error.UnreviewedInput;
            var found = false;
            for (self.review.dependencies) |dependency| if (std.mem.eql(u8, item.name, dependency.package_hash)) {
                found = true;
            };
            if (!found) return error.UnreviewedInput;
            count += 1;
        }
        if (count != self.review.dependencies.len) return error.UnreviewedInput;
    }

    pub fn prepared(self: *Context, input: fs.Directory, expected: c.File, metadata: ?*const config.Metadata) !Receipt {
        const before = try self.verify();
        try fs.requireFile(try input.record(self.allocator, self.io, expected.path, config.config_cap, .private), expected);
        const bytes = try input.read(self.allocator, self.io, expected.path, config.config_cap, .private);
        defer self.allocator.free(bytes);
        try config.validateWithMetadata(self.allocator, bytes, self.guard, metadata);
        const receipt: Receipt = .{
            .schema = .hyperv_artifact_preparation_native_v2,
            .phase = .prepared,
            .purpose = self.purpose,
            .run_id = self.guard.run_id,
            .guard = self.guard,
            .source_before = before,
            .source_after = try self.verify(),
            .provenance = self.review,
            .reviewed_provenance_sha256 = self.reviewed_provenance_sha256,
            .config_before = expected,
            .config_after = expected,
            .parent_sha256 = null,
            .execution = null,
            .efi = null,
            .packaging = null,
            .authority = .not_admitted,
        };
        try validate(receipt);
        return receipt;
    }

    /// Only a real successful supervised producer can create the next local
    /// phase. There is no failure-text recovery or acceptance-state transition.
    pub fn runProducer(
        self: *Context,
        parent: Link,
        inputs: producer.Inputs,
        expected_binding: c.Sha,
        expected_inspection_binding: c.Sha,
    ) !Receipt {
        try requireLink(self.allocator, parent);
        try self.requireReceiptBinding(parent.receipt);
        try self.requireProducerBinding(inputs);
        const step: producer.Step = switch (parent.receipt.phase) {
            .prepared => .configure,
            .configured => .build,
            else => return error.InvalidPhase,
        };

        const before = try self.verify();
        try source.require(parent.receipt.source_after, before);
        try fs.requireFile(inputs.workspace.config, parent.receipt.config_after);
        var outcome = try producer.execute(self.allocator, self.io, step, inputs, .{
            .source = before,
            .binding_sha256 = expected_binding,
        }, self.git.deadline);
        defer outcome.deinit(self.allocator);
        if (outcome.child.failures.primary) |value| try self.failures.record(.primary, value);
        if (outcome.child.failures.cleanup) |value| try self.failures.record(.cleanup, value);
        if (outcome.child.failures.recording) |value| try self.failures.record(.recording, value);
        const after = try self.verify();
        if (!outcome.succeeded()) return error.ProducerFailed;
        const updated = try inputs.workspace.directory.record(self.allocator, self.io, inputs.workspace.config.path, config.config_cap, .private);
        const bytes = try inputs.workspace.directory.read(self.allocator, self.io, updated.path, config.config_cap, .private);
        defer self.allocator.free(bytes);
        var inspected_inputs = inputs;
        inspected_inputs.workspace.config = updated;
        var inspected = try producer.execute(self.allocator, self.io, .inspect, inspected_inputs, .{
            .source = after,
            .binding_sha256 = expected_inspection_binding,
        }, self.git.deadline);
        defer inspected.deinit(self.allocator);
        if (inspected.child.failures.primary) |value| try self.failures.record(.primary, value);
        if (inspected.child.failures.cleanup) |value| try self.failures.record(.cleanup, value);
        if (inspected.child.failures.recording) |value| try self.failures.record(.recording, value);
        if (!inspected.succeeded()) return error.ProducerFailed;
        const metadata_bytes = try inputs.workspace.output.read(self.allocator, self.io, "native-config/metadata.tsv", config.config_cap, .artifact);
        defer self.allocator.free(metadata_bytes);
        try @import("inputs.zig").validateAuthoritativeConfig(self.allocator, bytes, metadata_bytes, self.guard);
        try source.require(after, try self.verify());
        var receipt = parent.receipt;
        receipt.phase = if (step == .configure) .configured else .built;
        receipt.parent_sha256 = parent.sha256;
        receipt.source_before = before;
        receipt.source_after = after;
        receipt.config_before = parent.receipt.config_after;
        receipt.config_after = updated;
        receipt.execution = .{ .step = step, .exit_code = 0, .cleanup_complete = true, .admitted_binding_sha256 = expected_binding };
        if (step == .build) receipt.efi = try inputs.workspace.output.record(
            self.allocator,
            self.io,
            "helloworld_hyperv-x86_64-efi-netvsc",
            packaging.maximum_efi_bytes,
            .artifact,
        );
        try requireParent(self.allocator, receipt, parent);
        return receipt;
    }

    pub const BindingKind = enum { configured, built, configured_inspection, built_inspection };

    pub fn publishBinding(self: *Context, lock: *private.Locked, kind: BindingKind, inputs: producer.Inputs, expected: c.Sha) !c.File {
        try self.requireProducerBinding(inputs);
        const observed = try self.verify();
        try source.require(observed, inputs.observed_source);
        try producer.preflight(self.allocator, self.io, switch (kind) {
            .configured => .configure,
            .built => .build,
            .configured_inspection, .built_inspection => .inspect,
        }, inputs, .{ .source = observed, .binding_sha256 = expected });
        const encoded = try c.canonical(self.allocator, try producer.describe(self.allocator, inputs));
        defer self.allocator.free(encoded);
        if (!std.meta.eql(c.digest(encoded), expected)) return error.UnreviewedInput;
        const name = switch (kind) {
            .configured => "configured.binding.json",
            .built => "built.binding.json",
            .configured_inspection => "configured.inspection.binding.json",
            .built_inspection => "built.inspection.binding.json",
        };
        const result = try fs.publish(lock, self.io, name, encoded);
        if (result.failures.primary) |value| try self.failures.record(.primary, value);
        if (result.failures.cleanup) |value| try self.failures.record(.cleanup, value);
        if (result.failures.recording) |value| try self.failures.record(.recording, value);
        if (result.status != .durable or result.failures.primary != null or
            result.failures.cleanup != null or result.failures.recording != null)
            return error.PublicationIncomplete;
        return .{ .path = name, .size = encoded.len, .sha256 = expected, .mode = 0o600 };
    }

    pub fn package(self: *Context, parent: Link, lock: *private.Locked, input: fs.Directory) !Receipt {
        try requireLink(self.allocator, parent);
        try self.requireReceiptBinding(parent.receipt);
        if (parent.receipt.phase != .built) return error.InvalidPhase;
        const before = try self.verify();
        try source.require(before, parent.receipt.source_after);
        const result = packaging.package(self.allocator, self.io, lock, input, parent.receipt.efi.?);
        if (result.primary) |err| if (self.failures.primary == null) {
            self.failures.primary = c.failure(err).primary;
        };
        if (result.cleanup != null) try self.failures.record(.cleanup, .{ .stage = .private_file, .category = .cleanup_failed });
        const after = try self.verify();
        if (!result.succeeded()) return error.PackageFailed;
        var receipt = parent.receipt;
        receipt.phase = .packaged;
        receipt.parent_sha256 = parent.sha256;
        receipt.execution = null;
        receipt.source_before = before;
        receipt.source_after = after;
        receipt.packaging = result.report;
        try requireParent(self.allocator, receipt, parent);
        return receipt;
    }

    pub fn publish(self: *Context, lock: *private.Locked, receipt: Receipt) !Link {
        try validate(receipt);
        try self.requireReceiptBinding(receipt);
        try source.require(receipt.source_after, try self.verify());
        const bytes = try c.canonical(self.allocator, receipt);
        defer self.allocator.free(bytes);
        const result = try fs.publish(lock, self.io, switch (receipt.phase) {
            .prepared => "prepared.receipt.json",
            .configured => "configured.receipt.json",
            .built => "built.receipt.json",
            .packaged => "packaged.receipt.json",
        }, bytes);
        if (result.failures.cleanup) |value| try self.failures.record(.cleanup, value);
        if (result.failures.recording) |value| try self.failures.record(.recording, value);
        if (result.status != .durable or result.failures.primary != null or result.failures.cleanup != null or
            result.failures.recording != null) return error.PublicationIncomplete;
        return .{ .receipt = receipt, .sha256 = c.digest(bytes) };
    }
};
