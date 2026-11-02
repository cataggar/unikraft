//! Production-local embedding seam, not an approval-file parser or cloud entry.
//! The caller independently selects every review and holds every directory.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const config = @import("config.zig");
const direct_config = @import("direct_config.zig");
const original_seed = @import("original_seed.zig");
const provenance = @import("provenance.zig");
const source = @import("source.zig");
const producer = @import("producer.zig");
const receipts = @import("receipts.zig");
const inputs = @import("inputs.zig");
const admission = @import("admission.zig");
const private = c.core.private_files;
const Deadline = c.core.process.Deadline;

pub const Configuration = struct {
    directory: fs.Directory,
    initial_metadata: c.File,
    solved_config: c.File,
    solved_metadata: c.File,
};

pub const ExecutionReview = struct {
    execution_sha256: c.Sha,
    inspection_sha256: c.Sha,
};

pub const Selection = struct {
    plan: inputs.Plan,
    reviewed_sha256: c.Sha,
    capability_provenance_sha256: c.Sha,
    capability_source: admission.ProducerSource,
    package_directory: private.Directory,
    assets: []const inputs.Binding,
    qemu: fs.Directory,
};

/// Borrowed descriptors and allocator-owned records must outlive this value.
/// Reconstructing it between phases does not bypass create-only publications.
pub const Facade = struct {
    context: *receipts.Context,
    producer_inputs: producer.Inputs,
    configuration: Configuration,
    receipt_lock: *private.Locked,

    fn requireContext(self: *Facade) !void {
        try requirePurpose(self.context.purpose);
        try config.validateGuardPurpose(self.context.guard, .platform_preflight);
        const directory = self.context.configuration_directory orelse return error.MissingConfiguration;
        try fs.requireDirectoryIdentity(directory, self.producer_inputs.workspace.directory);
    }

    fn solvedFile(self: *Facade) !c.File {
        return inspectionConfig(self.producer_inputs.workspace.config.path, self.configuration.solved_config);
    }

    fn readControl(self: *Facade, file: c.File) ![]u8 {
        return readConfiguration(self.context.allocator, self.context.io, self.configuration.directory, file);
    }

    fn requireConfiguration(self: *Facade, solved: bool) !void {
        const allocator = self.context.allocator;
        const io = self.context.io;
        const workspace = self.producer_inputs.workspace;
        const current = try readConfiguration(allocator, io, workspace.directory, workspace.config);
        defer allocator.free(current);
        const initial_metadata = try self.readControl(self.configuration.initial_metadata);
        defer allocator.free(initial_metadata);
        const expected = try self.readControl(self.configuration.solved_config);
        defer allocator.free(expected);
        const metadata = try self.readControl(self.configuration.solved_metadata);
        defer allocator.free(metadata);
        for ([_]c.File{
            self.configuration.initial_metadata,
            self.configuration.solved_config,
            self.configuration.solved_metadata,
        }) |file| {
            try requireDistinctFile(io, self.configuration.directory, file.path, workspace.directory, workspace.config.path);
            const path = try std.fs.path.join(allocator, &.{ self.configuration.directory.path, file.path });
            defer allocator.free(path);
            const output = try std.fs.path.join(allocator, &.{ workspace.output.path, "native-config/metadata.tsv" });
            defer allocator.free(output);
            if (std.mem.eql(u8, path, output)) return error.MutableExpectation;
        }
        try inputs.validateAuthoritativeConfig(allocator, expected, metadata, self.context.guard);
        try inputs.validateAuthoritativeConfig(allocator, current, if (solved) metadata else initial_metadata, self.context.guard);
        if (solved) try fs.requireFile(workspace.config, try self.solvedFile());
    }

    /// The complete execution and future inspection bindings are reviewed
    /// before any Context operation can execute the supplied native Git.
    fn requireExecutionReview(self: *Facade, step: producer.Step, review: ExecutionReview) !void {
        try self.requireContext();
        try requireNativeBindings(self.producer_inputs);
        const allocator = self.context.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var described = try producer.describe(a, self.producer_inputs);
        try requireDigest(try producer.bindingDigest(a, described), review.execution_sha256);
        described.config = try self.solvedFile();
        try requireDigest(try producer.bindingDigest(a, described), review.inspection_sha256);
        try source.require(self.producer_inputs.observed_source, self.context.review.source);
        try self.context.requireProducerBinding(self.producer_inputs);
        try provenance.verify(a, self.context.io, self.context.review, self.context.bindings, self.context.reviewed_provenance_sha256);
        try producer.preflight(a, self.context.io, step, self.producer_inputs, .{
            .source = self.context.review.source,
            .binding_sha256 = review.execution_sha256,
        });
    }

    pub fn prepared(self: *Facade, review: ExecutionReview) !receipts.Link {
        try self.requireExecutionReview(.configure, review);
        try self.requireConfiguration(false);
        const bytes = try self.readControl(self.configuration.initial_metadata);
        defer self.context.allocator.free(bytes);
        var metadata = try config.Metadata.parse(self.context.allocator, bytes);
        defer metadata.deinit();
        const receipt = try self.context.prepared(self.producer_inputs.workspace.directory, self.producer_inputs.workspace.config, &metadata);
        return self.context.publish(self.receipt_lock, receipt);
    }

    pub fn runProducer(self: *Facade, parent: receipts.Link, review: ExecutionReview) !receipts.Link {
        try self.requireContext();
        try self.context.requireReceiptBinding(parent.receipt);
        const step: producer.Step = switch (parent.receipt.phase) {
            .prepared => .configure,
            .configured => .build,
            else => return error.InvalidPhase,
        };
        try receipts.requireLink(self.context.allocator, parent);
        try fs.requireFile(self.producer_inputs.workspace.config, parent.receipt.config_after);
        try self.requireExecutionReview(step, review);
        try self.requireConfiguration(step == .build);
        // Consume the existing phase publication before executing the producer.
        // A failed operation cannot be replayed into the same receipt root.
        _ = try self.context.publishBinding(self.receipt_lock, if (step == .configure) .configured else .built, self.producer_inputs, review.execution_sha256);
        const receipt = try self.context.runProducer(parent, self.producer_inputs, review.execution_sha256, review.inspection_sha256);
        try fs.requireFile(receipt.config_after, try self.solvedFile());
        try self.requireSolvedMetadata();
        var inspected = self.producer_inputs;
        inspected.workspace.config = receipt.config_after;
        _ = try self.context.publishBinding(self.receipt_lock, if (step == .configure) .configured_inspection else .built_inspection, inspected, review.inspection_sha256);
        const published = try self.context.publish(self.receipt_lock, receipt);
        self.producer_inputs = inspected;
        return published;
    }

    fn requireSolvedMetadata(self: *Facade) !void {
        const allocator = self.context.allocator;
        const expected = try self.readControl(self.configuration.solved_metadata);
        defer allocator.free(expected);
        const actual = try self.producer_inputs.workspace.output.read(allocator, self.context.io, "native-config/metadata.tsv", config.config_cap, .artifact);
        defer allocator.free(actual);
        // The private expectation and native output have distinct mode policies.
        if (!std.mem.eql(u8, actual, expected)) return error.InspectionMismatch;
    }

    pub fn package(self: *Facade, parent: receipts.Link, package_lock: *private.Locked) !receipts.Link {
        try self.requireContext();
        try self.context.requireReceiptBinding(parent.receipt);
        if (parent.receipt.phase != .built) return error.InvalidPhase;
        try fs.requireFile(self.producer_inputs.workspace.config, parent.receipt.config_after);
        try self.requireConfiguration(true);
        try self.requireSolvedMetadata();
        const receipt = try self.context.package(parent, package_lock, self.producer_inputs.workspace.output);
        return self.context.publish(self.receipt_lock, receipt);
    }

    pub fn generate(self: *Facade, parent: receipts.Link, selection: Selection, staging: *private.Locked) !inputs.Input {
        try self.requireContext();
        try self.context.requireReceiptBinding(parent.receipt);
        if (parent.receipt.phase != .packaged) return error.InvalidPhase;
        try receipts.requireLink(self.context.allocator, parent);
        try fs.requireFile(self.producer_inputs.workspace.config, parent.receipt.config_after);
        try self.requireConfiguration(true);
        try self.requireSolvedMetadata();
        var arena = std.heap.ArenaAllocator.init(self.context.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        try requireDigest(c.digest(try c.canonical(a, selection.plan)), selection.reviewed_sha256);
        for ([_]c.File{
            self.configuration.initial_metadata,
            self.configuration.solved_config,
            self.configuration.solved_metadata,
        }) |file| try inputs.requireControlFileBinding(self.context.io, selection.plan, selection.assets, self.configuration.directory, file, .private);
        try source.require(parent.receipt.source_after, try self.context.verify());
        const capability = try inputs.loadCapability(a, self.context.io, selection.plan, selection.assets);
        defer capability.deinit();
        try admission.verifySource(a, self.context.io, capability.value.provenance, selection.capability_source, selection.capability_provenance_sha256, self.context.git.deadline);
        return inputs.generate(self.context, staging, parent, selection.package_directory, self.producer_inputs.workspace.output, selection.plan, selection.reviewed_sha256, selection.assets, selection.qemu);
    }
};

pub const DirectConfiguration = struct {
    directory: fs.Directory,
    derivation: c.File,
    initial_metadata: c.File,
    solved_config: c.File,
    solved_metadata: c.File,
};

pub const DirectPersistenceBundle = struct {
    guard: config.Guard,
    commitments: admission.Commitments,
    os_vhd: c.File,
    seed_raw: c.File,
    seed_vhd: c.File,
    manifest: c.File,
    original_config: c.File,
    derived_config: c.File,
    solved_config: c.File,
    original_production_sha256: c.Sha,
    derivation_sha256: c.Sha,
};

pub const DirectFacade = struct {
    context: *receipts.Context,
    producer_inputs: producer.Inputs,
    configuration: DirectConfiguration,
    receipt_lock: *private.Locked,

    fn requireContext(self: *DirectFacade) !void {
        try requireDirectPurpose(self.context.purpose);
        try requireDirectGuard(self.context.guard);
        const directory = self.context.configuration_directory orelse return error.MissingConfiguration;
        try fs.requireDirectoryIdentity(directory, self.producer_inputs.workspace.directory);
    }

    fn solvedFile(self: *DirectFacade) !c.File {
        return inspectionConfig(self.producer_inputs.workspace.config.path, self.configuration.solved_config);
    }

    fn readControl(self: *DirectFacade, file: c.File) ![]u8 {
        return readConfiguration(self.context.allocator, self.context.io, self.configuration.directory, file);
    }

    fn requireConfiguration(self: *DirectFacade, solved: bool) !void {
        try requireDirectGuard(self.context.guard);
        const allocator = self.context.allocator;
        const io = self.context.io;
        const workspace = self.producer_inputs.workspace;
        const current = try readConfiguration(allocator, io, workspace.directory, workspace.config);
        defer allocator.free(current);
        const derivation_bytes = try self.readControl(self.configuration.derivation);
        defer allocator.free(derivation_bytes);
        const initial_metadata = try self.readControl(self.configuration.initial_metadata);
        defer allocator.free(initial_metadata);
        const expected = try self.readControl(self.configuration.solved_config);
        defer allocator.free(expected);
        const metadata = try self.readControl(self.configuration.solved_metadata);
        defer allocator.free(metadata);
        for ([_]c.File{
            self.configuration.derivation,
            self.configuration.initial_metadata,
            self.configuration.solved_config,
            self.configuration.solved_metadata,
        }) |file| {
            try requireDistinctFile(io, self.configuration.directory, file.path, workspace.directory, workspace.config.path);
            const path = try std.fs.path.join(allocator, &.{ self.configuration.directory.path, file.path });
            defer allocator.free(path);
            const output = try std.fs.path.join(allocator, &.{ workspace.output.path, "native-config/metadata.tsv" });
            defer allocator.free(output);
            if (std.mem.eql(u8, path, output)) return error.MutableExpectation;
        }
        const parsed = try c.parse(direct_config.Record, allocator, derivation_bytes);
        defer parsed.deinit();
        try validateDerivationRecord(parsed.value, self.context.guard);
        if (!solved) try fs.requireFile(workspace.config, try inspectionConfig(workspace.config.path, parsed.value.derived_config));
        try inputs.validateDirectAuthoritativeConfig(allocator, expected, metadata, self.context.guard);
        try inputs.validateDirectAuthoritativeConfig(allocator, current, if (solved) metadata else initial_metadata, self.context.guard);
        if (solved) try fs.requireFile(workspace.config, try self.solvedFile());
    }

    fn requireExecutionReview(self: *DirectFacade, step: producer.Step, review: ExecutionReview) !void {
        try self.requireContext();
        try requireNativeBindings(self.producer_inputs);
        const allocator = self.context.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var described = try producer.describe(a, self.producer_inputs);
        try requireDigest(try producer.bindingDigest(a, described), review.execution_sha256);
        described.config = try self.solvedFile();
        try requireDigest(try producer.bindingDigest(a, described), review.inspection_sha256);
        try source.require(self.producer_inputs.observed_source, self.context.review.source);
        try self.context.requireProducerBinding(self.producer_inputs);
        try provenance.verify(a, self.context.io, self.context.review, self.context.bindings, self.context.reviewed_provenance_sha256);
        try producer.preflight(a, self.context.io, step, self.producer_inputs, .{
            .source = self.context.review.source,
            .binding_sha256 = review.execution_sha256,
        });
    }

    pub fn prepared(self: *DirectFacade, review: ExecutionReview) !receipts.Link {
        try self.requireExecutionReview(.configure, review);
        try self.requireConfiguration(false);
        const bytes = try self.readControl(self.configuration.initial_metadata);
        defer self.context.allocator.free(bytes);
        var metadata = try config.Metadata.parse(self.context.allocator, bytes);
        defer metadata.deinit();
        const receipt = try self.context.prepared(self.producer_inputs.workspace.directory, self.producer_inputs.workspace.config, &metadata);
        return self.context.publish(self.receipt_lock, receipt);
    }

    pub fn runProducer(self: *DirectFacade, parent: receipts.Link, review: ExecutionReview) !receipts.Link {
        try self.requireContext();
        try self.context.requireReceiptBinding(parent.receipt);
        const step: producer.Step = switch (parent.receipt.phase) {
            .prepared => .configure,
            .configured => .build,
            else => return error.InvalidPhase,
        };
        try receipts.requireLink(self.context.allocator, parent);
        try fs.requireFile(self.producer_inputs.workspace.config, parent.receipt.config_after);
        try self.requireExecutionReview(step, review);
        try self.requireConfiguration(step == .build);
        _ = try self.context.publishBinding(self.receipt_lock, if (step == .configure) .configured else .built, self.producer_inputs, review.execution_sha256);
        const receipt = try self.context.runProducer(parent, self.producer_inputs, review.execution_sha256, review.inspection_sha256);
        try fs.requireFile(receipt.config_after, try self.solvedFile());
        try self.requireSolvedMetadata();
        var inspected = self.producer_inputs;
        inspected.workspace.config = receipt.config_after;
        _ = try self.context.publishBinding(self.receipt_lock, if (step == .configure) .configured_inspection else .built_inspection, inspected, review.inspection_sha256);
        const published = try self.context.publish(self.receipt_lock, receipt);
        self.producer_inputs = inspected;
        return published;
    }

    fn requireSolvedMetadata(self: *DirectFacade) !void {
        const allocator = self.context.allocator;
        const expected = try self.readControl(self.configuration.solved_metadata);
        defer allocator.free(expected);
        const actual = try self.producer_inputs.workspace.output.read(allocator, self.context.io, "native-config/metadata.tsv", config.config_cap, .artifact);
        defer allocator.free(actual);
        if (!std.mem.eql(u8, actual, expected)) return error.InspectionMismatch;
    }

    pub fn package(self: *DirectFacade, parent: receipts.Link, package_lock: *private.Locked) !receipts.Link {
        try self.requireContext();
        try self.context.requireReceiptBinding(parent.receipt);
        if (parent.receipt.phase != .built) return error.InvalidPhase;
        try fs.requireFile(self.producer_inputs.workspace.config, parent.receipt.config_after);
        try self.requireConfiguration(true);
        try self.requireSolvedMetadata();
        const receipt = try self.context.package(parent, package_lock, self.producer_inputs.workspace.output);
        return self.context.publish(self.receipt_lock, receipt);
    }

    pub fn generate(self: *DirectFacade, parent: receipts.Link, selection: Selection, staging: *private.Locked) !inputs.Input {
        try self.requireContext();
        try self.context.requireReceiptBinding(parent.receipt);
        if (parent.receipt.phase != .packaged) return error.InvalidPhase;
        try receipts.requireLink(self.context.allocator, parent);
        try fs.requireFile(self.producer_inputs.workspace.config, parent.receipt.config_after);
        try self.requireConfiguration(true);
        try self.requireSolvedMetadata();
        var arena = std.heap.ArenaAllocator.init(self.context.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        try requireDigest(c.digest(try c.canonical(a, selection.plan)), selection.reviewed_sha256);
        for ([_]c.File{
            self.configuration.derivation,
            self.configuration.initial_metadata,
            self.configuration.solved_config,
            self.configuration.solved_metadata,
        }) |file| try inputs.requireControlFileBinding(self.context.io, selection.plan, selection.assets, self.configuration.directory, file, .private);
        try source.require(parent.receipt.source_after, try self.context.verify());
        const capability = try inputs.loadCapability(a, self.context.io, selection.plan, selection.assets);
        defer capability.deinit();
        try admission.verifySource(a, self.context.io, capability.value.provenance, selection.capability_source, selection.capability_provenance_sha256, self.context.git.deadline);
        return inputs.generate(self.context, staging, parent, selection.package_directory, self.producer_inputs.workspace.output, selection.plan, selection.reviewed_sha256, selection.assets, selection.qemu);
    }
};

/// Call from the independently selected actual importing executable, after
/// releasing generation's staging lock and independently reviewing input.json.
/// No review hash is derived here, and the loader retains its existing lock.
pub fn load(allocator: std.mem.Allocator, io: std.Io, guard: config.Guard, review: admission.Review, bindings: admission.Bindings, deadline: Deadline) !admission.Loaded {
    try config.validateGuardPurpose(guard, .platform_preflight);
    if (try deadline.expired()) return error.DeadlineExceeded;
    const bytes = try (fs.Directory{ .dir = bindings.staging.dir, .path = "" }).read(allocator, io, "input.json", 4 * 1024 * 1024, .private);
    defer allocator.free(bytes);
    try requireDigest(c.digest(bytes), review.input_sha256);
    const parsed = try c.parse(inputs.Input, allocator, bytes);
    defer parsed.deinit();
    try requirePurpose(parsed.value.receipt.purpose);
    if (parsed.value.receipt.phase != .packaged) return error.InvalidPhase;
    if (!std.meta.eql(parsed.value.receipt.guard, guard)) return error.IdentityChanged;
    return admission.load(allocator, io, review, bindings, deadline);
}

pub fn loadDirectPersistence(
    allocator: std.mem.Allocator,
    io: std.Io,
    guard: config.Guard,
    derivation: c.File,
    review: admission.Review,
    bindings: admission.Bindings,
    deadline: Deadline,
) !admission.Loaded {
    try requireDirectGuard(guard);
    if (try deadline.expired()) return error.DeadlineExceeded;
    const bytes = try (fs.Directory{ .dir = bindings.staging.dir, .path = "" }).read(allocator, io, "input.json", 4 * 1024 * 1024, .private);
    defer allocator.free(bytes);
    try requireDigest(c.digest(bytes), review.input_sha256);
    const parsed = try c.parse(inputs.Input, allocator, bytes);
    defer parsed.deinit();
    try requireDirectPurpose(parsed.value.receipt.purpose);
    if (parsed.value.receipt.phase != .packaged) return error.InvalidPhase;
    if (!std.meta.eql(parsed.value.receipt.guard, guard)) return error.IdentityChanged;
    const derivation_bytes = try readConfiguration(allocator, io, bindings.config, derivation);
    defer allocator.free(derivation_bytes);
    const derivation_parsed = try c.parse(direct_config.Record, allocator, derivation_bytes);
    defer derivation_parsed.deinit();
    try validateDerivationRecord(derivation_parsed.value, guard);
    {
        var chain_arena = std.heap.ArenaAllocator.init(allocator);
        defer chain_arena.deinit();
        const a = chain_arena.allocator();
        _ = try c.sha(&review.receipt_sha256[0]);
        const receipt_bytes = try bindings.receipts.read(a, io, "prepared.receipt.json", 4 * 1024 * 1024, .private);
        if (!std.meta.eql(c.digest(receipt_bytes), review.receipt_sha256[0])) return error.UnreviewedInput;
        const receipt = try receipts.parse(a, receipt_bytes, review.receipt_sha256[0]);
        try fs.requireFile(
            receipt.value.config_before,
            try inspectionConfig(receipt.value.config_before.path, derivation_parsed.value.derived_config),
        );
    }
    try inputs.requireControlFileBinding(io, parsed.value.selection, bindings.assets, bindings.config, derivation, .private);
    var loaded = try admission.load(allocator, io, review, bindings, deadline);
    errdefer loaded.deinit();
    try fs.requireFile(
        loaded.chain[0].receipt.config_before,
        try inspectionConfig(loaded.chain[0].receipt.config_before.path, derivation_parsed.value.derived_config),
    );
    return loaded;
}

pub fn verifyDirectPersistenceRecords(
    guard: config.Guard,
    commitments: admission.Commitments,
    receipt: receipts.Receipt,
    initial_config: c.File,
    derivation: direct_config.Record,
    derivation_sha256: c.Sha,
    original: original_seed.Record,
    original_production_sha256: c.Sha,
) !DirectPersistenceBundle {
    try requireDirectGuard(guard);
    try requireDirectPurpose(receipt.purpose);
    if (receipt.phase != .packaged) return error.InvalidPhase;
    if (!std.meta.eql(receipt.guard, guard) or !std.meta.eql(original.guard, guard)) return error.IdentityChanged;
    _ = try c.sha(&derivation_sha256);
    _ = try c.sha(&original_production_sha256);
    try validateDerivationRecord(derivation, guard);
    if (!std.meta.eql(derivation.original.production_record.sha256, original_production_sha256)) return error.HashMismatch;
    try fs.requireFile(original.manifest, derivation.original.manifest);
    try fs.requireFile(original.original_config, derivation.original.config);
    try fs.requireFile(original.raw, derivation.original.raw);
    try fs.requireFile(original.vhd, derivation.original.vhd);
    if (original.raw.size != original_seed.logical_size or original.vhd.size != original_seed.logical_size + 512) return error.InvalidImageLength;
    try fs.requireFile(initial_config, try inspectionConfig(initial_config.path, derivation.derived_config));
    const packaging = receipt.packaging orelse return error.MissingPackaging;
    if (packaging.vhd.size < 1024 * 1024 + 512 or packaging.vhd.size > c.total_cap + 512 or (packaging.vhd.size - 512) % (1024 * 1024) != 0) return error.InvalidImageLength;
    if (!std.meta.eql(commitments.vhd_sha256, packaging.vhd.sha256) or !std.meta.eql(commitments.raw_sha256, packaging.raw.sha256) or !std.meta.eql(commitments.solved_config_sha256, receipt.config_after.sha256)) return error.HashMismatch;
    return .{
        .guard = guard,
        .commitments = commitments,
        .os_vhd = packaging.vhd,
        .seed_raw = original.raw,
        .seed_vhd = original.vhd,
        .manifest = original.manifest,
        .original_config = original.original_config,
        .derived_config = derivation.derived_config,
        .solved_config = receipt.config_after,
        .original_production_sha256 = original_production_sha256,
        .derivation_sha256 = derivation_sha256,
    };
}

pub fn bundleFromLoaded(
    loaded: *const admission.Loaded,
    derivation: direct_config.Record,
    derivation_sha256: c.Sha,
    original: original_seed.Record,
    original_production_sha256: c.Sha,
) !DirectPersistenceBundle {
    return verifyDirectPersistenceRecords(
        loaded.input.receipt.guard,
        loaded.commitments,
        loaded.input.receipt,
        loaded.chain[0].receipt.config_before,
        derivation,
        derivation_sha256,
        original,
        original_production_sha256,
    );
}

fn requirePurpose(purpose: c.Purpose) !void {
    if (purpose != .platform_preflight) return error.ProductionPurposeRequired;
}

fn requireDirectPurpose(purpose: c.Purpose) !void {
    if (purpose != .persistence) return error.ProductionPurposeRequired;
}

fn requireDirectGuard(guard: config.Guard) !void {
    try config.validateGuardPurpose(guard, .persistence);
    if (c.same(guard.run_id, guard.disk_id)) return error.IdentityCollision;
}

fn validateDerivationRecord(record: direct_config.Record, guard: config.Guard) !void {
    try requireDirectGuard(guard);
    if (!std.meta.eql(record.guard, guard)) return error.IdentityChanged;
    try configurationFile(record.derived_config);
    for ([_]c.File{
        record.original.production_record,
        record.original.manifest,
        record.original.config,
        record.original.raw,
        record.original.vhd,
    }) |file| {
        try c.relative(file.path);
        _ = try c.sha(&file.sha256);
        if (file.mode != 0o600 or file.size == 0) return error.InvalidConfigurationExpectation;
    }
}

fn requireNativeBindings(value: producer.Inputs) !void {
    if (value.native_execution == null or value.native_proof == null or value.isolation == null)
        return error.MissingProductionBindings;
}

fn requireDigest(actual: c.Sha, expected: c.Sha) !void {
    _ = try c.sha(&expected);
    if (!std.meta.eql(actual, expected)) return error.UnreviewedInput;
}

fn configurationFile(file: c.File) !void {
    try c.relative(file.path);
    _ = try c.sha(&file.sha256);
    if (file.mode != 0o600 or file.size == 0 or file.size > config.config_cap)
        return error.InvalidConfigurationExpectation;
}

fn inspectionConfig(path: []const u8, expected: c.File) !c.File {
    try c.relative(path);
    try configurationFile(expected);
    var result = expected;
    result.path = path;
    return result;
}

fn readConfiguration(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, expected: c.File) ![]u8 {
    try configurationFile(expected);
    const bytes = try directory.read(allocator, io, expected.path, config.config_cap, .private);
    errdefer allocator.free(bytes);
    if (bytes.len != expected.size) return error.HashMismatch;
    try requireDigest(c.digest(bytes), expected.sha256);
    return bytes;
}

fn requireDistinctFile(io: std.Io, left: fs.Directory, left_path: []const u8, right: fs.Directory, right_path: []const u8) !void {
    const first = try left.openFile(io, left_path, .private);
    defer first.close(io);
    const second = try right.openFile(io, right_path, .private);
    defer second.close(io);
    const a = try fs.metadata(first);
    const b = try fs.metadata(second);
    if (a.device == b.device and a.inode == b.inode) return error.MutableExpectation;
}

test "production local purpose and independent commitments are required" {
    try requirePurpose(.platform_preflight);
    try std.testing.expectError(error.ProductionPurposeRequired, requirePurpose(.synthetic));
    try std.testing.expectError(error.ProductionPurposeRequired, requirePurpose(.persistence));
    const provenance_hash = c.digest("reviewed provenance, not an executable");
    const producer_hash = c.digest("producer executable");
    const engine_hash = c.digest("separate importing executable");
    try requireDigest(provenance_hash, provenance_hash);
    try std.testing.expectError(error.UnreviewedInput, requireDigest(producer_hash, provenance_hash));
    try std.testing.expectError(error.UnreviewedInput, requireDigest(engine_hash, producer_hash));
    try std.testing.expectError(error.InvalidSha256, requireDigest(engine_hash, @as([64]u8, @splat('?'))));
}

test "production local real entrypoints compile without executing a producer" {
    inline for (.{
        Facade.prepared,
        Facade.runProducer,
        Facade.package,
        Facade.generate,
        load,
    }) |entry| {
        var pointer: *const @TypeOf(entry) = &entry;
        std.mem.doNotOptimizeAway(&pointer);
    }
}

test "production local facade refuses nonproduction purposes and absent configuration before other bindings" {
    var context: receipts.Context = undefined;
    var facade: Facade = undefined;
    facade.context = &context;
    for ([_]c.Purpose{ .synthetic, .persistence }) |purpose| {
        context.purpose = purpose;
        try std.testing.expectError(error.ProductionPurposeRequired, facade.prepared(undefined));
        try std.testing.expectError(error.ProductionPurposeRequired, facade.runProducer(undefined, undefined));
        try std.testing.expectError(error.ProductionPurposeRequired, facade.package(undefined, undefined));
        try std.testing.expectError(error.ProductionPurposeRequired, facade.generate(undefined, undefined, undefined));
    }
    context.purpose = .platform_preflight;
    context.guard = .{
        .run_id = "11111111111111111111111111111111".*,
        .disk_id = "22222222222222222222222222222222".*,
        .sectors = config.persistence_sectors,
        .lun = 7,
    };
    context.configuration_directory = null;
    try std.testing.expectError(error.MissingConfiguration, facade.prepared(undefined));
}

test "production local missing native bindings fail before directory or tool access" {
    const missing: producer.Inputs = .{
        .repository = undefined,
        .observed_source = undefined,
        .workspace = undefined,
        .tools = undefined,
        .native_execution = null,
        .native_proof = null,
        .isolation = null,
    };
    try std.testing.expectError(error.MissingProductionBindings, requireNativeBindings(missing));
}

test "production local inspection retains independent bytes under the actual config path" {
    const expected: c.File = .{ .path = "expected-solved.config", .sha256 = c.digest("independent bytes"), .size = 17, .mode = 0o600 };
    const inspected = try inspectionConfig("run.config", expected);
    try std.testing.expectEqualStrings("run.config", inspected.path);
    try std.testing.expectEqualDeep(expected.sha256, inspected.sha256);
    try std.testing.expectEqual(expected.size, inspected.size);
    try std.testing.expectEqual(expected.mode, inspected.mode);
    var bad = expected;
    bad.size = 0;
    try std.testing.expectError(error.InvalidConfigurationExpectation, inspectionConfig("run.config", bad));
    bad = expected;
    bad.mode = 0o644;
    try std.testing.expectError(error.InvalidConfigurationExpectation, inspectionConfig("run.config", bad));
    bad = expected;
    bad.size = config.config_cap + 1;
    try std.testing.expectError(error.InvalidConfigurationExpectation, inspectionConfig("run.config", bad));
    try std.testing.expectError(error.UnsafePath, inspectionConfig("../outside", expected));
}

test "production local explicit configuration expectations reject subsets aliases mutations and missing files" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", a) };
    const guard: config.Guard = .{
        .run_id = "11111111111111111111111111111111".*,
        .disk_id = "22222222222222222222222222222222".*,
        .sectors = config.persistence_sectors,
        .lun = 7,
    };
    const metadata =
        "unikraft-native-config-metadata-v1\n" ++
        "symbol\tAPPHYPERVACCEPTANCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_NETWORK_APPLICATION\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_LUN\tint\n" ++
        "symbol\tLIBSTORVSC\tbool\n" ++
        "symbol\tLIBSTORVSC_LUN_DISCOVERY\tbool\n" ++
        "symbol\tLIBSTORVSC_GUARDED_IO\tbool\n" ++
        "symbol\tLIBSTORVSC_MAX_DEVICES\tint\n" ++
        "symbol\tLIBSTORVSC_MAX_LUNS\tint\n" ++
        "symbol\tARCH_X86_64\tbool\nsymbol\tPLAT_HYPERV\tbool\n";
    const subset = try config.render(a, guard);
    const initial = try a.print("{s}CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\n", .{subset});
    const solved = try a.print("{s}# independently expected solved bytes\n", .{initial});
    try writeConfigurationFixture(fixture.dir, "run.config", initial, 0o600);
    try writeConfigurationFixture(fixture.dir, "expected.config", solved, 0o600);
    try writeConfigurationFixture(fixture.dir, "expected.metadata", metadata, 0o600);
    // Only the configuration reader is exercised. No runtime or receipt exists.
    var context: receipts.Context = undefined;
    context.allocator = a;
    context.io = io;
    context.guard = guard;
    var facade: Facade = undefined;
    facade.context = &context;
    facade.producer_inputs.workspace = .{
        .directory = directory,
        .output = directory,
        .scratch = directory,
        .config = try directory.record(a, io, "run.config", config.config_cap, .private),
    };
    facade.configuration = .{
        .directory = directory,
        .initial_metadata = try directory.record(a, io, "expected.metadata", config.config_cap, .private),
        .solved_config = try directory.record(a, io, "expected.config", config.config_cap, .private),
        .solved_metadata = try directory.record(a, io, "expected.metadata", config.config_cap, .private),
    };
    try facade.requireConfiguration(false);
    try std.testing.expectError(error.HashMismatch, facade.requireConfiguration(true));
    try writeConfigurationFixture(fixture.dir, "run.config", solved, 0o600);
    facade.producer_inputs.workspace.config = try directory.record(a, io, "run.config", config.config_cap, .private);
    try facade.requireConfiguration(true);
    try fixture.dir.createDir(io, "native-config", .fromMode(0o700));
    try writeConfigurationFixture(fixture.dir, "native-config/metadata.tsv", metadata, 0o644);
    try facade.requireSolvedMetadata();
    try writeConfigurationFixture(fixture.dir, "native-config/metadata.tsv", "substituted output", 0o644);
    try std.testing.expectError(error.InspectionMismatch, facade.requireSolvedMetadata());
    const original = facade.configuration;
    facade.configuration.solved_config = facade.producer_inputs.workspace.config;
    try std.testing.expectError(error.MutableExpectation, facade.requireConfiguration(true));
    facade.configuration = original;
    facade.configuration.solved_metadata.sha256 = c.digest("another independent expectation");
    try std.testing.expectError(error.UnreviewedInput, facade.requireConfiguration(true));
    facade.configuration = original;
    facade.configuration.initial_metadata.path = "missing.metadata";
    try std.testing.expectError(error.FileNotFound, facade.requireConfiguration(false));
    facade.configuration = original;
    try writeConfigurationFixture(fixture.dir, "run.config", subset, 0o600);
    facade.producer_inputs.workspace.config = try directory.record(a, io, "run.config", config.config_cap, .private);
    try std.testing.expectError(error.InvalidSelection, facade.requireConfiguration(false));
    try std.testing.expectEqualStrings(solved, try directory.read(a, io, "expected.config", config.config_cap, .private));
    try std.testing.expectEqualStrings(metadata, try directory.read(a, io, "expected.metadata", config.config_cap, .private));
}

test "production local direct persistence facade and configuration validation" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    inline for (.{
        DirectFacade.prepared,
        DirectFacade.runProducer,
        DirectFacade.package,
        DirectFacade.generate,
        loadDirectPersistence,
        verifyDirectPersistenceRecords,
        bundleFromLoaded,
    }) |entry| {
        var pointer: *const @TypeOf(entry) = &entry;
        std.mem.doNotOptimizeAway(&pointer);
    }

    try requireDirectPurpose(.persistence);
    try std.testing.expectError(error.ProductionPurposeRequired, requireDirectPurpose(.synthetic));
    try std.testing.expectError(error.ProductionPurposeRequired, requireDirectPurpose(.platform_preflight));

    const guard: config.Guard = .{
        .run_id = "11111111111111111111111111111111".*,
        .disk_id = "22222222222222222222222222222222".*,
        .sectors = config.persistence_sectors,
        .lun = 7,
    };
    var context: receipts.Context = undefined;
    var facade: DirectFacade = undefined;
    facade.context = &context;
    for ([_]c.Purpose{ .synthetic, .platform_preflight }) |purpose| {
        context.purpose = purpose;
        try std.testing.expectError(error.ProductionPurposeRequired, facade.prepared(undefined));
        try std.testing.expectError(error.ProductionPurposeRequired, facade.runProducer(undefined, undefined));
        try std.testing.expectError(error.ProductionPurposeRequired, facade.package(undefined, undefined));
        try std.testing.expectError(error.ProductionPurposeRequired, facade.generate(undefined, undefined, undefined));
    }
    context.purpose = .persistence;
    context.guard = guard;
    context.guard.disk_id = context.guard.run_id;
    try std.testing.expectError(error.IdentityCollision, facade.prepared(undefined));
    context.guard = guard;
    context.configuration_directory = null;
    try std.testing.expectError(error.MissingConfiguration, facade.prepared(undefined));

    var fixture = std.testing.tmpDir(.{ .iterate = true });
    defer fixture.cleanup();
    try fixture.dir.setPermissions(io, .fromMode(0o700));
    const directory: fs.Directory = .{ .dir = fixture.dir, .path = try fixture.dir.realPathFileAlloc(io, ".", a) };
    const metadata =
        "unikraft-native-config-metadata-v1\n" ++
        "symbol\tAPPHYPERVACCEPTANCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_NETWORK_APPLICATION\tbool\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID\tstring\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTORS\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY\tint\n" ++
        "symbol\tAPPHYPERVACCEPTANCE_PERSISTENCE_LUN\tint\n" ++
        "symbol\tLIBSTORVSC\tbool\n" ++
        "symbol\tLIBSTORVSC_LUN_DISCOVERY\tbool\n" ++
        "symbol\tLIBSTORVSC_GUARDED_IO\tbool\n" ++
        "symbol\tLIBSTORVSC_MAX_DEVICES\tint\n" ++
        "symbol\tLIBSTORVSC_MAX_LUNS\tint\n" ++
        "symbol\tUKPLAT_CPU_MAXCOUNT\tint\n" ++
        "symbol\tARCH_X86_64\tbool\n" ++
        "symbol\tPLAT_HYPERV\tbool\n";
    const subset = try config.renderDirectPersistence(a, guard);
    const initial = try a.print("{s}CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\n", .{subset});
    const solved = try a.print("{s}# independently expected solved direct persistence bytes\n", .{initial});
    try writeConfigurationFixture(fixture.dir, "run.config", initial, 0o600);
    try writeConfigurationFixture(fixture.dir, "expected.config", solved, 0o600);
    try writeConfigurationFixture(fixture.dir, "expected.metadata", metadata, 0o600);

    const placeholder_file: c.File = .{
        .path = "seed.file",
        .sha256 = c.digest("seed"),
        .size = 4,
        .mode = 0o600,
    };
    const derivation_record: direct_config.Record = .{
        .guard = guard,
        .original = .{
            .production_record = placeholder_file,
            .manifest = placeholder_file,
            .config = placeholder_file,
            .raw = placeholder_file,
            .vhd = placeholder_file,
        },
        .derived_config = .{
            .path = direct_config.config_name,
            .sha256 = c.digest(initial),
            .size = initial.len,
            .mode = 0o600,
        },
    };
    try writeConfigurationFixture(fixture.dir, direct_config.record_name, try c.canonical(a, derivation_record), 0o600);

    context.allocator = a;
    context.io = io;
    context.guard = guard;
    facade.producer_inputs.workspace = .{
        .directory = directory,
        .output = directory,
        .scratch = directory,
        .config = try directory.record(a, io, "run.config", config.config_cap, .private),
    };
    facade.configuration = .{
        .directory = directory,
        .derivation = try directory.record(a, io, direct_config.record_name, config.config_cap, .private),
        .initial_metadata = try directory.record(a, io, "expected.metadata", config.config_cap, .private),
        .solved_config = try directory.record(a, io, "expected.config", config.config_cap, .private),
        .solved_metadata = try directory.record(a, io, "expected.metadata", config.config_cap, .private),
    };

    try facade.requireConfiguration(false);
    try std.testing.expectError(error.HashMismatch, facade.requireConfiguration(true));

    // Reject mismatched derivation.json guard
    var bad_derivation = derivation_record;
    bad_derivation.guard.run_id = "33333333333333333333333333333333".*;
    try writeConfigurationFixture(fixture.dir, direct_config.record_name, try c.canonical(a, bad_derivation), 0o600);
    facade.configuration.derivation = try directory.record(a, io, direct_config.record_name, config.config_cap, .private);
    try std.testing.expectError(error.IdentityChanged, facade.requireConfiguration(false));

    // Reject mismatched derived_config digest
    bad_derivation = derivation_record;
    bad_derivation.derived_config.sha256 = c.digest("mismatched derived config");
    try writeConfigurationFixture(fixture.dir, direct_config.record_name, try c.canonical(a, bad_derivation), 0o600);
    facade.configuration.derivation = try directory.record(a, io, direct_config.record_name, config.config_cap, .private);
    try std.testing.expectError(error.HashMismatch, facade.requireConfiguration(false));

    // Restore valid derivation and verify solved state
    try writeConfigurationFixture(fixture.dir, direct_config.record_name, try c.canonical(a, derivation_record), 0o600);
    facade.configuration.derivation = try directory.record(a, io, direct_config.record_name, config.config_cap, .private);
    try writeConfigurationFixture(fixture.dir, "run.config", solved, 0o600);
    facade.producer_inputs.workspace.config = try directory.record(a, io, "run.config", config.config_cap, .private);
    try facade.requireConfiguration(true);

    // Reject mutable expectation aliasing
    const original = facade.configuration;
    facade.configuration.solved_config = facade.producer_inputs.workspace.config;
    try std.testing.expectError(error.MutableExpectation, facade.requireConfiguration(true));
    facade.configuration = original;
    facade.configuration.derivation = facade.producer_inputs.workspace.config;
    try std.testing.expectError(error.MutableExpectation, facade.requireConfiguration(true));
    facade.configuration = original;
    try fixture.dir.createDir(io, "native-config", .fromMode(0o700));
    try writeConfigurationFixture(fixture.dir, "native-config/metadata.tsv", metadata, 0o600);
    facade.configuration.solved_metadata = try directory.record(a, io, "native-config/metadata.tsv", config.config_cap, .private);
    try std.testing.expectError(error.MutableExpectation, facade.requireConfiguration(true));
    facade.configuration = original;

    // Reject MAX_LUNS=8 (seed/preflight config) in direct persistence facade
    const seed_subset = try config.render(a, guard);
    const seed_initial = try a.print("{s}CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\nCONFIG_UKPLAT_CPU_MAXCOUNT=1\n", .{seed_subset});
    try writeConfigurationFixture(fixture.dir, "expected.config", seed_initial, 0o600);
    facade.configuration.solved_config = try directory.record(a, io, "expected.config", config.config_cap, .private);
    try std.testing.expectError(error.InvalidGuardProfile, facade.requireConfiguration(true));
}

test "production local direct persistence bundle binds original seed derivation and packaged commitments" {
    const guard: config.Guard = .{
        .run_id = "11111111111111111111111111111111".*,
        .disk_id = "22222222222222222222222222222222".*,
        .sectors = config.persistence_sectors,
        .lun = 7,
    };
    const original_production_sha256 = c.digest("original-production-record");
    const derivation_sha256 = c.digest("direct-derivation-record");
    const original: original_seed.Record = .{
        .guard = guard,
        .raw = .{
            .path = "original.raw",
            .sha256 = c.digest("original-raw"),
            .size = original_seed.logical_size,
            .mode = 0o600,
        },
        .vhd = .{
            .path = "original.vhd",
            .sha256 = c.digest("original-vhd"),
            .size = original_seed.logical_size + 512,
            .mode = 0o600,
        },
        .manifest = .{
            .path = "original.json",
            .sha256 = c.digest("original-manifest"),
            .size = 256,
            .mode = 0o600,
        },
        .original_config = .{
            .path = "original.config",
            .sha256 = c.digest("original-config"),
            .size = 512,
            .mode = 0o600,
        },
    };
    const derived_config: c.File = .{
        .path = direct_config.config_name,
        .sha256 = c.digest("derived-direct-config"),
        .size = 540,
        .mode = 0o600,
    };
    const derivation: direct_config.Record = .{
        .guard = guard,
        .original = .{
            .production_record = .{
                .path = original_seed.record_name,
                .sha256 = original_production_sha256,
                .size = 1024,
                .mode = 0o600,
            },
            .manifest = original.manifest,
            .config = original.original_config,
            .raw = original.raw,
            .vhd = original.vhd,
        },
        .derived_config = derived_config,
    };
    const initial_config: c.File = .{
        .path = "workspace.config",
        .sha256 = derived_config.sha256,
        .size = derived_config.size,
        .mode = 0o600,
    };
    const solved_config: c.File = .{
        .path = "workspace.config",
        .sha256 = c.digest("solved-direct-config"),
        .size = 4096,
        .mode = 0o600,
    };
    const os_raw: c.File = .{
        .path = "acceptance.raw",
        .sha256 = c.digest("os-raw"),
        .size = c.image_bytes,
        .mode = 0o600,
    };
    const os_vhd: c.File = .{
        .path = "acceptance.vhd",
        .sha256 = c.digest("os-vhd"),
        .size = c.image_bytes + 512,
        .mode = 0o600,
    };
    var packaging: @import("package.zig").PackageReport = undefined;
    packaging.raw = os_raw;
    packaging.vhd = os_vhd;
    var receipt: receipts.Receipt = undefined;
    receipt.purpose = .persistence;
    receipt.phase = .packaged;
    receipt.guard = guard;
    receipt.config_before = solved_config;
    receipt.config_after = solved_config;
    receipt.packaging = packaging;
    const commitments: admission.Commitments = .{
        .scheme = .reviewed_provenance_projection_v1,
        .guarded_producer_sha256 = c.digest("provenance"),
        .producer_executable_sha256 = c.digest("producer"),
        .engine_executable_sha256 = c.digest("engine"),
        .packaged_receipt_sha256 = c.digest("packaged-receipt"),
        .selection_sha256 = c.digest("selection"),
        .input_sha256 = c.digest("input"),
        .solved_config_sha256 = solved_config.sha256,
        .raw_sha256 = os_raw.sha256,
        .vhd_sha256 = os_vhd.sha256,
    };

    const bundle = try verifyDirectPersistenceRecords(
        guard,
        commitments,
        receipt,
        initial_config,
        derivation,
        derivation_sha256,
        original,
        original_production_sha256,
    );
    try std.testing.expectEqualDeep(guard, bundle.guard);
    try std.testing.expectEqualDeep(commitments, bundle.commitments);
    try std.testing.expectEqualDeep(os_vhd, bundle.os_vhd);
    try std.testing.expectEqualDeep(original.raw, bundle.seed_raw);
    try std.testing.expectEqualDeep(original.vhd, bundle.seed_vhd);
    try std.testing.expectEqualDeep(original.manifest, bundle.manifest);
    try std.testing.expectEqualDeep(original.original_config, bundle.original_config);
    try std.testing.expectEqualDeep(derived_config, bundle.derived_config);
    try std.testing.expectEqualDeep(solved_config, bundle.solved_config);
    try std.testing.expectEqualDeep(original_production_sha256, bundle.original_production_sha256);
    try std.testing.expectEqualDeep(derivation_sha256, bundle.derivation_sha256);

    var loaded: admission.Loaded = undefined;
    loaded.input.receipt = receipt;
    loaded.commitments = commitments;
    loaded.chain[0].receipt.config_before = initial_config;
    const from_loaded = try bundleFromLoaded(&loaded, derivation, derivation_sha256, original, original_production_sha256);
    try std.testing.expectEqualDeep(bundle, from_loaded);

    // Reject guard collisions and wrong geometry
    var bad_guard = guard;
    bad_guard.disk_id = bad_guard.run_id;
    try std.testing.expectError(
        error.IdentityCollision,
        verifyDirectPersistenceRecords(bad_guard, commitments, receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
    );
    bad_guard = guard;
    bad_guard.sectors = 4096;
    try std.testing.expectError(
        error.WrongPurposeGeometry,
        verifyDirectPersistenceRecords(bad_guard, commitments, receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
    );

    // Reject wrong purpose or phase or missing packaging
    for ([_]c.Purpose{ .platform_preflight, .synthetic }) |purpose| {
        var bad_receipt = receipt;
        bad_receipt.purpose = purpose;
        try std.testing.expectError(
            error.ProductionPurposeRequired,
            verifyDirectPersistenceRecords(guard, commitments, bad_receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
    for ([_]c.Phase{ .prepared, .configured, .built }) |phase| {
        var bad_receipt = receipt;
        bad_receipt.phase = phase;
        try std.testing.expectError(
            error.InvalidPhase,
            verifyDirectPersistenceRecords(guard, commitments, bad_receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
    {
        var bad_receipt = receipt;
        bad_receipt.packaging = null;
        try std.testing.expectError(
            error.MissingPackaging,
            verifyDirectPersistenceRecords(guard, commitments, bad_receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }

    // Reject guard identity drift across receipt, original seed, and derivation record
    {
        var bad_receipt = receipt;
        bad_receipt.guard.run_id = "33333333333333333333333333333333".*;
        try std.testing.expectError(
            error.IdentityChanged,
            verifyDirectPersistenceRecords(guard, commitments, bad_receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
    {
        var bad_original = original;
        bad_original.guard.disk_id = "44444444444444444444444444444444".*;
        try std.testing.expectError(
            error.IdentityChanged,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }
    {
        var bad_derivation = derivation;
        bad_derivation.guard.run_id = "55555555555555555555555555555555".*;
        try std.testing.expectError(
            error.IdentityChanged,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, bad_derivation, derivation_sha256, original, original_production_sha256),
        );
    }

    // Reject invalid or mismatched record digests
    try std.testing.expectError(
        error.InvalidSha256,
        verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, @splat('?'), original, original_production_sha256),
    );
    try std.testing.expectError(
        error.InvalidSha256,
        verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, original, @splat('?')),
    );
    try std.testing.expectError(
        error.HashMismatch,
        verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, original, c.digest("other-production-record")),
    );

    // Reject mismatched original raw/VHD/manifest/config bindings
    {
        var bad_original = original;
        bad_original.manifest.sha256 = c.digest("tampered-manifest");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }
    {
        var bad_original = original;
        bad_original.original_config.sha256 = c.digest("tampered-original-config");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }
    {
        var bad_original = original;
        bad_original.raw.sha256 = c.digest("tampered-raw");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }
    {
        var bad_original = original;
        bad_original.vhd.sha256 = c.digest("tampered-vhd");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }

    // Reject invalid data raw/VHD and OS VHD sizes
    {
        var bad_original = original;
        var bad_derivation = derivation;
        bad_original.raw.size = original_seed.logical_size - 512;
        bad_derivation.original.raw.size = bad_original.raw.size;
        try std.testing.expectError(
            error.InvalidImageLength,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, bad_derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }
    {
        var bad_original = original;
        var bad_derivation = derivation;
        bad_original.vhd.size = original_seed.logical_size;
        bad_derivation.original.vhd.size = bad_original.vhd.size;
        try std.testing.expectError(
            error.InvalidImageLength,
            verifyDirectPersistenceRecords(guard, commitments, receipt, initial_config, bad_derivation, derivation_sha256, bad_original, original_production_sha256),
        );
    }
    for ([_]u64{ 512, 1024 * 1024, 1024 * 1024 + 513, c.total_cap + 1024 }) |bad_os_size| {
        var bad_receipt = receipt;
        bad_receipt.packaging.?.vhd.size = bad_os_size;
        try std.testing.expectError(
            error.InvalidImageLength,
            verifyDirectPersistenceRecords(guard, commitments, bad_receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }

    // Reject mismatched initial derived config and commitment hashes
    {
        var bad_initial = initial_config;
        bad_initial.sha256 = c.digest("wrong-initial-config");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, commitments, receipt, bad_initial, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
    {
        var bad_commitments = commitments;
        bad_commitments.vhd_sha256 = c.digest("wrong-vhd");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, bad_commitments, receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
    {
        var bad_commitments = commitments;
        bad_commitments.raw_sha256 = c.digest("wrong-raw");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, bad_commitments, receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
    {
        var bad_commitments = commitments;
        bad_commitments.solved_config_sha256 = c.digest("wrong-solved-config");
        try std.testing.expectError(
            error.HashMismatch,
            verifyDirectPersistenceRecords(guard, bad_commitments, receipt, initial_config, derivation, derivation_sha256, original, original_production_sha256),
        );
    }
}

fn writeConfigurationFixture(directory: std.Io.Dir, path: []const u8, bytes: []const u8, mode: u16) !void {
    const io = std.testing.io;
    const file = try directory.createFile(io, path, .{ .permissions = .fromMode(mode) });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(mode));
    try file.writePositionalAll(io, bytes, 0);
}
