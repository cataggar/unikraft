//! Production-local embedding seam, not an approval-file parser or cloud entry.
//! The caller independently selects every review and holds every directory.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const config = @import("config.zig");
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

fn requirePurpose(purpose: c.Purpose) !void {
    if (purpose != .platform_preflight) return error.ProductionPurposeRequired;
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
    try std.testing.expectError(error.InvalidSha256, requireDigest(engine_hash, ("?" ** 64).*));
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
    const initial = try std.fmt.allocPrint(a, "{s}CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_HYPERV=y\n", .{subset});
    const solved = try std.fmt.allocPrint(a, "{s}# independently expected solved bytes\n", .{initial});
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

fn writeConfigurationFixture(directory: std.Io.Dir, path: []const u8, bytes: []const u8, mode: u16) !void {
    const io = std.testing.io;
    const file = try directory.createFile(io, path, .{ .permissions = .fromMode(mode) });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(mode));
    try file.writePositionalAll(io, bytes, 0);
}
