//! Read-only local engine entry. Review commitments are supplied separately;
//! neither received JSON nor freshly measured records can select their approval.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const inputs = @import("inputs.zig");
const receipts = @import("receipts.zig");
const provenance = @import("provenance.zig");
const source = @import("source.zig");
const runtime = @import("runtime.zig");
const budget = @import("budget.zig");
const package = @import("package.zig");
const producer = @import("producer.zig");
const ns = @import("namespace.zig");
const private = c.core.private_files;
const Deadline = c.core.process.Deadline;

pub const Review = struct {
    input_sha256: c.Sha,
    selection_sha256: c.Sha,
    provenance_sha256: c.Sha,
    capability_provenance_sha256: c.Sha,
    receipt_sha256: [4]c.Sha,
    execution_sha256: [2]c.Sha,
    engine_runtime_sha256: c.Sha,
    engine_executable_sha256: c.Sha,
};

pub const ProducerSource = struct {
    repository: fs.Directory,
    git: *runtime.Git,
    provenance_bindings: provenance.Bindings,
};

pub const Bindings = struct {
    /// All directories are independently selected, already-open descriptors.
    staging: private.Directory,
    receipts: fs.Directory,
    producer_source: ProducerSource,
    capability_source: ProducerSource,
    config: fs.Directory,
    packaged: private.Directory,
    efi: fs.Directory,
    assets: []const inputs.Binding,
    qemu: fs.Directory,
    engine: runtime.Bound,
};

pub const Commitments = struct {
    scheme: enum { reviewed_provenance_projection_v1 },
    guarded_producer_sha256: c.Sha,
    producer_executable_sha256: c.Sha,
    engine_executable_sha256: c.Sha,
    packaged_receipt_sha256: c.Sha,
    selection_sha256: c.Sha,
    input_sha256: c.Sha,
    solved_config_sha256: c.Sha,
    raw_sha256: c.Sha,
    vhd_sha256: c.Sha,
};

/// This projection is a local, explicitly versioned convention for parent
/// review. Its provenance digest is NOT the producer executable or host-image
/// digest. It conveys no live image, operator, signature, or completed admission.
pub fn project(input: inputs.PreparedInputV2, review: Review) !Commitments {
    try receipts.validate(input.receipt);
    if (input.receipt.phase != .packaged) return error.InvalidPhase;
    if (!std.meta.eql(input.receipt.reviewed_provenance_sha256, review.provenance_sha256) or
        !std.meta.eql(input.reviewed_selection_sha256, review.selection_sha256))
        return error.UnreviewedInput;
    return .{
        .scheme = .reviewed_provenance_projection_v1,
        .guarded_producer_sha256 = review.provenance_sha256,
        .producer_executable_sha256 = input.receipt.provenance.producer.executable.?.sha256,
        .engine_executable_sha256 = review.engine_executable_sha256,
        .packaged_receipt_sha256 = review.receipt_sha256[3],
        .selection_sha256 = review.selection_sha256,
        .input_sha256 = review.input_sha256,
        .solved_config_sha256 = input.receipt.config_after.sha256,
        .raw_sha256 = input.receipt.packaging.?.raw.sha256,
        .vhd_sha256 = input.receipt.packaging.?.vhd.sha256,
    };
}

pub fn rawHash(hex: c.Sha) !c.core.contracts.Sha256 {
    _ = try c.sha(&hex);
    var bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &hex);
    return bytes;
}

/// Storage identifiers have no RFC UUID variant/version or host-run semantics.
pub const StorageIdentity = struct { bytes: [16]u8 };

pub fn storageIdentity(hex: c.Identity) !StorageIdentity {
    _ = try c.identity(&hex);
    var bytes: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, &hex);
    return .{ .bytes = bytes };
}

pub const Loaded = struct {
    arena: std.heap.ArenaAllocator,
    input: inputs.PreparedInputV2,
    chain: [4]receipts.Link,
    commitments: Commitments,
    staging_tree: c.Tree,
    /// Retained existing lock, never created by the loader. The engine must
    /// retain this lifetime and revalidate before any later artifact use.
    lock: private.Locked,
    io: std.Io,

    pub fn deinit(self: *Loaded) void {
        self.lock.close(self.io);
        self.arena.deinit();
        self.* = undefined;
    }
};

fn checkDeadline(deadline: Deadline) !void {
    if (try deadline.expired()) return error.DeadlineExceeded;
}

fn readReviewed(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, name: []const u8, digest: c.Sha) ![]const u8 {
    _ = try c.sha(&digest);
    const bytes = try directory.read(allocator, io, name, 4 * 1024 * 1024, .private);
    if (!std.meta.eql(c.digest(bytes), digest)) return error.UnreviewedInput;
    return bytes;
}

pub fn requireChain(allocator: std.mem.Allocator, chain: [4]receipts.Link, input: inputs.Input, review: Review) !void {
    try inputs.validate(allocator, input, review.selection_sha256);
    for (chain, 0..) |link, i| {
        try receipts.requireLink(allocator, link);
        if (@intFromEnum(link.receipt.phase) != i or !std.meta.eql(link.sha256, review.receipt_sha256[i]) or
            !std.meta.eql(link.receipt.reviewed_provenance_sha256, review.provenance_sha256))
            return error.ReceiptSubstitution;
        if (i != 0) try receipts.requireParent(allocator, link.receipt, chain[i - 1]);
        if (!std.meta.eql(input.selection.publication.receipts[i].sha256, review.receipt_sha256[i]))
            return error.ReceiptSubstitution;
    }
    try receipts.requireLink(allocator, .{ .receipt = input.receipt, .sha256 = review.receipt_sha256[3] });
    for ([_]usize{ 1, 2 }, 0..) |index, execution|
        if (!std.meta.eql(chain[index].receipt.execution.?.admitted_binding_sha256, review.execution_sha256[execution]) or
            !std.meta.eql(input.selection.publication.executions[execution].sha256, review.execution_sha256[execution]))
            return error.UnreviewedInput;
}

pub fn requireEngine(allocator: std.mem.Allocator, io: std.Io, bound: runtime.Bound, review: Review) !void {
    if (!std.mem.eql(u8, builtin.zig_version_string, c.compiler_version)) return error.CompilerMismatch;
    const encoded = try c.canonical(allocator, bound.contract);
    defer allocator.free(encoded);
    const executable = bound.contract.executable orelse return error.InvalidRuntime;
    if (!std.meta.eql(c.digest(encoded), review.engine_runtime_sha256) or
        !std.meta.eql(executable.sha256, review.engine_executable_sha256)) return error.UnreviewedInput;
    try bound.validate(allocator, io);
    const file = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});
    defer file.close(io);
    const before = try fs.metadata(file);
    if (before.size != executable.size or before.mode & 0o7777 != executable.mode or
        !std.meta.eql(try fs.hashFile(io, file, before.size), executable.sha256) or
        !std.meta.eql(before, try fs.metadata(file))) return error.UnreviewedInput;
}

fn verifySource(allocator: std.mem.Allocator, io: std.Io, record: provenance.Record, binding: ProducerSource, digest: c.Sha, deadline: Deadline) !void {
    try checkDeadline(deadline);
    try fs.requireDirectoryIdentity(binding.git.runtime.directory, binding.provenance_bindings.git);
    const actual = try c.canonical(allocator, binding.git.runtime.contract);
    const expected = try c.canonical(allocator, record.git);
    if (!std.mem.eql(u8, actual, expected)) return error.UnreviewedInput;
    try provenance.verify(allocator, io, record, binding.provenance_bindings, digest);
    try checkDeadline(deadline);
    // Keep the caller's Git object intact while imposing this entry's deadline.
    var git = binding.git.*;
    git.allocator = allocator;
    git.deadline = deadline;
    const observed = source.inspect(&git, binding.repository) catch |err| {
        if (git.failures.primary) |value| try binding.git.failures.record(.primary, value);
        if (git.failures.cleanup) |value| try binding.git.failures.record(.cleanup, value);
        if (git.failures.recording) |value| try binding.git.failures.record(.recording, value);
        return err;
    };
    try source.require(observed, record.source);
    try checkDeadline(deadline);
}

fn verifyTool(allocator: std.mem.Allocator, io: std.Io, tool: ns.Tool) !void {
    const directory = try fs.Directory.open(allocator, io, tool.path);
    defer directory.close(allocator, io);
    try (runtime.Bound{ .directory = directory, .contract = tool.contract }).validate(allocator, io);
}

fn verifyIdentity(allocator: std.mem.Allocator, io: std.Io, identity: ns.Identity) !void {
    const directory = try fs.Directory.open(allocator, io, identity.path);
    defer directory.close(allocator, io);
    try identity.require(try ns.Identity.directory(directory));
}

fn sameTool(allocator: std.mem.Allocator, actual: ns.Tool, directory: fs.Directory, expected: runtime.Tool) !void {
    if (!std.mem.eql(u8, actual.path, directory.path)) return error.UnreviewedInput;
    const left = try c.canonical(allocator, actual.contract);
    const right = try c.canonical(allocator, expected);
    if (!std.mem.eql(u8, left, right)) return error.UnreviewedInput;
}

fn requireProducerLocations(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, input: inputs.Input, bindings: Bindings) !void {
    const parsed = try c.parse(producer.Binding, allocator, bytes);
    defer parsed.deinit();
    const selected = parsed.value;
    try selected.repository.require(try ns.Identity.directory(bindings.producer_source.repository));
    try selected.workspace.require(try ns.Identity.directory(bindings.config));
    try selected.output.require(try ns.Identity.directory(bindings.efi));
    const metadata = try inputs.publicationAsset(input.selection, input.selection.solved_metadata);
    try selected.output.require(try ns.Identity.directory(try inputs.binding(bindings.assets, metadata.id)));
    const review = input.receipt.provenance;
    const locations = bindings.producer_source.provenance_bindings;
    try sameTool(allocator, selected.git, locations.git, review.git);
    try sameTool(allocator, selected.trust, locations.trust, review.trust);
    var compiler_found = false;
    for (selected.native) |native| if (native.name == .zig) {
        if (compiler_found) return error.UnreviewedInput;
        compiler_found = true;
        try sameTool(allocator, native.tool, locations.compiler, review.compiler);
    };
    if (!compiler_found) return error.UnreviewedInput;
    const packages = try fs.Directory.open(allocator, io, selected.packages.path);
    defer packages.close(allocator, io);
    var iterator = packages.dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) return error.IncompleteProvenance;
        var found = false;
        for (review.dependencies) |dependency| if (std.mem.eql(u8, entry.name, dependency.package_hash)) {
            found = true;
            for (locations.dependencies) |location| if (std.mem.eql(u8, location.name, dependency.name)) {
                const expected_path = try std.fs.path.join(allocator, &.{ selected.packages.path, dependency.package_hash });
                if (!std.mem.eql(u8, expected_path, location.directory.path)) return error.UnreviewedInput;
            };
        };
        if (!found) return error.IncompleteProvenance;
        count += 1;
    }
    if (count != review.dependencies.len) return error.IncompleteProvenance;
    const helper = selected.isolation.?.helper;
    const helper_directory = try fs.Directory.open(allocator, io, helper.path);
    defer helper_directory.close(allocator, io);
    try inputs.requireControlBinding(io, input.selection, bindings.assets, .{ .directory = helper_directory, .contract = helper.contract });
}

/// Rechecks stored producer inputs WITHOUT rerunning configure/build, changing
/// historical directory identities, or comparing the engine to the producer.
pub fn verifyExecution(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, child: receipts.Receipt, expected_sha256: c.Sha, deadline: Deadline) !void {
    if (!std.meta.eql(c.digest(bytes), expected_sha256) or child.execution == null or
        !std.meta.eql(child.execution.?.admitted_binding_sha256, expected_sha256))
        return error.UnreviewedInput;
    try verifyStoredBinding(allocator, io, bytes, child.config_before, child.source_before, child.phase == .built, expected_sha256, deadline);
}

fn verifyStoredBinding(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, expected_config: c.File, expected_source: c.Source, needs_proof: bool, expected_sha256: c.Sha, deadline: Deadline) !void {
    if (!std.meta.eql(c.digest(bytes), expected_sha256)) return error.UnreviewedInput;
    const parsed = try c.parse(producer.Binding, allocator, bytes);
    defer parsed.deinit();
    const binding = parsed.value;
    try producer.validateBindingStructure(allocator, binding);
    try source.require(binding.source, expected_source);
    try fs.requireFile(binding.config, expected_config);
    const execution = binding.native_execution orelse return error.DependencyUnavailable;
    const isolation = binding.isolation orelse return error.DependencyUnavailable;
    if (isolation.git_metadata.len == 0 or isolation.git_metadata.len > 2) return error.IncompleteProvenance;
    if (!std.mem.eql(u8, execution.root_build.path, "build.zig") or
        !std.mem.eql(u8, execution.facade.path, "support/build/zig-facade-runner.zig") or
        !std.mem.eql(u8, execution.makefile.path, "Makefile")) return error.UnreviewedInput;
    inline for (.{ "repository", "workspace", "output", "scratch" }) |name|
        try verifyIdentity(allocator, io, @field(binding, name));
    if (binding.path) |path| try verifyIdentity(allocator, io, path);
    inline for (.{ "git", "packages", "bison_data", "trust" }) |name| {
        try checkDeadline(deadline);
        try verifyTool(allocator, io, @field(binding, name));
    }
    if (binding.native.len == 0 or binding.native.len > std.meta.fields(producer.Alias).len) return error.IncompleteRuntime;
    for (binding.native, 0..) |tool, i| {
        for (binding.native[0..i]) |previous| if (previous.name == tool.name) return error.InvalidRuntime;
        try checkDeadline(deadline);
        try verifyTool(allocator, io, tool.tool);
    }
    try verifyTool(allocator, io, isolation.helper);
    const repository = try fs.Directory.open(allocator, io, binding.repository.path);
    defer repository.close(allocator, io);
    for ([_]c.File{ execution.root_build, execution.facade, execution.makefile }) |file|
        try fs.requireFile(try repository.record(allocator, io, file.path, 1024 * 1024, .source), file);
    if (execution.git_entry_source) |file|
        try fs.requireFile(try repository.record(allocator, io, file.path, 1024 * 1024, .source), file);
    if (needs_proof) {
        const root = try repository.read(allocator, io, "build.zig", 1024 * 1024, .source);
        try producer.requireNativeProof(allocator, root, binding.source, binding.native_proof);
        for (binding.native_proof.?.inputs) |proof|
            try fs.requireFile(try repository.record(allocator, io, proof.file.path, 1024 * 1024, .source), proof.file);
    }
    if (!std.meta.eql(execution.source_sha256, binding.source.tree_sha256) or
        !std.mem.eql(u8, execution.compiler_version, c.compiler_version)) return error.UnreviewedInput;
    for (isolation.git_metadata) |git| {
        try verifyIdentity(allocator, io, git.directory);
        const directory = try fs.Directory.open(allocator, io, git.directory.path);
        defer directory.close(allocator, io);
        try fs.requireTree((try fs.inventory(allocator, io, directory, 100000, 4 * 1024 * 1024 * 1024)).tree, git.tree);
    }
    const workspace = try fs.Directory.open(allocator, io, binding.workspace.path);
    defer workspace.close(allocator, io);
    try fs.requireFile(try workspace.record(allocator, io, isolation.environment.path, 16 * 1024, .private), isolation.environment);
    const env_path = try std.fs.path.join(allocator, &.{ workspace.path, isolation.environment.path });
    const environment = try @import("environment.zig").load(allocator, io, env_path, isolation.environment.sha256);
    defer environment.deinit();
    const expected_environment = try producer.bindingEnvironment(allocator, binding);
    if (!std.mem.eql(u8, try c.canonical(allocator, expected_environment), try c.canonical(allocator, environment.value)))
        return error.UnreviewedInput;
    const trust = try fs.Directory.open(allocator, io, binding.trust.path);
    defer trust.close(allocator, io);
    try fs.requireFile(try trust.record(allocator, io, binding.trust_bundle.path, 1024 * 1024, .artifact), binding.trust_bundle);
    try checkDeadline(deadline);
}

/// No publications, lock creation, producer execution, or live authority
/// operations occur here. Git's fixed read-only operations are supervised.
pub fn load(backing_allocator: std.mem.Allocator, io: std.Io, review: Review, bindings: Bindings, deadline: Deadline) !Loaded {
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    try checkDeadline(deadline);
    const lock_file = try bindings.staging.openFile(io, ".writer.lock");
    var lock: private.Locked = .{ .directory = bindings.staging, .file = lock_file };
    errdefer lock.close(io);
    if (!try lock_file.tryLock(io, .exclusive)) return error.WouldBlock;
    try fs.requireLock(io, &lock);
    const staging: fs.Directory = .{ .dir = bindings.staging.dir, .path = "" };
    const bytes = try readReviewed(allocator, io, staging, "input.json", review.input_sha256);
    const parsed = try c.parse(inputs.PreparedInputV2, allocator, bytes);
    const input = parsed.value;
    var chain: [4]receipts.Link = undefined;
    for ([_][]const u8{ "prepared.receipt.json", "configured.receipt.json", "built.receipt.json", "packaged.receipt.json" }, 0..) |name, i| {
        const receipt_bytes = try readReviewed(allocator, io, bindings.receipts, name, review.receipt_sha256[i]);
        const receipt = try receipts.parse(allocator, receipt_bytes, review.receipt_sha256[i]);
        chain[i] = .{ .receipt = receipt.value, .sha256 = review.receipt_sha256[i] };
    }
    try requireChain(allocator, chain, input, review);
    const reservation = try inputs.publicationAllowance(input.ledger);
    if (bytes.len > reservation) return error.ControlLimitExceeded;
    const input_file: c.File = .{ .path = "input.json", .size = bytes.len, .sha256 = review.input_sha256, .mode = 0o600 };
    const staging_before = try inputs.requireStagedClosure(allocator, io, &lock, input.selection.assets, input_file);
    try requireEngine(allocator, io, bindings.engine, review);
    try inputs.requireControlBinding(io, input.selection, bindings.assets, bindings.engine);
    try inputs.requireControlBinding(io, input.selection, bindings.assets, .{
        .directory = bindings.producer_source.provenance_bindings.producer,
        .contract = input.receipt.provenance.producer,
    });
    try verifySource(allocator, io, input.receipt.provenance, bindings.producer_source, review.provenance_sha256, deadline);
    for ([_][]const u8{ "configured.binding.json", "built.binding.json" }, 0..) |name, i| {
        const recorded = try readReviewed(allocator, io, bindings.receipts, name, review.execution_sha256[i]);
        try verifyExecution(allocator, io, recorded, chain[i + 1].receipt, review.execution_sha256[i], deadline);
        try requireProducerLocations(allocator, io, recorded, input, bindings);
        const inspection = input.selection.publication.inspections[i];
        const inspected = try readReviewed(allocator, io, bindings.receipts, inspection.path, inspection.sha256);
        try verifyStoredBinding(allocator, io, inspected, chain[i + 1].receipt.config_after, chain[i + 1].receipt.source_after, i == 1, inspection.sha256, deadline);
        try requireProducerLocations(allocator, io, inspected, input, bindings);
    }
    try inputs.validateSolvedConfig(allocator, io, input.selection, bindings.assets, bindings.config, input.receipt);
    _ = try package.validate(allocator, io, bindings.packaged, bindings.efi, input.receipt.packaging.?);
    try checkDeadline(deadline);
    try inputs.checkQemuClosure(allocator, io, input.selection, bindings.qemu);
    const capability = try inputs.loadCapability(allocator, io, input.selection, bindings.assets);
    defer capability.deinit();
    if (!std.meta.eql(capability.value.reviewed_provenance_sha256, review.capability_provenance_sha256))
        return error.UnreviewedInput;
    try verifySource(allocator, io, capability.value.provenance, bindings.capability_source, review.capability_provenance_sha256, deadline);
    const expected = try inputs.ledger(allocator, input.selection, chain[3]);
    const ledger_bindings = try allocator.alloc(budget.Binding, bindings.assets.len);
    for (bindings.assets, ledger_bindings) |binding, *target| target.* = .{ .id = binding.id, .directory = binding.directory };
    const totals = try budget.recompute(allocator, io, input.ledger, expected, ledger_bindings);
    if (!std.meta.eql(totals, input.budget)) return error.BudgetSubstitution;
    try verifySource(allocator, io, input.receipt.provenance, bindings.producer_source, review.provenance_sha256, deadline);
    try verifySource(allocator, io, capability.value.provenance, bindings.capability_source, review.capability_provenance_sha256, deadline);
    try inputs.checkQemuClosure(allocator, io, input.selection, bindings.qemu);
    try requireEngine(allocator, io, bindings.engine, review);
    try fs.requireTree(staging_before, try inputs.requireStagedClosure(allocator, io, &lock, input.selection.assets, input_file));
    try checkDeadline(deadline);
    return .{
        .arena = arena,
        .input = input,
        .chain = chain,
        .commitments = try project(input, review),
        .staging_tree = staging_before,
        .lock = lock,
        .io = io,
    };
}
