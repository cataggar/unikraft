const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");
const budget = @import("budget.zig");
const receipts = @import("receipts.zig");
const source = @import("source.zig");
const runtime = @import("runtime.zig");
const packaging = @import("package.zig");
const private = c.core.private_files;
const provenance = @import("provenance.zig");
const config = @import("config.zig");
const producer = @import("producer.zig");

pub const evidence_reservation: u64 = 8 * 1024 * 1024;
pub const firmware_copy_count = 6;
pub const Asset = struct {
    id: []const u8,
    role: budget.Role,
    source: c.File,
    destination: []const u8,
    placement: enum { staged, baked, future_copy },
};
pub const SelectionV2 = struct {
    schema: enum { hyperv_native_input_selection_v2 },
    packaged_receipt_sha256: c.Sha,
    solved_metadata: c.File,
    publication: struct { receipts: [4]c.File, executions: [2]c.File, inspections: [2]c.File },
    capability_source: c.Source,
    capability_receipt: c.File,
    qemu: runtime.Tool,
    assets: []const Asset,
};
pub const PreparedInputV2 = struct {
    schema: enum { hyperv_native_prepared_input_v2 },
    state: enum { prepared },
    authority: enum { not_admitted },
    receipt: receipts.Receipt,
    reviewed_selection_sha256: c.Sha,
    selection: Plan,
    ledger: []const budget.Entry,
    budget: budget.Totals,
};
pub const Plan = SelectionV2;
pub const Input = PreparedInputV2;
pub const Binding = struct { id: []const u8, directory: fs.Directory };
pub const Capability = struct {
    schema: enum { hyperv_public_capability_artifact_native_v1 },
    image: c.File,
    provenance: provenance.Record,
    reviewed_provenance_sha256: c.Sha,
    authority: enum { not_admitted },
};

pub fn requireFresh(io: std.Io, lock: *private.Locked) !void {
    try fs.requireLock(io, lock);
    var iterator = lock.directory.dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (!std.mem.eql(u8, entry.name, ".writer.lock")) return error.StagingNotFresh;
    }
}

pub fn requireStagedClosure(allocator: std.mem.Allocator, io: std.Io, lock: *private.Locked, assets: []const Asset, published: ?c.File) !c.Tree {
    try fs.requireLock(io, lock);
    var directory_count: usize = 0;
    try requireStagingDirectories(allocator, io, lock.directory.dir, "", assets, &directory_count, 0);
    const inventory = try fs.inventory(allocator, io, .{ .dir = lock.directory.dir, .path = "" }, 256, c.total_cap);
    var expected_count: usize = if (published != null) 2 else 1;
    for (assets) |item| if (item.placement == .staged) {
        expected_count += 1;
    };
    if (inventory.entries.len != expected_count) return error.InvalidSelection;
    for (inventory.entries) |record| {
        if (std.mem.eql(u8, record.path, ".writer.lock")) {
            if (record.size != 0 or record.mode != 0o600) return error.InvalidSelection;
            continue;
        }
        if (published) |input| if (std.mem.eql(u8, record.path, "input.json")) {
            const file = try (fs.Directory{ .dir = lock.directory.dir, .path = "" }).openFile(io, record.path, .private);
            file.close(io);
            try fs.requireFile(record, input);
            continue;
        };
        var found = false;
        for (assets) |item| {
            if (item.placement != .staged or !std.mem.eql(u8, record.path, item.destination)) continue;
            var expected = item.source;
            expected.path = item.destination;
            expected.mode = 0o600;
            const file = try (fs.Directory{ .dir = lock.directory.dir, .path = "" }).openFile(io, record.path, .private);
            file.close(io);
            try fs.requireFile(record, expected);
            found = true;
        }
        if (!found) return error.InvalidSelection;
    }
    return inventory.tree;
}

fn requireStagingDirectories(allocator: std.mem.Allocator, io: std.Io, directory: std.Io.Dir, prefix: []const u8, assets: []const Asset, count: *usize, depth: usize) !void {
    if (depth > 32 or count.* > 256) return error.LimitExceeded;
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        count.* += 1;
        const path = try std.fmt.allocPrint(allocator, "{s}{s}/", .{ prefix, entry.name });
        defer allocator.free(path);
        var required = false;
        for (assets) |item| if (item.placement == .staged and std.mem.startsWith(u8, item.destination, path)) {
            required = true;
        };
        if (!required) return error.InvalidSelection;
        const child = try directory.openDir(io, entry.name, .{ .follow_symlinks = false, .iterate = true });
        defer child.close(io);
        const info = try fs.metadata(.{ .handle = child.handle, .flags = .{ .nonblocking = false } });
        if (info.mode & 0o7777 != 0o700 or info.uid != std.os.linux.geteuid()) return error.UnsafeFile;
        try requireStagingDirectories(allocator, io, child, path, assets, count, depth + 1);
    }
}

pub fn asset(entries: []const Asset, role: budget.Role) !Asset {
    var found: ?Asset = null;
    for (entries) |entry| if (entry.role == role) {
        if (found != null) return error.InvalidSelection;
        found = entry;
    };
    return found orelse error.InvalidSelection;
}

pub fn publicationAsset(plan: Plan, expected: c.File) !Asset {
    var found: ?Asset = null;
    for (plan.assets) |item| {
        if (item.role != .publication_control or !std.mem.eql(u8, item.source.path, expected.path)) continue;
        try fs.requireFile(item.source, expected);
        if (found != null) return error.InvalidSelection;
        found = item;
    }
    return found orelse error.MissingControls;
}

pub fn controlAsset(plan: Plan, expected: c.File) !Asset {
    for (plan.assets) |item| {
        if (!item.role.isControl() or !std.mem.eql(u8, item.source.path, expected.path)) continue;
        if (std.meta.eql(item.source.sha256, expected.sha256)) {
            try fs.requireFile(item.source, expected);
            return item;
        }
    }
    return error.MissingControls;
}

/// Charge every physical file in an independently validated control runtime,
/// including its interpreter, libraries and non-ELF support files.
pub fn requireControlBinding(allocator: std.mem.Allocator, io: std.Io, plan: Plan, bindings: []const Binding, required: runtime.Bound) !void {
    const expected = required.contract.executable orelse return error.InvalidRuntime;
    if (required.contract.tree.bytes > c.control_cap) return error.ControlLimitExceeded;
    if (required.contract.tree.files > plan.assets.len) return error.MissingControlBinding;
    try requireControlFileBinding(io, plan, bindings, required.directory, expected, .executable);
    const inventory = try fs.inventory(allocator, io, required.directory, 240, c.control_cap);
    defer {
        for (inventory.entries) |file| allocator.free(file.path);
        allocator.free(inventory.entries);
    }
    try fs.requireTree(inventory.tree, required.contract.tree);
    for (inventory.entries) |file|
        try requireControlFileBinding(io, plan, bindings, required.directory, file, .artifact);
}

pub fn requireControlFileBinding(io: std.Io, plan: Plan, bindings: []const Binding, required_directory: fs.Directory, expected: c.File, policy: fs.Policy) !void {
    const required_file = try required_directory.openFile(io, expected.path, policy);
    defer required_file.close(io);
    const identity = try fs.metadata(required_file);
    if (identity.size != expected.size or identity.mode & 0o7777 != expected.mode or
        expected.size > c.total_cap or
        !std.meta.eql(try fs.hashFile(io, required_file, expected.size), expected.sha256) or
        !std.meta.eql(identity, try fs.metadata(required_file))) return error.HashMismatch;
    for (plan.assets) |item| {
        if (!item.role.isControl() or !std.mem.eql(u8, item.source.path, expected.path) or
            !std.meta.eql(item.source.sha256, expected.sha256)) continue;
        try fs.requireFile(item.source, expected);
        const directory = try binding(bindings, item.id);
        const selected = try directory.openFile(io, item.source.path, .artifact);
        defer selected.close(io);
        const actual = try fs.metadata(selected);
        if (std.meta.eql(actual, identity) and
            std.meta.eql(identity, try fs.metadata(required_file))) return;
    }
    return error.MissingControlBinding;
}

pub fn publicationAllowance(entries: []const budget.Entry) !u64 {
    var allowance: ?u64 = null;
    for (entries) |entry| if (entry.role == .publication_reservation and std.mem.eql(u8, entry.id, "remaining-controls")) {
        if (allowance != null or entry.source != null or entry.reserved == 0) return error.InvalidSelection;
        allowance = entry.reserved;
    };
    return allowance orelse error.InvalidSelection;
}

fn requirePolicyControls(allocator: std.mem.Allocator, io: std.Io, plan: Plan, bindings: []const Binding) !void {
    for (plan.publication.executions ++ plan.publication.inspections) |file| {
        const item = try publicationAsset(plan, file);
        const directory = try binding(bindings, item.id);
        const bytes = try directory.read(allocator, io, file.path, 4 * 1024 * 1024, .private);
        defer allocator.free(bytes);
        if (!std.meta.eql(c.digest(bytes), file.sha256) or bytes.len != file.size) return error.HashMismatch;
        const parsed = try c.parse(producer.Binding, allocator, bytes);
        defer parsed.deinit();
        try producer.validateBindingStructure(allocator, parsed.value);
        try producer.validatePolicyFiles(allocator, io, parsed.value);
        const isolated = parsed.value.isolation.?;
        const helper = try fs.Directory.open(allocator, io, isolated.helper.path);
        defer helper.close(allocator, io);
        const helper_runtime: runtime.Bound = .{ .directory = helper, .contract = isolated.helper.contract };
        try helper_runtime.validate(allocator, io);
        try requireControlBinding(allocator, io, plan, bindings, helper_runtime);
        const workspace = try fs.Directory.open(allocator, io, parsed.value.workspace.path);
        defer workspace.close(allocator, io);
        for ([_]c.File{ isolated.environment, isolated.make_environment.?, isolated.git_policy.? }) |policy|
            try requireControlFileBinding(io, plan, bindings, workspace, policy, .private);
    }
}

fn requireRuntimeAssets(plan: Plan) !void {
    var count: usize = 0;
    var bytes: u64 = 0;
    for (plan.assets, 0..) |item, i| {
        if (item.role != .qemu and item.role != .qemu_support) continue;
        for (plan.assets[0..i]) |previous| {
            if ((previous.role == .qemu or previous.role == .qemu_support) and
                std.mem.eql(u8, item.source.path, previous.source.path)) return error.IncompleteRuntime;
        }
        count += 1;
        bytes = try std.math.add(u64, bytes, item.source.size);
    }
    if (count != plan.qemu.tree.files or bytes != plan.qemu.tree.bytes) return error.IncompleteRuntime;
    if (plan.qemu.loader) |loader| try requireRuntimeAsset(plan.assets, loader);
    for (plan.qemu.libraries) |library| try requireRuntimeAsset(plan.assets, library);
}

fn requireRuntimeAsset(assets: []const Asset, expected: c.File) !void {
    for (assets) |item| {
        if (item.role == .qemu_support and std.mem.eql(u8, item.source.path, expected.path))
            return fs.requireFile(item.source, expected);
    }
    return error.IncompleteRuntime;
}

pub fn ledger(allocator: std.mem.Allocator, plan: Plan, packaged: receipts.Link) ![]budget.Entry {
    try receipts.requireLink(allocator, packaged);
    if (packaged.receipt.phase != .packaged or !std.meta.eql(plan.packaged_receipt_sha256, packaged.sha256))
        return error.ReceiptSubstitution;
    if (plan.assets.len == 0 or plan.assets.len > 240 or plan.qemu.role != .qemu or plan.qemu.target != .x86_64_linux or
        plan.qemu.executable == null) return error.InvalidSelection;
    try c.objectId(plan.capability_source.head);
    try c.objectId(plan.capability_source.tree);
    _ = try c.sha(&plan.capability_receipt.sha256);
    if (plan.capability_receipt.size == 0) return error.InvalidSelection;
    if (!std.mem.eql(u8, plan.solved_metadata.path, "native-config/metadata.tsv") or
        plan.solved_metadata.size == 0 or plan.solved_metadata.size > config.config_cap)
        return error.InvalidMetadata;
    var entries: std.ArrayList(budget.Entry) = .empty;
    errdefer entries.deinit(allocator);
    var working: usize = 0;
    var controls = [_]usize{0} ** 4;
    const vars = try asset(plan.assets, .firmware_vars);
    for (plan.assets) |item| {
        try c.relative(item.destination);
        if (item.destination[0] == '.' or std.mem.eql(u8, item.destination, "input.json")) return error.UnsafePath;
        if (item.role == .evidence or item.role == .publication_reservation) return error.InvalidSelection;
        if (item.role == .firmware_working_copy) {
            working += 1;
            if (item.placement != .future_copy) return error.InvalidSelection;
            try fs.requireFile(item.source, vars.source);
        } else if (item.role == .baked_control) {
            if (item.placement != .baked) return error.InvalidSelection;
        } else if (item.placement != .staged) return error.InvalidSelection;
        switch (item.role) {
            .native_control => controls[0] += 1,
            .producer_control => controls[1] += 1,
            .publication_control => controls[2] += 1,
            .baked_control => controls[3] += 1,
            else => {},
        }
        try entries.append(allocator, .{
            .id = item.id,
            .role = item.role,
            .artifact = item.destination,
            .source = item.source,
            .reserved = 0,
        });
    }
    if (working != firmware_copy_count) return error.InvalidSelection;
    for (controls) |count| if (count == 0) return error.MissingControls;
    try fs.requireFile((try asset(plan.assets, .raw)).source, packaged.receipt.packaging.?.raw);
    try fs.requireFile((try asset(plan.assets, .vhd)).source, packaged.receipt.packaging.?.vhd);
    if ((try asset(plan.assets, .vhd)).source.size != try std.math.add(u64, (try asset(plan.assets, .raw)).source.size, 512))
        return error.InvalidSelection;
    _ = try publicationAsset(plan, plan.solved_metadata);
    _ = try publicationAsset(plan, plan.capability_receipt);
    _ = try controlAsset(plan, packaged.receipt.provenance.producer.executable.?);
    if (packaged.receipt.provenance.producer.loader) |loader| _ = try controlAsset(plan, loader);
    for (packaged.receipt.provenance.producer.libraries) |library| _ = try controlAsset(plan, library);
    _ = try publicationAsset(plan, packaged.receipt.config_after);
    for (plan.publication.receipts, [_][]const u8{ "prepared.receipt.json", "configured.receipt.json", "built.receipt.json", "packaged.receipt.json" }) |file, name| {
        if (!std.mem.eql(u8, file.path, name) or file.mode != 0o600) return error.InvalidSelection;
        _ = try publicationAsset(plan, file);
    }
    if (!std.meta.eql(plan.publication.receipts[3].sha256, packaged.sha256) or
        !std.meta.eql(plan.publication.receipts[2].sha256, packaged.receipt.parent_sha256.?))
        return error.ReceiptSubstitution;
    for (plan.publication.executions, [_][]const u8{ "configured.binding.json", "built.binding.json" }) |file, name| {
        if (!std.mem.eql(u8, file.path, name) or file.mode != 0o600) return error.InvalidSelection;
        _ = try publicationAsset(plan, file);
    }
    for (plan.publication.inspections, [_][]const u8{ "configured.inspection.binding.json", "built.inspection.binding.json" }) |file, name| {
        if (!std.mem.eql(u8, file.path, name) or file.mode != 0o600) return error.InvalidSelection;
        _ = try publicationAsset(plan, file);
    }
    _ = try asset(plan.assets, .boot_disk);
    _ = try asset(plan.assets, .firmware_code);
    try fs.requireFile((try asset(plan.assets, .qemu)).source, plan.qemu.executable.?);
    try requireRuntimeAssets(plan);
    const observed = try budget.compute(entries.items);
    if (observed.control >= c.control_cap) return error.ControlLimitExceeded;
    // The input document and future commands consume this remaining allowance.
    // It is charged in full, so no self-referential manifest hash is invented.
    try entries.append(allocator, .{
        .id = "remaining-controls",
        .role = .publication_reservation,
        .artifact = "control-reservation",
        .source = null,
        .reserved = c.control_cap - observed.control,
    });
    try entries.append(allocator, try budget.reserve("evidence", "evidence-reservation", evidence_reservation));
    _ = try budget.compute(entries.items);
    return entries.toOwnedSlice(allocator);
}

pub fn binding(bindings: []const Binding, id: []const u8) !fs.Directory {
    var found: ?fs.Directory = null;
    for (bindings) |item| if (std.mem.eql(u8, item.id, id)) {
        if (found != null) return error.InvalidSelection;
        found = item.directory;
    };
    return found orelse error.InvalidSelection;
}

pub fn checkQemuClosure(allocator: std.mem.Allocator, io: std.Io, plan: Plan, qemu: fs.Directory) !void {
    try (runtime.Bound{ .directory = qemu, .contract = plan.qemu }).validate(allocator, io);
    const inventory = try fs.inventory(allocator, io, qemu, 256, c.total_cap);
    var count: usize = 0;
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    for (plan.assets) |item| {
        if (item.role != .qemu and item.role != .qemu_support) continue;
        if (seen.contains(item.source.path)) return error.IncompleteRuntime;
        try seen.put(item.source.path, {});
        count += 1;
        var found = false;
        for (inventory.entries) |member| if (std.mem.eql(u8, item.source.path, member.path)) {
            try fs.requireFile(item.source, member);
            found = true;
        };
        if (!found) return error.IncompleteRuntime;
    }
    if (count != inventory.entries.len) return error.IncompleteRuntime;
}

pub fn loadCapability(allocator: std.mem.Allocator, io: std.Io, plan: Plan, bindings: []const Binding) !std.json.Parsed(Capability) {
    const item = try publicationAsset(plan, plan.capability_receipt);
    const directory = try binding(bindings, item.id);
    try fs.requireFile(try directory.record(allocator, io, item.source.path, 1024 * 1024, .artifact), item.source);
    const bytes = try directory.read(allocator, io, item.source.path, 1024 * 1024, .artifact);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), plan.capability_receipt.sha256)) return error.HashMismatch;
    const parsed = try c.parse(Capability, allocator, bytes);
    errdefer parsed.deinit();
    try provenance.validate(parsed.value.provenance);
    try source.require(parsed.value.provenance.source, plan.capability_source);
    const encoded = try c.canonical(allocator, parsed.value.provenance);
    defer allocator.free(encoded);
    if (!std.meta.eql(c.digest(encoded), parsed.value.reviewed_provenance_sha256)) return error.UnreviewedInput;
    try fs.requireFile(parsed.value.image, (try asset(plan.assets, .boot_disk)).source);
    return parsed;
}

pub fn validateSolvedConfig(allocator: std.mem.Allocator, io: std.Io, plan: Plan, bindings: []const Binding, directory: fs.Directory, receipt: receipts.Receipt) !void {
    const item = try publicationAsset(plan, plan.solved_metadata);
    const metadata_directory = try binding(bindings, item.id);
    try fs.requireFile(try metadata_directory.record(allocator, io, item.source.path, config.config_cap, .artifact), item.source);
    const bytes = try metadata_directory.read(allocator, io, item.source.path, config.config_cap, .artifact);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), item.source.sha256)) return error.HashMismatch;
    try fs.requireFile(try directory.record(allocator, io, receipt.config_after.path, config.config_cap, .private), receipt.config_after);
    const solved = try directory.read(allocator, io, receipt.config_after.path, config.config_cap, .private);
    defer allocator.free(solved);
    if (!std.meta.eql(c.digest(solved), receipt.config_after.sha256)) return error.HashMismatch;
    try validateAuthoritativeConfig(allocator, solved, bytes, receipt.guard);
}

pub fn validateAuthoritativeConfig(allocator: std.mem.Allocator, solved: []const u8, metadata_bytes: []const u8, guard: config.Guard) !void {
    if (solved.len > config.config_cap or metadata_bytes.len > config.config_cap) return error.LimitExceeded;
    var metadata = try config.Metadata.parse(allocator, metadata_bytes);
    defer metadata.deinit();
    const kconfig = @import("native_kconfig");
    var diagnostic: kconfig.Diagnostic = .{};
    var document = try kconfig.parseWithMetadata(allocator, solved, &metadata, &diagnostic);
    defer document.deinit();
    for (document.entries.items) |entry|
        if (entry.symbol_type == null) return error.IncompleteMetadata;
    if (!document.enabled("ARCH_X86_64") or !document.enabled("PLAT_HYPERV")) return error.InvalidSelection;
    for ([_][]const u8{ "ARCH_ARM_64", "ARCH_ARM", "ARCH_X86_32", "PLAT_KVM", "PLAT_XEN", "PLAT_LINUXU" }) |name|
        if (document.enabled(name)) return error.InvalidSelection;
    try config.validateWithMetadata(allocator, solved, guard, &metadata);
}

pub fn validate(
    allocator: std.mem.Allocator,
    input: Input,
    expected_selection_sha256: c.Sha,
) !void {
    const selection = try c.canonical(allocator, input.selection);
    defer allocator.free(selection);
    if (!std.meta.eql(c.digest(selection), expected_selection_sha256) or
        !std.meta.eql(input.reviewed_selection_sha256, expected_selection_sha256)) return error.UnreviewedInput;
    const receipt = try c.canonical(allocator, input.receipt);
    defer allocator.free(receipt);
    const expected = try ledger(allocator, input.selection, .{ .receipt = input.receipt, .sha256 = c.digest(receipt) });
    defer allocator.free(expected);
    const totals = try budget.validateLedger(input.ledger, expected);
    if (!std.meta.eql(totals, input.budget)) return error.BudgetSubstitution;
}

/// This stages public/local artifacts only. No command, credential, upload,
/// historical state, completed handoff, or cloud-admission field is accepted.
pub fn generate(
    context: *receipts.Context,
    lock: *private.Locked,
    packaged: receipts.Link,
    package_directory: private.Directory,
    efi_directory: fs.Directory,
    plan: Plan,
    reviewed_selection_sha256: c.Sha,
    bindings: []const Binding,
    qemu_directory: fs.Directory,
) !Input {
    const allocator = context.allocator;
    const io = context.io;
    try requireFresh(io, lock);
    try receipts.requireLink(allocator, packaged);
    try context.requireReceiptBinding(packaged.receipt);
    const before = try context.verify();
    try source.require(before, packaged.receipt.source_after);
    const entries = try ledger(allocator, plan, packaged);
    errdefer allocator.free(entries);
    if (bindings.len != plan.assets.len) return error.InvalidSelection;
    const selection = try c.canonical(allocator, plan);
    defer allocator.free(selection);
    if (!std.meta.eql(c.digest(selection), reviewed_selection_sha256)) return error.UnreviewedInput;
    const package_bytes = try c.canonical(allocator, packaged.receipt);
    defer allocator.free(package_bytes);
    if (!std.meta.eql(c.digest(package_bytes), packaged.sha256)) return error.ReceiptSubstitution;
    _ = try packaging.validate(allocator, io, package_directory, efi_directory, packaged.receipt.packaging.?);
    try checkQemuClosure(allocator, io, plan, qemu_directory);
    const capability = try loadCapability(allocator, io, plan, bindings);
    defer capability.deinit();
    try validateSolvedConfig(allocator, io, plan, bindings, context.configuration_directory orelse return error.MissingConfiguration, packaged.receipt);
    for (plan.assets) |item| {
        const directory = try binding(bindings, item.id);
        try fs.requireFile(try directory.record(allocator, io, item.source.path, c.total_cap, .artifact), item.source);
    }
    try requireControlBinding(allocator, io, plan, bindings, .{ .directory = context.bindings.producer, .contract = context.review.producer });
    try requirePolicyControls(allocator, io, plan, bindings);
    const result: Input = .{
        .schema = .hyperv_native_prepared_input_v2,
        .state = .prepared,
        .authority = .not_admitted,
        .receipt = packaged.receipt,
        .reviewed_selection_sha256 = reviewed_selection_sha256,
        .selection = plan,
        .ledger = entries,
        .budget = try budget.compute(entries),
    };
    const bytes = try c.canonical(allocator, result);
    defer allocator.free(bytes);
    const remaining = try publicationAllowance(entries);
    if (bytes.len > remaining) return error.ControlLimitExceeded;
    for (plan.assets) |item| {
        if (item.placement != .staged) continue;
        const publication = try fs.copyImmutable(allocator, io, lock, try binding(bindings, item.id), item.source, item.destination, context.git.deadline);
        if (publication.failures.primary) |value| try context.failures.record(.primary, value);
        if (publication.failures.cleanup) |value| try context.failures.record(.cleanup, value);
        if (publication.failures.recording) |value| try context.failures.record(.recording, value);
        if (publication.status != .durable or publication.failures.cleanup != null) return error.PublicationIncomplete;
    }
    try source.require(before, try context.verify());
    try checkQemuClosure(allocator, io, plan, qemu_directory);
    for (plan.assets) |item| {
        try fs.requireFile(try (try binding(bindings, item.id)).record(allocator, io, item.source.path, c.total_cap, .artifact), item.source);
        if (item.placement == .staged) {
            const staged = try (fs.Directory{ .dir = lock.directory.dir, .path = "" }).record(
                allocator,
                io,
                item.destination,
                c.total_cap,
                .private,
            );
            var expected = item.source;
            expected.path = item.destination;
            expected.mode = 0o600;
            try fs.requireFile(staged, expected);
        }
    }
    if (try context.git.deadline.expired()) return error.DeadlineExceeded;
    _ = try requireStagedClosure(allocator, io, lock, plan.assets, null);
    const published = try fs.publish(lock, io, "input.json", bytes);
    if (published.failures.cleanup) |value| try context.failures.record(.cleanup, value);
    if (published.failures.recording) |value| try context.failures.record(.recording, value);
    if (published.status != .durable or published.failures.cleanup != null) return error.PublicationIncomplete;
    return result;
}
