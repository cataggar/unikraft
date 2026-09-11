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

pub const evidence_reservation: u64 = 8 * 1024 * 1024;
pub const firmware_copy_count = 6;
pub const Asset = struct {
    id: []const u8,
    role: budget.Role,
    source: c.File,
    destination: []const u8,
    placement: enum { staged, baked, future_copy },
};
pub const Plan = struct {
    schema: enum { hyperv_native_input_selection_v1 },
    packaged_receipt_sha256: c.Sha,
    capability_source: c.Source,
    capability_receipt: c.File,
    qemu: runtime.Tool,
    assets: []const Asset,
};
pub const Input = struct {
    schema: enum { hyperv_native_prepared_input_v1 },
    state: enum { prepared },
    authority: enum { not_admitted },
    receipt: receipts.Receipt,
    reviewed_selection_sha256: c.Sha,
    selection: Plan,
    ledger: []const budget.Entry,
    budget: budget.Totals,
};
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

fn requireStagedClosure(allocator: std.mem.Allocator, io: std.Io, lock: *private.Locked, assets: []const Asset) !void {
    try fs.requireLock(io, lock);
    const inventory = try fs.inventory(allocator, io, .{ .dir = lock.directory.dir, .path = "" }, 256, c.total_cap);
    var expected_count: usize = 1;
    for (assets) |item| if (item.placement == .staged) {
        expected_count += 1;
    };
    if (inventory.entries.len != expected_count) return error.InvalidSelection;
    for (inventory.entries) |record| {
        if (std.mem.eql(u8, record.path, ".writer.lock")) continue;
        var found = false;
        for (assets) |item| {
            if (item.placement != .staged or !std.mem.eql(u8, record.path, item.destination)) continue;
            var expected = item.source;
            expected.path = item.destination;
            expected.mode = 0o600;
            try fs.requireFile(record, expected);
            found = true;
        }
        if (!found) return error.InvalidSelection;
    }
}

fn asset(entries: []const Asset, role: budget.Role) !Asset {
    var found: ?Asset = null;
    for (entries) |entry| if (entry.role == role) {
        if (found != null) return error.InvalidSelection;
        found = entry;
    };
    return found orelse error.InvalidSelection;
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

fn binding(bindings: []const Binding, id: []const u8) !fs.Directory {
    var found: ?fs.Directory = null;
    for (bindings) |item| if (std.mem.eql(u8, item.id, id)) {
        if (found != null) return error.InvalidSelection;
        found = item.directory;
    };
    return found orelse error.InvalidSelection;
}

fn checkQemuClosure(allocator: std.mem.Allocator, io: std.Io, plan: Plan, qemu: fs.Directory) !void {
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

fn checkCapability(allocator: std.mem.Allocator, io: std.Io, plan: Plan, bindings: []const Binding) !void {
    var selected: ?Asset = null;
    for (plan.assets) |item| {
        if (item.role != .publication_control or !std.meta.eql(item.source.sha256, plan.capability_receipt.sha256)) continue;
        try fs.requireFile(item.source, plan.capability_receipt);
        if (selected != null) return error.InvalidSelection;
        selected = item;
    }
    const item = selected orelse return error.InvalidSelection;
    const directory = try binding(bindings, item.id);
    const bytes = try directory.read(allocator, io, item.source.path, 1024 * 1024, .artifact);
    defer allocator.free(bytes);
    if (!std.meta.eql(c.digest(bytes), plan.capability_receipt.sha256)) return error.HashMismatch;
    const parsed = try c.parse(Capability, allocator, bytes);
    defer parsed.deinit();
    try provenance.validate(parsed.value.provenance);
    try source.require(parsed.value.provenance.source, plan.capability_source);
    const encoded = try c.canonical(allocator, parsed.value.provenance);
    defer allocator.free(encoded);
    if (!std.meta.eql(c.digest(encoded), parsed.value.reviewed_provenance_sha256)) return error.UnreviewedInput;
    try fs.requireFile(parsed.value.image, (try asset(plan.assets, .boot_disk)).source);
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
    try checkCapability(allocator, io, plan, bindings);
    for (plan.assets) |item| {
        const directory = try binding(bindings, item.id);
        try fs.requireFile(try directory.record(allocator, io, item.source.path, c.total_cap, .artifact), item.source);
    }
    const result: Input = .{
        .schema = .hyperv_native_prepared_input_v1,
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
    const remaining = entries[entries.len - 2].reserved;
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
    try requireStagedClosure(allocator, io, lock, plan.assets);
    const published = try fs.publish(lock, io, "input.json", bytes);
    if (published.failures.cleanup) |value| try context.failures.record(.cleanup, value);
    if (published.failures.recording) |value| try context.failures.record(.recording, value);
    if (published.status != .durable or published.failures.cleanup != null) return error.PublicationIncomplete;
    return result;
}
