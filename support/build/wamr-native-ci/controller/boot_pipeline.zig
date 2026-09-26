// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const builtin = @import("builtin");
const core = @import("hyperv_core");
const files = core.private_files;
const contracts = core.contracts;
const build = @import("build_pipeline.zig");
const adapter = @import("command_adapter.zig");
const plan = @import("command_plan.zig");
const inputs = @import("input_custody.zig");
const physical = @import("custody_files.zig");
const dependencies = @import("dependency_custody.zig");
const records = @import("records.zig");
const profile = @import("profile.zig");

const Value = std.json.Value;
const mib = 1024 * 1024;
const efi_name = "wamr_hyperv-x86_64-efi";
const marker = "WAMR_NATIVE_AOT_OK answer=42 teardown=0";
const legacy_marker = "Using legacy xAPIC MMIO";
const forbidden = [_][]const u8{
    "HYPERV_ACCEPTANCE", "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_PLATFORM_READY", "WAMR_NATIVE_WASI=", "WAMR_NATIVE_AOT_FAIL",
};

pub const Context = struct {
    build_context: *build.Context,
    pinned: std.StringHashMap(physical.File),
    boot_inputs: ?inputs.Custody = null,
    file_bindings: []const inputs.Binding = &.{},
    tree_bindings: []const inputs.Binding = &.{},
    package: ?Value = null,
    finalization: ?Value = null,
    derivation: ?Value = null,
    acceptance: ?Value = null,
    boots: [profile.production_modes.len]?Value = .{null} ** profile.production_modes.len,

    fn allocator(self: *Context) std.mem.Allocator {
        return self.build_context.allocator;
    }

    fn io(self: *Context) std.Io {
        return self.build_context.io;
    }

    fn path(self: *Context, relative: []const u8) ![]const u8 {
        return std.fs.path.join(self.allocator(), &.{ self.build_context.compute, relative });
    }

    fn evidencePath(self: *Context, name: []const u8) ![]const u8 {
        return self.path(try std.fs.path.join(self.allocator(), &.{ "evidence", name }));
    }

    fn cancelled(self: *Context) !void {
        if (self.build_context.signal.flag().load(.acquire)) return error.Cancelled;
    }

    fn pin(self: *Context, name: []const u8) !void {
        if (self.pinned.contains(name)) return error.PriorEvidence;
        const path_name = try self.evidencePath(name);
        const observed = try physical.readFile(self.io(), path_name, records.max_record_bytes, true);
        try self.pinned.put(try self.allocator().dupe(u8, name), observed);
    }

    fn checkPins(self: *Context) !void {
        var iterator = self.pinned.iterator();
        while (iterator.next()) |entry| {
            try self.cancelled();
            const observed = try physical.readFile(self.io(), try self.evidencePath(entry.key_ptr.*), records.max_record_bytes, true);
            if (!std.meta.eql(observed, entry.value_ptr.*)) return error.EvidenceChanged;
        }
    }

    fn requireExactEvidence(self: *Context) !void {
        const directory = try files.openDirectory(self.io(), try self.path("evidence"), .private);
        defer directory.close(self.io());
        try self.requireExactEvidenceIn(directory);
    }

    fn requireExactEvidenceIn(self: *Context, directory: std.Io.Dir) !void {
        var iterator = directory.iterate();
        var count: usize = 0;
        while (try iterator.next(self.io())) |entry| {
            try self.cancelled();
            if (!self.pinned.contains(entry.name) or count >= self.pinned.count())
                return error.UnexpectedEvidence;
            count += 1;
        }
        if (count != self.pinned.count()) return error.MissingEvidence;
        try self.checkPins();
    }

    fn hash(self: *Context, name: []const u8) ![]const u8 {
        const file = self.pinned.get(name) orelse return error.MissingEvidence;
        return self.allocator().dupe(u8, &file.sha256);
    }

    fn publish(self: *Context, name: []const u8, value: anytype) !void {
        try self.cancelled();
        try self.checkPins();
        const raw = try std.json.Stringify.valueAlloc(self.allocator(), value, .{});
        const encoded = try records.canonicalAlloc(self.allocator(), raw);
        const directory = try files.openDirectory(self.io(), try self.path("evidence"), .private);
        defer directory.close(self.io());
        if (std.mem.eql(u8, name, "result.json")) try self.requireExactEvidenceIn(directory);
        const file = try directory.createFile(self.io(), name, .{
            .exclusive = true, .read = true, .permissions = .fromMode(0o600),
        });
        defer file.close(self.io());
        try file.writeStreamingAll(self.io(), encoded);
        try file.sync(self.io());
        try (std.Io.File{ .handle = directory.handle, .flags = .{ .nonblocking = false } }).sync(self.io());
        try self.pin(name);
    }

    fn readValue(self: *Context, path_name: []const u8, limit: usize, private: bool) !Value {
        var retained = try files.RetainedFile.open(self.io(), path_name, if (private) .private else .artifact);
        defer retained.close(self.io());
        var buffer = try files.readSensitiveFile(self.io(), self.allocator(), retained.file, limit, if (private) .private else .artifact);
        defer buffer.deinit();
        const document = try contracts.Document.parse(self.allocator(), buffer.bytes(), .{
            .bytes = @min(limit, records.max_record_bytes), .depth = 32, .items = 4096, .tokens = 65536,
        });
        defer document.deinit();
        try document.requireCanonical(self.allocator(), buffer.bytes());
        try retained.verify(self.io());
        return std.json.parseFromSliceLeaky(Value, self.allocator(), buffer.bytes(), .{
            .duplicate_field_behavior = .@"error", .allocate = .alloc_always,
            .parse_numbers = false, .max_value_len = 4096,
        });
    }

    fn readEvidence(self: *Context, name: []const u8) !Value {
        const path_name = try self.evidencePath(name);
        const value = try self.readValue(path_name, records.max_record_bytes, true);
        const expected = self.pinned.get(name) orelse return error.MissingEvidence;
        if (!std.meta.eql(expected, try physical.readFile(self.io(), path_name, records.max_record_bytes, true)))
            return error.EvidenceChanged;
        return value;
    }

    fn base(self: *Context) !void {
        try self.cancelled();
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        var transient_build = self.build_context.*;
        transient_build.allocator = scratch.allocator();
        var transient = self.*;
        transient.build_context = &transient_build;
        try transient.checkPins();
        try build.requireBuildEvidence(&transient_build);
        try build.requireSource(&transient_build);
        try build.requireConsumer(&transient_build);
        try build.revalidateAccepted(&transient_build);
        const context = &transient_build;
        try dependencies.requireDocument(context.allocator, context.io, context.repository, context.git, context.compute, context.dependency.?);
        if (self.boot_inputs) |expected|
            try inputs.requireSame(context.allocator, context.io, expected, self.file_bindings, self.tree_bindings);
        try self.cancelled();
    }
};

pub const HostAdmitted = struct { context: *Context };
pub const BootInputsBound = struct { context: *Context };
pub const PackageCreated = struct { context: *Context };
pub const RawX2Validated = struct { context: *Context };
pub const RawLegacyValidated = struct { context: *Context };
pub const Qcow2IntentPublished = struct { context: *Context };
pub const Qcow2Finalized = struct { context: *Context };
pub const Qcow2X2Validated = struct { context: *Context };
pub const Qcow2LegacyValidated = struct { context: *Context };
pub const Qcow2Accepted = struct { context: *Context };
pub const DerivedVhdAbsenceProved = struct { context: *Context };
pub const VhdIntentPublished = struct { context: *Context };
pub const VhdGatePublished = struct { context: *Context };
pub const VhdDerived = struct { context: *Context };
pub const VpcX2Validated = struct { context: *Context };
pub const VpcLegacyValidated = struct { context: *Context };
pub const PackageInspected = struct { context: *Context };
pub const FinalInspectionPublished = struct { context: *Context };
pub const ResultPublished = struct { context: *Context };

fn advance(state: anytype, comptime T: type) T {
    return .{ .context = state.context };
}

fn field(value: Value, name: []const u8) !Value {
    if (value != .object) return error.InvalidEvidence;
    return value.object.get(name) orelse error.InvalidEvidence;
}

fn text(value: Value) ![]const u8 {
    return contracts.string(value);
}

fn number(comptime T: type, value: Value) !T {
    return contracts.integer(T, value);
}

fn sameText(value: Value, expected: []const u8) !void {
    if (!std.mem.eql(u8, try text(value), expected)) return error.InvalidEvidence;
}

fn sameJson(a: std.mem.Allocator, first: Value, second: Value) !void {
    const one = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, first, .{}));
    const two = try records.canonicalAlloc(a, try std.json.Stringify.valueAlloc(a, second, .{}));
    if (!std.mem.eql(u8, one, two)) return error.EvidenceChanged;
}

fn typed(a: std.mem.Allocator, value: anytype) !Value {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    return std.json.parseFromSliceLeaky(Value, a, raw, .{ .parse_numbers = false, .allocate = .alloc_always });
}

fn digestFile(ctx: *Context, path_name: []const u8, limit: u64, private: bool) !physical.File {
    return physical.readFile(ctx.io(), path_name, limit, private);
}

fn matchFile(ctx: *Context, path_name: []const u8, value: Value, limit: u64, private: bool) !physical.File {
    const observed = try digestFile(ctx, path_name, limit, private);
    if (!std.mem.eql(u8, &observed.sha256, try text(try field(value, "sha256"))))
        return error.ArtifactChanged;
    return observed;
}

fn absent(io: std.Io, path_name: []const u8) !void {
    if (files.openAbsolute(io, path_name, .artifact)) |file| {
        file.close(io);
        return error.PriorOutput;
    } else |err| if (err != error.FileNotFound) return err;
}

pub fn admitHost(architecture: std.Target.Cpu.Arch, kvm_mode: u32, accessible: bool) !void {
    if (architecture != .x86_64 or kvm_mode & std.os.linux.S.IFMT != std.os.linux.S.IFCHR or !accessible)
        return error.KvmUnavailable;
}

pub fn admit(context: *Context) !HostAdmitted {
    context.build_context.failed_stage = "boot-platform";
    try context.cancelled();
    if (builtin.cpu.arch != .x86_64) return error.KvmUnavailable;
    const device = std.Io.Dir.openFileAbsolute(context.io(), "/dev/kvm", .{
        .mode = .read_write, .follow_symlinks = false,
    }) catch return error.KvmUnavailable;
    defer device.close(context.io());
    const info = try files.snapshot(device);
    try admitHost(builtin.cpu.arch, info.mode, true);
    const runtime = try files.Directory.open(context.io(), context.build_context.runtime);
    defer runtime.close(context.io());
    const work = try files.Directory.open(context.io(), context.build_context.compute);
    defer work.close(context.io());
    try build.loadAccepted(context.build_context);
    for ([_][]const u8{ "package", "public-source", "boot-raw-x2apic",
        "boot-raw-legacy-apic", "boot-qcow2-x2apic", "boot-qcow2-legacy-apic",
        "boot-vpc-x2apic", "boot-vpc-legacy-apic" }) |name| {
        const slot = try files.Directory.open(context.io(), try context.path(name));
        defer slot.close(context.io());
        var iterator = slot.dir.iterate();
        if (try iterator.next(context.io()) != null) return error.PriorOutput;
    }
    for ([_][]const u8{ "build-start.json", "build.json",
        "command-adapter.json", "command-local-boot-tool.json",
        "command-fixtures.json", "command-prepare.json",
        "command-config.json", "command-native-image.json" }) |name|
        try context.pin(name);
    try context.base();
    return .{ .context = context };
}

pub fn bindInputs(state: HostAdmitted) !BootInputsBound {
    const ctx = state.context;
    ctx.build_context.failed_stage = "boot-input-record";
    try ctx.base();
    const a = ctx.allocator();
    const roots = &ctx.build_context.roots;
    roots.package_tool = try ctx.path("tools/bin/wamr-ci-package");
    roots.local_boot_tool = try ctx.path("local-boot-tools/bin/uk-hyperv-local-boot");
    roots.efi = try std.fs.path.join(a, &.{ ctx.build_context.repository, "support/apps/wamr-aot/build", efi_name });
    roots.identity = try std.fs.path.join(a, &.{ ctx.build_context.repository, "support/apps/wamr-aot/build/artifacts/identity.json" });
    roots.qemu = try std.fs.path.join(a, &.{ ctx.build_context.runtime, "bin/qemu-system-x86_64" });
    roots.ovmf_code = try std.fs.path.join(a, &.{ ctx.build_context.runtime, "firmware/code.fd" });
    roots.ovmf_vars = try std.fs.path.join(a, &.{ ctx.build_context.runtime, "firmware/vars.fd" });
    var bound: std.ArrayList(inputs.Binding) = .empty;
    const named = [_]inputs.Binding{
        .{ .role = "package_tool", .path = roots.package_tool },
        .{ .role = "local_boot_tool", .path = roots.local_boot_tool },
        .{ .role = "qemu", .path = roots.qemu },
        .{ .role = "ovmf_code", .path = roots.ovmf_code },
        .{ .role = "ovmf_vars", .path = roots.ovmf_vars },
        .{ .role = "efi", .path = roots.efi },
        .{ .role = "log_validator", .path = roots.validator },
    };
    try bound.appendSlice(a, &named);
    for (named) |binding| {
        var executable = try files.RetainedFile.open(ctx.io(), binding.path, .artifact);
        defer executable.close(ctx.io());
        if (executable.file_snapshot.mode & 0o111 == 0) continue;
        const closure = try inputs.executableRuntimePaths(a, ctx.io(), binding.path);
        for (closure) |path_name| {
            var found = false;
            for (bound.items) |previous| if (std.mem.eql(u8, previous.path, path_name)) {
                found = true;
                break;
            };
            if (!found) try bound.append(a, .{
                .role = try std.fmt.allocPrint(a, "runtime:{s}", .{path_name}), .path = path_name,
            });
        }
    }
    ctx.file_bindings = try bound.toOwnedSlice(a);
    const qemu_data = try std.fs.path.join(a, &.{ ctx.build_context.runtime, "bin/share" });
    ctx.tree_bindings = try a.dupe(inputs.Binding, &.{.{ .role = "qemu-data", .path = qemu_data }});
    ctx.boot_inputs = try inputs.capture(a, ctx.io(), ctx.file_bindings, ctx.tree_bindings);
    try ctx.publish("boot-inputs.json", try readValueFromCustody(ctx));
    try ctx.base();
    return advance(state, BootInputsBound);
}

fn readValueFromCustody(ctx: *Context) !Value {
    const raw = try ctx.boot_inputs.?.canonical(ctx.allocator());
    return std.json.parseFromSliceLeaky(Value, ctx.allocator(), raw, .{ .parse_numbers = false, .allocate = .alloc_always });
}

fn runStage(ctx: *Context, stage: plan.Stage, private_record: bool) !Value {
    ctx.build_context.failed_stage = @tagName(stage);
    try ctx.base();
    const is_validator = plan.isValidator(stage);
    if (private_record != is_validator) return error.InvalidStage;
    const slot = if (is_validator)
        std.fs.path.dirname(ctx.build_context.roots.serial) orelse return error.UnboundSerial
    else
        try ctx.path("evidence");
    const log_root = if (is_validator) slot else try ctx.path("private");
    const log_dir = try files.openDirectory(ctx.io(), log_root, .private);
    defer log_dir.close(ctx.io());
    const record_dir = try files.openDirectory(ctx.io(), slot, .private);
    defer record_dir.close(ctx.io());
    const outcome = try adapter.execute(ctx.allocator(), ctx.io(), .{
        .roots = ctx.build_context.roots, .stage = stage,
        .private_dir = log_dir, .evidence_dir = record_dir,
        .cancel = ctx.build_context.signal.flag(),
        .capture_stdout = true, .private_record = private_record,
    });
    if (outcome.poisoned) return error.CleanupPoisoned;
    if (!outcome.accepted) return error.StageRefused;
    try ctx.base();
    const name = try std.fmt.allocPrint(ctx.allocator(), "command-{s}.json", .{@tagName(stage)});
    if (is_validator) {
        _ = try physical.readFile(ctx.io(), try std.fs.path.join(ctx.allocator(), &.{ slot, name }), records.max_record_bytes, true);
    } else try ctx.pin(name);
    if (outcome.stdout.len == 0 or outcome.stderr_bytes != 0 and is_validator)
        return error.InvalidStageOutput;
    const document = try contracts.Document.parse(ctx.allocator(), outcome.stdout, .{
        .bytes = if (is_validator) 64 * 1024 else 64 * 1024,
        .depth = 32, .items = 4096, .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(ctx.allocator(), outcome.stdout);
    return std.json.parseFromSliceLeaky(Value, ctx.allocator(), outcome.stdout, .{ .parse_numbers = false, .allocate = .alloc_always });
}

fn packageImage(ctx: *Context) !Value {
    return field(ctx.package orelse return error.NoPackage, "image");
}

pub fn package(state: BootInputsBound) !PackageCreated {
    const ctx = state.context;
    try recordPackage(ctx, try runStage(ctx, .package, false));
    return advance(state, PackageCreated);
}

fn recordPackage(ctx: *Context, observed: Value) !void {
    try sameText(try field(observed, "scope"), "public_local_compute_packaging_only");
    try sameText(try field(observed, "acceptance"), "not_established");
    const image = try field(observed, "image");
    const boot_inputs = try ctx.readEvidence("boot-inputs.json");
    try sameText(try field(observed, "producer_sha256"),
        try text(try field(try field(try field(boot_inputs, "files"), "package_tool"), "sha256")));
    _ = try matchFile(ctx, ctx.build_context.roots.efi, try field(image, "efi"), 64 * mib, false);
    _ = try matchFile(ctx, try ctx.path("package/unikraft.raw"), try field(image, "raw"), 66 * mib, true);
    _ = try matchFile(ctx, try ctx.path("package/unikraft.vhd"), try field(image, "vhd"), 66 * mib + 512, true);
    var selected = Value{ .object = .empty };
    const image_out = try typed(ctx.allocator(), .{
        .schema_version = try field(image, "schema_version"),
        .miz_revision = try field(image, "miz_revision"),
        .efi = try field(image, "efi"),
        .raw = try field(image, "raw"),
        .vhd = try field(image, "vhd"),
        .footer_sha256 = try field(image, "footer_sha256"),
        .packaging = try field(image, "packaging"),
    });
    try selected.object.put(ctx.allocator(), "scope", try field(observed, "scope"));
    try selected.object.put(ctx.allocator(), "acceptance", try field(observed, "acceptance"));
    try selected.object.put(ctx.allocator(), "producer_sha256", try field(observed, "producer_sha256"));
    try selected.object.put(ctx.allocator(), "image", image_out);
    ctx.package = observed;
    try ctx.publish("package.json", selected);
}

pub fn parseValidator(a: std.mem.Allocator, raw: []const u8, expected_bytes: u64, expected_sha256: []const u8) !Value {
    const document = try contracts.Document.parse(a, raw, .{
        .bytes = 64 * 1024, .depth = 32, .items = 4096, .tokens = 65536,
    });
    defer document.deinit();
    try document.requireCanonical(a, raw);
    const validated = try contracts.exactFields(document.value(), &.{
        "schema", "schema_version", "mode", "raw_serial_bytes", "raw_serial_sha256", "compute",
    });
    try sameText(validated.get("schema").?, "uk.wamr.log-validation");
    if (try number(u8, validated.get("schema_version").?) != 1 or
        try number(u64, validated.get("raw_serial_bytes").?) != expected_bytes)
        return error.InvalidValidatorResult;
    try sameText(validated.get("mode").?, "tiny");
    try sameText(validated.get("raw_serial_sha256").?, expected_sha256);
    if (validated.get("compute").? != .object) return error.InvalidValidatorResult;
    return std.json.parseFromSliceLeaky(Value, a, raw, .{ .parse_numbers = false, .allocate = .alloc_always });
}

fn modeConfig(ctx: *Context, mode: profile.Mode) !Value {
    const a = ctx.allocator();
    var prohibited: std.ArrayList([]const u8) = .empty;
    try prohibited.appendSlice(a, &forbidden);
    if (!mode.legacyApic()) try prohibited.append(a, legacy_marker);
    const kind: []const u8 = switch (mode) {
        .@"raw-x2apic", .@"raw-legacy-apic" => "raw_disk",
        .@"qcow2-x2apic", .@"qcow2-legacy-apic" => "qcow2",
        .@"vpc-x2apic", .@"vpc-legacy-apic" => "fixed_vhd",
    };
    const roots = ctx.build_context.roots;
    const source_path = try ctx.path(try std.fmt.allocPrint(a, "package/{s}", .{plan.bootImage(mode)}));
    return typed(a, .{
        .source = .{ .kind = kind, .path = source_path },
        .ovmf_code = roots.ovmf_code, .ovmf_vars = roots.ovmf_vars, .qemu = roots.qemu,
        .work_dir = try ctx.path(try std.fmt.allocPrint(a, "boot-{s}", .{@tagName(mode)})),
        .expect = marker, .expect_main_return = @as(i32, 0),
        .required = if (mode.legacyApic()) &[_][]const u8{legacy_marker} else &[_][]const u8{},
        .forbidden = prohibited.items, .cpus = @as(u8, 1),
        .disable_x2apic = mode.legacyApic(), .timeout_ms = @as(u32, 60_000),
    });
}

fn pinFor(ctx: *Context, path_name: []const u8) !Value {
    var retained = try files.RetainedFile.open(ctx.io(), path_name, .artifact);
    defer retained.close(ctx.io());
    const current = try physical.readFile(ctx.io(), path_name, 256 * mib + 512, false);
    try retained.verify(ctx.io());
    const stat = retained.file_snapshot;
    const sha = try contracts.parseSha256(&current.sha256);
    return typed(ctx.allocator(), .{
        .device_major = stat.dev_major, .device_minor = stat.dev_minor,
        .inode = stat.ino, .mode = stat.mode, .uid = stat.uid, .gid = stat.gid,
        .nlink = stat.nlink, .size = stat.size,
        .mtime_seconds = stat.mtime.sec, .mtime_nanoseconds = stat.mtime.nsec,
        .ctime_seconds = stat.ctime.sec, .ctime_nanoseconds = stat.ctime.nsec,
        .sha256 = sha,
    });
}

const CheckedBoot = struct {
    report: Value,
    pins: Value,
    request_sha256: []const u8,
    report_sha256: []const u8,
    serial_sha256: []const u8,
    serial_bytes: u64,
};

fn checkBoot(ctx: *Context, index: usize) !CheckedBoot {
    const mode = profile.production_modes[index];
    const a = ctx.allocator();
    const work = try ctx.path(try std.fmt.allocPrint(a, "boot-{s}", .{@tagName(mode)}));
    const request_path = try std.fs.path.join(a, &.{ work, "request.json" });
    const report_path = try std.fs.path.join(a, &.{ work, "report.json" });
    const raw_path = try std.fs.path.join(a, &.{ work, "hyperv-efi-boot.log" });
    const request = try ctx.readValue(request_path, 64 * 1024, true);
    if (try number(u8, try field(request, "schema_version")) != 2 or
        try number(u32, try field(request, "supervisor_pid")) == 0)
        return error.InvalidBootRequest;
    try sameJson(a, try field(request, "config"), try modeConfig(ctx, mode));
    const pins = try field(request, "pins");
    if (pins != .array or pins.array.items.len != 4) return error.InvalidBootPins;
    const roots = ctx.build_context.roots;
    const source = try ctx.path(try std.fmt.allocPrint(a, "package/{s}", .{plan.bootImage(mode)}));
    for ([_][]const u8{ source, roots.ovmf_code, roots.ovmf_vars, roots.qemu }, pins.array.items) |path_name, pin|
        try sameJson(a, pin, try pinFor(ctx, path_name));
    const launched = try physical.readFile(ctx.io(), try std.fs.path.join(a, &.{ work, "launched" }), 1, true);
    if (launched.bytes != 0) return error.InvalidBootLaunch;
    const report = try ctx.readValue(report_path, 64 * 1024, true);
    try sameText(try field(report, "scope"), "public_local_qemu_only");
    try sameText(try field(report, "acceptance"), "not_established");
    if (try number(u8, try field(report, "schema_version")) != 1) return error.InvalidBootReport;
    for ([_][]const u8{ "passed", "consumed", "cleanup_complete", "input_unchanged", "serial_valid" }) |key| {
        const value = try field(report, key);
        if (value != .bool or !value.bool) return error.InvalidBootReport;
    }
    const limit = try field(report, "serial_limit_reached");
    if (limit != .bool or limit.bool) return error.InvalidBootReport;
    const term = try field(report, "termination");
    _ = try contracts.exactFields(term, &.{"exited"});
    if (try number(u8, try field(term, "exited")) != 0) return error.InvalidBootReport;
    const failures = try field(report, "failures");
    _ = try contracts.exactFields(failures, &.{ "primary", "cleanup", "recording" });
    for ([_][]const u8{ "primary", "cleanup", "recording" }) |key|
        if (try field(failures, key) != .null) return error.InvalidBootReport;
    const serial = try physical.readFile(ctx.io(), raw_path, 4 * mib, true);
    if (serial.bytes == 0 or serial.bytes >= 4 * mib or
        try number(u64, try field(report, "serial_bytes")) != serial.bytes or
        !std.mem.eql(u8, try text(try field(report, "serial_sha256")), &serial.sha256))
        return error.SerialChanged;
    const req = try physical.readFile(ctx.io(), request_path, 64 * 1024, true);
    const rep = try physical.readFile(ctx.io(), report_path, 64 * 1024, true);
    return .{
        .report = report, .pins = pins,
        .request_sha256 = try a.dupe(u8, &req.sha256),
        .report_sha256 = try a.dupe(u8, &rep.sha256),
        .serial_sha256 = try a.dupe(u8, &serial.sha256),
        .serial_bytes = serial.bytes,
    };
}

fn summary(ctx: *Context, index: usize, checked: CheckedBoot) !Value {
    const name = try std.fmt.allocPrint(ctx.allocator(), "{s}-compute.json", .{@tagName(profile.production_modes[index])});
    return typed(ctx.allocator(), .{
        .request_sha256 = checked.request_sha256, .report_sha256 = checked.report_sha256,
        .serial_sha256 = checked.serial_sha256, .compute_sha256 = try ctx.hash(name),
    });
}

fn requireModeImage(ctx: *Context, index: usize) !void {
    const mode = profile.production_modes[index];
    const expected = if (index < 2)
        try field(try packageImage(ctx), "raw")
    else if (index < 4)
        try field(ctx.finalization orelse return error.MissingFinalization, "output")
    else
        try field(ctx.derivation orelse return error.MissingDerivation, "output");
    _ = try matchFile(ctx, try ctx.path(try std.fmt.allocPrint(ctx.allocator(), "package/{s}", .{plan.bootImage(mode)})),
        expected, 66 * mib + 512, true);
}

fn verifyMode(ctx: *Context, index: usize) !Value {
    const mode = profile.production_modes[index];
    const checked = try checkBoot(ctx, index);
    const name = try std.fmt.allocPrint(ctx.allocator(), "{s}-compute.json", .{@tagName(mode)});
    const evidence = try ctx.readEvidence(name);
    try sameText(try field(evidence, "scope"), "local_native_compute_only");
    try sameJson(ctx.allocator(), try field(evidence, "report"), checked.report);
    try sameJson(ctx.allocator(), try field(evidence, "input_pins"), checked.pins);
    try sameText(try field(evidence, "request_sha256"), checked.request_sha256);
    try sameText(try field(evidence, "report_sha256"), checked.report_sha256);
    if (try field(evidence, "compute") != .object) return error.InvalidComputeEvidence;
    try requireModeImage(ctx, index);
    return summary(ctx, index, checked);
}

fn publishCheckedMode(ctx: *Context, index: usize, checked: CheckedBoot, compute: Value) !void {
    const evidence = try typed(ctx.allocator(), .{
        .scope = "local_native_compute_only", .report = checked.report,
        .input_pins = checked.pins, .request_sha256 = checked.request_sha256,
        .report_sha256 = checked.report_sha256, .compute = compute,
    });
    try publishMode(ctx, index, evidence);
    ctx.boots[index] = try verifyMode(ctx, index);
}

fn publishMode(ctx: *Context, index: usize, evidence: Value) !void {
    try requireModeImage(ctx, index);
    const name = try std.fmt.allocPrint(ctx.allocator(), "{s}-compute.json", .{@tagName(profile.production_modes[index])});
    try ctx.publish(name, evidence);
}

fn runMode(ctx: *Context, index: usize) !void {
    const mode = profile.production_modes[index];
    const report_result = try runStage(ctx, plan.modeStage(mode), false);
    const checked_before = try checkBoot(ctx, index);
    try sameJson(ctx.allocator(), report_result, checked_before.report);
    const a = ctx.allocator();
    const serial = try ctx.path(try std.fmt.allocPrint(a, "boot-{s}/hyperv-efi-boot.log", .{@tagName(mode)}));
    const identity = ctx.build_context.roots.identity;
    const serial_pin = try physical.readFile(ctx.io(), serial, 4 * mib, true);
    const identity_pin = try physical.readFile(ctx.io(), identity, mib, false);
    ctx.build_context.roots.serial = serial;
    const validator = try runStage(ctx, if (mode.legacyApic()) .@"log-validator-legacy" else .@"log-validator-x2apic", true);
    _ = try contracts.exactFields(validator, &.{
        "schema", "schema_version", "mode", "raw_serial_bytes", "raw_serial_sha256", "compute",
    });
    const expected_hash = try text(try field(checked_before.report, "serial_sha256"));
    try sameText(try field(validator, "schema"), "uk.wamr.log-validation");
    if (try number(u8, try field(validator, "schema_version")) != 1 or
        try number(u64, try field(validator, "raw_serial_bytes")) != checked_before.serial_bytes)
        return error.InvalidValidatorResult;
    try sameText(try field(validator, "mode"), "tiny");
    try sameText(try field(validator, "raw_serial_sha256"), expected_hash);
    const compute = try field(validator, "compute");
    if (compute != .object) return error.InvalidValidatorResult;
    if (!std.meta.eql(serial_pin, try physical.readFile(ctx.io(), serial, 4 * mib, true)) or
        !std.meta.eql(identity_pin, try physical.readFile(ctx.io(), identity, mib, false)))
        return error.ValidatorInputChanged;
    const checked = try checkBoot(ctx, index);
    try publishCheckedMode(ctx, index, checked, compute);
}

pub fn rawX2(state: PackageCreated) !RawX2Validated {
    try runMode(state.context, 0);
    return advance(state, RawX2Validated);
}
pub fn rawLegacy(state: RawX2Validated) !RawLegacyValidated {
    try runMode(state.context, 1);
    return advance(state, RawLegacyValidated);
}

const compute_limits = .{
    .max_input_bytes = 66 * mib,
    .max_output_bytes = 66 * mib + 512,
    .max_virtual_bytes = 66 * mib,
    .max_partition_array_bytes = mib,
    .max_metadata_bytes = 128 * 1024,
    .max_metadata_work = 8194,
    .max_work_bytes = 4 * 66 * mib,
    .max_memory_bytes = 512 * mib,
    .max_workload_bytes = 64 * mib,
};

fn noDerived(ctx: *Context) !void {
    try absent(ctx.io(), try ctx.path("package/unikraft-derived.vhd"));
    try absent(ctx.io(), try ctx.path("package/fixed-vhd-derivation.json"));
}

pub fn qcow2Intent(state: RawLegacyValidated) !Qcow2IntentPublished {
    const ctx = state.context;
    ctx.build_context.failed_stage = "qcow2-finalization-intent";
    try ctx.base();
    try publishQcow2Intent(ctx);
    return advance(state, Qcow2IntentPublished);
}

fn publishQcow2Intent(ctx: *Context) !void {
    const image = try packageImage(ctx);
    const raw = try field(image, "raw");
    const efi = try field(image, "efi");
    try noDerived(ctx);
    const raw_file = try matchFile(ctx, try ctx.path("package/unikraft.raw"), raw, 66 * mib, true);
    if (raw_file.bytes != try number(u64, try field(raw, "size"))) return error.RawImageChanged;
    try ctx.publish("qcow2-finalization-intent.json", .{
        .schema = "uk.wamr.compute-qcow2-finalization-intent",
        .schema_version = @as(u8, 1), .source_path = try ctx.path("package/unikraft.raw"),
        .expected_source_sha256 = try text(try field(raw, "sha256")),
        .expected_source_bytes = raw_file.bytes, .expected_virtual_bytes = raw_file.bytes,
        .expected_workload_sha256 = try text(try field(efi, "sha256")),
        .expected_workload_bytes = try number(u64, try field(efi, "size")),
        .timeout_ms = 120_000, .limits = compute_limits,
    });
}

fn packageProducer(ctx: *Context) ![]const u8 {
    const boot_inputs = try ctx.readEvidence("boot-inputs.json");
    return text(try field(try field(try field(boot_inputs, "files"), "package_tool"), "sha256"));
}

fn checkFinalize(ctx: *Context, value: Value) !void {
    _ = try contracts.exactFields(value, &.{
        "schema", "schema_version", "status", "source_sha256", "source_bytes",
        "output", "identity", "profile", "limits", "provenance",
    });
    try sameText(try field(value, "schema"), "uk.wamr.compute-qcow2-finalization");
    try sameText(try field(value, "status"), "succeeded");
    if (try number(u8, try field(value, "schema_version")) != 1) return error.InvalidQcow2;
    const image = try packageImage(ctx);
    const raw = try field(image, "raw");
    const efi = try field(image, "efi");
    try sameText(try field(value, "source_sha256"), try text(try field(raw, "sha256")));
    if (try number(u64, try field(value, "source_bytes")) != try number(u64, try field(raw, "size")))
        return error.InvalidQcow2;
    const output = try field(value, "output");
    const size = try number(u64, try field(output, "file_bytes"));
    if (size == 0 or size > 66 * mib or
        try number(u64, try field(output, "virtual_bytes")) != try number(u64, try field(raw, "size")))
        return error.InvalidQcow2;
    const record = try matchFile(ctx, try ctx.path("package/unikraft.qcow2"), output, 66 * mib, true);
    if (record.bytes != size) return error.InvalidQcow2;
    const identity = try field(value, "identity");
    try sameText(try field(identity, "workload_sha256"), try text(try field(efi, "sha256")));
    if (try number(u64, try field(identity, "workload_bytes")) != try number(u64, try field(efi, "size")))
        return error.InvalidQcow2;
    const expected_profile = try typed(ctx.allocator(), .{
        .format = "qcow2", .version = 3, .cluster_bytes = 64 * 1024,
        .compression = "zstd", .incompatible_features = 8,
        .compatible_features = 0, .autoclear_features = 0,
        .header_extensions = false, .extended_l2 = false, .encryption = false,
        .snapshots = 0, .backing_file = false, .external_data_file = false,
        .standalone = true,
    });
    try sameJson(ctx.allocator(), try field(value, "profile"), expected_profile);
    try sameJson(ctx.allocator(), try field(value, "limits"), try typed(ctx.allocator(), compute_limits));
    const provenance = try field(value, "provenance");
    try sameText(try field(provenance, "parent_kind"), "raw");
    try sameText(try field(provenance, "parent_sha256"), try text(try field(raw, "sha256")));
    try sameText(try field(provenance, "producer_sha256"), try packageProducer(ctx));
}

pub fn finalize(state: Qcow2IntentPublished) !Qcow2Finalized {
    const ctx = state.context;
    try recordFinalization(ctx, try runStage(ctx, .@"finalize-qcow2", false));
    return advance(state, Qcow2Finalized);
}

fn recordFinalization(ctx: *Context, observed: Value) !void {
    try checkFinalize(ctx, observed);
    try sameJson(ctx.allocator(), observed, try ctx.readValue(try ctx.path("package/qcow2-finalization.json"), 64 * 1024, true));
    ctx.finalization = observed;
    try ctx.publish("qcow2-finalization.json", observed);
}

pub fn qcow2X2(state: Qcow2Finalized) !Qcow2X2Validated {
    try runMode(state.context, 2);
    return advance(state, Qcow2X2Validated);
}
pub fn qcow2Legacy(state: Qcow2X2Validated) !Qcow2LegacyValidated {
    try runMode(state.context, 3);
    return advance(state, Qcow2LegacyValidated);
}

fn collectedBoots(ctx: *Context, count: usize) !Value {
    var object = Value{ .object = .empty };
    for (profile.production_modes[0..count], 0..) |mode, i| {
        const prior = ctx.boots[i] orelse return error.MissingBoot;
        const checked = try verifyMode(ctx, i);
        try sameJson(ctx.allocator(), checked, prior);
        try object.object.put(ctx.allocator(), @tagName(mode), checked);
    }
    return object;
}

fn artifact(ctx: *Context, path_name: []const u8, virtual_bytes: u64) !Value {
    const file = try physical.readFile(ctx.io(), path_name, 256 * mib + 512, false);
    var retained = try files.RetainedFile.open(ctx.io(), path_name, .artifact);
    defer retained.close(ctx.io());
    const stat = retained.file_snapshot;
    try retained.verify(ctx.io());
    return typed(ctx.allocator(), .{
        .path = path_name, .sha256 = file.sha256,
        .file_bytes = file.bytes,
        .allocated = .{ .state = "available", .bytes = stat.blocks * 512 },
        .virtual_bytes = virtual_bytes, .metadata = file.metadata,
    });
}

pub fn acceptQcow2(state: Qcow2LegacyValidated) !Qcow2Accepted {
    const ctx = state.context;
    ctx.build_context.failed_stage = "qcow2-acceptance";
    try ctx.base();
    try publishQcow2Acceptance(ctx);
    return advance(state, Qcow2Accepted);
}

fn publishQcow2Acceptance(ctx: *Context) !void {
    try noDerived(ctx);
    try checkFinalize(ctx, ctx.finalization.?);
    const output = try field(ctx.finalization.?, "output");
    const accepted = try artifact(ctx, try ctx.path("package/unikraft.qcow2"),
        try number(u64, try field(output, "virtual_bytes")));
    try sameText(try field(accepted, "sha256"), try text(try field(output, "sha256")));
    if (try number(u64, try field(accepted, "file_bytes")) != try number(u64, try field(output, "file_bytes")))
        return error.Qcow2Changed;
    const source = ctx.build_context.source.?;
    const modes = [_][]const u8{
        "raw-x2apic", "raw-legacy-apic", "qcow2-x2apic", "qcow2-legacy-apic",
    };
    try ctx.publish("qcow2-acceptance.json", .{
        .schema = "uk.wamr.compute-qcow2-acceptance", .schema_version = @as(u8, 1),
        .profile = "qcow2-derived-vhd", .status = "accepted",
        .source = .{ .revision = source.revision, .tree = source.tree },
        .accepted_qcow2 = accepted,
        .finalization_sha256 = try ctx.hash("qcow2-finalization.json"),
        .modes = modes, .boots = try collectedBoots(ctx, 4),
        .build_sha256 = try ctx.hash("build.json"),
        .boot_inputs_sha256 = try ctx.hash("boot-inputs.json"),
    });
    ctx.acceptance = try ctx.readEvidence("qcow2-acceptance.json");
}

pub fn proveAbsence(state: Qcow2Accepted) !DerivedVhdAbsenceProved {
    try state.context.base();
    try noDerived(state.context);
    return advance(state, DerivedVhdAbsenceProved);
}

pub fn vhdIntent(state: DerivedVhdAbsenceProved) !VhdIntentPublished {
    const ctx = state.context;
    try ctx.base();
    try publishVhdIntent(ctx);
    return advance(state, VhdIntentPublished);
}

fn publishVhdIntent(ctx: *Context) !void {
    try noDerived(ctx);
    const accepted = try field(ctx.acceptance.?, "accepted_qcow2");
    try ctx.publish("fixed-vhd-derivation-intent.json", .{
        .schema = "uk.wamr.compute-fixed-vhd-derivation-intent",
        .schema_version = @as(u8, 1),
        .source_path = try ctx.path("package/unikraft.qcow2"),
        .accepted_qcow2_sha256 = try text(try field(accepted, "sha256")),
        .expected_source_bytes = try number(u64, try field(accepted, "file_bytes")),
        .expected_capacity_bytes = try number(u64, try field(accepted, "virtual_bytes")),
        .timeout_ms = 120_000, .limits = compute_limits,
    });
}

pub fn vhdGate(state: VhdIntentPublished) !VhdGatePublished {
    const ctx = state.context;
    try ctx.base();
    try publishVhdGate(ctx);
    return advance(state, VhdGatePublished);
}

fn publishVhdGate(ctx: *Context) !void {
    try noDerived(ctx);
    try ctx.publish("fixed-vhd-derivation-gate.json", .{
        .schema = "uk.wamr.compute-fixed-vhd-derivation-gate",
        .schema_version = @as(u8, 1), .profile = "qcow2-derived-vhd",
        .status = "accepted_qcow2_only",
        .accepted_qcow2_sha256 = try text(try field(try field(ctx.acceptance.?, "accepted_qcow2"), "sha256")),
        .qcow2_acceptance_sha256 = try ctx.hash("qcow2-acceptance.json"),
        .derivation_intent_sha256 = try ctx.hash("fixed-vhd-derivation-intent.json"),
        .derived_output_absent = true,
    });
}

fn checkDerivation(ctx: *Context, value: Value) !void {
    _ = try contracts.exactFields(value, &.{
        "schema", "schema_version", "status", "accepted_qcow2",
        "accepted_qcow2_decoded_sha256", "accepted_qcow2_profile",
        "source_identity", "output", "output_identity", "footer",
        "relocation", "limits", "provenance",
    });
    try sameText(try field(value, "schema"), "uk.wamr.compute-fixed-vhd-derivation");
    try sameText(try field(value, "status"), "succeeded");
    if (try number(u8, try field(value, "schema_version")) != 1) return error.InvalidDerivation;
    const accepted = try field(ctx.acceptance.?, "accepted_qcow2");
    const source = try field(value, "accepted_qcow2");
    for ([_][]const u8{ "sha256", "file_bytes", "virtual_bytes" }) |key|
        try sameJson(ctx.allocator(), try field(source, key), try field(accepted, key));
    try sameText(try field(value, "accepted_qcow2_decoded_sha256"),
        try text(try field(try field(try packageImage(ctx), "raw"), "sha256")));
    try sameJson(ctx.allocator(), try field(value, "accepted_qcow2_profile"),
        try field(ctx.finalization.?, "profile"));
    try sameJson(ctx.allocator(), try field(value, "source_identity"),
        try field(ctx.finalization.?, "identity"));
    try sameJson(ctx.allocator(), try field(value, "output_identity"),
        try field(ctx.finalization.?, "identity"));
    try sameJson(ctx.allocator(), try field(value, "limits"), try typed(ctx.allocator(), compute_limits));
    const output = try field(value, "output");
    if (try number(u64, try field(output, "file_bytes")) != 66 * mib + 512 or
        try number(u64, try field(output, "virtual_bytes")) != 66 * mib)
        return error.InvalidDerivation;
    const actual = try matchFile(ctx, try ctx.path("package/unikraft-derived.vhd"), output, 66 * mib + 512, true);
    if (actual.bytes != 66 * mib + 512) return error.InvalidDerivation;
    const footer = try field(value, "footer");
    try sameText(try field(footer, "creator"), "miz ");
    if (try number(u64, try field(footer, "timestamp")) != 0) return error.InvalidDerivation;
    var retained = try files.RetainedFile.open(ctx.io(), try ctx.path("package/unikraft-derived.vhd"), .artifact);
    defer retained.close(ctx.io());
    var bytes: [512]u8 = undefined;
    if (try retained.file.readPositionalAll(ctx.io(), &bytes, actual.bytes - 512) != bytes.len)
        return error.InvalidDerivation;
    try retained.verify(ctx.io());
    const hash = std.fmt.bytesToHex(records.fileIdentity(&bytes), .lower);
    try sameText(try field(footer, "sha256"), &hash);
    const relocation = try field(value, "relocation");
    const expected = try typed(ctx.allocator(), .{
        .was_relocated = false,
        .old_backup_lba = try field(relocation, "new_backup_lba"),
        .new_backup_lba = try field(relocation, "new_backup_lba"),
        .old_last_usable_lba = try field(relocation, "new_last_usable_lba"),
        .new_last_usable_lba = try field(relocation, "new_last_usable_lba"),
        .allowed_differences = "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
    });
    try sameJson(ctx.allocator(), relocation, expected);
    const provenance = try field(value, "provenance");
    try sameText(try field(provenance, "parent_kind"), "qcow2");
    try sameText(try field(provenance, "parent_sha256"), try text(try field(accepted, "sha256")));
    try sameText(try field(provenance, "producer_sha256"), try packageProducer(ctx));
}

pub fn derive(state: VhdGatePublished) !VhdDerived {
    const ctx = state.context;
    try recordDerivation(ctx, try runStage(ctx, .@"derive-fixed-vhd", false));
    return advance(state, VhdDerived);
}

fn recordDerivation(ctx: *Context, observed: Value) !void {
    try checkDerivation(ctx, observed);
    try sameJson(ctx.allocator(), observed, try ctx.readValue(try ctx.path("package/fixed-vhd-derivation.json"), 64 * 1024, true));
    ctx.derivation = observed;
    try ctx.publish("fixed-vhd-derivation.json", observed);
}

pub fn vpcX2(state: VhdDerived) !VpcX2Validated {
    try runMode(state.context, 4);
    return advance(state, VpcX2Validated);
}
pub fn vpcLegacy(state: VpcX2Validated) !VpcLegacyValidated {
    try runMode(state.context, 5);
    return advance(state, VpcLegacyValidated);
}

pub fn inspect(state: VpcLegacyValidated) !PackageInspected {
    const ctx = state.context;
    const observed = try runStage(ctx, .inspect, false);
    try sameJson(ctx.allocator(), observed, ctx.package.?);
    return advance(state, PackageInspected);
}

pub fn finalInspection(state: PackageInspected) !FinalInspectionPublished {
    const ctx = state.context;
    ctx.build_context.failed_stage = "boot-final-inspection";
    try ctx.base();
    try ctx.publish("final-inspection.json", try inspectArtifacts(ctx));
    return advance(state, FinalInspectionPublished);
}

fn inspectArtifacts(ctx: *Context) !Value {
    try checkFinalize(ctx, try ctx.readEvidence("qcow2-finalization.json"));
    try checkDerivation(ctx, try ctx.readEvidence("fixed-vhd-derivation.json"));
    try sameJson(ctx.allocator(), ctx.acceptance.?, try ctx.readEvidence("qcow2-acceptance.json"));
    const boots = try collectedBoots(ctx, profile.production_modes.len);
    const image = try packageImage(ctx);
    const raw = try field(image, "raw");
    const efi = try field(image, "efi");
    const qcow2 = try field(ctx.finalization.?, "output");
    const derived = try field(ctx.derivation.?, "output");
    var artifacts = Value{ .object = .empty };
    for ([_]struct { name: []const u8, path_name: []const u8, identity: Value, virtual: u64 }{
        .{ .name = "efi", .path_name = ctx.build_context.roots.efi, .identity = efi,
            .virtual = try number(u64, try field(efi, "size")) },
        .{ .name = "raw", .path_name = try ctx.path("package/unikraft.raw"), .identity = raw,
            .virtual = try number(u64, try field(raw, "size")) },
        .{ .name = "qcow2", .path_name = try ctx.path("package/unikraft.qcow2"), .identity = qcow2,
            .virtual = try number(u64, try field(qcow2, "virtual_bytes")) },
        .{ .name = "vhd", .path_name = try ctx.path("package/unikraft-derived.vhd"), .identity = derived,
            .virtual = try number(u64, try field(derived, "virtual_bytes")) },
    }) |item| {
        const observed = try artifact(ctx, item.path_name, item.virtual);
        try sameText(try field(observed, "sha256"), try text(try field(item.identity, "sha256")));
        try artifacts.object.put(ctx.allocator(), item.name, observed);
    }
    var pin_map = Value{ .object = .empty };
    for ([_][]const u8{
        "build-start.json", "build.json", "boot-inputs.json", "package.json",
        "qcow2-finalization-intent.json", "qcow2-finalization.json", "qcow2-acceptance.json",
        "fixed-vhd-derivation-intent.json", "fixed-vhd-derivation-gate.json",
        "fixed-vhd-derivation.json",
    }) |name| try pin_map.object.put(ctx.allocator(), name, .{ .string = try ctx.hash(name) });
    const source = ctx.build_context.source.?;
    var modes: [profile.production_modes.len][]const u8 = undefined;
    for (profile.production_modes, &modes) |mode, *entry| entry.* = @tagName(mode);
    return typed(ctx.allocator(), .{
        .schema = "uk.wamr.compute-image-chain-inspection", .schema_version = @as(u8, 1),
        .profile = "qcow2-derived-vhd", .status = "complete",
        .source = .{ .revision = source.revision, .tree = source.tree },
        .artifacts = artifacts, .records = pin_map, .modes = modes, .boots = boots,
    });
}

pub fn result(state: FinalInspectionPublished) !ResultPublished {
    const ctx = state.context;
    ctx.build_context.failed_stage = "boot-final-custody";
    try ctx.base();
    try sameJson(ctx.allocator(), try ctx.readEvidence("final-inspection.json"), try inspectArtifacts(ctx));
    return publishAcceptedResult(ctx);
}

fn publishAcceptedResult(ctx: *Context) !ResultPublished {
    try ctx.requireExactEvidence();
    var map = Value{ .object = .empty };
    var iterator = ctx.pinned.iterator();
    while (iterator.next()) |record|
        try map.object.put(ctx.allocator(), record.key_ptr.*, .{
            .string = try ctx.allocator().dupe(u8, &record.value_ptr.sha256),
        });
    var modes: [profile.production_modes.len][]const u8 = undefined;
    for (profile.production_modes, &modes) |mode, *entry| entry.* = @tagName(mode);
    const accepted = try typed(ctx.allocator(), .{
        .schema_version = @as(u8, 2), .profile = "qcow2-derived-vhd",
        .scope = "local_native_compute_only", .passed = true,
        .hardware_acceptance = "not_established", .cloud_authority = "not_admitted",
        .benchmark = "not_measured", .workload = "tiny", .modes = modes, .records = map,
    });
    _ = try records.readResult(accepted);
    try ctx.publish("result.json", accepted);
    return .{ .context = ctx };
}

pub const testing = if (builtin.is_test) struct {
    pub fn revalidateBase(ctx: *Context) !void {
        return ctx.base();
    }

    pub fn publish(ctx: *Context, name: []const u8, value: Value) !void {
        return ctx.publish(name, value);
    }

    pub fn recordPackageResult(ctx: *Context, value: Value) !void {
        return recordPackage(ctx, value);
    }

    pub fn config(ctx: *Context, index: usize) !Value {
        return modeConfig(ctx, profile.production_modes[index]);
    }

    pub fn pin(ctx: *Context, path_name: []const u8) !Value {
        return pinFor(ctx, path_name);
    }

    pub fn recordBoot(ctx: *Context, index: usize, compute: Value) !void {
        return publishCheckedMode(ctx, index, try checkBoot(ctx, index), compute);
    }

    pub fn qcow2Intent(ctx: *Context) !void {
        return publishQcow2Intent(ctx);
    }

    pub fn qcow2Finalization(ctx: *Context, value: Value) !void {
        return recordFinalization(ctx, value);
    }

    pub fn qcow2Acceptance(ctx: *Context) !void {
        return publishQcow2Acceptance(ctx);
    }

    pub fn vhdIntent(ctx: *Context) !void {
        return publishVhdIntent(ctx);
    }

    pub fn vhdGate(ctx: *Context) !void {
        return publishVhdGate(ctx);
    }

    pub fn vhdDerivation(ctx: *Context, value: Value) !void {
        return recordDerivation(ctx, value);
    }

    pub fn inspect(ctx: *Context) !void {
        return ctx.publish("final-inspection.json", try inspectArtifacts(ctx));
    }

    pub fn resultAfterInspection(ctx: *Context) !ResultPublished {
        try sameJson(ctx.allocator(), try ctx.readEvidence("final-inspection.json"), try inspectArtifacts(ctx));
        return publishAcceptedResult(ctx);
    }

    pub fn checkExactEvidence(ctx: *Context) !void {
        return ctx.requireExactEvidence();
    }

    pub fn publishResult(ctx: *Context) !ResultPublished {
        return publishAcceptedResult(ctx);
    }

    pub fn publishCompute(ctx: *Context, index: usize, evidence: Value) !void {
        return publishMode(ctx, index, evidence);
    }

    pub fn checkModeImage(ctx: *Context, index: usize) !void {
        return requireModeImage(ctx, index);
    }
} else struct {};

pub fn run(context: *Context) !ResultPublished {
    const bound = try bindInputs(try admit(context));
    const packaged = try package(bound);
    const raw_0 = try rawX2(packaged);
    const raw_1 = try rawLegacy(raw_0);
    const intent = try qcow2Intent(raw_1);
    const qcow2 = try finalize(intent);
    const qcow2_0 = try qcow2X2(qcow2);
    const qcow2_1 = try qcow2Legacy(qcow2_0);
    const accepted = try acceptQcow2(qcow2_1);
    const absent_state = try proveAbsence(accepted);
    const vhd_intent = try vhdIntent(absent_state);
    const gate = try vhdGate(vhd_intent);
    const vhd = try derive(gate);
    const vpc_0 = try vpcX2(vhd);
    const vpc_1 = try vpcLegacy(vpc_0);
    const inspected = try inspect(vpc_1);
    return result(try finalInspection(inspected));
}

fn diagnosticBytes(ctx: *Context, path_name: []const u8, maximum: usize) ![]const u8 {
    var retained = try files.RetainedFile.open(ctx.io(), path_name, .private);
    defer retained.close(ctx.io());
    var buffer = try files.readSensitiveFile(ctx.io(), ctx.allocator(), retained.file, maximum, .private);
    defer buffer.deinit();
    try retained.verify(ctx.io());
    return ctx.allocator().dupe(u8, buffer.bytes());
}

fn diagnosticName(ctx: *Context, path_name: []const u8, upper: bool) ![]const u8 {
    const bytes = try diagnosticBytes(ctx, path_name, 96);
    if (bytes.len == 0 or bytes.len > 80 or
        !(if (upper) std.ascii.isUpper(bytes[0]) else std.ascii.isLower(bytes[0])))
        return error.InvalidDiagnostic;
    for (bytes[1..]) |byte|
        if (!(std.ascii.isAlphanumeric(byte) or (if (upper) false else byte == '-')))
            return error.InvalidDiagnostic;
    const hash = std.fmt.bytesToHex(records.fileIdentity(bytes), .lower);
    return ctx.allocator().dupe(u8, &hash);
}

fn testMarkers(a: std.mem.Allocator, raw: []const u8) !Value {
    var found = Value{ .array = std.array_list.Managed(Value).init(a) };
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (found.array.items.len >= 8) break;
        const suffix = if (std.mem.endsWith(u8, line, " ... ERROR"))
            " ... ERROR"
        else if (std.mem.endsWith(u8, line, " ... FAIL"))
            " ... FAIL"
        else
            continue;
        const at = std.mem.indexOf(u8, line, " (") orelse continue;
        if (!std.mem.startsWith(u8, line, "test_") or at <= 5 or
            line.len <= at + 3 + suffix.len or line[at + 2] == '.' or
            !std.mem.endsWith(u8, line[0 .. line.len - suffix.len], ")"))
            continue;
        var safe_name = true;
        for (line[0..at]) |byte| if (!(std.ascii.isAlphanumeric(byte) or byte == '_')) {
            safe_name = false;
            break;
        };
        if (!safe_name) continue;
        const module = line[at + 2 .. line.len - suffix.len - 1];
        if (module.len == 0 or module.len > 256) continue;
        var safe = true;
        for (module) |byte| if (!(std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '.')) {
            safe = false;
            break;
        };
        if (!safe) continue;
        const marker_name = try std.fmt.allocPrint(a, "{s}.{s}", .{ module, line[0..at] });
        var duplicate = false;
        for (found.array.items) |known| if (std.mem.eql(u8, known.string, marker_name)) {
            duplicate = true;
            break;
        };
        if (!duplicate) try found.array.append(.{ .string = marker_name });
    }
    return found;
}

fn commandFailure(ctx: *Context, name: []const u8) !?i32 {
    const path_name = try ctx.evidencePath(try std.fmt.allocPrint(ctx.allocator(), "command-{s}.json", .{name}));
    const record = ctx.readValue(path_name, records.max_record_bytes, true) catch return null;
    if (record != .object) return null;
    const code = number(i32, record.object.get("exit_code") orelse return null) catch return null;
    if (code == 0) return null;
    return code;
}

fn configFailure(ctx: *Context, code: i32) !Value {
    const a = ctx.allocator();
    const base = try std.fs.path.join(a, &.{ ctx.build_context.repository,
        "support/apps/wamr-aot/build/native-environment" });
    const dir = try files.Directory.open(ctx.io(), base);
    defer dir.close(ctx.io());
    const name = try diagnosticName(ctx, try std.fs.path.join(a, &.{ base, "failure-error-name.txt" }), true);
    var record = try typed(a, .{ .exit_code = code, .native_error_name_sha256 = name });
    if (diagnosticName(ctx, try std.fs.path.join(a, &.{ base, "failure-tool-role.txt" }), false) catch null) |role|
        try record.object.put(a, "tool_role_sha256", .{ .string = role });
    const diagnostic_path = try std.fs.path.join(a, &.{ base, "diagnostics" });
    const diagnostic_dir = try files.Directory.open(ctx.io(), diagnostic_path);
    defer diagnostic_dir.close(ctx.io());
    var iterator = diagnostic_dir.dir.iterate();
    const entry = try iterator.next(ctx.io()) orelse return error.InvalidDiagnostic;
    if (try iterator.next(ctx.io()) != null or entry.kind != .directory or
        !std.mem.startsWith(u8, entry.name, "image-")) return error.InvalidDiagnostic;
    for (entry.name["image-".len..]) |byte|
        if (!std.ascii.isDigit(byte) and byte != '-') return error.InvalidDiagnostic;
    const backend_path = try std.fs.path.join(a, &.{ diagnostic_path, entry.name });
    const backend_dir = try files.Directory.open(ctx.io(), backend_path);
    defer backend_dir.close(ctx.io());
    const backend = try ctx.readValue(
        try std.fs.path.join(a, &.{ backend_path, "000-root-olddefconfig.json" }), 64 * 1024, true);
    try sameText(try field(backend, "stage"), "root-olddefconfig");
    const exit_code = try number(u8, try field(try field(backend, "primary"), "exited"));
    const raw = try diagnosticBytes(ctx, try std.fs.path.join(a, &.{
        backend_path, "000-root-olddefconfig.stderr",
    }), 64 * 1024);
    try record.object.put(a, "backend_exit_code", try typed(a, exit_code));
    try record.object.put(a, "known_error_markers", try adapter.markers(a, raw));
    return record;
}

pub fn diagnostics(ctx: *Context) !void {
    const a = ctx.allocator();
    const io = ctx.io();
    const runtime = try files.Directory.open(io, ctx.build_context.runtime);
    defer runtime.close(io);
    if (files.Directory.open(io, ctx.build_context.compute)) |opened| {
        opened.close(io);
    } else |err| {
        if (err != error.FileNotFound) return err;
        try runtime.dir.createDir(io, "compute", .fromMode(0o700));
    }
    const work = try files.Directory.open(io, ctx.build_context.compute);
    defer work.close(io);
    if (files.Directory.open(io, try ctx.path("evidence"))) |opened| {
        opened.close(io);
    } else |err| {
        if (err != error.FileNotFound) return err;
        try work.dir.createDir(io, "evidence", .fromMode(0o700));
    }
    var observations = Value{ .object = .empty };
    for (profile.production_modes) |mode| {
        var item = try typed(a, .{ .report = "unavailable", .serial = "unavailable" });
        const work_path = try ctx.path(try std.fmt.allocPrint(a, "boot-{s}", .{@tagName(mode)}));
        const report_path = try std.fs.path.join(a, &.{ work_path, "report.json" });
        if (ctx.readValue(report_path, 64 * 1024, true) catch null) |report| {
            if (report != .object) {
                try observations.object.put(a, @tagName(mode), item);
                continue;
            }
            const flags = [_][]const u8{
                "passed", "cleanup_complete", "input_unchanged",
                "serial_valid", "serial_limit_reached",
            };
            var state = Value{ .object = .empty };
            var valid = true;
            for (flags) |name| {
                const value = report.object.get(name) orelse {
                    valid = false;
                    break;
                };
                if (value != .bool) {
                    valid = false;
                    break;
                }
                try state.object.put(a, name, value);
            }
            if (valid) {
                var lanes = Value{ .array = std.array_list.Managed(Value).init(a) };
                if (report.object.get("failures")) |failure| {
                    if (failure == .object) {
                        for ([_][]const u8{ "primary", "cleanup", "recording" }) |name|
                            if (failure.object.get(name)) |entry| {
                                if (entry != .null) try lanes.array.append(.{ .string = name });
                            };
                    }
                }
                try item.object.put(a, "report", state);
                try item.object.put(a, "failure_lanes", lanes);
                if (state.object.get("cleanup_complete").?.bool) {
                    const log_path = try std.fs.path.join(a, &.{ work_path, "hyperv-efi-boot.log" });
                    if (physical.readFile(io, log_path, 4 * mib, true) catch null) |log| {
                        try item.object.put(a, "serial", try typed(a, .{
                            .bytes = log.bytes, .sha256 = log.sha256,
                        }));
                    }
                }
            }
        }
        try observations.object.put(a, @tagName(mode), item);
    }
    var failures = Value{ .object = .empty };
    if (try commandFailure(ctx, "fixtures")) |code| {
        const log_path = try ctx.path("private/fixtures.log");
        const raw = diagnosticBytes(ctx, log_path, 64 * 1024) catch "";
        try failures.object.put(a, "fixtures", try typed(a, .{
            .exit_code = code, .tests = try testMarkers(a, raw),
        }));
    }
    if (try commandFailure(ctx, "config")) |code| {
        if (configFailure(ctx, code) catch null) |value|
            try failures.object.put(a, "config", value);
    }
    if (try commandFailure(ctx, "native-image")) |code| {
        const base = try std.fs.path.join(a, &.{ ctx.build_context.repository,
            "support/apps/wamr-aot/build/native-environment" });
        if (diagnosticName(ctx, try std.fs.path.join(a, &.{ base, "failure-error-name.txt" }), true) catch null) |name| {
            var item = try typed(a, .{ .exit_code = code, .native_error_name_sha256 = name });
            if (diagnosticName(ctx, try std.fs.path.join(a, &.{ base, "failure-image-guard.txt" }), false) catch null) |guard|
                try item.object.put(a, "image_guard_sha256", .{ .string = guard });
            if (diagnosticName(ctx, try std.fs.path.join(a, &.{ base, "failure-tool-role.txt" }), false) catch null) |role|
                try item.object.put(a, "tool_role_sha256", .{ .string = role });
            try failures.object.put(a, "native-image", item);
        }
    }
    try ctx.publish("diagnostics.json", .{
        .scope = "diagnostics_not_acceptance",
        .redaction = "no_raw_serial_paths_environment_or_account_state",
        .build_failures = failures,
        .boots = observations,
    });
}
