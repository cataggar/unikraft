// SPDX-License-Identifier: BSD-3-Clause
//! WAMR-only approval and result adapter. No Azure calls or authority discovery.
const std = @import("std");
const core = @import("hyperv_core");
const base = @import("main.zig");
const serial = @import("local_serial");
const c = core.contracts;
const files = core.private_files;
pub const Artifact = base.Artifact;
pub const SerialMode = base.SerialMode;
pub const parse = base.parse;
pub const sdk = "a53205d77be3b880eb8f8b96679512ba58e2331a";
pub const marker = "WAMR_NATIVE_AOT_OK answer=42 teardown=0";
pub const prefix = "WAMR_NATIVE_COMPUTE=";
pub const forbidden = [_][]const u8{
    "HYPERV_ACCEPTANCE",        "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_PLATFORM_READY", "WAMR_NATIVE_WASI=",  "WAMR_NATIVE_AOT_FAIL",
};
pub const artifact_names = .{
    "efi",   "debug_elf",   "bootinfo",    "raw",              "vhd",            "runtime",      "compiler",
    "wasm",  "cwasm",       "config",      "runtime_identity", "image_identity", "local_result", "package",
    "build", "build_start", "boot_inputs",
};
pub const Identity = struct {
    wamr_revision: []const u8,
    wasm_sha256: []const u8,
    cwasm_sha256: []const u8,
    runtime_sha256: []const u8,
    compiler_sha256: []const u8,
    config_sha256: []const u8,
};
pub const Scope = struct {
    schema: []const u8,
    version: u8,
    purpose: enum { @"tiny-aot-two-boot" },
    authority: enum { not_admitted, final_image_approved },
    approval: struct {
        direct_specialized_gen2: bool,
        os_only_private: bool,
        two_boots_only: bool,
        cleanup_owned_group: bool,
        exact_image_and_local_bundle_reviewed: bool,
        fresh_final_approval: bool,
        approved_unix: u64,
        expires_unix: u64,
    },
    attempt_id: []const u8,
    subscription: []const u8,
    location: []const u8,
    prefix: []const u8,
    vm_size: []const u8,
    serial_mode: SerialMode,
    runtime_seconds: u32,
    cleanup_seconds: u32,
    operation_seconds: u32,
    poll_seconds: u32,
    source_revision: []const u8,
    source_tree: []const u8,
    identity: Identity,
    os_vhd: Artifact,
    bundle: Artifact,

    pub fn validate(self: Scope) !void {
        if (!eq(self.schema, "uk.wamr.direct-compute") or self.version != 1) return error.InvalidScope;
        if (self.authority != .final_image_approved) return error.NotAuthorized;
        inline for (.{ "direct_specialized_gen2", "os_only_private", "two_boots_only", "cleanup_owned_group", "exact_image_and_local_bundle_reviewed", "fresh_final_approval" }) |name|
            if (!@field(self.approval, name)) return error.NotAuthorized;
        try uuid(self.attempt_id);
        try uuid(self.subscription);
        if (!eq(self.location, "northeurope") or !eq(self.vm_size, "Standard_D2s_v5")) return error.InvalidTopology;
        if (self.prefix.len < 6 or self.prefix.len > 32) return error.InvalidPrefix;
        for (self.prefix) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-') return error.InvalidPrefix;
        if (self.runtime_seconds < 60 or self.runtime_seconds > 3600 or
            self.cleanup_seconds < 60 or self.cleanup_seconds > 1800 or
            self.operation_seconds < 10 or self.operation_seconds > 600 or
            self.poll_seconds < 1 or self.poll_seconds > 30) return error.InvalidBudget;
        if (self.approval.approved_unix == 0 or self.approval.expires_unix <= self.approval.approved_unix or
            self.approval.expires_unix - self.approval.approved_unix > 3600) return error.InvalidApprovalWindow;
        try hex(self.source_revision, 40);
        try hex(self.source_tree, 40);
        if (!eq(self.identity.wamr_revision, sdk)) return error.WrongSdk;
        inline for (std.meta.fields(Identity)) |member| {
            if (comptime !eq(member.name, "wamr_revision")) _ = try c.parseSha256(@field(self.identity, member.name));
        }
        try artifact(self.os_vhd);
        try artifact(self.bundle);
        if (self.os_vhd.size != 66 * 1024 * 1024 + 512 or self.bundle.size > 65536) return error.InvalidArtifact;
    }

    pub fn current(self: Scope, now: u64) !void {
        try self.validate();
        if (now < self.approval.approved_unix or now >= self.approval.expires_unix) return error.ApprovalExpired;
    }
};

pub const Boot = struct {
    mode: enum { @"raw-x2apic", @"raw-legacy-apic", @"vpc-x2apic", @"vpc-legacy-apic" },
    serial: Artifact,
    request: Artifact,
    report: Artifact,
    compute: Artifact,
};
pub const Bundle = struct {
    schema: []const u8,
    version: u8,
    authority: enum { not_admitted },
    source_revision: []const u8,
    source_tree: []const u8,
    identity: Identity,
    artifacts: [artifact_names.len]Artifact,
    boots: [4]Boot,
    evidence: []Artifact,

    pub fn get(self: Bundle, comptime name: []const u8) Artifact {
        inline for (artifact_names, 0..) |found, i| if (comptime eq(name, found)) return self.artifacts[i];
        @compileError("unknown compute artifact");
    }
};

pub const Result = struct {
    version: u8,
    workload: enum { tiny },
    wamr_revision: []const u8,
    wasm_sha256: []const u8,
    cwasm_sha256: []const u8,
    runtime_sha256: []const u8,
    platform_status: i32,
    checks: u32,
    answer: i32,
    terminal: u32,
    detail: u32,
    reserved_bytes: u64,
    frame_bytes: u64,
    accessible_bytes: u64,
    allocation_bytes: u64,
    system_page_table_bytes: u64,
    error_name: []const u8,

    pub fn validate(self: Result, identity: Identity) !void {
        if (self.version != 1 or self.platform_status != 0 or self.checks != 2 or self.answer != 42 or
            self.terminal != 1 or self.detail != 2 or self.reserved_bytes != 0 or self.frame_bytes != 0 or
            self.accessible_bytes != 0 or self.allocation_bytes != 0 or self.error_name.len != 0 or
            self.system_page_table_bytes == 0 or self.system_page_table_bytes > 256 * 1024 * 1024 or
            self.system_page_table_bytes % 4096 != 0) return error.ComputeFailed;
        inline for (.{ "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256" }) |name|
            if (!eq(@field(self, name), @field(identity, name))) return error.WrongComputeIdentity;
    }
};

pub const CaptureRecord = struct {
    schema: []const u8 = "uk.wamr.direct-serial-capture",
    version: u8 = 1,
    boot: u8,
    poll: u8,
    serial_mode: SerialMode,
    serial_sha256: []const u8,
    cli_wrapper_sha256: []const u8,
    scope_sha256: []const u8,
    vm_id: []const u8,
    vm_uuid: []const u8,
    os_id: []const u8,
    os_uuid: []const u8,
    data_id: ?[]const u8,
    data_uuid: ?[]const u8,
    vm_observation_sha256: []const u8,
    original_boot1_sha256: []const u8,
    boot2_admission_sha256: []const u8,
    compute_result_sha256: []const u8 = "",
    serial_bytes: u64 = 0,
};

pub fn checkSerial(a: std.mem.Allocator, raw: []const u8, identity: Identity) !Result {
    if (raw.len == 0) return error.EvidenceIncomplete;
    if (raw.len >= 4 * 1024 * 1024) return error.SerialLimit;
    const text = try serial.normalize(a, raw);
    defer a.free(text);
    for (forbidden ++ .{ "Unikraft Crash", "Assertion failure", "Exception Type" }) |bad|
        if (std.mem.indexOf(u8, text, bad) != null) return error.ForbiddenMarker;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var record: ?Result = null;
    var complete = false;
    var returned = false;
    var starts: u8 = 0;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (std.mem.indexOf(u8, line, "Calling main(") != null) {
            if (starts != 0 or record != null) return error.DuplicateStart;
            starts += 1;
        }
        if (std.mem.indexOf(u8, line, prefix) != null) {
            if (record != null or starts != 1 or complete or returned or !std.mem.startsWith(u8, line, prefix))
                return error.InvalidComputeRecord;
            const parsed = try parse(Result, a, line[prefix.len..]);
            defer parsed.deinit();
            try parsed.value.validate(identity);
            // All strings in a validated result equal the scope's stable pins.
            var result = parsed.value;
            inline for (.{ "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256" }) |name|
                @field(result, name) = @field(identity, name);
            result.error_name = "";
            record = result;
        }
        if (std.mem.indexOf(u8, line, marker) != null) {
            if (!eq(line, marker) or complete or record == null or returned) return error.InvalidCompletion;
            complete = true;
        }
        if (std.mem.indexOf(u8, line, "main returned") != null) {
            if (!complete or returned) return error.InvalidMainReturn;
            returned = true;
        }
    }
    if (!returned) return error.EvidenceIncomplete;
    try serial.validateEnvelope(a, raw, marker, 0, &.{}, &forbidden);
    return record orelse error.EvidenceIncomplete;
}

pub fn secondBytes(raw: []const u8, first: []const u8, mode: SerialMode) ![]const u8 {
    if (mode == .per_boot) return raw;
    const prefix_bytes = if (mode == .azure_cumulative) std.mem.trimEnd(u8, first, "\x00") else first;
    if (prefix_bytes.len == 0 or !std.mem.startsWith(u8, raw, prefix_bytes)) return error.WrongSerialPrefix;
    return raw[prefix_bytes.len..];
}

pub fn loadScope(a: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(Scope) {
    var bytes = try files.readSensitiveAbsolute(io, a, path, 65536, null);
    defer bytes.deinit();
    const scope = try parse(Scope, a, bytes.bytes());
    errdefer scope.deinit();
    try scope.value.validate();
    return scope;
}

pub fn inspectArtifact(io: std.Io, item: Artifact) !void {
    try artifact(item);
    const file = try files.openAbsolute(io, item.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    if (before.size != item.size) return error.ArtifactChanged;
    var hash = core.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (offset < item.size) {
        const n: usize = @intCast(@min(buffer.len, item.size - offset));
        if (try file.readPositionalAll(io, buffer[0..n], offset) != n) return error.ArtifactChanged;
        hash.update(buffer[0..n]);
        offset += n;
    }
    if (try file.readPositionalAll(io, buffer[0..1], offset) != 0 or !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
    if (!std.mem.eql(u8, &hash.finalResult(), &try c.parseSha256(item.sha256))) return error.HashMismatch;
}

fn read(a: std.mem.Allocator, io: std.Io, item: Artifact, limit: usize) ![]u8 {
    if (item.size > limit) return error.FileTooLarge;
    try inspectArtifact(io, item);
    const file = try files.openAbsolute(io, item.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    const bytes = try a.alloc(u8, @intCast(item.size));
    errdefer a.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len or !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
    var hash: [32]u8 = undefined;
    core.Sha256.hash(bytes, &hash, .{});
    if (!std.mem.eql(u8, &hash, &try c.parseSha256(item.sha256))) return error.HashMismatch;
    return bytes;
}

pub fn inspect(a: std.mem.Allocator, io: std.Io, scope: Scope) !void {
    const bytes = try read(a, io, scope.bundle, 65536);
    defer a.free(bytes);
    const parsed = try parse(Bundle, a, bytes);
    defer parsed.deinit();
    const bundle = parsed.value;
    if (!eq(bundle.schema, "uk.wamr.local-image-handoff") or bundle.version != 1 or
        !eq(bundle.source_revision, scope.source_revision) or !eq(bundle.source_tree, scope.source_tree))
        return error.WrongSource;
    inline for (std.meta.fields(Identity)) |member|
        if (!eq(@field(bundle.identity, member.name), @field(scope.identity, member.name))) return error.WrongComputeIdentity;
    if (!same(bundle.get("vhd"), scope.os_vhd)) return error.WrongImage;
    inline for (.{ .{ "runtime", "runtime_sha256" }, .{ "compiler", "compiler_sha256" }, .{ "wasm", "wasm_sha256" }, .{ "cwasm", "cwasm_sha256" }, .{ "config", "config_sha256" } }) |pair|
        if (!eq(bundle.get(pair[0]).sha256, @field(scope.identity, pair[1]))) return error.WrongComputeIdentity;
    try verifyBundle(a, io, bundle);
}

pub fn verifyBundle(a: std.mem.Allocator, io: std.Io, bundle: Bundle) !void {
    if (!eq(bundle.schema, "uk.wamr.local-image-handoff") or bundle.version != 1 or
        !eq(bundle.identity.wamr_revision, sdk)) return error.WrongSdk;
    try hex(bundle.source_revision, 40);
    try hex(bundle.source_tree, 40);
    inline for (.{ .{ "runtime", "runtime_sha256" }, .{ "compiler", "compiler_sha256" }, .{ "wasm", "wasm_sha256" }, .{ "cwasm", "cwasm_sha256" }, .{ "config", "config_sha256" } }) |pair|
        if (!eq(bundle.get(pair[0]).sha256, @field(bundle.identity, pair[1]))) return error.WrongComputeIdentity;
    for (bundle.artifacts) |item| try inspectArtifact(io, item);
    try evidenceRecords(a, io, bundle);
    try rawVhd(io, bundle.get("raw"), bundle.get("vhd"));
    for (bundle.boots, 0..) |boot, i| {
        if (@intFromEnum(boot.mode) != i) return error.WrongLocalMode;
        inline for (.{ "request", "report", "compute" }) |name| try inspectArtifact(io, @field(boot, name));
        const raw = try read(a, io, boot.serial, 4 * 1024 * 1024);
        defer a.free(raw);
        const result = try checkSerial(a, raw, bundle.identity);
        const text = try serial.normalize(a, raw);
        defer a.free(text);
        if (std.mem.count(u8, text, "Using legacy xAPIC MMIO") != i % 2) return error.WrongLocalMode;
        try localReport(a, io, boot, if (i < 2) bundle.get("raw") else bundle.get("vhd"), result);
    }
}

fn evidenceRecords(a: std.mem.Allocator, io: std.Io, bundle: Bundle) !void {
    const bytes = try read(a, io, bundle.get("local_result"), 65536);
    defer a.free(bytes);
    const document = try c.Document.parse(a, bytes, .{ .bytes = 65536 });
    defer document.deinit();
    const value = document.value();
    if (!eq(try string(value, "scope"), "local_native_compute_only") or
        !eq(try string(value, "cloud_authority"), "not_admitted") or
        !eq(try string(value, "hardware_acceptance"), "not_established") or
        !eq(try string(value, "benchmark"), "not_measured") or
        !eq(try string(value, "workload"), "tiny")) return error.WrongLocalReport;
    const passed = try field(value, "passed");
    if (passed != .bool or !passed.bool) return error.LocalBootFailed;
    const records = try field(value, "records");
    if (records != .object or records.object.count() != bundle.evidence.len or bundle.evidence.len < 8) return error.WrongLocalReport;
    for (bundle.evidence, 0..) |item, i| {
        const name = std.fs.path.basename(item.path);
        for (bundle.evidence[0..i]) |prior|
            if (eq(std.fs.path.basename(prior.path), name)) return error.DuplicateField;
        if (!eq(try c.string(records.object.get(name) orelse return error.MissingField), item.sha256)) return error.HashMismatch;
        try inspectArtifact(io, item);
    }
    inline for (.{ "build", "build_start", "boot_inputs", "package" }, .{ "build.json", "build-start.json", "boot-inputs.json", "package.json" }) |name, filename| {
        if (!eq(try c.string(records.object.get(filename) orelse return error.MissingField), bundle.get(name).sha256)) return error.HashMismatch;
    }
    for (bundle.boots) |boot| {
        const filename = try std.fmt.allocPrint(a, "{s}-compute.json", .{@tagName(boot.mode)});
        defer a.free(filename);
        if (!eq(try c.string(records.object.get(filename) orelse return error.MissingField), boot.compute.sha256)) return error.HashMismatch;
    }
    const build_bytes = try read(a, io, bundle.get("build"), 65536);
    defer a.free(build_bytes);
    const build_doc = try c.Document.parse(a, build_bytes, .{ .bytes = 65536 });
    defer build_doc.deinit();
    const source = try field(build_doc.value(), "source");
    if (!eq(try string(source, "revision"), bundle.source_revision) or !eq(try string(source, "tree"), bundle.source_tree))
        return error.WrongSource;
    const runtime = try field(build_doc.value(), "runtime");
    if (!eq(try string(runtime, "wamr_revision"), sdk) or
        !eq(try string(runtime, "compiler_profile"), "unikraft-x86_64") or
        !eq(try string(runtime, "zig_version"), "0.16.0")) return error.WrongSdk;
    const wasi = try field(runtime, "minimal_wasi");
    if (wasi != .bool or wasi.bool) return error.WrongSdk;
    const runtime_files = try field(runtime, "files");
    inline for (.{ .{ "tiny.wasm", "wasm" }, .{ "tiny.cwasm", "cwasm" }, .{ "wamrc", "compiler" }, .{ "libwamr-aot.a", "runtime" } }) |pair|
        if (!eq(try string(runtime_files, pair[0]), bundle.get(pair[1]).sha256)) return error.WrongComputeIdentity;
    const image = try field(build_doc.value(), "image");
    if (!eq(try string(image, "unikraft_revision"), bundle.source_revision) or
        !eq(try string(image, "runtime_inputs_sha256"), bundle.get("runtime_identity").sha256) or
        !eq(try string(image, "solved_config_sha256"), bundle.get("config").sha256)) return error.WrongSource;
    inline for (.{ .{ "wamr_hyperv-x86_64-efi", "efi" }, .{ "wamr_hyperv-x86_64-efi.dbg", "debug_elf" }, .{ "wamr_hyperv-x86_64-efi.bootinfo", "bootinfo" } }) |pair|
        if (!eq(try string(try field(image, "files"), pair[0]), bundle.get(pair[1]).sha256)) return error.WrongImage;
    const package_bytes = try read(a, io, bundle.get("package"), 65536);
    defer a.free(package_bytes);
    const package_doc = try c.Document.parse(a, package_bytes, .{ .bytes = 65536 });
    defer package_doc.deinit();
    const package = package_doc.value();
    if (!eq(try string(package, "scope"), "public_local_compute_packaging_only") or
        !eq(try string(package, "acceptance"), "not_established")) return error.WrongLocalReport;
    inline for (.{ "efi", "raw", "vhd" }) |name| {
        const item = try field(try field(package, "image"), name);
        if (!eq(try string(item, "sha256"), bundle.get(name).sha256) or
            try c.integer(u64, try field(item, "size")) != bundle.get(name).size) return error.WrongImage;
    }
}

fn localReport(a: std.mem.Allocator, io: std.Io, boot: Boot, image: Artifact, result: Result) !void {
    const bytes = try read(a, io, boot.report, 65536);
    defer a.free(bytes);
    const doc = try c.Document.parse(a, bytes, .{ .bytes = 65536 });
    defer doc.deinit();
    const value = doc.value();
    if (!eq(try string(value, "scope"), "public_local_qemu_only") or
        !eq(try string(value, "acceptance"), "not_established") or
        try c.integer(u8, try field(value, "schema_version")) != 1) return error.WrongLocalReport;
    inline for (.{ "passed", "consumed", "cleanup_complete", "input_unchanged", "serial_valid" }) |name| {
        const flag = try field(value, name);
        if (flag != .bool or !flag.bool) return error.LocalBootFailed;
    }
    const limited = try field(value, "serial_limit_reached");
    if (limited != .bool or limited.bool or
        try c.integer(u64, try field(value, "serial_bytes")) != boot.serial.size or
        !eq(try string(value, "serial_sha256"), boot.serial.sha256) or
        try c.integer(u8, try field(try field(value, "termination"), "exited")) != 0) return error.LocalBootFailed;
    inline for (.{ "primary", "cleanup", "recording" }) |name|
        if (try field(try field(value, "failures"), name) != .null) return error.LocalBootFailed;
    const request_bytes = try read(a, io, boot.request, 65536);
    defer a.free(request_bytes);
    const request = try c.Document.parse(a, request_bytes, .{ .bytes = 65536 });
    defer request.deinit();
    const config = try field(request.value(), "config");
    const source = try field(config, "source");
    const mode = @intFromEnum(boot.mode);
    if (try c.integer(u8, try field(request.value(), "schema_version")) != 1 or
        !eq(try string(config, "expect"), marker) or
        try c.integer(i32, try field(config, "expect_main_return")) != 0 or
        try c.integer(u8, try field(config, "cpus")) != 1 or
        try c.integer(u32, try field(config, "timeout_ms")) != 60000 or
        !eq(try string(source, "kind"), if (mode < 2) "raw_disk" else "fixed_vhd"))
        return error.WrongLocalReport;
    _ = try string(source, "path");
    const legacy = try field(config, "disable_x2apic");
    if (legacy != .bool or legacy.bool != (mode % 2 == 1)) return error.WrongLocalMode;
    const pins = try field(request.value(), "pins");
    if (pins != .array or pins.array.items.len != 4) return error.WrongLocalReport;
    const pin = pins.array.items[0];
    if (try c.integer(u64, try field(pin, "size")) != image.size) return error.WrongImage;
    const hash = try field(pin, "sha256");
    if (hash != .array or hash.array.items.len != 32) return error.WrongImage;
    for (hash.array.items, try c.parseSha256(image.sha256)) |byte, expected|
        if (try c.integer(u8, byte) != expected) return error.WrongImage;
    const compute_bytes = try read(a, io, boot.compute, 65536);
    defer a.free(compute_bytes);
    const computed = try c.Document.parse(a, compute_bytes, .{ .bytes = 65536 });
    defer computed.deinit();
    const observation = computed.value();
    if (!eq(try string(observation, "scope"), "local_native_compute_only") or
        !eq(try string(observation, "request_sha256"), boot.request.sha256) or
        !eq(try string(observation, "report_sha256"), boot.report.sha256)) return error.WrongLocalReport;
    const encoded = try std.json.Stringify.valueAlloc(a, try field(observation, "compute"), .{});
    defer a.free(encoded);
    const checked = try parse(Result, a, encoded);
    defer checked.deinit();
    inline for (std.meta.fields(Result)) |member| {
        const actual = @field(checked.value, member.name);
        const expected = @field(result, member.name);
        if (comptime member.type == []const u8) {
            if (!eq(actual, expected)) return error.WrongLocalReport;
        } else if (actual != expected) return error.WrongLocalReport;
    }
}

pub fn rawVhd(io: std.Io, raw: Artifact, vhd: Artifact) !void {
    if (raw.size != 66 * 1024 * 1024 or vhd.size != raw.size + 512) return error.InvalidArtifact;
    const file = try files.openAbsolute(io, vhd.path, .artifact);
    defer file.close(io);
    const before = try files.snapshot(file);
    var hash = core.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (offset < raw.size) {
        const n: usize = @intCast(@min(buffer.len, raw.size - offset));
        if (try file.readPositionalAll(io, buffer[0..n], offset) != n) return error.ArtifactChanged;
        hash.update(buffer[0..n]);
        offset += n;
    }
    if (!std.mem.eql(u8, &hash.finalResult(), &try c.parseSha256(raw.sha256))) return error.WrongRawPrefix;
    var footer: [512]u8 = undefined;
    if (try file.readPositionalAll(io, &footer, offset) != 512) return error.ArtifactChanged;
    try base.footer(&footer, raw.size, null);
    if (try file.readPositionalAll(io, buffer[0..1], vhd.size) != 0 or !files.sameSnapshot(before, try files.snapshot(file))) return error.ArtifactChanged;
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidObject;
    return value.object.get(name) orelse error.MissingField;
}
fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    return c.string(try field(value, name));
}
fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn same(a: Artifact, b: Artifact) bool {
    return a.size == b.size and eq(a.sha256, b.sha256) and eq(a.path, b.path);
}
fn artifact(item: Artifact) !void {
    try files.absoluteFilePath(item.path);
    _ = try c.parseSha256(item.sha256);
    if (item.size == 0 or item.size > 256 * 1024 * 1024 + 512) return error.InvalidArtifact;
}
fn hex(text: []const u8, length: usize) !void {
    if (text.len != length) return error.InvalidIdentity;
    var nonzero = false;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidIdentity;
        nonzero = nonzero or byte != '0';
    }
    if (!nonzero) return error.InvalidIdentity;
}
fn uuid(text: []const u8) !void {
    if (text.len != 36) return error.InvalidIdentity;
    var compact: [32]u8 = undefined;
    var n: usize = 0;
    for (text, 0..) |byte, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (byte != '-') return error.InvalidIdentity;
        } else {
            compact[n] = byte;
            n += 1;
        }
    }
    try hex(&compact, 32);
}
