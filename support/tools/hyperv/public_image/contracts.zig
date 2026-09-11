const std = @import("std");
pub const core = @import("hyperv_core");
pub const boot = @import("local_boot");
pub const mib = 1024 * 1024;
pub const esp_bytes = 64 * mib;
pub const raw_bytes = 66 * mib;
pub const vhd_bytes = raw_bytes + 512;
pub const max_efi = 64 * mib;
pub const max_tool = 64 * mib;
pub const max_config = mib;
pub const max_record = 64 * 1024;
pub const package_timeout_ms = 120_000;
pub const miz_revision = "2db68ca0c3ab12155012a823c3fb8d7aba1cb544";
pub const controller_revision = 4;
pub const platform_marker = "UK_HYPERV_PLATFORM_READY";
pub const legacy_marker = "Using legacy xAPIC MMIO";
pub const modes = [_][]const u8{ "raw-x2apic", "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic" };
pub const Hash = [32]u8;

pub fn hash(bytes: []const u8) Hash {
    var result: Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
pub fn hex(a: std.mem.Allocator, value: Hash) ![]const u8 {
    return a.dupe(u8, &std.fmt.bytesToHex(value, .lower));
}
pub fn sha(text: []const u8) !Hash {
    if (text.len != 64) return error.InvalidHash;
    for (text) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidHash;
    return core.contracts.parseSha256(text);
}
pub const encode = boot.config.encode;

pub fn read(comptime T: type, a: std.mem.Allocator, bytes: []const u8) !T {
    var document = try core.contracts.Document.parse(a, bytes, .{ .bytes = max_record });
    defer document.deinit();
    try document.requireCanonical(a, bytes);
    const value = try std.json.parseFromSliceLeaky(T, a, bytes, .{ .ignore_unknown_fields = false, .allocate = .alloc_always, .parse_numbers = false });
    const encoded = try encode(a, value);
    defer a.free(encoded);
    if (!std.mem.eql(u8, encoded, bytes)) return error.IncompleteRecord;
    return value;
}

pub const File = struct {
    path: []const u8,
    size: u64,
    sha256: []const u8,
    pub fn validate(self: File, maximum: u64) !void {
        try core.private_files.absoluteFilePath(self.path);
        if (self.size == 0 or self.size > maximum) return error.InvalidFileSize;
        _ = try sha(self.sha256);
    }
};

pub const Input = struct {
    efi: []const u8,
    qemu: []const u8,
    ovmf_code: []const u8,
    ovmf_vars: []const u8,
    state_dir: []const u8,
    solved_config: ?[]const u8 = null,
    expect: []const u8 = platform_marker,
    timeout_ms: u32 = 30_000,
    pub fn validate(self: Input) !void {
        for ([_][]const u8{ self.efi, self.qemu, self.ovmf_code, self.ovmf_vars, self.state_dir }) |path|
            try core.private_files.absoluteFilePath(path);
        if (self.solved_config) |path| try core.private_files.absoluteFilePath(path);
        try boot.config.marker(self.expect);
        if (!std.mem.eql(u8, self.expect, std.mem.trim(u8, self.expect, " "))) return error.InvalidMarker;
        if (self.timeout_ms == 0 or self.timeout_ms > 120_000) return error.InvalidTimeout;
    }
};
pub const Inputs = struct { efi: File, qemu: File, code: File, vars: File, producer: File, solved_config: ?File };
pub const Phase = enum { preparing, prepared, failed };
pub const Boot = struct {
    index: u8,
    request_sha256: []const u8,
    report_sha256: []const u8,
    serial_sha256: []const u8,
    serial_bytes: u64,
};
pub const State = struct {
    schema: []const u8 = "unikraft.hyperv.native-public-preparation",
    schema_version: u8 = 1,
    controller_revision: u8 = controller_revision,
    phase: Phase = .preparing,
    input: Input,
    inputs: Inputs,
    acceptance: std.json.Value,
    package: ?@import("package.zig").Report = null,
    boots: [4]?Boot = .{ null, null, null, null },
    failures: core.diagnostics.Failures = .{},
    pub fn validate(self: State) !void {
        if (!std.mem.eql(u8, self.schema, "unikraft.hyperv.native-public-preparation") or
            self.schema_version != 1 or self.controller_revision != 4) return error.InvalidState;
        try self.input.validate();
        try self.inputs.efi.validate(max_efi);
        try self.inputs.qemu.validate(max_tool);
        try self.inputs.code.validate(boot.config.max_firmware);
        try self.inputs.vars.validate(boot.config.max_vars);
        try self.inputs.producer.validate(max_tool);
        if (self.inputs.solved_config) |file| try file.validate(max_config);
        if ((self.input.solved_config == null) != (self.inputs.solved_config == null)) return error.InvalidState;
        for ([_][]const u8{ self.input.efi, self.input.qemu, self.input.ovmf_code, self.input.ovmf_vars }, [_][]const u8{ self.inputs.efi.path, self.inputs.qemu.path, self.inputs.code.path, self.inputs.vars.path }) |path, bound|
            if (!std.mem.eql(u8, path, bound)) return error.InvalidState;
        if (self.input.solved_config) |path| if (!std.mem.eql(u8, path, self.inputs.solved_config.?.path)) return error.InvalidState;
        _ = try @import("network.zig").parse(self.acceptance);
    }
};

pub const Source = struct {
    provider: []const u8 = "github-actions",
    repository: []const u8,
    repository_id: u64,
    workflow_ref: []const u8,
    job: []const u8 = "zig-hyperv",
    run_id: u64,
    run_attempt: u64,
    head_sha: []const u8,
    pub fn validate(self: Source) !void {
        if (!std.mem.eql(u8, self.provider, "github-actions") or !std.mem.eql(u8, self.job, "zig-hyperv") or
            self.repository_id == 0 or self.run_id == 0 or self.run_attempt == 0) return error.InvalidSource;
        var components = std.mem.splitScalar(u8, self.repository, '/');
        try name(components.next() orelse return error.InvalidSource);
        try name(components.next() orelse return error.InvalidSource);
        if (components.next() != null or self.workflow_ref.len > 500) return error.InvalidSource;
        if (!std.mem.startsWith(u8, self.workflow_ref, self.repository)) return error.InvalidSource;
        const rest = self.workflow_ref[self.repository.len..];
        const prefix = "/.github/workflows/";
        if (!std.mem.startsWith(u8, rest, prefix)) return error.InvalidSource;
        const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.InvalidSource;
        if (at <= prefix.len) return error.InvalidSource;
        const workflow = rest[prefix.len..at];
        const suffix: usize = if (std.mem.endsWith(u8, workflow, ".yaml")) 5 else if (std.mem.endsWith(u8, workflow, ".yml")) 4 else return error.InvalidSource;
        if (workflow.len <= suffix) return error.InvalidSource;
        for (workflow) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "_.-", byte) == null) return error.InvalidSource;
        const ref = rest[at + 1 ..];
        if (ref.len < 6 or ref.len > 305 or !std.mem.startsWith(u8, ref, "refs/") or std.mem.indexOf(u8, ref, "..") != null) return error.InvalidSource;
        for (ref) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "_./-", byte) == null) return error.InvalidSource;
        if (self.head_sha.len != 40 and self.head_sha.len != 64) return error.InvalidSource;
        for (self.head_sha) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidSource;
    }
};
fn name(value: []const u8) !void {
    if (value.len == 0 or value.len > 100) return error.InvalidSource;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "_.-", byte) == null) return error.InvalidSource;
}
