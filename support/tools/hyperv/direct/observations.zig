// SPDX-License-Identifier: BSD-3-Clause
//! Native read-only Azure observation contracts.
//! These checks neither authorize effects nor parse evidence.
const std = @import("std");
const core = @import("hyperv_core");
const profile = @import("profile.zig");
const direct = profile.contract;
const c = core.contracts;
const sensitive = core.sensitive;
const files = core.private_files;

pub const maximum_capture_bytes = 8 * 1024 * 1024;
pub const maximum_uint: u64 = 9007199254740991;
pub const Role = enum { os, data };
pub const Allocation = enum { allocated, deallocated };
pub const PowerState = enum { running, stopped, deallocated };

/// A completed capture must have successful child status, EOF, no overflow and
/// resolved supervision. Failed/partial stdout is never an observation.
pub const Capture = union(enum) {
    complete: []const u8,
    failed: void,

    fn bytes(self: Capture) ![]const u8 {
        return switch (self) {
            .complete => |source| source,
            .failed => error.CaptureFailed,
        };
    }
};

/// Keep provider exit/timeout/cancellation details in the runtime result. These
/// categories distinguish jq false (normally 1), filter errors (normally 5),
/// malformed input and private capture/recording failures; they are not exits.
pub const FailureClass = enum { refused, filter_error, malformed, capture, local };

pub fn failureClass(err: anyerror) FailureClass {
    return switch (err) {
        error.ObservationRefused, error.UnknownOriginalIdentity => .refused,
        error.InvalidObservationShape,
        error.InvalidUint,
        error.InvalidPowerShape,
        error.InvalidPowerCount,
        error.InvalidPowerCode,
        error.InvalidGrantShape,
        error.InvalidGrantValue,
        error.InvalidSerialWrapper,
        => .filter_error,
        error.MalformedJson,
        error.DuplicateField,
        error.InputTooLarge,
        error.TooDeep,
        error.TooManyItems,
        error.TooManyTokens,
        error.ValueTooLong,
        => .malformed,
        error.CaptureFailed => .capture,
        else => .local,
    };
}

/// Returned strings borrow this document. Copy accepted original UUIDs into
/// controller custody before deinit; never replace them with a later observation.
pub const Document = struct {
    parsed: std.json.Parsed(std.json.Value),
    owner: *sensitive.Allocator,

    pub fn parse(allocator: std.mem.Allocator, capture: Capture) !Document {
        const source = try capture.bytes();
        if (source.len > maximum_capture_bytes) return error.InputTooLarge;
        const owner = try allocator.create(sensitive.Allocator);
        owner.* = .{ .backing = allocator };
        errdefer destroyOwner(owner);
        const a = owner.allocator();
        // c.Document is deliberately stricter: integer tokens only and <=4 MiB.
        // ARM numeric 4.0/4e0 and an 8-MiB diagnostic wrapper need this scanner,
        // not a relaxation of canonical private records or Scope decoding.
        try scan(a, source);
        const parsed = std.json.parseFromSlice(std.json.Value, a, source, .{
            .duplicate_field_behavior = .@"error",
            .allocate = .alloc_always,
            .parse_numbers = false,
            .max_value_len = maximum_capture_bytes,
        }) catch |err| return jsonError(err);
        errdefer parsed.deinit();
        try checkItems(parsed.value);
        return .{ .parsed = parsed, .owner = owner };
    }

    pub fn value(self: Document) std.json.Value {
        return self.parsed.value;
    }

    pub fn deinit(self: Document) void {
        self.parsed.deinit();
        destroyOwner(self.owner);
    }
};

fn destroyOwner(owner: *sensitive.Allocator) void {
    const allocator = owner.backing;
    std.crypto.secureZero(u8, std.mem.asBytes(owner));
    allocator.destroy(owner);
}

fn jsonError(err: anyerror) anyerror {
    return switch (err) {
        error.OutOfMemory,
        error.DuplicateField,
        error.ValueTooLong,
        error.InputTooLarge,
        error.TooDeep,
        error.TooManyItems,
        error.TooManyTokens,
        => err,
        else => error.MalformedJson,
    };
}

fn scan(allocator: std.mem.Allocator, source: []const u8) !void {
    var scanner = std.json.Scanner.initCompleteInput(allocator, source);
    defer scanner.deinit();
    var depth: usize = 0;
    var tokens: usize = 0;
    while (true) {
        const token = scanner.nextAllocMax(allocator, .alloc_always, maximum_capture_bytes) catch |err| return jsonError(err);
        defer switch (token) {
            .allocated_string, .allocated_number => |bytes| allocator.free(bytes),
            else => {},
        };
        tokens += 1;
        if (tokens > 65536) return error.TooManyTokens;
        switch (token) {
            .object_begin, .array_begin => {
                depth += 1;
                if (depth > 32) return error.TooDeep;
            },
            .object_end, .array_end => {
                if (depth == 0) return error.MalformedJson;
                depth -= 1;
            },
            .end_of_document => return,
            else => {},
        }
    }
}

fn checkItems(value: std.json.Value) anyerror!void {
    switch (value) {
        .array => |array| {
            if (array.items.len > 4096) return error.TooManyItems;
            for (array.items) |child| try checkItems(child);
        },
        .object => |object| {
            if (object.count() > 4096) return error.TooManyItems;
            for (object.values()) |child| try checkItems(child);
        },
        else => {},
    }
}

pub const Expectations = struct {
    allocator: std.mem.Allocator,
    scope: direct.Scope,
    group_id: []const u8,
    vm_id: []const u8,
    os_id: []const u8,
    data_id: []const u8,
    nic_id: []const u8,

    /// Borrows the already loaded Scope; no disk/image inspection or authority
    /// discovery occurs here. Identifier spelling is preserved, not normalized.
    pub fn init(allocator: std.mem.Allocator, scope: direct.Scope) !Expectations {
        try scope.validate();
        const group_id = try std.fmt.allocPrint(allocator, "/subscriptions/{s}/resourceGroups/{s}-rg", .{ scope.subscription, scope.prefix });
        errdefer allocator.free(group_id);
        const vm_id = try resourceId(allocator, group_id, "Microsoft.Compute/virtualMachines", scope.prefix, "vm");
        errdefer allocator.free(vm_id);
        const os_id = try resourceId(allocator, group_id, "Microsoft.Compute/disks", scope.prefix, "os");
        errdefer allocator.free(os_id);
        const data_id = try resourceId(allocator, group_id, "Microsoft.Compute/disks", scope.prefix, "data");
        errdefer allocator.free(data_id);
        const nic_id = try resourceId(allocator, group_id, "Microsoft.Network/networkInterfaces", scope.prefix, "nic");
        return .{ .allocator = allocator, .scope = scope, .group_id = group_id, .vm_id = vm_id, .os_id = os_id, .data_id = data_id, .nic_id = nic_id };
    }

    pub fn deinit(self: Expectations) void {
        inline for (.{ "group_id", "vm_id", "os_id", "data_id", "nic_id" }) |name|
            self.allocator.free(@field(self, name));
    }

    pub fn diskId(self: Expectations, role: Role) []const u8 {
        return if (role == .os) self.os_id else self.data_id;
    }

    pub fn artifact(self: Expectations, role: Role) direct.Artifact {
        if (profile.compute) {
            std.debug.assert(role == .os);
            return self.scope.os_vhd;
        }
        return if (role == .os) self.scope.os_vhd else self.scope.seed_vhd;
    }
};

fn resourceId(a: std.mem.Allocator, group_id: []const u8, kind: []const u8, prefix: []const u8, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}/providers/{s}/{s}-{s}", .{ group_id, kind, prefix, suffix });
}

/// JSON number tokens may use decimal/exponent syntax; JSON strings may not.
/// Evaluate the decimal value exactly rather than rounding a fraction to f64.
pub fn uint(value: std.json.Value) !u64 {
    return switch (value) {
        .string => |text| decimalString(text),
        .number_string => |text| numberUint(text),
        .integer => |n| if (n >= 0 and n <= maximum_uint) @intCast(n) else error.InvalidUint,
        .float => |n| if (std.math.isFinite(n) and n >= 0 and n <= maximum_uint and @floor(n) == n) @intFromFloat(n) else error.InvalidUint,
        else => error.InvalidUint,
    };
}

fn decimalString(text: []const u8) !u64 {
    if (text.len == 0 or text.len > 16 or (text.len > 1 and text[0] == '0')) return error.InvalidUint;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidUint;
    const result = std.fmt.parseInt(u64, text, 10) catch return error.InvalidUint;
    return if (result <= maximum_uint) result else error.InvalidUint;
}

fn numberUint(text: []const u8) !u64 {
    if (text.len == 0) return error.InvalidUint;
    const negative = text[0] == '-';
    const start: usize = if (negative) 1 else 0;
    var i = start;
    if (i == text.len or !std.ascii.isDigit(text[i])) return error.InvalidUint;
    const leading_zero = text[i] == '0';
    while (i < text.len and std.ascii.isDigit(text[i])) : (i += 1) {}
    if (leading_zero and i - start != 1) return error.InvalidUint;
    var fraction_digits: i64 = 0;
    if (i < text.len and text[i] == '.') {
        i += 1;
        const fraction_start = i;
        while (i < text.len and std.ascii.isDigit(text[i])) : (i += 1) {}
        if (i == fraction_start) return error.InvalidUint;
        fraction_digits = @intCast(i - fraction_start);
    }
    const mantissa_end = i;
    var exponent: i64 = 0;
    if (i < text.len and (text[i] == 'e' or text[i] == 'E')) {
        i += 1;
        const minus = i < text.len and text[i] == '-';
        if (i < text.len and (text[i] == '+' or text[i] == '-')) i += 1;
        const exponent_start = i;
        while (i < text.len and std.ascii.isDigit(text[i])) : (i += 1)
            exponent = @min(2 * maximum_capture_bytes, exponent * 10 + text[i] - '0');
        if (i == exponent_start) return error.InvalidUint;
        if (minus) exponent = -exponent;
    }
    if (i != text.len) return error.InvalidUint;
    var significant: i64 = 0;
    var trailing_zeroes: i64 = 0;
    for (text[start..mantissa_end]) |byte| {
        if (byte == '.') continue;
        if (significant == 0 and byte == '0') continue;
        significant += 1;
        trailing_zeroes = if (byte == '0') trailing_zeroes + 1 else 0;
    }
    if (significant == 0) return 0; // Numeric -0 is zero; the string "-0" is not uint.
    const digits = significant - trailing_zeroes;
    const zeroes = exponent - fraction_digits + trailing_zeroes;
    if (negative or zeroes < 0 or digits + zeroes > 16) return error.InvalidUint;
    var result: u64 = 0;
    var collected: i64 = 0;
    for (text[start..mantissa_end]) |byte| {
        if (byte == '.' or (collected == 0 and byte == '0')) continue;
        if (collected == digits) break;
        result = result * 10 + byte - '0';
        collected += 1;
    }
    for (0..@intCast(zeroes)) |_| result *= 10;
    return if (result <= maximum_uint) result else error.InvalidUint;
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    return switch (value) {
        .object => |object| object.get(name) orelse .null,
        .null => .null,
        else => error.InvalidObservationShape,
    };
}

fn at(value: std.json.Value, comptime names: []const []const u8) !std.json.Value {
    var current = value;
    inline for (names) |name| current = try field(current, name);
    return current;
}

fn eq(value: std.json.Value, expected: []const u8) bool {
    return value == .string and std.mem.eql(u8, value.string, expected);
}

fn require(ok: bool) !void {
    if (!ok) return error.ObservationRefused;
}

fn nonempty(value: std.json.Value) ![]const u8 {
    try require(value == .string and value.string.len > 0);
    return value.string;
}

fn original(uuid: ?[]const u8) ![]const u8 {
    const known = uuid orelse return error.UnknownOriginalIdentity;
    if (known.len == 0) return error.UnknownOriginalIdentity;
    return known;
}

fn tags(value: std.json.Value, expected: Expectations) !void {
    const observed = try field(value, "tags");
    try require(eq(try field(observed, "uk-direct-run"), expected.scope.attempt_id) and
        eq(try field(observed, "unikraft-run"), expected.scope.prefix) and
        eq(try field(observed, "image-sha256"), expected.scope.os_vhd.sha256) and
        eq(try field(observed, "managed-by"), "unikraft-hyperv"));
}

pub fn owned(value: std.json.Value, expected: Expectations, id: []const u8) !void {
    try require(eq(try field(value, "id"), id));
    try tags(value, expected);
}

pub fn group(value: std.json.Value, expected: Expectations) !void {
    try owned(value, expected, expected.group_id);
}

pub fn freshAbsence(value: std.json.Value) !void {
    try require(value == .bool and !value.bool);
}

pub const InventoryObservation = struct { resources: usize };

pub fn inventory(value: std.json.Value, expected: Expectations) !InventoryObservation {
    try require(value == .array);
    for (value.array.items) |item| {
        const kind = c.string(try field(item, "type")) catch return error.InvalidObservationShape;
        const name = try field(item, "name");
        var allowed = false;
        inline for (.{
            .{ "microsoft.compute/disks", "os" },
            .{ "microsoft.compute/disks", "data" },
            .{ "microsoft.compute/virtualmachines", "vm" },
            .{ "microsoft.network/networkinterfaces", "nic" },
            .{ "microsoft.network/networksecuritygroups", "nsg" },
            .{ "microsoft.network/virtualnetworks", "vnet" },
        }) |entry| {
            if (profile.compute and comptime std.mem.eql(u8, entry[1], "data")) continue;
            if (std.ascii.eqlIgnoreCase(kind, entry[0]) and name == .string and
                matchesParts(name.string, &.{ expected.scope.prefix, "-", entry[1] }, false))
                allowed = true;
        }
        try require(allowed);
        const id = c.string(try field(item, "id")) catch return error.InvalidObservationShape;
        try require(matchesParts(id, &.{ expected.group_id, "/providers/", kind, "/", name.string }, true));
        try tags(item, expected);
    }
    return .{ .resources = value.array.items.len };
}

fn matchesParts(text: []const u8, parts: []const []const u8, fold: bool) bool {
    var offset: usize = 0;
    for (parts) |part| {
        if (part.len > text.len - offset) return false;
        const found = text[offset..][0..part.len];
        if (!(if (fold) std.ascii.eqlIgnoreCase(found, part) else std.mem.eql(u8, found, part))) return false;
        offset += part.len;
    }
    return offset == text.len;
}

pub const UploadObservation = struct { unique_id: []const u8, upload_bytes: u64 };
pub const DiskObservation = struct { unique_id: []const u8, logical_bytes: u64 };
pub const VmObservation = struct { unique_id: []const u8 };

pub fn uploadReady(value: std.json.Value, expected: Expectations, role: Role, original_uuid: ?[]const u8) !UploadObservation {
    try owned(value, expected, expected.diskId(role));
    try require(eq(try field(value, "diskState"), "ReadyToUpload") and
        eq(try at(value, &.{ "creationData", "createOption" }), "Upload"));
    const size = try uint(try at(value, &.{ "creationData", "uploadSizeBytes" }));
    try require(size == expected.artifact(role).size and eq(try at(value, &.{ "sku", "name" }), "StandardSSD_LRS"));
    const sector = try field(value, "logicalSectorSize");
    if (sector != .null) try require(try uint(sector) == 512);
    const uuid = try nonempty(try field(value, "uniqueId"));
    if (original_uuid != null) try require(std.mem.eql(u8, uuid, try original(original_uuid)));
    if (role == .os) {
        try require(eq(try field(value, "osType"), "Linux") and eq(try field(value, "hyperVGeneration"), "V2"));
    } else try require(try field(value, "osType") == .null);
    return .{ .unique_id = uuid, .upload_bytes = size };
}

pub fn afterUpload(value: std.json.Value, expected: Expectations, role: Role, original_uuid: []const u8) !DiskObservation {
    const uuid = try original(original_uuid);
    try owned(value, expected, expected.diskId(role));
    try require(eq(try field(value, "uniqueId"), uuid) and
        eq(try field(value, "diskState"), "Unattached") and try field(value, "managedBy") == .null);
    const logical = try uint(try field(value, "diskSizeBytes"));
    try require(logical == expected.artifact(role).size - 512);
    return .{ .unique_id = uuid, .logical_bytes = logical };
}

pub fn retainedDisk(value: std.json.Value, expected: Expectations, role: Role, allocation: Allocation, original_uuid: []const u8) !DiskObservation {
    const uuid = try original(original_uuid);
    try owned(value, expected, expected.diskId(role));
    try require(eq(try field(value, "uniqueId"), uuid) and eq(try field(value, "managedBy"), expected.vm_id) and
        eq(try field(value, "diskState"), if (allocation == .allocated) "Attached" else "Reserved"));
    const logical = try uint(try field(value, "diskSizeBytes"));
    try require(logical == expected.artifact(role).size - 512);
    return .{ .unique_id = uuid, .logical_bytes = logical };
}

pub fn vm(value: std.json.Value, expected: Expectations, original_uuid: ?[]const u8) !VmObservation {
    try owned(value, expected, expected.vm_id);
    try require(try field(value, "osProfile") == .null and
        eq(try at(value, &.{ "securityProfile", "securityType" }), "Standard") and
        eq(try at(value, &.{ "hardwareProfile", "vmSize" }), expected.scope.vm_size));
    const diagnostics = try at(value, &.{ "diagnosticsProfile", "bootDiagnostics" });
    const enabled = try field(diagnostics, "enabled");
    try require(enabled == .bool and enabled.bool and try field(diagnostics, "storageUri") == .null);
    const storage = try field(value, "storageProfile");
    const os = try field(storage, "osDisk");
    try require(eq(try field(storage, "diskControllerType"), "SCSI") and
        eq(try field(os, "createOption"), "Attach") and eq(try field(os, "caching"), "ReadOnly") and
        eq(try field(os, "deleteOption"), "Detach") and eq(try at(os, &.{ "managedDisk", "id" }), expected.os_id));
    if (profile.compute) {
        const data = try field(storage, "dataDisks");
        try require(data == .array and data.array.items.len == 0);
    } else {
        const data = try singleton(try field(storage, "dataDisks"));
        try require(try uint(try field(data, "lun")) == 7 and eq(try field(data, "createOption"), "Attach") and
            eq(try field(data, "caching"), "None") and eq(try field(data, "deleteOption"), "Detach") and
            eq(try at(data, &.{ "managedDisk", "id" }), expected.data_id));
    }
    const nic = try singleton(try at(value, &.{ "networkProfile", "networkInterfaces" }));
    try require(eq(try field(nic, "id"), expected.nic_id));
    const uuid = try nonempty(try field(value, "vmId"));
    if (original_uuid != null) try require(std.mem.eql(u8, uuid, try original(original_uuid)));
    return .{ .unique_id = uuid };
}

fn singleton(value: std.json.Value) !std.json.Value {
    // jq length(null)==0; an object of length one cannot be indexed with [0].
    if (value == .object and value.object.count() == 1) return error.InvalidObservationShape;
    try require(value == .array and value.array.items.len == 1);
    return value.array.items[0];
}

pub fn rawPower(value: std.json.Value) ![]const u8 {
    if (value != .object) return error.InvalidPowerShape;
    const nested = value.object.contains("instanceView");
    const direct_statuses = value.object.contains("statuses");
    if (nested == direct_statuses) return error.InvalidPowerShape;
    const statuses = if (nested) try at(value, &.{ "instanceView", "statuses" }) else try field(value, "statuses");
    // ARM status collections must be arrays. Refuse object-shaped collections
    // explicitly instead of jq map()'s implicit object-value iteration.
    if (statuses != .array) return error.InvalidPowerShape;
    var found: ?[]const u8 = null;
    for (statuses.array.items) |status| {
        const code_value = try field(status, "code");
        const code = c.string(code_value) catch return error.InvalidPowerCode;
        if (std.mem.startsWith(u8, code, "PowerState/")) {
            if (found != null) return error.InvalidPowerCount;
            found = code;
        }
    }
    return found orelse error.InvalidPowerCount;
}

pub fn power(value: std.json.Value, allocation: Allocation) !PowerState {
    const code = try rawPower(value);
    if (allocation == .allocated) {
        if (std.mem.eql(u8, code, "PowerState/running")) return .running;
        if (std.mem.eql(u8, code, "PowerState/stopped")) return .stopped;
    } else if (std.mem.eql(u8, code, "PowerState/deallocated")) return .deallocated;
    return error.ObservationRefused;
}

/// Unknown originals deliberately fail. The controller may skip an unknown
/// identity read as the shell did, but cannot turn that into deletion authority.
pub fn cleanupDisk(value: std.json.Value, expected: Expectations, role: Role, original_uuid: ?[]const u8) !void {
    const uuid = try original(original_uuid);
    try owned(value, expected, expected.diskId(role));
    const managed = try field(value, "managedBy");
    try require(eq(try field(value, "uniqueId"), uuid) and (managed == .null or eq(managed, expected.vm_id)));
}

pub fn cleanupVm(value: std.json.Value, expected: Expectations, original_uuid: ?[]const u8) !void {
    const uuid = try original(original_uuid);
    try owned(value, expected, expected.vm_id);
    try require(eq(try field(value, "vmId"), uuid));
}

/// Revocation is narrower than retained/group cleanup: ownership and original
/// UUID only, even while Azure reports an upload-related managedBy/state.
pub fn cleanupRevoke(value: std.json.Value, expected: Expectations, role: Role, original_uuid: ?[]const u8) !void {
    const uuid = try original(original_uuid);
    try owned(value, expected, expected.diskId(role));
    try require(eq(try field(value, "uniqueId"), uuid));
}

pub const Grant = struct {
    document: c.SensitiveDocument,
    endpoint_length: usize,

    pub fn parse(allocator: std.mem.Allocator, capture: Capture) !Grant {
        const source = try capture.bytes();
        // The old native `json` check precedes jq: retain its grant limits and
        // duplicate-key rejection, rather than using the larger ARM limits.
        const document = c.SensitiveDocument.parse(allocator, source, .{ .bytes = 65536 }) catch |err| return jsonError(err);
        errdefer document.deinit();
        const value = document.value();
        if (value != .object or value.object.count() != 1) return error.InvalidGrantShape;
        const key = value.object.keys()[0];
        if (!std.mem.eql(u8, key, "accessSAS") and !std.mem.eql(u8, key, "accessSas")) return error.InvalidGrantShape;
        _ = try c.exactFields(value, &.{key});
        const text = c.string(value.object.values()[0]) catch return error.InvalidGrantValue;
        return .{ .document = document, .endpoint_length = try grantUrl(text) };
    }

    pub fn deinit(self: Grant) void {
        self.document.deinit();
    }

    pub fn endpoint(self: Grant) []const u8 {
        return self.url()[0..self.endpoint_length];
    }

    fn url(self: Grant) []const u8 {
        return self.document.value().object.values()[0].string;
    }

    pub fn format(_: Grant, writer: *std.Io.Writer) !void {
        try writer.writeAll("AzureGrant(redacted)");
    }

    /// No public query accessor: hand SAS directly to the owner-private file
    /// helper, not a writer/argv/environment. Any failure still requires the
    /// caller's normal secret cleanup; partial publication is not success.
    pub fn writePrivateFiles(self: Grant, allocator: std.mem.Allocator, io: std.Io, locked: *files.Locked, artifact: direct.Artifact) !void {
        const request = .{
            .schema = "unikraft.hyperv.managed-disk-page-worker",
            .schema_version = @as(u8, 1),
            .endpoint = self.endpoint(),
            .path = artifact.path,
            .size = artifact.size,
            .sha256 = artifact.sha256,
        };
        var writer = std.Io.Writer.Allocating.init(allocator);
        defer writer.deinit();
        try std.json.Stringify.value(request, .{}, &writer.writer);
        try writer.writer.writeByte('\n');
        const sas_result = try locked.createImmutable(io, "sas.txt", self.url()[self.endpoint_length + 1 ..]);
        try requireHandoffCommit(sas_result);
        const request_result = try locked.createImmutable(io, "request.json", writer.written());
        try requireHandoffCommit(request_result);
    }
};

fn requireHandoffCommit(result: files.CommitResult) !void {
    if (result.status != .durable or result.failures.primary != null or
        result.failures.recording != null or result.failures.cleanup != null)
        return error.PrivateHandoffNotDurable;
}

test "grant handoff rejects nondurable records and durable records with unresolved cleanup" {
    const t = std.testing;
    for ([_]files.CommitStatus{ .not_committed, .publication_unknown, .visible_not_durable }) |status|
        try t.expectError(error.PrivateHandoffNotDurable, requireHandoffCommit(.{ .status = status }));
    try requireHandoffCommit(.{ .status = .durable });
    inline for (.{ "primary", "recording", "cleanup" }) |lane| {
        var result: files.CommitResult = .{ .status = .durable };
        @field(result.failures, lane) = .{ .stage = .state_record, .category = .local_io };
        try t.expectError(error.PrivateHandoffNotDurable, requireHandoffCommit(result));
    }
}

fn grantUrl(url: []const u8) !usize {
    if (!std.mem.startsWith(u8, url, "https://")) return error.InvalidGrantValue;
    const slash = std.mem.indexOfScalarPos(u8, url, 8, '/') orelse return error.InvalidGrantValue;
    const authority = url[8..slash];
    const colon = std.mem.indexOfScalar(u8, authority, ':');
    const host = if (colon) |i| authority[0..i] else authority;
    if (colon) |i| {
        const port = authority[i + 1 ..];
        if (!std.mem.eql(u8, port, "443") and !std.mem.eql(u8, port, "8443")) return error.InvalidGrantValue;
    }
    var prefix: ?[]const u8 = null;
    for ([_][]const u8{ ".blob.core.windows.net", ".blob.storage.azure.net" }) |suffix| {
        if (std.mem.endsWith(u8, host, suffix)) prefix = host[0 .. host.len - suffix.len];
    }
    const account = prefix orelse return error.InvalidGrantValue;
    if (account.len < 2 or (!std.ascii.isLower(account[0]) and !std.ascii.isDigit(account[0]))) return error.InvalidGrantValue;
    for (account) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '.' and byte != '-') return error.InvalidGrantValue;
    const question = std.mem.indexOfScalarPos(u8, url, slash + 1, '?') orelse return error.InvalidGrantValue;
    if (question == slash + 1 or question + 1 == url.len) return error.InvalidGrantValue;
    for ([_][]const u8{ url[slash + 1 .. question], url[question + 1 ..] }) |part| {
        var iterator = (std.unicode.Utf8View.init(part) catch return error.InvalidGrantValue).iterator();
        while (iterator.nextCodepoint()) |point| {
            if (point == '?' or point == '#' or unicodeSpace(point)) return error.InvalidGrantValue;
        }
    }
    return question;
}

fn unicodeSpace(point: u21) bool {
    return switch (point) {
        0x09...0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

pub const DiagnosticPurpose = enum { primary, failure_only };

pub const Diagnostics = struct {
    document: Document,
    purpose: DiagnosticPurpose,

    pub fn decode(allocator: std.mem.Allocator, capture: Capture, purpose: DiagnosticPurpose) !Diagnostics {
        const document = try Document.parse(allocator, capture);
        errdefer document.deinit();
        if (document.value() != .string) return error.InvalidSerialWrapper;
        return .{ .document = document, .purpose = purpose };
    }

    pub fn deinit(self: Diagnostics) void {
        self.document.deinit();
    }

    /// Decoded NUL/ANSI/CRLF are preserved byte-for-byte, including empty input.
    /// Empty primary bytes go to direct.serialFirst/Second (EvidenceIncomplete).
    pub fn evidenceBytes(self: Diagnostics) ![]const u8 {
        if (self.purpose != .primary) return error.FailureOnlyDiagnostics;
        return self.privateBytes();
    }

    /// For private diagnostic recording only; never acceptance or public logs.
    pub fn privateBytes(self: Diagnostics) []const u8 {
        return self.document.value().string;
    }

    pub fn format(_: Diagnostics, writer: *std.Io.Writer) !void {
        try writer.writeAll("AzureDiagnostics(redacted)");
    }
};
