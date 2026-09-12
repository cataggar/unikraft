const std = @import("std");
const core = @import("hyperv_core");

pub const max_serial = 4 * 1024 * 1024;
pub const max_input = 256 * 1024 * 1024;
pub const max_firmware = 16 * 1024 * 1024;
pub const max_vars = max_serial;
pub const max_qemu = 256 * 1024 * 1024;
pub const max_record = 64 * 1024;
pub const max_markers = 32;
pub const cleanup_ms = 2000;
pub const cpu_features = "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies";
pub const log_name = "hyperv-efi-boot.log";

pub const Config = struct {
    image: ?[]const u8 = null,
    raw_disk: ?[]const u8 = null,
    fixed_vhd: ?[]const u8 = null,
    ovmf_code: []const u8,
    ovmf_vars: []const u8,
    qemu: []const u8,
    work_dir: []const u8,
    expect: []const u8,
    expect_main_return: i32 = 0,
    required: []const []const u8 = &.{},
    forbidden: []const []const u8 = &.{},
    cpus: u8 = 1,
    disable_x2apic: bool = false,
    timeout_ms: u32 = 30_000,

    pub fn validate(self: Config) !void {
        if (@as(u8, @intFromBool(self.image != null)) + @as(u8, @intFromBool(self.raw_disk != null)) +
            @as(u8, @intFromBool(self.fixed_vhd != null)) != 1) return error.InvalidSource;
        for ([_][]const u8{ self.source(), self.ovmf_code, self.ovmf_vars, self.qemu, self.work_dir }) |path|
            try core.private_files.absoluteFilePath(path);
        if (self.cpus < 1 or self.cpus > 8 or (self.disable_x2apic and self.cpus != 1)) return error.InvalidCpuCount;
        if (self.timeout_ms == 0 or self.timeout_ms > 120_000) return error.InvalidTimeout;
        try marker(self.expect);
        if (self.required.len > max_markers or self.forbidden.len > max_markers) return error.TooManyMarkers;
        for (self.required, 0..) |value, i| {
            try marker(value);
            for (self.required[0..i]) |previous| if (std.mem.eql(u8, previous, value)) return error.DuplicateMarker;
            for (self.forbidden) |forbidden| if (std.mem.indexOf(u8, value, forbidden) != null) return error.ConflictingMarker;
        }
        for (self.forbidden, 0..) |value, i| {
            try marker(value);
            if (std.mem.indexOf(u8, self.expect, value) != null) return error.ConflictingMarker;
            for (self.forbidden[0..i]) |previous| if (std.mem.eql(u8, previous, value)) return error.DuplicateMarker;
        }
    }

    pub fn source(self: Config) []const u8 {
        return self.image orelse self.raw_disk orelse self.fixed_vhd orelse "";
    }

    pub fn paths(self: Config) [4][]const u8 {
        return .{ self.source(), self.ovmf_code, self.ovmf_vars, self.qemu };
    }
};

pub fn marker(value: []const u8) !void {
    if (value.len == 0 or value.len > 512) return error.InvalidMarker;
    for (value) |byte| if (byte < 0x20 or byte > 0x7e) return error.InvalidMarker;
    if (std.mem.trim(u8, value, " ").len == 0) return error.InvalidMarker;
}

pub fn integer(comptime T: type, value: []const u8) !T {
    if (value.len == 0 or value.len > 11) return error.InvalidNumber;
    const digits = if (value[0] == '-') value[1..] else value;
    if (digits.len == 0 or (digits.len > 1 and digits[0] == '0') or std.mem.eql(u8, value, "-0")) return error.InvalidNumber;
    for (digits) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidNumber;
    return std.fmt.parseInt(T, value, 10) catch error.InvalidNumber;
}

/// Decimal seconds, exact millisecond precision; NaN/infinity/exponents refuse.
pub fn timeout(value: []const u8) !u32 {
    var fields = std.mem.splitScalar(u8, value, '.');
    const seconds = try integer(u32, fields.next().?);
    if (seconds > 120) return error.InvalidTimeout;
    var milliseconds = seconds * 1000;
    if (fields.next()) |fraction| {
        if (fraction.len == 0 or fraction.len > 3) return error.InvalidTimeout;
        var number: u32 = 0;
        for (fraction) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidTimeout;
            number = number * 10 + byte - '0';
        }
        milliseconds += number * @as(u32, switch (fraction.len) {
            1 => 100,
            2 => 10,
            else => 1,
        });
    }
    if (fields.next() != null or milliseconds == 0 or milliseconds > 120_000) return error.InvalidTimeout;
    return milliseconds;
}

/// Borrows argument strings; the two marker slices use the supplied allocator.
pub fn parse(a: std.mem.Allocator, args: []const []const u8) !Config {
    if (args.len > 150) return error.TooManyArguments;
    var total: usize = 0;
    for (args) |arg| {
        if (arg.len > 4095 or std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidArgument;
        total += arg.len;
    }
    if (total > max_record) return error.TooManyArguments;
    var result: Config = .{ .ovmf_code = "", .ovmf_vars = "", .qemu = "", .work_dir = "", .expect = "" };
    var required: std.ArrayList([]const u8) = .empty;
    defer required.deinit(a);
    var forbidden: std.ArrayList([]const u8) = .empty;
    defer forbidden.deinit(a);
    var seen: u16 = 0;
    var i: usize = 0;
    const names = [_][]const u8{ "--image", "--raw-disk", "--ovmf-code", "--ovmf-vars", "--qemu", "--work-dir", "--expect", "--expect-main-return", "--cpus", "--timeout", "--disable-x2apic", "--require-marker", "--forbid-marker", "--fixed-vhd" };
    while (i < args.len) {
        const selected = for (names, 0..) |name, index| {
            if (std.mem.eql(u8, args[i], name)) break index;
        } else return error.UnknownArgument;
        i += 1;
        if (selected < 11 or selected == 13) {
            const bit = @as(u16, 1) << @intCast(selected);
            if (seen & bit != 0) return error.DuplicateArgument;
            seen |= bit;
        }
        if (selected == 10) {
            result.disable_x2apic = true;
            continue;
        }
        if (i == args.len) return error.MissingArgument;
        const value = args[i];
        i += 1;
        switch (selected) {
            0 => result.image = value,
            1 => result.raw_disk = value,
            2 => result.ovmf_code = value,
            3 => result.ovmf_vars = value,
            4 => result.qemu = value,
            5 => result.work_dir = value,
            6 => result.expect = value,
            7 => result.expect_main_return = try integer(i32, value),
            8 => result.cpus = try integer(u8, value),
            9 => result.timeout_ms = try timeout(value),
            13 => result.fixed_vhd = value,
            11 => {
                if (required.items.len == max_markers) return error.TooManyMarkers;
                try required.append(a, value);
            },
            12 => {
                if (forbidden.items.len == max_markers) return error.TooManyMarkers;
                try forbidden.append(a, value);
            },
            else => unreachable,
        }
    }
    result.required = required.items;
    result.forbidden = forbidden.items;
    try result.validate();
    result.required = try required.toOwnedSlice(a);
    errdefer a.free(result.required);
    result.forbidden = try forbidden.toOwnedSlice(a);
    return result;
}

pub fn encode(a: std.mem.Allocator, value: anytype) ![]u8 {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(raw);
    var document = try core.contracts.Document.parse(a, raw, .{ .bytes = max_record });
    defer document.deinit();
    return document.canonicalAlloc(a);
}
