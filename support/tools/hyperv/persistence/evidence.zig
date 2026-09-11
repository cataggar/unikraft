const std = @import("std");
const contract = @import("contract.zig");
const local = @import("local.zig");

pub const Identity = struct {
    controller: local.Id,
    path: u8,
    target: u8,
    lun: u8,
    sectors: u64,
    vpd_length: u8,
    vpd_code_set: u8,
    vpd_type: u8,
    vpd_association: u8,
    vpd: [128]u8,
};
pub const Evidence = struct {
    boot: u8,
    identity: Identity,
    bytes: u32,
    sha256: local.Hash,
    writes: u8,
    flushes: u8,
};

pub fn boot2Suffix(full: []const u8, first: Evidence) ![]const u8 {
    if (first.boot != 1 or first.bytes == 0 or full.len > contract.serial_limit or full.len < first.bytes or
        !std.mem.eql(u8, &local.hash(full[0..first.bytes]), &first.sha256)) return error.SerialPrefixChanged;
    if (full.len == first.bytes) return error.EvidenceIncomplete;
    return full[first.bytes..];
}

pub fn parse(bytes: []const u8, boot: u8, input: contract.Contract, previous: ?Evidence) !Evidence {
    if (boot != 1 and boot != 2) return error.InvalidBoot;
    if ((boot == 1) != (previous == null)) return error.InvalidBoot;
    if (bytes.len == 0 or bytes.len > contract.serial_limit) return error.InvalidSerialLength;
    const last_newline = std.mem.lastIndexOfScalar(u8, bytes, '\n') orelse return error.EvidenceIncomplete;
    // ukprint emits its reset (including NUL) after the message's newline.
    if (!resetTail(bytes[last_newline + 1 ..])) return error.EvidenceIncomplete;
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidSerial;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var expected: u8 = 0;
    var rejected: u8 = 0;
    var identity: ?Identity = null;
    var cleaned: [8192]u8 = undefined;
    while (lines.next()) |raw| {
        const line = try normalize(raw, &cleaned);
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "UK_HYPERV_ACCEPTANCE_FAIL:") or
            std.mem.startsWith(u8, line, "UK_HYPERV_PERSISTENCE_UNAVAILABLE:") or
            std.mem.indexOf(u8, line, "Unikraft Crash") != null or
            std.mem.indexOf(u8, line, "Assertion failure") != null or
            std.mem.indexOf(u8, line, "Exception Type") != null) return error.GuestFailure;
        if (std.mem.startsWith(u8, line, "HYPERV_PERSISTENCE CANDIDATE_REJECT PASS reason=boot-signature id=")) {
            if (expected != 1 or rejected == 16) return error.InvalidCandidateOrder;
            _ = try decimal(u32, line["HYPERV_PERSISTENCE CANDIDATE_REJECT PASS reason=boot-signature id=".len..]);
            rejected += 1;
            continue;
        }
        var marker: ?u8 = null;
        if (std.mem.startsWith(u8, line, "HYPERV_PERSISTENCE START ")) {
            marker = 0;
            const parts = try split(7, line, ' ');
            if (!std.mem.eql(u8, parts[2], "PASS") or !std.mem.eql(u8, try after(parts[3], "run="), &input.run_id))
                return error.WrongIdentity;
            const address = try split(3, try after(parts[4], "address="), ':');
            if (try decimal(u8, address[0]) != 0 or try decimal(u8, address[1]) != 0 or
                try decimal(u8, address[2]) != input.lun or
                try decimal(u64, try after(parts[5], "sectors=")) != input.sectors or
                try decimal(u16, try after(parts[6], "sector_size=")) != 512) return error.WrongGeometry;
        } else if (std.mem.startsWith(u8, line, "HYPERV_PERSISTENCE SELECT ")) {
            marker = 1;
            const parts = try split(6, line, ' ');
            if (!std.mem.eql(u8, parts[2], "PASS")) return error.GuestFailure;
            _ = try decimal(u32, try after(parts[3], "id="));
            _ = try decimal(u32, try after(parts[4], "controller="));
            if (try decimal(u8, try after(parts[5], "state=")) != @as(u8, if (boot == 1) 0 else 2)) return error.WrongBootState;
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_PERSISTENCE_IDENTITY:")) {
            marker = 2;
            const parts = try split(16, line, ':');
            if (!std.mem.eql(u8, parts[1], "1") or !std.mem.eql(u8, parts[2], "2") or
                !std.mem.eql(u8, parts[3], &input.run_id) or !std.mem.eql(u8, parts[4], &input.disk_id) or parts[5].len != 32)
                return error.WrongIdentity;
            try local.hex(parts[5], true);
            var found: Identity = .{
                .controller = parts[5][0..32].*,
                .path = try decimal(u8, parts[6]),
                .target = try decimal(u8, parts[7]),
                .lun = try decimal(u8, parts[8]),
                .sectors = try decimal(u64, parts[9]),
                .vpd_length = try decimal(u8, parts[11]),
                .vpd_code_set = try decimal(u8, parts[12]),
                .vpd_type = try decimal(u8, parts[13]),
                .vpd_association = try decimal(u8, parts[14]),
                .vpd = [_]u8{'0'} ** 128,
            };
            if (found.lun != input.lun or found.sectors != input.sectors or try decimal(u16, parts[10]) != 512 or
                found.vpd_length == 0 or found.vpd_length > 64 or parts[15].len != @as(usize, found.vpd_length) * 2)
                return error.WrongIdentity;
            try local.hex(parts[15], true);
            @memcpy(found.vpd[0..parts[15].len], parts[15]);
            if (previous) |first| if (!std.meta.eql(found, first.identity)) return error.IdentityDrift;
            identity = found;
        } else if (std.mem.startsWith(u8, line, "HYPERV_PERSISTENCE BOOT")) {
            marker = 3;
            const parts = try split(4, line, ' ');
            if (!std.mem.eql(u8, parts[1], if (boot == 1) "BOOT1_WRITE" else "BOOT2_READ") or
                !std.mem.eql(u8, parts[2], "PASS") or !std.mem.eql(u8, try after(parts[3], "run="), &input.run_id))
                return error.WrongBootAction;
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_PERSISTENCE_IO:")) {
            marker = 4;
            const parts = try split(7, line, ':');
            if (!std.mem.eql(u8, parts[1], "1") or try decimal(u8, parts[2]) != boot or
                !std.mem.eql(u8, parts[3], &input.run_id) or try decimal(u8, parts[4]) != @as(u8, if (boot == 1) 5 else 0) or
                try decimal(u8, parts[5]) != @as(u8, if (boot == 1) 3 else 0) or !std.mem.eql(u8, parts[6], "receipt-verified"))
                return error.WrongIoLedger;
        } else if (std.mem.startsWith(u8, line, "UK_HYPERV_PERSISTENCE_BOOT")) {
            marker = 5;
            const parts = try split(2, line, ':');
            if (!std.mem.eql(u8, parts[0], if (boot == 1) "UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE" else "UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE") or
                !std.mem.eql(u8, parts[1], &input.run_id)) return error.WrongCompletion;
        } else if (std.mem.startsWith(u8, line, "HYPERV_PERSISTENCE FINAL ")) {
            marker = 6;
            if (!std.mem.eql(u8, line, "HYPERV_PERSISTENCE FINAL PASS rc=0")) return error.GuestFailure;
        } else if (terminalBody(line)) |body| {
            marker = 7;
            if (!std.mem.eql(u8, body, "main returned 0")) return error.GuestFailure;
        } else if (std.mem.startsWith(u8, line, "HYPERV_PERSISTENCE ") or std.mem.startsWith(u8, line, "UK_HYPERV_PERSISTENCE_")) {
            return error.UnknownProtocolMarker;
        }
        if (marker) |current| {
            if (current != expected) return error.InvalidEvidenceOrder;
            expected += 1;
        }
    }
    if (expected != 8 or identity == null) return error.EvidenceIncomplete;
    return .{ .boot = boot, .identity = identity.?, .bytes = @intCast(bytes.len), .sha256 = local.hash(bytes), .writes = if (boot == 1) 5 else 0, .flushes = if (boot == 1) 3 else 0 };
}

fn resetTail(raw: []const u8) bool {
    var rest = raw;
    while (rest.len != 0) {
        if (rest[0] == 0) {
            rest = rest[1..];
        } else if (std.mem.startsWith(u8, rest, "\x1b[0m")) {
            rest = rest[4..];
        } else return false;
    }
    return true;
}

// Only the boot.c terminal message has a kernel envelope. Protocol markers
// remain bare. Order/widths follow ukprint/console.c and snprintf.c.
fn terminalBody(line: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, line, "main returned ")) return line;
    if (line.len > 256) return null;
    var rest = line;
    if (std.mem.startsWith(u8, rest, "[")) {
        const end = std.mem.indexOf(u8, rest, "] ") orelse return null;
        const time = rest[1..end];
        const dot = std.mem.indexOfScalar(u8, time, '.') orelse return null;
        if (!paddedDecimal(time[0..dot], 5, 20) or time.len - dot - 1 != 6) return null;
        for (time[dot + 1 ..]) |byte| if (!std.ascii.isDigit(byte)) return null;
        rest = rest[end + 2 ..];
    }
    if (!std.mem.startsWith(u8, rest, "Info: ")) return null;
    rest = rest["Info: ".len..];
    if (std.mem.startsWith(u8, rest, "<<n/a>> ")) {
        rest = rest["<<n/a>> ".len..];
    } else if (std.mem.startsWith(u8, rest, "<")) {
        const end = std.mem.indexOf(u8, rest, "> ") orelse return null;
        const thread = rest[1..end];
        if (!std.mem.eql(u8, thread, "main") and !std.mem.eql(u8, thread, "init") and !kernelPointer(thread))
            return null;
        rest = rest[end + 2 ..];
    }
    if (std.mem.startsWith(u8, rest, "{r:")) {
        const end = std.mem.indexOf(u8, rest, "} ") orelse return null;
        const caller = rest["{r:".len..end];
        const comma = std.mem.indexOf(u8, caller, ",f:") orelse return null;
        if (!kernelPointer(caller[0..comma]) or !kernelPointer(caller[comma + 3 ..])) return null;
        rest = rest[end + 2 ..];
    }
    // boot.c is compiled as libukboot, whose ID is in uklibid's name map.
    if (!std.mem.startsWith(u8, rest, "[libukboot] ")) return null;
    rest = rest["[libukboot] ".len..];
    if (std.mem.startsWith(u8, rest, "<boot.c @ ")) {
        const end = std.mem.indexOf(u8, rest, "> ") orelse return null;
        const number = rest["<boot.c @ ".len..end];
        if (!paddedDecimal(number, 4, 5) or std.mem.eql(u8, std.mem.trimStart(u8, number, " "), "0"))
            return null;
        rest = rest[end + 2 ..];
    }
    return if (std.mem.startsWith(u8, rest, "main returned ")) rest else null;
}

fn paddedDecimal(text: []const u8, width: usize, maximum: usize) bool {
    const digits = std.mem.trimStart(u8, text, " ");
    if (digits.len == 0 or digits.len > maximum or text.len != @max(width, digits.len) or
        (digits.len > 1 and digits[0] == '0')) return false;
    for (digits) |byte| if (!std.ascii.isDigit(byte)) return false;
    _ = std.fmt.parseInt(u64, digits, 10) catch return false;
    return true;
}

fn kernelPointer(text: []const u8) bool {
    if (std.mem.eql(u8, text, "0")) return true;
    if (text.len < 3 or text.len > 18 or !std.mem.startsWith(u8, text, "0x") or text[2] == '0') return false;
    for (text[2..]) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}

fn normalize(raw: []const u8, output: []u8) ![]const u8 {
    var used: usize = 0;
    var at: usize = 0;
    while (at < raw.len) {
        const byte = raw[at];
        at += 1;
        if (byte == 0) continue;
        if (byte == 0x1b) {
            if (at >= raw.len or raw[at] != '[') return error.InvalidSerial;
            at += 1;
            while (at < raw.len and raw[at] >= 0x30 and raw[at] <= 0x3f) : (at += 1) {}
            while (at < raw.len and raw[at] >= 0x20 and raw[at] <= 0x2f) : (at += 1) {}
            if (at >= raw.len or raw[at] < 0x40 or raw[at] > 0x7e) return error.InvalidSerial;
            at += 1;
            continue;
        }
        if (used == output.len) return error.SerialLineTooLong;
        output[used] = byte;
        used += 1;
    }
    return std.mem.trim(u8, output[0..used], " \t\r");
}
fn split(comptime count: usize, bytes: []const u8, separator: u8) ![count][]const u8 {
    var fields = std.mem.splitScalar(u8, bytes, separator);
    var result: [count][]const u8 = undefined;
    for (&result) |*field| field.* = fields.next() orelse return error.InvalidSerial;
    if (fields.next() != null) return error.InvalidSerial;
    return result;
}
fn after(bytes: []const u8, prefix: []const u8) ![]const u8 {
    if (!std.mem.startsWith(u8, bytes, prefix)) return error.InvalidSerial;
    return bytes[prefix.len..];
}
fn decimal(comptime T: type, text: []const u8) !T {
    if (text.len == 0 or text.len > 20 or (text.len > 1 and text[0] == '0')) return error.InvalidDecimal;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidDecimal;
    return std.fmt.parseInt(T, text, 10);
}
