const std = @import("std");
const c = @import("config.zig");

pub const milestones = [_][]const u8{ "Hyper-V Hv#1 hypercall page enabled", "Hyper-V SynIC:", "Powered by", "Calling main(" };

pub fn validate(a: std.mem.Allocator, raw: []const u8, config: c.Config) !void {
    try config.validate();
    const text = try normalize(a, raw);
    defer a.free(text);
    for ([_][]const u8{ "Unikraft Crash", "Assertion failure", "Exception Type" }) |failure|
        if (std.mem.indexOf(u8, text, failure) != null) return error.GuestCrash;
    for (config.forbidden) |forbidden|
        if (std.mem.indexOf(u8, text, forbidden) != null) return error.ForbiddenMarker;
    var position: usize = 0;
    for (milestones, 0..) |milestone, i| {
        const found = std.mem.indexOf(u8, text, milestone) orelse return error.MissingMilestone;
        if (i != 0 and found <= position) return error.ReorderedMilestone;
        position = found;
    }
    const expected = std.mem.indexOf(u8, text, config.expect) orelse return error.MissingExpected;
    if (expected <= position) return error.ReorderedMilestone;
    var terminal: ?usize = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var offset: usize = 0;
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (std.mem.indexOf(u8, line, "main returned") != null) {
            const body = terminalBody(line) orelse return error.InvalidMainReturn;
            if (try c.integer(i32, body["main returned ".len..]) != config.expect_main_return) return error.UnexpectedMainReturn;
            if (terminal != null) return error.DuplicateMainReturn;
            terminal = offset;
        }
        offset += raw_line.len + 1;
    }
    const end = terminal orelse return error.MissingMainReturn;
    if (end <= expected) return error.ReorderedMilestone;
    var previous: ?usize = null;
    for (config.required) |required| {
        const found = std.mem.indexOf(u8, text, required) orelse return error.MissingRequired;
        if (found >= end or (previous != null and found <= previous.?)) return error.ReorderedRequired;
        previous = found;
    }
}

fn normalize(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len == 0 or raw.len > c.max_serial) return error.SerialLimit;
    if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidSerial;
    const output = try a.alloc(u8, raw.len);
    errdefer a.free(output);
    var used: usize = 0;
    var at: usize = 0;
    var line: usize = 0;
    while (at < raw.len) {
        const byte = raw[at];
        at += 1;
        if (byte == 0) continue;
        if (byte == 0x1b) {
            if (at >= raw.len or raw[at] != '[') return error.InvalidSerial;
            at += 1;
            while (at < raw.len and raw[at] >= 0x30 and raw[at] <= 0x3f) : (at += 1) {}
            while (at < raw.len and raw[at] >= 0x20 and raw[at] <= 0x2f) : (at += 1) {}
            if (at == raw.len or raw[at] < 0x40 or raw[at] > 0x7e) return error.InvalidSerial;
            at += 1;
            continue;
        }
        if (byte < 0x20 and std.mem.indexOfScalar(u8, "\n\r\t", byte) == null) return error.InvalidSerial;
        if (byte == '\n') line = 0 else line += 1;
        if (line > 8192) return error.SerialLineLimit;
        output[used] = byte;
        used += 1;
    }
    return a.realloc(output, used);
}

// Terminal-only grammar from ukprint/console.c and snprintf.c. Other local
// assertions remain bounded substring markers, not host admission policies.
fn terminalBody(line: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, line, "main returned ")) return line;
    if (line.len > 256) return null;
    var rest = line;
    if (std.mem.startsWith(u8, rest, "[")) {
        const end = std.mem.indexOf(u8, rest, "] ") orelse return null;
        const time = rest[1..end];
        const dot = std.mem.indexOfScalar(u8, time, '.') orelse return null;
        if (!padded(time[0..dot], 5, 20) or time.len - dot - 1 != 6) return null;
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
        if (!std.mem.eql(u8, thread, "main") and !std.mem.eql(u8, thread, "init") and !pointer(thread)) return null;
        rest = rest[end + 2 ..];
    }
    if (std.mem.startsWith(u8, rest, "{r:")) {
        const end = std.mem.indexOf(u8, rest, "} ") orelse return null;
        const caller = rest[3..end];
        const comma = std.mem.indexOf(u8, caller, ",f:") orelse return null;
        if (!pointer(caller[0..comma]) or !pointer(caller[comma + 3 ..])) return null;
        rest = rest[end + 2 ..];
    }
    if (!std.mem.startsWith(u8, rest, "[libukboot] ")) return null;
    rest = rest["[libukboot] ".len..];
    if (std.mem.startsWith(u8, rest, "<boot.c @ ")) {
        const end = std.mem.indexOf(u8, rest, "> ") orelse return null;
        const number = rest["<boot.c @ ".len..end];
        if (!padded(number, 4, 5) or std.mem.eql(u8, std.mem.trimStart(u8, number, " "), "0")) return null;
        rest = rest[end + 2 ..];
    }
    return if (std.mem.startsWith(u8, rest, "main returned ")) rest else null;
}

fn padded(text: []const u8, width: usize, maximum: usize) bool {
    const digits = std.mem.trimStart(u8, text, " ");
    if (digits.len == 0 or digits.len > maximum or text.len != @max(width, digits.len) or
        (digits.len > 1 and digits[0] == '0')) return false;
    for (digits) |byte| if (!std.ascii.isDigit(byte)) return false;
    _ = std.fmt.parseInt(u64, digits, 10) catch return false;
    return true;
}
fn pointer(text: []const u8) bool {
    if (std.mem.eql(u8, text, "0")) return true;
    if (text.len < 3 or text.len > 18 or !std.mem.startsWith(u8, text, "0x") or text[2] == '0') return false;
    for (text[2..]) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}
