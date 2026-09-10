const std = @import("std");
const p = @import("protocol.zig");

pub const unavailable_records = [_][]const u8{
    "HYPERV_ACCEPTANCE PLATFORM_READY PASS cpu_count=1 vmbus_offers=0",
    "HYPERV_ACCEPTANCE STORAGE_INVENTORY UNAVAILABLE devices=0 offers=0 reason=no-storvsc-offer",
    "HYPERV_ACCEPTANCE STORAGE_READ UNAVAILABLE reason=no-device",
    "HYPERV_ACCEPTANCE NETWORK_INVENTORY UNAVAILABLE devices=0 offers=0 reason=no-netvsc-offer",
    "HYPERV_ACCEPTANCE NETWORK_DHCP_TX UNAVAILABLE reason=no-device",
    "HYPERV_ACCEPTANCE NETWORK_DHCP_RX UNAVAILABLE reason=no-device",
    "HYPERV_ACCEPTANCE FINAL_RESULT UNAVAILABLE storage=UNAVAILABLE network=UNAVAILABLE",
};
pub const unavailable_marker = "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network";
pub const platform_marker = "UK_HYPERV_PLATFORM_READY";
pub const legacy_marker = "Using legacy xAPIC MMIO";
const capabilities = [_][]const u8{ "Hyper-V Hv#1 hypercall page enabled", "Hyper-V SynIC:", "Powered by", "Calling main(" };
const live_markers = [_][]const u8{ "UK_HYPERV_BLOCK_READ_OK", "UK_HYPERV_NET_DHCP_OFFER", "UK_HYPERV_NET_APP_LEASE", "UK_HYPERV_NET_APP_ARP", "UK_HYPERV_NET_APP_TCP", "UK_HYPERV_NET_APP_UDP", "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_IO_READY" };

fn normalized(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len == 0 or text.len > p.max_serial) return error.SerialLimit;
    var result: std.Io.Writer.Allocating = .init(allocator);
    defer result.deinit();
    var index: usize = 0;
    while (index < text.len) {
        if (text[index] == 0) {
            index += 1;
        } else if (text[index] == 0x1b and index + 1 < text.len and text[index + 1] == '[') {
            index += 2;
            while (index < text.len and text[index] >= 0x30 and text[index] <= 0x3f) : (index += 1) {}
            while (index < text.len and text[index] >= 0x20 and text[index] <= 0x2f) : (index += 1) {}
            if (index >= text.len or text[index] < 0x40 or text[index] > 0x7e) return error.MalformedSerial;
            index += 1;
        } else {
            if (text[index] == 0x1b or (text[index] < 0x20 and std.mem.indexOfScalar(u8, "\t\r\n\x0b\x0c", text[index]) == null)) return error.MalformedSerial;
            try result.writer.writeByte(if (text[index] == '\r' or text[index] == '\x0b' or text[index] == '\x0c') '\n' else text[index]);
            index += 1;
        }
    }
    return result.toOwnedSlice();
}

fn contains(line: []const u8, value: []const u8) bool {
    return std.mem.indexOf(u8, line, value) != null;
}

fn trim(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t");
}

fn afterPrefix(bytes: []const u8) ![]const u8 {
    if (bytes.len == 0 or (bytes[0] != ' ' and bytes[0] != '\t')) return error.InvalidMainReturn;
    return std.mem.trimStart(u8, bytes, " \t");
}

fn mainReturn(line: []const u8) !i32 {
    var remaining = line;
    if (std.mem.startsWith(u8, remaining, "[")) {
        const close = std.mem.indexOfScalar(u8, remaining, ']') orelse return error.InvalidMainReturn;
        const inner = std.mem.trimStart(u8, remaining[1..close], " \t");
        var numeric = inner.len > 0;
        var digits: usize = 0;
        var dots: usize = 0;
        for (inner) |ch| {
            if (std.ascii.isDigit(ch)) digits += 1 else if (ch == '.') dots += 1 else numeric = false;
        }
        if (numeric and digits > 0 and dots <= 1 and inner[0] != '.' and inner[inner.len - 1] != '.') {
            remaining = try afterPrefix(remaining[close + 1 ..]);
        }
    }
    if (std.mem.startsWith(u8, remaining, "Info:")) remaining = try afterPrefix(remaining[5..]);
    if (std.mem.startsWith(u8, remaining, "[")) {
        const close = std.mem.indexOfScalar(u8, remaining, ']') orelse return error.InvalidMainReturn;
        if (close < 2 or close > 65) return error.InvalidMainReturn;
        for (remaining[1..close]) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-' and ch != '.') return error.InvalidMainReturn;
        remaining = try afterPrefix(remaining[close + 1 ..]);
    }
    if (std.mem.startsWith(u8, remaining, "<")) {
        const close = std.mem.indexOfScalar(u8, remaining, '>') orelse return error.InvalidMainReturn;
        if (close < 2 or close > 161 or std.mem.indexOfAny(u8, remaining[1..close], "<>\r\n") != null) return error.InvalidMainReturn;
        remaining = remaining[close + 1 ..];
        if (std.mem.startsWith(u8, remaining, ":")) remaining = remaining[1..];
        remaining = try afterPrefix(remaining);
    }
    const prefix = "main returned ";
    if (!std.mem.startsWith(u8, remaining, prefix)) return error.InvalidMainReturn;
    const value = remaining[prefix.len..];
    if (value.len == 0) return error.InvalidMainReturn;
    for (value, 0..) |ch, index| if (!std.ascii.isDigit(ch) and !(index == 0 and ch == '-')) return error.InvalidMainReturn;
    return std.fmt.parseInt(i32, value, 10) catch error.InvalidMainReturn;
}

pub fn validate(allocator: std.mem.Allocator, text: []const u8, policy: p.Policy, legacy_apic: bool, guarded: ?p.Guarded) !void {
    if (guarded) |contract| try contract.validate();
    const bytes = try normalized(allocator, text);
    defer allocator.free(bytes);
    var capability_counts = [_]usize{0} ** 4;
    var capability_positions: [4]usize = undefined;
    var platform_count: usize = 0;
    var platform_position: usize = 0;
    var legacy_count: usize = 0;
    var main_count: usize = 0;
    var main_position: usize = 0;
    var acceptance_count: usize = 0;
    var unavailable_count: usize = 0;
    var persistence_count: usize = 0;
    var persistence_positions: [3]usize = undefined;
    var start_buffer: [256]u8 = undefined;
    const start = if (guarded) |g| try std.fmt.bufPrint(&start_buffer, "HYPERV_PERSISTENCE START PASS run={s} address=0:0:{d} sectors={d} sector_size=512", .{ g.run_id, g.lun, g.sectors }) else "";
    const persistence = [_][]const u8{ start, "HYPERV_PERSISTENCE SELECT UNAVAILABLE reason=no-devices writes=0 flushes=0", "UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices" };
    if ((policy == .guarded_v2) != (guarded != null)) return error.InvalidGuardedContract;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var position: usize = 0;
    while (lines.next()) |raw| : (position += 1) {
        const line = trim(raw);
        if (line.len == 0) continue;
        for (capabilities, 0..) |marker, i| if (contains(line, marker)) {
            capability_counts[i] += 1;
            capability_positions[i] = position;
        };
        if (std.mem.eql(u8, line, platform_marker)) {
            platform_count += 1;
            platform_position = position;
        }
        if (contains(line, legacy_marker)) legacy_count += 1;
        inline for (.{ "Unikraft Crash", "Assertion failure", "Exception Type" }) |marker| if (contains(line, marker)) return error.GuestCrash;
        if (contains(line, "main returned")) {
            main_count += 1;
            main_position = position;
            if (try mainReturn(line) != @as(i32, if (policy == .platform_main_zero) 0 else 2)) return error.UnexpectedMainReturn;
        }
        for (live_markers) |marker| if (std.mem.eql(u8, line, marker)) return error.UnexpectedLiveIo;
        if (std.mem.startsWith(u8, line, "UK_HYPERV_") and
            ((std.mem.endsWith(u8, line, "_READY") and !std.mem.eql(u8, line, platform_marker)) or std.mem.endsWith(u8, line, "_READ_OK"))) return error.UnexpectedLiveIo;
        if (policy == .guarded_v2) {
            if (contains(line, "HYPERV_PERSISTENCE") or contains(line, "UK_HYPERV_PERSISTENCE")) {
                if (persistence_count >= persistence.len or !std.mem.eql(u8, line, persistence[persistence_count])) return error.InvalidGuardedEvidence;
                persistence_positions[persistence_count] = position;
                persistence_count += 1;
            }
            inline for (.{ "HYPERV_ACCEPTANCE ", "UK_HYPERV_ACCEPTANCE_", "HYPERV_STORAGE ", "HYPERV_NETWORK_APP " }) |prefix| if (std.mem.startsWith(u8, line, prefix)) return error.UnexpectedGuardedActivity;
        } else {
            if (contains(line, " PASS") and (std.mem.startsWith(u8, line, "HYPERV_ACCEPTANCE") or std.mem.startsWith(u8, line, "HYPERV_NETWORK_APP") or std.mem.startsWith(u8, line, "HYPERV_STORAGE")) and !std.mem.eql(u8, line, unavailable_records[0])) return error.UnexpectedLiveIo;
            if (policy == .platform_unavailable) {
                if (std.mem.startsWith(u8, line, "HYPERV_ACCEPTANCE ")) {
                    if (acceptance_count >= unavailable_records.len or !std.mem.eql(u8, line, unavailable_records[acceptance_count])) return error.InvalidUnavailableEvidence;
                    acceptance_count += 1;
                }
                if (std.mem.startsWith(u8, line, "UK_HYPERV_ACCEPTANCE_")) {
                    if (!std.mem.eql(u8, line, unavailable_marker)) return error.InvalidUnavailableEvidence;
                    unavailable_count += 1;
                }
            } else if (contains(line, "UNAVAILABLE")) return error.UnexpectedUnavailable;
        }
        if (contains(line, "FAIL")) return error.GuestFailure;
    }
    for (capability_counts) |count| if (count != 1) return error.MissingCapability;
    if (main_count != 1 or platform_count != 1 or legacy_count != @as(usize, if (legacy_apic) 1 else 0)) return error.InvalidBootEvidence;
    if (policy == .platform_unavailable and (acceptance_count != 7 or unavailable_count != 1)) return error.InvalidUnavailableEvidence;
    if (policy == .guarded_v2) {
        if (persistence_count != 3) return error.InvalidGuardedEvidence;
        const ordered = capability_positions ++ [_]usize{ persistence_positions[0], persistence_positions[1], platform_position, persistence_positions[2], main_position };
        for (ordered[1..], ordered[0 .. ordered.len - 1]) |next, prior| if (next <= prior) return error.ReorderedGuardedEvidence;
    }
}
