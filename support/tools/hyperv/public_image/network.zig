const std = @import("std");
const c = @import("contracts.zig");
const kconfig = @import("native_kconfig");
const pins = @import("producer_pins");
const j = c.core.contracts;

pub const Transcript = struct {
    schema: []const u8 = "ukna-v1",
    request_sha256: []const u8,
    response_sha256: []const u8,
    tcp_connections: u8 = 3,
    udp_datagrams: u8 = 6,
    tcp_bytes: u32 = 1760,
    udp_bytes: u32 = 3408,
};
pub const Network = struct {
    mode: []const u8 = "network-application",
    peer_ipv4: []const u8,
    tcp_port: u16,
    udp_port: u16,
    nonce: []const u8,
    solved_config_sha256: []const u8,
    peer_script_sha256: []const u8,
    transcript: Transcript,
};
pub fn value(a: std.mem.Allocator, data: anytype) !std.json.Value {
    const encoded = try c.encode(a, data);
    defer a.free(encoded);
    return std.json.parseFromSliceLeaky(std.json.Value, a, encoded, .{ .allocate = .alloc_always, .parse_numbers = false });
}
pub fn raw(a: std.mem.Allocator) !std.json.Value {
    return value(a, .{ .mode = "raw-dhcp" });
}
pub fn transcript(a: std.mem.Allocator, nonce: u64) !Transcript {
    var hashes = [_]c.Hash{ undefined, undefined };
    for (1..3) |direction| {
        var digest = std.crypto.hash.sha2.Sha256.init(.{});
        for ([_]struct { transport: u8, sequence: u32, length: u32 }{
            .{ .transport = 1, .sequence = 1, .length = 31 },       .{ .transport = 1, .sequence = 2, .length = 1400 },
            .{ .transport = 1, .sequence = 3, .length = 257 },      .{ .transport = 2, .sequence = 0x100, .length = 19 },
            .{ .transport = 2, .sequence = 0x101, .length = 1448 }, .{ .transport = 2, .sequence = 0x102, .length = 73 },
            .{ .transport = 2, .sequence = 0x103, .length = 1448 }, .{ .transport = 2, .sequence = 0x104, .length = 257 },
            .{ .transport = 2, .sequence = 0x105, .length = 19 },
        }) |item| {
            var message: [24 + 1448]u8 = undefined;
            message[0..4].* = "UKNA".*;
            message[4..8].* = .{ 1, item.transport, @intCast(direction), 24 };
            std.mem.writeInt(u32, message[8..12], item.sequence, .big);
            std.mem.writeInt(u32, message[12..16], item.length, .big);
            std.mem.writeInt(u64, message[16..24], nonce, .big);
            for (message[24..][0..item.length], 0..) |*byte, i|
                byte.* = @truncate((nonce >> @intCast((7 - (i & 7)) * 8)) ^
                    (item.sequence >> @intCast((3 - (i & 3)) * 8)) ^
                    (@as(u64, item.transport) * 0x31) ^ (direction * 0x57) ^ (i * 0x1d));
            digest.update(message[0 .. 24 + item.length]);
        }
        hashes[direction - 1] = digest.finalResult();
    }
    return .{ .request_sha256 = try c.hex(a, hashes[0]), .response_sha256 = try c.hex(a, hashes[1]) };
}
fn ipv4(text: []const u8) !void {
    var parts = std.mem.splitScalar(u8, text, '.');
    var octets: [4]u8 = undefined;
    for (&octets) |*octet| octet.* = try c.boot.config.integer(u8, parts.next() orelse return error.InvalidNetwork);
    if (parts.next() != null or !(octets[0] == 10 or
        (octets[0] == 172 and octets[1] >= 16 and octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168))) return error.InvalidNetwork;
}
fn nonceValue(text: []const u8) !u64 {
    if (text.len != 16) return error.InvalidNetwork;
    for (text) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidNetwork;
    return std.fmt.parseInt(u64, text, 16);
}
pub fn fromConfig(a: std.mem.Allocator, bytes: []const u8) !std.json.Value {
    if (bytes.len == 0 or bytes.len > c.max_config or !std.unicode.utf8ValidateSlice(bytes)) return error.InvalidNetwork;
    const symbols = [_]struct { name: []const u8, kind: kconfig.SymbolType }{
        .{ .name = "APPHYPERVACCEPTANCE_NETWORK_APPLICATION", .kind = .boolean },
        .{ .name = "APPHYPERVACCEPTANCE_PEER_IPV4", .kind = .string },
        .{ .name = "APPHYPERVACCEPTANCE_PEER_TCP_PORT", .kind = .integer },
        .{ .name = "APPHYPERVACCEPTANCE_PEER_UDP_PORT", .kind = .integer },
        .{ .name = "APPHYPERVACCEPTANCE_NONCE", .kind = .string },
    };
    var metadata = kconfig.Metadata.init(a);
    defer metadata.deinit();
    for (symbols) |symbol| try metadata.addSymbol(symbol.name, symbol.kind);
    // The public contract types only these five settings; unrelated solved
    // symbols still bind through the hash of the complete original config.
    var selected: std.Io.Writer.Allocating = .init(a);
    defer selected.deinit();
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        const candidate = if (std.mem.startsWith(u8, trimmed, "# ")) trimmed[2..] else trimmed;
        if (!std.mem.startsWith(u8, candidate, "CONFIG_")) continue;
        const setting = candidate["CONFIG_".len..];
        for (symbols) |symbol| {
            if (std.mem.startsWith(u8, setting, symbol.name) and
                (setting.len == symbol.name.len or setting[symbol.name.len] == '=' or setting[symbol.name.len] == ' '))
            {
                try selected.writer.writeAll(trimmed);
                try selected.writer.writeByte('\n');
                break;
            }
        }
    }
    var diagnostic: kconfig.Diagnostic = .{};
    var config = try kconfig.parseWithMetadata(a, selected.written(), &metadata, &diagnostic);
    defer config.deinit();
    if (!(try config.getBool("APPHYPERVACCEPTANCE_NETWORK_APPLICATION") orelse false)) return error.InvalidNetwork;
    const peer = try config.getString("APPHYPERVACCEPTANCE_PEER_IPV4") orelse return error.InvalidNetwork;
    try ipv4(peer);
    const tcp = try config.getInteger("APPHYPERVACCEPTANCE_PEER_TCP_PORT") orelse return error.InvalidNetwork;
    const udp = try config.getInteger("APPHYPERVACCEPTANCE_PEER_UDP_PORT") orelse return error.InvalidNetwork;
    if (tcp < 1 or tcp > 65535 or udp < 1 or udp > 65535 or tcp == udp) return error.InvalidNetwork;
    const nonce = try std.ascii.allocLowerString(a, try config.getString("APPHYPERVACCEPTANCE_NONCE") orelse return error.InvalidNetwork);
    const result: Network = .{
        .peer_ipv4 = peer,
        .tcp_port = @intCast(tcp),
        .udp_port = @intCast(udp),
        .nonce = nonce,
        .solved_config_sha256 = try c.hex(a, c.hash(bytes)),
        .peer_script_sha256 = try c.hex(a, pins.peer_sha256),
        .transcript = try transcript(a, try nonceValue(nonce)),
    };
    return value(a, result);
}
pub fn parse(input: std.json.Value) !?Network {
    if (input != .object) return error.InvalidNetwork;
    const mode = try j.string(input.object.get("mode") orelse return error.InvalidNetwork);
    if (std.mem.eql(u8, mode, "raw-dhcp")) {
        _ = try j.exactFields(input, &.{"mode"});
        return null;
    }
    if (!std.mem.eql(u8, mode, "network-application")) return error.InvalidNetwork;
    const o = try j.exactFields(input, &.{ "mode", "peer_ipv4", "tcp_port", "udp_port", "nonce", "solved_config_sha256", "peer_script_sha256", "transcript" });
    const tr = try j.exactFields(o.get("transcript").?, &.{ "schema", "request_sha256", "response_sha256", "tcp_connections", "udp_datagrams", "tcp_bytes", "udp_bytes" });
    const result: Network = .{
        .peer_ipv4 = try j.string(o.get("peer_ipv4").?),
        .tcp_port = try j.integer(u16, o.get("tcp_port").?),
        .udp_port = try j.integer(u16, o.get("udp_port").?),
        .nonce = try j.string(o.get("nonce").?),
        .solved_config_sha256 = try j.string(o.get("solved_config_sha256").?),
        .peer_script_sha256 = try j.string(o.get("peer_script_sha256").?),
        .transcript = .{
            .schema = try j.string(tr.get("schema").?),
            .request_sha256 = try j.string(tr.get("request_sha256").?),
            .response_sha256 = try j.string(tr.get("response_sha256").?),
            .tcp_connections = try j.integer(u8, tr.get("tcp_connections").?),
            .udp_datagrams = try j.integer(u8, tr.get("udp_datagrams").?),
            .tcp_bytes = try j.integer(u32, tr.get("tcp_bytes").?),
            .udp_bytes = try j.integer(u32, tr.get("udp_bytes").?),
        },
    };
    try ipv4(result.peer_ipv4);
    _ = try nonceValue(result.nonce);
    if (result.tcp_port == 0 or result.udp_port == 0 or result.tcp_port == result.udp_port) return error.InvalidNetwork;
    _ = try c.sha(result.solved_config_sha256);
    if (!std.mem.eql(u8, &try c.sha(result.peer_script_sha256), &pins.peer_sha256)) return error.InvalidNetwork;
    _ = try c.sha(result.transcript.request_sha256);
    _ = try c.sha(result.transcript.response_sha256);
    return result;
}
pub fn validate(a: std.mem.Allocator, input: std.json.Value) !void {
    if (try parse(input)) |config|
        try @import("files.zig").same(a, try transcript(a, try nonceValue(config.nonce)), config.transcript);
}
pub fn marker(a: std.mem.Allocator, config: Network) ![]const u8 {
    return std.fmt.allocPrint(a, "HYPERV_ACCEPTANCE NETWORK_APP_CONFIG PASS peer_ipv4={s} tcp_port={d} udp_port={d} nonce={s} tcp_connections=3 udp_datagrams=6", .{ config.peer_ipv4, config.tcp_port, config.udp_port, config.nonce });
}
pub fn serial(a: std.mem.Allocator, bytes: []const u8, config: c.boot.config.Config, acceptance: std.json.Value) !void {
    try c.boot.serial.validate(a, bytes, config);
    try validate(a, acceptance);
    const normalized = try c.boot.serial.normalize(a, bytes);
    defer a.free(normalized);
    const application_start = std.mem.indexOf(u8, normalized, c.boot.serial.milestones[3]) orelse return error.InvalidPublicSerial;
    const wanted = if (try parse(acceptance)) |n| try marker(a, n) else null;
    defer if (wanted) |text| a.free(text);
    var lines = std.mem.splitScalar(u8, normalized, '\n');
    var platforms: usize = 0;
    var legacy: usize = 0;
    var configs: usize = 0;
    var returned = false;
    var offset: usize = 0;
    while (lines.next()) |raw_line| {
        defer offset += raw_line.len + 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        // The shared validator already establishes the unique anchored return.
        if (std.mem.indexOf(u8, line, "main returned") != null) returned = true;
        if (std.mem.eql(u8, line, config.expect)) {
            if (offset <= application_start or returned) return error.InvalidPublicSerial;
            platforms += 1;
        }
        if (std.mem.indexOf(u8, line, c.legacy_marker) != null) legacy += 1;
        if (std.mem.indexOf(u8, line, "HYPERV_ACCEPTANCE NETWORK_APP_CONFIG") != null) {
            if (returned or wanted == null or !std.mem.eql(u8, line, wanted.?)) return error.NetworkMarkerMismatch;
            configs += 1;
        }
        for ([_][]const u8{ "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY", "HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS", "UK_HYPERV_ACCEPTANCE_FAIL:" }) |bad|
            if (std.mem.indexOf(u8, line, bad) != null) return error.UnexpectedAcceptance;
    }
    if (platforms != 1 or legacy != @as(usize, @intFromBool(config.disable_x2apic)) or
        configs != @as(usize, @intFromBool(wanted != null))) return error.InvalidPublicSerial;
}
