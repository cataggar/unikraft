const std = @import("std");

pub const Tristate = enum {
    n,
    m,
    y,
};

pub const SymbolType = enum {
    boolean,
    tristate,
    string,
    integer,
    hex,
};

pub const Platform = struct {
    symbol: []const u8,
    name: []const u8,
};

pub const SymbolMetadata = struct {
    name: []const u8,
    symbol_type: SymbolType,
};

pub const Metadata = struct {
    allocator: std.mem.Allocator,
    symbols: std.array_list.Managed(SymbolMetadata),
    platforms: std.array_list.Managed(Platform),

    pub fn init(allocator: std.mem.Allocator) Metadata {
        return .{
            .allocator = allocator,
            .symbols = std.array_list.Managed(SymbolMetadata).init(allocator),
            .platforms = std.array_list.Managed(Platform).init(allocator),
        };
    }

    pub fn deinit(self: *Metadata) void {
        for (self.symbols.items) |symbol| self.allocator.free(symbol.name);
        for (self.platforms.items) |platform| {
            self.allocator.free(platform.symbol);
            self.allocator.free(platform.name);
        }
        self.symbols.deinit();
        self.platforms.deinit();
        self.* = undefined;
    }

    pub fn addSymbol(
        self: *Metadata,
        name: []const u8,
        symbol_type: SymbolType,
    ) !void {
        if (!validSymbol(name)) return error.InvalidMetadata;
        for (self.symbols.items) |existing| {
            if (!std.mem.eql(u8, existing.name, name)) continue;
            if (existing.symbol_type != symbol_type) return error.ConflictingMetadata;
            return error.DuplicateMetadata;
        }
        try self.symbols.append(.{
            .name = try self.allocator.dupe(u8, name),
            .symbol_type = symbol_type,
        });
    }

    pub fn addPlatform(
        self: *Metadata,
        symbol: []const u8,
        name: []const u8,
    ) !void {
        if (!validSymbol(symbol) or !validPlatformName(name)) return error.InvalidMetadata;
        for (self.platforms.items) |existing| {
            if (std.mem.eql(u8, existing.symbol, symbol)) {
                if (!std.mem.eql(u8, existing.name, name)) return error.ConflictingMetadata;
                return error.DuplicateMetadata;
            }
            if (std.mem.eql(u8, existing.name, name)) return error.ConflictingMetadata;
        }
        try self.platforms.append(.{
            .symbol = try self.allocator.dupe(u8, symbol),
            .name = try self.allocator.dupe(u8, name),
        });
    }

    pub fn typeOf(self: *const Metadata, name: []const u8) ?SymbolType {
        for (self.symbols.items) |symbol| {
            if (std.mem.eql(u8, symbol.name, name)) return symbol.symbol_type;
        }
        return null;
    }

    pub fn parse(allocator: std.mem.Allocator, source: []const u8) !Metadata {
        var metadata = Metadata.init(allocator);
        errdefer metadata.deinit();
        var lines = std.mem.splitScalar(u8, source, '\n');
        const header = lines.next() orelse return error.InvalidMetadata;
        if (!std.mem.eql(u8, std.mem.trimEnd(u8, header, "\r"), "unikraft-native-config-metadata-v1")) {
            return error.InvalidMetadata;
        }
        while (lines.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            if (line.len == 0) continue;
            var fields = std.mem.splitScalar(u8, line, '\t');
            const kind = fields.next() orelse return error.InvalidMetadata;
            const first = fields.next() orelse return error.InvalidMetadata;
            const second = fields.next() orelse return error.InvalidMetadata;
            if (fields.next() != null) return error.InvalidMetadata;
            if (std.mem.eql(u8, kind, "symbol")) {
                try metadata.addSymbol(first, parseSymbolType(second) orelse return error.InvalidMetadata);
            } else if (std.mem.eql(u8, kind, "platform")) {
                try metadata.addPlatform(first, second);
            } else {
                return error.InvalidMetadata;
            }
        }
        return metadata;
    }
};

pub const Number = struct {
    value: i64,
    text: []const u8,
};

pub const Hex = struct {
    value: u64,
    text: []const u8,
};

pub const Value = union(enum) {
    unset,
    tristate: Tristate,
    string: []const u8,
    integer: Number,
    hex: Hex,
};

pub const Entry = struct {
    name: []const u8,
    value: Value,
    symbol_type: ?SymbolType,
    line: usize,
};

pub const Diagnostic = struct {
    kind: Kind = .malformed_line,
    line: usize = 0,
    column: usize = 0,
    previous_line: ?usize = null,
    symbol: []const u8 = "",

    pub const Kind = enum {
        malformed_line,
        invalid_symbol,
        invalid_value,
        malformed_string,
        ambiguous_numeric,
        type_mismatch,
        duplicate_entry,
        conflicting_entry,
    };
};

pub const ParseError = error{
    InvalidConfig,
    OutOfMemory,
};

pub const AccessError = error{TypeMismatch};

pub const Document = struct {
    allocator: std.mem.Allocator,
    entries: std.array_list.Managed(Entry),
    authoritative_metadata: bool,

    pub fn deinit(self: *Document) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            switch (entry.value) {
                .string => |value| self.allocator.free(value),
                .integer => |number| self.allocator.free(number.text),
                .hex => |number| self.allocator.free(number.text),
                else => {},
            }
        }
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn get(self: *const Document, name: []const u8) ?*const Entry {
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry;
        }
        return null;
    }

    pub fn getTristate(self: *const Document, name: []const u8) AccessError!?Tristate {
        const entry = self.get(name) orelse return null;
        return switch (entry.value) {
            .unset => .n,
            .tristate => |value| value,
            else => error.TypeMismatch,
        };
    }

    pub fn getBool(self: *const Document, name: []const u8) AccessError!?bool {
        const value = try self.getTristate(name) orelse return null;
        return switch (value) {
            .n => false,
            .y => true,
            .m => error.TypeMismatch,
        };
    }

    pub fn getString(self: *const Document, name: []const u8) AccessError!?[]const u8 {
        const entry = self.get(name) orelse return null;
        return switch (entry.value) {
            .string => |value| value,
            else => error.TypeMismatch,
        };
    }

    pub fn getInteger(self: *const Document, name: []const u8) AccessError!?i64 {
        const entry = self.get(name) orelse return null;
        return switch (entry.value) {
            .integer => |number| number.value,
            else => error.TypeMismatch,
        };
    }

    pub fn getHex(self: *const Document, name: []const u8) AccessError!?u64 {
        const entry = self.get(name) orelse return null;
        return switch (entry.value) {
            .hex => |number| number.value,
            else => error.TypeMismatch,
        };
    }

    pub fn enabled(self: *const Document, name: []const u8) bool {
        const entry = self.get(name) orelse return false;
        return switch (entry.value) {
            .tristate => |value| value == .y,
            else => false,
        };
    }

    pub fn renderHeader(self: *const Document, writer: *std.Io.Writer) !void {
        for (self.entries.items) |entry| {
            // Current Kconfig generators omit stale symbols absent from the model.
            if (self.authoritative_metadata and entry.symbol_type == null) continue;
            switch (entry.value) {
                .unset => {},
                .tristate => |value| switch (value) {
                    .n => {},
                    .y => try writer.print("#define CONFIG_{s} 1\n", .{entry.name}),
                    .m => try writer.print("#define CONFIG_{s}_MODULE 1\n", .{entry.name}),
                },
                .string => |value| {
                    try writer.print("#define CONFIG_{s} \"", .{entry.name});
                    for (value) |byte| {
                        if (byte == '\\' or byte == '"') try writer.writeByte('\\');
                        try writer.writeByte(byte);
                    }
                    try writer.writeAll("\"\n");
                },
                .integer => |number| try writer.print(
                    "#define CONFIG_{s} {s}\n",
                    .{ entry.name, number.text },
                ),
                .hex => |number| {
                    try writer.print("#define CONFIG_{s} ", .{entry.name});
                    if (!std.mem.startsWith(u8, number.text, "0x") and
                        !std.mem.startsWith(u8, number.text, "0X"))
                    {
                        try writer.writeAll("0x");
                    }
                    try writer.print("{s}\n", .{number.text});
                },
            }
        }
    }

    pub fn headerAlloc(self: *const Document, allocator: std.mem.Allocator) ![]u8 {
        var output = std.Io.Writer.Allocating.init(allocator);
        defer output.deinit();
        try self.renderHeader(&output.writer);
        return output.toOwnedSlice();
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    diagnostic: *Diagnostic,
) ParseError!Document {
    return parseWithMetadata(allocator, source, null, diagnostic);
}

pub fn parseWithMetadata(
    allocator: std.mem.Allocator,
    source: []const u8,
    metadata: ?*const Metadata,
    diagnostic: *Diagnostic,
) ParseError!Document {
    diagnostic.* = .{};
    var document = Document{
        .allocator = allocator,
        .entries = std.array_list.Managed(Entry).init(allocator),
        .authoritative_metadata = metadata != null,
    };
    errdefer document.deinit();

    var lines = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;

        if (std.mem.startsWith(u8, line, "# CONFIG_")) {
            const suffix = " is not set";
            if (!std.mem.endsWith(u8, line, suffix)) {
                return fail(diagnostic, .malformed_line, line_number, 1, "", null);
            }
            const name = line["# CONFIG_".len .. line.len - suffix.len];
            if (!validSymbol(name)) {
                return fail(diagnostic, .invalid_symbol, line_number, "# CONFIG_".len + 1, name, null);
            }
            const symbol_type = if (metadata) |types| types.typeOf(name) else null;
            if (symbol_type) |actual| {
                if (actual != .boolean and actual != .tristate) {
                    return fail(diagnostic, .type_mismatch, line_number, 1, name, null);
                }
            }
            try appendEntry(&document, diagnostic, name, .unset, symbol_type, line_number);
            continue;
        }
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " \t"), "#")) continue;
        if (!std.mem.startsWith(u8, line, "CONFIG_")) {
            return fail(diagnostic, .malformed_line, line_number, 1, "", null);
        }

        const equals = std.mem.indexOfScalar(u8, line, '=') orelse
            return fail(diagnostic, .malformed_line, line_number, line.len + 1, "", null);
        const name = line["CONFIG_".len..equals];
        if (!validSymbol(name)) {
            return fail(diagnostic, .invalid_symbol, line_number, "CONFIG_".len + 1, name, null);
        }
        const text = line[equals + 1 ..];
        if (text.len == 0) {
            return fail(diagnostic, .invalid_value, line_number, equals + 2, name, null);
        }
        const symbol_type = if (metadata) |types| types.typeOf(name) else null;
        const value = try parseValue(
            allocator,
            text,
            symbol_type,
            diagnostic,
            line_number,
            equals + 2,
            name,
        );
        errdefer freeValue(allocator, value);
        try appendEntry(&document, diagnostic, name, value, symbol_type, line_number);
    }
    return document;
}

fn parseValue(
    allocator: std.mem.Allocator,
    text: []const u8,
    symbol_type: ?SymbolType,
    diagnostic: *Diagnostic,
    line: usize,
    column: usize,
    name: []const u8,
) ParseError!Value {
    if (text.len == 1) {
        return switch (text[0]) {
            'n' => parseTristate(.n, symbol_type, diagnostic, line, column, name),
            'm' => parseTristate(.m, symbol_type, diagnostic, line, column, name),
            'y' => parseTristate(.y, symbol_type, diagnostic, line, column, name),
            else => parseNumber(allocator, text, symbol_type, diagnostic, line, column, name),
        };
    }
    if (text[0] == '"') {
        if (symbol_type) |actual| {
            if (actual != .string) {
                return fail(diagnostic, .type_mismatch, line, column, name, null);
            }
        }
        if (text.len < 2 or text[text.len - 1] != '"') {
            return fail(diagnostic, .malformed_string, line, column, name, null);
        }
        var decoded = std.array_list.Managed(u8).init(allocator);
        defer decoded.deinit();
        var index: usize = 1;
        while (index < text.len - 1) {
            const byte = text[index];
            if (byte == '"') {
                return fail(diagnostic, .malformed_string, line, column + index, name, null);
            }
            if (byte == '\\') {
                if (index + 1 >= text.len - 1) {
                    return fail(diagnostic, .malformed_string, line, column + index, name, null);
                }
                index += 1;
                try decoded.append(text[index]);
            } else {
                try decoded.append(byte);
            }
            index += 1;
        }
        return .{ .string = try decoded.toOwnedSlice() };
    }
    return parseNumber(allocator, text, symbol_type, diagnostic, line, column, name);
}

fn parseTristate(
    value: Tristate,
    symbol_type: ?SymbolType,
    diagnostic: *Diagnostic,
    line: usize,
    column: usize,
    name: []const u8,
) ParseError!Value {
    if (symbol_type) |actual| {
        if (actual != .boolean and actual != .tristate) {
            return fail(diagnostic, .type_mismatch, line, column, name, null);
        }
        if (actual == .boolean and value == .m) {
            return fail(diagnostic, .type_mismatch, line, column, name, null);
        }
    }
    return .{ .tristate = value };
}

fn parseNumber(
    allocator: std.mem.Allocator,
    text: []const u8,
    symbol_type: ?SymbolType,
    diagnostic: *Diagnostic,
    line: usize,
    column: usize,
    name: []const u8,
) ParseError!Value {
    if (symbol_type) |actual| {
        switch (actual) {
            .integer => {
                const value = std.fmt.parseInt(i64, text, 10) catch
                    return fail(diagnostic, .type_mismatch, line, column, name, null);
                return .{ .integer = .{
                    .value = value,
                    .text = try allocator.dupe(u8, text),
                } };
            },
            .hex => {
                const digits = if (std.mem.startsWith(u8, text, "0x") or
                    std.mem.startsWith(u8, text, "0X"))
                    text[2..]
                else
                    text;
                if (digits.len == 0) {
                    return fail(diagnostic, .type_mismatch, line, column, name, null);
                }
                const value = std.fmt.parseInt(u64, digits, 16) catch
                    return fail(diagnostic, .type_mismatch, line, column, name, null);
                return .{ .hex = .{
                    .value = value,
                    .text = try allocator.dupe(u8, text),
                } };
            },
            else => return fail(diagnostic, .type_mismatch, line, column, name, null),
        }
    }
    if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) {
        if (text.len == 2) return fail(diagnostic, .invalid_value, line, column, name, null);
        const value = std.fmt.parseInt(u64, text[2..], 16) catch
            return fail(diagnostic, .invalid_value, line, column, name, null);
        return .{ .hex = .{
            .value = value,
            .text = try allocator.dupe(u8, text),
        } };
    }
    if (isBareHex(text)) {
        const value = std.fmt.parseInt(u64, text, 16) catch
            return fail(diagnostic, .invalid_value, line, column, name, null);
        return .{ .hex = .{
            .value = value,
            .text = try allocator.dupe(u8, text),
        } };
    }
    if (isUnsignedDecimal(text)) {
        return fail(diagnostic, .ambiguous_numeric, line, column, name, null);
    }
    const value = std.fmt.parseInt(i64, text, 10) catch
        return fail(diagnostic, .invalid_value, line, column, name, null);
    return .{ .integer = .{
        .value = value,
        .text = try allocator.dupe(u8, text),
    } };
}

fn isUnsignedDecimal(text: []const u8) bool {
    const digits = if (text.len != 0 and text[0] == '+') text[1..] else text;
    if (digits.len == 0) return false;
    for (digits) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn isBareHex(text: []const u8) bool {
    var has_hex_letter = false;
    for (text) |byte| {
        if (!std.ascii.isHex(byte)) return false;
        if (std.ascii.isAlphabetic(byte)) has_hex_letter = true;
    }
    return has_hex_letter;
}

fn appendEntry(
    document: *Document,
    diagnostic: *Diagnostic,
    name: []const u8,
    value: Value,
    symbol_type: ?SymbolType,
    line: usize,
) ParseError!void {
    for (document.entries.items) |entry| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        const kind: Diagnostic.Kind = if (valuesEqual(entry.value, value))
            .duplicate_entry
        else
            .conflicting_entry;
        return fail(diagnostic, kind, line, 1, name, entry.line);
    }
    try document.entries.append(.{
        .name = try document.allocator.dupe(u8, name),
        .value = value,
        .symbol_type = symbol_type,
        .line = line,
    });
}

fn validSymbol(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '_')) return false;
    }
    return true;
}

fn validPlatformName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or
            std.mem.indexOfScalar(u8, "._+-", byte) != null))
        {
            return false;
        }
    }
    return true;
}

fn parseSymbolType(text: []const u8) ?SymbolType {
    if (std.mem.eql(u8, text, "bool")) return .boolean;
    if (std.mem.eql(u8, text, "tristate")) return .tristate;
    if (std.mem.eql(u8, text, "string")) return .string;
    if (std.mem.eql(u8, text, "int")) return .integer;
    if (std.mem.eql(u8, text, "hex")) return .hex;
    return null;
}

fn valuesEqual(left: Value, right: Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .unset => true,
        .tristate => |value| value == right.tristate,
        .string => |value| std.mem.eql(u8, value, right.string),
        .integer => |number| number.value == right.integer.value,
        .hex => |number| number.value == right.hex.value,
    };
}

fn freeValue(allocator: std.mem.Allocator, value: Value) void {
    switch (value) {
        .string => |text| allocator.free(text),
        .integer => |number| allocator.free(number.text),
        .hex => |number| allocator.free(number.text),
        else => {},
    }
}

fn fail(
    diagnostic: *Diagnostic,
    kind: Diagnostic.Kind,
    line: usize,
    column: usize,
    symbol: []const u8,
    previous_line: ?usize,
) error{InvalidConfig} {
    diagnostic.* = .{
        .kind = kind,
        .line = line,
        .column = column,
        .previous_line = previous_line,
        .symbol = symbol,
    };
    return error.InvalidConfig;
}

pub const Architecture = struct {
    symbol: []const u8,
    name: []const u8,
    family: []const u8,
};

pub const Target = struct {
    architecture: Architecture,
    platform: Platform,
};

pub const ValidationDiagnostic = struct {
    kind: Kind = .missing_architecture,
    symbol: []const u8 = "",
    other_symbol: []const u8 = "",

    pub const Kind = enum {
        missing_architecture,
        multiple_architectures,
        unsupported_architecture,
        missing_platform,
        multiple_platforms,
        unsupported_platform,
        missing_boot_entry,
    };
};

pub const supported_architectures = [_]Architecture{
    .{ .symbol = "ARCH_X86_64", .name = "x86_64", .family = "x86" },
    .{ .symbol = "ARCH_ARM_64", .name = "arm64", .family = "arm" },
    .{ .symbol = "ARCH_ARM_32", .name = "arm", .family = "arm" },
};

pub const builtin_platforms = [_]Platform{
    .{ .symbol = "PLAT_KVM", .name = "kvm" },
    .{ .symbol = "PLAT_XEN", .name = "xen" },
};

pub fn deriveTarget(
    config: *const Document,
    diagnostic: *ValidationDiagnostic,
) error{InvalidTarget}!Target {
    return deriveTargetWithPlatforms(config, &builtin_platforms, diagnostic);
}

pub fn deriveTargetWithPlatforms(
    config: *const Document,
    platforms: []const Platform,
    diagnostic: *ValidationDiagnostic,
) error{InvalidTarget}!Target {
    diagnostic.* = .{};
    var architecture: ?Architecture = null;
    for (supported_architectures) |candidate| {
        if (!config.enabled(candidate.symbol)) continue;
        if (architecture) |selected| {
            diagnostic.* = .{
                .kind = .multiple_architectures,
                .symbol = selected.symbol,
                .other_symbol = candidate.symbol,
            };
            return error.InvalidTarget;
        }
        architecture = candidate;
    }
    for (config.entries.items) |entry| {
        if (!config.enabled(entry.name) or !std.mem.startsWith(u8, entry.name, "ARCH_")) continue;
        var known = false;
        for (supported_architectures) |candidate| {
            if (std.mem.eql(u8, entry.name, candidate.symbol)) {
                known = true;
                break;
            }
        }
        if (!known) {
            diagnostic.* = .{ .kind = .unsupported_architecture, .symbol = entry.name };
            return error.InvalidTarget;
        }
    }
    const selected_architecture = architecture orelse {
        diagnostic.* = .{ .kind = .missing_architecture };
        return error.InvalidTarget;
    };

    var platform: ?Platform = null;
    for (platforms) |candidate| {
        if (!config.enabled(candidate.symbol)) continue;
        if (platform) |selected| {
            diagnostic.* = .{
                .kind = .multiple_platforms,
                .symbol = selected.symbol,
                .other_symbol = candidate.symbol,
            };
            return error.InvalidTarget;
        }
        platform = candidate;
    }
    for (config.entries.items) |entry| {
        if (!config.enabled(entry.name) or !std.mem.startsWith(u8, entry.name, "PLAT_")) continue;
        var known_or_helper = false;
        for (platforms) |candidate| {
            if (std.mem.eql(u8, entry.name, candidate.symbol) or
                (std.mem.startsWith(u8, entry.name, candidate.symbol) and
                    entry.name.len > candidate.symbol.len and
                    entry.name[candidate.symbol.len] == '_'))
            {
                known_or_helper = true;
                break;
            }
        }
        if (!known_or_helper) {
            diagnostic.* = .{ .kind = .unsupported_platform, .symbol = entry.name };
            return error.InvalidTarget;
        }
    }
    const selected_platform = platform orelse {
        diagnostic.* = .{ .kind = .missing_platform };
        return error.InvalidTarget;
    };
    return .{
        .architecture = selected_architecture,
        .platform = selected_platform,
    };
}

pub fn validateBootEntry(
    config: *const Document,
    diagnostic: *ValidationDiagnostic,
) error{InvalidTarget}!void {
    if (!config.enabled("HAVE_BOOTENTRY")) {
        diagnostic.* = .{ .kind = .missing_boot_entry, .symbol = "HAVE_BOOTENTRY" };
        return error.InvalidTarget;
    }
}

test "typed values and Kconfig-compatible header semantics" {
    const allocator = std.testing.allocator;
    var metadata = Metadata.init(allocator);
    defer metadata.deinit();
    try metadata.addSymbol("BOOL", .boolean);
    try metadata.addSymbol("MODULE", .tristate);
    try metadata.addSymbol("OFF", .boolean);
    try metadata.addSymbol("TEXT", .string);
    try metadata.addSymbol("NEGATIVE", .integer);
    try metadata.addSymbol("ADDRESS", .hex);
    try metadata.addSymbol("DIGIT_HEX", .hex);
    try metadata.addSymbol("BARE_HEX", .hex);
    try metadata.addSymbol("UNKNOWN_SYMBOL", .integer);
    const source =
        \\CONFIG_BOOL=y
        \\CONFIG_MODULE=m
        \\# CONFIG_OFF is not set
        \\CONFIG_TEXT="quote: \" slash: \\ dropped: \q"
        \\CONFIG_NEGATIVE=-0042
        \\CONFIG_ADDRESS=0X00ff
        \\CONFIG_DIGIT_HEX=40000000
        \\CONFIG_BARE_HEX=deAd
        \\CONFIG_UNKNOWN_SYMBOL=7
        \\CONFIG_UNKNOWN_PREFIXED=0x7
        \\
    ;
    var diagnostic: Diagnostic = .{};
    var config = try parseWithMetadata(allocator, source, &metadata, &diagnostic);
    defer config.deinit();

    try std.testing.expectEqual(true, (try config.getBool("BOOL")).?);
    try std.testing.expectEqual(Tristate.m, (try config.getTristate("MODULE")).?);
    try std.testing.expectEqual(false, (try config.getBool("OFF")).?);
    try std.testing.expectEqualStrings(
        "quote: \" slash: \\ dropped: q",
        (try config.getString("TEXT")).?,
    );
    try std.testing.expectEqual(@as(i64, -42), (try config.getInteger("NEGATIVE")).?);
    try std.testing.expectEqual(@as(u64, 255), (try config.getHex("ADDRESS")).?);
    try std.testing.expectEqual(@as(u64, 0x40000000), (try config.getHex("DIGIT_HEX")).?);
    try std.testing.expectEqual(@as(u64, 0xdead), (try config.getHex("BARE_HEX")).?);
    try std.testing.expect(config.get("UNKNOWN_SYMBOL") != null);
    try std.testing.expect(config.get("UNKNOWN_PREFIXED") != null);

    const header = try config.headerAlloc(allocator);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        \\#define CONFIG_BOOL 1
        \\#define CONFIG_MODULE_MODULE 1
        \\#define CONFIG_TEXT "quote: \" slash: \\ dropped: q"
        \\#define CONFIG_NEGATIVE -0042
        \\#define CONFIG_ADDRESS 0X00ff
        \\#define CONFIG_DIGIT_HEX 0x40000000
        \\#define CONFIG_BARE_HEX 0xdeAd
        \\#define CONFIG_UNKNOWN_SYMBOL 7
        \\
    , header);
}

test "digit-only numeric values require authoritative type metadata" {
    const allocator = std.testing.allocator;
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "CONFIG_ADDRESS=40000000\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.ambiguous_numeric, diagnostic.kind);

    var metadata = Metadata.init(allocator);
    defer metadata.deinit();
    try metadata.addSymbol("ADDRESS", .hex);
    try metadata.addSymbol("COUNT", .integer);
    var config = try parseWithMetadata(
        allocator,
        "CONFIG_ADDRESS=40000000\nCONFIG_COUNT=40000000\n",
        &metadata,
        &diagnostic,
    );
    defer config.deinit();
    try std.testing.expectEqual(@as(u64, 0x40000000), (try config.getHex("ADDRESS")).?);
    try std.testing.expectEqual(@as(i64, 40000000), (try config.getInteger("COUNT")).?);

    try std.testing.expectError(
        error.InvalidConfig,
        parseWithMetadata(
            allocator,
            "CONFIG_ADDRESS=-1\n",
            &metadata,
            &diagnostic,
        ),
    );
    try std.testing.expectEqual(Diagnostic.Kind.type_mismatch, diagnostic.kind);
}

test "metadata rejects duplicate and conflicting platform mappings" {
    const allocator = std.testing.allocator;
    var metadata = Metadata.init(allocator);
    defer metadata.deinit();
    try metadata.addPlatform("PLAT_ACME", "acme");
    try std.testing.expectError(
        error.DuplicateMetadata,
        metadata.addPlatform("PLAT_ACME", "acme"),
    );
    try std.testing.expectError(
        error.ConflictingMetadata,
        metadata.addPlatform("PLAT_ACME", "other"),
    );
    try std.testing.expectError(
        error.ConflictingMetadata,
        metadata.addPlatform("PLAT_OTHER", "acme"),
    );
}

test "duplicates and conflicts have source diagnostics" {
    const allocator = std.testing.allocator;
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "CONFIG_A=y\nCONFIG_A=y\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.duplicate_entry, diagnostic.kind);
    try std.testing.expectEqual(@as(usize, 2), diagnostic.line);
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.previous_line);

    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "# CONFIG_A is not set\nCONFIG_A=y\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.conflicting_entry, diagnostic.kind);
}

test "malformed syntax is rejected" {
    const allocator = std.testing.allocator;
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "CONFIG_TEXT=\"unterminated\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.malformed_string, diagnostic.kind);

    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "CONFIG_TEXT=\"dangling\\\"\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.malformed_string, diagnostic.kind);

    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "CONFIG_NUMBER=12x\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.invalid_value, diagnostic.kind);

    try std.testing.expectError(
        error.InvalidConfig,
        parse(allocator, "CONFIG_BAD-NAME=y\n", &diagnostic),
    );
    try std.testing.expectEqual(Diagnostic.Kind.invalid_symbol, diagnostic.kind);

    var comments = try parse(
        allocator,
        "  # ordinary Kconfig comment\nCONFIG_lowercase=y\n",
        &diagnostic,
    );
    defer comments.deinit();
    try std.testing.expect(comments.enabled("lowercase"));
}

test "target derivation matches Make architecture and platform names" {
    const allocator = std.testing.allocator;
    var parse_diagnostic: Diagnostic = .{};
    var validation_diagnostic: ValidationDiagnostic = .{};
    var config = try parse(
        allocator,
        "CONFIG_ARCH_ARM_64=y\nCONFIG_PLAT_KVM=y\nCONFIG_HAVE_BOOTENTRY=y\n",
        &parse_diagnostic,
    );
    defer config.deinit();
    const target = try deriveTarget(&config, &validation_diagnostic);
    try std.testing.expectEqualStrings("arm64", target.architecture.name);
    try std.testing.expectEqualStrings("arm", target.architecture.family);
    try std.testing.expectEqualStrings("kvm", target.platform.name);
}

test "callers can supply external platform symbols and Make names" {
    const allocator = std.testing.allocator;
    var parse_diagnostic: Diagnostic = .{};
    var validation_diagnostic: ValidationDiagnostic = .{};
    var config = try parse(
        allocator,
        "CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_ACME=y\nCONFIG_HAVE_BOOTENTRY=y\n",
        &parse_diagnostic,
    );
    defer config.deinit();
    const platforms = [_]Platform{
        builtin_platforms[0],
        builtin_platforms[1],
        .{ .symbol = "PLAT_ACME", .name = "acme" },
    };
    const target = try deriveTargetWithPlatforms(
        &config,
        &platforms,
        &validation_diagnostic,
    );
    try std.testing.expectEqualStrings("acme", target.platform.name);
}
