// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const contracts = @import("contracts.zig");
const types = @import("types.zig");
pub const Command = types.Command;
pub const Action = std.meta.Tag(Command);
pub const Result = union(enum) { help: ?Action, command: Command };
pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    result: Result,
    pub fn deinit(self: *Parsed) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// argv excludes the executable. Scalar strings borrow argv; repeated arrays
/// belong to Parsed. Filesystem and authority policy checks belong to owners.
pub fn parse(allocator: std.mem.Allocator, argv: []const []const u8) !Parsed {
    if (argv.len == 0) return error.MissingCommand;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    if (help(argv[0])) {
        if (argv.len != 1) return error.UnexpectedArgument;
        return .{ .arena = arena, .result = .{ .help = null } };
    }
    const action = std.meta.stringToEnum(Action, argv[0]) orelse return error.UnknownCommand;
    inline for (std.meta.fields(Command)) |field| {
        if (action == @field(Action, field.name)) {
            var value: field.type = .{};
            const table = comptime options(@field(Action, field.name));
            var seen: [table.required.len + table.optional.len + table.repeated_required.len + table.repeated_optional.len]bool = @splat(false);
            var lists: [seen.len]std.ArrayList([]const u8) = @splat(.empty);
            var index: usize = 1;
            while (index < argv.len) {
                const argument = argv[index];
                if (help(argument)) {
                    if (index != argv.len - 1) return error.UnexpectedArgument;
                    return .{ .arena = arena, .result = .{ .help = action } };
                }
                const equal = std.mem.indexOfScalar(u8, argument, '=');
                const flag = if (equal) |at| argument[0..at] else argument;
                const flags = comptime table.required ++ table.optional ++ table.repeated_required ++ table.repeated_optional;
                var selected: ?usize = null;
                for (flags, 0..) |known, at| if (std.mem.eql(u8, known, flag)) {
                    selected = at;
                    break;
                };
                const at = selected orelse return error.UnknownOption;
                const repeated = at >= table.required.len + table.optional.len;
                if (seen[at] and !repeated) return error.DuplicateOption;
                const text = if (equal) |separator| argument[separator + 1 ..] else blk: {
                    index += 1;
                    if (index >= argv.len or std.mem.startsWith(u8, argv[index], "--") or help(argv[index]))
                        return error.MissingValue;
                    break :blk argv[index];
                };
                if (repeated) try lists[at].append(arena.allocator(), text);
                try assign(field.type, &value, flag, text, lists[at].items);
                seen[at] = true;
                index += 1;
            }
            for (seen[0..table.required.len]) |present| if (!present) return error.MissingOption;
            const start = table.required.len + table.optional.len;
            for (seen[start .. start + table.repeated_required.len]) |present| if (!present) return error.MissingOption;
            return .{ .arena = arena, .result = .{ .command = @unionInit(Command, field.name, value) } };
        }
    }
    unreachable;
}

const Options = struct {
    required: []const []const u8,
    optional: []const []const u8,
    repeated_required: []const []const u8,
    repeated_optional: []const []const u8,
};
fn options(comptime action: Action) Options {
    const c = contracts.cli;
    return switch (action) {
        .@"prepare-azure-runtime" => .{ .required = &c.prepare_required, .optional = &c.prepare_optional, .repeated_required = &c.prepare_repeated_required, .repeated_optional = &c.prepare_repeated_optional },
        .plan => .{ .required = &c.plan_required, .optional = &c.plan_optional, .repeated_required = &c.plan_repeated_required, .repeated_optional = &c.plan_repeated_optional },
        .@"record-authorization" => .{ .required = &c.authorize_required, .optional = &c.authorize_optional, .repeated_required = &c.authorize_repeated_required, .repeated_optional = &c.authorize_repeated_optional },
        .admit => .{ .required = &c.admit_required, .optional = &c.admit_optional, .repeated_required = &c.admit_repeated_required, .repeated_optional = &c.admit_repeated_optional },
    };
}
fn assign(comptime T: type, value: *T, flag: []const u8, text: []const u8, repeated: []const []const u8) !void {
    var buffer: [80]u8 = undefined;
    if (flag.len < 3 or flag.len - 2 > buffer.len) return error.UnknownOption;
    const name = buffer[0 .. flag.len - 2];
    for (flag[2..], name) |byte, *out| out.* = if (byte == '-') '_' else byte;
    inline for (std.meta.fields(T)) |field| {
        if (comptime std.mem.eql(u8, field.name, "tools")) {
            inline for (std.meta.fields(types.ToolPaths)) |tool| if (std.mem.eql(u8, name, tool.name)) {
                @field(value.tools, tool.name) = text;
                return;
            };
        } else if (std.mem.eql(u8, name, field.name)) {
            if (comptime field.type == []const []const u8) {
                if (repeated.len == 0) return error.InvalidOptionTable;
                @field(value, field.name) = repeated;
            } else if (comptime field.type == types.Integer or field.type == ?types.Integer) {
                @field(value, field.name) = std.fmt.parseInt(types.Integer, text, 10) catch return error.InvalidInteger;
            } else if (comptime field.type == types.Decision) {
                @field(value, field.name) = std.meta.stringToEnum(types.Decision, text) orelse return error.InvalidDecision;
            } else {
                @field(value, field.name) = text;
            }
            return;
        }
    }
    return error.InvalidOptionTable;
}
fn help(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}
