// SPDX-License-Identifier: BSD-3-Clause
//! Non-installed offline adapter. The state machine, parser, custody and real
//! child supervision are production code; only fixture references/env/hash vary.
const std = @import("std");
const controller = @import("controller.zig");
const custody = @import("custody.zig");
const runtime = @import("runtime.zig");
const direct = @import("profile.zig").contract;
const f = @import("lifecycle_fixture_support.zig");
const seams = @import("lifecycle_fixture_seams.zig");

const Offline = struct {
    context: f.Context,
    scenario: []const u8,
    validator: []const u8,

    pub const References = struct {
        tools: [3]custody.Reference,
        pub fn verify(self: References, io: std.Io) !void {
            for (self.tools) |tool| try tool.verify(io);
        }
    };

    pub fn references(self: Offline, io: std.Io, scope: direct.Scope, programs: runtime.Programs) !References {
        try self.context.validate();
        inline for (f.input_names) |entry| {
            const artifact = @field(scope, entry[0]);
            try f.expect(f.eq(artifact.path, try self.context.path(entry[1])) and f.eq(artifact.sha256, f.image_sha));
        }
        return .{ .tools = .{
            try custody.Reference.tool(io, programs.azure),
            try custody.Reference.tool(io, programs.uploader),
            try custody.Reference.tool(io, programs.validator),
        } };
    }

    pub fn environment(self: Offline, a: std.mem.Allocator, _: *const std.process.Environ.Map) !runtime.Environment {
        var operator = std.process.Environ.Map.init(a);
        defer operator.deinit();
        try operator.put("HOME", self.context.root);
        var env = try runtime.Environment.init(a, &operator);
        errdefer env.deinit();
        inline for (.{ "azure", "native" }) |name| {
            try @field(env, name).put("UK_DIRECT_FIXTURE_ROOT", self.context.root);
            try @field(env, name).put("UK_DIRECT_FIXTURE_VALIDATOR", self.validator);
        }
        return env;
    }

    pub fn checkHashFault(self: Offline, store: *custody.Store, name: []const u8) !u8 {
        const role: seams.HashRole = if (f.eq(name, "boot2-candidate.log")) .candidate else if (f.eq(name, "boot1.log")) .boot1 else if (f.eq(name, "boot1-capture.json")) .capture else if (f.eq(name, "scope.json")) .scope else if (f.eq(name, "boot2-admission.json")) .admission else .other;
        const state = try self.context.document("fake-cloud.json");
        const reads: u8 = if (state.object.get("boot2_reads")) |value| @intCast(try f.number(value)) else 0;
        var bytes = try store.directory.readSensitive(store.io, self.context.a, name, custody.cli_limit, null);
        defer bytes.deinit();
        return seams.hash(self.scenario, role, reads, bytes.bytes()).exit;
    }

    pub fn sleep(_: Offline, io: std.Io, milliseconds: u64) !void {
        try std.Io.sleep(io, .fromMilliseconds(@intCast(milliseconds)), .awake);
    }
};

pub fn main(init: std.process.Init) void {
    f.privateUmask();
    const status = run(init) catch |err| blk: {
        var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
        stderr.interface.print("offline controller refused: {s}\n", .{@errorName(err)}) catch {};
        break :blk @as(u8, 1);
    };
    std.process.exit(status);
}

fn run(init: std.process.Init) !u8 {
    try seams.selfCheck();
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    const inputs = try controller.Inputs.parse(args[1..]);
    const c: f.Context = .{ .a = a, .io = init.io, .root = init.environ_map.get("UK_DIRECT_FIXTURE_ROOT") orelse return error.NoFixtureRoot };
    try c.validate();
    for ([_][]const u8{ inputs.scope, inputs.attempt, inputs.ledger }) |path| try c.confined(path);
    try f.expect(f.eq(inputs.programs.azure, inputs.programs.uploader) and f.eq(inputs.programs.azure, inputs.programs.validator));
    try f.expect(f.eq(std.fs.path.basename(inputs.programs.azure), f.fake_name));
    const real_validator = init.environ_map.get("UK_DIRECT_FIXTURE_VALIDATOR") orelse return error.NoNativeValidator;
    try f.expect(f.eq(std.fs.path.basename(real_validator), f.validator_name));
    inline for (.{ inputs.programs.azure, real_validator }) |path| {
        const file = try f.files.openAbsolute(init.io, path, .artifact);
        defer file.close(init.io);
        var magic: [4]u8 = undefined;
        try f.expect(try file.readPositionalAll(init.io, &magic, 0) == 4 and f.eq(&magic, "\x7fELF"));
    }
    const scenario = std.mem.trimEnd(u8, try c.read("scenario"), "\n");
    return controller.execute(Offline, .{
        .context = c,
        .scenario = scenario,
        .validator = real_validator,
    }, init, inputs);
}
