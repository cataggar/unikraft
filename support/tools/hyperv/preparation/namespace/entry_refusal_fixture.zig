const std = @import("std");
const ns = @import("../namespace.zig");
const env = @import("../environment.zig");
const c = @import("../contracts.zig");

pub fn invalidAccount(a: std.mem.Allocator, io: std.Io) !ns.Sandbox {
    var account = try env.Account.current(a, io);
    account.uid ^= 1;
    const directory = @import("../files.zig").Directory{ .dir = .{ .handle = -1 }, .path = "/unused" };
    const identity: ns.Identity = .{ .path = "/unused", .device = 0, .inode = 0, .mode = 0, .uid = 0 };
    return .{
        .repository = directory,
        .workspace = directory,
        .scratch = directory,
        .runtimes = &.{},
        .aliases = &.{},
        .root = identity,
        .isolation = .{
            .account = account,
            .helper = .{ .directory = directory, .contract = .{
                .role = .preparation,
                .origin = @import("../origin_fixture.zig").local(),
                .target = .data,
                .tree = .{ .sha256 = c.digest("unreachable synthetic runtime"), .files = 0, .bytes = 0 },
                .executable = null,
                .loader = null,
                .libraries = &.{},
            } },
            .git_metadata = &.{},
            .facade_runtime = directory,
            .facade_lock = identity,
            .environment = .{ .path = "unused", .sha256 = c.digest("unused"), .size = 1, .mode = 0o600 },
        },
    };
}
