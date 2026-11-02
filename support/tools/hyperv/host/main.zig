const std = @import("std");
const host = @import("host");
const options = @import("image_options");

const trust_root: [32]u8 = key: {
    const text = options.image_trust_key orelse @compileError("Build an image-bound public key explicitly with -Dimage-trust-key; no runtime key option exists");
    if (text.len != 64) @compileError("image-trust-key must be 64 lowercase hexadecimal characters");
    for (text) |ch| if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) @compileError("image-trust-key must be lowercase hexadecimal");
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch @compileError("invalid image trust root");
    break :key bytes;
};

pub fn main(init: std.process.Init) void {
    dispatch(init) catch {
        var writer = std.Io.File.stderr().writer(init.io, &.{});
        writer.interface.writeAll("uk-hyperv-host: operation failed; inspect private outcomes\n") catch {};
        std.process.exit(2);
    };
}

fn dispatch(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidCommand;
    if (std.mem.eql(u8, args[1], "--help")) {
        var writer = std.Io.File.stdout().writer(init.io, &.{});
        try writer.interface.writeAll("uk-hyperv-host run\nImage-bound key and signed admission required. No credential, endpoint, key, or fixture argv options.\n");
    } else if (std.mem.eql(u8, args[1], "run")) {
        try host.native.run(init, trust_root);
    } else if (std.mem.eql(u8, args[1], "--wire-child")) {
        try host.native.wireChild(init, trust_root);
    } else if (std.mem.eql(u8, args[1], "--boot-child")) {
        try host.native.authorizeBootChild(init, trust_root);
        try host.boot.execChild(init);
    } else return error.InvalidCommand;
}
