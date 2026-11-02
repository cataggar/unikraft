const std = @import("std");

pub fn main(init: std.process.Init) void {
    std.Io.File.stderr().writeStreamingAll(init.io, "{\"error\":\"operator-guard-engine-and-authority-binding-required\"}\n") catch std.process.exit(3);
    std.process.exit(2);
}
