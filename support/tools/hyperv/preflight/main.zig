const std = @import("std");

/// The public CLI/preparation resolver belongs to the integration lane. A worker
/// executable with no trusted resolver must never accept an "approved" JSON file.
pub fn main(init: std.process.Init) void {
    const message = "{\"error\":\"native-preparation-and-authority-binding-required\",\"schema\":\"uk-hyperv-preflight-unavailable-v1\"}\n";
    std.Io.File.stderr().writeStreamingAll(init.io, message) catch std.process.exit(3);
    std.process.exit(2);
}
