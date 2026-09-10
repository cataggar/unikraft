pub const diagnostic = @import("diagnostic.zig");
pub const files = @import("files.zig");
pub const request = @import("request.zig");
pub const client = @import("client.zig");
pub const Client = client.Client;
pub const Budget = client.Budget;
pub const NativeRuntime = client.NativeRuntime;
pub const Outcome = diagnostic.Outcome;

test {
    _ = @import("fixtures.zig");
    _ = diagnostic;
    _ = request;
}
