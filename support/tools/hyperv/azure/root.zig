pub const secret = @import("secret.zig");
pub const scope = @import("scope.zig");
pub const transport = @import("transport.zig");
pub const auth = @import("auth.zig");
pub const operations = @import("operations.zig");
pub const models = @import("models.zig");
pub const client = @import("client.zig");
pub const admission = @import("admission.zig");

test {
    _ = @import("tests.zig");
    _ = @import("wire_tests.zig");
}
