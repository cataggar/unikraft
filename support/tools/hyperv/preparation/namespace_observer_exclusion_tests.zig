const std = @import("std");
const ns = @import("namespace.zig");
const rt = @import("runtime.zig");

test "production root compiles and refuses before IO without an observer dependency" {
    comptime {
        if (@hasDecl(@import("root"), "namespace_fixture_observer"))
            @compileError("Exclusion root must not select observation hooks");
    }
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sandbox = try @import("namespace/entry_refusal_fixture.zig").invalidAccount(a, std.testing.io);
    var environment = std.process.Environ.Map.init(a);
    defer environment.deinit();
    try std.testing.expectError(error.InvalidAccount, ns.enter(a, std.testing.io, sandbox, &.{"/unused"}, &environment));
    var bound: rt.Bound = sandbox.isolation.helper;
    var excess: [257]@import("contracts.zig").File = undefined;
    bound.contract.libraries = &excess;
    try std.testing.expectError(error.LimitExceeded, bound.validate(a, std.testing.io));
}
