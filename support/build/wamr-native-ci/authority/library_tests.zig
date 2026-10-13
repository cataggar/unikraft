// SPDX-License-Identifier: BSD-3-Clause
test {
    _ = @import("tests.zig");
    _ = @import("plan_tests.zig");
    _ = @import("authorization_tests.zig");
    _ = @import("admission_tests.zig");
    _ = @import("runtime_copy_tests.zig");
    _ = @import("runtime_probes_tests.zig");
    _ = @import("composition_tests.zig");
    _ = @import("composition_fault_tests.zig");
    _ = @import("composition_namespace_tests.zig");
    _ = @import("composition_helper_tests.zig");
}
