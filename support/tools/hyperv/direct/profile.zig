// SPDX-License-Identifier: BSD-3-Clause
//! Compile-time purpose selection, never a scope field or environment switch.
pub const compute = @hasDecl(@import("root"), "wamr_direct_compute");
pub const legacy_fixture = compute and @hasDecl(@import("root"), "wamr_legacy_compute_fixture");
pub const authorization = compute and !legacy_fixture;
pub const contract = if (compute) @import("compute.zig") else @import("main.zig");
pub const roles = if (compute) .{.os} else .{ .os, .data };
pub const artifacts = if (authorization)
    .{ "os_vhd", "bundle", "candidate", "public_bundle", "transport", "qcow2", "plan", "authorization" }
else if (compute)
    .{ "os_vhd", "bundle" }
else
    .{ "os_vhd", "seed_raw", "seed_vhd", "manifest", "config" };
pub const retained = if (compute) .{ "vm", "os", "power" } else .{ "vm", "os", "data", "power" };
