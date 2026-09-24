// SPDX-License-Identifier: BSD-3-Clause
pub const Entry = struct {
    name: []const u8,
    content: []const u8,
};

// Compiled-in tracked source inputs; additions to the controller's import
// graph must be added here before they can be admitted as its source closure.
pub const entries = [_]Entry{
    .{ .name = "support/build/wamr-native-ci/build.zig", .content = @embedFile("build/wamr-native-ci/build.zig") },
    .{ .name = "support/build/wamr-native-ci/build.zig.zon", .content = @embedFile("build/wamr-native-ci/build.zig.zon") },
    .{ .name = "support/build/wamr-native-ci/controller/cli.zig", .content = @embedFile("build/wamr-native-ci/controller/cli.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/install.zig", .content = @embedFile("build/wamr-native-ci/controller/install.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/layout.zig", .content = @embedFile("build/wamr-native-ci/controller/layout.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/main.zig", .content = @embedFile("build/wamr-native-ci/controller/main.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/portable_main.zig", .content = @embedFile("build/wamr-native-ci/controller/portable_main.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/profile.zig", .content = @embedFile("build/wamr-native-ci/controller/profile.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/records.zig", .content = @embedFile("build/wamr-native-ci/controller/records.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/root.zig", .content = @embedFile("build/wamr-native-ci/controller/root.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/source_custody.zig", .content = @embedFile("build/wamr-native-ci/controller/source_custody.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/target.zig", .content = @embedFile("build/wamr-native-ci/controller/target.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/tests.zig", .content = @embedFile("build/wamr-native-ci/controller/tests.zig") },
    .{ .name = "support/controller_source_closure.zig", .content = @embedFile("controller_source_closure.zig") },
    .{ .name = "support/tools/hyperv/contracts.zig", .content = @embedFile("tools/hyperv/contracts.zig") },
    .{ .name = "support/tools/hyperv/core.zig", .content = @embedFile("tools/hyperv/core.zig") },
    .{ .name = "support/tools/hyperv/diagnostics.zig", .content = @embedFile("tools/hyperv/diagnostics.zig") },
    .{ .name = "support/tools/hyperv/private_files.zig", .content = @embedFile("tools/hyperv/private_files.zig") },
    .{ .name = "support/tools/hyperv/process-command-v1.json", .content = @embedFile("tools/hyperv/process-command-v1.json") },
    .{ .name = "support/tools/hyperv/process.zig", .content = @embedFile("tools/hyperv/process.zig") },
    .{ .name = "support/tools/hyperv/sensitive.zig", .content = @embedFile("tools/hyperv/sensitive.zig") },
    .{ .name = "support/tools/hyperv/sha256.zig", .content = @embedFile("tools/hyperv/sha256.zig") },
    .{ .name = "support/tools/hyperv/sha256_clear_upper.S", .content = @embedFile("tools/hyperv/sha256_clear_upper.S") },
};
