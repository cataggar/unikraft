// SPDX-License-Identifier: BSD-3-Clause
pub const Entry = struct {
    name: []const u8,
    content: []const u8,
};

// Compiled-in tracked source inputs; additions to the controller's import
// graph must be added here before they can be admitted as its source closure.
pub const previous_entries = [_]Entry{
    .{ .name = "support/apps/wamr-aot/validator/base64.zig", .content = @embedFile("apps/wamr-aot/validator/base64.zig") },
    .{ .name = "support/apps/wamr-aot/validator/coremark.zig", .content = @embedFile("apps/wamr-aot/validator/coremark.zig") },
    .{ .name = "support/apps/wamr-aot/validator/input.zig", .content = @embedFile("apps/wamr-aot/validator/input.zig") },
    .{ .name = "support/apps/wamr-aot/validator/optional.zig", .content = @embedFile("apps/wamr-aot/validator/optional.zig") },
    .{ .name = "support/apps/wamr-aot/validator/records.zig", .content = @embedFile("apps/wamr-aot/validator/records.zig") },
    .{ .name = "support/apps/wamr-aot/validator/root.zig", .content = @embedFile("apps/wamr-aot/validator/root.zig") },
    .{ .name = "support/apps/wamr-aot/validator/sampler.zig", .content = @embedFile("apps/wamr-aot/validator/sampler.zig") },
    .{ .name = "support/apps/wamr-aot/validator/tiny.zig", .content = @embedFile("apps/wamr-aot/validator/tiny.zig") },
    .{ .name = "support/build/wamr-native-ci/build.zig", .content = @embedFile("build/wamr-native-ci/build.zig") },
    .{ .name = "support/build/wamr-native-ci/build.zig.zon", .content = @embedFile("build/wamr-native-ci/build.zig.zon") },
    .{ .name = "support/build/wamr-native-ci/controller/accepted_run.zig", .content = @embedFile("build/wamr-native-ci/controller/accepted_run.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/boot_pipeline.zig", .content = @embedFile("build/wamr-native-ci/controller/boot_pipeline.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/build_pipeline.zig", .content = @embedFile("build/wamr-native-ci/controller/build_pipeline.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/cli.zig", .content = @embedFile("build/wamr-native-ci/controller/cli.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/command_adapter.zig", .content = @embedFile("build/wamr-native-ci/controller/command_adapter.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/command_plan.zig", .content = @embedFile("build/wamr-native-ci/controller/command_plan.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/command_validation.zig", .content = @embedFile("build/wamr-native-ci/controller/command_validation.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/custody_files.zig", .content = @embedFile("build/wamr-native-ci/controller/custody_files.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/custody_limits.zig", .content = @embedFile("build/wamr-native-ci/controller/custody_limits.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/dependency_custody.zig", .content = @embedFile("build/wamr-native-ci/controller/dependency_custody.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/fixture_contract.zig", .content = @embedFile("build/wamr-native-ci/controller/fixture_contract.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/fixture_runner.zig", .content = @embedFile("build/wamr-native-ci/controller/fixture_runner.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/handoff_inspect.zig", .content = @embedFile("build/wamr-native-ci/controller/handoff_inspect.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/import_supervisor_identity.zig", .content = @embedFile("build/wamr-native-ci/controller/import_supervisor_identity.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/import_validator_build.zig", .content = @embedFile("build/wamr-native-ci/controller/import_validator_build.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/input_custody.zig", .content = @embedFile("build/wamr-native-ci/controller/input_custody.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/install.zig", .content = @embedFile("build/wamr-native-ci/controller/install.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/install_target_tests.zig", .content = @embedFile("build/wamr-native-ci/controller/install_target_tests.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/layout.zig", .content = @embedFile("build/wamr-native-ci/controller/layout.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/local_consumer_custody.zig", .content = @embedFile("build/wamr-native-ci/controller/local_consumer_custody.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/main.zig", .content = @embedFile("build/wamr-native-ci/controller/main.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/portable_main.zig", .content = @embedFile("build/wamr-native-ci/controller/portable_main.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/profile.zig", .content = @embedFile("build/wamr-native-ci/controller/profile.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/public_image_serial.zig", .content = @embedFile("build/wamr-native-ci/controller/public_image_serial.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/public_validator_build.zig", .content = @embedFile("build/wamr-native-ci/controller/public_validator_build.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/records.zig", .content = @embedFile("build/wamr-native-ci/controller/records.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/root.zig", .content = @embedFile("build/wamr-native-ci/controller/root.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/source_custody.zig", .content = @embedFile("build/wamr-native-ci/controller/source_custody.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/target.zig", .content = @embedFile("build/wamr-native-ci/controller/target.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/test_command.zig", .content = @embedFile("build/wamr-native-ci/controller/test_command.zig") },
    .{ .name = "support/build/wamr-native-ci/controller/tests.zig", .content = @embedFile("build/wamr-native-ci/controller/tests.zig") },
    .{ .name = "support/controller_source_closure.zig", .content = @embedFile("controller_source_closure.zig") },
    .{ .name = "support/tools/hyperv/contracts.zig", .content = @embedFile("tools/hyperv/contracts.zig") },
    .{ .name = "support/tools/hyperv/core.zig", .content = @embedFile("tools/hyperv/core.zig") },
    .{ .name = "support/tools/hyperv/diagnostics.zig", .content = @embedFile("tools/hyperv/diagnostics.zig") },
    .{ .name = "support/tools/hyperv/local_boot/serial.zig", .content = @embedFile("tools/hyperv/local_boot/serial.zig") },
    .{ .name = "support/tools/hyperv/private_files.zig", .content = @embedFile("tools/hyperv/private_files.zig") },
    .{ .name = "support/tools/hyperv/process-command-v1.json", .content = @embedFile("tools/hyperv/process-command-v1.json") },
    .{ .name = "support/tools/hyperv/process.zig", .content = @embedFile("tools/hyperv/process.zig") },
    .{ .name = "support/tools/hyperv/sensitive.zig", .content = @embedFile("tools/hyperv/sensitive.zig") },
    .{ .name = "support/tools/hyperv/sha256.zig", .content = @embedFile("tools/hyperv/sha256.zig") },
    .{ .name = "support/tools/hyperv/sha256_clear_upper.S", .content = @embedFile("tools/hyperv/sha256_clear_upper.S") },
};

pub const previous_native_entries = blk: {
    @setEvalBranchQuota(100_000);
    var all = previous_entries ++ import_validator_entries;
    @import("std").mem.sort(Entry, &all, {}, struct {
        fn less(_: void, first: Entry, second: Entry) bool {
            return @import("std").mem.lessThan(u8, first.name, second.name);
        }
    }.less);
    break :blk all;
};

pub const entries = blk: {
    @setEvalBranchQuota(100_000);
    var all = previous_native_entries ++ private_consumer_entries;
    @import("std").mem.sort(Entry, &all, {}, struct {
        fn less(_: void, first: Entry, second: Entry) bool {
            return @import("std").mem.lessThan(u8, first.name, second.name);
        }
    }.less);
    break :blk all;
};

const private_consumer_entries = [_]Entry{
    .{ .name = "support/build/wamr-native-ci/handoff/contracts.zig", .content = @embedFile("build/wamr-native-ci/handoff/contracts.zig") },
    .{ .name = "support/build/wamr-native-ci/handoff/layout.zig", .content = @embedFile("build/wamr-native-ci/handoff/layout.zig") },
    .{ .name = "support/build/wamr-native-ci/handoff/profile.zig", .content = @embedFile("build/wamr-native-ci/handoff/profile.zig") },
};

const import_validator_entries = [_]Entry{
    .{ .name = "support/build/kconfig.zig", .content = @embedFile("build/kconfig.zig") },
    .{ .name = "support/tools/hyperv/direct/azure_runtime.zig", .content = @embedFile("tools/hyperv/direct/azure_runtime.zig") },
    .{ .name = "support/tools/hyperv/direct/build.zig", .content = @embedFile("tools/hyperv/direct/build.zig") },
    .{ .name = "support/tools/hyperv/direct/compute.zig", .content = @embedFile("tools/hyperv/direct/compute.zig") },
    .{ .name = "support/tools/hyperv/direct/compute_main.zig", .content = @embedFile("tools/hyperv/direct/compute_main.zig") },
    .{ .name = "support/tools/hyperv/direct/main.zig", .content = @embedFile("tools/hyperv/direct/main.zig") },
    .{ .name = "support/tools/hyperv/local_boot/config.zig", .content = @embedFile("tools/hyperv/local_boot/config.zig") },
    .{ .name = "support/tools/hyperv/persistence/contract.zig", .content = @embedFile("tools/hyperv/persistence/contract.zig") },
    .{ .name = "support/tools/hyperv/persistence/evidence.zig", .content = @embedFile("tools/hyperv/persistence/evidence.zig") },
    .{ .name = "support/tools/hyperv/persistence/local.zig", .content = @embedFile("tools/hyperv/persistence/local.zig") },
    .{ .name = "support/tools/hyperv/preparation/admission.zig", .content = @embedFile("tools/hyperv/preparation/admission.zig") },
    .{ .name = "support/tools/hyperv/preparation/budget.zig", .content = @embedFile("tools/hyperv/preparation/budget.zig") },
    .{ .name = "support/tools/hyperv/preparation/config.zig", .content = @embedFile("tools/hyperv/preparation/config.zig") },
    .{ .name = "support/tools/hyperv/preparation/contracts.zig", .content = @embedFile("tools/hyperv/preparation/contracts.zig") },
    .{ .name = "support/tools/hyperv/preparation/direct_config.zig", .content = @embedFile("tools/hyperv/preparation/direct_config.zig") },
    .{ .name = "support/tools/hyperv/preparation/environment.zig", .content = @embedFile("tools/hyperv/preparation/environment.zig") },
    .{ .name = "support/tools/hyperv/preparation/files.zig", .content = @embedFile("tools/hyperv/preparation/files.zig") },
    .{ .name = "support/tools/hyperv/preparation/git_entry.zig", .content = @embedFile("tools/hyperv/preparation/git_entry.zig") },
    .{ .name = "support/tools/hyperv/preparation/inputs.zig", .content = @embedFile("tools/hyperv/preparation/inputs.zig") },
    .{ .name = "support/tools/hyperv/preparation/namespace.zig", .content = @embedFile("tools/hyperv/preparation/namespace.zig") },
    .{ .name = "support/tools/hyperv/preparation/origin.zig", .content = @embedFile("tools/hyperv/preparation/origin.zig") },
    .{ .name = "support/tools/hyperv/preparation/origin_fixture.zig", .content = @embedFile("tools/hyperv/preparation/origin_fixture.zig") },
    .{ .name = "support/tools/hyperv/preparation/origin_tests.zig", .content = @embedFile("tools/hyperv/preparation/origin_tests.zig") },
    .{ .name = "support/tools/hyperv/preparation/original_seed.zig", .content = @embedFile("tools/hyperv/preparation/original_seed.zig") },
    .{ .name = "support/tools/hyperv/preparation/package.zig", .content = @embedFile("tools/hyperv/preparation/package.zig") },
    .{ .name = "support/tools/hyperv/preparation/producer.zig", .content = @embedFile("tools/hyperv/preparation/producer.zig") },
    .{ .name = "support/tools/hyperv/preparation/production_local.zig", .content = @embedFile("tools/hyperv/preparation/production_local.zig") },
    .{ .name = "support/tools/hyperv/preparation/provenance.zig", .content = @embedFile("tools/hyperv/preparation/provenance.zig") },
    .{ .name = "support/tools/hyperv/preparation/receipts.zig", .content = @embedFile("tools/hyperv/preparation/receipts.zig") },
    .{ .name = "support/tools/hyperv/preparation/root.zig", .content = @embedFile("tools/hyperv/preparation/root.zig") },
    .{ .name = "support/tools/hyperv/preparation/runtime.zig", .content = @embedFile("tools/hyperv/preparation/runtime.zig") },
    .{ .name = "support/tools/hyperv/preparation/seed.zig", .content = @embedFile("tools/hyperv/preparation/seed.zig") },
    .{ .name = "support/tools/hyperv/preparation/source.zig", .content = @embedFile("tools/hyperv/preparation/source.zig") },
    .{ .name = "support/tools/hyperv/preparation/tests.zig", .content = @embedFile("tools/hyperv/preparation/tests.zig") },
};
