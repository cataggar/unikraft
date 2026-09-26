// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const process = @import("hyperv_core").process;
const inputs = @import("input_custody.zig");
const profile = @import("profile.zig");

pub const Stage = enum {
    adapter,
    @"local-boot-tool",
    fixtures,
    prepare,
    config,
    @"native-image",
    package,
    @"raw-x2apic",
    @"raw-legacy-apic",
    @"finalize-qcow2",
    @"qcow2-x2apic",
    @"qcow2-legacy-apic",
    @"derive-fixed-vhd",
    @"vpc-x2apic",
    @"vpc-legacy-apic",
    inspect,
    @"log-validator-x2apic",
    @"log-validator-legacy",
};

pub const Binding = union(enum) {
    literal: []const u8,
    path: struct { role: []const u8, relative: []const u8 = "" },
};

pub const Spec = struct {
    stage: Stage,
    executable: []const u8,
    seconds: u32,
    output_limit: usize,
    argv: []const Binding,
};

const zig = Binding{ .path = .{ .role = "tool:zig" } };
const producer = Binding{ .path = .{ .role = "native:wamr-aot-build" } };
const fixtures = Binding{ .path = .{ .role = "native:wamr-native-ci-fixtures" } };
const source = Binding{ .path = .{ .role = "source" } };
const package_tool = Binding{ .path = .{ .role = "input:package_tool" } };
const boot_tool = Binding{ .path = .{ .role = "input:local_boot_tool" } };
const validator = Binding{ .path = .{ .role = "native:wamr-log-validate" } };
const marker = "WAMR_NATIVE_AOT_OK answer=42 teardown=0";
const legacy_marker = "Using legacy xAPIC MMIO";
const forbidden = [_][]const u8{
    "HYPERV_ACCEPTANCE", "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_PLATFORM_READY", "WAMR_NATIVE_WASI=", "WAMR_NATIVE_AOT_FAIL",
};

pub fn modeStage(mode: profile.Mode) Stage {
    return switch (mode) {
        .@"raw-x2apic" => .@"raw-x2apic",
        .@"raw-legacy-apic" => .@"raw-legacy-apic",
        .@"qcow2-x2apic" => .@"qcow2-x2apic",
        .@"qcow2-legacy-apic" => .@"qcow2-legacy-apic",
        .@"vpc-x2apic" => .@"vpc-x2apic",
        .@"vpc-legacy-apic" => .@"vpc-legacy-apic",
    };
}

pub fn bootImage(mode: profile.Mode) []const u8 {
    return switch (mode) {
        .@"raw-x2apic", .@"raw-legacy-apic" => "unikraft.raw",
        .@"qcow2-x2apic", .@"qcow2-legacy-apic" => "unikraft.qcow2",
        .@"vpc-x2apic", .@"vpc-legacy-apic" => "unikraft-derived.vhd",
    };
}

fn bootArgv(comptime mode: profile.Mode) []const Binding {
    const source_flag = switch (mode) {
        .@"raw-x2apic", .@"raw-legacy-apic" => "--raw-disk",
        .@"qcow2-x2apic", .@"qcow2-legacy-apic" => "--qcow2",
        .@"vpc-x2apic", .@"vpc-legacy-apic" => "--fixed-vhd",
    };
    const start = [_]Binding{
        boot_tool, .{ .literal = source_flag },
        .{ .path = .{ .role = "work", .relative = "package/" ++ comptime bootImage(mode) } },
        .{ .literal = "--qemu" }, .{ .path = .{ .role = "input:qemu" } },
        .{ .literal = "--ovmf-code" }, .{ .path = .{ .role = "input:ovmf_code" } },
        .{ .literal = "--ovmf-vars" }, .{ .path = .{ .role = "input:ovmf_vars" } },
        .{ .literal = "--work-dir" }, .{ .path = .{ .role = "work", .relative = "boot-" ++ @tagName(mode) } },
        .{ .literal = "--expect" }, .{ .literal = marker },
        .{ .literal = "--expect-main-return" }, .{ .literal = "0" },
        .{ .literal = "--cpus" }, .{ .literal = "1" },
        .{ .literal = "--timeout" }, .{ .literal = "60" },
    };
    const no_hardware = comptime blk: {
        var values: [forbidden.len * 2]Binding = undefined;
        for (forbidden, 0..) |item, i| {
            values[i * 2] = .{ .literal = "--forbid-marker" };
            values[i * 2 + 1] = .{ .literal = item };
        }
        break :blk values;
    };
    return if (comptime mode.legacyApic())
        &(start ++ [_]Binding{
            .{ .literal = "--disable-x2apic" }, .{ .literal = "--require-marker" },
            .{ .literal = legacy_marker },
        } ++ no_hardware)
    else
        &(start ++ no_hardware ++ [_]Binding{
            .{ .literal = "--forbid-marker" }, .{ .literal = legacy_marker },
        });
}

pub fn isBoot(stage: Stage) bool {
    return switch (stage) {
        .package, .@"raw-x2apic", .@"raw-legacy-apic", .@"finalize-qcow2",
        .@"qcow2-x2apic", .@"qcow2-legacy-apic", .@"derive-fixed-vhd",
        .@"vpc-x2apic", .@"vpc-legacy-apic", .inspect => true,
        else => false,
    };
}

pub fn isValidator(stage: Stage) bool {
    return stage == .@"log-validator-x2apic" or stage == .@"log-validator-legacy";
}

pub fn spec(stage: Stage) Spec {
    return switch (stage) {
        .adapter => .{ .stage = stage, .executable = "tool:zig", .seconds = 900, .output_limit = 8 * 1024 * 1024, .argv = &.{
            zig,                                                                                      .{ .literal = "build" },                               .{ .literal = "--build-file" },
            .{ .path = .{ .role = "source", .relative = "support/build/wamr-native-ci/build.zig" } }, .{ .literal = "--system" },                            .{ .path = .{ .role = "work", .relative = "dependencies/zig-pkg" } },
            .{ .literal = "--prefix" },                                                               .{ .path = .{ .role = "work", .relative = "tools" } }, .{ .literal = "-Doptimize=ReleaseSafe" },
            .{ .literal = "-j2" },                                                                    .{ .literal = "test-unit" },                           .{ .literal = "install" },
        } },
        .@"local-boot-tool" => .{ .stage = stage, .executable = "tool:zig", .seconds = 900, .output_limit = 8 * 1024 * 1024, .argv = &.{
            zig,                                                                                         .{ .literal = "build" },                                          .{ .literal = "--build-file" },
            .{ .path = .{ .role = "source", .relative = "support/tools/hyperv/local_boot/build.zig" } }, .{ .literal = "--system" },                                       .{ .path = .{ .role = "work", .relative = "dependencies/zig-pkg" } },
            .{ .literal = "--prefix" },                                                                  .{ .path = .{ .role = "work", .relative = "local-boot-tools" } }, .{ .literal = "-Doptimize=ReleaseSafe" },
            .{ .literal = "-j2" },                                                                       .{ .literal = "install" },
        } },
        .fixtures => .{ .stage = stage, .executable = "native:wamr-native-ci-fixtures", .seconds = 600, .output_limit = 8 * 1024 * 1024, .argv = &.{
            fixtures, .{ .literal = "--fixture-root" }, .{ .path = .{ .role = "work", .relative = "fixtures" } },
        } },
        .prepare => .{ .stage = stage, .executable = "native:wamr-aot-build", .seconds = 1800, .output_limit = 8 * 1024 * 1024, .argv = &.{
            producer,                           .{ .literal = "prepare" },                                                  .{ .literal = "--repository" }, source,
            .{ .literal = "--source-archive" }, .{ .path = .{ .role = "runtime", .relative = "custody/wamr-source.tar" } },
        } },
        .config => .{ .stage = stage, .executable = "native:wamr-aot-build", .seconds = 600, .output_limit = 8 * 1024 * 1024, .argv = &.{
            producer, .{ .literal = "olddefconfig" }, .{ .literal = "--repository" }, source,
        } },
        .@"native-image" => .{ .stage = stage, .executable = "native:wamr-aot-build", .seconds = 1800, .output_limit = 8 * 1024 * 1024, .argv = &.{
            producer, .{ .literal = "native-images" }, .{ .literal = "--repository" }, source,
        } },
        .package => packageSpec(.package),
        .inspect => packageSpec(.inspect),
        .@"finalize-qcow2" => packageSpec(.@"finalize-qcow2"),
        .@"derive-fixed-vhd" => packageSpec(.@"derive-fixed-vhd"),
        .@"raw-x2apic" => bootSpec(stage, .@"raw-x2apic"),
        .@"raw-legacy-apic" => bootSpec(stage, .@"raw-legacy-apic"),
        .@"qcow2-x2apic" => bootSpec(stage, .@"qcow2-x2apic"),
        .@"qcow2-legacy-apic" => bootSpec(stage, .@"qcow2-legacy-apic"),
        .@"vpc-x2apic" => bootSpec(stage, .@"vpc-x2apic"),
        .@"vpc-legacy-apic" => bootSpec(stage, .@"vpc-legacy-apic"),
        .@"log-validator-x2apic" => validatorSpec(.@"log-validator-x2apic"),
        .@"log-validator-legacy" => validatorSpec(.@"log-validator-legacy"),
    };
}

fn packageSpec(comptime stage: Stage) Spec {
    const verb = switch (stage) {
        .package => "package", .inspect => "inspect",
        .@"finalize-qcow2" => "finalize-qcow2",
        .@"derive-fixed-vhd" => "derive-fixed-vhd",
        else => @compileError("invalid package stage"),
    };
    const input = switch (stage) {
        .package, .inspect => Binding{ .path = .{ .role = "input:efi" } },
        .@"finalize-qcow2" => Binding{ .path = .{ .role = "work", .relative = "evidence/qcow2-finalization-intent.json" } },
        .@"derive-fixed-vhd" => Binding{ .path = .{ .role = "work", .relative = "evidence/fixed-vhd-derivation-intent.json" } },
        else => unreachable,
    };
    return .{ .stage = stage, .executable = "input:package_tool", .seconds = 150,
        .output_limit = 64 * 1024,
        .argv = &.{ package_tool, .{ .literal = verb }, input,
            .{ .path = .{ .role = "work", .relative = "package" } } },
    };
}

fn validatorSpec(comptime stage: Stage) Spec {
    return .{
        .stage = stage, .executable = "native:wamr-log-validate",
        .seconds = 30, .output_limit = 64 * 1024,
        .argv = &.{ validator, .{ .literal = "tiny" },
            .{ .literal = "--log" }, .{ .path = .{ .role = "input:serial" } },
            .{ .literal = "--identity" }, .{ .path = .{ .role = "input:identity" } },
            .{ .literal = "--legacy-apic" }, .{ .literal = if (stage == .@"log-validator-legacy") "required" else "forbidden" },
            .{ .literal = "--output" }, .{ .literal = "json-v1" },
        },
    };
}

fn bootSpec(stage: Stage, comptime mode: profile.Mode) Spec {
    return .{ .stage = stage, .executable = "input:local_boot_tool", .seconds = 90, .output_limit = 64 * 1024, .argv = bootArgv(mode) };
}

pub fn limits(plan: Spec) process.CommandLimits {
    return .{
        .stdout_bytes = if (isValidator(plan.stage)) 64 * 1024 else @min(plan.output_limit + 1, 4 * 1024 * 1024),
        .stderr_bytes = if (isValidator(plan.stage)) 4 * 1024 else @min(plan.output_limit + 1, 4 * 1024 * 1024),
        .term_grace_ms = 1000,
    };
}

pub fn path(allocator: std.mem.Allocator, binding: Binding, roots: Roots) ![]const u8 {
    return switch (binding) {
        .literal => |value| allocator.dupe(u8, value),
        .path => |value| blk: {
            const root = try roots.get(value.role);
            if (value.relative.len == 0) break :blk allocator.dupe(u8, root);
            try @import("custody_limits.zig").relative(value.relative, 4096, 64);
            break :blk std.fs.path.join(allocator, &.{ root, value.relative });
        },
    };
}

pub const Roots = struct {
    source_root: []const u8,
    work: []const u8,
    runtime: []const u8,
    zig: []const u8,
    producer: []const u8,
    fixture_runner: []const u8,
    supervisor: []const u8,
    package_tool: []const u8,
    validator: []const u8,
    supervisor_fixture: []const u8,
    efi: []const u8 = "",
    local_boot_tool: []const u8 = "",
    qemu: []const u8 = "",
    ovmf_code: []const u8 = "",
    ovmf_vars: []const u8 = "",
    serial: []const u8 = "",
    identity: []const u8 = "",
    tools: [inputs.host_tools.len][]const u8,

    pub fn get(self: Roots, role: []const u8) ![]const u8 {
        if (std.mem.eql(u8, role, "source")) return self.source_root;
        if (std.mem.eql(u8, role, "work")) return self.work;
        if (std.mem.eql(u8, role, "runtime")) return self.runtime;
        if (std.mem.eql(u8, role, "tool:zig")) return self.zig;
        if (std.mem.eql(u8, role, "tool-tree:zig")) return std.fs.path.dirname(self.zig) orelse error.UnboundCommandRole;
        if (std.mem.eql(u8, role, "command-supervisor")) return self.supervisor;
        if (std.mem.eql(u8, role, "native:wamr-aot-build")) return self.producer;
        if (std.mem.eql(u8, role, "native:wamr-native-ci-fixtures")) return self.fixture_runner;
        if (std.mem.eql(u8, role, "native:wamr-log-validate")) return self.validator;
        if (std.mem.eql(u8, role, "native:wamr-ci-package")) return self.package_tool;
        if (std.mem.eql(u8, role, "native:wamr-ci-supervisor-fixture")) return self.supervisor_fixture;
        if (std.mem.eql(u8, role, "input:efi") and self.efi.len != 0) return self.efi;
        if (std.mem.eql(u8, role, "input:package_tool")) return self.package_tool;
        if (std.mem.eql(u8, role, "input:local_boot_tool") and self.local_boot_tool.len != 0) return self.local_boot_tool;
        if (std.mem.eql(u8, role, "input:qemu") and self.qemu.len != 0) return self.qemu;
        if (std.mem.eql(u8, role, "input:ovmf_code") and self.ovmf_code.len != 0) return self.ovmf_code;
        if (std.mem.eql(u8, role, "input:ovmf_vars") and self.ovmf_vars.len != 0) return self.ovmf_vars;
        if (std.mem.eql(u8, role, "input:serial") and self.serial.len != 0) return self.serial;
        if (std.mem.eql(u8, role, "input:identity") and self.identity.len != 0) return self.identity;
        if (std.mem.startsWith(u8, role, "tool:")) {
            for (inputs.host_tools, self.tools) |name, value|
                if (std.mem.eql(u8, role["tool:".len..], name)) return value;
        }
        return error.UnboundCommandRole;
    }
};

pub const EnvironmentBinding = struct {
    name: []const u8,
    value: Binding,
};

fn envLess(_: void, left: EnvironmentBinding, right: EnvironmentBinding) bool {
    return std.mem.lessThan(u8, left.name, right.name);
}

pub fn environment(allocator: std.mem.Allocator, stage: Stage) ![]EnvironmentBinding {
    var bindings: std.ArrayList(EnvironmentBinding) = .empty;
    errdefer bindings.deinit(allocator);
    if (isValidator(stage)) return bindings.toOwnedSlice(allocator);
    const build = !isBoot(stage);
    try bindings.appendSlice(allocator, &.{
        .{ .name = "HOME", .value = .{ .path = .{ .role = "work", .relative = "private" } } },
        .{ .name = "LANG", .value = .{ .literal = "C" } },
        .{ .name = "LC_ALL", .value = .{ .literal = "C" } },
        .{ .name = "PATH", .value = .{ .literal = "/usr/bin:/bin" } },
        .{ .name = "PYTHONDONTWRITEBYTECODE", .value = .{ .literal = "1" } },
        .{ .name = "TMPDIR", .value = .{ .path = .{ .role = "work", .relative = if (build) "scratch" else "private" } } },
        .{ .name = "WAMR_CI_GIT", .value = .{ .path = .{ .role = "tool:git" } } },
        .{ .name = "WAMR_CI_SUPERVISOR", .value = .{ .path = .{ .role = "command-supervisor" } } },
    });
    if (build) try bindings.appendSlice(allocator, &.{
        .{ .name = "BISON_PKGDATADIR", .value = .{ .path = .{ .role = "runtime", .relative = "bison" } } },
        .{ .name = "KCONFIG_CONFIG", .value = .{ .path = .{ .role = "source", .relative = "support/apps/wamr-aot/build/.config" } } },
        .{ .name = "KCONFIG_OVERWRITECONFIG", .value = .{ .literal = "1" } },
        .{ .name = "M4", .value = .{ .path = .{ .role = "tool:m4" } } },
        .{ .name = "MAKEFLAGS", .value = .{ .literal = "-j2" } },
        .{ .name = "WAMR_CI_PORTABLE_CONFIG", .value = .{ .literal = "1" } },
        .{ .name = "ZIG_GLOBAL_CACHE_DIR", .value = .{ .path = .{ .role = "work", .relative = "global-cache" } } },
        .{ .name = "ZIG_LIB_DIR", .value = .{ .path = .{ .role = "tool-tree:zig", .relative = "lib" } } },
        .{ .name = "ZIG_LOCAL_CACHE_DIR", .value = .{ .path = .{ .role = "work", .relative = "cache" } } },
    });
    if (stage == .adapter or stage == .@"local-boot-tool")
        try bindings.append(allocator, .{ .name = "WAMR_CI_LAUNCH_EXECUTABLE", .value = zig });
    if (stage == .fixtures)
        try bindings.appendSlice(allocator, &.{
            .{ .name = "WAMR_CI_PACKAGE", .value = .{ .path = .{ .role = "work", .relative = "tools/bin/wamr-ci-package" } } },
            .{ .name = "WAMR_CI_PYTHON", .value = .{ .path = .{ .role = "tool:python3" } } },
            .{ .name = "WAMR_CI_LOG_VALIDATE", .value = .{ .path = .{ .role = "native:wamr-log-validate" } } },
            .{ .name = "WAMR_CI_SUPERVISOR_FIXTURE", .value = .{ .path = .{ .role = "work", .relative = "tools/bin/wamr-ci-supervisor-fixture" } } },
        });
    for (inputs.host_tools) |name| {
        const env_name = try std.fmt.allocPrint(allocator, "WAMR_CI_TOOL_{s}", .{name});
        for (env_name["WAMR_CI_TOOL_".len..]) |*letter|
            letter.* = if (letter.* == '-') '_' else std.ascii.toUpper(letter.*);
        const env_role = try std.fmt.allocPrint(allocator, "tool:{s}", .{name});
        defer allocator.free(env_role);
        const owned_role = try allocator.dupe(u8, env_role);
        try bindings.append(allocator, .{ .name = env_name, .value = .{ .path = .{ .role = owned_role } } });
    }
    std.mem.sort(EnvironmentBinding, bindings.items, {}, envLess);
    return bindings.toOwnedSlice(allocator);
}

pub fn freeEnvironment(allocator: std.mem.Allocator, bindings: []EnvironmentBinding) void {
    for (bindings) |binding| {
        if (!std.mem.startsWith(u8, binding.name, "WAMR_CI_TOOL_")) continue;
        allocator.free(binding.name);
        allocator.free(binding.value.path.role);
    }
    allocator.free(bindings);
}
