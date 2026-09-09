// SPDX-License-Identifier: BSD-3-Clause

//! Native link metadata for the documented hello-world image profiles.
//!
//! This module registers link inputs and transformations only. Compilation and
//! command execution remain separate concerns.

const std = @import("std");
const component = @import("component-api.zig");
const data = @import("native-image-data.zig");
const native_final_link = @import("final-link.zig");
const native_library_link = @import("native-library-link.zig");

pub const Profile = enum {
    @"qemu-x86_64",
    @"qemu-arm64",
    @"hyperv-x86_64-efi",
    @"hyperv-x86_64-efi-netvsc",
};

pub const Error = component.RegistrationError || component.ValidationError || error{
    OutOfMemory,
    UnsupportedConfiguration,
};

pub const Options = struct {
    roots: component.Roots,
    profile: Profile,
    enable_ukblkdev: bool = false,
    enable_storvsc: bool = false,
    enable_uklibparam: bool = false,
    enable_hyperv_acceptance: bool = false,
    enable_hyperv_persistence: bool = false,
    enable_lwip: bool = false,
    enable_ukrandom_lcpu: bool = false,
    lwip_root: ?[]const u8 = null,
};

pub fn parseProfile(name: []const u8) error{UnsupportedConfiguration}!Profile {
    return std.meta.stringToEnum(Profile, name) orelse error.UnsupportedConfiguration;
}

pub const RegisteredGraph = struct {
    context: component.BuildContext,
    graph: component.FinalizedGraph,
    profile: Profile,

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!RegisteredGraph {
        var scratch = std.heap.ArenaAllocator.init(allocator);
        defer scratch.deinit();

        const profile_data = switch (options.profile) {
            .@"qemu-x86_64" => data.x86_64,
            .@"qemu-arm64" => data.arm64,
            .@"hyperv-x86_64-efi",
            .@"hyperv-x86_64-efi-netvsc",
            => data.x86_64,
        };
        const target = targetFor(options.profile);
        var context = component.BuildContext.init(allocator, .{
            .roots = options.roots,
            .target = target,
            .toolchain = toolchainFor(target),
            .config = empty_config,
        }) catch return error.OutOfMemory;
        errdefer context.deinit();

        try registerLibraries(
            &context,
            scratch.allocator(),
            options,
            profile_data,
        );
        try registerPlatform(&context, scratch.allocator(), options, profile_data);
        const graph = try context.finalize();
        return .{
            .context = context,
            .graph = graph,
            .profile = options.profile,
        };
    }

    pub fn deinit(self: *RegisteredGraph) void {
        self.context.deinit();
        self.* = undefined;
    }
};

fn targetFor(profile: Profile) component.Target {
    return switch (profile) {
        .@"qemu-x86_64",
        .@"hyperv-x86_64-efi",
        .@"hyperv-x86_64-efi-netvsc",
        => .{
            .architecture = .x86_64,
            .family = .x86,
            .abi = "none",
            .triple = "x86_64-freestanding-none",
        },
        .@"qemu-arm64" => .{
            .architecture = .arm64,
            .family = .arm,
            .abi = "none",
            .triple = "aarch64-freestanding-none",
        },
    };
}

fn isHyperv(profile: Profile) bool {
    return profile == .@"hyperv-x86_64-efi" or
        profile == .@"hyperv-x86_64-efi-netvsc";
}

fn hasNetvsc(profile: Profile) bool {
    return profile == .@"hyperv-x86_64-efi-netvsc";
}

fn toolchainFor(target: component.Target) component.Toolchain {
    return .{
        .target_triple = target.triple,
        .compiler = .{
            .tool = .{ .command = "zig" },
            .kind = .zig_cc,
            .already_targets_triple = true,
        },
        .partial_linker = .{
            .tool = .{ .command = "zig cc" },
            .kind = .compiler_driver,
            .mode = .driver,
        },
        .final_linker = .{
            .tool = .{ .command = "zig cc" },
            .kind = .compiler_driver,
        },
        .binutils = .{
            .ar = .{ .command = "zig ar" },
            .objcopy = .{ .command = "llvm-objcopy" },
            .strip = .{ .command = "llvm-strip" },
            .nm = .{ .command = "llvm-nm" },
            .objdump = .{ .command = "llvm-objdump" },
        },
        .host = .{ .python = .{ .command = "python3" } },
        .capabilities = &.{ .response_files, .relocatable_link, .gc_sections, .build_id, .target_flag },
    };
}

fn registerLibraries(
    context: *component.BuildContext,
    allocator: std.mem.Allocator,
    options: Options,
    profile: data.Profile,
) Error!void {
    for (profile.libraries) |library| {
        if (isHyperv(options.profile) and
            std.mem.eql(u8, library.name, "libvgacons"))
        {
            continue;
        }
        if (isHyperv(options.profile) and
            std.mem.eql(u8, library.name, "libkvmplat"))
        {
            const source = try joinPath(
                allocator,
                options.roots.base,
                "plat/hyperv/hyperv_runtime.zig",
            );
            const output = try joinPath(
                allocator,
                options.roots.output,
                "libhypervplat/hyperv_runtime.o",
            );
            try registerLibrary(
                context,
                allocator,
                options,
                data.x86_64_efi_hyperv_platform,
                &.{.{
                    .name = "hyperv-runtime",
                    .root_source_file = source,
                    .output = output,
                    .optimize = .ReleaseFast,
                    .pic = true,
                    .isr = true,
                }},
            );
            continue;
        }
        if (hasNetvsc(options.profile) and options.enable_hyperv_acceptance and
            std.mem.eql(u8, library.name, "apphelloworld"))
        {
            try registerLibrary(
                context,
                allocator,
                options,
                if (options.enable_hyperv_persistence)
                    data.x86_64_efi_hyperv_persistence_app
                else
                    data.x86_64_efi_hyperv_acceptance_app,
                &.{},
            );
            continue;
        }
        if (isHyperv(options.profile)) {
            if (std.mem.eql(u8, library.name, "libukallocstack")) {
                try registerLibrary(context, allocator, options, data.x86_64_efi_libraries[0], &.{});
            } else if (options.enable_ukblkdev and
                std.mem.eql(u8, library.name, "libukboot"))
            {
                try registerLibrary(context, allocator, options, data.x86_64_efi_ukblkdev, &.{});
            } else if (std.mem.eql(u8, library.name, "libuklibid")) {
                try registerLibrary(context, allocator, options, data.x86_64_efi_libraries[3], &.{});
                try registerLibrary(context, allocator, options, data.x86_64_efi_libraries[4], &.{});
            } else if (std.mem.eql(u8, library.name, "libuklcpu")) {
                try registerLibrary(context, allocator, options, data.x86_64_efi_libraries[5], &.{});
            } else if (std.mem.eql(u8, library.name, "libukplat_native")) {
                try registerLibrary(context, allocator, options, data.x86_64_efi_libraries[1], &.{});
                try registerLibrary(context, allocator, options, data.x86_64_efi_libraries[2], &.{});
            }
        }
        var effective = library;
        if (isHyperv(options.profile) and
            std.mem.eql(u8, library.name, "libukplat_native"))
        {
            effective.objects = &data.x86_64_efi_native_objects;
        }
        try registerLibrary(context, allocator, options, effective, &.{});
    }
    if (isHyperv(options.profile)) {
        const source = try joinPath(
            allocator,
            options.roots.base,
            "drivers/hyperv/vmbus/vmbus_protocol.zig",
        );
        const output = try joinPath(
            allocator,
            options.roots.output,
            "libvmbus/vmbus_protocol.o",
        );
        const channel_source = try joinPath(
            allocator,
            options.roots.base,
            "drivers/hyperv/vmbus/vmbus_channel.zig",
        );
        const channel_output = try joinPath(
            allocator,
            options.roots.output,
            "libvmbus/vmbus_channel_core.o",
        );
        try registerLibrary(
            context,
            allocator,
            options,
            data.x86_64_efi_vmbus,
            &.{
                .{
                    .name = "vmbus-protocol",
                    .root_source_file = source,
                    .output = output,
                    .optimize = .ReleaseFast,
                    .pic = true,
                    .isr = true,
                },
                .{
                    .name = "vmbus-channel",
                    .root_source_file = channel_source,
                    .output = channel_output,
                    .optimize = .ReleaseFast,
                    .pic = true,
                },
            },
        );
        if (options.enable_storvsc) {
            const storvsc_source = try joinPath(
                allocator,
                options.roots.base,
                "drivers/hyperv/storvsc/storvsc_core.zig",
            );
            const storvsc_output = try joinPath(
                allocator,
                options.roots.output,
                "libstorvsc/storvsc_core.o",
            );
            try registerLibrary(
                context,
                allocator,
                options,
                data.x86_64_efi_storvsc,
                &.{.{
                    .name = "storvsc-core",
                    .root_source_file = storvsc_source,
                    .output = storvsc_output,
                    .optimize = .ReleaseFast,
                    .pic = true,
                }},
            );
        }
        if (options.enable_uklibparam) {
            try registerLibrary(
                context,
                allocator,
                options,
                data.uklibparam,
                &.{},
            );
        }
        if (hasNetvsc(options.profile)) {
            try registerLibrary(
                context,
                allocator,
                options,
                data.x86_64_efi_uknetdev,
                &.{},
            );
            const netvsc_source = try joinPath(
                allocator,
                options.roots.base,
                "drivers/hyperv/netvsc/netvsc_protocol.zig",
            );
            const netvsc_output = try joinPath(
                allocator,
                options.roots.output,
                "libnetvsc/netvsc_protocol.o",
            );
            try registerLibrary(
                context,
                allocator,
                options,
                data.x86_64_efi_netvsc,
                &.{.{
                    .name = "netvsc-protocol",
                    .root_source_file = netvsc_source,
                    .output = netvsc_output,
                    .optimize = .ReleaseFast,
                    .pic = true,
                }},
            );
            if (options.enable_lwip) {
                if (options.lwip_root == null)
                    return error.UnsupportedConfiguration;
                try registerLibrary(
                    context,
                    allocator,
                    options,
                    data.x86_64_efi_ukrandom,
                    &.{},
                );
                if (options.enable_ukrandom_lcpu) {
                    try registerLibrary(
                        context,
                        allocator,
                        options,
                        data.x86_64_efi_ukrandom_lcpu,
                        &.{},
                    );
                }
                try registerLibrary(
                    context,
                    allocator,
                    options,
                    data.x86_64_efi_lwip,
                    &.{},
                );
            }
        }
    }
}

fn registerLibrary(
    context: *component.BuildContext,
    allocator: std.mem.Allocator,
    options: Options,
    library: data.Library,
    target_zig_objects: []const component.TargetZigObject,
) Error!void {
    const roots = options.roots;
    const objects = try allocator.alloc(component.RegisteredArtifact, library.objects.len);
    const sequence = try allocator.alloc(
        component.LinkSequenceItem,
        2 + library.objects.len + target_zig_objects.len + library.archives.len + 2,
    );
    var sequence_index: usize = 0;
    sequence[sequence_index] = .{ .literal_flag = "-Wl,--build-id=none" };
    sequence_index += 1;
    sequence[sequence_index] = .{ .literal_flag = "-no-pie" };
    sequence_index += 1;

    for (library.objects, 0..) |relative, index| {
        const path = try joinPath(allocator, roots.output, relative);
        objects[index] = .{ .path = path };
        sequence[sequence_index] = .{ .artifact = .{
            .kind = .object,
            .artifact = .{ .component_output = .{
                .component = library.name,
                .path = path,
            } },
            .provenance = .library_local,
        } };
        sequence_index += 1;
    }
    for (target_zig_objects) |object| {
        sequence[sequence_index] = .{ .artifact = .{
            .kind = .object,
            .artifact = .{ .component_output = .{
                .component = library.name,
                .path = object.output,
            } },
            .provenance = .library_local,
        } };
        sequence_index += 1;
    }
    sequence[sequence_index] = .group_start;
    sequence_index += 1;
    for (library.archives) |archive| {
        sequence[sequence_index] = .{ .artifact = .{
            .kind = .archive,
            .artifact = .{ .path = try resolvePath(allocator, roots, archive) },
            .provenance = .library_local,
        } };
        sequence_index += 1;
    }
    sequence[sequence_index] = .group_end;

    const exports = if (library.export_symbols) |symbol|
        try allocator.dupe([]const u8, &.{try resolvePath(allocator, roots, symbol)})
    else
        &.{};
    const transform_count: usize =
        @as(usize, @intFromBool(library.export_symbols != null)) +
        @as(usize, @intFromBool(library.localize_symbols != null));
    const transform_sequence = try allocator.alloc(
        component.ObjectTransformItem,
        transform_count,
    );
    var transform_index: usize = 0;
    if (library.export_symbols) |symbol| {
        transform_sequence[transform_index] = .{ .symbol_file = .{
            .action = .keep_global,
            .symbols_file = try resolvePath(allocator, roots, symbol),
            .provenance = .library_local,
        } };
        transform_index += 1;
    }
    if (library.localize_symbols) |symbol| {
        transform_sequence[transform_index] = .{ .symbol_file = .{
            .action = .localize,
            .symbols_file = try resolvePath(allocator, roots, symbol),
            .provenance = .library_local,
        } };
        transform_index += 1;
    }
    std.debug.assert(transform_index == transform_count);
    const linker_scripts = try resolveRegisteredPaths(
        allocator,
        roots,
        library.linker_scripts,
    );
    const archives = try resolveRegisteredPaths(allocator, roots, library.archives);
    const origin: component.Origin = if (std.mem.eql(
        u8,
        library.name,
        "liblwip",
    )) .{ .external = .{
        .package_name = "lwip",
        .root = options.lwip_root.?,
    } } else switch (library.origin) {
        .application => .{ .external = .{
            .package_name = "helloworld",
            .root = roots.app,
        } },
        .architecture => .{ .internal = .architecture },
        .driver => .{ .internal = .driver },
        .library => .{ .internal = .library },
        .platform => .{ .internal = .platform },
    };

    try context.registerLibrary(.{
        .name = library.name,
        .kind = if (isPrimaryPlatformLibrary(library.name))
            .platform_library
        else
            .library,
        .origin = origin,
        .layout = .{ .ordinary = .{ .build_subdir = library.name } },
        .platforms = if (isPrimaryPlatformLibrary(library.name))
            &.{platformName(options.profile)}
        else
            &.{},
        .exports = exports,
        .archives = archives,
        .raw_objects = objects,
        .target_zig_objects = target_zig_objects,
        .linker_scripts = linker_scripts,
        .object_pipeline = .{
            .partial_link_output = try joinPath(
                allocator,
                roots.output,
                try std.fmt.allocPrint(allocator, "{s}.ld.o", .{library.name}),
            ),
            .partial_link_sequence = sequence,
            .transform = .{
                .input = .{ .library_partial_output = library.name },
                .output = try joinPath(
                    allocator,
                    roots.output,
                    try std.fmt.allocPrint(allocator, "{s}.o", .{library.name}),
                ),
                .sequence = transform_sequence,
            },
        },
    });
}

fn registerPlatform(
    context: *component.BuildContext,
    allocator: std.mem.Allocator,
    options: Options,
    profile: data.Profile,
) Error!void {
    const extra_script_count: usize =
        @as(usize, @intFromBool(isHyperv(options.profile))) +
        @as(usize, @intFromBool(options.enable_uklibparam));
    const merge_sequence = try allocator.alloc(
        component.LinkSequenceItem,
        profile.linker_script_inputs.len + extra_script_count,
    );
    const platform_scripts = try allocator.alloc(
        component.ArtifactReference,
        profile.linker_script_inputs.len + extra_script_count + 1,
    );
    for (profile.linker_script_inputs, 0..) |script, index| {
        const path = if (isHyperv(options.profile) and index < 2)
            try joinPath(
                allocator,
                options.roots.output,
                if (index == 0)
                    "libhypervplat/link64.lds"
                else
                    "libhypervplat/bootinfo.lds",
            )
        else
            try resolvePath(allocator, options.roots, script);
        merge_sequence[index] = .{ .artifact = .{
            .kind = .linker_script,
            .artifact = .{ .path = path },
            .provenance = if (index < 2) .platform else .global,
        } };
        platform_scripts[index] = .{ .path = path };
    }
    var extra_script_index = profile.linker_script_inputs.len;
    if (isHyperv(options.profile)) {
        const reloc_script = try joinPath(
            allocator,
            options.roots.output,
            "libukreloc/reloc.lds",
        );
        merge_sequence[extra_script_index] = .{ .artifact = .{
            .kind = .linker_script,
            .artifact = .{ .path = reloc_script },
            .provenance = .global,
        } };
        platform_scripts[extra_script_index] = .{ .path = reloc_script };
        extra_script_index += 1;
    }
    if (options.enable_uklibparam) {
        const libparam_script = try joinPath(
            allocator,
            options.roots.output,
            "libuklibparam/libparam.lds",
        );
        merge_sequence[extra_script_index] = .{ .artifact = .{
            .kind = .linker_script,
            .artifact = .{ .path = libparam_script },
            .provenance = .global,
        } };
        platform_scripts[extra_script_index] = .{ .path = libparam_script };
        extra_script_index += 1;
    }
    std.debug.assert(extra_script_index ==
        profile.linker_script_inputs.len + extra_script_count);
    platform_scripts[profile.linker_script_inputs.len + extra_script_count] = .{ .stage_output = .{
        .platform = platformName(options.profile),
        .stage = "merge-linker-scripts",
    } };

    const extra_final_flags: usize = if (isHyperv(options.profile)) 4 else 0;
    const final_sequence = try allocator.alloc(
        component.LinkSequenceItem,
        context.libraries.items.len + 8 + extra_final_flags,
    );
    var sequence_index: usize = 0;
    final_sequence[sequence_index] = .{ .literal_flag = switch (options.profile) {
        .@"qemu-x86_64" => "-Wl,--entry=_multiboot_entry",
        .@"qemu-arm64" => "-Wl,--entry=_libkvmplat_entry",
        .@"hyperv-x86_64-efi",
        .@"hyperv-x86_64-efi-netvsc",
        => "-Wl,--entry=uk_efi_entry64",
    } };
    sequence_index += 1;
    for (context.libraries.items, 0..) |library, index| {
        final_sequence[sequence_index] = .{ .artifact = .{
            .kind = .object,
            .artifact = .{ .library_final_object = library.name },
            .provenance = if (index == 0) .platform else .global,
        } };
        sequence_index += 1;
    }
    final_sequence[sequence_index] = .group_start;
    sequence_index += 1;
    final_sequence[sequence_index] = .group_end;
    sequence_index += 1;
    final_sequence[sequence_index] = .{ .literal_flag = "-nostdlib" };
    sequence_index += 1;
    final_sequence[sequence_index] = .{ .literal_flag = "-Wl,--build-id=none" };
    sequence_index += 1;
    if (isHyperv(options.profile)) {
        for ([_][]const u8{
            "-pie",
            "-z",
            "notext",
            "-z",
            "norelro",
        }) |flag| {
            final_sequence[sequence_index] = .{ .literal_flag = flag };
            sequence_index += 1;
        }
    } else {
        final_sequence[sequence_index] = .{ .literal_flag = "-no-pie" };
        sequence_index += 1;
    }
    final_sequence[sequence_index] = .{ .literal_flag = "-rtlib=compiler-rt" };
    sequence_index += 1;
    final_sequence[sequence_index] = .{ .artifact = .{
        .kind = .linker_script,
        .artifact = .{ .stage_output = .{
            .platform = platformName(options.profile),
            .stage = "merge-linker-scripts",
        } },
        .provenance = .platform,
    } };

    const merged_script = try joinPath(
        allocator,
        options.roots.output,
        if (isHyperv(options.profile))
            "hyperv-combined.lds"
        else
            "kvm-combined.lds",
    );
    const final_output = try joinPath(
        allocator,
        options.roots.output,
        switch (options.profile) {
            .@"hyperv-x86_64-efi" => "helloworld_hyperv-x86_64-efi.dbg",
            .@"hyperv-x86_64-efi-netvsc" => "helloworld_hyperv-x86_64-efi-netvsc.dbg",
            else => profile.final_output,
        },
    );
    const post_process = try postProcess(
        allocator,
        options.profile,
        options.roots.output,
    );

    try context.registerPlatform(.{
        .name = platformName(options.profile),
        .origin = .{ .internal = .platform },
        .linker_definition = try joinPath(
            allocator,
            options.roots.base,
            if (isHyperv(options.profile))
                "plat/hyperv/Linker.uk"
            else
                "plat/kvm/Linker.uk",
        ),
        .libraries = if (isHyperv(options.profile))
            &.{"libhypervplat"}
        else
            &.{"libkvmplat"},
        .object_inputs = if (isHyperv(options.profile))
            &.{.{ .library_final_object = "libhypervplat" }}
        else
            &.{.{ .library_final_object = "libkvmplat" }},
        .linker_scripts = platform_scripts,
        .link_stages = &.{
            .{
                .name = "merge-linker-scripts",
                .transformation = .{ .custom = "merge-linker-scripts" },
                .output = merged_script,
                .sequence = merge_sequence,
            },
            .{
                .name = "final-link",
                .transformation = .final_link,
                .output = final_output,
                .output_role = .debug,
                .sequence = final_sequence,
            },
        },
        .post_process = post_process,
    });
}

fn postProcess(
    allocator: std.mem.Allocator,
    profile: Profile,
    output_root: []const u8,
) ![]const component.PostProcessTransformation {
    const image_relative = switch (profile) {
        .@"qemu-x86_64" => "helloworld_qemu-x86_64",
        .@"qemu-arm64" => "helloworld_qemu-arm64",
        .@"hyperv-x86_64-efi" => "helloworld_hyperv-x86_64-efi",
        .@"hyperv-x86_64-efi-netvsc" => "helloworld_hyperv-x86_64-efi-netvsc",
    };
    const image = try joinPath(allocator, output_root, image_relative);
    const bootinfo = try std.fmt.allocPrint(allocator, "{s}.bootinfo", .{image});
    const debug_image = try std.fmt.allocPrint(allocator, "{s}.dbg", .{image});
    const relocations = try std.fmt.allocPrint(allocator, "{s}.uk_reloc.bin", .{debug_image});
    const compile_database = try joinPath(allocator, output_root, "compile_commands.json");
    const protocol_name = switch (profile) {
        .@"qemu-x86_64" => "multiboot",
        .@"qemu-arm64" => "linux-header",
        .@"hyperv-x86_64-efi",
        .@"hyperv-x86_64-efi-netvsc",
        => "efi",
    };
    const transformations = try allocator.alloc(
        component.PostProcessTransformation,
        if (profile == .@"qemu-x86_64") 4 else 5,
    );
    const strip_index: usize = if (isHyperv(profile)) 1 else 0;
    if (isHyperv(profile)) {
        transformations[0] = .{
            .name = "uk-reloc",
            .kind = .uk_reloc,
            .input = .{ .stage_output = .{
                .platform = platformName(profile),
                .stage = "final-link",
            } },
            .effects = try copyEffects(allocator, &.{
                .{ .create = .{
                    .name = "relocations",
                    .path = relocations,
                    .role = .side,
                } },
                .{ .mutate_input = .{
                    .name = "debug",
                    .role = .debug,
                } },
            }),
        };
    }
    transformations[strip_index] = .{
        .name = "strip",
        .kind = .strip,
        .input = if (isHyperv(profile))
            .{ .post_process_output = .{
                .platform = platformName(profile),
                .transformation = "uk-reloc",
                .output = "debug",
            } }
        else
            .{ .stage_output = .{
                .platform = platformName(profile),
                .stage = "final-link",
            } },
        .flags = if (isHyperv(profile))
            &.{ ".dynamic", ".gnu.hash", ".hash", ".dynsym", ".dynstr", ".rela.dyn" }
        else
            &.{},
        .effects = try copyEffects(allocator, &.{.{ .create = .{
            .name = "image",
            .path = image,
            .role = .image,
        } }}),
    };
    const bootinfo_index = strip_index + 1;
    transformations[bootinfo_index] = .{
        .name = "bootinfo",
        .kind = .bootinfo,
        .input = .{ .post_process_output = .{
            .platform = platformName(profile),
            .transformation = "strip",
            .output = "image",
        } },
        .effects = try copyEffects(allocator, &.{
            .{ .create = .{ .name = "bootinfo", .path = bootinfo, .role = .side } },
            .{ .mutate_input = .{ .name = "image", .role = .image } },
        }),
    };
    const protocol_index = bootinfo_index + 1;
    if (profile == .@"qemu-x86_64") {
        transformations[protocol_index] = .{
            .name = "multiboot",
            .kind = .multiboot,
            .input = .{ .post_process_output = .{
                .platform = platformName(profile),
                .transformation = "bootinfo",
                .output = "image",
            } },
            .effects = try copyEffects(allocator, &.{.{
                .mutate_input = .{ .name = "image", .role = .image },
            }}),
        };
    } else if (profile == .@"qemu-arm64") {
        transformations[protocol_index] = .{
            .name = "linux-binary",
            .kind = .objcopy_binary,
            .input = .{ .post_process_output = .{
                .platform = platformName(profile),
                .transformation = "bootinfo",
                .output = "image",
            } },
            .effects = try copyEffects(allocator, &.{.{
                .mutate_input = .{ .name = "image", .role = .image },
            }}),
        };
        transformations[protocol_index + 1] = .{
            .name = "linux-header",
            .kind = .linux_header,
            .input = .{ .post_process_output = .{
                .platform = platformName(profile),
                .transformation = "linux-binary",
                .output = "image",
            } },
            .additional_inputs = try copyArtifactReferences(allocator, &.{.{ .stage_output = .{
                .platform = platformName(profile),
                .stage = "final-link",
            } }}),
            .effects = try copyEffects(allocator, &.{.{
                .mutate_input = .{ .name = "image", .role = .image },
            }}),
        };
    } else {
        transformations[protocol_index] = .{
            .name = "efi",
            .kind = .efi,
            .input = .{ .post_process_output = .{
                .platform = platformName(profile),
                .transformation = "bootinfo",
                .output = "image",
            } },
            .additional_inputs = try copyArtifactReferences(allocator, &.{.{
                .post_process_output = .{
                    .platform = platformName(profile),
                    .transformation = "uk-reloc",
                    .output = "debug",
                },
            }}),
            .effects = try copyEffects(allocator, &.{.{
                .mutate_input = .{ .name = "image", .role = .image },
            }}),
        };
    }
    const compile_index = transformations.len - 1;
    transformations[compile_index] = .{
        .name = "compile-db",
        .kind = .compile_database,
        .input = .{ .post_process_output = .{
            .platform = platformName(profile),
            .transformation = protocol_name,
            .output = "image",
        } },
        .effects = try copyEffects(allocator, &.{.{ .create = .{
            .name = "database",
            .path = compile_database,
            .role = .auxiliary,
        } }}),
    };
    return transformations;
}

fn platformName(profile: Profile) []const u8 {
    return if (isHyperv(profile)) "hyperv" else "kvm";
}

fn isPrimaryPlatformLibrary(name: []const u8) bool {
    return std.mem.eql(u8, name, "libkvmplat") or
        std.mem.eql(u8, name, "libhypervplat");
}

fn copyEffects(
    allocator: std.mem.Allocator,
    effects: []const component.PostProcessEffect,
) ![]const component.PostProcessEffect {
    return allocator.dupe(component.PostProcessEffect, effects);
}

fn copyArtifactReferences(
    allocator: std.mem.Allocator,
    references: []const component.ArtifactReference,
) ![]const component.ArtifactReference {
    return allocator.dupe(component.ArtifactReference, references);
}

fn resolveRegisteredPaths(
    allocator: std.mem.Allocator,
    roots: component.Roots,
    paths: []const data.Path,
) ![]const component.RegisteredArtifact {
    const result = try allocator.alloc(component.RegisteredArtifact, paths.len);
    for (paths, 0..) |path, index| {
        result[index] = .{ .path = try resolvePath(allocator, roots, path) };
    }
    return result;
}

fn resolvePath(
    allocator: std.mem.Allocator,
    roots: component.Roots,
    path: data.Path,
) ![]const u8 {
    const root = switch (path.root) {
        .base => roots.base,
        .app => roots.app,
        .output => roots.output,
    };
    return joinPath(allocator, root, path.relative);
}

fn joinPath(
    allocator: std.mem.Allocator,
    root: []const u8,
    relative: []const u8,
) ![]const u8 {
    if (relative.len == 0) return allocator.dupe(u8, root);
    return std.fs.path.join(allocator, &.{ root, relative });
}

fn configDisabled(_: ?*const anyopaque, _: []const u8) bool {
    return false;
}

fn configValue(_: ?*const anyopaque, _: []const u8) ?[]const u8 {
    return null;
}

const empty_config = component.ConfigQuery{
    .is_enabled_fn = configDisabled,
    .value_fn = configValue,
};

const ParityFixture = struct {
    profile: []const u8,
    library_order: []const []const u8,
    libraries: []const LibraryFixture,
    platform: PlatformFixture,
    outputs: OutputFixture,

    const LibraryFixture = struct {
        name: []const u8,
        objects: []const []const u8,
        archives: []const []const u8,
        partial_output: []const u8,
        final_output: []const u8,
        symbol_transforms: []const SymbolFixture,
    };

    const SymbolFixture = struct {
        action: []const u8,
        path: []const u8,
    };

    const PlatformFixture = struct {
        name: []const u8,
        libraries: []const []const u8,
        linker_script_inputs: []const []const u8,
        merged_linker_script: []const u8,
        final_link: LinkStageFixture,
        post_process: []const []const u8,
    };

    const LinkStageFixture = struct {
        inputs: []const LinkInputFixture,
        name: []const u8,
        output: []const u8,
    };

    const LinkInputFixture = struct {
        kind: []const u8,
        path: []const u8,
    };

    const OutputFixture = struct {
        auxiliary: []const []const u8,
        debug: []const []const u8,
        images: []const []const u8,
    };
};

test "registered profiles use the native Zig library executor contract" {
    inline for (.{ Profile.@"qemu-x86_64", Profile.@"qemu-arm64" }) |profile| {
        var registered = try RegisteredGraph.init(std.testing.allocator, .{
            .roots = .{
                .base = "/src/unikraft",
                .app = "/src/app-helloworld",
                .output = "/build",
                .config = "/build/.config",
            },
            .profile = profile,
        });
        defer registered.deinit();

        try std.testing.expectEqualStrings("zig cc", registered.graph.toolchain.partial_linker.tool.command);
        try std.testing.expectEqualStrings("zig", registered.graph.toolchain.compiler.tool.command);
        try std.testing.expect(registered.graph.toolchain.partial_linker.mode == .driver);
        var plan = try native_library_link.plan(std.testing.allocator, registered.graph);
        defer plan.deinit();
        try std.testing.expectEqual(registered.graph.libraries.len, plan.libraries.len);
        for (plan.libraries) |library| {
            try std.testing.expectEqualStrings("cc", library.partial_arguments[0].literal);
            try std.testing.expectEqualStrings("-target", library.partial_arguments[1].literal);
            try std.testing.expectEqualStrings("-nostdlib", library.partial_arguments[3].literal);
            try std.testing.expectEqualStrings("-r", library.partial_arguments[4].literal);
            for (library.partial_arguments) |argument| {
                if (argument != .literal) continue;
                try std.testing.expect(!std.mem.eql(u8, argument.literal, "-Wl,-r"));
                try std.testing.expect(!std.mem.eql(u8, argument.literal, "-Wl,-d"));
            }
        }
    }
}

test "registered profiles satisfy the native final-link planner contract" {
    inline for (.{ Profile.@"qemu-x86_64", Profile.@"qemu-arm64" }) |profile| {
        var registered = try RegisteredGraph.init(std.testing.allocator, .{
            .roots = .{
                .base = "/src/unikraft",
                .app = "/src/app-helloworld",
                .output = "/build",
                .config = "/build/.config",
            },
            .profile = profile,
        });
        defer registered.deinit();

        const plans = try native_final_link.planSelected(
            std.testing.allocator,
            registered.graph,
        );
        defer native_final_link.deinitPlans(std.testing.allocator, plans);
        try std.testing.expectEqual(@as(usize, 1), plans.len);
        try std.testing.expectEqual(@as(usize, 1), plans[0].linker_scripts.len);
        try std.testing.expect(plans[0].linker_scripts[0].artifact == .stage_output);
        try std.testing.expectEqualStrings(
            "merge-linker-scripts",
            plans[0].linker_scripts[0].artifact.stage_output.stage,
        );

        var merged_script_arguments: usize = 0;
        for (plans[0].arguments) |argument| {
            switch (argument) {
                .merged_linker_script => merged_script_arguments += 1,
                .literal => |literal| {
                    try std.testing.expect(!std.mem.startsWith(u8, literal, "-Wl,-T"));
                    try std.testing.expect(!std.mem.startsWith(u8, literal, "-Wl,-m"));
                },
                .artifact => {},
            }
        }
        try std.testing.expectEqual(@as(usize, 1), merged_script_arguments);
    }
}

test "Hyper-V EFI profile registers source-built Zig objects and PIE link ordering" {
    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/app-helloworld",
            .output = "/build",
            .config = "/build/.config",
        },
        .profile = .@"hyperv-x86_64-efi",
        .enable_ukblkdev = true,
        .enable_storvsc = true,
    });
    defer registered.deinit();

    try std.testing.expectEqualStrings("hyperv", registered.graph.selectedPlatform().name);
    try std.testing.expectEqualStrings(
        "x86_64-freestanding-none",
        registered.graph.target.triple,
    );
    var hyperv_library: ?component.Library = null;
    for (registered.graph.libraries) |library| {
        if (std.mem.eql(u8, library.name, "libhypervplat")) {
            hyperv_library = library;
            break;
        }
    }
    const zig_library = hyperv_library orelse return error.TestUnexpectedResult;
    try std.testing.expect(zig_library.raw_objects.len > 0);
    try std.testing.expectEqual(@as(usize, 1), zig_library.target_zig_objects.len);
    try std.testing.expect(zig_library.target_zig_objects[0].pic);
    try std.testing.expect(zig_library.target_zig_objects[0].isr);
    try std.testing.expectEqualStrings(
        "/src/unikraft/plat/hyperv/hyperv_runtime.zig",
        zig_library.target_zig_objects[0].root_source_file,
    );
    try std.testing.expect(
        zig_library.object_pipeline.?.partial_link_sequence[
            2 + data.x86_64_efi_hyperv_objects.len
        ].artifact.artifact ==
            .component_output,
    );

    var vmbus_library: ?component.Library = null;
    for (registered.graph.libraries) |library| {
        if (std.mem.eql(u8, library.name, "libvmbus")) {
            vmbus_library = library;
            break;
        }
    }
    const vmbus = vmbus_library orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), vmbus.target_zig_objects.len);
    try std.testing.expect(vmbus.target_zig_objects[0].isr);
    try std.testing.expect(!vmbus.target_zig_objects[1].isr);
    try std.testing.expectEqualStrings(
        "/build/libvmbus/vmbus_bus.isr.o",
        vmbus.raw_objects[0].path,
    );
    try std.testing.expectEqualStrings(
        "/src/unikraft/drivers/hyperv/vmbus/vmbus_protocol.zig",
        vmbus.target_zig_objects[0].root_source_file,
    );
    try std.testing.expectEqualStrings(
        "/src/unikraft/drivers/hyperv/vmbus/vmbus_channel.zig",
        vmbus.target_zig_objects[1].root_source_file,
    );
    var storvsc_library: ?component.Library = null;
    for (registered.graph.libraries) |library| {
        if (std.mem.eql(u8, library.name, "libstorvsc")) {
            storvsc_library = library;
            break;
        }
    }
    const storvsc = storvsc_library orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), storvsc.target_zig_objects.len);
    try std.testing.expectEqual(@as(usize, 1), storvsc.exports.len);
    try std.testing.expectEqualStrings(
        "/src/unikraft/drivers/hyperv/storvsc/exportsyms.uk",
        storvsc.exports[0],
    );
    const storvsc_transform = storvsc.object_pipeline.?.transform.sequence;
    try std.testing.expectEqual(@as(usize, 1), storvsc_transform.len);
    try std.testing.expect(storvsc_transform[0] == .symbol_file);
    try std.testing.expect(storvsc_transform[0].symbol_file.action == .keep_global);
    try std.testing.expectEqualStrings(
        storvsc.exports[0],
        storvsc_transform[0].symbol_file.symbols_file,
    );
    try std.testing.expectEqualStrings(
        "/src/unikraft/drivers/hyperv/storvsc/storvsc_core.zig",
        storvsc.target_zig_objects[0].root_source_file,
    );

    const final_stage = registered.graph.selectedPlatform().link_stages[1];
    var saw_entry = false;
    var saw_pie = false;
    var saw_zig_library = false;
    for (final_stage.sequence) |item| switch (item) {
        .literal_flag => |flag| {
            saw_entry = saw_entry or std.mem.eql(u8, flag, "-Wl,--entry=uk_efi_entry64");
            saw_pie = saw_pie or std.mem.eql(u8, flag, "-pie");
        },
        .artifact => |artifact| {
            if (artifact.artifact == .library_final_object) {
                saw_zig_library = saw_zig_library or std.mem.eql(
                    u8,
                    artifact.artifact.library_final_object,
                    "libhypervplat",
                );
            }
        },
        else => {},
    };
    try std.testing.expect(saw_entry);
    try std.testing.expect(saw_pie);
    try std.testing.expect(saw_zig_library);

    const post = registered.graph.selectedPlatform().post_process;
    try std.testing.expectEqual(@as(usize, 5), post.len);
    try std.testing.expect(post[0].kind == .uk_reloc);
    try std.testing.expectEqualStrings("uk-reloc", post[0].name);
    try std.testing.expect(post[1].kind == .strip);
    try std.testing.expect(post[1].input == .post_process_output);
    try std.testing.expectEqualStrings(
        "uk-reloc",
        post[1].input.post_process_output.transformation,
    );
    try std.testing.expect(post[3].kind == .efi);
    try std.testing.expect(post[3].additional_inputs[0] == .post_process_output);
    try std.testing.expectEqualStrings(
        "uk-reloc",
        post[3].additional_inputs[0].post_process_output.transformation,
    );
}

test "Hyper-V block libraries follow the solved configuration" {
    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/app-helloworld",
            .output = "/build",
            .config = "/build/.config",
        },
        .profile = .@"hyperv-x86_64-efi",
    });
    defer registered.deinit();

    for (registered.graph.libraries) |library| {
        try std.testing.expect(!std.mem.eql(u8, library.name, "libukblkdev"));
        try std.testing.expect(!std.mem.eql(u8, library.name, "libstorvsc"));
        try std.testing.expect(!std.mem.eql(u8, library.name, "libuknetdev"));
        try std.testing.expect(!std.mem.eql(u8, library.name, "libnetvsc"));
    }
}

test "Hyper-V NetVSC profile registers protocol and uknetdev" {
    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/app-helloworld",
            .output = "/build",
            .config = "/build/.config",
        },
        .profile = .@"hyperv-x86_64-efi-netvsc",
        .enable_uklibparam = true,
    });
    defer registered.deinit();

    var saw_uknetdev = false;
    var saw_uklibparam = false;
    var application: ?component.Library = null;
    var netvsc_library: ?component.Library = null;
    for (registered.graph.libraries) |library| {
        saw_uknetdev = saw_uknetdev or
            std.mem.eql(u8, library.name, "libuknetdev");
        saw_uklibparam = saw_uklibparam or
            std.mem.eql(u8, library.name, "libuklibparam");
        if (std.mem.eql(u8, library.name, "libnetvsc"))
            netvsc_library = library;
        if (std.mem.eql(u8, library.name, "apphelloworld"))
            application = library;
    }
    try std.testing.expect(saw_uknetdev);
    try std.testing.expect(saw_uklibparam);
    const app = application orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), app.raw_objects.len);
    try std.testing.expectEqualStrings(
        "/build/apphelloworld/main.o",
        app.raw_objects[0].path,
    );
    const netvsc = netvsc_library orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), netvsc.target_zig_objects.len);
    try std.testing.expectEqualStrings(
        "/src/unikraft/drivers/hyperv/netvsc/netvsc_protocol.zig",
        netvsc.target_zig_objects[0].root_source_file,
    );
    var saw_libparam_script = false;
    for (registered.graph.platforms[0].link_stages[0].sequence) |item| {
        if (item != .artifact or item.artifact.artifact != .path)
            continue;
        saw_libparam_script = saw_libparam_script or std.mem.eql(
            u8,
            item.artifact.artifact.path,
            "/build/libuklibparam/libparam.lds",
        );
    }
    try std.testing.expect(saw_libparam_script);
}

test "Hyper-V application networking registers pinned stack inputs" {
    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/hyperv-acceptance",
            .output = "/build",
            .config = "/build/.config",
        },
        .profile = .@"hyperv-x86_64-efi-netvsc",
        .enable_hyperv_acceptance = true,
        .enable_lwip = true,
        .enable_ukrandom_lcpu = true,
        .lwip_root = "/deps/lib-lwip",
    });
    defer registered.deinit();

    var application: ?component.Library = null;
    var lwip: ?component.Library = null;
    var saw_random = false;
    var saw_random_lcpu = false;
    for (registered.graph.libraries) |library| {
        if (std.mem.eql(u8, library.name, "apphelloworld"))
            application = library;
        if (std.mem.eql(u8, library.name, "liblwip"))
            lwip = library;
        saw_random = saw_random or
            std.mem.eql(u8, library.name, "libukrandom");
        saw_random_lcpu = saw_random_lcpu or
            std.mem.eql(u8, library.name, "libukrandom_lcpu");
    }
    const app = application orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 5), app.raw_objects.len);
    try std.testing.expectEqualStrings(
        "/build/apphelloworld/application_network.o",
        app.raw_objects[3].path,
    );
    const stack = lwip orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        data.x86_64_efi_lwip.objects.len,
        stack.raw_objects.len,
    );
    try std.testing.expect(stack.origin == .external);
    try std.testing.expectEqualStrings("lwip", stack.origin.external.package_name);
    try std.testing.expectEqualStrings(
        "/deps/lib-lwip",
        stack.origin.external.root,
    );
    try std.testing.expect(saw_random);
    try std.testing.expect(saw_random_lcpu);
    for (registered.graph.libraries) |library| {
        if (std.mem.eql(u8, library.name, "libukrandom")) {
            try std.testing.expectEqual(@as(usize, 1), library.exports.len);
            try std.testing.expectEqualStrings(
                "/src/unikraft/lib/ukrandom/exportsyms.uk",
                library.exports[0],
            );
            try std.testing.expect(
                library.object_pipeline.?.transform.sequence[0].symbol_file.action ==
                    .keep_global,
            );
        }
        if (!std.mem.eql(u8, library.name, "libukrandom_lcpu"))
            continue;
        try std.testing.expectEqual(
            @as(usize, 1),
            library.object_pipeline.?.transform.sequence.len,
        );
        try std.testing.expect(
            library.object_pipeline.?.transform.sequence[0].symbol_file.action ==
                .localize,
        );
    }

    try std.testing.expectError(
        error.UnsupportedConfiguration,
        RegisteredGraph.init(std.testing.allocator, .{
            .roots = .{
                .base = "/src/unikraft",
                .app = "/src/hyperv-acceptance",
                .output = "/build",
                .config = "/build/.config",
            },
            .profile = .@"hyperv-x86_64-efi-netvsc",
            .enable_lwip = true,
        }),
    );
}

test "Hyper-V raw acceptance registers its sources without the network stack" {
    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/hyperv-acceptance",
            .output = "/build",
            .config = "/build/.config",
        },
        .profile = .@"hyperv-x86_64-efi-netvsc",
        .enable_hyperv_acceptance = true,
    });
    defer registered.deinit();

    var application: ?component.Library = null;
    for (registered.graph.libraries) |library| {
        if (std.mem.eql(u8, library.name, "apphelloworld"))
            application = library;
        try std.testing.expect(!std.mem.eql(u8, library.name, "liblwip"));
    }

    const app = application orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 5), app.raw_objects.len);
    try std.testing.expectEqualStrings(
        "/build/apphelloworld/acceptance_protocol.o",
        app.raw_objects[1].path,
    );
}

test "Hyper-V persistence registers its separately compiled workload" {
    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/hyperv-acceptance",
            .output = "/build",
            .config = "/build/.config",
        },
        .profile = .@"hyperv-x86_64-efi-netvsc",
        .enable_hyperv_acceptance = true,
        .enable_hyperv_persistence = true,
    });
    defer registered.deinit();

    for (registered.graph.libraries) |library| {
        if (!std.mem.eql(u8, library.name, "apphelloworld"))
            continue;
        try std.testing.expectEqual(@as(usize, 6), library.raw_objects.len);
        try std.testing.expectEqualStrings(
            "/build/apphelloworld/persistence.o",
            library.raw_objects[4].path,
        );
        return;
    }
    return error.TestUnexpectedResult;
}

test "registered profiles match normalized Make graph fixtures" {
    inline for (.{
        .{
            .profile = Profile.@"qemu-x86_64",
            .fixture = @embedFile("tests/native-qemu-graph/qemu-x86_64.json"),
        },
        .{
            .profile = Profile.@"qemu-arm64",
            .fixture = @embedFile("tests/native-qemu-graph/qemu-arm64.json"),
        },
    }) |case| {
        try expectParity(case.profile, case.fixture);
    }
}

test "unsupported configuration names fail explicitly" {
    try std.testing.expectError(
        error.UnsupportedConfiguration,
        parseProfile("qemu-riscv64"),
    );
    try std.testing.expectError(
        error.UnsupportedConfiguration,
        parseProfile("xen-x86_64"),
    );
}

fn expectParity(profile: Profile, source: []const u8) !void {
    const roots = component.Roots{
        .base = "/src/unikraft",
        .app = "/src/app-helloworld",
        .output = "/build",
        .config = "/build/.config",
    };
    var parsed = try std.json.parseFromSlice(
        ParityFixture,
        std.testing.allocator,
        source,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const fixture = parsed.value;
    try std.testing.expectEqualStrings(@tagName(profile), fixture.profile);

    var registered = try RegisteredGraph.init(std.testing.allocator, .{
        .roots = roots,
        .profile = profile,
    });
    defer registered.deinit();
    const graph = registered.graph;

    try std.testing.expectEqual(fixture.library_order.len, graph.libraries.len);
    try std.testing.expectEqual(fixture.libraries.len, graph.libraries.len);
    for (graph.libraries, 0..) |library, index| {
        try std.testing.expectEqualStrings(fixture.library_order[index], library.name);
        const expected = fixture.libraries[index];
        try std.testing.expectEqualStrings(expected.name, library.name);
        try std.testing.expectEqual(expected.objects.len, library.raw_objects.len);
        for (library.raw_objects, expected.objects) |actual, expected_path| {
            try expectFixturePath(roots, expected_path, actual.path);
        }
        try std.testing.expectEqual(expected.archives.len, library.archives.len);
        for (library.archives, expected.archives) |actual, expected_path| {
            try expectFixturePath(roots, expected_path, actual.path);
        }

        const pipeline = library.object_pipeline.?;
        try expectFixturePath(roots, expected.partial_output, pipeline.partial_link_output);
        try expectFixturePath(roots, expected.final_output, pipeline.transform.output);
        try expectLibrarySequence(roots, library, expected);
        try std.testing.expectEqual(
            expected.symbol_transforms.len,
            pipeline.transform.sequence.len,
        );
        for (pipeline.transform.sequence, expected.symbol_transforms) |actual, symbol| {
            try std.testing.expect(actual == .symbol_file);
            try std.testing.expectEqualStrings("keep-global", symbol.action);
            try std.testing.expect(actual.symbol_file.action == .keep_global);
            try expectFixturePath(roots, symbol.path, actual.symbol_file.symbols_file);
        }
    }

    const platform = graph.selectedPlatform();
    try std.testing.expectEqualStrings(fixture.platform.name, platform.name);
    try std.testing.expectEqual(fixture.platform.libraries.len, platform.libraries.len);
    for (platform.libraries, fixture.platform.libraries) |actual, expected| {
        try std.testing.expectEqualStrings(expected, actual);
    }
    try std.testing.expectEqual(@as(usize, 2), platform.link_stages.len);
    const merge = platform.link_stages[0];
    try std.testing.expectEqualStrings("merge-linker-scripts", merge.name);
    try expectFixturePath(roots, fixture.platform.merged_linker_script, merge.output);
    try std.testing.expectEqual(fixture.platform.linker_script_inputs.len, merge.sequence.len);
    try std.testing.expectEqual(
        fixture.platform.linker_script_inputs.len + 1,
        platform.linker_scripts.len,
    );
    for (merge.sequence, fixture.platform.linker_script_inputs) |item, expected_path| {
        try std.testing.expect(item == .artifact);
        try std.testing.expect(item.artifact.kind == .linker_script);
        try expectFixturePath(
            roots,
            expected_path,
            try artifactPath(graph, item.artifact.artifact),
        );
    }
    try std.testing.expect(platform.linker_scripts[platform.linker_scripts.len - 1] == .stage_output);
    try std.testing.expectEqualStrings(
        "merge-linker-scripts",
        platform.linker_scripts[platform.linker_scripts.len - 1].stage_output.stage,
    );

    const final_link = platform.link_stages[1];
    try std.testing.expectEqualStrings(fixture.platform.final_link.name, final_link.name);
    try expectFixturePath(roots, fixture.platform.final_link.output, final_link.output);
    var artifact_index: usize = 0;
    var group_start_count: usize = 0;
    var group_end_count: usize = 0;
    for (final_link.sequence) |item| switch (item) {
        .artifact => |artifact| {
            const expected = fixture.platform.final_link.inputs[artifact_index];
            const actual_kind: []const u8 = switch (artifact.kind) {
                .object => "object",
                .archive => "archive",
                .linker_script => "linker-script",
                .intermediate => "intermediate",
                .custom_link_dependency => "custom-link-dependency",
            };
            try std.testing.expectEqualStrings(expected.kind, actual_kind);
            try expectFixturePath(
                roots,
                expected.path,
                try artifactPath(graph, artifact.artifact),
            );
            artifact_index += 1;
        },
        .group_start => group_start_count += 1,
        .group_end => group_end_count += 1,
        else => {},
    };
    try std.testing.expectEqual(fixture.platform.final_link.inputs.len, artifact_index);
    try std.testing.expectEqual(@as(usize, 1), group_start_count);
    try std.testing.expectEqual(@as(usize, 1), group_end_count);

    try std.testing.expectEqual(fixture.platform.post_process.len, platform.post_process.len);
    for (platform.post_process, fixture.platform.post_process) |actual, expected| {
        try std.testing.expectEqualStrings(expected, actual.name);
    }
    try std.testing.expect(platform.post_process[0].kind == .strip);
    try std.testing.expect(platform.post_process[1].kind == .bootinfo);
    if (profile == .@"qemu-x86_64") {
        try std.testing.expect(platform.post_process[2].kind == .multiboot);
    } else {
        try std.testing.expect(platform.post_process[2].kind == .objcopy_binary);
        try std.testing.expect(platform.post_process[3].kind == .linux_header);
    }
    try std.testing.expect(
        platform.post_process[platform.post_process.len - 1].kind == .compile_database,
    );
    try expectFixturePath(roots, fixture.outputs.debug[0], final_link.output);
    try expectFixturePath(
        roots,
        fixture.outputs.images[0],
        platform.post_process[0].effects[0].create.path,
    );
    try expectFixturePath(
        roots,
        fixture.outputs.auxiliary[0],
        platform.post_process[platform.post_process.len - 1].effects[0].create.path,
    );
}

fn expectLibrarySequence(
    roots: component.Roots,
    library: component.Library,
    expected: ParityFixture.LibraryFixture,
) !void {
    const sequence = library.object_pipeline.?.partial_link_sequence;
    try std.testing.expectEqual(
        2 + expected.objects.len + expected.archives.len + 2,
        sequence.len,
    );
    for (expected.objects, 0..) |expected_path, index| {
        const item = sequence[2 + index];
        try std.testing.expect(item == .artifact);
        try std.testing.expect(item.artifact.kind == .object);
        try expectFixturePath(
            roots,
            expected_path,
            item.artifact.artifact.component_output.path,
        );
    }
    const group_start = 2 + expected.objects.len;
    try std.testing.expect(sequence[group_start] == .group_start);
    for (expected.archives, 0..) |expected_path, index| {
        const item = sequence[group_start + 1 + index];
        try std.testing.expect(item == .artifact);
        try std.testing.expect(item.artifact.kind == .archive);
        try expectFixturePath(roots, expected_path, item.artifact.artifact.path);
    }
    try std.testing.expect(sequence[sequence.len - 1] == .group_end);
}

fn artifactPath(
    graph: component.FinalizedGraph,
    reference: component.ArtifactReference,
) ![]const u8 {
    return switch (reference) {
        .path => |path| path,
        .component_output => |output| output.path,
        .library_partial_output => |name| for (graph.libraries) |library| {
            if (std.mem.eql(u8, library.name, name)) {
                break library.object_pipeline.?.partial_link_output;
            }
        } else error.UnsupportedConfiguration,
        .library_final_object => |name| for (graph.libraries) |library| {
            if (std.mem.eql(u8, library.name, name)) {
                break library.object_pipeline.?.transform.output;
            }
        } else error.UnsupportedConfiguration,
        .stage_output => |wanted| for (graph.selectedPlatform().link_stages) |stage| {
            if (std.mem.eql(u8, stage.name, wanted.stage)) break stage.output;
        } else error.UnsupportedConfiguration,
        else => error.UnsupportedConfiguration,
    };
}

fn expectFixturePath(
    roots: component.Roots,
    fixture_path: []const u8,
    actual: []const u8,
) !void {
    const prefixes = .{
        .{ "$BUILD_DIR", roots.output },
        .{ "$UK_BASE", roots.base },
        .{ "$APP_DIR", roots.app },
    };
    inline for (prefixes) |entry| {
        if (std.mem.startsWith(u8, fixture_path, entry[0])) {
            const relative = std.mem.trimStart(u8, fixture_path[entry[0].len..], "/");
            const expected = try joinPath(std.testing.allocator, entry[1], relative);
            defer std.testing.allocator.free(expected);
            return std.testing.expectEqualStrings(expected, actual);
        }
    }
    return std.testing.expectEqualStrings(fixture_path, actual);
}
