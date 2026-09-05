# Typed component metadata API

`component-api.zig` is the internal, experimental Zig 0.16 metadata API for
describing Unikraft components and platform image pipelines. It models the
current `Makefile.uk` contract without compiling or linking anything. The API
may change until the external component contract is defined.

`BuildContext` copies all registration metadata into context-owned storage.
Callers retain ownership of input slices, keep the borrowed `ConfigQuery`
implementation alive through `finalize`, and call `deinit`. Library, source,
variant, link-stage, and link-input slices retain registration order. The
finalized graph's `registrations` slice also records the deterministic
cross-category component/platform order.

Library object production is explicit: `LibraryObjectPipeline` records the
ordered partial-link command, provenance of local versus `EACHOLIB` inputs,
the relocatable intermediate, symbol-localizing objcopy transformation, and
the final typed library object. `LinkStage.sequence` interleaves artifacts,
literal or driver/raw-translated flags, archive-group markers, and system
library arguments without regrouping them. Ordered post-processing
transformations can create several named artifacts or declare an in-place
mutation; later transformations refer to those named results.

```zig
const build = @import("component-api.zig");

var context = try build.BuildContext.init(allocator, .{
    .roots = .{
        .base = "/src/unikraft",
        .app = "/src/app",
        .output = "/src/app/build",
        .config = "/src/app/build/.config",
    },
    .target = .{
        .architecture = .x86_64,
        .family = .x86,
        .abi = "none",
        .triple = "x86_64-unknown-none",
    },
    .toolchain = toolchain,
    .config = config_query,
});
defer context.deinit();

try build.registerComponent(&context, .{
    .name = "libhello",
    .origin = .{ .external = .{
        .package_name = "hello",
        .root = "/packages/hello",
    } },
    .enable = .{ .config_enabled = "CONFIG_LIBHELLO" },
    .layout = .{ .ordinary = .{ .build_subdir = "libhello" } },
    .sources = &.{.{
        .name = "hello",
        .path = "/packages/hello/hello.c",
        .language = .c,
        .variants = &.{.{
            .output = .{ .path = "/src/app/build/libhello/hello.o", .kind = .object },
        }},
    }},
    .object_pipeline = .{
        .partial_link_output = "/src/app/build/libhello.ld.o",
        .partial_link_sequence = &.{
            .{ .artifact = .{
                .kind = .object,
                .artifact = .{ .component_output = .{
                    .component = "libhello",
                    .path = "/src/app/build/libhello/hello.o",
                } },
                .provenance = .library_local,
            } },
        },
        .transform = .{
            .input = .{ .library_partial_output = "libhello" },
            .output = "/src/app/build/libhello.o",
        },
    },
});

try build.registerPlatform(&context, .{
    .name = "kvm",
    .origin = .{ .internal = .platform },
    .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
    .link_stages = &.{.{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/src/app/build/app_kvm.dbg",
        .output_role = .debug,
        .sequence = &.{
            .{ .artifact = .{
                .kind = .object,
                .artifact = .{ .library_final_object = "libhello" },
            } },
            .group_start,
            .{ .artifact = .{
                .kind = .archive,
                .artifact = .{ .path = "/src/app/build/runtime.a" },
            } },
            .group_end,
            .{ .library_argument = "-lgcc" },
        },
    }},
    .post_process = &.{.{
        .name = "strip",
        .kind = .strip,
        .input = .{ .stage_output = .{
            .platform = "kvm",
            .stage = "final-link",
        } },
        .effects = &.{.{ .create = .{
            .name = "image",
            .path = "/src/app/build/app_kvm",
            .role = .image,
        } }},
    }},
});

const graph = try context.finalize();
_ = graph.selectedPlatform();
```

Validation first resolves the one selected platform and all conditions, then
checks active references and producers. It rejects duplicate active outputs,
inconsistent platform-library registrations, unknown or forward typed
references, malformed archive groups, and configurations that select zero or
multiple platforms. Inactive platform pipelines may intentionally name the
same eventual output, such as `compile_commands.json`.
`lastDiagnostic()` supplies the offending names or paths.

Run the standalone, leak-checked unit tests with:

```sh
zig test support/build/component-api.zig
```
