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
});

try build.registerPlatform(&context, .{
    .name = "kvm",
    .origin = .{ .internal = .platform },
    .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
    .link_stages = &.{.{
        .name = "final-link",
        .transformation = .final_link,
        .output = "/src/app/build/app_kvm.dbg",
    }},
});

const graph = try context.finalize();
_ = graph.selectedPlatform();
```

Validation rejects duplicate names and outputs, inconsistent platform-library
registrations, unknown component/generated/stage references, forward stage
references, and configurations that select zero or multiple platforms.
`lastDiagnostic()` supplies the offending names or paths.

Run the standalone, leak-checked unit tests with:

```sh
zig test support/build/component-api.zig
```
