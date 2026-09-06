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
the final typed library object. `TargetZigObject` separately models Zig source
compiled for the target, including its logical object output, optimization
mode, C include roots/macros, generated-file dependencies, PIC setting, and
frame-pointer policy. `native-target-object.zig` materializes those entries as
`LazyPath` objects with libc disabled, no red zone, no stack checks or
unwinding, single-threaded runtime assumptions, and trap-on-panic behavior.
`LinkStage.sequence` interleaves artifacts,
literal or driver/raw-translated flags, archive-group markers, and system
library arguments without regrouping them. Ordered post-processing
transformations can create several named artifacts or declare an in-place
mutation; later transformations refer to those named results.

## Registered native image graphs

`native-image-graph.zig` registers production metadata for the documented
hello-world `qemu-x86_64`, `qemu-arm64`, and `hyperv-x86_64-efi`
configurations. The metadata is compiled into Zig through
`native-image-data.zig`; it does not load a Make JSON
export at graph construction time. Each profile records:

- every selected library in final-link order, with its ordered object/archive
  inputs, relocatable output, final object, and symbol-file transformations;
- the ordered default and supplemental linker scripts, followed by an
  explicit merged-script stage;
- the complete final-link sequence, including archive group boundaries; and
- the architecture-specific relocation, strip, bootinfo,
  Multiboot/EFI/Linux Image, and compile-database declarations. PIE profiles
  model `mkukreloc.py` as an ordered mutation before any section stripping.

Production `build.zig` constructs and validates one of these graphs with:

```sh
zig build native-link-graph \
  -Dapp=/absolute/path/to/app-helloworld \
  -Dnative-profile=qemu-x86_64
```

Use `qemu-arm64` for the ARM64 profile or `hyperv-x86_64-efi` for the
x86_64 EFI profile. Other names fail explicitly. The older
`-Dnative-qemu-graph` spelling remains an alias for the QEMU profiles. This
step registers metadata only. The `native-images` step uses the same graph to ask
Make for compile-time inputs, then executes the native library links, linker
script merge, final link, post-processing, and output publication:

```sh
zig build native-images \
  -Dapp=/absolute/path/to/app-helloworld \
  -Dconfig=/absolute/path/to/solved.config \
  -Dnative-profile=qemu-x86_64
```

Fixtures under
`tests/native-qemu-graph/` are deterministic projections of `make build-graph`
for the documented Zig/raw compatibility configurations and are checked by
the module tests.

`Source.effectiveInput(config, variant)` resolves conditions and returns the
last active source- or variant-level preprocessing output, or the original
source when the source, variant, or every preprocessing step is inactive.
Finalization uses the same active-step rules for generated references and
output conflicts.

Post-processing describes files, not Make log labels. In particular, the
`.multiboot`, `.efi`, `.bin`, and `.img` labels in `plat/common/Makefile.rules`
do not denote products: the Multiboot, EFI, and Linux helpers mutate the KVM
image in place. Bootinfo additionally creates its real `.bootinfo` side file.
Xen ARM/ARM64 alone creates a separate raw image, which is the input to gzip;
Xen x86 gzip consumes the processed ELF image.

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
The finalized graph retains resolved active-library and selected-platform
link-stage bitmaps so native executors do not need to retain or re-evaluate
the borrowed configuration query.
`lastDiagnostic()` supplies the offending names or paths.

`native-library-link.zig` plans and materializes active library object
pipelines. It uses the configured Zig executable as
`zig cc -target <triple> -nostdlib -r`, passes ordered link inputs without a
shell, validates the resulting ELF for forbidden `SHN_COMMON` symbols, and
then runs the configured objcopy localization sequence. Generated and
component outputs must be supplied as `PathBinding` values so their producing
steps remain tracked; typed library outputs are connected automatically.
Non-Zig compiler drivers are rejected instead of silently adopting Zig's
COMMON-symbol behavior.

Run the standalone, leak-checked unit tests with:

```sh
zig test support/build/component-api.zig
zig test support/build/native-library-link.zig
zig test support/build/elf-common-validator.zig
```

## Native final links

`final-link.zig` plans active `final_link` stages from a `FinalizedGraph` and
executes them through the configured Zig compiler driver. It preserves sequence
order, resolves typed artifacts through a caller-supplied `LazyPath` resolver,
tracks custom dependencies, and replaces all modeled linker scripts with one
generated `-Wl,-T,<path>` argument.

`linker-script.zig` creates that tracked artifact. The first script is the
primary script; later scripts may only contribute ordered `PHDRS` entries or
`SECTIONS { ... } INSERT BEFORE/AFTER <section>` blocks. Malformed scripts,
unknown supplemental commands, duplicate program headers, and missing or
ambiguous insertion anchors are rejected rather than ignored.
