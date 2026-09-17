# Optional native workload images

These are **correctness-only application integrations**, not qualified images,
hardware measurements, deployment receipts, or a replacement for #88's guarded
request/admission/dispatch work. They reuse the **same** #160 `platform.c`,
caller-selected `uk_alloc`, owned 4 KiB native pages, W^X transitions, honest
Hyper-V monotonic clock and output path. There are no Linux adapters.
The tiny default and its existing `--coremark` option remain unchanged.

## Explicit variants and boot modes

Prepare **one variant in each fresh application worktree**. As with the original
wrapper, preparation refuses existing source/artifact directories rather than
silently replacing previously identified inputs.

| `prepare.py --variant` | Boot application arguments | Actual linked consumer |
| --- | --- | --- |
| `tiny` (default) | unchanged | Original compiler-free tiny check; optional original CoreMarks |
| `snapshot` | none or `correctness` | `wamr-aot.benchmark` / `.runner`, one root |
| `sample-aot` | none or `correctness` | Only `wamr-jit-aot-sample`, compiler-free comparator |
| `jit --jit-mode fast` | none, or exactly `correctness-fast` | Only `wamr-jit`, fixed fast correctness image |
| `jit --jit-mode full` | none, or exactly `correctness-full` | Only `wamr-jit`, fixed full correctness image |

Both matched images import the public `wamr-jit-workload` source module.
They do **not** import both sampler roots or duplicate the SDK's API types.
Fast/full use the same compiler/runtime and workload, but are **separately
identified correctness images**. Preparation requires the explicit `--jit-mode`;
there is no implicit fast default. The existing application Kconfig mechanism
binds `APPWAMRAOT_JIT_BOOT_MODE` to that prepared identity. Each image selects its
fixed preset when ordinary EFI fallback boot supplies only argv[0]. Contradictory
or unknown arguments fail before execution. Arguments cannot change fuel,
heap/code/reservation/compiler limits, input Wasm, exports, rounds or repeats.
Every optional image rejects `measurement` before any execution, with the
explicit diagnostic
`independent-image-deployment-and-memory-qualification-unavailable`.
Request fields are never echoed into independent observations.

### Supported SDK and explicit development selection

All variants use merged WAMR
`a53205d77be3b880eb8f8b96679512ba58e2331a`, including the AOT producer and the
PIC, final-link-owned compiler-runtime sampler APIs. This supported source pin
is not qualified image or deployment lineage:

```sh
python3 support/apps/wamr-aot/prepare.py prepare \
  --source /path/to/local/wamr --variant snapshot
python3 support/apps/wamr-aot/build-image.py olddefconfig
python3 support/apps/wamr-aot/build-image.py native-images
```

Repeat in fresh worktrees with `sample-aot`, `jit --jit-mode fast` and
`jit --jit-mode full`. The selected Git commit
is exported into the application's ignored private build directory; the source
checkout, its branches, dirty files and outputs are never modified.
For local experiments only, an explicit
`--development-revision FULL_40_CHARACTER_LOCAL_SDK_COMMIT` overrides the pin.
Those manifests say `local-development-build-only-not-supported-lineage`.
This escape hatch is **not** an upstream source pin or a qualified deployment.
An explicitly selected development revision also supports local tiny/CoreMark
bridge integration, but its manifest remains development-only and the
credential-free CI adapter refuses it.

The same existing `hyperv-x86_64-efi-wamr` graph produces the real native ELF and
EFI, including its final IRQ/SMP/relocation safety gates. No selector-only or
audit ELF is substituted. A fresh optional solved config provisions a **1 MiB
application stack**; compilation rejects a smaller config. This leaves 256 KiB
for admitted generated frames and 768 KiB for compiler/embedder/callback frames,
but is build provisioning, **not an independently measured/qualified stack
high-water guarantee**. Default tiny stacks are not changed.

The wrapper writes the fixed JIT preset only when creating a fresh `.config`;
compilation refuses a solved-config/header mismatch rather than silently changing
an existing configuration. This uses ordinary Unikraft application configuration,
not a new boot-info or public runner ABI. EFI LoadOptions and the existing
`HYPERV_EFI_STUB_CMDLINE_FNAME` mechanism can carry a matching optional argument,
but are unnecessary. Neither existing miz packaging nor `local_boot` is asked
to invent an argument or an unbound sidecar. The two correctness images cannot
be presented as the single JIT image expected by a future independently qualified
fast/full measurement transport.

All consumers and imported SDK modules are PIC, ReleaseSafe, single-threaded,
x86_64 freestanding SysV, with no red zone, libc, stack checker/protector, unwind
tables or Zig error tracing. The archive does **not** bundle compiler-rt:
Unikraft's existing final link supplies those intrinsics. Preparation records
these real options and commands. The compiler-free comparator has no compiler,
filesystem, subprocess or thread dependency. A JIT compiler is linked only into
the explicit `jit` consumer.

## Real, distinct lifecycles

### Snapshot producer exercise

The `snapshot` image uses the new producer's shared `Session.createCaptured`,
`invoke`, `resetTimed` and teardown APIs, not a parallel runtime implementation.
It embeds the original pinned `unroll4.wasm` (`compute`) and `iv_store.wasm`
(`memory`) and matching external `wamrc --profile=unikraft-x86_64` output.
These are nontrivial, deterministic, self-checking supported workloads: the
compute fixture checks its 100,000,000-round result; memory performs 20,000
rounds of 65,536 byte stores and checks the results. No short/calibration rewrite
is used.

Each workload has a genuine staged load, instantiate/module-start, post-start
snapshot allocation/copy, one first `_start`, then **three separately timed
snapshot resets and calls on that same instance**. The eight-domain lifecycle
comes from the SDK, including memory permissions/contents/logical size, globals,
passive drops, tables/signatures, WASI context and output. The memory exercise
additionally checks that a changed byte is restored by each actual reset.
Setup/reset/call phases stay separate; there is no fabricated steady-state time.
Module-start and each call's real terminal, stdout/stderr and clock/output errors
are serialized before reuse, reset or release.

This is deliberately a `Session` correctness exercise, **not a call to v2
`benchmark.run` with invented deployment metadata**. The full v2 producer's
independent image/placement/RAM/qualification inputs do not exist in this app.
Wiring that measurement entry and guarded physical transport remains separate;
the current entry fails rather than forging a receipt to satisfy admission.
These fixed finite AOT workloads do not acquire a JIT fuel guarantee.

### Matched sampler

`native.sample.run` retains its SDK-enforced fixed caps and verification:
64 MiB compiler retained backing cap, 4 MiB code cap, 100,000 cooperative
compiler polls, 16 MiB runtime heap, 8 MiB runtime reservation, eight linear
pages, sixteen table elements and (JIT only) 100,000 fuel polls per invocation.
Unsupported modules/options fail; checked bounds/imports/traps, W^X and
generated frame/direct-call-depth admission remain intact.

The SDK's exact volatile arithmetic/control/memory source executes four
2,000-round calls with the exact expected result. Each timed call initializes
its own data on the **same instance**. A separately timed real growth after the
first call changes committed linear memory from two to three pages, with stable
eight-page reservation. This is **not snapshot replay or unqualified
steady-state reuse**. Compile/subphases, load, instantiate, explicit start,
growth and calls are independently observed. Comparator compile/fuel fields
stay null. Compile cancellation is cooperative, not hard real time; fuel counts
polls, not time, and cannot preempt native callbacks.

The AOT comparator embeds the matching externally compiled artifact. Preparation
compares its compiler input hash with the **actual generated Wasm file behind
the SDK's imported workload module** and refuses a mismatch. `Capture` stays at
a stable address through `writeRecord`. The SDK releases both the instance and
JIT artifact before return; errors and incomplete teardown cannot print the
application success marker.

## Bounded evidence and memory coverage

`WAMR_JIT_SAMPLE=` stays separate from compiler-free `WAMR_BENCH_RESULT=` v2.
The sampler's request hash identifies the exact fixed
`wamr-native-correctness-only-v1\nMODE\n` bytes, **not a host measurement challenge**.
No success-shaped measurement/deployment receipt is generated. Snapshot records
use separate `WAMR_NATIVE_SNAPSHOT_*` and private invocation evidence markers;
no v2 measurement prefix is emitted at all.

Records use fixed, caller-owned storage; no serial formatting allocator or
filesystem is required. Snapshot output is capped at 4096 combined stdout/stderr
bytes per phase, transmitted losslessly through the SDK's base64 formatter
before clearing. Individual records are at most 16 KiB; sampler records retain
the SDK's tighter 8192-byte maximum including prefix/newline. Output requires
exactly one synchronous UART stdout device and uses `uk_console_out_direct`,
including for the final completion marker. Missing/ambiguous/asynchronous
devices, driver errors and partial writes fail capture without silent retries.
The generic `printf`/`uk_console_out` best-effort path is not evidence transport.

`WAMR_NATIVE_WORKLOAD_BUILD` binds real source-tree, compiler and **actual linked
consumer archive** SHA256 identities. The archive is hashed first; the identity
data is supplied separately by the final C application object, avoiding a
self-hash cycle. Source tree identity hashes sorted compact JSON mapping actual
exported relative file paths to byte counts and SHA256, before generating build
outputs. `build/source-files.json`, exact commands and tool/input hashes stay private.
The external image wrapper hashes the completed EFI and ELF; neither is a
qualified complete-disk/boot identity.

Native callback-boundary observations report reserved VA, owned physical data
frames (including NONE), accessible bytes and caller/adapter requested allocator
bytes separately. Maxima are **observed boundary maxima**, not continuous peaks.
Physical frame coverage is **code/linear pages only**: compiler/runtime allocator
backing, image, stacks, page tables and other kernel allocations are excluded.
Requested allocation counts cannot supply the independently qualified physical
memory coverage required by the native measurement importer. All owned frame,
reservation, accessibility and requested allocation counters must be zero after
teardown. Base adapter page-permission/failure selftests still execute first.

## Validation, without relabeling emulation

```sh
python3 -B -m unittest discover -s support/apps/wamr-aot/tests -v
python3 -B support/apps/wamr-aot/check-workload-log.py \
  --mode snapshot --log /private/exact-boot/serial.log
# Use --mode aot, fast or full for the corresponding matched image;
# those modes reuse the actual source-pinned SDK's strict sampler validator.
```

The bounded checker requires exact workload/build identities, phase/reset/call
counts, exact results and native teardown. It rejects mixed v2/sampler protocols,
duplicate, truncated, failed or oversized records. Its success is only a
**compute correctness check**, not native boot or deployment acceptance.

The checker reuses the inherited native CI serial normalizer: validate UTF-8
**before** removing NUL padding and complete ANSI CSI sequences, then normalize
CRLF to LF. The original capture is limited to 2 MiB and normalized lines to
8192 bytes. Other controls, including standalone CR, DEL and Unicode control/
separator/format characters, are refused. Malformed UTF-8 or escapes cannot
be repaired by extraction. Printable boot context outside the contiguous
workload transcript is retained as context, not boot evidence; nonblank
interleaved noise, unanchored/embedded WAMR markers, crashes and unrelated
acceptance markers fail. Both snapshot and sampler extraction use this path.

The CLI reuses the native CI bounded, regular-file read with change detection.
It never rewrites the log and reports the **complete original capture's**
`raw_serial_bytes` and `raw_serial_sha256`, including framing and boot context.
Normalized text and extracted JSON are only parser inputs, never replacements
for the raw identity in external exact-boot records. This diagnostic is not a
measurement receipt. `-B` avoids creating Python cache files in the reviewed
source closure while loading the shared helper. The framing regressions are
synthetic; observed tiny-image console framing does not qualify optional images.

Use the unchanged existing exact-image EFI/four-boot packaging tools and their
x86 KVM/OVMF prerequisites. A cross-compiled EFI, successful final safety gate,
packaged disk or qemu-user/Linux result is not a native boot or four-boot pass.
Do not weaken those gates on an ARM development host. Independent boot/hardware,
guarded transport and physical memory qualification remain outstanding.

The inherited compute-specific `support/build/wamr-native-ci` packager supports
physical packaging without a boot and avoids the network application's return-2
contract. For an optional EFI check, `uk-hyperv-local-boot --image ...` uses
`--expect-main-return 0` and the exact mode marker (variant 2, mode 1 for fast or
mode 2 for full). Do not pass nonexistent guest-argument flags to that CLI.
Its successful process/image/serial checks and this app's compute validator are
both required; packaging alone is not a four-boot result.
