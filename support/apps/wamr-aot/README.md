# Compiler-free native WAMR correctness image

This is a **distinct application**, `appwamraot`, and native Zig profile,
`hyperv-x86_64-efi-wamr`. It is not the hardware, storage, or HTTP probe.
The default embeds a tiny trusted AOT module: `answer()` must return 42,
`memory.grow(1)` must return the previous two-page size, and `trap()` must
produce the explicit unreachable terminal outcome. No guest compiler,
filesystem, network, or host-thread dependency is added for WAMR.

Refs #156, [cataggar/wamr#1045](https://github.com/cataggar/wamr/issues/1045)
and [cataggar/wamr#1046](https://github.com/cataggar/wamr/issues/1046).
The optional [snapshot guest and matched JIT/AOT sampler images](WORKLOADS.md)
are explicit dependent integrations. The default remains this tiny,
compiler-free image; all current application modes produce **no benchmark score**.

## Build the actual EFI image

Use Zig **0.16.0**, Make, Bison/Flex (including their usual `yacc`/`lex`
names), M4, Bash, LLVM binary tools, and Python 3 for the still-native
Make graph and separate log validators. Python does **not** prepare or
verify artifacts, solve the config, or build the native image. From a
clean Unikraft checkout with a fresh application output root:

```sh
umask 077
tool_root="$PWD/support/apps/wamr-aot/build/tool"
test ! -e "$tool_root"
zig build --build-file support/apps/wamr-aot/build.zig \
  --prefix "$tool_root" -Doptimize=ReleaseSafe install
tool="$tool_root/bin/uk-wamr-aot-build"
"$tool" prepare --repository "$PWD" --source /path/to/wamr
"$tool" verify --repository "$PWD"
"$tool" olddefconfig --repository "$PWD"
"$tool" native-images --repository "$PWD"
```

`uk-wamr-aot-build prepare` exports exactly WAMR
`a53205d77be3b880eb8f8b96679512ba58e2331a` from the local Git object
database into this application's ignored `build/wamr-source/`. It never
builds in, changes, or inherits uncommitted files from the source checkout.
It builds that revision's host `wamrc`, its freestanding library audit,
then the integration archive. `prepare` requires `llvm-objcopy` to remove
checkout-dependent debug sections, then checks the single Zig object member
and uses pinned `zig ar` to repack it with a stable basename. The original
archive's long-name table otherwise records an absolute, checkout-dependent
cache path. These supervised commands retain linkable symbols and are included
in the verified producer plan. The tiny wasm is genuinely generated from
`fixture.zig` and compiled with `--target=x86_64
--profile=unikraft-x86_64`. Hosted artifacts are not renamed or relabelled.
Only trusted output of this pinned producer is admissible. The adapter installs
the **same app-owned executable**, binds its physical ELF identity as the
`native:wamr-aot-build` role for all three production stages, and never selects
an interpreter or a Python producer fallback. `Makefile.uk` calls this tool's
`verify` through `APPWAMRAOT_TOOL`; direct Make users must install it first.
All four commands require `--repository` with the canonical absolute checkout
path. For supervised CI, `prepare` takes the sealed `--source-archive` instead
of `--source`; it is incompatible with `--development-revision`.

The same merged SDK supplies the single-root CoreMark bridge and optional
workloads in [WORKLOADS.md](WORKLOADS.md). This source pin does not establish
native boot, hardware or measurement qualification.

The integration archive explicitly uses x86_64 SysV, PIC, no red zone,
stack protector, stack checking, unwind tables, libc, or error tracing, and
single-threaded Zig support. ReleaseSafe checks remain enabled. The wrapper
records the actual required native-link properties:

* **PIC** is necessary for Unikraft's EFI PIE link; non-PIC absolute 32-bit
  relocations are not compatible.
* Compiler intrinsics are supplied by the existing native final link rather
  than bundled twice. The duplicate Zig archive would otherwise hide the
  strong native `memcpy`/`memset` symbols used by the IRQ binding proof.

The native build still uses the existing object graph, library/final link,
SMP/IRQ proofs, relocation and EFI post-processing. No gate is skipped.
SSE/FPU remain enabled for ordinary application objects, including WAMR;
they are not compiled as ISR objects. The returning IRQ register restriction
and existing scheduler/FPU ownership contract remain in force.

The solved config explicitly enables `LIBUKVMEM`, `LIBUKPAGING`, paging
statistics and the buddy frame allocator. `ukboot` initializes and selects
the kernel VAS; the application verifies both its VAS/page-table identity
and hardware CR3 before use. Admission requires one CPU; five-level paging
and storage/network-probe configurations are refused.

`build/source-files.json` holds the sorted compact source-file byte-count/hash
map, with one final LF. `build/artifacts/identity.json` is pretty schema 1 and
retains source/wasm/cwasm/library identities, options and a verified command
plan with portable `<app>`, `<source>`, `<zig>` and `<objcopy>` roles. The
supervised physical commands and working directories remain in owner-private
diagnostics; the image record separately pins tool bytes. Its
`prepare_source_sha256` hashes tracked `build-tool-prepare.zig`.
Make verifies the generated artifacts before compiling.
`build/image-identity.json` is pretty schema 1 and binds complete EFI, debug
ELF and bootinfo bytes, solved config, application/build-tool source hashes,
clean Unikraft revision/diff, input manifest and tool hashes; its mode is
`0600`. Rebuild after committing for a clean revision identity. These are
**build records, not deployment or hardware receipts**.
Keep `build/` private: output/cache directories are `0700`, private config,
JSON and diagnostics are `0600`, and the host compiler is executable/private
`0700`. Preparation is create-only for `build/artifacts`,
`build/wamr-source` and `build/workload-consumer`; a collision or partial
failure refuses rather than overwriting evidence. Use a fresh worktree for
another preparation. Config/image state can be reused but an existing
`.config` is not silently rewritten. A failed/changed tool, source or child
refuses with a bounded diagnostic, retains private failure records and does
not publish a new success identity.

`BISON_PKGDATADIR` can explicitly select a private, absolute Bison data
directory. The existing native Make environment guard still validates it;
an invalid override never falls back to ambient data. Hosted CI reuses the
authenticated package-data acquisition rather than writable `/usr/share`.
When `WAMR_CI_PORTABLE_CONFIG=1` is selected for paired CI, Make derives
`HOSTUTC` from the verified source commit's UTC timestamp instead of each
image build's wall clock. This keeps the loadable `.uk_libinfo` metadata
reproducible across source worktrees without changing Kconfig or the
application's ordinary build-time metadata.
For supervised config and image builds, `WAMR_CI_EXECUTABLE_PATH` names the
supervisor's physical installed executable. The producer binds its physical
identity to the supervisor's retained descriptor and its bytes to the
running `/proc/self/exe` snapshot before passing the path to the root build;
an ambient path naming another executable is refused. Direct invocations
continue to resolve and physically verify their own executable.
After the trusted root `native-images` command, a metadata-only rewrite of
`build/.config` is accepted only if its private-file policy, ownership, mode,
size and solved bytes still match the retained pre-build config. The rebound
file remains strictly bound through identity publication; changed bytes and
subsequent rewrites are refused.

## Memory ownership and failure paths

`platform.c` is specific to the pinned native x86_64 PAL, direct-mapped
page tables, four-level paging, buddy frames and one CPU:

* Runtime allocations use the **explicit caller-selected `uk_alloc`**,
  `uk_posix_memalign` and `uk_free`. Requested alignment is preserved;
  there is no hidden allocator fallback. VMA storage uses the initialized
  **VAS allocator**, because ukvmem owns its final `uk_free(vas->a, vma)`.
  These allocators may be different.
* A reservation is one custom `uk_vma_map` VMA with **no populate/fault/
  advise/set-attribute handler**. Its split and merge hooks deny both
  operations. Metadata and the VMA are one allocation owned by ukvmem
  after successful mapping. The destroy callback only unregisters and
  accounts it; it must not free storage that ukvmem subsequently reads
  and frees. A failed map has no populate/replacement stage and leaves
  that allocation caller-owned for cleanup. Addresses are stable and
  initially inaccessible; no virtual hole is guessed.
* Commit prevalidates the complete inaccessible range and maps real frames
  eagerly, one forced **4 KiB** leaf at a time. On frame or intermediate
  page-table allocation failure it unmaps every newly mapped leaf and empty
  intermediate table, restoring pre-existing hidden PTEs. Previously
  accessible bytes and reservation ownership are unchanged. Zero filling
  occurs only after every fallible mapping has succeeded.
* Protection changes use existing native leaf slots, not
  `uk_vma_set_attr`'s fatal/splitting path. RW is present+RW+NX, RX is
  present+read-only+executable, and NONE explicitly clears PRESENT.
  The native `pte_create(attr=0)` still produces a readable page and is
  **not** used to implement NONE. Every changed entry is invalidated in
  the active CPU's TLB. There is no RWX mode.
* NONE retains physical ownership and bytes in a saved present PTE.
  Restoring RW preserves bytes; recommitting NONE zeroes them.
  Nonzero hidden entries keep their leaf tables alive during neighboring
  rollback. On complete release hidden pages are restored RX solely so
  ukpaging cannot skip their ownership, then all pages are unmapped.
* Exact, nonmerged VMAs eliminate teardown splitting/allocation.
  Forced-small-page unmap cannot enter the fallible large-page split path.
  At this revision native PAL PTE reads/writes are direct memory accesses
  returning zero; page-table mappings are direct-map translations.
  Buddy freeing of **valid uniquely owned** frames has no allocation path.
  The adapter's ownership restrictions exclude buddy's out-of-zone and
  double-free errors. Every returned paging/VMA teardown error is checked
  as an invariant failure, never silently reported as successful release.

This reasoning is not a general guarantee for other PALs, frame allocators,
SMP, competing VMA mutation, corrupted kernel state, or arbitrary native
code. Kernel libraries share a protection domain, including the platform's
existing direct-map aliases. RX at the WAMR mapping is not a claim that
arbitrary kernel code cannot write physical memory through another alias.
Wasm bounds/import checks and explicit traps are unchanged.

Accounting distinguishes reserved VA, owned physical data frames (including
NONE), accessible committed bytes, and allocator-requested runtime/adapter
bytes. VMA metadata is included in the latter; allocator overhead and heap
backing are not; requested bytes from both explicit allocator owners are
counted, not just the runtime heap. `system_page_table_bytes` is the actual **whole active
page table's** counter, not guest frames and not a zero-on-teardown claim.

`selftest.c` runs before the fixture. Distinct runtime/VAS allocator probes
check allocator-specific allocation denial, correct-owner frees exactly
once, two live reservations released out of order, and teardown with
metadata allocation denied. It also checks real alignment/zero filling,
stable earlier bytes after failed growth, PTE permissions and reactivation,
and full release with hidden pages and an uncommitted suffix. A scoped
allocator proxy injects actual native frame/page-table allocation denial
at early and leaf-table-boundary positions and checks real frees and frame
balance. It restores allocator and IRQ state on every return. Teardown
runs while allocations are completely denied. These checks are compiled
into the image; **only a real native boot executes them**.

## Optional minimal WASI / CoreMark

Add `--coremark` to fresh preparation to embed **both original pinned**
`coremark_wasi.wasm` and `coremark_wasi_nofp.wasm`, compiled ahead of time
by the matching host compiler. `wasi.zig` is a small C bridge to the pinned
allocation-free `wamr-aot.benchmark.wasi`, not another WASI implementation.
It imports that single public SDK root, sharing its actual WASI/API types.
It preserves exactly its twelve `wasi_unstable` signatures, guest-pointer
checks, descriptor state, partial-write progress/deferred errors, full u32
`proc_exit`, returned/trap/host-error distinctions and fresh-instance lifetime.

Both original guests request realtime clock ID 0. The bridge enables it
**only** through the explicit native capability described below. Firmware
without qualified UTC semantics remains unsupported: the record reports
`realtime_supported:false` and the unchanged external validator refuses
it even if CRC fields happen to match. A native boot with a qualified
source, followed by both actual CRC executions, is still required.
Compilation and hosted tests are not evidence that this occurred.
The tiny image and its memory checks have no realtime dependency.

Each guest receives only `coremark 0 0 0 100 0`, an empty environment and
bounded caller-owned stdout/stderr buffers. Known consumed bytes, including
partial failure prefixes, are preserved in canonical base64 records. Pending
errors are inspected before destroying the context and prevent success.
No output byte is silently replaced by a debug logger.

Hyper-V **monotonic nanoseconds** remain ID 1, at the reference source's
**100 ns resolution**. Realtime uses a validated EFI Unix epoch plus
Hyper-V reference elapsed time, never the monotonic origin as an epoch.
`UINT64_MAX`/provider saturation fails. Process/thread CPU time remains
unsupported. An unsupported guest clock request is retained and prevents
qualification. No clock is fabricated to make CoreMark pass.
CRC admission in both guest and host requires unique exact key/value
fields for all five CRCs, context zero and 100 iterations. Only the
documented short-duration warning and its `Errors detected` summary are
allowed; CRC error diagnostics, expected-value mentions, duplicate or
extra-context fields, truncation and unexpected stderr are rejected.
Short CRC checks retain the “Must execute for at least 10 secs” diagnostics.
Printed timing/throughput text in the preserved guest output is **not a
benchmark score**. No reuse/replay or performance lifecycle is claimed here.

### Native EFI realtime capability and its limits

The supported source is deliberately a conservative subset of UEFI
[GetTime / EFI_TIME_CAPABILITIES](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html#gettime):

* The existing pre-exit Hyper-V discovery checks must succeed.
  `uk_efi_main()` calls `ukplat_efi_pre_exit()` before boot-info memory-map
  construction and `ExitBootServices`. The hook brackets its one real
  Microsoft-ABI `GetTime(&time, &capabilities)` call with partition reference
  counter MSR reads. Missing fields start invalid/unknown, not implicitly UTC.
* `efi_clock.h` requires **explicit `TimeZone == 0` and `Daylight == 0`**.
  `EFI_UNSPECIFIED_TIMEZONE` (2047) is not evidence of UTC. All nonzero
  timezones, daylight flags (including valid adjustment flags), unknown
  bits, and invalid timezone values are unsupported by this capability.
  This is a refusal policy, not a guessed timezone sign or DST correction.
* Gregorian month/day/leap-year validation reuses `uktimeconv` helpers.
  Checked conversion supports positive Unix nanoseconds through
  `UINT64_MAX - 1`; zero, pre-epoch, invalid calendar and overflow/sentinel
  values cannot qualify. A checked January-1 conversion plus a bounded
  remainder avoids the legacy converter's whole-date multiplication wrap.
* EFI `Resolution` is **counts per second**, not nanoseconds or accuracy.
  Reporting resolution is conservatively
  `max(ceil(1e9 / Resolution), 100)` ns. Zero and `UINT32_MAX` capability
  values, invalid BOOLEAN representations, and unknown accuracy are refused.
  `SetsToZero` describes **SetTime** behavior only; it does not justify
  discarding or manufacturing GetTime subseconds.
* EFI `Accuracy` is a **rate error in 1E-6 ppm (parts per trillion)**.
  It is retained as `efi_accuracy_pptrillion`, not converted into an
  absolute epoch-error promise. The bracket width is retained separately
  as `sample_span_ns`; the epoch is anchored at the bracket's final tick.
  Interpolation improves neither firmware UTC correctness nor its initial
  sampling uncertainty. No synchronization to an external UTC authority,
  absolute epoch accuracy, or Hyper-V frequency-error bound is attested.

The validated sample is copied into kernel-owned static storage in `time.c`
before the EFI handoff. It is not a pointer into firmware memory and is
immutable after early boot. Native boot info remains **version 1, 80 bytes**;
its `efi_st` field is still a system-table address, not a UTC attestation.
There is no serialized clock/shim field or boot-info ABI change. EFI entry
relocation, `uk_efi_jmp_to_kern()` and the existing page-table/IRQ handoff
remain unchanged. No GetTime/runtime-service call is introduced after
ExitBootServices or memory initialization.

`hyperv_clock_realtime(caps, ns)` is a separate **version-1 C capability
ABI**, leaving the pinned WAMR config ABI and legacy native wall-clock and
monotonic policies in place. It returns zero only with both outputs valid:

| Capability field | Contract |
| --- | --- |
| `version`, `source` | 1, 1 (`HYPERV_REALTIME_EFI_UTC`) |
| `resolution_ns` | Conservative reporting resolution above |
| `efi_accuracy_pptrillion` | Firmware-reported rate error, not epoch accuracy |
| `reserved` | Must be zero |
| `sample_span_ns` | Pre-exit GetTime bracket width in ns |

The 32-byte layout is checked on the C and Zig sides. `-ENOTSUP` means no
qualified sample; `-EOVERFLOW` means invalid/regressing reference ticks or
saturated arithmetic. Outputs are untouched on error. The running source
is the existing sequence-checked Hyper-V reference-TSC page with checked
scale/offset, or its partition-counter MSR fallback. Both use 100 ns ticks.
The qualified path refuses sentinel ticks and wrap/regression rather than
treating them as valid elapsed time. It reuses the saturating delta/add
helpers without changing legacy callers' behavior.

The WASI bridge binds the actual capability, uses it for ID 0 reads, checks
provider status/ABI/metadata and zero/sentinel timestamps again, and fails
closed if the provider changes or fails during execution. The bounded
record carries actual support, capability version/source/resolution,
firmware rate error and sample span; `epoch_accuracy_ns:null` explicitly
means no absolute accuracy claim. No validator requirement is relaxed.

**Extension boundary:** non-UTC/DST or unspecified-timezone firmware needs
an independently justified native conversion/provenance policy, or a real
qualified time source. A build flag, assumed cloud/OVMF UTC convention,
static date, imported boot record, or monotonic-only fallback is not such
a policy. This hook intentionally stays unsupported on those sources.
Even explicit UTC fields are firmware declarations, not hardware receipts;
actual source behavior still needs native execution/qualification.

## Existing packaging and exact-image boot

Use the compute-specific
[`wamr-native-ci` adapter](../../build/wamr-native-ci/README.md), which composes
the existing pinned native **miz** package/inspect machinery and
`local_boot` four-boot exact raw/fixed-VHD matrix with main return 0.
The network application's `public_image prepare` return-2 contract is not a
WAMR boot contract and cannot be changed with `--expect` alone. Do not pass its
solved-config contract or export a networking receipt. Retain the full raw disk
and fixed-VHD hashes, including the footer.
Do not substitute a `.text` hash, hosted binary or earlier EFI for that image.

For an initial EFI-only local check, use the existing native
[`uk-hyperv-local-boot`](../../tools/hyperv/local_boot/README.md) with that
exact EFI, one CPU, real canonical QEMU/OVMF inputs and the same marker.
After the boot tool's crash/termination/exact-input checks pass, validate
the private serial record with the installed native validator:

```sh
zig build --build-file support/apps/wamr-aot/validator.build.zig \
  --prefix "$PWD/.d/wamr-validator" -Doptimize=ReleaseSafe install
"$PWD/.d/wamr-validator/bin/uk-wamr-log-validate" tiny \
  --log /private/attempt/hyperv-efi-boot.log \
  --identity support/apps/wamr-aot/build/artifacts/identity.json \
  --legacy-apic forbidden --output json-v1
```

This checks runtime/workload identities, exact 42 result, trap detail,
teardown accounting and optional original CRC output. It is an additional
correctness-only compute check, **not a replacement for exact-image boot
validation**. The production tiny adapter invokes this installed executable
through its closed, identity-bound native command supervisor; there is no
Python validator fallback and no CoreMark production image profile.

Use `--legacy-apic required` for a legacy xAPIC boot; omit it for the
standalone developer check. `--output json-v1` emits exactly one compact
`uk.wamr.log-validation` version-1 object and LF, with `mode=tiny`, the
**raw** capture byte count/SHA-256 and the checked `compute` object. The
CLI does not infer a path, select a workload override or run a Python
fallback. Validation failure returns 1 with empty stdout and one bounded,
path-free stderr line; CLI usage returns 2.

No Azure provisioning, cloud dispatch, hardware acceptance, networking,
storage, performance, or resource-cleanup claim is made by this work.
Native boot/pressure/permissions qualification remains external until the
exact image is run on an appropriate x86 KVM/Hyper-V host. Both CRC
executions additionally require firmware admitted by the realtime capability above.
The implementation host is ARM with no `/dev/kvm`, x86 QEMU
or OVMF: its native boot attempt was refused, not counted as a passing run.

## Focused developer checks

The app-owned native validator reuses optioned local-boot serial normalization,
no-follow bounded raw input/SHA-256 snapshots, canonical bounded base64 and
the bounded Hyper-V JSON contracts. Its shared tiny/CoreMark parser checks
exact record identity, boot order, return-0, zero accounting and independent
CoreMark stdout (including literal `[0]crclist`, `[0]crcmatrix`, `[0]crcstate`
and `[0]crcfinal` keys), stderr, realtime support and termination. Direct
validation calls this same core in its stricter tiny-only scope: it still
refuses WASI/CoreMark. The optional-mode library also validates complete,
ordered snapshot/setup/reset/invocation and matched AOT/fast/full transcripts,
including the source-pinned sampler's exact keys, identity, request hash,
limits, memory growth and teardown. Required-subset guest records retain
extension fields; the sampler and fixed nested objects retain exact fields.
The app, CI adapter and direct build install the **same shared** native CLI
source. The CI adapter records it as `native:wamr-log-validate` in the
consumer-tool custody and dispatches it for every production tiny boot with
the exact APIC argv, an empty environment, bounded output and supervised
executable identity. Its result must retain the raw serial count/SHA-256 and
the unchanged compute evidence object; changed inputs/tools refuse. The direct
controller already calls the shared parser in-process for its stricter
tiny-only serial scope. Run synthetic unit/property/fault, C oracle and native
CLI integration fixtures without building or booting an image:

```sh
zig build --build-file support/apps/wamr-aot/validator.build.zig -Doptimize=ReleaseSafe test
```

The native golden and property cases cover the former parser mutation matrices;
the retained independent C `coremark.h` oracle checks actual CoreMark bytes.
The local-boot terminal/crash check is represented by native envelope tests.
Optional Unicode printability is pinned to Python 3.12's Unicode 15 domain,
not the host Python version: native goldens include Unicode 16-only rejection
ranges and printable Unicode 15 boundary cases.

```sh
zig build --build-file support/apps/wamr-aot/build.zig test-unit test-integration
zig test build.zig --test-filter 'native WAMR'
zig test support/build/native-image-graph.zig
zig build test-hyperv-image-proofs test-native-compiler-options -j2
zig build test-hyperv-clock -j2
```

The app's native tests own producer golden bytes/modes, image command plans,
refusals and supervision faults; the former parser-only Python tests have
been replaced by native golden/property and CLI fixtures. The compute controller/boot/handoff Python
surface belongs to later #186/#187/#189 migrations, not a producer fallback.

After preparation, run the hosted WASI bridge clock tests with the pinned
source export (on an ARM host, append `--test-cmd /path/to/qemu-x86_64
--test-cmd-bin` to execute the **Linux test binary**, not an EFI image):

```sh
zig test -target x86_64-linux-musl \
  --dep wamr-aot -Mroot=support/apps/wamr-aot/wasi.zig \
  -target x86_64-linux-musl --dep minimal-wasi --dep native-wasi \
  -Mwamr-aot=support/apps/wamr-aot/build/wamr-source/src/aot_native.zig \
  -target x86_64-linux-musl \
  -Mminimal-wasi=support/apps/wamr-aot/build/wamr-source/src/wasi/minimal.zig \
  -target x86_64-linux-musl --dep minimal-wasi \
  -Mnative-wasi=support/apps/wamr-aot/build/wamr-source/src/wasi/native_aot.zig \
  --test-filter clock
```

`test-hyperv-clock` exercises the production calendar helpers, actual EFI
time-structure layout, overflow/invalid-source refusals, and `time.c`'s
handoff/getter with the existing hosted native SMP test doubles. WASI
tests inject synthetic capability values and check exact ID 0 guest-memory
writes and untouched outputs on refusal; they do not execute CoreMark.

The host parser fixtures exercise the production C parser and independent
Python validator. They are explicitly synthetic and never become native
evidence. Actual native compilation and the existing linked-image proofs
are separate from executing the in-image memory checks.
