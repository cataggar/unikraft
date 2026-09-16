# Compiler-free native WAMR correctness image

This is a **distinct application**, `appwamraot`, and native Zig profile,
`hyperv-x86_64-efi-wamr`. It is not the hardware, storage, or HTTP probe.
The default embeds a tiny trusted AOT module: `answer()` must return 42,
`memory.grow(1)` must return the previous two-page size, and `trap()` must
produce the explicit unreachable terminal outcome. No guest compiler,
filesystem, network, or host-thread dependency is added for WAMR.

Refs #156, [cataggar/wamr#1045](https://github.com/cataggar/wamr/issues/1045)
and [cataggar/wamr#1046](https://github.com/cataggar/wamr/issues/1046).
The freestanding benchmark producer and optional JIT sampler are separate
dependent integrations; this application produces **no benchmark score**.

## Build the actual EFI image

Use Zig **0.16.0**, Python 3, Make, Bison/Flex (including their usual
`yacc`/`lex` names), M4, Bash, and LLVM binary tools on PATH. From the
Unikraft checkout:

```sh
python3 support/apps/wamr-aot/prepare.py prepare --source /path/to/wamr
python3 support/apps/wamr-aot/build-image.py olddefconfig
python3 support/apps/wamr-aot/build-image.py native-images
```

`prepare.py` exports exactly WAMR
`2399694fb7ed11fffff0a34c82172dfdd54d7439` from the local Git object
database into this application's ignored `build/wamr-source/`. It never
builds in, changes, or inherits uncommitted files from the source checkout.
It builds that revision's host `wamrc`, its freestanding library audit,
then the integration archive. The tiny wasm is genuinely generated from
`fixture.zig` and compiled with `--target=x86_64
--profile=unikraft-x86_64`. Hosted artifacts are not renamed or relabelled.
Only trusted output of this pinned producer is admissible.

The integration archive explicitly uses x86_64 SysV, PIC, no red zone,
stack protector, stack checking, unwind tables, libc, or error tracing, and
single-threaded Zig support. ReleaseSafe checks remain enabled. Two necessary
differences from the baseline standalone archive are recorded:

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

`build/artifacts/identity.json` retains source/tool/wasm/cwasm/library
identities and exact options. Make verifies the generated artifacts before
compiling. `build/image-identity.json` records the entire final EFI and debug
ELF, solved config, application source hashes, Unikraft revision/diff, input
manifest and tool hashes. Rebuild after committing for a clean revision
identity. These are **build records, not deployment or hardware receipts**.
Keep `build/` private. Re-preparation deliberately refuses existing artifact
or source-export directories; use a fresh worktree or remove only those two
generated directories after retaining needed evidence.

## Memory ownership and failure paths

`platform.c` is specific to the pinned native x86_64 PAL, direct-mapped
page tables, four-level paging, buddy frames and one CPU:

* Runtime and mapping metadata use the **explicit caller-selected
  `uk_alloc`**, `uk_posix_memalign` and `uk_free`. Requested alignment is
  preserved; there is no hidden allocator fallback.
* A reservation is one custom `uk_vma_map` VMA with **no populate/fault/
  advise/set-attribute handler**. Its split and merge hooks deny both
  operations. Metadata and the VMA are one owned allocation. Addresses are
  stable and initially inaccessible; no virtual hole is guessed.
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
backing are not. `system_page_table_bytes` is the actual **whole active
page table's** counter, not guest frames and not a zero-on-teardown claim.

`selftest.c` runs before the fixture. It checks real alignment/zero filling,
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
allocation-free `wasi/minimal.zig`, not another WASI implementation.
It preserves exactly its twelve `wasi_unstable` signatures, guest-pointer
checks, descriptor state, partial-write progress/deferred errors, full u32
`proc_exit`, returned/trap/host-error distinctions and fresh-instance lifetime.

Each guest receives only `coremark 0 0 0 100 0`, an empty environment and
bounded caller-owned stdout/stderr buffers. Known consumed bytes, including
partial failure prefixes, are preserved in canonical base64 records. Pending
errors are inspected before destroying the context and prevent success.
No output byte is silently replaced by a debug logger.

Only real Hyper-V **monotonic nanoseconds** are supplied, at the reference
source's **100 ns resolution**. `UINT64_MAX`/provider saturation fails.
Realtime is unsupported without a qualified EFI epoch; process/thread CPU
time is unsupported. An unsupported guest clock request is retained and
prevents qualification. No clock is fabricated to make CoreMark pass.
Short CRC checks retain the “Must execute for at least 10 secs” diagnostics.
Printed timing/throughput text in the preserved guest output is **not a
benchmark score**. No reuse/replay or performance lifecycle is claimed here.

## Existing packaging and exact-image boot

Use the existing native
[`public_image` tool](../../tools/hyperv/public_image/README.md) with
`--efi /absolute/.../build/wamr_hyperv-x86_64-efi` and
`--expect 'WAMR_NATIVE_AOT_OK answer=42 teardown=0'`. It uses pinned native
**miz** and the existing four-boot exact raw/fixed-VHD matrix. Do not pass
the network application's solved-config contract or export a networking
receipt. Retain the full raw disk and fixed-VHD hashes, including the footer.
Do not substitute a `.text` hash, hosted binary or earlier EFI for that image.

For an initial EFI-only local check, use the existing native
[`uk-hyperv-local-boot`](../../tools/hyperv/local_boot/README.md) with that
exact EFI, one CPU, real canonical QEMU/OVMF inputs and the same marker.
After the boot tool's crash/termination/exact-input checks pass, validate
the private serial record:

```sh
python3 support/apps/wamr-aot/check-log.py \
  --log /private/attempt/hyperv-efi-boot.log \
  --identity support/apps/wamr-aot/build/artifacts/identity.json
```

This checks runtime/workload identities, exact 42 result, trap detail,
teardown accounting and optional original CRC output. It is an additional
compute check, **not a replacement for exact-image boot validation**.

No Azure provisioning, cloud dispatch, hardware acceptance, networking,
storage, performance, or resource-cleanup claim is made by this work.
Native boot/pressure/permissions qualification and both CRC executions
remain external until the exact image is run on an appropriate x86 KVM/
Hyper-V host. The implementation host is ARM with no `/dev/kvm`, x86 QEMU
or OVMF: its native boot attempt was refused, not counted as a passing run.

## Focused developer checks

```sh
zig test build.zig --test-filter 'native WAMR'
zig test support/build/native-image-graph.zig
zig build test-hyperv-image-proofs test-native-compiler-options -j2
python3 -m unittest discover -s support/apps/wamr-aot/tests -v
```

The host parser fixtures are explicitly synthetic and never become native
evidence. Actual native compilation and the existing linked-image proofs
are separate from executing the in-image memory checks.
