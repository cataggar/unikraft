# Native Hyper-V linked-image proofs

The Zig 0.16 `hyperv-image-proof` executable replaces the three Python proof
subprocesses in `finishNativeImages`. It checks the **final unstripped ELF**,
before relocations, stripping, bootinfo, and EFI wrapping. It never runs the
image, contacts a host/cloud endpoint, or treats link evidence as boot, live
I/O, interrupt delivery, or AP workload acceptance.

## Build and run

```sh
zig build build-hyperv-image-proofs -j2
zig-out/bin/hyperv-image-proof smp --image kernel.dbg --max-cpus 4
zig-out/bin/hyperv-image-proof irq --image kernel.dbg
zig-out/bin/hyperv-image-proof drivers --image kernel.dbg \
  --require-driver storvsc --require-driver netvsc
zig build test-hyperv-image-proofs -j2 \
  -Dproof-nm=/path/to/llvm-nm -Dproof-objdump=/path/to/llvm-objdump
```

Use the solved `CONFIG_UKPLAT_CPU_MAXCOUNT` value, not a guessed CPU count.
Each CLI accepts `--nm` and `--objdump`; defaults are `llvm-nm` and
`llvm-objdump`. Quoted native tool command prefixes use the existing
postprocessor's argument splitter, never a shell or Python fallback.
Repeated driver requirements are deduplicated; at least one is required.
Invocation errors exit 2. Failed proofs, malformed images, and failed,
empty, malformed, or incomplete decoder results exit 1 with `FAIL:` and
the failing subject/error. Successful proofs explicitly disclaim boot evidence.

For constrained validation environments, set `TMPDIR`, `XDG_CACHE_HOME`,
`ZIG_GLOBAL_CACHE_DIR`, `ZIG_LOCAL_CACHE_DIR`, and `--prefix` to the approved
output area before invoking these selectors.

## Assertion-to-native-case coverage

The `hyperv-proof-tests.zig` unit cases and `hyperv-proof-fixtures.zig` native
process cases form one focused aggregate. Fixtures cross-compile real C and
Zig objects with Zig's native toolchain, then link kernel-shaped ELF files.
The C fixture uses the actual VMBus driver structure, `VMBUS_DRIVER_REGISTER`,
constructor, and event macros, with compile-time pointer/descriptor ABI
assertions. The Zig object retains actual protocol getter exports and GUID
constants from `vmbus_protocol.zig`. Both object format/symbols and final linked
bytes are inspected; relocatable objects are refused as final-image proofs.
No Python generator, oracle, proof executor, or install hook is involved.

| Legacy assertion / added byte evidence | Native coverage |
| --- | --- |
| Eight unique strong SMP hooks, not weak/localized fallbacks | All eight weakened in real ELF; localized duplicate definitions; ELF binding plus NM kind/address checks |
| Boot/init/halt call the strong hooks; multicore startup calls `uk_lcpu_start` | Four real call-to-tail-jump refusals; three required global call removals |
| Multiple CPUs do not imply fixed schedcoop | Single-CPU and non-fixed multicore linked fixtures; a single-CPU image refuses a multicore requirement |
| Fixed CPU count uses ACPI; AP entry initializes its logical CPU | Missing/wrong linked calls, indirect AP init, duplicate localized count; fixed and non-fixed positive images |
| Runtime paging symbols occur together, with init/get/activate ordering | Each missing symbol/call and both reorderings; a fixed-SMP image without paging remains valid |
| AP EFER LME/NXE, cleared EDX, correct MSR, CR4 PAE, CR0 PE/WP/PG | Required-bit, MSR, source-register, EDX/EAX/AND clobber, missing/duplicate write and ordering unit cases; real immediate mutations |
| AP controls precede paging enable without intervening control flow | Branch/clobber insertions, control ordering, address-range inspection independent of disassembly label aliases |
| Every present scheduler constructor binds the ISR callback | Actual direct store and shared call/tail-wrapper fixtures; missing, individually unbound, cyclic and unresolved wrapper refusals |
| Actual scheduler callback assignment, not a textual mention | Full-width immediate/register stores; register copies, partial writes, unary clobbers, caller/callee-saved behavior; materialization without a store is rejected |
| Three SynIC/pending callbacks are registered | Real argument materialization for each registration API; each removed independently; SysV RDI/RSI call-site evidence |
| Exactly the reviewed native IRQ event handler | Actual retained event pointer, missing/extra handler entries, and changed pointer refusals |
| Follow linked calls, tail/local branches, and symbol aliases | Real C/Zig graph and aliases; numeric targets are independently checked against relative-branch bytes |
| Reviewed indirect callers and exact counts 1/2/1 | Real event/controller/wake indirect sites; count mutation, indirect tail jump, and unreviewed caller refusals |
| Required IRQ roots, SynIC helpers, protocol getters and ISR wake are reachable | Real returning graph; removal of the ISR wake edge refuses publication |
| No x87/MMX/SSE/AVX/mask/tile state on returning IRQ paths | Register/mnemonic family unit matrix, prefix normalization, real SIMD insertion |
| Only straight-line terminal assertion logging is exempt | Worker-only SIMD logger behind UD2 passes; returning logger and SIMD in the asserting caller fail; branch/call/return/loop barrier cases |
| Unique strong driver registration and unique constructors/entries | Real macro-generated symbols; weak/duplicate registration, absent call and wrong constructor pointer refusals |
| Nonempty ctor bounds, complete slot within bounds, no orphan priority sections | Empty table, entry at end, wrong slot size, and orphan section mutations; linker KEEP retains constructors |
| Actual driver descriptor argument, names, IDs and callbacks | Both drivers: argument removal, 40-byte descriptor/32-byte ID ABI, GUID/sentinel, name/ID/add/remove/optional callback pointers |
| Configured driver requirements remain conditional | Each driver individually, both together, duplicate arguments; corruption of an unrequired driver's GUID does not fail the selected driver |
| Static and PIE pointer evidence | EXEC and DYN fixtures; loaded absolute pointers and `R_X86_64_RELATIVE` RELA; unsupported and ambiguous relocation refusals |
| Native tools cannot supply success-shaped bad evidence | Native mock executable covers nonzero/empty/malformed/truncated NM and objdump; mismatched NM addresses, raw bytes and branch targets |
| Format/bounds/architecture failure is explicit, without panic | Wrong class/encoding/architecture, truncated ELF, empty symtab, and non-executable load segment; shared bounds-checked ELF parser |

Each fixture loop asserts its expected source-site count rather than silently
omitting cases when compiler output changes. Per-fixture `summary.txt` files
are produced in the build's generated output directories.

## Integration and evidence limits

`hyperv-proof-build.zig` supplies the host-native executable and its named
`vmbus_protocol` module. The production `finishNativeImages` runs `smp` and
`irq`, plus `drivers` when StorVSC and/or NetVSC is configured. The existing
validated-output copy depends on every required proof. NM/objdump command
choices and maximum-CPU extraction are unchanged.

`test-hyperv-image-proofs` is also a dependency of the default tests and
`test-hyperv-regression`. The old IRQ helper unittest module was removed from
the Python controller batch because its assertions now run natively. The
unrelated hosted `test-hyperv-irq`, network/controller regressions, and their
existing selectors are unchanged. The broader regression aggregate still
contains unrelated Python/controller tests: use the focused native selector
when Python or cloud/controller actions are prohibited.

`test-native-compiler-options` exercises the actual Make flag-probe macro with
Zig, including PIE and invalid-option cases. Empty C input is supplied through
stdin rather than a device pathname, so an unsupported input type cannot
silently remove required position-independent-code flags.

Supported final images are little-endian ELF64 x86-64 EXEC/DYN with the full
symbol table and loaded executable sections. Native AArch64 hosts can run the
proof tools and cross-decode x86-64 fixtures; ARM64 images are explicitly
refused, not skipped or certified. Decoder output is bounded, newline-complete
AT&T syntax with raw bytes, including LLVM continuation annotations and GNU
wrapped instruction bytes. Configured native decoders remain trusted toolchain
inputs, not an independent instruction decoder. Register proofs deliberately
fail when the required materialization/store cannot be established; they do
not infer pointers through arbitrary stack spills or control-flow joins.
PIE callback/argument evidence must retain a full-width position-independent
address: absolute immediates and narrowed register copies are not accepted.
The selected non-LTO C ABI is SysV x86-64. Embedded real-mode bootstrap code,
GDT bytes, and the post-paging far-transfer suffix are not certified as IRQ
code. Mixed 16/32/64-bit fixture sections exercise the ELF64 decoder's handling
of these bytes; unknown instructions still fail inside the returning IRQ graph
or before the AP paging-enable write. Dynamic pointer proofs support
RELATIVE RELA, not symbol-dependent RELA, REL, or packed RELR.

The shared ELF parser's explicit `allow_relocatable` option exists only for
object-fixture inspection; its normal postprocessing/final-image API still
rejects ET_REL. The three original Python drivers and their helper regressions
remain dormant staged-cutover references for other explicit callers. This
change does not remove them from legacy producer closures, refresh either
producer-pin map, or replace unrelated controller Python. Integration must add
the new native sources/fixture dependencies to the complete producer closure;
the parent owns that refresh and the exclusive full guest build.
