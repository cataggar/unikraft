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
The allocator fixture also includes the actual `uk/alloc.h` and native ECTX
header, checks their pointer offsets/size/alignment, and uses a real bounded
bump allocator. Native unit tests and the complete linked-fixture matrix run
against both Debug and ReleaseSafe proof executables. No Python generator,
oracle, proof executor, or install hook is involved.

| Legacy assertion / added byte evidence | Native coverage |
| --- | --- |
| Eight unique strong SMP hooks, not weak/localized fallbacks | All eight weakened in real ELF; localized duplicate definitions; ELF binding plus NM kind/address checks |
| Boot/init/halt call the strong hooks; multicore startup calls `uk_lcpu_start` | Four real call-to-tail-jump refusals; three required global call removals |
| Multiple CPUs do not imply fixed schedcoop | Single-CPU and non-fixed multicore linked fixtures; a single-CPU image refuses a multicore requirement |
| Fixed CPU count uses ACPI; AP entry initializes its logical CPU | Missing/wrong linked calls, indirect AP init, duplicate localized count; fixed and non-fixed positive images |
| Runtime paging symbols occur together, with init/get/activate ordering | Each missing symbol/call and both reorderings; a fixed-SMP image without paging remains valid |
| AP EFER LME/NXE, cleared EDX, correct MSR, CR4 PAE, CR0 PE/WP/PG | Required-bit, MSR, source-register, EDX/EAX/AND clobber, missing/duplicate write and ordering unit cases; real immediate mutations |
| AP controls precede paging enable without intervening control flow | Branch/clobber insertions, control ordering, address-range inspection independent of disassembly label aliases |
| Every present scheduler constructor binds the ISR callback | Actual direct store, allocated-object shared initializer, call/tail-wrapper and nullable return fixtures; missing, individually unbound, cyclic and unresolved wrapper refusals |
| Actual destination and object, not merely callback materialization | Consumer-derived global slot or object field; displacement-only redirection to `registered_driver`, wrong object field and bypassed initializer store all fail |
| Callback facts survive only valid register/memory operations | Full-width immediate/register stores, copies, stack spills, partial/unary/exchange writes, caller/callee-saved effects; overlapping stores and escaped-stack writes invalidate facts and publication |
| Every operand and implicit GP write participates in provenance | Real LLVM `imulq $0, %rdi, %rdi` registration refusal and `$1` positive case; numeric multiplication, MUL/DIV/CPUID/RDTSCP and unknown-operation units |
| Constructor vector stores use their actual footprint | Real XMM16/YMM32/ZMM64 boundary fixtures, including YMM at callback-minus-24, ZMM at callback-minus-56, exact-slot and non-overlap cases; scalar SSE widths and merge-mask uncertainty units |
| High-byte aliases cannot borrow low-byte values or parent-register identity | All AH/CH/DH/BH slices, differing high/low bytes, partial knowledge, MOVZX, TEST/CMP/sign branches, high-byte writes and SETcc; real LLVM positive/negative constructor branches and unchanged AP full-register requirements |
| Mask-decorated stores cannot retain spilled pointers/lengths or invent zero | Real masked ZMM stack overlap/disjoint and zero-branch fixtures; XMM/YMM/ZMM potential-write boundaries and preserved disjoint heap/stack facts |
| Unmodeled address syntax is not a harmless unknown non-stack write | Checked write-address decoding; real GS and address-size-override refusals, retained prefix metadata, malformed masks/indexes/extra fields, and implicit-string footprint refusals |
| SMP map/queue/worker effects preserve the published object | Heap constructor, bounded two-CPU map, retained tail pointer, independent thread allocation and actual indirect `thread_add` member at offset 8; map/queue redirection and helper/method overwrites refuse |
| Partial values, flags and stack slots cannot manufacture bindings | Narrow pointer-load, partial scalar/null return, CMPXCHG flag, compare-snapshot, CALL return-address and masked-vector stack-argument regressions |
| Memory TEST uses bitwise flags, never CMP's operand-zero comparison | All four widths with nonzero and unknown stack cells; real LLVM constructor branch inversions, preserved CMP-zero behavior, width-masked zero/sign results, stale-flag clearing and high-byte register masks |
| Own-stack origin cannot become an apparently unrelated scalar address | Parent LEA/MOVL/store regression; same/different-register copies, MOVZX/MOVSX, partial writes, spilled and unaligned reads, unsupported arithmetic/implicit writes, joins and offset overflow; full-width alias/offset/spill positives |
| Conditional narrowing and memory remnants retain possible stack aliases | Taken and untaken CMOV r32 zero-extension; unpruned narrow stack tests, incoming-only spills, partial/masked overwrites and vector transport; exact overwrite/non-overlap boundaries and bounded heap/global preservation |
| Registered-list and initial-image facts survive only justified writes | Current/previous scheduler callback protection, partial/unknown list-link refusal, dirty constant ranges and non-resurrection cases |
| Three SynIC/pending callbacks are registered on reachable paths | Must-provenance at each SysV RDI/RSI call site; removed materialization and jump-only bypass fail; valid branch joins and loop-invariant arguments pass |
| Exactly the reviewed native IRQ event handler | Actual retained event pointer, missing/extra handler entries, and changed pointer refusals |
| Follow linked calls, tail/local branches, aliases and interior-label fallthrough | ELF function extents, not objdump label blocks; adding only an interior ELF symbol cannot hide unchanged executed SIMD bytes; valid interior labels pass |
| Reviewed indirect callers and exact counts 1/2/1 | Real event/controller/wake indirect sites; count mutation, indirect tail jump, and unreviewed caller refusals |
| Required IRQ roots, SynIC helpers, protocol getters and ISR wake are reachable | Real returning graph; removal of the ISR wake edge refuses publication |
| No x87/MMX/SSE/AVX/mask/tile state on returning IRQ paths | Register/mnemonic family unit matrix, prefix normalization, real SIMD insertion, and HLT/INT3 resumption fallthrough |
| Legitimate integer LOCK operations retain IRQ coverage | Real `lock; orq` memory RMW fixture and split-record parser case; register-only LOCK remains unknown and is refused when reached |
| Only straight-line terminal assertion logging is exempt | Worker-only SIMD logger behind UD2 passes; returning logger and SIMD in the asserting caller fail; branch/call/return/loop barrier cases |
| Unique strong driver registration and unique constructors/entries | Real macro-generated symbols; weak/duplicate registration, absent call and wrong constructor pointer refusals |
| Nonempty ctor bounds, complete slot within bounds, no orphan priority sections | Empty table, entry at end, wrong slot size, and orphan section mutations; linker KEEP retains constructors |
| Actual driver descriptor argument, names, IDs and callbacks | Both drivers: argument removal and jump-only LEA bypass, 40-byte descriptor/32-byte ID ABI, GUID/sentinel, name/ID/add/remove/optional callback pointers |
| Configured driver requirements remain conditional | Each driver individually, both together, duplicate arguments; corruption of an unrequired driver's GUID does not fail the selected driver |
| Static and PIE pointer evidence | EXEC and DYN fixtures; loaded absolute pointers and `R_X86_64_RELATIVE` RELA; unsupported and ambiguous relocation refusals |
| Native tools cannot supply success-shaped bad evidence | Native mock executable covers nonzero/empty/malformed/truncated NM and objdump; mismatched NM addresses, raw bytes and branch targets |
| Format/bounds/architecture failure is explicit, without panic | Wrong class/encoding/architecture, truncated ELF, empty symtab, and non-executable load segment; shared bounds-checked ELF parser |

Each fixture loop asserts its expected source-site count rather than silently
omitting cases when compiler output changes. Per-fixture `summary.txt` files
are produced in the build's generated output directories.

## Control flow and scheduler provenance

`hyperv-proof-image.zig` derives function extents from sized ELF `STT_FUNC`
symbols. Exact aliases and nested labels retain the enclosing extent;
ambiguous partial overlaps are refused. IRQ traversal visits instruction PCs,
following both conditional edges and physical fallthrough. A new objdump label
does not end a function or change its reviewed indirect-call identity.

`hyperv-proof-flow.zig` constructs a bounded CFG and computes must-facts at
joins. Unreachable materialization is never used, and every reachable
registration call must have an allowed argument. Full-width pointer null tests
refine both register and spilled aliases; narrow tests and clobbered flags do
not establish a null object. Unknown or unsupported control flow is refused.
Comparison facts describe the operands at the comparison, not a later value
in the same register. CMPXCHG does not borrow ordinary CMP semantics. Opcode
classification parses all operands; unsupported forms cannot retain stale
argument provenance. Partial integers are not full-width ABI lengths or null
return values, and narrow memory loads never preserve complete pointers.
Memory TEST records the width-limited AND result separately from its operand:
a zero mask establishes ZF=1/SF=0 even for unknown memory, without refining that
memory to zero. Known scalar operands supply exact zero/sign flags;
indeterminate results leave both branches possible. CMP-memory-zero retains its
comparison semantics. Unspecified TEST widths do not supply nonzero flag
results without a register-width input.
AH/CH/DH/BH read bits 8 through 15, not the low byte of their parent register.
Such reads require known bits covering that slice; ranged or incomplete
evidence becomes unknown. Supported high-byte writes preserve known low and
upper bits and can extend known low-eight-bit evidence to sixteen bits without
claiming a complete 64-bit value. Writes that cannot be represented safely
and unmodeled high-byte unary/exchange forms are refused. Constructor conditional
writes use the same slice-aware writer; AP control-register proofs still require
their original full-register evidence.

Known own-frame addresses carry stack origin independently of numeric width.
Narrow register/spill reads and unrepresentable joins retain a `lost_stack`
fact rather than becoming an ordinary unknown or a zero-extended scalar range.
It cannot establish an exact pointer, numeric flag result, allocation, or memory
footprint. Register writes that would discard this origin, partial GP-register
updates to own-stack pointers, and unsupported stack-dependent arithmetic refuse
analysis.
The shared conditional writer also handles the architectural zero-extension
of an untaken 32-bit CMOV destination. Full-width copies, representable LEA and
ADD/SUB offsets, full-width spills, and independent complete replacements
(including zeroing XOR and multiplication by zero) remain supported.

An own-stack address is not the same as an otherwise unknown scalar loaded
from a stack argument. Undecoded reads retain possible origin when they depend
on an already stack-derived register; they never authorize a write or create
an exact memory location. This preserves existing opaque per-CPU reads without
using address spelling as non-alias evidence. Reads crossing tracked stack
pointer bytes cannot erase that origin. Partial or masked pointer overwrites,
unmodeled vector transport, and incoming-only pointer spills at joins retain
possible escape through the existing conservative stack-write policy. Complete
overwrites and disjoint writes do not introduce escape unnecessarily. Proven
bounded heap/global separation and caller/callee private-frame handling remain
unchanged. No assumption places the stack above 4 GiB.

`hyperv-proof-binding.zig` derives the callback location from the actual
`uk_thread_wake_isr` indirect load/call. The object form requires a scheduler
loaded from the original thread, that same scheduler in RDI, and the original
thread in RSI. Constructor/helper analysis requires the callback in that
object's derived field before publication through strong `uk_sched_register`,
then requires the same bound object on every non-null return. The global form
requires the exact consumed global slot on every return. An arbitrary memory
store of the callback is insufficient.

The publication contract is the reviewed `uk_sched_init` macro in
`lib/uksched/include/uk/sched_impl.h` and `uk_sched_register` in
`lib/uksched/sched.c`: initialize `thread_woken_isr`, then link that scheduler
into the scheduler list without replacing its callback. The real public image
loads `thread->sched` at offset 80 and calls field 40; the independent native
object fixture deliberately uses offsets 8 and 24, so passing cannot depend
on a hard-coded fixture or kernel displacement. Shared initializers, pointer
copies/spills, tail wrappers, and allocation-failure returns are exercised.
Overwrites invalidate publication even for spilled aliases or nullable helper
summaries. Separate untracked memory loads are not assumed to return the same
object; repeated allocation sites inside constructor call cycles are refused.

### SMP constructor memory effects

Constructor helpers use the separate bounded path analysis in
`hyperv-proof-paths.zig`, retaining allocation/error alternatives instead of
merging them into a success-shaped object. Direct helpers are analyzed, not
selected merely because they mention a callback symbol. CALL writes its real
return address; caller-relative stack arguments and callee-local frame cleanup
remain distinct. Known unmasked vector zeroes can initialize stack arguments;
merge-masked XOR cannot manufacture zero-valued arguments.
Masked vector stores with a trailing `{%k1}` through `{%k7}` invalidate their
entire potentially written scalar/XMM/YMM/ZMM range. They never establish
zero-valued cells, even when the source vector is known zero: a masked-off
lane retains its old contents. Disjoint tracked stack slots and justified
heap-versus-stack separation remain intact.

Memory writes use checked address decoding, distinct from a valid address
whose value is not known. Segment/address-size overrides (including retained
raw/textual prefixes), non-64-bit address registers, malformed masks/indexes,
and unrepresentable stack-dependent indexing refuse provenance analysis
instead of falling back to a non-stack write. Implicit string instructions
also refuse rather than approximating an unknown footprint as sixteen bytes.
The reviewed bounded memory-API contracts below remain available; the
separate returning-IRQ instruction policy is unchanged.

The entry contract is the selected cooperative-scheduler startup ABI: the
four allocator arguments are valid allocator objects, as supplied by
`lib/ukboot/{boot,smp}.c`. This is not a claim about calls with invalid/null
allocator arguments or arbitrary runtime inputs. Allocations themselves remain
nullable. Only calls through the matching `struct uk_alloc` receiver establish
fresh storage: malloc/calloc/memalign/free at offsets 0/8/32/40. Sizes, counts,
alignment and memory-helper lengths require complete scalar evidence.
Arbitrary call results do not acquire allocator freshness.

Fresh objects are separate from allocated ELF globals and other fresh
allocations only for bounded, in-object accesses. Member values are retained,
including queue tail pointers, allocator fields and the actual stored
`thread_add` function pointer. Indexed global writes require a bounded index
and a sized allocated ELF object covering the entire write. Known disjoint
heap writes do not erase caller stack arguments just because another stack
value escaped; unknown writes still invalidate exposed facts.

Registration also analyzes the existing scheduler-list path. A bounded
abstract set represents valid previously registered schedulers and the
current scheduler, not an exact pointer identity. The next-field offset is
derived from the actual registration body's null store, must lie after the
consumer-derived callback, and must fit the fresh object. Every registration
instruction is still analyzed. Writes into any represented node's callback
are refused, as are partial or unproven next-pointer writes. A list link can
only retain this abstraction when assigned a full null pointer, the current
scheduler, or the validated list set. This models the selected heap-allocated
cooperative-scheduler list, not arbitrary foreign/dangling registrations.

The SMP case requires several narrow, reviewed C API effect contracts:

| Contract | Required evidence and modeled effects |
| --- | --- |
| `memset`, `memcpy`, `memmove` and ISR copy/set variants | Strong symbol, complete bounded length; invalidate the entire destination range and return its post-write pointer facts |
| `uk_plat_native_ectx_init` | Strong symbol; fresh allocation, 64-byte guaranteed alignment, full 2688-byte worst-case footprint in bounds; invalidate that whole range |
| Returning `_uk_printk` | Strong symbol, unchanged allocated read-only format, supported non-writing conversions; reject `%n`, positional/unknown conversions and incomplete formats; caller-owned memory is not an output |

These contracts rely on the approved implementations and valid C API/allocator
invariants; they are not independent correctness proofs of libc, the allocator
backend, the logger, or XSAVE initialization. Their sources are
`lib/ukalloc/include/uk/alloc.h`, `lib/ukprint/print.c`, the memory APIs, and
`plat/native/arch/x86_64/{ectx.c,include/uk/plat/native/arch/ectx.h}`. The ECTX
maximum covers the source's supported XSAVE layouts and smaller fallback save
formats. Unknown helpers/writes do not gain these contracts. The IRQ graph's
separate FP/SIMD prohibition is unchanged, including returning logging.

Untouched read-only data and exact RELATIVE relocations provide initial
constant evidence, including TLS pointers folded into `.data` rather than a
separate `.got`. Overlapping writes and unknown effects invalidate it; partial
reads overlapping pointer relocations do not invent relocated scalar values.
The real parent SMP image now exercises TLS/context initialization, the
previously failing CPU-map and tail-queue writes, thread allocation and the
resolved `thread_add` call. This remains linked-image evidence, not execution.

The parent acceptance ELF's former `ukplat_time_init` error actually occurred
in `uk_intctlr_irq_handle`: LLVM printed `f0 lock` at `0x12ca40` separately
from `orq $1, (%r12)` at `0x12ca41`. The parser now joins only contiguous,
at-most-15-byte LOCK plus integer **memory** RMW encodings. Invalid prefixes
remain unknown; executable boot/table data is not blanket-whitelisted as IRQ
code. Failure diagnostics now retain the current instruction PC and opcode.

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
fail when required provenance cannot be established. They support modeled
full-width copies, object-relative/RIP-relative addressing, unescaped spills,
and must-facts across joins, not arbitrary alias analysis, general heap
lifetime proofs, or arbitrary calling conventions. Constructor-only vector
writes use their full XMM/YMM/ZMM or scalar footprint, without spuriously
clobbering GP registers. Overlap invalidates callback facts; this does not
authorize vector state in the IRQ graph.
PIE callback/argument evidence must retain a full-width position-independent
address: absolute immediates and narrowed register copies are not accepted.
The selected non-LTO C ABI is SysV x86-64, with the reviewed scheduler
publication contract above. Analysis is capped at 8,192 instructions per
function, 131,072 state transfers (also shared across constructor summaries),
192 tracked memory cells, 64 initial-constant write ranges, two ordinary load
levels, 16 helper levels, 256 call contexts, 8,192 call-hook operations,
2,048 constructor states per function, 512 pending constructor states,
16-MiB allocation/memory-helper extents, 16,384 normalized functions, and
131,072 visited IRQ PCs. Recursive helpers, constructor
call-containing cycles, conditional exits beyond function extents, indirect
transfers whose targets cannot be resolved, and exhausted bounds explicitly fail.
These conservative restrictions are not silent skips or boot evidence.
Embedded real-mode bootstrap code,
GDT bytes, and the post-paging far-transfer suffix are not certified as IRQ
code. Mixed 16/32/64-bit fixture sections exercise the ELF64 decoder's handling
of these bytes; unknown instructions still fail inside the returning IRQ graph
or before the AP paging-enable write. Dynamic pointer proofs support
RELATIVE RELA, not symbol-dependent RELA, REL, or packed RELR.

The shared ELF parser's explicit `allow_relocatable` option exists only for
object-fixture inspection; its normal postprocessing/final-image API still
rejects ET_REL. The three original Python drivers and their helper regressions
remain dormant staged-cutover references for other explicit callers. This
change does not remove them from legacy producer closures or replace unrelated
controller Python. Both transitional producer-pin maps bind the native sources
and fixtures, plus complete source directories for the reviewed allocator,
memory, logger, scheduler-entry and ECTX contracts and the fixture's ABI headers.
These pins preserve the coexistence boundary; they do not reinterpret old
receipts or admit a new private build. The dedicated CI step runs both native
proof modes and the actual Make compiler-option probe.
The transitional operator-local input manifest and completed receipt have a
separate 128-KiB read/generation bound for their repeated producer pin records.
Host-wire manifests and receipts remain bounded to 64 KiB, private state to
192 KiB, and all existing transfer, control and total staging budgets remain
unchanged. This is a coexistence serialization bound, not native admission.
