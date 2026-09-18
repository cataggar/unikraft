# Native public local boot driver

Standalone Zig 0.16 replacement for `support/build/tests/hyperv-efi-boot-test.py`
and its focused Python fixtures. No Python interpreter, SDK, cloud client,
shell, preparation engine, or host admission is used. QCOW2 inspection uses
the exact pinned Miz host library and its native zstd dependency.
Dedicated native CI fixtures and the fixed two-CPU SMP boot use this package.
Public root CLI assembly and the remaining legacy Python call sites are separate
integration work; this is not the complete Python-free controller cutover.

**This is only a public local QEMU/KVM boot and log assertion. It does not
establish VMBus, StorVSC, NetVSC, Azure, #120, or #89 acceptance, and cannot
admit a signed host image or authorize a real attempt.** Native fixtures
simulate processes and serial protocols; they are not real guest boots.

## CLI

```text
uk-hyperv-local-boot --raw-disk /canonical/public/smp.raw \
  --qemu /canonical/qemu-system-x86_64 \
  --ovmf-code /canonical/OVMF_CODE.fd --ovmf-vars /canonical/OVMF_VARS.fd \
  --work-dir /canonical/private/new-attempt \
  --cpus 2 --timeout 60 --expect 'application marker' \
  --require-marker 'first additional marker' \
  --require-marker 'second additional marker' \
  --forbid-marker 'unwanted marker'
```

Use `--image /canonical/application.efi` for a directory-backed ESP,
`--fixed-vhd /canonical/disk.vhd` for an actual fixed-VHD/vpc boot, or
`--qcow2 /canonical/disk.qcow2` for the narrow standalone native-Miz zstd
profile. Exactly one of image, raw disk, fixed VHD, or QCOW2 is required. The
selected source and the four supporting paths must be explicit, absolute,
canonical, and free of symlink components. In particular, there is no QEMU
PATH search or inherited environment. Commas/spaces in input paths are safe.
Resolve external tool symlinks before invocation.

The work directory must already exist, be current-user-owned mode 0700, and
be empty except for the core's stable `.writer.lock`. It is **consumed once**;
repeated use refuses instead of overwriting evidence or retrying QEMU. Inputs
must be outside it. A durable, create-only `request.json` precedes the leaf
process, whose separate create-only `launched` record prevents another exec.
These are local execution records, not an authority or completion receipt.

Options preserve the legacy names:

| Option | Contract |
| --- | --- |
| `--cpus` | 1 through 8; default 1 |
| `--disable-x2apic` | Legacy xAPIC; permitted only with one CPU |
| `--timeout` | Decimal seconds in 0.001 through 120, at most three fractional digits; default 30; CI can select 60 |
| `--expect-main-return` | Exact signed i32, default 0 |
| `--expect` | Required nonempty printable ASCII marker, at most 512 bytes |
| `--require-marker` | Repeatable, up to 32 distinct markers, in required occurrence order |
| `--forbid-marker` | Repeatable, up to 32 distinct markers |

Unknown options, duplicate singleton flags, conflicting/empty markers,
NaN/infinite/exponential timeouts and ambiguous numeric forms refuse. There
are no fixture, arbitrary-argv, shell, HTTP, credential, or admission options.
The internal `--exec` entry requires the parent's private typed record,
writer lock, parent PID, process group and death-signal setup; it cannot
independently select a command. The QEMU executable must be native ELF, not
an interpreter script. Selecting a trusted QEMU/tool runtime remains the
local operator's responsibility, not an assertion made by this driver.

Stdout is one bounded canonical JSON report: schema 1,
`scope=public_local_qemu_only`, `acceptance=not_established`, `passed`,
`consumed`, `input_unchanged`, `serial_valid`, `serial_limit_reached`,
`serial_bytes`, lowercase hex `serial_sha256` or null, termination, and
independent core primary/cleanup/recording diagnostics. No original paths,
arguments, exception text or guest output appear in the report. Exit 0 means
only that the local assertions passed; 1 is execution/evidence failure,
2 is refusal, and 3 is output-recording failure.

## Execution and evidence

`root.zig` exports `config`, `serial`, `files`, `runner`, `child`, `vhd`, the
dependency-free merged `core`, and the single pinned Miz module identity used
by QCOW2 validation and native fixtures.

- `config.parse(allocator, args)!Config` borrows strings and allocates its two
  marker slices. `Config.source` is the canonical `{kind,path}` tagged source;
  `Config.validate()` also supports typed in-process callers.
- `runner.run(allocator, io, Config, Options)!Report` requires a dedicated
  `core.process.initialize()` supervisor. `Options.self_executable` identifies
  this CLI; an optional atomic cancellation flag interrupts its leaf.
- `child.arguments(allocator, Config, source_size, source_fd)` constructs only the
  fixed QEMU operation. Arena allocation is appropriate for an execution.
- `serial.validate(allocator, raw, Config)!void` is a local marker validator,
  deliberately separate from the single-CPU signed host serial policies.
- `runner.Report.decode(allocator, canonical_bytes)!Report` checks the exact
  stored report shape and consistency. Consumers must separately verify
  physical request/artifact/log bindings; a parsed report is not admission.
- `vhd.validate(io, file)!u64` checks a complete fixed footer, checksum, file/
  original/current size, sector/whole-MiB geometry, CHS bounds, nonnil identity
  and reserved fields. Legacy `vpc `, `vs  ` and `qemu` creators additionally
  require CHS size to equal the exact current size; otherwise they refuse.
  Dynamic/differencing, partial and excess files refuse.

QEMU uses q35/KVM, 512 MiB RAM, the established Hyper-V CPU features,
`vmbus-bridge,irq=15`, no NIC/display/monitor, no reboot and no user config.
The leaf execs QEMU in its existing process group; it does not fork another
supervisor. The parent supplies an empty environment; QEMU receives only
`TMPDIR` pointing at the owned workspace.

Inputs use core's public artifact policy, not its private 0600 file policy:
regular files, safe descriptor-relative ancestor walks, no symlink following,
and no group/world writes. Owner-readable 0644 firmware/images and 0755 QEMU
are supported. Source, firmware templates and QEMU are hashed in bounded
32-KiB reads, pinned before launch, revalidated by the leaf, and checked in
full afterward, including inode/device, length and modification metadata.
Path replacement, growth, truncation, or changed bytes cannot pass.

The raw disk, fixed VHD, or QCOW2 is **never copied, staged, linked, reseeded,
or writable**. QEMU receives a separately inherited duplicate of the retained
O_RDONLY descriptor. Raw uses the existing nested JSON `-blockdev` file node
and exact-size read-only raw node at offset zero. This both avoids comma-based
option injection and preserves exact backing-file identity.
Fixed VHD instead uses a genuine read-only **`vpc`** node over the entire
descriptor with no raw offset/size or creation-only options. Its footer is not
sliced off. The virtual-size limit is 256 MiB, plus the 512-byte VHD footer.
Pinned QEMU v11.0.91-z.15 opens vpc through `BlockdevOptionsGenericFormat`;
`force-size` is creation-only, and neither it nor `force_size_calc` is sent
in opening JSON. The pinned miz creator tag `miz ` selects footer
`current_size`. Legacy CHS-based creators are accepted only when that
geometry gives the same exact size; no creator/footer bytes are rewritten.

QCOW2 admission never reopens its pathname. The retained custody descriptor is
duplicated once with close-on-exec for
`miz.Image.openStandaloneQcow2FileWithLimits(io, duplicate, limits)`;
ownership transfers only after a successful open, `Image.close()` closes that
duplicate, and the retained descriptor remains available for hashing and the
later QEMU duplicate. Before header-controlled scans or allocations, the
reviewed limits cap physical and virtual size at 256 MiB, require cluster bits
16 (64 KiB), permit one L1 entry/eight L1 bytes, one 64-KiB refcount-table
cluster/8192 entries, and permit no snapshot records or snapshot L1 geometry.
Aggregate open metadata is capped at 65,664 bytes and 8,194 work units: the
112-byte header, one L1 entry, one refcount-table cluster, its 8192 slots, and
one terminating extension record. Miz charges the complete refcount-table
entry count before its first table read, so sparse geometry cannot amplify
admission into millions of reads. Backing-file and external-data references
are rejected before referenced path I/O. The accepted profile is QCOW2 v3,
native Miz zstd compression type 1, the exact supported incompatible feature
bit, one bounded L1/refcount-table/refcount block shape, no encryption or
snapshots, and no backing/data dependency. Checked metadata/refcount and
physical mappings are validated before a bounded full virtual read exercises
every allocated compressed cluster. QEMU receives two explicit nodes in order:
a read-only `file` node over `/proc/self/fd/N`, then a read-only `qcow2` node
named `local-boot-disk` referring to it. The existing
`virtio-blk-pci,drive=local-boot-disk` device is unchanged.
Malformed, unsupported, over-limit, or decompression-invalid QCOW2 content
remains an `invalid_input` refusal. Host stat/read failures, cancellation,
allocation failure, descriptor/resource exhaustion, and other operational
errors retain their original error instead of being relabeled as malformed
image content; the validation duplicate is closed on every such failure.

EFI mode copies only the supplied application into private
`esp/EFI/BOOT/BOOTX64.EFI`; that disposable ESP retains legacy writable-FAT
behavior. All modes make private firmware code and variables copies.

Finite limits are 256 MiB per physical input/QEMU binary, an independent
256-MiB QCOW2 decoded/virtual capacity, 16 MiB firmware code, 4 MiB firmware
variables, 64 KiB control records, 4 MiB serial, and 8192 normalized bytes per
line. EFI preparation may copy up to the input plus firmware limits; disk
modes copy **only** firmware. Neither QCOW2 bound is derived from
`RLIMIT_FSIZE`: the child retains the existing 4-MiB writable-file limit for
serial, variables, and temporary writes. These local limits are not a
preflight staging ledger or data-upload authority.

The hard monotonic leaf deadline includes its validation/copy/exec and QEMU
work. Parent-side local admission and post-exit full-file hashing are bounded
in size but are not claimed to interrupt a stalled filesystem syscall.
Core provides an **independent 2-second TERM/KILL/reap budget**, subreaper
ownership and descendant-group cleanup even after normal leader exit.
`cleanup_complete` records process reaping; artifact cleanup failures remain
separate. An unresolved group poisons supervision, retains writer custody
and refuses file cleanup/replay. Abrupt supervisor/host loss is not a
crash-recovery or host-admission proof; the work directory remains consumed.

Both stdout and stderr append to exclusive 0600 `hyperv-efi-boot.log`.
`RLIMIT_FSIZE` prevents oversized capture and core dumps are disabled.
The raw log remains on failure even though core erases failed pipe capture.
Reaching the cap always refuses; a preceding process failure is retained,
with `serial_limit_reached` recording the independent bound observation.
Only known disposable firmware/ESP paths are removed after confirmed reaping.
Raw logs, request/launch/report records and any unknown files are retained;
no recursive production workspace deletion occurs.

The four platform/application-start milestones, expected application marker,
and unique terminal return must occur in order. Additional required markers
must occur in supplied order before the terminal. Ordinary markers retain
legacy substring semantics, but terminal returns do not: `main returned 10`
cannot satisfy return 0. Supported terminal envelopes follow actual ukprint
timestamp/Info/thread/caller/`[libukboot]`/`<boot.c @ line>` formatting, plus the
bare compatibility form. ANSI/NUL decoration and CRLF are normalized only for
parsing; raw bytes and SHA256 are retained. Complete bare terminal text at EOF
is allowed as in the legacy fixtures. Nonzero/unexpected, duplicate, spoofed
or trailing-garbage returns, malformed serial, crash markers anywhere
(including after application success), and forbidden markers all refuse.

## Offline build and fixtures

The build restores reviewed Miz revision
`669a27982b376311f558e820b69e9a692735b0cd` with package hash
`miz-0.2.0-Z3lHlD--2gAdGiguNwbjjdjBmv2f8QlAcwHYRw1De0Sx` from
`build.zig.zon`; Miz's exported `dependency.module("miz")` supplies its native
zstd wiring. After that pinned restore is available, builds run offline through `--system`.
This Zig distribution creates `zig-pkg` beside the selected build file, so
restore copied manifests under owned scratch before source custody is
established. Never fetch beside the tracked build file. Use Zig 0.16, `-j2`,
and explicit owned scratch for HOME, TMPDIR, XDG/Zig caches and outputs:

```sh
SCRATCH="$PWD/.d/local-boot"
umask 077
mkdir -p "$SCRATCH"/{home,tmp,cache,restore,fixtures,outputs} \
  "$SCRATCH/global-cache/tmp" "$SCRATCH/restore/zig-pkg"
export HOME="$SCRATCH/home" TMPDIR="$SCRATCH/tmp"
export XDG_CACHE_HOME="$SCRATCH/cache"
export ZIG_LOCAL_CACHE_DIR="$SCRATCH/cache"
export ZIG_GLOBAL_CACHE_DIR="$SCRATCH/global-cache"
cp support/tools/hyperv/local_boot/build.zig \
  support/tools/hyperv/local_boot/build.zig.zon "$SCRATCH/restore/"
zig build --build-file "$SCRATCH/restore/build.zig" --fetch=all \
  --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" -j2
zig build --build-file support/tools/hyperv/local_boot/build.zig \
  --system "$SCRATCH/restore/zig-pkg" \
  --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
  --prefix "$SCRATCH/outputs/debug" -Dtest-root="$SCRATCH/fixtures" \
  -j2 test install --summary all
```

Repeat with `-Doptimize=ReleaseSafe` and a separate output prefix. A missing
or incomplete `--system` package tree is an explicit build error; builds do
not fall back to fetching into tracked source.
CI additionally selects the explicit test-only path:

```text
-Dstrip-fixture-debug=true -Dfixture-objcopy=/absolute/pinned/llvm-objcopy \
-Dstrip-fixture-report=/absolute/private/fixture-strip-proof.json \
test test-strip-equivalence test-strip-proof install
```

This invokes pinned LLVM `--strip-debug` **after compilation**, only on copies
of the two uninstalled synthetic QEMU executables. Raw outputs remain in their
original cache locations. Every test invocation first runs the existing native
preparation `fixture_debug_verifier` on both current pairs with the reviewed
`file_offset_relayout` policy. The gate checks complete ELF/loadable content,
entry, machine, logical segments and allowed file-offset/section-locator
normalizations, then rechecks complete hashes and file identities. Gate failure
blocks fixture execution, including on a cached candidate. Native selection
tests repeat the checks, refuse aliases/substitution/unknown policy, and may
publish the separately named, create-only private pair proof. The existing
13 shared equivalence/refusal cases are reused without a second ELF parser.

The installed CLI, synthetic CLI, compilation mode/backend/CPU features,
whole-file hashing and deadline placement are unchanged. `install` alone
does not strip or qualify anything. The plain synthetic QEMU copy remains
uninstrumented and still runs against the production CLI in the existing
diagnostic-separation test. No real QEMU, firmware, guest image or production
binary is stripped. This reduces nonloaded debug bytes subject to actual
measured deadline coverage; it is not evidence that an unstripped timed run
passed, a guest optimization, or a namespace-timeout fix.

`test-root` must exist with mode 0700. Tests create and remove only their own
randomly named child directories. The native fake QEMU is a separate,
uninstalled executable; the production CLI has no synthetic switch.
Fixtures cover the legacy cases and native CPU/EFI/raw argument execution,
fixed-VHD footer/geometry/exclusivity and unsliced vpc argument construction
(the public-image suite additionally executes native four-mode vpc fixtures),
plus a genuine native-zstd standalone QCOW2. QCOW2 coverage includes typed
source serialization/exclusivity, exact two-node JSON, retained read-only
descriptor identity, external-reference refusal, independent physical/virtual
caps, malformed metadata/extents/features, decompression failure, source
replacement/mutation, serial cap, timeout and descendant cleanup. Existing
coverage retains read-only exact backing identity, private variables mutation,
merged failure logs, deadlines/cancellation/ignored TERM, descendant reaping, process exit/
kill/crash, cap exhaustion, consumption/locking, strict child records,
artifact changes and unsafe files, independent failure lanes and actual CLI
serialization/refusals. Only small public synthetic files are used; the
over-limit input case is sparse metadata, not a seed copy.

The standalone test build also creates separate, uninstalled
`local-boot-cli-fixture` and `local-boot-qemu-diagnostic-fixture` roots. Only
those executable roots declare the compile-time
`local_boot_synthetic_diagnostics` constant; codec/writer unit tests use
`builtin.is_test`. Installed/public CLI roots have
no declaration: the diagnostic imports and calls are not compiled into their
execution path. There is no runtime switch, environment hook, callback,
arbitrary command or diagnostic-path option. The fixture CLI uses the same
`main.zig`, validation and execution code as the installed CLI.

Each instrumented child writes the fixed private
`synthetic-local-boot-phases-v1` file, separate from serial and `report.json`.
Eight 512-byte slots bound it to 4096 bytes. Fixed-schema records contain
the effective compiler backend, target architecture, optimization mode,
AArch64 SHA2 and x86 SHA/AVX2 feature flags, actual pinned executable size,
monotonic time and process-CPU time. Slots bracket initial artifact hashing,
firmware copying including its existing fsyncs, final verification, exec
handoff and mock entry. The gap between firmware-copy end and final-verify
begin includes optional EFI staging and argument construction. Mock entry
means the synthetic process reached its private-cwd hook, not a kernel exec
receipt. It independently stats `/proc/self/exe` for the fixture byte count.
No pre-TERM PID sampling, signal handler or core supervisor change is made.

Diagnostic writes add no fsyncs and claim no durability or completion.
Termination can leave missing metadata, an aligned prefix, a partial slot
or an invalid slot. The bounded decoder retains only valid preceding records,
never treats absence as process absence and never admits authority or success.
Instrumentation has nonzero overhead and its actual executable size is
reported; these observations alone are not a performance diagnosis.
Existing deadlines, complete hashes, assertions and serial semantics remain
unchanged. A diagnostic write failure fails the synthetic helper explicitly;
it does not change production behavior or yield a successful observation.

On test error, before the existing fixture teardown, the harness emits
`native local synthetic phases:` and `native local stored report:` lines.
Only decoded fixed-schema metadata and the canonical stored `report.json`
are eligible; missing, malformed, oversized or unavailable files get fixed
status labels. Failed stdout/stderr and raw serial are not inspected for
diagnostic retention. Existing CI test logs capture these lines, including
the two actual-CLI exit-code assertion cases; no new artifact wiring is
required. Phase JSON is bounded to 4352 bytes per case. The stored report is
an observed copy, not proof that its publication fsync succeeded or that it
contains failures arising after publication. Teardown still removes only
each test's own directory. Additional
fixtures cover bounds, interrupted/invalid records, non-authority, separation
from serial/report output, teardown and the uninstrumented production path.
The dedicated retention fixtures also emit one validated synthetic CLI-failure
sample and fixed invalid-file labels during a passing test run, so the CI log
format itself is exercised without weakening any expected process outcome.
The successful phase test and the 1200-ms intentional-stall case also emit
complete phase samples and require mock entry before their unchanged budget,
measured from the first hash event. This measured interval excludes the
earlier request/child startup; the existing supervisor deadline still covers
that startup and remains authoritative. Both initial and final full-hash
CPU/wall intervals can be computed from the retained records. CI retains
these logs and both raw/candidate synthetic executable pairs with their
private equivalence proof even when later image stages never execute.

Offline fixtures access no actual guest, KVM, Python, Azure, credential,
original seed or historical private evidence. Separately, Hyper-V CI invokes
the installed ReleaseSafe driver for the real fixed two-CPU SMP raw-disk boot,
with canonical paths, private firmware templates and an outer command ceiling
covering local setup/post-exit I/O. The raw disk digest is checked independently
afterward. The raw log and local report are retained; remaining legacy
controller and packaging paths are not changed by this integration.
The public-image fixture checks the pinned QAPI opening-field contract,
including rejection of creation-only size controls. This is not a real-QEMU
option probe or an actual VHD guest boot; exact pinned-QEMU x86/KVM execution
remains a parent-owned CI gate.
