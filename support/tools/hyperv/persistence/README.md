# Native persistence execution engine

The selected #89 execution route is now the separately authorized
[direct specialized-Gen2 two-boot harness](../../../azure/DIRECT-TWO-BOOT.md):
bounded Azure CLI resource management plus native validation/transfer, not
this engine's unconnected production dispatcher or a nested #120 host.
The legacy engine contracts and closed gates documented below remain honest
and unchanged. `evidence.EvidenceInput` / `evidence.parseWorkload` expose only
the pure serial identity/geometry parser for the direct lane; they carry no authority
and cannot turn a synthetic or nested receipt into accepted persistence.

This standalone Zig 0.16 package implements the #89 two-boot execution and
cleanup state machine. It does **not** constitute real boot, upload, or
persistence acceptance. No production preparation/COMPLETED-preflight loader
or approved credential/route selection is provided by this package.

The installed `uk-hyperv-persistence-engine inspect PRIVATE_ROOT` only inspects
local state and its saved serial bytes. Its output explicitly identifies
production admission as unavailable. All other commands, including internal
worker dispatch, refuse with `production_bindings_unavailable`. The parent
owns final root CLI integration; a boolean, digest, PREPARED state, standalone
receipt, legacy record, or synthetic fixture cannot unlock this executable.

## Integration boundary

`root.zig` exports `contract`, `engine`, `model`, `evidence`, `native`, `worker`,
and `local`. The principal interfaces are:

- `engine.prepare(allocator, io, Directory, Contract)` records metadata only.
  It preserves the supplied run/disk identities, never opens or generates a
  seed/image, and does not consume the attempt.
- `engine.execute(allocator, io, Directory, Options, cleanup_only)` holds the
  original private writer lock. `Options.trusted: contract.TrustedInputs`
  is a trusted **in-process callback**, not a serialized admission claim.
  It must validate the original unconsumed seed, actual native COMPLETED #120
  handoff, immutable preparation/build/image/artifact/authority bindings,
  approved operator provenance/trust/route, and selected authority lifetime.
  Cleanup uses its independent authority lane. Cross-host/host-reboot state
  admission must be refused until the caller establishes the monotonic epoch.
- `worker.Supervisor.driver()` executes pinned, sealed native leaf workers via
  core `process.run`. Its trusted provisioning callback may supply private
  bootstrap inputs, not an arbitrary command or an argv/environment secret.
  The parent facade must connect its committed loaders to `worker.child`
  and `native.Session`/`native.Context`; no fixture mode exists in production.
  Admission and provisioning callbacks must perform only bounded local
  validation/provisioning; token acquisition and network activity belong in
  the directly supervised leaf, not those parent callbacks.
- `native.Session` owns an explicitly selected merged ARM auth provider, pinned
  CA runtime, token, clock/budget and native clients. It requires stable address
  and `deinit`, including after failed initialization. `native.Context.execute`
  maps only the enumerated persistence jobs to real ARM/page-Blob operations.
  The embedding executable must retain the fixed SDK log renderer.

The provider config supports only the merged explicit native auth boundaries.
It does not select or approve a real principal, operator signing source,
managed-identity endpoint, route or trust bundle. There is no Azure CLI,
ambient credential chain, cache borrowing, external broker or shell fallback.

### Preparation handoff constraints

The preparation API documentation at commit
`012f4f93f24d9304099d324f5d87e8dbeedc51f5` has been reviewed, not imported.
Its prepared/configured/built/packaged receipts carry `not_admitted`
authority; none is a COMPLETED-preflight handoff. No engine-side importer,
receipt reinterpretation or fixture admission path is provided here.

Storage run/disk identities are lowercase nonnil hex32, independent of ARM
ownership and host attempt RFC UUIDs. Neither identity is regenerated or
converted into the other. Execution and cleanup must still bind the same ARM
ownership UUID. Preparation's hex64 `contracts.Sha` must be explicitly
validated with `core.contracts.parseSha256` before entering a raw32 host hash
field; matching array widths do not establish equivalent semantics.

Production admission still requires the parent-owned read-only loader and
versioned input/ledger extension. Input-v1 has no private VHD role:
`boot_disk` names public `capability.raw`, not an OS disk or private VHD.
VHD bytes cannot be relabeled as controls/support or copied outside accounting.
`inputs.generate` is create-only staging, not adoption or crash recovery.

Producer `Context.verify` must retain its `/proc/self/exe` binding and cannot
be repurposed for a different engine. The loader must independently bind its
own executable and remeasure the reviewed provenance, physical Git source,
receipt chain, configuration, package, staged inventory and complete ledger.
The guarded producer commitment projection is still pending implementation
and review; `bindings.producer` is not permission to substitute an executable,
receipt, selection or image digest for that future commitment.

### Committed preflight consumer contract

The preflight implementation at
`45088c9ffe6af2d387c3ab48f7e39f48e191cffc` and API handoff at
`b166e1ba9bc470f45604463ca5e4530b9fd73646` have been reviewed through Git
objects without importing that package. The actual consumer is
`hyperv_preflight.completed.load(allocator, io, directory, expected)`, where
`expected` is a pointer to an independently validated `contract.Input`.
`worker.Resolved`, `adapters.Native` and `supervisor.run` are the preflight
execution interfaces, not substitutes for its completed-state loader.

The integrating dispatcher must run the loader as a hard-supervised read of
the complete protected preflight attempt directory. The loader acquires that
directory's writer lock itself; do not pre-lock it or alias it to the
persistence attempt directory. Do not introduce a nested supervisor inside
an already supervised persistence leaf. Artifact/source hashing and input
resolution likewise need an independent hard deadline, not merely a callback
with elapsed-time checks.

`completed.Handoff` has UUID-text fields `attempt`, `run_id`, `vm_id` and
`host_boot_id`; raw32 hashes `input_sha256`, `preparation_sha256`,
`public_receipt_sha256`, `private_receipt_sha256`, `completion_sha256`; and
`native`, `scope`, `storage`. It owns no allocator-backed storage, has no
serialized schema, and requires no `deinit`. Its native implementation,
preparation, source, dependency, tool-runtime and operator-binary hashes bind
the preflight producer, not this persistence executable. Keep this worker's
independent executable/artifact pin; do not reuse the preflight operator pin.

The loader, not an engine-side compatibility decoder, must establish production
COMPLETED state, all operation/consumption proofs and required accepted
mutations, no primary/cleanup/recording failure, the complete signed completion
envelope under the independently admitted key, both original commands and
receipts, all six serial files and launch identities, and independent cleanup/
group absence. The expected input binds the original authority, source,
preparation, artifacts, image/key/route/provider and disjoint ledger context;
none may be selected from the receipt being authenticated. The preparer must
physically revalidate source and artifacts before reuse: the completed loader
does not do that work or refresh expired credentials.

`Input`, `Approved`, `Handoff`, and this engine's `TrustedInputs` callback
container are ordinary structs, not non-forgeable authority. Production
admission depends on the complete trusted dispatch chain, not on constructing
one of them, supplying nonzero hashes, selecting `.production`, or verifying
a signature with a caller-chosen key. No parallel completion receipt/schema or
serialized Handoff will be added here.

The returned scope is platform-only with storage unavailable. Its original VM
and host boot UUID identify the completed preflight whose group was removed;
they must not populate persistence's original VM/disk fields or authorize
another boot. Persistence still requires separately admitted #89 authority,
the original unconsumed storage identities/seed, immutable guest bindings and
its own cleanup lifetime and complete accounting.

The real preparation read-only loader, versioned private-VHD ledger input,
closed native namespace, and independently admitted authority/key/route/ledger
remain prerequisites. A native Make bridge or a successful local build cannot
discharge them. The public production gate remains unchanged and closed.

## Private records and lifecycle

Version 1 exact canonical schemas are `uk.hyperv.persistence-input`,
`uk.hyperv.persistence-state`, `uk.hyperv.persistence-job`,
`uk.hyperv.persistence-result`, `uk.hyperv.persistence-worker-ack` and
`uk.hyperv.persistence-worker-stopped`. The input schema includes distinct
execution/cleanup authorities, original hex32 identities, sealed guest/data
descriptions (size/SHA256/footer SHA256), eight source bindings and budgets.
The owning Zig structs define every required field; unknown, duplicate,
noncanonical or mistyped fields fail. Local JSON is bounded to 256 KiB.

Core descriptor-safe 0700/0600 single-link policy protects contract, journal,
SAS and worker records. Sealed artifact input remains the distinct transfer
artifact policy, not the private-contract policy. SAS readers and parsed
secret allocations use the merged zeroizing APIs/arena. Credentials/SAS/URLs
are absent from argv, environment, acknowledgments and diagnostics.

`consumed.json` is immutable and durable before any effect. Every subsequent
mutation has a durable intent. A failed attempt cannot resume, rearm, replace
the VM/disk, reseed, or obtain a third boot. Boot count records reserved boot
intents, not an assertion that a guest actually booted.

The sequence is original OS/data create/grant/page upload/revoke/access proof,
fixed private network, original VM deployment (Boot1), exact write/flush/
receipt/readback evidence, deallocation readback, sole durable Boot2 start,
persisted readback with zero workload writes/flushes, and final deallocation
readback. Uploads retain the merged page journal's attempted/confirmed
mutations and bytes, outcome, full-stream hash and footer readback. Transfer
certainty never derives from completion, HTTP status, or zero byte counts.

Primary, cleanup and recording failures remain separate. Cleanup validates
owned inventory and original UUIDs, never replays an ambiguous mutation, and
requires independent recognized group absence. HTTP 403 or malformed 404
cannot prove absence. Retained granted endpoints receive bounded independent
denial probes; header/body metadata remain distinct. SAS files are not
discarded while an access-proof obligation remains unresolved.
An original UUID is retained even when a valid private result loses stdout
delivery. Failed provisioning does not erase otherwise valid network
ownership. Only a bound grant result explicitly proving `not_started` clears
its unused SAS obligation; unknown/rejected grants are not treated that way.

Cleanup may reconcile an interrupted job only after a bound, durable parent
terminate/reap proof. Valid private results/page checkpoints retain known
effects and identities despite malformed/missing stdout. A lock alone is not
a stopped-process proof. If the parent died before recording that proof,
cleanup fails closed with `ProcessRecoveryRequired`; it does not guess PIDs,
claim reaping, replay the worker, or discard consumption/cleanup obligations.
An outer-owner crash recovery proof is a remaining integration requirement.

## Bounds and concrete adapters

Runtime is explicitly 60--3600 seconds, cleanup independently 60--1800 seconds;
each operation is at most 600000 ms and bounded by its enclosing deadline.
Leaf processes have hard monotonic TERM/KILL/reap supervision and separate
2-second process cleanup, with 2048-byte stdout/8192-byte discarded stderr
ceilings. They do not start another process supervisor or escape a parent
process group. Per-read transport budgets are additional guards, never a
replacement for the parent's hard process deadline.

Input staging is capped at 256 MiB, including its admitted controls (at most
2 MiB) and guest VHD. These are admitted staging categories, not a claim that
every journal rewrite or ARM response is preflight staging. The original #89
4-GiB data payload plus its 512-byte footer is a separate exact upload
authority, not an exemption or reallocation within #120 staging. This engine
does no artifact staging; the production loader must reconcile these amounts
with the actual preparation/preflight ledger. Remote responses retain merged
ARM byte/poll bounds; serial capture has its separate legacy 4-MiB ceiling.

The narrow shared ARM additions provide the original NSG/VNet/NIC (no public
IP, acceleration, forwarding, NAT, custom routes, load-balancer pools/NAT rules,
or application-gateway pools), MiB-aligned VHD upload geometry with a locally
checked GiB ceiling (including the original 66-MiB guest), and an opt-in full
persistence VM attachment envelope. Existing default VM behavior is unchanged.
OS creation explicitly selects Linux/Generation 2.
Upload requests specify exact `uploadSizeBytes` including the footer and omit
`diskSizeGB` entirely: for non-Empty creation that field requests resizing.
Empty requests still specify `diskSizeGB`. Neither the local GiB ceiling nor
the response's GiB field rounds or replaces the exact VHD logical byte count.
Before deployment, detached original disk UUIDs, raw `diskSizeBytes`, roles and
readiness are checked. Subsequent observations require attachment to the
original VM; cleanup never accepts an unrelated attachment. Both NIC readiness
and cleanup ownership require absent or empty-array association fields;
nonempty or malformed association values refuse. Generic network parsing
remains unchanged.

APIs remain pinned: groups/deployments 2021-04-01,
compute VM 2025-11-01, disks 2025-01-02, network 2024-05-01, pages 2020-10-02,
Blob downloads 2024-11-04. No storage account/key/firewall is created by #89.

## Evidence and offline fixtures

`evidence.parse` implements the actual guest's eight ordered serial markers,
run/disk/controller/VPD identity, LUN 7, 8388608x512 geometry, Boot1 5 writes/
3 flushes, Boot2 0 writes/0 flushes, receipt verification and terminal return.
It requires the complete raw Boot1 prefix unchanged in accumulated Boot2
serial. Terminal `main returned 0` accepts the bare compatibility form or the
anchored `lib/ukprint/console.c` Info envelope from `lib/ukboot/boot.c`: optional
`[%5seconds.%06microseconds] `, `Info: `, optional thread then caller,
`[libukboot] `, and optional `<boot.c @ %4line> `. Thread forms are the boot
paths' `main`/`init`, an unnamed pointer, or `<<n/a>>`; caller pointers use
ukprint's lowercase `0x` form (or `0`). Source lines are not pinned to one
revision, but must fit the producer's six-byte line buffer. Envelopes are
bounded to 256 normalized bytes and are never found by substring/suffix
search. Nonzero returns, duplicate/reordered terminals and trailing message
garbage fail; the other seven protocol markers remain bare and exact.
Parsing strips ANSI CSI/NUL decoration and accepts CRLF. A complete LF must
precede any final reset/NUL-only ukprint tail; partial text/escape tails refuse.
Saved bytes, byte counts and hashes, including those resets, remain exact.
VPD is limited to the actual C maximum of 64 bytes. Benign unrelated text is
not rejected merely for containing `BOOT1` or `RESEED`.

`test` covers canonical admission, permissions/locking/consumption, full
two-boot synthetic models, identity/geometry/serial negatives, all failure
lanes, recording faults, native child cancellation/deadline/output bounds,
partial page-journal recovery, conservative crash custody, expiry and typed
CLI refusal. It also calls the concrete native SAS adapter with injected
synthetic HTTP responses. `test-arm` covers the affected ARM suite and new
fixed-network wire/readback, guest upload geometry and VM envelope cases.
The 4-GiB fixtures are **metadata-only models**, not 4-GiB files or uploads.
No historical private artifacts, original seed, image, credential or cloud
operation is needed or permitted.

Use the pinned manifest, restore copied manifests into scoped scratch with
`--fetch=all`, then build with `--system SCRATCH/restore/zig-pkg`. Set HOME,
TMPDIR and Zig/XDG caches beneath `.d/zig-migration-persistence`. With an
existing owner-only absolute fixture directory:

```text
zig build --build-file support/tools/hyperv/persistence/build.zig \
  --system SCRATCH/restore/zig-pkg \
  --cache-dir SCRATCH/cache --global-cache-dir SCRATCH/global-cache \
  --prefix SCRATCH/outputs/debug -Dtest-root=SCRATCH/fixtures \
  -j2 test test-arm install
```

Repeat with `-Doptimize=ReleaseSafe` and a distinct output prefix. No new SDK
surface, dependency, tool installation, root build, CI, producer-pin or
legacy-controller change is required by this package.

### Default-off synthetic persistence timing

`-Dpersistence-timing=true` instruments **only** the non-installed worker
fixture and engine tests. Omit it for the quiet default. Neither the installed
CLI nor serialized job data can select this diagnostic or synthetic backend.
`-Dtest-filter=TEXT` uses Zig's standard fixture-name filter, as in the other
native packages; it filters `test`, not `test-arm`. The original 28 engine
tests and assertions remain, with seven additional `persistence timing` tests.

The sole shared extension is the null-by-default, trusted in-process
`worker.Observer` callback (`void`, no errors entering worker failure lanes),
`Supervisor.observer`, and `childObserved(..., ?Observer)`. Ordinary `child`
supplies null. No clocks, sidecars or timing output are used with null observers.
The sampler is the existing `../synthetic_measurement.zig`, also used by
local-boot/namespace diagnostics. No hashing algorithm, hash frequency, wire
schema, deadline construction/check, process ownership, descriptor allowlist,
ack, result validation, recording or recovery rule changes.

Output lines start with `persistence_timing`. Stage records are canonical
closed-schema JSON v1: `scope=synthetic_timing_only`, `authority=none`, fixed
`stage`, fixture `mode`, numeric `sequence`, fixed model `step`, selected
`worker_bytes`, absolute `deadline_ns`, original `operation_ms`, nullable
`cleanup_complete` (only at `process_return`), and the shared `sample` fields:
compiler backend, architecture, optimization mode, aarch64 SHA2/x86 SHA/AVX2
feature booleans, monotonic nanoseconds and **process-local** CPU nanoseconds.
No path, URL, credential, arbitrary error, job/result body or failed
stdout/stderr is rendered. Fixed-label summary/status and recovery-precondition
lines are not worker records and must never be fed to a result/admission loader.

| Stages | Measured interval / boundary |
| --- | --- |
| `selection_begin/end` | Test helper's initial path resolution, full read and SHA256 pin; **before** any job budget. These two records have only size and shared sample metadata, not job fields. |
| `parent_begin`, `seal_begin/end` | Supervisor entry; full guarded `SealedInput.open` (SHA256 **and** MD5). |
| `job_prepare_begin/end`, `provision_begin/end` | Worker directory/job record preparation, then fixture provisioning including diagnostic sidecar creation. |
| `verify_begin/end` | Original second full guarded SHA256/MD5 hash and path/metadata verification. |
| `process_begin/return` | Entire existing `process.run`: spawn, monitor and terminate/reap. This is not a separate kernel exec or cleanup-duration measurement. |
| `result_read_begin/end`, `result_validate_begin/end`, `delivery_begin/end`, `supervision_begin/end` | Private result read/validation, bound ack check, original supervision recording, including failure branches. |
| `parent_error/end` | Error-return marker if applicable, then end of the supervisor call after its original defers. |
| `child_entry`, `child_job_begin/validated`, `child_started_recorded` | Earliest fixture Zig entry, existing job/canonical/input/parent/deadline validation, and original started-record durability. Runtime/loader time before Zig entry is not sampled. |
| `child_backend_begin/end`, `child_result_validated/recorded`, `child_ack_begin/end`, `child_error/end` | Synthetic backend and normal result/ack lifecycle. Malformed fixture delivery instead uses `child_fixture_result_begin/end` and `child_fixture_ack_begin/end`; partial-page exit uses `child_fixture_checkpoint`. |

Compare wall clocks across parent/child only for the **same** step, deadline,
mode and sequence. Subtract CPU clocks only between parent records or between
records from one child; never parent minus child or two different children.
`process_begin` to `child_entry` bounds startup; `process_begin/return` includes
the independent original 2000-ms cleanup allowance. The exact job expiry is
copied, not recomputed. Entry is slightly after the engine created the deadline,
and a job clipped by its enclosing deadline need not have a full 1000 ms left.
An end marker or `child_status=complete` means observation coverage, **not**
worker success, admission, accepted effects, or a reaping proof.

The private 0600, exclusive-create `synthetic-persistence-timing-v1` file lives
in the existing private worker directory. It has one 1024-byte header followed
by at most 17 1024-byte child slots (18432 bytes total). The header binds the
attempt nonce, input digest, step, exact deadline, parent PID, operation budget,
fixture size/mode and bounded sequence. The child compares that identity with
the validated job. This is an observation identity, not another job/result
signature or recovery claim. The parent retains its descriptor, checks the
pathname's private inode/snapshot and exact header, and reads only on the
existing `process.run` cleanup-complete return (including no-child start
refusals). Unconfirmed cleanup never permits a read. No FD is passed through
exec; no new descriptor is added to any allowlist.

There are at most 21 parent and 17 child records per call, each at most
1024 bytes plus its fixed log prefix, and one bounded summary. A fixture
collector allows at most `8 * step_count + 1 = 265` calls and one overflow
notice. Unknown/duplicate/noncanonical fields, identity changes, stage
regressions, process-local clock regressions and oversized files refuse.
Summaries distinguish `empty`, `prefix`, `partial_slot`, `complete`, `invalid`,
`overflow`, `clock_failed`, `io_failed`, `missing`, `not_started` and
`cleanup_unconfirmed`; parent `ok` means its samples were collected. Diagnostic
failures never replace the original primary/cleanup/recording failures.
Missing child observations remain empty/prefix observations: they cannot
distinguish death from a child diagnostic clock/write/open failure.

**Overhead is real and is not reimbursed.** Sampling/slot encoding, sidecar
opening and writes occur under the unchanged running budgets. Slots use
positional writes without additional fsyncs, not crash-durable logging. Parent
decoding after reaping contributes to the gap before result reading; bounded
printing at call exit contributes to the enclosing attempt/cleanup budget.
No deadline is paused, reset or extended. The instrumented executable itself
can be larger, so use its reported byte count and retain default-off controls.
Timing can perturb or cause a failure; these observations do not yet establish
the native x64 Debug failure's cause.

Normal credential-free fixture CI explicitly enables this existing option in
both modes. Every actual native timing case now emits its bounded report on
success and failure, including blocked-upload, partial-page and deliberately
missing-diagnostic controls. Pure codec/overflow controls may suppress printing.
Parent reports are encoded into a fixed `report_bytes` buffer; the existing
265-call cap plus one overflow notice also bounds each collector's aggregate.
A native test covers full-size reports, refusal of excessive counts and
retention of copied child records after their fixture directory is removed.
Neither the shared worker nor its complete SHA256/MD5 sealing/verification
passes are changed.

The existing always-run runtime artifact now retains validated copies of
`Debug-fixtures.log` and `ReleaseSafe-fixtures.log` under
`native-persistence/observation-evidence/`. A fixed-name workflow copier drains
no subprocess and never parses diagnostics as status: it runs after the test
step, accepts only owner-private single-link regular files, and refuses logs
larger than 64 MiB rather than truncating or changing native execution.
Both successful and failed test outputs remain eligible for retention.
The native raw/candidate proof and artifacts remain in the same runtime upload.
This activation is diagnostic only, not a demonstrated timeout correction.

The cleanup-recovery fixture emits `recovery_initial`, `recovery_rewritten`
and (only if the original validation succeeds) `recovery_validated`. They
show only phase and the OS/data grant/access preconditions. The historical
`InvalidAccessProof` stack identifies validation of the **rewritten** state:
OS access was not pending, a grant obligation existed, and neither normal nor
cleanup OS-access proof was done. Rewriting clears records from `data_upload`
onward, including cleanup proofs, but does not change `os_access_pending`.
That stack alone does not identify the earlier failed worker or prove a
timing cause. The new before/after observations expose the distinction;
validation and fixture rewriting remain untouched.

#### Parent-owned native x64 trial recipe

After independent review, the parent can use the same native x64 environment
and exact already-staged **persistence** SDK dependencies (not preparation's).
Set `ZIG`, `REVIEWED_SOURCE`, `PERSISTENCE_PACKAGES`, and a new private
`TRIAL_ROOT` to absolute paths. This recipe neither fetches dependencies nor
performs VM, hardware, cloud, publication or integration operations:

```bash
cd "${REVIEWED_SOURCE:?}"
mkdir -p "${TRIAL_ROOT:?}"/{home,tmp,global}
chmod 700 "$TRIAL_ROOT"
export HOME="$TRIAL_ROOT/home" TMPDIR="$TRIAL_ROOT/tmp"
export XDG_CACHE_HOME="$TRIAL_ROOT/global"
filters=(
  'real native leaf workers deliver bound private results and exact serial model'
  'partial native page checkpoint survives killed delivery without claiming full upload'
  'cleanup recovery requires bound parent reaping proof and never replays mutations'
  'failed native creation delivery retains UUID and refuses cleanup replacement'
)
for mode in Debug ReleaseSafe; do
  for timing in false true; do
    index=0
    for filter in "${filters[@]}"; do
      run="$TRIAL_ROOT/$mode-$timing-$index"
      mkdir -p "$run/fixtures"
      chmod 700 "$run" "$run/fixtures"
      status=0
      "$ZIG" build --build-file support/tools/hyperv/persistence/build.zig \
        --system "${PERSISTENCE_PACKAGES:?}" \
        --cache-dir "$run/cache" --global-cache-dir "$TRIAL_ROOT/global" \
        --prefix "$run/out" -Dtest-root="$run/fixtures" \
        -Dtest-filter="$filter" -Doptimize="$mode" \
        -Dpersistence-timing="$timing" -j2 test --summary all \
        > "$run/engine.log" 2>&1 || status=$?
      printf '%s\n' "$status" > "$run/engine.exit"
      index=$((index + 1))
    done
  done
done
```

No native target, backend, CPU feature, stripping or budget override is used.
Keep both exit codes and full bounded timing logs, including failed cases.
Fixture directories/sidecars retain the original test cleanup lifetime; only
sanitized parent log observations survive that cleanup. Do not promote them
to accepted-effect or recovery evidence. For just the six focused diagnostic
tests, use the same build command with `-Dtest-filter='persistence timing'`.

### Default-off synthetic worker stripping qualification

This is **qualification only**, not production adoption or a proven fix. The
historical Debug failure remains unreproduced: the later unmodified `9ebaf`
Debug control passed 28/28 with the same 18300386-byte worker. The subsequent
default-off/on timing controls passed 34/34 each. The targeted timing data
showed expensive guarded hashing and narrow headroom, not a demonstrated cause.

`-Dstrip-fixture-debug=true` selects a separately produced copy of **only**
`hyperv-persistence-worker-fixture`. The quiet default still selects the raw
fixture. Neither this worker nor the verifier is installed. The installed CLI,
engine test executable, libraries, unrelated fixtures and production materials
are not stripped. The compiler/backend/optimization options and all original
runtime hashes, 1000-ms fixture budgets, guards, assertions, protocol, result,
ack and recovery behavior are unchanged.

| Build option | Contract |
| --- | --- |
| `-Dstrip-fixture-debug=true` | Explicitly qualify/select the non-installed worker copy. Default false. |
| `-Dfixture-objcopy=ABS` | Required with stripping; explicit approved pinned native LLVM 22.1.8 `llvm-objcopy`. No PATH lookup or Zig-objcopy fallback. |
| `-Dfixture-file-relayout=true` | Explicitly select the existing `file_offset_relayout` policy. Default remains `identical_program_headers`; there is no automatic retry or fallback. |
| `-Dstrip-fixture-report=ABS` | Optional private, create-only report. Requires stripping. Existing files, aliases and symlinks refuse rather than being overwritten. |
| `-Dpersistence-timing=true` | Independent, default-off timing of the actual selected candidate bytes and original runtime checks. |

Tool/report arguments without stripping, relayout without stripping, a missing
tool with stripping, and relative tool/report paths refuse. The caller remains
responsible for the tool's approved distribution/pin; version text alone does
not establish provenance. The objcopy executable is a build `addFileInput`, so
its contents participate in the candidate cache key. No dependencies are fetched
during these runs: use the exact already-staged persistence SDKs with `--system`.

The build invokes the explicit tool as `--strip-debug RAW CANDIDATE`, retains
both artifacts in separate cache directories with the original worker basename,
and never overwrites raw. `qualify-fixture` builds and verifies just that worker
pair without installing or executing it; it refuses without the opt-in.
Every explicitly qualified build target depends on the fresh host-native
ReleaseSafe verifier. In particular, the engine test run cannot consume the
candidate until verification succeeds. `Run.has_side_effects=true` prevents a
cached success from replacing this check, including when the report is omitted.
An existing report on an otherwise identical repeat invocation therefore
refuses; use a new private report path, not deletion/retry.

The verifier calls the unchanged namespace `gate.Pair.openWithPolicy` and
`recheck`, which retain the existing 64-MiB input limit and ELF acceptance
algorithm. Strict policy requires identical program headers. The explicit
relayout policy retains exact entry, virtual layout, flags, sizes, order and
corresponding program-backed bytes, and all existing offset/anchor/backing/
overlap/congruence/page-residue checks. Unknown, zero-byte, PHDR, NULL and STACK
movement remains rejected. No namespace roles or acceptance rules were extended.

The optional report has schema
`hyperv_persistence_fixture_debug_stripping_v1`, authority
`synthetic_only_not_admitted`, `passed=true`, `synthetic=true`,
`admitted=false`, `qualification_only=true`, and the chosen `layout_policy`.
Its sole `worker` contains role `persistence_worker` and the existing gate's
`raw`, `candidate` literal file proofs and `content` proof. There is no invented
second namespace role, `pairs` array or external namespace fixture. The existing
namespace proof consumer rejects this distinct schema.

Reports reuse the bounded 32768-byte, 0600, exclusive-create shared publisher
with file/directory fsync. Publication is followed by private single-link
readback, exact content comparison and renewed input identity/full-hash checks.
The literal full-file hashes differ; normalized mapped-content hashes do not
claim literal byte identity, debugger equivalence or arbitrary executable
self-inspection equivalence. A successful check is a fresh observation, not a
lock against later owner mutation. The caller must retain private cache custody
through execution. A failure after publication may leave a report, but the
invocation fails and that report must not be consumed as a successful handoff.
Neither stripping nor its report establishes 8-MiB/256-MiB ledger fit or any
production admission.

#### Selected synthetic integration CI

The `integration` workflow's native `zig-hyperv-runtime` persistence-fixture step
explicitly selects verified stripped worker copies in Debug and ReleaseSafe.
It uses the already acquired pinned LLVM 22.1.8 distribution, an absolute
objcopy path and explicit file-offset-relayout policy. Version evidence and
the executable hash are retained, with a final hash recheck.

Each mode runs the engine, affected ARM and shared ELF/proof cases together
with installation, behind the fresh native verifier and a private per-mode
report. Raw/candidate cache binaries, reports and fixture logs are retained in
`zig-hyperv-runtime-evidence`. This lane must succeed before the unchanged real
`zig-hyperv` image producer can run.
Timing remains default-off. The installed CLI is not stripped and must still
refuse with `production_bindings_unavailable`; direct build defaults and all
runtime hashing, deadlines and production gates remain unchanged. This CI
selection does not retire the separate legacy controller workflow or confer
production admission.

#### Focused author checks

Use a process-local `umask 077`; the existing shared fixtures require private
temporary directories. `test-strip-equivalence` runs the original 13 byte-only
ELF/private-file cases, including synthetic x64 data without executing it.
`test-strip-proof` runs five persistence argument/report cases against the real
qualified pair and requires the stripping opt-in. The engine `test` suite
remains the same 34 cases.

```bash
umask 077
"$ZIG" build --build-file support/tools/hyperv/persistence/build.zig \
  --system "$PERSISTENCE_PACKAGES" --cache-dir "$SCRATCH/cache" \
  --global-cache-dir "$SCRATCH/global" --prefix "$SCRATCH/out" \
  -Dtest-root="$SCRATCH/fixtures" -Doptimize=Debug \
  -Dstrip-fixture-debug=true -Dfixture-objcopy="$LLVM_OBJCOPY" \
  -j2 test-strip-equivalence test-strip-proof --summary all
bash support/tools/hyperv/persistence/fixture-strip-build-tests.sh \
  "$ZIG" "$LLVM_OBJCOPY" "$PERSISTENCE_PACKAGES" "$PRIVATE_TEST_ROOT"
```

The Bash runner requires a new existing owner-only root. It uses the real
build/run graph to cover quiet raw selection, invalid flags, qualified native
execution, create-only report refusal on a cache hit, uncached verification
with no report, namespace-schema refusal, invalid tool output and cached
candidate tampering. Deliberately invalid shell payloads would leave a marker
if incorrectly executed; both rejection paths must leave none. Only the
runner's candidate cache copy is corrupted, after retaining full good raw/
candidate copies. The selected raw is never modified, and a final default-off
run remains independent of the rejected candidate.

#### Parent-owned native x64 qualification recipe

After independent review, use the already-approved native Zig 0.16, exact
persistence SDKs and pinned LLVM 22.1.8. Set the absolute variables below and a
new private `QUALIFICATION_ROOT`; the parent separately owns VM/readiness,
source/tool provenance and disk bindings. Choose `LAYOUT_POLICY` **before**
the run: either `identical_program_headers` or the explicitly qualified
`file_offset_relayout`. A refusal is retained, never automatically retried.

```bash
cd "${REVIEWED_SOURCE:?}"
umask 077
root="${QUALIFICATION_ROOT:?}"
mkdir -m 700 -- "$root"
mkdir -- "$root/home" "$root/tmp" "$root/global"
export HOME="$root/home" TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/global"
"${ZIG:?}" version > "$root/zig.version"
test "$(tr -d '\n' < "$root/zig.version")" = 0.16.0
"${LLVM_OBJCOPY:?}" --version > "$root/objcopy.version"
awk -f support/tools/hyperv/preparation/ci-objcopy-version.awk "$root/objcopy.version"
sha256sum -- "$LLVM_OBJCOPY" > "$root/objcopy.sha256"
git rev-parse HEAD > "$root/source.sha"
sha256sum support/tools/hyperv/persistence/build.zig.zon > "$root/manifest.sha256"
case "${LAYOUT_POLICY:?}" in
  identical_program_headers) layout=() ;;
  file_offset_relayout) layout=(-Dfixture-file-relayout=true) ;;
  *) echo 'Unsupported layout policy' >&2; exit 2 ;;
esac
filters=(
  'real native leaf workers deliver bound private results and exact serial model'
  'partial native page checkpoint survives killed delivery without claiming full upload'
  'cleanup recovery requires bound parent reaping proof and never replays mutations'
  'failed native creation delivery retains UUID and refuses cleanup replacement'
)
for mode in Debug ReleaseSafe; do
  for variant in raw qualified; do
    index=0
    for filter in "${filters[@]}"; do
      run="$root/$mode-$variant-$index"
      mkdir -p -- "$run/fixtures"
      selection=()
      if [ "$variant" = qualified ]; then
        selection=(-Dstrip-fixture-debug=true "-Dfixture-objcopy=$LLVM_OBJCOPY"
          "${layout[@]}" "-Dstrip-fixture-report=$run/qualification.json")
      fi
      status=0
      "$ZIG" build --build-file support/tools/hyperv/persistence/build.zig \
        --system "${PERSISTENCE_PACKAGES:?}" --cache-dir "$run/cache" \
        --global-cache-dir "$root/global" --prefix "$run/out" \
        -Dtest-root="$run/fixtures" -Dtest-filter="$filter" \
        -Doptimize="$mode" -Dpersistence-timing=true "${selection[@]}" \
        -j2 test --summary all > "$run/engine.log" 2>&1 || status=$?
      printf '%s\n' "$status" > "$run/engine.exit"
      index=$((index + 1))
    done
  done
done
```

Keep logs, exits, proofs and full raw/candidate cache artifacts, including
refusals. Compare only matching mode/filter/timing-enabled controls using each
log's selected byte count; quiet historical off logs supply no timing baseline.
This recipe changes no backend/CPU flags, runtime budget, hashing or production
gate. No CI activation, publication or production adoption is implied.
