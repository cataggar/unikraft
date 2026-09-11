# Native persistence execution engine

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
IP, acceleration, forwarding, NAT, or custom routes), MiB-aligned VHD upload
geometry with a GiB allocation ceiling (including the original 66-MiB guest),
and an opt-in full persistence VM attachment envelope. Existing default VM
behavior is unchanged. OS creation explicitly selects Linux/Generation 2;
logical bytes are the VHD payload size, not the GiB billing/allocation ceiling.
Before deployment, detached original disk UUIDs, raw `diskSizeBytes`, roles and
readiness are checked. Subsequent observations require attachment to the
original VM; cleanup never accepts an unrelated attachment.

APIs remain pinned: groups/deployments 2021-04-01,
compute VM 2025-11-01, disks 2025-01-02, network 2024-05-01, pages 2020-10-02,
Blob downloads 2024-11-04. No storage account/key/firewall is created by #89.

## Evidence and offline fixtures

`evidence.parse` implements the actual guest's eight ordered serial markers,
run/disk/controller/VPD identity, LUN 7, 8388608x512 geometry, Boot1 5 writes/
3 flushes, Boot2 0 writes/0 flushes, receipt verification and terminal return.
It requires the complete raw Boot1 prefix unchanged in accumulated Boot2
serial. Parsing strips ANSI CSI/NUL decoration only; saved bytes and hashes
remain exact. VPD is limited to the actual C maximum of 64 bytes. Benign
unrelated text is not rejected merely for containing `BOOT1` or `RESEED`.

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
