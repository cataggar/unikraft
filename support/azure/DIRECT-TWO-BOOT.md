# Direct Azure #89: one guarded image, two boots

WAMR tiny-AOT has a [separate purpose-specific adapter](WAMR-DIRECT-COMPUTE.md).
It shares the native lifecycle machinery but accepts neither this persistence
scope nor its seed/approval/result contract. This document remains the
two-disk persistence lane.

The native `uk-hyperv-direct-two-boot` is the bounded **direct specialized
Generation 2 Unikraft VM** lane. Azure CLI manages only run-owned resources;
the existing native `uk-hyperv transfer` uploads each exact fixed VHD. It does
not run a Linux host, guest agent, nested QEMU/KVM, SSH, cloud-init, Python
workflow, or the parked native ARM controller. It does not consume, fabricate,
or reinterpret a nested #120 completion receipt.

The direct native platform boot observed on 2026-09-14 reached
`UK_HYPERV_PLATFORM_READY` and passed networking, but subsequently failed
storage binding and returned 1. Its boot-only exit 0 was **not #89 acceptance**.
A later guarded direct attempt on the same date completed real Boot1
enrollment, five writes, three flushes and receipt/readback, but the controller
refused Boot2 because the successful workload omitted its platform marker.
That attempt was cleaned up and remains consumed; it did not establish
reboot persistence. The guarded workload now emits `UK_HYPERV_PLATFORM_READY`
after complete discovery and unique target admission, before workload
mutation. The controller still requires that marker and the full persistence
evidence independently; neither one substitutes for the other.

A separately authorized attempt on 2026-09-15 used a fresh native seed and
matching image, but failed the controller's running-only post-deployment
check when Azure reported `PowerState/stopped`. No serial was fetched before
owned cleanup deleted the VM, so its guest result is **unknown**. No Boot2
admission or start occurred. Cleanup independently confirmed group absence;
the local seed bytes remained unchanged and the attempt's ledger remains
consumed. This fix does not authorize a retry.

A third separately authorized fresh experiment on 2026-09-15 passed full
Boot1 evidence, verified deallocation and original identities, and issued
the sole admitted start. Its first post-start diagnostic capture was
byte-identical to pinned Boot1, including the old timings and write/flush
markers. The failure-only capture was also the old Boot1 text. No genuine
Boot2 result was observed; the attempt failed and owned cleanup completed.
Those three experiment grants remain consumed, with their local seed sets and
prior evidence unchanged. This readonly polling correction authorizes no
new cloud attempt.

A fourth separately authorized fresh experiment on 2026-09-15 passed Boot1,
retained deallocation/identity checks and the sole Boot2 start. Three exact
cached Boot1 snapshots were skipped. A later **normal** diagnostic capture
contained appended boot data, but the approved `per_boot` mode rejected it:
the original 5632-byte Boot1 capture had 5168 log bytes followed by 464 terminal
NULs; the new 10752-byte capture preserved those 5168 bytes and replaced the
padding with appended data, not the entire raw Boot1 prefix. Read-only,
non-authoritative postrun analysis of the exact suffix from that original
normal capture passed the unchanged native Boot2 identity, receipt, zero-I/O,
platform and completion checks. Failure-only diagnostics were not used for
that analysis. The original scope/mode, raw captures, ledger and outcome
remain immutable: **accepted=false, primary=1, cleanup=0, boots=2, cached=3**.
That analysis does not retrospectively accept the run. Those four grants
remain consumed; the opt-in framing change itself authorized no fifth attempt.

A fifth, separately approved experiment on 2026-09-15 ran from 04:06:47 to
04:18:09 UTC using `azure_cumulative` and the source tree subsequently merged
in #145 (`577f64b6`). Both boots passed the native canonical/platform gates:
Boot1 enrolled the original seed, wrote and flushed data, and read it back;
Boot2 verified the persisted receipt/data with unchanged identity and zero
workload writes or flushes. The original VM/image/disks survived the sole
deallocate/start transition, and final deallocation was observed. The recorded
result was **accepted=true, primary=0, cleanup=0, boots=2, cached=3**.
Owned resource absence and capability removal were independently confirmed.
All five seed sets and earlier evidence remain unchanged; all five grants are
consumed. This accepted #89 result is the behavioral baseline for the #144
native controller migration, not authorization for another cloud run. That
accepted run used the shell orchestrator; it is not live qualification of the
native replacement.

## Authorization and input custody

Do not execute this lane under an earlier OS-only boot grant. A human must
separately approve the exact original private seed/manifest, final guarded
native image and solved configuration, disposable **4 GiB data disk at LUN
7**, two boots, fresh resource group, and bounded owner-checked cleanup.
Code availability, a fixture, or an image digest alone is not that approval.

The caller supplies a private JSON scope with **all** fields below. Placeholder
values are intentionally not executable approval. Hashes bind the actual
files, not filenames or another preparation's receipts. Use lowercase SHA256
hex; IDs are distinct, nonnil lowercase hex32. `attempt_id` and `subscription`
are UUIDs, not the seed identities.

```json
{
  "schema": "uk.hyperv.direct-two-boot",
  "version": 1,
  "approval": {
    "destructive_data_disk": false,
    "direct_specialized_gen2": false,
    "two_boots_only": false,
    "cleanup_owned_group": false,
    "original_seed_reviewed": false,
    "guarded_native_image_reviewed": false,
    "expires_unix": 0
  },
  "attempt_id": "OPERATOR-SELECTED-FRESH-UUID",
  "subscription": "EXPLICITLY-APPROVED-SUBSCRIPTION-UUID",
  "location": "APPROVED-REGION",
  "prefix": "APPROVED-FRESH-NAME",
  "vm_size": "Standard_D2s_v5",
  "run_id": "ORIGINAL-HEX32",
  "disk_id": "ORIGINAL-DISTINCT-HEX32",
  "controller": "SCSI",
  "lun": 7,
  "sectors": 8388608,
  "sector_size": 512,
  "serial_mode": "per_boot",
  "runtime_seconds": 3600,
  "cleanup_seconds": 1800,
  "operation_seconds": 600,
  "poll_seconds": 10,
  "os_vhd": {"path": "/PRIVATE/guarded.vhd", "size": 69206528, "sha256": "EXACT-SHA256"},
  "seed_raw": {"path": "/PRIVATE/original.raw", "size": 4294967296, "sha256": "EXACT-SHA256"},
  "seed_vhd": {"path": "/PRIVATE/original.vhd", "size": 4294967808, "sha256": "EXACT-SHA256"},
  "manifest": {"path": "/PRIVATE/original.json", "size": 1, "sha256": "EXACT-SHA256"},
  "config": {"path": "/PRIVATE/solved.config", "size": 1, "sha256": "EXACT-SHA256"}
}
```

The original policy-2 manifest format is the existing storage manifest JSON:
version/policy 2, `seed-enrollment-v2`, null path/target, seed LBAs 8/9, intent
16, receipt 17, extent 32..47, original IDs, CRC and exact geometry. Synthetic
seed manifests and policy 1 are not accepted. The native validator streams
the complete original raw/VHD, checks their approved hashes and two seed
records, requires all other payload bytes pristine zero, verifies fixed-VHD
footer checksum/size/UUID, and never rewrites or regenerates either disk.
It also hashes the entire solved config and checks its guarded-v2 projection.
The operator's reviewed image/config pairing must come from the real native
build and image checker: this small importer does **not** prove build
provenance or reconstruct compiled Kconfig from EFI bytes.
The native helper reuses the pure module APIs `evidence.EvidenceInput` and
`evidence.parseWorkload`; these are not `uk-hyperv` CLI subcommands and carry
no execution authority.

SCSI is explicit in the ARM template. Policy 2 intentionally enrolls the
actual StorVSC controller instance, path, target and VPD only after exactly
one original seed matches at LUN 7/capacity. Those identities must remain
byte-identical on Boot2; never guess a controller GUID or weaken the seed gate.
The explicit direct guest profile uses `CONFIG_LIBSTORVSC_MAX_DEVICES=2`,
`CONFIG_LIBSTORVSC_MAX_LUNS=2`, `CONFIG_LIBSTORVSC_LUN_DISCOVERY=y` (REPORT
LUNS), and guarded I/O. `MAX_LUNS` counts retained identities per controller,
not the largest numeric LUN address; two slots therefore support the original
LUN 7 seed without alteration. The new pure
`prep.config.validateDirectPersistence` check admits this exact direct
profile; legacy preparation render/validation still require their original
eight-slot profile and are not reinterpreted or silently normalized.
The guest driver/workload must actually support this direct target. A
platform-only marker, read-only smoke test, or old nested receipt cannot
establish target readiness.

The OS VHD is only read locally; OS caching is `ReadOnly`, both disks use
`Detach`, and the workload must reject the OS as a writable candidate.
Azure OS caching `ReadOnly` is **not** a hypervisor-enforced read-only disk
permission. The guarded guest's exact seeded-target selection is the write
boundary. Data caching is `None`.

Disk-state admission follows the observed VM phase: both disks must be
`Attached` while allocated (`PowerState/running` **or** `PowerState/stopped`)
and `Reserved` after explicit deallocation, still owned by the same VM with
unchanged disk UUIDs, attachments and geometry. Retained/final deallocation
requires exactly `PowerState/deallocated`; stopped is not a substitute.
Normal kernel halt and crash both use EFI shutdown, so stopped alone proves
neither guest success nor failure. Both boot phases still require the full
native canonical, platform-marker and fresh-serial gates.

## Build and invoke

Requirements: Linux, native Zig 0.16, an explicitly selected authenticated
Azure CLI (tested wire shapes include 2.81/2.90), and the already-built native
transfer CLI. The selected native controller and fixtures do not invoke Bash,
jq, a Python controller, or coreutils as a fallback. Azure CLI and its
implementation dependencies remain permitted for resource management.
The direct build needs no SDK download or new auth provider and reuses the
existing `EvidenceInput`/`parseWorkload` module APIs, not a competing parser.

Both direct controllers support the same [local launcher preflight and explicit
interpreter option](#local-cli-startup-before-consumption). This does not change
their separate approval, topology, seed/image or result contracts.

```sh
umask 077
mkdir -p .d/direct-cache .d/direct-global .d/direct-runtime
TMPDIR="$PWD/.d/direct-runtime" zig build \
  --build-file support/tools/hyperv/direct/build.zig -j2 \
  --cache-dir "$PWD/.d/direct-cache" \
  --global-cache-dir "$PWD/.d/direct-global" \
  --prefix "$PWD/.d/direct-tools" -Doptimize=ReleaseSafe

# ONLY after new explicit destructive approval, never as part of build/test:
"$PWD/.d/direct-tools/bin/uk-hyperv-direct-two-boot" \
  /PRIVATE/approved-direct-scope.json \
  /PRIVATE/NEW-attempt \
  /PRIVATE/original-seed-consumption-ledger \
  /EXPLICIT/path/to/az \
  /EXPLICIT/native/bin/uk-hyperv \
  "$PWD/.d/direct-tools/bin/uk-hyperv-direct-validate"
# For a reviewed tarball launcher requiring Python, append:
#   --az-python /EXPLICIT/CANONICAL/path/to/python3.14
```

The scope and private seed files must be owner-private regular files in
safe, non-symlinked directories. The attempt path must not exist. The ledger
must already exist, mode 0700, and be the operator-selected **persistent
ledger for this original seed**, not a fresh alternative ledger on retry.
The controller reserves attempt UUID, original run/disk identity and seed digest with
atomic directories, then syncs consumption before the first cloud effect.
It never removes those records. An incomplete reservation remains consumed.

### Local CLI startup before consumption

An offline/tarball Azure CLI launcher can require an explicit Python even
though a self-contained CLI does not. The controller deliberately **does not
inherit** ambient `AZ_PYTHON`, `PATH`, `PYTHONPATH`, `PYTHONHOME`,
`PYTHONSTARTUP`, `PYTHONUSERBASE`, `LD_PRELOAD` or `LD_LIBRARY_PATH`. Do not
work around this by changing system installations, exporting language hooks
or wrapping the controller.

Select the reviewed CLI and, only if needed, its interpreter with explicit
canonical absolute paths. The CLI and interpreter must be regular executable
files; no path component may be a symlink. For example, an operator may inspect
`readlink -f` on their selected versioned install to find the canonical path,
but must review it rather than blindly copying ambient `AZ_PYTHON`. The
interpreter must not be group/world writable. Its inode/device, size, mode,
owner, link count and modification/change timestamps are pinned through the
existing executable custody mechanism, rechecked after successful startup and
before/after lifecycle child operations. The legacy platform-only route supplies its selected interpreter as
`AZ_PYTHON` only to the Azure child. That pathname-based package arrangement
does **not** satisfy the finite-cost WAMR authorization route.

`uk-wamr-direct-compute` instead requires the create-only
`uk.wamr.azure-cli-runtime-closure` described in
[WAMR-DIRECT-COMPUTE.md](WAMR-DIRECT-COMPUTE.md). Before planning, its
operator must run `prepare-azure-runtime` with the reviewed Python bootstrap,
explicit Python ELF, complete standard library and every Azure package import
root. The prepared interpreter/bootstrap paths and `azure-runtime.json` are
mandatory in plan, authorization, admission, preflight and execution. WAMR
re-execs itself in a private user/mount namespace before admission, copies the
already authenticated closure to a bounded tmpfs mounted over the approved
root, remounts it read-only, and drops namespace capabilities. It invokes the
retained loader with RPATH and the loader cache inhibited, masks host library
directories in that private namespace, refuses a system `ld.so.preload`, and
resolves only the copied
`DT_NEEDED` names before running Python with `-s -S -B -P`; the interpreter,
bootstrap, modules, data and extensions are addressed below the retained root
as `/proc/self/fd/N/...`. Kernel UID/GID maps, disabled setgroups and private
mount propagation plus the exact initial-namespace parent relationship
authenticate the internal re-exec marker. It does not use
`AZ_PYTHON`, the original bootstrap pathname or an ambient/default loader as
execution authority. The original root and every approved parent remain
retained and revalidated, so later source or parent drift still refuses even
though it cannot alter executed bytes.

Run this local-only command before obtaining a future live approval:

```sh
umask 077
# Existing private parent; use a fresh directory for these local captures.
mkdir -m 700 "$PRIVATE_PARENT/FRESH-cli-startup"
AZURE_CONFIG_DIR="$REVIEWED_OPERATOR_AZURE_CONFIG" \
  "$DIRECT_TOOLS/uk-hyperv-direct-two-boot" preflight \
  "$PRIVATE_PARENT/FRESH-cli-startup" "$REVIEWED_CANONICAL_AZ" \
  --az-python "$REVIEWED_CANONICAL_PYTHON"
# Omit the final flag/value for a self-contained platform-only CLI.

# The WAMR finite-cost route has no optional module/interpreter form:
"$DIRECT_TOOLS/uk-wamr-direct-compute" preflight \
  "$PRIVATE_PARENT/FRESH-wamr-cli-startup" \
  "$PRIVATE_PARENT/FRESH-azure-runtime/runtime/bootstrap/azure-cli" \
  --az-python \
  "$PRIVATE_PARENT/FRESH-azure-runtime/runtime/bin/python" \
  --azure-runtime \
  "$PRIVATE_PARENT/FRESH-azure-runtime/azure-runtime.json"
```

`preflight` accepts no scope, subscription, attempt or ledger argument. It runs
only `az version --output json --only-show-errors` under the same selected,
cleared environment as the lifecycle. It requires exit zero, complete bounded
capture, confirmed process cleanup, empty stderr and the exact supported Azure
version object (`azure-cli`, matching `azure-cli-core`, `azure-cli-telemetry`,
`extensions` with bounded names/three-part numeric versions). It fails closed
on malformed/duplicate/extra/noisy output, timeout or output overflow.
The ceiling is 30 seconds, 4096 bytes per stream, plus the existing two-second
TERM/one-second reap budget. Captures and separate child/cleanup/recording
status stay private; stdout reports only `authority=not_admitted`. This is
launcher compatibility, **not account/resource preflight, provenance
attestation, cloud authority or an admission receipt**.

Normal invocation automatically repeats that exact check after scope/input
validation and **before any attempt/seed/source/image reservation or resource
call**. It uses the lesser of that ceiling and the original operation/execution
budget, rechecks expiry/cancellation/custody before consumption, and does not
restart or extend a deadline. This invocation has already created a private
attempt directory for diagnostics: startup failure leaves that directory
non-resumable but the ledger unconsumed. Use standalone preflight to detect
launcher failures without creating an attempt at all. A standalone pass cannot
be replayed to skip the automatic check.

The planned campaign ledger must already exist and be owner-private (0700).
For a genuinely new campaign, create its reviewed persistent ledger once,
**before the first invocation**:

```sh
# New campaign initialization ONLY, not recovery/reset of an existing ledger.
mkdir -m 700 "$REVIEWED_NEW_CAMPAIGN_LEDGER"
```

For an existing campaign, use its original ledger unchanged; do not create a
replacement. Missing ledger now reports sanitized
`phase=pre-admission reason=CampaignLedgerMissing` without claiming that
nonexistent attempt records can be inspected. Other early failures expose an
error name, never arbitrary child output, credentials or private paths.

An already consumed failure stays consumed even if no resource was created.
Never delete, clear, copy, rename or substitute its ledger/claims, never resume
its attempt, and never reuse its grant. Fresh human approval is required before
any further live invocation, even while an earlier window remains open. A fresh
attempt UUID alone cannot bypass the same persistent ledger's seed/source/image
reservation. If those bytes/identities are already consumed, this software
continues to refuse them; it introduces no retry or administrative override.

The fresh group name is `prefix-rg`; VM, OS/data disks and private networking
are named from the same prefix. All resources must match the attempt UUID,
prefix, image hash, and managed-by tags. A preexisting or unobservably absent
group is never adopted or deleted.

The default build installs only the production controller and read-only
validator. The controller embeds the unchanged ARM template and publishes
its exact bytes privately as `ATTEMPT/deployment-template.json`; it never
searches the checkout for a deployment template at runtime. The seven ARM
parameters are unchanged. The selected runtime and offline lifecycle are
native-only; there is no shell entry or reference-controller fallback.

## Lifecycle and failure semantics

1. Validate approval, exact local inputs and local CLI startup; durably consume the original seed.
2. Create one fresh tagged group and the exact OS/data upload disks. Upload
   sizes include the footer; no `diskSizeGB` resize is requested. Native pages
   retain their existing <=4 MiB PUT/MD5/hash/footer checks.
3. Accept exactly one `accessSas` or `accessSAS` string and no unknown grant
   fields. SAS stays in 0600 files inside 0700 directories, never argv/env.
   Revoke access and observe original UUID, exact byte size and unattached
   disk state before attachment.
4. Durably reserve Boot1 before deployment. Require full ordered enrollment,
   write/flush/receipt/readback, final PASS and `main returned 0` evidence.
5. Deallocate the **original** VM; reobserve original VM UUID, disk UUIDs,
   exact attachments/geometry and deallocated power state; recheck local
   inputs. The create-only, synced `boot2-admission.json` binds the original
   Boot1 serial/capture hashes, scope, VM/disk UUIDs and retained observation
   hashes before the **sole** start.
6. Require full Boot2 persisted-data/receipt evidence with **zero workload
   writes and flushes**, and unchanged enrolled controller/address/VPD.
   Deallocate and observe the original objects again.
7. Always run separately bounded cleanup. Revoke outstanding grants, verify
   group ownership/inventory and original identities, retain eligible
   failure-only diagnostics, delete only the owned group, independently
   observe absence, remove SAS/grant inputs, and retain private outcome/state.

No mutation/start retry, reset, replacement enrollment, third boot, reseed or
success-shaped resume exists. An ambiguous deployment/start/deallocate fails
into cleanup, retaining its reserved boot count. CLI read-only serial polling
is bounded by the execution deadline and 60 reads per boot; CLI output files
are capped at 8 MiB. Serial's Azure JSON-string wrapper is
retained privately then decoded; escaped one-line JSON is never grepped as a
guest transcript. Select `per_boot` for logs replaced on each boot, or
`cumulative` only when the complete Boot1 bytes are retained as a prefix.
These existing modes are unchanged, with no fallback or auto-detection.
Explicitly select `"serial_mode": "azure_cumulative"` only for Azure's
append-over-terminal-NUL framing:

- First validate the **raw** Boot1 log with every canonical stage and the
  platform gate, as before. Empty, all-NUL or incomplete Boot1 cannot admit
  Boot2. Raw log/capture/scope/admission hashes continue to bind unchanged bytes.
- Derive an in-memory Boot1 view by removing **only its terminal NUL run**.
  Canonical `parseWorkload` supplies this view's exact byte length and SHA256.
  Interior NULs, whitespace, ANSI sequences and every nonzero byte remain
  inside that exact prefix gate; no marker scanning or normalization repairs
  a missing, changed or truncated prefix.
- Apply existing `boot2Suffix` to the unmodified cumulative candidate and
  that prefix evidence, then require full canonical Boot2, unchanged identity,
  zero writes/flushes, platform readiness and completion on the exact suffix.
  Both overwritten terminal padding and a fully retained raw Boot1 prefix
  work. Candidate terminal NULs need no trimming: canonical parsing already
  handles them, including a padding-only suffix as incomplete.

All modes require exact phase-specific evidence, not a fresh platform marker alone.
During Boot2 only, a decoded candidate whose full SHA256 exactly matches the
unchanged pinned Boot1 is classified as **not yet fresh**. Before every such
skip, the controller revalidates original Boot1, its capture record, scope
and Boot2 admission hashes. It does not invoke the native parser on cached
bytes or promote them to `boot2.log` or a Boot2 capture. The read consumes the
existing poll count, delay and execution deadline; none is increased, and no
additional start or refresh mutation is issued. Cumulative exact no-advance
remains incomplete under the same bounds. In `azure_cumulative`, unchanged
nonpadding Boot1 bytes alone, or with only a different amount of terminal NUL
padding, also remain incomplete under those existing bounds. No new time,
read-count or output-size budget is introduced.
Every different candidate still goes through the unchanged full native
canonical, platform, identity and zero-write/flush checks in its explicitly
selected framing mode; a nonpadding change to old Boot1 is not treated as
cache. Hash-read failures propagate instead of being
classified as fresh or cached. Private `driver.stderr` records cached-read
indices and `outcome.boot2_freshness` records `cached_reads` and
`cached_reason` (`identical-pinned-boot1`, or null when none were skipped).
If diagnostics never become fresh, the attempt fails under the existing
60-read/runtime limits and follows ordinary owned cleanup. A later
successful-looking failure-only diagnostic cannot establish Boot2 acceptance.
The original `boot1.log` and its create-only `boot1-capture.json` are hash-pinned
and rechecked before admission, before Boot2 parsing and before acceptance.
`boot2-capture.json` attributes the new capture to the original VM UUID, its
post-start observation, the durable Boot2 admission, selected serial mode,
raw CLI wrapper and decoded log hashes. Reset diagnostics never replace or
reinterpret Boot1 evidence; `cumulative` must preserve its exact raw bytes,
while `azure_cumulative` must preserve its exact terminal-NUL-unpadded view.
No stripped log replaces a raw capture or custody hash. These are local
custody/operation records, not a fabricated guest boot
receipt or evidence that an unobserved external restart could not occur.

`outcome.json` keeps primary and cleanup exits separate. Successful deletion
never erases a failed upload or guest failure; failed empty-upload revoke
(`InvalidVhd`) remains a cleanup failure even if owner-checked deletion works.
Typed observation failures preserve their public nonzero category and private
raw capture without promoting failed, partial or undurable output to evidence.

On nonzero primary failure, cleanup may make **one** read-only boot-log
request before deleting the group, only after the existing group, inventory,
VM and disk identity/ownership checks pass, with known original UUIDs and a
reserved boot. Uncertain ownership or identity prohibits diagnostic access.
The capture shares the existing cleanup deadline and is capped at 30 seconds,
including termination grace; it reserves full delete/absence operation
budgets and is skipped if that cleanup budget is unavailable.
`failure-boot-diagnostics.json` retains the private CLI wrapper;
`failure-boot-diagnostics.log` is its privately decoded JSON string. Read and
decode errors have separate private stderr files. `outcome.failure_diagnostics`
records `attempted`, `exit` (read/decode status, or null when skipped) and
`decoded`, independently of primary and cleanup exits. Provider/decode failures
do not become cleanup failures or erase the primary failure.
Actual local capture IO or durability failures permanently latch a recording
failure, including for diagnostic captures, rather than being retried into
acceptance. These files are **never parsed as acceptance evidence or promoted** to
Boot1/Boot2 captures or admission, even if the text appears to contain a full
pass. There is no diagnostic retry, resume, start or resource creation.

Grant/credential inputs are removed even on failure; no Azure account/token
cache is copied into the attempt. Raw CLI/native diagnostics and logs are
private. Do not publish the attempt directory.

TERM/INT/HUP use cleanup; an uncatchable kill or machine loss may interrupt
it. Retained consumption and intent records forbid rerun. The operator must
then reconcile the retained IDs and perform separately authorized bounded
cleanup; this controller has no crash-resume or automatic reauthorization mode.
Do not describe an uncertain cleanup as absent or accepted.

## Offline validation

```sh
umask 077
mkdir -p .d/direct-runtime .d/direct-foundation-fixtures
fixture_parent="$PWD/.d/NEW-direct-fixture-parent"
mkdir -m 0700 "$fixture_parent"
TMPDIR="$PWD/.d/direct-runtime" zig build \
  --build-file support/tools/hyperv/direct/build.zig -j2 \
  --cache-dir "$PWD/.d/direct-cache" --global-cache-dir "$PWD/.d/direct-global" \
  --prefix "$PWD/.d/direct-tools" \
  -Dtest-root="$PWD/.d/direct-foundation-fixtures" \
  -Dlifecycle-root="$fixture_parent/native" \
  -Doptimize=ReleaseSafe test test-foundation test-controller test-lifecycle-native install
```

`test-lifecycle-native` builds a separate **noninstalled** fixture controller
that uses the same state machine and real clocks, with unchanged scope
budgets. Its explicit fake programs cannot delegate to Azure, a real transfer,
or real input disks; the real native serial validator still processes fixture
bytes. Production has no fixture backend, clock, admission or hash-failure
switch. `-Dlifecycle-cases=name,name` selects cases. The root must be absolute
and nonexistent, beneath a fresh private mode-0700 parent inside the
checkout's `.d`. This preserves repository-template resolution without
changing shared ancestor permissions. No fixture root is needed for an
ordinary production build.

The optional `fixture-tools` target installs only the native fake and runner
for inventory or explicitly isolated native runs, never the fixture controller:

```sh
TMPDIR="$PWD/.d/direct-runtime" zig build \
  --build-file support/tools/hyperv/direct/build.zig -j2 \
  --cache-dir "$PWD/.d/direct-cache" --global-cache-dir "$PWD/.d/direct-global" \
  --prefix "$PWD/.d/direct-tools" -Doptimize=ReleaseSafe fixture-tools
"$PWD/.d/direct-tools/bin/hyperv-direct-lifecycle-fixtures" \
  --inventory
```

`fixture-tools` is explicit and separate from the default installation.
The native suite retains all 92 named legacy cases plus signal and overflow
process cases. It supplies a checked-in native fake CLI and transfer/input
reader with no real-CLI/network/disk delegation. The real native serial
validator still processes fixture bytes. `--inventory` lists the coverage
map; `--case name,name` selects a subset. Direct runner invocation requires
`--controller ABS --root NONEXISTENT_ABS --fake ABS --validator ABS`, with
all three programs verified as native executables. The retired `--backend`
and `--compare` options are refused, not ignored; the build no longer accepts
`-Dlifecycle-compare`. Use absolute paths, preserve source executable modes,
and do not precreate a suite root. Use a separate nonexistent child of the
fresh private parent for each additional invocation.
The immediate parent of each suite root must already be owner-private
(mode 0700), and suite roots must remain beneath the checkout's `.d` so the
fixture tools resolve the unchanged repository template. If that shared `.d`
directory is not private, create a dedicated fresh mode-0700 parent beneath
it rather than changing shared permissions or moving suites outside the
checkout. CI uses one such parent per run/attempt; build tools and caches
remain in the separate external `${RUNNER_TEMP}/hyperv-ci/direct` tree.

The native suite recomputes every custody hash and requires each named
case's mandatory evidence records, including refusal cases. Missing-record
controls remove each required file, all required files together, and both
captures together where required. Malformed JSON and byte-only record drift,
within-run exit bindings, exact mutation/cleanup order, and native adapter
privacy/template guards remain independently checked. Only
`stale-boot1-log` and `azure-padding-only` allow the declared 1/124 deadline
race; no other statuses or budgets are normalized. Overflow requires public
status 153, an independently recorded actual TERM/KILL termination, exactly
8 MiB retained, and observed termination before the original deadline.
The defective drain-without-termination negative control remains rejected.
CI runs all 94 native cases once, plus the controller and foundation cases.
Reference-controller comparison and its comparison-only checks are retired;
there is no duplicate lifecycle or additional CI pipeline.

The full native runner reports **890 assertion-regression checks**, in
addition to the ordinary assertions for all 94 lifecycle cases:

| Native regression group | Checks |
|---|---:|
| Case-specific missing custody records (287 removal masks, 58 restored cases) | 345 |
| Native grant-output, private-context and exact-template controls | 52 |
| Explicit CLI inputs, retired-option refusals and selectors | 23 |
| Within-run outcome status, type and mandatory-field controls | 455 |
| Malformed capture/admission JSON, hash drift and restored custody | 7 |
| Overflow status, termination deadline and defective natural-completion controls | 8 |

Cutover removes 292 cross-run outcome-comparison checks, 345 redundant
self-comparison custody checks, and 22 reference-only adapter checks from
the former 1,060-check native run. The former 1,634-check strict comparison
also had 574 additional cross-run custody checks, which are retired.
All 401 noncomparison native checks remain, with 489 new native checks:
23 CLI, 455 outcome, 7 malformed-record/restoration, 2 retired-context and
2 stricter overflow-status controls. The separate controller and foundation
targets retain their 18 and 85 tests, including permanent local-failure
latches, supervisor poison and unconditional final local custody auditing.

Read-only validator fixtures exercise seed/manifest/footer validation in
memory, not on real disks, and call the same direct-helper framing functions.
Framing cases cover overwritten/retained padding, no advancement, interior
NUL/ANSI/whitespace custody, prefix drift/truncation, canonical refusals and
unchanged legacy modes. Lifecycle cases also retain raw hashes/captures,
the sole start, bounded polling and failure-only diagnostic non-authority.
These tests cannot authorize or establish live #89 acceptance.

## Native controller contract (#144)

The observation, custody and private subprocess libraries are implemented
under `support/tools/hyperv/direct/`. `test-foundation` exercises these
libraries, including isolated process-poison cases, and compiles their
production interfaces without running them. `test-controller` exercises
controller policies and private IO; `test-lifecycle-native` exercises the
complete orchestration without cloud access. Neither test target installs
the fixture controller. The selected obsolete shell/jq entry, shell fixture
tools and temporary reference-comparison machinery have been removed.

The native cutover retains the six explicit command inputs shown above. It does
not add a broad `uk-hyperv` execution mode or enable the parked production
stubs. The native validator remains a bounded child; transfer remains the
existing native `transfer PRIVATE_DIRECTORY JOB_BASENAME` protocol.

The local JSON contract is unchanged. In the table, **identity fields** means
`vm_id`, `vm_uuid`, `os_id`, `os_uuid`, `data_id`, `data_uuid`, all exact
strings. Hash fields are lowercase SHA256 strings, not paths or substitute
guest receipts.

| Record | Fields |
|---|---|
| `scope.json`, ledger `consumed.json` | Byte-for-byte copies of the complete admitted scope above; no reserialization or alternate approval. |
| `events.jsonl` | `phase`, `reserved_boots`; append-only, synced records using the existing hyphenated phase names. |
| `boot1-capture.json`, `boot2-capture.json` | `schema` = `uk.hyperv.direct-serial-capture`, `version` = 1, `boot`, `poll`, `serial_mode`, `serial_sha256`, `cli_wrapper_sha256`, `scope_sha256`, identity fields, `vm_observation_sha256`, `original_boot1_sha256`, `boot2_admission_sha256`. |
| `boot2-admission.json` | `schema` = `uk.hyperv.direct-boot2-admission`, `version` = 1, `reserved_boots` = 2, `scope_sha256`, `original_boot1_sha256`, `boot1_capture_sha256`, identity fields, `retained_vm_sha256`, `retained_os_sha256`, `retained_data_sha256`, `deallocated_power_sha256`. |
| `outcome.json` | `phase`, `primary_exit`, `cleanup_exit`, `reserved_boots`, `persistence_evidence_complete`, `owned_group_absent`, `group_creation_attempted`, `failure_diagnostics`, `boot2_freshness`, `accepted`. |
| `outcome.failure_diagnostics` | `attempted`, nullable `exit`, `decoded`; diagnostic failure is separate from primary and cleanup failure. |
| `outcome.boot2_freshness` | `cached_reads`, nullable `cached_reason`; the sole nonnull reason is `identical-pinned-boot1`. |
| Native page `request.json` | `schema` = `unikraft.hyperv.managed-disk-page-worker`, `schema_version` = 1, `endpoint` without SAS, `path`, `size`, `sha256`. |
| Native transfer job | `contract` = `uk.hyperv.transfer-job`, `schema_version` = 1, `kind` = `pages`, `request`, `sas`, `timeout_ms`, `cleanup_ms`; SAS is a private filename, never the capability value. |

Ledger names remain `attempt-<attempt_id>`, `<run_id>-<disk_id>`, and
`sha256-<seed_vhd.sha256>`. Every reservation and its containing directory
must become durable before effects. Partial creation remains consumed.
The stable `.writer.lock` inode is never replaced or removed. Scope,
capture, admission and outcome publication is create-only; collisions do
not authorize overwrite, resume or another ledger. Raw captures use
bounded streaming publication, not the small-record API.

The existing executable-status baseline is also explicit:

| Condition | Existing observable behavior to preserve |
|---|---|
| Invalid command/local admission or explicit controller refusal | Nonzero, normally 1; no effects before admission and consumption. |
| Propagated Azure/native child failure | Retain the actual nonzero child status; successful deletion never replaces it with 0. |
| Execution budget exhausted / approval expires before a primary Azure call | 124 / 125 respectively. The initial expired-approval admission is a local refusal. |
| Handled HUP / INT / TERM | 129 / 130 / 143 respectively, followed by separately budgeted owned cleanup. |
| Canonical serial validator | 0 may establish a capture; 2 means incomplete and consumes the existing poll/delay budget; other statuses reject guest evidence. Read-only serial-provider failures may consume a poll, not authorize another mutation. |
| Typed observations | Refusal/capture/local failure 1, malformed JSON 4, filter/type failure 5; the mapping preserves the declared legacy categories without invoking jq. |
| Private output limit | Public status 153 preserves the legacy file-size refusal, only for a confirmed `output_limit` failure. Actual native child termination remains separately recorded; it is not misreported as SIGXFSZ. |
| Successful primary with failed cleanup, final input validation or outcome recording | Nonzero final status; no acceptance. |

Native observation errors retain separate `refused`, `filter_error`,
`malformed`, `capture` and `local` categories rather than pretending that
every error is jq false. Runtime results separately retain the actual child
exit/signal, execution failures, capture state, byte counts and cleanup
completion. Partial, overflowed, failed or undurable output is private
diagnostic material, never an admissible observation. Capture IO/durability
and process-record publication failures permanently poison primary admission
and retain an independent recording failure, even if a later read succeeds.
The actual child status and the explicit overflow mapping remain unchanged.
The controller's
integer mapping must preserve the lifecycle contract above and its named
parity assertions; libraries do not invent an exit status for their callers.

Primary evidence refusal is permanent but does not itself fabricate a cleanup
failure. The two cleanup intent phases may append only after independently
revalidating the original private directory, stable writer lock and event-log
custody; they never clear refusal or enable another primary operation.
Cleanup authority remains the original admitted in-memory scope and identities.
Real writer/durability, capability, final-input and outcome-recording failures
remain independent failures. The final-input status is the actual bounded
validator result, not an already-recorded primary scope-byte-hash refusal.
`FinalResult.evidence_error` is an internal final-evidence result, not a new
JSON field; callers must always honor the final `exit_code`.
Final local scope/source/reference checks run even when supervisor poison
prevents another child or cleanup budgeting fails. A new scope-proof refusal
is recorded without replacing an earlier primary failure or the actual final
validator status; it never changes cleanup authority.

Intentional parser strictness is limited and explicit: reject duplicate
JSON keys, bounded structural overflow, object-shaped status collections,
and fractional numbers that floating-point jq evaluation might round to an
integer. Exact integral JSON numbers and canonical decimal strings retain
their field-specific rules; missing/null/extra ARM fields are accepted only
where the existing observation contract permits them. Resource identifiers
are not globally case-normalized.

Native `runPrivate` does not widen existing `process.run` callers: their
4-MiB limits, failed-stdout clearing and stderr redaction remain unchanged.
The new private capture path permits at most 8 MiB per stream. Native transfer
now latches handled signals and passes cancellation to its existing worker
supervisor, so its own child groups can be reconciled. For a nonnested private
command, an observed leader exit and both pipe EOFs end the command without
an artificial two-second delay. Any remaining group members with closed output
are treated as abandoned and killed immediately. The unreaped leader remains
pinned through that final group signal, and bounded reaping is still mandatory:
EOF alone never proves that descendants are gone. Running work, inherited open
pipes, timeout/cancellation, nested supervision and legacy callers retain
their previous termination behavior. Unresolved descendants
poison the dedicated supervisor and retain writer ownership until process
exit; they prohibit further supervised operations, including cloud cleanup.
No poison reset, unbounded wait or success-shaped cleanup fallback exists.

Optional native diagnostics reserve two complete cleanup operations,
including each operation's termination and reaping allowance. Their own
absolute cap remains 30 seconds: at most 27 seconds of execution, two seconds
of TERM grace and one second of reaping. Reaping consumes that existing cap;
it never adds time to it.

Acceptance requires successful process completion as well as durable
records. An immutable `outcome.json` can become visible before its final
directory sync fails; even an `accepted` field in such a partial publication
cannot establish acceptance. Do not infer success from that file alone or
retry the consumed attempt. The five historical live grants remain consumed;
these offline foundations grant no new cloud authority.
