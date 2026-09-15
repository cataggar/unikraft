# Direct Azure #89: one guarded image, two boots

`support/scripts/hyperv-direct-two-boot.sh` is the bounded **direct specialized
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
All three experiment grants remain consumed, with their local seed sets and
prior evidence unchanged. This readonly polling correction authorizes no
new cloud attempt.

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

Requirements: Bash, GNU `timeout`/`sync`/`stat`, `/usr/bin/jq`, native Zig
0.16, an explicitly selected authenticated Azure CLI (tested wire shapes
include 2.81/2.90), and the already-built native transfer CLI. No SDK download
or new auth provider is needed for the small validation helper.
Integrate the owner-frozen workload parser change
`5a75a470fc8651d4141ffed1c8adab8f8a8f42e6` (or its reviewed integration replay)
before building: it supplies the real `EvidenceInput`/`parseWorkload` module
API. This harness does not carry a competing parser implementation.

```sh
mkdir -p .d/direct-cache .d/direct-global .d/direct-runtime
TMPDIR="$PWD/.d/direct-runtime" zig build \
  --build-file support/tools/hyperv/direct/build.zig \
  --cache-dir "$PWD/.d/direct-cache" \
  --global-cache-dir "$PWD/.d/direct-global" \
  --prefix "$PWD/.d/direct-tools" -Doptimize=ReleaseSafe

# ONLY after new explicit destructive approval, never as part of build/test:
support/scripts/hyperv-direct-two-boot.sh \
  /PRIVATE/approved-direct-scope.json \
  /PRIVATE/NEW-attempt \
  /PRIVATE/original-seed-consumption-ledger \
  /EXPLICIT/path/to/az \
  /EXPLICIT/native/bin/uk-hyperv \
  "$PWD/.d/direct-tools/bin/uk-hyperv-direct-validate"
```

The scope and private seed files must be owner-private regular files in
safe, non-symlinked directories. The attempt path must not exist. The ledger
must already exist, mode 0700, and be the operator-selected **persistent
ledger for this original seed**, not a fresh alternative ledger on retry.
The script reserves attempt UUID, original run/disk identity and seed digest with
atomic directories, then syncs consumption before the first cloud effect.
It never removes those records. An incomplete reservation remains consumed.

The fresh group name is `prefix-rg`; VM, OS/data disks and private networking
are named from the same prefix. All resources must match the attempt UUID,
prefix, image hash, and managed-by tags. A preexisting or unobservably absent
group is never adopted or deleted.

## Lifecycle and failure semantics

1. Validate approval and exact local inputs; durably consume the original seed.
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
Both require exact phase-specific evidence, not a fresh platform marker alone.
During Boot2 only, a decoded candidate whose full SHA256 exactly matches the
unchanged pinned Boot1 is classified as **not yet fresh**. Before every such
skip, the controller revalidates original Boot1, its capture record, scope
and Boot2 admission hashes. It does not invoke the native parser on cached
bytes or promote them to `boot2.log` or a Boot2 capture. The read consumes the
existing poll count, delay and execution deadline; none is increased, and no
additional start or refresh mutation is issued. Cumulative exact no-advance
remains incomplete under the same bounds.
Every different candidate still goes through the unchanged full native
canonical, platform, identity and zero-write/flush checks; a different old
Boot1 is not treated as cache. Hash-read failures propagate instead of being
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
reinterpret Boot1 evidence; cumulative diagnostics must preserve its exact
bytes. These are local custody/operation records, not a fabricated guest boot
receipt or evidence that an unobserved external restart could not occur.

`outcome.json` keeps primary and cleanup exits separate. Successful deletion
never erases a failed upload or guest failure; failed empty-upload revoke
(`InvalidVhd`) remains a cleanup failure even if owner-checked deletion works.
Failed jq observations identify only their internal observation filename in
private `driver.stderr`, preserving the original nonzero status and the
existing cleanup control paths.

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
`decoded`, independently of primary and cleanup exits. Diagnostic failures
do not become cleanup failures or erase the primary failure.
These files are **never parsed as acceptance evidence or promoted** to
Boot1/Boot2 captures or admission, even if the text appears to contain a full
pass. There is no diagnostic retry, resume, start or resource creation.

Grant/credential inputs are removed even on failure; no Azure account/token
cache is copied into the attempt. Raw CLI/native diagnostics and logs are
private. Do not publish the attempt directory.

TERM/INT/HUP use cleanup; an uncatchable kill or machine loss may interrupt
it. Retained consumption and intent records forbid rerun. The operator must
then reconcile the retained IDs and perform separately authorized bounded
cleanup; this script has no crash-resume or automatic reauthorization mode.
Do not describe an uncertain cleanup as absent or accepted.

## Offline validation

```sh
TMPDIR="$PWD/.d/direct-runtime" zig build \
  --build-file support/tools/hyperv/direct/build.zig \
  --cache-dir "$PWD/.d/direct-cache" --global-cache-dir "$PWD/.d/direct-global" \
  -Doptimize=ReleaseSafe test
support/scripts/tests/test_hyperv_direct_two_boot.sh \
  "$PWD/.d/NEW-direct-fixtures" \
  "$PWD/.d/direct-tools/bin/uk-hyperv-direct-validate"
```

The shell suite explicitly substitutes a checked-in isolated fake CLI and
transfer/input reader, whose source has no real-CLI/network/disk delegation.
The native serial parser still processes fixture bytes. Native fixtures
exercise seed/manifest/footer validation in memory, not on real disks.
These tests cannot authorize or establish live #89 acceptance.
