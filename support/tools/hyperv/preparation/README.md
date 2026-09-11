# Native local preparation, version 0.2

This package implements the local #120/#89 preparation boundary: strict native
contracts, physical source/tool provenance, guarded configuration, synthetic
storage formats, pinned miz packaging, version-2 VHD-inclusive staging, a
read-only engine-entry loader, and an executing native Linux namespace worker.
It does **not** admit cloud authority, host images, operator credentials,
completed preflight, persistence acceptance, or historical evidence.

**The whole preparation workflow remains incomplete until parent integration
executes it.** The native namespace fixtures execute real isolated processes;
they are not a full root configure/build/package/engine-entry demonstration.
Root environment/UMASK integration and corrected native-image proofs remain
parent-owned dependencies. The frozen runtime/source fixtures still require
explicit non-AArch64 runtime parameterization; skips are not coverage.

Only this package is modified. Shared core (`../core.zig`), native Kconfig,
facade paths, ELF helpers and pinned native miz are reused. No Python, shell
wrapper, automatic legacy fallback, Azure CLI, credential probing, download or
failure-message recovery is implemented.

## Build and focused fixtures

Use installed Zig 0.16.0, never the repository root build. Put all caches,
outputs and temporary directories under an explicit fresh preparation scratch.
The existing dependency cache may be read with `--system`; restore only after a
manifest change or missing-dependency failure, using copied manifests and
`--fetch=all -j2` in scratch, never beside source.

```sh
cd /d/unikraft-worktrees/fleet-ci
umask 077
scratch="$PWD/.d/zig-migration-preparation/resume"
export TMPDIR="$scratch/tmp" HOME="$scratch/home"
export XDG_CACHE_HOME="$scratch/cache"
export ZIG_GLOBAL_CACHE_DIR="$scratch/global"
export ZIG_LOCAL_CACHE_DIR="$scratch/local"
cd "$scratch/build-work"
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-ci/support/tools/hyperv/preparation/build.zig \
  --system /d/unikraft-worktrees/fleet-ci/.d/zig-migration-preparation/restore/zig-pkg \
  --prefix "$scratch/outputs/debug" -j2 test install --summary all
```

Repeat with `-Doptimize=ReleaseSafe` and a different output prefix. Installed
executables are `uk-hyperv-prepare` and `preparation-namespace`; the latter has
an actual typed, descriptor/status-channel worker implementation.

The separate existing-runner namespace fixture build uses:

```sh
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-ci/support/tools/hyperv/preparation/namespace/build.zig \
  --cache-dir "$scratch/namespace-local" \
  --global-cache-dir "$scratch/namespace-global" \
  --prefix "$scratch/namespace-install" \
  -Dworkspace="$scratch/namespace-fixtures" -j2 test install --summary all
```

Create the selected scratch directories first. Never execute the reference
namespace shell scripts, full guest/Make/native-image builds, or original seed
operations as part of these fixtures.

## Wire versions and types

Canonical JSON has sorted keys, exact fields/types and one final LF, included
in document hashes. Duplicate/unknown/missing fields, noncanonical encodings,
floating/exponent integers and unknown enums are rejected. Generic document
bounds are 4 MiB, depth 32, 4096 items and 65536 tokens.

| Type | Schema and exact fields |
| --- | --- |
| `provenance.Record` | `hyperv_native_producer_provenance_v1`: `schema,source,host_target,guest_target,compiler_version,producer,compiler,git,dependencies,trust` |
| `producer.Binding` | `hyperv_local_native_producer_binding_v2`: `schema,source,repository,workspace,output,scratch,config,path,native,git,packages,bison_data,trust,trust_bundle,native_execution,native_proof,isolation` |
| `receipts.Receipt` | `hyperv_artifact_preparation_native_v1`: `schema,phase,purpose,run_id,guard,source_before,source_after,provenance,reviewed_provenance_sha256,config_before,config_after,parent_sha256,execution,efi,packaging,authority` |
| `inputs.SelectionV2` (`Plan`) | `hyperv_native_input_selection_v2`: `schema,packaged_receipt_sha256,solved_metadata,publication,capability_source,capability_receipt,qemu,assets` |
| `inputs.PreparedInputV2` (`Input`) | `hyperv_native_prepared_input_v2`: `schema,state,authority,receipt,reviewed_selection_sha256,selection,ledger,budget` |
| `inputs.Capability` | `hyperv_public_capability_artifact_native_v1`: `schema,image,provenance,reviewed_provenance_sha256,authority` |

Input/selection v1 are **not reinterpreted or accepted** by v2. The existing
build-receipt schema is retained, not replaced with a weaker engine receipt.
`state` is exactly `prepared`; `authority` is exactly `not_admitted`.

`File = {path,sha256,size,mode}`. `Sha` is **64 lowercase ASCII hex bytes**;
`admission.rawHash` explicitly converts it into core's **32 raw hash bytes**.
Storage run/disk identities are 32 lowercase nonnil hex digits;
`admission.storageIdentity` returns a distinct `StorageIdentity{bytes:[16]u8}`.
This is not a host RFC UUID. Host attempt/VM/phase UUID parsing and generation
remain in the host protocol; never cast storage identifiers into them.

Receipt phases are exactly `prepared -> configured -> built -> packaged`.
Canonical parent hashes, stable source/guard/provenance, successful execution
and cleanup, config continuity and packaging continuity are required.
An `Execution` is `{step,exit_code,cleanup_complete,admitted_binding_sha256}`.
These local states are never completed/accepted states.

## Accounting and immutable publication

The unchanged limits are **268435456 total bytes** and **2097152 control
bytes**, with no native/baked/producer/publication exemption.

Every selection requires a private `raw` and distinct private `vhd`, both
matching the package report; VHD size is raw size + 512. Public capability raw
uses the separate existing `boot_disk` role, not `vhd`. Both private files are
materialized and charged. Six firmware working copies are separately charged,
plus an 8 MiB evidence reservation. All QEMU executable/runtime/support files
must match its complete physical runtime inventory.

`publication` contains fixed arrays `receipts[4]`, `executions[2]` and
`inspections[2]`. Each element is a full `File`, present as a charged
`publication_control` asset:

```text
prepared.receipt.json
configured.receipt.json
built.receipt.json
packaged.receipt.json
configured.binding.json
built.binding.json
configured.inspection.binding.json
built.inspection.binding.json
```

The solved config, exact `native-config/metadata.tsv`, capability receipt and
producer executable also require charged assets. Engine entry additionally
requires the actual importing engine and namespace helper executables as
charged control assets. A single actual shared executable may satisfy both
producer and engine commitments; different copies remain distinct charges.

Native, producer, publication and baked control classes must be present. The
remaining control headroom is charged as `publication_reservation`, covering
`input.json` and future control publication without a self-referential hash.
Its size must actually cover the canonical input document.

`inputs.generate` only creates a fresh directory containing its existing writer
lock. It validates config, package, capability, QEMU and physical assets, copies
each staged file privately without replacement, rechecks the exact inventory,
then durably publishes `input.json`. Baked and future-copy assets remain
charged but are not silently materialized. Leftovers, symlinks, unexpected
directories, changed files/modes and private hardlinks are rejected.

Generation is a producer operation, **never an adoption/entry-loader API**.

## Producer and native namespace

`producer.plan` composes only `configure`, `inspect` and `build`, using fixed
application/profile/target/tool options, `-j2`, explicit dependency/cache/output
paths, and exact `-Dmake-arg=UMASK=0077`. No arbitrary command, Make argument,
shell string, inherited environment or alternate facade lock hook is exposed
by the worker protocol.

`producer.describe` and `bindingDigest` create material for independent review.
They do not approve it. `producer.execute` requires an independently supplied
binding commitment, revalidates source-bound selection and tools, invokes the
reviewed native helper under core supervision, then revalidates immutable
inputs. No ambiguous mutation is retried.

`Inputs.isolation` contains the reviewed static namespace helper, complete Git
metadata trees, canonical account, existing facade directory/lock identity
and private environment-file binding. Other native tools **may be dynamic**:
their executable, ELF interpreter and complete declared native library closure
are validated and made available at constrained paths. The worker supplies its
own `/bin` aliases instead of inheriting host PATH.

The worker creates actual user/mount/PID/network namespaces, a private chroot
and proc view, read-only source/tool/Git mounts, hidden historical `.d`, and
only the selected writable preparation workspace. Canonical passwd HOME is
preserved inside the private root. The facade's **existing host build.lock
inode/UID** is preserved; no replacement host lock is created. Descriptor
closure, no-new-privileges and capability removal precede the payload.

A pre-fork pidfd plus parent-death signal closes the PID1 registration race.
The eight-byte native status channel is inaccessible to the payload and
distinguishes signal termination from normal exit, setup/spawn failures and
cleanup failures. Missing, partial or malformed status cannot imply success.
Primary, cleanup and recording lanes remain separate; exact temporary-resource
cleanup checks identity and reports replacement/hardlink/move failures.

`receipts.Context` is producer-side. Its `verify` still checks
`provenance.requireCurrentExecutable`; importing engines must **not** call or
bypass it to impersonate the producer.

Before execution, persist externally approved bindings using:

```zig
try context.publishBinding(lock, kind, selected, independent_binding_sha);
const next = try context.runProducer(
    parent_link, selected, independent_execution_sha,
    independent_post_solve_inspection_sha,
);
```

`BindingKind` is `configured`, `built`, `configured_inspection` or
`built_inspection`. Each call publishes its fixed immutable filename.
Inspection approval must describe the actual resulting solved config; it is
not inferred by hashing a fresh measurement and declaring it approved.
`runProducer` executes `config-inspect` with that separately supplied binding,
then reads its canonical metadata file through checked descriptors. It does
not parse stdout/stderr or accept a caller-invented metadata model.
`Context.configuration_directory` is required for `inputs.generate`.

## Read-only engine entry

The reusable API is:

```zig
var loaded = try preparation.admission.load(
    allocator, io, independent_review, physical_bindings, deadline,
);
defer loaded.deinit();
// Local prepared material only; live/host/operator admission is still closed.
```

`Review` is supplied independently of the received document. Its exact fields
are `input_sha256`, `selection_sha256`, `provenance_sha256`,
`capability_provenance_sha256`, `receipt_sha256:[4]Sha`,
`execution_sha256:[2]Sha`, `engine_runtime_sha256`,
`engine_executable_sha256`. Inspection bindings are additionally committed by
the independently reviewed selection.

`Bindings` supplies already-open `staging`, `receipts`, `config`, `packaged`,
`efi`, `assets`, `qemu` and `engine`, plus separate `producer_source` and
`capability_source`. Each source binding contains `repository`, an explicit
`runtime.Git` and complete `provenance_bindings`. There is no ambient Git,
credential, trust, compiler or package discovery.

The loader opens and locks the **existing** `.writer.lock` without creating
state, then validates canonical input/hash/version, the exact four-receipt
chain, externally selected execution commitments and charged publication
records. It remeasures physical Git objects/index/source (including unreplaced
HEAD, modes, symlinks and forbidden flags), all stored producer runtimes,
compiler/dependencies/trust, original directory identities, proof selections,
environment and metadata records. It separately checks `/proc/self/exe`
against the current engine's independently reviewed runtime/executable.

Final config must use authoritative native metadata for every symbol and
select x86_64 Hyper-V. The loader validates actual miz packaging, capability
source/image/provenance, complete QEMU closure, physical ledger bindings and
exact staged inventory including immutable `input.json`. It rechecks source,
engine, QEMU and staging before returning. Git failures retain their primary,
cleanup and recording lanes on the supplied Git objects.

`Loaded` owns its arena and existing writer-lock descriptor, but borrows the
supplied directories. Keep those directories and the lock lifetime alive;
remeasure before later artifact use. The loader neither executes a producer
nor publishes state. Its return type is not a signed image/host admission or
completed-state object. A full successful root-produced loader fixture remains
part of parent integration, not something the small negative fixtures prove.
Before entering a real engine, select its intended purpose/guard independently
and reject `synthetic`; local fixture permission is not live workflow permission.

### Guarded-producer projection: parent review required

`admission.Commitments.scheme` is `reviewed_provenance_projection_v1`.
`guarded_producer_sha256` means the independently reviewed **canonical complete
producer provenance document**, including its final LF. This intentionally
differs from `producer_executable_sha256`.

The projection separately preserves producer executable, current engine
executable, packaged receipt, selection, input, solved config, raw and VHD
commitments. It contains no host-image commitment. Parent must explicitly
approve this semantic mapping before connecting it to signed host
`guarded_producer_sha256`/manifest `producer_sha256`. Host image, runner,
attempt UUID, startup policy, acceptance/evidence and operator/cleanup-lifetime
admission remain separately required. No signature is manufactured here.

## Required root integration

Root build/Make/facade/CI changes are not included in this scope.

1. Add optional `-Dpreparation-environment=FILE` and
   `-Dpreparation-environment-sha256=HEX`, forwarding them as dedicated internal
   facade arguments, not Make assignments. Reject a partial pair.
2. After the facade obtains canonical passwd HOME and its normal sanitized
   environment, call `environment.load(allocator,io,path,parseDigest(hex))`
   and `record.value.apply(allocator,&environment,canonical_home)`.
   Preserve normal behavior when options are absent.
3. Permit the exact `UMASK=0077` assignment in the opt-in preparation path.
   GNU Make already honors it; its normal default need not change.
4. Retain actual corrected native-image proof selectors. The legacy selected
   proof veto remains active; a reviewed flag cannot override it.

Environment schema is exactly `uk.native-preparation-environment.v1`, fields
`schema,workspace,bison_pkgdatadir,m4,git_exec_path,trust_bundle`. `workspace`
means scratch, not HOME. Only fixed cache/temp, Git-isolation, Bison/M4 and
trust variables are derived. Arbitrary inherited variables are not forwarded.
Reuse the same named `facade_paths` module for the runner and environment
module to avoid duplicate Zig file ownership; provide `hyperv_core` too.

## CLI, formats and remaining boundaries

The public CLI remains deliberately narrow:

```text
synthetic-seed PRIVATE_DIRECTORY REQUEST_BASENAME
package PRIVATE_DIRECTORY REQUEST_BASENAME
inspect-receipt PRIVATE_DIRECTORY BASENAME EXPECTED_SHA256
```

Success stdout is respectively:

```json
{"scope":"synthetic_only","state":"prepared"}
{"authority":"not_admitted","inspection":"native_package","state":"packaged"}
{"authority":"not_admitted","inspection":"shape_and_binding_only","phase":"prepared"}
```

Each line ends in LF; inspected phase may differ. No CLI command claims full
entry admission. The namespace helper is an internal typed FILE/HASH/status-FD
worker, not a user-facing arbitrary command proxy.

Failures use core enum-only `Failures` JSON: `cleanup,primary,recording,
schema_version`. Non-null lanes contain only `category,http_status,
service_code,stage`, never raw messages, stderr, paths, IDs or secrets.

Synthetic storage rendering is limited to 49..4096 sectors of 512 bytes,
with independently specified seed/intent/receipt layouts and fixed-VHD footer.
It never reads, copies, hashes or regenerates the original 4 GiB seed.
Persistence's later custody gate still requires original IDs and exact
LUN 7 / 8388608 x 512 geometry. Pinned miz revision is
`2db68ca0c3ab12155012a823c3fb8d7aba1cb544`, package hash
`miz-0.2.0-Z3lHlPw00wAx7bBDTJjcF1O3Vva6085mA_DZS2uWdwzL`.

Filesystem traversal/hash byte/count bounds and between-operation deadlines
do not interrupt every blocked syscall or native miz call. An independent
parent hard process deadline remains mandatory. Native runtime fixtures on
other architectures and full integrated producer execution remain necessary;
neither the migration nor cloud admission is complete.

The focused preparation suite currently exercises 71 cases in both Debug and
ReleaseSafe; the separate namespace suite exercises 14 cases in each mode.
The namespace cases include forced parent death during registration, normal
exit versus signal, spawn/setup errors, malformed/missing status, cleanup
failure, timeout and escaped-session descendant cleanup. Entry cases cover
independent review/receipt/selection substitution, physical current-executable
binding, authoritative metadata, v1 rejection, read-only missing-state/lock
behavior, reordered reservations and distinct-copy control accounting.

The stripped ReleaseSafe standalone producer and helper currently measure
1093312 and 645760 bytes: 1739072 bytes together, leaving only 358080 of the
2097152-byte control cap before other required controls/publications. This is
not a complete workflow budget result. A distinct engine executable and actual
QEMU/image/control selection must fit the unchanged ledger; no exemption or
larger approval is implied.
