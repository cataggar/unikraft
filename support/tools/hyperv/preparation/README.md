# Native local preparation, version 0.4.1

This package implements the local #120/#89 preparation boundary: strict native
contracts, physical source/tool provenance, guarded configuration, synthetic
storage formats, pinned miz packaging, version-2 VHD-inclusive staging, a
read-only engine-entry loader, and an executing native Linux namespace worker.
It does **not** admit cloud authority, host images, operator credentials,
completed preflight, persistence acceptance, or historical evidence.

**The whole preparation workflow remains incomplete until parent integration
executes it.** The native namespace fixtures execute real isolated processes;
they are not a full root configure/build/package/engine-entry demonstration.
The parent root bridge and native image proofs are merged upstream at
`368dade0` (#129) and `53226729` (#130). This stacked branch has not been rebased
or integrated with them; parent-directed integration and full root-produced
engine entry remain necessary. After the recorded review release, the targeted
source/runtime corrections replace lexical symlink normalization and
architecture-specific Git fixture discovery. Native fixture paths are explicit;
the reported runs are AArch64, not claimed x86_64 execution coverage.

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
scratch="$PWD/.d/zig-migration-preparation/control-cap-8mib"
proof_fixture="$PWD/.d/zig-migration-preparation/proof-compat-53226729/fixtures"
export TMPDIR="$scratch/tmp" HOME="$scratch/home"
export XDG_CACHE_HOME="$scratch/cache"
export XDG_CONFIG_HOME="$scratch/config"
export ZIG_GLOBAL_CACHE_DIR="$scratch/global"
export ZIG_LOCAL_CACHE_DIR="$scratch/local"
git_fixture=(
  -Dgit-executable=/home/g/.pixi/envs/git/bin/git
  -Dgit-loader=/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
  -Dgit-library=/home/g/.pixi/envs/git/lib/libpcre2-8.so.0
  -Dgit-library=/home/g/.pixi/envs/git/lib/libz.so.1
  -Dgit-library=/home/g/.pixi/envs/git/lib/libiconv.so.2
  -Dgit-library=/home/g/.pixi/envs/git/lib/libcrypto.so.3
  -Dgit-library=/usr/lib/aarch64-linux-gnu/libpthread.so.0
  -Dgit-library=/usr/lib/aarch64-linux-gnu/libc.so.6
  -Dgit-library=/usr/lib/aarch64-linux-gnu/libdl.so.2
)
cd "$scratch/work"
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-ci/support/tools/hyperv/preparation/build.zig \
  --system /d/unikraft-worktrees/fleet-ci/.d/zig-migration-preparation/restore/zig-pkg \
  -Dproof-fixture="$proof_fixture" \
  --prefix "$scratch/outputs/debug" "${git_fixture[@]}" \
  -j2 test install --summary all
```

Repeat with `-Doptimize=ReleaseSafe` and a different output prefix. Installed
executables are `uk-hyperv-prepare` and `preparation-namespace`; the latter has
an actual typed, descriptor/status-channel worker implementation.
The example selects the installed public AArch64 Git closure. CI must supply
its own complete native executable/interpreter/library paths with the same
options; no Git path, library discovery or architecture skip is substituted.
`runtime.TestFixture.copyRuntime` is shared by both fixture builds. Missing
fixture options fail tests, but ordinary package installation does not need
fixture inputs.

The proof fixture reads actual root/builder/tool source bytes; it never executes
the root build. `-Dproof-fixture` defaults to the current checkout root after
integration. On this older stacked base, the example selects private snapshots
of these three files from merged commit `53226729aafbc9654240656f6533f88a1dd7b983`:

```text
build.zig
support/build/hyperv-proof-build.zig
support/build/hyperv-proof-tool.zig
```

Create a fresh fixture directory with that layout and populate it with
`git show COMMIT:PATH` output, without changing the working checkout. These are
read-only public source fixtures, not a complete reviewed producer checkout or
fresh execution/admission evidence.

The separate existing-runner namespace fixture build uses:

```sh
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-ci/support/tools/hyperv/preparation/namespace/build.zig \
  --cache-dir "$scratch/ns-local" \
  --global-cache-dir "$scratch/ns-global" \
  --system /d/unikraft-worktrees/fleet-ci/.d/zig-migration-preparation/restore/zig-pkg \
  --prefix "$scratch/outputs/namespace-debug" \
  -Dworkspace="$scratch/ns-debug-work" "${git_fixture[@]}" \
  -j2 test install --summary all
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
| `producer.Binding` | `hyperv_local_native_producer_binding_v3`: `schema,source,repository,workspace,output,scratch,config,path,native,git,packages,bison_data,trust,trust_bundle,native_execution,native_proof,isolation` |
| `producer.NativeProof` | `hyperv_native_elf_proofs_v2`: `schema,source_sha256,root_build,builder,tool,modes` |
| `receipts.Receipt` | `hyperv_artifact_preparation_native_v1`: `schema,phase,purpose,run_id,guard,source_before,source_after,provenance,reviewed_provenance_sha256,config_before,config_after,parent_sha256,execution,efi,packaging,authority` |
| `inputs.SelectionV2` (`Plan`) | `hyperv_native_input_selection_v2`: `schema,packaged_receipt_sha256,solved_metadata,publication,capability_source,capability_receipt,qemu,assets` |
| `inputs.PreparedInputV2` (`Input`) | `hyperv_native_prepared_input_v2`: `schema,state,authority,receipt,reviewed_selection_sha256,selection,ledger,budget` |
| `inputs.Capability` | `hyperv_public_capability_artifact_native_v1`: `schema,image,provenance,reviewed_provenance_sha256,authority` |

Input/selection v1 are **not reinterpreted or accepted** by v2. The existing
build-receipt schema is retained, not replaced with a weaker engine receipt.
`state` is exactly `prepared`; `authority` is exactly `not_admitted`.
Producer binding v3 requires separately bound Make and Git policy files;
binding-v2 documents are rejected rather than silently upgraded.
Native proof v2 replaces the obsolete three-direct-source representation:
`builder` is `support/build/hyperv-proof-build.zig`, `tool` is
`support/build/hyperv-proof-tool.zig`, and `modes` is exactly
`["smp","irq","drivers"]`. Proof-v1 records are rejected. Outer producer
binding v3, input/selection v2 and the existing build-receipt version remain
unchanged.

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

The explicitly approved native control limit is **8388608 bytes (8 MiB)**
inside the **unchanged 268435456-byte (256 MiB) total staging limit**.
There is no native/baked/producer/publication/operator/host exemption.
This replaces the former 2 MiB native allowance only; it changes no legacy
512 KiB control policy or 64/128/192/256 KiB document limit, and grants no
image, operator, cloud, seed or historical-evidence admission.

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
`inputs.requireControlBinding(allocator, io, plan, bindings, runtime)` now
requires the complete physical producer/engine/helper runtime inventory, not
just its executable: interpreters, libraries and non-ELF support files all need
charged control assets. Byte-identical files at different inodes cannot cover
one another. A runtime exceeding the control cap is rejected before inventory.
All three namespace/Make/Git policy files also require charged, physically
associated control assets, checked during generation and read-only entry.

Native, producer, publication and baked control classes must be present. The
remaining control headroom is charged as `publication_reservation`, covering
`input.json` and future control publication without a self-referential hash.
Its size must actually cover the canonical input document.
Fresh ledgers reserve the remaining allowance under the approved 8 MiB policy.
An older prepared-input ledger reserving only the former allowance does not
match current recomputation. It is rejected, not silently upgraded or rewritten;
historical receipts and evidence remain untouched. Wire schema versions and
document-size bounds are unchanged.

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
paths, and `-Dnative-make-environment=FILE`. It does not send disallowed direct
UMASK/SHELL/cache overrides or the former preparation-environment option pair.
No arbitrary command, Make argument,
shell string, inherited environment or alternate facade lock hook is exposed
by the worker protocol.

`producer.describe` and `bindingDigest` create material for independent review.
They do not approve it. `producer.execute` requires an independently supplied
binding commitment, revalidates source-bound selection and tools, invokes the
reviewed native helper under core supervision, then revalidates immutable
inputs. No ambiguous mutation is retried.

`producer.requireNativeProofFiles(allocator, io, repository, source, proof)`
is shared by producer execution and read-only entry. It remeasures the root,
builder and tool records and recognizes the actual merged shared-tool calls,
three fixed mode invocations and gate dependencies. It also binds the builder's
host/ReleaseSafe tool construction and native CLI proof calls. Comments or
unconnected source-path strings cannot supply the required wiring. This is a
bounded supported-shape guard, not a general Zig semantic proof: complete
independent physical source/compiler/dependency/runtime review remains required
and binds all transitively compiled proof inputs.

`Inputs.isolation` contains the reviewed static namespace helper, complete Git
metadata trees, canonical account, existing facade directory/lock identity
and private policy-file bindings. Other native tools **may be dynamic**:
their executable, ELF interpreter and complete declared native library closure
are validated and made available at constrained paths. The worker supplies its
own `/bin` aliases instead of inheriting host PATH.

The same static helper now implements `/bin/git`; no third executable is
installed. Its fixed read-only `/etc/unikraft-preparation-git.json` policy
reinstalls canonical HOME, explicit trust/cache paths and fixed Git isolation
after facade filtering. Inherited `GIT_*`, `LD_*`, HOME and other variables are
not copied. It revalidates the declared relocated Git/loader/library closure,
closes descriptors and replaces itself with Git, preserving exit/signal while
discarding native Git/loader stderr. Wrapper errors use enum-only diagnostics.
Only `rev-parse --short HEAD` and `ls-files -m`, used by the existing selected
`gitsha1` helper, are accepted. No path selection, remote operation or generic
Git proxy is exposed. The separate #87 networking workflow is not rewritten.

`Inputs.isolation.environment`, `.make_environment` and `.git_policy` are
private `File` bindings. The latter two are nullable only in the generic
namespace mechanism; v3 producer/admission entry requires both. All original
workspace paths remain read-only inside the namespace, including the Git policy
also mounted at its fixed `/etc` path. The helper's source/compiler commitments
must match the producer source and selected compiler.

Use `producer.bindingEnvironment`, `bindingMakeEnvironment` and
`bindingGitPolicy` to construct review material. Publish the canonical records
privately using the existing immutable filesystem API, bind their observed
`File` records, then obtain independent review of the completed producer
binding. `validatePolicyFiles` checks the three physical files and their exact
associations with tools, repository, account and caches; hashing freshly
constructed records does not grant approval.

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

No full `Context.runProducer` configure/build execution result is claimed by
the current standalone results. Its root command sequence is `olddefconfig`,
then `config-inspect`, then `native-images`, then `config-inspect`, with the
fixed argv built by `producer.plan`. The current committed base predates both
merged root changes; parent-directed integration and the permitted full producer
run must provide actual command/results and fresh metadata/receipts. Neither
the bridge nor native-proof source implementation is pending upstream.

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
The selected executable descriptor must identify the actual `/proc/self/exe`
inode/device and stable metadata; hashing a copied executable is insufficient.
Source symlinks are expanded component-by-component before processing later
parent components, with 32-link/4096-byte bounds. Missing or regular-file
intermediates, transient source escapes and evidence/Git traversal are rejected,
even if lexical normalization would end at a tracked pathname.

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

## Root bridge compatibility

Root build/Make/facade/CI changes are not included in this scope.

The adapter matches the parent bridge contract first supplied at `5dbdf050`
and now merged through #129:
`-Dnative-make-environment=FILE`. `environment.MakeRecord` uses exactly
`bison_data,m4,schema,shell,tmp,xdg_cache,xdg_config,zig_global_cache,zig_local_cache`,
with schema `unikraft_native_make_environment_v1`, compact canonical JSON and
one LF. It requires a private 0600 file/0700 parent, canonical existing tool and
Bison paths, and private cache directories. Preparation independently binds
its hash and mounts it read-only; root needs no extra SHA option.

Root generates only fixed `UMASK=0077` plus nine fixed-name assignments for
SHELL/CONFIG_SHELL, M4, BISON_PKGDATADIR, TMPDIR and the four Zig/XDG caches.
Canonical passwd HOME, the global facade lock and ordinary invocations remain
unchanged. This bridge is not isolation, source review or admission. Actual
root execution with this package waits for parent-directed merged-base
integration; this branch does not cherry-pick or copy parent root source.

The internal namespace policy retains schema
`uk.native-preparation-environment.v1` and fields
`schema,workspace,bison_pkgdatadir,m4,git_exec_path,trust_bundle`. It is no longer
the root bridge contract. Git policy schema is `hyperv_native_git_entry_v1`,
fields `schema,repository,runtime_directory,runtime,environment,account`.
Both are checked against the independently reviewed producer binding.
The selected legacy image-proof veto remains active. Neither canonical_home
source strings nor the normal Make UMASK default need deletion.

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
parent hard process deadline remains mandatory. Actual runs of the parameterized
fixtures on other native architectures and full integrated producer execution remain necessary;
neither the migration nor cloud admission is complete.

The cap update passes **80/80 preparation cases** (10/10 build steps) in both
Debug and ReleaseSafe under umask 077, with no skipped cases. New cases cover
physical producer/baked copies and publication reservation above the former cap,
exact 8 MiB/256 MiB boundaries, one-byte overruns and refusal to reinterpret an
older prepared ledger. The unchanged namespace suite's last recorded results
are **16/16 cases** (11/11 steps) in both modes. The bridge/Git extension adds exact
bridge-wire/private-path fixtures, v3 policy substitution cases, and actual Git
execution after stripped or poisoned facade-like environments, with read-only
policy and lifetime cases.
The namespace cases include forced parent death during registration, normal
exit versus signal, spawn/setup errors, malformed/missing status, cleanup
failure, timeout and escaped-session descendant cleanup. Entry cases cover
independent review/receipt/selection substitution, physical current-executable
binding versus a byte-identical copy, authoritative metadata, v1 rejection,
read-only missing-state/lock behavior, reordered reservations and complete
runtime control accounting. Real-Git cases cover nested symlink/parent-component
order; native-only unit cases cover hop and pending-path bounds.
The additional merged-source case uses the actual #130 root/builder/CLI files
and rejects missing gate dependencies, redirected roots, wrong modes, changed
compiler selection/imports, omitted proof calls, stale hashes and symlinks.
Current cap logs are `control-cap-8mib/outputs/{debug,release-safe}.log` under
the preparation scratch root. The earlier namespace results remain at
`proof-compat-53226729/outputs/namespace-{debug,release-safe}.log`.
All earlier logs are preserved.

The stripped ReleaseSafe producer and Git-enabled helper measure
1093312 and 705648 bytes: 1798960 bytes together, leaving 6589648 of the
8388608-byte control cap before other required controls/publications. This
two-binary measurement is not a complete workflow budget result. The parent
reported a separate partial control measurement of 3536943 bytes before
unmeasured engine/dependency/publication inputs when obtaining the 8 MiB
approval. Neither partial measurement proves the integrated ledger fits.
All selected operator, dependency, guard, publication, image-baked and other
control copies still require measurement and charging inside both caps.
