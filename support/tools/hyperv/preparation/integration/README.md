# Native preparation integration driver 0.2.0

This standalone driver uses the existing preparation package. Material creation
does not approve material. An independently trusted native actor may measure
held files, but a separate runtime review is required **before the first
supplied Git, loader or other tool executes**. Subsequent independently supplied
phase reviews authorize producer execution. Import is read-only and grants no operator, host-image,
cloud, signature, or live-storage authority.

The driver is synthetic-only (storage LUN 0, at most 4096 sectors). It does not
read the historical seed. Its complete source must be committed before source
measurement; do not use a hidden `.d` implementation or change source between
phases. Build/Make execution is reserved for the parent integrator.

## Build

Use Zig 0.16.0 and the parent's pinned local preparation/miz dependency. All
outputs and caches belong below the scoped private scratch root. The executable
and `preparation-namespace` are installed together; keep their physical files
unchanged during the run. The importing mode uses the same physical executable
by default. A separately selected engine copy is separately inventoried and
charged, and must itself execute importer mode.

Choose a Git-coherence setup below before material generation. This build
example uses the owned, clean, committed worktree. A private clone instead
uses its own checkout as the working directory and its own
`.d/zig-migration-preparation/integration-parent-v1` as `S`; the pinned package
cache may remain at its explicitly reviewed existing location. A fresh
parent-selected directory is required; do not overwrite earlier measurements:

```sh
cd /d/unikraft-worktrees/fleet-origin
umask 077
export S="$PWD/.d/zig-migration-preparation/integration-parent-v2"
test ! -e "$S"
mkdir -p "$S"/{tmp,home,xdg-cache,xdg-config,zig-global,zig-local,run/requests}
export HOME="$S/home" TMPDIR="$S/tmp"
export XDG_CACHE_HOME="$S/xdg-cache" XDG_CONFIG_HOME="$S/xdg-config"
export ZIG_GLOBAL_CACHE_DIR="$S/zig-global" ZIG_LOCAL_CACHE_DIR="$S/zig-local"
/home/g/.local/bin/zig build \
  --build-file support/tools/hyperv/preparation/integration/build.zig \
  --system /d/unikraft-worktrees/fleet-ci/.d/zig-migration-preparation/restore/zig-pkg \
  --prefix "$S/install" -Doptimize=ReleaseSafe -j2 test install --summary all
export DRIVER="$S/install/bin/uk-hyperv-prepare-integration"
export WORK="$S/run"
```

The local dependency is `..`, module `hyperv_preparation`; its manifest pins
`miz_source` revision `2db68ca0c3ab12155012a823c3fb8d7aba1cb544`, package hash
`miz-0.2.0-Z3lHlPw00wAx7bBDTJjcF1O3Vva6085mA_DZS2uWdwzL`.
Core, native ELF and Kconfig helpers are its existing explicit imports.
There is no root build dependency. No dependencies are downloaded by these
commands. An absent declared package is a failure, not a restore authorization.

`HOME` above controls compiler caches only. The producer obtains the actual
account from `/etc/passwd`, preserves its canonical HOME and the already
existing canonical facade `build.lock` inode, and supplies the namespace's
closed environment. Do not relocate, recreate or replace the facade lock.
The driver does not initialize it. The facade path is
`/run/user/UID/unikraft-zig-facade-UID` when `/run/user/UID` exists, otherwise
`PASSWD_HOME/unikraft-zig-facade-UID`.

## Git metadata coherence: parent setup decision

**Recommend a private, independent normal clone for the staged run.** Using
the shared fleet worktree is also supported, but requires one continuous
parent-coordinated Git-mutation freeze, not a separate freeze around each
command. The review pauses make the duration larger than just configure/build;
there is no promise that the shared freeze will be brief.

Bootstrap resolves the actual `--git-common-dir` and `--absolute-git-dir`
through the declared native Git runtime. It inventories each distinct complete
metadata tree into `binding.isolation.git_metadata` (directory physical
identity plus tree SHA/file count/byte count). In a linked worktree, this
includes the common objects, refs, reflogs, configuration and other worktrees'
metadata, not just this branch's HEAD/index. A sibling commit, fetch, ref
update, index refresh, worktree change, maintenance, GC or repack can therefore
invalidate the binding even when this checkout's HEAD and source bytes stay
unchanged. A source commit/tree digest is not the Git metadata inventory.

The existing namespace validates that full inventory before/after producer
execution, and the read-only importer remeasures the inventories from the
stored execution/inspection bindings. Discrepancies fail closed; there is no
ignored-path list, automatic rebaseline or retry against changed metadata.
Read-only namespace mounts, workspace `.writer.lock`, facade `build.lock`,
`GIT_OPTIONAL_LOCKS=0` and disabled auto-maintenance do **not** lock out host
writers in other worktrees.

### Option A: private Git clone (recommended)

Parent-only setup inputs are the local source checkout, an independently
chosen complete commit containing this driver and every linked repository
source, a fresh private destination, an empty private Git template directory,
and the reviewed native Git executable/loader/library closure. No setup
command is executed by the driver.

Use native Git's local-copy clone mode with **`--local --no-hardlinks
--no-checkout`**, the empty template, then a detached checkout of that exact
chosen commit. Setup must use an explicit closed environment, disabled hooks,
global/system config and maintenance, and local filesystem transport only.
Do not fall back to remote transport, ambient Git helpers or a shell wrapper.
Coordinate a short source-Git mutation freeze while making the independent
copy so concurrent packing/pruning/ref changes cannot corrupt the acquisition.
Complete checkout and all target configuration/index changes before measuring.

This must be a normal standalone clone with `repository/.git` as its own
directory, **not** `git worktree add`, a copied worktree `.git` pointer, a bare
repository pretending to be the working tree, or a filtered/shallow clone.
Do not use `--shared`, `--reference` (even with later `--dissociate`), alternates,
hardlinked objects, symlinked metadata, or a live snapshot backed by the fleet
common directory. Independently confirm that both Git-directory queries
resolve to the clone's own `.git`, metadata regular files are independent
single-link files, and no alternates/grafts/replacements/promisor/shallow
state exists. The existing source validator remains authoritative; don't
sanitize an invalid clone after approving its binding.

After acquisition, the original fleet repository may resume Git mutations.
Keep **the clone's** source and all Git metadata unchanged from bootstrap
through final import (and any later re-admission using those receipts).
No commits, fetches, checkout/index updates, registration for background
maintenance, or housekeeping may run in the clone during that interval.
Clone acquisition copies repository objects and checks out committed source;
it must not copy the source worktree's `.d`, seed, receipts or historical
private evidence.

Set `requests/bootstrap.json.repository` to the clone's actual canonical path
and place `WORK` below **that clone's**
`.d/zig-migration-preparation/`; a workspace remaining under the original
worktree is not valid for the clone. Build the driver/helper from that selected
checkout. Bootstrap then measures the clone's real source HEAD/tree/physical
closure and new directory identities/metadata trees. Independently review
those new bindings and all resulting hashes; never relabel or copy a shared
worktree's bootstrap, execution/inspection approvals or receipts onto the
clone. Keep the canonical passwd HOME/facade lock unchanged.
The separately supplied capability-source locations/provenance do not move
automatically; preserve their actual reviewed source and dependency bindings
too, or independently prepare and review their replacements.

### Option B: shared-worktree freeze

First finish all source/harness commits, parent integration, fetches and
setup; prearrange reviewers and the independent expected config/materials.
The parent then pauses **all writers to the selected Git common directory**,
including sibling branches/worktrees and background Git maintenance, before
`material`. Keep that same freeze across prepare, both staged reviews,
configure/inspection, build/inspection, package, selection review, generate
and final read-only import. Per-command freezes cannot work: the original
metadata inventory persists in every later binding. Release only after the
last intended import; mutating shared metadata afterwards makes later
re-admission of those bindings fail. If mutation occurs mid-run, stop and
retain the failed workspace; use fresh material and independent approvals,
not updated hashes pasted into the old receipt chain.

Neither choice changes source/dependency coverage: all tracked
`integration/` files, the preparation/core modules, and linked native
ELF/Kconfig/facade/root-proof sources belong to the selected repository
commit/physical-source closure. The pinned miz source and every other
external linked dependency remain separately inventoried and reviewed in
`provenance.dependencies`. `.d` is not a source-code commitment. A private
clone's equal commit ID does not establish equal namespace identities, build
artifacts or review hashes. These choices establish local synthetic input
coherence only, not GitHub publication or cloud/host/live authority.

## Required material, not approval

All JSON uses the existing `contracts.parse`/`canonical` policy: exact fields
(including explicit nulls), lower-case ASCII hex, sorted compact JSON plus one
LF, strict duplicate/numeric/enum checks, maximum 4 MiB and the existing nested
item/token limits. Private inputs are current-user, single-link 0600 files in
0700 directories with trusted canonical ancestors. Tool/source paths must be
explicit absolute canonical paths, without symlinks or writable ancestors.
No ambient PATH, LD variables, shell snippets, tool discovery, origin defaults,
or arbitrary child arguments are supported.

`requests/bootstrap.json` has precisely the `common.Spec` fields:

| Field | Required value |
| --- | --- |
| `schema` | `hyperv_native_integration_spec_v2` |
| `repository` | The selected committed checkout (shared frozen worktree or independent private clone), including the driver sources |
| `actor_directory` | The physical `$S/install/bin` directory |
| `facade_runtime` | Existing canonical facade directory described above |
| `guard` | `{run_id,disk_id,sectors,lun,sector_size,identity_policy}`; two distinct synthetic 32-character storage hex identities, 49..4096 sectors, LUN 0, sector size 512, policy 2 |
| `initial_config` | Private basename in `requests`, or null to render the native guarded fragment |
| `initial_metadata` | Private authoritative metadata basename for the supplied initial config, or null for the native fragment; never invented symbol types |
| `native` | Array of `{name,tool}` for the complete namespace alias closure |
| `git`, `packages`, `bison_data`, `trust` | Explicit `ToolSpec` records |
| `trust_bundle` | Actual relative certificate-bundle path within `trust` |
| `dependencies` | Every package as `{name,package_hash,origin}`; directory is `packages.directory/package_hash`, including exact `miz_source` |

`initial_config:null` renders only `config.render`'s **guarded fragment**. It
does not supply a complete Hyper-V configuration. Parent-owned configuration
composition and the independently supplied expected inspection `File`
(content/path/mode, not future inode/timestamps) remain separate prerequisites.

`ToolSpec` has exactly `directory,role,target,executable,loader,libraries,origin,evidence`.
`executable`/`loader` are relative paths or null; `libraries` is an explicit
array of relative SONAME paths. `origin` is
`{schema:"hyperv_runtime_origin_v2",payload}`, with the closed
`local_build|distribution|zig_packages` payloads and separately held evidence
bindings documented in [the preparation contract](../README.md#origin-v2-identities-witnesses-and-independent-review).
There are no generic nullable source/compiler hashes. Complete physical
tree records are measured by `runtime.Bound`, not supplied as assertions.
Data roles use target `data`, null executable/loader and empty libraries.
Native roles use the actual host target. Dynamic ELF tools are supported;
libraries are `lib/SONAME`, and the relocated loader is normally `lib/loader`.
Do not put unrelated files in a tool root: all files become its bound closure.

Required aliases are `zig,make,bison,flex,m4,llvm-nm,llvm-objcopy,llvm-objdump,
llvm-readelf,llvm-strip,sh,bash`; declare every other actual script utility too
(the exact allowlist is `producer.Alias`). Zig/Make/Bison/Flex/M4/LLVM use their
corresponding runtime roles; `yacc` is Bison, `lex` is Flex, shell/utilities
use role `preparation`. A script-only Yacc wrapper cannot masquerade as ELF:
use a reviewed native alias if actually required. Do not introduce a new
static-only restriction on these tools. The existing namespace helper is
static and built from the same measured source.

Available original tool locations, for explicit provenance-backed relocation
or direct use only when the existing closure policy accepts them:

| Tool | Supplied source |
| --- | --- |
| Zig 0.16.0 | `/home/g/.local/bin/zig` (resolve the installed symlink for the runtime contract) |
| Git | `/home/g/.pixi/envs/git/bin/git` |
| Make | `/d/unikraft-worktrees/fleet-ci/.d/tools/ubuntu-root/usr/bin/make` |
| LLVM | `/d/unikraft-worktrees/fleet-ci/.d/tools/llvm-tools-22.1.8-aarch64-linux/bin` |
| Bison/Flex/M4/Yacc | `/d/unikraft-worktrees/fleet-platform/.d/zig-migration-build-tools/tools/.pixi/envs/default/bin` |

The real Git contract requires exactly `bin/git`, `lib/loader`, and all selected
libraries. Its documented AArch64 closure uses interpreter
`/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`,
Git-environment `libpcre2-8.so.0,libz.so.1,libiconv.so.2,libcrypto.so.3`, and system
`libpthread.so.0,libc.so.6,libdl.so.2`. Independently establish their actual
origins and bytes. Declaring names alone is not approval. Git execution uses
the existing fixed native Git-entry policy, never a generated shell wrapper.

Use the actual merged root bridge **`-Dnative-make-environment=PRIVATE_JSON`**.
Bootstrap creates and physically binds the existing
`unikraft_native_make_environment_v1` with
`bison_data,m4,schema,shell,tmp,xdg_cache,xdg_config,zig_global_cache,zig_local_cache`.
The root bridge supplies its fixed ten Make assignments including UMASK=0077.
No `-Dpreparation-environment`, generic `-Dmake-arg=UMASK`, or replacement
root integration is requested. Namespace and Git policy JSON remain separately
bound. The current native proof v2 root/builder/tool records are checked through
the existing preparation API.

## Executable staged procedure (parent only)

Place reviewed material recipes in the fixed request files using a private
editor or an independently reviewed native producer. The driver never writes
an approval file. `measure` emits observations with `authority:not_admitted`;
do not pipe its output into an approval file or treat measurement as approval.

```sh
"$DRIVER" runtime-material "$WORK"
# PURE held-file measurement publishes controls/runtime.json.
# Independent external review supplies reviews/runtime.json (schema below).
# No supplied Git/loader/tool has run yet.
"$DRIVER" material "$WORK"
"$DRIVER" measure "$WORK" prepare
# Independent review creates reviews/prepare.json.
"$DRIVER" producer "$WORK" prepare

# Independently supply requests/expected.config before this step.
"$DRIVER" stage "$WORK" configure expected.config
"$DRIVER" measure "$WORK" configure
# Independent review creates reviews/configure.json.
"$DRIVER" producer "$WORK" configure

"$DRIVER" stage "$WORK" build
"$DRIVER" measure "$WORK" build
# Independent review creates reviews/build.json.
"$DRIVER" producer "$WORK" build

"$DRIVER" measure "$WORK" package
# Independent review creates reviews/package.json.
"$DRIVER" producer "$WORK" package

# Supply requests/selection.json and its actual public artifacts described below.
"$DRIVER" selection "$WORK"
"$DRIVER" measure "$WORK" generate
# Independent review creates reserved-controls/generate.json.
"$DRIVER" producer "$WORK" generate

"$DRIVER" measure "$WORK" importer
# Independent review creates reserved-controls/import.json.
"$DRIVER" importer "$WORK"
```

### The pre-bootstrap runtime review is a distinct boundary

`runtime-material` uses `World.tool`, physical inventory and bounded witness/
declaration parsing only. It does not run Git, manifests, hooks, verifiers,
installers, Make or a producer. Its current actor is already independently
trusted/built; the selected actor file must be the actual running inode.
Current-source HEAD is **not** pretended known here.

`controls/runtime.json` is `hyperv_native_runtime_material_v1`, with
`authority:not_admitted`, exact request `spec` and `spec_physical` metadata,
repository directory identity, explicit native preparation role/target,
actual actor/helper files and complete actor
tree/physical commitment, every named native ToolBinding, Git/package/Bison/
trust bindings and every individual dependency. A measured ToolBinding has
`{tool:{path,contract},directory,physical_sha256}`. This binds roles, targets,
executable selection, all support files, evidence catalogs/witnesses and
physical copies before any supplied runtime is used.

The externally supplied `reviews/runtime.json` is exactly:

```text
{
  schema: "hyperv_native_runtime_review_v1",
  material_sha256: independently reviewed complete controls/runtime.json hash,
  authentication: "existing_publisher_assurance",
  realization: "declared_prefix_relocation",
  evidence: [{evidence_set_sha256, policy: [origin.Policy, ...]}, ...]
}
```

This is a field guide, not admissible JSON or an approval generator. Policies
must come from independent review of the actual retained witnesses and existing
approved publisher/channel/key—not the artifact's preferred method. They bind
expected method/authority/key and exact authentication/realization evidence.
The policy transported with a Tool is only a candidate until matched against
this separate review. There is no command to fill expectations from newly
measured bytes, adopt a publisher/key, or convert signature failure to absence.

`material` reads that review first, verifies its complete retained material,
remeasures spec/runtime/evidence physical identities, and compares again
immediately before `source.inspect`'s first supplied Git call.
A later `reviews/prepare.json`, Bundle or provenance review cannot substitute.
Every subsequent Bundle load (including direct producer/importer entry)
requires the retained independent runtime review, matches all selected tools
against it and revalidates their physical identities. Hand-supplying a Bundle
cannot skip the boundary. Execution/inspection bindings cannot silently
exchange the bootstrap-approved runtimes or authority requirements.
After approved inspection the actor/helper constructors still require actual
current source physical SHA, reviewed HEAD and selected Zig executable SHA.
The subsequent full provenance/build reviews remain mandatory.
The generated Bundle/stage schemas are
`hyperv_native_integration_material_v2` and
`hyperv_native_integration_stage_v2`.

Keep bootstrap evidence roots immutable. New selection evidence must have its
own independently reviewed held root; never append to a hashed bootstrap set.
Evidence is not placed inside source/runtime/CA/Git roots and is not exempt
from staging or charging. Existing parser limits (4 MiB/depth 32/items 4096/
tokens 65536/string 8192), 8 MiB control and 256 MiB total caps are unchanged.
All expected provenance/binding/input/selection/import hashes require new
independent reviews after this epoch; old records are rejected, not upgraded.

Each `reviews/PHASE.json` (or `reserved-controls/generate.json`) is `common.Review`:
`schema:"hyperv_native_integration_review_v1",phase,material_sha256,
provenance_sha256,parent_sha256,execution_sha256,inspection_sha256,
selection_sha256,capability_provenance_sha256`. The following fields are required;
all other nullable fields must be explicitly null:

| Phase | Material commitment | Additional commitments |
| --- | --- | --- |
| `prepare` | Canonical `controls/bootstrap.json` | Provenance |
| `configure` | Canonical `controls/configure.json` | Provenance, prepared receipt, execution binding, separately anticipated inspection binding |
| `build` | Canonical `controls/build.json` | Provenance, configured receipt, execution binding, unchanged-config inspection binding |
| `package` | Canonical `controls/bootstrap.json` | Provenance, built receipt |
| `generate` | Canonical `reserved-controls/selection.json` | Provenance, packaged receipt, selection plan, public capability provenance |

For every non-prepare phase `parent_sha256` is required. These digests are of
the actual canonical object/file, not its path, a rendered JSON substring or
the entire enclosing object. `measure` exposes the exact candidate field
digests for independent review. It does not endorse their contents or origins.

Importer approval is `selection.ImportReview`:
`schema:"hyperv_native_integration_import_review_v1",material_sha256,review`.
The nested existing `admission.Review` requires `input_sha256,selection_sha256,
provenance_sha256,capability_provenance_sha256,receipt_sha256[4],
execution_sha256[2],engine_runtime_sha256,engine_executable_sha256`.
Receipts are ordered prepared/configured/built/packaged; executions are
configured/built. Independently review the two inspection bindings as part
of the committed selection; they have no substitute engine-bypass flag.

Every phase has a durable immutable attempt marker **before mutation**.
Failure is not resumable or replayable. Do not delete markers, overwrite
receipts, replace policies, or rerun against a changed config; retain failed
evidence and establish a fresh independently reviewed workspace.
Receipt content must have the phase required by its selected pipeline slot,
not merely a valid receipt hash or the expected filename. Stage creation,
producer dispatch and packaged-selection intake reject a wrong phase before
workspace-lock creation, material loading, attempt/binding publication or
producer/package execution. Bootstrap material
also passes the existing provenance/binding structural validators before use.
Data-only or absent compiler/engine executables are refused explicitly before
their executable fields can be used; these shape checks never replace native
runtime or actual-process identity validation.

Execution calls `Context.verify`, `publishBinding`, `runProducer`, `package`,
`publish`, and `inputs.generate`, not root Make directly. Configure/build use
the real namespace; each is followed by real native `config-inspect`.
Authoritative metadata is read only from
`output/native-config/metadata.tsv`, never stdout/stderr or invented types.
Receipt publication occurs only after successful execution and inspection.
The produced EFI is `output/helloworld_hyperv-x86_64-efi-netvsc`; native miz
creates `package/acceptance.raw` (66 MiB) and `package/acceptance.vhd`
(66 MiB + 512 bytes). Neither is the historical persistence seed.

### Post-solve review boundary

`Context.runProducer` takes execution **and inspection** binding hashes before
it configures. The future config is bound by path/size/mode/SHA, not an
unknowable future inode. An independently known, exact expected solved config
therefore permits the route above. The expectation is measured without
pretending it is an observed result; actual authoritative inspection validates
all resulting symbols and guard fields. A mismatching result fails closed.
Build expects the already reviewed configured file to remain unchanged.

If the parent does not independently know the exact post-solve bytes, there
is a **real current API cycle**, not a missing root bridge: configure must run
before its actual inspection binding can be reviewed, but `runProducer`
requires that approval before configure. It exposes no durable pending step
or inspection-only continuation. The minimal proposed correction is a checked
durable execution/pending receipt, followed by independent review of the
post-solve binding and checked inspection/finalization without replaying
configure. This driver does not emulate that split, approve fresh output, or
modify the frozen API. Missing expectation is an explicit failure gate.

## Selection, complete staged accounting and importer

`requests/selection.json` is `selection.Spec` with exact fields:
`schema:"hyperv_native_integration_selection_spec_v2",qemu,firmware_code,
firmware_vars,capability_receipt,capability_images,capability_source,engine,
baked_controls,extra_controls`.

- `qemu` is a complete ToolSpec, role `qemu`, target **`x86_64_linux`**.
- Each file spec is `{directory,path}`. `capability_receipt.path` is exactly
  `capability.receipt.json`; its private directory contains the existing
  `hyperv_public_capability_artifact_native_v2` contract. `capability_images`
  holds its independently supplied public boot image.
- `capability_source` is `common.Locations`:
  `repository,producer,compiler,git,trust,dependencies,git_scratch`, with
  dependencies `{name,directory}`. These actual native source/tool/dependency
  bindings must verify the capability receipt's separate provenance.
- `firmware_code` and `firmware_vars` are each `{tool:ToolSpec,member}`.
  The tool must be a complete `role:firmware,target:data` distribution with
  no executable/loader/libraries. The relative member is tied to the exact
  generated asset ID/file, held data-root identity and complete physical
  file/directory commitment through mandatory named
  `SelectionV3.firmware_origins.code|vars` mappings. Creation, generation and
  read-only admission recheck them. Six future firmware working copies and
  every support/evidence file are charged; there is no file-only firmware path.
- `engine` is null for the same physical driver, or an explicit ToolSpec for
  a separate driver executable/runtime. Different copies are separately
  charged even when bytes match. Execute importer using the selected file.
- `baked_controls` is a nonempty, complete explicit inventory of real baked
  controls; `extra_controls` enumerates additional operator/host controls and
  publications not automatically collected. No invented one-byte controls,
  host exemption, or arbitrary uncharged copies are permitted.

The driver automatically measures and charges distinct private raw/VHD,
public capability image/receipt, full x86 QEMU closure, firmware, the actor
and helper and selected engine's **entire runtime inventories**, requests,
reviews, materials, attempt markers, all eight receipt/binding publications,
the solved config, authoritative metadata and all three policy files.
Identical actual runtime descriptors can share a runtime source charge only
when the same physical file/path is covered; byte-identical different files
cannot. Every different destination/future copy has a separate ledger entry.

Native controls remain **8,388,608 bytes inside 268,435,456 total**. Existing
8-MiB evidence and remaining-control reservations are retained. Final
`selection.json`, generate review/attempt, import review and `input.json`
are measured against the existing remaining-control allowance, not omitted.
Unexpected post-selection files in fixed control directories fail closed.
`inputs.generate` enforces fresh staging and physically copies the reviewed
assets. Import uses `admission.load` to remeasure provenance/source/tools,
verify the exact chain, actual running engine device/inode, package,
config/metadata, capability, QEMU and exact staged inventory/ledger. It does
not call `Context.verify` as a substitute for engine binding or regenerate
anything during adoption.

Build compiler, Git, native utility and package/trust inputs are physically
inventoried and provenance-bound, not secretly copied into staging. The
existing ledger covers staging/control/baked/future artifacts; it is not a
256-MiB cap on the source checkout or multi-gigabyte build cache. Any of those
inputs additionally shipped as controls/artifacts must be explicitly selected
and charged; the driver grants no exemption for such copies.

### Output and limits of the result

Successful material/producer operations emit one canonical JSON object:
`schema:"hyperv_native_integration_result_v1",operation,authority:"not_admitted",
sha256`. Producer SHA is the real phase receipt (generate: `input.json`).
Measurements use `hyperv_native_integration_measurement_v1` with
`authority:"not_admitted",phase,measured`.
Successful importer emits `state:"loaded_prepared",authority:"not_admitted",
projection_use:"pending_parent_review",commitments` under the result schema.
Its existing `reviewed_provenance_projection_v1` retains distinct provenance,
producer executable, actual engine executable, receipt, selection, input,
config, raw and VHD commitments. It is **not** a signed-host admission.
All SHA values are 64 ASCII hex characters; `admission.rawHash` is the explicit
32-byte conversion. Storage identities are 32 hex characters, not host/run
UUIDs and not evidence of RFC UUID semantics.

Failures emit only `hyperv_native_integration_failure_v1`, a closed `gate`
enum and the core's primary/cleanup/recording diagnostics. No arbitrary error
name, path, identifier, process stderr/body or credential appears. The
30-minute monotonic command deadline and process-tree supervision are the
existing core/producer mechanisms, with primary failure preserved separately
from cleanup/recording failures.

### Required before claiming a successful integration

The supplied tool paths do not by themselves constitute complete relocated
native closures or reviewed origins. The parent must supply the bootstrap
recipe, every missing tool/data/dependency/trust closure, existing facade lock,
and exact expected config (or coordinate the pending-step API correction).
Pinned x86 QEMU, real firmware, an independently produced native public
capability image/receipt/provenance, and complete baked/operator control
inventories have not been supplied by this driver task. They are genuine
remaining inputs, not placeholder success cases. No KVM execution/evidence
is required by preparation itself; AArch64 cannot be relabelled `qemu_kvm`,
nor can an AArch64 QEMU runtime satisfy the x86 contract.

The parent must execute the full sequence and measure the integrated ledger;
neither binary compilation nor fixture success proves it fits 8/256 MiB.
Host/live image/operator admission and guarded projection review stay closed.
The whole preparation/migration is incomplete until that real producer-to-
read-only-importer run succeeds; no original seed, historical receipt or cloud
resource is needed or authorized by this driver.

The concrete phase prerequisites are:

| First blocked stage without its inputs | Required independent input or decision |
| --- | --- |
| `runtime-material` | Complete held runtime/evidence/declaration files, current independently trusted actor/helper installation, canonical `requests/bootstrap.json`; no supplied execution |
| `material` | The above plus **independently supplied** `reviews/runtime.json` approving `controls/runtime.json` and exact policies; existing facade lock and selected frozen Git checkout |
| `stage ... configure` / configure execution | Exact `requests/expected.config` and separately approved execution/inspection digests, or parent-coordinated durable pending-execution API correction |
| `selection` | Populated `requests/selection.json`; actual public capability image/receipt/native provenance, x86 QEMU, firmware and complete baked/additional controls |
| `producer ... generate` / `importer` | Independent phase/import reviews and successful physical full-ledger/closure admission, including later publications |

These are currently unsupplied integration prerequisites, not claimed failures
from executing the full producer. A trusted Git runtime passing CI fixtures
can be selected with its actual complete material/provenance; fixture success
does not populate or approve the bootstrap recipe. Likewise, a separate
public local-boot report is neither the required capability provenance
contract nor preparer/host admission. Root CI fixture-cache canonicalization
is parent-owned and is not reimplemented in this harness.

## Earlier bounded execution records (historical)

Only the standalone driver and its non-executing fixtures were compiled/run.
Both `-Doptimize=Debug -j2 test install --summary all` and
`-Doptimize=ReleaseSafe -j2 test install --summary all` completed **8/8 build
steps and 12/12 fixtures**, with no skips. The complete commands are the Build
command above with scratch root
`.d/zig-migration-preparation/integration-driver-v1`, prefix
`output/debug` or `output/release-safe`, and the corresponding optimization.
Logs are `output/debug.log` and `output/release-safe.log` within that scratch.

Fixtures cover fixed arguments, required independent review fields, strict
canonical/duplicate/unknown rejection, expectation binding, private file/hash
refusals, immutable attempts, real actual-executable versus identical-copy
identity, post-selection reservation boundaries and unexpected controls, and
synthetic geometry. They do not simulate successful producer receipts.
The actual CLI's missing-expectation case exited 1 before opening the workspace,
with empty stdout and enum-only stderr (`postsolve_expectation_required`).

Installed ReleaseSafe sizes at that measurement were 1,892,280 bytes for the
driver and 705,720 for its helper: **2,598,000 bytes combined**. This is only
the two original binaries, not a complete integrated ledger or proof of fit.
The author did not execute material bootstrap, guest/Make/native-image builds,
packaging/generation/import against real produced artifacts, or any cloud
operation; those remain the parent's exclusive integration execution.

A subsequent harness-only stage-guard pass completed **14/14 fixtures and 8/8
steps in both Debug and ReleaseSafe**, still with `-j2`, no skips and no full
producer execution. Its fresh scratch is
`.d/zig-migration-preparation/integration-gates-v1`, with the same focused
commands and `output/{debug,release-safe}.log`. The added fixtures exercise
every receipt-phase pairing and missing/wrong-role/data-only executable
refusals without creating synthetic success receipts. The earlier binary
sizes above are historical measurements, not sizes of this updated build.

The reviewer follow-up adds native private-file fixtures with a configured
receipt whose contract and both canonical hashes pass `receipts.requireLink`.
Its bytes under `prepared.receipt.json` fail the expected-phase loader, while
the correctly named configured receipt succeeds and a wrong independent hash
still fails. The actual stage function and CLI dispatcher reject the
wrong-phase input without any workspace inventory change or attempt file.
Selection similarly rejects that valid configured receipt, with null
packaging, under `packaged.receipt.json` before dereferencing packaging.
No corresponding source/runtime material is installed in these negative
fixtures, and no actual producer is run.
The focused standalone `-j2 test install --summary all` commands passed
**16/16 fixtures and 8/8 steps in each of Debug and ReleaseSafe**. Final logs
are `.d/zig-migration-preparation/integration-phase-review-v1/output/`
`debug-final.log` and `release-safe-final.log`; prefixes use the corresponding
`debug-final` and `release-safe-final` directories. Other command arguments
match the Build section, with that fresh scratch root.

## Origin epoch execution record

The 2026-09-11 Origin repair passed **18/18 integration fixtures and 8/8 steps
in both Debug and ReleaseSafe**, alongside 93/93 preparation and 19/19
namespace fixtures in both modes, all with `-j2`. Runtime-review tests reject
the absence of a separate pre-bootstrap review even when a later phase review
exists, and independently mutate roles/targets/executables, physical
identities, spec bytes and required authority policies. No full material
bootstrap or producer was run.

Current measured ReleaseSafe integration files are **2,311,568 bytes** for
`uk-hyperv-prepare-integration` and **1,011,912 bytes** for its helper:
**3,323,480 bytes combined**. Debug files are 13,466,168 and 8,168,400 bytes.
These are actual installed-file measurements, not compressed estimates,
historical pair sizes or a complete ledger. Exact six focused commands,
environment, logs, physical-identity checks, hashes, other installed sizes
and remaining real authentication/realization material gates are recorded in
[the preparation execution record](../README.md#origin-repair-execution-record-2026-09-11).

Existing pinned signatures remain required; unsigned LLVM/conda metadata is
represented honestly as existing publisher/channel HTTPS assurance only when
independently reviewed with its retained acquisition/TLS context. No verifier
invocation, new authority, network acquisition, conda hook or relocation of
real packages was performed. Ubuntu key approval/native verification, actual
archive/member evidence, firmware and fresh source/compiler/build approvals
remain material gates. Historical upstream manufacture, parent configuration
composition, full workflow, ledger fit and cloud/live admission are not
claimed complete.
