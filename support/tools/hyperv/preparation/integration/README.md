# Native preparation integration driver

This standalone driver uses the existing preparation package. Material creation
does not approve material. Only independently supplied phase reviews authorize
producer execution. Import is read-only and grants no operator, host-image,
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

Run this from the owned, clean, committed worktree. A fresh parent-selected
directory is required; do not overwrite earlier measurements:

```sh
cd /d/unikraft-worktrees/fleet-ci
umask 077
export S="$PWD/.d/zig-migration-preparation/integration-parent-v1"
test ! -e "$S"
mkdir -p "$S"/{tmp,home,xdg-cache,xdg-config,zig-global,zig-local,run/requests}
export HOME="$S/home" TMPDIR="$S/tmp"
export XDG_CACHE_HOME="$S/xdg-cache" XDG_CONFIG_HOME="$S/xdg-config"
export ZIG_GLOBAL_CACHE_DIR="$S/zig-global" ZIG_LOCAL_CACHE_DIR="$S/zig-local"
/home/g/.local/bin/zig build \
  --build-file support/tools/hyperv/preparation/integration/build.zig \
  --system "$PWD/.d/zig-migration-preparation/restore/zig-pkg" \
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
| `schema` | `hyperv_native_integration_spec_v1` |
| `repository` | This committed worktree, including the driver sources |
| `actor_directory` | The physical `$S/install/bin` directory |
| `facade_runtime` | Existing canonical facade directory described above |
| `guard` | `{run_id,disk_id,sectors,lun,sector_size,identity_policy}`; two distinct synthetic 32-character storage hex identities, 49..4096 sectors, LUN 0, sector size 512, policy 2 |
| `initial_config` | Private basename in `requests`, or null to render the native guarded fragment |
| `initial_metadata` | Private authoritative metadata basename for the supplied initial config, or null for the native fragment; never invented symbol types |
| `native` | Array of `{name,tool}` for the complete namespace alias closure |
| `git`, `packages`, `bison_data`, `trust` | Explicit `ToolSpec` records |
| `trust_bundle` | Actual relative certificate-bundle path within `trust` |
| `dependencies` | Every package as `{name,package_hash,origin}`; directory is `packages.directory/package_hash`, including exact `miz_source` |

`ToolSpec` has exactly `directory,role,target,executable,loader,libraries,origin`.
`executable`/`loader` are relative paths or null; `libraries` is an explicit
array of relative SONAME paths. `origin` has
`scheme,revision,source_sha256,producer_sha256` using genuine reviewed upstream
provenance, not hashes invented to get through validation. Complete physical
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
`schema:"hyperv_native_integration_selection_spec_v1",qemu,firmware_code,
firmware_vars,capability_receipt,capability_images,capability_source,engine,
baked_controls,extra_controls`.

- `qemu` is a complete ToolSpec, role `qemu`, target **`x86_64_linux`**.
- Each file spec is `{directory,path}`. `capability_receipt.path` is exactly
  `capability.receipt.json`; its private directory contains the existing
  `hyperv_public_capability_artifact_native_v1` contract. `capability_images`
  holds its independently supplied public boot image.
- `capability_source` is `common.Locations`:
  `repository,producer,compiler,git,trust,dependencies,git_scratch`, with
  dependencies `{name,directory}`. These actual native source/tool/dependency
  bindings must verify the capability receipt's separate provenance.
- `firmware_code` and `firmware_vars` are genuine selected firmware files.
  Six distinct future firmware working copies are charged.
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

## Author's bounded execution record

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
