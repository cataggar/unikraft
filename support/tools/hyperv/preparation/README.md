# Native local Hyper-V artifact preparation

This package implements local primitives for the selected #120/#89 workflow.
It is **not an executable end-to-end replacement yet**: the current repository
producer path is deliberately rejected before spawning a build. No cloud
authority, completed preflight, persistence acceptance, or historical-state
conversion is provided.

Engine implementers must use the [integration contract](#preflight-engine-integration-contract)
below, including its external-review boundary and unresolved input-v1/private-VHD
projection. A prepared document is never an admitted engine input by itself.

Only `support/tools/hyperv/preparation/` is changed. The dependency-free core,
native Kconfig parser, facade path canonicalizer, and native ELF implementation
are reused. Packaging and fixed-VHD codecs use the workflow's exact miz revision
`2db68ca0c3ab12155012a823c3fb8d7aba1cb544`, package hash
`miz-0.2.0-Z3lHlPw00wAx7bBDTJjcF1O3Vva6085mA_DZS2uWdwzL`.
There is no shell/Python wrapper, Azure CLI, credential discovery, download,
automatic dependency restoration during execution, or failed-command recovery.

## Standalone build

Use the installed Zig 0.16.0. The build does not evaluate the repository root
build. It currently imports the foundation from `../root.zig`; after the
parent-owned facade integration, change this one entry to `../core.zig`.
Do not use the future facade as an unconfigured dependency-free import.

All paths below are new scratch paths. Do not use the repository source as the
working directory for generated output or package extraction.

```sh
cd /d/unikraft-worktrees/fleet-ci
umask 077
scratch="$PWD/.d/zig-migration-preparation"
mkdir -p "$scratch/tmp" "$scratch/home" "$scratch/cache" \
  "$scratch/zig-global/tmp" "$scratch/zig-local/tmp" \
  "$scratch/restore" "$scratch/build-work" "$scratch/outputs"
export TMPDIR="$scratch/tmp" HOME="$scratch/home"
export XDG_CACHE_HOME="$scratch/cache"
export ZIG_GLOBAL_CACHE_DIR="$scratch/zig-global"
export ZIG_LOCAL_CACHE_DIR="$scratch/zig-local"
cp support/tools/hyperv/preparation/build.zig \
  support/tools/hyperv/preparation/build.zig.zon "$scratch/restore/"
cd "$scratch/build-work"
/home/g/.local/bin/zig build --build-file "$scratch/restore/build.zig" \
  --fetch=all -j2
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-ci/support/tools/hyperv/preparation/build.zig \
  --system "$scratch/restore/zig-pkg" --prefix "$scratch/outputs/debug" \
  -j2 test install --summary all
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-ci/support/tools/hyperv/preparation/build.zig \
  --system "$scratch/restore/zig-pkg" --prefix "$scratch/outputs/release-safe" \
  -Doptimize=ReleaseSafe -j2 test install --summary all
```

The explicit global-cache `tmp` directory is necessary for Zig's ZIP dependency
extraction. No dependency receipt fields or upstream manifests are removed.
Tests run with their current directory inside the explicit Zig local cache.
Native Git fixtures read public installed Git/runtime files and make private
relocated copies under that cache; they never inspect credentials or old
acceptance artifacts. Those real-Git fixtures currently select this AArch64
host's explicit installed paths and skip on other architectures; another CI
architecture needs its own explicit public runtime fixture binding.

## Implemented interfaces

| Module | Reusable contract |
| --- | --- |
| `contracts` | Core-backed bounded canonical JSON, exact fields/types, lowercase SHA/object/identity parsing, native policy constants and safe failure mapping. |
| `files` | Descriptor-stable source/artifact/executable policy distinct from 0600 single-link private state; fd-relative no-follow complete inventories; bounded durable no-replace streaming publication. |
| `runtime` | Complete reviewed native ELF/runtime trees, explicit relocated Git loader/libraries, sanitized environment, allowlisted Git operations and core process supervision. |
| `source` | Physical SHA1/SHA256 commit/blob/tree verification, exact index/mode/symlink closure, unreplaced HEAD, no grafts/alternates/hidden index flags/unreviewed extra files. `inspect` measures; `require` compares independent review. |
| `config` | Authoritative native Kconfig metadata reuse, `Guard`, rendering, normalization, guarded identity validation before/after solving, separate purpose geometry gate. |
| `seed` | `Parameters`, owned `Products`, native sector encode/decode and deterministic synthetic raw/fixed-VHD/config/manifest production. |
| `package` | Actual pinned native miz `package` and descriptor-backed `validate`; raw/VHD prefix equality, GPT/ESP/PE/fallback/hash/geometry/identity checks. |
| `producer` | Typed `plan`, `describe`/`bindingDigest`, and real supervised `execute` for configure/inspect/build. Exact target/app/profile/flags, no extra arguments, no retry or output-text recovery. |
| `provenance` | Source/compiler/host/guest/current-binary/dependency/runtime/trust records and physical verification against an independently reviewed digest. |
| `receipts` | Fresh immutable local-phase records, canonical parent hashes, context binding, `Context.prepared/runProducer/package/publish`, explicit not-admitted authority. |
| `budget` | Overflow-checked complete source-bound ledger; physical copies and baked/producer/publication controls are not exempt. |
| `inputs` | Native prepared selection/capability bindings, full QEMU closure, actual immutable staging, and publication of `input.json` after successful revalidation. |

Except owned results with `deinit`, composite returned strings/arrays use the
caller's allocator and are intended for a bounded per-operation arena. Directory
handles remain caller-owned. Use `files.openPrivate` for publication directories:
it reuses the current core's full private-path validation, then reopens the same
directory identity with a readable descriptor. The older core otherwise returns
an `O_PATH` descriptor, which cannot be fsynced by its lock/publication methods.
No private policy is weakened, and no shared-core source is modified.
`Context` is used in a dedicated process that owns
the core supervisor and holds the workspace's core writer lock. Primary,
cleanup, and recording lanes are independent; raw child stderr is never returned.
An unresolved process cleanup must not transfer writer ownership.

The expected provenance, producer-binding, receipt, and input-selection digests
are **external review inputs**. Measuring a digest does not approve it.
`validate`, `parse`, `requireLink`, and `requireParent` establish shape/hash/link
consistency, not historical proof that a build happened. `Context.verify`,
physical artifact revalidation, and independent audit remain necessary.
Use `package.validate` before admitting a stored packaging record.
`inputs.generate` requires a fresh staging directory containing only its stable
writer lock and verifies the final file inventory against the selected staged
assets. Unreceipted leftovers cannot be adopted or excluded from accounting.

`files.copyImmutable` checks deadlines around each positional progress read and
write. Filesystem traversal/hashing has byte/count/depth limits. Native miz and
one blocked filesystem syscall cannot be interrupted by every between-operation
check: an independent parent hard process deadline is mandatory. No package
receipt is returned after primary or cleanup failure.

## CLI

The installed `uk-hyperv-prepare` has only implemented local commands:

```text
synthetic-seed PRIVATE_DIRECTORY REQUEST_BASENAME
package PRIVATE_DIRECTORY REQUEST_BASENAME
inspect-receipt PRIVATE_DIRECTORY BASENAME EXPECTED_SHA256
```

Requests must be owner-only canonical JSON in an owner-only directory.
Synthetic parameters are exactly `disk_id`, `lun`, `run_id`, `sectors`; IDs are
32 lowercase nonnil hex digits. The command publishes `synthetic.raw`,
`synthetic.vhd`, `synthetic.config`, and `synthetic.json` without replacement.
The package request has exactly `input_directory` and `efi`; `efi` is a
`contracts.File` record. It creates `acceptance.raw`, `acceptance.vhd`, and
`package.inspection.json`. This inspection is not a source-bound build receipt.
The receipt command reports **shape and binding only**, never physical admission.
The measured AArch64 ReleaseSafe CLI is 1,092,688 bytes (stripped); Debug is
8,476,200 bytes and exceeds the control cap by itself. Neither measurement admits
the complete control closure: baked host, producer, publication and future
command bytes must still fit the shared ledger.

## Fresh contracts and assertion mapping

No legacy v6/v9 receipt, producer map, or historical artifact is patched.
The native contracts are `hyperv_native_producer_provenance_v1`,
`hyperv_local_native_producer_binding_v1`,
`hyperv_artifact_preparation_native_v1`,
`hyperv_native_input_selection_v1`, `hyperv_native_prepared_input_v1`, and
`hyperv_public_capability_artifact_native_v1`. All local receipts carry
`authority: not_admitted`. The input state is only `prepared`; the parser cannot
reinterpret a `completed`/`accepted` or historical failure state.

The native seed manifest is
`unikraft.hyperv.synthetic-storage-seed.native`, schema version 1. Native footer
creator `ukn1` deliberately does not masquerade as the historical producer.
Full-image rendering/validation is restricted to 49..4096 sectors, 512 bytes
per sector. Seed records bind both IDs, policy 2, LUN, geometry, duplicate
sectors, reserved zeroes, and CRC. Intent/receipt/extent regions remain pristine.
The sector decoder can support a future streaming original-seed importer;
the full-image renderer cannot regenerate the 4-GiB acceptance seed.

For persistence, the configuration purpose gate requires LUN 7 and
8,388,608 x 512 geometry. This does not establish custody of the original IDs,
raw/VHD/config/manifest, nor authorize a write. No original seed is read by these
fixtures. The original artifact admission/importer and persistence engine remain
separate integration work.

The input ledger requires the complete selected asset list, six firmware
working copies, an 8-MiB evidence reservation, and staged/native/baked/producer/
publication controls. The native control maximum is exactly **2,097,152** bytes
inside **268,435,456** total bytes. Remaining control headroom is charged as a
reservation, including the input document and future commands, avoiding a
self-referential manifest hash. Generation refuses a document exceeding that
headroom. Hashes/sizes/modes are remeasured; received totals are never trusted.

Fixtures cover strict field/numeric/canonical negatives; real relocated Git and
SHA1/SHA256 source/index/tree/mode/symlink mutations; malformed ELF/runtime
closure; guarded config and seed formats; real native miz image packaging;
no-overwrite/private-path/deadline publication; separate failure lanes; and
receipt/source/target/dependency/budget substitution. Tests explicitly named
`SHAPE ONLY` do not claim an end-to-end producer approval.

## Remaining integration blockers

The scoped local modules are implemented, but the artifact-preparation todo
cannot honestly be marked complete while the real producer cannot run:

These producer observations describe this branch's base
`25453c84459b946b6ba401dc3490aeab81def9b0`, not a claim that another branch has
not advanced. Core/transfer, ARM and host are merged at the parent-reported main
`d648e4b1304a14a70b83b4e1c73a80924ecb77ae`. The preparation branch has not been
rebased; parent-directed compatibility and producer reassessment are still
required.

1. The current root `finishNativeImages` still selects Python SMP/IRQ/driver
   proofs. The adapter rejects these before any child; parent must merge and
   audit the native proof lane and provide its three source-bound selectors.
2. The current facade restores canonical passwd HOME and strips parts of the
   Git/cache/Bison environment. Its **existing shared lock inode and ownership
   must remain unchanged**, while a coordinated native preparation execution
   contract preserves the reviewed isolated environment.
3. Current Make selects an ambient absolute shell and resets umask to 0022.
   The closed native runtime and private solved-config policy must be integrated,
   not bypassed. The adapter currently requires reviewed static native PATH
   aliases, including a source-bound relocated-Git entry; provisioning that
   entry/closed toolchain is not supplied here.
4. Current `config-inspect` emits inspection on stderr rather than a canonical
   metadata stdout contract. Callers must supply separately bound authoritative
   metadata; no failed/stderr-text recovery is implemented.
5. Parent owns foundation `core.zig` entry update, root facade/CI wiring,
   producer pins, serial integration, full `-j2` guest/build execution and fresh
   independently audited receipts. No shared-scope workaround is included.

Credential lifetime, host image, route, identity/RBAC, publication and cloud
authority remain blocked independently. This package neither selects an
operator credential nor grants any live cleanup lifetime.

## Preflight engine integration contract

This section records the reusable boundary implemented by preparation commit
`bfe678048d6212c5a07406ca14875b83bc648301`. The merged host comparison is against
Git objects at `d648e4b1304a14a70b83b4e1c73a80924ecb77ae`; no host source is
copied or changed here. Import the configured `hyperv_preparation` module and
reuse its exported modules/types. Do not create another build-receipt schema or
weaker parallel JSON decoder in the engine.

**There is no exported admitted-input token or complete read-only engine-entry
loader yet.** `inputs.Input` is a prepared document, not authority to execute.
The APIs below can validate its components. The parent-owned entry adapter must
compose the required checks and remain unavailable until its missing shared
integration is implemented and reviewed. A successful CLI inspection or
`inputs.validate` alone is not that adapter.

### Canonical bytes, types and exact versions

Use `contracts.parse(T, allocator, bytes)` and `contracts.canonical(allocator,
value)`, not the permissive default JSON decoder. Canonical documents are compact
UTF-8 with byte-sorted object keys and **exactly one final LF**; hashes cover that
LF. Duplicate, unknown and missing fields fail, including omitted nullable
fields or omitted fields that have Zig defaults. Integers cannot be floats,
exponents or strings. Current general limits are 4 MiB, depth 32, 4,096 items
per container, 65,536 tokens and 8,192 bytes per string. Narrower CLI/consumer
limits still apply.

| Exported type | Representation / exact field set |
| --- | --- |
| `contracts.Sha` | `[64]u8`, lowercase ASCII hex, JSON string; not 32 raw digest bytes. |
| `contracts.Identity` | `[32]u8`, lowercase nonnil ASCII hex, JSON string; a storage run/disk ID, not an RFC UUID. |
| `contracts.File` | `path, sha256, size, mode`; `size: u64`, `mode: u16` numeric permission bits (0600 is decimal 384). |
| `contracts.Tree` | `sha256, files, bytes`; `files: u32`, `bytes: u64`. |
| `contracts.Source` | `scheme, head, tree, tree_sha256, physical`; scheme exactly `git_physical_native_v1`, Git IDs 40 or 64 lowercase hex, `physical: Tree`. |
| `config.Guard` | `run_id, disk_id, sectors, lun, sector_size, identity_policy`; `u64/u8/u32/u32` numeric fields, sector size 512, policy 2. |
| `runtime.Origin` | `scheme, revision, source_sha256, producer_sha256`; scheme `git`, `zig_package` or `authenticated_distribution`. |
| `runtime.Tool` | `role, origin, target, tree, executable, loader, libraries`; target `aarch64_linux`, `x86_64_linux` or `data`; nullable file records remain explicit. |
| `provenance.Dependency` | `name, package_hash, content`; `content: runtime.Tool`. |
| `receipts.Link` | In-memory `receipt: Receipt, sha256: Sha`; not another persisted receipt. |

`Source.tree_sha256` is the SHA-256 of the raw Git tree listing. It is not
interchangeable with the Git tree object ID or the physical-source digest.
Likewise, a generic filesystem inventory digest is not a replacement for
`source.inspect`'s physical Git verification.

Except the separate synthetic-seed manifest, these native wire versions are
encoded in the **exact `schema` string**, not in a numeric `schema_version`:

| Type / schema | Exact top-level keys |
| --- | --- |
| `provenance.Record` / `hyperv_native_producer_provenance_v1` | `schema, source, host_target, guest_target, compiler_version, producer, compiler, git, dependencies, trust` |
| `producer.Binding` / `hyperv_local_native_producer_binding_v1` | `schema, source, repository, workspace, output, scratch, config, path, native, git, packages, bison_data, trust, trust_bundle, native_execution, native_proof` |
| `receipts.Receipt` / `hyperv_artifact_preparation_native_v1` | `schema, phase, purpose, run_id, guard, source_before, source_after, provenance, reviewed_provenance_sha256, config_before, config_after, parent_sha256, execution, efi, packaging, authority` |
| `package.PackageReport` / `miz_efi_application_package_v1` | `schema, miz_revision, architecture, generation, boot_path, efi, raw, vhd, identities, geometry, raw_vhd_prefix_sha256` |
| `inputs.Plan` / `hyperv_native_input_selection_v1` | `schema, packaged_receipt_sha256, capability_source, capability_receipt, qemu, assets` |
| `inputs.Input` / `hyperv_native_prepared_input_v1` | `schema, state, authority, receipt, reviewed_selection_sha256, selection, ledger, budget` |
| `inputs.Capability` / `hyperv_public_capability_artifact_native_v1` | `schema, image, provenance, reviewed_provenance_sha256, authority` |

`Record.guest_target` is the enum string `x86_64_freestanding_none`; the compiler
command target constant is instead `x86_64-freestanding-none`. Host target must
match the producer/compiler/Git runtime, and compiler version is `0.16.0`.
The exact miz revision/package hash remains mandatory. Dependency/runtime/trust
fields cannot be dropped when moving receipts between the preparation binary
and engine.
`producer.Binding` preserves the original directory identities, tool contracts,
execution and proof attestations. Each successful execution's
`admitted_binding_sha256` must select that independently reviewed binding;
preserve its original bytes rather than rewriting directory identities to match
an engine workspace.

`Receipt.authority`, `Input.authority` and `Capability.authority` are exactly
`not_admitted`. `Input.state` is exactly `prepared`.
`Receipt.purpose` is `platform_preflight`, `persistence` or `synthetic`; an engine
must explicitly select its intended real purpose and reject `synthetic`.
`Receipt.run_id` must equal `guard.run_id`.

| Receipt phase | Mandatory local transition evidence |
| --- | --- |
| `prepared` | No parent/execution/EFI/package; config before equals config after. |
| `configured` | Parent is prepared; execution step is configure; no EFI/package. |
| `built` | Parent is configured; execution step is build; EFI present; no package; config unchanged by this step. |
| `packaged` | Parent is built; execution is null; same EFI plus native package report; config unchanged by this step. |

`receipts.Execution` has exactly `step, exit_code, cleanup_complete,
admitted_binding_sha256`. Recorded successful transitions require exit code 0
and complete cleanup. This is necessary consistency, **not independent proof**
that the claimed process ran. `requireParent` recomputes canonical parent hashes
and binds purpose, guard, provenance commitment, source and config across steps.
Persisted filenames are `prepared.receipt.json`, `configured.receipt.json`,
`built.receipt.json`, and `packaged.receipt.json`. Neither a standalone receipt
nor any of these phases is a completed preflight handoff.

`inputs.Asset` has exactly `id, role, source, destination, placement`, with
placement `staged`, `baked` or `future_copy`. `budget.Entry` has exactly
`id, role, artifact, source, reserved`; `budget.Totals` has exactly
`used, control, reserved, total_remaining`. Reuse the actual `budget.Role` enum.
The `boot_disk` role in this version means the **public capability raw image**,
not the Azure host OS disk.

### Callable validators and their limits

The following signatures use the modules exported by `hyperv_preparation`.
All allocators and borrowed directories must outlive their returned records.
`std.json.Parsed(T)` owns its parsed storage and needs `deinit`.

```zig
receipts.parse(allocator, bytes, expected_sha256) !std.json.Parsed(receipts.Receipt)
receipts.requireLink(allocator, link: receipts.Link) !void
receipts.requireParent(allocator, child: receipts.Receipt, parent: receipts.Link) !void
inputs.validate(allocator, input: inputs.Input, expected_selection_sha256) !void
inputs.ledger(allocator, plan: inputs.Plan, packaged: receipts.Link) ![]budget.Entry
provenance.verify(allocator, io, record, bindings: provenance.Bindings, reviewed_sha256) !void
source.inspect(git: *runtime.Git, repository: files.Directory) !contracts.Source
source.require(actual: contracts.Source, expected: contracts.Source) !void
config.validateWithMetadata(allocator, bytes, expected: config.Guard, metadata: ?*const config.Metadata) !void
package.validate(allocator, io, output: core.private_files.Directory, input: files.Directory, expected: package.PackageReport) !package.PackageReport
budget.recompute(allocator, io, entries, expected, bindings: []const budget.Binding) !budget.Totals
producer.describe(allocator, inputs: producer.Inputs) !producer.Binding
producer.bindingDigest(allocator, binding: producer.Binding) !contracts.Sha
```

The expected receipt, provenance and selection hashes must come from independent
review/authority, not be calculated from the submitted object and then passed
back as its own expected hash. In particular, `receipts.parse` checks the
embedded provenance digest for internal consistency; only
`provenance.verify(..., externally_reviewed_hash)` establishes agreement with
the independently selected provenance and physically remeasures its bindings.
`inputs.validate` validates selection/receipt/ledger consistency; it does not
read artifact files, inspect Git, verify image packaging, verify signatures or
grant cloud authority.

`provenance.Bindings` contains explicit producer/compiler/Git/trust directories
and named dependency directories. `runtime.Git` must be bound to that **same**
reviewed Git contract and directory before it runs. The existing
`receipts.Context.requireGitBinding` supplies that comparison.
`Context.requireProducerBinding` similarly prevents checking one repository or
compiler while building another.

`receipts.Context.verify` is a **producer-side** check: it also calls
`provenance.requireCurrentExecutable`, requiring `/proc/self/exe` to match the
recorded preparation producer. A different engine binary cannot use that method
as a generic stored-receipt importer. Do not bypass or rewrite this producer
check. The read-only engine adapter must use `provenance.verify`, the bound Git
inspection and artifact checks, and independently bind its own executable.

`inputs.generate` is a mutating, create-only preparation operation, not a loader:

```zig
inputs.generate(
    context: *receipts.Context, lock: *core.private_files.Locked,
    packaged: receipts.Link, package_directory: core.private_files.Directory,
    efi_directory: files.Directory, plan: inputs.Plan,
    reviewed_selection_sha256: contracts.Sha,
    bindings: []const inputs.Binding, qemu_directory: files.Directory,
) !inputs.Input
```

It requires fresh staging, validates the source/capability/QEMU/package bindings,
copies planned staged files privately, rechecks source and final inventory, and
durably creates `input.json`. Baked and future-copy records are charged but not
materialized there. `inputs.Binding` is `{id, directory}`.
Generation's private helper checks do not constitute an exported persisted-input
loader; the engine must not call generation to "repair" or adopt a failed
preparation.

### Required checks before executable engine entry

Inspection may report a document, but no host launch, credential acquisition,
upload or cloud operation is permitted until all entry conditions hold:

1. Load bounded private input and receipt bytes through validated descriptors,
   compare independently selected file digests, and use the existing strict
   parsers. Preserve the exact canonical bytes, including LF. Validate the full
   prepared/configured/built/packaged receipt chain and require the packaged
   terminal receipt selected by `inputs.Plan`.
2. Compare the real intended purpose, storage IDs, geometry, final configuration
   and all external review commitments. For #120 the synthetic purpose is
   forbidden; #89 additionally needs original-seed custody and LUN 7,
   8,388,608 x 512 geometry. A matching declaration is not original-seed custody.
3. Physically remeasure the reviewed producer, compiler, dependency, complete
   relocated Git, runtime and trust bindings. Inspect the unreplaced physical
   source with that exact Git, compare it with the reviewed source, and retain
   before/after checks around any preparation work. Do not replace this with
   `git status`, a supplied source hash or a producer's own assertion.
4. Remeasure the final config/EFI/raw/VHD, run
   `config.validateWithMetadata` with authoritative bound metadata and
   `package.validate`, and verify the capability receipt/image/source plus the
   complete QEMU closure. Staged files use `destination` and mode 0600 even when
   the original `Asset.source` has a different safe path/mode. Do not apply
   private single-link policy to every original read-only source artifact.
5. Require an exact staged-file inventory: planned staged assets, the immutable
   `input.json` and stable writer lock, with no unreceipted leftovers. Recompute
   file records, the complete ledger, all six firmware copies, evidence and
   control reservations. Account for the input document and all other controls;
   a parent ledger must also bind bytes outside the staging directory.
6. Validate the reviewed host projection and signed authority described below,
   including total workflow accounting, approved image, runner, unit, engine,
   routes, identity/RBAC and cleanup-valid credential lifetime. Reject any
   unresolved primary/cleanup/recording failure. Keep the independent parent
   hard deadline and exclusive ownership; no default approvals.

Successful completion of these checks is an engine-internal admission result,
not a new persisted build receipt, a host public-acceptance signature, or a
completed preflight record. The completed-state loader and persistence engine
remain separate work.

### Merged host projection and current hard gaps

Reuse `hyperv_host.protocol` from the merged host module. Its `Hash` is the
core's **32 raw bytes**: explicitly parse preparation's hex with
`core.contracts.parseSha256`; do not cast `[64]u8` to `[32]u8`.
Its scope run/VM/phase identifiers are RFC UUIDs, separate from the guarded
storage run/disk identities. Do not reinterpret a storage ID as the attempt
UUID. Use the host's actual `Role`, `validName` and `artifactBlob` helpers.

| Preparation source | Host role and required name |
| --- | --- |
| Asset `qemu` | `qemu`, `qemu/bin/qemu-system-x86_64` |
| Asset `qemu_support` | `support`, validated names under `qemu/lib/` or `qemu/share/`; at most 124 |
| Asset `firmware_code` | `ovmf_code`, `OVMF_CODE.fd` |
| Asset `firmware_vars` | `ovmf_vars`, `OVMF_VARS.fd` |
| Asset `boot_disk`, bound by `inputs.Capability.image` | Public `capability_raw`, `capability.raw` |
| Asset `raw`, bound by packaged receipt | Private `raw`, `private.raw` |
| `Receipt.packaging.vhd` | Private `vhd`, `private.vhd`; **no dedicated preparation input-v1 asset role exists yet** |

That last row is an actual unresolved schema/projection dependency. The merged
host requires both private raw and VHD. Input-v1 requires one raw and already
uses its single `boot_disk` for capability.raw; it cannot honestly represent the
private VHD with another typed role. Do not relabel VHD as a control/QEMU support
file, add an uncharged copy after input publication, invent a second engine
receipt, or bypass final inventory checks. A preparation-owned, reviewed,
versioned input/ledger extension is required before the selected six-boot
workflow can enter execution. Existing package validation and build-receipt
types can be reused; no historical record should be patched.

The host manifest has exactly `raw_size, policy, guarded, artifacts`; each
artifact has `role, name, blob, sha256, size`. Public and private infrastructure
must have the same ordered commitment. Choose `raw_size` and `image_sha256` from
the corresponding validated public/private raw artifact, not from the host
image or receipt file. The private VHD must be raw-size + 512.
Guarded policy on this path is `guarded-v2-pristine-unavailable`; its exact
fields are `run_id, disk_id, lun, sectors, solved_config_sha256,
producer_sha256`. IDs/geometry come from the checked `Guard`, and solved-config
hash comes from the checked terminal `config_after`.

The recommended projection for the parent-reviewed adapter binds the guarded
producer commitment to the
existing **externally reviewed canonical provenance SHA-256**:
`Receipt.reviewed_provenance_sha256`, in both signed image admission's
`guarded_producer_sha256` and manifest guarded `producer_sha256`. Keep the
producer executable hash, receipt hash, input-selection hash, host-image hash
and runner hash distinct. This is a proposed adapter mapping, not an implemented
signer or a claim that any current image admission carries it. Its meaning must
be fixed by parent review and fixtures before use; actual signing authority is
also a prerequisite. Do not silently choose a different digest because its
field happens to be named `producer_sha256`.

Signed host envelopes have exactly `body, signature`. Use the existing host
canonical encoder and Ed25519 verification: signatures cover
`DOMAIN + "\n" + canonical(body)`, with one final LF in the canonical body.
Signature text is 128 lowercase hex characters. Existing domains are
`uk-hyperv-image-admission-v1`, `uk-hyperv-host-command-v1`, and
`uk-hyperv-public-acceptance-v1`; use `Admission.parse`,
`Admission.validateStartup`, `Command.parse` and `Acceptance.parse`.
Host `Verified.digest` binds the received complete envelope bytes, not merely a
reencoded body. Public acceptance must bind the exact public command and
successful public evidence bytes plus the original host boot ID; a capability
artifact receipt is not that acceptance.

Preparation totals are not a signed host-image ledger. Host
`image_control_bytes` must cover the complete baked control closure, and
`image_staging_bytes` is its independently admitted starting debit/reservation.
The host subsequently charges startup, command/state versions, transfers,
firmware and evidence. Do not blindly copy preparation's used/reserved total
into either field or treat reserved headroom as free bytes. The parent must
prove a coherent complete-workflow accounting with no omissions, exemptions or
accidental repeated debits, within 2,097,152 control and 268,435,456 total bytes.

### Exact standalone CLI result shapes

Successful commands exit 0 and write one JSON line to stdout:

| Command | Exact result (before the final LF) |
| --- | --- |
| `synthetic-seed` | `{"scope":"synthetic_only","state":"prepared"}` |
| `package` | `{"authority":"not_admitted","inspection":"native_package","state":"packaged"}` |
| `inspect-receipt` | `{"authority":"not_admitted","inspection":"shape_and_binding_only","phase":"prepared"}` |

The inspection phase value is the validated receipt's `prepared`, `configured`,
`built` or `packaged`; every other field is fixed. The request bounds for seed
and package are 4,096 bytes; receipt inspection is bounded to 4 MiB and requires
the expected digest as its final argument. Neither CLI result is an engine
admission interface, and `package.inspection.json` is a `PackageReport`, not a
source-bound `Receipt`.

Failures exit 1 and write the core `Failures` JSON to stderr with exactly
`cleanup, primary, recording, schema_version`, version 1 and a final LF. Each
lane is null or a diagnostic with exactly `category, http_status, service_code,
stage`; values are the core enum vocabulary and an observed HTTP status or
null. Preserve all three lanes. Never use stdout/stderr text to recover a
failed producer, mark a phase complete, or infer cloud permission.
