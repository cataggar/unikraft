# Native local Hyper-V artifact preparation

This package implements local primitives for the selected #120/#89 workflow.
It is **not an executable end-to-end replacement yet**: the current repository
producer path is deliberately rejected before spawning a build. No cloud
authority, completed preflight, persistence acceptance, or historical-state
conversion is provided.

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
