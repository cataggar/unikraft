# Native public image-and-evidence archive engine

`root.zig.public_archive` is a library. The additive `public_products` APIs and
controller commands compose it with merged private products; this is not a
production caller cutover. It imports the named `handoff_contracts` and typed
`AcceptedRun`/`PrivateBundle` owners; it neither imports nor admits authority.
Python's public bundle producer, transport, workflows and callers remain live.
“Public-source” here means the public lane's image outputs and evidence, not a
source-code archive.

## Ownership and API boundaries

* `Context.fromCI` binds the fixed public pull-request job, checkout, producer
  revision and independently supplied run ID/attempt. `pack` requires both that
  CI context and an explicitly supplied matching `Context`. The source tree and
  revision remain the accepted producer's identities, even when another commit
  has the same tree.
* `Metadata.fromRootBound` accepts only the closed positional handoff schema at
  its exact absolute root, then replaces each authenticated member path with its
  fixed portable name. `fromPortable` does not confer private-owner status.
  Both preserve canonical metadata, v1/v2 dispatch and original identity,
  lineage, order and bytes.
  `rootBoundBundle` performs inverse positive-path rebasing for a separately
  validated import; it does not itself admit a private owner.
* `pack` borrows either a merged `PrivateBundle` or an accepted local run plus
  its retained root-bound exported manifest. Local handoffs must retain their
  validated native inspection record and matching package-inspection output.
  Production inputs remain confined to the original public runtime's
  `compute/public-source/handoff` under the CI checkout's
  `.d/wamr-native-runtime` or `/d/wamr-ci/wamr-native-runtime`.
  It checks the accepted record/result/artifact bindings, exact source tree,
  fresh content hashes and retained physical identities at live boundaries.
  Known private inspection/export bookkeeping is never selected.
* Publication reserves a fresh private `0700` output directory. `archive.partial`
  is create-only `0600`, written as deterministic stored ZIP32, synced and
  reopened before final revalidation. A no-replace rename publishes
  `public-inner.zip` last, followed by directory sync and retained reopen.
  `Outcome` distinguishes input refusal from poisoned partial state, reporting
  phase, error and publication durability. Failures retain partial evidence;
  no success receipt or automatic destructive cleanup is produced.
  Pass the caller's installed cancellation signal, or let `pack` own a scoped
  signal handler; streaming checks cancellation between chunks.
* `verifyBytes` authenticates the complete ZIP and canonical portable metadata
  against an independently supplied context and digest. Digest omission is
  limited to the frozen historical v1 source table and dependency-free original
  build-start record. Exact allowlists, ordering, regular `0600` ZIP attributes,
  CRCs, member hashes, bounds and secret-pattern refusals apply.
* `Archive.open` retains the file and a wiping immutable image buffer.
  `revalidate` rereads and hashes the live retained input, not a cached digest.
  `materialize` creates a private **portable imported stage**, runs the existing
  native `AcceptedRun.openImportedStage` acceptance/lineage validator and returns
  `Imported`. It never relabels portable archived paths as a root-bound private
  bundle. `Imported` borrows its `Archive`; deinitialize it first.

The frozen v2 product is exactly 85 regular members: 83 positively selected
outputs/evidence, then `bundle.json` and `public-source.json`. Limits remain 96
members, 512 MiB complete ZIP/aggregate content, 64 KiB JSON and the frozen
per-member bounds. Duplicate names, case collisions, links, traversal, extras,
input replacement/mutation, cancellation and uncertain durability refuse.

## Independent local transport engine

`root.zig.public_transport` implements local staging and binding only.
`stageUpload` borrows a verified `Archive` and separately supplied context and
`InnerDigest`. It reserves a create-only `0700` directory, streams a create-only
`0600` `upload.partial` using the existing retained-copy owner, syncs and reopens
it, revalidates the live source, and publishes only
`tiny-aot-public-source.zip` with a no-replace rename followed by directory sync.
Its `Outcome` owns a retained `Standalone` on success; refusal/poison diagnostics
report the phase and durability without deleting evidence.

`Download.open` consumes a retained private directory containing exactly that
one regular single-link file, with no extras, links, alternate case or nested
fallback. `Expected` contains independently trusted upload metadata and the inner
digest; `DownloadSelection` records the exact Actions selection. Both artifact
IDs, container digests and source/run contexts must agree, and the archive
verifier independently checks the inner digest and context. `ArtifactId`,
`ContainerDigest` and `InnerDigest` are distinct types: the container SHA is
**not** the inner SHA. The engine does not download anything, hash container
bytes, or authenticate remote metadata from filenames or receipt equality.
The existing exact `artifact-ids` `download-artifact` action remains the network
owner. Callers must provide trusted upload metadata, not data discovered beside
the downloaded ZIP.

The owner copies its context and retains both the directory snapshot and genuine
`Archive`. Each revalidation rechecks exact membership, physical identities and
directory metadata and rereads/hashes the live ZIP; identical replacement,
in-place mutation and transient added/removed members refuse. `receipt` returns
canonical frozen v2 bytes only, with no new fields and no receipt publication.
Historical v1 cannot receive v2 transport metadata; its existing archive/import
and digest-omission rules remain unchanged.

`Download.materialize` calls `Archive.materialize` and the genuine existing
`AcceptedRun.openImportedStage`, returning `Imported` which borrows the
`Download`; destroy it first. Keep both owners at stable addresses while borrowed.
Its live revalidation also checks the downloaded directory. It creates only the
portable stage, not a root-bound private bundle, `transport.json`,
`candidate-bundle.json` or final `bundle.json`. Actual private supervisor and
validator executable custody, native imported-command revalidation, publication
records and publication-last final bundle belong to `public_products`, not
these library-only owners.
There is no synthetic identity wrapper, fallback, arbitrary command runner,
network process or authority admission API here.

## Qualification

Use an existing external system dependency forest, caches, temporary root and
private fixture root; hold the fleet qualification lease during sensitive tests:

```sh
zig build --build-file support/build/wamr-native-ci/handoff.build.zig \
  --system /absolute/system --cache-dir /absolute/cache \
  --global-cache-dir /absolute/global -Dtest-root=/absolute/private-scratch \
  -Doptimize=ReleaseSafe test
```

`test-public-archive` selects the archive engine. Optional
`-Dpublic-archive=/absolute/current.zip` enables genuine retained archive
qualification. Defaults retain historical run `37321447300`, attempt `1`,
synthetic producer merge
`c8f45aefcb855480605830ea47a8990c72d0fda3` and tree
`47fafaddda9b4c56cba06c868c1cad0a62084c60`, with the independently trusted inner
digest. It also tests native imported acceptance, genuine byte-identical
retained repacking and fully rehashed source/run/member adversaries.
For another genuine source, supply all independently authenticated identity
options: `-Dpublic-source`, `-Dpublic-tree`, `-Dpublic-run-id`,
`-Dpublic-run-attempt`, `-Dpublic-inner-sha256`, `-Dpublic-archive-bytes`,
`-Dpublic-artifact-id` and `-Dpublic-container-sha256`. Never relabel a
historical fixture as current.

`test-public-transport` selects the transport engine. Supply the same genuine
`-Dpublic-archive` and `-Dtransport-receipt=/absolute/live-python-receipt.json`
for zero-skip genuine staging, native imported-stage acceptance and receipt byte
parity. The receipt oracle must be generated by the existing Python producer's
`run.save` canonical serializer with the exact v2 import dictionary and trusted
run/source/upload context. Focused faults exercise retained exact-member binding,
ID/context/digest mismatches, links/extras, actual sparse-file size limits,
same-byte replacement, cancellation, create-only collisions and partial/sync
durability. Only explicit test faults replace syscall failures; genuine
acceptance is not replaced with a test-only trusted owner.

Golden/fault packing substitutes only the expensive producer CI/private-tool
process boundary with an explicit test-only API. Genuine repacking additionally
binds every member to a real native imported `AcceptedRun`; this does **not**
claim an archived portable stage is a production private owner. The additive
`public_products.exportArchive` and `public_products.importBundle` APIs perform
real supervised validation and durable final publication. See the controller
README for the complete CLI and ownership/trust boundaries. Protected product
acceptance, production workflow/local caller cutover and Python removal remain
separate milestones.
