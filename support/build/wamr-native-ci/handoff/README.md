# Native public image-and-evidence archive engine

`root.zig.public_archive` is a library. The additive `public_products` APIs and
controller commands compose it with merged private products; this is not a
production caller cutover. It imports the named `handoff_contracts` and typed
`AcceptedRun`/`PrivateBundle` owners; it neither imports nor admits authority.
Python's public bundle producer, transport, workflows and callers remain live.
“Public-source” here means the public lane's image outputs and evidence, not a
source-code archive.

## No-authority candidate boundary

`root.zig.candidate.create` and `open` yield an opaque `Finalized` only after
the merged private owner, genuine supervised native private validation, and all
candidate bindings have been rechecked. The source is a borrowed
`PrivateBundle` or durable `ImportedProduct`; it must outlive the candidate.
An imported product retains its original archive/container, transport, native
command evidence and immutable copies through that borrowed owner. A CLI
reader reconstructs a private owner and runs a **fresh** native validation;
it does not pretend that a receipt proves an independent GitHub download.
Portable metadata cannot construct `Finalized`.

`Finalized.inspect`, `artifact`, `result`, and `revalidate` are the explicit
boundary for later authority consumers. Those consumers must revalidate this
owner at their acceptance boundaries, not duplicate candidate parsing or
custody. The product imports no authority-producing module. Its typed authority
has only `not_admitted`; the frozen six approval flags remain false and both
approval times remain zero. No approvals are read or consumed.

All CLI paths are canonical absolute paths with existing private parents.
Each invocation requires a fresh `--validation-output ABS` outside the input
and source checkout, plus explicit `--git ABS --supervisor ABS --validator ABS`.

* `candidate --bundle ABS/bundle.json --output ABS` additionally accepts
  `--attempt-id UUID --subscription TEXT --prefix NAME`. Omitted attempt IDs
  are freshly generated UUIDv4s. V1 retains the frozen placeholder subscription
  and prefix, four modes, and direct bundle binding. V2 retains the current
  profile, six modes and exact lineage; it requires a matching canonical
  `transport.json`, publishes `OUTPUT.admission.json`, then the candidate last.
  V2 defaults remain subscription `00000000-0000-0000-0000-000000000001`
  and prefix `not-admitted-candidate`.
* `candidate-inspect --bundle ABS/bundle.json --candidate ABS` retains and
  compares the complete canonical candidate and v2 admission against the
  freshly validated source. It does not rewrite either document.
* `candidate-result --bundle ABS/bundle.json --candidate ABS
  --serial-first ABS [--serial-second ABS]` additionally runs the shared tiny
  native log validator in direct scope. With two captures the second must
  extend the exact first Azure cumulative prefix, ignoring only its trailing
  NUL padding. The result has the existing direct serial result shape, not an
  admission or execution receipt. Incomplete evidence exits 2 with a diagnostic;
  other refusals exit 1.

Candidate/admission publication is create-only, private and durable. Refusals
report their exact phase/cause and retain partial state without resume or
destructive cleanup. Native command records/logs, transport, source, candidate,
admission and serial captures are physically retained and freshly hashed at
their boundaries. The compiler source closure now includes this product and
its public-product dependencies, while the earlier export closure remains an
explicit read-only historical selector; closure schema and guarded pins are
unchanged. Python/workflow callers and the frozen differential witnesses remain
live until a separately qualified cutover.

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

## Test-only stagewise shadow witness (#187)

`tests/handoff_shadow.py` is a bounded driver, not a production caller,
qualification service, network downloader, or authority consumer. It executes
the actual native commands and unmodified Python `export`, `verify_archive`,
`import_bundle`, and `candidate_plan` implementations in separate processes.
There are no accepted-owner stubs or Python fallback after native refusal.
`handoff/shadow_compare.zig` performs the canonical-record comparison using
the shared native handoff contracts and the existing typed tiny result.
The Python process driver/filesystem witness remains test-only until its
separate native coverage/deletion gate; production Python is unchanged.

### Source-only validation

The independent build avoids the production package's dependency restoration
and does not modify root/authority builds or install production commands.
Use Zig 0.16, `-j1`, existing owner-private external scratch/caches, and both
Debug and ReleaseSafe:

```sh
SHADOW=/absolute/owner-private/shadow
zig build --build-file \
  support/build/wamr-native-ci/handoff/shadow/build.zig \
  --cache-dir "$SHADOW/cache-debug" \
  --global-cache-dir "$SHADOW/global-debug" \
  --prefix "$SHADOW/tools-debug" -Dtest-root="$SHADOW/scratch" \
  -Doptimize=Debug -j1 test-shadow install
zig build --build-file \
  support/build/wamr-native-ci/handoff/shadow/build.zig \
  --cache-dir "$SHADOW/cache-safe" \
  --global-cache-dir "$SHADOW/global-safe" \
  --prefix "$SHADOW/tools-safe" -Dtest-root="$SHADOW/scratch" \
  -Doptimize=ReleaseSafe -j1 test-shadow install
```

`test-shadow` runs **synthetic comparator/driver tests only**, including
dependent-commitment, source/run/attempt/transport, authority, selected-payload,
extra-member, command timeout/status/custody, partial-report and scope refusals.
It neither needs nor runs private producer resources, and a passing result
does not count missing/skipped genuine tests as parity.

### Required externally qualified inputs (not provisioned by this driver)

The only live entry point is:

```sh
python3 -B support/build/wamr-native-ci/tests/handoff_shadow.py \
  run-stagewise --inputs /absolute/approved-inputs.json \
  --output /absolute/fresh-external-shadow
```

This invocation is blocked until an owner has independently qualified and
immutably staged the **complete** genuine native-produced v2 run. Source-only
PR tests do not run it, request private inputs, or supply synthetic replacements.
The canonical UTF-8 sorted-key compact-LF input document has exactly:

* `schema: "uk.wamr.handoff-shadow-inputs"`, integer `version: 1`;
 `context`: the frozen public context's six exact fields (`repository`,
  `run_id`, `run_attempt`, `source_revision`, `source_tree`, `wamr_revision`);
* canonical absolute `producer_repository`, `reader_repository`, `runtime`,
  `handoff`, `download_root`, and an explicitly supplied UUIDv4 `attempt_id`;
* `tools`: pinned artifacts for `producer_controller`, `reader_controller`,
  `python`, `git`, `supervisor`, `validator`, `comparator`;
* `inputs`: pinned artifacts for `approved_stage`, `consumer_proof`,
  `custody`, `producer_records`, `upload_metadata`, `selection_metadata`,
  `transport_authentication`, `container`, `inner`, `serial_first`,
  `serial_second`, `serial_incomplete`. Only `serial_second` may be null.

Each pin has exactly `path`, integer `size`, and lowercase SHA-256 `sha256`.
The accepted #263 consumer proof and approved-stage/transport provenance are
mandatory nonempty **external prerequisites**. Their pin equality is not a
new acceptance, remote authentication, or producer proof. Never put credentials
in them. `producer_records` is the original canonical genuine
`records --runtime ... --output handoff-v1` output; the driver runs that command
again and compares its exact bytes and source identity before exporting.
The original runtime, source checkout/objects, result, cleanup, six boots,
images, dependencies and every runtime input/tool closure must remain available.
No private owner is reconstructed from metadata by the witness.

`upload_metadata` has exactly `context`, `artifact_id`, `container_digest`,
`inner_sha256`. `selection_metadata` has exactly `context`, `artifact_id`,
`container_digest`, `artifact_ids`. Both contexts must equal the independently
approved producer context. `artifact_ids` must be exactly the singleton trusted
upload ID. Digests are lowercase 64-character hex, without `sha256:` prefixes.
`container` is the retained raw Actions artifact container, while `inner` is
the exact `download_root/tiny-aot-public-source.zip` single regular member.
The IDs, container SHA and inner SHA are separately checked; equal receipts or
sidecars inside the download cannot authenticate it. The separately pinned
`transport_authentication` must come from the owner's independent upload and
exact-ID download authentication. The harness performs no remote authentication
and must not be treated as evidence of it.

`custody` is a canonical `uk.wamr.handoff-shadow-custody` document, integer
version 1, with exactly `roots` and `entries` in addition to schema/version.
`roots` has nonempty arrays of canonical immutable paths for
`producer_source`, `reader_source`, `producer_objects`, `runtime`,
`tool_closure`. `entries` is their complete union of `snapshot(path)` inventories,
independently staged and approved: files contain `path`, `size`, `sha256`,
`metadata`; directories contain `path`, `kind: "directory"`, `metadata`.
Approved original source/tool links contain `path`, `kind: "symlink"`,
`metadata`, and their exact `target`. They are recorded without following them;
their actual target closures must be independently pinned too. Original file
link counts are preserved, not rewritten to impersonate private assets.
Metadata is `[dev, ino, mode, uid, gid, nlink, size, mtime_ns, ctime_ns]`.
The driver re-enumerates/re-hashes these live trees before and after; extras,
removals, link/target changes, same-byte replacement and metadata changes refuse.
Downloads, selected assets and witness product trees still forbid links.
All producer `runtime_inputs`, result/cleanup, executable pins, test driver,
and both original frozen Python oracle closures must be covered.
Use immutable source/object/input subtrees, not mutable validation/cache/output
parents. Each inventory is bounded to 65,536 entries, depth 32, 8 GiB total
and 2 GiB per file. Input JSON records (including custody) are also bounded to
2 MiB; product canonical records to 64 KiB and native comparison requests to
1 MiB. Oversized staging refuses rather than partially comparing.

### Fixed public scope and retained evidence

The original inherited public pull-request job environment must already match
the producer/run/attempt/workspace. The driver never manufactures GitHub CI
variables or copies/relabels a runtime. `runtime` must be that checkout's
`.d/wamr-native-runtime` or `/d/wamr-ci/wamr-native-runtime`; `handoff` must be
its existing genuine `compute/public-source/handoff`.
All witness products/validation roots are fresh external children of the
exclusive owner-private output. A completed genuine Python publication has
already occupied its create-only
`compute/public-source/handoff-revalidation` slot. The driver does **not**
re-run `pack`, reuse that slot, move it, or substitute another sibling.
Instead the separately authenticated original production inner ZIP is the
Python archive byte oracle; the driver runs the frozen Python verifier again.
The original publication/validation evidence remains immutable staged input.
The inherited PATH must select the pinned Git executable.

The driver compares both fresh private exports, then a freshly packed native
archive **over the existing genuine fixed-scope handoff**, not over either
arbitrary sibling shadow export. The native archive must byte-match the retained
original production Python archive, freshly verified from the separately
authenticated exact-ID redownload, before import. This is explicitly not fresh
Python archive production or a composed public-export run. Imported selected bytes,
portable metadata, transport, candidate/admission, inspection stdout and serial
result bytes are compared. The witness checks all 83 selected v2 assets and
85 ZIP members/metadata; only enumerated selected output paths, admission
bundle/transport paths, and candidate VHD/admission paths may rebase.
Each original dependent size/SHA commitment is checked before recomputing its
rebased counterpart. Run/source/identity/transport/failure differences are
never normalized. The six candidate approval flags must be false, the two
timestamps zero, and both incomplete-serial commands must exit 2 without
publishing result stdout.

Each of the 17 ordered stages retains its exact argv/cwd, allowlisted original
environment (no credentials), timeout, original status, stdout/stderr hashes
and physical custody in create-only command/receipt files. Captures are bounded
to 8 MiB each; stages to 2,400 seconds. Timeout kills include descendants in
their own sessions. Existing native private command receipts/partial products
are retained too. Inventories, canonical records, requests, before/after custody,
output pins and failed partial executions are durable external evidence.
Missing, skipped, changed or failed stages refuse; no retry/resume or destructive
cleanup is performed.

`report.json` always states `acceptance: false` and
`genuine_producer_parity: false`. Its strongest outcome is
`stagewise_shadow_equal`, labeled `stagewise-existing-fixed-handoff`.
An authentic, fresh native `public-export` composition run, separate protected
product acceptance/review and caller-cutover/deletion gates remain required.
Neither #263 consumer proof, this source PR, synthetic comparator tests, nor a
stagewise equality report substitutes for that genuine producer composition.
