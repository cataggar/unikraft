# Credential-free tiny native WAMR PR gate

## Native no-authority candidates (additive)

The native CLI provides `candidate`, `candidate-inspect`, and
`candidate-result`. They do not replace the Python `handoff.py candidate`
caller, change the default backend, or grant execution authority. See
[`handoff/README.md`](handoff/README.md#no-authority-candidate-boundary) for
the closed arguments, retained native validation, and typed consumer boundary.
The frozen Python candidate and direct serial validators remain differential
oracles. This product has no Azure launch, approval consumption, deployment,
or cleanup operation.

## Native public products (additive; no caller cutover)

The public product commands compose the merged private owners and the native
archive/transport libraries. They perform real native supervised validation;
portable materialization and a transport receipt alone are not acceptance.
Python public producers, callers, workflows and historical witnesses remain
unchanged pending protected product acceptance and actual merge.

Every public command requires `--expected-source COMMIT --expected-tree TREE
--run-id ID --run-attempt ID`. These are independently supplied identities,
not values inferred from the archive. Source means the actual producer commit
(including a genuine synthetic PR merge), not another commit with its tree.
All paths below must be canonical absolute paths with private existing parents.

* `public-export --runtime ABS --stage-root ABS --validation-output ABS
  --output ARCHIVE_DIR --git ABS --supervisor ABS --validator ABS` creates the
  private handoff, authenticates a `PrivateBundle`, runs native private
  revalidation, then constructs and durably publishes the public ZIP.
  `public-archive` has the same arguments except `--runtime`: it consumes an
  already published private handoff. Both enforce the original fixed public CI
  environment and public runtime's `compute/public-source/handoff` scope.
  The validation output must be outside both the repository and input handoff.
* `verify-public-source-bundle --archive ABS --expected-archive-sha256 HEX`
  verifies retained ZIP bytes and canonical portable metadata without importing
  or publishing anything.
* `stage-public-source-upload --archive ABS --expected-archive-sha256 HEX
  --output ABS` creates one private standalone upload containing exactly
  `tiny-aot-public-source.zip`; no metadata file or success receipt is added.
* `import-public-source-download --download-root ABS --container-archive ABS
  --expected-archive-sha256 INNER_HEX --artifact-id EXPECTED_ID
  --container-digest EXPECTED_CONTAINER_HEX --selected-artifact-id ACTUAL_ID
  --selected-container-digest ACTUAL_CONTAINER_HEX --output ABS --git ABS
  --supervisor ABS --validator ABS` consumes an exact-ID redownload containing
  exactly that one regular, single-link filename. The expected upload metadata
  and actual selection are separate trusted caller inputs. It hashes the
  separately retained raw Actions container and the inner ZIP independently;
  the artifact ID, container digest and inner digest are different types and
  are never interchangeable. This is a local consumer, not a network downloader
  or remote artifact authenticator.
  The raw container is an opaque authenticated transport input, not a native
  ZIP extraction API; the exact extracted member is independently authenticated
  against the trusted inner digest.
* `import-public-source-bundle --archive ABS --output ABS --git ABS
  --supervisor ABS --validator ABS [--expected-archive-sha256 HEX]` preserves
  the frozen historical v1 import. Digest omission remains confined to the
  original historical source table and dependency-free build-start evidence.
  V2 import requires the exact download command rather than an unbound raw ZIP.

The importer retains a pure portable stage under `private/materialized`,
then copies authenticated selected members to the operator root. The current
native reader's supervisor must be the executing controller; the validator must
match its compiled native validator identity. The producer's Git commit, tree
and original source map are verified separately from the current reader's
checkout, executable and runtime custody. Real supervised `--identity` and
handoff validation produce retained command records and output logs under
`private/native-validation`. Source, archive, download, container, selected
members, canonical metadata and those command captures are revalidated before
`bundle.json` is published create-only and durably last.

The operator root preserves `portable-bundle.json`, `public-source.json`,
`candidate-bundle.json`, the v2 `transport.json`, and root-bound `bundle.json`.
The internal materialized archive is never silently relabeled a private owner.
The library returns a heap-stable `ImportedProduct`; its `revalidate` checks
the real private owner, fresh input hashes, sealed output directories and
retained native validation captures. Its `deinit` closes borrowed consumers
before `Download`/`Archive` owners and never removes retained evidence.
The existing `private-validate --stage-root ABS --git ABS --supervisor ABS
--validator ABS --output ABS` reopens an operator bundle and performs a fresh
real native validation in another create-only external output. That fresh
private validation does not reconstruct former archive/download descriptor
custody after the `ImportedProduct` owner has been destroyed.
Failures are explicit refused/poisoned outcomes with phase and publication
durability; partially created state is non-resumable and retained.
Authority stays `not_admitted`; there are no cloud operations, approvals,
candidate execution, Python fallback, or production caller changes.

## Authority contract freeze (#189 PR1; no caller cutover)

`authority/root.zig` is a contract/test surface importing only `hyperv_core`;
it does not install an authority executable or change the four Python operator
commands. The goldens call the existing `handoff.py` runtime, plan, decision and
admission constructors. Only external candidate/ledger inputs, executable/ELF
and process boundaries, time/UUID generation, and physical metadata are stubbed.
The runtime tree, canonical publication, manifest scan, and content/metadata/
parent hashes use the real implementation. Schema inventories are sorted field
sets, not incidental Python dictionary insertion order; canonical record bytes
remain unchanged.

Live probes freeze text byte bounds (including UTF-8, every C0 byte and DEL),
all four UUID inputs, cost/window bounds and refusal output absence. Runtime
copy-budget and scan probes test each exact limit and its first overflow;
virtual scan entries and metadata avoid allocating 2 GiB, and a synthetic
manifest exercises the 32-MiB publication cap. Deterministic external validator
stubs are not evidence of independent validation or decision freshness: the
existing `test_v2_lineage.py` native-validator fixtures remain that gate.
Mutation verification changes eight representative constructor behaviors plus
twelve copy/scan/loader/manifest boundary checks **in memory**, never editing
`handoff.py`; all twenty must change the golden or refuse a previously successful
operation.

The native fixture consumer independently enforces recursive exact field sets,
scalar types, record versions, CLI option metadata, schema domains, and every
fixed runtime isolation/resource/policy value against native literals. Permanent
negative fixtures mutate the actual consumer input, re-canonicalizing both the
embedded records and the outer document; malformed metadata, extra domains or
nested fields, scalar coercions and unsupported versions must fail that same
consumer, not a comparison against another golden.

Run with Zig 0.16 and fresh owner-only roots (no credentials or cloud calls):

```sh
umask 077
mkdir -p .d
mkdir .d/authority-contract-check
export WAMR_AUTHORITY_CONTRACT_SCRATCH="$PWD/.d/authority-contract-check/python"
export ZIG_LOCAL_CACHE_DIR="$PWD/.d/authority-contract-check/cache"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.d/authority-contract-check/global"
(cd support/build/wamr-native-ci && zig build --build-file authority.build.zig test)
python3 -B support/build/wamr-native-ci/tests/test_authority_contract_goldens.py --mutations
```

The full package build's `test-authority-contracts`, `test-controller`, and
`test` targets include the same native/Python gate. Each oracle invocation owns
and removes only its fresh child below the scratch parent, preserving existing
parent contents. `--write` intentionally regenerates checked-in goldens for
review; it is not part of verification.

The scenario inventory tracks every test in its three named Python sources.
After adding or removing tests there, regenerate and review
`authority/goldens/python-scenarios.json` and update the native inventory count
in `authority/tests.zig`; unrelated additions must leave
`authority/goldens/contracts.json` unchanged. Check inventory synchronization
without restoring tools or running the full oracle:

```sh
python3 -B support/build/wamr-native-ci/tests/test_authority_contract_goldens.py \
  AuthorityContractGoldens.test_python_scenario_inventory_matches_current_tests
```

The native compute and integration runtime jobs run this check before tool
acquisition and native builds. The full native/Python authority gate remains
unchanged.

## Native package and boot chain (production caller)

The installed controller now implements `boot --runtime ABS` as a closed,
local-only `tiny_exact_v2` chain. It first refuses hosts without readable and
writable x86 KVM (never TCG or a successful skip), reopens the accepted build,
source, dependency and executable custody, binds the QEMU/OVMF/EFI/package/
local-boot/validator runtime inputs in `boot-inputs.json`, and checks that all
precreated package, publication and six boot slots are empty. It runs the
existing native Miz package tool and local-boot CLI in this order:

```
package → raw x2APIC → raw legacy → QCOW2 intent/finalize
→ QCOW2 x2APIC → QCOW2 legacy → QCOW2 acceptance
→ prove derived VHD absent → VHD intent/gate/derive
→ VPC x2APIC → VPC legacy → inspect → final inspection → result
```

Each boot checks its closed one-CPU/60-second guest request, four physical
input pins, report, raw serial byte count and SHA-256. The #188 installed
`uk-wamr-log-validate tiny` validates guest semantics independently after
each local boot; its supervised 30-second invocation has an empty environment,
64-KiB stdout and 4-KiB stderr caps. Its owner-only per-boot command record
remains private, as do raw logs and validator output. A failure retains prior
evidence and the failed command, never publishes that mode's compute record,
and prevents every subsequent transition. Public success contains exactly
the v2 six-mode record set, `final-inspection.json`, then `result.json` last
without self-hashing. Historical four-mode v1 is read-only; there is no
caller-selected downgrade. `diagnostics --runtime ABS` emits allowlisted
redacted observations only, never acceptance. The protected production
workflow now invokes the installed portable controller for build, boot and
diagnostics; `run.py` remains temporarily for the unmigrated #187/#189 oracles and
historical compatibility reader until its later removal slices.

## Native record-consumer bridge (Python still performs the handoff)

`uk-wamr-native-ci records --runtime ABS --output handoff-v1` reopens a
completed local v2 run, including source and input custody, the six boot
transcripts and image chain, before emitting a bounded, canonical private JSON
description of pinned records, artifacts and runtime inputs. Local replay
requires the original runtime-installed controller and its recorded source
worktree; a separately installed controller cannot replay a Python-produced
run. The separate
`records --stage-root ABS --transport trusted-inner-zip --output handoff-v1`
form checks an extracted public-source inner tree. The initial imported-stage
fixture covers older allowlisted v1 evidence; the current v2 import is also
exercised against a retained protected archive. Neither form executes build or
boot, changes authority, or makes a partially checked manifest an accepted run.

The public bundle importer now requires this native imported-records check
before publishing its candidate, while retaining the Python publication policy.
Only the protected in-job import that passes `--native-import-revalidation`
runs trusted-v2 native revalidation through the native controller; default,
off-runner, and historical Python-produced trusted-v2 imports retain Python supervised-stage
revalidation with the caller-supplied validator. Native-produced v2 local
handoff requires native acceptance before using its result-record hashes and
source identity, and its local inspection is routed through the recorded
runtime controller. Operational Python-produced v2 and historical v1 local
record selection instead uses the explicit
`readonly-records --runtime ABS --output handoff-v1` operation. It reuses native
selected-artifact, packaging, boot and image-chain validation, with recorded
local input custody. Historical local-v1 admission also recaptures the complete
recorded Git checkout before and after selected evidence validation and retains
that physical source snapshot for later rechecks. Later historical producers
require their original recorded input custody. The earliest pinned v1 sources
instead require explicit `--git ABS` for records-only admission: the current
reader Git executable is retained under its own role, not fabricated as
producer custody. Missing original supervisor custody still refuses handoff
inspection/export. Neither path admits a v1 producer or falls back to Python.
Later pre-supervisor v1 source identities retain their exact historical
21-tool inventory, including `head` and `timeout`; supervised v2 keeps the
current exact 19-tool inventory.
Later local-v1 constructors also close the build/boot role and fixed-path sets
before recapturing files, runtime loaders/libraries, trees and ancestry; an
extra recorded executable cannot be admitted merely by resealing its custody
digest. Discovered `runtime:ABS` roles bind the recorded path to that exact
absolute library path in both build and boot custody; an identical separate
copy is not a substitute. Original dependency restore/package custody and Bison
content are recaptured as well, and v2 supervisor source/runtime maps must match the real
producer files and executable runtime, not just internally consistent seals.
Read-only local cleanup proof retains its collected physical artifact snapshot;
the production-native owner's wrapper cleanup remains export-owned custody.
The complete local constructor fixture covers all three later v1
source/tree pairs and a separate historical Python-v2 checkout. It uses real
Git objects and physical Python scans, real native packaging/QCOW2/VHD
production, and actual constructor/recheck/CLI routes. Its command/serial
fixtures are synthetic and do not claim guest or hardware acceptance.
The separate direct-Azure physical image/copy fixture has mocked producer
custody, not a complete native-accepted run. It first proves export refuses
without a native controller, then stubs the read-only view only for downstream
full-image, four-boot, archive and mutation checks, just as its imported-stage
checks do. Its imported native-revalidation seam also proves refusal prevents
candidate/public bundle publication before using a stub for those archive
checks; the real direct validator reopens the imported image and records.
These stubs are not native-admission qualification; the complete-local native
constructor fixture above remains the genuine admission gate.
These fixtures require the genuine historical Git objects in the reader's
repository, so qualification from a shallow checkout must first fetch its
complete history with `git fetch --unshallow`. The native CI checkout uses
`fetch-depth: 0`, matching the existing integration runtime job. Missing
historical objects refuse the fixture; no synthetic commit replaces them.
The historical fixture also needs the complete pinned dependency graph, not
only the lazy subset fetched by a native package build. Native CI restores the
unchanged local-boot manifests with `zig build --fetch=all` in a private root
and supplies its genuine `zig-pkg` forest through `--system`, matching the
existing integration runtime job. Every copied package still undergoes the
original content-hash and custody checks; missing packages are not synthesized
or ignored. Offline qualification must provide that same complete graph.
The mandatory source-custody limit gate and the subsequent controller fixture
gate retain the same isolated checkout, compiler caches and genuine
dependency forest. Both compile against the same physical `--system` paths:
changing from the lazy default forest to a separately restored copy invalidates
package helpers and their dependent test options even with a shared cache.
The first gate restores that complete forest for its existing helper builds,
with a private global-cache temporary directory for SDK ZIP downloads.
The compile-only `build-controller-fixtures` target prepares all controller
and package-boot test binaries alongside that mandatory limit gate. Every
fixture invocation uses the same pipeline-root option so emitted test options
and artifacts remain reusable. This target does not execute fixture cases;
controller, pipeline and Python fixture execution stays in the later gate.
The controller gate checks the exact checkout identity, cleanliness and both
unchanged manifests, then repeats SDK fetch-all before its fixture executions.
Failed limit qualification removes the checkout; successful limits leave it
for the controller gate's cleanup. No fixture execution is moved outside the
controller gate, and its 15-minute deadline remains unchanged.
The ReleaseSafe controller test harness and its host reader CLI use LLVM
code generation: repeated genuine tool, image and runtime custody hashing
dominates their execution, rather than compilation alone. Their safety checks,
fixture identities and all constructor/recheck/CLI refusals remain intact.
Debug fixtures retain the compiler's default backend, as do the production
portable controller, supervisor and other native targets. The compile-only
prerequisite target prepares these exact artifacts before fixture execution.
The four complete-local historical vectors use at most two process-isolated
fixture workers inside that same controller gate. Every revision directory is
preallocated before custody capture; workers own separate checkouts, runtimes, compiler
caches and arenas, and are joined even when one fails. All four preparations
finish before the process-wide cancellation cases execute serially on their
clean inputs. Constructor, recheck, CLI, private-product parity and every
refusal then run unchanged within each owned revision. No digest is reused
across live revalidation, and no case moves into the compile-only prerequisite.
The two worker lanes claim the next prepared revision as soon as either lane
finishes instead of waiting for a fixed pair. A failed operation stops queued
work, but both already assigned workers finish before failure or cleanup.
Physical descendant parity cases privately stage the genuine native
`runtime_fixture.zig` executable compiled by the existing prerequisite graph,
rather than recompiling it with three empty per-case SDK caches. Every case
still owns a separate single-link executable and runs its real descendants,
deadlines, cancellation, output-overflow and cleanup checks in the fixture
gate; preparation only compiles the helper.
Four-CPU measurements attributed the serial cost to repeated genuine custody
hashing, not validators; CPU-target trials did not improve that cost. Backend,
ISA, production defaults, inventories and the 900-second gate remain unchanged.
The fixture-only `wamr-ci-local-acceptance-worker` executes the existing helper
and typed owners directly, not a substituted controller or acceptance record.
Its real process boundary preserves the native owner's `SupervisorBusy` guard;
concurrent typed acceptance inside one process remains forbidden.
The test graph preallocates the native and Python contract scratch parents
before any fixture runs, and completes source-limit fixtures before controller
custody capture. Contract goldens may still run in parallel within their
existing scratch parents, but cannot add siblings to a recorded tool's cache
ancestor during revalidation. All ancestor metadata checks remain enforced.
Reader fixtures stage a single-link private copy of real Git and its real ELF
interpreter, relocating only `PT_INTERP` while preserving Git's loaded code and
bundled-library search paths. This gives both system and bundled Git an actual
owned runtime dependency for physical mutation tests without changing system
libraries, weakening tool-file policy, or dropping any refusal case.
Complete local fixtures also stage a byte-identical private copy of genuine
Python before capturing tool, ELF-runtime and standard-library custody. System
Python may have multiple hard links, which retained native post-run tools forbid.
The regression keeps that refusal and verifies the staged executable's bytes,
execution and unchanged standard-library path; it never changes system files.
The relocated-tool and Python-free current-reader fixtures use the same private
Git setup. Placeholder roles use the existing compiled native command fixture
rather than assuming `/usr/bin/true` is ELF (some distributions install it as a
coreutils script). The handoff command-contract fixture also uses this executable
as its selected Zig stand-in: it accepts only the closed validator-build argv,
returns no output, and does not claim an actual compiler build. Genuine validator
builds remain separately qualified. Physical fault-parity fixtures use the same
compiled executable for retained same-byte replacement and pre-spawn refusal;
neither case assumes a distro `true` is ELF. Their copied executable is bounded
by the unchanged 64 MiB tool limit rather than a distro-specific small file size.
The controller test runner omits debug sections because it is itself pinned as
a supervisor under that limit; Debug safety checks and all frozen test
declarations remain unchanged.
The relocated producer-import fixture uses the genuine native controller in
its installable ReleaseSafe profile, including its imported modules, even when
the test runner uses Debug. Its supervisor must fit the separate unchanged
16 MiB import-runtime bound; stripping a Debug CLI alone is insufficient.
ReleaseSafe controllers and the forced ReleaseSafe import fixture omit debug
sections so the candidate/public-product implementation fits that unchanged
bound on the host CPU as well as the portable target. The relocated-tool test
measures the actual supervisor before binding and reports any excess directly.
Other CLI fixtures and native test modules retain the selected optimization
profile. ReleaseSafe reuses the existing CLI artifact; Debug adds one genuine
ReleaseSafe CLI build, not a mock identity executable.
Read-only Python-v2 custody checks bind the complete recorded producer checkout,
not the newer reader's compiled source bytes, and recapture the original input
roles and physical identities unchanged. The production local-consumer probe
still requires its compiled producer source closure.
The direct controller runner forwards explicit runner arguments, so seeded
qualification uses `test-controller-direct -- --seed=0x6f59af14` (not just the
build runner's seed). `-Dtest-filter='trusted historical inner stage'` selects
the bounded complete-local fixture without changing the frozen declarations.
For diagnosis only, `-Dlocal-fixture-source=REVISION` selects one of its four
recorded producer vectors; the default qualification executes all four.
The Python `result_records` function remains an offline scanning oracle;
`accepted_result_records` and actual export use native acceptance. Historical
v1 local handoff inspection remains confined to the explicit legacy action. `records
--runtime` and `public-validator-build --runtime` remain native-produced
local-runtime gates.
The digest-pinned local-consumer custody probe admits both recorded v2
producer layouts without a refusal-triggered fallback.
The separately validated `command-public-validator-build.json` may appear in
Python-produced evidence after acceptance; it is not part of the 33 pinned
result records or the exported archive. Other extra evidence is refused.
Historical v1 retains its pinned-source compatibility path; native-produced v2
never falls back to Python after a native refusal. The caller must
independently authenticate the executable provided by `WAMR_CI_CONTROLLER`;
owner and mode checks alone do not prove its provenance. Protected paired boots
have exercised the completed native local-record replay and Python record
selection, with public-source publication and trusted import passing separately.
For a trusted v2 import, the native accepted-run records gate validates the
imported command bindings before Python applies archive and publication policy;
Python no longer reinterprets those imported command records. Trusted v1
imports with supervisor command records are fail-closed by the native
imported-stage gate and publication policy; pre-supervisor v1 imports keep
their historical no-supervisor behavior. Producer-direct publication retains
its existing Python command checks.
`handoff-inspect --runtime ABS --output ABS` is the native owner of the
non-legacy local handoff inspection, and `handoff-inspect-legacy --runtime
ABS --output ABS` owns the historical v1 output names
`private/handoff-inspect-legacy.log` and
`evidence/command-handoff-inspect-legacy.json`. They accept native-produced
v2 runtimes and Python-produced v2 runtimes through `handoff-inspect` only, or
synthetic/historical v1 runtimes through `handoff-inspect-legacy` only, when
the recorded supervisor, source and consumer custody can be recaptured. They
use the pinned package/EFI inputs and retain bounded private logs and command
records in a create-only owner-only output beneath an existing private parent
outside the runtime's pinned input ancestors. For Python-produced v2 runs the
command record names the actually running native controller as
`native:handoff-inspect-controller`; historical legacy inspection requires the
recorded `command-supervisor` role instead of an ambient compatibility
supervisor. The stages neither export an image nor fall back to Python after
refusal. `public-validator-build --runtime
ABS --output ABS` accepts native-produced local runtimes only, using the
recorded Zig tool and controller to build the fixed x86_64 validator in an
independent private output, retaining its bounded command evidence without
modifying the accepted runtime or publishing an archive. The production public
bundle path selects the native or Python owner solely from the recorded
`build-start.json` supervisor path; native-produced runs never fall back to
Python after a native refusal.
`supervisor-import-identity --stage-root ABS --supervisor ABS --git ABS
--output ABS` is a separate support-only operation for a clean, trusted
imported v2 inner stage. It checks the recorded supervisor source files
against the imported Git revision and the supplied executable and loader
closure against the imported consumer records, then supervises `--identity`
under the fixed plan. Its owner-only output is outside the imported stage and
checkout. Trusted v2 imports invoke this operation before writing
transport/candidate records; the default Python revalidation path reuses that
native identity instead of repeating the identity command through Python; the
protected native revalidation path also avoids a Python handoff between
validator build and execution. Python still owns publication policy and
legacy/producer-direct compatibility checks; native-produced local runs use
the native records, handoff-inspect, public-validator-build and
local-consumer-custody owners.
The controller's read-only `--identity` probe emits the unchanged supervisor
identity protocol using its embedded native source closure and the recorded
`command-supervisor-source-v1` hash recipe. It takes no runtime or extra
options and grants no acceptance or execution authority. Local export binds
every recorded tool before custody; a native-produced run without the
non-legacy supervisor record refuses rather than taking the Python path.
`local-handoff-revalidation --runtime ABS --output ABS` reopens the native
accepted run and public-validator build evidence, then supervises only the
fixed public validator and local handoff paths with the existing 600-second
deadline, bounded streams and cleanup proof. Its private diagnostic records
are outside the archive. Native-produced imports stay native-owned, but
portable downloaded imports and explicit same-runner imports have distinct
tool-authentication contexts. Neither launches an unsupervised Python
subprocess or falls back after refusal.
`import-validator-build --stage-root ABS --output ABS` is a support-only
trusted-v2 companion for a pristine imported stage. It accepts no caller
selected executable: it requires the current clean physical checkout to
match the imported revision, tree, and source-content commitment, and the
recorded Git and Zig executables, loader files, and Zig installation tree to
retain their imported consumer content. It supervises the fixed x86_64 direct-validator build in
a separate owner-only output and checks its ELF and bounded private command
evidence. A historical revision or unavailable recorded tool refuses this
operation. The standalone build command remains support-only. The protected
workflow's same-job trusted-v2 import passes the explicit
`import-public-source-bundle --native-import-revalidation` option to use the
combined `import-native-revalidation` operation so the validator is built and
retained through execution without a Python handoff between them.
`import-native-revalidation --stage-root ABS --output ABS` builds that fixed
direct validator and supervises its `handoff` verification in the same native
invocation for trusted v2 imports whose pristine stage matches the current
checkout and recorded tool custody. It constructs a private canonical
candidate outside the pristine imported stage by rebasing only the exact
artifact, boot, and evidence member paths already validated against the
imported portable bundle; neither the candidate nor the validator is a public
bundle member. The validator is retained from build through execution and its
exact success stdout, empty stderr, bounded log, and command binding are
checked before returning. A caller cannot select a validator or manifest. The
protected in-job import path invokes this strict native operation only when the
explicit handoff option is present, before writing
transport or candidate records; native refusal fails the import with no Python
fallback. Default Python-produced
trusted-v2 imports (including the documented off-runner operator flow),
historical v2 revisions, unavailable recorded-tool imports, and
Python-produced producer-direct revalidation remain Python-owned because
they either need
the caller-supplied validator or do not satisfy the pristine same-revision
trusted-stage preconditions. Native-produced production imports bind the
recorded controller identity and direct validator built by
`public-validator-build --runtime` in that explicit same-runner lane.

Default native-produced downloads instead invoke
`import-handoff-revalidation --stage-root ABS --git ABS --supervisor ABS
--validator ABS --output ABS`. This closed trusted-inner-ZIP owner authenticates
the explicitly supplied local native supervisor by producer content/runtime
commitments and the exact Git source tree. The local controller must have the
same authenticated native executable content; the validator must match the
native owner's build-derived direct-validator digest, not a caller-provided
claim or an identity string emitted by an untrusted executable. The build
graph obtains that digest from the existing direct-validator artifact and
includes its tracked source inputs in the native source closure.
Source and destination tool paths, inodes and timestamps need not agree.
Producer filesystem identities remain observations of the producer context:
portable import neither opens the producer's Git/Zig paths nor compares local
filesystem metadata to their recorded metadata. Native ownership retains
local executable and loader pins and local clean source snapshots before and
after supervised validation. A fresh portable checkout need not contain the
producer's generated output roots; present ignored outputs still use the
existing closed role allowlist and bounds. Source/tool substitution or mutation refuses;
the same-runner option cannot weaken these checks or select Python fallback.

The explicit `import-handoff-revalidation` operation also accepts an already
validated historical v1 inner stage. Its four-mode member rebasing uses the
same typed `AcceptedRun` and unchanged historical source/tree exceptions.
Because those records predate supervisor custody, this read-only path requires
the supplied supervisor to match the current native owner and the supplied
validator to match its build-derived validator digest. The current reader
checkout must be clean, match the owner's embedded tracked source closure,
and remain unchanged throughout bounded native supervision. It is not required
to masquerade as the historical producer checkout. No v1 build, boot,
validator-build, profile admission, or Python fallback is enabled.
The historical archive/operator router now selects this native read-only
operation before writing candidate records, using the current native supervisor
and its build-derived validator. Its independent Python publication-record
oracle and final publication barriers remain. The standalone supervisor's
historical identity contract remains available; this route does not execute it
or retire the Python controller.

The separate native `accepted_run.PrivateBundle` owns an actual private
`bundle.json`, not a fabricated public-source envelope. It validates the existing
absolute-root v1/v2 contract and all selected bytes, retains the original
manifest descriptor, and authenticates the current native reader, Git,
supervisor, validator and runtime closure before and after use. Historical
v1 source/tree identities and v2 producer source maps are checked against Git
objects independently of the current reader checkout. The owner retains those
claims and repeats their Git proof at every recheck. Inspection diagnostics outside the selected
evidence list are not acceptance evidence. Private views cannot serialize as
trusted-inner-ZIP records; `import_validator_build.runPrivate` accepts the
authenticated owner and supervises its real manifest. The bounded private
product commands below consume these owners; they do not enable v1 production,
public archive construction, import/transport, candidate products or authority.
Temporary Git source-proof output buffers are freed on success and refusal;
the owner retains its source claims rather than copies of the historical blobs.

`reader-source-closure --git ABS --output sha256-v1` checks the current native
reader's embedded source inputs against a clean, unchanged Git checkout. It
does not physically read `run.py`. The separate `supervisor-source-closure`
query and historical source-name/Git-blob admission sets remain unchanged for
the standalone supervisor and archived producers. Adding the private contract
dependency preserves both prior native source-name sets.

`local-consumer-custody --runtime ABS --expected-build-start-sha256 HEX
--expected-boot-inputs-sha256 HEX` is the production owner for a completed
v2 runtime's local checkout/source and build/boot consumer-input
custody *before* the managed QEMU loader is removed. The public source-bundle
path hashes the exact `build-start.json` and `boot-inputs.json` bytes it read,
passes those digests into the native owner, and reuses the same proof on later
validator-build/export postchecks; Python no longer reinterprets the same
source/consumer records or falls back after native refusal. The command compares
the clean current checkout's full physical source custody and both recorded
build/boot consumer sets against fresh native captures, including exact
executable loader roles, the recorded `tool:python3` stdlib tree, input tree
contents and physical ancestry. It emits no public or acceptance record and does
not replace Python's dependency, supervisor, packaging, validator-build command,
or production policy checks. An extracted historical archive cannot satisfy this
local proof after the original consumer files or loader are removed.

## Native controller preparation (unpublished build path)

`zig build --build-file support/build/wamr-native-ci/build.zig test-controller`
runs the native controller foundation's CLI/profile, canonical-record,
source-closure and refusal fixtures. Build the portable executable with
`-Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v2 -Doptimize=ReleaseSafe`. To place
only that executable in an existing canonical, owner-only `0700` runtime,
invoke `install-controller` with `-Dcontroller-runtime=/absolute/runtime`.
Installation creates `controller/bin/uk-wamr-native-ci` (private `0700` path
and ELF) and refuses any preexisting slot; it does not install over a prior
controller. The controller is always compiled for GNU/x86_64_v2, independent
of the other package artifacts; `install-controller` additionally requires
the explicit GNU/v2 and `ReleaseSafe` flags and refuses musl, v3, or an
unspecified target before creating a slot. `describe --output json-v1`
reports that fixed target and the embedded source-content closure without
accessing a runtime or granting boot authority.

The protected native-compute workflow installs this same portable controller
from the checked-out source after pinned Zig setup at
`/d/wamr-ci/wamr-native-runtime/controller/bin/uk-wamr-native-ci`. That
path is the production build/boot/diagnostics controller; the workflow obtains
the recorded executable target from native
`describe --output json-v1` instead of importing `run.py`. Native fault jobs
install the same controller at the same runtime-relative path. There is no
Python controller replay or orchestration fallback.

The native custody library now exposes clean Git tracked-object/physical
source and ignored-output checks, fixed-revision create-only WAMR archive
sealing, Bison and consumer-input-v2 file/tree/ELF-runtime custody, and pinned
Miz dependency-v1 custody. It reuses the Hyper-V no-follow private-file and
supervised-command primitives; archive stdout first enters a sealed,
non-growing sparse memfd, then is copied in bounded chunks to the private
create-only file and reopened for verification. Limits include 40,000
tracked entries/2 GiB (256 MiB per file), 131,072 ignored entries/8 GiB
(512 MiB per file, 8 MiB Git inventory), 100,000 input-tree entries/2 GiB,
512 Bison entries/8 MiB, and 128 dependency roots/16,384 entries/256 MiB.
Custody checks bind content hashes and stable physical metadata before and
after use; only the four fixed output roles may be ignored. Bounded diagnostics
and refusal never grant acceptance.

`input_custody.executableRuntimePathsWithOptions(allocator, io, executable,
RuntimeInventoryOptions)` adds an optional borrowed atomic cancellation flag
to the existing closed native ELF inventory. The original three-argument
`executableRuntimePaths` retains its default behavior and sorted canonical
loader/library paths. Both entrypoints use the same retained native loader,
`loader --list executable`, root cwd, and closed `LC_ALL=C` environment,
30-second primary/10-second later cleanup deadlines, 1-MiB stdout/4096-byte
stderr bounds, 256-path limit and physical identity checks. No tool allowlist,
reader source-name policy, controller CLI or caller is changed.

Cancellation is checked around ELF reads, loader/path resolution, identity
work and final sorting, and passed directly to the shared native process
owner during inventory. `error.Cancelled` never carries a partial closure.
For a spawned cancellation it requires proven complete native tree cleanup;
an unproved cleanup remains `error.RuntimeInventoryRefused` and preserves the
process owner's irreversible poison. Subsequent supervised work still refuses
with `error.UnresolvedCleanup`. Other native failures retain their existing
refusal classification rather than becoming cancellation because the flag
was set later.

An optional initially empty `RuntimeInventoryEvidence` receives the owned
private `CommandResult` on success or refusal, including partial output,
executable identity, cancellation, stream/descendant/cleanup/reap observations
and timestamps. Cancellation before spawning leaves `command=null`.
Post-inventory cancellation can retain a successful native command but still
refuses the closure. Call `evidence.deinit(allocator)` before reuse; evidence
is not a public record and does not authorize publication. The focused
`test-controller-direct -Dtest-filter="native ELF runtime"` cases use genuine
ELFs and loaders, kernel FIFO-open synchronization (no timed sleeps), native
cleanup-proof fault injection, and real executable/loader replacement,
hardlink and byte mutations.

The build path now supervises a closed
adapter/local-boot/fixtures/prepare/config/native-image sequence directly
through the shared Hyper-V process supervisor. It freezes installed native
producer/validator/fixture identities in `build-start.json`, checks the pinned
tiny artifacts and image before publishing `build.json`, and retains bounded
private command logs and create-only public command records. The local-boot
installer has its own precreated `compute/local-boot-tools` slot so it cannot
mutate the already frozen `compute/tools/bin` consumer-input directory.
Both installer command records precede `build-start.json`, which baselines
the post-installation consumer inputs in the same order as the Python controller.
Native boot reopens `build-start.json` and `build.json` with the 4-MiB
evidence-record limit, not the 256-MiB tracked-source-file bound; physical
custody of larger executables remains independently bounded.
`test-controller` exercises native custody, build-command failures, production
boundaries, tamper/refusal, and `run.py` differential record fixtures. Its
historical v1 inner-stage fixture exercises real native portable revalidation
and refuses substituted supervisors/validators, dirty readers, and clean
readers with mismatched embedded source before reserving output. The
installed fixture stage itself supervises bounded native success, nonzero,
partial-output, signal, overflow, timeout, and cancellation children; its
create-only private report binds the observed output hashes and cleanup states,
and the build gate verifies every required result. Each stream is capped at
4 MiB; the independent native-result transport permits up to 12 MiB so the
full allowed 8 MiB combined output is encoded without truncation. The
production adapter's `test-unit` runs the package command boundary and
log-validator CLI, without cold-compiling and repeating the controller and
source-limit suites already exercised by the mandatory fixture gate.
Those suites remain in `test-controller` and aggregate `test`; all fixture
cases and the original CI deadlines remain unchanged.
`test-controller` additionally checks invalid
installer build flags, which can restore `zig-pkg` in the source tree; that
test runs in a separate clean worktree in the protected gate, never during
the supervised production adapter build. Custody link and depth fixtures use
the selected cache even when production sets `ZIG_LOCAL_CACHE_DIR` outside
the checkout.
The protected x86 job exercises `test-controller-limits` and then
`test-controller` in the same retained clean worktree, keeping test dependencies
and cache outside the production source checkout; this reports fixture failures
without exposing private supervised-command output. On failure it runs the
host test binary directly for diagnostic errors while keeping the original
gate failed. The Python
`tests/source_custody_production_limits.py` remains paired with the native
limit fixture while production `build` uses the installed native controller.

`build --runtime ABS --wamr-source ABS`, `boot --runtime ABS`, and
`diagnostics --runtime ABS` are available only through the installed
native controller. Native stage failures report only a static Zig error name
alongside the failed stage; dependency restoration also reports a static
operation label. Command output and private paths remain in bounded private
logs. Production workflow callers use the same installed controller path for
build, boot and diagnostics; there is no fallback to `run.py` after a native
refusal and no change in cloud authority. The closed
`tiny_exact_v2` production type has six ordered raw/QCOW2/VPC modes;
the four-mode v1 type is read-only compatibility. No caller-selectable profile,
CoreMark mode, Azure entry, or alternate validator is installed.
The v2 result reader requires all 33 closed earlier records, including every
supervised build/package/image/boot stage; historical v1 remains read-only
and retains its pre-supervisor compatibility.

Refs #156. `wamr-native-compute.yaml` is an **additive ordinary
`pull_request` job**, including the native integration's stacked base.
It has only `contents: read`, a GitHub-hosted Ubuntu 24.04 x86 runner, no
protected environment, no dispatch, no cloud identity and no deployment
entry. Its only uploads are the bounded Actions artifacts described below.
All existing required contexts, default images and safety gates stay
unchanged. This does not complete #88's guarded Azure authority or image handoff.

The job builds the distinct `hyperv-x86_64-efi-wamr` target using the
adapter-installed app-owned `uk-wamr-aot-build` executable, pinned WAMR
`a53205d77be3b880eb8f8b96679512ba58e2331a`, Zig 0.16.0, the existing LLVM
distribution and the native final-image graph. Its constructor/returning-IRQ,
SMP, relocation and EFI checks are not replaced, mocked or disabled.
There is no guest compiler or hosted-runtime substitute. Only the tiny
answer/growth/trap/native-memory-selftest mode is enabled; CoreMark, native
benchmarks and JIT workloads are deliberately separate.

Bison data is materialized by the same authenticated package acquisition
used by the existing QEMU candidate workflow, including the exact installed
executable comparison. Native Make uses that private copy, not writable
runner `/usr/share` data. Its complete regular-file contents are bound before
and after use, capped at 512 entries and 8 MiB; the published record contains
only the aggregate digest, file count and byte count.
Boot revalidation addresses the fixed private runtime input directly after
the managed credential boundary clears the environment; it does not forward
build variables through that boundary. Build admission separately requires
the configured Bison directory to match that bound input.

## Why this adapter exists

The existing `public_image` **engine** binds the hardware application's
`main returned 2` and its hardware/network log contract. Passing a different
`--expect` does not make that engine compute-compatible. This adapter does
not change those semantics or spoof unavailable-storage markers:

* `wamr-ci-package` imports the existing pinned native miz packaging,
  structural inspection, immutable private-file and supervised packaging-worker
  primitives. It produces the existing deterministic 66-MiB GPT raw disk
  and complete 66-MiB-plus-footer fixed VHD. Separate native miz builds must
  agree on the complete raw prefix; the existing fixed-VHD validator checks
  EFI bytes, ESP, geometry and footer. `inspect` physically reopens and
  rehashes them, checks the supervised worker records and refuses partial state.
  Its additive compute-only `finalize-qcow2` and `derive-fixed-vhd` operations
  accept canonical typed intents, retain exact source identity, and run native
  Miz conversion in dedicated bounded workers. They publish create-only
  `unikraft.qcow2`/`qcow2-finalization.json` and
  `unikraft-derived.vhd`/`fixed-vhd-derivation.json` pairs. The QCOW2 record
  binds decoded raw/GPT/ESP/workload identity and native-zstd/64-KiB settings;
  the VHD record binds the exact QCOW2 digest, complete footer, partition
  identity and allowed GPT relocation only. Failure supervision distinguishes
  refusal from partial publication and rolls owned outputs back before
  reporting refusal.
* The existing installed `uk-hyperv-local-boot` runs six fresh one-CPU
  attempts: raw, finalized standalone native-zstd/64-KiB QCOW2 and derived
  fixed VHD, each with x2APIC and masked x2APIC. Derivation is admitted only
  after both retained QCOW2 boots and all preceding custody are reopened and
  accepted. Each uses the **exact read-only image**, a genuine QCOW2 or VPC
  opening as appropriate, private OVMF variables, no NIC and return **0**. Its
  crash, ordered startup/terminal, exact-input, bounded serial and process
  cleanup checks remain mandatory.
* The existing pinned-QEMU acquisition and managed libfdt/KVM runtime owner
  are reused. Its only extension selects a fixed compute driver for the
  new job. Only the ordinary-user process tree receives the existing KVM
  group; capabilities are dropped and no-new-privileges is required.
  No device permissions, shared group database or udev rules are changed.
  Missing x86/KVM/OVMF/tools fails; there is no successful skip or TCG fallback.
* `run.py` then checks physical request/report/raw-log bindings, the correct
  legacy-APIC observation, and an exact ordered completion line rather than
  a substring or request echo. The app-owned checker independently requires
  answer 42, both checks (native selftest plus growth/trap), unreachable
  outcome and zero owned teardown accounting. Hardware/network and optional
  WASI records are forbidden.

The source must be clean and committed before building. The source record
independently hashes every tracked blob/symlink target against its Git object
ID and binds every tracked parent directory's device/inode/type, ownership,
links, size, mtime and ctime. Its bounded summary records file, directory and
byte counts plus content and physical SHA256 values. Native rechecks compare
these source fields by value, including independently allocated Git
object-format strings, while still rejecting changed hashes, counts, revisions
and excluded-output roles. The only role-excluded output roots are exactly
`.d`, the fail-closed precreated `.zig-cache`,
`support/apps/wamr-aot/build`, and the precreated
`support/apps/wamr-aot/.config`. `.d` alone may already contain the workflow's
pinned WAMR checkout and acquired runtime; those consumed inputs are separately
content- and physical-identity-bound by the source archive, tool, Bison,
firmware, QEMU and package records. The other three roots must not preexist and
are created by the adapter before custody. Every custody check uses normalized
repository-relative path components, not string prefixes, to reject all
ignored entries outside those exact roots, including sibling names. It then
walks every allowed root without following links and rejects escaping links,
symlink cycles (including where non-strict Python resolution permits them),
hard-linked or nonregular files, unsafe root/directory ownership or modes, path
or depth excess, and changes during inspection. Regular-file modes remain
physical metadata and are separately enforced for every consumed dependency or
tool input. Python bytecode is disabled. The same physical/content snapshots
are required immediately before and after each build/boot consumer and again
at inspection/handoff. This detects accidental mutation and mutation that
persists across an observation boundary; it is not continuous isolation from
a hostile same-UID process between those checks.

Ignored output links into tracked source retain their no-follow metadata and
target-byte checks. Each ignored-output scan freshly proves Git index membership
in bounded batches of at most 64 ordinary links, rejecting missing, unexpected,
duplicate or partially matched results. Names containing Git pathspec syntax
retain the original single-path check and refusals. No membership proof is reused
across scans or replaces a build, boot or handoff revalidation boundary.
The original link and parent descriptors remain owned until the Git query and
terminal named-descriptor/path checks finish; pending batches drain before each
directory's final metadata check. Failed queries release all owned descriptors.

`build-start.json` now carries
`uk.wamr.consumer-input-custody` version 2. It inventories each selected host
tool and dynamic runtime object plus the bounded Zig, LLVM,
Python-standard-library and authenticated Bison data trees. The selected tools
include the exact indirect shell/coreutils executables used by the native build
graph (`dash`, `cp`, `env`, `mkdir`, `readlink` and `uname`) rather than
unrelated `/usr/bin` members. Selected executable invocations use retained
descriptor paths for Zig, Python, compiler/binutils and the recorded helper
tools. Only the pinned Zig and five LLVM executable roles admit up to the
existing 256 MiB process-executable limit under no-follow, owner, mode and
single-link checks; other retained tools keep their generic 64 MiB limit.
Data trees, package paths and other pathname inputs remain path-based and are
protected by their physical/content snapshots immediately before and after
consumption; custody does not claim arbitrary pathname data is read through
retained descriptors. The post-processing graph uses the objcopy
interface for descriptor-safe stripping. The hosted workflow first materializes the pinned Zig distribution
create-only beneath the owned ignored `.d` tool root, avoiding mutable
runner-managed ancestor directories. Native Make's unused Wget version probe is disabled by a fixed
offline build-contract value. Every record binds device/inode,
type/mode, uid/gid, link count, size, nanosecond mtime/ctime and content
identity, with deduplicated absolute directory-component identities. The
pinned tree scanner refuses on the first excess entry before sorting and
separately bounds all unique regular-file bytes hashed through symlinks.
Dangling input-tree links are accepted only when their retained deepest
existing target ancestor is root-owned and cannot be modified by the build
principal and their absolute resolved target has at most 64 components; the
missing suffix and ancestor identity are part of the record.
The pinned WAMR checkout is consumed only while creating a fixed-revision Git
archive through retained repository and Git descriptors; all later WAMR build
steps use the create-only archived object by its recorded pathname. Top-level
build-tool executables use retained no-follow descriptors and closed adapter
variables, while `PATH` is restricted to the root-owned system directory
containing the separately recorded indirect executables. Tool/data and
Miz-tree lookups are physically revalidated
immediately before and after each consumer and fully rehashed at final
inspection and export. Consumer subprocesses use adapter-owned
cache/configuration paths; ambient loader, shell-startup, Python, Make and Zig
injection variables are not inherited.

Before the clean source baseline is taken, the historical Python reference
restores the exact
out-of-tree dependency tree and builds the internal
`wamr-ci-supervisor` from `supervisor.build.zig`. The bootstrap inputs and the
supervisor's exact tracked source closure are checked before and after that
build. The native production controller supervises commands directly through
the shared process library and records its own embedded source closure.
Both supervisor implementations and the public validator use the fixed
`-Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v2` target with `ReleaseSafe`, not the
runner's native microarchitecture. The validator's supervised command contract
binds these exact flags; the supervisor's source closure binds the bootstrap
selection. Rebuilding the same sources with the pinned Zig compiler and those
flags therefore does not require the original runner CPU. Executing the tools
still requires an x86-64 host with v2 support. Native offline fixture builds
below remain host-native, including on aarch64.
`build-start.json` then embeds `uk.wamr.command-supervisor` version 1:
the fixed protocol version plus independently recomputed source and runtime
maps, each with actual file/byte counts and content/physical closure SHA256
values. The runtime map includes the supervisor ELF and its dynamic runtime;
the ELF is also a normal version-2 consumer input. Current-custody checks,
final handoff and public export recompute the same maps rather than trusting
copied pins.
The package, publication and six boot work directories are empty private
slots created before that final custody baseline, so later outputs do not
change a recorded supervisor/tool ancestor directory.

The compute conversion primitives do not reinterpret the four legacy
version-1 boots or stored preparation state. In particular, fixed-VHD
derivation takes an exact expected QCOW2 SHA-256 and capacity, not a JSON
boot-success assertion. The version-2 orchestrator invokes it only after the
exact QCOW2 acceptance record is complete, then binds the two derived-VHD
boots and final inspection without granting Azure authority.

Bootstrap execution is an explicit call-site capability, not a global
fallback. Its closed exact-stage allowlist is `dependency-restore`,
`supervisor-build`, and `dependency-hash-000` through
`dependency-hash-127` (the already bounded package-root maximum); there is no
prefix or glob match. The adapter ignores `WAMR_CI_SUPERVISOR` when loading
production orchestration. Every other build, packaging, boot, inspection,
handoff, validator, import/export and publication command refuses while the
custodied supervisor is unbound or unavailable.

Every later trusted WAMR command is launched by that retained native ELF using
the merged `Executable`, `CommandRequest` and `CommandResult` contract. The
request supplies an explicit retained ELF, fixed argv, closed environment,
cwd, one absolute primary deadline, a separately fixed cleanup deadline and
bounded output/result limits. Direct scripts name the retained Python or Bash
ELF explicitly; there is no shebang or ambient interpreter selection.
The prepare, configuration and native-image stages instead bind the installed
`native:wamr-aot-build` role as both command and native executable, with no
interpreter. The old Python producers and their differential tests have been removed.
The adapter also installs the app-owned `uk-wamr-log-validate` from the
shared validator source, records its physical executable identity as
`native:wamr-log-validate`, and revalidates the consumer input. Dispatched
`log-validator-x2apic`/`log-validator-legacy` supervisor contracts pin
the exact `tiny --log ... --identity ... --legacy-apic forbidden|required
--output json-v1` argv, empty environment, executable identity, timeout
and output bound. The same strict stage policy normalizes and validates the
actual supervised request: fixture runs prove both APIC modes with an empty
child environment, exact JSON output and fail-closed wrong-APIC refusal.
Every successful tiny boot is checked through one of these stages (including
physical revalidation), with the raw serial count/SHA-256 checked against
the unchanged boot report before and after invocation. The exact JSON-v1
`compute` object retains the existing evidence shape; the executable and
identity/log inputs are reopened and checked for changes. The supervised
diagnostic stays private; it is not extra public acceptance evidence.
Adapter and direct native CLI fixtures exercise synthetic records only;
the CLI result cannot replace boot/image or acceptance evidence. The
Python log validators and fallback paths have been removed.
There is no production fallback, PATH lookup or sibling executable discovery.
The adapter supplies a fresh private application output root and a sealed
`--source-archive` for `prepare`; `verify` is enforced by Make with the
installed `APPWAMRAOT_TOOL`. The native `olddefconfig` retains the solved
`build/.config`, and `native-images` publishes schema-1
`build/image-identity.json` only after a complete clean-source image build.
The schema-1 artifact identity, exact source-file manifest, image hashes,
command arrays and permission contract remain unchanged except that
`prepare_source_sha256` now identifies tracked `build-tool-prepare.zig`.
Private state directories are `0700`, identity/config/diagnostic files
are `0600`, and any failed or partial build is a refusal, never a boot,
cloud, or workload-acceptance result. The installed native producer's
golden/fault/integration tests are `zig build --build-file
support/apps/wamr-aot/build.zig test-unit test-integration`; Azure
admission, broader workload validation and final `run.py` removal remain
separate follow-up slices, not producer-side fallbacks.
Recorded indirect executable variables are replaced inside the supervisor by
paths to its retained descriptors. The reviewed self-reexecuting package and
local-boot tools ignore inherited retained-self values unless the original
path binds their current `argv[0]`. The exact recorded Zig installation tree
supplies `ZIG_LIB_DIR`; direct Zig commands also bind a separately opened
retained executable descriptor. A private supervisor launcher mode replaces
its own sealed snapshot with that descriptor before Zig starts, so Zig can
find its standard library and re-execute its integrated linker without an
ambient path. Canonical native results bind the supervisor launcher identity
and the retained Zig identity and report primary outcome, stream status,
descendant observations, cleanup outcome, poison state, and monotonic
start/primary-completion/final-completion times. Those timestamps are
u64 values ordered against the one original primary deadline and the later
cleanup deadline; elapsed values are differences of those absolute samples,
so cleanup cannot reset the clock. A timeout completion is at or after the
absolute primary deadline (equality is timeout), while every non-timeout
primary completion is strictly before it. Leader exit recognition samples
that boundary once and uses the same observation for primary completion, so
preemption between the preceding deadline check and exit observation cannot
produce late success. An overflow stream contains exactly
its configured capture limit; the other stream may be shorter, including when
both streams were eligible to overflow. A complete spawned-command cleanup
has at least one primary-monitor event and the five cleanup events guaranteed
by the TERM/KILL/final-exit state-machine path. Before `execveat`, a
close-on-exec sequenced socket gate holds the forked child after its raw
PDEATHSIG, process-group, cwd, stdio and descriptor setup. The parent retains
the original deadline while it opens and validates the child's pidfd/start
identity, transfers the leader into the tracker, receives the child's ready
token and sends exactly one release token. EOF, a malformed/short token or any
tracking, clock, deadline, cancellation or release failure closes the gate,
reaps the still-unexecuted leader through its pidfd and requires final ECHILD.
As soon as the spawned leader exists, an unwind guard follows it through
pidfd acquisition and tracker ownership and records whether the gate was
released and whether normal tree cleanup completed. Any later error therefore
recovers the gated leader before release or runs full tracked-tree cleanup
after release; cleanup proof failure is retained as irreversible supervisor
poison without replacing the primary command failure.
A proved pre-release recovery is `cleanup=complete`, unpoisoned, with no
primary-monitor events, empty complete streams, no descendants, two reap
events (leader plus ECHILD) and at least four cleanup events. The minimum is
shared by the native producer and adapter through `process-command-v1.json`.
An unavailable identity, reap or ECHILD proof poisons the supervisor even if best-effort
termination succeeds. Pre-spawn `not_required` results remain limited to
timeout, cancellation, local spawn/snapshot I/O failure or unsupported
snapshot creation. They have empty complete streams and hashes, no
termination, descendants or events, identical primary/final completion, and
the unchanged executable identity. Timeout,
cancellation, overflow, nonzero/signal, exec/identity failure or any unproven
cleanup is a refusal; cleanup failure prevents publication even when the
leader exited zero.
Each supervised command record also binds hashes of the complete canonical
request, the canonical raw native request/result transports, and the
normalized native result, exact supervisor, command executable,
native executable and interpreter identities, ordered argv, closed explicit
environment, cwd, stage/schema versions, primary/cleanup deadlines and every
supervisor limit. A closed per-stage contract fixes the executable roles,
argv template, cwd role, environment allowlist, timeout, output limits and
successful result expectations. Every digest is recomputed from the retained
fields during creation, export, archive reopen and import; a syntactically
valid supplied digest or cross-stage relabel is not accepted. Separate stream
status/size/digests, a domain-separated aggregate commitment over both stream
byte counts and digests, the direct combined-output observation, termination,
descendant relationships and native-width event/reap counts remain bound.
SHA256(empty) is recomputed for empty streams. Nonempty raw command output
remains private, so its stream and combined digests are explicitly labelled
transport-authenticated observations rather than independently reproducible
claims.

Supervisor JSON is compact canonical UTF-8 with byte-sorted keys, exact
separators and one final LF. Python emits literal UTF-8 (`ensure_ascii=False`)
and hashes/sends those same bytes; escaped input is parsed but is not
canonical. Strings must be valid Unicode scalar sequences and native path
limits count UTF-8 bytes. Filesystem paths are not normalized: NFC and NFD
code-point sequences remain distinct paths and produce distinct digests.

Records also bind the Unikraft revision/tree, app-source hashes, pinned WAMR/compiler options,
actual tools, wasm/cwasm/compiler/library bytes, solved configuration,
entire EFI/debug ELF/bootinfo, native package producer, QEMU and OVMF,
complete raw/QCOW2/VHD/footer lineage, and each request/report/raw serial.
Inputs are reverified after the six boots and physical package reload. The final result
hashes earlier records only, **not itself**. These are local build/compute
observations, not authenticated source attestations or deployment receipts.

## Bounds and diagnostics

Writable build, package, firmware and boot slots are under the protected
CI job's private `/d/wamr-native-runtime` (or the local in-worktree runtime)
or the app's ignored `build/`. Zig's
source-pinned dependency restoration copies the exact Git-identified
local-boot manifests create-only into `compute/dependencies` before the clean
source baseline. Descriptor/Git-object checks bind those actual manifest
inputs, and the later full source baseline must still be clean and exact.
Before Zig runs it binds each copy's exact
device/inode/type, ownership, links, size, mtime and ctime plus the parent
directory metadata, and requires the same identities immediately afterward.
It also byte-compares the copies, parses the one exact Miz
URL/revision/package hash, and only then performs the bounded fetch. Before
reading package content it enumerates and snapshots the complete bounded
directory set, including `zig-pkg`, then requires the exact set and metadata
after traversal. The restored tree rejects links, nonregular entries, unsafe
names, extra/missing/duplicate roots and incomplete transitive manifests.
An upstream package's `.dependencies = .{}` has no transitive edges; the
source-pinned root manifest must still name exactly one Miz dependency.
Under its owner-only `0700` root, descriptor-relative native custody admits
and records upstream package file/directory modes (including `0777`) without
relaxing the general host-artifact policy. Zig 0.16
`fetch PATH` independently recomputes every package hash, including Miz rather
than trusting its directory name. `build-start.json` embeds
`uk.wamr.zig-dependency-custody` version 1: request and source/copy manifest
identities and restore-parent metadata, bounded restore diagnostics,
package/root/file/directory/byte counts, per-package
content/physical/manifests, and aggregate closure, physical, manifest,
hash-verification and root-metadata SHA256 values. Limits
are 128 roots, 16,384 entries, 256 MiB total, 64 MiB per file, depth 64 and
4 MiB per manifest. Restore-root, package-root, package-tree and directory
inventory scans enumerate at most the remaining budget plus the first excess
entry before sorting, and always close their iterators. Both builds use that
one tree through `--system`; it is
revalidated around every consumer and at final inspection/export. No
package-manager state is created below tracked source. The ignored-source
policy allows at most 131,072 entries, 8 GiB total regular-file/link bytes,
512 MiB per regular file, 1,024 UTF-8 bytes per repository-relative path and
64 path components. Its collapsed Git inventory is capped at 8 MiB before
parsing. Failure diagnostics use a separately terminated-and-drained 1-MiB Git
status capture, retain at most 128 ignored paths, and refuse immediately on the
129th repository-root entry before sorting the bounded collection.
The production command path uses the standard native subreaper/pidfd
supervisor. It discovers and reaps ordinary owned descendants after leader
success, including `setsid`, double-fork and closed-capture descendants.
Cleanup has its own absolute deadline and bounded scan/signal/reap budgets;
exhaustion or uncertain ownership poisons the one-shot supervisor result and
cannot become success. This is cleanup for cooperative or accidentally
detached owned descendants, not a hostile same-UID or PID-namespace ownership
claim. Git bootstrap/custody probes have a 120-second primary deadline and report
distinct static startup/monitor I/O, cleanup, stream, output-overflow, and stderr refusal
categories; raw Git output stays private. Repeated source-custody rechecks
release their per-call scratch rather than retaining whole-tree file bytes
in the controller's lifetime arena. Boot-stage rechecks also release the
temporary evidence, dependency, and tool-custody snapshots after each stage;
their accepted identities and pinned evidence remain in the lifetime arena.
Each recheck compares one fresh snapshot of each pinned source, dependency,
consumer input, and build record rather than capturing the same inputs again
while reconstructing the accepted build. Production consumer-input comparison
uses the freshly captured identities without repeating the full tree walk.
They run with
system/global configuration, hooks, repository fsmonitor helpers, credential
helpers, replacement objects, terminal prompts and pagers disabled where
applicable.
Build commands use `-j2`; the production and fault-matrix jobs each have a
180-minute ceiling and their paired KVM steps a 150-minute ceiling. Each build
command has an absolute deadline, 4-MiB limits per native stream and an
8-MiB combined private-log limit (one extra byte detects overflow), followed
by an independent ten-second supervisor cleanup deadline. The native packaging
worker retains its 120-second deadline and
independent two-second cleanup budget. Each native boot is limited to 60
seconds with the existing independent cleanup budget; the Actions job deadline
separately bounds orchestration and post-exit hashing without GNU `timeout`.
The empty private package output and six boot work directories are created
before boot-input custody, and the native packager accepts its slot only while
empty; later package and serial writes therefore keep the shared
compute-directory identity stable without allowing package reuse. An empty
publication container is reserved at the same time; validator, handoff and
archive-reopen outputs are later created only beneath it, so final export does
not mutate any recorded input ancestor.
Each attempt is create-only, with no resume, overwrite or automatic retry.

Raw build, runtime and bounded 4-MiB serial logs stay in private local slots.
The seven-day **metadata** Actions artifact includes only explicit `compute/evidence/*.json`:
build/content hashes, typed successful compute observations, native packaging
inspection, and allowlisted failure flags/byte counts/hashes. Diagnostics do
not copy paths, arbitrary exceptions, environment, raw serial or runtime/account
state. Command records also report only fixed, allowlisted error-name markers
observed in bounded output, not copied error messages or a diagnosis. A null
marker list means the capture exceeded the scan bound. A failed/missing boot
never creates `result.json`. Evidence collection
is diagnostic only and cannot turn failure into success.
Native config and image failures additionally report SHA-256 digests of
the compiled error name and, if a tool was rejected, its selected role.
An image-input refusal may also report a digest of the fixed guard stage.
No source text from these fields or child output is included in the metadata
artifact.

## Focused checks

From a checkout with Zig 0.16:

```sh
umask 077
mkdir -p .d/wamr-ci-check/{cache,global-cache/tmp,scratch,restore,out,fixtures}
export TMPDIR="$PWD/.d/wamr-ci-check/scratch"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.d/wamr-ci-check/global-cache"
cp support/tools/hyperv/local_boot/build.zig \
  support/tools/hyperv/local_boot/build.zig.zon .d/wamr-ci-check/restore/
zig build --build-file .d/wamr-ci-check/restore/build.zig --fetch=all \
  --cache-dir .d/wamr-ci-check/cache \
  --global-cache-dir .d/wamr-ci-check/global-cache -j2
zig build --build-file support/build/wamr-native-ci/build.zig \
  --system "$PWD/.d/wamr-ci-check/restore/zig-pkg" \
  --cache-dir .d/wamr-ci-check/cache --prefix "$PWD/.d/wamr-ci-check/out" \
  -Dtest-root="$PWD/.d/wamr-ci-check/fixtures" \
  -Doptimize=ReleaseSafe -j2 test install
SUPERVISOR_SOURCE_SHA256="$(
  "$PWD/.d/wamr-ci-check/out/bin/uk-wamr-native-ci" \
    supervisor-source-closure --git "$(command -v git)" --output sha256-v1
)"
zig build --build-file support/build/wamr-native-ci/supervisor.build.zig \
  --system "$PWD/.d/wamr-ci-check/restore/zig-pkg" \
  --cache-dir .d/wamr-ci-check/cache \
  --global-cache-dir .d/wamr-ci-check/global-cache \
  --prefix "$PWD/.d/wamr-ci-check/supervisor" \
  -Dsource-closure-sha256="$SUPERVISOR_SOURCE_SHA256" \
  -Doptimize=ReleaseSafe -j2 install
WAMR_CI_PACKAGE="$PWD/.d/wamr-ci-check/out/bin/wamr-ci-package" \
WAMR_CI_LOG_VALIDATE="$PWD/.d/wamr-ci-check/out/bin/uk-wamr-log-validate" \
WAMR_CI_SUPERVISOR="$PWD/.d/wamr-ci-check/supervisor/bin/wamr-ci-supervisor" \
WAMR_CI_SUPERVISOR_FIXTURE="$PWD/.d/wamr-ci-check/out/bin/wamr-ci-supervisor-fixture" \
  python3 -m unittest discover -s support/build/wamr-native-ci/tests -v
```

`test` is the protected aggregate and requires `-Dtest-root`; `test-pipeline`
runs the real conversion fixtures and two independently isolated private
six-mode synthetic boot-proof fixtures with the same requirement.
`test-unit` runs the package command boundary and log-validator CLI tests only;
it does not repeat the controller/source-limit suites or run the real package
conversion pipeline. The protected controller gate and aggregate `test`
retain those controller/source-limit cases.

The Zig fixtures additionally run real raw-to-native-zstd-QCOW2 and
exact-QCOW2-to-fixed-VHD workers, reopen both artifacts, validate byte/content
identity and exercise a hard-deadline refusal with rollback and typed
supervision. The six-mode fixture invokes the actual package and validator
CLIs, uses the production boot report/image checks and acceptance gates over
those real package bytes, then reopens all six reports and the final physical
image chain. Only the native validator invocation uses the supervised adapter
in these fixtures, with an empty request environment and private record. The
16 public `command-*.json` records are explicitly synthetic fixture-only
inputs, not attestations of supervised build/boot commands. One fixture
publishes and parses a canonical `result.json` only after final inspection,
checks all 33 earlier record hashes against physical file bytes, asserts no
result self-hash, and checks exact physical directory membership.
The other fixture independently mutates the last serial and the derived VHD
after final inspection, requiring both to refuse before `result.json`.
Both fixtures' local-boot request/report/serial inputs are expressly synthetic:
they do not launch QEMU, prove KVM, or run the full build/source custody.
An actual native six-guest success gate requires the protected production
x86/KVM CI worktree and runtime with the pinned tools, archive, QEMU and
firmware; these synthetic fixtures remain non-authoritative.
The Python fixtures use the actual native packaging helper and pinned miz
with a synthetic **nonbootable** PE, plus synthetic compute/log records.
They check full raw/QCOW2/VHD/footer hashes, physical reload,
mutation/partial-state/replay refusal, exact results, the six CLI
configurations, standard
descendant cleanup, timeout/overflow/nonzero/exec failures, cleanup poison,
canonical-result tamper, executable identity and the closed environment.
These are not
guest execution evidence. `WAMR_CI_PACKAGE` selects only that test executable;
the supervisor fixture is likewise test-only. Production orchestration has no
fixture, executable-override or skip switch.
ARM development can run these fixtures, but cannot qualify the guest.
Only a successful real x86 PR run of the corrected, committed native base
establishes the first local tiny-compute observation.

## Native-only qualification

`test-controller` now includes native source-custody production limits, twelve
physical Bison/consumer/dependency/supervision fault fixtures, frozen v1/v2
result-parser goldens, and the #187 handoff/public-bundle contract golden.
The handoff library also contains the private retained-copy primitive and
the non-resumable v2 export custody state machine; Python remains the production
publisher until the later cutover. Export consumes the controller's typed
accepted-run API and supervised handoff inspection, never a Python replay or
a second controller acceptance implementation. Native export produces only v2;
the literal historical v1 layouts remain read-only compatibility.
`test-controller-limits`, `test-controller-fault-parity`,
`test-differential-records`, and `test-handoff-contracts` run those suites separately.
The neutral v1/v2 fixture constructors in `tests/controller_record_fixtures.py`
remain available to #187/#189. `test_differential_parity.DeterministicContracts`
is only a compatibility import of their neutral byte tests, not a controller
comparison or an executable `local`/`full` harness. No acceptance is inferred
from these synthetic records. The handoff/public-bundle and authority oracles
remain in their owners until those migrations; `run.py` is not deleted here.

The credential-free KVM workflow runs the real native build and six-mode tiny
chain once, then reopens its accepted native records and exercises the existing
handoff/public-source import gates. The managed wrapper still requires an
ordinary user, accessible x86 KVM, credential clearing, capability drop and
no-new-privileges; missing capability fails, never skips or falls back to TCG.

The four required contexts retain their **legacy names**:
`wamr-differential-parity (build-start-tamper|missing-build|occupied-boot-slot|prior-build-output)`.
Their unchanged matrix job ID is a branch-protection compatibility constraint,
not a differential implementation. Each invokes `wamr-native-fault-ci.sh` and
`tests/native_fault_qualification.py`, which execute only the installed native
controller. The three boot faults first require a successful real native build;
then they mutate precisely the build-start revision, remove `build.json`, or
occupy the first boot slot. They require exit 1, empty stdout and the exact native
boot-platform cause (`BuildStartChanged`, `FileNotFound`, or `PriorOutput`).
The prior-output case requires the exact startup `PathAlreadyExists` failure.
Every case compares physical metadata and content before/after the refused
command, including retained records, outputs, tools and images, and forbids
`result.json`; prior-output also forbids `build.json`. Unexpected success, a
different failure, later publication, changed bytes or incomplete build fails
the gate. Renaming these required contexts needs a separate coordinator-owned
protection transition; this PR does not change protection.

Offline gate-driver tests run from the repository root with
`PYTHONPATH=support/build/wamr-native-ci/tests python3 -B -m unittest -q test_native_qualification`,
using a fresh owner-only `TMPDIR` outside the source. Native gates must likewise
use an absolute `--build-file`, fresh private caches and an explicit private
`-Dtest-root` for `test-pipeline`. Native test/fixture-runner coverage owns the
controller's six-mode order, records, custody, supervision, reap and poison
semantics; no Python controller reference decides those outcomes.

### Private export custody

The installed `uk-wamr-native-ci` provides two local-only product commands:

```sh
# Run export in the original accepted producer checkout before discarding it.
uk-wamr-native-ci private-export --runtime "$RUNTIME" --output "$FRESH_HANDOFF"
# Run validation in a clean checkout matching this reader's embedded closure.
uk-wamr-native-ci private-validate --stage-root "$FRESH_HANDOFF" \
  --git "$GIT" --supervisor "$NATIVE_CONTROLLER" \
  --validator "$DIRECT_VALIDATOR" --output "$FRESH_VALIDATION"
```

All paths are absolute, canonical and owner-private where required. Output
parents must already exist; both output directories are fresh, create-only and
non-resumable. Export reads the accepted local owner (native or read-only Python
producer), dispatches the frozen v1/v2 member tables and runs the original
retained package inspection before copying. Historical export without recorded
supervisor custody still refuses; a current reader never manufactures it.
V2 export requires the existing `GITHUB_REPOSITORY=cataggar/unikraft`,
`GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` identity inputs. V1 has no run/profile/
lineage fields and does not become a production profile.

Validation opens genuine root-bound `bundle.json` through `PrivateBundle`,
not `openImportedStage`, a public envelope, a raw validator bypass or Python.
The caller-supplied supervisor must match the running reader; the validator
must match the native build-derived direct-validator digest. Git, producer
revision/tree/source-map availability, reader source, retained executables and
ELF runtime loaders are authenticated and rechecked around the existing
bounded direct-validator adapter. That adapter preserves its fixed empty
environment, process limits, cancellation, descendant cleanup and poison
handling. The supplied supervisor is not an arbitrary runner.

Only complete success emits one stdout line:
`Private handoff exported; authority=not_admitted.` or
`Compute handoff revalidated; authority=not_admitted.` Refusal exits 1 with no
success stdout; invalid CLI usage exits 2. Export stderr includes the failed
phase and publication status, never evidence contents. Validation retains its
private logs/requests and `evidence/command-import-native-revalidation.json`.
Directory sync barriers and a retained private lock anchor bind its create-only
output. Catchable failures after reservation retain a best-effort
`private/failed-private-validation.json`; I/O failures or external termination
can prevent diagnostics, but existing partial state is never removed or adopted.
Neither a command record nor file existence substitutes for successful outer
source/custody rechecks and the command exit status.

These commands do **not** cut over the workflow or local production publisher.
`handoff.py` and `public_bundle.py`, all live witnesses and shared removal gates
remain unchanged. The executable imports the handoff owner above the controller
library; the controller does not acquire an export dependency. Its expanded
source-name closure retains the complete prior private-consumer name set for
historical source-map authentication.

Focused CLI coverage is included in the existing controller fixtures:

```sh
zig build test-controller-direct -Doptimize=ReleaseSafe \
  -Dtest-filter='private product CLI' \
  -Dtest-filter='trusted historical inner stage' --summary all
zig build test-handoff-contracts --summary all
```

Use the same private cache roots, genuine dynamic Git and complete pinned
`--system` dependency forest as the controller qualification described above.
The complete-local fixture exercises actual native CLI export, all 83 v2
members against the live Python export oracle, genuine private v1/v2 validator
processes, public-envelope absence, fully rehashed serial tampering, reuse
refusal and real file-size-limit write failures retaining non-resumable output.
It uses real historical Git objects and native image/package tools, but its
command/guest records are synthetic: it is not new managed-KVM, protected
archive or production-native-run qualification.

`handoff.export_state.run()` owns the complete attempt and releases its
descriptors, accepted-run arena and installed cancellation handler on every
exit. Its phase-token API borrows that same owner: call `deinit()` exactly once,
including after refusal, and do not use tokens afterwards or deinitialize an
active owner. Transitions serialize concurrent aliases. Copied tokens cannot
replay a consumed phase, manufacture a later phase, recover a failed attempt,
or republish a successful attempt.

Export reserves a fresh owner-private 0700 output outside the runtime.
An existing directory, file or symlink refuses; it is never adopted or
overwritten. Selected artifacts, boots and evidence are copied create-only as
0600 files. Original source files, their ancestors, file inputs, input-tree
roots, the inspection command record, output files and lock anchors remain
pinned until the attempt ends. Copies hash both sides, sync files and created
directories, reopen the created inode and compare custody snapshots including
gid. Accepted record, input, artifact, boot and cleanup identities are measured
on the exact retained descriptor returned to export, not a second pathname
open. Descriptor and ancestor revalidation also guard result/cleanup capture.
Destination reopening uses the shared nonblocking private-file opener, so a
FIFO substitution refuses instead of trapping cancellation behind a blocking
open. Publication barriers revalidate the accepted run, source pins, selected
source directories, exact output membership, sealed destination directories,
copied bytes and canonical root-bound manifest.

Export reuses `controller/custody_files.readRetained()` for same-descriptor
identity binding. The shared module retains its bounded nested canonicalization
workspace; input-tree reads do not add an immediate duplicate verification after
this helper. Independent alias, final directory/member and named publication
barrier revalidations remain separate; no observation is cached across barriers.

Completed native `records` replay, handoff inspection and validator builds run
inside the managed runtime, before its outer owner publishes
`evidence/runtime-cleanup.txt`. That export-only proof is not a prerequisite of
the controller's completed record view. Export's `AcceptedRunPinned` transition
must instead admit and retain the actual owner-private cleanup descriptor with
the exact successful literal, hash and metadata before reserving output.
Missing, failed or changed cleanup refuses; it is never optional at export,
manufactured by the controller, or adopted from an earlier failed attempt.

The manifest is staged and reopened as `private/export/handoff.json` before
validation. Bounded phase/failure journals and publication intent also stay in
that private directory, outside the frozen public member table. Cancellation,
mutation, I/O failure or lost custody irreversibly poison an attempt once
reservation has started. Partial files and private evidence are retained, not
automatically removed. A retry needs a new path after operator review; there is
no resume or retry-in-place.

`bundle.json` is the final create-only durable publication. Known failures
before publication leave no final bundle. The shared durable publisher
distinguishes `not_committed`, `publication_unknown`, `visible_not_durable`
and `durable`: a real post-link sync/cleanup failure may leave a visible file,
and even a durable commit can fail subsequent custody revalidation. Neither
case reports export success or permits reuse. Preserve the poisoned evidence;
never interpret file existence or the staged manifest as acceptance and never
unlink an ambiguous publication as an unsafe rollback.

`zig build --build-file handoff.build.zig test --summary all` and
`zig build test-handoff-contracts --summary all` exercise the complete export
transitions, retained ownership, descriptor cleanup, phase/copy/durability and
allocation faults, cancellation, swaps/symlinks/hardlinks and binary secret-scan
boundaries. Ancestor-directory ABA probes cover all five pin families; bounded
FIFO/SIGINT helpers verify irreversible poisoning, no bundle and descriptor
cleanup without hanging the runner.
Build-time oracle/result fixture paths are absolute for both package-directory
and repository-root `--build-file` invocations; retained-file validation is not
relaxed to accept relative paths. Qualification includes the protected aggregate
`test install` gate with `-Dtest-root`, isolated restored dependencies and
private fixture/cache roots outside the source under test, not just the
standalone handoff or controller selectors.
They invoke actual Python `handoff.export()` to compare all 83 selected v2
members, canonical manifests after local-root rebasing and accepted result
identity, and check Python reuse/I/O/producer-binding refusals. This complete
typed fixture is synthetic and nonbootable: controller acceptance and expensive
supervised build/boot/inspection boundaries are substituted only in tests.
Real record decoding, typed pinning, copy/hash, filesystem barriers and
publication execute. The fixture is not live guest/KVM or production controller
acceptance evidence and does not authorize production cutover or Azure.

### Historical reproducibility work retained after differential retirement

The former paired comparison required the following production reproducibility
properties. Its live runner and diagnostics have been removed; this history does
not describe a currently executable gate.
The different Python/native supervised build commands, controller closures,
local-boot installation paths, and native-only boot-input validator role are
checked against their own exact physical contracts; each QCOW2 acceptance
binds its own boot-input record rather than treating different hashes as equal.
Shared production executables are built without path-dependent debug sections
outside Debug mode so separately cached ReleaseSafe builds retain identical
bytes for strict paired tool and boot-input custody. The pinned upstream WAMR
compiler is also built with its supported `-Dstrip=true` option: otherwise its
debug sections change the compiler and generated runtime-identity bytes across
the two source roots, even when the compiled workload is identical.
The native static runtime archive is passed through the pinned LLVM objcopy
`--strip-debug` in a supervised, recorded producer command before publication;
its separately built ELF members otherwise retain checkout-dependent DWARF
strings and line tables. The single checked Zig object member is then extracted
and repacked by pinned `zig ar` under a stable basename: the original archive's
long-name table embeds the absolute, checkout-dependent Zig cache path. Symbols
and relocations required for linking remain.
The CI production build command and the paired differential build comparison
set `WAMR_CI_PORTABLE_CONFIG=1` for the native and Python controllers. The
native image builder forwards it to the root Zig facade,
which gives both Kconfig solvers the same inert defaults for `CONFIG_UK_BASE`
and `CONFIG_UK_APP`; Make still uses the actual checkout and application paths
for source discovery and compilation. Make also derives paired `HOSTUTC` from
the verified source commit's UTC timestamp, rather than embedding each
separately built image's wall-clock time in its loadable `.uk_libinfo`
section. Ordinary builds retain their path and build-time metadata defaults.
Portable C, C++, and assembly builds map the source checkout root to
`/wamr-ci/source` in DWARF without stripping the debug ELF; this keeps its
nonload debug sections comparable across worktrees.
For paired portable CI only, Zig-owned target objects omit their debug
sections: their generated wrapper modules otherwise record each worktree's
private `native-environment/zig_local_cache/o/` path. The final debug ELF
still retains the C and assembly DWARF; ordinary builds retain Zig target
debugging as well.
The paired comparison still requires identical raw `.config` bytes and
matching image hashes; it does not normalize either artifact.
Protected paired runs print only closed stage-start and stage-completion
labels to identify which of the four real controller invocations has exhausted
the bounded step deadline. Failed paired builds and boots report only per-side
exit classes, evidence and artifact names, and path-free refusal or static
native error markers. Artifact differences identify only the fixed role and
changed size, hash or mode field; a config hash mismatch is additionally marked
when rechecked config bytes differ only by the source-root path, without
normalizing acceptance. A changed build image record also identifies only
fixed config, input, tool or image-file roles, without exposing their values
or relaxing the byte comparison. A differing runtime identity is diagnosed
using only fixed artifact roles and whether its commands or other metadata
differ; the diagnostic first rechecks the original identity-file hash against
the build record. Differing EFI and debug images are likewise rehashed against
their build records before reporting only PE header/section or ELF
header/alloc/nonalloc section indices with allowlisted section names; byte
comparison remains strict. A changed `.debug_str` additionally reports only
fixed classes for differing strings (source-root, other-absolute, relative-path
or other), including fixed app build/source roles and whether replacing the checkout
roots solely for diagnosis would equalize the bytes or string sets. Raw DWARF
strings and private command logs remain local.
Image command arguments embedded in the build identity retain their actual
paths; paired comparison treats only the four reviewed app, config, Make
environment, and private tool path assignments as equivalent across roots,
after checking their physical roles. All other arguments remain strict. Once
both native-image stages and their pinned tool identities have been verified,
the selected `/proc/<pid>/fd/<fd>` descriptor used by the Python supervisor
and the corresponding pinned tool path used by the native supervisor compare
by their fixed tool role. Repeated occurrences of each role must still use
the same path within each command; without the verified stage, descriptor
paths remain strict. Other executable paths retain exact path or source-root
comparison. A remaining build-record
difference reports only fixed top-level and image
argument-position labels. Retained-output differences report only fixed
private, fixture, package, public-source or boot-slot roles and changed
membership, mode, type or size, never raw filenames or log contents.
Known package job/image and boot request/report/validator slots receive more
specific fixed-role size or membership labels; unknown files remain strict.
Differing selected image-command tool paths additionally report only their
fixed roles and path classes (retained descriptor, bound producer tool,
checkout/private root, other absolute path, or other), never path values.
At completed builds, the Python-only Zig and supervisor version logs must
match their pinned versions, its supervisor build log must be bounded and
free of known error markers, and its source-metadata diagnostic must be a
canonical, valid nonempty baseline. The native-only fixture report must
match the exact canonical seven-scenario contract already verified by the
native fixture stage. Only these reviewed, physically checked side-specific
files are removed from cross-controller retained membership comparison;
unreviewed retained outputs and shared slots remain strict.
When completed boots differ, comparison rehashes each QCOW2 acceptance's
own build, finalization, boot-input, boot request, report, serial, and compute
records before reporting only fixed mode/field labels. Changed finalization
and per-mode compute records likewise identify only reviewed nested field
roles. Finalization and derivation provenance are rechecked against each
side's canonical intent bytes (including the domain-separated config hash),
the pinned package tool, and the corresponding source-image commitment;
unreviewed intent fields remain strict after normalizing verified source
roots. Each differing raw serial is independently rehashed against its
report. At completed paired boots, cross-controller serial comparison removes
only UART framing accepted by the shared native validator and the
kernel-log timestamps; every other byte must agree. Each side's original
serial, request, report, compute, acceptance, derivation gate, and final
inspection hashes still bind its own unchanged bytes. Differing receipt
hashes are reviewed only after their per-side commitments, physical boot
inputs and all six compute results are proved; unreviewed content remains
strict. If that proof is unavailable, fixed-class timestamp, framing, phase
and retained-role diagnostics do not grant parity. Boot command records are checked
against their own supervised stage contracts and physically pinned tool
identities before their per-side command outcome is compared. Side-specific
validator records/logs are rehashed and checked against their pinned
supervised contract, raw serial and compute output before removing only
their verified retained slots from membership comparison. Rooted package-job
sizes are reviewed only after checking each job's source pin, producer,
intent and ownership roles. No private
serial data, command logs, hashes, or paths are printed.

## Private final-image handoff

After a successful final-source build and all six boots, `handoff.py export`
can retain and revalidate the **actual private bytes** before the runner is
discarded. It uses the existing native physical package inspector, original
request/report/compute checks, and complete earlier result hashes. Its bundle
and `handoff.py candidate` output remain `authority=not_admitted`; they do not
promote this lane's local result to cloud acceptance. For an imported
version-2 public-source bundle, `handoff.py plan` now creates the separate
canonical private `uk.wamr.azure-execution-plan` version 2 and pending
approval template. The plan remains unapproved and requires explicit
validator, supervisor, transfer and prepared Azure runtime paths plus a
finite integer micro-USD maximum. Before plan generation,
`handoff.py prepare-azure-runtime` must create a fresh private closure from a
reviewed Python bootstrap, explicit Python ELF, standard-library tree and at
least one repeated `--package-root` import root. Optional repeated data roots
and explicit native dependencies are copied/bound during that authority-free
preparation; there is no package restore after custody. The closure document
binds exact launcher/interpreter/manifest artifacts, all module/data/native
files, the copied dynamic loader and DSOs, the exact controller command set,
parent and physical metadata, counts/bytes/depth, fixed limits and the isolated
`-s -S -B -P` policy. It rejects links, special files, unsafe modes/parents and
Python startup hooks. ELF preparation preserves every `DT_NEEDED` lookup name,
rejects slash-bearing dependencies, RPATH/RUNPATH and audit/filter dependency
tags, and requires a loader listing to resolve entirely below the copied DSO
directory. All allowed Azure command modules are probed authority-free before
publication, and traversal limits apply before copying.
The plan also binds a
campaign UUID, unique
ledger UUID, retained directory identity, bounded legacy pre-state digest,
expected marker digest and an explicit `initialization_required` decision.
Planning never mutates the ledger. A legacy marker is created durably only
after the exact version-2 authorization/admission, local CLI startup and final
tool/scope recheck, and before claims; later plans bind that existing identity
and cannot reinitialize a missing or replaced marker. `--ledger-id` can make the proposed first
identity explicit; otherwise planning generates a fresh UUID. Metadata-only
Actions artifacts cannot be used in place of missing raw/VHD/EFI/log bytes.

Admission and every explicit tool path use canonical descriptor-relative
no-follow custody. The controller retains the admission bytes, stores only
that exact scope, rehashes the copy, and rechecks tool parents, mode, link,
inode and content before attempt/backend work. Retained native ELF tools run through descriptor snapshots. Before admission
the controller re-execs in a private user/mount namespace, copies the
authenticated runtime to bounded tmpfs, remounts it read-only, and drops its
namespace capabilities. Exact kernel UID/GID maps, supplementary GIDs
restricted to mapped-primary or kernel overflow IDs, disabled setgroups,
private mount propagation and an exact initial-namespace parent relationship
authenticate the controller re-exec boundary. Its marker is distinct from
the native-validator child marker, which requires the same maps and an
untraced `no_new_privs` process and parent with zero effective, permitted,
inheritable and ambient capability sets. Azure calls inhibit the loader cache
and RPATH, execute the retained copied loader with only copied DSOs, refuse a
system `ld.so.preload`, and cannot fall back to masked host library
directories; Python and the bootstrap/modules/data are addressed below a
retained `/proc/self/fd/N` root. The original source closure, every approved
parent and the immutable execution copy are revalidated before and after
every Azure consumer and final cleanup/absence observation. Runtime sealing
completes before the first campaign-ledger access.

See [WAMR direct compute](../../azure/WAMR-DIRECT-COMPUTE.md) for the private
export, independent native revalidation, explicit authorization recording,
native admission and final image-specific approval boundary. No cloud
execution is added by generation or validation.

## Expressly authorized public-source image bundle

The separate `public-source-bundle` command is enabled only by the named
`wamr-native-compute` PR job in the **public** `cataggar/unikraft` repository.
It accepts no runtime/output/operator-tree arguments. It checks the clean
current CI revision/tree, clean pinned public `cataggar/wamr` SDK checkout,
fixed workflow/job/run/attempt context and successful managed-runtime cleanup.
The protected job builds and boots from the fixed private
`/d/wamr-ci/wamr-native-runtime` root, with the sealed Zig distribution
beside it under `/d/wamr-ci/wamr-native-tools`; the root-owned `/d` boundary
and precreated private `wamr-ci` directory avoid mutable hosted-runner home
ancestors while retaining exact component custody. Its authenticated QEMU
`libfdt` runtime is established before the build-input baseline and removed
by exact recorded identity only after final handoff revalidation, so neither
boot setup nor pre-export cleanup can mutate a recorded system-library
directory. The publication command accepts only that literal CI runtime or
the legacy in-worktree runtime.
Because publication is a fresh Python handoff process, it first reopens
`build-start.json`, validates its closed schema and directly rehashes every
recorded consumer file/tree without selecting tools from ambient variables.
It uses only the validated recorded Git executable for the source/dependency
recheck, recomputes the exact source, dependency, Bison, consumer and guarded
supervisor custody, and only then binds the full recorded tool set and the
fixed-runtime supervisor. It repeats the full custody check after binding.
Public publication emits opt-in, fixed-label native phase timings on stderr;
stdout retains its exact archive-digest/tree contract. Timings contain no
arguments, paths, records, child output or refusal details, and a returned
transport is not an acceptance result. Every existing revalidation boundary
still runs, including the pre/post validator, export and final custody checks.
Canonical custody framing uses a short-lived nested arena so its JSON workspace
does not accumulate in the acceptance arena across inventory entries. Tree
members are hashed through the already retained descriptor, using the same
`readRetained` primitive as the #187 export foundation; before/after descriptor
snapshots and full pathname/component verification remain intact. Each newly
hashed member uses that primitive's terminal verification without immediately
repeating the same walk; alias reuse and final tree member/directory checks
still verify independently. No digests or pathnames are cached across
revalidation boundaries.
Pre-export refusal names only a fixed result, build-start schema/consumer
role/tree/custody (with a fixed allowlisted file or tree role when physical
custody changes), physical path role/binary/runtime/tree, dependency/custody,
or CI environment/source/binding stage; it does not print recorded paths,
content, hashes, or private runner state.
If the native log validator is installed, the preflight requires its recorded
role, exact runtime path and executable dependency closure; a missing or
misbound role refuses publication before tools are bound.
Public bundle validation also binds the native `prepare`, `config` and
`native-image` command records to the installed producer's recorded consumer
identity; a missing or substituted producer role refuses those records.
The public validator build then runs through that retained supervisor; its
`command-public-validator-build.json` must be the exact in-memory/on-disk
canonical non-bootstrap record with the retained Zig identity, complete
primary/descendant/output/deadline/cleanup/poison observations and successful
cleanup. The same record and custody are rechecked before export, after export
and after archive reopen. A missing supervisor, changed consumer record,
bootstrap substitution or stage relabel refuses publication.
After all six genuine boots, while the complete runner files still exist,
the workflow invokes the production private export and native handoff checker,
then copies only its closed image/local-evidence allowlist into a standalone
ZIP. Verification hashes and parses one retained no-follow archive descriptor;
import extracts through another duplicate of that same descriptor and requires
the final descriptor identity to match. The workflow natively reconciles the
ZIP before upload.

Native QEMU acquisition uses the existing read-only Actions `GH_TOKEN` only
in its acquisition step, consistently across compute, fault, public-image
and candidate workflows. Without that explicitly supplied token it retains
anonymous downloads and does not discover host credentials. Release, asset,
digest, size, archive and package checks remain unchanged. Downloader failures
retain their evidence, print the failed acquisition phase and original
diagnostic, and preserve the original nonzero exit status; no failed download
is accepted or converted into a fault-qualification result.

Native LLVM acquisition explicitly passes the same read-only `GH_TOKEN` to
the pinned downloader, rather than only to its setup action. The shared
`hyperv-native-llvm-acquire.sh` retains separate private staging/logs for up to
three attempts (180 seconds each, 5-second kill grace, 5/10-second backoff).
Only ghr 0.8.0's exact attestation-lookup `UnexpectedHttpStatus` failure is
retried; that CLI does not
expose the underlying status. Every attempt repeats the existing checksum and
attestation checks. Cryptographic rejections, extraction failures and exhausted
lookups preserve their nonzero status. Only a fully verified/extracted attempt
is moved create-only into the final LLVM destination. No skip-verification
flags or cached-success fallback are used.

The destination-collision fixture covers the host `mv` and both GNU
`--no-clobber` behaviors: a successful skip and a nonzero refusal. In either
case, acquisition must refuse explicitly, preserve the occupied destination
and retain verified staging; it does not require a version-specific exit code.

Controller dependency restoration uses `hyperv-native-zig-restore.sh` before
installation, never a retried build. It copies the unchanged pinned local-boot
dependency graph outside the source tree and runs Zig's hash-verifying
`--fetch=all` in up to three isolated stages/caches, each bounded to 180 seconds
with five-second kill grace and 5/10-second backoff. Only exit 1 with exclusively
`HttpConnectionClosing` transport errors permits another attempt; mixed,
hash/extraction, timeout and exhausted failures retain their original nonzero
status and evidence. Only a successful verified package directory is published.
Both portable controller installations then use `--system` with those packages,
so compilation cannot silently fetch dependencies or replay an installation.
The primary's existing fixture restore is reused instead of fetched again.

LLVM acquisition and synthetic cold-setup/refusal fixtures precede the long
controller fixtures. The four required native fault jobs independently build
their own inputs and now run alongside the producer, without changing their
context names, job inventory, permissions or budgets. Setup failures therefore
do not wait for the producer's full build/boot/publication chain.

Both x86/KVM prerequisite steps have a ten-minute ceiling and command tracing,
retain the same host/resource checks, and recheck every prerequisite after
installation. Privileged operations use noninteractive `sudo -n`.
The shared `hyperv-native-apt-prerequisites.sh` reports metadata/install phases
and preserves failures, uses only the existing Ubuntu sources, and bounds each
APT invocation to 240 seconds with five-second kill grace, 30-second HTTP/HTTPS
timeouts, two acquisition retries and a 60-second lock wait. A failed metadata
refresh cannot silently use stale indexes; installation is noninteractive.
Cleanup runs only after QEMU acquisition was attempted, and controller
diagnostic/publication steps require its successful installation, so an early
prerequisite refusal does not manufacture missing-runtime secondary failures.

Local CI monitors use `github-read-retry.sh` for read-only `gh api`, `pr view`,
`pr list` and `run view` requests. It enforces GET for API requests, rejects
method/body overrides and mutating commands, and retries timeouts, 429, selected
5xx responses or explicit rate-limit errors up to three times with 5/10-second
backoff, a 120-second attempt cap and 5-second kill grace. Authorization
failures and exhausted reads remain errors; failed output is never returned as
successful JSON.
Mutation calls are never replayed, and retrying reads does not extend an
acceptance deadline or authorize auto-merge.

Artifact name:
`wamr-public-source-tiny-RUN_ID-RUN_ATTEMPT-SOURCE_SHA`.
Its sole uploaded file is `tiny-aot-public-source.zip`, stored for seven days.
Current version 2 contains 26 exact image/compiler/runtime/config/manifest and
lineage artifacts, six original serial/request/report/compute sets, 33 exact
local JSON records, portable `bundle.json`, and `public-source.json` (85
regular files). Its closed archive bound is 96 members, 512 MiB total and 64
KiB per JSON record; the measured contract does not use globs or optional
members. Exact artifact-ID redownload is followed by production import,
transport binding and native non-authorizing candidate validation. Version 1
is not reinterpreted: it remains exactly 17 artifacts, four boot sets, 20
evidence records and 55 ZIP members for the old tiny profile. Dependency
custody is embedded in the existing `build-start.json`; it is not a 21st
version-1 evidence member. The delivered source
`993e4d0d394c08202c0d0c57ea97450a19a4f394`, its reference PR head
`34e5c88a165c4da878b3122b8b91716116d65d4b`, and retained run
`35277215611` merge source `b5a8fdbee033349f7145fbc76aebfee29b2fa04f`
all have tree `54f8e118146c78c24e7c802657c6ec62b268a5de` and remain
import-compatible without the later custody record. No other identity may
omit it. Those exact legacy archives retain their source/run/member trust
contract and may omit the new external-digest input; any archive containing a
current custody claim requires it. Member names, modes/types, individual
sizes, complete SHA256/EOF, source/run bindings and successful receipts are
checked.
The exact pre-supervisor merged sources
`0711a0b6bf2285a4ba6ab6dd3bd4088478d665e1`,
`c9c00535399354063486957611bf6e09c8ae4592` and
`3c6d5d98dc5736d86e97884184b26be39c3f11d5`, with their literal recorded
trees, remain compatible with the same fixed 20-evidence/55-file archive
shape without a command-supervisor record. Any other current source must carry
the native supervisor result fields. WAMR native CI source-only changes no
longer require guarded Hyper-V producer map repins: that pin excludes this
subtree, while the WAMR controller's own source custody and supervisor
source-closure pins remain separate.
Symlinks/hardlinks, duplicate/extra/absolute/traversal members, compression,
oversize inputs and known credential/account/approval patterns are refused.

The final upload copy is create-only in a dedicated root-owned, group-readable
directory. `actions/upload-artifact@v4` retains its artifact ID, URL and
container digest. The latter is explicitly an Actions-container digest and is
never compared with the inner ZIP digest. A later trusted step downloads that
exact artifact ID into a fresh private directory, requires exactly the one
regular `tiny-aot-public-source.zip` member, and verifies it through the same
retained-descriptor archive API against the pre-upload inner digest. Only that
successful comparison publishes the job outputs and summary containing the
inner ZIP digest, separate container digest, artifact ID/URL, run ID/attempt
and source SHA. No attestation or OIDC permission is added.

There are **no Azure credentials, subscription/VM identities, SAS, grants,
approval files, campaign state, raw command logs or private diagnostics** in
the allowlist. Public tiny local serial is expressly authorized here; it is
not arbitrary private guest output. The portable manifests use relative member paths and no operator/account data.
Supervised command requests replace absolute native paths with closed public
roles (`source`, `runtime`, command work root, exact tool/input and supervisor
roles) plus bounded repository-relative suffixes. The normalized fields are
generated directly from the exact native request before execution evidence is
published; unbound absolute paths refuse. Config/compiler/debug bytes may
likewise contain public build paths; no paths are rewritten inside original
non-command evidence.

The ordinary metadata artifact is still published on failure. The public
image upload is success-only; failed export, cleanup, revalidation or boot
cannot publish a successful image bundle. This public-source permission does
not authorize public export from the private operator CLI and supplies no
Azure permission, measurement or acceptance.

Download and import as described in the operator documentation. Current
imports require the independently selected inner-ZIP SHA256 from the
successful exact-artifact redownload summary/output; the Actions container
digest is separate and is not an acceptable substitute. Computing the expected
value from a later downloaded ZIP is not a trust decision.
The exact expected source commit and tree must also be available in the local
Git object database. The importer resolves both dependency manifests from that
tree and compares their blob OIDs, bytes and SHA256 values, then recomputes
manifest, closure, root-metadata and Zig hash-verification summaries.
Import also requires explicit `--validator` and `--supervisor` paths. It never
uses ambient environment, `PATH` or sibling inference. The supervisor is
opened no-follow, checked as the exact executable native ELF (x86-64 on the
hosted runner) recorded in the
accepted build, and its independently opened dynamic-runtime objects must have
the same bounded content set. It is queried under its own supervision for its
canonical protocol/source-closure identity and compared with the supervisor
source blobs from the exact expected Git tree before it may launch native
revalidation.

Package-tree physical metadata and the recorded Zig executions are producer
observations: their package bytes are intentionally not included in this tiny
archive, so import does not pretend to re-run those observations. They are
authenticated to the selected successful run only by the independently
trusted complete-archive SHA256. The same rule applies to nonempty supervised
stdout/stderr observations: production validates them against the direct
native result before creating the record, but the raw streams are deliberately
not public members. Import recomputes empty-stream hashes and aggregate
count/digest commitments, validates all native-width and cross-field
invariants, and accepts nonempty stream digests only in the independently
selected current inner-ZIP digest context. Missing archive trust is a refusal,
never a best-effort downgrade. The importer then safely copies only bounded regular
members to a fresh private directory, rebuilds local artifact references (not
original requests), and uses the production native checker before publishing
a usable `bundle.json`. Its plan remains `authority=not_admitted`; new final
artifact-bound human approval is required.

The native `test-controller-limits` production-boundary fixture is the
protected CI source-custody limit check. It covers the historical Python
script's frozen ignored-output constants, exact/excess 131,072-entry and
8-GiB sparse-file limits, exact/excess 8-MiB Git ignored inventories,
1,024-byte path, 64-component depth and 128-root diagnostic boundaries, and
adds tracked-source entry, byte, file-size and unsafe-type boundaries. The
Python `tests/source_custody_production_limits.py` remains intentionally
excluded from default discovery and runs explicitly in protected CI as long
as production `run.py build` still owns the build path.
