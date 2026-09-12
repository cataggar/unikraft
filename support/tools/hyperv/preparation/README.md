# Native local preparation, version 0.5.0

This package implements the local #120/#89 preparation boundary: strict native
contracts, physical source/tool provenance, guarded configuration, synthetic
storage formats, pinned miz packaging, version-3 VHD-inclusive staging, a
read-only engine-entry loader, and an executing native Linux namespace worker.
It does **not** admit cloud authority, host images, operator credentials,
completed preflight, persistence acceptance, or historical evidence.

**The whole preparation workflow remains incomplete until parent integration
executes it.** The native namespace fixtures execute real isolated processes;
they are not a full root configure/build/package/engine-entry demonstration.
The parent root bridge and native image proofs are merged upstream at
`368dade0` (#129) and `53226729` (#130), and are included in this branch.
Full root-produced engine entry remains necessary. After the recorded review
release, the targeted
source/runtime corrections replace lexical symlink normalization and
architecture-specific Git fixture discovery. Native fixture paths are explicit;
the reported runs are AArch64, not claimed x86_64 execution coverage.

The production implementation is local to this package. Shared core (`../core.zig`), native Kconfig,
facade paths, ELF helpers and pinned native miz are reused. No Python, production
shell wrapper, automatic legacy fallback, Azure CLI, credential probing, download
or failure-message recovery is implemented.

## Build and focused fixtures

Use installed Zig 0.16.0, never the repository root build. Put all caches,
outputs and temporary directories under an explicit fresh preparation scratch.
The existing dependency cache is read-only through `--system`. These focused
commands do not authorize dependency restoration or real evidence acquisition.

```sh
cd /d/unikraft-worktrees/fleet-origin
umask 077
scratch="$PWD/.d/zig-migration-origin-repair/focused-example"
test ! -e "$scratch"
mkdir -p "$scratch"/{tmp,home,cache,config,global,local,work}
proof_fixture="$PWD"
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
  --build-file /d/unikraft-worktrees/fleet-origin/support/tools/hyperv/preparation/build.zig \
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
CI copies the trusted installed Git executable, its ELF interpreter and complete
shared-library closure into private directories before supplying these options.

The proof fixture reads actual root/builder/tool source bytes; it never executes
the root build. `-Dproof-fixture` defaults to the current checkout root. The
example selects these actual files from that checkout:

```text
build.zig
support/build/hyperv-proof-build.zig
support/build/hyperv-proof-tool.zig
```

These are read-only public source fixtures, not a complete reviewed producer
checkout or fresh execution/admission evidence.

The separate existing-runner namespace fixture build uses:

```sh
/home/g/.local/bin/zig build \
  --build-file /d/unikraft-worktrees/fleet-origin/support/tools/hyperv/preparation/namespace/build.zig \
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

### Hosted namespace fixture setup

The separate `zig-hyperv-preparation` job runs this **hosted-only** setup command:

```sh
bash support/tools/hyperv/preparation/ci-fixtures.sh
```

It retains the preparation, namespace and nonexecuting integration-driver suites
in both Debug and ReleaseSafe with `-j2`, and supplies the actual checkout through
`-Dproof-fixture`. Its shell is CI orchestration, not a production namespace
transport. Do not run it locally: it performs the explicitly approved root-owned
synthetic-fixture installation and, only when justified below, AppArmor setup.
The native fixtures alone remain locally runnable without changing policy.
The job uses the pinned native Zig/LLVM distributions and the installed Git
closure without Python or package-installation hooks. It has its own
60-minute ceiling, keeping the existing Hyper-V job's identity and deadline
unchanged. The new check is required alongside, not instead of, the existing
branch-protection checks. Evidence is retained in its separate bounded
artifact; synthetic namespace success is not a full producer or admission.

The namespace build has two **test-only** options:
`-Dfixture-executable=/absolute/native/file` selects an existing fixture instead
of the default cache executable; `-Dci-report=/absolute/private/new.json` writes
an exclusive mode-0600 canonical baseline report. Relative paths are rejected.
The `install-fixture` target installs only `preparation-namespace-fixture`; it
still compiles the real namespace helper whose path is baked into the fixture.
For example, after creating private cache/workspace directories:

```sh
cd /d/unikraft-worktrees/fleet-origin
/home/g/.local/bin/zig build \
  --build-file support/tools/hyperv/preparation/namespace/build.zig \
  --cache-dir "$scratch/ns-release-cache" --prefix "$scratch/ns-release-fixture" \
  -Dworkspace="$scratch/ns-release-work" "${git_fixture[@]}" \
  -Doptimize=ReleaseSafe -j2 install-fixture --summary all
/home/g/.local/bin/zig build \
  --build-file support/tools/hyperv/preparation/namespace/build.zig \
  --cache-dir "$scratch/ns-release-cache" --prefix "$scratch/ns-release-suite" \
  -Dworkspace="$scratch/ns-release-work" "${git_fixture[@]}" \
  -Dfixture-executable="$scratch/ns-release-fixture/bin/preparation-namespace-fixture" \
  -Dci-report="$scratch/ns-release-baseline.json" \
  -Doptimize=ReleaseSafe -j2 test install --summary all
```

The external executable must be built with the same workspace, Git material and
helper options as its tests. CI builds two native files with distinct baked
Debug/ReleaseSafe workspaces, then installs them root:root, mode 0555, single-link:
`/var/lib/unikraft-hyperv-preparation-ci/namespace-fixture-debug` and
`/var/lib/unikraft-hyperv-preparation-ci/namespace-fixture-release-safe`.
The existing `/`, `/var` and `/var/lib` ancestors must already be root:root,
mode 0755 and nonsymlinks. The setup refuses an existing installation directory;
it neither repairs shared paths nor uses writable `/opt`.

Before any compiler or test invocation, CI checks the canonical passwd account.
Extra supplementary groups or a different effective primary GID trigger
`sudo setpriv --reuid=UID --regid=GID --clear-groups --bounding-set=-all
--inh-caps=-all --ambient-caps=-all`, which drops credentials **before** executing
the ordinary-user compiler/test process. No Zig/test process runs as root.
The launcher and native fixture independently require zero host effective,
permitted, inheritable and ambient capabilities; production's supplementary-group
restriction is unchanged. HOME remains the actual passwd HOME. The canonical
facade directory and zero-byte `build.lock` are initialized only if absent;
existing ownership/modes are checked and lock device/inode are preserved through
cleanup. The setup never deletes that facade or lock.

A single 15-second native baseline actually crosses the user/mount namespace
boundary, checks isolation, and cleans up its descendants. Only the synthetic
fixture sets the stable 15-byte audit comm `uk-prep-ns-test`. A second existing
eight-byte namespace status memfd carries a closed fixture-only error enum:
arbitrary stderr is still discarded, not parsed into a policy decision.
Successful self-copy evidence compares held-file bytes/metadata and requires a
different physical inode from the selected external executable. Each full-mode
suite retains its own `namespace-baseline.json`; CI also requires the installed
files' physical identity, size, ownership, mode, link count and hashes unchanged
afterwards. These reports and the copy inventory describe synthetic test
material, not production ledger admission.

If the baseline passes, **no profile is loaded**. Otherwise the setup requires
both the bounded report's specific namespace/mount-unavailable classification
with completed outer-process cleanup and actual `journalctl -k` evidence from
the microsecond-bounded baseline interval. `ci-denial.awk` retains at most eight
4096-byte lines matching DENIED, the exact fixture comm,
`profile="unprivileged_userns"`, `operation="capable"`, capability 21 and
`capname="sys_admin"`. Missing/unrelated/overflowing evidence remains a failure.
Only then may `ci-debug.apparmor` and `ci-release-safe.apparmor` attach their
`flags=(unconfined) { userns, }` exception to those **two exact immutable paths**.
No compiler, shell, test driver, writable cache path or production helper is
profiled. This userns exception is not a sandbox or production permission.
`kernel.apparmor_restrict_unprivileged_userns` must stay 1 throughout that path.

Cleanup removes only the two owned profiles, four exact installation files and
the now-empty dedicated directory. Failed cleanup is separately recorded from
the primary exit; it does not erase the primary failure or silently remove files
under a still-active profile. Synthetic logs, credential/baseline/cleanup JSON,
installed-binary hashes and a size/device/inode/mode/link-count inventory of
compiled/staged/installed fixture copies are retained at the workflow's exact
`hyperv-ci/native-preparation` artifact paths. The inventory is a snapshot before
installation cleanup, not a complete producer staging ledger or authority claim.

This setup does not run configure, Make, guest/native-image builds, a complete
producer/importer, or any host/cloud/seed operation. Actual hosted AppArmor
execution remains a separate parent-owned CI gate.

## Wire versions and types

Canonical JSON has sorted keys, exact fields/types and one final LF, included
in document hashes. Duplicate/unknown/missing fields, noncanonical encodings,
floating/exponent integers and unknown enums are rejected. Generic document
bounds are 4 MiB, depth 32, 4096 items, 65536 tokens and 8192-byte strings.

| Type | Schema and exact fields |
| --- | --- |
| `provenance.Record` | `hyperv_native_producer_provenance_v2`: `schema,source,host_target,guest_target,compiler_version,producer,compiler,git,dependencies,trust` |
| `producer.Binding` | `hyperv_local_native_producer_binding_v4`: `schema,source,repository,workspace,output,scratch,config,path,native,git,packages,bison_data,trust,trust_bundle,native_execution,native_proof,isolation` |
| `producer.NativeProof` | `hyperv_native_elf_proofs_v2`: `schema,source_sha256,root_build,builder,tool,modes` |
| `receipts.Receipt` | `hyperv_artifact_preparation_native_v2`: `schema,phase,purpose,run_id,guard,source_before,source_after,provenance,reviewed_provenance_sha256,config_before,config_after,parent_sha256,execution,efi,packaging,authority` |
| `inputs.SelectionV3` (`Plan`) | `hyperv_native_input_selection_v3`: `schema,packaged_receipt_sha256,solved_metadata,publication,capability_source,capability_receipt,qemu,firmware_origins,assets` |
| `inputs.PreparedInputV3` (`Input`) | `hyperv_native_prepared_input_v3`: `schema,state,authority,receipt,reviewed_selection_sha256,selection,ledger,budget` |
| `inputs.Capability` | `hyperv_public_capability_artifact_native_v2`: `schema,image,provenance,reviewed_provenance_sha256,authority` |

Earlier Origin, provenance, producer-binding, receipt, capability, input and
selection epochs are **rejected, never upgraded or reinterpreted**.
`state` is exactly `prepared`; `authority` is exactly `not_admitted`.
Producer binding v4 retains separately bound Make and Git policy files.
Native proof v2 replaces the obsolete three-direct-source representation:
`builder` is `support/build/hyperv-proof-build.zig`, `tool` is
`support/build/hyperv-proof-tool.zig`, and `modes` is exactly
`["smp","irq","drivers"]`. Proof-v1 records are rejected. NativeProof v2,
Make/Git environment schemas, namespace status bytes, host wire and budgets
are unchanged. The typed namespace request is now
`uk.native-preparation-namespace.v2`, not a status-format change.

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

## Origin v2: identities, witnesses and independent review

`runtime.Tool` has exact fields
`role,origin,target,tree,executable,loader,libraries,evidence`. Evidence is a
separate array of held-set bindings, not a Tool claiming an origin for its own
catalog. Executable, ELF/SONAME/interpreter/RPATH, complete inventory, native
target, exact Git file set and actual running-inode checks still apply.

`Origin = {schema:"hyperv_runtime_origin_v2",payload}`. Payload is exactly one
recognized tag with its exact non-null payload:

| Tag | Payload and digest meanings |
| --- | --- |
| `local_build` | `{source_revision,source_physical_sha256,compiler_executable_sha256}`: current reviewed Git HEAD, actual current physical source snapshot, actual selected compiler executable bytes |
| `distribution` | `{runtime_revision,evidence_set_sha256,components}`: principal runtime version, canonical `Set` commitment, components `{artifact_id,selected_tree,scope}` |
| `zig_packages` | `{packages}`: each `{package_hash,locator,revision,declaration,selected_tree,scope}` identifies dependency data, not a prebuilt compiler or firmware |

No recipe/archive/tree digest can stand in for a compiler executable digest.
Actual local actor and same-source static namespace helper require
`local_build` at their consuming call sites; distribution cannot bypass those
relations. Utilities also use `role=preparation`, so that role does **not**
impose local-build or static-only requirements on utilities. Prebuilt Zig must
be a native executable distribution at runtime revision `0.16.0`.
Bison data, CA bundles and firmware use data distributions, never package-data
disguises. The miz hash/revision pins remain immutable.

Scope is `{"whole":{}}` (one component/package only), or
`{"selected":[{"file":"relative/path"},{"subtree":"relative/directory"}]}`.
Selectors must resolve within the held root, contain no escapes, overlaps,
gaps or extras, and cover **every selected file exactly once**, including
DSOs and non-ELF support. `selected_tree` uses the existing
`hyperv-native-tree-v1` encoding, directory modes and relative selected paths,
not an artifact digest. A singleton package's tree is relative to its hash
root; aggregate scopes retain the hash-basename prefix.
Compact unchanged tree maps cover 19,546 Zig files without embedding a
19,546-item JSON array or raising any parser/document limit.

Each evidence `Binding` is
`{directory,set,physical_sha256,policy}`; `directory` is
`{path,device,inode,mode,uid}`, `set` is `{tree,catalog:File}`.
`physical_sha256` commits every physical file/directory's metadata and file
bytes using `hyperv-native-physical-v1`. `distribution.evidence_set_sha256`
hashes the complete canonical `set`. Source and runtime directories must be
separate from evidence roots, including Git's exact root and CA data.
The immutable catalog has
`schema:"hyperv_runtime_origin_evidence_v1",artifacts`, with artifacts
`{id,subject,authentication,realizations}`. A subject is
`{publisher,repository,asset_id,locator,revision,artifact_sha256}`.
Artifact SHA means the original acquired package/release artifact only.

Authentication is the independently selected **existing publisher assurance**:

* `pinned_key_signature`: exact subject, `key_id`, detached `signature:File`
  and `verification:File`.
* `publisher_https_sha256`: exact subject, retained raw `metadata:File`,
  `metadata_url`, and `acquisition:File`. This is HTTPS publisher/channel
  metadata plus SHA256, **not an independent package signature**.
* `signed_repository_metadata`: exact subject, independently approved
  `key_id`, retained `metadata:File`, `index:File` and `verification:File`.

The exact policy per artifact is
`{artifact_id,authority,authentication_sha256,realization_verification_sha256}`.
`authority` is the same closed method tag with expected publisher/repository,
and key ID for signed methods. It comes from the separate independent runtime
review, not from an artifact choosing its method. The authentication hash
commits the entire typed witness. Each realization verification digest is
independently approved in catalog order. Unknown/mismatched authorities,
methods, keys, absent witnesses and failure-to-absence downgrades fail closed.
Transported `Tool.evidence[].policy` is not itself approval: bootstrap compares
it against the **separately supplied** review, then remeasures the entire
material before the first supplied Git/loader invocation.

`hyperv_origin_signature_verification_v1` binds `subject_sha256`,
`signed_bytes_sha256`, `key_id` and `verifier`. The signed-input digest is the
artifact digest for a detached signature and the metadata digest for signed
repository metadata; it is never the detached signature file's digest. The
signature file is independently retained and bound by the authentication witness.
`hyperv_origin_https_acquisition_v1` binds `subject_sha256`, raw
`metadata_sha256`, URL, TLS peer name/certificate SHA256, acquisition time and
retained transport-evidence file.
`Verifier = {name,version,executable_sha256,transcript:File}`.
All referenced physical files must exist and match. Raw metadata is retained
verbatim, not replaced with a rendered excerpt. Independent review establishes
authentication of these **actual witnesses**. Parsing/hashing them is not a
new cryptographic verifier, network client, PKI or trust service. Installer
flags, arbitrary booleans and self-declared success never grant trust.

Realization is `{payload,verification:File}`. The closed payload is either:

* `unchanged_extraction {artifact_sha256,selected_tree,maps}`. Maps are
  `file {member:File,destination:File}` with identical sizes/hashes/modes, or
  `tree {member_prefix,destination_prefix,tree}` with the complete unchanged
  canonical tree. Empty prefixes denote the root.
* `declared_prefix_relocation {artifact_sha256,selected_tree,declaration:File,
  declaration_member,unchanged,relocated}`. Only authenticated
  `info/paths.json`, paths version 1 and hardlink entries are supported.
  Every relocated record binds original member and retained original file,
  exact installed destination, placeholder, `binary|text` mode and installed
  prefix. Original SHA256/size, declaration mode/placeholder and result
  bytes/size/mode must agree. Unix binary replacement shortens each complete
  NUL-terminated string and appends the aggregate shortening as NUL padding;
  an oversized replacement or unterminated match is rejected. Text mode is
  literal byte replacement. Hooks, arbitrary transforms, Windows relocation
  and special shebang rewriting are not supported.

`hyperv_origin_archive_verification_v1` binds original artifact SHA256,
canonical `realization_payload_sha256` and actual verifier/transcript evidence.
Out-of-band archive membership is accepted only through that retained,
independently approved proof—not a mutable mapping or caller success claim.
Native relocation comparison executes no installer hooks.

Package declarations bind `{directory,file,entry}`: an actual
`build.zig.zon` in the selected source or another selected package, its exact
file bytes and named dependency entry. Native bounded ZON AST generation and
literal-value validation reject expressions and duplicate fields throughout the
manifest, then check literal URL/hash/lazy declarations without executing a
manifest or root build. Revision is explicitly `git_commit` (full commit) or `archive_selector`
(possibly short, such as progrez's `7d70ce8`); Zig keys are never decoded as
upstream SHA256. Singleton/aggregate lists, hash basenames, declarations,
locators and complete dependency bindings must agree.

Firmware selection carries mandatory named `firmware_origins.code` and
`.vars` mappings `{asset_id,directory,physical_sha256,tool,member}`. Creation, generation and
read-only admission bind exact asset files to held physical data roots and
origins. Every support/evidence file required for admission must have a staged,
physically matching charged control asset. No outside-host exception exists;
all six firmware working copies and both existing budget caps remain intact.

See [integration/README.md](integration/README.md) for the mandatory
pure-measure → external runtime review → bootstrap CLI boundary and the
additional independent complete provenance/build/selection/import reviews.

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
historical receipts and evidence remain untouched. The cap-only change did not
alter document limits; the current Origin schema epoch is specified above.

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
namespace mechanism; v4 producer/admission entry requires both. All original
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

### Earlier cap/bridge execution record (historical)

The cap update passed **80/80 preparation cases** (10/10 build steps) in both
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

### Origin repair execution record, 2026-09-11

On the AArch64 owned `fleet-origin` worktree, Zig 0.16.0 focused runs passed
**93/93 preparation, 19/19 namespace and 18/18 integration fixtures in each
of Debug and ReleaseSafe**, without skips. Build-step totals were 10/10,
11/11 and 8/8 respectively. The 5-second Git timeout/readiness assertion,
ordinary fixture credentials, actual passwd HOME and canonical facade/lock
device/inode/ownership/modes were retained. No AppArmor/credential changes,
acquisition, dependency restore or full producer/Make/guest execution occurred.

Exact command wrappers, environment, complete six logs, all twelve installed
component sizes/SHA256s and before/after identity records are retained under
the following directory. The final review-correction runs and remeasurements
use its `review-*` filenames:

```text
/d/unikraft-worktrees/fleet-origin/.d/zig-migration-origin-repair/run-20260911-1/
  environment.sh
  focused.sh
  {preparation,namespace,integration}-{debug,safe}.log
  installed-components.txt
  installed-components.sha256
  physical-before.txt
  physical-after.txt
```

The six commands were `bash .../focused.sh SUITE MODE`, with `SUITE=prep,ns,int`
and `MODE=Debug,ReleaseSafe`. The wrapper uses the build files in this package,
`test install -j2 -Doptimize=MODE --summary all`, explicit per-suite caches/
prefixes below that fresh root, and the **read-only**
`/d/unikraft-worktrees/fleet-ci/.d/zig-migration-preparation/restore/zig-pkg`
via `--system`. Preparation and namespace use the exact public Git options
listed above; preparation supplies `-Dproof-fixture=/d/unikraft-worktrees/fleet-origin`
and namespace supplies `-Dworkspace=R/ns-{debug,safe}`. Integration has no
fixture Git option or supplied-tool execution.

Measured installed executable bytes (not a ledger):

| Installation | Executable | Debug | ReleaseSafe |
| --- | --- | ---: | ---: |
| preparation | `uk-hyperv-prepare` | 8,716,624 | 1,139,000 |
| preparation | `preparation-namespace` | 8,168,400 | 1,011,912 |
| integration | `uk-hyperv-prepare-integration` | 13,466,168 | 2,311,568 |
| integration | `preparation-namespace` | 8,168,400 | 1,011,912 |
| namespace fixtures | `preparation-namespace` | 8,168,400 | 7,114,664 |
| namespace fixtures | `preparation-namespace-fixture` | 8,046,920 | 7,072,024 |

The namespace fixture build retains its existing unstripped output policy.
Its files are not substitutes for the stripped production helper. The current
ReleaseSafe integration driver/helper pair is **3,323,480 bytes**, not the
historical 2,598,000-byte pair and not evidence of complete controller fit.
Every additional control, support/evidence file and physical copy remains
chargeable under the unchanged 8 MiB/256 MiB caps.

The new witnesses in focused tests are **explicitly synthetic**. None
authenticates actual installed Zig/LLVM/conda/Ubuntu/firmware material.
Real remaining gates: retained approved Zig archive/member realization plus
actual signature-verification evidence under its existing pinned key; LLVM's
matching retained archive/GitHub asset digest with approved retained HTTPS
acquisition and member proof (not a package signature); all nine conda package
hashes' channel HTTPS context, original archives/authenticated `info/paths.json`
and actual relocation evidence/replay for Git/Bison/Flex/M4/libcrypto.
The 38 matching local records and five declared binary prefix changes are
observations, not authentication or replay. Ubuntu's existing-key approval,
native OpenPGP verifier and verified signed-index/member chain remain material
gates. Firmware, complete native utility closure (including native `which`),
public capability artifacts, fresh actual source/compiler/build reviews and
all new independent runtime/provenance/selection/import commitments remain
unsupplied. Historical upstream compiler manufacture is not a gate.
