# Credential-free tiny native WAMR PR gate

Refs #156. `wamr-native-compute.yaml` is an **additive ordinary
`pull_request` job**, including the native integration's stacked base.
It has only `contents: read`, a GitHub-hosted Ubuntu 24.04 x86 runner, no
protected environment, no dispatch, no cloud identity and no upload/deployment
entry. All existing required contexts, default images and safety gates stay
unchanged. This does not complete #88's guarded Azure authority or image handoff.

The job builds the distinct `hyperv-x86_64-efi-wamr` target using the
app-owned `prepare.py` and `build-image.py`, pinned WAMR
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
* The existing installed `uk-hyperv-local-boot` runs four fresh one-CPU
  attempts: raw/x2APIC, raw/masked-x2APIC, full VHD/x2APIC and full
  VHD/masked-x2APIC. Each uses the **exact read-only package**, a genuine VPC
  opening for VHD, private OVMF variables, no NIC and return **0**. Its
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
byte counts plus content and physical SHA256 values. The only role-excluded
output roots are exactly `.d`, the fail-closed precreated `.zig-cache`,
`support/apps/wamr-aot/build`, and the precreated
`support/apps/wamr-aot/.config`. `.d` alone may already contain the workflow's
pinned WAMR checkout and acquired runtime; those consumed inputs are separately
content- and physical-identity-bound by the source archive, tool, Bison,
firmware, QEMU and package records. The other three roots must not preexist and
are created by the adapter before custody. Every custody check uses normalized
repository-relative path components, not string prefixes, to reject all
ignored entries outside those exact roots, including sibling names. It then
walks every allowed root without following links and rejects escaping links,
hard-linked or nonregular files, unsafe root/directory ownership or modes, path
or depth excess, and changes during inspection. Regular-file modes remain
physical metadata and are separately enforced for every consumed dependency or
tool input. Python bytecode is disabled. The same physical record is required
around each build/boot consumer and at inspection/handoff, so a create/delete
transient cannot be hidden by a finally clean Git status.

`build-start.json` now carries
`uk.wamr.consumer-input-custody` version 2. It inventories each selected host
tool and dynamic runtime object plus the bounded Zig, LLVM,
Python-standard-library and authenticated Bison data trees. The selected tools
include the exact indirect shell/coreutils executables used by the native build
graph (`dash`, `cp`, `env`, `mkdir`, `readlink` and `uname`) rather than
unrelated `/usr/bin` members. Native Make receives retained descriptor paths
for Zig, Python and its consumed copy/directory/readlink helpers; the Zig-owned
link and post-processing graph receives the retained compiler, binutils,
readelf and copy paths and uses the objcopy interface for descriptor-safe
stripping. The hosted workflow first materializes the pinned Zig distribution
create-only beneath the owned ignored `.d` tool root, avoiding mutable
runner-managed ancestor directories. Native Make's unused Wget version probe is disabled by a fixed
offline build-contract value. Every record binds device/inode,
type/mode, uid/gid, link count, size, nanosecond mtime/ctime and content
identity, with deduplicated absolute directory-component identities. The
pinned tree scanner refuses on the first excess entry before sorting and
separately bounds all unique regular-file bytes hashed through symlinks.
Dangling input-tree links are accepted only when their retained deepest
existing target ancestor is root-owned and cannot be modified by the build
principal; the missing suffix and ancestor identity are part of the record.
The pinned WAMR checkout is consumed only while creating a fixed-revision Git
archive through retained repository and Git descriptors; all later WAMR build
steps read the create-only archived object. Top-level build tools execute
through retained no-follow descriptors. Build scripts receive those same
retained descriptor paths through closed adapter variables, while `PATH` is
restricted to the root-owned system directory containing the separately
recorded indirect executables. Tool/data and Miz-tree lookups are physically revalidated
immediately before and after each consumer and fully rehashed at final
inspection and export. Consumer subprocesses use adapter-owned
cache/configuration paths; ambient loader, shell-startup, Python, Make and Zig
injection variables are not inherited.

Records also bind the Unikraft revision/tree, app-source hashes, pinned WAMR/compiler options,
actual tools, wasm/cwasm/compiler/library bytes, solved configuration,
entire EFI/debug ELF/bootinfo, native package producer, QEMU and OVMF,
complete raw/VHD/footer, and each request/report/raw serial. Inputs are
reverified after the four boots and physical package reload. The final result
hashes earlier records only, **not itself**. These are local build/compute
observations, not authenticated source attestations or deployment receipts.

## Bounds and diagnostics

Writable build, package, firmware and boot slots are under the protected
CI job's private `/d/wamr-native-runtime` (or the local in-worktree runtime)
or the app's ignored `build/`. Zig's
source-pinned dependency restoration first establishes clean physical source
custody, then copies the exact Git-identified local-boot manifests create-only
into `compute/dependencies`. Before Zig runs it binds each copy's exact
device/inode/type, ownership, links, size, mtime and ctime plus the parent
directory metadata, and requires the same identities immediately afterward.
It also byte-compares the copies, parses the one exact Miz
URL/revision/package hash, and only then performs the bounded fetch. Before
reading package content it enumerates and snapshots the complete bounded
directory set, including `zig-pkg`, then requires the exact set and metadata
after traversal. The restored tree rejects links, nonregular entries, unsafe
names, extra/missing/duplicate roots and incomplete transitive manifests. Zig 0.16
`fetch PATH` independently recomputes every package hash, including Miz rather
than trusting its directory name. `build-start.json` embeds
`uk.wamr.zig-dependency-custody` version 1: request and source/copy manifest
identities and restore-parent metadata, bounded restore diagnostics,
package/root/file/directory/byte counts, per-package
content/physical/manifests, and aggregate closure, physical, manifest,
hash-verification and root-metadata SHA256 values. Limits
are 128 roots, 16,384 entries, 256 MiB total, 64 MiB per file, depth 64 and
4 MiB per manifest. Both builds use that one tree through `--system`; it is
revalidated around every consumer and at final inspection/export. No
package-manager state is created below tracked source. The ignored-source
policy allows at most 131,072 entries, 8 GiB total regular-file/link bytes,
512 MiB per regular file, 1,024 UTF-8 bytes per repository-relative path and
64 path components. Its collapsed Git inventory is capped at 8 MiB before
parsing. Failure diagnostics use a separately terminated-and-drained 1-MiB Git
status capture, retain at most 128 ignored paths, and refuse immediately on the
129th repository-root entry before sorting the bounded collection.
The subprocess collector gives termination, kill and post-kill/post-leader
pipe draining separate absolute one-second budgets. Escaped `setsid()`
descendants therefore cannot keep a captured pipe open indefinitely; the
collector closes the pipe at its absolute drain deadline and always reaps the
leader while preserving the original overflow, timeout or command-failure
lane. Git runs with system/global configuration, hooks, credential helpers,
replacement objects, terminal prompts and pagers disabled where applicable.
Build commands use `-j2`; the workflow has a 60-minute ceiling. Each build
command has a fixed deadline and an 8-MiB log limit (one extra byte detects
overflow). The native packaging worker retains its 120-second deadline and
independent two-second cleanup budget. Each native boot is limited to 60
seconds with the existing independent cleanup budget; an outer 660-second
compute ceiling also bounds the orchestration and post-exit hashing.
The empty private package output directory is created before boot-input
custody, and the native packager accepts it only while empty; this keeps the
shared compute-directory identity stable without allowing package reuse.
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

## Focused checks

From a checkout with Zig 0.16:

```sh
mkdir -p .d/wamr-ci-check/{cache,global-cache/tmp,scratch,restore,out}
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
  -Doptimize=ReleaseSafe -j2 test install
WAMR_CI_PACKAGE="$PWD/.d/wamr-ci-check/out/bin/wamr-ci-package" \
  python3 -m unittest discover -s support/build/wamr-native-ci/tests -v
```

The Python fixtures use the actual native packaging helper and pinned miz
with a synthetic **nonbootable** PE, plus synthetic compute/log records.
They check full raw/VHD/footer hashes, physical reload, mutation/partial-state/
replay refusal, exact results and the four CLI configurations. These are not
guest execution evidence. `WAMR_CI_PACKAGE` selects only that test executable;
production orchestration has no fixture, executable-override or skip switch.
ARM development can run these fixtures, but cannot qualify the guest.
Only a successful real x86 PR run of the corrected, committed native base
establishes the first local tiny-compute observation.

## Private final-image handoff

After a successful final-source build and all four boots, `handoff.py export`
can retain and revalidate the **actual private bytes** before the runner is
discarded. It uses the existing native physical package inspector, original
request/report/compute checks, and complete earlier result hashes. Its bundle
and `handoff.py plan` output remain `authority=not_admitted`; they do not
promote this lane's local result to cloud acceptance. Metadata-only Actions
artifacts cannot be used in place of missing raw/VHD/EFI/log bytes.

See [WAMR direct compute](../../azure/WAMR-DIRECT-COMPUTE.md) for the private
export, independent native revalidation, offline plan and separate final
image-specific approval boundary. The default private export/plan remains
unchanged. No cloud execution is added.

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
After all four genuine boots, while the complete runner files still exist,
the workflow invokes the production private export and native handoff checker,
then copies only its closed image/local-evidence allowlist into a standalone
ZIP. It reopens, re-extracts and natively reconciles the ZIP before upload.

Artifact name:
`wamr-public-source-tiny-RUN_ID-RUN_ATTEMPT-SOURCE_SHA`.
Its sole uploaded file is `tiny-aot-public-source.zip`, stored for seven days.
It contains the 17 exact image/compiler/runtime/config/manifest artifacts,
four original serial/request/report/compute sets, the original fixed 20 local
JSON records, portable `bundle.json`, and `public-source.json` (55 regular
files, at most 512 MiB total). Dependency custody is embedded in the existing
`build-start.json`; it is not a 21st evidence member. The delivered source
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
Symlinks/hardlinks, duplicate/extra/absolute/traversal members, compression,
oversize inputs and known credential/account/approval patterns are refused.

There are **no Azure credentials, subscription/VM identities, SAS, grants,
approval files, campaign state, raw command logs or private diagnostics** in
the allowlist. Public tiny local serial is expressly authorized here; it is
not arbitrary private guest output. The portable manifests use relative
member paths and no operator/account data. Original request bytes retain
only the validated public CI checkout paths, so their original hashes and
four local outcomes remain intact. Config/compiler/debug bytes may likewise
contain public build paths; no paths are rewritten inside original evidence.

The ordinary metadata artifact is still published on failure. The public
image upload is success-only; failed export, cleanup, revalidation or boot
cannot publish a successful image bundle. This public-source permission does
not authorize public export from the private operator CLI and supplies no
Azure permission, measurement or acceptance.

Download and import as described in the operator documentation. Current
imports require an independently selected SHA256 of the complete ZIP from the
successful workflow summary or an independently verified attestation subject;
computing the expected value from the downloaded ZIP is not a trust decision.
The exact expected source commit and tree must also be available in the local
Git object database. The importer resolves both dependency manifests from that
tree and compares their blob OIDs, bytes and SHA256 values, then recomputes
manifest, closure, root-metadata and Zig hash-verification summaries.

Package-tree physical metadata and the recorded Zig executions are producer
observations: their package bytes are intentionally not included in this tiny
archive, so import does not pretend to re-run those observations. They are
authenticated to the selected successful run only by the independently
trusted complete-archive SHA256. Missing archive trust is a refusal, never a
best-effort downgrade. The importer then safely copies only bounded regular
members to a fresh private directory, rebuilds local artifact references (not
original requests), and uses the production native checker before publishing
a usable `bundle.json`. Its plan remains `authority=not_admitted`; new final
artifact-bound human approval is required.

The expensive production-boundary module
`tests/source_custody_production_limits.py` is intentionally excluded from
default discovery and runs explicitly in protected CI. Its single PID-scoped
`/d` fixture combines 131,072-entry and 8-GiB sparse-file exact/excess checks,
constructs real exact/first-excess 8-MiB Git ignored inventories, and covers
the 1,024-byte path, 64-component and 128-root diagnostic boundaries. It uses
sparse allocation, emits no large payloads, and removes only its exact fixture
directory.
