# Credential-free tiny native WAMR PR gate

## Native package and boot chain (unpublished caller)

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
redacted observations only, never acceptance. `run.py` remains the
authoritative production caller and differential reference until the later
parity/bridge/cutover PRs; production callers, wrappers and authority are
unchanged.

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
and refusal never grant acceptance. The build path now supervises a closed
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
boundaries, tamper/refusal, and `run.py` differential record fixtures. The
installed fixture stage itself supervises bounded native success, nonzero,
partial-output, signal, overflow, timeout, and cancellation children; its
create-only private report binds the observed output hashes and cleanup states,
and the build gate verifies every required result. Each stream is capped at
4 MiB; the independent native-result transport permits up to 12 MiB so the
full allowed 8 MiB combined output is encoded without truncation. The
`test-unit` also runs the controller custody and command fault fixtures in
its isolated Zig cache. `test-controller` additionally checks invalid
installer build flags, which can restore `zig-pkg` in the source tree; that
test runs in a separate clean worktree in the protected gate, never during
the supervised production adapter build. Custody link and depth fixtures use
the selected cache even when production sets `ZIG_LOCAL_CACHE_DIR` outside
the checkout.
The protected x86 job exercises `test-controller` first in a separate clean
worktree, keeping its test dependencies and cache outside the production
source checkout; this reports fixture failures without exposing private
supervised-command output. On failure it runs the host test binary directly
for diagnostic errors while keeping the original gate failed.
`python3 -m unittest support/build/wamr-native-ci/tests/source_custody_production_limits.py`
remains the independent full-size source-boundary oracle until cutover.

`build --runtime ABS --wamr-source ABS`, `boot --runtime ABS`, and
`diagnostics --runtime ABS` are available only through the installed
native controller. Native stage failures report only a static Zig error name
alongside the failed stage; dependency restoration also reports a static
operation label. Command output and private paths remain in bounded private
logs. Production workflow callers continue using the Python controller;
there is no fallback, boot cutover, or change in acceptance authority before
the later parity and cutover PRs. The closed
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

Before the clean source baseline is taken, the adapter restores the exact
out-of-tree dependency tree and builds the internal
`wamr-ci-supervisor` from `supervisor.build.zig`. The bootstrap inputs and the
supervisor's exact tracked source closure are checked before and after that
build. The production supervisor and public validator use the fixed
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
support/apps/wamr-aot/build.zig test-unit test-integration`; serial
validation and controller/boot/handoff Python belong to subsequent
#188/#186/#187/#189 cutovers, not to this producer.
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
mkdir -p .d/wamr-ci-check/{cache,global-cache/tmp,scratch,restore,out}
export TMPDIR="$PWD/.d/wamr-ci-check/scratch"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.d/wamr-ci-check/global-cache"
cp support/tools/hyperv/local_boot/build.zig \
  support/tools/hyperv/local_boot/build.zig.zon .d/wamr-ci-check/restore/
zig build --build-file .d/wamr-ci-check/restore/build.zig --fetch=all \
  --cache-dir .d/wamr-ci-check/cache \
  --global-cache-dir .d/wamr-ci-check/global-cache -j2
SUPERVISOR_SOURCE_SHA256="$(
  PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import importlib.util
from pathlib import Path

path = Path("support/build/wamr-native-ci/run.py").resolve()
spec = importlib.util.spec_from_file_location("wamr_native_ci", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(module.supervisor_source_map()["content_closure_sha256"])
PY
)"
zig build --build-file support/build/wamr-native-ci/supervisor.build.zig \
  --system "$PWD/.d/wamr-ci-check/restore/zig-pkg" \
  --cache-dir .d/wamr-ci-check/cache \
  --global-cache-dir .d/wamr-ci-check/global-cache \
  --prefix "$PWD/.d/wamr-ci-check/supervisor" \
  -Dsource-closure-sha256="$SUPERVISOR_SOURCE_SHA256" \
  -Doptimize=ReleaseSafe -j2 install
zig build --build-file support/build/wamr-native-ci/build.zig \
  --system "$PWD/.d/wamr-ci-check/restore/zig-pkg" \
  --cache-dir .d/wamr-ci-check/cache --prefix "$PWD/.d/wamr-ci-check/out" \
  -Dtest-root="$PWD/.d/wamr-ci-check/fixtures" \
  -Doptimize=ReleaseSafe -j2 test install
WAMR_CI_PACKAGE="$PWD/.d/wamr-ci-check/out/bin/wamr-ci-package" \
WAMR_CI_LOG_VALIDATE="$PWD/.d/wamr-ci-check/out/bin/uk-wamr-log-validate" \
WAMR_CI_SUPERVISOR="$PWD/.d/wamr-ci-check/supervisor/bin/wamr-ci-supervisor" \
WAMR_CI_SUPERVISOR_FIXTURE="$PWD/.d/wamr-ci-check/out/bin/wamr-ci-supervisor-fixture" \
  python3 -m unittest discover -s support/build/wamr-native-ci/tests -v
```

`test` is the protected aggregate and requires `-Dtest-root`; `test-pipeline`
runs the real conversion fixtures and two independently isolated private
six-mode synthetic boot-proof fixtures with the same requirement.
`test-unit` runs the package command boundary and native controller/fault
fixtures; it does not run the real package conversion pipeline.

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
An actual native six-guest success gate requires a separate fresh x86/KVM CI worktree
and runtime with the pinned tools, archive, QEMU and firmware; the existing
production Python job remains authoritative until its scheduled cutover.
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

## Differential parity preparation

`test-controller` now includes native source-custody production limits, twelve
physical Bison/consumer/dependency/supervision fault fixtures, and frozen v1/v2
result-parser goldens. `test-controller-limits`,
`test-controller-fault-parity`, and `test-differential-records` run those
suites separately. The matching Python
parser fixtures run with
`python3 -B -m unittest test_differential_parity.DeterministicContracts`
from the tests directory. These goldens contain synthetic records, not guest
boot evidence.

On a host without accessible x86 KVM,
`python3 -B support/build/wamr-native-ci/tests/test_differential_parity.py local`
compares actual Python and native controller CLI refusals in separate private
roots. Its three documented legacy-CLI exceptions require exact refusal
versus closed-grammar usage outcomes; they do not make a failed controller
run successful. The `full` action requires separate clean worktrees, real
pinned tools and WAMR source, an empty private `.d` output role in each
worktree, an owner-only runtime template and portable controller, and
accessible x86 KVM. The protected x86 job installs that
controller from its isolated fixture worktree into a separate private root,
then runs one paired six-mode success case after the Python production boot
within the same managed, non-root KVM process. An unexplained difference fails
the job before the public bundle is published. Passing this one case does not
grant native production authority or invoke Azure. Once the production job
passes, four separate bounded, credential-free x86/KVM matrix jobs run paired
`build-start-tamper`, `missing-build`, `occupied-boot-slot`, and
`prior-build-output` cases from fresh worktrees. Each retains strict fault
and evidence parity; there is no TCG or successful-skip fallback.
The different Python/native supervised build commands, controller closures,
local-boot installation paths, and native-only boot-input validator role are
checked against their own exact physical contracts; each QCOW2 acceptance
binds its own boot-input record rather than treating different hashes as equal.
Shared production executables are built without path-dependent debug sections
outside Debug mode so separately cached ReleaseSafe builds retain identical
bytes for strict paired tool and boot-input custody.
Protected paired runs print only closed stage-start and stage-completion
labels to identify which of the four real controller invocations has exhausted
the bounded step deadline. Failed paired builds and boots report only per-side
exit classes, evidence and artifact names, and path-free refusal or static
native error markers. Artifact differences identify only the fixed role and
changed size, hash or mode field; a config hash mismatch is additionally marked
when rechecked config bytes differ only by the source-root path, without
normalizing acceptance. A changed build image record also identifies only
fixed config, input, tool or image-file roles, without exposing their values
or relaxing the byte comparison. Private command logs remain local.

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
the native supervisor result fields and guarded producer maps.
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

The expensive production-boundary module
`tests/source_custody_production_limits.py` is intentionally excluded from
default discovery and runs explicitly in protected CI. Its single PID-scoped
`/d` fixture combines 131,072-entry and 8-GiB sparse-file exact/excess checks,
constructs real exact/first-excess 8-MiB Git ignored inventories, and covers
the 1,024-byte path, 64-component and 128-root diagnostic boundaries. It uses
sparse allocation, emits no large payloads, and removes only its exact fixture
directory.
