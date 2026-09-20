# WAMR tiny-AOT direct compute: software prerequisite, not permission to run

Refs cataggar/unikraft#170, cataggar/unikraft#177, cataggar/unikraft#156,
cataggar/unikraft#88 and cataggar/wamr#1060. None of this software or its
synthetic tests establishes an Azure deployment. Earlier native boot metadata
is **not reusable disk bytes**, an Azure receipt, or a grant to launch this
controller.

`uk-wamr-direct-validate` keeps explicit evidence dispatch for legacy bundle
version 1 purpose `tiny-aot-two-boot` and current bundle/candidate version 2
profile `qcow2-derived-vhd`. Version 1 remains the old four-mode
raw/package-VHD contract; it cannot satisfy version 2. Version 2 requires raw
and finalized QCOW2 normal/masked-x2APIC boots, an acceptance gate, derivation
from that exact accepted QCOW2, and derived fixed-VHD normal/masked-x2APIC
boots. Neither evidence version is executable authority. The installed
`uk-wamr-direct-compute` live entry point accepts only
`uk.wamr.azure-execution-admission` version 2, which digest-binds the separate
plan and authorization records described below.
It reuses the native direct route's managed fixed-VHD upload, private process
supervision, create-only custody, bounded deallocate/start lifecycle, owner and
inventory checks, and independently confirmed cleanup. It does **not** relabel
the persistence scope, synthesize a seed, call a Python cloud controller, use
the nested platform-only preflight, or accept caller-supplied ARM templates.
The existing persistence and platform-only contracts remain closed.

## Fixed topology and claim

The embedded `wamr-direct-compute.json` admits one specialized x64 Generation 2
`Standard_D2s_v5` in `northeurope`: one uploaded OS disk, SCSI, `Attach`,
`ReadOnly` caching and `Detach` deletion. There is **no data disk or public IP**.
A private NIC/subnet has no default outbound access; explicit NSG rules deny
all inbound/outbound traffic. There is no OS profile, SSH, guest agent,
cloud-init, guest compiler, VM extension, or guest network service.

Exactly two tiny-AOT boots are separated by the sole deallocate/start.
Allocated observations may be running or stopped, but retained and final
observations must be deallocated. VM resource ID/`vmId`, OS disk resource
ID/`uniqueId`, attachment, ownership tags, geometry and image digest must
remain unchanged. Cleanup rejects unknown inventory, replacements and
ambiguous absence rather than touching third-party resources.

The production `WAMR_NATIVE_COMPUTE=` schema is checked, not a guessed
Hyper-V marker: answer 42, checks 2 (native memory selftest and growth/trap),
terminal 1/detail 2 (unreachable), platform status 0, and zero
**caller-owned** reserved/frame/accessible/allocation accounting. System
page-table accounting is explicitly nonzero, bounded and page aligned; this
does not claim whole-guest teardown or whole-guest memory qualification.
The exact completion line and native startup/return-0 envelope are mandatory.
Hardware, persistence, WASI/CoreMark and failure markers are forbidden.
Malformed, duplicate, unanchored, negative, noisy or reordered compute records
fail. Missing terminal evidence is incomplete, never successful.

No hardware authority, Azure benchmark, CoreMark, JIT, snapshot execution or
optional workload qualification follows from a successful tiny result.

## Build and offline tests

Zig 0.16.0, Linux, existing Python unittest, and the existing native packaging
dependencies suffice. Native tests run on aarch64; x64 build-only is useful
but cannot establish guest execution. These commands do not authenticate or
provision. Keep caches and private state in ignored `.d/`.

```sh
umask 077
mkdir -p .d/wamr-direct/scratch .d/wamr-direct/tests
mkdir -m 0700 .d/wamr-direct/package-fixtures
export TMPDIR="$PWD/.d/wamr-direct/scratch"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p .d/wamr-direct/restore
cp support/tools/hyperv/local_boot/build.zig \
  support/tools/hyperv/local_boot/build.zig.zon .d/wamr-direct/restore/
zig build --build-file .d/wamr-direct/restore/build.zig --fetch=all \
  --cache-dir "$PWD/.d/wamr-direct/restore-cache" \
  --global-cache-dir "$PWD/.d/wamr-direct/global-cache" -j2
zig build --build-file support/tools/hyperv/direct/build.zig \
  --cache-dir "$PWD/.d/wamr-direct/cache" \
  --prefix "$PWD/.d/wamr-direct/tools" -j2 install compute-fixture-tools
zig build --build-file support/build/wamr-native-ci/build.zig \
  --system "$PWD/.d/wamr-direct/restore/zig-pkg" \
  --cache-dir "$PWD/.d/wamr-direct/package-cache" \
  --prefix "$PWD/.d/wamr-direct/package-tools" \
  -Dtest-root="$PWD/.d/wamr-direct/package-fixtures" \
  -Doptimize=ReleaseSafe -j2 test install
SUPERVISOR_SOURCE_SHA256="$(
  python3 - <<'PY'
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
  --system "$PWD/.d/wamr-direct/restore/zig-pkg" \
  --cache-dir "$PWD/.d/wamr-direct/supervisor-cache" \
  --prefix "$PWD/.d/wamr-direct/supervisor" \
  -Dsource-closure-sha256="$SUPERVISOR_SOURCE_SHA256" \
  -Doptimize=ReleaseSafe -j2 install
WAMR_DIRECT_TOOLS="$PWD/.d/wamr-direct/tools/bin" \
WAMR_CI_PACKAGE="$PWD/.d/wamr-direct/package-tools/bin/wamr-ci-package" \
WAMR_CI_SUPERVISOR="$PWD/.d/wamr-direct/supervisor/bin/wamr-ci-supervisor" \
  python3 -m unittest discover -s support/tools/hyperv/direct/tests -v
```

Only `compute-fixture-tools` installs the **non-production** fixture
controller/backend. They reuse the existing native fake CLI and its confined
`.d/` marker, explicit ELF-name checks, fake state, private SAS sentinel and
empty inherited environment. The controller tests cannot dispatch real Azure
or transfer commands. Production has no fixture switch, environment override
or runtime purpose selector. The physical export test uses real native miz
packaging but synthetic nonbootable EFI and synthetic local reports; it
checks custody, not real execution. Ordinary PR CI gains no cloud entry point.
The existing integration job runs these offline fixtures alongside the direct
persistence fixtures; its parent-build evidence collection is unchanged.

## Prepare exact final local bytes

On an appropriate private x86/KVM runner, use the existing credential-free
[native compute lane](../build/wamr-native-ci/README.md) at the **clean,
committed final source**, with the pinned SDK
`a53205d77be3b880eb8f8b96679512ba58e2331a`, unchanged compiler profile and tiny
configuration. Complete all six exact-image local boots (raw/QCOW2/derived
fixed VHD, each with x2APIC and masked x2APIC) and process cleanup. Derivation
is forbidden until both retained QCOW2 boots and all preceding custody have
been revalidated. The WAMR build/boot adapter uses
the retained native command supervisor: ordinary owned children, `setsid`,
double-fork and closed-capture descendants must be gone even after a successful
leader, and any cleanup exhaustion/poison blocks handoff. This detects
accidental or persistent input mutation at the guarded before/after
boundaries; it is not isolation from a hostile same-UID process or PID
namespace. Do not run privilege-sensitive
runner setup on a shared development host.

Before that private runner discards the runtime, export to a fresh private
directory. No earlier metadata-only Actions download can replace this step.

```sh
# RUNTIME already contains a successful, complete native build and six boots.
python3 support/build/wamr-native-ci/handoff.py export \
  --runtime "$RUNTIME" --output "$PRIVATE_PARENT/FRESH-image-handoff"
.d/wamr-direct/tools/bin/uk-wamr-direct-validate handoff \
  "$PRIVATE_PARENT/FRESH-image-handoff/bundle.json"
python3 support/build/wamr-native-ci/handoff.py candidate \
  --bundle "$PRIVATE_PARENT/FRESH-image-handoff/bundle.json" \
  --output "$PRIVATE_PARENT/FRESH-non-authorizing-candidate.json"
```

`export` rechecks the actual source/build/tool inputs, all original result
record hashes, each original request/report/raw serial, and a real physical
native package reload under the existing 150-second/64-KiB inspection bound.
It retains complete EFI/debug ELF/bootinfo, solved config, compiler/runtime,
wasm/cwasm, runtime/image identities, complete raw/QCOW2/derived-fixed-VHD
bytes, finalization/acceptance/derivation/final-inspection records, all earlier
result records, and six original request/report/compute/raw serial sets.
Copies are create-only and fully rehashed; original records are not rewritten.
The resulting bundle binds source revision/tree, SDK, workload/profile inputs,
hashes **and sizes**. The native read-only `handoff` command independently
reopens/hashes the bundle, checks raw-to-QCOW2-to-VHD lineage, the complete
VHD raw prefix/footer/GPT/workload identity and all six bound native results.
Failure leaves incomplete private state for
inspection, never a successful bundle or resumable export.

`candidate` preserves the legacy version-dispatched, non-authorizing scope
used to inspect bundle versions 1 and 2. It emits
**`authority=not_admitted`** and cannot be passed to the production controller
as an Azure authorization. Version 1/tiny scopes, version 2 public bundles,
transport records and local evidence remain evidence only; none is inferred
to be approval. The finite-cost plan described below is a separate canonical
private schema.

Keep operator handoffs and all Azure attempt/campaign data private (0700
directories/0600 files). Private `export` never opts into publication. The
separately authorized [public-source CI image lane](../build/wamr-native-ci/README.md#expressly-authorized-public-source-image-bundle)
now retains only a fixed tiny image/local-outcome allowlist, alongside the
existing redacted metadata artifact. It never uploads operator state, approval
files, Azure/account data, command raw logs or arbitrary private images.

### Download, independently revalidate and plan a public-source CI image

Select a successful **current-source** native CI run and independently verify
its run attempt, tested source commit/tree and six local outcomes. On PRs,
`SOURCE_SHA`/`SOURCE_TREE` identify the tested synthetic merge commit/tree, not
silently the branch head. Retain that distinction in the final approval.
Retain `ARTIFACT_ID`, `ARTIFACT_URL` and the inner-ZIP `ARCHIVE_SHA256` only
from the successful job output/summary published after the workflow
redownloaded that exact artifact ID and matched its inner ZIP digest. The
separately labelled Actions container digest is not the inner digest and is
not an import substitute. Never derive the expected inner digest from a later
downloaded ZIP. Ensure the exact reviewed `SOURCE_SHA` commit object is
available in this repository and verify that it resolves to `SOURCE_TREE`.
Download the exact artifact ID; no old metadata-only artifact supplies the
required bytes. The following commands are offline/GitHub-only, not Azure:

```sh
umask 077
mkdir -p .d/wamr-download
gh api -H "Accept: application/vnd.github+json" \
  "/repos/cataggar/unikraft/actions/artifacts/${ARTIFACT_ID}/zip" \
  > "$PWD/.d/wamr-download/artifact-container.zip"
python3 - "$PWD/.d/wamr-download/artifact-container.zip" \
  "$PWD/.d/wamr-download/tiny-aot-public-source.zip" <<'PY'
import os
from pathlib import Path
import shutil
import sys
import zipfile

container, output = map(Path, sys.argv[1:])
with zipfile.ZipFile(container) as zipped:
    entries = zipped.infolist()
    if (
        len(entries) != 1
        or entries[0].filename != "tiny-aot-public-source.zip"
        or entries[0].is_dir()
        or not 0 < entries[0].file_size <= 512 * 1024 * 1024
    ):
        raise SystemExit("unexpected exact-artifact members")
    with zipped.open(entries[0]) as source, output.open("xb") as target:
        os.fchmod(target.fileno(), 0o600)
        shutil.copyfileobj(source, target, 65536)
        target.flush()
        os.fsync(target.fileno())
PY
python3 support/build/wamr-native-ci/handoff.py import-public-source-bundle \
  --archive "$PWD/.d/wamr-download/tiny-aot-public-source.zip" \
  --output "$PRIVATE_PARENT/FRESH-imported-image" \
  --expected-source "$SOURCE_SHA" --expected-tree "$SOURCE_TREE" \
  --expected-archive-sha256 "$ARCHIVE_SHA256" \
  --run-id "$RUN_ID" --run-attempt "$RUN_ATTEMPT" \
  --validator "$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" \
  --supervisor "$PWD/.d/wamr-direct/supervisor/bin/wamr-ci-supervisor" \
  --artifact-id "$ARTIFACT_ID" \
  --container-digest "$CONTAINER_DIGEST"
"$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" handoff \
  "$PRIVATE_PARENT/FRESH-imported-image/bundle.json"

# Before planning, materialize the reviewed Python/Azure import environment.
# REVIEWED_AZURE_IMPORT_ROOT is an import root (for example a reviewed,
# reduced site-packages tree), not a package directory whose basename is
# needed for import. Repeat --package-root for every distinct import root.
python3 support/build/wamr-native-ci/handoff.py prepare-azure-runtime \
  --output "$PRIVATE_PARENT/FRESH-azure-runtime" \
  --azure "$REVIEWED_PYTHON_AZURE_BOOTSTRAP" \
  --az-python "$REVIEWED_CANONICAL_PYTHON_SOURCE" \
  --stdlib "$REVIEWED_PYTHON_STDLIB_ROOT" \
  --package-root "$REVIEWED_AZURE_IMPORT_ROOT" \
  --validator "$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate"
REVIEWED_CANONICAL_AZ="$PRIVATE_PARENT/FRESH-azure-runtime/runtime/bootstrap/azure-cli"
REVIEWED_CANONICAL_PYTHON="$PRIVATE_PARENT/FRESH-azure-runtime/runtime/bin/python"
REVIEWED_AZURE_RUNTIME="$PRIVATE_PARENT/FRESH-azure-runtime/azure-runtime.json"

mkdir -m 700 "$PRIVATE_PARENT/ORIGINAL-campaign-ledger"
PROPOSED_LEDGER_UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
python3 support/build/wamr-native-ci/handoff.py plan \
  --bundle "$PRIVATE_PARENT/FRESH-imported-image/bundle.json" \
  --candidate-output "$PRIVATE_PARENT/FRESH-candidate.json" \
  --output "$PRIVATE_PARENT/FRESH-execution-plan.json" \
  --approval-template "$PRIVATE_PARENT/FRESH-approval-template.json" \
  --campaign-id "$CAMPAIGN_UUID" \
  --ledger "$PRIVATE_PARENT/ORIGINAL-campaign-ledger" \
  --ledger-id "$PROPOSED_LEDGER_UUID" \
  --subscription "$SUBSCRIPTION_UUID" \
  --prefix "$FRESH_EXACT_PREFIX" \
  --maximum-authorized-cost-microusd "$REQUESTED_MAXIMUM_MICROUSD" \
  --azure "$REVIEWED_CANONICAL_AZ" \
  --uploader "$EXPLICIT_UK_HYPERV_TRANSFER_CLI" \
  --validator "$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" \
  --supervisor "$PWD/.d/wamr-direct/supervisor/bin/wamr-ci-supervisor" \
  --az-python "$REVIEWED_CANONICAL_PYTHON" \
  --azure-runtime "$REVIEWED_AZURE_RUNTIME"
"$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" plan \
  "$PRIVATE_PARENT/FRESH-execution-plan.json" \
  "$PRIVATE_PARENT/FRESH-approval-template.json"
```

The importer requires both locally reviewed native executables explicitly;
there is no `PATH`, environment or sibling-file fallback for either one. It
opens the supervisor no-follow, binds its physical/content identity, requires
the exact native ELF bytes (x86-64 on the hosted runner) and dynamic-runtime
contents recorded by the
accepted build, checks its canonical protocol/source-closure identity against
the accepted source commit/tree, and only then uses it for native validator
revalidation. The importer bounds and
verifies every member and rejects extra files, duplicate or reordered entries,
symlinks, changed
source/image/serial/report/hash or failed local outcomes.
Version 2 additionally binds the trusted inner ZIP digest, exact Actions
artifact ID and separately reported container digest from the exact-ID
redownload. It retains only the closed 85-member public-source set (26
artifacts, 24 boot members, 33 evidence records and two manifests) under the
96-member, 512-MiB and 64-KiB JSON bounds. Legacy version 1 remains exactly 55
members with 20 evidence records.
It also recomputes native-width supervisor invariants, canonical UTF-8 request
and result bindings, empty-stream hashes, and the aggregate stream
count/digest commitment. Nonempty command streams are intentionally absent
from the public archive, so their labelled digests are accepted only as
observations authenticated by the independently selected current inner-ZIP
digest above; they are not claimed to be independently reproducible.
It preserves original bytes and request hashes, changes only the handoff's
local file references, and invokes native production revalidation. An
incomplete import never publishes the final operator `bundle.json`.

`prepare-azure-runtime` is create-only and authority-free. Its `--azure`
input must be a reviewed Python bootstrap that can be run by the explicit
interpreter; do not pass a shell wrapper that selects Python through
`AZ_PYTHON`. It copies the bootstrap, Python ELF, complete standard library,
every repeated Azure package import root and any repeated fixed `--data-root`
into a private Python home. It discovers the interpreter/native-extension
ELF dependencies, rejects embedded RPATH/RUNPATH, audit/filter dependencies
and slash-bearing `DT_NEEDED` entries, and copies the exact dynamic loader and
every DSO under each requested `DT_NEEDED` name into the private home. A loader `--list`
probe must resolve every interpreter dependency below that copied directory.
The files and names are recorded as fixed loader artifacts; an operator may
add a reviewed dependency with `--native-dependency`. No package download,
restore or import-root discovery occurs after preparation.

The resulting `uk.wamr.azure-cli-runtime-closure` version 1 manifest records
canonical roles and paths, file/directory counts, bytes, maximum depth,
content and physical-metadata digests, parent identities, exact launcher,
interpreter, dynamic-loader and manifest artifacts, the loader dependencies,
and the closed Azure command set. Current
limits are 16,384 files, 4,096 directories, 2 GiB total, depth 32, 256 MiB
per file, 256 loader files and a 32-MiB manifest. Symlinks, special files,
hard links, set-ID or group/world-writable files and parents, startup `.pth`,
`sitecustomize.py` and `usercustomize.py` are refused. Source traversal applies
the limits before copying or accumulating an unbounded inventory. Preparation
runs isolated probes for `az version` and every group, disk, deployment, VM,
boot-diagnostics and resource command the controller can issue, then
revalidates the complete closure. A missing lazy command module therefore
refuses before planning. Any later path/content/mode/identity change
invalidates planning or approval.
The prepared empty extension directory is also part of the closure;
`AZURE_EXTENSION_DIR` is fixed to it and dynamic extension installation is
disabled, so operator config cannot import or restore extension code outside
the reviewed runtime.

## Versioned finite-cost authorization

The private unapproved plan is
`uk.wamr.azure-execution-plan` version 2. Native canonical JSON is compact
UTF-8 with byte-sorted keys and one final LF; its SHA-256 is calculated over
those complete bytes and is deliberately not stored inside the plan itself.
The separate `uk.wamr.azure-execution-approval-template` version 2 carries
that external digest. Regenerating or changing the plan therefore changes the
digest and invalidates every earlier template and authorization.

The plan binds the exact version-2 imported candidate, public admission,
85-member public bundle, transport, Actions run/attempt and artifact ID,
source commit/tree, raw-to-QCOW2-to-derived-VHD lineage, QCOW2 and VHD
digests, VHD file length (69,206,528 bytes) and virtual capacity
(69,206,016 bytes), WAMR identities, execution attempt UUID, campaign UUID,
campaign profile and a versioned campaign-ledger identity. That identity
includes the campaign UUID, unique ledger UUID, canonical directory physical
identity, purpose, whether one authorized initialization is required, the
bounded digest of the legacy pre-state and the exact expected marker digest.
The displayed ledger path is not authority. It also binds the exact
subscription and fresh prefix, North Europe `Standard_D2s_v5` Generation 2
topology, one `StandardSSD_LRS` OS disk, no data disk or public IP, private
no-default-outbound networking, one VM, two boots and maximum parallelism one.
Retries and source/image/topology/workload substitution are zero/false.
Cleanup is restricted to the exact owned group and requires a separate
absence observation; replacement resources are forbidden.

All money is an unsigned integer count of **micro-USD**. There are no floats,
NaN/infinity spellings, zero or unbounded sentinels. Policy
`northeurope-standard-d2s-v5-conservative-2026-09-v1` computes:

```text
5,000,000 + ceil((runtime_seconds + cleanup_seconds) / 3600)
            * (2,000,000 * VM count + 250,000 * OS-disk count)
```

For the fixed 3,600-second execution and 1,800-second cleanup bounds this is
9,500,000 micro-USD. The repository maximum is 100,000,000 micro-USD. The
requested authorization maximum must be at least the recomputed estimate and
at most the repository maximum; neither side is silently clamped.

After an operator has obtained a **fresh explicit decision for the exact plan
digest**, record it through the private command. A chat or user response is
not parsed or inferred by this software. The operator deliberately transfers
that decision into the record:

```sh
APPROVED_UNIX="$(date +%s)"
EXPIRES_UNIX="$((APPROVED_UNIX + 3600))"
python3 support/build/wamr-native-ci/handoff.py record-authorization \
  --plan "$PRIVATE_PARENT/FRESH-execution-plan.json" \
  --template "$PRIVATE_PARENT/FRESH-approval-template.json" \
  --output "$PRIVATE_PARENT/FRESH-authorization.json" \
  --decision approved \
  --approver "$BOUNDED_OPERATOR_ID" \
  --reference "$BOUNDED_APPROVAL_REFERENCE" \
  --recorded-unix "$APPROVED_UNIX" \
  --expires-unix "$EXPIRES_UNIX" \
  --azure "$REVIEWED_CANONICAL_AZ" \
  --uploader "$EXPLICIT_UK_HYPERV_TRANSFER_CLI" \
  --validator "$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" \
  --supervisor "$PWD/.d/wamr-direct/supervisor/bin/wamr-ci-supervisor" \
  --az-python "$REVIEWED_CANONICAL_PYTHON" \
  --azure-runtime "$REVIEWED_AZURE_RUNTIME"
python3 support/build/wamr-native-ci/handoff.py admit \
  --plan "$PRIVATE_PARENT/FRESH-execution-plan.json" \
  --authorization "$PRIVATE_PARENT/FRESH-authorization.json" \
  --output "$PRIVATE_PARENT/FRESH-admission.json" \
  --azure "$REVIEWED_CANONICAL_AZ" \
  --uploader "$EXPLICIT_UK_HYPERV_TRANSFER_CLI" \
  --validator "$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" \
  --supervisor "$PWD/.d/wamr-direct/supervisor/bin/wamr-ci-supervisor" \
  --az-python "$REVIEWED_CANONICAL_PYTHON" \
  --azure-runtime "$REVIEWED_AZURE_RUNTIME"
```

`uk.wamr.azure-execution-authorization` version 2 binds the exact plan SHA-256,
attempt, campaign and ledger UUIDs, ledger-initialization decision, candidate
digest, estimated and maximum micro-USD values, resource and time limits,
decision, bounded approver/reference and a maximum one-hour window. Its
mandatory runtime binding includes the closure schema/version,
canonicalization, Python version, document/content/metadata/parent digests,
exact launcher/interpreter/manifest artifacts, limits, observed totals,
loader dependency artifacts and isolation policy; there is no optional module
field or best-effort fallback.
`uk.wamr.azure-execution-admission` version 2 is published only after
the native validator reopens the plan, authorization, candidate, tools and
image lineage and finds every binding equal. Unknown fields, duplicate keys,
noncanonical bytes, denial, future/expired time, a different plan/attempt,
changed cost or limit, or any regenerated digest refuse admission.

This is not a cryptographic identity or signature protocol. Trust comes from
the operator's explicit command invocation, reviewed local executable paths
and private 0700/0600 file custody. If stronger authenticated multi-party
approval is required, it must be supplied outside this contract and named in
the bounded reference.

Plan, template, authorization, admission and candidate are private operator
records. They are not members of the fixed 85-member public bundle, its
allowlist or redownload summary.

## Final approval, run and cleanup boundary

Before seeking approval, use the shared [local CLI startup preflight](DIRECT-TWO-BOOT.md#local-cli-startup-before-consumption):

```sh
umask 077
mkdir -m 700 "$PRIVATE_PARENT/FRESH-cli-startup"
"$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-compute" preflight \
  "$PRIVATE_PARENT/FRESH-cli-startup" "$REVIEWED_CANONICAL_AZ" \
  --az-python "$REVIEWED_CANONICAL_PYTHON" \
  --azure-runtime "$REVIEWED_AZURE_RUNTIME"
```

The explicit interpreter is required by the finite-cost route. Use reviewed
canonical executable paths, not a symlinked version alias or unchecked ambient
variables. The interpreter is pinned/rechecked, while arbitrary Python
settings and loader hooks remain excluded. The only child command is bounded
local `az version`;
passing does not authenticate an account, inspect resources, consume an attempt
or authorize Azure use. Raw output and tool identities remain private.

Create the reviewed persistent campaign ledger once, mode 0700, before
planning; for an existing campaign use the original ledger unchanged.
Do not confuse this existing ledger with the required **nonexistent** attempt
directory. A missing ledger is a pre-admission refusal with a sanitized reason.
Planning is authority-free and never creates or changes the identity marker.
For a legacy ledger without a marker, the plan exposes
`ledger.initialization_required=true`, the proposed ledger UUID and the exact
bounded legacy pre-state digest. Explicit authorization approves that one
initialization as well as the attempt. After complete admission, candidate
and tool validation, execution atomically creates
`ledger-identity.json` and the create-once
`ledger-identity.initialized` sentinel before creating any claim. Both are
fsynced, private and bound to the campaign, ledger UUID, purpose and initial
state. Initialization occurs only after the bounded local CLI startup and a
final admission/scope/tool recheck. Marker initialization is an authorized
durable transition: it may remain if a later claim or backend operation
fails, but it does not itself consume a claim.

All later plans expose `initialization_required=false` and the established
ledger UUID. A missing/replaced marker, a marker for another campaign or
ledger, a stale legacy pre-state, or a remaining sentinel without its marker
refuses; an initialized ledger is never silently reinitialized. Execution
opens the ledger once and retains that directory descriptor through identity
validation, eligibility, claim creation and outcome recording, so replacing
the pathname cannot substitute another ledger.

The initial explicitly approved tiny attempt failed before resource creation
because the selected tarball CLI needed an interpreter that the restricted
environment correctly did not inherit. That attempt's reservations remain
consumed, its records and grant are frozen, and it established no VM boot or
Azure compute result. This software fix grants no retry. A subsequent live
invocation needs fresh approval even if the old window has not expired; it
must still use the same persistent ledger and satisfy its unchanged
attempt/source-tree/image consumption rules. Do not clear/copy/substitute
claims or reinterpret the old failure as an unconsumed attempt.

Planning ceilings (USD1000/72h/three concurrent campaign VMs), Azure
authentication, provider/quota availability, old grants and earlier images are
**not** execution authority. This adapter is deliberately smaller: one VM,
one attempt, execution at most 3600 seconds and independent cleanup at most
1800 seconds; individual calls retain the direct route's maximum 600 seconds.
It implements no campaign batching or automatic retries.

The only live interface (shown for later approved use, **not an instruction
to execute now**) is:

```text
uk-wamr-direct-compute PRIVATE_ADMISSION_JSON FRESH_ATTEMPT_DIR CAMPAIGN_LEDGER \
  EXPLICIT_AZ_EXECUTABLE EXPLICIT_UK_HYPERV_TRANSFER_CLI \
  EXPLICIT_UK_WAMR_DIRECT_VALIDATE EXPLICIT_WAMR_CI_SUPERVISOR \
    --az-python EXPLICIT_CLOSURE_INTERPRETER \
    --azure-runtime EXPLICIT_AZURE_RUNTIME_CLOSURE_JSON
```

Before creating the attempt directory, the production entry point
opens the admission once through canonical no-follow custody, retains and
parses those exact bytes, and binds their metadata and SHA-256. It copies only
those retained bytes into the create-only attempt scope, reopens and rehashes
the copy, revalidates the original retained identity, rehashes the plan and
authorization, checks expiry, finite cost and repository policy, validates
the exact candidate, runtime and tool bindings, seals the runtime, and only
then performs the first read-only ledger eligibility check. Runtime
verification, namespace setup, copying, read-only remounting, loader
isolation or capability-drop failure therefore reaches neither ledger access
nor backend invocation. It then
checks bundle/input custody and bounded clean-environment CLI startup before
consuming attempt/source-tree/image reservations and before the first Azure
resource call. Malformed, missing, stale, denied, wrong-plan, wrong-attempt or
wrong-cost authorization reaches neither ledger mutation nor backend
invocation. Reservations are retained on later failure. A fresh attempt
directory is mandatory; neither resume nor an automatic retry exists.

Every executable and parent component is canonical, no-follow and retained;
group/world-writable, set-ID, non-regular, hard-linked or replaced files
refuse. Execution tools must be owned by the invoking UID. The user-namespace
view accepts the kernel overflow owner only for safe-mode directory ancestors,
never for a final execution tool. Runtime ancestors additionally must
reproduce the authorization's aggregate host-identity digest, so an
other-user ancestor cannot be reinterpreted as host root. Native ELF uploader,
validator and supervisor execution uses retained sealed descriptor snapshots
with `execveat`. Before admission the controller
re-execs in a private user/mount namespace, copies the authenticated Azure
runtime to bounded tmpfs, remounts it read-only, and drops namespace
capabilities. The initial process must have full host UID/GID maps. The
re-exec marker is accepted only from its exact live parent with exact one-ID
UID/GID kernel maps, disabled setgroups, private root-mount propagation and a
parent still in the initial user namespace. That controller marker cannot be
replaced by the separate native-validator child marker, which requires the
same exact maps plus an untraced, zero-capability `no_new_privs` process and
parent. Azure calls use
`--inhibit-cache --inhibit-rpath ''`, execute the retained copied loader with
only copied DSOs, refuse any system `ld.so.preload`, and mask host loader
directories in the private mount namespace. Python, bootstrap, modules, data
and native extensions are addressed below the retained root as
`/proc/self/fd/N/...`. Neither the
original Azure script/interpreter pathname, `AZ_PYTHON`, loader cache,
RPATH/RUNPATH nor an ambient/default library path is execution authority. The
child uses `-s -S -B -P`, no ambient/user
site or `PYTHONPATH`, no startup/bytecode hooks, no loader injection and no
post-custody package restore. Both the original closure and immutable
execution copy are rehashed immediately before and after every Azure
consumer, including cleanup and the final absence observation. Retained
descriptors also revalidate every approved original-source ancestor at each
boundary.
Before Boot2 it revalidates inputs, original Boot1 bytes, VM/disk identities,
deallocation, scope/expiry and durable start admission. `azure_cumulative`
allows only the exact Boot1 prefix excluding terminal NUL padding to be
overwritten by appended bytes. The complete original serial remains pinned;
cached reads cannot establish another boot. Per-boot and strict cumulative
modes are also explicit, never auto-detected.
Offline fixtures include byte-identical deterministic WAMR output for both
boots: only a complete **second appended frame** establishes Boot2, and a
cached-first-only stream expires/refuses. This does not prove Azure retains
cumulative diagnostic bytes. If Azure resets its diagnostic log after
deallocate/start, an approved `azure_cumulative` attempt fails closed; there
is no automatic mode switch, reused-Boot1 acceptance or requirement that the
workload artificially vary its output. A different mode would need separate
concrete approval, not postrun reinterpretation.

Cleanup starts independently even after a failed primary lane. It rechecks
exact group ownership, allowlisted inventory and known immutable VM/disk
identities before revocation/deletion, then independently requires explicit
group absence. An uncertain observation, foreign replacement or failed
cleanup leaves failure evidence, not an absent/success-shaped fallback.
The bounded upload SAS is private, never an argument/public record, and is
removed with other capabilities after revocation/cleanup. See
[the shared direct engine](DIRECT-TWO-BOOT.md) for process/custody and
failure-only diagnostic semantics; persistence seed authorization does not
apply to this separate lane.

Private `bootN-compute.json` records bind each checked result to attempt,
expiry, raw serial bytes/hash, scope hash, VM and OS disk IDs/immutable IDs.
`bootN-capture.json` pins these records, original full serial, wrapper and VM
observations. Boot2 admission pins retained identities/deallocation and Boot1
evidence. `outcome.json` uses `uk.wamr.direct-compute-result` and separates
primary/cleanup status, compute completion, cached-read count and confirmed
owned-group absence; process/capture/recording failures remain independently
visible. Acceptance requires two complete results, final input verification,
durable recording and confirmed cleanup. Failure-only diagnostics never count
as a boot result.
