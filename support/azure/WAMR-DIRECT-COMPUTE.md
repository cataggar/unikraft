# WAMR tiny-AOT direct compute: software prerequisite, not permission to run

Refs cataggar/unikraft#156 and cataggar/unikraft#88. Neither acceptance issue is
completed by this software or its synthetic tests. No Azure deployment is
established here. Earlier native four-boot metadata is **not reusable disk
bytes**, an Azure receipt, or a grant to launch this controller.

`uk-wamr-direct-compute` is a separate, purpose-specific executable. Its
compile-time contract is `uk.wamr.direct-compute`, purpose `tiny-aot-two-boot`.
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
export TMPDIR="$PWD/.d/wamr-direct/scratch"
export PYTHONDONTWRITEBYTECODE=1
zig build --build-file support/tools/hyperv/direct/build.zig \
  --cache-dir "$PWD/.d/wamr-direct/cache" \
  --prefix "$PWD/.d/wamr-direct/tools" -j2 install compute-fixture-tools
zig build --build-file support/build/wamr-native-ci/build.zig \
  --cache-dir "$PWD/.d/wamr-direct/package-cache" \
  --prefix "$PWD/.d/wamr-direct/package-tools" \
  -Doptimize=ReleaseSafe -j2 test install
WAMR_DIRECT_TOOLS="$PWD/.d/wamr-direct/tools/bin" \
WAMR_CI_PACKAGE="$PWD/.d/wamr-direct/package-tools/bin/wamr-ci-package" \
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
configuration. Complete all four exact-image local boots (raw/VPC, each with
x2APIC and masked x2APIC) and process cleanup. Do not run privilege-sensitive
runner setup on a shared development host.

Before that private runner discards the runtime, export to a fresh private
directory. No earlier metadata-only Actions download can replace this step.

```sh
# RUNTIME already contains a successful, complete native build and four boots.
python3 support/build/wamr-native-ci/handoff.py export \
  --runtime "$RUNTIME" --output "$PRIVATE_PARENT/FRESH-image-handoff"
.d/wamr-direct/tools/bin/uk-wamr-direct-validate handoff \
  "$PRIVATE_PARENT/FRESH-image-handoff/bundle.json"
python3 support/build/wamr-native-ci/handoff.py plan \
  --bundle "$PRIVATE_PARENT/FRESH-image-handoff/bundle.json" \
  --output "$PRIVATE_PARENT/FRESH-unapproved-plan.json"
```

`export` rechecks the actual source/build/tool inputs, all original result
record hashes, each original request/report/raw serial, and a real physical
native package reload under the existing 150-second/64-KiB inspection bound.
It retains complete EFI/debug ELF/bootinfo, solved config, compiler/runtime,
wasm/cwasm, runtime/image identities, complete raw/fixed-VHD bytes, all earlier
result records, and four original request/report/compute/raw serial sets.
Copies are create-only and fully rehashed; original records are not rewritten.
The resulting bundle binds source revision/tree, SDK, workload/profile inputs,
hashes **and sizes**. The native read-only `handoff` command independently
reopens/hashes the bundle, checks raw-prefix/footer relationships and validates
all four bound native results. Failure leaves incomplete private state for
inspection, never a successful bundle or resumable export.

`plan` rehashes retained files and emits **`authority=not_admitted`**, all
approval flags false, zero approval/expiry times, a fresh attempt UUID, and
non-executable subscription/name placeholders. It neither calls Azure nor
fabricates approval, guest measurements or cloud receipts. Local records
remain `local_native_compute_only`, not Azure evidence. This is an operator
review handoff, not an authenticated build/source attestation. Native
verification checks the recorded relationships; the human must review the
actual final build provenance and local execution before granting cloud use.

Keep operator handoffs and all Azure attempt/campaign data private (0700
directories/0600 files). Private `export` never opts into publication. The
separately authorized [public-source CI image lane](../build/wamr-native-ci/README.md#expressly-authorized-public-source-image-bundle)
now retains only a fixed tiny image/local-outcome allowlist, alongside the
existing redacted metadata artifact. It never uploads operator state, approval
files, Azure/account data, command raw logs or arbitrary private images.

### Download, independently revalidate and plan a public-source CI image

Select a successful **current-source** native CI run and independently verify
its run attempt, tested source commit/tree and four local outcomes. On PRs,
`SOURCE_SHA`/`SOURCE_TREE` identify the tested synthetic merge commit/tree, not
silently the branch head. Retain that distinction in the final approval.
Download only the named artifact; no old metadata-only artifact supplies the
required bytes. The following commands are offline/GitHub-only, not Azure:

```sh
umask 077
mkdir -p .d/wamr-download
gh run download "$RUN_ID" --repo cataggar/unikraft \
  --name "wamr-public-source-tiny-${RUN_ID}-${RUN_ATTEMPT}-${SOURCE_SHA}" \
  --dir "$PWD/.d/wamr-download"
python3 support/build/wamr-native-ci/handoff.py import-public-source-bundle \
  --archive "$PWD/.d/wamr-download/tiny-aot-public-source.zip" \
  --output "$PRIVATE_PARENT/FRESH-imported-image" \
  --expected-source "$SOURCE_SHA" --expected-tree "$SOURCE_TREE" \
  --run-id "$RUN_ID" --run-attempt "$RUN_ATTEMPT" \
  --validator "$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate"
"$PWD/.d/wamr-direct/tools/bin/uk-wamr-direct-validate" handoff \
  "$PRIVATE_PARENT/FRESH-imported-image/bundle.json"
python3 support/build/wamr-native-ci/handoff.py plan \
  --bundle "$PRIVATE_PARENT/FRESH-imported-image/bundle.json" \
  --output "$PRIVATE_PARENT/FRESH-unapproved-plan.json"
```

The importer bounds and verifies every member and rejects extra files,
symlinks, changed source/image/serial/report/hash or failed local outcomes.
It preserves original bytes and request hashes, changes only the handoff's
local file references, and invokes native production revalidation. An
incomplete import never publishes the final operator `bundle.json`.

## Final approval, run and cleanup boundary

Planning ceilings (USD1000/72h/three concurrent campaign VMs), Azure
authentication, provider/quota availability, old grants and earlier images are
**not** execution authority. This adapter is deliberately smaller: one VM,
one attempt, execution at most 3600 seconds and independent cleanup at most
1800 seconds; individual calls retain the direct route's maximum 600 seconds.
It implements no campaign batching or automatic retries.

After reviewing the **concrete final bundle** and exact subscription, fresh
resource names, region/SKU and cleanup plan, a human must separately approve a
private scope copied from the plan:

* Set `authority` to `final_image_approved`, retain the exact source,
  identity, `os_vhd` and `bundle` artifacts, and approve every named boolean
  in `approval`, including `fresh_final_approval`.
* Set `approved_unix` to the actual approval time and `expires_unix` to a
  future deadline no more than 3600 seconds later. Future-dated, expired and
  oversized windows are refused. No approval is supplied by this PR.
* Replace the subscription/name placeholders with explicitly approved values.
  Choose one persistent private campaign ledger and one nonexistent attempt
  directory. Do not select another ledger to defeat consumption.

The only live interface (shown for later approved use, **not an instruction
to execute now**) is:

```text
uk-wamr-direct-compute APPROVED_SCOPE_JSON FRESH_ATTEMPT_DIR CAMPAIGN_LEDGER \
  EXPLICIT_AZ_EXECUTABLE EXPLICIT_UK_HYPERV_TRANSFER_CLI \
  EXPLICIT_UK_WAMR_DIRECT_VALIDATE
```

The engine checks source scope custody, approval, bundle and exact inputs
before consuming attempt/source-tree/image reservations in that ledger and
before the first Azure call. Reservations are retained on failure. A fresh
attempt directory is mandatory; neither resume nor an automatic retry exists.
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
