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

The source must be clean and committed before building. Records bind the
Unikraft revision/tree, app-source hashes, pinned WAMR/compiler options,
actual tools, wasm/cwasm/compiler/library bytes, solved configuration,
entire EFI/debug ELF/bootinfo, native package producer, QEMU and OVMF,
complete raw/VHD/footer, and each request/report/raw serial. Inputs are
reverified after the four boots and physical package reload. The final result
hashes earlier records only, **not itself**. These are local build/compute
observations, not authenticated source attestations or deployment receipts.

## Bounds and diagnostics

Writable build, package, firmware and boot slots are under the checkout's
ignored `.d/wamr-native-runtime` or the app's ignored `build/`. Zig's
source-pinned dependency restoration also uses this helper's ignored `zig-pkg/`.
Build commands use `-j2`; the workflow has a 60-minute ceiling. Each build
command has a fixed deadline and an 8-MiB log limit (one extra byte detects
overflow). The native packaging worker retains its 120-second deadline and
independent two-second cleanup budget. Each native boot is limited to 60
seconds with the existing independent cleanup budget; an outer 660-second
compute ceiling also bounds the orchestration and post-exit hashing.
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
mkdir -p .d/wamr-ci-check/cache .d/wamr-ci-check/global-cache/tmp \
  .d/wamr-ci-check/scratch
export TMPDIR="$PWD/.d/wamr-ci-check/scratch"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.d/wamr-ci-check/global-cache"
zig build --build-file support/build/wamr-native-ci/build.zig \
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
After all four genuine boots, while the complete runner files still exist,
the workflow invokes the production private export and native handoff checker,
then copies only its closed image/local-evidence allowlist into a standalone
ZIP. It reopens, re-extracts and natively reconciles the ZIP before upload.

Artifact name:
`wamr-public-source-tiny-RUN_ID-RUN_ATTEMPT-SOURCE_SHA`.
Its sole uploaded file is `tiny-aot-public-source.zip`, stored for seven days.
It contains the 17 exact image/compiler/runtime/config/manifest artifacts,
four original serial/request/report/compute sets, the fixed 20 earlier local
JSON records, portable `bundle.json`, and `public-source.json` (55 regular
files, at most 512 MiB total). Member names, modes/types, individual sizes,
complete SHA256/EOF, source/run bindings and successful receipts are checked.
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

Download and import as described in the operator documentation. The importer
requires independently selected source/tree/run/attempt values, safely copies
only bounded regular members to a fresh private directory, rebuilds local
artifact references (not original requests), and uses the production native
checker before publishing a usable `bundle.json`. Its plan remains
`authority=not_admitted`; new final artifact-bound human approval is required.
