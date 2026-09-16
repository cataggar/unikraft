# Credential-free tiny native WAMR PR gate

Refs #156. `wamr-native-compute.yaml` is an **additive ordinary
`pull_request` job**, including the native integration's stacked base.
It has only `contents: read`, a GitHub-hosted Ubuntu 24.04 x86 runner, no
protected environment, no dispatch, no cloud identity and no upload/deployment
entry. All existing required contexts, default images and safety gates stay
unchanged. This does not complete #88's guarded Azure authority or image handoff.

The job builds the distinct `hyperv-x86_64-efi-wamr` target using the
app-owned `prepare.py` and `build-image.py`, pinned WAMR
`2399694fb7ed11fffff0a34c82172dfdd54d7439`, Zig 0.16.0, the existing LLVM
distribution and the native final-image graph. Its constructor/returning-IRQ,
SMP, relocation and EFI checks are not replaced, mocked or disabled.
There is no guest compiler or hosted-runtime substitute. Only the tiny
answer/growth/trap/native-memory-selftest mode is enabled; CoreMark, native
benchmarks and JIT workloads are deliberately separate.

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
The seven-day Actions artifact includes only explicit `compute/evidence/*.json`:
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
