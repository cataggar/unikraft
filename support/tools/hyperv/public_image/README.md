# Native public image preparation and export

Standalone Zig 0.16 implementation of the selected public CI `prepare`,
four-mode matrix assertion, and `export-prepared` operations. It uses the
pinned **native miz library**, core private-file/canonical-JSON/process helpers,
native Kconfig/ELF readers, and the native `local_boot` runner. It does not
execute miz, Python, a shell, an SDK, an HTTP client, or a credential provider.

**This produces public local packaging evidence, not VMBus/StorVSC/NetVSC,
Azure, #120 or #89 acceptance.** It is not the private preparation engine,
completed preflight loader, signed-image admission, or a live authority entry.
Neither a local state file nor a caller-constructed Zig struct is an
unforgeable capability. External GitHub source/attestation verification and
all private image/operator/authority gates remain separate.

## Commands and integration

Paths must be explicit, absolute, canonical, and free of symlink components.
Resolve QEMU/OVMF symlinks before invoking the CLI. The source EFI, QEMU,
firmware and optional solved config use the core public artifact policy:
regular files, safe ancestors, no group/world writes. QEMU and the running
producer must pass the native ELF reader. The state directory must **not
exist**; its parent must exist. The CLI creates it mode 0700 and keeps a stable
writer lock. There is no resume, automatic retry, adoption, or overwrite.

```text
uk-hyperv-public-image prepare \
  --efi /canonical/public/hyperv-acceptance.efi \
  --qemu /canonical/qemu-system-x86_64 \
  --ovmf-code /canonical/OVMF_CODE_4M.fd \
  --ovmf-vars /canonical/OVMF_VARS_4M.fd \
  --state-dir /canonical/private/packaging --timeout 60

uk-hyperv-public-image validate-matrix \
  --state-dir /canonical/private/packaging

uk-hyperv-public-image export-prepared \
  --state-dir /canonical/private/packaging \
  --artifact-dir /canonical/public/export \
  --source-repository cataggar/unikraft --source-repository-id 123 \
  --source-workflow-ref cataggar/unikraft/.github/workflows/integration.yaml@refs/heads/main \
  --source-job zig-hyperv --source-run-id 456 --source-run-attempt 1 \
  --source-head-sha 0123456789abcdef0123456789abcdef01234567
```

Add `--solved-config /canonical/public/hyperv-acceptance.config` for the public
network-application packaging contract. `--expect` optionally selects a
printable platform marker (default `UK_HYPERV_PLATFORM_READY`). Timeout is
exact decimal seconds, 0.001 through 120 with at most three fractional digits;
default 30, selected CI value 60. Each boot uses one CPU. The separate native
two-CPU raw SMP proof is not part of this four-boot matrix.

The native implementation embeds miz: **remove the old `--miz` argument**.
It rejects unused tool paths, fixture/runtime overrides, arbitrary arguments,
and unknown/duplicate options. Internal `--package-worker` and `--exec`
dispatch require a canonical private typed job, the actual parent PID/group
and parent-death signal, and the parent-held writer lock. They are not general
worker entry points.

Successful export stdout is **only the lowercase 64-character SHA256 of the
exact manifest bytes plus LF**, suitable for checked shell capture. Prepare
and matrix commands emit bounded canonical JSON. Failures contain only
enumerated core stages/categories with independent primary, cleanup and
recording lanes; no raw errors, input paths, process output or environment.
Exit 0 is success, 1 an execution/export failure, 2 a refusal, and 3 a failure
to deliver the diagnostic. Always require exit 0.

### Deliberate producer compatibility boundary

Export keeps the existing two artifact names, schema
`unikraft.hyperv.prepared-image`, **schema version 2**, artifact/packaging
shapes, GitHub source fields, and raw/network-application contracts. Source
integers are exact positive u64, head SHA is lowercase 40 or 64 hex, workflow
must belong to the specified repository under `.github/workflows/` at a
bounded `refs/...` revision without `..`, and the selected job is `zig-hyperv`.
Manifest bytes use sorted compact ASCII keys/values and one LF.

**Native controller revision is 4, not 3.** Revision 3's existing Python
validator requires a fingerprint of two Python controllers and two ARM
templates. Those are not this producer. Revision 4 sets `controller_sha256`
to the physically reverified native executable SHA256;
`artifacts.miz.sha256` identifies that same executable containing embedded
miz, rather than an unused external miz CLI. `artifacts.miz.revision` remains
`2db68ca0c3ab12155012a823c3fb8d7aba1cb544`, with its exact package hash pinned
in `build.zig.zon`.

Consequently the **unchanged legacy revision-3 importer intentionally
rejects this export**. Parent integration must explicitly admit native
revision-4 producer/embedded-miz semantics and independently expected
GitHub source plus attestation subject digest; accepting an arbitrary
caller-supplied producer hash is not sufficient. This package does not
silently impersonate revision 3 or change legacy import/network behavior.
Root CLI assembly, workflow selectors, producer maps and importer migration
are not edited here. The workflow's inline Python matrix assertion can become
`validate-matrix`; `prepare` already requires the entire matrix.

## Actual preparation and physical reload

Native miz builds a 64-MiB FAT32 ESP in a **66-MiB GPT raw disk**, and a
**66-MiB + 512-byte fixed VHD**. Separate deterministic builds must have
identical complete raw/VHD-prefix hashes. The native fixed-VHD checker
independently checks footer, GPT, FAT, fallback x86_64 PE/EFI, EFI bytes, ESP
offset/length and exact virtual/file geometry. No guest image or seed is
downloaded, regenerated or borrowed. Public source EFI bytes are copied once
to private `BOOTX64.EFI`; the original is rehashed.

An exclusive private package stage contains miz's outputs/temporaries.
Artifacts are normalized to 0600, fsynced, structurally checked, and published
without replacement. The native packaging leaf is supervised for at most
120 seconds, with an independent two-second TERM/KILL/reap cleanup budget.
It never spawns another supervisor. Its file-size limit is the exact fixed
VHD size. The parent orchestrates four independent single-exec local leaves,
not nested supervisor process groups:

| Disk | APIC setting | QEMU block node |
| --- | --- | --- |
| raw | x2APIC | read-only `raw`, offset 0, exact full size |
| raw | legacy xAPIC | same raw node, `x2apic=off` |
| fixed VHD | x2APIC | read-only **`vpc`**, `force-size=true` |
| fixed VHD | legacy xAPIC | same vpc node, `x2apic=off` |

Both disk modes retain the complete original O_RDONLY descriptor, including
the VHD footer, without copying/slicing it for a boot. VPC has no raw offset
or size option. This deliberately corrects the legacy helper which labeled
a raw prefix of the VHD as VPC coverage. Every source byte and named-file
identity is checked by the local runner before/after QEMU. Firmware variables
are separate private copies for every boot; no NIC, user config, reboot,
display or monitor is enabled.

Serial requires the actual ordered Hyper-V/application-start milestones,
one exact platform marker, the expected APIC marker presence/absence, no
crash/live-I/O claims, and a unique anchored **`main returned 2`**. Return 2
is the selected acceptance application's local storage+network-unavailable
result, not arbitrary nonzero success. The real ukprint terminal envelope
is parsed by `local_boot`; 20, duplicate/spoofed/trailing-garbage returns do
not pass. The raw bytes are never normalized for hashing or export binding.

The optional network configuration uses native typed parsing of its five
selected settings, with a hash of the **entire** solved config. Unrelated
Kconfig symbols are not reinterpreted. Duplicate/missing settings, nonprivate
or noncanonical IPv4, invalid/equal ports and malformed nonce refuse.
The native UKNA-v1 request/response transcript reproduces the public peer
header/body protocol: 3 TCP connections, 6 UDP datagrams, 1760 TCP bytes and
3408 UDP bytes per direction. The public peer script's bytes are hashed at
build time, never executed. Every log needs one exact matching CONFIG record
before return and must not claim NETWORK_APP_FINAL PASS or live network/I/O
readiness.

State schema `unikraft.hyperv.native-public-preparation` version 1 records
`preparing`, `prepared` or `failed`, native producer/input fingerprints,
packaging, four ordered request/report/raw-log hash bindings, and failure
lanes. A create-only `prepare.json` precedes effects. A failed/partial state
cannot become an export or a new attempt. A completed reload reopens and
validates the immutable initial request, native package job/launch/report,
packaging JSON, copied and original EFI, raw/VHD relation, original tools and
firmware, solved config, and all four exact boot requests/reports/launches/
raw logs. It does not trust the stored success booleans alone.

Bounded raw logs remain in each `boot-{raw,vpc}-{x2apic,legacy-apic}` directory
on failure, and are also copied to the matching top-level
`local-*-serial.log` after confirmed process reaping. `packaging.json`
preserves the existing miz report shape. Native miz has no subprocess
`miz-*.log`; `package-job.json`, `package-launched`, `package-report.json`
and `state.json` replace that evidence. Failed pipe capture is never used
as guest serial. Each log is at most 4 MiB, each record 64 KiB, solved config
1 MiB, EFI/tool 64 MiB, code 16 MiB, variables 4 MiB. Hashing/copy uses
32-KiB buffers; no full raw/VHD allocation occurs.

Export holds the original lock during physical reload, stages exactly
`prepared-image-manifest.json` and `unikraft.vhd` in a private sibling
directory, fsyncs both, and publishes the directory with no-replace rename
and parent fsync. Collisions never overwrite an artifact. Publication/
cleanup/recording failure yields no digest; a post-rename fsync failure may
leave the two-file directory present and must not be treated as success.

Local admission/post-exit/readonly reload filesystem work is size-bounded,
not claimed to interrupt a stalled filesystem syscall. CI should retain an
outer command ceiling covering that work (as for the local SMP driver).
Core interrupts running leaves and cleans their owned descendant groups.
Unresolved reaping poisons supervision and retains lock custody; there is
no automatic replay. Abrupt supervisor/host loss is not a crash-recovery
proof. None of these public limits reallocates a private staging/upload
ledger or establishes live authority.

## Module API

`root.zig` exports `contracts`, `files`, `network`, `package`, `engine`,
`worker`, `manifest`, `boot` and `core`. Use an arena per bounded command.

- `engine.prepare(a, io, contracts.Input, Options)!State`: requires dedicated
  `core.process.initialize()`; `Options` contains the actual producer path
  and optional atomic cancellation flag. Performs real native packaging and
  four boots, returning phase plus independent failure lanes.
- `engine.load(a, io, *core.private_files.Locked, actual_self_path)!State`:
  read-only physical preparation/matrix validation while caller holds the lock.
- `manifest.publish(a, io, lock, actual_self_path, artifact_dir, Source)Result`:
  performs the physical load and durable no-clobber export; result is
  optional raw32 SHA256 plus independent failures.
- `manifest.validate(a, bytes, independently_expected_source, producer_hash)`:
  strict canonical native-v4 **manifest-only** validation, not artifact,
  attestation or authority admission. `manifest.build` only formats a state;
  callers must not substitute it for physical `publish`.
- `package.build`/`observe`, `network.fromConfig`/`serial`, and
  `engine.bootConfig` expose the focused native primitives. Only trusted
  orchestration should invoke them; no production fixture switch exists.

## Focused offline fixtures

Use only explicitly owned scratch, Zig 0.16 and `-j2`. Dependency restore is
from copied manifests, followed by `--system`; no SDK checkout is modified:

```sh
S="$PWD/.d/zig-migration-public-image"
umask 077
mkdir -p "$S"/home "$S"/tmp "$S"/cache "$S"/global-cache/tmp \
  "$S"/restore "$S"/fixtures "$S"/outputs
export HOME="$S/home" TMPDIR="$S/tmp" XDG_CACHE_HOME="$S/cache"
export ZIG_LOCAL_CACHE_DIR="$S/cache" ZIG_GLOBAL_CACHE_DIR="$S/global-cache"
cp support/tools/hyperv/public_image/build.zig \
  support/tools/hyperv/public_image/build.zig.zon "$S/restore/"
zig build --build-file "$S/restore/build.zig" --fetch=all -j2
zig build --build-file support/tools/hyperv/public_image/build.zig \
  --system "$S/restore/zig-pkg" --prefix "$S/outputs/debug" \
  -Dtest-root="$S/fixtures" -j2 test install --summary all
zig build --build-file support/tools/hyperv/public_image/build.zig \
  --system "$S/restore/zig-pkg" --prefix "$S/outputs/release" \
  -Dtest-root="$S/fixtures" -Doptimize=ReleaseSafe -j2 test install --summary all
zig build --build-file support/tools/hyperv/local_boot/build.zig \
  --prefix "$S/outputs/local-debug" -Dtest-root="$S/fixtures" \
  -j2 test install --summary all
zig build --build-file support/tools/hyperv/local_boot/build.zig \
  --prefix "$S/outputs/local-release" -Dtest-root="$S/fixtures" \
  -Doptimize=ReleaseSafe -j2 test install --summary all
```

The separate uninstalled native QEMU fixture checks actual argv, vpc versus
raw shape, full read-only descriptor identity, CPU/APIC/no-NIC options,
restricted environment, limits, private variable copies and process groups.
Fixtures create real miz containers from a public synthetic 512-byte PE,
not a bootable guest or original seed. Cases include partial matrices,
nonzero/missing/reordered/wrong markers, optional network transcript/config,
mutation, timeout/flood/cancel, surviving descendants, independent cleanup/
recording failures, duplicate/unknown JSON, physical evidence tampering,
permission refusals, manifest/source compatibility and actual CLI/digest
serialization. They remove only their own named fixture directories.
No real guest, KVM, Python, Azure, token, credential, original data seed or
historical private artifact is used. Real x86/KVM integration remains CI work.
