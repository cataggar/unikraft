# Hyper-V / Azure acceptance

`../scripts/hyperv-azure.py` packages an already-built x86-64 Hyper-V EFI
application, boots the resulting disks locally, and then optionally runs a
bounded Azure Generation 2 acceptance deployment. A platform boot is not a
storage/network pass.

## Observed hardware coverage

On 2026-09-08, the single-CPU acceptance probe completed on an Azure Generation
2 `Standard_D2s_v5` VM in `westus2`, using the implementation through
[`8c87f56ab3eaa71974812cd748c3a6bfa61c563b`][unikraft-revision].
After the single-CPU legacy-APIC correction in
[`4cdabd975ab4bc39dcdabeca496d8ee8630e3759`][amd-revision], the same image
completed the full probe on both `Standard_D2as_v5` and `Standard_D2s_v5` in
`westus2`. A further `Standard_D2s_v5` run in `westus3` completed the same
platform, storage, and DHCP stages. These successful runs all negotiated
VMBus 5.3, VMStor 6.2, and NVS 6.1.

| Surface | Observed result |
| --- | --- |
| Interrupt controller | Intel x2APIC path and AMD legacy xAPIC MMIO path |
| Platform | Hypercall/SynIC initialization and the application-ready marker |
| VMBus | Protocol 5.3, twelve offers |
| Storage | VMStor 6.2, 66 MiB OS disk; 1,024 bytes read from MBR/primary GPT |
| Network | NVS 6.1; matching DHCP Offer after one Discover and one received packet |
| Completion | All four readiness markers, `main returned 0`, no crash |
| Cleanup | Run-owned Azure resource group deleted |

The storage operation was read-only. This is bounded boot/device smoke
coverage, not a filesystem, throughput, hotplug, suspend/resume, or SMP
workload result. The kernel used one CPU even though the Azure size exposes
two. The configured storage-controller pool accepted the OS controller and
rejected one additional offer; multiple-controller coverage is not implied.

A fresh configuration at the initial revision exposed missing legacy-APIC
support on `Standard_D2as_v5`; [#81][amd-irq] is now resolved by the correction
and both-family runs above. Another `Standard_D2s_v5` host using VMBus 6.0 and
VMStor 6.0 passed platform/storage but rejected NetVSC binding with `EPROTO`
([#82][netvsc-variant]). The successful smoke runs are not blanket coverage of
every Azure host variant, and the legacy-APIC path is restricted to single-CPU
Hyper-V configurations.

Retain each run's private `state.json`, `packaging.json`, `acceptance.json`,
and serial logs for its exact image fingerprints and outcome. Do not publish
Azure account identifiers or credential-bearing diagnostics.

## Prerequisites

- A successful local native or GNU build of the EFI application. Keep the
  kernel configured for one CPU for initial acceptance, with informational
  boot logging enabled.
- A `miz` build providing `build-efi-application` and the
  `check-efi-application` version-1 `miz.efi-application-image` JSON contract.
  These APIs and their reviewed hardening are available at
  [`2db68ca0c3ab12155012a823c3fb8d7aba1cb544`][miz-revision].
  Generic `miz check`/`info` do not validate the embedded EFI payload, and
  `miz azure fixup` can modify an image; neither substitutes for this gate.
- QEMU with KVM and `vmbus-bridge`, plus x86-64 OVMF code and
  variable-store files.
- For `run` only: an authenticated Azure CLI public-cloud subscription with
  Compute/Network already registered, Compute API `2025-11-01`, and available
  regional/family quota for the selected two-vCPU size.
- For `run` only: the Azure Blob SDK in the controller's Python environment;
  the working version is pinned in `support/azure/requirements.txt`.
  Dependencies are checked before creating resources. An Azure CLI Python
  installation may already provide it; otherwise use a private environment:

```shell
python3 -m venv "$PWD/.d/azure-python"
. "$PWD/.d/azure-python/bin/activate"
mkdir -p "$PWD/.d/azure-python/tmp"
TMPDIR="$PWD/.d/azure-python/tmp" \
PIP_CACHE_DIR="$PWD/.d/azure-python/pip-cache" \
python3 -m pip install -r support/azure/requirements.txt
```

The controller does not register providers or subscription-wide preview
features, install tools/extensions, provision a guest agent, generate SSH keys,
or change the Azure CLI authentication directory.

## Prepare locally

Run from the Unikraft repository or its implementation worktree. Use a new,
private state directory for each attempt:

```shell
EFI=/absolute/path/to/helloworld_hyperv-x86_64-efi
MIZ=/absolute/path/to/miz
STATE="$PWD/.d/azure/first-platform"

python3 support/scripts/hyperv-azure.py prepare \
  --efi "$EFI" --miz "$MIZ" --state-dir "$STATE" \
  --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --expect 'Hello world!' \
  --location westus2 --vm-size Standard_D2s_v5
```

Preparation makes no Azure calls. `miz` creates a deterministic GPT disk with
a 64 MiB FAT32 ESP and a 66 MiB virtual disk, then a native fixed VHD. The raw
disk boots under OVMF before VHD generation; the exact VHD is independently
preflighted by `miz` and also booted under OVMF, read-only. Both artifacts boot
once with normal x2APIC discovery and once with x2APIC masked to require the
single-CPU legacy-xAPIC fallback. Each local boot is bounded and must reach
hypercall/SynIC initialization and the exact application marker without a
crash. QEMU's missing storage/network endpoints may produce the probe's
`UNAVAILABLE` result; that is platform-only local evidence and never an I/O
success.
The local platform fixture does not attach a balloon device: balloon support
is optional in QEMU builds and is not a storage or network acceptance endpoint.
VMBus channel and device traffic remain separate hosted and real-host gates.
QEMU maps the exact artifact's 66 MiB guest-visible data region read-only.
For fixed VHD, this excludes the trailing footer already validated by `miz`;
it neither converts the image nor substitutes the earlier raw-disk file.
This also avoids requiring QEMU's optional VPC format driver.

The private directory retains the EFI payload, raw disk, VHD, their fingerprints,
the `miz` executable fingerprint and packaging report, and all four serial logs
(`local-{raw,vpc}-{x2apic,legacy-apic}-serial.log`).
Tool caches and temporary files stay below that directory. Fresh firmware
copies are removed after each local boot. Existing state directories are never
overwritten.

## Private nested-KVM platform preflight

`support/scripts/hyperv_private_preflight.py` is a separate, operator-run
platform preflight. It does not replace `hyperv-azure.py`, consume a public
prepared-image artifact, build Unikraft in Azure, or claim StorVSC persistence.
It uses `azure-storage-blob==12.28.0`. Its complete 12-distribution closure,
including `azure-core==1.41.0`, `requests==2.34.2`, and
`cryptography==50.0.1`, is pinned in `support/azure/requirements.txt`.
The controller fingerprints every installed file in every locked distribution.
Create an isolated worktree-local runtime and verify the installed closure
before generating an input contract:

```shell
RUNTIME="$PWD/.d/private-preflight-runtime"
mkdir -p "$RUNTIME/tmp" "$RUNTIME/pip-cache"
python3 -m venv "$RUNTIME/venv"
TMPDIR="$RUNTIME/tmp" PIP_CACHE_DIR="$RUNTIME/pip-cache" \
  "$RUNTIME/venv/bin/python" -m pip install \
  --disable-pip-version-check -r support/azure/requirements.txt
"$RUNTIME/venv/bin/python" -c \
  'import sys; sys.path.insert(0, "support/scripts"); import hyperv_private_preflight as p; assert len(p.sdk_dependency_contract()["distributions"]) == 12'
```

First solve the selected Hyper-V configuration using the documented
`olddefconfig` command. For the guarded V2 policy, create one policy-2 manifest
and retain its raw seed and JSON receipt for the later, separately authorized
real-data-disk workload. The seed is not uploaded to this platform preflight:
Set `ZIG`, `MAKE`, `BISON`, `FLEX`, `M4`, `BISON_DATA`, `LLVM_BIN`, and
`GIT_RUNTIME` to absolute reviewed tool paths. `GIT_RUNTIME` must be a
relocatable owner-selected directory containing native ELF files only:
`bin/git`, the matching dynamic loader at `lib/loader`, and every transitive
DSO needed by Git directly below `lib/` under its requested SONAME. Symlinks,
scripts, launchers that require adjacent configuration, missing or unused
libraries, ambient dependency fallback, and unknown paths are rejected. The
loader, C runtime, thread/dlopen compatibility DSOs, and Git's private
libraries are fingerprinted and copied together; only the kernel and virtual
DSO remain outside that runtime closure.

```shell
PERSISTENCE="$PWD/.d/private-preflight-persistence"
mkdir -p "$PERSISTENCE" "$PWD/.d/acceptance-tmp" \
  "$PWD/.d/acceptance-cache"
CONFIG_TOOLS="$PWD/.d/private-preflight-config-tools"
mkdir -m 700 "$CONFIG_TOOLS"
cat >"$CONFIG_TOOLS/yacc" <<EOF
#!/bin/sh
set -eu
export BISON_PKGDATADIR="$BISON_DATA"
export M4="$M4"
exec "$BISON" "\$@"
EOF
cat >"$CONFIG_TOOLS/lex" <<EOF
#!/bin/sh
set -eu
export M4="$M4"
exec "$FLEX" "\$@"
EOF
cat >"$CONFIG_TOOLS/git" <<EOF
#!/bin/sh
set -eu
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_EXEC_PATH="$GIT_RUNTIME/disabled-exec-path"
export GIT_OPTIONAL_LOCKS=0
export GIT_NO_REPLACE_OBJECTS=1
export OPENSSL_CONF=/dev/null
export OPENSSL_MODULES="$GIT_RUNTIME/disabled-openssl-modules"
export LC_ALL=C
export PATH="$GIT_RUNTIME/disabled-path"
exec "$GIT_RUNTIME/lib/loader" --inhibit-cache \
  --library-path "$GIT_RUNTIME/lib" "$GIT_RUNTIME/bin/git" \
  --no-replace-objects -c core.fsmonitor=false \
  -c core.hooksPath=/dev/null "\$@"
EOF
chmod 700 "$CONFIG_TOOLS/yacc" "$CONFIG_TOOLS/lex" "$CONFIG_TOOLS/git"
"$RUNTIME/venv/bin/python" support/scripts/hyperv-storage-manifest.py \
  --output-prefix "$PERSISTENCE/run" \
  --identity-policy seed-enrollment-v2 --sectors 262144 --lun 1
cp support/apps/hyperv-acceptance/defconfig \
  support/apps/hyperv-acceptance/.config
cat "$PERSISTENCE/run.config" >> \
  support/apps/hyperv-acceptance/.config
TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
PATH="$CONFIG_TOOLS:$RUNTIME/venv/bin:$LLVM_BIN:/usr/bin:/bin" \
  "$ZIG" build olddefconfig -j2 \
  -Dapp="$PWD/support/apps/hyperv-acceptance" \
  -Dconfig="$PWD/support/apps/hyperv-acceptance/.config" \
  -Dmake-command="$MAKE" \
  "-Dcompiler=$ZIG cc -target x86_64-freestanding-none" \
  -Dcompiler-targeted=true "-Dhost-cc=$ZIG cc" \
  "-Dhost-cxx=$ZIG c++" -Dhost-cflags=-fno-sanitize=null \
  "-Dmake-arg=AR=$ZIG ar" -Dmake-arg=NM=llvm-nm \
  -Dmake-arg=OBJCOPY=llvm-objcopy \
  -Dmake-arg=OBJDUMP=llvm-objdump \
  -Dmake-arg=READELF=llvm-readelf -Dmake-arg=STRIP=llvm-strip
SOLVED_CONFIG="$PWD/support/apps/hyperv-acceptance/.config"
```

The solved configuration must enable persistence, StorVSC, LUN discovery, and
guarded I/O; use identity policy 2; preserve the exact run ID, disk ID, LUN,
sector count, and 512-byte sector size; and leave path and target unenrolled.
V1, network-application, altered geometry, or incomplete guarded configurations
are rejected before packaging or any cloud action.

The guarded producer pin is a separately versioned reviewed contract. It
fingerprints the native build selection, Hyper-V message ingress and ABI,
VMBus storage-offer matcher and sticky lifetime state, StorVSC coherent
inventory/core, and the acceptance application's unavailable decision and
record framing, including their Kconfig, Make, and exported-symbol wiring.
Any update to that critical proof closure requires an explicit reviewed pin
change before another guarded image can be generated.

Run the solve command with the controlled tool path shown above rather than an
ambient developer shell. `python3` then resolves from the pinned runtime, the
parser wrappers resolve first, source versioning uses the selected Git runtime,
LLVM tools retain their symbolic command names, and the Make-backed facade
uses the absolute `$MAKE` supplied by `-Dmake-command`.

Then let the controller invoke the fixed native builder itself. It first
copies and preflights the complete Git runtime, then uses only that relocated
copy for source snapshots and Make's symbolic `git` invocation. The receipt
fingerprints the complete Git runtime, compiler, LLVM, Make, Python, parser
tools and Bison data. Git configuration, hook, helper, fsmonitor, and
repository-selection environment overrides are removed; system/global config
and the helper search path are disabled, and dynamic-loader injection
variables are removed. Dependency resolution must remain entirely inside the
copied runtime before and after every source query. Provenance rejects object
replacement refs, assume-unchanged and skip-worktree flags, and any index
difference, then hashes every tracked physical regular file or symlink and
checks its Git mode and object ID against the unreplaced `HEAD` tree using
NUL-delimited path records. Both complete bounded
native passes must return successfully and contain no failure record. The only
recoverable materialization record is the exact pinned `uk-reloc` command
whose cache-local inputs are validated before a clean second pass:

```shell
LOCAL_BUILD="$PWD/.d/private-preflight-local-build"
"$RUNTIME/venv/bin/python" support/scripts/hyperv_private_preflight.py \
  build-private --output-dir "$LOCAL_BUILD" --repository "$PWD" \
  --solved-config "$SOLVED_CONFIG" --zig "$ZIG" --make "$MAKE" \
  --python "$RUNTIME/venv/bin/python" --bison "$BISON" --flex "$FLEX" \
  --m4 "$M4" --bison-data "$BISON_DATA" --llvm-bin "$LLVM_BIN" \
  --git-runtime "$GIT_RUNTIME"
PRIVATE_EFI="$LOCAL_BUILD/build/helloworld_hyperv-x86_64-efi-netvsc"
PRIVATE_BUILD_RECEIPT="$LOCAL_BUILD/private-build-receipt.json"
SOLVED_CONFIG="$LOCAL_BUILD/solved.config"
```

Package that exact EFI into raw/fixed-VHD files locally with the pinned `miz`
API. Do not use a converted or previously built image:

```shell
LOCAL_PACKAGE="$PWD/.d/private-preflight-package"
mkdir -m 700 "$LOCAL_PACKAGE"
"$MIZ" build-efi-application --efi "$PRIVATE_EFI" \
  --architecture x86_64 --esp-size 64M -O raw \
  -o "$LOCAL_PACKAGE/private.raw"
"$MIZ" build-efi-application --efi "$PRIVATE_EFI" \
  --architecture x86_64 --esp-size 64M -O vhd \
  -o "$LOCAL_PACKAGE/private.vhd"
"$MIZ" check-efi-application --output=json --architecture x86_64 \
  --expected-efi-sha256 "$(sha256sum "$PRIVATE_EFI" | cut -d' ' -f1)" \
  --expected-virtual-size 66M "$LOCAL_PACKAGE/private.vhd"
```

`generate-input` repeats the pinned check and rejects an EFI whose hash, size, source
snapshot, solved configuration, invocation, or build tools differ from the
receipt. The QEMU closure is an owner-selected directory whose
executable is exactly `bin/qemu-system-x86_64`; required regular files below
`lib/` and `share/` are copied and hashed recursively. Symlinks are rejected.
Generate the canonical schema-9 manifest and owner-only input directory:

```shell
INPUTS="$PWD/.d/private-preflight-input"
STATE="$PWD/.d/private-preflight-state"
CAPABILITY_RAW="$AUTHENTICATED_CAPABILITY/capability.raw"
CAPABILITY_RECEIPT="$AUTHENTICATED_CAPABILITY/capability.source.json"
PRIVATE_RAW="$LOCAL_PACKAGE/private.raw"
PRIVATE_VHD="$LOCAL_PACKAGE/private.vhd"
"$RUNTIME/venv/bin/python" support/scripts/hyperv_private_preflight.py \
  generate-input --output-dir "$INPUTS" --repository "$PWD" \
  --solved-config "$SOLVED_CONFIG" --qemu-root "$PINNED_QEMU_ROOT" \
  --ovmf-code "$PINNED_OVMF_CODE" --ovmf-vars "$PINNED_OVMF_VARS" \
  --capability-raw "$CAPABILITY_RAW" \
  --capability-receipt "$CAPABILITY_RECEIPT" \
  --private-efi "$PRIVATE_EFI" \
  --private-build-receipt "$PRIVATE_BUILD_RECEIPT" \
  --private-raw "$PRIVATE_RAW" --private-vhd "$PRIVATE_VHD" \
  --miz "$MIZ" --git-runtime "$GIT_RUNTIME" \
  --boot-policy guarded-v2-pristine-unavailable
PRIVATE_INPUT_MANIFEST_SHA256="<digest printed by generate-input>"
"$RUNTIME/venv/bin/python" support/scripts/hyperv_private_preflight.py \
  prepare --input-dir "$INPUTS" \
  --expected-manifest-sha256 "$PRIVATE_INPUT_MANIFEST_SHA256" \
  --state-dir "$STATE" --miz "$MIZ"
```

The exact generated names are `private-preflight-input.json`, `solved.config`,
`capability.source.json`, `private-build-receipt.json`, `git-runtime/bin/git`,
`git-runtime/lib/loader`, the complete enumerated `git-runtime/lib` closure,
`qemu/bin/qemu-system-x86_64`, the enumerated `qemu/lib`/`qemu/share` closure,
`OVMF_CODE.fd`, `OVMF_VARS.fd`, `capability.raw`, `private.efi`, `private.raw`,
and `private.vhd`. The manifest binds the clean Git `HEAD`, SHA-256 of the raw
`git ls-tree -r --full-tree -z HEAD` output, the independently verified
physical tracked-tree digest and byte count, solved configuration, pinned
`miz`, controller, runner, Blob worker, imported shared controller and network
helper, ARM template, requirements file, every installed SDK distribution,
all inputs, packaging geometry, sizes, and reviewed policy. The separately
scoped capability receipt binds its historical public source identity and raw
hash; it is never represented as current private-build provenance. The
controller pins the exact reviewed repository/workflow/job/run/attempt/commit,
receipt-file digest, source manifest, EFI, raw image, fixed VHD, and four
platform-only boot outcomes. A structurally valid fork, different run, or
operator-provided replacement receipt is rejected. Updating that historical
capability requires an explicit reviewed source change. Any tracked source,
configuration, helper, requirement, SDK file, or prepared-input change fails
before the first cloud command.

The guarded producer-pin-v4 contract additionally binds the complete
`support/build` directory, including production validation gates even when
they live below `tests/`, plus every external native-image helper invoked by
the root Make/facade/postprocessing path. Unknown additions, removals, or byte
changes fail closed. The input-manifest-v9 and private-build-receipt-v6
contracts bind the copied Git runtime used for every source query and
native-build invocation, the exact reviewed producer files, protocol 1,
identity policy 2, `no-devices`, guest return 2, and the private solved
run/LUN/geometry. Updating a pinned producer or build-closure file requires an
explicit reviewed source change. The exact same causal
`private.efi`, raw disk, and fixed VHD are used for all four private platform
boots and must be retained unchanged for the later real-data workload; there
is no preflight-only guest flag, rebuild, or reseed.

`private.efi`, copied `miz`, source/config metadata, and controller files stay
local. Only the capability raw, private raw/fixed VHD, QEMU closure, and OVMF
files are Blob-staged. The three fixed-size images use 207,618,560 bytes; the
measured QEMU executable uses 26,911,032 bytes; the required closure adds
`share/kvmvapic.bin`, `share/vgabios-stdvga.bin`, and
`share/efi-virtio.rom`, totaling 209,408 bytes. The immutable OVMF code is
referenced read-only from its staged copy; each of the six boots receives a
fresh copy of only the 540,672-byte variables file, totaling 3,244,032
cumulative working-copy bytes. Including the
8,388,608-byte cumulative evidence limit and 524,288-byte cumulative
runner/manifest control limit, the measured maximum is 251,090,232 bytes,
leaving 17,345,224 bytes below the 268,435,456-byte limit.
`generate-input` measures the real closure and refuses a total above
268,435,456 bytes. Feasibility therefore requires the operator's authenticated
QEMU/OVMF assets; fixture sizes are not acceptance evidence.

Live execution is a separate explicitly authorized action:

```shell
"$RUNTIME/venv/bin/python" support/scripts/hyperv_private_preflight.py run \
  --state-dir "$STATE" --subscription "$AZURE_SUBSCRIPTION" \
  --transfer-source-ip "$EXPLICIT_OPERATOR_IPV4" \
  --approve-transfer-source-ip
```

Every Azure command carries the explicit private subscription; the controller
never changes the global account default. The uploader address must be one
explicit public IPv4. It is temporarily narrowed to `/32` for authenticated
Blob upload and receipt download, then removed. There is no automatic address
discovery. The explicit approval flag is checked before subscription or other
cloud preflight calls. If this temporary exception is not approved, the run requires a
separately authorized private controller path and must stop before deployment.

The fixed ARM topology contains one North Europe `Standard_D2s_v5` Ubuntu Gen2
host with Standard security, a 32 GiB `StandardSSD_LRS` OS disk, one dedicated
owned resource group, `/29` VNet/subnet, NIC, NSG, and network-deny Blob
account. The subnet disables default outbound access and enables the
Microsoft.Storage service endpoint. There is no public IP, SSH ingress, NAT
gateway, data disk, or reuse of network-acceptance resources. Before creating
the group, the controller validates the exact immutable Ubuntu image, SKU,
generation, x64 architecture, two-vCPU/eight-GiB shape, providers, and
regional/family quota. Azure's Resource SKUs metadata does not currently
advertise a `NestedVirtualization` capability for this exact
`Standard_D2s_v5`/North Europe selection. That absence is admitted only for
the bounded public capability-smoke phase because Microsoft's
[Dsv5 documentation][dsv5-nested] explicitly lists nested virtualization as
supported (documentation source revision
`2072bfd7009384b9fde1357342d91953104e293d`, updated 2026-07-27). The
controller records the absent advertisement and this authority in private
state and the completed receipt; it does not synthesize an advertised
`True`. An explicit `False`, duplicate, conflicting, or malformed
advertisement remains a pre-deployment failure. The same narrow admission
does not apply to another SKU or region. It never changes region, image, SKU,
or host in response to failure.
Operators can inspect the same immutable retail-image/SKU inputs without
changing account defaults:

```shell
az vm image list --all --location northeurope --publisher Canonical \
  --offer ubuntu-24_04-lts --sku server --subscription "$AZURE_SUBSCRIPTION"
az vm image show \
  --urn "Canonical:ubuntu-24_04-lts:server:$IMMUTABLE_VERSION" \
  --subscription "$AZURE_SUBSCRIPTION"
az vm list-skus --all --location northeurope --size Standard_D2s_v5 \
  --subscription "$AZURE_SUBSCRIPTION"
az vm list-usage --location northeurope \
  --subscription "$AZURE_SUBSCRIPTION"
```

The first RunCommand receives only the public capability image and pinned
QEMU/OVMF inputs. It must prove Linux KVM plus the required QEMU Hyper-V
features in both x2APIC and masked legacy-APIC modes. Only that exact PASS
allows any private seed or image upload. This runtime result, not the
Resource SKUs advertisement or the public documentation, is the capability
proof. A durable capability sentinel binds
the Linux boot identity, and a host restart between phases is rejected. The
second phase boots the exact private raw and fixed-VHD bytes in both modes,
masking the fixed-VHD footer as
the local controller does. Logs have strict stage, normal-return, uniqueness,
size, and deadline checks. Ordinary `platform-unavailable-v1` and
`platform-main-zero-v1` behavior is unchanged.

`guarded-v2-pristine-unavailable` is a separate, versioned platform-only
consumer. After the standard Hyper-V capability records it requires exactly
one ordered producer sequence matching the private solved configuration:

```text
HYPERV_PERSISTENCE START PASS run=<bound-run> address=0:0:<bound-lun> sectors=<bound-sectors> sector_size=512
HYPERV_PERSISTENCE SELECT UNAVAILABLE reason=no-devices writes=0 flushes=0
UK_HYPERV_PLATFORM_READY
UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices
... main returned 2
```

Only a genuinely pristine, coherent, empty inventory with no recognized
storage-lifetime activity can produce that sequence. Missing, duplicate,
reordered, malformed, policy-1, wrong-configuration, `SELECT FAIL`,
`FINAL PASS`, identity, Boot1/Boot2, write/read/flush, completion, ordinary
acceptance, or live-I/O evidence is rejected even when valid unavailable
markers are also present. The START record and full serial logs contain private
configuration and remain only in protected host state and owner-only receipts.
The committed positive records fixture was captured from the actual hosted V2
empty-inventory producer linked with the real driver, using public synthetic
IDs; it is producer evidence, not an x86 nested-KVM capture.

Host and final receipts state `acceptance_scope=platform-only` and
`storage_result=UNAVAILABLE`. A successful runner result proves only that the
same image reached the reviewed pristine-no-device outcome in the two APIC
modes and two packaging formats. It does not prove StorVSC discovery, a live
LUN, writes, flushes, reboot persistence, or any storage PASS. V1 guarded
images remain unsupported. This controller adds no data disk or seed payload
to the host; real two-boot storage acceptance remains a separately authorized
workload using the retained V2 seed and exact unchanged image.

Downstream local controllers must import
`load_completed_receipt(state_directory)` from
`support/scripts/hyperv_private_preflight.py` rather than accepting a prepared
input manifest or build receipt. It returns the normalized completed receipt
and its `private-receipt.json` path only after revalidating immutable inputs,
all six host boot logs and both host-evidence receipts, exact image/build/source
and tool bindings, completed cleanup, and the final receipt digest recorded in
`state.json`. Prepared, partially cleaned, stale, or mismatched state is
rejected. Completion additionally requires revoked SAS state, no retained
signing-key fingerprint, a deallocated host, and the original
`resources-verified` VM/OS-disk identity anchors. The retained host-resource
IDs and exact byte total of both host receipts plus all six serial logs must
also match the durable state.

## Exact two-boot persistence controller

`support/scripts/hyperv_persistence_controller.py` is the destructive,
default-off consumer for one separately authorized disposable Azure run. It
does not build, reseed, convert, or discover a resource budget. It requires:

- an operator-supplied canonical schema-1
  `unikraft.hyperv.persistence-two-boot-contract`;
- explicit 128-bit run and disk IDs, 512-byte logical geometry and Azure LUN;
- one exact subscription, region, VM size/vCPU count, resource prefix, disk
  SKUs, runtime, cleanup duration, and fixed one-VM/two-disk resource count;
- the exact guarded V2 guest fixed VHD, raw seed, matching fixed data VHD and
  generator receipt;
- a completed schema-4 `unikraft.hyperv.private-preflight-receipt` loaded from
  the private preflight's complete state directory, binding the same guest
  VHD, source tree, solved configuration, private build receipt, twelve-tool
  closure, schema-4 guarded producer pin, all six retained boot logs, immutable
  host/deployment identities, the exact nested-capability admission record,
  accounting and completed cleanup.

The controller accepts only whole-MiB 512-byte geometry, capped at 2 TiB; the
operator chooses the exact approved value. WRITE(16) coverage uses the
workload's low-LBA command selection and does not require a disk larger than
2 TiB. Azure billing/allocation tiers do not replace the exact guest-visible
SCSI capacity and Azure-reported `diskSizeBytes` checks.

For example, a bounded persistence envelope uses North Europe,
`Standard_D2s_v5` with two vCPUs, one `StandardSSD_LRS` boot disk, and one
4 GiB (`8388608` 512-byte sectors) `StandardSSD_LRS` data disk. It retains the
fixed one-VM/two-disk topology, no public IP or SSH, one deployment boot and
one restart only. This example does not authorize allocation: the operator
must separately authorize the resource budget, and the completed-consumer,
exact-image, and publication gates must pass.

A build or packaging receipt, local ARM-hosted fixture, receipt file by itself,
or prepared private-preflight state is not this handoff. The controller imports
`load_completed_receipt()`, which revalidates the complete state, immutable
inputs, final receipt hash, four private exact-image boots, two separate
capability boots, guarded no-device result and owner-checked cleanup. The
handoff is private: do not publish host UUIDs, image identifiers, source policy,
serial evidence, seed, contract, state directory or resulting receipts.

Generate the seed and fixed data VHD before the one final guarded-image build:

```shell
python3 support/scripts/hyperv-storage-manifest.py \
  --output-prefix "$PWD/.d/persistence/run" \
  --identity-policy seed-enrollment-v2 \
  --run-id "$PRIVATE_RUN_ID" --disk-id "$PRIVATE_DISK_ID" \
  --sectors "$APPROVED_SECTORS" --lun "$APPROVED_LUN" --fixed-vhd
```

After the exact image completes private x86 preflight, create the fully
explicit contract. The command makes no cloud calls and creates a new
owner-only file:

```shell
PYTHONPATH=support/scripts python3 \
  support/scripts/hyperv_persistence_controller.py create-contract \
  --output "$PRIVATE/contract.json" \
  --run-id "$PRIVATE_RUN_ID" --disk-id "$PRIVATE_DISK_ID" \
  --sectors "$APPROVED_SECTORS" --lun "$APPROVED_LUN" \
  --subscription "$EXPLICIT_SUBSCRIPTION" --location "$APPROVED_LOCATION" \
  --vm-size "$APPROVED_VM_SIZE" --vm-vcpus "$APPROVED_VCPUS" \
  --name-prefix "$APPROVED_PREFIX" \
  --os-disk-sku "$APPROVED_OS_SKU" \
  --data-disk-sku "$APPROVED_DATA_SKU" \
  --runtime-seconds "$APPROVED_RUNTIME" \
  --cleanup-seconds "$APPROVED_CLEANUP_RUNTIME" \
  --guest-vhd "$PRIVATE_GUEST_VHD" \
  --data-raw "$PWD/.d/persistence/run.raw" \
  --data-vhd "$PWD/.d/persistence/run.vhd" \
  --seed-manifest "$PWD/.d/persistence/run.json" \
  --preflight-state-dir "$COMPLETED_PRIVATE_PREFLIGHT_STATE"
```

The generator prints both the whole contract SHA-256 and the separately
approved Azure resource-envelope SHA-256. `prepare` revalidates the current
controller/template/uploader/requirements fingerprints, preflight binding,
seed records and CRC, pristine intent/receipt/write regions, fixed-VHD
footer/checksum, exact data-region equality, and all file hashes before copying
them into new durable private state:

```shell
python3 support/scripts/hyperv_persistence_controller.py prepare \
  --contract "$PRIVATE/contract.json" \
  --expected-contract-sha256 "$CONTRACT_SHA256" \
  --state-dir "$PRIVATE/state" \
  --guest-vhd "$PRIVATE_GUEST_VHD" \
  --data-raw "$PWD/.d/persistence/run.raw" \
  --data-vhd "$PWD/.d/persistence/run.vhd" \
  --seed-manifest "$PWD/.d/persistence/run.json" \
  --preflight-state-dir "$COMPLETED_PRIVATE_PREFLIGHT_STATE"
```

`run` remains inert unless both the exact subscription and the SHA-256 of the
contract's Azure resource envelope are supplied with the explicit approval
flag. Actual data-disk allocation and this cloud action require separate user
authorization:

```shell
python3 support/scripts/hyperv_persistence_controller.py run \
  --state-dir "$PRIVATE/state" \
  --subscription "$EXPLICIT_SUBSCRIPTION" \
  --approved-resource-envelope-sha256 "$RESOURCE_ENVELOPE_SHA256" \
  --approve-cloud-run
```

The controller creates one owned group, uploads one OS VHD and one seeded data
VHD with the existing SDK page uploader, and records each disk `uniqueId`
directly from its create response. Immediately before deployment it rereads
both disks and requires their original UUIDs, exact geometry, ownership and
unattached readiness. The disks are pre-existing external ARM inputs; the
template does not rely on a `resourceId()` reference to order their creation.
The controller durably creates a random operation UUID before the VM call and
requires that UUID in the returned deployment parameters and every
template-created resource. Only that create response may establish the
deployment correlation and guest VM `vmId`. A timeout or lost response leaves
an unresolved cleanup obligation: a later deployment GET, matching name, tag,
ARM ID or live-resource UUID can never enroll replacement identities. Before
each later boundary the controller verifies reciprocal VM/disk attachment,
geometry, LUN, operation tags and all three UUIDs.

The deployment itself is Boot 1. The controller accepts exactly one ordered V2
identity, five-write/three-flush/receipt record, Boot 1 completion and normal
return. It stores the exact serial prefix, deallocates the proven VM, durably
records `boot_count=2` before the sole `vm start`, and treats that start as Boot
2. Deallocated Azure disks may report `Reserved`; only the UUID-anchored,
reciprocally attached disks in that phase can proceed to the second start.
The second serial segment must append to the unchanged Boot 1 prefix and
must contain the same controller GUID, path, target, LUN, VPD, run/disk IDs and
geometry, a zero-write/zero-flush receipt readback, Boot 2 completion and
normal return. Any Boot 1/write/reseed marker in the Boot 2 segment fails even
if a later line says PASS. Unavailable/no-device evidence is never persistence
success.

Interrupted mutation phases cannot be resumed or re-enrolled; they may only
enter explicit cleanup, preventing a replacement or third boot. Cleanup gets
its own deadline, independently verifies and deallocates a proven VM even when
one disk or the VM's attachment graph is unproven, while retaining those
validation failures and refusing group deletion. Cleanup checks UUID, geometry,
ownership and attachment independently of transient readiness, so a proven
pre-upload `ReadyToUpload` disk or a deallocated `Reserved` disk is not
misclassified. It refuses replacement UUIDs or foreign resources, preserves
primary, cleanup and durable-recording failures, and deletes the group only
when every extant resource is an owner-verified member of the fixed envelope.
Interrupted creation may leave a strict subset, but an extant VM or disk still
requires its original UUID proof. A successful private receipt binds both
serial segments, the complete enrolled identity, immutable provenance, the
same VM/OS-disk/data-disk UUIDs, exact two-boot count and completed cleanup.

Credential-free Python and hosted driver fixtures exercise this state machine
with synthetic IDs. They do not establish local x86/KVM capability, completion
of the private exact-image preflight, Azure allocation authorization, or actual
two-boot durability.

Cleanup remains available without granting permission for another run:

```shell
python3 support/scripts/hyperv_persistence_controller.py cleanup \
  --state-dir "$PRIVATE/state" \
  --subscription "$EXPLICIT_SUBSCRIPTION"
```

Its independent deadline never renews the acceptance deadline. If deletion
completed after an acceptance-eligible receipt was durably staged, a later
cleanup invocation finalizes that same receipt rather than starting another
boot. Staging the pending receipt and its hash is not eligibility: the
controller records eligibility only after the final acceptance deadline check.
Any primary acceptance rejection records the state as ineligible, so a later
cleanup-only recovery cannot promote that pending receipt to a completed PASS.
Cloud operations retain fractional timeout budgets, and their return is
checked against the relevant deadline before any success phase is persisted.

`run` and `cleanup` hold one owner-only advisory lock file in the state
directory from the first load through final recording. A concurrent process
using the same canonical state directory fails before cloud access. This is a
single-host, single-filesystem guard: copying the prepared directory creates a
different lock inode, and advisory locks do not coordinate unrelated hosts.
Operators must therefore never copy, mount independently, or run the same
prepared identity from multiple hosts; the fixed resource names and cloud
ownership checks are fail-closed backstops, not a distributed lock.

## Private nested-KVM platform preflight cleanup

Private manifests, SAS values, host identity, serial logs, and receipts remain
in owner-only local state and authenticated Blob/control-plane parameters.
Ordinary CLI errors redact identifiers and credentials. The operator needs
only the resource permissions for this topology plus storage-account key
listing/regeneration and network-rule mutation, VM RunCommand/deallocation,
deployment inspection, and owner-checked deletion; it creates no role
assignments and assumes no broader grant.
The 60-minute deadline starts before deployment and is never extended; bounded
transfer, RunCommand, and boot limits are subordinate to it. Managed auto-shutdown is
configured before private work only as a backstop. Guest shutdown or the
schedule is not proof of compute deallocation or a hard billing cap.

Cleanup is attempted after success, failure, interruption, or deadline expiry:

```shell
python3 support/scripts/hyperv_private_preflight.py cleanup \
  --state-dir "$STATE" --subscription "$AZURE_SUBSCRIPTION"
```

Cleanup receives one separate bounded 20-minute budget; it does not renew the
60-minute attempt or permit uploads, deployment, or new VM work. The controller
first resolves any durable pending/active uploader `/32`, then
removes interrupted protected-parameter files and attempts SAS-key rotation,
explicit VM deallocation, and owner-checked resource-group deletion
independently. Firewall intent is persisted before
the add call and remains pending until exact absence is re-read, including
after interrupted processes. It persists the original deployment operation
before create. A successful deployment must return server-side ARM outputs
for the original VM `vmId` and OS-disk `uniqueId`; both immutable anchors are
recorded together before any live VM or disk query. The disk identity output
comes from a nested deployment that explicitly waits for VM creation and reads
the managed-disk ID returned by that VM, rather than racing an undeclared
implicit disk. Live reads may only
confirm those anchors, never fill or replace them from matching names, tags,
resource IDs, images, or attachments. Cleanup may deallocate the exact
UUID-anchored VM independently when disk inspection fails, but group deletion
still refuses an unknown, detached, replaced, or foreign disk. Required
ownership tags
may contain additive Azure metadata, but tags never substitute for persisted
VM UUID, disk UUID, attachment, and original deployment proof. Untagged
extension children are accepted during cleanup only when their resource ID is
structurally below that already proven VM; the exact pre-private resource
inventory still rejects unexpected extension software. There is no
keep-resources mode. Control-plane or
ownership failures are reported as cleanup failures rather than claimed as
successful deletion. If both the primary operation and cleanup fail, the
durable state and raised error retain both sanitized failures; failure to write
that combined record is also reported without exposing subscription, storage,
endpoint, identifier, or local private-state values. The final private receipt
binds the exact inputs, tools,
host identity, four boot outcomes, and cleanup obligations; live nested-KVM
success still requires the operator-run attempt.

## Local CI interface

`zig build test-hyperv-regression` aggregates the existing focused Hyper-V
protocol, ABI, driver, IRQ, SMP, controller, and packaging fixtures without
selecting the repository's broad test suite. The ordinary pull-request job
freshly solves `support/apps/hyperv-acceptance/defconfig`, builds
`hyperv-x86_64-efi-netvsc`, runs the final constructor/IRQ/SMP link gates, and
passes that exact EFI payload to `prepare`.

On a non-x86 development host, the same selector runs the architecture-neutral
hosted fixtures and the x86-64 freestanding object checks, and reports that
x86-only hosted IRQ, driver, and SMP executables are deferred to the x86-64 CI
job. It does not reinterpret an architecture skip, missing local KVM, or
missing Hyper-V devices as a boot or I/O pass.

`zig build test-hyperv-private-preflight -j2` runs only the synthetic
manifest, host-runner, ARM-shape, private-error, ordering, deadline, and
owner-checked cleanup fixtures. It makes no Azure calls and uses no private
identifiers.

The production-backed VMBus control, channel, and disconnect fixtures also run
on non-x86 hosts. Use `zig build test-vmbus-lifecycle -j2` for that focused
subset, including teardown quarantine, callback lifetime, resource pressure,
and repeated reconnect/rescind cases. Hosted lifecycle coverage is not a
scheduled SMP workload or real-host reconnect result.

`zig build test-storvsc-regression -j2` runs the StorVSC core, C/C++ public
mapping ABI, native export metadata, and production topology/lifetime fixtures
on either host architecture. It includes mixed polling/interrupt LUNs and
retained-client interrupt restoration after same-controller rebind.

`state.json` retains `local_platform_boot_modes` for the raw and fixed-VHD
x2APIC/legacy-APIC boots, while `image_sha256` remains the deployment identity.
Ordinary pull requests intentionally have no Azure stage or credentials.
The `zig-hyperv-local-evidence` CI artifact retains selected local serial and
packaging logs, the packaging report, and EFI/debug-ELF digests for seven days,
including boot failures. It excludes raw controller state, disk images, tool
caches, and credentials.

## Opt-in storage topology

The default remains one StorVSC controller and LUN 0, without REPORT LUNS or
VPD discovery. To build a topology-aware workload, explicitly select limits
and discovery in its configuration, then run `olddefconfig`:

```text
CONFIG_LIBSTORVSC_MAX_DEVICES=2
CONFIG_LIBSTORVSC_LUN_DISCOVERY=y
CONFIG_LIBSTORVSC_MAX_LUNS=4
```

Each LUN has independent capacity, access mode, queue, and completion routing.
The limits reserve controller/LUN identities for the boot; removed identities
are not recycled into different devices. Pool exhaustion is reported without
discarding healthy attached LUNs.

`<uk/storvsc.h>` exposes `uk_storvsc_mapping_count`, `uk_storvsc_mapping_get`,
and `uk_storvsc_mapping_find` to C and C++ callers. Active snapshots include
the controller instance GUID, channel, SCSI address, block-device ID, media
properties, and any supported LU-associated VPD designator. A missing VPD
designator is explicit, not a fabricated stable identity. Snapshots do not
pin a disk across removal and are not authorization to write.

This driver support does not extend the existing smoke controller into a
multi-disk or write-persistence acceptance lane. Those still require a
run-owned data-disk guard and separate real-host evidence.

## Private application-network peer

`support/scripts/hyperv-network-peer.py` implements the guest's UKNA v1
application protocol using only the Python standard library. On an explicitly
owned, private peer host, bind it to the intended interface and guest address:

```shell
python3 support/scripts/hyperv-network-peer.py \
  --peer-ip 10.87.0.4 --guest-ip 10.87.0.5 \
  --tcp-port 18887 --udp-port 18888 --nonce 87c0ffee5aa8dfd6 \
  --timeout 300
```

The peer rejects wildcard, loopback, link-local, public, and IPv6 endpoints.
Its peer address, ports, and 16-hex-digit nonce must match the exact guest
image's application-network configuration. The nonce correlates evidence; it
is not authentication. Private-network isolation remains required.

It validates three fresh TCP request streams and six UDP datagrams with the
documented guest sequences, lengths, and direction-specific payloads, and
returns independently generated responses. Stream reads/writes share absolute
deadlines even with partial I/O. Each active exchange has at most five seconds;
the total service lifetime is bounded by `--timeout` (1 through 600 seconds).
Unexpected-source traffic is bounded, the UDP source port must remain stable,
and trailing TCP bytes or extra expected-guest traffic during the final
200-millisecond drain fail the run. All sockets close on success or failure.

`HYPERV_NETWORK_PEER` records are schema-1 JSON with readiness, per-exchange
outcomes, and a final result with endpoint/nonce correlation and exact byte
counts. `READY` appears only after both sockets are bound. A peer-side PASS
alone is not networking acceptance: the controller must also require the
matching guest lease, ARP, TCP, UDP, cleanup, and final records.

The service itself creates no Azure resources. For a reviewed
application-network export, explicitly select both
`hyperv_network_application` and `export_hyperv_prepared_image` in an
`integration` workflow dispatch. The existing `zig-hyperv` job then fetches
the pinned lwIP wrapper, freshly solves `app-network.defconfig`, builds the
native image, and requires the exact `NETWORK_APP_CONFIG` record in all four
raw/fixed-VHD APIC preflight logs. The preflight remains platform-only and
does not claim StorVSC or NetVSC I/O. The raw-DHCP `run` path remains the
original smoke lane and is not application-network coverage.

## Transfer an exact prepared image

The `export-prepared` and `import-prepared` commands transfer the exact fixed
VHD that passed the four local boots. They do not rebuild or repackage it.
Export is available in CI only when a trusted operator explicitly enables the
`export_hyperv_prepared_image` `workflow_dispatch` input. Normal pushes and
pull requests never upload the VHD.

The opt-in artifact contains exactly `prepared-image-manifest.json` and
`unikraft.vhd`. The canonical manifest contains only strict schema/controller
revision data, GitHub repository/workflow/job/run/head provenance, fixed image,
EFI, raw-image, and pinned-`miz` fingerprints, the allowlisted packaging
contract, and the four platform-only APIC outcomes. Its discriminated
acceptance contract is either `raw-dhcp` or `network-application`. The latter
also binds the solved peer IPv4, TCP/UDP ports, 16-hex nonce, solved
configuration, unchanged peer script, UKNA request/response transcript
digests, and exact message/byte totals. It contains no private state, guest
address, local paths, serial logs, Azure identifiers, SAS values, credentials,
or resource ownership.

Record the manifest SHA-256 printed in the reviewed job summary separately from
the downloaded artifact. Import requires that externally supplied digest and
the expected source identity:

```shell
ARTIFACT="$PWD/.d/artifacts/zig-hyperv-prepared"
STATE="$PWD/.d/azure/imported-platform"
MIZ=/absolute/path/to/the/pinned/miz

python3 support/scripts/hyperv-azure.py import-prepared \
  --artifact-dir "$ARTIFACT" --state-dir "$STATE" --miz "$MIZ" \
  --expected-manifest-sha256 "$REVIEWED_MANIFEST_SHA256" \
  --expected-repository "$REVIEWED_REPOSITORY" \
  --expected-repository-id "$REVIEWED_REPOSITORY_ID" \
  --expected-workflow-ref "$REVIEWED_WORKFLOW_REF" \
  --expected-job zig-hyperv \
  --expected-run-id "$REVIEWED_RUN_ID" \
  --expected-run-attempt "$REVIEWED_RUN_ATTEMPT" \
  --expected-head-sha "$REVIEWED_HEAD_SHA" \
  --location westus2 --vm-size Standard_D2s_v5
```

Import accepts no archive and follows no manifest-provided path. It rejects
extra files, symlinks, duplicate or unknown fields, incompatible controller
revisions, source mismatches, and changed image or packaging content. The
pinned `miz` check is rerun against the copied VHD. A new private state
directory and random ownership prefix are created; no cloud subscription,
resource ID, credential, or previous ownership is imported. The existing
`run` and `cleanup` commands then operate on this private ledger unchanged.
Import itself makes no GitHub or Azure calls.

## Run one Azure VM

For the hello-world example, explicitly select platform-only acceptance:

```shell
python3 support/scripts/hyperv-azure.py run \
  --state-dir "$STATE" --stage platform --timeout 300
```

The VHD digest is checked before and after upload. The controller creates one
uniquely named resource group and a Gen2 Linux managed disk, grants short-lived
write access, writes the already-created page blob, and always revokes access.
The SDK helper uses bounded 4 MiB page updates with service-verified checksums
and reads back the final 512 bytes before import. It never calls Create Page
Blob and does not rely on the ordinary `az storage blob upload` path, which
returned `ApiNotSupportedForAccount` against the managed-disk service. The helper
runs in a subprocess with a 1,200-second total timeout.

SAS credentials
are confined to process memory/environment, not arguments, state files or
command logs. The VM attaches this specialized disk without an `osProfile`,
uses private networking without a public IP or default Internet egress, and
has managed Boot Diagnostics enabled before its first boot.

The ARM template explicitly selects Standard security for the custom unsigned
EFI application. This is per-VM configuration, not a subscription-wide change.
See Microsoft's [Trusted Launch FAQ][trusted-launch] for the API requirement.
Direct managed-disk upload follows the [Azure disk upload workflow][upload].

By default, owned resources are deleted after success or failure. `serial.log`,
`acceptance.json`, and `state.json` remain local. `--keep-resources` explicitly
retains resources for debugging; they continue consuming quota and may incur
charges until cleaned up:

```shell
python3 support/scripts/hyperv-azure.py cleanup --state-dir "$STATE"
```

Cleanup is idempotent and refuses to delete a group if its ownership tags, or
those of any contained resource, do not match the run. An interrupted or
partially uploaded run is not silently resumed: clean it up, then prepare a
fresh state directory for another attempt. The implicit private-peer OS disk is
not adopted by adding ownership tags. The successful ARM deployment itself
outputs the peer VM and disk UUIDs. The controller records those immutable
anchors with the deployment correlation and exact declared resources before
any follow-up read, then re-reads that original deployment during cleanup. A
VM-dependent nested identity deployment obtains the implicit OS-disk ID from
the completed VM before reading its UUID; direct resource-ID output references
are not treated as ordering dependencies.
The live VM must still have the anchored UUID and own the anchored disk, even
if its tags match the run. Required ownership tags are matched as a subset, so
unrelated additional tags do not invalidate otherwise proven resources; tags
alone still never authorize the implicit disk. Missing deployment outputs, a
disk present before deployment, a detached or replaced disk, or a replaced VM
stops cleanup. Matching names or tags alone never authorize deletion through
the VM or resource group.

The uploaded guest disk is anchored separately from the original `disk create`
response: its expected resource ID, immutable `uniqueId`, and run ownership
tags are recorded before upload access is granted. The controller revalidates
that identity while unattached before VM deployment and requires the same live
UUID plus reciprocal VM/disk attachment before accepting the guest or deleting
the group. A same-name disk with copied tags is never re-enrolled.
Cleanup can remove that proven disk before upload completes, including the
`ReadyToUpload` state; deployment still requires a fully imported disk.

## Run private application-network acceptance

Application-network acceptance consumes an imported, trusted, exact VHD. It
cannot run from mutable local preparation, cannot rebuild after preflight, and
does not permit `--keep-resources`. Supply a private `/29`, a static guest
address that avoids Azure's first four and last subnet addresses, and either an
explicit subscription UUID or an explicitly authorized private reservation:

```shell
chmod 600 "$PRIVATE_RESERVATION"
python3 support/scripts/hyperv-azure.py run \
  --state-dir "$STATE" --stage io --timeout 600 \
  --resource-group-reservation "$PRIVATE_RESERVATION" \
  --guest-ipv4 10.87.0.5 --subnet 10.87.0.0/29
```

Without a reservation, replace the reservation option with
`--subscription "$AZURE_SUBSCRIPTION"`. The controller passes that selection
to every Azure CLI command and never changes the global `az account` default.
Subscription identifiers remain only in private state and are omitted from
returned acceptance evidence.

A reservation is a private owner-only, non-symlink JSON file with schema
`unikraft.hyperv.resource-group-reservation`, version 1, phase
`group-created`, an explicit subscription/location/name prefix/group/group ID,
the exact disposable ownership tags, and `resource_count: 0`. The controller
first takes a nonblocking exclusive lock on a stable owner-only sibling lock
file. While retaining that lock across atomic reservation-file replacement, it
binds the reservation durably to the private run, exact image, and reviewed
manifest before any Azure check or mutation. It then verifies the selected
account, exact live group identity and tags, and two empty-resource listings
around the tag update. A successful claim leaves the reservation in the
`consumed` phase; a crash leaves it fail-closed in `claiming`, so neither can be
silently retried.

This exclusivity guarantee applies to cooperating processes using the same
canonical reservation path on one local filesystem. Copying the private
reservation creates a distinct lock domain and is unsupported; Azure tag
updates are not treated as compare-and-swap. Keep the consumed file and its
`.lock` sibling private for audit rather than copying or recreating them.
Normal runs still refuse to adopt any existing group.

Before any resource creation, the controller validates the Gen2 guest size,
one private `Standard_B1s` peer, x64/generation capabilities, combined regional
and family quotas, and the fixed Canonical `ubuntu-24_04-lts:server` image
line. It resolves and records one exact immutable image version; it never
deploys `latest` and never retries another region, size, SKU, or host.

The exact guest VHD upload completes before the 600-second peer lifetime
begins. One run-owned VNet has static peer `.4` and guest `.5` addresses, no
public IP, no default outbound access, and NSG rules limited to the configured
TCP/UDP exchanges plus Azure platform DHCP/metadata services. Cloud-init
embeds the unchanged standard-library peer and a lifecycle wrapper; it
downloads nothing and opens no SSH ingress. The required OS-profile password
is generated in memory, passed only through an owner-only ARM parameter file
as a `secureString`, and deleted after peer deployment.

The controller starts its conservative deadline before peer VM deployment,
durably records the successful deployment correlation, declared top-level
resources, and ARM-output immutable peer VM/disk identities before waiting
through bounded `Creating` or `Updating` control-plane states. The guest ARM
deployment similarly records its VM UUID, imported-disk attachment, and
reserved NIC before bounded readiness checks. Every peer, disk, NIC, guest, and
boot-diagnostic query must finish within the original deadline; no query or
transient state resets it. Terminal provisioning states fail immediately. The
controller then requires one exact `START` and matching `READY` before creating
the guest. The peer retains the 600-second process lifetime and five-second
exchange bounds.
Both serial streams must then contain unique ordered correlated evidence:
lease, ARP, three TCP exchanges, six UDP exchanges, exact bytes and transcript
digests, guest/peer cleanup, peer `EOF`, application final, overall I/O-ready,
and the exact producer `main returned 0` record. Integer wire fields must be
JSON integers (never booleans or floats), and the fixed TCP producer schedules
must prove at least 2/9/3 writes with the final total matching the three
records. TCP write and receive-callback counts cannot exceed the corresponding
transferred byte counts. Raw DHCP, peer-only success, stale/duplicate records, restart, bad
endpoint/nonce, missing EOF, or any failure is rejected.

Private `peer-serial.log`, `guest-serial.log`, and
`network-acceptance.json` are retained in the state directory. Cleanup is
attempted on success, failure, SIGINT, or SIGTERM, and deletes the disposable
group only after verifying ownership of every resource. Top-level peer
resources are bounded by the successful deployment record and durable
identities. Cleanup also revalidates the original guest deployment, exact VM
UUID, anchored uploaded-disk UUID, and reciprocal attachment before recovering
an interrupted post-deployment guest inspection. VM extensions are accepted
only as immediate children of the proven peer VM and must either be untagged or
carry the normal required ownership tags; unknown children and siblings remain
fail-closed. Cleanup independently verifies and requests deallocation of a
proven peer VM even when guest or uploaded-disk ownership cannot be established;
group deletion still remains blocked. If the run and cleanup both fail, all
sanitized failures are retained and reported without converting the run into
success. Unknown ownership stops deletion and surfaces a cleanup failure; it is
not a successful run or an implicit keep-resources mode. This controller path
creates no GitHub resources; live Azure acceptance remains an explicit operator
action after reviewing the exported manifest digest and source provenance.

## Real device acceptance

Build the [Hyper-V acceptance probe](../apps/hyperv-acceptance/README.md), then
prepare it in a fresh directory. Omit `prepare --expect` and `run --stage`;
their defaults require the probe's full I/O contract:

```shell
EFI="$PWD/support/apps/hyperv-acceptance/build/helloworld_hyperv-x86_64-efi-netvsc"
STATE="$PWD/.d/azure/device-probe"

python3 support/scripts/hyperv-azure.py prepare \
  --efi "$EFI" --miz "$MIZ" --state-dir "$STATE" \
  --ovmf-code /usr/share/OVMF/OVMF_CODE.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS.fd
python3 support/scripts/hyperv-azure.py run --state-dir "$STATE"
```

Success requires these exact serial lines, with the device results between
platform readiness and the final marker:

```text
UK_HYPERV_PLATFORM_READY
UK_HYPERV_BLOCK_READ_OK
UK_HYPERV_NET_DHCP_OFFER
UK_HYPERV_IO_READY
```

Missing devices, a failed request, a timeout, a nonzero application result, or
a crash cannot produce I/O acceptance. The block probe must perform actual
non-destructive reads; the network probe must receive a matching DHCP offer
after transmitting its request. Queue admission alone is insufficient.

Inspect saved evidence without any Azure calls:

```shell
python3 support/scripts/hyperv-azure.py inspect-log "$STATE/serial.log"
```

For a custom platform marker, supply matching `--stage platform --expect ...`.
The first controlled Azure VM may supply the real Hyper-V host when no separate
host is available, but only after the local gates pass. Full workload SMP,
stress testing, and production readiness remain separate milestones.

[trusted-launch]: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq#can-i-disable-trusted-launch-for-a-new-vm-deployment
[dsv5-nested]: https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dsv5-series
[upload]: https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-upload-vhd-to-managed-disk-cli
[miz-revision]: https://github.com/cataggar/miz/commit/2db68ca0c3ab12155012a823c3fb8d7aba1cb544
[unikraft-revision]: https://github.com/cataggar/unikraft/commit/8c87f56ab3eaa71974812cd748c3a6bfa61c563b
[amd-revision]: https://github.com/cataggar/unikraft/commit/4cdabd975ab4bc39dcdabeca496d8ee8630e3759
[amd-irq]: https://github.com/cataggar/unikraft/issues/81
[netvsc-variant]: https://github.com/cataggar/unikraft/issues/82
