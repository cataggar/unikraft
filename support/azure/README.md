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
- QEMU with KVM, `vmbus-bridge`, and `hv-balloon`, plus x86-64 OVMF code and
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
  --ovmf-code /usr/share/OVMF/OVMF_CODE.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS.fd \
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

The private directory retains the EFI payload, raw disk, VHD, their fingerprints,
the `miz` executable fingerprint and packaging report, and all four serial logs
(`local-{raw,vpc}-{x2apic,legacy-apic}-serial.log`).
Tool caches and temporary files stay below that directory. Fresh firmware
copies are removed after each local boot. Existing state directories are never
overwritten.

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

`state.json` retains `local_platform_boot_modes` for the raw and fixed-VHD
x2APIC/legacy-APIC boots, while `image_sha256` remains the deployment identity.
A later trusted `workflow_dispatch` stage should consume this prepared VHD and
call the existing `run`/`cleanup` controller paths one VM at a time; it should
not rebuild, repackage, add a second deployment pipeline, infer coverage from
CPU/SKU labels, or allocate repeatedly to search for a protocol version.
Ordinary pull requests intentionally have no Azure stage or credentials.
The `zig-hyperv-local-evidence` CI artifact retains selected local serial and
packaging logs, the packaging report, and EFI/debug-ELF digests for seven days,
including boot failures. It excludes raw controller state, disk images, tool
caches, and credentials.

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
fresh state directory for another attempt.

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
[upload]: https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-upload-vhd-to-managed-disk-cli
[miz-revision]: https://github.com/cataggar/miz/commit/2db68ca0c3ab12155012a823c3fb8d7aba1cb544
[unikraft-revision]: https://github.com/cataggar/unikraft/commit/8c87f56ab3eaa71974812cd748c3a6bfa61c563b
[amd-revision]: https://github.com/cataggar/unikraft/commit/4cdabd975ab4bc39dcdabeca496d8ee8630e3759
[amd-irq]: https://github.com/cataggar/unikraft/issues/81
[netvsc-variant]: https://github.com/cataggar/unikraft/issues/82
