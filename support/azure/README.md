# Hyper-V / Azure acceptance

`../scripts/hyperv-azure.py` packages an already-built x86-64 Hyper-V EFI
application, boots the resulting disks locally, and then optionally runs a
bounded Azure Generation 2 acceptance deployment. A platform boot is not a
storage/network pass.

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
preflighted by `miz` and also booted under OVMF, read-only. Each local boot is
bounded and must reach hypercall/SynIC initialization and the exact application
marker without a crash. QEMU's missing storage/network endpoints do not count
as I/O success.

The private directory retains the EFI payload, raw disk, VHD, their fingerprints,
the `miz` executable fingerprint and packaging report, and both serial logs.
Tool caches and temporary files stay below that directory. Fresh firmware
copies are removed after each local boot. Existing state directories are never
overwritten.

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
