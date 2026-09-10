# Native agentless Hyper-V host

This is an implemented, offline-fixture-tested host runner and phased Blob
protocol, **not an admitted or deployable host image**. It does not provision
resources, publish an image, configure networking/RBAC, or use SSH. The existing
controller and root CLI integration remain separate work.

The executable has no credential, SAS, endpoint, signing-key, or fixture runtime
arguments. `uk-hyperv-host run` reads only the image's fixed
`/etc/uk-hyperv-host/{admission,locator}.json` files. Its Ed25519 verification key
is compiled into the image with `-Dimage-trust-key=<64 lowercase hex>`. No default
key is provided. Building with a synthetic fixture key is not production
admission. The two internal child commands require private operation records;
production children additionally require their process-group owner to be the
same admitted runner image. A boot child revalidates the current durable boot
intent, signed command, expiry, real host boot ID, and private acceptance.

## Authority and wire contracts

`protocol.zig` uses the merged core's bounded JSON parser and canonical encoder:
compact JSON, byte-sorted keys, and one final LF. Signed envelopes have exactly
`body` and `signature`, where the signature is 128 lowercase hexadecimal
characters. Ed25519 signs `DOMAIN + "\n" + canonical(body)`. Domains are separate:

| Domain/schema | Bound authority |
| --- | --- |
| `uk-hyperv-image-admission-v1` | Runner SHA-256, host-image SHA-256, guarded-producer SHA-256, account/container, issuance/expiry, exact host envelope, and image-baked staging/control bytes |
| `uk-hyperv-host-command-v1` | Exact run UUID, original IMDS VM UUID, phase UUID nonce, phase, issuance/expiry, runner/image/manifest SHA-256, manifest, and private acceptance |
| `uk-hyperv-public-acceptance-v1` | Run/VM UUIDs, public phase nonce, **complete public command bytes** SHA-256, **exact successful public receipt bytes** SHA-256, original host boot ID, issuance/expiry |

`protocol.zig` defines the complete exact field sets. UUIDs have canonical
lowercase spelling and RFC variant/version 1-5. Hashes are lowercase hex.
Issuance cannot be in the future, expiry is exclusive, and validity cannot exceed
3,600 seconds. Commands cannot outlive image admission. Duplicate/unknown JSON
fields, floating-point coercions, ambiguous names, unknown roles and mismatched
bindings are rejected.

The non-secret locator contains exactly `account`, `container`, and `run_id`.
Account/container must equal signed image admission. No URL, query string,
credential source, client ID or trust root is accepted from the locator.

Blob paths are constructed, not supplied as arbitrary URLs:

```text
https://ACCOUNT.blob.core.windows.net/CONTAINER/
  runs/RUN/commands/public.json
  runs/RUN/commands/private.json
  runs/RUN/PHASE/artifacts/NAME
  runs/RUN/evidence/PHASE/PHASE_NONCE/boot-N.log
  runs/RUN/evidence/PHASE/PHASE_NONCE/receipt.json
```

The manifest has `raw_size`, `policy`, `guarded`, and `artifacts`. Each artifact
has exactly `role`, `name`, `blob`, `sha256`, and `size`. Public roles are QEMU,
OVMF code/vars, and `capability.raw`; private roles reuse exactly the public
infrastructure and add `private.raw` and `private.vhd`. Up to 124 support records
may name safe components under `qemu/lib/` or `qemu/share/`. Every byte is hashed;
the VHD must be raw-size plus 512, have the same raw prefix digest, and begin its
footer with `conectix`. The private manifest's ordered infrastructure commitment
must equal the public one. Infrastructure is not redownloaded in the private
phase.

`wire.Client` uses the pinned Azure Core streaming HTTP transport and standard
crypto. Its IMDS endpoints are literal link-local addresses with `Metadata: true`.
It reads the original VM UUID, North Europe location and D2s-v5 size, then requests
a managed-identity token for the fixed Storage resource, without an identity
selector. The parent must admit the VM's **system-assigned-only** identity/RBAC
configuration; the token request is not an independent ARM identity-mode proof.
There is no ambient/default credential chain, CLI subprocess, environment
credential, token cache, or SDK credential/error-logging path. The SDK convenience
managed-identity helper is deliberately not called: it buffers and logs error
responses. Tokens and owned Authorization copies are erased; tokens never cross
the worker boundary or enter argv, job files, receipts or public diagnostics.

All HTTP requests disable redirects and retries. GETs stream through bounded
buffers; duplicate framing headers, compression, conflicting transfer framing,
wrong lengths and excess bytes fail closed. PUT uses BlockBlob,
`If-None-Match: *`, exact content length and MD5. Only a completely bounded,
successful 201 response completes publication. Lost replies and uncertain
mutations remain **unknown**, never a retry or a success-shaped fallback.

## Execution and durable evidence

`worker.Engine` connects signature verification, the durable store, streaming
artifact staging, real subprocess supervision, serial validation and publication.
`native.Supervised` is its concrete process-isolated transport adapter. The
exported build module is `hyperv_host`; import names are `hyperv_core` and the
pinned `azure_sdk_core`. Parent integration can use `worker.Engine`,
`native.Supervised`, `wire.Client`, or the standalone executable.
The production `native.run`, `wireChild`, and `authorizeBootChild` entrypoints
require a compile-time key. An embedding CLI must retain the supplied child
dispatch/authorization and immutable paths; it must not expose fixture transports
or `worker.Engine`'s test injection parameters as runtime overrides.

There is one stable core writer lock and one attempt per host state directory.
An attempt-start marker is create-only. A phase's complete signed command is
durably consumed **before staging/booting**; each boot counter is durable before
launch. Each helper also consumes a create-only launch claim. Interrupted intents,
interrupted network operations, duplicate phases and a process restart cannot
replay boots. The production CLI deliberately refuses to restart even a completed
public phase: the continuously running, admitted service must receive private
acceptance during the same attempt. State must never be rolled back or erased to
retry an attempt.

Public has exactly two successful required boots: x2APIC and legacy xAPIC.
Private has exactly four: raw then VHD, each in those two modes. Private staging
is unreachable until the parent authenticates the exact successfully published
public evidence. A public boot or evidence-publication failure permanently
prevents private transfer. There is no seventh boot and no automatic retry after
partial failure.

QEMU keeps the legacy exact q35/KVM, Hyper-V CPU features, one CPU, 512-MiB guest,
OVMF pflash, raw offset/size blockdev, virtio-blk, vmbus-bridge, headless stdio
serial, no monitor/reboot/NIC arguments. The verified QEMU descriptor is executed
with `execveat`. Each boot hard-links the same verified image inode and copies
fresh OVMF vars. Image/code/template inode, size and timestamps are checked after
execution. The launch helper redirects both QEMU streams to a private, 1-MiB
RLIMIT_FSIZE-bounded serial file, preserving failure output rather than relying
on the core supervisor's success-only stdout buffer.

The core supervisor owns each QEMU or wire child process group separately, with
monotonic hard deadlines and independent TERM/KILL/reap cleanup. **There are no
nested supervisors creating groups outside an outer supervisor's ownership.**
Network operations, including blocking SDK reads and token acquisition, run in
separate supervised workers. QEMU has at most 120 seconds, additionally bounded
by command expiry and the original attempt deadline. Per-read budget checks are
not claimed to interrupt blocking syscalls.

The supplied, **not installed** systemd unit provides an independent 60-minute
whole-service deadline and 120-second cgroup cleanup bound, including parent
filesystem work. Its installation/enforcement must be admitted as part of the
immutable image. Primary, cleanup and recording failures remain separate in
private state, per-boot outcomes and receipts. Serial semantics require the
legacy capability/platform/acceptance/main-return gates, reject live I/O and
crashes, and enforce exact guarded persistence identity/order with zero writes
and flushes. Receipts include actual kernel host boot IDs, fresh launch UUIDs,
image/serial hashes, byte counts and evidence kind. No exit-code-only PASS exists.

## Limits and admission blockers

The user explicitly approved a **2-MiB native-only control cap on 2026-09-10**.
The cumulative staging limit remains unchanged. This approval changes no cloud,
image-publication, identity, RBAC or network admission.

| Item | Native bound |
| --- | --- |
| Control allowance | 2,097,152 bytes, including image-baked controls |
| Cumulative staging | 268,435,456 bytes |
| Command/admission | 65,536 bytes each |
| Individual artifact | 134,217,728 bytes |
| Serial per boot / aggregate evidence | 1,048,576 / 8,388,608 bytes |
| Attempt / per-boot / independent cleanup | 3,600 / 120 / 120 seconds |
| Total wire operations | 256, with no mutation retries |

Signed `image_control_bytes` includes the executable, unit and every other
image-baked control. It must cover at least the measured runner plus the supplied
unit's compiled-in byte length; this minimum is not proof that all other controls
are present in the signed subtotal. `image_staging_bytes` is the parent's signed
starting debit/reservation for the complete workflow ledger, including **all** image-baked
bytes, image publication and other producer staging. It cannot be less than image
controls. Other lanes' future staging must already be reserved there; this
host-local ledger is not a substitute for that admission. The ledger additionally charges
commands, operation files, every atomic state version, evidence copies/uploads,
artifact transfers and fresh firmware copies. Failed/uncertain transfers retain
their reservation. Only known unused GET/result reservations are released.
4 KiB is reserved for emergency recording; serial reserves its full bound.
Before the first identity worker or network operation, the startup gate also
requires room for the actual admission/locator bytes, the 8-KiB bootstrap
reservation and both initial ledger writes at their full 4-KiB bounds. The
bootstrap reservation covers one identity job/result and the attempt marker,
not an unmetered sequence of workers. The running ledger charges actual state
versions; the conservative pre-network check does not exempt later recording.
Hard links add no second image byte copy. No image publication, baked payload,
runner or control wrapper may be excluded from the admission accounting.
Receipt counters explicitly describe the reservation **before that receipt**;
the durable local ledger also charges the receipt and subsequent recording.

An executable or declared image subtotal above the native cap remains invalid.
An otherwise fitting image without complete startup/recording headroom is also
rejected before IMDS. A runner-plus-unit measurement alone does not admit a
complete image, all remaining controls, or its cumulative staging ledger.
There are no binary, unit, image-baked, startup, ledger or emergency exemptions.
Legacy Python policy, historical receipts and existing signed admissions are
not rewritten or reinterpreted by this native policy change.

The synthetic-key x86_64 Linux-musl ReleaseSmall measurement is **887,336 bytes**
for the runner and **647 bytes** for the unit: **887,983 bytes together**.
That known subtotal fits the approved 2,097,152-byte cap, leaving 1,209,169 bytes
before accounting for every other control, admission/locator, startup,
emergency reservation and ledger version. It is not whole-image or deployment
admission, nor permission to exclude any remaining bytes.

Production remains blocked on a reviewed immutable-image closure and signing
authority, secure delivery/binding of signed admission and non-secret locator,
the complete image-publication/staging ledger, enforced unit/deadline policy,
exact original VM/identity/RBAC admission and restricted IMDS/Blob routes.
The signed envelope retains North Europe, Standard security, D2s-v5, one
32-GiB StandardSSD OS disk, no host data disks, no inbound access/SSH/public IP or
NAT. This module neither provisions nor proves those ARM-side conditions; the
parent's independent admission must. No real IMDS/token, credential, Azure,
resource, image-publication, network, original artifact or private seed operation
was used in these fixtures.

## Focused local build

Zig 0.16.0 is required. Run from the owned worktree. Restore only the pinned
package manifests, into scratch; this distribution otherwise creates `zig-pkg`
beside the build file. All subsequent builds use `--system` to disable fetching.

```sh
out=/d/fleet-platform/.d/zig-migration-host
export TMPDIR="$out/tmp" XDG_CACHE_HOME="$out/cache"
export ZIG_GLOBAL_CACHE_DIR="$out/global-cache" ZIG_LOCAL_CACHE_DIR="$out/local-cache"
mkdir -p "$out/packages/restore" "$out/out/fixtures"
chmod 700 "$out/out/fixtures"
cp support/tools/hyperv/host/build.zig support/tools/hyperv/host/build.zig.zon "$out/packages/restore/"
/home/g/.local/bin/zig build --build-file "$out/packages/restore/build.zig" --fetch=all -j2
/home/g/.local/bin/zig build --build-file support/tools/hyperv/host/build.zig test \
  --system "$out/packages/restore/zig-pkg" --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" --prefix "$out/out" \
  -Dtest-root="$out/out/fixtures" -j2 --summary all
```

Use `-Doptimize=ReleaseSafe` for checked optimized fixtures. A cross-build uses
`-Dtarget=x86_64-linux-musl -Doptimize=ReleaseSmall` and an explicitly synthetic
image public key; it is not cloud admission. `-Dtest-filter=TEXT` narrows native
fixture names. Fixture directories retain private local evidence under scratch.
`test install` also compiles the CLI and therefore requires an explicit synthetic
`-Dimage-trust-key`. Both cache layouts are supported: an absolute cache outside
cwd, and an absolute cache inside cwd such as
`$PWD/.d/zig-migration-host-controls/Debug/zig-local-cache`. Keep `--cache-dir`
explicit. Zig may emit the latter fixture path relative to cwd; the fixture
normalizes it once into its assets arena and uses that same absolute path for
byte loading and both supervisors. No production path requirement or lazy build
dependency is weakened, and moving caches is not the fix.
Fixtures execute native child processes and synthetic streaming responses,
including six-boot phasing, interruption, publication ambiguity, failures,
timeouts, descendant cleanup, serial limits and negative authority cases.
Their receipts are labeled `synthetic_child`; neither an architecture skip nor
a synthetic child is represented as real guest/KVM/cloud evidence.
