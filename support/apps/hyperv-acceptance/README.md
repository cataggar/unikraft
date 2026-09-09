# Hyper-V hardware acceptance probe

This application is a bounded, non-destructive acceptance probe for a real
Hyper-V guest. Its default configuration preserves the lightweight hardware
smoke:

- inventory VMBus offers and bound StorVSC/NetVSC devices;
- read only OS-disk LBAs 0 and 1 and require MBR plus primary GPT signatures;
- send a checksummed raw DHCP Discover and accept one bounded, validated Offer;
- emit `HYPERV_ACCEPTANCE ... PASS|FAIL|UNAVAILABLE` serial markers.

The separately selected `app-network.defconfig` replaces only the raw DHCP
network stage with an official lib-lwip path. It manually attaches the first
NetVSC device with one RX and one TX queue, completes DHCP through the BOUND
state, verifies the applied lease, resolves an explicit same-subnet private peer
with ARP, and performs exact TCP and UDP exchanges. Storage remains read-only.
This profile admits two StorVSC controllers for Azure's normal OS/resource-disk
offer topology. It uses REPORT LUNS discovery, and an additional controller is
accepted as empty only after two successful zero-entry reports on the same
binding. Failed or disrupted addressed discovery remains unresolved. The probe
waits for current bound offers and a coherent StorVSC generation instead of
treating previously registered device counts as ready.
The application replaces only that netif instance's unbounded lib-lwIP
poll/transmit callbacks with a scoped boundary that processes at most 64 RX
packets per pump and attempts each TX exactly once. Persistent TX backpressure
fails acceptance instead of spinning; a continuous RX flood returns to lwIP
timers and the outer deadlines after every bounded batch. NetVSC also limits
each deferred channel drain to 64 VMBus packets and requeues remaining work on
the VMBus worker, including on legacy VMBus versions, so the bound applies
below the stack adapter. The pinned
external wrapper checkout remains unmodified.
On a DHCP start, adapter, or lease deadline failure, the application emits an
additive `NETWORK_DHCP_DIAGNOSTIC INFO` record containing bounded lwIP state and
NetVSC TX, completion, RX, queue, and transport counters before the existing
stable failure marker.

`UK_HYPERV_IO_READY` is emitted only when storage and the selected network mode
both pass. A missing offer is `UNAVAILABLE`; a present but unbound device or any
DHCP, ARP, peer, content, sequence, count, or timeout error is `FAIL`.

## Application-network peer contract

The default probe never writes to a block device. An environment without
StorVSC or NetVSC returns 2 (`UNAVAILABLE`); a present device that cannot bind,
configure, complete I/O, or meet the timeout returns 1.

The default private peer inputs are:

| Input | Value |
| --- | --- |
| IPv4 | `10.87.0.4` |
| TCP port | `18887` |
| UDP port | `18888` |
| Nonce | `87c0ffee5aa8dfd6` |

Override these with the
`APPHYPERVACCEPTANCE_PEER_*` and
`APPHYPERVACCEPTANCE_NONCE` Kconfig values before building. The nonce is exactly
16 hexadecimal digits without a `0x` prefix. The controller must copy these
four solved values into its image/run manifest and require the runtime
`NETWORK_APP_CONFIG` and `NETWORK_APP_FINAL` values to match. Invalid or missing
endpoint/nonce values fail before traffic. The peer address must be RFC 1918
and on the acquired interface's subnet, so this path cannot silently use public
ingress or a default Internet route.

Every application message starts with this 24-byte network-byte-order header:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `UKNA` |
| 4 | 1 | version `1` |
| 5 | 1 | transport: TCP `1`, UDP `2` |
| 6 | 1 | direction: guest request `1`, peer response `2` |
| 7 | 1 | header size `24` |
| 8 | 4 | sequence |
| 12 | 4 | body length |
| 16 | 8 | nonce |

For body byte offset `i`, both endpoints generate:

```text
(nonce >> ((7 - (i & 7)) * 8))
^ (sequence >> ((3 - (i & 3)) * 8))
^ (transport * 0x31)
^ (direction * 0x57)
^ (i * 0x1d)
```

and keep the low eight bits. The peer must validate every request and return
the same sequence, nonce, and body length with response direction/body bytes.
Malformed or additional expected-peer responses must not be treated as
success.

The bounded operation set is:

- TCP: three fresh connections, sequences `1..3`, with body sizes `31`, `1400`,
  and `257`; the guest writes each stream in repeating `7`, `113`, and `509`
  byte chunks and accepts arbitrary response segmentation;
- UDP: one PCB and six request/response datagrams, sequences `0x100..0x105`,
  with body sizes `19`, `1448`, `73`, `1448`, `257`, and `19`; a 1448-byte
  body plus the header is a 1472-byte IPv4 UDP payload;
- DHCP: 12-second deadline;
- ARP: 5-second deadline with one-second retries;
- each TCP connection and each UDP exchange: 5-second deadline.

After sending each complete TCP response, the peer must shut down its write
side to deliver orderly EOF. The guest keeps the PCB callbacks installed and
does not count success until the request is fully acknowledged, the exact
response is validated, and that EOF arrives. Delayed extra bytes, a reset, or
missing EOF fails under the same five-second deadline. The peer must keep the
UDP source address and port equal to the configured destination.

Stable application markers are:

- `HYPERV_ACCEPTANCE NETWORK_APP_CONFIG`
- `HYPERV_ACCEPTANCE NETWORK_APP_LEASE`
- `HYPERV_ACCEPTANCE NETWORK_APP_ARP`
- `HYPERV_ACCEPTANCE NETWORK_APP_TCP`
- `HYPERV_ACCEPTANCE NETWORK_APP_UDP`
- `HYPERV_ACCEPTANCE NETWORK_APP_FINAL`
- `UK_HYPERV_NET_APP_LEASE`
- `UK_HYPERV_NET_APP_ARP`
- `UK_HYPERV_NET_APP_TCP`
- `UK_HYPERV_NET_APP_UDP`
- `UK_HYPERV_NETWORK_APP_READY`

The config and final markers report the exact peer IPv4, TCP/UDP ports, and
nonce for manifest correlation. PASS markers also report connection/datagram,
byte, chunk/callback, pbuf, adapter-budget, and cleanup counts. No
application-network marker proves Azure acceptance until a real same-VNet peer
run produces the exact PASS contract.

## Pinned stack dependency

`network-stack.mk` pins the official
[`unikraft/lib-lwip`](https://github.com/unikraft/lib-lwip) integration to
commit `ec55ae17618feeb57c8c10109bcf5c42723e8e95`. The application configuration
selects upstream `STABLE-2_1_2_RELEASE`; the official integration verifies its
archive with SHA-256
`8f0ae46e2702720ce852b00de5d304adb2809b0203741f299876594bb8be7890`.
Both integrations carry BSD-3-Clause notices in their source files.

Materialize and verify the wrapper below the checkout:

```sh
make -C support/apps/hyperv-acceptance network-stack
```

Application-network builds also verify the wrapper commit, origin URL, and
clean worktree during `prepare`. Do not point `-Dexternal-lib` at an unreviewed
checkout.

## Protocol fixtures

Run the host-side protocol, production NetVSC, and native-profile fixtures
without booting a guest on either x86-64 or AArch64:

```sh
mkdir -p .d/acceptance-tmp .d/acceptance-cache
TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
zig build test-network-regression -j2
```

The required `test-hyperv-regression` selector includes this coverage, including
the real worker continuation path after legacy protocol negotiation.

The application fixture includes deterministic multi-pump callback-state
regressions for a reset PCB with unsent bytes, delayed extra bytes or reset
after a valid response, orderly EOF, and missing-EOF timeout. It also drives
endless mock RX and persistent TX-busy statuses through the same bounded
policy used by the guest, proving that timer/deadline checks and cleanup regain
control. The NetVSC production fixture separately replenishes mock VMBus
traffic during a real driver drain, reenters `drain_pending`, verifies exact
64-packet returns and deferred progress, then covers TX saturation and detach
cleanup.

## Build the default raw smoke

```sh
umask 077
mkdir -p .d/acceptance-tmp .d/acceptance-cache
cp support/apps/hyperv-acceptance/defconfig \
  support/apps/hyperv-acceptance/.config

TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
zig build olddefconfig -j2 \
  -Dapp="$PWD/support/apps/hyperv-acceptance" \
  -Dconfig="$PWD/support/apps/hyperv-acceptance/.config"
```

Then use the native command below without `-Dexternal-lib`.

## Build the application-network image

```sh
umask 077
make -C support/apps/hyperv-acceptance network-stack
mkdir -p .d/acceptance-tmp .d/acceptance-cache
cp support/apps/hyperv-acceptance/app-network.defconfig \
  support/apps/hyperv-acceptance/.config

TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
zig build olddefconfig -j2 \
  -Dapp="$PWD/support/apps/hyperv-acceptance" \
  -Dconfig="$PWD/support/apps/hyperv-acceptance/.config" \
  -Dexternal-lib="$PWD/.d/deps/lib-lwip"
```

Build either solved configuration with:

```sh
TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
zig build native-images -j2 \
  -Dapp="$PWD/support/apps/hyperv-acceptance" \
  -Dconfig="$PWD/support/apps/hyperv-acceptance/.config" \
  -Dnative-profile=hyperv-x86_64-efi-netvsc \
  '-Dcompiler=zig cc -target x86_64-freestanding-none' \
  -Dcompiler-targeted=true \
  '-Dhost-cc=zig cc' \
  '-Dhost-cxx=zig c++' \
  -Dhost-cflags=-fno-sanitize=null \
  '-Dmake-arg=AR=zig ar' \
  -Dmake-arg=NM=llvm-nm \
  -Dmake-arg=OBJCOPY=llvm-objcopy \
  -Dmake-arg=OBJDUMP=llvm-objdump \
  -Dmake-arg=READELF=llvm-readelf \
  -Dmake-arg=STRIP=llvm-strip \
  -Dmake-arg=UK_CFLAGS=-std=gnu17 \
  -Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt
```

For application networking, add
`-Dexternal-lib="$PWD/.d/deps/lib-lwip"` to that command.

The native image is
`support/apps/hyperv-acceptance/build/helloworld_hyperv-x86_64-efi-netvsc`.
The application library retains the native graph's `apphelloworld`
compatibility name.

## Opt-in persistence workload

`CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE=y` replaces the ordinary probe with a
destructive workload that is valid only for a disposable, run-owned data disk.
Generate the private seed and matching Kconfig fragment before the one final
guest image build:

```sh
python3 support/scripts/hyperv-storage-manifest.py \
  --output-prefix "$PWD/.d/persistence/run" \
  --identity-policy seed-enrollment-v2 \
  --sectors 262144 --lun 1 --fixed-vhd
cat .d/persistence/run.config >> support/apps/hyperv-acceptance/.config
```

The helper creates a sparse raw disk with identical immutable manifests at
LBAs 8 and 9, plus a private JSON receipt for orchestration. With
`--fixed-vhd`, it also creates a sparse fixed VHD whose data region is
byte-for-byte equal to the raw seed and whose deterministic footer UUID is the
private disk ID. This conversion must happen before the final guest build and
controller contract; neither file may subsequently be reseeded or mutated.
The controller provisions the requested exact logical geometry, attaches the
same managed data disk at the configured LUN, and retains the exact guest image
and data-disk UUIDs for both boots.

Identity policy 1 (`address-v1`, the generator default for compatibility)
requires `--path`, `--target`, and `--lun` and emits the original `UKPSEED1`,
`UKPINT01`, and `UKPDONE1` records unchanged. Identity policy 2
(`seed-enrollment-v2`) fixes LUN, geometry, run ID, and disk ID before the
build, but deliberately does not guess path or target. The guest considers
all exact LUN/geometry candidates in one coherent inventory generation,
rejects unsafe boot-shaped or identity-less candidates, and enrolls path,
target, controller instance, and VPD only after exactly one private seed
matches. V2 uses `UKPSEED2`, `UKPINT02`, and `UKPDONE2`; record versions,
manifest CRC, and explicit policy bytes prevent fallback or cross-policy
reuse.
The private JSON `version` and `identity_policy_version` are likewise 1 or 2;
v2 reports `path` and `target` as `null` because they are enrollment outputs,
not controller guesses.

The guest opens read sessions only for policy-matching candidates, rejects
MBR/GPT-shaped media, and requires exactly one matching private manifest with
a supported nonzero VPD identity. Boot 1 then authorizes that session, flushes
an intent at LBA 16, writes and verifies deterministic patterns at LBA 0, the
final LBA, and LBAs 32..47, flushes and verifies again, and flushes a
completion receipt at LBA 17. Boot 2 requires the complete enrolled address,
controller, and VPD identity plus a valid receipt, rereads every pattern, and
performs no writes.

The controller and LUN limits reserve identities for the life of the boot;
they are not reusable active-slot limits after removal. Mapping and inventory
snapshots are observations, not immutable disk pins. Candidate enumeration,
rejected sessions, the retained candidate, and write authorization are bound
to one topology generation, and any enumerate, removal, reset, or rebind makes
the session permanently stale. If an accepted request exceeds the workload
deadline, its descriptor and DMA storage remain reserved and immutable and
the workload cannot issue more I/O or end the session during that boot.

Persistence and application-network workloads are mutually exclusive Kconfig
choices. The default selection remains the non-destructive storage/network
smoke probe.

For policy 2 only, a boot that remains storage-pristine through the existing
bounded bind wait is classified as platform-only unavailable. The driver must
produce two coherent empty inventory snapshots at
`UK_STORVSC_TOPOLOGY_PRISTINE_GENERATION`, and must still report that no
storage offer, session, or I/O activity has ever occurred during the boot.
The offer observation is sticky at VMBus ingress, so device-pool exhaustion
before StorVSC admission cannot be misclassified as an empty platform.
The exact output is:

```text
HYPERV_PERSISTENCE SELECT UNAVAILABLE reason=no-devices writes=0 flushes=0
UK_HYPERV_PLATFORM_READY
UK_HYPERV_PERSISTENCE_UNAVAILABLE:1:2:no-devices
```

It returns 2 and emits no selection failure, final success, identity,
Boot 1/Boot 2, write, or completion marker. This is not storage acceptance.
Policy 1, any nonempty or uncertain inventory, and an empty inventory after
any earlier offer, topology transition, session, or I/O activity remain
failures. Controllers must match the complete versioned marker; a generic
failure or unavailable result is not equivalent.

Stable success markers are:

- `UK_HYPERV_PERSISTENCE_BOOT1_COMPLETE:<run-id>`
- `UK_HYPERV_PERSISTENCE_BOOT2_COMPLETE:<run-id>`
- `UK_HYPERV_PERSISTENCE_IO:1:1:<run-id>:5:3:receipt-verified`
- `UK_HYPERV_PERSISTENCE_IO:1:2:<run-id>:0:0:receipt-verified`

The versioned I/O records are emitted only by policy 2. The Boot 1 counts bind
the five write requests and three flush requests in the guarded workload,
including the durable intent and completion receipt. The Boot 2 record binds
zero writes and zero flushes after readback of the accepted receipt and all
patterns. Policy 1 output is unchanged.

Each successful selection also emits one bounded private identity record:

```
UK_HYPERV_PERSISTENCE_IDENTITY:1:<policy>:<run-id>:<disk-id>:<controller-guid>:<path>:<target>:<lun>:<sectors>:<sector-size>:<vpd-length>:<code-set>:<type>:<association>:<vpd-id>
```

IDs and VPD bytes are lowercase hexadecimal without separators; all other
fields are unsigned decimal. The controller must keep this line private,
require the same enrolled identity on Boot 2, and never place real run
records or the seeded image in public CI artifacts. Public fixtures use only
synthetic identifiers.

The immutable guest cannot distinguish a controller rollback to the pristine
seed from a genuine first boot. During the expected second boot, orchestration
must therefore reject any boot-1/write marker; a receipt alone is not accepted
without the guest's boot-2 pattern-read marker. Incomplete or corrupt
intent/receipt state fails closed and is never restarted.
