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
The application replaces only that netif instance's unbounded lib-lwip
poll/transmit callbacks with a scoped boundary that processes at most 64 RX
packets per pump and attempts each TX exactly once. Persistent TX backpressure
fails acceptance instead of spinning; a continuous RX flood returns to lwIP
timers and the outer deadlines after every bounded batch. NetVSC also limits
each deferred channel drain to 64 VMBus packets and requeues remaining work on
the VMBus worker, so the bound applies below the stack adapter. The pinned
external wrapper checkout remains unmodified.

`UK_HYPERV_IO_READY` is emitted only when storage and the selected network mode
both pass. A missing offer is `UNAVAILABLE`; a present but unbound device or any
DHCP, ARP, peer, content, sequence, count, or timeout error is `FAIL`.

## Application-network peer contract

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
PATH="$PWD/.d/pixi/bin:$PATH" \
make -C support/apps/hyperv-acceptance network-stack
```

Application-network builds also verify the wrapper commit, origin URL, and
clean worktree during `prepare`. Do not point `-Dexternal-lib` at an unreviewed
checkout.

## Protocol fixtures

Run both host-side protocol fixtures without booting a guest:

```sh
make -C support/apps/hyperv-acceptance \
  HOSTCC='/home/g/.local/bin/zig cc' protocol-test
```

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
