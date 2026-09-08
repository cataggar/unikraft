# Hyper-V hardware acceptance probe

This application is a bounded, non-destructive acceptance probe for a real
Hyper-V guest:

- inventories VMBus offers and bound StorVSC/NetVSC devices;
- reads only OS-disk LBAs 0 and 1 and requires MBR plus primary GPT signatures;
- sends a checksummed DHCP Discover from the NetVSC MAC and accepts only a
  bounded, validated DHCP Offer;
- emits `HYPERV_ACCEPTANCE ... PASS|FAIL|UNAVAILABLE` serial markers;
- emits `HYPERV_ACCEPTANCE HARDWARE_IO_READY PASS` only after both real I/O
  stages pass.

An environment without StorVSC or NetVSC returns 2 (`UNAVAILABLE`); a present
device that cannot bind, configure, complete I/O, or meet the timeout returns 1.
The probe never writes to a block device.

From the repository root, generate a private solved configuration and build the
native Hyper-V EFI profile:

```sh
umask 077
mkdir -p .d/acceptance-tmp .d/acceptance-cache
cp support/apps/hyperv-acceptance/defconfig \
  support/apps/hyperv-acceptance/.config

TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
zig build olddefconfig \
  -Dapp="$PWD/support/apps/hyperv-acceptance" \
  -Dconfig="$PWD/support/apps/hyperv-acceptance/.config"

TMPDIR="$PWD/.d/acceptance-tmp" \
XDG_CACHE_HOME="$PWD/.d/acceptance-cache" \
ZIG_GLOBAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-global" \
ZIG_LOCAL_CACHE_DIR="$PWD/.d/acceptance-cache/zig-local" \
zig build native-images \
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

The native image graph currently publishes this profile as
`support/apps/hyperv-acceptance/build/helloworld_hyperv-x86_64-efi-netvsc`.
The application library retains the graph's `apphelloworld` compatibility
name; the serial markers and binary behavior are Hyper-V acceptance-specific.
