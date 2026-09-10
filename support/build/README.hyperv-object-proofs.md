# Native Hyper-V object contracts

`hyperv-object-proofs.zig` replaces the five object-checker invocations in the
root build. Their original freestanding Zig compilation, real `zig cc -r`
links, C/C++ header compilation and downstream dependencies remain intact.
The Python source files remain dormant references; this selector neither
executes them nor uses their output as an oracle.

## Interface and assertion mapping

```
hyperv-object-proofs PROFILE --object FILE [--nm TOOL] [--readelf TOOL]
    [--mapping-api-object FILE]... [--timeout-ms N]
```

| Profile / former `tests/*-test.py` | Native contract |
| --- | --- |
| `hyperv-runtime` | All 24 original exports; four exact page section names; numeric section size, alignment, type, flags, offsets and storage-symbol binding |
| `vmbus-protocol` | All 14 original protocol exports |
| `vmbus-channel` | All 9 original channel/ring exports |
| `storvsc-core` | All 20 original storage core exports; all five original unmangled mapping references in **each** repeated mapping input |
| `netvsc-protocol` | All 13 original NVS/RNDIS exports; reusable separately from network/controller aggregates |

Every primary object rejects undefined and COMMON symbols. Required exports
are exact, unique, strong global/default-visible definitions with the proper
FUNC/OBJECT type, nonzero size and section containment. Functions occupy
allocated, executable, nonwritable PROGBITS. Extra legitimate definitions are
allowed. A prefix collision, weak/local/absolute pseudo-export or text-only
tool claim cannot satisfy a required definition.

The mapping C and C++ producers still compile the production header's layout
and signature assertions. Each object must independently reference all five
mapping/inventory API names as global undefined symbols and through nonzero
RELA entries in allocated executable PROGBITS. References are not unioned
across inputs. Other undefined API references in these ABI fixtures remain
permitted; this is not a link-completeness requirement for the ABI objects.

The four runtime pages are exactly 4096 bytes, aligned to 4096, with an exact
4096-byte storage symbol at section offset zero. The actual producer emits
the const hypercall page as **PROGBITS/A**, not AX; the three mutable pages
are **NOBITS/WA**. The native checks cross-check exact numeric `readelf -SW`
rows with ELF metadata, rather than searching for section-name or size
substrings. Executability of the final mapped hypercall page is a separate
linked-image proof, not inferred from its `.text` name here.

Library boundaries are `Object.parse/deinit/definition/reference` in
`hyperv-object-elf.zig`, and `Options.parse`, `validate`, `validateMapping`,
`checkNm`, `checkSections`, `execute` in `hyperv-object-proofs.zig`.
Objects borrow their immutable input bytes; callers own those bytes and
deinitialize the allocated index. `Options` borrows argument strings.

`--nm` and `--readelf` retain the original `llvm-nm` and `llvm-readelf`
defaults. Each is a single executable name/path, never a shell command.
Multicall symlink basenames are preserved. `--readelf` is runtime-only;
repeated `--mapping-api-object` is StorVSC-only. CLI failure output contains
only a fixed prefix and static error-name enum; it never forwards file paths,
tool stderr/stdout, symbol strings or arbitrary subprocess messages. Exit 2
means invalid arguments/tool specification, exit 1 an unsuccessful proof,
and exit 0 a completed proof (or explicitly requested help/notice).

## Bounds and process contract

The parser accepts only little-endian ELF64 x86-64 ET_REL objects: at most
64 MiB, 4096 sections, 65536 symbols, 262144 total RELA entries and 4096-byte
names. Unsupported symbol tables/extended indices and REL records fail
closed. There are at most 32 mapping inputs and 80 option arguments.
LLVM stdout is capped at 4 MiB and stderr at 64 KiB.

The Linux `support/tools/hyperv/process.zig` supervisor supplies a shared
invocation deadline (default 30 seconds, configurable from 1 to 30000 ms),
process-group termination/reaping, bounded capture and separate cleanup
failure handling. Its cleanup grace remains separate from the execution
deadline. Children receive an empty environment; PATH is used only for
parent-side executable lookup. Parser work has explicit count/size bounds.
This is a build-owned regular-file verifier, not an adversarial filesystem
race/immutable-artifact admission service or a cryptographic attestation.

## Focused selectors

`hyperv-object-proofs` installs only the verifier at
`PREFIX/bin/hyperv-object-proofs`. `test-hyperv-object-proofs` exercises the
five real linked freestanding objects, both mapping ABI objects, four
portable protocol/core Zig suites, the NetVSC/VMBus C ABI executables, native
parser/CLI unit tests and the real-object negative fixture driver.

The focused selector does not add the runtime's x86-only hosted calling
convention tests on an AArch64 host; it always produces and verifies the
real x86-64 runtime object. Existing architecture branches and hosted gates
are unchanged. The separate `architecture-notice` command replaces only
the former fixed Python print. Neither notice nor architecture omission
counts as boot evidence.

The fixture driver uses native `llvm-objcopy`, real relocatable linking with
an unresolved C reference, and bounded mutations of the produced ELF bytes.
Cases cover all five profiles, exact/prefix-colliding/duplicate exports,
local/weak/wrong-type/hidden/absolute/COMMON exports, empty or out-of-section
definitions, unresolved symbols, wrong page/storage properties, mapping
order and per-input failures, detached mapping relocations, bad headers and
tables, truncation/oversized/nonregular inputs, missing/invalid/failing/silent
or flooding tools, deadlines, fixed-output redaction, and invalid CLI options.
Fixture-only native fake tools are never selected by production code.
Each successful fixture run records its case count in its generated
`hyperv-object-fixtures/result.txt`.

Pinned local invocation (Linux, Zig 0.16.0, existing LLVM 22.1.8):

```sh
cd /d/unikraft-worktrees/fleet-network
work="$PWD/.d/zig-migration-object-proofs"
export HOME="$work/home" TMPDIR="$work/tmp"
export ZIG_LOCAL_CACHE_DIR="$work/cache"
export ZIG_GLOBAL_CACHE_DIR="$work/global-cache"
export PATH="/home/g/.local/bin:/d/unikraft-worktrees/fleet-ci/.d/tools/llvm-tools-22.1.8-aarch64-linux/bin:$PATH"
mkdir -p "$HOME" "$TMPDIR" "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"
/home/g/.local/bin/zig build hyperv-object-proofs test-hyperv-object-proofs \
  -Doptimize=Debug -j2 --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" --prefix "$work/outputs/debug"
/home/g/.local/bin/zig build hyperv-object-proofs test-hyperv-object-proofs \
  -Doptimize=ReleaseSafe -j2 --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" --prefix "$work/outputs/release-safe"
```

The existing protocol/C suites retain their existing Debug mode and the
freestanding producers retain ReleaseFast; the new verifier, parser tests,
CLI fixture driver and fake tool use the selected optimization mode.
`-Dhyperv-object-nm=PATH`, `-Dhyperv-object-readelf=PATH` and
`-Dhyperv-object-objcopy=PATH` select explicit native tool executables.

Producer-closure additions for parent integration: the six
`hyperv-object-*.zig` implementation/build/fixture files, this documentation,
`tests/hyperv-object-undefined.c`, existing `elf-common-validator.zig`, and
the shared `support/tools/hyperv/process.zig` / `diagnostics.zig` modules.
There are no new package dependencies or package restores. Parent-owned
producer pins and CI are intentionally not edited.

This selector supplies object/link/ABI evidence only. It does not run
remaining controller/persistence/preparation Python aggregates, linked-image
SMP/IRQ/driver proofs, a full guest build, Hyper-V boot, network tests or Azure.
