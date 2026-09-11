# Native public local boot driver

Standalone Zig 0.16 replacement for `support/build/tests/hyperv-efi-boot-test.py`
and its focused Python fixtures. No Python interpreter, SDK, cloud client,
shell, package dependency, preparation engine, or host admission is used.
Dedicated native CI fixtures and the fixed two-CPU SMP boot use this package.
Public root CLI assembly and the remaining legacy Python call sites are separate
integration work; this is not the complete Python-free controller cutover.

**This is only a public local QEMU/KVM boot and log assertion. It does not
establish VMBus, StorVSC, NetVSC, Azure, #120, or #89 acceptance, and cannot
admit a signed host image or authorize a real attempt.** Native fixtures
simulate processes and serial protocols; they are not real guest boots.

## CLI

```text
uk-hyperv-local-boot --raw-disk /canonical/public/smp.raw \
  --qemu /canonical/qemu-system-x86_64 \
  --ovmf-code /canonical/OVMF_CODE.fd --ovmf-vars /canonical/OVMF_VARS.fd \
  --work-dir /canonical/private/new-attempt \
  --cpus 2 --timeout 60 --expect 'application marker' \
  --require-marker 'first additional marker' \
  --require-marker 'second additional marker' \
  --forbid-marker 'unwanted marker'
```

Use `--image /canonical/application.efi` instead of `--raw-disk` for a
directory-backed ESP. Exactly one is required. All five paths must be
explicit, absolute, canonical, and free of symlink components. In particular,
there is no QEMU PATH search or inherited environment. Commas/spaces in input
paths are safe. Resolve external tool symlinks before invocation.

The work directory must already exist, be current-user-owned mode 0700, and
be empty except for the core's stable `.writer.lock`. It is **consumed once**;
repeated use refuses instead of overwriting evidence or retrying QEMU. Inputs
must be outside it. A durable, create-only `request.json` precedes the leaf
process, whose separate create-only `launched` record prevents another exec.
These are local execution records, not an authority or completion receipt.

Options preserve the legacy names:

| Option | Contract |
| --- | --- |
| `--cpus` | 1 through 8; default 1 |
| `--disable-x2apic` | Legacy xAPIC; permitted only with one CPU |
| `--timeout` | Decimal seconds in 0.001 through 120, at most three fractional digits; default 30; CI can select 60 |
| `--expect-main-return` | Exact signed i32, default 0 |
| `--expect` | Required nonempty printable ASCII marker, at most 512 bytes |
| `--require-marker` | Repeatable, up to 32 distinct markers, in required occurrence order |
| `--forbid-marker` | Repeatable, up to 32 distinct markers |

Unknown options, duplicate singleton flags, conflicting/empty markers,
NaN/infinite/exponential timeouts and ambiguous numeric forms refuse. There
are no fixture, arbitrary-argv, shell, HTTP, credential, or admission options.
The internal `--exec` entry requires the parent's private typed record,
writer lock, parent PID, process group and death-signal setup; it cannot
independently select a command. The QEMU executable must be native ELF, not
an interpreter script. Selecting a trusted QEMU/tool runtime remains the
local operator's responsibility, not an assertion made by this driver.

Stdout is one bounded canonical JSON report: schema 1,
`scope=public_local_qemu_only`, `acceptance=not_established`, `passed`,
`consumed`, `input_unchanged`, `serial_valid`, `serial_limit_reached`,
`serial_bytes`, lowercase hex `serial_sha256` or null, termination, and
independent core primary/cleanup/recording diagnostics. No original paths,
arguments, exception text or guest output appear in the report. Exit 0 means
only that the local assertions passed; 1 is execution/evidence failure,
2 is refusal, and 3 is output-recording failure.

## Execution and evidence

`root.zig` exports `config`, `serial`, `files`, `runner`, `child`, and the
dependency-free merged `core`.

- `config.parse(allocator, args)!Config` borrows strings and allocates its two
  marker slices. `Config.validate()` also supports typed in-process callers.
- `runner.run(allocator, io, Config, Options)!Report` requires a dedicated
  `core.process.initialize()` supervisor. `Options.self_executable` identifies
  this CLI; an optional atomic cancellation flag interrupts its leaf.
- `child.arguments(allocator, Config, raw_size, raw_fd)` constructs only the
  fixed QEMU operation. Arena allocation is appropriate for an execution.
- `serial.validate(allocator, raw, Config)!void` is a local marker validator,
  deliberately separate from the single-CPU signed host serial policies.

QEMU uses q35/KVM, 512 MiB RAM, the established Hyper-V CPU features,
`vmbus-bridge,irq=15`, no NIC/display/monitor, no reboot and no user config.
The leaf execs QEMU in its existing process group; it does not fork another
supervisor. The parent supplies an empty environment; QEMU receives only
`TMPDIR` pointing at the owned workspace.

Inputs use core's public artifact policy, not its private 0600 file policy:
regular files, safe descriptor-relative ancestor walks, no symlink following,
and no group/world writes. Owner-readable 0644 firmware/images and 0755 QEMU
are supported. Source, firmware templates and QEMU are hashed in bounded
32-KiB reads, pinned before launch, revalidated by the leaf, and checked in
full afterward, including inode/device, length and modification metadata.
Path replacement, growth, truncation, or changed bytes cannot pass.

The raw disk is **never copied, staged, linked, reseeded, or writable**.
QEMU receives the retained O_RDONLY descriptor via a JSON `-blockdev` file
node and an exact-size read-only raw node at offset zero. This both avoids
comma-based option injection and preserves exact backing-file identity.
EFI mode copies only the supplied application into private
`esp/EFI/BOOT/BOOTX64.EFI`; that disposable ESP retains legacy writable-FAT
behavior. Both modes make private firmware code and variables copies.

Finite limits are 256 MiB per input/QEMU binary, 16 MiB firmware code,
4 MiB firmware variables, 64 KiB control records, 4 MiB serial, and 8192
normalized bytes per line. EFI preparation may copy up to the input plus
firmware limits; raw mode copies **only** firmware. The 4-MiB process file
limit also bounds regular-file writes to the variables/temporary files.
These local limits are not a preflight staging ledger or data-upload authority.

The hard monotonic leaf deadline includes its validation/copy/exec and QEMU
work. Parent-side local admission and post-exit full-file hashing are bounded
in size but are not claimed to interrupt a stalled filesystem syscall.
Core provides an **independent 2-second TERM/KILL/reap budget**, subreaper
ownership and descendant-group cleanup even after normal leader exit.
`cleanup_complete` records process reaping; artifact cleanup failures remain
separate. An unresolved group poisons supervision, retains writer custody
and refuses file cleanup/replay. Abrupt supervisor/host loss is not a
crash-recovery or host-admission proof; the work directory remains consumed.

Both stdout and stderr append to exclusive 0600 `hyperv-efi-boot.log`.
`RLIMIT_FSIZE` prevents oversized capture and core dumps are disabled.
The raw log remains on failure even though core erases failed pipe capture.
Reaching the cap always refuses; a preceding process failure is retained,
with `serial_limit_reached` recording the independent bound observation.
Only known disposable firmware/ESP paths are removed after confirmed reaping.
Raw logs, request/launch/report records and any unknown files are retained;
no recursive production workspace deletion occurs.

The four platform/application-start milestones, expected application marker,
and unique terminal return must occur in order. Additional required markers
must occur in supplied order before the terminal. Ordinary markers retain
legacy substring semantics, but terminal returns do not: `main returned 10`
cannot satisfy return 0. Supported terminal envelopes follow actual ukprint
timestamp/Info/thread/caller/`[libukboot]`/`<boot.c @ line>` formatting, plus the
bare compatibility form. ANSI/NUL decoration and CRLF are normalized only for
parsing; raw bytes and SHA256 are retained. Complete bare terminal text at EOF
is allowed as in the legacy fixtures. Nonzero/unexpected, duplicate, spoofed
or trailing-garbage returns, malformed serial, crash markers anywhere
(including after application success), and forbidden markers all refuse.

## Offline build and fixtures

No package restore is needed. Use Zig 0.16, `-j2`, and explicit owned scratch
for HOME, TMPDIR, XDG/Zig caches and outputs, for example:

```text
zig build --build-file support/tools/hyperv/local_boot/build.zig \
  --cache-dir SCRATCH/cache --global-cache-dir SCRATCH/global-cache \
  --prefix SCRATCH/outputs/debug -Dtest-root=/absolute/SCRATCH/fixtures \
  -j2 test install
```

Repeat with `-Doptimize=ReleaseSafe` and a separate output prefix.
`test-root` must exist with mode 0700. Tests create and remove only their own
randomly named child directories. The native fake QEMU is a separate,
uninstalled executable; the production CLI has no synthetic switch.
Fixtures cover the legacy cases and native CPU/EFI/raw argument execution,
read-only exact backing identity, private variables mutation, merged failure
logs, deadlines/cancellation/ignored TERM, descendant reaping, process exit/
kill/crash, cap exhaustion, consumption/locking, strict child records,
artifact changes and unsafe files, independent failure lanes and actual CLI
serialization/refusals. Only small public synthetic files are used; the
over-limit input case is sparse metadata, not a seed copy.

Offline fixtures access no actual guest, KVM, Python, Azure, credential,
original seed or historical private evidence. Separately, Hyper-V CI invokes
the installed ReleaseSafe driver for the real fixed two-CPU SMP raw-disk boot,
with canonical paths, private firmware templates and an outer command ceiling
covering local setup/post-exit I/O. The raw disk digest is checked independently
afterward. The raw log and local report are retained; remaining legacy
controller and packaging paths are not changed by this integration.
