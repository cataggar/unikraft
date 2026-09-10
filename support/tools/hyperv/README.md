# Native Hyper-V host tool and supervised transfers

This standalone Zig 0.16.0 package does not import the repository's root build,
run any legacy controller, use Azure CLI, or acquire ambient credentials.
The dependency-free `hyperv_core` foundation is combined with the pinned SDK
transfer module in the `hyperv` facade. Its only installed executable is
`uk-hyperv`; its explicit transfer command is a real network implementation,
not a success-shaped stub. Azure execution remains paused. Local fixture
results do not authorize execution or establish preflight/persistence acceptance.

## Build and test

From the repository root, using the already installed Zig 0.16.0 compiler:

```sh
CORE_WORK="$PWD/.d/zig-migration-transfer-core"
umask 077
mkdir -p "$CORE_WORK"/{tmp,home,cache,zig-global,zig-local,fixtures,out,restore}
chmod 700 "$CORE_WORK" "$CORE_WORK"/{tmp,home,cache,zig-global,zig-local,fixtures,out,restore}
export TMPDIR="$CORE_WORK/tmp" HOME="$CORE_WORK/home"
export XDG_CACHE_HOME="$CORE_WORK/cache"
export ZIG_GLOBAL_CACHE_DIR="$CORE_WORK/zig-global"
export ZIG_LOCAL_CACHE_DIR="$CORE_WORK/zig-local"
# This Zig distribution restores beside the build file. Keep that operation
# in scratch, then disable fetching for every source-tree build.
cp support/tools/hyperv/build.zig support/tools/hyperv/build.zig.zon "$CORE_WORK/restore/"
/home/g/.local/bin/zig build --build-file "$CORE_WORK/restore/build.zig" \
  --fetch=all --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" -j2
/home/g/.local/bin/zig build --build-file support/tools/hyperv/build.zig \
  --system "$CORE_WORK/restore/zig-pkg" \
  --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
  --prefix "$CORE_WORK/out" -Dtest-root="$CORE_WORK/fixtures" \
  -j2 test-core test-transfer test-worker install --summary all
```

`test` requires an existing, current-user-owned, mode-0700 absolute test root.
Every filesystem fixture gets a new private child of that root and removes only
its own child afterward. Tests do not use `std.testing.tmpDir`, an interpreter,
a shell subprocess, a network endpoint, or external images. The native process
and injected-transfer fixtures are built only for tests and are not installed.
Tests run on the build host even when the operator executable is cross-compiled.

The current operating-system implementation requires Linux 5.11 or newer
(`statx`, `close_range(CLOEXEC)`, and subreaper support); both AArch64 and x86-64
are supported targets. Other operating systems fail compilation rather than
silently weakening the file or supervision policy.

## Local inspection CLI

```text
uk-hyperv inspect-json PRIVATE_DIRECTORY BASENAME
uk-hyperv validate-binding PRIVATE_DIRECTORY BASENAME
uk-hyperv inspect-diagnostic PRIVATE_DIRECTORY BASENAME
```

The directory must be mode 0700 and every ancestor must be owned by root or the
current user, without group/other write permission. All path components are
opened without following symlinks. Inputs must be current-user-owned mode-0600
regular files with one hard link, at most 256 KiB.

`inspect-json` reports only `canonical` and `valid` booleans, not input values.
The other commands require canonical JSON. `validate-binding` checks a local
immutable-input binding, **not** a build receipt, cloud admission, historical
state conversion, or completed handoff. Its exact fields are:

- `schema_version`: integer `1`;
- `contract`: string `"uk.hyperv.input-binding"`;
- `run_id`: canonical lowercase UUID;
- `sha256`: 64 lowercase hexadecimal digits;
- `byte_length`: unsigned 64-bit integer.

`inspect-diagnostic` validates and emits a single allowlisted diagnostic.
Inspection failures emit the versioned `Failures` object on stderr and exit 1.
Unknown commands fail; arguments, input bytes, exception names,
paths, resource identifiers, and raw process/HTTP output are never echoed.

## Restricted transfer CLI

```text
uk-hyperv transfer PRIVATE_DIRECTORY JOB_BASENAME
```

This command validates private inputs, durably admits one attempt, starts the
same native executable's restricted worker, and supervises it through `process`.
It supplies an empty environment and descriptor-validated cwd; argv contains
only the executable, internal command and simple job basename. SAS is loaded
from a separate private file, never argv or environment. See the
[transfer contracts](transfer/README.md#restricted-worker-and-parent-protocol)
for the exact job, state and output interfaces.

The public command emits a bounded `uk.hyperv.transfer-report` on stdout and
exits 1 unless transfer, protocol delivery, state recording and process cleanup
all succeed. A valid child report with exit 0 means protocol delivery only,
not transfer success. The production binary cannot select an injected runtime.
It replaces SDK log formatting with a fixed literal; raw SDK errors are never
unwrapped or formatted.

`test-core`, `test-transfer` and `test-worker` are focused selectors; `test`
depends on all three. Dependencies, including versions and package hashes, are
pinned in both manifests; the SDK commits are documented in the transfer README.
The parent owns CI selector/restore updates and producer-pin refresh.

## Module interfaces

Import build module `hyperv` for the facade, `hyperv_transfer` for transfers,
or dependency-free `hyperv_core` (`core.zig`) for these foundation interfaces.
The facade's `root.zig` needs those two named module imports wired by the build.

### `contracts`

- `Document.parse(allocator, bytes, Limits)` owns its parsed data until `deinit`.
  A bounded scanner runs before the standard JSON parser. Duplicate decoded
  keys, including escape-equivalent keys, are rejected at every depth.
- Defaults: 256 KiB input, depth 16, 4096 decoded bytes per string, 256 members
  per object/array, 8192 tokens. Caller-selected bounds have hard upper caps.
- Numbers preserve their lexical form. Only canonical decimal integers in
  `[-2^63, 2^64-1]` are admitted: no floats, exponents, leading zeroes, `-0`,
  non-finite constants, bool-as-integer, or numeric strings.
- `exactFields`, `integer(T, value)`, `enumeration(T, value)`, and `string`
  implement schema-specific checking without permissive struct coercion.
- `canonicalAlloc` / `requireCanonical`: compact UTF-8 JSON, byte-sorted object
  keys at all levels, minimal standard JSON string escaping, exactly one final
  LF. This is the native contract, not a claim of RFC 8785 compatibility.
- `parseSha256` and `parseUuid` return fixed byte arrays. UUID spelling does
  **not** establish version, variant, non-nil identity, or workflow authority;
  each owning schema must impose those policies.
- `SensitiveDocument.parse` uses the same strict parser but owns a stable
  wiping allocator. Scanner copies, decoded keys/strings, parser arenas,
  canonicalization copies and failed partial parses are cleared on release.
  `requireCanonical(source)` uses that allocator internally; `deinit` is
  mandatory. The caller owns and must clear the original source buffer.
- `Geometry.byteSize` requires positive 512-byte-sector geometry and checks
  multiplication overflow. Owning schemas must additionally bind exact sector
  counts, LUNs, and original identities.

### `sensitive`

`Allocator { backing }` is a wiping allocator adapter. Keep the adapter's
address stable until every allocation is released. In-place resize/remap is
refused so relocation cannot bypass a wiping free. `Buffer.bytes()` exposes
only the read length; `Buffer.deinit()` clears the entire allocation, including
the overflow-probe byte. Do not release it with an ordinary allocator free.
These APIs do not clear independently copied caller data or caller-owned files.
Forced process death cannot promise userspace destructors; the supervisor must
reap the worker's address space and retain explicit unresolved-cleanup state.

### `diagnostics`

`Diagnostic` contains only `Stage`, `Category`, `http_status: ?u16`, and
`ServiceCode`. HTTP status is an actually observed value in 100–599 or `null`.
A null status requires `service_code = unavailable`. A present status does not
establish side-effect certainty or imply a request is safe to replay.

Service codes are enumerated. `classifyServiceCode` and
`reconcileServiceCodes` inspect raw codes transiently without retaining them:

- `unavailable`: no code was provided;
- `unknown`: a syntactically plausible but unallowlisted code;
- `malformed`: empty, oversized, or invalid code syntax;
- `conflicting`: header and body codes disagree.

Transport adapters remain responsible for bounded header/XML/JSON extraction,
observed status, and distinct side-effect certainty. A 403 is not absence.
The shared allowlist includes `LeaseIdMismatchWithBlobOperation`,
`AuthorizationServiceMismatch`, `KeyBasedAuthenticationNotPermitted`,
`InvalidBlobType` and `PendingCopyOperation`. The old undocumented
`LeaseIdMismatchWithBlob` spelling stays unknown. Transfer `MetadataState`
retains each header/body source independently; its aggregate maps `absent` to
core `unavailable` and the other sentinel states by name. Do not flatten those
sources or infer effects from this summary.

`Failures` has schema version 1 and independent nullable `primary`, `cleanup`,
and `recording` diagnostics. `record` retains the first error in each lane;
`parse` checks exact fields and typed diagnostics; `write` emits canonical JSON.
None of these objects has a message, body, stderr, resource-ID, path, or SAS
field. Never serialize private `process.Result` as a public diagnostic.

### `private_files`

- `Directory.open` retains a descriptor for an already prepared private root.
  `openFile` checks metadata on a nonblocking, no-follow descriptor, refusing
  FIFO/device/directory/symlink/hard-link inputs without blocking on a FIFO.
- `read` has an explicit byte bound, checks size/timestamps before and after
  descriptor reads, and can verify an expected SHA-256. A hash supplied by the
  owning immutable contract is necessary for adversarial content substitution.
- `readSensitive` and `readSensitiveAbsolute` return `sensitive.Buffer`, with
  no unzeroized intermediate copy, including read/hash rejection paths. Use
  these for private requests, SAS and sensitive JSON. Ordinary `read` clears
  its intermediate but returns an ordinary caller-owned copy, not a secret API.
- `openAbsolute(io, path, policy)`, `FileParent`, `snapshot` and `sameSnapshot`
  centralize descriptor-safe file access. `.private` requires owner-only
  directories and current-user 0600 single-link files. `.artifact` is distinct:
  a no-follow regular file in a trusted path, without forcing private mode,
  ownership or single-link policy. Transfers additionally enforce its exact
  size, immutable SHA-256, metadata and final pathname binding.
- `Directory.openWorkerCwd` adopts and checks the inherited descriptor-relative
  working directory; it does not discover a credential or authority path.
- `Directory.lock` obtains a nonblocking exclusive lock on `.writer.lock`.
  The stable lock inode is never replaced or removed by this API.
- `Locked.commit` replaces state atomically; `Locked.createImmutable` uses
  atomic nonreplacement for immutable input. Both require a live lock guard,
  simple non-hidden basenames, and at most 4 MiB. Callers must validate and
  canonicalize their owning schema first.
- The standard library's `std.Io.File.Atomic` supplies atomic staging/link/rename.
  The wrapper verifies private metadata and adds file fsync before publication,
  directory fsync after publication, and separate cleanup/recording failures.
- `CommitResult.status` is `not_committed`, `publication_unknown`,
  `visible_not_durable`, or `durable`. A failed publication syscall has an
  explicitly unknown outcome; a directory-sync failure after successful
  publication must not be treated as rollback. Retain failed state and reconcile
  it instead of blindly retrying a mutation.
- `Locked.close` releases the lock, but borrows rather than closes `Directory`.
  No transfer of writer ownership is allowed while a prior process has
  unresolved cleanup.

The facade's existing filesystem policy was reviewed; its helper functions
are private and remain unchanged. This package reuses standard file/atomic
operations and implements only the additional private-data policy. It adds
no ELF, configuration, guest-build, or packaging implementation.

### `process`

Call `initialize` explicitly in a dedicated native supervisor: it enables the
Linux child-subreaper policy. `run(allocator, io, Options)` requires an absolute
executable, explicit environment map and directory, a monotonic `Deadline`,
and an independent cleanup budget (100 ms to 30 minutes).

The module owns fork/exec and a nonblocking, bounded exec-status handshake.
This narrow implementation is necessary because Zig 0.16's
`Threaded.processSpawnPosix` discards PID/pipe ownership on an exec error.
All allocations precede fork; the child uses only Linux syscalls before exec.
Exec preserves only stdio, and parent-death signaling binds the direct child.
No executable/PATH discovery, automatic mutation retry, or shell command
construction is supplied. Owning workflows must allowlist fingerprinted native
executables and must not place credentials in argv.

Stdout is captured under a hard cap; stderr is discarded under an independent
cap. Deadlines and the optional atomic cancellation flag are checked while
draining both streams. Output is returned only for a successful child with
complete cleanup; failed stdout storage is zeroized, and `deinit` zeroizes all
capture storage.

Cleanup always runs, including after a successful leader exits. It signals
the owned process group with TERM then KILL and reaps adopted descendants.
The leader is not reaped until the final signal, preventing PID/PGID-reuse
signals. Cleanup receives a fresh budget, not the expired primary deadline.
An incomplete cleanup records a separate diagnostic and poisons the supervisor:
later `run` calls fail, and the caller must retain state/lock ownership and
escalate to independent cleanup. There is intentionally no reset/rearm API.

This is process-group supervision of trusted native tools, not a sandbox:
descendants must not call `setsid`/escape their group, change credentials,
or install another child reaper. The dedicated supervisor must have no
unrelated child reapers. Kernel-uninterruptible processes cannot be guaranteed
to disappear by a userspace deadline; unresolved cleanup is explicit failure,
never success. Parent-death signaling alone does not replace independent
whole-tree cleanup after a supervisor crash. Native controller/parent/host
state machines must implement that higher-level recovery protocol.

## Assertion-to-native-test mapping

`tests.zig` covers these migration-foundation assertions:

| Assertion | Native cases |
| --- | --- |
| Strict contracts | decoded duplicate keys, nested duplicates, non-UTF-8, exact fields/schema, bool/string-as-integer, signed/unsigned limits, overflow |
| Bounded/canonical JSON | input/depth/string/member/token caps, nested key order, escaped spelling, final LF |
| Identity/geometry | lowercase fixed-width SHA/UUID, malformed variants, sector-size/zero/overflow checks |
| Secret-safe diagnostics | missing/unknown/malformed/conflicting codes, invalid status/enums/extra message fields, independent first failures and canonical round-trip |
| Private filesystem | private modes/ancestors, symlink traversal, hard links/FIFO/directories, bounded/hash-bound reads, exclusive immutable creation |
| Durable ownership | lock contention/stable inode, closed-guard rejection, atomic file-sync/rename/directory-sync failure boundaries, old/new visibility and scratch cleanup |
| Native subprocesses | exact stdout cap, stderr cap/disposal, nonzero/missing executable, deadline/active cancellation, TERM-resistant child, grandchild/orphan reaping |
| Inheritance isolation | private lock descriptor absent after exec, empty explicit environment, no failed output exposed |
| Sensitive allocation lifecycle | zero-before-free observer for reads/hash failures, scanner/decoded strings, canonicalization, malformed/duplicate JSON, resize and allocation failures |

`transfer/worker_tests.zig` runs real native child processes through the same
restricted entry and supervisor, using a separately built injected HTTP
runtime. Cases cover normal Blob/page transfers, shared artifact policy,
partial and blocked mutations, cancellation/deadline, malformed/stale/flooded
output, independent metadata and failure lanes, request substitution, consumed
attempts, strict job/report schemas, and pre-transport recording failure.
The public production CLI is also invoked with a deliberately missing synthetic
source, proving native worker dispatch and durable failure reporting with zero
HTTP attempts. Terminal-status contradictions and post-child lock failures have
dedicated regressions.

Durability error tests inject failure at the filesystem-operation boundaries;
they do not claim to simulate a power loss or certify storage hardware.
Live transport acceptance, credentials, source receipts, controller state machines, boot evidence,
original acceptance artifacts, and production CI migration remain separate
work. No cloud acceptance is authorized by passing these tests.
