# Native Hyper-V private transfers

This is the Linux Zig 0.16.0 transfer module for the Python-free
#120/#89 migration. It does **not** authorize cloud execution, allocate disks,
grant/revoke access, discover credentials, select subscription authority, or
replace either controller. Azure execution remains paused.

## Public interface

Import `hyperv_transfer` from the enclosing host tool's `build.zig`, or use
this directory's source-local build wrapper. The wrapper imports `../core.zig`;
it is not a separately distributable package containing only this directory.

- `Client { allocator, io, runtime: core.http.HttpRuntime, budget: Budget }`
- `createContainer(account_url, container, sas) -> Outcome`
- `uploadBlock(client.Blob, files.Input) -> Outcome`
- `downloadBlob(client.Blob, client.Download) -> Outcome`
- `uploadPages(client.Disk, files.Input) -> Outcome`
- `execute(*const request.Request, sas) -> Outcome`
- `executePrivate(request_path, sas_path) -> Outcome`
- `uploadPagesPrivate(request_path, sas_path) -> Outcome`
- `request.Request.load(allocator, io, absolute_private_path)`
- `request.DiskRequest.load(allocator, io, absolute_private_path)`
- `request.loadSas(allocator, io, absolute_private_path)`
- `NativeRuntime.init(configured_std_http_client)`, `runtime()`, `deinit()`

`files.Input` binds an absolute path, exact `u64` size and `[32]u8` SHA-256.
`Blob` holds an account URL, container, blob name and **borrowed private SAS
memory**. `Disk` holds the grant's endpoint and separate private SAS memory.
`Download` holds an absolute output path and byte ceiling.
`Budget` requires an injected **monotonic** millisecond clock, absolute deadline
and Core cancellation token. Runtime descriptors borrow contexts; do not move
or destroy those contexts while a client/operation uses them.
Clock failures propagate; the clock callback returns `anyerror!u64`.
`request.loadSas` returns a shared `sensitive.Buffer`: use `bytes()` while
borrowed and `deinit()` to clear its entire storage. Private request parsing
uses shared `SensitiveDocument`, including all decoded strings and temporaries.

`executePrivate` accepts only paths to separate owner-only files; there is no
SAS argv, environment, credential-chain or Azure CLI fallback. The block-worker
request schema and version remain `unikraft.hyperv.private-preflight-blob-worker`
and integer `1`, with the original exact upload/download record field sets.
Parsing rejects duplicate/unknown fields, floats/exponents/bools as integers,
excessive nesting, invalid paths, duplicate destinations and oversized input.
SAS query names are explicitly restricted to SAS fields, preventing operation
parameter injection; their encoded values are retained verbatim.

The private page-worker schema is
`unikraft.hyperv.managed-disk-page-worker`, integer version `1`, with exactly
`schema`, `schema_version`, `endpoint`, `path`, `size` and `sha256`. The endpoint
has no query; SAS bytes are exclusively in the separate private channel.

The supervised entry below records per-attempt intent and applies a **separate
hard process deadline**. An enclosing controller still owns cumulative workflow
admission, approval and ambiguity reconciliation without replay. The Core
cancellation token cannot interrupt every blocking filesystem/socket call.
There is no retry, redirect, reseed, resume, grant or cleanup-authority mechanism.

Each response-consumption step performs one progress read, with budget checks
before and after that call. Download, footer, error-body and empty-response
probes use explicit EOF; a zero-byte progress result is not EOF. Fragmentation
cannot cause a fill-buffer helper to issue further reads after a stop signal.
This does not remove the separate hard deadline for one blocked syscall.

## Transfer and diagnostic contracts

- All source/request path components are descriptor-walked with `O_NOFOLLOW`.
  Regular inputs are opened nonblocking once; size, inode/device, ownership,
  permissions and nanosecond modification/change metadata are checked along
  with full SHA-256 before and after transfer and the pathname's final binding.
  Request/SAS files use shared `.private`: current UID, exactly 0600, one link,
  with a 0700 private parent. Source files use the distinct shared `.artifact`
  policy: regular and hash/metadata-bound, but not forced 0600 or single-link.
  Source bytes never come from a device, FIFO or symlink.
- Container creation uses one `PUT ?restype=container`. A conflict is a failure,
  not an idempotent success.
- Block uploads are a single streaming, create-only `Put Blob`, capped at
  256 MiB. `If-None-Match: *`, `x-ms-blob-type: BlockBlob`, exact
  `Content-Length` and base64 `Content-MD5` are mandatory. MD5 is for Azure
  transport verification, not artifact identity; SHA-256 is the identity.
- Downloads stream through a 16-KiB buffer into an exclusively created mode-0600
  file inside a descriptor-held owner-only directory. Response length and the
  configured ceiling are checked independently. A returned `Content-MD5` is
  verified; an absent checksum is permitted for the preflight's original
  download contract, with native HTTPS and the returned SHA-256. Compressed
  responses are refused. Files and directories are synced. Failure unlinks only
  an output successfully created by this call; cleanup failure is explicit.
- Managed-disk uploads are **only** `PUT ?comp=page` with
  `x-ms-page-write: update`, exact 512-byte geometry and at most 4-MiB pages.
  There is no `Put Blob` or `Put Block` substitution. The current scope permits
  at most 4 GiB + the fixed VHD footer. Every page has Content-MD5; the full
  stream has SHA-256 before/during/after. Readback requires a 206 response,
  exact final 512-byte `Content-Range`/length, requested range Content-MD5 and
  byte-identical footer. Input/footer fixtures are synthetic, not image data.
- Container/block/download API versions are individually pinned to
  `2024-11-04`; page update/footer readback use `2020-10-02`.

`Outcome` separates `completion` from `side_effect`:

| Side-effect certainty | Meaning |
| --- | --- |
| `not_started` | No mutation entered the HTTP transport |
| `accepted` | All issued updates have accepted response heads; validation may still fail |
| `rejected` | A mutation received a non-2xx response and no earlier batch/page update was accepted |
| `unknown` | A mutation entered transport but no response head establishes its outcome |
| `incomplete` | Earlier mutations succeeded but a remaining update/batch member did not complete |
| `not_applicable` | Read-only HTTP operation (output cleanup is tracked separately) |

`bytes_streamed` counts bytes handed to transport, **not** acknowledged wire
bytes. Zero does not establish absence of effects. `bytes_accepted` counts
update payloads covered by accepted heads. Download counts are separate.
After local validation failure the diagnostic status may be null because that
stage issued no request; accepted byte accounting and certainty remain intact.
Footer failure retains its actual GET status and accepted page effects.

`Outcome.write(*std.Io.Writer)` is the only public diagnostic renderer: a bounded
schema-2 JSON record of enums, numeric status/null, counters, fixed digests,
cleanup flag and independent core `Failures` lanes. `Outcome.parse(Value)`
checks exact fields, types and consistent metadata; `writeValue` embeds the
record without its final LF. The result retains `header_code` and `body_code`
beside their independent source states and aggregate code.
It never renders paths, URLs, SAS, SDK errors, arbitrary service messages, or
response bytes. `Diagnostic` contains enumerated stage/category, actual
status/null and `Metadata`. Header/XML/JSON service-code extraction reads at
most 8192 body bytes plus one overflow probe, with bounded depth/allocation,
and explicitly distinguishes `absent`, `known`, `unknown`, `malformed` and
`conflicting` sources. Only the enumerated `ServiceCode` allowlist is retained.
Never log a request, URI, SDK `Result.unwrap()` or raw caught error alongside it.
`aggregateDiagnostic()` explicitly maps to core vocabulary;
`failureSummary()` records no primary error for complete/category-none and
keeps cleanup/recording separate. Keep the full Outcome alongside the aggregate:
known-header/malformed-body information is not recoverable from the aggregate.
The single shared service-code enum uses the documented
`LeaseIdMismatchWithBlobOperation` spelling and the full reviewed transfer/core
allowlist. There are no arbitrary-string casts or implicit aliases.

## SDK reuse and integration

The manifest pins Core `0.3.0` at
`bc77bcacbb64af935ca53d60bf8a351c9592bc41` and Storage Common `0.3.0` at
`5291e5d7224b4d69989d403f605345d949c41db7`, including package hashes. Core's
transitive serde dependency is pinned to commit
`73d872776b0361b6fc92f6cecd7ccf2f05e77cdd`, version `1.0.1`.

Storage Blobs `0.3.0` at `2bd2b47df464e2bd548d6aad6f5d8d425f2e74a9`
was inspected through Git objects. Its `SasBlobClient` already streams and has
useful certainty outcomes, but cannot supply the required condition/integrity
headers or bounded service metadata. Storage Common's `send` also discards that
metadata and finishes by draining. This package therefore reuses
`CompleteSasUri` construction and the **actual Core streaming pipeline/runtime**
with empty policies, no retry and redirects forbidden. Its four narrow
operation adapters are not a general HTTP SDK. No SDK branch/package change is
needed, and the unused Storage Blobs package is not restored as a dependency.

`NativeRuntime` uses Core `StdHttpTransport`; the production path is not a mock
or successful placeholder. Buffered-only injected runtimes are refused.
Trust-store/network configuration is explicitly the caller's responsibility.
The production worker supplies a wiping allocator to the native HTTP client
and SDK runtime, and disposes them before that allocator expires. The file
adapter now reuses core descriptor-safe I/O; it implements only transfer
streaming/hash logic, not a second UID/nofollow implementation.

## Restricted worker and parent protocol

`worker.supervise(allocator, io, absolute_private_directory, job_basename,
Options{ executable, cancel? }) -> Report` is the library parent entry.
The installed `uk-hyperv transfer PRIVATE_DIRECTORY JOB_BASENAME` calls it
using its own absolute executable. An embedding parent must select a reviewed,
fingerprinted native executable, not an arbitrary command. The worker's
`executeNative` runs real Core HTTP; `execute` permits explicit library injection
for native fixtures, never selection through production job data or environment.

Job JSON has exactly these fields (up to 8192 bytes, strict bounded JSON):

```json
{"contract":"uk.hyperv.transfer-job","schema_version":1,"kind":"blob","request":"request.json","sas":"sas","timeout_ms":30000,"cleanup_ms":1000}
```

`kind` is `blob` or `pages`; `request` refers to the existing version-1 transfer
schema described above. Job/request/SAS names must be distinct, non-hidden ASCII
basenames, not paths, and cannot use reserved state names. `timeout_ms` is
1..3600000; independent `cleanup_ms` is 100..1800000. Private files and directories
are descriptor-validated. The SAS is a separate raw private file, not a JSON
field, URL query in argv, environment variable or credential-chain lookup.

Each private directory is single-use. Under the shared stable lock the parent
durably creates `transfer-intent.json` and initial `transfer-state.json`.
Intent binds job/request/SAS hashes, exact operation plan, parent PID, monotonic
deadline and a fresh 256-bit nonsecret attempt nonce. Outputs bind that nonce
as well as the job hash, so identical job descriptors cannot accept an older
attempt's report. The parent releases the lock before starting the child with
an empty environment, `/dev/null` stdin and validated cwd. Its argv is only
`ABSOLUTE_EXECUTABLE __transfer-worker JOB_BASENAME`.

The child checks intent, parent PID, deadline and every input binding, then
creates immutable `transfer-started.json`. It holds the writer lock through
transfer and secret disposal. A durable write-ahead checkpoint precedes each
HTTP transport entry; a recording error blocks further requests. The optional
typed `Client.observer` receives `begin{stage,mutation,bytes}` and
`end{transport_started,status}` events. Accepted response-head counters survive
an end-checkpoint failure. No marker or state record is a retry/rearm API.

The canonical, exact `uk.hyperv.transfer-report`, schema version 1, is capped at
8192 bytes. Its fields are `attempt_id`, `contract`, `delivery_complete`,
`failures`, `job_sha256`, `kind`, `outcome`, `phase`, `process_cleanup_complete`,
`progress`, `schema_version`, and `side_effect`. Hashes/nonces are fixed lowercase
hex, optional values are explicit nulls, and no field accepts arbitrary text.
`outcome` embeds Outcome v2. `progress` independently records declared attempted
bytes, response-confirmed bytes, request/mutation counts, pending operation
bytes/kind, stage, observed status and prior certainty. A pending write-ahead
attempt can be conservatively unknown after termination even if transport
entry itself cannot be established. Lost/invalid progress is null, never
invented zero counts. Actual reader-provided bytes require a final Outcome.

The supervisor enforces the independent monotonic process deadline with
`core.process.run`, 8192-byte stdout and 4096-byte discarded stderr caps,
TERM/KILL process-group cleanup and reaping. It reacquires the writer lock only
after cleanup is complete. Malformed/stale/flooded/nonzero child output is not
success; the parent recovers only valid durable state bound to the same intent.
Accepted effects can coexist with failed output delivery. The immutable
`transfer-supervised.json` records the final parent result when publication
succeeds; recording failure is returned in its own lane, never hidden.

`Report.succeeded()` requires complete valid delivery, a complete Outcome,
confirmed process cleanup and no primary/cleanup/recording failure. Child exit
0 means a delivered protocol record only; the public CLI exits 1 on any failed
report. Keep full transfer metadata, progress and certainty beside aggregate
core failures. Never infer effects from completion, an HTTP status, a digest,
an absent result or a core diagnostic.

This is trusted native process-group supervision, not a sandbox. Worker
descendants must not escape the group or install another reaper; unresolved
cleanup poisons the supervisor. One blocked transport call still requires the
hard parent deadline. Admission and final private-file publication in the parent
are synchronous; `timeout_ms` is not a whole-command timing bound if that
filesystem blocks. An enclosing controller must supervise the CLI itself.
Hard death cannot guarantee userspace zeroization before
exit; the address space must be reaped. Original private input files remain
caller-owned. Controller approval, SAS lifetime/file disposal, disk-grant
revocation, crash recovery after supervisor loss and cumulative workflow
budgets remain integration requirements, not locally simulated cloud acceptance.

## Standalone offline tests

All outputs, caches, package restores and synthetic fixtures must be placed in
an explicit `/d` worktree-private directory. With the specified worktree:

```bash
cd /d/unikraft-worktrees/fleet-network
out="$PWD/.d/zig-migration-transfer-core"
umask 077
export ZIG_GLOBAL_CACHE_DIR="$out/global-cache"
export ZIG_LOCAL_CACHE_DIR="$out/cache"
export TMPDIR="$out/tmp" HOME="$out/home"
mkdir -p "$out"/{global-cache,cache,tmp,home,outputs,restore}
# This Zig distribution restores into zig-pkg beside the build file. Restore
# from copies here, not beside tracked sources or inside an SDK checkout.
cp support/tools/hyperv/transfer/build.zig \
   support/tools/hyperv/transfer/build.zig.zon "$out/restore/"
/home/g/.local/bin/zig build --build-file "$out/restore/build.zig" --fetch=all \
  --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" -j2
# Package restore is the only permitted network operation. All builds/tests
# thereafter explicitly disable fetching:
/home/g/.local/bin/zig build --build-file support/tools/hyperv/transfer/build.zig \
  test --system "$out/restore/zig-pkg" \
  --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
  --prefix "$out/outputs/install" -Dfixture-root="$out/outputs" -j2 --summary all
# Use the same flags without `test` for the standalone library build.
/home/g/.local/bin/zig fmt --check support/tools/hyperv/transfer/*.zig \
  support/tools/hyperv/transfer/build.zig.zon
```

The test runtime runs the real empty Core pipeline and checks exact request
method, SAS query preservation, protocol parameters, per-operation headers,
MD5, body lengths and streaming boundaries. Its response reader injects
partial/unknown outcomes, body failures and bounded fragments. No DNS, sockets,
live Azure, credentials, seed/image data, Python oracle, guest build or Make is
used. Tests clean up only the synthetic directories they created.

Coverage includes container conflicts, create-only blocks, empty transfers,
short/growing/modified inputs, post-upload mutation, per-page geometry/chunking,
partial and unknown second-page outcomes, footer mismatch/integrity/range/size,
download excess/short/cancelled streams and partial cleanup, private request/SAS
files, FIFO/symlink/permission refusal, strict JSON/numeric/endpoint contracts,
bounded service metadata, response-body failures, redirect refusal, error
redaction, independent completion/certainty and no automatic replay. Fragmented
download/footer/error fixtures assert zero reader calls after cancellation or
deadline expiry, rather than merely checking eventual failure. Zero-progress
fixtures distinguish explicit EOF from a reader that has not delivered bytes.

These fixtures verify the local subsystem, not TLS/cloud acceptance or the
whole Python-free controller workflow. The enclosing build's `test-worker`
selector additionally exercises real native child supervision, blocked calls,
partial effects, malformed/stale/flooded output, strict jobs/reports, metadata,
private input substitution, recording/cleanup failure and redaction. The parent
still owns workflow integration, credential approval/lifetime, grant revocation,
producer pins, CI wiring and all cloud gates.
