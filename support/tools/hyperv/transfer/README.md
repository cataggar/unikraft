# Native Hyper-V private transfers

This is the standalone, Linux Zig 0.16.0 transfer module for the Python-free
#120/#89 migration. It does **not** authorize cloud execution, allocate disks,
grant/revoke access, discover credentials, select subscription authority, or
replace either controller. Azure execution remains paused.

## Public interface

Import `hyperv_transfer` from this package's `build.zig`.

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

The parent must durably record mutation intent, enforce cumulative admission
budgets, run the worker with a **separate hard process deadline**, and reconcile
ambiguity without mutation replay. The Core cancellation token cannot interrupt
every blocking filesystem/socket call. This package supplies no retry, redirect,
reseed, resume, grant or cleanup-authority mechanism.

## Transfer and diagnostic contracts

- All source/request path components are descriptor-walked with `O_NOFOLLOW`.
  Regular inputs are opened nonblocking once; size, inode/device, ownership,
  permissions and nanosecond modification/change metadata are checked along
  with full SHA-256 before and after transfer and the pathname's final binding.
  Request/SAS files must belong to the current UID, have no group/other access,
  and have one link. Source bytes never come from a device, FIFO or symlink.
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
schema-1 JSON record of enums, numeric status/null, counters and cleanup flag.
It never renders paths, URLs, SAS, SDK errors, arbitrary service messages, or
response bytes. `Diagnostic` contains enumerated stage/category, actual
status/null and `Metadata`. Header/XML/JSON service-code extraction reads at
most 8192 body bytes plus one overflow probe, with bounded depth/allocation,
and explicitly distinguishes `absent`, `known`, `unknown`, `malformed` and
`conflicting` sources. Only the enumerated `ServiceCode` allowlist is retained.
Never log a request, URI, SDK `Result.unwrap()` or raw caught error alongside it.
Returned digests remain typed outcome fields rather than diagnostic strings.

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
The standalone Linux file adapter is intended to be consolidated with the
foundation agent's core private-file module at serial integration; this package
does not edit the foundation build, controllers or producer pin maps.

## Standalone offline tests

All outputs, caches, package restores and synthetic fixtures must be placed in
an explicit `/d` worktree-private directory. With the specified worktree:

```bash
cd /d/unikraft-worktrees/fleet-network
export ZIG_GLOBAL_CACHE_DIR="$PWD/.d/zig-migration-transfers/global-cache"
export ZIG_LOCAL_CACHE_DIR="$PWD/.d/zig-migration-transfers/cache"
export TMPDIR="$PWD/.d/zig-migration-transfers/scratch"
out="$PWD/.d/zig-migration-transfers"
mkdir -p "$out"/{global-cache,cache,scratch,outputs,restore}
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
redaction, independent completion/certainty and no automatic replay.

These fixtures verify the local subsystem, not TLS/cloud acceptance or the
whole Python-free controller workflow. The parent still owns worker subprocess
integration, durable intent/admission, hard termination, output capture,
credential approval/lifetime, managed-disk grant revocation and all cloud gates.
