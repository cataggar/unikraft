# Native ARM and explicit credentials

This is a standalone Zig 0.16 module, `hyperv_azure`, built against the existing
Hyper-V foundation and pinned Azure SDK Core. It binds real SDK HTTP operations;
the tests inject HTTP responses and never acquire a real token or contact ARM.
There is no CLI, arbitrary-URL ARM proxy, credential discovery, controller state
machine, or cloud-admission grant.

## Interfaces and ownership

| Module | Interface |
| --- | --- |
| `auth.zig` | `Config`, explicitly selected `Provider`, `acquire`, zeroizing `Token`, authority/expiry checks |
| `scope.zig` | Canonical nonnil UUIDs, `Authority`, typed resource `Ref`, version and continuation validation |
| `operations.zig` | `Operation`, `Plan.create`, bounded typed request bodies, original disk/VM identities, private key snapshots |
| `client.zig` | Caller-serialized `Client.execute` and `Client.list`; owned `Result`/`Collection` and private `Created` identity bindings |
| `models.zig` | Strict raw field/type parsers, ownership/identity/geometry/security checks, private SAS/key results |
| `admission.zig` | Read-only `inspect(Spec)` and owned `Evidence`; not allocation authority |
| `transport.zig` | Injected `Channel`, `Clock`/`NativeClock`, cumulative `Budget`, `NativeRuntime`, safe `Failure`/`Effect` |
| `secret.zig` | Zeroizing allocator, heap-stable arena, explicitly owned byte buffers |
| `json.zig` | Bounded duplicate-rejecting remote JSON profile |

Construct a `Client` with an explicitly reviewed authority, a live `Token`, and
a `Channel` containing a pinned SDK `HttpRuntime` and shared budget. Call only
typed operations. Call `deinit` on successful tokens, results, collections and
admission evidence. Their strings are borrowed private data, not public receipts;
do not serialize or log responses, tokens, assertions, SAS URLs, keys or key
snapshots. Keep caller-owned authority/configuration strings alive while using
the client and its results.

`Result.effect` and `Failure.effect` describe the initiating mutation, including
after reconciliation fails. A precheck failure is `not_started`; an ambiguous
started transport is `unknown`; a successful submission followed by a failed
readback remains `accepted`. Neither `accepted` nor HTTP 202 means completion.
`Failure.write` emits only the foundation diagnostic, effect and enumerated
OAuth code. It never emits error names, messages, response bodies, resource IDs,
URLs, paths, credentials or SDK stderr. OAuth string error envelopes and ARM
object error envelopes are distinct supported raw shapes.

The caller must preserve the primary failure separately from cleanup/recording
failures using the existing foundation `Failures`. A later successful cleanup
must not erase an earlier accepted/ambiguous mutation or primary failure.

## Explicit identity and trust

Supported providers are Core `ClientAssertionCredential` with a caller-supplied
already-signed native assertion callback, and explicitly selected system- or
user-assigned VM managed identity. Managed identity is restricted to the exact
IMDS endpoint and selected client/resource; it does not probe other environments.
Tenant, subscription, application/client, principal, location, run owner and
resource-group bindings are explicit configuration, not discovered authority.
ARM uses the public-cloud `https://management.azure.com/.default` audience.

The gateway validates one bounded request and an explicit token expiry before
returning a response to the SDK. Non-success bodies never reach identity
providers that would log them. It does not rely on the SDK's missing-expiry
default or hidden clock. The caller specifies the required remaining lifetime,
including cleanup, and must explicitly reacquire credentials if necessary.

The pinned Core certificate provider contains a placeholder assertion and is
deliberately **not** exposed as working certificate authentication. No default
chain, Azure CLI identity, client-secret fallback, credential-cache scraping,
workload-file loader, or delegated device flow is provided. An approved native
workload/certificate signer may supply an assertion through the callback, but
that signer and its private-file policy are caller-owned. If the operator must
retain delegated interactive identity, a separately approved public-client
registration and native device/authorization flow remain design work; do not
borrow Azure CLI's application ID.

The foundation's generic `Directory.read` returns ordinary caller-owned data,
not a sensitive credential buffer. Use explicit validated handles and zeroizing
allocation for any future credential file adapter; this module does not add
another filesystem implementation.

`NativeRuntime.init` requires nonempty caller-supplied DER CA certificates, their
approved concatenated-byte SHA-256, and an explicit clock. It installs this
bundle and a non-null TLS time, disables ambient CA rescanning/proxy discovery,
and uses zeroizing bounded allocation. Do not share the runtime concurrently.
`deinit` reports active SDK operations rather than freeing their allocator.
No system trust files or credential files are opened by this module.

**Live operator identity, cleanup lifetime, trust selection, host identity/RBAC,
image publication and cloud allocation remain admission-blocked.** Implemented
providers and local fixtures do not establish any of those approvals.

## Narrow ARM surface

| Operations | API version |
| --- | --- |
| Subscription | `2022-12-01` |
| Providers, groups, deployments, group inventory | `2021-04-01` |
| VM identity/Standard security, instance view, start/deallocate, boot diagnostics, managed images, Compute usage | `2025-11-01` |
| Managed disks and upload grant/revoke | `2025-01-02` |
| Resource SKUs, location-filtered | `2021-07-01` |
| Quota limits | `2023-02-01` |
| Gallery definitions and immutable versions | `2025-03-03` |
| Owned NIC/NSG/VNet/subnet inventory | `2024-05-01` |
| Owned storage inventory, firewall, list/regenerate keys | `2023-05-01` |
| Shutdown schedules | `2018-09-15` |

Compute's documentation moniker is not one API version for every resource:
[VM/usage](https://learn.microsoft.com/en-us/rest/api/compute/usage/list?view=rest-compute-2025-11-01),
[disk grant](https://learn.microsoft.com/en-us/rest/api/compute/disks/grant-access?view=rest-compute-2025-11-01),
and [gallery version](https://learn.microsoft.com/en-us/rest/api/compute/gallery-image-versions/get?view=rest-compute-2025-11-01)
have separate versioned paths. VM Standard-security readback remains
`2025-11-01`. Quota uses the raw
[applicable `LimitValue` shape](https://learn.microsoft.com/en-us/rest/api/quota/quota/get?view=rest-quota-2023-02-01).

Mutations require the owned group's exact `uk-hyperv-run` tag. Group creation
requires recognized absence; disk/deployment creation also checks target
absence. Deployment bodies are limited to typed disk, attached-disk Linux VM
and restricted StorageV2 definitions, not arbitrary templates. Completion reads
back every created definition and returns its observed VM/disk UUID through
`Result.created`, so the caller can persist the original identity. VM definitions
require original UUID/geometry bindings for existing unattached disks and verify
them again after attachment. Existing network provisioning is not rewritten.

VM actions bind the original VM UUID; power completion requires the same UUID
and the requested instance-view state. VM parsing requires explicit Standard
security, one owned NIC, and at most one data disk at LUN 7 with no caching.
Boot diagnostics requests put the exact ten-minute lifetime in the
`sasUriExpirationTimeInMinutes=10` query parameter, not in a JSON body. The
initial-request query policy permits that parameter only for boot diagnostics.
Managed disks require original UUID, raw `diskSizeGB`, explicit 512-byte logical
sectors, StandardSSD_LRS, and 1--32 GiB geometry. Write grants require an Upload
disk in ReadyToUpload with exact VHD upload size. Revocation reads back original
identity and a non-active-SAS disk state; that control-plane observation is not
an independent data-plane SAS rejection proof.

Storage parsing uses `properties.networkAcls` and
`properties.supportsHttpsTrafficOnly`, never CLI aliases. Firewall updates require
the exact prior host IP and subnet set, preserve that set, and emit a bare IPv4
host rather than the rejected `/32` wire spelling. Key regeneration requires a
private before-snapshot of both keys and verifies that only the selected key
changed. Independent signed-request revocation proof remains caller-owned.
Schedule readback checks target VM, enabled state, UTC time and disabled
notifications. Deletion requires a separate recognized 404; 403, malformed
404 bodies and unknown service codes are never absence.

Image reads may use an explicitly selected source group in the same
subscription; this exception is read-only and limited to image resource kinds.
Admission binds exact reviewed response hashes, specialized Linux/Gen2 metadata,
the selected region, SKU/vCPU/memory and family/total quota headroom. Gallery
versions require separate definition evidence. This is metadata admission, not
image-content verification or proof of nested boots. Unknown/missing metadata
fails closed; SKU restrictions are conservatively rejected.

## Bounds and completion

Defaults are 64 total requests, 1 MiB per response, 8 MiB total response bytes,
16 pages, 32 polls and 512 observed collection items. Explicit larger budgets
are capped at 256 requests, 4 MiB/response, 32 MiB total, 64 pages, 128 polls and
4096 items. Deadlines cannot exceed 24 hours remaining. Headers are capped at
64 entries and 16 KiB; Retry-After is bounded to 60 seconds. Secret allocators
cap outstanding storage at 64 MiB.

Remote JSON rejects duplicate keys, excessive depth/tokens/strings and numeric
coercions in typed fields. Lexical decimals are allowed in otherwise ignored
progress fields, unlike the foundation's integer-only local contract profile.
Unknown optional ARM properties are not admission evidence.

There are no automatic request retries or redirects. Pagination retains exact
collection, subscription, version and selected SKU location filter, rejects
cycles, and shares the cumulative budget. LRO URLs are restricted to matching
ARM authority and recognized scoped resource/operation paths. Both
status-monitor plus result-Location and direct Location result protocols are
supported. A missing secret result fails instead of replaying a grant or key
rotation. HTTP success/LRO success does not bypass resource reconciliation.

Compute `2025-01-02` regional `DiskOperations` URLs have a separate signed-query
contract: exactly `p`, `api-version`, `t`, `c`, `s`, `h`, plus `monitor=true` on
Location URLs. The complete URL is bounded to 4096 bytes; opaque values remain
within that bound without a smaller per-value limit. Fixtures cover a
service-sized 2956-byte `c` value and the exact URL limit. Signed values and
percent-escape spelling are preserved byte-for-byte,
never decoded/re-encoded or rendered in diagnostics. This does not relax
authority, subscription, provider, location, operation-ID or other query
policies.

All native channel requests, including credentials, explicitly select
`Accept-Encoding: identity`. The pinned SDK maps this well-known header to
the standard HTTP client's override rather than adding a second header beside
its compressed default. Unexpected compressed responses remain failures.

Each response loop uses a single `readVec` progress call with budget checks
before and after it, including zero progress, errors and explicit EndOfStream.
Zero progress is not EOF. This covers successful JSON, LRO and error responses,
including credential responses. Budget stops cancel the HTTP operation without
another read. After guarded EOF, the transport closes locally instead of calling
the SDK's unbudgeted draining `finish`; this does not undo an accepted ARM action.

These are synchronous SDK transports. Per-progress cancellation and deadlines
cannot interrupt a blocked socket, DNS operation or native callback.
**An independently supervised worker with the foundation's hard process-tree
deadline is mandatory before live use.** Durable mutation intent, exclusive
locks, process supervision, resource-admission policy, artifact/image proofs,
route admission, budgets for the whole workflow, and cleanup/recording state
machines remain parent/controller responsibilities. Ownership prechecks are
not distributed transactions or an authorization grant.

## Standalone build

No repository root build, guest/Make build, interpreter, CLI login or new test
framework is required. From the repository root with Zig 0.16.0 on `PATH`:

```sh
repo="$PWD"
base="$PWD/.d/zig-migration-arm"
umask 077
export TMPDIR="$base/tmp" HOME="$base/home" XDG_CACHE_HOME="$base/cache"
export ZIG_GLOBAL_CACHE_DIR="$base/zig-global"
export ZIG_LOCAL_CACHE_DIR="$base/zig-local"
mkdir -p "$TMPDIR" "$HOME" "$XDG_CACHE_HOME" "$base/restore" "$base/outputs"
cp support/tools/hyperv/azure/build.zig \
  support/tools/hyperv/azure/build.zig.zon "$base/restore/"
zig build --build-file "$base/restore/build.zig" --fetch=all -j2

for mode in Debug ReleaseSafe; do
  ZIG_LOCAL_CACHE_DIR="$base/$mode/zig-local" \
    zig build --build-file "$repo/support/tools/hyperv/azure/build.zig" \
      --system "$base/restore/zig-pkg" --prefix "$base/outputs/$mode" \
      -Doptimize="$mode" -j2 test install --summary all
done
```

The isolated package directory contains these immutable dependencies:

| Package | Git revision | Zig package hash |
| --- | --- | --- |
| Core | `bc77bcacbb64af935ca53d60bf8a351c9592bc41` | `azure_sdk_core-0.3.0-eFY0Ev0-CACjsFaYPL6jS7CpeVNvsqYqTrXRfgQKiRFV` |
| serde | `73d872776b0361b6fc92f6cecd7ccf2f05e77cdd` | `serde-1.0.1-1DszT1XhDACnteUU3yWahMMjLjkJqB34hwROPIfhZc7l` |

Restoration verifies the package hashes from the pinned manifests. This Zig
distribution writes `zig-pkg` beside the build file, so only the scratch copy
may fetch. Every source-tree build uses `--system` to disable implicit fetching.
The required Hyper-V integration job uses the same isolated bootstrap and both
optimization modes.

The native fixtures cover exact HTTP binding, expiry and OAuth errors,
redaction/zeroization, raw aliases/types/duplicates, authority escapes,
one-byte progress cancellation/deadline stops, zero progress and explicit EOF,
pagination/filter/cycles, LRO result variants and failures, ambiguity/no replay,
disk geometry/upload/revocation, created-resource reconciliation, schedule
completion/deletion, network rejection, firewall preservation, key rotation and
metadata admission. They use synthetic authority, tokens and SAS material.
Native loopback HTTP fixtures additionally inspect the actual SDK wire request
for one identity encoding header and unchanged opaque query bytes, and reject
an unsolicited compressed response.
They do not exercise a live TLS handshake, real identity authority, ARM service,
cloud cleanup, host boot or the complete migration.
