# Native preflight execution and cleanup engine

This Zig 0.16 module implements the #120 platform-only controller engine using
the merged native core, ARM/auth, transfer worker, and signed host protocol.
It does not implement artifact preparation and does not supersede its receipt
schema. Storage remains **UNAVAILABLE**, not a #89 persistence PASS.

**Production execution is not integrated or admitted.** The installed
`uk-hyperv-preflight-worker` exits 2 with
`native-preparation-and-authority-binding-required`. It has no fixture switch,
credential argument, default credential chain, or live fallback. Tests build a
different, explicitly synthetic executable. Its receipts cannot pass the
production completed-state loader.

## Integration boundary

`contract.Input` is a trusted in-process handoff, not a JSON approval interface.
The integrating CLI must first consume the preparation lane's actual validator
and separately validate the original authority and image/route/provider
approvals. Nonzero proof hashes identify those verified approvals; inventing
hashes is not an authorization mechanism.

The preparation validator must supply immutable, physically verified artifacts
and public/private host manifests, the original input-manifest hash, and the
reviewed native source/dependency/tool/preparation/operator-binary bindings.
`Preparation` does not claim to validate source Git, compile/package artifacts,
or authenticate a build-only receipt. The engine additionally fingerprints the
complete typed preparation handoff, including paths, manifests, and artifacts,
and binds this fingerprint into its state and signed completion.

The approved context fixes the original tenant/subscription/principal/client,
run and resource group, exact resource inventory, immutable image metadata,
image-bound Ed25519 public key, signed host admission, native provider,
uploader IPv4, authority windows, and disjoint byte reservations. Production
workers verify their own native executable hash and control-byte reservation.
`commands.Signer.load` reads an explicitly selected, private, no-follow 32-byte
seed file; it must match the separately admitted image public key. Sensitive
buffers and key objects must be deinitialized. No private key is image-baked.

The integrating CLI supplies `worker.Resolved`, with a validated input, signer,
real wall/monotonic clocks, operator boot UUID, and a backend factory tied to the
worker's opened `journal.Store`. Credentials and TLS/provider configuration
must be explicitly retained independently for cleanup. The factory must not
silently obtain another principal or borrow an application/CLI identity.
`adapters.acquireApproved` selects only the explicitly admitted native provider
and enforces the original authority and required remaining credential lifetime.
`adapters.Native` combines the concrete ARM and Storage adapters; it is not a
generic HTTP or command executor.

Public root CLI wiring and producer-pin/CI updates belong to the integration
owner. The standalone build imports the merged dependency-free `../core.zig`,
not the configured facade. It exports module `hyperv_preflight` through
`build.zig`; direct consumers can configure the named imports in `root.zig`.

## Worker and supervisor contract

The root CLI should dispatch a fixed internal operation set to
`worker.execute(.production, ...)`, never choose synthetic execution from input:

| Internal operation | Worker mode |
| --- | --- |
| Prepare admitted context | `prepare` |
| Read-only inspection | `inspect` |
| Read-only next-operation deadline plan | `plan` |
| One admitted run/cleanup step | `step` |
| Read-only cleanup/recovery deadline plan | `plan_cleanup` |
| One cleanup-only recovery step | `cleanup` |

`supervisor.run` invokes the fixed `--worker-plan`, `--worker-step`,
`--worker-plan-cleanup`, and `--worker-cleanup` dispatch names. Its arguments
contain only the operation and a bounded diagnostic category. The integrating
CLI must similarly supervise preparation, inspection, and its own input/
credential resolution. Prevalidated absolute executable and directory
descriptors are retained by the dedicated parent, not reopened from an
untrusted job.

Every operation and every deadline-planning read runs in a separate supervised
sibling process group. Filesystem operations, fsync, SDK transport, and transfer
body processing happen in that child. The merged transfer worker executes
directly in the operation child: it does not launch a nested supervisor.
Its child report deliberately does not assert process cleanup; only the outer
supervisor can establish reaping.

The parent enforces the 3,600-second attempt ceiling, up to 1,200 seconds of
independent cleanup, action-specific ceilings, bounded stdout/stderr, and
TERM/KILL/reaping. Read-only plans carry the persisted cleanup deadline back to
the parent, including the unrenewed wall-clock ceiling after operator reboot.
Reaping is reserved inside the cleanup ceiling, not added after it; failed
worker time is conservatively included rather than granting a new cleanup
window after reaping. A failed supervisor invocation must never be resumed as
a run; only the separate cleanup entry is valid.
An SDK read budget or elapsed-time check is not treated as interruption of a
blocking syscall. Incomplete process cleanup returns the unreaped group and
forbids transfer of writer ownership; the caller must retain that obligation.

## Durable lifecycle and cleanup

Preparation creates a unique attempt and phase nonces in private, locked,
descriptor-safe files. An immutable consumed claim precedes run operations.
Each operation has an immutable intent, including its held byte reservation,
before effects. A reopened in-flight intent becomes unknown and cleanup-only.
Neither a stale command nor recovery can replay a deployment, transfer, phase,
or ambiguous cleanup mutation.

`recovery.json` is durably updated before `state.json`. Cleanup-only workers
can use the recovery checkpoint without following or overwriting a damaged
`state.json` path. An independently reserved failure record poisons completion;
claim interruption before mutable publication also remains consumed.
Primary, cleanup, and recording failures are separate. Cleanup cannot renew an
expired attempt or erase prior uncertainty.

The run sequence performs metadata admission, owned group/deployment creation,
host/inventory readback, access setup, public staging/publication/evidence,
signed public acceptance, and only then private staging/publication/evidence.
Commands reuse the host's signature domains and exact parser. Evidence reuses
host boot outcomes and serial assertions, including two public and four
private launches, image/APIC order, unique launch UUIDs, original VM UUID,
continuous host boot ID, nonces, hashes, acceptance, and cumulative host ledger.
Synthetic children and architecture-skip labels cannot become production boot
evidence. There is no seventh-boot operation.

Cleanup is independent of guest connectivity: original-VM deallocation, owned
role removal, old account-key/SAS revocation and an independent signed-request
rejection, firewall clearance, exact owned inventory/group deletion, separate
group-absence proof, and disposal of engine-owned capability copies.
Disposal includes interrupted transfer directories and works without a usable
ARM token; caller-owned credential sources are not unlinked.

The native deployment fixes North Europe, Standard security, D2s-v5, one
32-GiB StandardSSD OS disk, no data disk/public IP/SSH/NAT, and an explicit
Storage/DNS/IMDS-only outbound policy. Readback rejects missing agent/security/
identity metadata. Implicit OS disk ownership uses its exact VM reference and
`managedBy` backlink, not assumed inherited tags. Partial-deployment recovery
can durably bind the first observed owned VM; an already bound UUID cannot be
replaced. Unprovable or extra resources retain cleanup obligations rather than
being force-deleted. A 403 or unrecognized 404 is not absence; absence is not a
successful DELETE or successful key rotation.

Local schemas are `uk-hyperv-preflight-state-v1`,
`uk-hyperv-preflight-operation-v1`,
`uk-hyperv-preflight-worker-result-v1`, and the signed
`uk-hyperv-preflight-completion-v1`. The admitted-context, consumption,
reconciliation and failure files are private engine records, not alternate
preparation receipts. Blob uploads use the merged transfer job/request/intent
schemas. Host command/acceptance/evidence schemas are unchanged.

`completed.load` requires expected validated native preparation/authority,
production COMPLETED state, all operation proofs, accepted mandatory
mutations, independent absence, no failure lane, valid completion signature,
and revalidated exact commands/receipts/private serial files. Standalone,
PREPARED, build-only, historical Python, FAILED, consumed noncomplete,
substituted-native, and synthetic receipts are not a handoff.

## Persistence consumer contract

This describes the engine API introduced by commit
`45088c9ffe6af2d387c3ab48f7e39f48e191cffc`. Persistence must use the actual
committed preparer and this loader through parent-integrated imports, not copy
another lane's working sources or implement a receipt-compatibility parser.

The public entry is `@import("hyperv_preflight").completed.load`:

```zig
pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: core.private_files.Directory,
    expected: *const contract.Input,
) !completed.Handoff
```

The caller retains the private directory descriptor and runs the load under a
hard-supervised read operation. The loader takes the directory lock itself;
the caller must not already hold that lock. It reads the full private attempt
directory, not a standalone completion file. The returned value owns no
allocator-backed storage and needs no `deinit`.

`Handoff` has exactly these data fields: `attempt`, `run_id`, `vm_id`,
`host_boot_id`, `native`, `input_sha256`, `preparation_sha256`,
`public_receipt_sha256`, `private_receipt_sha256`, `completion_sha256`, `scope`,
and `storage`. UUID fields are `contract.Uuid` (`[36]u8` UUID text); hashes are
`host.protocol.Hash` (`[32]u8`). `native` is `contract.NativeBinding` with
`implementation`, `preparation`, `source`, `dependencies`, `tool_runtime`, and
`operator_binary` hashes. These identify the preflight producer, not the
future persistence executable.

There is **no serialized Handoff schema or version**. It is an in-process
result, not a portable admission token. Its `scope` is `.platform_only` and
`storage` is `.unavailable`; neither authorizes persistence or fresh cloud
operations. The preflight VM and its host boot UUID identify the completed
preflight execution, whose owned group has been removed, not a VM to reuse.

### Exact records and bindings

Native preflight versions are encoded in the `schema` string's `-v1` suffix;
there is no separate numeric `schema_version` in these records. Use the
module's canonical codec and typed loader rather than reconstructing them.

| Record or binding | Required relationship |
| --- | --- |
| `state.json` | `uk-hyperv-preflight-state-v1`, `kind = production`, `phase = completed`; every action complete with a non-null proof; all three failure lanes null. Recovery state alone cannot qualify. |
| `intent-<action>.json` | `uk-hyperv-preflight-operation-v1`; exact action, consumed attempt, original run, authority digest, native implementation binding and retained debit. Missing or interrupted intents cannot qualify. |
| `completion.json` | Envelope fields `body` and `signature`; body schema and Ed25519 signature domain both `uk-hyperv-preflight-completion-v1`. `completion_sha256` hashes the entire envelope bytes. |
| Original authority | `authority_sha256 = SHA256(canonical(expected.approved))`; the private `admitted-context.json` must hash to it. This binds the original authority/resource/image/key/route/provider/budget context, not new persistence approvals. |
| Native source and artifacts | State `binding` equals `expected.preparation.binding`; `input_sha256` equals its validated input-manifest digest; `preparation_sha256 = SHA256(canonical(expected.preparation))`, including the exact paths, artifact descriptors and both manifests. |
| Commands and acceptance | Existing `uk-hyperv-host-command-v1` and `uk-hyperv-public-acceptance-v1` signed contracts; exact original run/VM, distinct saved phase nonces, phase, manifest/image/runner hashes, artifact roles/names/sizes/hashes and derived Blob scope. The private acceptance binds the exact public command digest, public receipt digest, public nonce and host boot UUID. |
| Host receipts and serial | Existing `uk-hyperv-host-evidence-v1`; production `qemu_kvm`, `PASS`, platform-only scope, matching command/manifest/runner/guest-image/host-image hashes. Exactly two public and four private launches, unique valid launch UUIDs across all six, continuous host boot UUID, required image/APIC order, exact serial lengths/hashes and reused serial-semantic assertions. |
| Cleanup and accounting | Complete recorded cleanup actions, separate independent group-absence proof, no retained failure lane, and host ledger snapshots within the approved disjoint reservations. No 403-to-absence or absence-to-DELETE-success conversion. |

The exact signed completion body fields are `schema`, `kind`, `attempt`,
`run_id`, `binding`, `input_sha256`, `preparation_sha256`, `authority_sha256`,
`public`, `private`, `group_absence`, `scope`, and `storage`. The final two wire
values are `"platform-only"` and `"UNAVAILABLE"`. The signature is 128
lowercase hexadecimal characters encoding Ed25519's 64 signature bytes over
`domain + "\n" + canonical(body)`; canonical body bytes include their final LF.
The loader reconstructs and compares the entire body, not a subset of hashes.

`public` and `private` are `evidence.Summary` values containing `kind`, `phase`,
`receipt_sha256`, `command_sha256`, `phase_nonce`, `vm_id`, `host_boot_id`,
`launches`, `count`, `host_staged`, `host_control`, and `host_evidence`.
`group_absence` equals the proof recorded for `prove_group_absent`.

The loader additionally requires accepted mutation effects for `create_group`,
`deploy_host`, `grant_access`, `stage_public`, `publish_public`,
`stage_private`, `publish_private`, `deallocate`, `revoke_roles`, `revoke_sas`,
and `delete_group`. The cleanup sequence also includes `prove_sas_revoked`,
`clear_firewall`, `prove_group_absent`, and `dispose_credentials`; all require
complete recorded proofs. Merely observing absence does not substitute for the
accepted mandatory mutations.

The loader reopens both command files, both receipt files, and `boot-0.log`
through `boot-5.log`; it does not accept receipt digests without those bytes.
Commands/admission are evaluated at the recorded public/private evidence
times. Public evidence cannot precede start, private evidence cannot precede
public evidence or reach attempt expiry, and the last operation observation
must precede cleanup-authority expiry. This is offline verification of a
completed native attempt, not a live Azure absence check, a refresh of expired
credentials, or permission to allocate again. It also does not rehash source
Git or reopen/revalidate every guest artifact: that remains the actual
preparer's job before the trusted input is supplied and before later reuse.

### Non-forgeable production admission is an integration gate

`Input`, `Approved`, and `Handoff` are ordinary public Zig structs. They are
**not opaque, non-forgeable capabilities**. A `.production` enum, nonzero proof
hashes, a structurally valid `Handoff`, or a signature verified under a key
chosen by the same untrusted request cannot establish production admission.
`Input.validate` checks consistency and the signed host contract under its
supplied key; it does not authenticate the external approval-hash provenance.
Likewise, the completion signature authenticates the native controller's
record under the admitted key, not a separately signed Azure attestation.

The required boundary is the complete trusted call chain: actual committed
preparer validation and independently admitted original authority/image/key/
route/provider/ledger inputs, then this loader over the protected native
execution records, then internal consumption of its returned value. None of
those trusted inputs may be selected from the receipt being authenticated.
Persistence must not deserialize or manually assemble `Handoff`, accept
`validated = true`, accept hashes alone, treat `qemu_kvm` as a self-proving
label, or add standalone/build-only/historical receipt compatibility.

That concrete preparer/authority-to-production-dispatch binding is **not
implemented by this standalone engine commit**. Until the parent supplies and
wires the real admitted interfaces, both preflight and persistence production
execution must remain refused. Synthetic injection is limited to separately
built fixtures and cannot discharge this gate. Even a successfully loaded
preflight handoff requires separate #89 authority, artifact and lifecycle
admission before any persistence operation.

## Byte accounting

Limits remain **2,097,152 control bytes** and **268,435,456 cumulative staged
bytes**. `Budget` partitions producer/publication, controller, image-baked host,
and host-runtime reservations. The host's starting debit already includes the
entire controller reservation; actual controller spending is not added to that
floor again. No image-baked/control binary or unit is exempt.

The controller holds all bounded supervisor stdout/stderr and emergency
recording capacity at preparation. It charges immutable records before writes,
both mutable state copies, command publication copies, transfer job/request/
capability/consumption/journal checkpoints, both downloaded and retained
evidence copies, and unexpected revocation-probe output. Failed or uncertain
transfer reservations are not released. Host firmware, evidence and remaining
runtime controls stay in the separately held host-runtime partition; a
before-receipt host snapshot does not release the remainder.

Synthetic fixture budgets are not complete-image approval. The refusal-only
installed executable's size must not be substituted for the future integrated
controller binary or used to claim that all production controls fit.

## Remaining production gates

There has been no cloud operation or approval in this implementation.
Preparation/root CLI binding, original authority, native credential selection,
immutable image publication and complete staging ledger, identity/RBAC,
uploader route, TLS roots, and cleanup lifetime still need explicit admission.

Two concrete bootstrap contracts also remain closed. The merged host reads an
image-provisioned `/etc/uk-hyperv-host/locator.json`; the admitted image must bind
its exact non-secret account/container/run scope and include those bytes.
Further, a newly started host must not make its first authorized Blob read
before container roles are ready. Authorization failure is not retried as
NotFound. The immutable bootstrap/readiness policy needs an approved binding.

Specialized VM deployment omits a generalized `osProfile`. The controller will
not infer disabled agents from missing service readback. An approved,
service-supported explicit agent/extension property evidence contract is
required before this template can be admitted for production. This module does
not invent that approval or claim a deployable Python-free host image.

## Focused offline validation

Use the existing Zig 0.16 executable, explicit owned scratch/cache/output paths,
restored pinned packages, and `-j2`. Restore missing packages using copied
manifests in scratch with `--fetch=all`; subsequent builds use that directory
with `--system`. Do not create source-tree `zig-pkg`.

```sh
root=/d/unikraft-worktrees/fleet-platform/.d/zig-migration-preflight
export TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/cache"
export ZIG_GLOBAL_CACHE_DIR="$root/global-cache"
export ZIG_LOCAL_CACHE_DIR="$root/local-cache/Debug"
/home/g/.local/bin/zig build \
  --build-file support/tools/hyperv/preflight/build.zig test install \
  -Doptimize=Debug -Dtest-root="$root/out/Debug/fixtures" -j2 \
  --system "$root/packages/restore/zig-pkg" \
  --cache-dir "$ZIG_LOCAL_CACHE_DIR" \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
  --prefix "$root/out/Debug/install" --summary all
```

Repeat with ReleaseSafe and corresponding explicit paths. The fixture root
must already be private (0700). Generated executable paths are resolved against
cwd, supporting caches beneath or outside cwd. The suite uses synthetic keys,
native child processes and synthetic streaming transports only; no Python,
live IMDS/token/Azure calls, original private artifacts, or guest/Make build.
