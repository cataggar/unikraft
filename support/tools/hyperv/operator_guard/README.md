# Native operator process custody

This dependency-free Zig 0.16 module supplies local process custody for a
future parent-integrated preflight/persistence controller. It does not grant
cloud authority, admit preparation/image evidence, resume a consumed attempt,
or replace either engine's state loader. The installed production entry
refuses with `operator-guard-engine-and-authority-binding-required`.

## Kernel boundary

An operator starts one ephemeral custodian, not a daemon or service. The
custodian atomically creates a child and its pidfd with `CLONE_PIDFD`; the child
is PID1 of a new PID namespace and belongs to a new user namespace. All process
signals use retained pidfds, not reconstructed PID/PGID ownership.

The custodian stays in the original user namespace. It maps only the existing
operator UID/GID into the child, denies supplementary group mapping, and
retains no host capabilities. A bounded raw-syscall handshake precedes exec
so the mapping is available before exec recalculates private-namespace
capabilities. That pre-exec child has no signing key in memory or its descriptor
set. The key-bearing memfd is replaced before this mapping handshake; the
custodian loads its contents only after the child's exec and readiness.

PID1 mounts a private, non-propagating procfs for its PID namespace, locks
`SECBIT_NOROOT`, sets `NO_NEW_PRIVS`, and drops all effective, permitted and
inheritable capabilities before worker dispatch. Each exec uses the retained
same-executable descriptor and a fixed internal mode, empty environment and
closed descriptor set. There is no command, executable-path, HTTP or credential
selection interface.

The worker cannot start until the custodian has published and fsynced its
signed create-only registration. PID1 checks the original owner's pidfd, its
custodian pidfd, the dispatch gate and the monotonic deadline. It arms
`PDEATHSIG=SIGKILL` and checks parent-death races both before exec and before
dispatch. Both PID1 and the custodian observe owner death independently.

PID1 uses a raw-syscall monitoring loop while the typed worker executes, with
64 KiB stdout and stderr limits. Existing engine/process supervisors may run
inside the worker. Their new process groups, `setsid`, double-forked children
and nested PID namespaces remain inside this PID namespace.
The final fixed-size event uses the nonblocking I/O report pipe; a stalled
reporter cannot prevent the independently observing custodian from terminating
the namespace.

Linux kills every member when namespace PID1 exits. The custodian must actually
`waitpid` and reap that pinned PID1 before signing a
`pid_namespace_init_reaped` witness. This uses the kernel namespace teardown
guarantee, not output EOF, a free lock, a process-group scan, or PID absence.
See [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).

## Integration API

The standalone build exports `hyperv_operator_guard`. Import `root.zig` with
its `hyperv_core` module pointing to the existing
dependency-free core. The integrating executable supplies a statically bound
handler through:

```zig
pub fn dispatch(
    comptime kind: records.Kind,
    init: std.process.Init,
    comptime handler: fn (WorkerInput) anyerror!void,
) !bool;
```

The only internal modes are `--operator-guard-custodian`,
`--operator-guard-init`, and `--operator-guard-worker`. They require sealed
inherited descriptors, not argv JSON or an environment approval flag.
`WorkerInput` supplies the exact expected binding, retained worker directory,
I/O and deadline. Its operation is one of `preflight`, `persistence`, `cleanup`.
The handler must load the actual validated engine/preparation/authority input
matching `expected.context` and must not treat that digest as self-attestation.
Synthetic handlers are compiled separately and reject production kind.

The dedicated original operator calls:

```zig
pub fn start(allocator, io, options: Options) !Handle;
```

`Options` requires independently admitted `Expected`, a matching explicit
`Signer`, separate private guard and engine-worker directory descriptors, a
monotonic deadline and cleanup/control reservations. `Expected` contains kind,
operation, run/attempt UUIDs, complete context digest, exact executable digest,
trusted proof public key and required `budget: Budget`. The budget contains
independent remaining `control` and `staging` byte allowances for this guard
component, derived by the trusted parent from its admitted ledger. Both are
bound into the consumed claim, dispatch and signed registration. The library
rehashes its actual executable;
callers cannot select a different worker executable. `Signer.load` accepts
only an explicit bounded private seed file matching that public key. No
ambient credentials, host trust override or private key in argv/env/image is
introduced. The signer and sensitive buffers must be destroyed.

`Handle.cancel()` latches local termination in the shared eventfd. Neither PID1
nor the custodian reads/drains that counter: both independently poll it,
including before mapping/dispatch gates and worker creation. Repeated
cancellation cannot clear the event or renew the first cancellation deadline.
`Handle.wait` also observes externally queued cancellation and shortens its
ceiling to the earlier of the original attempt-plus-cleanup deadline and the
first cancellation observation plus `cleanup_ms`. It reserves termination and
reaping inside that ceiling even if both namespace observers are paused.

`Handle.wait(allocator)` reaps
the custodian and returns status plus independent primary/cleanup/recording
lanes. **That result is not a stopped-process proof.** If the custodian cannot
be reaped, `wait` returns `ProcessRecoveryRequired` and the handle retains its
pidfd; `close()` refuses to discard unreaped ownership.
Termination/reaping time is reserved inside the supplied cleanup ceiling,
not added after it. Use a dedicated process with normal `SIGCHLD` handling
and no competing `waitpid` users.

`recovery.load(allocator, io, guard_directory, expected) !Proof` requires the
complete private signed registration, matching consumed claim and signed
kernel witness. `recovery.inspect` additionally exposes pending/rejected/local
I/O diagnostics without discarding independent lanes. `awaitStopped` waits
boundedly for a still-pending seal; malformed, substituted or unauthorized
records do not become retryable success. The integrating parent must itself
hard-supervise admission/loading/recording I/O: elapsed checks do not interrupt
a blocked filesystem operation.

The loader checks the current kernel boot ID, run/attempt/context/native/key
binding, directory device/inode, original owner/custodian/PID1 start identities,
PID namespace identity, registration nonce, chronology and required witness.
An existing custodian PID is pinned and checked for matching start identity
and exit; an active or reused writer is refused. Missing records, cross-boot
records, an unsealed result, a live writer, invalid signatures and wrong
kind/context all remain `ProcessRecoveryRequired`.

`Proof` is ordinary in-process data, not a serializable authorization token.
Only the trusted dispatch's call to the loader with independently validated
`Expected` is an admission boundary. Neither a caller-constructed struct nor
an independently signed caller assertion substitutes for the registered native
custodian's witness. The private proof key and its public-key binding are
trusted operator inputs, distinct from cloud/host authority. As with the shared
private-file policy, the operator UID, kernel and admitted native executable
are trusted; this does not sandbox a hostile same-UID host administrator.

## Records, failures and recovery limits

Private create-only files are `custody-claim.json`,
`custody-registration.json`, and `custody-seal.json`; the existing stable core
writer lock is reused. The signed schemas/domains are
`uk-operator-custody-registration-v1` and `uk-operator-custody-seal-v2`.
Signatures are Ed25519 over `domain + "\n" + canonical(body)`; canonical JSON
has sorted keys and a final LF. The seal hashes the entire signed registration.
Fields, including schema, witness and `publication: "unconfirmed"`, are
required; there is no legacy import. A v1 seal, omitted publication field or
signed assertion of confirmed publication is refused.

A seal is created **before** its own final name and parent-directory fsync.
Consequently it can witness the preceding kernel reap, but cannot certify
its own subsequent publication outcome. There is no second finalization
marker repeating that circular assertion. Every persisted `recovery.load`,
`inspect` or `awaitStopped` proof has `publication = .unconfirmed` and
`scope = .cleanup_only`, even when the worker's cause is `.completed`.
The loader retains all signed prior failures and fills otherwise empty
recording and local-file cleanup lanes with `.ambiguous`. A visible signed
seal after failed/interrupted fsync therefore never becomes all-clear
recording. `inspect.reason = .stopped` describes process custody only.

Live feedback reports the actual publication return, including known
fsync/cleanup failures, independently of the earlier worker failure.
Successful live feedback is not a persistable replacement for this loader,
nor may a caller boolean, serialized `WaitResult` or missing feedback erase
recovery uncertainty. Integration must carry both the live failure lanes and
the cleanup-only persisted proof without promoting it to a completed run.

Owner death normally leaves the custodian able to reap PID1 and seal a
cleanup-only witness, preserving the primary interruption. Killing the
custodian still kills PID1 and its descendants, but if no custodian survived to
record its kernel witness, recovery remains closed. Simultaneous loss of owner
and witness, an uninterruptible kernel exit, or lost/uncertain recording is
**not** automatically repairable by scanning PIDs or assuming reboot cleanup.
No privileged persistent witness service or broader approval is requested.
Old attempts without this registration cannot be adopted.

The witness discharges only local process custody. Its only recovery scope is
the integrating engine's separately authorized cleanup path, never run
resumption or completed-state admission. Cloud mutation uncertainty, cleanup
authority expiry, state recording failure, exact resource ownership and engine
admission remain the engines' independent obligations.

Owner death, cancellation or deadline expiry immediately after registration
durability also goes through termination, reaping and cleanup-only sealing,
without opening the worker gate. A surviving custodian does not abandon an
already registered attempt. Live owners receive all accumulated failure lanes
even when sealing succeeds; recovery after owner death instead consumes the
signed stop witness while retaining unconfirmed publication and cleanup
obligations.

## Requirements, accounting and native fixtures

Linux 5.11+ on AArch64 or x86_64, enabled unprivileged user/PID/mount namespaces,
procfs, pidfds/atomic `CLONE_PIDFD`, memfd sealing, `close_range(CLOEXEC)` and
private descriptor-safe local files are required. Missing kernel facilities
fail closed without a process-group fallback. No host capability, daemon,
shell child, Python, cloud call or package dependency is needed.

`requiredControl(binary_bytes)` charges the executable plus **233,504 bytes**:
three 16 KiB persistent-record slots, both 16 KiB sealed dispatch copies, a
16 KiB emergency reservation, 4 KiB failure feedback, the 32-byte sealed key
copy and both 64 KiB output limits. Failed or uncertain operations retain the
reservation. The record/output/feedback limits are unchanged.
The v2 publication field remains inside the existing seal slot; no new
persistent marker, sealed descriptor copy or feedback copy was introduced.

`Budget.admit(binary_bytes, control_reserved)` requires that complete charge
to fit the reservation and that the reservation fit **both** explicit remaining
allowances. The guard contains no independent hardcoded workflow cap. The
trusted parent must derive the allowances from the approved **8,388,608 control /
268,435,456 cumulative staging** policy, after charging other reservations,
all guard/engine copies and runtime assets. They are not caller-controlled
runtime policy overrides, whole-workflow admission or exemptions. The still
unmeasured components must fit the final ledger; this approval changes no cloud
or seed authority and no legacy, wire or document limit.

The required budget has no missing-field default. Older guard records lacking
it fail closed; no receipt/history rewriting or attempt reuse is provided.
The parent must start all relevant engine writers inside the namespace; a
guard cannot adopt an older process forest. Separately authorized cleanup
uses a fresh guard directory without resetting the consumed engine attempt.

The standalone `test` step uses real native processes and namespaces, including
owner/custodian/PID1/worker/escaped-descendant kills, deadline/output limits,
paused owner-observers, death at the registration-fsync boundary, pre-dispatch
and recording failures, kernel pidfd reaping observations, exact
budget bounds, cross-boot/stale/reused identities and malformed/missing proofs.
Cancellation fixtures hold the registration gate until PID1 observes a queued
event, pause PID1 after a single cancellation while the custodian is stopped
(without any later signal that could relatch a drained event), and exercise
both resumed-custodian termination and the owner's bounded
both-observers-paused shutdown. Worker and escaped-descendant pidfds must
report kernel reaping, not just exit. Publication fixtures inject failure or
actual process interruption after the final seal is visible but before its
directory fsync, with and without original-owner feedback.
All workloads and signing keys are explicitly synthetic; namespace reaping is
actual kernel behavior, not simulated success.

`test` selects its driver mode with `-Doptimize`; the independently compiled
native child defaults to ReleaseSmall and has an explicit
`-Dfixture-optimize` selector. The correction suites passed 19/19 in Debug
with a ReleaseSmall child and 19/19 with **both driver and child ReleaseSafe**.
`compile-guard` now honors `-Doptimize` for the complete target fixture and
its module, rather than silently selecting ReleaseSmall.

From the worktree root, using existing private fixture directories:

```sh
root="$PWD/.d/zig-migration-operator-guard"
export TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/cache"
export ZIG_GLOBAL_CACHE_DIR="$root/global-cache"
for mode in Debug ReleaseSafe; do
    child=ReleaseSmall
    if [ "$mode" = ReleaseSafe ]; then child=ReleaseSafe; fi
    export ZIG_LOCAL_CACHE_DIR="$root/$mode/cache"
    /home/g/.local/bin/zig build --build-file support/tools/hyperv/operator_guard/build.zig test install \
        -Dtest-root="$root/$mode/fixtures" -Doptimize="$mode" -Dfixture-optimize="$child" -j2 \
        --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
        --prefix "$root/$mode/install" --summary all
done
for target in x86_64-linux-musl aarch64-linux-musl; do
    export ZIG_LOCAL_CACHE_DIR="$root/targets-release-safe/$target/cache"
    /home/g/.local/bin/zig build --build-file support/tools/hyperv/operator_guard/build.zig compile-guard \
        -Dtarget="$target" -Doptimize=ReleaseSafe -j2 \
        --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
        --prefix "$root/targets-release-safe/$target/install" --summary all
done
```

Measured complete, unstripped `operator-guard-target-fixture` artifacts for
these actual ReleaseSafe target builds:

| Target | Executable bytes | Executable + 233,504 reservation |
| --- | ---: | ---: |
| x86_64-linux-musl | 5,670,240 | 5,903,744 |
| aarch64-linux-musl | 5,573,536 | 5,807,040 |

The earlier 398,584 / 368,288 byte target measurements were **ReleaseSmall**,
not ReleaseSafe, and preceded these corrections. The current measurements
include the separately bound synthetic fixture; neither table is a
measurement of the final integrated operator, all copies or its runtime
assets. **Final 8 MiB / 256 MiB operator-ledger fit remains unproven.**

Use explicit private `-Dtest-root`, `--cache-dir`, `--global-cache-dir`,
`--prefix`, and `-j2`. No public CLI or existing engine is integrated here.
