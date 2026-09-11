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

PID1 remains a raw-syscall supervisor while the typed worker executes, with
64 KiB stdout and stderr limits. Existing engine/process supervisors may run
inside the worker. Their new process groups, `setsid`, double-forked children
and nested PID namespaces remain inside this PID namespace.

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
operation, run/attempt UUIDs, complete context digest, exact executable digest
and trusted proof public key. The library rehashes its actual executable;
callers cannot select a different worker executable. `Signer.load` accepts
only an explicit bounded private seed file matching that public key. No
ambient credentials, host trust override or private key in argv/env/image is
introduced. The signer and sensitive buffers must be destroyed.

`Handle.cancel()` requests local termination. `Handle.wait(allocator)` reaps
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
`uk-operator-custody-registration-v1` and `uk-operator-custody-seal-v1`.
Signatures are Ed25519 over `domain + "\n" + canonical(body)`; canonical JSON
has sorted keys and a final LF. The seal hashes the entire signed registration.
Fields, including schema and witness, are required; there is no legacy import.

Owner death normally leaves the custodian able to reap PID1 and seal a
cleanup-only witness, preserving the primary interruption. Killing the
custodian still kills PID1 and its descendants, but if no custodian survived to
record its kernel witness, recovery remains closed. Simultaneous loss of owner
and witness, an uninterruptible kernel exit, or lost/uncertain recording is
**not** automatically repairable by scanning PIDs or assuming reboot cleanup.
No privileged persistent witness service or broader approval is requested.
Old attempts without this registration cannot be adopted.

The witness discharges only local process custody. A non-completed cause
permits the integrating engine's separately authorized cleanup path, never
run resumption. Cloud mutation uncertainty, cleanup authority expiry, state
recording failure, exact resource ownership and engine admission remain the
engines' independent obligations.

Owner death or deadline expiry immediately after registration durability also
goes through termination, reaping and cleanup-only sealing, without opening the
worker gate. A surviving custodian does not abandon an already registered
attempt. Live owners receive all accumulated failure lanes even when sealing
succeeds; recovery after owner death instead consumes the durable seal.

## Requirements, accounting and native fixtures

Linux 5.11+ on AArch64 or x86_64, enabled unprivileged user/PID/mount namespaces,
procfs, pidfds/atomic `CLONE_PIDFD`, memfd sealing, `close_range(CLOEXEC)` and
private descriptor-safe local files are required. Missing kernel facilities
fail closed without a process-group fallback. No host capability, daemon,
shell child, Python, cloud call or package dependency is needed.

`requiredControl(binary_bytes)` charges the executable plus four 16 KiB record/
dispatch/emergency reservations and both 64 KiB output limits. Every call must
fit its explicitly reserved component budget; the integrating parent must also
charge all guard/engine binaries, state, worker controls and any actual copies
in the unchanged **2,097,152 control / 268,435,456 cumulative staging** ledger.
These component bounds are not whole-workflow admission or an exemption.
The parent must start all relevant engine writers inside the namespace; a
guard cannot adopt an older process forest. Separately authorized cleanup
uses a fresh guard directory without resetting the consumed engine attempt.

The standalone `test` step uses real native processes and namespaces, including
owner/custodian/PID1/worker/escaped-descendant kills, deadline/output limits,
paused owner-observers, death at the registration-fsync boundary, pre-dispatch
and recording failures, kernel pidfd reaping observations, exact
budget bounds, cross-boot/stale/reused identities and malformed/missing proofs.
All workloads and signing keys are explicitly synthetic; namespace reaping is
actual kernel behavior, not simulated success. `compile-guard` compiles the
complete bound fixture for another supported Linux target without executing it.
Use explicit private `-Dtest-root`, `--cache-dir`, `--global-cache-dir`,
`--prefix`, and `-j2`. No public CLI or existing engine is integrated here.
