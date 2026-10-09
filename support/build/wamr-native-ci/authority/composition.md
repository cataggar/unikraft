# Retained authority source library composition

`authority/root.zig` exports `prepare`, `runtime_copy`, `runtime_probes`,
`plan`, `authorization`, `admission`, and `handlers`, alongside the existing
contracts, CLI parser, types, records and transaction library.

`handlers.run(handlers.Context, types.Command)` dispatches the **real** library
operations. Its context explicitly carries retained allocator/I/O/cancellation,
optional live imported `candidate.Finalized`, independently acquired plan and
authorization artifact commitments, and explicit retained ELF discovery inputs.
Missing context is refusal, not a request to recover an owner from JSON, PATH,
the executing program's name, a receipt, or a selected directory. There is no
installed authority command, Python fallback, frozen flag change, ledger claim,
approval consumption, Azure operation, or standalone owner acquisition.

## Operations and lifetimes

* `prepare.run(types.Context, PrepareRuntime, DiscoveryInput) -> Outcome`
  returns a heap-stable `*prepare.Prepared` only after completed preparation.
  `result()`, `revalidate()` and `deinit()` retain the original finite deadline,
  source/destination custody, both native validator runs, real probe evidence,
  manifest and all published records. Results borrow through `deinit()`.
* `plan.run(Context, PlanCommand, *Finalized) -> plan.Outcome` returns the
  existing `*plan.Prepared`, with `result/revalidate/deinit`.
* `authorization.run(Context, AuthorizationCommand)` returns the existing
  `Outcome(*Recorded)`, with `value/artifact/revalidate/deinit`. A current denied
  decision is a valid record, never admission.
* `admission.run(admission.Context, AdmitCommand)` requires the live imported
  owner and independent plan/authorization commitments. It returns
  `*Admitted` with `artifact/revalidate/deinit`, not permission consumption.

The trusted caller retains genuine imported ownership and cancellation/I/O for
the corresponding operation's complete lifetime. `Stage.initNamed` takes its
own copies of discovered names, dependency custody and request strings; discovery
can then be destroyed. The embedded `Stage` is not moved while root, layout,
manifest inputs, output directory or barriers are borrowed. Preparation uses a
dedicated process supervisor; callers with unrelated `waitpid` users must not
share that process.

## Actual preparation and publication order

Discovery checks explicit retained interpreter, loader and candidate DSOs.
Preparation hashes the original retained interpreter before discovery.
`Stage.bindInterpreter` compares COPY's acquired descriptor snapshot and digest
with that original custody, rehashes the original descriptor, and rechecks its
named identity after acquisition. Path equality or identical replacement bytes
cannot establish continuity. A between-phase same-byte atomic replacement test
requires refusal before COPY or any output publication.
COPY streams only that owned inventory and the requested source trees, closes
the native dependency graph independently on the copied tree, prohibits startup
hooks, and freezes runtime directories at `0500`, files at `0400`, and launcher,
interpreter and loader at `0500`. The output and separate startup configuration
remain `0700`. No host Python, opportunistic PATH tool or host-loader fallback is
substituted.

The physical, create-only `azure-runtime.manifest` is written and synced at its
final path first. Its actual `A` identity is then bound to the frozen content,
metadata and parent commitments. As in the original Python ordering, a later
refusal can leave that manifest; its existence is **not** completed preparation.
It uses the frozen private `0600` manifest mode; readonly runtime member modes
are separate. It is not moved or rewritten to make an unreviewed staging-path
commitment appear valid. Manifest writes refuse zero/overreported progress and
check full source/validator custody, the pinned manifest descriptor/name and
signal/I/O cancellation/deadlines between short writes and durability barriers.

The canonical `azure-runtime.pending.json` is private validation evidence. The
retained explicit native validator checks it under descriptor supervision and a
closed environment. Both physical runtime verification and copied ELF
enumeration must succeed before any probe. A closed fork helper alone enters
kernel-verified private user/mount namespaces. It seals a readonly clone, masks
host loader directories, and drops namespace capabilities. The parent retains
its original root; child source barriers are authenticated acknowledgements over
an inherited close-on-exec sequenced socket, checked by the live parent in the
original UID/mount namespace. No outer snapshots are compared as though mapped
UIDs or the overlay were the original tree.

The probe worker is the init of a private PID namespace with its own procfs.
It initializes the native command supervisor after the second fork:
Linux does not inherit the subreaper flag. A real second-fork test supervises
the compiled benign process fixture, then deliberately refuses with
`SourceOnlyWorkerFinished`; it does not synthesize runtime evidence.
Before that transition, the helper authenticates its actual pre-map UID/GID and
live initial-map parent through the existing guarded namespace verifier. Its
fresh four-key internal map never inherits caller environment or receipt data;
the reviewed private-file source and its hash are not changed for this bridge.
The expected retained parent is compared with `getppid` before namespace changes;
only that actual parent and the pre-map syscall UID/GID enter the internal map.
Real fork tests check nonparent refusal and mapped retained-file custody. A host
namespace refusal explicitly skips the positive test, never qualifies it.
Parent-death protection and namespace-init death contain even escaped sessions
if outer cleanup must kill the helper. A PID-pinned parent supervisor enforces
cancellation, the finite preparation deadline and independent cleanup time.
The kernel writes the worker PID into a pre-fork shared anonymous mapping using
`CLONE_PARENT_SETTID`; no post-fork userspace announcement can be lost when the
leader dies. The leader polls its worker pidfd but never reaps it, retaining the
PID until the original subreaper specifically reaps that adopted worker.
Every post-fork outcome, including `Io.checkCancel` failure, goes through the
owned-family supervisor and returns explicit cleanup status. Cleanup has a
15-second bound with TERM grace and a final five-second KILL/reaping reserve.
Forced termination or incomplete custody remains explicit uncertainty even
after successful reaping. There is no global wait or unrelated-family signal.
An actual post-worker-fork I/O cancellation test proves both owned PIDs reaped
while dynamically orphaned foreign live and zombie children remain untouched.
The channel transports pointer-free typed evidence, never paths, authority text
or raw child output, and checks exact count and all four runtime commitments.
There are sixteen frozen Azure command probes plus the separate loader listing,
Python version and import checks: nineteen evidence slots, not sixteen renamed
successes.

Only complete probes, complete helper cleanup, a second real native validation,
fresh source/runtime checks and a durable validation record permit publication
of `azure-runtime.json`. The existing direct runtime engine validates that final
file again. A late failure is poisoned even if the final file is durable.
Cross-record publication is **not atomic**. Pending/failed evidence remains
non-resumable; `deinit` closes descriptors and does not delete it.

Refusals retain separate copy/manifest/pending/validation/final/failure publication
statuses, original phase/error, typed probe failure and native primary/cleanup/
stream/executable/freshness lanes. Failure recording uses only the already proven
private output inode, preserves its independent recording error, and never writes
into a refused input or through the guarded unbounded immutable writer. It makes
one create-only shared transaction attempt with an independent 15-second
recording barrier and null signal; original primary/cleanup failures remain in
the canonical payload. Its context explicitly uses that fresh deadline rather
than inheriting the expired primary publication deadline.
Native captures are represented by lengths and hashes, not child text.
Joined failure-writer regressions require zero progress to terminate after one
write, actual I/O cancellation after three seven-byte writes, and durable
successful short writes without replacing the primary preparation error.
An actual expired publication deadline refuses the pending runtime publication
but still durably records the original refusal through the independent deadline.

## Source validation selectors and excluded gates

`authority.build.zig test` now joins every library's tests, the unchanged original
foundation/contract tests, Python goldens and a non-test source object exercising
all complete handlers and owner APIs. `source-check -Dtarget=x86_64-linux-gnu`
typechecks the entire x86 helper without executing a runtime. `-Dtest-filter=TEXT`
is available for focused native checks. The package build's
`test-authority-libraries`, `test-authority-contracts`, `test-controller` and
`test` include the aggregate and complete source object; fixtures share one
options module with the retained handoff module.
`-Dtest-filter='joined namespace'` selects the real namespace bootstrap/refusal
cases; even a passing bootstrap is not genuine runtime-probe qualification.
Cleanup fault selectors use the shared test-only real named atomic fixture:
an unnamed `O_TMPFILE` has no named cleanup operation to fail. All original
cleanup/failure/publication assertions and guarded production bytes are retained.
Late-expiry and cancellation fixtures arm from the retained final record's
actual durable publication, not a progress-barrier ordinal. Real write and
file-sync failures preserve their original `InputOutput` cause and independent
recording lane with no final publication; directory-sync failure retains the
visible record without claiming durability. These syscall failures are distinct
from deliberately injected `PublicationUncertain` faults and link ambiguity.

Use Zig 0.16, precreated owner-private external fixture/cache roots, `-j1`,
the complete read-only `--system` package directory, and both Debug/ReleaseSafe.
Generated build fixture paths can be relative to the invocation cwd; fixture
constructors canonicalize the actual validator before borrowing its descriptor.
Production commands still require explicit canonical absolute paths.
Do not create, remove or rename ancestors of another running custody capture.
The source tests include actual COPY → physical manifest → native validator →
copied-ELF refusal, collision retention, cancellation and explicit-context
refusals. Synthetic ELF is not executed in that joined negative test.

A genuine compatible x86 Python/Azure runtime positive and a genuine live
imported-owner positive remain **uncovered**, explicitly distinct from source
compilation or synthetic decision-record tests. Standalone owner acquisition,
trusted caller migration, genuine approvals, approval consumption, deletion
authority and cloud/hardware acceptance remain blocked separate gates.
