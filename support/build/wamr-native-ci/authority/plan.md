# Native plan source library

`plan.run(Context, PlanCommand, *candidate.Finalized) -> plan.Outcome` performs
the plan operation; it is not a CLI handler, owner-acquisition adapter or runtime
builder. It consumes an existing verified Azure runtime independently of the
runtime-copy/probe producers.

The caller retains the genuine imported-product `Finalized`, its complete
import/download/archive/private-reader chain, allocator, I/O and optional
cancellation owner through `Prepared.deinit`. `bundle` must identify its actual
imported root-bound manifest; `candidate_output` identifies its already published
candidate, not a request to recreate or copy one. An optional attempt must match
that candidate; omission retains the candidate's attempt. Campaign, subscription
and supplied ledger/attempt UUIDs use the frozen normalization. Omitted creation
time and ledger UUID use the frozen clock/random defaults.

The operation requires imported v2 provenance, six false candidate approval flags
and two zero timestamps, frozen topology/budgets, exact candidate selectors,
retained supervisor/validator identities and the executing controller. It does
not recover import authority from a transport receipt or standalone paths, infer
PATH tools, initialize a ledger, consume approval or call Azure.

## Publication and results

All output parents already exist privately. The following names are reserved
create-only; collisions, unsafe modes, links, symlink walks, protected input roots
and physical directory aliases are refused:

| Path | Contents |
| --- | --- |
| `output + ".pending-plan.json"` | Canonical plan bytes |
| `approval_template + ".pending-template.json"` | Canonical pending template |
| `output + ".validation.json"` | Real descriptor-supervised validator result |
| `output` | Final canonical plan |
| `approval_template` | Final pending template, published last |
| `output + ".failure.json"` | Safe private refusal/poison diagnostic, if needed |

The native validator consumes both pending records with the retained current
reader's validator descriptor, empty environment, retained repository cwd,
bounded separate captures and independent primary/descendant-cleanup deadlines.
Its primary exit/signal, cleanup, physical executable identity, reader/source
commitments, timestamps, stream statuses and exact hex-encoded stdout/stderr are
recorded even when it fails or post-run custody fails. The existing typed compute
validator also checks staged, final-plan/staged-template and final/final pairs.

Each transaction is create-only and durably checked, with the full borrowed
candidate, runtime/tools, unchanged ledger proposal/state and earlier retained
records revalidated around slow stages and publication. Locks are released
between records, so same-parent outputs work without lock contention. Earlier
records stay retained. Cross-directory publication is **not** atomic: a failure
can leave a durable plan without a template, or poison a late-published template.
Only a typed `success` plus fresh `Prepared.result()` is success. The pending
template is never permission.

`Prepared.result()` returns borrowed typed plan/template and final/validation
artifacts after full revalidation. `Prepared.revalidate()` enforces the original
finite operation deadline and cancellation as well as custody. `deinit` closes
owned descriptors without deleting immutable evidence or borrowed sources.

Refused/poisoned diagnostics preserve the original error/phase, all six separate
publication statuses, primary/cleanup/recording lanes, child status and an
independent recording error. Failure recording bypasses cancellation only for
already proven safe output locations and rechecks physical separation; unsafe
early refusals return typed diagnostics without writing inside inputs. Pending
and failed evidence is non-resumable and retained, not silently cleaned away.

## Focused validation

From `support/build/wamr-native-ci`, run with Zig 0.16, an existing owner-private
absolute external fixture root, private cache/global directories, and the
complete read-only package directory:

```sh
zig build --build-file authority-plan.build.zig test -j1 \
  -Dtest-root=ABS --cache-dir ABS --global-cache-dir ABS --system PACKAGES
# Repeat with -Doptimize=ReleaseSafe.
```

The isolated selector includes foundation transaction/fault/cancellation/process
tests, frozen plan/template byte parity, pure imported-selector/policy refusal
tests, physical output/ledger/controller/receipt negatives and a non-test object
that typechecks the complete `run`/`result` algorithm. A real retained native
validator also exercises malformed-plan refusal with exact child stderr/exit
and complete cleanup. Initialized-ledger testing freezes current state separately:
the reused pre-state constructor intentionally refuses an existing marker.
No trusted test-only
`Finalized` is manufactured. Genuine positive operation acceptance still needs
a live authentic imported-product `Finalized` in its executing controller,
plus a real prepared runtime. Shared source handler composition is now exported
as described in [composition.md](composition.md). Genuine acceptance,
standalone owner acquisition, caller migration, approval and cloud execution are not
claimed by these source tests.
