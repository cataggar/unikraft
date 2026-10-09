# Native authorization recording (source only)

`authorization.run(types.Context, types.AuthorizationCommand)` returns
`types.Outcome(*authorization.Recorded)`. A successful heap-stable owner retains
the copied command, canonical plan/template/runtime documents, exact input
digests, private path walks, executable bindings, public-bundle artifacts,
six-mode boot/evidence records, and both output records. Its `value()` is an
authorization, **not admission**. `artifact()` describes the durable final file;
`revalidate()` checks custody, independent engines and decision freshness again.
`deinit()` closes descriptors and wipes allocations without deleting evidence.
The supplied `io` and optional cancellation owner must outlive `Recorded`.

The recursive canonical parser rejects duplicate/unknown fields, numeric-string
and boolean coercion, invalid UTF-8 and wrong record shapes before using the
existing schema validators. The existing direct-compute plan and authorization
engines independently verify seeded inputs, ledger proposals, candidate/image
lineage and complete runtime content/physical/parent hashes **in-process**.
Explicit tool arguments must match the retained plan bindings. No path is
inferred to be the executing controller; no receipt is reconstructed into an
`ImportedProduct` or `Finalized`. This operation accepts externally verified
existing plans/templates and does not depend on native plan production.

Construction uses `authority.records`. A current approved **or denied** decision
requires a positive recorded time, a maximum 3600-second window and
`recorded_unix <= now < expires_unix`. The approved-only `Authorization.current`
is deliberately not used for recording denial; it still refuses denial for
admission. Approver/reference are bounded UTF-8 operator text (128/256 bytes),
not executable identities, and are never logged.

A create-only durable `<output>.partial-<uuid>` is independently validated before
the final transaction publishes the same sorted, compact UTF-8 bytes and one LF.
The partial is retained even on success as private validation evidence. Both
records and all inputs remain pinned. Freshness/cancellation checks bracket
potentially slow engine validation and final publication. A late refusal returns
`poisoned`, never success, even if a durable file appeared. Partial publication,
write/sync uncertainty and independent recording/cleanup failures retain their
status and evidence; failures are not resumable. Logging contains only phase,
error name and publication status, never paths, authority text or captures.

No installed command, frozen CLI change, Python fallback, genuine approval,
approval consumption, ledger initialization/claim or cloud operation is added.
Standalone context acquisition and genuine acceptance remain separate gates.

## Focused source gate

With an existing owner-private absolute root, fresh per-owner external caches
and Zig 0.16, run from `support/build/wamr-native-ci`:

```sh
zig build --build-file authority-authorization.build.zig test \
  -Dtest-root=ABS -j1 --summary all
zig build --build-file authority-authorization.build.zig test \
  -Dtest-root=ABS -Doptimize=ReleaseSafe -j1 --summary all
```

The selector also compiles the real handler in a non-test object. It does not
install an executable. The test fixture uses the existing native image package
producer and existing v2 lineage fixture, Python's frozen metadata scan, and
explicitly synthetic tool bindings/local observations. The **actual handler and
unreplaced compute engines** process the fixtures; they are not externally
qualified owners, real Azure runtimes, genuine decisions or hardware acceptance.
Fault hooks cannot replace an engine and are unavailable to production callers.

The root now exports `authorization`, and the shared source handler dispatches
this actual operation; see [composition.md](composition.md). Module imports are
the existing `hyperv_core`, `wamr_direct_compute`, and `wamr_handoff`; no new
production dependency is needed. The standalone selector supplies the focused
tests' `test_options.authorization_package` and `authorization_fixture`, in
addition to the foundation fixture root/process executable options. The aggregate
provides these through the single shared `testOptions` module.
The frozen 196-scenario inventory and authority golden are unchanged.
