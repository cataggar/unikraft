# Native-v4 physical public artifact import

`importer.zig` is a synchronous native filesystem leaf for the **exact
two-file native-v4 public artifact**. It does not execute Python, miz, QEMU,
a guest, a shell, a downloader, an Azure client or a credential provider.
It calls the embedded pinned miz library for real read-only image inspection.
This replaces only physical public artifact load/import/reload behavior.
The revision-3 Python importer, existing #87 consumers, artifact upload and
attestation workflows are not changed.

**An import is LOCAL ONLY / NOT ADMITTED.** It creates no `engine.State`,
local four-boot observations, completed preflight, ownership prefix, cloud
resource ledger, resume authorization, signed-image trust or cloud acceptance.
Source boot claims remain explicitly `source_manifest` claims. No caller
struct, receipt digest or successful inspection is an attestation capability.

## Independent trust inputs

Both commands require all of:

| Input | Required independent origin |
| --- | --- |
| Expected manifest SHA256 | Reviewed job summary or independently verified artifact-attestation subject; never computed from the supplied artifact as an approval shortcut |
| Expected GitHub source | Independently selected repository, repository ID, workflow/ref, job, run ID, run attempt and head SHA; never copied from the artifact |
| Expected native producer SHA256 | Independently approved **source exporter** executable digest, not the manifest's own `controller_sha256`, and not the importing executable's digest |

`validate-import` additionally requires the **import receipt SHA256 returned
by a successful durable import**, retained separately by the caller. This
anchors the original local physical commitments against receipt mutation.
Never derive this expectation from residual files after a failed/ambiguous
import. There is no repair, adoption, retry or recovery command.

These expectations are mandatory inputs, not booleans or self-approval
defaults. The leaf checks their exact values but **does not cryptographically
verify a GitHub/Sigstore attestation** or prove where the caller obtained
them. Trusted acquisition, executable selection, root-dispatch binding,
attestation verification and all private image/authority admission remain
separate integration gates before cutover.

The source producer and importer are intentionally distinct: the source
digest comes from independent expectations and must match native-v4 manifest
semantics. The importer's digest and size come from the actual running
`/proc/self/exe`, checked against its canonical named ELF file. Reload
requires that same importing executable content; a different binary must
not impersonate it. Both record the exact embedded miz revision. No source
executable size is invented, and the source executable is not opened.

## Commands

Use the standalone `uk-hyperv-public-image`. All paths must be explicit,
absolute, canonical and symlink-free. `--state-dir` is a **new**, nonexistent
destination whose parent already exists.

```sh
uk-hyperv-public-image import-prepared \
  --artifact-dir /canonical/public/artifact \
  --state-dir /canonical/private/imported \
  --expected-manifest-sha256 "$REVIEWED_MANIFEST_SHA256" \
  --expected-producer-sha256 "$REVIEWED_SOURCE_NATIVE_SHA256" \
  --expected-repository cataggar/unikraft \
  --expected-repository-id 123 \
  --expected-workflow-ref cataggar/unikraft/.github/workflows/integration.yaml@refs/heads/main \
  --expected-job zig-hyperv \
  --expected-run-id 456 --expected-run-attempt 1 \
  --expected-head-sha 0123456789abcdef0123456789abcdef01234567
```

On exit 0, retain the `receipt_sha256` from the bounded canonical JSON result
in a separate trusted caller record. Do not infer success from directory or
receipt existence.

```sh
uk-hyperv-public-image validate-import \
  --state-dir /canonical/private/imported \
  --expected-import-sha256 "$RETAINED_SUCCESSFUL_IMPORT_SHA256" \
  --expected-manifest-sha256 "$REVIEWED_MANIFEST_SHA256" \
  --expected-producer-sha256 "$REVIEWED_SOURCE_NATIVE_SHA256" \
  --expected-repository cataggar/unikraft \
  --expected-repository-id 123 \
  --expected-workflow-ref cataggar/unikraft/.github/workflows/integration.yaml@refs/heads/main \
  --expected-job zig-hyperv \
  --expected-run-id 456 --expected-run-attempt 1 \
  --expected-head-sha 0123456789abcdef0123456789abcdef01234567
```

The import result contains schema version 1, `scope=public_local_import_only`,
`authority=not_admitted`, `attestation=not_verified`, `succeeded`,
`destination`, `publication`, optional receipt SHA256 and independent
primary/cleanup/recording failures. The latter two statuses use the core
`not_committed`, `publication_unknown`, `visible_not_durable`, `durable`
vocabulary. Receipt SHA256 is returned only with both durable statuses and
no failures. Validation success has `validated=true` with the same closed
scope/authority/attestation labels.

Exit 0 means only the requested local operation succeeded. Import execution
failure is exit 1; argument/validation refusal is exit 2; diagnostic-output
failure is exit 3. Errors contain fixed enumerated diagnostics, not paths,
raw exception messages, subprocess output or manifest-provided strings.
Post-import serialization/output failure preserves the known destination and
receipt publication statuses, suppresses the successful receipt digest, and
adds a recording failure without replacing earlier failures in any lane.
The CLI attempts a bounded, independently buffered stderr report and exits 3,
even when that fallback also cannot be delivered. It does not replay the
import, remove published files, or claim a prepublication argument refusal.
After successful `validate-import`, output failure likewise exits 3 with a
no-digest stderr report preserving `validated=true` as the completed physical
observation, plus the independent recording failure; it publishes nothing.
Only a complete exit-0 response is usable. Partial stdout, even if it contains
a digest, and residual receipts after failed delivery are not recovery inputs.
There are no `--miz`, location, VM-size, trust-artifact, fixture, acquisition
or credential options for these commands.

## Physical invariants

Input contains exactly `prepared-image-manifest.json` and `unikraft.vhd`.
There is no archive extraction and no manifest-selected filesystem path.
Extra, hidden, missing, symlink, FIFO/device and nonregular entries refuse.
Ancestors and directories use the existing core descriptor-walk policy.
Input files must have one link, be current-user/root owned, and have ordinary
read-only or owner-writable data modes (0400/0444/0600/0644); executable,
special and group/world-writable modes refuse.

The manifest is bounded to 64 KiB and must be the exact canonical bytes:
sorted compact JSON with one LF, no duplicate/unknown fields, exact integers,
the unchanged prepared-image schema version 2, and native controller revision
4. Its complete byte digest, GitHub source and source producer must match
the independent expectations through `manifest.validate`.

Inspection requires the exact 66-MiB + 512-byte fixed VHD, full VHD SHA256,
the full 66-MiB raw-prefix SHA256 and complete footer. The native miz
validator actually reads/checks the EFI/PE, GPT and backup GPT, FAT tree,
fallback boot path, architecture, deterministic image identities,
EFI digest, exact virtual/file geometry and packaging projection. The
inspection also records the full footer SHA256 and native image metadata.
Correctly updated outer hashes cannot make an internally malformed or
wrong-identity image pass.

Retained read-only descriptors, complete stream hashes and inode/device/
mode/link/mtime/ctime snapshots bind the originals through copy, inspection
and receipt publication. Named source files and the source directory are
rechecked. The copied VHD is independently reinspected with the same native
validator. No VHD is converted, footer rewritten, raw/EFI file extracted,
disk reseeded or guest booted.

Destination-parent ancestry is compared by retained directory identity, not
only string prefixes, to refuse output within the input. Creation is
exclusive; existing destinations, including empty or failed imports, refuse.
No input, source receipt or other worktree is modified.

## Private namespace and receipt

Successful import contains exactly:

```text
.writer.lock
import-request.json
prepared-image-manifest.json
unikraft.vhd
inspection.json
import-receipt.json
```

The directory is owner-only 0700; every file is owner-only 0600 and single
linked. The original stable lock is never renamed or removed. A durable
create-only request binds expectations, importer identity and destination
directory identity before copies. Each copy is exclusive and file/directory
fsynced. Inspection and final receipt use the core durable immutable-file
publication mechanism.

Request schema is `unikraft.hyperv.public-import-request` version 1 with
phase `importing`. Receipt schema is `unikraft.hyperv.public-import` version
1 with phase `imported`, scope `local_only`, authority `not_admitted`,
attestation `not_verified`, and boot-claim origin `source_manifest`.
There is no claim of a completed private attempt.

The receipt binds all independent expectations, distinct source/importer
identities, actual directory and stable-lock identity, the request, exact
copied manifest/VHD and canonical inspection bytes, packaging, acceptance,
and source boot claims. Physical file commitments include SHA256, size,
device/inode, owner/mode/link count and modification/change timestamps.
The copied manifest and canonical request/inspection digests must match
the validated/generated records before publication; all receipt commitments
are reconstructed and compared again before returning success.
This is a commitment to the original physical namespace, not a portable
authority receipt that can be copied to new files.

Reload requires the separately retained receipt digest, re-reads the actual
private files, reruns manifest and native VHD inspection, reconstructs the
receipt from current physical facts plus caller expectations, and checks
exact equality. It rejects phase/authority changes, inconsistent claims,
content or metadata mutation, renamed/replaced file identities, copied
receipts, namespace changes and importer substitution. It does not need
the original artifact directory and never opens a path taken from a receipt.

## Failure and lifetime behavior

Destination creation and receipt publication have separate certainty
statuses. A sync or write failure can leave an empty/partial private
directory or a visible receipt. `publication_unknown` and
`visible_not_durable` are not converted into success merely because a file
exists. A directory-creation error without a definite no-effect answer
retains `publication_unknown`. No receipt digest is returned on any failure,
including a late input-integrity failure after publication.

Partial data, the stable writer lock and any atomic-publication cleanup
failure remain visible for diagnosis. There is no recursive production
cleanup and no failed-directory reuse. Core atomic-file cleanup and
recording failures remain independent of the primary operation failure.
Caller-owned cleanup or reconciliation of an unsuccessful local operation
is outside this import leaf and must not manufacture a successful receipt.

All records are bounded by 64 KiB; image size is exact, EFI inspection by
64 MiB, stream buffers by 32 KiB and namespaces by their fixed entry counts.
The original and copied VHDs are streamed, not loaded wholesale into memory.
This synchronous filesystem leaf makes **no claim that size bounds or
elapsed checks interrupt stalled filesystem syscalls**. A trusted outer
native supervisor/deadline is a separate integration responsibility; this
leaf creates no nested process group or child workload.

## API and focused fixtures

`root.zig` exports `importer` and `import_contracts`:

```text
importer.importPrepared(allocator, io, artifact_dir, destination, Expectations) Result
importer.load(allocator, io, destination, Expectations, retained_receipt_sha256) !Receipt
package.inspectVhd(allocator, io, read_only_file, ExpectedImage) !Inspection
```

Use an arena per bounded operation. Expectation hash fields are validated
lowercase 64-hex text; the retained receipt digest is raw32 in the API.
`package.inspectVhd` is also used by the existing public packaging observer,
not a parallel image validator. `importFault` is compile-time restricted
to native tests, following the existing core fault boundary; no production
entry or runtime flag exposes it.

Use Zig 0.16 and only the new worktree's caches/output directories. The
already restored package directory is read-only input, not a build location:

```sh
S="$PWD/.d/zig-migration-public-import"
PKGS=/d/unikraft-worktrees/fleet-local-boot/.d/zig-migration-public-image/restore/zig-pkg
umask 077
mkdir -p "$S"/home "$S"/tmp "$S"/cache "$S"/global-cache/tmp \
  "$S"/fixtures "$S"/outputs
export HOME="$S/home" TMPDIR="$S/tmp" XDG_CACHE_HOME="$S/cache"
export ZIG_LOCAL_CACHE_DIR="$S/cache" ZIG_GLOBAL_CACHE_DIR="$S/global-cache"
/home/g/.local/bin/zig build --build-file support/tools/hyperv/public_image/build.zig \
  --system "$PKGS" --prefix "$S/outputs/debug" \
  -Dimport-test-root="$S/fixtures" -Dtest-root="$S/fixtures" \
  -j2 test-import test install --summary all
/home/g/.local/bin/zig build --build-file support/tools/hyperv/public_image/build.zig \
  --system "$PKGS" --prefix "$S/outputs/release" -Doptimize=ReleaseSafe \
  -Dimport-test-root="$S/fixtures" -Dtest-root="$S/fixtures" \
  -j2 test-import test install --summary all
/home/g/.local/bin/zig build --build-file support/tools/hyperv/local_boot/build.zig \
  --prefix "$S/outputs/local-debug" -Dtest-root="$S/fixtures" -j2 test install
/home/g/.local/bin/zig build --build-file support/tools/hyperv/local_boot/build.zig \
  --prefix "$S/outputs/local-release" -Dtest-root="$S/fixtures" \
  -Doptimize=ReleaseSafe -j2 test install
```

`test-import` uses ordinary public synthetic 512-byte EFI inputs and real
native miz containers/inspection, without QEMU or boot execution. It covers
independent expectations, canonical/schema and exact namespace refusals,
symlinks/FIFOs/hardlinks/modes, aliasing/no-clobber, coherent-hash footer/GPT/
EFI corruption, exact length, source mutation, separate producer identities,
receipt/phase/claim/inspection/physical mutations, durable failure states,
lock contention, original-input independence, and actual native CLI arguments.
Delivery regressions send real post-import stdout to `/dev/full` and a closed
pipe, retain and inspect the durable receipt/VHD, and exercise failed reload
output and error-output delivery without replaying or adopting an import.
All factory source boot claims are explicitly synthetic, not attested or
locally observed. Existing public-image/local-boot suites use their separate
native mock processes, never actual QEMU. No guest/Make/producer build,
download, Python, cloud, credential, original seed or historical evidence
operation is part of these fixtures.
