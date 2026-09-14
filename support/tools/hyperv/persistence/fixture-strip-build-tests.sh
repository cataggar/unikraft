#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$#" -ne 4 ]; then
  echo 'Usage: fixture-strip-build-tests.sh ABS_ZIG ABS_LLVM_OBJCOPY ABS_PACKAGES EXISTING_PRIVATE_ROOT' >&2
  exit 2
fi
for path in "$@"; do
  case "$path" in /*) ;; *) echo 'All test paths must be absolute' >&2; exit 2 ;; esac
done
zig="$1"
objcopy="$2"
packages="$3"
root="$4"
if [ -L "$root" ] || [ "$(stat -c '%u:%a' "$root")" != "$(id -u):700" ]; then
  echo 'The test root must be an existing private owner-only directory' >&2
  exit 2
fi
package="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd -- "$root" && pwd -P)/build-gating"
mkdir -m 700 -- "$root"
mkdir -- "$root/home" "$root/tmp" "$root/global" "$root/fixtures" "$root/retained"
export HOME="$root/home" TMPDIR="$root/tmp" XDG_CACHE_HOME="$root/global"
test "$("$zig" version)" = 0.16.0
"$objcopy" --version > "$root/objcopy-version.txt"
test "$(stat -c '%s' "$root/objcopy-version.txt")" -le 4096
awk -f "$package/../preparation/ci-objcopy-version.awk" "$root/objcopy-version.txt"
sha256sum -- "$objcopy" > "$root/objcopy.sha256"
common=(
  "$zig" build --build-file "$package/build.zig" --system "$packages"
  --cache-dir "$root/cache" --global-cache-dir "$root/global" --prefix "$root/out"
  "-Dtest-root=$root/fixtures" -Doptimize=Debug -j2 --summary all
)
qualified=(-Dstrip-fixture-debug=true "-Dfixture-objcopy=$objcopy")
filter="-Dtest-filter=persistence timing native malformed delivery"

run_build() {
  local name="$1" expected="$2" status=0
  shift 2
  "${common[@]}" "$@" > "$root/$name.log" 2>&1 || status=$?
  printf '%s\n' "$status" > "$root/$name.exit"
  if { [ "$expected" = pass ] && [ "$status" -ne 0 ]; } ||
     { [ "$expected" = refuse ] && [ "$status" -eq 0 ]; }; then
    echo "Unexpected build-gating result: $name exit=$status" >&2
    sed -n '1,100p' "$root/$name.log" >&2
    exit 1
  fi
  printf '%s exit=%s expected=%s\n' "$name" "$status" "$expected"
}

run_build raw pass test "$filter"
grep -Fq '1/1 tests passed' "$root/raw.log"
if grep -Eq '^persistence_timing |run exe persistence-fixture-strip-verifier|run .*objcopy' "$root/raw.log"; then
  echo 'Default-off unexpectedly activated qualification' >&2
  exit 1
fi
run_build not-enabled refuse qualify-fixture
run_build missing-tool refuse qualify-fixture -Dstrip-fixture-debug=true
run_build tool-without-opt-in refuse qualify-fixture "-Dfixture-objcopy=$objcopy"
run_build relayout-without-opt-in refuse qualify-fixture -Dfixture-file-relayout=true
run_build report-without-opt-in refuse qualify-fixture "-Dstrip-fixture-report=$root/invalid.json"
run_build relative-tool refuse qualify-fixture -Dstrip-fixture-debug=true -Dfixture-objcopy=relative-objcopy
run_build relative-report refuse qualify-fixture "${qualified[@]}" -Dstrip-fixture-report=relative.json
grep -Fq 'requires strip-fixture-debug=true' "$root/not-enabled.log"
grep -Fq 'requires -Dfixture-objcopy=ABS' "$root/missing-tool.log"
grep -Fq 'fixture-objcopy requires strip-fixture-debug=true' "$root/tool-without-opt-in.log"
grep -Fq 'fixture-file-relayout requires strip-fixture-debug=true' "$root/relayout-without-opt-in.log"
grep -Fq 'strip-fixture-report requires strip-fixture-debug=true' "$root/report-without-opt-in.log"
grep -Fq 'fixture-objcopy must be absolute' "$root/relative-tool.log"
grep -Fq 'strip-fixture-report must be absolute' "$root/relative-report.log"

proof="$root/qualification.json"
run_build qualified pass qualify-fixture test "$filter" "${qualified[@]}" "-Dstrip-fixture-report=$proof"
grep -Fq '1/1 tests passed' "$root/qualified.log"
if grep -q '^persistence_timing ' "$root/qualified.log"; then
  echo 'Stripping unexpectedly enabled timing' >&2
  exit 1
fi
test "$(stat -c '%u:%a:%h' "$proof")" = "$(id -u):600:1"
jq -e '.schema == "hyperv_persistence_fixture_debug_stripping_v1" and
  .authority == "synthetic_only_not_admitted" and .admitted == false and
  .qualification_only == true and .worker.role == "persistence_worker" and
  .layout_policy == "identical_program_headers" and
  .worker.candidate.size < .worker.raw.size' "$proof" > /dev/null
raw="$(jq -er '.worker.raw.path' "$proof")"
candidate="$(jq -er '.worker.candidate.path' "$proof")"
for artifact in "$raw" "$candidate"; do
  case "$artifact" in "$root"/cache/o/*/hyperv-persistence-worker-fixture) ;;
    *) echo 'Unexpected artifact location in owned test cache' >&2; exit 1 ;;
  esac
done
test "$raw" != "$candidate"
test "$(sha256sum -- "$raw" | cut -d ' ' -f1)" = "$(jq -r '.worker.raw.sha256' "$proof")"
test "$(sha256sum -- "$candidate" | cut -d ' ' -f1)" = "$(jq -r '.worker.candidate.sha256' "$proof")"
raw_hash="$(sha256sum -- "$raw")"
proof_hash="$(sha256sum -- "$proof")"
mkdir -- "$root/retained/raw" "$root/retained/qualified"
cp -- "$raw" "$root/retained/raw/hyperv-persistence-worker-fixture"
cp -- "$candidate" "$root/retained/qualified/hyperv-persistence-worker-fixture"

run_build repeat-report refuse qualify-fixture test "$filter" "${qualified[@]}" "-Dstrip-fixture-report=$proof"
grep -Fq 'persistence_fixture_strip_refused: PathAlreadyExists' "$root/repeat-report.log"
test "$(sha256sum -- "$proof")" = "$proof_hash"
run_build no-report pass test "$filter" "${qualified[@]}"
run_build cached-no-report pass test "$filter" "${qualified[@]}"
for name in no-report cached-no-report; do
  grep -Fq 'run exe persistence-fixture-strip-verifier success' "$root/$name.log"
done

status=0
bash "$package/../preparation/ci-strip-proof.sh" "$proof" "$candidate" \
  > "$root/namespace-refusal.log" 2>&1 || status=$?
printf '%s\n' "$status" > "$root/namespace-refusal.exit"
test "$status" -ne 0
grep -Fq 'Qualification proof is invalid' "$root/namespace-refusal.log"
printf 'namespace-refusal exit=%s expected=refuse\n' "$status"

run_build invalid-output refuse test "$filter" -Dstrip-fixture-debug=true \
  "-Dfixture-objcopy=$package/fixture-strip-reject-objcopy.sh"
grep -Fq 'persistence_fixture_strip_refused:' "$root/invalid-output.log"

# Preserve the good candidate above, then corrupt only this test's cached copy.
cp -- "$package/fixture-strip-rejected-worker.sh" "$candidate"
chmod 700 -- "$candidate"
run_build cached-tamper refuse test "$filter" "${qualified[@]}"
grep -Fq 'persistence_fixture_strip_refused:' "$root/cached-tamper.log"
grep -Fq "run $objcopy (hyperv-persistence-worker-fixture) cached" "$root/cached-tamper.log"
if [ -n "$(find "$root/cache" -type f -name '*.executed' -print -quit)" ]; then
  echo 'A rejected candidate executed' >&2
  exit 1
fi
test "$(sha256sum -- "$raw")" = "$raw_hash"
test "$(sha256sum -- "$proof")" = "$proof_hash"
run_build raw-after-tamper pass test "$filter"
grep -Fq '1/1 tests passed' "$root/raw-after-tamper.log"
if grep -Eq '^persistence_timing |run exe persistence-fixture-strip-verifier|run .*objcopy' "$root/raw-after-tamper.log"; then
  echo 'Default-off unexpectedly consumed the qualified candidate' >&2
  exit 1
fi
echo 'Persistence fixture build-gating cases passed; retained artifacts and refusals remain private.'
