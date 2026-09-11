#!/usr/bin/env bash
set -euo pipefail
umask 077

test "$(id -u)" -ne 0
root="${RUNNER_TEMP:?}/hyperv-ci/native-operator-guard"
package=support/tools/hyperv/operator_guard
installation=/opt/unikraft-hyperv-custody-ci
executable="${installation}/operator-guard-fixture"
profile="${installation}/profile"
profile_name=unikraft-hyperv-custody-ci
created=false
loaded=false

cleanup() {
  result=$?
  trap - EXIT
  if [ "${loaded}" = true ]; then
    if ! sudo apparmor_parser --remove "${profile}"; then
      echo 'Failed to remove the custody fixture AppArmor profile' >&2
      exit 1
    fi
  fi
  if [ "${created}" = true ]; then
    if ! sudo rm -f -- "${profile}" "${executable}" ||
       ! sudo rmdir -- "${installation}"; then
      echo 'Failed to remove the custody fixture installation' >&2
      exit 1
    fi
  fi
  exit "${result}"
}
trap cleanup EXIT

mkdir -p "${root}/baseline/fixtures"
zig build --build-file "${package}/build.zig" \
  --cache-dir "${root}/fixture-cache" --prefix "${root}/fixture-out" \
  -Dfixture-optimize=ReleaseSafe -j2 install-fixture --summary all

# Never profile a writable cache path, compiler, shell, or arbitrary test runner.
sudo mkdir -m 0755 -- "${installation}"
created=true
sudo install -o root -g root -m 0555 \
  "${root}/fixture-out/bin/operator-guard-fixture" "${executable}"
test "$(stat -c '%u:%g:%a:%h' "${executable}")" = '0:0:555:1'
cmp "${root}/fixture-out/bin/operator-guard-fixture" "${executable}"
sha256sum "${executable}" > "${root}/fixture-sha256.txt"

started="$(date --utc '+%Y-%m-%d %H:%M:%S')"
baseline=0
zig build --build-file "${package}/build.zig" \
  --cache-dir "${root}/baseline/cache" --prefix "${root}/baseline/out" \
  -Dtest-root="${root}/baseline/fixtures" \
  "-Dfixture-executable=${executable}" \
  -Dtest-filter='kernel guard completes' -Doptimize=Debug -j2 test --summary all \
  > "${root}/baseline.log" 2>&1 || baseline=$?

if [ "${baseline}" -ne 0 ]; then
  # Only a matching kernel denial authorizes the approved per-fixture exception.
  tail -n 60 "${root}/baseline.log"
  grep --fixed-strings --quiet 'MountNamespaceUnavailable' "${root}/baseline.log"
  test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
  sudo journalctl --kernel --since "${started}" --no-pager --output=cat \
    > "${root}/kernel.log"
  grep --fixed-strings 'apparmor="DENIED"' "${root}/kernel.log" |
    grep --fixed-strings 'comm="uk-custody-test"' > "${root}/namespace-denial.log"
  test -s "${root}/namespace-denial.log"
  head -n 12 "${root}/namespace-denial.log"
  grep --fixed-strings 'profile="unprivileged_userns"' "${root}/namespace-denial.log" |
    grep --fixed-strings --quiet 'capname="sys_admin"'
  command -v apparmor_parser
  sudo install -o root -g root -m 0600 "${package}/ci.apparmor" "${profile}"
  # Add rather than replace: an existing profile with this name is an error.
  sudo apparmor_parser --add "${profile}"
  loaded=true
  sudo grep --fixed-strings --line-regexp --quiet \
    "${profile_name} (unconfined)" /sys/kernel/security/apparmor/profiles
  test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
fi

for mode in Debug ReleaseSafe; do
  mkdir -p "${root}/${mode}/fixtures"
  zig build --build-file "${package}/build.zig" \
    --cache-dir "${root}/${mode}/zig-local-cache" \
    --prefix "${root}/${mode}/out" \
    -Dtest-root="${root}/${mode}/fixtures" \
    "-Dfixture-executable=${executable}" \
    -Doptimize="${mode}" -j2 test install --summary all
  result=0
  "${root}/${mode}/out/bin/uk-hyperv-operator-guard" \
    > "${root}/${mode}/stdout" 2> "${root}/${mode}/stderr" || result=$?
  test "${result}" -eq 2
  test ! -s "${root}/${mode}/stdout"
  grep --fixed-strings --line-regexp --quiet \
    '{"error":"operator-guard-engine-and-authority-binding-required"}' \
    "${root}/${mode}/stderr"
done
sha256sum --check "${root}/fixture-sha256.txt"
if [ "${loaded}" = true ]; then
  test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
fi

for target in x86_64-linux-musl aarch64-linux-musl; do
  zig build --build-file "${package}/build.zig" \
    --cache-dir "${root}/${target}/zig-local-cache" \
    --prefix "${root}/${target}/out" \
    -Dtarget="${target}" -Doptimize=ReleaseSafe \
    -j2 compile-guard --summary all
  binary_bytes="$(stat -c %s "${root}/${target}/out/bin/operator-guard-target-fixture")"
  test "$((binary_bytes + 233504))" -le 8388608
  printf 'Synthetic guard %s bytes: %s + 233504 reserved; not complete operator admission\n' \
    "${target}" "${binary_bytes}"
done
