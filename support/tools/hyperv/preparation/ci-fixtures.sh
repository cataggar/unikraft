#!/usr/bin/env bash
set -euo pipefail
umask 077

# Hosted CI only. Local validation must not invoke this policy/setup entrypoint.
test "${GITHUB_ACTIONS:-}" = true
test "$(id -u)" -ne 0
root="${RUNNER_TEMP:?}/hyperv-ci/native-preparation"
package=support/tools/hyperv/preparation
bash "${package}/ci-policy-tests.sh"
installation=/var/lib/unikraft-hyperv-preparation-ci
parser=/usr/sbin/apparmor_parser
uid="$(id -u)"
account="$(awk -F: -v uid="${uid}" '$3 == uid { print; n++ } END { if (n != 1) exit 1 }' /etc/passwd)"
IFS=: read -r username _ passwd_uid gid _ canonical_home _ <<< "${account}"
test "${uid}" = "${passwd_uid}"
test "${canonical_home}" = "$(readlink -f "${canonical_home}")"
test -d "${canonical_home}"
zig="$(readlink -f "$(command -v zig)")"
test "$(awk '/^Cap(Inh|Prm|Eff|Amb):/ { if ($2 != "0000000000000000") bad=1; n++ } END { print (n == 4 && !bad) }' "/proc/$$/status")" = 1

normalize=false
if [ "$(id -g)" != "${gid}" ]; then normalize=true; fi
for group in $(id -G); do
  if [ "${group}" != "${gid}" ]; then normalize=true; fi
done
test ! -e "${root}"
mkdir -p "${root}/restore" "${root}/git-runtime/lib" "${root}/tmp" \
  "${root}/cache" "${root}/config" "${root}/global/tmp" "${root}/driver-cache"
clean_environment=(
  /usr/bin/env -i PATH=/usr/bin:/bin
  "HOME=${canonical_home}" "USER=${username}" "LOGNAME=${username}" LC_ALL=C TZ=UTC
  "TMPDIR=${root}/tmp" "XDG_CACHE_HOME=${root}/cache" "XDG_CONFIG_HOME=${root}/config"
  "ZIG_GLOBAL_CACHE_DIR=${root}/global" "ZIG_LOCAL_CACHE_DIR=${root}/driver-cache"
)
native() {
  if [ "${normalize}" = true ]; then
    # setpriv drops credentials before env/any compiler or test executable runs.
    sudo -n /usr/bin/setpriv "--reuid=${uid}" "--regid=${gid}" --clear-groups \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      "${clean_environment[@]}" "$@"
  else
    "${clean_environment[@]}" "$@"
  fi
}
native /usr/bin/awk -v uid="${uid}" -v gid="${gid}" '
  /^Uid:/ { if ($2 != uid || $3 != uid || $4 != uid || $5 != uid) exit 1; u=1 }
  /^Gid:/ { if ($2 != gid || $3 != gid || $4 != gid || $5 != gid) exit 1; g=1 }
  /^Groups:/ { for (i=2; i<=NF; i++) if ($i != gid) exit 1; s=1 }
  /^Cap(Inh|Prm|Eff|Amb):/ { if ($2 != "0000000000000000") exit 1; c++ }
  END { if (!u || !g || !s || c != 4) exit 1 }
' /proc/self/status
test "$(native "${zig}" version)" = 0.16.0
printf '{"schema":"hyperv_preparation_ci_credentials_v1","uid":%s,"gid":%s,"supplementaries_normalized":%s,"host_caps_zero":true}\n' \
  "${uid}" "${gid}" "${normalize}" > "${root}/credentials.json"

# Match production's canonical facade location, preserving any existing inode.
facade_parent="${canonical_home}"
if [ -d "/run/user/${uid}" ]; then facade_parent="/run/user/${uid}"; fi
facade="${facade_parent}/unikraft-zig-facade-${uid}"
if [ ! -e "${facade}" ]; then mkdir -m 0700 -- "${facade}"; fi
test ! -L "${facade}"
test "$(stat -c '%u:%a' "${facade}")" = "${uid}:700"
if [ ! -e "${facade}/build.lock" ]; then
  (set -o noclobber; : > "${facade}/build.lock")
fi
test ! -L "${facade}/build.lock"
test "$(stat -c '%u:%a:%h:%s' "${facade}/build.lock")" = "${uid}:600:1:0"
facade_identity="$(stat -c '%d:%i:%u:%a:%h:%s' "${facade}/build.lock")"

created=false
debug_profile=false
release_profile=false
profile_used=false
installation_identity=
record_fixture_copies() {
  for mode in Debug ReleaseSafe; do
    for directory in "${root}/${mode}/namespace-cache" "${root}/${mode}/fixture-out" "${root}/${mode}/namespace-out"; do
      if [ -d "${directory}" ]; then
        find "${directory}" -type f -name preparation-namespace-fixture \
          -exec stat --printf='%n\t%s\t%d:%i\t%u:%g:%a:%h\n' {} + || return
      fi
    done
  done
  for variant in debug release-safe; do
    if [ -f "${installation}/namespace-fixture-${variant}" ]; then
      stat --printf='%n\t%s\t%d:%i\t%u:%g:%a:%h\n' "${installation}/namespace-fixture-${variant}" || return
    fi
  done
}
cleanup() {
  primary=$?
  trap - EXIT
  cleanup_failed=false
  if [ "${created}" = true ] &&
     ! record_fixture_copies > "${root}/fixture-copies.tsv"; then
    echo 'Failed to record the synthetic fixture copies' >&2
    cleanup_failed=true
  fi
  if [ "${release_profile}" = true ] &&
     ! sudo -n "${parser}" --remove "${installation}/profile-release-safe"; then
    echo 'Failed to remove the synthetic ReleaseSafe namespace profile' >&2
    cleanup_failed=true
  fi
  if [ "${debug_profile}" = true ] &&
     ! sudo -n "${parser}" --remove "${installation}/profile-debug"; then
    echo 'Failed to remove the synthetic Debug namespace profile' >&2
    cleanup_failed=true
  fi
  restriction=null
  if [ "${profile_used}" = true ]; then
    restriction=false
    if [ "$(/usr/sbin/sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1 ]; then
      restriction=true
    else
      cleanup_failed=true
    fi
  fi
  removed=false
  if [ "${created}" = true ] && [ "${cleanup_failed}" = false ]; then
    if [ -n "${installation_identity}" ] &&
       [ "$(stat -c '%d:%i:%u:%g:%a' "${installation}")" = "${installation_identity}" ] &&
       sudo -n rm -f -- "${installation}/profile-debug" "${installation}/profile-release-safe" \
         "${installation}/namespace-fixture-debug" "${installation}/namespace-fixture-release-safe" &&
       sudo -n rmdir -- "${installation}"; then
      removed=true
    else
      cleanup_failed=true
    fi
  fi
  if [ "$(stat -c '%d:%i:%u:%a:%h:%s' "${facade}/build.lock")" != "${facade_identity}" ]; then
    echo 'Canonical facade lock identity changed' >&2
    cleanup_failed=true
  fi
  printf '{"schema":"hyperv_preparation_ci_cleanup_v1","primary_exit":%s,"profile_used":%s,"cleanup_failed":%s,"installation_removed":%s,"global_restriction_preserved":%s}\n' \
    "${primary}" "${profile_used}" "${cleanup_failed}" "${removed}" "${restriction}" > "${root}/cleanup.json"
  if [ "${cleanup_failed}" = true ]; then exit 1; fi
  exit "${primary}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Retain the existing installed-public-Git closure staging, without probing new tools.
runtime="${root}/git-runtime"
git_executable="$(readlink -f /usr/bin/git)"
llvm-readelf --program-headers --wide "${git_executable}" > "${root}/git-elf.txt"
loader="$(sed -n 's/.*Requesting program interpreter: \(\/[^]]*\)\].*/\1/p' "${root}/git-elf.txt")"
test -n "${loader}"
loader="$(readlink -f "${loader}")"
ldd "${git_executable}" > "${root}/git-ldd.txt"
awk '
  $1 ~ /^linux-vdso/ { next }
  $2 == "=>" && $3 ~ /^\// { print $3; next }
  $1 ~ /^\// && $2 ~ /^\(0x[[:xdigit:]]+\)$/ { print $1; next }
  NF { exit 1 }
' "${root}/git-ldd.txt" > "${root}/git-runtime-paths.txt"
cp --no-preserve=mode,ownership "${git_executable}" "${runtime}/git"
cp --no-preserve=mode,ownership "${loader}" "${runtime}/loader"
chmod 500 "${runtime}/git" "${runtime}/loader"
git_fixture=("-Dgit-executable=${runtime}/git" "-Dgit-loader=${runtime}/loader")
while IFS= read -r source; do
  test -f "${source}"
  if [ "$(readlink -f "${source}")" = "${loader}" ]; then continue; fi
  destination="${runtime}/lib/$(basename "${source}")"
  test ! -e "${destination}"
  cp --no-preserve=mode,ownership "${source}" "${destination}"
  git_fixture+=("-Dgit-library=${destination}")
done < "${root}/git-runtime-paths.txt"
test "${#git_fixture[@]}" -gt 2
cp "${package}/build.zig" "${package}/build.zig.zon" "${root}/restore/"
native "${zig}" build --build-file "${root}/restore/build.zig" \
  --cache-dir "${root}/restore-cache" --fetch=all -j2

# Two physical native children: each embeds its mode's actual workspace/helper.
for mode in Debug ReleaseSafe; do
  mkdir -p "${root}/${mode}/namespace-work"
  native "${zig}" build --build-file "${package}/namespace/build.zig" \
    --cache-dir "${root}/${mode}/namespace-cache" --prefix "${root}/${mode}/fixture-out" \
    "-Dworkspace=${root}/${mode}/namespace-work" "${git_fixture[@]}" \
    "-Doptimize=${mode}" -j2 install-fixture --summary all \
    > "${root}/${mode}/fixture-build.log" 2>&1
done
for directory in / /var /var/lib; do
  test ! -L "${directory}"
  test "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:755
done
sudo -n mkdir -m 0755 -- "${installation}"
created=true
installation_identity="$(stat -c '%d:%i:%u:%g:%a' "${installation}")"
test "$(stat -c '%u:%g:%a' "${installation}")" = 0:0:755
sudo -n install -o root -g root -m 0555 \
  "${root}/Debug/fixture-out/bin/preparation-namespace-fixture" "${installation}/namespace-fixture-debug"
sudo -n install -o root -g root -m 0555 \
  "${root}/ReleaseSafe/fixture-out/bin/preparation-namespace-fixture" "${installation}/namespace-fixture-release-safe"
declare -A fixture_identity
for variant in debug release-safe; do
  test "$(stat -c '%u:%g:%a:%h' "${installation}/namespace-fixture-${variant}")" = 0:0:555:1
  fixture_identity["${variant}"]="$(stat -c '%d:%i:%s:%u:%g:%a:%h' "${installation}/namespace-fixture-${variant}")"
done
cmp "${root}/Debug/fixture-out/bin/preparation-namespace-fixture" "${installation}/namespace-fixture-debug"
cmp "${root}/ReleaseSafe/fixture-out/bin/preparation-namespace-fixture" "${installation}/namespace-fixture-release-safe"
sha256sum "${installation}/namespace-fixture-debug" "${installation}/namespace-fixture-release-safe" \
  > "${root}/fixture-sha256.txt"
record_fixture_copies > "${root}/fixture-copies.tsv"

started="$(date --utc '+%Y-%m-%d %H:%M:%S.%6N UTC')"
baseline=0
native "${zig}" build --build-file "${package}/namespace/build.zig" \
  --cache-dir "${root}/Debug/namespace-cache" --prefix "${root}/Debug/namespace-out" \
  "-Dworkspace=${root}/Debug/namespace-work" "${git_fixture[@]}" \
  "-Dfixture-executable=${installation}/namespace-fixture-debug" \
  "-Dci-report=${root}/Debug/baseline.json" \
  -Dtest-filter='namespace CI baseline crosses' -Doptimize=Debug -j2 test --summary all \
  > "${root}/baseline.log" 2>&1 || baseline=$?
finished="$(date --utc '+%Y-%m-%d %H:%M:%S.%6N UTC')"
if [ "${baseline}" -ne 0 ]; then
  tail -n 60 "${root}/baseline.log"
  # Diagnostic only: these bounded records never authorize a profile.
  sudo -n /usr/bin/journalctl -k --since "${started}" --until "${finished}" \
    --no-pager --output=cat --lines=256 |
    awk '
      /(^|[[:space:]])apparmor="DENIED"([[:space:]]|$)/ &&
      /(^|[[:space:]])comm="uk-prep-ns-test"([[:space:]]|$)/ &&
      /(^|[[:space:]])profile="unprivileged_userns"([[:space:]]|$)/ &&
      /(^|[[:space:]])operation="capable"([[:space:]]|$)/ {
        if (length($0) > 4096 || ++matched > 8) exit 1
        print
      }
    ' > "${root}/namespace-capability-diagnostics.log"
  # A supervised failure alone never authorizes a profile.
  jq -e -f "${package}/ci-baseline.jq" "${root}/Debug/baseline.json" > /dev/null
  test "$(/usr/sbin/sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
  sudo -n /usr/bin/journalctl -k --since "${started}" --until "${finished}" \
    --no-pager --output=cat --lines=256 |
    awk -f "${package}/ci-denial.awk" > "${root}/namespace-denial.log"
  test -s "${root}/namespace-denial.log"
  test -x "${parser}"
  # Refuse any existing profile before setting ownership flags for cleanup.
  collision=0
  sudo -n grep '^unikraft-hyperv-preparation-ci-' /sys/kernel/security/apparmor/profiles \
    > "${root}/profile-collision.txt" || collision=$?
  test "${collision}" -eq 1
  test ! -s "${root}/profile-collision.txt"
  sudo -n install -o root -g root -m 0600 "${package}/ci-debug.apparmor" "${installation}/profile-debug"
  sudo -n install -o root -g root -m 0600 "${package}/ci-release-safe.apparmor" "${installation}/profile-release-safe"
  profile_used=true
  debug_profile=true
  sudo -n "${parser}" --add "${installation}/profile-debug"
  release_profile=true
  sudo -n "${parser}" --add "${installation}/profile-release-safe"
  sudo -n grep --fixed-strings --line-regexp --quiet \
    'unikraft-hyperv-preparation-ci-debug (unconfined)' /sys/kernel/security/apparmor/profiles
  sudo -n grep --fixed-strings --line-regexp --quiet \
    'unikraft-hyperv-preparation-ci-release-safe (unconfined)' /sys/kernel/security/apparmor/profiles
  test "$(/usr/sbin/sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
fi

for mode in Debug ReleaseSafe; do
  variant=debug
  if [ "${mode}" = ReleaseSafe ]; then variant=release-safe; fi
  native "${zig}" build --build-file "${package}/build.zig" \
    --system "${root}/restore/zig-pkg" --cache-dir "${root}/${mode}/zig-local-cache" \
    --prefix "${root}/${mode}/out" "-Dproof-fixture=${GITHUB_WORKSPACE:?}" "${git_fixture[@]}" \
    "-Doptimize=${mode}" -j2 test install --summary all \
    > "${root}/${mode}/preparation.log" 2>&1
  native "${zig}" build --build-file "${package}/namespace/build.zig" \
    --cache-dir "${root}/${mode}/namespace-cache" --prefix "${root}/${mode}/namespace-out" \
    "-Dworkspace=${root}/${mode}/namespace-work" "${git_fixture[@]}" \
    "-Dfixture-executable=${installation}/namespace-fixture-${variant}" \
    "-Dci-report=${root}/${mode}/namespace-baseline.json" \
    "-Doptimize=${mode}" -j2 test install --summary all \
    > "${root}/${mode}/namespace.log" 2>&1
  native "${zig}" build --build-file "${package}/integration/build.zig" \
    --system "${root}/restore/zig-pkg" --cache-dir "${root}/${mode}/integration-cache" \
    --prefix "${root}/${mode}/integration-out" "-Doptimize=${mode}" -j2 test install --summary all \
    > "${root}/${mode}/integration.log" 2>&1
done
for variant in debug release-safe; do
  test "$(stat -c '%d:%i:%s:%u:%g:%a:%h' "${installation}/namespace-fixture-${variant}")" = "${fixture_identity[${variant}]}"
done
sha256sum --check "${root}/fixture-sha256.txt"
test "$(stat -c '%d:%i:%u:%a:%h:%s' "${facade}/build.lock")" = "${facade_identity}"
printf '%s\n' 'Synthetic preparation CI only; no full producer, staging-ledger or host/cloud admission.'
