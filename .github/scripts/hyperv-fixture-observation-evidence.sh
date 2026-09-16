#!/usr/bin/env bash
# Copy only bounded, fixed-name diagnostic outputs; never parse them as status.
set -euo pipefail
umask 077
trap 'status=$?; printf "%s\n" "Fixture observation retention refused" >&2; exit "$status"' ERR
if [ "$#" -ne 1 ]; then exit 2; fi
case "$1" in
  persistence) log_limit=67108864 ;;
  host) log_limit=8388608 ;;
  *) exit 2 ;;
esac
root="${RUNNER_TEMP:?}/hyperv-ci/native-$1"
if [ ! -e "${root}" ] && [ ! -L "${root}" ]; then exit 0; fi
test -d "${root}"
test ! -L "${root}"
test "$(stat -c '%a' "${root}")" = 700
destination="${root}/observation-evidence"
mkdir -m 0700 "${destination}"
set -C

copy_bounded() {
  local source="$1" target="$2" limit="$3" size
  if [ ! -e "${source}" ] && [ ! -L "${source}" ]; then return; fi
  test -f "${source}"
  test ! -L "${source}"
  test "$(stat -c '%h' "${source}")" -eq 1
  test "$(stat -c '%u' "${source}")" -eq "$(id -u)"
  test "$(stat -c '%a' "${source}")" = 600
  size="$(stat -c '%s' "${source}")"
  test "${size}" -le "${limit}"
  head -c "$((limit + 1))" -- "${source}" > "${destination}/${target}"
  if [ "$(stat -c '%s' "${destination}/${target}")" -ne "${size}" ] ||
     [ "$(stat -c '%s' "${source}")" -ne "${size}" ]; then
    rm -- "${destination}/${target}"
    printf '%s\n' 'Fixture observation retention refused changed bytes' >&2
    return 1
  fi
}

for mode in Debug ReleaseSafe; do
  if [ ! -e "${root}/${mode}" ] && [ ! -L "${root}/${mode}" ]; then continue; fi
  test -d "${root}/${mode}"
  test ! -L "${root}/${mode}"
  test "$(stat -c '%a' "${root}/${mode}")" = 700
  copy_bounded "${root}/${mode}/fixtures.log" "${mode}-fixtures.log" "${log_limit}"
  if [ "$1" = host ]; then
    if [ ! -e "${root}/${mode}/fixtures" ] && [ ! -L "${root}/${mode}/fixtures" ]; then continue; fi
    test -d "${root}/${mode}/fixtures"
    test ! -L "${root}/${mode}/fixtures"
    test "$(stat -c '%a' "${root}/${mode}/fixtures")" = 700
    for fixture in hard_deadline success setup_refusal expired launch_failure observer_refusal; do
      name="synthetic-host-timing-${fixture}-v1.jsonl"
      copy_bounded "${root}/${mode}/fixtures/${name}" "${mode}-${name}" 11264
    done
  fi
done
