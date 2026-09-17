#!/usr/bin/env bash
# Run only the already-built private collector after the original fixture step.
set -euo pipefail
umask 077
trap 'status=$?; printf "%s\n" "Persistence build evidence retention refused" >&2; exit "$status"' ERR
test "$#" -eq 0
root="${RUNNER_TEMP:?}/hyperv-ci/native-persistence"
if [ ! -e "${root}" ] && [ ! -L "${root}" ]; then
  printf '%s\n' 'persistence_build_evidence: not_started'
  exit 0
fi

private_directory() {
  test -d "$1"
  test ! -L "$1"
  test "$(stat -c '%u' "$1")" -eq "$(id -u)"
  test "$(stat -c '%a' "$1")" = 700
}

private_file() {
  test -f "$1"
  test ! -L "$1"
  test "$(stat -c '%h' "$1")" -eq 1
  test "$(stat -c '%u' "$1")" -eq "$(id -u)"
  test "$(stat -c '%a' "$1")" = "$2"
  test "$(stat -c '%s' "$1")" -le "$3"
}

private_directory "${root}"
for mode in Debug ReleaseSafe; do
  work="${root}/${mode}"
  if [ ! -e "${work}" ] && [ ! -L "${work}" ]; then
    printf 'persistence_build_evidence: %s_not_started\n' "${mode}"
    continue
  fi
  private_directory "${work}"
  capture="${work}/build-evidence"
  if [ ! -e "${capture}" ] && [ ! -L "${capture}" ]; then
    if [ -e "${work}/fixtures.log" ] || [ -L "${work}/fixtures.log" ]; then
      private_file "${work}/fixtures.log" 600 67108864
      private_file "${work}/fixture-build-exit.txt" 600 4
      IFS= read -r status < "${work}/fixture-build-exit.txt"
      [[ "${status}" =~ ^[1-9][0-9]{0,2}$ ]]
      # read stops at LF and skips NULs; account for every input byte.
      test "$(stat -c '%s' "${work}/fixture-build-exit.txt")" -eq "$((${#status} + 1))"
      test "${status}" -le 255
      printf 'persistence_build_evidence: %s_build_failed_before_baseline\n' "${mode}"
    else
      test ! -e "${work}/fixture-build-exit.txt"
      test ! -L "${work}/fixture-build-exit.txt"
      printf 'persistence_build_evidence: %s_not_started\n' "${mode}"
    fi
    continue
  fi
  private_directory "${capture}"
  private_file "${capture}/collector" 700 100663296
  test -s "${capture}/collector"
  "${capture}/collector" collect "${capture}"
done
