#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
set -C
umask 077
export LC_ALL=C

if [[ $# != 1 || "$1" != /* ]]; then
  echo "usage: hyperv-native-zig-restore.sh ABSOLUTE_NEW_ROOT" >&2
  exit 2
fi
root="$1"
parent="$(dirname "${root}")"
test "$(readlink -f "${parent}")" = "${parent}"
if [[ -e "${root}" || -L "${root}" ]]; then
  echo "Native Zig restoration refused: root already exists." >&2
  exit 2
fi
repository="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/../..")"
mkdir -m 700 -- "${root}"
cp -- "${repository}/support/tools/hyperv/local_boot/build.zig" \
  "${repository}/support/tools/hyperv/local_boot/build.zig.zon" "${root}/"
closing_error='(^|: )error: invalid HTTP response: HttpConnectionClosing$'
for attempt in 1 2 3; do
  stage="${root}/attempt-${attempt}"
  mkdir -m 700 -- "${stage}"
  mkdir -m 700 -- "${stage}/global" "${stage}/global/tmp"
  cp -- "${root}/build.zig" "${root}/build.zig.zon" "${stage}/"
  if timeout --kill-after=5 180 zig build \
      --build-file "${stage}/build.zig" --fetch=all -j2 \
      --cache-dir "${stage}/cache" --global-cache-dir "${stage}/global" \
      > "${stage}/fetch.log" 2>&1; then
    cat -- "${stage}/fetch.log"
    if [[ ! -d "${stage}/zig-pkg" || -L "${stage}/zig-pkg" ]]; then
      echo "Native Zig restoration refused: missing verified packages." >&2
      exit 1
    fi
    mv --no-clobber -T -- "${stage}/zig-pkg" "${root}/zig-pkg"
    if [[ -e "${stage}/zig-pkg" ]]; then
      echo "Native Zig restoration refused: package destination occupied." >&2
      exit 2
    fi
    exit 0
  else
    status=$?
  fi
  printf 'Native Zig restoration attempt %d/3 failed (exit %d).\n' \
    "${attempt}" "${status}" >&2
  cat -- "${stage}/fetch.log" >&2
  if [[ "${status}" != 1 || "${attempt}" == 3 ]] ||
      ! grep -Eq -- "${closing_error}" "${stage}/fetch.log" ||
      grep -E '(^|: )error:' "${stage}/fetch.log" |
        grep -Ev -- "${closing_error}" \
          > "${stage}/nontransport-errors.log"; then
    exit "${status}"
  fi
  sleep "$((attempt * 5))"
done
