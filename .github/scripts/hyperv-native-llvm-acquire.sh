#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
set -C
umask 077
export LC_ALL=C

if [[ $# != 1 || "$1" != /* || -z "${GH_TOKEN:-}" ]]; then
  echo "usage: hyperv-native-llvm-acquire.sh ABSOLUTE_DEST with GH_TOKEN" >&2
  exit 2
fi
destination="$1"
parent="$(dirname "${destination}")"
test "$(readlink -f "${parent}")" = "${parent}"
if [[ -e "${destination}" || -L "${destination}" ]]; then
  echo "Native LLVM acquisition refused: destination already exists." >&2
  exit 2
fi
evidence="${destination}.acquisition"
mkdir -m 700 -- "${evidence}"
spec=cataggar/llvm-project/llvm-tools-22.1.8-x86_64-linux.tar.xz@llvm-zig-22.1.8
printf -v lookup_error '%s%s' \
  'error: GitHub attestation lookup failed for ' \
  "'cataggar/llvm-project': UnexpectedHttpStatus"
for attempt in 1 2 3; do
  stage="${evidence}/attempt-${attempt}"
  mkdir -m 700 -- "${stage}"
  if timeout --kill-after=5 180 ghr download "${spec}" \
      --output "${stage}/llvm-tools-22.1.8-x86_64-linux.tar.xz" \
      --extract "${stage}/extracted" --strip-components 1 --keep-archive \
      > "${stage}/download.log" 2>&1; then
    cat -- "${stage}/download.log"
    for tool in llvm-readelf llvm-strip; do
      if [[ ! -x "${stage}/extracted/bin/${tool}" ]]; then
        echo "Native LLVM acquisition refused: missing verified ${tool}." >&2
        exit 1
      fi
    done
    chmod 700 -- "${stage}/extracted"
    mv --no-clobber -T -- "${stage}/extracted" "${destination}"
    if [[ -e "${stage}/extracted" ]]; then
      echo "Native LLVM acquisition refused: destination became occupied." >&2
      exit 2
    fi
    exit 0
  else
    status=$?
  fi
  printf 'Native LLVM acquisition attempt %d/3 failed (exit %d).\n' \
    "${attempt}" "${status}" >&2
  cat -- "${stage}/download.log" >&2
  # ghr 0.8.0 does not expose the lookup's HTTP status. Never retry a
  # cryptographic rejection or extraction failure as a lookup failure.
  if [[ "${status}" != 2 || "${attempt}" == 3 ]] ||
      ! grep -Fxq -- "${lookup_error}" "${stage}/download.log"; then
    exit "${status}"
  fi
  sleep "$((attempt * 5))"
done
