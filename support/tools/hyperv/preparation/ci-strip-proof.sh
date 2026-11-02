#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo 'Usage: ci-strip-proof.sh REPORT FIXTURE [LAYOUT_POLICY]' >&2
  exit 2
fi
report="$1"
fixture="$2"
layout_policy="${3:-identical_program_headers}"
case "${layout_policy}" in
  identical_program_headers|file_offset_relayout) ;;
  *)
    echo 'Unknown qualification layout policy' >&2
    exit 2
    ;;
esac
uid="$(id -u)"
package="$(dirname -- "${BASH_SOURCE[0]}")"
if [ -L "${report}" ] || [ ! -f "${report}" ] ||
   [ "$(stat -c '%u:%a:%h' "${report}")" != "${uid}:600:1" ]; then
  echo 'Qualification proof must be a private single-link regular file' >&2
  exit 1
fi
report_size="$(stat -c '%s' "${report}")"
if [ "${report_size}" -eq 0 ] || [ "${report_size}" -gt 32768 ]; then
  echo 'Qualification proof exceeds its nonempty 32768-byte bound' >&2
  exit 1
fi
if [ -L "${fixture}" ] || [ ! -f "${fixture}" ] || [ ! -x "${fixture}" ]; then
  echo 'Qualification fixture must be a regular executable, not a symlink' >&2
  exit 1
fi
report_identity="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${report}")"
fixture_identity="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${fixture}")"
fixture_size="$(stat -c '%s' "${fixture}")"
if [ "${fixture_size}" -eq 0 ] || [ "${fixture_size}" -gt 67108864 ]; then
  echo 'Qualification fixture exceeds its nonempty 64-MiB bound' >&2
  exit 1
fi
report_hash="$(sha256sum -- "${report}")"
fixture_hash="$(sha256sum -- "${fixture}")"
if ! jq -se --argjson uid "${uid}" --arg layout_policy "${layout_policy}" \
  --arg fixture_sha "${fixture_hash%% *}" --argjson fixture_size "${fixture_size}" \
  -f "${package}/ci-strip-proof.jq" "${report}" > /dev/null; then
  echo 'Qualification proof is invalid or does not bind the selected fixture' >&2
  exit 1
fi
if [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${report}")" != "${report_identity}" ] ||
   [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${fixture}")" != "${fixture_identity}" ] ||
   [ "$(sha256sum -- "${report}")" != "${report_hash}" ] ||
   [ "$(sha256sum -- "${fixture}")" != "${fixture_hash}" ]; then
  echo 'Qualification proof or fixture changed during verification' >&2
  exit 1
fi
