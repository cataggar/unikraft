#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ] || [[ ! "$1" =~ ^[0-9a-f]{40}$ ]] ||
   [[ "$2" != /* ]] || [ ! -x "$2" ]; then
  echo 'Source check requires an expected commit and explicit native Git path' >&2
  exit 2
fi
expected="$1"
git="$2"
if ! source_sha="$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null "${git}" rev-parse HEAD)"; then
  echo 'Failed to read the local fixture source commit' >&2
  exit 1
fi
if ! source_status="$(GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  "${git}" -c core.fsmonitor=false status --porcelain)"; then
  echo 'Failed to establish local fixture source cleanliness' >&2
  exit 1
fi
if [ "${source_sha}" != "${expected}" ] || [ -n "${source_status}" ]; then
  echo 'Local fixture source is not clean at the expected commit' >&2
  exit 1
fi
printf '%s\n' "${source_sha}"
