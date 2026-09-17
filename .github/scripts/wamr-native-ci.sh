#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "${GITHUB_JOB:-}" != wamr-native-compute || "$(id -u)" -eq 0 ]]; then
  echo "Native compute requires its ordinary-user local CI runner." >&2
  exit 2
fi
test "${QUALIFICATION_SOURCE_JOB:?}" = "${GITHUB_JOB}"
test "${QUALIFICATION_REPOSITORY_ID:?}" = "${GITHUB_REPOSITORY_ID:?}"
test "$(git rev-parse HEAD)" = "${GITHUB_SHA:?}"
test "$(uname -m)" = x86_64
test -r /dev/kvm
test -w /dev/kvm
# Reuse the credential-restricted runtime owner and the native leaf supervisors.
# The extra ceiling bounds parent-side package hashing/inspection as well.
exec timeout --signal=TERM --kill-after=10s 660s \
  python3 support/build/wamr-native-ci/run.py boot --runtime "$1"
