#!/usr/bin/env bash
set -euo pipefail
umask 077
refuse() {
  echo "Native compute driver refused: $1" >&2
  exit 2
}
if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "${GITHUB_JOB:-}" != wamr-native-compute || "$(id -u)" -eq 0 ]]; then
  refuse invocation
fi
[[ "${QUALIFICATION_SOURCE_JOB:?}" == "${GITHUB_JOB}" ]] ||
  refuse qualification-source
[[ "${QUALIFICATION_REPOSITORY_ID:?}" == "${GITHUB_REPOSITORY_ID:?}" ]] ||
  refuse repository-identity
revision="$(git rev-parse HEAD)" || refuse source-revision
[[ "${revision}" == "${GITHUB_SHA:?}" ]] || refuse source-revision
[[ "$(uname -m)" == x86_64 ]] || refuse architecture
[[ -r /dev/kvm ]] || refuse kvm-read
[[ -w /dev/kvm ]] || refuse kvm-write
# Reuse the credential-restricted runtime owner and the native leaf supervisors.
# The extra ceiling bounds parent-side package hashing/inspection as well.
exec timeout --signal=TERM --kill-after=10s 660s \
  python3 support/build/wamr-native-ci/run.py boot --runtime "$1"
