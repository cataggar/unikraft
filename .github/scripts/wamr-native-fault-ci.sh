#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
umask 077
refuse() {
  echo "Native fault driver refused: $1" >&2
  exit 2
}
# Keep the required context's legacy job ID until a coordinated rename.
if [[ $# != 2 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "${GITHUB_JOB:-}" != wamr-differential-parity || "$(id -u)" -eq 0 ]]; then
  refuse invocation
fi
case "$2" in
  build-start-tamper|missing-build|occupied-boot-slot|prior-build-output) ;;
  *) refuse case ;;
esac
[[ "${QUALIFICATION_SOURCE_JOB:?}" == "${GITHUB_JOB}" ]] ||
  refuse qualification-source
[[ "${QUALIFICATION_REPOSITORY_ID:?}" == "${GITHUB_REPOSITORY_ID:?}" ]] ||
  refuse repository-identity
revision="$(git rev-parse HEAD)" || refuse source-revision
[[ "${revision}" == "${GITHUB_SHA:?}" ]] || refuse source-revision
[[ "$(uname -m)" == x86_64 ]] || refuse architecture
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || refuse kvm
controller="$1/controller/bin/uk-wamr-native-ci"
[[ -x "${controller}" ]] || refuse native-controller-unavailable
output="/d/wamr-ci/wamr-native-fault-$2"
[[ ! -e "${output}" && ! -L "${output}" ]] || refuse prior-fault-output
mkdir -m 0700 -- "${output}"
qualifier=support/build/wamr-native-ci/tests/native_fault_qualification.py
exec python3 -B "${qualifier}" \
  --case "$2" --runtime "$1" --output "${output}" \
  --wamr-source "${PWD}/.d/wamr-source" --controller "${controller}"
