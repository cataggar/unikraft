#!/usr/bin/env bash
set -euo pipefail
umask 077
refuse() {
  echo "Native differential driver refused: $1" >&2
  exit 2
}
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
[[ -r /dev/kvm && -w /dev/kvm ]] || refuse kvm

source_root=/d/wamr-ci/wamr-differential-sources
comparison_root="/d/wamr-ci/wamr-differential-${2}"
controller=/d/wamr-ci/wamr-differential-controller/controller/bin/uk-wamr-native-ci
python_source="${source_root}/python"
native_source="${source_root}/native"
[[ ! -e "${source_root}" && ! -L "${source_root}" &&
   ! -e "${comparison_root}" && ! -L "${comparison_root}" ]] ||
  refuse prior-parity-output
[[ -x "${controller}" ]] || refuse native-controller-unavailable
mkdir -m 0700 -- "${source_root}" "${comparison_root}"
cleanup() {
  status=$?
  trap - EXIT
  for source in "${native_source}" "${python_source}"; do
    if test -d "${source}"; then
      git worktree remove --force -- "${source}" || status=1
    fi
  done
  rmdir -- "${source_root}" || status=1
  exit "${status}"
}
trap cleanup EXIT
git worktree add --detach "${python_source}" HEAD
git worktree add --detach "${native_source}" HEAD
mkdir -m 0700 -- "${python_source}/.d" "${native_source}/.d"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  support/build/wamr-native-ci/tests/test_differential_parity.py full \
  --case "$2" --root "${comparison_root}" \
  --python-repository "${python_source}" \
  --native-repository "${native_source}" \
  --runtime-template "$1" \
  --wamr-source "${PWD}/.d/wamr-source" \
  --controller "${controller}"
