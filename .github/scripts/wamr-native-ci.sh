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
# The job deadline bounds orchestration; every trusted leaf command has its own
# absolute primary and cleanup deadlines in the native supervisor.
python3 support/build/wamr-native-ci/run.py boot --runtime "$1"

source_root=/d/wamr-ci/wamr-differential-sources
comparison_root=/d/wamr-ci/wamr-differential
controller=/d/wamr-ci/wamr-differential-controller/controller/bin/uk-wamr-native-ci
python_source="${source_root}/python"
native_source="${source_root}/native"
shopt -s nullglob dotglob
for output in "${source_root}" "${comparison_root}"; do
  [[ -d "${output}" && ! -L "${output}" ]] || refuse prior-parity-output
  [[ "$(stat -c '%u:%g:%a' "${output}")" == "$(id -u):$(id -g):700" ]] ||
    refuse prior-parity-output
  entries=("${output}"/*)
  (( ${#entries[@]} == 0 )) || refuse prior-parity-output
done
[[ -x "${controller}" ]] || refuse native-controller-unavailable
cleanup() {
  status=$?
  trap - EXIT
  for source in "${native_source}" "${python_source}"; do
    if test -d "${source}"; then
      git worktree remove --force -- "${source}" || status=1
    fi
  done
  entries=("${source_root}"/*)
  if (( ${#entries[@]} != 0 )); then status=1; fi
  exit "${status}"
}
trap cleanup EXIT
git worktree add --detach "${python_source}" HEAD
git worktree add --detach "${native_source}" HEAD
mkdir -m 0700 -- "${python_source}/.d" "${native_source}/.d"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  support/build/wamr-native-ci/tests/test_differential_parity.py full \
  --case success --root "${comparison_root}" \
  --python-repository "${python_source}" \
  --native-repository "${native_source}" \
  --runtime-template "$1" \
  --wamr-source "${PWD}/.d/wamr-source" \
  --controller "${controller}"
