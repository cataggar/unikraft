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
controller=/d/wamr-ci/wamr-native-runtime/controller/bin/uk-wamr-native-ci
[[ -x "${controller}" ]] || refuse native-controller-unavailable
exec "${controller}" boot --runtime "$1"
