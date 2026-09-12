#!/usr/bin/env bash
set -euo pipefail

package="$(dirname -- "${BASH_SOURCE[0]}")"

jq -nc '
  {
    schema: "hyperv_preparation_namespace_ci_baseline_v1",
    authority: "synthetic_only", process_cleanup_complete: true,
    helper_exit: 125, namespace_succeeded: false,
    namespace_error: "user_mapping_unavailable"
  } as $baseline |
  [
    {allowed: true, report: $baseline},
    {allowed: true, report: ($baseline | .namespace_error = "namespace_unavailable")},
    {allowed: true, report: ($baseline | .namespace_error = "mount_namespace_unavailable")},
    {allowed: false, report: ($baseline | .namespace_error = "other")},
    {allowed: false, report: ($baseline | .namespace_error = "user_namespace_unavailable")},
    {allowed: false, report: ($baseline | .namespace_error = "credentials")},
    {allowed: false, report: ($baseline | .namespace_error = "unavailable")},
    {allowed: false, report: ($baseline | del(.namespace_error))},
    {allowed: false, report: ($baseline | .authority = "production")},
    {allowed: false, report: ($baseline | .schema = "unknown")},
    {allowed: false, report: ($baseline | .helper_exit = 0)},
    {allowed: false, report: ($baseline | .helper_exit = 124)},
    {allowed: false, report: ($baseline | .namespace_succeeded = true)},
    {allowed: false, report: ($baseline | .process_cleanup_complete = false)},
    {allowed: false, report: ($baseline | del(.process_cleanup_complete))}
  ] | .[]
' | while IFS= read -r item; do
  expected="$(jq -r '.allowed' <<< "${item}")"
  result=0
  jq '.report' <<< "${item}" | jq -e -f "${package}/ci-baseline.jq" > /dev/null || result=$?
  if { [ "${expected}" = true ] && [ "${result}" -ne 0 ]; } ||
     { [ "${expected}" = false ] && [ "${result}" -ne 1 ]; }; then
    printf 'Unexpected baseline gate result %s for %s\n' "${result}" "${item}" >&2
    exit 1
  fi
done

denial='audit: type=1400 audit(1.0:1): apparmor="DENIED" operation="capable" class="cap" profile="unprivileged_userns" pid=1234 comm="uk-prep-ns-test" capability=21 capname="sys_admin"'
check_denial() {
  local expected="$1" result=0
  awk -f "${package}/ci-denial.awk" > /dev/null || result=$?
  if [ "${result}" -ne "${expected}" ]; then
    printf 'Unexpected kernel-denial gate result %s; expected %s\n' "${result}" "${expected}" >&2
    exit 1
  fi
}
printf '%s\n' "${denial}" | check_denial 0
for record in \
  "${denial/apparmor=\"DENIED\"/apparmor=\"ALLOWED\"}" \
  "${denial/operation=\"capable\"/operation=\"other\"}" \
  "${denial/profile=\"unprivileged_userns\"/profile=\"other\"}" \
  "${denial/comm=\"uk-prep-ns-test\"/comm=\"uk-prep-ns-test-extra\"}" \
  "${denial/capability=21/capability=7}" \
  "${denial/capname=\"sys_admin\"/capname=\"setuid\"}"; do
  printf '%s\n' "${record}" | check_denial 1
done
printf '' | check_denial 1
printf '%s%4096s\n' "${denial}" '' | check_denial 1
for ((i=0; i<8; i++)); do printf '%s\n' "${denial}"; done | check_denial 0
for ((i=0; i<9; i++)); do printf '%s\n' "${denial}"; done | check_denial 1
printf '%s\n' 'Preparation baseline and exact kernel-denial policy fixtures passed'
