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

umask 077
scratch="$(mktemp -d)"
trap 'rm -f -- "${scratch}/report" "${scratch}/fixture" "${scratch}/report-link" "${scratch}/fixture-link" "${scratch}/error.log"; rmdir -- "${scratch}"' EXIT
printf '%s\n' 'synthetic policy fixture' > "${scratch}/fixture"
chmod 500 "${scratch}/fixture"
fixture_hash="$(sha256sum -- "${scratch}/fixture")"
fixture_sha="${fixture_hash%% *}"
fixture_size="$(stat -c '%s' "${scratch}/fixture")"
check_strip_proof() {
  local expected="$1" result=0
  shift
  bash "${package}/ci-strip-proof.sh" "$@" > /dev/null 2> "${scratch}/error.log" || result=$?
  if [ "${result}" -ne "${expected}" ]; then
    printf 'Unexpected qualification proof result %s; expected %s\n' "${result}" "${expected}" >&2
    sed -n '1,12p' "${scratch}/error.log" >&2
    exit 1
  fi
}

# Schema fixtures do not represent native ELF equivalence evidence.
jq -nc --argjson uid "$(id -u)" --arg hash "${fixture_sha}" --argjson size "${fixture_size}" '
  {
    path: "/synthetic/candidate", sha256: $hash, size: $size,
    device_major: 0, device_minor: 1, inode: 1, uid: $uid, mode: 33261, links: 1,
    stable_identity_and_hash: true
  } as $file |
  {
    role: "namespace_fixture", candidate: $file,
    raw: ($file | .path = "/synthetic/raw" | .sha256 = ("0" * 64) | .size += 1),
    content: {
      program_headers_sha256: ("1" * 64), loaded_content_sha256: ("2" * 64),
      load_segments: 1, loaded_file_bytes: 1, removed_debug_sections: 1,
      removed_debug_bytes: 1, size_reduction: 1
    }
  } as $pair |
  {
    schema: "hyperv_fixture_debug_stripping_v1", authority: "synthetic_only_not_admitted",
    passed: true, synthetic: true, admitted: false, qualification_only: true,
    pairs: [($pair | .role = "namespace_helper"), $pair], external_fixture: null
  } as $proof |
  [
    {expected: 0, report: $proof},
    {expected: 1, report: ($proof | .schema = "unknown")},
    {expected: 1, report: ($proof | .authority = "production")},
    {expected: 1, report: ($proof | .passed = false)},
    {expected: 1, report: ($proof | .synthetic = false)},
    {expected: 1, report: ($proof | .admitted = true)},
    {expected: 1, report: ($proof | .qualification_only = false)},
    {expected: 1, report: ($proof | .external_fixture = {})},
    {expected: 1, report: ($proof | .unknown = true)},
    {expected: 1, report: ($proof | del(.passed))},
    {expected: 1, report: ($proof | .pairs = null)},
    {expected: 1, report: ($proof | .pairs = [])},
    {expected: 1, report: ($proof | .pairs |= reverse)},
    {expected: 1, report: ($proof | .pairs[1].role = "namespace_helper")},
    {expected: 1, report: ($proof | .pairs[0].candidate.uid += 1)},
    {expected: 1, report: ($proof | .pairs[0].raw.stable_identity_and_hash = false)},
    {expected: 1, report: ($proof | .pairs[0].raw.links = 0)},
    {expected: 1, report: ($proof | .pairs[0].raw.mode = 40960)},
    {expected: 1, report: ($proof | .pairs[0].raw.size = 0)},
    {expected: 1, report: ($proof | del(.pairs[0].raw.inode))},
    {expected: 1, report: ($proof | .pairs[0].candidate.sha256 = ("A" * 64))},
    {expected: 1, report: ($proof | .pairs[1].candidate.sha256 = ("f" * 64))},
    {expected: 1, report: ($proof | .pairs[1].candidate.size += 0.5)},
    {expected: 1, report: ($proof | .pairs[1].candidate.size += 1)},
    {expected: 1, report: ($proof | .pairs[0].raw = .pairs[0].candidate)},
    {expected: 1, report: ($proof | .pairs[0].content.load_segments = 0)},
    {expected: 1, report: ($proof | .pairs[0].content.removed_debug_sections = 0)},
    {expected: 1, report: ($proof | .pairs[0].content.removed_debug_bytes = 0)},
    {expected: 1, report: ($proof | .pairs[0].content.size_reduction = 2)},
    {expected: 1, report: ($proof | .pairs[0].content.loaded_content_sha256 = "")},
    {expected: 1, report: null},
    {expected: 1, report: []},
    {expected: 0, report: $proof}
  ] | .[]
' | while IFS= read -r item; do
  expected="$(jq -r '.expected' <<< "${item}")"
  jq '.report' <<< "${item}" > "${scratch}/report"
  check_strip_proof "${expected}" "${scratch}/report" "${scratch}/fixture"
done
check_strip_proof 2
check_strip_proof 1 "${scratch}/missing" "${scratch}/fixture"
valid_proof="$(jq -c . "${scratch}/report")"
printf 'null\n%s\n' "${valid_proof}" > "${scratch}/report"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
printf '%s' "${valid_proof}" > "${scratch}/report"
printf '%*s' "$((32768 - ${#valid_proof}))" '' >> "${scratch}/report"
check_strip_proof 0 "${scratch}/report" "${scratch}/fixture"
printf ' ' >> "${scratch}/report"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
printf '%s\n' "${valid_proof}" > "${scratch}/report"
chmod 640 "${scratch}/report"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
chmod 600 "${scratch}/report"
ln "${scratch}/report" "${scratch}/report-link"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
rm -- "${scratch}/report-link"
ln -s report "${scratch}/report-link"
check_strip_proof 1 "${scratch}/report-link" "${scratch}/fixture"
ln -s fixture "${scratch}/fixture-link"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture-link"
check_strip_proof 1 "${scratch}/report" "${scratch}/missing"
chmod 600 "${scratch}/fixture"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
chmod 700 "${scratch}/fixture"
printf '%s\n' changed >> "${scratch}/fixture"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
printf '' > "${scratch}/report"
check_strip_proof 1 "${scratch}/report" "${scratch}/fixture"
printf '%s\n' 'Preparation baseline, exact kernel-denial and qualification-proof policy fixtures passed'
