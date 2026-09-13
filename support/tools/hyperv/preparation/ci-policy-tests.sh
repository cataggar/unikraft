#!/usr/bin/env bash
set -euo pipefail

package="$(dirname -- "${BASH_SOURCE[0]}")"

jq -nc '
  {
    schema:"unikraft_fixture_vm_v1",authority:"disposable_test_only_not_admitted",
    vm_uuid:"12345678-1234-4234-8234-123456789abc",nonce:("a"*32),
    test_user:"uktest",uid:1001,gid:1001,source_root:"/work/unikraft",
    test_root:"/work/hyperv-ci/native-preparation",python_guard:true,
    image_sha256:"612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354",
    kernel_sha256:"0066409132868538bc0c9076f60131025775d5bbd8617df074d059f91b584918",
    initrd_sha256:"e7732308dee547d2455f6203b664d4ff47da050227fd6f2ad6a331dbff4ec0d2"
  } as $marker |
  [
    {allowed:true,marker:$marker},
    {allowed:false,marker:($marker | .schema="unknown")},
    {allowed:false,marker:($marker | .authority="production")},
    {allowed:false,marker:($marker | .vm_uuid="not-a-uuid")},
    {allowed:false,marker:($marker | .nonce="unknown")},
    {allowed:false,marker:($marker | .uid=0)},
    {allowed:false,marker:($marker | .gid=0)},
    {allowed:false,marker:($marker | .test_user="root")},
    {allowed:false,marker:($marker | .source_root="/d/unikraft")},
    {allowed:false,marker:($marker | .test_root="/tmp")},
    {allowed:false,marker:($marker | .python_guard=false)},
    {allowed:false,marker:($marker | del(.python_guard))},
    {allowed:false,marker:($marker | .image_sha256="unknown")},
    {allowed:false,marker:($marker | .kernel_sha256="unknown")},
    {allowed:false,marker:($marker | .initrd_sha256="unknown")},
    {allowed:false,marker:($marker | .extra=true)},
    {allowed:false,marker:[]},
    {allowed:false,marker:null}
  ] | .[]
' | while IFS= read -r item; do
  expected="$(jq -r '.allowed' <<< "${item}")"
  result=0
  jq '.marker' <<< "${item}" | jq -se -f "${package}/ci-vm-marker.jq" > /dev/null || result=$?
  if { [ "${expected}" = true ] && [ "${result}" -ne 0 ]; } ||
     { [ "${expected}" = false ] && [ "${result}" -ne 1 ]; }; then
    printf 'Unexpected VM marker result %s for %s\n' "${result}" "${item}" >&2
    exit 1
  fi
done
result=0
GITHUB_ACTIONS=true bash "${package}/ci-vm-context.sh" raw > /dev/null 2>&1 || result=$?
if [ "${result}" -ne 1 ]; then
  echo 'VM context guard accepted a GitHub invocation' >&2
  exit 1
fi

check_apparmor_feature() {
  local expected="$1" result=0
  awk -f "${package}/ci-apparmor-feature.awk" > /dev/null || result=$?
  if [ "${result}" -ne "${expected}" ]; then
    printf 'Unexpected AppArmor feature result %s; expected %s\n' "${result}" "${expected}" >&2
    exit 1
  fi
}
printf '%s\n' yes | check_apparmor_feature 0
printf '' | check_apparmor_feature 1
for value in '' 1 0 no true YES ' yes' 'yes ' $'yes\r'; do
  printf '%s\n' "${value}" | check_apparmor_feature 1
done
printf '%s\n' yes yes | check_apparmor_feature 1
printf '%s\n' yes '' | check_apparmor_feature 1
printf '%s\n' yes no | check_apparmor_feature 1
result=0
(printf '%s\n' yes; exit 1) |
  awk -f "${package}/ci-apparmor-feature.awk" > /dev/null || result=$?
if [ "${result}" -ne 1 ]; then
  echo 'AppArmor feature pipeline accepted a failed read' >&2
  exit 1
fi

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

check_objcopy_version() {
  local expected="$1" result=0
  awk -f "${package}/ci-objcopy-version.awk" > /dev/null || result=$?
  if [ "${result}" -ne "${expected}" ]; then
    printf 'Unexpected objcopy version result %s; expected %s\n' "${result}" "${expected}" >&2
    exit 1
  fi
}
for line in 'LLVM version 22.1.8' '  LLVM version 22.1.8' $'\tLLVM version 22.1.8'; do
  printf '%s\n' 'llvm-objcopy, compatible with GNU objcopy' 'LLVM (http://llvm.org/):' \
    "${line}" '  Optimized build.' | check_objcopy_version 0
done
for line in 'LLVM version 22.1.7' 'LLVM version 22.1.80' 'LLVM version 22.1.8git' \
  'LLVM version 22x1x8' 'prefix LLVM version 22.1.8' 'LLVM version 22.1.8 '; do
  printf '%s\n' "${line}" | check_objcopy_version 1
done
printf '' | check_objcopy_version 1
printf '%s\n' 'LLVM version 22.1.8' 'LLVM version 22.1.8' | check_objcopy_version 1
printf '%s\n' 'LLVM version 22.1.8' 'LLVM version 22.1.7' | check_objcopy_version 1

umask 077
scratch="$(mktemp -d)"
trap 'rm -f -- "${scratch}/report" "${scratch}/fixture" "${scratch}/report-link" "${scratch}/fixture-link" "${scratch}/git-stub" "${scratch}/error.log"; rmdir -- "${scratch}"' EXIT
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -eu' \
  'case "$1" in' \
  '  rev-parse)' \
  '    if [ "${SOURCE_CHECK_MODE}" = bad-head ]; then exit 23; fi' \
  '    printf "%s\n" 1111111111111111111111111111111111111111 ;;' \
  '  -c)' \
  '    test "$2" = core.fsmonitor=false && test "$3" = status && test "$4" = --porcelain' \
  '    case "${SOURCE_CHECK_MODE}" in' \
  '      bad-status) exit 42 ;;' \
  '      dirty) printf "%s\n" " M changed-file" ;;' \
  '      clean) ;;' \
  '      *) exit 24 ;;' \
  '    esac ;;' \
  '  *) exit 25 ;;' \
  'esac' > "${scratch}/git-stub"
chmod 0500 "${scratch}/git-stub"
for source_mode in clean bad-head bad-status dirty; do
  expected=1
  if [ "${source_mode}" = clean ]; then expected=0; fi
  result=0
  SOURCE_CHECK_MODE="${source_mode}" bash "${package}/ci-source-context.sh" \
    1111111111111111111111111111111111111111 "${scratch}/git-stub" \
    > /dev/null 2> "${scratch}/error.log" || result=$?
  if [ "${result}" -ne "${expected}" ]; then
    printf 'Unexpected source-query result %s for %s\n' "${result}" "${source_mode}" >&2
    exit 1
  fi
done
result=0
SOURCE_CHECK_MODE=clean bash "${package}/ci-source-context.sh" \
  2222222222222222222222222222222222222222 "${scratch}/git-stub" \
  > /dev/null 2> "${scratch}/error.log" || result=$?
if [ "${result}" -ne 1 ]; then
  echo 'Source check accepted a different commit' >&2
  exit 1
fi
printf '%s\n' 'synthetic policy fixture' > "${scratch}/fixture"
printf '%8192s' '' >> "${scratch}/fixture"
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
      elf_class: "elf64", endian: "little", machine: "X86_64",
      layout_policy: "identical_program_headers", load_offset_modulus: 4096,
      raw_program_headers_sha256: ("1" * 64),
      candidate_program_headers_sha256: ("1" * 64),
      normalized_program_headers_sha256: ("1" * 64),
      mapped_program_content_sha256: ("2" * 64),
      mapped_loaded_content_sha256: ("3" * 64),
      program_mappings: [{
        index: 0, raw_offset: 0, candidate_offset: 0, changed: false,
        offset_field_file_offset: 72, offset_field_width: 8,
        logical_mapping: {
          type: 1, flags: 4, virtual_address: 4096, physical_address: 4096,
          file_bytes: 1, memory_bytes: 1, alignment: 4096
        },
        logical_mapping_sha256: ("4" * 64)
      }],
      load_segments: 1, loaded_file_bytes: 1, removed_debug_sections: 1,
      removed_debug_bytes: 1, size_reduction: 1
    }
  } as $pair |
  {
    schema: "hyperv_fixture_debug_stripping_v2", authority: "synthetic_only_not_admitted",
    passed: true, synthetic: true, admitted: false, qualification_only: true,
    layout_policy: "identical_program_headers",
    pairs: [($pair | .role = "namespace_helper"), $pair], external_fixture: null
  } as $proof |
  ($proof | .layout_policy = "file_offset_relayout" |
    .pairs[].content.layout_policy = "file_offset_relayout") as $relayout |
  ($relayout | .pairs[].content |= (
    .candidate_program_headers_sha256 = ("5" * 64) |
    .program_mappings[0].candidate_offset = 4096 |
    .program_mappings[0].changed = true)) as $moved |
  [
    {expected: 0, report: $proof},
    {expected: 0, policy: "file_offset_relayout", report: $relayout},
    {expected: 0, policy: "file_offset_relayout", report: $moved},
    {expected: 1, report: $relayout},
    {expected: 1, policy: "file_offset_relayout", report: $proof},
    {expected: 1, report: ($proof | .schema = "hyperv_fixture_debug_stripping_v1")},
    {expected: 1, report: ($proof | .schema = "unknown")},
    {expected: 1, report: ($proof | .authority = "production")},
    {expected: 1, report: ($proof | .passed = false)},
    {expected: 1, report: ($proof | .synthetic = false)},
    {expected: 1, report: ($proof | .admitted = true)},
    {expected: 1, report: ($proof | .qualification_only = false)},
    {expected: 1, report: ($proof | .external_fixture = {})},
    {expected: 1, report: ($proof | .unknown = true)},
    {expected: 1, report: ($proof | del(.passed))},
    {expected: 1, report: ($proof | .layout_policy = "unknown")},
    {expected: 1, report: ($proof | .pairs[0].content.layout_policy = "file_offset_relayout")},
    {expected: 1, report: ($proof | .pairs[0].content.program_mappings = [])},
    {expected: 1, report: ($proof | .pairs[0].content.program_mappings = null)},
    {expected: 1, report: ($proof |
      .pairs[0].content.program_mappings |= (.[0] as $mapping | [range(129) | $mapping]))},
    {expected: 1, report: ($proof | .pairs[0].content.program_mappings[0].index = 1)},
    {expected: 1, report: ($proof | .pairs[0].content.program_mappings[0].offset_field_width = 4)},
    {expected: 1, report: ($proof | .pairs[0].content.program_mappings[0].changed = true)},
    {expected: 1, report: ($proof | .pairs[0].content.program_mappings[0].logical_mapping.flags = null)},
    {expected: 1, report: ($proof | .pairs[0].content.candidate_program_headers_sha256 = ("5" * 64))},
    {expected: 1, report: ($proof | .pairs[0].content.normalized_program_headers_sha256 = "")},
    {expected: 1, report: ($proof | .pairs[0].content.load_offset_modulus = 8192)},
    {expected: 1, policy: "file_offset_relayout",
      report: ($moved | .pairs[0].content.program_mappings[0].candidate_offset = 999999)},
    {expected: 1, policy: "file_offset_relayout",
      report: ($moved | .pairs[0].content.program_mappings[0].logical_mapping.file_bytes = 0)},
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
    {expected: 1, report: ($proof | .pairs[0].content.mapped_loaded_content_sha256 = "")},
    {expected: 1, report: null},
    {expected: 1, report: []},
    {expected: 0, report: $proof}
  ] | .[]
' | while IFS= read -r item; do
  expected="$(jq -r '.expected' <<< "${item}")"
  policy="$(jq -r '.policy // "identical_program_headers"' <<< "${item}")"
  jq '.report' <<< "${item}" > "${scratch}/report"
  check_strip_proof "${expected}" "${scratch}/report" "${scratch}/fixture" "${policy}"
done
check_strip_proof 2
check_strip_proof 2 "${scratch}/report" "${scratch}/fixture" unknown
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
