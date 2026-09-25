#!/usr/bin/env bash
set -euo pipefail
umask 077
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT QEMU_MODULE_DIR
failure_stage=invocation
trap 'status=$?; echo "Native runtime wrapper refused: ${failure_stage}" >&2; exit "${status}"' ERR

if [[ ( $# != 1 && $# != 2 && $# != 3 && $# != 4 ) || "${1:-}" != /* ||
      "${GITHUB_ACTIONS:-}" != true || "$(id -u)" -eq 0 ]]; then
  echo "usage: hyperv-qemu-candidate-runtime.sh ROOT [compute | differential CASE | integration CI_ROOT NETWORK_APPLICATION] on an ordinary-user GitHub runner" >&2
  exit 2
fi
root="$(readlink -f "$1")"
if [[ $# == 2 ]]; then
  if [[ "$2" != compute || "${GITHUB_JOB:-}" != wamr-native-compute ]]; then
    echo "Invalid native compute driver selection." >&2
    exit 2
  fi
  driver="$(readlink -f .github/scripts/wamr-native-ci.sh)"
  driver_args=("${root}")
elif [[ $# == 3 ]]; then
  if [[ "$2" != differential || "${GITHUB_JOB:-}" != wamr-differential-parity ||
        ( "$3" != build-start-tamper && "$3" != missing-build &&
          "$3" != occupied-boot-slot && "$3" != prior-build-output ) ]]; then
    echo "Invalid differential driver selection." >&2
    exit 2
  fi
  driver="$(readlink -f .github/scripts/wamr-native-differential-ci.sh)"
  driver_args=("${root}" "$3")
elif [[ $# == 4 ]]; then
  if [[ "$2" != integration || "$3" != /* || ( "$4" != true && "$4" != false ) ]]; then
    echo "Invalid native integration driver selection." >&2
    exit 2
  fi
  driver="$(readlink -f .github/scripts/hyperv-native-public-ci.sh)"
  driver_args=("${root}" "$3" "$4")
else
  driver="$(readlink -f .github/scripts/hyperv-qemu-candidate-guest.sh)"
  driver_args=(boot "${root}" "${root}/bin/qemu-system-x86_64")
fi
source="${root}/runtime/libfdt.so.1"
expected=66c111808e61c7f6be6715b4b03d0fe75beb5bc5b3a8809608d58d99a6bc9828
kvm_identity=
runtime_started="$(date --iso-8601=seconds)"
test -f "${source}"
test ! -L "${source}"
test "$(sha256sum "${source}" | cut -d ' ' -f 1)" = "${expected}"
for directory in / /usr /usr/bin /usr/lib /usr/lib/x86_64-linux-gnu; do
  test -d "${directory}"
  test ! -L "${directory}"
  test "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:755
done

cleanup() {
  primary=$?
  trap - ERR EXIT HUP INT TERM
  cleanup_status=0
  if [[ -n "${kvm_identity}" ]]; then
    if [[ -c /dev/kvm && ! -L /dev/kvm ]] &&
       [[ "$(stat -c '%d:%i:%u:%g:%t:%T' /dev/kvm)" = "${kvm_identity}" ]]; then
      stat -c '%d:%i:%u:%g:%a:%t:%T' /dev/kvm > "${root}/evidence/kvm-before-cleanup.txt" \
        || cleanup_status=1
      getfacl --omit-header --no-effective --numeric /dev/kvm \
        > "${root}/evidence/kvm-before-cleanup.acl" || cleanup_status=1
      cmp "${root}/evidence/kvm-before.acl" "${root}/evidence/kvm-before-cleanup.acl" \
        || cleanup_status=1
    else
      echo "KVM device identity changed; no shared device state will be modified." >&2
      cleanup_status=1
    fi
    if [[ "${primary}" -ne 0 ]]; then
      journalctl --dmesg --no-pager --since "${runtime_started}" \
        --grep 'apparmor="DENIED".*(qemu|/dev/kvm)' --lines=20 \
        > "${root}/evidence/kvm-kernel-denials.txt" 2>&1 || {
          diagnostic=$?
          printf 'Kernel-denial query exited %s; retained its output.\n' "${diagnostic}" >&2
        }
    fi
  fi
  printf 'primary=%s cleanup=%s\n' "${primary}" "${cleanup_status}" \
    > "${root}/evidence/runtime-cleanup.txt" || cleanup_status=1
  if [[ "${primary}" -ne 0 ]]; then exit "${primary}"; fi
  exit "${cleanup_status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

failure_stage=kvm-device
test -c /dev/kvm
test ! -L /dev/kvm
test "$(stat -c %u /dev/kvm)" = 0
kvm_gid="$(stat -c %g /dev/kvm)"
test "${kvm_gid}" != 0
test "$(getent group kvm | cut -d : -f 3)" = "${kvm_gid}"
getfacl --omit-header --no-effective --numeric /dev/kvm > "${root}/evidence/kvm-before.acl"
kvm_identity="$(stat -c '%d:%i:%u:%g:%t:%T' /dev/kvm)"
grep -Eq '^group::rw-$' "${root}/evidence/kvm-before.acl"
if grep -Eq '^mask::' "${root}/evidence/kvm-before.acl"; then
  grep -Eq '^mask::rw-$' "${root}/evidence/kvm-before.acl"
fi
failure_stage=credentials
runner_uid="$(id -u)"
runner_gid="$(id -g)"
test "$(id -ru)" = "${runner_uid}"
test "$(id -rg)" = "${runner_gid}"
original_groups="$(awk '/^Groups:/ { for (i=2; i<=NF; i++) print $i }' "/proc/$$/status" | sort -nu)"
guest_groups="$(printf '%s\n%s\n' "${original_groups}" "${kvm_gid}" | awk 'NF' | sort -nu | tr '\n' ,)"
guest_groups="${guest_groups%,}"
id > "${root}/evidence/kvm-caller.txt"
printf 'uid=%s gid=%s supplementary=%s\n' "${runner_uid}" "${runner_gid}" "${guest_groups}" \
  > "${root}/evidence/guest-expected-credentials.txt"
for tool in /usr/bin/setpriv /usr/bin/env /usr/bin/bash; do
  test -f "${tool}"
  test ! -L "${tool}"
  test "$(stat -c '%u:%g:%a' "${tool}")" = 0:0:755
  test "$(od -An -N4 -tx1 "${tool}" | tr -d ' \n')" = 7f454c46
done
sha256sum /usr/bin/setpriv /usr/bin/env /usr/bin/bash /etc/group \
  > "${root}/evidence/credential-inputs.sha256"

failure_stage=libfdt
bash .github/scripts/hyperv-native-libfdt-prepare.sh "${root}"

failure_stage=qemu-probe
bash .github/scripts/hyperv-qemu-candidate.sh \
  "${root}/bin/qemu-system-x86_64" "${root}/bin/qemu-img" "${root}/evidence/managed-probe"
getfacl --omit-header --no-effective --numeric /dev/kvm > "${root}/evidence/kvm-before-boots.acl"
# Only this ordinary-user process tree receives the existing device group.
# No persistent membership, ACL, device mode or udev rule is changed.
failure_stage=guest-launch
sudo /usr/bin/setpriv --reuid="${runner_uid}" --regid="${runner_gid}" --groups="${guest_groups}" \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  /usr/bin/env -i "HOME=${HOME}" "PATH=${PATH}" LC_ALL=C \
  "GITHUB_ACTIONS=${GITHUB_ACTIONS}" "GITHUB_REPOSITORY=${GITHUB_REPOSITORY:?}" \
  "GITHUB_REPOSITORY_ID=${GITHUB_REPOSITORY_ID:?}" "GITHUB_WORKFLOW_REF=${GITHUB_WORKFLOW_REF:?}" \
  "GITHUB_JOB=${GITHUB_JOB:?}" "GITHUB_RUN_ID=${GITHUB_RUN_ID:?}" \
  "GITHUB_RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:?}" "GITHUB_SHA=${GITHUB_SHA:?}" \
  "QUALIFICATION_REPOSITORY_ID=${QUALIFICATION_REPOSITORY_ID:?}" \
  "QUALIFICATION_SOURCE_JOB=${QUALIFICATION_SOURCE_JOB:?}" \
  /usr/bin/bash --noprofile --norc -c '
    set -euo pipefail
    set -C
    umask 077
    refuse() {
      echo "Restricted native guest refused: $1" >&2
      exit 2
    }
    awk "/^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):/" \
      "/proc/$$/status" > "$4/evidence/guest-credentials.txt"
    awk -v uid="$1" -v gid="$2" "
      /^(Uid|Gid):/ {
        expected = (\$1 == \"Uid:\" ? uid : gid)
        if (NF != 5) exit 1
        for (i=2; i<=NF; i++) if (\$i != expected) exit 1
        identities++
      }
      /^Cap(Inh|Prm|Eff|Bnd|Amb):/ {
        if (NF != 2 || \$2 !~ /^0+$/) exit 1
        capabilities++
      }
      /^NoNewPrivs:/ { if (NF != 2 || \$2 != 1) exit 1; restricted++ }
      END { if (identities != 2 || capabilities != 5 || restricted != 1) exit 1 }
    " "$4/evidence/guest-credentials.txt" || refuse credentials
    actual_groups="$(awk "/^Groups:/ { for (i=2; i<=NF; i++) print \$i }" \
      "$4/evidence/guest-credentials.txt" | sort -nu | tr "\n" ,)"
    test "${actual_groups%,}" = "$3" || refuse groups
    test "$(stat -c "%d:%i:%u:%g:%t:%T" /dev/kvm)" = "$6" ||
      refuse kvm-identity
    test -r /dev/kvm || refuse kvm-read
    test -w /dev/kvm || refuse kvm-write
    driver="$5"
    shift 6
    exec /usr/bin/bash "$driver" "$@"
  ' _ "${runner_uid}" "${runner_gid}" "${guest_groups}" "${root}" \
  "${driver}" "${kvm_identity}" "${driver_args[@]}"
failure_stage=post-guest
id > "${root}/evidence/kvm-caller-after.txt"
cmp "${root}/evidence/kvm-caller.txt" "${root}/evidence/kvm-caller-after.txt"
sha256sum -c "${root}/evidence/managed-probe/executables.sha256" \
  "${root}/evidence/managed-probe/libraries.sha256" "${root}/evidence/qemu-data.sha256" \
  "${root}/evidence/credential-inputs.sha256" \
  > "${root}/evidence/runtime-after-boots.txt"
