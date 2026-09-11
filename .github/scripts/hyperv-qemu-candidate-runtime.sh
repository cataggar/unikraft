#!/usr/bin/env bash
set -euo pipefail
umask 077
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT QEMU_MODULE_DIR

if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true || "$(id -u)" -eq 0 ]]; then
  echo "The managed candidate runtime requires an ordinary-user GitHub runner and an absolute root." >&2
  exit 2
fi
root="$(readlink -f "$1")"
source="${root}/runtime/libfdt.so.1"
target=/usr/lib/x86_64-linux-gnu/libfdt.so.1
ownership="${root}/evidence/runtime-created.txt"
expected=66c111808e61c7f6be6715b4b03d0fe75beb5bc5b3a8809608d58d99a6bc9828
kvm_changed=false
kvm_identity=
runtime_started="$(date --iso-8601=seconds)"
test -f "${source}"
test ! -L "${source}"
test "$(sha256sum "${source}" | cut -d ' ' -f 1)" = "${expected}"
for directory in / /usr /usr/lib /usr/lib/x86_64-linux-gnu; do
  test -d "${directory}"
  test ! -L "${directory}"
  test "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:755
done

cleanup() {
  primary=$?
  trap - EXIT HUP INT TERM
  cleanup_status=0
  if [[ "${kvm_changed}" = true ]]; then
    if [[ -c /dev/kvm && ! -L /dev/kvm ]] &&
       [[ "$(stat -c '%d:%i:%u:%g:%t:%T' /dev/kvm)" = "${kvm_identity}" ]]; then
      stat -c '%d:%i:%u:%g:%a:%t:%T' /dev/kvm > "${root}/evidence/kvm-before-cleanup.txt" \
        || cleanup_status=1
      getfacl --omit-header --no-effective --numeric /dev/kvm \
        > "${root}/evidence/kvm-before-cleanup.acl" || cleanup_status=1
      sudo setfacl --set-file="${root}/evidence/kvm-before.acl" -- /dev/kvm \
        || cleanup_status=$?
      getfacl --omit-header --no-effective /dev/kvm > "${root}/evidence/kvm-after.acl" \
        || cleanup_status=1
      cmp "${root}/evidence/kvm-before.acl" "${root}/evidence/kvm-after.acl" \
        || cleanup_status=1
    else
      echo "KVM device identity changed; refusing unrelated ACL cleanup." >&2
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
  if [[ -f "${ownership}" ]]; then
    identity="$(< "${ownership}")"
    if [[ -f "${target}" && ! -L "${target}" ]] &&
       [[ "$(stat -c '%d:%i:%u:%g' "${target}")" = "${identity}" ]] &&
       [[ "$(stat -c %h "${target}")" = 1 ]]; then
      sudo rm -- "${target}" || cleanup_status=$?
      if [[ -e "${target}" || -L "${target}" ]]; then cleanup_status=1; fi
    else
      echo "Managed runtime identity changed; refusing unrelated cleanup." >&2
      cleanup_status=1
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

test -c /dev/kvm
test ! -L /dev/kvm
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  command -v getfacl setfacl > "${root}/evidence/acl-tools.txt"
  kvm_identity="$(stat -c '%d:%i:%u:%g:%t:%T' /dev/kvm)"
  getfacl --omit-header --no-effective /dev/kvm > "${root}/evidence/kvm-before.acl"
  if grep -Eq '^mask::' "${root}/evidence/kvm-before.acl"; then
    grep -Eq '^mask::rw[-x]$' "${root}/evidence/kvm-before.acl"
  else
    grep -Eq '^group::rw[-x]$' "${root}/evidence/kvm-before.acl"
  fi
  kvm_changed=true
  sudo setfacl --modify="u:$(id -u):rw" -- /dev/kvm
fi
test -r /dev/kvm
test -w /dev/kvm
getfacl --omit-header --no-effective --numeric /dev/kvm > "${root}/evidence/kvm-granted.acl"
id > "${root}/evidence/kvm-caller.txt"

if [[ -e "${target}" || -L "${target}" ]]; then
  test -f "${target}"
  test ! -L "${target}"
  test "$(stat -c '%u:%g:%h' "${target}")" = 0:0:1
  [[ "$(stat -c %a "${target}")" = 444 || "$(stat -c %a "${target}")" = 644 ]]
  test "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}"
else
  # Root opens the exact new file exclusively; record its identity before writing.
  sudo bash -c '
    set -euo pipefail
    set -C
    umask 077
    exec 8> "$2"
    chmod 644 "$2"
    exec 9> /usr/lib/x86_64-linux-gnu/libfdt.so.1
    stat -Lc "%d:%i:%u:%g" /proc/self/fd/9 >&8
    cat -- "$1" >&9
    chmod 444 /usr/lib/x86_64-linux-gnu/libfdt.so.1
    sync -f /usr/lib/x86_64-linux-gnu/libfdt.so.1
  ' _ "${source}" "${ownership}"
fi
test "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}"
stat -c '%d:%i:%u:%g:%a:%h:%s' "${target}" > "${root}/evidence/managed-libfdt.txt"

bash .github/scripts/hyperv-qemu-candidate.sh \
  "${root}/bin/qemu-system-x86_64" "${root}/bin/qemu-img" "${root}/evidence/managed-probe"
getfacl --omit-header --no-effective --numeric /dev/kvm > "${root}/evidence/kvm-before-boots.acl"
bash .github/scripts/hyperv-qemu-candidate-guest.sh boot "${root}" "${root}/bin/qemu-system-x86_64"
sha256sum -c "${root}/evidence/managed-probe/executables.sha256" \
  "${root}/evidence/managed-probe/libraries.sha256" "${root}/evidence/qemu-data.sha256" \
  > "${root}/evidence/runtime-after-boots.txt"
