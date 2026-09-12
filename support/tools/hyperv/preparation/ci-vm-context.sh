#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || { [ "$1" != raw ] && [ "$1" != qualified ]; }; then
  echo 'Usage: ci-vm-context.sh raw|qualified' >&2
  exit 2
fi
if [ "${GITHUB_ACTIONS:-}" = true ] ||
   [ "$(id -u)" -ne 1001 ] || [ "$(id -g)" -ne 1001 ]; then
  echo 'Local fixture mode requires the ordinary dedicated VM account, not GitHub context' >&2
  exit 1
fi
package="$(dirname -- "${BASH_SOURCE[0]}")"
marker=/etc/unikraft-fixture-vm.json
if [ -L "${marker}" ] || [ ! -f "${marker}" ] ||
   [ "$(stat -c '%u:%g:%a:%h' "${marker}")" != 0:0:444:1 ] ||
   [ "$(stat -c '%s' "${marker}")" -gt 2048 ]; then
  echo 'The root-owned disposable-VM marker is missing or invalid' >&2
  exit 1
fi
identity="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${marker}")"
document="$(head -c 2049 "${marker}")"
if [ "${#document}" -gt 2048 ] ||
   ! jq -se -f "${package}/ci-vm-marker.jq" <<< "${document}" > /dev/null; then
  echo 'Disposable-VM marker does not match the approved fixture contract' >&2
  exit 1
fi
if [ "$(uname -m)" != x86_64 ] || [ "$(uname -r)" != 6.8.0-139-generic ] ||
   [ "$(systemd-detect-virt --vm)" != kvm ] ||
   [ "$(tr -d '\n' < /proc/1/comm)" != systemd ]; then
  echo 'Local fixture mode requires the prepared native Ubuntu KVM guest' >&2
  exit 1
fi
if ! grep -Fxq 'ID=ubuntu' /etc/os-release ||
   ! grep -Fxq 'VERSION_ID="24.04"' /etc/os-release; then
  echo 'Unexpected local fixture guest distribution' >&2
  exit 1
fi
uuid="$(sudo -n /usr/bin/cat /sys/class/dmi/id/product_uuid | tr A-F a-f)"
if [ "${uuid}" != "$(jq -r .vm_uuid <<< "${document}")" ] ||
   [ "$(pwd -P)" != /work/unikraft ]; then
  echo 'VM identity or source location does not match the root-owned marker' >&2
  exit 1
fi
if ! systemctl is-active --quiet apparmor ||
   [ "$(cat /sys/module/apparmor/parameters/enabled)" != Y ] ||
   [ "$(sudo -n /usr/bin/cat /sys/kernel/security/apparmor/features/policy/unconfined_restrictions/userns)" != 1 ] ||
   [ "$(/usr/sbin/sysctl -n kernel.apparmor_restrict_unprivileged_userns)" != 1 ]; then
  echo 'The prepared guest must retain active AppArmor and the global userns restriction' >&2
  exit 1
fi
python_mode="$(stat -c '%a' /usr/bin/python3.12)"
if [[ ! "${python_mode}" =~ ^[0-7]{3,4}$ ]] ||
   [ "$((8#${python_mode} & 0111))" -ne 0 ]; then
  echo 'The guest interpreter execution-bit guard is not intact' >&2
  exit 1
fi
if [[ ! "${UK_FIXTURE_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Local fixture mode requires an independently supplied source commit' >&2
  exit 2
fi
source_sha="$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git rev-parse HEAD)"
if [ "${source_sha}" != "${UK_FIXTURE_SOURCE_SHA}" ] ||
   [ -n "$(GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git -c core.fsmonitor=false status --porcelain)" ] ||
   [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${marker}")" != "${identity}" ]; then
  echo 'Local fixture source or VM marker changed' >&2
  exit 1
fi
jq -nc --arg uuid "${uuid}" --arg source "${source_sha}" --arg variant "$1" '
  {schema:"hyperv_preparation_fixture_context_v1",authority:"synthetic_only",
   environment:"local_disposable_vm",vm_uuid:$uuid,source_sha:$source,variant:$variant}
'
