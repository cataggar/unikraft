#!/usr/bin/env bash
set -euo pipefail
set -C
umask 077

refuse() {
  echo "Native libfdt preparation refused: $1" >&2
  exit 1
}

if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "$(id -u)" -eq 0 || "$(uname -m)" != x86_64 ]]; then
  echo "usage: hyperv-native-libfdt-prepare.sh ROOT on an ordinary-user x64 GitHub runner" >&2
  exit 2
fi
root="$(readlink -f "$1")"
source="${root}/runtime/libfdt.so.1"
target=/usr/lib/x86_64-linux-gnu/libfdt.so.1
ownership="${root}/evidence/runtime-created.txt"
expected=66c111808e61c7f6be6715b4b03d0fe75beb5bc5b3a8809608d58d99a6bc9828
runner_uid="$(id -u)"
runner_gid="$(id -g)"

[[ -f "${source}" && ! -L "${source}" ]] || refuse source
[[ "$(sha256sum "${source}" | cut -d ' ' -f 1)" = "${expected}" ]] ||
  refuse source-digest
for directory in / /usr /usr/lib /usr/lib/x86_64-linux-gnu; do
  [[ -d "${directory}" && ! -L "${directory}" ]] || refuse directory
  [[ "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:755 ]] ||
    refuse directory-metadata
done

if [[ -e "${target}" || -L "${target}" ]]; then
  [[ -f "${target}" && ! -L "${target}" ]] || refuse target
  [[ "$(stat -c '%u:%g:%h' "${target}")" = 0:0:1 ]] ||
    refuse target-metadata
  [[ "$(stat -c %a "${target}")" = 444 || "$(stat -c %a "${target}")" = 644 ]] ||
    refuse target-mode
  [[ "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}" ]] ||
    refuse target-digest
else
  [[ ! -e "${ownership}" ]] || refuse ownership-preexists
  sudo bash -c '
    set -euo pipefail
    set -C
    umask 077
    exec 8> "$2"
    chmod 600 "$2"
    exec 9> /usr/lib/x86_64-linux-gnu/libfdt.so.1
    stat -Lc "%d:%i:%u:%g" /proc/self/fd/9 >&8
    cat -- "$1" >&9
    chmod 444 /usr/lib/x86_64-linux-gnu/libfdt.so.1
    sync -f /usr/lib/x86_64-linux-gnu/libfdt.so.1
    chown --no-dereference "$3:$4" "$2"
  ' _ "${source}" "${ownership}" "${runner_uid}" "${runner_gid}"
fi
if [[ -f "${ownership}" ]]; then
  [[ ! -L "${ownership}" ]] || refuse ownership-link
  [[ "$(stat -c '%u:%g:%a:%h' "${ownership}")" = \
    "${runner_uid}:${runner_gid}:600:1" ]] || refuse ownership-metadata
  [[ "$(< "${ownership}")" = "$(stat -c '%d:%i:%u:%g' "${target}")" ]] ||
    refuse ownership-identity
fi
[[ "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}" ]] ||
  refuse final-digest
managed="${root}/evidence/managed-libfdt.txt"
managed_identity="$(stat -c '%d:%i:%u:%g:%a:%h:%s' "${target}")"
if [[ -e "${managed}" || -L "${managed}" ]]; then
  [[ -f "${managed}" && ! -L "${managed}" ]] || refuse managed-record
  [[ "$(stat -c '%u:%g:%a:%h' "${managed}")" = \
    "${runner_uid}:${runner_gid}:600:1" ]] || refuse managed-record-metadata
  [[ "$(< "${managed}")" = "${managed_identity}" ]] ||
    refuse managed-record-identity
else
  printf '%s\n' "${managed_identity}" > "${managed}"
fi
