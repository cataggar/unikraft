#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "$(id -u)" -eq 0 || "$(uname -m)" != x86_64 ]]; then
  echo "usage: hyperv-native-libfdt-cleanup.sh ROOT on an ordinary-user x64 GitHub runner" >&2
  exit 2
fi
root="$(readlink -f "$1")"
target=/usr/lib/x86_64-linux-gnu/libfdt.so.1
ownership="${root}/evidence/runtime-created.txt"
result="${root}/evidence/libfdt-cleanup.txt"
expected=66c111808e61c7f6be6715b4b03d0fe75beb5bc5b3a8809608d58d99a6bc9828

if [[ ! -f "${ownership}" ]]; then
  printf 'managed=0 cleanup=0\n' > "${result}"
  exit 0
fi
test ! -L "${ownership}"
test "$(stat -c '%u:%g:%a:%h' "${ownership}")" = \
  "$(id -u):$(id -g):600:1"
identity="$(< "${ownership}")"
[[ "${identity}" =~ ^[0-9]+:[0-9]+:0:0$ ]]
test -f "${target}"
test ! -L "${target}"
test "$(stat -c '%d:%i:%u:%g' "${target}")" = "${identity}"
test "$(stat -c '%a:%h' "${target}")" = 444:1
test "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}"
sudo rm -- "${target}"
test ! -e "${target}"
test ! -L "${target}"
printf 'managed=1 cleanup=0\n' > "${result}"
