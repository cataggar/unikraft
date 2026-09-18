#!/usr/bin/env bash
set -euo pipefail
set -C
umask 077

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

test -f "${source}"
test ! -L "${source}"
test "$(sha256sum "${source}" | cut -d ' ' -f 1)" = "${expected}"
for directory in / /usr /usr/lib /usr/lib/x86_64-linux-gnu; do
  test -d "${directory}"
  test ! -L "${directory}"
  test "$(stat -c '%u:%g:%a' "${directory}")" = 0:0:755
done

if [[ -e "${target}" || -L "${target}" ]]; then
  test -f "${target}"
  test ! -L "${target}"
  test "$(stat -c '%u:%g:%h' "${target}")" = 0:0:1
  [[ "$(stat -c %a "${target}")" = 444 || "$(stat -c %a "${target}")" = 644 ]]
  test "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}"
else
  test ! -e "${ownership}"
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
  test ! -L "${ownership}"
  test "$(stat -c '%u:%g:%a:%h' "${ownership}")" = \
    "${runner_uid}:${runner_gid}:600:1"
  test "$(< "${ownership}")" = "$(stat -c '%d:%i:%u:%g' "${target}")"
fi
test "$(sha256sum "${target}" | cut -d ' ' -f 1)" = "${expected}"
stat -c '%d:%i:%u:%g:%a:%h:%s' "${target}" > "${root}/evidence/managed-libfdt.txt"
