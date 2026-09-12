#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT QEMU_MODULE_DIR

if [[ $# != 3 && $# != 4 ]]; then
  echo "usage: hyperv-qemu-candidate.sh ABSOLUTE_QEMU ABSOLUTE_QEMU_IMG NEW_EVIDENCE_DIR [PRIVATE_LIBRARY_DIR]" >&2
  exit 2
fi
qemu="$1"
image_tool="$2"
root="$3"
if [[ $# == 4 ]]; then
  [[ "$4" = /* && -d "$4" && ! -L "$4" ]]
  export LD_LIBRARY_PATH
  LD_LIBRARY_PATH="$(readlink -f "$4")"
fi
for executable in "${qemu}" "${image_tool}"; do
  [[ "${executable}" = /* && -f "${executable}" && ! -L "${executable}" && -x "${executable}" ]]
done
[[ "${root}" = /* ]]
test "$(uname -m)" = x86_64
mkdir -m 700 "${root}"
root="$(readlink -f "${root}")"
loader=/lib64/ld-linux-x86-64.so.2
test -x "${loader}"

for executable in "${qemu}" "${image_tool}"; do
  name="$(basename "${executable}")"
  readelf --wide --program-headers --dynamic --version-info "${executable}" \
    > "${root}/${name}-elf.txt"
  grep -Fq "Requesting program interpreter: ${loader}" "${root}/${name}-elf.txt"
  "${loader}" --list "${executable}" > "${root}/${name}-libraries.txt" 2>&1
  awk '/=>/ { if ($3 !~ /^\//) exit 1; print $3 }' \
    "${root}/${name}-libraries.txt" > "${root}/${name}-library-paths.txt"
  test -s "${root}/${name}-library-paths.txt"
  while IFS= read -r library; do
    sha256sum "$(readlink -f "${library}")"
  done < "${root}/${name}-library-paths.txt"
done > "${root}/libraries.sha256"
sha256sum "${qemu}" "${image_tool}" "$(readlink -f "${loader}")" > "${root}/executables.sha256"

timeout --signal=TERM --kill-after=5s 15s \
  "${qemu}" -no-user-config -machine none -nodefaults -display none -S \
    -drive format=help > "${root}/formats.txt" 2>&1
grep -Eq '(^|[[:space:]])vpc([[:space:]]|$)' "${root}/formats.txt"
timeout --signal=TERM --kill-after=5s 15s \
  "${qemu}" -no-user-config -machine none -nodefaults -display none -device help \
    > "${root}/devices.txt" 2>&1
grep -Fq 'name "vmbus-bridge"' "${root}/devices.txt"

# This zero-filled disk tests the format driver, not a guest or miz packaging.
payload_bytes=$((66 * 1024 * 1024))
disk="${root}/synthetic-fixed.vhd"
timeout --signal=TERM --kill-after=5s 20s \
  "${image_tool}" create -f vpc -o subformat=fixed,force_size=on \
    "${disk}" "${payload_bytes}" > "${root}/create.txt" 2>&1
test "$(stat -c %s "${disk}")" -eq "$((payload_bytes + 512))"
test "$(stat -c %h "${disk}")" -eq 1
chmod 400 "${disk}"
od -An -v -tu1 -j "${payload_bytes}" -N 512 "${disk}" > "${root}/footer.txt"
awk -v capacity="${payload_bytes}" '
  function integer(offset, width, result, i) {
    result = 0
    for (i = 0; i < width; i++) result = result * 256 + bytes[offset + i + 1]
    return result
  }
  { for (i = 1; i <= NF; i++) bytes[++count] = $i }
  END {
    if (count != 512) exit 1
    split("99 111 110 101 99 116 105 120", cookie, " ")
    for (i = 1; i <= 8; i++) if (bytes[i] != cookie[i]) exit 1
    for (i = 17; i <= 24; i++) if (bytes[i] != 255) exit 1
    if (integer(8, 4) != 2 || integer(12, 4) != 65536 ||
        integer(40, 8) != capacity || integer(48, 8) != capacity ||
        integer(60, 4) != 2) exit 1
    sum = 0
    for (i = 1; i <= 512; i++) if (i < 65 || i > 68) sum += bytes[i]
    if (integer(64, 4) != 4294967295 - sum) exit 1
  }
' "${root}/footer.txt"
sha256sum "${disk}" > "${root}/disk-before.sha256"

# Only capabilities, a read-only query, and quit are sent; never initialize a board.
printf '%s\n' \
  '{"execute":"qmp_capabilities","id":"caps"}' \
  '{"execute":"query-named-block-nodes","id":"nodes"}' \
  '{"execute":"quit","id":"quit"}' > "${root}/commands.jsonl"
exec 64< "${disk}"
set +e
(
  ulimit -f 1024
  exec timeout --signal=TERM --kill-after=5s 20s \
    "${qemu}" -no-user-config -machine none -accel tcg --preconfig -S \
      -nodefaults -display none -serial none -monitor none -qmp stdio \
      -blockdev '{"driver":"vpc","node-name":"local-boot-disk","read-only":true,"file":{"driver":"file","filename":"/proc/self/fd/64","read-only":true}}' \
      < "${root}/commands.jsonl" > "${root}/qmp.jsonl" 2> "${root}/qmp-stderr.txt"
)
status=$?
set -e
exec 64<&-
printf '%s\n' "${status}" > "${root}/qmp-exit.txt"
sha256sum -c "${root}/disk-before.sha256" "${root}/executables.sha256" \
  "${root}/libraries.sha256" > "${root}/unchanged.txt"
test "${status}" -eq 0
jq -es --argjson capacity "${payload_bytes}" '
  ([.[] | select(has("QMP"))] | length) == 1 and
  ([.[] | select(has("error"))] | length) == 0 and
  ([.[] | select(.id == "caps")] | length) == 1 and
  ([.[] | select(.id == "caps")][0].return == {}) and
  ([.[] | select(.id == "quit")] | length) == 1 and
  ([.[] | select(.id == "quit")][0].return == {}) and
  ([.[] | select(.id == "nodes")] | length) == 1 and
  ([.[] | select(.id == "nodes")][0].return |
    map(select(."node-name" == "local-boot-disk")) |
    length == 1 and
    .[0].drv == "vpc" and .[0].ro == true and
    .[0].image.format == "vpc" and .[0].image."virtual-size" == $capacity)
' "${root}/qmp.jsonl" > "${root}/qmp-valid.txt"
qemu_sha256="$(sha256sum "${qemu}" | cut -d ' ' -f 1)"
disk_sha256="$(sha256sum "${disk}" | cut -d ' ' -f 1)"
jq -n --arg executable_sha256 "${qemu_sha256}" --arg disk_sha256 "${disk_sha256}" \
  --argjson capacity "${payload_bytes}" '{
    scope: "synthetic_fixed_vhd_open_only",
    authority: "not_admitted",
    guest_booted: false,
    executable_sha256: $executable_sha256,
    disk_sha256: $disk_sha256,
    virtual_size: $capacity,
    driver: "vpc",
    read_only: true,
    vmbus_device_registered: true,
    input_and_runtime_unchanged: true
  }' > "${root}/result.json"
