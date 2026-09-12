#!/usr/bin/env bash
set -euo pipefail
set -C
umask 077
export LC_ALL=C

if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "$(id -u)" -eq 0 || "$(uname -m)" != x86_64 ]]; then
  echo "usage: hyperv-native-qemu-acquire.sh NEW_ABSOLUTE_ROOT on an ordinary-user x64 GitHub runner" >&2
  exit 2
fi
root="$1"
test "$(readlink -f "${root}")" = "${root}"
mkdir -m 700 "${root}"
mkdir -m 700 "${root}/evidence" "${root}/downloads" "${root}/bin" \
  "${root}/tmp" "${root}/cache" "${root}/ghr-tools" "${root}/ghr-bin"
export TMPDIR="${root}/tmp"
export GHR_CACHE_DIR="${root}/cache"
export XDG_CACHE_HOME="${root}/cache"
export GHR_TOOL_DIR="${root}/ghr-tools"
export GHR_BIN_DIR="${root}/ghr-bin"
metadata="${root}/evidence/release.json"
archive="${root}/downloads/qemu-v11.0.50-z.7-linux-x64.tar.gz"
expected=f8b9cc818959f95326010c95dad644177ebb0cbb0feef3db9528c4434855e397
ghr download --no-auth \
  https://api.github.com/repos/cataggar/qemu/releases/tags/v11.0.50-z.7 \
  -o "${metadata}" > "${root}/evidence/metadata-download.txt" 2>&1
jq -e --arg digest "sha256:${expected}" '
  .tag_name == "v11.0.50-z.7" and
  .target_commitish == "559ac9def5a65912ae602cc5682fc7c045fcbbcd" and
  ([.assets[] | select(.id == 477103841)] |
    length == 1 and
    .[0].name == "qemu-v11.0.50-z.7-linux-x64.tar.gz" and
    .[0].size == 137302371 and .[0].digest == $digest)
' "${metadata}" > "${root}/evidence/metadata-valid.txt"
ghr download --no-auth --sha256 "${expected}" \
  cataggar/qemu/qemu-v11.0.50-z.7-linux-x64.tar.gz@v11.0.50-z.7 \
  -o "${archive}" > "${root}/evidence/archive-download.txt" 2>&1
test "$(stat -c %s "${archive}")" -eq 137302371
printf '%s  %s\n' "${expected}" "${archive}" | sha256sum -c - \
  > "${root}/evidence/archive-valid.txt"
sha256sum "$(readlink -f "$(command -v ghr)")" "$(command -v tar)" \
  "$(command -v gzip)" > "${root}/evidence/acquisition-tools.sha256"
tar --list --gzip --ignore-zeros --quoting-style=escape --file "${archive}" \
  > "${root}/evidence/members.txt"
tar --list --verbose --gzip --ignore-zeros --quoting-style=escape --file "${archive}" \
  > "${root}/evidence/member-types.txt"
gzip --decompress --stdout "${archive}" > "${root}/downloads/qemu-members.tar"
awk '
  $0 !~ /^qemu-v11\.0\.50-z\.7-linux-x64\/[A-Za-z0-9_.+,/-]*$/ ||
    $0 ~ /(^|\/)\.\.?($|\/)/ || $0 ~ /\/\// {
    print "Rejected archive member: " $0 > "/dev/stderr"; exit 1
  }
  {
    name = $0
    sub(/\/$/, "", name)
    if (seen[name]++) {
      print "Duplicate archive member: " $0 > "/dev/stderr"; exit 1
    }
  }
' "${root}/evidence/members.txt"
awk '
  NF != 6 || $1 !~ /^[-d]/ || $3 !~ /^[0-9]+$/ {
    print "Unexpected archive member type or listing: " $0 > "/dev/stderr"; exit 1
  }
' "${root}/evidence/member-types.txt"
for name in qemu-system-x86_64 qemu-img; do
  mapfile -t members < <(grep -E "(^|/)${name}$" "${root}/evidence/members.txt")
  test "${#members[@]}" -eq 1
  member="${members[0]}"
  awk -v member="${member}" '
    $NF == member { count++; if (substr($1, 1, 1) != "-") exit 1 }
    END { if (count != 1) exit 1 }
  ' "${root}/evidence/member-types.txt"
  tar --extract --to-stdout --no-wildcards --occurrence=1 \
    --file "${root}/downloads/qemu-members.tar" \
    -- "${member}" > "${root}/bin/${name}"
  test -s "${root}/bin/${name}"
  chmod 500 "${root}/bin/${name}"
done
sha256sum "${root}/bin/qemu-system-x86_64" "${root}/bin/qemu-img" \
  > "${root}/evidence/candidate-executables.sha256"
mkdir -m 700 "${root}/bin/share"
: > "${root}/evidence/qemu-data.sha256"
# The release uses an empty bindir/suffix: share/ is beside the executable.
awk '$1 ~ /^-/ && $NF ~ /^qemu-v11\.0\.50-z\.7-linux-x64\/share\// { print $NF }' \
  "${root}/evidence/member-types.txt" > "${root}/evidence/qemu-data-members.txt"
while IFS= read -r member; do
  relative="${member#qemu-v11.0.50-z.7-linux-x64/}"
  output="${root}/bin/${relative}"
  mkdir -p "$(dirname "${output}")"
  tar --extract --to-stdout --no-wildcards --occurrence=1 \
    --file "${root}/downloads/qemu-members.tar" \
    -- "${member}" > "${output}"
  chmod 400 "${output}"
  sha256sum "${output}" >> "${root}/evidence/qemu-data.sha256"
done < "${root}/evidence/qemu-data-members.txt"
test -s "${root}/evidence/qemu-data.sha256"

mkdir -m 700 "${root}/apt-lists" "${root}/apt-cache" "${root}/runtime"
test -r /etc/apt/sources.list.d/ubuntu.sources
test -r /usr/share/keyrings/ubuntu-archive-keyring.gpg
awk '
  /^Signed-By:/ {
    count++
    if (NF != 2 || $2 != "/usr/share/keyrings/ubuntu-archive-keyring.gpg") exit 1
  }
  END { if (count == 0) exit 1 }
' /etc/apt/sources.list.d/ubuntu.sources
# APT_CONFIG is read before configuration fragments: exclude runner hooks.
printf '%s\n' \
  'Dir::Etc::parts "-";' \
  'Dir::Etc::main "-";' \
  'Dir::Etc::sourcelist "/etc/apt/sources.list.d/ubuntu.sources";' \
  'Dir::Etc::sourceparts "-";' \
  "Dir::State::lists \"${root}/apt-lists\";" \
  "Dir::Cache \"${root}/apt-cache\";" \
  'APT::Update::Error-Mode "any";' \
  > "${root}/evidence/apt.conf"
export APT_CONFIG="${root}/evidence/apt.conf"
apt-config dump > "${root}/evidence/apt-config.txt"
if grep -Eq '(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs)' "${root}/evidence/apt-config.txt"; then
  echo "Unexpected package-manager hook in native QEMU acquisition." >&2
  exit 1
fi
apt-get update > "${root}/evidence/apt-update.txt" 2>&1
apt-cache policy libfdt1 > "${root}/evidence/libfdt-policy.txt"
version=1.7.0-2build1
apt-cache show "libfdt1=${version}" > "${root}/evidence/libfdt-package.txt"
(
  cd "${root}/downloads"
  apt-get download "libfdt1=${version}" > "${root}/evidence/libfdt-download.txt" 2>&1
)
packages=("${root}"/downloads/libfdt1_*.deb)
test "${#packages[@]}" -eq 1
test -f "${packages[0]}"
expected="$(awk '$1 == "SHA256:" { print $2 }' "${root}/evidence/libfdt-package.txt" | sort -u)"
test "${expected}" = 274d20dfab9d6b216b5de85446a93f6ce5b2cd82c847b8dfdc508577f76eb96a
printf '%s  %s\n' "${expected}" "${packages[0]}" | sha256sum -c - \
  > "${root}/evidence/libfdt-package-valid.txt"
dpkg-deb --fsys-tarfile "${packages[0]}" > "${root}/downloads/libfdt.tar"
tar --list --verbose --file "${root}/downloads/libfdt.tar" \
  > "${root}/evidence/libfdt-members.txt"
mapfile -t members < <(
  awk '$1 ~ /^-/ && $NF ~ /^\.\/usr\/lib\/x86_64-linux-gnu\/libfdt-[0-9.]+\.so$/ { print $NF }' \
    "${root}/evidence/libfdt-members.txt"
)
test "${#members[@]}" -eq 1
tar --extract --to-stdout --no-wildcards --file "${root}/downloads/libfdt.tar" \
  -- "${members[0]}" > "${root}/runtime/libfdt.so.1"
chmod 400 "${root}/runtime/libfdt.so.1"
sha256sum "${root}/runtime/libfdt.so.1" \
  /usr/share/keyrings/ubuntu-archive-keyring.gpg /etc/apt/sources.list.d/ubuntu.sources \
  > "${root}/evidence/libfdt-inputs.sha256"
