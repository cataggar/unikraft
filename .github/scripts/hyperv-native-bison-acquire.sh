#!/usr/bin/env bash
set -euo pipefail
set -C
umask 077
export LC_ALL=C

if [[ $# != 1 || "$1" != /* || "${GITHUB_ACTIONS:-}" != true ||
      "$(id -u)" -eq 0 || "$(uname -m)" != x86_64 ]]; then
  echo "usage: hyperv-native-bison-acquire.sh EXISTING_ABSOLUTE_ROOT on an ordinary-user x64 GitHub runner" >&2
  exit 2
fi
root="$1"
test "$(readlink -f "${root}")" = "${root}"
for directory in "${root}" "${root}/evidence" "${root}/downloads"; do
  test -d "${directory}"
  test ! -L "${directory}"
  test "$(stat -c '%a:%u' "${directory}")" = "700:$(id -u)"
done
# Reuse the hook-free, signed package indexes acquired for the native runtime.
export APT_CONFIG="${root}/evidence/apt.conf"
test -f "${APT_CONFIG}"
test ! -L "${APT_CONFIG}"
mkdir -m 700 "${root}/bison"
version="$(dpkg-query --show --showformat='${Version}' bison)"
test -n "${version}"
apt-cache show "bison=${version}" > "${root}/evidence/bison-package.txt"
(
  cd "${root}/downloads"
  apt-get download "bison=${version}" > "${root}/evidence/bison-download.txt" 2>&1
)
packages=("${root}"/downloads/bison_*.deb)
test "${#packages[@]}" -eq 1
expected="$(awk '$1 == "SHA256:" { print $2 }' "${root}/evidence/bison-package.txt" | sort -u)"
[[ "${expected}" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "${expected}" "${packages[0]}" | sha256sum -c - \
  > "${root}/evidence/bison-package-valid.txt"
dpkg-deb --fsys-tarfile "${packages[0]}" > "${root}/downloads/bison.tar"
tar --list --verbose --ignore-zeros --quoting-style=escape \
  --file "${root}/downloads/bison.tar" > "${root}/evidence/bison-members.txt"
awk '
  $NF == "./usr/bin/bison" {
    count++
    if (NF != 6 || substr($1, 1, 1) != "-") exit 1
  }
  END { if (count != 1) exit 1 }
' "${root}/evidence/bison-members.txt"
tar --extract --to-stdout --no-wildcards --file "${root}/downloads/bison.tar" \
  -- ./usr/bin/bison > "${root}/downloads/bison-member.elf"
executable="$(readlink -f "$(type -P bison)")"
cmp "${root}/downloads/bison-member.elf" "${executable}"
sha256sum "${root}/downloads/bison-member.elf" "${executable}" \
  > "${root}/evidence/bison-executable-match.sha256"
awk '
  $0 ~ / \.\/usr\/share\/bison\// {
    if (NF != 6 || $1 !~ /^[-d]/ ||
        $NF !~ /^\.\/usr\/share\/bison\/[A-Za-z0-9_.+/-]*$/) exit 1
    name = $NF
    sub(/^\.\/usr\/share\/bison\//, "", name)
    sub(/\/$/, "", name)
    if (name ~ /(^|\/)\.\.?($|\/)/ || name ~ /\/\// || seen[name]++) exit 1
    if (substr($1, 1, 1) == "-") print $NF
  }
' "${root}/evidence/bison-members.txt" > "${root}/evidence/bison-data-members.txt"
test -s "${root}/evidence/bison-data-members.txt"
: > "${root}/evidence/bison-data.sha256"
while IFS= read -r member; do
  relative="${member#./usr/share/bison/}"
  output="${root}/bison/${relative}"
  mkdir -p "$(dirname "${output}")"
  tar --extract --to-stdout --no-wildcards --file "${root}/downloads/bison.tar" \
    -- "${member}" > "${output}"
  chmod 400 "${output}"
  sha256sum "${output}" >> "${root}/evidence/bison-data.sha256"
done < "${root}/evidence/bison-data-members.txt"
echo "BISON_PKGDATADIR=${root}/bison" >> "${GITHUB_ENV}"
