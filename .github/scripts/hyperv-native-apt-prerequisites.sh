#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
if [[ $# != 0 ]]; then
  echo "usage: hyperv-native-apt-prerequisites.sh" >&2
  exit 2
fi
options=(
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources
  -o Dir::Etc::sourceparts=-
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o Acquire::Retries=2
  -o DPkg::Lock::Timeout=60
  -o APT::Update::Error-Mode=any
  -o Dpkg::Use-Pty=0
)
run_apt() {
  local phase="$1"
  shift
  printf 'Native Ubuntu prerequisite phase: %s\n' "${phase}" >&2
  if sudo -n timeout --kill-after=5 240 env \
      DEBIAN_FRONTEND=noninteractive apt-get "${options[@]}" "$@"; then
    return
  else
    local status=$?
    printf 'Native Ubuntu prerequisites refused at %s (exit %d).\n' \
      "${phase}" "${status}" >&2
    exit "${status}"
  fi
}
run_apt metadata update
run_apt installation install -y --no-install-recommends \
  make bison flex m4 python3 acl ovmf
