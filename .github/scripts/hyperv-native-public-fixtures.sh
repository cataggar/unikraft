#!/usr/bin/env bash
set -euo pipefail
umask 077

modes=(Debug ReleaseSafe)
if [[ $# != 0 ]]; then
  if [[ $# != 1 || ( "$1" != Debug && "$1" != ReleaseSafe ) ]]; then
    echo "usage: hyperv-native-public-fixtures.sh [Debug|ReleaseSafe]" >&2
    exit 2
  fi
  modes=("$1")
fi

root="${RUNNER_TEMP:?}/hyperv-ci/native-public-image"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-${RUNNER_TEMP}/hyperv-ci/zig-global-cache}"
TIMEFORMAT='hyperv-ci public-image total: elapsed=%3R user=%3U system=%3S seconds'
time (
  # A standalone restore can unpack SQLite before any compilation creates tmp.
  mkdir -p "${ZIG_GLOBAL_CACHE_DIR:?}/tmp"
  mkdir -p "${root}/restore"
  cp support/tools/hyperv/public_image/build.zig \
    support/tools/hyperv/public_image/build.zig.zon "${root}/restore/"
  (
    TIMEFORMAT='hyperv-ci public-image restore: elapsed=%3R user=%3U system=%3S seconds'
    time ZIG_LOCAL_CACHE_DIR="${root}/restore-cache" \
      zig build --build-file "${root}/restore/build.zig" --fetch=all -j2
  )
  for mode in "${modes[@]}"; do
    mkdir -p "${root}/${mode}/fixtures" "${root}/${mode}/import-fixtures"
    (
      TIMEFORMAT="hyperv-ci public-image ${mode}: elapsed=%3R user=%3U system=%3S seconds"
      time zig build --build-file support/tools/hyperv/public_image/build.zig \
        --system "${root}/restore/zig-pkg" \
        --cache-dir "${root}/${mode}/zig-local-cache" \
        --prefix "${root}/${mode}/out" \
        -Dtest-root="${root}/${mode}/fixtures" \
        -Dimport-test-root="${root}/${mode}/import-fixtures" \
        -Doptimize="${mode}" -j2 test test-import install --summary all
    )
  done
)
