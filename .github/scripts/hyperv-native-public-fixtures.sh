#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 0 ]]; then
  echo "usage: hyperv-native-public-fixtures.sh" >&2
  exit 2
fi

root="${RUNNER_TEMP:?}/hyperv-ci/native-public-image"
TIMEFORMAT='hyperv-ci public-image total: elapsed=%3R user=%3U system=%3S seconds'
time (
  mkdir -p "${root}/restore"
  cp support/tools/hyperv/public_image/build.zig \
    support/tools/hyperv/public_image/build.zig.zon "${root}/restore/"
  TIMEFORMAT='hyperv-ci public-image restore: elapsed=%3R user=%3U system=%3S seconds'
  time ZIG_LOCAL_CACHE_DIR="${root}/restore-cache" \
    zig build --build-file "${root}/restore/build.zig" --fetch=all -j2
  for mode in Debug ReleaseSafe; do
    mkdir -p "${root}/${mode}/fixtures" "${root}/${mode}/import-fixtures"
    TIMEFORMAT="hyperv-ci public-image ${mode}: elapsed=%3R user=%3U system=%3S seconds"
    time zig build --build-file support/tools/hyperv/public_image/build.zig \
      --system "${root}/restore/zig-pkg" \
      --cache-dir "${root}/${mode}/zig-local-cache" \
      --prefix "${root}/${mode}/out" \
      -Dtest-root="${root}/${mode}/fixtures" \
      -Dimport-test-root="${root}/${mode}/import-fixtures" \
      -Doptimize="${mode}" -j2 test test-import install --summary all
  done
)
