#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 0 ]]; then
  echo "usage: hyperv-native-proofs-ci.sh" >&2
  exit 2
fi

root="${RUNNER_TEMP:?}/hyperv-ci/native-image-proofs"
TIMEFORMAT='hyperv-ci image-proofs/compiler: elapsed=%3R user=%3U system=%3S seconds'
time ZIG_LOCAL_CACHE_DIR="${root}/zig-local-cache" \
  zig build -j2 test-hyperv-image-proofs build-hyperv-image-proofs \
    test-native-compiler-options \
    --cache-dir "${root}/zig-local-cache" \
    --prefix "${root}/out" "-Doutput=${root}/build" \
    --summary all
