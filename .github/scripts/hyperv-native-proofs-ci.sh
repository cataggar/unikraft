#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 0 ]]; then
  echo "usage: hyperv-native-proofs-ci.sh" >&2
  exit 2
fi

root="${RUNNER_TEMP:?}/hyperv-ci/native-image-proofs"
TIMEFORMAT='hyperv-ci image-proofs/compiler/regression: elapsed=%3R user=%3U system=%3S seconds'
# One build graph shares the proof and compiler dependencies of regression.
time ZIG_LOCAL_CACHE_DIR="${root}/zig-local-cache" \
  zig build -j2 test-hyperv-image-proofs build-hyperv-image-proofs \
    test-native-compiler-options test-hyperv-regression \
    --cache-dir "${root}/zig-local-cache" \
    --prefix "${root}/out" "-Doutput=${root}/build" \
    --summary all
