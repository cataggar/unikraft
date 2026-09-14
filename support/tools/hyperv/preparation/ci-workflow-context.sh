#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo 'Expected one synthetic fixture workflow mode' >&2
  exit 2
fi
if [ "${GITHUB_ACTIONS:-}" != true ] ||
   [ "${GITHUB_REPOSITORY:-}" != cataggar/unikraft ]; then
  echo 'Verified fixture selection requires the selected repository CI context' >&2
  exit 2
fi
case "$1" in
  qualification)
    if [ "${GITHUB_WORKFLOW:-}" != 'Hyper-V fixture debug qualification' ] ||
       [ "${GITHUB_JOB:-}" != fixture-debug-qualification ] ||
       [ "${GITHUB_REF:-}" != refs/heads/fleet/zig-hyperv-fixture-strip-qualification ]; then
      echo 'Fixture qualification requires the explicit qualification workflow' >&2
      exit 2
    fi
    ;;
  verified)
    if [ "${GITHUB_WORKFLOW:-}" != integration ] ||
       [ "${GITHUB_JOB:-}" != zig-hyperv-preparation ]; then
      echo 'Verified fixture selection requires the native preparation CI job' >&2
      exit 2
    fi
    ;;
  *)
    echo 'Unknown synthetic fixture workflow mode' >&2
    exit 2
    ;;
esac
