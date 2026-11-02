#!/bin/sh
# Deliberately invalid output for the real build-gating refusal test.
set -eu
test "$#" -eq 3
test "$1" = --strip-debug
cp -- "$(dirname -- "$0")/fixture-strip-rejected-worker.sh" "$3"
chmod 700 -- "$3"
