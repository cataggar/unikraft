#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail
umask 077
export LC_ALL=C

case "${1:-}:${2:-}" in
  api:*)
    if [[ $# -lt 2 ]]; then
      echo "GitHub read refused: API path required." >&2
      exit 2
    fi
    for argument in "$@"; do
      case "${argument}" in
        -X*|--method*|-f*|-F*|--field*|--raw-field*|--input*)
          echo "GitHub read refused: API method/body override." >&2
          exit 2
          ;;
      esac
    done
    command=(gh api --method GET "${@:2}")
    ;;
  pr:view|pr:list|run:view)
    command=(gh "$@")
    ;;
  *)
    echo "GitHub read refused: use api, pr view/list, run view." >&2
    exit 2
    ;;
esac
temporary="$(mktemp -d)"
cleanup() {
  rm -f -- "${temporary}/stdout" "${temporary}/stderr"
  rmdir -- "${temporary}"
}
trap cleanup EXIT
for attempt in 1 2 3; do
  if timeout --kill-after=5 120 "${command[@]}" \
      > "${temporary}/stdout" 2> "${temporary}/stderr"; then
    cat -- "${temporary}/stderr" >&2
    cat -- "${temporary}/stdout"
    exit 0
  else
    status=$?
  fi
  printf 'GitHub read attempt %d/3 failed (exit %d).\n' \
    "${attempt}" "${status}" >&2
  cat -- "${temporary}/stderr" >&2
  if [[ "${attempt}" == 3 ]] || {
    [[ "${status}" != 124 ]] &&
      ! grep -Eq \
        'HTTP (429|500|502|503|504)([^0-9]|$)|API rate limit exceeded' \
        "${temporary}/stderr"
  }; then
    exit "${status}"
  fi
  sleep "$((attempt * 5))"
done
