#!/usr/bin/env bash
set -euo pipefail
set -C
umask 077
export LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT QEMU_MODULE_DIR

if [[ $# != 3 || "$1" != /* || "$2" != /* ||
      ( "$3" != true && "$3" != false ) || "${GITHUB_ACTIONS:-}" != true ||
      "$(id -u)" -eq 0 || "${GITHUB_JOB:-}" != zig-hyperv ]]; then
  echo "usage: hyperv-native-public-ci.sh RUNTIME_ROOT CI_ROOT NETWORK_APPLICATION on the ordinary-user zig-hyperv job" >&2
  exit 2
fi
runtime="$1"
ci="$2"
test "$(readlink -f "${runtime}")" = "${runtime}"
test "$(readlink -f "${ci}")" = "${ci}"
test "${QUALIFICATION_REPOSITORY_ID:?}" = "${GITHUB_REPOSITORY_ID:?}"
test "${QUALIFICATION_SOURCE_JOB:?}" = "${GITHUB_JOB}"
test "$(git rev-parse HEAD)" = "${GITHUB_SHA:?}"
test -r /dev/kvm
test -w /dev/kvm
root="${ci}/native-public-boot"
mkdir -m 700 "${root}"
mkdir -m 700 "${root}/firmware"
cp --no-preserve=mode,ownership \
  "$(readlink -f /usr/share/OVMF/OVMF_CODE_4M.fd)" "${root}/firmware/code.fd"
cp --no-preserve=mode,ownership \
  "$(readlink -f /usr/share/OVMF/OVMF_VARS_4M.fd)" "${root}/firmware/vars.fd"
cli="$(readlink -f "${ci}/native-public-image/ReleaseSafe/out/bin/uk-hyperv-public-image")"
efi="$(readlink -f "${ci}/build/helloworld_hyperv-x86_64-efi-netvsc")"
qemu="${runtime}/bin/qemu-system-x86_64"
sha256sum "${cli}" > "${root}/source-exporter.sha256"
source_exporter_sha256="$(cut -d ' ' -f 1 "${root}/source-exporter.sha256")"
[[ "${source_exporter_sha256}" =~ ^[0-9a-f]{64}$ ]]
solved_config=()
if [[ "$3" == true ]]; then
  solved_config=(--solved-config "$(readlink -f "${ci}/hyperv-acceptance.config")")
fi
timeout --signal=TERM --kill-after=5s 480s \
  "${cli}" prepare --efi "${efi}" --qemu "${qemu}" \
    --ovmf-code "${root}/firmware/code.fd" \
    --ovmf-vars "${root}/firmware/vars.fd" \
    --state-dir "${root}/packaging" "${solved_config[@]}" --timeout 60 \
    > "${root}/prepare-result.json"
timeout --signal=TERM --kill-after=5s 60s \
  "${cli}" validate-matrix --state-dir "${root}/packaging" \
    > "${root}/matrix.json"
# Native-v4 export is separate from the unchanged legacy #87 output contract.
timeout --signal=TERM --kill-after=5s 90s \
  "${cli}" export-prepared --state-dir "${root}/packaging" \
    --artifact-dir "${root}/export" \
    --source-repository "${GITHUB_REPOSITORY:?}" \
    --source-repository-id "${GITHUB_REPOSITORY_ID}" \
    --source-workflow-ref "${GITHUB_WORKFLOW_REF:?}" --source-job "${GITHUB_JOB}" \
    --source-run-id "${GITHUB_RUN_ID:?}" \
    --source-run-attempt "${GITHUB_RUN_ATTEMPT:?}" \
    --source-head-sha "${GITHUB_SHA:?}" > "${root}/export-digest.txt"
digest="$(< "${root}/export-digest.txt")"
[[ "${digest}" =~ ^[0-9a-f]{64}$ ]]
test "$(wc -c < "${root}/export-digest.txt")" -eq 65
test "$(sha256sum "${root}/export/prepared-image-manifest.json" | cut -d ' ' -f 1)" = "${digest}"
test "$(find "${root}/export" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = $'prepared-image-manifest.json\nunikraft.vhd'
sha256sum "${root}/export/prepared-image-manifest.json" \
  "${root}/export/unikraft.vhd" > "${root}/export-sha256.txt"

# Expectations come from this caller's exporter and GitHub context, not the
# artifact being imported. This exercises local import, not attestation.
expected=(
  --expected-manifest-sha256 "${digest}"
  --expected-producer-sha256 "${source_exporter_sha256}"
  --expected-repository "${GITHUB_REPOSITORY}"
  --expected-repository-id "${GITHUB_REPOSITORY_ID}"
  --expected-workflow-ref "${GITHUB_WORKFLOW_REF}"
  --expected-job "${GITHUB_JOB}"
  --expected-run-id "${GITHUB_RUN_ID}"
  --expected-run-attempt "${GITHUB_RUN_ATTEMPT}"
  --expected-head-sha "${GITHUB_SHA}"
)
timeout --signal=TERM --kill-after=5s 120s \
  "${cli}" import-prepared --artifact-dir "${root}/export" \
    --state-dir "${root}/imported" "${expected[@]}" > "${root}/import-result.json"
jq -er '
  select(.schema_version == 1 and .scope == "public_local_import_only" and
    .authority == "not_admitted" and .attestation == "not_verified" and
    .succeeded == true and .destination == "durable" and .publication == "durable" and
    .failures == {primary:null,cleanup:null,recording:null}) |
  .receipt_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))
' "${root}/import-result.json" > "${root}/import-receipt-sha256.txt"
test "$(wc -c < "${root}/import-receipt-sha256.txt")" -eq 65
receipt="$(< "${root}/import-receipt-sha256.txt")"
timeout --signal=TERM --kill-after=5s 120s \
  "${cli}" validate-import --state-dir "${root}/imported" \
    --expected-import-sha256 "${receipt}" "${expected[@]}" \
    > "${root}/validate-import-result.json"
jq -e --arg receipt "${receipt}" '
  .schema_version == 1 and .scope == "public_local_import_only" and
  .authority == "not_admitted" and .attestation == "not_verified" and
  .validated == true and .receipt_sha256 == $receipt
' "${root}/validate-import-result.json" > "${root}/import-validated.txt"
sha256sum --check "${root}/source-exporter.sha256" "${root}/export-sha256.txt" \
  > "${root}/import-inputs-unchanged.txt"
