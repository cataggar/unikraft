#!/usr/bin/env bash
# CI-only public qualification: build ROOT; boot ROOT ABSOLUTE_QEMU.
# ROOT must already be a canonical, current-user-owned 0700 directory.
# The caller supplies private firmware/{code,vars}.fd and records the exact
# QEMU/default-library/ROM runtime. No library installation or pin change here.
# Boot requires QUALIFICATION_REPOSITORY_ID and QUALIFICATION_SOURCE_JOB,
# plus the real GITHUB_REPOSITORY, GITHUB_WORKFLOW_REF, GITHUB_JOB,
# GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT and GITHUB_SHA. The declared job must
# equal the actual zig-hyperv job; these metadata fields are not an attestation.
# Build needs Zig 0.16, LLVM binutils, Make/Bison/Flex/M4, Bash/Git and
# standard Ubuntu GNU utilities on PATH. BISON_PKGDATADIR is optional.
# Keep HOME unchanged. Created build/boot slots are never reused.
# CLI build: 900s; fetch: 300s; config: 600s; image: 1800s, with 8-MiB logs.
# Boot CLI phases share 480s, plus bounded termination; records cap at 64 KiB.
# Retain guest/evidence/** plus native packaging records/logs and the export
# manifest. Binaries, caches, firmware and disk images stay outside evidence/.
# This script performs no uploads.
set -euo pipefail
set -o noclobber
umask 077
export LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT QEMU_MODULE_DIR

die() { printf 'candidate guest: %s\n' "$*" >&2; exit 2; }
case "${1-}" in
  build) [[ $# == 2 ]] || die 'usage: build ABSOLUTE_ROOT' ;;
  boot) [[ $# == 3 ]] || die 'usage: boot ABSOLUTE_ROOT ABSOLUTE_QEMU' ;;
  *) die 'usage: hyperv-qemu-candidate-guest.sh build ROOT | boot ROOT QEMU' ;;
esac
[[ ${EUID} != 0 ]] || die 'ordinary UID required'
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || die 'Linux x86_64 required'

canonical_path() {
  [[ "$1" =~ ^/[a-zA-Z0-9_./+-]+$ && ${#1} -le 4095 ]] || die 'unsafe absolute path'
  [[ "$(readlink -f -- "$1")" == "$1" ]] || die "noncanonical path: $1"
}
private_dir() {
  canonical_path "$1"
  [[ -d "$1" && ! -L "$1" ]] || die "not a real directory: $1"
  [[ "$(stat -c '%u:%a' -- "$1")" == "${EUID}:700" ]] || die "nonprivate directory: $1"
}
artifact() {
  local path="$1" maximum="$2" uid mode links bytes
  canonical_path "$path"
  [[ -f "$path" && ! -L "$path" ]] || die "not a regular file: $path"
  read -r uid mode links bytes < <(stat -c '%u %a %h %s' -- "$path")
  [[ "$uid" == 0 || "$uid" == "${EUID}" ]] || die "unsafe file owner: $path"
  (( (8#$mode & 8#7022) == 0 && links == 1 && bytes > 0 && bytes <= maximum )) ||
    die "unsafe file mode, links or size: $path"
}
private_file() {
  artifact "$1" "$2"
  [[ "$(stat -c '%u:%a' -- "$1")" == "${EUID}:600" ]] || die "nonprivate file: $1"
}
new_path() {
  [[ ! -e "$1" && ! -L "$1" ]] || die "refusing reuse: $1"
}
native_tool() {
  local path
  path="$(type -P "$1")" || die "missing native tool: $1"
  path="$(readlink -f -- "$path")"
  canonical_path "$path"
  [[ -f "$path" && -x "$path" ]] || die "invalid native tool: $1"
  [[ "$(od -An -N4 -tx1 "$path" | tr -d ' \n')" == 7f454c46 ]] ||
    die "tool is not a native ELF: $1"
  printf '%s\n' "$path"
}

root="$2"
private_dir "$root"
guest="$root/guest"
evidence="$guest/evidence"
script="$(readlink -f -- "${BASH_SOURCE[0]}")"
repo="$(cd -- "$(dirname -- "$script")/../.." && pwd -P)"
canonical_path "$repo"
cd -- "$repo"
boot_deadline=0

monotonic_cs() {
  local uptime ignored
  read -r uptime ignored < /proc/uptime
  [[ "$uptime" =~ ^([0-9]+)\.([0-9]{2})$ ]] || die 'invalid monotonic uptime'
  printf '%s\n' "$((10#${BASH_REMATCH[1]} * 100 + 10#${BASH_REMATCH[2]}))"
}

# The reader has its own finite lifetime, including after a failed writer.
# One overflow byte distinguishes an exact-size output from truncation.
# Status files describe command execution only, never boot acceptance.
run_bounded() {
  local output="$1" seconds="$2" limit="$3" ticks remaining duration reader status=0 bytes
  local stages=(0 0)
  shift 3
  new_path "$output"
  new_path "$output.status"
  ticks=$((seconds * 100))
  if (( boot_deadline != 0 )); then
    remaining=$((boot_deadline - $(monotonic_cs)))
    (( remaining > 0 )) || die '480-second boot command budget exhausted'
    (( ticks <= remaining )) || ticks="$remaining"
  fi
  printf -v duration '%d.%02ds' "$((ticks / 100))" "$((ticks % 100))"
  reader=$(((ticks + 99) / 100 + 6))
  timeout --signal=TERM --kill-after=5s "$duration" "$@" 2>&1 |
    timeout --signal=TERM --kill-after=1s "${reader}s" head -c "$((limit + 1))" > "$output" ||
    stages=("${PIPESTATUS[@]}")
  status="${stages[0]}"
  bytes="$(wc -c < "$output")" || return 2
  printf 'command=%s\ncapture=%s\n' "$status" "${stages[1]}" > "$output.status" || return 2
  if (( stages[1] != 0 || bytes > limit )); then
    printf 'candidate guest: incomplete or over-limit output: %s\n' "$output" >&2
    return 125
  fi
  if (( status != 0 )); then
    printf 'candidate guest: command failed (%s), retained %s\n' "$status" "$output" >&2
  fi
  return "$status"
}

source_unchanged() {
  [[ "$(git rev-parse --verify HEAD)" == "$(< "$evidence/source-head.txt")" ]] ||
    die 'source HEAD changed'
  git diff --quiet --ignore-submodules=none HEAD -- || die 'tracked source changed'
  sha256sum --check "$evidence/source-inputs.sha256"
}
assert_config() {
  local symbol config="$evidence/hyperv-acceptance.config"
  private_file "$config" $((1024 * 1024))
  for symbol in CONFIG_ARCH_X86_64 CONFIG_PLAT_HYPERV CONFIG_APPHYPERVACCEPTANCE \
    CONFIG_LIBVMBUS CONFIG_LIBUKBLKDEV CONFIG_LIBSTORVSC CONFIG_LIBUKNETDEV \
    CONFIG_LIBNETVSC CONFIG_OPTIMIZE_PIE CONFIG_LIBUKPAGING; do
    [[ "$(grep -Fxc "${symbol}=y" "$config")" == 1 ]] || die "required configuration: $symbol"
  done
  [[ "$(grep -Fxc 'CONFIG_UKPLAT_CPU_MAXCOUNT=1' "$config")" == 1 ]] || die 'CPU count must be one'
  if grep -Eq '^CONFIG_(APPHYPERVACCEPTANCE_(NETWORK_APPLICATION|PERSISTENCE)|APPHYPERVSMPWORKLOAD|LIBLWIP|HYPERV_FIXED_SMP_WORKLOAD|LIBSTORVSC_(GUARDED_IO|LUN_DISCOVERY))=y$' "$config"; then
    die 'unexpected network-application, persistence or SMP configuration'
  fi
}

if [[ "$1" == build ]]; then
  new_path "$guest"
  mkdir -m 700 "$guest"
  mkdir -m 700 "$evidence" "$guest/tmp" "$guest/cache" "$guest/xdg-config" \
    "$guest/zig-global-cache" "$guest/empty-packages" "$guest/public-image" "$guest/image"
  mkdir -m 700 "$evidence/logs" "$guest/public-image/zig-local-cache" "$guest/public-image/out" \
    "$guest/image/zig-local-cache" "$guest/image/out"
  export TMPDIR="$guest/tmp" XDG_CACHE_HOME="$guest/cache" XDG_CONFIG_HOME="$guest/xdg-config"
  export ZIG_GLOBAL_CACHE_DIR="$guest/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$guest/public-image/zig-local-cache"

  git diff --quiet --ignore-submodules=none HEAD -- || die 'clean tracked source required'
  git rev-parse --verify HEAD > "$evidence/source-head.txt"
  git rev-parse 'HEAD^{tree}' > "$evidence/source-tree.txt"
  timeout --signal=TERM --kill-after=5s 120s git archive --format=tar HEAD |
    timeout --signal=TERM --kill-after=1s 126s sha256sum > "$evidence/source-archive.sha256"
  public="$repo/support/tools/hyperv/public_image"
  sha256sum "$script" "$repo/build.zig" "$repo/build.zig.zon" \
    "$public/build.zig" "$public/build.zig.zon" \
    "$repo/support/apps/hyperv-acceptance/defconfig" > "$evidence/source-inputs.sha256"
  : > "$evidence/tool-files.sha256"
  for tool in zig llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip \
    make bison flex m4 bash git timeout head sha256sum cp awk grep readlink \
    stat sort find cmp od tr uname dirname wc cut mkdir; do
    path="$(native_tool "$tool")"
    printf '%s %s\n' "$tool" "$path"
    sha256sum "$path" >> "$evidence/tool-files.sha256"
  done > "$evidence/tool-paths.txt"
  zig="$(native_tool zig)"
  [[ "$("$zig" version)" == 0.16.0 ]] || die 'Zig 0.16.0 required'
  printf '0.16.0\n' > "$evidence/zig-version.txt"
  private_dir "$root/firmware"
  private_file "$root/firmware/code.fd" $((16 * 1024 * 1024))
  private_file "$root/firmware/vars.fd" $((4 * 1024 * 1024))
  sha256sum "$root/firmware/code.fd" "$root/firmware/vars.fd" > "$evidence/firmware.sha256"

  export ZIG_LOCAL_CACHE_DIR="$guest/public-image/zig-local-cache"
  packages="$guest/empty-packages"
  cli_args=(
    --build-file "$public/build.zig" --cache-dir "$ZIG_LOCAL_CACHE_DIR"
    --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" --prefix "$guest/public-image/out"
    -Doptimize=ReleaseSafe -j2 install --summary all
  )
  if run_bounded "$evidence/logs/cli-system-check.log" 900 $((8 * 1024 * 1024)) \
    "$zig" build --system "$packages" "${cli_args[@]}"; then
    :
  else
    # Only the pinned package's missing --system input permits restoration.
    [[ $? == 1 ]] || die 'CLI failure is not a missing-package compiler error'
    package_hash="$(awk -F '"' '/^[[:space:]]*\.hash = "/ { n++; value=$2 } END { if (n != 1) exit 1; print value }' "$public/build.zig.zon")"
    log="$evidence/logs/cli-system-check.log"
    grep -Fq "$package_hash" "$log" || die 'CLI failure is not the pinned missing package'
    if ! { grep -Fq "unable to open system package directory '" "$log" && grep -Fq FileNotFound "$log"; } &&
       ! grep -Fq "error: package not found at '$packages/$package_hash'" "$log"; then
      die 'CLI failure is not a missing-system-package error'
    fi
    mkdir -m 700 "$guest/public-image/restore" "$guest/public-image/restore-cache"
    cp --no-preserve=mode,ownership "$public/build.zig" "$public/build.zig.zon" \
      "$guest/public-image/restore/"
    export ZIG_LOCAL_CACHE_DIR="$guest/public-image/restore-cache"
    run_bounded "$evidence/logs/cli-restore.log" 300 $((8 * 1024 * 1024)) \
      "$zig" build --build-file "$guest/public-image/restore/build.zig" --fetch=all -j2 \
        --cache-dir "$ZIG_LOCAL_CACHE_DIR" --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" \
        --prefix "$guest/public-image/restore-out"
    cmp "$public/build.zig" "$guest/public-image/restore/build.zig"
    cmp "$public/build.zig.zon" "$guest/public-image/restore/build.zig.zon"
    packages="$guest/public-image/restore/zig-pkg"
    export ZIG_LOCAL_CACHE_DIR="$guest/public-image/zig-local-cache"
    run_bounded "$evidence/logs/cli-build.log" 900 $((8 * 1024 * 1024)) \
      "$zig" build --system "$packages" "${cli_args[@]}"
  fi

  export ZIG_LOCAL_CACHE_DIR="$guest/image/zig-local-cache"
  bison="$(native_tool bison)"
  bison_data="${BISON_PKGDATADIR:-$("$bison" --print-datadir)}"
  bison_data="$(readlink -f -- "$bison_data")"
  canonical_path "$bison_data"
  [[ -d "$bison_data" ]] || die 'Bison data directory required'
  m4="$(native_tool m4)"
  shell="$(native_tool bash)"
  # The existing root facade strips ambient build variables. Its narrow native
  # environment contract forwards these paths and fixed UMASK=0077 without
  # changing canonical passwd HOME or the shared facade lock.
  printf '{"bison_data":"%s","m4":"%s","schema":"unikraft_native_make_environment_v1","shell":"%s","tmp":"%s","xdg_cache":"%s","xdg_config":"%s","zig_global_cache":"%s","zig_local_cache":"%s"}\n' \
    "$bison_data" "$m4" "$shell" "$TMPDIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" \
    "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR" > "$evidence/native-make-environment.json"
  cp --no-preserve=mode,ownership "$repo/support/apps/hyperv-acceptance/defconfig" \
    "$evidence/hyperv-acceptance.config"
  image_args=(
    --system "$guest/empty-packages" --cache-dir "$ZIG_LOCAL_CACHE_DIR"
    --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" --prefix "$guest/image/out"
    -Doptimize=ReleaseSafe -j2
    "-Dapp=$repo/support/apps/hyperv-acceptance" "-Doutput=$guest/image/build"
    "-Dconfig=$evidence/hyperv-acceptance.config"
    "-Dnative-make-environment=$evidence/native-make-environment.json"
    '-Dcompiler=zig cc -target x86_64-freestanding-none' -Dcompiler-targeted=true
    '-Dhost-cc=zig cc' '-Dhost-cxx=zig c++' -Dhost-cflags=-fno-sanitize=null
    '-Dmake-arg=AR=zig ar' -Dmake-arg=NM=llvm-nm -Dmake-arg=OBJCOPY=llvm-objcopy
    -Dmake-arg=OBJDUMP=llvm-objdump -Dmake-arg=READELF=llvm-readelf
    -Dmake-arg=STRIP=llvm-strip -Dmake-arg=UK_CFLAGS=-std=gnu17
    -Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt --summary all
  )
  run_bounded "$evidence/logs/olddefconfig.log" 600 $((8 * 1024 * 1024)) \
    "$zig" build olddefconfig "${image_args[@]}"
  assert_config
  run_bounded "$evidence/logs/native-images.log" 1800 $((8 * 1024 * 1024)) \
    "$zig" build native-images -Dnative-profile=hyperv-x86_64-efi-netvsc "${image_args[@]}"
  assert_config
  efi="$guest/image/build/helloworld_hyperv-x86_64-efi-netvsc"
  cli="$guest/public-image/out/bin/uk-hyperv-public-image"
  artifact "$efi" $((64 * 1024 * 1024))
  artifact "$efi.dbg" $((64 * 1024 * 1024))
  artifact "$cli" $((64 * 1024 * 1024))
  [[ -x "$cli" ]] || die 'native public-image CLI not executable'
  source_unchanged
  sha256sum --check "$evidence/tool-files.sha256" "$evidence/firmware.sha256"
  sha256sum "$cli" "$efi" "$efi.dbg" "$evidence/hyperv-acceptance.config" \
    "$evidence/native-make-environment.json" > "$evidence/build-artifacts.sha256"
  printf 'Native public CPU1 EFI and ReleaseSafe CLI built; no boot acceptance claimed.\n'
  exit 0
fi

private_dir "$guest"
private_dir "$evidence"
private_dir "$guest/tmp"
private_file "$evidence/build-artifacts.sha256" 65536
source_unchanged
sha256sum --check "$evidence/build-artifacts.sha256" "$evidence/firmware.sha256"
assert_config
qemu="$3"
artifact "$qemu" $((64 * 1024 * 1024))
[[ -x "$qemu" ]] || die 'QEMU not executable'
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die 'ordinary-UID KVM access required'
repository_id="${QUALIFICATION_REPOSITORY_ID:?repository ID from github.repository_id required}"
source_job="${QUALIFICATION_SOURCE_JOB:?declared source job required}"
[[ "$source_job" == "${GITHUB_JOB:?real job ID required}" && "$source_job" == zig-hyperv ]] ||
  die 'declared source job must match the actual zig-hyperv job'
if [[ ${GITHUB_REPOSITORY_ID+x} ]]; then
  [[ "$repository_id" == "$GITHUB_REPOSITORY_ID" ]] || die 'repository ID metadata mismatch'
fi
[[ "${GITHUB_REPOSITORY:?}" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]] || die 'invalid repository'
for value in "$repository_id" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"; do
  [[ "$value" =~ ^[1-9][0-9]{0,19}$ ]] || die 'invalid positive source identifier'
  [[ ${#value} -lt 20 || "$value" < 18446744073709551615 || "$value" == 18446744073709551615 ]] ||
    die 'source identifier exceeds u64'
done
[[ "${GITHUB_SHA:?}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ &&
   "$GITHUB_SHA" == "$(< "$evidence/source-head.txt")" ]] || die 'source head must match the actual checkout'
workflow="${GITHUB_WORKFLOW_REF:?}"
workflow_tail="${workflow#"$GITHUB_REPOSITORY"/.github/workflows/}"
[[ "$workflow" == "$GITHUB_REPOSITORY"/.github/workflows/* &&
   "$workflow_tail" =~ ^[a-zA-Z0-9_.-]+\.ya?ml@refs/[a-zA-Z0-9_./-]+$ &&
   "$workflow" != *..* && ${#workflow} -le 500 ]] || die 'invalid workflow source'
new_path "$evidence/boot"
new_path "$guest/packaging"
new_path "$guest/export"
mkdir -m 700 "$evidence/boot"
export TMPDIR="$guest/tmp" XDG_CACHE_HOME="$guest/cache" XDG_CONFIG_HOME="$guest/xdg-config"
export ZIG_GLOBAL_CACHE_DIR="$guest/zig-global-cache" ZIG_LOCAL_CACHE_DIR="$guest/public-image/zig-local-cache"
sha256sum "$qemu" > "$evidence/boot/qemu-before.sha256"
cli="$guest/public-image/out/bin/uk-hyperv-public-image"
efi="$guest/image/build/helloworld_hyperv-x86_64-efi-netvsc"
boot_deadline=$(($(monotonic_cs) + 48000))

# Invoke the native CLI, never a QEMU wrapper. Its child constructs the strict
# TMPDIR-only execveat environment and owns the four single-CPU boot leaves.
run_bounded "$evidence/boot/prepare-result.json" 480 65536 \
  "$cli" prepare --efi "$efi" --qemu "$qemu" \
    --ovmf-code "$root/firmware/code.fd" --ovmf-vars "$root/firmware/vars.fd" \
    --state-dir "$guest/packaging" --timeout 60
run_bounded "$evidence/boot/matrix.json" 60 65536 \
  "$cli" validate-matrix --state-dir "$guest/packaging"
# This is an assertion over the preceding physical reload, not generated evidence.
modes='"legacy-apic":{"apic_path":"legacy-xapic","io_ready":false,"platform_ready":true},"x2apic":{"apic_path":"x2apic","io_ready":false,"platform_ready":true}'
expected='{"boots":{"raw":{'"$modes"'},"vhd":{'"$modes"'}},"platform_marker":"UK_HYPERV_PLATFORM_READY","scope":"platform-only"}'
[[ "$(< "$evidence/boot/matrix.json")" == "$expected" ]] || die 'unexpected native four-mode matrix'
run_bounded "$evidence/boot/export-digest.txt" 90 65536 \
  "$cli" export-prepared --state-dir "$guest/packaging" --artifact-dir "$guest/export" \
    --source-repository "$GITHUB_REPOSITORY" --source-repository-id "$repository_id" \
    --source-workflow-ref "$GITHUB_WORKFLOW_REF" --source-job "$source_job" \
    --source-run-id "$GITHUB_RUN_ID" --source-run-attempt "$GITHUB_RUN_ATTEMPT" \
    --source-head-sha "$GITHUB_SHA"
digest="$(< "$evidence/boot/export-digest.txt")"
[[ "$digest" =~ ^[0-9a-f]{64}$ && "$(wc -c < "$evidence/boot/export-digest.txt")" == 65 ]] ||
  die 'invalid native export digest'
manifest="$guest/export/prepared-image-manifest.json"
private_file "$manifest" 65536
private_file "$guest/export/unikraft.vhd" $((66 * 1024 * 1024 + 512))
[[ "$(stat -c %s "$guest/export/unikraft.vhd")" == "$((66 * 1024 * 1024 + 512))" ]] ||
  die 'unexpected exported fixed VHD size'
[[ "$(find "$guest/export" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == $'prepared-image-manifest.json\nunikraft.vhd' ]] ||
  die 'unexpected export entries'
[[ "$(sha256sum "$manifest" | cut -d ' ' -f 1)" == "$digest" ]] || die 'manifest digest mismatch'
sha256sum --check "$evidence/boot/qemu-before.sha256" "$evidence/build-artifacts.sha256" \
  "$evidence/firmware.sha256" > "$evidence/boot/unchanged.txt"
sha256sum "$manifest" "$guest/export/unikraft.vhd" > "$evidence/boot/export-files.sha256"
printf 'Four native public platform-only boots reloaded and native-v4 export retained locally: %s\n' "$digest"
