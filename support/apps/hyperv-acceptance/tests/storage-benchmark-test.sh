#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
cd "$(dirname "$0")/../../../.."
mkdir -p .d/workload-native/scratch .d/workload-native/cache
export TMPDIR="$PWD/.d/workload-native/scratch"
export XDG_CACHE_HOME="$PWD/.d/workload-native/cache"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$XDG_CACHE_HOME/global}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$XDG_CACHE_HOME/local}"

"${ZIG:-zig}" cc -std=gnu11 -Wall -Wextra -Werror \
	-DSTORVSC_HOST_TEST \
	-DSTORAGE_BENCHMARK_HOST_TEST \
	-DSTORAGE_BENCHMARK_READ_TIMEOUT_NS=50000ULL \
	-DSTORAGE_BENCHMARK_POLL_NS=10000ULL \
	-DCONFIG_LIBSTORVSC_QUEUE_DEPTH=32 \
	-DCONFIG_LIBSTORVSC_MAX_TRANSFER_PAGES=33 \
	-DCONFIG_LIBUKALLOC_IFSTATS=1 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK=1 \
	'-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_RUN_ID="00112233445566778899aabbccddeeff"' \
	'-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_DISK_ID="102132435465768798a9bacbdcedfe0f"' \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_SECTORS=8388608 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_SECTOR_SIZE=512 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_IDENTITY_POLICY=2 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_LUN=7 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_SLOTS=32 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_MAX_TRANSFER_BYTES=131072 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_WARMUP_OPS=4 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_STEADY_OPS=8 \
	-DCONFIG_APPHYPERVACCEPTANCE_STORAGE_BENCHMARK_TRIALS=2 \
	-I support/build/tests/storvsc-host-include \
	-I drivers/hyperv/storvsc/include \
	-I support/apps/hyperv-acceptance \
	support/apps/hyperv-acceptance/acceptance_protocol.c \
	support/apps/hyperv-acceptance/storage_benchmark.c \
	support/apps/hyperv-acceptance/tests/storage-benchmark-test.c \
	-o .d/workload-native/storage-benchmark-test

.d/workload-native/storage-benchmark-test > .d/workload-native/storage-benchmark.log
grep -q '^storage-benchmark-test: synthetic cases passed$' .d/workload-native/storage-benchmark.log
cat .d/workload-native/storage-benchmark.log
