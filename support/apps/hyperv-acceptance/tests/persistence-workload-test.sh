#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
cd "$(dirname "$0")/../../../.."
mkdir -p .d/workload-native/scratch .d/workload-native/cache
export TMPDIR="$PWD/.d/workload-native/scratch"
export XDG_CACHE_HOME="$PWD/.d/workload-native/cache"
export ZIG_GLOBAL_CACHE_DIR="$XDG_CACHE_HOME/global"
export ZIG_LOCAL_CACHE_DIR="$XDG_CACHE_HOME/local"
"${ZIG:-zig}" cc -std=gnu11 -Wall -Wextra -Werror \
	-I support/build/tests/storvsc-host-include \
	-I drivers/hyperv/storvsc/include \
	-I support/apps/hyperv-acceptance \
	-DHYPERV_PERSISTENCE_HOST_TEST \
	-DPERSISTENCE_TIMEOUT_NS=5000000ULL \
	-DPERSISTENCE_BIND_TIMEOUT_NS=50000000ULL \
	-DPERSISTENCE_POLL_NS=1000000ULL \
	'-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID="00112233445566778899aabbccddeeff"' \
	'-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID="102132435465768798a9bacbdcedfe0f"' \
	-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS=8388608 \
	-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE=512 \
	-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=2 \
	-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN=7 \
	support/apps/hyperv-acceptance/acceptance_protocol.c \
	support/apps/hyperv-acceptance/persistence.c \
	support/apps/hyperv-acceptance/storage_target.c \
	support/apps/hyperv-acceptance/tests/persistence-workload-test.c \
	-o .d/workload-native/persistence-workload-test
.d/workload-native/persistence-workload-test
