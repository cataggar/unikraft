#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
cd "$(dirname "$0")/../../../.."
mkdir -p .d/topology-native/scratch .d/topology-native/cache
export TMPDIR="$PWD/.d/topology-native/scratch"
export XDG_CACHE_HOME="$PWD/.d/topology-native/cache"
export ZIG_GLOBAL_CACHE_DIR="$XDG_CACHE_HOME/global"
export ZIG_LOCAL_CACHE_DIR="$XDG_CACHE_HOME/local"
"${ZIG:-zig}" cc -std=gnu11 -Wall -Wextra -Werror \
	-DSTORVSC_HOST_TEST \
	-include support/apps/hyperv-acceptance/tests/topology-host-config.h \
	-I support/build/tests/storvsc-host-include \
	-I drivers/hyperv/storvsc/include \
	-I support/apps/hyperv-acceptance \
	support/apps/hyperv-acceptance/acceptance_protocol.c \
	support/apps/hyperv-acceptance/storage_target.c \
	support/apps/hyperv-acceptance/tests/topology-workload-test.c \
	-o .d/topology-native/topology-workload-test
: >.d/topology-native/topology.log
for scenario in end timeout; do
	.d/topology-native/topology-workload-test "$scenario" \
		>>.d/topology-native/topology.log
done
if grep -Eq '00112233445566778899aabbccddeeff|102132435465768798a9bacbdcedfe0f|ffeeddccbbaa99887766554433221100|NETWORK.*(TX|RX|PASS)' \
	.d/topology-native/topology.log; then
	echo "topology-workload-test: leaked identifiers or network evidence" >&2
	exit 1
fi
echo "topology-workload-test: PASS (offer order, seeds, failures, timeout, no offer)"
