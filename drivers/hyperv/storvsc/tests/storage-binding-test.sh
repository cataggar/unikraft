#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu
cd "$(dirname "$0")/../../../.."
ZIG=${ZIG:-zig}
work="$PWD/.zig-cache/storage-binding"
mkdir -p "$work" "$PWD/.zig-cache/global"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-cache/global"
export TMPDIR="$work"

"$ZIG" build test-hyperv-persistence-workflow test-vmbus-lifecycle --summary all \
	>"$work/adjacent.log" 2>&1 || { cat "$work/adjacent.log"; exit 1; }
"$ZIG" test drivers/hyperv/storvsc/storvsc_core.zig \
	>"$work/core.log" 2>&1 || { cat "$work/core.log"; exit 1; }
"$ZIG" test drivers/hyperv/vmbus/vmbus_protocol.zig \
	>"$work/protocol-tests.log" 2>&1 || { cat "$work/protocol-tests.log"; exit 1; }
"$ZIG" build-obj drivers/hyperv/storvsc/storvsc_core.zig -O ReleaseSafe \
	-femit-bin="$work/core.o"
"$ZIG" build-obj drivers/hyperv/vmbus/vmbus_protocol.zig -O ReleaseSafe \
	-femit-bin="$work/protocol.o"
"$ZIG" cc -std=gnu11 -Wall -Wextra -Werror -Wno-unused-variable \
	-Wno-ignored-attributes -Wno-documentation -pthread \
	-DVMBUS_BUS_HOST_TEST -DVMBUS_EPOCH_ONLY_HOST_TEST \
	-Dvmbus_device_bind_epoch=vmbus_epoch_object_bind_epoch \
	-Dvmbus_device_bind_retry=vmbus_epoch_object_bind_retry \
	-Dvmbus_device_bind_ready=vmbus_epoch_object_bind_ready \
	-ffunction-sections -fdata-sections \
	-Isupport/build/tests/vmbus-host-include \
	-Isupport/build/tests/vmbus-include -Idrivers/hyperv/vmbus \
	-c drivers/hyperv/vmbus/vmbus_bus.c -o "$work/bus.o"
for controllers in 1 2; do
	"$ZIG" cc -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function \
		-pthread -ffunction-sections -fdata-sections -Wl,--gc-sections \
		-DSTORVSC_HOST_TEST -DHYPERV_PERSISTENCE_HOST_TEST \
		-DSTORAGE_BINDING_CONTROLLERS="$controllers" \
		-include drivers/hyperv/storvsc/tests/storage-binding-config.h \
		-DPERSISTENCE_TIMEOUT_NS=5000000ULL \
		-DPERSISTENCE_BIND_TIMEOUT_NS=50000000ULL \
		-DPERSISTENCE_POLL_NS=1000000ULL \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID='"00112233445566778899aabbccddeeff"' \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID='"102132435465768798a9bacbdcedfe0f"' \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS=1000 \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE=512 \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=2 \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH=0 \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET=0 \
		-DCONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN=0 \
		-Isupport/build/tests/storvsc-host-include \
		-Idrivers/hyperv/storvsc -Idrivers/hyperv/storvsc/include \
		-Isupport/apps/hyperv-acceptance \
		drivers/hyperv/storvsc/storvsc.c \
		support/apps/hyperv-acceptance/acceptance_protocol.c \
		support/apps/hyperv-acceptance/persistence.c \
		support/apps/hyperv-acceptance/storage_target.c \
		drivers/hyperv/storvsc/tests/storage-binding-test.c \
		"$work/core.o" "$work/protocol.o" "$work/bus.o" \
		-o "$work/driver-$controllers"
	count=33
	if [ "$controllers" = 1 ]; then count=4; fi
	test=0
	while [ "$test" -lt "$count" ]; do
		"$work/driver-$controllers" "$test"
		test=$((test + 1))
	done
	echo "storage-binding-test: PASS ($count cases, $controllers controllers)"
done
"$ZIG" cc -std=c11 -Wall -Wextra -Werror \
	-Isupport/apps/hyperv-acceptance \
	support/apps/hyperv-acceptance/acceptance_protocol.c \
	support/apps/hyperv-acceptance/tests/storage-binding-main-test.c \
	-o "$work/main"
"$work/main"
tail -n 1 "$work/core.log"
tail -n 1 "$work/protocol-tests.log"
echo "storage-binding: existing production/guarded-I/O and VMBus lifecycle PASS"
