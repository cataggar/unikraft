/* SPDX-License-Identifier: BSD-3-Clause */
#include "../../../../support/build/tests/storvsc-host-include/uk/config.h"
#undef CONFIG_LIBSTORVSC_MAX_DEVICES
#undef CONFIG_LIBSTORVSC_MAX_LUNS
#define CONFIG_LIBSTORVSC_MAX_DEVICES STORAGE_BINDING_CONTROLLERS
#define CONFIG_LIBSTORVSC_MAX_LUNS 2
#define CONFIG_APPHYPERVACCEPTANCE_STORAGE_TOPOLOGY 1
#define CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_RUN_ID \
	"00112233445566778899aabbccddeeff"
#define CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_ID \
	"102132435465768798a9bacbdcedfe0f"
#define CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_ID \
	"ffeeddccbbaa99887766554433221100"
#define CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK0_SECTORS 2000
#define CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_DISK_NONZERO_SECTORS 2300
#define CONFIG_APPHYPERVACCEPTANCE_TOPOLOGY_NONZERO_LUN 3

#include "../../../../support/build/tests/storvsc-host-include/uk/print.h"
void storage_binding_capture_log(const char *format, ...);
#undef uk_pr_err
#undef uk_pr_debug
#define uk_pr_err(...) storage_binding_capture_log(__VA_ARGS__)
#define uk_pr_debug(...) storage_binding_capture_log(__VA_ARGS__)
