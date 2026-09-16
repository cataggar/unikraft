/* SPDX-License-Identifier: BSD-3-Clause */
#include "workloads.h"
#include "identity.h"
#include "workload-mode.h"
#include <stdio.h>
#include <string.h>
#include <uk/alloc.h>
#include <uk/console.h>
#include <uk/console/driver.h>

#if WAMR_APP_VARIANT
#if CONFIG_STACK_SIZE_PAGE_ORDER < 8
#error "Optional WAMR workloads require a separately provisioned 1 MiB native stack"
#endif
#if CONFIG_APPWAMRAOT_JIT_BOOT_MODE != WAMR_JIT_BOOT_MODE
#error "Solved JIT boot mode differs from the prepared artifact identity"
#endif

int wamr_workload_write(const uint8_t *bytes, size_t length)
{
	struct uk_console *selected = NULL, *console;
	unsigned int index, count = uk_console_count();

	if (!length || length > 16384 || bytes[length - 1] != '\n')
		return -1;
	if (count > 16)
		return -1;
	for (index = 0; index < count; index++) {
		console = uk_console_get(index);
		if (!console || console->dclass != UK_CONSOLE_CLASS_UART ||
		    !(console->flags & UK_CONSOLE_FLAG_STDOUT))
			continue;
		if (selected || (console->flags & UK_CONSOLE_FLAG_ASYNC_TX))
			return -1;
		selected = console;
	}
	/* uk_console_out/printf are best effort and discard driver errors.
	 * Use one real synchronous serial device, with no hidden partial retry. */
	if (!selected || uk_console_out_direct(selected, (const char *)bytes,
					     length) != (ssize_t)length)
		return -1;
	return 0;
}

void wamr_workload_observe(void *context, struct wamr_workload_pages *out)
{
	struct wamr_platform *p = context;

	*out = (struct wamr_workload_pages) {
		.reserved_bytes = p->reserved_bytes,
		.frame_bytes = p->frame_bytes,
		.accessible_bytes = p->accessible_bytes,
		.allocation_bytes = p->allocation_bytes,
	};
}

int wamr_workload_main(int argc, char **argv)
{
	const struct wamr_workload_facts facts = {
		.revision = WAMR_REVISION,
		.source_tree_sha256 = WAMR_SOURCE_TREE_SHA256,
		.runtime_sha256 = WAMR_LIBRARY_SHA256,
		.compiler_sha256 = WAMR_COMPILER_SHA256,
	};
	struct wamr_platform platform = { 0 };
	wamr_aot_config config;
	unsigned int mode = 0;
	int status, length;
	char completed[128];

	/* No transport/placement/image/physical-memory qualification is available
	 * here. In particular, a command line is not an independent attestation. */
	if (argc > 1 && !strcmp(argv[1], "measurement")) {
		printf("WAMR_NATIVE_WORKLOAD_REJECTED "
		       "independent-image-deployment-and-memory-qualification-unavailable\n");
		return 1;
	}
	if (wamr_workload_mode(WAMR_APP_VARIANT,
			      CONFIG_APPWAMRAOT_JIT_BOOT_MODE, argc, argv, &mode))
		goto invalid;
	status = wamr_platform_config(&platform, uk_alloc_get_default(), &config);
	if (!status)
		status = wamr_platform_selftest(&platform, &config);
	if (!status)
		status = wamr_workload_run(&config, &facts, mode);
	if (platform.reserved_bytes || platform.frame_bytes ||
	    platform.accessible_bytes || platform.allocation_bytes)
		status = 1;
	if (status) {
		printf("WAMR_NATIVE_WORKLOAD_FAILED status=%d\n", status);
		return 1;
	}
	length = snprintf(completed, sizeof(completed),
			  "WAMR_NATIVE_WORKLOAD_CHECK_OK variant=%d mode=%u teardown=0\n",
			  WAMR_APP_VARIANT, mode);
	if (length <= 0 || (size_t)length >= sizeof(completed))
		return 1;
	return wamr_workload_write((const uint8_t *)completed, length) ? 1 : 0;
invalid:
	printf("WAMR_NATIVE_WORKLOAD_REJECTED invalid-explicit-correctness-mode\n");
	return 1;
}
#endif
