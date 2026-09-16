/* SPDX-License-Identifier: BSD-3-Clause */
#include "platform.h"
#include "identity.h"
#include <stdio.h>
#include <string.h>
#include <uk/alloc.h>
#include <uk/paging.h>
#include "wasi.h"
#include "workloads.h"

#if !WAMR_APP_VARIANT
extern const unsigned char wamr_fixture[];
extern const size_t wamr_fixture_size;

#if WAMR_HAS_COREMARK
#include "coremark.h"
extern const unsigned char wamr_coremark[], wamr_coremark_nofp[];
extern const size_t wamr_coremark_size, wamr_coremark_nofp_size;
static struct wamr_wasi_output guest_output;

static void base64(const uint8_t *bytes, size_t length)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i;
	uint32_t value;

	for (i = 0; i < length; i += 3) {
		value = (uint32_t)bytes[i] << 16;
		if (i + 1 < length)
			value |= (uint32_t)bytes[i + 1] << 8;
		if (i + 2 < length)
			value |= bytes[i + 2];
		printf("%c%c%c%c", alphabet[value >> 18], alphabet[(value >> 12) & 63],
		       i + 1 < length ? alphabet[(value >> 6) & 63] : '=',
		       i + 2 < length ? alphabet[value & 63] : '=');
	}
}

static int coremark(wamr_aot_config *config, const char *name,
		    const uint8_t *bytes, size_t length,
		    const char *wasm_hash, const char *cwasm_hash)
{
	wamr_aot_result r = wamr_wasi_check(config, bytes, length, &guest_output);
	int correct = r.kind == WAMR_AOT_RETURNED ||
		      (r.kind == WAMR_AOT_EXIT && r.detail == 0);

	correct &= wamr_coremark_crc_ok(guest_output.stdout_bytes,
				       guest_output.stdout_length);
	correct &= !guest_output.output_error && !guest_output.pending_stdout &&
		   !guest_output.pending_stderr && !guest_output.unsupported_clock &&
		   !guest_output.stderr_length && guest_output.realtime_supported;
	printf("WAMR_NATIVE_WASI={\"version\":1,\"correctness_only\":true,"
	       "\"workload\":\"%s\",\"wasm_sha256\":\"%s\",\"cwasm_sha256\":\"%s\","
	       "\"terminal\":%u,\"detail\":%u,\"crc_ok\":%s,\"output_error\":%u,"
	       "\"pending_stdout\":%u,\"pending_stderr\":%u,"
	       "\"unsupported_clock\":%u,\"realtime_supported\":%s,"
	       "\"realtime_capability_version\":%u,\"realtime_source\":%u,"
	       "\"realtime_resolution_ns\":%lu,\"efi_accuracy_pptrillion\":%u,"
	       "\"efi_sample_span_ns\":%lu,\"epoch_accuracy_ns\":null,"
	       "\"stdout_base64\":\"",
	       name, wasm_hash, cwasm_hash, r.kind, r.detail,
	       correct ? "true" : "false", guest_output.output_error,
	       guest_output.pending_stdout, guest_output.pending_stderr,
	       guest_output.unsupported_clock,
	       guest_output.realtime_supported ? "true" : "false",
	       guest_output.realtime_caps.version,
	       guest_output.realtime_caps.source,
	       guest_output.realtime_caps.resolution_ns,
	       guest_output.realtime_caps.efi_accuracy_pptrillion,
	       guest_output.realtime_caps.sample_span_ns);
	base64(guest_output.stdout_bytes, guest_output.stdout_length);
	printf("\",\"stderr_base64\":\"");
	base64(guest_output.stderr_bytes, guest_output.stderr_length);
	printf("\"}\n");
	return correct;
}
#endif

int main(int argc __unused, char **argv __unused)
{
	struct wamr_platform platform;
	wamr_aot_config config;
	wamr_aot_handle *instance = NULL;
	wamr_aot_value value;
	wamr_aot_result result = { .kind = WAMR_AOT_ERROR };
	int status, checks = 0, wasi_ok = 1;
	uint64_t now;
	uint32_t answer = 0;
	unsigned long table_bytes = 0;
	size_t level;

	status = wamr_platform_config(&platform, uk_alloc_get_default(), &config);
	if (status)
		goto done;
	status = wamr_platform_selftest(&platform, &config);
	if (status)
		goto done;
	checks = 1;
	status = config.monotonic_ns(&platform, &now);
	if (status)
		goto done;
	result = wamr_aot_load(&config, wamr_fixture, wamr_fixture_size,
			       NULL, 0, &instance);
	if (result.kind != WAMR_AOT_RETURNED)
		goto done;
	result = wamr_aot_start(instance);
	if (result.kind != WAMR_AOT_RETURNED)
		goto done;
	result = wamr_aot_call(instance, (const uint8_t *)"answer", 6,
			       NULL, 0, &value, 1);
	if (result.kind != WAMR_AOT_RETURNED || result.count != 1 ||
	    value.kind != WAMR_AOT_I32 || value.bits != 42)
		goto done;
	answer = 42;
	value = (wamr_aot_value){ .kind = WAMR_AOT_I32, .bits = 1 };
	result = wamr_aot_call(instance, (const uint8_t *)"grow", 4,
			       &value, 1, &value, 1);
	if (result.kind != WAMR_AOT_RETURNED || result.count != 1 ||
	    value.kind != WAMR_AOT_I32 || value.bits != 2)
		goto done;
	result = wamr_aot_call(instance, (const uint8_t *)"trap", 4,
			       NULL, 0, NULL, 0);
	if (result.kind != WAMR_AOT_TRAP ||
	    result.detail != WAMR_AOT_UNREACHABLE)
		goto done;
	checks = 2;
done:
	if (instance)
		wamr_aot_destroy(instance);
#if WAMR_HAS_COREMARK
	if (!status && checks == 2) {
		wasi_ok = coremark(&config, "coremark", wamr_coremark,
				  wamr_coremark_size, WAMR_COREMARK_WASM_SHA256,
				  WAMR_COREMARK_CWASM_SHA256);
		wasi_ok &= coremark(&config, "coremark-nofp", wamr_coremark_nofp,
				   wamr_coremark_nofp_size, WAMR_COREMARK_NOFP_WASM_SHA256,
				   WAMR_COREMARK_NOFP_CWASM_SHA256);
	}
#endif
	if (platform.pt)
		for (level = 0; level < UK_PAL_PT_LEVELS; level++)
			table_bytes += platform.pt->nr_pt_pages[level] * 4096;
	/* Bounded compute-only correctness record, never a deployment receipt or
	 * a benchmark. The complete EFI/disk hashes belong to host packaging. */
	printf("WAMR_NATIVE_COMPUTE={\"version\":1,\"workload\":\"tiny\","
	       "\"wamr_revision\":\"%s\",\"wasm_sha256\":\"%s\","
	       "\"cwasm_sha256\":\"%s\",\"runtime_sha256\":\"%s\","
	       "\"platform_status\":%d,\"checks\":%d,\"answer\":%u,"
	       "\"terminal\":%u,\"detail\":%u,\"reserved_bytes\":%lu,"
	       "\"frame_bytes\":%lu,\"accessible_bytes\":%lu,"
	       "\"allocation_bytes\":%lu,\"system_page_table_bytes\":%lu,"
	       "\"error_name\":\"%s\"}\n",
	       WAMR_REVISION, WAMR_WASM_SHA256, WAMR_CWASM_SHA256,
	       WAMR_LIBRARY_SHA256, status, checks, answer, result.kind,
	       result.detail, platform.reserved_bytes, platform.frame_bytes,
	       platform.accessible_bytes, platform.allocation_bytes, table_bytes,
	       result.error_name ? result.error_name : "");
	if (!status && checks == 2 && answer == 42 && wasi_ok &&
	    !platform.reserved_bytes && !platform.frame_bytes &&
	    !platform.accessible_bytes && !platform.allocation_bytes) {
		printf("WAMR_NATIVE_AOT_OK answer=42 teardown=0\n");
		return 0;
	}
	return 1;
}
#else
int main(int argc, char **argv)
{
	return wamr_workload_main(argc, argv);
}
#endif
