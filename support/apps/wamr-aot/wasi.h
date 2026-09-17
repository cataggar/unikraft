/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef WAMR_NATIVE_WASI_CHECK_H
#define WAMR_NATIVE_WASI_CHECK_H
#include <wamr_aot.h>

/* Actual guest bytes, not logger output. All storage belongs to the caller. */
struct wamr_wasi_output {
	uint8_t stdout_bytes[4096], stderr_bytes[4096];
	size_t stdout_length, stderr_length;
	uint32_t output_error, pending_stdout, pending_stderr, unsupported_clock;
};

wamr_aot_result wamr_wasi_check(const wamr_aot_config *, const uint8_t *,
				size_t, struct wamr_wasi_output *);
#endif
