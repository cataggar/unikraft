/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef UK_HYPERV_ACCEPTANCE_HTTP_PROTOCOL_H
#define UK_HYPERV_ACCEPTANCE_HTTP_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UK_HYPERV_HTTP_BODY_LEN 1024U
#define UK_HYPERV_HTTP_BOOT_ID_HEX_LEN 16U
#define UK_HYPERV_HTTP_MAX_REQUEST_LEN 4096U
#define UK_HYPERV_HTTP_MAX_HEADER_LINES 32U
#define UK_HYPERV_HTTP_MAX_LINE_LEN 1024U
#define UK_HYPERV_HTTP_MAX_URI_LEN 256U
#define UK_HYPERV_HTTP_MAX_RESPONSE_LEN 1536U

enum uk_hyperv_http_scan_status {
	UK_HYPERV_HTTP_SCAN_INCOMPLETE = 0,
	UK_HYPERV_HTTP_SCAN_OK = 1,
	UK_HYPERV_HTTP_SCAN_MALFORMED = -400,
	UK_HYPERV_HTTP_SCAN_TOO_LARGE = -413,
};

enum uk_hyperv_http_method {
	UK_HYPERV_HTTP_METHOD_NONE = 0,
	UK_HYPERV_HTTP_METHOD_GET = 1,
	UK_HYPERV_HTTP_METHOD_HEAD = 2,
};

struct uk_hyperv_http_request {
	enum uk_hyperv_http_method method;
	uint8_t http_minor;
	uint8_t keep_alive;
	uint16_t header_lines;
	size_t consumed;
	size_t uri_offset;
	size_t uri_length;
};

void uk_hyperv_http_fill_body(uint8_t out[UK_HYPERV_HTTP_BODY_LEN]);
void uk_hyperv_http_format_boot_id(uint64_t boot_id, char out[17]);
int uk_hyperv_http_valid_boot_id_hex(const char *hex, size_t len);

enum uk_hyperv_http_scan_status
uk_hyperv_http_scan_request(const uint8_t *buf, size_t len,
			    struct uk_hyperv_http_request *out);

size_t uk_hyperv_http_build_ok_response(
	uint8_t *out, size_t capacity,
	const char boot_id_hex[17],
	const uint8_t body[UK_HYPERV_HTTP_BODY_LEN],
	enum uk_hyperv_http_method method,
	int keep_alive);

size_t uk_hyperv_http_build_error_response(
	uint8_t *out, size_t capacity,
	const char boot_id_hex[17],
	int status_code);

#ifdef __cplusplus
}
#endif

#endif /* UK_HYPERV_ACCEPTANCE_HTTP_PROTOCOL_H */
