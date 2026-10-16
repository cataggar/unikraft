/* SPDX-License-Identifier: BSD-3-Clause */
#include "../http_protocol.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void test_deterministic_body_and_boot_id(void)
{
	uint8_t body_a[UK_HYPERV_HTTP_BODY_LEN];
	uint8_t body_b[UK_HYPERV_HTTP_BODY_LEN];
	char boot_id[17];

	memset(body_a, 0xaa, sizeof(body_a));
	memset(body_b, 0x55, sizeof(body_b));
	uk_hyperv_http_fill_body(body_a);
	uk_hyperv_http_fill_body(body_b);
	assert(memcmp(body_a, body_b, UK_HYPERV_HTTP_BODY_LEN) == 0);
	assert(memcmp(body_a,
		      "unikraft-hyperv-http-1k-payload-line-00:"
		      "0123456789abcdef0123456\n",
		      64) == 0);
	assert(memcmp(body_a + 15U * 64U,
		      "unikraft-hyperv-http-1k-payload-line-15:"
		      "0123456789abcdef0123456\n",
		      64) == 0);

	uk_hyperv_http_format_boot_id(0x0123456789abcdefULL, boot_id);
	assert(strcmp(boot_id, "0123456789abcdef") == 0);
	assert(uk_hyperv_http_valid_boot_id_hex(boot_id, 16) == 1);

	uk_hyperv_http_format_boot_id(0ULL, boot_id);
	assert(strcmp(boot_id, "0000000000000001") == 0);
	assert(uk_hyperv_http_valid_boot_id_hex(boot_id, 16) == 1);

	assert(uk_hyperv_http_valid_boot_id_hex("0000000000000000", 16) == 0);
	assert(uk_hyperv_http_valid_boot_id_hex("0123456789abcdeg", 16) == 0);
	assert(uk_hyperv_http_valid_boot_id_hex("0123456789abcde", 15) == 0);
}

static void test_keep_alive_and_close_semantics(void)
{
	static const char req_default[] =
		"GET /benchmark HTTP/1.1\r\n"
		"Host: 10.87.0.5:8080\r\n"
		"User-Agent: unikraft-bench/1.0\r\n"
		"\r\n";
	static const char req_close[] =
		"GET / HTTP/1.1\r\n"
		"Host: 10.87.0.5\r\n"
		"Connection: keep-alive, ClOsE\r\n"
		"\r\n";
	static const char req_http10_default[] =
		"GET / HTTP/1.0\r\n"
		"Host: 10.87.0.5\r\n"
		"\r\n";
	static const char req_http10_ka[] =
		"HEAD /ready HTTP/1.0\r\n"
		"Connection: Keep-Alive\r\n"
		"\r\n";
	struct uk_hyperv_http_request parsed;
	enum uk_hyperv_http_scan_status status;

	status = uk_hyperv_http_scan_request(
		(const uint8_t *)req_default, sizeof(req_default) - 1U,
		&parsed);
	assert(status == UK_HYPERV_HTTP_SCAN_OK);
	assert(parsed.method == UK_HYPERV_HTTP_METHOD_GET);
	assert(parsed.http_minor == 1);
	assert(parsed.keep_alive == 1);
	assert(parsed.header_lines == 2);
	assert(parsed.consumed == sizeof(req_default) - 1U);
	assert(parsed.uri_length == 10U);
	assert(memcmp(req_default + parsed.uri_offset, "/benchmark", 10U) == 0);

	status = uk_hyperv_http_scan_request(
		(const uint8_t *)req_close, sizeof(req_close) - 1U,
		&parsed);
	assert(status == UK_HYPERV_HTTP_SCAN_OK);
	assert(parsed.keep_alive == 0);

	status = uk_hyperv_http_scan_request(
		(const uint8_t *)req_http10_default,
		sizeof(req_http10_default) - 1U, &parsed);
	assert(status == UK_HYPERV_HTTP_SCAN_OK);
	assert(parsed.http_minor == 0);
	assert(parsed.keep_alive == 0);

	status = uk_hyperv_http_scan_request(
		(const uint8_t *)req_http10_ka,
		sizeof(req_http10_ka) - 1U, &parsed);
	assert(status == UK_HYPERV_HTTP_SCAN_OK);
	assert(parsed.method == UK_HYPERV_HTTP_METHOD_HEAD);
	assert(parsed.http_minor == 0);
	assert(parsed.keep_alive == 1);
}

static void test_partial_accumulation_and_pipelining(void)
{
	static const char pipelined[] =
		"GET /first HTTP/1.1\r\nHost: peer\r\n\r\n"
		"GET /second HTTP/1.1\r\nConnection: close\r\n\r\n";
	uint8_t accum[UK_HYPERV_HTTP_MAX_REQUEST_LEN];
	struct uk_hyperv_http_request parsed;
	size_t total_len = sizeof(pipelined) - 1U;
	size_t first_len = 35U;
	size_t i;

	for (i = 1; i < first_len; i++) {
		memcpy(accum, pipelined, i);
		assert(uk_hyperv_http_scan_request(accum, i, &parsed) ==
		       UK_HYPERV_HTTP_SCAN_INCOMPLETE);
		assert(parsed.consumed == 0);
	}

	memcpy(accum, pipelined, total_len);
	assert(uk_hyperv_http_scan_request(accum, total_len, &parsed) ==
	       UK_HYPERV_HTTP_SCAN_OK);
	assert(parsed.consumed == first_len);
	assert(parsed.keep_alive == 1);
	assert(memcmp(accum + parsed.uri_offset, "/first", 6U) == 0);

	memmove(accum, accum + parsed.consumed, total_len - parsed.consumed);
	total_len -= parsed.consumed;
	assert(uk_hyperv_http_scan_request(accum, total_len, &parsed) ==
	       UK_HYPERV_HTTP_SCAN_OK);
	assert(parsed.consumed == total_len);
	assert(parsed.keep_alive == 0);
	assert(memcmp(accum + parsed.uri_offset, "/second", 7U) == 0);
}

static void test_malformed_and_oversized_rejection(void)
{
	static const char bare_lf[] = "GET / HTTP/1.1\nHost: a\r\n\r\n";
	static const char bare_cr[] = "GET / HTTP/1.1\rHost: a\r\n\r\n";
	static const char bad_method[] = "POST / HTTP/1.1\r\nHost: a\r\n\r\n";
	static const char bad_uri[] = "GET index.html HTTP/1.1\r\n\r\n";
	static const char bad_version[] = "GET / HTTP/2.0\r\nHost: a\r\n\r\n";
	static const char bad_header_space[] =
		"GET / HTTP/1.1\r\nHost : a\r\n\r\n";
	static const char bad_chunked[] =
		"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
	static const char huge_cl[] =
		"GET / HTTP/1.1\r\nContent-Length: 8192\r\n\r\n";
	uint8_t buf[UK_HYPERV_HTTP_MAX_REQUEST_LEN + 64U];
	struct uk_hyperv_http_request parsed;
	size_t pos;
	unsigned int h;

	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bare_lf, sizeof(bare_lf) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bare_cr, sizeof(bare_cr) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bad_method, sizeof(bad_method) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bad_uri, sizeof(bad_uri) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bad_version, sizeof(bad_version) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bad_header_space,
		       sizeof(bad_header_space) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)bad_chunked, sizeof(bad_chunked) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_MALFORMED);
	assert(uk_hyperv_http_scan_request(
		       (const uint8_t *)huge_cl, sizeof(huge_cl) - 1U,
		       &parsed) == UK_HYPERV_HTTP_SCAN_TOO_LARGE);

	/* Too many header lines (> 32) -> 413 */
	memcpy(buf, "GET / HTTP/1.1\r\n", 16U);
	pos = 16U;
	for (h = 0; h < UK_HYPERV_HTTP_MAX_HEADER_LINES + 1U; h++) {
		memcpy(buf + pos, "X-H: 1\r\n", 8U);
		pos += 8U;
	}
	memcpy(buf + pos, "\r\n", 2U);
	pos += 2U;
	assert(uk_hyperv_http_scan_request(buf, pos, &parsed) ==
	       UK_HYPERV_HTTP_SCAN_TOO_LARGE);

	/* Single line exceeding UK_HYPERV_HTTP_MAX_LINE_LEN -> 413 */
	memset(buf, 'a', UK_HYPERV_HTTP_MAX_LINE_LEN + 10U);
	assert(uk_hyperv_http_scan_request(
		       buf, UK_HYPERV_HTTP_MAX_LINE_LEN + 10U, &parsed) ==
	       UK_HYPERV_HTTP_SCAN_TOO_LARGE);
}

static void test_response_builders(void)
{
	uint8_t body[UK_HYPERV_HTTP_BODY_LEN];
	uint8_t resp[UK_HYPERV_HTTP_MAX_RESPONSE_LEN];
	char boot_id[17];
	size_t n;
	const char *hdr_end;

	uk_hyperv_http_fill_body(body);
	uk_hyperv_http_format_boot_id(0xdeadbeefcafe1234ULL, boot_id);

	n = uk_hyperv_http_build_ok_response(
		resp, sizeof(resp), boot_id, body,
		UK_HYPERV_HTTP_METHOD_GET, 1);
	assert(n > UK_HYPERV_HTTP_BODY_LEN);
	hdr_end = strstr((const char *)resp, "\r\n\r\n");
	assert(hdr_end != NULL);
	assert((size_t)(hdr_end - (const char *)resp) + 4U +
		       UK_HYPERV_HTTP_BODY_LEN == n);
	assert(strstr((const char *)resp, "Content-Length: 1024\r\n") != NULL);
	assert(strstr((const char *)resp, "Connection: keep-alive\r\n") != NULL);
	assert(strstr((const char *)resp,
		      "X-Unikraft-Boot-Id: deadbeefcafe1234\r\n") != NULL);
	assert(memcmp(hdr_end + 4, body, UK_HYPERV_HTTP_BODY_LEN) == 0);

	n = uk_hyperv_http_build_ok_response(
		resp, sizeof(resp), boot_id, body,
		UK_HYPERV_HTTP_METHOD_HEAD, 0);
	assert(n > 0 && n < UK_HYPERV_HTTP_BODY_LEN);
	assert(strstr((const char *)resp, "Connection: close\r\n") != NULL);

	n = uk_hyperv_http_build_error_response(
		resp, sizeof(resp), boot_id, 400);
	assert(n > 0);
	assert(memcmp(resp, "HTTP/1.1 400 Bad Request\r\n", 26U) == 0);

	n = uk_hyperv_http_build_error_response(
		resp, sizeof(resp), boot_id, 413);
	assert(n > 0);
	assert(memcmp(resp, "HTTP/1.1 413 Payload Too Large\r\n", 32U) == 0);
}

int main(void)
{
	test_deterministic_body_and_boot_id();
	test_keep_alive_and_close_semantics();
	test_partial_accumulation_and_pipelining();
	test_malformed_and_oversized_rejection();
	test_response_builders();
	return 0;
}
