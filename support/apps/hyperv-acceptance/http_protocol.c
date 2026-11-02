/* SPDX-License-Identifier: BSD-3-Clause */
#include "http_protocol.h"

static int is_tchar(uint8_t ch)
{
	if ((ch >= '0' && ch <= '9') ||
	    (ch >= 'A' && ch <= 'Z') ||
	    (ch >= 'a' && ch <= 'z'))
		return 1;
	switch (ch) {
	case '!':
	case '#':
	case '$':
	case '%':
	case '&':
	case '\'':
	case '*':
	case '+':
	case '-':
	case '.':
	case '^':
	case '_':
	case '`':
	case '|':
	case '~':
		return 1;
	default:
		return 0;
	}
}

static uint8_t ascii_lower(uint8_t ch)
{
	if (ch >= 'A' && ch <= 'Z')
		return (uint8_t)(ch + ('a' - 'A'));
	return ch;
}

static int slice_iequals(const uint8_t *buf, size_t len, const char *lit)
{
	size_t index = 0;

	while (lit[index] != '\0') {
		if (index >= len)
			return 0;
		if (ascii_lower(buf[index]) !=
		    ascii_lower((uint8_t)lit[index]))
			return 0;
		index++;
	}
	return index == len;
}

static int slice_equals(const uint8_t *buf, size_t len, const char *lit)
{
	size_t index = 0;

	while (lit[index] != '\0') {
		if (index >= len || buf[index] != (uint8_t)lit[index])
			return 0;
		index++;
	}
	return index == len;
}

static void trim_ows(const uint8_t **start, size_t *len)
{
	const uint8_t *p = *start;
	size_t n = *len;

	while (n > 0 && (p[0] == ' ' || p[0] == '\t')) {
		p++;
		n--;
	}
	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
		n--;
	*start = p;
	*len = n;
}

static int valid_field_value(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		uint8_t ch = buf[i];

		if (ch == '\t' || (ch >= 0x20 && ch != 0x7f))
			continue;
		return 0;
	}
	return 1;
}

static int parse_connection_value(const uint8_t *val, size_t len,
				  int *saw_close, int *saw_keep_alive)
{
	size_t pos = 0;
	int tokens = 0;

	while (pos < len) {
		size_t start;
		size_t tok_len;
		const uint8_t *tok;
		size_t i;

		while (pos < len &&
		       (val[pos] == ' ' || val[pos] == '\t' ||
			val[pos] == ','))
			pos++;
		if (pos >= len)
			break;
		start = pos;
		while (pos < len && val[pos] != ',')
			pos++;
		tok = val + start;
		tok_len = pos - start;
		trim_ows(&tok, &tok_len);
		if (tok_len == 0)
			return -1;
		for (i = 0; i < tok_len; i++) {
			if (!is_tchar(tok[i]))
				return -1;
		}
		tokens++;
		if (slice_iequals(tok, tok_len, "close"))
			*saw_close = 1;
		else if (slice_iequals(tok, tok_len, "keep-alive"))
			*saw_keep_alive = 1;
	}
	return tokens > 0 ? 0 : -1;
}

static int parse_content_length(const uint8_t *val, size_t len,
				size_t *out_len)
{
	size_t result = 0;
	size_t i;

	trim_ows(&val, &len);
	if (len == 0)
		return -1;
	for (i = 0; i < len; i++) {
		uint8_t ch = val[i];
		size_t next;

		if (ch < '0' || ch >= '9' + 1)
			return -1;
		if (result > (SIZE_MAX - 9U) / 10U)
			return -1;
		next = result * 10U + (size_t)(ch - '0');
		result = next;
	}
	*out_len = result;
	return 0;
}

void uk_hyperv_http_fill_body(uint8_t out[UK_HYPERV_HTTP_BODY_LEN])
{
	static const char prefix[] = "unikraft-hyperv-http-1k-payload-line-";
	static const char suffix[] = ":0123456789abcdef0123456\n";
	static const char hex[] = "0123456789abcdef";
	unsigned int line;

	if (!out)
		return;
	for (line = 0; line < 16U; line++) {
		uint8_t *dst = out + (size_t)line * 64U;
		size_t i;

		for (i = 0; i < sizeof(prefix) - 1U; i++)
			dst[i] = (uint8_t)prefix[i];
		dst[37] = (uint8_t)hex[(line / 10U) % 10U];
		dst[38] = (uint8_t)hex[line % 10U];
		for (i = 0; i < sizeof(suffix) - 1U; i++)
			dst[39U + i] = (uint8_t)suffix[i];
	}
}

void uk_hyperv_http_format_boot_id(uint64_t boot_id, char out[17])
{
	static const char hex[] = "0123456789abcdef";
	unsigned int i;

	if (!out)
		return;
	if (boot_id == 0)
		boot_id = 1ULL;
	for (i = 0; i < 16U; i++) {
		unsigned int shift = (15U - i) * 4U;

		out[i] = hex[(boot_id >> shift) & 0x0fU];
	}
	out[16] = '\0';
}

int uk_hyperv_http_valid_boot_id_hex(const char *hex, size_t len)
{
	size_t i;
	int non_zero = 0;

	if (!hex || len != UK_HYPERV_HTTP_BOOT_ID_HEX_LEN)
		return 0;
	for (i = 0; i < len; i++) {
		char c = hex[i];

		if (!((c >= '0' && c <= '9') ||
		      (c >= 'a' && c <= 'f') ||
		      (c >= 'A' && c <= 'F')))
			return 0;
		if (c != '0')
			non_zero = 1;
	}
	return non_zero;
}

static int find_crlf(const uint8_t *buf, size_t start, size_t len,
		     size_t *line_end_out, int *saw_bare_cr_or_lf)
{
	size_t i;

	*saw_bare_cr_or_lf = 0;
	for (i = start; i < len; i++) {
		if (buf[i] == '\0') {
			*saw_bare_cr_or_lf = 1;
			return -1;
		}
		if (buf[i] == '\r') {
			if (i + 1U >= len)
				return 0;
			if (buf[i + 1U] != '\n') {
				*saw_bare_cr_or_lf = 1;
				return -1;
			}
			*line_end_out = i;
			return 1;
		}
		if (buf[i] == '\n') {
			*saw_bare_cr_or_lf = 1;
			return -1;
		}
	}
	return 0;
}

enum uk_hyperv_http_scan_status
uk_hyperv_http_scan_request(const uint8_t *buf, size_t len,
			    struct uk_hyperv_http_request *out)
{
	size_t line_start = 0;
	size_t line_end = 0;
	size_t req_line_len;
	size_t sp1;
	size_t sp2;
	size_t i;
	const uint8_t *method_ptr;
	size_t method_len;
	const uint8_t *uri_ptr;
	size_t uri_len;
	const uint8_t *ver_ptr;
	size_t ver_len;
	uint8_t http_minor;
	uint8_t keep_alive;
	int saw_close = 0;
	int saw_keep_alive = 0;
	int saw_content_length = 0;
	size_t content_length = 0;
	uint16_t header_lines = 0;
	int bad_eol = 0;
	int rc;

	if (!out)
		return UK_HYPERV_HTTP_SCAN_MALFORMED;
	out->method = UK_HYPERV_HTTP_METHOD_NONE;
	out->http_minor = 1;
	out->keep_alive = 0;
	out->header_lines = 0;
	out->consumed = 0;
	out->uri_offset = 0;
	out->uri_length = 0;

	if (!buf || len == 0)
		return UK_HYPERV_HTTP_SCAN_INCOMPLETE;

	rc = find_crlf(buf, 0, len, &line_end, &bad_eol);
	if (rc < 0)
		return UK_HYPERV_HTTP_SCAN_MALFORMED;
	if (rc == 0) {
		if (len > UK_HYPERV_HTTP_MAX_LINE_LEN ||
		    len >= UK_HYPERV_HTTP_MAX_REQUEST_LEN)
			return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
		return UK_HYPERV_HTTP_SCAN_INCOMPLETE;
	}

	req_line_len = line_end;
	if (req_line_len == 0)
		return UK_HYPERV_HTTP_SCAN_MALFORMED;
	if (req_line_len > UK_HYPERV_HTTP_MAX_LINE_LEN)
		return UK_HYPERV_HTTP_SCAN_TOO_LARGE;

	sp1 = req_line_len;
	for (i = 0; i < req_line_len; i++) {
		if (buf[i] == ' ') {
			sp1 = i;
			break;
		}
	}
	if (sp1 == 0 || sp1 >= req_line_len)
		return UK_HYPERV_HTTP_SCAN_MALFORMED;

	sp2 = req_line_len;
	for (i = sp1 + 1U; i < req_line_len; i++) {
		if (buf[i] == ' ') {
			sp2 = i;
			break;
		}
	}
	if (sp2 <= sp1 + 1U || sp2 >= req_line_len - 1U)
		return UK_HYPERV_HTTP_SCAN_MALFORMED;

	method_ptr = buf;
	method_len = sp1;
	for (i = 0; i < method_len; i++) {
		if (!is_tchar(method_ptr[i]))
			return UK_HYPERV_HTTP_SCAN_MALFORMED;
	}
	if (slice_equals(method_ptr, method_len, "GET"))
		out->method = UK_HYPERV_HTTP_METHOD_GET;
	else if (slice_equals(method_ptr, method_len, "HEAD"))
		out->method = UK_HYPERV_HTTP_METHOD_HEAD;
	else
		return UK_HYPERV_HTTP_SCAN_MALFORMED;

	uri_ptr = buf + sp1 + 1U;
	uri_len = sp2 - (sp1 + 1U);
	if (uri_len == 0 || uri_ptr[0] != '/')
		return UK_HYPERV_HTTP_SCAN_MALFORMED;
	if (uri_len > UK_HYPERV_HTTP_MAX_URI_LEN)
		return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
	for (i = 0; i < uri_len; i++) {
		if (uri_ptr[i] <= 0x20 || uri_ptr[i] >= 0x7f)
			return UK_HYPERV_HTTP_SCAN_MALFORMED;
	}

	ver_ptr = buf + sp2 + 1U;
	ver_len = req_line_len - (sp2 + 1U);
	if (slice_equals(ver_ptr, ver_len, "HTTP/1.1")) {
		http_minor = 1;
		keep_alive = 1;
	} else if (slice_equals(ver_ptr, ver_len, "HTTP/1.0")) {
		http_minor = 0;
		keep_alive = 0;
	} else {
		return UK_HYPERV_HTTP_SCAN_MALFORMED;
	}

	line_start = line_end + 2U;
	for (;;) {
		size_t hdr_len;
		size_t colon;
		const uint8_t *name_ptr;
		size_t name_len;
		const uint8_t *val_ptr;
		size_t val_len;

		rc = find_crlf(buf, line_start, len, &line_end, &bad_eol);
		if (rc < 0)
			return UK_HYPERV_HTTP_SCAN_MALFORMED;
		if (rc == 0) {
			if (len - line_start > UK_HYPERV_HTTP_MAX_LINE_LEN ||
			    len >= UK_HYPERV_HTTP_MAX_REQUEST_LEN)
				return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
			return UK_HYPERV_HTTP_SCAN_INCOMPLETE;
		}

		hdr_len = line_end - line_start;
		if (hdr_len == 0) {
			size_t total_consumed = line_end + 2U;

			if (total_consumed > UK_HYPERV_HTTP_MAX_REQUEST_LEN)
				return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
			if (content_length > 0) {
				if (content_length >
					    UK_HYPERV_HTTP_MAX_REQUEST_LEN ||
				    total_consumed + content_length >
					    UK_HYPERV_HTTP_MAX_REQUEST_LEN)
					return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
				if (len < total_consumed + content_length)
					return UK_HYPERV_HTTP_SCAN_INCOMPLETE;
				total_consumed += content_length;
			}
			if (saw_close)
				keep_alive = 0;
			else if (saw_keep_alive)
				keep_alive = 1;

			out->http_minor = http_minor;
			out->keep_alive = keep_alive;
			out->header_lines = header_lines;
			out->consumed = total_consumed;
			out->uri_offset = sp1 + 1U;
			out->uri_length = uri_len;
			return UK_HYPERV_HTTP_SCAN_OK;
		}

		if (hdr_len > UK_HYPERV_HTTP_MAX_LINE_LEN)
			return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
		header_lines++;
		if (header_lines > UK_HYPERV_HTTP_MAX_HEADER_LINES)
			return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
		if (line_end + 2U > UK_HYPERV_HTTP_MAX_REQUEST_LEN)
			return UK_HYPERV_HTTP_SCAN_TOO_LARGE;

		colon = hdr_len;
		for (i = 0; i < hdr_len; i++) {
			if (buf[line_start + i] == ':') {
				colon = i;
				break;
			}
		}
		if (colon == 0 || colon >= hdr_len)
			return UK_HYPERV_HTTP_SCAN_MALFORMED;

		name_ptr = buf + line_start;
		name_len = colon;
		for (i = 0; i < name_len; i++) {
			if (!is_tchar(name_ptr[i]))
				return UK_HYPERV_HTTP_SCAN_MALFORMED;
		}

		val_ptr = buf + line_start + colon + 1U;
		val_len = hdr_len - (colon + 1U);
		trim_ows(&val_ptr, &val_len);
		if (!valid_field_value(val_ptr, val_len))
			return UK_HYPERV_HTTP_SCAN_MALFORMED;

		if (slice_iequals(name_ptr, name_len, "Connection")) {
			if (parse_connection_value(val_ptr, val_len,
						   &saw_close,
						   &saw_keep_alive) != 0)
				return UK_HYPERV_HTTP_SCAN_MALFORMED;
		} else if (slice_iequals(name_ptr, name_len,
					 "Content-Length")) {
			size_t parsed_len = 0;

			if (parse_content_length(val_ptr, val_len,
						 &parsed_len) != 0)
				return UK_HYPERV_HTTP_SCAN_MALFORMED;
			if (saw_content_length &&
			    parsed_len != content_length)
				return UK_HYPERV_HTTP_SCAN_MALFORMED;
			saw_content_length = 1;
			content_length = parsed_len;
			if (content_length > UK_HYPERV_HTTP_MAX_REQUEST_LEN)
				return UK_HYPERV_HTTP_SCAN_TOO_LARGE;
		} else if (slice_iequals(name_ptr, name_len,
					 "Transfer-Encoding")) {
			return UK_HYPERV_HTTP_SCAN_MALFORMED;
		}

		line_start = line_end + 2U;
	}
}

static size_t append_str(uint8_t *out, size_t pos, size_t cap, const char *s)
{
	size_t i = 0;

	while (s[i] != '\0') {
		if (pos >= cap)
			return cap + 1U;
		out[pos++] = (uint8_t)s[i++];
	}
	return pos;
}

static size_t append_bytes(uint8_t *out, size_t pos, size_t cap,
			   const uint8_t *src, size_t len)
{
	size_t i;

	if (pos > cap || len > cap - pos)
		return cap + 1U;
	for (i = 0; i < len; i++)
		out[pos + i] = src[i];
	return pos + len;
}

size_t uk_hyperv_http_build_ok_response(
	uint8_t *out, size_t capacity,
	const char boot_id_hex[17],
	const uint8_t body[UK_HYPERV_HTTP_BODY_LEN],
	enum uk_hyperv_http_method method,
	int keep_alive)
{
	size_t pos = 0;

	if (!out || !boot_id_hex || !body)
		return 0;
	if (!uk_hyperv_http_valid_boot_id_hex(
		    boot_id_hex, UK_HYPERV_HTTP_BOOT_ID_HEX_LEN))
		return 0;

	pos = append_str(out, pos, capacity,
			 "HTTP/1.1 200 OK\r\n"
			 "Content-Type: text/plain; charset=utf-8\r\n"
			 "Content-Length: 1024\r\n"
			 "Connection: ");
	pos = append_str(out, pos, capacity,
			 keep_alive ? "keep-alive\r\n" : "close\r\n");
	pos = append_str(out, pos, capacity, "X-Unikraft-Boot-Id: ");
	pos = append_bytes(out, pos, capacity,
			   (const uint8_t *)boot_id_hex,
			   UK_HYPERV_HTTP_BOOT_ID_HEX_LEN);
	pos = append_str(out, pos, capacity, "\r\n\r\n");
	if (method != UK_HYPERV_HTTP_METHOD_HEAD)
		pos = append_bytes(out, pos, capacity, body,
				   UK_HYPERV_HTTP_BODY_LEN);
	return pos <= capacity ? pos : 0;
}

size_t uk_hyperv_http_build_error_response(
	uint8_t *out, size_t capacity,
	const char boot_id_hex[17],
	int status_code)
{
	size_t pos = 0;
	const char *status_line;
	const char *content_len;
	const char *err_body;

	if (!out || !boot_id_hex)
		return 0;
	if (!uk_hyperv_http_valid_boot_id_hex(
		    boot_id_hex, UK_HYPERV_HTTP_BOOT_ID_HEX_LEN))
		return 0;

	if (status_code == 413) {
		status_line = "HTTP/1.1 413 Payload Too Large\r\n";
		content_len = "Content-Length: 18\r\n";
		err_body = "Payload Too Large\n";
	} else {
		status_line = "HTTP/1.1 400 Bad Request\r\n";
		content_len = "Content-Length: 12\r\n";
		err_body = "Bad Request\n";
	}

	pos = append_str(out, pos, capacity, status_line);
	pos = append_str(out, pos, capacity,
			 "Content-Type: text/plain; charset=utf-8\r\n");
	pos = append_str(out, pos, capacity, content_len);
	pos = append_str(out, pos, capacity,
			 "Connection: close\r\n"
			 "X-Unikraft-Boot-Id: ");
	pos = append_bytes(out, pos, capacity,
			   (const uint8_t *)boot_id_hex,
			   UK_HYPERV_HTTP_BOOT_ID_HEX_LEN);
	pos = append_str(out, pos, capacity, "\r\n\r\n");
	pos = append_str(out, pos, capacity, err_body);
	return pos <= capacity ? pos : 0;
}
