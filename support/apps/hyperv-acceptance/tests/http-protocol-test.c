/* SPDX-License-Identifier: BSD-3-Clause */
#include "../application_protocol.h"
#include "../http_protocol.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
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

typedef int8_t err_t;
#define ERR_OK 0
#define ERR_MEM (-1)
#define ERR_IF (-11)

struct pbuf {
	struct pbuf *next;
	void *payload;
	uint16_t tot_len;
	uint16_t len;
};

struct netif {
	void *state;
	err_t (*linkoutput)(struct netif *netif, struct pbuf *p);
};

struct uk_alloc {
	size_t cur_allocs;
	size_t max_allocs;
	size_t total_allocs;
	size_t total_frees;
	size_t cur_bytes;
	size_t fail_after_allocs;
	int fail_enabled;
};

struct uk_netdev_info {
	uint16_t max_rx_queues;
	uint16_t max_tx_queues;
	uint16_t nb_encap_tx;
	uint16_t nb_encap_rx;
	uint16_t ioalign;
};

struct uk_netbuf;
typedef void (*uk_netbuf_dtor_t)(struct uk_netbuf *);

struct uk_netbuf {
	struct uk_netbuf *next;
	struct uk_netbuf *prev;
	uint8_t flags;
	void *data;
	uint16_t len;
	uint32_t refcount;
	void *priv;
	void *buf;
	size_t buflen;
	uint16_t csum_start;
	uint16_t csum_offset;
	uint16_t header_len;
	uint16_t gso_size;
	uk_netbuf_dtor_t dtor;
	struct uk_alloc *_a;
	void *_b;
};

#define UK_NETDEV_STATUS_SUCCESS 0x1
#define UK_NETDEV_STATUS_UNDERRUN 0x4
#define uk_netdev_status_notready(status) \
	(((status) & (UK_NETDEV_STATUS_SUCCESS | UK_NETDEV_STATUS_UNDERRUN)) == \
	 UK_NETDEV_STATUS_UNDERRUN)

struct uk_netdev {
	struct uk_netdev_info info;
	int next_tx_status;
	struct uk_netbuf *in_flight[256];
	unsigned int in_flight_head;
	unsigned int in_flight_tail;
	unsigned int in_flight_count;
	uint16_t last_tx_len;
	uint16_t last_tx_headroom;
	uintptr_t last_tx_buf_addr;
	uint8_t last_tx_payload[2048];
};

struct mock_alloc_header {
	uint32_t magic;
	size_t size;
	size_t align;
	void *raw_ptr;
};

#define MOCK_ALLOC_MAGIC 0x554b4e42U

static struct uk_alloc mock_default_alloc;
static int mock_default_alloc_available = 1;

static struct uk_alloc *uk_alloc_get_default(void)
{
	return mock_default_alloc_available ? &mock_default_alloc : NULL;
}

static void *mock_uk_memalign(struct uk_alloc *a, size_t align, size_t size)
{
	size_t eff_align = align < sizeof(void *) ? sizeof(void *) : align;
	size_t total;
	uintptr_t raw_addr;
	uintptr_t aligned_addr;
	struct mock_alloc_header *hdr;
	void *raw;

	if (!a)
		return NULL;
	if ((eff_align & (eff_align - 1U)) != 0U)
		return NULL;
	if (a->fail_enabled && a->total_allocs >= a->fail_after_allocs)
		return NULL;

	total = size + eff_align + sizeof(struct mock_alloc_header);
	raw = calloc(1U, total);
	assert(raw != NULL);
	raw_addr = (uintptr_t)raw + sizeof(struct mock_alloc_header);
	aligned_addr = (raw_addr + (eff_align - 1U)) & ~(eff_align - 1U);
	hdr = (struct mock_alloc_header *)(aligned_addr -
					   sizeof(struct mock_alloc_header));
	hdr->magic = MOCK_ALLOC_MAGIC;
	hdr->size = size;
	hdr->align = eff_align;
	hdr->raw_ptr = raw;

	a->cur_allocs++;
	a->total_allocs++;
	if (a->cur_allocs > a->max_allocs)
		a->max_allocs = a->cur_allocs;
	a->cur_bytes += size;
	return (void *)aligned_addr;
}

static void uk_free(struct uk_alloc *a, void *ptr)
{
	struct mock_alloc_header *hdr;

	assert(a != NULL);
	assert(ptr != NULL);
	hdr = (struct mock_alloc_header *)((uintptr_t)ptr -
					   sizeof(struct mock_alloc_header));
	assert(hdr->magic == MOCK_ALLOC_MAGIC);
	assert(a->cur_allocs > 0U);
	assert(a->cur_bytes >= hdr->size);
	hdr->magic = 0U;
	a->cur_allocs--;
	a->total_frees++;
	a->cur_bytes -= hdr->size;
	free(hdr->raw_ptr);
}

static void uk_refcount_init(uint32_t *refcount, uint32_t value)
{
	*refcount = value;
}

static size_t uk_netbuf_tailroom(const struct uk_netbuf *m)
{
	uintptr_t data_end;
	uintptr_t buf_end;

	assert(m != NULL);
	assert(m->buf != NULL);
	data_end = (uintptr_t)m->data + (uintptr_t)m->len;
	buf_end = (uintptr_t)m->buf + m->buflen;
	assert(data_end <= buf_end);
	return (size_t)(buf_end - data_end);
}

static struct uk_netbuf *uk_netbuf_alloc_buf(struct uk_alloc *a, size_t buflen,
					     size_t bufalign, uint16_t headroom,
					     size_t privlen,
					     uk_netbuf_dtor_t dtor)
{
	size_t aligned_buflen = (buflen + 7U) & ~((size_t)7U);
	size_t meta_len = ((sizeof(struct uk_netbuf) + privlen) + 7U) &
			  ~((size_t)7U);
	size_t alloc_len = aligned_buflen + meta_len;
	void *mem;
	struct uk_netbuf *m;

	assert(buflen > 0U);
	assert(headroom <= buflen);
	mem = mock_uk_memalign(a, bufalign ? bufalign : 1U, alloc_len);
	if (!mem)
		return NULL;
	m = (struct uk_netbuf *)((uintptr_t)mem + aligned_buflen);
	memset(m, 0, sizeof(*m) + privlen);
	m->buf = mem;
	m->buflen = aligned_buflen;
	m->data = (void *)((uintptr_t)mem + headroom);
	m->priv = privlen > 0U ? (void *)((uintptr_t)m + sizeof(*m)) : NULL;
	m->dtor = dtor;
	m->_a = a;
	m->_b = mem;
	uk_refcount_init(&m->refcount, 1U);
	return m;
}

static void uk_netbuf_free_single(struct uk_netbuf *m)
{
	struct uk_alloc *a;
	void *b;

	assert(m != NULL);
	assert(m->refcount > 0U);
	m->refcount--;
	if (m->refcount == 0U) {
		if (m->prev)
			m->prev->next = m->next;
		if (m->next)
			m->next->prev = m->prev;
		m->prev = NULL;
		m->next = NULL;

		a = m->_a;
		b = m->_b;
		if (m->dtor)
			m->dtor(m);
		if (a && b)
			uk_free(a, b);
	}
}

static void uk_netbuf_free(struct uk_netbuf *m)
{
	struct uk_netbuf *n;

	assert(m != NULL);
	for (; m->next != NULL; m = m->next)
		;
	while (m != NULL) {
		n = m->prev;
		uk_netbuf_free_single(m);
		m = n;
	}
}

static void uk_netdev_info_get(struct uk_netdev *dev,
			       struct uk_netdev_info *info)
{
	assert(dev != NULL);
	assert(info != NULL);
	*info = dev->info;
}

static int uk_netdev_tx_one(struct uk_netdev *dev, uint16_t queue_id,
			    struct uk_netbuf *pkt)
{
	uintptr_t buf_addr;
	uintptr_t data_addr;

	assert(dev != NULL);
	assert(queue_id == 0U);
	assert(pkt != NULL);
	assert(pkt->prev == NULL);
	assert(pkt->next == NULL);
	assert(pkt->flags == 0U);
	assert(pkt->refcount == 1U);

	buf_addr = (uintptr_t)pkt->buf;
	data_addr = (uintptr_t)pkt->data;
	assert(data_addr >= buf_addr);
	assert(data_addr - buf_addr <= pkt->buflen);
	assert((size_t)pkt->len <= pkt->buflen - (data_addr - buf_addr));

	if (dev->next_tx_status < 0 ||
	    uk_netdev_status_notready(dev->next_tx_status))
		return dev->next_tx_status;

	assert(dev->in_flight_count < 256U);
	dev->last_tx_len = pkt->len;
	dev->last_tx_headroom = (uint16_t)(data_addr - buf_addr);
	dev->last_tx_buf_addr = buf_addr;
	memcpy(dev->last_tx_payload, pkt->data, pkt->len);

	dev->in_flight[dev->in_flight_head] = pkt;
	dev->in_flight_head = (dev->in_flight_head + 1U) % 256U;
	dev->in_flight_count++;
	return dev->next_tx_status;
}

int hyperv_acceptance_app_single_tx_attempt(
	hyperv_acceptance_app_tx_attempt_fn attempt, void *argument,
	unsigned int *attempts_out)
{
	if (attempts_out)
		*attempts_out = 1U;
	return attempt(argument);
}

#define HYPERV_HTTP_SERVICE_HOST_TEST 1
#include "../http_service.c"

static void mock_netvsc_drain_one_tx(struct uk_netdev *dev)
{
	struct uk_netbuf *pkt;

	assert(dev->in_flight_count > 0U);
	pkt = dev->in_flight[dev->in_flight_tail];
	dev->in_flight[dev->in_flight_tail] = NULL;
	dev->in_flight_tail = (dev->in_flight_tail + 1U) % 256U;
	dev->in_flight_count--;
	uk_netbuf_free(pkt);
}

static void mock_netvsc_drain_all_tx(struct uk_netdev *dev)
{
	while (dev->in_flight_count > 0U)
		mock_netvsc_drain_one_tx(dev);
}

static void test_http_tx_pool_steady_state_and_async_completion(void)
{
	struct uk_netdev dev;
	struct netif nif;
	uint8_t seg_a[64];
	uint8_t seg_b[128];
	struct pbuf p1;
	struct pbuf p2;
	unsigned int i;

	memset(&mock_default_alloc, 0, sizeof(mock_default_alloc));
	memset(&dev, 0, sizeof(dev));
	memset(&nif, 0, sizeof(nif));
	mock_default_alloc_available = 1;

	dev.info.ioalign = 64U;
	dev.info.nb_encap_tx = 44U;
	dev.next_tx_status = UK_NETDEV_STATUS_SUCCESS;
	nif.state = &dev;

	assert(http_adapter_attach(&nif, &dev) == 0);
	assert(nif.linkoutput == http_adapter_output);
	assert(http_adapter.tx_pool_active == 1U);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);
	assert(mock_default_alloc.total_allocs == HTTP_SERVICE_TX_POOL_SIZE);
	assert(mock_default_alloc.cur_allocs == HTTP_SERVICE_TX_POOL_SIZE);

	for (i = 0; i < sizeof(seg_a); i++)
		seg_a[i] = (uint8_t)(i + 1U);
	for (i = 0; i < sizeof(seg_b); i++)
		seg_b[i] = (uint8_t)(0xa0U ^ i);

	p1.next = &p2;
	p1.payload = seg_a;
	p1.len = (uint16_t)sizeof(seg_a);
	p1.tot_len = (uint16_t)(sizeof(seg_a) + sizeof(seg_b));
	p2.next = NULL;
	p2.payload = seg_b;
	p2.len = (uint16_t)sizeof(seg_b);
	p2.tot_len = (uint16_t)sizeof(seg_b);

	for (i = 0; i < 512U; i++) {
		seg_a[0] = (uint8_t)(i & 0xffU);
		assert(nif.linkoutput(&nif, &p1) == ERR_OK);
		assert((dev.last_tx_buf_addr % 64U) == 0U);
		assert(dev.last_tx_headroom == 44U);
		assert(dev.last_tx_len == p1.tot_len);
		assert(memcmp(dev.last_tx_payload, seg_a, sizeof(seg_a)) == 0);
		assert(memcmp(dev.last_tx_payload + sizeof(seg_a), seg_b,
			      sizeof(seg_b)) == 0);

		if (dev.in_flight_count >= 16U)
			mock_netvsc_drain_one_tx(&dev);
	}

	mock_netvsc_drain_all_tx(&dev);
	assert(http_adapter.tx_pool_hits == 512U);
	assert(http_adapter.tx_pool_misses == 0U);
	assert(http_adapter.tx_pool_recycled == 512U);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);
	assert(mock_default_alloc.total_allocs == HTTP_SERVICE_TX_POOL_SIZE);
	assert(mock_default_alloc.total_frees == 0U);

	http_adapter_release();
	assert(http_adapter.tx_pool_active == 0U);
	assert(http_adapter.tx_pool_free_count == 0U);
	assert(mock_default_alloc.cur_allocs == 0U);
	assert(mock_default_alloc.cur_bytes == 0U);
	assert(mock_default_alloc.total_frees == HTTP_SERVICE_TX_POOL_SIZE);
}

static void test_http_tx_pool_exhaustion_busy_and_fallbacks(void)
{
	struct uk_netdev dev;
	struct netif nif;
	uint8_t payload[2048];
	struct pbuf p;
	unsigned int i;
	size_t baseline_allocs;

	memset(&mock_default_alloc, 0, sizeof(mock_default_alloc));
	memset(&dev, 0, sizeof(dev));
	memset(&nif, 0, sizeof(nif));
	memset(payload, 0x5a, sizeof(payload));
	mock_default_alloc_available = 1;

	dev.info.ioalign = 32U;
	dev.info.nb_encap_tx = 64U;
	dev.next_tx_status = UK_NETDEV_STATUS_SUCCESS;
	nif.state = &dev;

	assert(http_adapter_attach(&nif, &dev) == 0);
	baseline_allocs = mock_default_alloc.total_allocs;
	assert(baseline_allocs == HTTP_SERVICE_TX_POOL_SIZE);

	p.next = NULL;
	p.payload = payload;
	p.len = 256U;
	p.tot_len = 256U;

	/* Exhaust all pooled TX buffers + 8 fallback heap buffers in flight. */
	for (i = 0; i < HTTP_SERVICE_TX_POOL_SIZE + 8U; i++)
		assert(nif.linkoutput(&nif, &p) == ERR_OK);

	assert(http_adapter.tx_pool_hits == HTTP_SERVICE_TX_POOL_SIZE);
	assert(http_adapter.tx_pool_misses == 8U);
	assert(http_adapter.tx_pool_free_count == 0U);
	assert(mock_default_alloc.cur_allocs == HTTP_SERVICE_TX_POOL_SIZE + 8U);

	/* Reclaim all in-flight packets: pooled buffers return to pool, fallbacks free. */
	mock_netvsc_drain_all_tx(&dev);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);
	assert(http_adapter.tx_pool_recycled == HTTP_SERVICE_TX_POOL_SIZE);
	assert(mock_default_alloc.cur_allocs == HTTP_SERVICE_TX_POOL_SIZE);

	/* Busy and error sends immediately recycle pooled buffers without heap churn. */
	dev.next_tx_status = UK_NETDEV_STATUS_UNDERRUN;
	assert(nif.linkoutput(&nif, &p) == ERR_MEM);
	assert(http_adapter.transmit_busy == 1U);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);

	dev.next_tx_status = -5;
	assert(nif.linkoutput(&nif, &p) == ERR_IF);
	assert(http_adapter.failure == HTTP_ADAPTER_TX_ERROR);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);
	http_adapter.failure = HTTP_ADAPTER_OK;
	dev.next_tx_status = UK_NETDEV_STATUS_SUCCESS;

	/* Oversized pbuf (> HTTP_SERVICE_NETDEV_BUFFER_SIZE - headroom) returns ERR_MEM. */
	p.len = (uint16_t)(HTTP_SERVICE_NETDEV_BUFFER_SIZE - 64U + 16U);
	p.tot_len = p.len;
	assert(nif.linkoutput(&nif, &p) == ERR_MEM);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);
	assert(mock_default_alloc.cur_allocs == HTTP_SERVICE_TX_POOL_SIZE);

	/* Dynamic headroom increase exceeding pooled headroom falls back cleanly. */
	p.len = 256U;
	p.tot_len = 256U;
	http_adapter.info.nb_encap_tx = 128U;
	assert(nif.linkoutput(&nif, &p) == ERR_OK);
	assert(dev.last_tx_headroom == 128U);
	mock_netvsc_drain_all_tx(&dev);
	assert(mock_default_alloc.cur_allocs == HTTP_SERVICE_TX_POOL_SIZE);

	http_adapter_release();
	assert(mock_default_alloc.cur_allocs == 0U);
	assert(mock_default_alloc.cur_bytes == 0U);
}

static void test_http_tx_pool_teardown_with_inflight_and_reattach(void)
{
	struct uk_netdev dev1;
	struct uk_netdev dev2;
	struct netif nif1;
	struct netif nif2;
	uint8_t payload[128];
	struct pbuf p;

	memset(&mock_default_alloc, 0, sizeof(mock_default_alloc));
	memset(&dev1, 0, sizeof(dev1));
	memset(&dev2, 0, sizeof(dev2));
	memset(&nif1, 0, sizeof(nif1));
	memset(&nif2, 0, sizeof(nif2));
	memset(payload, 0x33, sizeof(payload));
	mock_default_alloc_available = 1;

	dev1.info.ioalign = 64U;
	dev1.info.nb_encap_tx = 64U;
	dev1.next_tx_status = UK_NETDEV_STATUS_SUCCESS;
	nif1.state = &dev1;

	dev2.info.ioalign = 64U;
	dev2.info.nb_encap_tx = 64U;
	dev2.next_tx_status = UK_NETDEV_STATUS_SUCCESS;
	nif2.state = &dev2;

	p.next = NULL;
	p.payload = payload;
	p.len = (uint16_t)sizeof(payload);
	p.tot_len = (uint16_t)sizeof(payload);

	assert(http_adapter_attach(&nif1, &dev1) == 0);
	assert(nif1.linkoutput(&nif1, &p) == ERR_OK);
	assert(nif1.linkoutput(&nif1, &p) == ERR_OK);
	assert(dev1.in_flight_count == 2U);
	assert(http_adapter.tx_pool_free_count ==
	       HTTP_SERVICE_TX_POOL_SIZE - 2U);

	/* Release while 2 packets are still in-flight on dev1. */
	http_adapter_release();
	assert(mock_default_alloc.cur_allocs == 2U);

	/* Re-attach a second session before dev1's in-flight packets complete. */
	assert(http_adapter_attach(&nif2, &dev2) == 0);
	assert(mock_default_alloc.cur_allocs ==
	       HTTP_SERVICE_TX_POOL_SIZE + 2U);

	/* Completing dev1's stale-generation packets frees them to the heap. */
	mock_netvsc_drain_all_tx(&dev1);
	assert(mock_default_alloc.cur_allocs == HTTP_SERVICE_TX_POOL_SIZE);
	assert(http_adapter.tx_pool_free_count == HTTP_SERVICE_TX_POOL_SIZE);

	http_adapter_release();
	assert(mock_default_alloc.cur_allocs == 0U);
	assert(mock_default_alloc.cur_bytes == 0U);
}

int main(void)
{
	test_deterministic_body_and_boot_id();
	test_keep_alive_and_close_semantics();
	test_partial_accumulation_and_pipelining();
	test_malformed_and_oversized_rejection();
	test_response_builders();
	test_http_tx_pool_steady_state_and_async_completion();
	test_http_tx_pool_exhaustion_busy_and_fallbacks();
	test_http_tx_pool_teardown_with_inflight_and_reattach();
	return 0;
}
