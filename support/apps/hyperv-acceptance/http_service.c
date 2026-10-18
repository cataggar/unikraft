/* SPDX-License-Identifier: BSD-3-Clause */
#include "http_service.h"

#ifndef HYPERV_HTTP_SERVICE_HOST_TEST
#include <uk/config.h>
#endif

#if CONFIG_APPHYPERVACCEPTANCE_HTTP_SERVICE || \
	defined(HYPERV_HTTP_SERVICE_HOST_TEST)

#include "application_protocol.h"
#include "http_protocol.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifndef HYPERV_HTTP_SERVICE_HOST_TEST
#include <hyperv/hyperv.h>
#include <lwip/dhcp.h>
#include <lwip/etharp.h>
#include <lwip/ip4_addr.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <netif/uknetdev.h>
#include <uk/alloc.h>
#include <uk/netdev.h>
#include <uk/netvsc.h>
#include <uk/plat/time.h>
#include <uk/random.h>
#include <uk/sched.h>

#include "netbuf.h"
#endif

#ifndef CONFIG_APPHYPERVACCEPTANCE_HTTP_PORT
#define CONFIG_APPHYPERVACCEPTANCE_HTTP_PORT 8080
#endif

#ifndef CONFIG_APPHYPERVACCEPTANCE_HTTP_DURATION_MS
#define CONFIG_APPHYPERVACCEPTANCE_HTTP_DURATION_MS 360000
#endif

#ifndef CONFIG_APPHYPERVACCEPTANCE_HTTP_MAX_CONNS
#define CONFIG_APPHYPERVACCEPTANCE_HTTP_MAX_CONNS 64
#endif

#define HTTP_SERVICE_DHCP_TIMEOUT_NS (12ULL * 1000000000ULL)
#define HTTP_SERVICE_IDLE_SLEEP_NS 200000ULL
#define HTTP_SERVICE_STATS_INTERVAL_NS (5ULL * 1000000000ULL)
#define HTTP_SERVICE_CONN_IDLE_TIMEOUT_NS (30ULL * 1000000000ULL)
#define HTTP_SERVICE_NETDEV_BUFFER_SIZE 2048U
#ifndef HTTP_SERVICE_TX_POOL_SIZE
#define HTTP_SERVICE_TX_POOL_SIZE 128U
#endif
#define HTTP_SERVICE_MAX_CONNS_CAP 256U

#if CONFIG_APPHYPERVACCEPTANCE_HTTP_MAX_CONNS > HTTP_SERVICE_MAX_CONNS_CAP
#define HTTP_SERVICE_POOL_SIZE HTTP_SERVICE_MAX_CONNS_CAP
#else
#define HTTP_SERVICE_POOL_SIZE CONFIG_APPHYPERVACCEPTANCE_HTTP_MAX_CONNS
#endif

enum http_adapter_failure {
	HTTP_ADAPTER_OK = 0,
	HTTP_ADAPTER_TX_BUSY,
	HTTP_ADAPTER_TX_ERROR,
	HTTP_ADAPTER_RX_ERROR,
	HTTP_ADAPTER_INPUT_ERROR,
};

struct http_tx_pool_meta {
	struct uk_alloc *allocator;
	uint32_t generation;
};

struct http_bounded_adapter {
	struct netif *netif;
	struct uk_netdev *device;
	struct uk_alloc *allocator;
	struct uk_netdev_info info;
	enum http_adapter_failure failure;
	unsigned int receive_packets;
	unsigned int receive_budget_exhaustions;
	unsigned int transmit_attempts;
	unsigned int transmit_busy;
	uint64_t pumps;
	struct uk_netbuf *tx_pool_free[HTTP_SERVICE_TX_POOL_SIZE];
	unsigned int tx_pool_free_count;
	uint32_t tx_pool_generation;
	uint16_t tx_pool_ioalign;
	uint16_t tx_pool_headroom;
	uint8_t tx_pool_active;
	unsigned int tx_pool_hits;
	unsigned int tx_pool_misses;
	unsigned int tx_pool_recycled;
};

struct http_tx_attempt {
	struct uk_netdev *device;
	struct uk_netbuf *buffer;
};

static struct http_bounded_adapter http_adapter;
static uint32_t http_tx_pool_next_generation;

static void http_tx_pool_dtor(struct uk_netbuf *buffer)
{
	struct http_tx_pool_meta *meta;

	if (!buffer)
		return;
	meta = (struct http_tx_pool_meta *)buffer->priv;
	if (meta && http_adapter.tx_pool_active &&
	    meta->generation == http_adapter.tx_pool_generation &&
	    http_adapter.tx_pool_free_count < HTTP_SERVICE_TX_POOL_SIZE) {
		http_adapter.tx_pool_free[http_adapter.tx_pool_free_count++] =
			buffer;
		http_adapter.tx_pool_recycled++;
		return;
	}
	if (meta && meta->allocator && buffer->_b)
		uk_free(meta->allocator, buffer->_b);
}

static void http_tx_pool_init(void)
{
	unsigned int i;

	http_tx_pool_next_generation++;
	if (http_tx_pool_next_generation == 0)
		http_tx_pool_next_generation = 1;
	http_adapter.tx_pool_generation = http_tx_pool_next_generation;
	http_adapter.tx_pool_ioalign = http_adapter.info.ioalign;
	http_adapter.tx_pool_headroom = http_adapter.info.nb_encap_tx;
	http_adapter.tx_pool_free_count = 0;
	http_adapter.tx_pool_active = 1;

	if (http_adapter.tx_pool_headroom > HTTP_SERVICE_NETDEV_BUFFER_SIZE)
		return;

	for (i = 0; i < HTTP_SERVICE_TX_POOL_SIZE; i++) {
		struct uk_netbuf *buffer;
		struct http_tx_pool_meta *meta;

		buffer = uk_netbuf_alloc_buf(
			http_adapter.allocator,
			HTTP_SERVICE_NETDEV_BUFFER_SIZE,
			http_adapter.tx_pool_ioalign,
			http_adapter.tx_pool_headroom,
			sizeof(*meta),
			http_tx_pool_dtor);
		if (!buffer)
			break;
		meta = (struct http_tx_pool_meta *)buffer->priv;
		meta->allocator = http_adapter.allocator;
		meta->generation = http_adapter.tx_pool_generation;
		buffer->_a = NULL;
		http_adapter.tx_pool_free[http_adapter.tx_pool_free_count++] =
			buffer;
	}
}

static struct uk_netbuf *http_tx_pool_acquire(uint16_t tot_len)
{
	uint16_t headroom = http_adapter.info.nb_encap_tx;
	uint16_t ioalign = http_adapter.info.ioalign;

	if (http_adapter.tx_pool_active &&
	    http_adapter.tx_pool_free_count > 0 &&
	    ioalign == http_adapter.tx_pool_ioalign &&
	    headroom <= http_adapter.tx_pool_headroom &&
	    headroom <= HTTP_SERVICE_NETDEV_BUFFER_SIZE &&
	    (size_t)tot_len <=
		    (size_t)HTTP_SERVICE_NETDEV_BUFFER_SIZE - (size_t)headroom) {
		struct uk_netbuf *buffer =
			http_adapter.tx_pool_free[--http_adapter.tx_pool_free_count];

		buffer->next = NULL;
		buffer->prev = NULL;
		buffer->flags = 0;
		buffer->data = (void *)((uintptr_t)buffer->buf + headroom);
		buffer->len = 0;
		buffer->csum_start = 0;
		buffer->csum_offset = 0;
		buffer->header_len = 0;
		buffer->gso_size = 0;
		uk_refcount_init(&buffer->refcount, 1);
		http_adapter.tx_pool_hits++;
		return buffer;
	}

	http_adapter.tx_pool_misses++;
	if (headroom > HTTP_SERVICE_NETDEV_BUFFER_SIZE)
		return NULL;
	return uk_netbuf_alloc_buf(
		http_adapter.allocator, HTTP_SERVICE_NETDEV_BUFFER_SIZE,
		ioalign, headroom, 0, NULL);
}

static void http_adapter_release(void)
{
	http_adapter.tx_pool_active = 0;
	while (http_adapter.tx_pool_free_count > 0) {
		struct uk_netbuf *buffer =
			http_adapter.tx_pool_free[--http_adapter.tx_pool_free_count];
		struct http_tx_pool_meta *meta;

		http_adapter.tx_pool_free[http_adapter.tx_pool_free_count] =
			NULL;
		if (!buffer)
			continue;
		meta = (struct http_tx_pool_meta *)buffer->priv;
		if (meta && meta->allocator && buffer->_b)
			uk_free(meta->allocator, buffer->_b);
	}
}

static int http_tx_one(void *argument)
{
	struct http_tx_attempt *attempt = argument;

	return uk_netdev_tx_one(attempt->device, 0, attempt->buffer);
}

static err_t http_adapter_output(struct netif *netif, struct pbuf *pbuf)
{
	struct http_tx_attempt attempt;
	struct uk_netbuf *buffer;
	struct pbuf *part;
	char *write_position;
	unsigned int attempts;
	int status;

	if (netif != http_adapter.netif ||
	    netif->state != http_adapter.device) {
		if (http_adapter.failure == HTTP_ADAPTER_OK)
			http_adapter.failure = HTTP_ADAPTER_TX_ERROR;
		return ERR_IF;
	}
	buffer = http_tx_pool_acquire(pbuf->tot_len);
	if (!buffer)
		return ERR_MEM;
	if (pbuf->tot_len > uk_netbuf_tailroom(buffer)) {
		uk_netbuf_free_single(buffer);
		return ERR_MEM;
	}
	write_position = buffer->data;
	for (part = pbuf; part; part = part->next) {
		memcpy(write_position, part->payload, part->len);
		write_position += part->len;
	}
	buffer->len = pbuf->tot_len;

	attempt.device = http_adapter.device;
	attempt.buffer = buffer;
	status = hyperv_acceptance_app_single_tx_attempt(
		http_tx_one, &attempt, &attempts);
	http_adapter.transmit_attempts += attempts;
	if (uk_netdev_status_notready(status)) {
		http_adapter.transmit_busy++;
		uk_netbuf_free_single(buffer);
		return ERR_MEM;
	}
	if (status < 0) {
		if (http_adapter.failure == HTTP_ADAPTER_OK)
			http_adapter.failure = HTTP_ADAPTER_TX_ERROR;
		uk_netbuf_free_single(buffer);
		return ERR_IF;
	}
	return ERR_OK;
}

static int http_adapter_attach(struct netif *netif, struct uk_netdev *device)
{
	http_adapter_release();
	memset(&http_adapter, 0, sizeof(http_adapter));
	http_adapter.netif = netif;
	http_adapter.device = device;
	http_adapter.allocator = uk_alloc_get_default();
	if (!http_adapter.allocator || netif->state != device)
		return -1;
	uk_netdev_info_get(device, &http_adapter.info);
	http_tx_pool_init();
	netif->linkoutput = http_adapter_output;
	return 0;
}

#if CONFIG_APPHYPERVACCEPTANCE_HTTP_SERVICE

struct http_conn_slot {
	struct tcp_pcb *pcb;
	uint64_t last_active_ns;
	size_t rx_len;
	size_t tx_len;
	size_t tx_sent;
	uint8_t in_use;
	uint8_t close_after_send;
	uint8_t rx_buf[UK_HYPERV_HTTP_MAX_REQUEST_LEN];
	uint8_t tx_buf[UK_HYPERV_HTTP_MAX_RESPONSE_LEN];
};

struct http_service_metrics {
	uint64_t requests;
	uint64_t bytes_tx;
	uint64_t bytes_rx;
	uint64_t total_conns;
	uint64_t errors;
	uint64_t status_200;
	uint64_t status_400;
	uint64_t status_413;
	unsigned int active_conns;
	unsigned int peak_conns;
};

static struct http_conn_slot http_slots[HTTP_SERVICE_POOL_SIZE];
static struct http_service_metrics http_metrics;
static uint8_t http_body[UK_HYPERV_HTTP_BODY_LEN];
static char http_boot_id_hex[17];

static uint64_t mix_boot_id(uint64_t value)
{
	value += 0x9e3779b97f4a7c15ULL;
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
	value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
	value ^= value >> 31;
	return value ? value : 0x4859504552563031ULL;
}

static uint64_t derive_boot_id(uint64_t t_efi_pre_exit, uint64_t t_time_init,
			       uint64_t t_vmbus_ready)
{
	uint64_t random_seed = 0;
	uint64_t wall_ns = (uint64_t)ukplat_wall_clock();
	uint64_t mono_ns = (uint64_t)ukplat_monotonic_clock();
	uint64_t combined;

	if (uk_random_fill_buffer(&random_seed, sizeof(random_seed)) != 0)
		random_seed = 0;
	combined = random_seed ^
		   mix_boot_id(t_efi_pre_exit ^ (t_time_init << 7)) ^
		   mix_boot_id(t_vmbus_ready ^ (wall_ns << 13) ^ mono_ns);
	return mix_boot_id(combined);
}

static int http_adapter_rx_step(void *argument)
{
	struct http_bounded_adapter *adapter = argument;
	struct uk_netbuf *buffer;
	struct uk_netbuf *next;
	struct pbuf *pbuf;
	struct pbuf *part;
	err_t error;
	int status;

	status = uk_netdev_rx_one(adapter->device, 0, &buffer);
	if (status < 0) {
		if (adapter->failure == HTTP_ADAPTER_OK)
			adapter->failure = HTTP_ADAPTER_RX_ERROR;
		netif_set_down(adapter->netif);
		return HYPERV_ACCEPTANCE_APP_RX_ERROR;
	}
	if (uk_netdev_status_notready(status))
		return HYPERV_ACCEPTANCE_APP_RX_IDLE;
	if (!buffer) {
		if (adapter->failure == HTTP_ADAPTER_OK)
			adapter->failure = HTTP_ADAPTER_RX_ERROR;
		netif_set_down(adapter->netif);
		return HYPERV_ACCEPTANCE_APP_RX_ERROR;
	}

	adapter->receive_packets++;
	pbuf = lwip_netbuf_to_pbuf(buffer);
	pbuf->payload = buffer->data;
	pbuf->tot_len = pbuf->len = buffer->len;
	for (next = buffer->next; next; next = next->next) {
		part = lwip_netbuf_to_pbuf(next);
		part->payload = next->data;
		part->tot_len = part->len = next->len;
		pbuf_cat(pbuf, part);
	}
	error = adapter->netif->input(pbuf, adapter->netif);
	if (error != ERR_OK) {
		pbuf_free(pbuf);
		if (adapter->failure == HTTP_ADAPTER_OK)
			adapter->failure = HTTP_ADAPTER_INPUT_ERROR;
		return HYPERV_ACCEPTANCE_APP_RX_ERROR;
	}
	return uk_netdev_status_more(status) ?
	       HYPERV_ACCEPTANCE_APP_RX_MORE :
	       HYPERV_ACCEPTANCE_APP_RX_LAST;
}

static unsigned int http_adapter_poll(void)
{
	struct hyperv_acceptance_app_rx_result result;

	http_adapter.pumps++;
	result = hyperv_acceptance_app_bounded_rx_drain(
		http_adapter_rx_step, &http_adapter);
	if (result.budget_exhausted)
		http_adapter.receive_budget_exhaustions++;
	if (result.error && http_adapter.failure == HTTP_ADAPTER_OK)
		http_adapter.failure = HTTP_ADAPTER_RX_ERROR;
	sys_check_timeouts();
	return result.packets;
}

static void release_slot(struct http_conn_slot *slot)
{
	if (!slot || !slot->in_use)
		return;
	slot->pcb = NULL;
	slot->rx_len = 0;
	slot->tx_len = 0;
	slot->tx_sent = 0;
	slot->in_use = 0;
	slot->close_after_send = 0;
	if (http_metrics.active_conns > 0)
		http_metrics.active_conns--;
}

static void close_slot_pcb(struct http_conn_slot *slot)
{
	struct tcp_pcb *pcb;
	err_t err;

	if (!slot || !slot->in_use)
		return;
	pcb = slot->pcb;
	release_slot(slot);
	if (!pcb)
		return;
	tcp_arg(pcb, NULL);
	tcp_recv(pcb, NULL);
	tcp_sent(pcb, NULL);
	tcp_err(pcb, NULL);
	tcp_poll(pcb, NULL, 0);
	err = tcp_close(pcb);
	if (err != ERR_OK)
		tcp_abort(pcb);
}

static int flush_slot_tx(struct http_conn_slot *slot)
{
	struct tcp_pcb *pcb;
	size_t pending;
	size_t sndbuf;
	uint16_t chunk;
	err_t err;

	if (!slot || !slot->in_use || !slot->pcb)
		return -1;
	pcb = slot->pcb;
	if (slot->tx_sent >= slot->tx_len) {
		slot->tx_len = 0;
		slot->tx_sent = 0;
		if (slot->close_after_send) {
			close_slot_pcb(slot);
			return 1;
		}
		return 0;
	}
	pending = slot->tx_len - slot->tx_sent;
	sndbuf = (size_t)tcp_sndbuf(pcb);
	if (sndbuf == 0)
		return 0;
	if (pending > sndbuf)
		pending = sndbuf;
	if (pending > 0xffffU)
		pending = 0xffffU;
	chunk = (uint16_t)pending;
	err = tcp_write(pcb, slot->tx_buf + slot->tx_sent, chunk,
			TCP_WRITE_FLAG_COPY);
	if (err == ERR_MEM)
		return 0;
	if (err != ERR_OK) {
		http_metrics.errors++;
		close_slot_pcb(slot);
		return -1;
	}
	slot->tx_sent += chunk;
	http_metrics.bytes_tx += chunk;
	(void)tcp_output(pcb);
	return 0;
}

static void process_slot_requests(struct http_conn_slot *slot)
{
	while (slot->in_use && !slot->close_after_send &&
	       slot->tx_len == 0 && slot->rx_len > 0) {
		struct uk_hyperv_http_request req;
		enum uk_hyperv_http_scan_status status;
		size_t resp_len;

		status = uk_hyperv_http_scan_request(
			slot->rx_buf, slot->rx_len, &req);
		if (status == UK_HYPERV_HTTP_SCAN_INCOMPLETE)
			break;
		if (status == UK_HYPERV_HTTP_SCAN_OK) {
			resp_len = uk_hyperv_http_build_ok_response(
				slot->tx_buf, sizeof(slot->tx_buf),
				http_boot_id_hex, http_body,
				req.method, req.keep_alive);
			if (resp_len == 0) {
				http_metrics.errors++;
				close_slot_pcb(slot);
				return;
			}
			slot->tx_len = resp_len;
			slot->tx_sent = 0;
			if (!req.keep_alive)
				slot->close_after_send = 1;
			if (req.consumed < slot->rx_len) {
				memmove(slot->rx_buf,
					slot->rx_buf + req.consumed,
					slot->rx_len - req.consumed);
				slot->rx_len -= req.consumed;
			} else {
				slot->rx_len = 0;
			}
			http_metrics.requests++;
			http_metrics.status_200++;
		} else {
			int code = (status == UK_HYPERV_HTTP_SCAN_TOO_LARGE) ?
				   413 : 400;

			resp_len = uk_hyperv_http_build_error_response(
				slot->tx_buf, sizeof(slot->tx_buf),
				http_boot_id_hex, code);
			slot->rx_len = 0;
			slot->tx_len = resp_len;
			slot->tx_sent = 0;
			slot->close_after_send = 1;
			http_metrics.errors++;
			if (code == 413)
				http_metrics.status_413++;
			else
				http_metrics.status_400++;
		}
		if (flush_slot_tx(slot) != 0)
			return;
	}
}

static void http_conn_err(void *arg, err_t err)
{
	struct http_conn_slot *slot = arg;

	(void)err;
	if (!slot || !slot->in_use)
		return;
	slot->pcb = NULL;
	release_slot(slot);
}

static err_t http_conn_sent(void *arg, struct tcp_pcb *tpcb, uint16_t len)
{
	struct http_conn_slot *slot = arg;

	(void)tpcb;
	(void)len;
	if (!slot || !slot->in_use)
		return ERR_OK;
	slot->last_active_ns = (uint64_t)ukplat_monotonic_clock();
	if (slot->tx_sent < slot->tx_len) {
		if (flush_slot_tx(slot) != 0)
			return ERR_OK;
	} else {
		slot->tx_len = 0;
		slot->tx_sent = 0;
		if (slot->close_after_send) {
			close_slot_pcb(slot);
			return ERR_OK;
		}
	}
	process_slot_requests(slot);
	return ERR_OK;
}

static err_t http_conn_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
			    err_t err)
{
	struct http_conn_slot *slot = arg;
	size_t incoming;

	if (!slot || !slot->in_use) {
		if (p)
			pbuf_free(p);
		return ERR_OK;
	}
	if (!p) {
		close_slot_pcb(slot);
		return ERR_OK;
	}
	if (err != ERR_OK) {
		pbuf_free(p);
		http_metrics.errors++;
		close_slot_pcb(slot);
		return ERR_OK;
	}

	slot->last_active_ns = (uint64_t)ukplat_monotonic_clock();
	incoming = (size_t)p->tot_len;
	http_metrics.bytes_rx += incoming;
	tcp_recved(tpcb, p->tot_len);

	if (slot->close_after_send) {
		pbuf_free(p);
		return ERR_OK;
	}

	if (incoming > sizeof(slot->rx_buf) - slot->rx_len) {
		pbuf_free(p);
		slot->rx_len = 0;
		slot->tx_len = uk_hyperv_http_build_error_response(
			slot->tx_buf, sizeof(slot->tx_buf),
			http_boot_id_hex, 413);
		slot->tx_sent = 0;
		slot->close_after_send = 1;
		http_metrics.errors++;
		http_metrics.status_413++;
		(void)flush_slot_tx(slot);
		return ERR_OK;
	}

	if (pbuf_copy_partial(p, slot->rx_buf + slot->rx_len,
			      p->tot_len, 0) != p->tot_len) {
		pbuf_free(p);
		http_metrics.errors++;
		close_slot_pcb(slot);
		return ERR_OK;
	}
	slot->rx_len += incoming;
	pbuf_free(p);

	process_slot_requests(slot);
	return ERR_OK;
}

static err_t http_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	struct http_conn_slot *slot = NULL;
	unsigned int i;

	(void)arg;
	if (err != ERR_OK || !newpcb)
		return ERR_VAL;

	for (i = 0; i < HTTP_SERVICE_POOL_SIZE; i++) {
		if (!http_slots[i].in_use) {
			slot = &http_slots[i];
			break;
		}
	}
	if (!slot) {
		http_metrics.errors++;
		tcp_abort(newpcb);
		return ERR_ABRT;
	}

	memset(slot, 0, sizeof(*slot));
	slot->pcb = newpcb;
	slot->in_use = 1;
	slot->last_active_ns = (uint64_t)ukplat_monotonic_clock();
	http_metrics.total_conns++;
	http_metrics.active_conns++;
	if (http_metrics.active_conns > http_metrics.peak_conns)
		http_metrics.peak_conns = http_metrics.active_conns;

	tcp_nagle_disable(newpcb);
	tcp_arg(newpcb, slot);
	tcp_recv(newpcb, http_conn_recv);
	tcp_sent(newpcb, http_conn_sent);
	tcp_err(newpcb, http_conn_err);
	return ERR_OK;
}

static void emit_http_service_stats(const char *phase, uint64_t elapsed_ms)
{
	struct uk_netvsc_diagnostics diag;
	uint64_t cur_mem_use = 0;
	uint64_t max_mem_use = 0;
	uint64_t cur_nb_allocs = 0;
	uint64_t max_nb_allocs = 0;
	uint64_t nb_enomem = 0;
	uint64_t availmem = 0;
	uint64_t pavailmem = 0;

	memset(&diag, 0, sizeof(diag));
	if (http_adapter.device)
		(void)uk_netvsc_diagnostics_get(http_adapter.device, &diag);

#if CONFIG_LIBUKALLOC_IFSTATS
	if (http_adapter.allocator) {
		struct uk_alloc_stats astats;

		memset(&astats, 0, sizeof(astats));
		uk_alloc_stats_get(http_adapter.allocator, &astats);
		cur_mem_use = (uint64_t)astats.cur_mem_use;
		max_mem_use = (uint64_t)astats.max_mem_use;
		cur_nb_allocs = (uint64_t)astats.cur_nb_allocs;
		max_nb_allocs = (uint64_t)astats.max_nb_allocs;
		nb_enomem = (uint64_t)astats.nb_enomem;
		availmem = (uint64_t)astats.availmem;
		pavailmem = (uint64_t)astats.pavailmem;
	}
#endif

	printf("UK_HYPERV_HTTP_SERVICE_STATS phase=%s boot_id=%s "
	       "elapsed_ms=%" PRIu64 " requests=%" PRIu64
	       " bytes_tx=%" PRIu64 " bytes_rx=%" PRIu64
	       " active_conns=%u peak_conns=%u total_conns=%" PRIu64
	       " errors=%" PRIu64 " status_200=%" PRIu64
	       " status_400=%" PRIu64 " status_413=%" PRIu64
	       " tx_submitted=%" PRIu64 " tx_completed=%" PRIu64
	       " tx_pending=%" PRIu16 " rx_packets=%" PRIu64
	       " rx_dropped=%" PRIu64 " rx_queued=%" PRIu16
	       " channel_packets=%" PRIu64 " transfer_packets=%" PRIu64
	       " pending_acks=%" PRIu16 " malformed=%" PRIu32
	       " adapter_rx_packets=%u adapter_rx_budget_exhaustions=%u "
	       "adapter_tx_attempts=%u adapter_tx_busy=%u "
	       "alloc_cur_mem_use=%" PRIu64 " alloc_max_mem_use=%" PRIu64
	       " alloc_cur_nb_allocs=%" PRIu64 " alloc_max_nb_allocs=%" PRIu64
	       " alloc_nb_enomem=%" PRIu64 " alloc_availmem=%" PRIu64
	       " alloc_pavailmem=%" PRIu64 "\n",
	       phase, http_boot_id_hex, elapsed_ms,
	       http_metrics.requests, http_metrics.bytes_tx,
	       http_metrics.bytes_rx, http_metrics.active_conns,
	       http_metrics.peak_conns, http_metrics.total_conns,
	       http_metrics.errors, http_metrics.status_200,
	       http_metrics.status_400, http_metrics.status_413,
	       diag.tx_submitted, diag.tx_completed, diag.tx_pending,
	       diag.rx_packets, diag.rx_dropped, diag.rx_queued,
	       diag.channel_packets, diag.transfer_packets, diag.pending_acks,
	       diag.malformed_messages,
	       http_adapter.receive_packets,
	       http_adapter.receive_budget_exhaustions,
	       http_adapter.transmit_attempts,
	       http_adapter.transmit_busy,
	       cur_mem_use, max_mem_use, cur_nb_allocs, max_nb_allocs,
	       nb_enomem, availmem, pavailmem);
}

static int acquire_http_lease(struct uk_netdev *device,
			      struct netif **netif_out)
{
	struct netif *netif;
	uint64_t deadline;
	err_t error;
	int rc;

	if (uk_netdev_state_get(device) == UK_NETDEV_UNPROBED) {
		rc = uk_netdev_probe(device);
		if (rc)
			return -1;
	}
	if (uk_netdev_state_get(device) != UK_NETDEV_UNCONFIGURED)
		return -1;

	netif = uknetdev_addif(device, NULL, NULL, NULL, "hyperv-http");
	if (!netif)
		return -1;
	if (http_adapter_attach(netif, device))
		return -1;

	netif_set_default(netif);
	netif_set_up(netif);
	error = dhcp_start(netif);
	if (error != ERR_OK) {
		http_adapter_release();
		return -1;
	}

	deadline = (uint64_t)ukplat_monotonic_clock() +
		   HTTP_SERVICE_DHCP_TIMEOUT_NS;
	while ((uint64_t)ukplat_monotonic_clock() < deadline) {
		if (dhcp_supplied_address(netif))
			break;
		(void)http_adapter_poll();
		if (http_adapter.failure != HTTP_ADAPTER_OK) {
			dhcp_stop(netif);
			http_adapter_release();
			return -1;
		}
		uk_sched_thread_sleep(1000000ULL);
	}
	if (!dhcp_supplied_address(netif)) {
		dhcp_stop(netif);
		http_adapter_release();
		return -1;
	}
	*netif_out = netif;
	return 0;
}

static void reap_stale_connections(uint64_t now_mono_ns)
{
	unsigned int i;

	for (i = 0; i < HTTP_SERVICE_POOL_SIZE; i++) {
		struct http_conn_slot *slot = &http_slots[i];

		if (!slot->in_use)
			continue;
		if (now_mono_ns > slot->last_active_ns &&
		    now_mono_ns - slot->last_active_ns >=
			    HTTP_SERVICE_CONN_IDLE_TIMEOUT_NS)
			close_slot_pcb(slot);
	}
}

enum hyperv_acceptance_result
hyperv_acceptance_run_http_service(unsigned int network_offers,
				   int binding_ready,
				   uint64_t t_vmbus_ready_ns)
{
	__u64 t_efi_pre_exit = 0;
	__u64 t_time_init = 0;
	uint64_t t_vmbus_ready;
	uint64_t t_net_ready;
	uint64_t t_http_ready;
	uint64_t guest_internal_init_ns;
	uint64_t boot_id;
	uint64_t service_start_mono_ns;
	uint64_t service_duration_ns;
	uint64_t next_stats_mono_ns;
	struct uk_netdev *device;
	struct netif *netif = NULL;
	struct tcp_pcb *raw_pcb;
	struct tcp_pcb *listen_pcb;
	char ipv4_str[16];
	unsigned int i;
	err_t err;

	puts("STAGE:http-service-start");
	uk_hyperv_boot_ref_timestamps(&t_efi_pre_exit, &t_time_init);
	t_vmbus_ready = t_vmbus_ready_ns ? t_vmbus_ready_ns :
			((uint64_t)t_time_init + (uint64_t)ukplat_monotonic_clock());

	boot_id = derive_boot_id((uint64_t)t_efi_pre_exit,
				 (uint64_t)t_time_init, t_vmbus_ready);
	uk_hyperv_http_format_boot_id(boot_id, http_boot_id_hex);
	uk_hyperv_http_fill_body(http_body);
	memset(&http_metrics, 0, sizeof(http_metrics));
	memset(http_slots, 0, sizeof(http_slots));

	if ((network_offers && !binding_ready) || !uk_netdev_count()) {
		printf("HYPERV_ACCEPTANCE HTTP_SERVICE FAIL "
		       "reason=no-netdev offers=%u binding_ready=%d\n",
		       network_offers, binding_ready);
		return HYPERV_ACCEPTANCE_FAIL;
	}

	device = uk_netdev_get(0);
	if (acquire_http_lease(device, &netif) != 0 || !netif) {
		puts("HYPERV_ACCEPTANCE HTTP_SERVICE FAIL reason=dhcp-lease");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	t_net_ready = t_time_init + (uint64_t)ukplat_monotonic_clock();

	raw_pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
	if (!raw_pcb) {
		http_adapter_release();
		puts("HYPERV_ACCEPTANCE HTTP_SERVICE FAIL reason=tcp-new");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	ip_set_option(raw_pcb, SOF_REUSEADDR);
	err = tcp_bind(raw_pcb, IP4_ADDR_ANY,
		       (uint16_t)CONFIG_APPHYPERVACCEPTANCE_HTTP_PORT);
	if (err != ERR_OK) {
		tcp_abort(raw_pcb);
		http_adapter_release();
		printf("HYPERV_ACCEPTANCE HTTP_SERVICE FAIL "
		       "reason=tcp-bind rc=%d\n", (int)err);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	listen_pcb = tcp_listen_with_backlog(
		raw_pcb, (uint8_t)HTTP_SERVICE_POOL_SIZE);
	if (!listen_pcb) {
		tcp_abort(raw_pcb);
		http_adapter_release();
		puts("HYPERV_ACCEPTANCE HTTP_SERVICE FAIL reason=tcp-listen");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	tcp_accept(listen_pcb, http_accept_cb);

	t_http_ready = t_time_init + (uint64_t)ukplat_monotonic_clock();
	guest_internal_init_ns = (t_http_ready >= t_efi_pre_exit) ?
				 (t_http_ready - t_efi_pre_exit) : 0ULL;

	ip4addr_ntoa_r(netif_ip4_addr(netif), ipv4_str, sizeof(ipv4_str));
	printf("UK_HYPERV_HTTP_SERVICE_CONFIG port=%u duration_ms=%u "
	       "max_conns=%u body_bytes=%u boot_id=%s ipv4=%s\n",
	       (unsigned int)CONFIG_APPHYPERVACCEPTANCE_HTTP_PORT,
	       (unsigned int)CONFIG_APPHYPERVACCEPTANCE_HTTP_DURATION_MS,
	       (unsigned int)HTTP_SERVICE_POOL_SIZE,
	       (unsigned int)UK_HYPERV_HTTP_BODY_LEN,
	       http_boot_id_hex, ipv4_str);
	printf("UK_HYPERV_BOOT_TIMING boot_id=%s "
	       "t_efi_pre_exit=%" PRIu64 " t_time_init=%" PRIu64
	       " t_vmbus_ready=%" PRIu64 " t_net_ready=%" PRIu64
	       " t_http_ready=%" PRIu64 " guest_internal_init_ns=%" PRIu64 "\n",
	       http_boot_id_hex, (uint64_t)t_efi_pre_exit, (uint64_t)t_time_init,
	       t_vmbus_ready, t_net_ready, t_http_ready,
	       guest_internal_init_ns);
	puts("STAGE:http-service-ready");
	emit_http_service_stats("idle", 0);

	service_start_mono_ns = (uint64_t)ukplat_monotonic_clock();
	service_duration_ns =
		(uint64_t)CONFIG_APPHYPERVACCEPTANCE_HTTP_DURATION_MS *
		1000000ULL;
	next_stats_mono_ns = service_start_mono_ns +
			     HTTP_SERVICE_STATS_INTERVAL_NS;

	for (;;) {
		uint64_t now_mono_ns = (uint64_t)ukplat_monotonic_clock();
		unsigned int packets;

		if (now_mono_ns >= service_start_mono_ns &&
		    now_mono_ns - service_start_mono_ns >= service_duration_ns)
			break;

		packets = http_adapter_poll();
		if (http_adapter.failure != HTTP_ADAPTER_OK) {
			http_adapter_release();
			emit_http_service_stats(
				"error",
				(now_mono_ns - service_start_mono_ns) /
					1000000ULL);
			puts("HYPERV_ACCEPTANCE HTTP_SERVICE FAIL "
			     "reason=adapter-failure");
			return HYPERV_ACCEPTANCE_FAIL;
		}

		now_mono_ns = (uint64_t)ukplat_monotonic_clock();
		if (now_mono_ns >= next_stats_mono_ns) {
			reap_stale_connections(now_mono_ns);
			emit_http_service_stats(
				"periodic",
				(now_mono_ns - service_start_mono_ns) /
					1000000ULL);
			next_stats_mono_ns = now_mono_ns +
					     HTTP_SERVICE_STATS_INTERVAL_NS;
		}

		if (packets == 0)
			uk_sched_thread_sleep(HTTP_SERVICE_IDLE_SLEEP_NS);
	}

	for (i = 0; i < HTTP_SERVICE_POOL_SIZE; i++) {
		if (http_slots[i].in_use)
			close_slot_pcb(&http_slots[i]);
	}
	(void)tcp_close(listen_pcb);
	http_adapter_release();

	emit_http_service_stats(
		"final",
		(uint64_t)CONFIG_APPHYPERVACCEPTANCE_HTTP_DURATION_MS);
	puts("STAGE:http-service-complete");
	puts("UK_HYPERV_HTTP_SERVICE_READY");
	return HYPERV_ACCEPTANCE_PASS;
}

#endif /* CONFIG_APPHYPERVACCEPTANCE_HTTP_SERVICE */

#else

enum hyperv_acceptance_result
hyperv_acceptance_run_http_service(unsigned int network_offers,
				   int binding_ready,
				   uint64_t t_vmbus_ready_ns)
{
	(void)network_offers;
	(void)binding_ready;
	(void)t_vmbus_ready_ns;
	return HYPERV_ACCEPTANCE_UNAVAILABLE;
}

#endif /* CONFIG_APPHYPERVACCEPTANCE_HTTP_SERVICE || HYPERV_HTTP_SERVICE_HOST_TEST */
