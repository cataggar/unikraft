/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Bounded adapter portions derive from unikraft/lib-lwip uknetdev.c.
 * Copyright (c) 2019, NEC Laboratories Europe GmbH, NEC Corporation.
 */
#include "application_network.h"

#include <uk/config.h>

#if CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION

#include "application_protocol.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <lwip/dhcp.h>
#include <lwip/etharp.h>
#include <lwip/ip4_addr.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/udp.h>
#include <netif/uknetdev.h>
#include <uk/alloc.h>
#include <uk/netdev.h>
#include <uk/plat/time.h>
#include <uk/sched.h>

#include "netbuf.h"

#define APPLICATION_DHCP_TIMEOUT_NS (12ULL * 1000000000ULL)
#define APPLICATION_ARP_TIMEOUT_NS (5ULL * 1000000000ULL)
#define APPLICATION_IO_TIMEOUT_NS (5ULL * 1000000000ULL)
#define APPLICATION_POLL_INTERVAL_NS 1000000ULL
#define APPLICATION_ARP_RETRY_NS 1000000000ULL
#define APPLICATION_TCP_CONNECTIONS 3U
#define APPLICATION_UDP_DATAGRAMS 6U
#define APPLICATION_NETDEV_BUFFER_SIZE 2048U

static const size_t tcp_body_lengths[APPLICATION_TCP_CONNECTIONS] = {
	31, 1400, 257
};
static const size_t udp_body_lengths[APPLICATION_UDP_DATAGRAMS] = {
	19, 1448, 73, 1448, 257, 19
};

struct tcp_exchange {
	struct tcp_pcb *pcb;
	uint8_t transmit[HYPERV_ACCEPTANCE_APP_MAX_MESSAGE_SIZE];
	uint8_t receive[HYPERV_ACCEPTANCE_APP_MAX_MESSAGE_SIZE];
	size_t transmit_length;
	size_t transmit_offset;
	size_t receive_length;
	size_t receive_expected;
	size_t next_chunk;
	uint32_t sequence;
	uint32_t acknowledged;
	unsigned int write_chunks;
	unsigned int receive_callbacks;
	unsigned int receive_pbufs_freed;
	uint64_t nonce;
	int connected;
	int response_valid;
	int peer_closed;
	int failed;
	err_t error;
	const char *failure;
};

struct tcp_totals {
	unsigned int connections;
	unsigned int transmit_messages;
	unsigned int receive_messages;
	unsigned int write_chunks;
	unsigned int receive_callbacks;
	unsigned int receive_pbufs_freed;
	unsigned int close_accepted;
	size_t transmit_bytes;
	size_t receive_bytes;
};

struct udp_exchange {
	const ip_addr_t *peer;
	uint16_t port;
	uint32_t sequence;
	size_t body_length;
	uint64_t nonce;
	uint8_t receive[HYPERV_ACCEPTANCE_APP_MAX_MESSAGE_SIZE];
	size_t receive_length;
	unsigned int unrelated;
	unsigned int receive_pbufs_freed;
	int received;
	int failed;
	const char *failure;
};

struct udp_totals {
	unsigned int transmit_datagrams;
	unsigned int receive_datagrams;
	unsigned int pbuf_allocated;
	unsigned int pbuf_freed;
	unsigned int receive_pbufs_freed;
	unsigned int pcb_removed;
	unsigned int unrelated;
	size_t transmit_bytes;
	size_t receive_bytes;
};

enum bounded_adapter_failure {
	BOUNDED_ADAPTER_OK,
	BOUNDED_ADAPTER_TX_BUSY,
	BOUNDED_ADAPTER_TX_ERROR,
	BOUNDED_ADAPTER_RX_ERROR,
	BOUNDED_ADAPTER_INPUT_ERROR,
};

struct bounded_adapter {
	struct netif *netif;
	struct uk_netdev *device;
	struct uk_alloc *allocator;
	struct uk_netdev_info info;
	enum bounded_adapter_failure failure;
	unsigned int receive_packets;
	unsigned int receive_budget_exhaustions;
	unsigned int transmit_attempts;
	unsigned int transmit_busy;
};

struct bounded_tx_attempt {
	struct uk_netdev *device;
	struct uk_netbuf *buffer;
};

static struct bounded_adapter application_adapter;

static const char *application_result_name(
	enum hyperv_acceptance_result result)
{
	switch (result) {
	case HYPERV_ACCEPTANCE_PASS:
		return "PASS";
	case HYPERV_ACCEPTANCE_FAIL:
		return "FAIL";
	case HYPERV_ACCEPTANCE_UNAVAILABLE:
		return "UNAVAILABLE";
	}
	return "FAIL";
}

static const char *bounded_adapter_failure_name(void)
{
	switch (application_adapter.failure) {
	case BOUNDED_ADAPTER_OK:
		return "none";
	case BOUNDED_ADAPTER_TX_BUSY:
		return "tx-busy";
	case BOUNDED_ADAPTER_TX_ERROR:
		return "tx-error";
	case BOUNDED_ADAPTER_RX_ERROR:
		return "rx-error";
	case BOUNDED_ADAPTER_INPUT_ERROR:
		return "stack-input";
	}
	return "unknown";
}

static void bounded_adapter_fail(enum bounded_adapter_failure failure)
{
	if (application_adapter.failure == BOUNDED_ADAPTER_OK)
		application_adapter.failure = failure;
}

static int bounded_tx_one(void *argument)
{
	struct bounded_tx_attempt *attempt = argument;

	return uk_netdev_tx_one(attempt->device, 0, attempt->buffer);
}

static err_t bounded_adapter_output(struct netif *netif, struct pbuf *pbuf)
{
	struct bounded_tx_attempt attempt;
	struct uk_netbuf *buffer;
	struct pbuf *part;
	char *write_position;
	unsigned int attempts;
	int status;

	if (netif != application_adapter.netif ||
	    netif->state != application_adapter.device) {
		bounded_adapter_fail(BOUNDED_ADAPTER_TX_ERROR);
		return ERR_IF;
	}
	buffer = uk_netbuf_alloc_buf(
		application_adapter.allocator, APPLICATION_NETDEV_BUFFER_SIZE,
		application_adapter.info.ioalign,
		application_adapter.info.nb_encap_tx, 0, NULL);
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

	attempt.device = application_adapter.device;
	attempt.buffer = buffer;
	status = hyperv_acceptance_app_single_tx_attempt(
		bounded_tx_one, &attempt, &attempts);
	application_adapter.transmit_attempts += attempts;
	if (uk_netdev_status_notready(status)) {
		application_adapter.transmit_busy++;
		bounded_adapter_fail(BOUNDED_ADAPTER_TX_BUSY);
		uk_netbuf_free_single(buffer);
		return ERR_IF;
	}
	if (status < 0) {
		bounded_adapter_fail(BOUNDED_ADAPTER_TX_ERROR);
		uk_netbuf_free_single(buffer);
		return ERR_IF;
	}
	return ERR_OK;
}

static int bounded_adapter_rx_step(void *argument)
{
	struct bounded_adapter *adapter = argument;
	struct uk_netbuf *buffer;
	struct uk_netbuf *next;
	struct pbuf *pbuf;
	struct pbuf *part;
	err_t error;
	int status;

	status = uk_netdev_rx_one(adapter->device, 0, &buffer);
	if (status < 0) {
		bounded_adapter_fail(BOUNDED_ADAPTER_RX_ERROR);
		netif_set_down(adapter->netif);
		return HYPERV_ACCEPTANCE_APP_RX_ERROR;
	}
	if (uk_netdev_status_notready(status))
		return HYPERV_ACCEPTANCE_APP_RX_IDLE;
	if (!buffer) {
		bounded_adapter_fail(BOUNDED_ADAPTER_RX_ERROR);
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
		bounded_adapter_fail(BOUNDED_ADAPTER_INPUT_ERROR);
		return HYPERV_ACCEPTANCE_APP_RX_ERROR;
	}
	return uk_netdev_status_more(status) ?
	       HYPERV_ACCEPTANCE_APP_RX_MORE :
	       HYPERV_ACCEPTANCE_APP_RX_LAST;
}

static int bounded_adapter_attach(
	struct netif *netif, struct uk_netdev *device)
{
	memset(&application_adapter, 0, sizeof(application_adapter));
	application_adapter.netif = netif;
	application_adapter.device = device;
	application_adapter.allocator = uk_alloc_get_default();
	if (!application_adapter.allocator || netif->state != device)
		return -1;
	uk_netdev_info_get(device, &application_adapter.info);
	netif->linkoutput = bounded_adapter_output;
	return 0;
}

static int bounded_adapter_poll(void)
{
	struct hyperv_acceptance_app_rx_result result;

	result = hyperv_acceptance_app_bounded_rx_drain(
		bounded_adapter_rx_step, &application_adapter);
	if (result.budget_exhausted)
		application_adapter.receive_budget_exhaustions++;
	if (result.error && application_adapter.failure == BOUNDED_ADAPTER_OK)
		bounded_adapter_fail(BOUNDED_ADAPTER_RX_ERROR);
	return application_adapter.failure != BOUNDED_ADAPTER_OK;
}

static int application_pump(void)
{
	(void)bounded_adapter_poll();
	sys_check_timeouts();
	return application_adapter.failure != BOUNDED_ADAPTER_OK;
}

static int application_wait(void)
{
	if (application_pump())
		return -1;
	uk_sched_thread_sleep(APPLICATION_POLL_INTERVAL_NS);
	return 0;
}

static int private_ipv4(const ip4_addr_t *address)
{
	uint32_t value = lwip_ntohl(ip4_addr_get_u32(address));

	return (value & 0xff000000U) == 0x0a000000U ||
	       (value & 0xfff00000U) == 0xac100000U ||
	       (value & 0xffff0000U) == 0xc0a80000U;
}

static void print_unavailable_stages(enum hyperv_acceptance_result result,
				     const char *reason)
{
	printf("HYPERV_ACCEPTANCE NETWORK_APP_LEASE %s reason=%s\n",
	       application_result_name(result), reason);
	printf("HYPERV_ACCEPTANCE NETWORK_APP_ARP %s reason=%s\n",
	       application_result_name(result), reason);
	printf("HYPERV_ACCEPTANCE NETWORK_APP_TCP %s reason=%s\n",
	       application_result_name(result), reason);
	printf("HYPERV_ACCEPTANCE NETWORK_APP_UDP %s reason=%s\n",
	       application_result_name(result), reason);
	printf("HYPERV_ACCEPTANCE NETWORK_APP_FINAL %s reason=%s\n",
	       application_result_name(result), reason);
}

static enum hyperv_acceptance_result acquire_lease(struct uk_netdev *device,
						    struct netif **netif_out)
{
	struct netif *netif;
	struct dhcp *client;
	char address[16];
	char netmask[16];
	char gateway[16];
	char server[16];
	uint64_t deadline;
	err_t error;
	int rc;

	if (uk_netdev_state_get(device) == UK_NETDEV_UNPROBED) {
		rc = uk_netdev_probe(device);
		if (rc) {
			printf("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
			       "reason=probe rc=%d\n", rc);
			return HYPERV_ACCEPTANCE_FAIL;
		}
	}
	if (uk_netdev_state_get(device) != UK_NETDEV_UNCONFIGURED) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		       "reason=unexpected-state state=%d\n",
		       uk_netdev_state_get(device));
		return HYPERV_ACCEPTANCE_FAIL;
	}

	netif = uknetdev_addif(device, NULL, NULL, NULL,
			      "hyperv-acceptance");
	if (!netif) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		     "reason=stack-attach");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (bounded_adapter_attach(netif, device)) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		     "reason=bounded-adapter-attach");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	netif_set_default(netif);
	netif_set_up(netif);
	error = dhcp_start(netif);
	if (error != ERR_OK) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		       "reason=dhcp-start rc=%d\n", (int)error);
		return HYPERV_ACCEPTANCE_FAIL;
	}

	deadline = ukplat_monotonic_clock() + APPLICATION_DHCP_TIMEOUT_NS;
	while (ukplat_monotonic_clock() < deadline) {
		if (dhcp_supplied_address(netif))
			break;
		if (application_wait()) {
			printf("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
			       "reason=adapter-%s\n",
			       bounded_adapter_failure_name());
			return HYPERV_ACCEPTANCE_FAIL;
		}
	}
	if (!dhcp_supplied_address(netif)) {
		dhcp_stop(netif);
		puts("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		     "reason=dhcp-timeout");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	client = netif_dhcp_data(netif);
	if (!client ||
	    !ip4_addr_cmp(&client->offered_ip_addr,
			  netif_ip4_addr(netif))) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		     "reason=lease-not-applied");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!ip4addr_ntoa_r(netif_ip4_addr(netif), address, sizeof(address)) ||
	    !ip4addr_ntoa_r(netif_ip4_netmask(netif), netmask,
			    sizeof(netmask)) ||
	    !ip4addr_ntoa_r(netif_ip4_gw(netif), gateway, sizeof(gateway)) ||
	    !ipaddr_ntoa_r(&client->server_ip_addr, server, sizeof(server))) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_LEASE FAIL "
		     "reason=address-format");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_ACCEPTANCE NETWORK_APP_LEASE PASS "
	       "address=%s netmask=%s gateway=%s mtu=%" PRIu16
	       " server=%s xid=%08" PRIx32 " state=%" PRIu8
	       " retries=%" PRIu8 " lease_seconds=%" PRIu32
	       " proof=discover-offer-request-ack-bound\n",
	       address, netmask, gateway, netif->mtu, server, client->xid,
	       client->state, client->tries, client->offered_t0_lease);
	puts("UK_HYPERV_NET_APP_LEASE");
	*netif_out = netif;
	return HYPERV_ACCEPTANCE_PASS;
}

static enum hyperv_acceptance_result resolve_peer(
	struct netif *netif, const ip4_addr_t *peer)
{
	struct eth_addr *hardware_address;
	const ip4_addr_t *cached_address;
	uint64_t deadline;
	uint64_t next_request = 0;
	unsigned int requests = 0;
	err_t error;

	if (!ip4_addr_netcmp(peer, netif_ip4_addr(netif),
			    netif_ip4_netmask(netif))) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_ARP FAIL "
		     "reason=peer-not-on-link");
		return HYPERV_ACCEPTANCE_FAIL;
	}

	deadline = ukplat_monotonic_clock() + APPLICATION_ARP_TIMEOUT_NS;
	while (ukplat_monotonic_clock() < deadline) {
		uint64_t now = ukplat_monotonic_clock();

		if (etharp_find_addr(netif, peer, &hardware_address,
				    &cached_address) >= 0) {
			printf("HYPERV_ACCEPTANCE NETWORK_APP_ARP PASS "
			       "peer=%s mac=%02x:%02x:%02x:%02x:%02x:%02x "
			       "requests=%u\n",
			       CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4,
			       hardware_address->addr[0],
			       hardware_address->addr[1],
			       hardware_address->addr[2],
			       hardware_address->addr[3],
			       hardware_address->addr[4],
			       hardware_address->addr[5], requests);
			puts("UK_HYPERV_NET_APP_ARP");
			return HYPERV_ACCEPTANCE_PASS;
		}
		if (now >= next_request) {
			error = etharp_request(netif, peer);
			requests++;
			if (error != ERR_OK) {
				printf("HYPERV_ACCEPTANCE NETWORK_APP_ARP FAIL "
				       "reason=request rc=%d requests=%u\n",
				       (int)error, requests);
				return HYPERV_ACCEPTANCE_FAIL;
			}
			next_request = now + APPLICATION_ARP_RETRY_NS;
		}
		if (application_wait()) {
			printf("HYPERV_ACCEPTANCE NETWORK_APP_ARP FAIL "
			       "reason=adapter-%s requests=%u\n",
			       bounded_adapter_failure_name(), requests);
			return HYPERV_ACCEPTANCE_FAIL;
		}
	}
	printf("HYPERV_ACCEPTANCE NETWORK_APP_ARP FAIL "
	       "reason=timeout peer=%s requests=%u\n",
	       CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4, requests);
	return HYPERV_ACCEPTANCE_FAIL;
}

static err_t tcp_connected_callback(void *arg, struct tcp_pcb *pcb,
				    err_t error)
{
	struct tcp_exchange *exchange = arg;

	(void)pcb;
	if (error != ERR_OK) {
		exchange->failed = 1;
		exchange->error = error;
		exchange->failure = "connect-callback";
		return error;
	}
	exchange->connected = 1;
	return ERR_OK;
}

static err_t tcp_sent_callback(void *arg, struct tcp_pcb *pcb, uint16_t length)
{
	struct tcp_exchange *exchange = arg;

	(void)pcb;
	exchange->acknowledged += length;
	if (exchange->acknowledged > exchange->transmit_length) {
		exchange->failed = 1;
		exchange->failure = "ack-overflow";
	}
	return ERR_OK;
}

static err_t tcp_receive_callback(void *arg, struct tcp_pcb *pcb,
				  struct pbuf *pbuf, err_t error)
{
	struct tcp_exchange *exchange = arg;
	size_t remaining;

	if (!pbuf) {
		exchange->peer_closed = 1;
		if (!exchange->response_valid) {
			exchange->failed = 1;
			exchange->failure = "peer-closed-early";
		}
		return ERR_OK;
	}
	exchange->receive_callbacks++;
	if (error != ERR_OK) {
		exchange->failed = 1;
		exchange->error = error;
		exchange->failure = "receive";
		pbuf_free(pbuf);
		exchange->receive_pbufs_freed++;
		return ERR_OK;
	}
	remaining = exchange->receive_expected - exchange->receive_length;
	if (pbuf->tot_len > remaining ||
	    pbuf_copy_partial(pbuf,
			      exchange->receive + exchange->receive_length,
			      pbuf->tot_len, 0) != pbuf->tot_len) {
		exchange->failed = 1;
		exchange->failure = "response-overflow";
		tcp_recved(pcb, pbuf->tot_len);
		pbuf_free(pbuf);
		exchange->receive_pbufs_freed++;
		return ERR_OK;
	}
	exchange->receive_length += pbuf->tot_len;
	tcp_recved(pcb, pbuf->tot_len);
	pbuf_free(pbuf);
	exchange->receive_pbufs_freed++;
	if (exchange->receive_length == exchange->receive_expected) {
		int validation = hyperv_acceptance_app_validate(
			exchange->receive, exchange->receive_length,
			HYPERV_ACCEPTANCE_APP_TCP,
			HYPERV_ACCEPTANCE_APP_RESPONSE, exchange->sequence,
			exchange->receive_expected -
				HYPERV_ACCEPTANCE_APP_HEADER_SIZE,
			exchange->nonce);

		if (validation) {
			exchange->failed = 1;
			exchange->failure = "response-content";
			exchange->error = (err_t)validation;
		} else {
			exchange->response_valid = 1;
		}
	}
	return ERR_OK;
}

static void tcp_error_callback(void *arg, err_t error)
{
	struct tcp_exchange *exchange = arg;

	exchange->pcb = NULL;
	exchange->failed = 1;
	exchange->error = error;
	exchange->failure = "stack";
}

static int tcp_send_chunk(struct tcp_exchange *exchange)
{
	static const size_t chunks[] = { 7, 113, 509 };
	size_t remaining = exchange->transmit_length -
			   exchange->transmit_offset;
	size_t length = chunks[exchange->next_chunk %
			       (sizeof(chunks) / sizeof(chunks[0]))];
	err_t error;

	if (!exchange->pcb) {
		exchange->failed = 1;
		exchange->failure = "pcb-lost";
		return -1;
	}
	if (length > remaining)
		length = remaining;
	if (length > tcp_sndbuf(exchange->pcb))
		length = tcp_sndbuf(exchange->pcb);
	if (!length)
		return 0;
	error = tcp_write(exchange->pcb,
			  exchange->transmit + exchange->transmit_offset,
			  (uint16_t)length, TCP_WRITE_FLAG_COPY);
	if (error == ERR_MEM)
		return 0;
	if (error != ERR_OK) {
		exchange->failed = 1;
		exchange->error = error;
		exchange->failure = "write";
		return -1;
	}
	exchange->transmit_offset += length;
	exchange->next_chunk++;
	exchange->write_chunks++;
	error = tcp_output(exchange->pcb);
	if (error != ERR_OK) {
		exchange->failed = 1;
		exchange->error = error;
		exchange->failure = "output";
		return -1;
	}
	return 1;
}

static int run_tcp_connection(
	const ip_addr_t *peer, uint32_t sequence, size_t body_length,
	uint64_t nonce, struct tcp_totals *totals)
{
	struct tcp_exchange exchange;
	uint64_t deadline;
	err_t error;
	int close_accepted = 0;

	memset(&exchange, 0, sizeof(exchange));
	exchange.sequence = sequence;
	exchange.nonce = nonce;
	exchange.transmit_length = hyperv_acceptance_app_build(
		exchange.transmit, sizeof(exchange.transmit),
		HYPERV_ACCEPTANCE_APP_TCP, HYPERV_ACCEPTANCE_APP_REQUEST,
		sequence, body_length, exchange.nonce);
	exchange.receive_expected =
		HYPERV_ACCEPTANCE_APP_HEADER_SIZE + body_length;
	if (!exchange.transmit_length)
		return -1;

	exchange.pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
	if (!exchange.pcb)
		return -1;
	tcp_arg(exchange.pcb, &exchange);
	tcp_recv(exchange.pcb, tcp_receive_callback);
	tcp_sent(exchange.pcb, tcp_sent_callback);
	tcp_err(exchange.pcb, tcp_error_callback);
	tcp_nagle_disable(exchange.pcb);
	error = tcp_connect(exchange.pcb, peer,
			    CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT,
			    tcp_connected_callback);
	if (error != ERR_OK) {
		exchange.error = error;
		exchange.failure = "connect";
		exchange.failed = 1;
	}

	deadline = ukplat_monotonic_clock() + APPLICATION_IO_TIMEOUT_NS;
	while (!exchange.failed && ukplat_monotonic_clock() < deadline) {
		enum hyperv_acceptance_app_tcp_action action;

		if (application_pump()) {
			exchange.failed = 1;
			exchange.error = ERR_IF;
			exchange.failure = bounded_adapter_failure_name();
		}
		action = hyperv_acceptance_app_tcp_next_action(
			exchange.failed, exchange.pcb != NULL,
			exchange.connected,
			exchange.transmit_offset < exchange.transmit_length,
			exchange.response_valid,
			exchange.acknowledged == exchange.transmit_length);
		if (action == HYPERV_ACCEPTANCE_APP_TCP_FAIL)
			break;
		if (action == HYPERV_ACCEPTANCE_APP_TCP_SEND) {
			(void)tcp_send_chunk(&exchange);
			if (application_adapter.failure != BOUNDED_ADAPTER_OK &&
			    !exchange.failed) {
				exchange.failed = 1;
				exchange.error = ERR_IF;
				exchange.failure =
					bounded_adapter_failure_name();
			}
			action = hyperv_acceptance_app_tcp_next_action(
				exchange.failed, exchange.pcb != NULL,
				exchange.connected,
				exchange.transmit_offset <
					exchange.transmit_length,
				exchange.response_valid,
				exchange.acknowledged ==
					exchange.transmit_length);
			if (action == HYPERV_ACCEPTANCE_APP_TCP_FAIL)
				break;
		}
		if (action == HYPERV_ACCEPTANCE_APP_TCP_CLOSE) {
			tcp_arg(exchange.pcb, NULL);
			tcp_recv(exchange.pcb, NULL);
			tcp_sent(exchange.pcb, NULL);
			tcp_err(exchange.pcb, NULL);
			error = tcp_close(exchange.pcb);
			if (error == ERR_OK) {
				exchange.pcb = NULL;
				close_accepted = 1;
				break;
			}
			tcp_arg(exchange.pcb, &exchange);
			tcp_recv(exchange.pcb, tcp_receive_callback);
			tcp_sent(exchange.pcb, tcp_sent_callback);
			tcp_err(exchange.pcb, tcp_error_callback);
			if (error != ERR_MEM) {
				exchange.failed = 1;
				exchange.error = error;
				exchange.failure = "close";
			}
		}
		uk_sched_thread_sleep(APPLICATION_POLL_INTERVAL_NS);
	}
	if (exchange.pcb) {
		tcp_arg(exchange.pcb, NULL);
		tcp_recv(exchange.pcb, NULL);
		tcp_sent(exchange.pcb, NULL);
		tcp_err(exchange.pcb, NULL);
		tcp_abort(exchange.pcb);
		exchange.pcb = NULL;
	}
	if (application_adapter.failure != BOUNDED_ADAPTER_OK &&
	    !exchange.failed) {
		exchange.failed = 1;
		exchange.error = ERR_IF;
		exchange.failure = bounded_adapter_failure_name();
	}
	if (!close_accepted || exchange.failed) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_TCP_CONNECTION FAIL "
		       "reason=%s sequence=%" PRIu32 " rc=%d "
		       "tx=%zu/%zu ack=%" PRIu32 " rx=%zu/%zu "
		       "rx_callbacks=%u rx_pbuf_freed=%u\n",
		       exchange.failed ? exchange.failure : "timeout",
		       sequence, (int)exchange.error, exchange.transmit_offset,
		       exchange.transmit_length, exchange.acknowledged,
		       exchange.receive_length, exchange.receive_expected,
		       exchange.receive_callbacks,
		       exchange.receive_pbufs_freed);
		return -1;
	}
	if (exchange.receive_pbufs_freed != exchange.receive_callbacks) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_TCP_CONNECTION FAIL "
		       "reason=receive-cleanup sequence=%" PRIu32
		       " rx_callbacks=%u rx_pbuf_freed=%u\n",
		       sequence, exchange.receive_callbacks,
		       exchange.receive_pbufs_freed);
		return -1;
	}

	totals->connections++;
	totals->transmit_messages++;
	totals->receive_messages++;
	totals->write_chunks += exchange.write_chunks;
	totals->receive_callbacks += exchange.receive_callbacks;
	totals->receive_pbufs_freed += exchange.receive_pbufs_freed;
	totals->close_accepted++;
	totals->transmit_bytes += exchange.transmit_length;
	totals->receive_bytes += exchange.receive_length;
	return 0;
}

static enum hyperv_acceptance_result run_tcp(
	const ip_addr_t *peer, uint64_t nonce)
{
	struct tcp_totals totals = { 0 };
	unsigned int index;

	for (index = 0; index < APPLICATION_TCP_CONNECTIONS; index++) {
		if (run_tcp_connection(peer, index + 1,
				       tcp_body_lengths[index], nonce, &totals)) {
			printf("HYPERV_ACCEPTANCE NETWORK_APP_TCP FAIL "
			       "reason=connection sequence=%u completed=%u "
			       "tx_messages=%u rx_messages=%u "
			       "close_accepted=%u\n", index + 1,
			       totals.connections, totals.transmit_messages,
			       totals.receive_messages, totals.close_accepted);
			return HYPERV_ACCEPTANCE_FAIL;
		}
	}
	printf("HYPERV_ACCEPTANCE NETWORK_APP_TCP PASS "
	       "connections=%u tx_messages=%u rx_messages=%u "
	       "tx_bytes=%zu rx_bytes=%zu write_chunks=%u "
	       "rx_callbacks=%u rx_pbuf_freed=%u close_accepted=%u\n",
	       totals.connections, totals.transmit_messages,
	       totals.receive_messages, totals.transmit_bytes,
	       totals.receive_bytes, totals.write_chunks,
	       totals.receive_callbacks, totals.receive_pbufs_freed,
	       totals.close_accepted);
	puts("UK_HYPERV_NET_APP_TCP");
	return HYPERV_ACCEPTANCE_PASS;
}

static void udp_receive_callback(void *arg, struct udp_pcb *pcb,
				 struct pbuf *pbuf, const ip_addr_t *address,
				 uint16_t port)
{
	struct udp_exchange *exchange = arg;
	int validation;

	(void)pcb;
	if (!pbuf)
		return;
	if (!ip_addr_cmp(address, exchange->peer) || port != exchange->port) {
		exchange->unrelated++;
		pbuf_free(pbuf);
		exchange->receive_pbufs_freed++;
		return;
	}
	if (exchange->received) {
		exchange->failed = 1;
		exchange->failure = "duplicate-response";
		pbuf_free(pbuf);
		exchange->receive_pbufs_freed++;
		return;
	}
	if (pbuf->tot_len > sizeof(exchange->receive) ||
	    pbuf_copy_partial(pbuf, exchange->receive, pbuf->tot_len, 0) !=
		    pbuf->tot_len) {
		exchange->failed = 1;
		exchange->failure = "response-overflow";
		pbuf_free(pbuf);
		exchange->receive_pbufs_freed++;
		return;
	}
	exchange->receive_length = pbuf->tot_len;
	pbuf_free(pbuf);
	exchange->receive_pbufs_freed++;
	validation = hyperv_acceptance_app_validate(
		exchange->receive, exchange->receive_length,
		HYPERV_ACCEPTANCE_APP_UDP, HYPERV_ACCEPTANCE_APP_RESPONSE,
		exchange->sequence, exchange->body_length, exchange->nonce);
	if (validation) {
		exchange->failed = 1;
		exchange->failure = "response-content";
		return;
	}
	exchange->received = 1;
}

static enum hyperv_acceptance_result run_udp(
	const ip_addr_t *peer, uint64_t nonce)
{
	struct udp_exchange exchange;
	struct udp_totals totals = { 0 };
	struct udp_pcb *pcb;
	uint8_t transmit[HYPERV_ACCEPTANCE_APP_MAX_MESSAGE_SIZE];
	unsigned int index;
	err_t error;

	pcb = udp_new_ip_type(IPADDR_TYPE_V4);
	if (!pcb) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_UDP FAIL "
		     "reason=pcb-allocation");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	error = udp_bind(pcb, IP_ADDR_ANY, 0);
	if (error != ERR_OK) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_UDP FAIL "
		       "reason=bind rc=%d\n", (int)error);
		udp_remove(pcb);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	memset(&exchange, 0, sizeof(exchange));
	exchange.peer = peer;
	exchange.port = CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT;
	exchange.nonce = nonce;
	udp_recv(pcb, udp_receive_callback, &exchange);

	for (index = 0; index < APPLICATION_UDP_DATAGRAMS; index++) {
		struct pbuf *pbuf;
		size_t length;
		uint64_t deadline;

		exchange.sequence = 0x100U + index;
		exchange.body_length = udp_body_lengths[index];
		exchange.receive_length = 0;
		exchange.received = 0;
		exchange.failed = 0;
		exchange.failure = NULL;
		length = hyperv_acceptance_app_build(
			transmit, sizeof(transmit), HYPERV_ACCEPTANCE_APP_UDP,
			HYPERV_ACCEPTANCE_APP_REQUEST, exchange.sequence,
			exchange.body_length, exchange.nonce);
		if (!length) {
			exchange.failed = 1;
			exchange.failure = "message-build";
			break;
		}
		pbuf = pbuf_alloc(PBUF_TRANSPORT, (uint16_t)length, PBUF_RAM);
		if (!pbuf) {
			exchange.failed = 1;
			exchange.failure = "pbuf-allocation";
			break;
		}
		totals.pbuf_allocated++;
		error = pbuf_take(pbuf, transmit, (uint16_t)length);
		if (error == ERR_OK)
			error = udp_sendto(pcb, pbuf, peer, exchange.port);
		pbuf_free(pbuf);
		totals.pbuf_freed++;
		if (error != ERR_OK) {
			exchange.failed = 1;
			exchange.failure = "send";
			break;
		}
		totals.transmit_datagrams++;
		totals.transmit_bytes += length;
		deadline = ukplat_monotonic_clock() +
			   APPLICATION_IO_TIMEOUT_NS;
		while (!exchange.received && !exchange.failed &&
		       ukplat_monotonic_clock() < deadline) {
			if (application_wait()) {
				exchange.failure =
					bounded_adapter_failure_name();
				exchange.failed = 1;
			}
		}
		if (!exchange.received) {
			if (!exchange.failed)
				exchange.failure = "timeout";
			exchange.failed = 1;
			break;
		}
		totals.receive_datagrams++;
		totals.receive_bytes += exchange.receive_length;
	}
	totals.unrelated = exchange.unrelated;
	totals.receive_pbufs_freed = exchange.receive_pbufs_freed;
	udp_recv(pcb, NULL, NULL);
	udp_remove(pcb);
	totals.pcb_removed = 1;
	if (exchange.failed) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_UDP FAIL "
		       "reason=%s sequence=%" PRIu32
		       " tx_datagrams=%u rx_datagrams=%u "
		       "pbuf_allocated=%u pbuf_freed=%u "
		       "rx_pbuf_freed=%u pcb_removed=%u\n",
		       exchange.failure, exchange.sequence,
		       totals.transmit_datagrams, totals.receive_datagrams,
		       totals.pbuf_allocated, totals.pbuf_freed,
		       totals.receive_pbufs_freed, totals.pcb_removed);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (totals.pbuf_allocated != totals.pbuf_freed ||
	    totals.receive_pbufs_freed !=
		    totals.receive_datagrams + totals.unrelated) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_UDP FAIL "
		       "reason=buffer-cleanup pbuf_allocated=%u "
		       "pbuf_freed=%u rx_pbuf_freed=%u expected_rx_freed=%u "
		       "pcb_removed=%u\n",
		       totals.pbuf_allocated, totals.pbuf_freed,
		       totals.receive_pbufs_freed,
		       totals.receive_datagrams + totals.unrelated,
		       totals.pcb_removed);
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_ACCEPTANCE NETWORK_APP_UDP PASS "
	       "datagrams=%u tx_bytes=%zu rx_bytes=%zu "
	       "pbuf_allocated=%u pbuf_freed=%u rx_pbuf_freed=%u "
	       "pcb_removed=%u "
	       "unrelated=%u\n", totals.receive_datagrams,
	       totals.transmit_bytes, totals.receive_bytes,
	       totals.pbuf_allocated, totals.pbuf_freed,
	       totals.receive_pbufs_freed, totals.pcb_removed,
	       totals.unrelated);
	puts("UK_HYPERV_NET_APP_UDP");
	return HYPERV_ACCEPTANCE_PASS;
}

enum hyperv_acceptance_result
hyperv_acceptance_probe_application_network(unsigned int network_offers)
{
	enum hyperv_acceptance_result lease;
	enum hyperv_acceptance_result arp;
	enum hyperv_acceptance_result tcp;
	enum hyperv_acceptance_result udp;
	enum hyperv_acceptance_result result;
	struct uk_netdev *device;
	struct netif *netif = NULL;
	ip4_addr_t peer;
	uint64_t nonce;
	unsigned int index;

	if (hyperv_acceptance_app_parse_nonce(
		    CONFIG_APPHYPERVACCEPTANCE_NONCE, &nonce)) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_CONFIG FAIL "
		       "reason=invalid-nonce nonce=%s\n",
		       CONFIG_APPHYPERVACCEPTANCE_NONCE);
		print_unavailable_stages(
			HYPERV_ACCEPTANCE_FAIL, "invalid-config");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!ip4addr_aton(CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4, &peer)) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_CONFIG FAIL "
		       "reason=invalid-peer-address peer_ipv4=%s\n",
		       CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4);
		print_unavailable_stages(
			HYPERV_ACCEPTANCE_FAIL, "invalid-config");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	if (!private_ipv4(&peer)) {
		printf("HYPERV_ACCEPTANCE NETWORK_APP_CONFIG FAIL "
		       "reason=non-private-peer peer_ipv4=%s\n",
		       CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4);
		print_unavailable_stages(
			HYPERV_ACCEPTANCE_FAIL, "invalid-config");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	printf("HYPERV_ACCEPTANCE NETWORK_APP_CONFIG PASS "
	       "peer_ipv4=%s tcp_port=%u udp_port=%u nonce=%016" PRIx64
	       " tcp_connections=%u udp_datagrams=%u\n",
	       CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4,
	       (unsigned int)CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT,
	       (unsigned int)CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT, nonce,
	       APPLICATION_TCP_CONNECTIONS, APPLICATION_UDP_DATAGRAMS);

	if (!uk_netdev_count()) {
		result = network_offers ? HYPERV_ACCEPTANCE_FAIL :
			 HYPERV_ACCEPTANCE_UNAVAILABLE;
		printf("HYPERV_ACCEPTANCE NETWORK_INVENTORY %s "
		       "devices=0 offers=%u reason=%s\n",
		       application_result_name(result), network_offers,
		       network_offers ? "offered-unbound" :
		       "no-netvsc-offer");
		print_unavailable_stages(
			result, network_offers ? "offered-unbound" :
			"no-netvsc-offer");
		return result;
	}

	device = uk_netdev_get(0);
	for (index = 0; index < uk_netdev_count(); index++) {
		struct uk_netdev *inventory_device = uk_netdev_get(index);
		const char *driver = uk_netdev_drv_name_get(inventory_device);

		printf("HYPERV_ACCEPTANCE NETWORK_DEVICE PASS index=%u "
		       "id=%" PRIu16 " driver=%s state=%d\n", index,
		       uk_netdev_id_get(inventory_device),
		       driver ? driver : "unknown",
		       uk_netdev_state_get(inventory_device));
	}
	printf("HYPERV_ACCEPTANCE NETWORK_INVENTORY PASS devices=%u offers=%u "
	       "selected=%" PRIu16 " driver=%s state=%d mode=application\n",
	       uk_netdev_count(), network_offers, uk_netdev_id_get(device),
	       uk_netdev_drv_name_get(device) ?
	       uk_netdev_drv_name_get(device) : "unknown",
	       uk_netdev_state_get(device));

	lease = acquire_lease(device, &netif);
	if (lease != HYPERV_ACCEPTANCE_PASS) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_ARP FAIL "
		     "reason=prerequisite-lease");
		puts("HYPERV_ACCEPTANCE NETWORK_APP_TCP FAIL "
		     "reason=prerequisite-lease");
		puts("HYPERV_ACCEPTANCE NETWORK_APP_UDP FAIL "
		     "reason=prerequisite-lease");
		puts("HYPERV_ACCEPTANCE NETWORK_APP_FINAL FAIL "
		     "reason=lease");
		return HYPERV_ACCEPTANCE_FAIL;
	}
	arp = resolve_peer(netif, &peer);
	if (arp != HYPERV_ACCEPTANCE_PASS) {
		puts("HYPERV_ACCEPTANCE NETWORK_APP_TCP FAIL "
		     "reason=prerequisite-arp");
		puts("HYPERV_ACCEPTANCE NETWORK_APP_UDP FAIL "
		     "reason=prerequisite-arp");
		puts("HYPERV_ACCEPTANCE NETWORK_APP_FINAL FAIL reason=arp");
		return HYPERV_ACCEPTANCE_FAIL;
	}

	tcp = run_tcp(&peer, nonce);
	udp = run_udp(&peer, nonce);
	result = tcp == HYPERV_ACCEPTANCE_PASS &&
		 udp == HYPERV_ACCEPTANCE_PASS ?
		 HYPERV_ACCEPTANCE_PASS : HYPERV_ACCEPTANCE_FAIL;
	printf("HYPERV_ACCEPTANCE NETWORK_APP_FINAL %s "
	       "lease=PASS arp=PASS tcp=%s udp=%s "
	       "tcp_connections=%u udp_datagrams=%u peer_ipv4=%s "
	       "tcp_port=%u udp_port=%u nonce=%016" PRIx64
	       " adapter_rx_packets=%u adapter_rx_budget_exhaustions=%u "
	       "adapter_tx_attempts=%u adapter_tx_busy=%u\n",
	       application_result_name(result),
	       application_result_name(tcp), application_result_name(udp),
	       tcp == HYPERV_ACCEPTANCE_PASS ?
	       APPLICATION_TCP_CONNECTIONS : 0,
	       udp == HYPERV_ACCEPTANCE_PASS ? APPLICATION_UDP_DATAGRAMS : 0,
	       CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4,
	       (unsigned int)CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT,
	       (unsigned int)CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT, nonce,
	       application_adapter.receive_packets,
	       application_adapter.receive_budget_exhaustions,
	       application_adapter.transmit_attempts,
	       application_adapter.transmit_busy);
	if (result == HYPERV_ACCEPTANCE_PASS)
		puts("UK_HYPERV_NETWORK_APP_READY");
	return result;
}

#else

enum hyperv_acceptance_result
hyperv_acceptance_probe_application_network(unsigned int network_offers)
{
	(void)network_offers;
	return HYPERV_ACCEPTANCE_FAIL;
}

#endif
