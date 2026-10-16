/* SPDX-License-Identifier: BSD-3-Clause */
#define _POSIX_C_SOURCE 200809L

#include "../../../apps/hyperv-acceptance/http_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LINUX_HTTP_MAX_CONNS_CAP 256U
#define LINUX_HTTP_EPOLL_EVENTS 64
#define LINUX_HTTP_STATS_INTERVAL_NS (5ULL * 1000000000ULL)

struct linux_conn_slot {
	int fd;
	uint64_t last_active_ns;
	size_t rx_len;
	size_t tx_len;
	size_t tx_sent;
	uint8_t in_use;
	uint8_t close_after_send;
	uint8_t rx_buf[UK_HYPERV_HTTP_MAX_REQUEST_LEN];
	uint8_t tx_buf[UK_HYPERV_HTTP_MAX_RESPONSE_LEN];
};

struct linux_http_metrics {
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

static struct linux_conn_slot conn_slots[LINUX_HTTP_MAX_CONNS_CAP];
static struct linux_http_metrics metrics;
static uint8_t http_body[UK_HYPERV_HTTP_BODY_LEN];
static char boot_id_hex[17];
static volatile sig_atomic_t stop_requested;

static void handle_sigterm(int signo)
{
	(void)signo;
	stop_requested = 1;
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t derive_linux_boot_id(void)
{
	uint64_t value = 0;
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd >= 0) {
		ssize_t n = read(fd, &value, sizeof(value));

		(void)n;
		close(fd);
	}
	value ^= monotonic_ns() ^ ((uint64_t)getpid() << 32);
	value += 0x9e3779b97f4a7c15ULL;
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
	value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
	value ^= value >> 31;
	return value ? value : 0x4c494e5558303031ULL;
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void query_rss_bytes(uint64_t *rss_bytes, uint64_t *max_rss_bytes)
{
	struct rusage usage;
	FILE *fp;

	*rss_bytes = 0;
	*max_rss_bytes = 0;
	if (getrusage(RUSAGE_SELF, &usage) == 0 && usage.ru_maxrss > 0)
		*max_rss_bytes = (uint64_t)usage.ru_maxrss * 1024ULL;

	fp = fopen("/proc/self/status", "r");
	if (!fp)
		return;
	{
		char line[256];

		while (fgets(line, sizeof(line), fp) != NULL) {
			unsigned long long kb = 0;

			if (sscanf(line, "VmRSS: %llu kB", &kb) == 1) {
				*rss_bytes = (uint64_t)kb * 1024ULL;
				break;
			}
		}
	}
	fclose(fp);
	if (*rss_bytes == 0)
		*rss_bytes = *max_rss_bytes;
}

static void emit_stats(const char *phase, uint64_t elapsed_ms)
{
	uint64_t rss_bytes = 0;
	uint64_t max_rss_bytes = 0;

	query_rss_bytes(&rss_bytes, &max_rss_bytes);
	printf("LINUX_HTTP_SERVICE_STATS phase=%s boot_id=%s "
	       "elapsed_ms=%" PRIu64 " requests=%" PRIu64
	       " bytes_tx=%" PRIu64 " bytes_rx=%" PRIu64
	       " active_conns=%u peak_conns=%u total_conns=%" PRIu64
	       " errors=%" PRIu64 " status_200=%" PRIu64
	       " status_400=%" PRIu64 " status_413=%" PRIu64
	       " rss_bytes=%" PRIu64 " max_rss_bytes=%" PRIu64 "\n",
	       phase, boot_id_hex, elapsed_ms,
	       metrics.requests, metrics.bytes_tx, metrics.bytes_rx,
	       metrics.active_conns, metrics.peak_conns, metrics.total_conns,
	       metrics.errors, metrics.status_200,
	       metrics.status_400, metrics.status_413,
	       rss_bytes, max_rss_bytes);
	fflush(stdout);
}

static void close_slot(int epfd, struct linux_conn_slot *slot)
{
	if (!slot || !slot->in_use)
		return;
	if (slot->fd >= 0) {
		(void)epoll_ctl(epfd, EPOLL_CTL_DEL, slot->fd, NULL);
		close(slot->fd);
		slot->fd = -1;
	}
	slot->rx_len = 0;
	slot->tx_len = 0;
	slot->tx_sent = 0;
	slot->in_use = 0;
	slot->close_after_send = 0;
	if (metrics.active_conns > 0)
		metrics.active_conns--;
}

static int flush_slot_tx(int epfd, struct linux_conn_slot *slot)
{
	while (slot->in_use && slot->tx_sent < slot->tx_len) {
		size_t pending = slot->tx_len - slot->tx_sent;
		ssize_t written = send(slot->fd,
				       slot->tx_buf + slot->tx_sent,
				       pending, MSG_NOSIGNAL);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			metrics.errors++;
			close_slot(epfd, slot);
			return -1;
		}
		if (written == 0) {
			close_slot(epfd, slot);
			return -1;
		}
		slot->tx_sent += (size_t)written;
		metrics.bytes_tx += (uint64_t)written;
	}

	if (slot->in_use && slot->tx_sent >= slot->tx_len) {
		slot->tx_len = 0;
		slot->tx_sent = 0;
		if (slot->close_after_send) {
			close_slot(epfd, slot);
			return 1;
		}
	}
	return 0;
}

static void process_slot_requests(int epfd, struct linux_conn_slot *slot)
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
				boot_id_hex, http_body,
				req.method, req.keep_alive);
			if (resp_len == 0) {
				metrics.errors++;
				close_slot(epfd, slot);
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
			metrics.requests++;
			metrics.status_200++;
		} else {
			int code = (status == UK_HYPERV_HTTP_SCAN_TOO_LARGE) ?
				   413 : 400;

			resp_len = uk_hyperv_http_build_error_response(
				slot->tx_buf, sizeof(slot->tx_buf),
				boot_id_hex, code);
			slot->rx_len = 0;
			slot->tx_len = resp_len;
			slot->tx_sent = 0;
			slot->close_after_send = 1;
			metrics.errors++;
			if (code == 413)
				metrics.status_413++;
			else
				metrics.status_400++;
		}
		if (flush_slot_tx(epfd, slot) != 0)
			return;
	}
}

static void handle_slot_io(int epfd, struct linux_conn_slot *slot,
			   uint32_t events)
{
	if (!slot || !slot->in_use)
		return;
	if (events & (EPOLLERR | EPOLLHUP)) {
		close_slot(epfd, slot);
		return;
	}
	slot->last_active_ns = monotonic_ns();

	if ((events & EPOLLOUT) && slot->tx_sent < slot->tx_len) {
		if (flush_slot_tx(epfd, slot) != 0)
			return;
	}

	if (events & EPOLLIN) {
		for (;;) {
			uint8_t scratch[2048];
			ssize_t n = recv(slot->fd, scratch, sizeof(scratch), 0);

			if (n < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				metrics.errors++;
				close_slot(epfd, slot);
				return;
			}
			if (n == 0) {
				close_slot(epfd, slot);
				return;
			}
			metrics.bytes_rx += (uint64_t)n;
			if (slot->close_after_send)
				continue;
			if ((size_t)n > sizeof(slot->rx_buf) - slot->rx_len) {
				slot->rx_len = 0;
				slot->tx_len =
					uk_hyperv_http_build_error_response(
						slot->tx_buf,
						sizeof(slot->tx_buf),
						boot_id_hex, 413);
				slot->tx_sent = 0;
				slot->close_after_send = 1;
				metrics.errors++;
				metrics.status_413++;
				(void)flush_slot_tx(epfd, slot);
				return;
			}
			memcpy(slot->rx_buf + slot->rx_len, scratch, (size_t)n);
			slot->rx_len += (size_t)n;
			process_slot_requests(epfd, slot);
			if (!slot->in_use)
				return;
		}
	}

	process_slot_requests(epfd, slot);
}

static void accept_clients(int epfd, int listen_fd, unsigned int max_conns)
{
	for (;;) {
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		struct linux_conn_slot *slot = NULL;
		struct epoll_event ev;
		int one = 1;
		unsigned int i;
		int client_fd = accept(listen_fd, (struct sockaddr *)&peer,
				       &peer_len);

		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			metrics.errors++;
			return;
		}

		for (i = 0; i < max_conns; i++) {
			if (!conn_slots[i].in_use) {
				slot = &conn_slots[i];
				break;
			}
		}
		if (!slot || set_nonblocking(client_fd) != 0) {
			metrics.errors++;
			close(client_fd);
			continue;
		}
		(void)setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY,
				 &one, sizeof(one));

		memset(slot, 0, sizeof(*slot));
		slot->fd = client_fd;
		slot->in_use = 1;
		slot->last_active_ns = monotonic_ns();

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
		ev.data.ptr = slot;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) != 0) {
			slot->in_use = 0;
			slot->fd = -1;
			metrics.errors++;
			close(client_fd);
			continue;
		}

		metrics.total_conns++;
		metrics.active_conns++;
		if (metrics.active_conns > metrics.peak_conns)
			metrics.peak_conns = metrics.active_conns;
	}
}

int main(int argc, char **argv)
{
	const char *bind_ip = "0.0.0.0";
	const char *custom_boot_id = NULL;
	unsigned int port = 8080;
	unsigned int max_conns = 64;
	uint64_t duration_ms = 360000;
	uint64_t max_requests = 0;
	int listen_fd;
	int epfd;
	int one = 1;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	struct epoll_event listen_ev;
	struct epoll_event events[LINUX_HTTP_EPOLL_EVENTS];
	uint64_t start_ns;
	uint64_t duration_ns;
	uint64_t next_stats_ns;
	unsigned int i;
	int argi;

	for (argi = 1; argi < argc; argi++) {
		if (strcmp(argv[argi], "--bind") == 0 && argi + 1 < argc) {
			bind_ip = argv[++argi];
		} else if (strcmp(argv[argi], "--port") == 0 &&
			   argi + 1 < argc) {
			port = (unsigned int)strtoul(argv[++argi], NULL, 10);
		} else if (strcmp(argv[argi], "--max-conns") == 0 &&
			   argi + 1 < argc) {
			max_conns = (unsigned int)strtoul(
				argv[++argi], NULL, 10);
		} else if (strcmp(argv[argi], "--duration-ms") == 0 &&
			   argi + 1 < argc) {
			duration_ms = strtoull(argv[++argi], NULL, 10);
		} else if (strcmp(argv[argi], "--max-requests") == 0 &&
			   argi + 1 < argc) {
			max_requests = strtoull(argv[++argi], NULL, 10);
		} else if (strcmp(argv[argi], "--boot-id") == 0 &&
			   argi + 1 < argc) {
			custom_boot_id = argv[++argi];
		} else {
			fprintf(stderr,
				"usage: %s [--bind IP] [--port PORT] "
				"[--max-conns N] [--duration-ms MS] "
				"[--max-requests N] [--boot-id HEX16]\n",
				argv[0]);
			return 2;
		}
	}

	if (max_conns == 0 || max_conns > LINUX_HTTP_MAX_CONNS_CAP ||
	    port > 65535U)
		return 2;

	if (custom_boot_id) {
		if (!uk_hyperv_http_valid_boot_id_hex(
			    custom_boot_id, strlen(custom_boot_id))) {
			fprintf(stderr, "invalid --boot-id (expected 16 hex)\n");
			return 2;
		}
		memcpy(boot_id_hex, custom_boot_id, 16);
		boot_id_hex[16] = '\0';
	} else {
		uk_hyperv_http_format_boot_id(
			derive_linux_boot_id(), boot_id_hex);
	}

	uk_hyperv_http_fill_body(http_body);
	memset(&metrics, 0, sizeof(metrics));
	for (i = 0; i < LINUX_HTTP_MAX_CONNS_CAP; i++)
		conn_slots[i].fd = -1;

	signal(SIGINT, handle_sigterm);
	signal(SIGTERM, handle_sigterm);
	signal(SIGPIPE, SIG_IGN);

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return 1;
	(void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
			 &one, sizeof(one));
	if (set_nonblocking(listen_fd) != 0) {
		close(listen_fd);
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
		close(listen_fd);
		return 2;
	}
	if (bind(listen_fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(listen_fd, (int)max_conns) != 0 ||
	    getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
		close(listen_fd);
		return 1;
	}
	port = (unsigned int)ntohs(addr.sin_port);

	epfd = epoll_create1(0);
	if (epfd < 0) {
		close(listen_fd);
		return 1;
	}
	memset(&listen_ev, 0, sizeof(listen_ev));
	listen_ev.events = EPOLLIN;
	listen_ev.data.ptr = NULL;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &listen_ev) != 0) {
		close(epfd);
		close(listen_fd);
		return 1;
	}

	printf("LINUX_HTTP_SERVICE_CONFIG bind=%s port=%u duration_ms=%" PRIu64
	       " max_conns=%u body_bytes=%u boot_id=%s\n",
	       bind_ip, port, duration_ms, max_conns,
	       (unsigned int)UK_HYPERV_HTTP_BODY_LEN, boot_id_hex);
	printf("LINUX_HTTP_SERVER_READY port=%u boot_id=%s\n",
	       port, boot_id_hex);
	emit_stats("idle", 0);

	start_ns = monotonic_ns();
	duration_ns = duration_ms * 1000000ULL;
	next_stats_ns = start_ns + LINUX_HTTP_STATS_INTERVAL_NS;

	while (!stop_requested) {
		uint64_t now_ns = monotonic_ns();
		int nready;
		int idx;

		if (now_ns >= start_ns && now_ns - start_ns >= duration_ns)
			break;
		if (max_requests > 0 && metrics.requests >= max_requests &&
		    metrics.active_conns == 0)
			break;

		nready = epoll_wait(epfd, events, LINUX_HTTP_EPOLL_EVENTS, 10);
		if (nready < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (idx = 0; idx < nready; idx++) {
			if (events[idx].data.ptr == NULL)
				accept_clients(epfd, listen_fd, max_conns);
			else
				handle_slot_io(
					epfd,
					(struct linux_conn_slot *)
						events[idx].data.ptr,
					events[idx].events);
		}

		now_ns = monotonic_ns();
		if (now_ns >= next_stats_ns) {
			emit_stats("periodic",
				   (now_ns - start_ns) / 1000000ULL);
			next_stats_ns = now_ns + LINUX_HTTP_STATS_INTERVAL_NS;
		}
	}

	for (i = 0; i < max_conns; i++) {
		if (conn_slots[i].in_use)
			close_slot(epfd, &conn_slots[i]);
	}
	close(epfd);
	close(listen_fd);

	emit_stats("final", (monotonic_ns() - start_ns) / 1000000ULL);
	puts("LINUX_HTTP_SERVER_COMPLETE");
	fflush(stdout);
	return 0;
}
