#ifndef __UK_NETBUF_H__
#define __UK_NETBUF_H__
#include <stddef.h>
#include <stdint.h>
#define UK_NETBUF_F_PARTIAL_CSUM 0x02
#define UK_NETBUF_F_GSO_TCPV4 0x04
struct uk_netbuf {
	struct uk_netbuf *next;
	struct uk_netbuf *prev;
	uint8_t flags;
	void *data;
	uint16_t len;
	unsigned int refcount;
	void *priv;
	void *buf;
	size_t buflen;
	uint16_t csum_start;
	uint16_t csum_offset;
	uint16_t header_len;
	uint16_t gso_size;
	void (*dtor)(struct uk_netbuf *);
	void *_a;
	void *_b;
};
void uk_netbuf_free(struct uk_netbuf *packet);
#endif
