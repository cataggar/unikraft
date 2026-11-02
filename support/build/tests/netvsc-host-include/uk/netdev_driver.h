#ifndef __UK_NETDEV_DRIVER_H__
#define __UK_NETDEV_DRIVER_H__
#include <stddef.h>
#include <stdint.h>
#include <uk/alloc.h>
#include <uk/arch/spinlock.h>
#include <uk/arch/types.h>
#include <uk/netbuf.h>

#define UK_NETDEV_HWADDR_LEN 6
#define UK_NETDEV_F_RXQ_INTR 1UL
#define UK_NETDEV_STATUS_SUCCESS 1
#define UK_NETDEV_STATUS_MORE 2
#define UK_NETDEV_STATUS_UNDERRUN 4

struct uk_netdev;
struct uk_netdev_rx_queue;
struct uk_netdev_tx_queue;

struct uk_hwaddr {
	uint8_t addr_bytes[UK_NETDEV_HWADDR_LEN];
} __attribute__((packed));

typedef uint16_t (*uk_netdev_alloc_rxpkts)(void *, struct uk_netbuf **,
					   uint16_t);
typedef void (*uk_netdev_queue_event_t)(struct uk_netdev *, uint16_t,
					void *);

struct uk_netdev_conf {
	uint16_t nb_rx_queues;
	uint16_t nb_tx_queues;
	uint8_t lro;
};

struct uk_netdev_rxqueue_conf {
	uk_netdev_queue_event_t callback;
	void *callback_cookie;
	struct uk_alloc *a;
	uk_netdev_alloc_rxpkts alloc_rxpkts;
	void *alloc_rxpkts_argp;
};

struct uk_netdev_txqueue_conf {
	struct uk_alloc *a;
};

struct uk_netdev_info {
	uint16_t max_rx_queues;
	uint16_t max_tx_queues;
	uint16_t max_mtu;
	uint16_t nb_encap_tx;
	uint16_t nb_encap_rx;
	uint16_t ioalign;
	unsigned long features;
};

struct uk_netdev_queue_info {
	uint16_t nb_min;
	uint16_t nb_max;
	uint16_t nb_align;
	uint8_t nb_is_power_of_two;
};

struct uk_netdev_ops {
	int (*rxq_intr_enable)(struct uk_netdev *, struct uk_netdev_rx_queue *);
	int (*rxq_intr_disable)(struct uk_netdev *, struct uk_netdev_rx_queue *);
	const struct uk_hwaddr *(*hwaddr_get)(struct uk_netdev *);
	int (*hwaddr_set)(struct uk_netdev *, const struct uk_hwaddr *);
	uint16_t (*mtu_get)(struct uk_netdev *);
	int (*mtu_set)(struct uk_netdev *, uint16_t);
	int (*promiscuous_set)(struct uk_netdev *, unsigned int);
	unsigned int (*promiscuous_get)(struct uk_netdev *);
	void (*info_get)(struct uk_netdev *, struct uk_netdev_info *);
	int (*txq_info_get)(struct uk_netdev *, uint16_t,
			    struct uk_netdev_queue_info *);
	int (*rxq_info_get)(struct uk_netdev *, uint16_t,
			    struct uk_netdev_queue_info *);
	const char *(*einfo_get)(struct uk_netdev *, int);
	int (*probe)(struct uk_netdev *);
	int (*configure)(struct uk_netdev *, const struct uk_netdev_conf *);
	struct uk_netdev_tx_queue *(*txq_configure)(
		struct uk_netdev *, uint16_t, uint16_t,
		struct uk_netdev_txqueue_conf *);
	struct uk_netdev_rx_queue *(*rxq_configure)(
		struct uk_netdev *, uint16_t, uint16_t,
		struct uk_netdev_rxqueue_conf *);
	int (*start)(struct uk_netdev *);
	void (*tx_returned)(struct uk_netdev *, struct uk_netdev_tx_queue *,
			    struct uk_netbuf *);
};

struct uk_netdev_tx_stats {
	size_t bytes;
	size_t packets;
	size_t errors;
	size_t fifo;
};

struct uk_netdev {
	int (*tx_one)(struct uk_netdev *, struct uk_netdev_tx_queue *,
		      struct uk_netbuf *);
	int (*rx_one)(struct uk_netdev *, struct uk_netdev_rx_queue *,
		      struct uk_netbuf **);
	void *_data;
	const struct uk_netdev_ops *ops;
	struct uk_netdev_rx_queue *_rx_queue[1];
	struct uk_netdev_tx_queue *_tx_queue[1];
	struct uk_netdev_tx_stats tx_stats;
	__spinlock stats_lock;
};

void netvsc_host_tx_wrapper_stage(struct uk_netbuf *packet, int status);

static inline int uk_netdev_tx_one(struct uk_netdev *dev, uint16_t queue_id,
				   struct uk_netbuf *packet)
{
	struct uk_netbuf *current;
	int rc = dev->tx_one(dev, dev->_tx_queue[queue_id], packet);

	if (rc >= 0 && (rc & UK_NETDEV_STATUS_SUCCESS)) {
		netvsc_host_tx_wrapper_stage(packet, rc);
		ukarch_spin_lock(&dev->stats_lock);
		for (current = packet; current; current = current->next)
			dev->tx_stats.bytes += current->len;
		dev->tx_stats.packets++;
		ukarch_spin_unlock(&dev->stats_lock);
		if (dev->ops->tx_returned)
			dev->ops->tx_returned(dev, dev->_tx_queue[queue_id],
					      packet);
	} else if (rc >= 0 && (rc & UK_NETDEV_STATUS_UNDERRUN)) {
		ukarch_spin_lock(&dev->stats_lock);
		dev->tx_stats.fifo++;
		ukarch_spin_unlock(&dev->stats_lock);
	} else if (rc < 0) {
		ukarch_spin_lock(&dev->stats_lock);
		dev->tx_stats.errors++;
		ukarch_spin_unlock(&dev->stats_lock);
	}
	return rc;
}

int uk_netdev_drv_register(struct uk_netdev *, struct uk_alloc *,
			   const char *);
void uk_netdev_drv_rx_event(struct uk_netdev *, uint16_t);

#endif
