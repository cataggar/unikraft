/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_BLKDEV_H__
#define __STORVSC_HOST_BLKDEV_H__
#include <stddef.h>
#include <stdint.h>
#include <uk/alloc.h>
#include <uk/blkreq.h>
#include <uk/config.h>

struct uk_blkdev;
struct uk_blkdev_queue;
struct uk_blkdev_conf {
	uint16_t nb_queues;
};
struct uk_blkdev_info {
	uint16_t max_queues;
};
struct uk_blkdev_queue_info {
	uint16_t nb_max;
	uint16_t nb_min;
	uint16_t nb_align;
	int nb_is_power_of_two;
};
typedef void (*uk_blkdev_queue_event_t)(struct uk_blkdev *, uint16_t, void *);
struct uk_blkdev_queue_conf {
	struct uk_alloc *a;
	uk_blkdev_queue_event_t callback;
	void *callback_cookie;
};
enum uk_blkdev_state {
	UK_BLKDEV_INVALID = 0,
	UK_BLKDEV_UNCONFIGURED,
	UK_BLKDEV_CONFIGURED,
	UK_BLKDEV_RUNNING,
};
struct uk_blkdev_event_handler {
	uk_blkdev_queue_event_t callback;
	void *cookie;
};
struct uk_blkdev_data {
	uint16_t id;
	enum uk_blkdev_state state;
	struct uk_blkdev_event_handler
		queue_handler[CONFIG_LIBUKBLKDEV_MAXNBQUEUES];
	const char *drv_name;
	struct uk_alloc *a;
};
struct uk_blkdev_cap {
	__sector sectors;
	size_t ssize;
	int mode;
	__sector max_sectors_per_req;
	uint16_t ioalign;
};
typedef void (*uk_blkdev_get_info_t)(struct uk_blkdev *,
				      struct uk_blkdev_info *);
typedef int (*uk_blkdev_configure_t)(struct uk_blkdev *,
				      const struct uk_blkdev_conf *);
typedef int (*uk_blkdev_queue_get_info_t)(struct uk_blkdev *, uint16_t,
					   struct uk_blkdev_queue_info *);
typedef struct uk_blkdev_queue *(*uk_blkdev_queue_configure_t)(
	struct uk_blkdev *, uint16_t, uint16_t,
	const struct uk_blkdev_queue_conf *);
typedef int (*uk_blkdev_start_t)(struct uk_blkdev *);
typedef int (*uk_blkdev_stop_t)(struct uk_blkdev *);
typedef int (*uk_blkdev_queue_intr_enable_t)(struct uk_blkdev *,
					      struct uk_blkdev_queue *);
typedef int (*uk_blkdev_queue_intr_disable_t)(struct uk_blkdev *,
					       struct uk_blkdev_queue *);
typedef int (*uk_blkdev_queue_unconfigure_t)(struct uk_blkdev *,
					      struct uk_blkdev_queue *);
typedef int (*uk_blkdev_unconfigure_t)(struct uk_blkdev *);
typedef int (*uk_blkdev_queue_submit_one_t)(struct uk_blkdev *,
					     struct uk_blkdev_queue *,
					     struct uk_blkreq *);
typedef int (*uk_blkdev_queue_finish_reqs_t)(struct uk_blkdev *,
					      struct uk_blkdev_queue *);
struct uk_blkdev_ops {
	uk_blkdev_get_info_t get_info;
	uk_blkdev_configure_t dev_configure;
	uk_blkdev_queue_get_info_t queue_get_info;
	uk_blkdev_queue_configure_t queue_configure;
	uk_blkdev_start_t dev_start;
	uk_blkdev_stop_t dev_stop;
	uk_blkdev_queue_intr_enable_t queue_intr_enable;
	uk_blkdev_queue_intr_disable_t queue_intr_disable;
	uk_blkdev_queue_unconfigure_t queue_unconfigure;
	uk_blkdev_unconfigure_t dev_unconfigure;
};
struct uk_blkdev {
	uk_blkdev_queue_submit_one_t submit_one;
	uk_blkdev_queue_finish_reqs_t finish_reqs;
	struct uk_blkdev_data *_data;
	struct uk_blkdev_cap capabilities;
	const struct uk_blkdev_ops *dev_ops;
	struct uk_blkdev_queue *_queue[CONFIG_LIBUKBLKDEV_MAXNBQUEUES];
};
#define UK_BLKDEV_STATUS_SUCCESS 0x1
#define UK_BLKDEV_STATUS_MORE 0x2
struct uk_blkdev *uk_blkdev_get(uint16_t id);
enum uk_blkdev_state uk_blkdev_state_get(struct uk_blkdev *device);
int uk_blkdev_configure(struct uk_blkdev *device,
			const struct uk_blkdev_conf *config);
int uk_blkdev_queue_configure(struct uk_blkdev *device, uint16_t queue_id,
			      uint16_t descriptors,
			      const struct uk_blkdev_queue_conf *config);
int uk_blkdev_start(struct uk_blkdev *device);
int uk_blkdev_queue_intr_enable(struct uk_blkdev *device, uint16_t queue_id);
int uk_blkdev_queue_submit_one(struct uk_blkdev *device, uint16_t queue_id,
			       struct uk_blkreq *request);
int uk_blkdev_queue_finish_reqs(struct uk_blkdev *device, uint16_t queue_id);
#endif
