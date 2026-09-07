/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_BLKDEV_DRIVER_H__
#define __STORVSC_HOST_BLKDEV_DRIVER_H__
#include <stdatomic.h>
#include <uk/blkdev.h>
int uk_blkdev_drv_register(struct uk_blkdev *dev, struct uk_alloc *allocator,
			   const char *name);
void uk_blkdev_drv_unregister(struct uk_blkdev *dev);
static inline void uk_blkdev_drv_queue_event(struct uk_blkdev *dev,
					      uint16_t queue_id)
{
	struct uk_blkdev_event_handler *handler =
		&dev->_data->queue_handler[queue_id];
	if (handler->callback)
		handler->callback(dev, queue_id, handler->cookie);
}
#define uk_blkreq_finished(req) \
	atomic_store(&(req)->state.counter, UK_BLKREQ_FINISHED)
#endif
