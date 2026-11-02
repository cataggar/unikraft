/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_HOST_BLKREQ_H__
#define __STORVSC_HOST_BLKREQ_H__
#include <stdatomic.h>
#include <uk/arch/types.h>
typedef __sz __sector;
enum uk_blkreq_state {
	UK_BLKREQ_FINISHED = 0,
	UK_BLKREQ_UNFINISHED,
};
enum uk_blkreq_op {
	UK_BLKREQ_READ = 0,
	UK_BLKREQ_WRITE,
	UK_BLKREQ_FFLUSH = 4,
};
struct uk_blkreq;
typedef void (*uk_blkreq_event_t)(struct uk_blkreq *, void *);
struct uk_blkreq {
	enum uk_blkreq_op operation;
	__sector start_sector;
	__sector nb_sectors;
	void *aio_buf;
	uk_blkreq_event_t cb;
	void *cb_cookie;
	struct {
		atomic_int counter;
	} state;
	int result;
};
static inline void uk_blkreq_init(struct uk_blkreq *req,
		enum uk_blkreq_op operation, __sector start,
		__sector sectors, void *buffer, uk_blkreq_event_t callback,
		void *cookie)
{
	req->operation = operation;
	req->start_sector = start;
	req->nb_sectors = sectors;
	req->aio_buf = buffer;
	req->cb = callback;
	req->cb_cookie = cookie;
	atomic_store(&req->state.counter, UK_BLKREQ_UNFINISHED);
}
#define uk_blkreq_is_done(req) \
	(atomic_load(&(req)->state.counter) == UK_BLKREQ_FINISHED)
#endif
