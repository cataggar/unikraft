/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Non-preemptive (cooperative) Round Robin scheduler.
 * Ported from Mini-OS
 */

#ifndef __UK_SCHEDCOOP_H__
#define __UK_SCHEDCOOP_H__

#include <uk/sched.h>
#include <uk/alloc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uk_sched *uk_schedcoop_create(struct uk_alloc *a,
				     struct uk_alloc *sa,
				     struct uk_alloc *axusa,
				     struct uk_alloc *tls_a);

#if CONFIG_LIBUKSCHEDCOOP_FIXED_SMP
typedef int (*uk_schedcoop_work_fn_t)(void *arg);

struct uk_sched *uk_schedcoop_create_on(struct uk_alloc *a,
					struct uk_alloc *sa,
					struct uk_alloc *auxsa,
					struct uk_alloc *tls_a,
					unsigned int lcpu_idx);

/*
 * Publish one bounded work item to the persistent thread of @lcpu_idx.
 * If this returns an error with @published set, the work remains committed;
 * retry only uk_sched_kick_retry(uk_sched_get_lcpu(lcpu_idx), ...).
 */
int uk_schedcoop_fixed_submit(unsigned int lcpu_idx,
			      uk_schedcoop_work_fn_t fn, void *arg,
			      int *published);

int uk_schedcoop_fixed_wait(unsigned int lcpu_idx, __nsec deadline,
			    int *work_result, int *completion_kick_error);

int uk_schedcoop_fixed_idle_armed(unsigned int lcpu_idx);

void uk_schedcoop_fixed_destroy(struct uk_sched *sched);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __UK_SCHEDCOOP_H__ */
