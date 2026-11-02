/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef UK_HYPERV_ACCEPTANCE_HTTP_SERVICE_H
#define UK_HYPERV_ACCEPTANCE_HTTP_SERVICE_H

#include "acceptance_protocol.h"

#include <stdint.h>

enum hyperv_acceptance_result
hyperv_acceptance_run_http_service(unsigned int network_offers,
				   int binding_ready,
				   uint64_t t_vmbus_ready_ns);

#endif /* UK_HYPERV_ACCEPTANCE_HTTP_SERVICE_H */
