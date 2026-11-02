/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_APPLICATION_NETWORK_H
#define HYPERV_ACCEPTANCE_APPLICATION_NETWORK_H

#include "acceptance_protocol.h"

enum hyperv_acceptance_result
hyperv_acceptance_probe_application_network(unsigned int network_offers,
					     int binding_ready);

#endif
