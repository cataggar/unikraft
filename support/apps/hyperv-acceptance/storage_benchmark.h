/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HYPERV_ACCEPTANCE_STORAGE_BENCHMARK_H
#define HYPERV_ACCEPTANCE_STORAGE_BENCHMARK_H

#include "acceptance_protocol.h"

#include <stddef.h>
#include <stdint.h>

#define HYPERV_STORAGE_BENCHMARK_SCHEMA_VERSION 1U
#define HYPERV_STORAGE_BENCHMARK_DATA_START_LBA 256ULL
#define HYPERV_STORAGE_BENCHMARK_MAX_SLOTS_LIMIT 32U
#define HYPERV_STORAGE_BENCHMARK_MAX_TRANSFER_LIMIT 131072U
#define HYPERV_STORAGE_BENCHMARK_MAX_SAMPLES_LIMIT 4096U
#define HYPERV_STORAGE_BENCHMARK_MAX_TRIALS_LIMIT 10U
#define HYPERV_STORAGE_BENCHMARK_REQ_SIZE_COUNT 4U
#define HYPERV_STORAGE_BENCHMARK_QD_COUNT 6U

enum hyperv_storage_benchmark_pattern {
	HYPERV_STORAGE_BENCHMARK_PATTERN_SEQ = 0,
	HYPERV_STORAGE_BENCHMARK_PATTERN_STRIDED = 1,
	HYPERV_STORAGE_BENCHMARK_PATTERN_COUNT = 2,
};

struct hyperv_storage_benchmark_lat_stats {
	uint64_t min_ns;
	uint64_t p50_ns;
	uint64_t p95_ns;
	uint64_t p99_ns;
	uint64_t max_ns;
	uint64_t mean_ns;
	uint32_t sample_count;
};

int hyperv_storage_benchmark_compute_stats(
	uint64_t *samples, uint32_t count,
	struct hyperv_storage_benchmark_lat_stats *out);

uint64_t hyperv_storage_benchmark_next_lba(
	enum hyperv_storage_benchmark_pattern pattern,
	uint64_t data_start_lba, uint64_t total_sectors,
	uint32_t req_sectors, uint32_t cell_index,
	uint32_t trial_index, uint32_t op_index);

enum hyperv_acceptance_result hyperv_acceptance_storage_benchmark_probe(
	unsigned int storage_offers, int binding_ready, int discovery_error);

#ifdef STORAGE_BENCHMARK_HOST_TEST
void hyperv_storage_benchmark_host_reset(void);
int hyperv_storage_benchmark_host_request_owned(void);
int hyperv_storage_benchmark_host_session_quarantined(void);
#endif

#endif
