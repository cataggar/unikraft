/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __STORVSC_CORE_H__
#define __STORVSC_CORE_H__

#include <stddef.h>
#include <stdint.h>

#define STORVSC_CORE_STORAGE_SIZE	8192U
#define STORVSC_CORE_STORAGE_ALIGN	8U
#define STORVSC_CORE_MAX_CONTEXTS	64U
#define STORVSC_PACKET_MAX		64U
#define STORVSC_SENSE_MAX		20U
#define STORVSC_REPORT_LUNS_MAX		64U
#define STORVSC_REPORT_LUNS_HEADER_SIZE	8U
#define STORVSC_REPORT_LUN_ENTRY_SIZE	8U
#define STORVSC_REPORT_LUNS_DATA_SIZE	\
	(STORVSC_REPORT_LUNS_HEADER_SIZE + \
	 STORVSC_REPORT_LUNS_MAX * STORVSC_REPORT_LUN_ENTRY_SIZE)
#define STORVSC_VPD_ID_MAX		64U

#define STORVSC_DIRECTION_WRITE		0U
#define STORVSC_DIRECTION_READ		1U
#define STORVSC_DIRECTION_NONE		2U

enum storvsc_event_kind {
	STORVSC_EVENT_IGNORED = 0,
	STORVSC_EVENT_TRANSMIT = 1,
	STORVSC_EVENT_INITIALIZATION_READY = 2,
	STORVSC_EVENT_INITIALIZATION_FAILED = 3,
	STORVSC_EVENT_REQUEST_COMPLETE = 4,
	STORVSC_EVENT_REQUEST_TIMEOUT = 5,
	STORVSC_EVENT_RESET_COMPLETE = 6,
	STORVSC_EVENT_REMOVE_DEVICE = 7,
	STORVSC_EVENT_ENUMERATE_BUS = 8,
	STORVSC_EVENT_PROTOCOL_ERROR = 9,
};

struct storvsc_tx {
	uint64_t transaction_id;
	uint32_t packet_len;
	uint32_t transfer_len;
	uint16_t slot;
	uint8_t direction;
	uint8_t reserved;
	uint8_t packet[STORVSC_PACKET_MAX];
};

struct storvsc_event {
	enum storvsc_event_kind kind;
	int error;
	uint64_t transaction_id;
	uint32_t transferred;
	uint16_t slot;
	uint8_t srb_status;
	uint8_t scsi_status;
	uint8_t sense_len;
	uint8_t reserved[3];
	uint8_t sense[STORVSC_SENSE_MAX];
	struct storvsc_tx tx;
};

struct storvsc_scsi_spec {
	uint32_t transfer_len;
	uint32_t minimum_transfer;
	uint64_t timeout_ns;
	uint8_t cdb[16];
	uint8_t cdb_len;
	uint8_t direction;
	uint8_t allow_short;
	uint8_t reserved;
	uint8_t path_id;
	uint8_t target_id;
	uint8_t lun;
	uint8_t address_reserved;
};

struct storvsc_address {
	uint8_t path_id;
	uint8_t target_id;
	uint8_t lun;
	uint8_t reserved;
};

struct storvsc_capacity {
	uint64_t sectors;
	uint32_t sector_size;
	uint8_t needs_capacity16;
	uint8_t reserved[3];
};

struct storvsc_inquiry {
	uint8_t peripheral_type;
	uint8_t removable;
	uint8_t reserved[2];
};

struct storvsc_mode {
	uint8_t read_only;
	uint8_t reserved[3];
};

struct storvsc_media {
	uint64_t sectors;
	uint32_t sector_size;
	uint8_t read_only;
	uint8_t reserved[3];
};

struct storvsc_vpd_id {
	uint8_t length;
	uint8_t code_set;
	uint8_t designator_type;
	uint8_t association;
	uint8_t bytes[STORVSC_VPD_ID_MAX];
};

int storvsc_core_initialize(void *storage, uint32_t epoch,
			    uint16_t queue_depth);
int storvsc_core_start(void *storage, uint64_t now, uint64_t timeout_ns,
		       struct storvsc_event *event);
int storvsc_core_receive(void *storage, uint64_t transaction_id,
			 const uint8_t *payload, size_t payload_len,
			 uint64_t now, struct storvsc_event *event);
int storvsc_core_tick(void *storage, uint64_t now,
		      struct storvsc_event *event);
int storvsc_core_prepare_scsi(void *storage,
			      const struct storvsc_scsi_spec *spec,
			      uint64_t now, struct storvsc_tx *tx);
int storvsc_core_prepare_block(void *storage, int operation,
			       uint64_t start_sector, uint64_t sector_count,
			       uint64_t buffer_address, uint64_t now,
			       uint64_t timeout_ns, struct storvsc_tx *tx);
int storvsc_core_prepare_block_at(void *storage,
				  const struct storvsc_address *address,
				  int operation, uint64_t start_sector,
				  uint64_t sector_count,
				  uint64_t buffer_address, uint64_t now,
				  uint64_t timeout_ns,
				  struct storvsc_tx *tx);
int storvsc_core_prepare_block_media(void *storage,
				     const struct storvsc_address *address,
				     const struct storvsc_media *media,
				     int operation, uint64_t start_sector,
				     uint64_t sector_count,
				     uint64_t buffer_address, uint64_t now,
				     uint64_t timeout_ns,
				     struct storvsc_tx *tx);
int storvsc_core_begin_reset(void *storage, uint64_t now,
			     uint64_t timeout_ns,
			     struct storvsc_event *event);
int storvsc_core_abort(void *storage, uint16_t slot,
		       uint64_t transaction_id);
uint32_t storvsc_core_cancel_all(void *storage, int result);
int storvsc_core_next_completed(void *storage, uint16_t *slot);
int storvsc_core_take_completed(void *storage, uint16_t slot,
				uint64_t transaction_id,
				struct storvsc_event *event);
uint32_t storvsc_core_active_count(void *storage);
uint32_t storvsc_core_free_count(void *storage);
int storvsc_core_set_transfer_limit(void *storage, uint32_t transfer_limit);
int storvsc_core_set_media(void *storage, uint64_t sectors,
			   uint32_t sector_size, uint8_t read_only);
uint16_t storvsc_core_version(void *storage);
uint32_t storvsc_core_packet_size(void *storage);
uint32_t storvsc_core_host_max_transfer(void *storage);

int storvsc_build_report_luns(struct storvsc_scsi_spec *spec,
			      uint8_t path_id, uint8_t target_id,
			      uint32_t lun_capacity, uint64_t timeout_ns);
int storvsc_parse_report_luns(const uint8_t *data, size_t data_len,
			      uint8_t path_id, uint8_t target_id,
			      struct storvsc_address *addresses,
			      size_t address_capacity,
			      size_t *address_count);
int storvsc_parse_vpd83(const uint8_t *data, size_t data_len,
			struct storvsc_vpd_id *identity);
int storvsc_parse_inquiry(const uint8_t *data, size_t data_len,
			  struct storvsc_inquiry *inquiry);
int storvsc_parse_capacity10(const uint8_t *data, size_t data_len,
			     struct storvsc_capacity *capacity);
int storvsc_parse_capacity16(const uint8_t *data, size_t data_len,
			     struct storvsc_capacity *capacity);
int storvsc_parse_mode_sense6(const uint8_t *data, size_t data_len,
			      struct storvsc_mode *mode);
int storvsc_parse_mode_sense10(const uint8_t *data, size_t data_len,
			       struct storvsc_mode *mode);

_Static_assert(sizeof(struct storvsc_tx) == 88,
	       "StorVSC transmit ABI changed");
_Static_assert(offsetof(struct storvsc_tx, packet) == 20,
	       "StorVSC packet offset changed");
_Static_assert(sizeof(struct storvsc_event) == 136,
	       "StorVSC event ABI changed");
_Static_assert(offsetof(struct storvsc_event, tx) == 48,
	       "StorVSC event transmit offset changed");
_Static_assert(sizeof(struct storvsc_scsi_spec) == 40,
	       "StorVSC SCSI specification ABI changed");
_Static_assert(offsetof(struct storvsc_scsi_spec, cdb) == 16,
	       "StorVSC CDB offset changed");
_Static_assert(offsetof(struct storvsc_scsi_spec, path_id) == 36,
	       "StorVSC SCSI address offset changed");
_Static_assert(offsetof(struct storvsc_scsi_spec, target_id) == 37,
	       "StorVSC SCSI target offset changed");
_Static_assert(offsetof(struct storvsc_scsi_spec, lun) == 38,
	       "StorVSC SCSI LUN offset changed");
_Static_assert(offsetof(struct storvsc_scsi_spec, address_reserved) == 39,
	       "StorVSC SCSI address reserved offset changed");
_Static_assert(sizeof(struct storvsc_address) == 4,
	       "StorVSC address ABI changed");
_Static_assert(STORVSC_REPORT_LUNS_DATA_SIZE == 520,
	       "StorVSC REPORT LUNS layout changed");
_Static_assert(sizeof(struct storvsc_capacity) == 16,
	       "StorVSC capacity ABI changed");
_Static_assert(sizeof(struct storvsc_media) == 16,
	       "StorVSC media ABI changed");
_Static_assert(offsetof(struct storvsc_media, read_only) == 12,
	       "StorVSC media mode offset changed");
_Static_assert(sizeof(struct storvsc_vpd_id) == 68,
	       "StorVSC VPD identity ABI changed");
_Static_assert(offsetof(struct storvsc_vpd_id, bytes) == 4,
	       "StorVSC VPD identity offset changed");

#endif /* __STORVSC_CORE_H__ */
