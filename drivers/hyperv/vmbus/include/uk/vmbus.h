/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_VMBUS_H__
#define __UK_VMBUS_H__

#include <uk/arch/types.h>
#include <uk/ctors.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMBUS_GUID_SIZE			16U
#define VMBUS_USER_DATA_SIZE		120U

struct vmbus_guid {
	__u8 bytes[VMBUS_GUID_SIZE];
};

struct vmbus_device {
	struct vmbus_guid class_id;
	struct vmbus_guid instance_id;
	__u32 channel_id;
	__u32 connection_id;
	__u16 flags;
	__u16 mmio_megabytes;
	__u16 mmio_megabytes_optional;
	__u16 subchannel_index;
	__u8 monitor_id;
	__u8 monitor_allocated;
	__u16 dedicated;
	__u8 user_data[VMBUS_USER_DATA_SIZE];
	const struct vmbus_driver *driver;
	__u8 present;
};

struct vmbus_device_id {
	struct vmbus_guid class_id;
};

struct vmbus_driver {
	const char *name;
	const struct vmbus_device_id *device_ids;
	int (*add_dev)(struct vmbus_device *dev);
	void (*remove_dev)(struct vmbus_device *dev);
};

extern const struct vmbus_guid vmbus_storage_guid;
extern const struct vmbus_guid vmbus_network_guid;

unsigned int vmbus_device_count(void);
const struct vmbus_device *vmbus_device_get(unsigned int index);
int vmbus_reconnect(void);
int vmbus_unload(void);
int _vmbus_register_driver(struct vmbus_driver *driver);

#define VMBUS_GUID_END { .bytes = { 0 } }

#define VMBUS_DRIVER_REGISTER(driver) \
	_VMBUS_DRIVER_REGISTER(__LIBNAME__, driver)

#define _VMBUS_DRIVER_REGFNNAME(x, y) x##y
#define _VMBUS_DRIVER_REGISTER(libname, driver)			\
	static void						\
	_VMBUS_DRIVER_REGFNNAME(libname, _vmbus_register_driver)(void) \
	{							\
		(void)_vmbus_register_driver((driver));		\
	}							\
	UK_CTOR_PRIO(						\
		_VMBUS_DRIVER_REGFNNAME(libname, _vmbus_register_driver), \
		UK_PRIO_AFTER(UK_BUS_REGISTER_PRIO))

_Static_assert(sizeof(struct vmbus_guid) == 16,
	       "VMBus GUID ABI must be 16 bytes");
_Static_assert(sizeof(((struct vmbus_device *)0)->user_data) == 120,
	       "VMBus offer user data ABI must be 120 bytes");

#ifdef __cplusplus
}
#endif

#endif /* __UK_VMBUS_H__ */
