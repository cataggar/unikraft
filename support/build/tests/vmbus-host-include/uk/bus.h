#ifndef __UK_BUS_H__
#define __UK_BUS_H__
struct uk_alloc;
struct uk_bus {
	int (*init)(struct uk_alloc *);
	int (*probe)(void);
};
#ifdef VMBUS_EPOCH_ONLY_HOST_TEST
#define UK_BUS_REGISTER(bus)
#else
#define UK_BUS_REGISTER(bus) \
	static const void *uk_bus_registration __attribute__((used)) = (bus)
#endif
#define UK_BUS_REGISTER_PRIO 0
#endif
