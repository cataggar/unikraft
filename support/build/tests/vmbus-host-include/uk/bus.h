#ifndef __UK_BUS_H__
#define __UK_BUS_H__
struct uk_alloc;
struct uk_bus {
	int (*init)(struct uk_alloc *);
	int (*probe)(void);
};
#define UK_BUS_REGISTER(bus) \
	static const void *uk_bus_registration __attribute__((used)) = (bus)
#define UK_BUS_REGISTER_PRIO 0
#endif
