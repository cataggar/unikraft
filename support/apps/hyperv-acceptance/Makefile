UK_ROOT ?= $(CURDIR)/../../..
UK_LIBS ?= $(UK_ROOT)/lib

all:
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) L=$(UK_LIBS)

$(MAKECMDGOALS):
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) L=$(UK_LIBS) $@

.PHONY: all
