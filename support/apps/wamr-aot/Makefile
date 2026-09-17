.DEFAULT_GOAL := all
UK_ROOT ?= $(CURDIR)/../../..

all:
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR)

$(filter-out all,$(MAKECMDGOALS)):
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) $@
