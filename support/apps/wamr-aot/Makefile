.DEFAULT_GOAL := all
UK_ROOT ?= $(CURDIR)/../../..
APPWAMRAOT_TOOL ?= $(CURDIR)/build/tool/bin/uk-wamr-aot-build

all:
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) APPWAMRAOT_TOOL="$(APPWAMRAOT_TOOL)"

$(filter-out all,$(MAKECMDGOALS)):
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) APPWAMRAOT_TOOL="$(APPWAMRAOT_TOOL)" $@
