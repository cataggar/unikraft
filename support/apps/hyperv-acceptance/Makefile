UK_ROOT ?= $(CURDIR)/../../..
UK_LIBS ?= $(UK_ROOT)/lib
HOSTCC ?= cc
PROTOCOL_TEST_DIR ?= $(UK_ROOT)/.d/hyperv-acceptance-tests

include $(CURDIR)/network-stack.mk

all:
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) L=$(UK_LIBS)

$(filter-out network-stack protocol-test,$(MAKECMDGOALS)):
	$(MAKE) -C $(UK_ROOT) A=$(CURDIR) L=$(UK_LIBS) $@

.PHONY: all protocol-test
protocol-test:
	@mkdir -p "$(PROTOCOL_TEST_DIR)"
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -I$(CURDIR) \
		$(CURDIR)/application_protocol.c \
		$(CURDIR)/tests/application-protocol-test.c \
		-o $(PROTOCOL_TEST_DIR)/application-protocol-test
	@$(PROTOCOL_TEST_DIR)/application-protocol-test
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -I$(CURDIR) \
		$(CURDIR)/acceptance_protocol.c \
		$(UK_ROOT)/support/build/tests/hyperv-acceptance-protocol-test.c \
		-o $(PROTOCOL_TEST_DIR)/acceptance-protocol-test
	@$(PROTOCOL_TEST_DIR)/acceptance-protocol-test
