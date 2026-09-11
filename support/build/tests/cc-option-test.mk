# SPDX-License-Identifier: BSD-3-Clause

CC := $(ZIG) cc -target x86_64-freestanding-none
include $(UK_ROOT)/support/build/Makefile.rules

ifneq ($(call cc-option,-fpie,unsupported),-fpie)
$(error native compiler PIE support was incorrectly rejected)
endif
ifneq ($(call cc-option,-funikraft-invalid-option,unsupported),unsupported)
$(error invalid native compiler option was accepted)
endif
ifneq ($(call cc-option,-funikraft-invalid-option),)
$(error absent fallback for an invalid option was not empty)
endif

.PHONY: test
test:
	@printf 'Native compiler option probes passed\n'
