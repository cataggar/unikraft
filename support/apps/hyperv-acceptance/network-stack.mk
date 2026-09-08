# SPDX-License-Identifier: BSD-3-Clause

HYPERV_ACCEPTANCE_LWIP_REPOSITORY := https://github.com/unikraft/lib-lwip.git
HYPERV_ACCEPTANCE_LWIP_COMMIT := ec55ae17618feeb57c8c10109bcf5c42723e8e95
HYPERV_ACCEPTANCE_LWIP_UPSTREAM_TAG := STABLE-2_1_2_RELEASE
HYPERV_ACCEPTANCE_LWIP_UPSTREAM_SHA256 := 8f0ae46e2702720ce852b00de5d304adb2809b0203741f299876594bb8be7890
HYPERV_ACCEPTANCE_LWIP_DIR ?= $(UK_ROOT)/.d/deps/lib-lwip

.PHONY: network-stack
network-stack:
	@test ! -e "$(HYPERV_ACCEPTANCE_LWIP_DIR)" || \
		test -d "$(HYPERV_ACCEPTANCE_LWIP_DIR)/.git"
	@mkdir -p "$(dir $(HYPERV_ACCEPTANCE_LWIP_DIR))"
	@if test ! -d "$(HYPERV_ACCEPTANCE_LWIP_DIR)/.git"; then \
		git init -q "$(HYPERV_ACCEPTANCE_LWIP_DIR)"; \
		git -C "$(HYPERV_ACCEPTANCE_LWIP_DIR)" remote add origin \
			"$(HYPERV_ACCEPTANCE_LWIP_REPOSITORY)"; \
	fi
	@test "$$(git -C "$(HYPERV_ACCEPTANCE_LWIP_DIR)" remote get-url origin)" = \
		"$(HYPERV_ACCEPTANCE_LWIP_REPOSITORY)"
	@test -z "$$(git -C "$(HYPERV_ACCEPTANCE_LWIP_DIR)" status \
		--porcelain --untracked-files=all)"
	@git -C "$(HYPERV_ACCEPTANCE_LWIP_DIR)" fetch -q --depth=1 origin \
		"$(HYPERV_ACCEPTANCE_LWIP_COMMIT)"
	@git -C "$(HYPERV_ACCEPTANCE_LWIP_DIR)" checkout -q --detach FETCH_HEAD
	@test "$$(git -C "$(HYPERV_ACCEPTANCE_LWIP_DIR)" rev-parse HEAD)" = \
		"$(HYPERV_ACCEPTANCE_LWIP_COMMIT)"
