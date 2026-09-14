/* SPDX-License-Identifier: BSD-3-Clause */
#include "../../../../support/build/tests/storvsc-host-include/uk/config.h"
#undef CONFIG_LIBSTORVSC_MAX_DEVICES
#undef CONFIG_LIBSTORVSC_MAX_LUNS
#define CONFIG_LIBSTORVSC_MAX_DEVICES STORAGE_BINDING_CONTROLLERS
#define CONFIG_LIBSTORVSC_MAX_LUNS 2
