/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_VMBUS_STORAGE_H__
#define __UK_VMBUS_STORAGE_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Zero requires completed enumeration and all admitted primary storage
 * offers bound, not that their LUN discovery succeeded. -EAGAIN means
 * enumeration or binding is still pending. Enumeration failure survives
 * probe unwind and cannot prove pristine no-storage availability. Other
 * negative errors describe terminal rejection. A storage offer lost before
 * admission poisons this status for the boot: its absence cannot establish
 * a complete inventory. Subchannels cannot introduce independent LUNs.
 */
int vmbus_storage_binding_status(void);

#ifdef __cplusplus
}
#endif

#endif /* __UK_VMBUS_STORAGE_H__ */
