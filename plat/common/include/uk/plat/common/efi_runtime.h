/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __UK_PLAT_COMMON_EFI_RUNTIME_H__
#define __UK_PLAT_COMMON_EFI_RUNTIME_H__

#define UK_EFI_RUNTIME_TYPE_CODE	5U
#define UK_EFI_RUNTIME_TYPE_DATA	6U

#define UK_EFI_RUNTIME_MEMRF_READ	0x0001U
#define UK_EFI_RUNTIME_MEMRF_WRITE	0x0002U
#define UK_EFI_RUNTIME_MEMRF_EXECUTE	0x0004U

enum uk_efi_runtime_mrd_action {
	UK_EFI_RUNTIME_MRD_NOT_RUNTIME,
	UK_EFI_RUNTIME_MRD_SKIP,
	UK_EFI_RUNTIME_MRD_APPLY,
};

static inline enum uk_efi_runtime_mrd_action
uk_efi_runtime_mrd_flags(unsigned int type, int mat_present,
			 unsigned int *flags)
{
	if (type != UK_EFI_RUNTIME_TYPE_CODE &&
	    type != UK_EFI_RUNTIME_TYPE_DATA)
		return UK_EFI_RUNTIME_MRD_NOT_RUNTIME;
	if (mat_present)
		return UK_EFI_RUNTIME_MRD_SKIP;

	*flags = UK_EFI_RUNTIME_MEMRF_READ;
	if (type == UK_EFI_RUNTIME_TYPE_CODE)
		*flags |= UK_EFI_RUNTIME_MEMRF_EXECUTE;
	else
		*flags |= UK_EFI_RUNTIME_MEMRF_WRITE;

	return UK_EFI_RUNTIME_MRD_APPLY;
}

#endif /* __UK_PLAT_COMMON_EFI_RUNTIME_H__ */
