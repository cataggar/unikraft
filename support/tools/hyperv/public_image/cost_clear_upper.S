/* Diagnostic-only SysV leaf: no digest implementation or optimization override. */
.text
.global hyperv_public_cost_clear_upper
.hidden hyperv_public_cost_clear_upper
.type hyperv_public_cost_clear_upper,@function
hyperv_public_cost_clear_upper:
	vzeroupper
	ret
.size hyperv_public_cost_clear_upper, .-hyperv_public_cost_clear_upper
.global hyperv_public_cost_dirty_upper
.hidden hyperv_public_cost_dirty_upper
.type hyperv_public_cost_dirty_upper,@function
hyperv_public_cost_dirty_upper:
	vpcmpeqd %ymm0, %ymm0, %ymm0
	ret
.size hyperv_public_cost_dirty_upper, .-hyperv_public_cost_dirty_upper
.section .note.GNU-stack,"",@progbits
