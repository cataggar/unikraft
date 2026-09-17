/* SysV vector registers are caller-saved. No hashing or runtime checks here. */
.text
.global hyperv_sha256_clear_upper
.hidden hyperv_sha256_clear_upper
.type hyperv_sha256_clear_upper,@function
hyperv_sha256_clear_upper:
	vzeroupper
	ret
.size hyperv_sha256_clear_upper, .-hyperv_sha256_clear_upper
.section .note.GNU-stack,"",@progbits
