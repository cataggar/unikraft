/* SPDX-License-Identifier: BSD-3-Clause */
ENTRY(_start)
PHDRS
{
	text PT_LOAD FLAGS(5);
	data PT_LOAD FLAGS(6);
	dynamic PT_DYNAMIC FLAGS(6);
}
SECTIONS
{
	. = 0x100000;
	.text : { KEEP(*(.text.proof.boot16)) *(.text .text.*) } :text
	. = ALIGN(0x1000);
	.rodata : { *(.rodata .rodata.*) } :data
	.uk_ctortab ALIGN(8) : {
		uk_ctortab_start = .;
		KEEP(*(SORT_BY_NAME(.uk_ctortab[0-9])))
		uk_ctortab_end = .;
		KEEP(*(.proof_rw))
	} :data
	.uk_eventtab ALIGN(8) : { KEEP(*(SORT_BY_NAME(.uk_event_*))) } :data
	.data : { *(.data .data.*) } :data
	.dynamic : { *(.dynamic) } :data :dynamic
	.dynsym : { *(.dynsym) } :data
	.dynstr : { *(.dynstr) } :data
	.gnu.hash : { *(.gnu.hash) } :data
	.hash : { *(.hash) } :data
	.rela.dyn : { *(.rela .rela.*) } :data
	.bss : { *(.bss .bss.*) *(COMMON) } :data
	/DISCARD/ : { *(.eh_frame .comment) }
}
