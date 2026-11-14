/* SPDX-License-Identifier: MIT */
/* Linker script of every payload (docs/SP11-PAYLOAD.md): the flat binary is .text then .rodata, with the
 * start stub (.text.start) first, so entry is at offset 0.
 *
 * Linked at 0 and flattened, because the firmware chooses where the file goes. Nothing in the image may
 * depend on that address, and tools/sp11_payload_elfcheck.py (run by the Makefile after every link, on
 * the relocations --emit-relocs keeps) refuses any relocation that does.
 *
 * A payload has no writable globals. The file is loaded into pages the firmware may map read-only for
 * all this tree knows, a flat binary carries no .bss, and nothing would clear it; state lives on the
 * stack the runner provides. The two ASSERTs turn a global into a link error that says so. */
ENTRY(_start)

PHDRS
{
    image PT_LOAD FLAGS(5);
}

SECTIONS
{
    . = 0;
    .text : { KEEP(*(.text.start)) *(.text .text.*) } :image
    .rodata : { *(.rodata .rodata.*) } :image
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.* COMMON) }
    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame .eh_frame.*) *(.ARM.attributes) }
}

ASSERT(SIZEOF(.data) == 0, "payload: no writable globals (.data): keep state on the stack")
ASSERT(SIZEOF(.bss) == 0, "payload: no writable globals (.bss): keep state on the stack")
