ENTRY(boot)
SECTIONS {
  .boot 0x7c00 : AT(0) { *(.boot) }
  .text 0x10000 : AT(512) { *(.text*) }
  .rodata : AT(LOADADDR(.text) + SIZEOF(.text)) { *(.rodata*) }
  .data : AT(LOADADDR(.rodata) + SIZEOF(.rodata)) { *(.data*) }
  .bss (NOLOAD) : ALIGN(4096) {
    __bss_start = .;
    *(.bss*) *(COMMON)
    __bss_end = .;
  }
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment*) }
}
