ENTRY(_start)

SECTIONS {
    . = 1M;

    .text : ALIGN(4K) {
        KEEP(*(.multiboot2))
        *(.bootstrap) /* Code that runs before long mode */
        *(.text)      /* 64-bit code */
    }

    .rodata : ALIGN(4K) {
        *(.rodata)
    }

    .data : ALIGN(4K) {
        *(.data)
    }
    
    .gdt : ALIGN(4K) {
        *(.gdt)
    }

    .bss : ALIGN(4096) { /* Page-align BSS */
        *(COMMON)
        *(.bss)
    }

    _kernel_end = .;
}