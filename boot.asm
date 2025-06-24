;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  Multiboot 2 header (8-byte aligned)                             ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .multiboot2
align 8
mb2_header_start:
    dd 0xE85250D6
    dd 0
    dd mb2_header_end - mb2_header_start
    dd -(0xE85250D6 + 0 + (mb2_header_end - mb2_header_start))

    ; frame-buffer request -------------------------------------------
    dw 5, 0
    dd 24
    dd 0, 0, 0, 0

    ; memory-map request --------------------------------------------
    dw 4, 0
    dd 8

    ; end tag --------------------------------------------------------
    dw 0, 0
    dd 8
mb2_header_end:


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  Bootstrap – switch to long mode and jump to C kernel            ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .bootstrap
bits 32
global _start
extern start

_start:
    ; 1. zero PML4 + PDPT -------------------------------------------
    mov     edi, pml4_table
    mov     ecx, 4096*2
    xor     eax, eax
    cld
    rep     stosb

    ; 2. link PML4 → PDPT -------------------------------------------
    mov     eax, pdpt_table
    or      eax, 0b11
    mov     [pml4_table], eax

    ; 3. identity-map first 256 GiB with 1 GiB pages -----------------
    xor     ecx, ecx
.map_loop:
    mov     eax, ecx
    shl     eax, 30                ; 1 GiB * ECX
    xor     edx, edx
    or      eax, 0b10000011        ; present|writable|1 GiB
    lea     edi, [pdpt_table + ecx*8]
    mov     [edi],  eax
    mov     [edi+4], edx
    inc     ecx
    cmp     ecx, 256
    jl      .map_loop

    ; 4. enable paging + long mode ----------------------------------
    mov     eax, pml4_table
    mov     cr3, eax

    mov     eax, cr4
    or      eax, 1<<5              ; CR4.PAE
    mov     cr4, eax

    mov     ecx, 0xC0000080        ; IA32_EFER
    rdmsr
    or      eax, 1<<8              ; EFER.LME
    wrmsr

    mov     eax, cr0
    or      eax, 1<<31             ; CR0.PG
    mov     cr0, eax

    ; 5. load GDT and far-jump to 64-bit code ------------------------
    lgdt    [gdt_descriptor]
    jmp     0x08:long_mode_start


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  64-bit GDT                                                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .gdt
gdt_start:
    dq 0
    dq 0x00209A0000000000          ; 0x08 – code
    dq 0x0000920000000000          ; 0x10 – data
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dq gdt_start


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  Long-mode entry point                                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .text
bits 64
long_mode_start:
    ; --- minimal/dummy IDT -----------------------------------------
    lidt    [idt_descriptor]       ; make sure faults have someplace to go

    ; --- enable FPU/SSE (use 64-bit regs here) ----------------------
    mov     rax, cr0
    and     rax, ~(1 << 2)         ; clear EM
    or      rax,  1 << 1           ; set  MP
    mov     cr0, rax

    mov     rax, cr4
    or      rax, (1 << 9) | (1 << 10)  ; OSFXSR | OSXMMEXCPT
    mov     cr4, rax

    finit                           ; zero x87/SSE state
    ; ----------------------------------------------------------------

    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    mov     rsp, stack_top          ; establish stack

    mov     rdi, rbx                ; pass Multiboot 2 info ptr
    call    start                   ; into C kernel

.hang:
    hlt
    jmp     .hang


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  Dummy 256-entry IDT (all zero)                                  ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .rodata
align 16
idt:
    times 256 dq 0
idt_end:

idt_descriptor:
    dw idt_end - idt - 1
    dq idt


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  BSS                                                             ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

section .bss
align 4096
pml4_table:   resb 4096
pdpt_table:   resb 4096
stack_bottom: resb 4096*4
stack_top:
