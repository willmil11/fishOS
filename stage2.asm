bits 16
org 0x8000

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax

    in al, 0x92
    or al, 2
    out 0x92, al

    xor eax, eax
    mov ax, gdt
    add eax, 0x8000
    mov [gdtr + 2], eax

    lgdt [gdtr]
    
    mov eax, cr0
    or  eax, 1
    mov cr0, eax
    jmp 0x08:pm_entry

bits 32
pm_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0xA0000

%define BOOT_DATA_KSIZE 0x1F10
%define PML4_ADDR 0x90000
%define PDPT_ADDR 0x91000

    mov edi, PML4_ADDR
    mov ecx, 2048
    xor eax, eax
    rep stosd

    mov esi, 0x10000
    mov edi, 0x100000
    mov ecx, [BOOT_DATA_KSIZE]
    rep movsd

    mov dword [PML4_ADDR], PDPT_ADDR | 3
    mov dword [PML4_ADDR + 4], 0

    mov dword [PDPT_ADDR + 0*8], 0x00000000 | 0x9B
    mov dword [PDPT_ADDR + 0*8 + 4], 0
    mov dword [PDPT_ADDR + 1*8], 0x40000000 | 0x9B
    mov dword [PDPT_ADDR + 1*8 + 4], 0
    mov dword [PDPT_ADDR + 2*8], 0x80000000 | 0x9B
    mov dword [PDPT_ADDR + 2*8 + 4], 0
    mov dword [PDPT_ADDR + 3*8], 0xC0000000 | 0x9B
    mov dword [PDPT_ADDR + 3*8 + 4], 0

    mov eax, cr4
    or  eax, 1 << 5
    mov cr4, eax

    mov eax, PML4_ADDR
    mov cr3, eax

    mov ecx, 0xC0000080
    rdmsr
    or  eax, 1 << 8
    wrmsr

    mov eax, cr0
    or  eax, 1 << 31
    mov cr0, eax

    jmp 0x08:lm_entry

bits 64
lm_entry:
    mov ax, 0x10
    mov ds, ax
    mov ss, ax

    mov rsp, 0x200000 
    mov rax, 0x100000
    jmp rax

align 8
gdt:
    dq 0
    dq 0x00A09A000000FFFF
    dq 0x00C092000000FFFF
gdtr:
    dw gdt_end - gdt - 1
    dd 0
    dw 0
gdt_end: