bits 16
org 0x7C00

%define VBE_INFO_BLOCK 0x1000
%define VBE_MODE_INFO  0x1100
%define BOOT_DATA_FB_ADDR   0x1F00
%define BOOT_DATA_WIDTH     0x1F04
%define BOOT_DATA_HEIGHT    0x1F08
%define BOOT_DATA_PITCH     0x1F0C
%define BOOT_DATA_KSIZE     0x1F10
%define KERNEL_TEMP_ADDR 0x1000

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00

; --- VBE Setup ---
    mov ax, 0x4F00
    mov di, VBE_INFO_BLOCK
    int 0x10
    cmp ax, 0x004F
    jne hang

    mov bx, [VBE_INFO_BLOCK+0x0E]
    mov es, [VBE_INFO_BLOCK+0x10]
    mov ax, es
    mov ds, ax
    mov si, bx
find_mode:
    lodsw
    cmp ax, 0xFFFF
    je hang
    push ax
    mov cx, ax
    mov di, VBE_MODE_INFO
    mov ax, 0x4F01
    int 0x10
    pop bx
    cmp ax, 0x004F
    jne find_mode
    test word [VBE_MODE_INFO], 0x90 
    jz find_mode
    cmp byte [VBE_MODE_INFO+0x19], 32
    jne find_mode
    jmp found_mode
    jmp find_mode

found_mode:
    ; Set the video mode using the mode number in BX
    mov ax, 0x4F02
    or bx, 0x4000
    int 0x10
    cmp ax, 0x004F
    jne hang

    ; THE DEFINITIVE FIX:
    ; The last int 0x10 call corrupted DS. We MUST restore it to 0
    ; BEFORE we try to read or write to our data areas.
    xor ax, ax
    mov ds, ax
    
; --- Store Info in Hardcoded Locations ---
    mov eax, [VBE_MODE_INFO+0x28]
    mov dword [BOOT_DATA_FB_ADDR], eax
    xor eax, eax
    mov ax, [VBE_MODE_INFO+0x12]
    mov dword [BOOT_DATA_WIDTH], eax
    xor eax, eax
    mov ax, [VBE_MODE_INFO+0x14]
    mov dword [BOOT_DATA_HEIGHT], eax
    xor eax, eax
    mov ax, [VBE_MODE_INFO+0x16]
    mov dword [BOOT_DATA_PITCH], eax
    mov eax, [k_dword_count]
    mov dword [BOOT_DATA_KSIZE], eax

; --- Disk Loading (with robust error checking) ---
    mov ah, 0x02
    mov al, [s2_sectors_count]
    mov ch, 0
    mov cl, 2
    mov dh, 0
    mov dl, 0x80
    mov ax, 0x0800
    mov es, ax
    mov bx, 0x0000
    int 0x13
    jc hang
    cmp ah, 0
    jne hang

    mov ah, 0x02
    mov al, [k_sectors_count]
    mov ch, 0
    mov cl, [s2_sectors_count]
    add cl, 2
    mov dh, 0
    mov dl, 0x80
    mov ax, KERNEL_TEMP_ADDR
    mov es, ax
    mov bx, 0x0000
    int 0x13
    jc hang
    cmp ah, 0
    jne hang

; --- Reset segment registers and jump ---
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    jmp 0x0000:0x8000

hang:
    hlt
    jmp hang

times 504 - ($ - $$) db 0
k_dword_count:    dd 0
s2_sectors_count: db 0
k_sectors_count:  db 0
dw 0xAA55