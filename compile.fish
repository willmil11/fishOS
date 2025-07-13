#!/usr/bin/env fish
echo "[*] Building FishOS..."

# --- Dependency Healing (Safe & Polite) ---
function install_missing
    set -l pkg $argv[1]
    set -l cmd $argv[2]
    if not type -q $cmd
        echo $pkg
    end
end

function prompt_yes_no --description "Ask for yes/no and exit on Ctrl+C"
    set -l prompt_msg $argv[1]
    while true
        echo "$prompt_msg [Y/n] "
        read -l ans
        switch $status
            case 130
                echo "\n[-] Cancelled by user."
                exit 130
            case 1
                echo "\n[-] Input failed."
                exit 1
        end
        switch $ans
            case '' y Y
                return 0
            case n N
                return 1
            case '*'
                echo "Please answer y or n."
        end
    end
end

set -l required
set required (install_missing nasm nasm)
set required $required (install_missing gcc gcc)
set required $required (install_missing grub grub-mkstandalone)
set required $required (install_missing xorriso grub-mkrescue)
set required $required (install_missing qemu qemu-system-x86_64)

if test (count $required) -gt 0
    echo
    echo "[!] The following packages are missing and required:"
    for pkg in $required
        echo "  - $pkg"
    end
    echo

    # Detect supported package manager
    set -l pkg_mgr ""
    if type -q pacman
        set pkg_mgr "pacman"
    else if type -q apt
        set pkg_mgr "apt"
    else if type -q dnf
        set pkg_mgr "dnf"
    else if type -q zypper
        set pkg_mgr "zypper"
    else if type -q apk
        set pkg_mgr "apk"
    else
        echo "[-] No supported package manager found."
        exit 1
    end

    echo "[*] Detected package manager: $pkg_mgr"

    if not prompt_yes_no "Would you like to install them automatically?"
        echo "[-] Cannot proceed without required dependencies."
        exit 1
    else
        echo "[*] Updating package list..."
        if test "$pkg_mgr" = "pacman"
            sudo pacman -Sy
            for pkg in $required
                sudo pacman --noconfirm -S $pkg
            end
        else if test "$pkg_mgr" = "apt"
            sudo apt update
            sudo apt install -y $required
        else if test "$pkg_mgr" = "dnf"
            sudo dnf makecache
            sudo dnf install -y $required
        else if test "$pkg_mgr" = "apk"
            sudo apk update
            sudo apk add $required
        else if test "$pkg_mgr" = "zypper"
            sudo zypper refresh
            sudo zypper install -y $required
        end
    end
end

# --- Assemble Multiboot2 header ---
nasm -f elf64 boot.asm -o boot.o
or begin
    echo "[-] Failed to assemble boot.asm"
    exit 1
end

# --- Compile C kernel ---
gcc -ffreestanding -m64 -mno-red-zone -O3 -g \
    -fno-omit-frame-pointer -fno-inline -fno-stack-protector \
    -nostdlib -fno-builtin -fno-builtin-memcpy \
    -fno-builtin-memset -fno-builtin-memmove \
    -c fishOS.c -o fishOS.o
or begin
    echo "[-] Failed to compile fishOS.c"
    exit 1
end

# --- Link ---
gcc -ffreestanding -nostdlib -static -no-pie -m64 -g \
    -T linker.ld -o kernel.elf boot.o fishOS.o
or begin
    echo "[-] Failed to link kernel.elf"
    exit 1
end

# --- Create GRUB UEFI binary ---
mkdir -p build/efi
grub-mkstandalone \
    -O x86_64-efi \
    -o build/efi/BOOTX64.EFI \
    "boot/grub/grub.cfg=boot/grub/grub.cfg"

# --- Stage ISO tree ---
mkdir -p iso/EFI/BOOT
cp build/efi/BOOTX64.EFI       iso/EFI/BOOT/
cp boot/grub/grub.cfg          iso/EFI/BOOT/grub.cfg
mkdir -p iso/boot/grub
cp boot/grub/grub.cfg          iso/boot/grub/
cp kernel.elf                  iso/boot/

# --- Generate ISO ---
grub-mkrescue -o fishos.iso iso/ \
    --modules="normal linux configfile multiboot2" \
    --fonts="unicode"

# --- Cleanup ---
rm boot.o fishOS.o kernel.elf
rm -rf build iso
echo "[*] Cleaned up build artifacts."

echo "[*] Build complete. Running..."

# --- Run QEMU ---
qemu-system-x86_64 \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.4m.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -cdrom fishos.iso \
    -m 512 \
    -display sdl --accel kvm
