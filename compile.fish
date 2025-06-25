#!/usr/bin/env fish
echo "[*] Building FishOS..."

# Clean
rm -rf iso '*.o' '*.elf' '*.iso'

# Assemble Multiboot2 header
nasm -f elf64 boot.asm -o boot.o
or begin
    echo "[-] Failed to assemble boot.asm"
    exit 1
end

# Compile C kernel
gcc -ffreestanding -m64 -mno-red-zone -O0 -g -fno-omit-frame-pointer -fno-inline -fno-stack-protector -c fishOS.c -o fishOS.o
or begin
    echo "[-] Failed to compile fishOS.c"
    exit 1
end

# Link using GCC (no PIE, no relocations)
gcc -ffreestanding -nostdlib -static -no-pie -m64 -g -T linker.ld -o kernel.elf boot.o fishOS.o
or begin
    echo "[-] Failed to link kernel.elf"
    exit 1
end

# Create ISO
mkdir -p iso/boot/grub
cp kernel.elf iso/boot/
cp boot/grub/grub.cfg iso/boot/grub/

grub-mkrescue -o fishos.iso iso/
or begin
    echo "[-] Failed to make ISO"
    exit 1
end

echo "[*] Build complete. Running..."
#We give 1gb ram with -m 1024 but you can change it.
qemu-system-x86_64 -cdrom fishos.iso -display sdl --accel kvm -m 1024

rm boot.o fishOS.o kernel.elf
rm -rf iso
echo "[*] Cleaned up build artifacts."