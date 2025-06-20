#!/usr/bin/env fish
echo "[*] build…"

nasm -f bin boot.asm   -o boot.bin
nasm -f bin stage2.asm -o stage2.bin

gcc -ffreestanding -m64 -mno-red-zone -c fishOS.c -o fishOS.o
ld  -nostdlib -T linker.ld fishOS.o -o kernel.elf
objcopy -O binary kernel.elf kernel.bin

set s2_size  (stat -c "%s" stage2.bin)
set s2_secs  (math "ceil( $s2_size / 512 )")
set k_size   (stat -c "%s" kernel.bin)
set k_secs   (math "ceil( $k_size / 512 )")
set k_dwords (math "ceil( $k_size / 4 )")

dd if=(printf "%08x" $k_dwords | sed -E 's/(..)(..)(..)(..)/\\x\4\\x\3\\x\2\\x\1/') bs=1 seek=504 of=boot.bin conv=notrunc &>/dev/null
printf "%c" $s2_secs | dd bs=1 seek=508 of=boot.bin conv=notrunc &>/dev/null
printf "%c" $k_secs  | dd bs=1 seek=509 of=boot.bin conv=notrunc &>/dev/null
echo "[patch] boot.bin: s2_secs=$s2_secs, k_secs=$k_secs, k_dwords=$k_dwords"

cat boot.bin stage2.bin kernel.bin > os.img
echo "run QEMU…"
qemu-system-x86_64 -vga std -drive format=raw,file=os.img