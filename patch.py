import sys
import struct

# This script takes four arguments:
# 1. The file to patch (boot.bin)
# 2. The kernel size in dwords
# 3. The stage2 size in sectors
# 4. The kernel size in sectors

if len(sys.argv) != 5:
    print("Usage: python patch.py <file> <k_dwords> <s2_secs> <k_secs>")
    sys.exit(1)

file_path = sys.argv[1]
k_dwords = int(sys.argv[2])
s2_secs = int(sys.argv[3])
k_secs = int(sys.argv[4])

with open(file_path, "r+b") as f:
    # Patch kernel size in dwords (as a 4-byte little-endian integer)
    f.seek(504)
    f.write(struct.pack("<I", k_dwords))

    # Patch stage2 sector count (as a single byte)
    f.seek(508)
    f.write(struct.pack("<B", s2_secs))

    # Patch kernel sector count (as a single byte)
    f.seek(509)
    f.write(struct.pack("<B", k_secs))

print(f"[patch] {file_path}: s2_secs={s2_secs}, k_secs={k_secs}, k_dwords={k_dwords}")