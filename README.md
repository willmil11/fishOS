# 🐟 FishOS 0.0.7

# What's this?
It's an os built from scratch, the only thing not built by me here is grub that i'm only using to boot.

# Why?
Why not?

# How to use
The iso works on x86, you can run ```qemu-system-x86_64 -cdrom fishos.iso -m 1024 -accel kvm``` to run it if you have qemu installed. Remove ```-accel kvm``` if you don't have virtualisation enabled. You can change the amount of ram you give it by changing ```1024``` to something else in mb. If you want to change the code and test it you can use ```fish compile.fish``` assuming you have all the tools required by the fish script including fish itself to run it.

# Known bugs
- Chars are not the same size
- Chars are too fat

# Version history
Notes: It works that's it. For now it boots and does something interesting, it's only gonna become an actual useful os over time.
- 0.0.7 — Slightly better compile.fish.
- 0.0.6 — Faster memory allocator and char caching for faster than ever print(). Also the test displayed on screen changed: we print() all of the available chars in one call as a single string in a loop instead of each char one after the other in a loop this is more representative of print() performance and char caching effectiveness.
- 0.0.5 — Print function scrollback is fixed, way better fill algorithm for chars.
- 0.0.4 — PRINT FUNCTION WORKS + MEMORY ALLOCATOR FIXED + FINALLY
- 0.0.3 — Better text fill even tough still flawed.
- 0.0.2 — Readme edit.
- 0.0.1 — memory allocator + frame render + text raster + bouncing text
- junk — old stuff

# Liscense
Mit license: <a href="./LICENSE">LICENSE</a>