# 🐟 FishOS 0.0.4

# What's this?
It's an os built from scratch, the only thing not built by me here is grub that i'm only using to boot.

# Why?
Why not?

# How to use
The iso works on x86, you can run ```qemu-system-x86_64 -cdrom fishos.iso -m 1024 -accel kvm``` to run it if you have qemu installed. Remove ```-accel kvm``` if you don't have virtualisation enabled. You can change the amount of ram you give it by changing ```1024``` to something else in mb. If you want to change the code and test it you can use ```fish compile.fish``` assuming you have all the tools required by the fish script including fish itself to run it.

# Known bugs
For the current version there is a bug that the scrollback for the print function does not work and just overwrites the last line of the screen which is a bug that i'm gonna fix but not a breaking one rn i'll just commit because i'm just happy it works.

# Version history
Notes: It works that's it. For now it boots and does something interesting, it's only gonna become an actual useful os over time.
- 0.0.4 — PRINT FUNCTION WORKS + MEMORY ALLOCATOR FIXED + FINALLY
- 0.0.3 — Better text fill even tough still flawed.
- 0.0.2 — Readme edit.
- 0.0.1 — memory allocator + frame render + text raster + bouncing text
- junk — old stuff

# Liscense
Mit license: <a href="./LICENSE">LICENSE</a>