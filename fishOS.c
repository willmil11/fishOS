#include <stdint.h>

#define KERNEL_DATA_FB_ADDR   (*(volatile uint32_t*)0x1F00)
#define KERNEL_DATA_WIDTH     (*(volatile uint32_t*)0x1F04)
#define KERNEL_DATA_HEIGHT    (*(volatile uint32_t*)0x1F08)
#define KERNEL_DATA_PITCH     (*(volatile uint32_t*)0x1F0C)

void _start(void) {
    volatile uint32_t* framebuffer = (volatile uint32_t*)(uint64_t)KERNEL_DATA_FB_ADDR;
    uint32_t width  = KERNEL_DATA_WIDTH;
    uint32_t height = KERNEL_DATA_HEIGHT;
    uint32_t pitch  = KERNEL_DATA_PITCH;

    uint32_t pitch_in_pixels = pitch / 4;

    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < width; x++) {
            framebuffer[y * pitch_in_pixels + x] = 0x00FF0000;
        }
    }

    for (;;) {
        __asm__ volatile("hlt");
    }
}