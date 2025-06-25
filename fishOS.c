#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void *malloc (uint32_t n);
void  free   (void *ptr);
void *realloc(void *ptr, uint32_t n);

uint64_t __stack_chk_guard = 0xdeadbeefcafebabe;
void __attribute__((noreturn)) __stack_chk_fail(void) { for(;;)__asm__("cli;hlt"); }

typedef struct { uint32_t type, size; }                        multiboot_tag_t;
typedef struct { uint32_t type, size, entry_size, entry_ver; } multiboot_tag_mmap_t;
typedef struct { uint64_t base, len;  uint32_t type, resv;  }  multiboot_mmap_entry_t;
#define  MULTIBOOT_MEMORY_AVAILABLE  1
typedef struct { uint32_t type, size; uint64_t addr; uint32_t pitch,w,h; uint8_t bpp,kind,_r;}
        multiboot_tag_framebuffer_t;

volatile uint32_t *framebuffer; uint32_t screen_w,screen_h,fb_pitch;
static inline void pixel(uint32_t x,uint32_t y,uint32_t c){
    if(x<screen_w&&y<screen_h) framebuffer[y*(fb_pitch>>2)+x]=c;
}
static inline uint32_t rgb(uint8_t r,uint8_t g,uint8_t b){return b|(g<<8)|(r<<16);}
static void draw_rect(uint32_t x,uint32_t y,uint32_t w,uint32_t h,uint32_t c){
    for(uint32_t j=y;j<y+h;++j) for(uint32_t i=x;i<x+w;++i) pixel(i,j,c);
}

#define FLAG_USED        0x80000000u
#define SIZE_MASK        0x7fffffffu
#define ALIGN8(x)        (((x)+7)&~7u)

#define MIN_PAYLOAD_FREE 16u
#define HEADER_FOOTER    8u
#define MIN_FREE_BLOCK  (MIN_PAYLOAD_FREE+HEADER_FOOTER)

#define TINY_LIM   32u
#define SMALL_LIM  128u
#define BUMP_LIM   (64u*1024u)

typedef struct blk { uint32_t size_flags; struct blk* next,*prev; } blk_t;

#define MAX_REGIONS 32
typedef struct { uint64_t p,v,sz; } region_t;
static region_t region[MAX_REGIONS]; static int n_region;

static blk_t *bin_tiny,*bin_small,*bin_big;
static blk_t *rov_tiny,*rov_small,*rov_big;

static uint8_t *bump_base,*bump_top,*bump_end;

static uint64_t heap_base = 0;

__attribute__((noreturn)) void PANIC(void)
{
    for(;;) __asm__("cli; hlt");
}
#define ASSERT(c) do { if(!(c)) PANIC(); } while(0)

static inline void verify(blk_t *b) {
    uint32_t sz = b->size_flags & SIZE_MASK;

    /* size and alignment checks */
    ASSERT(sz >= MIN_PAYLOAD_FREE && ((uintptr_t)b & 7u) == 0);

    /* header ↔ footer consistency */
    uint32_t *foot = (uint32_t *)((uint8_t *)b + 4 + sz);
    ASSERT(*foot == sz);

    /* used blocks must not be on any free list */
    if (b->size_flags & FLAG_USED)
        ASSERT(b->next == NULL && b->prev == NULL);
}

static inline bool is_valid_block(blk_t *b) {
        if (!b) return false;
        uint32_t sz = b->size_flags & SIZE_MASK;
        if (sz < MIN_PAYLOAD_FREE)              return false;
        if (((uintptr_t)b & 7u) != 0)           return false;
        uint32_t *foot = (uint32_t *)((uint8_t*)b + 4 + sz);
        return *foot == sz;
}

static void heap_selftest(void) {
        void *a = malloc(24);
        void *b = malloc(24);
        free(a);
        void *c = malloc(24);
        ASSERT(c == a);          /* recycled the block we just freed  */
        free(b);  free(c);
}

static inline void* v2p(uint64_t v){
    for(int i=0;i<n_region;++i)
        if(v>=region[i].v && v<region[i].v+region[i].sz)
            return (void*)(region[i].p + (v-region[i].v));
    return 0;
}
static inline uint64_t p2v(void *p){
    uint64_t ph=(uint64_t)p;
    for(int i=0;i<n_region;++i)
        if(ph>=region[i].p && ph<region[i].p+region[i].sz)
            return region[i].v + (ph-region[i].p);
    return 0;
}

// Replace your put_footer with this one.
static inline void put_footer(blk_t *b) {
    uint64_t v_block_start = p2v(b);
    if (v_block_start == 0) PANIC();          // header inside a hole ⇒ fatal

    uint64_t v_footer_addr = v_block_start + 4 + (b->size_flags & SIZE_MASK);

    /* NEW: confirm footer is in the same region */
    if (v2p(v_footer_addr) == 0) PANIC();

    *(uint32_t*)v2p(v_footer_addr) = b->size_flags & SIZE_MASK;
}

static inline blk_t** pick_bin(uint32_t sz, blk_t ***rover){
    if(sz<=TINY_LIM){ *rover=&rov_tiny;  return &bin_tiny; }
    if(sz<=SMALL_LIM){*rover=&rov_small; return &bin_small;}
    *rover=&rov_big;  return &bin_big;
}
static inline void list_push(blk_t *b){
    //verify(b);
    blk_t **rov,**head=pick_bin(b->size_flags&SIZE_MASK,&rov);
    b->prev=0; b->next=*head; if(*head) (*head)->prev=b; *head=b;
    if(!*rov) *rov=b;
}
static inline void list_remove(blk_t *b){
    //verify(b);
    blk_t **rov,**head=pick_bin(b->size_flags&SIZE_MASK,&rov);
    if(b->prev) b->prev->next=b->next; else *head=b->next;
    if(b->next) b->next->prev=b->prev;
    if(*rov==b) *rov=b->next?b->next:*head;
}

static void heap_init(void){
    //if(!heap_bytes) return;
    /* -------------------------------------------------------------------
       Put the very first free block right after the kernel image
       ------------------------------------------------------------------- */
    extern char _kernel_end;               /* provided by the linker script */

    uint64_t heap_start = ((uint64_t)&_kernel_end + 7) & ~7ULL; /* 8-byte align */
    heap_base = heap_start;

    /* find the RAM region that contains heap_start */
    int r = -1;
    for (int i = 0; i < n_region; ++i)
        if (heap_start >= region[i].p &&
            heap_start <  region[i].p + region[i].sz) { r = i; break; }
    ASSERT(r >= 0);                        /* must be inside usable RAM   */

    blk_t *b = (blk_t*)heap_start;
    uint64_t avail = region[r].p + region[r].sz - heap_start;
    ASSERT(avail > MIN_FREE_BLOCK);        /* image can’t eat whole region */

    b->size_flags = (uint32_t)(avail - HEADER_FOOTER);  /* payload size   */
    ASSERT((b->size_flags & SIZE_MASK) >= MIN_PAYLOAD_FREE);
    put_footer(b);
    bin_big=rov_big=b; b->next=b->prev=0;
}

void *malloc(uint32_t n){
    if(!n) return 0;

    if(n>=BUMP_LIM && bump_top){
        uint32_t sz=ALIGN8(n);
        uint8_t *hdr=bump_top, *end=hdr+sz+HEADER_FOOTER;
        if(end<=bump_end){
            *(uint32_t*)hdr           = sz|FLAG_USED;
            *(uint32_t*)(hdr+4+sz)    = sz;
            bump_top=end;
            return hdr+4;
        }
    }

    uint32_t sz=ALIGN8(n);
    if(sz<MIN_PAYLOAD_FREE) sz=MIN_PAYLOAD_FREE;

    blk_t **rov, **bin = pick_bin(sz, &rov);
    blk_t *best = 0;
    uint32_t best_sz = ~0u;

    for (;;) {
        for (int phase = 0; phase < 2 && !best; ++phase) {
            blk_t *cur = (phase == 0 ? *rov : *bin);
            for (; cur; cur = cur->next) {
                uint32_t csz = cur->size_flags & SIZE_MASK;
                if (csz >= sz && csz < best_sz) {
                    best = cur; best_sz = csz;
                    //verify(best);
                    if (csz == sz) break;
                }
            }
        }

        if (best) break;
        if (bin == &bin_big) return 0;

        if (bin == &bin_tiny) { bin = &bin_small; rov = &rov_small; }
        else                  { bin = &bin_big;  rov = &rov_big;  }
    }

    if(!best) return 0;

    list_remove(best);
    *rov = (*bin);
    best->next = best->prev = 0;
    uint32_t spare=best_sz - sz;

    if(spare >= MIN_FREE_BLOCK){
        blk_t *tail=(blk_t*)((uint8_t*)best + 4 + sz + 4);
        tail->size_flags = spare - HEADER_FOOTER;
        put_footer(tail); list_push(tail);
        best->size_flags = sz|FLAG_USED; put_footer(best);
    } else {
       best->size_flags |= FLAG_USED;
       put_footer(best);          /* footer must match the header     */
    }


    return (uint8_t*)best + 4;
}

// Replace your free function with this one.
void free(void *ptr) {
    if (!ptr) return;

    if (ptr >= (void*)bump_base && ptr < (void*)bump_end) {
        uint8_t *hdr = (uint8_t*)ptr - 4;
        uint32_t psz = *(uint32_t*)hdr & SIZE_MASK;
        if (hdr + HEADER_FOOTER + psz == bump_top)
            bump_top = hdr;
        return;
    }

    blk_t *b = (blk_t*)((uint8_t*)ptr - 4);
    //ASSERT(b->size_flags & FLAG_USED);
    //verify(b);
    b->size_flags &= SIZE_MASK;
    put_footer(b);

    uint64_t v_b = p2v(b);

    // Right-coalesce
    uint64_t v_r = v_b + HEADER_FOOTER + (b->size_flags & SIZE_MASK);
    blk_t   *r   = (blk_t*)v2p(v_r);
    if (is_valid_block(r) && !(r->size_flags & FLAG_USED)) {
        list_remove(r);
        b->size_flags += HEADER_FOOTER + (r->size_flags & SIZE_MASK);
        put_footer(b);
    }

    // Left-coalesce
    if (v_b > heap_base) {
        uint32_t psz = *(((uint32_t*)b) - 1) & SIZE_MASK;
        uint64_t v_l = v_b - HEADER_FOOTER - psz;
        blk_t *l = (blk_t*)v2p(v_l);
        if (is_valid_block(l) && !(l->size_flags & FLAG_USED)) {
            list_remove(l);
            l->size_flags += HEADER_FOOTER + (b->size_flags & SIZE_MASK);
            put_footer(l);
            b = l;
        }
    }
    list_push(b);
}

// Replace your entire realloc function with this one.
void *realloc(void *old, uint32_t n) {
    if (!old) return malloc(n);
    if (!n) { free(old); return 0; }

    blk_t *b = (blk_t*)((uint8_t*)old - 4);
    //verify(b);
    uint32_t cur = b->size_flags & SIZE_MASK;
    uint32_t need = ALIGN8(n);
    if (need < MIN_PAYLOAD_FREE) need = MIN_PAYLOAD_FREE;

    // This part is now correct, assuming 'free' is also fixed.
    if (need <= cur) {
        uint32_t spare = cur - need;
        if (spare >= MIN_FREE_BLOCK) {
            b->size_flags = need | FLAG_USED;
            put_footer(b);
            uint64_t v_tail = p2v(b) + HEADER_FOOTER + need;
            blk_t *tail = (blk_t*)v2p(v_tail);
            if (tail) {
                tail->size_flags = spare - HEADER_FOOTER;
                put_footer(tail);
                list_push(tail);
            }
        }
        //verify(b);
        return old;
    }
    
    // --- In-place expansion logic (this was a secondary bug, but should be correct) ---
    uint64_t v_b_realloc = p2v(b);
    uint64_t v_r_realloc = v_b_realloc + HEADER_FOOTER + cur;
    blk_t *r = (blk_t*)v2p(v_r_realloc);

    if (r && !(r->size_flags & FLAG_USED)) {
        uint32_t comb = cur + HEADER_FOOTER + (r->size_flags & SIZE_MASK);
        if (comb >= need) {
            list_remove(r);
            uint32_t spare = comb - need;
            if (spare >= MIN_FREE_BLOCK) {
                b->size_flags = need | FLAG_USED;
                put_footer(b);
                uint64_t v_tail = v_b_realloc + HEADER_FOOTER + need;
                blk_t* tail = (blk_t*)v2p(v_tail);
                tail->size_flags = spare - HEADER_FOOTER;
                put_footer(tail);
                list_push(tail);
            } else {
                b->size_flags = comb | FLAG_USED;
                put_footer(b);
            }
            //verify(b);
            return old;
        }
    }

    // --- Malloc and Safe Copy ---
    void *nu = malloc(n);
    if (!nu) return 0;

    uint32_t copy_size = (cur < n) ? cur : n;
    uint8_t *src = (uint8_t *)old;
    uint8_t *dst = (uint8_t *)nu;
    for (uint32_t i = 0; i < copy_size; ++i){
        dst[i] = src[i];
    }

    free(old);
    return nu;
}

extern char _kernel_end;
void start(uint64_t info){
    multiboot_tag_t *tag; uint8_t fb_done=0;
    uint64_t kern_end=((uint64_t)&_kernel_end+4095)&~4095ULL;
    uint64_t big_base=0,big_len=0;

    for(tag=(void*)(info+8); tag->type;
        tag=(void*)((uint8_t*)tag+((tag->size+7)&~7))){

        if(tag->type==8 && !fb_done){
            multiboot_tag_framebuffer_t *fb=(void*)tag;
            framebuffer=(uint32_t*)fb->addr;
            screen_w=fb->w; screen_h=fb->h; fb_pitch=fb->pitch; fb_done=1;
        }
        if(tag->type==6){
            multiboot_tag_mmap_t *mm=(void*)tag;
            for(multiboot_mmap_entry_t *e=(void*)(mm+1);
                (uint8_t*)e<(uint8_t*)tag+tag->size;
                e=(void*)((uint8_t*)e+mm->entry_size))
                if(e->type==MULTIBOOT_MEMORY_AVAILABLE && e->len>big_len){
                    big_base=e->base; big_len=e->len;
                }
        }
    }

    bump_base = bump_top = bump_end = 0;
    if (big_base + big_len > kern_end) {
        uint64_t bump_sz = 16ULL * 1024 * 1024;
        if (bump_sz > big_len)
            bump_sz = (big_len > BUMP_LIM) ? BUMP_LIM : 0; 
        if (bump_sz) {
            bump_base = (uint8_t*)(big_base + big_len - bump_sz);
            bump_top  = bump_base;
            bump_end  = (uint8_t*)(big_base + big_len);
            /* NEW: add the bump region so v2p/p2v can translate it */
            ASSERT(n_region < MAX_REGIONS);
            region[n_region++] = (region_t){ (uint64_t)bump_base,
                                            (uint64_t)bump_base,
                                            bump_sz };
            big_len  -= bump_sz;
        }
    }
    
    if (big_len) {
        ASSERT(n_region < MAX_REGIONS);
        /* identity-map the region: virtual == physical */
        region[n_region++] = (region_t){ big_base, big_base, big_len };
    }
    for(tag=(void*)(info+8); tag->type;
        tag=(void*)((uint8_t*)tag+((tag->size+7)&~7)))
        if(tag->type==6){
            multiboot_tag_mmap_t *mm=(void*)tag;
            for(multiboot_mmap_entry_t *e=(void*)(mm+1);
                (uint8_t*)e<(uint8_t*)tag+tag->size;
                e=(void*)((uint8_t*)e+mm->entry_size))
                if(e->type==MULTIBOOT_MEMORY_AVAILABLE && e->base!=big_base){
                    ASSERT(n_region<MAX_REGIONS);
                    /* identity-map the rest as well */
                    region[n_region++] = (region_t){ e->base, e->base, e->len };
                }
        }
    heap_init();
    heap_selftest();
    //Actual code starts here
    //

    //Font renderer
    int* svg_to_bitmap(int width, int height, const char* svg) {
        long total = 2 + width * height * 3 + 1;
        int* buf = (int*)malloc(total * sizeof(int));
        buf[0] = width; buf[1] = height;
        for (long i = 2; i < total; i++) buf[i] = 0;
        buf[total - 1] = 0;

        float minx = 0, miny = 0, maxx = 0, maxy = 0;
        int first = 1, i = 0;

        // Find bounding box
        while (svg[i]) {
            char c = svg[i];
            if (c != 'M' && c != 'L' && c != 'Q') { i++; continue; }
            i++;
            int need = (c == 'Q' ? 4 : 2);
            for (int n = 0; n < need; n++) {
                while (svg[i] == ' ' || svg[i] == ',' || svg[i] == '\n' || svg[i] == '\r' || svg[i] == '\t') i++;
                int sgn = 1; if (svg[i] == '-') { sgn = -1; i++; }
                float val = 0, frac = 0, scale = 0.1f;
                while ((svg[i] >= '0' && svg[i] <= '9') || svg[i] == '.') {
                    if (svg[i] == '.') { i++; while (svg[i] >= '0' && svg[i] <= '9') { frac += (svg[i++] - '0') * scale; scale *= 0.1f; } break; }
                    val = val * 10 + (svg[i++] - '0');
                }
                float full = sgn * (val + frac);
                if (first) { minx = maxx = full; miny = maxy = full; first = 0; }
                if (n & 1) { if (full < miny) miny = full; if (full > maxy) maxy = full; }
                else       { if (full < minx) minx = full; if (full > maxx) maxx = full; }
            }
        }

        float diffx = maxx - minx; if (diffx == 0) diffx = 1;
        float diffy = maxy - miny; if (diffy == 0) diffy = 1;
        float scalex = (float)(width  - 1) / diffx;
        float scaley = (float)(height - 1) / diffy;
        float scale = (scalex < scaley) ? scalex : scaley;
        float offx = ((width  - 1) - scale * diffx) / 2.0f;
        float offy = ((height - 1) - scale * diffy) / 2.0f;

        // replacements for abs() and fabsf()
        #define iabs(a) ((a) < 0 ? -(a) : (a))
        #define fabsf(a) ((a) < 0.0f ? -(a) : (a))

        i = 0;
        int cx = 0, cy = 0, sx0 = 0, sy0 = 0;
        while (svg[i]) {
            char cmd = svg[i];
            if (cmd != 'M' && cmd != 'L' && cmd != 'Q' && cmd != 'Z') { i++; continue; }
            i++;

            if (cmd == 'Z') {
                int x1 = sx0, y1 = sy0;
                int x0 = cx,  y0 = cy;
                int dx = iabs(x1 - x0), sx = (x0 < x1 ? 1 : -1);
                int dy = iabs(y1 - y0), sy = (y0 < y1 ? 1 : -1);
                int err = (dx > dy ? dx : -dy) / 2;
                for (;;) {
                    if (x0 >= 0 && x0 < width && y0 >= 0 && y0 < height) {
                        long p = 2 + ((long)y0 * width + x0) * 3;
                        buf[p] = buf[p + 1] = buf[p + 2] = 255;
                    }
                    if (x0 == x1 && y0 == y1) break;
                    int e2 = err;
                    if (e2 > -dx) { err -= dy; x0 += sx; }
                    if (e2 < dy)  { err += dx; y0 += sy; }
                }
                cx = sx0; cy = sy0;
                continue;
            }

            float nums[4];
            int need = (cmd == 'Q' ? 4 : 2);
            for (int n = 0; n < need; n++) {
                while (svg[i] == ' ' || svg[i] == ',' || svg[i] == '\n' || svg[i] == '\r' || svg[i] == '\t') i++;
                int sgn = 1; if (svg[i] == '-') { sgn = -1; i++; }
                float val = 0, frac = 0, scale10 = 0.1f;
                while ((svg[i] >= '0' && svg[i] <= '9') || svg[i] == '.') {
                    if (svg[i] == '.') { i++; while (svg[i] >= '0' && svg[i] <= '9') { frac += (svg[i++] - '0') * scale10; scale10 *= 0.1f; } break; }
                    val = val * 10 + (svg[i++] - '0');
                }
                nums[n] = sgn * (val + frac);
            }

            if (cmd == 'M') {
                cx = (int)((nums[0] - minx) * scale + offx + 0.5f);
                cy = (int)((nums[1] - miny) * scale + offy + 0.5f);
                sx0 = cx; sy0 = cy;
            }
            else if (cmd == 'L') {
                int x1 = (int)((nums[0] - minx) * scale + offx + 0.5f);
                int y1 = (int)((nums[1] - miny) * scale + offy + 0.5f);
                int x0 = cx, y0 = cy;
                int dx = iabs(x1 - x0), sx = (x0 < x1 ? 1 : -1);
                int dy = iabs(y1 - y0), sy = (y0 < y1 ? 1 : -1);
                int err = (dx > dy ? dx : -dy) / 2;
                for (;;) {
                    if (x0 >= 0 && x0 < width && y0 >= 0 && y0 < height) {
                        long p = 2 + ((long)y0 * width + x0) * 3;
                        buf[p] = buf[p + 1] = buf[p + 2] = 255;
                    }
                    if (x0 == x1 && y0 == y1) break;
                    int e2 = err;
                    if (e2 > -dx) { err -= dy; x0 += sx; }
                    if (e2 < dy)  { err += dx; y0 += sy; }
                }
                cx = x1; cy = y1;
            }
            else if (cmd == 'Q') {
                float cpx = (nums[0] - minx) * scale + offx;
                float cpy = (nums[1] - miny) * scale + offy;
                float ex  = (nums[2] - minx) * scale + offx;
                float ey  = (nums[3] - miny) * scale + offy;

                float px = (float)cx, py = (float)cy;
                float dx1 = fabsf(cpx - px), dy1 = fabsf(cpy - py);
                float dx2 = fabsf(ex  - cpx), dy2 = fabsf(ey  - cpy);
                float est = dx1 + dy1 + dx2 + dy2;
                int segs = (int)(est / 2); if (segs < 4) segs = 4; if (segs > 1000) segs = 1000;

                for (int s = 1; s <= segs; s++) {
                    float t = (float)s / segs;
                    float omt = 1.0f - t;
                    float qx = omt * omt * px + 2 * omt * t * cpx + t * t * ex;
                    float qy = omt * omt * py + 2 * omt * t * cpy + t * t * ey;

                    int x1 = (int)(qx + 0.5f), y1 = (int)(qy + 0.5f);
                    int x0 = (int)(px + 0.5f), y0 = (int)(py + 0.5f);
                    int dx = iabs(x1 - x0), sx = (x0 < x1 ? 1 : -1);
                    int dy = iabs(y1 - y0), sy = (y0 < y1 ? 1 : -1);
                    int err = (dx > dy ? dx : -dy) / 2;
                    for (;;) {
                        if (x0 >= 0 && x0 < width && y0 >= 0 && y0 < height) {
                            long p = 2 + ((long)y0 * width + x0) * 3;
                            buf[p] = buf[p + 1] = buf[p + 2] = 255;
                        }
                        if (x0 == x1 && y0 == y1) break;
                        int e2 = err;
                        if (e2 > -dx) { err -= dy; x0 += sx; }
                        if (e2 < dy)  { err += dx; y0 += sy; }
                    }
                    px = qx; py = qy;
                }
                cx = (int)(ex + 0.5f); cy = (int)(ey + 0.5f);
            }
        }

        return buf;
    }



    //Default font for fishOS is jetbrains mono regular.

    const char* font_chars[128][2] = {
        { " ", "" },
        { "!", "M34.10-21.50L25.90-21.50L24.70-73L35.30-73L34.10-21.50ZM31.50 0.50L28.50 0.50Q25.90 0.50 24.20-1.20Q22.50-2.90 22.50-5.50L22.50-5.50Q22.50-8.10 24.20-9.80Q25.90-11.50 28.50-11.50L28.50-11.50L31.50-11.50Q34.40-11.50 35.95-9.85Q37.50-8.20 37.50-5.60L37.50-5.60Q37.50-3 35.80-1.25Q34.10 0.50 31.50 0.50L31.50 0.50Z" },
        { "\"", "M23.80-43L15.10-43L14.30-73L24.50-73L23.80-43ZM45-43L36.30-43L35.50-73L45.70-73L45-43Z" },
        { "#", "M15.30 0L8.30 0L12.20-21L3.50-21L3.50-27.50L13.30-27.50L16.70-45.50L7-45.50L7-52L17.80-52L21.70-73L28.70-73L24.80-52L40.80-52L44.70-73L51.70-73L47.80-52L56.50-52L56.50-45.50L46.70-45.50L43.30-27.50L53-27.50L53-21L42.20-21L38.30 0L31.30 0L35.20-21L19.20-21L15.30 0ZM23.70-45.50L20.30-27.50L36.30-27.50L39.70-45.50L23.70-45.50Z" },
        { "$", "M33.50 14L27.50 14L27.50 0.90Q18.10 0.10 12.75-5.15Q7.40-10.40 7.20-19L7.20-19L16.20-19Q16.20-14.10 19.15-11Q22.10-7.90 27.50-7.20L27.50-7.20L27.50-33.40L24.80-34.20Q17.30-36.50 13.25-41.90Q9.20-47.30 9.20-54.60L9.20-54.60Q9.20-62.60 14.15-67.80Q19.10-73 27.50-73.80L27.50-73.80L27.50-87L33.50-87L33.50-73.90Q41.80-73.10 46.80-67.90Q51.80-62.70 51.90-54.50L51.90-54.50L42.90-54.50Q42.90-59.20 40.45-62.15Q38-65.10 33.50-65.80L33.50-65.80L33.50-41L37.50-39.70Q44.80-37.40 48.80-31.90Q52.80-26.40 52.80-19L52.80-19Q52.80-10.80 47.55-5.40Q42.30 0 33.50 0.90L33.50 0.90L33.50 14ZM18.20-55.40L18.20-55.40Q18.20-50.90 20.60-47.60Q23-44.30 27.50-42.90L27.50-42.90L27.50-65.80Q23.10-65.10 20.65-62.40Q18.20-59.70 18.20-55.40ZM33.50-31.50L33.50-7.20Q38.40-8 41.10-11Q43.80-14 43.80-18.80L43.80-18.80Q43.80-23.20 41.45-26.45Q39.10-29.70 34.70-31.10L34.70-31.10L33.50-31.50Z" },
        { "%", "M15.30-40L15.30-40Q8.90-40 5.15-43.65Q1.40-47.30 1.50-53.50L1.50-53.50L1.50-60Q1.40-66.20 5.15-69.85Q8.90-73.50 15.30-73.50L15.30-73.50Q21.70-73.50 25.45-69.85Q29.20-66.20 29.30-60L29.30-60L29.30-53.50Q29.30-47.30 25.55-43.65Q21.80-40 15.30-40ZM8.80 0L1.40 0L51.20-73L58.60-73L8.80 0ZM15.40-46.80L15.40-46.80Q18.40-46.80 20.15-48.60Q21.90-50.40 21.90-53.50L21.90-53.50L21.90-60Q21.90-63.10 20.15-64.90Q18.40-66.70 15.40-66.70L15.40-66.70Q12.40-66.70 10.65-64.90Q8.90-63.10 8.90-60L8.90-60L8.90-53.50Q8.90-50.40 10.65-48.60Q12.40-46.80 15.40-46.80ZM44.60 0.50L44.60 0.50Q38.20 0.50 34.45-3.15Q30.70-6.80 30.70-13L30.70-13L30.70-19.50Q30.60-25.70 34.40-29.35Q38.20-33 44.60-33L44.60-33Q51-33 54.75-29.35Q58.50-25.70 58.50-19.50L58.50-19.50L58.50-13Q58.50-6.80 54.75-3.15Q51 0.50 44.60 0.50ZM44.60-6.40L44.60-6.40Q47.60-6.40 49.35-8.15Q51.10-9.90 51.10-13L51.10-13L51.10-19.50Q51.10-22.60 49.35-24.40Q47.60-26.20 44.50-26.20L44.50-26.20Q41.60-26.20 39.85-24.40Q38.10-22.60 38.10-19.50L38.10-19.50L38.10-13Q38-9.90 39.75-8.15Q41.50-6.40 44.60-6.40Z" },
        { "&", "M21.50 0.90L21.50 0.90Q12.70 0.90 7.60-4.25Q2.50-9.40 2.50-18.20L2.50-18.20L2.50-23.90Q2.50-31.90 7-36.70Q11.50-41.50 19.10-41.90L19.10-41.90L16.30-45.50Q10.90-52.60 10.90-58.10L10.90-58.10Q10.90-65.20 15.70-69.60Q20.50-74 28.20-74L28.20-74Q33.70-74 37.85-71.60Q42-69.20 44.35-64.95Q46.70-60.70 46.70-55L46.70-55L37.90-55Q37.90-60 35.25-63.15Q32.60-66.30 28.20-66.30L28.20-66.30Q24.50-66.30 22.15-64Q19.80-61.70 19.80-57.90L19.80-57.90Q19.80-54 22.70-50.30L22.70-50.30L42.20-25.10L51.30-36.50L61.30-36.50L47-18.90L61.50 0L51.60 0L41.90-12.80L37.60-7.40Q34.20-3.20 30.05-1.15Q25.90 0.90 21.50 0.90ZM22.10-7.20L22.10-7.20Q27.80-7.20 31.80-12.30L31.80-12.30L37-18.90L24.50-34.90L21.50-34.90Q16.80-34.90 14.05-31.95Q11.30-29 11.30-23.90L11.30-23.90L11.30-18.20Q11.30-13.10 14.25-10.15Q17.20-7.20 22.10-7.20Z" },
        { "'", "M34.40-43L25.70-43L24.90-73L35.10-73L34.40-43Z" },
        { "(", "M48.50 3.30L48.50 12Q34.20 8.80 26.35-1.40Q18.50-11.60 18.50-27L18.50-27L18.50-45Q18.50-60.40 26.35-70.60Q34.20-80.80 48.50-84L48.50-84L48.50-75.30Q42.10-73.80 37.35-69.60Q32.60-65.40 30.05-59.15Q27.50-52.90 27.50-45L27.50-45L27.50-27Q27.50-19.20 30.05-12.90Q32.60-6.60 37.35-2.40Q42.10 1.80 48.50 3.30L48.50 3.30Z" },
        { ")", "M11.50 12L11.50 12L11.50 3.30Q18 1.80 22.70-2.40Q27.40-6.60 29.95-12.90Q32.50-19.20 32.50-27L32.50-27L32.50-45Q32.50-52.90 29.95-59.15Q27.40-65.40 22.70-69.60Q18-73.80 11.50-75.30L11.50-75.30L11.50-84Q25.80-80.80 33.65-70.60Q41.50-60.40 41.50-45L41.50-45L41.50-27Q41.50-11.60 33.65-1.40Q25.80 8.80 11.50 12Z" },
        { "*", "M24.20-19.70L17.70-10.30L10.80-15.20L17.30-24.50Q18.60-26.30 20.85-28.90Q23.10-31.50 25.10-33.50L25.10-33.50Q22.30-33.90 19.20-34.70Q16.10-35.50 14.30-36.20L14.30-36.20L3.60-40.20L6.40-48.10L17.20-44.10Q18.90-43.50 21.70-42.20Q24.50-40.90 26.80-39.50L26.80-39.50Q26.30-42.10 26.05-44.85Q25.80-47.60 25.80-49.50L25.80-49.50L25.80-62L34.20-62L34.20-49.50Q34.20-47.60 33.90-44.85Q33.60-42.10 33.10-39.50L33.10-39.50Q35.50-40.90 38.25-42.20Q41-43.50 42.80-44.10L42.80-44.10L53.60-48.10L56.40-40.20L45.70-36.20Q43.90-35.50 40.80-34.70Q37.70-33.90 34.90-33.50L34.90-33.50Q36.90-31.50 39.20-28.85Q41.50-26.20 42.70-24.50L42.70-24.50L49.20-15.20L42.30-10.30L35.80-19.70Q34.60-21.40 32.90-24.40Q31.20-27.40 30-30L30-30Q28.80-27.40 27.10-24.45Q25.40-21.50 24.20-19.70L24.20-19.70Z" },
        { "+", "M34.40-9.50L25.60-9.50L25.60-29L6.50-29L6.50-37L25.60-37L25.60-56.50L34.40-56.50L34.40-37L53.50-37L53.50-29L34.40-29L34.40-9.50Z" },
        { ",", "M30.30 16L21 16L26.50-14.60L37.30-14.60L30.30 16Z" },
        { "-", "M46-29L14-29L14-37L46-37L46-29Z" },
        { ".", "M30 1L30 1Q26.30 1 24.05-1.20Q21.80-3.40 21.80-6.90L21.80-6.90Q21.80-10.60 24.05-12.90Q26.30-15.20 30-15.20L30-15.20Q33.70-15.20 35.95-12.90Q38.20-10.60 38.20-6.90L38.20-6.90Q38.20-3.40 35.95-1.20Q33.70 1 30 1Z" },
        { "/", "M17 11L7.50 11L43-83L52.50-83L17 11Z" },
        { "0", "M30 1L30 1Q19.90 1 13.95-4.85Q8-10.70 8-20.50L8-20.50L8-52.50Q8-62.30 13.95-68.15Q19.90-74 30-74L30-74Q40.10-74 46.05-68.15Q52-62.30 52-52.50L52-52.50L52-20.50Q52-14 49.30-9.15Q46.60-4.30 41.65-1.65Q36.70 1 30 1ZM30-6.70L30-6.70Q36-6.70 39.65-10.55Q43.30-14.40 43.30-20.50L43.30-20.50L43.30-52.50Q43.30-58.60 39.65-62.45Q36-66.30 30-66.30L30-66.30Q24-66.30 20.35-62.45Q16.70-58.60 16.70-52.50L16.70-52.50L16.70-20.50Q16.70-14.40 20.35-10.55Q24-6.70 30-6.70ZM30-31L30-31Q27.30-31 25.65-32.50Q24-34 24-36.80L24-36.80Q24-39.50 25.65-40.95Q27.30-42.40 30-42.40L30-42.40Q32.70-42.40 34.35-40.95Q36-39.50 36-36.80L36-36.80Q36-34 34.35-32.50Q32.70-31 30-31Z" },
        { "1", "M54 0L9 0L9-8.20L28.80-8.20L28.80-65.20L9-50.40L9-60.70L25.50-73L37.80-73L37.80-8.20L54-8.20L54 0Z" },
        { "2", "M52.70 0L8.60 0L8.60-8.30L32.90-34.30Q38.20-39.90 40.40-44.30Q42.60-48.70 42.60-52.90L42.60-52.90Q42.60-58.90 39.15-62.45Q35.70-66 29.80-66L29.80-66Q23.70-66 20.15-62.35Q16.60-58.70 16.60-52.50L16.60-52.50L7.60-52.50Q7.90-62.40 13.90-68.20Q19.90-74 29.80-74L29.80-74Q39.90-74 45.85-68.30Q51.80-62.60 51.80-52.80L51.80-52.80Q51.80-47.60 48.95-41.80Q46.10-36 39.20-28.80L39.20-28.80L19.50-8.20L52.70-8.20L52.70 0Z" },
        { "3", "M28.90 1L28.90 1Q18.80 1 12.90-4.65Q7-10.30 7-20L7-20L16-20Q16-14 19.50-10.50Q23-7 29-7L29-7Q35-7 38.50-10.50Q42-14 42-20L42-20L42-25Q42-31 38.50-34.50Q35-38 29-38L29-38L21.10-38L21.10-45.80L39-64.80L9-64.80L9-73L49.20-73L49.20-64.60L31.60-45.90Q40.60-45.20 45.80-39.65Q51-34.10 51-25L51-25L51-20Q51-10.30 45.05-4.65Q39.10 1 28.90 1Z" },
        { "4", "M49 0L40 0L40-16L7-16L7-30.10L33.60-73L43.80-73L16-28.10L16-24.20L40-24.20L40-42L49-42L49 0Z" },
        { "5", "M29.40 1L29.40 1Q19.30 1 13.40-4.65Q7.50-10.30 7.50-20L7.50-20L16.50-20Q16.50-14 20-10.50Q23.50-7 29.50-7L29.50-7Q35.50-7 39-10.50Q42.50-14 42.50-20L42.50-20L42.50-24.50Q42.50-30.50 39.10-34Q35.70-37.50 29.90-37.50L29.90-37.50L10-37.50L10-73L48.90-73L48.90-64.80L18.40-64.80L18.60-45.70L30.40-45.70Q40.50-45.70 46-40.15Q51.50-34.60 51.50-24.50L51.50-24.50L51.50-20Q51.50-10.30 45.55-4.65Q39.60 1 29.40 1Z" },
        { "6", "M30.10 1L30.10 1Q23.10 1 17.75-1.95Q12.40-4.90 9.40-10.15Q6.40-15.40 6.40-22.30L6.40-22.30Q6.40-27.10 8.20-32.15Q10-37.20 13.10-42.70L13.10-42.70L30-73L40-73L22-41.70L22.30-41.50Q23.60-43.20 26.20-44.10Q28.80-45 31.90-45L31.90-45Q38.40-45 43.25-42.15Q48.10-39.30 50.85-34.30Q53.60-29.30 53.60-22.70L53.60-22.70Q53.60-15.70 50.60-10.35Q47.60-5 42.35-2Q37.10 1 30.10 1ZM30-7L30-7Q36.50-7 40.55-11.30Q44.60-15.60 44.60-22.50L44.60-22.50Q44.60-29.40 40.55-33.70Q36.50-38 30-38L30-38Q23.50-38 19.45-33.70Q15.40-29.40 15.40-22.50L15.40-22.50Q15.40-15.60 19.45-11.30Q23.50-7 30-7Z" },
        { "7", "M28.80 0L19 0L45-64.80L17.20-64.80L17.20-53L8.20-53L8.20-73L54.60-73L54.60-64.60L28.80 0Z" },
        { "8", "M30 1L30 1Q23.10 1 17.80-1.70Q12.50-4.40 9.55-9.25Q6.60-14.10 6.60-20.40L6.60-20.40Q6.60-27.30 10.55-32.30Q14.50-37.30 21.10-38.40L21.10-38.40L21.10-38.70Q15.40-40 12-44.45Q8.60-48.90 8.60-54.70L8.60-54.70Q8.60-60.40 11.30-64.75Q14-69.10 18.85-71.55Q23.70-74 30-74L30-74Q36.40-74 41.20-71.55Q46-69.10 48.70-64.75Q51.40-60.40 51.40-54.70L51.40-54.70Q51.40-48.90 48-44.45Q44.60-40 38.90-38.70L38.90-38.70L38.90-38.40Q45.50-37.30 49.45-32.30Q53.40-27.30 53.40-20.40L53.40-20.40Q53.40-14.10 50.45-9.25Q47.50-4.40 42.25-1.70Q37 1 30 1ZM30-42.20L30-42.20Q35.60-42.20 39-45.50Q42.40-48.80 42.40-54.10L42.40-54.10Q42.40-59.40 39-62.70Q35.60-66 30-66L30-66Q24.50-66 21.05-62.70Q17.60-59.40 17.60-54.10L17.60-54.10Q17.60-48.80 21.05-45.50Q24.50-42.20 30-42.20ZM30-7.10L30-7.10Q36.40-7.10 40.40-10.85Q44.40-14.60 44.40-20.60L44.40-20.60Q44.40-26.70 40.40-30.45Q36.40-34.20 30-34.20L30-34.20Q23.60-34.20 19.60-30.45Q15.60-26.70 15.60-20.60L15.60-20.60Q15.60-14.60 19.60-10.85Q23.60-7.10 30-7.10Z" },
        { "9", "M30 0L19.50 0L37.50-31.30L37.20-31.50Q36.20-29.90 33.50-28.95Q30.80-28 27.60-28L27.60-28Q21.30-28 16.55-30.85Q11.80-33.70 9.10-38.70Q6.40-43.70 6.40-50.30L6.40-50.30Q6.40-57.40 9.40-62.70Q12.40-68 17.70-71Q23-74 29.90-74L29.90-74Q37-74 42.30-71.05Q47.60-68.10 50.60-62.85Q53.60-57.60 53.60-50.70L53.60-50.70Q53.60-45.90 51.80-40.85Q50-35.80 46.90-30.30L46.90-30.30L30 0ZM30-35L30-35Q36.50-35 40.55-39.30Q44.60-43.60 44.60-50.50L44.60-50.50Q44.60-57.40 40.55-61.70Q36.50-66 30-66L30-66Q23.50-66 19.45-61.70Q15.40-57.40 15.40-50.50L15.40-50.50Q15.40-43.60 19.45-39.30Q23.50-35 30-35Z" },
        { ":", "M30-41.20L30-41.20Q25.90-41.20 23.80-43.20Q21.70-45.20 21.70-48.60L21.70-48.60Q21.70-52 23.80-54Q25.90-56 30-56L30-56Q34.10-56 36.20-54Q38.30-52 38.30-48.60L38.30-48.60Q38.30-45.20 36.20-43.20Q34.10-41.20 30-41.20ZM30 1L30 1Q25.90 1 23.80-1Q21.70-3 21.70-6.40L21.70-6.40Q21.70-9.80 23.80-11.80Q25.90-13.80 30-13.80L30-13.80Q34.10-13.80 36.20-11.80Q38.30-9.80 38.30-6.40L38.30-6.40Q38.30-3 36.20-1Q34.10 1 30 1Z" },
        { ";", "M31-41L29-41Q25.70-41 23.60-43.10Q21.50-45.20 21.50-48.50L21.50-48.50Q21.50-51.70 23.65-53.85Q25.80-56 29-56L29-56L31-56Q34.20-56 36.35-53.85Q38.50-51.70 38.50-48.50L38.50-48.50Q38.50-45.20 36.40-43.10Q34.30-41 31-41L31-41ZM29.80 16L20.50 16L26-14.60L36.80-14.60L29.80 16Z" },
        { "<", "M51.50-15.50L51.50-6.50L8.50-28L8.50-38L51.50-59.50L51.50-50.80L20.50-35.60Q18.60-34.70 16.95-34.05Q15.30-33.40 14.50-33.20L14.50-33.20Q15.40-33 17.10-32.35Q18.80-31.70 20.50-30.80L20.50-30.80L51.50-15.50Z" },
        { "=", "M51.50-41L8.50-41L8.50-49L51.50-49L51.50-41ZM51.50-17L8.50-17L8.50-25L51.50-25L51.50-17Z" },
        { ">", "M51.50-28L8.50-6.50L8.50-15.20L39.50-30.40Q41.40-31.30 43.05-31.95Q44.70-32.60 45.50-32.80L45.50-32.80Q44.60-33 42.90-33.70Q41.20-34.40 39.50-35.20L39.50-35.20L8.50-50.50L8.50-59.50L51.50-38L51.50-28Z" },
        { "?", "M29.60-21.50L20.60-21.50L20.60-38.50L25.60-38.50Q32-38.50 35.75-42.05Q39.50-45.60 39.50-51.50L39.50-51.50Q39.50-57.40 35.75-60.95Q32-64.50 25.50-64.50L25.50-64.50L13-64.50L13-73L25.50-73Q32.50-73 37.65-70.35Q42.80-67.70 45.65-62.90Q48.50-58.10 48.50-51.50L48.50-51.50Q48.50-45.80 46.10-41.25Q43.70-36.70 39.45-34Q35.20-31.30 29.60-31L29.60-31L29.60-21.50ZM26.50 0.50L23.50 0.50Q20.90 0.50 19.20-1.20Q17.50-2.90 17.50-5.50L17.50-5.50Q17.50-8.10 19.20-9.80Q20.90-11.50 23.50-11.50L23.50-11.50L26.50-11.50Q29.40-11.50 30.95-9.85Q32.50-8.20 32.50-5.60L32.50-5.60Q32.50-3 30.80-1.25Q29.10 0.50 26.50 0.50L26.50 0.50Z" },
        { "@", "M43.50 18L32.50 18Q24 18 17.70 14.45Q11.40 10.90 7.95 4.35Q4.50-2.20 4.50-11L4.50-11L4.50-45Q4.50-58.50 11.70-66.25Q18.90-74 31.50-74L31.50-74Q42.90-74 49.45-67.45Q56-60.90 56-49.50L56-49.50L56-22.40Q56-14.60 51.70-10.05Q47.40-5.50 40-5.50L40-5.50Q32.70-5.50 28.35-9.90Q24-14.30 24-21.40L24-21.40L24-33Q24-40.40 27.50-44.45Q31-48.50 37.40-48.50L37.40-48.50Q41.50-48.50 44.20-46.90Q46.90-45.30 47.80-42.50L47.80-42.50L48-42.50L48-49.50Q48-58 43.75-62.50Q39.50-67 31.50-67L31.50-67Q22.50-67 17.50-61.20Q12.50-55.40 12.50-45L12.50-45L12.50-11Q12.50-1 17.85 4.75Q23.20 10.50 32.50 10.50L32.50 10.50L43.50 10.50L43.50 18ZM40-12.20L40-12.20Q43.80-12.20 45.90-14.65Q48-17.10 48-21.40L48-21.40L48-33.10Q48-37.50 45.90-39.85Q43.80-42.20 40-42.20L40-42.20Q36.20-42.20 34.10-39.80Q32-37.40 32-33L32-33L32-21.40Q32-17.10 34.10-14.65Q36.20-12.20 40-12.20Z" },
        { "A", "M14.20 0L5 0L24-73L36.10-73L55 0L45.90 0L41.10-19.40L19-19.40L14.20 0ZM26.40-49.60L20.80-27L39.20-27L33.60-49.50Q32-55.90 31.10-60.20Q30.20-64.50 30-65.80L30-65.80Q29.80-64.50 28.90-60.20Q28-55.90 26.40-49.60L26.40-49.60Z" },
        { "B", "M31.50 0L9.30 0L9.30-73L30-73Q40-73 45.65-68Q51.30-63 51.30-54.10L51.30-54.10Q51.30-48.50 47.75-44Q44.20-39.50 38.50-38.40L38.50-38.40L38.50-38.10Q42.80-37.60 46.05-35.10Q49.30-32.60 51.15-28.75Q53-24.90 53-20.30L53-20.30Q53-10.90 47.25-5.45Q41.50 0 31.50 0L31.50 0ZM18.10-64.90L18.10-41.90L29.90-41.90Q35.70-41.90 39.05-45Q42.40-48.10 42.40-53.40L42.40-53.40Q42.40-58.70 39.10-61.80Q35.80-64.90 30-64.90L30-64.90L18.10-64.90ZM18.10-34.10L18.10-8.10L30.50-8.10Q36.80-8.10 40.45-11.45Q44.10-14.80 44.10-20.60L44.10-20.60Q44.10-26.60 40.45-30.35Q36.80-34.10 30.50-34.10L30.50-34.10L18.10-34.10Z" },
        { "C", "M30.80 1L30.80 1Q20.80 1 15-4.60Q9.20-10.20 9.20-20L9.20-20L9.20-53Q9.20-62.80 15-68.40Q20.80-74 30.80-74L30.80-74Q40.60-74 46.40-68.35Q52.20-62.70 52.20-53L52.20-53L43.20-53Q43.20-59.20 39.95-62.55Q36.70-65.90 30.80-65.90L30.80-65.90Q24.90-65.90 21.55-62.55Q18.20-59.20 18.20-53L18.20-53L18.20-20Q18.20-13.80 21.55-10.45Q24.90-7.10 30.80-7.10L30.80-7.10Q36.70-7.10 39.95-10.45Q43.20-13.80 43.20-20L43.20-20L52.20-20Q52.20-10.30 46.40-4.65Q40.60 1 30.80 1Z" },
        { "D", "M28.10 0L9.20 0L9.20-73L28.10-73Q35.20-73 40.35-70.30Q45.50-67.60 48.35-62.70Q51.20-57.80 51.20-51.10L51.20-51.10L51.20-22Q51.20-15.30 48.35-10.35Q45.50-5.40 40.35-2.70Q35.20 0 28.10 0L28.10 0ZM18.20-65L18.20-8L28.10-8Q34.70-8 38.45-11.70Q42.20-15.40 42.20-22L42.20-22L42.20-51.10Q42.20-57.60 38.45-61.30Q34.70-65 28.10-65L28.10-65L18.20-65Z" },
        { "E", "M52 0L10 0L10-73L52-73L52-64.80L18.90-64.80L18.90-42.20L48.50-42.20L48.50-34.20L18.90-34.20L18.90-8.20L52-8.20L52 0Z" },
        { "F", "M18.50 0L9.50 0L9.50-73L52.50-73L52.50-64.80L18.30-64.80L18.30-40.60L49.90-40.60L49.90-32.40L18.50-32.40L18.50 0Z" },
        { "G", "M30.40 1L30.40 1Q20.40 1 14.60-4.60Q8.80-10.20 8.80-20L8.80-20L8.80-53Q8.80-62.80 14.60-68.40Q20.40-74 30.40-74L30.40-74Q40.20-74 46-68.35Q51.80-62.70 51.80-53L51.80-53L42.80-53Q42.80-59.20 39.55-62.55Q36.30-65.90 30.40-65.90L30.40-65.90Q24.50-65.90 21.15-62.60Q17.80-59.30 17.80-53.10L17.80-53.10L17.80-20Q17.80-13.80 21.15-10.40Q24.50-7 30.40-7L30.40-7Q36.30-7 39.55-10.40Q42.80-13.80 42.80-20L42.80-20L42.80-30L28-30L28-38.20L51.80-38.20L51.80-20Q51.80-10.30 46-4.65Q40.20 1 30.40 1Z" },
        { "H", "M18.30 0L9.30 0L9.30-73L18.30-73L18.30-41.80L41.70-41.80L41.70-73L50.70-73L50.70 0L41.70 0L41.70-33.60L18.30-33.60L18.30 0Z" },
        { "I", "M49.50 0L10.50 0L10.50-8.20L25.40-8.20L25.40-64.80L10.50-64.80L10.50-73L49.50-73L49.50-64.80L34.60-64.80L34.60-8.20L49.50-8.20L49.50 0Z" },
        { "J", "M27 1L27 1Q16.50 1 10.50-4.90Q4.50-10.80 4.50-21L4.50-21L13.50-21Q13.50-14.30 17.05-10.65Q20.60-7 27-7L27-7Q33.40-7 36.95-10.65Q40.50-14.30 40.50-21L40.50-21L40.50-73L49.50-73L49.50-21Q49.50-10.80 43.45-4.90Q37.40 1 27 1Z" },
        { "K", "M18.20 0L9.20 0L9.20-73L18.20-73L18.20-41.60L29-41.60L45.20-73L55-73L36.90-37.80L56 0L45.70 0L28.70-33.70L18.20-33.70L18.20 0Z" },
        { "L", "M55 0L13 0L13-73L22-73L22-8.20L55-8.20L55 0Z" },
        { "M", "M15.90 0L7.20 0L7.20-73L20.50-73L29.80-41.40L39.50-73L52.80-73L52.80 0L44.10 0L44.10-34.50Q44.10-39.40 44.25-45.75Q44.40-52.10 44.70-58.60Q45-65.10 45.40-70.30L45.40-70.30L33.60-32.60L25.80-32.60L14.50-69.40Q15.30-62 15.60-53.20Q15.90-44.40 15.90-34.50L15.90-34.50L15.90 0Z" },
        { "N", "M17.70 0L9 0L9-73L21-73L43.30-10.50Q43.10-13 42.85-16.65Q42.60-20.30 42.45-24.35Q42.30-28.40 42.30-32L42.30-32L42.30-73L51-73L51 0L39 0L16.80-62.50Q17-60.10 17.20-56.45Q17.40-52.80 17.55-48.75Q17.70-44.70 17.70-41L17.70-41L17.70 0Z" },
        { "O", "M30 1L30 1Q20.20 1 14.50-4.70Q8.80-10.40 8.80-21L8.80-21L8.80-52Q8.80-62.60 14.50-68.30Q20.20-74 30-74L30-74Q39.80-74 45.50-68.30Q51.20-62.60 51.20-52.10L51.20-52.10L51.20-21Q51.20-10.40 45.50-4.70Q39.80 1 30 1ZM30-7.10L30-7.10Q35.90-7.10 39.05-10.45Q42.20-13.80 42.20-20L42.20-20L42.20-53Q42.20-59.20 39.05-62.55Q35.90-65.90 30-65.90L30-65.90Q24.20-65.90 21-62.55Q17.80-59.20 17.80-53L17.80-53L17.80-20Q17.80-13.80 21-10.45Q24.20-7.10 30-7.10Z" },
        { "P", "M18.20 0L9.20 0L9.20-73L32.70-73Q42.90-73 48.95-67.15Q55-61.30 55-51.50L55-51.50Q55-41.70 48.95-35.85Q42.90-30 32.70-30L32.70-30L18.20-30L18.20 0ZM18.20-64.90L18.20-38.10L32.70-38.10Q38.60-38.10 42.15-41.75Q45.70-45.40 45.70-51.50L45.70-51.50Q45.70-57.70 42.15-61.30Q38.60-64.90 32.70-64.90L32.70-64.90L18.20-64.90Z" },
        { "Q", "M52.60 18L42.20 18L31.90 0.90Q31.50 0.90 31 0.95Q30.50 1 30 1L30 1Q19.90 1 13.95-4.85Q8-10.70 8-20.50L8-20.50L8-52.50Q8-62.30 13.95-68.15Q19.90-74 30-74L30-74Q40.10-74 46.05-68.15Q52-62.30 52-52.50L52-52.50L52-20.50Q52-13.80 49.10-8.80Q46.20-3.80 40.90-1.30L40.90-1.30L52.60 18ZM30-7L30-7Q35.90-7 39.45-10.70Q43-14.40 43-20.50L43-20.50L43-52.50Q43-58.70 39.45-62.35Q35.90-66 30-66L30-66Q24.10-66 20.55-62.35Q17-58.70 17-52.50L17-52.50L17-20.50Q17-14.40 20.55-10.70Q24.10-7 30-7Z" },
        { "R", "M18.20 0L9.30 0L9.30-73L31.80-73Q38.30-73 43.20-70.35Q48.10-67.70 50.80-63Q53.50-58.30 53.50-52L53.50-52Q53.50-44.60 49.70-39.30Q45.90-34 39.60-31.90L39.60-31.90L54.50 0L44.60 0L30.30-31L18.20-31L18.20 0ZM18.20-64.90L18.20-39.10L31.80-39.10Q37.40-39.10 40.80-42.65Q44.20-46.20 44.20-52L44.20-52Q44.20-57.90 40.80-61.40Q37.40-64.90 31.80-64.90L31.80-64.90L18.20-64.90Z" },
        { "S", "M30.40 1L30.40 1Q19.80 1 13.50-4.60Q7.20-10.20 7.20-20L7.20-20L16.20-20Q16.20-13.90 20.10-10.45Q24-7 30.40-7L30.40-7Q36.60-7 40.30-10.60Q44-14.20 44-20L44-20Q44-24.40 41.65-27.65Q39.30-30.90 34.90-32.10L34.90-32.10L23.80-35.20Q16.90-37.20 12.95-42.35Q9-47.50 9-54.50L9-54.50Q9-60.30 11.60-64.70Q14.20-69.10 18.90-71.55Q23.60-74 29.70-74L29.70-74Q35.90-74 40.65-71.55Q45.40-69.10 48.10-64.75Q50.80-60.40 50.80-54.70L50.80-54.70L41.80-54.70Q41.80-59.70 38.40-62.85Q35-66 29.70-66L29.70-66Q24.40-66 21.10-62.85Q17.80-59.70 17.80-54.70L17.80-54.70Q17.80-50.70 19.95-47.85Q22.10-45 26-43.90L26-43.90L37.40-40.70Q44.70-38.70 48.75-33.15Q52.80-27.60 52.80-20L52.80-20Q52.80-10.40 46.70-4.70Q40.60 1 30.40 1Z" },
        { "T", "M34.50 0L25.50 0L25.50-64.80L5.50-64.80L5.50-73L54.50-73L54.50-64.80L34.50-64.80L34.50 0Z" },
        { "U", "M30 1L30 1Q19.80 1 14.40-4.65Q9-10.30 9-20L9-20L9-73L18-73L18-20Q18-14 20.95-10.50Q23.90-7 30-7L30-7Q36-7 39-10.50Q42-14 42-20L42-20L42-73L51-73L51-20Q51-10.20 45.65-4.60Q40.30 1 30 1Z" },
        { "V", "M36.10 0L23.80 0L5-73L14.20-73L26.70-23.30Q28-18.10 28.85-13.70Q29.70-9.30 30.10-7L30.10-7Q30.50-9.30 31.45-13.75Q32.40-18.20 33.70-23.40L33.70-23.40L45.70-73L55-73L36.10 0Z" },
        { "W", "M22 0L10.70 0L2-73L10.30-73L16-19Q16.40-15.70 16.60-12.15Q16.80-8.60 16.90-6.50L16.90-6.50Q17.10-8.60 17.45-12.15Q17.80-15.70 18.20-19L18.20-19L25.40-73L35.10-73L41.70-19Q42.10-15.70 42.50-12.15Q42.90-8.60 43.10-6.50L43.10-6.50Q43.30-8.60 43.55-12.15Q43.80-15.70 44.20-19L44.20-19L50.10-73L58-73L49.10 0L37.80 0L31.20-55Q30.80-58.40 30.60-61.65Q30.40-64.90 30.20-66.70L30.20-66.70Q30-64.90 29.80-61.65Q29.60-58.40 29.10-55L29.10-55L22 0Z" },
        { "X", "M14 0L4 0L25-37L5.10-73L15.50-73L26.80-51.40Q27.70-49.70 28.65-47.75Q29.60-45.80 30.20-44.70L30.20-44.70Q30.70-45.80 31.65-47.75Q32.60-49.70 33.50-51.40L33.50-51.40L45-73L54.90-73L35-37.60L56 0L45.70 0L33.20-23.20Q32.30-24.90 31.35-26.85Q30.40-28.80 29.90-30L29.90-30Q29.40-28.80 28.45-26.90Q27.50-25 26.60-23.30L26.60-23.30L14 0Z" },
        { "Y", "M34.50 0L25.50 0L25.50-27.30L3.50-73L13.10-73L27.30-43Q28.50-40.50 29.20-38.75Q29.90-37 30.10-36.20L30.10-36.20Q30.30-37 31.05-38.75Q31.80-40.50 33-43L33-43L47.20-73L56.50-73L34.50-27.30L34.50 0Z" },
        { "Z", "M51.50 0L8.50 0L8.50-9L41.40-64.80L9-64.80L9-73L50.50-73L50.50-64L17.60-8.20L51.50-8.20L51.50 0Z" },
        { "[", "M45 11L20.50 11L20.50-83L45-83L45-75L29.50-75L29.50 3L45 3L45 11Z" },
        { "\\", "M52.50 11L43 11L7.50-83L17-83L52.50 11Z" },
        { "]", "M39.50 11L15 11L15 3L30.50 3L30.50-75L15-75L15-83L39.50-83L39.50 11Z" },
        { "^", "M16.10-34L8-34L25.90-73L34.30-73L52-34L43.90-34L32.70-59.80Q31.90-61.80 31.25-63.65Q30.60-65.50 30.30-66.50L30.30-66.50Q29.90-65.50 29.20-63.65Q28.50-61.80 27.60-59.80L27.60-59.80L16.10-34Z" },
        { "_", "M54 10L6 10L6 2.50L54 2.50L54 10Z" },
        { "`", "M37.20-64.50L27.70-64.50L16.20-78.50L26.20-78.50L37.20-64.50Z" },
        { "a", "M25.20 1L25.20 1Q16.70 1 11.70-3.75Q6.70-8.50 6.70-16.20L6.70-16.20Q6.70-21.30 9-25.10Q11.30-28.90 15.40-31.05Q19.50-33.20 24.80-33.20L24.80-33.20L41.80-33.20L41.80-37.50Q41.80-48.20 30.10-48.20L30.10-48.20Q24.90-48.20 21.70-46.30Q18.50-44.40 18.30-41L18.30-41L9.30-41Q9.80-47.50 15.35-51.75Q20.90-56 30.10-56L30.10-56Q40.10-56 45.45-51.20Q50.80-46.40 50.80-37.80L50.80-37.80L50.80 0L41.90 0L41.90-10L41.70-10Q40.90-4.90 36.60-1.95Q32.30 1 25.20 1ZM27.40-6.60L27.40-6.60Q34-6.60 37.90-9.80Q41.80-13 41.80-18.50L41.80-18.50L41.80-26.20L25.80-26.20Q21.40-26.20 18.65-23.55Q15.90-20.90 15.90-16.50L15.90-16.50Q15.90-11.90 18.95-9.25Q22-6.60 27.40-6.60Z" },
        { "b", "M33.20 1L33.20 1Q27 1 23-2.05Q19-5.10 18.30-10.50L18.30-10.50L18.20-10.50L18.20 0L9.20 0L9.20-73L18.20-73L18.20-57L18-44.50L18.10-44.50Q18.90-49.80 22.95-52.90Q27-56 33.20-56L33.20-56Q41.50-56 46.40-50.50Q51.30-45 51.30-35.50L51.30-35.50L51.30-19.40Q51.30-10 46.40-4.50Q41.50 1 33.20 1ZM30.20-6.80L30.20-6.80Q35.90-6.80 39.10-9.80Q42.30-12.80 42.30-19.50L42.30-19.50L42.30-35.50Q42.30-42.30 39.10-45.25Q35.90-48.20 30.20-48.20L30.20-48.20Q24.70-48.20 21.45-44.70Q18.20-41.20 18.20-35L18.20-35L18.20-20Q18.20-13.80 21.45-10.30Q24.70-6.80 30.20-6.80Z" },
        { "c", "M30.80 1L30.80 1Q20.80 1 14.80-4.60Q8.80-10.20 8.80-20L8.80-20L8.80-35Q8.80-44.80 14.80-50.40Q20.80-56 30.80-56L30.80-56Q40.30-56 46.15-50.90Q52-45.80 52.30-37L52.30-37L43.30-37Q43-42.30 39.70-45.15Q36.40-48 30.80-48L30.80-48Q24.90-48 21.35-44.65Q17.80-41.30 17.80-35.10L17.80-35.10L17.80-20Q17.80-13.80 21.35-10.40Q24.90-7 30.80-7L30.80-7Q36.40-7 39.70-9.90Q43-12.80 43.30-18L43.30-18L52.30-18Q52-9.20 46.15-4.10Q40.30 1 30.80 1Z" },
        { "d", "M26.80 1L26.80 1Q18.60 1 13.65-4.50Q8.70-10 8.70-19.40L8.70-19.40L8.70-35.50Q8.70-45 13.60-50.50Q18.50-56 26.80-56L26.80-56Q33-56 37.05-52.90Q41.10-49.80 41.90-44.50L41.90-44.50L42-44.50L41.80-57L41.80-73L50.80-73L50.80 0L41.80 0L41.80-10.50L41.70-10.50Q41-5.10 37-2.05Q33 1 26.80 1ZM29.80-6.80L29.80-6.80Q35.40-6.80 38.60-10.30Q41.80-13.80 41.80-20L41.80-20L41.80-35Q41.80-41.20 38.60-44.70Q35.40-48.20 29.80-48.20L29.80-48.20Q24.10-48.20 20.90-45.25Q17.70-42.30 17.70-35.50L17.70-35.50L17.70-19.50Q17.70-12.80 20.90-9.80Q24.10-6.80 29.80-6.80Z" },
        { "e", "M30 1L30 1Q20.30 1 14.35-4.85Q8.40-10.70 8.40-21L8.40-21L8.40-34Q8.40-44.30 14.35-50.15Q20.30-56 30-56L30-56Q36.50-56 41.35-53.40Q46.20-50.80 48.90-46.10Q51.60-41.40 51.60-35L51.60-35L51.60-25.20L17.20-25.20L17.20-20Q17.20-13.90 20.70-10.35Q24.20-6.80 30-6.80L30-6.80Q35-6.80 38.25-8.75Q41.50-10.70 42.20-14L42.20-14L51.20-14Q50.30-7.10 44.50-3.05Q38.70 1 30 1ZM17.20-35L17.20-32.20L42.80-32.20L42.80-35Q42.80-41.50 39.45-45.05Q36.10-48.60 30-48.60L30-48.60Q23.90-48.60 20.55-45.05Q17.20-41.50 17.20-35L17.20-35Z" },
        { "f", "M30.50 0L21.50 0L21.50-39.30L5.50-39.30L5.50-47.50L21.50-47.50L21.50-59Q21.50-65.50 25.60-69.25Q29.70-73 36.90-73L36.90-73L53-73L53-64.80L36.90-64.80Q30.50-64.80 30.50-59L30.50-59L30.50-47.50L53-47.50L53-39.30L30.50-39.30L30.50 0Z" },
        { "g", "M31.50 18L16.10 18L16.10 9.80L31.60 9.80Q36.30 9.80 39 7.15Q41.70 4.50 41.70 0L41.70 0L41.70-5L41.90-14L41.60-14Q40.80-9.10 36.90-6.45Q33-3.80 27.10-3.80L27.10-3.80Q18.60-3.80 13.70-9.20Q8.80-14.60 8.80-24L8.80-24L8.80-35.60Q8.80-45 13.70-50.50Q18.60-56 27.10-56L27.10-56Q33-56 36.90-53.20Q40.80-50.40 41.60-45.50L41.60-45.50L41.80-45.50L41.80-55L50.70-55L50.70 0Q50.70 8.30 45.55 13.15Q40.40 18 31.50 18L31.50 18ZM29.80-11.30L29.80-11.30Q35.40-11.30 38.60-14.80Q41.80-18.30 41.80-24.50L41.80-24.50L41.80-35Q41.80-41.20 38.60-44.70Q35.40-48.20 29.80-48.20L29.80-48.20Q24.10-48.20 20.95-44.90Q17.80-41.60 17.80-36L17.80-36L17.80-23.50Q17.80-17.90 20.95-14.60Q24.10-11.30 29.80-11.30Z" },
        { "h", "M18.20 0L9.20 0L9.20-73L18.20-73L18.20-44.50L18.30-44.50Q19-50 22.80-53Q26.60-56 32.90-56L32.90-56Q41.20-56 46.10-50.90Q51-45.80 51-37L51-37L51 0L42 0L42-35.50Q42-41.70 38.85-45.05Q35.70-48.40 30.30-48.40L30.30-48.40Q24.70-48.40 21.45-44.90Q18.20-41.40 18.20-35L18.20-35L18.20 0Z" },
        { "i", "M55.50 0L8.50 0L8.50-8.20L28-8.20L28-46.80L10.50-46.80L10.50-55L37-55L37-8.20L55.50-8.20L55.50 0ZM31.50-64.90L31.50-64.90Q28.20-64.90 26.30-66.60Q24.40-68.30 24.40-71.20L24.40-71.20Q24.40-74.20 26.30-75.95Q28.20-77.70 31.50-77.70L31.50-77.70Q34.80-77.70 36.70-75.95Q38.60-74.20 38.60-71.20L38.60-71.20Q38.60-68.30 36.70-66.60Q34.80-64.90 31.50-64.90Z" },
        { "j", "M21.40 18L9 18L9 9.80L21.40 9.80Q27.60 9.80 31.05 6.40Q34.50 3 34.50-3.10L34.50-3.10L34.50-46.80L8.50-46.80L8.50-55L43.50-55L43.50-3.10Q43.50 6.60 37.50 12.30Q31.50 18 21.40 18L21.40 18ZM38-64.90L38-64.90Q34.70-64.90 32.80-66.60Q30.90-68.30 30.90-71.20L30.90-71.20Q30.90-74.20 32.80-75.95Q34.70-77.70 38-77.70L38-77.70Q41.30-77.70 43.20-75.95Q45.10-74.20 45.10-71.20L45.10-71.20Q45.10-68.30 43.20-66.60Q41.30-64.90 38-64.90Z" },
        { "k", "M18.70 0L9.70 0L9.70-73L18.70-73L18.70-32.30L29.20-32.30L44.60-55L54.90-55L37.20-28.80L55.90 0L45.40 0L29.40-24.50L18.70-24.50L18.70 0Z" },
        { "l", "M55 0L38 0Q30.70 0 26.35-4.25Q22-8.50 22-15.50L22-15.50L22-64.80L3-64.80L3-73L31-73L31-15.50Q31-12.10 32.90-10.15Q34.80-8.20 38-8.20L38-8.20L55-8.20L55 0Z" },
        { "m", "M14.40 0L6 0L6-55L13.80-55L13.80-47.70L14-47.70Q14.50-51.40 16.95-53.70Q19.40-56 23.20-56L23.20-56Q26.80-56 29.30-53.90Q31.80-51.80 32.90-48.20L32.90-48.20L33-48.20Q33.70-51.80 36.15-53.90Q38.60-56 42.40-56L42.40-56Q47.70-56 50.85-52.05Q54-48.10 54-41.80L54-41.80L54 0L45.60 0L45.60-41.90Q45.60-45.20 44-47.15Q42.40-49.10 39.60-49.10L39.60-49.10Q36.90-49.10 35.30-47.20Q33.70-45.30 33.70-42L33.70-42L33.70 0L26.30 0L26.30-41.90Q26.30-45.20 24.70-47.15Q23.10-49.10 20.40-49.10L20.40-49.10Q17.60-49.10 16-47.20Q14.40-45.30 14.40-42L14.40-42L14.40 0Z" },
        { "n", "M18.20 0L9.20 0L9.20-55L18.20-55L18.20-44.50L18.30-44.50Q19-50 22.80-53Q26.60-56 32.90-56L32.90-56Q41.20-56 46.10-50.90Q51-45.80 51-37L51-37L51 0L42 0L42-35.40Q42-41.70 38.85-45.05Q35.70-48.40 30.30-48.40L30.30-48.40Q24.70-48.40 21.45-44.90Q18.20-41.40 18.20-35L18.20-35L18.20 0Z" },
        { "o", "M30 0.80L30 0.80Q20.10 0.80 14.25-5Q8.40-10.80 8.40-21.20L8.40-21.20L8.40-33.80Q8.40-44.30 14.20-50.05Q20-55.80 30-55.80L30-55.80Q40-55.80 45.80-50.05Q51.60-44.30 51.60-33.80L51.60-33.80L51.60-21.20Q51.60-10.80 45.75-5Q39.90 0.80 30 0.80ZM30-7.20L30-7.20Q35.90-7.20 39.25-10.50Q42.60-13.80 42.60-20.20L42.60-20.20L42.60-34.80Q42.60-41.20 39.25-44.50Q35.90-47.80 30-47.80L30-47.80Q24.20-47.80 20.80-44.50Q17.40-41.20 17.40-34.80L17.40-34.80L17.40-20.20Q17.40-13.80 20.80-10.50Q24.20-7.20 30-7.20Z" },
        { "p", "M18.20 18L9.20 18L9.20-55L18.20-55L18.20-44.50L18.30-44.50Q19-49.90 23-52.95Q27-56 33.20-56L33.20-56Q41.50-56 46.40-50.55Q51.30-45.10 51.30-35.60L51.30-35.60L51.30-19.50Q51.30-10 46.40-4.50Q41.50 1 33.20 1L33.20 1Q27 1 23-2.10Q19-5.20 18.30-10.50L18.30-10.50L18-10.50L18.20 2L18.20 18ZM30.20-6.80L30.20-6.80Q35.90-6.80 39.10-9.80Q42.30-12.80 42.30-19.50L42.30-19.50L42.30-35.50Q42.30-42.30 39.10-45.25Q35.90-48.20 30.20-48.20L30.20-48.20Q24.70-48.20 21.45-44.70Q18.20-41.20 18.20-35L18.20-35L18.20-20Q18.20-13.80 21.45-10.30Q24.70-6.80 30.20-6.80Z" },
        { "q", "M50.80 18L41.80 18L41.80 2L42-10.50L41.70-10.50Q41-5.20 37-2.10Q33 1 26.80 1L26.80 1Q18.50 1 13.60-4.50Q8.70-10 8.70-19.50L8.70-19.50L8.70-35.60Q8.70-45.10 13.65-50.55Q18.60-56 26.80-56L26.80-56Q33-56 37-52.95Q41-49.90 41.70-44.50L41.70-44.50L41.80-44.50L41.80-55L50.80-55L50.80 18ZM29.80-6.80L29.80-6.80Q35.40-6.80 38.60-10.30Q41.80-13.80 41.80-20L41.80-20L41.80-35Q41.80-41.20 38.60-44.70Q35.40-48.20 29.80-48.20L29.80-48.20Q24.10-48.20 20.90-45.30Q17.70-42.40 17.70-36L17.70-36L17.70-19Q17.70-12.60 20.90-9.70Q24.10-6.80 29.80-6.80Z" },
        { "r", "M20.20 0L11.20 0L11.20-55L20.20-55L20.20-44.50L20.40-44.50Q21.10-49.80 24.90-52.90Q28.70-56 35.10-56L35.10-56Q43.70-56 48.35-50.85Q53-45.70 53-36.20L53-36.20L53-31.50L44-31.50L44-36.20Q44-48.20 32.30-48.20L32.30-48.20Q26.40-48.20 23.30-44.80Q20.20-41.40 20.20-35L20.20-35L20.20 0Z" },
        { "s", "M32.20 0.80L27.80 0.80Q18.60 0.80 13.55-3.35Q8.50-7.50 8.50-15.10L8.50-15.10L17.50-15.10Q17.50-11.30 20.20-9.15Q22.90-7 27.80-7L27.80-7L32.20-7Q37.20-7 39.95-9.20Q42.70-11.40 42.70-15.40L42.70-15.40Q42.70-22.50 36.20-23.40L36.20-23.40L21-25.60Q15.40-26.40 12.30-30.25Q9.20-34.10 9.20-40.40L9.20-40.40Q9.20-47.60 14.15-51.70Q19.10-55.80 27.80-55.80L27.80-55.80L32.20-55.80Q40.20-55.80 45.25-51.85Q50.30-47.90 50.70-41.50L50.70-41.50L41.60-41.50Q41.40-44.40 38.85-46.30Q36.30-48.20 32.20-48.20L32.20-48.20L27.80-48.20Q23.20-48.20 20.60-46.10Q18-44 18-40.40L18-40.40Q18-34.60 23.30-33.80L23.30-33.80L37.50-31.80Q51.50-29.80 51.50-15.40L51.50-15.40Q51.50-7.70 46.45-3.45Q41.40 0.80 32.20 0.80L32.20 0.80Z" },
        { "t", "M51.50 0L35.50 0Q28.70 0 24.60-3.95Q20.50-7.90 20.50-14.50L20.50-14.50L20.50-46.80L4.70-46.80L4.70-55L20.50-55L20.50-70.50L29.50-70.50L29.50-55L52-55L52-46.80L29.50-46.80L29.50-14.50Q29.50-11.70 31.15-9.95Q32.80-8.20 35.50-8.20L35.50-8.20L51.50-8.20L51.50 0Z" },
        { "u", "M29.90 1L29.90 1Q20.40 1 14.70-4.65Q9-10.30 9-20L9-20L9-55L18-55L18-20Q18-14 21.20-10.45Q24.40-6.90 29.90-6.90L29.90-6.90Q35.50-6.90 38.75-10.45Q42-14 42-20L42-20L42-55L51-55L51-20Q51-10.30 45.20-4.65Q39.40 1 29.90 1Z" },
        { "v", "M35.90 0L24.10 0L5.40-55L15.10-55L27.10-18Q28.20-14.70 29-11.65Q29.80-8.60 30.20-6.90L30.20-6.90Q30.70-8.60 31.40-11.65Q32.10-14.70 33.10-18L33.10-18L45.10-55L54.60-55L35.90 0Z" },
        { "w", "M22 0L12.10 0L3.10-55L10.90-55L16.50-16.20Q16.80-14 17.10-11.35Q17.40-8.70 17.50-7L17.50-7Q17.70-8.70 17.95-11.35Q18.20-14 18.60-16.20L18.60-16.20L25.50-55L34.50-55L41.40-16.20Q41.80-14 42.15-11.35Q42.50-8.70 42.60-7L42.60-7Q42.80-8.70 43.10-11.35Q43.40-14 43.70-16.20L43.70-16.20L49.50-55L56.90-55L47.50 0L37.60 0L31.30-38Q30.90-40.80 30.55-43.95Q30.20-47.10 30-48.80L30-48.80Q29.90-47.10 29.50-43.95Q29.10-40.80 28.60-38L28.60-38L22 0Z" },
        { "x", "M15.60 0L5 0L24.50-28.30L6.20-55L16.80-55L27.70-38Q28.40-36.90 29.05-35.60Q29.70-34.30 30.10-33.50L30.10-33.50Q30.40-34.30 31.05-35.60Q31.70-36.90 32.40-38L32.40-38L43.30-55L53.90-55L35.60-28.20L55 0L44.40 0L32.60-18Q31.90-19.10 31.25-20.55Q30.60-22 30.10-22.90L30.10-22.90Q29.70-22 28.95-20.55Q28.20-19.10 27.40-18L27.40-18L15.60 0Z" },
        { "y", "M27.20 18L17.80 18L25.90-3.40L5.40-55L15.10-55L28.10-21Q28.90-19 29.60-16.80Q30.30-14.60 30.60-13L30.60-13Q30.90-14.60 31.60-16.80Q32.30-19 33-21L33-21L45.10-55L54.60-55L27.20 18Z" },
        { "z", "M51 0L9 0L9-9L39.80-46.80L9.80-46.80L9.80-55L49.90-55L49.90-46L18.50-8.20L51-8.20L51 0Z" },
        { "{", "M50.50 11L46 11Q37.20 11 32 6.65Q26.80 2.30 27.50-5.60L27.50-5.60L29-22Q29.50-27.30 27.50-29.65Q25.50-32 19-32L19-32L7.50-32L7.50-40L19-40Q25.50-40 27.50-42.35Q29.50-44.70 29-50L29-50L27.50-66.40Q26.80-74.30 32-78.65Q37.20-83 46-83L46-83L50.50-83L50.50-75L46-75Q41.30-75 38.70-72.85Q36.10-70.70 36.50-66.40L36.50-66.40L38-50Q38.50-44.10 35.20-40.55Q31.90-37 24.40-36.30L24.40-36.30Q31.90-35.60 35.20-31.70Q38.50-27.80 38-22L38-22L36.50-5.60Q36.10-1.30 38.70 0.85Q41.30 3 46 3L46 3L50.50 3L50.50 11Z" },
        { "|", "M34.50 11L25.50 11L25.50-83L34.50-83L34.50 11Z" },
        { "}", "M14 11L9.50 11L9.50 3L14 3Q18.70 3 21.45 0.85Q24.20-1.30 23.50-5.60L23.50-5.60L21-22Q20.10-27.70 23-31.65Q25.90-35.60 31-36.50L31-36.50Q25.90-37.30 23-40.80Q20.10-44.30 21-50L21-50L23.50-66.40Q24.20-70.70 21.45-72.85Q18.70-75 14-75L14-75L9.50-75L9.50-83L14-83Q19.90-83 24.35-81.05Q28.80-79.10 31.05-75.40Q33.30-71.70 32.50-66.40L32.50-66.40L30-50Q29.20-44.70 31.35-42.35Q33.50-40 40-40L40-40L52.50-40L52.50-32L40-32Q33.60-32 31.40-29.65Q29.20-27.30 30-22L30-22L32.50-5.60Q33.30-0.40 31.05 3.35Q28.80 7.10 24.35 9.05Q19.90 11 14 11L14 11Z" },
        { "~", "M15.50-25.50L7-25.50L7-32.50Q7-38.40 10.60-41.95Q14.20-45.50 20-45.50L20-45.50Q23.70-45.50 26.20-44.20Q28.70-42.90 30.40-40.95Q32.10-39 33.45-37.05Q34.80-35.10 36.30-33.80Q37.80-32.50 39.80-32.50L39.80-32.50Q44.50-32.50 44.50-38L44.50-38L44.50-45L53-45L53-38Q53-32.20 49.45-28.60Q45.90-25 40-25L40-25Q36.30-25 33.80-26.30Q31.30-27.60 29.60-29.55Q27.90-31.50 26.55-33.45Q25.20-35.40 23.70-36.70Q22.20-38 20.20-38L20.20-38Q15.50-38 15.50-32.50L15.50-32.50L15.50-25.50Z" },
        { NULL, NULL }
    };

    int font_chars_length = 0;
    for (int index = 0; font_chars[index][0] != NULL; index++) {
        font_chars_length++;
    }

    int* draw_chr(char chr, int x, int y, float size, int* screen_) {
        //Check if char is in font_chars
        bool found = false;
        char* svgToChr = malloc(1 * sizeof(char));
        for (int index = 0; index < font_chars_length; index++) {
            if (font_chars[index][0][0] == chr){
                found = true;

                //Copy svg of char to svgToChar with dynamic memory scaling...
                int subindex;
                for (subindex = 0; font_chars[index][1][subindex] != '\0'; subindex++){
                    char* tmp = realloc(svgToChr, subindex + 2);
                    if (!tmp) { 
                        free(svgToChr); 
                        return NULL;
                    }
                    svgToChr = tmp;
                    svgToChr[subindex] = font_chars[index][1][subindex];
                }
                svgToChr[subindex] = '\0';

                break;
            }
        }
        
        //If char doesn't exist in font.
        if (!found){
            free(svgToChr);
            return NULL;
        }

        //Check if size is correct
        if (!(size > 0)){
            free(svgToChr);
            return NULL;
        }

        //Check pos
        if (x < 0 || x >= (int)screen_w){
            free(svgToChr);
            return NULL;
        }

        if (y < 0 || y >= (int)screen_h){
            free(svgToChr);
            return NULL;
        }

        if (screen_[0] < screen_w || screen_[0] > screen_w){
            free(svgToChr);
            return NULL;
        }
        
        if (screen_[1] < screen_h || screen_[1] > screen_h){
            free(svgToChr);
            return NULL;
        }

        //Raster char
        int* bmap = svg_to_bitmap((int)(16 * size + 0.5f), (int)(24 * size + 0.5f), svgToChr);

        //Post processing (fill char)
        /* ------------- robust glyph interior fill (edge flood-fill) ------------ */
        int W = bmap[0];
        int H = bmap[1];
        int N = W * H;                      /* total pixel count (no metadata)    */

        /* mark[i] = 0 → unvisited background
        mark[i] = 1 → background reachable from the border (outside)          */
        unsigned char *mark = (unsigned char *)malloc(N);
        for (int i = 0; i < N; i++) {
            mark[i] = 0;
        }

        /* simple FIFO queue for the flood-fill */
        int *queue = (int *)malloc(N * sizeof(int));
        int head = 0;
        int tail = 0;

        /* helper to push a pixel index into the queue if it is background */
        void push_if_bg(int idx) {
            long o = 2 + (long)idx * 3;
            int bg = (bmap[o] | bmap[o + 1] | bmap[o + 2]) == 0;
            if (bg && mark[idx] == 0) {
                mark[idx] = 1;
                queue[tail++] = idx;
            }
        }

        /* seed the flood-fill with every transparent border pixel */
        for (int x = 0; x < W; x++) {
            push_if_bg(x);
            push_if_bg((H - 1) * W + x);
        }
        for (int y = 0; y < H; y++) {
            push_if_bg(y * W);
            push_if_bg(y * W + (W - 1));
        }

        /* breadth-first flood-fill of the outside region */
        while (head < tail) {
            int p  = queue[head++];
            int py = p / W;
            int px = p - py * W;

            if (px > 0)          push_if_bg(p - 1);
            if (px < W - 1)      push_if_bg(p + 1);
            if (py > 0)          push_if_bg(p - W);
            if (py < H - 1)      push_if_bg(p + W);
        }

        /* every background pixel NOT reachable from the border is inside → fill */
        for (int i = 0; i < N; i++) {
            if (mark[i] == 0) {
                long o = 2 + (long)i * 3;
                if ((bmap[o] | bmap[o + 1] | bmap[o + 2]) == 0) {
                    bmap[o]     = 255;
                    bmap[o + 1] = 255;
                    bmap[o + 2] = 255;
                }
            }
        }

        free(queue);
        free(mark);
        /* ---------------------------------------------------------------------- */

        free(svgToChr);

        if (!bmap){
            return NULL;
        }

        for (int index = 0; index < bmap[0] * bmap[1]; index++) {
            int r = bmap[2 + index * 3 + 0];
            int g = bmap[2 + index * 3 + 1];
            int b = bmap[2 + index * 3 + 2];
            int px = x + (index % bmap[0]);
            int py = y + (index / bmap[0]);

            //Repeat the pos checks here in case something happens.
            if (px < 0 || px >= (int)screen_w){
                continue;
            }

            if (py < 0 || py >= (int)screen_h){
                continue;
            }

            screen_[2 + ((py * screen_[0] + px) * 3)] = r;
            screen_[2 + ((py * screen_[0] + px) * 3) + 1] = g;
            screen_[2 + ((py * screen_[0] + px) * 3) + 2] = b;
        }
        
        free(bmap);
        return screen_;
    }

    //Frame render function, this makes sure that the things we wanna draw are 
    //already rendered before we begin rendering them which prevents flicker.
    int render_frame(int* bmap){
        //Size checks
        if (bmap[0] > screen_w){
            //Frame too wide
            return -1;
        }
        if (bmap[1] > screen_h){
            //Frame too tall
            return -1;
        }
        if (bmap[0] < screen_w){
            //Frame too small
            return -1;
        }
        if (bmap[1] < screen_h){
            //Frame too small
            return -1;
        }

        for (int index = 0; index < bmap[0] * bmap[1]; index++) {
            int r = bmap[2 + index * 3 + 0];
            int g = bmap[2 + index * 3 + 1];
            int b = bmap[2 + index * 3 + 2];
            int px = index % bmap[0];
            int py = index / bmap[0];

            pixel(px, py, rgb(r, g, b));
        }

        for (int i = 0; i < bmap[0] * bmap[1] * 3; i++) {
            bmap[2 + i] = 0; // clear the screen (skip width/height metadata)
        }

        return 0;
    }

    //Init screen
    int *screen = malloc(sizeof(int) * (2 + screen_h * screen_w * 3));

    screen[0] = screen_w;
    screen[1] = screen_h;

    for (int index = 2; index < (screen[0] * screen[1] * 3); index++){
        screen[index] = 0;
    }
    
    //Cool test
    char* scrollback = malloc(1);
    scrollback[0] = '\0';
    int scrollback_cursor = 0;
    int scrollback_size = 0;

    void refresh_scrollback_render(){
        int column = 0;
        int row = 0;
        int skiprow = 0;
        int howmanycharsinarow = 0;
        for (int index = 0; !(scrollback[index] == '\0'); index++){
            int x_char = (int)(screen_w / 50 + (column * 16));
            int y_char = (int)(24 * row);

            if (x_char + 16 > screen_w){
                column = 0;
                row++;
                if (!howmanycharsinarow){
                    howmanycharsinarow = index;
                }
                if ((int)(24 * row) > screen_h){
                    skiprow++;
                }
            }

            if (row >= skiprow){
                draw_chr(scrollback[index], 16 * column, 24 * (row - skiprow), 1, screen);
            }

            column++;
        }
    }

    void print(char* text){
        int text_len;
        for (text_len = 0; !(text[text_len] == '\0'); text_len++){}

        scrollback = realloc(scrollback, scrollback_size + text_len + 1);
        for (int index = 0; index < text_len; index++){
            scrollback[scrollback_size + index] = text[index];
        }
        scrollback[scrollback_size + text_len] = '\0';

        scrollback_size += text_len;

        refresh_scrollback_render();
        render_frame(screen);
    }

    while (true){
        for (int index = 0; index < font_chars_length; index++){
            print(font_chars[index][0]);
        }
    }

    for (;;) __asm__("cli; hlt"); 
}