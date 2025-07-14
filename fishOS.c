#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

//Jetbrains mono regular (utf8) + noto svg emojis (all)
#include "font_chars.c"

#ifdef __builtin_memcpy
#undef memcpy
#endif
#ifdef __builtin_memset
#undef memset
#endif
#ifdef __builtin_memmove
#undef memmove
#endif

void *malloc (uint32_t n);
void  free   (void *ptr);
void *realloc(void *ptr, uint32_t n);

uint64_t __stack_chk_guard = 0xdeadbeef;

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

#define SLAB_MAX        512
#define SLAB_CHUNK_SIZE (64 * 1024) //IF YOU SET THIS BELOW 64KB (64 * 1024) EVERYTHING WILL EXPLODE
#define SLAB_CLASSES    6

static const uint16_t slab_sz[SLAB_CLASSES] = {16, 32, 64, 128, 256, 512};

typedef struct slab_chunk {
    struct slab_chunk *next;
    uint16_t used;
    uint16_t obj_sz;
    uint8_t *free_list;
} slab_chunk_t;

typedef struct {
    slab_chunk_t *chunk;
    uint32_t      req_sz;
    uint32_t      pad;
} slab_hdr_t;
#define SLAB_HDR  sizeof(slab_hdr_t)

static slab_chunk_t *slab_cache[SLAB_CLASSES];

static inline void* v2p(uint64_t v);

static inline int slab_class(uint32_t n){
    for (int i = 0; i < SLAB_CLASSES; ++i)
        if (n <= slab_sz[i]) return i;
    return -1;
}

static slab_chunk_t *slab_new_chunk(int cls){
    uint32_t need = sizeof(slab_chunk_t) + SLAB_CHUNK_SIZE;
    slab_chunk_t *c = (slab_chunk_t*)malloc(need);
    if (!c) return 0;

    c->obj_sz   = slab_sz[cls];
    c->used     = 0;
    c->next            = slab_cache[cls];
    slab_cache[cls]    = c;

    uint32_t slot = ALIGN8(c->obj_sz + SLAB_HDR);
    uint8_t *start = (uint8_t*)(c + 1);
    uint8_t *p     = start;
    while (p + slot <= start + SLAB_CHUNK_SIZE) {
        *(uint8_t**)p = p + slot;
        p += slot;
    }
    *(uint8_t**)(p - slot) = 0;
    c->free_list = start;
    return c;
}

static void *slab_alloc(uint32_t n){
    int cls = slab_class(n);
    if (cls < 0) return 0;

    slab_chunk_t *c = slab_cache[cls];
    while (c && !c->free_list)
        c = c->next;

    if (!c) {
        c = slab_new_chunk(cls);
        if (!c) return 0;
    }

    uint8_t *obj = c->free_list;
    c->free_list = *(uint8_t**)obj;
    c->used++;

    slab_hdr_t *h = (slab_hdr_t*)obj;
    h->chunk  = c;
    h->req_sz = n;

    return obj + SLAB_HDR;
}

static bool slab_free(void *ptr){
    if (!ptr) return false;

    uint8_t      *raw = (uint8_t*)ptr - SLAB_HDR;
    slab_chunk_t *c   = *(slab_chunk_t**)raw;
    if (!c || !v2p((uint64_t)c) ||
        c->obj_sz > SLAB_MAX ||
        (uint8_t*)ptr - (uint8_t*)(c + 1) >= SLAB_CHUNK_SIZE)
        return false;

    uint8_t *obj = raw;
    *(uint8_t**)obj = c->free_list;
    c->free_list   = obj;
    if (--c->used == 0) {
        int cls = slab_class(c->obj_sz);
        slab_chunk_t **pp = &slab_cache[cls];
        while (*pp && *pp != c) pp = &(*pp)->next;
        if (*pp) *pp = c->next;
        free(c);
    }
    return true;
}

typedef struct blk { 
    uint32_t size_flags; struct blk* next,*prev; 
} blk_t;

#define MAX_REGIONS 32
typedef struct { 
    uint64_t p,v,sz; 
} region_t;
static region_t region[MAX_REGIONS]; 
static int n_region;

static blk_t *bin_tiny,*bin_small,*bin_big;
static blk_t *rov_tiny,*rov_small,*rov_big;

static uint8_t *bump_base,*bump_top,*bump_end;

static uint64_t heap_base = 0;

__attribute__((noreturn)) void PANIC(void){
    draw_rect(0, 0, screen_w, screen_h, rgb(0, 0, 255));
    for(;;) __asm__("cli; hlt");
}
#define ASSERT(c) do { if(!(c)) PANIC(); } while(0)

void __attribute__((noreturn)) __stack_chk_fail(void) { 
    PANIC(); 
}

static inline void verify(blk_t *b) {
    uint32_t sz = b->size_flags & SIZE_MASK;

    ASSERT(sz >= MIN_PAYLOAD_FREE && ((uintptr_t)b & 7u) == 0);

    uint32_t *foot = (uint32_t *)((uint8_t *)b + 4 + sz);
    ASSERT(*foot == sz);

    if (b->size_flags & FLAG_USED)
        ASSERT(b->next == NULL && b->prev == NULL);
}

static inline bool is_valid_block(blk_t *b) {
    if (!b) return false;

    if (((uintptr_t)b & 7u) != 0) return false;

    uint32_t sz = b->size_flags & SIZE_MASK;

    if (sz < MIN_PAYLOAD_FREE || sz > 0x10000000) { //Once i fix some other stuff remove that
        return false;
    }

    uint64_t footer_addr = (uint64_t)b + 4 + sz;

    bool footer_is_valid = false;
    for (int i = 0; i < n_region; ++i) {
        if (footer_addr >= region[i].p && footer_addr < (region[i].p + region[i].sz)) {
            footer_is_valid = true;
            break;
        }
    }
    
    if (!footer_is_valid) {
        return false;
    }

    uint32_t *foot = (uint32_t *)footer_addr;
    return *foot == sz;
}

static void heap_selftest(void) {
    void *a = malloc(24);
    void *b = malloc(24);
    free(a);
    void *c = malloc(24);
    ASSERT(c == a);
    free(b); 
    free(c);
}

static inline void *memset(void *dst, int val, size_t n){
    uint8_t *d = (uint8_t*)dst;
    while (n--) *d++ = (uint8_t)val;
    return dst;
}

static inline void *memmove(void *dst, const void *src, size_t n){
    uint8_t *d = (uint8_t*)dst;
    const uint8_t *s = (const uint8_t*)src;

    if (s < d && d < s + n) {
        d += n;  s += n;
        while (n--) *--d = *--s;
    } 
    else {
        while (n--) *d++ = *s++;
    }
    return dst;
}

static inline void *memcpy(void *dst, const void *src, size_t n){
    return memmove(dst, src, n);
}

#define NBUCKETS 32
static blk_t *bins[NBUCKETS];
static blk_t *rover[NBUCKETS];

static inline int bucket_index(uint32_t sz) {
    if (sz <= 32) return 0;
    int i = 1;
    sz >>= 6;
    while (sz) { sz >>= 1; i++; }
    return (i >= NBUCKETS) ? NBUCKETS - 1 : i;
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

static inline void put_footer(blk_t *b) {
    uint64_t v_block_start = p2v(b);
    if (v_block_start == 0) PANIC();

    uint64_t v_footer_addr = v_block_start + 4 + (b->size_flags & SIZE_MASK);

    if (v2p(v_footer_addr) == 0) PANIC();

    *(uint32_t*)v2p(v_footer_addr) = b->size_flags & SIZE_MASK;
}

static inline blk_t** pick_bin(uint32_t sz, blk_t ***rover_out) {
    int i = bucket_index(sz);
    *rover_out = &rover[i];
    return &bins[i];
}
static inline void list_push(blk_t *b){
    blk_t **rov,**head=pick_bin(b->size_flags&SIZE_MASK,&rov);
    b->prev=0; b->next=*head; if(*head) (*head)->prev=b; *head=b;
    if(!*rov) *rov=b;
}
static inline void list_remove(blk_t *b){
    blk_t **rov,**head=pick_bin(b->size_flags&SIZE_MASK,&rov);
    if(b->prev) b->prev->next=b->next; else *head=b->next;
    if(b->next) b->next->prev=b->prev;
    if(*rov==b) *rov=b->next?b->next:*head;
}

#define absf(x) ((x) < 0 ? -(x) : (x))

static void heap_init(void){
    extern char _kernel_end;

    uint64_t heap_start = ((uint64_t)&_kernel_end + 7) & ~7ULL;
    heap_base = heap_start;

    int r = -1;
    for (int i = 0; i < n_region; ++i){
        if (heap_start >= region[i].p && heap_start <  region[i].p + region[i].sz) { 
            r = i; 
            break;
        }
    }
    ASSERT(r >= 0);

    blk_t *b = (blk_t*)heap_start;
    uint64_t avail = region[r].p + region[r].sz - heap_start;
    ASSERT(avail > MIN_FREE_BLOCK);

    b->size_flags = (uint32_t)(avail - HEADER_FOOTER);
    ASSERT((b->size_flags & SIZE_MASK) >= MIN_PAYLOAD_FREE);
    put_footer(b);
    int i = bucket_index(b->size_flags & SIZE_MASK);
    bins[i] = rover[i] = b;
    b->next = b->prev = 0;
}

void *malloc(uint32_t n){
    if(!n) return 0;

    if (n && n <= SLAB_MAX) {
        void *s = slab_alloc(n);
        if (s) return s;
    }

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

    int idx = bucket_index(sz);
    blk_t *best = 0;
    uint32_t best_sz = ~0u;

    for (blk_t *cur = bins[idx]; cur; cur = cur->next) {
        uint32_t csz = cur->size_flags & SIZE_MASK;
        if (csz >= sz && csz < best_sz) {
            best = cur;
            best_sz = csz;
        }
    }
    if (!best) {
        for (int i = idx + 1; i < NBUCKETS; ++i) {
            for (blk_t *cur = bins[i]; cur; cur = cur->next) {
                uint32_t csz = cur->size_flags & SIZE_MASK;
                if (csz >= sz && csz < best_sz) {
                    best = cur;
                    best_sz = csz;
                }
            }
            if (best) break;
        }

        if (!best) {
            for (int i = idx - 1; i >= 0; --i) {
                for (blk_t *cur = bins[i]; cur; cur = cur->next) {
                    uint32_t csz = cur->size_flags & SIZE_MASK;
                    if (csz >= sz && csz < best_sz) {
                        best = cur;
                        best_sz = csz;
                    }
                }
                if (best) break;
            }
        }
    }

    blk_t **rov = &rover[bucket_index(best_sz)];
    blk_t **bin = &bins[bucket_index(best_sz)];

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
       put_footer(best);
    }


    return (uint8_t*)best + 4;
}

void free(void *ptr) {
    if (!ptr) return;

    if (slab_free(ptr)) return;

    if (ptr >= (void*)bump_base && ptr < (void*)bump_end) {
        uint8_t *hdr = (uint8_t*)ptr - 4;
        uint32_t psz = *(uint32_t*)hdr & SIZE_MASK;
        if (hdr + HEADER_FOOTER + psz == bump_top)
            bump_top = hdr;
        return;
    }

    blk_t *b = (blk_t*)((uint8_t*)ptr - 4);
    b->size_flags &= SIZE_MASK;
    put_footer(b);

    uint64_t v_b = p2v(b);
    uint64_t v_r = v_b + HEADER_FOOTER + (b->size_flags & SIZE_MASK);
    blk_t   *r   = (blk_t*)v2p(v_r);
    if (is_valid_block(r) && !(r->size_flags & FLAG_USED)) {
        list_remove(r);
        b->size_flags += HEADER_FOOTER + (r->size_flags & SIZE_MASK);
        put_footer(b);
    }

    if (v_b > heap_base && v2p(v_b - 4)) { 
        uint32_t psz = *(((uint32_t*)b) - 1) & SIZE_MASK;
        if (psz > 0 && psz < 0x10000000) { //Once i fix some other stuff remove that
            uint64_t v_l = v_b - HEADER_FOOTER - psz;
            blk_t *l = (blk_t*)v2p(v_l);
            if (is_valid_block(l) && !(l->size_flags & FLAG_USED)) {
                list_remove(l);
                l->size_flags += HEADER_FOOTER + (b->size_flags & SIZE_MASK);
                put_footer(l);
                b = l;
            }
        }
    }
    list_push(b);
}

void *realloc(void *old, uint32_t n) {
    if (!old) return malloc(n);
    if (!n) { 
        free(old);
        return 0; 
    }

    slab_hdr_t *h = (slab_hdr_t*)((uint8_t*)old - SLAB_HDR);
    slab_chunk_t *chunk = h->chunk;

    if (chunk && v2p((uint64_t)chunk) &&
        chunk->obj_sz > 0 && chunk->obj_sz <= SLAB_MAX &&
        (uint8_t*)old >= (uint8_t*)(chunk + 1) &&
        (uint8_t*)old < (uint8_t*)(chunk + 1) + SLAB_CHUNK_SIZE) {
        if (n <= chunk->obj_sz) {
            h->req_sz = n;
            return old;
        }

        void *nu = malloc(n);
        if (!nu) return 0;
        memcpy(nu, old, h->req_sz);
        slab_free(old);
        return nu;
    }

    blk_t *b = (blk_t*)((uint8_t*)old - 4);
    uint32_t cur = b->size_flags & SIZE_MASK;
    uint32_t need = ALIGN8(n);
    if (need < MIN_PAYLOAD_FREE) need = MIN_PAYLOAD_FREE;

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
        return old;
    }
    
    uint64_t v_b_realloc = p2v(b);
    uint64_t v_r_realloc = v_b_realloc + HEADER_FOOTER + cur;
    blk_t *r = (blk_t*)v2p(v_r_realloc);

    if (is_valid_block(r) && !(r->size_flags & FLAG_USED)) {
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
            return old;
        }
    }

    void *nu = malloc(n);
    if (!nu) return 0;

    uint32_t copy_size = (cur < n) ? cur : n;
    memcpy(nu, old, copy_size);

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
            ASSERT(n_region < MAX_REGIONS);
            region[n_region++] = (region_t){ (uint64_t)bump_base,
                                            (uint64_t)bump_base,
                                            bump_sz };
            big_len  -= bump_sz;
        }
    }
    
    if (big_len) {
        ASSERT(n_region < MAX_REGIONS);
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
                    region[n_region++] = (region_t){ e->base, e->base, e->len };
                }
        }
    heap_init();
    heap_selftest();
    //Actual code starts here
    //

    float parse_float(const char *s) {
        float result = 0.0f;
        int sign = 1;

        // Skip whitespace
        while (*s == ' ' || *s == '\t') s++;

        // Optional sign
        if (*s == '-') {
            sign = -1;
            s++;
        } else if (*s == '+') {
            s++;
        }

        // Parse integer part
        while (*s >= '0' && *s <= '9') {
            result = result * 10.0f + (*s - '0');
            s++;
        }

        // Parse fractional part
        if (*s == '.') {
            s++;
            float frac = 0.0f;
            float base = 0.1f;
            while (*s >= '0' && *s <= '9') {
                frac += (*s - '0') * base;
                base *= 0.1f;
                s++;
            }
            result += frac;
        }

        return result * sign;
    }

    int *char2bitmap(int target_w, int target_h, const char *svg, const int *color, bool do_fill){
        bool is_space(char c){ return c==' '||c=='\t'||c=='\n'||c=='\r'; }
        bool is_digit(char c){ return c>='0'&&c<='9'; }
        bool is_alpha(char c){ return (c>='A'&&c<='Z')||(c>='a'&&c<='z'); }
        char to_upper(char c){ return (c>='a'&&c<='z')?(char)(c-'a'+'A'):c; }

        const char* find_char(const char* s, char ch){ 
            while(*s&&*s!=ch) ++s; return *s ? s : 0; 
        }

        const char* find_token(const char* s, const char* tok, const char* lim){
            size_t L=0; while(tok[L]) ++L;
            while(*s && (!lim || s<lim)){
                size_t i=0; while(i<L && s[i]==tok[i]) ++i;
                if(i==L) return s;
                ++s;
            }
            return 0;
        }

        int parse_int(const char **ps){
            const char *p=*ps; int sign=1,val=0;
            if(*p=='-'||*p=='+'){ if(*p=='-') sign=-1; ++p; }
            while(is_digit(*p)){ val=val*10+(*p-'0'); ++p; }
            *ps=p; return sign*val;
        }

        typedef struct{ 
            float x0,y0,x1,y1; 
        } Edge;
        typedef struct Path{
            Edge*e; 
            int ec,cap; 
            int r,g,b; 
            struct Path*next; 
        } Path;

        void edge_add(Path*p, float x0, float y0, float x1, float y1){
            if(p->ec == p->cap){
                p->cap = p->cap ? p->cap*2 : 16;
                p->e = (Edge*)realloc(p->e,(size_t)p->cap*sizeof *p->e);
            }
            p->e[p->ec++] = (Edge){x0,y0,x1,y1};
        }

        void skip_ws(const char **ps){
            while(**ps && (is_space(**ps)||**ps==',')) ++(*ps); 
        }

        float next_f(const char **ps){
            char buf[64]; int n=0;
            const char *p=*ps;
            if(*p=='-'||*p=='+') buf[n++]=*p++;
            while(1){
                char c=*p;
                if(is_digit(c)||c=='.'){ buf[n++]=c; ++p; continue; }
                if((c=='e'||c=='E') && (p[1]=='+'||p[1]=='-'||is_digit(p[1]))){
                    buf[n++]=c; ++p; buf[n++]=*p++; continue;
                }
                break;
            }
            buf[n]=0; *ps=p;
            return parse_float(buf);
        }

        const float DT = 0.01f;
        void quad(Path*p, float x0, float y0, float x1, float y1, float x2, float y2){
            float px=x0,py=y0;
            for(float t=DT;t<=1.0f+1e-4f;t+=DT){
                float u=1.0f-t;
                float x=u*u*x0+2*u*t*x1+t*t*x2;
                float y=u*u*y0+2*u*t*y1+t*t*y2;
                edge_add(p,px,py,x,y); px=x; py=y;
            }
        }
        void cubic(Path*p,float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3){
            float px=x0,py=y0;
            for(float t=DT;t<=1.0f+1e-4f;t+=DT){
                float u=1.0f-t;
                float x=u*u*u*x0 + 3*u*u*t*x1 + 3*u*t*t*x2 + t*t*t*x3;
                float y=u*u*u*y0 + 3*u*u*t*y1 + 3*u*t*t*y2 + t*t*t*y3;
                edge_add(p,px,py,x,y); px=x; py=y;
            }
        }

        bool inside(const Path *p, float px, float py){
            bool in=false;
            for(int i=0;i<p->ec;++i){
                Edge e=p->e[i];
                if((e.y0>py)!=(e.y1>py)){
                    float ix=e.x0+(py-e.y0)*(e.x1-e.x0)/(e.y1-e.y0);
                    if(ix>px) in=!in;
                }
            }
            return in;
        }
        bool on_edge(const Path *p, float px, float py){
            const float EPS=0.50f;
            for(int i=0;i<p->ec;++i){
                Edge e=p->e[i];
                if(px < (e.x0<e.x1?e.x0:e.x1)-EPS ||
                px > (e.x0>e.x1?e.x0:e.x1)+EPS ||
                py < (e.y0<e.y1?e.y0:e.y1)-EPS ||
                py > (e.y0>e.y1?e.y0:e.y1)+EPS) continue;

                float dx=e.x1-e.x0, dy=e.y1-e.y0;
                float t=((px-e.x0)*dx+(py-e.y0)*dy)/(dx*dx+dy*dy);
                if(t<0) t=0; else if(t>1) t=1;
                float qx=e.x0+t*dx, qy=e.y0+t*dy;
                dx=px-qx; dy=py-qy;
                if(dx*dx+dy*dy<=EPS*EPS) return true;
            }
            return false;
        }

        const char *hash=find_char(svg,'#');
        bool has_metrics=false;
        int hdr_adv=0,hdr_xMin=0,hdr_yMin=0,hdr_xMax=0,hdr_yMax=0;
        if(hash){
            const char *ptr=svg;
            int tmp[5]={0}; int n=0;
            while(n<5 && ptr<hash){
                tmp[n++]=parse_int(&ptr);
                if(ptr<hash && *ptr==',') ++ptr; else break;
            }
            if(n==5){
                hdr_adv=tmp[0]; hdr_xMin=tmp[1]; hdr_yMin=tmp[2];
                hdr_xMax=tmp[3]; hdr_yMax=tmp[4];
                has_metrics=true;
            }
        }

        int cell_w = has_metrics ? target_w : target_w * 2;
        int cell_h = target_h;

        const char *p=hash?hash+1:svg;
        Path *paths=0,*tail=0;
        float minx= 1e30f, miny= 1e30f, maxx=-1e30f, maxy=-1e30f;

        while(*p){
            const char *br=find_char(p,'[');
            if(!br) break;
            const char *brEnd=find_char(br,']');
            if(!brEnd) break;

            size_t pdLen=(size_t)(br-p);
            char *pd=(char*)malloc(pdLen+1);
            memcpy(pd,p,pdLen); pd[pdLen]=0;

            int cr=color[0],cg=color[1],cb=color[2];
            const char *rgb=find_token(br,"{rgb(",brEnd);
            if(rgb){
                const char *q=rgb+5;
                if(is_digit(*q)||*q=='-'||*q=='+'){
                    cr=parse_int(&q); if(*q==',') ++q;
                    cg=parse_int(&q); if(*q==',') ++q;
                    cb=parse_int(&q);
                }
            }

            Path *pp=(Path*)malloc(sizeof *pp);
            pp->e=0; pp->ec=pp->cap=0;
            pp->r=cr; pp->g=cg; pp->b=cb; pp->next=0;
            if(!paths) paths=pp; else tail->next=pp;
            tail=pp;

            const char *sp=pd;
            float cx = 0;
            float cy = 0;
            float sx = 0;
            float sy = 0;
            float cpx = 0;
            float cpy = 0;
            float qpx = 0;
            float qpy = 0;
            char lastRaw = 0;
            char lastUC = 0;

            while(*sp){
                skip_ws(&sp);
                if(!*sp) break;

                char raw = is_alpha(*sp)?*sp++:lastRaw;
                bool rel = (raw>='a'&&raw<='z');
                char cmd = to_upper(raw);

                if(cmd=='M'){
                    float x = next_f(&sp); 
                    skip_ws(&sp);
                    float y=next_f(&sp); if(rel){x+=cx; y+=cy;}
                    cx=sx=x; cy=sy=y; cpx=cx; cpy=cy; qpx=cx; qpy=cy;
                    skip_ws(&sp);
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float lx=next_f(&sp); skip_ws(&sp);
                        float ly=next_f(&sp); if(rel){lx+=cx; ly+=cy;}
                        edge_add(pp,cx,cy,lx,ly); cx=lx; cy=ly;
                        cpx=cx; cpy=cy; qpx=cx; qpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='L'){
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float lx=next_f(&sp); skip_ws(&sp);
                        float ly=next_f(&sp); if(rel){lx+=cx; ly+=cy;}
                        edge_add(pp,cx,cy,lx,ly); cx=lx; cy=ly;
                        cpx=cx; cpy=cy; qpx=cx; qpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='H'||cmd=='V'){
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float v=next_f(&sp);
                        float lx=cx,ly=cy;
                        if(cmd=='H'){lx=rel?cx+v:v;} else{ly=rel?cy+v:v;}
                        edge_add(pp,cx,cy,lx,ly); cx=lx; cy=ly;
                        cpx=cx; cpy=cy; qpx=cx; qpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='Q'){
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float x1=next_f(&sp); skip_ws(&sp);
                        float y1=next_f(&sp); skip_ws(&sp);
                        float x =next_f(&sp); skip_ws(&sp);
                        float y =next_f(&sp);
                        if(rel){x1+=cx;y1+=cy;x+=cx;y+=cy;}
                        quad(pp,cx,cy,x1,y1,x,y); cx=x; cy=y;
                        qpx=x1; qpy=y1; cpx=cx; cpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='T'){
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float x=next_f(&sp); skip_ws(&sp);
                        float y=next_f(&sp);
                        if(rel){x+=cx;y+=cy;}
                        float x1=(lastUC=='Q'||lastUC=='T')?(2*cx-qpx):cx;
                        float y1=(lastUC=='Q'||lastUC=='T')?(2*cy-qpy):cy;
                        quad(pp,cx,cy,x1,y1,x,y); cx=x; cy=y;
                        qpx=x1; qpy=y1; cpx=cx; cpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='C'){
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float x1=next_f(&sp); skip_ws(&sp);
                        float y1=next_f(&sp); skip_ws(&sp);
                        float x2=next_f(&sp); skip_ws(&sp);
                        float y2=next_f(&sp); skip_ws(&sp);
                        float x =next_f(&sp); skip_ws(&sp);
                        float y =next_f(&sp);
                        if(rel){x1+=cx;y1+=cy;x2+=cx;y2+=cy;x+=cx;y+=cy;}
                        cubic(pp,cx,cy,x1,y1,x2,y2,x,y); cx=x; cy=y;
                        cpx=x2; cpy=y2; qpx=cx; qpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='S'){
                    while(*sp && (*sp=='-'||*sp=='+'||is_digit(*sp))){
                        float x2=next_f(&sp); skip_ws(&sp);
                        float y2=next_f(&sp); skip_ws(&sp);
                        float x =next_f(&sp); skip_ws(&sp);
                        float y =next_f(&sp);
                        if(rel){x2+=cx;y2+=cy;x+=cx;y+=cy;}
                        float x1=(lastUC=='C'||lastUC=='S')?(2*cx-cpx):cx;
                        float y1=(lastUC=='C'||lastUC=='S')?(2*cy-cpy):cy;
                        cubic(pp,cx,cy,x1,y1,x2,y2,x,y); cx=x; cy=y;
                        cpx=x2; cpy=y2; qpx=cx; qpy=cy;
                        skip_ws(&sp);
                    }
                }
                else if(cmd=='Z'){
                    edge_add(pp,cx,cy,sx,sy); cx=sx; cy=sy;
                    cpx=cx; cpy=cy; qpx=cx; qpy=cy;
                }
                else{
                    while(*sp && !is_alpha(*sp)) ++sp;
                    cpx=cx; cpy=cy; qpx=cx; qpy=cy;
                }
                lastRaw=raw; lastUC=cmd;
            }
            free(pd);

            for(int i=0;i<pp->ec;++i){
                Edge e=pp->e[i];
                if(e.x0<minx) minx=e.x0; if(e.x1<minx) minx=e.x1;
                if(e.y0<miny) miny=e.y0; if(e.y1<miny) miny=e.y1;
                if(e.x0>maxx) maxx=e.x0; if(e.x1>maxx) maxx=e.x1;
                if(e.y0>maxy) maxy=e.y0; if(e.y1>maxy) maxy=e.y1;
            }
            p=brEnd+1;
        }

        if(minx>=maxx || miny>=maxy || cell_w<=0 || cell_h<=0){
            int *z=(int*)malloc(3*sizeof *z);
            z[0]=z[1]=0; z[2]=-2; return z;
        }

        float gw=maxx-minx, gh=maxy-miny;
        float scale, dx, dy;

        if(has_metrics){
            float sy=(float)cell_h / gh;
            float sx=((float)cell_w - 1.0f) / maxx;
            scale = sy < sx ? sy : sx;

            dx = minx * scale;
            dy = (float)cell_h + miny*scale;
        }
        else{
            float sx=(float)cell_w / gw;
            float sy=(float)cell_h / gh;
            float s0 = sx<sy ? sx : sy;
            float enlarge = s0 * 1.3f;
            if(enlarge*gw > (float)cell_w || enlarge*gh > (float)cell_h){
                enlarge = ((float)cell_w/gw < (float)cell_h/gh)
                        ? (float)cell_w/gw : (float)cell_h/gh;
            }
            scale = enlarge;

            dx = ((float)cell_w - gw*scale)*0.5f;
            dy = ((float)cell_h - gh*scale)*0.5f;
        }

        size_t pixN=(size_t)cell_w*(size_t)cell_h*3u;
        int *bmp=(int*)malloc((3+pixN)*sizeof *bmp);
        bmp[0]=cell_w; bmp[1]=cell_h;
        bmp[2+pixN] = has_metrics ? -2 : -3;
        for(size_t i=0;i<pixN;++i) bmp[2+i]=-1;

        for(Path *pp=paths; pp; pp=pp->next){
            for(int iy=0; iy<cell_h; ++iy){
                float py=(float)iy+0.5f;
                float wy=miny + ((py-dy)/scale);
                for(int ix=0; ix<cell_w; ++ix){
                    float px=(float)ix+0.5f;
                    float wx=minx + ((px-dx)/scale);
                    bool hit = do_fill ? inside(pp,wx,wy)
                                    : on_edge(pp,wx,wy);
                    if(hit){
                        size_t idx=2+3*((size_t)iy*cell_w+ix);
                        bmp[idx  ]=pp->r;
                        bmp[idx+1]=pp->g;
                        bmp[idx+2]=pp->b;
                    }
                }
            }
        }

        while(paths){
            Path *n=paths->next;
            free(paths->e);
            free(paths);
            paths=n;
        }
        return bmp;
    }


    int font_chars_length = 0;
    for (int index = 0; font_chars[index][0] != NULL; index++) {
        font_chars_length++;
    }

    //Char_raster_cache format
    //[indexOfChar, scale, width, height, r, g, b, ..., indexOfChar, ...]
    int *char_raster_cache = malloc(1 * sizeof(int)); //Just exists for now.
    int char_raster_cache_length = 0;
    char_raster_cache[0] = -1; //Signal that cache is empty.
    bool cache_chars = true;
    if (!char_raster_cache){
        cache_chars = false;
    }

    int* draw_chr(char* chr, int x, int y, float size, int* bgcolor, int* screen_) {
        int* bmap = malloc(1 * sizeof(int));
        if (!bmap){
            PANIC();
            //Shit
            return NULL;
        }

        if (chr[0] != ' '){
            //Check if char is in font_chars
            //Let's measure the length of the given char
            int char_len;
            for (char_len = 0; chr[char_len] != '\0'; char_len++){}
            bool found = false;
            int char_index;
            for (int index = 0; index < font_chars_length; index++) {
                //We need to measure that char's length.
                int char_len_scroller;
                for (char_len_scroller = 0; font_chars[index][0][char_len_scroller] != '\0'; char_len_scroller++){}
                //Nice now we can first do a cheap check: is the length of this char and the one given equal.
                if (char_len_scroller == char_len){
                    //It's equal meaning we now have to check inside to see if the bytes are the same...
                    found = true;
                    for (int subindex = 0; subindex < char_len; subindex++){
                        if (chr[subindex] != font_chars[index][0][subindex]){
                            found = false; //Not it
                            break;
                        }
                    }
                    if (found){
                        char_index = index;
                        break;
                    }
                }
            }
            
            //If char doesn't exist in font.
            if (!found){
                return NULL;
            }

            //Check if size is correct
            if (!(size > 0)){
                return NULL;
            }

            //Check pos
            if (x < 0 || x >= (int)screen_w){
                return NULL;
            }

            if (y < 0 || y >= (int)screen_h){
                return NULL;
            }

            if (screen_[0] < screen_w || screen_[0] > screen_w){
                return NULL;
            }
            
            if (screen_[1] < screen_h || screen_[1] > screen_h){
                return NULL;
            }

            found = false;
            int SCALE_PRECISION = 1000;
            if (cache_chars){
                //We need to check if the char is in cache.
                if (!(char_raster_cache[0] == -1)){
                    //At least a char must be cached. Check for index and scale.
                    int index = 0;
                    while (index < char_raster_cache_length){
                        if (char_raster_cache[index] == char_index){
                            //This is the char then.
                            //Check if scale is right ofc
                            if (absf(size - (float)char_raster_cache[index + 1] / (float)SCALE_PRECISION) < 0.001f) {
                                //Damn its perfect
                                //Set found to true and collect bmap
                                int w = char_raster_cache[index + 2];
                                int h = char_raster_cache[index + 3];
                                if (w <= 0 || h <= 0 || w > screen_w || h > screen_h) {
                                    PANIC(); // corrupted cache entry
                                }

                                found = true;
                                bmap = realloc(bmap, ((char_raster_cache[index + 2] * char_raster_cache[index + 3] * 3) + 2) * sizeof(int));
                                if (!bmap){
                                    PANIC();
                                    //bruh
                                    free(bmap);
                                    bmap = char2bitmap((int)(16 * size), (int)(24 * size), font_chars[char_index][1], (int[]){255, 255, 255}, true);
                                    if (!bmap){
                                        return NULL;
                                    }
                                }
                                //We got the space, collect bmap
                                bmap[0] = char_raster_cache[index + 2]; //w
                                bmap[1] = char_raster_cache[index + 3]; //h
                                for (int subindex = 0; subindex < (char_raster_cache[index + 2] * char_raster_cache[index + 3]) * 3; subindex++){
                                    bmap[subindex + 2] = char_raster_cache[index + 2 + 2 + subindex];
                                }
                                //Got the bmap
                                break;
                            }
                        }
                        index += (char_raster_cache[index + 2] * char_raster_cache[index + 3]) * 3 + 4;
                    }
                    if (!found){
                        free(bmap);
                        bmap = char2bitmap((int)(16 * size), (int)(24 * size), font_chars[char_index][1], (int[]){255, 255, 255}, true);
                        if (!bmap){
                            return NULL;
                        }
                    }
                }
                else{
                    free(bmap);
                    bmap = char2bitmap((int)(16 * size), (int)(24 * size), font_chars[char_index][1], (int[]){255, 255, 255}, true);
                    if (!bmap){
                        return NULL;
                    }
                }
            }

            if (!found){
                //Char was not found in cache database.
                if (char_raster_cache[0] == -1){
                    //It's not init
                    int* tmp = realloc(char_raster_cache, ((bmap[0] * bmap[1] * 3) + 4) * sizeof(int));
                    if (tmp){
                        //Nice
                        char_raster_cache = tmp;
                        //We could realloc meaning now we can override the contents of char_raster_cache 
                        //with the index, scale and bmap
                        char_raster_cache[0] = char_index;
                        int quantized_scale = (int)(size * SCALE_PRECISION + 0.5f);
                        char_raster_cache[1] = quantized_scale;
                        for (int index = 0; index < (bmap[0] * bmap[1]) * 3 + 2; index++){
                            char_raster_cache[index + 2] = bmap[index];
                        }
                        char_raster_cache_length = 4 + (bmap[0] * bmap[1] * 3); //char_index + scale + width + height + pixels
                        //Copy successful.
                    }
                    else{
                        PANIC();
                    }
                    //else we give up on trying to cache it
                }
                else{
                    //It's init this makes things slightly more complicated as we
                    //now have to use char_raster_cache_length
                    int* tmp = realloc(char_raster_cache, ((bmap[0] * bmap[1] * 3) + 4 + char_raster_cache_length) * sizeof(int));
                    if (tmp){
                        //Cool we could make it long enough
                        //Assign
                        char_raster_cache = tmp;
                        //Now we append our shit
                        //char_raster_cache_length started at 1 and we always add to it meaning
                        //that as an index it will always be 1 over the last element which is good here.
                        char_raster_cache[char_raster_cache_length] = char_index;
                        int quantized_scale = (int)(size * SCALE_PRECISION + 0.5f);
                        char_raster_cache[char_raster_cache_length + 1] = quantized_scale;
                        for (int index = 0; index < (bmap[0] * bmap[1]) * 3 + 2; index++){
                            char_raster_cache[index + 2 + char_raster_cache_length] = bmap[index];
                        }
                        char_raster_cache_length += 4 + (bmap[0] * bmap[1] * 3);
                    }
                    else{
                        PANIC();
                    }
                    //Here we also give up trying if it fails
                }
            }
        }
        else{
            //Its a space bru
            //Empty bitmap of height and width -1 pixels (bg)
            int height = (int)(24 * size);
            int width = (int)(16 * size);
            free(bmap);
            bmap = malloc(height * width * 3 + 2);
            bmap[0] = width;
            bmap[1] = height;
            for (int index = 0; index < width * height * 3; index++){
                bmap[index + 2] = -1;
            }
            //Perfection
        }

        //Raster char

        //Just beforehand we have to replace every -1 pixel with the actual background color lol
        int flipper = 1;
        for (int index = 2; index < 2 + bmap[0] * bmap[1] * 3; index++){
            if (bmap[index] == -1){
                if (flipper == 1){
                    bmap[index] = bgcolor[0];
                }
                else{
                    if (flipper == 2){
                        bmap[index] = bgcolor[1];
                    }
                    else{
                        if (flipper == 3){
                            bmap[index] = bgcolor[2];
                        }
                    }
                }
            }
            if (flipper == 3){
                flipper = 0;
            }
            flipper++;
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

        if (bmap[0] > screen_w || bmap[1] > screen_h){
            PANIC(); //huh
        }

        //yea check if its an emoji
        if (bmap[bmap[0] * bmap[1] * 3 + 2] == -3){
            //Alr then we pass on the signal so scrollback can catch it because it's twice as 
            //large so we count it like its two chars
            screen_[screen_w * screen_h * 3 + 2 + 1] = -3;
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

        for (int i = 0; i < bmap[0] * bmap[1] * 3; i++){
            bmap[2 + i] = 0; // clear the screen (skip width/height metadata)
        }

        return 0;
    }

    //Init screen
    int *screen = malloc(sizeof(int) * (2 + screen_h * screen_w * 3) + sizeof(int));

    screen[0] = screen_w;
    screen[1] = screen_h;

    for (int index = 2; index < 2 + screen[0] * screen[1] * 3; index++){
        screen[index] = 0;
    }

    screen[screen_h * screen_w * 3 + 2 + 1] = -4;
    
    //Cool test
    //Oh and so basically scrollback is ** now because its an array of strings because
    //utf8 is now our friend but its multibyte so yea.
    char** scrollback = malloc(sizeof(char*)); // one entry to start
    scrollback[0] = NULL;
    int scrollback_cursor = 0;
    int scrollback_size = 0;

    void refresh_scrollback_render() {
        int max_rows = screen_h / 24;
        if (max_rows == 0) max_rows = 1;

        int rows = 0;
        int col  = 0;
        for (int i = 0; i < scrollback_size && scrollback[i]; i++) {
            int x_char_next = (int)(screen_w / 50 + ((col + 1) * 16));
            if (x_char_next > screen_w) {
                col = 1;
                rows++;
            }
            else{
                col++;
            }
        }
        if (col != 0) rows++;

        int overflow = rows - max_rows;
        if (overflow > 0) {
            int skipped_rows = 0;
            int i = 0;
            int col = 0;

            while (i < scrollback_size && scrollback[i] && skipped_rows < overflow) {
                int x_next = (int)(screen_w / 50 + ((col + 1) * 16));
                if (x_next > screen_w) {
                    col = 1;
                    skipped_rows++;
                } else {
                    col++;
                }
                i++;
            }
            scrollback_cursor = i;
        } else {
            scrollback_cursor = 0;
        }
        
        int column = 0;
        int row = 0;
        for (int i = scrollback_cursor; i < scrollback_size && scrollback[i]; i++) {
            int x_char = (int)(screen_w / 50 + (column * 16));
            int y_char = (int)(24 * row);

            if (x_char + 16 > screen_w) {
                column = 0;
                row++;
                x_char = (int)(screen_w / 50);
                y_char = (int)(24 * row);
            }

            screen[screen_w * screen_h * 3 + 2 + 1] = -4;

            screen = draw_chr(scrollback[i], x_char, y_char, 1, (int[]){0, 0, 0}, screen); // Default scale + black background
            if (!screen) {
                PANIC();
            }

            if (screen[screen_w * screen_h * 3 + 2 + 1] == -3) {
                screen[screen_w * screen_h * 3 + 2 + 1] = -4;
                column += 2;
            } else {
                column++;
            }
        }
    }

    void print(char* text) {
        int index = 0;
        while (text[index] != '\0') {
            int len;
            for (len = 1; text[index + len] != '\0'; len++) {
                if ((text[index + len] & 0xC0) != 0x80) break;
            }

            char* chr = malloc(len + 1);
            for (int j = 0; j < len; j++) {
                chr[j] = text[index + j];
            }
            chr[len] = '\0';

            char** tmp = realloc(scrollback, (scrollback_size + 2) * sizeof(char*));
            if (!tmp) PANIC();
            scrollback = tmp;
            scrollback[scrollback_size] = chr;
            scrollback[scrollback_size + 1] = NULL;
            scrollback_size++;

            index += len;
        }

        refresh_scrollback_render();
        if (screen[0] != screen_w || screen[1] != screen_h) PANIC();
        int render_res = render_frame(screen);
        if (render_res != 0){
            PANIC();
        }
    }

    // //mem test
    // //We'll just alloc more and more in 64b chunks let's see
    
    // for (int r = 0; r < 255; r++){
    //     for (int g = 0; g < 255; g++){
    //         for (int b = 0; b < 255; b++){

    //             void* mem = malloc(64); //64 bytes
    //             if (!mem){
    //                 while (true){}
    //             }

    //             draw_rect(0, 0, 300, 300, rgb(r, g, b));
    //         }
    //     }
    // }

    // draw_rect(0, 0, 300, 300, rgb(0, 255, 0));
    // draw_rect(0, 0, 100, 100, rgb(0, 0, 255));

    print("Welcome to fishOS. Here's a fish btw: 🐟 nice also here's another emoji: 🥀");
    for (;;) __asm__("cli; hlt"); 
}