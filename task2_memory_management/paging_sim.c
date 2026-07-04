/*
 * paging_sim.c
 * -------------
 * ST5004CEM - Operating Systems and Security
 * Task 2: Memory Management Simulation
 *
 * WHAT THIS PROGRAM DOES:
 * Simulates virtual memory paging. A stream of virtual addresses is
 * translated into page numbers using a configurable page size, then
 * fed through a configurable number of physical frames using two
 * page replacement algorithms: FIFO and LRU. For each, it reports
 * every access as a HIT or FAULT, then prints total faults, hits,
 * and hit/miss ratios so the two algorithms can be compared.
 *
 * CONFIGURABLE:
 *   - PAGE_SIZE      (bytes per page, used to translate address -> page number)
 *   - NUM_FRAMES     (number of physical frames / how many pages can be resident)
 *   - The reference string (sequence of virtual addresses) itself.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FRAMES 16
#define MAX_REFS   256

/* ---------- Shared frame table state ---------- */
typedef struct {
    int frames[MAX_FRAMES];   /* page number resident in each frame, -1 = empty */
    int num_frames;
    int page_faults;
    int page_hits;
} FrameTable;

/* ---------- Address to page number translation ---------- */
int address_to_page(int address, int page_size) {
    return address / page_size;
}

/* ---------- Helper: is a page already resident? ---------- */
int find_page(FrameTable *ft, int page) {
    for (int i = 0; i < ft->num_frames; i++) {
        if (ft->frames[i] == page) return i;
    }
    return -1;
}

/* ---------- Helper: print current frame state ---------- */
void print_frames(FrameTable *ft) {
    printf("[ ");
    for (int i = 0; i < ft->num_frames; i++) {
        if (ft->frames[i] == -1) printf("_ ");
        else printf("%d ", ft->frames[i]);
    }
    printf("]");
}

/* =========================================================
 * FIFO Page Replacement
 * A queue (circular index) tracks the order pages were loaded.
 * On a fault with no free frame, the OLDEST loaded page is evicted,
 * regardless of how recently it was used.
 * ========================================================= */
void run_fifo(int *refs, int num_refs, int num_frames, int page_size) {
    FrameTable ft;
    for (int i = 0; i < MAX_FRAMES; i++) ft.frames[i] = -1;
    ft.num_frames = num_frames;
    ft.page_faults = 0;
    ft.page_hits = 0;

    int fifo_queue_next = 0;   /* index of the next frame to evict, cycles 0..num_frames-1 */
    int filled = 0;            /* how many frames currently occupied */

    printf("\n--- FIFO (frames = %d) ---\n", num_frames);
    for (int i = 0; i < num_refs; i++) {
        int page = address_to_page(refs[i], page_size);
        int idx = find_page(&ft, page);

        if (idx != -1) {
            ft.page_hits++;
            printf("Access addr=%-5d page=%-3d -> HIT   ", refs[i], page);
        } else {
            ft.page_faults++;
            if (filled < num_frames) {
                ft.frames[filled] = page;
                filled++;
            } else {
                ft.frames[fifo_queue_next] = page;      /* evict oldest */
                fifo_queue_next = (fifo_queue_next + 1) % num_frames;
            }
            printf("Access addr=%-5d page=%-3d -> FAULT ", refs[i], page);
        }
        print_frames(&ft);
        printf("\n");
    }

    double total = ft.page_hits + ft.page_faults;
    printf("FIFO summary: hits=%d faults=%d hit_ratio=%.2f%% miss_ratio=%.2f%%\n",
           ft.page_hits, ft.page_faults,
           100.0 * ft.page_hits / total, 100.0 * ft.page_faults / total);
}

/* =========================================================
 * LRU Page Replacement
 * Every access updates a "last used" timestamp (logical clock) for
 * that page. On a fault with no free frame, the page with the
 * SMALLEST (oldest) last-used timestamp is evicted.
 * ========================================================= */
void run_lru(int *refs, int num_refs, int num_frames, int page_size) {
    int frames[MAX_FRAMES];
    int last_used[MAX_FRAMES];
    for (int i = 0; i < MAX_FRAMES; i++) { frames[i] = -1; last_used[i] = -1; }

    int page_faults = 0, page_hits = 0;
    int filled = 0;
    int clock = 0;   /* logical timestamp, incremented on every access */

    printf("\n--- LRU (frames = %d) ---\n", num_frames);
    for (int i = 0; i < num_refs; i++) {
        int page = address_to_page(refs[i], page_size);
        int idx = -1;
        for (int f = 0; f < num_frames; f++) {
            if (frames[f] == page) { idx = f; break; }
        }

        if (idx != -1) {
            page_hits++;
            last_used[idx] = clock;
            printf("Access addr=%-5d page=%-3d -> HIT   ", refs[i], page);
        } else {
            page_faults++;
            if (filled < num_frames) {
                frames[filled] = page;
                last_used[filled] = clock;
                filled++;
            } else {
                /* find the frame with the smallest last_used value */
                int victim = 0;
                for (int f = 1; f < num_frames; f++) {
                    if (last_used[f] < last_used[victim]) victim = f;
                }
                frames[victim] = page;
                last_used[victim] = clock;
            }
            printf("Access addr=%-5d page=%-3d -> FAULT ", refs[i], page);
        }

        printf("[ ");
        for (int f = 0; f < num_frames; f++) {
            if (frames[f] == -1) printf("_ ");
            else printf("%d ", frames[f]);
        }
        printf("]\n");

        clock++;
    }

    double total = page_hits + page_faults;
    printf("LRU summary: hits=%d faults=%d hit_ratio=%.2f%% miss_ratio=%.2f%%\n",
           page_hits, page_faults,
           100.0 * page_hits / total, 100.0 * page_faults / total);
}

/* ---------- Generates a virtual address reference string from a
 * page access pattern, so it's easy to configure test cases by
 * page number rather than by raw byte address. ---------- */
int build_addresses_from_pages(int *page_pattern, int count, int page_size, int *out_addresses) {
    for (int i = 0; i < count; i++) {
        out_addresses[i] = page_pattern[i] * page_size + (page_size / 2);
        /* +page_size/2 just simulates accessing somewhere in the middle
         * of the page, to show address->page translation is being used,
         * not just page numbers directly. */
    }
    return count;
}

int main(void) {
    int page_size = 4096;   /* configurable page size in bytes (4 KB) */

    /* ---- Test Case 1: classic textbook reference string, small frame count ----
     * Page access pattern: 1,2,3,4,1,2,5,1,2,3,4,5
     * This is a well-known example (Belady's Anomaly candidate for FIFO). */
    int pattern1[] = {1,2,3,4,1,2,5,1,2,3,4,5};
    int addrs1[MAX_REFS];
    int n1 = build_addresses_from_pages(pattern1, 12, page_size, addrs1);

    printf("=========================================\n");
    printf("TEST CASE 1: reference string = 1,2,3,4,1,2,5,1,2,3,4,5\n");
    printf("Page size = %d bytes\n", page_size);
    printf("=========================================\n");
    run_fifo(addrs1, n1, 3, page_size);
    run_lru(addrs1, n1, 3, page_size);

    /* ---- Test Case 2: same pattern, MORE frames (show fewer faults) ---- */
    printf("\n=========================================\n");
    printf("TEST CASE 2: same reference string, frames = 4\n");
    printf("=========================================\n");
    run_fifo(addrs1, n1, 4, page_size);
    run_lru(addrs1, n1, 4, page_size);

    /* ---- Test Case 3: locality-heavy pattern (LRU should shine) ---- */
    int pattern2[] = {1,2,3,1,2,3,1,2,3,4,5,1,2,3};
    int addrs2[MAX_REFS];
    int n2 = build_addresses_from_pages(pattern2, 14, page_size, addrs2);

    printf("\n=========================================\n");
    printf("TEST CASE 3: locality-heavy pattern, frames = 3\n");
    printf("Reference string = 1,2,3,1,2,3,1,2,3,4,5,1,2,3\n");
    printf("=========================================\n");
    run_fifo(addrs2, n2, 3, page_size);
    run_lru(addrs2, n2, 3, page_size);

    return 0;
}
