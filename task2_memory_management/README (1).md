# Task 2: Memory Management Simulation

## Files
- `paging_sim.c` — Paging simulator implementing FIFO and LRU page
  replacement, with configurable page size and frame count.

## Requirements
- Any C compiler (`gcc` recommended). No external dependencies.

## Compile & Run
```bash
gcc -Wall -o paging_sim paging_sim.c
./paging_sim
```

## What It Does
1. Translates a sequence of virtual addresses into page numbers using
   `page_number = address / PAGE_SIZE` (page size configurable in
   `main()`, default 4096 bytes).
2. Runs the same reference string through both FIFO and LRU replacement
   across a configurable number of physical frames.
3. Prints a step-by-step trace: for every memory access, shows whether
   it was a HIT or a page FAULT, and the resulting frame contents.
4. Prints a summary per run: total hits, total faults, hit ratio, and
   miss ratio.

## Test Cases Included
1. **Classic reference string** (`1,2,3,4,1,2,5,1,2,3,4,5`), 3 frames —
   a well-known textbook example used to compare replacement behaviour.
2. **Same reference string, 4 frames** — shows how increasing frame
   count changes fault counts differently for FIFO vs LRU.
3. **Locality-heavy pattern** (`1,2,3,1,2,3,1,2,3,4,5,1,2,3`), 3 frames —
   designed to test how each algorithm handles a working set with
   strong temporal locality before a change in access pattern.

## Configuring Your Own Test Case
Edit `main()` in `paging_sim.c`:
- Change `page_size` to alter address-to-page translation.
- Define a new `int pattern[] = {...}` array (page numbers).
- Call `build_addresses_from_pages(...)` then `run_fifo(...)` /
  `run_lru(...)` with your desired frame count.

## Notes
See `docs/analysis_report.md` for a comparison of FIFO vs LRU
performance across the included test cases, including discussion of
Belady's Anomaly.
