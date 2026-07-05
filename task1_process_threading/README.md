# Task 1: Process Management and Threading

## Files
- `scheduler.c` — Round-robin CPU scheduler simulation using POSIX threads,
  mutex + semaphore synchronization, and a race-condition demo.
- `deadlock_demo.c` — Deadlock reproduction (unsafe lock ordering) and
  deadlock prevention (consistent lock ordering) demo.

## Requirements
- Linux or WSL (uses POSIX threads / `pthread.h`, `semaphore.h`)
- `gcc` compiler

## Compile & Run

### 1. Scheduler (round-robin + race condition demo)
```bash
gcc -Wall -o scheduler scheduler.c -lpthread
./scheduler
```
This will:
1. Simulate 4 processes with different burst times, scheduled round-robin
   with a quantum of 2 time units (each unit = 0.3 real seconds).
2. Run a race condition demo: increments a shared counter from 4 threads,
   once without a mutex (shows lost updates) and once with a mutex
   (shows correct result).

### 2. Deadlock demo — SAFE mode (default, deadlock-free)
```bash
gcc -Wall -o deadlock_safe deadlock_demo.c -lpthread
./deadlock_safe
```
Completes normally — both threads acquire `resource_1` then `resource_2`
in the same order, so no circular wait can occur.

### 3. Deadlock demo — UNSAFE mode (reproduces the deadlock)
```bash
gcc -Wall -o deadlock_unsafe deadlock_demo.c -lpthread -DDEMO_UNSAFE
timeout 5 ./deadlock_unsafe
```
**This will hang** (that's the point — it demonstrates a real deadlock).
Thread A locks `resource_1` then wants `resource_2`; Thread B locks
`resource_2` then wants `resource_1`. Each waits forever for a lock the
other holds. Use `timeout 5` (or Ctrl+C) to stop it, or it will hang
indefinitely.

## Notes on Design
See `docs/design_doc.md` for the full explanation of design decisions,
synchronization strategy, and how each requirement (threading, scheduling,
race conditions, deadlock prevention) is satisfied.