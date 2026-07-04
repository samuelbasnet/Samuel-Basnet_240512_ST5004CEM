# Task 1: Design Documentation
## Process Management and Threading

### Overview

This implementation simulates an operating system's round-robin CPU
scheduler using POSIX threads (pthreads) in C. Rather than building four
disconnected demos for threading, synchronization, scheduling, and
deadlock handling, I combined threading, synchronization, and scheduling
into a single coherent program (`scheduler.c`), with deadlock prevention
demonstrated separately (`deadlock_demo.c`) since it needed a controlled,
isolated scenario to reproduce reliably.

### Modelling Processes as Threads

Each simulated process is represented by a **Process Control Block (PCB)**
struct containing a process ID, total burst time, remaining time, and a
state field (`READY`, `RUNNING`, `DONE`). This mirrors what a real kernel
tracks for scheduling decisions, simplified to the fields relevant here.
Each PCB is driven by its own pthread, and a separate **dispatcher**
(running on the main thread) coordinates which process thread executes
at any given moment — this separation between "the process doing work"
and "the scheduler deciding who works next" reflects how a real OS
separates process execution from kernel-level scheduling.

### Synchronization Strategy

Three synchronization primitives were used, each for a distinct purpose:

1. **Mutex (`pcb_lock`)** protects the shared PCB array, since both the
   dispatcher and the process threads read and write PCB fields
   concurrently. Without this lock, two threads could interleave updates
   to `remaining_time` or `state` and produce inconsistent results.

2. **Per-process semaphores (`turn_sem[i]`)** implement the actual
   round-robin handoff. Each starts locked (value 0), so process threads
   block immediately until the dispatcher explicitly grants them a turn
   with `sem_post`. This is a cleaner mechanism than busy-waiting or
   polling a shared "current turn" variable, and it maps naturally onto
   the concept of a scheduler "waking" a process.

3. **A shared semaphore (`done_sem`)** lets each process thread signal
   the dispatcher when its time slice has ended, so the dispatcher knows
   when it's safe to move to the next process in the rotation.

One subtle bug I encountered during testing: after a process thread
finished its final slice, it looped back to wait on its semaphore again
— but the dispatcher had already stopped signalling finished processes,
causing the thread (and therefore `pthread_join`) to hang indefinitely.
The fix was to have the thread break out of its loop immediately after
detecting its own completion, rather than waiting for a signal that
would never arrive. This highlighted how easy it is to introduce subtle
deadlocks purely through thread lifecycle logic, separate from lock
ordering issues.

### Demonstrating Race Conditions

To make the race condition visible and measurable, I used a shared
counter incremented by four threads, comparing an unprotected version
against a mutex-protected version. On modern hardware, a simple
`counter++` can compile down to very few instructions and rarely loses
updates in short loops, so I deliberately widened the race window by
splitting the operation into explicit read → `sched_yield()` → modify →
write steps. This reliably produces lost updates (in testing, roughly
6000 of 8000 increments were lost without the mutex), while the
mutex-protected counter always reaches the exact expected value. This
demonstrates that the race condition isn't just theoretical — it directly
corrupts shared state without proper synchronization.

### Deadlock Prevention

`deadlock_demo.c` reproduces the classic two-thread, two-lock deadlock:
Thread A acquires `resource_1` then requests `resource_2`, while Thread B
acquires `resource_2` then requests `resource_1`. Compiled with
`-DDEMO_UNSAFE`, this reliably deadlocks, since each thread ends up
waiting on a lock the other holds — a circular wait. The fix applies the
standard **lock ordering** technique: every thread must acquire
`resource_1` before `resource_2`, regardless of which one it logically
needs first. This eliminates circular wait entirely, since no thread can
ever hold `resource_2` while waiting for `resource_1`. This approach was
chosen over alternatives like `pthread_mutex_trylock` with backoff
because it's simpler to reason about and guarantees deadlock avoidance
by construction, rather than by retry logic.

*(Word count: approx. 620 words)*
