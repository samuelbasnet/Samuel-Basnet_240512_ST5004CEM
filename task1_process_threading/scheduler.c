/*
 * scheduler.c
 * -----------
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 *
 * WHAT THIS PROGRAM DOES:
 * Simulates a Round-Robin CPU scheduler. Each "process" is implemented
 * as a POSIX thread (pthread). A dispatcher thread hands out fixed
 * time slices (quantum) to each process thread in turn, just like a
 * real OS scheduler would do on a single CPU core.
 *
 * It demonstrates:
 *   1. Thread creation & management        (>= 3 process threads)
 *   2. Synchronization                     (mutex + semaphores)
 *   3. Round-robin scheduling simulation   (dispatcher + quantum)
 *   4. Race condition handling             (shared counter demo)
 *
 * Deadlock prevention is demonstrated separately in deadlock_demo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>

#define NUM_PROCESSES   4      /* minimum requirement was 3, we use 4 */
#define TIME_QUANTUM    2      /* seconds "executed" per turn        */

/* ---------- Process Control Block (PCB) ----------
 * In a real OS, the kernel keeps one of these per process:
 * PID, program counter, registers, memory pointers, state, etc.
 * We keep a simplified version relevant to scheduling.
 */
typedef enum { READY, RUNNING, DONE } ProcessState;

typedef struct {
    int pid;                 /* simulated process ID        */
    int burst_time;          /* total CPU time needed        */
    int remaining_time;      /* time left before it finishes */
    ProcessState state;
} PCB;

PCB processes[NUM_PROCESSES];

/* ---------- Synchronization primitives ----------
 * mutex        -> protects shared data (the PCB array, the counter)
 * turn_sem[i]  -> one binary semaphore per process thread.
 *                 The dispatcher "signals" turn_sem[i] to tell
 *                 process i it is allowed to run for this quantum.
 *                 The process thread "waits" on it until told to go.
 * done_sem     -> each process thread signals this when it finishes
 *                 its slice, so the dispatcher knows to move on.
 */
pthread_mutex_t pcb_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t turn_sem[NUM_PROCESSES];
sem_t done_sem;

/* ---------- Race condition demo ----------
 * shared_counter is incremented by every process thread.
 * We increment it TWICE per run: once WITHOUT the mutex (to show the
 * race condition / lost updates) and once WITH the mutex (to show the
 * fix). Results are printed at the end for the documentation.
 */
long shared_counter_unsafe = 0;
long shared_counter_safe   = 0;
#define INCREMENTS_PER_THREAD 2000

void *counter_worker(void *arg) {
    for (int i = 0; i < INCREMENTS_PER_THREAD; i++) {
        /* UNSAFE: no lock -> race condition.
         * We deliberately split the increment into read -> modify -> write
         * with sched_yield() in between. This widens the "window" where
         * another thread can interleave, so the race actually shows up
         * in the output (on a fast machine a bare `counter++` can compile
         * to a single instruction and rarely loses updates in practice,
         * even though the race is still technically present). */
        long temp = shared_counter_unsafe;
        sched_yield();
        temp = temp + 1;
        shared_counter_unsafe = temp;

        /* SAFE: protected by mutex -> always correct, no interleaving possible */
        pthread_mutex_lock(&pcb_lock);
        shared_counter_safe++;
        pthread_mutex_unlock(&pcb_lock);
    }
    return NULL;
}

/* ---------- Process thread function ----------
 * Each process thread loops: wait for the dispatcher to give it a
 * turn, "execute" for one quantum (or less, if it's about to finish),
 * update its own PCB (protected by the mutex since the dispatcher
 * also reads/writes the PCB array), then signal done_sem.
 */
void *process_thread(void *arg) {
    int id = *(int *)arg;

    while (1) {
        sem_wait(&turn_sem[id]);          /* wait for dispatcher's signal */

        pthread_mutex_lock(&pcb_lock);
        processes[id].state = RUNNING;
        int run_time = (processes[id].remaining_time < TIME_QUANTUM)
                            ? processes[id].remaining_time
                            : TIME_QUANTUM;
        int remaining_before = processes[id].remaining_time;
        pthread_mutex_unlock(&pcb_lock);

        printf("[P%d] running for %d unit(s) (remaining before run: %d)\n",
               processes[id].pid, run_time, remaining_before);

        usleep(run_time * 300000);        /* simulate CPU burst execution
                                              (0.3s per unit, so it's fast
                                              to observe but still visibly
                                              time-sliced) */

        pthread_mutex_lock(&pcb_lock);
        processes[id].remaining_time -= run_time;
        int just_finished = 0;
        if (processes[id].remaining_time <= 0) {
            processes[id].state = DONE;
            just_finished = 1;
            printf("[P%d] FINISHED\n", processes[id].pid);
        } else {
            processes[id].state = READY;
        }
        pthread_mutex_unlock(&pcb_lock);

        sem_post(&done_sem);              /* tell dispatcher this slice is done */

        if (just_finished) {
            break;                         /* thread exits cleanly, no more turns coming */
        }
    }
    return NULL;
}

/* ---------- Dispatcher (the "scheduler" itself) ----------
 * Cycles through the process list in order (round-robin), giving each
 * READY process one turn via its semaphore, then waiting for it to
 * report back before moving to the next one. Skips DONE processes.
 * Stops when all processes are DONE.
 */
void run_round_robin(void) {
    int finished = 0;

    while (finished < NUM_PROCESSES) {
        finished = 0;
        for (int i = 0; i < NUM_PROCESSES; i++) {
            pthread_mutex_lock(&pcb_lock);
            ProcessState st = processes[i].state;
            pthread_mutex_unlock(&pcb_lock);

            if (st == DONE) {
                finished++;
                continue;
            }

            sem_post(&turn_sem[i]);   /* give process i its turn */
            sem_wait(&done_sem);      /* wait until it's done with this slice */
        }
    }
}

int main(void) {
    pthread_t threads[NUM_PROCESSES];
    int ids[NUM_PROCESSES];

    /* ---- Initialize PCBs with sample burst times ---- */
    int burst_times[NUM_PROCESSES] = {6, 4, 8, 2};
    for (int i = 0; i < NUM_PROCESSES; i++) {
        processes[i].pid = i + 1;
        processes[i].burst_time = burst_times[i];
        processes[i].remaining_time = burst_times[i];
        processes[i].state = READY;
        sem_init(&turn_sem[i], 0, 0);   /* starts locked: threads wait */
        ids[i] = i;
    }
    sem_init(&done_sem, 0, 0);

    printf("=== Round-Robin Scheduler Simulation (quantum = %d) ===\n",
           TIME_QUANTUM);

    /* ---- Create process threads ---- */
    for (int i = 0; i < NUM_PROCESSES; i++) {
        pthread_create(&threads[i], NULL, process_thread, &ids[i]);
    }

    /* ---- Run the dispatcher on the main thread ---- */
    run_round_robin();

    /* ---- Join all process threads ---- */
    for (int i = 0; i < NUM_PROCESSES; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("=== All processes completed ===\n\n");

    /* ---- Race condition demo ---- */
    printf("=== Race Condition Demo (%d threads x %d increments) ===\n",
           NUM_PROCESSES, INCREMENTS_PER_THREAD);
    pthread_t counter_threads[NUM_PROCESSES];
    for (int i = 0; i < NUM_PROCESSES; i++) {
        pthread_create(&counter_threads[i], NULL, counter_worker, NULL);
    }
    for (int i = 0; i < NUM_PROCESSES; i++) {
        pthread_join(counter_threads[i], NULL);
    }
    long expected = (long)NUM_PROCESSES * INCREMENTS_PER_THREAD;
    printf("Expected value:            %ld\n", expected);
    printf("Unsafe counter (no lock):  %ld  (lost updates = %ld)\n",
           shared_counter_unsafe, expected - shared_counter_unsafe);
    printf("Safe counter (with mutex): %ld  (matches expected: %s)\n",
           shared_counter_safe,
           (shared_counter_safe == expected) ? "YES" : "NO");

    /* ---- Cleanup ---- */
    for (int i = 0; i < NUM_PROCESSES; i++) {
        sem_destroy(&turn_sem[i]);
    }
    sem_destroy(&done_sem);
    pthread_mutex_destroy(&pcb_lock);

    return 0;
}
