/*
 * deadlock_demo.c
 * ----------------
 * ST5004CEM - Operating Systems and Security
 * Task 1: Process Management and Threading
 *
 * WHAT THIS PROGRAM DOES:
 * Demonstrates the classic two-thread / two-lock deadlock scenario,
 * then demonstrates the fix using consistent lock ordering.
 *
 * Compile with two modes using a preprocessor flag:
 *   gcc -o deadlock_demo deadlock_demo.c -lpthread -DDEMO_UNSAFE
 *   gcc -o deadlock_demo deadlock_demo.c -lpthread            (safe, default)
 *
 * UNSAFE MODE (-DDEMO_UNSAFE):
 *   Thread A locks resource_1 then tries to lock resource_2.
 *   Thread B locks resource_2 then tries to lock resource_1.
 *   If both threads acquire their first lock at roughly the same time,
 *   each waits forever for the lock the other is holding -> DEADLOCK.
 *
 * SAFE MODE (default):
 *   Both threads always acquire locks in the SAME global order
 *   (resource_1 before resource_2). This is the standard "lock
 *   ordering" deadlock-prevention technique: if every thread requests
 *   resources in a fixed order, circular wait (one of the four
 *   necessary conditions for deadlock) can never happen.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

pthread_mutex_t resource_1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t resource_2 = PTHREAD_MUTEX_INITIALIZER;

#ifdef DEMO_UNSAFE

/* ---------- UNSAFE: inconsistent lock ordering ---------- */
void *thread_a(void *arg) {
    printf("[Thread A] locking resource_1...\n");
    pthread_mutex_lock(&resource_1);
    printf("[Thread A] got resource_1, sleeping briefly...\n");
    usleep(200000);   /* give Thread B time to grab resource_2 */

    printf("[Thread A] locking resource_2...\n");
    pthread_mutex_lock(&resource_2);   /* <-- will block: Thread B has it */
    printf("[Thread A] got both locks!\n");

    pthread_mutex_unlock(&resource_2);
    pthread_mutex_unlock(&resource_1);
    return NULL;
}

void *thread_b(void *arg) {
    printf("[Thread B] locking resource_2...\n");
    pthread_mutex_lock(&resource_2);
    printf("[Thread B] got resource_2, sleeping briefly...\n");
    usleep(200000);   /* give Thread A time to grab resource_1 */

    printf("[Thread B] locking resource_1...\n");
    pthread_mutex_lock(&resource_1);   /* <-- will block: Thread A has it */
    printf("[Thread B] got both locks!\n");

    pthread_mutex_unlock(&resource_1);
    pthread_mutex_unlock(&resource_2);
    return NULL;
}

#else

/* ---------- SAFE: consistent lock ordering (deadlock prevention) ----------
 * Both threads always lock resource_1 BEFORE resource_2, regardless of
 * which resource they "logically" need first. This removes the
 * possibility of circular wait entirely. */
void *thread_a(void *arg) {
    printf("[Thread A] locking resource_1...\n");
    pthread_mutex_lock(&resource_1);
    printf("[Thread A] got resource_1, sleeping briefly...\n");
    usleep(200000);

    printf("[Thread A] locking resource_2...\n");
    pthread_mutex_lock(&resource_2);
    printf("[Thread A] got both locks!\n");

    pthread_mutex_unlock(&resource_2);
    pthread_mutex_unlock(&resource_1);
    return NULL;
}

void *thread_b(void *arg) {
    /* Note: Thread B ALSO locks resource_1 first, resource_2 second,
     * even though from its own point of view it might "want" resource_2
     * first. This consistent global ordering is the whole trick. */
    printf("[Thread B] locking resource_1...\n");
    pthread_mutex_lock(&resource_1);
    printf("[Thread B] got resource_1, sleeping briefly...\n");
    usleep(200000);

    printf("[Thread B] locking resource_2...\n");
    pthread_mutex_lock(&resource_2);
    printf("[Thread B] got both locks!\n");

    pthread_mutex_unlock(&resource_2);
    pthread_mutex_unlock(&resource_1);
    return NULL;
}

#endif

int main(void) {
#ifdef DEMO_UNSAFE
    printf("=== UNSAFE MODE: inconsistent lock ordering (may deadlock) ===\n");
#else
    printf("=== SAFE MODE: consistent lock ordering (deadlock-free) ===\n");
#endif

    pthread_t a, b;
    pthread_create(&a, NULL, thread_a, NULL);
    pthread_create(&b, NULL, thread_b, NULL);

    pthread_join(a, NULL);
    pthread_join(b, NULL);

    printf("=== Program completed without hanging ===\n");
    return 0;
}
