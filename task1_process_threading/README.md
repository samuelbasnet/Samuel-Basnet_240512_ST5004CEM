# Task 1: Process Management and Threading

## Overview

This project demonstrates key operating system concepts using POSIX threads (`pthread`) in C. It contains two programs:

* **scheduler.c** – Simulates a Round-Robin CPU scheduler, demonstrates thread synchronization using mutexes and semaphores, and includes a race condition example.
* **deadlock_demo.c** – Demonstrates both unsafe locking (causing deadlock) and safe locking (preventing deadlock).

---

## Requirements

Before compiling, ensure you have:

* Linux or Windows Subsystem for Linux (WSL)
* GCC compiler
* POSIX Threads (`pthread`)
* POSIX Semaphores (`semaphore.h`)

---

## Project Files

```
scheduler.c
deadlock_demo.c
docs/
└── design_doc.md
README.md
```

---

# Compilation and Execution

## 1. Round-Robin Scheduler

Compile:

```bash
gcc -Wall -o scheduler scheduler.c -lpthread
```

Run:

```bash
./scheduler
```

### Features

The scheduler:

* Simulates **4 processes** with different CPU burst times.
* Uses **Round-Robin scheduling** with a **time quantum of 2**.
* Treats **1 time unit as 0.3 seconds**.
* Uses **POSIX threads** to represent processes.
* Synchronizes execution using **mutexes** and **semaphores**.

After the scheduling simulation, the program runs a **race condition demonstration**.

Two experiments are performed:

1. Multiple threads increment a shared counter **without a mutex**, showing lost updates due to race conditions.
2. The same operation is repeated **with a mutex**, producing the correct result.

---

## 2. Deadlock Demonstration (Safe Mode)

Compile:

```bash
gcc -Wall -o deadlock_safe deadlock_demo.c -lpthread
```

Run:

```bash
./deadlock_safe
```

### Expected Behaviour

The program finishes successfully.

Both threads acquire resources in the same order:

```
resource_1 → resource_2
```

Because every thread follows the same lock ordering, circular wait cannot occur and deadlock is prevented.

---

## 3. Deadlock Demonstration (Unsafe Mode)

Compile:

```bash
gcc -Wall -o deadlock_unsafe deadlock_demo.c -lpthread -DDEMO_UNSAFE
```

Run:

```bash
timeout 5 ./deadlock_unsafe
```

### Expected Behaviour

The program intentionally enters a deadlock.

Thread A:

```
Locks resource_1
Waits for resource_2
```

Thread B:

```
Locks resource_2
Waits for resource_1
```

Each thread waits indefinitely for a resource held by the other, creating a circular wait condition.

Use:

* `timeout 5` (recommended), or
* `Ctrl + C`

to terminate the program.

---

# Operating System Concepts Demonstrated

* Process scheduling
* Round-Robin scheduling algorithm
* Multithreading using POSIX threads
* Mutex synchronization
* Semaphore synchronization
* Race conditions
* Critical sections
* Deadlock creation
* Deadlock prevention through consistent lock ordering

---



# Summary

This project satisfies the Task 1 requirements by implementing:

* A multithreaded Round-Robin CPU scheduler
* Thread synchronization using mutexes and semaphores
* A race condition demonstration with and without mutex protection
* A deadlock demonstration
* A deadlock prevention implementation using consistent resource ordering
