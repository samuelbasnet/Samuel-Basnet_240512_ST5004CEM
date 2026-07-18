# ST5004CEM — Operating Systems and Security
## Coursework Submission — Samuel Basnet (240512)

This repository contains all four tasks for the ST5004CEM coursework,
each in its own folder with source code, a README with compile/run
instructions, and supporting documentation.

## Structure
```
Samuel-Basnet_240512_ST5004CEM/
├── task1_process_threading/       Process Management & Threading (25 marks)
├── task2_memory_management/       Memory Management Simulation (25 marks)
├── task3_filesystem_security/     File System Operations & Security (25 marks)
├── task4_network_ipc/             Network Programming & IPC (25 marks)
└── README.md                      (this file)
```

## Task Summaries

### Task 1 — Process Management and Threading
A round-robin CPU scheduler simulation using POSIX threads, with
mutex/semaphore synchronization, a race-condition demonstration, and a
separate deadlock reproduction + prevention demo (lock ordering).
→ `task1_process_threading/`

### Task 2 — Memory Management Simulation
A paging simulator implementing FIFO and LRU page replacement with
configurable page size and frame count, including an analysis of
Belady's Anomaly across three test cases.
→ `task2_memory_management/`

### Task 3 — File System Operations and Security
A secure file management system with salted SHA-256 password hashing,
Unix-style owner/group/others permissions, XOR-based file encryption,
and full audit logging.
→ `task3_filesystem_security/`

### Task 4 — Network Programming and IPC
A multi-threaded TCP client-server implementing an authenticated
key-value store protocol, with brute-force protection, input
validation, and concurrent client handling.
→ `task4_network_ipc/`

## Compiling Everything
Each task folder has its own README.md with exact compile commands.
All four compile with plain `gcc` (Tasks 1–3 need `-lpthread`; Task 4
also needs `-lws2_32` on Windows for networking, or just `-lpthread`
on Linux/WSL/Ubuntu VM).

Quick reference:
```powershell
# Task 1
gcc -Wall -o scheduler scheduler.c -lpthread
gcc -Wall -o deadlock_demo deadlock_demo.c -lpthread

# Task 2
gcc -Wall -o paging_sim paging_sim.c

# Task 3
gcc -Wall -o fms main.c auth.c perms.c fileops.c crypto.c audit.c

# Task 4 (Windows)
gcc -Wall -o server.exe server.c -lws2_32 -lpthread
gcc -Wall -o client.exe client.c -lws2_32
```

## Notes
- All programs were compiled and tested against real inputs before
  submission (not just reasoned about) — see each task's testing/
  analysis documentation for actual verified output.
- Task 4 uses Winsock2 for Windows compatibility. A POSIX sockets
  version (for Linux/WSL) is available on request but not included
  here since the primary development environment was Windows/VS Code.