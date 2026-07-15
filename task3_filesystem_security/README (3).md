# Task 3: File System Operations and Security

## Files
- `common.h` — shared structs and constants
- `crypto.c/.h` — SHA-256 (password hashing) + XOR stream cipher (file encryption)
- `auth.c/.h` — user registration and login (salted, hashed passwords)
- `perms.c/.h` — Unix-style rwx permission storage and checking
- `audit.c/.h` — timestamped audit logging
- `fileops.c/.h` — create/read/write/delete/encrypt/decrypt, permission-gated
- `main.c` — CLI menu tying everything together

## Requirements
- Any C compiler (`gcc` recommended). No external library dependencies —
  SHA-256 is implemented from scratch so no OpenSSL/crypto library is needed.

## Compile & Run
```bash
gcc -Wall -o fms main.c auth.c perms.c fileops.c crypto.c audit.c
./fms
```

## Data Files Created at Runtime
- `users.dat` — registered users (binary, salted password hashes only)
- `files_meta.dat` — file ownership, group, and permission records
- `storage/` — actual file contents (encrypted or plaintext, per file)
- `audit.log` — plain-text, human-readable audit trail

These are created automatically on first use in the current working
directory. Delete them to reset the system to a clean state.

## Quick Start Example
```
1) Login   2) Register   3) Exit
> 2                          (register)
Username: alice
Password: alice123
Group: staff

> 1                          (login)
Username: alice
Password: alice123

--- File Menu ---
> 1                          (create file)
Filename: notes.txt
Initial permissions: rw-r-----
Content: Hello world

> 2                          (read file)
Filename: notes.txt
Passphrase: (leave blank, not encrypted)
```

See `docs/user_guide.md` for full usage instructions and
`docs/security_analysis.md` for a discussion of the security design,
known limitations, and recommended production hardening.
