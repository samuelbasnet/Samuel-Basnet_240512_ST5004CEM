/*
 * common.h
 * ---------
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 *
 * Shared constants and data structures used across all modules.
 */

#ifndef COMMON_H
#define COMMON_H

#define MAX_USERNAME   32
#define MAX_PASSWORD   64
#define MAX_GROUP      32
#define MAX_FILENAME   64
#define MAX_LINE       512
#define SALT_LEN       16
#define HASH_LEN       32   /* SHA-256 produces 32 bytes */

#define USERS_DB       "users.dat"
#define FILES_DB       "files_meta.dat"
#define AUDIT_LOG      "audit.log"
#define STORAGE_DIR    "storage"   /* where actual file contents live */

/* ---------- Permission bits, Unix-style ----------
 * Stored as a 9-character string "rwxr-x---":
 *   chars 0-2 = owner  (read, write, execute)
 *   chars 3-5 = group  (read, write, execute)
 *   chars 6-8 = others (read, write, execute)
 * '-' means the permission is not granted.
 */
#define PERM_STRING_LEN 9

typedef struct {
    char username[MAX_USERNAME];
    char group[MAX_GROUP];
    unsigned char salt[SALT_LEN];
    unsigned char hash[HASH_LEN];
} User;

typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    char group[MAX_GROUP];
    char permissions[PERM_STRING_LEN + 1]; /* +1 for null terminator */
    int  is_encrypted;                     /* 0 = plaintext, 1 = encrypted */
} FileMeta;

typedef enum { PERM_READ, PERM_WRITE, PERM_EXECUTE } PermType;

#endif
