/*
 * fileops.h
 * ----------
 * ST5004CEM - Task 3: File System Operations and Security
 *
 * File create/read/write/delete/encrypt/decrypt operations. Every
 * operation is permission-gated (via perms.h) and audit-logged
 * (via audit.h). Actual file contents are stored under STORAGE_DIR/
 * so real filesystem paths never need to be exposed to users directly.
 */

#ifndef FILEOPS_H
#define FILEOPS_H

#include <stddef.h>

/* Creates a new file owned by `username`, in `group`, with the given
 * initial permission string, and writes `content` into it.
 * Returns 1 on success, 0 on failure (invalid perms, already exists,
 * or I/O error). */
int fs_create_file(const char *username, const char *group, const char *filename,
                    const char *perm_str, const char *content);

/* Reads a file's contents into `out_buffer` (max `buf_size` bytes,
 * null-terminated). Requires the acting user to have READ permission.
 * If the file is marked encrypted, `passphrase` is used to decrypt
 * before returning the content (a wrong passphrase will simply produce
 * garbage output, since XOR cannot itself detect a wrong key -- this
 * limitation is discussed in the security analysis).
 * Returns 1 on success, 0 on failure (not found, permission denied). */
int fs_read_file(const char *username, const char *user_group, const char *filename,
                  const char *passphrase, char *out_buffer, size_t buf_size);

/* Overwrites (or appends, if append=1) a file's contents. Requires
 * WRITE permission. If the file is encrypted, `passphrase` must match
 * the one used to encrypt it, or the stored content will become
 * corrupted (XOR encryption limitation, discussed in security analysis). */
int fs_write_file(const char *username, const char *user_group, const char *filename,
                   const char *passphrase, const char *content, int append);

/* Deletes a file and its metadata. Requires WRITE permission
 * (deletion is treated as a write-class operation on the containing
 * entry, matching common OS conventions). */
int fs_delete_file(const char *username, const char *user_group, const char *filename);

/* Encrypts a file currently stored as plaintext, using `passphrase`.
 * Requires WRITE permission. No-op (returns 0) if already encrypted. */
int fs_encrypt_file(const char *username, const char *user_group, const char *filename,
                     const char *passphrase);

/* Decrypts a file currently stored as encrypted, using `passphrase`.
 * Requires WRITE permission. No-op (returns 0) if already plaintext.
 * NOTE: since XOR encryption has no built-in integrity check, a wrong
 * passphrase here will "succeed" but silently produce garbage content --
 * this is a known limitation of the simple cipher used, covered in the
 * security analysis along with the recommended fix (authenticated
 * encryption, e.g. AES-GCM, which detects wrong keys/tampering). */
int fs_decrypt_file(const char *username, const char *user_group, const char *filename,
                     const char *passphrase);

#endif
