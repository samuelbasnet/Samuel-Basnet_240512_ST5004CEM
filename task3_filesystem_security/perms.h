/*
 * perms.h
 * --------
 * ST5004CEM - Task 3: File System Operations and Security
 *
 * Unix-style rwx permission checking for owner / group / others,
 * stored per-file in files_meta.dat.
 */

#ifndef PERMS_H
#define PERMS_H

#include "common.h"

/* Looks up a file's metadata record. Returns 1 if found, 0 otherwise. */
int find_file_meta(const char *filename, FileMeta *out_meta);

/* Creates a new metadata record for `filename`, owned by `owner`,
 * assigned to `group`, with initial permissions `perm_str` (must be
 * exactly 9 characters of 'r'/'w'/'x'/'-', e.g. "rwxr-----").
 * Returns 1 on success, 0 if the file already has metadata or input
 * is invalid. */
int create_file_meta(const char *filename, const char *owner, const char *group,
                      const char *perm_str);

/* Updates the permission string of an existing file's metadata.
 * Returns 1 on success, 0 if the file has no metadata or perm_str
 * is invalid. */
int chmod_file(const char *filename, const char *perm_str);

/* Updates the is_encrypted flag in a file's metadata. */
int set_encrypted_flag(const char *filename, int is_encrypted);

/* Deletes a file's metadata record (used when the file itself is deleted). */
int delete_file_meta(const char *filename);

/* Checks whether `username` (with group membership `user_group`) is
 * allowed to perform `perm` (read/write/execute) on the file described
 * by `meta`, following standard Unix semantics:
 *   - if username == meta->owner,        check the OWNER bits
 *   - else if user_group == meta->group, check the GROUP bits
 *   - else                                check the OTHERS bits
 * Returns 1 if allowed, 0 if denied.
 */
int check_permission(const char *username, const char *user_group,
                      const FileMeta *meta, PermType perm);

/* Validates that a permission string is exactly 9 chars of r/w/x/-
 * in the correct positions. Returns 1 if valid, 0 otherwise. */
int is_valid_perm_string(const char *perm_str);

#endif
