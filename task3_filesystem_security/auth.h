/*
 * auth.h
 * -------
 * ST5004CEM - Task 3: File System Operations and Security
 *
 * User registration and login. Passwords are never stored in plaintext:
 * each user record stores a random salt and SHA-256(salt || password).
 */

#ifndef AUTH_H
#define AUTH_H

#include "common.h"

/* Registers a new user. Returns 1 on success, 0 if the username already
 * exists or input is invalid. `group` assigns the user to a group for
 * permission checks (e.g. "staff", "guest"). */
int register_user(const char *username, const char *password, const char *group);

/* Attempts to log in. On success, fills `out_user` and returns 1.
 * On failure (wrong username or password), returns 0. */
int login_user(const char *username, const char *password, User *out_user);

/* Looks up a user record by username without authenticating.
 * Used internally for permission checks (e.g. resolving a file's
 * owner group). Returns 1 if found, 0 otherwise. */
int find_user(const char *username, User *out_user);

#endif
