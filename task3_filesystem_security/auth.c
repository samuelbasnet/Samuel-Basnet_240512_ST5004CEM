/*
 * auth.c
 * -------
 * Implementation of user registration and login, backed by a simple
 * binary file (users.dat) of fixed-size User records.
 */

#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "crypto.h"
#include "audit.h"

int find_user(const char *username, User *out_user) {
    FILE *fp = fopen(USERS_DB, "rb");
    if (!fp) return 0;   /* no users registered yet */

    User u;
    while (fread(&u, sizeof(User), 1, fp) == 1) {
        if (strncmp(u.username, username, MAX_USERNAME) == 0) {
            if (out_user) *out_user = u;
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int register_user(const char *username, const char *password, const char *group) {
    if (!username || !password || !group ||
        strlen(username) == 0 || strlen(username) >= MAX_USERNAME ||
        strlen(password) == 0 || strlen(password) >= MAX_PASSWORD ||
        strlen(group) >= MAX_GROUP) {
        log_action(username, "REGISTER", username, "FAILED_INVALID_INPUT");
        return 0;
    }

    if (find_user(username, NULL)) {
        log_action(username, "REGISTER", username, "FAILED_ALREADY_EXISTS");
        return 0;   /* username taken */
    }

    User u;
    memset(&u, 0, sizeof(User));
    strncpy(u.username, username, MAX_USERNAME - 1);
    strncpy(u.group, group, MAX_GROUP - 1);
    generate_salt(u.salt);
    hash_password(password, u.salt, u.hash);

    FILE *fp = fopen(USERS_DB, "ab");
    if (!fp) {
        log_action(username, "REGISTER", username, "FAILED_IO_ERROR");
        return 0;
    }
    fwrite(&u, sizeof(User), 1, fp);
    fclose(fp);

    log_action(username, "REGISTER", username, "SUCCESS");
    return 1;
}

int login_user(const char *username, const char *password, User *out_user) {
    User u;
    if (!find_user(username, &u)) {
        /* Deliberately give the same generic failure message a caller
         * would see for a wrong password, so the CLI layer doesn't leak
         * whether a username exists (a common authentication hardening
         * practice, discussed in the security analysis). */
        log_action(username, "LOGIN", username, "FAILED_UNKNOWN_USER");
        return 0;
    }

    unsigned char attempt_hash[HASH_LEN];
    hash_password(password, u.salt, attempt_hash);

    if (memcmp(attempt_hash, u.hash, HASH_LEN) != 0) {
        log_action(username, "LOGIN", username, "FAILED_WRONG_PASSWORD");
        return 0;
    }

    if (out_user) *out_user = u;
    log_action(username, "LOGIN", username, "SUCCESS");
    return 1;
}
