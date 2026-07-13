/*
 * fileops.c
 * ----------
 * Implementation of permission-gated, audit-logged file operations.
 * Actual file bytes are stored under STORAGE_DIR/<filename>, separate
 * from the metadata (files_meta.dat) that tracks ownership and perms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "fileops.h"
#include "perms.h"
#include "crypto.h"
#include "audit.h"
#include "common.h"

/* Builds the real on-disk path for a logical filename, e.g.
 * "secret.txt" -> "storage/secret.txt". Ensures STORAGE_DIR exists. */
static void storage_path(const char *filename, char *out_path, size_t out_size) {
    mkdir(STORAGE_DIR, 0700);   /* no-op if it already exists */
    snprintf(out_path, out_size, "%s/%s", STORAGE_DIR, filename);
}

int fs_create_file(const char *username, const char *group, const char *filename,
                    const char *perm_str, const char *content) {
    if (!create_file_meta(filename, username, group, perm_str)) {
        log_action(username, "CREATE", filename, "FAILED_META_EXISTS_OR_INVALID");
        return 0;
    }

    char path[MAX_FILENAME + 32];
    storage_path(filename, path, sizeof(path));

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        delete_file_meta(filename);   /* roll back the metadata we just created */
        log_action(username, "CREATE", filename, "FAILED_IO_ERROR");
        return 0;
    }
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);

    log_action(username, "CREATE", filename, "SUCCESS");
    return 1;
}

int fs_read_file(const char *username, const char *user_group, const char *filename,
                  const char *passphrase, char *out_buffer, size_t buf_size) {
    FileMeta meta;
    if (!find_file_meta(filename, &meta)) {
        log_action(username, "READ", filename, "FAILED_NOT_FOUND");
        return 0;
    }
    if (!check_permission(username, user_group, &meta, PERM_READ)) {
        log_action(username, "READ", filename, "FAILED_PERMISSION_DENIED");
        return 0;
    }

    char path[MAX_FILENAME + 32];
    storage_path(filename, path, sizeof(path));
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        log_action(username, "READ", filename, "FAILED_STORAGE_MISSING");
        return 0;
    }

    size_t n = fread(out_buffer, 1, buf_size - 1, fp);
    out_buffer[n] = '\0';
    fclose(fp);

    if (meta.is_encrypted && passphrase) {
        xor_cipher((unsigned char *)out_buffer, n, passphrase);
    }

    log_action(username, "READ", filename, "SUCCESS");
    return 1;
}

int fs_write_file(const char *username, const char *user_group, const char *filename,
                   const char *passphrase, const char *content, int append) {
    FileMeta meta;
    if (!find_file_meta(filename, &meta)) {
        log_action(username, "WRITE", filename, "FAILED_NOT_FOUND");
        return 0;
    }
    if (!check_permission(username, user_group, &meta, PERM_WRITE)) {
        log_action(username, "WRITE", filename, "FAILED_PERMISSION_DENIED");
        return 0;
    }

    char path[MAX_FILENAME + 32];
    storage_path(filename, path, sizeof(path));

    size_t len = strlen(content);
    char *buf = malloc(len + 1);
    if (!buf) {
        log_action(username, "WRITE", filename, "FAILED_MEMORY_ERROR");
        return 0;
    }
    memcpy(buf, content, len);

    if (meta.is_encrypted && passphrase) {
        xor_cipher((unsigned char *)buf, len, passphrase);
    }

    FILE *fp = fopen(path, append ? "ab" : "wb");
    if (!fp) {
        free(buf);
        log_action(username, "WRITE", filename, "FAILED_IO_ERROR");
        return 0;
    }
    fwrite(buf, 1, len, fp);
    fclose(fp);
    free(buf);

    log_action(username, append ? "APPEND" : "WRITE", filename, "SUCCESS");
    return 1;
}

int fs_delete_file(const char *username, const char *user_group, const char *filename) {
    FileMeta meta;
    if (!find_file_meta(filename, &meta)) {
        log_action(username, "DELETE", filename, "FAILED_NOT_FOUND");
        return 0;
    }
    if (!check_permission(username, user_group, &meta, PERM_WRITE)) {
        log_action(username, "DELETE", filename, "FAILED_PERMISSION_DENIED");
        return 0;
    }

    char path[MAX_FILENAME + 32];
    storage_path(filename, path, sizeof(path));
    remove(path);
    delete_file_meta(filename);

    log_action(username, "DELETE", filename, "SUCCESS");
    return 1;
}

/* Shared helper for encrypt/decrypt: loads raw bytes, transforms them,
 * writes them back, and flips the is_encrypted flag. Since XOR is its
 * own inverse, "encrypt" and "decrypt" use the exact same transform --
 * they differ only in the expected starting state and the flag value
 * they set afterward. */
static int transform_file(const char *username, const char *user_group, const char *filename,
                           const char *passphrase, int expect_encrypted, int set_to,
                           const char *action_name) {
    FileMeta meta;
    if (!find_file_meta(filename, &meta)) {
        log_action(username, action_name, filename, "FAILED_NOT_FOUND");
        return 0;
    }
    if (!check_permission(username, user_group, &meta, PERM_WRITE)) {
        log_action(username, action_name, filename, "FAILED_PERMISSION_DENIED");
        return 0;
    }
    if (meta.is_encrypted != expect_encrypted) {
        log_action(username, action_name, filename, "FAILED_WRONG_STATE");
        return 0;   /* e.g. trying to encrypt an already-encrypted file */
    }

    char path[MAX_FILENAME + 32];
    storage_path(filename, path, sizeof(path));

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        log_action(username, action_name, filename, "FAILED_STORAGE_MISSING");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(fp);
        log_action(username, action_name, filename, "FAILED_MEMORY_ERROR");
        return 0;
    }
    fread(buf, 1, size, fp);
    fclose(fp);

    xor_cipher(buf, size, passphrase);

    fp = fopen(path, "wb");
    fwrite(buf, 1, size, fp);
    fclose(fp);
    free(buf);

    set_encrypted_flag(filename, set_to);
    log_action(username, action_name, filename, "SUCCESS");
    return 1;
}

int fs_encrypt_file(const char *username, const char *user_group, const char *filename,
                     const char *passphrase) {
    return transform_file(username, user_group, filename, passphrase,
                           /*expect_encrypted=*/0, /*set_to=*/1, "ENCRYPT");
}

int fs_decrypt_file(const char *username, const char *user_group, const char *filename,
                     const char *passphrase) {
    return transform_file(username, user_group, filename, passphrase,
                           /*expect_encrypted=*/1, /*set_to=*/0, "DECRYPT");
}
