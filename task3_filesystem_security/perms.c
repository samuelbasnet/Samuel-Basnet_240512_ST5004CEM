/*
 * perms.c
 * --------
 * Implementation of file permission metadata storage and checking,
 * backed by a simple binary file (files_meta.dat) of FileMeta records.
 */

#include <stdio.h>
#include <string.h>
#include "perms.h"

int is_valid_perm_string(const char *perm_str) {
    if (!perm_str || strlen(perm_str) != PERM_STRING_LEN) return 0;
    const char expected_type[PERM_STRING_LEN] = {'r','w','x','r','w','x','r','w','x'};
    for (int i = 0; i < PERM_STRING_LEN; i++) {
        if (perm_str[i] != expected_type[i] && perm_str[i] != '-') return 0;
    }
    return 1;
}

int find_file_meta(const char *filename, FileMeta *out_meta) {
    FILE *fp = fopen(FILES_DB, "rb");
    if (!fp) return 0;

    FileMeta m;
    while (fread(&m, sizeof(FileMeta), 1, fp) == 1) {
        if (strncmp(m.filename, filename, MAX_FILENAME) == 0) {
            if (out_meta) *out_meta = m;
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int create_file_meta(const char *filename, const char *owner, const char *group,
                      const char *perm_str) {
    if (!is_valid_perm_string(perm_str)) return 0;
    if (find_file_meta(filename, NULL)) return 0;   /* already exists */

    FileMeta m;
    memset(&m, 0, sizeof(FileMeta));
    strncpy(m.filename, filename, MAX_FILENAME - 1);
    strncpy(m.owner, owner, MAX_USERNAME - 1);
    strncpy(m.group, group, MAX_GROUP - 1);
    strncpy(m.permissions, perm_str, PERM_STRING_LEN);
    m.permissions[PERM_STRING_LEN] = '\0';
    m.is_encrypted = 0;

    FILE *fp = fopen(FILES_DB, "ab");
    if (!fp) return 0;
    fwrite(&m, sizeof(FileMeta), 1, fp);
    fclose(fp);
    return 1;
}

/* Generic helper: rewrite files_meta.dat with one record modified,
 * used by chmod_file, set_encrypted_flag, and delete_file_meta. */
static int rewrite_meta_matching(const char *filename,
                                  int delete_record,
                                  const char *new_perm_str,   /* NULL = don't change */
                                  int set_encrypted,          /* -1 = don't change, else 0/1 */
                                  int *found) {
    FILE *fp = fopen(FILES_DB, "rb");
    if (!fp) { *found = 0; return 0; }

    FileMeta records[1024];
    int count = 0;
    FileMeta m;
    while (fread(&m, sizeof(FileMeta), 1, fp) == 1 && count < 1024) {
        records[count++] = m;
    }
    fclose(fp);

    *found = 0;
    FILE *out = fopen(FILES_DB, "wb");
    if (!out) return 0;

    for (int i = 0; i < count; i++) {
        if (strncmp(records[i].filename, filename, MAX_FILENAME) == 0) {
            *found = 1;
            if (delete_record) continue;   /* skip writing it back out */
            if (new_perm_str) {
                strncpy(records[i].permissions, new_perm_str, PERM_STRING_LEN);
                records[i].permissions[PERM_STRING_LEN] = '\0';
            }
            if (set_encrypted != -1) {
                records[i].is_encrypted = set_encrypted;
            }
        }
        fwrite(&records[i], sizeof(FileMeta), 1, out);
    }
    fclose(out);
    return 1;
}

int chmod_file(const char *filename, const char *perm_str) {
    if (!is_valid_perm_string(perm_str)) return 0;
    int found = 0;
    rewrite_meta_matching(filename, 0, perm_str, -1, &found);
    return found;
}

int set_encrypted_flag(const char *filename, int is_encrypted) {
    int found = 0;
    rewrite_meta_matching(filename, 0, NULL, is_encrypted, &found);
    return found;
}

int delete_file_meta(const char *filename) {
    int found = 0;
    rewrite_meta_matching(filename, 1, NULL, -1, &found);
    return found;
}

int check_permission(const char *username, const char *user_group,
                      const FileMeta *meta, PermType perm) {
    int base_index;   /* index into permissions[] where this actor's bits start */

    if (strncmp(username, meta->owner, MAX_USERNAME) == 0) {
        base_index = 0;   /* owner bits: positions 0-2 */
    } else if (strncmp(user_group, meta->group, MAX_GROUP) == 0) {
        base_index = 3;   /* group bits: positions 3-5 */
    } else {
        base_index = 6;   /* others bits: positions 6-8 */
    }

    char bit = meta->permissions[base_index + (int)perm];
    return bit != '-';
}
