/*
 * main.c
 * -------
 * ST5004CEM - Operating Systems and Security
 * Task 3: File System Operations and Security
 *
 * CLI entry point. Handles the login/registration screen, then a
 * session menu for file operations once a user is authenticated.
 * All actual logic lives in auth.c, perms.c, fileops.c, crypto.c,
 * audit.c -- this file is deliberately thin, just wiring user input
 * to those modules.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include "auth.h"
#include "perms.h"
#include "fileops.h"
#include "audit.h"

/* Reads a line of input safely, stripping the trailing newline. */
static void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin) != NULL) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
    } else {
        buf[0] = '\0';
    }
}

static void print_banner(void) {
    printf("\n=========================================\n");
    printf(" Secure File Management System - ST5004CEM\n");
    printf("=========================================\n");
}

/* Returns 1 if login succeeded (fills current_user), 0 if the user
 * chose to exit instead. Loops on failed login attempts. */
static int login_screen(User *current_user) {
    char choice[8];
    char username[MAX_USERNAME], password[MAX_PASSWORD], group[MAX_GROUP];

    while (1) {
        printf("\n1) Login\n2) Register\n3) Exit\nChoice: ");
        read_line(choice, sizeof(choice));

        if (strcmp(choice, "1") == 0) {
            printf("Username: ");
            read_line(username, sizeof(username));
            printf("Password: ");
            read_line(password, sizeof(password));

            if (login_user(username, password, current_user)) {
                printf("Login successful. Welcome, %s (group: %s).\n",
                       current_user->username, current_user->group);
                return 1;
            } else {
                printf("Login failed: invalid username or password.\n");
            }
        } else if (strcmp(choice, "2") == 0) {
            printf("Choose a username: ");
            read_line(username, sizeof(username));
            printf("Choose a password: ");
            read_line(password, sizeof(password));
            printf("Choose a group (e.g. staff, guest): ");
            read_line(group, sizeof(group));

            if (register_user(username, password, group)) {
                printf("Registration successful. You can now log in.\n");
            } else {
                printf("Registration failed (username may already exist, or input invalid).\n");
            }
        } else if (strcmp(choice, "3") == 0) {
            return 0;
        } else {
            printf("Invalid choice.\n");
        }
    }
}

static void print_menu(void) {
    printf("\n--- File Menu ---\n");
    printf("1) Create file\n");
    printf("2) Read file\n");
    printf("3) Write/overwrite file\n");
    printf("4) Append to file\n");
    printf("5) Delete file\n");
    printf("6) Change permissions (chmod)\n");
    printf("7) Encrypt file\n");
    printf("8) Decrypt file\n");
    printf("9) Logout\n");
    printf("Choice: ");
}

static void session_loop(User *current_user) {
    char choice[8];
    char filename[MAX_FILENAME];
    char content[MAX_LINE];
    char perm_str[16];
    char passphrase[MAX_PASSWORD];
    char read_buf[4096];

    while (1) {
        print_menu();
        read_line(choice, sizeof(choice));

        if (strcmp(choice, "1") == 0) {
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            printf("Initial permissions (e.g. rw-r-----): ");
            read_line(perm_str, sizeof(perm_str));
            printf("Content: ");
            read_line(content, sizeof(content));

            if (fs_create_file(current_user->username, current_user->group,
                                filename, perm_str, content)) {
                printf("File created.\n");
            } else {
                printf("Failed: invalid permission string, or file already exists.\n");
            }

        } else if (strcmp(choice, "2") == 0) {
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            printf("Passphrase (leave blank if not encrypted): ");
            read_line(passphrase, sizeof(passphrase));

            const char *pass = (passphrase[0] != '\0') ? passphrase : NULL;
            if (fs_read_file(current_user->username, current_user->group,
                              filename, pass, read_buf, sizeof(read_buf))) {
                printf("--- Content ---\n%s\n---------------\n", read_buf);
            } else {
                printf("Failed: file not found or permission denied.\n");
            }

        } else if (strcmp(choice, "3") == 0 || strcmp(choice, "4") == 0) {
            int append = (strcmp(choice, "4") == 0);
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            printf("Passphrase (leave blank if not encrypted): ");
            read_line(passphrase, sizeof(passphrase));
            printf("Content: ");
            read_line(content, sizeof(content));

            const char *pass = (passphrase[0] != '\0') ? passphrase : NULL;
            if (fs_write_file(current_user->username, current_user->group,
                               filename, pass, content, append)) {
                printf("File %s.\n", append ? "appended" : "written");
            } else {
                printf("Failed: file not found or permission denied.\n");
            }

        } else if (strcmp(choice, "5") == 0) {
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            if (fs_delete_file(current_user->username, current_user->group, filename)) {
                printf("File deleted.\n");
            } else {
                printf("Failed: file not found or permission denied.\n");
            }

        } else if (strcmp(choice, "6") == 0) {
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            printf("New permissions (e.g. rwxr-x---): ");
            read_line(perm_str, sizeof(perm_str));

            /* Note: chmod itself is deliberately NOT permission-gated
             * by check_permission() here beyond file existence -- in a
             * more complete system only the owner (or root) should be
             * allowed to chmod. This is flagged as a limitation in the
             * security analysis with the recommended fix. */
            if (chmod_file(filename, perm_str)) {
                log_action(current_user->username, "CHMOD", filename, "SUCCESS");
                printf("Permissions updated.\n");
            } else {
                log_action(current_user->username, "CHMOD", filename, "FAILED");
                printf("Failed: file not found or invalid permission string.\n");
            }

        } else if (strcmp(choice, "7") == 0) {
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            printf("Passphrase: ");
            read_line(passphrase, sizeof(passphrase));
            if (fs_encrypt_file(current_user->username, current_user->group,
                                 filename, passphrase)) {
                printf("File encrypted.\n");
            } else {
                printf("Failed: file not found, permission denied, or already encrypted.\n");
            }

        } else if (strcmp(choice, "8") == 0) {
            printf("Filename: ");
            read_line(filename, sizeof(filename));
            printf("Passphrase: ");
            read_line(passphrase, sizeof(passphrase));
            if (fs_decrypt_file(current_user->username, current_user->group,
                                 filename, passphrase)) {
                printf("File decrypted.\n");
            } else {
                printf("Failed: file not found, permission denied, or not encrypted.\n");
            }

        } else if (strcmp(choice, "9") == 0) {
            printf("Logging out.\n");
            log_action(current_user->username, "LOGOUT", "-", "SUCCESS");
            return;

        } else {
            printf("Invalid choice.\n");
        }
    }
}

int main(void) {
    srand((unsigned int)time(NULL));   /* seed for salt generation */

    print_banner();

    User current_user;
    while (login_screen(&current_user)) {
        session_loop(&current_user);
        print_banner();
    }

    printf("Goodbye.\n");
    return 0;
}
