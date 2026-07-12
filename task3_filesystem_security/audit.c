/*
 * audit.c
 * --------
 * Implementation of the append-only audit logger.
 */

#include <stdio.h>
#include <time.h>
#include "audit.h"
#include "common.h"

void log_action(const char *username, const char *action, const char *target, const char *result) {
    FILE *fp = fopen(AUDIT_LOG, "a");
    if (!fp) {
        /* If we can't write the audit log, at least warn on stderr --
         * silently losing audit records would itself be a security gap. */
        fprintf(stderr, "WARNING: could not write to audit log!\n");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestr[32];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", t);

    fprintf(fp, "[%s] user=%s action=%s target=%s result=%s\n",
            timestr,
            (username && username[0]) ? username : "-",
            action ? action : "-",
            target ? target : "-",
            result ? result : "-");

    fclose(fp);
}
