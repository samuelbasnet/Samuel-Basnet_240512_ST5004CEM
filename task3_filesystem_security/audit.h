/*
 * audit.h
 * --------
 * ST5004CEM - Task 3: File System Operations and Security
 *
 * Appends timestamped records of security-relevant events (logins,
 * file access, permission changes) to audit.log, so activity can be
 * reviewed after the fact -- a standard OS/security requirement for
 * detecting misuse or investigating incidents.
 */

#ifndef AUDIT_H
#define AUDIT_H

/* Appends one line to audit.log in the form:
 *   [YYYY-MM-DD HH:MM:SS] user=<username> action=<action> target=<target> result=<result>
 * `username` may be "-" if no one is logged in yet (e.g. a failed login
 * attempt with an unknown username). */
void log_action(const char *username, const char *action, const char *target, const char *result);

#endif
