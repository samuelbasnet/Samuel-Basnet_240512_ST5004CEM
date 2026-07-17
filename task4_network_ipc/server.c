/*
 * server.c (Windows / Winsock version)
 * --------------------------------------
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 *
 * Same protocol and logic as the POSIX version, ported to Winsock2 so
 * it compiles natively on Windows with MinGW in VS Code. See
 * docs/protocol_doc.md for the full protocol spec.
 *
 * COMPILE (Windows, MinGW / VS Code terminal):
 *   gcc -Wall -o server.exe server.c -lws2_32 -lpthread
 * RUN:
 *   .\server.exe [port]        (default port 5050)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define DEFAULT_PORT     5050
#define BACKLOG          10
#define MAX_LINE         512
#define MAX_KEY          64
#define MAX_VALUE        400
#define MAX_STORE        128
#define MAX_AUTH_ATTEMPTS 3

/* ---------- Hardcoded credentials for this demo ----------
 * In a real system these would be looked up against a proper user
 * database with salted/hashed passwords (as implemented in Task 3). */
typedef struct { const char *username; const char *password; } Credential;
static const Credential VALID_USERS[] = {
    {"alice", "alicepass"},
    {"bob",   "bobpass"},
};
#define NUM_VALID_USERS (sizeof(VALID_USERS) / sizeof(VALID_USERS[0]))

/* ---------- Shared key-value store ---------- */
typedef struct {
    char key[MAX_KEY];
    char value[MAX_VALUE];
    int used;
} StoreEntry;

static StoreEntry store[MAX_STORE];
static pthread_mutex_t store_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------- Logging helper ---------- */
static void log_msg(const char *client_desc, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestr[32];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", t);

    printf("[%s] [%s] ", timestr, client_desc);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

/* ---------- Store operations (mutex-protected) ---------- */
static int store_put(const char *key, const char *value) {
    pthread_mutex_lock(&store_lock);
    int free_slot = -1;
    for (int i = 0; i < MAX_STORE; i++) {
        if (store[i].used && strcmp(store[i].key, key) == 0) {
            strncpy(store[i].value, value, MAX_VALUE - 1);
            store[i].value[MAX_VALUE - 1] = '\0';
            pthread_mutex_unlock(&store_lock);
            return 1;
        }
        if (!store[i].used && free_slot == -1) free_slot = i;
    }
    if (free_slot == -1) {
        pthread_mutex_unlock(&store_lock);
        return 0;
    }
    strncpy(store[free_slot].key, key, MAX_KEY - 1);
    store[free_slot].key[MAX_KEY - 1] = '\0';
    strncpy(store[free_slot].value, value, MAX_VALUE - 1);
    store[free_slot].value[MAX_VALUE - 1] = '\0';
    store[free_slot].used = 1;
    pthread_mutex_unlock(&store_lock);
    return 1;
}

static int store_get(const char *key, char *out_value) {
    pthread_mutex_lock(&store_lock);
    for (int i = 0; i < MAX_STORE; i++) {
        if (store[i].used && strcmp(store[i].key, key) == 0) {
            strcpy(out_value, store[i].value);
            pthread_mutex_unlock(&store_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&store_lock);
    return 0;
}

static int store_del(const char *key) {
    pthread_mutex_lock(&store_lock);
    for (int i = 0; i < MAX_STORE; i++) {
        if (store[i].used && strcmp(store[i].key, key) == 0) {
            store[i].used = 0;
            pthread_mutex_unlock(&store_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&store_lock);
    return 0;
}

static int store_list(char *out_buf, size_t buf_size) {
    pthread_mutex_lock(&store_lock);
    int count = 0;
    size_t offset = 0;
    for (int i = 0; i < MAX_STORE; i++) {
        if (store[i].used) {
            count++;
            int n = snprintf(out_buf + offset, buf_size - offset, "%s ", store[i].key);
            if (n < 0 || (size_t)n >= buf_size - offset) break;
            offset += n;
        }
    }
    pthread_mutex_unlock(&store_lock);
    return count;
}

/* ---------- Input validation ---------- */
static int is_valid_token(const char *s, int max_len) {
    int len = (int)strlen(s);
    if (len == 0 || len > max_len) return 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c == 127) return 0;
    }
    return 1;
}

/* ---------- Sends a line (adds \n). ---------- */
static void send_line(SOCKET sock, const char *msg) {
    char buf[MAX_LINE + 2];
    snprintf(buf, sizeof(buf), "%s\n", msg);
    send(sock, buf, (int)strlen(buf), 0);
}

/* ---------- Reads one newline-terminated line from the socket.
 * Returns line length on success, 0 on clean disconnect, -1 on error
 * or if the line exceeds MAX_LINE. ---------- */
static int recv_line(SOCKET sock, char *out_line, int max_len) {
    int pos = 0;
    char c;
    while (pos < max_len - 1) {
        int n = recv(sock, &c, 1, 0);
        if (n == 0) return 0;         /* client disconnected */
        if (n < 0) return -1;         /* socket error */
        if (c == '\n') {
            out_line[pos] = '\0';
            if (pos > 0 && out_line[pos - 1] == '\r') out_line[pos - 1] = '\0';
            return pos;
        }
        out_line[pos++] = c;
    }
    return -1;
}

/* ---------- Per-client thread ---------- */
typedef struct {
    SOCKET sock;
    struct sockaddr_in addr;
} ClientArgs;

static void *handle_client(void *arg) {
    ClientArgs *ca = (ClientArgs *)arg;
    SOCKET sock = ca->sock;
    char client_desc[64];
    char ip_str[32];
    inet_ntop(AF_INET, &ca->addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(client_desc, sizeof(client_desc), "%s:%d",
             ip_str, ntohs(ca->addr.sin_port));
    free(ca);

    log_msg(client_desc, "connected");

    char line[MAX_LINE];
    char authed_user[MAX_KEY] = "";
    int authenticated = 0;
    int auth_attempts = 0;

    while (1) {
        int n = recv_line(sock, line, sizeof(line));
        if (n == 0) {
            log_msg(client_desc, "disconnected (client closed connection)");
            break;
        }
        if (n < 0) {
            log_msg(client_desc, "disconnected (error or line too long)");
            send_line(sock, "ERR protocol_violation");
            break;
        }
        if (n == 0) continue;

        char cmd[MAX_KEY] = "", arg1[MAX_KEY] = "", arg2[MAX_VALUE] = "";
        sscanf(line, "%63s %63s %399[^\n]", cmd, arg1, arg2);

        if (strcmp(cmd, "AUTH") == 0) {
            if (authenticated) {
                send_line(sock, "ERR already_authenticated");
                continue;
            }
            int ok = 0;
            for (size_t i = 0; i < NUM_VALID_USERS; i++) {
                if (strcmp(arg1, VALID_USERS[i].username) == 0 &&
                    strcmp(arg2, VALID_USERS[i].password) == 0) {
                    ok = 1;
                    break;
                }
            }
            if (ok) {
                authenticated = 1;
                strncpy(authed_user, arg1, MAX_KEY - 1);
                log_msg(client_desc, "AUTH success user=%s", arg1);
                send_line(sock, "OK AUTH");
            } else {
                auth_attempts++;
                log_msg(client_desc, "AUTH failed user=%s attempt=%d/%d",
                        arg1, auth_attempts, MAX_AUTH_ATTEMPTS);
                send_line(sock, "ERR AUTH invalid_credentials");
                if (auth_attempts >= MAX_AUTH_ATTEMPTS) {
                    log_msg(client_desc, "too many failed AUTH attempts, closing connection");
                    send_line(sock, "ERR too_many_attempts_closing");
                    break;
                }
            }
            continue;
        }

        if (!authenticated) {
            send_line(sock, "ERR not_authenticated");
            log_msg(client_desc, "rejected command '%s' (not authenticated)", cmd);
            continue;
        }

        if (strcmp(cmd, "PUT") == 0) {
            if (!is_valid_token(arg1, MAX_KEY - 1) || strlen(arg2) == 0 ||
                (int)strlen(arg2) > MAX_VALUE - 1) {
                send_line(sock, "ERR PUT invalid_input");
                log_msg(client_desc, "PUT rejected: invalid input");
                continue;
            }
            store_put(arg1, arg2);
            send_line(sock, "OK PUT");
            log_msg(client_desc, "user=%s PUT key=%s", authed_user, arg1);

        } else if (strcmp(cmd, "GET") == 0) {
            if (!is_valid_token(arg1, MAX_KEY - 1)) {
                send_line(sock, "ERR GET invalid_input");
                continue;
            }
            char value[MAX_VALUE];
            if (store_get(arg1, value)) {
                char resp[MAX_LINE];
                snprintf(resp, sizeof(resp), "OK GET %s", value);
                send_line(sock, resp);
            } else {
                send_line(sock, "ERR GET not_found");
            }
            log_msg(client_desc, "user=%s GET key=%s", authed_user, arg1);

        } else if (strcmp(cmd, "DEL") == 0) {
            if (!is_valid_token(arg1, MAX_KEY - 1)) {
                send_line(sock, "ERR DEL invalid_input");
                continue;
            }
            if (store_del(arg1)) {
                send_line(sock, "OK DEL");
            } else {
                send_line(sock, "ERR DEL not_found");
            }
            log_msg(client_desc, "user=%s DEL key=%s", authed_user, arg1);

        } else if (strcmp(cmd, "LIST") == 0) {
            char keys[MAX_LINE];
            int count = store_list(keys, sizeof(keys));
            char resp[MAX_LINE + 32];
            snprintf(resp, sizeof(resp), "OK LIST %d %s", count, keys);
            send_line(sock, resp);
            log_msg(client_desc, "user=%s LIST (%d keys)", authed_user, count);

        } else if (strcmp(cmd, "QUIT") == 0) {
            send_line(sock, "OK BYE");
            log_msg(client_desc, "user=%s sent QUIT", authed_user);
            break;

        } else {
            send_line(sock, "ERR unknown_command");
            log_msg(client_desc, "unknown command '%s'", cmd);
        }
    }

    closesocket(sock);
    log_msg(client_desc, "connection closed");
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;

    /* Winsock must be initialized before any socket calls. */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    BOOL opt = TRUE;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((u_short)port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    if (listen(server_sock, BACKLOG) == SOCKET_ERROR) {
        fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    printf("Server listening on port %d...\n", port);
    printf("Valid demo users: alice/alicepass, bob/bobpass\n");

    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "accept() failed: %d\n", WSAGetLastError());
            continue;
        }

        ClientArgs *ca = malloc(sizeof(ClientArgs));
        ca->sock = client_sock;
        ca->addr = client_addr;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, ca) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            closesocket(client_sock);
            free(ca);
            continue;
        }
        pthread_detach(tid);
    }

    closesocket(server_sock);
    WSACleanup();
    return 0;
}