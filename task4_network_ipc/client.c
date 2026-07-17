/*
 * client.c (Windows / Winsock version)
 * --------------------------------------
 * ST5004CEM - Operating Systems and Security
 * Task 4: Network Programming and IPC
 *
 * Same behaviour as the POSIX version, ported to Winsock2. See
 * docs/protocol_doc.md for the full protocol spec.
 *
 * COMPILE (Windows, MinGW / VS Code terminal):
 *   gcc -Wall -o client.exe client.c -lws2_32
 * RUN:
 *   .\client.exe [server_ip] [port]     (defaults: 127.0.0.1, 5050)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define DEFAULT_PORT 5050
#define MAX_LINE     512

/* Reads one newline-terminated line from the socket into out_line.
 * Returns line length, 0 on clean disconnect, -1 on error. */
static int recv_line(SOCKET sock, char *out_line, int max_len) {
    int pos = 0;
    char c;
    while (pos < max_len - 1) {
        int n = recv(sock, &c, 1, 0);
        if (n == 0) return 0;
        if (n < 0) return -1;
        if (c == '\n') {
            out_line[pos] = '\0';
            if (pos > 0 && out_line[pos - 1] == '\r') out_line[pos - 1] = '\0';
            return pos;
        }
        out_line[pos++] = c;
    }
    return -1;
}

static void send_line(SOCKET sock, const char *msg) {
    char buf[MAX_LINE + 2];
    snprintf(buf, sizeof(buf), "%s\n", msg);
    send(sock, buf, (int)strlen(buf), 0);
}

/* Reads a line of user input from stdin, stripping the trailing newline.
 * Returns 1 on success, 0 on EOF (stdin closed / Ctrl+Z on Windows), so
 * the caller can exit cleanly instead of looping forever on empty reads. */
static int read_stdin_line(char *buf, int size) {
    if (fgets(buf, size, stdin) != NULL) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
        return 1;
    }
    buf[0] = '\0';
    return 0;
}

int main(int argc, char *argv[]) {
    const char *server_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((u_short)port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address: %s\n", server_ip);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Connecting to %s:%d...\n", server_ip, port);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("Connected. Type HELP for available commands.\n");

    char input[MAX_LINE];
    char response[MAX_LINE];

    while (1) {
        printf("> ");
        fflush(stdout);
        if (!read_stdin_line(input, sizeof(input))) {
            printf("\nEOF on input, closing connection.\n");
            break;
        }

        if (strlen(input) == 0) continue;

        if (strcmp(input, "HELP") == 0) {
            printf("Commands:\n"
                   "  AUTH <username> <password>\n"
                   "  PUT <key> <value>\n"
                   "  GET <key>\n"
                   "  DEL <key>\n"
                   "  LIST\n"
                   "  QUIT\n");
            continue;
        }

        send_line(sock, input);

        int n = recv_line(sock, response, sizeof(response));
        if (n == 0) {
            printf("Server closed the connection.\n");
            break;
        }
        if (n < 0) {
            printf("Connection error or server response too long.\n");
            break;
        }
        printf("%s\n", response);

        if (strncmp(input, "QUIT", 4) == 0) {
            break;
        }
    }

    closesocket(sock);
    WSACleanup();
    printf("Disconnected.\n");
    return 0;
}