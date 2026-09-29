/* A standalone application: deliberately contains no RASP SDK calls. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *operation = argc > 1 ? argv[1] : "hello";
    if (strcmp(operation, "connect") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: %s connect <loopback-port>\n", argv[0]);
            return 2;
        }
        char *end;
        long port = strtol(argv[2], &end, 10);
        if (*end != '\0' || port < 1 || port > 65535) return 2;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return 2;
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((unsigned short)port);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            perror("application connect");
            close(fd);
            return 2;
        }
        puts("Application connected after authorization.");
        close(fd);
        return 0;
    }
    printf("Application: %s\n", operation);
    fflush(stdout);
    if (strcmp(operation, "wait") == 0) sleep(30);
    return strcmp(operation, "exit") == 0 ? 7 : 0;
}
