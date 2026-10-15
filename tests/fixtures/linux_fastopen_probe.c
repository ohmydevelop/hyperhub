#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    struct timeval timeout = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in target = {.sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[2])),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    const char data[] = "fast-open-local-diagnostic";
    ssize_t sent;
    if (!strcmp(argv[1], "sendto")) {
        sent = sendto(fd, data, sizeof(data), MSG_FASTOPEN, (void *)&target, sizeof(target));
    } else if (!strcmp(argv[1], "sendmsg")) {
        struct iovec vector = {(void *)data, sizeof(data)};
        struct msghdr message = {.msg_name = &target, .msg_namelen = sizeof(target),
            .msg_iov = &vector, .msg_iovlen = 1};
        sent = sendmsg(fd, &message, MSG_FASTOPEN);
    } else {
        if (connect(fd, (void *)&target, sizeof(target))) { perror("connect"); return 4; }
        sent = send(fd, data, sizeof(data), 0);
    }
    if (sent != sizeof(data)) {
        if (errno == EOPNOTSUPP) { puts("fastopen=unsupported"); close(fd); return 0; }
        perror("send"); return 5;
    }
    char reply[sizeof(data)];
    if (recv(fd, reply, sizeof(reply), MSG_WAITALL) != sizeof(reply)) { perror("recv"); return 6; }
    if (memcmp(reply, data, sizeof(data))) return 7;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    if (getpeername(fd, (void *)&peer, &length)) return 8;
    printf("mode=%s echo=ok kernel_peer_port=%u application_target_port=%s\n",
        argv[1], ntohs(peer.sin_port), argv[2]);
    close(fd);
    return 0;
}
