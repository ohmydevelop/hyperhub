#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void fail(const char *what) { perror(what); exit(1); }
static size_t query(unsigned char *out, const char *name, unsigned char id) {
    unsigned char header[12] = {0x68, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    memcpy(out, header, 12);
    size_t n = strlen(name);
    out[12] = (unsigned char)n;
    memcpy(out + 13, name, n);
    unsigned char tail[5] = {0, 0, 1, 0, 1};
    memcpy(out + 13 + n, tail, 5);
    return 18 + n;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    const char *mode = argv[1];
    int dns = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns < 0) fail("socket dns");
    struct timeval timeout = {.tv_sec = 3};
    setsockopt(dns, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in resolver = {.sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[2])),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(dns, (void *)&resolver, sizeof(resolver))) fail("connect dns");
    unsigned char request[128];
    size_t length = query(request, "localhost", 1);
    struct iovec send_iov[2] = {{request, 12}, {request + 12, length - 12}};
    if (!strcmp(mode, "sendmmsg") || !strcmp(mode, "sendmmsg-partial")) {
        struct msghdr message = {.msg_iov = send_iov, .msg_iovlen = 2};
        struct mmsghdr batch[2] = {{.msg_hdr = message}, {.msg_hdr = {.msg_iov = (struct iovec *)(uintptr_t)-8, .msg_iovlen = 1}}};
        unsigned count = !strcmp(mode, "sendmmsg-partial") ? 2 : 1;
        if (sendmmsg(dns, batch, count, 0) != 1) fail("sendmmsg dns");
    } else if (!strcmp(mode, "writev")) {
        if (writev(dns, send_iov, 2) != (ssize_t)length) fail("writev dns");
    } else {
        if (sendto(dns, request, length, 0, NULL, 0) != (ssize_t)length) fail("sendto dns");
    }
    if (!strcmp(mode, "pipeline")) {
        length = query(request, "ip6-localhost", 2);
        if (sendto(dns, request, length, 0, NULL, 0) != (ssize_t)length) fail("sendto second");
    }
    unsigned char response[512];
    struct iovec receive_iov[2] = {{response, 12}, {response + 12, sizeof(response) - 12}};
    struct msghdr message = {.msg_iov = receive_iov, .msg_iovlen = 2};
    ssize_t count;
    if (!strcmp(mode, "readv")) {
        count = readv(dns, receive_iov, 2);
    } else if (!strcmp(mode, "recvmmsg")) {
        struct mmsghdr batch = {.msg_hdr = message};
        if (recvmmsg(dns, &batch, 1, 0, NULL) != 1) fail("recvmmsg dns");
        count = batch.msg_len;
    } else if (!strcmp(mode, "recvmsg")) {
        count = recvmsg(dns, &message, 0);
    } else {
        count = recvfrom(dns, response, sizeof(response), 0, NULL, NULL);
    }
    if (count < 4) fail("receive dns");
    if (response[1] != 1) { fputs("unexpected response order\n", stderr); return 4; }
    struct sockaddr_in destination = {.sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[3]))};
    memcpy(&destination.sin_addr, response + count - 4, 4);
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &destination.sin_addr, address, sizeof(address));
    printf("mode=%s queried=localhost dns_address=%s\n", mode, address);
    fflush(stdout);
    close(dns);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp < 0) fail("socket tcp");
    setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(tcp, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(tcp, (void *)&destination, sizeof(destination))) fail("connect tcp");
    const char payload[] = "dns-equivalence-probe";
    if (send(tcp, payload, sizeof(payload), 0) != sizeof(payload)) fail("send echo");
    char reply[sizeof(payload)];
    if (recv(tcp, reply, sizeof(reply), MSG_WAITALL) != sizeof(reply)) fail("recv echo");
    if (memcmp(reply, payload, sizeof(reply))) return 3;
    close(tcp);
    puts("echo=ok");
    return 0;
}
