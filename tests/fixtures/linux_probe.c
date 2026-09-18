#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int network_probe(const char *name, const char *service, int nonblocking) {
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, service, &hints, &result) != 0 || !result)
        return 0;
    int fd = socket(result->ai_family, SOCK_STREAM, result->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(result);
        return 0;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | (nonblocking ? O_NONBLOCK : 0));
    unsigned long nonblocking_value = (unsigned long)nonblocking;
    ioctl(fd, FIONBIO, &nonblocking_value);
    int connected = connect(fd, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    if (connected != 0 && (!nonblocking || errno != EINPROGRESS)) {
        close(fd);
        return 0;
    }
    if (connected != 0) {
        struct pollfd descriptor = {.fd = fd, .events = POLLOUT};
        if (poll(&descriptor, 1, 5000) <= 0) {
            close(fd);
            return 0;
        }
        int socket_error = 0;
        socklen_t socket_error_length = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_length) != 0 ||
            socket_error != 0) {
            close(fd);
            return 0;
        }
    }
    const char payload[] = "hyperhub-dynamic-probe";
    char response[sizeof(payload)] = {0};
    ssize_t sent = send(fd, payload, sizeof(payload) - 1, 0);
    if (sent < 0 && nonblocking && errno == EAGAIN) {
        struct pollfd descriptor = {.fd = fd, .events = POLLOUT};
        if (poll(&descriptor, 1, 5000) > 0)
            sent = send(fd, payload, sizeof(payload) - 1, 0);
    }
    ssize_t received = recv(fd, response, sizeof(payload) - 1, 0);
    if (received < 0 && nonblocking && errno == EAGAIN) {
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        if (poll(&descriptor, 1, 5000) > 0)
            received = recv(fd, response, sizeof(payload) - 1, 0);
    }
    int ok = sent == (ssize_t)(sizeof(payload) - 1) &&
             received == (ssize_t)(sizeof(payload) - 1) &&
             memcmp(payload, response, sizeof(payload) - 1) == 0;
    close(fd);
    return ok;
}

static int file_probe(void) {
    const char *path = "hyperhub-linux-fixture.data";
    const char *renamed = "hyperhub-linux-fixture.renamed";
    const char *renamed_at = "hyperhub-linux-fixture.renamed-at";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0)
        return 0;
    const char data[] = "fixture";
    if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data) || lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return 0;
    }
    char readback[sizeof(data)] = {0};
    if (read(fd, readback, sizeof(readback)) != (ssize_t)sizeof(readback)) {
        close(fd);
        return 0;
    }
    void *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        close(fd);
        return 0;
    }
    memcpy(mapped, data, sizeof(data));
    int ok = mprotect(mapped, 4096, PROT_READ) == 0 && munmap(mapped, 4096) == 0;
    close(fd);

    int opened = open64(path, O_RDONLY);
    if (opened >= 0)
        close(opened);
    opened = openat(AT_FDCWD, path, O_RDONLY);
    if (opened >= 0)
        close(opened);
    opened = openat64(AT_FDCWD, path, O_RDONLY);
    if (opened >= 0)
        close(opened);
    opened = creat("hyperhub-linux-fixture.creat", 0600);
    if (opened >= 0)
        close(opened);
    unlink("hyperhub-linux-fixture.creat");

    ok = ok && rename(path, renamed) == 0;
    ok = ok && renameat(AT_FDCWD, renamed, AT_FDCWD, renamed_at) == 0;
    ok = ok && unlinkat(AT_FDCWD, renamed_at, 0) == 0;
    unlink(path);
    unlink(renamed);
    unlink(renamed_at);
    return ok && memcmp(data, readback, sizeof(data)) == 0;
}

static void exercise_failed_execve(void) {
    char *arguments[] = {(char *)"/hyperhub-missing-executable", NULL};
    execve(arguments[0], arguments, environ);
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--leaf") == 0)
        return network_probe(argv[2], argv[3], 1) ? 0 : 2;
    if (argc != 3)
        return 64;
    if (!network_probe(argv[1], argv[2], 0) || !network_probe(argv[1], argv[2], 1) ||
        !file_probe())
        return 1;

    exercise_failed_execve();

    pid_t child = fork();
    if (child < 0)
        return 3;
    if (child == 0) {
        execl(argv[0], argv[0], "--leaf", argv[1], argv[2], NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 4;

    child = 0;
    char *child_argv[] = {argv[0], (char *)"--leaf", argv[1], argv[2], NULL};
    if (posix_spawn(&child, argv[0], NULL, NULL, child_argv, environ) != 0)
        return 5;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 6;

    child = 0;
    if (posix_spawnp(&child, argv[0], NULL, NULL, child_argv, environ) != 0)
        return 7;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 8;
    return 0;
}
