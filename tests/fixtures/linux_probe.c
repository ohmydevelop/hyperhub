#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int network_probe(const char *name, const char *service, int nonblocking, int verify_flags) {
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
    if (verify_flags) {
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ((flags & O_NONBLOCK) != 0) != (nonblocking != 0)) {
            close(fd);
            freeaddrinfo(result);
            return 0;
        }
    }
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
    const char sendto_payload[] = "hyperhub-sendto";
    const char sendmsg_payload[] = "hyperhub-sendmsg";
    char response_to[sizeof(sendto_payload)] = {0};
    char response_message[sizeof(sendmsg_payload)] = {0};
    struct iovec send_iov = {(void *)sendmsg_payload, sizeof(sendmsg_payload) - 1};
    struct iovec recv_iov = {response_message, sizeof(sendmsg_payload) - 1};
    struct msghdr send_message = {0};
    struct msghdr recv_message = {0};
    send_message.msg_iov = &send_iov;
    send_message.msg_iovlen = 1;
    recv_message.msg_iov = &recv_iov;
    recv_message.msg_iovlen = 1;
    ssize_t sent_to = sendto(fd, sendto_payload, sizeof(sendto_payload) - 1, 0, NULL, 0);
    if (sent_to < 0 && nonblocking && errno == EAGAIN) {
        struct pollfd descriptor = {.fd = fd, .events = POLLOUT};
        if (poll(&descriptor, 1, 5000) > 0)
            sent_to = sendto(fd, sendto_payload, sizeof(sendto_payload) - 1, 0, NULL, 0);
    }
    ssize_t received_from = recvfrom(fd, response_to, sizeof(sendto_payload) - 1, 0, NULL, NULL);
    if (received_from < 0 && nonblocking && errno == EAGAIN) {
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        if (poll(&descriptor, 1, 5000) > 0)
            received_from = recvfrom(fd, response_to, sizeof(sendto_payload) - 1, 0, NULL, NULL);
    }
    ssize_t sent_message = sendmsg(fd, &send_message, 0);
    if (sent_message < 0 && nonblocking && errno == EAGAIN) {
        struct pollfd descriptor = {.fd = fd, .events = POLLOUT};
        if (poll(&descriptor, 1, 5000) > 0)
            sent_message = sendmsg(fd, &send_message, 0);
    }
    ssize_t received_message = recvmsg(fd, &recv_message, 0);
    if (received_message < 0 && nonblocking && errno == EAGAIN) {
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        if (poll(&descriptor, 1, 5000) > 0)
            received_message = recvmsg(fd, &recv_message, 0);
    }
    ok = ok && sent_to == (ssize_t)(sizeof(sendto_payload) - 1) &&
         received_from == (ssize_t)(sizeof(sendto_payload) - 1) &&
         memcmp(sendto_payload, response_to, sizeof(sendto_payload) - 1) == 0 &&
         sent_message == (ssize_t)(sizeof(sendmsg_payload) - 1) &&
         received_message == (ssize_t)(sizeof(sendmsg_payload) - 1) &&
         memcmp(sendmsg_payload, response_message, sizeof(sendmsg_payload) - 1) == 0;
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
    struct iovec vector = {(void *)data, sizeof(data)};
    if (lseek(fd, 0, SEEK_SET) < 0 || writev(fd, &vector, 1) != (ssize_t)sizeof(data)) {
        close(fd);
        return 0;
    }
    struct iovec read_vector = {readback, sizeof(readback)};
    memset(readback, 0, sizeof(readback));
    if (lseek(fd, 0, SEEK_SET) < 0 || readv(fd, &read_vector, 1) != (ssize_t)sizeof(data)) {
        close(fd);
        return 0;
    }
    if (pread(fd, readback, sizeof(data), 0) != (ssize_t)sizeof(data) ||
        pwrite(fd, data, sizeof(data), 0) != (ssize_t)sizeof(data)) {
        close(fd);
        return 0;
    }
    memset(readback, 0, sizeof(readback));
    if (pread(fd, readback, sizeof(data), 0) != (ssize_t)sizeof(data)) {
        close(fd);
        return 0;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return 0;
    }
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

static int writable_mapping_upgrade_probe(const char *path, int cleanup) {
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, 4096) != 0) {
        if (fd >= 0)
            close(fd);
        if (cleanup)
            unlink(path);
        return 0;
    }
    void *mapped = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        if (cleanup)
            unlink(path);
        return 0;
    }
    int protected = mprotect(mapped, 4096, PROT_READ | PROT_WRITE) == 0;
    if (protected)
        ((char *)mapped)[0] = 'x';
    int unmapped = munmap(mapped, 4096) == 0;
    if (cleanup)
        unlink(path);
    return protected && unmapped;
}

static int rename_probe(const char *old_path, const char *new_path, int cleanup) {
    int fd = open(old_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        return 0;
    close(fd);
    int ok = rename(old_path, new_path) == 0;
    if (cleanup) {
        unlink(old_path);
        unlink(new_path);
    }
    return ok;
}

static int unix_nonblocking_probe(int mode) {
    int socket_type = SOCK_STREAM | SOCK_CLOEXEC;
    if (mode == 0)
        socket_type |= SOCK_NONBLOCK;
    int fd = socket(AF_UNIX, socket_type, 0);
    if (fd < 0)
        return 0;

    if (mode == 1) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(fd);
            return 0;
        }
    } else if (mode == 2) {
        unsigned long enabled = 1;
        if (ioctl(fd, FIONBIO, &enabled) != 0) {
            close(fd);
            return 0;
        }
    }

    int flags = fcntl(fd, F_GETFL, 0);
    int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 100);
    if (duplicate >= 0)
        close(duplicate);
    duplicate = dup(fd);
    if (duplicate >= 0)
        close(duplicate);
    duplicate = dup2(fd, 200);
    if (duplicate >= 0)
        close(duplicate);
#ifdef __linux__
    duplicate = dup3(fd, 201, O_CLOEXEC);
    if (duplicate >= 0)
        close(duplicate);
#endif
    if (flags < 0 || (flags & O_NONBLOCK) == 0) {
        close(fd);
        return 0;
    }

    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    int written = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                           "hyperhub-nonblocking-%ld-%d", (long)getpid(), mode);
    if (written < 0 || (size_t)written >= sizeof(address.sun_path) - 1) {
        close(fd);
        return 0;
    }
    socklen_t address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + written);
    if (bind(fd, (const struct sockaddr *)&address, address_length) != 0 || listen(fd, 1) != 0) {
        close(fd);
        return 0;
    }

    int accepted = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    int ok = accepted < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    if (accepted >= 0)
        close(accepted);
    close(fd);
    return ok;
}

static int close_range_probe(void) {
#ifdef SYS_close_range
    int descriptors[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors) != 0)
        return 0;
    if (syscall(SYS_close_range, (unsigned int)descriptors[1],
                (unsigned int)descriptors[1], 0) != 0) {
        int error = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        return error == ENOSYS;
    }
    int ok = fcntl(descriptors[1], F_GETFD) < 0 && errno == EBADF;
    close(descriptors[0]);
    return ok;
#else
    return 1;
#endif
}

static void exercise_failed_execve(void) {
    char *arguments[] = {(char *)"/hyperhub-missing-executable", NULL};
    execve(arguments[0], arguments, environ);
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--leaf") == 0)
        return network_probe(argv[2], argv[3], 1, 0) ? 0 : 2;
    if (argc == 3 && strcmp(argv[1], "--intent-mprotect-write") == 0)
        return writable_mapping_upgrade_probe(argv[2], 0) ? 0 : 13;
    if (argc == 4 && strcmp(argv[1], "--intent-rename") == 0)
        return rename_probe(argv[2], argv[3], 0) ? 0 : 13;
    if (argc != 3)
        return 64;
    if (!network_probe(argv[1], argv[2], 0, 0) || !network_probe(argv[1], argv[2], 1, 1) ||
        !file_probe() || !writable_mapping_upgrade_probe("hyperhub-linux-fixture.mprotect", 1) ||
        !unix_nonblocking_probe(0) || !unix_nonblocking_probe(1) ||
        !unix_nonblocking_probe(2) || !close_range_probe())
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
