#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
static long raw_syscall0(long number) {
    long result;
    __asm__ volatile ("syscall" : "=a"(result) : "a"(number) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long arg1) {
    long result;
    __asm__ volatile ("syscall" : "=a"(result) : "a"(number), "D"(arg1) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long arg1, long arg2) {
    long result;
    __asm__ volatile ("syscall"
                      : "=a"(result)
                      : "a"(number), "D"(arg1), "S"(arg2)
                      : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long arg1, long arg2, long arg3) {
    long result;
    __asm__ volatile ("syscall"
                      : "=a"(result)
                      : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3)
                      : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long arg1, long arg2, long arg3, long arg4) {
    long result;
    register long register4 __asm__("r10") = arg4;
    __asm__ volatile ("syscall"
                      : "=a"(result)
                      : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(register4)
                      : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long arg1, long arg2, long arg3, long arg4, long arg5) {
    long result;
    register long register4 __asm__("r10") = arg4;
    register long register5 __asm__("r8") = arg5;
    __asm__ volatile ("syscall"
                      : "=a"(result)
                      : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(register4), "r"(register5)
                      : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long result;
    register long register4 __asm__("r10") = arg4;
    register long register5 __asm__("r8") = arg5;
    register long register6 __asm__("r9") = arg6;
    __asm__ volatile ("syscall"
                      : "=a"(result)
                      : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(register4), "r"(register5), "r"(register6)
                      : "rcx", "r11", "memory");
    return result;
}
#elif defined(__aarch64__)
static long raw_syscall0(long number) {
    register long result __asm__("x0");
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "=r"(result) : "r"(syscall_number) : "memory");
    return result;
}

static long raw_syscall1(long number, long arg1) {
    register long result __asm__("x0") = arg1;
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "+r"(result) : "r"(syscall_number) : "memory");
    return result;
}

static long raw_syscall2(long number, long arg1, long arg2) {
    register long result __asm__("x0") = arg1;
    register long register2 __asm__("x1") = arg2;
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "+r"(result) : "r"(register2), "r"(syscall_number) : "memory");
    return result;
}

static long raw_syscall3(long number, long arg1, long arg2, long arg3) {
    register long result __asm__("x0") = arg1;
    register long register2 __asm__("x1") = arg2;
    register long register3 __asm__("x2") = arg3;
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "+r"(result) : "r"(register2), "r"(register3), "r"(syscall_number) : "memory");
    return result;
}

static long raw_syscall4(long number, long arg1, long arg2, long arg3, long arg4) {
    register long result __asm__("x0") = arg1;
    register long register2 __asm__("x1") = arg2;
    register long register3 __asm__("x2") = arg3;
    register long register4 __asm__("x3") = arg4;
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "+r"(result) : "r"(register2), "r"(register3), "r"(register4), "r"(syscall_number) : "memory");
    return result;
}

static long raw_syscall5(long number, long arg1, long arg2, long arg3, long arg4, long arg5) {
    register long result __asm__("x0") = arg1;
    register long register2 __asm__("x1") = arg2;
    register long register3 __asm__("x2") = arg3;
    register long register4 __asm__("x3") = arg4;
    register long register5 __asm__("x4") = arg5;
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "+r"(result) : "r"(register2), "r"(register3), "r"(register4), "r"(register5), "r"(syscall_number) : "memory");
    return result;
}

static long raw_syscall6(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    register long result __asm__("x0") = arg1;
    register long register2 __asm__("x1") = arg2;
    register long register3 __asm__("x2") = arg3;
    register long register4 __asm__("x3") = arg4;
    register long register5 __asm__("x4") = arg5;
    register long register6 __asm__("x5") = arg6;
    register long syscall_number __asm__("x8") = number;
    __asm__ volatile ("svc 0" : "+r"(result) : "r"(register2), "r"(register3), "r"(register4), "r"(register5), "r"(register6), "r"(syscall_number) : "memory");
    return result;
}
#else
#error "linux_static_probe supports x86_64 and aarch64 only"
#endif

static int is_negative(long value) {
    return value < 0;
}

static size_t text_length(const char *value) {
    size_t length = 0;
    while (value[length] != '\0') {
        length += 1;
    }
    return length;
}

static void write_text(const char *value) {
    raw_syscall3(SYS_write, STDOUT_FILENO, (long)value, (long)text_length(value));
}

static int text_equals(const char *left, const char *right) {
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return 0;
        }
        index += 1;
    }
    return left[index] == right[index];
}

static size_t append_unsigned(char *output, size_t offset, unsigned long value) {
    char digits[24];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count != 0) {
        output[offset++] = digits[--count];
    }
    output[offset] = '\0';
    return offset;
}

static int parse_port(const char *value) {
    int port = 0;
    size_t index = 0;
    while (value[index] >= '0' && value[index] <= '9') {
        port = port * 10 + value[index++] - '0';
        if (port > 65535) {
            return -1;
        }
    }
    return value[index] == '\0' && port > 0 ? port : -1;
}

static int parse_ipv4(const char *value, unsigned char output[4]) {
    int part = 0;
    int count = 0;
    size_t index = 0;
    for (;;) {
        if (value[index] >= '0' && value[index] <= '9') {
            part = part * 10 + value[index++] - '0';
            if (part > 255) {
                return 0;
            }
            continue;
        }
        if ((value[index] == '.' || value[index] == '\0') && count < 4) {
            output[count++] = (unsigned char)part;
            part = 0;
            if (value[index] == '\0') {
                return count == 4;
            }
            index += 1;
            continue;
        }
        return 0;
    }
}

static void exercise_file_hook_variants(long fd, const char *path) {
    char buffer[32] = {0};
    const char extra[] = "variant";
    struct iovec write_iov = {(void *)extra, sizeof(extra) - 1};
    struct iovec read_iov = {buffer, sizeof(buffer)};
#ifdef SYS_pread64
    raw_syscall4(SYS_pread64, fd, (long)buffer, sizeof(buffer), 0);
#endif
#ifdef SYS_pwrite64
    raw_syscall4(SYS_pwrite64, fd, (long)extra, sizeof(extra) - 1, 0);
#endif
#ifdef SYS_readv
    raw_syscall3(SYS_readv, fd, (long)&read_iov, 1);
#endif
#ifdef SYS_writev
    raw_syscall3(SYS_writev, fd, (long)&write_iov, 1);
#endif
#ifdef SYS_preadv
    raw_syscall5(SYS_preadv, fd, (long)&read_iov, 1, 0, 0);
#endif
#ifdef SYS_pwritev
    raw_syscall5(SYS_pwritev, fd, (long)&write_iov, 1, 0, 0);
#endif
#ifdef SYS_preadv2
    raw_syscall6(SYS_preadv2, fd, (long)&read_iov, 1, 0, 0, 0);
#endif
#ifdef SYS_pwritev2
    raw_syscall6(SYS_pwritev2, fd, (long)&write_iov, 1, 0, 0, 0);
#endif
#ifdef SYS_open
    long opened = raw_syscall3(SYS_open, (long)path, O_RDONLY, 0);
    if (!is_negative(opened)) raw_syscall1(SYS_close, opened);
#endif
#ifdef SYS_openat2
    struct {
        unsigned long flags;
        unsigned long mode;
        unsigned long resolve;
    } how = {O_RDONLY, 0, 0};
    long opened2 = raw_syscall4(SYS_openat2, AT_FDCWD, (long)path, (long)&how, sizeof(how));
    if (!is_negative(opened2)) raw_syscall1(SYS_close, opened2);
#endif
#ifdef SYS_creat
    char created[128] = "/tmp/hyperhub-static-creat-variant";
    long created_fd = raw_syscall2(SYS_creat, (long)created, 0600);
    if (!is_negative(created_fd)) raw_syscall1(SYS_close, created_fd);
    raw_syscall1(SYS_unlink, (long)created);
#endif
#ifdef SYS_rename
    raw_syscall2(SYS_rename, (long)"/tmp/hyperhub-missing-old", (long)"/tmp/hyperhub-missing-new");
#endif
#ifdef SYS_unlink
    raw_syscall1(SYS_unlink, (long)"/tmp/hyperhub-missing-unlink");
#endif
#ifdef SYS_renameat2
    raw_syscall5(SYS_renameat2, AT_FDCWD, (long)"/tmp/hyperhub-missing-old2", AT_FDCWD,
                 (long)"/tmp/hyperhub-missing-new2", 0);
#endif
}

static int run_file_probe(void) {
    char path[128] = "/tmp/hyperhub-static-probe-";
    char renamed[128] = "/tmp/hyperhub-static-probe-renamed-";
    unsigned long pid = (unsigned long)raw_syscall0(SYS_getpid);
    size_t path_length = append_unsigned(path, text_length(path), pid);
    size_t renamed_length = append_unsigned(renamed, text_length(renamed), pid);
    (void)path_length;
    (void)renamed_length;

    long fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (is_negative(fd)) {
        return 0;
    }
    const char payload[] = "static-direct-syscall";
    if (is_negative(raw_syscall3(SYS_write, fd, (long)payload, sizeof(payload) - 1)) ||
        is_negative(raw_syscall3(SYS_lseek, fd, 0, SEEK_SET))) {
        raw_syscall1(SYS_close, fd);
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
        return 0;
    }
    char readback[sizeof(payload)] = {0};
    if (raw_syscall3(SYS_read, fd, (long)readback, sizeof(payload) - 1) != (long)(sizeof(payload) - 1)) {
        raw_syscall1(SYS_close, fd);
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
        return 0;
    }
    exercise_file_hook_variants(fd, path);
    long mapped = raw_syscall6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (is_negative(mapped)) {
        raw_syscall1(SYS_close, fd);
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
        return 0;
    }
    ((char *)mapped)[0] = 'S';
    if (is_negative(raw_syscall3(SYS_mprotect, mapped, 4096, PROT_READ)) ||
        is_negative(raw_syscall2(SYS_munmap, mapped, 4096))) {
        raw_syscall1(SYS_close, fd);
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
        return 0;
    }
    long flags = raw_syscall3(SYS_fcntl, fd, F_GETFL, 0);
    if (is_negative(flags) || is_negative(raw_syscall3(SYS_fcntl, fd, F_SETFL, flags))) {
        raw_syscall1(SYS_close, fd);
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
        return 0;
    }
    raw_syscall1(SYS_close, fd);
    if (is_negative(raw_syscall4(SYS_renameat, AT_FDCWD, (long)path, AT_FDCWD, (long)renamed)) ||
        is_negative(raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)renamed, 0))) {
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0);
        return 0;
    }

    long ca_fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)"/etc/ssl/certs/ca-certificates.crt", O_RDONLY, 0);
    if (!is_negative(ca_fd)) {
        char ca_prefix[64];
        raw_syscall3(SYS_read, ca_fd, (long)ca_prefix, sizeof(ca_prefix));
        raw_syscall1(SYS_close, ca_fd);
    }
    return text_equals(readback, payload);
}

static int exchange_payload(long fd, const char *payload, size_t length, int mode) {
    char response[64] = {0};
    long sent;
    long received;
    if (mode == 0) {
        sent = raw_syscall6(SYS_sendto, fd, (long)payload, length, 0, 0, 0);
        received = raw_syscall6(SYS_recvfrom, fd, (long)response, length, 0, 0, 0);
    } else if (mode == 1) {
        sent = raw_syscall3(SYS_write, fd, (long)payload, length);
        received = raw_syscall3(SYS_read, fd, (long)response, length);
    } else {
        struct iovec send_iov = {(void *)payload, length};
        struct iovec recv_iov = {response, length};
        struct msghdr send_message = {0};
        struct msghdr recv_message = {0};
        send_message.msg_iov = &send_iov;
        send_message.msg_iovlen = 1;
        recv_message.msg_iov = &recv_iov;
        recv_message.msg_iovlen = 1;
        sent = raw_syscall3(SYS_sendmsg, fd, (long)&send_message, 0);
        received = raw_syscall3(SYS_recvmsg, fd, (long)&recv_message, 0);
    }
    return sent == (long)length && received == (long)length && text_equals(response, payload);
}

static int run_network_probe(const char *host, const char *port_text) {
    unsigned char address_bytes[4];
    int port = parse_port(port_text);
    if (port < 0 || !parse_ipv4(host, address_bytes)) return 0;
    long fd = raw_syscall3(SYS_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (is_negative(fd)) return 0;
    int nonblocking = 0;
    raw_syscall3(SYS_ioctl, fd, FIONBIO, (long)&nonblocking);
    long duplicated = raw_syscall1(SYS_dup, fd);
    if (!is_negative(duplicated)) raw_syscall1(SYS_close, duplicated);
#ifdef SYS_dup2
    long duplicated2 = raw_syscall2(SYS_dup2, fd, 100);
    if (!is_negative(duplicated2)) raw_syscall1(SYS_close, duplicated2);
#endif
#ifdef SYS_dup3
    long duplicated3 = raw_syscall3(SYS_dup3, fd, 101, O_CLOEXEC);
    if (!is_negative(duplicated3)) raw_syscall1(SYS_close, duplicated3);
#endif
    long fcntl_dup = raw_syscall3(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 102);
    if (!is_negative(fcntl_dup)) raw_syscall1(SYS_close, fcntl_dup);

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = (unsigned short)((port >> 8) | (port << 8));
    unsigned char *raw_address = (unsigned char *)&address.sin_addr.s_addr;
    raw_address[0] = address_bytes[0]; raw_address[1] = address_bytes[1];
    raw_address[2] = address_bytes[2]; raw_address[3] = address_bytes[3];
    long connected = raw_syscall3(SYS_connect, fd, (long)&address, sizeof(address));
    if (is_negative(connected)) { raw_syscall1(SYS_close, fd); return 0; }
    int socket_error = 0;
    unsigned int socket_error_length = sizeof(socket_error);
    raw_syscall5(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, (long)&socket_error,
                 (long)&socket_error_length);
    const char sendto_payload[] = "hyperhub-sendto";
    const char write_payload[] = "hyperhub-write";
    const char sendmsg_payload[] = "hyperhub-sendmsg";
    int ok = exchange_payload(fd, sendto_payload, sizeof(sendto_payload) - 1, 0) &&
             exchange_payload(fd, write_payload, sizeof(write_payload) - 1, 1) &&
             exchange_payload(fd, sendmsg_payload, sizeof(sendmsg_payload) - 1, 2);
    raw_syscall1(SYS_close, fd);
    return ok;
}

static size_t build_dns_query(unsigned char *output, unsigned short transaction) {
    unsigned char query[] = {
        0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0,
        0, 1, 0, 1
    };
    query[0] = (unsigned char)(transaction >> 8);
    query[1] = (unsigned char)transaction;
    for (size_t i = 0; i < sizeof(query); i++) output[i] = query[i];
    return sizeof(query);
}

static int run_dns_probe(const char *port_text) {
    int port = parse_port(port_text);
    if (port < 0) return 0;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = (unsigned short)((port >> 8) | (port << 8));
    ((unsigned char *)&address.sin_addr.s_addr)[0] = 127;
    ((unsigned char *)&address.sin_addr.s_addr)[3] = 1;
    unsigned char query[64];
    unsigned char response[512];
    size_t query_length = build_dns_query(query, 0x1234);

    long fd = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (is_negative(fd)) return 0;
    if (is_negative(raw_syscall6(SYS_sendto, fd, (long)query, query_length, 0,
                                 (long)&address, sizeof(address))) ||
        is_negative(raw_syscall6(SYS_recvfrom, fd, (long)response, sizeof(response), 0, 0, 0))) {
        raw_syscall1(SYS_close, fd); return 0;
    }
    raw_syscall1(SYS_close, fd);

    fd = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (is_negative(fd) || is_negative(raw_syscall3(SYS_connect, fd, (long)&address, sizeof(address)))) return 0;
    query_length = build_dns_query(query, 0x1235);
    if (is_negative(raw_syscall3(SYS_write, fd, (long)query, query_length)) ||
        is_negative(raw_syscall3(SYS_read, fd, (long)response, sizeof(response)))) {
        raw_syscall1(SYS_close, fd); return 0;
    }
    raw_syscall1(SYS_close, fd);

    fd = raw_syscall3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (is_negative(fd)) return 0;
    query_length = build_dns_query(query, 0x1236);
    struct iovec send_iov = {query, query_length};
    struct iovec recv_iov = {response, sizeof(response)};
    struct msghdr send_message = {0};
    struct msghdr recv_message = {0};
    send_message.msg_name = &address; send_message.msg_namelen = sizeof(address);
    send_message.msg_iov = &send_iov; send_message.msg_iovlen = 1;
    recv_message.msg_iov = &recv_iov; recv_message.msg_iovlen = 1;
    int ok = !is_negative(raw_syscall3(SYS_sendmsg, fd, (long)&send_message, 0)) &&
             !is_negative(raw_syscall3(SYS_recvmsg, fd, (long)&recv_message, 0));
    raw_syscall1(SYS_close, fd);
    return ok;
}

static void exercise_process_hook_variants(void) {
#ifdef SYS_clone3
    raw_syscall2(SYS_clone3, 0, 0);
#endif
#ifdef SYS_execveat
    char *arguments[] = {(char *)"missing", 0};
    char *environment[] = {0};
    raw_syscall5(SYS_execveat, AT_FDCWD, (long)"/hyperhub-missing-exec", (long)arguments,
                 (long)environment, 0);
#endif
#ifdef SYS_fork
    long child = raw_syscall0(SYS_fork);
    if (child == 0) raw_syscall1(SYS_exit, 0);
    if (child > 0) { int status = 0; raw_syscall4(SYS_wait4, child, (long)&status, 0, 0); }
#endif
#ifdef SYS_vfork
    long vchild = raw_syscall0(SYS_vfork);
    if (vchild == 0) raw_syscall1(SYS_exit, 0);
    if (vchild > 0) { int status = 0; raw_syscall4(SYS_wait4, vchild, (long)&status, 0, 0); }
#endif
}

static int run_process_probe(const char *host, const char *port) {
    exercise_process_hook_variants();
    long child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        char *arguments[] = {(char *)"/proc/self/exe", (char *)"--child", (char *)host, (char *)port, 0};
        char *environment[] = {0};
        raw_syscall3(SYS_execve, (long)arguments[0], (long)arguments, (long)environment);
        raw_syscall1(SYS_exit, 127);
    }
    int status = 0;
    long waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    return !is_negative(waited) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_intent_mode(int argc, char **argv) {
    if (argc == 3 && text_equals(argv[1], "--intent-create")) {
        long fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)argv[2], O_CREAT | O_WRONLY, 0600);
        if (!is_negative(fd)) raw_syscall1(SYS_close, fd);
        return is_negative(fd) ? 13 : 0;
    }
    if (argc == 3 && text_equals(argv[1], "--intent-read")) {
        long fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)argv[2], O_RDONLY, 0);
        if (is_negative(fd)) return 13;
        char byte = 0;
        long result = raw_syscall3(SYS_read, fd, (long)&byte, 1);
        raw_syscall1(SYS_close, fd);
        return is_negative(result) ? 13 : 0;
    }
    if (argc == 3 && text_equals(argv[1], "--intent-write")) {
        long fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)argv[2], O_WRONLY, 0);
        if (is_negative(fd)) return 13;
        const char byte = 'x';
        long result = raw_syscall3(SYS_write, fd, (long)&byte, 1);
        raw_syscall1(SYS_close, fd);
        return is_negative(result) ? 13 : 0;
    }
    if (argc == 3 && text_equals(argv[1], "--intent-delete")) {
        long result = raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)argv[2], 0);
        return is_negative(result) ? 13 : 0;
    }
    if (argc == 4 && text_equals(argv[1], "--intent-rename")) {
        long result = raw_syscall4(SYS_renameat, AT_FDCWD, (long)argv[2], AT_FDCWD, (long)argv[3]);
        return is_negative(result) ? 13 : 0;
    }
    if (argc == 2 && text_equals(argv[1], "--intent-fork")) {
        long child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
        if (child < 0) return 13;
        if (child == 0) raw_syscall1(SYS_exit, 0);
        int status = 0;
        return is_negative(raw_syscall4(SYS_wait4, child, (long)&status, 0, 0)) ? 13 : 0;
    }
    if (argc == 3 && text_equals(argv[1], "--intent-exec")) {
        char *arguments[] = {argv[2], 0};
        char *environment[] = {0};
        raw_syscall3(SYS_execve, (long)argv[2], (long)arguments, (long)environment);
        return 13;
    }
    if (argc == 3 && text_equals(argv[1], "--intent-child-exec")) {
        long child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
        if (child < 0) return 13;
        if (child == 0) {
            char *arguments[] = {argv[2], 0};
            char *environment[] = {0};
            raw_syscall3(SYS_execve, (long)argv[2], (long)arguments, (long)environment);
            raw_syscall1(SYS_exit, 13);
        }
        int status = 0;
        if (is_negative(raw_syscall4(SYS_wait4, child, (long)&status, 0, 0))) return 13;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 13;
    }
    return -1;
}

int main(int argc, char **argv) {
    int intent_result = run_intent_mode(argc, argv);
    if (intent_result >= 0) return intent_result;
    if (argc == 4 && text_equals(argv[1], "--child")) {
        if (!run_network_probe(argv[2], argv[3])) {
            write_text("static-direct-child-failed\n");
            return 1;
        }
        write_text("static-direct-child-ok\n");
        return 0;
    }
    const char *host = argc > 2 ? argv[1] : "127.0.0.1";
    const char *port = argc > 2 ? argv[2] : "1";
    const char *dns_port = argc > 3 ? argv[3] : "1";
    if (!run_file_probe() || !run_dns_probe(dns_port) || !run_network_probe(host, port) ||
        !run_process_probe(host, port)) {
        write_text("static-direct-probe-failed\n");
        return 1;
    }
    write_text("static-direct-probe-ok\n");
    return 0;
}
