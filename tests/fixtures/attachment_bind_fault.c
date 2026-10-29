/* A fixture-only, opt-in bind fault. No HyperHub product debug interface.
 * cc -std=c11 -Wall -Wextra -Werror -fPIC -shared attachment_bind_fault.c -o fault.so
 * cc -std=c11 -Wall -Wextra -Werror -DATTACHMENT_BIND_FAULT_ORACLE attachment_bind_fault.c -o oracle
 * The driver initializes a private MAP_SHARED file and supplies its path only
 * to the disposable target via HH_FIXTURE_BIND_FAULT_FILE and LD_PRELOAD.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

struct control {
    _Atomic uint32_t version, enabled, root_pid, hits, last_pid;
    _Atomic uint32_t root_bind_passes, child_bind_passes, path_length;
    char prefix[108], last_path[108];
};
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "fixture needs lock-free 32-bit shared atomics");
_Static_assert(offsetof(struct control, prefix) == 32 && sizeof(struct control) == 248,
               "control file layout must match the driver");
static struct control *mapped_control;

static struct control *map_control(const char *path, int initialize) {
    if (!path || !*path) return NULL;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | (initialize ? O_CREAT : 0), 0600);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) || (initialize && ftruncate(fd, sizeof(struct control))) ||
        (!initialize && st.st_size != (off_t)sizeof(struct control))) {
        close(fd); return NULL;
    }
    struct control *control = mmap(NULL, sizeof(*control), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    return control == MAP_FAILED ? NULL : control;
}

#ifndef ATTACHMENT_BIND_FAULT_ORACLE
__attribute__((constructor)) static void initialize_fault(void) {
    mapped_control = map_control(getenv("HH_FIXTURE_BIND_FAULT_FILE"), 0);
    if (!mapped_control || atomic_load_explicit(&mapped_control->version, memory_order_acquire) != 1) {
        mapped_control = NULL; return;
    }
    uint32_t absent = 0;
    atomic_compare_exchange_strong(&mapped_control->root_pid, &absent, (uint32_t)getpid());
}

int bind(int fd, const struct sockaddr *address, socklen_t length) {
    int saved_errno = errno;
    struct control *control = mapped_control;
    if (control && address && length >= sizeof(sa_family_t) && address->sa_family == AF_UNIX &&
        length > offsetof(struct sockaddr_un, sun_path) && length <= sizeof(struct sockaddr_un)) {
        const struct sockaddr_un *unix_address = (const struct sockaddr_un *)address;
        size_t available = length - offsetof(struct sockaddr_un, sun_path);
        size_t path_length = strnlen(unix_address->sun_path, available);
        size_t prefix_length = strnlen(control->prefix, sizeof(control->prefix));
        /* Abstract Frida sockets, the separate broker directory and business
           paths outside this exact private namespace cannot match. */
        if (unix_address->sun_path[0] == '/' && prefix_length > 1 && prefix_length < sizeof(control->prefix) &&
            control->prefix[prefix_length - 1] == '/' && path_length > prefix_length &&
            !memcmp(unix_address->sun_path, control->prefix, prefix_length)) {
            uint32_t pid = (uint32_t)getpid();
            if (pid == atomic_load(&control->root_pid)) {
                atomic_fetch_add(&control->root_bind_passes, 1);
            } else if (atomic_load_explicit(&control->enabled, memory_order_acquire)) {
                size_t copy = path_length < sizeof(control->last_path) - 1 ? path_length : sizeof(control->last_path) - 1;
                memcpy(control->last_path, unix_address->sun_path, copy);
                control->last_path[copy] = 0;
                atomic_store(&control->path_length, (uint32_t)copy);
                atomic_store(&control->last_pid, pid);
                atomic_fetch_add_explicit(&control->hits, 1, memory_order_release);
                errno = EADDRINUSE; return -1;
            } else {
                atomic_fetch_add(&control->child_bind_passes, 1);
            }
        }
    }
    errno = saved_errno;
    return (int)syscall(SYS_bind, fd, address, length);
}
#else
static int bind_path(const char *path, int abstract) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (length >= sizeof(address.sun_path) - (unsigned)abstract) { close(fd); errno = ENAMETOOLONG; return -1; }
    memcpy(address.sun_path + abstract, path, length + 1);
    socklen_t bytes = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
    int result = bind(fd, (struct sockaddr *)&address, bytes);
    int error = errno; close(fd); errno = error;
    if (!abstract && result == 0) unlink(path);
    return result;
}
static int child_status(pid_t pid) {
    int status = 0; pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int oracle(const char *business) {
    struct control *control = mapped_control;
    char root[108], child[108], abstract[80];
    int a = snprintf(root, sizeof(root), "%sroot", control->prefix);
    int b = snprintf(child, sizeof(child), "%schild", control->prefix);
    if (a < 0 || b < 0 || a >= (int)sizeof(root) || b >= (int)sizeof(child)) return 3;
    if (bind_path(root, 0)) return 4;
    pid_t pid = fork();
    if (pid == 0) {
        if (bind_path(child, 0) != -1 || errno != EADDRINUSE) _exit(5);
        snprintf(abstract, sizeof(abstract), "hh-bind-oracle-%ld", (long)getpid());
        if (bind_path(abstract, 1) || bind_path(business, 0)) _exit(6);
        _exit(0);
    }
    if (pid < 0 || !child_status(pid) || atomic_load(&control->last_pid) != (uint32_t)pid ||
        !atomic_load(&control->hits) || !atomic_load(&control->root_bind_passes)) return 7;
    atomic_store_explicit(&control->enabled, 0, memory_order_release);
    pid = fork();
    if (pid == 0) _exit(bind_path(child, 0) == 0 ? 0 : 8);
    if (pid < 0 || !child_status(pid) || !atomic_load(&control->child_bind_passes)) return 9;
    /* Native FIFO is the later live scenario's app-thread return witness. A
       writer must fail before the sole reader exists and observe a real S read. */
    char fifo[108]; int n = snprintf(fifo, sizeof(fifo), "%sfifo", control->prefix);
    if (n < 0 || n >= (int)sizeof(fifo) || mkfifo(fifo, 0600)) return 10;
    int writer = open(fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (writer != -1 || errno != ENXIO) return 11;
    pid = fork();
    if (pid == 0) {
        char value = 0; int reader = open(fifo, O_RDONLY | O_CLOEXEC);
        if (reader < 0 || read(reader, &value, 1) != 1 || value != 'S') _exit(12);
        close(reader); _exit(0);
    }
    for (unsigned attempt = 0; attempt < 500 && writer < 0; attempt++) {
        writer = open(fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (writer < 0 && errno != ENXIO) return 13;
        if (writer < 0) usleep(1000);
    }
    if (pid < 0 || writer < 0 || write(writer, "S", 1) != 1) {
        if (writer >= 0) close(writer);
        if (pid > 0) { kill(pid, SIGKILL); (void)child_status(pid); }
        unlink(fifo); return 14;
    }
    close(writer);
    if (!child_status(pid) || unlink(fifo)) return 15;
    printf("{\"status\":\"pass\",\"root_bind_allowed\":true,\"child_bind_denied\":true,\"abstract_and_business_allowed\":true,\"released_bind_allowed\":true,\"fifo_native_read\":true,\"fault_hits\":%u}\n", atomic_load(&control->hits));
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int initialize = !strcmp(argv[1], "--initialize");
    mapped_control = map_control(argv[2], initialize);
    if (!mapped_control) return 16;
    if (initialize) {
        if (argc != 4 || argv[3][0] != '/' || strlen(argv[3]) >= sizeof(mapped_control->prefix) ||
            argv[3][strlen(argv[3]) - 1] != '/') return 17;
        memset(mapped_control, 0, sizeof(*mapped_control));
        memcpy(mapped_control->prefix, argv[3], strlen(argv[3]) + 1);
        atomic_store_explicit(&mapped_control->version, 1, memory_order_release);
        return 0;
    }
    if (atomic_load_explicit(&mapped_control->version, memory_order_acquire) != 1) return 18;
    if (!strcmp(argv[1], "--enable")) { atomic_store_explicit(&mapped_control->enabled, 1, memory_order_release); return 0; }
    if (!strcmp(argv[1], "--disable")) { atomic_store_explicit(&mapped_control->enabled, 0, memory_order_release); return 0; }
    if (!strcmp(argv[1], "--oracle") && argc == 4) return oracle(argv[3]);
    return 19;
}
#endif
