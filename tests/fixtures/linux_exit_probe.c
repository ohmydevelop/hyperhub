#define _GNU_SOURCE
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

static pthread_t worker;
static _Atomic int worker_tid;
static _Atomic int worker_done;

static void map_once(void) {
    void *memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED || munmap(memory, 4096)) abort();
}
static void *first_io(void *unused) {
    (void)unused;
    atomic_store_explicit(&worker_tid, (int)syscall(SYS_gettid), memory_order_release);
    map_once();
    atomic_store_explicit(&worker_done, 1, memory_order_release);
    return NULL;
}
static int under_loader_lock(struct dl_phdr_info *info, size_t size, void *unused) {
    (void)info; (void)size; (void)unused;
    if (pthread_create(&worker, NULL, first_io, NULL)) abort();
    int tid;
    while (!(tid = atomic_load_explicit(&worker_tid, memory_order_acquire))) sched_yield();
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
    /* Inspect the other thread through raw syscalls: calling intercepted file
     * IO while holding the loader lock would obscure the mapping regression. */
    while (!atomic_load_explicit(&worker_done, memory_order_acquire)) {
        char state[128] = {0};
        int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) abort();
        long count = syscall(SYS_read, fd, state, sizeof(state) - 1);
        syscall(SYS_close, fd);
        if (count > 0 && strstr(state, "futex")) break;
        sched_yield();
    }
    map_once();
    return 1;
}
static int loader_race(void) {
    alarm(10);
    dl_iterate_phdr(under_loader_lock, NULL);
    if (pthread_join(worker, NULL)) return 5;
    alarm(0);
    return 7;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "loader")) return loader_race();
    if (!strcmp(argv[1], "exit")) exit(7);
    if (!strcmp(argv[1], "_exit")) _exit(7);
    if (!strcmp(argv[1], "_Exit")) _Exit(7);
    return 7;
}
