#define _GNU_SOURCE
/* A late pthread destructor performs IO after resident Rust TLS destructors.
 * Native Hooks must keep thread teardown safe without touching destroyed TLS. */
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_key_t file_key;
static int close_failed;
static void close_on_exit(void *value) {
    if (value != NULL && fclose((FILE *)value) != 0) close_failed = 1;
}
static void *worker(void *path) {
    FILE *file = fopen((const char *)path, "w");
    if (file == NULL) return (void *)(uintptr_t)1;
    if (pthread_setspecific(file_key, file) != 0) {
        fclose(file);
        return (void *)(uintptr_t)2;
    }
    if (fputs("thread teardown completed\n", file) < 0) return (void *)(uintptr_t)3;
    return NULL; /* fclose runs from the pthread key destructor. */
}
static atomic_uint exit_ready;
static void *exit_group_worker(void *unused) {
    (void)unused;
    atomic_fetch_add_explicit(&exit_ready, 1, memory_order_release);
    for (;;) {
        syscall(SYS_gettid);
        syscall(SYS_getpid);
        syscall(SYS_sched_yield);
    }
    return NULL;
}
static int exit_group_race(const char *count_text, const char *status_text) {
    char *end = NULL;
    unsigned long count = strtoul(count_text, &end, 10);
    if (!*count_text || *end || count < 2 || count > 64) return 20;
    long status = strtol(status_text, &end, 10);
    if (!*status_text || *end || status < 0 || status > 125) return 21;
    pthread_t threads[64];
    for (unsigned long index = 0; index < count; ++index) {
        if (pthread_create(&threads[index], NULL, exit_group_worker, NULL) != 0) return 22;
    }
    while (atomic_load_explicit(&exit_ready, memory_order_acquire) != count) sched_yield();
    printf("exit-group-race workers=%lu status=%ld\n", count, status);
    fflush(stdout);
    syscall(SYS_exit_group, status);
    return 23; /* A successful exit_group never returns. */
}
struct exec_arguments {
    const char *program;
    char leader[32];
};
static void *exec_worker(void *argument) {
    struct exec_arguments *args = argument;
    while (atomic_load_explicit(&exit_ready, memory_order_acquire) < 4) sched_yield();
    char *child[] = {(char *)args->program, "--exec-child", args->leader, NULL};
    execv(args->program, child);
    _exit(24);
}
static int nonleader_exec(const char *program) {
    struct exec_arguments args = {.program = program};
    snprintf(args.leader, sizeof(args.leader), "%ld", (long)getpid());
    pthread_t threads[4], executor;
    for (unsigned index = 0; index < 4; ++index) {
        if (pthread_create(&threads[index], NULL, exit_group_worker, NULL) != 0) return 25;
    }
    if (pthread_create(&executor, NULL, exec_worker, &args) != 0) return 26;
    for (;;) {
        syscall(SYS_getpid);
        syscall(SYS_sched_yield);
    }
    return 27;
}
int main(int argc, char **argv) {
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "--exit-group-race") == 0)
        return exit_group_race(argv[2], argc == 4 ? argv[3] : "7");
    if (argc == 2 && strcmp(argv[1], "--nonleader-exec") == 0)
        return nonleader_exec(argv[0]);
    if (argc == 3 && strcmp(argv[1], "--exec-child") == 0) {
        char *end = NULL;
        long leader = strtol(argv[2], &end, 10);
        if (!*argv[2] || *end || leader != (long)getpid()) return 28;
        printf("nonleader-exec identity-preserved\n");
        return 9;
    }
    if (argc != 2) return 10;
    if (pthread_key_create(&file_key, close_on_exit) != 0) return 11;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, argv[1]) != 0) return 12;
    void *result = NULL;
    if (pthread_join(thread, &result) != 0 || result != NULL || close_failed) return 13;
    pthread_key_delete(file_key);
    FILE *file = fopen(argv[1], "r");
    if (file == NULL) return 14;
    char line[64] = {0};
    int ok = fgets(line, sizeof(line), file) != NULL && strcmp(line, "thread teardown completed\n") == 0;
    if (fclose(file) != 0) return 15;
    return ok ? 0 : 16;
}
