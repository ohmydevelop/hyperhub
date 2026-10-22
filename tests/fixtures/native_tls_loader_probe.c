/* A real loader-lock/pthread interleave and policy work in a later TLS dtor. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
static pthread_key_t late_key;
static atomic_int ok;
static atomic_int late_calls;
static int open_control(void) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char byte;
    int result = read(fd, &byte, 1) == 0;
    close(fd);
    return result;
}
static void late_destructor(void *value) {
    if (value && open_control()) atomic_fetch_add(&late_calls, 1);
}
static void *worker(void *unused) {
    (void)unused;
    void *memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return (void *)(intptr_t)1;
    ((char *)memory)[0] = 7;
    int result = open_control() && mprotect(memory, 4096, PROT_READ) == 0;
    munmap(memory, 4096);
    if (!result || pthread_setspecific(late_key, (void *)(intptr_t)1))
        return (void *)(intptr_t)2;
    return NULL;
}
__attribute__((constructor)) static void initialize(void) {
    if (pthread_key_create(&late_key, late_destructor)) return;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) return;
    void *result = NULL;
    /* dlopen owns the loader lock until this constructor returns. The worker's
       first Hook must not register a Rust __cxa_thread_atexit destructor. */
    if (!pthread_join(thread, &result) && !result && atomic_load(&late_calls) == 1)
        atomic_store(&ok, 1);
    pthread_key_delete(late_key);
}
int hh_loader_probe_ok(void) { return atomic_load(&ok); }
