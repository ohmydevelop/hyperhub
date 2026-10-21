/* A late pthread destructor performs IO after resident Rust TLS destructors.
 * Native Hooks must keep thread teardown safe without touching destroyed TLS. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
int main(int argc, char **argv) {
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
