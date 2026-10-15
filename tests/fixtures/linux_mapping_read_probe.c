#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int fd = open(argv[2], O_RDWR);
    if (fd < 0) { perror("open writable control"); return 3; }
    if (!strcmp(argv[1], "write")) {
        ssize_t count = pwrite(fd, "x", 1, 0);
        close(fd);
        return count == 1 ? 0 : 6;
    }
    int shared = !strcmp(argv[3], "shared") ? MAP_SHARED : MAP_PRIVATE;
    int upgrade = !strncmp(argv[1], "upgrade", 7);
    int writable = !strcmp(argv[1], "write-map") || !strcmp(argv[1], "upgrade-write");
    int protection = writable ? PROT_WRITE : PROT_READ;
    if (upgrade) protection = PROT_NONE;
    void *memory = mmap(NULL, 4096, protection, shared, fd, 0);
    int error = errno;
    if (memory != MAP_FAILED && upgrade) {
        int result = mprotect(memory, 4096, writable ? PROT_WRITE : PROT_READ);
        error = errno;
        munmap(memory, 4096);
        close(fd);
        if (result == -1 && error == EACCES) { puts("read-map=denied"); return 13; }
        return result == 0 ? 0 : 4;
    }
    if (memory != MAP_FAILED) munmap(memory, 4096);
    close(fd);
    if (memory == MAP_FAILED && error == EACCES) { puts("read-map=denied"); return 13; }
    return memory != MAP_FAILED ? 0 : 5;
}
