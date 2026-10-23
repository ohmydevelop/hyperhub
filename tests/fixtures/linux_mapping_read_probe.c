#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int mapping_fd(const char *path) {
    const char *inherited = getenv("HH_MAPPING_INHERITED_FD");
    if (!inherited) return open(path, O_RDWR);
    char *end = NULL;
    errno = 0;
    long number = strtol(inherited, &end, 10);
    if (errno || !*inherited || *end || number < 0 || number > INT_MAX) return -1;
    int fd = (int)number;
    struct stat actual, expected;
    int flags = fcntl(fd, F_GETFL);
    if (fstat(fd, &actual) != 0 || stat(path, &expected) != 0 ||
        !S_ISREG(actual.st_mode) || actual.st_dev != expected.st_dev ||
        actual.st_ino != expected.st_ino || actual.st_size != expected.st_size ||
        flags < 0 || (flags & O_ACCMODE) != O_RDWR || fcntl(fd, F_GETFD) != 0) {
        errno = EINVAL;
        return -1;
    }
    printf("mapping-fd=verified fd=%d device=%ju inode=%ju size=%jd\n", fd,
           (uintmax_t)actual.st_dev, (uintmax_t)actual.st_ino, (intmax_t)actual.st_size);
    return fd;
}

static int verify_memory(void *memory, int writable) {
    const char *expected = getenv("HH_MAPPING_EXPECTED_BYTE");
    if (!expected) return 1;
    char *end = NULL;
    long number = strtol(expected, &end, 10);
    if (!*expected || *end || number < 0 || number > UCHAR_MAX) return 0;
    volatile unsigned char *byte = memory;
    unsigned char original = (unsigned char)number;
    if (*byte != original) return 0;
    if (writable) {
        unsigned char changed = original ^ 1;
        *byte = changed;
        int valid = *byte == changed;
        *byte = original;
        return valid && *byte == original;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int fd = mapping_fd(argv[2]);
    if (fd < 0) { perror("mapping descriptor setup"); return 3; }
    if (!strcmp(argv[1], "write")) {
        ssize_t count = pwrite(fd, "x", 1, 0);
        close(fd);
        if (count == 1) puts("write-control=allowed");
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
        int valid = result == 0 ? verify_memory(memory, writable) : 1;
        munmap(memory, 4096);
        close(fd);
        if (result == -1 && error == EACCES) { puts("read-map=denied stage=mprotect"); return 13; }
        if (result == 0 && valid) { puts("read-map=allowed stage=mprotect"); return 0; }
        return 4;
    }
    int valid = memory != MAP_FAILED ? verify_memory(memory, writable) : 1;
    if (memory != MAP_FAILED) munmap(memory, 4096);
    close(fd);
    if (memory == MAP_FAILED && error == EACCES) { puts("read-map=denied stage=mmap"); return 13; }
    if (memory != MAP_FAILED && valid) { puts("read-map=allowed stage=mmap"); return 0; }
    return 5;
}
