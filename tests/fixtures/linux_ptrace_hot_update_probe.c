#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static int held_fd = -1;

static void run_read(const char *path) {
    char byte = 0;
    errno = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("read:denied:%d\n", errno);
        fflush(stdout);
        return;
    }
    ssize_t count = read(fd, &byte, 1);
    int error = errno;
    close(fd);
    if (count == 1) {
        puts("read:ok");
    } else {
        printf("read:denied:%d\n", error);
    }
    fflush(stdout);
}


static void hold_read_path(const char *path) {
    if (held_fd >= 0) {
        close(held_fd);
    }
    held_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (held_fd < 0) {
        printf("hold:denied:%d\n", errno);
    } else {
        puts("hold:ok");
    }
    fflush(stdout);
}

static void run_held_read(void) {
    char byte = 0;
    errno = 0;
    if (held_fd < 0) {
        puts("held-read:missing");
    } else if (read(held_fd, &byte, 1) == 1) {
        puts("held-read:ok");
    } else {
        printf("held-read:denied:%d\n", errno);
    }
    fflush(stdout);
}

static void run_exec(const char *path) {
    pid_t child = fork();
    if (child < 0) {
        printf("exec:denied:%d\n", errno);
        fflush(stdout);
        return;
    }
    if (child == 0) {
        execl(path, path, (char *)NULL);
        _exit(errno == EACCES ? 111 : 112);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        printf("exec:denied:%d\n", errno);
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        puts("exec:ok");
    } else {
        printf("exec:denied:%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : 128);
    }
    fflush(stdout);
}


static void run_spawn(const char *path) {
    pid_t child = 0;
    char *const arguments[] = {(char *)path, NULL};
    int result = posix_spawn(&child, path, NULL, NULL, arguments, environ);
    if (result != 0) {
        printf("spawn:denied:%d\n", result);
        fflush(stdout);
        return;
    }
    int status = 0;
    if (waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        puts("spawn:ok");
    } else {
        printf("spawn:denied:%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : 128);
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s READ_PATH EXECUTABLE\n", argv[0]);
        return 64;
    }
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ready");

    char command[64];
    while (fgets(command, sizeof(command), stdin) != NULL) {
        command[strcspn(command, "\r\n")] = '\0';
        if (strcmp(command, "read") == 0) {
            run_read(argv[1]);
        } else if (strcmp(command, "hold") == 0) {
            hold_read_path(argv[1]);
        } else if (strcmp(command, "held-read") == 0) {
            run_held_read();
        } else if (strcmp(command, "exec") == 0) {
            run_exec(argv[2]);
        } else if (strcmp(command, "spawn") == 0) {
            run_spawn(argv[2]);
        } else if (strcmp(command, "quit") == 0) {
            return 0;
        } else {
            printf("unknown:%s\n", command);
        }
    }
    return 0;
}
