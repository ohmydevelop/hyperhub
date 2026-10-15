#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct context { int fd; const char *mode; const char *program; };
static void *exec_thread(void *argument) {
    struct context *context = argument;
    char number[32];
    snprintf(number, sizeof(number), "%d", context->fd);
    execl(context->program, context->program, "thread-child", number, NULL);
    _exit(18);
}
static int replace_socket(void *argument) {
    struct context *context = argument;
    int fd = context->fd;
    if (!strcmp(context->mode, "exec")) {
        char number[32];
        snprintf(number, sizeof(number), "%d", fd);
        execl(context->program, context->program, "exec-child", number, NULL);
        return 18;
    }
    if (!strcmp(context->mode, "unshare")) {
        if (syscall(SYS_close_range, fd, fd, 1U << 1)) return 19;
    } else if (close(fd)) return 10;
    int replacement = socket(AF_INET, SOCK_DGRAM, 0);
    return replacement == fd ? 0 : 11;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "shared";
    if (!strcmp(mode, "thread-child")) {
        int fd = atoi(argv[2]);
        int flags = fcntl(fd, F_GETFL);
        close(fd);
        return flags >= 0 && (flags & O_NONBLOCK) ? 0 : 20;
    }
    if (!strcmp(mode, "exec-child")) {
        struct context context = {atoi(argv[2]), "shared", argv[0]};
        return replace_socket(&context);
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return 12;
    size_t size = 1024 * 1024;
    char *stack = malloc(size);
    if (!stack) return 13;
    struct context context = {fd, mode, argv[0]};
    if (!strcmp(mode, "thread-exec")) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, exec_thread, &context)) return 21;
        pthread_join(thread, NULL);
        return 22;
    }
    int clone_flags = SIGCHLD | (!strcmp(mode, "copy") ? 0 : CLONE_FILES);
    pid_t child = clone(replace_socket, stack + size, clone_flags, &context);
    if (child < 0) { perror("clone"); return 14; }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 15;
    int type = 0;
    socklen_t type_length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length)) return 16;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return 17;
    int nonblocking = strcmp(mode, "shared") != 0;
    printf("mode=%s actual_type=%d visible_nonblocking=%d expected_nonblocking=%d\n",
        mode, type, !!(flags & O_NONBLOCK), nonblocking);
    close(fd);
    free(stack);
    return type == (nonblocking ? SOCK_STREAM : SOCK_DGRAM) && !!(flags & O_NONBLOCK) == nonblocking ? 0 : 3;
}
