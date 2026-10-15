#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "exit")) exit(7);
    if (!strcmp(argv[1], "_exit")) _exit(7);
    if (!strcmp(argv[1], "_Exit")) _Exit(7);
    return 7;
}
