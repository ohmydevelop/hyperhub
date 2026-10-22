#include <stdint.h>

/* The fixture compiler supplies its own process's callback address. The
 * constructor runs before dlopen releases the loader lock. */
__attribute__((constructor)) static void initialize(void) {
    ((void (*)(void))(uintptr_t)HYPERHUB_FIXTURE_CALLBACK)();
}
