#define _GNU_SOURCE
/* Plain execve error-return regression; optional report path also supports the
 * isolated Core runner. The regular Suite consumes stdout. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *
guarded_page (size_t page_size)
{
  void * memory = mmap (NULL, 2 * page_size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED || mprotect ((char *) memory + page_size, page_size, PROT_NONE) != 0)
    abort ();
  return memory;
}

int
main (int argc, char ** arguments)
{
  char self[4096], missing[4128];
  char * argv_data[] = { self, NULL };
  char * envp_data[] = { "EXECVE_ERROR_REGRESSION=1", NULL };
  char ** argv = argv_data;
  char ** envp = envp_data;
  const char * path = self;
  const char * test_case;
  size_t page_size = sysconf (_SC_PAGESIZE);
  char * guarded = guarded_page (page_size);
  char * unterminated = guarded + page_size - 16;
  int expected = EFAULT;
  int policy_control = 0;
  int native_result, native_errno, monitored_result, monitored_errno;
  unsigned int iteration;
  FILE * report;

  if ((argc != 2 && argc != 3) || realpath (arguments[0], self) == NULL)
    return 2;
  test_case = arguments[1];
  snprintf (missing, sizeof (missing), "%s.missing", self);
  memset (unterminated, 'x', 16);

  if (strcmp (test_case, "path-bad") == 0)
    path = (const char *) (uintptr_t) 1;
  else if (strcmp (test_case, "path-null") == 0)
    path = NULL;
  else if (strcmp (test_case, "argv-bad") == 0)
    argv = (char **) (uintptr_t) 1;
  else if (strcmp (test_case, "envp-bad") == 0)
    envp = (char **) (uintptr_t) 1;
  else if (strcmp (test_case, "argv-string-bad") == 0)
    argv_data[0] = (char *) (uintptr_t) 1;
  else if (strcmp (test_case, "envp-string-bad") == 0)
    envp_data[0] = (char *) (uintptr_t) 1;
  else if (strcmp (test_case, "path-guard") == 0)
    path = unterminated;
  else if (strcmp (test_case, "argv-guard") == 0)
  {
    argv = (char **) (guarded + page_size - sizeof (char *));
    argv[0] = self;
  }
  else if (strcmp (test_case, "envp-guard") == 0)
  {
    envp = (char **) (guarded + page_size - sizeof (char *));
    envp[0] = envp_data[0];
  }
  else if (strcmp (test_case, "argv-string-guard") == 0)
    argv_data[0] = unterminated;
  else if (strcmp (test_case, "envp-string-guard") == 0)
    envp_data[0] = unterminated;
  else if (strcmp (test_case, "valid-missing") == 0)
  {
    path = missing;
    expected = ENOENT;
  }
  else if (strcmp (test_case, "null-vectors-missing") == 0)
  {
    path = missing;
    argv = envp = NULL;
    expected = ENOENT;
  }
  else if (strcmp (test_case, "empty-vectors-missing") == 0)
  {
    path = missing;
    argv_data[0] = envp_data[0] = NULL;
    expected = ENOENT;
  }
  else if (strcmp (test_case, "policy-deny") == 0)
  {
    snprintf (missing, sizeof (missing), "%s.policy-denied", self);
    path = missing;
    expected = EACCES;
    policy_control = 1;
  }
  else if (strcmp (test_case, "over-budget-argv") == 0)
  {
    size_t length = 2 * 1024 * 1024;
    argv_data[0] = malloc (length + 1);
    if (argv_data[0] == NULL)
      abort ();
    memset (argv_data[0], 'x', length);
    argv_data[0][length] = '\0';
    expected = E2BIG;
  }
  else
    return 2;

  /* Repeated errors also exercise the monitor's prepare/cancel recovery. */
  for (iteration = 0; iteration != 3; iteration++)
  {
    /* The baseline bypasses libc listeners but uses exactly the same pointers. */
    errno = 77;
    native_result = syscall (SYS_execve, path, argv, envp);
    native_errno = errno;
    errno = 77;
    monitored_result = execve (path, argv, envp);
    monitored_errno = errno;
    if (native_result != -1 || monitored_result != -1 ||
        (policy_control ? (native_errno != ENOENT && native_errno != EACCES) : native_errno != expected) ||
        monitored_errno != expected)
      break;
  }

  /* The ptrace backend also mediates the raw syscall. In policy-control mode
   * it may deny that call too; the independent policy oracle is libc EACCES. */
  report = argc == 3 ? fopen (arguments[2], "w") : stdout;
  if (report == NULL)
    return 2;
  fprintf (report, "%s native=%d/%d libc=%d/%d expected=-1/%d\n", test_case,
      native_result, native_errno, monitored_result, monitored_errno, expected);
  if (argc == 3)
    fclose (report);
  return native_result == -1 && monitored_result == -1 &&
      (policy_control ? (native_errno == ENOENT || native_errno == EACCES) : native_errno == expected) &&
      monitored_errno == expected ? 0 : 1;
}
