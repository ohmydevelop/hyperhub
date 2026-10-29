#define _GNU_SOURCE
#include <glib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_eventfd
# ifdef __x86_64__
#  define SYS_eventfd 284
#  define SYS_eventfd2 290
# else
#  define SYS_eventfd 323
#  define SYS_eventfd2 328
# endif
#endif
#ifndef SYS_pipe2
# ifdef __x86_64__
#  define SYS_pipe2 293
# else
#  define SYS_pipe2 331
# endif
#endif
typedef struct _GWakeup GWakeup;
extern void glib_init (void);
extern GWakeup * g_wakeup_new (void);
extern void g_wakeup_get_pollfd (GWakeup *, GPollFD *);
extern void g_wakeup_free (GWakeup *);
extern long __real_syscall (long, ...);
extern int __real_fcntl (int, int, ...);
extern int __real_close (int);
extern gboolean __real_g_unix_open_pipe (gint *, gint, GError **);

static int mode, modern_calls, legacy_calls, legacy_fd = -1;
static int failure_injected, closed_before_pipe, pipe_entry_errno;

long
__wrap_syscall (long number, ...)
{
  va_list ap;
  unsigned int count;
  long result;
  int flags;
  va_start (ap, number);
  if (number == SYS_eventfd2)
    {
      count = va_arg (ap, unsigned int);
      flags = va_arg (ap, int);
      modern_calls++;
      if (mode != 0)
        {
          errno = mode == 2 ? EPERM : ENOSYS;
          result = -1;
        }
      else
        result = __real_syscall (number, count, flags);
    }
  else if (number == SYS_eventfd)
    {
      count = va_arg (ap, unsigned int);
      legacy_calls++;
      result = __real_syscall (number, count);
      legacy_fd = result;
    }
  else if (number == SYS_pipe2)
    {
      int * descriptors = va_arg (ap, int *);
      flags = va_arg (ap, int);
      result = __real_syscall (number, descriptors, flags);
    }
  else
    {
      /* Do not guess varargs for unrelated syscalls. */
      fprintf (stderr, "unexpected syscall in isolated GWakeup test: %ld\n", number);
      abort ();
    }
  va_end (ap);
  return result;
}

int
__wrap_fcntl (int fd, int command, ...)
{
  va_list ap;
  int argument = 0;
  static const int failures[] = { 0, 0, 0, F_GETFD, F_SETFD, F_GETFL, F_SETFL };
  if (command == F_SETFD || command == F_SETFL)
    {
      va_start (ap, command);
      argument = va_arg (ap, int);
      va_end (ap);
    }
  if (mode >= 3 && fd == legacy_fd && command == failures[mode] && !failure_injected)
    {
      failure_injected = 1;
      errno = EIO;
      return -1;
    }
  return __real_fcntl (fd, command, argument);
}

int
__wrap_fcntl64 (int fd, int command, ...)
{
  va_list ap;
  int argument = 0;
  if (command == F_SETFD || command == F_SETFL)
    {
      va_start (ap, command);
      argument = va_arg (ap, int);
      va_end (ap);
    }
  return __wrap_fcntl (fd, command, argument);
}

int
__wrap_close (int fd)
{
  int result = __real_close (fd);
  if (mode >= 3 && failure_injected && fd == legacy_fd)
    errno = EINTR; /* Verify g_try_eventfd restores the fcntl failure. */
  return result;
}

gboolean
__wrap_g_unix_open_pipe (gint * fds, gint flags, GError ** error)
{
  int saved_errno = errno;
  pipe_entry_errno = saved_errno;
  if (mode >= 3)
    closed_before_pipe = __real_fcntl (legacy_fd, F_GETFD) == -1 && errno == EBADF;
  errno = saved_errno;
  return __real_g_unix_open_pipe (fds, flags, error);
}

int
main (int argc, char ** argv)
{
  GWakeup * wakeup;
  GPollFD pollfd;
  int status, descriptor, passed;
  if (argc != 2 || (mode = atoi (argv[1])) < 0 || mode > 6)
    return 2;
  glib_init ();
  wakeup = g_wakeup_new ();
  g_wakeup_get_pollfd (wakeup, &pollfd);
  status = fcntl (pollfd.fd, F_GETFL);
  descriptor = fcntl (pollfd.fd, F_GETFD);
  passed = status >= 0 && descriptor >= 0 &&
      (status & O_NONBLOCK) && (descriptor & FD_CLOEXEC) && modern_calls == 1;
  if (mode == 0 || mode == 2)
    passed = passed && legacy_calls == 0;
  else
    passed = passed && legacy_calls == 1;
  if (mode >= 3)
    passed = passed && failure_injected && closed_before_pipe && pipe_entry_errno == EIO;
  if (mode == 2)
    passed = passed && pipe_entry_errno == EPERM;
  printf ("mode=%d modern=%d legacy=%d status=0x%x descriptor=0x%x injected=%d closed_before_pipe=%d pipe_errno=%d pass=%d\n",
      mode, modern_calls, legacy_calls, status, descriptor, failure_injected,
      closed_before_pipe, pipe_entry_errno, !!passed);
  g_wakeup_free (wakeup);
  return passed ? 0 : 1;
}
