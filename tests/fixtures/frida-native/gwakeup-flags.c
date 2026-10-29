#define _GNU_SOURCE
#include <glib.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>

typedef struct _GWakeup GWakeup;
#ifdef FRIDA_PREFIXED
# define init_glib _frida_glib_init
# define wakeup_new _frida_g_wakeup_new
# define wakeup_get_pollfd _frida_g_wakeup_get_pollfd
# define wakeup_free _frida_g_wakeup_free
# define wakeup_signal _frida_g_wakeup_signal
# define wakeup_acknowledge _frida_g_wakeup_acknowledge
#else
# define init_glib glib_init
# define wakeup_new g_wakeup_new
# define wakeup_get_pollfd g_wakeup_get_pollfd
# define wakeup_free g_wakeup_free
# define wakeup_signal g_wakeup_signal
# define wakeup_acknowledge g_wakeup_acknowledge
#endif
extern void init_glib (void);
extern GWakeup * wakeup_new (void);
extern void wakeup_get_pollfd (GWakeup *, GPollFD *);
extern void wakeup_free (GWakeup *);
extern void wakeup_signal (GWakeup *);
extern void wakeup_acknowledge (GWakeup *);

int
main (void)
{
  GWakeup * wakeup;
  GPollFD pollfd;
  int status, descriptor, released, cycle = 0;

  init_glib ();
  wakeup = wakeup_new ();
  wakeup_get_pollfd (wakeup, &pollfd);
  status = fcntl (pollfd.fd, F_GETFL);
  descriptor = fcntl (pollfd.fd, F_GETFD);
  if (status == -1 || descriptor == -1)
    return 2;
  printf ("wakeup fd=%d F_GETFL=0x%x F_GETFD=0x%x nonblock=%d cloexec=%d\n",
      pollfd.fd, status, descriptor, !!(status & O_NONBLOCK), !!(descriptor & FD_CLOEXEC));

  if ((status & O_NONBLOCK) && (descriptor & FD_CLOEXEC))
    {
      struct pollfd readable = { pollfd.fd, POLLIN, 0 };
      /* Empty acknowledge must return; the subprocess watchdog bounds a bug. */
      wakeup_acknowledge (wakeup);
      wakeup_signal (wakeup);
      if (poll (&readable, 1, 0) == 1 && (readable.revents & POLLIN))
        {
          wakeup_acknowledge (wakeup);
          cycle = poll (&readable, 1, 0) == 0;
          wakeup_acknowledge (wakeup);
        }
    }
  printf ("signal_acknowledge_empty_cycle=%d\n", cycle);

  /* Release only through the owning API; never close guessed descriptors. */
  wakeup_free (wakeup);
  errno = 0;
  released = fcntl (pollfd.fd, F_GETFD) == -1 && errno == EBADF;
  printf ("owner_release_closed_fd=%d\n", released);
  return (status & O_NONBLOCK) && (descriptor & FD_CLOEXEC) && released && cycle ? 0 : 1;
}
