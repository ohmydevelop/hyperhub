#include "frida-core.h"
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Fork-recovery inherited-socket disconnect regression.
 *
 * The target registers a libc child-atfork callback before Frida is attached.
 * Gum's fork interceptor runs its on-enter callback before libc fork(), while
 * libc runs child-atfork callbacks before fork() returns to Gum's on-leave
 * callback. The fault therefore closes only the fork child's inherited
 * sockets after Frida prepared the child transport, but before Frida tries to
 * recover it. The target owns no application sockets, so every closed socket
 * belongs to the injected runtime; the four fixture pipes remain open.
 *
 *   plain                 normal gated fork and complete child unload.
 *   child-close           close inherited runtime sockets before recovery.
 *   eternal-control       normal fork with an eternal script.
 *   eternal-child-close   same socket fault with eternal child state.
 *   controller-close-fork close the controller before an eternal target forks.
 *   controller-exit-fork  force controller-loss recovery while an eternal
 *                         target enters a real fork.
 */
static FridaDevice * device;
static pid_t target_pid, child_pid;
static int target_keep_fds[4];
static int target_max_fd;
static volatile sig_atomic_t target_closed_sockets;
static volatile sig_atomic_t regression_disconnect_before_prepare;

/* The patched agent resolves this weak symbol only in this executable. A
 * normal target does not export it, so production behavior is unchanged. */
__attribute__ ((visibility ("default")))
int
hyperhub_frida_regression_disconnect_before_prepare_v1 (void)
{
  return __atomic_exchange_n (&regression_disconnect_before_prepare, 0,
      __ATOMIC_SEQ_CST);
}

static gboolean target_keeps_fd (int fd) {
  for (size_t i = 0; i != G_N_ELEMENTS (target_keep_fds); i++)
    if (target_keep_fds[i] == fd) return TRUE;
  return FALSE;
}

static void close_child_runtime_sockets (void) {
  int closed = 0;
  for (int fd = STDERR_FILENO + 1; fd < target_max_fd; fd++) {
    struct stat state;
    if (target_keeps_fd (fd)) continue;
    if (fstat (fd, &state) == 0 && S_ISSOCK (state.st_mode) && close (fd) == 0)
      closed++;
  }
  target_closed_sockets = closed;
}

static void watchdog (int signal_number) {
  const char message[] = "FAIL stage=oracle-watchdog\n";
  (void) signal_number;
  write (STDERR_FILENO, message, sizeof message - 1);
  if (child_pid > 0) kill (child_pid, SIGKILL);
  if (target_pid > 0) {
    kill (target_pid, SIGKILL);
  }
  _exit (124);
}

static void fail (const char * stage, GError * error) {
  fprintf (stderr, "FAIL stage=%s error=%s\n", stage,
      error != NULL ? error->message : strerror (errno));
  if (child_pid > 0) kill (child_pid, SIGKILL);
  if (target_pid > 0) {
    kill (target_pid, SIGKILL);
    waitpid (target_pid, NULL, 0);
  }
  exit (1);
}

static void checked (const char * stage, GError * error) {
  if (error != NULL) fail (stage, error);
  printf ("OK stage=%s\n", stage); fflush (stdout);
}

static void require (gboolean condition, const char * stage) {
  if (!condition) fail (stage, NULL);
}

static void send_byte (int fd, char byte) {
  if (write (fd, &byte, 1) != 1) fail ("owned-pipe-write", NULL);
}

static void receive (int fd, void * result, size_t length) {
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  size_t offset = 0;
  while (offset != length) {
    struct pollfd p = { fd, POLLIN, 0 };
    while (g_main_context_iteration (NULL, FALSE)) ;
    if (g_get_monotonic_time () >= deadline) { errno = ETIMEDOUT; fail ("owned-pipe-read", NULL); }
    if (poll (&p, 1, 10) > 0) {
      ssize_t n = read (fd, (char *) result + offset, length - offset);
      if (n <= 0) fail ("owned-pipe-eof", NULL);
      offset += n;
    }
  }
}

static FridaSession * attach (guint pid, const char * stage) {
  GError * error = NULL;
  FridaSessionOptions * options = frida_session_options_new ();
  frida_session_options_set_exit_monitor (options, FALSE);
  FridaSession * session = frida_device_attach_sync (device, pid, options, NULL, &error);
  frida_unref (options);
  checked (stage, error);
  return session;
}

static void detach (FridaSession * session, const char * stage) {
  GError * error = NULL;
  frida_session_detach_sync (session, NULL, &error);
  checked (stage, error);
  frida_unref (session);
}

static void enable_gating (FridaSession * session, const char * stage) {
  GError * error = NULL;
  frida_session_enable_child_gating_sync (session, NULL, &error);
  checked (stage, error);
}

static void probe (guint pid, const char * stage) {
  GError * error = NULL;
  FridaSession * session = attach (pid, stage);
  FridaScript * script = frida_session_create_script_sync (session,
      "globalThis.oracleProbe = 1;", NULL, NULL, &error);
  checked ("reattach-create-script", error);
  frida_script_load_sync (script, NULL, &error);
  checked ("reattach-load-script", error);
  frida_script_unload_sync (script, NULL, &error);
  checked ("reattach-unload-script", error);
  frida_unref (script);
  detach (session, "reattach-detach");
}

static void eternalize (FridaSession * session) {
  GError * error = NULL;
  FridaScript * script = frida_session_create_script_sync (session,
      "globalThis.oraclePermanent = 1;", NULL, NULL, &error);
  checked ("permanent-create", error);
  frida_script_load_sync (script, NULL, &error); checked ("permanent-load", error);
  frida_script_eternalize_sync (script, NULL, &error); checked ("permanent-eternalize", error);
  frida_unref (script);
}

static guint pending_child (guint parent) {
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  while (g_get_monotonic_time () < deadline) {
    GError * error = NULL;
    while (g_main_context_iteration (NULL, FALSE)) ;
    FridaChildList * list = frida_device_enumerate_pending_children_sync (device, NULL, &error);
    if (error != NULL) fail ("pending-children", error);
    guint result = 0;
    for (int i = 0; i != frida_child_list_size (list); i++) {
      FridaChild * child = frida_child_list_get (list, i);
      if (frida_child_get_parent_pid (child) == parent) result = frida_child_get_pid (child);
      frida_unref (child);
    }
    frida_unref (list);
    if (result != 0) return result;
    g_usleep (1000);
  }
  return 0;
}

static void ping (int command, int report) {
  char response;
  send_byte (command, 'P'); receive (report, &response, 1);
  if (response != 'P') { errno = EPROTO; fail ("business-pipe-content", NULL); }
}

static int cmp_int (const void * a, const void * b) {
  int x = *(const int *) a;
  int y = *(const int *) b;
  return (x > y) - (x < y);
}

static int native_thread_count (void) {
  DIR * directory = opendir ("/proc/self/task");
  struct dirent * entry;
  int count = 0;
  if (directory == NULL) _exit (7);
  while ((entry = readdir (directory)) != NULL)
    if (entry->d_name[0] != '.') count++;
  closedir (directory);
  return count;
}

/* Report the sorted TID set so the harness can calibrate an explainable role
 * baseline instead of trusting a raw thread count. */
static void report_thread_tids (int fd) {
  DIR * directory = opendir ("/proc/self/task");
  struct dirent * entry;
  int tids[256];
  int count = 0;
  if (directory == NULL) _exit (7);
  while ((entry = readdir (directory)) != NULL && count < 256)
    if (entry->d_name[0] != '.') tids[count++] = atoi (entry->d_name);
  closedir (directory);
  qsort (tids, count, sizeof (int), cmp_int);
  if (write (fd, &count, sizeof count) != (ssize_t) sizeof count) _exit (8);
  if (write (fd, tids, (size_t) count * sizeof (int)) != (ssize_t) ((size_t) count * sizeof (int))) _exit (8);
}

static int query_thread_count (int command, int report) {
  int threads;
  send_byte (command, 'T'); receive (report, &threads, sizeof threads);
  return threads;
}

static int query_thread_tids (int command, int report, int * tids, int capacity) {
  int count;
  send_byte (command, 'L'); receive (report, &count, sizeof count);
  if (count < 0 || count > capacity) { errno = EPROTO; fail ("thread-list-capacity", NULL); }
  receive (report, tids, count * sizeof (int));
  return count;
}

static gboolean tid_present (int tid, const int * tids, int count) {
  for (int i = 0; i != count; i++)
    if (tids[i] == tid) return TRUE;
  return FALSE;
}

/* Explainable-role check: the business thread (the child main TID) stays
 * alive and the sorted TID set is stable across two samples. The exact
 * infrastructure thread set is reported for the harness to calibrate against a
 * native no-fault eternal control; this fixture does not claim a raw count is
 * a unique owner. */
static void assert_child_runner_roles (int command, int report, const char * stage) {
  int first[256], second[256];
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  int n1 = query_thread_tids (command, report, first, 256);
  for (;;) {
    gboolean stable = TRUE;
    g_usleep (1000);
    int n2 = query_thread_tids (command, report, second, 256);
    if (n1 != n2) {
      stable = FALSE;
    } else {
      for (int i = 0; i != n1; i++)
        if (first[i] != second[i]) stable = FALSE;
    }
    if (stable) break;
    if (g_get_monotonic_time () >= deadline) {
      errno = ETIMEDOUT;
      fail ("runner-stable-tids", NULL);
    }
    memcpy (first, second, (size_t) n2 * sizeof (int));
    n1 = n2;
  }
  require (tid_present ((int) child_pid, first, n1), "business-thread-alive");
  printf ("INFO stage=%s child_tids=", stage);
  for (int i = 0; i != n1; i++)
    printf ("%s%d", i ? "," : "", first[i]);
  printf ("\n");
}

static void wait_for_thread_count (int command, int report, int expected, const char * stage) {
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    int threads = query_thread_count (command, report);
    if (threads == expected) { checked (stage, NULL); return; }
    g_usleep (1000);
  } while (g_get_monotonic_time () < deadline);
  errno = ETIMEDOUT; fail (stage, NULL);
}

static int target (int pc, int po, int cc, int co, const char * mode) {
  char command;
  gboolean close_child_sockets = strcmp (mode, "child-close") == 0 ||
      strcmp (mode, "eternal-child-close") == 0;
  target_keep_fds[0] = pc;
  target_keep_fds[1] = po;
  target_keep_fds[2] = cc;
  target_keep_fds[3] = co;
  long open_max = sysconf (_SC_OPEN_MAX);
  target_max_fd = open_max > 0 && open_max < 65536 ? (int) open_max : 65536;
  if (close_child_sockets && pthread_atfork (NULL, NULL, close_child_runtime_sockets) != 0)
    _exit (9);
  regression_disconnect_before_prepare =
      strcmp (mode, "controller-exit-fork") == 0;
  send_byte (po, 'R');
  while (read (pc, &command, 1) == 1) {
    if (command == 'F') {
      pid_t child = fork ();
      if (child < 0) _exit (2);
      if (child == 0) {
        if (close_child_sockets &&
            write (co, (const void *) &target_closed_sockets, sizeof target_closed_sockets) !=
                (ssize_t) sizeof target_closed_sockets)
          _exit (8);
        send_byte (co, 'R');
        while (read (cc, &command, 1) == 1) {
          if (command == 'Q') _exit (0);
          if (command == 'P') send_byte (co, 'P');
          if (command == 'T') {
            int threads = native_thread_count ();
            if (write (co, &threads, sizeof threads) != sizeof threads) _exit (8);
          }
          if (command == 'L') report_thread_tids (co);
        }
        _exit (3);
      }
      if (write (po, &child, sizeof child) != sizeof child) _exit (4);
    } else if (command == 'T') {
      int threads = native_thread_count ();
      if (write (po, &threads, sizeof threads) != sizeof threads) _exit (8);
    } else if (command == 'L') report_thread_tids (po);
    else if (command == 'P') send_byte (po, 'P');
    else if (command == 'Q') {
      int status; pid_t reaped = wait (&status);
      int ok = reaped > 0 && WIFEXITED (status) && WEXITSTATUS (status) == 0;
      send_byte (po, ok ? 'X' : 'E');
      _exit (ok ? 0 : 5);
    }
  }
  return 6;
}

int main (int argc, char ** argv) {
  if (argc == 7 && strcmp (argv[1], "--target") == 0)
    return target (atoi (argv[2]), atoi (argv[3]), atoi (argv[4]), atoi (argv[5]), argv[6]);
  if (argc != 2 || (strcmp (argv[1], "plain") != 0 && strcmp (argv[1], "child-close") != 0 &&
      strcmp (argv[1], "eternal-control") != 0 && strcmp (argv[1], "eternal-child-close") != 0 &&
      strcmp (argv[1], "controller-close-fork") != 0 &&
      strcmp (argv[1], "controller-exit-fork") != 0)) {
    fprintf (stderr, "usage: %s plain|child-close|eternal-control|eternal-child-close|controller-close-fork|controller-exit-fork\n",
        argv[0]); return 2;
  }
  int mode_plain = strcmp (argv[1], "plain") == 0;
  int mode_child_close = strcmp (argv[1], "child-close") == 0;
  int mode_eternal_control = strcmp (argv[1], "eternal-control") == 0;
  int mode_eternal_child_close = strcmp (argv[1], "eternal-child-close") == 0;
  int mode_controller_close = strcmp (argv[1], "controller-close-fork") == 0;
  int mode_controller_exit = strcmp (argv[1], "controller-exit-fork") == 0;
  int mode_eternal = mode_eternal_control || mode_eternal_child_close || mode_controller_close ||
      mode_controller_exit;
  int mode_fault = mode_child_close || mode_eternal_child_close;
  int mode_gated = mode_plain || mode_eternal_control;
  int manager_closed = FALSE;

  signal (SIGALRM, watchdog);
  alarm (30);

  int pc[2], po[2], cc[2], co[2];
  if (pipe (pc) || pipe (po) || pipe (cc) || pipe (co)) fail ("pipe", NULL);
  target_pid = fork ();
  if (target_pid < 0) fail ("spawn", NULL);
  if (target_pid == 0) {
    char a[20], b[20], c[20], d[20];
    close (pc[1]); close (po[0]); close (cc[1]); close (co[0]);
    snprintf (a, sizeof a, "%d", pc[0]); snprintf (b, sizeof b, "%d", po[1]);
    snprintf (c, sizeof c, "%d", cc[0]); snprintf (d, sizeof d, "%d", co[1]);
    execl (argv[0], argv[0], "--target", a, b, c, d, argv[1], NULL); _exit (127);
  }
  close (pc[0]); close (po[1]); close (cc[0]); close (co[1]);

  GError * error = NULL;
  frida_init ();
  FridaDeviceManager * manager = frida_device_manager_new ();
  device = frida_device_manager_get_device_by_type_sync (manager,
      FRIDA_DEVICE_TYPE_LOCAL, 0, NULL, &error);
  checked ("local-device", error);

  char response;
  receive (po[0], &response, 1);
  if (response != 'R') { errno = EPROTO; fail ("parent-ready", NULL); }

  FridaSession * parent = attach (target_pid, "parent-initial-attach");
  enable_gating (parent, "parent-enable-gating");
  if (mode_eternal)
    eternalize (parent);

  if (mode_controller_close) {
    /* The eternalized target runtime remains installed after its last Session
     * is detached. A synchronous DeviceManager close is the fixture's
     * observable controller-loss boundary. Only then may the business target
     * enter fork(), so this is a controlled history rather than a timing race. */
    detach (parent, "controller-close-parent-detach");
    parent = NULL;
    frida_device_manager_close_sync (manager, NULL, &error);
    checked ("controller-close-manager", error);
    manager_closed = TRUE;
  }

  send_byte (pc[1], 'F');

  if (mode_gated) {
    child_pid = pending_child (target_pid);
    if (child_pid == 0) { errno = ETIMEDOUT; fail ("pending-child-deadline", NULL); }
    FridaSession * child = attach (child_pid, "fork-child-attach");
    enable_gating (child, "child-enable-gating");
    frida_device_resume_sync (device, child_pid, NULL, &error); checked ("child-resume", error);

    pid_t reported; receive (po[0], &reported, sizeof reported);
    if (reported != child_pid) { errno = EPROTO; fail ("child-pid", NULL); }
    char child_ready;
    receive (co[0], &child_ready, 1);
    if (child_ready != 'R') { errno = EPROTO; fail ("child-ready", NULL); }
    ping (pc[1], po[0]); ping (cc[1], co[0]);

    if (mode_eternal_control) {
      probe (child_pid, "child-reattach-control");
    }
    detach (child, "child-last-session-detach");
  } else if (mode_fault) {
    /* The child-atfork callback has already closed every inherited Frida
     * socket before Gum's fork on-leave recovery runs. Parent recovery and its
     * control connection are unaffected. */
    pid_t reported; receive (po[0], &reported, sizeof reported);
    if (reported <= 0) { errno = EPROTO; fail ("fault-child-pid", NULL); }
    child_pid = reported;
    guint pending = pending_child (target_pid);
    if (pending != 0) {
      require (pending == (guint) child_pid, "fault-pending-child");
      frida_device_resume_sync (device, pending, NULL, &error); checked ("fault-child-resume", error);
    }
    sig_atomic_t closed_sockets;
    receive (co[0], &closed_sockets, sizeof closed_sockets);
    require (closed_sockets > 0, "fault-runtime-socket-closed");
    printf ("INFO stage=fault-runtime-socket-closed count=%d\n", (int) closed_sockets);
    fflush (stdout);
    char child_ready;
    receive (co[0], &child_ready, 1);
    if (child_ready != 'R') { errno = EPROTO; fail ("fault-child-ready", NULL); }
    ping (cc[1], co[0]);
  } else {
    /* No controller remains to gate or resume this fork. The target-side
     * recovery path must release its own native gate and must never send a
     * zero/stale child identity to a retired controller. */
    pid_t reported; receive (po[0], &reported, sizeof reported);
    if (reported <= 0) { errno = EPROTO; fail ("controller-close-child-pid", NULL); }
    child_pid = reported;
    char child_ready;
    receive (co[0], &child_ready, 1);
    if (child_ready != 'R') { errno = EPROTO; fail ("controller-close-child-ready", NULL); }
    ping (pc[1], po[0]);
    ping (cc[1], co[0]);
    checked ("controller-close-business-progress", NULL);
  }

  if (parent != NULL) {
    if (mode_controller_exit && frida_session_is_detached (parent))
      frida_unref (parent);
    else
      detach (parent, "parent-last-session-detach");
  }
  ping (pc[1], po[0]);

  if (mode_plain || mode_child_close) {
    /* Plain unload is the one proven single-thread invariant. */
    wait_for_thread_count (cc[1], co[0], 1, "plain-child-unloaded");
  } else {
    /* No raw-count uniqueness claim: check business-thread liveness and a
     * stable TID set, and report the set for harness calibration against the
     * no-fault eternal-control baseline. */
    assert_child_runner_roles (cc[1], co[0],
        mode_eternal_control ? "eternal-control-baseline" :
        mode_controller_close ? "controller-close-child-roles" :
        mode_controller_exit ? "controller-exit-child-roles" : "fault-child-roles");
  }

  if (child_pid != 0) send_byte (cc[1], 'Q');
  send_byte (pc[1], 'Q');
  receive (po[0], &response, 1);
  if (response != 'X') { errno = ECHILD; fail ("child-native-exit", NULL); }
  child_pid = 0;
  int status;
  if (waitpid (target_pid, &status, 0) != target_pid || !WIFEXITED (status) || WEXITSTATUS (status) != 0)
    fail ("parent-native-exit", NULL);
  target_pid = 0;
  if (!manager_closed) {
    frida_device_manager_close_sync (manager, NULL, &error); checked ("manager-close", error);
  }
  frida_unref (device); frida_unref (manager);
  alarm (0);
  printf ("PASS mode=%s fault=%d\n", argv[1], mode_fault || mode_controller_exit);
  return 0;
}
