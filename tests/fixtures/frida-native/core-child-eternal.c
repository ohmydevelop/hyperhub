#include "frida-core.h"
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Linux dependency regression. All pipes and target processes are created here. */
static FridaDevice * device;
static pid_t target_pid, child_pid;

static void watchdog (int signal_number) {
  const char message[] = "FAIL stage=oracle-watchdog\n";
  (void) signal_number;
  write (STDERR_FILENO, message, sizeof message - 1);
  if (child_pid > 0) kill (child_pid, SIGKILL);
  if (target_pid > 0) kill (target_pid, SIGKILL);
  _exit (124);
}

static void fail (const char * stage, GError * error) {
  fprintf (stderr, "FAIL stage=%s error=%s\n", stage,
      error != NULL ? error->message : strerror (errno));
  if (child_pid > 0) kill (child_pid, SIGKILL);
  if (target_pid > 0) { kill (target_pid, SIGKILL); waitpid (target_pid, NULL, 0); }
  exit (1);
}
static void checked (const char * stage, GError * error) {
  if (error != NULL) fail (stage, error);
  printf ("OK stage=%s\n", stage); fflush (stdout);
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
  frida_session_disable_child_gating_sync (session, NULL, &error);
  checked ("disable-gating", error);
  frida_session_detach_sync (session, NULL, &error);
  checked (stage, error);
  frida_unref (session);
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
  frida_session_detach_sync (session, NULL, &error);
  checked ("reattach-detach", error);
  frida_unref (session);
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
  errno = ETIMEDOUT; fail ("pending-child-deadline", NULL); return 0;
}
static void ping (int command, int report) {
  char response;
  send_byte (command, 'P'); receive (report, &response, 1);
  if (response != 'P') { errno = EPROTO; fail ("business-pipe-content", NULL); }
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
static void wait_for_plain_unload (int command, int report, const char * stage) {
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    int threads;
    send_byte (command, 'T'); receive (report, &threads, sizeof threads);
    if (threads == 1) { checked (stage, NULL); return; }
    g_usleep (1000);
  } while (g_get_monotonic_time () < deadline);
  errno = ETIMEDOUT; fail (stage, NULL);
}
static int target (int pc, int po, int cc, int co) {
  char command;
  send_byte (po, 'R');
  while (read (pc, &command, 1) == 1) {
    if (command == 'F') {
      pid_t child = fork ();
      if (child < 0) _exit (2);
      if (child == 0) {
        send_byte (co, 'R');
        while (read (cc, &command, 1) == 1) {
          if (command == 'Q') _exit (0);
          if (command == 'P') send_byte (co, 'P');
          if (command == 'T') {
            int threads = native_thread_count ();
            if (write (co, &threads, sizeof threads) != sizeof threads) _exit (8);
          }
        }
        _exit (3);
      }
      if (write (po, &child, sizeof child) != sizeof child) _exit (4);
    } else if (command == 'T') {
      int threads = native_thread_count ();
      if (write (po, &threads, sizeof threads) != sizeof threads) _exit (8);
    } else if (command == 'P') send_byte (po, 'P');
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
  if (argc == 6 && strcmp (argv[1], "--target") == 0)
    return target (atoi (argv[2]), atoi (argv[3]), atoi (argv[4]), atoi (argv[5]));
  if (argc != 2 || (strcmp (argv[1], "eternal") != 0 && strcmp (argv[1], "plain") != 0 &&
      strcmp (argv[1], "child-late-eternal") != 0 && strcmp (argv[1], "eternal-no-initial-session") != 0)) {
    fprintf (stderr, "usage: %s eternal|plain|child-late-eternal|eternal-no-initial-session\n", argv[0]); return 2;
  }
  int parent_eternal = strcmp (argv[1], "eternal") == 0 || strcmp (argv[1], "eternal-no-initial-session") == 0;
  int late_eternal = strcmp (argv[1], "child-late-eternal") == 0;
  int skip_child_session = strcmp (argv[1], "eternal-no-initial-session") == 0;
  signal (SIGALRM, watchdog);
  alarm (25);
  int pc[2], po[2], cc[2], co[2];
  if (pipe (pc) || pipe (po) || pipe (cc) || pipe (co)) fail ("pipe", NULL);
  target_pid = fork ();
  if (target_pid < 0) fail ("spawn", NULL);
  if (target_pid == 0) {
    char a[20], b[20], c[20], d[20];
    close (pc[1]); close (po[0]); close (cc[1]); close (co[0]);
    snprintf (a, sizeof a, "%d", pc[0]); snprintf (b, sizeof b, "%d", po[1]);
    snprintf (c, sizeof c, "%d", cc[0]); snprintf (d, sizeof d, "%d", co[1]);
    execl (argv[0], argv[0], "--target", a, b, c, d, NULL); _exit (127);
  }
  close (pc[0]); close (po[1]); close (cc[0]); close (co[1]);
  frida_init ();
  GError * error = NULL;
  FridaDeviceManager * manager = frida_device_manager_new ();
  device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_LOCAL, 0, NULL, &error);
  checked ("local-device", error);
  char response; receive (po[0], &response, 1);
  if (response != 'R') { errno = EPROTO; fail ("parent-ready", NULL); }
  FridaSession * parent = attach (target_pid, "parent-initial-attach");
  if (parent_eternal) eternalize (parent);
  frida_session_enable_child_gating_sync (parent, NULL, &error); checked ("parent-enable-gating", error);
  send_byte (pc[1], 'F');
  child_pid = pending_child (target_pid);
  FridaSession * child = NULL;
  if (!skip_child_session) {
    child = attach (child_pid, "fork-child-initial-attach");
    frida_session_enable_child_gating_sync (child, NULL, &error); checked ("child-enable-gating", error);
    if (late_eternal) eternalize (child);
  }
  frida_device_resume_sync (device, child_pid, NULL, &error); checked ("child-resume", error);
  pid_t reported; receive (po[0], &reported, sizeof reported);
  if (reported != child_pid) { errno = EPROTO; fail ("child-pid", NULL); }
  receive (co[0], &response, 1);
  if (response != 'R') { errno = EPROTO; fail ("child-ready", NULL); }
  ping (pc[1], po[0]); ping (cc[1], co[0]);
  if (child != NULL) detach (child, "child-last-session-detach");
  detach (parent, "parent-last-session-detach");
  ping (pc[1], po[0]); ping (cc[1], co[0]);
  if (!parent_eternal) wait_for_plain_unload (pc[1], po[0], "plain-parent-unloaded");
  if (!parent_eternal && !late_eternal) wait_for_plain_unload (cc[1], co[0], "plain-child-unloaded");
  probe (target_pid, "parent-reattach-control");
  probe (child_pid, "fork-child-reattach");
  ping (pc[1], po[0]); ping (cc[1], co[0]);
  send_byte (cc[1], 'Q'); send_byte (pc[1], 'Q');
  receive (po[0], &response, 1);
  if (response != 'X') { errno = ECHILD; fail ("child-native-exit", NULL); }
  child_pid = 0; /* Parent acknowledged that it reaped the owned child. */
  int status;
  if (waitpid (target_pid, &status, 0) != target_pid || !WIFEXITED (status) || WEXITSTATUS (status) != 0)
    fail ("parent-native-exit", NULL);
  target_pid = child_pid = 0;
  frida_device_manager_close_sync (manager, NULL, &error); checked ("manager-close", error);
  frida_unref (device); frida_unref (manager);
  alarm (0);
  printf ("PASS mode=%s\n", argv[1]); return 0;
}
