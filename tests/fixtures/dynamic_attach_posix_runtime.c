/* A POSIX runtime target: use a Cygwin/MSYS compiler on Windows. No credentials. */
#define _POSIX_C_SOURCE 200809L
#if defined(_WIN32) && !(defined(__CYGWIN__) || defined(__MSYS__))
#error "This fixture requires a POSIX fork runtime, not a native MinGW compiler"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__CYGWIN__) || defined(__MSYS__)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

extern char **environ;
static const char * protected_path;
static unsigned short echo_port;
static int stream = -1;
static char original_cwd[32768];
static uint64_t original_environment;
static volatile sig_atomic_t pending_child;

static unsigned long native_pid(void) {
#if defined(__CYGWIN__) || defined(__MSYS__)
  return (unsigned long) GetCurrentProcessId();
#else
  return (unsigned long) getpid();
#endif
}
static uint64_t environment_hash(void) {
  uint64_t hash = UINT64_C(1469598103934665603);
  for (char **entry = environ; *entry != NULL; entry++) {
    for (const unsigned char *p = (const unsigned char *) *entry; *p != 0; p++) {
      hash ^= *p;
      hash *= UINT64_C(1099511628211);
    }
    hash ^= 0xff;
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}
static void timeout_handler(int number) {
  (void) number;
  if (pending_child > 0) kill((pid_t) pending_child, SIGKILL);
  _exit(97);
}
static int echo(void) {
  unsigned char sent[2] = {0x51, 0xa7}, received[2];
  if (send(stream, sent, sizeof(sent), 0) != (ssize_t) sizeof(sent)) return 0;
  size_t offset = 0;
  while (offset != sizeof(received)) {
    ssize_t size = recv(stream, received + offset, sizeof(received) - offset, 0);
    if (size <= 0) return 0;
    offset += (size_t) size;
  }
  return memcmp(sent, received, sizeof(sent)) == 0;
}
static int replace_stream(void) {
  int fresh = socket(AF_INET, SOCK_STREAM, 0);
  if (fresh < 0) return 0;
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(echo_port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(fresh, (struct sockaddr *) &address, sizeof(address)) != 0) {
    close(fresh);
    return 0;
  }
  if (stream >= 0) close(stream);
  stream = fresh;
  return echo();
}
static int read_protected(void) {
  FILE *file = fopen(protected_path, "rb");
  if (file == NULL) return errno;
  int value = fgetc(file);
  int result = value == 'S' ? 0 : (ferror(file) ? errno : EIO);
  fclose(file);
  return result;
}
struct ChildReport {
  unsigned long native_pid;
  int read_result;
  int old_stream;
  int stable_environment;
  int stable_cwd;
};
static struct ChildReport snapshot(void) {
  char cwd[sizeof(original_cwd)];
  struct ChildReport result;
  result.native_pid = native_pid();
  result.read_result = read_protected();
  result.old_stream = echo();
  result.stable_environment = environment_hash() == original_environment;
  result.stable_cwd = getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, original_cwd) == 0;
  return result;
}
static int transfer(int descriptor, void *bytes, size_t length, int writing) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t amount = writing ? write(descriptor, (char *) bytes + offset, length - offset)
                             : read(descriptor, (char *) bytes + offset, length - offset);
    if (amount < 0 && errno == EINTR) continue;
    if (amount <= 0) return 0;
    offset += (size_t) amount;
  }
  return 1;
}
static void print_report(const struct ChildReport *report, int child_exit, int fork_error) {
  printf("{\"pid\":%lu,\"read_result\":%d,\"old_stream\":%s,"
         "\"stable_environment\":%s,\"stable_cwd\":%s,\"child_exit\":%d,\"fork_error\":%d}\n",
         report->native_pid, report->read_result, report->old_stream ? "true" : "false",
         report->stable_environment ? "true" : "false", report->stable_cwd ? "true" : "false",
         child_exit, fork_error);
}
static void fork_report(void) {
  int channel[2];
  struct ChildReport report;
  memset(&report, 0, sizeof(report));
  if (pipe(channel) != 0) {
    print_report(&report, -1, errno);
    return;
  }
  pid_t child = fork();
  if (child == 0) {
    close(channel[0]);
    report = snapshot();
    int ok = transfer(channel[1], &report, sizeof(report), 1);
    close(channel[1]);
    _exit(ok ? 37 : 38);
  }
  close(channel[1]);
  if (child < 0) {
    int error = errno;
    close(channel[0]);
    print_report(&report, -1, error);
    return;
  }
  pending_child = child;
  alarm(20);
  int received = transfer(channel[0], &report, sizeof(report), 0), status = 0;
  close(channel[0]);
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) { status = -1; break; }
  }
  alarm(0);
  pending_child = 0;
  int code = status == -1 ? -1 : (WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
  print_report(&report, code, received ? 0 : EIO);
}
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  protected_path = argv[1];
  unsigned long port = strtoul(argv[2], NULL, 10);
  if (port == 0 || port > 65535) return 2;
  echo_port = (unsigned short) port;
  if (getcwd(original_cwd, sizeof(original_cwd)) == NULL) return 3;
  original_environment = environment_hash();
  setvbuf(stdout, NULL, _IONBF, 0);
  signal(SIGALRM, timeout_handler);
  signal(SIGPIPE, SIG_IGN);
  if (!replace_stream()) return 4;
  struct ChildReport initial = snapshot();
  print_report(&initial, 0, 0);
  char command[64];
  while (fgets(command, sizeof(command), stdin) != NULL) {
    command[strcspn(command, "\r\n")] = 0;
    if (strcmp(command, "exit") == 0) { close(stream); return 37; }
    if (strcmp(command, "fork") == 0) fork_report();
    else {
      if (strcmp(command, "replace-stream") == 0 && !replace_stream()) return 5;
      struct ChildReport report = snapshot();
      print_report(&report, 0, 0);
    }
  }
  close(stream);
  return 6;
}
