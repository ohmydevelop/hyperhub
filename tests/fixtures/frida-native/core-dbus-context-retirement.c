#include "frida-core.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Exercise Core's actual private context-discovery coroutine and bundled GIO.
 * Link with both --wrap=_frida_g_dbus_connection_close and
 * --wrap=_frida_g_dbus_connection_close_finish. No process is attached, no
 * device is opened, and the probe creates only its own in-memory streams.
 *
 * closed: complete the probe's real close before asking GIO to close it again.
 * disposed: dispose the probe before its real async close.
 * overlap: start two real discoveries, invalidating the cache between them
 * before pumping the caller context. Each closure must resolve its own Promise.
 * All modes check multiple generations, cache hits, real worker-context
 * dispatch, the exact CLOSED result, and finalization of all probe objects.
 */
void frida_get_dbus_context (GAsyncReadyCallback callback, gpointer user_data);
GMainContext * frida_get_dbus_context_finish (GAsyncResult * result);
void frida_invalidate_dbus_context (void);

void __real__frida_g_dbus_connection_close (GDBusConnection * connection,
    GCancellable * cancellable, GAsyncReadyCallback callback, gpointer user_data);
gboolean __real__frida_g_dbus_connection_close_finish (GDBusConnection * connection,
    GAsyncResult * result, GError ** error);

typedef struct {
  const char * mode;
  GMainContext * caller_context;
  GThread * caller_thread;
  gint probes;
  gint closed_results;
  gint connections_freed;
  gint streams_freed;
  gint inputs_freed;
  gint outputs_freed;
} Fixture;

typedef struct {
  Fixture * fixture;
  GMainContext * context;
  GMainContext * expected_context;
  gint completed;
  gint verified;
} Request;

typedef struct {
  GDBusConnection * connection;
  GCancellable * cancellable;
  GAsyncReadyCallback callback;
  gpointer user_data;
} CloseAgain;

static Fixture fixture;

static void
require (gboolean condition, const char * stage)
{
  if (!condition)
  {
    fprintf (stderr, "FAIL stage=%s mode=%s probes=%d closed=%d\n", stage,
        fixture.mode, fixture.probes, fixture.closed_results);
    exit (1);
  }
}

static void
watchdog (int signo)
{
  static const char message[] = "FAIL stage=watchdog timeout=15s\n";
  (void) signo;
  (void) write (STDERR_FILENO, message, sizeof message - 1);
  _exit (124);
}

static void
finalized (gpointer data, GObject * object)
{
  (void) object;
  g_atomic_int_inc ((gint *) data);
}

static gboolean
is_probe (GDBusConnection * connection)
{
  GIOStream * stream = g_dbus_connection_get_stream (connection);
  return strcmp (G_OBJECT_TYPE_NAME (g_io_stream_get_input_stream (stream)),
      "FridaDummyInputStream") == 0
      && G_IS_MEMORY_OUTPUT_STREAM (g_io_stream_get_output_stream (stream));
}

static void
close_again (GObject * object, GAsyncResult * result, gpointer data)
{
  CloseAgain * again = data;
  GError * error = NULL;
  gboolean closed = __real__frida_g_dbus_connection_close_finish (
      G_DBUS_CONNECTION (object), result, &error);
  /* EOF may have completed the first close before the wrapper got control. */
  require (closed || g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED),
      "initial-real-close-completed");
  g_clear_error (&error);
  require (g_dbus_connection_is_closed (again->connection), "real-probe-is-closed");
  __real__frida_g_dbus_connection_close (again->connection, again->cancellable,
      again->callback, again->user_data);
  g_clear_object (&again->cancellable);
  g_object_unref (again->connection);
  g_free (again);
}

void
__wrap__frida_g_dbus_connection_close (GDBusConnection * connection,
    GCancellable * cancellable, GAsyncReadyCallback callback, gpointer user_data)
{
  GIOStream * stream;
  require (is_probe (connection), "wrapper-only-receives-context-probe");
  require (g_object_get_data (G_OBJECT (connection), "context-retirement-wrapped") == NULL,
      "one-close-injection-per-probe");
  g_object_set_data (G_OBJECT (connection), "context-retirement-wrapped", GINT_TO_POINTER (1));
  stream = g_dbus_connection_get_stream (connection);
  g_object_weak_ref (G_OBJECT (connection), finalized, &fixture.connections_freed);
  g_object_weak_ref (G_OBJECT (stream), finalized, &fixture.streams_freed);
  g_object_weak_ref (G_OBJECT (g_io_stream_get_input_stream (stream)), finalized, &fixture.inputs_freed);
  g_object_weak_ref (G_OBJECT (g_io_stream_get_output_stream (stream)), finalized, &fixture.outputs_freed);
  fixture.probes++;

  if (strcmp (fixture.mode, "disposed") == 0)
  {
    g_object_run_dispose (G_OBJECT (connection));
    require (g_dbus_connection_is_closed (connection), "disposed-probe-is-closed");
    __real__frida_g_dbus_connection_close (connection, cancellable, callback, user_data);
  }
  else
  {
    CloseAgain * again = g_new0 (CloseAgain, 1);
    again->connection = g_object_ref (connection);
    again->cancellable = cancellable != NULL ? g_object_ref (cancellable) : NULL;
    again->callback = callback;
    again->user_data = user_data;
    __real__frida_g_dbus_connection_close (connection, NULL, close_again, again);
  }
}

gboolean
__wrap__frida_g_dbus_connection_close_finish (GDBusConnection * connection,
    GAsyncResult * result, GError ** error)
{
  gboolean closed;
  require (is_probe (connection), "finish-wrapper-only-receives-context-probe");
  require (g_object_get_data (G_OBJECT (connection), "context-retirement-wrapped") == GINT_TO_POINTER (1),
      "finish-belongs-to-injected-probe");
  closed = __real__frida_g_dbus_connection_close_finish (connection, result, error);
  require (!closed && error != NULL && g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_CLOSED),
      "actual-close-finish-reports-closed");
  g_object_set_data (G_OBJECT (connection), "context-retirement-wrapped", GINT_TO_POINTER (2));
  fixture.closed_results++;
  return closed;
}

static gboolean
verify_worker_context (gpointer data)
{
  Request * request = data;
  require (g_thread_self () != request->fixture->caller_thread, "context-is-served-by-worker");
  require (g_main_context_get_thread_default () == request->context, "real-worker-thread-default-context");
  g_atomic_int_set (&request->verified, TRUE);
  return G_SOURCE_REMOVE;
}

static void
context_obtained (GObject * object, GAsyncResult * result, gpointer data)
{
  Request * request = data;
  GSource * source;
  (void) object;
  require (!request->completed, "context-request-completes-once");
  request->context = frida_get_dbus_context_finish (result);
  require (request->context != NULL, "real-context-resolved");
  require (request->expected_context == NULL || request->context == request->expected_context,
      "cache-hit-retains-resolved-context");
  source = g_idle_source_new ();
  g_source_set_callback (source, verify_worker_context, request, NULL);
  g_source_attach (source, request->context);
  g_source_unref (source);
  request->completed = TRUE;
}

static void
wait_requests (Request * requests, guint count)
{
  gboolean done;
  do
  {
    guint i;
    while (g_main_context_iteration (fixture.caller_context, FALSE))
      ;
    done = TRUE;
    for (i = 0; i != count; i++)
      done = done && requests[i].completed && g_atomic_int_get (&requests[i].verified);
    if (!done)
      g_usleep (100);
  }
  while (!done);
}

static void
wait_finalization (gint expected)
{
  while (g_atomic_int_get (&fixture.connections_freed) != expected
      || g_atomic_int_get (&fixture.streams_freed) != expected
      || g_atomic_int_get (&fixture.inputs_freed) != expected
      || g_atomic_int_get (&fixture.outputs_freed) != expected)
  {
    while (g_main_context_iteration (fixture.caller_context, FALSE))
      ;
    g_usleep (100);
  }
}

int
main (int argc, char ** argv)
{
  guint generation;
  guint width;
  if (argc != 2 || (strcmp (argv[1], "closed") != 0
      && strcmp (argv[1], "disposed") != 0 && strcmp (argv[1], "overlap") != 0))
  {
    fprintf (stderr, "Usage: %s closed|disposed|overlap\n", argv[0]);
    return 2;
  }
  fixture.mode = argv[1];
  width = strcmp (fixture.mode, "overlap") == 0 ? 2 : 1;
  signal (SIGALRM, watchdog);
  alarm (15);
  frida_init ();
  fixture.caller_thread = g_thread_self ();
  fixture.caller_context = g_main_context_new ();
  g_main_context_push_thread_default (fixture.caller_context);

  for (generation = 0; generation != 4; generation++)
  {
    Request requests[4] = { 0 };
    gint expected = (generation + 1) * width;
    guint i;
    for (i = 0; i != width; i++)
    {
      requests[i].fixture = &fixture;
      frida_invalidate_dbus_context ();
      frida_get_dbus_context (context_obtained, &requests[i]);
      /* No caller iteration between A, invalidation and B: old discovery is
       * still awaiting its connection callback when the next Promise exists. */
    }
    wait_requests (requests, width);
    require (fixture.probes == expected && fixture.closed_results == expected,
        "one-retired-connection-per-new-discovery");
    for (i = width; i != width + 2; i++)
    {
      requests[i].fixture = &fixture;
      requests[i].expected_context = requests[width - 1].context;
      frida_get_dbus_context (context_obtained, &requests[i]);
    }
    wait_requests (requests, width + 2);
    require (fixture.probes == expected && fixture.closed_results == expected,
        "cache-hits-do-not-create-or-close-probes");
    wait_finalization (expected);
    for (i = 0; i != width + 2; i++)
      g_main_context_unref (requests[i].context);
  }
  frida_invalidate_dbus_context ();
  while (g_main_context_iteration (fixture.caller_context, FALSE))
    ;
  g_main_context_pop_thread_default (fixture.caller_context);
  g_main_context_unref (fixture.caller_context);
  frida_deinit ();
  alarm (0);
  printf ("PASS mode=%s generations=4 probes=%d closed=%d references=released\n",
      fixture.mode, fixture.probes, fixture.closed_results);
  return 0;
}
