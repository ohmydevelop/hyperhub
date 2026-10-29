#include "frida-core.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Local GDBus lifecycle regression. Link against the project Core devkit so
 * this exercises its bundled GLib, rather than the host's installed library.
 * No Frida device, external process, system bus, or network service is used.
 *
 * dispatch: keep the server context paused until a real method call is queued;
 * unregister and dispose the connection, then dispatch its queued callback.
 * async: capture a real invocation, unregister and dispose its connection,
 * then run a separately queued method completion callback.
 */
#define TEST_PATH "/hyperhub/test/retirement"
#define TEST_INTERFACE "org.hyperhub.test.Retirement"

static const gchar introspection[] =
    "<node><interface name='" TEST_INTERFACE "'>"
    "<method name='Ping'><arg type='s' direction='out'/></method>"
    "</interface></node>";

typedef struct {
  GMutex mutex;
  GCond changed;
  gboolean client_ready;
  gboolean start_call;
  GSocketConnection * client_stream;
  GMainContext * server_context;
  GDBusMethodInvocation * invocation;
  gint call_seen;
  gint method_calls;
  gint callback_count;
  gint client_closed_error;
  gint registration_freed;
  gint invocation_finalized;
  gint server_finalized;
  gint client_finalized;
  gint completion_count;
  gint pending_seen;
  gint pending_count;
  gint retired_operations;
  gint cancellable_finalized;
  gchar * callback_error;
} Fixture;

static void
watchdog (int signo)
{
  static const char message[] = "FAIL stage=watchdog timeout=5s\n";
  (void) signo;
  (void) write (STDERR_FILENO, message, sizeof message - 1);
  _exit (124);
}

static void
fail (const char * stage, const GError * error)
{
  fprintf (stderr, "FAIL stage=%s error=%s\n", stage,
      error != NULL ? error->message : "contract assertion failed");
  exit (1);
}

static void
require (gboolean condition, const char * stage)
{
  if (!condition)
    fail (stage, NULL);
}

static void
finalized (gpointer data, GObject * object)
{
  (void) object;
  g_atomic_int_inc ((gint *) data);
}

static void
registration_freed (gpointer data)
{
  Fixture * fixture = data;
  g_atomic_int_inc (&fixture->registration_freed);
}

static GSocketConnection *
stream_from_fd (int fd)
{
  GError * error = NULL;
  GSocket * socket = g_socket_new_from_fd (fd, &error);
  GSocketConnection * stream;
  if (socket == NULL)
    fail ("socket-wrapper", error);
  stream = g_socket_connection_factory_create_connection (socket);
  g_object_unref (socket);
  return stream;
}

static void
call_finished (GObject * object, GAsyncResult * result, gpointer data)
{
  Fixture * fixture = data;
  GError * error = NULL;
  GVariant * reply = g_dbus_connection_call_finish (
      G_DBUS_CONNECTION (object), result, &error);
  if (reply != NULL)
    g_variant_unref (reply);
  fixture->callback_error = g_strdup (error != NULL ? error->message : "success");
  g_atomic_int_set (&fixture->client_closed_error,
      error != NULL && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED));
  g_clear_error (&error);
  g_atomic_int_inc (&fixture->callback_count);
}

/* Drop only our test's outgoing pending call so it remains outstanding until
 * local disposal. A real peer reply must not race the retirement assertion. */
static GDBusMessage *
withhold_pending_reply (GDBusConnection * connection, GDBusMessage * message,
    gboolean incoming, gpointer data)
{
  Fixture * fixture = data;
  (void) connection;
  if (incoming && g_dbus_message_get_message_type (message) == G_DBUS_MESSAGE_TYPE_METHOD_CALL
      && g_strcmp0 (g_dbus_message_get_member (message), "Pending") == 0)
  {
    g_atomic_int_inc (&fixture->pending_seen);
    g_object_unref (message);
    return NULL;
  }
  return message;
}

static void
pending_finished (GObject * object, GAsyncResult * result, gpointer data)
{
  Fixture * fixture = data;
  GError * error = NULL;
  GVariant * reply = g_dbus_connection_call_finish (G_DBUS_CONNECTION (object), result, &error);
  require (reply == NULL && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED),
      "local-pending-call-completes-with-closed");
  g_clear_error (&error);
  g_atomic_int_inc (&fixture->pending_count);
}

static void
retired_flush_finished (GObject * object, GAsyncResult * result, gpointer data)
{
  Fixture * fixture = data;
  GError * error = NULL;
  require (!g_dbus_connection_flush_finish (G_DBUS_CONNECTION (object), result, &error)
      && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED), "retired-async-flush-closed");
  g_clear_error (&error);
  g_atomic_int_inc (&fixture->retired_operations);
}

static void
retired_close_finished (GObject * object, GAsyncResult * result, gpointer data)
{
  Fixture * fixture = data;
  GError * error = NULL;
  require (!g_dbus_connection_close_finish (G_DBUS_CONNECTION (object), result, &error)
      && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED), "retired-async-close-closed");
  g_clear_error (&error);
  g_atomic_int_inc (&fixture->retired_operations);
}

static gpointer
client_main (gpointer data)
{
  Fixture * fixture = data;
  GMainContext * context = g_main_context_new ();
  GDBusConnection * client;
  GError * error = NULL;

  g_main_context_push_thread_default (context);
  client = g_dbus_connection_new_sync (G_IO_STREAM (fixture->client_stream),
      NULL, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT, NULL, NULL, &error);
  if (client == NULL)
    fail ("client-authentication", error);
  g_object_weak_ref (G_OBJECT (client), finalized, &fixture->client_finalized);
  g_dbus_connection_set_exit_on_close (client, FALSE);
  g_dbus_connection_add_filter (client, withhold_pending_reply, fixture, NULL);

  g_mutex_lock (&fixture->mutex);
  fixture->client_ready = TRUE;
  g_cond_broadcast (&fixture->changed);
  while (!fixture->start_call)
    g_cond_wait (&fixture->changed, &fixture->mutex);
  g_mutex_unlock (&fixture->mutex);

  g_dbus_connection_call (client, NULL, TEST_PATH, TEST_INTERFACE, "Ping",
      NULL, G_VARIANT_TYPE ("(s)"), G_DBUS_CALL_FLAGS_NONE, 4000, NULL,
      call_finished, fixture);
  while (g_atomic_int_get (&fixture->callback_count) == 0)
    g_main_context_iteration (context, TRUE);

  g_object_unref (client);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  g_main_context_pop_thread_default (context);
  g_main_context_unref (context);
  return NULL;
}

static GDBusMessage *
observe_call (GDBusConnection * connection, GDBusMessage * message,
    gboolean incoming, gpointer data)
{
  Fixture * fixture = data;
  (void) connection;
  if (incoming && g_dbus_message_get_message_type (message) == G_DBUS_MESSAGE_TYPE_METHOD_CALL
      && g_strcmp0 (g_dbus_message_get_interface (message), TEST_INTERFACE) == 0
      && g_strcmp0 (g_dbus_message_get_member (message), "Ping") == 0)
    g_atomic_int_inc (&fixture->call_seen);
  return message;
}

static void
method_called (GDBusConnection * connection, const gchar * sender,
    const gchar * path, const gchar * interface, const gchar * method,
    GVariant * parameters, GDBusMethodInvocation * invocation, gpointer data)
{
  Fixture * fixture = data;
  (void) connection;
  (void) sender;
  (void) path;
  (void) interface;
  (void) method;
  (void) parameters;
  require (fixture->invocation == NULL, "single-method-invocation");
  /* The method callback owns this invocation until a reply consumes it. */
  fixture->invocation = invocation;
  g_object_weak_ref (G_OBJECT (invocation), finalized, &fixture->invocation_finalized);
  g_atomic_int_inc (&fixture->method_calls);
}

static const GDBusInterfaceVTable vtable = {
  .method_call = method_called
};

static gboolean
complete_method (gpointer data)
{
  Fixture * fixture = data;
  GDBusMethodInvocation * invocation = fixture->invocation;
  require (invocation != NULL, "captured-async-invocation");
  fixture->invocation = NULL;
  g_dbus_method_invocation_return_value (invocation, g_variant_new ("(s)", "done"));
  g_atomic_int_inc (&fixture->completion_count);
  return G_SOURCE_REMOVE;
}

static void
require_closed_send (GDBusConnection * connection)
{
  GDBusMessage * message = g_dbus_message_new_signal (TEST_PATH, TEST_INTERFACE, "Probe");
  GError * error = NULL;
  gboolean sent = g_dbus_connection_send_message (connection, message,
      G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, &error);
  require (!sent && error != NULL && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED),
      "disposed-connection-rejects-send-with-closed");
  g_clear_error (&error);
  g_object_unref (message);
}

int
main (int argc, char ** argv)
{
  Fixture fixture = { 0 };
  int pair[2];
  gboolean asynchronous;
  GError * error = NULL;
  GSocketConnection * server_stream;
  GDBusConnection * server;
  GDBusNodeInfo * info;
  GThread * client_thread;
  gchar * guid;
  guint registration;
  guint filter;
  GCancellable * pending_cancellable;

  if (argc != 2 || (strcmp (argv[1], "dispatch") != 0 && strcmp (argv[1], "async") != 0))
  {
    fprintf (stderr, "Usage: %s dispatch|async\n", argv[0]);
    return 2;
  }
  asynchronous = strcmp (argv[1], "async") == 0;
  signal (SIGALRM, watchdog);
  alarm (5);
  frida_init ();
  g_mutex_init (&fixture.mutex);
  g_cond_init (&fixture.changed);
  require (socketpair (AF_UNIX, SOCK_STREAM, 0, pair) == 0, "local-socketpair");
  server_stream = stream_from_fd (pair[0]);
  fixture.client_stream = stream_from_fd (pair[1]);
  fixture.server_context = g_main_context_new ();
  g_main_context_push_thread_default (fixture.server_context);
  client_thread = g_thread_new ("dbus-retirement-client", client_main, &fixture);
  guid = g_dbus_generate_guid ();
  server = g_dbus_connection_new_sync (G_IO_STREAM (server_stream), guid,
      G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_SERVER
          | G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_ALLOW_ANONYMOUS
          | G_DBUS_CONNECTION_FLAGS_DELAY_MESSAGE_PROCESSING,
      NULL, NULL, &error);
  g_free (guid);
  if (server == NULL)
    fail ("server-authentication", error);
  g_object_weak_ref (G_OBJECT (server), finalized, &fixture.server_finalized);
  g_dbus_connection_set_exit_on_close (server, FALSE);
  info = g_dbus_node_info_new_for_xml (introspection, &error);
  if (info == NULL)
    fail ("introspection", error);
  registration = g_dbus_connection_register_object (server, TEST_PATH, info->interfaces[0],
      &vtable, &fixture, registration_freed, &error);
  if (registration == 0)
    fail ("register-test-method", error);
  filter = g_dbus_connection_add_filter (server, observe_call, &fixture, NULL);
  g_dbus_connection_start_message_processing (server);
  while (g_main_context_pending (fixture.server_context))
    g_main_context_iteration (fixture.server_context, FALSE);

  g_mutex_lock (&fixture.mutex);
  while (!fixture.client_ready)
    g_cond_wait (&fixture.changed, &fixture.mutex);
  fixture.start_call = TRUE;
  g_cond_broadcast (&fixture.changed);
  g_mutex_unlock (&fixture.mutex);

  /* The filter runs in GDBus' worker. Pending context work after that filter
   * proves delivery reached the real dispatcher without invoking the method.
   * This bounded wait deliberately does not pump the server context. */
  while (g_atomic_int_get (&fixture.call_seen) == 0
      || !g_main_context_pending (fixture.server_context))
    g_usleep (100);
  require (g_atomic_int_get (&fixture.call_seen) == 1, "one-queued-test-call");
  require (g_atomic_int_get (&fixture.method_calls) == 0, "server-context-is-paused");
  if (asynchronous)
  {
    while (g_atomic_int_get (&fixture.method_calls) == 0)
      g_main_context_iteration (fixture.server_context, TRUE);
    require (fixture.invocation != NULL, "async-invocation-was-captured");
  }

  pending_cancellable = g_cancellable_new ();
  g_object_weak_ref (G_OBJECT (pending_cancellable), finalized, &fixture.cancellable_finalized);
  g_dbus_connection_call (server, NULL, TEST_PATH, TEST_INTERFACE, "Pending", NULL,
      NULL, G_DBUS_CALL_FLAGS_NONE, 4000, pending_cancellable, pending_finished, &fixture);
  g_object_unref (pending_cancellable);
  while (g_atomic_int_get (&fixture.pending_seen) == 0)
    g_usleep (100);
  require (g_atomic_int_get (&fixture.pending_count) == 0, "local-call-still-pending");
  require (g_dbus_connection_unregister_object (server, registration), "unregister-test-method");
  g_object_run_dispose (G_OBJECT (server));
  g_object_run_dispose (G_OBJECT (server));
  if (asynchronous)
  {
    GSource * source = g_idle_source_new ();
    g_source_set_priority (source, G_PRIORITY_DEFAULT);
    g_source_set_callback (source, complete_method, &fixture, NULL);
    g_source_attach (source, fixture.server_context);
    g_source_unref (source);
  }
  while (g_atomic_int_get (&fixture.registration_freed) == 0
      || (asynchronous && g_atomic_int_get (&fixture.completion_count) == 0))
    g_main_context_iteration (fixture.server_context, TRUE);
  while (g_main_context_pending (fixture.server_context))
    g_main_context_iteration (fixture.server_context, FALSE);

  /* Keep this after dispatch/completion so the regression exercises the actual
   * queued callback path before checking the public retirement error. */
  require_closed_send (server);
  require (g_dbus_connection_is_closed (server), "disposed-connection-is-closed");
  require (!g_dbus_connection_flush_sync (server, NULL, &error)
      && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED), "retired-sync-flush-closed");
  g_clear_error (&error);
  require (!g_dbus_connection_close_sync (server, NULL, &error)
      && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CLOSED), "retired-sync-close-closed");
  g_clear_error (&error);
  g_dbus_connection_start_message_processing (server);
  g_dbus_connection_flush (server, NULL, retired_flush_finished, &fixture);
  g_dbus_connection_close (server, NULL, retired_close_finished, &fixture);
  g_dbus_connection_call (server, NULL, TEST_PATH, TEST_INTERFACE, "Pending", NULL,
      NULL, G_DBUS_CALL_FLAGS_NONE, 4000, NULL, pending_finished, &fixture);
  while (g_atomic_int_get (&fixture.retired_operations) != 2
      || g_atomic_int_get (&fixture.pending_count) != 2)
    g_main_context_iteration (fixture.server_context, TRUE);
  require (g_atomic_int_get (&fixture.cancellable_finalized) == 1,
      "pending-cancellable-and-task-released");
  g_thread_join (client_thread);
  if (!g_atomic_int_get (&fixture.client_closed_error))
  {
    fprintf (stderr, "FAIL stage=client-completion-closed actual=%s\n", fixture.callback_error);
    return 1;
  }
  require (g_atomic_int_get (&fixture.callback_count) == 1, "client-completes-once");
  require (g_atomic_int_get (&fixture.method_calls) == (asynchronous ? 1 : 0), "expected-method-dispatch-count");
  require (g_atomic_int_get (&fixture.registration_freed) == 1, "registration-freed-once");
  if (asynchronous)
    require (g_atomic_int_get (&fixture.invocation_finalized) == 1, "invocation-finalized-once");

  g_dbus_connection_remove_filter (server, filter);
  g_object_unref (server);
  g_dbus_node_info_unref (info);
  g_object_unref (server_stream);
  g_object_unref (fixture.client_stream);
  while (g_main_context_pending (fixture.server_context))
    g_main_context_iteration (fixture.server_context, FALSE);
  require (g_atomic_int_get (&fixture.server_finalized) == 1, "server-finalized-once");
  require (g_atomic_int_get (&fixture.client_finalized) == 1, "client-finalized-once");
  g_main_context_pop_thread_default (fixture.server_context);
  g_main_context_unref (fixture.server_context);
  g_free (fixture.callback_error);
  g_cond_clear (&fixture.changed);
  g_mutex_clear (&fixture.mutex);
  frida_deinit ();
  alarm (0);
  printf ("PASS mode=%s methods=%d completed=1 references=released\n", argv[1], asynchronous ? 1 : 0);
  return 0;
}
