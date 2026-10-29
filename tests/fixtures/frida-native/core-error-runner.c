#include "frida-core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main (int argc, char ** argv)
{
  FridaDeviceManager * manager;
  FridaDevice * device = NULL;
  FridaDeviceList * devices;
  FridaSpawnOptions * options;
  FridaSession * session = NULL;
  GError * error = NULL;
  guint pid = 0;
  gint64 deadline;
  int i, result = 1;
  char * child_argv[3];

  if (argc != 4)
  {
    fprintf (stderr, "Usage: %s target case report\n", argv[0]);
    return 2;
  }
  frida_init ();
  manager = frida_device_manager_new ();
  devices = frida_device_manager_enumerate_devices_sync (manager, NULL, &error);
  if (error != NULL)
    goto failure;
  for (i = 0; i != frida_device_list_size (devices); i++)
  {
    FridaDevice * candidate = frida_device_list_get (devices, i);
    if (frida_device_get_dtype (candidate) == FRIDA_DEVICE_TYPE_LOCAL)
      device = g_object_ref (candidate);
    g_object_unref (candidate);
  }
  frida_unref (devices);
  if (device == NULL)
    return 2;

  child_argv[0] = argv[1];
  child_argv[1] = argv[2];
  child_argv[2] = argv[3];
  options = frida_spawn_options_new ();
  frida_spawn_options_set_argv (options, child_argv, 3);
  pid = frida_device_spawn_sync (device, argv[1], options, NULL, &error);
  frida_unref (options);
  if (error != NULL)
    goto failure;
  session = frida_device_attach_sync (device, pid, NULL, NULL, &error);
  if (error != NULL)
    goto failure;
  frida_session_enable_child_gating_sync (session, NULL, &error);
  if (error != NULL)
    goto failure;
  frida_device_resume_sync (device, pid, NULL, &error);
  if (error != NULL)
    goto failure;

  deadline = g_get_monotonic_time () + 15 * G_TIME_SPAN_SECOND;
  while (g_get_monotonic_time () < deadline)
  {
    while (g_main_context_iteration (NULL, FALSE))
      ;
    FILE * report = fopen (argv[3], "r");
    if (report != NULL)
    {
      int value;
      while ((value = fgetc (report)) != EOF)
        if (value == '\n')
          result = 0;
      fclose (report);
      if (result == 0)
        break;
    }
    if (frida_session_is_detached (session))
      break;
    g_usleep (1000);
  }
  if (result != 0)
  {
    fprintf (stderr, "No error-return report for %s; detached=%d\n",
        argv[2], frida_session_is_detached (session));
  }
  /* Do not make manager shutdown race the target's natural exit. The injected
   * agent may still be retiring after the report is durable, so explicitly
   * terminate the fixture process before detaching and closing the manager. */
  frida_device_kill_sync (device, pid, NULL, NULL);
  frida_session_detach_sync (session, NULL, NULL);
  frida_unref (session);
  frida_device_manager_close_sync (manager, NULL, NULL);
  frida_unref (device);
  frida_unref (manager);
  return result;

failure:
  fprintf (stderr, "Core API failed: %s\n", error->message);
  if (pid != 0)
    frida_device_kill_sync (device, pid, NULL, NULL);
  if (session != NULL)
    frida_unref (session);
  if (device != NULL)
    frida_unref (device);
  frida_device_manager_close_sync (manager, NULL, NULL);
  frida_unref (manager);
  g_error_free (error);
  return 2;
}
