#include <stdio.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "install.h"

//
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//

GUID ProviderGuid = {
  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
};

//
// GUID:
//   {53d82d11-cede-4dff-8eb4-f06631800128}
//

GUID SessionGuid = {
  0x53d82d11, 0xcede, 0x4dff, { 0x8e, 0xb4, 0xf0, 0x66, 0x31, 0x80, 0x1, 0x28 }
};

TCHAR SessionName[] = TEXT("InjSession");

VOID
WINAPI
TraceEventCallback(
  _In_ PEVENT_RECORD EventRecord
  )
{
  if (!EventRecord->UserData)
  {
    return;
  }

  //
  // TODO: Check that EventRecord contains only WCHAR string.
  //

  wprintf(L"[PID:%04X][TID:%04X] %s\n",
          EventRecord->EventHeader.ProcessId,
          EventRecord->EventHeader.ThreadId,
          (PWCHAR)EventRecord->UserData);
}

ULONG
NTAPI
TraceStart(
  VOID
  )
{
  //
  // Start new trace session.
  // For an awesome blogpost on ETW API, see:
  // https://caseymuratori.com/blog_0025
  //

  ULONG ErrorCode;

  TRACEHANDLE TraceSessionHandle = INVALID_PROCESSTRACE_HANDLE;

  BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
  RtlZeroMemory(Buffer, sizeof(Buffer));

  PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
  EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);

  RtlZeroMemory(Buffer, sizeof(Buffer));
  EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
  EventTraceProperties->Wnode.ClientContext = 1; // Use QueryPerformanceCounter, see MSDN
  EventTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  EventTraceProperties->LogFileMode = PROCESS_TRACE_MODE_REAL_TIME;
  EventTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  ErrorCode = StartTrace(&TraceSessionHandle, SessionName, EventTraceProperties);
  if (ErrorCode != ERROR_SUCCESS)
  {
    goto Exit;
  }

  //
  // Enable tracing of our provider.
  //

  ErrorCode = EnableTrace(TRUE, 0, 0, &ProviderGuid, TraceSessionHandle);
  if (ErrorCode != ERROR_SUCCESS)
  {
    goto Exit;
  }

  EVENT_TRACE_LOGFILE TraceLogfile = { 0 };
  TraceLogfile.LoggerName = SessionName;
  TraceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
  TraceLogfile.EventRecordCallback = &TraceEventCallback;

  //
  // Open real-time tracing session.
  //

  TRACEHANDLE TraceHandle = OpenTrace(&TraceLogfile);
  if (TraceHandle == INVALID_PROCESSTRACE_HANDLE)
  {
    //
    // Synthetic error code.
    //
    ErrorCode = ERROR_FUNCTION_FAILED;
    goto Exit;
  }

  //
  // Process trace events.  This call is blocking.
  //

  ErrorCode = ProcessTrace(&TraceHandle, 1, NULL, NULL);

Exit:
  if (TraceHandle)
  {
    CloseTrace(TraceHandle);
  }

  if (TraceSessionHandle)
  {
    CloseTrace(TraceSessionHandle);
  }

  RtlZeroMemory(Buffer, sizeof(Buffer));
  EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
  StopTrace(0, SessionName, EventTraceProperties);

  if (ErrorCode != ERROR_SUCCESS)
  {
    printf("Error: %08x\n", ErrorCode);
  }

  return ErrorCode;
}

VOID
NTAPI
TraceStop(
  VOID
  )
{
  BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
  RtlZeroMemory(Buffer, sizeof(Buffer));

  PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
  EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);

  StopTrace(0, SessionName, EventTraceProperties);
}

//////////////////////////////////////////////////////////////////////////

BOOLEAN
DoInstallUninstall(
  _In_ BOOLEAN Install
  )
{
  TCHAR driverLocation[MAX_PATH] = { 0 };

  //
  // The driver is not started yet so let us install the driver.
  // First setup full path to driver name.
  //

  if (!SetupDriverName(driverLocation, sizeof(driverLocation)))
  {
    return FALSE;
  }

  if (Install)
  {
    if (!ManageDriver(TEXT(DRIVER_NAME),
                      driverLocation,
                      DRIVER_FUNC_INSTALL))
    {
      printf("Unable to install driver. \n");

      //
      // Error - remove driver.
      //

      ManageDriver(TEXT(DRIVER_NAME),
                   driverLocation,
                   DRIVER_FUNC_REMOVE);

      return FALSE;
    }
  }
  else
  {
    //
    // Ignore errors.
    //

    ManageDriver(TEXT(DRIVER_NAME),
                 driverLocation,
                 DRIVER_FUNC_REMOVE);
  }

  return TRUE;
}

BOOL
WINAPI
CtrlCHandlerRoutine(
  _In_ DWORD dwCtrlType
  )
{
  if (dwCtrlType == CTRL_C_EVENT)
  {
    //
    // Ctrl+C was pressed, stop the trace session.
    //
    printf("Ctrl+C pressed, stopping trace session...\n");

    TraceStop();
  }

  return FALSE;
}

int main(int argc, char* argv[])
{
  SetConsoleCtrlHandler(&CtrlCHandlerRoutine, TRUE);

  //
  // Stop any previous trace session (if exists).
  //

  TraceStop();

  //
  // Parse command-line parameters.
  //

  if (argc == 2)
  {
    TCHAR DriverLocation[MAX_PATH];
    SetupDriverName(DriverLocation, sizeof(DriverLocation));

    if (!strcmp(argv[1], "-i"))
    {
      printf("Installing driver...\n");

      if (DoInstallUninstall(TRUE))
      {
        printf("Driver installed!\n");
      }
      else
      {
        printf("Error!\n");
        return EXIT_FAILURE;
      }
    }
    else if (!strcmp(argv[1], "-u"))
    {
      printf("Uninstalling driver...\n");

      DoInstallUninstall(FALSE);

      return EXIT_SUCCESS;
    }
  }

  printf("Starting tracing session...\n");

  ULONG ErrorCode = TraceStart();

  return ErrorCode == ERROR_SUCCESS
    ? EXIT_SUCCESS
    : EXIT_FAILURE;
}
