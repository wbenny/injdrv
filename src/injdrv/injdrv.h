#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#if DBG
#  define InjDbgPrint(Format, ...)  \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_ERROR_LEVEL,          \
               Format,                      \
               __VA_ARGS__)
#else
#  define InjDbgPrint(Format, ...)
#endif

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _INJ_ARCHITECTURE
{
  InjArchitectureX86,
  InjArchitectureX64,
  InjArchitectureARM32,
  InjArchitectureARM64,
  InjArchitectureMax,

#if defined(_M_IX86)
  InjArchitectureNative = InjArchitectureX86
#elif defined (_M_AMD64)
  InjArchitectureNative = InjArchitectureX64
#elif defined (_M_ARM64)
  InjArchitectureNative = InjArchitectureARM64
#endif
} INJ_ARCHITECTURE;

typedef enum _INJ_METHOD
{
  //
  // Inject process by executing short "shellcode" which
  // calls LdrLoadDll.
  // This method always loads DLL of the same architecture
  // as the process.
  //

  InjMethodThunk,

  //
  // Inject process by directly setting LdrLoadDll as the
  // user-mode APC routine.
  // This method always loads x64 DLL into the process.
  //
  // N.B. Available only on x64.
  //

  InjMethodThunkless,

  //
  // Inject Wow64 process by redirecting path of the "wow64log.dll"
  // to the path of the "injdll".  Native processes are injected
  // as if the "thunk method" was selected (InjMethodThunk).
  //
  // This method always loads DLL of the same architecture
  // as the OS into the process.
  //

  InjMethodWow64LogReparse,
} INJ_METHOD;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _INJ_SETTINGS
{
  //
  // Paths to the inject DLLs for each architecture.
  // Unsupported architectures (either by OS or the
  // method) can have empty string.
  //

  UNICODE_STRING  DllPath[InjArchitectureMax];

  //
  // Injection method.
  //

  INJ_METHOD      Method;
} INJ_SETTINGS, *PINJ_SETTINGS;

typedef struct _INJ_INJECTION_INFO
{
  LIST_ENTRY  ListEntry;

  //
  // Process ID.
  //

  HANDLE      ProcessId;

  //
  // Combination of INJ_SYSTEM_DLL flags indicating
  // which DLLs has been already loaded into this
  // process.
  //

  ULONG       LoadedDlls;

  //
  // If true, the process has been already injected.
  //

  BOOLEAN     IsInjected;

  //
  // If true, trigger of the queued user APC will be
  // immediately forced upon next kernel->user transition.
  //

  BOOLEAN     ForceUserApc;

  //
  // Address of LdrLoadDll routine within ntdll.dll
  // (which ntdll.dll is selected is based on the INJ_METHOD).
  //

  PVOID       LdrLoadDllRoutineAddress;

  //
  // Injection method.
  //

  INJ_METHOD  Method;
} INJ_INJECTION_INFO, *PINJ_INJECTION_INFO;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjInitialize(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath,
  _In_ PINJ_SETTINGS Settings
  );

VOID
NTAPI
InjDestroy(
  VOID
  );

NTSTATUS
NTAPI
InjCreateInjectionInfo(
  _In_opt_ PINJ_INJECTION_INFO* InjectionInfo,
  _In_ HANDLE ProcessId
  );

VOID
NTAPI
InjRemoveInjectionInfo(
  _In_ PINJ_INJECTION_INFO InjectionInfo,
  _In_ BOOLEAN FreeMemory
  );

VOID
NTAPI
InjRemoveInjectionInfoByProcessId(
  _In_ HANDLE ProcessId,
  _In_ BOOLEAN FreeMemory
  );

PINJ_INJECTION_INFO
NTAPI
InjFindInjectionInfo(
  _In_ HANDLE ProcessId
  );

BOOLEAN
NTAPI
InjCanInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo
  );

NTSTATUS
NTAPI
InjInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo
  );

//////////////////////////////////////////////////////////////////////////
// Notify routines.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
InjCreateProcessNotifyRoutineEx(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
  );

VOID
NTAPI
InjLoadImageNotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_ HANDLE ProcessId,
  _In_ PIMAGE_INFO ImageInfo
  );

#ifdef __cplusplus
}
#endif
