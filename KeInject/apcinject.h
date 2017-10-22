#pragma once
#include "nt/ntapc.h"

#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _AI_HOOK_FLAG
{
  AHF_NONE           = 0,
  AHF_NTDLL_LOADED   = 1 << 0,
  AHF_HOOK_INSTALLED = 1 << 1,
} AI_HOOK_FLAG;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _AI_HOOK_INFO
{
  LIST_ENTRY ListEntry;

  HANDLE ProcessId;
  ULONG  Flags;
} AI_HOOK_INFO, *PAI_HOOK_INFO;

typedef struct _AI_COMMON_DATA
{
  LIST_ENTRY ProcessListHead;
  PVOID      NtdllBaseAddress;
  PVOID      NtdllLdrLoadDllRoutine;
} AI_COMMON_DATA;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AiInitialize(
  PDRIVER_OBJECT DriverObject
  );

VOID
NTAPI
AiDestroy(
  PDRIVER_OBJECT DriverObject
  );

PAI_HOOK_INFO
NTAPI
AiFindHookInfoByProcessId(
  _In_ HANDLE ProcessId
  );

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
AipInjectorUserKernelRoutine(
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
  _Inout_ PVOID *NormalContext,
  _Inout_ PVOID *SystemArgument1,
  _Inout_ PVOID *SystemArgument2
  );

VOID
NTAPI
AipInjectorKernelKernelRoutine(
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
  _Inout_ PVOID *NormalContext,
  _Inout_ PVOID *SystemArgument1,
  _Inout_ PVOID *SystemArgument2
  );

VOID
NTAPI
AipInjectorKernelRundownRoutine(
  _In_ PKAPC Apc
  );

VOID
NTAPI
AipLoadImageNotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_ HANDLE ProcessId,
  _In_ PIMAGE_INFO ImageInfo
  );

VOID
NTAPI
AipCreateProcessNotifyRoutineEx(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
  );

VOID
NTAPI
AipDriverDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  );
