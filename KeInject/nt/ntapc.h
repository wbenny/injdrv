#pragma once
#include <ntifs.h>

typedef enum _KAPC_ENVIRONMENT {
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment,
  InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(NTAPI *PKNORMAL_ROUTINE) (
  _In_ PVOID NormalContext,
  _In_ PVOID SystemArgument1,
  _In_ PVOID SystemArgument2
  );

typedef
VOID
(NTAPI *PKKERNEL_ROUTINE) (
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
  _Inout_ PVOID *NormalContext,
  _Inout_ PVOID *SystemArgument1,
  _Inout_ PVOID *SystemArgument2
  );

typedef
VOID
(NTAPI *PKRUNDOWN_ROUTINE) (
  _In_ PKAPC Apc
  );

VOID
NTAPI
KeInitializeApc(
  _Out_ PRKAPC Apc,
  _In_ PRKTHREAD Thread,
  _In_ KAPC_ENVIRONMENT Environment,
  _In_ PKKERNEL_ROUTINE KernelRoutine,
  _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
  _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
  _In_opt_ KPROCESSOR_MODE ApcMode,
  _In_opt_ PVOID NormalContext
  );

BOOLEAN
NTAPI
KeInsertQueueApc(
  _Inout_ PRKAPC Apc,
  _In_opt_ PVOID SystemArgument1,
  _In_opt_ PVOID SystemArgument2,
  _In_ KPRIORITY Increment
  );

BOOLEAN
NTAPI
KeAlertThread(
  _Inout_ PKTHREAD Thread,
  _In_ KPROCESSOR_MODE AlertMode
  );

