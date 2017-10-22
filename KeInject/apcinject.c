#include "apcinject.h"
#include "utils/image.h"
#include "nt/ntapc.h"

#define AI_MEMORY_TAG ' jnI'

//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

AI_COMMON_DATA CommonData;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
AiInitialize(
  PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  NTSTATUS Status;

  InitializeListHead(&CommonData.ProcessListHead);

  Status = PsSetLoadImageNotifyRoutine(&AipLoadImageNotifyRoutine);
  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  Status = PsSetCreateProcessNotifyRoutineEx(&AipCreateProcessNotifyRoutineEx, FALSE);
  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  return Status;
}

VOID
NTAPI
AiDestroy(
  PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  PsRemoveLoadImageNotifyRoutine(&AipLoadImageNotifyRoutine);
  PsSetCreateProcessNotifyRoutineEx(&AipCreateProcessNotifyRoutineEx, TRUE);
}

PAI_HOOK_INFO
NTAPI
AiFindHookInfoByProcessId(
  _In_ HANDLE ProcessId
  )
{
  PLIST_ENTRY NextEntry = CommonData.ProcessListHead.Flink;
  while (NextEntry != &CommonData.ProcessListHead)
  {
    PAI_HOOK_INFO HookInfo = CONTAINING_RECORD(NextEntry, AI_HOOK_INFO, ListEntry);

    if (HookInfo->ProcessId == ProcessId)
    {
      return HookInfo;
    }

    NextEntry = NextEntry->Flink;
  }

  return NULL;
}

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
  )
{
  UNREFERENCED_PARAMETER(NormalRoutine);
  UNREFERENCED_PARAMETER(NormalContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  ExFreePoolWithTag(Apc, AI_MEMORY_TAG);
}

VOID
NTAPI
AipInjectorKernelKernelRoutine(
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
  _Inout_ PVOID *NormalContext,
  _Inout_ PVOID *SystemArgument1,
  _Inout_ PVOID *SystemArgument2
  )
{
  UNREFERENCED_PARAMETER(NormalRoutine);
  UNREFERENCED_PARAMETER(NormalContext);
  UNREFERENCED_PARAMETER(SystemArgument2);

  NTSTATUS Status;

  //
  // Create memory section.
  //

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(
    &ObjectAttributes,
    NULL,
    OBJ_KERNEL_HANDLE,
    NULL,
    NULL);

  HANDLE SectionHandle;
  LARGE_INTEGER MaximumSize;
  MaximumSize.QuadPart = PAGE_SIZE;
  Status = ZwCreateSection(
    &SectionHandle,
    GENERIC_READ | GENERIC_WRITE,
    &ObjectAttributes,
    &MaximumSize,
    PAGE_EXECUTE_READWRITE,
    SEC_COMMIT,
    NULL);

  if (!NT_SUCCESS(Status))
  {
    return;
  }

  //
  // Map view of section.
  //

  PVOID BaseAddress = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  Status = ZwMapViewOfSection(
    SectionHandle,
    NtCurrentProcess(),
    &BaseAddress,
    0,
    PAGE_SIZE,
    NULL,
    &ViewSize,
    ViewUnmap,
    0,
    PAGE_EXECUTE_READWRITE);

  if (!NT_SUCCESS(Status))
  {
    return;
  }

  //
  // Write the stub.
  //

  //
  // BYTE ApcCallbackStub[];
  // UNICODE_STRING DllName;
  // WCHAR DllNameBuffer[];
  //

  PWCHAR DllNameStatic = L"C:\\ai.dll";

  extern ULONG_PTR AiDeliverApcLabelSize;
  extern VOID(NTAPI*AiDeliverApc)();
  __debugbreak();
  PUCHAR ApcCallbackStub  = (PUCHAR)BaseAddress;
  PUNICODE_STRING DllName = (PUNICODE_STRING)(ApcCallbackStub + AiDeliverApcLabelSize);
  PWCHAR DllNameBuffer    = (PWCHAR)((PUCHAR)DllName + sizeof(UNICODE_STRING));

  RtlCopyMemory(ApcCallbackStub, &AiDeliverApc, AiDeliverApcLabelSize);
  RtlCopyMemory(DllNameBuffer, DllNameStatic, sizeof(DllNameStatic));
  RtlInitUnicodeString(DllName, DllNameBuffer);

  PKAPC UserModeApc = ExAllocatePoolWithTag(
    NonPagedPoolNx,
    sizeof(KAPC),
    AI_MEMORY_TAG);

  if (!Apc)
  {
    return;
  }

  //
  // Initialize and queue the APC.
  //

  KeInitializeApc(
    UserModeApc,                              // Apc
    PsGetCurrentThread(),                     // Thread
    OriginalApcEnvironment,                   // Environment
    &AipInjectorUserKernelRoutine,            // KernelRoutine
    NULL,                                     // RundownRoutine
    (PKNORMAL_ROUTINE)(ULONG_PTR)BaseAddress, // NormalRoutine
    UserMode,                                 // ApcMode
    NULL);                                    // NormalContext

  KeInsertQueueApc(
    UserModeApc,                              // Apc
    CommonData.NtdllLdrLoadDllRoutine,        // SystemArgument1
    NULL,                                     // SystemArgument2
    0);                                       // Increment

  PAI_HOOK_INFO HookInfo = *SystemArgument1;
  HookInfo->Flags |= AHF_HOOK_INSTALLED;

  //
  // Set thread to the alertable state.
  // This will result in immediate APC trigger.
  //
  // LARGE_INTEGER Interval = { 0 };
  // KeDelayExecutionThread(UserMode, TRUE, &Interval);
  KeAlertThread(KeGetCurrentThread(), UserMode);

  //
  // Deallocate the APC.
  //
  ExFreePoolWithTag(Apc, AI_MEMORY_TAG);
}

VOID
NTAPI
AipInjectorKernelRundownRoutine(
  _In_ PKAPC Apc
  )
{
  ExFreePoolWithTag(Apc, AI_MEMORY_TAG);
}

VOID
NTAPI
AipLoadImageNotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_ HANDLE ProcessId,
  _In_ PIMAGE_INFO ImageInfo
  )
{
  UNREFERENCED_PARAMETER(ImageInfo);

  PAI_HOOK_INFO HookInfo = AiFindHookInfoByProcessId(ProcessId);

  if (!HookInfo)
  {
    return;
  }

  if (HookInfo->Flags == AHF_NTDLL_LOADED)
  {
    //
    // We cannot call MapViewOfSection directly from here,
    // because MapViewOfSection is already on stack
    // and it locks EPROCESS->AddressCreationLock.
    //
    // Therefore calling this function recursively would result
    // in deadlock. Work around this by kernel APC.
    //
    PKAPC KernelModeApc = ExAllocatePoolWithTag(
      NonPagedPoolNx,
      sizeof(KAPC),
      AI_MEMORY_TAG);

    KeInitializeApc(
      KernelModeApc,                    // Apc
      PsGetCurrentThread(),             // Thread
      OriginalApcEnvironment,           // Environment
      &AipInjectorKernelKernelRoutine,   // KernelRoutine
      &AipInjectorKernelRundownRoutine,  // RundownRoutine
      NULL,                             // NormalRoutine
      KernelMode,                       // ApcMode
      NULL);                            // NormalContext

    KeInsertQueueApc(
      KernelModeApc,                    // Apc
      HookInfo,                         // SystemArgument1
      NULL,                             // SystemArgument2
      0);                               // Increment
  }

  UNICODE_STRING NtdllExpression = RTL_CONSTANT_STRING(L"*\\NTDLL.DLL");
  if (FsRtlIsNameInExpression(&NtdllExpression, FullImageName, TRUE, NULL))
  {
    ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");
    CommonData.NtdllBaseAddress = ImageInfo->ImageBase;
    CommonData.NtdllLdrLoadDllRoutine = AiFindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDllRoutineName);

    HookInfo->Flags |= AHF_NTDLL_LOADED;
  }
}

VOID
NTAPI
AipCreateProcessNotifyRoutineEx(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
  )
{
  UNREFERENCED_PARAMETER(Process);

  if (CreateInfo)
  {
    PAI_HOOK_INFO HookInfo = ExAllocatePoolWithTag(
      NonPagedPoolNx,
      sizeof(AI_HOOK_INFO),
      AI_MEMORY_TAG);

    HookInfo->ProcessId = ProcessId;
    HookInfo->Flags = AHF_NONE;

    InsertTailList(&CommonData.ProcessListHead, &HookInfo->ListEntry);
  }
  else
  {
    PAI_HOOK_INFO HookInfo = AiFindHookInfoByProcessId(ProcessId);

    if (HookInfo)
    {
      RemoveEntryList(&HookInfo->ListEntry);
      ExFreePoolWithTag(HookInfo, AI_MEMORY_TAG);
    }
  }
}
