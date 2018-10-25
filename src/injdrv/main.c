#include "../injlib/injlib.h"

#include <ntddk.h>

//////////////////////////////////////////////////////////////////////////
// Helper functions.
//////////////////////////////////////////////////////////////////////////

//
// Taken from ReactOS, used by InjpInitializeDllPaths.
//

typedef union
{
  WCHAR Name[sizeof(ULARGE_INTEGER) / sizeof(WCHAR)];
  ULARGE_INTEGER Alignment;
} ALIGNEDNAME;

//
// DOS Device Prefix \??\
//

ALIGNEDNAME ObpDosDevicesShortNamePrefix = { { L'\\', L'?', L'?', L'\\' } };
UNICODE_STRING ObpDosDevicesShortName = {
  sizeof(ObpDosDevicesShortNamePrefix), // Length
  sizeof(ObpDosDevicesShortNamePrefix), // MaximumLength
  (PWSTR)&ObpDosDevicesShortNamePrefix  // Buffer
};

NTSTATUS
NTAPI
InjpJoinPath(
  _In_ PUNICODE_STRING Directory,
  _In_ PUNICODE_STRING Filename,
  _Inout_ PUNICODE_STRING FullPath
  )
{
  UNICODE_STRING UnicodeBackslash = RTL_CONSTANT_STRING(L"\\");

  BOOLEAN DirectoryEndsWithBackslash = Directory->Length > 0 &&
                                       Directory->Buffer[Directory->Length - 1] == L'\\';

  if (FullPath->MaximumLength < Directory->Length ||
      FullPath->MaximumLength - Directory->Length -
        (!DirectoryEndsWithBackslash ? 1 : 0) < Filename->Length)
  {
    return STATUS_DATA_ERROR;
  }

  RtlCopyUnicodeString(FullPath, Directory);

  if (!DirectoryEndsWithBackslash)
  {
    RtlAppendUnicodeStringToString(FullPath, &UnicodeBackslash);
  }

  RtlAppendUnicodeStringToString(FullPath, Filename);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
InjCreateSettings(
  _In_ PUNICODE_STRING RegistryPath,
  _Inout_ PINJ_SETTINGS Settings
  )
{
  //
  // In the "ImagePath" key of the RegistryPath, there
  // is a full path of this driver file.  Fetch it.
  //

  NTSTATUS Status;

  UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"ImagePath");

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(&ObjectAttributes,
                             RegistryPath,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

  HANDLE KeyHandle;
  Status = ZwOpenKey(&KeyHandle,
                     KEY_READ,
                     &ObjectAttributes);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Save all information on stack - simply fail if path
  // is too long.
  //

  UCHAR KeyValueInformationBuffer[sizeof(KEY_VALUE_FULL_INFORMATION) + sizeof(WCHAR) * 128];
  PKEY_VALUE_FULL_INFORMATION KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformationBuffer;

  ULONG ResultLength;
  Status = ZwQueryValueKey(KeyHandle,
                           &ValueName,
                           KeyValueFullInformation,
                           KeyValueInformation,
                           sizeof(KeyValueInformationBuffer),
                           &ResultLength);

  ZwClose(KeyHandle);

  //
  // Check for succes.  Also check if the value is of expected
  // type and whether the path has a meaninful length.
  //

  if (!NT_SUCCESS(Status) ||
      KeyValueInformation->Type != REG_EXPAND_SZ ||
      KeyValueInformation->DataLength < sizeof(ObpDosDevicesShortNamePrefix))
  {
    return Status;
  }

  //
  // Save pointer to the fetched ImagePath value and test if
  // the path starts with "\??\" prefix - if so, skip it.
  //

  PWCHAR ImagePathValue = (PWCHAR)((PUCHAR)KeyValueInformation + KeyValueInformation->DataOffset);
  ULONG  ImagePathValueLength = KeyValueInformation->DataLength;

  if (*(PULONGLONG)(ImagePathValue) == ObpDosDevicesShortNamePrefix.Alignment.QuadPart)
  {
    ImagePathValue += ObpDosDevicesShortName.Length / sizeof(WCHAR);
    ImagePathValueLength -= ObpDosDevicesShortName.Length;
  }

  //
  // Cut the string by the last '\' character, leaving there
  // only the directory path.
  //

  PWCHAR LastBackslash = wcsrchr(ImagePathValue, L'\\');

  if (!LastBackslash)
  {
    return STATUS_DATA_ERROR;
  }

  *LastBackslash = UNICODE_NULL;

  UNICODE_STRING Directory;
  RtlInitUnicodeString(&Directory, ImagePathValue);

  //
  // Finally, fill all the buffers...
  //

#define INJ_DLL_X86_NAME    L"injdllx86.dll"
  UNICODE_STRING InjDllNameX86 = RTL_CONSTANT_STRING(INJ_DLL_X86_NAME);
  InjpJoinPath(&Directory, &InjDllNameX86, &Settings->DllPath[InjArchitectureX86]);
  InjDbgPrint("DLL path (x86):   '%wZ'\n", &Settings->DllPath[InjArchitectureX86]);

#define INJ_DLL_X64_NAME    L"injdllx64.dll"
  UNICODE_STRING InjDllNameX64 = RTL_CONSTANT_STRING(INJ_DLL_X64_NAME);
  InjpJoinPath(&Directory, &InjDllNameX64, &Settings->DllPath[InjArchitectureX64]);
  InjDbgPrint("DLL path (x64):   '%wZ'\n", &Settings->DllPath[InjArchitectureX64]);

#define INJ_DLL_ARM32_NAME  L"injdllARM.dll"
  UNICODE_STRING InjDllNameARM32 = RTL_CONSTANT_STRING(INJ_DLL_ARM32_NAME);
  InjpJoinPath(&Directory, &InjDllNameARM32, &Settings->DllPath[InjArchitectureARM32]);
  InjDbgPrint("DLL path (ARM32): '%wZ'\n",   &Settings->DllPath[InjArchitectureARM32]);

#define INJ_DLL_ARM64_NAME  L"injdllARM64.dll"
  UNICODE_STRING InjDllNameARM64 = RTL_CONSTANT_STRING(INJ_DLL_ARM64_NAME);
  InjpJoinPath(&Directory, &InjDllNameARM64, &Settings->DllPath[InjArchitectureARM64]);
  InjDbgPrint("DLL path (ARM64): '%wZ'\n",   &Settings->DllPath[InjArchitectureARM64]);

  return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// DriverEntry and DriverDestroy.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
DriverDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  PsRemoveLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);
  PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, TRUE);

  InjDestroy();
}

NTSTATUS
NTAPI
DriverEntry(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS Status;

  //
  // Register DriverUnload routine.
  //

  DriverObject->DriverUnload = &DriverDestroy;

  //
  // Create injection settings.
  //

  INJ_SETTINGS Settings;

  WCHAR BufferDllPathX86[128];
  Settings.DllPath[InjArchitectureX86].Length = 0;
  Settings.DllPath[InjArchitectureX86].MaximumLength = sizeof(BufferDllPathX86);
  Settings.DllPath[InjArchitectureX86].Buffer = BufferDllPathX86;

  WCHAR BufferDllPathX64[128];
  Settings.DllPath[InjArchitectureX64].Length = 0;
  Settings.DllPath[InjArchitectureX64].MaximumLength = sizeof(BufferDllPathX64);
  Settings.DllPath[InjArchitectureX64].Buffer = BufferDllPathX64;

  WCHAR BufferDllPathARM32[128];
  Settings.DllPath[InjArchitectureARM32].Length = 0;
  Settings.DllPath[InjArchitectureARM32].MaximumLength = sizeof(BufferDllPathARM32);
  Settings.DllPath[InjArchitectureARM32].Buffer = BufferDllPathARM32;

  WCHAR BufferDllPathARM64[128];
  Settings.DllPath[InjArchitectureARM64].Length = 0;
  Settings.DllPath[InjArchitectureARM64].MaximumLength = sizeof(BufferDllPathARM64);
  Settings.DllPath[InjArchitectureARM64].Buffer = BufferDllPathARM64;

  Status = InjCreateSettings(RegistryPath, &Settings);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

#if defined (_M_IX86)
  Settings.Method = InjMethodThunk;
#elif defined (_M_AMD64)
  Settings.Method = InjMethodThunkless;
#elif defined (_M_ARM64)
  Settings.Method = InjMethodWow64LogReparse;
#endif
  //
  // Initialize injection driver.
  //

  Status = InjInitialize(DriverObject, RegistryPath, &Settings);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Install CreateProcess and LoadImage notification routines.
  //

  Status = PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, FALSE);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  Status = PsSetLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);

  if (!NT_SUCCESS(Status))
  {
    PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, TRUE);
    return Status;
  }

  return STATUS_SUCCESS;
}
