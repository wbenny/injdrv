#include "injlib.h"

#include <ntddk.h>
#include <ntimage.h>

#if defined(_M_AMD64) || defined(_M_ARM64)
# define INJ_CONFIG_SUPPORTS_WOW64
#endif

//////////////////////////////////////////////////////////////////////////
// ke.h
//////////////////////////////////////////////////////////////////////////

typedef enum _KAPC_ENVIRONMENT
{
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment,
  InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(NTAPI *PKNORMAL_ROUTINE)(
  _In_ PVOID NormalContext,
  _In_ PVOID SystemArgument1,
  _In_ PVOID SystemArgument2
  );

typedef
VOID
(NTAPI *PKKERNEL_ROUTINE)(
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
  _Inout_ PVOID* NormalContext,
  _Inout_ PVOID* SystemArgument1,
  _Inout_ PVOID* SystemArgument2
  );

typedef
VOID
(NTAPI *PKRUNDOWN_ROUTINE) (
  _In_ PKAPC Apc
  );

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
  _Out_ PRKAPC Apc,
  _In_ PETHREAD Thread,
  _In_ KAPC_ENVIRONMENT Environment,
  _In_ PKKERNEL_ROUTINE KernelRoutine,
  _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
  _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
  _In_opt_ KPROCESSOR_MODE ApcMode,
  _In_opt_ PVOID NormalContext
  );

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
  _Inout_ PRKAPC Apc,
  _In_opt_ PVOID SystemArgument1,
  _In_opt_ PVOID SystemArgument2,
  _In_ KPRIORITY Increment
  );

NTKERNELAPI
BOOLEAN
NTAPI
KeAlertThread(
  _Inout_ PKTHREAD Thread,
  _In_ KPROCESSOR_MODE AlertMode
  );

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(
  _In_ KPROCESSOR_MODE AlertMode
  );

//////////////////////////////////////////////////////////////////////////
// ps.h
//////////////////////////////////////////////////////////////////////////

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
  _In_ PEPROCESS Process
  );

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
  _In_ PEPROCESS Process
  );

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(
  _In_ PEPROCESS Process
  );

NTKERNELAPI
USHORT
NTAPI
PsWow64GetProcessMachine(
  _In_ PEPROCESS Process
  );

//////////////////////////////////////////////////////////////////////////
// ntrtl.h
//////////////////////////////////////////////////////////////////////////

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

NTSYSAPI
NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
  _In_ ULONG Flags,
  _In_ PUNICODE_STRING StringIn,
  _Out_ PUNICODE_STRING StringOut
  );

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
  _In_ PVOID BaseOfImage,
  _In_ BOOLEAN MappedAsImage,
  _In_ USHORT DirectoryEntry,
  _Out_ PULONG Size
  );

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define INJ_MEMORY_TAG ' jnI'

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _INJ_SYSTEM_DLL
{
  INJ_NOTHING_LOADED            = 0x0000,
  INJ_SYSARM32_NTDLL_LOADED     = 0x0001,
  INJ_SYCHPE32_NTDLL_LOADED     = 0x0002,
  INJ_SYSWOW64_NTDLL_LOADED     = 0x0004,
  INJ_SYSTEM32_NTDLL_LOADED     = 0x0008,
  INJ_SYSTEM32_WOW64_LOADED     = 0x0010,
  INJ_SYSTEM32_WOW64WIN_LOADED  = 0x0020,
  INJ_SYSTEM32_WOW64CPU_LOADED  = 0x0040,
  INJ_SYSTEM32_WOWARMHW_LOADED  = 0x0080,
  INJ_SYSTEM32_XTAJIT_LOADED    = 0x0100,
} INJ_SYSTEM_DLL;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _INJ_SYSTEM_DLL_DESCRIPTOR
{
  UNICODE_STRING  DllPath;
  INJ_SYSTEM_DLL  Flag;
} INJ_SYSTEM_DLL_DESCRIPTOR, *PINJ_SYSTEM_DLL_DESCRIPTOR;

typedef struct _INJ_THUNK
{
  PVOID           Buffer;
  USHORT          Length;
} INJ_THUNK, *PINJ_THUNK;

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjpQueueApc(
  _In_ KPROCESSOR_MODE ApcMode,
  _In_ PKNORMAL_ROUTINE NormalRoutine,
  _In_ PVOID NormalContext,
  _In_ PVOID SystemArgument1,
  _In_ PVOID SystemArgument2
  );

VOID
NTAPI
InjpInjectApcNormalRoutine(
  _In_ PVOID NormalContext,
  _In_ PVOID SystemArgument1,
  _In_ PVOID SystemArgument2
  );

VOID
NTAPI
InjpInjectApcKernelRoutine(
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
  _Inout_ PVOID* NormalContext,
  _Inout_ PVOID* SystemArgument1,
  _Inout_ PVOID* SystemArgument2
  );

//
// reparse.c
//

NTSTATUS
NTAPI
SimRepInitialize(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
  );

//////////////////////////////////////////////////////////////////////////
// Private constant variables.
//////////////////////////////////////////////////////////////////////////

ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");

//
// Paths can have format "\Device\HarddiskVolume3\Windows\System32\ntdll.dll",
// so only the end of the string is compared.
//

INJ_SYSTEM_DLL_DESCRIPTOR InjpSystemDlls[] = {
  { RTL_CONSTANT_STRING(L"\\SysArm32\\ntdll.dll"),    INJ_SYSARM32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\SyChpe32\\ntdll.dll"),    INJ_SYCHPE32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\SysWow64\\ntdll.dll"),    INJ_SYSWOW64_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\ntdll.dll"),    INJ_SYSTEM32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64.dll"),    INJ_SYSTEM32_WOW64_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64win.dll"), INJ_SYSTEM32_WOW64WIN_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64cpu.dll"), INJ_SYSTEM32_WOW64CPU_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\wowarmhw.dll"), INJ_SYSTEM32_WOWARMHW_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\xtajit.dll"),   INJ_SYSTEM32_XTAJIT_LOADED   },
};

//
// ;++
// ;
// ; VOID
// ; NTAPI
// ; ApcNormalRoutine(
// ;   _In_ PVOID NormalContext,
// ;   _In_ PVOID SystemArgument1,
// ;   _In_ PVOID SystemArgument2
// ;   )
// ;
// ; Routine Description:
// ;
// ;    This routine loads DLL specified in the NormalContext.
// ;
// ;    If native process is being injected, this function is called
// ;    from the ntdll.dll!KiUserApcDispatcher routine.
// ;
// ;    If Wow64 process is being injected, the following code-flow
// ;    is responsible for reaching this function:
// ;
// ;    - wow64.dll!Wow64ApcRoutine (set by PsWrapApcWow64Thread):
// ;      - Puts NormalRoutine, NormalContext, SystemArgument1 and
// ;        SystemArgument2 on the top of the stack, sets EIP to
// ;        KiUserApcDispatcher of Wow64 ntdll.dll.
// ;    - ntdll.dll!KiUserApcDispatcher (note this is Wow64 ntdll.dll)
// ;      - Pops NormalRoutine - our ApcNormalRoutine - from the stack
// ;        and calls it (note that NormalCountext, SystemArgument1 and
// ;        SystemArgument2 remain on the stack).
// ;
// ;    The shellcode is equivalent to this code - regardless of the
// ;    architecture:
// ;
// ;    VOID
// ;    NTAPI
// ;    ApcNormalRoutine(
// ;        _In_ PVOID NormalContext,    // LdrLoadDll routine address
// ;        _In_ PVOID SystemArgument1,  // DllPath
// ;        _In_ PVOID SystemArgument2   // DllPath length
// ;        )
// ;    {
// ;        UNICODE_STRING DllName;
// ;        PVOID          BaseAddress;
// ;
// ;        DllName.Length        = (USHORT)SystemArgument2;
// ;        DllName.MaximumLength = (USHORT)SystemArgument2;
// ;        DllName.Buffer        = (PWSTR) SystemArgument1;
// ;
// ;        ((PLDRLOADDLL_ROUTINE)NormalContext)(0, 0, &DllName, &BaseAddress);
// ;    }
// ;
// ;    // See: https://gcc.godbolt.org/z/1DDtuW
// ;
// ; Arguments:
// ;
// ;    NormalContext   - LdrLoadDll routine address.
// ;    SystemArgument1 - DLL path.
// ;    SystemArgument2 - Length of DLL path.
// ;
// ; Return Value:
// ;
// ;    None.
// ;
// ;--
//

UCHAR InjpThunkX86[] = {              //
  0x83, 0xec, 0x08,                   // sub    esp,0x8
  0x0f, 0xb7, 0x44, 0x24, 0x14,       // movzx  eax,[esp + 0x14]
  0x66, 0x89, 0x04, 0x24,             // mov    [esp],ax
  0x66, 0x89, 0x44, 0x24, 0x02,       // mov    [esp + 0x2],ax
  0x8b, 0x44, 0x24, 0x10,             // mov    eax,[esp + 0x10]
  0x89, 0x44, 0x24, 0x04,             // mov    [esp + 0x4],eax
  0x8d, 0x44, 0x24, 0x14,             // lea    eax,[esp + 0x14]
  0x50,                               // push   eax
  0x8d, 0x44, 0x24, 0x04,             // lea    eax,[esp + 0x4]
  0x50,                               // push   eax
  0x6a, 0x00,                         // push   0x0
  0x6a, 0x00,                         // push   0x0
  0xff, 0x54, 0x24, 0x1c,             // call   [esp + 0x1c]
  0x83, 0xc4, 0x08,                   // add    esp,0x8
  0xc2, 0x0c, 0x00,                   // ret    0xc
};                                    //

UCHAR InjpThunkX64[] = {              //
  0x48, 0x83, 0xec, 0x38,             // sub    rsp,0x38
  0x48, 0x89, 0xc8,                   // mov    rax,rcx
  0x66, 0x44, 0x89, 0x44, 0x24, 0x20, // mov    [rsp+0x20],r8w
  0x66, 0x44, 0x89, 0x44, 0x24, 0x22, // mov    [rsp+0x22],r8w
  0x4c, 0x8d, 0x4c, 0x24, 0x40,       // lea    r9,[rsp+0x40]
  0x48, 0x89, 0x54, 0x24, 0x28,       // mov    [rsp+0x28],rdx
  0x4c, 0x8d, 0x44, 0x24, 0x20,       // lea    r8,[rsp+0x20]
  0x31, 0xd2,                         // xor    edx,edx
  0x31, 0xc9,                         // xor    ecx,ecx
  0xff, 0xd0,                         // call   rax
  0x48, 0x83, 0xc4, 0x38,             // add    rsp,0x38
  0xc2, 0x00, 0x00,                   // ret    0x0
};                                    //

UCHAR InjpThunkARM32[] = {            //
  0x1f, 0xb5,                         // push   {r0-r4,lr}
  0xad, 0xf8, 0x08, 0x20,             // strh   r2,[sp,#8]
  0xad, 0xf8, 0x0a, 0x20,             // strh   r2,[sp,#0xA]
  0x03, 0x91,                         // str    r1,[sp,#0xC]
  0x02, 0xaa,                         // add    r2,sp,#8
  0x00, 0x21,                         // movs   r1,#0
  0x04, 0x46,                         // mov    r4,r0
  0x6b, 0x46,                         // mov    r3,sp
  0x00, 0x20,                         // movs   r0,#0
  0xa0, 0x47,                         // blx    r4
  0x1f, 0xbd,                         // pop    {r0-r4,pc}
};                                    //

UCHAR InjpThunkARM64[] = {            //
  0xfe, 0x0f, 0x1f, 0xf8,             // str    lr,[sp,#-0x10]!
  0xff, 0x83, 0x00, 0xd1,             // sub    sp,sp,#0x20
  0xe9, 0x03, 0x00, 0xaa,             // mov    x9,x0
  0xe2, 0x13, 0x00, 0x79,             // strh   w2,[sp,#8]
  0x00, 0x00, 0x80, 0xd2,             // mov    x0,#0
  0xe2, 0x17, 0x00, 0x79,             // strh   w2,[sp,#0xA]
  0xe2, 0x23, 0x00, 0x91,             // add    x2,sp,#8
  0xe1, 0x0b, 0x00, 0xf9,             // str    x1,[sp,#0x10]
  0x01, 0x00, 0x80, 0xd2,             // mov    x1,#0
  0xe3, 0x03, 0x00, 0x91,             // mov    x3,sp
  0x20, 0x01, 0x3f, 0xd6,             // blr    x9
  0xff, 0x83, 0x00, 0x91,             // add    sp,sp,#0x20
  0xfe, 0x07, 0x41, 0xf8,             // ldr    lr,[sp],#0x10
  0xc0, 0x03, 0x5f, 0xd6,             // ret
};                                    //

//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

LIST_ENTRY      InjInfoListHead;

INJ_METHOD      InjMethod;

UNICODE_STRING  InjDllPath[InjArchitectureMax];

INJ_THUNK       InjThunk[InjArchitectureMax] = {
  { InjpThunkX86,   sizeof(InjpThunkX86)   },
  { InjpThunkX64,   sizeof(InjpThunkX64)   },
  { InjpThunkARM32, sizeof(InjpThunkARM32) },
  { InjpThunkARM64, sizeof(InjpThunkARM64) },
};

BOOLEAN         InjIsWindows7;

//////////////////////////////////////////////////////////////////////////
// Helper functions.
//////////////////////////////////////////////////////////////////////////

PVOID
NTAPI
RtlxFindExportedRoutineByName(
  _In_ PVOID DllBase,
  _In_ PANSI_STRING ExportName
  )
{
  //
  // RtlFindExportedRoutineByName is not exported by ntoskrnl until Win10.
  // Following code is borrowed from ReactOS.
  //

  PULONG NameTable;
  PUSHORT OrdinalTable;
  PIMAGE_EXPORT_DIRECTORY ExportDirectory;
  LONG Low = 0, Mid = 0, High, Ret;
  USHORT Ordinal;
  PVOID Function;
  ULONG ExportSize;
  PULONG ExportTable;

  //
  // Get the export directory.
  //

  ExportDirectory = RtlImageDirectoryEntryToData(DllBase,
                                                 TRUE,
                                                 IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                 &ExportSize);

  if (!ExportDirectory)
  {
    return NULL;
  }

  //
  // Setup name tables.
  //

  NameTable    = (PULONG) ((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
  OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

  //
  // Do a binary search.
  //

  High = ExportDirectory->NumberOfNames - 1;
  while (High >= Low)
  {
    //
    // Get new middle value.
    //

    Mid = (Low + High) >> 1;

    //
    // Compare name.
    //

    Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);
    if (Ret < 0)
    {
      //
      // Update high.
      //
      High = Mid - 1;
    }
    else if (Ret > 0)
    {
      //
      // Update low.
      //
      Low = Mid + 1;
    }
    else
    {
      //
      // We got it.
      //
      break;
    }
  }

  //
  // Check if we couldn't find it.
  //

  if (High < Low)
  {
    return NULL;
  }

  //
  // Otherwise, this is the ordinal.
  //

  Ordinal = OrdinalTable[Mid];

  //
  // Validate the ordinal.
  //

  if (Ordinal >= ExportDirectory->NumberOfFunctions)
  {
    return NULL;
  }

  //
  // Resolve the address and write it.
  //

  ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
  Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

  //
  // We found it!
  //

  NT_ASSERT(
    (Function < (PVOID)ExportDirectory) ||
    (Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
  );

  return Function;
}

BOOLEAN
NTAPI
RtlxSuffixUnicodeString(
  _In_ PUNICODE_STRING String1,
  _In_ PUNICODE_STRING String2,
  _In_ BOOLEAN CaseInSensitive
  )
{
  //
  // RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
  //

  return String2->Length >= String1->Length &&
         RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - String1->Length) / sizeof(WCHAR),
                                  String1->Length / sizeof(WCHAR),
                                  String1->Buffer,
                                  String1->Length / sizeof(WCHAR),
                                  CaseInSensitive) == 0;

}

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjpQueueApc(
  _In_ KPROCESSOR_MODE ApcMode,
  _In_ PKNORMAL_ROUTINE NormalRoutine,
  _In_ PVOID NormalContext,
  _In_ PVOID SystemArgument1,
  _In_ PVOID SystemArgument2
  )
{
  //
  // Allocate memory for the KAPC structure.
  //

  PKAPC Apc = ExAllocatePoolWithTag(NonPagedPoolNx,
                                    sizeof(KAPC),
                                    INJ_MEMORY_TAG);

  if (!Apc)
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  //
  // Initialize and queue the APC.
  //

  KeInitializeApc(Apc,                                  // Apc
                  PsGetCurrentThread(),                 // Thread
                  OriginalApcEnvironment,               // Environment
                  &InjpInjectApcKernelRoutine,          // KernelRoutine
                  NULL,                                 // RundownRoutine
                  NormalRoutine,                        // NormalRoutine
                  ApcMode,                              // ApcMode
                  NormalContext);                       // NormalContext

  BOOLEAN Inserted = KeInsertQueueApc(Apc,              // Apc
                                      SystemArgument1,  // SystemArgument1
                                      SystemArgument2,  // SystemArgument2
                                      0);               // Increment

  if (!Inserted)
  {
    ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
    return STATUS_UNSUCCESSFUL;
  }

  return STATUS_SUCCESS;
}

VOID
NTAPI
InjpInjectApcNormalRoutine(
  _In_ PVOID NormalContext,
  _In_ PVOID SystemArgument1,
  _In_ PVOID SystemArgument2
  )
{
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  PINJ_INJECTION_INFO InjectionInfo = NormalContext;
  InjInject(InjectionInfo);
}

VOID
NTAPI
InjpInjectApcKernelRoutine(
  _In_ PKAPC Apc,
  _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
  _Inout_ PVOID* NormalContext,
  _Inout_ PVOID* SystemArgument1,
  _Inout_ PVOID* SystemArgument2
  )
{
  UNREFERENCED_PARAMETER(NormalRoutine);
  UNREFERENCED_PARAMETER(NormalContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  //
  // Common kernel routine for both user-mode and
  // kernel-mode APCs queued by the InjpQueueApc
  // function.  Just release the memory of the APC
  // structure and return back.
  //

  ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
}

NTSTATUS
NTAPI
InjpInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo,
  _In_ INJ_ARCHITECTURE Architecture,
  _In_ HANDLE SectionHandle,
  _In_ SIZE_T SectionSize
  )
{
  NTSTATUS Status;

  //
  // First, map this section with read-write access.
  //

  PVOID SectionMemoryAddress = NULL;
  Status = ZwMapViewOfSection(SectionHandle,
                              ZwCurrentProcess(),
                              &SectionMemoryAddress,
                              0,
                              SectionSize,
                              NULL,
                              &SectionSize,
                              ViewUnmap,
                              0,
                              PAGE_READWRITE);

  if (!NT_SUCCESS(Status))
  {
    goto Exit;
  }

  //
  // Code of the APC routine (ApcNormalRoutine defined in the
  // "shellcode" above) starts at the SectionMemoryAddress.
  // Copy the shellcode to the allocated memory.
  //

  PVOID ApcRoutineAddress = SectionMemoryAddress;
  RtlCopyMemory(ApcRoutineAddress,
                InjThunk[Architecture].Buffer,
                InjThunk[Architecture].Length);

  //
  // Fill the data of the ApcContext.
  //

  PWCHAR DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + InjThunk[Architecture].Length);
  RtlCopyMemory(DllPath,
                InjDllPath[Architecture].Buffer,
                InjDllPath[Architecture].Length);

  //
  // Unmap the section and map it again, but now
  // with read-execute (no write) access.
  //

  ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);

  SectionMemoryAddress = NULL;
  Status = ZwMapViewOfSection(SectionHandle,
                              ZwCurrentProcess(),
                              &SectionMemoryAddress,
                              0,
                              PAGE_SIZE,
                              NULL,
                              &SectionSize,
                              ViewUnmap,
                              0,
                              PAGE_EXECUTE_READ);

  if (!NT_SUCCESS(Status))
  {
    goto Exit;
  }

  //
  // Reassign remapped address.
  //

  DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + InjThunk[Architecture].Length);

  PVOID ApcContext   = (PVOID)InjectionInfo->LdrLoadDllRoutineAddress;
  PVOID ApcArgument1 = (PVOID)DllPath;
  PVOID ApcArgument2 = (PVOID)InjDllPath[Architecture].Length;

#if defined(INJ_CONFIG_SUPPORTS_WOW64)

  if (PsGetProcessWow64Process(PsGetCurrentProcess()))
  {
    //
    // The ARM32 ntdll.dll uses "BLX" instruction for calling the ApcRoutine.
    // This instruction can change the processor state (between Thumb & ARM),
    // based on the LSB (least significant bit).  If this bit is 0, the code
    // will run in the ARM instruction set.  If this bit is 1, the code will
    // run in Thumb instruction set.  Because Windows can run only in the Thumb
    // instruction set, we have to ensure this bit is set.  Otherwise, Windows
    // would raise STATUS_ILLEGAL_INSTRUCTION upon execution of the ApcRoutine.
    //

    if (Architecture == InjArchitectureARM32)
    {
      ApcRoutineAddress = (PVOID)((ULONG_PTR)ApcRoutineAddress | 1);
    }

    //
    // PsWrapApcWow64Thread essentially assigns wow64.dll!Wow64ApcRoutine
    // to the NormalRoutine.  This Wow64ApcRoutine (which is 64-bit code)
    // in turn calls KiUserApcDispatcher (in 32-bit ntdll.dll) which finally
    // calls our provided ApcRoutine.
    //

    PsWrapApcWow64Thread(&ApcContext, &ApcRoutineAddress);
  }

#endif

  PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutineAddress;

  Status = InjpQueueApc(UserMode,
                        ApcRoutine,
                        ApcContext,
                        ApcArgument1,
                        ApcArgument2);

  if (!NT_SUCCESS(Status))
  {
    //
    // If injection failed for some reason, unmap the section.
    //

    ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);
  }

Exit:
  return Status;
}

NTSTATUS
NTAPI
InjpInjectX64NoThunk(
  _In_ PINJ_INJECTION_INFO InjectionInfo,
  _In_ INJ_ARCHITECTURE Architecture,
  _In_ HANDLE SectionHandle,
  _In_ SIZE_T SectionSize
  )
{
  NT_ASSERT(InjectionInfo->LdrLoadDllRoutineAddress);
  NT_ASSERT(Architecture == InjArchitectureX64);

  UNREFERENCED_PARAMETER(Architecture);

  NTSTATUS Status;

  PVOID SectionMemoryAddress = NULL;
  Status = ZwMapViewOfSection(SectionHandle,
                              ZwCurrentProcess(),
                              &SectionMemoryAddress,
                              0,
                              PAGE_SIZE,
                              NULL,
                              &SectionSize,
                              ViewUnmap,
                              0,
                              PAGE_READWRITE);

  if (!NT_SUCCESS(Status))
  {
    goto Exit;
  }

  //
  // Create the UNICODE_STRING structure and fill out the
  // full path of the DLL.
  //

  PUNICODE_STRING DllPath = (PUNICODE_STRING)(SectionMemoryAddress);
  PWCHAR DllPathBuffer = (PWCHAR)((PUCHAR)DllPath + sizeof(UNICODE_STRING));

  RtlCopyMemory(DllPathBuffer,
                InjDllPath[Architecture].Buffer,
                InjDllPath[Architecture].Length);

  RtlInitUnicodeString(DllPath, DllPathBuffer);

  Status = InjpQueueApc(UserMode,
                        (PKNORMAL_ROUTINE)(ULONG_PTR)InjectionInfo->LdrLoadDllRoutineAddress,
                        NULL,     // Translates to 1st param. of LdrLoadDll (SearchPath)
                        NULL,     // Translates to 2nd param. of LdrLoadDll (DllCharacteristics)
                        DllPath); // Translates to 3rd param. of LdrLoadDll (DllName)

  //
  // 4th param. of LdrLoadDll (BaseAddress) is actually an output parameter.
  //
  // When control is transferred to the KiUserApcDispatcher routine of the
  // 64-bit ntdll.dll, the RSP points to the CONTEXT structure which might
  // be eventually provided to the ZwContinue function (in case this APC
  // dispatch will be routed to the Wow64 subsystem).
  //
  // Also, the value of the RSP register is moved to the R9 register before
  // calling the KiUserCallForwarder function.  The KiUserCallForwarder
  // function actually passes this value of the R9 register down to the
  // NormalRoutine as a "hidden 4th parameter".
  //
  // Because LdrLoadDll writes to the provided address, it'll actually
  // result in overwrite of the CONTEXT.P1Home field (the first field of
  // the CONTEXT structure).
  //
  // Luckily for us, this field is only used in the very early stage of
  // the APC dispatch and can be overwritten without causing any troubles.
  //
  // For excellent explanation, see:
  // https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-2
  //

Exit:
  return Status;
}

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjInitialize(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath,
  _In_ PINJ_SETTINGS Settings
  )
{
  NTSTATUS Status;

  //
  // Initialize injection info linked list.
  //

  InitializeListHead(&InjInfoListHead);

  ULONG Flags = RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE
              | RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING;

  for (ULONG Architecture = 0; Architecture < InjArchitectureMax; Architecture += 1)
  {
    Status = RtlDuplicateUnicodeString(Flags,
                                       &Settings->DllPath[Architecture],
                                       &InjDllPath[Architecture]);
    if (!NT_SUCCESS(Status))
    {
      goto Error;
    }
  }

  //
  // Check if we're running on Windows 7.
  //

  RTL_OSVERSIONINFOW VersionInformation = { 0 };
  VersionInformation.dwOSVersionInfoSize = sizeof(VersionInformation);
  RtlGetVersion(&VersionInformation);

  if (VersionInformation.dwMajorVersion == 6 &&
      VersionInformation.dwMinorVersion == 1)
  {
    InjDbgPrint("Current system is Windows 7\n");
    InjIsWindows7 = TRUE;
  }

  //
  // Default setting of the injection of Wow64 processes.
  //

#if defined(INJ_CONFIG_SUPPORTS_WOW64)
  InjMethod = Settings->Method;

#  if !defined(_M_AMD64)
  //
  // Thunkless method is available on x64.
  //

  if (InjMethod == InjMethodThunkless)
  {
    InjMethod = InjMethodThunk;
  }
#  endif

#else
  InjMethod = InjMethodThunk;
#endif

  InjDbgPrint("InjMethod: '%s'\n",
    InjMethod == InjMethodThunk           ? "InjMethodThunk"           :
    InjMethod == InjMethodThunkless       ? "InjMethodThunkLess"       :
    InjMethod == InjMethodWow64LogReparse ? "InjMethodWow64LogReparse" :
                                            "UNKNOWN"
    );

  if (InjMethod == InjMethodWow64LogReparse)
  {
    Status = SimRepInitialize(DriverObject, RegistryPath);
  }

  return Status;

Error:
  InjDestroy();
  return Status;
}

VOID
NTAPI
InjDestroy(
  VOID
  )
{
  //
  // Release memory of all injection-info entries.
  //

  PLIST_ENTRY NextEntry = InjInfoListHead.Flink;

  while (NextEntry != &InjInfoListHead)
  {
    PINJ_INJECTION_INFO InjectionInfo = CONTAINING_RECORD(NextEntry,
                                                          INJ_INJECTION_INFO,
                                                          ListEntry);
    NextEntry = NextEntry->Flink;

    ExFreePoolWithTag(InjectionInfo, INJ_MEMORY_TAG);
  }

  //
  // Release memory of all buffers.
  //

  for (ULONG Architecture = 0; Architecture < InjArchitectureMax; Architecture += 1)
  {
    RtlFreeUnicodeString(&InjDllPath[Architecture]);
  }
}

NTSTATUS
NTAPI
InjCreateInjectionInfo(
  _In_opt_ PINJ_INJECTION_INFO* InjectionInfo,
  _In_ HANDLE ProcessId
  )
{
  PINJ_INJECTION_INFO CapturedInjectionInfo;

  if (InjectionInfo && *InjectionInfo)
  {
    CapturedInjectionInfo = *InjectionInfo;
  }
  else
  {
    CapturedInjectionInfo = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                  sizeof(INJ_INJECTION_INFO),
                                                  INJ_MEMORY_TAG);

    if (!CapturedInjectionInfo)
    {
      return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (InjectionInfo)
    {
      *InjectionInfo = CapturedInjectionInfo;
    }
  }

  RtlZeroMemory(CapturedInjectionInfo, sizeof(INJ_INJECTION_INFO));

  CapturedInjectionInfo->ProcessId = ProcessId;
  CapturedInjectionInfo->ForceUserApc = TRUE;
  CapturedInjectionInfo->Method = InjMethod;

  InsertTailList(&InjInfoListHead, &CapturedInjectionInfo->ListEntry);

  return STATUS_SUCCESS;
}

VOID
NTAPI
InjRemoveInjectionInfo(
  _In_ PINJ_INJECTION_INFO InjectionInfo,
  _In_ BOOLEAN FreeMemory
  )
{
  RemoveEntryList(&InjectionInfo->ListEntry);

  if (FreeMemory)
  {
    ExFreePoolWithTag(InjectionInfo, INJ_MEMORY_TAG);
  }
}

VOID
NTAPI
InjRemoveInjectionInfoByProcessId(
  _In_ HANDLE ProcessId,
  _In_ BOOLEAN FreeMemory
  )
{
  PINJ_INJECTION_INFO InjectionInfo = InjFindInjectionInfo(ProcessId);

  if (InjectionInfo)
  {
    InjRemoveInjectionInfo(InjectionInfo, FreeMemory);
  }
}

PINJ_INJECTION_INFO
NTAPI
InjFindInjectionInfo(
  _In_ HANDLE ProcessId
  )
{
  PLIST_ENTRY NextEntry = InjInfoListHead.Flink;

  while (NextEntry != &InjInfoListHead)
  {
    PINJ_INJECTION_INFO InjectionInfo = CONTAINING_RECORD(NextEntry,
                                                          INJ_INJECTION_INFO,
                                                          ListEntry);

    if (InjectionInfo->ProcessId == ProcessId)
    {
      return InjectionInfo;
    }

    NextEntry = NextEntry->Flink;
  }

  return NULL;
}

BOOLEAN
NTAPI
InjCanInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo
  )
{
  //
  // DLLs that need to be loaded in the native process
  // (i.e.: x64 process on x64 Windows, x86 process on
  // x86 Windows) before we can safely load our DLL.
  //

  ULONG RequiredDlls = INJ_SYSTEM32_NTDLL_LOADED;

#if defined(INJ_CONFIG_SUPPORTS_WOW64)

  if (PsGetProcessWow64Process(PsGetCurrentProcess()))
  {
    //
    // DLLs that need to be loaded in the Wow64 process
    // before we can safely load our DLL.
    //

    RequiredDlls |= INJ_SYSTEM32_NTDLL_LOADED;
    RequiredDlls |= INJ_SYSTEM32_WOW64_LOADED;
    RequiredDlls |= INJ_SYSTEM32_WOW64WIN_LOADED;

#   if defined (_M_AMD64)

    RequiredDlls |= INJ_SYSTEM32_WOW64CPU_LOADED;
    RequiredDlls |= INJ_SYSWOW64_NTDLL_LOADED;

#   elif defined (_M_ARM64)

    switch (PsWow64GetProcessMachine(PsGetCurrentProcess()))
    {
      case IMAGE_FILE_MACHINE_I386:
        RequiredDlls |= INJ_SYCHPE32_NTDLL_LOADED;
        RequiredDlls |= INJ_SYSTEM32_XTAJIT_LOADED;
        break;

      case IMAGE_FILE_MACHINE_ARMNT:
        RequiredDlls |= INJ_SYSARM32_NTDLL_LOADED;
        RequiredDlls |= INJ_SYSTEM32_WOWARMHW_LOADED;
        break;

      case IMAGE_FILE_MACHINE_ARM64:
        break;
    }

#   endif

  }

#endif

  return (InjectionInfo->LoadedDlls & RequiredDlls) == RequiredDlls;
}

NTSTATUS
NTAPI
InjInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo
  )
{
  NTSTATUS Status;

  //
  // Create memory space for injection-specific data,
  // such as path to the to-be-injected DLL.  Memory
  // of this section will be eventually mapped to the
  // injected process.
  //
  // Note that this memory is created using sections
  // instead of ZwAllocateVirtualMemory, mainly because
  // function ZwProtectVirtualMemory is not exported
  // by ntoskrnl.exe until Windows 8.1.  In case of
  // sections, the effect of memory protection change
  // is achieved by remaping the section with different
  // protection type.
  //

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(&ObjectAttributes,
                             NULL,
                             OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

  HANDLE SectionHandle;
  SIZE_T SectionSize = PAGE_SIZE;
  LARGE_INTEGER MaximumSize;
  MaximumSize.QuadPart = SectionSize;
  Status = ZwCreateSection(&SectionHandle,
                           GENERIC_READ | GENERIC_WRITE,
                           &ObjectAttributes,
                           &MaximumSize,
                           PAGE_EXECUTE_READWRITE,
                           SEC_COMMIT,
                           NULL);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  INJ_ARCHITECTURE Architecture = InjArchitectureMax;

  if (InjectionInfo->Method == InjMethodThunk ||
      InjectionInfo->Method == InjMethodWow64LogReparse)
  {
#if defined(_M_IX86)

    Architecture = InjArchitectureX86;

#elif defined(_M_AMD64)

    Architecture = PsGetProcessWow64Process(PsGetCurrentProcess())
      ? InjArchitectureX86
      : InjArchitectureX64;

#elif defined(_M_ARM64)

    switch (PsWow64GetProcessMachine(PsGetCurrentProcess()))
    {
      case IMAGE_FILE_MACHINE_I386:
        Architecture = InjArchitectureX86;
        break;

      case IMAGE_FILE_MACHINE_ARMNT:
        Architecture = InjArchitectureARM32;
        break;

      case IMAGE_FILE_MACHINE_ARM64:
        Architecture = InjArchitectureARM64;
        break;
    }

#endif

    NT_ASSERT(Architecture != InjArchitectureMax);

    InjpInject(InjectionInfo,
               Architecture,
               SectionHandle,
               SectionSize);
  }
#if defined(_M_AMD64)
  else if (InjectionInfo->Method == InjMethodThunkless)
  {
    Architecture = InjArchitectureX64;

    InjpInjectX64NoThunk(InjectionInfo,
                         Architecture,
                         SectionHandle,
                         SectionSize);
  }
#endif

  ZwClose(SectionHandle);

  if (NT_SUCCESS(Status) && InjectionInfo->ForceUserApc)
  {
    //
    // Sets CurrentThread->ApcState.UserApcPending to TRUE.
    // This causes the queued user APC to be triggered immediately
    // on next transition of this thread to the user-mode.
    //

    KeTestAlertThread(UserMode);
  }

  return Status;
}

//////////////////////////////////////////////////////////////////////////
// Notify routines.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
InjCreateProcessNotifyRoutineEx(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
  )
{
  UNREFERENCED_PARAMETER(Process);

  if (CreateInfo)
  {
    InjCreateInjectionInfo(NULL, ProcessId);
  }
  else
  {
    InjRemoveInjectionInfoByProcessId(ProcessId, TRUE);
  }
}

VOID
NTAPI
InjLoadImageNotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_ HANDLE ProcessId,
  _In_ PIMAGE_INFO ImageInfo
  )
{
  //
  // Check if current process is injected.
  //

  PINJ_INJECTION_INFO InjectionInfo = InjFindInjectionInfo(ProcessId);

  if (!InjectionInfo || InjectionInfo->IsInjected)
  {
    return;
  }

#if defined(INJ_CONFIG_SUPPORTS_WOW64)
  //
  // If reparse-injection is enabled and this process is
  // Wow64 process, then do not track load-images.
  //

  if (InjectionInfo->Method == InjMethodWow64LogReparse &&
      PsGetProcessWow64Process(PsGetCurrentProcess()))
  {
    return;
  }
#endif

  if (PsIsProtectedProcess(PsGetCurrentProcess()))
  {
    //
    // Protected processes throw code-integrity error when
    // they are injected.  Signing policy can be changed, but
    // it requires hacking with lots of internal and Windows-
    // version-specific structures.  Simly don't inject such
    // processes.
    //
    // See Blackbone project (https://github.com/DarthTon/Blackbone)
    // if you're interested how protection can be temporarily
    // disabled on such processes.  (Look for BBSetProtection).
    //

    InjDbgPrint("Ignoring protected process (PID: %u, Name: '%s')\n",
                (ULONG)(ULONG_PTR)ProcessId,
                PsGetProcessImageFileName(PsGetCurrentProcess()));

    InjRemoveInjectionInfoByProcessId(ProcessId, TRUE);

    return;
  }

  if (!InjCanInject(InjectionInfo))
  {
    //
    // This process is in early stage - important DLLs (such as
    // ntdll.dll - or wow64.dll in case of Wow64 process) aren't
    // properly initialized yet.  We can't inject the DLL until
    // they are.
    //
    // Check if any of the system DLLs we're interested in is being
    // currently loaded - if so, mark that information down into the
    // LoadedDlls field.
    //

    for (ULONG Index = 0; Index < RTL_NUMBER_OF(InjpSystemDlls); Index += 1)
    {
      PUNICODE_STRING SystemDllPath = &InjpSystemDlls[Index].DllPath;

      if (RtlxSuffixUnicodeString(SystemDllPath, FullImageName, TRUE))
      {
        PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase,
                                                                       &LdrLoadDllRoutineName);

        ULONG DllFlag = InjpSystemDlls[Index].Flag;
        InjectionInfo->LoadedDlls |= DllFlag;

        switch (DllFlag)
        {
          //
          // In case of "thunk method", capture address of the LdrLoadDll
          // routine from the ntdll.dll (which is of the same architecture
          // as the process).
          //

          case INJ_SYSARM32_NTDLL_LOADED:
          case INJ_SYCHPE32_NTDLL_LOADED:
          case INJ_SYSWOW64_NTDLL_LOADED:
            if (InjectionInfo->Method != InjMethodThunkless)
            {
              InjectionInfo->LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;
            }
            break;

          //
          // For "thunkless method", capture address of the LdrLoadDll
          // routine from the native ntdll.dll.
          //

          case INJ_SYSTEM32_NTDLL_LOADED:
            InjectionInfo->LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;
            break;

          default:
            break;
        }

        //
        // Break the for-loop.
        //

        break;
      }
    }
  }
  else
  {
#if defined(INJ_CONFIG_SUPPORTS_WOW64)

    if (InjIsWindows7 &&
        InjectionInfo->Method == InjMethodThunk &&
        PsGetProcessWow64Process(PsGetCurrentProcess()))
    {
      //
      // On Windows 7, if we're injecting DLL into Wow64 process using
      // the "thunk method", we have additionaly postpone the load after
      // these system DLLs.
      //
      // This is because on Windows 7, these DLLs are loaded as part of
      // the wow64!ProcessInit routine, therefore the Wow64 subsystem
      // is not fully initialized to execute our injected Wow64ApcRoutine.
      //

      UNICODE_STRING System32Kernel32Path = RTL_CONSTANT_STRING(L"\\System32\\kernel32.dll");
      UNICODE_STRING SysWOW64Kernel32Path = RTL_CONSTANT_STRING(L"\\SysWOW64\\kernel32.dll");
      UNICODE_STRING System32User32Path   = RTL_CONSTANT_STRING(L"\\System32\\user32.dll");
      UNICODE_STRING SysWOW64User32Path   = RTL_CONSTANT_STRING(L"\\SysWOW64\\user32.dll");

      if (RtlxSuffixUnicodeString(&System32Kernel32Path, FullImageName, TRUE) ||
          RtlxSuffixUnicodeString(&SysWOW64Kernel32Path, FullImageName, TRUE) ||
          RtlxSuffixUnicodeString(&System32User32Path, FullImageName, TRUE) ||
          RtlxSuffixUnicodeString(&SysWOW64User32Path, FullImageName, TRUE))
      {
        InjDbgPrint("Postponing injection (%wZ)\n", FullImageName);
        return;
      }
    }

#endif

    //
    // All necessary DLLs are loaded - perform the injection.
    //
    // Note that injection is done via kernel-mode APC, because
    // InjInject calls ZwMapViewOfSection and MapViewOfSection
    // might be already on the callstack.  Because MapViewOfSection
    // locks the EPROCESS->AddressCreationLock, we would be risking
    // deadlock by calling InjInject directly.
    //

#if defined(INJ_CONFIG_SUPPORTS_WOW64)
    InjDbgPrint("Injecting (PID: %u, Wow64: %s, Name: '%s')\n",
                (ULONG)(ULONG_PTR)ProcessId,
                PsGetProcessWow64Process(PsGetCurrentProcess()) ? "TRUE" : "FALSE",
                PsGetProcessImageFileName(PsGetCurrentProcess()));
#else
    InjDbgPrint("Injecting (PID: %u, Name: '%s')\n",
                (ULONG)(ULONG_PTR)ProcessId,
                PsGetProcessImageFileName(PsGetCurrentProcess()));

#endif

    InjpQueueApc(KernelMode,
                 &InjpInjectApcNormalRoutine,
                 InjectionInfo,
                 NULL,
                 NULL);

    //
    // Mark that this process is injected.
    //

    InjectionInfo->IsInjected = TRUE;
  }
}
