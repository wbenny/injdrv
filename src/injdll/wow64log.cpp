#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1

#include "wow64log.h"

#if defined(_M_AMD64) || defined(_ARM64)

#  if defined(WOW64_LOG_FAKE_EXPORT_ENABLE)

#    define DECLSPEC_EXPORT
#    define WOW64_LOG_NUMBER_OF_FUNCTIONS  4

typedef struct _WOW64_LOG_FAKE_EXPORT_DIRECTORY
{
  IMAGE_EXPORT_DIRECTORY ExportDirectory;

  ULONG ExportTable   [WOW64_LOG_NUMBER_OF_FUNCTIONS];
  ULONG NameTable     [WOW64_LOG_NUMBER_OF_FUNCTIONS];
  SHORT OrdinalTable  [WOW64_LOG_NUMBER_OF_FUNCTIONS];
  CHAR  FunctionNames [WOW64_LOG_NUMBER_OF_FUNCTIONS][32];
} WOW64_LOG_FAKE_EXPORT_DIRECTORY, *PWOW64_LOG_FAKE_EXPORT_DIRECTORY;

WOW64_LOG_FAKE_EXPORT_DIRECTORY Wow64LogFakeExportDirectory;

#  else
#    define DECLSPEC_EXPORT                __declspec(dllexport)
#  endif

typedef ULONG (*WOW64_LOG_ARGUMENTS)[32];

typedef struct _WOW64_LOG_SERVICE
{
  PLDR_DATA_TABLE_ENTRY BtLdrEntry; // NULL on Win7
  WOW64_LOG_ARGUMENTS   Arguments;
  ULONG                 Reserved;
  ULONG                 ServiceNumber;
  NTSTATUS              Status;
  BOOLEAN               PostCall;
} WOW64_LOG_SERVICE, *PWOW64_LOG_SERVICE;

EXTERN_C
DECLSPEC_EXPORT
NTSTATUS
NTAPI
Wow64LogInitialize(
  VOID
  )
{
  return STATUS_SUCCESS;
}

EXTERN_C
DECLSPEC_EXPORT
NTSTATUS
NTAPI
Wow64LogMessageArgList(
  UCHAR Level,
  const CHAR* Format,
  va_list Args
  )
{
#if 0
#  define DPFLTR_ERROR_LEVEL    0
#  define DPFLTR_WARNING_LEVEL  1
#  define DPFLTR_TRACE_LEVEL    2
#  define DPFLTR_INFO_LEVEL     3

#  define DPFLTR_IHVDRIVER_ID   77

  vDbgPrintEx(DPFLTR_IHVDRIVER_ID,
              DPFLTR_ERROR_LEVEL,
              (PCH)Format,
              Args);
#else
  UNREFERENCED_PARAMETER(Level);
  UNREFERENCED_PARAMETER(Format);
  UNREFERENCED_PARAMETER(Args);
#endif

  return STATUS_SUCCESS;
}

EXTERN_C
DECLSPEC_EXPORT
NTSTATUS
NTAPI
Wow64LogSystemService(
  PWOW64_LOG_SERVICE ServiceParameters
  )
{
  UNREFERENCED_PARAMETER(ServiceParameters);

  return STATUS_SUCCESS;
}

EXTERN_C
DECLSPEC_EXPORT
NTSTATUS
NTAPI
Wow64LogTerminate(
  VOID
  )
{
  return STATUS_SUCCESS;
}

#else
  //
  // Force #undef of WOW64_LOG_FAKE_EXPORT_ENABLE on platforms
  // that don't support Wow64 (such as x86, ARM32).
  //
#   undef WOW64_LOG_FAKE_EXPORT_ENABLE
#endif

EXTERN_C
NTSTATUS
NTAPI
Wow64LogCreateExports(
  PVOID BaseAddress
  )
{
#if defined(WOW64_LOG_FAKE_EXPORT_ENABLE)

#  define RelVa(Address)                      (ULONG)((ULONG_PTR)Address - (ULONG_PTR)BaseAddress)

  PIMAGE_NT_HEADERS      NtHeaders            = RtlImageNtHeader(BaseAddress);
  PIMAGE_OPTIONAL_HEADER OptionalHeader       = &NtHeaders->OptionalHeader;
  PIMAGE_DATA_DIRECTORY  ExportDataDirectory  = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  RTL_ASSERT(
    ExportDataDirectory->VirtualAddress == 0 &&
    ExportDataDirectory->Size == 0
  );

  NTSTATUS Status;

  PVOID  ExportDataDirectoryAddress = ExportDataDirectory;
  SIZE_T RegionSize = sizeof(IMAGE_DATA_DIRECTORY);
  ULONG  OldProtect;
  Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                  &ExportDataDirectoryAddress,
                                  &RegionSize,
                                  PAGE_READWRITE,
                                  &OldProtect);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  ExportDataDirectory->VirtualAddress = RelVa(&Wow64LogFakeExportDirectory);
  ExportDataDirectory->Size           = sizeof(Wow64LogFakeExportDirectory);

  Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                  &ExportDataDirectoryAddress,
                                  &RegionSize,
                                  OldProtect,
                                  &OldProtect);

  if (!NT_SUCCESS(Status))
  {
    //
    // Ignore...
    //
  }

  Wow64LogFakeExportDirectory.ExportDirectory.NumberOfFunctions       = WOW64_LOG_NUMBER_OF_FUNCTIONS;
  Wow64LogFakeExportDirectory.ExportDirectory.NumberOfNames           = WOW64_LOG_NUMBER_OF_FUNCTIONS;
  Wow64LogFakeExportDirectory.ExportDirectory.AddressOfFunctions      = RelVa(Wow64LogFakeExportDirectory.ExportTable);
  Wow64LogFakeExportDirectory.ExportDirectory.AddressOfNames          = RelVa(Wow64LogFakeExportDirectory.NameTable);
  Wow64LogFakeExportDirectory.ExportDirectory.AddressOfNameOrdinals   = RelVa(Wow64LogFakeExportDirectory.OrdinalTable);

  Wow64LogFakeExportDirectory.NameTable[0]                            = RelVa(Wow64LogFakeExportDirectory.FunctionNames[0]);
  Wow64LogFakeExportDirectory.NameTable[1]                            = RelVa(Wow64LogFakeExportDirectory.FunctionNames[1]);
  Wow64LogFakeExportDirectory.NameTable[2]                            = RelVa(Wow64LogFakeExportDirectory.FunctionNames[2]);
  Wow64LogFakeExportDirectory.NameTable[3]                            = RelVa(Wow64LogFakeExportDirectory.FunctionNames[3]);

  Wow64LogFakeExportDirectory.OrdinalTable[0]                         = 0;
  Wow64LogFakeExportDirectory.OrdinalTable[1]                         = 1;
  Wow64LogFakeExportDirectory.OrdinalTable[2]                         = 2;
  Wow64LogFakeExportDirectory.OrdinalTable[3]                         = 3;

  Wow64LogFakeExportDirectory.ExportTable[0]                          = RelVa(&Wow64LogInitialize);
  Wow64LogFakeExportDirectory.ExportTable[1]                          = RelVa(&Wow64LogMessageArgList);
  Wow64LogFakeExportDirectory.ExportTable[2]                          = RelVa(&Wow64LogSystemService);
  Wow64LogFakeExportDirectory.ExportTable[3]                          = RelVa(&Wow64LogTerminate);

  ANSI_STRING Wow64LogInitializeRoutineName;
  RtlInitAnsiString(&Wow64LogInitializeRoutineName, (PSTR)"Wow64LogInitialize");
  RtlCopyMemory(Wow64LogFakeExportDirectory.FunctionNames[0],
                Wow64LogInitializeRoutineName.Buffer,
                Wow64LogInitializeRoutineName.Length + 1);

  ANSI_STRING Wow64LogMessageArgListRoutineName;
  RtlInitAnsiString(&Wow64LogMessageArgListRoutineName, (PSTR)"Wow64LogMessageArgList");
  RtlCopyMemory(Wow64LogFakeExportDirectory.FunctionNames[1],
                Wow64LogMessageArgListRoutineName.Buffer,
                Wow64LogMessageArgListRoutineName.Length + 1);

  ANSI_STRING Wow64LogSystemServiceRoutineName;
  RtlInitAnsiString(&Wow64LogSystemServiceRoutineName, (PSTR)"Wow64LogSystemService");
  RtlCopyMemory(Wow64LogFakeExportDirectory.FunctionNames[2],
                Wow64LogSystemServiceRoutineName.Buffer,
                Wow64LogSystemServiceRoutineName.Length + 1);

  ANSI_STRING Wow64LogTerminateRoutineName;
  RtlInitAnsiString(&Wow64LogTerminateRoutineName, (PSTR)"Wow64LogTerminate");
  RtlCopyMemory(Wow64LogFakeExportDirectory.FunctionNames[3],
                Wow64LogTerminateRoutineName.Buffer,
                Wow64LogTerminateRoutineName.Length + 1);

#else

  UNREFERENCED_PARAMETER(BaseAddress);

#endif

  return STATUS_SUCCESS;
}
