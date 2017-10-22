#include "image.h"
#include "nt/ntimage.h"
#include "nt/rtlapi.h"

PVOID
NTAPI
AiFindExportedRoutineByName(
  _In_ PVOID DllBase,
  _In_ PANSI_STRING ExportName
  )
{
  //
  // Borrowed from ReactOS.
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
  ExportDirectory = RtlImageDirectoryEntryToData(
    DllBase,
    TRUE,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    &ExportSize);

  if (!ExportDirectory) return NULL;

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

  { //
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
  if (High < Low) return NULL;

  //
  // Otherwise, this is the ordinal.
  //
  Ordinal = OrdinalTable[Mid];

  //
  // Validate the ordinal.
  //
  if (Ordinal >= ExportDirectory->NumberOfFunctions) return NULL;

  //
  // Resolve the address and write it.
  //
  ExportTable = (PULONG)((ULONG_PTR)DllBase +
    ExportDirectory->AddressOfFunctions);
  Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

  //
  // We found it!
  //
  NT_ASSERT(
    (Function < (PVOID)ExportDirectory) ||
    (Function >(PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
  );
  return Function;

}
