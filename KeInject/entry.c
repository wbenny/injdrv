#include "entry.h"
#include "apcinject.h"

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
DriverDestroy(
  PDRIVER_OBJECT DriverObject
  )
{
  AiDestroy(DriverObject);
}

NTSTATUS
NTAPI
DriverEntry(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
  )
{
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS Status;

  Status = AiInitialize(DriverObject);
  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  DriverObject->DriverUnload = &DriverDestroy;

  return Status;
}
